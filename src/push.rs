//! Push d'un observable enrichi vers MISP (REST) et OpenCTI (GraphQL).
//!
//! Gated : actif seulement si les URL + clés correspondantes sont configurées
//! (`MISP_URL`+`MISP_API_KEY`, `OPENCTI_URL`+`OPENCTI_TOKEN`). Ne pousse que les
//! observables porteurs d'un **signal de menace** — on n'inonde pas les
//! plateformes avec du bruit (une IP résidentielle propre n'a rien à y faire).

use std::collections::HashSet;
use std::time::Duration;

use serde::Serialize;
use serde_json::{Value, json};

use crate::enrich::{Ctx, Report};

/// Catégories de signaux qui justifient un push vers les plateformes CTI.
/// Alignées sur ce qu'indic émet réellement : `malicious` (threatfox, urlhaus,
/// malwarebazaar, safebrowsing, metadefender, Spamhaus DROP), `c2` (Feodo),
/// `abuse` (dshield, ipqs, IPsum), `threat` (fallback feed de menace). Le reste
/// est du futur-proofing. `exploited` (IP vulnérable) est volontairement exclu
/// (indicateur d'exposition, pas d'IOC → trop bruyant) ; l'anonymisation pure
/// (tor/vpn/proxy/datacenter) aussi — c'est un attribut, pas une menace.
const THREAT_CATEGORIES: &[&str] = &[
    "malicious",
    "c2",
    "abuse",
    "threat",
    "botnet",
    "phishing",
    "malware",
    "compromised",
];

/// Catégories « graves » → remontent le threat level MISP au max.
const HIGH_SEVERITY: &[&str] = &["malicious", "c2", "botnet", "malware", "compromised"];

/// Résultat d'un push (une plateforme).
#[derive(Debug, Serialize)]
pub struct TargetResult {
    pub ok: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl TargetResult {
    fn ok(id: String) -> Self {
        Self {
            ok: true,
            id: Some(id),
            error: None,
        }
    }
    fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            id: None,
            error: Some(msg.into()),
        }
    }
}

/// Verdict global du push pour un observable.
#[derive(Debug, Serialize)]
pub struct PushOutcome {
    pub pushed: bool,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub misp: Option<TargetResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opencti: Option<TargetResult>,
}

impl PushOutcome {
    fn skipped(reason: impl Into<String>) -> Self {
        Self {
            pushed: false,
            reason: reason.into(),
            misp: None,
            opencti: None,
        }
    }
}

/// Toutes les paires (catégorie, source) des signaux du rapport (enrichers + IP).
fn threat_tags(report: &Report) -> Vec<(String, String)> {
    let mut out: Vec<(String, String)> = report
        .enrichments
        .iter()
        .flat_map(|e| e.signals.iter())
        .map(|s| (s.category.clone(), s.source.clone()))
        .collect();
    if let Some(ip) = &report.ip {
        out.extend(
            ip.signals
                .iter()
                .map(|s| (s.category.clone(), s.source.clone())),
        );
    }
    out
}

/// Sources « curées » à haute confiance : un seul hit suffit à pousser
/// (blocklists / feeds de malware, pas des avis de réputation bruyants).
const CURATED_SOURCES: &[&str] = &[
    "feodo",
    "spamhaus_drop",
    "spamhaus_asndrop",
    "ipsum",
    "threatfox",
    "urlhaus",
    "malwarebazaar",
    "safebrowsing",
];

/// Signaux de menace du rapport : (catégorie, source) restreints aux catégories
/// de menace (exclut anonymisation / infra / info).
fn threat_signals(report: &Report) -> Vec<(String, String)> {
    threat_tags(report)
        .into_iter()
        .filter(|(cat, _)| THREAT_CATEGORIES.contains(&cat.as_str()))
        .collect()
}

/// Faut-il pousser ce rapport ? Oui si un signal provient d'une source curée
/// (haute confiance), ou si ≥ 3 sources distinctes le flaggent (corroboration —
/// évite le faux positif d'une seule API de réputation, ex. 1.1.1.1).
fn should_push(report: &Report) -> bool {
    let threat = threat_signals(report);
    if threat
        .iter()
        .any(|(_, src)| CURATED_SOURCES.contains(&src.as_str()))
    {
        return true;
    }
    let distinct: HashSet<&str> = threat.iter().map(|(_, s)| s.as_str()).collect();
    distinct.len() >= 3
}

/// Type d'attribut MISP pour un observable donné.
fn misp_attr_type(kind: &str, value: &str) -> &'static str {
    match kind {
        "ip" => "ip-dst",
        "domain" => "domain",
        "url" => "url",
        "email" => "email-src",
        "hash" => match value.len() {
            32 => "md5",
            40 => "sha1",
            64 => "sha256",
            _ => "other",
        },
        _ => "comment",
    }
}

/// Catégorie MISP (taxonomie fixe de l'outil).
fn misp_category(kind: &str) -> &'static str {
    match kind {
        "hash" => "Payload delivery",
        _ => "Network activity",
    }
}

/// `threat_level_id` MISP : 1=high, 2=medium, 3=low, 4=undefined.
fn threat_level(report: &Report) -> &'static str {
    let tags = threat_tags(report);
    if tags
        .iter()
        .any(|(c, _)| HIGH_SEVERITY.contains(&c.as_str()))
    {
        "1"
    } else if tags
        .iter()
        .any(|(c, _)| THREAT_CATEGORIES.contains(&c.as_str()))
    {
        "2"
    } else {
        "4"
    }
}

/// Type OpenCTI + clé d'input `stixCyberObservableAdd` (`IPv4-Addr` → `IPv4Addr`).
/// `None` pour les types dont l'input diffère (hash → `StixFile{hashes}`, à venir).
fn opencti_type(kind: &str, value: &str) -> Option<(&'static str, &'static str)> {
    match kind {
        "ip" if value.contains(':') => Some(("IPv6-Addr", "IPv6Addr")),
        "ip" => Some(("IPv4-Addr", "IPv4Addr")),
        "domain" => Some(("Domain-Name", "DomainName")),
        "url" => Some(("Url", "Url")),
        "email" => Some(("Email-Addr", "EmailAddr")),
        _ => None,
    }
}

/// Tags MISP `indic:<catégorie>` (catégories de menace, dédupliquées).
fn misp_tags(report: &Report) -> Vec<Value> {
    let mut seen = HashSet::new();
    threat_signals(report)
        .into_iter()
        .filter(|(cat, _)| seen.insert(cat.clone()))
        .map(|(cat, _)| json!({ "name": format!("indic:{cat}") }))
        .collect()
}

/// Commentaire d'attribut : les sources de menace distinctes (max 6).
fn push_comment(report: &Report) -> String {
    let mut seen = HashSet::new();
    let srcs: Vec<String> = threat_signals(report)
        .into_iter()
        .filter(|(_, src)| seen.insert(src.clone()))
        .map(|(_, src)| src)
        .take(6)
        .collect();
    format!("indic — sources : {}", srcs.join(", "))
}

/// Pousse un rapport vers les plateformes CTI configurées.
///
/// Ne fait rien si aucune plateforme n'est configurée ou si l'observable ne
/// porte aucun signal de menace.
pub async fn push_report(report: &Report, ctx: &Ctx) -> PushOutcome {
    let misp_url = ctx.key("MISP_URL");
    let misp_key = ctx.key("MISP_API_KEY");
    let octi_url = ctx.key("OPENCTI_URL");
    let octi_token = ctx.key("OPENCTI_TOKEN");

    if misp_url.is_none() && octi_url.is_none() {
        return PushOutcome::skipped("aucune plateforme CTI configurée (MISP_URL / OPENCTI_URL)");
    }
    if !should_push(report) {
        return PushOutcome::skipped(
            "signal insuffisant (ni source curée, ni ≥3 corroborations) — non poussé",
        );
    }

    // Client tolérant au cert self-signed de MISP sur le réseau docker interne.
    let insecure = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(20))
        .build()
        .ok();

    let misp = match (misp_url, misp_key, insecure.as_ref()) {
        (Some(url), Some(key), Some(client)) => Some(push_misp(report, url, key, client).await),
        (Some(_), Some(_), None) => Some(TargetResult::err("client HTTP indisponible")),
        _ => None,
    };
    let opencti = match (octi_url, octi_token) {
        (Some(url), Some(token)) => Some(push_opencti(report, url, token, ctx).await),
        _ => None,
    };

    PushOutcome {
        pushed: true,
        reason: "poussé (signal de menace présent)".into(),
        misp,
        opencti,
    }
}

/// Crée un event MISP portant l'observable en attribut + tags `indic:*`.
async fn push_misp(
    report: &Report,
    url: &str,
    key: &str,
    client: &reqwest::Client,
) -> TargetResult {
    let value = report.query.as_str();
    let body = json!({
        "Event": {
            "info": format!("indic: {} {}", report.kind, value),
            "distribution": "0",
            "analysis": "0",
            "threat_level_id": threat_level(report),
            "Attribute": [{
                "type": misp_attr_type(&report.kind, value),
                "category": misp_category(&report.kind),
                "value": value,
                "to_ids": true,
                "comment": push_comment(report),
            }],
            "Tag": misp_tags(report),
        }
    });
    let endpoint = format!("{}/events/add", url.trim_end_matches('/'));
    match client
        .post(&endpoint)
        .header("Authorization", key)
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let v: Value = resp.json().await.unwrap_or(Value::Null);
            match v
                .get("Event")
                .and_then(|e| e.get("id"))
                .and_then(|i| i.as_str())
            {
                Some(id) => TargetResult::ok(id.to_string()),
                None => {
                    let msg = v
                        .get("message")
                        .and_then(Value::as_str)
                        .or_else(|| v.pointer("/errors/value/0").and_then(Value::as_str))
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("réponse inattendue (HTTP {status})"));
                    TargetResult::err(msg)
                }
            }
        }
        Err(e) => TargetResult::err(e.to_string()),
    }
}

/// Crée un StixCyberObservable dans OpenCTI via GraphQL.
async fn push_opencti(report: &Report, url: &str, token: &str, ctx: &Ctx) -> TargetResult {
    let value = report.query.as_str();
    let Some((octi_type, input_key)) = opencti_type(&report.kind, value) else {
        return TargetResult::err(format!("type non supporté par OpenCTI : {}", report.kind));
    };
    let mutation = format!(
        "mutation($v:String!){{stixCyberObservableAdd(type:\"{octi_type}\",{input_key}:{{value:$v}}){{id observable_value}}}}"
    );
    let body = json!({ "query": mutation, "variables": { "v": value } });
    let endpoint = format!("{}/graphql", url.trim_end_matches('/'));
    match ctx
        .http
        .post(&endpoint)
        .header("Authorization", format!("Bearer {token}"))
        .json(&body)
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let v: Value = resp.json().await.unwrap_or(Value::Null);
            match v
                .pointer("/data/stixCyberObservableAdd/id")
                .and_then(Value::as_str)
            {
                Some(id) => TargetResult::ok(id.to_string()),
                None => {
                    let msg = v
                        .pointer("/errors/0/message")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                        .unwrap_or_else(|| format!("réponse inattendue (HTTP {status})"));
                    TargetResult::err(msg)
                }
            }
        }
        Err(e) => TargetResult::err(e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn misp_attr_type_par_kind() {
        assert_eq!(misp_attr_type("ip", "1.2.3.4"), "ip-dst");
        assert_eq!(misp_attr_type("domain", "evil.com"), "domain");
        assert_eq!(misp_attr_type("url", "http://x"), "url");
        assert_eq!(misp_attr_type("email", "a@b.c"), "email-src");
        assert_eq!(misp_attr_type("hash", &"a".repeat(32)), "md5");
        assert_eq!(misp_attr_type("hash", &"a".repeat(40)), "sha1");
        assert_eq!(misp_attr_type("hash", &"a".repeat(64)), "sha256");
    }

    #[test]
    fn opencti_type_ipv4_vs_ipv6() {
        assert_eq!(
            opencti_type("ip", "1.2.3.4"),
            Some(("IPv4-Addr", "IPv4Addr"))
        );
        assert_eq!(
            opencti_type("ip", "2001:db8::1"),
            Some(("IPv6-Addr", "IPv6Addr"))
        );
        assert_eq!(
            opencti_type("domain", "x.com"),
            Some(("Domain-Name", "DomainName"))
        );
        assert_eq!(opencti_type("url", "http://x"), Some(("Url", "Url")));
        assert_eq!(opencti_type("hash", &"a".repeat(64)), None);
    }

    #[test]
    fn should_push_gate() {
        use crate::enrich::Enrichment;
        use crate::model::Signal;
        let report = |sigs: Vec<Signal>| Report {
            query: "x".into(),
            kind: "ip".into(),
            ip: None,
            enrichments: vec![Enrichment {
                source: "e".into(),
                facts: vec![],
                signals: sigs,
                pivots: vec![],
                error: None,
            }],
            pivots: vec![],
            verdict: None,
        };
        // Source curée → un seul hit suffit.
        assert!(should_push(&report(vec![Signal::new("feodo", "c2")])));
        // Avis d'une seule API de réputation → non poussé (cf. 1.1.1.1).
        assert!(!should_push(&report(vec![Signal::new(
            "ipdata",
            "malicious"
        )])));
        // Deux sources de réputation → toujours insuffisant.
        assert!(!should_push(&report(vec![
            Signal::new("ipdata", "malicious"),
            Signal::new("dshield", "threat"),
        ])));
        // Trois sources distinctes → corroboration suffisante.
        assert!(should_push(&report(vec![
            Signal::new("a", "malicious"),
            Signal::new("b", "abuse"),
            Signal::new("c", "threat"),
        ])));
        // Anonymisation seule → non poussé.
        assert!(!should_push(&report(vec![
            Signal::new("tor_exit_list", "tor"),
            Signal::new("x4bnet_vpn", "vpn"),
        ])));
    }
}
