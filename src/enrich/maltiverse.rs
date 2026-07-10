//! Maltiverse — threat intel multi-observable (IP, domaine, hash) : classification
//! (malicious/suspicious/neutral/whitelist) + blacklist + tags. `Authorization: Bearer`.
//! Gated. Inconnu = HTTP 200 avec stub `classification: neutral` (sans blacklist/tag) ;
//! entrée invalide/réservée = HTTP 400.

use std::net::IpAddr;

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    run(ctx, format!("ip/{ip}")).await
}
pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, format!("hostname/{domain}")).await
}
pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, format!("sample/{hash}")).await
}

async fn run(ctx: &Ctx, path: String) -> Enrichment {
    let Some(key) = ctx.key("MALTIVERSE_API_KEY") else {
        return Enrichment::failed("maltiverse", "clé absente".into());
    };
    match fetch(&ctx.http, &path, key).await {
        Ok(Some(v)) => build(&v),
        Ok(None) => Enrichment::ok(
            "maltiverse",
            vec![Fact::new("maltiverse", "observable non exploitable")],
        ),
        Err(e) => Enrichment::failed("maltiverse", super::scrub(format!("{e:#}"), key)),
    }
}

/// `Ok(None)` = HTTP 400 (entrée malformée/réservée : TEST-NET, mauvaise longueur).
async fn fetch(http: &reqwest::Client, path: &str, key: &str) -> Result<Option<Value>> {
    let resp = http
        .get(format!("https://api.maltiverse.com/{path}"))
        .bearer_auth(key)
        .send()
        .await?;
    if resp.status() == StatusCode::BAD_REQUEST {
        return Ok(None);
    }
    Ok(Some(resp.error_for_status()?.json().await?))
}

fn build(v: &Value) -> Enrichment {
    let classification = v
        .get("classification")
        .and_then(|x| x.as_str())
        .unwrap_or("neutral");
    let blacklist = v
        .get("blacklist")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let tags: Vec<String> = v
        .get("tag")
        .and_then(|x| x.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();

    // Stub "neutral" sans blacklist ni tag = inconnu de Maltiverse.
    if classification == "neutral" && blacklist.is_empty() && tags.is_empty() {
        return Enrichment::ok(
            "maltiverse",
            vec![Fact::new("maltiverse", "aucune donnée (neutre)")],
        );
    }

    let mut facts = vec![Fact::new("classification", classification)];
    for (label, k) in [
        ("as", "as_name"),
        ("country", "country_code"),
        ("filetype", "filetype"),
    ] {
        if let Some(s) = v.get(k).and_then(|x| x.as_str()).filter(|s| !s.is_empty()) {
            facts.push(Fact::new(label, s));
        }
    }
    if !tags.is_empty() {
        facts.push(Fact::new("tags", super::dedup_join(tags, 8)));
    }
    let descs = blacklist.iter().filter_map(|b| {
        b.get("description")
            .and_then(|x| x.as_str())
            .map(String::from)
    });
    let descs_j = super::dedup_join(descs, 5);
    if !descs_j.is_empty() {
        facts.push(Fact::new("menaces", descs_j));
    }

    // Pivots vers les IP résolues (réponses domaine).
    let mut pivots = Vec::new();
    if let Some(ips) = v.get("resolved_ip").and_then(|x| x.as_array()) {
        for ip in ips
            .iter()
            .filter_map(|r| r.get("ip_addr").and_then(|x| x.as_str()))
            .take(10)
        {
            pivots.push(Pivot {
                relation: "resolves".into(),
                kind: "ip".into(),
                value: ip.to_string(),
            });
        }
    }

    let mut signals = Vec::new();
    let cat = match classification {
        "malicious" => Some("malicious"),
        "suspicious" => Some("suspicious"),
        _ => None, // neutral / whitelist
    };
    if let Some(c) = cat {
        signals.push(Signal::with_detail(
            "maltiverse",
            c,
            format!("classification {classification}"),
        ));
    }

    Enrichment {
        source: "maltiverse".into(),
        facts,
        signals,
        pivots,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_malicious_ip() {
        let v = serde_json::json!({
            "type": "ip", "classification": "malicious", "as_name": "AS1 Example",
            "country_code": "RU", "blacklist": [{"source": "ThreatFox", "description": "Mirai"}],
            "tag": ["botnet"]
        });
        let e = build(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "classification" && f.value == "malicious")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "menaces" && f.value.contains("Mirai"))
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
    }

    #[test]
    fn build_neutral_stub_unknown() {
        let e = build(&serde_json::json!({"type": "sample", "classification": "neutral"}));
        assert!(e.signals.is_empty());
        assert!(e.facts.iter().any(|f| f.value.contains("aucune donnée")));
    }

    #[test]
    fn build_domain_pivots() {
        let v = serde_json::json!({
            "type": "hostname", "classification": "suspicious",
            "resolved_ip": [{"ip_addr": "1.2.3.4"}, {"ip_addr": "5.6.7.8"}], "tag": ["phishing"]
        });
        let e = build(&v);
        assert_eq!(e.pivots.iter().filter(|p| p.kind == "ip").count(), 2);
        assert_eq!(e.signals[0].category, "suspicious");
    }
}
