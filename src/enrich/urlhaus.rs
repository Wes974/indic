//! URLhaus (abuse.ch) — URLs de distribution de malware : host (domaine/IP),
//! URL exacte ou payload (md5/sha256). POST form-urlencoded, clé header
//! `Auth-Key` (portail auth.abuse.ch), gated.

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

/// Signature d'un parseur de réponse URLhaus : `Value` → (facts, signals).
type ParseFn = fn(&Value) -> Result<(Vec<Fact>, Vec<Signal>)>;

/// Domaine ou IP littérale — endpoint `host/`.
pub async fn enrich_host(host: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, "host", ("host", host), parse_host).await
}

/// URL complète — endpoint `url/`.
pub async fn enrich_url(url: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, "url", ("url", url), parse_url).await
}

/// Hash d'un payload distribué — md5 (32) ou sha256 (64) selon la longueur.
pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    let param = match hash.len() {
        64 => "sha256_hash",
        32 => "md5_hash",
        // URLhaus n'indexe ni sha1 ni autre : inutile d'interroger l'API.
        _ => {
            return Enrichment::failed(
                "urlhaus",
                "hash non supporté (md5/sha256 uniquement)".into(),
            );
        }
    };
    run(ctx, "payload", (param, hash), parse_payload).await
}

async fn run(ctx: &Ctx, endpoint: &str, param: (&str, &str), parse: ParseFn) -> Enrichment {
    let Some(key) = ctx.key("ABUSE_CH_API_KEY") else {
        return Enrichment::failed("urlhaus", "clé absente".into());
    };
    match fetch(&ctx.http, endpoint, param, key)
        .await
        .and_then(|v| parse(&v))
    {
        Ok((facts, signals)) => Enrichment {
            source: "urlhaus".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("urlhaus", format!("{e:#}")),
    }
}

async fn fetch(
    http: &reqwest::Client,
    endpoint: &str,
    param: (&str, &str),
    key: &str,
) -> Result<Value> {
    Ok(http
        .post(format!("https://urlhaus-api.abuse.ch/v1/{endpoint}/"))
        .header("Auth-Key", key)
        .form(&[param])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Vrai si la réponse porte des données, faux si `no_results` (réponse saine).
fn has_results(v: &Value) -> Result<bool> {
    match v
        .get("query_status")
        .and_then(|x| x.as_str())
        .unwrap_or("?")
    {
        "ok" => Ok(true),
        "no_results" => Ok(false),
        other => anyhow::bail!("query_status: {other}"),
    }
}

fn parse_host(v: &Value) -> Result<(Vec<Fact>, Vec<Signal>)> {
    if !has_results(v)? {
        return Ok((vec![Fact::new("urlhaus", "aucune URL connue")], vec![]));
    }
    let mut facts = Vec::new();
    if let Some(n) = v.get("url_count").and_then(as_text) {
        facts.push(Fact::new("urls", n));
    }
    if let Some(fs) = v.get("firstseen").and_then(|x| x.as_str()) {
        facts.push(Fact::new("first_seen", fs));
    }

    let urls = v
        .get("urls")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    let online = urls
        .iter()
        .filter(|u| u.get("url_status").and_then(|x| x.as_str()) == Some("online"))
        .count();
    if online > 0 {
        facts.push(Fact::new("urls_online", online.to_string()));
    }
    let threats = uniq_join(
        urls.iter()
            .filter_map(|u| u.get("threat").and_then(|x| x.as_str()).map(str::to_string)),
        3,
    );
    if !threats.is_empty() {
        facts.push(Fact::new("threat", threats.clone()));
    }
    let tags = uniq_join(
        urls.iter()
            .flat_map(|u| {
                u.get("tags")
                    .and_then(|x| x.as_array())
                    .cloned()
                    .unwrap_or_default()
            })
            .filter_map(|t| t.as_str().map(str::to_string)),
        10,
    );
    if !tags.is_empty() {
        facts.push(Fact::new("tags", tags));
    }
    push_blacklists(v, &mut facts);

    let detail = if threats.is_empty() {
        "distribution de malware".into()
    } else {
        threats
    };
    Ok((
        facts,
        vec![Signal::with_detail("urlhaus", "malicious", detail)],
    ))
}

fn parse_url(v: &Value) -> Result<(Vec<Fact>, Vec<Signal>)> {
    if !has_results(v)? {
        return Ok((vec![Fact::new("urlhaus", "URL inconnue")], vec![]));
    }
    let mut facts = Vec::new();
    for (label, key) in [
        ("status", "url_status"),
        ("threat", "threat"),
        ("date_added", "date_added"),
    ] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            facts.push(Fact::new(label, s));
        }
    }
    let tags = uniq_join(
        v.get("tags")
            .and_then(|x| x.as_array())
            .cloned()
            .unwrap_or_default()
            .into_iter()
            .filter_map(|t| t.as_str().map(str::to_string)),
        10,
    );
    if !tags.is_empty() {
        facts.push(Fact::new("tags", tags));
    }
    if let Some(p) = v.get("payloads").and_then(|x| x.as_array())
        && !p.is_empty()
    {
        facts.push(Fact::new("payloads", p.len().to_string()));
    }
    push_blacklists(v, &mut facts);

    let threat = v
        .get("threat")
        .and_then(|x| x.as_str())
        .unwrap_or("distribution de malware")
        .to_string();
    Ok((
        facts,
        vec![Signal::with_detail("urlhaus", "malicious", threat)],
    ))
}

fn parse_payload(v: &Value) -> Result<(Vec<Fact>, Vec<Signal>)> {
    if !has_results(v)? {
        return Ok((vec![Fact::new("urlhaus", "payload inconnu")], vec![]));
    }
    let mut facts = Vec::new();
    for (label, key) in [
        ("file_type", "file_type"),
        ("signature", "signature"),
        ("first_seen", "firstseen"),
    ] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str()) {
            facts.push(Fact::new(label, s));
        }
    }
    if let Some(sz) = v.get("file_size").and_then(as_text) {
        facts.push(Fact::new("file_size", format!("{sz} octets")));
    }
    if let Some(n) = v.get("url_count").and_then(as_text) {
        facts.push(Fact::new("urls", n));
    }

    let detail = v
        .get("signature")
        .and_then(|x| x.as_str())
        .unwrap_or("payload distribué par URLhaus")
        .to_string();
    Ok((
        facts,
        vec![Signal::with_detail("urlhaus", "malicious", detail)],
    ))
}

/// Blacklists (Spamhaus DBL, SURBL) — on ne remonte que les statuts listés.
fn push_blacklists(v: &Value, facts: &mut Vec<Fact>) {
    let Some(bl) = v.get("blacklists").and_then(|x| x.as_object()) else {
        return;
    };
    for (name, val) in bl {
        if let Some(s) = val.as_str()
            && s != "not listed"
        {
            facts.push(Fact::new(name, s));
        }
    }
}

/// URLhaus renvoie certains nombres en string ("url_count": "124") : on tolère les deux.
fn as_text(v: &Value) -> Option<String> {
    match v {
        Value::String(s) => Some(s.clone()),
        Value::Number(n) => Some(n.to_string()),
        _ => None,
    }
}

/// Déduplique en conservant l'ordre, borne à `max` éléments, joint par ", ".
fn uniq_join(it: impl Iterator<Item = String>, max: usize) -> String {
    let mut seen: Vec<String> = Vec::new();
    for s in it {
        if !s.is_empty() && !seen.contains(&s) {
            seen.push(s);
            if seen.len() == max {
                break;
            }
        }
    }
    seen.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_host_ok() {
        let v = serde_json::json!({
            "query_status": "ok",
            "firstseen": "2019-01-15 07:09:01 UTC",
            "url_count": "124",
            "blacklists": { "spamhaus_dbl": "abused_legit_malware", "surbl": "not listed" },
            "urls": [
                { "url": "http://x/a.exe", "url_status": "online",
                  "threat": "malware_download", "tags": ["exe", "Gozi"] },
                { "url": "http://x/b.exe", "url_status": "offline",
                  "threat": "malware_download", "tags": null }
            ]
        });
        let (facts, signals) = parse_host(&v).unwrap();
        assert!(facts.iter().any(|f| f.key == "urls" && f.value == "124"));
        assert!(
            facts
                .iter()
                .any(|f| f.key == "urls_online" && f.value == "1")
        );
        assert!(
            facts
                .iter()
                .any(|f| f.key == "tags" && f.value == "exe, Gozi")
        );
        assert!(facts.iter().any(|f| f.key == "spamhaus_dbl"));
        assert!(!facts.iter().any(|f| f.key == "surbl"));
        assert_eq!(signals[0].detail.as_deref(), Some("malware_download"));
    }

    #[test]
    fn parse_payload_no_results() {
        let v = serde_json::json!({ "query_status": "no_results" });
        let (facts, signals) = parse_payload(&v).unwrap();
        assert_eq!(facts[0].value, "payload inconnu");
        assert!(signals.is_empty());
    }
}
