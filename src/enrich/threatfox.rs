//! ThreatFox (abuse.ch) — IOC C2 / malware pour IP, domaine, URL et hash.
//! POST JSON `search_ioc`, clé header `Auth-Key` (portail auth.abuse.ch), gated.

use std::net::IpAddr;

use anyhow::Result;
use serde::Deserialize;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    // Recherche wildcard (défaut) : matche aussi les IOC stockés en `ip:port`.
    run(ctx, &ip.to_string()).await
}
pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, domain).await
}
pub async fn enrich_url(url: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, url).await
}
pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, hash).await
}

async fn run(ctx: &Ctx, term: &str) -> Enrichment {
    let Some(ref key) = ctx.key("ABUSE_CH_API_KEY") else {
        return Enrichment::failed("threatfox", "clé absente".into());
    };
    match fetch(&ctx.http, term, key).await {
        Ok((facts, signals)) => Enrichment {
            source: "threatfox".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("threatfox", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, term: &str, key: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let v: Value = http
        .post("https://threatfox-api.abuse.ch/api/v1/")
        .header("Auth-Key", key)
        .json(&serde_json::json!({ "query": "search_ioc", "search_term": term }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    parse(&v)
}

/// Entrée IOC de `search_ioc` — seuls les champs exploités sont déclarés.
#[derive(Debug, Deserialize)]
struct Ioc {
    threat_type: Option<String>,
    malware_printable: Option<String>,
    confidence_level: Option<i64>,
    first_seen: Option<String>,
    #[serde(default)]
    tags: Option<Vec<String>>,
}

fn parse(v: &Value) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let status = v
        .get("query_status")
        .and_then(|x| x.as_str())
        .unwrap_or("?");
    // Pas de match = réponse saine (cachable), pas une erreur. L'API renvoie
    // "no_result" ; on tolère aussi le pluriel utilisé par les APIs sœurs.
    if matches!(status, "no_result" | "no_results") {
        return Ok((vec![Fact::new("threatfox", "aucun IOC connu")], vec![]));
    }
    if status != "ok" {
        anyhow::bail!("query_status: {status}");
    }
    let iocs: Vec<Ioc> =
        serde_json::from_value(v.get("data").cloned().unwrap_or(Value::Array(vec![])))?;
    if iocs.is_empty() {
        return Ok((vec![Fact::new("threatfox", "aucun IOC connu")], vec![]));
    }

    let mut facts = vec![Fact::new("iocs", iocs.len().to_string())];
    let families = uniq_join(iocs.iter().filter_map(|i| i.malware_printable.clone()), 5);
    if !families.is_empty() {
        facts.push(Fact::new("malware", families.clone()));
    }
    let threats = uniq_join(iocs.iter().filter_map(|i| i.threat_type.clone()), 5);
    if !threats.is_empty() {
        facts.push(Fact::new("threat_type", threats));
    }
    if let Some(conf) = iocs.iter().filter_map(|i| i.confidence_level).max() {
        facts.push(Fact::new("confidence", format!("{conf}/100")));
    }
    // Format "YYYY-MM-DD hh:mm:ss UTC" → le min lexicographique est le plus ancien.
    if let Some(seen) = iocs.iter().filter_map(|i| i.first_seen.as_deref()).min() {
        facts.push(Fact::new("first_seen", seen));
    }
    let tags = uniq_join(
        iocs.iter().flat_map(|i| i.tags.clone().unwrap_or_default()),
        10,
    );
    if !tags.is_empty() {
        facts.push(Fact::new("tags", tags));
    }

    let detail = if families.is_empty() {
        "IOC référencé".to_string()
    } else {
        families
    };
    Ok((
        facts,
        vec![Signal::with_detail("threatfox", "malicious", detail)],
    ))
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
    fn parse_ok() {
        let v = serde_json::json!({
            "query_status": "ok",
            "data": [{
                "id": "41",
                "ioc": "139.180.203.104:443",
                "threat_type": "botnet_cc",
                "ioc_type": "ip:port",
                "malware": "win.cobalt_strike",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 75,
                "first_seen": "2020-12-06 09:10:23 UTC",
                "last_seen": null,
                "tags": ["c2"]
            }]
        });
        let (facts, signals) = parse(&v).unwrap();
        assert!(
            facts
                .iter()
                .any(|f| f.key == "malware" && f.value == "Cobalt Strike")
        );
        assert!(
            facts
                .iter()
                .any(|f| f.key == "confidence" && f.value == "75/100")
        );
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, "malicious");
        assert_eq!(signals[0].detail.as_deref(), Some("Cobalt Strike"));
    }

    #[test]
    fn parse_no_result() {
        // En cas d'absence de match, `data` est un texte, pas un tableau.
        let v = serde_json::json!({
            "query_status": "no_result",
            "data": "Your search did not yield any result"
        });
        let (facts, signals) = parse(&v).unwrap();
        assert_eq!(facts[0].value, "aucun IOC connu");
        assert!(signals.is_empty());
    }
}
