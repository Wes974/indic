//! Pulsedive — threat intel IOC (IP, domaine) : risque + menaces + feeds.
//! `GET pulsedive.com/api/indicator.php?indicator=&key=`. Clé en query. Gated.
//! Inconnu = HTTP 404. NB : les hashes ne sont PAS supportés (404) → pas d'`enrich_hash`.

use std::net::IpAddr;

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    run(ctx, &ip.to_string()).await
}
pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, domain).await
}

async fn run(ctx: &Ctx, indicator: &str) -> Enrichment {
    let Some(ref key) = ctx.key("PULSEDIVE_API_KEY") else {
        return Enrichment::failed("pulsedive", "clé absente".into());
    };
    match fetch(&ctx.http, indicator, key).await {
        Ok(Some(v)) => build(&v),
        Ok(None) => Enrichment::ok(
            "pulsedive",
            vec![Fact::new("pulsedive", "indicateur inconnu")],
        ),
        Err(e) => Enrichment::failed("pulsedive", super::scrub(format!("{e:#}"), key)),
    }
}

/// `Ok(None)` = HTTP 404 (indicateur absent de la base Pulsedive).
async fn fetch(http: &reqwest::Client, indicator: &str, key: &str) -> Result<Option<Value>> {
    let resp = http
        .get("https://pulsedive.com/api/indicator.php")
        .query(&[("indicator", indicator), ("key", key)])
        .send()
        .await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }
    Ok(Some(resp.error_for_status()?.json().await?))
}

fn build(v: &Value) -> Enrichment {
    if let Some(err) = v.get("error").and_then(|x| x.as_str()) {
        return Enrichment::ok("pulsedive", vec![Fact::new("pulsedive", err)]);
    }
    let risk = v.get("risk").and_then(|x| x.as_str()).unwrap_or("unknown");
    let mut facts = vec![Fact::new("risk", risk)];

    let names = |field: &str| -> Vec<String> {
        v.get(field)
            .and_then(|x| x.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    };
    let threats = names("threats");
    if !threats.is_empty() {
        facts.push(Fact::new("menaces", super::dedup_join(threats, 6)));
    }
    let feeds = names("feeds");
    if !feeds.is_empty() {
        facts.push(Fact::new("feeds", super::dedup_join(feeds, 5)));
    }

    let mut signals = Vec::new();
    let cat = match risk {
        "critical" | "high" => Some("malicious"),
        "medium" => Some("suspicious"),
        _ => None, // low / none / unknown
    };
    if let Some(c) = cat {
        signals.push(Signal::with_detail(
            "pulsedive",
            c,
            format!("risque {risk}"),
        ));
    }

    Enrichment {
        source: "pulsedive".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_high_risk_malicious() {
        let v = serde_json::json!({
            "risk": "high", "threats": [{"name": "Emotet"}], "feeds": [{"name": "Abuse.ch"}]
        });
        let e = build(&v);
        assert!(e.facts.iter().any(|f| f.key == "risk" && f.value == "high"));
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "menaces" && f.value.contains("Emotet"))
        );
        assert_eq!(e.signals[0].category, "malicious");
    }

    #[test]
    fn build_none_no_signal() {
        let e = build(&serde_json::json!({"risk": "none"}));
        assert!(e.signals.is_empty());
        assert!(e.facts.iter().any(|f| f.key == "risk" && f.value == "none"));
    }
}
