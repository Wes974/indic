//! AbuseIPDB — score d'abus + catégories. Clé header `Key`, gated.

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("ABUSEIPDB_API_KEY") else {
        return Enrichment::failed("abuseipdb", "clé absente".into());
    };
    match fetch(&ctx.http, ip, key).await {
        Ok((facts, signals)) => Enrichment {
            source: "abuseipdb".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("abuseipdb", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, key: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let ip_s = ip.to_string();
    let v: Value = http
        .get("https://api.abuseipdb.com/api/v2/check")
        .query(&[("ipAddress", ip_s.as_str()), ("maxAgeInDays", "90")])
        .header("Key", key)
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let d = v
        .get("data")
        .ok_or_else(|| anyhow::anyhow!("réponse AbuseIPDB vide"))?;

    let mut facts = Vec::new();
    let mut signals = Vec::new();
    let score = d
        .get("abuseConfidenceScore")
        .and_then(|x| x.as_i64())
        .unwrap_or(0);
    facts.push(Fact::new("abuse_score", format!("{score}/100")));
    if let Some(r) = d.get("totalReports").and_then(|x| x.as_i64()) {
        facts.push(Fact::new("reports", r.to_string()));
    }
    if let Some(u) = d.get("usageType").and_then(|x| x.as_str()) {
        facts.push(Fact::new("usage", u));
    }
    if let Some(i) = d.get("isp").and_then(|x| x.as_str()) {
        facts.push(Fact::new("isp", i));
    }
    if d.get("isTor").and_then(|x| x.as_bool()) == Some(true) {
        signals.push(Signal::with_detail("abuseipdb", "tor", "AbuseIPDB"));
    }
    if score >= 50 {
        signals.push(Signal::with_detail(
            "abuseipdb",
            "abuse",
            format!("score {score}"),
        ));
    }
    Ok((facts, signals))
}
