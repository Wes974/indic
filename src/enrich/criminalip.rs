//! Criminal IP — score inbound/outbound + is_vpn/proxy/tor. Header `x-api-key`, gated.

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("CRIMINALIP_API_KEY") else {
        return Enrichment::failed("criminalip", "clé absente".into());
    };
    match fetch(&ctx.http, ip, key).await {
        Ok((facts, signals)) => Enrichment {
            source: "criminalip".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("criminalip", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, key: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let ip_s = ip.to_string();
    let v: Value = http
        .get("https://api.criminalip.io/v1/asset/ip/report")
        .query(&[("ip", ip_s.as_str())])
        .header("x-api-key", key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut facts = Vec::new();
    let mut signals = Vec::new();
    if let Some(score) = v.get("score") {
        if let Some(i) = score.get("inbound").and_then(|x| x.as_str()) {
            facts.push(Fact::new("inbound_score", i));
        }
        if let Some(o) = score.get("outbound").and_then(|x| x.as_str()) {
            facts.push(Fact::new("outbound_score", o));
        }
    }
    if let Some(issues) = v.get("issues").and_then(|x| x.as_object()) {
        for (flag, cat) in [("is_vpn", "vpn"), ("is_proxy", "proxy"), ("is_tor", "tor")] {
            if issues.get(flag).and_then(|x| x.as_bool()) == Some(true) {
                signals.push(Signal::with_detail("criminalip", cat, "Criminal IP"));
            }
        }
        let active: Vec<&str> = issues
            .iter()
            .filter(|(_, val)| val.as_bool() == Some(true))
            .map(|(k, _)| k.as_str())
            .collect();
        if !active.is_empty() {
            facts.push(Fact::new("issues", active.join(", ")));
        }
    }
    if facts.is_empty() && signals.is_empty() {
        facts.push(Fact::new("criminalip", "aucune donnée"));
    }
    Ok((facts, signals))
}
