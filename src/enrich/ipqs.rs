//! IPQualityScore — fraud score + proxy/VPN/Tor. Clé dans le path, gated.

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("IPQUALITYSCORE_API_KEY") else {
        return Enrichment::failed("ipqs", "clé absente".into());
    };
    match fetch(&ctx.http, ip, key).await {
        Ok((facts, signals)) => Enrichment {
            source: "ipqs".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("ipqs", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, key: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let url = format!("https://ipqualityscore.com/api/json/ip/{key}/{ip}");
    let v: Value = http
        .get(&url)
        .query(&[("strictness", "1")])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if v.get("success").and_then(|x| x.as_bool()) == Some(false) {
        anyhow::bail!(
            "{}",
            v.get("message")
                .and_then(|x| x.as_str())
                .unwrap_or("échec IPQS")
        );
    }

    let mut facts = Vec::new();
    let mut signals = Vec::new();
    if let Some(fs) = v.get("fraud_score").and_then(|x| x.as_i64()) {
        facts.push(Fact::new("fraud_score", format!("{fs}/100")));
        if fs >= 85 {
            signals.push(Signal::with_detail("ipqs", "abuse", format!("fraud {fs}")));
        }
    }
    for flag in [
        "proxy",
        "vpn",
        "tor",
        "recent_abuse",
        "bot_status",
        "is_crawler",
    ] {
        if v.get(flag).and_then(|x| x.as_bool()) == Some(true) {
            let cat = match flag {
                "proxy" => "proxy",
                "vpn" => "vpn",
                "tor" => "tor",
                _ => "abuse",
            };
            signals.push(Signal::with_detail("ipqs", cat, flag));
        }
    }
    for (label, key) in [
        ("isp", "ISP"),
        ("organization", "organization"),
        ("country", "country_code"),
        ("connection", "connection_type"),
    ] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str())
            && !s.is_empty()
        {
            facts.push(Fact::new(label, s));
        }
    }
    Ok((facts, signals))
}
