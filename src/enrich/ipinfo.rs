//! IPinfo — geo ville / ASN / hostname / privacy. Clé query `token`, gated.

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("IPINFO_TOKEN") else {
        return Enrichment::failed("ipinfo", "clé absente".into());
    };
    match fetch(&ctx.http, ip, key).await {
        Ok((facts, signals)) => Enrichment {
            source: "ipinfo".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("ipinfo", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, key: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let url = format!("https://ipinfo.io/{ip}");
    let v: Value = http
        .get(&url)
        .query(&[("token", key)])
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut facts = Vec::new();
    for (label, key) in [
        ("city", "city"),
        ("region", "region"),
        ("country", "country"),
        ("org", "org"),
        ("hostname", "hostname"),
        ("timezone", "timezone"),
    ] {
        if let Some(s) = v.get(key).and_then(|x| x.as_str())
            && !s.is_empty()
        {
            facts.push(Fact::new(label, s));
        }
    }

    // `privacy` = feature payante ; présente seulement sur les plans qui l'incluent.
    let mut signals = Vec::new();
    if let Some(p) = v.get("privacy").and_then(|x| x.as_object()) {
        for flag in ["vpn", "proxy", "tor", "hosting", "relay"] {
            if p.get(flag).and_then(|x| x.as_bool()) == Some(true) {
                signals.push(Signal::with_detail("ipinfo", flag, "IPinfo privacy"));
            }
        }
    }
    if facts.is_empty() {
        facts.push(Fact::new("ipinfo", "aucune donnée"));
    }
    Ok((facts, signals))
}
