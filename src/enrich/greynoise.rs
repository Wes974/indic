//! Enricher GreyNoise Community : scanner de masse vs benign vs connu.

use std::net::IpAddr;

use anyhow::Result;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("GREYNOISE_API_KEY") else {
        return Enrichment::failed("greynoise", "clé absente".into());
    };
    match fetch(&ctx.http, ip, key).await {
        Ok((facts, signals)) => Enrichment {
            source: "greynoise".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("greynoise", format!("{e:#}")),
    }
}

#[derive(Deserialize)]
struct Community {
    #[serde(default)]
    noise: bool,
    #[serde(default)]
    riot: bool,
    #[serde(default)]
    classification: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    last_seen: String,
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, key: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let url = format!("https://api.greynoise.io/v3/community/{ip}");
    let resp = http.get(&url).header("key", key).send().await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok((
            vec![Fact::new("greynoise", "non observé (pas de bruit)")],
            vec![],
        ));
    }
    let c: Community = resp.error_for_status()?.json().await?;

    let mut facts = vec![
        Fact::new("noise", c.noise.to_string()),
        Fact::new("riot", c.riot.to_string()),
    ];
    if !c.classification.is_empty() {
        facts.push(Fact::new("classification", c.classification.as_str()));
    }
    if !c.name.is_empty() {
        facts.push(Fact::new("name", c.name.as_str()));
    }
    if !c.last_seen.is_empty() {
        facts.push(Fact::new("last_seen", c.last_seen.as_str()));
    }

    let mut signals = Vec::new();
    if c.classification == "malicious" {
        signals.push(Signal::with_detail(
            "greynoise",
            "malicious",
            "classification GreyNoise",
        ));
    } else if c.noise {
        signals.push(Signal::with_detail(
            "greynoise",
            "scanner",
            "bruit Internet",
        ));
    }
    Ok((facts, signals))
}
