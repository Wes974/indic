//! Enricher StopForumSpam : IP connue comme spammeur/abuseur. Sans clé.

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, ip).await {
        Ok((facts, signals)) => Enrichment {
            source: "stopforumspam".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("stopforumspam", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let url = format!("https://api.stopforumspam.org/api?ip={ip}&json");
    let v: Value = http
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let d = v
        .get("ip")
        .ok_or_else(|| anyhow::anyhow!("réponse SFS vide"))?;

    let appears = d.get("appears").and_then(|x| x.as_i64()).unwrap_or(0);
    let mut facts = vec![Fact::new("appears", appears.to_string())];
    if let Some(freq) = d.get("frequency").and_then(|x| x.as_i64()) {
        facts.push(Fact::new("frequency", freq.to_string()));
    }
    if let Some(ls) = d.get("lastseen").and_then(|x| x.as_str()) {
        facts.push(Fact::new("lastseen", ls));
    }

    let mut signals = Vec::new();
    if appears > 0 {
        signals.push(Signal::with_detail(
            "stopforumspam",
            "abuse",
            "spammeur connu",
        ));
    }
    Ok((facts, signals))
}

pub async fn enrich_email(email: &str, ctx: &Ctx) -> Enrichment {
    match fetch_email(&ctx.http, email).await {
        Ok((facts, signals)) => Enrichment {
            source: "stopforumspam".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("stopforumspam", format!("{e:#}")),
    }
}

async fn fetch_email(http: &reqwest::Client, email: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let v: Value = http
        .get("https://api.stopforumspam.org/api?json")
        .query(&[("email", email)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let d = v
        .get("email")
        .ok_or_else(|| anyhow::anyhow!("réponse SFS vide"))?;

    let appears = d.get("appears").and_then(|x| x.as_i64()).unwrap_or(0);
    let mut facts = vec![Fact::new("appears", appears.to_string())];
    if let Some(freq) = d.get("frequency").and_then(|x| x.as_i64()) {
        facts.push(Fact::new("frequency", freq.to_string()));
    }
    if let Some(ls) = d.get("lastseen").and_then(|x| x.as_str()) {
        facts.push(Fact::new("lastseen", ls));
    }
    let mut signals = Vec::new();
    if appears > 0 {
        signals.push(Signal::with_detail(
            "stopforumspam",
            "abuse",
            "email spammeur",
        ));
    }
    Ok((facts, signals))
}
