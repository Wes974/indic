//! Enricher Hudson Rock (Cavalier) : présence d'un domaine dans des logs
//! d'infostealers (employés/users compromis). Sans clé.

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, domain).await {
        Ok((facts, signals)) => Enrichment {
            source: "hudsonrock".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("hudsonrock", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, domain: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let url = format!(
        "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-domain?domain={domain}"
    );
    let v: Value = http
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut facts = Vec::new();
    let mut total = 0i64;
    for (label, key) in [
        ("employees", "employees"),
        ("users", "users"),
        ("third_parties", "third_parties"),
        ("total", "total"),
    ] {
        if let Some(n) = v.get(key).and_then(|x| x.as_i64()) {
            facts.push(Fact::new(label, n.to_string()));
            if key == "total" {
                total = n;
            }
        }
    }

    let mut signals = Vec::new();
    if total > 0 {
        signals.push(Signal::with_detail(
            "hudsonrock",
            "infostealer",
            format!("{total} compromissions"),
        ));
    }
    if facts.is_empty() {
        facts.push(Fact::new("hudsonrock", "aucune donnée"));
    }
    Ok((facts, signals))
}

pub async fn enrich_email(email: &str, ctx: &Ctx) -> Enrichment {
    match fetch_email(&ctx.http, email).await {
        Ok((facts, signals)) => Enrichment {
            source: "hudsonrock".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("hudsonrock", format!("{e:#}")),
    }
}

async fn fetch_email(http: &reqwest::Client, email: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let v: Value = http
        .get("https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email")
        .query(&[("email", email)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut facts = Vec::new();
    let mut signals = Vec::new();
    if let Some(msg) = v.get("message").and_then(|x| x.as_str()) {
        facts.push(Fact::new("status", msg));
    }
    let stealers = v
        .get("stealers")
        .and_then(|x| x.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    if stealers > 0 {
        facts.push(Fact::new("stealers", stealers.to_string()));
        signals.push(Signal::with_detail(
            "hudsonrock",
            "infostealer",
            format!("{stealers} infections"),
        ));
    }
    if facts.is_empty() {
        facts.push(Fact::new("hudsonrock", "aucune donnée"));
    }
    Ok((facts, signals))
}
