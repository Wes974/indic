//! Enricher DShield / SANS ISC : signalements d'attaques sur une IP. Sans clé.

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, ip).await {
        Ok((facts, signals)) => Enrichment {
            source: "dshield".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("dshield", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let url = format!("https://isc.sans.edu/api/ip/{ip}?json");
    let v: Value = http
        .get(&url)
        .header("User-Agent", "indic")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let d = v
        .get("ip")
        .ok_or_else(|| anyhow::anyhow!("réponse ISC vide"))?;

    let mut facts = Vec::new();
    let mut signals = Vec::new();
    let count = d.get("count").and_then(|x| x.as_i64());
    if let Some(c) = count {
        facts.push(Fact::new("reports", c.to_string()));
    }
    if let Some(a) = d.get("attacks").and_then(|x| x.as_i64()) {
        facts.push(Fact::new("targets", a.to_string()));
    }
    if let Some(tf) = d.get("threatfeeds").and_then(|x| x.as_object()) {
        let names: Vec<String> = tf.keys().cloned().collect();
        if !names.is_empty() {
            facts.push(Fact::new("threatfeeds", names.join(", ")));
            signals.push(Signal::with_detail(
                "dshield",
                "threat",
                format!("{} feeds", names.len()),
            ));
        }
    }
    if count.unwrap_or(0) > 0 && signals.is_empty() {
        signals.push(Signal::with_detail("dshield", "abuse", "signalé DShield"));
    }
    if facts.is_empty() {
        facts.push(Fact::new("dshield", "aucun signalement"));
    }
    Ok((facts, signals))
}
