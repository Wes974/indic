//! Enricher Wayback Machine : plus proche snapshot archivé d'un domaine/URL. Sans clé.

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_domain(target: &str, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, target).await {
        Ok(facts) => Enrichment::ok("wayback", facts),
        Err(e) => Enrichment::failed("wayback", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, target: &str) -> Result<Vec<Fact>> {
    // `.query()` encode `target` (une URL peut contenir ?, &, # qui casseraient la query).
    let v: Value = http
        .get("https://archive.org/wayback/available")
        .query(&[("url", target)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    match v.get("archived_snapshots").and_then(|x| x.get("closest")) {
        Some(c) => {
            let mut facts = Vec::new();
            if let Some(ts) = c.get("timestamp").and_then(|x| x.as_str()) {
                facts.push(Fact::new("closest_snapshot", ts));
            }
            if let Some(u) = c.get("url").and_then(|x| x.as_str()) {
                facts.push(Fact::new("snapshot_url", u));
            }
            if facts.is_empty() {
                facts.push(Fact::new("wayback", "snapshot sans détail"));
            }
            Ok(facts)
        }
        None => Ok(vec![Fact::new("wayback", "aucun snapshot archivé")]),
    }
}
