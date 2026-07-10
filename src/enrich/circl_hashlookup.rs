//! Enricher CIRCL hashlookup : hash connu (NSRL known-good / malveillant). Sans clé.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, hash).await {
        Ok(facts) => Enrichment::ok("hashlookup", facts),
        Err(e) => Enrichment::failed("hashlookup", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, hash: &str) -> Result<Vec<Fact>> {
    let algo = match hash.len() {
        32 => "md5",
        40 => "sha1",
        64 => "sha256",
        _ => return Ok(vec![Fact::new("hashlookup", "format de hash inconnu")]),
    };
    let url = format!("https://hashlookup.circl.lu/lookup/{algo}/{hash}");
    let resp = http
        .get(&url)
        .header("accept", "application/json")
        .send()
        .await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(vec![Fact::new(
            "hashlookup",
            "inconnu (ni NSRL ni base malveillante)",
        )]);
    }
    let v: Value = resp.error_for_status()?.json().await?;
    // CIRCL renvoie {"message":"Non existing..."} quand introuvable.
    if v.get("message").is_some() {
        return Ok(vec![Fact::new("hashlookup", "inconnu")]);
    }

    let mut facts = vec![Fact::new("hashlookup", "connu")];
    if let Some(name) = v.get("FileName").and_then(|x| x.as_str()) {
        facts.push(Fact::new("filename", name));
    }
    if let Some(src) = v.get("source").and_then(|x| x.as_str()) {
        facts.push(Fact::new("source", src));
    }
    if let Some(km) = v.get("KnownMalicious") {
        facts.push(Fact::new("malicious", km.to_string()));
    }
    if let Some(trust) = v.get("hashlookup:trust") {
        facts.push(Fact::new("trust", trust.to_string()));
    }
    Ok(facts)
}
