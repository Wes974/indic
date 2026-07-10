//! Gravatar — profil public associé à un email (hash SHA256). GRATUIT, sans clé.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_email(email: &str, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, email).await {
        Ok(facts) => Enrichment::ok("gravatar", facts),
        Err(e) => Enrichment::failed("gravatar", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, email: &str) -> Result<Vec<Fact>> {
    let hash = hex_sha256(email.trim().to_ascii_lowercase().as_bytes());
    let url = format!("https://gravatar.com/{hash}.json");
    let resp = http.get(&url).header("User-Agent", "indic").send().await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(vec![Fact::new("gravatar", "aucun profil")]);
    }
    let v: Value = resp.error_for_status()?.json().await?;
    let entry = v
        .get("entry")
        .and_then(|x| x.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| anyhow::anyhow!("profil vide"))?;

    let mut facts = vec![Fact::new("gravatar", "profil trouvé")];
    if let Some(n) = entry.get("displayName").and_then(|x| x.as_str()) {
        facts.push(Fact::new("name", n));
    }
    if let Some(loc) = entry.get("currentLocation").and_then(|x| x.as_str())
        && !loc.is_empty()
    {
        facts.push(Fact::new("location", loc));
    }
    if let Some(u) = entry.get("profileUrl").and_then(|x| x.as_str()) {
        facts.push(Fact::new("profile", u));
    }
    if let Some(accts) = entry.get("accounts").and_then(|x| x.as_array()) {
        let list = accts
            .iter()
            .filter_map(|a| a.get("shortname").and_then(|x| x.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        if !list.is_empty() {
            facts.push(Fact::new("linked_accounts", list));
        }
    }
    Ok(facts)
}

fn hex_sha256(input: &[u8]) -> String {
    let digest = Sha256::digest(input);
    let mut s = String::with_capacity(64);
    for b in digest {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
