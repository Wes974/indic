//! Enricher RDAP (allocation, org, registrant) via le bootstrap public rdap.org.

use std::net::IpAddr;

use anyhow::Result;

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, ip).await {
        Ok(facts) => Enrichment::ok("rdap", facts),
        Err(e) => Enrichment::failed("rdap", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr) -> Result<Vec<Fact>> {
    let url = format!("https://rdap.org/ip/{ip}");
    let v: serde_json::Value = http
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut facts = Vec::new();
    for (key, json_key) in [
        ("rdap_name", "name"),
        ("handle", "handle"),
        ("country", "country"),
        ("type", "type"),
    ] {
        if let Some(s) = v.get(json_key).and_then(|x| x.as_str())
            && !s.is_empty()
        {
            facts.push(Fact::new(key, s));
        }
    }
    if let (Some(a), Some(b)) = (
        v.get("startAddress").and_then(|x| x.as_str()),
        v.get("endAddress").and_then(|x| x.as_str()),
    ) {
        facts.push(Fact::new("range", format!("{a} – {b}")));
    }
    // Registrant : premier entity avec le rôle "registrant".
    if let Some(entities) = v.get("entities").and_then(|x| x.as_array()) {
        for e in entities {
            let is_registrant = e
                .get("roles")
                .and_then(|r| r.as_array())
                .is_some_and(|roles| roles.iter().any(|x| x.as_str() == Some("registrant")));
            if is_registrant
                && let Some(h) = e.get("handle").and_then(|x| x.as_str())
                && !h.is_empty()
            {
                facts.push(Fact::new("registrant", h));
                break;
            }
        }
    }

    if facts.is_empty() {
        anyhow::bail!("réponse RDAP vide");
    }
    Ok(facts)
}
