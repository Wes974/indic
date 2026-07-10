//! RIPEstat — infos ASN (holder, préfixes annoncés, contact abuse). Sans clé.
//! Les préfixes deviennent des pivots ASN → CIDR.

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};

pub async fn enrich_asn(asn: u32, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, asn).await {
        Ok((facts, pivots)) => Enrichment {
            source: "ripestat".into(),
            facts,
            signals: vec![],
            pivots,
            error: None,
        },
        Err(e) => Enrichment::failed("ripestat", format!("{e:#}")),
    }
}

async fn get(http: &reqwest::Client, path: &str, resource: &str) -> Result<Value> {
    Ok(http
        .get(format!("https://stat.ripe.net/data/{path}/data.json"))
        .query(&[("resource", resource)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

async fn fetch(http: &reqwest::Client, asn: u32) -> Result<(Vec<Fact>, Vec<Pivot>)> {
    let res = format!("AS{asn}");
    let mut facts = Vec::new();
    let mut pivots = Vec::new();

    let overview = get(http, "as-overview", &res).await?;
    if let Some(d) = overview.get("data") {
        if let Some(h) = d.get("holder").and_then(|x| x.as_str()) {
            facts.push(Fact::new("holder", h));
        }
        if let Some(b) = d
            .get("block")
            .and_then(|x| x.get("name"))
            .and_then(|x| x.as_str())
        {
            facts.push(Fact::new("rir_block", b));
        }
    }

    if let Ok(pf) = get(http, "announced-prefixes", &res).await
        && let Some(prefixes) = pf
            .get("data")
            .and_then(|d| d.get("prefixes"))
            .and_then(|x| x.as_array())
    {
        facts.push(Fact::new("prefixes", prefixes.len().to_string()));
        let sample: Vec<&str> = prefixes
            .iter()
            .filter_map(|p| p.get("prefix").and_then(|x| x.as_str()))
            .take(6)
            .collect();
        if !sample.is_empty() {
            facts.push(Fact::new("sample", sample.join(", ")));
        }
        for p in prefixes
            .iter()
            .filter_map(|p| p.get("prefix").and_then(|x| x.as_str()))
            .take(5)
        {
            pivots.push(Pivot {
                relation: "announces".into(),
                kind: "cidr".into(),
                value: p.to_string(),
            });
        }
    }

    if let Ok(ab) = get(http, "abuse-contact-finder", &res).await
        && let Some(contacts) = ab
            .get("data")
            .and_then(|d| d.get("abuse_contacts"))
            .and_then(|x| x.as_array())
    {
        let list = contacts
            .iter()
            .filter_map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if !list.is_empty() {
            facts.push(Fact::new("abuse_contact", list));
        }
    }

    if facts.is_empty() {
        facts.push(Fact::new("ripestat", "aucune donnée"));
    }
    Ok((facts, pivots))
}
