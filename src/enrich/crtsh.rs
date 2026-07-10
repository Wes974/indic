//! Enricher crt.sh : certificats CT → sous-domaines observés (+ pivots).

use std::collections::BTreeSet;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, domain).await {
        Ok((facts, pivots)) => Enrichment {
            source: "crtsh".into(),
            facts,
            signals: vec![],
            pivots,
            error: None,
        },
        Err(e) => Enrichment::failed("crtsh", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, domain: &str) -> Result<(Vec<Fact>, Vec<Pivot>)> {
    let resp = http
        .get("https://crt.sh/")
        .query(&[("q", domain), ("output", "json")])
        .send()
        .await?
        .error_for_status()?;
    // crt.sh peut renvoyer des centaines de Mo sur un gros domaine → borne mémoire.
    if let Some(len) = resp.content_length()
        && len > 15_000_000
    {
        anyhow::bail!("réponse crt.sh trop volumineuse ({len} octets)");
    }
    let items: Vec<Value> = resp.json().await?;

    let mut names: BTreeSet<String> = BTreeSet::new();
    for it in &items {
        if let Some(nv) = it.get("name_value").and_then(|x| x.as_str()) {
            for line in nv.split('\n') {
                let n = line.trim().trim_start_matches("*.").to_ascii_lowercase();
                if !n.is_empty() && !n.contains(' ') {
                    names.insert(n);
                }
            }
        }
    }

    let mut facts = vec![
        Fact::new("certs", items.len().to_string()),
        Fact::new("subdomains", names.len().to_string()),
    ];
    let sample: Vec<String> = names.iter().take(20).cloned().collect();
    if !sample.is_empty() {
        facts.push(Fact::new("sample", sample.join(", ")));
    }

    let pivots = names
        .iter()
        .filter(|n| n.as_str() != domain)
        .take(12)
        .map(|n| Pivot {
            relation: "subdomain".into(),
            kind: "domain".into(),
            value: n.clone(),
        })
        .collect();

    Ok((facts, pivots))
}
