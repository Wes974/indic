//! Enricher DNS (A/AAAA/MX/NS/TXT) via DoH Cloudflare. A/AAAA → pivots IP.

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    let types = [
        ("A", 1u16),
        ("AAAA", 28),
        ("MX", 15),
        ("NS", 2),
        ("TXT", 16),
    ];
    let mut facts = Vec::new();
    let mut pivots = Vec::new();
    let mut any = false;
    let mut last_err = None;

    for (label, qtype) in types {
        match query(&ctx.http, domain, qtype).await {
            Ok(vals) if !vals.is_empty() => {
                any = true;
                facts.push(Fact::new(label, vals.join(", ")));
                if label == "A" || label == "AAAA" {
                    for v in &vals {
                        pivots.push(Pivot {
                            relation: "resolves_to".into(),
                            kind: "ip".into(),
                            value: v.clone(),
                        });
                    }
                }
            }
            Ok(_) => {}
            Err(e) => last_err = Some(format!("{e:#}")),
        }
    }

    if !any {
        return match last_err {
            Some(e) => Enrichment::failed("dns", e),
            None => Enrichment::ok("dns", vec![Fact::new("dns", "aucun enregistrement")]),
        };
    }
    Enrichment {
        source: "dns".into(),
        facts,
        signals: vec![],
        pivots,
        error: None,
    }
}

#[derive(Deserialize)]
struct DohResp {
    #[serde(rename = "Answer", default)]
    answer: Vec<DohAnswer>,
}

#[derive(Deserialize)]
struct DohAnswer {
    #[serde(rename = "type")]
    rtype: u16,
    data: String,
}

async fn query(http: &reqwest::Client, domain: &str, qtype: u16) -> Result<Vec<String>> {
    let resp: DohResp = http
        .get("https://cloudflare-dns.com/dns-query")
        .query(&[("name", domain)])
        .query(&[("type", qtype)])
        .header("accept", "application/dns-json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(resp
        .answer
        .into_iter()
        .filter(|a| a.rtype == qtype)
        .map(|a| a.data.trim_end_matches('.').to_string())
        .collect())
}
