//! Enricher rDNS (PTR) via DNS-over-HTTPS Cloudflare — pas de crate DNS.

use std::net::IpAddr;

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    match query_ptr(&ctx.http, ip).await {
        Ok(hosts) if !hosts.is_empty() => {
            let mut facts = Vec::new();
            let mut pivots = Vec::new();
            for h in hosts {
                facts.push(Fact::new("ptr", h.clone()));
                pivots.push(Pivot {
                    relation: "resolves_to".into(),
                    kind: "domain".into(),
                    value: h,
                });
            }
            Enrichment {
                source: "rdns".into(),
                facts,
                signals: vec![],
                pivots,
                error: None,
            }
        }
        Ok(_) => Enrichment::ok("rdns", vec![Fact::new("ptr", "(aucun)")]),
        Err(e) => Enrichment::failed("rdns", format!("{e:#}")),
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

async fn query_ptr(http: &reqwest::Client, ip: IpAddr) -> Result<Vec<String>> {
    let url = format!(
        "https://cloudflare-dns.com/dns-query?name={}&type=PTR",
        ptr_name(ip)
    );
    let resp: DohResp = http
        .get(&url)
        .header("accept", "application/dns-json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let hosts = resp
        .answer
        .into_iter()
        .filter(|a| a.rtype == 12) // PTR
        .map(|a| a.data.trim_end_matches('.').to_string())
        .filter(|s| !s.is_empty())
        .collect();
    Ok(hosts)
}

/// Nom PTR : `d.c.b.a.in-addr.arpa` (v4) ou nibbles `…ip6.arpa` (v6).
fn ptr_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}
