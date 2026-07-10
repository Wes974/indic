//! Shodan InternetDB — ports / CPE / tags / vulns d'une IP. GRATUIT, sans clé.
//! Les vulns deviennent des pivots IP → CVE.

use std::net::IpAddr;

use anyhow::Result;
use reqwest::StatusCode;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};
use crate::model::Signal;

#[derive(Deserialize)]
struct Idb {
    #[serde(default)]
    ports: Vec<i64>,
    #[serde(default)]
    cpes: Vec<String>,
    #[serde(default)]
    hostnames: Vec<String>,
    #[serde(default)]
    tags: Vec<String>,
    #[serde(default)]
    vulns: Vec<String>,
}

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, ip).await {
        Ok((facts, signals, pivots)) => Enrichment {
            source: "internetdb".into(),
            facts,
            signals,
            pivots,
            error: None,
        },
        Err(e) => Enrichment::failed("internetdb", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr) -> Result<(Vec<Fact>, Vec<Signal>, Vec<Pivot>)> {
    let url = format!("https://internetdb.shodan.io/{ip}");
    let resp = http.get(&url).send().await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok((
            vec![Fact::new("internetdb", "aucune donnée")],
            vec![],
            vec![],
        ));
    }
    let d: Idb = resp.error_for_status()?.json().await?;

    let mut facts = Vec::new();
    let mut signals = Vec::new();
    let mut pivots = Vec::new();

    if !d.ports.is_empty() {
        let list = d
            .ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        facts.push(Fact::new("ports", list));
    }
    if !d.hostnames.is_empty() {
        facts.push(Fact::new("hostnames", d.hostnames.join(", ")));
    }
    if !d.tags.is_empty() {
        facts.push(Fact::new("tags", d.tags.join(", ")));
        for t in &d.tags {
            let tl = t.to_ascii_lowercase();
            if ["vpn", "tor", "proxy"].contains(&tl.as_str()) {
                signals.push(Signal::with_detail("internetdb", &tl, "tag"));
            }
        }
    }
    if !d.vulns.is_empty() {
        let n = d.vulns.len();
        let mut shown = d.vulns.clone();
        shown.truncate(8);
        facts.push(Fact::new("vulns", format!("{n} — {}", shown.join(", "))));
        signals.push(Signal::with_detail(
            "internetdb",
            "vuln",
            format!("{n} CVE"),
        ));
        for cve in d.vulns.iter().take(10) {
            pivots.push(Pivot {
                relation: "vulnerable_to".into(),
                kind: "cve".into(),
                value: cve.clone(),
            });
        }
    }
    if !d.cpes.is_empty() {
        let mut shown = d.cpes.clone();
        shown.truncate(5);
        facts.push(Fact::new("cpes", shown.join(", ")));
    }
    if facts.is_empty() {
        facts.push(Fact::new("internetdb", "aucune donnée"));
    }
    Ok((facts, signals, pivots))
}
