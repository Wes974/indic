//! Enricher Shodan (ports, services, CVE, tags). Clé requise + requête autorisée.

use std::net::IpAddr;

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("SHODAN_API_KEY") else {
        return Enrichment::failed("shodan", "clé absente".into());
    };
    match fetch(&ctx.http, ip, key).await {
        Ok((facts, signals)) => Enrichment {
            source: "shodan".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("shodan", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, key: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let url = format!("https://api.shodan.io/shodan/host/{ip}?key={key}");
    let resp = http.get(&url).send().await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok((
            vec![Fact::new("shodan", "aucune donnée (IP non indexée)")],
            vec![],
        ));
    }
    let v: Value = resp.error_for_status()?.json().await?;

    let mut facts = Vec::new();
    let mut signals = Vec::new();

    if let Some(ports) = v.get("ports").and_then(|x| x.as_array()) {
        let list = ports
            .iter()
            .filter_map(|p| p.as_i64())
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        if !list.is_empty() {
            facts.push(Fact::new("ports", list));
        }
    }
    for (key, json_key) in [("org", "org"), ("isp", "isp"), ("os", "os")] {
        if let Some(s) = v.get(json_key).and_then(|x| x.as_str())
            && !s.is_empty()
        {
            facts.push(Fact::new(key, s));
        }
    }
    if let Some(hs) = v.get("hostnames").and_then(|x| x.as_array()) {
        let list = hs
            .iter()
            .filter_map(|h| h.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if !list.is_empty() {
            facts.push(Fact::new("hostnames", list));
        }
    }
    if let Some(tags) = v.get("tags").and_then(|x| x.as_array()) {
        let taglist: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
        if !taglist.is_empty() {
            facts.push(Fact::new("tags", taglist.join(", ")));
        }
        for t in &taglist {
            let tl = t.to_ascii_lowercase();
            if ["vpn", "tor", "proxy"].contains(&tl.as_str()) {
                signals.push(Signal::with_detail("shodan", &tl, "tag Shodan"));
            }
        }
    }
    // vulns : tableau OU objet {cve: {...}}.
    let vulns: Vec<String> = match v.get("vulns") {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(String::from))
            .collect(),
        Some(Value::Object(o)) => o.keys().cloned().collect(),
        _ => vec![],
    };
    if !vulns.is_empty() {
        let mut shown = vulns.clone();
        shown.truncate(8);
        facts.push(Fact::new(
            "vulns",
            format!("{} — {}", vulns.len(), shown.join(", ")),
        ));
    }

    if facts.is_empty() {
        facts.push(Fact::new("shodan", "aucune donnée exploitable"));
    }
    Ok((facts, signals))
}
