//! Netlas — moteur de scan Internet (ports, logiciels, ASN, géo) pour une IP.
//! `GET app.netlas.io/api/host/{ip}/`, `Authorization: Bearer <key>`. Gated.

use std::net::IpAddr;

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("NETLAS_API_KEY") else {
        return Enrichment::failed("netlas", "clé absente".into());
    };
    match fetch(&ctx.http, ip, key).await {
        Ok(v) => build(&v),
        Err(e) => Enrichment::failed("netlas", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, key: &str) -> Result<Value> {
    let url = format!("https://app.netlas.io/api/host/{ip}/");
    let resp = http
        .get(&url)
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(Value::Null);
    }
    Ok(resp.error_for_status()?.json().await?)
}

fn build(v: &Value) -> Enrichment {
    if v.is_null() || v.get("ip").is_none() {
        return Enrichment::ok(
            "netlas",
            vec![Fact::new("netlas", "aucune donnée (IP non indexée)")],
        );
    }
    let mut facts = Vec::new();

    if let Some(ports) = v.get("ports").and_then(|x| x.as_array()) {
        let list = ports
            .iter()
            .filter_map(|p| p.get("port").and_then(|x| x.as_i64()))
            .map(|p| p.to_string());
        let joined = super::dedup_join(list, 20);
        if !joined.is_empty() {
            facts.push(Fact::new("ports", joined));
        }
    }
    if let Some(sw) = v.get("software").and_then(|x| x.as_array()) {
        let names = sw
            .iter()
            .flat_map(|s| {
                s.get("tag")
                    .and_then(|t| t.as_array())
                    .cloned()
                    .unwrap_or_default()
            })
            .filter_map(|t| t.get("name").and_then(|n| n.as_str()).map(String::from));
        let joined = super::dedup_join(names, 8);
        if !joined.is_empty() {
            facts.push(Fact::new("software", joined));
        }
    }
    if let Some(org) = v
        .get("organization")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
    {
        facts.push(Fact::new("org", org));
    }
    if let Some(asn) = v
        .get("whois")
        .and_then(|w| w.get("asn"))
        .and_then(|a| a.get("num"))
        .and_then(|n| n.as_i64())
    {
        facts.push(Fact::new("asn", format!("AS{asn}")));
    }
    if let Some(country) = v
        .get("geo")
        .and_then(|g| g.get("country"))
        .and_then(|c| c.get("name").or_else(|| c.get("iso_code")))
        .and_then(|x| x.as_str())
    {
        facts.push(Fact::new("country", country));
    }

    if facts.is_empty() {
        facts.push(Fact::new("netlas", "aucune donnée exploitable"));
    }
    Enrichment {
        source: "netlas".into(),
        facts,
        signals: vec![],
        pivots: vec![],
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_extracts_ports_asn_software() {
        let v = serde_json::json!({
            "ip": "1.2.3.4",
            "organization": "Example ISP",
            "ports": [{"port": 443}, {"port": 80}],
            "software": [{"tag": [{"name": "nginx"}]}],
            "whois": {"asn": {"num": 12345}},
            "geo": {"country": {"name": "France"}}
        });
        let e = build(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "ports" && f.value.contains("443"))
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "asn" && f.value == "AS12345")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "software" && f.value.contains("nginx"))
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "country" && f.value == "France")
        );
    }

    #[test]
    fn build_empty_on_null() {
        let e = build(&Value::Null);
        assert!(e.error.is_none());
        assert!(e.facts.iter().any(|f| f.value.contains("aucune donnée")));
    }
}
