//! Quake (360) — moteur de scan (ports, services, hostnames) pour une IP.
//! `POST quake.360.net/api/v3/search/quake_service`, header `X-QuakeToken`,
//! body `query = ip:"…"`. Gated. Pivote vers les domaines observés.

use std::net::IpAddr;

use anyhow::Result;
use serde_json::{Value, json};

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("QUAKE_API_KEY") else {
        return Enrichment::failed("quake", "clé absente".into());
    };
    match fetch(&ctx.http, ip, key).await {
        Ok(v) => build(&v),
        Err(e) => Enrichment::failed("quake", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, key: &str) -> Result<Value> {
    let body = json!({
        "query": format!("ip:\"{ip}\""),
        "start": 0,
        "size": 20,
        "ignore_cache": false,
        "include": ["ip", "port", "hostname", "domain", "asn", "service.name"]
    });
    Ok(http
        .post("https://quake.360.net/api/v3/search/quake_service")
        .header("X-QuakeToken", key)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(v: &Value) -> Enrichment {
    if let Some(code) = v.get("code").and_then(|x| x.as_i64())
        && code != 0
    {
        let msg = v
            .get("message")
            .and_then(|x| x.as_str())
            .unwrap_or("erreur Quake");
        return Enrichment::failed("quake", format!("API Quake (code {code}) : {msg}"));
    }
    let rows = v
        .get("data")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    if rows.is_empty() {
        return Enrichment::ok("quake", vec![Fact::new("quake", "aucun host indexé")]);
    }

    let s = |row: &Value, k: &str| {
        row.get(k)
            .and_then(|x| x.as_str())
            .map(String::from)
            .filter(|s| !s.is_empty())
    };
    let mut ports = Vec::new();
    let mut services = Vec::new();
    let mut hostnames = Vec::new();
    let mut domains = Vec::new();
    let mut asn = None;
    for row in &rows {
        if let Some(p) = row.get("port").and_then(|x| x.as_i64()) {
            ports.push(p.to_string());
        }
        if let Some(sv) = row
            .get("service")
            .and_then(|s| s.get("name"))
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
        {
            services.push(sv.to_string());
        }
        if let Some(h) = s(row, "hostname") {
            hostnames.push(h);
        }
        if let Some(d) = s(row, "domain") {
            domains.push(d);
        }
        asn = asn.or_else(|| row.get("asn").and_then(|x| x.as_i64()));
    }

    let mut facts = vec![Fact::new("hosts", rows.len().to_string())];
    let pj = super::dedup_join(ports, 20);
    if !pj.is_empty() {
        facts.push(Fact::new("ports", pj));
    }
    let sj = super::dedup_join(services, 8);
    if !sj.is_empty() {
        facts.push(Fact::new("services", sj));
    }
    let hj = super::dedup_join(hostnames, 5);
    if !hj.is_empty() {
        facts.push(Fact::new("hostnames", hj));
    }
    if let Some(a) = asn {
        facts.push(Fact::new("asn", format!("AS{a}")));
    }

    // Pivots vers les domaines observés sur l'IP.
    let mut seen: Vec<String> = Vec::new();
    let mut pivots = Vec::new();
    for d in domains {
        if !seen.contains(&d) {
            seen.push(d.clone());
            pivots.push(Pivot {
                relation: "resolves".into(),
                kind: "domain".into(),
                value: d,
            });
            if pivots.len() == 5 {
                break;
            }
        }
    }

    Enrichment {
        source: "quake".into(),
        facts,
        signals: vec![],
        pivots,
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_extracts_services_and_pivots() {
        let v = serde_json::json!({
            "code": 0,
            "data": [
                {"ip": "1.2.3.4", "port": 443, "domain": "example.com", "asn": 12345,
                 "service": {"name": "http/ssl"}},
                {"ip": "1.2.3.4", "port": 80, "hostname": "web.example.com",
                 "service": {"name": "http"}}
            ]
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
                .any(|f| f.key == "services" && f.value.contains("http/ssl"))
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "asn" && f.value == "AS12345")
        );
        assert!(
            e.pivots
                .iter()
                .any(|p| p.value == "example.com" && p.kind == "domain")
        );
    }

    #[test]
    fn build_error_code() {
        let v = serde_json::json!({"code": 4001, "message": "token invalid"});
        let e = build(&v);
        assert!(e.error.is_some());
    }
}
