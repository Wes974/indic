//! ZoomEye — moteur de scan (ports, produits, ASN) pour une IP.
//! `POST api.zoomeye.ai/v2/search`, header `API-KEY`, body `qbase64` = base64 de
//! `ip="…"`. Enveloppe de réponse incertaine (`matches` ou `data`) → parse défensif.

use std::net::IpAddr;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Value, json};

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("ZOOMEYE_API_KEY") else {
        return Enrichment::failed("zoomeye", "clé absente".into());
    };
    match fetch(&ctx.http, ip, key).await {
        Ok(v) => build(&v),
        Err(e) => Enrichment::failed("zoomeye", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, key: &str) -> Result<Value> {
    let qbase64 = STANDARD.encode(format!("ip=\"{ip}\""));
    let body = json!({ "qbase64": qbase64, "page": 1, "pagesize": 20, "sub_type": "v4" });
    Ok(http
        .post("https://api.zoomeye.ai/v2/search")
        .header("API-KEY", key)
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

/// Champ potentiellement numérique OU chaîne → chaîne non vide.
fn num_or_str(v: Option<&Value>) -> Option<String> {
    match v {
        Some(Value::Number(n)) => Some(n.to_string()),
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn build(v: &Value) -> Enrichment {
    if let Some(code) = v.get("code").and_then(|x| x.as_i64())
        && code != 0
    {
        let msg = v
            .get("message")
            .and_then(|x| x.as_str())
            .unwrap_or("erreur ZoomEye");
        return Enrichment::failed("zoomeye", format!("API ZoomEye (code {code}) : {msg}"));
    }
    let rows = v
        .get("matches")
        .or_else(|| v.get("data"))
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    if rows.is_empty() {
        return Enrichment::ok("zoomeye", vec![Fact::new("zoomeye", "aucun host indexé")]);
    }

    let s = |row: &Value, k: &str| {
        row.get(k)
            .and_then(|x| x.as_str())
            .map(String::from)
            .filter(|s| !s.is_empty())
    };
    let mut ports = Vec::new();
    let mut products = Vec::new();
    let (mut org, mut asn, mut country) = (None, None, None);
    for row in &rows {
        if let Some(p) = row.get("port").and_then(|x| x.as_i64()) {
            ports.push(p.to_string());
        }
        if let Some(pr) = s(row, "product") {
            products.push(pr);
        }
        org = org.or_else(|| s(row, "organization").or_else(|| s(row, "isp")));
        asn = asn.or_else(|| num_or_str(row.get("asn")));
        country = country.or_else(|| s(row, "country"));
    }

    let mut facts = vec![Fact::new("hosts", rows.len().to_string())];
    let pj = super::dedup_join(ports, 20);
    if !pj.is_empty() {
        facts.push(Fact::new("ports", pj));
    }
    let prj = super::dedup_join(products, 8);
    if !prj.is_empty() {
        facts.push(Fact::new("products", prj));
    }
    if let Some(o) = org {
        facts.push(Fact::new("org", o));
    }
    if let Some(a) = asn {
        facts.push(Fact::new("asn", format!("AS{a}")));
    }
    if let Some(c) = country {
        facts.push(Fact::new("country", c));
    }

    Enrichment {
        source: "zoomeye".into(),
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
    fn build_matches_envelope() {
        let v = serde_json::json!({
            "code": 0,
            "matches": [
                {"ip": "1.2.3.4", "port": 443, "product": "nginx", "asn": 12345, "country": "FR", "organization": "Example"},
                {"ip": "1.2.3.4", "port": 22, "asn": "12345"}
            ]
        });
        let e = build(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "ports" && f.value.contains("443") && f.value.contains("22"))
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "asn" && f.value == "AS12345")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "products" && f.value.contains("nginx"))
        );
    }

    #[test]
    fn build_error_code() {
        let v = serde_json::json!({"code": 60000, "message": "quota exceeded"});
        let e = build(&v);
        assert!(e.error.is_some());
    }
}
