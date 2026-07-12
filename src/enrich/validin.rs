//! Validin — historique DNS d'un domaine (résolutions A/AAAA, NS, MX) via
//! `GET app.validin.com/api/axon/domain/dns/history/{domain}`, `Authorization: Bearer`.
//! Gated. Quota gratuit très serré (~10/jour → TTL long). Pivote vers les IP résolues.

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("VALIDIN_API_KEY") else {
        return Enrichment::failed("validin", "clé absente".into());
    };
    match fetch(&ctx.http, domain, key).await {
        Ok(v) => build(&v),
        Err(e) => Enrichment::failed("validin", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, domain: &str, key: &str) -> Result<Value> {
    let url = format!("https://app.validin.com/api/axon/domain/dns/history/{domain}");
    Ok(http
        .get(&url)
        .query(&[("limit", "200")])
        .bearer_auth(key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(v: &Value) -> Enrichment {
    let Some(records) = v.get("records").and_then(|x| x.as_object()) else {
        return Enrichment::ok("validin", vec![Fact::new("validin", "aucune donnée DNS")]);
    };

    // Valeurs uniques (dans l'ordre) d'un type d'enregistrement.
    let values = |rtype: &str| -> Vec<String> {
        let mut out: Vec<String> = Vec::new();
        if let Some(arr) = records.get(rtype).and_then(|x| x.as_array()) {
            for rec in arr {
                if let Some(val) = rec
                    .get("value")
                    .and_then(|x| x.as_str())
                    .filter(|s| !s.is_empty())
                {
                    let val = val.to_string();
                    if !out.contains(&val) {
                        out.push(val);
                    }
                }
            }
        }
        out
    };

    let a = values("A");
    let aaaa = values("AAAA");
    let ns = values("NS");
    let mx = values("MX");

    let mut facts = Vec::new();
    if !a.is_empty() {
        facts.push(Fact::new("résolutions", a.len().to_string()));
        facts.push(Fact::new("IPs", super::dedup_join(a.clone(), 10)));
    }
    if !aaaa.is_empty() {
        facts.push(Fact::new("IPv6", super::dedup_join(aaaa.clone(), 5)));
    }
    if !ns.is_empty() {
        facts.push(Fact::new("NS", super::dedup_join(ns, 6)));
    }
    if !mx.is_empty() {
        facts.push(Fact::new("MX", super::dedup_join(mx, 4)));
    }
    if facts.is_empty() {
        facts.push(Fact::new("validin", "aucun enregistrement exploitable"));
    }

    // Pivots vers les IP résolues (A + AAAA), bornés.
    let pivots: Vec<Pivot> = a
        .into_iter()
        .chain(aaaa)
        .take(15)
        .map(|ip| Pivot {
            relation: "resolves".into(),
            kind: "ip".into(),
            value: ip,
        })
        .collect();

    Enrichment {
        source: "validin".into(),
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
    fn build_extracts_a_ns_and_pivots() {
        let v = serde_json::json!({
            "status": "finished",
            "records": {
                "A": [
                    {"key": "github.com", "value": "20.26.156.215", "value_type": "ip4"},
                    {"key": "github.com", "value": "20.205.243.166", "value_type": "ip4"}
                ],
                "NS": [{"key": "github.com", "value": "ns1.example.net", "value_type": "dom"}]
            }
        });
        let e = build(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "IPs" && f.value.contains("20.26.156.215"))
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "NS" && f.value.contains("ns1.example.net"))
        );
        assert_eq!(e.pivots.iter().filter(|p| p.kind == "ip").count(), 2);
    }

    #[test]
    fn build_no_records() {
        let e = build(&serde_json::json!({"status": "finished"}));
        assert!(e.error.is_none());
        assert!(e.facts.iter().any(|f| f.value.contains("aucune donnée")));
    }
}
