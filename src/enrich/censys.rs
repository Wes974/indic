//! Censys Platform — inventaire host (ASN, géoloc, services/ports exposés).
//! Header `Authorization: Bearer`. Schéma nested/optionnel → parse défensif en
//! `serde_json::Value`. Purement descriptif (pas de signal). Gated (token).

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("CENSYS_API_KEY") else {
        return Enrichment::failed("censys", "clé absente".into());
    };
    match fetch(ctx, ip, key).await {
        Ok(e) => e,
        Err(e) => Enrichment::failed("censys", format!("{e:#}")),
    }
}

async fn fetch(ctx: &Ctx, ip: IpAddr, key: &str) -> Result<Enrichment> {
    let url = format!("https://api.platform.censys.io/v3/global/asset/host/{ip}");
    let v: Value = ctx
        .http
        .get(url.as_str())
        .header("Authorization", format!("Bearer {key}"))
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(build(&v))
}

fn build(v: &Value) -> Enrichment {
    let Some(res) = v.pointer("/result/resource") else {
        return Enrichment::ok("censys", vec![Fact::new("censys", "aucune donnée")]);
    };
    let mut facts = Vec::new();

    // ASN + nom.
    if let Some(asys) = res.get("autonomous_system") {
        let asn = asys.get("asn").and_then(|x| x.as_i64());
        let name = asys
            .get("name")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty());
        let label = match (asn, name) {
            (Some(n), Some(nm)) => format!("{nm} (AS{n})"),
            (Some(n), None) => format!("AS{n}"),
            (None, Some(nm)) => nm.to_string(),
            (None, None) => String::new(),
        };
        if !label.is_empty() {
            facts.push(Fact::new("asn", label));
        }
    }

    // Pays : géoloc en priorité, repli sur le pays de l'AS.
    let country = res
        .pointer("/location/country")
        .and_then(|x| x.as_str())
        .or_else(|| {
            res.pointer("/autonomous_system/country_code")
                .and_then(|x| x.as_str())
        })
        .filter(|s| !s.is_empty());
    if let Some(c) = country {
        facts.push(Fact::new("country", c));
    }
    if let Some(city) = res
        .pointer("/location/city")
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
    {
        facts.push(Fact::new("city", city));
    }

    // Services : compte + échantillon de ports (12 max, triés/dédupliqués).
    if let Some(services) = res.get("services").and_then(|x| x.as_array()) {
        if !services.is_empty() {
            facts.push(Fact::new("services", services.len().to_string()));
        }
        let mut ports: Vec<i64> = services
            .iter()
            .filter_map(|s| s.get("port").and_then(|x| x.as_i64()))
            .collect();
        ports.sort_unstable();
        ports.dedup();
        if !ports.is_empty() {
            let shown = ports
                .iter()
                .take(12)
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            facts.push(Fact::new("ports", shown));
        }
    }

    if facts.is_empty() {
        facts.push(Fact::new("censys", "aucune donnée exploitable"));
    }
    Enrichment {
        source: "censys".into(),
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
    fn build_full_resource() {
        let v = serde_json::json!({
            "result": {
                "resource": {
                    "autonomous_system": { "asn": 15169, "name": "GOOGLE", "country_code": "US" },
                    "location": { "country": "United States", "city": "Mountain View" },
                    "services": [
                        { "port": 443, "service_name": "HTTP" },
                        { "port": 80, "protocol": "HTTP" },
                        { "port": 443, "extended_service_name": "HTTPS" }
                    ]
                }
            }
        });
        let e = build(&v);
        assert!(e.signals.is_empty()); // descriptif
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "asn" && f.value == "GOOGLE (AS15169)")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "country" && f.value == "United States")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "services" && f.value == "3")
        );
        // ports triés + dédupliqués.
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "ports" && f.value == "80, 443")
        );
    }

    #[test]
    fn build_no_result() {
        let v = serde_json::json!({ "error": "not found" });
        let e = build(&v);
        assert!(e.error.is_none());
        assert_eq!(e.facts[0].value, "aucune donnée");
    }
}
