//! Onyphe — moteur de recherche CTI : scan ports/services + threat list + geo.
//! Auth header `Authorization: apikey $KEY`, gated.
//! Free tier: 1000 req/mois. Endpoints summary IP et domaine.

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(key) = &ctx.key("ONYPHE_API_KEY") else {
        return Enrichment::failed("onyphe", "clé absente".into());
    };
    match fetch(&ctx.http, &format!("ip/{}", ip), key).await {
        Ok((facts, signals)) => Enrichment {
            source: "onyphe".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("onyphe", format!("{e:#}")),
    }
}

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    let Some(key) = &ctx.key("ONYPHE_API_KEY") else {
        return Enrichment::failed("onyphe", "clé absente".into());
    };
    match fetch(&ctx.http, &format!("domain/{}", domain), key).await {
        Ok((facts, signals)) => Enrichment {
            source: "onyphe".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("onyphe", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, path: &str, key: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let v: Value = http
        .get(format!("https://www.onyphe.io/api/v2/summary/{}", path))
        .header("Authorization", format!("apikey {}", key))
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    parse(&v)
}

fn parse(v: &Value) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let results = v
        .get("results")
        .and_then(|r| r.as_array())
        .cloned()
        .unwrap_or_default();

    let mut facts = Vec::new();
    let mut signals = Vec::new();
    let mut tags: Vec<String> = Vec::new();
    let mut threats: Vec<String> = Vec::new();

    // Scan count (total de résultats agrégeant toutes les catégories).
    if let Some(c) = v.get("count").and_then(|x| x.as_i64()) {
        facts.push(Fact::new("scans", c.to_string()));
    }

    for result in &results {
        // Catégories de données Onyphe (sniffer, ctl, threatlist, geoloc…).
        if let Some(cat) = result.get("@category").and_then(|x| x.as_str()) {
            push_unique(&mut tags, cat);
        }

        // Géolocalisation.
        if let Some(country) = result.get("country").and_then(|x| x.as_str()) {
            facts.push(Fact::new("country", country));
        }
        if let Some(city) = result.get("city").and_then(|x| x.as_str()) {
            facts.push(Fact::new("city", city));
        }

        // ASN / organisation.
        if let Some(asn) = result.get("asn").and_then(|x| x.as_str()) {
            facts.push(Fact::new("asn", asn));
        }
        if let Some(org) = result.get("organization").and_then(|x| x.as_str()) {
            facts.push(Fact::new("org", org));
        }

        // Threatlist : chaque entrée a un champ `tag` (ex: "mirai", "c2"…).
        if let Some(arr) = result.get("threatlist").and_then(|x| x.as_array()) {
            for threat in arr {
                if let Some(tag) = threat.get("tag").and_then(|x| x.as_str()) {
                    push_unique(&mut threats, tag);
                }
            }
        }

        // Tags plats (alternative selon les catégories).
        if let Some(arr) = result.get("tags").and_then(|x| x.as_array()) {
            for t in arr {
                if let Some(tag) = t.as_str() {
                    push_unique(&mut tags, tag);
                }
            }
        }
    }

    if !tags.is_empty() {
        facts.push(Fact::new("categories", tags.join(", ")));
    }

    if !threats.is_empty() {
        signals.push(Signal::with_detail("onyphe", "threat", threats.join(", ")));
    }

    Ok((facts, signals))
}

fn push_unique(dest: &mut Vec<String>, val: &str) {
    if !dest.iter().any(|s| s == val) {
        dest.push(val.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ip_summary_empty() {
        let json = serde_json::json!({
            "count": 0,
            "error": 0,
            "results": []
        });
        let (facts, signals) = parse(&json).unwrap();
        assert!(facts.iter().any(|f| f.key == "scans" && f.value == "0"));
        assert!(signals.is_empty());
    }

    #[test]
    fn parse_ip_summary_with_threats() {
        let json = serde_json::json!({
            "count": 3,
            "results": [
                {
                    "@category": "threatlist",
                    "@timestamp": "2026-07-10T00:00:00.000Z",
                    "threatlist": [
                        {"tag": "mirai", "category": "IoT Botnet"},
                        {"tag": "c2", "category": "C2"}
                    ],
                    "country": "CN",
                    "asn": "AS4134"
                },
                {
                    "@category": "sniffer",
                    "@timestamp": "2026-07-12T00:00:00.000Z",
                    "country": "CN",
                    "city": "Beijing",
                    "organization": "ChinaNet"
                },
                {
                    "@category": "geoloc",
                    "@timestamp": "2026-07-14T00:00:00.000Z",
                    "country": "CN",
                    "city": "Shanghai",
                    "tags": ["china", "high-risk"]
                }
            ]
        });
        let (facts, signals) = parse(&json).unwrap();

        assert!(facts.iter().any(|f| f.key == "scans" && f.value == "3"));
        assert!(facts.iter().any(|f| f.key == "asn" && f.value == "AS4134"));
        assert!(facts.iter().any(|f| f.key == "country" && f.value == "CN"));
        assert!(
            facts
                .iter()
                .any(|f| f.key == "city" && f.value == "Beijing")
        );
        assert!(
            facts
                .iter()
                .any(|f| f.key == "org" && f.value == "ChinaNet")
        );
        assert!(
            facts
                .iter()
                .any(|f| f.key == "categories" && f.value.contains("threatlist"))
        );

        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, "threat");
        assert!(
            signals[0]
                .detail
                .as_ref()
                .is_some_and(|d| d.contains("mirai") && d.contains("c2"))
        );
    }

    #[test]
    fn parse_domain_without_threats() {
        let json = serde_json::json!({
            "count": 2,
            "results": [
                {
                    "@category": "ctl",
                    "@timestamp": "2026-07-15T00:00:00.000Z",
                    "domain": "example.com",
                    "tags": ["cdn", "cloudflare"]
                }
            ]
        });
        let (facts, signals) = parse(&json).unwrap();

        assert!(facts.iter().any(|f| f.key == "scans" && f.value == "2"));
        assert!(
            facts
                .iter()
                .any(|f| f.key == "categories" && f.value.contains("cdn"))
        );
        assert!(signals.is_empty());
    }
}
