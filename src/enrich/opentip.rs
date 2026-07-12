//! Kaspersky OpenTIP — réputation IP (zone Red/Orange/Yellow/Grey/Green) + catégories.
//! `GET opentip.kaspersky.com/api/v1/search/ip?request={ip}`, header `x-api-key`. Gated.

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("KASPERSKY_OPENTIP_KEY") else {
        return Enrichment::failed("opentip", "clé absente".into());
    };
    match fetch(&ctx.http, ip, key).await {
        Ok(v) => build(&v),
        Err(e) => Enrichment::failed("opentip", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, key: &str) -> Result<Value> {
    let url = format!("https://opentip.kaspersky.com/api/v1/search/ip?request={ip}");
    Ok(http
        .get(&url)
        .header("x-api-key", key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(v: &Value) -> Enrichment {
    let zone = v.get("Zone").and_then(|x| x.as_str()).unwrap_or("Grey");
    let mut facts = vec![Fact::new("zone", zone)];

    if let Some(info) = v.get("IpGeneralInfo") {
        if let Some(cc) = info
            .get("CountryCode")
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
        {
            facts.push(Fact::new("country", cc));
        }
        if let Some(hits) = info
            .get("HitsCount")
            .and_then(|x| x.as_i64())
            .filter(|n| *n > 0)
        {
            facts.push(Fact::new("hits", hits.to_string()));
        }
        if let Some(cats) = info.get("Categories").and_then(|x| x.as_array()) {
            let joined =
                super::dedup_join(cats.iter().filter_map(|c| c.as_str().map(String::from)), 8);
            if !joined.is_empty() {
                facts.push(Fact::new("categories", joined));
            }
        }
    }
    if let Some(asn) = v
        .get("IpWhoIs")
        .and_then(|w| w.get("Asn"))
        .and_then(|a| a.get("Number"))
        .and_then(|n| n.as_i64())
    {
        facts.push(Fact::new("asn", format!("AS{asn}")));
    }

    // Zone Kaspersky → signal (Grey = pas de donnée, Green = sain → aucun signal).
    let mut signals = Vec::new();
    let category = match zone.to_ascii_lowercase().as_str() {
        "red" => Some("malicious"),
        "orange" | "yellow" => Some("suspicious"),
        _ => None,
    };
    if let Some(c) = category {
        signals.push(Signal::with_detail(
            "opentip",
            c,
            format!("zone Kaspersky {zone}"),
        ));
    }

    Enrichment {
        source: "opentip".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_red_zone_malicious() {
        let v = serde_json::json!({
            "Zone": "Red",
            "IpGeneralInfo": {"CountryCode": "RU", "HitsCount": 42, "Categories": ["Malware", "Botnet"]},
            "IpWhoIs": {"Asn": {"Number": 12345}}
        });
        let e = build(&v);
        assert!(e.facts.iter().any(|f| f.key == "zone" && f.value == "Red"));
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "categories" && f.value.contains("Malware"))
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "asn" && f.value == "AS12345")
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
    }

    #[test]
    fn build_green_no_signal() {
        let v = serde_json::json!({"Zone": "Green", "IpGeneralInfo": {"CountryCode": "FR"}});
        let e = build(&v);
        assert!(e.signals.is_empty());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "zone" && f.value == "Green")
        );
    }
}
