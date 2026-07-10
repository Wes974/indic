//! AlienVault OTX — pulses de threat intel pour IP / domaine / hash / URL.
//! Header `X-OTX-API-KEY`. Gated (token).

use std::net::IpAddr;

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

const BASE: &str = "https://otx.alienvault.com";

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    // OTX expose des endpoints distincts par famille d'IP (IPv4 vs IPv6).
    let fam = if ip.is_ipv6() { "IPv6" } else { "IPv4" };
    run(ctx, format!("/api/v1/indicators/{fam}/{ip}/general")).await
}

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, format!("/api/v1/indicators/domain/{domain}/general")).await
}

pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, format!("/api/v1/indicators/file/{hash}/general")).await
}

pub async fn enrich_url(url: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, format!("/api/v1/indicators/url/{url}/general")).await
}

async fn run(ctx: &Ctx, path: String) -> Enrichment {
    let Some(key) = ctx.key("OTX_API_KEY") else {
        return Enrichment::failed("otx", "clé absente".into());
    };
    match fetch(ctx, &path, key).await {
        Ok(resp) => build(resp),
        Err(e) => Enrichment::failed("otx", format!("{e:#}")),
    }
}

async fn fetch(ctx: &Ctx, path: &str, key: &str) -> Result<Resp> {
    Ok(ctx
        .http
        .get(format!("{BASE}{path}"))
        .header("X-OTX-API-KEY", key)
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(r: Resp) -> Enrichment {
    let info = r.pulse_info.unwrap_or_default();
    let mut facts = vec![Fact::new("pulses", info.count.to_string())];

    // Noms des 5 premiers pulses.
    let names: Vec<String> = info
        .pulses
        .iter()
        .take(5)
        .filter_map(|p| p.name.clone())
        .filter(|s| !s.is_empty())
        .collect();
    if !names.is_empty() {
        facts.push(Fact::new("names", names.join(" | ")));
    }

    // Tags dédupliqués (ordre conservé), 10 max.
    let mut tags: Vec<String> = Vec::new();
    for t in info.pulses.iter().flat_map(|p| &p.tags) {
        if !t.is_empty() && !tags.contains(t) {
            tags.push(t.clone());
        }
    }
    tags.truncate(10);
    if !tags.is_empty() {
        facts.push(Fact::new("tags", tags.join(", ")));
    }

    let mut signals = Vec::new();
    if info.count > 0 {
        signals.push(Signal::with_detail(
            "otx",
            "suspicious",
            format!("{} pulses", info.count),
        ));
    }
    Enrichment {
        source: "otx".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[derive(Deserialize)]
struct Resp {
    pulse_info: Option<PulseInfo>,
}

#[derive(Deserialize, Default)]
struct PulseInfo {
    #[serde(default)]
    count: i64,
    #[serde(default)]
    pulses: Vec<Pulse>,
}

#[derive(Deserialize)]
struct Pulse {
    name: Option<String>,
    #[serde(default)]
    tags: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_with_pulses() {
        let r = Resp {
            pulse_info: Some(PulseInfo {
                count: 2,
                pulses: vec![
                    Pulse {
                        name: Some("Cobalt Strike C2".into()),
                        tags: vec!["c2".into(), "apt".into()],
                    },
                    Pulse {
                        name: Some("Emotet".into()),
                        tags: vec!["apt".into(), "malware".into()],
                    },
                ],
            }),
        };
        let e = build(r);
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "suspicious");
        assert_eq!(e.signals[0].detail.as_deref(), Some("2 pulses"));
        // "apt" dédupliqué.
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "tags" && f.value == "c2, apt, malware")
        );
        assert!(e.facts.iter().any(|f| f.key == "names"));
    }

    #[test]
    fn build_no_pulses() {
        let r = Resp {
            pulse_info: Some(PulseInfo {
                count: 0,
                pulses: vec![],
            }),
        };
        let e = build(r);
        assert!(e.signals.is_empty());
        assert!(e.facts.iter().any(|f| f.key == "pulses" && f.value == "0"));
    }
}
