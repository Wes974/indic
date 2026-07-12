//! FullHunt — surface d'attaque d'un domaine (sous-domaines + IPs observés).
//! Header `X-API-KEY`. Descriptif (attack surface) → aucun signal. Gated (clé).

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};

const BASE: &str = "https://fullhunt.io";

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("FULLHUNT_API_KEY") else {
        return Enrichment::failed("fullhunt", "clé absente".into());
    };
    match fetch(ctx, domain, key).await {
        Ok(resp) => build(resp),
        Err(e) => Enrichment::failed("fullhunt", format!("{e:#}")),
    }
}

async fn fetch(ctx: &Ctx, domain: &str, key: &str) -> Result<Resp> {
    Ok(ctx
        .http
        .get(format!("{BASE}/api/v1/domain/{domain}/details"))
        .header("X-API-KEY", key)
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(r: Resp) -> Enrichment {
    let hosts = r.hosts.unwrap_or_default();
    let n_cloud = hosts.iter().filter(|h| h.is_cloud).count();
    let n_cdn = hosts.iter().filter(|h| h.is_cdn).count();

    let mut facts = vec![Fact::new("hosts", hosts.len().to_string())];
    if n_cloud > 0 {
        facts.push(Fact::new("cloud", n_cloud.to_string()));
    }
    if n_cdn > 0 {
        facts.push(Fact::new("cdn", n_cdn.to_string()));
    }
    // Échantillon de 10 hosts : "sub.domain (ip)".
    let sample: Vec<String> = hosts
        .iter()
        .filter(|h| !h.host.is_empty())
        .take(10)
        .map(
            |h| match h.ip_address.as_deref().filter(|s| !s.is_empty()) {
                Some(ip) => format!("{} ({ip})", h.host),
                None => h.host.clone(),
            },
        )
        .collect();
    if !sample.is_empty() {
        facts.push(Fact::new("sample", sample.join(", ")));
    }

    // Pivots : sous-domaines (max 10) + résolutions IP dédupliquées (max 5).
    let mut pivots: Vec<Pivot> = hosts
        .iter()
        .filter(|h| !h.host.is_empty())
        .take(10)
        .map(|h| Pivot {
            relation: "subdomain".into(),
            kind: "domain".into(),
            value: h.host.clone(),
        })
        .collect();
    let mut seen_ip: Vec<String> = Vec::new();
    for h in &hosts {
        let Some(ip) = h.ip_address.as_deref().filter(|s| !s.is_empty()) else {
            continue;
        };
        if !seen_ip.iter().any(|s| s == ip) {
            seen_ip.push(ip.to_string());
            pivots.push(Pivot {
                relation: "resolves_to".into(),
                kind: "ip".into(),
                value: ip.into(),
            });
            if seen_ip.len() == 5 {
                break;
            }
        }
    }

    Enrichment {
        source: "fullhunt".into(),
        facts,
        signals: vec![],
        pivots,
        error: None,
    }
}

#[derive(Deserialize)]
struct Resp {
    #[serde(default)]
    hosts: Option<Vec<Host>>,
}

#[derive(Deserialize)]
struct Host {
    #[serde(default)]
    host: String,
    ip_address: Option<String>,
    #[serde(default)]
    is_cloud: bool,
    #[serde(default)]
    is_cdn: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn host(h: &str, ip: Option<&str>, cloud: bool, cdn: bool) -> Host {
        Host {
            host: h.into(),
            ip_address: ip.map(Into::into),
            is_cloud: cloud,
            is_cdn: cdn,
        }
    }

    #[test]
    fn build_with_hosts() {
        let r = Resp {
            hosts: Some(vec![
                host("www.exemple.fr", Some("1.2.3.4"), true, false),
                host("api.exemple.fr", Some("1.2.3.4"), true, true), // même IP → dédupliquée
                host("mx.exemple.fr", Some("5.6.7.8"), false, false),
            ]),
        };
        let e = build(r);
        assert!(e.error.is_none());
        assert!(e.signals.is_empty()); // descriptif → jamais de signal
        assert!(e.facts.iter().any(|f| f.key == "hosts" && f.value == "3"));
        assert!(e.facts.iter().any(|f| f.key == "cloud" && f.value == "2"));
        assert!(e.facts.iter().any(|f| f.key == "cdn" && f.value == "1"));
        // 3 pivots sous-domaine + 2 IP distinctes.
        assert_eq!(
            e.pivots
                .iter()
                .filter(|p| p.relation == "subdomain")
                .count(),
            3
        );
        assert_eq!(
            e.pivots
                .iter()
                .filter(|p| p.relation == "resolves_to")
                .count(),
            2
        );
    }

    #[test]
    fn build_no_hosts() {
        let e = build(Resp { hosts: None });
        assert!(e.error.is_none());
        assert!(e.facts.iter().any(|f| f.key == "hosts" && f.value == "0"));
        assert!(e.pivots.is_empty());
    }
}
