//! Scamalytics — score de fraude IP (0-100) + niveau de risque + flags proxy.
//! Compte perso : user (dans l'URL) + clé (query). Gated (token). API v3.

use std::net::IpAddr;

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

/// Hostname d'API spécifique au compte (visible dans le dashboard Scamalytics).
/// À changer ici si le compte est réassigné à un autre nœud (apiN).
const HOST: &str = "api12.scamalytics.com";

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let (Some(user), Some(key)) = (
        ctx.key("SCAMALYTICS_API_USER"),
        ctx.key("SCAMALYTICS_API_KEY"),
    ) else {
        return Enrichment::failed("scamalytics", "user/clé absent".into());
    };
    match fetch(ctx, user, key, ip).await {
        Ok(e) => e,
        Err(e) => Enrichment::failed("scamalytics", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(ctx: &Ctx, user: &str, key: &str, ip: IpAddr) -> Result<Enrichment> {
    let ip_s = ip.to_string();
    let url = format!("https://{HOST}/v3/{user}/");
    let resp: Resp = ctx
        .http
        .get(url.as_str())
        .query(&[("key", key), ("ip", ip_s.as_str())])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(build(resp.scamalytics))
}

fn build(sc: Sc) -> Enrichment {
    if sc.status.as_deref() != Some("ok") {
        return Enrichment::failed(
            "scamalytics",
            format!("statut API : {}", sc.status.unwrap_or_else(|| "?".into())),
        );
    }
    let score = sc.scamalytics_score.unwrap_or(-1);
    let risk = sc.scamalytics_risk.unwrap_or_default();

    let mut facts = vec![Fact::new("score", format!("{score}/100"))];
    if !risk.is_empty() {
        facts.push(Fact::new("risk", risk.clone()));
    }
    if let Some(isp) = sc.scamalytics_isp.filter(|s| !s.is_empty()) {
        facts.push(Fact::new("isp", isp));
    }
    let mut flags = Vec::new();
    if let Some(p) = &sc.scamalytics_proxy {
        if p.is_datacenter {
            flags.push("datacenter");
        }
        if p.is_vpn {
            flags.push("vpn");
        }
        if p.is_tor {
            flags.push("tor");
        }
        if p.is_apple_icloud_private_relay {
            flags.push("icloud-relay");
        }
    }
    if !flags.is_empty() {
        facts.push(Fact::new("proxy", flags.join(", ")));
    }
    if sc.is_blacklisted_external == Some(true) {
        facts.push(Fact::new(
            "blacklist",
            "listée (blacklist externe Scamalytics)",
        ));
    }

    // Signal selon le niveau de risque déclaré par Scamalytics.
    let mut signals = Vec::new();
    let category = match risk.to_ascii_lowercase().as_str() {
        "medium" => Some("suspicious"),
        "high" | "very high" => Some("malicious"),
        _ => None,
    };
    if let Some(cat) = category {
        signals.push(Signal::with_detail(
            "scamalytics",
            cat,
            format!("risk {risk} (score {score}/100)"),
        ));
    }

    Enrichment {
        source: "scamalytics".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[derive(Deserialize)]
struct Resp {
    scamalytics: Sc,
}

#[derive(Deserialize)]
struct Sc {
    status: Option<String>,
    scamalytics_score: Option<i64>,
    scamalytics_risk: Option<String>,
    scamalytics_isp: Option<String>,
    scamalytics_proxy: Option<Proxy>,
    is_blacklisted_external: Option<bool>,
}

#[derive(Deserialize)]
struct Proxy {
    #[serde(default)]
    is_datacenter: bool,
    #[serde(default)]
    is_vpn: bool,
    #[serde(default)]
    is_tor: bool,
    #[serde(default)]
    is_apple_icloud_private_relay: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_datacenter_low() {
        let sc = Sc {
            status: Some("ok".into()),
            scamalytics_score: Some(0),
            scamalytics_risk: Some("low".into()),
            scamalytics_isp: Some("Google LLC".into()),
            scamalytics_proxy: Some(Proxy {
                is_datacenter: true,
                is_vpn: false,
                is_tor: false,
                is_apple_icloud_private_relay: false,
            }),
            is_blacklisted_external: Some(false),
        };
        let e = build(sc);
        assert!(e.error.is_none());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "proxy" && f.value == "datacenter")
        );
        assert!(e.signals.is_empty()); // risk low → pas de signal
    }

    #[test]
    fn build_high_risk_signal() {
        let sc = Sc {
            status: Some("ok".into()),
            scamalytics_score: Some(88),
            scamalytics_risk: Some("very high".into()),
            scamalytics_isp: None,
            scamalytics_proxy: None,
            is_blacklisted_external: Some(true),
        };
        let e = build(sc);
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
    }
}
