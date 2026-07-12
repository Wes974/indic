//! vpnapi.io — détection VPN/proxy/tor/relay + org de l'ASN.
//! Clé en query `key`. Gated (token).

use std::net::IpAddr;

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("VPNAPI_KEY") else {
        return Enrichment::failed("vpnapi", "clé absente".into());
    };
    match fetch(ctx, ip, key).await {
        Ok(e) => e,
        Err(e) => Enrichment::failed("vpnapi", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(ctx: &Ctx, ip: IpAddr, key: &str) -> Result<Enrichment> {
    let url = format!("https://vpnapi.io/api/{ip}");
    let resp: Resp = ctx
        .http
        .get(url.as_str())
        .query(&[("key", key)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(build(resp))
}

fn build(r: Resp) -> Enrichment {
    let mut facts = Vec::new();
    if let Some(org) = r
        .network
        .and_then(|n| n.autonomous_system_organization)
        .filter(|s| !s.is_empty())
    {
        facts.push(Fact::new("org", org));
    }

    let sec = r.security.unwrap_or_default();
    // Catégorie du signal = le type d'anonymisation détecté.
    let mut signals = Vec::new();
    let mut active = Vec::new();
    for (flag, cat) in [
        (sec.vpn, "vpn"),
        (sec.proxy, "proxy"),
        (sec.tor, "tor"),
        (sec.relay, "relay"),
    ] {
        if flag {
            active.push(cat);
            signals.push(Signal::with_detail("vpnapi", cat, "vpnapi.io"));
        }
    }
    if !active.is_empty() {
        facts.push(Fact::new("flags", active.join(", ")));
    }

    if facts.is_empty() {
        facts.push(Fact::new("vpnapi", "aucun flag"));
    }
    Enrichment {
        source: "vpnapi".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[derive(Deserialize)]
struct Resp {
    security: Option<Security>,
    network: Option<Network>,
}

#[derive(Deserialize, Default)]
struct Security {
    #[serde(default)]
    vpn: bool,
    #[serde(default)]
    proxy: bool,
    #[serde(default)]
    tor: bool,
    #[serde(default)]
    relay: bool,
}

#[derive(Deserialize)]
struct Network {
    autonomous_system_organization: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_vpn_flag() {
        let r = Resp {
            security: Some(Security {
                vpn: true,
                ..Default::default()
            }),
            network: Some(Network {
                autonomous_system_organization: Some("Google LLC".into()),
            }),
        };
        let e = build(r);
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "vpn");
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "org" && f.value == "Google LLC")
        );
        assert!(e.facts.iter().any(|f| f.key == "flags" && f.value == "vpn"));
    }

    #[test]
    fn build_clean_no_signal() {
        let r = Resp {
            security: Some(Security::default()),
            network: None,
        };
        let e = build(r);
        assert!(e.signals.is_empty());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "vpnapi" && f.value == "aucun flag")
        );
    }
}
