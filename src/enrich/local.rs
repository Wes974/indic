//! Enricher « datasets locaux » : le moteur IP offline (ASN, infra, VPN/Tor/proxy).

use std::net::IpAddr;

use crate::enrich::Ctx;
use crate::model::{AnonType, InfraType, IpReport};

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> IpReport {
    let store = ctx.store.load();
    store.lookup(&ip.to_string()).unwrap_or_else(|_| IpReport {
        ip: ip.to_string(),
        asn: None,
        as_name: None,
        country: None,
        infra_type: InfraType::Unknown,
        anonymous: false,
        anon_type: AnonType::Unknown,
        provider: None,
        confidence: 0.0,
        signals: vec![],
    })
}
