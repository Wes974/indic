//! Enricher géo (ville, coords, ISP) via ip-api.com — gratuit, sans clé.

use std::net::IpAddr;

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, ip).await {
        Ok(facts) => Enrichment::ok("geo", facts),
        Err(e) => Enrichment::failed("geo", format!("{e:#}")),
    }
}

#[derive(Deserialize)]
struct IpApi {
    #[serde(default)]
    status: String,
    #[serde(default)]
    message: String,
    #[serde(default)]
    country: String,
    #[serde(default, rename = "regionName")]
    region_name: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    lat: f64,
    #[serde(default)]
    lon: f64,
    #[serde(default)]
    isp: String,
    #[serde(default)]
    org: String,
    #[serde(default)]
    timezone: String,
}

async fn fetch(http: &reqwest::Client, ip: IpAddr) -> Result<Vec<Fact>> {
    let url = format!(
        "http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,lat,lon,isp,org,timezone"
    );
    let r: IpApi = http
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    if r.status != "success" {
        anyhow::bail!(
            "ip-api: {}",
            if r.message.is_empty() {
                "échec"
            } else {
                &r.message
            }
        );
    }

    let mut facts = Vec::new();
    let loc = [r.city.as_str(), r.region_name.as_str(), r.country.as_str()]
        .iter()
        .filter(|s| !s.is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    if !loc.is_empty() {
        facts.push(Fact::new("location", loc));
    }
    if r.lat != 0.0 || r.lon != 0.0 {
        facts.push(Fact::new("coords", format!("{:.4}, {:.4}", r.lat, r.lon)));
    }
    if !r.isp.is_empty() {
        facts.push(Fact::new("isp", r.isp));
    }
    if !r.org.is_empty() {
        facts.push(Fact::new("org", r.org));
    }
    if !r.timezone.is_empty() {
        facts.push(Fact::new("timezone", r.timezone));
    }
    if facts.is_empty() {
        anyhow::bail!("géo vide");
    }
    Ok(facts)
}
