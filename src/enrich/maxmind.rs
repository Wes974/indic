//! Enricher géo offline (MaxMind GeoLite2-City) : ville, région, pays, coordonnées.
//! Lit la base mmdb chargée dans le store (aucun réseau).

use std::net::IpAddr;

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let Some(g) = ctx.store.load().geoip_city(ip) else {
        return Enrichment::ok(
            "maxmind",
            vec![Fact::new("maxmind", "non localisée (ou base absente)")],
        );
    };
    let mut facts = Vec::new();
    if let Some(city) = g.city {
        facts.push(Fact::new("ville", city));
    }
    if let Some(region) = g.region {
        facts.push(Fact::new("région", region));
    }
    if let Some(country) = g.country {
        facts.push(Fact::new("pays", country));
    }
    if let (Some(lat), Some(lon)) = (g.lat, g.lon) {
        facts.push(Fact::new("coordonnées", format!("{lat:.4}, {lon:.4}")));
    }
    if facts.is_empty() {
        facts.push(Fact::new("maxmind", "pas de géo précise"));
    }
    Enrichment {
        source: "maxmind".into(),
        facts,
        signals: vec![],
        pivots: vec![],
        error: None,
    }
}
