//! FOFA — moteur de scan (ports, produits, ASN) pour une IP.
//! `GET fofa.info/api/v1/search/all` : email+key en query, `qbase64` = base64 de
//! `ip="…"`, résultats = array-of-arrays aligné sur `fields`. Gated.
//! NB : l'API FOFA exige un compte membre (pas le tier gratuit de base) → une
//! erreur applicative « membership » est remontée proprement.

use std::net::IpAddr;

use anyhow::Result;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};

/// Champs demandés, dans cet ordre — l'API renvoie les valeurs alignées dessus.
/// FOFA restreint beaucoup de champs au tier payant (erreur 820001 sur
/// as_number/as_organization/server/product) → on ne garde que le socle gratuit.
const FIELDS: &str = "ip,port,protocol,country_name";

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    let (Some(ref email), Some(ref key)) = (ctx.key("FOFA_EMAIL"), ctx.key("FOFA_KEY")) else {
        return Enrichment::failed("fofa", "email/clé absent".into());
    };
    match fetch(&ctx.http, ip, email, key).await {
        Ok(v) => build(&v),
        Err(e) => Enrichment::failed("fofa", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, ip: IpAddr, email: &str, key: &str) -> Result<Value> {
    let qbase64 = STANDARD.encode(format!("ip=\"{ip}\""));
    Ok(http
        .get("https://fofa.info/api/v1/search/all")
        .query(&[
            ("email", email),
            ("key", key),
            ("qbase64", qbase64.as_str()),
            ("fields", FIELDS),
            ("size", "100"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(v: &Value) -> Enrichment {
    if v.get("error").and_then(|x| x.as_bool()) == Some(true) {
        let msg = v
            .get("errmsg")
            .and_then(|x| x.as_str())
            .unwrap_or("erreur FOFA");
        // L'errmsg d'origine est en chinois → traduit les codes courants.
        let human = if msg.contains("820031") {
            "crédits F-point épuisés — recharge du compte FOFA nécessaire"
        } else if msg.contains("820001") {
            "champ réservé au tier payant FOFA"
        } else {
            msg
        };
        return Enrichment::failed("fofa", format!("FOFA : {human}"));
    }
    let rows = v
        .get("results")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    if rows.is_empty() {
        return Enrichment::ok("fofa", vec![Fact::new("fofa", "aucun host indexé")]);
    }

    // FIELDS: ip0 port1 protocol2 country_name3 (le reste est premium)
    let cell = |row: &Value, i: usize| {
        row.get(i)
            .and_then(|x| x.as_str())
            .map(String::from)
            .filter(|s| !s.is_empty())
    };
    let mut ports = Vec::new();
    let mut country = None;
    for row in &rows {
        if let Some(p) = cell(row, 1) {
            ports.push(p);
        }
        country = country.or_else(|| cell(row, 3));
    }

    let mut facts = vec![Fact::new("hosts", rows.len().to_string())];
    let pj = super::dedup_join(ports, 20);
    if !pj.is_empty() {
        facts.push(Fact::new("ports", pj));
    }
    if let Some(c) = country {
        facts.push(Fact::new("country", c));
    }

    Enrichment {
        source: "fofa".into(),
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
    fn build_aggregates_rows() {
        let v = serde_json::json!({
            "error": false,
            "results": [
                ["1.2.3.4", "443", "https", "France"],
                ["1.2.3.4", "80", "http", "France"]
            ]
        });
        let e = build(&v);
        assert!(e.facts.iter().any(|f| f.key == "hosts" && f.value == "2"));
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "ports" && f.value.contains("443") && f.value.contains("80"))
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "country" && f.value == "France")
        );
    }

    #[test]
    fn build_api_error() {
        let v = serde_json::json!({"error": true, "errmsg": "insufficient privileges"});
        let e = build(&v);
        assert!(e.error.is_some());
    }
}
