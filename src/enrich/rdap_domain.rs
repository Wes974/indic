//! Enricher RDAP domaine (registrar, dates registration/expiration, NS, statut).

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, domain).await {
        Ok(facts) => Enrichment::ok("rdap_domain", facts),
        Err(e) => Enrichment::failed("rdap_domain", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, domain: &str) -> Result<Vec<Fact>> {
    let url = format!("https://rdap.org/domain/{domain}");
    let resp = http
        .get(&url)
        .header("accept", "application/rdap+json")
        .send()
        .await?;
    // 404 = domaine non enregistré ou sous-domaine (pas d'entrée RDAP) → neutre,
    // pas une erreur.
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(vec![Fact::new(
            "rdap_domain",
            "non enregistré (ou sous-domaine — vise le domaine apex)",
        )]);
    }
    let v: Value = resp.error_for_status()?.json().await?;

    let mut facts = Vec::new();
    if let Some(s) = v.get("handle").and_then(|x| x.as_str()) {
        facts.push(Fact::new("handle", s));
    }
    if let Some(status) = v.get("status").and_then(|x| x.as_array()) {
        let list = status
            .iter()
            .filter_map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if !list.is_empty() {
            facts.push(Fact::new("status", list));
        }
    }
    // Dates clés (création → détection NRD, expiration).
    if let Some(events) = v.get("events").and_then(|x| x.as_array()) {
        for e in events {
            let action = e.get("eventAction").and_then(|x| x.as_str()).unwrap_or("");
            let date = e.get("eventDate").and_then(|x| x.as_str()).unwrap_or("");
            if !date.is_empty() && matches!(action, "registration" | "expiration" | "last changed")
            {
                facts.push(Fact::new(action, date));
            }
        }
    }
    if let Some(ns) = v.get("nameservers").and_then(|x| x.as_array()) {
        let list = ns
            .iter()
            .filter_map(|n| n.get("ldhName").and_then(|x| x.as_str()))
            .collect::<Vec<_>>()
            .join(", ");
        if !list.is_empty() {
            facts.push(Fact::new("nameservers", list));
        }
    }
    if let Some(entities) = v.get("entities").and_then(|x| x.as_array()) {
        for e in entities {
            let is_registrar = e
                .get("roles")
                .and_then(|r| r.as_array())
                .is_some_and(|r| r.iter().any(|x| x.as_str() == Some("registrar")));
            if is_registrar && let Some(name) = vcard_fn(e) {
                facts.push(Fact::new("registrar", name));
                break;
            }
        }
    }

    if facts.is_empty() {
        anyhow::bail!("RDAP domaine vide");
    }
    Ok(facts)
}

/// Extrait le champ `fn` (nom) d'un `vcardArray` RDAP.
fn vcard_fn(entity: &Value) -> Option<String> {
    let items = entity.get("vcardArray")?.as_array()?.get(1)?.as_array()?;
    for it in items {
        if let Some(it) = it.as_array()
            && it.first().and_then(|x| x.as_str()) == Some("fn")
        {
            return it.get(3).and_then(|x| x.as_str()).map(String::from);
        }
    }
    None
}
