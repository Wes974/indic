//! Shodan CVEDB — CVSS + EPSS + CISA KEV + flag ransomware. GRATUIT, sans clé.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_cve(cve: &str, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, cve).await {
        Ok((facts, signals)) => Enrichment {
            source: "cvedb".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("cvedb", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, cve: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let url = format!("https://cvedb.shodan.io/cve/{cve}");
    let resp = http.get(&url).send().await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok((vec![Fact::new("cvedb", "non référencé")], vec![]));
    }
    let v: Value = resp.error_for_status()?.json().await?;

    let mut facts = Vec::new();
    let mut signals = Vec::new();
    if let Some(s) = v.get("cvss").and_then(|x| x.as_f64()) {
        facts.push(Fact::new("cvss", format!("{s}")));
    }
    if let Some(e) = v.get("epss").and_then(|x| x.as_f64()) {
        facts.push(Fact::new("epss", format!("{e:.5}")));
    }
    if let Some(r) = v.get("ranking_epss").and_then(|x| x.as_f64()) {
        facts.push(Fact::new("epss_percentile", format!("{:.1}%", r * 100.0)));
    }
    if v.get("kev").and_then(|x| x.as_bool()) == Some(true) {
        facts.push(Fact::new("cisa_kev", "oui — exploité en réel"));
        signals.push(Signal::with_detail("cvedb", "exploited", "CISA KEV"));
    }
    if v.get("ransomware_campaign").and_then(|x| x.as_bool()) == Some(true) {
        facts.push(Fact::new("ransomware", "oui"));
        signals.push(Signal::with_detail(
            "cvedb",
            "ransomware",
            "campagne ransomware",
        ));
    }
    if let Some(cpes) = v.get("cpes").and_then(|x| x.as_array()) {
        let list = cpes
            .iter()
            .filter_map(|x| x.as_str())
            .take(4)
            .collect::<Vec<_>>()
            .join(", ");
        if !list.is_empty() {
            facts.push(Fact::new("cpes", list));
        }
    }
    if facts.is_empty() {
        facts.push(Fact::new("cvedb", "aucune donnée"));
    }
    Ok((facts, signals))
}
