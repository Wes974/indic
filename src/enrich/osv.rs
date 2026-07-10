//! Enricher OSV.dev : vulnérabilité open-source (packages affectés, alias). Sans clé.

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};
use crate::model::Signal;

pub async fn enrich_cve(cve: &str, ctx: &Ctx) -> Enrichment {
    match fetch(&ctx.http, cve).await {
        Ok(facts) => Enrichment::ok("osv", facts),
        Err(e) => Enrichment::failed("osv", format!("{e:#}")),
    }
}

/// Enrichit un package (`ÉcoOSV/nom`) : vulnérabilités connues via OSV
/// `POST /v1/query`. Pivote vers les CVE (aliases). Sans clé.
pub async fn enrich_package(spec: &str, ctx: &Ctx) -> Enrichment {
    let Some((eco, name)) = spec.split_once('/') else {
        return Enrichment::failed("osv", "package mal formé".into());
    };
    match query_package(&ctx.http, eco, name).await {
        Ok(e) => e,
        Err(e) => Enrichment::failed("osv", format!("{e:#}")),
    }
}

async fn query_package(http: &reqwest::Client, eco: &str, name: &str) -> Result<Enrichment> {
    let v: Value = http
        .post("https://api.osv.dev/v1/query")
        .json(&serde_json::json!({ "package": { "ecosystem": eco, "name": name } }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let vulns = v.get("vulns").and_then(|x| x.as_array());
    let count = vulns.map_or(0, |a| a.len());
    let mut facts = vec![
        Fact::new("package", format!("{eco}/{name}")),
        Fact::new("vulnérabilités", count.to_string()),
    ];
    let mut pivots = Vec::new();
    if let Some(vulns) = vulns {
        let ids: Vec<&str> = vulns.iter().filter_map(|x| x["id"].as_str()).collect();
        if !ids.is_empty() {
            facts.push(Fact::new(
                "ids",
                ids.iter().take(8).cloned().collect::<Vec<_>>().join(", "),
            ));
        }
        // Pivots vers les CVE (via les alias), dédupliqués.
        let mut seen = std::collections::BTreeSet::new();
        for vln in vulns {
            for a in vln
                .get("aliases")
                .and_then(|x| x.as_array())
                .into_iter()
                .flatten()
                .filter_map(|x| x.as_str())
            {
                if a.starts_with("CVE-") && seen.insert(a.to_string()) {
                    pivots.push(Pivot {
                        relation: "vuln".into(),
                        kind: "cve".into(),
                        value: a.to_string(),
                    });
                }
            }
        }
    }
    let signals = if count > 0 {
        vec![Signal::with_detail(
            "osv",
            "vulnerable",
            format!("{count} vulnérabilité(s) OSV connue(s)"),
        )]
    } else {
        Vec::new()
    };

    Ok(Enrichment {
        source: "osv".into(),
        facts,
        signals,
        pivots,
        error: None,
    })
}

async fn fetch(http: &reqwest::Client, cve: &str) -> Result<Vec<Fact>> {
    let url = format!("https://api.osv.dev/v1/vulns/{cve}");
    let resp = http.get(&url).send().await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok(vec![Fact::new("osv", "non référencé")]);
    }
    let v: Value = resp.error_for_status()?.json().await?;

    let mut facts = Vec::new();
    if let Some(id) = v.get("id").and_then(|x| x.as_str()) {
        facts.push(Fact::new("osv_id", id));
    }
    if let Some(al) = v.get("aliases").and_then(|x| x.as_array()) {
        let list = al
            .iter()
            .filter_map(|x| x.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        if !list.is_empty() {
            facts.push(Fact::new("aliases", list));
        }
    }
    if let Some(affected) = v.get("affected").and_then(|x| x.as_array()) {
        let pkgs: Vec<String> = affected
            .iter()
            .filter_map(|a| a.get("package"))
            .filter_map(|p| {
                let name = p.get("name").and_then(|x| x.as_str())?;
                let eco = p.get("ecosystem").and_then(|x| x.as_str()).unwrap_or("?");
                Some(format!("{eco}/{name}"))
            })
            .collect();
        if !pkgs.is_empty() {
            let n = pkgs.len();
            let mut shown = pkgs;
            shown.truncate(6);
            facts.push(Fact::new("packages", format!("{n} — {}", shown.join(", "))));
        }
    }
    Ok(facts)
}
