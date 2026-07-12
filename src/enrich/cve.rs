//! Enricher CVE : NVD (description, CVSS, date) + EPSS (probabilité d'exploitation).

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_cve(cve: &str, ctx: &Ctx) -> Enrichment {
    // Clé NVD optionnelle : lève le rate-limit (5 → 50 req/30s) si présente.
    let nvd_key = ctx.key("NVD_API_KEY");
    let (nvd_res, epss_res) = tokio::join!(nvd(&ctx.http, cve, nvd_key.as_deref()), epss(&ctx.http, cve));

    let mut facts = Vec::new();
    let mut err = None;
    match nvd_res {
        Ok(mut f) => facts.append(&mut f),
        Err(e) => err = Some(format!("nvd: {e:#}")),
    }
    if let Ok(mut f) = epss_res {
        facts.append(&mut f);
    }

    if facts.is_empty() {
        return Enrichment::failed("cve", err.unwrap_or_else(|| "aucune donnée".into()));
    }
    Enrichment::ok("cve", facts)
}

async fn nvd(http: &reqwest::Client, cve: &str, key: Option<&str>) -> Result<Vec<Fact>> {
    let url = format!("https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}");
    let mut req = http.get(&url);
    if let Some(k) = key {
        // La clé NVD passe en header `apiKey` (jamais dans l'URL → pas de fuite).
        req = req.header("apiKey", k);
    }
    let v: Value = req.send().await?.error_for_status()?.json().await?;
    let item = v
        .get("vulnerabilities")
        .and_then(|x| x.as_array())
        .and_then(|a| a.first())
        .and_then(|x| x.get("cve"))
        .ok_or_else(|| anyhow::anyhow!("CVE introuvable"))?;

    let mut facts = Vec::new();
    if let Some(descs) = item.get("descriptions").and_then(|x| x.as_array())
        && let Some(d) = descs
            .iter()
            .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
            .and_then(|d| d.get("value"))
            .and_then(|x| x.as_str())
    {
        let mut s: String = d.chars().take(300).collect();
        if d.chars().count() > 300 {
            s.push('…');
        }
        facts.push(Fact::new("description", s));
    }
    if let Some(p) = item.get("published").and_then(|x| x.as_str()) {
        facts.push(Fact::new("published", p));
    }
    // CVSS : v3.1 → v3.0 → v2 (première métrique disponible).
    if let Some(metrics) = item.get("metrics") {
        for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
            let Some(arr) = metrics
                .get(key)
                .and_then(|x| x.as_array())
                .filter(|a| !a.is_empty())
            else {
                continue;
            };
            let data = arr[0].get("cvssData");
            let score = data
                .and_then(|d| d.get("baseScore"))
                .and_then(|x| x.as_f64());
            let sev = data
                .and_then(|d| d.get("baseSeverity"))
                .and_then(|x| x.as_str())
                .or_else(|| arr[0].get("baseSeverity").and_then(|x| x.as_str()));
            if let Some(sc) = score {
                let label = sev.map(|s| format!(" ({s})")).unwrap_or_default();
                facts.push(Fact::new("cvss", format!("{sc}{label}")));
            }
            break;
        }
    }
    Ok(facts)
}

async fn epss(http: &reqwest::Client, cve: &str) -> Result<Vec<Fact>> {
    let url = format!("https://api.first.org/data/v1/epss?cve={cve}");
    let v: Value = http
        .get(&url)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let d = v
        .get("data")
        .and_then(|x| x.as_array())
        .and_then(|a| a.first())
        .ok_or_else(|| anyhow::anyhow!("pas d'EPSS"))?;

    let mut facts = Vec::new();
    if let Some(e) = d.get("epss").and_then(|x| x.as_str()) {
        let pct = d.get("percentile").and_then(|x| x.as_str()).unwrap_or("");
        let suffix = if pct.is_empty() {
            String::new()
        } else {
            format!(" (percentile {pct})")
        };
        facts.push(Fact::new("epss", format!("{e}{suffix}")));
    }
    Ok(facts)
}
