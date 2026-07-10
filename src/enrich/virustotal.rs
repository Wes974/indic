//! VirusTotal API v3 — IP / domaine / hash / URL. Clé `x-apikey`, enricher gated.

use std::net::IpAddr;

use anyhow::Result;
use reqwest::StatusCode;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    run(ctx, &format!("ip_addresses/{ip}")).await
}
pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, &format!("domains/{domain}")).await
}
pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, &format!("files/{hash}")).await
}
#[allow(dead_code)]
pub async fn enrich_url(url: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, &format!("urls/{}", base64_url_nopad(url.as_bytes()))).await
}

async fn run(ctx: &Ctx, path: &str) -> Enrichment {
    let Some(key) = ctx.key("VIRUSTOTAL_API_KEY") else {
        return Enrichment::failed("virustotal", "clé absente".into());
    };
    match fetch(&ctx.http, path, key).await {
        Ok((facts, signals)) => Enrichment {
            source: "virustotal".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("virustotal", format!("{e:#}")),
    }
}

async fn fetch(http: &reqwest::Client, path: &str, key: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    let url = format!("https://www.virustotal.com/api/v3/{path}");
    let resp = http.get(&url).header("x-apikey", key).send().await?;
    if resp.status() == StatusCode::NOT_FOUND {
        return Ok((
            vec![Fact::new("virustotal", "inconnu (non analysé)")],
            vec![],
        ));
    }
    let v: Value = resp.error_for_status()?.json().await?;
    let a = v
        .get("data")
        .and_then(|d| d.get("attributes"))
        .ok_or_else(|| anyhow::anyhow!("réponse VT vide"))?;

    let mut facts = Vec::new();
    let mut signals = Vec::new();

    if let Some(stats) = a.get("last_analysis_stats") {
        let g = |k: &str| stats.get(k).and_then(|x| x.as_i64()).unwrap_or(0);
        let (mal, susp) = (g("malicious"), g("suspicious"));
        facts.push(Fact::new(
            "detections",
            format!(
                "{mal} malicious / {susp} suspicious / {} harmless / {} undetected",
                g("harmless"),
                g("undetected")
            ),
        ));
        if mal > 0 {
            signals.push(Signal::with_detail(
                "virustotal",
                "malicious",
                format!("{mal} moteurs"),
            ));
        } else if susp > 0 {
            signals.push(Signal::with_detail(
                "virustotal",
                "suspicious",
                format!("{susp} moteurs"),
            ));
        }
    }
    if let Some(rep) = a.get("reputation").and_then(|x| x.as_i64()) {
        facts.push(Fact::new("reputation", rep.to_string()));
    }
    // Fichier
    if let Some(t) = a.get("type_description").and_then(|x| x.as_str()) {
        facts.push(Fact::new("type", t));
    }
    if let Some(label) = a
        .get("popular_threat_classification")
        .and_then(|x| x.get("suggested_threat_label"))
        .and_then(|x| x.as_str())
    {
        facts.push(Fact::new("threat_label", label));
    }
    if let Some(names) = a.get("names").and_then(|x| x.as_array()) {
        let list = names
            .iter()
            .filter_map(|x| x.as_str())
            .take(3)
            .collect::<Vec<_>>()
            .join(", ");
        if !list.is_empty() {
            facts.push(Fact::new("names", list));
        }
    }
    // Domaine
    if let Some(cats) = a.get("categories").and_then(|x| x.as_object()) {
        let set: std::collections::BTreeSet<&str> =
            cats.values().filter_map(|x| x.as_str()).collect();
        if !set.is_empty() {
            facts.push(Fact::new(
                "categories",
                set.into_iter().collect::<Vec<_>>().join(", "),
            ));
        }
    }
    if let Some(reg) = a.get("registrar").and_then(|x| x.as_str()) {
        facts.push(Fact::new("registrar", reg));
    }
    // IP
    if let Some(owner) = a.get("as_owner").and_then(|x| x.as_str()) {
        facts.push(Fact::new("as_owner", owner));
    }

    if facts.is_empty() {
        facts.push(Fact::new("virustotal", "aucune donnée exploitable"));
    }
    Ok((facts, signals))
}

/// base64url sans padding (id d'URL VirusTotal), sans crate externe.
fn base64_url_nopad(input: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((b[0] as u32) << 16) | ((b[1] as u32) << 8) | (b[2] as u32);
        out.push(T[((n >> 18) & 63) as usize] as char);
        out.push(T[((n >> 12) & 63) as usize] as char);
        if chunk.len() > 1 {
            out.push(T[((n >> 6) & 63) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(T[(n & 63) as usize] as char);
        }
    }
    out
}
