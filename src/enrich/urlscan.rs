//! urlscan.io — recherche dans les scans passés (domaine/URL/IP observés en
//! visite réelle : IP finale, serveur, etc.). Header API-Key. Gated (clé).

use std::net::IpAddr;

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact};

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, format!("domain:{domain}")).await
}

pub async fn enrich_url(url: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, format!("page.url:\"{url}\"")).await
}

pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    // Quoter la valeur : les `:` d'une IPv6 casseraient le parser Lucene d'urlscan.
    run(ctx, format!("ip:\"{ip}\"")).await
}

async fn run(ctx: &Ctx, query: String) -> Enrichment {
    let Some(key) = ctx.key("URLSCAN_API_KEY") else {
        return Enrichment::failed("urlscan", "clé absente".into());
    };
    match search(ctx, key, &query).await {
        Ok(raw) => build(raw),
        Err(e) => Enrichment::failed("urlscan", format!("{e:#}")),
    }
}

async fn search(ctx: &Ctx, key: &str, q: &str) -> Result<RawResp> {
    // Ne PAS appeler `.error_for_status()` avant d'avoir lu le corps : sur clé
    // invalide/malformée l'API renvoie un 400 avec un `message` exploitable
    // (ex. "Invalid API key format"), qu'on veut remonter tel quel.
    let resp = ctx
        .http
        .get("https://urlscan.io/api/v1/search/")
        .query(&[("q", q), ("size", "10")])
        .header("API-Key", key)
        .send()
        .await?;
    Ok(resp.json().await?)
}

fn build(r: RawResp) -> Enrichment {
    if let Some(msg) = r.message.filter(|_| r.results.is_none()) {
        return Enrichment::failed("urlscan", msg);
    }
    let results = r.results.unwrap_or_default();
    let mut facts = vec![Fact::new(
        "scans",
        r.total.unwrap_or(results.len() as u64).to_string(),
    )];
    let sample: Vec<String> = results
        .iter()
        .take(5)
        .map(|res| {
            let ip = res.page.ip.as_deref().unwrap_or("?");
            let server = res.page.server.as_deref().unwrap_or("?");
            format!("{} ({ip}, {server})", res.page.url)
        })
        .collect();
    if !sample.is_empty() {
        facts.push(Fact::new("sample", sample.join(", ")));
    }
    // Pas de champ verdict/tag garanti dans la réponse search → purement descriptif.
    Enrichment {
        source: "urlscan".into(),
        facts,
        signals: vec![],
        pivots: vec![],
        error: None,
    }
}

#[derive(Deserialize)]
struct RawResp {
    total: Option<u64>,
    #[serde(default)]
    results: Option<Vec<ResultItem>>,
    message: Option<String>,
}

#[derive(Deserialize)]
struct ResultItem {
    page: Page,
}

#[derive(Deserialize)]
struct Page {
    url: String,
    ip: Option<String>,
    server: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_ok_with_results() {
        let r = RawResp {
            total: Some(42),
            results: Some(vec![ResultItem {
                page: Page {
                    url: "https://exemple.fr/".into(),
                    ip: Some("1.2.3.4".into()),
                    server: Some("nginx".into()),
                },
            }]),
            message: None,
        };
        let e = build(r);
        assert!(e.error.is_none());
        assert!(e.facts.iter().any(|f| f.key == "scans" && f.value == "42"));
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "sample" && f.value.contains("1.2.3.4"))
        );
    }

    #[test]
    fn build_invalid_key_error() {
        let r = RawResp {
            total: None,
            results: None,
            message: Some("Invalid API key format".into()),
        };
        let e = build(r);
        assert_eq!(e.error.as_deref(), Some("Invalid API key format"));
    }

    #[test]
    fn build_empty_results() {
        let r = RawResp {
            total: Some(0),
            results: Some(vec![]),
            message: None,
        };
        let e = build(r);
        assert!(e.error.is_none());
        assert!(e.facts.iter().any(|f| f.key == "scans" && f.value == "0"));
    }
}
