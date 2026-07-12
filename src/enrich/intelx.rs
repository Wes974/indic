//! Intelligence X — leaks/pastes/darknet mentionnant un domaine ou un email.
//! Recherche async 2-temps (POST puis GET résultat, polling borné). Gated (clé).

use std::time::Duration;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

const BASE: &str = "https://free.intelx.io";

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, domain).await
}

pub async fn enrich_email(email: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, email).await
}

async fn run(ctx: &Ctx, term: &str) -> Enrichment {
    let Some(ref key) = ctx.key("INTELX_API_KEY") else {
        return Enrichment::failed("intelx", "clé absente".into());
    };
    match search(ctx, key, term).await {
        Ok(records) => build(records),
        Err(e) => Enrichment::failed("intelx", format!("{e:#}")),
    }
}

/// Recherche brute (leaks/pastes/darknet) d'un terme — réutilisée par la veille
/// (monitoring de mots-clés). Renvoie les enregistrements pour dédup côté appelant.
pub async fn search_terms(ctx: &Ctx, term: &str) -> Result<Vec<Record>> {
    let key = ctx.key("INTELX_API_KEY").context("clé IntelX absente")?;
    search(ctx, &key, term).await
}

async fn search(ctx: &Ctx, key: &str, term: &str) -> Result<Vec<Record>> {
    let start: StartResp = ctx
        .http
        .post(format!("{BASE}/intelligent/search"))
        .header("x-key", key)
        .json(&serde_json::json!({
            "term": term,
            "maxresults": 10,
            "media": 0,
            "sort": 2,
            "terminate": [],
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let Some(id) = start.id.filter(|s| !s.is_empty()) else {
        anyhow::bail!("pas d'id de recherche renvoyé");
    };

    // Recherche asynchrone côté IntelX : status 3 = pas encore prêt. On retente
    // une seule fois après un court délai plutôt que de boucler indéfiniment.
    let mut result = fetch_result(ctx, key, &id).await?;
    if result.status == Some(3) {
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        result = fetch_result(ctx, key, &id).await?;
    }
    Ok(result.records)
}

async fn fetch_result(ctx: &Ctx, key: &str, id: &str) -> Result<ResultResp> {
    Ok(ctx
        .http
        .get(format!("{BASE}/intelligent/search/result"))
        .query(&[("id", id), ("limit", "10")])
        .header("x-key", key)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(records: Vec<Record>) -> Enrichment {
    let mut facts = vec![Fact::new("records", records.len().to_string())];
    let sample: Vec<String> = records
        .iter()
        .take(5)
        .map(|r| format!("{} ({})", r.name, r.bucketh))
        .collect();
    if !sample.is_empty() {
        facts.push(Fact::new("sample", sample.join(", ")));
    }

    let mut signals = Vec::new();
    if !records.is_empty() {
        signals.push(Signal::with_detail(
            "intelx",
            "exposure",
            format!("{} résultat(s) en fuites/pastes/darknet", records.len()),
        ));
    }

    Enrichment {
        source: "intelx".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[derive(Deserialize)]
struct StartResp {
    id: Option<String>,
}

#[derive(Deserialize)]
struct ResultResp {
    status: Option<i64>,
    #[serde(default)]
    records: Vec<Record>,
}

#[derive(Deserialize)]
pub struct Record {
    /// Identifiant unique IntelX (GUID) — clé de dédup stable pour la veille.
    #[serde(default)]
    pub systemid: String,
    pub name: String,
    pub bucketh: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_with_records() {
        let records = vec![Record {
            systemid: "abc-123".into(),
            name: "leak_2019.sql".into(),
            bucketh: "Leaks » Public » General".into(),
        }];
        let e = build(records);
        assert!(e.error.is_none());
        assert!(e.facts.iter().any(|f| f.key == "records" && f.value == "1"));
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "exposure");
    }

    #[test]
    fn build_empty() {
        let e = build(vec![]);
        assert!(e.error.is_none());
        assert!(e.signals.is_empty());
        assert!(e.facts.iter().any(|f| f.key == "records" && f.value == "0"));
    }
}
