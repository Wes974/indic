//! GitHub code search — un domaine mentionné en code public peut signaler une
//! fuite (clé, config, credential codée en dur…). Header Bearer. Gated (clé).

use anyhow::Result;
use serde::Deserialize;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    let Some(token) = ctx.key("GITHUB_TOKEN") else {
        return Enrichment::failed("github", "clé absente".into());
    };
    match fetch(ctx, domain, token).await {
        Ok(resp) => build(resp),
        Err(e) => Enrichment::failed("github", format!("{e:#}")),
    }
}

async fn fetch(ctx: &Ctx, domain: &str, token: &str) -> Result<Resp> {
    Ok(ctx
        .http
        .get("https://api.github.com/search/code")
        .query(&[("q", format!("\"{domain}\"")), ("per_page", "10".into())])
        .header("Authorization", format!("Bearer {token}"))
        .header("Accept", "application/vnd.github+json")
        .header("User-Agent", "indic")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(r: Resp) -> Enrichment {
    let mut facts = vec![Fact::new("code_matches", r.total_count.to_string())];
    let sample: Vec<String> = r
        .items
        .iter()
        .take(5)
        .map(|it| format!("{}:{}", it.repository.full_name, it.path))
        .collect();
    if !sample.is_empty() {
        facts.push(Fact::new("sample", sample.join(", ")));
    }

    let mut signals = Vec::new();
    if r.total_count > 0 {
        signals.push(Signal::with_detail(
            "github",
            "exposure",
            format!("{} occurrence(s) en code public", r.total_count),
        ));
    }

    Enrichment {
        source: "github".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[derive(Deserialize)]
struct Resp {
    total_count: u64,
    #[serde(default)]
    items: Vec<Item>,
}

#[derive(Deserialize)]
struct Item {
    repository: Repo,
    path: String,
}

#[derive(Deserialize)]
struct Repo {
    full_name: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_with_matches() {
        let r = Resp {
            total_count: 3,
            items: vec![Item {
                repository: Repo {
                    full_name: "owner/repo".into(),
                },
                path: "config/secrets.yml".into(),
            }],
        };
        let e = build(r);
        assert!(e.error.is_none());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "code_matches" && f.value == "3")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "sample" && f.value.contains("owner/repo:config/secrets.yml"))
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "exposure");
    }

    #[test]
    fn build_no_matches() {
        let e = build(Resp {
            total_count: 0,
            items: vec![],
        });
        assert!(e.error.is_none());
        assert!(e.signals.is_empty());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "code_matches" && f.value == "0")
        );
    }
}
