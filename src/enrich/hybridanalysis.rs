//! Hybrid Analysis (Falcon Sandbox) — enricher hash via `/overview/{hash}`.
//!
//! ⚠️ Base **sans www** (`hybrid-analysis.com` ; `www.` renvoie un 301). Header
//! `api-key` + `User-Agent` obligatoire. L'ancien `/search/hash` est déprécié
//! (410) → on utilise l'overview. Gated (clé).

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

const BASE: &str = "https://hybrid-analysis.com/api/v2";

pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("HYBRIDANALYSIS_API_KEY") else {
        return Enrichment::failed("hybridanalysis", "clé absente".into());
    };
    match fetch(ctx, key, hash).await {
        Ok(e) => e,
        Err(e) => Enrichment::failed("hybridanalysis", format!("{e:#}")),
    }
}

async fn fetch(ctx: &Ctx, key: &str, hash: &str) -> Result<Enrichment> {
    let resp = ctx
        .http
        .get(format!("{BASE}/overview/{hash}"))
        .header("api-key", key)
        .header("User-Agent", "Falcon Sandbox")
        .header("accept", "application/json")
        .send()
        .await?;
    // Hash jamais analysé → 404 : réponse neutre, pas une erreur.
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(Enrichment::ok(
            "hybridanalysis",
            vec![Fact::new("hybridanalysis", "hash inconnu du sandbox")],
        ));
    }
    let v: Value = resp.error_for_status()?.json().await?;
    Ok(build(&v))
}

fn build(v: &Value) -> Enrichment {
    let verdict = v.get("verdict").and_then(Value::as_str);

    let mut facts = Vec::new();
    if let Some(vd) = verdict {
        facts.push(Fact::new("verdict", vd));
    }
    if let Some(fam) = v.get("vx_family").and_then(Value::as_str) {
        facts.push(Fact::new("famille", fam));
    }
    if let Some(score) = v.get("threat_score").and_then(Value::as_i64) {
        facts.push(Fact::new("threat_score", format!("{score}/100")));
    }
    if let Some(ms) = v.get("multiscan_result").and_then(Value::as_i64) {
        facts.push(Fact::new("av_detect", format!("{ms}%")));
    }
    // type de fichier (`type_short` = tableau court, ex. ["peexe","executable"]).
    let types: Vec<&str> = v
        .get("type_short")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    if !types.is_empty() {
        facts.push(Fact::new("type", types.join(", ")));
    }
    let tags: Vec<&str> = v
        .get("tags")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).take(8).collect())
        .unwrap_or_default();
    if !tags.is_empty() {
        facts.push(Fact::new("tags", tags.join(", ")));
    }
    if let Some(sha) = v.get("sha256").and_then(Value::as_str) {
        facts.push(Fact::new(
            "rapport",
            format!("https://hybrid-analysis.com/sample/{sha}"),
        ));
    }

    let mut signals = Vec::new();
    match verdict {
        Some("malicious") => signals.push(Signal::with_detail(
            "hybridanalysis",
            "malicious",
            "Falcon Sandbox : malicious",
        )),
        Some("suspicious") => signals.push(Signal::with_detail(
            "hybridanalysis",
            "suspicious",
            "Falcon Sandbox : suspicious",
        )),
        _ => {}
    }

    Enrichment {
        source: "hybridanalysis".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_malicious_avec_famille() {
        let v = json!({
            "verdict": "malicious",
            "vx_family": "Trojan.Emotet",
            "threat_score": 90,
            "multiscan_result": 72,
            "type_short": ["peexe", "executable"],
            "tags": ["emotet", "banker"],
            "sha256": "abc123"
        });
        let e = build(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "verdict" && f.value == "malicious")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "famille" && f.value == "Trojan.Emotet")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "type" && f.value == "peexe, executable")
        );
        assert!(e.signals.iter().any(|s| s.category == "malicious"));
    }

    #[test]
    fn build_clean_no_signal() {
        let v = json!({ "verdict": "no specific threat", "sha256": "x" });
        let e = build(&v);
        assert!(e.signals.is_empty());
        assert!(e.facts.iter().any(|f| f.key == "rapport"));
    }
}
