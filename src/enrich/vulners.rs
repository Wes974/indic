//! Vulners — enrichissement CVE : CVSS, exploitation "in the wild", références.
//! `POST vulners.com/api/v3/search/id`, header `X-Api-Key` (endpoint gratuit depuis
//! 2025). Réponse = `data.documents{<type:cve>: {...}}` (plusieurs docs possibles) →
//! parsing défensif sur tous les documents. Gated.

use anyhow::Result;
use serde_json::{Value, json};

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_cve(cve: &str, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("VULNERS_API_KEY") else {
        return Enrichment::failed("vulners", "clé absente".into());
    };
    match fetch(&ctx.http, cve, key).await {
        Ok(v) => build(&v),
        Err(e) => Enrichment::failed("vulners", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, cve: &str, key: &str) -> Result<Value> {
    Ok(http
        .post("https://vulners.com/api/v3/search/id")
        .header("X-Api-Key", key)
        .json(&json!({ "id": cve, "fields": ["*"] }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(v: &Value) -> Enrichment {
    let docs = v
        .get("data")
        .and_then(|d| d.get("documents"))
        .and_then(|x| x.as_object())
        .filter(|m| !m.is_empty());
    let Some(docs) = docs else {
        return Enrichment::ok("vulners", vec![Fact::new("vulners", "CVE inconnu")]);
    };

    let mut best_cvss: Option<(f64, String)> = None;
    let mut wild_exploited = false;
    let mut references = 0usize;
    for doc in docs.values() {
        // CVSS : cvss3 prioritaire, sinon cvss (v2) ; on garde le meilleur score > 0.
        for field in ["cvss3", "cvss"] {
            if let Some(c) = doc.get(field)
                && let Some(s) = c.get("score").and_then(|x| x.as_f64()).filter(|s| *s > 0.0)
            {
                let sev = c.get("severity").and_then(|x| x.as_str()).unwrap_or("");
                if best_cvss.as_ref().is_none_or(|(b, _)| s > *b) {
                    best_cvss = Some((s, sev.to_string()));
                }
                break; // cvss3 l'emporte
            }
        }
        if doc
            .get("enchantments")
            .and_then(|e| e.get("exploitation"))
            .and_then(|x| x.get("wildExploited"))
            .and_then(|x| x.as_bool())
            == Some(true)
        {
            wild_exploited = true;
        }
        references += doc
            .get("references")
            .and_then(|x| x.as_array())
            .map_or(0, |a| a.len());
    }

    let mut facts = Vec::new();
    if let Some((score, sev)) = &best_cvss {
        let label = if sev.is_empty() {
            String::new()
        } else {
            format!(" ({sev})")
        };
        facts.push(Fact::new("cvss", format!("{score}{label}")));
    }
    if references > 0 {
        facts.push(Fact::new("références", references.to_string()));
    }
    if facts.is_empty() {
        facts.push(Fact::new("vulners", "présent (métadonnées limitées)"));
    }

    let mut signals = Vec::new();
    if wild_exploited {
        signals.push(Signal::with_detail(
            "vulners",
            "malicious",
            "exploité dans la nature (Vulners)",
        ));
    }

    Enrichment {
        source: "vulners".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_cvss_and_exploited() {
        let v = serde_json::json!({"data": {"documents": {
            "CVELIST:CVE-2021-44228": {"cvss": {"score": 0.0}, "references": ["a", "b"]},
            "NVD:CVE-2021-44228": {"cvss3": {"score": 10.0, "severity": "CRITICAL"},
                "enchantments": {"exploitation": {"wildExploited": true}}}
        }}});
        let e = build(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "cvss" && f.value.contains("10"))
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "références" && f.value == "2")
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
    }

    #[test]
    fn build_unknown() {
        let e = build(&serde_json::json!({"data": {"documents": {}}}));
        assert!(e.error.is_none());
        assert!(e.facts.iter().any(|f| f.value.contains("inconnu")));
    }
}
