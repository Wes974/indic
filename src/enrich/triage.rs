//! Hatching Triage (tria.ge) — sandbox malware, enricher hash.
//!
//! Cherche le sample par hash (`/search?query=sha256:…`) puis lit son overview
//! (`/samples/<id>/overview.json`) : score 0-10, famille, tags, et les **C2
//! extraits** de la config remontés en pivots. Auth `Bearer`. Gated (clé).

use std::collections::HashSet;
use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact, Pivot};
use crate::model::Signal;

const BASE: &str = "https://tria.ge/api/v0";

pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("TRIAGE_API_KEY") else {
        return Enrichment::failed("triage", "clé absente".into());
    };
    match lookup(ctx, key, hash).await {
        Ok(e) => e,
        Err(e) => Enrichment::failed("triage", format!("{e:#}")),
    }
}

async fn lookup(ctx: &Ctx, key: &str, hash: &str) -> Result<Enrichment> {
    // Préfixe selon la longueur du hash (md5 32 / sha1 40 / sha256 64).
    let query = match hash.len() {
        32 => format!("md5:{hash}"),
        40 => format!("sha1:{hash}"),
        _ => format!("sha256:{hash}"),
    };
    let search: Value = ctx
        .http
        .get(format!("{BASE}/search"))
        .query(&[("query", query.as_str())])
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let Some(id) = search
        .pointer("/data/0/id")
        .and_then(Value::as_str)
        .map(str::to_string)
    else {
        return Ok(Enrichment::ok(
            "triage",
            vec![Fact::new("triage", "aucun sample analysé")],
        ));
    };
    let overview: Value = ctx
        .http
        .get(format!("{BASE}/samples/{id}/overview.json"))
        .header("Authorization", format!("Bearer {key}"))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(build(&id, &overview))
}

fn build(id: &str, ov: &Value) -> Enrichment {
    let score = ov.pointer("/analysis/score").and_then(Value::as_i64);
    let families = str_list(ov.pointer("/analysis/family"));
    let tags = str_list(ov.pointer("/analysis/tags"));

    let mut facts = Vec::new();
    if let Some(s) = score {
        facts.push(Fact::new("score", format!("{s}/10")));
    }
    if !families.is_empty() {
        facts.push(Fact::new("famille", families.join(", ")));
    }
    if !tags.is_empty() {
        facts.push(Fact::new(
            "tags",
            tags.iter().take(8).cloned().collect::<Vec<_>>().join(", "),
        ));
    }
    facts.push(Fact::new("rapport", format!("https://tria.ge/{id}")));

    // C2 extraits de la config (« host:port ») → pivots dédupliqués.
    let mut pivots = Vec::new();
    let mut seen = HashSet::new();
    if let Some(items) = ov.get("extracted").and_then(Value::as_array) {
        for item in items {
            let Some(c2s) = item.pointer("/config/c2").and_then(Value::as_array) else {
                continue;
            };
            for c2 in c2s.iter().filter_map(Value::as_str) {
                let host = c2.rsplit_once(':').map(|(h, _)| h).unwrap_or(c2);
                if host.is_empty() || !seen.insert(host.to_string()) {
                    continue;
                }
                let kind = if host.parse::<IpAddr>().is_ok() {
                    "ip"
                } else {
                    "domain"
                };
                pivots.push(Pivot {
                    relation: "c2".into(),
                    kind: kind.into(),
                    value: host.to_string(),
                });
                if pivots.len() >= 20 {
                    break;
                }
            }
        }
    }

    // Signal selon le score sandbox (0-10).
    let mut signals = Vec::new();
    match score {
        Some(s) if s >= 8 => signals.push(Signal::with_detail(
            "triage",
            "malicious",
            format!("score sandbox {s}/10"),
        )),
        Some(s) if s >= 5 => signals.push(Signal::with_detail(
            "triage",
            "suspicious",
            format!("score sandbox {s}/10"),
        )),
        _ => {}
    }

    Enrichment {
        source: "triage".into(),
        facts,
        signals,
        pivots,
        error: None,
    }
}

fn str_list(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(String::from)
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn build_extrait_score_famille_c2() {
        let ov = json!({
            "analysis": {
                "score": 10,
                "family": ["emotet"],
                "tags": ["family:emotet", "banker", "trojan"]
            },
            "extracted": [{
                "config": { "c2": ["95.179.195.74:80", "evil.example.com:443", "95.179.195.74:80"] }
            }]
        });
        let e = build("260707-abc", &ov);
        assert!(e.error.is_none());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "score" && f.value == "10/10")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "famille" && f.value == "emotet")
        );
        assert!(e.signals.iter().any(|s| s.category == "malicious"));
        // C2 dédupliqués → 1 IP + 1 domaine.
        assert_eq!(e.pivots.len(), 2);
        assert!(
            e.pivots
                .iter()
                .any(|p| p.kind == "ip" && p.value == "95.179.195.74")
        );
        assert!(
            e.pivots
                .iter()
                .any(|p| p.kind == "domain" && p.value == "evil.example.com")
        );
    }

    #[test]
    fn build_score_bas_sans_signal() {
        let ov = json!({ "analysis": { "score": 2, "family": [], "tags": [] } });
        let e = build("x", &ov);
        assert!(e.signals.is_empty());
        assert!(e.facts.iter().any(|f| f.key == "rapport"));
    }
}
