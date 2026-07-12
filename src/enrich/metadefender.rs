//! MetaDefender Cloud (OPSWAT) — multi-scan AV par hash + réputation IP/URL/domaine
//! agrégée de plusieurs sources. Header `apikey`. Gated. Free = 4000 lookups/j.
//! Parsing défensif (serde_json::Value) : le schéma réputation n'est pas figé.

use std::net::IpAddr;

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

const BASE: &str = "https://api.metadefender.com/v4";

pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, format!("hash/{hash}"), build_hash).await
}
pub async fn enrich_ip(ip: IpAddr, ctx: &Ctx) -> Enrichment {
    run(ctx, format!("ip/{ip}"), build_reputation).await
}
pub async fn enrich_url(url: &str, ctx: &Ctx) -> Enrichment {
    // L'URL doit être encodée dans le chemin ; reqwest s'en charge via .query n'étant
    // pas applicable ici → on encode manuellement les caractères réservés courants.
    let enc = urlencode(url);
    run(ctx, format!("url/{enc}"), build_reputation).await
}
pub async fn enrich_domain(domain: &str, ctx: &Ctx) -> Enrichment {
    run(ctx, format!("domain/{domain}"), build_reputation).await
}

async fn run(ctx: &Ctx, path: String, build: fn(&Value) -> Enrichment) -> Enrichment {
    let Some(ref key) = ctx.key("METADEFENDER_API_KEY") else {
        return Enrichment::failed("metadefender", "clé absente".into());
    };
    match fetch(ctx, &path, key).await {
        Ok(v) => build(&v),
        Err(e) => Enrichment::failed("metadefender", format!("{e:#}")),
    }
}

async fn fetch(ctx: &Ctx, path: &str, key: &str) -> Result<Value> {
    // 404 = observable inconnu (hash/ip jamais vu) → réponse JSON `error`, pas fatal :
    // on lit le corps sans `error_for_status` pour distinguer "inconnu" d'une vraie erreur.
    Ok(ctx
        .http
        .get(format!("{BASE}/{path}"))
        .header("apikey", key)
        .header("Accept", "application/json")
        .send()
        .await?
        .json()
        .await?)
}

/// Encodage minimal pour un segment de chemin URL (les URLs contiennent ? # & etc.).
fn urlencode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn build_hash(v: &Value) -> Enrichment {
    // Hash inconnu : l'API renvoie un objet `error` (code 404003) sans scan_results.
    let sr = match v.get("scan_results") {
        Some(sr) => sr,
        None => {
            return Enrichment::ok(
                "metadefender",
                vec![Fact::new("metadefender", "hash inconnu (non scanné)")],
            );
        }
    };
    let detected = sr
        .get("total_detected_avs")
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let total = sr.get("total_avs").and_then(Value::as_i64).unwrap_or(0);
    let verdict = sr
        .get("scan_all_result_a")
        .and_then(Value::as_str)
        .unwrap_or("");

    let mut facts = vec![Fact::new("detections", format!("{detected}/{total}"))];
    if !verdict.is_empty() {
        facts.push(Fact::new("verdict", verdict));
    }
    if let Some(threat) = v
        .get("threat_name")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
    {
        facts.push(Fact::new("threat", threat));
    }
    if let Some(ft) = v
        .get("file_info")
        .and_then(|f| f.get("file_type_description"))
        .and_then(Value::as_str)
    {
        facts.push(Fact::new("type", ft));
    }

    let mut signals = Vec::new();
    if detected > 0 {
        let detail = match v
            .get("threat_name")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
        {
            Some(t) => format!("{detected}/{total} moteurs — {t}"),
            None => format!("{detected}/{total} moteurs"),
        };
        signals.push(Signal::with_detail("metadefender", "malicious", detail));
    }
    Enrichment {
        source: "metadefender".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

fn build_reputation(v: &Value) -> Enrichment {
    let lr = v.get("lookup_results");
    let detected = lr
        .and_then(|l| l.get("detected_by"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let sources = lr.and_then(|l| l.get("sources")).and_then(Value::as_array);

    let mut facts = vec![Fact::new("detected_by", detected.to_string())];
    // Échantillon des sources ayant un verdict non bénin.
    if let Some(srcs) = sources {
        let flagged: Vec<String> = srcs
            .iter()
            .filter_map(|s| {
                let provider = s.get("provider").and_then(Value::as_str)?;
                let assessment = s.get("assessment").and_then(Value::as_str).unwrap_or("");
                let bad = !matches!(
                    assessment.to_ascii_lowercase().as_str(),
                    "" | "trustworthy" | "unknown" | "no threat detected"
                );
                bad.then(|| format!("{provider}: {assessment}"))
            })
            .take(6)
            .collect();
        if !flagged.is_empty() {
            facts.push(Fact::new("sources", flagged.join(", ")));
        }
    }

    let mut signals = Vec::new();
    if detected > 0 {
        let category = if detected >= 2 {
            "malicious"
        } else {
            "suspicious"
        };
        signals.push(Signal::with_detail(
            "metadefender",
            category,
            format!("réputation : détecté par {detected} source(s)"),
        ));
    }
    Enrichment {
        source: "metadefender".into(),
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
    fn hash_infected() {
        let v = json!({
            "scan_results": {"total_detected_avs": 42, "total_avs": 45, "scan_all_result_a": "Infected"},
            "threat_name": "Win.Trojan.Emotet",
            "file_info": {"file_type_description": "PE32 executable"}
        });
        let e = build_hash(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "detections" && f.value == "42/45")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "threat" && f.value == "Win.Trojan.Emotet")
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
    }

    #[test]
    fn hash_unknown() {
        let v = json!({"error": {"code": 404003, "messages": ["The hash was not found"]}});
        let e = build_hash(&v);
        assert!(e.error.is_none());
        assert!(e.signals.is_empty());
        assert!(e.facts.iter().any(|f| f.value.contains("inconnu")));
    }

    #[test]
    fn reputation_flagged() {
        let v = json!({
            "lookup_results": {
                "detected_by": 3,
                "sources": [
                    {"provider": "webroot.com", "assessment": "high risk"},
                    {"provider": "clean.example", "assessment": "trustworthy"}
                ]
            }
        });
        let e = build_reputation(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "detected_by" && f.value == "3")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "sources" && f.value.contains("webroot"))
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
    }

    #[test]
    fn reputation_clean() {
        let v = json!({"lookup_results": {"detected_by": 0, "sources": []}});
        let e = build_reputation(&v);
        assert!(e.signals.is_empty());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "detected_by" && f.value == "0")
        );
    }
}
