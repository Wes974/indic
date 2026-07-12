//! Filescan.io (OPSWAT MetaDefender Sandbox) — recherche d'un rapport par hash :
//! verdict + tags + type de fichier. `GET www.filescan.io/api/reports/search?sha256=`,
//! header `X-Api-Key`. Gated. Schéma variable (verdict/finalVerdict, tags/allTags)
//! → parsing défensif.

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("FILESCAN_API_KEY") else {
        return Enrichment::failed("filescan", "clé absente".into());
    };
    match fetch(&ctx.http, hash, key).await {
        Ok(v) => build(&v),
        Err(e) => Enrichment::failed("filescan", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, hash: &str, key: &str) -> Result<Value> {
    // Le paramètre de recherche dépend de la longueur du hash.
    let param = match hash.len() {
        32 => "md5",
        40 => "sha1",
        _ => "sha256",
    };
    Ok(http
        .get("https://www.filescan.io/api/reports/search")
        .query(&[(param, hash)])
        .header("X-Api-Key", key)
        .header("accept", "application/json")
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(v: &Value) -> Enrichment {
    let items = v
        .get("items")
        .and_then(|x| x.as_array())
        .cloned()
        .unwrap_or_default();
    if items.is_empty() {
        return Enrichment::ok(
            "filescan",
            vec![Fact::new("filescan", "aucun rapport (hash inconnu)")],
        );
    }
    let item = &items[0];

    // verdict : "verdict" OU finalVerdict.verdict (schéma variable selon version).
    let verdict = item
        .get("verdict")
        .and_then(|x| x.as_str())
        .or_else(|| {
            item.get("finalVerdict")
                .and_then(|f| f.get("verdict"))
                .and_then(|x| x.as_str())
        })
        .unwrap_or("unknown")
        .to_string();

    let mut facts = vec![
        Fact::new("rapports", items.len().to_string()),
        Fact::new("verdict", verdict.clone()),
    ];
    if let Some(ft) = item
        .get("file")
        .and_then(|f| f.get("type").or_else(|| f.get("short_type")))
        .and_then(|x| x.as_str())
        .filter(|s| !s.is_empty())
    {
        facts.push(Fact::new("type", ft));
    }
    let tags: Vec<String> = item
        .get("tags")
        .or_else(|| item.get("allTags"))
        .and_then(|x| x.as_array())
        .map(|a| a.iter().filter_map(tag_name).collect())
        .unwrap_or_default();
    if !tags.is_empty() {
        facts.push(Fact::new("tags", super::dedup_join(tags, 8)));
    }

    // Verdict → signal.
    let mut signals = Vec::new();
    let cat = match verdict.to_ascii_lowercase().as_str() {
        "malicious" | "likely_malicious" => Some("malicious"),
        "suspicious" => Some("suspicious"),
        _ => None,
    };
    if let Some(c) = cat {
        signals.push(Signal::with_detail(
            "filescan",
            c,
            format!("verdict Filescan : {verdict}"),
        ));
    }

    Enrichment {
        source: "filescan".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

/// Un tag peut être une chaîne, `{name}`, ou `{tag:{name}}`.
fn tag_name(t: &Value) -> Option<String> {
    if let Some(s) = t.as_str() {
        return Some(s.to_string());
    }
    t.get("name")
        .or_else(|| t.get("tag").and_then(|x| x.get("name")))
        .and_then(|x| x.as_str())
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_malicious_verdict() {
        let v = serde_json::json!({
            "count": 1,
            "items": [{"id": "x", "verdict": "malicious", "file": {"type": "PE32"},
                       "tags": ["trojan", "packed"]}]
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
                .any(|f| f.key == "tags" && f.value.contains("trojan"))
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
    }

    #[test]
    fn build_finalverdict_shape() {
        let v = serde_json::json!({
            "items": [{"finalVerdict": {"verdict": "suspicious"}, "allTags": [{"name": "obfuscated"}]}]
        });
        let e = build(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "verdict" && f.value == "suspicious")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "tags" && f.value.contains("obfuscated"))
        );
        assert_eq!(e.signals[0].category, "suspicious");
    }

    #[test]
    fn build_unknown_empty() {
        let e = build(&serde_json::json!({"count": 0, "items": []}));
        assert!(e.error.is_none());
        assert!(e.facts.iter().any(|f| f.value.contains("inconnu")));
    }
}
