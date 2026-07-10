//! MalShare — présence d'un hash dans le corpus de malware MalShare (+ type, sources).
//! `GET malshare.com/api.php?api_key=&action=details&hash=`. Clé en query. Gated.
//! ⚠️ Hash inconnu = réponse TEXTE ("Sample not found by hash") en HTTP 200, pas du
//! JSON → on lit le corps en texte et on ne parse que si ça commence par `{`.

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("MALSHARE_API_KEY") else {
        return Enrichment::failed("malshare", "clé absente".into());
    };
    match fetch(&ctx.http, hash, key).await {
        Ok(Some(v)) => build(&v),
        Ok(None) => Enrichment::ok("malshare", vec![Fact::new("malshare", "hash inconnu")]),
        Err(e) => Enrichment::failed("malshare", super::scrub(format!("{e:#}"), key)),
    }
}

/// `Ok(None)` = hash inconnu (réponse texte). `Ok(Some)` = présent (JSON).
async fn fetch(http: &reqwest::Client, hash: &str, key: &str) -> Result<Option<Value>> {
    let resp = http
        .get("https://malshare.com/api.php")
        .query(&[("api_key", key), ("action", "details"), ("hash", hash)])
        .send()
        .await?;
    // MalShare renvoie 404 pour un hash absent de son corpus (≠ erreur).
    if resp.status() == reqwest::StatusCode::NOT_FOUND {
        return Ok(None);
    }
    let body = resp.error_for_status()?.text().await?;
    if body.trim_start().starts_with('{') {
        Ok(Some(serde_json::from_str(&body)?))
    } else if body.to_ascii_lowercase().contains("not found") {
        Ok(None)
    } else {
        // "Invalid Hash", "Account not activated", etc.
        anyhow::bail!("réponse MalShare : {}", body.trim())
    }
}

fn build(v: &Value) -> Enrichment {
    // Casing incertain (md5 vs MD5) → on tente les deux.
    let field = |lower: &str, upper: &str| {
        v.get(lower)
            .or_else(|| v.get(upper))
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
    };

    // Présence dans MalShare = échantillon de malware connu.
    let mut facts = vec![Fact::new("malshare", "hash présent (malware connu)")];
    if let Some(t) = field("f_type", "F_TYPE") {
        facts.push(Fact::new("type", t));
    }
    if let Some(s) = field("ssdeep", "SSDEEP") {
        facts.push(Fact::new("ssdeep", s));
    }
    if let Some(sources) = v
        .get("sources")
        .or_else(|| v.get("SOURCES"))
        .and_then(|x| x.as_array())
        .filter(|a| !a.is_empty())
    {
        facts.push(Fact::new("sources", sources.len().to_string()));
    }

    let signals = vec![Signal::with_detail(
        "malshare",
        "malicious",
        "échantillon présent dans MalShare",
    )];
    Enrichment {
        source: "malshare".into(),
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
    fn build_present_flags_malicious() {
        let v = serde_json::json!({
            "md5": "a", "sha256": "b", "f_type": "PE32",
            "sources": ["http://x", "http://y"]
        });
        let e = build(&v);
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
        assert!(e.facts.iter().any(|f| f.key == "type" && f.value == "PE32"));
        assert!(e.facts.iter().any(|f| f.key == "sources" && f.value == "2"));
    }

    #[test]
    fn build_uppercase_casing() {
        let v = serde_json::json!({"F_TYPE": "ELF"});
        let e = build(&v);
        assert!(e.facts.iter().any(|f| f.key == "type" && f.value == "ELF"));
    }
}
