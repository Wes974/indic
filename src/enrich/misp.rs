//! Corrélation MISP : interroge le MISP du user (feeds OSINT CIRCL/Botvrij + ce
//! qu'indic y a poussé) pour signaler si l'observable y est déjà documenté.
//! Lecture seule (`/attributes/restSearch`), gated (MISP_URL + MISP_API_KEY).
//! Transforme MISP d'un puits en écriture-seule en source d'enrichissement.

use std::time::Duration;

use anyhow::Result;
use serde_json::{Value, json};

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich(value: &str, ctx: &Ctx) -> Enrichment {
    let (Some(url), Some(key)) = (ctx.key("MISP_URL"), ctx.key("MISP_API_KEY")) else {
        return Enrichment::failed("misp", "non configuré".into());
    };
    match query(value, &url, &key).await {
        Ok((facts, signals)) => Enrichment {
            source: "misp".into(),
            facts,
            signals,
            pivots: vec![],
            error: None,
        },
        Err(e) => Enrichment::failed("misp", format!("{e:#}")),
    }
}

async fn query(value: &str, url: &str, key: &str) -> Result<(Vec<Fact>, Vec<Signal>)> {
    // MISP interne = cert self-signed → même assouplissement TLS que le push.
    let insecure = std::env::var("INDIC_PUSH_INSECURE_TLS").is_ok_and(|v| v == "1" || v == "true");
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(insecure)
        .timeout(Duration::from_secs(15))
        .build()?;
    let endpoint = format!("{}/attributes/restSearch", url.trim_end_matches('/'));
    let body = json!({
        "returnFormat": "json",
        "value": value,
        "limit": 25,
        "includeEventTags": true,
    });
    let v: Value = client
        .post(&endpoint)
        .header("Authorization", key)
        .header("Accept", "application/json")
        .json(&body)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    Ok(parse(&v))
}

/// Extrait les events distincts + tags des attributs correspondants.
fn parse(v: &Value) -> (Vec<Fact>, Vec<Signal>) {
    let attrs = v
        .pointer("/response/Attribute")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    if attrs.is_empty() {
        return (vec![Fact::new("misp", "inconnu")], vec![]);
    }

    let mut events: Vec<(String, String)> = Vec::new(); // (event_id, info)
    let mut tags: Vec<String> = Vec::new();
    for a in &attrs {
        let eid = a.get("event_id").and_then(Value::as_str).unwrap_or("?");
        let info = a.pointer("/Event/info").and_then(Value::as_str).unwrap_or("");
        if !events.iter().any(|(id, _)| id == eid) {
            events.push((eid.to_string(), info.to_string()));
        }
        for t in a.get("Tag").and_then(Value::as_array).into_iter().flatten() {
            if let Some(name) = t.get("name").and_then(Value::as_str) {
                if !tags.iter().any(|x| x == name) {
                    tags.push(name.to_string());
                }
            }
        }
    }

    let n = events.len();
    let mut facts = vec![Fact::new("misp_events", n.to_string())];
    if let Some((id, info)) = events.first() {
        let info: String = info.chars().take(70).collect();
        facts.push(Fact::new("misp_event", format!("#{id} {info}").trim().to_string()));
    }
    if !tags.is_empty() {
        let shown: Vec<String> = tags.iter().take(6).cloned().collect();
        facts.push(Fact::new("misp_tags", shown.join(", ")));
    }
    // `threat` (pas `malicious`) : un match MISP est fort mais MISP peut aussi
    // contenir du bénin/référence → on reste conservateur pour le verdict.
    let signals = vec![Signal::with_detail(
        "misp",
        "threat",
        format!("connu de MISP ({n} event{})", if n > 1 { "s" } else { "" }),
    )];
    (facts, signals)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_match_produces_signal() {
        let v = json!({
            "response": { "Attribute": [
                {
                    "event_id": "42",
                    "value": "1.2.3.4",
                    "Event": { "info": "CIRCL OSINT feed - malware C2" },
                    "Tag": [{ "name": "tlp:white" }, { "name": "type:OSINT" }]
                },
                {
                    "event_id": "42",
                    "value": "1.2.3.4",
                    "Event": { "info": "CIRCL OSINT feed - malware C2" }
                }
            ]}
        });
        let (facts, signals) = parse(&v);
        // 2 attributs mais 1 seul event distinct
        assert!(facts.iter().any(|f| f.key == "misp_events" && f.value == "1"));
        assert!(facts.iter().any(|f| f.key == "misp_event" && f.value.contains("#42")));
        assert!(facts.iter().any(|f| f.key == "misp_tags" && f.value.contains("tlp:white")));
        assert_eq!(signals.len(), 1);
        assert_eq!(signals[0].category, "threat");
    }

    #[test]
    fn parse_no_match_no_signal() {
        let v = json!({ "response": { "Attribute": [] } });
        let (facts, signals) = parse(&v);
        assert!(signals.is_empty());
        assert!(facts.iter().any(|f| f.value == "inconnu"));
    }
}
