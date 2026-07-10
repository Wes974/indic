//! Hunter.io — vérification de délivrabilité d'un email : status, score, flags
//! (disposable/webmail/accept_all/block). `GET api.hunter.io/v2/email-verifier`,
//! clé en query `api_key`. Gated. Parsing défensif (Value).

use anyhow::Result;
use serde_json::Value;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

pub async fn enrich_email(email: &str, ctx: &Ctx) -> Enrichment {
    let Some(key) = ctx.key("HUNTER_IO_API_KEY") else {
        return Enrichment::failed("hunter", "clé absente".into());
    };
    match fetch(&ctx.http, email, key).await {
        Ok(v) => build(&v),
        Err(e) => Enrichment::failed("hunter", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, email: &str, key: &str) -> Result<Value> {
    Ok(http
        .get("https://api.hunter.io/v2/email-verifier")
        .query(&[("email", email), ("api_key", key)])
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?)
}

fn build(v: &Value) -> Enrichment {
    let Some(data) = v.get("data") else {
        return Enrichment::ok("hunter", vec![Fact::new("hunter", "aucune donnée")]);
    };

    let mut facts = Vec::new();
    for (label, k) in [("status", "status"), ("deliverability", "result")] {
        if let Some(s) = data
            .get(k)
            .and_then(|x| x.as_str())
            .filter(|s| !s.is_empty())
        {
            facts.push(Fact::new(label, s));
        }
    }
    if let Some(score) = data.get("score").and_then(|x| x.as_i64()) {
        facts.push(Fact::new("score", format!("{score}/100")));
    }

    // Flags booléens actifs.
    let flags: Vec<&str> = ["disposable", "webmail", "accept_all", "block", "gibberish"]
        .into_iter()
        .filter(|f| data.get(*f).and_then(|x| x.as_bool()) == Some(true))
        .collect();
    if !flags.is_empty() {
        facts.push(Fact::new("flags", flags.join(", ")));
    }
    if facts.is_empty() {
        facts.push(Fact::new("hunter", "aucune donnée exploitable"));
    }

    // Email jetable = signal (inscriptions frauduleuses / abus).
    let mut signals = Vec::new();
    if data.get("disposable").and_then(|x| x.as_bool()) == Some(true) {
        signals.push(Signal::with_detail(
            "hunter",
            "suspicious",
            "email jetable (disposable)",
        ));
    }

    Enrichment {
        source: "hunter".into(),
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
    fn build_disposable_flags_suspicious() {
        let v = serde_json::json!({"data": {
            "status": "webmail", "result": "risky", "score": 40,
            "disposable": true, "webmail": true
        }});
        let e = build(&v);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "status" && f.value == "webmail")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "flags" && f.value.contains("disposable"))
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "suspicious");
    }

    #[test]
    fn build_valid_no_signal() {
        let v = serde_json::json!({"data": {
            "status": "valid", "result": "deliverable", "score": 95, "disposable": false
        }});
        let e = build(&v);
        assert!(e.signals.is_empty());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "score" && f.value == "95/100")
        );
    }
}
