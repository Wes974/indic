//! EmailRep.io — réputation d'email (fraude, credentials leakés, blacklist).
//! API: GET /{email}?key=... — gratuite avec quota basique.

use serde_json::Value;

use super::{Ctx, Enrichment, Fact, Signal, scrub};

pub async fn enrich_email(email: &str, ctx: &Ctx) -> Enrichment {
    let key = ctx.key("EMAILREP_API_KEY").unwrap_or_default();
    let url = format!("https://emailrep.io/{email}");
    match ctx
        .http
        .get(&url)
        .header("Key", &key)
        .header("User-Agent", "indic/0.1")
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            let v: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
            let mut facts = Vec::new();
            let mut signals = Vec::new();

            if let Some(reputation) = v.get("reputation").and_then(|r| r.as_str()) {
                facts.push(Fact::new("réputation", reputation));
            }
            if let Some(suspicious) = v.get("suspicious").and_then(|b| b.as_bool()) {
                facts.push(Fact::new("suspect", if suspicious { "oui" } else { "non" }));
                if suspicious {
                    signals.push(Signal::new("emailrep", "suspicious"));
                }
            }
            if let Some(details) = v.get("details").and_then(|d| d.as_object()) {
                if let Some(blacklisted) = details.get("blacklisted").and_then(|b| b.as_bool())
                    && blacklisted
                {
                    signals.push(Signal::new("emailrep", "abuse"));
                    facts.push(Fact::new("blacklisté", "oui"));
                }
                if let Some(malicious) = details.get("malicious_activity").and_then(|b| b.as_bool())
                    && malicious
                {
                    signals.push(Signal::new("emailrep", "malicious"));
                    facts.push(Fact::new("activité_malveillante", "oui"));
                }
                if let Some(deliverable) = details.get("deliverable").and_then(|b| b.as_bool()) {
                    facts.push(Fact::new(
                        "délivrable",
                        if deliverable { "oui" } else { "non" },
                    ));
                }
                if let Some(disposable) = details.get("disposable").and_then(|b| b.as_bool())
                    && disposable
                {
                    signals.push(Signal::new("emailrep", "suspicious"));
                    facts.push(Fact::new("jetable", "oui"));
                }
                if let Some(credentials_leaked) =
                    details.get("credentials_leaked").and_then(|b| b.as_bool())
                    && credentials_leaked
                {
                    signals.push(Signal::new("emailrep", "compromised"));
                    facts.push(Fact::new("credentials_fuitées", "oui"));
                }
                if let Some(leaked) = details.get("leaked").and_then(|b| b.as_bool())
                    && leaked
                {
                    facts.push(Fact::new("données_fuitées", "oui"));
                }
                // Dates de dernière fuite
                if let Some(days) = details
                    .get("credentials_leaked_recent")
                    .and_then(|d| d.as_i64())
                {
                    facts.push(Fact::new("dernière_fuite", format!("il y a {days} jours")));
                }
                for key in &["domain_reputation", "spam", "spoofable", "social_medias"] {
                    if let Some(val) = details.get(*key).and_then(|v| v.as_bool())
                        && (!val || matches!(*key, "spam"))
                    {
                        facts.push(Fact::new(
                            key,
                            if val {
                                "oui"
                            } else if *key == "spam" {
                                "non"
                            } else {
                                "ok"
                            },
                        ));
                    }
                }
            }

            let error = if status.is_client_error() || status.is_server_error() {
                let msg = v
                    .get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or(&body)
                    .to_string();
                Some(scrub(msg, &key))
            } else {
                None
            };

            Enrichment {
                source: "emailrep".into(),
                facts,
                signals,
                pivots: vec![],
                error,
            }
        }
        Err(e) => Enrichment::failed("emailrep", scrub(e.to_string(), &key)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emailrep_scrub_hides_key() {
        // Ne pas faire de requête réseau, juste tester le comportement de base.
        let scrubbed = scrub("error for url (key=secret) and more".into(), "secret");
        assert!(!scrubbed.contains("secret"));
        assert!(scrubbed.contains("<redacted>"));
    }
}
