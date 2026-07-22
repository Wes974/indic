//! AURA (PCEF) — triage malware par IA, interrogeable **par hash SHA-256**.
//! `POST ai.perkinsfund.org/api/search`, clé en en-tête `x-api-key`. Gated.
//!
//! Même plateforme et **même clé que Traceix** (compte perkinsfund unique,
//! vérifié : la clé Traceix authentifie bien `/api/search`). D'où le gating sur
//! `TRACEIX_API_KEY` plutôt qu'une seconde variable à remplir avec la même
//! valeur — le panneau de santé affiche la clé réellement utilisée.
//!
//! Corpus **distinct** de celui de Traceix/CAPA : EICAR est connu d'AURA et
//! absent de CAPA. Les deux sources ne font donc pas doublon, elles se
//! corroborent — ce que le moteur de verdict d'indic sait exploiter.
//!
//! ⚠️ HTTP 200 même en erreur : `success`/`error` dans le corps.
//! ⚠️ Ne classe que les exécutables **PE Windows et ELF Linux** ; tout le reste
//! ressort en `unknown`, ce qui n'est pas un échec mais une non-couverture.

use anyhow::Result;
use serde::Deserialize;
use serde_json::json;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

const ENDPOINT: &str = "https://ai.perkinsfund.org/api/search";

#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    error: Option<ErrorBody>,
    #[serde(default)]
    results: Option<Results>,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error_message: String,
}

#[derive(Deserialize)]
struct Results {
    /// Classe prédite : `safe`, `unknown`, ou une étiquette de détection.
    #[serde(default)]
    class: String,
    /// Horodatage de la classification (epoch), absent si jamais analysé.
    #[serde(default)]
    created_at: Option<f64>,
}

/// Vrai si `h` ressemble à un SHA-256 (64 caractères hexadécimaux).
fn is_sha256(h: &str) -> bool {
    h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit())
}

pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("TRACEIX_API_KEY") else {
        return Enrichment::failed("aura", "clé absente".into());
    };
    if !is_sha256(hash) {
        return Enrichment::ok("aura", vec![Fact::new("aura", "SHA-256 uniquement")]);
    }
    match fetch(ctx, hash, key).await {
        Ok(env) => build(&env),
        Err(e) => Enrichment::failed("aura", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(ctx: &Ctx, hash: &str, key: &str) -> Result<Envelope> {
    let resp = ctx
        .http
        .post(ENDPOINT)
        .header("x-api-key", key)
        .json(&json!({ "sha256": hash }))
        .send()
        .await?;
    if resp.status().is_server_error() {
        anyhow::bail!("AURA HTTP {}", resp.status());
    }
    Ok(resp.json().await?)
}

/// Vrai si le motif d'échec traduit une absence de données plutôt qu'une panne.
fn is_not_found(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("did not pass heuristics") || m.contains("no data") || m.contains("not found")
}

fn build(env: &Envelope) -> Enrichment {
    let err = env
        .error
        .as_ref()
        .map(|e| e.error_message.trim())
        .unwrap_or("");
    if !err.is_empty() {
        // Une absence n'est pas une panne : la distinguer évite de faire passer
        // la source pour cassée à chaque hash qu'elle ne connaît pas.
        if is_not_found(err) {
            return Enrichment::ok("aura", vec![Fact::new("aura", "hash inconnu")]);
        }
        return Enrichment::failed("aura", err.to_string());
    }

    let Some(r) = env.results.as_ref().filter(|r| !r.class.is_empty()) else {
        return Enrichment::ok("aura", vec![Fact::new("aura", "hash inconnu")]);
    };

    let class = r.class.to_ascii_lowercase();
    let mut facts = vec![Fact::new("classification", &r.class)];
    if let Some(ts) = r.created_at.filter(|t| *t > 0.0) {
        facts.push(Fact::new("analysé_le", fmt_date(ts)));
    }

    let mut signals = Vec::new();
    // `unknown` = format non couvert (AURA ne classe que PE et ELF), pas un
    // verdict : ne rien en conclure, ni dans un sens ni dans l'autre.
    if class.contains("malware") || class.contains("malicious") {
        signals.push(Signal::with_detail(
            "aura",
            "malicious",
            format!("classé {} par AURA", r.class),
        ));
    } else if class == "unknown" {
        facts.push(Fact::new("note", "format non couvert (PE/ELF uniquement)"));
    }

    Enrichment {
        source: "aura".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

/// `YYYY-MM-DD` depuis un epoch. `civil_from_days` (Hinnant), déjà utilisé pour
/// les fenêtres de quota — évite une dépendance date pour ce seul affichage.
fn fmt_date(epoch: f64) -> String {
    let days = (epoch as i64) / 86_400;
    let (y, m, d) = crate::enrich::civil_from_days(days);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn env(v: Value) -> Envelope {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn only_sha256_is_accepted() {
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"a".repeat(32)));
    }

    /// Réponse réelle relevée en production sur un échantillon du dataset public.
    #[test]
    fn safe_class_raises_no_signal() {
        let e = build(&env(json!({
            "error": {},
            "results": {"class": "safe", "created_at": 1746727082.19, "file_hash": "x"}
        })));
        assert!(e.signals.is_empty());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "classification" && f.value == "safe")
        );
        assert!(e.facts.iter().any(|f| f.key == "analysé_le"));
    }

    /// `unknown` = format non couvert (AURA ne classe que PE/ELF). Ce n'est pas
    /// un verdict « propre » : aucun signal, mais on explique pourquoi.
    #[test]
    fn unknown_class_is_explained_not_judged() {
        let e = build(&env(json!({
            "error": {},
            "results": {"class": "unknown", "created_at": 1758813933.81}
        })));
        assert!(e.signals.is_empty());
        assert!(e.facts.iter().any(|f| f.value.contains("PE/ELF")));
    }

    /// Chemin de détection : **non observé** faute d'échantillon détecté dans le
    /// corpus public — forme déduite de la doc et du chemin « safe ».
    #[test]
    fn malware_class_raises_a_signal() {
        let e = build(&env(json!({"error": {}, "results": {"class": "malware"}})));
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
    }

    #[test]
    fn heuristics_rejection_is_not_a_failure() {
        let e = build(&env(json!({
            "error": {"error_message": "SHA256 hash did not pass heuristics check, is it a hash?"}
        })));
        assert!(e.error.is_none());
        assert!(e.facts.iter().any(|f| f.value == "hash inconnu"));
    }

    #[test]
    fn invalid_key_is_a_failure() {
        let e = build(&env(json!({
            "error": {"error_message": "invalid API key supplied"}
        })));
        assert_eq!(e.error.as_deref(), Some("invalid API key supplied"));
    }

    /// Réponse **réelle** enregistrée (voir `fixtures/README.md`).
    #[test]
    fn replays_recorded_response() {
        let env: Envelope = serde_json::from_str(include_str!("fixtures/aura-known.json")).unwrap();
        let e = build(&env);
        assert!(e.error.is_none());
        assert!(e.facts.iter().any(|f| f.key == "classification"));
    }

    #[test]
    fn formats_the_analysis_date() {
        // 1746727082 = 2025-05-08 (UTC)
        assert_eq!(fmt_date(1_746_727_082.0), "2025-05-08");
    }
}
