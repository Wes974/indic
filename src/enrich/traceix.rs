//! Traceix (PCEF / Perkins Cybersecurity Educational Fund) — classification de
//! fichiers par IA + capacités CAPA, interrogeable **par hash SHA-256 seul**.
//! `POST ai.perkinsfund.org/api/traceix/v1/capa/search`, clé en en-tête
//! `x-api-key`, corps `{"sha256": …}`. Gated.
//!
//! ⚠️ L'API répond **HTTP 200 même en erreur** — « hash inconnu » comme « clé
//! invalide » arrivent avec un statut 200 et `success: false`. `error_for_status`
//! ne détecte donc rien : c'est l'enveloppe JSON qui fait foi.
//!
//! ⚠️ Ne connaît que le **SHA-256**. Un MD5 ou un SHA-1 est refusé côté service
//! (« No data found ») — on court-circuite avant l'appel réseau.

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

const ENDPOINT: &str = "https://ai.perkinsfund.org/api/traceix/v1/capa/search";

/// Enveloppe commune à toutes les réponses Traceix.
#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    error: Option<ErrorBody>,
    /// Forme non figée côté service : conservée en `Value` et lue défensivement.
    #[serde(default)]
    results: Option<Value>,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default)]
    error_message: String,
}

/// Vrai si `h` ressemble à un SHA-256 (64 caractères hexadécimaux).
fn is_sha256(h: &str) -> bool {
    h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit())
}

pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("TRACEIX_API_KEY") else {
        return Enrichment::failed("traceix", "clé absente".into());
    };
    if !is_sha256(hash) {
        // Pas une erreur : le service ne couvre simplement pas ce type de hash.
        return Enrichment::ok("traceix", vec![Fact::new("traceix", "SHA-256 uniquement")]);
    }
    match fetch(&ctx.http, hash, key).await {
        Ok(env) => build(&env),
        Err(e) => Enrichment::failed("traceix", super::scrub(format!("{e:#}"), key)),
    }
}

async fn fetch(http: &reqwest::Client, hash: &str, key: &str) -> Result<Envelope> {
    let resp = http
        .post(ENDPOINT)
        .header("x-api-key", key)
        .json(&json!({ "sha256": hash }))
        .send()
        .await?;
    // Un 5xx reste une vraie erreur de transport ; le reste se lit dans le corps.
    if resp.status().is_server_error() {
        anyhow::bail!("Traceix HTTP {}", resp.status());
    }
    Ok(resp.json().await?)
}

fn build(env: &Envelope) -> Enrichment {
    if !env.success {
        let msg = env
            .error
            .as_ref()
            .map(|e| e.error_message.as_str())
            .unwrap_or("")
            .trim();
        // « pas de données » n'est pas un échec d'enrichissement : c'est un
        // résultat négatif, et le distinguer évite de polluer la liste des
        // sources en erreur avec des hashs simplement inconnus.
        if msg.to_ascii_lowercase().contains("no data found") {
            return Enrichment::ok("traceix", vec![Fact::new("traceix", "hash inconnu")]);
        }
        let reason = if msg.is_empty() {
            "réponse Traceix sans détail".to_string()
        } else {
            msg.to_string()
        };
        return Enrichment::failed("traceix", reason);
    }

    let results = env.results.as_ref().unwrap_or(&Value::Null);
    let mut facts = vec![Fact::new("traceix", "hash connu")];
    let mut signals = Vec::new();

    // La forme exacte de `results` n'est pas figée par le service : on lit ce
    // qu'on reconnaît et on résume le reste, plutôt que d'imposer un schéma qui
    // casserait au premier changement.
    if let Some(v) = str_field(
        results,
        &["verdict", "classification", "label", "prediction"],
    ) {
        facts.push(Fact::new("classification", &v));
        let low = v.to_ascii_lowercase();
        if low.contains("malicious") || low.contains("malware") {
            signals.push(Signal::with_detail(
                "traceix",
                "malicious",
                format!("classé {v} par Traceix"),
            ));
        } else if low.contains("suspicious") {
            signals.push(Signal::with_detail(
                "traceix",
                "suspicious",
                format!("classé {v} par Traceix"),
            ));
        }
    }
    if let Some(fam) = str_field(results, &["family", "malware_family"]) {
        facts.push(Fact::new("famille", &fam));
    }
    if let Some(score) = results
        .get("confidence")
        .or_else(|| results.get("score"))
        .and_then(Value::as_f64)
    {
        facts.push(Fact::new("confiance", format!("{:.0} %", score * 100.0)));
    }

    // CAPA : liste de capacités observées dans le binaire.
    let caps = capabilities(results);
    if !caps.is_empty() {
        facts.push(Fact::new("capacités", caps.len().to_string()));
        facts.push(Fact::new(
            "capa",
            caps.iter().take(6).cloned().collect::<Vec<_>>().join(", "),
        ));
    }

    // Aucun champ reconnu mais `success: true` → on le dit franchement plutôt
    // que d'afficher une fiche vide qui laisserait croire à une absence.
    if facts.len() == 1 && caps.is_empty() {
        facts.push(Fact::new("résultat", "présent, format non reconnu"));
    }

    Enrichment {
        source: "traceix".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

/// Premier champ texte non vide parmi `keys`, cherché à la racine puis dans un
/// éventuel objet imbriqué unique (les API enveloppent souvent leurs résultats).
fn str_field(v: &Value, keys: &[&str]) -> Option<String> {
    for k in keys {
        if let Some(s) = v.get(*k).and_then(Value::as_str).filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
    }
    // `results` peut être un tableau d'un seul élément.
    if let Some(first) = v.as_array().and_then(|a| a.first()) {
        return str_field(first, keys);
    }
    None
}

/// Noms de capacités CAPA, quel que soit l'emballage (tableau de chaînes ou
/// tableau d'objets `{name|rule|capability}`).
fn capabilities(v: &Value) -> Vec<String> {
    let arr = v
        .get("capabilities")
        .or_else(|| v.get("capa"))
        .or_else(|| v.get("rules"))
        .and_then(Value::as_array);
    let Some(arr) = arr else { return Vec::new() };
    arr.iter()
        .filter_map(|e| match e {
            Value::String(s) => Some(s.clone()),
            _ => str_field(e, &["name", "rule", "capability"]),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(v: Value) -> Envelope {
        serde_json::from_value(v).unwrap()
    }

    #[test]
    fn only_sha256_is_accepted() {
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"a".repeat(32))); // MD5
        assert!(!is_sha256(&"a".repeat(40))); // SHA-1
        assert!(!is_sha256(&"z".repeat(64))); // non hexadécimal
    }

    /// Le service répond 200 avec `success: false` — c'est l'enveloppe qui fait foi.
    #[test]
    fn unknown_hash_is_a_result_not_a_failure() {
        let e = build(&env(json!({
            "success": false,
            "error": {"error_message": "No data found with SHA hash"},
            "results": null
        })));
        assert!(
            e.error.is_none(),
            "un hash inconnu ne doit pas compter comme source en erreur"
        );
        assert!(e.facts.iter().any(|f| f.value == "hash inconnu"));
    }

    #[test]
    fn invalid_key_is_a_failure() {
        let e = build(&env(json!({
            "success": false,
            "error": {"error_message": "Invalid API key presented"},
            "results": null
        })));
        assert_eq!(e.error.as_deref(), Some("Invalid API key presented"));
    }

    #[test]
    fn malicious_classification_raises_a_signal() {
        let e = build(&env(json!({
            "success": true,
            "results": {"verdict": "malicious", "family": "Emotet", "confidence": 0.97}
        })));
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "famille" && f.value == "Emotet")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "confiance" && f.value == "97 %")
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
    }

    /// `results` peut arriver enveloppé dans un tableau, ou porter des capacités
    /// CAPA sous plusieurs formes — la lecture doit rester tolérante.
    #[test]
    fn tolerates_alternative_shapes() {
        let e = build(&env(json!({
            "success": true,
            "results": [{"classification": "benign"}]
        })));
        assert!(e.facts.iter().any(|f| f.value == "benign"));
        assert!(
            e.signals.is_empty(),
            "un verdict bénin ne doit pas lever de signal"
        );

        let e = build(&env(json!({
            "success": true,
            "results": {"capabilities": ["persist via registry", {"name": "inject into process"}]}
        })));
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "capacités" && f.value == "2")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "capa" && f.value.contains("inject into process"))
        );
    }

    /// `success: true` mais forme inconnue : on l'annonce au lieu d'afficher une
    /// fiche vide qui se lirait comme « rien trouvé ».
    #[test]
    fn unknown_shape_is_reported() {
        let e = build(&env(
            json!({"success": true, "results": {"quelque_chose": 1}}),
        ));
        assert!(
            e.facts
                .iter()
                .any(|f| f.value == "présent, format non reconnu")
        );
    }
}
