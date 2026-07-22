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
use serde_json::json;

use crate::enrich::{Ctx, Enrichment, Fact};

const ENDPOINT: &str = "https://ai.perkinsfund.org/api/traceix/v1/capa/search";

/// Enveloppe commune à toutes les réponses Traceix.
#[derive(Deserialize)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    error: Option<ErrorBody>,
    /// Tableau des capacités CAPA (vide ou absent si le hash est inconnu).
    #[serde(default)]
    results: Option<Vec<Capability>>,
}

/// Une capacité CAPA telle que renvoyée par Traceix.
#[derive(Deserialize)]
struct Capability {
    #[serde(default)]
    name: String,
    /// Paires `[tactique, technique]` MITRE ATT&CK.
    #[serde(default)]
    attack: Vec<Vec<String>>,
    /// Paires `[comportement, identifiant]` du Malware Behavior Catalog.
    #[serde(default)]
    catalog: Vec<Vec<String>>,
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

    // Forme réelle observée en production : `results` est un tableau plat de
    // capacités CAPA, chacune `{name, attack: [[tactique, Txxxx]], catalog:
    // [[comportement, ID MBC]]}`. Pas de verdict : CAPA décrit ce que le
    // binaire *sait faire*, pas s'il est malveillant — allouer de la mémoire
    // n'accuse personne. On expose donc des faits, sans lever de signal.
    let caps: &[Capability] = env.results.as_deref().unwrap_or(&[]);
    if caps.is_empty() {
        return Enrichment::ok(
            "traceix",
            vec![Fact::new("traceix", "aucune capacité extraite")],
        );
    }

    let mut facts = vec![Fact::new("capacités", caps.len().to_string())];

    // ATT&CK : l'information la plus exploitable pour du CTI, dédupliquée et
    // triée pour rester stable d'un lookup à l'autre.
    let mut attack: Vec<String> = caps
        .iter()
        .flat_map(|c| c.attack.iter())
        .filter_map(|p| match p.as_slice() {
            [tactic, id] => Some(format!("{id} ({tactic})")),
            _ => None,
        })
        .collect();
    attack.sort_unstable();
    attack.dedup();
    if !attack.is_empty() {
        facts.push(Fact::new("att&ck", attack.join(", ")));
    }

    // MBC (Malware Behavior Catalog) : complément d'ATT&CK côté comportements.
    let mut mbc: Vec<String> = caps
        .iter()
        .flat_map(|c| c.catalog.iter())
        .filter_map(|p| p.first().cloned())
        .collect();
    mbc.sort_unstable();
    mbc.dedup();
    if !mbc.is_empty() {
        facts.push(Fact::new(
            "comportements",
            mbc.iter().take(8).cloned().collect::<Vec<_>>().join(", "),
        ));
    }

    let names: Vec<&str> = caps.iter().map(|c| c.name.as_str()).collect();
    facts.push(Fact::new(
        "capa",
        names.iter().take(8).copied().collect::<Vec<_>>().join(", "),
    ));

    Enrichment::ok("traceix", facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn env(v: serde_json::Value) -> Envelope {
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

    /// Extrait vérbatim d'une réponse réelle de l'API (hash présent dans le
    /// dataset public IPFS de Traceix) — la première version du parseur visait
    /// un objet `{verdict, capabilities}` qui n'existe pas, et aurait affiché
    /// « format non reconnu » sur toutes les réponses valides.
    #[test]
    fn parses_the_real_capa_shape() {
        let e = build(&env(json!({
            "success": true,
            "error": {},
            "results": [
                {"attack": [["Execution", "T1129"]], "catalog": [],
                 "name": "Link Function At Runtime On Windows"},
                {"attack": [["Defense Evasion", "T1564.003"]], "catalog": [],
                 "name": "Hide Graphical Window"},
                {"attack": [], "catalog": [["Debugger Detection", "B0001.019"]],
                 "name": "Peb Access"},
                {"attack": [["Execution", "T1129"]], "catalog": [["Allocate Memory", "C0007"]],
                 "name": "Allocate Memory"}
            ]
        })));
        assert!(e.error.is_none());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "capacités" && f.value == "4")
        );
        // T1129 apparaît deux fois dans la réponse : il ne doit sortir qu'une fois.
        let atk = e.facts.iter().find(|f| f.key == "att&ck").expect("att&ck");
        assert_eq!(atk.value, "T1129 (Execution), T1564.003 (Defense Evasion)");
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "comportements" && f.value.contains("Debugger Detection"))
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "capa" && f.value.contains("Hide Graphical Window"))
        );
        // CAPA décrit des capacités, pas une intention : aucun signal levé.
        assert!(
            e.signals.is_empty(),
            "une capacité n'est pas un verdict — allouer de la mémoire n'accuse personne"
        );
    }

    /// `success: true` avec un tableau vide : le hash est connu mais rien n'a
    /// été extrait. À dire explicitement plutôt que d'afficher une fiche vide.
    #[test]
    fn empty_results_is_reported() {
        let e = build(&env(json!({"success": true, "results": []})));
        assert!(
            e.facts
                .iter()
                .any(|f| f.value == "aucune capacité extraite")
        );
    }
}
