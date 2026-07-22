//! Traceix (PCEF / Perkins Cybersecurity Educational Fund) — trois recherches
//! par **hash SHA-256**, lancées en parallèle :
//!   - `/api/v1/traceix/av/lookup`      verdicts multi-moteurs (la seule qui juge)
//!   - `/api/traceix/v1/capa/search`    capacités CAPA + techniques ATT&CK
//!   - `/api/v1/traceix/ioc/hash`       règle YARA générée, si elle existe
//!
//! Clé en en-tête `x-api-key`. Gated.
//!
//! ⚠️ L'API répond **HTTP 200 même en erreur** : `success: false` et le motif
//! dans le corps. `error_for_status` ne détecte rien.
//!
//! ⚠️ **La doc officielle diverge de l'API en production** — vérifié sur les
//! deux. Elle annonce pour CAPA `results: {sha256, capabilities: [{name,
//! attack_id}]}` alors que le service renvoie un tableau plat `[{name, attack:
//! [[tactique, id]], catalog: [[…]]}]`, et un libellé d'absence différent. Les
//! deux formes sont donc acceptées : coder sur la doc seule casserait tout de
//! suite, coder sur l'observation seule casserait le jour de l'alignement.
//!
//! ⚠️ Ne connaît que le SHA-256 : MD5/SHA-1 court-circuités avant le réseau.

use anyhow::Result;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

const BASE: &str = "https://ai.perkinsfund.org";

/// Enveloppe commune. L'endpoint YARA renvoie `data` là où les autres renvoient
/// `results`, et `error.msg` là où les autres utilisent `error.error_message` :
/// `post()` normalise le premier, l'alias serde couvre le second.
#[derive(Deserialize, Default)]
struct Envelope {
    #[serde(default)]
    success: bool,
    #[serde(default)]
    error: Option<ErrorBody>,
    #[serde(default)]
    results: Option<Value>,
}

#[derive(Deserialize)]
struct ErrorBody {
    #[serde(default, alias = "msg")]
    error_message: String,
}

/// Verdict d'un moteur antivirus.
#[derive(Deserialize, Default)]
struct AvResult {
    #[serde(default)]
    engine: String,
    #[serde(default)]
    verdict: String,
}

/// Vrai si `h` ressemble à un SHA-256 (64 caractères hexadécimaux).
fn is_sha256(h: &str) -> bool {
    h.len() == 64 && h.chars().all(|c| c.is_ascii_hexdigit())
}

/// Vrai si le motif d'échec signifie « ce hash est inconnu » plutôt qu'une
/// panne. Deux libellés coexistent : celui observé en production (« No data
/// found with SHA hash ») et celui de la doc (« No matching record for provided
/// SHA256 »). On couvre les deux — s'appuyer sur une seule chaîne ferait
/// basculer tous les hashs inconnus dans les sources en erreur le jour où le
/// service reformule.
fn is_not_found(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    m.contains("no data found") || m.contains("no matching record") || m.contains("no yara rule")
}

pub async fn enrich_hash(hash: &str, ctx: &Ctx) -> Enrichment {
    let Some(ref key) = ctx.key("TRACEIX_API_KEY") else {
        return Enrichment::failed("traceix", "clé absente".into());
    };
    if !is_sha256(hash) {
        return Enrichment::ok("traceix", vec![Fact::new("traceix", "SHA-256 uniquement")]);
    }

    // Trois requêtes indépendantes : en parallèle, la latence est celle de la
    // plus lente, pas leur somme.
    let (av, capa, yara) = tokio::join!(
        post(ctx, "/api/v1/traceix/av/lookup", hash, key),
        post(ctx, "/api/traceix/v1/capa/search", hash, key),
        post(ctx, "/api/v1/traceix/ioc/hash", hash, key),
    );

    // Échec de transport sur les trois = la source est en panne. Si au moins une
    // répond, on exploite ce qu'on a plutôt que de tout jeter.
    if let (Err(e), Err(_), Err(_)) = (&av, &capa, &yara) {
        return Enrichment::failed("traceix", super::scrub(format!("{e:#}"), key));
    }
    build(av.ok(), capa.ok(), yara.ok())
}

async fn post(ctx: &Ctx, path: &str, hash: &str, key: &str) -> Result<Envelope> {
    let resp = ctx
        .http
        .post(format!("{BASE}{path}"))
        .header("x-api-key", key)
        .json(&json!({ "sha256": hash }))
        .send()
        .await?;
    if resp.status().is_server_error() {
        anyhow::bail!("Traceix HTTP {}", resp.status());
    }
    let mut v: Value = resp.json().await?;
    if v.get("results").is_none()
        && let Some(data) = v.get("data").cloned()
    {
        v["results"] = data;
    }
    Ok(serde_json::from_value(v).unwrap_or_default())
}

/// Motif d'échec « réel » (`None` si succès ou simple absence de données).
fn hard_error(env: &Option<Envelope>) -> Option<String> {
    let e = env.as_ref()?;
    if e.success {
        return None;
    }
    let msg = e
        .error
        .as_ref()
        .map(|x| x.error_message.trim())
        .unwrap_or("");
    (!is_not_found(msg) && !msg.is_empty()).then(|| msg.to_string())
}

fn results(env: &Option<Envelope>) -> Option<&Value> {
    let e = env.as_ref()?;
    e.success.then_some(e.results.as_ref()?)
}

fn build(av: Option<Envelope>, capa: Option<Envelope>, yara: Option<Envelope>) -> Enrichment {
    // Une clé invalide se manifeste sur tous les appels : le dire une fois vaut
    // mieux que de rendre une fiche à moitié vide sans expliquer pourquoi.
    if let Some(msg) = hard_error(&av).or_else(|| hard_error(&capa)) {
        return Enrichment::failed("traceix", msg);
    }

    let mut facts = Vec::new();
    let mut signals = Vec::new();

    // ── Verdicts antivirus : la seule partie qui juge ────────────────────────
    if let Some(r) = results(&av) {
        let engines: Vec<AvResult> = serde_json::from_value(r.clone()).unwrap_or_default();
        let flagged: Vec<&str> = engines
            .iter()
            .filter(|e| e.verdict.eq_ignore_ascii_case("malicious"))
            .map(|e| e.engine.as_str())
            .collect();
        let judged = engines
            .iter()
            .filter(|e| !e.verdict.eq_ignore_ascii_case("unknown"))
            .count();
        if !engines.is_empty() {
            facts.push(Fact::new(
                "antivirus",
                format!("{}/{} moteurs concluants", judged, engines.len()),
            ));
            let detail: Vec<String> = engines
                .iter()
                .map(|e| format!("{} : {}", e.engine, e.verdict))
                .collect();
            facts.push(Fact::new("moteurs", detail.join(", ")));
        }
        if !flagged.is_empty() {
            signals.push(Signal::with_detail(
                "traceix",
                "malicious",
                format!("détecté par {}", flagged.join(", ")),
            ));
        }
    }

    // ── CAPA : capacités + ATT&CK. Aucun signal : CAPA décrit ce qu'un binaire
    //    sait faire, pas s'il est malveillant — allouer de la mémoire n'accuse
    //    personne, et un packer légitime fait de l'anti-debug.
    if let Some(r) = results(&capa) {
        let caps = capabilities(r);
        if !caps.is_empty() {
            facts.push(Fact::new("capacités", caps.len().to_string()));
            let mut attack: Vec<String> = caps.iter().flat_map(|c| c.attack.clone()).collect();
            attack.sort_unstable();
            attack.dedup();
            if !attack.is_empty() {
                facts.push(Fact::new("att&ck", attack.join(", ")));
            }
            let mut mbc: Vec<String> = caps.iter().flat_map(|c| c.catalog.clone()).collect();
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
        }
    }

    // ── Règle YARA générée ───────────────────────────────────────────────────
    if let Some(r) = results(&yara)
        && let Some(rule) = r
            .get("rule")
            .or_else(|| r.get("yara_rule"))
            .and_then(Value::as_str)
    {
        let name = rule
            .split_once("rule ")
            .and_then(|(_, rest)| rest.split_whitespace().next())
            .unwrap_or("disponible");
        facts.push(Fact::new("yara", name));
    }

    if facts.is_empty() {
        return Enrichment::ok("traceix", vec![Fact::new("traceix", "hash inconnu")]);
    }
    Enrichment {
        source: "traceix".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

/// Une capacité, normalisée depuis l'une ou l'autre des deux formes connues.
struct Capability {
    name: String,
    /// Techniques ATT&CK déjà formatées (`T1129 (Execution)`).
    attack: Vec<String>,
    /// Comportements MBC.
    catalog: Vec<String>,
}

/// Lit les capacités, que `results` soit le tableau plat renvoyé en production
/// ou l'objet `{capabilities: [{name, attack_id}]}` décrit par la doc.
fn capabilities(v: &Value) -> Vec<Capability> {
    let arr = match v {
        Value::Array(a) => a.clone(),
        _ => v
            .get("capabilities")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default(),
    };
    arr.iter()
        .map(|e| {
            let name = e
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            // Production : `attack: [["Execution", "T1129"]]`.
            let mut attack: Vec<String> = e
                .get("attack")
                .and_then(Value::as_array)
                .map(|ps| {
                    ps.iter()
                        .filter_map(|p| {
                            let a = p.as_array()?;
                            let tactic = a.first()?.as_str()?;
                            let id = a.get(1)?.as_str()?;
                            Some(format!("{id} ({tactic})"))
                        })
                        .collect()
                })
                .unwrap_or_default();
            // Doc : `attack_id: "T1060"`.
            if let Some(id) = e.get("attack_id").and_then(Value::as_str) {
                attack.push(id.to_string());
            }
            let catalog: Vec<String> = e
                .get("catalog")
                .and_then(Value::as_array)
                .map(|ps| {
                    ps.iter()
                        .filter_map(|p| p.as_array()?.first()?.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            Capability {
                name,
                attack,
                catalog,
            }
        })
        .filter(|c| !c.name.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(v: Value) -> Option<Envelope> {
        Some(serde_json::from_value(v).unwrap())
    }

    #[test]
    fn only_sha256_is_accepted() {
        assert!(is_sha256(&"a".repeat(64)));
        assert!(!is_sha256(&"a".repeat(32))); // MD5
        assert!(!is_sha256(&"a".repeat(40))); // SHA-1
        assert!(!is_sha256(&"z".repeat(64))); // non hexadécimal
    }

    /// Les deux libellés d'absence — celui de la prod et celui de la doc —
    /// doivent être reconnus, sinon les hashs inconnus polluent les erreurs.
    #[test]
    fn both_not_found_wordings_are_recognised() {
        assert!(is_not_found("No data found with SHA hash")); // observé en prod
        assert!(is_not_found("No matching record for provided SHA256")); // doc
        assert!(is_not_found("No Yara rule from provided sha hash"));
        assert!(!is_not_found("Invalid API key presented"));
    }

    #[test]
    fn unknown_hash_is_a_result_not_a_failure() {
        let e = build(
            env(
                json!({"success": false, "error": {"error_message": "No data found with SHA hash"}}),
            ),
            env(
                json!({"success": false, "error": {"error_message": "No matching record for provided SHA256"}}),
            ),
            env(json!({"success": false, "error": {"msg": "No Yara rule from provided sha hash"}})),
        );
        assert!(e.error.is_none(), "un hash inconnu n'est pas une panne");
        assert!(e.facts.iter().any(|f| f.value == "hash inconnu"));
    }

    #[test]
    fn invalid_key_is_a_failure() {
        let e = build(
            env(json!({"success": false, "error": {"error_message": "Invalid API key provided"}})),
            None,
            None,
        );
        assert_eq!(e.error.as_deref(), Some("Invalid API key provided"));
    }

    /// Réponse AV réelle relevée en production sur un échantillon du dataset
    /// public : tous les moteurs disent « Safe », aucun signal ne doit sortir.
    #[test]
    fn clean_av_verdict_raises_no_signal() {
        let e = build(
            env(json!({"success": true, "results": [
                {"engine": "xVirus", "engine_type": "micro-antivirus", "verdict": "Safe"},
                {"engine": "ClamAV", "engine_type": "antivirus", "verdict": "Safe"},
                {"engine": "Intelix", "engine_type": "hash-lookup", "verdict": "Unknown"}
            ]})),
            None,
            None,
        );
        assert!(e.signals.is_empty());
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "antivirus" && f.value == "2/3 moteurs concluants")
        );
    }

    /// Chemin `Malicious` : **aucun échantillon du dataset public de Traceix
    /// n'est détecté**, il n'a donc pas pu être observé en vrai. La forme est
    /// celle de la doc, confirmée sur le chemin « Safe ».
    #[test]
    fn malicious_engine_raises_a_signal() {
        let e = build(
            env(json!({"success": true, "results": [
                {"engine": "ClamAV", "verdict": "Malicious"},
                {"engine": "xVirus", "verdict": "Safe"}
            ]})),
            None,
            None,
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "malicious");
        assert!(e.signals[0].detail.as_deref().unwrap().contains("ClamAV"));
    }

    /// Forme CAPA **de la production** : tableau plat, `attack` en paires.
    #[test]
    fn parses_production_capa_shape() {
        let e = build(
            None,
            env(json!({"success": true, "results": [
                {"attack": [["Execution", "T1129"]], "catalog": [], "name": "Link Function At Runtime"},
                {"attack": [["Execution", "T1129"]], "catalog": [["Debugger Detection", "B0001.019"]], "name": "Peb Access"}
            ]})),
            None,
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "capacités" && f.value == "2")
        );
        // T1129 apparaît deux fois : une seule sortie attendue.
        let atk = e.facts.iter().find(|f| f.key == "att&ck").unwrap();
        assert_eq!(atk.value, "T1129 (Execution)");
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "comportements" && f.value.contains("Debugger Detection"))
        );
    }

    /// Forme CAPA **de la doc** : objet `{capabilities: [{name, attack_id}]}`.
    /// Acceptée aussi, pour survivre à un alignement du service sur sa doc.
    #[test]
    fn parses_documented_capa_shape() {
        let e = build(
            None,
            env(json!({"success": true, "results": {
                "sha256": "x",
                "capabilities": [{"name": "persistence via registry run key", "attack_id": "T1060"}]
            }})),
            None,
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "capacités" && f.value == "1")
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "att&ck" && f.value == "T1060")
        );
    }

    /// Réponses **réelles** enregistrées (voir `fixtures/README.md`). C'est ce
    /// qui aurait signalé tout de suite que la doc décrit une forme que l'API
    /// ne renvoie pas — le cas qui m'a fait réécrire ce parseur.
    #[test]
    fn replays_recorded_responses() {
        let capa: Envelope =
            serde_json::from_str(include_str!("fixtures/traceix-capa.json")).unwrap();
        let av: Envelope = serde_json::from_str(include_str!("fixtures/traceix-av.json")).unwrap();
        let e = build(Some(av), Some(capa), None);
        assert!(e.error.is_none(), "les réponses réelles doivent parser");
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "att&ck" && f.value.contains("T1")),
            "au moins une technique ATT&CK doit être extraite"
        );
        assert!(e.facts.iter().any(|f| f.key == "antivirus"));
        // Échantillon du dataset public : non détecté, donc aucun signal.
        assert!(e.signals.is_empty());
    }

    /// Réponse réelle pour un hash absent du corpus.
    #[test]
    fn replays_recorded_unknown_hash() {
        let env: Envelope =
            serde_json::from_str(include_str!("fixtures/traceix-unknown.json")).unwrap();
        let e = build(None, Some(env), None);
        assert!(e.error.is_none(), "un hash inconnu n'est pas une panne");
        assert!(e.facts.iter().any(|f| f.value == "hash inconnu"));
    }

    /// L'endpoint YARA répond `data` au lieu de `results` : `post()` normalise,
    /// on vérifie ici que le nom de règle est bien extrait.
    #[test]
    fn extracts_yara_rule_name() {
        let e = build(
            None,
            None,
            env(
                json!({"success": true, "results": {"rule": "rule TraceixRuleGenerator_abc { condition: true }"}}),
            ),
        );
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "yara" && f.value == "TraceixRuleGenerator_abc")
        );
    }
}
