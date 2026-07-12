//! MITRE ATT&CK : mapping CWE → technique pour les CVE enrichies.
//! Feed offline basé sur `cwe2attack.csv` (un CWE par ligne, avec les techniques
//! associées). Le fichier est généré depuis le dataset officiel MITRE.

use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// CWE-ID → liste de techniques ATT&CK (ex. "CWE-79" → ["T1059.007", "T1190"])
pub type AttackMap = HashMap<String, Vec<String>>;

/// Charge le mapping CWE→ATT&CK depuis un CSV `cwe_id,attack_id` (un par ligne).
/// Format: `CWE-79,T1059.007`
pub fn load_attack_map(path: &Path) -> AttackMap {
    let Ok(content) = fs::read_to_string(path) else {
        tracing::warn!("fichier cwe2attack.csv absent, mapping ATT&CK non chargé");
        return HashMap::new();
    };
    let mut map: AttackMap = HashMap::new();
    for line in content.lines().skip(1) {
        // skip header
        let parts: Vec<&str> = line.trim().split(',').collect();
        if parts.len() >= 2 && !parts[0].is_empty() && !parts[1].is_empty() {
            map.entry(parts[0].to_string())
                .or_default()
                .push(parts[1].to_string());
        }
    }
    tracing::info!(count = map.len(), "mapping CWE→ATT&CK chargé");
    map
}

/// Construit les signaux ATT&CK depuis les CWEs (un enricher CVE les expose en facts).
/// `cwes` : liste de CWE-IDs (ex. ["CWE-79", "CWE-89"]).
pub fn attack_signals(cwes: &[String], map: &AttackMap) -> Vec<crate::model::Signal> {
    let mut signals = Vec::new();
    for cwe in cwes {
        if let Some(techniques) = map.get(cwe) {
            for t in techniques {
                signals.push(crate::model::Signal::with_detail(
                    "mitre_attack",
                    "exploit",
                    format!("{cwe}→{t}"),
                ));
            }
        }
    }
    signals.dedup_by(|a, b| a.detail == b.detail);
    signals
}
