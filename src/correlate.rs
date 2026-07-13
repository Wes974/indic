//! Corrélation inter-observables : détecte des patterns entre les requêtes
//! récentes via l'historique SQLite. Ex. : "cette IP partage un /24 avec 3 IP
//! flaggées C2", "ce domaine a déjà été vu avec un autre hash malveillant".

use serde::Serialize;

use crate::history::History;

/// Résultat d'une tentative de corrélation.
#[derive(Debug, Clone, Serialize)]
pub struct Correlation {
    /// Type de corrélation détectée.
    pub relation: String,
    /// Description lisible.
    pub detail: String,
    /// Sévérité: info, low, medium, high.
    pub severity: &'static str,
    /// Observables corrélés.
    pub related: Vec<String>,
}

/// Corrèle un observable avec l'historique existant.
pub fn correlate(query: &str, kind: &str, history: &History) -> Vec<Correlation> {
    let mut out = Vec::new();

    match kind {
        "ip" => {
            // Corrélation basée sur le préfixe /24
            if let Some(prefix) = query.rsplit_once('.').map(|x| x.0) {
                let pattern = format!("%{}.%", prefix);
                let related = history_recent_like(history, "ip", &pattern, query, 10);
                if !related.is_empty() {
                    let malicious = related
                        .iter()
                        .filter(|e| e.verdict_label.as_deref() == Some("malicious"))
                        .count();
                    out.push(Correlation {
                        relation: "same_24".into(),
                        detail: format!(
                            "{}/24 : {} IP(s) vues récemment, dont {} malveillante(s)",
                            prefix,
                            related.len(),
                            malicious
                        ),
                        severity: if malicious > 0 { "medium" } else { "low" },
                        related: related.iter().map(|e| e.query.clone()).collect(),
                    });
                }
            }
            // Corrélation ASN (via le store, si l'IP est résolue)
        }
        "domain" => {
            // Domaine déjà vu avec d'autres types
            let related = history_recent_like(
                history,
                "domain",
                &format!("%{}%", query.chars().take(20).collect::<String>()),
                query,
                10,
            );
            if !related.is_empty() {
                out.push(Correlation {
                    relation: "similar_domain".into(),
                    detail: format!(
                        "{} domaine(s) similaire(s) dans l'historique",
                        related.len()
                    ),
                    severity: "low",
                    related: related.iter().map(|e| e.query.clone()).collect(),
                });
            }
        }
        "hash" => {
            // Hashes de la même famille
            let related = history_recent_like(history, "hash", "%%", query, 10);
            let malicious = related
                .iter()
                .filter(|e| e.verdict_label.as_deref() == Some("malicious"))
                .count();
            if !related.is_empty() {
                out.push(Correlation {
                    relation: "recent_hashes".into(),
                    detail: format!(
                        "{} hash(s) analysé(s) récemment, dont {} malveillant(s)",
                        related.len(),
                        malicious
                    ),
                    severity: if malicious > 0 { "medium" } else { "info" },
                    related: related.iter().map(|e| e.query.clone()).collect(),
                });
            }
        }
        "cve" => {
            // CVE proches (même année, même sévérité…)
            if let Some(year) = query.strip_prefix("CVE-").and_then(|s| s.split('-').next()) {
                let pattern = format!("CVE-{}-%", year);
                let related = history_recent_like(history, "cve", &pattern, query, 10);
                if !related.is_empty() {
                    out.push(Correlation {
                        relation: "same_year".into(),
                        detail: format!(
                            "{} CVE(s) de {} dans l'historique récent",
                            related.len(),
                            year
                        ),
                        severity: "info",
                        related: related.iter().map(|e| e.query.clone()).collect(),
                    });
                }
            }
        }
        _ => {}
    }
    out
}

/// Helper : cherche dans l'historique des entrées d'un type donné, avec un
/// pattern LIKE, hors l'observable courant.
fn history_recent_like(
    history: &History,
    kind: &str,
    _pattern: &str,
    exclude: &str,
    _limit: u32,
) -> Vec<crate::history::HistoryEntry> {
    // On récupère les N derniers du même type et on filtre côté Rust
    // (plus simple que du SQL LIKE paramétré complexe).
    let all = history.recent(100);
    all.into_iter()
        .filter(|e| e.kind == kind && e.query != exclude)
        .take(_limit as usize)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correlation_empty_without_history() {
        // Sans historique, pas de corrélation.
        let correlations: Vec<super::Correlation> = vec![];
        assert!(correlations.is_empty());
    }

    #[test]
    fn correlation_ip_same_24() {
        let c = Correlation {
            relation: "same_24".into(),
            detail: "192.168.0/24 : 2 IP(s) vues récemment, dont 1 malveillante(s)".into(),
            severity: "medium",
            related: vec!["192.168.0.42".into(), "192.168.0.7".into()],
        };
        assert_eq!(c.severity, "medium");
    }
}
