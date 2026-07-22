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
            // Même /24 : on compare le préfixe des trois premiers octets.
            if let Some(prefix) = query.rsplit_once('.').map(|x| x.0) {
                let needle = format!("{prefix}.");
                let related =
                    history_matching(history, "ip", query, 10, |q| q.starts_with(&needle));
                if !related.is_empty() {
                    let malicious = count_malicious(&related);
                    out.push(Correlation {
                        relation: "same_24".into(),
                        detail: format!(
                            "{}/24 : {} IP(s) vues récemment, dont {} malveillante(s)",
                            prefix,
                            related.len(),
                            malicious
                        ),
                        severity: if malicious > 0 { "medium" } else { "low" },
                        related: queries(&related),
                    });
                }
            }
        }
        "domain" => {
            // Même domaine enregistrable : `mail.exemple.fr` et `vpn.exemple.fr`
            // sont liés, `exemple.fr` et `exemple-piege.fr` ne le sont pas.
            if let Some(apex) = crate::observable::registrable_domain(query) {
                let related = history_matching(history, "domain", query, 10, |q| {
                    crate::observable::registrable_domain(q).as_deref() == Some(apex.as_str())
                });
                if !related.is_empty() {
                    let malicious = count_malicious(&related);
                    out.push(Correlation {
                        relation: "same_apex".into(),
                        detail: format!(
                            "{} : {} sous-domaine(s) vu(s) récemment, dont {} malveillant(s)",
                            apex,
                            related.len(),
                            malicious
                        ),
                        severity: if malicious > 0 { "medium" } else { "low" },
                        related: queries(&related),
                    });
                }
            }
        }
        "hash" => {
            // Aucun lien prétendu ici : juste le contexte des hashs récents.
            let related = history_matching(history, "hash", query, 10, |_| true);
            if !related.is_empty() {
                let malicious = count_malicious(&related);
                out.push(Correlation {
                    relation: "recent_hashes".into(),
                    detail: format!(
                        "{} hash(s) analysé(s) récemment, dont {} malveillant(s)",
                        related.len(),
                        malicious
                    ),
                    severity: if malicious > 0 { "medium" } else { "info" },
                    related: queries(&related),
                });
            }
        }
        "cve" => {
            if let Some(year) = query.strip_prefix("CVE-").and_then(|s| s.split('-').next()) {
                let needle = format!("CVE-{year}-");
                let related =
                    history_matching(history, "cve", query, 10, |q| q.starts_with(&needle));
                if !related.is_empty() {
                    out.push(Correlation {
                        relation: "same_year".into(),
                        detail: format!(
                            "{} CVE(s) de {} dans l'historique récent",
                            related.len(),
                            year
                        ),
                        severity: "info",
                        related: queries(&related),
                    });
                }
            }
        }
        _ => {}
    }
    out
}

fn count_malicious(entries: &[crate::history::HistoryEntry]) -> usize {
    entries
        .iter()
        .filter(|e| e.verdict_label.as_deref() == Some("malicious"))
        .count()
}

fn queries(entries: &[crate::history::HistoryEntry]) -> Vec<String> {
    entries.iter().map(|e| e.query.clone()).collect()
}

/// Entrées de l'historique du type demandé qui satisfont `matches`, hors
/// l'observable courant, **dédupliquées** par valeur.
///
/// Le prédicat n'est pas décoratif : la version précédente recevait un motif
/// `LIKE` et **ne s'en servait pas** (paramètre nommé `_pattern`). Résultat, un
/// lookup de `8.8.8.8` affirmait que `1.1.1.1` et `185.220.101.1` étaient dans
/// son /24, et la même IP revenue trois fois dans l'historique était comptée
/// trois fois. Un outil CTI qui invente des liens est pire qu'un outil qui n'en
/// montre aucun.
fn history_matching(
    history: &History,
    kind: &str,
    exclude: &str,
    limit: usize,
    matches: impl Fn(&str) -> bool,
) -> Vec<crate::history::HistoryEntry> {
    let mut seen = std::collections::HashSet::new();
    history
        .recent(200)
        .into_iter()
        .filter(|e| {
            e.kind == kind
                && e.query != exclude
                && matches(&e.query)
                && seen.insert(e.query.clone())
        })
        .take(limit)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::history::History;

    /// Historique jetable, alimenté puis interrogé.
    ///
    /// Le nom du fichier vient d'un compteur atomique, pas du nombre d'entrées :
    /// les tests tournent en parallèle dans le même processus, et deux jeux de
    /// même taille se partageaient la même base — l'un voyait les données de
    /// l'autre et échouait, mais seulement en suite complète.
    fn hist(entries: &[(&str, &str, Option<&str>)]) -> History {
        static N: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(0);
        let id = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("indic-corr-{}-{id}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let h = History::open(&path).expect("sqlite");
        for (q, kind, verdict) in entries {
            h.record(q, kind, *verdict, None, 1, 0);
        }
        h
    }

    /// **Régression.** L'ancienne implémentation ignorait le motif : un lookup
    /// de 8.8.8.8 annonçait 1.1.1.1 et 185.220.101.1 comme étant dans son /24.
    #[test]
    fn same_24_only_matches_the_actual_prefix() {
        let h = hist(&[
            ("8.8.4.4", "ip", None),
            ("1.1.1.1", "ip", None),
            ("185.220.101.1", "ip", Some("malicious")),
            ("8.8.8.1", "ip", Some("malicious")),
        ]);
        let c = correlate("8.8.8.8", "ip", &h);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].relation, "same_24");
        assert_eq!(
            c[0].related,
            vec!["8.8.8.1"],
            "seule une IP du même /24 doit être corrélée"
        );
        assert!(c[0].detail.contains("dont 1 malveillante"));
    }

    /// **Régression.** Une même IP revue plusieurs fois était comptée autant de
    /// fois — « 10 IP(s) vues » pour trois valeurs distinctes.
    #[test]
    fn repeated_lookups_are_counted_once() {
        let h = hist(&[
            ("8.8.8.1", "ip", None),
            ("8.8.8.1", "ip", None),
            ("8.8.8.1", "ip", None),
            ("8.8.8.2", "ip", None),
        ]);
        let c = correlate("8.8.8.8", "ip", &h);
        assert_eq!(c[0].related.len(), 2, "doublons attendus dédupliqués");
    }

    /// Les sous-domaines d'un même domaine enregistrable sont liés ; un domaine
    /// qui contient seulement la même chaîne ne l'est pas.
    #[test]
    fn domains_correlate_on_registrable_domain() {
        let h = hist(&[
            ("vpn.exemple.fr", "domain", None),
            ("exemple-piege.fr", "domain", Some("malicious")),
            ("autre.com", "domain", None),
        ]);
        let c = correlate("mail.exemple.fr", "domain", &h);
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].relation, "same_apex");
        assert_eq!(c[0].related, vec!["vpn.exemple.fr"]);
    }

    #[test]
    fn cve_correlates_on_year_only() {
        let h = hist(&[
            ("CVE-2021-4034", "cve", None),
            ("CVE-2014-0160", "cve", None),
        ]);
        let c = correlate("CVE-2021-44228", "cve", &h);
        assert_eq!(c[0].related, vec!["CVE-2021-4034"]);
    }

    #[test]
    fn no_correlation_without_matching_history() {
        let h = hist(&[("1.1.1.1", "ip", None)]);
        assert!(correlate("8.8.8.8", "ip", &h).is_empty());
    }
}
