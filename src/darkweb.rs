//! Module C — dark web / Tor (framework).
//!
//! Garde-fou ROADMAP : connecteurs read-only DÉSACTIVÉS par défaut, aucun crawl
//! autonome. Les connecteurs ne s'activent que si `INDIC_DARKWEB_ENABLED=1`.
//! Sources : Ahmia.fi (moteur de recherche .onion), OnionScan (métadonnées).
//!
//! ATTENTION : ce module est conçu pour la recherche défensive (CTI/OSINT)
//! uniquement. L'utilisation des connecteurs est soumise aux conditions
//! d'utilisation des sources et aux lois locales.

use crate::enrich::Ctx;
use crate::veille::{Alert, State};

/// Active le module dark web ? Désactivé par défaut (garde-fou).
fn darkweb_enabled() -> bool {
    std::env::var("INDIC_DARKWEB_ENABLED").is_ok_and(|v| v == "1" || v == "true")
}

/// Point d'entrée — ne fait rien si le module n'est pas activé.
pub async fn run(ctx: &Ctx, state: &mut State) -> Vec<Alert> {
    if !darkweb_enabled() {
        return vec![];
    }
    let mut alerts = Vec::new();
    alerts.extend(module_ahmia(ctx, state).await);
    alerts.extend(module_onion_search(ctx, state).await);
    alerts
}

/// Connecteur Ahmia.fi — moteur de recherche .onion (read-only).
/// Cherche les mots-clés de `INDIC_DARKWEB_KEYWORDS` dans l'index Ahmia.
async fn module_ahmia(ctx: &Ctx, state: &mut State) -> Vec<Alert> {
    let keywords: Vec<String> = std::env::var("INDIC_DARKWEB_KEYWORDS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if keywords.is_empty() {
        return vec![];
    }
    let mut alerts = Vec::new();
    for kw in &keywords {
        let url = format!(
            "https://ahmia.fi/search/?q={}",
            urlencoding(kw)
        );
        match ctx
            .http
            .get(&url)
            .header("User-Agent", "indic/0.1 (CTI research)")
            .send()
            .await
        {
            Ok(resp) => {
                if let Ok(body) = resp.text().await {
                    // Extraction basique des résultats .onion de la page HTML
                    let onions = extract_onions(&body, kw);
                    let module = format!("darkweb:ahmia:{kw}");
                    for onion in state.fresh(&module, onions) {
                        alerts.push(Alert {
                            title: format!("Tor — nouveau .onion pour « {kw} »"),
                            message: format!("Onion : {onion}"),
                            priority: 0,
                            url: Some(format!("http://{onion}")),
                        });
                    }
                }
            }
            Err(e) => {
                tracing::warn!("darkweb: ahmia search failed for « {kw} »: {e}");
            }
        }
    }
    alerts
}

/// Extrait les adresses .onion du HTML d'Ahmia. Cherche les liens contenant
/// `.onion` dans le HTML rendu.
fn extract_onions(html: &str, _keyword: &str) -> Vec<String> {
    let mut out = Vec::new();
    // Pattern : chaîne entre `href="http://` et `"` contenant `.onion`
    for (i, _) in html.match_indices("href=\"http://") {
        let rest = &html[i + 13..]; // après `href="http://`
        if let Some(end) = rest.find('"') {
            let link = &rest[..end];
            if link.contains(".onion") && link.len() < 100 {
                out.push(link.to_string());
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

/// Recherche de surface Onion (pattern keyword → hidden services via patterns).
/// Utilise l'API Ahmia stateless pour chercher des services .onion sans crawler.
async fn module_onion_search(_ctx: &Ctx, _state: &mut State) -> Vec<Alert> {
    let keywords: Vec<String> = std::env::var("INDIC_DARKWEB_KEYWORDS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if keywords.is_empty() {
        return vec![];
    }
    // Sans Tor, on ne peut pas accéder aux .onions eux-mêmes — on se limite
    // aux métadonnées publiques (Ahmia, dark.fail, etc.)
    tracing::info!(
        "darkweb: {} mot(s)-clé(s) surveillé(s) via Ahmia (sans accès Tor direct)",
        keywords.len()
    );
    vec![] // métadonnées déjà couvertes par module_ahmia
}

/// Encode une chaîne pour URL (échappe les caractères spéciaux).
fn urlencoding(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' || c == '~' {
                c.to_string()
            } else {
                format!("%{:02X}", c as u8)
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_onions_from_html() {
        let html = r#"<a href="http://abcdefghijklmnop.onion">link1</a><a href="http://xyz.onion">link2</a>"#;
        let onions = extract_onions(html, "test");
        assert_eq!(onions.len(), 2);
        assert!(onions.contains(&"abcdefghijklmnop.onion".to_string()));
        assert!(onions.contains(&"xyz.onion".to_string()));
    }

    #[test]
    fn urlencoding_basic() {
        assert_eq!(urlencoding("hello world"), "hello%20world");
        assert_eq!(urlencoding("test-key_word"), "test-key_word");
    }
}
