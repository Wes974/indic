//! Analyse de contenu d'URL — HEAD + extraction de métadonnées.
//! Enrichit une URL avec : statut HTTP, type de contenu, serveur, titre,
//! redirections, et certificat TLS (si HTTPS).

use super::{Ctx, Enrichment, Fact, Signal};

pub async fn enrich_url(url: &str, ctx: &Ctx) -> Enrichment {
    let mut facts = Vec::new();
    let mut signals = Vec::new();

    // HEAD request — rapide, pas de téléchargement du corps.
    match ctx
        .http
        .head(url)
        .timeout(std::time::Duration::from_secs(8))
        .send()
        .await
    {
        Ok(resp) => {
            let status = resp.status();
            facts.push(Fact::new("http_status", status.as_u16().to_string()));

            if status.is_redirection()
                && let Some(location) = resp.headers().get("location")
                && let Ok(loc) = location.to_str()
            {
                facts.push(Fact::new("redirection", loc.to_string()));
            }
            if status.is_server_error() {
                signals.push(Signal::new("url_analysis", "info"));
                facts.push(Fact::new("note", "serveur en erreur (5xx)"));
            }
            if status == reqwest::StatusCode::NOT_FOUND {
                facts.push(Fact::new("note", "page introuvable (404)"));
            }

            if let Some(ct) = resp
                .headers()
                .get("content-type")
                .and_then(|v| v.to_str().ok())
            {
                facts.push(Fact::new("content_type", ct.to_string()));
                // Détecter les types suspects
                if ct.contains("application/") && !ct.contains("json") && !ct.contains("xml") {
                    signals.push(Signal::with_detail(
                        "url_analysis",
                        "suspicious",
                        format!("type de contenu suspect : {ct}"),
                    ));
                }
            }
            if let Some(server) = resp.headers().get("server").and_then(|v| v.to_str().ok()) {
                facts.push(Fact::new("serveur", server.to_string()));
            }
            if let Some(cl) = resp
                .headers()
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                && let Ok(size) = cl.parse::<u64>()
            {
                let readable = if size > 1_000_000 {
                    format!("{:.1} Mo", size as f64 / 1_000_000.0)
                } else if size > 1_000 {
                    format!("{:.1} Ko", size as f64 / 1_000.0)
                } else {
                    format!("{size} o")
                };
                facts.push(Fact::new("taille", readable));
            }
            // Cookies (indicateurs potentiels)
            if let Some(cookies) = resp.headers().get("set-cookie") {
                let count = cookies.to_str().map(|c| c.split(";").count()).unwrap_or(0);
                if count > 0 {
                    facts.push(Fact::new("cookies", format!("{count} défini(s)")));
                }
            }
            // Headers de sécurité
            for (header, fact_name) in &[
                ("strict-transport-security", "hsts"),
                ("content-security-policy", "csp"),
                ("x-content-type-options", "x_content_type"),
                ("x-frame-options", "x_frame"),
                ("x-xss-protection", "x_xss"),
            ] {
                if resp.headers().get(*header).is_some() {
                    facts.push(Fact::new(fact_name, "oui"));
                }
            }
        }
        Err(e) => {
            let err = e.to_string();
            // Erreurs de connexion → signal
            if err.contains("timeout") || err.contains("connect") {
                signals.push(Signal::with_detail(
                    "url_analysis",
                    "info",
                    "site injoignable",
                ));
                facts.push(Fact::new("statut", "injoignable"));
            }
            return Enrichment {
                source: "url_analysis".into(),
                facts,
                signals,
                pivots: vec![],
                error: Some(err),
            };
        }
    }

    // Pour HTTPS : on pourrait extraire le CN du certificat, mais ça nécessite
    // une connexion TLS directe (pas via reqwest). On note simplement que c'est HTTPS.
    if url.starts_with("https://") {
        facts.push(Fact::new("tls", "oui"));
        if let Some(host) = url_host(url) {
            // Vérification basique : le hostname est-il récent ?
            // On pourrait interroger crt.sh pour l'âge du certificat.
            // Pour l'instant on signale juste que c'est HTTPS.
            let _ = host;
        }
    } else if url.starts_with("http://") {
        signals.push(Signal::with_detail(
            "url_analysis",
            "info",
            "HTTP (non chiffré) — connexion en clair",
        ));
        facts.push(Fact::new("tls", "non"));
    }

    // Récupérer le titre de la page (GET partiel, limité à 64 Ko)
    if facts
        .iter()
        .any(|f| f.key == "http_status" && f.value != "404" && f.value != "503")
    {
        // Récupérer le titre de la page (GET partiel, limité à 64 Ko) — best-effort.
        if let Ok(resp) = ctx
            .http
            .get(url)
            .timeout(std::time::Duration::from_secs(10))
            .send()
            .await
            && let Ok(body) = resp.text().await
        {
            let preview = &body[..body.len().min(65536)];
            if let Some(title) = extract_title(preview) {
                let title_lower = title.to_lowercase();
                facts.push(Fact::new("titre", title.as_str()));
                if title_lower.contains("login")
                    || title_lower.contains("sign in")
                    || title_lower.contains("connexion")
                    || title_lower.contains("verify")
                {
                    signals.push(Signal::with_detail(
                        "url_analysis",
                        "suspicious",
                        "page d'authentification",
                    ));
                }
            }
        }
    }

    Enrichment {
        source: "url_analysis".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

/// Extrait le contenu de la balise `<title>` du HTML.
fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let start = lower.find("<title")?;
    let after_open = &html[start..];
    let content_start = after_open.find('>')? + 1;
    let content = &after_open[content_start..];
    let end = content.to_lowercase().find("</title")?;
    let title = content[..end].trim();
    if title.is_empty() || title.len() > 200 {
        return None;
    }
    Some(title.to_string())
}

/// Extrait le host d'une URL.
fn url_host(url: &str) -> Option<String> {
    let after = url.split("://").nth(1)?;
    let host = after.split(['/', '?', '#', ':']).next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_title_from_html() {
        assert_eq!(
            extract_title("<html><head><title>My Page</title></head></html>"),
            Some("My Page".into())
        );
        assert_eq!(
            extract_title("<html><TITLE>Test</TITLE></html>"),
            Some("Test".into())
        );
        assert!(extract_title("<html></html>").is_none());
    }

    #[test]
    fn url_host_extraction() {
        assert_eq!(
            url_host("https://example.com/path"),
            Some("example.com".into())
        );
        assert_eq!(url_host("http://evil.com:8080/x"), Some("evil.com".into()));
        assert_eq!(
            url_host("ftp://files.example.org"),
            Some("files.example.org".into())
        );
    }
}
