//! Enricher username OSINT (façon WhatsMyName) : teste la présence d'un pseudo
//! sur un sous-ensemble BORNÉ de sites, en concurrent, timeout court. Best-effort
//! — certains sites bloquent les requêtes automatisées (miss silencieux, pas d'erreur).

use std::time::Duration;

use reqwest::StatusCode;

use crate::enrich::{Ctx, Enrichment, Fact};
use crate::model::Signal;

/// Méthode de détection d'existence d'un compte.
#[derive(Clone, Copy)]
enum Check {
    /// HTTP 200 = existe.
    Status,
    /// Chaîne présente dans le corps = existe.
    Found(&'static str),
}

/// (nom, gabarit d'URL `{}`=pseudo, méthode). Sous-ensemble à détection fiable.
const SITES: &[(&str, &str, Check)] = &[
    ("GitHub", "https://github.com/{}", Check::Status),
    ("GitLab", "https://gitlab.com/{}", Check::Status),
    ("Keybase", "https://keybase.io/{}", Check::Status),
    ("PyPI", "https://pypi.org/user/{}/", Check::Status),
    ("Replit", "https://replit.com/@{}", Check::Status),
    ("dev.to", "https://dev.to/{}", Check::Status),
    ("Codeberg", "https://codeberg.org/{}", Check::Status),
    (
        "Reddit",
        "https://www.reddit.com/user/{}/about.json",
        Check::Status,
    ),
    (
        "Chess.com",
        "https://api.chess.com/pub/player/{}",
        Check::Status,
    ),
    (
        "Docker Hub",
        "https://hub.docker.com/v2/users/{}/",
        Check::Status,
    ),
    (
        "Telegram",
        "https://t.me/{}",
        Check::Found("tgme_page_title"),
    ),
    (
        "HackerNews",
        "https://hacker-news.firebaseio.com/v0/user/{}.json",
        Check::Found("\"id\""),
    ),
];

pub async fn enrich_username(username: &str, ctx: &Ctx) -> Enrichment {
    let mut set = tokio::task::JoinSet::new();
    for (name, tmpl, check) in SITES {
        let http = ctx.http.clone();
        let url = tmpl.replace("{}", username);
        let name = *name;
        let check = *check;
        set.spawn(async move { (name, probe(&http, &url, check).await) });
    }
    let mut found: Vec<&'static str> = Vec::new();
    while let Some(res) = set.join_next().await {
        if let Ok((name, true)) = res {
            found.push(name);
        }
    }
    found.sort_unstable();
    build(found)
}

/// Teste un site (timeout court ; toute erreur = non trouvé). Best-effort.
async fn probe(http: &reqwest::Client, url: &str, check: Check) -> bool {
    let Ok(resp) = http.get(url).timeout(Duration::from_secs(6)).send().await else {
        return false;
    };
    match check {
        Check::Status => resp.status() == StatusCode::OK,
        Check::Found(needle) => resp
            .text()
            .await
            .map(|b| b.contains(needle))
            .unwrap_or(false),
    }
}

fn build(found: Vec<&'static str>) -> Enrichment {
    let mut facts = vec![Fact::new("sites_testés", SITES.len().to_string())];
    if found.is_empty() {
        facts.push(Fact::new("comptes", "aucun sur le sous-ensemble testé"));
        return Enrichment {
            source: "username".into(),
            facts,
            signals: vec![],
            pivots: vec![],
            error: None,
        };
    }
    let n = found.len();
    facts.push(Fact::new("comptes_trouvés", n.to_string()));
    facts.push(Fact::new("sur", found.join(", ")));
    // Empreinte OSINT = signal informatif (ni bon ni mauvais).
    let signals = vec![Signal::with_detail(
        "whatsmyname",
        "osint",
        format!("{n} compte(s) : {}", found.join(", ")),
    )];
    Enrichment {
        source: "username".into(),
        facts,
        signals,
        pivots: vec![],
        error: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_none() {
        let e = build(vec![]);
        assert!(e.signals.is_empty());
        assert!(e.facts.iter().any(|f| f.value.contains("aucun")));
    }

    #[test]
    fn build_found() {
        let e = build(vec!["GitHub", "Reddit"]);
        assert!(
            e.facts
                .iter()
                .any(|f| f.key == "comptes_trouvés" && f.value == "2")
        );
        assert_eq!(e.signals.len(), 1);
        assert_eq!(e.signals[0].category, "osint");
    }
}
