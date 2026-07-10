//! Veille proactive : watchers planifiés qui détectent du **nouveau** et
//! poussent une alerte (Pushover). Réutilise le client HTTP + les clés du `Ctx`.
//!
//! Modules :
//! - **KEV** : CISA KEV (nouvelles CVE activement exploitées).
//! - **pastes** : mots-clés surveillés dans les leaks/pastes (IntelX).
//! - **apple** : nouvelles releases de sécurité macOS/iOS (scrape support.apple.com).
//!
//! Anti-spam : un état persistant (`data/veille_state.json`) mémorise ce qui a
//! déjà été vu ; au **premier run** d'un module on **amorce en silence** (on ne
//! réalerte pas sur tout l'historique), ensuite on n'alerte que sur le neuf.

use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::enrich::Ctx;

/// Une alerte à pousser vers le sink.
pub struct Alert {
    pub title: String,
    pub message: String,
    /// Priorité Pushover (-2 silencieux … 2 urgent). 0 par défaut.
    pub priority: i8,
    pub url: Option<String>,
}

/// État persistant de la veille : par module, les identifiants déjà signalés.
#[derive(Default, Serialize, Deserialize)]
struct State {
    /// module → identifiants déjà vus (dédup des alertes).
    seen: HashMap<String, BTreeSet<String>>,
    /// modules déjà amorcés (au 1er run on n'alerte pas, on remplit `seen`).
    #[serde(default)]
    seeded: BTreeSet<String>,
}

impl State {
    fn load(path: &Path) -> State {
        std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default()
    }

    fn save(&self, path: &Path) {
        match serde_json::to_string(self) {
            Ok(json) => {
                if let Err(e) = std::fs::write(path, json) {
                    tracing::error!("veille: écriture de l'état échouée : {e}");
                }
            }
            Err(e) => tracing::error!("veille: sérialisation de l'état échouée : {e}"),
        }
    }

    /// Renvoie les identifiants **neufs** (jamais vus) et les marque vus. Au
    /// premier passage d'un module, amorce en silence (renvoie vide).
    fn fresh(&mut self, module: &str, ids: impl IntoIterator<Item = String>) -> Vec<String> {
        let first_run = !self.seeded.contains(module);
        let seen = self.seen.entry(module.to_string()).or_default();
        let mut out = Vec::new();
        for id in ids {
            let is_new = seen.insert(id.clone());
            if is_new && !first_run {
                out.push(id);
            }
        }
        self.seeded.insert(module.to_string());
        out
    }
}

fn state_path(data_dir: &Path) -> PathBuf {
    data_dir.join("veille_state.json")
}

/// Lance un cycle de veille : chaque module actif, alertes envoyées, état sauvé.
pub async fn run_once(ctx: &Ctx, data_dir: &Path) {
    let path = state_path(data_dir);
    let mut state = State::load(&path);

    let mut alerts = module_kev(ctx, &mut state).await;
    alerts.extend(module_pastes(ctx, &mut state).await);
    alerts.extend(module_apple(ctx, &mut state).await);

    let n = alerts.len();
    for alert in &alerts {
        notify(ctx, alert).await;
    }
    state.save(&path);
    tracing::info!("veille: cycle terminé, {n} alerte(s) émise(s)");
}

/// Boucle de fond : un cycle de veille toutes les `INDIC_VEILLE_INTERVAL_HOURS`
/// (défaut 6 h). Le premier cycle amorce l'état sans alerter.
pub async fn run_loop(ctx: Arc<Ctx>, data_dir: PathBuf) {
    let hours: u64 = std::env::var("INDIC_VEILLE_INTERVAL_HOURS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&h| h > 0)
        .unwrap_or(6);
    tracing::info!("veille: activée, cycle toutes les {hours} h");
    let mut ticker = tokio::time::interval(Duration::from_secs(hours * 3600));
    loop {
        ticker.tick().await;
        run_once(&ctx, &data_dir).await;
    }
}

/// Envoie une alerte de test (vérifie la config Pushover de bout en bout).
pub async fn send_test(ctx: &Ctx) {
    notify(
        ctx,
        &Alert {
            title: "Veille indic".to_string(),
            message: "Test — la veille est bien configurée ✅".to_string(),
            priority: 0,
            url: None,
        },
    )
    .await;
}

/// Sink Pushover. Sans `PUSHOVER_TOKEN`+`PUSHOVER_USER`, l'alerte est loguée
/// mais pas envoyée (dégradation gracieuse).
async fn notify(ctx: &Ctx, alert: &Alert) {
    let (Some(token), Some(user)) = (ctx.key("PUSHOVER_TOKEN"), ctx.key("PUSHOVER_USER")) else {
        tracing::warn!(
            "veille: alerte non envoyée (Pushover non configuré) : {}",
            alert.title
        );
        return;
    };
    let priority = alert.priority.to_string();
    let mut form = vec![
        ("token", token),
        ("user", user),
        ("title", alert.title.as_str()),
        ("message", alert.message.as_str()),
        ("priority", priority.as_str()),
    ];
    if let Some(u) = &alert.url {
        form.push(("url", u.as_str()));
    }
    match ctx
        .http
        .post("https://api.pushover.net/1/messages.json")
        .form(&form)
        .send()
        .await
    {
        Ok(r) if r.status().is_success() => {
            tracing::info!("veille: alerte Pushover envoyée : {}", alert.title)
        }
        Ok(r) => tracing::error!(
            "veille: Pushover a répondu {} pour : {}",
            r.status(),
            alert.title
        ),
        Err(e) => tracing::error!("veille: envoi Pushover échoué : {e}"),
    }
}

/// URL du flux CISA KEV (surchargeable par `INDIC_FEED_KEV`).
fn kev_url() -> String {
    std::env::var("INDIC_FEED_KEV").unwrap_or_else(|_| {
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            .to_string()
    })
}

/// Module B — CISA KEV : alerte sur chaque nouvelle CVE activement exploitée.
async fn module_kev(ctx: &Ctx, state: &mut State) -> Vec<Alert> {
    let body = match ctx.http.get(kev_url()).send().await {
        Ok(r) => match r.error_for_status() {
            Ok(r) => match r.json::<serde_json::Value>().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::error!("veille kev: JSON invalide : {e}");
                    return vec![];
                }
            },
            Err(e) => {
                tracing::error!("veille kev: statut HTTP : {e}");
                return vec![];
            }
        },
        Err(e) => {
            tracing::error!("veille kev: fetch échoué : {e}");
            return vec![];
        }
    };

    let Some(vulns) = body.get("vulnerabilities").and_then(|v| v.as_array()) else {
        tracing::error!("veille kev: champ `vulnerabilities` absent");
        return vec![];
    };

    // cveID → entrée, pour retrouver les détails des IDs neufs.
    let mut by_id: HashMap<String, &serde_json::Value> = HashMap::new();
    for v in vulns {
        if let Some(id) = v.get("cveID").and_then(|x| x.as_str()) {
            by_id.insert(id.to_string(), v);
        }
    }

    let fresh = state.fresh("kev", by_id.keys().cloned());
    if fresh.is_empty() {
        return vec![];
    }
    let s = |v: &serde_json::Value, k: &str| {
        v.get(k).and_then(|x| x.as_str()).unwrap_or("").to_string()
    };
    fresh
        .into_iter()
        .filter_map(|id| {
            let v = by_id.get(&id)?;
            let name = s(v, "vulnerabilityName");
            let vendor = s(v, "vendorProject");
            let product = s(v, "product");
            let ransomware = s(v, "knownRansomwareCampaignUse").eq_ignore_ascii_case("known");
            let due = s(v, "dueDate");
            let mut message = format!("{vendor} {product} — {name}");
            if ransomware {
                message.push_str("\n⚠️ Utilisée dans des campagnes ransomware");
            }
            if !due.is_empty() {
                message.push_str(&format!("\nÉchéance remédiation : {due}"));
            }
            Some(Alert {
                title: format!("CVE exploitée (KEV) : {id}"),
                message,
                priority: if ransomware { 1 } else { 0 },
                url: Some(format!("https://nvd.nist.gov/vuln/detail/{id}")),
            })
        })
        .collect()
}

/// Mots-clés surveillés dans les pastes/leaks (`INDIC_VEILLE_KEYWORDS`, séparés
/// par des virgules). Vide → module pastes inactif.
fn watch_keywords() -> Vec<String> {
    std::env::var("INDIC_VEILLE_KEYWORDS")
        .unwrap_or_default()
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Module A (pastes ciblés) — pour chaque mot-clé surveillé, cherche dans les
/// leaks/pastes/darknet (IntelX) et alerte sur les résultats **neufs**. Chaque
/// mot-clé a son propre amorçage (ajouter un mot-clé n'inonde pas d'historique).
async fn module_pastes(ctx: &Ctx, state: &mut State) -> Vec<Alert> {
    let keywords = watch_keywords();
    if keywords.is_empty() || ctx.key("INTELX_API_KEY").is_none() {
        return vec![];
    }
    let mut alerts = Vec::new();
    for kw in keywords {
        let records = match crate::enrich::intelx::search_terms(ctx, &kw).await {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("veille pastes: recherche « {kw} » échouée : {e:#}");
                continue;
            }
        };
        // Clé de dédup = systemid (GUID) ; repli sur le nom si absent.
        let mut by_id: HashMap<String, &crate::enrich::intelx::Record> = HashMap::new();
        for r in &records {
            let id = if r.systemid.is_empty() {
                r.name.clone()
            } else {
                r.systemid.clone()
            };
            by_id.insert(id, r);
        }
        let module = format!("pastes:{kw}");
        for id in state.fresh(&module, by_id.keys().cloned()) {
            if let Some(r) = by_id.get(&id) {
                alerts.push(Alert {
                    title: format!("Paste/leak — « {kw} »"),
                    message: format!("{} ({})", r.name, r.bucketh),
                    priority: 0,
                    url: (!r.systemid.is_empty())
                        .then(|| format!("https://intelx.io/?did={}", r.systemid)),
                });
            }
        }
    }
    alerts
}

/// URL de la liste officielle des releases de sécurité Apple (surchargeable).
fn apple_sec_url() -> String {
    std::env::var("INDIC_FEED_APPLE_SEC")
        .unwrap_or_else(|_| "https://support.apple.com/en-us/100100".to_string())
}

/// Module — advisories Apple : alerte sur chaque nouvelle release de sécurité
/// macOS/iOS/… (scrape de la page officielle, diff par id d'advisory).
async fn module_apple(ctx: &Ctx, state: &mut State) -> Vec<Alert> {
    let html = match ctx.http.get(apple_sec_url()).send().await {
        Ok(r) => match r.error_for_status() {
            Ok(r) => match r.text().await {
                Ok(t) => t,
                Err(e) => {
                    tracing::error!("veille apple: corps illisible : {e}");
                    return vec![];
                }
            },
            Err(e) => {
                tracing::error!("veille apple: statut HTTP : {e}");
                return vec![];
            }
        },
        Err(e) => {
            tracing::error!("veille apple: fetch échoué : {e}");
            return vec![];
        }
    };
    let releases = parse_apple_releases(&html);
    if releases.is_empty() {
        tracing::warn!("veille apple: 0 release parsée (structure de la page changée ?)");
        return vec![];
    }
    let by_id: HashMap<String, String> = releases.into_iter().collect();
    state
        .fresh("apple_sec", by_id.keys().cloned())
        .into_iter()
        .filter_map(|id| {
            let name = by_id.get(&id)?;
            Some(Alert {
                title: format!("Release sécu Apple : {name}"),
                message: format!("Nouvel avis de sécurité Apple.\n{name}"),
                priority: 0,
                url: Some(format!("https://support.apple.com/en-us/{id}")),
            })
        })
        .collect()
}

/// Extrait les (id_advisory, nom) des liens `…/en-us/NNNNNN` dont le texte
/// d'ancre contient un chiffre (= vraie release avec version ; écarte les liens
/// d'aide « update the software on… », « Get help… » qui n'ont pas de version).
fn parse_apple_releases(html: &str) -> Vec<(String, String)> {
    const NEEDLE: &str = "en-us/";
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    for (i, _) in html.match_indices(NEEDLE) {
        let rest = &html[i + NEEDLE.len()..];
        // NNNNNN suivi d'un guillemet (fin du href).
        if rest.len() < 7 || rest.as_bytes()[6] != b'"' {
            continue;
        }
        let id = &rest[..6];
        if !id.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        // Texte d'ancre : premier `>` (fin de balise <a>) puis jusqu'au `<`.
        let after = &rest[6..];
        let Some(gt) = after.find('>') else { continue };
        let text = &after[gt + 1..];
        let Some(lt) = text.find('<') else { continue };
        let name = text[..lt].trim();
        if name.is_empty() || name.len() > 80 || !name.bytes().any(|b| b.is_ascii_digit()) {
            continue;
        }
        if seen.insert(id.to_string()) {
            out.push((id.to_string(), name.to_string()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_apple_garde_les_releases() {
        let html = concat!(
            r#"<a href="https://support.apple.com/en-us/108382" class="x">update the software on your Mac</a>"#,
            r#"<a href="https://support.apple.com/en-us/127595" data-a="1">macOS Tahoe 26.5.2</a>"#,
            r#"<a href="https://support.apple.com/en-us/100100">Apple security releases</a>"#,
        );
        let r = parse_apple_releases(html);
        // Seule la release avec version est gardée (aide + self-link sans chiffre écartés).
        assert_eq!(
            r,
            vec![("127595".to_string(), "macOS Tahoe 26.5.2".to_string())]
        );
    }

    #[test]
    fn fresh_amorce_en_silence_puis_alerte_le_neuf() {
        let mut st = State::default();
        // 1er run : amorçage, aucune alerte même si 3 IDs présents.
        let first = st.fresh("kev", ["CVE-1".into(), "CVE-2".into(), "CVE-3".into()]);
        assert!(first.is_empty(), "le 1er run doit amorcer sans alerter");
        // 2e run : 2 connus + 1 neuf → seul le neuf remonte.
        let second = st.fresh("kev", ["CVE-2".into(), "CVE-3".into(), "CVE-4".into()]);
        assert_eq!(second, vec!["CVE-4".to_string()]);
        // 3e run : rien de neuf.
        assert!(st.fresh("kev", ["CVE-4".into()]).is_empty());
    }

    #[test]
    fn modules_sont_independants() {
        let mut st = State::default();
        st.fresh("kev", ["A".into()]); // amorce kev
        // Un autre module a son propre amorçage indépendant.
        assert!(st.fresh("pastes", ["X".into()]).is_empty());
        assert_eq!(
            st.fresh("pastes", ["X".into(), "Y".into()]),
            vec!["Y".to_string()]
        );
    }
}
