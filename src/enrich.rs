//! Dispatch d'enrichissement : détecte les enrichers concernés par l'observable,
//! les lance en parallèle et fusionne en un rapport générique.

pub(crate) mod abuseipdb;
pub(crate) mod aura;
pub(crate) mod binaryedge;
pub(crate) mod blocklists;
pub(crate) mod censys;
pub(crate) mod certspotter;
pub(crate) mod circl_hashlookup;
pub(crate) mod criminalip;
pub(crate) mod crtsh;
pub(crate) mod crypto;
pub(crate) mod cve;
pub(crate) mod cvedb;
pub(crate) mod decryptor;
pub(crate) mod dns;
pub(crate) mod dshield;
pub(crate) mod emailrep;
pub(crate) mod filescan;
pub(crate) mod fofa;
pub(crate) mod fullhunt;
pub(crate) mod github;
pub(crate) mod gravatar;
pub(crate) mod greynoise;
pub(crate) mod hudsonrock;
pub(crate) mod hunter;
pub(crate) mod hybridanalysis;
pub(crate) mod ikwyd;
pub(crate) mod intelx;
pub(crate) mod internetdb;
pub(crate) mod ipdata;
pub(crate) mod ipgeo;
pub(crate) mod ipinfo;
pub(crate) mod ipqs;
pub(crate) mod leakix;
pub(crate) mod local;
pub(crate) mod malshare;
pub(crate) mod maltiverse;
pub(crate) mod malwarebazaar;
pub(crate) mod maxmind;
pub(crate) mod metadefender;
pub(crate) mod misp;
pub(crate) mod netlas;
pub(crate) mod onion;
pub(crate) mod onyphe;
pub(crate) mod opentip;
pub(crate) mod osv;
pub(crate) mod otx;
pub(crate) mod phone;
pub(crate) mod poc;
pub(crate) mod proxycheck;
pub(crate) mod pulsedive;
pub(crate) mod quake;
pub(crate) mod rdap;
pub(crate) mod rdap_domain;
pub(crate) mod rdns;
pub(crate) mod ripestat;
pub(crate) mod safebrowsing;
pub(crate) mod scamalytics;
pub(crate) mod securitytrails;
pub(crate) mod shodan;
pub(crate) mod stopforumspam;
pub(crate) mod threatfox;
pub(crate) mod traceix;
pub(crate) mod triage;
pub(crate) mod url_analysis;
pub(crate) mod urlhaus;
pub(crate) mod urlscan;
pub(crate) mod urlscan_pro;
pub(crate) mod username;
pub(crate) mod validin;
pub(crate) mod virustotal;
pub(crate) mod vpnapi;
pub(crate) mod vulncheck;
pub(crate) mod vulners;
pub(crate) mod wayback;
pub(crate) mod zoomeye;

use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use serde::{Deserialize, Serialize};
use tokio::sync::Semaphore;

use crate::model::{IpReport, Signal};
use crate::observable::Observable;
use crate::store::Store;
use crate::verdict::Verdict;

/// Un enricher payant, boxé pour cohabiter avec d'autres dans un `Vec` et
/// tourner en parallèle (`join_all`). Ne peut pas être `JoinSet`/spawn : les
/// futures empruntent `ctx` (pas `'static`). `+ Send` : `run()` les tient à
pub(crate) type BoxedEnricher<'a> = Pin<Box<dyn Future<Output = Enrichment> + Send + 'a>>;

/// Plafond d'entrées du cache (borne mémoire).
const CACHE_MAX: usize = 50_000;
/// Concurrence max des appels réseau sortants (borne amplification / quotas upstream).
const OUTBOUND_MAX: usize = 32;
/// Concurrence max par source (≈ par hôte d'API) — protège les quotas free-tier
/// quand plusieurs requêtes concurrentes visent la même API.
const PER_SOURCE_MAX: usize = 4;
/// TTL du cache négatif : une source qui vient d'échouer (tier-limited, clé
/// invalide, timeout…) n'est pas re-tapée avant ce délai. Court, pour laisser
/// une erreur transitoire se résorber, mais assez long pour arrêter le
/// matraquage d'une source durablement cassée à chaque lookup.
const NEG_TTL: Duration = Duration::from_secs(600);
/// Timeout par source dans `get_or` : borne la latence qu'une source lente
/// (crt.sh jusqu'à ~50 s, intelx en polling) peut imposer au lookup global.
/// Plus court que le timeout du client HTTP (15 s) pour cadrer aussi les
/// enrichers multi-requêtes. Un dépassement → erreur → négativement cachée.
const ENRICHER_TIMEOUT: Duration = Duration::from_secs(10);
/// TTL du cache négatif pour une erreur de **rate-limit / quota** (HTTP 429).
/// Bien plus long que `NEG_TTL` : retaper une API dont le quota est épuisé ne
/// produit que des rejets — et chez certains fournisseurs (Validin) une
/// notification de quota par jour. On recule jusqu'au reset probable.
const RATE_LIMIT_TTL: Duration = Duration::from_secs(6 * 3600);
/// Fenêtre de réinitialisation d'un quota fournisseur.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum QuotaWindow {
    Day,
    /// Mois **civil** (le fournisseur remet à zéro le 1er), pas 30 jours glissants.
    Month,
}

/// Quotas **durs** côté fournisseur, appliqués localement avec une marge (on
/// s'arrête juste en dessous). Empêche d'émettre le moindre appel une fois le
/// plafond atteint → aucun 429, donc aucune notification de quota.
const QUOTAS: &[(&str, u32, QuotaWindow)] = &[
    ("validin", 9, QuotaWindow::Day),    // free tier = 10/jour
    ("fullhunt", 9, QuotaWindow::Month), // free tier = 10/mois
];

/// Vrai si l'erreur d'un enricher traduit un rate-limit / quota épuisé.
fn is_rate_limited(err: &str) -> bool {
    err.contains("429") || err.to_ascii_lowercase().contains("too many requests")
}

/// Quota local d'une source (`None` = pas de plafond).
fn quota_of(source: &str) -> Option<(u32, QuotaWindow)> {
    QUOTAS
        .iter()
        .find(|(s, _, _)| *s == source)
        .map(|(_, n, w)| (*n, *w))
}

/// Identifiant de la fenêtre de quota courante : numéro de jour depuis l'epoch,
/// ou numéro de mois civil. Dès qu'il change, le compteur repart à zéro.
fn window_id(window: QuotaWindow) -> u64 {
    let days = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0) as i64;
    match window {
        QuotaWindow::Day => days.max(0) as u64,
        QuotaWindow::Month => {
            let (y, m) = civil_year_month(days);
            (y * 12 + m as i64 - 1).max(0) as u64
        }
    }
}

/// (année, mois) civils depuis un nombre de jours depuis l'epoch Unix.
/// `civil_from_days` de Howard Hinnant (domaine public) — évite d'ajouter une
/// dépendance date pour ce seul besoin.
fn civil_year_month(days: i64) -> (i64, u32) {
    let (y, m, _) = civil_from_days(days);
    (y, m)
}

/// (année, mois, jour) civils depuis un nombre de jours depuis l'epoch Unix.
/// `civil_from_days` de Howard Hinnant (domaine public).
pub(crate) fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

/// Relit les compteurs de quota persistés (`source<TAB>fenêtre<TAB>appels`).
/// Fichier absent ou ligne illisible → ignoré (on repart de zéro pour la source).
fn load_quota(path: &std::path::Path) -> HashMap<String, (u64, u32)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    text.lines()
        .filter_map(|l| {
            let mut it = l.split('\t');
            let source = it.next()?.trim();
            let window: u64 = it.next()?.trim().parse().ok()?;
            let used: u32 = it.next()?.trim().parse().ok()?;
            (!source.is_empty()).then(|| (source.to_string(), (window, used)))
        })
        .collect()
}

/// Relit le cache persisté, en écartant ce qui a déjà expiré. Fichier absent,
/// ligne illisible ou entrée périmée → ignoré silencieusement : un cache est un
/// accélérateur, jamais une source de vérité qui doit empêcher le démarrage.
fn load_entries(path: &std::path::Path) -> HashMap<String, (Instant, Enrichment)> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return HashMap::new();
    };
    let now_u = unix_now();
    let now_i = Instant::now();
    text.lines()
        .filter_map(|l| serde_json::from_str::<StoredEntry>(l).ok())
        .filter_map(|e| {
            // Âge conservé tel quel : l'entrée reprend exactement là où elle en
            // était, sans repartir d'un TTL neuf qu'elle n'a pas mérité.
            let age = Duration::from_secs(now_u.saturating_sub(e.at));
            if age >= MAX_PERSIST_AGE {
                return None;
            }
            Some((e.k, (now_i.checked_sub(age)?, e.v)))
        })
        .take(CACHE_MAX)
        .collect()
}

/// Compteurs atomiques par source, pour l'endpoint `/metrics`.
#[derive(Default)]
struct SourceStat {
    ok: AtomicU64,
    err: AtomicU64,
    cache_hit: AtomicU64,
    /// Hits du cache négatif : appels court-circuités car la source a échoué
    /// récemment (dans la fenêtre NEG_TTL).
    neg_hit: AtomicU64,
    calls: AtomicU64,
    latency_ms_sum: AtomicU64,
    /// Dernier message d'erreur observé. Sans lui, savoir *pourquoi* une source
    /// est en panne impose de relancer un lookup et d'éplucher la réponse —
    /// c'est comme ça que fofa et zoomeye sont restés cassés sans qu'on le voie.
    last_error: Mutex<Option<String>>,
}

/// Vue sérialisable des compteurs d'une source (réponse `/metrics`).
#[derive(Serialize)]
pub struct SourceMetric {
    pub source: String,
    pub ok: u64,
    pub err: u64,
    pub cache_hit: u64,
    pub neg_hit: u64,
    pub calls: u64,
    pub avg_latency_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

/// Cache mémoire TTL par `(source:observable)` — protège les quotas API.
pub struct Cache {
    inner: Mutex<HashMap<String, (Instant, Enrichment)>>,
    sem: Semaphore,
    /// Sémaphores de concurrence par source (≈ par hôte), créés à la volée.
    host_sems: Mutex<HashMap<String, Arc<Semaphore>>>,
    /// Compteurs par source (ok/err/cache-hit/latence), créés à la volée.
    stats: Mutex<HashMap<String, Arc<SourceStat>>>,
    /// Compteurs de quota par source : `source -> (fenêtre courante, appels)`.
    /// **Persisté sur disque** : un quota mensuel (fullhunt = 10/mois) ne
    /// survivrait pas aux redéploiements sinon — chaque restart le remettrait à
    /// zéro et on dépasserait le plafond réel en quelques déploiements.
    quota: Mutex<HashMap<String, (u64, u32)>>,
    /// Fichier de persistance des compteurs (`None` = mémoire seule, pour les tests).
    quota_path: Option<std::path::PathBuf>,
    /// Fichier de persistance des **résultats** (`None` = mémoire seule).
    /// Sans lui, chaque redéploiement repart d'un cache vide et re-tape toutes
    /// les API — dont celles à 10 appels/mois. Le quota était déjà protégé ;
    /// c'est le travail déjà payé qui était jeté.
    store_path: Option<std::path::PathBuf>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            sem: Semaphore::new(OUTBOUND_MAX),
            host_sems: Mutex::new(HashMap::new()),
            stats: Mutex::new(HashMap::new()),
            quota: Mutex::new(HashMap::new()),
            quota_path: None,
            store_path: None,
        }
    }
}

/// Une entrée du cache telle qu'elle est écrite sur disque.
///
/// On persiste **l'heure d'insertion** (epoch), pas une expiration : le TTL
/// n'est pas porté par l'entrée mais fourni par l'appelant à chaque lecture
/// (`peek(key, ttl)`), exactement comme en mémoire où la map stocke `at` et
/// compare `at.elapsed() < ttl`. Un `Instant` n'a aucun sens d'un processus à
/// l'autre, d'où l'horodatage absolu.
#[derive(Serialize, Deserialize)]
struct StoredEntry {
    k: String,
    /// Insertion, en secondes depuis l'epoch Unix.
    at: u64,
    v: Enrichment,
}

/// Âge maximal d'une entrée persistée. Au-delà, plus aucun TTL en usage ne la
/// considérerait valide : la relire ne ferait que gonfler le fichier.
const MAX_PERSIST_AGE: Duration = Duration::from_secs(24 * 3600);

/// Secondes depuis l'epoch Unix.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

impl Cache {
    /// Sémaphore de concurrence propre à une source (≈ un hôte d'API), créé à
    /// la volée. Deux sources distinctes ne se bloquent jamais l'une l'autre.
    fn source_sem(&self, source: &str) -> Arc<Semaphore> {
        self.host_sems
            .lock()
            .entry(source.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(PER_SOURCE_MAX)))
            .clone()
    }

    /// Cache dont les compteurs de quota sont persistés dans `data_dir`
    /// (indispensable pour un quota mensuel : sinon chaque redéploiement
    /// remettrait le compteur à zéro).
    pub fn with_data_dir(data_dir: &std::path::Path) -> Self {
        let path = data_dir.join("quota.tsv");
        let store_path = data_dir.join("cache.jsonl");
        let entries = load_entries(&store_path);
        if !entries.is_empty() {
            tracing::info!(entries = entries.len(), "cache d'enrichissement restauré");
        }
        Self {
            inner: Mutex::new(entries),
            quota: Mutex::new(load_quota(&path)),
            quota_path: Some(path),
            store_path: Some(store_path),
            ..Self::default()
        }
    }

    /// Écrit le cache sur disque. Appelé périodiquement et à l'arrêt propre.
    /// Les entrées expirées et les **échecs** sont écartés : re-tenter une
    /// source au redémarrage est souhaitable, re-payer un succès ne l'est pas.
    pub fn save(&self) {
        let Some(path) = &self.store_path else { return };
        let now_u = unix_now();
        let entries: Vec<StoredEntry> = {
            let map = self.inner.lock();
            map.iter()
                .filter(|(_, (at, enr))| at.elapsed() < MAX_PERSIST_AGE && enr.error.is_none())
                .map(|(k, (at, enr))| StoredEntry {
                    k: k.clone(),
                    at: now_u.saturating_sub(at.elapsed().as_secs()),
                    v: enr.clone(),
                })
                .collect()
        };
        let body: String = entries
            .iter()
            .filter_map(|e| serde_json::to_string(e).ok())
            .collect::<Vec<_>>()
            .join("\n");
        // Écriture atomique : un kill pendant l'écriture ne doit pas laisser un
        // fichier tronqué que le prochain démarrage lirait à moitié.
        let tmp = path.with_extension("jsonl.tmp");
        if std::fs::write(&tmp, body).is_ok() && std::fs::rename(&tmp, path).is_ok() {
            tracing::debug!(entries = entries.len(), "cache d'enrichissement écrit");
        }
    }

    /// Réserve un appel dans le quota de `source`. `false` = plafond atteint
    /// pour la fenêtre en cours → aucun appel réseau ne doit partir. Le
    /// compteur repart à zéro au changement de fenêtre (jour ou mois civil).
    fn take_quota_slot(&self, source: &str) -> bool {
        let Some((limit, window)) = quota_of(source) else {
            return true; // pas de plafond pour cette source
        };
        let now = window_id(window);
        let snapshot = {
            let mut guard = self.quota.lock();
            let entry = guard.entry(source.to_string()).or_insert((now, 0));
            if entry.0 != now {
                *entry = (now, 0); // nouvelle fenêtre → remise à zéro
            }
            if entry.1 >= limit {
                return false;
            }
            entry.1 += 1;
            guard.clone()
        }; // verrou relâché avant l'écriture disque
        self.save_quota(&snapshot);
        true
    }

    /// Écrit les compteurs (`source<TAB>fenêtre<TAB>appels`). Best-effort : un
    /// échec d'écriture ne doit jamais casser un lookup.
    fn save_quota(&self, map: &HashMap<String, (u64, u32)>) {
        let Some(path) = &self.quota_path else { return };
        let body: String = map
            .iter()
            .map(|(s, (w, n))| format!("{s}\t{w}\t{n}\n"))
            .collect();
        let _ = std::fs::write(path, body);
    }

    /// Compteur d'une source (créé à la volée).
    fn stat(&self, source: &str) -> Arc<SourceStat> {
        self.stats
            .lock()
            .entry(source.to_string())
            .or_default()
            .clone()
    }

    /// Quota local consommé pour une source, sur la fenêtre en cours.
    /// `None` = pas de plafond déclaré pour cette source.
    pub fn quota_state(&self, source: &str) -> Option<(u32, u32, &'static str)> {
        let (limit, window) = quota_of(source)?;
        let current = window_id(window);
        let used = match self.quota.lock().get(source) {
            // Compteur d'une fenêtre passée : il ne décrit plus rien d'utile.
            Some((w, n)) if *w == current => *n,
            _ => 0,
        };
        let unit = match window {
            QuotaWindow::Day => "jour",
            QuotaWindow::Month => "mois",
        };
        Some((used, limit, unit))
    }

    /// Snapshot trié des compteurs par source (pour `/metrics`).
    pub fn metrics(&self) -> Vec<SourceMetric> {
        let map = self.stats.lock();
        let mut out: Vec<SourceMetric> = map
            .iter()
            .map(|(source, s)| {
                let calls = s.calls.load(Ordering::Relaxed);
                SourceMetric {
                    source: source.clone(),
                    ok: s.ok.load(Ordering::Relaxed),
                    err: s.err.load(Ordering::Relaxed),
                    cache_hit: s.cache_hit.load(Ordering::Relaxed),
                    neg_hit: s.neg_hit.load(Ordering::Relaxed),
                    calls,
                    avg_latency_ms: s
                        .latency_ms_sum
                        .load(Ordering::Relaxed)
                        .checked_div(calls)
                        .unwrap_or(0),
                    last_error: s.last_error.lock().clone(),
                }
            })
            .collect();
        out.sort_by(|a, b| a.source.cmp(&b.source));
        out
    }

    /// Ressert du cache si frais (< ttl), sinon exécute `fut` et mémorise
    /// (sauf erreur). Le verrou n'est jamais tenu à travers un `await`.
    pub async fn get_or<F>(&self, key: String, ttl: Duration, fut: F) -> Enrichment
    where
        F: Future<Output = Enrichment>,
    {
        let source = key.split(':').next().unwrap_or_default().to_string();
        if let Some(mut hit) = self.peek(&key, ttl) {
            // Hit positif (succès mémorisé) ou négatif (erreur dans NEG_TTL) :
            // dans les deux cas on évite l'appel réseau.
            let stat = self.stat(&source);
            if hit.error.is_some() {
                stat.neg_hit.fetch_add(1, Ordering::Relaxed);
            } else {
                stat.cache_hit.fetch_add(1, Ordering::Relaxed);
            }
            hit.source = format!("{} (cache)", hit.source);
            return hit;
        }
        // Quota local : on s'arrête AVANT d'émettre l'appel, donc la source ne
        // voit jamais de dépassement (pas de 429, pas de notification de quota).
        if !self.take_quota_slot(&source) {
            let (limit, window) = quota_of(&source).unwrap_or((0, QuotaWindow::Day));
            let (unit, retry) = match window {
                QuotaWindow::Day => ("j", "demain"),
                QuotaWindow::Month => ("mois", "le mois prochain"),
            };
            let enr = Enrichment::failed(
                &source,
                format!("quota local atteint ({limit}/{unit}) — réessai {retry}"),
            );
            self.stat(&source).err.fetch_add(1, Ordering::Relaxed);
            self.insert_bounded(key, enr.clone());
            return enr;
        }
        // Sur un vrai appel réseau : borne d'abord la concurrence par source
        // (≈ par hôte, protège les quotas free-tier), puis la globale. Ordre
        // source→globale : on ne retient un permis global qu'une fois prêt à
        // taper l'API, jamais en attente d'un permis de source.
        let _host_permit = self.source_sem(&source).acquire_owned().await;
        let _permit = self.sem.acquire().await;
        let started = Instant::now();
        // Timeout par source : une source lente ne plombe pas la latence du
        // lookup. Le dépassement devient une erreur, donc négativement cachée
        // → les lookups suivants la court-circuitent au lieu de re-attendre.
        let fresh = match tokio::time::timeout(ENRICHER_TIMEOUT, fut).await {
            Ok(enr) => enr,
            Err(_) => Enrichment::failed(
                &source,
                format!("timeout (> {} s)", ENRICHER_TIMEOUT.as_secs()),
            ),
        };
        let stat = self.stat(&source);
        stat.calls.fetch_add(1, Ordering::Relaxed);
        stat.latency_ms_sum
            .fetch_add(started.elapsed().as_millis() as u64, Ordering::Relaxed);
        if fresh.error.is_none() {
            stat.ok.fetch_add(1, Ordering::Relaxed);
            // Un succès efface l'erreur mémorisée : elle décrirait un état révolu.
            *stat.last_error.lock() = None;
        } else {
            stat.err.fetch_add(1, Ordering::Relaxed);
            *stat.last_error.lock() = fresh.error.clone();
        }
        // Cache positif (succès, TTL de la source) ET négatif (erreur, NEG_TTL
        // court) : dans les deux cas on mémorise pour ne pas re-taper la source.
        // Le TTL effectif est choisi à la lecture (`peek`) selon l'erreur.
        self.insert_bounded(key, fresh.clone());
        fresh
    }

    /// Insère en bornant la taille (au plafond, évince la moitié la plus
    /// ancienne). Sert aux entrées positives comme négatives.
    fn insert_bounded(&self, key: String, enr: Enrichment) {
        let mut map = self.inner.lock();
        if map.len() >= CACHE_MAX {
            let mut times: Vec<Instant> = map.values().map(|(t, _)| *t).collect();
            times.sort_unstable();
            let cutoff = times[times.len() / 2];
            map.retain(|_, (t, _)| *t >= cutoff);
        }
        map.insert(key, (Instant::now(), enr));
    }

    fn peek(&self, key: &str, ttl: Duration) -> Option<Enrichment> {
        let map = self.inner.lock();
        let (at, enr) = map.get(key)?;
        // Entrée en erreur → TTL court (NEG_TTL) : on retente la source plus
        // vite qu'un succès mémorisé. Exception : un rate-limit (429) recule
        // beaucoup plus longtemps — insister ne fait que collecter des rejets.
        let effective = match enr.error.as_deref() {
            Some(e) if is_rate_limited(e) => RATE_LIMIT_TTL,
            Some(_) => NEG_TTL,
            None => ttl,
        };
        (at.elapsed() < effective).then(|| enr.clone())
    }
}

#[cfg(test)]
mod cache_throttle_tests {
    use super::{
        Cache, Enrichment, Fact, PER_SOURCE_MAX, QuotaWindow, civil_year_month, is_rate_limited,
        quota_of,
    };
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

    #[test]
    fn rate_limit_is_detected() {
        assert!(is_rate_limited(
            "HTTP status client error (429 Too Many Requests) for url (https://app.validin.com/...)"
        ));
        assert!(is_rate_limited("too many requests"));
        // Une erreur ordinaire garde le TTL négatif court.
        assert!(!is_rate_limited(
            "HTTP status client error (400 Bad Request)"
        ));
        assert!(!is_rate_limited("timeout (> 10 s)"));
    }

    #[test]
    fn quota_caps_daily_and_monthly_sources() {
        let cache = Cache::default();
        for (source, expected) in [
            ("validin", QuotaWindow::Day),
            ("fullhunt", QuotaWindow::Month),
        ] {
            let (limit, window) = quota_of(source).expect("source à quota");
            assert_eq!(window, expected);
            // On consomme exactement `limit` appels…
            for _ in 0..limit {
                assert!(cache.take_quota_slot(source));
            }
            // …puis c'est fermé jusqu'à la fenêtre suivante.
            assert!(!cache.take_quota_slot(source));
        }
        // Une source sans plafond n'est jamais bloquée.
        assert!(quota_of("dns").is_none());
        for _ in 0..100 {
            assert!(cache.take_quota_slot("dns"));
        }
    }

    #[test]
    fn civil_year_month_anchors() {
        assert_eq!(civil_year_month(0), (1970, 1)); // epoch
        assert_eq!(civil_year_month(19_722), (2023, 12));
        assert_eq!(civil_year_month(19_723), (2024, 1)); // passage d'année
    }

    /// Le point critique du quota **mensuel** : sans persistance, chaque
    /// redéploiement remettrait le compteur à zéro et on dépasserait les 10/mois.
    #[test]
    fn monthly_quota_survives_restart() {
        let dir = std::env::temp_dir().join("indic_quota_persist_test");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::remove_file(dir.join("quota.tsv"));

        let before = Cache::with_data_dir(&dir);
        assert!(before.take_quota_slot("fullhunt"));
        assert!(before.take_quota_slot("fullhunt"));

        // « Redémarrage » : le compteur est relu, les 2 appels restent comptés.
        let after = Cache::with_data_dir(&dir);
        let (limit, _) = quota_of("fullhunt").unwrap();
        for _ in 0..(limit - 2) {
            assert!(after.take_quota_slot("fullhunt"));
        }
        assert!(!after.take_quota_slot("fullhunt"));

        let _ = std::fs::remove_file(dir.join("quota.tsv"));
    }

    #[test]
    fn per_source_semaphore_is_stable_and_capped() {
        let cache = Cache::default();
        let a = cache.source_sem("shodan");
        // Même source → même sémaphore (partagé entre requêtes concurrentes).
        assert!(Arc::ptr_eq(&a, &cache.source_sem("shodan")));
        // Source différente → sémaphore distinct (pas de blocage croisé).
        assert!(!Arc::ptr_eq(&a, &cache.source_sem("censys")));
        // Le cap vaut PER_SOURCE_MAX ; au-delà, plus aucun permis disponible.
        let _permits: Vec<_> = (0..PER_SOURCE_MAX)
            .map(|_| a.try_acquire().unwrap())
            .collect();
        assert!(
            a.try_acquire().is_err(),
            "au-delà de PER_SOURCE_MAX, l'acquisition doit échouer"
        );
    }

    #[test]
    fn metrics_aggregates_per_source() {
        let cache = Cache::default();
        let s = cache.stat("shodan");
        s.ok.fetch_add(3, Ordering::Relaxed);
        s.err.fetch_add(1, Ordering::Relaxed);
        s.cache_hit.fetch_add(5, Ordering::Relaxed);
        s.neg_hit.fetch_add(2, Ordering::Relaxed);
        s.calls.fetch_add(4, Ordering::Relaxed);
        s.latency_ms_sum.fetch_add(400, Ordering::Relaxed);
        let m = cache.metrics();
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].source, "shodan");
        assert_eq!(m[0].ok, 3);
        assert_eq!(m[0].err, 1);
        assert_eq!(m[0].cache_hit, 5);
        assert_eq!(m[0].neg_hit, 2);
        assert_eq!(m[0].avg_latency_ms, 100); // 400 / 4
    }

    #[tokio::test]
    async fn negative_cache_evite_de_re_taper_une_source_en_erreur() {
        use super::Enrichment;
        use std::sync::atomic::AtomicU64;
        use std::time::Duration;
        let cache = Cache::default();
        let calls = Arc::new(AtomicU64::new(0));
        let run = |calls: Arc<AtomicU64>| async move {
            calls.fetch_add(1, Ordering::Relaxed);
            Enrichment::failed("fofa", "820001 no permission".to_string())
        };
        let ttl = Duration::from_secs(3600);
        // 1er appel : la source échoue et exécute réellement le futur.
        let r1 = cache.get_or("fofa:x".into(), ttl, run(calls.clone())).await;
        assert!(r1.error.is_some());
        // 2e appel dans la fenêtre NEG_TTL : servi du cache négatif, futur non rejoué.
        let r2 = cache.get_or("fofa:x".into(), ttl, run(calls.clone())).await;
        assert!(r2.error.is_some());
        assert!(r2.source.ends_with("(cache)"));
        assert_eq!(
            calls.load(Ordering::Relaxed),
            1,
            "la 2e requête doit être servie du cache négatif, pas ré-appeler la source"
        );
    }

    /// Un succès doit survivre au redémarrage — c'est tout l'intérêt : un
    /// redéploiement ne doit pas re-payer des appels déjà effectués.
    #[tokio::test]
    async fn cache_survives_restart() {
        let dir = std::env::temp_dir().join(format!("indic-cache-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let cache = Cache::with_data_dir(&dir);
        let ttl = std::time::Duration::from_secs(3600);
        let enr = Enrichment::ok("demo", vec![Fact::new("k", "v")]);
        let got = cache.get_or("demo:x".into(), ttl, async move { enr }).await;
        assert!(got.error.is_none());
        cache.save();

        // Nouveau processus simulé : même dossier, instance neuve.
        let revived = Cache::with_data_dir(&dir);
        let hit = revived
            .get_or("demo:x".into(), ttl, async {
                Enrichment::failed("demo", "ne doit pas être appelé".into())
            })
            .await;
        assert!(
            hit.source.contains("cache"),
            "l'entrée doit venir du cache restauré, pas d'un nouvel appel"
        );
        assert!(hit.facts.iter().any(|f| f.value == "v"));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Les échecs ne sont PAS persistés : au redémarrage, une source qui avait
    /// échoué doit avoir droit à une nouvelle tentative.
    #[tokio::test]
    async fn failures_are_not_persisted() {
        let dir = std::env::temp_dir().join(format!("indic-cache-err-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let cache = Cache::with_data_dir(&dir);
        let ttl = std::time::Duration::from_secs(3600);
        cache
            .get_or("boom:x".into(), ttl, async {
                Enrichment::failed("boom", "panne".into())
            })
            .await;
        cache.save();

        let revived = Cache::with_data_dir(&dir);
        let retried = revived
            .get_or("boom:x".into(), ttl, async {
                Enrichment::ok("boom", vec![Fact::new("k", "réessayé")])
            })
            .await;
        assert!(
            !retried.source.contains("cache"),
            "un échec ne doit pas être restauré : la source doit être re-tentée"
        );
        assert!(retried.facts.iter().any(|f| f.value == "réessayé"));

        std::fs::remove_dir_all(&dir).ok();
    }
}

/// Contexte partagé passé à chaque enricher.
pub struct Ctx {
    /// Datasets offline (hot-swappables) — base du moteur IP + pivots.
    pub store: Arc<ArcSwap<Store>>,
    /// Client HTTP réutilisé (RDAP, DoH, APIs).
    pub http: reqwest::Client,
    /// Toutes les clés API non vides, par nom d'env. Hot-swappables via SIGHUP.
    pub keys: RwLock<HashMap<String, String>>,
    /// Token requis pour les enrichers payants. `None` = ouvert (dev).
    pub token: Option<String>,
    /// Cache TTL des résultats d'enrichers réseau.
    pub cache: Cache,
    /// Historique SQLite des lookups (opt-in, `INDIC_HISTORY=1`).
    pub history: Option<crate::history::History>,
    /// Rate limiter par IP (protège les quotas gratuits).
    pub rate_limiter: crate::rate::RateLimiter,
    /// Mapping CWE→MITRE ATT&CK (offline).
    pub attack_map: crate::attack::AttackMap,
    /// Registre des enrichers (construit au démarrage, jamais muté après).
    pub registry: Arc<Registry>,
    /// Sources désactivées à la main (`INDIC_DISABLED_SOURCES`), par nom
    /// d'enricher. Volontairement distinct de l'absence de clé : retirer une
    /// clé du `.env` désactive aussi la source, mais mélange l'identifiant et
    /// l'intention — et ne permet pas de couper une source *sans* clé.
    pub disabled: std::collections::HashSet<String>,
}

impl Ctx {
    /// Clé API par nom d'env, `None` si absente/vide.
    pub fn key(&self, name: &str) -> Option<String> {
        self.keys.read().get(name).cloned()
    }

    /// Vrai si au moins une clé d'enricher payant est configurée.
    pub fn has_paid_key(&self) -> bool {
        self.registry.entries.iter().any(|e| {
            e.key_name()
                .is_some_and(|k| k != "__gated__" && self.key(k).is_some())
        })
    }
}

/// Un fait atomique produit par un enricher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Fact {
    pub key: String,
    pub value: String,
}

impl Fact {
    pub fn new(key: &str, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }
}

/// Un pivot = un autre observable relié (domaine↔IP↔ASN…).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pivot {
    pub relation: String,
    pub kind: String,
    pub value: String,
}

/// Résultat d'un enricher (une source).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enrichment {
    pub source: String,
    pub facts: Vec<Fact>,
    // `default` est indispensable, pas décoratif : `skip_serializing_if` retire
    // le champ du JSON quand il est vide, et serde exige un `Vec` présent à la
    // relecture. Sans lui, toute entrée sans signal ni pivot — l'immense
    // majorité — échouait silencieusement à se recharger depuis le disque.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<Signal>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pivots: Vec<Pivot>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl Enrichment {
    fn ok(source: &str, facts: Vec<Fact>) -> Self {
        Self {
            source: source.into(),
            facts,
            signals: vec![],
            pivots: vec![],
            error: None,
        }
    }
    fn failed(source: &str, error: String) -> Self {
        Self {
            source: source.into(),
            facts: vec![],
            signals: vec![],
            pivots: vec![],
            error: Some(error),
        }
    }
}

// ── Enricher trait + Registry ───────────────────────────────────────────

/// Trait qu'un enricher doit implémenter. Chaque module d'enricher expose
/// une fonction libre ; le registre (`registry.rs`) l'enveloppe dans un
/// adaptateur généré par la macro `enricher!`. Ajouter un enricher = une
/// ligne dans `registry.rs` ; aucun changement dans le dispatch.
pub trait Enricher: Send + Sync {
    /// Identifiant unique de la source (ex. "abuseipdb").
    fn name(&self) -> &'static str;
    /// Clé API associée (env var). `None` = enricher gratuit (keyless).
    fn key_name(&self) -> Option<&'static str>;
    /// Types d'observables que cet enricher sait traiter.
    fn applicable(&self, obs: &Observable) -> bool;
    /// TTL du cache positif pour cette source.
    fn ttl(&self) -> Duration;
    /// IPv4-only ? (GreyNoise community, CriminalIP, OpenTIP, Netlas).
    fn ipv4_only(&self) -> bool {
        false
    }
    /// Lancer l'enrichissement. Reçoit l'observable complet ; l'adaptateur
    /// extrait le champ nécessaire et appelle la fonction d'origine.
    fn enrich<'a>(&'a self, obs: &'a Observable, ctx: &'a Ctx) -> BoxedEnricher<'a>;
    /// Clé de cache construite à partir du nom de source et de l'observable.
    fn cache_key(&self, obs: &Observable) -> String {
        format!("{}:{}", self.name(), obs.value())
    }
}

/// Registre des enrichers, construit au démarrage et partagé via `Ctx`.
#[derive(Default)]
pub struct Registry {
    pub(crate) entries: Vec<Arc<dyn Enricher>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, e: Arc<dyn Enricher>) {
        self.entries.push(e);
    }

    /// Tous les enrichers applicables à un observable (clonés pour être déplacés
    /// dans les futures parallèles).
    pub fn for_obs(&self, obs: &Observable) -> Vec<Arc<dyn Enricher>> {
        self.entries
            .iter()
            .filter(|e| e.applicable(obs))
            .cloned()
            .collect()
    }

    /// Vrai si au moins un enricher applicable a sa clé configurée. Ignore les
    /// sources désactivées : sinon un lookup non authentifié afficherait
    /// « des enrichers à clé nécessitent un token » alors qu'aucun ne tournerait.
    pub fn has_keyed_for(&self, obs: &Observable, ctx: &Ctx) -> bool {
        self.entries.iter().any(|e| {
            e.applicable(obs)
                && !ctx.disabled.contains(e.name())
                && e.key_name().is_some_and(|k| ctx.key(k).is_some())
        })
    }
}

/// Macro déclarative : génère un struct adaptateur + `impl Enricher` qui
/// appelle la fonction d'enrichissement existante. L'adaptateur extrait le
/// champ de l'`Observable` via le pattern et délègue à la closure fournie.
///
/// Usage :
/// ```ignore
/// enricher!(reg, AbuseIpDb, "abuseipdb", Some("ABUSEIPDB_API_KEY"),
///     Observable::Ip(_), TTL_THREAT, false,
///     |obs, ctx| match obs {
///         Observable::Ip(ip) => abuseipdb::enrich_ip(*ip, ctx),
///         _ => unreachable!(),
///     }
/// );
/// ```
macro_rules! enricher {
    ($reg:expr, $name:ident, $source:literal, $key:expr, $obs_pat:pat, $ttl:expr, $ipv4:expr, $body:expr) => {{
        #[allow(non_camel_case_types)]
        struct $name;
        impl $crate::enrich::Enricher for $name {
            fn name(&self) -> &'static str {
                $source
            }
            fn key_name(&self) -> Option<&'static str> {
                $key
            }
            fn applicable(&self, obs: &$crate::observable::Observable) -> bool {
                matches!(obs, $obs_pat)
            }
            fn ttl(&self) -> std::time::Duration {
                $ttl
            }
            fn ipv4_only(&self) -> bool {
                $ipv4
            }
            fn enrich<'a>(
                &'a self,
                obs: &'a $crate::observable::Observable,
                ctx: &'a $crate::enrich::Ctx,
            ) -> $crate::enrich::BoxedEnricher<'a> {
                let obs = obs.clone();
                Box::pin($body(obs, ctx))
            }
        }
        $reg.register(std::sync::Arc::new($name));
    }};
}
pub(crate) use enricher;

/// Rapport unifié pour un observable.
#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub query: String,
    pub kind: String,
    /// Résumé IP typé (cartes du front) quand `kind == ip`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpReport>,
    pub enrichments: Vec<Enrichment>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub pivots: Vec<Pivot>,
    /// Verdict pondéré (signaux de menace + prior de popularité). `None` pour
    /// les types sans dimension menace (téléphone, onion, asn…).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verdict: Option<Verdict>,
    /// Acteurs de menace identifiés (agrégés depuis MalwareBazaar, ThreatFox,
    /// Triage…). Dédupliqués, en minuscules.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub threat_actors: Vec<String>,
    /// Score de fraîcheur 0.0-1.0 (1.0 = IOC vu aujourd'hui).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freshness: Option<f32>,
}

/// Point d'entrée : dispatch les enrichers puis calcule le **verdict pondéré**
/// (agrège les signaux de menace avec un prior de popularité pour éviter les
/// faux positifs sur les plateformes légitimes qui hébergent du malware).
/// `authorized` conditionne les enrichers payants (protection des clés).
#[tracing::instrument(skip(ctx), fields(query = %query, kind = %obs.kind()))]
pub async fn run(query: &str, obs: &Observable, ctx: &Ctx, authorized: bool) -> Report {
    let mut report = dispatch(query, obs, ctx, authorized).await;
    // Le domaine (ou l'apex d'une URL/email) est-il de confiance ? Liste curée +
    // réservés (verdict.rs) OU top mondial Majestic (store, prior de popularité).
    let popular = observable_apex(obs).is_some_and(|a| {
        crate::verdict::is_trusted_domain(&a) || ctx.store.load().is_popular_domain(&a)
    });
    // Tous les signaux : ceux des enrichers + ceux du résumé IP.
    let mut signals: Vec<Signal> = report
        .enrichments
        .iter()
        .flat_map(|e| e.signals.clone())
        .collect();
    if let Some(r) = &report.ip {
        signals.extend(r.signals.iter().cloned());
    }
    let v = crate::verdict::compute(&signals, popular);
    // Exposé pour les types à dimension menace (verdict « clean » rassurant sur
    // une IP/domaine), ou dès qu'un signal existe — jamais sur un téléphone nu.
    let threat_kind = matches!(
        obs,
        Observable::Ip(_)
            | Observable::Domain(_)
            | Observable::Url(_)
            | Observable::Hash(_)
            | Observable::Cidr(_)
            | Observable::Email(_)
            | Observable::Crypto(_)
    );
    report.verdict = (popular || v.raw > 0 || threat_kind).then_some(v);
    // Acteurs de menace : extraire les noms de famille/malware des enrichers.
    report.threat_actors = extract_threat_actors(&report);
    // Score de fraîcheur : 1.0 si vu aujourd'hui, décroît sur 90 jours.
    report.freshness = compute_freshness(&report);
    report
}

/// Apex (eTLD+1) associé à un observable, pour le prior de popularité.
fn observable_apex(obs: &Observable) -> Option<String> {
    use crate::observable::registrable_domain;
    match obs {
        Observable::Domain(d) => registrable_domain(d),
        Observable::Url(u) => url_host(u).and_then(|h| registrable_domain(&h)),
        Observable::Email(e) => e.split('@').nth(1).and_then(registrable_domain),
        _ => None,
    }
}

/// Dispatch d'enrichissement par type d'observable (sans verdict — posé par `run`).
/// Nouveau dispatch — utilise le registre pour sélectionner les enrichers.
/// La logique métier spécifique à chaque type (IpReport, pivots) reste ici ;
/// le choix des enrichers est délégué au registre.
#[tracing::instrument(skip(ctx), fields(query = %query, kind = %obs.kind()))]
async fn dispatch(query: &str, obs: &Observable, ctx: &Ctx, authorized: bool) -> Report {
    match obs {
        Observable::Ip(ip) => {
            let ip_report = local::enrich_ip(*ip, ctx).await;
            let enrichments = run_enrichers(obs, ctx, authorized).await;
            let pivots = enrichments.iter().flat_map(|e| e.pivots.clone()).collect();
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: Some(ip_report),
                enrichments,
                pivots,
                threat_actors: vec![],
                freshness: None,
            }
        }
        Observable::Domain(d) => {
            let enrichments = run_enrichers(obs, ctx, authorized).await;
            let mut pivots: Vec<Pivot> =
                enrichments.iter().flat_map(|e| e.pivots.clone()).collect();
            if let Some(apex) = crate::observable::registrable_domain(d)
                && apex != *d
            {
                pivots.push(Pivot {
                    relation: "apex".into(),
                    kind: "domain".into(),
                    value: apex,
                });
            }
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments,
                pivots,
                threat_actors: vec![],
                freshness: None,
            }
        }
        Observable::Cidr(cidr) => {
            let Ok(net) = cidr.parse::<ipnet::IpNet>() else {
                return stub(query, obs);
            };
            let net_ip = net.network();
            let ip_report = local::enrich_ip(net_ip, ctx).await;
            let enrichments = run_enrichers(obs, ctx, authorized).await;
            let range = Enrichment::ok(
                "cidr",
                vec![
                    Fact::new("plage", net.to_string()),
                    Fact::new("adresse_réseau", net_ip.to_string()),
                    Fact::new("adresses", host_count(&net)),
                ],
            );
            let mut all = vec![range];
            all.extend(enrichments);
            let pivots = all.iter().flat_map(|e| e.pivots.clone()).collect();
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: Some(ip_report),
                enrichments: all,
                pivots,
                threat_actors: vec![],
                freshness: None,
            }
        }
        // Types sans logique de pivot spécifique : juste les enrichers du registre.
        _ => {
            let enrichments = run_enrichers(obs, ctx, authorized).await;
            let pivots = enrichments.iter().flat_map(|e| e.pivots.clone()).collect();
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments,
                pivots,
                threat_actors: vec![],
                freshness: None,
            }
        }
    }
}

/// Exécute tous les enrichers applicables à un observable.
/// - Keyless : toujours exécutés.
/// - Keyed : exécutés seulement si `authorized` ET la clé est présente.
/// - IPv4-only : ignorés sur IPv6.
async fn run_enrichers(obs: &Observable, ctx: &Ctx, authorized: bool) -> Vec<Enrichment> {
    // Filtré ici plutôt qu'au moment du résultat : une source désactivée ne doit
    // pas être appelée du tout — ni latence, ni quota consommé, ni ligne d'erreur.
    let candidates: Vec<_> = ctx
        .registry
        .for_obs(obs)
        .into_iter()
        .filter(|e| !ctx.disabled.contains(e.name()))
        .collect();
    let (keyless, keyed): (Vec<_>, Vec<_>) =
        candidates.into_iter().partition(|e| e.key_name().is_none());

    let mut futs: Vec<BoxedEnricher<'_>> = Vec::new();

    for e in keyless {
        let key = e.cache_key(obs);
        let ttl = e.ttl();
        futs.push(Box::pin(async move {
            ctx.cache.get_or(key, ttl, e.enrich(obs, ctx)).await
        }));
    }

    if authorized {
        for e in keyed {
            let kn = e.key_name().unwrap_or("");
            // Sentinelle "__gated__" = enricher sans clé mais gated (ex. username).
            let can_run = if kn == "__gated__" {
                true
            } else {
                ctx.key(kn).is_some()
            };
            if !can_run {
                continue;
            }
            if e.ipv4_only()
                && let Observable::Ip(ip) = obs
                && !ip.is_ipv4()
            {
                continue;
            }
            let key = e.cache_key(obs);
            let ttl = e.ttl();
            futs.push(Box::pin(async move {
                ctx.cache.get_or(key, ttl, e.enrich(obs, ctx)).await
            }));
        }
    } else if !keyed.is_empty() && ctx.registry.has_keyed_for(obs, ctx) {
        return vec![Enrichment::ok(
            "gated",
            vec![Fact::new(
                "info",
                "des enrichers à clé nécessitent un token",
            )],
        )];
    }

    futures::future::join_all(futs).await
}

/// Retire un secret (clé API) d'un message d'erreur avant de l'exposer : les clés
/// passées en query/path d'URL apparaissent dans les erreurs reqwest (`for url (…)`)
/// et ne doivent jamais fuiter dans une réponse.
pub(super) fn scrub(msg: String, secret: &str) -> String {
    if secret.is_empty() {
        msg
    } else {
        msg.replace(secret, "<redacted>")
    }
}

/// Déduplique une liste en conservant l'ordre, borne à `max`, joint par ", ".
pub(super) fn dedup_join(items: impl IntoIterator<Item = String>, max: usize) -> String {
    let mut seen: Vec<String> = Vec::new();
    for s in items {
        if !s.is_empty() && !seen.contains(&s) {
            seen.push(s);
            if seen.len() == max {
                break;
            }
        }
    }
    seen.join(", ")
}

/// Extrait le host d'une URL (`https://host/path` → `host`).
fn url_host(url: &str) -> Option<String> {
    let after = url.split("://").nth(1)?;
    let host = after.split(['/', '?', '#', ':']).next()?;
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// Nombre d'adresses d'un préfixe, sous forme lisible (`2^n` au-delà de 2^64).
fn host_count(net: &ipnet::IpNet) -> String {
    let total = if net.addr().is_ipv4() { 32u32 } else { 128 };
    let host_bits = total - net.prefix_len() as u32;
    if host_bits >= 65 {
        format!("2^{host_bits}")
    } else {
        (1u128 << host_bits).to_string()
    }
}

/// Extrait les noms d'acteurs de menace depuis les faits des enrichers
/// (MalwareBazaar « malware », Triage « family », ThreatFox « malware »).
fn extract_threat_actors(report: &Report) -> Vec<String> {
    let mut actors: Vec<String> = report
        .enrichments
        .iter()
        .flat_map(|e| e.facts.iter())
        .filter(|f| {
            matches!(
                f.key.as_str(),
                "malware" | "family" | "malware_family" | "actor" | "signature"
            )
        })
        .map(|f| f.value.to_lowercase())
        .filter(|v| !v.is_empty() && v != "unknown" && v != "none" && v != "clean")
        .collect();
    actors.sort();
    actors.dedup();
    actors
}

/// Score de fraîcheur 0.0–1.0 basé sur la date la plus récente trouvée dans les
/// faits des enrichers. 1.0 = vu aujourd'hui, décroît linéairement sur 90 jours.
fn compute_freshness(report: &Report) -> Option<f32> {
    use std::time::{SystemTime, UNIX_EPOCH};
    let _now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let mut best_age: Option<u64> = None;
    for enr in &report.enrichments {
        for fact in &enr.facts {
            let age = match fact.key.as_str() {
                "last_seen" | "last_seen_days" | "age_days" => {
                    fact.value.parse::<u64>().ok().map(|d| d * 86400)
                }
                "first_seen" => {
                    // first_seen n'est pas la date la plus récente, mais on le prend
                    // comme upper bound.
                    fact.value.parse::<u64>().ok().map(|d| d * 86400)
                }
                _ => None,
            };
            if let Some(dur) = age {
                best_age = Some(best_age.map_or(dur, |b| b.min(dur)));
            }
        }
    }
    best_age.map(|age_secs| {
        let max_age: u64 = 90 * 86400; // 90 jours
        ((max_age.saturating_sub(age_secs) as f32) / max_age as f32).clamp(0.0, 1.0)
    })
}

/// Réponse minimale pour un type détecté mais pas encore enrichi.
fn stub(query: &str, obs: &Observable) -> Report {
    let e = Enrichment::ok(
        "detect",
        vec![
            Fact::new(obs.kind(), obs.value()),
            Fact::new("status", "type détecté — enrichers à venir"),
        ],
    );
    Report {
        query: query.into(),
        verdict: None,
        kind: obs.kind().into(),
        ip: None,
        enrichments: vec![e],
        pivots: vec![],
        threat_actors: vec![],
        freshness: None,
    }
}
