//! Dispatch d'enrichissement : détecte les enrichers concernés par l'observable,
//! les lance en parallèle et fusionne en un rapport générique.

pub(crate) mod abuseipdb;
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
pub(crate) mod netlas;
pub(crate) mod onion;
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
pub(crate) mod shodan;
pub(crate) mod stopforumspam;
pub(crate) mod threatfox;
pub(crate) mod triage;
pub(crate) mod url_analysis;
pub(crate) mod urlhaus;
pub(crate) mod urlscan;
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
use serde::Serialize;
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
}

/// Cache mémoire TTL par `(source:observable)` — protège les quotas API.
pub struct Cache {
    inner: Mutex<HashMap<String, (Instant, Enrichment)>>,
    sem: Semaphore,
    /// Sémaphores de concurrence par source (≈ par hôte), créés à la volée.
    host_sems: Mutex<HashMap<String, Arc<Semaphore>>>,
    /// Compteurs par source (ok/err/cache-hit/latence), créés à la volée.
    stats: Mutex<HashMap<String, Arc<SourceStat>>>,
}

impl Default for Cache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            sem: Semaphore::new(OUTBOUND_MAX),
            host_sems: Mutex::new(HashMap::new()),
            stats: Mutex::new(HashMap::new()),
        }
    }
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

    /// Compteur d'une source (créé à la volée).
    fn stat(&self, source: &str) -> Arc<SourceStat> {
        self.stats
            .lock()
            .entry(source.to_string())
            .or_default()
            .clone()
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
        } else {
            stat.err.fetch_add(1, Ordering::Relaxed);
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
        // vite qu'un succès mémorisé.
        let effective = if enr.error.is_some() { NEG_TTL } else { ttl };
        (at.elapsed() < effective).then(|| enr.clone())
    }
}

#[cfg(test)]
mod cache_throttle_tests {
    use super::{Cache, PER_SOURCE_MAX};
    use std::sync::Arc;
    use std::sync::atomic::Ordering;

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
#[derive(Debug, Clone, Serialize)]
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
#[derive(Debug, Clone, Serialize)]
pub struct Pivot {
    pub relation: String,
    pub kind: String,
    pub value: String,
}

/// Résultat d'un enricher (une source).
#[derive(Debug, Clone, Serialize)]
pub struct Enrichment {
    pub source: String,
    pub facts: Vec<Fact>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub signals: Vec<Signal>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
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
    entries: Vec<Arc<dyn Enricher>>,
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

    /// Vrai si au moins un enricher applicable a sa clé configurée.
    pub fn has_keyed_for(&self, obs: &Observable, ctx: &Ctx) -> bool {
        self.entries
            .iter()
            .any(|e| e.applicable(obs) && e.key_name().is_some_and(|k| ctx.key(k).is_some()))
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
    let candidates = ctx.registry.for_obs(obs);
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
