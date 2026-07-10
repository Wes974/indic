//! Dispatch d'enrichissement : détecte les enrichers concernés par l'observable,
//! les lance en parallèle et fusionne en un rapport générique.

mod abuseipdb;
mod blocklists;
mod censys;
mod certspotter;
mod circl_hashlookup;
mod criminalip;
mod crtsh;
mod crypto;
mod cve;
mod cvedb;
mod dns;
mod dshield;
mod filescan;
mod fofa;
mod fullhunt;
mod github;
mod gravatar;
mod greynoise;
mod hudsonrock;
mod hunter;
mod hybridanalysis;
mod ikwyd;
pub(crate) mod intelx;
mod internetdb;
mod ipdata;
mod ipgeo;
mod ipinfo;
mod ipqs;
mod leakix;
mod local;
mod malshare;
mod maltiverse;
mod malwarebazaar;
mod maxmind;
mod metadefender;
mod netlas;
mod onion;
mod opentip;
mod osv;
mod otx;
mod phone;
mod poc;
mod proxycheck;
mod pulsedive;
mod quake;
mod rdap;
mod rdap_domain;
mod rdns;
mod ripestat;
mod safebrowsing;
mod scamalytics;
mod shodan;
mod stopforumspam;
mod threatfox;
mod triage;
mod urlhaus;
mod urlscan;
mod username;
mod validin;
mod virustotal;
mod vpnapi;
mod vulncheck;
mod vulners;
mod wayback;
mod zoomeye;

use std::collections::HashMap;
use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
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
/// travers un `await`, et axum exige des handlers `Send`.
type BoxedEnricher<'a> = Pin<Box<dyn Future<Output = Enrichment> + Send + 'a>>;

/// Ajoute un enricher payant au fan-out parallèle si sa clé API est présente.
/// (`$ctx` passé explicitement car un `macro_rules!` n'est pas hygiénique pour
/// les identifiants de valeur.)
macro_rules! gated {
    ($futs:ident, $ctx:ident, $key:literal, $cachekey:expr, $ttl:expr, $call:expr) => {
        if $ctx.key($key).is_some() {
            $futs.push(Box::pin($ctx.cache.get_or($cachekey, $ttl, $call)) as BoxedEnricher);
        }
    };
}

/// Variante pour les enrichers dont l'API est **IPv4-only** (GreyNoise
/// community, CriminalIP, Kaspersky OpenTIP, Netlas — doc confirmée) : sur une
/// IPv6 on skippe l'appel au lieu de récolter un 400 garanti.
macro_rules! gated_v4 {
    ($futs:ident, $ctx:ident, $ip:ident, $key:literal, $cachekey:expr, $ttl:expr, $call:expr) => {
        if $ctx.key($key).is_some() && $ip.is_ipv4() {
            $futs.push(Box::pin($ctx.cache.get_or($cachekey, $ttl, $call)) as BoxedEnricher);
        }
    };
}

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
            .unwrap()
            .entry(source.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(PER_SOURCE_MAX)))
            .clone()
    }

    /// Compteur d'une source (créé à la volée).
    fn stat(&self, source: &str) -> Arc<SourceStat> {
        self.stats
            .lock()
            .unwrap()
            .entry(source.to_string())
            .or_default()
            .clone()
    }

    /// Snapshot trié des compteurs par source (pour `/metrics`).
    pub fn metrics(&self) -> Vec<SourceMetric> {
        let map = self.stats.lock().unwrap();
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
        let mut map = self.inner.lock().unwrap();
        if map.len() >= CACHE_MAX {
            let mut times: Vec<Instant> = map.values().map(|(t, _)| *t).collect();
            times.sort_unstable();
            let cutoff = times[times.len() / 2];
            map.retain(|_, (t, _)| *t >= cutoff);
        }
        map.insert(key, (Instant::now(), enr));
    }

    fn peek(&self, key: &str, ttl: Duration) -> Option<Enrichment> {
        let map = self.inner.lock().unwrap();
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
    /// Toutes les clés API non vides, par nom d'env (ex. "VIRUSTOTAL_API_KEY").
    pub keys: HashMap<String, String>,
    /// Token requis pour les enrichers payants. `None` = ouvert (dev).
    pub token: Option<String>,
    /// Cache TTL des résultats d'enrichers réseau.
    pub cache: Cache,
}

impl Ctx {
    /// Clé API par nom d'env, `None` si absente/vide.
    pub fn key(&self, name: &str) -> Option<&str> {
        self.keys.get(name).map(String::as_str)
    }

    /// Vrai si au moins une clé d'enricher payant est configurée.
    pub fn has_paid_key(&self) -> bool {
        PAID_IP_KEYS.iter().any(|k| self.key(k).is_some())
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
}

/// Point d'entrée : dispatch les enrichers puis calcule le **verdict pondéré**
/// (agrège les signaux de menace avec un prior de popularité pour éviter les
/// faux positifs sur les plateformes légitimes qui hébergent du malware).
/// `authorized` conditionne les enrichers payants (protection des clés).
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
async fn dispatch(query: &str, obs: &Observable, ctx: &Ctx, authorized: bool) -> Report {
    match obs {
        Observable::Ip(ip) => {
            // Fan-out gratuit : datasets locaux + rDNS + RDAP en parallèle.
            let (ip_report, rdns, rdap, geo, dshield, sfs, idb) = tokio::join!(
                local::enrich_ip(*ip, ctx),
                ctx.cache
                    .get_or(format!("rdns:{ip}"), TTL_RDNS, rdns::enrich_ip(*ip, ctx)),
                ctx.cache
                    .get_or(format!("rdap:{ip}"), TTL_RDAP, rdap::enrich_ip(*ip, ctx)),
                ctx.cache
                    .get_or(format!("geo:{ip}"), TTL_GEO, ipgeo::enrich_ip(*ip, ctx)),
                ctx.cache.get_or(
                    format!("dshield:{ip}"),
                    TTL_THREAT,
                    dshield::enrich_ip(*ip, ctx)
                ),
                ctx.cache.get_or(
                    format!("sfs:{ip}"),
                    TTL_THREAT,
                    stopforumspam::enrich_ip(*ip, ctx)
                ),
                ctx.cache.get_or(
                    format!("idb:{ip}"),
                    TTL_THREAT,
                    internetdb::enrich_ip(*ip, ctx)
                ),
            );
            let mut enrichments = vec![rdns, rdap, geo, dshield, sfs, idb];
            // Géo offline précise (MaxMind GeoLite2, si base présente).
            enrichments.push(maxmind::enrich_ip(*ip, ctx).await);

            // Enrichers payants : uniquement si la requête est autorisée.
            if authorized {
                enrichments.append(&mut paid_ip_enrichers(*ip, ctx).await);
            } else if has_paid_ip_key(ctx) {
                enrichments.push(Enrichment::ok(
                    "gated",
                    vec![Fact::new(
                        "info",
                        "des enrichers à clé nécessitent un token",
                    )],
                ));
            }

            let pivots = enrichments.iter().flat_map(|e| e.pivots.clone()).collect();
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: Some(ip_report),
                enrichments,
                pivots,
            }
        }
        Observable::Domain(d) => {
            let (dns, rdap_d, crt, wb, hr, hz) = tokio::join!(
                ctx.cache
                    .get_or(format!("dns:{d}"), TTL_DNS, dns::enrich_domain(d, ctx)),
                ctx.cache.get_or(
                    format!("rdap_domain:{d}"),
                    TTL_RDAP,
                    rdap_domain::enrich_domain(d, ctx)
                ),
                ctx.cache
                    .get_or(format!("crtsh:{d}"), TTL_RDAP, crtsh::enrich_domain(d, ctx)),
                ctx.cache.get_or(
                    format!("wayback:{d}"),
                    TTL_RDAP,
                    wayback::enrich_domain(d, ctx)
                ),
                ctx.cache.get_or(
                    format!("hudsonrock:{d}"),
                    TTL_THREAT,
                    hudsonrock::enrich_domain(d, ctx)
                ),
                blocklists::enrich_domain(d, ctx),
            );
            let mut enrichments = vec![dns, rdap_d, crt, wb, hr, hz];
            // Enrichers domaine payants : fan-out parallèle (au lieu d'une série
            // de `.await`) si la requête est autorisée.
            if authorized {
                let mut futs: Vec<BoxedEnricher> = Vec::new();
                gated!(
                    futs,
                    ctx,
                    "VIRUSTOTAL_API_KEY",
                    format!("vt_domain:{d}"),
                    TTL_PAID,
                    virustotal::enrich_domain(d, ctx)
                );
                if ctx.key("ABUSE_CH_API_KEY").is_some() {
                    futs.push(Box::pin(ctx.cache.get_or(
                        format!("tf_domain:{d}"),
                        TTL_THREAT,
                        threatfox::enrich_domain(d, ctx),
                    )) as BoxedEnricher);
                    futs.push(Box::pin(ctx.cache.get_or(
                        format!("uh_host:{d}"),
                        TTL_THREAT,
                        urlhaus::enrich_host(d, ctx),
                    )) as BoxedEnricher);
                }
                gated!(
                    futs,
                    ctx,
                    "OTX_API_KEY",
                    format!("otx_domain:{d}"),
                    TTL_THREAT,
                    otx::enrich_domain(d, ctx)
                );
                gated!(
                    futs,
                    ctx,
                    "FULLHUNT_API_KEY",
                    format!("fullhunt:{d}"),
                    TTL_RDAP,
                    fullhunt::enrich_domain(d, ctx)
                );
                gated!(
                    futs,
                    ctx,
                    "GITHUB_TOKEN",
                    format!("github:{d}"),
                    TTL_RDAP,
                    github::enrich_domain(d, ctx)
                );
                gated!(
                    futs,
                    ctx,
                    "URLSCAN_API_KEY",
                    format!("urlscan_domain:{d}"),
                    TTL_RDAP,
                    urlscan::enrich_domain(d, ctx)
                );
                gated!(
                    futs,
                    ctx,
                    "INTELX_API_KEY",
                    format!("intelx_domain:{d}"),
                    TTL_RDAP,
                    intelx::enrich_domain(d, ctx)
                );
                gated!(
                    futs,
                    ctx,
                    "METADEFENDER_API_KEY",
                    format!("mdc_domain:{d}"),
                    TTL_THREAT,
                    metadefender::enrich_domain(d, ctx)
                );
                gated!(
                    futs,
                    ctx,
                    "GOOGLE_SAFEBROWSING_API_KEY",
                    format!("gsb_domain:{d}"),
                    TTL_THREAT,
                    safebrowsing::enrich_domain(d, ctx)
                );
                gated!(
                    futs,
                    ctx,
                    "CERTSPOTTER_API_KEY",
                    format!("certspotter:{d}"),
                    TTL_RDAP,
                    certspotter::enrich_domain(d, ctx)
                );
                gated!(
                    futs,
                    ctx,
                    "VALIDIN_API_KEY",
                    format!("validin:{d}"),
                    TTL_RDAP,
                    validin::enrich_domain(d, ctx)
                );
                gated!(
                    futs,
                    ctx,
                    "MALTIVERSE_API_KEY",
                    format!("maltiverse:domain:{d}"),
                    TTL_THREAT,
                    maltiverse::enrich_domain(d, ctx)
                );
                gated!(
                    futs,
                    ctx,
                    "PULSEDIVE_API_KEY",
                    format!("pulsedive_d:{d}"),
                    TTL_THREAT,
                    pulsedive::enrich_domain(d, ctx)
                );
                enrichments.extend(futures::future::join_all(futs).await);
            }
            let mut pivots: Vec<Pivot> =
                enrichments.iter().flat_map(|e| e.pivots.clone()).collect();
            // Sous-domaine → pivot vers le domaine apex (eTLD+1), qui porte les
            // données de registre (RDAP/crt.sh répondent sur l'apex, pas le sous-domaine).
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
            }
        }
        Observable::Cve(c) => {
            let (cve_e, osv_e, cvedb_e) = tokio::join!(
                ctx.cache
                    .get_or(format!("cve:{c}"), TTL_CVE, cve::enrich_cve(c, ctx)),
                ctx.cache
                    .get_or(format!("osv:{c}"), TTL_CVE, osv::enrich_cve(c, ctx)),
                ctx.cache
                    .get_or(format!("cvedb:{c}"), TTL_CVE, cvedb::enrich_cve(c, ctx)),
            );
            let mut enrichments = vec![cve_e, osv_e, cvedb_e];
            // PoC publics (offline, index tg12/PoC_CVEs dans le store).
            enrichments.push(poc::enrich_cve(c, ctx));
            if authorized && ctx.key("VULNCHECK_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("vulncheck:{c}"),
                            TTL_CVE,
                            vulncheck::enrich_cve(c, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("VULNERS_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(format!("vulners:{c}"), TTL_CVE, vulners::enrich_cve(c, ctx))
                        .await,
                );
            }
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments,
                pivots: vec![],
            }
        }
        Observable::Hash(h) => {
            let mut enrichments = vec![
                ctx.cache
                    .get_or(
                        format!("hashlookup:{h}"),
                        TTL_HASH,
                        circl_hashlookup::enrich_hash(h, ctx),
                    )
                    .await,
            ];
            if authorized && ctx.key("VIRUSTOTAL_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("vt_hash:{h}"),
                            TTL_PAID,
                            virustotal::enrich_hash(h, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("ABUSE_CH_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("tf_hash:{h}"),
                            TTL_THREAT,
                            threatfox::enrich_hash(h, ctx),
                        )
                        .await,
                );
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("uh_hash:{h}"),
                            TTL_THREAT,
                            urlhaus::enrich_hash(h, ctx),
                        )
                        .await,
                );
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("mb_hash:{h}"),
                            TTL_THREAT,
                            malwarebazaar::enrich_hash(h, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("OTX_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("otx_hash:{h}"),
                            TTL_THREAT,
                            otx::enrich_hash(h, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("METADEFENDER_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("mdc_hash:{h}"),
                            TTL_HASH,
                            metadefender::enrich_hash(h, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("MALSHARE_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("malshare:{h}"),
                            TTL_HASH,
                            malshare::enrich_hash(h, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("FILESCAN_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("filescan:{h}"),
                            TTL_HASH,
                            filescan::enrich_hash(h, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("MALTIVERSE_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("maltiverse:hash:{h}"),
                            TTL_HASH,
                            maltiverse::enrich_hash(h, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("TRIAGE_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(format!("triage:{h}"), TTL_HASH, triage::enrich_hash(h, ctx))
                        .await,
                );
            }
            if authorized && ctx.key("HYBRIDANALYSIS_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("hybridanalysis:{h}"),
                            TTL_HASH,
                            hybridanalysis::enrich_hash(h, ctx),
                        )
                        .await,
                );
            }
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments,
                pivots: vec![],
            }
        }
        Observable::Email(e) => {
            let (hr, sfs, grav) = tokio::join!(
                ctx.cache.get_or(
                    format!("hr_email:{e}"),
                    TTL_THREAT,
                    hudsonrock::enrich_email(e, ctx)
                ),
                ctx.cache.get_or(
                    format!("sfs_email:{e}"),
                    TTL_THREAT,
                    stopforumspam::enrich_email(e, ctx)
                ),
                ctx.cache.get_or(
                    format!("gravatar:{e}"),
                    TTL_RDAP,
                    gravatar::enrich_email(e, ctx)
                ),
            );
            let mut enrichments = vec![hr, sfs, grav];
            if authorized && ctx.key("INTELX_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("intelx_email:{e}"),
                            TTL_RDAP,
                            intelx::enrich_email(e, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("HUNTER_IO_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("hunter:{e}"),
                            TTL_RDAP,
                            hunter::enrich_email(e, ctx),
                        )
                        .await,
                );
            }
            let mut pivots = Vec::new();
            if let Some(domain) = e.split('@').nth(1) {
                pivots.push(Pivot {
                    relation: "domain".into(),
                    kind: "domain".into(),
                    value: domain.to_string(),
                });
            }
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments,
                pivots,
            }
        }
        Observable::Url(u) => {
            let mut enrichments = vec![
                ctx.cache
                    .get_or(
                        format!("wayback_url:{u}"),
                        TTL_RDAP,
                        wayback::enrich_domain(u, ctx),
                    )
                    .await,
            ];
            if authorized && ctx.key("VIRUSTOTAL_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("vt_url:{u}"),
                            TTL_PAID,
                            virustotal::enrich_url(u, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("ABUSE_CH_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("tf_url:{u}"),
                            TTL_THREAT,
                            threatfox::enrich_url(u, ctx),
                        )
                        .await,
                );
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("uh_url:{u}"),
                            TTL_THREAT,
                            urlhaus::enrich_url(u, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("OTX_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(format!("otx_url:{u}"), TTL_THREAT, otx::enrich_url(u, ctx))
                        .await,
                );
            }
            if authorized && ctx.key("URLSCAN_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("urlscan_url:{u}"),
                            TTL_RDAP,
                            urlscan::enrich_url(u, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("METADEFENDER_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("mdc_url:{u}"),
                            TTL_THREAT,
                            metadefender::enrich_url(u, ctx),
                        )
                        .await,
                );
            }
            if authorized && ctx.key("GOOGLE_SAFEBROWSING_API_KEY").is_some() {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("gsb_url:{u}"),
                            TTL_THREAT,
                            safebrowsing::enrich_url(u, ctx),
                        )
                        .await,
                );
            }
            let mut pivots = Vec::new();
            if let Some(host) = url_host(u) {
                pivots.push(Pivot {
                    relation: "host".into(),
                    kind: "domain".into(),
                    value: host,
                });
            }
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments,
                pivots,
            }
        }
        Observable::Asn(n) => {
            let e = ctx
                .cache
                .get_or(
                    format!("ripestat:{n}"),
                    TTL_RDAP,
                    ripestat::enrich_asn(*n, ctx),
                )
                .await;
            let pivots = e.pivots.clone();
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments: vec![e],
                pivots,
            }
        }
        Observable::Crypto(addr) => {
            let mut enrichments = vec![crypto::ofac(addr, ctx).await];
            // Etherscan (ETH uniquement, gated) — cache par adresse.
            if crypto::chain(addr) == "eth" && authorized && ctx.key("ETHERSCAN_API_KEY").is_some()
            {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("etherscan:{addr}"),
                            TTL_THREAT,
                            crypto::etherscan(addr, ctx),
                        )
                        .await,
                );
            }
            let pivots = enrichments.iter().flat_map(|e| e.pivots.clone()).collect();
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments,
                pivots,
            }
        }
        Observable::Username(u) => {
            // Recherche multi-sites (12 requêtes sortantes) : gated pour éviter
            // qu'indic serve de proxy d'énumération public.
            let mut enrichments = Vec::new();
            if authorized {
                enrichments.push(
                    ctx.cache
                        .get_or(
                            format!("username:{u}"),
                            TTL_RDAP,
                            username::enrich_username(u, ctx),
                        )
                        .await,
                );
            } else {
                enrichments.push(Enrichment::ok(
                    "gated",
                    vec![Fact::new("info", "recherche username nécessite un token")],
                ));
            }
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments,
                pivots: vec![],
            }
        }
        Observable::Cidr(cidr) => {
            // Enrichit la plage via son adresse réseau : résumé offline
            // (ASN/org/géo/menace) + RDAP. Pas d'enrichers per-IP payants (plage).
            let Ok(net) = cidr.parse::<ipnet::IpNet>() else {
                return stub(query, obs);
            };
            let net_ip = net.network();
            let (ip_report, rdap) = tokio::join!(
                local::enrich_ip(net_ip, ctx),
                ctx.cache.get_or(
                    format!("rdap:{net_ip}"),
                    TTL_RDAP,
                    rdap::enrich_ip(net_ip, ctx)
                ),
            );
            let range = Enrichment::ok(
                "cidr",
                vec![
                    Fact::new("plage", net.to_string()),
                    Fact::new("adresse_réseau", net_ip.to_string()),
                    Fact::new("adresses", host_count(&net)),
                ],
            );
            let enrichments = vec![range, rdap];
            let pivots = enrichments.iter().flat_map(|e| e.pivots.clone()).collect();
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: Some(ip_report),
                enrichments,
                pivots,
            }
        }
        Observable::Phone(p) => {
            let e = phone::enrich_phone(p, ctx).await;
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments: vec![e],
                pivots: vec![],
            }
        }
        Observable::Onion(o) => {
            let e = onion::enrich_onion(o, ctx).await;
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments: vec![e],
                pivots: vec![],
            }
        }
        Observable::Package(p) => {
            let e = osv::enrich_package(p, ctx).await;
            let pivots = e.pivots.clone();
            Report {
                query: query.into(),
                verdict: None,
                kind: obs.kind().into(),
                ip: None,
                enrichments: vec![e],
                pivots,
            }
        }
    }
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

// TTL par source.
const TTL_RDNS: Duration = Duration::from_secs(3_600);
const TTL_RDAP: Duration = Duration::from_secs(86_400);
const TTL_SHODAN: Duration = Duration::from_secs(21_600);
const TTL_GREYNOISE: Duration = Duration::from_secs(3_600);
const TTL_DNS: Duration = Duration::from_secs(3_600);
const TTL_GEO: Duration = Duration::from_secs(86_400);
const TTL_CVE: Duration = Duration::from_secs(86_400);
const TTL_THREAT: Duration = Duration::from_secs(3_600);
const TTL_HASH: Duration = Duration::from_secs(86_400);
const TTL_PAID: Duration = Duration::from_secs(21_600);
const TTL_CENSYS: Duration = Duration::from_secs(604_800); // 7 j — quota Censys free 100/mois

/// Enrichers IP à clé (payants), séquentiels (cache dès le 1er appel).
/// Étendu au fil des ajouts (VirusTotal, AbuseIPDB, IPinfo, IPQS, CriminalIP, Censys…).
async fn paid_ip_enrichers(ip: IpAddr, ctx: &Ctx) -> Vec<Enrichment> {
    // Fan-out parallèle : tous les enrichers payants dont la clé est présente
    // partent en même temps (bornés par les sémaphores dans `get_or`) au lieu
    // de s'exécuter en série. `join_all` préserve l'ordre d'insertion.
    let ip_str = ip.to_string();
    let mut futs: Vec<BoxedEnricher> = Vec::new();
    gated!(
        futs,
        ctx,
        "SHODAN_API_KEY",
        format!("shodan:{ip}"),
        TTL_SHODAN,
        shodan::enrich_ip(ip, ctx)
    );
    gated_v4!(
        futs,
        ctx,
        ip,
        "GREYNOISE_API_KEY",
        format!("greynoise:{ip}"),
        TTL_GREYNOISE,
        greynoise::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "VIRUSTOTAL_API_KEY",
        format!("vt_ip:{ip}"),
        TTL_PAID,
        virustotal::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "ABUSEIPDB_API_KEY",
        format!("abuseipdb:{ip}"),
        TTL_THREAT,
        abuseipdb::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "IPINFO_TOKEN",
        format!("ipinfo:{ip}"),
        TTL_GEO,
        ipinfo::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "IPQUALITYSCORE_API_KEY",
        format!("ipqs:{ip}"),
        TTL_PAID,
        ipqs::enrich_ip(ip, ctx)
    );
    gated_v4!(
        futs,
        ctx,
        ip,
        "CRIMINALIP_API_KEY",
        format!("criminalip:{ip}"),
        TTL_PAID,
        criminalip::enrich_ip(ip, ctx)
    );
    if ctx.key("ABUSE_CH_API_KEY").is_some() {
        futs.push(Box::pin(ctx.cache.get_or(
            format!("tf_ip:{ip}"),
            TTL_THREAT,
            threatfox::enrich_ip(ip, ctx),
        )) as BoxedEnricher);
        futs.push(Box::pin(ctx.cache.get_or(
            format!("uh_host:{ip}"),
            TTL_THREAT,
            urlhaus::enrich_host(&ip_str, ctx),
        )) as BoxedEnricher);
    }
    if ctx.key("SCAMALYTICS_API_KEY").is_some() && ctx.key("SCAMALYTICS_API_USER").is_some() {
        futs.push(Box::pin(ctx.cache.get_or(
            format!("scamalytics:{ip}"),
            TTL_PAID,
            scamalytics::enrich_ip(ip, ctx),
        )) as BoxedEnricher);
    }
    gated!(
        futs,
        ctx,
        "IPDATA_API_KEY",
        format!("ipdata:{ip}"),
        TTL_GEO,
        ipdata::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "PROXYCHECK_API_KEY",
        format!("proxycheck:{ip}"),
        TTL_GEO,
        proxycheck::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "VPNAPI_KEY",
        format!("vpnapi:{ip}"),
        TTL_GEO,
        vpnapi::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "OTX_API_KEY",
        format!("otx:{ip}"),
        TTL_THREAT,
        otx::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "CENSYS_API_KEY",
        format!("censys:{ip}"),
        TTL_CENSYS,
        censys::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "LEAKIX_API_KEY",
        format!("leakix:{ip}"),
        TTL_THREAT,
        leakix::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "URLSCAN_API_KEY",
        format!("urlscan_ip:{ip}"),
        TTL_RDAP,
        urlscan::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "METADEFENDER_API_KEY",
        format!("mdc_ip:{ip}"),
        TTL_THREAT,
        metadefender::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "IKNOWWHATYOUDOWNLOAD_API_KEY",
        format!("ikwyd:{ip}"),
        TTL_RDAP,
        ikwyd::enrich_ip(ip, ctx)
    );
    gated_v4!(
        futs,
        ctx,
        ip,
        "NETLAS_API_KEY",
        format!("netlas:{ip}"),
        TTL_PAID,
        netlas::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "FOFA_KEY",
        format!("fofa:{ip}"),
        TTL_PAID,
        fofa::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "ZOOMEYE_API_KEY",
        format!("zoomeye:{ip}"),
        TTL_PAID,
        zoomeye::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "QUAKE_API_KEY",
        format!("quake:{ip}"),
        TTL_PAID,
        quake::enrich_ip(ip, ctx)
    );
    gated_v4!(
        futs,
        ctx,
        ip,
        "KASPERSKY_OPENTIP_KEY",
        format!("opentip:{ip}"),
        TTL_THREAT,
        opentip::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "MALTIVERSE_API_KEY",
        format!("maltiverse:ip:{ip}"),
        TTL_THREAT,
        maltiverse::enrich_ip(ip, ctx)
    );
    gated!(
        futs,
        ctx,
        "PULSEDIVE_API_KEY",
        format!("pulsedive:{ip}"),
        TTL_THREAT,
        pulsedive::enrich_ip(ip, ctx)
    );
    futures::future::join_all(futs).await
}

/// Noms d'env des enrichers IP à clé (pour le badge "gated").
const PAID_IP_KEYS: &[&str] = &[
    "SHODAN_API_KEY",
    "GREYNOISE_API_KEY",
    "VIRUSTOTAL_API_KEY",
    "ABUSEIPDB_API_KEY",
    "IPINFO_TOKEN",
    "IPQUALITYSCORE_API_KEY",
    "CRIMINALIP_API_KEY",
    "ABUSE_CH_API_KEY",
    "SCAMALYTICS_API_KEY",
    "IPDATA_API_KEY",
    "PROXYCHECK_API_KEY",
    "VPNAPI_KEY",
    "OTX_API_KEY",
    "CENSYS_API_KEY",
    "LEAKIX_API_KEY",
    "URLSCAN_API_KEY",
    "METADEFENDER_API_KEY",
    "IKNOWWHATYOUDOWNLOAD_API_KEY",
    "NETLAS_API_KEY",
    "FOFA_KEY",
    "ZOOMEYE_API_KEY",
    "QUAKE_API_KEY",
    "KASPERSKY_OPENTIP_KEY",
    "MALTIVERSE_API_KEY",
    "PULSEDIVE_API_KEY",
];

fn has_paid_ip_key(ctx: &Ctx) -> bool {
    PAID_IP_KEYS.iter().any(|k| ctx.key(k).is_some())
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
    }
}
