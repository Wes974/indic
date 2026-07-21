//! API HTTP (axum) + service du front. `/lookup?q=` détecte le type et enrichit.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::enrich::{self, Ctx, Report};
use crate::observable::Observable;
use crate::push;

/// Contexte partagé (datasets hot-swappables + client HTTP).
pub type SharedCtx = Arc<Ctx>;

const INDEX_HTML: &str = include_str!(concat!(env!("OUT_DIR"), "/index.html"));

pub fn router(ctx: SharedCtx) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/settings", get(settings))
        .route("/lookup", get(lookup_q))
        .route("/lookup/bulk", post(lookup_bulk))
        .route("/lookup/export", get(lookup_export))
        .route("/push", post(push_obs))
        .route("/sw.js", get(service_worker))
        .route("/history", get(history_recent))
        .route("/dashboard", get(dashboard))
        .route("/extract", post(extract_iocs))
        .route("/correlate", get(correlate_q))
        .route("/compare", post(compare))
        // ── API v2 ────────────────────────────────────────────────────────
        .route("/v2/lookup", get(lookup_q))
        .route("/v2/lookup/bulk", post(lookup_bulk))
        .route("/v2/lookup/export", get(lookup_export))
        .route("/v2/compare", post(compare))
        .route("/v2/correlate", get(correlate_q))
        .route("/v2/extract", post(extract_iocs))
        .route("/v2/push", post(push_obs))
        .route("/v2/history", get(history_recent))
        .route("/v2/dashboard", get(dashboard))
        .route("/v2/metrics", get(metrics))
        .route("/v2/settings", get(settings))
        // ── Debug ──────────────────────────────────────────────────────────
        .route("/chaos", get(chaos_test))
        // ── Assets statiques ──────────────────────────────────────────────
        .nest_service("/assets", tower_http::services::ServeDir::new("assets"))
        // Alias historiques (compat).
        .route("/v1/check", get(check_query))
        .route("/ip/{addr}", get(check_path))
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers(tower_http::cors::Any),
        )
        .layer(tower_http::compression::CompressionLayer::new())
        .layer(axum::middleware::from_fn(security_headers))
        .layer(tower_http::limit::RequestBodyLimitLayer::new(1024 * 1024))
        .with_state(ctx)
}

/// Ajoute les en-têtes de sécurité sur toutes les réponses HTML.
async fn security_headers(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    let mut response = next.run(request).await;
    let headers = response.headers_mut();
    headers.insert(
        axum::http::header::CONTENT_SECURITY_POLICY,
        axum::http::HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        ),
    );
    headers.insert(
        axum::http::HeaderName::from_static("x-content-type-options"),
        axum::http::HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        axum::http::HeaderName::from_static("referrer-policy"),
        axum::http::HeaderValue::from_static("strict-origin-when-cross-origin"),
    );
    response
}

async fn index() -> impl IntoResponse {
    (
        [(
            axum::http::header::CACHE_CONTROL,
            "no-cache, no-store, must-revalidate",
        )],
        Html(INDEX_HTML),
    )
}

async fn healthz() -> &'static str {
    "ok"
}

/// Service worker PWA : network-first avec repli sur le cache, **et uniquement
/// pour la coquille HTML**. Les réponses d'API ne sont jamais mises en cache —
/// elles laisseraient sur le disque du visiteur la trace de chaque observable
/// analysé, sans borne de taille ni expiration.
///
/// La mise à jour repose sur `skipWaiting` + `clients.claim` + le versionnage
/// de `CACHE` : bumper la version purge les caches précédents à l'activation.
///
/// `Cache-Control: no-cache` est indispensable : sans en-tête explicite,
/// Cloudflare applique son TTL par défaut aux `.js` (4 h) et continue de servir
/// l'ancien worker longtemps après un déploiement — un correctif de SW resterait
/// invisible en prod.
async fn service_worker() -> (
    StatusCode,
    [(axum::http::header::HeaderName, &'static str); 2],
    &'static str,
) {
    // v3 : purge les caches v1/v2, qui contenaient les réponses /lookup.
    let sw = r#"const CACHE = 'indic-v3';
self.addEventListener('install', (e) => e.waitUntil(self.skipWaiting()));
self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((ks) => Promise.all(ks.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});
self.addEventListener('fetch', (e) => {
  // Tout ce qui n'est pas une navigation (donc /lookup, /compare, /extract,
  // /dashboard…) passe au réseau sans jamais être stocké.
  if (e.request.mode !== 'navigate') return;
  e.respondWith(
    fetch(e.request)
      .then((r) => {
        const copy = r.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy)).catch(() => {});
        return r;
      })
      .catch(() => caches.match(e.request).then((r) => r || Response.error()))
  );
});
"#;
    (
        StatusCode::OK,
        [
            (axum::http::header::CONTENT_TYPE, "application/javascript"),
            (axum::http::header::CACHE_CONTROL, "no-cache"),
        ],
        sw,
    )
}

/// `GET /metrics` — compteurs par source. Format par défaut JSON, `?format=prometheus`
/// pour exposition Prometheus (scrapable). Gated.
async fn metrics(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let token = params.get("token").map(|s| s.as_str());
    if !authorized(&ctx, &headers, token) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "non autorisé — utiliser ?token= ou le header x-indic-token" })),
        )
            .into_response();
    }
    let fmt = params.get("format").map(|s| s.as_str()).unwrap_or("json");
    if fmt == "prometheus" {
        prometheus_metrics(&ctx).into_response()
    } else {
        Json(ctx.cache.metrics()).into_response()
    }
}

/// Génère les métriques au format exposition Prometheus.
fn prometheus_metrics(ctx: &Ctx) -> String {
    let mut out = String::new();
    let metrics = ctx.cache.metrics();
    for m in &metrics {
        out.push_str(&format!(
            "indic_source_ok{{source=\"{}\"}} {}\n",
            m.source, m.ok
        ));
        out.push_str(&format!(
            "indic_source_err{{source=\"{}\"}} {}\n",
            m.source, m.err
        ));
        out.push_str(&format!(
            "indic_source_cache_hit{{source=\"{}\"}} {}\n",
            m.source, m.cache_hit
        ));
        out.push_str(&format!(
            "indic_source_neg_hit{{source=\"{}\"}} {}\n",
            m.source, m.neg_hit
        ));
        out.push_str(&format!(
            "indic_source_calls{{source=\"{}\"}} {}\n",
            m.source, m.calls
        ));
        out.push_str(&format!(
            "indic_source_avg_latency_ms{{source=\"{}\"}} {}\n",
            m.source, m.avg_latency_ms
        ));
    }
    out.push_str(&format!("indic_cache_size {}\n", metrics.len()));
    out
}

#[derive(Deserialize)]
struct LookupQ {
    q: Option<String>,
    ip: Option<String>,
    token: Option<String>,
    /// Format d'export : `stix` ou `csv` (uniquement sur /lookup/export).
    format: Option<String>,
}

#[derive(Deserialize)]
struct BulkQ {
    queries: Vec<String>,
    token: Option<String>,
    /// `stix` ou `csv` — si présent, exporte tous les résultats au lieu de JSON.
    format: Option<String>,
}

#[derive(Deserialize)]
struct CompareQ {
    /// Forme N-aire (comparateur web : le sujet + jusqu'à 2 autres observables).
    #[serde(default)]
    items: Vec<String>,
    /// Forme historique à deux — toujours acceptée.
    #[serde(default)]
    a: Option<String>,
    #[serde(default)]
    b: Option<String>,
    token: Option<String>,
}

#[derive(Deserialize)]
struct TokenQ {
    token: Option<String>,
}

#[derive(Deserialize)]
struct HistoryQ {
    token: Option<String>,
    limit: Option<u32>,
    kind: Option<String>,
    verdict: Option<String>,
}

#[derive(Deserialize)]
struct CorrelateQ {
    q: Option<String>,
    token: Option<String>,
}

/// `GET /settings` — statut de config (présence booléenne de chaque clé). Gated.
async fn settings(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Query(q): Query<TokenQ>,
) -> Response {
    if !authorized(&ctx, &headers, q.token.as_deref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "non autorisé" })),
        )
            .into_response();
    }
    let keys: serde_json::Map<String, serde_json::Value> = crate::KNOWN_KEYS
        .iter()
        .map(|k| (k.to_string(), json!(ctx.key(k).is_some())))
        .collect();
    let configured = keys.values().filter(|v| v.as_bool() == Some(true)).count();
    Json(json!({
        "token_required": ctx.token.is_some(),
        "keys_total": crate::KNOWN_KEYS.len(),
        "keys_configured": configured,
        "feed_version": crate::feeds::FEED_VERSION,
        "keys": keys,
    }))
    .into_response()
}

/// `GET /lookup?q=…` — enrichit un observable (avec rate limiting).
async fn lookup_q(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Query(p): Query<LookupQ>,
) -> Response {
    let ip = client_ip(&headers).unwrap_or_else(|| "unknown".into());
    if !ctx.rate_limiter.allow(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "trop de requêtes — réessaie dans une minute" })),
        )
            .into_response();
    }
    let auth = authorized(&ctx, &headers, p.token.as_deref());
    match p.q.or(p.ip).or_else(|| client_ip(&headers)) {
        Some(raw) => dispatch_and_record(&ctx, &raw, auth).await,
        None => bad_request("paramètre `q` manquant et IP client indéterminée"),
    }
}

/// `GET /lookup/export?q=…&format=stix|csv` — enrichit + exporte au format demandé.
async fn lookup_export(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Query(p): Query<LookupQ>,
) -> Response {
    let auth = authorized(&ctx, &headers, p.token.as_deref());
    let Some(raw) = p.q.or(p.ip).or_else(|| client_ip(&headers)) else {
        return bad_request("paramètre `q` manquant");
    };
    let Some(obs) = Observable::detect(&raw) else {
        return bad_request(&format!("observable non reconnu : {raw}"));
    };
    let report = enrich::run(&raw, &obs, &ctx, auth).await;
    record_lookup(&ctx, &report);

    match p.format.as_deref() {
        Some("stix") | Some("stix21") => {
            let bundle = crate::stix::to_stix21(&report);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/stix+json")],
                Json(bundle),
            )
                .into_response()
        }
        Some("csv") => {
            let csv = crate::stix::to_csv(&report);
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/csv")],
                csv,
            )
                .into_response()
        }
        _ => bad_request("format inconnu — utiliser `stix` ou `csv`"),
    }
}

/// `POST /lookup/bulk` — enrichit jusqu'à 20 observables en parallèle.
/// Body JSON : `{"queries": [...], "token": "...", "format": "stix|csv"}`.
/// Sans `format` → résumé JSON. Avec → export STIX 2.1 ou CSV agrégé.
async fn lookup_bulk(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Json(body): Json<BulkQ>,
) -> Response {
    let auth = authorized(&ctx, &headers, body.token.as_deref());
    if body.queries.is_empty() {
        return bad_request("liste `queries` vide");
    }
    if body.queries.len() > 20 {
        return bad_request("maximum 20 observables par lot");
    }
    let futs: Vec<_> = body
        .queries
        .iter()
        .map(|q| {
            let obs = Observable::detect(q);
            let raw = q.clone();
            let ctx = ctx.clone();
            async move {
                match obs {
                    Some(o) => {
                        let r = enrich::run(&raw, &o, &ctx, auth).await;
                        (raw, Some(r))
                    }
                    None => (raw, None),
                }
            }
        })
        .collect();
    let results: Vec<_> = futures::future::join_all(futs).await;

    match body.format.as_deref() {
        Some("stix") | Some("stix21") => {
            let bundles: Vec<_> = results
                .iter()
                .filter_map(|(_, r)| r.as_ref())
                .map(crate::stix::to_stix21)
                .collect();
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "application/stix+json")],
                Json(json!({ "type": "bundle", "objects": bundles.into_iter().flat_map(|b| b["objects"].as_array().cloned().unwrap_or_default()).collect::<Vec<_>>() })),
            )
                .into_response()
        }
        Some("csv") => {
            let csvs: Vec<String> = results
                .iter()
                .filter_map(|(_, r)| r.as_ref())
                .map(crate::stix::to_csv)
                .collect();
            // Garder l'en-tête du premier CSV, enlever les suivants.
            let header_end = csvs
                .first()
                .map_or(0, |c| c.find('\n').map_or(c.len(), |i| i + 1));
            let body: String = csvs
                .iter()
                .enumerate()
                .map(|(i, c)| if i == 0 { c.as_str() } else { &c[header_end..] })
                .collect();
            (
                StatusCode::OK,
                [(axum::http::header::CONTENT_TYPE, "text/csv")],
                body,
            )
                .into_response()
        }
        _ => {
            let summary: Vec<_> = results
                .into_iter()
                .map(|(raw, r)| match r {
                    Some(r) => {
                        json!({ "query": raw, "kind": r.kind, "verdict": r.verdict, "ok": true })
                    }
                    None => json!({ "query": raw, "error": "observable non reconnu", "ok": false }),
                })
                .collect();
            Json(json!({ "results": summary })).into_response()
        }
    }
}

/// `GET /history?limit=50` — N derniers lookups (opt-in, gated).
async fn history_recent(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Query(q): Query<HistoryQ>,
) -> Response {
    if !authorized(&ctx, &headers, q.token.as_deref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "non autorisé" })),
        )
            .into_response();
    }
    let Some(ref h) = ctx.history else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "historique non activé (INDIC_HISTORY=1)" })),
        )
            .into_response();
    };
    let limit = q.limit.unwrap_or(50).min(200);
    let mut entries = h.recent(limit * 2); // overfetch for filtering
    // Filtres optionnels
    if let Some(ref k) = q.kind {
        entries.retain(|e| e.kind == *k);
    }
    if let Some(ref v) = q.verdict {
        entries.retain(|e| e.verdict_label.as_deref() == Some(v.as_str()));
    }
    entries.truncate(limit as usize);
    Json(entries).into_response()
}

/// `GET /dashboard` — stats agrégées : public (anonymisé) ou gated (détaillé).
async fn dashboard(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Query(q): Query<TokenQ>,
) -> Response {
    let Some(ref h) = ctx.history else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "historique non activé (INDIC_HISTORY=1)" })),
        )
            .into_response();
    };
    let gated = authorized(&ctx, &headers, q.token.as_deref());
    // Stats publiques (anonymisées) : toujours dispo.
    let recent = h.recent(100);
    let total = recent.len() as u64;
    let by_kind: std::collections::HashMap<String, u64> =
        recent
            .iter()
            .fold(std::collections::HashMap::new(), |mut acc, e| {
                *acc.entry(e.kind.clone()).or_default() += 1;
                acc
            });
    let malicious = recent
        .iter()
        .filter(|e| e.verdict_label.as_deref() == Some("malicious"))
        .count() as u64;
    let suspect = recent
        .iter()
        .filter(|e| e.verdict_label.as_deref() == Some("suspect"))
        .count() as u64;
    let clean = recent
        .iter()
        .filter(|e| e.verdict_label.as_deref() == Some("clean"))
        .count() as u64;
    let mut base = json!({
        "total_lookups": total,
        "by_kind": by_kind,
        "verdicts": { "malicious": malicious, "suspect": suspect, "clean": clean },
    });
    // Détails gated : derniers lookups avec query.
    if gated && let Some(obj) = base.as_object_mut() {
        obj.insert(
            "recent".into(),
            json!(recent.iter().take(20).collect::<Vec<_>>()),
        );
    }
    Json(base).into_response()
}

/// `POST /extract` — extrait les IOC d'un texte (IP, domaines, hashes, CVE, URLs, emails).
#[derive(Deserialize)]
struct ExtractQ {
    text: String,
}
async fn extract_iocs(Json(body): Json<ExtractQ>) -> Response {
    use crate::observable::Observable;
    let mut iocs: Vec<serde_json::Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    // Découper le texte en tokens par whitespace/punctuation
    for token in body.text.split(|c: char| {
        !c.is_alphanumeric() && c != '.' && c != '-' && c != '_' && c != '@' && c != ':' && c != '/'
    }) {
        let token = token
            .trim()
            .trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
        if token.is_empty() || token.len() > 300 {
            continue;
        }
        // Exclure les numéros de version, dates, etc.
        if token.chars().all(|c| c.is_ascii_digit() || c == '.') && token.matches('.').count() <= 1
        {
            continue;
        }
        if let Some(obs) = Observable::detect(token) {
            let v = token.to_lowercase();
            if seen.insert(v.clone()) {
                match obs {
                    Observable::Ip(_) => iocs.push(json!({"type": "ip", "value": v})),
                    Observable::Cidr(_) => iocs.push(json!({"type": "ip", "value": v})),
                    Observable::Domain(_) => iocs.push(json!({"type": "domain", "value": v})),
                    Observable::Url(_) => {
                        iocs.push(json!({"type": "url", "value": token.to_string()}))
                    }
                    Observable::Hash(_) => iocs.push(json!({"type": "hash", "value": v})),
                    Observable::Cve(_) => {
                        iocs.push(json!({"type": "cve", "value": token.to_uppercase()}))
                    }
                    Observable::Email(_) => iocs.push(json!({"type": "email", "value": v})),
                    _ => {}
                }
            }
        }
    }
    iocs.truncate(50);
    Json(json!({"iocs": iocs, "count": iocs.len()})).into_response()
}

/// `GET /correlate?q=1.2.3.4` — cherche des corrélations dans l'historique.
async fn correlate_q(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Query(q): Query<CorrelateQ>,
) -> Response {
    if !authorized(&ctx, &headers, q.token.as_deref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "non autorisé" })),
        )
            .into_response();
    }
    let Some(ref h) = ctx.history else {
        return (
            StatusCode::NOT_FOUND,
            Json(json!({ "error": "historique non activé (INDIC_HISTORY=1)" })),
        )
            .into_response();
    };
    let Some(raw) = q.q else {
        return bad_request("paramètre `q` manquant");
    };
    let Some(obs) = Observable::detect(&raw) else {
        return bad_request(&format!("observable non reconnu : {raw}"));
    };
    let correlations = crate::correlate::correlate(&raw, obs.kind(), h);
    Json(correlations).into_response()
}

#[derive(Deserialize)]
struct CheckQ {
    ip: Option<String>,
    token: Option<String>,
}

// Rate-limited alias for backward compat
async fn check_query(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Query(q): Query<CheckQ>,
) -> Response {
    let ip = client_ip(&headers).unwrap_or_else(|| "unknown".into());
    if !ctx.rate_limiter.allow(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "trop de requêtes — réessaie dans une minute" })),
        )
            .into_response();
    }
    let auth = authorized(&ctx, &headers, q.token.as_deref());
    match q.ip.or_else(|| client_ip(&headers)) {
        Some(addr) => dispatch_and_record(&ctx, &addr, auth).await,
        None => bad_request("paramètre `ip` manquant et IP client indéterminée"),
    }
}

async fn check_path(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Path(addr): Path<String>,
) -> Response {
    let ip = client_ip(&headers).unwrap_or_else(|| "unknown".into());
    if !ctx.rate_limiter.allow(&ip) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({ "error": "trop de requêtes — réessaie dans une minute" })),
        )
            .into_response();
    }
    let auth = authorized(&ctx, &headers, None);
    dispatch_and_record(&ctx, &addr, auth).await
}

async fn dispatch_and_record(ctx: &Ctx, raw: &str, auth: bool) -> Response {
    match Observable::detect(raw) {
        Some(obs) => {
            let report = enrich::run(raw, &obs, ctx, auth).await;
            record_lookup(ctx, &report);
            // Ajouter les corrélations si l'historique est activé
            let mut resp = json!(report);
            if let Some(ref h) = ctx.history {
                let correlations = crate::correlate::correlate(raw, obs.kind(), h);
                if !correlations.is_empty()
                    && let Some(obj) = resp.as_object_mut()
                {
                    obj.insert("correlations".into(), json!(correlations));
                }
            }
            // Ajouter le mapping ATT&CK pour les CVE
            if let Observable::Cve(_) = obs {
                // Récupérer les CWEs depuis l'enrichment cvedb
                let cwes: Vec<String> = report
                    .enrichments
                    .iter()
                    .filter(|e| e.source == "cvedb")
                    .flat_map(|e| e.facts.iter())
                    .filter(|f| f.key == "cwes")
                    .flat_map(|f| f.value.split(", ").map(String::from))
                    .collect();
                if !cwes.is_empty() {
                    let attack_signals = crate::attack::attack_signals(&cwes, &ctx.attack_map);
                    if !attack_signals.is_empty()
                        && let Some(obj) = resp.as_object_mut()
                    {
                        obj.insert("mitre_attack".into(), json!(attack_signals));
                    }
                }
            }
            Json(resp).into_response()
        }
        None => bad_request(&format!("observable non reconnu : {raw}")),
    }
}

/// Enregistre un lookup dans l'historique SQLite si activé.
fn record_lookup(ctx: &Ctx, report: &Report) {
    if let Some(ref h) = ctx.history {
        let source_count = report.enrichments.len() as u32;
        let signal_count = report
            .enrichments
            .iter()
            .map(|e| e.signals.len() as u32)
            .sum();
        h.record(
            &report.query,
            &report.kind,
            report.verdict.as_ref().map(|v| v.label),
            report.verdict.as_ref().map(|v| v.score),
            source_count,
            signal_count,
        );
    }
}

/// `POST /push?q=…` — enrichit puis pousse vers MISP/OpenCTI. Gated.
async fn push_obs(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Query(p): Query<LookupQ>,
) -> Response {
    if !authorized(&ctx, &headers, p.token.as_deref()) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "non autorisé" })),
        )
            .into_response();
    }
    let Some(raw) = p.q.or(p.ip) else {
        return bad_request("paramètre `q` manquant");
    };
    match Observable::detect(&raw) {
        Some(obs) => {
            let report = enrich::run(&raw, &obs, &ctx, true).await;
            Json(push::push_report(&report, &ctx).await).into_response()
        }
        None => bad_request(&format!("observable non reconnu : {raw}")),
    }
}

/// Autorise les enrichers payants.
fn authorized(ctx: &Ctx, headers: &HeaderMap, query_token: Option<&str>) -> bool {
    let Some(expected) = &ctx.token else {
        return !ctx.has_paid_key();
    };
    let provided = query_token
        .or_else(|| headers.get("x-indic-token").and_then(|v| v.to_str().ok()))
        .or_else(|| cookie_value(headers, "indic_token"));
    provided == Some(expected.as_str())
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookies = headers.get("cookie")?.to_str().ok()?;
    cookies
        .split(';')
        .find_map(|kv| kv.trim().strip_prefix(name)?.strip_prefix('='))
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
}

fn client_ip(headers: &HeaderMap) -> Option<String> {
    for h in ["cf-connecting-ip", "x-forwarded-for", "x-real-ip"] {
        if let Some(val) = headers.get(h).and_then(|v| v.to_str().ok()) {
            let first = val.split(',').next().unwrap_or("").trim();
            if !first.is_empty() {
                return Some(first.to_string());
            }
        }
    }
    None
}

/// Plafond du comparateur : au-delà, les colonnes deviennent illisibles et le
/// coût en appels d'enrichers grimpe linéairement.
const COMPARE_MAX: usize = 3;

/// `POST /compare` — enrichit 2 à 3 observables en parallèle et retourne les
/// rapports complets côte à côte. Accepte `{items:[…]}` (N-aire) ou `{a,b}`.
async fn compare(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Json(body): Json<CompareQ>,
) -> Response {
    let auth = authorized(&ctx, &headers, body.token.as_deref());
    let mut queries: Vec<String> = if body.items.is_empty() {
        [body.a, body.b].into_iter().flatten().collect()
    } else {
        body.items
    };
    queries.retain(|q| !q.trim().is_empty());
    if queries.len() < 2 {
        return bad_request("au moins deux observables sont requis");
    }
    queries.truncate(COMPARE_MAX);

    let reports = futures::future::join_all(queries.iter().map(|q| async {
        match Observable::detect(q) {
            Some(o) => Some(enrich::run(q, &o, &ctx, auth).await),
            None => None,
        }
    }))
    .await;

    let items: Vec<Value> = reports
        .into_iter()
        .map(|r| serde_json::to_value(r).unwrap_or(Value::Null))
        .collect();
    // `a`/`b` restent exposés pour les clients de la forme historique à deux.
    let a = items.first().cloned().unwrap_or(Value::Null);
    let b = items.get(1).cloned().unwrap_or(Value::Null);
    Json(json!({ "items": items, "a": a, "b": b })).into_response()
}

/// `GET /chaos?delay=2000&error=502` — injecte un délai ou une erreur pour
/// tester la robustesse du client et le graceful shutdown.
/// Réservé au développement (pas de token requis).
async fn chaos_test(Query(p): Query<ChaosQ>) -> Response {
    if let Some(ms) = p.delay {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
    if let Some(code) = p.error {
        let status = StatusCode::from_u16(code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return (
            status,
            Json(json!({ "error": format!("chaos: erreur injectée {code}") })),
        )
            .into_response();
    }
    Json(json!({ "chaos": "ok", "delay_ms": p.delay, "error_code": p.error })).into_response()
}

#[derive(Deserialize)]
struct ChaosQ {
    delay: Option<u64>,
    error: Option<u16>,
}
