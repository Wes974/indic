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
use serde_json::json;

use crate::enrich::{self, Ctx};
use crate::observable::Observable;
use crate::push;

/// Contexte partagé (datasets hot-swappables + client HTTP).
pub type SharedCtx = Arc<Ctx>;

const INDEX_HTML: &str = include_str!("web/index.html");

pub fn router(ctx: SharedCtx) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics))
        .route("/settings", get(settings))
        .route("/lookup", get(lookup_q))
        .route("/push", post(push_obs))
        // Alias historiques (compat).
        .route("/v1/check", get(check_query))
        .route("/ip/{addr}", get(check_path))
        .with_state(ctx)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn healthz() -> &'static str {
    "ok"
}

/// `GET /metrics` — compteurs par source (ok/err/cache-hit/latence moyenne). Gated.
async fn metrics(State(ctx): State<SharedCtx>, headers: HeaderMap) -> Response {
    if !authorized(&ctx, &headers, None) {
        return (
            StatusCode::FORBIDDEN,
            Json(json!({ "error": "non autorisé" })),
        )
            .into_response();
    }
    Json(ctx.cache.metrics()).into_response()
}

#[derive(Deserialize)]
struct LookupQ {
    q: Option<String>,
    ip: Option<String>,
    token: Option<String>,
}

#[derive(Deserialize)]
struct TokenQ {
    token: Option<String>,
}

/// `GET /settings` — statut de configuration pour la page réglages : présence
/// **booléenne** de chaque clé connue (jamais la valeur), état du token, version
/// des feeds. Gated (mêmes règles que /metrics) — ne révèle aucun secret.
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

/// `GET /lookup?q=…` — accepte n'importe quel observable ; sans `q`/`ip`,
/// tente l'IP du client (header CF/proxy).
async fn lookup_q(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Query(p): Query<LookupQ>,
) -> Response {
    let auth = authorized(&ctx, &headers, p.token.as_deref());
    match p.q.or(p.ip).or_else(|| client_ip(&headers)) {
        Some(raw) => dispatch(&ctx, &raw, auth).await,
        None => bad_request("paramètre `q` manquant et IP client indéterminée"),
    }
}

#[derive(Deserialize)]
struct CheckQ {
    ip: Option<String>,
    token: Option<String>,
}

async fn check_query(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Query(q): Query<CheckQ>,
) -> Response {
    let auth = authorized(&ctx, &headers, q.token.as_deref());
    match q.ip.or_else(|| client_ip(&headers)) {
        Some(ip) => dispatch(&ctx, &ip, auth).await,
        None => bad_request("paramètre `ip` manquant et IP client indéterminée"),
    }
}

async fn check_path(
    State(ctx): State<SharedCtx>,
    headers: HeaderMap,
    Path(addr): Path<String>,
) -> Response {
    let auth = authorized(&ctx, &headers, None);
    dispatch(&ctx, &addr, auth).await
}

async fn dispatch(ctx: &Ctx, raw: &str, auth: bool) -> Response {
    match Observable::detect(raw) {
        Some(obs) => Json(enrich::run(raw, &obs, ctx, auth).await).into_response(),
        None => bad_request(&format!("observable non reconnu : {raw}")),
    }
}

/// `POST /push?q=…` — enrichit l'observable puis pousse le résultat vers MISP /
/// OpenCTI si un signal de menace est présent. Gated : écrit dans les plateformes.
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

/// Autorise les enrichers payants. Aucun token configuré = ouvert (dev).
fn authorized(ctx: &Ctx, headers: &HeaderMap, query_token: Option<&str>) -> bool {
    let Some(expected) = &ctx.token else {
        // Aucun token configuré : fail-closed si des clés payantes existent
        // (sinon un INDIC_TOKEN oublié exposerait tes quotas au public).
        return !ctx.has_paid_key();
    };
    let provided = query_token
        .or_else(|| headers.get("x-indic-token").and_then(|v| v.to_str().ok()))
        .or_else(|| cookie_value(headers, "indic_token"));
    provided == Some(expected.as_str())
}

/// Extrait la valeur d'un cookie par nom.
fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let cookies = headers.get("cookie")?.to_str().ok()?;
    cookies
        .split(';')
        .find_map(|kv| kv.trim().strip_prefix(name)?.strip_prefix('='))
}

fn bad_request(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": msg }))).into_response()
}

/// IP réelle du client derrière le tunnel Cloudflare / un reverse-proxy.
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
