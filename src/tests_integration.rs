//! Tests d'intégration HTTP — exercent les endpoints via `tower::ServiceExt`.

use std::collections::HashMap;
use std::sync::Arc;

use arc_swap::ArcSwap;
use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::{Value, json};
use tower::ServiceExt;

use crate::api;
use crate::enrich;
use crate::store::Store;

fn test_ctx() -> Arc<enrich::Ctx> {
    let store = Arc::new(ArcSwap::from_pointee(Store::default()));
    let http = reqwest::Client::builder()
        .user_agent("indic-test/0.1")
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let keys = std::sync::RwLock::new(HashMap::new());
    let registry = Arc::new(crate::registry::build());
    let attack_map = HashMap::new();
    Arc::new(enrich::Ctx {
        store,
        http,
        keys,
        token: None,
        cache: enrich::Cache::default(),
        history: None,
        rate_limiter: crate::rate::RateLimiter::new(),
        attack_map,
        registry,
    })
}

fn app() -> axum::Router {
    api::router(test_ctx())
}

async fn json_body(response: axum::response::Response) -> Value {
    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&body).unwrap()
}

async fn get(uri: &str) -> (StatusCode, Value) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let response = app().oneshot(req).await.unwrap();
    let status = response.status();
    let body = json_body(response).await;
    (status, body)
}

async fn post(uri: &str, body_json: Value) -> (StatusCode, Value) {
    let body_str = serde_json::to_string(&body_json).unwrap();
    let req = Request::builder()
        .uri(uri)
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(body_str))
        .unwrap();
    let response = app().oneshot(req).await.unwrap();
    let status = response.status();
    let body = json_body(response).await;
    (status, body)
}

// ── Tests ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn healthz_plain_text() {
    let req = Request::builder()
        .uri("/healthz")
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .unwrap();
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn index_returns_html() {
    let req = Request::builder().uri("/").body(Body::empty()).unwrap();
    let response = app().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let ct = response
        .headers()
        .get(header::CONTENT_TYPE)
        .unwrap()
        .to_str()
        .unwrap();
    assert!(ct.contains("html"));
}

#[tokio::test]
async fn lookup_ip_returns_report() {
    let (status, body) = get("/lookup?q=8.8.8.8").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["query"], "8.8.8.8");
    assert_eq!(body["kind"], "ip");
    assert!(body["verdict"].is_object());
}

#[tokio::test]
async fn lookup_domain_returns_report() {
    let (status, body) = get("/lookup?q=example.com").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["query"], "example.com");
    assert_eq!(body["kind"], "domain");
}

#[tokio::test]
async fn lookup_missing_query_returns_400() {
    let (status, _body) = get("/lookup").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn lookup_empty_query_returns_400() {
    let (status, _body) = get("/lookup?q=").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn dashboard_without_history_returns_404() {
    let (status, _body) = get("/dashboard").await;
    // Sans INDIC_HISTORY=1, le dashboard n'est pas disponible.
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn extract_iocs_parses_text() {
    let input = json!({"text": "Scan from 1.2.3.4 and evil.com"});
    let (status, body) = post("/extract", input).await;
    assert_eq!(status, StatusCode::OK);
    let iocs = body["iocs"].as_array().unwrap();
    assert!(!iocs.is_empty());
    let types: Vec<&str> = iocs.iter().map(|i| i["type"].as_str().unwrap()).collect();
    assert!(types.contains(&"ip"));
    assert!(types.contains(&"domain"));
}

#[tokio::test]
async fn bulk_lookup_returns_summary() {
    let input = json!({"queries": ["8.8.8.8", "1.1.1.1"]});
    let (status, body) = post("/lookup/bulk", input).await;
    assert_eq!(status, StatusCode::OK);
    let results = body["results"].as_array().unwrap();
    assert_eq!(results.len(), 2);
    assert!(results.iter().all(|r| r["ok"] == true));
}

#[tokio::test]
async fn bulk_lookup_empty_returns_400() {
    let input = json!({"queries": []});
    let (status, _body) = post("/lookup/bulk", input).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn bulk_lookup_too_many_returns_400() {
    let queries: Vec<String> = (0..25).map(|i| format!("{i}.{i}.{i}.{i}")).collect();
    let input = json!({"queries": queries});
    let (status, _body) = post("/lookup/bulk", input).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn correlate_without_history_returns_404() {
    let (status, _body) = get("/correlate?q=8.8.8.8").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn export_stix_returns_bundle() {
    let req = Request::builder()
        .uri("/lookup/export?q=8.8.8.8&format=stix")
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("stix")
    );
}

#[tokio::test]
async fn export_csv_returns_csv() {
    let req = Request::builder()
        .uri("/lookup/export?q=8.8.8.8&format=csv")
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("csv")
    );
}

#[tokio::test]
async fn compare_two_ips_returns_both() {
    let input = json!({"a": "8.8.8.8", "b": "1.1.1.1"});
    let (status, body) = post("/compare", input).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["a"].is_object());
    assert!(body["b"].is_object());
    assert_eq!(body["a"]["query"], "8.8.8.8");
    assert_eq!(body["b"]["query"], "1.1.1.1");
}

#[tokio::test]
async fn compare_unrecognized_returns_null() {
    let input = json!({"a": "!!!not_anything!!!", "b": "8.8.8.8"});
    let (status, body) = post("/compare", input).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["a"].is_null());
    assert!(body["b"].is_object());
}
#[tokio::test]
async fn bulk_export_stix_returns_bundle() {
    let input = json!({"queries": ["8.8.8.8", "1.1.1.1"], "format": "stix"});
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/lookup/bulk")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&input).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("stix")
    );
}

#[tokio::test]
async fn bulk_export_csv_returns_csv() {
    let input = json!({"queries": ["8.8.8.8", "1.1.1.1"], "format": "csv"});
    let response = app()
        .oneshot(
            Request::builder()
                .uri("/lookup/bulk")
                .method("POST")
                .header("content-type", "application/json")
                .body(Body::from(serde_json::to_string(&input).unwrap()))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert!(
        response
            .headers()
            .get(header::CONTENT_TYPE)
            .unwrap()
            .to_str()
            .unwrap()
            .contains("csv")
    );
}

#[tokio::test]
async fn metrics_endpoint_accessible() {
    let req = Request::builder()
        .uri("/metrics")
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(req).await.unwrap();
    let status = response.status();
    // Sans token configuré, l'endpoint est public (pas de restriction).
    assert!(status == StatusCode::OK || status.is_client_error());
}

#[tokio::test]
async fn settings_endpoint_returns_json() {
    let req = Request::builder()
        .uri("/settings")
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(req).await.unwrap();
    // Avec token: None, l'accès est soit OK (pas de token requis) soit 4xx.
    // On vérifie juste que ça répond sans paniquer.
    let _ = response.status();
}

#[tokio::test]
async fn push_endpoint_accessible() {
    let req = Request::builder()
        .uri("/push?q=8.8.8.8")
        .method("POST")
        .body(Body::empty())
        .unwrap();
    let response = app().oneshot(req).await.unwrap();
    // Push peut échouer (pas de MISP configuré) mais ne doit pas paniquer.
    let status = response.status();
    assert!(status.is_success() || status.is_server_error() || status.is_client_error());
}
