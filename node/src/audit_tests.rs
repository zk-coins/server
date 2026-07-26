//! Unit tests for the audit-log middleware.
//!
//! The middleware is wired in `router::create_router` as the outermost
//! layer. We don't spin up the full router here — we exercise the two
//! pure helpers directly (`headers_to_json`, `buffer_body`) and then
//! drive the middleware through a minimal axum app so the
//! happy-path / binary-header / body-error branches all reach
//! `db::insert_request_log` and the right JSONB shape lands in
//! `request_log`.

use super::*;
use axum::body::Body;
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use axum::middleware::from_fn_with_state;
use axum::response::IntoResponse;
use axum::routing::post;
use axum::Router;
use tower::ServiceExt;

use crate::publisher::EsploraConfig;
use crate::router::{AppState, ProofStore};
use crate::test_db::{setup_pool, SchemaScope};
use std::sync::{Arc, Mutex};

/// Cover the binary-header branch of `headers_to_json`: a header value
/// that is not valid UTF-8 must land as `{"_binary": "<hex>"}` so the
/// JSONB row stays round-trippable. The happy-path UTF-8 branch is
/// covered by every other test.
#[test]
fn headers_to_json_renders_non_utf8_value_as_binary_hex() {
    let mut headers = axum::http::HeaderMap::new();
    // 0xFF is not valid UTF-8.
    headers.insert(
        HeaderName::from_static("x-binary"),
        HeaderValue::from_bytes(&[0xFFu8, 0xFE]).unwrap(),
    );
    let value = headers_to_json(&headers);
    let obj = value.as_object().expect("headers_to_json returns Object");
    let binary_obj = obj
        .get("x-binary")
        .and_then(|v| v.as_object())
        .expect("non-utf8 header rendered as nested object");
    assert_eq!(
        binary_obj.get("_binary").and_then(|v| v.as_str()),
        Some("fffe")
    );
}

/// Repeated headers (e.g. `Set-Cookie`) collapse into a JSON array.
/// First-occurrence stays as a `String`, subsequent matches promote
/// to `[String, String, …]`.
#[test]
fn headers_to_json_collapses_repeated_keys_into_array() {
    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("a=1"),
    );
    headers.append(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("b=2"),
    );
    let value = headers_to_json(&headers);
    let arr = value
        .as_object()
        .and_then(|o| o.get("set-cookie"))
        .and_then(|v| v.as_array())
        .expect("repeated key rendered as array");
    let values: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(values, vec!["a=1", "b=2"]);
}

/// Three+ repeats exercise the `Some(Value::Array(mut arr)) => arr.push`
/// branch — the second collapse takes the array-grow path, not the
/// `String → Array` promotion path covered above.
#[test]
fn headers_to_json_third_repeat_pushes_into_existing_array() {
    let mut headers = axum::http::HeaderMap::new();
    headers.append(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("a=1"),
    );
    headers.append(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("b=2"),
    );
    headers.append(
        HeaderName::from_static("set-cookie"),
        HeaderValue::from_static("c=3"),
    );
    let value = headers_to_json(&headers);
    let arr = value
        .as_object()
        .and_then(|o| o.get("set-cookie"))
        .and_then(|v| v.as_array())
        .expect("repeated key rendered as array");
    let values: Vec<&str> = arr.iter().filter_map(|v| v.as_str()).collect();
    assert_eq!(values, vec!["a=1", "b=2", "c=3"]);
}

/// `buffer_body` MUST never panic — it returns an empty `Bytes` on
/// any underlying error. We synthesize a body that fails to collect
/// to exercise the `Err(_) => eprintln + empty` arm.
#[tokio::test]
async fn buffer_body_returns_empty_on_collect_error() {
    // `Body::from_stream` over a stream that yields an error frame
    // is the cheapest way to drive `BodyExt::collect` into `Err(_)`.
    let stream = futures_util::stream::once(async {
        Err::<&[u8], std::io::Error>(std::io::ErrorKind::Other.into())
    });
    let body = Body::from_stream(stream);
    let buffered = buffer_body(body).await;
    assert_eq!(buffered.len(), 0);
}

/// Build an `AppState` that points at a per-test schema inside the
/// shared `postgres:17` container (issue #181 Opt B; see
/// `crate::test_db`). Everything else (account_node, proof_store,
/// minting_account, username_store, esplora_config) is filled with a
/// smallest-possible dummy because the audit middleware never reads
/// them. Returns the `SchemaScope` alongside the state so the caller
/// keeps the schema alive for the duration of the test.
async fn build_state_with_pool() -> (AppState, SchemaScope) {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    let state_arc = Arc::new(Mutex::new(crate::state::State::new()));
    let account_node = crate::account_node::AccountNode::new(state_arc);
    let esplora_config = EsploraConfig {
        url: "http://127.0.0.1:1".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
    };

    let tmp = tempfile::tempdir().expect("tempdir");
    let proof_dir = tmp.path().to_str().unwrap().to_string();

    let pool_arc = Arc::new(pool);
    let state = AppState {
        account_node: Arc::new(Mutex::new(account_node)),
        proof_store: Arc::new(ProofStore::new(&proof_dir)),
        mint_store: Arc::new(crate::router::MintStore::new()),
        username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
        pool: pool_arc.clone(),
        esplora_config: Arc::new(esplora_config),
        prover_warm: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        prover_health: Arc::new(crate::prover_health::ProverHealth::new()),
        // Job-API wiring (jobs PR #161): the audit middleware never
        // touches these slots, but `AppState` requires them. Use a
        // never-recv'd mpsc + empty notify map for shape parity.
        job_store: Arc::new(crate::job_store::JobStore::new((*pool_arc).clone())),
        job_tx: tokio::sync::mpsc::channel::<crate::job_dispatcher::JobEnvelope>(8).0,
        job_notify_map: Arc::new(dashmap::DashMap::new()),
        v11_scan_caught_up: None,
        v11_finality_ok: None,
        pending_sign_map: Arc::new(dashmap::DashMap::new()),
    };
    // tempdir lives until the test ends (Drop on test exit).
    std::mem::forget(tmp);
    (state, scope)
}

/// Drive the middleware end-to-end: a small handler that echoes the
/// request body, an audit layer that should write a row containing
/// the bodies, headers, status, and duration. The fire-and-forget
/// spawn means we sleep briefly after the response to let the
/// insert land.
#[tokio::test]
async fn audit_middleware_persists_request_response_pair() {
    let (state, _scope) = build_state_with_pool().await;
    let pool = state.pool.clone();

    async fn echo_handler(body: Body) -> impl IntoResponse {
        let bytes = http_body_util::BodyExt::collect(body)
            .await
            .unwrap()
            .to_bytes();
        (StatusCode::OK, bytes)
    }

    let app = Router::new()
        .route("/echo", post(echo_handler))
        .with_state(state.clone())
        .layer(from_fn_with_state(state.clone(), audit_log_middleware));

    let req = Request::builder()
        .method(Method::POST)
        .uri("/echo?trace=yes")
        .header("user-agent", "audit-test/1.0")
        .header("cf-connecting-ip", "203.0.113.42")
        .body(Body::from("hello"))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);

    // Fire-and-forget tokio::spawn — wait briefly for the insert.
    for _ in 0..40 {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM request_log")
            .fetch_one(pool.as_ref())
            .await
            .unwrap();
        if count >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    #[allow(clippy::type_complexity)]
    let (
        method,
        path,
        query,
        client_ip,
        user_agent,
        response_status,
        duration_us,
        request_body,
        response_body,
    ): (
        String,
        String,
        Option<String>,
        Option<String>,
        Option<String>,
        i16,
        i64,
        Vec<u8>,
        Vec<u8>,
    ) = sqlx::query_as(
        "SELECT method, path, query, client_ip, user_agent, response_status, duration_us, request_body, response_body \
         FROM request_log",
    )
    .fetch_one(pool.as_ref())
    .await
    .expect("audit insert must land");
    assert_eq!(method, "POST");
    assert_eq!(path, "/echo");
    assert_eq!(query.as_deref(), Some("trace=yes"));
    // CF-Connecting-IP wins over remote_addr / X-Forwarded-For.
    assert_eq!(client_ip.as_deref(), Some("203.0.113.42"));
    assert_eq!(user_agent.as_deref(), Some("audit-test/1.0"));
    assert_eq!(response_status, 200);
    assert!(duration_us >= 0);
    assert_eq!(request_body, b"hello");
    assert_eq!(response_body, b"hello");
}

/// `X-Forwarded-For` is the fallback when `CF-Connecting-IP` is
/// absent. Multi-value `XFF` collapses to its first segment.
#[tokio::test]
async fn audit_middleware_falls_back_to_x_forwarded_for() {
    let (state, _scope) = build_state_with_pool().await;
    let pool = state.pool.clone();

    async fn ok_handler() -> impl IntoResponse {
        StatusCode::NO_CONTENT
    }

    let app = Router::new()
        .route("/ping", post(ok_handler))
        .with_state(state.clone())
        .layer(from_fn_with_state(state, audit_log_middleware));

    let req = Request::builder()
        .method(Method::POST)
        .uri("/ping")
        .header("x-forwarded-for", "198.51.100.7, 10.0.0.1")
        .body(Body::empty())
        .unwrap();
    let _ = app.oneshot(req).await.unwrap();

    for _ in 0..40 {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM request_log")
            .fetch_one(pool.as_ref())
            .await
            .unwrap();
        if count >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }

    let (client_ip,): (Option<String>,) = sqlx::query_as("SELECT client_ip FROM request_log")
        .fetch_one(pool.as_ref())
        .await
        .unwrap();
    assert_eq!(client_ip.as_deref(), Some("198.51.100.7"));
}
