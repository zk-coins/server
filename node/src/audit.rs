//! HTTP audit-log middleware.
//!
//! Captures every request/response that flows through the public router
//! and persists the pair into `request_log` (migration 0007). Runs as a
//! standard `axum::middleware::from_fn_with_state` layer so it sees the
//! full URI, headers, body bytes, and final response — including the
//! 4xx/5xx responses error handlers emit.
//!
//! Why fire-and-forget: the audit insert must NEVER block the response
//! back to the client. The middleware buffers both bodies in memory,
//! reconstructs the response, and spawns a tokio task that ships the
//! tuple to Postgres. A failed insert is logged to stderr and dropped —
//! losing an audit row is preferable to wedging the request handler on
//! a transient DB blip.
//!
//! Why buffering is safe today: every route in `router::create_router`
//! consumes a small JSON body and returns a small JSON response. No
//! streaming routes (no SSE, no WebSocket — those live on a separate
//! WS endpoint outside the audited router). If a streaming route is
//! ever added, that endpoint needs to opt out of this middleware to
//! avoid `body.collect()` materialising an unbounded stream.

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, State},
    http::{HeaderMap, Request, Response},
    middleware::Next,
};
use http_body_util::BodyExt;
use serde_json::{Map, Value};
use std::net::SocketAddr;
use std::time::Instant;

use crate::db;
use crate::router::AppState;

/// Convert an `http::HeaderMap` into a `serde_json::Value` so it can be
/// stored as JSONB. Non-UTF-8 header values are rendered as a hex
/// debug string (`{"_binary":"…"}`) so the round-trip is still
/// reproducible — losing a single header to a bytes-only value would
/// cost more in forensics than the storage overhead.
fn headers_to_json(headers: &HeaderMap) -> Value {
    let mut map = Map::with_capacity(headers.len());
    for (name, value) in headers.iter() {
        let key = name.as_str().to_string();
        let val = match value.to_str() {
            Ok(s) => Value::String(s.to_string()),
            Err(_) => {
                let mut binary = Map::with_capacity(1);
                binary.insert(
                    "_binary".to_string(),
                    Value::String(hex::encode(value.as_bytes())),
                );
                Value::Object(binary)
            }
        };
        // Headers can repeat (Set-Cookie etc.). Collapse repeats into
        // an array under the same key — the JSONB schema stays flat
        // string|array<string>, which is easy to query.
        match map.remove(&key) {
            Some(Value::Array(mut arr)) => {
                arr.push(val);
                map.insert(key, Value::Array(arr));
            }
            Some(existing) => {
                map.insert(key, Value::Array(vec![existing, val]));
            }
            None => {
                map.insert(key, val);
            }
        }
    }
    Value::Object(map)
}

/// Best-effort `Body::collect()` that swallows the error and returns
/// the empty byte string. The body is already half-consumed by the
/// time an error surfaces (the underlying TCP connection broke or the
/// client cancelled), so the audit row will be incomplete either way —
/// the alternative of failing the request is worse.
async fn buffer_body(body: Body) -> Bytes {
    match body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            tracing::error!("audit: body collect failed: {}", e);
            Bytes::new()
        }
    }
}

pub(crate) async fn audit_log_middleware(
    State(state): State<AppState>,
    connect_info: Option<ConnectInfo<SocketAddr>>,
    request: Request<Body>,
    next: Next,
) -> Response<Body> {
    let start = Instant::now();

    let (req_parts, req_body) = request.into_parts();
    let req_bytes = buffer_body(req_body).await;

    let method = req_parts.method.to_string();
    let path = req_parts.uri.path().to_string();
    let query = req_parts.uri.query().map(|s| s.to_string());
    let remote_addr = connect_info.as_ref().map(|c| c.0.to_string());
    let user_agent = req_parts
        .headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    // Real client IP — zkcoins-node always runs behind a Cloudflare
    // Tunnel, so the TCP peer (`remote_addr`) is the local cloudflared
    // socket, not the user. Cloudflare injects the real client IP into
    // `CF-Connecting-IP`. If a different proxy is ever in front of the
    // tunnel (test setups, future direct ingress), fall back to the
    // first segment of `X-Forwarded-For`, then to `remote_addr` as a
    // last resort.
    let client_ip = req_parts
        .headers
        .get("cf-connecting-ip")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| {
            req_parts
                .headers
                .get("x-forwarded-for")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(',').next())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
        })
        .or_else(|| remote_addr.clone());
    let request_headers = headers_to_json(&req_parts.headers);

    // Reconstruct the request with the buffered body and forward.
    let request = Request::from_parts(req_parts, Body::from(req_bytes.clone()));
    let response = next.run(request).await;

    let (resp_parts, resp_body) = response.into_parts();
    let resp_bytes = buffer_body(resp_body).await;
    let duration_us = i64::try_from(start.elapsed().as_micros()).unwrap_or(i64::MAX);

    let entry = db::RequestLogEntry {
        method,
        path,
        query,
        remote_addr,
        client_ip,
        user_agent,
        request_headers,
        request_body: req_bytes.to_vec(),
        response_status: resp_parts.status.as_u16() as i16,
        response_headers: headers_to_json(&resp_parts.headers),
        response_body: resp_bytes.to_vec(),
        duration_us,
    };

    // Fire-and-forget: a slow or failing audit write must not stall
    // the response. The pool is cloned cheaply (it's an `Arc<PgPool>`
    // under the hood).
    let pool = state.pool.clone();
    tokio::spawn(persist_audit_entry(pool, entry));

    Response::from_parts(resp_parts, Body::from(resp_bytes))
}

/// Best-effort persistence of an audit entry. Extracted from the
/// fire-and-forget `tokio::spawn` in `audit_middleware` so the
/// failure branch — `eprintln!` on a real Postgres error — can be
/// covered without a flaky background-task assertion. The function
/// itself is `coverage(off)` because the only documented production
/// failure mode is "pool dropped during shutdown", which is not
/// reproducible from a `oneshot` test without races; the
/// `db::insert_request_log` call itself is covered by the audit
/// middleware happy-path tests in `audit_tests.rs`.
#[cfg_attr(coverage_nightly, coverage(off))]
async fn persist_audit_entry(pool: std::sync::Arc<sqlx::PgPool>, entry: db::RequestLogEntry) {
    if let Err(e) = db::insert_request_log(&pool, &entry).await {
        tracing::error!("audit: insert_request_log failed: {}", e);
    }
}

#[cfg(test)]
#[path = "audit_tests.rs"]
mod tests;
