//! Blossom blob-store client (§7.4).
//!
//! An untrusted HTTP peer that claims to serve content-addressed blobs.
//! After every successful `GET` the client recomputes `SHA-256(body)` and
//! rejects a mismatch — the content address **is** the security of this
//! layer. Size is bounded by the caller-supplied `max_blob_bytes` (from
//! `/v1/info`) **before** an oversized body is admitted into memory.
//!
//! | Method | Route | Auth |
//! |---|---|---|
//! | [`BlossomClient::fetch`] | `GET /blossom/<sha256>` | none |
//! | [`BlossomClient::probe`] | `HEAD /blossom/<sha256>` | none |
//! | [`BlossomClient::upload`] | `PUT /blossom/upload` | kind `24242` |
//!
//! # Out of scope
//!
//! - **`DELETE`** — returns with §4.6 retention management (AuthVerb::Delete
//!   removed until that block; a premature delete path has no production caller).
//! - Server-side Blossom routes (API plane).
//!
//! # ReplicaReceiptV1
//!
//! A successful upload **MAY** carry a `receipt` object under the dual-commit
//! rule (§4.6 / §7.4). This client **parses and returns** it when present
//! (closed schema, canonical hex / u64 strings). It does **not** invent a
//! receipt when the key is absent. Trust-list membership and BIP-340
//! `receipt_sig` verification are the outbox / sender's job (they hold the
//! operator trust list).
//!
//! # HTTP transport
//!
//! Production path uses `reqwest` (rustls, no default features) directly.
//! Response bodies are read with [`reqwest::Response::chunk`] so
//! `max_blob_bytes` can abort mid-stream — never `bytes().await` then
//! measure. Upload JSON is parsed with `serde_json` from raw bytes (no
//! `reqwest` `json` feature).
//!
//! Spec: §4.2.1 (`blob_id = H(ciphertext)`), §7.4 (routes, auth, errors).

use std::fmt;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::nostr::event::{Event, EventError};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Nostr event kind for Blossom upload/delete authorization (§7.4).
pub(crate) const BLOSSOM_AUTH_KIND: u32 = 24242;

/// Recommended server-side replay window (§7.4): `created_at ≥ now − 300`.
///
/// Documented for callers that pass `created_at` into [`sign_auth_event`];
/// the client does not read a wall clock. Server-side upper skew is the
/// fixed §7.4 bound of 60 seconds (asserted in unit tests, not a live
/// client check).
pub(crate) const AUTH_REPLAY_WINDOW_SECS: u64 = 300;

/// Bound on every transport wait (connect + headers + body), as with the
/// relay client.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Fail-closed reasons for the Blossom client.
///
/// Status codes from §7.4 are **distinct** variants so a caller can tell
/// "you may not" from "it does not exist" from "too large" without parsing
/// a message string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BlossomError {
    /// Caller passed an empty or non-`http(s)` base URL (no default).
    InvalidBaseUrl { url: String },
    /// Kind-24242 construction or signing failed.
    AuthEvent(EventError),
    /// Transport-level failure (timeout, DNS, connection reset, …).
    Transport { message: String },
    /// A wait exceeded [`REQUEST_TIMEOUT`].
    Timeout,
    /// `GET` body SHA-256 does not equal the requested `blob_id`.
    ///
    /// Both digests are named so a log or test can show *what* was asked
    /// for versus *what* arrived — the entire security property of this
    /// layer.
    ContentAddressMismatch {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Body (or advertised `Content-Length`) exceeds `max_blob_bytes`.
    ///
    /// When `content_length` is `Some`, the client rejected on the header
    /// **without** reading the body into memory. When `None`, the client
    /// stopped after reading past the limit while streaming.
    BlobTooLarge {
        max_blob_bytes: u64,
        content_length: Option<u64>,
    },
    /// Local upload body already larger than `max_blob_bytes` — never sent.
    UploadTooLarge { max_blob_bytes: u64, body_len: u64 },
    /// HTTP 401 — authorization event rejected (signature, kind, `t`, `x`,
    /// expiration / time window).
    Unauthorized,
    /// HTTP 403 — `op` key not permitted for this upload or delete.
    Forbidden,
    /// HTTP 404 — blob not present.
    NotFound,
    /// HTTP 413 — server rejected the body as too large.
    PayloadTooLarge,
    /// HTTP 409 on DELETE — retention hold (`retention_hold`).
    RetentionHold,
    /// HTTP 400 — malformed request (partial binding headers, bad hex, …).
    BadRequest,
    /// HTTP 415 — multipart/JSON body form rejected.
    UnsupportedMediaType,
    /// Any other HTTP status, preserved for diagnosis.
    UnexpectedStatus { status: u16 },
    /// Successful upload JSON missing or non-hex `blob_id`.
    MalformedUploadResponse { reason: &'static str },
    /// Upload `200` but returned `blob_id` ≠ `H(body)` we sent.
    UploadBlobIdMismatch {
        expected: [u8; 32],
        returned: [u8; 32],
    },
    /// `receipt` key present but fails the closed ReplicaReceiptV1Json schema.
    MalformedReplicaReceipt { reason: &'static str },
}

impl fmt::Display for BlossomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BlossomError::InvalidBaseUrl { url } => {
                write!(f, "invalid Blossom base URL: {url}")
            }
            BlossomError::AuthEvent(e) => write!(f, "blossom auth event: {e}"),
            BlossomError::Transport { message } => {
                write!(f, "blossom transport error: {message}")
            }
            BlossomError::Timeout => {
                write!(f, "blossom request timed out after {REQUEST_TIMEOUT:?}")
            }
            BlossomError::ContentAddressMismatch { expected, actual } => write!(
                f,
                "blossom content-address mismatch: expected={}, actual={}",
                hex::encode(expected),
                hex::encode(actual)
            ),
            BlossomError::BlobTooLarge {
                max_blob_bytes,
                content_length,
            } => match content_length {
                Some(n) => write!(
                    f,
                    "blossom blob Content-Length {n} exceeds max_blob_bytes {max_blob_bytes}"
                ),
                None => write!(
                    f,
                    "blossom blob body exceeds max_blob_bytes {max_blob_bytes} (no Content-Length)"
                ),
            },
            BlossomError::UploadTooLarge {
                max_blob_bytes,
                body_len,
            } => write!(
                f,
                "upload body length {body_len} exceeds max_blob_bytes {max_blob_bytes}"
            ),
            BlossomError::Unauthorized => write!(f, "blossom unauthorized (HTTP 401)"),
            BlossomError::Forbidden => write!(f, "blossom forbidden (HTTP 403)"),
            BlossomError::NotFound => write!(f, "blossom not found (HTTP 404)"),
            BlossomError::PayloadTooLarge => write!(f, "blossom payload too large (HTTP 413)"),
            BlossomError::RetentionHold => {
                write!(f, "blossom delete refused: retention hold (HTTP 409)")
            }
            BlossomError::BadRequest => write!(f, "blossom bad request (HTTP 400)"),
            BlossomError::UnsupportedMediaType => {
                write!(f, "blossom unsupported media type (HTTP 415)")
            }
            BlossomError::UnexpectedStatus { status } => {
                write!(f, "blossom unexpected HTTP status {status}")
            }
            BlossomError::MalformedUploadResponse { reason } => {
                write!(f, "malformed blossom upload response: {reason}")
            }
            BlossomError::UploadBlobIdMismatch { expected, returned } => write!(
                f,
                "upload blob_id mismatch: expected={}, returned={}",
                hex::encode(expected),
                hex::encode(returned)
            ),
            BlossomError::MalformedReplicaReceipt { reason } => {
                write!(f, "malformed ReplicaReceiptV1 in upload response: {reason}")
            }
        }
    }
}

impl std::error::Error for BlossomError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            BlossomError::AuthEvent(e) => Some(e),
            _ => None,
        }
    }
}

impl BlossomError {
    /// Whether retrying the same upload cannot recover.
    ///
    /// Transient (network, timeout, 5xx / rate-limit, rare 404): stay in the
    /// outbox drive loop with §4.2 backoff. Permanent (auth/policy, size,
    /// content-address, schema, bad base URL): outbox must
    /// [`crate::v1::db_outbox::mark_failed`] so the row leaves the drive loop
    /// with a named reason — never silent eternal republish of a maligned
    /// target or broken payload.
    pub(crate) fn is_terminal(&self) -> bool {
        match self {
            // Network / peer blips — backoff and retry.
            BlossomError::Transport { .. } | BlossomError::Timeout => false,
            // Upload path rarely sees 404; treat as transient (holder lag).
            BlossomError::NotFound => false,
            // DELETE-only; not an upload permanent reject.
            BlossomError::RetentionHold => false,
            BlossomError::UnexpectedStatus { status } => {
                // 408/425/429 and 5xx: retry. Other unexpected codes fail closed.
                !matches!(*status, 408 | 425 | 429) && !(500..600).contains(status)
            }
            // Config, auth, size, content-address, closed-schema: permanent
            // for this material / operator key / base URL.
            BlossomError::InvalidBaseUrl { .. }
            | BlossomError::AuthEvent(_)
            | BlossomError::ContentAddressMismatch { .. }
            | BlossomError::BlobTooLarge { .. }
            | BlossomError::UploadTooLarge { .. }
            | BlossomError::Unauthorized
            | BlossomError::Forbidden
            | BlossomError::PayloadTooLarge
            | BlossomError::BadRequest
            | BlossomError::UnsupportedMediaType
            | BlossomError::MalformedUploadResponse { .. }
            | BlossomError::UploadBlobIdMismatch { .. }
            | BlossomError::MalformedReplicaReceipt { .. } => true,
        }
    }
}

// ---------------------------------------------------------------------------
// Binding headers — all three or none (structural)
// ---------------------------------------------------------------------------

/// Closed retention class for `X-ZkCoins-Retention` (§7.4).
///
/// Mesh upload sets [`Indefinite`] only. The `policy` wire value returns
/// with §4.6 retention management — a class without a production setter
/// is not kept as dead surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RetentionClass {
    Indefinite,
}

impl RetentionClass {
    /// Wire value: exactly `indefinite`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            RetentionClass::Indefinite => "indefinite",
        }
    }
}

/// The three §7.4 binding headers as one value.
///
/// A server **MUST** reject a partial set with `400`. The client therefore
/// never offers a type that can carry only some of them: either
/// [`Option::Some`] of this struct (all three) or [`Option::None`] (pure
/// cache upload, no receipt).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct UploadBinding {
    /// `X-ZkCoins-Event-Id` — kind-1059 delivery event id (32 bytes).
    pub event_id: [u8; 32],
    /// `X-ZkCoins-Attempt-Nonce` — sender-chosen attempt nonce (32 bytes).
    pub attempt_nonce: [u8; 32],
    /// `X-ZkCoins-Retention` — closed enum.
    pub retention: RetentionClass,
}

/// Parsed `ReplicaReceiptV1` from a Blossom upload response (§4.6 / §7.4).
///
/// Fields match the closed JSON schema. `receipt_json` is the exact object
/// bytes as received (for durable outbox storage). Signature / trust-list
/// checks are performed by the sender outbox layer, not here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ReplicaReceiptV1 {
    pub blob_id: [u8; 32],
    pub event_id: [u8; 32],
    pub holder_op_pubkey: [u8; 32],
    pub canonical_base_url: String,
    pub stored_at: u64,
    pub retention_class: String,
    pub retention_until: u64,
    pub attempt_nonce: [u8; 32],
    pub receipt_sig: [u8; 64],
    /// Canonical JSON object bytes (no surrounding whitespace normalised).
    pub receipt_json: Vec<u8>,
}

/// Successful upload: content-address plus optional dual-commit receipt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct UploadResult {
    pub blob_id: [u8; 32],
    pub receipt: Option<ReplicaReceiptV1>,
}

// ---------------------------------------------------------------------------
// Content address (§4.2.1 / §7.4)
// ---------------------------------------------------------------------------

/// `blob_id = SHA-256(bytes)` — the Blossom content address.
pub(crate) fn blob_id_of(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// Reject a body whose digest is not exactly `expected`.
///
/// This is the load-bearing check after every `GET`. A store that returns
/// arbitrary bytes under a known address is refused, not trusted.
pub(crate) fn verify_content_address(expected: &[u8; 32], body: &[u8]) -> Result<(), BlossomError> {
    let actual = blob_id_of(body);
    if &actual != expected {
        return Err(BlossomError::ContentAddressMismatch {
            expected: *expected,
            actual,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Kind-24242 authorization event
// ---------------------------------------------------------------------------

/// Verb encoded in the `t` tag of a kind-24242 event.
///
/// Only `Upload` is wired. `Delete` returns with §4.6 retention management —
/// a verb without a production caller is not kept as dead surface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum AuthVerb {
    Upload,
}

impl AuthVerb {
    fn t_tag(self) -> &'static str {
        match self {
            AuthVerb::Upload => "upload",
        }
    }
}

/// Sign a kind-`24242` authorization event under `op_key`.
///
/// Tags (closed and exact, §7.4):
/// - `["t", "upload"]` (delete verb deferred to §4.6)
/// - `["x", <lowercase-hex>]` — body hash for upload
/// - `["expiration", <unix seconds decimal>]`
/// - `content` empty
///
/// `created_at` and `expiration` are **passed in** (no clock read) so the
/// client stays unit-testable. Callers must keep `created_at` inside the
/// server window (`≤ now + 60`, `≥ now − replay_window`).
pub(crate) fn sign_auth_event(
    op_key: &[u8; 32],
    verb: AuthVerb,
    x: &[u8; 32],
    created_at: u64,
    expiration: u64,
) -> Result<Event, BlossomError> {
    let tags = vec![
        vec!["t".to_string(), verb.t_tag().to_string()],
        vec!["x".to_string(), hex::encode(x)],
        vec!["expiration".to_string(), expiration.to_string()],
    ];
    Event::sign(op_key, created_at, BLOSSOM_AUTH_KIND, tags, String::new())
        .map_err(BlossomError::AuthEvent)
}

/// Compact NIP-01 event JSON (no whitespace) for the Authorization header.
pub(crate) fn event_to_compact_json(event: &Event) -> String {
    // Field order matches the common NIP-01 wire object; values are the
    // already-signed event fields (lowercase hex for binary).
    json!({
        "id": hex::encode(event.id),
        "pubkey": hex::encode(event.pubkey),
        "created_at": event.created_at,
        "kind": event.kind,
        "tags": event.tags,
        "content": event.content,
        "sig": hex::encode(event.sig),
    })
    .to_string()
}

/// `Authorization: Nostr <base64(event JSON)>` header value (§7.4).
pub(crate) fn authorization_header_value(event: &Event) -> String {
    let json = event_to_compact_json(event);
    let b64 = B64.encode(json.as_bytes());
    format!("Nostr {b64}")
}

// ---------------------------------------------------------------------------
// URL helpers
// ---------------------------------------------------------------------------

fn validate_base_url(base_url: &str) -> Result<&str, BlossomError> {
    if base_url.is_empty() {
        return Err(BlossomError::InvalidBaseUrl {
            url: base_url.to_string(),
        });
    }
    if !(base_url.starts_with("http://") || base_url.starts_with("https://")) {
        return Err(BlossomError::InvalidBaseUrl {
            url: base_url.to_string(),
        });
    }
    Ok(base_url.trim_end_matches('/'))
}

fn blob_url(base_url: &str, blob_id: &[u8; 32]) -> Result<String, BlossomError> {
    let base = validate_base_url(base_url)?;
    Ok(format!("{base}/blossom/{}", hex::encode(blob_id)))
}

fn upload_url(base_url: &str) -> Result<String, BlossomError> {
    let base = validate_base_url(base_url)?;
    Ok(format!("{base}/blossom/upload"))
}

// ---------------------------------------------------------------------------
// Status mapping (§7.4)
// ---------------------------------------------------------------------------

/// Map a non-success HTTP status to a typed error. Success statuses are
/// left to the caller (200 vs. method-specific handling).
pub(crate) fn map_error_status(status: u16) -> BlossomError {
    match status {
        400 => BlossomError::BadRequest,
        401 => BlossomError::Unauthorized,
        403 => BlossomError::Forbidden,
        404 => BlossomError::NotFound,
        409 => BlossomError::RetentionHold,
        413 => BlossomError::PayloadTooLarge,
        415 => BlossomError::UnsupportedMediaType,
        other => BlossomError::UnexpectedStatus { status: other },
    }
}

// ---------------------------------------------------------------------------
// Client (production HTTP via reqwest)
// ---------------------------------------------------------------------------

/// Blossom client over an untrusted store.
///
/// `max_blob_bytes` comes from `/v1/info` and is required — there is no
/// default size limit and no multi-store fallback. The HTTP stack is
/// `reqwest` with rustls; size limits are enforced on the response stream
/// before the full body is buffered (see [`BlossomClient::read_body`]).
#[derive(Clone, Debug)]
pub(crate) struct BlossomClient {
    http: reqwest::Client,
    max_blob_bytes: u64,
}

impl BlossomClient {
    /// Construct a client. `max_blob_bytes` is the advertised store limit
    /// from `/v1/info` (caller-supplied; never defaulted here).
    ///
    /// `reqwest::Client::builder` only fails on TLS-backend misconfiguration
    /// (a programming error with the pinned rustls feature set); map that
    /// to [`BlossomError::Transport`] rather than panicking.
    pub(crate) fn new(max_blob_bytes: u64) -> Result<Self, BlossomError> {
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|e| BlossomError::Transport {
                message: e.to_string(),
            })?;
        Ok(Self {
            http,
            max_blob_bytes,
        })
    }

    /// `GET /blossom/<sha256>` — fetch and **verify** content address.
    pub(crate) async fn fetch(
        &self,
        base_url: &str,
        blob_id: &[u8; 32],
    ) -> Result<Vec<u8>, BlossomError> {
        let url = blob_url(base_url, blob_id)?;
        let response = self
            .http
            .get(&url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(map_reqwest_error)?;

        let status = response.status().as_u16();
        if status != 200 {
            return Err(map_error_status(status));
        }

        let body = self.read_body(response).await?;
        verify_content_address(blob_id, &body)?;
        Ok(body)
    }

    /// `HEAD /blossom/<sha256>` — existence / size probe.
    ///
    /// Size is the **`Content-Length` response header**, not the body length.
    /// HEAD has an empty body by definition; reading body length would always
    /// yield `0` and mask the store's advertised size. Prefer the explicit
    /// header over [`reqwest::Response::content_length`], which can report
    /// the decoded body size (`Some(0)`) for empty HEAD responses.
    pub(crate) async fn probe(
        &self,
        base_url: &str,
        blob_id: &[u8; 32],
    ) -> Result<Option<u64>, BlossomError> {
        let url = blob_url(base_url, blob_id)?;
        let response = self
            .http
            .head(&url)
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(map_reqwest_error)?;

        let status = response.status().as_u16();
        match status {
            200 => Ok(content_length_header(&response)),
            404 => Err(BlossomError::NotFound),
            other => Err(map_error_status(other)),
        }
    }

    /// `PUT /blossom/upload` — raw body, kind-24242 auth, optional binding.
    ///
    /// `x` on the auth event is always `SHA-256(bytes)` computed here — the
    /// caller cannot supply a divergent hash. `created_at` / `expiration`
    /// are passed in (no clock). `binding`: all three headers or none.
    ///
    /// On success returns [`UploadResult`]. When the JSON carries `receipt`,
    /// it is parsed under the closed §7.4 schema (malformed → error). Absent
    /// `receipt` is valid (holder has not dual-committed).
    pub(crate) async fn upload(
        &self,
        base_url: &str,
        bytes: &[u8],
        binding: Option<&UploadBinding>,
        op_key: &[u8; 32],
        created_at: u64,
        expiration: u64,
    ) -> Result<UploadResult, BlossomError> {
        let body_len = bytes.len() as u64;
        if body_len > self.max_blob_bytes {
            return Err(BlossomError::UploadTooLarge {
                max_blob_bytes: self.max_blob_bytes,
                body_len,
            });
        }

        let blob_id = blob_id_of(bytes);
        let event = sign_auth_event(op_key, AuthVerb::Upload, &blob_id, created_at, expiration)?;

        let url = upload_url(base_url)?;
        let mut builder = self
            .http
            .put(&url)
            .timeout(REQUEST_TIMEOUT)
            .header("Authorization", authorization_header_value(&event))
            .header("Content-Type", "application/octet-stream")
            .body(bytes.to_vec());
        if let Some(b) = binding {
            builder = builder
                .header("X-ZkCoins-Event-Id", hex::encode(b.event_id))
                .header("X-ZkCoins-Attempt-Nonce", hex::encode(b.attempt_nonce))
                .header("X-ZkCoins-Retention", b.retention.as_str());
        }

        let response = builder.send().await.map_err(map_reqwest_error)?;
        let status = response.status().as_u16();
        if status != 200 {
            return Err(map_error_status(status));
        }

        // Upload JSON is small (blob_id hex + optional receipt). Stream-cap
        // so a malicious peer cannot fill memory here either.
        let body = self.read_body(response).await?;
        let (returned, receipt) = parse_upload_response(&body)?;
        if returned != blob_id {
            return Err(BlossomError::UploadBlobIdMismatch {
                expected: blob_id,
                returned,
            });
        }
        // When a receipt is present, its blob_id / binding fields must match
        // what we sent (fail closed — never store a cross-blob receipt).
        if let Some(ref r) = receipt {
            if r.blob_id != blob_id {
                return Err(BlossomError::MalformedReplicaReceipt {
                    reason: "receipt.blob_id != H(body)",
                });
            }
            if let Some(b) = binding {
                if r.event_id != b.event_id {
                    return Err(BlossomError::MalformedReplicaReceipt {
                        reason: "receipt.event_id != X-ZkCoins-Event-Id",
                    });
                }
                if r.attempt_nonce != b.attempt_nonce {
                    return Err(BlossomError::MalformedReplicaReceipt {
                        reason: "receipt.attempt_nonce != X-ZkCoins-Attempt-Nonce",
                    });
                }
            }
        }
        Ok(UploadResult { blob_id, receipt })
    }

    /// Read a response body under `max_blob_bytes`.
    ///
    /// Order of checks (fail closed, no full-body-then-measure):
    /// 1. If `Content-Length` is present and exceeds the limit → reject
    ///    **without** reading any body bytes.
    /// 2. Otherwise stream with [`reqwest::Response::chunk`] (always
    ///    available; does not need the unused `stream` feature) and stop
    ///    as soon as the next chunk would cross the limit.
    async fn read_body(&self, mut response: reqwest::Response) -> Result<Vec<u8>, BlossomError> {
        let content_length = response.content_length();
        if let Some(len) = content_length {
            if len > self.max_blob_bytes {
                // Drop the response without aggregating the body.
                drop(response);
                return Err(BlossomError::BlobTooLarge {
                    max_blob_bytes: self.max_blob_bytes,
                    content_length: Some(len),
                });
            }
        }

        let limit = self.max_blob_bytes;
        let mut body = Vec::new();
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|e| BlossomError::Transport {
                    message: e.to_string(),
                })?;
            let Some(chunk) = chunk else {
                break;
            };
            let new_len = (body.len() as u64).saturating_add(chunk.len() as u64);
            if new_len > limit {
                // Mid-stream abort: `content_length: None` means we stopped
                // while reading (even if a peer had advertised a length).
                // `Some` is reserved for pure Content-Length rejection above.
                return Err(BlossomError::BlobTooLarge {
                    max_blob_bytes: limit,
                    content_length: None,
                });
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }
}

fn map_reqwest_error(e: reqwest::Error) -> BlossomError {
    if e.is_timeout() {
        BlossomError::Timeout
    } else {
        BlossomError::Transport {
            message: e.to_string(),
        }
    }
}

/// Parse `Content-Length` from response headers (probe / size advertisement).
///
/// Returns `None` when the header is absent or not a decimal `u64`. Does
/// **not** fall back to body length — HEAD bodies are empty by definition.
fn content_length_header(response: &reqwest::Response) -> Option<u64> {
    response
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

/// Parse upload JSON: required `blob_id`, optional closed-schema `receipt`.
fn parse_upload_response(
    body: &[u8],
) -> Result<([u8; 32], Option<ReplicaReceiptV1>), BlossomError> {
    let value: Value =
        serde_json::from_slice(body).map_err(|_| BlossomError::MalformedUploadResponse {
            reason: "body is not JSON",
        })?;
    let obj = value
        .as_object()
        .ok_or(BlossomError::MalformedUploadResponse {
            reason: "body is not a JSON object",
        })?;
    let hex_str = obj.get("blob_id").and_then(|v| v.as_str()).ok_or(
        BlossomError::MalformedUploadResponse {
            reason: "missing string field blob_id",
        },
    )?;
    let blob_id = parse_hex32_lower(hex_str).ok_or(BlossomError::MalformedUploadResponse {
        reason: "blob_id is not 32-byte lowercase hex",
    })?;
    let receipt = match obj.get("receipt") {
        None => None,
        Some(v) if v.is_null() => None,
        Some(v) => Some(parse_replica_receipt_value(v)?),
    };
    Ok((blob_id, receipt))
}

/// Closed-schema decoder for `ReplicaReceiptV1Json` (§7.4).
///
/// Exactly nine keys; all binary fields lowercase hex of the stated width;
/// times as canonical decimal strings; `retention_class` ∈ {indefinite, policy}.
pub(crate) fn parse_replica_receipt_value(v: &Value) -> Result<ReplicaReceiptV1, BlossomError> {
    let obj = v.as_object().ok_or(BlossomError::MalformedReplicaReceipt {
        reason: "receipt is not a JSON object",
    })?;
    const REQUIRED: [&str; 9] = [
        "blob_id",
        "event_id",
        "holder_op_pubkey",
        "canonical_base_url",
        "stored_at",
        "retention_class",
        "retention_until",
        "attempt_nonce",
        "receipt_sig",
    ];
    for k in REQUIRED {
        if !obj.contains_key(k) {
            return Err(BlossomError::MalformedReplicaReceipt {
                reason: "receipt missing required key",
            });
        }
    }
    for k in obj.keys() {
        if !REQUIRED.contains(&k.as_str()) {
            return Err(BlossomError::MalformedReplicaReceipt {
                reason: "receipt has unknown extra key",
            });
        }
    }
    let blob_id = req_hex32(obj, "blob_id")?;
    let event_id = req_hex32(obj, "event_id")?;
    let holder_op_pubkey = req_hex32(obj, "holder_op_pubkey")?;
    let attempt_nonce = req_hex32(obj, "attempt_nonce")?;
    let receipt_sig = req_hex64(obj, "receipt_sig")?;
    let canonical_base_url = obj
        .get("canonical_base_url")
        .and_then(|x| x.as_str())
        .ok_or(BlossomError::MalformedReplicaReceipt {
            reason: "canonical_base_url not a string",
        })?
        .to_string();
    if canonical_base_url.is_empty() {
        return Err(BlossomError::MalformedReplicaReceipt {
            reason: "canonical_base_url empty",
        });
    }
    let retention_class = obj
        .get("retention_class")
        .and_then(|x| x.as_str())
        .ok_or(BlossomError::MalformedReplicaReceipt {
            reason: "retention_class not a string",
        })?
        .to_string();
    if retention_class != "indefinite" && retention_class != "policy" {
        return Err(BlossomError::MalformedReplicaReceipt {
            reason: "retention_class not in closed enum",
        });
    }
    let stored_at = req_u64_string(obj, "stored_at")?;
    let retention_until = req_u64_string(obj, "retention_until")?;
    if retention_class == "indefinite" && retention_until != 0 {
        return Err(BlossomError::MalformedReplicaReceipt {
            reason: "retention_until must be 0 when retention_class is indefinite",
        });
    }
    // Persist the exact object encoding as re-serialised compact JSON so the
    // outbox has a stable byte string without surrounding response noise.
    let receipt_json =
        serde_json::to_vec(v).map_err(|_| BlossomError::MalformedReplicaReceipt {
            reason: "receipt re-serialise failed",
        })?;
    Ok(ReplicaReceiptV1 {
        blob_id,
        event_id,
        holder_op_pubkey,
        canonical_base_url,
        stored_at,
        retention_class,
        retention_until,
        attempt_nonce,
        receipt_sig,
        receipt_json,
    })
}

fn req_hex32(
    obj: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<[u8; 32], BlossomError> {
    let s = obj
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or(BlossomError::MalformedReplicaReceipt {
            reason: "receipt field not a string",
        })?;
    parse_hex32_lower(s).ok_or(BlossomError::MalformedReplicaReceipt {
        reason: "receipt field not 32-byte lowercase hex",
    })
}

fn req_hex64(
    obj: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<[u8; 64], BlossomError> {
    let s = obj
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or(BlossomError::MalformedReplicaReceipt {
            reason: "receipt_sig not a string",
        })?;
    if s.len() != 128 {
        return Err(BlossomError::MalformedReplicaReceipt {
            reason: "receipt_sig not 64-byte lowercase hex",
        });
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(BlossomError::MalformedReplicaReceipt {
            reason: "receipt_sig not 64-byte lowercase hex",
        });
    }
    let bytes = hex::decode(s).map_err(|_| BlossomError::MalformedReplicaReceipt {
        reason: "receipt_sig hex decode failed",
    })?;
    let mut out = [0u8; 64];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Canonical u64 decimal string: `0|[1-9][0-9]*` (§7.4).
fn req_u64_string(
    obj: &serde_json::Map<String, Value>,
    key: &'static str,
) -> Result<u64, BlossomError> {
    let s = obj
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or(BlossomError::MalformedReplicaReceipt {
            reason: "u64 field not a string",
        })?;
    if s.is_empty() {
        return Err(BlossomError::MalformedReplicaReceipt {
            reason: "u64 string empty",
        });
    }
    if s == "0" {
        return Ok(0);
    }
    if s.as_bytes()[0] == b'0' {
        return Err(BlossomError::MalformedReplicaReceipt {
            reason: "u64 string has leading zero",
        });
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(BlossomError::MalformedReplicaReceipt {
            reason: "u64 string non-decimal",
        });
    }
    s.parse::<u64>()
        .map_err(|_| BlossomError::MalformedReplicaReceipt {
            reason: "u64 string out of range",
        })
}

fn parse_hex32_lower(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 {
        return None;
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let bytes = hex::decode(s).ok()?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use wiremock::matchers::{header, method, path};
    use wiremock::{Mock, MockServer, Request, ResponseTemplate};

    // -----------------------------------------------------------------------
    // Fixtures
    // -----------------------------------------------------------------------

    fn fixture_sk(label: &[u8]) -> [u8; 32] {
        let mut seed = Sha256::digest(label).to_vec();
        let secp = Secp256k1::new();
        loop {
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&seed[..32]);
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                let _ = Keypair::from_secret_key(&secp, &sk);
                return sk_bytes;
            }
            seed = Sha256::digest(&seed).to_vec();
        }
    }

    fn fixture_pubkey(sk: &[u8; 32]) -> [u8; 32] {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(sk).expect("fixture sk");
        let kp = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = kp.x_only_public_key();
        xonly.serialize()
    }

    fn test_client(max_blob_bytes: u64) -> BlossomClient {
        BlossomClient::new(max_blob_bytes).expect("reqwest client")
    }

    // -----------------------------------------------------------------------
    // Content address
    // -----------------------------------------------------------------------

    #[test]
    fn verify_content_address_accepts_matching_digest() {
        let body = b"honest-ciphertext-bytes";
        let id = blob_id_of(body);
        verify_content_address(&id, body).expect("matching digest must pass");
    }

    #[test]
    fn verify_content_address_rejects_mismatch_naming_both_digests() {
        let expected_body = b"bytes-under-known-address";
        let expected = blob_id_of(expected_body);
        let lying_body = b"different-bytes-from-the-store";
        let actual = blob_id_of(lying_body);
        assert_ne!(expected, actual, "fixture must use distinct digests");

        let err = verify_content_address(&expected, lying_body)
            .expect_err("mismatched body must be rejected");

        match err {
            BlossomError::ContentAddressMismatch {
                expected: e,
                actual: a,
            } => {
                assert_eq!(e, expected, "error must name the requested blob_id");
                assert_eq!(a, actual, "error must name the digest of the body");
                assert_ne!(e, a);
            }
            other => panic!("expected ContentAddressMismatch, got {other:?}"),
        }

        let display = err.to_string();
        assert!(
            display.contains(&hex::encode(expected)),
            "display must include expected: {display}"
        );
        assert!(
            display.contains(&hex::encode(actual)),
            "display must include actual: {display}"
        );
    }

    // -----------------------------------------------------------------------
    // Kind 24242 auth event
    // -----------------------------------------------------------------------

    #[test]
    fn auth_event_upload_tags_and_signature_under_op() {
        let op = fixture_sk(b"zkCoins/v1/test/blossom/op-sk");
        let op_pk = fixture_pubkey(&op);
        let body = b"upload-body-for-auth";
        let x = blob_id_of(body);
        let created_at = 1_700_000_000;
        let expiration = created_at + 300;

        let event =
            sign_auth_event(&op, AuthVerb::Upload, &x, created_at, expiration).expect("sign");

        assert_eq!(event.kind, BLOSSOM_AUTH_KIND);
        assert_eq!(event.pubkey, op_pk);
        assert_eq!(event.content, "");
        assert_eq!(event.created_at, created_at);
        assert_eq!(
            event.tags,
            vec![
                vec!["t".to_string(), "upload".to_string()],
                vec!["x".to_string(), hex::encode(x)],
                vec!["expiration".to_string(), expiration.to_string()],
            ]
        );
        event.verify().expect("signature must verify under op");
    }

    #[test]
    fn auth_event_x_is_hash_of_sent_body_not_caller_supplied() {
        // The upload path computes x from the body itself. This test pins
        // that contract: a divergent "caller hash" is never what gets signed.
        let op = fixture_sk(b"zkCoins/v1/test/blossom/op-sk-x");
        let body = b"exact-request-body-bytes";
        let body_hash = blob_id_of(body);
        let caller_diverted = blob_id_of(b"something-else-the-caller-claims");
        assert_ne!(body_hash, caller_diverted);

        // What upload() signs: hash of the body that will be sent.
        let event = sign_auth_event(&op, AuthVerb::Upload, &body_hash, 1, 2).expect("sign");
        let x_tag = &event.tags[1];
        assert_eq!(x_tag[0], "x");
        assert_eq!(x_tag[1], hex::encode(body_hash));
        assert_ne!(x_tag[1], hex::encode(caller_diverted));

        // Round-trip: recompute from the same body yields the tag value.
        assert_eq!(hex::encode(blob_id_of(body)), x_tag[1]);
    }

    #[test]
    fn authorization_header_is_nostr_base64_of_event_json() {
        let op = fixture_sk(b"zkCoins/v1/test/blossom/op-sk-hdr");
        let x = [0xab; 32];
        let event = sign_auth_event(&op, AuthVerb::Upload, &x, 42, 99).expect("sign");
        let header = authorization_header_value(&event);
        assert!(header.starts_with("Nostr "), "header={header}");
        let b64 = header.strip_prefix("Nostr ").expect("prefix");
        let json_bytes = B64.decode(b64).expect("standard base64");
        let v: Value = serde_json::from_slice(&json_bytes).expect("json");
        assert_eq!(v["kind"], BLOSSOM_AUTH_KIND);
        assert_eq!(v["id"], hex::encode(event.id));
        assert_eq!(v["sig"], hex::encode(event.sig));
        assert_eq!(v["content"], "");
        assert_eq!(v["tags"][0][1], "upload");
        assert_eq!(v["tags"][1][1], hex::encode(x));
    }

    #[test]
    fn blossom_error_terminal_classification() {
        assert!(!BlossomError::Timeout.is_terminal());
        assert!(!BlossomError::Transport {
            message: "reset".into()
        }
        .is_terminal());
        assert!(!BlossomError::NotFound.is_terminal());
        assert!(!BlossomError::UnexpectedStatus { status: 503 }.is_terminal());
        assert!(!BlossomError::UnexpectedStatus { status: 429 }.is_terminal());
        assert!(BlossomError::UnexpectedStatus { status: 418 }.is_terminal());
        assert!(BlossomError::Forbidden.is_terminal());
        assert!(BlossomError::Unauthorized.is_terminal());
        assert!(BlossomError::BadRequest.is_terminal());
        assert!(BlossomError::PayloadTooLarge.is_terminal());
        assert!(BlossomError::InvalidBaseUrl {
            url: "ftp://x".into()
        }
        .is_terminal());
    }

    // -----------------------------------------------------------------------
    // Binding headers — structural all-or-nothing
    // -----------------------------------------------------------------------

    #[test]
    fn upload_binding_carries_all_three_fields_together() {
        let binding = UploadBinding {
            event_id: [1u8; 32],
            attempt_nonce: [2u8; 32],
            retention: RetentionClass::Indefinite,
        };
        // The only construction paths are Some(binding) or None.
        let present: Option<UploadBinding> = Some(binding);
        let absent: Option<UploadBinding> = None;
        assert!(present.is_some());
        assert!(absent.is_none());
        assert_eq!(binding.retention.as_str(), "indefinite");
    }

    #[test]
    fn retention_class_is_closed_enum_not_free_string() {
        // Compile-time: only Indefinite is constructible on this path.
        // Runtime: wire string is exactly the closed value.
        assert_eq!(RetentionClass::Indefinite.as_str(), "indefinite");
    }

    // -----------------------------------------------------------------------
    // Status mapping
    // -----------------------------------------------------------------------

    #[test]
    fn each_status_maps_to_distinct_typed_error() {
        assert_eq!(map_error_status(400), BlossomError::BadRequest);
        assert_eq!(map_error_status(401), BlossomError::Unauthorized);
        assert_eq!(map_error_status(403), BlossomError::Forbidden);
        assert_eq!(map_error_status(404), BlossomError::NotFound);
        assert_eq!(map_error_status(409), BlossomError::RetentionHold);
        assert_eq!(map_error_status(413), BlossomError::PayloadTooLarge);
        assert_eq!(map_error_status(415), BlossomError::UnsupportedMediaType);
        assert_eq!(
            map_error_status(500),
            BlossomError::UnexpectedStatus { status: 500 }
        );
        assert_eq!(
            map_error_status(418),
            BlossomError::UnexpectedStatus { status: 418 }
        );
    }

    // -----------------------------------------------------------------------
    // HTTP tests via wiremock (same pattern as publisher / api_remote)
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn fetch_rejects_store_that_returns_wrong_bytes() {
        let server = MockServer::start().await;
        let honest = b"ciphertext-that-was-addressed";
        let blob_id = blob_id_of(honest);
        let lying = b"bytes-the-store-substituted";

        Mock::given(method("GET"))
            .and(path(format!("/blossom/{}", hex::encode(blob_id))))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(lying.to_vec()),
            )
            .mount(&server)
            .await;

        let client = test_client(1_048_576);
        let err = client
            .fetch(&server.uri(), &blob_id)
            .await
            .expect_err("lying store must be rejected");

        match err {
            BlossomError::ContentAddressMismatch { expected, actual } => {
                assert_eq!(expected, blob_id);
                assert_eq!(actual, blob_id_of(lying));
                assert_ne!(expected, actual);
            }
            other => panic!("expected ContentAddressMismatch, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_accepts_matching_body() {
        let server = MockServer::start().await;
        let body = b"zbe-ciphertext-payload";
        let blob_id = blob_id_of(body);

        Mock::given(method("GET"))
            .and(path(format!("/blossom/{}", hex::encode(blob_id))))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(body.to_vec()),
            )
            .mount(&server)
            .await;

        let client = test_client(1_048_576);
        let got = client
            .fetch(&server.uri(), &blob_id)
            .await
            .expect("honest store");
        assert_eq!(got, body);
    }

    #[tokio::test]
    async fn fetch_rejects_oversize_content_length_without_buffering_body() {
        let server = MockServer::start().await;
        let blob_id = blob_id_of(b"unused");
        // Large advertised length; body is also large so a naive client
        // would allocate. Our client must fail on Content-Length first —
        // the typed error carries `content_length: Some(n)`, which is only
        // produced on that pre-read path (stream oversize uses `None` or
        // the advertised length after partial read).
        let huge = vec![0x5au8; 64 * 1024];
        let max_blob_bytes = 1024u64;

        Mock::given(method("GET"))
            .and(path(format!("/blossom/{}", hex::encode(blob_id))))
            .respond_with(
                ResponseTemplate::new(200)
                    // Explicit Content-Length larger than the limit.
                    .insert_header("content-length", huge.len().to_string())
                    .set_body_bytes(huge.clone()),
            )
            .mount(&server)
            .await;

        let client = test_client(max_blob_bytes);
        let err = client
            .fetch(&server.uri(), &blob_id)
            .await
            .expect_err("oversize Content-Length must fail");

        match err {
            BlossomError::BlobTooLarge {
                max_blob_bytes: max,
                content_length: Some(n),
            } => {
                assert_eq!(max, max_blob_bytes);
                assert_eq!(n, huge.len() as u64);
            }
            other => panic!("expected BlobTooLarge with content_length, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fetch_maps_404_to_not_found() {
        let server = MockServer::start().await;
        let blob_id = [0x11u8; 32];
        Mock::given(method("GET"))
            .and(path(format!("/blossom/{}", hex::encode(blob_id))))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let client = test_client(1024);
        let err = client
            .fetch(&server.uri(), &blob_id)
            .await
            .expect_err("404");
        assert_eq!(err, BlossomError::NotFound);
    }

    #[tokio::test]
    async fn probe_returns_content_length_on_200() {
        let server = MockServer::start().await;
        let blob_id = [0x22u8; 32];
        Mock::given(method("HEAD"))
            .and(path(format!("/blossom/{}", hex::encode(blob_id))))
            .respond_with(ResponseTemplate::new(200).insert_header("content-length", "4096"))
            .mount(&server)
            .await;

        let client = test_client(1_048_576);
        let len = client.probe(&server.uri(), &blob_id).await.expect("probe");
        assert_eq!(len, Some(4096));
    }

    /// Captures the first matching request for post-hoc assertions.
    struct CapturingUpload {
        body: Arc<std::sync::Mutex<Vec<u8>>>,
        auth: Arc<std::sync::Mutex<Option<String>>>,
        blob_id_hex: String,
    }

    impl wiremock::Respond for CapturingUpload {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            *self.body.lock().expect("body lock") = request.body.clone();
            let auth = request
                .headers
                .get("authorization")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string());
            *self.auth.lock().expect("auth lock") = auth;
            // No receipt: pure cache upload without dual-commit (§7.4).
            // A present-but-malformed receipt is rejected by the client.
            ResponseTemplate::new(200).set_body_json(json!({
                "blob_id": self.blob_id_hex,
            }))
        }
    }

    #[tokio::test]
    async fn upload_sends_raw_body_auth_and_all_binding_headers() {
        let server = MockServer::start().await;
        let body = b"raw-zbe-blob-bytes";
        let blob_id = blob_id_of(body);
        let op = fixture_sk(b"zkCoins/v1/test/blossom/op-upload");
        let binding = UploadBinding {
            event_id: [0xae; 32],
            attempt_nonce: [0xbe; 32],
            retention: RetentionClass::Indefinite,
        };

        let captured_body = Arc::new(std::sync::Mutex::new(Vec::new()));
        let captured_auth = Arc::new(std::sync::Mutex::new(None));

        Mock::given(method("PUT"))
            .and(path("/blossom/upload"))
            .and(header("content-type", "application/octet-stream"))
            .and(header("x-zkcoins-event-id", hex::encode(binding.event_id)))
            .and(header(
                "x-zkcoins-attempt-nonce",
                hex::encode(binding.attempt_nonce),
            ))
            // Wire value must match RetentionClass::Indefinite.as_str() —
            // "policy" was removed with §4.6; a stale matcher yields 404
            // (unmatched mock), not a header-assertion failure.
            .and(header("x-zkcoins-retention", "indefinite"))
            .respond_with(CapturingUpload {
                body: captured_body.clone(),
                auth: captured_auth.clone(),
                blob_id_hex: hex::encode(blob_id),
            })
            .mount(&server)
            .await;

        let client = test_client(1_048_576);
        let now = 1_700_000_100u64;
        let got = client
            .upload(
                &server.uri(),
                body,
                Some(&binding),
                &op,
                now,
                now + AUTH_REPLAY_WINDOW_SECS,
            )
            .await
            .expect("upload");
        assert_eq!(got.blob_id, blob_id);
        assert!(got.receipt.is_none(), "mock returns no dual-commit receipt");

        let sent_body = captured_body.lock().expect("body").clone();
        assert_eq!(
            sent_body, body,
            "body must be raw octets, not multipart/JSON"
        );

        let auth = captured_auth
            .lock()
            .expect("auth")
            .clone()
            .expect("Authorization header");
        assert!(auth.starts_with("Nostr "));
        let json_bytes = B64
            .decode(auth.strip_prefix("Nostr ").expect("prefix"))
            .expect("b64");
        let v: Value = serde_json::from_slice(&json_bytes).expect("json");
        assert_eq!(v["kind"], BLOSSOM_AUTH_KIND);
        assert_eq!(v["tags"][0][1], "upload");
        // x must be the hash of the **sent** body, not a free parameter.
        assert_eq!(v["tags"][1][1], hex::encode(blob_id));
        assert_eq!(v["tags"][1][1], hex::encode(blob_id_of(&sent_body)));
        assert_eq!(v["content"], "");
    }

    struct CacheUploadResponder {
        saw_zk: Arc<std::sync::atomic::AtomicBool>,
        blob_id_hex: String,
    }

    impl wiremock::Respond for CacheUploadResponder {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            for name in request.headers.keys() {
                if name.as_str().starts_with("x-zkcoins-") {
                    self.saw_zk.store(true, Ordering::SeqCst);
                }
            }
            ResponseTemplate::new(200).set_body_json(json!({ "blob_id": self.blob_id_hex }))
        }
    }

    #[tokio::test]
    async fn upload_without_binding_sends_no_zkcoins_headers() {
        let server = MockServer::start().await;
        let body = b"cache-only-blob";
        let blob_id = blob_id_of(body);
        let op = fixture_sk(b"zkCoins/v1/test/blossom/op-cache");

        let saw_zk = Arc::new(std::sync::atomic::AtomicBool::new(false));

        Mock::given(method("PUT"))
            .and(path("/blossom/upload"))
            .respond_with(CacheUploadResponder {
                saw_zk: saw_zk.clone(),
                blob_id_hex: hex::encode(blob_id),
            })
            .mount(&server)
            .await;

        let client = test_client(1_048_576);
        client
            .upload(&server.uri(), body, None, &op, 1, 2)
            .await
            .expect("cache upload");
        assert!(
            !saw_zk.load(Ordering::SeqCst),
            "pure cache upload must not send any X-ZkCoins-* header"
        );
    }

    #[tokio::test]
    async fn upload_rejects_local_body_over_max_without_http() {
        let client = test_client(4);
        let op = fixture_sk(b"zkCoins/v1/test/blossom/op-big");
        let err = client
            .upload("http://127.0.0.1:1", b"12345", None, &op, 1, 2)
            .await
            .expect_err("local size check");
        match err {
            BlossomError::UploadTooLarge {
                max_blob_bytes,
                body_len,
            } => {
                assert_eq!(max_blob_bytes, 4);
                assert_eq!(body_len, 5);
            }
            other => panic!("expected UploadTooLarge, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn upload_status_codes_map_individually() {
        let cases: &[(u16, BlossomError)] = &[
            (401, BlossomError::Unauthorized),
            (403, BlossomError::Forbidden),
            (413, BlossomError::PayloadTooLarge),
            (400, BlossomError::BadRequest),
            (415, BlossomError::UnsupportedMediaType),
        ];
        for (status, expect) in cases {
            let server = MockServer::start().await;
            Mock::given(method("PUT"))
                .and(path("/blossom/upload"))
                .respond_with(ResponseTemplate::new(*status))
                .mount(&server)
                .await;

            let client = test_client(1_048_576);
            let op = fixture_sk(b"zkCoins/v1/test/blossom/op-status");
            let err = client
                .upload(&server.uri(), b"x", None, &op, 1, 2)
                .await
                .expect_err("status");
            assert_eq!(err, *expect, "status {status}");
        }
    }

    #[test]
    fn auth_time_window_constants_match_spec_7_4() {
        // Server checks created_at ≤ now + 60 (§7.4 fixed upper skew) and
        // created_at ≥ now − AUTH_REPLAY_WINDOW_SECS (recommended). The
        // client does not read a clock; callers pass created_at/expiration.
        assert_eq!(AUTH_REPLAY_WINDOW_SECS, 300);
    }

    #[test]
    fn parse_replica_receipt_closed_schema() {
        let receipt = json!({
            "blob_id": "aa".repeat(32),
            "event_id": "bb".repeat(32),
            "holder_op_pubkey": "cc".repeat(32),
            "canonical_base_url": "https://holder.example",
            "stored_at": "1700000000",
            "retention_class": "indefinite",
            "retention_until": "0",
            "attempt_nonce": "dd".repeat(32),
            "receipt_sig": "ee".repeat(64),
        });
        let parsed = parse_replica_receipt_value(&receipt).expect("valid");
        assert_eq!(parsed.stored_at, 1_700_000_000);
        assert_eq!(parsed.retention_class, "indefinite");
        assert_eq!(parsed.canonical_base_url, "https://holder.example");
        assert!(!parsed.receipt_json.is_empty());
    }

    #[test]
    fn parse_replica_receipt_rejects_extra_key() {
        let receipt = json!({
            "blob_id": "aa".repeat(32),
            "event_id": "bb".repeat(32),
            "holder_op_pubkey": "cc".repeat(32),
            "canonical_base_url": "https://holder.example",
            "stored_at": "1",
            "retention_class": "indefinite",
            "retention_until": "0",
            "attempt_nonce": "dd".repeat(32),
            "receipt_sig": "ee".repeat(64),
            "extra": true,
        });
        let err = parse_replica_receipt_value(&receipt).expect_err("extra");
        match err {
            BlossomError::MalformedReplicaReceipt { reason } => {
                assert!(reason.contains("extra") || reason.contains("unknown"));
            }
            other => panic!("expected MalformedReplicaReceipt, got {other:?}"),
        }
    }

    #[test]
    fn parse_upload_response_stores_receipt_when_present() {
        let body = json!({
            "blob_id": "11".repeat(32),
            "receipt": {
                "blob_id": "11".repeat(32),
                "event_id": "22".repeat(32),
                "holder_op_pubkey": "33".repeat(32),
                "canonical_base_url": "https://h.example",
                "stored_at": "9",
                "retention_class": "policy",
                "retention_until": "99",
                "attempt_nonce": "44".repeat(32),
                "receipt_sig": "55".repeat(64),
            }
        });
        let bytes = serde_json::to_vec(&body).expect("ser");
        let (blob, receipt) = parse_upload_response(&bytes).expect("parse");
        assert_eq!(hex::encode(blob), "11".repeat(32));
        let r = receipt.expect("receipt present");
        assert_eq!(r.retention_class, "policy");
        assert_eq!(r.stored_at, 9);
        assert_eq!(r.retention_until, 99);
    }

    #[test]
    fn empty_base_url_is_rejected_not_defaulted() {
        let err = blob_url("", &[0u8; 32]).expect_err("empty");
        match err {
            BlossomError::InvalidBaseUrl { url } => assert!(url.is_empty()),
            other => panic!("expected InvalidBaseUrl, got {other:?}"),
        }
    }

    #[test]
    fn non_http_base_url_is_rejected() {
        let err = blob_url("ws://relay.example", &[0u8; 32]).expect_err("ws");
        match err {
            BlossomError::InvalidBaseUrl { url } => {
                assert_eq!(url, "ws://relay.example");
            }
            other => panic!("expected InvalidBaseUrl, got {other:?}"),
        }
    }
}
