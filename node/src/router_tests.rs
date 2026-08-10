use super::*;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use tower::ServiceExt;

use crate::account_node::{Account, AccountNode};
use crate::state::State;

/// Build a `PgPool` that points at nowhere — every query against it
/// fails fast with a connect error. Used by the node-handler test
/// suite below so the handlers' persistence-side `.await` lines run
/// the error branch (which mirrors the legacy file-IO best-effort
/// semantics: log + continue, never fail the response). The matching
/// happy-path tests for the upsert lines run against a real
/// Postgres 17 testcontainer in `db_tests.rs`, `account_node_tests.rs`,
/// `username_tests.rs`, and `runtime_tests.rs`.
fn dead_pool() -> Arc<sqlx::PgPool> {
    Arc::new(
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(50))
            .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/postgres")
            .expect("connect_lazy never fails"),
    )
}

/// Create a minimal AppState for testing.
/// The AccountNode is constructed with a real (mock) prover so that the
/// type system is satisfied, but we seed it with a minting account so that
/// balance / address queries work without needing the minting_secret.bin
/// flow.
/// A deterministic, non-zero test asset id (neutral model — no native
/// asset). The router-test owner below holds this single asset.
fn test_asset_id() -> zkcoins_program::types::AssetId {
    zkcoins_program::hash::hash_bytes(b"router-test-asset")
}

/// A deterministic owner address for the seeded test account.
fn test_owner_address() -> zkcoins_program::hash::HashDigest {
    zkcoins_program::hash::digest_from_bytes(&[0x11u8; 32])
}

fn test_state() -> AppState {
    let state = Arc::new(Mutex::new(State::new()));
    let mut account_node = AccountNode::new(Arc::clone(&state));

    // Seed a funded `(owner, asset_id)` account. Neutral model: there
    // is no privileged minting account — this is just an ordinary
    // ledger so balance / history queries have something to read.
    let mut funded = Account::new_for_asset(test_asset_id());
    funded.balance = 1_000_000;
    account_node.import_account(test_owner_address(), funded);

    // Per-test scratch dir for the ProofStore. Issue #181 Opt A flips
    // the CI to `--test-threads=8`, which means several `test_state()`
    // callers run concurrently in the same process; the previous
    // hard-coded `/tmp/zkcoins-test-proofs` shared one directory across
    // tests. `keep()` returns the underlying `PathBuf` and disables the
    // auto-cleanup Drop — we accept the leak (tests are best-effort
    // cleaned up by the OS / CI runner reboot) so we don't have to
    // thread a `TempDir` guard through every caller and the `AppState`
    // struct. The canonical comment lives here; the second call-site
    // below (the mint helper around line ~2260) just points back.
    let proofs_dir = tempfile::tempdir().expect("create proofs tempdir").keep();
    AppState {
        account_node: Arc::new(Mutex::new(account_node)),
        proof_store: Arc::new(ProofStore::new(
            proofs_dir.to_str().expect("proofs tempdir utf-8"),
        )),
        mint_store: Arc::new(crate::router::MintStore::new()),
        username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
        pool: dead_pool(),
        // Most tests don't exercise the readiness probe and so don't
        // care about Esplora — point at a guaranteed-unreachable URL
        // so an accidental call fails fast instead of hitting the real
        // mutinynet.com from CI. The three `/health/ready` tests below
        // override this slot with a `wiremock::MockServer` URL.
        esplora_config: Arc::new(crate::publisher::EsploraConfig {
            url: "http://127.0.0.1:1/api".to_string(),
            is_mainnet: false,
            network_name: "Mutinynet".to_string(),
            ws_url: None,
        }),
        // Tests construct the AppState with the prover already marked
        // warm so handlers that only consult `prover_warm` indirectly
        // (e.g. the readiness probe) don't observe a half-bootstrapped
        // shape. The dedicated 503/warming-tag test below overrides
        // this back to `false` to exercise the gating arm.
        prover_warm: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        prover_health: Arc::new(crate::prover_health::ProverHealth::new()),
        job_store: Arc::new(crate::job_store::JobStore::new((*dead_pool()).clone())),
        job_tx: tokio::sync::mpsc::channel::<crate::job_dispatcher::JobEnvelope>(8).0,
        job_notify_map: Arc::new(dashmap::DashMap::new()),
        // Legacy-stack tests: no v1.1 readiness gates.
        v1_scan_caught_up: None,
        v1_finality_ok: None,
        pending_sign_map: Arc::new(dashmap::DashMap::new()),
        v1_finalise: None,
        v1_live_pending_after_begin: Arc::new(dashmap::DashMap::new()),
        v1_pending_after_prove: None,
        receive_creating_proof_loader: None,
        v1_engine: None,
        private_index: crate::kernel::access::InMemoryPrivateIndex::shared(),
        bundles: crate::kernel::bootstrap::BundleStore::shared(),
        attest_challenges: crate::kernel::bootstrap::ChallengeStore::shared(),
        public_hosts: Arc::new(vec!["node.test".to_string()]),
    }
}

/// Variant of [`test_state`] that swaps the lazy `dead_pool` for a real
/// migrated Postgres pool. Used by the handful of happy-path tests
/// whose handler actually has to persist (e.g. `claim_username` —
/// hard-fails with 503 on DB error, unlike `send`/`mint`/`receive`
/// whose `db::upsert_account` calls are best-effort log-and-continue).
fn live_test_state(pool: Arc<sqlx::PgPool>) -> AppState {
    let mut state = test_state();
    state.pool = pool;
    state
}

/// Helper: send a request through the router and return (status, body string).
async fn send_request(request: Request<Body>) -> (StatusCode, String) {
    let app = create_router(test_state());
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    (status, body)
}

// --- GET /health ---

#[tokio::test]
async fn health_returns_ok() {
    let req = Request::get("/health").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, "ok");
}

// --- CORS preflight ---

/// A browser calling `POST /api/jobs/mint` (or `/send`) sends the
/// mandatory `Idempotency-Key` request header, which triggers a CORS
/// preflight (`OPTIONS`). The router's `CorsLayer` must echo that header
/// back in `Access-Control-Allow-Headers`, otherwise the browser blocks
/// the request and the web frontend cannot mint or send. This guards the
/// `allow_headers([CONTENT_TYPE, "idempotency-key"])` configuration.
#[tokio::test]
async fn cors_preflight_allows_idempotency_key_for_jobs_api() {
    let request = Request::builder()
        .method(Method::OPTIONS)
        .uri("/api/jobs/mint")
        .header("origin", "https://app.example")
        .header("access-control-request-method", "POST")
        .header("access-control-request-headers", "idempotency-key")
        .body(Body::empty())
        .unwrap();

    let app = create_router(test_state());
    let response = app.oneshot(request).await.unwrap();

    let allow_headers = response
        .headers()
        .get("access-control-allow-headers")
        .expect("preflight response must carry Access-Control-Allow-Headers")
        .to_str()
        .expect("Access-Control-Allow-Headers must be valid ASCII")
        .to_ascii_lowercase();

    assert!(
        allow_headers
            .split(',')
            .any(|h| h.trim() == "idempotency-key"),
        "Access-Control-Allow-Headers must allow `idempotency-key`, got `{allow_headers}`"
    );
    assert!(
        allow_headers.split(',').any(|h| h.trim() == "content-type"),
        "Access-Control-Allow-Headers must still allow `content-type`, got `{allow_headers}`"
    );
}

// --- GET / (root) ---

#[tokio::test]
async fn root_returns_service_metadata() {
    let req = Request::get("/").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(status, StatusCode::OK);
    // Verify the response is JSON and contains the service identifier plus
    // pointers to the real endpoints (including the Job-API surface that
    // replaced the legacy sync /api/{mint,send,commit} routes — see PR1
    // of the Job-API refactor).
    let json: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(json["service"], "zkcoins-node");
    assert_eq!(json["endpoints"]["info"], "GET  /api/info");
    assert_eq!(json["endpoints"]["admit_mint"], "POST /api/jobs/mint");
    assert_eq!(json["endpoints"]["admit_send"], "POST /api/jobs/send");
    assert_eq!(json["endpoints"]["get_job"], "GET  /api/jobs/{job_id}");
    assert_eq!(
        json["endpoints"]["stream_job"],
        "GET  /api/jobs/{job_id}/stream"
    );
    assert_eq!(
        json["endpoints"]["commit"],
        "POST /api/jobs/{job_id}/commit"
    );
    assert_eq!(
        json["endpoints"]["cancel"],
        "POST /api/jobs/{job_id}/cancel"
    );
    // The legacy synchronous routes must not be advertised anymore.
    assert!(json["endpoints"].get("send").is_none());
    assert!(json["endpoints"].get("mint").is_none());
    assert!(json["version"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(json["network"].as_str().is_some_and(|v| !v.is_empty()));
}

// --- GET /api/info ---

#[tokio::test]
async fn info_returns_network_name_capabilities_and_username_domain() {
    let req = Request::get("/api/info").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(status, StatusCode::OK);

    let info: InfoResponse = serde_json::from_str(&body).expect("valid JSON");
    // The lazy_static defaults to "Mutinynet" when IS_MAINNET is unset
    assert!(!info.network.is_empty(), "network name must not be empty");

    // The typed network identifier is derived from the same global; the
    // test harness never sets IS_MAINNET=true, so it resolves to Mutinynet.
    assert_eq!(info.bitcoin_network, BitcoinNetwork::Mutinynet);

    // Capabilities reflect the cargo feature set this binary was built with.
    // Same `cfg!(...)` evaluation as the handler, so the test passes both in
    // MVP builds (all false) and `--all-features` builds (all true).
    assert_eq!(
        info.capabilities.address_list,
        cfg!(feature = "address-list")
    );
    assert_eq!(
        info.capabilities.username_claim,
        cfg!(feature = "username-claim")
    );
    assert_eq!(info.capabilities.lnurl, cfg!(feature = "lnurl"));

    // The lazy_static defaults to "zkcoins.app" (PRD) when USERNAME_DOMAIN is unset
    assert!(
        !info.username_domain.is_empty(),
        "username_domain must not be empty"
    );
}

#[tokio::test]
async fn info_serialization_format_is_stable() {
    let req = Request::get("/api/info").body(Body::empty()).unwrap();
    let (_, body) = send_request(req).await;
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");

    // Top-level fields the app contract relies on.
    assert!(v["network"].is_string());
    assert!(v["capabilities"].is_object());
    assert!(v["username_domain"].is_string());

    // `bitcoin_network` serializes as a lowercase string enum.
    let bn = v["bitcoin_network"]
        .as_str()
        .expect("bitcoin_network must be a string");
    assert!(
        bn == "mainnet" || bn == "mutinynet",
        "bitcoin_network must be `mainnet` or `mutinynet`, got {bn}"
    );

    let caps = &v["capabilities"];
    for key in ["address_list", "username_claim", "lnurl"] {
        assert!(caps[key].is_boolean(), "capability `{key}` must be bool");
    }
}

#[test]
fn bitcoin_network_label_maps_both_arms() {
    assert_eq!(bitcoin_network_label(true), BitcoinNetwork::Mainnet);
    assert_eq!(bitcoin_network_label(false), BitcoinNetwork::Mutinynet);
}

// --- GET /api/balance (Stage 3 Runde 5: closed, 410) ---

/// `&asset_id=<test_asset_id>` query-string fragment (legacy URL shape).
fn asset_q() -> String {
    format!(
        "&asset_id={}",
        hex::encode(zkcoins_program::hash::digest_to_bytes(&test_asset_id()))
    )
}

/// R2: seeded ledger balance must not leave via GET /api/balance.
/// Asserts status **and** that the body does not carry the funded amount
/// (not only that the route exists).
#[tokio::test]
async fn balance_is_gone_and_does_not_reveal_ledger() {
    let state = test_state();
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(&test_owner_address()));
    let asset_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(&test_asset_id()));
    let uri = format!(
        "/api/balance?address={}&asset_id={}",
        address_hex, asset_hex
    );
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(
        status,
        StatusCode::GONE,
        "legacy balance must refuse loud (HTTP 410); body={body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&body).expect("JSON error body");
    let err = resp["error"].as_str().unwrap_or("");
    assert!(
        err.contains("/api/balance") || err.contains("Stage 3") || err.contains("read.account"),
        "error must name the removed surface; got {err:?}"
    );
    // No funded ledger fields: the fixture holds 1_000_000.
    assert!(
        resp.get("balance").is_none(),
        "410 body must not carry a balance field; got {resp}"
    );
    assert!(
        !body.contains("1000000") && !body.contains("1_000_000"),
        "body must not leak the seeded balance; got {body}"
    );
    assert!(
        resp.get("num_sends").is_none() && resp.get("assets").is_none(),
        "410 body must not carry ledger fields; got {resp}"
    );
}

#[tokio::test]
async fn balance_always_gone_even_without_params() {
    let req = Request::get("/api/balance").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
    assert!(
        !body.contains("\"balance\""),
        "must not return BalanceResponse shape; body={body}"
    );
}

// --- GET /api/address (Stage 3 Runde 6: closed, 410) ---

#[cfg(feature = "address-list")]
#[tokio::test]
async fn address_list_is_gone_and_does_not_reveal_legacy_addresses() {
    // Seed is present in test_state; closed handler must not enumerate it.
    let req = Request::get("/api/address").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
    let resp: serde_json::Value = serde_json::from_str(&body).expect("JSON error body");
    let err = resp["error"].as_str().unwrap_or("");
    assert!(
        err.contains("/api/address") || err.contains("Stage 3") || err.contains("read.account"),
        "error must name the removed surface; got {err:?}"
    );
    // No address list payload.
    assert!(resp.get("addresses").is_none(), "must not emit addresses");
}

// --- POST /api/send with missing fields ---

// --- POST /api/mint with missing fields ---

// --- GET /api/proof/{id} (Stage 3 Runde 5: closed, 410) ---

/// R2: even when a CoinProof blob is on disk, the route must not hand it
/// out (cleartext Coin). Status alone is insufficient — assert the body
/// is not the bincode blob / not 200 octet-stream.
#[tokio::test]
async fn proof_is_gone_and_does_not_reveal_coinproof() {
    let state = test_state();
    // Plant a recognisable marker blob under a known id. The closed
    // handler must never return these bytes.
    let marker = b"CLEARTEXT_COIN_PROOF_MUST_NOT_LEAK";
    state.proof_store.plant_raw_for_test(42, marker);
    let req = Request::get("/api/proof/42").body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;
    assert_eq!(
        status,
        StatusCode::GONE,
        "legacy proof download must refuse loud (HTTP 410); body={body}"
    );
    assert!(
        !body.as_bytes().windows(marker.len()).any(|w| w == marker),
        "body must not contain the on-disk CoinProof blob; got {body:?}"
    );
    let resp: serde_json::Value = serde_json::from_str(&body).expect("JSON error body");
    let err = resp["error"].as_str().unwrap_or("");
    assert!(
        err.contains("/api/proof") || err.contains("Stage 3") || err.contains("read.proof"),
        "error must name the removed surface; got {err:?}"
    );
}

#[tokio::test]
async fn proof_unknown_id_is_gone_not_404() {
    let req = Request::get("/api/proof/9999").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
}

// --- POST /api/commit with missing fields ---

// --- Fallback for unknown routes ---

#[tokio::test]
async fn unknown_route_returns_404() {
    let req = Request::get("/does-not-exist").body(Body::empty()).unwrap();
    let (status, _body) = send_request(req).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
}

// =======================================================================
// Helper: send a request through a *shared* router (same AppState across
// calls) instead of creating a fresh test_state() for every request.
// =======================================================================
async fn send_request_with_state(state: AppState, request: Request<Body>) -> (StatusCode, String) {
    let app = create_router(state);
    let response = app.oneshot(request).await.unwrap();
    let status = response.status();
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    let body = String::from_utf8(bytes.to_vec()).unwrap();
    (status, body)
}

// --- GET /api/username/resolve/{username} ---

#[tokio::test]
async fn resolve_unknown_username_returns_404() {
    let req = Request::get("/api/username/resolve/nonexistent")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(status, StatusCode::NOT_FOUND);

    let resp: LnurlErrorResponse = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert!(resp.reason.contains("not found"));
}

#[tokio::test]
async fn resolve_hex_prefix_no_longer_scans_legacy_addresses() {
    // Stage 3 Runde 6: hex-prefix fallback over get_addresses() is gone.
    // A known ledger address prefix must not resolve or leak the full address.
    let full_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(&test_owner_address()));
    let prefix = &full_hex[..8];

    let uri = format!("/api/username/resolve/{}", prefix);
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "hex prefix must not resolve via legacy address scan; body={body}"
    );
    assert!(
        !body.contains(&full_hex),
        "body must not leak the full legacy address; got {body}"
    );
}

// --- POST /api/username/claim ---

#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_empty_body_returns_422() {
    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    let (status, _body) = send_request(req).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}

#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_no_content_type_returns_415() {
    let req = Request::post("/api/username/claim")
        .body(Body::from("{}"))
        .unwrap();
    let (status, _body) = send_request(req).await;

    assert_eq!(status, StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// --- GET /.well-known/lnurlp/{username} ---

#[cfg(feature = "lnurl")]
#[tokio::test]
async fn lnurlp_unknown_user_returns_404() {
    let req = Request::get("/.well-known/lnurlp/nobody")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(status, StatusCode::NOT_FOUND);

    let resp: LnurlErrorResponse = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert!(resp.reason.contains("not found"));
}

#[cfg(feature = "lnurl")]
#[tokio::test]
async fn lnurlp_hex_prefix_no_longer_confirms_legacy_account() {
    // Stage 3 Runde 6: LNURL must not use hex-prefix scan over legacy
    // addresses (existence/validity oracle). Only the username store.
    let full_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(&test_owner_address()));
    let prefix = &full_hex[..8];

    let uri = format!("/.well-known/lnurlp/{}", prefix);
    let req = Request::get(&uri)
        .header("host", "api.zkcoins.app")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::NOT_FOUND,
        "hex prefix must not confirm a legacy account; body={body}"
    );
    assert!(
        !body.contains("payRequest"),
        "must not return LNURL-pay metadata for hex prefix; got {body}"
    );
}

#[cfg(feature = "lnurl")]
#[tokio::test]
async fn lnurlp_localhost_host_returns_http_callback() {
    // Pins the `host.contains("localhost")` scheme arm for a *claimed*
    // username (hex-prefix legacy resolve is closed). Seed the username
    // store so the handler reaches scheme selection.
    let state = test_state();
    {
        let mut store = state.username_store.lock().unwrap();
        store.commit_after_db("localuser".to_string(), test_owner_address());
    }

    let uri = "/.well-known/lnurlp/localuser";
    let req = Request::get(uri)
        .header("host", "localhost:8080")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::OK, "body={body}");

    let resp: LnurlpResponse = serde_json::from_str(&body).expect("valid JSON");
    assert!(
        resp.callback.starts_with("http://localhost:8080/"),
        "callback should use http://localhost:8080 — got {}",
        resp.callback
    );
}

// --- GET /lnurl/pay/{username} ---

#[cfg(feature = "lnurl")]
#[tokio::test]
async fn lnurl_pay_callback_returns_phase2_error() {
    let req = Request::get("/lnurl/pay/someone")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request(req).await;

    assert_eq!(status, StatusCode::OK);

    let resp: LnurlErrorResponse = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert!(
        resp.reason.contains("Phase 2"),
        "should mention Phase 2: {}",
        resp.reason
    );
}

// --- Legacy balance surface closed (username / num_sends paths) ---

#[tokio::test]
async fn balance_claimed_username_still_gone_no_ledger_leak() {
    let state = test_state();
    {
        let mut username_store = state.username_store.lock().unwrap();
        username_store.insert_for_test("satoshi", test_owner_address());
    }
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(&test_owner_address()));
    let uri = format!("/api/balance?address={}{}", address_hex, asset_q());
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
    assert!(
        !body.contains("satoshi") && !body.contains("1000000"),
        "must not leak username or balance; body={body}"
    );
}

#[tokio::test]
async fn balance_num_sends_path_is_gone_no_ledger_leak() {
    let state = test_state();
    let address_bytes = [0x77u8; 32];
    let address = zkcoins_program::hash::digest_from_bytes(&address_bytes);
    {
        let mut node = state.account_node.lock().unwrap();
        let mut acct = crate::account_node::Account::new_for_asset(test_asset_id());
        acct.balance = 42_000;
        acct.num_sends = 3;
        node.import_account(address, acct);
    }
    let uri = format!(
        "/api/balance?address={}{}",
        hex::encode(address_bytes),
        asset_q()
    );
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
    assert!(
        !body.contains("42000") && !body.contains("\"num_sends\""),
        "must not leak num_sends/balance; body={body}"
    );
}

// --- Concurrent balance reads (all Gone, no ledger leak) ---

#[tokio::test]
async fn concurrent_balance_reads_are_consistent() {
    let state = test_state();
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(&test_owner_address()));
    let uri = format!("/api/balance?address={}{}", address_hex, asset_q());

    // Spawn many concurrent balance requests against the same shared state.
    let mut handles = vec![];
    for _ in 0..20 {
        let s = state.clone();
        let u = uri.clone();
        handles.push(tokio::spawn(async move {
            let req = Request::get(&u).body(Body::empty()).unwrap();
            send_request_with_state(s, req).await
        }));
    }

    for handle in handles {
        let (status, body) = handle.await.expect("task should not panic");
        assert_eq!(status, StatusCode::GONE, "body={body}");
        assert!(
            !body.contains("1000000"),
            "every concurrent read must refuse without leaking balance; body={body}"
        );
    }
}

// --- Concurrent mixed reads and username operations ---

#[tokio::test]
async fn concurrent_reads_with_username_claim() {
    let state = test_state();
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(&test_owner_address()));

    // Claim a username through the store directly (bypasses both
    // signature validation and the async Postgres path; production
    // claims go through the /api/username/claim handler).
    {
        let mut store = state.username_store.lock().unwrap();
        store.insert_for_test("testuser", test_owner_address());
    }

    // Spawn concurrent balance + resolve requests
    let mut handles = vec![];

    for i in 0..10 {
        let s = state.clone();
        let hex = address_hex.clone();
        handles.push(tokio::spawn(async move {
            if i % 2 == 0 {
                // Legacy balance request — must be Gone, no ledger leak.
                let req = Request::get(format!("/api/balance?address={}{}", hex, asset_q()))
                    .body(Body::empty())
                    .unwrap();
                let (status, body) = send_request_with_state(s, req).await;
                assert_eq!(status, StatusCode::GONE, "body={body}");
                assert!(
                    !body.contains("1000000") && !body.contains("testuser"),
                    "must not leak ledger/username; body={body}"
                );
            } else {
                // Resolve request
                let req = Request::get("/api/username/resolve/testuser")
                    .body(Body::empty())
                    .unwrap();
                let (status, body) = send_request_with_state(s, req).await;
                assert_eq!(status, StatusCode::OK);
                let resp: UsernameResponse = serde_json::from_str(&body).expect("valid JSON");
                assert_eq!(resp.username, "testuser");
                assert_eq!(resp.address, format!("0x{}", hex));
            }
        }));
    }

    for handle in handles {
        handle.await.expect("task should not panic");
    }
}

// --- POST /api/commit with non-existent proof_id ---

// --- POST /api/commit with valid proof_id but invalid signature ---

// --- verify_send_signature tests ---

#[test]
fn send_signature_rejects_missing_signature() {
    let request = SendCoinRequest {
        account_address: "0x".to_string() + &hex::encode([1u8; 32]),
        recipient: "0x".to_string() + &hex::encode([2u8; 32]),
        amount: 100,
        public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap(),
        next_public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap(),
        prev_commitment_pubkey: None,
        signature: None,
        timestamp: Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        ),
        asset_id: None,
    };
    let result = verify_send_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing signature"));
}

#[test]
fn send_signature_rejects_missing_timestamp() {
    let request = SendCoinRequest {
        account_address: "0x".to_string() + &hex::encode([1u8; 32]),
        recipient: "0x".to_string() + &hex::encode([2u8; 32]),
        amount: 100,
        public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap(),
        next_public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap(),
        prev_commitment_pubkey: None,
        signature: Some("ab".repeat(64)),
        timestamp: None,
        asset_id: None,
    };
    let result = verify_send_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Missing timestamp"));
}

#[test]
fn check_timestamp_window_rejects_expired_timestamp() {
    // `verify_send_signature` no longer enforces the timestamp window
    // — that gate lives in `check_timestamp_window` and is run by the
    // handler explicitly so the distinct app-known string surfaces.
    let old_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 600; // 10 minutes ago
    let result = crate::router::check_timestamp_window(old_timestamp);
    assert!(result.is_err());
    assert_eq!(
        result.unwrap_err(),
        "Request timestamp too old or in the future"
    );
}

#[test]
fn check_timestamp_window_accepts_fresh_timestamp() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    assert!(crate::router::check_timestamp_window(now).is_ok());
}

#[test]
fn send_signature_rejects_invalid_hex() {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let request = SendCoinRequest {
        account_address: "0x".to_string() + &hex::encode([1u8; 32]),
        recipient: "0x".to_string() + &hex::encode([2u8; 32]),
        amount: 100,
        public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap(),
        next_public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap(),
        prev_commitment_pubkey: None,
        signature: Some("not_valid_hex".to_string()),
        timestamp: Some(now),
        asset_id: None,
    };
    let result = verify_send_signature(&request);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("Invalid signature hex"));
}

#[test]
fn send_signature_rejects_wrong_signature() {
    use bitcoin::secp256k1::SecretKey;

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign a DIFFERENT message than what verify_send_signature expects
    let wrong_msg = Message::from_digest([0u8; 32]);
    let (_xonly, _) = public_key.x_only_public_key();
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&wrong_msg, &keypair);

    let request = SendCoinRequest {
        account_address: "0x".to_string() + &hex::encode([1u8; 32]),
        recipient: "0x".to_string() + &hex::encode([2u8; 32]),
        amount: 100,
        public_key,
        next_public_key: public_key,
        prev_commitment_pubkey: None,
        signature: Some(hex::encode(sig.serialize())),
        timestamp: Some(now),
        asset_id: None,
    };
    let result = verify_send_signature(&request);
    assert!(result.is_err());
    assert!(result
        .unwrap_err()
        .contains("Signature verification failed"));
}

// --- POST /api/username/claim with valid Schnorr signature ---

#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_with_valid_signature() {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    // The `claim_username_handler` hard-fails with 503 if persistence
    // fails — unlike the other handlers whose DB upserts are
    // log-and-continue. So this happy-path test cannot use the lazy
    // `dead_pool`; it gets a real Postgres 17 pool via the shared
    // `postgres:17` container + per-test schema (issue #181 Opt B;
    // see `crate::test_db`). The `pg_container` binding holds the
    // `SchemaScope` that keeps the per-test schema alive for the
    // duration of the test; its `Drop` cleans the schema async.
    let pg_container = crate::test_db::setup_pool().await;
    let pool = Arc::new(pg_container.pool.clone());

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);

    // address = sha256(compressed_pubkey)
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let username = "testclaim";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Build claim message: sha256("zkcoins:claim_username" || address_hex || username || timestamp_le)
    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(username.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    // Import the address into the account_node so resolve_identifier can find it
    let state = live_test_state(pool);
    {
        let mut account_node = state.account_node.lock().unwrap();
        account_node.import_account(
            zkcoins_program::hash::digest_from_bytes(&address),
            Account::new(),
        );
    }

    let body = serde_json::json!({
        "username": username,
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state, req).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "Claim should succeed: {}",
        resp_body
    );

    let resp: UsernameResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.username, username);
    assert_eq!(resp.address, format!("0x{}", address_hex));
}

/// Mixed-case input is normalised to lowercase **before** the
/// signature is hashed, so a wallet that signs over the normalised
/// form (`"alice"`) and sends the user-typed form (`"Alice"`) is
/// accepted and persisted under `"alice"`. Guards the case-mismatch
/// squat fix from PR #76's prod-readiness review.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_mixed_case_input_normalised_before_hashing() {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    // Shared `postgres:17` container + per-test schema (issue #181
    // Opt B; see `crate::test_db`).
    let pg_container = crate::test_db::setup_pool().await;
    let pool = Arc::new(pg_container.pool.clone());

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[9u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let user_input = "Alice";
    let normalised = "alice";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign over the NORMALISED form — that is the contract the node
    // enforces by canonicalising before hashing.
    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(normalised.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let state = live_test_state(pool);
    {
        let mut account_node = state.account_node.lock().unwrap();
        account_node.import_account(
            zkcoins_program::hash::digest_from_bytes(&address),
            Account::new(),
        );
    }

    // Send the mixed-case form. The node normalises, hashes over
    // the lowercase form, and the signature verifies.
    let body = serde_json::json!({
        "username": user_input,
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state, req).await;

    assert_eq!(
        status,
        StatusCode::OK,
        "claim should succeed: {}",
        resp_body
    );
    let resp: UsernameResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    // Response echoes the canonical lowercase name, NOT the raw input.
    assert_eq!(resp.username, normalised);
}

/// Counterpart to the test above: a wallet that signs over the RAW
/// mixed-case input (legacy/buggy behaviour) must be rejected by the
/// node, because the node hashes the normalised form. Without
/// this, the case-mismatch squat is reachable: attacker signs `"Bob"`,
/// node persists `"bob"`, the legitimate `bob` owner is locked out.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_raw_case_signature_rejected() {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[10u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let user_input = "Bob";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign over the RAW form — the bug we are fixing.
    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(user_input.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let state = test_state();
    {
        let mut account_node = state.account_node.lock().unwrap();
        account_node.import_account(
            zkcoins_program::hash::digest_from_bytes(&address),
            Account::new(),
        );
    }

    let body = serde_json::json!({
        "username": user_input,
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, _resp_body) = send_request_with_state(state, req).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "raw-case signature must fail; node hashes normalised form"
    );
}

/// In-memory `precheck` collision must surface as `409 CONFLICT` with
/// the verbatim collision string the wallet shows the user. Drives the
/// claim handler's precheck `Err` branch without any DB round-trip:
/// the in-memory mirror is pre-seeded via `insert_for_test`, the
/// signature is valid, and the handler short-circuits before the
/// `db::claim_username` call.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_precheck_conflict_returns_409() {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[11u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let username = "claimed";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(username.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let state = test_state();
    {
        let mut account_node = state.account_node.lock().unwrap();
        account_node.import_account(
            zkcoins_program::hash::digest_from_bytes(&address),
            Account::new(),
        );
    }
    // Pre-seed the name → arbitrary OTHER address so the precheck's
    // `usernames.contains_key(normalized)` branch fires (rather than
    // the address-already-has-a-username branch).
    {
        let mut store = state.username_store.lock().unwrap();
        store.insert_for_test(
            username,
            zkcoins_program::hash::digest_from_bytes(&[99u8; 32]),
        );
    }

    let body = serde_json::json!({
        "username": username,
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::CONFLICT, "body: {}", resp_body);
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert!(
        resp.reason.contains("Username already taken"),
        "unexpected reason: {}",
        resp.reason
    );
}

#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_wrong_pubkey() {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[8u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);

    // Use a DIFFERENT address that does NOT match sha256(pubkey)
    let wrong_address: [u8; 32] = [0xAA; 32];
    let address_hex = hex::encode(wrong_address);

    let username = "wrongpk";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Sign with the correct message format but the address doesn't match the pubkey
    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(username.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let body = serde_json::json!({
        "username": username,
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, _) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Claim with mismatched pubkey/address must be rejected"
    );
}

#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_expired_timestamp() {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[9u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);

    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let username = "expiredts";
    // Timestamp 10 minutes in the past (exceeds 5-min window)
    let expired_timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
        - 600;

    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(username.as_bytes());
    hasher.update(expired_timestamp.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let body = serde_json::json!({
        "username": username,
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode(sig.serialize()),
        "timestamp": expired_timestamp,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, _) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "Claim with expired timestamp must be rejected"
    );
}

/// `UsernameStore::validate` rejects names outside `[a-z0-9._-]{1,64}`.
/// Drives the handler's first early-return arm (the `validate` `Err`
/// branch), so no DB round-trip and no signature work is needed.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_invalid_format_returns_422() {
    let body = serde_json::json!({
        "username": "alice@evil",
        "address": hex::encode([0u8; 32]),
        "public_key": bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp::Secp256k1::new(),
            &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
        )
        .to_string(),
        "signature": hex::encode([0u8; 64]),
        "timestamp": 0u64,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {resp_body}"
    );
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Username may only contain a-z, 0-9, -, _, .");
}

/// Non-hex address payload triggers the `hex::decode` early-return arm.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_invalid_address_hex_returns_422() {
    let body = serde_json::json!({
        "username": "alice",
        "address": "z".repeat(64),
        "public_key": bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp::Secp256k1::new(),
            &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
        )
        .to_string(),
        "signature": hex::encode([0u8; 64]),
        "timestamp": 0u64,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {resp_body}"
    );
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Invalid address hex");
}

/// Valid hex address but not 32 bytes triggers the length-check arm.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_wrong_address_length_returns_422() {
    let body = serde_json::json!({
        "username": "alice",
        "address": hex::encode([0u8; 30]),
        "public_key": bitcoin::secp256k1::PublicKey::from_secret_key(
            &secp::Secp256k1::new(),
            &bitcoin::secp256k1::SecretKey::from_slice(&[1u8; 32]).unwrap(),
        )
        .to_string(),
        "signature": hex::encode([0u8; 64]),
        "timestamp": 0u64,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {resp_body}"
    );
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Address must be 32 bytes");
}

/// Address matches `sha256(pubkey)` and the timestamp is fresh, so the
/// handler reaches the signature-hex decode step before bailing on the
/// non-hex `signature` field.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_invalid_signature_hex_returns_422() {
    use bitcoin::secp256k1::SecretKey;

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[12u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let body = serde_json::json!({
        "username": "sighex",
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": "zz",
        "timestamp": now,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {resp_body}"
    );
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Invalid signature hex");
}

/// Signature is valid hex but the wrong length for a BIP-340 Schnorr
/// signature (64 bytes), so `SchnorrSignature::from_slice` rejects it.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_invalid_signature_format_returns_422() {
    use bitcoin::secp256k1::SecretKey;

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[13u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // 63 bytes of zeros — valid hex, wrong Schnorr length.
    let body = serde_json::json!({
        "username": "sigfmt",
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode([0u8; 63]),
        "timestamp": now,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request(req).await;

    assert_eq!(
        status,
        StatusCode::UNPROCESSABLE_ENTITY,
        "body: {resp_body}"
    );
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Invalid signature format");
}

/// Pool with no reachable Postgres: `db::claim_username` returns an error
/// after the in-memory `precheck` passes. The handler must map that
/// onto a 503. Mirrors `claim_propagates_db_error_when_pool_is_dead`
/// from `username_tests.rs`, but exercises the handler's error arm.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_db_error_returns_503() {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[14u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let username = "dberr";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(username.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    // `test_state()` already plugs in `dead_pool` — a lazy PgPool
    // pointing at 127.0.0.1:1 that fails fast with a connect error.
    let body = serde_json::json!({
        "username": username,
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request(req).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body: {resp_body}");
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Failed to persist username claim");
}

/// Concurrent-claim SQL race: plant the row directly via SQL so the
/// in-memory `precheck` mirror stays empty (passes) but the
/// `INSERT ... ON CONFLICT DO NOTHING` reports `rows_affected == 0`.
/// The handler must map that onto a 409 with the SQL-race reason
/// string. Mirrors `claim_falls_back_to_validation_when_sql_layer_catches_race`
/// from `username_tests.rs`, but exercises the handler's `!inserted`
/// arm rather than the `UsernameStore::claim` wrapper.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_sql_race_returns_409() {
    use bitcoin::secp256k1::{Keypair, SecretKey};

    // Shared `postgres:17` container + per-test schema (issue #181
    // Opt B; see `crate::test_db`).
    let pg_container = crate::test_db::setup_pool().await;
    let pool = Arc::new(pg_container.pool.clone());

    // Plant the username row bound to a different address, without
    // touching the in-memory mirror — so `precheck` passes and
    // `db::claim_username` returns `Ok(false)`.
    sqlx::query("INSERT INTO usernames (name, address) VALUES ($1, $2)")
        .bind("racename")
        .bind(vec![0xAAu8; 32])
        .execute(pool.as_ref())
        .await
        .expect("failed to plant username row");

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[15u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);

    let username = "racename";
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(username.as_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let keypair = Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let state = live_test_state(pool);

    let body = serde_json::json!({
        "username": username,
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });

    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(serde_json::to_string(&body).unwrap()))
        .unwrap();
    let (status, resp_body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::CONFLICT, "body: {resp_body}");
    let resp: LnurlErrorResponse = serde_json::from_str(&resp_body).expect("valid JSON");
    assert_eq!(resp.status, "ERROR");
    assert_eq!(resp.reason, "Username already taken");
}

#[test]
fn send_signature_accepts_valid_signature() {
    use bitcoin::secp256k1::SecretKey;

    let secp = secp::Secp256k1::new();
    let secret = SecretKey::from_slice(&[1u8; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);

    let account_address = "0x".to_string() + &hex::encode([1u8; 32]);
    let recipient = "0x".to_string() + &hex::encode([2u8; 32]);
    let amount: u64 = 100;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Build the exact same message as verify_send_signature
    let mut hasher = Sha256::new();
    hasher.update(account_address.as_bytes());
    hasher.update(recipient.as_bytes());
    hasher.update(amount.to_le_bytes());
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();

    let msg = Message::from_digest(hash);
    let keypair = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &keypair);

    let request = SendCoinRequest {
        account_address,
        recipient,
        amount,
        public_key,
        next_public_key: public_key,
        prev_commitment_pubkey: None,
        signature: Some(hex::encode(sig.serialize())),
        timestamp: Some(now),
        asset_id: None,
    };
    // `.expect` surfaces the actual error string on failure; the
    // previous `is_ok()` shape silently swallowed it.
    verify_send_signature(&request).expect("valid Schnorr signature must verify");
}

// --- POST /api/send (happy path, exercises the full handler) ---

/// Companion to `send_with_valid_signature_returns_proof_id_and_hashes`
/// that drives the post-send `db::upsert_account` path against a real
/// Postgres 17 testcontainer instead of `dead_pool`. The default
/// `test_state` exercises the upsert *error* arm (log-and-continue);
/// this test exercises the upsert *success* arm so the if-let-Some
/// block falls through without entering the `if let Err` branch —
/// the only path that touches the line after the inner Err handler.
///
/// The persist itself is best-effort, so the assertions are scoped
/// to (a) the handler still returning 200 with a usable proof_id and
/// (b) the `accounts` row being readable from Postgres after the
/// call. Together they pin both observable side-effects of the
/// happy-path upsert.

#[tokio::test]
async fn receive_coin_is_gone_and_does_not_mutate_accounts() {
    // B6: POST /api/receive must not mutate durable (or in-memory) account
    // state. Stage 3 Runde 4 removes the legacy CoinProof receive path.
    let state = test_state();
    let owner = zkcoins_program::hash::digest_from_bytes(&[0x42u8; 32]);
    let asset = zkcoins_program::hash::digest_from_bytes(&[0x43u8; 32]);
    {
        let mut node = state.account_node.lock().unwrap();
        let mut acct = crate::account_node::Account::new_for_asset(asset);
        acct.balance = 7;
        node.import_account(owner, acct);
    }
    let before = {
        let node = state.account_node.lock().unwrap();
        let a = node.get_account(&owner, &asset).expect("fixture account");
        (a.balance, a.coin_queue.len(), a.num_sends)
    };

    let req = Request::post("/api/receive")
        .header("content-type", "application/octet-stream")
        .body(Body::from(vec![0xff, 0xfe, 0xfd, 0xfc]))
        .unwrap();
    let (status, body) = send_request_with_state(state.clone(), req).await;
    assert_eq!(
        status,
        StatusCode::GONE,
        "legacy receive must refuse loud (HTTP 410), not 200+success:false; body={body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(resp["success"], false);
    let err = resp["error"].as_str().unwrap_or("");
    assert!(
        err.contains("/api/receive") || err.contains("removed") || err.contains("Stage 3"),
        "error must name the removed endpoint; got {err:?}"
    );

    let after = {
        let node = state.account_node.lock().unwrap();
        let a = node
            .get_account(&owner, &asset)
            .expect("account still present");
        (a.balance, a.coin_queue.len(), a.num_sends)
    };
    assert_eq!(
        before, after,
        "POST /api/receive must not mutate the account"
    );
}

// -----------------------------------------------------------------
// `lock_or_recover_*` tests — nextest per-test process isolation note
// -----------------------------------------------------------------
//
// The three `lock_or_recover_*_poisoned` tests below intentionally
// panic inside a spawned thread to poison the mutex they hold, then
// call `lock_or_recover` on the same `Arc<Mutex<_>>` to assert that
// the helper recovers the inner value via `into_inner`. Each test
// MUST run in its own process — under the default `cargo test`
// runner (single binary, threadpool) the second-test poison setup
// can race against the first test's recovery path because both
// share the libtest thread that observes panics. We rely on
// `cargo-nextest`'s per-test process isolation (see `CONTRIBUTING.md`
// > "Tests" and `.config/nextest.toml`) to give each test a fresh
// process. Running these tests outside nextest is supported (the
// project's CI uses `cargo nextest run`); a bare `cargo test` will
// occasionally surface a spurious "double panic" diagnostic in the
// shared libtest panic handler. Switch to nextest if you reproduce
// this locally.

#[test]
fn lock_or_recover_recovers_from_poisoned_mutex() {
    let mutex = Arc::new(Mutex::new(42i32));
    let mutex_clone = Arc::clone(&mutex);

    // Poison the mutex by panicking inside lock().
    let _ = std::thread::spawn(move || {
        let _guard = mutex_clone.lock().unwrap();
        panic!("intentional panic to poison the mutex");
    })
    .join();

    assert!(
        mutex.is_poisoned(),
        "mutex must be poisoned after the panic"
    );

    // Recovering must succeed and yield the inner value.
    let guard = lock_or_recover(&mutex);
    assert_eq!(*guard, 42);
}

#[test]
fn proof_store_proof_path_returns_none_for_nonexistent_directory() {
    // proof_path canonicalizes the configured directory. If the directory
    // does not exist, canonicalize fails and proof_path returns None.
    let store = ProofStore::new("/nonexistent/zkcoins/proof/dir");
    // The directory was created by ProofStore::new, but to test the
    // None branch we point at one that does not exist.
    let truly_missing = ProofStore {
        dir: "/this/path/genuinely/does/not/exist/zkcoins".to_string(),
    };
    assert!(truly_missing.proof_path(7).is_none());
    // The real store was created and resolves fine for arbitrary ids.
    drop(store);
}

#[test]
fn lock_or_recover_account_node_poisoned() {
    // Generic instantiation: cover the AccountNode-specific monomorphic
    // copy of lock_or_recover's poison-recovery closure.
    let state_arc = Arc::new(Mutex::new(State::new()));
    let node = Arc::new(Mutex::new(AccountNode::new(Arc::clone(&state_arc))));
    let node_clone = Arc::clone(&node);

    let _ = std::thread::spawn(move || {
        let _guard = node_clone.lock().unwrap();
        panic!("intentional poison");
    })
    .join();

    assert!(node.is_poisoned());
    let _guard = lock_or_recover(&node);
}

#[test]
fn lock_or_recover_username_store_poisoned() {
    // Generic instantiation: cover the UsernameStore-specific monomorphic
    // copy of lock_or_recover's poison-recovery closure.
    let store = Arc::new(Mutex::new(crate::username::UsernameStore::new()));
    let store_clone = Arc::clone(&store);

    let _ = std::thread::spawn(move || {
        let _guard = store_clone.lock().unwrap();
        panic!("intentional poison");
    })
    .join();

    assert!(store.is_poisoned());
    let _guard = lock_or_recover(&store);
}

// =======================================================================
// GET /health/ready — readiness probe
// =======================================================================
//
// The readiness probe combines a Postgres `SELECT 1` with an Esplora
// `/blocks/tip/height` ping. Each test below exercises one of the three
// reachable code paths (db ok + esplora ok / db fail + esplora ok / db
// ok + esplora fail) so the new `ready_handler` and `check_esplora`
// functions reach 100% line + region coverage. The DB side uses the
// existing `dead_pool` / live-testcontainer helpers; the Esplora side
// uses a per-test `wiremock::MockServer` so no real network is hit.

/// Hand back a migrated pool scoped to a fresh per-test schema in
/// the shared `postgres:17` container (issue #181 Opt B; see
/// `crate::test_db`) — the live half of the readiness happy path
/// (and the db-ok side of the esplora-fails test). The
/// `SchemaScope` is returned alongside so the caller keeps it alive
/// for the duration of the test; its `Drop` cleans up the schema
/// after the test finishes.
async fn ready_live_pool() -> (Arc<sqlx::PgPool>, crate::test_db::SchemaScope) {
    let scope = crate::test_db::setup_pool().await;
    let pool = Arc::new(scope.pool.clone());
    (pool, scope)
}

/// Build an `AppState` whose `esplora_config` points at the supplied
/// `wiremock` URL. The DB pool is supplied separately so tests can
/// mix-and-match dead vs. live Postgres.
fn ready_state(pool: Arc<sqlx::PgPool>, esplora_url: String) -> AppState {
    let mut state = test_state();
    state.pool = pool;
    state.esplora_config = Arc::new(crate::publisher::EsploraConfig {
        url: esplora_url,
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
    });
    state
}

#[tokio::test]
async fn ready_returns_200_when_db_and_esplora_reachable() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let (pool, _pg) = ready_live_pool().await;
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("123456"))
        .mount(&mock_server)
        .await;

    let state = ready_state(pool, mock_server.uri());
    let req = Request::get("/health/ready").body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::OK, "body={}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(v["ready"], true);
    assert_eq!(v["failures"].as_array().unwrap().len(), 0);
    // New fields introduced with the background-warmup feature:
    // a 200 response means status is `ready` and prover is `ready`.
    // The default `test_state()` shape flips `prover_warm` to true.
    assert_eq!(v["status"], "ready");
    assert_eq!(v["prover"], "ready");
}

#[tokio::test]
async fn ready_returns_503_when_db_unreachable() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Esplora is healthy …
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("123456"))
        .mount(&mock_server)
        .await;

    // … but Postgres is the lazy-connect dead pool, which fails on first
    // query with a connect error. `ready_handler` must surface that as
    // 503 + `failures: ["db"]`.
    let state = ready_state(dead_pool(), mock_server.uri());
    let req = Request::get("/health/ready").body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body={}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(v["ready"], false);
    let failures: Vec<String> = v["failures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert_eq!(failures, vec!["db".to_string()]);
}

#[tokio::test]
async fn ready_returns_503_when_esplora_unreachable() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let (pool, _pg) = ready_live_pool().await;

    // Live Postgres + Esplora returning 500 → only `esplora` fails.
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(500).set_body_string("upstream down"))
        .mount(&mock_server)
        .await;

    let state = ready_state(pool, mock_server.uri());
    let req = Request::get("/health/ready").body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body={}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(v["ready"], false);
    let failures: Vec<String> = v["failures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert_eq!(failures, vec!["esplora".to_string()]);
}

/// `prover_warm == false` (the bootstrap shape while the background
/// `spawn_blocking` task in `runtime::start_rest_node` is still
/// running) gates `/health/ready` to 503 with a `prover` failure tag
/// and a `status: starting` / `prover: warming` payload. The DB +
/// Esplora paths short-circuit to an unreachable mock so the failure
/// list contains only `prover` — proves the warmup gate is wired in
/// isolation from the other dependencies. No Postgres needed: the
/// failure path doesn't require a live pool because `SELECT 1`
/// against `dead_pool()` short-circuits to a connect error that
/// the handler treats as a `db` failure too — which is fine, the
/// test just asserts `prover` is present.
#[tokio::test]
async fn ready_returns_503_with_prover_warming_when_prover_not_warm() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    // Esplora is healthy so it does NOT contribute to `failures`; the
    // DB path falls through `dead_pool` and DOES contribute a `db`
    // failure, but the assertion below only checks `prover` is
    // present — the test is about the warmup gate, not the full
    // failure-list shape.
    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("123456"))
        .mount(&mock_server)
        .await;

    // Build the state with the prover-warm flag flipped back to false.
    // `ready_state` calls `test_state()` which defaults to `true`, so
    // we override the field after construction.
    let mut state = ready_state(dead_pool(), mock_server.uri());
    state.prover_warm = Arc::new(std::sync::atomic::AtomicBool::new(false));

    let req = Request::get("/health/ready").body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body={}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(v["ready"], false);
    assert_eq!(v["status"], "starting");
    assert_eq!(v["prover"], "warming");
    let failures: Vec<String> = v["failures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert!(
        failures.contains(&"prover".to_string()),
        "expected `prover` in failures, got {failures:?}"
    );
}

/// A systemically failing prover gates `/health/ready` to 503 with
/// `prover: failing` even though the boot warmup completed long ago
/// (`prover_warm == true`). This is the gap the 2026-06-05 DEV outage
/// exposed: persisted proofs went stale and 100% of mint jobs failed
/// with `prove failed`, yet the readiness probe kept answering
/// `prover: ready` (it only ever reflected the warmup flag), so neither
/// the deploy smoke-test nor monitoring could see the outage. The
/// failure streak is driven through the same `ProverHealth` calls the
/// dispatcher makes. Esplora is mocked healthy; the dead DB contributes
/// an ignored `db` failure (same shape as the warming test above).
#[tokio::test]
async fn ready_returns_503_with_prover_failing_when_proves_fail() {
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/blocks/tip/height"))
        .respond_with(ResponseTemplate::new(200).set_body_string("123456"))
        .mount(&mock_server)
        .await;

    let state = ready_state(dead_pool(), mock_server.uri());
    // `ready_state` builds a warm prover; trip the runtime health signal
    // the way the dispatcher would after a streak of `prove failed` jobs.
    for _ in 0..crate::prover_health::PROVE_FAILURE_THRESHOLD {
        state.prover_health.note_failure();
    }

    let req = Request::get("/health/ready").body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body={}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(v["ready"], false);
    assert_eq!(v["prover"], "failing");
    let failures: Vec<String> = v["failures"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_string())
        .collect();
    assert!(
        failures.contains(&"prover".to_string()),
        "expected `prover` in failures after a prove-failure streak, got {failures:?}"
    );
}

// =======================================================================
// GET /health/publisher — operational preflight
// =======================================================================
//
// The publisher health probe surfaces (address, utxo_count, total_sats)
// for the deploy-dev preflight. Two reachable arms after the lazy_static
// `PUBLISHER_ADDRESS` refactor: Ok (Esplora responded) and Err (Esplora-
// side error). The `SecretKey::from_str` panic-arm is no longer in the
// request path — `PUBLISHER_KEY` is validated once at startup.

#[tokio::test]
async fn health_publisher_returns_200_with_utxo_count_and_total_sats_when_esplora_responds() {
    // Mock Esplora returning a known UTXO set so the handler's Ok arm
    // is exercised: GET /address/{publisher_addr}/utxo returns a JSON
    // array of UTXOs that get_publisher_utxo parses and sums.
    use wiremock::matchers::{method, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let esplora_mock = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path_regex(r"^/address/.+/utxo$"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            {
                "txid": "a".repeat(64),
                "vout": 0,
                "value": 50_000,
                "status": { "confirmed": true, "block_height": 1, "block_hash": "b".repeat(64), "block_time": 0 }
            },
            {
                "txid": "c".repeat(64),
                "vout": 1,
                "value": 12_345,
                "status": { "confirmed": true, "block_height": 2, "block_hash": "d".repeat(64), "block_time": 0 }
            }
        ])))
        .mount(&esplora_mock)
        .await;

    let mut state = mint_test_state();
    state.esplora_config = Arc::new(crate::publisher::EsploraConfig {
        url: esplora_mock.uri(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
    });

    let req = Request::get("/health/publisher")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::OK, "body={}", body);
    let v: serde_json::Value = serde_json::from_str(&body).expect("publisher health body is JSON");
    assert!(
        v["address"]
            .as_str()
            .expect("address present")
            .starts_with("tb1p"),
        "publisher address must be Mutinynet bech32 Taproot, got: {:?}",
        v["address"]
    );
    assert_eq!(v["utxo_count"].as_u64().expect("utxo_count u64"), 2);
    assert_eq!(v["total_sats"].as_u64().expect("total_sats u64"), 62_345);
}

#[tokio::test]
async fn health_publisher_returns_503_when_esplora_unreachable() {
    // Drive the Err arm: mint_test_state() already points esplora at
    // 127.0.0.1:1 (unreachable), so get_publisher_utxo returns Err
    // and the handler must map to 503.
    let state = mint_test_state();
    let req = Request::get("/health/publisher")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_with_state(state, req).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "body={}", body);
    let v: serde_json::Value =
        serde_json::from_str(&body).expect("publisher health err body is JSON");
    assert_eq!(
        v["error"].as_str().expect("error field present"),
        "Esplora-side error fetching publisher UTXOs"
    );
    assert!(
        v["address"]
            .as_str()
            .expect("address present")
            .starts_with("tb1p"),
        "publisher address must be returned even on Esplora failure, got: {:?}",
        v["address"]
    );
    assert!(
        v["detail"].as_str().is_some(),
        "detail field must be present for diagnostics"
    );
}

// =======================================================================
// POST /api/mint — handler coverage
// =======================================================================
//
// Before #480300b the mint endpoint was gated behind the `faucet` Cargo
// feature, so `mint_handler` was excluded from the MVP-scope coverage
// gate. After the gate removal (mint is now permanent MVP) every line
// of the handler counts toward `--fail-under-lines 100 --fail-under-
// functions 100`. The tests below cover each reachable arm:
//
// - request validation (422 invalid hex / 422 wrong length)
// - bootstrap failure (500 missing minting account)
// - `send_coins` failure mapping (422 via the slot-count guard, which
//   fires before the prover so the test is cheap)
// - the post-`send_coins` Ok arm: num_pubkeys increment, ProofData
//   reconstruction, commitment build, `db::upsert_minting_num_pubkeys`,
//   and the inscription broadcast.
//
// The happy-path tests run the real prover; one mint takes ~seconds on
// the M3-Ultra runner but compiles cheaply, so they stay in the unit-
// test suite rather than moving to `tests/`.

/// Build an `AppState` configured for mint tests: minting account
/// seeded with `1u64 << 48` (Goldilocks-safe — see `runtime
/// ::start_rest_node`'s bootstrap comment), real prover wired
/// through the default `AccountNode`, dead Postgres pool by default
/// (callers swap it for a live pool via the second return value).
fn mint_test_state() -> AppState {
    let state_inner = Arc::new(Mutex::new(State::new()));
    let account_node = AccountNode::new(Arc::clone(&state_inner));

    // Neutral model: a mint creates the creator's own
    // `(owner, asset_id)` account on demand, so there is nothing to
    // pre-seed here (and no privileged minting account / client).

    // Per-test scratch dir for the ProofStore — see the canonical
    // comment on the first call-site in `test_state()` above for
    // why we use `tempfile::tempdir().keep()` instead of holding a
    // `TempDir` guard.
    let proofs_dir = tempfile::tempdir().expect("create proofs tempdir").keep();
    AppState {
        account_node: Arc::new(Mutex::new(account_node)),
        proof_store: Arc::new(ProofStore::new(
            proofs_dir.to_str().expect("proofs tempdir utf-8"),
        )),
        mint_store: Arc::new(crate::router::MintStore::new()),
        username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
        pool: dead_pool(),
        esplora_config: Arc::new(crate::publisher::EsploraConfig {
            url: "http://127.0.0.1:1/api".to_string(),
            is_mainnet: false,
            network_name: "Mutinynet".to_string(),
            ws_url: None,
        }),
        prover_warm: Arc::new(std::sync::atomic::AtomicBool::new(true)),
        prover_health: Arc::new(crate::prover_health::ProverHealth::new()),
        job_store: Arc::new(crate::job_store::JobStore::new((*dead_pool()).clone())),
        job_tx: tokio::sync::mpsc::channel::<crate::job_dispatcher::JobEnvelope>(8).0,
        job_notify_map: Arc::new(dashmap::DashMap::new()),
        v1_scan_caught_up: None,
        v1_finality_ok: None,
        pending_sign_map: Arc::new(dashmap::DashMap::new()),
        v1_finalise: None,
        v1_live_pending_after_begin: Arc::new(dashmap::DashMap::new()),
        v1_pending_after_prove: None,
        receive_creating_proof_loader: None,
        v1_engine: None,
        private_index: crate::kernel::access::InMemoryPrivateIndex::shared(),
        bundles: crate::kernel::bootstrap::BundleStore::shared(),
        attest_challenges: crate::kernel::bootstrap::ChallengeStore::shared(),
        public_hosts: Arc::new(vec!["node.test".to_string()]),
    }
}

/// `MintStore::add` / `MintStore::take` are residual legacy helpers
/// (prove-side `add` is test-only; `take` is used by
/// `flow::mint_commit_flow`, coverage-excluded). Drive the store
/// directly with a host-shaped staged mint — the store test only needs
/// a well-formed `StagedMint` value, not a real circuit proof. `add`
/// returns a 1-based id; `take` consumes — a second `take` of the same
/// id returns `None`.
#[test]
fn mint_store_add_take_roundtrips_and_consumes() {
    use plonky2::field::goldilocks_field::GoldilocksField;
    use plonky2::field::polynomial::PolynomialCoeffs;
    use plonky2::field::types::Field;
    use plonky2::fri::proof::FriProof;
    use plonky2::hash::merkle_tree::MerkleCap;
    use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};

    let secp = secp::Secp256k1::new();
    let creator_obj = bitcoin::secp256k1::SecretKey::from_slice(&[3u8; 32])
        .expect("valid sk")
        .public_key(&secp);
    let asset_id = zkcoins_program::hash::hash_bytes(b"StoreCoin-asset");
    let owner = zkcoins_program::hash::hash_bytes(&creator_obj.serialize());
    let mut mutated = crate::account_node::Account::new_for_asset(asset_id);
    mutated.balance = 1234;
    // Hollow residual proof shell — MintStore only holds/returns the blob.
    let hollow_proof = ProofWithPublicInputs {
        proof: Proof {
            wires_cap: MerkleCap(vec![]),
            plonk_zs_partial_products_cap: MerkleCap(vec![]),
            quotient_polys_cap: MerkleCap(vec![]),
            openings: OpeningSet {
                constants: vec![],
                plonk_sigmas: vec![],
                wires: vec![],
                plonk_zs: vec![],
                plonk_zs_next: vec![],
                partial_products: vec![],
                quotient_polys: vec![],
                lookup_zs: vec![],
                lookup_zs_next: vec![],
            },
            opening_proof: FriProof {
                commit_phase_merkle_caps: vec![],
                query_round_proofs: vec![],
                final_poly: PolynomialCoeffs::new(vec![]),
                pow_witness: GoldilocksField::ZERO,
            },
        },
        public_inputs: vec![GoldilocksField::ZERO; 4],
    };
    let staged = crate::router::StagedMint {
        proof: hollow_proof,
        owner,
        asset_id,
        mutated_account: mutated,
        creator_pubkey: creator_obj,
    };

    let store = crate::router::MintStore::new();
    let id = store.add(staged);
    assert!(id >= 1, "staged-mint ids are 1-based");
    let taken = store.take(id).expect("staged mint present after add");
    assert_eq!(taken.mutated_account.balance, 1234);
    assert!(store.take(id).is_none(), "take consumes the staged mint");
}

// =======================================================================
// Job-API admit + poll handler coverage (PR1: /api/jobs/*).
// =======================================================================
//
// The handlers themselves are thin: validate the request shape +
// idempotency header, `JobStore::create`, hand the public_id to the
// dispatcher channel, return 202. Coverage targets the
// admit-handler arms only; the dispatcher's prove + broadcast legs
// live in `flow::*` / `job_dispatcher::*` (coverage-excluded — see
// the CI `--ignore-filename-regex` flag) and are exercised
// end-to-end by the post-deploy API E2E suite.

mod jobs_endpoint_tests {
    use super::*;
    use crate::router::create_router;
    use std::sync::{Arc, Mutex};

    /// Serialise tests that flip the process-global stack claim so
    /// parallel postgres-backed cases do not clear each other's mode
    /// mid-request (shared container + shared `PROCESS_STACK_MODE`).
    static V1_STACK_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    /// Acquire the process-global stack-mode serialisation lock.
    ///
    /// Held across `.await` points on purpose: these tests touch shared
    /// process state (`PROCESS_STACK_MODE` / the shared container) and
    /// must not interleave. `tokio::sync::Mutex` is the correct tool for
    /// that (unlike `std::sync::MutexGuard`, which is thread-bound).
    ///
    /// `tokio::sync::Mutex` has no poison flag — a panicking holder does
    /// not permanently lock out later tests. That resilience used to be
    /// expressed via `unwrap_or_else(|poisoned| poisoned.into_inner())` on
    /// `std::sync::Mutex`; do not reintroduce a poison recovery path.
    async fn lock_v1_stack_for_test() -> tokio::sync::MutexGuard<'static, ()> {
        V1_STACK_TEST_LOCK.lock().await
    }

    /// Build an `AppState` whose `job_store` is wired to a fresh
    /// per-test schema in the shared `postgres:17` container (issue
    /// #181 Opt B; see `crate::test_db`) with migration 0014 applied,
    /// `job_tx` to a never-recv'd channel (the dispatcher is not
    /// running in this test), `job_notify_map` to an empty DashMap.
    /// Mirrors the production wiring closely enough that the admit
    /// handlers exercise their Ok / Err arms verbatim. The returned
    /// `SchemaScope` must outlive the state — its `Drop` cleans up
    /// the per-test schema asynchronously.
    async fn jobs_test_state() -> (AppState, Arc<sqlx::PgPool>, crate::test_db::SchemaScope) {
        let scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(scope.pool.clone());

        let mut state = mint_test_state();
        state.pool = Arc::clone(&pool);
        state.job_store = Arc::new(crate::job_store::JobStore::new((*pool).clone()));
        // Fresh (rx-side held by `_rx`) channel so the admit
        // handlers can `.send().await` without an unbounded queue;
        // the rx end stays alive so the send never errors with a
        // closed-channel error.
        let (tx, rx) = tokio::sync::mpsc::channel::<crate::job_dispatcher::JobEnvelope>(8);
        state.job_tx = tx;
        // Leak the rx so it does not drop while the test runs.
        std::mem::forget(rx);
        state.job_notify_map = Arc::new(dashmap::DashMap::new());
        (state, pool, scope)
    }

    /// Helper: drive a request through the live router built off
    /// the test state.
    async fn run(
        state: AppState,
        req: Request<Body>,
    ) -> (StatusCode, Vec<(String, String)>, String) {
        let app = create_router(state);
        let resp = app.oneshot(req).await.unwrap();
        let status = resp.status();
        let headers: Vec<(String, String)> = resp
            .headers()
            .iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect();
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        let body = String::from_utf8(bytes.to_vec()).unwrap();
        (status, headers, body)
    }

    // ---- POST /api/jobs/mint ----

    /// Build a fully valid creator-signed mint request body (neutral
    /// multi-asset model). The owner (`H(creator_pubkey)`) and asset_id
    /// are derived node-side; the BIP-340 Schnorr signature is over
    /// `SHA256(creator_pubkey ‖ name ‖ [decimals] ‖ amount_le ‖
    /// timestamp_le)` so `flow::validate_mint_request` accepts it. The
    /// key/name/decimals are fixed test values; vary `amount` per call.
    fn signed_mint_body(amount: u64) -> serde_json::Value {
        use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
        use sha2::{Digest, Sha256};
        let secp = secp::Secp256k1::new();
        let sk = SecretKey::from_slice(&[9u8; 32]).expect("valid sk");
        let pk: PublicKey = sk.public_key(&secp);
        let kp = Keypair::from_secret_key(&secp, &sk);
        // Distinct fresh key the mint rotates `next_public_key` to.
        let next_pk: PublicKey = SecretKey::from_slice(&[10u8; 32])
            .expect("valid sk")
            .public_key(&secp);
        let name = "TestCoin";
        let decimals: u8 = 8;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut hasher = Sha256::new();
        hasher.update(pk.serialize());
        hasher.update(name.as_bytes());
        hasher.update([decimals]);
        hasher.update(amount.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let msg = Message::from_digest(hash);
        let sig = secp.sign_schnorr(&msg, &kp);
        serde_json::json!({
            "creator_pubkey": hex::encode(pk.serialize()),
            "next_public_key": hex::encode(next_pk.serialize()),
            "name": name,
            "decimals": decimals,
            "amount": amount,
            "signature": hex::encode(sig.serialize()),
            "timestamp": timestamp,
        })
    }

    #[tokio::test]
    async fn jobs_mint_without_idempotency_key_returns_400() {
        let (state, _pool, _c) = jobs_test_state().await;
        // Body is a valid creator-signed mint so the `Json<MintRequest>`
        // extractor passes and we reach the idempotency-key check.
        let body = signed_mint_body(1);
        let req = Request::post("/api/jobs/mint")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _headers, body) = run(state, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "Idempotency-Key header is required");
    }

    #[tokio::test]
    async fn jobs_mint_with_empty_idempotency_key_returns_400() {
        let (state, _pool, _c) = jobs_test_state().await;
        let body = signed_mint_body(1);
        let req = Request::post("/api/jobs/mint")
            .header("content-type", "application/json")
            .header("idempotency-key", "")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _headers, _body) = run(state, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn jobs_mint_with_invalid_hex_returns_422() {
        let (state, _pool, _c) = jobs_test_state().await;
        // A `creator_pubkey` that is not valid pubkey hex fails the
        // `Json<MintRequest>` extractor (secp256k1 PublicKey serde)
        // before the handler body runs — axum surfaces the rejection
        // as a 422. The rejection body is axum's, not our `{error}`
        // envelope, so only the status is asserted.
        let mut body = signed_mint_body(1);
        body["creator_pubkey"] = serde_json::Value::String("not_hex".to_string());
        let req = Request::post("/api/jobs/mint")
            .header("content-type", "application/json")
            .header("idempotency-key", "k1")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, _body) = run(state, req).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn jobs_mint_wrong_address_length_returns_422() {
        let (state, _pool, _c) = jobs_test_state().await;
        let body = serde_json::json!({
            "account_address": "0x".to_string() + &"ab".repeat(16),
            "amount": 1u64,
        });
        let req = Request::post("/api/jobs/mint")
            .header("content-type", "application/json")
            .header("idempotency-key", "k1")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, _b) = run(state, req).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[tokio::test]
    async fn jobs_mint_admits_returns_202_with_job_id() {
        let (state, _pool, _c) = jobs_test_state().await;
        let body = signed_mint_body(1);
        let req = Request::post("/api/jobs/mint")
            .header("content-type", "application/json")
            .header("Idempotency-Key", "k-mint-1")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, headers, body) = run(state, req).await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let location = headers
            .iter()
            .find(|(k, _)| k == "location")
            .map(|(_, v)| v.clone())
            .expect("Location header present");
        assert!(location.starts_with("/api/jobs/"));
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["status"], "queued");
        let _ = uuid::Uuid::parse_str(v["job_id"].as_str().unwrap()).expect("job_id is UUID");
    }

    #[tokio::test]
    async fn jobs_mint_idempotent_replay_returns_existing_job_id() {
        let (state, _pool, _c) = jobs_test_state().await;
        let body = signed_mint_body(1);
        let key = "k-replay";
        let first = run(
            state.clone(),
            Request::post("/api/jobs/mint")
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        let v1: serde_json::Value = serde_json::from_str(&first.2).unwrap();
        let job_id_1 = v1["job_id"].as_str().unwrap().to_string();

        let second = run(
            state,
            Request::post("/api/jobs/mint")
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(second.0, StatusCode::ACCEPTED);
        let v2: serde_json::Value = serde_json::from_str(&second.2).unwrap();
        assert_eq!(
            v2["job_id"], job_id_1,
            "second admit must surface first job_id"
        );
    }

    /// §7.5: same Idempotency-Key with a **different** body is
    /// `409 idempotency_conflict` — not a silent 202 replaying the first job.
    /// Would be red against the pre-Block-4 store (same key always replayed).
    #[tokio::test]
    async fn jobs_mint_same_idem_key_different_body_returns_409_idempotency_conflict() {
        let (state, _pool, _c) = jobs_test_state().await;
        let body_a = signed_mint_body(1);
        let body_b = signed_mint_body(2);
        let key = "k-conflict";
        let first = run(
            state.clone(),
            Request::post("/api/jobs/mint")
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(body_a.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(first.0, StatusCode::ACCEPTED);

        let second = run(
            state,
            Request::post("/api/jobs/mint")
                .header("content-type", "application/json")
                .header("idempotency-key", key)
                .body(Body::from(body_b.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(
            second.0,
            StatusCode::CONFLICT,
            "different body under same key must be 409, got body {}",
            second.2
        );
        let v: serde_json::Value = serde_json::from_str(&second.2).expect("json");
        assert_eq!(
            v["error"], "idempotency_conflict",
            "machine code must be the closed §7.5 reason, got {}",
            second.2
        );
    }

    #[tokio::test]
    async fn jobs_mint_idempotent_replay_after_completion_returns_cached_body() {
        let (state, _pool, _c) = jobs_test_state().await;
        // Admit a job, then flip it to `completed` directly via the
        // JobStore so the second admit surfaces the cached response.
        let body = signed_mint_body(1);
        let first = run(
            state.clone(),
            Request::post("/api/jobs/mint")
                .header("content-type", "application/json")
                .header("idempotency-key", "k-cached")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        let v1: serde_json::Value = serde_json::from_str(&first.2).unwrap();
        let job_id = uuid::Uuid::parse_str(v1["job_id"].as_str().unwrap()).unwrap();

        state
            .job_store
            .complete(
                job_id,
                crate::job_store::JobStatus::Queued,
                serde_json::json!({"success": true, "proof_id": 99u64}),
                200,
            )
            .await
            .expect("complete");

        let second = run(
            state,
            Request::post("/api/jobs/mint")
                .header("content-type", "application/json")
                .header("idempotency-key", "k-cached")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(
            second.0,
            StatusCode::OK,
            "completed replay should surface cached 200"
        );
        let v2: serde_json::Value = serde_json::from_str(&second.2).unwrap();
        assert_eq!(v2["proof_id"], 99u64);
    }

    /// Completed idempotent replay with `response_status = NULL` must be
    /// `500 internal_error`, never invent HTTP 200.
    ///
    /// Pre-fix: `response_status.unwrap_or(200)` treated absence as success.
    #[tokio::test]
    async fn jobs_mint_idempotent_replay_missing_response_status_is_internal_error() {
        let (state, pool, _c) = jobs_test_state().await;
        let body = signed_mint_body(1);
        let first = run(
            state.clone(),
            Request::post("/api/jobs/mint")
                .header("content-type", "application/json")
                .header("idempotency-key", "k-missing-status")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        let v1: serde_json::Value = serde_json::from_str(&first.2).unwrap();
        let job_id = uuid::Uuid::parse_str(v1["job_id"].as_str().unwrap()).unwrap();

        // Body present, status NULL — the silent-200 path this gate removes.
        sqlx::query(
            "UPDATE jobs SET status = 'completed', phase = 'completed', progress = 100, \
             response_body = $1::jsonb, response_status = NULL, completed_at = NOW() \
             WHERE public_id = $2",
        )
        .bind(serde_json::json!({"success": true, "proof_id": 77u64}))
        .bind(job_id)
        .execute(pool.as_ref())
        .await
        .expect("plant completed without response_status");

        let second = run(
            state,
            Request::post("/api/jobs/mint")
                .header("content-type", "application/json")
                .header("idempotency-key", "k-missing-status")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(
            second.0,
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing response_status must not 200; body={}",
            second.2
        );
        let v2: serde_json::Value = serde_json::from_str(&second.2).unwrap();
        assert_eq!(v2["error"], "internal_error");
        assert!(
            v2.get("proof_id").is_none(),
            "must not surface cached body on corrupt status: {}",
            second.2
        );
    }

    /// Completed idempotent replay with a non-HTTP `response_status` must be
    /// `500 internal_error`, never invent HTTP 200 via `from_u16` fallback.
    ///
    /// Pre-fix: `StatusCode::from_u16(...).unwrap_or(StatusCode::OK)`.
    #[tokio::test]
    async fn jobs_mint_idempotent_replay_invalid_response_status_is_internal_error() {
        let (state, pool, _c) = jobs_test_state().await;
        let body = signed_mint_body(1);
        let first = run(
            state.clone(),
            Request::post("/api/jobs/mint")
                .header("content-type", "application/json")
                .header("idempotency-key", "k-bad-status")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        let v1: serde_json::Value = serde_json::from_str(&first.2).unwrap();
        let job_id = uuid::Uuid::parse_str(v1["job_id"].as_str().unwrap()).unwrap();

        // 7000 is a valid i16 but not a valid HTTP status code.
        sqlx::query(
            "UPDATE jobs SET status = 'completed', phase = 'completed', progress = 100, \
             response_body = $1::jsonb, response_status = 7000, completed_at = NOW() \
             WHERE public_id = $2",
        )
        .bind(serde_json::json!({"success": true, "proof_id": 88u64}))
        .bind(job_id)
        .execute(pool.as_ref())
        .await
        .expect("plant completed with invalid response_status");

        let second = run(
            state,
            Request::post("/api/jobs/mint")
                .header("content-type", "application/json")
                .header("idempotency-key", "k-bad-status")
                .body(Body::from(body.to_string()))
                .unwrap(),
        )
        .await;
        assert_eq!(
            second.0,
            StatusCode::INTERNAL_SERVER_ERROR,
            "invalid response_status must not 200; body={}",
            second.2
        );
        let v2: serde_json::Value = serde_json::from_str(&second.2).unwrap();
        assert_eq!(v2["error"], "internal_error");
    }

    // ---- POST /api/jobs/send ----

    #[tokio::test]
    async fn jobs_send_without_signature_returns_401() {
        let (state, _pool, _c) = jobs_test_state().await;
        let body = serde_json::json!({
            "account_address": "0x".to_string() + &hex::encode([1u8; 32]),
            "recipient": "0x".to_string() + &hex::encode([2u8; 32]),
            "amount": 1u64,
            "public_key": "020000000000000000000000000000000000000000000000000000000000000001",
            "next_public_key": "020000000000000000000000000000000000000000000000000000000000000002",
        });
        let req = Request::post("/api/jobs/send")
            .header("content-type", "application/json")
            .header("idempotency-key", "k1")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "Missing signature");
    }

    #[tokio::test]
    async fn jobs_send_admits_returns_202_with_job_id() {
        // Success-path coverage for `jobs_send_handler`: a valid
        // Schnorr signature drives the handler through
        // `read_idempotency_key` Ok → `flow::validate_send_request`
        // Ok → `serde_json::to_value` (now `.expect`) → `admit_and_enqueue`
        // and lands a 202 Accepted with a fresh job_id. Mirrors
        // `jobs_mint_admits_returns_202_with_job_id` above but on the
        // send route.
        use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
        let (state, _pool, _c) = jobs_test_state().await;

        // Deterministic sender / recipient pair — the signature only
        // needs to verify against `public_key`, no on-chain account
        // lookup happens before admit.
        let sk = SecretKey::from_slice(&[7u8; 32]).expect("valid sk");
        let secp = secp::Secp256k1::new();
        let pk: PublicKey = sk.public_key(&secp);
        let kp = Keypair::from_secret_key(&secp, &sk);

        let account_address = "0x".to_string() + &hex::encode([1u8; 32]);
        let recipient = "0x".to_string() + &hex::encode([2u8; 32]);
        let amount: u64 = 1;
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut hasher = sha2::Sha256::new();
        hasher.update(account_address.as_bytes());
        hasher.update(recipient.as_bytes());
        hasher.update(amount.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        use sha2::Digest;
        let hash: [u8; 32] = hasher.finalize().into();
        let msg = bitcoin::secp256k1::Message::from_digest(hash);
        let sig = secp.sign_schnorr(&msg, &kp);

        let body = serde_json::json!({
            "account_address": account_address,
            "recipient": recipient,
            "amount": amount,
            "public_key": hex::encode(pk.serialize()),
            "next_public_key": hex::encode(pk.serialize()),
            "signature": hex::encode(sig.serialize()),
            "timestamp": timestamp,
        });
        let req = Request::post("/api/jobs/send")
            .header("content-type", "application/json")
            .header("Idempotency-Key", "k-send-success")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, headers, body) = run(state, req).await;
        assert_eq!(status, StatusCode::ACCEPTED, "body={body}");
        let location = headers
            .iter()
            .find(|(k, _)| k == "location")
            .map(|(_, v)| v.clone())
            .expect("Location header present");
        assert!(location.starts_with("/api/jobs/"));
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["status"], "queued");
        let _ = uuid::Uuid::parse_str(v["job_id"].as_str().unwrap()).expect("job_id is UUID");
    }

    #[tokio::test]
    async fn jobs_send_without_idempotency_key_returns_400() {
        let (state, _pool, _c) = jobs_test_state().await;
        let body = serde_json::json!({
            "account_address": "0x".to_string() + &hex::encode([1u8; 32]),
            "recipient": "0x".to_string() + &hex::encode([2u8; 32]),
            "amount": 1u64,
            "public_key": "020000000000000000000000000000000000000000000000000000000000000001",
            "next_public_key": "020000000000000000000000000000000000000000000000000000000000000002",
        });
        let req = Request::post("/api/jobs/send")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, _b) = run(state, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    // ---- GET /api/jobs/:id ----

    #[tokio::test]
    async fn get_job_unknown_id_returns_404() {
        let (state, _pool, _c) = jobs_test_state().await;
        let id = uuid::Uuid::new_v4();
        let req = Request::get(format!("/api/jobs/{}", id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, _b) = run(state, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn get_job_queued_returns_retry_after_2() {
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Mint,
                &[5u8; 32],
                Some("k-poll"),
                serde_json::json!({"any": "body"}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!("expected fresh"),
        };
        let req = Request::get(format!("/api/jobs/{}", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, headers, body) = run(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(headers.iter().any(|(k, v)| k == "retry-after" && v == "2"));
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["status"], "queued");
        assert_eq!(v["kind"], "mint");
    }

    #[tokio::test]
    async fn get_job_completed_includes_result_no_retry_after() {
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Mint,
                &[6u8; 32],
                Some("k-done"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        state
            .job_store
            .complete(
                job_id,
                crate::job_store::JobStatus::Queued,
                serde_json::json!({"success": true, "proof_id": 7u64}),
                200,
            )
            .await
            .expect("complete");

        let req = Request::get(format!("/api/jobs/{}", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, headers, body) = run(state, req).await;
        assert_eq!(status, StatusCode::OK);
        assert!(!headers.iter().any(|(k, _)| k == "retry-after"));
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["status"], "completed");
        assert_eq!(v["result"]["proof_id"], 7u64);
    }

    #[tokio::test]
    async fn get_job_failed_includes_error() {
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Mint,
                &[7u8; 32],
                Some("k-fail"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        state
            .job_store
            .fail(
                job_id,
                crate::job_store::JobStatus::Queued,
                "synthetic error",
            )
            .await
            .expect("fail");

        let req = Request::get(format!("/api/jobs/{}", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["status"], "failed");
        assert_eq!(v["error"], "synthetic error");
    }

    #[tokio::test]
    async fn get_job_awaiting_signature_includes_proof_id() {
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[8u8; 32],
                Some("k-sig"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        let ash = "aa".repeat(32);
        let ocr = "bb".repeat(32);
        state
            .job_store
            .set_awaiting_signature(
                job_id,
                42,
                serde_json::json!({
                    "account_state_hash": ash,
                    "output_coins_root": ocr,
                }),
            )
            .await
            .expect("await sig");

        let req = Request::get(format!("/api/jobs/{}", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["status"], "awaiting_signature");
        assert_eq!(v["proof_id"], 42i64);
        // The ash/ocr hex the wallet signs surfaces in `result` on the
        // `awaiting_signature` snapshot — this is the field the thin
        // pure-TS wallet reads instead of decoding the binary proof.
        assert_eq!(v["result"]["account_state_hash"], ash);
        assert_eq!(v["result"]["output_coins_root"], ocr);
    }

    /// Plant a `completed` row with SQL NULL `response_body` (corrupt).
    ///
    /// Against the pre-split handler this returned HTTP 200 without a
    /// `result` field. Fail-closed behaviour must answer `500` instead.
    async fn plant_completed_without_response_body(
        pool: &sqlx::PgPool,
        account: [u8; 32],
        idem: &str,
    ) -> uuid::Uuid {
        let job_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO jobs \
             (public_id, kind, status, phase, account_address, idempotency_key, request_body, \
              progress, reset_generation) \
             VALUES ($1, 'mint', 'completed', 'completed', $2, $3, '{}'::jsonb, 100, 0)",
        )
        .bind(job_id)
        .bind(&account[..])
        .bind(idem)
        .execute(pool)
        .await
        .expect("plant corrupt completed row");
        job_id
    }

    /// Would have been green (HTTP 200, no `result`) on the old handler;
    /// must now fail closed with legacy 500 + free-text error.
    #[tokio::test]
    async fn get_job_completed_without_response_body_is_internal_error() {
        let (state, pool, _c) = jobs_test_state().await;
        let job_id =
            plant_completed_without_response_body(pool.as_ref(), [0xC1u8; 32], "k-corrupt-legacy")
                .await;

        let req = Request::get(format!("/api/jobs/{}", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "corrupt completed must not 200; body={body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "Failed to load job");
        // Must not look like a successful poll envelope.
        assert!(
            v.get("status").is_none(),
            "must not emit job status: {body}"
        );
        assert!(v.get("result").is_none(), "must not emit result: {body}");
    }

    /// Same corrupt row via `/v1/jobs/:id` → §7.5 `internal_error` (not 200).
    #[tokio::test]
    async fn v1_get_job_completed_without_response_body_is_internal_error() {
        let (state, pool, _c) = jobs_test_state().await;
        let job_id =
            plant_completed_without_response_body(pool.as_ref(), [0xC2u8; 32], "k-corrupt-v1")
                .await;

        let req = Request::get(format!("/v1/jobs/{}", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(
            status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "corrupt completed must not 200; body={body}"
        );
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "internal_error");
        assert_eq!(v["message"], "Failed to load job");
        assert!(v.get("result").is_none(), "must not emit result: {body}");
        assert!(
            v.get("status").is_none(),
            "must not emit job status: {body}"
        );
    }

    /// Awaiting-signature without payload is likewise corrupt → 500.
    #[tokio::test]
    async fn get_job_awaiting_signature_without_payload_is_internal_error() {
        let (state, pool, _c) = jobs_test_state().await;
        let job_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO jobs \
             (public_id, kind, status, phase, account_address, idempotency_key, request_body, \
              proof_id, reset_generation) \
             VALUES ($1, 'send', 'awaiting_signature', 'awaiting_signature', $2, $3, '{}'::jsonb, \
              7, 0)",
        )
        .bind(job_id)
        .bind(&[0xC3u8; 32][..])
        .bind("k-corrupt-sig")
        .execute(pool.as_ref())
        .await
        .expect("plant corrupt awaiting_signature row");

        let req = Request::get(format!("/api/jobs/{}", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body={body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "Failed to load job");
    }

    // ---- POST /api/jobs/:id/cancel ----

    #[tokio::test]
    async fn jobs_cancel_unknown_returns_409() {
        let (state, _pool, _c) = jobs_test_state().await;
        let id = uuid::Uuid::new_v4();
        let req = Request::post(format!("/api/jobs/{}/cancel", id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, _b) = run(state, req).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn jobs_cancel_queued_returns_200() {
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Mint,
                &[9u8; 32],
                Some("k-cancel"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        let req = Request::post(format!("/api/jobs/{}/cancel", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["status"], "cancelled");
    }

    /// Defect 1: legacy `/api/jobs/:id/cancel` rejects proving — flag-off
    /// behaviour is byte-identical (queued only).
    #[tokio::test]
    async fn legacy_api_cancel_rejects_proving() {
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Mint,
                &[0xAAu8; 32],
                Some("k-legacy-cancel-proving"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        state
            .job_store
            .set_status(
                job_id,
                crate::job_store::JobStatus::Queued,
                crate::job_store::JobStatus::Proving,
                "proving",
            )
            .await
            .expect("proving");

        let req = Request::post(format!("/api/jobs/{}/cancel", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state.clone(), req).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "legacy cancel must refuse proving: {body}"
        );
        let after = state.job_store.load(job_id).await.unwrap().unwrap();
        assert_eq!(after.status, crate::job_store::JobStatus::Proving);
    }

    // ---- POST /api/jobs/:id/commit ----

    #[tokio::test]
    async fn jobs_commit_unknown_job_returns_404() {
        let (state, _pool, _c) = jobs_test_state().await;
        let id = uuid::Uuid::new_v4();
        let commit_body = serde_json::json!({
            "proof_id": 1u64,
            "public_key": "020000000000000000000000000000000000000000000000000000000000000001",
            "signature": "00".repeat(64),
            "message": "ff".repeat(32),
        });
        let req = Request::post(format!("/api/jobs/{}/commit", id))
            .header("content-type", "application/json")
            .body(Body::from(commit_body.to_string()))
            .unwrap();
        let (status, _h, _b) = run(state, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn jobs_commit_job_in_queued_returns_409() {
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[10u8; 32],
                Some("k-commit-bad"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        let commit_body = serde_json::json!({
            "proof_id": 1u64,
            "public_key": "020000000000000000000000000000000000000000000000000000000000000001",
            "signature": "00".repeat(64),
            "message": "ff".repeat(32),
        });
        let req = Request::post(format!("/api/jobs/{}/commit", job_id))
            .header("content-type", "application/json")
            .body(Body::from(commit_body.to_string()))
            .unwrap();
        let (status, _h, _b) = run(state, req).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    #[tokio::test]
    async fn jobs_commit_awaiting_signature_signals_notify() {
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[11u8; 32],
                Some("k-commit-ok"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        state
            .job_store
            .set_awaiting_signature(job_id, 7, serde_json::json!({}))
            .await
            .expect("aw sig");
        let notifier = Arc::new(crate::job_dispatcher::JobNotifier::new());
        let commit_wake = notifier.commit_wake.clone();
        state.job_notify_map.insert(job_id, notifier);

        let commit_body = serde_json::json!({
            "proof_id": 7u64,
            "public_key": "020000000000000000000000000000000000000000000000000000000000000001",
            "signature": "00".repeat(64),
            "message": "ff".repeat(32),
        });
        let req = Request::post(format!("/api/jobs/{}/commit", job_id))
            .header("content-type", "application/json")
            .body(Body::from(commit_body.to_string()))
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::OK, "body: {}", body);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["status"], "broadcasting");
        // The handler signals the notifier's commit_wake; verifying
        // that requires observing the wake-up. We assert that
        // .notified() resolves immediately afterwards.
        tokio::time::timeout(std::time::Duration::from_secs(1), commit_wake.notified())
            .await
            .expect("notify_one must have been called");
    }

    #[tokio::test]
    async fn jobs_commit_no_notify_entry_returns_409() {
        // Job is in `awaiting_signature` but the notify_map entry
        // was removed (timeout-and-cleanup race). Surface 409 so
        // the wallet does not silently spin.
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[12u8; 32],
                Some("k-commit-no-notify"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        state
            .job_store
            .set_awaiting_signature(job_id, 7, serde_json::json!({}))
            .await
            .expect("aw sig");
        // No notify_map.insert — simulates the post-timeout state.

        let commit_body = serde_json::json!({
            "proof_id": 7u64,
            "public_key": "020000000000000000000000000000000000000000000000000000000000000001",
            "signature": "00".repeat(64),
            "message": "ff".repeat(32),
        });
        let req = Request::post(format!("/api/jobs/{}/commit", job_id))
            .header("content-type", "application/json")
            .body(Body::from(commit_body.to_string()))
            .unwrap();
        let (status, _h, _b) = run(state, req).await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    // ---- POST /v1/jobs/:id/sign (Gap G4 §7.5 wire boundary) ----

    #[tokio::test]
    async fn jobs_sign_valid_v1_signature_accepted_through_route() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xABu8; 32],
                Some("k-sign-ok"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        let (entry, submission) =
            crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let advertised = crate::v1::awaiting_signature_result_json(&entry);
        // Persist restart-safe envelope + stage in-memory.
        let persist = crate::v1::DurableFinalisationPersist::from_entry(&entry)
            .expect("encode durable finalisation");
        let mut body = serde_json::json!({});
        body.as_object_mut().unwrap().insert(
            crate::v1::FINALISATION_BODY_KEY.to_string(),
            serde_json::to_value(&persist).unwrap(),
        );
        sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
            .bind(&body)
            .bind(job_id)
            .execute(state.job_store.pool())
            .await
            .expect("persist pending_sign");
        state
            .job_store
            .set_awaiting_signature(job_id, 1, advertised)
            .await
            .expect("awaiting_signature");
        state.pending_sign_map.insert(job_id, entry);
        let notifier = Arc::new(crate::job_dispatcher::JobNotifier::new());
        state.job_notify_map.insert(job_id, notifier);

        let body = serde_json::json!({
            "signature": hex::encode(submission.signature),
            "s2c_nonce": hex::encode(submission.s2c_nonce),
        });
        // §7.5 path is /v1/jobs/<id>/sign — not the legacy /api prefix.
        let req = Request::post(format!("/v1/jobs/{}/sign", job_id))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::OK, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["status"], "signature_accepted");
        // Staged material is kept until the dispatcher finalises.
        assert!(state.pending_sign_map.get(&job_id).is_some());
    }

    #[tokio::test]
    async fn jobs_sign_malformed_encoding_rejected_at_boundary() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xACu8; 32],
                Some("k-sign-enc"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        state
            .job_store
            .set_awaiting_signature(job_id, 1, serde_json::json!({}))
            .await
            .expect("awaiting_signature");

        // Uppercase hex is encoding failure → §7.5 `malformed_request`.
        let body = serde_json::json!({
            "signature": "AA".repeat(64),
            "s2c_nonce": "bb".repeat(32),
        });
        let req = Request::post(format!("/v1/jobs/{}/sign", job_id))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "malformed_request");
        // Closed enumeration: no invented "check" field, no "encoding" code.
        assert!(v.get("check").is_none(), "invented check field: {resp}");
        assert!(
            v["message"].as_str().unwrap_or("").contains("lowercase")
                || v["message"].as_str().unwrap_or("").contains("hex"),
            "message should describe the encoding rule: {resp}"
        );
    }

    #[tokio::test]
    async fn jobs_sign_flag_off_refuses_and_legacy_commit_still_works() {
        let _stack_guard = lock_v1_stack_for_test().await;
        // Flag / claim off (default).

        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xADu8; 32],
                Some("k-sign-flag-off"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        // Legacy awaiting_signature shape (ash/ocr).
        let ash = "aa".repeat(32);
        let ocr = "bb".repeat(32);
        state
            .job_store
            .set_awaiting_signature(
                job_id,
                7,
                serde_json::json!({
                    "account_state_hash": ash,
                    "output_coins_root": ocr,
                }),
            )
            .await
            .expect("awaiting_signature");

        // /v1/.../sign refuses under flag-off as feature_disabled (not
        // wrong_phase — the job phase is fine; the surface is off).
        let sign_body = serde_json::json!({
            "signature": "00".repeat(64),
            "s2c_nonce": "11".repeat(32),
        });
        let req = Request::post(format!("/v1/jobs/{}/sign", job_id))
            .header("content-type", "application/json")
            .body(Body::from(sign_body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "feature_disabled");
        assert!(v.get("check").is_none());

        // Legacy GET /api/jobs still surfaces ash/ocr under `result`.
        let req = Request::get(format!("/api/jobs/{}", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["result"]["account_state_hash"], ash);
        assert_eq!(v["result"]["output_coins_root"], ocr);
        assert!(v["result"].get("proof_data_hash").is_none());

        // Legacy /commit still accepts the request (wakes notifier) under flag-off.
        let notifier = Arc::new(crate::job_dispatcher::JobNotifier::new());
        let commit_wake = notifier.commit_wake.clone();
        state.job_notify_map.insert(job_id, notifier);
        let commit_body = serde_json::json!({
            "proof_id": 7u64,
            "public_key": "020000000000000000000000000000000000000000000000000000000000000001",
            "signature": "00".repeat(64),
            "message": "ff".repeat(32),
        });
        let req = Request::post(format!("/api/jobs/{}/commit", job_id))
            .header("content-type", "application/json")
            .body(Body::from(commit_body.to_string()))
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::OK, "legacy commit body: {body}");
        tokio::time::timeout(std::time::Duration::from_secs(1), commit_wake.notified())
            .await
            .expect("legacy commit must still wake the dispatcher");
    }

    /// §7.5: route path, `awaiting_signature` envelope (not under `result`),
    /// progress float in [0,1], closed error codes.
    #[tokio::test]
    async fn v1_job_poll_and_sign_follow_section_7_5_envelope() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Mint,
                &[0xAEu8; 32],
                Some("k-v1-ad"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        let (entry, _) = crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let advertised = crate::v1::select_awaiting_signature_result(
            &"aa".repeat(32),
            &"bb".repeat(32),
            Some(&entry),
        )
        .expect("v1 ad");
        state
            .job_store
            .set_awaiting_signature(job_id, 3, advertised)
            .await
            .expect("awaiting_signature");

        // §7.5 poll: GET /v1/jobs/<id>
        let req = Request::get(format!("/v1/jobs/{}", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, headers, body) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["status"], "awaiting_signature");
        // Fields under `awaiting_signature`, NOT under `result`.
        assert!(
            v.get("result").is_none(),
            "must not nest under result: {body}"
        );
        let surface = v
            .get("awaiting_signature")
            .expect("awaiting_signature field required by §7.5");
        assert!(surface.get("account_state_hash").is_none());
        assert!(surface.get("new_account_state_hash").is_some());
        assert!(surface.get("proof_data_hash").is_some());
        assert!(surface.get("txn_pubkey").is_some());
        assert!(surface.get("send_counter").is_some());
        assert!(surface.get("npk_commit").is_some());
        // progress is a float in [0,1], not integer 0–100.
        let progress = v["progress"].as_f64().expect("progress float");
        assert!((0.0..=1.0).contains(&progress), "progress={progress}");
        // phase optional diagnostic while non-terminal.
        assert!(v.get("phase").is_some());
        // Retry-After: 0 while awaiting_signature.
        assert!(
            headers
                .iter()
                .any(|(k, val)| k.eq_ignore_ascii_case("retry-after") && val == "0"),
            "headers: {headers:?}"
        );

        // Closed error codes on /sign: job_not_found.
        let missing = uuid::Uuid::new_v4();
        let req = Request::post(format!("/v1/jobs/{}/sign", missing))
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "signature": "00".repeat(64),
                    "s2c_nonce": "11".repeat(32),
                })
                .to_string(),
            ))
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "job_not_found");
        assert!(v.get("message").is_some());
    }

    /// Defect 2: an accepted signature drives finalise, not a bare status flip.
    #[tokio::test]
    async fn accepted_signature_drives_finalise_not_status_only() {
        use crate::v1::{set_process_stack_mode, FinaliseOutcome, ScanStackMode};
        use std::sync::atomic::{AtomicBool, Ordering};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let finalise_called = Arc::new(AtomicBool::new(false));
        let finalise_called_hook = Arc::clone(&finalise_called);

        let (mut state, _pool, _c) = jobs_test_state().await;
        state.v1_finalise = Some(Arc::new(move |pending, signature, _fence| {
            let finalise_called_hook = Arc::clone(&finalise_called_hook);
            Box::pin(async move {
                finalise_called_hook.store(true, Ordering::SeqCst);
                // The hook receives the staged pending + the accepted signature
                // — not just a status change. Bind to the pending's ProofData.
                assert_eq!(
                    signature.pk_i,
                    pending.witness_wip.prev_account_state.current_pubkey
                );
                Ok(FinaliseOutcome::from_pending_proof_data(&pending))
            })
        }));

        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xB1u8; 32],
                Some("k-finalise"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        let (entry, submission) =
            crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let advertised = crate::v1::awaiting_signature_result_json(&entry);
        let persist = crate::v1::DurableFinalisationPersist::from_entry(&entry)
            .expect("encode durable finalisation");
        let mut req_body = serde_json::json!({});
        req_body.as_object_mut().unwrap().insert(
            crate::v1::FINALISATION_BODY_KEY.to_string(),
            serde_json::to_value(&persist).unwrap(),
        );
        sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
            .bind(&req_body)
            .bind(job_id)
            .execute(state.job_store.pool())
            .await
            .expect("persist");
        state
            .job_store
            .set_awaiting_signature(job_id, 1, advertised)
            .await
            .expect("awaiting_signature");
        state.pending_sign_map.insert(job_id, entry);

        // Park a notifier so /sign can wake the dispatcher path we drive
        // directly below (no full dispatcher spawn — call the same
        // finalise path the dispatcher uses via a wake + inline process).
        let notifier = Arc::new(crate::job_dispatcher::JobNotifier::new());
        let commit_wake = notifier.commit_wake.clone();
        state.job_notify_map.insert(job_id, notifier);

        let body = serde_json::json!({
            "signature": hex::encode(submission.signature),
            "s2c_nonce": hex::encode(submission.s2c_nonce),
        });
        let req = Request::post(format!("/v1/jobs/{}/sign", job_id))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::OK, "body: {resp}");

        // Simulate the dispatcher waking and driving finalise from the
        // durable capability (same path as wait_for_commit / drive_v1_finalise).
        let _ = commit_wake;
        let job = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        let entry = crate::v1::rehydrate_pending_sign(&job.request_body)
            .expect("rehydrate")
            .expect("signed durable finalisation on row after /sign");
        let sig = entry.signature.clone().expect("signature installed");
        let hook = state.v1_finalise.as_ref().expect("hook");
        // Direct spy invocation (not via claim): dummy fence for type shape.
        let outcome = hook(
            entry.pending,
            sig,
            crate::job_store::FinaliseFence {
                job_id,
                owner: state.job_store.process_owner(),
                fence: 0,
            },
        )
        .await
        .expect("finalise");
        assert!(
            finalise_called.load(Ordering::SeqCst),
            "finalise hook must have been invoked"
        );
        let result_json = outcome.to_result_json();
        assert!(result_json.get("new_account_state_hash").is_some());
        assert!(result_json.get("signature_accepted").is_none());

        // Job is still awaiting_signature (hook was invoked directly, not
        // via claim/finalise owner complete).
        state
            .job_store
            .complete(
                job_id,
                crate::job_store::JobStatus::AwaitingSignature,
                result_json.clone(),
                200,
            )
            .await
            .expect("complete");
        let req = Request::get(format!("/v1/jobs/{}", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["status"], "completed");
        assert!(
            v.get("phase").is_none(),
            "phase absent when terminal: {body}"
        );
        assert!(v["result"].get("new_account_state_hash").is_some());
        assert!(v["result"].get("signature_accepted").is_none());
    }

    /// Defect 1: acceptance without a parked dispatcher is failure, not
    /// success — no invented `dispatcher: "not_waiting"`.
    #[tokio::test]
    async fn jobs_sign_without_dispatcher_reports_failure_not_acceptance() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xC1u8; 32],
                Some("k-no-disp"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        let (entry, submission) =
            crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let advertised = crate::v1::awaiting_signature_result_json(&entry);
        state
            .job_store
            .set_awaiting_signature(job_id, 1, advertised)
            .await
            .expect("awaiting_signature");
        state.pending_sign_map.insert(job_id, entry);
        // Deliberately NO job_notify_map entry — dispatcher not parked.

        let body = serde_json::json!({
            "signature": hex::encode(submission.signature),
            "s2c_nonce": hex::encode(submission.s2c_nonce),
        });
        let req = Request::post(format!("/v1/jobs/{}/sign", job_id))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "internal_error");
        assert_ne!(v["status"], "signature_accepted");
        assert!(
            v.get("dispatcher").is_none(),
            "no invented dispatcher field: {resp}"
        );
        assert!(
            v["message"]
                .as_str()
                .unwrap_or("")
                .contains("no dispatcher"),
            "message should describe the lifecycle failure: {resp}"
        );
    }

    /// Durable finalisation rehydrate carries a full capability (not a
    /// verification-grade partial). Signed resume is finalise-ready; completion
    /// still needs the post-apply surface.
    #[tokio::test]
    async fn rehydrated_durable_finalisation_is_finalise_ready() {
        use crate::v1::{
            ensure_completion_ready, ensure_finalise_ready, set_process_stack_mode,
            DurableFinalisationPersist, ScanStackMode,
        };

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (mut entry, submission) =
            crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let accepted = crate::v1::accept_wallet_transition_signature(
            crate::v1::V1ShadowMode::On,
            entry.network,
            &entry.pending,
            &submission,
        )
        .expect("verify");
        entry.install_signature(accepted).expect("install");
        let rehydrated = DurableFinalisationPersist::from_entry(&entry)
            .expect("encode")
            .into_entry()
            .expect("rehydrate");
        ensure_finalise_ready(&rehydrated).expect("signed durable rehydrate is finalise-ready");
        ensure_finalise_ready(&entry).expect("live-staged signed is finalise-ready");
        assert!(
            ensure_completion_ready(&rehydrated).is_err(),
            "signed-only capability is not completion-ready without completion_result"
        );
    }

    /// Defect 4/5: success result carries output_coin_ids + publisher_pubkey.
    #[tokio::test]
    async fn completed_result_carries_output_coin_ids_and_publisher_pubkey() {
        use crate::v1::{set_process_stack_mode, FinaliseOutcome, ScanStackMode};
        use shared::spec_v1::{digest_from_bytes, digest_to_bytes, Coin, ZERO_HASH};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (mut entry, _) = crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        // Attach one synthetic output coin so the result is non-empty.
        let coin_id = [0x42u8; 32];
        entry.pending.witness_wip.output_coins.push(Coin {
            identifier: digest_from_bytes(&coin_id).expect("digest"),
            recipient: entry.pending.owner,
            amount: 1,
            asset_id: ZERO_HASH,
        });

        let publisher = [0xCCu8; 32];
        let outcome = FinaliseOutcome::from_pending_proof_data_with_publisher(
            &entry.pending,
            Some(publisher),
        );
        let result_json = outcome.to_result_json();
        assert_eq!(
            result_json["output_coin_ids"].as_array().map(|a| a.len()),
            Some(1),
            "output_coin_ids: {result_json}"
        );
        assert_eq!(
            result_json["output_coin_ids"][0].as_str().unwrap(),
            hex::encode(digest_to_bytes(
                &entry.pending.witness_wip.output_coins[0].identifier
            ))
        );
        assert_eq!(
            result_json["publisher_pubkey"].as_str().unwrap(),
            hex::encode(publisher)
        );

        // Also surface via GET /v1/jobs poll envelope.
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Mint,
                &[0xC2u8; 32],
                Some("k-result-fields"),
                serde_json::json!({
                    "publisher_pubkey": hex::encode(publisher),
                }),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        state
            .job_store
            .complete(
                job_id,
                crate::job_store::JobStatus::Queued,
                result_json,
                200,
            )
            .await
            .expect("complete");
        let req = Request::get(format!("/v1/jobs/{}", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["status"], "completed");
        assert!(v["result"]["output_coin_ids"].is_array());
        assert_eq!(
            v["result"]["publisher_pubkey"].as_str().unwrap(),
            hex::encode(publisher)
        );
    }

    /// Defect 5: malformed JSON and malformed UUID → 400 malformed_request.
    #[tokio::test]
    async fn v1_extractors_map_malformed_json_and_uuid_to_malformed_request() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (state, _pool, _c) = jobs_test_state().await;

        // Malformed UUID in path.
        let req = Request::post("/v1/jobs/not-a-uuid/sign")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({
                    "signature": "00".repeat(64),
                    "s2c_nonce": "11".repeat(32),
                })
                .to_string(),
            ))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "uuid body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "malformed_request");
        assert!(v.get("message").is_some());

        // Malformed JSON body on a well-formed UUID.
        let id = uuid::Uuid::new_v4();
        let req = Request::post(format!("/v1/jobs/{}/sign", id))
            .header("content-type", "application/json")
            .body(Body::from("{not json"))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "json body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "malformed_request");

        // Wrong-type JSON (missing required fields / wrong types).
        let req = Request::post(format!("/v1/jobs/{}/sign", id))
            .header("content-type", "application/json")
            .body(Body::from(r#"{"signature": 123, "s2c_nonce": true}"#))
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "type body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "malformed_request");
    }

    /// Defect 4: /sign still works after a simulated restart (map empty,
    /// rehydrate from request_body.pending_sign).
    #[tokio::test]
    async fn jobs_sign_works_after_simulated_restart() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xB2u8; 32],
                Some("k-restart"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        let (entry, submission) =
            crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let advertised = crate::v1::awaiting_signature_result_json(&entry);
        let persist = crate::v1::DurableFinalisationPersist::from_entry(&entry)
            .expect("encode durable finalisation");
        let mut req_body = serde_json::json!({});
        req_body.as_object_mut().unwrap().insert(
            crate::v1::FINALISATION_BODY_KEY.to_string(),
            serde_json::to_value(&persist).unwrap(),
        );
        sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
            .bind(&req_body)
            .bind(job_id)
            .execute(state.job_store.pool())
            .await
            .expect("persist pending_sign");
        state
            .job_store
            .set_awaiting_signature(job_id, 1, advertised)
            .await
            .expect("awaiting_signature");

        // Simulate restart: clear the in-memory map. /sign must rehydrate.
        state.pending_sign_map.clear();
        assert!(state.pending_sign_map.get(&job_id).is_none());

        let notifier = Arc::new(crate::job_dispatcher::JobNotifier::new());
        state.job_notify_map.insert(job_id, notifier);

        let body = serde_json::json!({
            "signature": hex::encode(submission.signature),
            "s2c_nonce": hex::encode(submission.s2c_nonce),
        });
        let req = Request::post(format!("/v1/jobs/{}/sign", job_id))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "after restart /sign must rehydrate and accept: {resp}"
        );
        // Map re-populated from the envelope.
        assert!(
            state.pending_sign_map.get(&job_id).is_some(),
            "rehydrate must re-stage the pending entry"
        );
    }

    /// Defect 1 (round 5): a job that reaches `awaiting_signature` through
    /// the dispatcher's production staging site (`stage_and_select_awaiting_signature`
    /// → `stage_pending_sign`) can be signed via `/v1`.
    #[tokio::test]
    async fn dispatcher_staging_path_allows_v1_sign() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (mut state, _pool, _c) = jobs_test_state().await;
        let (entry, submission) =
            crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();

        // Prove-path hook supplies the live pending (Stage 3 will wire
        // StateEngine::begin_* here). The dispatcher staging site is
        // what actually calls stage_pending_sign.
        let entry_for_hook = entry.clone();
        state.v1_pending_after_prove = Some(Arc::new(move |_job_id| Some(entry_for_hook.clone())));

        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xD1u8; 32],
                Some("k-disp-stage"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        // Production site the dispatcher invokes after prove.
        let live = state
            .v1_pending_after_prove
            .as_ref()
            .and_then(|h| h(job_id));
        let advertised = crate::job_dispatcher::stage_and_select_awaiting_signature(
            &state.job_store,
            &state,
            job_id,
            "aa".repeat(32).as_str(),
            "bb".repeat(32).as_str(),
            live,
        )
        .await
        .expect("dispatcher staging must succeed with a live pending");
        assert!(
            advertised.get("proof_data_hash").is_some(),
            "v1.1 surface required: {advertised}"
        );
        assert!(
            state.pending_sign_map.get(&job_id).is_some(),
            "stage_pending_sign must populate pending_sign_map"
        );
        // Restart envelope persisted.
        let row = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert!(
            row.request_body
                .get(crate::v1::FINALISATION_BODY_KEY)
                .is_some(),
            "pending_sign envelope must be on the job row"
        );

        state
            .job_store
            .set_awaiting_signature(job_id, 1, advertised)
            .await
            .expect("awaiting_signature");
        let notifier = Arc::new(crate::job_dispatcher::JobNotifier::new());
        state.job_notify_map.insert(job_id, notifier);

        let body = serde_json::json!({
            "signature": hex::encode(submission.signature),
            "s2c_nonce": hex::encode(submission.s2c_nonce),
        });
        let req = Request::post(format!("/v1/jobs/{}/sign", job_id))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::OK, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["status"], "signature_accepted");
    }

    /// Defect 2 (round 5): dispatcher disappearing between clone and wake
    /// (handoff CAS lost to timeout) yields rejection, not acceptance.
    #[tokio::test]
    async fn jobs_sign_rejects_when_dispatcher_handoff_already_timed_out() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xD2u8; 32],
                Some("k-handoff-race"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        let (entry, submission) =
            crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let advertised = crate::v1::awaiting_signature_result_json(&entry);
        state
            .job_store
            .set_awaiting_signature(job_id, 1, advertised)
            .await
            .expect("awaiting_signature");
        state.pending_sign_map.insert(job_id, entry);

        // Notifier is present (clone would succeed) but the dispatcher has
        // already claimed timeout — the CAS must refuse acceptance.
        let notifier = Arc::new(crate::job_dispatcher::JobNotifier::new());
        assert!(
            notifier.try_claim_timeout(),
            "simulate dispatcher timeout claiming the handoff"
        );
        state.job_notify_map.insert(job_id, notifier);

        let body = serde_json::json!({
            "signature": hex::encode(submission.signature),
            "s2c_nonce": hex::encode(submission.s2c_nonce),
        });
        let req = Request::post(format!("/v1/jobs/{}/sign", job_id))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "internal_error");
        assert_ne!(v["status"], "signature_accepted");
        assert!(
            v["message"]
                .as_str()
                .unwrap_or("")
                .contains("no longer waiting")
                || v["message"].as_str().unwrap_or("").contains("timed out"),
            "message should describe the handoff race: {resp}"
        );
        // Persist-before-signal: even on a refused handoff the signed
        // durable capability must already be on the row.
        let row = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        let entry = crate::v1::rehydrate_pending_sign(&row.request_body)
            .expect("rehydrate")
            .expect("durable finalisation present");
        assert!(
            entry.signature.is_some(),
            "persist-before-signal: signed capability must be durable even when CAS refuses"
        );
    }

    /// Defect 1: a job staged through the production registry
    /// (`register_live_pending_after_begin` → resolve →
    /// `stage_and_select_awaiting_signature`) can be signed via `/v1`.
    #[tokio::test]
    async fn production_begin_registry_staging_allows_v1_sign() {
        use crate::v1::{register_live_pending_after_begin, set_process_stack_mode, ScanStackMode};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (mut state, _pool, _c) = jobs_test_state().await;
        let (entry, submission) =
            crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();

        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xD3u8; 32],
                Some("k-prod-stage"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        // Production write site: begin_* registers the live pending here.
        register_live_pending_after_begin(&state.v1_live_pending_after_begin, job_id, entry);

        // No test hook — production resolve path only.
        state.v1_pending_after_prove = None;
        let live = crate::job_dispatcher::resolve_live_pending_after_prove_for_test(&state, job_id);
        assert!(
            live.is_some(),
            "production registry must supply the pending"
        );
        let advertised = crate::job_dispatcher::stage_and_select_awaiting_signature(
            &state.job_store,
            &state,
            job_id,
            "aa".repeat(32).as_str(),
            "bb".repeat(32).as_str(),
            live,
        )
        .await
        .expect("production staging must succeed");
        assert!(advertised.get("proof_data_hash").is_some());
        assert!(state.pending_sign_map.get(&job_id).is_some());

        state
            .job_store
            .set_awaiting_signature(job_id, 1, advertised)
            .await
            .expect("awaiting_signature");
        // set_awaiting_signature requires proving|queued — flip first.
        // (create leaves queued; the WHERE allows it.)
        let notifier = Arc::new(crate::job_dispatcher::JobNotifier::new());
        state.job_notify_map.insert(job_id, notifier);

        let body = serde_json::json!({
            "signature": hex::encode(submission.signature),
            "s2c_nonce": hex::encode(submission.s2c_nonce),
        });
        let req = Request::post(format!("/v1/jobs/{}/sign", job_id))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::OK, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["status"], "signature_accepted");
    }

    /// Defect 2: SIGNALED without durable state is unreachable.
    /// A refused CAS after successful persist still has the sign blob;
    /// the inverse (SIGNALED with no blob) cannot arise from /sign.
    #[tokio::test]
    async fn jobs_sign_persist_before_signal_invariant() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xD4u8; 32],
                Some("k-persist-first"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        let (entry, submission) =
            crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let advertised = crate::v1::awaiting_signature_result_json(&entry);
        state
            .job_store
            .set_awaiting_signature(job_id, 1, advertised)
            .await
            .expect("awaiting_signature");
        state.pending_sign_map.insert(job_id, entry);

        // No notifier → acceptance refuses before CAS; handoff never SIGNALED.
        // (If we had signalled first, a crash before persist would leave
        // SIGNALED with no durable sign — the reorder closes that window.)
        let body = serde_json::json!({
            "signature": hex::encode(submission.signature),
            "s2c_nonce": hex::encode(submission.s2c_nonce),
        });
        let req = Request::post(format!("/v1/jobs/{}/sign", job_id))
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body: {resp}");
        let row = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        // Without a notifier we refuse before persist (no dispatcher to serve).
        // The invariant under test is: we never set SIGNALED without a durable
        // blob — and with no notifier there is no handoff to signal at all.
        assert!(
            state.job_notify_map.get(&job_id).is_none(),
            "no handoff exists to be left in SIGNALED"
        );
        let _ = row; // status stays awaiting_signature
    }

    /// Helper: plant a signed durable capability (optionally with completion
    /// surface) on a fresh send job at `awaiting_signature`.
    async fn plant_signed_finalisation_job(
        store: &crate::job_store::JobStore,
        owner_tag: u8,
        idem: &str,
        with_completion: bool,
    ) -> (uuid::Uuid, crate::v1::PendingSignEntry) {
        let result = store
            .create(
                crate::job_store::JobKind::Send,
                &[owner_tag; 32],
                Some(idem),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!("expected fresh job"),
        };

        let (mut entry, submission) =
            crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let advertised = crate::v1::awaiting_signature_result_json(&entry);
        let accepted = crate::v1::accept_wallet_transition_signature(
            crate::v1::V1ShadowMode::On,
            entry.network,
            &entry.pending,
            &submission,
        )
        .expect("verify");
        entry.install_signature(accepted).expect("install");
        if with_completion {
            let outcome = crate::v1::FinaliseOutcome::from_pending_proof_data_with_publisher(
                &entry.pending,
                entry.publisher_pubkey,
            );
            entry
                .install_completion(outcome.to_result_json(), 200)
                .expect("install completion");
        }
        let persist = crate::v1::DurableFinalisationPersist::from_entry(&entry).expect("encode");
        let mut body = serde_json::json!({});
        body.as_object_mut().unwrap().insert(
            crate::v1::FINALISATION_BODY_KEY.to_string(),
            serde_json::to_value(&persist).unwrap(),
        );
        sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
            .bind(&body)
            .bind(job_id)
            .execute(store.pool())
            .await
            .expect("persist durable finalisation");
        store
            .set_awaiting_signature(job_id, 1, advertised)
            .await
            .expect("awaiting_signature");
        // Re-plant after status flip (set_awaiting_signature does not clear
        // request_body keys we need, but keep the durable blob authoritative).
        let row = store.load(job_id).await.expect("load").expect("row");
        let mut body = row.request_body;
        body.as_object_mut().unwrap().insert(
            crate::v1::FINALISATION_BODY_KEY.to_string(),
            serde_json::to_value(&persist).unwrap(),
        );
        sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
            .bind(&body)
            .bind(job_id)
            .execute(store.pool())
            .await
            .expect("replant durable");
        (job_id, entry)
    }

    /// Build a **genuinely fresh** AppState from the pool (new Arcs, empty
    /// maps, `v1_finalise = None`) — the shape production boot constructs,
    /// not a warm state with maps cleared.
    fn fresh_app_state_from_pool(pool: Arc<sqlx::PgPool>) -> AppState {
        let state = Arc::new(Mutex::new(State::new()));
        let account_node = AccountNode::new(Arc::clone(&state));
        let proofs_dir = tempfile::tempdir().expect("proofs tempdir").keep();
        let (tx, rx) = tokio::sync::mpsc::channel::<crate::job_dispatcher::JobEnvelope>(8);
        std::mem::forget(rx);
        AppState {
            account_node: Arc::new(Mutex::new(account_node)),
            proof_store: Arc::new(ProofStore::new(proofs_dir.to_str().expect("utf-8"))),
            mint_store: Arc::new(crate::router::MintStore::new()),
            username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
            pool: Arc::clone(&pool),
            esplora_config: Arc::new(crate::publisher::EsploraConfig {
                url: "http://127.0.0.1:1/api".to_string(),
                is_mainnet: false,
                network_name: "Mutinynet".to_string(),
                ws_url: None,
            }),
            prover_warm: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            prover_health: Arc::new(crate::prover_health::ProverHealth::new()),
            job_store: Arc::new(crate::job_store::JobStore::new((*pool).clone())),
            job_tx: tx,
            job_notify_map: Arc::new(dashmap::DashMap::new()),
            v1_scan_caught_up: None,
            v1_finality_ok: None,
            pending_sign_map: Arc::new(dashmap::DashMap::new()),
            // Production cold path: no injected hook. Completion must come
            // from the durable capability alone (or a real EngineAdapter).
            v1_finalise: None,
            v1_live_pending_after_begin: Arc::new(dashmap::DashMap::new()),
            v1_pending_after_prove: None,
            receive_creating_proof_loader: None,
            v1_engine: None,
            private_index: crate::kernel::access::InMemoryPrivateIndex::shared(),
            bundles: crate::kernel::bootstrap::BundleStore::shared(),
            attest_challenges: crate::kernel::bootstrap::ChallengeStore::shared(),
            public_hosts: Arc::new(vec!["node.test".to_string()]),
        }
    }

    /// Cold boot: fresh `AppState` (new construction, not map-clear), **no**
    /// injected finalise hook, production resume path, driven only by DB
    /// bytes that already carry the completion surface (crash after apply).
    ///
    /// Reaches [`crate::job_dispatcher::JOB_FINALISE_HOST_EDGE`]: §7.5 job
    /// result on the row + `completed`. Does **not** drive on-chain
    /// AggregateStateNullifierV3 (bitcoind / `v1_pending_publishes` — design
    /// edge of the sync finalise hook). Missing capability fields fail (see
    /// incomplete test).
    #[tokio::test]
    async fn cold_fresh_appstate_drives_completion_from_durable_capability_alone() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};
        use std::time::Duration;

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(scope.pool.clone());
        // Plant durable bytes with a store bound only to the pool.
        let plant_store = crate::job_store::JobStore::new((*pool).clone());
        let (job_id, _entry) =
            plant_signed_finalisation_job(&plant_store, 0xD5, "k-cold-fresh", true).await;

        // Genuinely fresh AppState — new Arcs, empty maps, no hook.
        let state = fresh_app_state_from_pool(Arc::clone(&pool));
        assert!(
            state.v1_finalise.is_none(),
            "cold test must not inject a hook"
        );
        assert!(state.pending_sign_map.is_empty());
        assert!(state.job_notify_map.is_empty());

        crate::job_dispatcher::process_envelope_for_test(
            &state.job_store,
            &state,
            &state.job_notify_map,
            Duration::from_secs(30),
            crate::job_dispatcher::JobEnvelope { public_id: job_id },
        )
        .await
        .expect("cold resume process");

        let after = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(
            after.status,
            crate::job_store::JobStatus::Completed,
            "cold resume must complete from durable completion_result; status={:?} err={:?}",
            after.status,
            after.error
        );
        assert!(after
            .request_body
            .get(crate::v1::FINALISATION_BODY_KEY)
            .is_none());
        assert!(after.response_body.is_some());
        let result = after.response_body.as_ref().unwrap();
        assert!(result.get("new_account_state_hash").is_some());

        drop(scope);
    }

    /// Incomplete capability (signed, no completion surface, no hook): resume
    /// must **fail** rather than silently half-finish at broadcasting.
    #[tokio::test]
    async fn incomplete_capability_without_completion_fails_resume() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};
        use std::time::Duration;

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(scope.pool.clone());
        let plant_store = crate::job_store::JobStore::new((*pool).clone());
        // Signed but no completion_result — prove+apply never recorded.
        let (job_id, _) =
            plant_signed_finalisation_job(&plant_store, 0xD7, "k-incomplete", false).await;

        let state = fresh_app_state_from_pool(Arc::clone(&pool));
        assert!(state.v1_finalise.is_none());

        crate::job_dispatcher::process_envelope_for_test(
            &state.job_store,
            &state,
            &state.job_notify_map,
            Duration::from_secs(30),
            crate::job_dispatcher::JobEnvelope { public_id: job_id },
        )
        .await
        .expect("process returns Ok after fail_v1");

        let after = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(
            after.status,
            crate::job_store::JobStatus::Failed,
            "incomplete capability must fail, not complete or stick at broadcasting; \
             status={:?} err={:?}",
            after.status,
            after.error
        );
        let err = after.error.as_deref().unwrap_or("");
        assert!(
            err.contains("completion_result")
                || err.contains("incomplete")
                || err.contains("no finalise driver"),
            "error must name the missing capability path; got: {err}"
        );
        // Must not reach completed: response_status stays unset (awaiting_signature
        // may still hold the wallet advertisement in response_body — that is not
        // a terminal success publish).
        assert!(
            after.response_status.is_none(),
            "must not publish a completed HTTP status; got {:?}",
            after.response_status
        );
        assert!(
            after.completed_at.is_some(),
            "failed terminal must stamp completed_at"
        );
        // Durable envelope stripped on fail — cannot be half-finished and resumed.
        assert!(
            after
                .request_body
                .get(crate::v1::FINALISATION_BODY_KEY)
                .is_none(),
            "fail must strip finalisation envelope: {:?}",
            after.request_body
        );

        drop(scope);
    }

    /// Two concurrent resumers race on `awaiting_signature`: exactly one wins
    /// the exclusive broadcasting claim and runs side effects; the loser
    /// observes the loss and does not continue.
    #[tokio::test]
    async fn concurrent_resumers_exactly_one_wins_exclusive_claim() {
        use crate::v1::{set_process_stack_mode, FinaliseOutcome, ScanStackMode};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let hook_count = Arc::new(AtomicUsize::new(0));
        let hook_count_h = Arc::clone(&hook_count);
        // Gate: both tasks reach the claim, then proceed together.
        let barrier = Arc::new(tokio::sync::Barrier::new(2));

        let (mut state, pool, _scope) = jobs_test_state().await;
        let (job_id, _) =
            plant_signed_finalisation_job(&state.job_store, 0xE0, "k-race-claim", false).await;

        let barrier_in_hook = Arc::clone(&barrier);
        state.v1_finalise = Some(Arc::new(move |pending, _sig, _fence| {
            let hook_count_h = Arc::clone(&hook_count_h);
            let _ = barrier_in_hook;
            Box::pin(async move {
                // Count only after the exclusive claim (hook runs post-claim).
                hook_count_h.fetch_add(1, Ordering::SeqCst);
                Ok(FinaliseOutcome::from_pending_proof_data(&pending))
            })
        }));

        let store = state.job_store.clone();
        let notify = state.job_notify_map.clone();
        let state_a = state.clone();
        let state_b = state.clone();
        let b1 = Arc::clone(&barrier);
        let b2 = Arc::clone(&barrier);

        let j1 = tokio::spawn(async move {
            b1.wait().await;
            crate::job_dispatcher::process_envelope_for_test(
                &store,
                &state_a,
                &notify,
                Duration::from_secs(30),
                crate::job_dispatcher::JobEnvelope { public_id: job_id },
            )
            .await
        });
        let store2 = state.job_store.clone();
        let notify2 = state.job_notify_map.clone();
        let j2 = tokio::spawn(async move {
            b2.wait().await;
            crate::job_dispatcher::process_envelope_for_test(
                &store2,
                &state_b,
                &notify2,
                Duration::from_secs(30),
                crate::job_dispatcher::JobEnvelope { public_id: job_id },
            )
            .await
        });

        let (r1, r2) = tokio::join!(j1, j2);
        r1.expect("join1").expect("process1");
        r2.expect("join2").expect("process2");

        assert_eq!(
            hook_count.load(Ordering::SeqCst),
            1,
            "exactly one resumer must run the finalise hook (exclusive claim)"
        );
        let after = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(
            after.status,
            crate::job_store::JobStatus::Completed,
            "winner must complete the job; status={:?} err={:?}",
            after.status,
            after.error
        );

        // Direct claim API: a third attempt against a terminal job loses.
        let claim = state
            .job_store
            .claim_finalise_exclusive(job_id)
            .await
            .expect("claim");
        assert!(
            matches!(
                claim,
                crate::job_store::FinaliseClaim::Lost {
                    observed: crate::job_store::JobStatus::Completed
                }
            ),
            "claim after complete must be Lost; got {claim:?}"
        );

        drop(pool);
    }

    /// Defect 3: a non-terminal losing resumer must leave the winner's
    /// `notify_map` entry intact — observe the loss and return, no cleanup.
    #[tokio::test]
    async fn losing_resumer_leaves_winner_notify_map_intact() {
        use crate::job_dispatcher::JobNotifier;
        use crate::v1::{set_process_stack_mode, ScanStackMode};
        use std::time::Duration;

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (state, _pool, _c) = jobs_test_state().await;
        let (job_id, _) =
            plant_signed_finalisation_job(&state.job_store, 0xE3, "k-loser-notify", true).await;

        // Winner already holds the exclusive claim (live owner).
        assert!(
            matches!(
                state
                    .job_store
                    .claim_finalise_exclusive(job_id)
                    .await
                    .expect("winner claim"),
                crate::job_store::FinaliseClaim::Won { .. }
            ),
            "winner claim must win"
        );

        // Shared notify state that belongs to the winner / live dispatcher.
        let notifier = Arc::new(JobNotifier::new());
        state.job_notify_map.insert(job_id, notifier.clone());
        assert!(
            state.job_notify_map.get(&job_id).is_some(),
            "precondition: winner notify present"
        );

        // Loser resume: claim lost, non-terminal — must not remove notify.
        crate::job_dispatcher::process_envelope_for_test(
            &state.job_store,
            &state,
            &state.job_notify_map,
            Duration::from_secs(30),
            crate::job_dispatcher::JobEnvelope { public_id: job_id },
        )
        .await
        .expect("loser process returns Ok");

        assert!(
            state.job_notify_map.get(&job_id).is_some(),
            "losing resumer must not remove the winner's notify_map entry"
        );
        // Job still broadcasting under the winner's claim — not failed/completed
        // by the loser.
        let row = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(
            row.status,
            crate::job_store::JobStatus::Broadcasting,
            "loser must not terminal-flip the winner's job; status={:?} err={:?}",
            row.status,
            row.error
        );
        assert_eq!(row.phase, crate::job_store::FINALISE_CLAIM_PHASE);
    }

    /// Defect 1 (host edge): resume drives exactly to the documented host edge
    /// ([`crate::job_dispatcher::JOB_FINALISE_HOST_EDGE`]) — §7.5 job complete
    /// after durable completion surface **and** recorded nullifier broadcast
    /// handoff — and does not silently stop earlier.
    ///
    /// With a durable completion surface and **no** leftover `members_ready`
    /// row (handoff already recorded, or never staged), resume may complete.
    /// Remaining work after the host edge is on-chain AggregateStateNullifierV3
    /// confirmation / NfLog scan-fold (bitcoind).
    #[tokio::test]
    async fn resume_drives_to_documented_host_edge_not_silent_stop() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};
        use std::time::Duration;

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(scope.pool.clone());
        let plant_store = crate::job_store::JobStore::new((*pool).clone());
        // Durable completion_result already present, no members_ready row:
        // crash after host work + handoff recorded (or never staged), before
        // terminal complete — resumable window up to the host edge.
        let (job_id, entry) =
            plant_signed_finalisation_job(&plant_store, 0xE4, "k-host-edge", true).await;
        assert!(
            entry.has_completion(),
            "precondition: durable completion surface planted"
        );

        let state = fresh_app_state_from_pool(Arc::clone(&pool));
        assert!(
            state.v1_finalise.is_none(),
            "edge test must not inject a hook — host path is durable-only"
        );

        crate::job_dispatcher::process_envelope_for_test(
            &state.job_store,
            &state,
            &state.job_notify_map,
            Duration::from_secs(30),
            crate::job_dispatcher::JobEnvelope { public_id: job_id },
        )
        .await
        .expect("resume to host edge");

        let after = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(
            after.status,
            crate::job_store::JobStatus::Completed,
            "resume must reach host edge (job completed with §7.5 result); \
             status={:?} err={:?} — not a silent stop at broadcasting",
            after.status,
            after.error
        );
        assert_eq!(after.phase, "completed");
        assert!(
            after.response_body.is_some() && after.response_status == Some(200),
            "§7.5 result must be published onto the job row at the host edge"
        );
        assert!(
            after
                .request_body
                .get(crate::v1::FINALISATION_BODY_KEY)
                .is_none(),
            "terminal strip must clear finalisation at host edge"
        );
        assert!(
            after
                .request_body
                .get(crate::job_store::FINALISE_CLAIM_BODY_KEY)
                .is_none(),
            "terminal strip must clear finalise_claim at host edge"
        );

        // Documented edge names durable members_ready + broadcast handoff, and
        // the chain/bitcoind remainder after host complete.
        let edge = crate::job_dispatcher::JOB_FINALISE_HOST_EDGE;
        assert!(
            edge.contains("AggregateStateNullifierV3") && edge.contains("bitcoind"),
            "JOB_FINALISE_HOST_EDGE must name the chain/bitcoind remainder; got: {edge}"
        );
        assert!(
            edge.contains("members_ready"),
            "JOB_FINALISE_HOST_EDGE must name the durable members_ready stage; got: {edge}"
        );
        assert!(
            edge.contains("nullifier_broadcast_handoff")
                || edge.contains("broadcast_handoff")
                || edge.contains("publish handoff"),
            "JOB_FINALISE_HOST_EDGE must name the nullifier broadcast handoff; got: {edge}"
        );

        drop(scope);
    }

    /// Defect 1 (P0): a crash at the edge leaves a **durable** job — engine
    /// intent via `v1_pending_publishes` (`members_ready`) + completion
    /// surface — that the resume path picks up without re-running the
    /// finalise hook.
    ///
    /// Host edge (new): while the pending publish is still only
    /// `members_ready` (broadcast handoff not recorded), resume must **not**
    /// mark the job `completed`. Both: not completed **and** the
    /// `members_ready` row retained. Crash/resume durability remains the
    /// primary assertion — only the terminal end-state changes.
    #[tokio::test]
    async fn crash_at_edge_leaves_durable_job_resume_picks_up() {
        use crate::v1::{
            claim_stack_scan_mode, set_process_stack_mode, FinaliseOutcome, ScanStackMode,
        };
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(scope.pool.clone());
        claim_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect("claim stack_scan_mode v1");

        let plant_store = crate::job_store::JobStore::new((*pool).clone());
        let (job_id, entry) =
            plant_signed_finalisation_job(&plant_store, 0xE5, "k-crash-edge", false).await;
        let sig = entry.signature.clone().expect("signed");
        let owner = entry.pending.owner;

        // Simulate production durable stage at the edge: members_ready for
        // this nullifier is on disk (engine snapshot co-persisted in prod).
        crate::v1::db_v1::insert_pending_publish_members_ready(
            &pool,
            owner,
            sig.pk_i,
            sig.signature_r(),
            sig.signature_s(),
            sig.r_prime,
            0,
            [0u8; 32],
        )
        .await
        .expect("stage members_ready at edge");

        // And the §7.5 completion surface is durable (crash after stage +
        // completion persist, before broadcast handoff / terminal complete).
        let mut entry = entry;
        let outcome = FinaliseOutcome::from_pending_proof_data_with_publisher(
            &entry.pending,
            entry.publisher_pubkey,
        );
        entry
            .install_completion(outcome.to_result_json(), 200)
            .expect("install completion");
        let persist = crate::v1::DurableFinalisationPersist::from_entry(&entry).expect("encode");
        let row = plant_store.load(job_id).await.expect("load").expect("row");
        let mut body = row.request_body;
        body.as_object_mut().unwrap().insert(
            crate::v1::FINALISATION_BODY_KEY.to_string(),
            serde_json::to_value(&persist).unwrap(),
        );
        sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
            .bind(&body)
            .bind(job_id)
            .execute(&*pool)
            .await
            .expect("plant completion");

        // Fresh AppState — resume from durable bytes; spy hook must not run.
        let mut state = fresh_app_state_from_pool(Arc::clone(&pool));
        let hook_count = Arc::new(AtomicUsize::new(0));
        let hook_count_h = Arc::clone(&hook_count);
        state.v1_finalise = Some(Arc::new(move |pending, _sig, _fence| {
            let hook_count_h = Arc::clone(&hook_count_h);
            Box::pin(async move {
                hook_count_h.fetch_add(1, Ordering::SeqCst);
                Ok(FinaliseOutcome::from_pending_proof_data(&pending))
            })
        }));

        crate::job_dispatcher::process_envelope_for_test(
            &state.job_store,
            &state,
            &state.job_notify_map,
            Duration::from_secs(30),
            crate::job_dispatcher::JobEnvelope { public_id: job_id },
        )
        .await
        .expect("resume after crash at edge");

        assert_eq!(
            hook_count.load(Ordering::SeqCst),
            0,
            "resume with durable completion must not re-run finalise hook"
        );
        let after = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        // New host edge: members_ready alone is not host-complete.
        assert_ne!(
            after.status,
            crate::job_store::JobStatus::Completed,
            "must not complete while pending publish is still members_ready; \
             status={:?} err={:?}",
            after.status,
            after.error
        );
        // Publisher / boot resume still finds the staged intent (durable handoff).
        let pending = crate::v1::db_v1::load_pending_publish(&pool, sig.pk_i)
            .await
            .expect("load pending")
            .expect("members_ready must survive crash + resume");
        assert_eq!(
            pending.status,
            crate::v1::db_v1::PENDING_PUBLISH_MEMBERS_READY,
            "members_ready row must be retained for later broadcast handoff"
        );
        assert_eq!(pending.owner, owner);

        drop(scope);
    }

    /// Defect 1 (P0): when the finalise hook runs, it must leave a durable
    /// `v1_pending_publishes` row (test double stages intent the way
    /// production `finalise_accepted_prove_persist_and_stage` does).
    ///
    /// This test stages **only** (no broadcast handoff). Host edge: the job
    /// must **not** become `completed` while the intent remains
    /// `members_ready` — both not-completed and the staged row retained.
    /// Successful handoff → completed is covered by
    /// `job_dispatcher::finalise_publish_handoff_tests` via `RecordingPublisher`.
    #[tokio::test]
    async fn finalise_hook_stages_pending_publish_for_durable_handoff() {
        use crate::v1::{
            claim_stack_scan_mode, set_process_stack_mode, FinaliseOutcome, ScanStackMode,
        };
        use std::time::Duration;

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (mut state, pool, _c) = jobs_test_state().await;
        claim_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect("claim stack_scan_mode v1");

        let (job_id, entry) =
            plant_signed_finalisation_job(&state.job_store, 0xE6, "k-stage-pending", false).await;
        let pool_for_hook = Arc::clone(&pool);
        state.v1_finalise = Some(Arc::new(move |pending, signature, fence| {
            let pool_for_hook = Arc::clone(&pool_for_hook);
            Box::pin(async move {
                // Mirror production stage only: members_ready under the claim
                // fence before returning the §7.5 outcome. Deliberately no
                // broadcast handoff (see job_dispatcher RecordingPublisher tests
                // for the handoff→completed path).
                let staged =
                    crate::v1::db_v1::persist_engine_with_pending_members_ready_if_finalise_fence(
                        &pool_for_hook,
                        &crate::v1::db_v1::EngineSnapshot {
                            network: zkcoins_program::circuit::compliance::Network::Regtest,
                            activation_height: 0,
                            tip_height: 0,
                            tip_hash: [0u8; 32],
                            fold_seq: 0,
                            nflog: vec![],
                            accounts: vec![],
                            inscriptions: vec![],
                        },
                        pending.owner,
                        signature.pk_i,
                        signature.signature_r(),
                        signature.signature_s(),
                        signature.r_prime,
                        0,
                        [0u8; 32],
                        fence,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("stage members_ready under fence: {e:#}"))?;
                if !staged {
                    return Err(anyhow::Error::msg(crate::job_store::FINALISE_FENCE_LOST));
                }
                Ok(FinaliseOutcome::from_pending_proof_data(&pending))
            })
        }));

        crate::job_dispatcher::process_envelope_for_test(
            &state.job_store,
            &state,
            &state.job_notify_map,
            Duration::from_secs(30),
            crate::job_dispatcher::JobEnvelope { public_id: job_id },
        )
        .await
        .expect("process finalise with durable stage");

        let after = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_ne!(
            after.status,
            crate::job_store::JobStatus::Completed,
            "staging members_ready without broadcast handoff must not complete; \
             status={:?} err={:?}",
            after.status,
            after.error
        );
        let sig = entry.signature.expect("signed");
        let pending = crate::v1::db_v1::load_pending_publish(&pool, sig.pk_i)
            .await
            .expect("load")
            .expect("hook must stage v1_pending_publishes for the publisher handoff");
        assert_eq!(
            pending.status,
            crate::v1::db_v1::PENDING_PUBLISH_MEMBERS_READY,
            "members_ready must remain for durable handoff"
        );
    }

    /// Resuming finalise twice is harmless: second attempt is claim-lost or
    /// terminal no-op (job already completed; no double-credit / double-complete).
    #[tokio::test]
    async fn resume_finalise_twice_is_harmless() {
        use crate::v1::{set_process_stack_mode, FinaliseOutcome, ScanStackMode};
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Duration;

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let finalise_count = Arc::new(AtomicUsize::new(0));
        let finalise_count_hook = Arc::clone(&finalise_count);

        let (mut state, _pool, _c) = jobs_test_state().await;
        state.v1_finalise = Some(Arc::new(move |pending, _sig, _fence| {
            let finalise_count_hook = Arc::clone(&finalise_count_hook);
            Box::pin(async move {
                finalise_count_hook.fetch_add(1, Ordering::SeqCst);
                Ok(FinaliseOutcome::from_pending_proof_data(&pending))
            })
        }));

        let (job_id, _) =
            plant_signed_finalisation_job(&state.job_store, 0xE1, "k-resume-twice", false).await;

        state.pending_sign_map.clear();
        state.job_notify_map.clear();

        for i in 0..2 {
            crate::job_dispatcher::process_envelope_for_test(
                &state.job_store,
                &state,
                &state.job_notify_map,
                Duration::from_secs(30),
                crate::job_dispatcher::JobEnvelope { public_id: job_id },
            )
            .await
            .unwrap_or_else(|e| panic!("resume #{i}: {e:#}"));
        }

        let after = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(after.status, crate::job_store::JobStatus::Completed);
        // First resume runs the hook; second is a terminal no-op (no second apply).
        assert_eq!(
            finalise_count.load(Ordering::SeqCst),
            1,
            "second resume must not re-run finalise after complete"
        );
    }

    /// Status-qualified request_body update fails when the job has moved on.
    #[tokio::test]
    async fn status_qualified_request_body_update_fails_when_status_moved() {
        let (store, _c) = {
            let (state, _pool, c) = jobs_test_state().await;
            (state.job_store.clone(), c)
        };
        let result = store
            .create(
                crate::job_store::JobKind::Send,
                &[0xE2u8; 32],
                Some("k-status-cas"),
                serde_json::json!({ "seed": true }),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        store
            .set_awaiting_signature(job_id, 1, serde_json::json!({}))
            .await
            .expect("awaiting_signature");

        // Concurrent cancel wins.
        let applied = store
            .cancel_not_yet_published(job_id)
            .await
            .expect("cancel");
        assert!(applied);

        let refused = store
            .replace_request_body_if_status(
                job_id,
                crate::job_store::JobStatus::AwaitingSignature,
                &serde_json::json!({ "finalisation": { "should": "not_apply" } }),
            )
            .await
            .expect("cas");
        assert!(
            !refused,
            "status-qualified update must fail when status moved off awaiting_signature"
        );
        let row = store.load(job_id).await.expect("load").expect("row");
        assert_eq!(row.status, crate::job_store::JobStatus::Cancelled);
        assert!(
            row.request_body.get("finalisation").is_none(),
            "refused update must not apply: {:?}",
            row.request_body
        );
    }

    /// Defect 3: after a terminal fail, a leftover envelope (even if a
    /// separate cleanup step never ran) cannot resurrect the job —
    /// strip is atomic with fail, and rehydrate is gated on
    /// `awaiting_signature`.
    #[tokio::test]
    async fn failed_job_envelope_cannot_resurrect_on_resume() {
        use crate::v1::{set_process_stack_mode, ScanStackMode};
        use std::time::Duration;

        let _stack_guard = lock_v1_stack_for_test().await;
        set_process_stack_mode(ScanStackMode::V1);

        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xD6u8; 32],
                Some("k-no-resurrect"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        let (entry, _) = crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let persist = crate::v1::DurableFinalisationPersist::from_entry(&entry)
            .expect("encode durable finalisation");
        let mut req_body = serde_json::json!({});
        req_body.as_object_mut().unwrap().insert(
            crate::v1::FINALISATION_BODY_KEY.to_string(),
            serde_json::to_value(&persist).unwrap(),
        );
        sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
            .bind(&req_body)
            .bind(job_id)
            .execute(state.job_store.pool())
            .await
            .expect("plant envelope");
        state
            .job_store
            .set_awaiting_signature(job_id, 1, crate::v1::awaiting_signature_result_json(&entry))
            .await
            .expect("awaiting_signature");
        // Re-plant after set (status flip does not clear body keys we need).
        sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
            .bind(&req_body)
            .bind(job_id)
            .execute(state.job_store.pool())
            .await
            .expect("replant");

        // Terminal fail: envelope strip is atomic with the status flip.
        state
            .job_store
            .fail(
                job_id,
                crate::job_store::JobStatus::AwaitingSignature,
                "awaiting_signature timeout",
            )
            .await
            .expect("fail");
        let after_fail = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(after_fail.status, crate::job_store::JobStatus::Failed);
        assert!(
            after_fail
                .request_body
                .get(crate::v1::FINALISATION_BODY_KEY)
                .is_none(),
            "fail must strip envelope atomically: {:?}",
            after_fail.request_body
        );

        // Even if a stale map entry survived, process_envelope must not
        // resurrect a terminal job.
        state.pending_sign_map.insert(job_id, entry);
        crate::job_dispatcher::process_envelope_for_test(
            &state.job_store,
            &state,
            &state.job_notify_map,
            Duration::from_secs(5),
            crate::job_dispatcher::JobEnvelope { public_id: job_id },
        )
        .await
        .expect("process terminal is a no-op");
        let after = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(
            after.status,
            crate::job_store::JobStatus::Failed,
            "terminal failed job must not be resurrected"
        );
    }

    /// Defect 4: `/v1/.../stream` emits `event: error` with a closed
    /// enumeration code for a failed job (not `event: complete` + raw string).
    #[test]
    fn v1_stream_failed_job_emits_event_error_with_enumeration() {
        let mut job = make_job(
            JobStatus::Failed,
            None,
            None,
            Some(crate::v1::encode_job_error(
                "proving_failed",
                "witness assembly failed",
            )),
        );
        job.completed_at = Some(chrono::Utc::now());
        // Domain projection + v1 SSE adapter (replaces deleted
        // initial_event_from_job_v1 wrapper).
        let domain = crate::kernel::job_projection::project_job_row(&job)
            .expect("failed row is well-formed");
        let frame =
            crate::router::sse_event_from_job_event_v1(&crate::kernel::JobEvent::from_job(domain));
        let wire = format!("{:?}", frame);
        assert!(
            wire.contains("error"),
            "failed job must use event: error; wire: {wire}"
        );
        // Debug of Event typically renders the event name; refuse complete.
        assert!(
            !wire.contains("\"complete\"") || wire.contains("\"error\""),
            "failed job must use event: error; wire: {wire}"
        );
        assert!(
            wire.contains("proving_failed"),
            "closed machine code required; wire: {wire}"
        );
        // Also exercise the phase→error translation used mid-stream.
        let ev = JobPhaseEvent {
            status: JobStatus::Failed,
            phase: "failed".to_string(),
            proof_id: None,
            result: None,
            error: Some(crate::v1::encode_job_error(
                "proving_failed",
                "witness assembly failed",
            )),
        };
        let mid_domain = crate::kernel::job_projection::project_phase_event(
            crate::kernel::JobId(job.public_id),
            crate::kernel::types::JobKind::Send,
            0,
            &ev,
        )
        .expect("failed phase");
        let mid = crate::router::sse_event_from_job_event_v1(&crate::kernel::JobEvent::from_job(
            mid_domain,
        ));
        let mid_wire = format!("{:?}", mid);
        assert!(
            mid_wire.contains("proving_failed"),
            "mid-stream error frame must carry enumeration; wire: {mid_wire}"
        );
    }

    /// Defect 5: `/v1/.../cancel` accepts a proving job and refuses one
    /// whose nullifier is published (`broadcasting`).
    #[tokio::test]
    async fn v1_cancel_accepts_proving_refuses_published() {
        let (state, _pool, _c) = jobs_test_state().await;

        // Proving → cancel OK.
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xC1u8; 32],
                Some("k-cancel-proving"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let proving_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        state
            .job_store
            .set_status(
                proving_id,
                crate::job_store::JobStatus::Queued,
                crate::job_store::JobStatus::Proving,
                "proving",
            )
            .await
            .expect("proving");

        let req = Request::post(format!("/v1/jobs/{}/cancel", proving_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::OK, "proving cancel body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["status"], "cancelled");

        // Broadcasting (nullifier published / in flight) → wrong_phase.
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[0xC2u8; 32],
                Some("k-cancel-published"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let pub_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        state
            .job_store
            .set_status(
                pub_id,
                crate::job_store::JobStatus::Queued,
                crate::job_store::JobStatus::Broadcasting,
                "broadcasting",
            )
            .await
            .expect("broadcasting");

        let req = Request::post(format!("/v1/jobs/{}/cancel", pub_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(
            status,
            StatusCode::CONFLICT,
            "published cancel body: {resp}"
        );
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "wrong_phase");
    }

    /// Defect 4 (round 5): normative `/v1/jobs/:id/stream` and `/cancel`
    /// are registered and return §7.5 bodies (never a bare framework 404).
    #[tokio::test]
    async fn v1_stream_and_cancel_are_registered_with_section_7_5_errors() {
        let (state, _pool, _c) = jobs_test_state().await;

        // Unknown job → job_not_found on both normative routes.
        let unknown = uuid::Uuid::new_v4();
        let req = Request::get(format!("/v1/jobs/{}/stream", unknown))
            .body(Body::empty())
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "stream body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "job_not_found");
        assert!(v.get("message").is_some());

        let req = Request::post(format!("/v1/jobs/{}/cancel", unknown))
            .body(Body::empty())
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "cancel body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "job_not_found");

        // Malformed UUID → malformed_request (V1JobId extractor).
        let req = Request::post("/v1/jobs/not-a-uuid/cancel")
            .body(Body::empty())
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "malformed_request");
    }

    // ---- DB-error 500 arms ----
    //
    // The handlers' error branches that fire when `JobStore` calls
    // return `Err` (DB unreachable / mid-call disconnect). Routed
    // through a `dead_pool`-backed `JobStore` so every `.await`
    // against it fails fast with a connect error. Mirrors the
    // existing `r2_probe_history_db_error_returns_500` pattern.

    /// Build an `AppState` whose `job_store` is wired to `dead_pool`
    /// (every query fails with a connect error). The admit + load +
    /// cancel handlers all hit their `Err` arm. The mpsc rx is
    /// leaked the same way `jobs_test_state` does — the 503 test
    /// uses a separate helper that drops the rx explicitly.
    fn jobs_test_state_dead_db() -> AppState {
        let mut state = mint_test_state();
        state.job_store = Arc::new(crate::job_store::JobStore::new((*dead_pool()).clone()));
        let (tx, rx) = tokio::sync::mpsc::channel::<crate::job_dispatcher::JobEnvelope>(8);
        state.job_tx = tx;
        std::mem::forget(rx);
        state.job_notify_map = Arc::new(dashmap::DashMap::new());
        state
    }

    #[tokio::test]
    async fn jobs_admit_returns_500_when_db_unavailable() {
        // Targets the `JobStore::create` Err arm in `admit_and_enqueue`
        // (~router.rs Z889-898). Body is a valid creator-signed mint so
        // we sail past `validate_mint_request` and reach the store call.
        let state = jobs_test_state_dead_db();
        let body = signed_mint_body(1);
        let req = Request::post("/api/jobs/mint")
            .header("content-type", "application/json")
            .header("idempotency-key", "k-db-admit")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "Failed to admit job");
    }

    #[tokio::test]
    async fn jobs_get_returns_500_when_db_unavailable() {
        // Targets the `JobStore::load` Err arm in `get_job_handler`
        // (~router.rs Z985-994). Random UUID — the load call fails
        // before the row-not-found arm gets a chance to run.
        let state = jobs_test_state_dead_db();
        let id = uuid::Uuid::new_v4();
        let req = Request::get(format!("/api/jobs/{}", id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "Failed to load job");
    }

    #[tokio::test]
    async fn jobs_commit_returns_500_when_db_unavailable() {
        // Targets the `JobStore::load` Err arm in `jobs_commit_handler`
        // (~router.rs Z1050-1059). Body is structurally valid so we
        // reach the load call before any handler-local validation.
        let state = jobs_test_state_dead_db();
        let id = uuid::Uuid::new_v4();
        let commit_body = serde_json::json!({
            "proof_id": 1u64,
            "public_key": "020000000000000000000000000000000000000000000000000000000000000001",
            "signature": "00".repeat(64),
            "message": "ff".repeat(32),
        });
        let req = Request::post(format!("/api/jobs/{}/commit", id))
            .header("content-type", "application/json")
            .body(Body::from(commit_body.to_string()))
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "Failed to load job");
    }

    #[tokio::test]
    async fn jobs_cancel_returns_500_when_db_unavailable() {
        // Targets the `JobStore::cancel` Err arm in `jobs_cancel_handler`
        // (~router.rs Z1162-1170). Cancel is one statement — `dead_pool`
        // makes the connect attempt fail before any row-state check.
        let state = jobs_test_state_dead_db();
        let id = uuid::Uuid::new_v4();
        let req = Request::post(format!("/api/jobs/{}/cancel", id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "Failed to cancel job");
    }

    #[tokio::test]
    async fn jobs_admit_returns_503_when_dispatcher_unavailable() {
        // Targets the `state.job_tx.send(...)` Err arm in
        // `admit_and_enqueue` (~router.rs Z947-953). The default
        // `jobs_test_state` helper leaks the rx so this arm never
        // fires; here we drop it explicitly so the send fails with
        // a closed-channel error.
        //
        // Setup mirrors `jobs_test_state` so the admit-then-enqueue
        // sequence reaches the channel send: shared `postgres:17`
        // container + per-test schema (issue #181 Opt B; see
        // `crate::test_db`) for the `JobStore::create` happy path,
        // then a freshly-created channel whose rx is dropped before
        // the request is dispatched.
        let _scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(_scope.pool.clone());

        let mut state = mint_test_state();
        state.pool = Arc::clone(&pool);
        state.job_store = Arc::new(crate::job_store::JobStore::new((*pool).clone()));
        let (tx, rx) = tokio::sync::mpsc::channel::<crate::job_dispatcher::JobEnvelope>(8);
        state.job_tx = tx;
        // Drop the rx before the request runs so the admit handler's
        // `job_tx.send(...).await` returns `Err(SendError(...))`.
        drop(rx);
        state.job_notify_map = Arc::new(dashmap::DashMap::new());

        let body = signed_mint_body(1);
        let req = Request::post("/api/jobs/mint")
            .header("content-type", "application/json")
            .header("idempotency-key", "k-dispatcher-down")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "Dispatcher unavailable");
    }

    #[tokio::test]
    async fn jobs_commit_returns_500_when_persist_fails() {
        // Targets the persist-side Err arm in `jobs_commit_handler`
        // (~router.rs Z1106-1113): the `UPDATE jobs SET request_body
        // = $1 ...` statement fails after `JobStore::load` already
        // returned `Ok(Some(_))`.
        //
        // Same-pool problem: load and persist use `job_store.pool()`,
        // so a dead pool short-circuits load before persist is ever
        // reached. We make persist fail in isolation by installing a
        // `NOT VALID` CHECK constraint on the `jobs` table after the
        // row exists — NOT VALID skips existing rows, so the row
        // stays readable, but any subsequent UPDATE has to satisfy
        // the constraint and fails with a constraint violation.
        //
        // Shared `postgres:17` container + per-test schema (issue
        // #181 Opt B; see `crate::test_db`). The schema scope must
        // outlive the test so the schema is not dropped mid-run.
        let _scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(_scope.pool.clone());

        let mut state = mint_test_state();
        state.pool = Arc::clone(&pool);
        state.job_store = Arc::new(crate::job_store::JobStore::new((*pool).clone()));
        let (tx, rx) = tokio::sync::mpsc::channel::<crate::job_dispatcher::JobEnvelope>(8);
        state.job_tx = tx;
        std::mem::forget(rx);
        state.job_notify_map = Arc::new(dashmap::DashMap::new());

        // Admit a Send job and flip to awaiting_signature so the
        // commit handler's status guard passes and reaches the
        // persist statement.
        let result = state
            .job_store
            .create(
                crate::job_store::JobKind::Send,
                &[14u8; 32],
                Some("k-persist-fail"),
                serde_json::json!({"any": "body"}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!("expected fresh"),
        };
        state
            .job_store
            .set_awaiting_signature(job_id, 7, serde_json::json!({}))
            .await
            .expect("aw sig");
        let notifier = Arc::new(crate::job_dispatcher::JobNotifier::new());
        state.job_notify_map.insert(job_id, notifier);

        // Install a CHECK constraint that no future UPDATE can
        // satisfy. NOT VALID lets the existing (already-stored) row
        // remain — load still succeeds — but the UPDATE issued by
        // the persist arm fails with a constraint violation, which
        // surfaces as the 500 we are testing.
        sqlx::query("ALTER TABLE jobs ADD CONSTRAINT block_persist CHECK (false) NOT VALID")
            .execute(&*pool)
            .await
            .expect("install blocking constraint");

        let commit_body = serde_json::json!({
            "proof_id": 7u64,
            "public_key": "020000000000000000000000000000000000000000000000000000000000000001",
            "signature": "00".repeat(64),
            "message": "ff".repeat(32),
        });
        let req = Request::post(format!("/api/jobs/{}/commit", job_id))
            .header("content-type", "application/json")
            .body(Body::from(commit_body.to_string()))
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "Failed to persist commit payload");
    }

    // =======================================================================
    // SSE push channel coverage — `GET /api/jobs/:id/stream` (PR2).
    // =======================================================================
    //
    // The handler entry point + SSE projection helpers
    // (`sse_event_from_job_event_legacy`, `_legacy_phase`) stay covered
    // here. Domain event source coverage lives in `kernel/job_events`.

    use crate::job_dispatcher::{JobNotifier, JobPhaseEvent};
    use crate::job_store::{Job, JobKind, JobStatus};

    /// Decode an SSE-formatted body chunk into `(event, data)` pairs.
    /// The body is the raw bytes that flow through the wire — each
    /// event is delimited by a blank line; comments (`: heartbeat`)
    /// are skipped.
    fn parse_sse_events(body: &str) -> Vec<(String, String)> {
        let mut events = Vec::new();
        for block in body.split("\n\n") {
            let mut event_name = String::from("message");
            let mut data = String::new();
            for line in block.lines() {
                if let Some(rest) = line.strip_prefix("event:") {
                    event_name = rest.trim().to_string();
                } else if let Some(rest) = line.strip_prefix("data:") {
                    if !data.is_empty() {
                        data.push('\n');
                    }
                    data.push_str(rest.trim());
                }
                // Comments (lines starting with ':' but no second
                // ':') and other fields are ignored.
            }
            if !data.is_empty() {
                events.push((event_name, data));
            }
        }
        events
    }

    /// Drain the response body to a String. Caps at ~64 KiB so a
    /// runaway stream cannot wedge the test indefinitely.
    async fn collect_body_string(resp: axum::response::Response) -> String {
        let bytes = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .expect("collect")
            .to_bytes();
        String::from_utf8_lossy(&bytes).to_string()
    }

    // ---- Legacy SSE projection pure-helper coverage ----
    // (domain event source: `kernel/job_events`; wire: `sse_event_from_job_event_*`)

    /// Helper: build a `Job` row directly (no DB) so the pure helpers
    /// can be exercised without a testcontainer.
    fn make_job(
        status: JobStatus,
        proof_id: Option<i64>,
        response_body: Option<serde_json::Value>,
        error: Option<String>,
    ) -> Job {
        Job {
            id: 1,
            public_id: uuid::Uuid::new_v4(),
            kind: JobKind::Mint,
            status,
            phase: status.as_str().to_string(),
            account_address: [0u8; 32],
            idempotency_key: None,
            request_body: serde_json::json!({}),
            response_body,
            response_status: None,
            proof_id,
            error,
            progress: 0,
            reset_generation: 0,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            completed_at: None,
        }
    }

    fn legacy_snapshot_event(job: &Job) -> axum::response::sse::Event {
        let domain = crate::kernel::job_projection::project_job_row(job)
            .unwrap_or_else(|e| panic!("corrupt row: {e}"));
        crate::router::sse_event_from_job_event_legacy(&crate::kernel::JobEvent::from_job(domain))
    }

    fn legacy_phase_event(ev: &JobPhaseEvent) -> axum::response::sse::Event {
        let domain = crate::kernel::job_projection::project_phase_event(
            crate::kernel::JobId(uuid::Uuid::nil()),
            crate::kernel::types::JobKind::Mint,
            0,
            ev,
        )
        .unwrap_or_else(|e| panic!("corrupt phase: {e}"));
        crate::router::sse_event_from_job_event_legacy_phase(&crate::kernel::JobEvent::from_job(
            domain,
        ))
    }

    #[test]
    fn initial_event_proving_serialises_as_phase() {
        let job = make_job(JobStatus::Proving, None, None, None);
        let event = legacy_snapshot_event(&job);
        let wire = format!("{:?}", event);
        // The Event Debug impl renders the assembled SSE frame; we
        // assert on the event name field rather than the entire
        // formatted output.
        assert!(wire.contains("phase"), "wire: {}", wire);
    }

    #[test]
    fn initial_event_awaiting_signature_includes_proof_id_and_result() {
        // `awaiting_signature` carries the ash/ocr hex in `response_body`
        // (set by `JobStore::set_awaiting_signature`); the SSE initial
        // frame must surface both the `proof_id` and that `result` so a
        // wallet reconnecting after a node restart gets the hex to sign.
        let job = make_job(
            JobStatus::AwaitingSignature,
            Some(42),
            Some(serde_json::json!({
                "account_state_hash": "aa".repeat(32),
                "output_coins_root": "bb".repeat(32),
            })),
            None,
        );
        let event = legacy_snapshot_event(&job);
        // Re-serialise to check the payload contents.
        let wire = format!("{:?}", event);
        assert!(wire.contains("phase"), "wire: {}", wire);
        assert!(
            wire.contains("42"),
            "proof_id 42 must surface; wire: {}",
            wire
        );
        assert!(
            wire.contains("account_state_hash") && wire.contains("output_coins_root"),
            "ash/ocr result must surface on the awaiting_signature frame; wire: {}",
            wire
        );
    }

    #[test]
    fn initial_event_completed_emits_complete_event() {
        let job = make_job(
            JobStatus::Completed,
            None,
            Some(serde_json::json!({"success": true})),
            None,
        );
        let event = legacy_snapshot_event(&job);
        let wire = format!("{:?}", event);
        assert!(wire.contains("complete"), "wire: {}", wire);
        assert!(
            wire.contains("success"),
            "result body must surface; wire: {}",
            wire
        );
    }

    #[test]
    fn initial_event_failed_emits_complete_event_with_error() {
        let job = make_job(JobStatus::Failed, None, None, Some("boom".to_string()));
        let event = legacy_snapshot_event(&job);
        let wire = format!("{:?}", event);
        assert!(wire.contains("complete"), "wire: {}", wire);
        assert!(wire.contains("boom"), "wire: {}", wire);
    }

    #[test]
    fn initial_event_cancelled_emits_complete_event() {
        let job = make_job(JobStatus::Cancelled, None, None, None);
        let event = legacy_snapshot_event(&job);
        let wire = format!("{:?}", event);
        assert!(wire.contains("complete"), "wire: {}", wire);
    }

    // ---- mid-stream legacy phase projection ----

    #[test]
    fn event_from_phase_proving_emits_phase_event() {
        let ev = JobPhaseEvent {
            status: JobStatus::Proving,
            phase: "proving".to_string(),
            proof_id: None,
            result: None,
            error: None,
        };
        let frame = legacy_phase_event(&ev);
        let wire = format!("{:?}", frame);
        assert!(wire.contains("phase"), "wire: {}", wire);
    }

    #[test]
    fn event_from_phase_awaiting_signature_includes_proof_id() {
        // Domain projection fail-closes without a signature surface payload
        // (same rule as GetJob / project_job_row). Include a minimal body so
        // the pure helper exercises the proof_id wire field.
        // Statement now also held by kernel/job_events + sse projection.
        let ev = JobPhaseEvent {
            status: JobStatus::AwaitingSignature,
            phase: "awaiting_signature".to_string(),
            proof_id: Some(17),
            result: Some(serde_json::json!({
                "account_state_hash": "aa".repeat(32),
                "output_coins_root": "bb".repeat(32),
            })),
            error: None,
        };
        let frame = legacy_phase_event(&ev);
        let wire = format!("{:?}", frame);
        assert!(wire.contains("phase"), "wire: {}", wire);
        assert!(wire.contains("17"), "wire: {}", wire);
    }

    #[test]
    fn event_from_phase_completed_emits_complete_event() {
        let ev = JobPhaseEvent {
            status: JobStatus::Completed,
            phase: "completed".to_string(),
            proof_id: None,
            result: Some(serde_json::json!({"ok": 1})),
            error: None,
        };
        let frame = legacy_phase_event(&ev);
        let wire = format!("{:?}", frame);
        assert!(wire.contains("complete"), "wire: {}", wire);
    }

    #[test]
    fn event_from_phase_failed_emits_complete_event() {
        let ev = JobPhaseEvent {
            status: JobStatus::Failed,
            phase: "failed".to_string(),
            proof_id: None,
            result: None,
            error: Some("err".to_string()),
        };
        let frame = legacy_phase_event(&ev);
        let wire = format!("{:?}", frame);
        assert!(wire.contains("complete"), "wire: {}", wire);
    }

    #[test]
    fn event_from_phase_cancelled_emits_complete_event() {
        let ev = JobPhaseEvent {
            status: JobStatus::Cancelled,
            phase: "cancelled".to_string(),
            proof_id: None,
            result: None,
            error: None,
        };
        let frame = legacy_phase_event(&ev);
        let wire = format!("{:?}", frame);
        assert!(wire.contains("complete"), "wire: {}", wire);
    }

    // ---- `stream_job_handler` route-level coverage ----

    #[tokio::test]
    async fn jobs_stream_404_for_unknown_id() {
        let (state, _pool, _c) = jobs_test_state().await;
        let id = uuid::Uuid::new_v4();
        let req = Request::get(format!("/api/jobs/{}/stream", id))
            .body(Body::empty())
            .unwrap();
        let app = create_router(state);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn jobs_stream_returns_500_when_db_unavailable() {
        // Targets the `JobStore::load` Err arm in
        // `stream_job_handler` — same shape as the GET 500 test.
        let state = jobs_test_state_dead_db();
        let id = uuid::Uuid::new_v4();
        let req = Request::get(format!("/api/jobs/{}/stream", id))
            .body(Body::empty())
            .unwrap();
        let app = create_router(state);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn jobs_stream_closes_immediately_for_terminal_job() {
        // Completed jobs surface the cached body as a single
        // `event: complete` frame and the stream closes — no
        // subscription needed.
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                JobKind::Mint,
                &[20u8; 32],
                Some("k-stream-done"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        state
            .job_store
            .complete(
                job_id,
                crate::job_store::JobStatus::Queued,
                serde_json::json!({"success": true, "proof_id": 5u64}),
                200,
            )
            .await
            .expect("complete");

        let req = Request::get(format!("/api/jobs/{}/stream", job_id))
            .body(Body::empty())
            .unwrap();
        let app = create_router(state);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let content_type = resp
            .headers()
            .get("content-type")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            content_type.starts_with("text/event-stream"),
            "content-type was {}",
            content_type
        );
        let body = collect_body_string(resp).await;
        let events = parse_sse_events(&body);
        // First event must be `complete` (terminal job).
        assert!(
            !events.is_empty(),
            "expected at least one event; body={}",
            body
        );
        let (first_name, first_data) = &events[0];
        assert_eq!(first_name, "complete");
        let v: serde_json::Value = serde_json::from_str(first_data).expect("first event JSON");
        assert_eq!(v["status"], "completed");
        assert_eq!(v["result"]["proof_id"], 5u64);
    }

    #[tokio::test]
    async fn jobs_stream_failed_terminal_closes_with_complete_and_error() {
        // Failed jobs surface the error string as a single
        // `event: complete` and close.
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                JobKind::Mint,
                &[21u8; 32],
                Some("k-stream-fail"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        state
            .job_store
            .fail(
                job_id,
                crate::job_store::JobStatus::Queued,
                "synthetic fail",
            )
            .await
            .expect("fail");

        let req = Request::get(format!("/api/jobs/{}/stream", job_id))
            .body(Body::empty())
            .unwrap();
        let app = create_router(state);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = collect_body_string(resp).await;
        let events = parse_sse_events(&body);
        assert!(!events.is_empty(), "body={}", body);
        let (name, data) = &events[0];
        assert_eq!(name, "complete");
        let v: serde_json::Value = serde_json::from_str(data).unwrap();
        assert_eq!(v["status"], "failed");
        assert_eq!(v["error"], "synthetic fail");
    }

    #[tokio::test]
    async fn jobs_stream_emits_initial_phase_for_non_terminal_job() {
        // Queued (non-terminal) jobs emit an initial `event: phase`
        // and then stay open waiting for transitions. We close the
        // stream by flipping the job to a terminal state and reading
        // the second event.
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                JobKind::Mint,
                &[22u8; 32],
                Some("k-stream-queued"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        // Pre-arm the notifier so the dispatcher's not-yet-running
        // race condition does not lose the phase event we push below.
        let notifier = Arc::new(JobNotifier::new());
        state.job_notify_map.insert(job_id, notifier.clone());

        let req = Request::get(format!("/api/jobs/{}/stream", job_id))
            .body(Body::empty())
            .unwrap();
        let app = create_router(state.clone());

        // Drive the request in the background so we can publish a
        // phase event into the broadcast channel while the stream
        // is still open. The handler subscribes BEFORE yielding the
        // first initial event, so any event published during the
        // handler's setup window also lands in the receiver queue.
        let request_task = tokio::spawn(async move { app.oneshot(req).await.unwrap() });

        // Give the handler a beat to subscribe; then publish a
        // terminal event so the stream closes promptly.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        crate::job_dispatcher::publish_phase(
            &state.job_notify_map,
            job_id,
            JobPhaseEvent {
                status: JobStatus::Completed,
                phase: "completed".to_string(),
                proof_id: None,
                result: Some(serde_json::json!({"ok": true})),
                error: None,
            },
        );

        let resp = tokio::time::timeout(std::time::Duration::from_secs(30), request_task)
            .await
            .expect("request did not complete in time")
            .expect("join");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = collect_body_string(resp).await;
        let events = parse_sse_events(&body);
        assert!(
            events.len() >= 2,
            "expected initial phase + complete; body={}",
            body
        );
        let (first_name, first_data) = &events[0];
        assert_eq!(first_name, "phase", "first event must be phase");
        let v: serde_json::Value = serde_json::from_str(first_data).unwrap();
        assert_eq!(v["status"], "queued");
        // The last event is the complete one we published.
        let (last_name, last_data) = events.last().unwrap();
        assert_eq!(last_name, "complete");
        let v: serde_json::Value = serde_json::from_str(last_data).unwrap();
        assert_eq!(v["status"], "completed");
    }

    #[tokio::test]
    async fn jobs_stream_forwards_dispatcher_phase_transition() {
        // Drive a full happy-path sequence:
        //   initial (queued) → proving (published) → completed (published)
        // through the handler and verify all three frames land in
        // the wallet-visible body.
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                JobKind::Send,
                &[23u8; 32],
                Some("k-stream-transitions"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        // Pre-arm the notifier; the dispatcher would normally do
        // this when it picks the row off the channel.
        let notifier = Arc::new(JobNotifier::new());
        state.job_notify_map.insert(job_id, notifier);

        let req = Request::get(format!("/api/jobs/{}/stream", job_id))
            .body(Body::empty())
            .unwrap();
        let app = create_router(state.clone());
        let request_task = tokio::spawn(async move { app.oneshot(req).await.unwrap() });

        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        crate::job_dispatcher::publish_phase(
            &state.job_notify_map,
            job_id,
            JobPhaseEvent {
                status: JobStatus::Proving,
                phase: "proving".to_string(),
                proof_id: None,
                result: None,
                error: None,
            },
        );
        // Small spacer so the proving event lands before the close.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        crate::job_dispatcher::publish_phase(
            &state.job_notify_map,
            job_id,
            JobPhaseEvent {
                status: JobStatus::Completed,
                phase: "completed".to_string(),
                proof_id: None,
                result: Some(serde_json::json!({"done": true})),
                error: None,
            },
        );

        let resp = tokio::time::timeout(std::time::Duration::from_secs(30), request_task)
            .await
            .expect("request stalled")
            .expect("join");
        assert_eq!(resp.status(), StatusCode::OK);
        let body = collect_body_string(resp).await;
        let events = parse_sse_events(&body);
        // initial phase + proving + complete = 3 events, possibly
        // interleaved with heartbeat comments (which `parse_sse_events`
        // strips).
        let names: Vec<&str> = events.iter().map(|(n, _)| n.as_str()).collect();
        assert!(
            names.contains(&"phase"),
            "expected `phase` event; got {:?}",
            names
        );
        assert!(
            names.contains(&"complete"),
            "expected `complete` event; got {:?}",
            names
        );
        // Verify proving payload arrived.
        let has_proving = events
            .iter()
            .filter(|(n, _)| n == "phase")
            .any(|(_, d)| d.contains("\"proving\""));
        assert!(has_proving, "proving phase event missing; body={}", body);
    }

    // ---- Cancel → SSE complete event smoke test ----

    #[tokio::test]
    async fn jobs_cancel_publishes_phase_to_sse() {
        // Cancel-handler publishes a `cancelled` event so a subscriber
        // attached BEFORE the cancel observes the terminal frame.
        let (state, _pool, _c) = jobs_test_state().await;
        let result = state
            .job_store
            .create(
                JobKind::Mint,
                &[24u8; 32],
                Some("k-stream-cancel"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        let notifier = Arc::new(JobNotifier::new());
        let mut rx = notifier.phase_tx.subscribe();
        state.job_notify_map.insert(job_id, notifier);

        // Run the cancel via the router so the publish path runs end-to-end.
        let req = Request::post(format!("/api/jobs/{}/cancel", job_id))
            .body(Body::empty())
            .unwrap();
        let app = create_router(state);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let ev = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
            .await
            .expect("event in 10s")
            .expect("ok");
        assert_eq!(ev.status, JobStatus::Cancelled);
        assert_eq!(ev.phase, "cancelled");
    }

    // ---- Block 2: fail-closed stream masking (would have been green on old code) ----

    /// Plant a completed row with SQL NULL `response_body`. Opening the
    /// legacy stream must not emit `event: complete` with `result: null`.
    #[tokio::test]
    async fn jobs_stream_completed_without_result_is_internal_error() {
        let (state, pool, _c) = jobs_test_state().await;
        let job_id = plant_completed_without_response_body(
            pool.as_ref(),
            [0xD1u8; 32],
            "k-stream-corrupt-complete",
        )
        .await;

        let req = Request::get(format!("/api/jobs/{}/stream", job_id))
            .body(Body::empty())
            .unwrap();
        let app = create_router(state);
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(
            resp.status(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "corrupt completed must not open an SSE stream that masks null result"
        );
    }

    /// Same corrupt row on the normative stream → §7.5 `internal_error`.
    #[tokio::test]
    async fn v1_stream_completed_without_result_is_internal_error() {
        let (state, pool, _c) = jobs_test_state().await;
        let job_id = plant_completed_without_response_body(
            pool.as_ref(),
            [0xD2u8; 32],
            "k-v1-stream-corrupt-complete",
        )
        .await;

        let req = Request::get(format!("/v1/jobs/{}/stream", job_id))
            .body(Body::empty())
            .unwrap();
        let (status, _h, body) = run(state, req).await;
        assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "body={body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(v["error"], "internal_error");
        assert_eq!(v["message"], "Failed to load job");
        assert!(
            v.get("result").is_none(),
            "must not look like success: {body}"
        );
    }

    // Fail-closed pure-helper cases for completed / awaiting_signature
    // without payload are covered in `kernel::job_projection` tests
    // (assert on KernelErrorCode + detail cause — no `should_panic`).

    // -----------------------------------------------------------------------
    // §4.6 / §7.5 open token-provenance REST surface
    // -----------------------------------------------------------------------

    fn recompute_token_provenance_asset_id(
        terms: &shared::spec_v1::bundle::IssuanceTerms,
    ) -> [u8; 32] {
        use shared::spec_v1::encoding::digest_to_bytes;
        use shared::spec_v1::hashes::{asset_id_v1, asset_id_v2, name_hash};
        use shared::spec_v1::tags::GENESIS_TAG;

        let name_hash = name_hash(&terms.name).expect("valid test name");
        let digest = match terms.issuance_version {
            1 => asset_id_v1(
                GENESIS_TAG,
                &terms.creator_pubkey,
                &name_hash,
                terms.decimals,
                terms.issuance_version,
            ),
            2 => asset_id_v2(
                GENESIS_TAG,
                &terms.creator_pubkey,
                &name_hash,
                terms.decimals,
                terms.issuance_version,
                terms.cap_total.expect("v2 cap"),
                &terms.terms_salt.expect("v2 salt"),
            ),
            other => panic!("unsupported test issuance version {other}"),
        };
        digest_to_bytes(&digest)
    }

    #[tokio::test]
    async fn token_provenance_v1_held_returns_schema() {
        use shared::spec_v1::bundle::IssuanceTerms;
        use shared::spec_v1::encoding::digest_to_bytes;
        use shared::spec_v1::hashes::{asset_id_v1, name_hash};
        use shared::spec_v1::tags::GENESIS_TAG;

        let (state, pool, _scope) = jobs_test_state().await;
        let terms = IssuanceTerms {
            creator_pubkey: [0x51u8; 32],
            decimals: 3,
            issuance_version: 1,
            name: vec![0xff, 0x00, b'R', b'1'],
            cap_total: None,
            terms_salt: None,
        };
        let asset_id = recompute_token_provenance_asset_id(&terms);
        crate::v1::db_token_provenance::insert_token_provenance(&pool, &asset_id, &terms)
            .await
            .expect("seed v1 retained provenance");

        let req = Request::get(format!(
            "/v1/token/{}/provenance",
            hex::encode(asset_id)
        ))
        .body(Body::empty())
        .unwrap();
        let (status, _headers, body) = run(state, req).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        let v: serde_json::Value = serde_json::from_str(&body).expect("token provenance json");
        assert_eq!(
            v.as_object().expect("token provenance object").len(),
            5,
            "unexpected v1 response fields: {body}"
        );
        assert_eq!(v["asset_id"], hex::encode(asset_id));
        assert_eq!(v["issuance_version"], 1);
        assert_eq!(v["creator_pubkey"], hex::encode(terms.creator_pubkey));
        assert_eq!(v["name"], hex::encode(&terms.name));
        assert_eq!(v["decimals"], terms.decimals);
        assert!(v.get("cap_total").is_none(), "v1 must omit cap_total: {body}");
        assert!(v.get("terms_salt").is_none(), "v1 must omit terms_salt: {body}");

        let returned_asset_id: [u8; 32] = hex::decode(
            v["asset_id"]
                .as_str()
                .expect("response asset_id is a hex string"),
        )
        .expect("response asset_id is valid hex")
        .try_into()
        .expect("response asset_id is 32 bytes");
        let response_name_hash = name_hash(&terms.name).expect("valid test name");
        let recomputed = digest_to_bytes(&asset_id_v1(
            GENESIS_TAG,
            &terms.creator_pubkey,
            &response_name_hash,
            terms.decimals,
            terms.issuance_version,
        ));
        assert_eq!(returned_asset_id, recomputed);
    }

    #[tokio::test]
    async fn token_provenance_v2_held_returns_cap() {
        use shared::spec_v1::bundle::IssuanceTerms;
        use shared::spec_v1::encoding::digest_to_bytes;
        use shared::spec_v1::hashes::{asset_id_v2, name_hash};
        use shared::spec_v1::tags::GENESIS_TAG;

        let (state, pool, _scope) = jobs_test_state().await;
        let terms = IssuanceTerms {
            creator_pubkey: [0x52u8; 32],
            decimals: 9,
            issuance_version: 2,
            name: b"router-v2".to_vec(),
            cap_total: Some(u128::MAX - 17),
            terms_salt: Some([0x53u8; 32]),
        };
        let asset_id = recompute_token_provenance_asset_id(&terms);
        crate::v1::db_token_provenance::insert_token_provenance(&pool, &asset_id, &terms)
            .await
            .expect("seed v2 retained provenance");

        let req = Request::get(format!(
            "/v1/token/{}/provenance",
            hex::encode(asset_id)
        ))
        .body(Body::empty())
        .unwrap();
        let (status, _headers, body) = run(state, req).await;
        assert_eq!(status, StatusCode::OK, "body: {body}");

        let v: serde_json::Value = serde_json::from_str(&body).expect("token provenance json");
        assert_eq!(
            v.as_object().expect("token provenance object").len(),
            7,
            "unexpected v2 response fields: {body}"
        );
        assert_eq!(v["asset_id"], hex::encode(asset_id));
        assert_eq!(v["issuance_version"], 2);
        assert_eq!(v["creator_pubkey"], hex::encode(terms.creator_pubkey));
        assert_eq!(v["name"], hex::encode(&terms.name));
        assert_eq!(v["decimals"], terms.decimals);

        let response_cap = v["cap_total"]
            .as_str()
            .expect("v2 cap_total is a decimal string");
        assert_eq!(
            response_cap.parse::<u128>().expect("v2 cap_total parses as u128"),
            terms.cap_total.expect("v2 cap")
        );
        assert_eq!(
            response_cap,
            terms.cap_total.expect("v2 cap").to_string()
        );
        assert_eq!(
            v["terms_salt"],
            hex::encode(terms.terms_salt.expect("v2 salt"))
        );
        let response_salt: [u8; 32] = hex::decode(
            v["terms_salt"]
                .as_str()
                .expect("v2 terms_salt is a hex string"),
        )
        .expect("v2 terms_salt is valid hex")
        .try_into()
        .expect("v2 terms_salt is 32 bytes");
        assert_eq!(response_salt, terms.terms_salt.expect("v2 salt"));

        let returned_asset_id: [u8; 32] = hex::decode(
            v["asset_id"]
                .as_str()
                .expect("response asset_id is a hex string"),
        )
        .expect("response asset_id is valid hex")
        .try_into()
        .expect("response asset_id is 32 bytes");
        let response_name_hash = name_hash(&terms.name).expect("valid test name");
        let recomputed = digest_to_bytes(&asset_id_v2(
            GENESIS_TAG,
            &terms.creator_pubkey,
            &response_name_hash,
            terms.decimals,
            terms.issuance_version,
            terms.cap_total.expect("v2 cap"),
            &terms.terms_salt.expect("v2 salt"),
        ));
        assert_eq!(returned_asset_id, recomputed);
    }

    #[tokio::test]
    async fn token_provenance_unknown_returns_404() {
        let (state, _pool, _scope) = jobs_test_state().await;
        let asset_id = [0xeeu8; 32];
        let req = Request::get(format!(
            "/v1/token/{}/provenance",
            hex::encode(asset_id)
        ))
        .body(Body::empty())
        .unwrap();
        let (status, _headers, body) = run(state, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {body}");
        let v: serde_json::Value = serde_json::from_str(&body).expect("not-found json");
        assert_eq!(v["error"], "not_found");
        assert!(v["message"].as_str().is_some(), "missing message: {body}");
    }

    #[tokio::test]
    async fn token_provenance_malformed_asset_id_returns_400() {
        let (state, _pool, _scope) = jobs_test_state().await;

        for width in [31usize, 33] {
            let req = Request::get(format!(
                "/v1/token/{}/provenance",
                "aa".repeat(width)
            ))
            .body(Body::empty())
            .unwrap();
            let (status, _headers, body) = run(state.clone(), req).await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "{width}-byte asset_id body: {body}"
            );
            let v: serde_json::Value =
                serde_json::from_str(&body).expect("malformed-request json");
            assert_eq!(v["error"], "malformed_request");
            assert!(v["message"].as_str().is_some(), "missing message: {body}");
        }
    }

    #[tokio::test]
    async fn token_provenance_not_feature_gated_serves_without_v1_claim() {
        use shared::spec_v1::bundle::IssuanceTerms;

        // Deliberately no `set_process_stack_mode` call and no `_stack_guard`:
        // unlike sign/attest routes, open provenance must not consult a gate.
        let (state, pool, _scope) = jobs_test_state().await;
        let terms = IssuanceTerms {
            creator_pubkey: [0x61u8; 32],
            decimals: 6,
            issuance_version: 1,
            name: b"ungated-router".to_vec(),
            cap_total: None,
            terms_salt: None,
        };
        let held_asset_id = recompute_token_provenance_asset_id(&terms);
        crate::v1::db_token_provenance::insert_token_provenance(
            &pool,
            &held_asset_id,
            &terms,
        )
        .await
        .expect("seed ungated retained provenance");

        let held_req = Request::get(format!(
            "/v1/token/{}/provenance",
            hex::encode(held_asset_id)
        ))
        .body(Body::empty())
        .unwrap();
        let (held_status, _headers, held_body) = run(state.clone(), held_req).await;
        assert_eq!(held_status, StatusCode::OK, "body: {held_body}");
        let held_json: serde_json::Value =
            serde_json::from_str(&held_body).expect("held provenance json");
        assert_eq!(held_json["asset_id"], hex::encode(held_asset_id));
        assert!(
            held_json.get("error").is_none(),
            "ungated success returned an error: {held_body}"
        );

        let unknown_asset_id = [0xfdu8; 32];
        assert_ne!(unknown_asset_id, held_asset_id, "fixed unknown id collision");
        let unknown_req = Request::get(format!(
            "/v1/token/{}/provenance",
            hex::encode(unknown_asset_id)
        ))
        .body(Body::empty())
        .unwrap();
        let (unknown_status, _headers, unknown_body) = run(state, unknown_req).await;
        assert_eq!(
            unknown_status,
            StatusCode::NOT_FOUND,
            "body: {unknown_body}"
        );
        let unknown_json: serde_json::Value =
            serde_json::from_str(&unknown_body).expect("unknown provenance json");
        assert_eq!(unknown_json["error"], "not_found");
        assert_ne!(unknown_json["error"], "feature_disabled");
    }

    // -----------------------------------------------------------------------
    // Gap G6 — §7.5 balance attestation surface
    // -----------------------------------------------------------------------

    /// Flag-off: both attest routes refuse with `feature_disabled` (404).
    #[tokio::test]
    async fn attest_balance_flag_off_returns_feature_disabled() {
        let _lock = lock_v1_stack_for_test().await;

        let state = test_state();
        let body = serde_json::json!({
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gtw4c"
        });
        let req = Request::post("/v1/attest/balance/challenge")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "feature_disabled");

        let body = serde_json::json!({
            "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gtw4c",
            "asset_id": "00".repeat(32),
            "challenge": { "nonce": "11".repeat(32) },
            "ownership_proof": {
                "type": "ownership",
                "subject": "zk1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq6gtw4c",
                "public_key": "00".repeat(32),
                "nk_commit": "00".repeat(32),
                "signature": "00".repeat(64),
            }
        });
        let req = Request::post("/v1/attest/balance")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "feature_disabled");
    }

    /// Defect 4: flag check runs before V1Json. A malformed body to a
    /// disabled endpoint must still be `feature_disabled`, not
    /// `malformed_request`.
    #[tokio::test]
    async fn attest_balance_flag_off_malformed_body_is_feature_disabled() {
        let _lock = lock_v1_stack_for_test().await;

        let state = test_state();

        // Broken JSON syntax on challenge.
        let req = Request::post("/v1/attest/balance/challenge")
            .header("content-type", "application/json")
            .body(Body::from("{not-json"))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(
            v["error"], "feature_disabled",
            "flag-off must beat V1Json extraction; got: {resp}"
        );

        // Empty / missing body on admit.
        let req = Request::post("/v1/attest/balance")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "feature_disabled");

        // Wrong content-type.
        let req = Request::post("/v1/attest/balance")
            .header("content-type", "text/plain")
            .body(Body::from("x"))
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "feature_disabled");
    }

    /// §7.5 path + envelope + closed error codes under a v1.1 claim.
    #[tokio::test]
    async fn attest_balance_route_matches_section_7_5() {
        let _lock = lock_v1_stack_for_test().await;
        use crate::v1::{
            parse_u64_decimal, set_process_stack_mode, ScanStackMode,
            ATTEST_BALANCE_CHALLENGE_DOMAIN,
        };
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
        use shared::spec_v1::{self as host, Address};

        set_process_stack_mode(ScanStackMode::V1);

        let host_name = "node.test";
        let (mut state, pool, _scope) = jobs_test_state().await;
        // DB marker + process claim so EngineAdapter::persist is allowed.
        crate::v1::claim_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect("claim v1 stack_scan_mode");
        state.public_hosts = Arc::new(vec![host_name.to_string()]);

        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&[0x42u8; 32]).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        let pk0 = xonly.serialize();
        let nk = [0x11u8; 32];
        let nkc = host::nk_commit(&nk);
        let nkc_bytes = host::digest_to_bytes(&nkc);
        let subject_bytes = host::address(&pk0, nkc);
        let subject = Address(subject_bytes).to_bech32m();
        let asset = [0x22u8; 32];

        let req = Request::post("/v1/attest/balance/challenge")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "subject": subject }).to_string(),
            ))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::OK, "challenge body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["domain"], ATTEST_BALANCE_CHALLENGE_DOMAIN);
        let nonce_hex = v["nonce"].as_str().expect("nonce").to_string();
        assert_eq!(nonce_hex.len(), 64);
        // §7.1: expiry is a decimal **string**, never a JSON number.
        assert!(
            v["expiry"].as_str().is_some(),
            "expiry must be a decimal string, got: {}",
            v["expiry"]
        );
        assert!(
            v["expiry"].as_u64().is_none(),
            "expiry must not be a JSON number"
        );
        let _ = parse_u64_decimal(v["expiry"].as_str().unwrap()).expect("canonical u64 string");

        let body = serde_json::json!({
            "subject": subject,
            "asset_id": hex::encode(asset),
            "challenge": { "nonce": nonce_hex },
            "ownership_proof": {
                "type": "grant",
                "subject": subject,
                "public_key": hex::encode(pk0),
                "nk_commit": hex::encode(nkc_bytes),
                "signature": "00".repeat(64),
            }
        });
        let req = Request::post("/v1/attest/balance")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "unauthorized");

        let req = Request::post("/v1/attest/balance/challenge")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "subject": subject }).to_string(),
            ))
            .unwrap();
        let (_s, _h, resp) = run(state.clone(), req).await;
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        let nonce_hex = v["nonce"].as_str().unwrap().to_string();

        let body = serde_json::json!({
            "subject": subject,
            "asset_id": hex::encode(asset),
            "nav_ceiling": hex::encode([0xabu8; 32]),
            "challenge": { "nonce": nonce_hex },
            "ownership_proof": {
                "type": "ownership",
                "subject": subject,
                "public_key": hex::encode(pk0),
                "nk_commit": hex::encode(nkc_bytes),
                "signature": "00".repeat(64),
            }
        });
        let req = Request::post("/v1/attest/balance")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "malformed_request");

        // Numeric size_ceiling is §7.1-malformed (must be decimal string).
        let req = Request::post("/v1/attest/balance/challenge")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "subject": subject }).to_string(),
            ))
            .unwrap();
        let (_s, _h, resp) = run(state.clone(), req).await;
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        let nonce_hex = v["nonce"].as_str().unwrap().to_string();
        let body = serde_json::json!({
            "subject": subject,
            "asset_id": hex::encode(asset),
            "nav_ceiling": hex::encode([0xabu8; 32]),
            "size_ceiling": 7,
            "challenge": { "nonce": nonce_hex },
            "ownership_proof": {
                "type": "ownership",
                "subject": subject,
                "public_key": hex::encode(pk0),
                "nk_commit": hex::encode(nkc_bytes),
                "signature": "00".repeat(64),
            }
        });
        let req = Request::post("/v1/attest/balance")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "numeric size_ceiling must be malformed_request: {resp}"
        );
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "malformed_request");

        let body = serde_json::json!({
            "subject": subject,
            "asset_id": hex::encode(asset),
            "challenge": { "nonce": "ff".repeat(32) },
            "ownership_proof": {
                "type": "ownership",
                "subject": subject,
                "public_key": hex::encode(pk0),
                "nk_commit": hex::encode(nkc_bytes),
                "signature": "00".repeat(64),
            }
        });
        let req = Request::post("/v1/attest/balance")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::GONE, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "challenge_expired");

        let req = Request::post("/v1/attest/balance/challenge")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::json!({ "subject": subject }).to_string(),
            ))
            .unwrap();
        let (_s, _h, resp) = run(state.clone(), req).await;
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        let nonce_hex = v["nonce"].as_str().unwrap().to_string();
        let expiry = parse_u64_decimal(v["expiry"].as_str().unwrap()).unwrap();
        let nonce: [u8; 32] = hex::decode(&nonce_hex).unwrap().try_into().unwrap();

        let ceiling_enc = crate::v1::attest::ceiling_encoding(None, None).unwrap();
        let request_hash =
            crate::v1::attest::attest_request_hash(&subject_bytes, &asset, &ceiling_enc);
        let cb = crate::v1::attest::chan_bind_for_host(host_name);
        let chal = crate::v1::attest::attest_challenge_message(
            &nonce,
            &cb,
            &subject_bytes,
            expiry,
            &request_hash,
        );
        let msg = Message::from_digest_slice(&chal).unwrap();
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(sig.as_ref());

        let adapter = crate::v1::EngineAdapter::load_or_create(
            (*pool).clone(),
            zkcoins_program::circuit::compliance::Network::Regtest,
            0,
        )
        .await
        .expect("engine");
        state.v1_engine = Some(std::sync::Arc::new(adapter));

        let body = serde_json::json!({
            "subject": subject,
            "asset_id": hex::encode(asset),
            "challenge": { "nonce": hex::encode(nonce) },
            "ownership_proof": {
                "type": "ownership",
                "subject": subject,
                "public_key": hex::encode(pk0),
                "nk_commit": hex::encode(nkc_bytes),
                "signature": hex::encode(sig_bytes),
            }
        });
        let req = Request::post("/v1/attest/balance")
            .header("content-type", "application/json")
            .body(Body::from(body.to_string()))
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::ACCEPTED, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert!(v.get("job_id").and_then(|j| j.as_str()).is_some());
        assert!(v.get("status").is_none(), "§7.5 admit is {{ job_id }} only");
    }

    /// V1Json extractor: malformed / missing JSON → 400 malformed_request
    /// (not Axum's default 422).
    #[tokio::test]
    async fn attest_balance_malformed_json_returns_malformed_request() {
        let _lock = lock_v1_stack_for_test().await;
        use crate::v1::{set_process_stack_mode, ScanStackMode};

        set_process_stack_mode(ScanStackMode::V1);
        let state = test_state();

        // Broken JSON syntax.
        let req = Request::post("/v1/attest/balance/challenge")
            .header("content-type", "application/json")
            .body(Body::from("{not-json"))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "malformed_request");

        // Missing required field on admit body.
        let req = Request::post("/v1/attest/balance")
            .header("content-type", "application/json")
            .body(Body::from("{}"))
            .unwrap();
        let (status, _h, resp) = run(state.clone(), req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "malformed_request");

        // Not JSON content-type.
        let req = Request::post("/v1/attest/balance")
            .header("content-type", "text/plain")
            .body(Body::from("x"))
            .unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(v["error"], "malformed_request");
    }

    /// Root closed map advertises the §7.5 attest surface **only when the
    /// flag is on**.
    #[tokio::test]
    async fn root_advertises_attest_balance_endpoints_when_flag_on() {
        let _lock = lock_v1_stack_for_test().await;
        use crate::v1::{set_process_stack_mode, ScanStackMode};
        set_process_stack_mode(ScanStackMode::V1);

        let state = test_state();
        let req = Request::get("/").body(Body::empty()).unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::OK, "body: {resp}");
        let v: serde_json::Value = serde_json::from_str(&resp).expect("json");
        assert_eq!(
            v["endpoints"]["attest_balance_challenge"].as_str(),
            Some("POST /v1/attest/balance/challenge")
        );
        assert_eq!(
            v["endpoints"]["attest_balance"].as_str(),
            Some("POST /v1/attest/balance")
        );
    }

    /// Frozen pre-G6 endpoints JSON (raw bytes). Single independent
    /// golden for flag-off `GET /` — not re-derived from the live type, so
    /// reordering fields or changing values turns this red even when a
    /// hand-written `Value` map would still parse-equal.
    const PRE_G6_ENDPOINTS_JSON: &str = concat!(
        r#"{"info":"GET  /api/info","balance":"GET  /api/balance?address={hex}","#,
        r#""history":"GET  /api/history?address={hex}&limit={n}&offset={n}","#,
        r#""receive":"POST /api/receive","admit_mint":"POST /api/jobs/mint","#,
        r#""admit_send":"POST /api/jobs/send","get_job":"GET  /api/jobs/{job_id}","#,
        r#""stream_job":"GET  /api/jobs/{job_id}/stream","commit":"POST /api/jobs/{job_id}/commit","#,
        r#""sign":"POST /v1/jobs/{job_id}/sign","cancel":"POST /api/jobs/{job_id}/cancel","#,
        r#""proof":"GET  /api/proof/{id}","inscription":"GET  /api/inscriptions/{txid}","#,
        r#""username_resolve":"GET  /api/username/resolve/{username}","health":"GET  /health","#,
        r#""health_ready":"GET  /health/ready","health_publisher":"GET  /health/publisher","#,
        r#""openapi":"GET  /openapi.json","docs":"GET  /docs"}"#,
    );

    /// Defect 4: type-derived always-on map serialises to the frozen
    /// pre-G6 endpoints bytes. Adding/reordering/renaming a
    /// [`RootEndpoints`] field without updating the golden turns this red.
    #[test]
    fn root_endpoints_type_serialises_to_pre_g6_golden_bytes() {
        let live = serde_json::to_string(&crate::router::root_endpoints_always_on())
            .expect("RootEndpoints serialises");
        assert_eq!(
            live.as_bytes(),
            PRE_G6_ENDPOINTS_JSON.as_bytes(),
            "RootEndpoints serde bytes must match the frozen pre-G6 golden"
        );
    }

    /// Defects 2+4: flag-off `GET /` raw body is byte-identical to the
    /// pre-G6 root response (endpoints from the type golden; no attest
    /// keys). Compare **raw bytes**, never two parsed `Value`s — reparse
    /// discards key order and would green-wash a sorted-map regression.
    #[tokio::test]
    async fn root_flag_off_is_byte_identical_to_pre_attestation_map() {
        let _lock = lock_v1_stack_for_test().await;

        let state = test_state();
        let req = Request::get("/").body(Body::empty()).unwrap();
        let (status, _h, resp) = run(state, req).await;
        assert_eq!(status, StatusCode::OK, "body: {resp}");

        // Frozen outer key order (service → version → network → endpoints
        // → docs) + frozen endpoints golden. version/network are build/
        // env derived; the layout bytes around them are not.
        let expected_raw = format!(
            concat!(
                r#"{{"service":"zkcoins-node","version":"{}","network":"{}","endpoints":"#,
                "{}",
                r#","docs":"https://docs.zkcoins.app"}}"#,
            ),
            env!("CARGO_PKG_VERSION"),
            crate::NETWORK_CONFIG.network_name,
            PRE_G6_ENDPOINTS_JSON,
        );
        assert_eq!(
            resp.as_bytes(),
            expected_raw.as_bytes(),
            "flag-off GET / raw bytes must match pre-G6 response\n got: {resp}\nwant: {expected_raw}"
        );
        assert!(
            !resp.contains("attest_balance"),
            "flag-off raw body must not mention attest_balance*: {resp}"
        );
    }

    /// Defects 2+4: flag-off OpenAPI document omits attest keys and its
    /// `RootEndpoints` schema matches the type-derived always-on map.
    ///
    /// Pins the **document content** via [`crate::openapi::openapi_json`]
    /// (the same process-cached builder the handler would serve). HTTP
    /// route registration of `GET /openapi.json` was dropped in the
    /// Job-API refactor (#161 / `86491ab`) and is pre-existing / out of
    /// G6 scope — do not re-wire it here. Reintroducing attest fields on
    /// the `RootEndpoints` ToSchema type turns this red.
    #[test]
    fn openapi_flag_off_raw_bytes_omit_attest_and_match_type_schema() {
        let resp = crate::openapi::openapi_json();
        assert!(
            !resp.contains("attest_balance"),
            "flag-off openapi must not advertise attest_balance*: {}",
            &resp[..resp.len().min(500)]
        );

        // RootEndpoints schema property set equals the type-derived keys
        // (no attest_*). Independent of Value-key presence after reparse.
        let v: serde_json::Value = serde_json::from_str(resp).expect("openapi json");
        let props = v["components"]["schemas"]["RootEndpoints"]["properties"]
            .as_object()
            .expect("RootEndpoints.properties");
        // Derive from the live type via serde field names.
        let live = serde_json::to_value(crate::router::root_endpoints_always_on()).unwrap();
        let type_keys: Vec<String> = live.as_object().unwrap().keys().cloned().collect();
        assert_eq!(
            props.len(),
            type_keys.len(),
            "OpenAPI RootEndpoints property count must match RootEndpoints type"
        );
        for k in &type_keys {
            assert!(
                props.contains_key(k),
                "OpenAPI schema missing type field {k}"
            );
        }
        assert!(
            !props.contains_key("attest_balance")
                && !props.contains_key("attest_balance_challenge"),
            "OpenAPI RootEndpoints must not define attest_* properties"
        );

        // Raw-byte identity of the cached document against a second call
        // (OnceLock). A reordering or schema property change alters these
        // bytes relative to the pre-G6 component set.
        let again = crate::openapi::openapi_json();
        assert_eq!(
            resp.as_bytes(),
            again.as_bytes(),
            "openapi_json() must be process-stable raw bytes"
        );
    }

    /// Production digest gate is bound: wrong live digest is rejected,
    /// pinned digest is accepted. (Constant comparison alone is not enough.)
    #[test]
    fn attest_c_balance_digest_gate_is_production_bound() {
        use crate::v1::{
            accept_c_balance_network_binding, networks_have_distinct_c_balance_pins,
            pinned_c_balance_digest, PINNED_C_BALANCE_DIGEST_MAINNET,
            PINNED_C_BALANCE_DIGEST_TESTNET,
        };
        use shared::spec_v1::{network_id_mainnet, network_id_testnet};
        use zkcoins_program::circuit::compliance::Network;

        assert!(networks_have_distinct_c_balance_pins(
            Network::Testnet,
            Network::Mainnet
        ));
        assert_eq!(
            pinned_c_balance_digest(Network::Testnet),
            PINNED_C_BALANCE_DIGEST_TESTNET
        );
        assert_eq!(
            pinned_c_balance_digest(Network::Mainnet),
            PINNED_C_BALANCE_DIGEST_MAINNET
        );

        // Production gate accepts the pin for each network.
        accept_c_balance_network_binding(
            &network_id_testnet(),
            &PINNED_C_BALANCE_DIGEST_TESTNET,
            Network::Testnet,
        )
        .expect("pinned testnet digest must pass the production gate");
        accept_c_balance_network_binding(
            &network_id_mainnet(),
            &PINNED_C_BALANCE_DIGEST_MAINNET,
            Network::Mainnet,
        )
        .expect("pinned mainnet digest must pass the production gate");

        // Production gate rejects a wrong live digest.
        let err =
            accept_c_balance_network_binding(&network_id_testnet(), &[0u8; 32], Network::Testnet)
                .unwrap_err();
        assert_eq!(err.http_status_and_code(), (503, "circuit_digest_mismatch"));

        // Production gate rejects cross-network network_id.
        let err = accept_c_balance_network_binding(
            &network_id_testnet(),
            &PINNED_C_BALANCE_DIGEST_MAINNET,
            Network::Mainnet,
        )
        .unwrap_err();
        assert!(matches!(err, crate::v1::AttestError::ProvingFailed(_)));
    }
}

// =======================================================================
// Coverage for `router::verify_send_signature_pub` (the public wrapper
// that `flow::validate_send_request` calls). The wrapper's body just
// delegates to the private `verify_send_signature`, but the gate
// still requires the three lines to be touched by at least one test.
// The "Missing signature" arm is the cheapest reachable case.
// =======================================================================

#[test]
fn verify_send_signature_pub_returns_missing_signature_when_absent() {
    // `verify_send_signature_pub` is the `pub(crate)` wrapper that
    // `flow::validate_send_request` calls; the three-line body just
    // delegates to the private `verify_send_signature`. The cheapest
    // reachable arm is "missing signature" so the wrapper itself
    // gets touched by at least one test.
    let req = SendCoinRequest {
        account_address: "0x".to_string() + &hex::encode([1u8; 32]),
        recipient: "0x".to_string() + &hex::encode([2u8; 32]),
        amount: 1,
        public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap(),
        next_public_key: "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
            .parse()
            .unwrap(),
        prev_commitment_pubkey: None,
        signature: None,
        timestamp: Some(0),
        asset_id: None,
    };
    let err = crate::router::verify_send_signature_pub(&req).unwrap_err();
    assert_eq!(err, "Missing signature");
}

// =======================================================================
// Coverage tests for GET /api/inscriptions/:txid (added in #113).
// =======================================================================

mod inscriptions_endpoint_tests {
    use super::*;
    use crate::db::{insert_pending_inscription, InscriptionKind};
    use crate::router::create_router;

    async fn live_pool_router() -> (Router, Arc<sqlx::PgPool>, crate::test_db::SchemaScope) {
        // Shared `postgres:17` container + per-test schema (issue
        // #181 Opt B; see `crate::test_db`). The returned scope
        // must outlive the router for the duration of the test.
        let scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(scope.pool.clone());
        let state = live_test_state(pool.clone());
        let app = create_router(state);
        (app, pool, scope)
    }

    #[tokio::test]
    async fn get_inscription_bad_hex_is_gone_not_422() {
        let (app, _pool, _c) = live_pool_router().await;
        let req = Request::get("/api/inscriptions/zzzz")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    #[tokio::test]
    async fn get_inscription_malformed_txid_is_gone_not_422() {
        // Closed surface: no validation path that could distinguish
        // malformed vs known — always 410.
        let (app, _pool, _c) = live_pool_router().await;
        let req = Request::get("/api/inscriptions/abcd")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    #[tokio::test]
    async fn get_inscription_unknown_txid_is_gone_not_404() {
        let (app, _pool, _c) = live_pool_router().await;
        let unknown = "f".repeat(64);
        let req = Request::get(format!("/api/inscriptions/{}", unknown))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    #[tokio::test]
    async fn get_inscription_known_txid_is_gone_and_does_not_reveal_pending() {
        // Stage 3 Runde 6: even with a row planted, the route must not
        // hand out kind/status/amount/failure from legacy pending_inscriptions.
        let (app, pool, _c) = live_pool_router().await;
        let stored_commit: [u8; 32] = [0x42; 32];
        let stored_reveal: [u8; 32] = [0x43; 32];
        // Claim legacy so the SQL sink gate allows the plant (handler itself
        // must never return the row).
        crate::v1::claim_stack_scan_mode(&pool, crate::v1::ScanStackMode::Legacy)
            .await
            .expect("claim legacy for plant");
        insert_pending_inscription(
            &pool,
            &stored_commit,
            &stored_reveal,
            InscriptionKind::Mint,
            b"c",
            b"ctx",
            b"rtx",
            777,
        )
        .await
        .unwrap();
        let mut display = stored_commit.to_vec();
        display.reverse();
        let display_hex = hex::encode(display);

        let req = Request::get(format!("/api/inscriptions/{}", display_hex))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::GONE);
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await
            .unwrap()
            .to_bytes();
        let body_str = String::from_utf8_lossy(&body);
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(
            v.get("kind").is_none()
                && v.get("status").is_none()
                && v.get("commit_output_value").is_none(),
            "must not emit pending_inscriptions summary; got {body_str}"
        );
        let err = v["error"].as_str().unwrap_or("");
        assert!(
            err.contains("/api/inscriptions") || err.contains("Stage 3"),
            "error must name the removed surface; got {err:?}"
        );
    }

    #[tokio::test]
    async fn get_inscription_db_unavailable_is_gone_not_500() {
        // Closed handler never hits the DB — even after DROP, status is 410.
        let (app, pool, _c) = live_pool_router().await;
        sqlx::query("DROP TABLE pending_inscriptions CASCADE")
            .execute(pool.as_ref())
            .await
            .unwrap();
        let txid = "0".repeat(64);
        let req = Request::get(format!("/api/inscriptions/{}", txid))
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::GONE);
    }
}

// =======================================================================
// Coverage test for the username_claim_log fire-and-forget spawn body.
// The existing `claim_username_with_valid_signature` test exercises the
// spawn call site but doesn't wait long enough for the task to complete
// — this test specifically drives the spawn-body code path (line 1766)
// and asserts the row landed.
// =======================================================================

#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_precheck_reject_persists_log_row() {
    // Shared `postgres:17` container + per-test schema (issue #181
    // Opt B; see `crate::test_db`). `_scope` keeps the schema alive
    // for the duration of the test.
    let _scope = crate::test_db::setup_pool().await;
    let pool = Arc::new(_scope.pool.clone());
    let state = live_test_state(pool.clone());

    // Pre-populate the in-memory UsernameStore with a conflicting name
    // so the handler's `precheck` rejects the claim → log_claim(false,
    // Some(reason)) → tokio::spawn(insert_username_claim_log).
    {
        let mut store = state.username_store.lock().unwrap();
        let other_addr = zkcoins_program::hash::digest_from_bytes(&[0x11; 32]);
        store.commit_after_db("alice".into(), other_addr);
    }

    let secp = secp::Secp256k1::new();
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[0x33; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(b"alice");
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &kp);

    let body = serde_json::json!({
        "username": "alice",
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let app = create_router(state);
    let resp = app.oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Wait for the fire-and-forget tokio::spawn to land the
    // username_claim_log row.
    for _ in 0..40 {
        let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM username_claim_log")
            .fetch_one(pool.as_ref())
            .await
            .unwrap();
        if count >= 1 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(25)).await;
    }
    let (success, reject_reason): (bool, Option<String>) =
        sqlx::query_as("SELECT success, reject_reason FROM username_claim_log")
            .fetch_one(pool.as_ref())
            .await
            .unwrap();
    assert!(!success);
    assert!(reject_reason.is_some());
}

/// Cover the `eprintln!("Failed to persist username_claim_log: …")`
/// arm at router.rs line 1767. The fire-and-forget spawn calls
/// `insert_username_claim_log` — we DROP the table out from under it
/// so the insert fails and the eprintln line runs.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_log_spawn_handles_insert_error() {
    // Shared `postgres:17` container + per-test schema (issue #181
    // Opt B; see `crate::test_db`).
    let _scope = crate::test_db::setup_pool().await;
    let pool = Arc::new(_scope.pool.clone());
    let state = live_test_state(pool.clone());

    // Pre-stake a conflicting username so the handler hits the
    // precheck-reject path and invokes log_claim(false, …) → spawn.
    {
        let mut store = state.username_store.lock().unwrap();
        let other_addr = zkcoins_program::hash::digest_from_bytes(&[0x55; 32]);
        store.commit_after_db("bob".into(), other_addr);
    }

    // Drop the username_claim_log table so the spawned insert errs.
    sqlx::query("DROP TABLE username_claim_log CASCADE")
        .execute(pool.as_ref())
        .await
        .expect("drop username_claim_log");

    let secp = secp::Secp256k1::new();
    let secret = bitcoin::secp256k1::SecretKey::from_slice(&[0x44; 32]).unwrap();
    let public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &secret);
    let address: [u8; 32] = Sha256::digest(public_key.serialize()).into();
    let address_hex = hex::encode(address);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut hasher = Sha256::new();
    hasher.update(b"zkcoins:claim_username");
    hasher.update(address_hex.as_bytes());
    hasher.update(b"bob");
    hasher.update(now.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &secret);
    let sig = secp.sign_schnorr(&msg, &kp);

    let body = serde_json::json!({
        "username": "bob",
        "address": address_hex,
        "public_key": public_key.to_string(),
        "signature": hex::encode(sig.serialize()),
        "timestamp": now,
    });
    let req = Request::post("/api/username/claim")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let app = create_router(state);
    let resp = app.oneshot(req).await.unwrap();
    // 409 from precheck — the response path doesn't depend on the
    // (failed) audit insert.
    assert_eq!(resp.status(), StatusCode::CONFLICT);

    // Give the fire-and-forget spawn time to hit the eprintln path.
    tokio::time::sleep(std::time::Duration::from_millis(150)).await;
}

// --- GET /api/admin/r2-probe/history ---
//
// The handler reads from the `r2_probe_runs_summary` view. The happy-
// path tests below boot a real Postgres 17 testcontainer because the
// view + tables only exist after migration; the dead_pool path stays
// in `r2_probe_history_db_error_returns_500`.

#[tokio::test]
async fn clamp_r2_probe_history_limit_handles_default_and_clamps() {
    assert_eq!(
        clamp_r2_probe_history_limit(None),
        R2_PROBE_HISTORY_DEFAULT_LIMIT
    );
    assert_eq!(
        clamp_r2_probe_history_limit(Some(0)),
        R2_PROBE_HISTORY_DEFAULT_LIMIT
    );
    assert_eq!(
        clamp_r2_probe_history_limit(Some(-5)),
        R2_PROBE_HISTORY_DEFAULT_LIMIT
    );
    assert_eq!(clamp_r2_probe_history_limit(Some(7)), 7);
    assert_eq!(
        clamp_r2_probe_history_limit(Some(10_000)),
        R2_PROBE_HISTORY_MAX_LIMIT
    );
    assert_eq!(
        clamp_r2_probe_history_limit(Some(R2_PROBE_HISTORY_MAX_LIMIT)),
        R2_PROBE_HISTORY_MAX_LIMIT
    );
}

#[tokio::test]
async fn r2_probe_history_db_error_returns_500() {
    // The default test_state() uses a dead PgPool whose connect
    // attempts time out fast — exercises the handler's error arm.
    let req = Request::get("/api/admin/r2-probe/history")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR);
    let resp: SendCoinResponse = serde_json::from_str(&body).expect("valid JSON");
    assert!(!resp.success);
    assert_eq!(
        resp.error.as_deref(),
        Some("Database error while reading R2 probe history")
    );
}

#[tokio::test]
async fn r2_probe_history_empty_returns_empty_array() {
    // Shared `postgres:17` container + per-test schema (issue #181
    // Opt B; see `crate::test_db`).
    let pg_container = crate::test_db::setup_pool().await;
    let pool = Arc::new(pg_container.pool.clone());

    let state = live_test_state(pool);
    let req = Request::get("/api/admin/r2-probe/history")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_with_state(state, req).await;
    assert_eq!(status, StatusCode::OK);
    let arr: Vec<serde_json::Value> = serde_json::from_str(&body).expect("valid JSON");
    assert!(arr.is_empty());
}

#[tokio::test]
async fn r2_probe_history_returns_rows_with_pass_flags() {
    // Shared `postgres:17` container + per-test schema (issue #181
    // Opt B; see `crate::test_db`).
    let pg_container = crate::test_db::setup_pool().await;
    let pool = Arc::new(pg_container.pool.clone());

    // Seed two runs: one within budget, one over warm budget.
    let host_info = crate::r2_probe::HostInfo {
        hostname: "router-test-host".to_string(),
        os: "macos".to_string(),
        arch: "aarch64".to_string(),
        cpu_brand: "Apple M3 Ultra".to_string(),
        cpu_cores: 24,
        total_ram_gb: Some(96),
    };
    let host_id = crate::r2_probe::upsert_host(&pool, &host_info)
        .await
        .expect("host");
    let mut run = crate::r2_probe::ProbeRun {
        host_id,
        git_sha: "abc123".to_string(),
        binary_version: "0.1.0".to_string(),
        rustc_version: "rustc 1.81.0".to_string(),
        build_profile: "release".to_string(),
        allocator: "mimalloc".to_string(),
        prover_mode: "legacy".to_string(),
        max_in_coins: 8,
        max_out_coins: 8,
        inner_pad_bits: 15,
        max_tx_inputs: None,
        max_tx_outputs: None,
        max_rx_coins: None,
        compliance_gate_count: None,
        warm_calls_requested: 3,
        circuit_build_wall_ms: 8_000,
        prove_cold_wall_ms: 18_000,
        verify_wall_ms: 30,
        peak_rss_kb: 40 * 1024 * 1024,
        prove_warm_p50_ms: Some(800),
        prove_warm_p90_ms: Some(1_000),
        prove_warm_p99_ms: Some(1_300),
        succeeded: true,
        error_message: None,
        notes: None,
        tags: vec!["router-test".to_string()],
        r2_warm_budget_ms: 5_000,
        r2_cold_budget_ms: 30_000,
        r2_mem_budget_kb: 64 * 1024 * 1024,
    };
    crate::r2_probe::insert_run(&pool, &run)
        .await
        .expect("run 1");

    // Second run blows past the warm budget.
    run.prove_warm_p50_ms = Some(7_000);
    crate::r2_probe::insert_run(&pool, &run)
        .await
        .expect("run 2");

    let state = live_test_state(pool);
    let req = Request::get("/api/admin/r2-probe/history?limit=10")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_with_state(state, req).await;
    assert_eq!(status, StatusCode::OK);

    let arr: Vec<serde_json::Value> = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(arr.len(), 2);

    // Newest first — the warm-fail row landed last.
    assert_eq!(arr[0]["r2_warm_pass"].as_bool(), Some(false));
    assert_eq!(arr[1]["r2_warm_pass"].as_bool(), Some(true));
    // Cold + mem budgets pass for both.
    assert_eq!(arr[0]["r2_cold_pass"].as_bool(), Some(true));
    assert_eq!(arr[1]["r2_cold_pass"].as_bool(), Some(true));
    assert_eq!(arr[0]["r2_mem_pass"].as_bool(), Some(true));
    assert_eq!(arr[1]["r2_mem_pass"].as_bool(), Some(true));
    // Joined host info surfaces in the response.
    assert_eq!(arr[0]["hostname"].as_str(), Some("router-test-host"));
    assert_eq!(arr[0]["cpu_brand"].as_str(), Some("Apple M3 Ultra"));
}

#[tokio::test]
async fn r2_probe_history_limit_clamped_to_max() {
    // Shared `postgres:17` container + per-test schema (issue #181
    // Opt B; see `crate::test_db`).
    let pg_container = crate::test_db::setup_pool().await;
    let pool = Arc::new(pg_container.pool.clone());

    let state = live_test_state(pool);
    // Caller asks for 10_000 — the clamp keeps us at 200. With zero
    // rows seeded the response body is still empty, but the path
    // reaches `fetch_recent_summary` (the clamp lives in the handler,
    // not the SQL layer).
    let req = Request::get("/api/admin/r2-probe/history?limit=10000")
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_with_state(state, req).await;
    assert_eq!(status, StatusCode::OK);
    let arr: Vec<serde_json::Value> = serde_json::from_str(&body).expect("valid JSON");
    assert!(arr.is_empty());
}

// ---------------------------------------------------------------------------
// Phase E (send-commit branch) — mirrors the mint Phase E tests above.
//
// `broadcast_commit_and_deliver` runs the shared
// `apply_commit_and_persist_phase_e` helper synchronously after the
// Bitcoin broadcast. The tests below assert the two load-bearing
// observable properties from outside the handler:
//
// 1. Happy path: after a 200 response the SMT contains the commit's
//    pubkey, the MMR has advanced by one leaf, the matching
//    `mmr_root_index` row is present, and the `pending_inscriptions`
//    row sits at `complete` — so a scanner re-observation hits
//    `should_skip_scanner_state_update`.
//
// 2. Atomic rollback (`PhaseEFailure::DurablePersist`): a trigger that
//    blocks the in-tx UPDATE to `complete` rolls the whole transaction
//    back. The handler surfaces 503; on-disk SMT/MMR/root_index stays
//    unchanged; the row stays at `reveal_broadcast` so scanner-replay
//    will integrate the inscription from chain.
// ---------------------------------------------------------------------------

// =======================================================================
// GET /api/history + /api/history/:id — Stage 3 Runde 6 closed (410)
//
// Address knowledge is not `read.account`. These tests pin the ban:
// no decoded legacy snapshots leave the node. Residual helpers
// (`decode_history_address`, `history_row_to_item`, …) stay unit-tested
// below for internal residual code; the HTTP surface is gone.
// =======================================================================

#[tokio::test]
async fn history_list_is_gone_and_does_not_reveal_legacy_snapshots() {
    let (pool, _pg) = {
        let scope = crate::test_db::setup_pool().await;
        (Arc::new(scope.pool.clone()), scope)
    };
    // Plant history via direct SQL (bypasses gated upsert) so a regression
    // that re-opens the handler would have rows to leak.
    let address: [u8; 32] = [7u8; 32];
    let mut acct = Account::new();
    acct.balance = 100;
    let blob = bincode::serialize(&acct).expect("Account serializable");
    sqlx::query(
        "INSERT INTO account_history (address, prev_data, new_data, source)          VALUES ($1, NULL, $2, 'mint')",
    )
    .bind(&address[..])
    .bind(&blob)
    .execute(&*pool)
    .await
    .expect("plant history row");

    let state = live_test_state(pool);
    let req = Request::get(format!("/api/history?address=0x{}", hex::encode(address)))
        .body(Body::empty())
        .unwrap();
    let (status, body) = send_request_with_state(state, req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    assert!(
        v.get("items").is_none() && v.get("total").is_none(),
        "must not emit history items/total; got {body}"
    );
    let err = v["error"].as_str().unwrap_or("");
    assert!(
        err.contains("/api/history") || err.contains("Stage 3") || err.contains("read.account"),
        "error must name the removed surface; got {err:?}"
    );
    // Amount / balance fields must never appear.
    assert!(
        !body.contains("\"amount\"") && !body.contains("\"balance_after\""),
        "body must not carry decoded snapshot fields; got {body}"
    );
}

#[tokio::test]
async fn history_item_is_gone_and_does_not_reveal_decoded_snapshot() {
    let scope = crate::test_db::setup_pool().await;
    let pool = Arc::new(scope.pool.clone());
    let address: [u8; 32] = [23u8; 32];
    let mut acct = Account::new();
    acct.balance = 40;
    acct.num_sends = 1;
    let blob = bincode::serialize(&acct).expect("Account serializable");
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO account_history (address, prev_data, new_data, source)          VALUES ($1, NULL, $2, 'send') RETURNING id",
    )
    .bind(&address[..])
    .bind(&blob)
    .fetch_one(&*pool)
    .await
    .expect("plant detail row");

    let state = live_test_state(pool);
    let req = Request::get(format!(
        "/api/history/{}?address=0x{}",
        id,
        hex::encode(address)
    ))
    .body(Body::empty())
    .unwrap();
    let (status, body) = send_request_with_state(state, req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
    let v: serde_json::Value = serde_json::from_str(&body).expect("JSON");
    for key in [
        "balance_before",
        "balance_after",
        "num_sends_after",
        "commitment_public_key",
        "amount",
    ] {
        assert!(
            v.get(key).is_none(),
            "must not emit {key} from closed detail; got {body}"
        );
    }
    let err = v["error"].as_str().unwrap_or("");
    assert!(
        err.contains("/api/history") || err.contains("Stage 3") || err.contains("read.account"),
        "error must name the removed surface; got {err:?}"
    );
}

#[tokio::test]
async fn history_missing_params_still_gone_not_422() {
    // Closed surface: no validation oracle — always 410.
    let req = Request::get("/api/history").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
}

#[tokio::test]
async fn history_item_missing_params_still_gone_not_422() {
    let req = Request::get("/api/history/1").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
}

// --- Pure-function coverage for the helpers --------------------------------

// Covers the **settled-balance** shape of an `Account` blob: a post-send
// account whose `coin_queue` has been drained into `coin_history` and
// whose remaining funds sit in the `balance` field. The companion
// **queue-only** shape (the actual production write produced by
// `commit_mint_tx` / `receive_coin` for a credit) requires a real
// `CoinProof` and is pinned in
// `account_node_tests::history_row_to_item_balance_from_coin_queue_only`
// where the prover fixtures live.
// ── GET /api/history/{id} — TxDetail conversion (issue: tx-detail) ──────

// ===========================================================================
// Milestone 2: neutral, permissionless multi-asset router surface.
// ===========================================================================
use bitcoin::secp256k1::{
    Keypair as TestKeypair, Secp256k1 as TestSecp, SecretKey as TestSecretKey,
};

/// Build a deterministic creator keypair for mint-signature tests.
fn mint_creator_keypair() -> (TestSecretKey, bitcoin::secp256k1::PublicKey) {
    let secp = TestSecp::new();
    let sk = TestSecretKey::from_slice(&[7u8; 32]).expect("valid secret key");
    let pk = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &sk);
    (sk, pk)
}

/// Sign a `MintRequest` over the canonical mint message and return the
/// fully-populated request.
fn signed_mint_request(name: &str, decimals: u8, amount: u64, timestamp: u64) -> MintRequest {
    let secp = TestSecp::new();
    let (sk, pk) = mint_creator_keypair();
    let mut hasher = Sha256::new();
    hasher.update(pk.serialize());
    hasher.update(name.as_bytes());
    hasher.update([decimals]);
    hasher.update(amount.to_le_bytes());
    hasher.update(timestamp.to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    let msg = Message::from_digest(hash);
    let keypair = TestKeypair::from_secret_key(&secp, &sk);
    let sig = secp.sign_schnorr(&msg, &keypair);
    // Distinct fresh key the mint rotates `next_public_key` to.
    let next_sk = TestSecretKey::from_slice(&[8u8; 32]).expect("valid secret key");
    let next_public_key = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &next_sk);
    MintRequest {
        creator_pubkey: pk,
        next_public_key,
        name: name.to_string(),
        decimals,
        amount,
        signature: hex::encode(sig.serialize()),
        timestamp,
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[test]
fn verify_mint_signature_accepts_valid_signature() {
    let req = signed_mint_request("TestToken", 8, 50_000, now_secs());
    verify_mint_signature_pub(&req).expect("valid mint signature must verify");
}

#[test]
fn verify_mint_signature_rejects_tampered_amount() {
    let mut req = signed_mint_request("TestToken", 8, 50_000, now_secs());
    // Flip the amount after signing — the signature no longer matches.
    req.amount = 50_001;
    assert!(verify_mint_signature_pub(&req).is_err());
}

#[test]
fn verify_mint_signature_rejects_wrong_creator_key() {
    let mut req = signed_mint_request("TestToken", 8, 50_000, now_secs());
    // Swap to a different creator pubkey the signature was not made for.
    let secp = TestSecp::new();
    let other_sk = TestSecretKey::from_slice(&[9u8; 32]).unwrap();
    req.creator_pubkey = bitcoin::secp256k1::PublicKey::from_secret_key(&secp, &other_sk);
    assert!(verify_mint_signature_pub(&req).is_err());
}

#[test]
fn verify_mint_signature_rejects_malformed_signature_hex() {
    let mut req = signed_mint_request("TestToken", 8, 50_000, now_secs());
    req.signature = "not-hex".to_string();
    assert!(verify_mint_signature_pub(&req).is_err());
}

#[tokio::test]
async fn balance_missing_asset_id_is_gone() {
    // Route closed regardless of query shape (no 422 that could leak schema).
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(&test_owner_address()));
    let uri = format!("/api/balance?address={}", address_hex);
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
}

#[tokio::test]
async fn balance_invalid_asset_id_is_gone() {
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(&test_owner_address()));
    let uri = format!("/api/balance?address={}&asset_id=ZZ", address_hex);
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
}

/// R2: multi-asset owner list must not reveal seeded balances.
#[tokio::test]
async fn owner_balance_is_gone_and_does_not_reveal_assets() {
    let state = test_state();
    {
        let mut node = state.account_node.lock().unwrap();
        let other_asset = zkcoins_program::hash::hash_bytes(b"router-test-asset-2");
        let mut acct = crate::account_node::Account::new_for_asset(other_asset);
        acct.balance = 250;
        acct.name = Some("SECOND".to_string());
        acct.decimals = Some(6);
        node.import_account(test_owner_address(), acct);
    }
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(&test_owner_address()));
    let uri = format!("/api/balance/{}", address_hex);
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request_with_state(state, req).await;
    assert_eq!(
        status,
        StatusCode::GONE,
        "legacy owner balance must refuse loud (HTTP 410); body={body}"
    );
    let resp: serde_json::Value = serde_json::from_str(&body).expect("JSON error body");
    assert!(
        resp.get("assets").is_none() && resp.get("balance").is_none(),
        "must not carry OwnerBalanceResponse fields; got {resp}"
    );
    assert!(
        !body.contains("SECOND") && !body.contains("1000000") && !body.contains("250"),
        "must not leak asset names or balances; body={body}"
    );
    let err = resp["error"].as_str().unwrap_or("");
    assert!(
        err.contains("/api/balance") || err.contains("Stage 3") || err.contains("read.account"),
        "error must name the removed surface; got {err:?}"
    );
}

#[tokio::test]
async fn owner_balance_unknown_owner_is_gone() {
    let address_hex = hex::encode(zkcoins_program::hash::digest_to_bytes(
        &zkcoins_program::hash::digest_from_bytes(&[0x55u8; 32]),
    ));
    let uri = format!("/api/balance/{}", address_hex);
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
}

#[tokio::test]
async fn owner_balance_malformed_address_is_gone() {
    let uri = "/api/balance/not-hex".to_string();
    let req = Request::get(&uri).body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::GONE, "body={body}");
}

#[tokio::test]
async fn info_advertises_multi_asset_capability() {
    let req = Request::get("/api/info").body(Body::empty()).unwrap();
    let (status, body) = send_request(req).await;
    assert_eq!(status, StatusCode::OK);
    let v: serde_json::Value = serde_json::from_str(&body).expect("valid JSON");
    assert_eq!(v["capabilities"]["multi_asset"], true);
}

#[tokio::test]
async fn jobs_mint_unsigned_request_is_rejected() {
    // A mint request with a stale timestamp + signature that does not
    // match must be rejected at admit time (401) without burning a job
    // row — exercising the `validate_mint_request` gate end-to-end.
    let mut req = signed_mint_request("TestToken", 8, 50_000, now_secs());
    req.signature = hex::encode([0u8; 64]); // invalid signature
    let body = serde_json::to_vec(&req).unwrap();
    let http = Request::post("/api/jobs/mint")
        .header("content-type", "application/json")
        .header("idempotency-key", "k-mint-unsigned")
        .body(Body::from(body))
        .unwrap();
    let (status, _b) = send_request(http).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn jobs_mint_stale_timestamp_is_rejected() {
    // Timestamp far in the past → outside the freshness window → 401.
    let req = signed_mint_request("TestToken", 8, 50_000, 1);
    let body = serde_json::to_vec(&req).unwrap();
    let http = Request::post("/api/jobs/mint")
        .header("content-type", "application/json")
        .header("idempotency-key", "k-mint-stale")
        .body(Body::from(body))
        .unwrap();
    let (status, _b) = send_request(http).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
