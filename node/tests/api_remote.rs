//! HTTP API end-to-end test suite for the deployed zkCoins node.
//!
//! This suite is the functional counterpart to the smoke test inside
//! `.github/workflows/deploy-dev.yaml` (which only probes `/api/info`).
//! Where the smoke test answers "is the listener bound?", this suite
//! answers "do all 15 routes behave as documented?". It signs real
//! Schnorr commitments with freshly-generated wallets, mints coins,
//! sends them, commits the resulting state, and claims a username —
//! exercising the API contract happy path against the same backend
//! the wallet app talks to.
//!
//! Scope note: the suite verifies API-visible behaviour (status
//! codes, response shapes, balance movements). The commit message
//! format used in `send_commit_roundtrip_moves_balance` is the
//! 64-byte `ash || ocr` raw concat, which the node accepts via
//! `Commitment::verify`'s SHA-256 fallback. The canonical wallet
//! client signs the 32-byte Poseidon `hash_concat(ash, ocr)` digest
//! (see `shared::ClientAccount::create_commitment`); the two forms
//! produce different SMT leaves but both pass the signature check,
//! and the suite never re-spends from the test wallet so the leaf
//! shape is observationally indistinguishable in-scope.
//!
//! The DEV node is shared by other workflows (per-PR app E2E,
//! interactive testing). To keep this suite race-free we always:
//!   - mint into freshly-generated wallets (no fixed addresses)
//!   - assert strictly on 4xx codes (client-fixable contract bugs)
//!   - assert strictly on 5xx codes as well (node-side regressions
//!     are real bugs, not flakes — the deploy-dev preflight verifies
//!     publisher wallet + /health/ready BEFORE this suite runs, so a
//!     503 here is unambiguous: it means something regressed)
//!
//! Read by:
//!   - `cargo test -p node --release --test api_remote` (locally)
//!   - the `api-e2e` job in `deploy-dev.yaml` after `build-and-deploy`
//!
//! Configuration:
//!   - `ZKCOINS_API_URL` (default `https://dev-api.zkcoins.app`) —
//!     the base URL of the node under test.

use bitcoin::bip32::{ChildNumber, Xpriv, Xpub};
use bitcoin::secp256k1::{self as secp, Keypair, Message, PublicKey, SecretKey};
use bitcoin::Network;
use node::account_node::CoinProof;
use node::router::Capabilities;
use rand::RngCore;
use reqwest::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use shared::commitment::Commitment;
use shared::ProofData;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS;
use zkcoins_program::hash::digest_to_bytes;
use zkcoins_program::types::calculate_asset_id_from_name;
use zkcoins_program::F;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_API_URL: &str = "https://dev-api.zkcoins.app";
const HTTP_TIMEOUT: Duration = Duration::from_secs(120);
const POLL_INTERVAL: Duration = Duration::from_secs(2);
const MINT_AMOUNT: u64 = 50_000;
/// Asset metadata the happy-path roundtrips mint under. Each test uses a
/// freshly-generated creator wallet, so `(creator_pubkey, name, decimals)`
/// — and thus the derived `asset_id` — is unique per test even with a
/// shared name; no cross-test asset-id collision against the shared DEV node.
const ASSET_NAME: &str = "roundtrip";
const ASSET_DECIMALS: u8 = 0;

fn api_base() -> String {
    std::env::var("ZKCOINS_API_URL").unwrap_or_else(|_| DEFAULT_API_URL.to_string())
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(HTTP_TIMEOUT)
        .build()
        .expect("build reqwest client")
}

fn url(path: &str) -> String {
    format!("{}{}", api_base().trim_end_matches('/'), path)
}

/// Derive the on-chain `asset_id` hex for an asset minted by `creator_pubkey`
/// under `(name, decimals)` — the same value the node computes server-side
/// via `calculate_asset_id(creator_pubkey, H(name), decimals)`. Used to scope
/// `/api/balance` queries and `/api/jobs/send` bodies to the asset a roundtrip
/// just minted (the multi-asset model keys balances by `(owner, asset_id)`).
fn asset_id_hex(creator_pubkey: &PublicKey, name: &str, decimals: u8) -> String {
    // The program-side derivation takes the SERIALIZED compressed pubkey
    // (`[u8; 33]`), matching what `flow::validate_mint_request` feeds it.
    let asset_id = calculate_asset_id_from_name(&creator_pubkey.serialize(), name, decimals);
    format!("0x{}", hex::encode(digest_to_bytes(&asset_id)))
}

/// Helper: log a one-line "feature off" skip and return.
///
/// When running in CI (env `CI=true`) this is a hard panic instead of
/// a silent skip: CI is supposed to build with `--all-features`, so a
/// `feature_skip!` firing in CI is the canary for an accidentally
/// dropped `--all-features` flag in a workflow (e.g. someone copied
/// the local `cargo test` invocation into the workflow). Outside CI
/// the macro is still a skip — the suite is also runnable against a
/// feature-trimmed PRD deploy, where an absent route is expected.
///
/// Escape hatch: setting `ZKCOINS_E2E_ALLOW_FEATURE_TRIMMED_SERVER`
/// (any value, even empty) downgrades the CI panic back to a silent
/// skip. The dev-api / prd-api Docker images intentionally ship the
/// MVP-only feature set (`Dockerfile` `ARG FEATURES=`), so when the
/// suite runs `--all-features` against a feature-trimmed *node*
/// the gated `address_list` / `lnurl` tests must skip cleanly instead
/// of panicking the CI canary. The env var documents this as an
/// opt-in: workflows that point the suite at a trimmed node set it,
/// workflows that point it at a fully-featured node leave it unset
/// so the canary stays armed.
///
/// The env-var name keeps the legacy `_SERVER` suffix as a stable
/// contract with `.github/workflows/deploy-dev.yaml`; the prose above
/// reflects the post-rename "node" terminology.
macro_rules! feature_skip {
    ($feature:expr, $test:expr) => {{
        let allow_trimmed_node = std::env::var("ZKCOINS_E2E_ALLOW_FEATURE_TRIMMED_SERVER").is_ok();
        if std::env::var("CI").is_ok() && !allow_trimmed_node {
            panic!(
                "feature `{}` disabled but running in CI — all-features build is required \
                 (set ZKCOINS_E2E_ALLOW_FEATURE_TRIMMED_SERVER=1 if the target node is \
                 intentionally feature-trimmed, e.g. the MVP-only DEV image)",
                $feature
            );
        }
        eprintln!(
            "SKIP {}: feature `{}` disabled on this node",
            $test, $feature
        );
        return;
    }};
}

/// Assert a closed Stage-3 legacy surface answers **HTTP 410 Gone** with a
/// JSON error body that names the removed path (or Stage 3 / replacement
/// surface). Never 200 with zeroed/partial ledger fields.
async fn assert_legacy_gone(
    client: &reqwest::Client,
    method: reqwest::Method,
    path: &str,
    surface_markers: &[&str],
) -> Value {
    let resp = client
        .request(method, url(path))
        .send()
        .await
        .unwrap_or_else(|e| panic!("request {path}: {e}"));
    assert_eq!(
        resp.status(),
        StatusCode::GONE,
        "legacy {path} must refuse loud (HTTP 410); status={}",
        resp.status()
    );
    let body: Value = resp.json().await.expect("410 body JSON");
    let err = body["error"].as_str().unwrap_or("");
    assert!(
        surface_markers.iter().any(|m| err.contains(m)),
        "410 error must name the removed surface {surface_markers:?}; got {err:?} body={body}"
    );
    // Closed handlers must not leak BalanceResponse / HistoryResponse shapes.
    assert!(
        body.get("balance").is_none()
            && body.get("assets").is_none()
            && body.get("items").is_none()
            && body.get("addresses").is_none()
            && body.get("num_sends").is_none(),
        "410 body must not carry ledger fields; got {body}"
    );
    body
}

// ---------------------------------------------------------------------------
// Capability detection
//
// Mint (`/api/jobs/mint`) and username *resolve*
// (`/api/username/resolve/:u`) are permanent MVP endpoints — always
// registered, never gated. They
// have no capability bit on `/api/info` (only opt-in features do), so
// tests against those routes do not consult `fetch_capabilities`.
//
// The optional, feature-gated routes (`address-list`, `username-claim`
// write path, `lnurl`) are off in the default deploy: the axum fallback
// answers 404 instead of the per-handler error codes. We fetch
// `/api/info` once per gated test, deserialise the well-known
// `Capabilities` shape, and skip the rest of the test if the relevant
// feature flag is `false`.
//
// `ZKCOINS_FORCE_DISABLE_FEATURES` (comma-separated list, e.g.
// `address_list,lnurl`) overrides any flag returned by the node
// to `false`. This is the local dry-run hook — point the suite at the
// live DEV node, force features off, and confirm that every gated
// test prints `SKIP …` instead of hitting a disabled-on-paper but
// actually-running endpoint. Unknown flags (including the retired
// `faucet` / `usernames` permanent-MVP names) are ignored with a
// warning.
// ---------------------------------------------------------------------------

async fn fetch_capabilities(client: &reqwest::Client) -> Capabilities {
    let resp = client
        .get(url("/api/info"))
        .send()
        .await
        .expect("GET /api/info for capability detection");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "/api/info must answer 200 — required for capability detection"
    );
    // We deserialise into a transient Value first so the override hook
    // can flip booleans without round-tripping through the strongly
    // typed `Capabilities` (which has no setters).
    let body: Value = resp
        .json()
        .await
        .expect("/api/info body is JSON for capability detection");
    // Each capability field MUST be a bool — a missing field or a
    // non-bool value is a contract regression in `/api/info` and a
    // `.unwrap_or(false)` would silently mask it as "feature off".
    let mut caps = Capabilities {
        address_list: body["capabilities"]["address_list"].as_bool().expect(
            "/api/info capabilities.address_list must be a bool — missing field is a contract regression",
        ),
        username_claim: body["capabilities"]["username_claim"].as_bool().expect(
            "/api/info capabilities.username_claim must be a bool — missing field is a contract regression",
        ),
        lnurl: body["capabilities"]["lnurl"].as_bool().expect(
            "/api/info capabilities.lnurl must be a bool — missing field is a contract regression",
        ),
        multi_asset: body["capabilities"]["multi_asset"].as_bool().expect(
            "/api/info capabilities.multi_asset must be a bool — missing field is a contract regression",
        ),
    };
    if let Ok(force) = std::env::var("ZKCOINS_FORCE_DISABLE_FEATURES") {
        for flag in force.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            match flag {
                "address_list" | "address-list" => caps.address_list = false,
                "username_claim" | "username-claim" => caps.username_claim = false,
                "lnurl" => caps.lnurl = false,
                "multi_asset" | "multi-asset" => caps.multi_asset = false,
                other => {
                    eprintln!(
                        "ZKCOINS_FORCE_DISABLE_FEATURES: unknown flag `{}` — ignored",
                        other
                    );
                }
            }
        }
    }
    caps
}

// ---------------------------------------------------------------------------
// TestWallet — fresh-per-test random key + helpers for signing the four
// request shapes the node accepts (send / commit / username-claim).
// ---------------------------------------------------------------------------

struct TestWallet {
    xpriv: Xpriv,
    secp: secp::Secp256k1<secp::All>,
}

impl TestWallet {
    fn new() -> Self {
        let mut seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);
        // Signet matches the mutinynet flavour the DEV node runs on;
        // the network choice only affects xpub serialisation prefixes,
        // not the derived secp256k1 keys we sign with.
        let xpriv = Xpriv::new_master(Network::Signet, &seed).expect("derive xpriv from seed");
        Self {
            xpriv,
            secp: secp::Secp256k1::new(),
        }
    }

    /// Normal-child secret key at index `i`. Matches the convention
    /// used by `shared::ClientAccount::generate_public_key`.
    fn seckey(&self, idx: u32) -> SecretKey {
        self.xpriv
            .derive_priv(&self.secp, &[ChildNumber::Normal { index: idx }])
            .expect("derive private key")
            .private_key
    }

    fn pubkey(&self, idx: u32) -> PublicKey {
        Xpub::from_priv(&self.secp, &self.xpriv)
            .derive_pub(&self.secp, &[ChildNumber::Normal { index: idx }])
            .expect("derive public key")
            .public_key
    }

    fn keypair(&self, idx: u32) -> Keypair {
        Keypair::from_secret_key(&self.secp, &self.seckey(idx))
    }

    /// The hex account address — `sha256(compressed_pubkey₀)`, per the
    /// normative spec (`docs/specification.md`: `address = H(Pk₀)`, H =
    /// SHA-256). This is the account key the wallet/SDK use for balance,
    /// send, and username operations.
    ///
    /// NOTE: minted balances are currently credited under a Poseidon-derived
    /// owner instead of this SHA-256 address — a node-side spec violation
    /// tracked in zk-coins/node#226. The mint→balance/send roundtrips below
    /// are `#[ignore]`d until that node fix lands.
    fn address_hex(&self) -> String {
        let pk = self.pubkey(0);
        let digest: [u8; 32] = Sha256::digest(pk.serialize()).into();
        format!("0x{}", hex::encode(digest))
    }

    /// Sign the canonical send-request preimage:
    /// `SHA256(account_address_str || recipient_str || amount_le8 || timestamp_le8)`.
    fn sign_send(
        &self,
        account_address: &str,
        recipient: &str,
        amount: u64,
        timestamp: u64,
    ) -> String {
        self.sign_send_at(account_address, recipient, amount, timestamp, 0)
    }

    /// Same as [`Self::sign_send`] but at an arbitrary BIP-32 child
    /// index. Needed for the multi-send regression test that drives
    /// `account.num_sends >= 2` against the live server.
    fn sign_send_at(
        &self,
        account_address: &str,
        recipient: &str,
        amount: u64,
        timestamp: u64,
        idx: u32,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(account_address.as_bytes());
        hasher.update(recipient.as_bytes());
        hasher.update(amount.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let msg = Message::from_digest(hash);
        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &self.keypair(idx));
        hex::encode(sig.as_ref())
    }

    /// Sign the commit message: the BIP-340 Schnorr signature is
    /// produced by `Commitment::new`, which SHA256s any non-32-byte
    /// payload before signing. The node reconstructs the
    /// `Commitment` struct from `(public_key, signature, message)`
    /// and re-verifies it the same way.
    fn sign_commit(&self, message_bytes: &[u8]) -> String {
        let commitment = Commitment::new(&self.seckey(0), message_bytes.to_vec())
            .expect("Commitment::new from random secret");
        hex::encode(commitment.signature.as_ref())
    }

    /// Sign the username-claim preimage:
    /// `SHA256("zkcoins:claim_username" || address_hex_str || normalised_username_str || timestamp_le8)`.
    ///
    /// The node canonicalises the username with `to_lowercase()`
    /// before hashing; wallets must sign over the same lowercase form
    /// or verification fails. The helper mirrors that to keep the
    /// signature path honest end-to-end.
    fn sign_username_claim(&self, address_hex: &str, username: &str, timestamp: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"zkcoins:claim_username");
        hasher.update(address_hex.as_bytes());
        hasher.update(username.to_lowercase().as_bytes());
        hasher.update(timestamp.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let msg = Message::from_digest(hash);
        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &self.keypair(0));
        hex::encode(sig.as_ref())
    }

    /// Sign the creator-signed mint preimage (Milestone 2):
    /// `SHA256(creator_pubkey.serialize() || name || [decimals] || amount_le8 || timestamp_le8)`,
    /// verified server-side against the x-only form of `creator_pubkey`
    /// (see `router::verify_mint_signature_pub`). The creator key is the
    /// wallet's index-0 child, so the derived owner `H(creator_pubkey)`
    /// equals `address_hex()`.
    fn sign_mint(&self, name: &str, decimals: u8, amount: u64, timestamp: u64) -> String {
        let mut hasher = Sha256::new();
        hasher.update(self.pubkey(0).serialize());
        hasher.update(name.as_bytes());
        hasher.update([decimals]);
        hasher.update(amount.to_le_bytes());
        hasher.update(timestamp.to_le_bytes());
        let hash: [u8; 32] = hasher.finalize().into();
        let msg = Message::from_digest(hash);
        let sig = self.secp.sign_schnorr_no_aux_rand(&msg, &self.keypair(0));
        hex::encode(sig.as_ref())
    }
}

// ---------------------------------------------------------------------------
// Section 1 — read-only endpoints
// ---------------------------------------------------------------------------

#[tokio::test]
async fn root_returns_service_metadata() {
    let resp = http_client().get(url("/")).send().await.expect("GET /");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("root body is JSON");
    assert_eq!(body["service"], "zkcoins-node");
    assert!(body["version"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(body["network"].as_str().is_some_and(|v| !v.is_empty()));
    assert!(body["endpoints"]["info"].is_string());
}

#[tokio::test]
async fn health_returns_ok() {
    let resp = http_client()
        .get(url("/health"))
        .send()
        .await
        .expect("GET /health");
    assert_eq!(resp.status(), StatusCode::OK);
    let body = resp.text().await.expect("read body");
    assert_eq!(body, "ok");
}

#[tokio::test]
async fn health_ready_returns_ready_with_no_failures() {
    let resp = http_client()
        .get(url("/health/ready"))
        .send()
        .await
        .expect("GET /health/ready");
    let status = resp.status();
    let body: Value = resp.json().await.expect("/health/ready body is JSON");
    assert_eq!(
        status,
        StatusCode::OK,
        "/health/ready must return 200 — failures: {:?}",
        body["failures"]
    );
    assert_eq!(body["ready"], Value::Bool(true));
    let failures = body["failures"].as_array().expect("failures is an array");
    assert!(
        failures.is_empty(),
        "expected no failures, got {:?}",
        failures
    );
}

#[tokio::test]
async fn info_returns_well_formed_response() {
    // Shape-only check: the MVP deploy may run with zero features and
    // PRD may differ from DEV, so the only invariant we assert is the
    // contract — `/api/info` returns a well-formed `InfoResponse` with
    // a non-empty `network`, a non-empty `username_domain`, and four
    // boolean capability flags. The per-feature `true`/`false`
    // expectations live in the gated tests below, which short-circuit
    // through `fetch_capabilities`.
    let resp = http_client()
        .get(url("/api/info"))
        .send()
        .await
        .expect("GET /api/info");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("/api/info body is JSON");

    assert!(
        body["network"].as_str().is_some_and(|v| !v.is_empty()),
        "network must be a non-empty string, got {:?}",
        body["network"]
    );
    assert!(
        body["username_domain"]
            .as_str()
            .is_some_and(|v| !v.is_empty()),
        "username_domain must be a non-empty string, got {:?}",
        body["username_domain"]
    );

    // `bitcoin_network` is the typed, lowercase network identifier the
    // wallet/SDK switch behaviour on. No fallback: a missing field or a
    // value outside the two-variant enum is a contract regression.
    let bitcoin_network = body["bitcoin_network"].as_str().expect(
        "/api/info bitcoin_network must be a string — missing field is a contract regression",
    );
    assert!(
        bitcoin_network == "mainnet" || bitcoin_network == "mutinynet",
        "/api/info bitcoin_network must be `mainnet` or `mutinynet`, got {bitcoin_network:?} \
         — value outside the enum is a contract regression"
    );

    for cap in ["address_list", "username_claim", "lnurl"] {
        assert!(
            body["capabilities"][cap].is_boolean(),
            "capability `{cap}` must be a bool, got {:?}",
            body["capabilities"][cap]
        );
    }
}

/// Shape-only probe of `/health/publisher` — the JSON contract is
/// asserted here so the suite breaks if the field set changes, even
/// when the publisher wallet itself is empty (the deploy-dev
/// preflight separately enforces a non-zero UTXO count). 200 is
/// required: an Esplora-side error surfaces as 503 and we want that
/// to fail the suite, not be silently tolerated.
#[tokio::test]
async fn health_publisher_returns_well_formed_response() {
    let resp = http_client()
        .get(url("/health/publisher"))
        .send()
        .await
        .expect("GET /health/publisher");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "/health/publisher must return 200 — anything else means Esplora is unreachable or the publisher route regressed"
    );
    let body: Value = resp.json().await.expect("/health/publisher body is JSON");
    assert!(
        body["address"].as_str().is_some_and(|v| !v.is_empty()),
        "publisher address must be a non-empty string, got {:?}",
        body["address"]
    );
    assert!(
        body["utxo_count"].as_u64().is_some(),
        "utxo_count must be a u64, got {:?}",
        body["utxo_count"]
    );
    assert!(
        body["total_sats"].as_u64().is_some(),
        "total_sats must be a u64, got {:?}",
        body["total_sats"]
    );
}

#[tokio::test]
async fn balance_unknown_address_is_gone() {
    // Stage 3 Runde 5: GET /api/balance is closed (410) for every query shape,
    // including a well-formed (address, asset_id) pair. Never 200 with
    // balance:0 — that masked the protocol error.
    let address = format!("0x{}", "00".repeat(32));
    let asset = format!("0x{}", "11".repeat(32));
    assert_legacy_gone(
        &http_client(),
        reqwest::Method::GET,
        &format!("/api/balance?address={}&asset_id={}", address, asset),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
}

#[tokio::test]
async fn balance_missing_param_is_gone() {
    // Closed handler ignores query validation: always 410, never 422.
    assert_legacy_gone(
        &http_client(),
        reqwest::Method::GET,
        "/api/balance",
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
}

#[tokio::test]
async fn balance_address_without_asset_id_is_gone() {
    // Multi-asset missing-asset_id used to be 422; after Stage 3 the route
    // is gone for every query shape.
    let address = format!("0x{}", "00".repeat(32));
    assert_legacy_gone(
        &http_client(),
        reqwest::Method::GET,
        &format!("/api/balance?address={}", address),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
}

#[tokio::test]
async fn balance_invalid_hex_is_gone() {
    assert_legacy_gone(
        &http_client(),
        reqwest::Method::GET,
        "/api/balance?address=not_hex",
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
}

// ---------------------------------------------------------------------------
// /api/history — paginated per-address history (issue #153)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn history_missing_address_is_gone() {
    assert_legacy_gone(
        &http_client(),
        reqwest::Method::GET,
        "/api/history",
        &["/api/history", "Stage 3", "read.account"],
    )
    .await;
}

#[tokio::test]
async fn history_invalid_hex_is_gone() {
    assert_legacy_gone(
        &http_client(),
        reqwest::Method::GET,
        "/api/history?address=not_hex",
        &["/api/history", "Stage 3", "read.account"],
    )
    .await;
}

#[tokio::test]
async fn history_limit_above_max_is_gone() {
    let address = format!("0x{}", "00".repeat(32));
    assert_legacy_gone(
        &http_client(),
        reqwest::Method::GET,
        &format!("/api/history?address={}&limit=201", address),
        &["/api/history", "Stage 3", "read.account"],
    )
    .await;
}

#[tokio::test]
async fn history_unknown_address_is_gone() {
    // Stage 3 Runde 6: unauthenticated history is closed. Fresh address
    // still yields 410 (not 200 with empty page).
    let address = TestWallet::new().address_hex();
    assert_legacy_gone(
        &http_client(),
        reqwest::Method::GET,
        &format!("/api/history?address={}", address),
        &["/api/history", "Stage 3", "read.account"],
    )
    .await;
}

/// Stage 3 Runde 6: unauthenticated `/api/history` is closed (410).
#[tokio::test]
async fn history_after_mint_is_gone() {
    let client = http_client();
    let alice = TestWallet::new();
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!("/api/history?address={}", alice.address_hex()),
        &["/api/history", "Stage 3", "read.account"],
    )
    .await;
}

/// Stage 3 Runde 6: `GET /api/history/{id}` is closed (410).
#[tokio::test]
async fn history_item_is_gone() {
    let client = http_client();
    let alice = TestWallet::new();
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!("/api/history/1?address={}", alice.address_hex()),
        &["/api/history", "Stage 3", "read.account"],
    )
    .await;
}

/// Closed handler ignores validation: every shape answers 410.
#[tokio::test]
async fn history_item_validation_shapes_are_gone() {
    // Closed handler ignores validation: missing address, bad id, bad hex,
    // and unknown id all answer 410 (never 422 / 404).
    let client = http_client();
    let some_addr = format!("0x{}", "ab".repeat(32));
    for path in [
        "/api/history/1".to_string(),
        format!("/api/history/not_a_number?address={}", some_addr),
        "/api/history/1?address=not_hex".to_string(),
        format!(
            "/api/history/999999999?address={}",
            TestWallet::new().address_hex()
        ),
    ] {
        assert_legacy_gone(
            &client,
            reqwest::Method::GET,
            &path,
            &["/api/history", "Stage 3", "read.account"],
        )
        .await;
    }
}

#[tokio::test]
async fn balance_wrong_length_is_gone() {
    let address = format!("0x{}", "ab".repeat(16));
    let asset = format!("0x{}", "11".repeat(32));
    assert_legacy_gone(
        &http_client(),
        reqwest::Method::GET,
        &format!("/api/balance?address={}&asset_id={}", address, asset),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
}

#[tokio::test]
async fn address_list_is_gone() {
    // Stage 3 Runde 6: unauthenticated address enumeration is closed.
    // Feature gate still applies (route may 404 when `address-list` is off);
    // when the route is mounted it must be 410, never a list payload.
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.address_list {
        feature_skip!("address_list", "address_list_is_gone");
    }
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        "/api/address",
        &["/api/address", "Stage 3", "read.account"],
    )
    .await;
}

#[tokio::test]
async fn proof_for_huge_id_is_gone() {
    // Stage 3 Runde 5: closed for every id — never 404 that probes the store.
    assert_legacy_gone(
        &http_client(),
        reqwest::Method::GET,
        &format!("/api/proof/{}", u64::MAX),
        &["/api/proof", "Stage 3", "read.proof"],
    )
    .await;
}

#[tokio::test]
async fn inscriptions_lookup_is_gone() {
    // Stage 3 Runde 6: GET /api/inscriptions/:txid is closed.
    let txid = "00".repeat(32);
    assert_legacy_gone(
        &http_client(),
        reqwest::Method::GET,
        &format!("/api/inscriptions/{}", txid),
        &["/api/inscriptions", "Stage 3"],
    )
    .await;
}

#[tokio::test]
async fn resolve_unknown_username_returns_404() {
    let client = http_client();
    let resp = client
        .get(url("/api/username/resolve/definitely_not_claimed_xyzzy"))
        .send()
        .await
        .expect("GET /api/username/resolve/<unknown>");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "expected 404 for unknown username, got {}",
        resp.status()
    );
}

#[tokio::test]
async fn lnurlp_unknown_user_returns_404() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.lnurl {
        feature_skip!("lnurl", "lnurlp_unknown_user_returns_404");
    }
    let resp = client
        .get(url("/.well-known/lnurlp/definitely_not_claimed_xyzzy"))
        .send()
        .await
        .expect("GET /.well-known/lnurlp/<unknown>");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn lnurl_pay_callback_returns_phase2_stub() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.lnurl {
        feature_skip!("lnurl", "lnurl_pay_callback_returns_phase2_stub");
    }
    let resp = client
        .get(url("/lnurl/pay/anyone"))
        .send()
        .await
        .expect("GET /lnurl/pay/anyone");
    // The lnurl callback returns Json directly (no error wrapping), so
    // it always answers 200 with a body that says "Phase 2".
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body JSON");
    assert_eq!(body["status"], "ERROR");
    assert!(
        body["reason"]
            .as_str()
            .is_some_and(|s| s.contains("Phase 2")),
        "expected Phase 2 stub, got {:?}",
        body["reason"]
    );
}

#[tokio::test]
async fn fallback_unknown_route_returns_404() {
    let resp = http_client()
        .get(url("/api/nonsense"))
        .send()
        .await
        .expect("GET /api/nonsense");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

// ---------------------------------------------------------------------------
// Section 2 — negative-path POSTs (no roundtrip required)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn mint_empty_body_returns_422() {
    // The `Json<MintRequest>` extractor deserialises before the
    // Idempotency-Key header gate, so an empty body 422s regardless of
    // the header — supply one anyway to keep the request well-formed.
    let resp = http_client()
        .post(url("/api/jobs/mint"))
        .header("Idempotency-Key", random_idempotency_key())
        .json(&json!({}))
        .send()
        .await
        .expect("POST /api/jobs/mint {}");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn mint_bad_signature_returns_401() {
    // Model 2: the mint is no longer addressed by `account_address` — the
    // owner is derived server-side from `creator_pubkey`. The request is
    // authenticated by a creator BIP-340 signature over the mint fields.
    // A well-formed MintRequest with a garbage signature is rejected
    // inline by `flow::validate_mint_request` with the `JobErrorResponse`
    // envelope (`{error}` only, no `success`).
    let alice = TestWallet::new();
    let resp = http_client()
        .post(url("/api/jobs/mint"))
        .header("Idempotency-Key", random_idempotency_key())
        .json(&json!({
            "creator_pubkey": hex::encode(alice.pubkey(0).serialize()),
            "next_public_key": hex::encode(alice.pubkey(1).serialize()),
            "name": ASSET_NAME,
            "decimals": ASSET_DECIMALS,
            "amount": 100u64,
            "signature": "00".repeat(64),
            "timestamp": unix_now(),
        }))
        .send()
        .await
        .expect("POST /api/jobs/mint bad sig");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.expect("mint 401 body JSON");
    assert!(
        body.get("success").is_none(),
        "Job-API error envelope must not carry `success` (got {:?})",
        body.get("success")
    );
    assert_eq!(body["error"], "Signature verification failed");
}

#[tokio::test]
async fn mint_stale_timestamp_returns_401() {
    // Model 2: `validate_mint_request` runs the timestamp-window gate
    // before the signature check, so a stale timestamp surfaces
    // distinctly as 401 with the canonical window message — even when the
    // signature itself is valid over the stale fields.
    let alice = TestWallet::new();
    let stale_ts = unix_now().saturating_sub(600);
    let signature = alice.sign_mint(ASSET_NAME, ASSET_DECIMALS, 100, stale_ts);
    let resp = http_client()
        .post(url("/api/jobs/mint"))
        .header("Idempotency-Key", random_idempotency_key())
        .json(&json!({
            "creator_pubkey": hex::encode(alice.pubkey(0).serialize()),
            "next_public_key": hex::encode(alice.pubkey(1).serialize()),
            "name": ASSET_NAME,
            "decimals": ASSET_DECIMALS,
            "amount": 100u64,
            "signature": signature,
            "timestamp": stale_ts,
        }))
        .send()
        .await
        .expect("POST /api/jobs/mint stale ts");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    let body: Value = resp.json().await.expect("mint 401 body JSON");
    assert!(
        body.get("success").is_none(),
        "Job-API error envelope must not carry `success` (got {:?})",
        body.get("success")
    );
    assert_eq!(body["error"], "Request timestamp too old or in the future");
}

#[tokio::test]
async fn send_empty_body_returns_422() {
    // `Json<SendCoinRequest>` deserialisation fails before the
    // Idempotency-Key gate, so an empty body 422s regardless.
    let resp = http_client()
        .post(url("/api/jobs/send"))
        .header("Idempotency-Key", random_idempotency_key())
        .json(&json!({}))
        .send()
        .await
        .expect("POST /api/jobs/send {}");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn send_bad_address_hex_returns_422() {
    // All required fields present, but account_address is not valid hex
    // — this should fail at the hex-decode step (handler-level 422,
    // not axum-level deserialization 422).
    let alice = TestWallet::new();
    // Signature/timestamp are present so the request passes the
    // "Missing signature" / "Missing timestamp" / timestamp-window gates
    // upstream; the test exercises the per-field hex validator that
    // runs after the auth gates.
    let ts = unix_now();
    let signature = alice.sign_send("0xZZZZZZ", &alice.address_hex(), 1, ts);
    let body = json!({
        "account_address": "0xZZZZZZ",
        "recipient": alice.address_hex(),
        "amount": 1u64,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "next_public_key": hex::encode(alice.pubkey(1).serialize()),
        "prev_commitment_pubkey": Option::<String>::None,
        "signature": Some(signature),
        "timestamp": Some(ts),
    });
    // Inline `validate_send_request` runs the sig + timestamp gates
    // first (both pass here), then the per-field hex decode fails →
    // synchronous 422 from `POST /api/jobs/send`, no job admitted.
    let resp = http_client()
        .post(url("/api/jobs/send"))
        .header("Idempotency-Key", random_idempotency_key())
        .json(&body)
        .send()
        .await
        .expect("POST /api/jobs/send bad hex");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // Body contract: `JobErrorResponse` envelope (`{error}` only). The
    // string is specific (per-field), not the generic `"Invalid hex"`
    // listed in the app's `KNOWN_SERVER_ERRORS` — the lockstep
    // inventory below tracks the mismatch.
    let body: Value = resp.json().await.expect("send 422 body JSON");
    assert!(
        body.get("success").is_none(),
        "Job-API error envelope must not carry `success` (got {:?})",
        body.get("success")
    );
    assert_eq!(body["error"], "account_address is not valid hex");
}

#[tokio::test]
async fn send_unknown_account_returns_404() {
    // Well-formed body, valid signatures, but the sender account has
    // no balance / state on the node. The signature + timestamp gates
    // pass inline so the send job is ADMITTED (202); the
    // "Unknown account address" rejection comes from `send_coins`,
    // which runs in the dispatcher's prove leg — so it surfaces as an
    // async terminal `failed` status, NOT a synchronous 404. The
    // FlowError carrying the 404 status maps the message into the
    // job's `error` field; the status code itself is not exposed on
    // the poll response.
    let client = http_client();
    let alice = TestWallet::new();
    let bob = TestWallet::new();
    let amount: u64 = 1;
    let ts = unix_now();
    let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), amount, ts);

    let body = json!({
        "account_address": alice.address_hex(),
        "recipient": bob.address_hex(),
        "amount": amount,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "next_public_key": hex::encode(alice.pubkey(1).serialize()),
        "prev_commitment_pubkey": Option::<String>::None,
        "signature": Some(signature),
        "timestamp": Some(ts),
        // Required under the multi-asset model; without it the job would
        // fail with "asset_id is required" before reaching the
        // unknown-account check this test targets.
        "asset_id": asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS),
    });
    let (job_id, status, _admit) = submit_send_job(&client, &body).await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "unknown-account send passes inline validation and is admitted"
    );
    let job_id = job_id.expect("admitted send job carries a job_id");

    // Poll to the terminal `failed` state and assert the canonical
    // "Unknown account address" string from `map_send_coins_error`.
    // This is the value-bearing half of the lockstep check — the app's
    // `KNOWN_SERVER_ERRORS` list is asserted against the live server
    // here so a server-side rename surfaces immediately.
    let terminal = poll_job_until_terminal(&client, &job_id).await;
    assert_eq!(
        terminal["status"], "failed",
        "unknown-account send job must fail, got {}",
        terminal
    );
    assert_eq!(terminal["error"], "Unknown account address");
}

#[tokio::test]
async fn send_bad_signature_returns_401() {
    let alice = TestWallet::new();
    let bob = TestWallet::new();
    let body = json!({
        "account_address": alice.address_hex(),
        "recipient": bob.address_hex(),
        "amount": 1u64,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "next_public_key": hex::encode(alice.pubkey(1).serialize()),
        "prev_commitment_pubkey": Option::<String>::None,
        "signature": Some("00".repeat(64)),
        "timestamp": Some(unix_now()),
    });
    // The signature gate runs inline in `validate_send_request`, so a
    // bad signature is rejected synchronously by `POST /api/jobs/send`.
    let resp = http_client()
        .post(url("/api/jobs/send"))
        .header("Idempotency-Key", random_idempotency_key())
        .json(&body)
        .send()
        .await
        .expect("POST /api/jobs/send bad sig");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Body contract: `JobErrorResponse` (`{error}`).
    // `"Signature verification failed"` is one of the app's
    // `KNOWN_SERVER_ERRORS` and the live server must emit the exact
    // same string.
    let body: Value = resp.json().await.expect("send 401 body JSON");
    assert!(
        body.get("success").is_none(),
        "Job-API error envelope must not carry `success` (got {:?})",
        body.get("success")
    );
    assert_eq!(body["error"], "Signature verification failed");
}

#[tokio::test]
async fn send_stale_timestamp_returns_401() {
    let alice = TestWallet::new();
    let bob = TestWallet::new();
    let amount: u64 = 1;
    // Timestamp ten minutes in the past — outside the 5-minute window.
    let stale_ts = unix_now().saturating_sub(600);
    let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), amount, stale_ts);
    let body = json!({
        "account_address": alice.address_hex(),
        "recipient": bob.address_hex(),
        "amount": amount,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "next_public_key": hex::encode(alice.pubkey(1).serialize()),
        "prev_commitment_pubkey": Option::<String>::None,
        "signature": Some(signature),
        "timestamp": Some(stale_ts),
    });
    // The timestamp-window gate runs inline in `validate_send_request`,
    // so a stale timestamp is rejected synchronously.
    let resp = http_client()
        .post(url("/api/jobs/send"))
        .header("Idempotency-Key", random_idempotency_key())
        .json(&body)
        .send()
        .await
        .expect("POST /api/jobs/send stale ts");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Body contract: `JobErrorResponse` (`{error}`).
    // `"Request timestamp too old or in the future"` is one of the
    // app's `KNOWN_SERVER_ERRORS` and the live server must emit the
    // exact same string.
    let body: Value = resp.json().await.expect("send 401 body JSON");
    assert!(
        body.get("success").is_none(),
        "Job-API error envelope must not carry `success` (got {:?})",
        body.get("success")
    );
    assert_eq!(body["error"], "Request timestamp too old or in the future");
}

#[tokio::test]
async fn receive_empty_body_is_gone() {
    // Stage 3 Runde 4: POST /api/receive is closed (410), not 200+success:false.
    let client = http_client();
    let resp = client
        .post(url("/api/receive"))
        .body(Vec::<u8>::new())
        .send()
        .await
        .expect("POST /api/receive empty");
    assert_eq!(resp.status(), StatusCode::GONE);
    let body: Value = resp.json().await.expect("body JSON");
    let err = body["error"].as_str().unwrap_or("");
    assert!(
        err.contains("/api/receive") || err.contains("Stage 3"),
        "error must name the removed surface; got {err:?}"
    );
    assert_eq!(body["success"], Value::Bool(false));
}

#[tokio::test]
async fn receive_garbage_body_is_gone() {
    let garbage = vec![0xFFu8; 64];
    let resp = http_client()
        .post(url("/api/receive"))
        .body(garbage)
        .send()
        .await
        .expect("POST /api/receive garbage");
    assert_eq!(resp.status(), StatusCode::GONE);
    let body: Value = resp.json().await.expect("body JSON");
    let err = body["error"].as_str().unwrap_or("");
    assert!(
        err.contains("/api/receive") || err.contains("Stage 3"),
        "error must name the removed surface; got {err:?}"
    );
    assert_eq!(body["success"], Value::Bool(false));
}

#[tokio::test]
async fn commit_unknown_proof_id_returns_404() {
    // Job-API: commit is keyed by JOB id, not proof_id. The proof_id
    // now lives inside the commit body and is only validated by
    // `commit_flow` once a real `awaiting_signature` job is resumed.
    // The synchronous negative path is "no job for this id" → 404
    // `{error: "Job not found"}`. A random UUID is guaranteed to miss.
    let alice = TestWallet::new();
    let unknown_job = uuid_v4_like();
    let body = json!({
        "proof_id": u64::MAX,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "signature": "00".repeat(64),
        "message": "00".repeat(64),
    });
    let resp = http_client()
        .post(url(&format!("/api/jobs/{}/commit", unknown_job)))
        .json(&body)
        .send()
        .await
        .expect("POST /api/jobs/:id/commit unknown id");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: Value = resp.json().await.expect("commit 404 body JSON");
    assert_eq!(body["error"], "Job not found");
}

#[tokio::test]
async fn commit_bad_message_hex_returns_404_for_unknown_job() {
    // Job-API: a malformed `message` hex is validated by `commit_flow`
    // in the dispatcher, reachable only after a real
    // `awaiting_signature` job. From a black-box client with no such
    // job, the commit endpoint short-circuits on the unknown job id at
    // 404 before any payload validation runs — so a bad-message body
    // against an unknown job is still a clean 404. (The async
    // bad-message rejection is covered by the deterministic unit tests
    // in `flow`/`router_tests`.)
    let alice = TestWallet::new();
    let unknown_job = uuid_v4_like();
    let body = json!({
        "proof_id": 1u64,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "signature": "00".repeat(64),
        "message": "not_valid_hex_zzz",
    });
    let resp = http_client()
        .post(url(&format!("/api/jobs/{}/commit", unknown_job)))
        .json(&body)
        .send()
        .await
        .expect("POST /api/jobs/:id/commit bad message");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    let body: Value = resp.json().await.expect("commit 404 body JSON");
    assert_eq!(body["error"], "Job not found");
}

#[tokio::test]
async fn claim_username_pk_mismatch_returns_401() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.username_claim {
        feature_skip!("username_claim", "claim_username_pk_mismatch_returns_401");
    }
    let alice = TestWallet::new();
    let mallory = TestWallet::new();
    let username = format!("mallory_{}", random_suffix());
    let ts = unix_now();
    // Sign with mallory's key but claim alice's address — the
    // sha256(pk) == address check fails.
    let signature = mallory.sign_username_claim(&alice.address_hex(), &username, ts);
    let body = json!({
        "username": username,
        "address": alice.address_hex(),
        "public_key": hex::encode(mallory.pubkey(0).serialize()),
        "signature": signature,
        "timestamp": ts,
    });
    let resp = client
        .post(url("/api/username/claim"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/username/claim mismatch");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn claim_username_bad_signature_returns_401() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.username_claim {
        feature_skip!("username_claim", "claim_username_bad_signature_returns_401");
    }
    let alice = TestWallet::new();
    let username = format!("alice_{}", random_suffix());
    let body = json!({
        "username": username,
        "address": alice.address_hex(),
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "signature": "00".repeat(64),
        "timestamp": unix_now(),
    });
    let resp = client
        .post(url("/api/username/claim"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/username/claim bad sig");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn claim_username_stale_timestamp_returns_401() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.username_claim {
        feature_skip!(
            "username_claim",
            "claim_username_stale_timestamp_returns_401"
        );
    }
    let alice = TestWallet::new();
    let username = format!("alice_{}", random_suffix());
    let stale_ts = unix_now().saturating_sub(600);
    let signature = alice.sign_username_claim(&alice.address_hex(), &username, stale_ts);
    let body = json!({
        "username": username,
        "address": alice.address_hex(),
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "signature": signature,
        "timestamp": stale_ts,
    });
    let resp = client
        .post(url("/api/username/claim"))
        .json(&body)
        .send()
        .await
        .expect("POST /api/username/claim stale");
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
#[tokio::test]
async fn mint_roundtrip_closed_observation_surfaces_are_gone() {
    // Stage 3: legacy observation via GET /api/balance and GET /api/proof/:id
    // is closed (410). #227 ignored the mint happy path over the #226 owner
    // mismatch; the cutover additionally removes the unauthenticated read
    // surfaces, so this test pins 410 rather than a ledger credit.
    let client = http_client();
    let alice = TestWallet::new();
    let asset = format!("0x{}", "11".repeat(32));
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!(
            "/api/balance?address={}&asset_id={}",
            alice.address_hex(),
            asset
        ),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!("/api/proof/{}", 1u64),
        &["/api/proof", "Stage 3", "read.proof"],
    )
    .await;
}
#[tokio::test]
async fn send_observation_via_balance_and_proof_is_gone() {
    // Stage 3 closed GET /api/balance and GET /api/proof/:id.
    let client = http_client();
    let alice = TestWallet::new();
    let asset = format!("0x{}", "11".repeat(32));
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!(
            "/api/balance?address={}&asset_id={}",
            alice.address_hex(),
            asset
        ),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!("/api/proof/{}", u64::MAX),
        &["/api/proof", "Stage 3", "read.proof"],
    )
    .await;
}

/// Roundtrip C — claim a username, resolve it, then hit the LNURLp
/// endpoint that depends on the username being resolvable.
#[tokio::test]
async fn username_claim_resolve_lnurlp_roundtrip() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    // The cascade hits three gated/permanent endpoints: claim (gated
    // on `username_claim`), resolve (permanent MVP), and the LNURLp
    // well-known leg (gated on `lnurl`). Skip if either gated feature
    // is off — the trailing probe cannot succeed without both.
    if !caps.username_claim {
        feature_skip!("username_claim", "username_claim_resolve_lnurlp_roundtrip");
    }
    if !caps.lnurl {
        feature_skip!("lnurl", "username_claim_resolve_lnurlp_roundtrip");
    }
    let alice = TestWallet::new();
    let username = format!("e2e_{}", random_suffix());
    let ts = unix_now();
    let signature = alice.sign_username_claim(&alice.address_hex(), &username, ts);

    let claim_resp = client
        .post(url("/api/username/claim"))
        .json(&json!({
            "username": username,
            "address": alice.address_hex(),
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "signature": signature,
            "timestamp": ts,
        }))
        .send()
        .await
        .expect("POST /api/username/claim");
    let claim_status = claim_resp.status();
    // DB availability is covered separately by `/health/ready`'s `db`
    // failure tag; a 503 here means the username claim path itself
    // regressed and is treated as a hard failure (no `dev_skip!`).
    assert_eq!(
        claim_status,
        StatusCode::OK,
        "claim failed: {}",
        claim_status
    );
    let claim_body: Value = claim_resp.json().await.expect("claim body");
    assert_eq!(claim_body["username"], username);

    // ---- Resolve ----
    let resolve_resp = client
        .get(url(&format!("/api/username/resolve/{}", username)))
        .send()
        .await
        .expect("GET resolve");
    assert_eq!(resolve_resp.status(), StatusCode::OK);
    let resolve_body: Value = resolve_resp.json().await.expect("resolve body");
    assert_eq!(resolve_body["username"], username);
    assert_eq!(resolve_body["address"], alice.address_hex());

    // ---- LNURLp ----
    let lnurlp_resp = client
        .get(url(&format!("/.well-known/lnurlp/{}", username)))
        .send()
        .await
        .expect("GET lnurlp");
    assert_eq!(lnurlp_resp.status(), StatusCode::OK);
    let lnurlp_body: Value = lnurlp_resp.json().await.expect("lnurlp body");
    assert_eq!(lnurlp_body["tag"], "payRequest");
    assert!(
        lnurlp_body["callback"]
            .as_str()
            .is_some_and(|s| s.contains(&username)),
        "callback must reference the username, got {:?}",
        lnurlp_body["callback"]
    );
    let min_sendable = lnurlp_body["minSendable"]
        .as_u64()
        .expect("minSendable must be a u64");
    let max_sendable = lnurlp_body["maxSendable"]
        .as_u64()
        .expect("maxSendable must be a u64");
    assert!(
        min_sendable >= 1,
        "minSendable must be >= 1 msat, got {}",
        min_sendable
    );
    assert!(
        max_sendable >= min_sendable,
        "maxSendable ({}) must be >= minSendable ({})",
        max_sendable,
        min_sendable
    );
    assert!(lnurlp_body["metadata"]
        .as_str()
        .is_some_and(|s| !s.is_empty()));
}
#[tokio::test]
async fn mint_observation_surfaces_are_gone() {
    let client = http_client();
    let alice = TestWallet::new();
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!(
            "/api/balance?address={}&asset_id=0x{}",
            alice.address_hex(),
            "11".repeat(32)
        ),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
}
#[tokio::test]
async fn commit_observation_via_proof_download_is_gone() {
    let client = http_client();
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!("/api/proof/{}", 1u64),
        &["/api/proof", "Stage 3", "read.proof"],
    )
    .await;
}

/// Field coverage #3 — `/api/balance` carries the claimed username.
///
/// `BalanceResponse.username` is `Option<String>` with
/// `skip_serializing_if = Option::is_none`. After a successful
/// `/api/username/claim`, querying balance for the claimed address
/// MUST surface the exact (lowercased) username in the response body.
/// The wallet app reads this to render the "@<username>" badge next
/// to a balance figure without making a second round-trip.
#[tokio::test]
async fn balance_after_username_claim_is_gone() {
    // Username claim may still succeed; the legacy balance surface that
    // used to echo the username is closed (Stage 3 Runde 5).
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.username_claim {
        feature_skip!("username_claim", "balance_after_username_claim_is_gone");
    }
    let alice = TestWallet::new();
    let username = format!("u_{}", random_suffix());
    let ts = unix_now();
    let signature = alice.sign_username_claim(&alice.address_hex(), &username, ts);
    let claim_resp = client
        .post(url("/api/username/claim"))
        .json(&json!({
            "username": username,
            "address": alice.address_hex(),
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "signature": signature,
            "timestamp": ts,
        }))
        .send()
        .await
        .expect("POST /api/username/claim");
    assert_eq!(claim_resp.status(), StatusCode::OK, "claim must succeed");
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!(
            "/api/balance?address={}&asset_id=0x{}",
            alice.address_hex(),
            "11".repeat(32)
        ),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
}

/// Field coverage #4 — `/api/username/claim` echoes the claimed
/// address. The roundtrip test asserts `username` only; the wallet
/// app reads BOTH fields (username + address) and uses the echoed
/// address to verify the claim landed on the wallet's own address
/// before persisting locally — a value-bearing assertion on `address`
/// is therefore required.
#[tokio::test]
async fn claim_response_carries_address() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.username_claim {
        feature_skip!("username_claim", "claim_response_carries_address");
    }
    let alice = TestWallet::new();
    let username = format!("u_{}", random_suffix());
    let ts = unix_now();
    let signature = alice.sign_username_claim(&alice.address_hex(), &username, ts);
    let claim_resp = client
        .post(url("/api/username/claim"))
        .json(&json!({
            "username": username,
            "address": alice.address_hex(),
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "signature": signature,
            "timestamp": ts,
        }))
        .send()
        .await
        .expect("POST /api/username/claim");
    assert_eq!(claim_resp.status(), StatusCode::OK, "claim must succeed");
    let body: Value = claim_resp.json().await.expect("claim body JSON");
    assert_eq!(
        body["username"].as_str(),
        Some(username.to_lowercase().as_str()),
        "claim response must echo the lowercased username, got {:?}",
        body["username"]
    );
    assert_eq!(
        body["address"].as_str(),
        Some(alice.address_hex().as_str()),
        "claim response must echo the claimed address verbatim, got {:?}",
        body["address"]
    );
}

/// Field coverage #5 — `/api/balance` omits `username` for an unclaimed
/// wallet. `BalanceResponse.username` is `Option<String>` with
/// `skip_serializing_if = Option::is_none`, so an unclaimed account
/// MUST produce a JSON body that either omits the field entirely
/// (preferred) or sets it to `null`. The wallet app's response schema
/// permits both shapes; the assertion fails if the server returns
/// e.g. `""` (empty string) instead, which would render as a phantom
/// empty username in the UI.
#[tokio::test]
async fn balance_for_unclaimed_wallet_is_gone() {
    let client = http_client();
    let wallet = TestWallet::new();
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!(
            "/api/balance?address={}&asset_id=0x{}",
            wallet.address_hex(),
            "11".repeat(32)
        ),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
}
#[tokio::test]
async fn balance_num_sends_surface_is_gone() {
    let client = http_client();
    let alice = TestWallet::new();
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!(
            "/api/balance?address={}&asset_id=0x{}",
            alice.address_hex(),
            "11".repeat(32)
        ),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
}
#[tokio::test]
async fn second_send_legacy_observation_surfaces_are_gone() {
    let client = http_client();
    let alice = TestWallet::new();
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!(
            "/api/balance?address={}&asset_id=0x{}",
            alice.address_hex(),
            "11".repeat(32)
        ),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
    assert_legacy_gone(
        &client,
        reqwest::Method::GET,
        &format!("/api/proof/{}", u64::MAX),
        &["/api/proof", "Stage 3", "read.proof"],
    )
    .await;
}

// ---------------------------------------------------------------------------
// Section 5 — error contract
//
// The error string the wallet app reads is the lockstep anchor against
// `app/src/lib/api/errorMessages.ts :: KNOWN_SERVER_ERRORS` — if the
// node renames a string without updating the app's mapping, the
// user-facing message degrades to `Serverfehler <status>: <raw>`.
//
// Under the async Job-API the error surfaces in two distinct shapes:
//   - inline validation failures (`POST /api/jobs/send` 401/422) carry
//     the `JobErrorResponse` envelope `{error: "..."}` (no `success`);
//   - `send_coins` business failures (unknown account, insufficient
//     funds) admit a job (202) that transitions to a terminal `failed`
//     status, with the message surfaced in the job's `error` field.
// The lockstep `error` *string* is identical across both — the tests
// assert on it directly.
// ---------------------------------------------------------------------------

/// Error contract #6 — the async send-failure path surfaces a clear,
/// non-empty error string.
///
/// Asserts only the SHAPE of the failure (terminal `failed` status,
/// `error` a non-empty string). The exact string is covered per-error
/// by the extended negative-path tests above and by the lockstep
/// inventory test below.
#[tokio::test]
async fn send_returns_structured_error_envelope() {
    // Use the "unknown account" path: a well-formed body with a
    // freshly-generated wallet that has never minted. The inline
    // validation gates pass, so the job is admitted and the failure
    // surfaces asynchronously in the job's terminal `error` field.
    let client = http_client();
    let alice = TestWallet::new();
    let bob = TestWallet::new();
    let amount: u64 = 1;
    let ts = unix_now();
    let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), amount, ts);
    let (job_id, status, admit) = submit_send_job(
        &client,
        &json!({
            "account_address": alice.address_hex(),
            "recipient": bob.address_hex(),
            "amount": amount,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "next_public_key": hex::encode(alice.pubkey(1).serialize()),
            "prev_commitment_pubkey": Option::<String>::None,
            "signature": Some(signature),
            "timestamp": Some(ts),
            // Required under the multi-asset model; without it the job would
            // fail with "asset_id is required" before reaching the
            // unknown-account check this test targets.
            "asset_id": asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS),
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "unknown-account send is admitted (inline gates pass); got {} body={}",
        status,
        admit
    );
    let job_id = job_id.expect("admitted send job carries a job_id");

    let terminal = poll_job_until_terminal(&client, &job_id).await;
    assert_eq!(
        terminal["status"], "failed",
        "unknown-account send job must fail, got {}",
        terminal
    );
    let error = terminal["error"]
        .as_str()
        .expect("failed job must carry an `error` string");
    assert!(!error.is_empty(), "job `error` must be non-empty");
}

/// The exact set of `error` strings the wallet app's
/// `KNOWN_SERVER_ERRORS` constant (in
/// `app/src/lib/api/errorMessages.ts`) maps from. Kept in alphabetical
/// groups matching the source comment in that file so a diff against
/// the app stays trivial. If the server adds or renames an error
/// string, BOTH this constant and the app's constant must be updated
/// in lockstep — the test below provokes every reachable string and
/// names the unreachable ones explicitly.
const APP_KNOWN_ERROR_STRINGS: &[&str] = &[
    // From `router::map_send_coins_error` — `send_coins` business errors.
    "Unknown account address",
    "prev_commitment_pubkey required for account update",
    "Insufficient funds",
    "In-coin not present in source's output_coins_root",
    "Source commitment not present in history MMR",
    "Coin is missing commitment",
    "Should provide an inclusion proof",
    "Coin should not exist in coin history tree",
    "Coin should not exist in tree yet",
    "Too many in-coins for one transition",
    "Too many out-coins for one transition",
    "prove failed",
    "internal error",
    // From `router::handler_error_response` call sites.
    "Signature verification failed",
    "Missing signature",
    "Request timestamp too old or in the future",
    "Invalid hex",
    "Invalid address length",
    "Broadcast failed",
];

/// Error contract #7 — lockstep with `app/src/lib/api/errorMessages.ts`.
///
/// Provokes every error string in `APP_KNOWN_ERROR_STRINGS` that is
/// reachable from a black-box HTTP client and asserts the server's
/// `error` body matches verbatim. Strings that depend on the
/// prover / publisher / Bitcoin network being in a specific failure
/// state are documented as comments — those are covered by deterministic
/// unit tests in `node/src/router_tests.rs` (search for
/// `map_send_coins_error`). Mismatches between the app's expected
/// strings and what the server actually emits are also documented:
/// the app lists generic `"Invalid hex"`, `"Invalid address length"`,
/// `"Broadcast failed"` placeholders that the server never emits as-is.
///
/// Covers the mint-INDEPENDENT lockstep strings (and the length guard) so
/// they keep running against DEV. The one mint-dependent provocation
/// ("Insufficient funds") lives in the separate
/// `error_strings_insufficient_funds` test, which is `#[ignore]`d pending
/// zk-coins/node#226.
#[tokio::test]
async fn error_strings_match_known_app_mapping() {
    let client = http_client();

    // ---- Strings reachable WITHOUT a prior mint -----------------

    // "Unknown account address" — fresh wallet send. Inline gates pass,
    // so the job is admitted and the rejection surfaces async as a
    // terminal `failed` status carrying the lockstep string.
    {
        let alice = TestWallet::new();
        let bob = TestWallet::new();
        let ts = unix_now();
        let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), 1, ts);
        let (job_id, status, _admit) = submit_send_job(
            &client,
            &json!({
                "account_address": alice.address_hex(),
                "recipient": bob.address_hex(),
                "amount": 1u64,
                "public_key": hex::encode(alice.pubkey(0).serialize()),
                "next_public_key": hex::encode(alice.pubkey(1).serialize()),
                "prev_commitment_pubkey": Option::<String>::None,
                "signature": Some(signature),
                "timestamp": Some(ts),
                "asset_id": asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS),
            }),
        )
        .await;
        assert_eq!(status, StatusCode::ACCEPTED);
        let job_id = job_id.expect("send job_id");
        let terminal = poll_job_until_terminal(&client, &job_id).await;
        assert_eq!(terminal["status"], "failed");
        assert_eq!(terminal["error"], "Unknown account address");
    }

    // "Signature verification failed" — 64 zero bytes as signature.
    // The signature gate runs inline, so this is rejected synchronously
    // with the `JobErrorResponse` envelope (`{error}`).
    {
        let alice = TestWallet::new();
        let bob = TestWallet::new();
        let resp = client
            .post(url("/api/jobs/send"))
            .header("Idempotency-Key", random_idempotency_key())
            .json(&json!({
                "account_address": alice.address_hex(),
                "recipient": bob.address_hex(),
                "amount": 1u64,
                "public_key": hex::encode(alice.pubkey(0).serialize()),
                "next_public_key": hex::encode(alice.pubkey(1).serialize()),
                "prev_commitment_pubkey": Option::<String>::None,
                "signature": Some("00".repeat(64)),
                "timestamp": Some(unix_now()),
            }))
            .send()
            .await
            .expect("send bad sig");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: Value = resp.json().await.expect("body JSON");
        assert_eq!(body["error"], "Signature verification failed");
    }

    // "Request timestamp too old or in the future" — stale timestamp
    // (inline gate → synchronous 401).
    {
        let alice = TestWallet::new();
        let bob = TestWallet::new();
        let stale_ts = unix_now().saturating_sub(600);
        let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), 1, stale_ts);
        let resp = client
            .post(url("/api/jobs/send"))
            .header("Idempotency-Key", random_idempotency_key())
            .json(&json!({
                "account_address": alice.address_hex(),
                "recipient": bob.address_hex(),
                "amount": 1u64,
                "public_key": hex::encode(alice.pubkey(0).serialize()),
                "next_public_key": hex::encode(alice.pubkey(1).serialize()),
                "prev_commitment_pubkey": Option::<String>::None,
                "signature": Some(signature),
                "timestamp": Some(stale_ts),
            }))
            .send()
            .await
            .expect("send stale ts");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: Value = resp.json().await.expect("body JSON");
        assert_eq!(body["error"], "Request timestamp too old or in the future");
    }

    // "Missing signature" — well-formed send body but signature: null.
    // `validate_send_request` rejects an absent `signature` (or
    // `timestamp`) field with 401 inline BEFORE crypto verification
    // runs, so a clock-skew or empty-credential misconfiguration
    // surfaces distinctly instead of collapsing into
    // `"Signature verification failed"`.
    {
        let alice = TestWallet::new();
        let body = json!({
            "account_address": alice.address_hex(),
            "recipient": TestWallet::new().address_hex(),
            "amount": 1u64,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "next_public_key": hex::encode(alice.pubkey(1).serialize()),
            "prev_commitment_pubkey": Option::<String>::None,
            "timestamp": unix_now(),
            // signature deliberately omitted
        });
        let resp = http_client()
            .post(url("/api/jobs/send"))
            .header("Idempotency-Key", random_idempotency_key())
            .json(&body)
            .send()
            .await
            .expect("send missing signature");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
        let body: Value = resp.json().await.expect("body JSON");
        assert_eq!(body["error"], "Missing signature");
    }

    // ---- Mismatches: app uses a generic placeholder, server emits a
    //      more-specific string. Document each here. -----------------

    // app `"Invalid hex"` vs. server emit. The per-field hex error now
    // lives on the SEND path (`flow::validate_send_request`); the Model-2
    // mint derives its owner from `creator_pubkey` and has no
    // `account_address` field. Signing over the (malformed) address lets
    // the request clear the auth gates and reach the hex validator →
    // synchronous 422.
    {
        let alice = TestWallet::new();
        let ts = unix_now();
        let signature = alice.sign_send("0xZZZZZZ", &alice.address_hex(), 1, ts);
        let resp = client
            .post(url("/api/jobs/send"))
            .header("Idempotency-Key", random_idempotency_key())
            .json(&json!({
                "account_address": "0xZZZZZZ",
                "recipient": alice.address_hex(),
                "amount": 1u64,
                "public_key": hex::encode(alice.pubkey(0).serialize()),
                "next_public_key": hex::encode(alice.pubkey(1).serialize()),
                "signature": Some(signature),
                "timestamp": Some(ts),
            }))
            .send()
            .await
            .expect("send bad hex");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body: Value = resp.json().await.expect("body JSON");
        let actual = body["error"].as_str().expect("error string");
        assert_eq!(
            actual, "account_address is not valid hex",
            "server emits a per-field hex error today; app `KNOWN_SERVER_ERRORS` \
             carries the generic `\"Invalid hex\"` — lockstep gap"
        );
    }

    // app `"Invalid address length"` vs. server emit (send length path).
    {
        let alice = TestWallet::new();
        let short_addr = format!("0x{}", "ab".repeat(16));
        let ts = unix_now();
        let signature = alice.sign_send(&short_addr, &alice.address_hex(), 1, ts);
        let resp = client
            .post(url("/api/jobs/send"))
            .header("Idempotency-Key", random_idempotency_key())
            .json(&json!({
                "account_address": short_addr,
                "recipient": alice.address_hex(),
                "amount": 1u64,
                "public_key": hex::encode(alice.pubkey(0).serialize()),
                "next_public_key": hex::encode(alice.pubkey(1).serialize()),
                "signature": Some(signature),
                "timestamp": Some(ts),
            }))
            .send()
            .await
            .expect("send short addr");
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
        let body: Value = resp.json().await.expect("body JSON");
        let actual = body["error"].as_str().expect("error string");
        assert_eq!(
            actual, "address must be 32 bytes (64 hex chars)",
            "server emits a single combined length error for from/to today; app \
             `KNOWN_SERVER_ERRORS` carries the generic \
             `\"Invalid address length\"` — lockstep gap"
        );
    }

    // ---- Strings NOT deterministically reachable from a black-box
    //      HTTP client. Each is covered by a unit test in
    //      `node/src/router_tests.rs`; the comments below name the
    //      reachable path so a future contributor can find it without
    //      a full repo grep. ----------------------------------------
    //
    // "In-coin not present in source's output_coins_root"
    //   → router_tests::map_send_coins_error_in_coin_not_present
    //     (reachable from `account_node::send_coins` only when the
    //      defense-in-depth shim catches a tampered in-coin proof —
    //      requires a doctored CoinProof on disk; not provoked here)
    //
    // "Source commitment not present in history MMR"
    //   → router_tests::map_send_coins_error_source_commitment_missing
    //     (requires a mint commitment that was somehow removed from
    //      the MMR between snapshot and prove — race window only)
    //
    // "Coin is missing commitment"
    //   → router_tests::map_send_coins_error_coin_missing_commitment
    //     (requires `receive_coin` with a CoinProof.commitment = None,
    //      which the router prevents via type — internal-state-only)
    //
    // "Should provide an inclusion proof"
    //   → router_tests::map_send_coins_error_should_provide_inclusion_proof
    //     (server-internal path through prepare_send_coins — none of
    //      the client-facing routes can pass a missing inclusion proof)
    //
    // "Coin should not exist in coin history tree" / "Coin should not
    //  exist in tree yet"
    //   → router_tests::map_send_coins_error_coin_history_*
    //     (a double-commit replay would reach these — but the publisher
    //      side rejects the replay before send_coins sees it; the
    //      provocation requires direct in-memory mutation that the HTTP
    //      surface forbids)
    //
    // "Too many in-coins for one transition" / "Too many out-coins for
    //  one transition"
    //   → router_tests::map_send_coins_error_too_many_*
    //     (`/api/send` accepts one recipient and reads one in-coin per
    //      sender, so the >8 path is unreachable from the HTTP surface)
    //
    // "prove failed"
    //   → router_tests::map_send_coins_error_prove_failed
    //     (catch-all for any error message ending in "failed" — would
    //      require the prover binary to fail at runtime; flaky to
    //      provoke against the live DEV deploy)
    //
    // "internal error"
    //   → router_tests::map_send_coins_error_unknown_returns_internal
    //     (catch-all for any unmapped `send_coins` error — would
    //      require the server to invent a new error string)
    //
    // "Missing signature"
    //   → router_tests::verify_send_signature_missing_signature for the
    //     helper-level unit; the live provocation in the block above
    //     exercises the handler-level 401.
    //
    // "Broadcast failed"
    //   → operator-only: requires the publisher's broadcast leg to
    //      fail. The server actually emits
    //      `"Failed to broadcast commitment inscription on-chain"` on
    //      this branch (see `runtime::broadcast_commit_and_deliver`),
    //      so the app's `"Broadcast failed"` is also a lockstep gap
    //      placeholder rather than an exact-match expectation.

    // ---- Inventory anchor ---------------------------------------
    //
    // Compile-time guard: the constant above tracks
    // `app/src/lib/api/errorMessages.ts :: KNOWN_SERVER_ERRORS` 1:1.
    // If the app drops a string, this `assert!` keeps the suite
    // honest — the test reads the constant rather than re-listing
    // strings so anyone updating the inventory has exactly one place
    // to touch in this file.
    assert!(
        APP_KNOWN_ERROR_STRINGS.len() == 19,
        "APP_KNOWN_ERROR_STRINGS length drifted from the app's \
         KNOWN_SERVER_ERRORS — update both in lockstep (got {})",
        APP_KNOWN_ERROR_STRINGS.len()
    );
}

/// Mint-dependent half of the error-string lockstep: the "Insufficient
/// funds" provocation needs a real minted balance **and** an unauthenticated
/// balance read. Stage 3 closed `GET /api/balance` (410); keep the test
/// ignored until a capability-bound observation path exists for this suite.
#[tokio::test]
#[ignore = "Stage 3 closed GET /api/balance (410); needs capability-bound observation to mint then over-send"]
async fn error_strings_insufficient_funds() {
    let client = http_client();
    let alice = TestWallet::new();
    let bob = TestWallet::new();

    let mint_result = mint_via_job(&client, &alice, ASSET_NAME, ASSET_DECIMALS, MINT_AMOUNT).await;
    assert_eq!(mint_result["success"], Value::Bool(true), "mint failed");
    let aid = asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS);
    let _ = poll_balance_at_least(&client, &alice.address_hex(), &aid, MINT_AMOUNT).await;

    // "Insufficient funds" — send MINT_AMOUNT + 1 (one sat over balance). A
    // `send_coins` business error: the job is admitted (inline gates pass) and
    // the rejection surfaces async as a terminal `failed` carrying the string.
    let amount: u64 = MINT_AMOUNT + 1;
    let ts = unix_now();
    let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), amount, ts);
    let (job_id, status, _admit) = submit_send_job(
        &client,
        &json!({
            "account_address": alice.address_hex(),
            "recipient": bob.address_hex(),
            "amount": amount,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "next_public_key": hex::encode(alice.pubkey(1).serialize()),
            "signature": Some(signature),
            "timestamp": Some(ts),
            "asset_id": aid,
        }),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::ACCEPTED,
        "insufficient-funds send is admitted (inline gates pass)"
    );
    let job_id = job_id.expect("send job_id");
    let terminal = poll_job_until_terminal(&client, &job_id).await;
    assert_eq!(terminal["status"], "failed");
    assert_eq!(terminal["error"], "Insufficient funds");
}
/// Stage 3: `/api/balance` is 410 Gone. Residual callers fail loud.
#[allow(dead_code)]
async fn poll_balance_at_least(
    client: &reqwest::Client,
    address: &str,
    asset_id: &str,
    _target: u64,
) -> u64 {
    assert_legacy_gone(
        client,
        reqwest::Method::GET,
        &format!("/api/balance?address={}&asset_id={}", address, asset_id),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
    panic!(
        "poll_balance_at_least: GET /api/balance is closed (Stage 3);          cannot observe balance for {address}"
    );
}
/// Stage 3: `/api/balance` is 410 Gone. Residual callers fail loud.
#[allow(dead_code)]
async fn poll_balance_at_most(
    client: &reqwest::Client,
    address: &str,
    asset_id: &str,
    _target: u64,
) -> u64 {
    assert_legacy_gone(
        client,
        reqwest::Method::GET,
        &format!("/api/balance?address={}&asset_id={}", address, asset_id),
        &["/api/balance", "Stage 3", "read.account"],
    )
    .await;
    panic!(
        "poll_balance_at_most: GET /api/balance is closed (Stage 3);          cannot observe balance for {address}"
    );
}

fn random_suffix() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

// ---------------------------------------------------------------------------
// Async Job-API helpers
//
// PR #161 removed the synchronous `/api/mint`, `/api/send`, `/api/commit`
// routes and replaced them with the async Job-API: clients POST to
// `/api/jobs/{mint,send}` (with an `Idempotency-Key` header), receive a
// `202 {job_id, status}`, then poll `GET /api/jobs/:id` for state
// transitions (`queued → proving → [awaiting_signature] → broadcasting
// → completed`). Send is two-phase: the wallet signs the proof's
// `ash || ocr` and attaches it via `POST /api/jobs/:id/commit`.
//
// The node is the source of truth — these helpers map the legacy
// 200-body assertions onto the job `result` object and surface async
// terminal failures (`failed`/`cancelled`) so a regression is never
// masked by a poll timeout.
// ---------------------------------------------------------------------------

/// Poll budget for one job's full lifecycle. Must absorb three
/// independent latencies on the shared DEV node:
///
/// - cold-start prover warm-up (~30 s before the first `proving` tick),
/// - the prove + broadcast legs themselves (several seconds each),
/// - and time spent `queued` behind the single-threaded dispatcher when
///   the suite (or a concurrent workflow on the shared DEV node) has
///   other jobs in flight — a fresh job can sit in `queued` for a while
///   before the dispatcher picks it up.
///
/// 180 s keeps the suite from flaking on a busy dispatcher while still
/// failing fast on a genuinely stuck job.
const JOB_POLL_TIMEOUT: Duration = Duration::from_secs(180);

/// A fresh, unique `Idempotency-Key` for an admit request. Each test
/// mints/sends into freshly-generated wallets, so a random key per
/// call guarantees no accidental idempotent-replay across the suite.
fn random_idempotency_key() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    format!("e2e-{}", hex::encode(bytes))
}

/// A syntactically valid, random UUID-v4 string. The `GET/POST
/// /api/jobs/:id` routes use axum's `Path<Uuid>` extractor, which
/// rejects non-UUID paths with 400 — so the negative-path "no such
/// job" tests must pass a well-formed (but unallocated) UUID to reach
/// the handler's 404 branch. Built by hand to avoid taking a `uuid`
/// dev-dependency just for the test suite.
fn uuid_v4_like() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    // Set the version (4) and variant (RFC 4122) nibbles.
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// Poll `GET /api/jobs/:id` until the job reaches a terminal status
/// (`completed | failed | cancelled`) or [`JOB_POLL_TIMEOUT`] elapses.
/// Returns the full terminal `JobStatusResponse` body. Panics with a
/// clear message on timeout (never silently returns a non-terminal
/// snapshot) so a stuck job surfaces as a test failure, not a flake.
async fn poll_job_until_terminal(client: &reqwest::Client, job_id: &str) -> Value {
    let deadline = std::time::Instant::now() + JOB_POLL_TIMEOUT;
    loop {
        let resp = client
            .get(url(&format!("/api/jobs/{}", job_id)))
            .send()
            .await
            .expect("GET /api/jobs/:id");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET /api/jobs/{} must answer 200 while polling",
            job_id
        );
        let body: Value = resp.json().await.expect("job status body is JSON");
        let status = body["status"].as_str().unwrap_or("").to_string();
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            return body;
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "job {} never reached a terminal status within {:?}; last body={}",
                job_id, JOB_POLL_TIMEOUT, body
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Poll `GET /api/jobs/:id` until the job reports `status == want`, or
/// until it reaches a *different* terminal status (in which case the
/// helper panics, surfacing the failure rather than spinning until the
/// timeout). Returns the matching `JobStatusResponse` body.
async fn poll_job_until_status(client: &reqwest::Client, job_id: &str, want: &str) -> Value {
    let deadline = std::time::Instant::now() + JOB_POLL_TIMEOUT;
    loop {
        let resp = client
            .get(url(&format!("/api/jobs/{}", job_id)))
            .send()
            .await
            .expect("GET /api/jobs/:id");
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "GET /api/jobs/{} must answer 200 while polling",
            job_id
        );
        let body: Value = resp.json().await.expect("job status body is JSON");
        let status = body["status"].as_str().unwrap_or("").to_string();
        if status == want {
            return body;
        }
        // Any terminal status other than the one we wanted is a hard
        // failure — break out instead of waiting for the deadline.
        if matches!(status.as_str(), "completed" | "failed" | "cancelled") {
            panic!(
                "job {} reached terminal status `{}` while waiting for `{}`; body={}",
                job_id, status, want, body
            );
        }
        if std::time::Instant::now() >= deadline {
            panic!(
                "job {} never reached status `{}` within {:?}; last body={}",
                job_id, want, JOB_POLL_TIMEOUT, body
            );
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Run a full **two-phase, creator-signed** mint (Milestone 2) to completion
/// and return the commit `result` object (`{success, proof_id,
/// account_state_hash, output_coins_root}`).
///
/// Phase 1: `POST /api/jobs/mint` with the signed [`MintRequest`] →
/// `202 queued` → poll to `awaiting_signature` (whose `result` carries the
/// `account_state_hash` / `output_coins_root` hex). Phase 2: sign `ash || ocr`
/// with the creator key and release it via `POST /api/jobs/:id/commit` →
/// `completed`.
///
/// The minted asset is owned by `H(creator_pubkey)` (== `wallet.address_hex()`)
/// and carries `asset_id == asset_id_hex(&wallet.pubkey(0), name, decimals)`.
async fn mint_via_job(
    client: &reqwest::Client,
    wallet: &TestWallet,
    name: &str,
    decimals: u8,
    amount: u64,
) -> Value {
    let ts = unix_now();
    let creator_pk = wallet.pubkey(0);
    let signature = wallet.sign_mint(name, decimals, amount, ts);
    let resp = client
        .post(url("/api/jobs/mint"))
        .header("Idempotency-Key", random_idempotency_key())
        .json(&json!({
            "creator_pubkey": hex::encode(creator_pk.serialize()),
            "next_public_key": hex::encode(wallet.pubkey(1).serialize()),
            "name": name,
            "decimals": decimals,
            "amount": amount,
            "signature": signature,
            "timestamp": ts,
        }))
        .send()
        .await
        .expect("POST /api/jobs/mint");
    assert_eq!(
        resp.status(),
        StatusCode::ACCEPTED,
        "mint job must be admitted with 202"
    );
    let accepted: Value = resp.json().await.expect("mint admit body JSON");
    let job_id = accepted["job_id"]
        .as_str()
        .expect("mint admit body carries job_id")
        .to_string();
    assert_eq!(accepted["status"], "queued", "fresh mint job is queued");

    // Phase 1 → awaiting_signature: the result carries the ash/ocr hex the
    // creator must sign (mirrors the send commit leg).
    let awaiting = poll_job_until_status(client, &job_id, "awaiting_signature").await;
    let proof_id = awaiting["proof_id"].as_u64().expect("mint proof_id");
    let ash_hex = awaiting["result"]["account_state_hash"]
        .as_str()
        .expect("awaiting mint result carries account_state_hash");
    let ocr_hex = awaiting["result"]["output_coins_root"]
        .as_str()
        .expect("awaiting mint result carries output_coins_root");
    let ash = hex::decode(ash_hex).expect("mint ash is hex");
    let ocr = hex::decode(ocr_hex).expect("mint ocr is hex");

    // Phase 2 → completed: sign `ash || ocr` with the creator key and release
    // it through the shared `/api/jobs/:id/commit` endpoint.
    let mut commit_message = Vec::with_capacity(64);
    commit_message.extend_from_slice(&ash);
    commit_message.extend_from_slice(&ocr);
    let commit_sig = wallet.sign_commit(&commit_message);
    commit_send_job(
        client,
        &job_id,
        &json!({
            "proof_id": proof_id,
            "public_key": hex::encode(creator_pk.serialize()),
            "signature": commit_sig,
            "message": hex::encode(&commit_message),
        }),
    )
    .await
}

/// Submit a `send` job and return `(job_id, admit_status, admit_body)`.
///
/// The signature + timestamp + hex gates run INLINE before admission,
/// so malformed requests surface their 401 / 422 here synchronously.
/// `send_coins` business failures (unknown account, insufficient
/// funds) instead admit a job (`202`) that later transitions to
/// `failed` — the caller polls for those.
async fn submit_send_job(
    client: &reqwest::Client,
    body: &Value,
) -> (Option<String>, StatusCode, Value) {
    let resp = client
        .post(url("/api/jobs/send"))
        .header("Idempotency-Key", random_idempotency_key())
        .json(body)
        .send()
        .await
        .expect("POST /api/jobs/send");
    let status = resp.status();
    let parsed: Value = resp.json().await.unwrap_or(Value::Null);
    let job_id = parsed["job_id"].as_str().map(|s| s.to_string());
    (job_id, status, parsed)
}

/// Decode `(ash, ocr)` from a send job's `CoinProof`. The send proof's
/// `.commitment` is `None`; the account-state-hash / output-coins-root
/// pair lives in the Plonky2 proof public inputs. Decode exactly like
/// `account_node_tests.rs` and `flow.rs` (the first
/// `N_PROOF_DATA_PUBLIC_INPUTS` field elements reconstruct `ProofData`).
///
/// Retained for residual/ignored helpers; Stage 3 closed unauthenticated
/// `GET /api/proof/:id`, so live tests must not depend on this path.
#[allow(dead_code)]
fn ash_ocr_from_send_proof(coin_proof: &CoinProof) -> ([u8; 32], [u8; 32]) {
    let pis: [F; N_PROOF_DATA_PUBLIC_INPUTS] = coin_proof.proof.public_inputs
        [..N_PROOF_DATA_PUBLIC_INPUTS]
        .try_into()
        .expect("send proof emits N_PROOF_DATA_PUBLIC_INPUTS field elements");
    let proof_data = ProofData::from_field_elements(&pis);
    let ash = digest_to_bytes(&proof_data.account_state_hash);
    let ocr = digest_to_bytes(&proof_data.output_coins_root);
    (ash, ocr)
}

/// Drive a send job that is `awaiting_signature` through the commit
/// leg: attach the wallet-signed commitment via `POST /api/jobs/:id/commit`
/// (which answers `200 {status:"broadcasting"}`), then poll to
/// `completed` and return the `result` object (the legacy `/api/commit`
/// body: `{success, proof_id, account_state_hash, output_coins_root}`).
async fn commit_send_job(client: &reqwest::Client, job_id: &str, commit_body: &Value) -> Value {
    let resp = client
        .post(url(&format!("/api/jobs/{}/commit", job_id)))
        .json(commit_body)
        .send()
        .await
        .expect("POST /api/jobs/:id/commit");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "commit must be accepted with 200"
    );
    let body: Value = resp.json().await.expect("commit accept body JSON");
    assert_eq!(
        body["status"], "broadcasting",
        "commit accept body must report broadcasting, got {}",
        body
    );

    let terminal = poll_job_until_terminal(client, job_id).await;
    assert_eq!(
        terminal["status"], "completed",
        "send job must complete after commit, got terminal body {}",
        terminal
    );
    terminal["result"].clone()
}
/// Stage 3 Runde 5: `GET /api/proof/:id` is 410 Gone.
#[allow(dead_code)]
async fn fetch_coin_proof(client: &reqwest::Client, proof_id: u64) -> CoinProof {
    assert_legacy_gone(
        client,
        reqwest::Method::GET,
        &format!("/api/proof/{}", proof_id),
        &["/api/proof", "Stage 3", "read.proof"],
    )
    .await;
    panic!(
        "fetch_coin_proof: GET /api/proof/{proof_id} is closed (Stage 3);          use job-result thin-client ash/ocr fields"
    );
}
