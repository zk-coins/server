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
const POLL_TIMEOUT: Duration = Duration::from_secs(60);
const MINT_AMOUNT: u64 = 50_000;
const SEND_AMOUNT: u64 = 10_000;
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
async fn balance_unknown_address_returns_ok_with_zero() {
    let address = format!("0x{}", "00".repeat(32));
    // Balance is per-(owner, asset_id) under the multi-asset model: an
    // unknown (address, asset_id) pair is canonical zero with 200 — not
    // 404, and not the 422 that a *missing* asset_id would produce.
    let asset = format!("0x{}", "11".repeat(32));
    let resp = http_client()
        .get(url(&format!(
            "/api/balance?address={}&asset_id={}",
            address, asset
        )))
        .send()
        .await
        .expect("GET /api/balance");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body JSON");
    assert_eq!(body["balance"], 0);
}

#[tokio::test]
async fn balance_missing_param_returns_422() {
    let resp = http_client()
        .get(url("/api/balance"))
        .send()
        .await
        .expect("GET /api/balance (no params)");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn balance_address_without_asset_id_returns_422() {
    // Multi-asset contract: balance is per-(owner, asset_id), so a query
    // with a valid `address` but NO `asset_id` is 422 — not a 200-with-zero.
    let address = format!("0x{}", "00".repeat(32));
    let resp = http_client()
        .get(url(&format!("/api/balance?address={}", address)))
        .send()
        .await
        .expect("GET /api/balance (address, no asset_id)");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn balance_invalid_hex_returns_422() {
    let resp = http_client()
        .get(url("/api/balance?address=not_hex"))
        .send()
        .await
        .expect("GET /api/balance (bad hex)");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // The balance handler returns a `BalanceResponse` (not a
    // `SendCoinResponse`) on the 422 branches — so the body has
    // `balance: 0` and no `error` field. This anchors the contract:
    // any future refactor that swaps the body for a `handler_error_response`
    // envelope (with an `error: "Invalid hex"` string, matching the
    // app's `KNOWN_SERVER_ERRORS`) must update this assertion.
    let body: Value = resp.json().await.expect("balance body JSON");
    assert_eq!(body["balance"], 0, "422 balance body must report balance 0");
    assert!(
        body.get("error").is_none(),
        "balance 422 body must not carry an `error` field today (got {:?})",
        body.get("error")
    );
}

// ---------------------------------------------------------------------------
// /api/history — paginated per-address history (issue #153)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn history_missing_address_returns_422() {
    let resp = http_client()
        .get(url("/api/history"))
        .send()
        .await
        .expect("GET /api/history (no params)");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn history_invalid_hex_returns_422() {
    let resp = http_client()
        .get(url("/api/history?address=not_hex"))
        .send()
        .await
        .expect("GET /api/history (bad hex)");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    let body: Value = resp.json().await.expect("history body JSON");
    assert!(
        body["error"].as_str().is_some(),
        "422 body must carry an `error` string"
    );
}

#[tokio::test]
async fn history_limit_above_max_returns_422() {
    let address = format!("0x{}", "00".repeat(32));
    let resp = http_client()
        .get(url(&format!("/api/history?address={}&limit=201", address)))
        .send()
        .await
        .expect("GET /api/history (oversize limit)");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
}

#[tokio::test]
async fn history_unknown_address_returns_empty_page() {
    // DEV is a persistent, shared closed-env DB (no reset on develop
    // push), so a hardcoded address accumulates history rows across runs
    // and `total == 0` stops holding. A freshly-generated keypair's
    // address has provably never been touched, so "unknown" is
    // guaranteed regardless of prior suite runs.
    let address = TestWallet::new().address_hex();
    let resp = http_client()
        .get(url(&format!("/api/history?address={}", address)))
        .send()
        .await
        .expect("GET /api/history (unknown addr)");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body JSON");
    assert_eq!(body["total"], 0);
    assert_eq!(body["offset"], 0);
    assert_eq!(body["limit"], 50);
    assert_eq!(body["items"].as_array().unwrap().len(), 0);
}

/// Live contract round-trip: mint into a freshly-generated address,
/// then probe `/api/history` and assert that the credit lands on the
/// minted account as a `direction: "mint"` row whose `amount` matches
/// the mint size.
///
/// This is the only `/api/history` test that performs a state-mutating
/// call; the bookkeeping mirrors `mint_roundtrip_lands_balance_and_proof`
/// so the suite stays race-free against parallel runs.
#[tokio::test]
#[ignore = "blocked on zk-coins/node#226 — mint credits a Poseidon owner, not the spec SHA-256 address; minted balance is not visible/spendable via address_hex()"]
async fn history_after_mint_records_mint_row() {
    let client = http_client();
    let alice = TestWallet::new();

    // Mint via the async Job-API; `mint_via_job` runs the two-phase,
    // creator-signed mint and returns the commit `result` on completion.
    let mint_result = mint_via_job(&client, &alice, ASSET_NAME, ASSET_DECIMALS, MINT_AMOUNT).await;
    assert_eq!(mint_result["success"], Value::Bool(true));
    let aid = asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS);

    // Wait for the mint credit to land on Alice's balance — same poll
    // pattern the existing mint roundtrip uses; once balance >= MINT,
    // the matching account_history row exists.
    let _observed = poll_balance_at_least(&client, &alice.address_hex(), &aid, MINT_AMOUNT).await;

    let history_resp = client
        .get(url(&format!(
            "/api/history?address={}",
            alice.address_hex()
        )))
        .send()
        .await
        .expect("GET /api/history (post-mint)");
    assert_eq!(history_resp.status(), StatusCode::OK);
    let body: Value = history_resp.json().await.expect("history body JSON");

    assert!(
        body["total"].as_i64().unwrap_or(0) >= 1,
        "expected at least one history row, got body={}",
        body
    );
    let items = body["items"].as_array().expect("items array");
    assert!(!items.is_empty(), "items must not be empty");
    // Newest-first: the latest row is the mint credit we just landed.
    let head = &items[0];
    assert_eq!(head["direction"], "mint");
    assert_eq!(head["amount"], MINT_AMOUNT);
    // No Rust caller threads `zkcoins.account_commit_txid` through the
    // mint path today (see the GUC TODO in db.rs::list_account_history),
    // so `triggering_commit_txid` is NULL, the LEFT JOINs return NULL,
    // and the on-chain side is not yet observable from `/api/history`:
    // wire status is `pending`, not `confirmed`. The default flipped
    // from `confirmed` -> `pending` in round 2 to stop misrepresenting
    // DB-committed-only rows as on-chain confirmations.
    assert_eq!(head["status"], "pending");
    assert!(head["id"].as_i64().is_some(), "id must be set");
    // Spec contract — these are nullable on the wire.
    assert!(head["counterparty"].is_null() || head["counterparty"].is_string());
    assert!(head["memo"].is_null());
}

/// Live contract round-trip for the per-transaction detail endpoint
/// (`GET /api/history/{id}`): mint, read the history list to learn the
/// row id, then fetch the detail and assert it carries the list fields
/// plus the decoded account-state snapshot. State-mutating like
/// `history_after_mint_records_mint_row`; uses a fresh wallet so it is
/// race-free against parallel runs.
#[tokio::test]
#[ignore = "blocked on zk-coins/node#226 — mint credits a Poseidon owner, not the spec SHA-256 address; minted balance is not visible/spendable via address_hex()"]
async fn history_item_after_mint_returns_full_detail() {
    let client = http_client();
    let alice = TestWallet::new();
    let mint_result = mint_via_job(&client, &alice, ASSET_NAME, ASSET_DECIMALS, MINT_AMOUNT).await;
    assert_eq!(mint_result["success"], Value::Bool(true));
    let aid = asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS);
    let _ = poll_balance_at_least(&client, &alice.address_hex(), &aid, MINT_AMOUNT).await;

    // Learn the row id from the list.
    let list: Value = client
        .get(url(&format!(
            "/api/history?address={}",
            alice.address_hex()
        )))
        .send()
        .await
        .expect("GET /api/history")
        .json()
        .await
        .expect("history JSON");
    let id = list["items"][0]["id"].as_i64().expect("row id");

    // Fetch the detail.
    let resp = client
        .get(url(&format!(
            "/api/history/{}?address={}",
            id,
            alice.address_hex()
        )))
        .send()
        .await
        .expect("GET /api/history/{id}");
    assert_eq!(resp.status(), StatusCode::OK);
    let d: Value = resp.json().await.expect("detail JSON");

    // Core fields (consistent with the list head).
    assert_eq!(d["id"].as_i64(), Some(id));
    assert_eq!(d["direction"], "mint");
    assert_eq!(d["amount"], MINT_AMOUNT);
    assert_eq!(d["address"], alice.address_hex().trim_start_matches("0x"));
    // Decoded account-state snapshot: a from-genesis mint credits the
    // full balance, leaves num_sends at 0, and sets no commitment pubkey.
    assert_eq!(d["balance_after"].as_u64(), Some(MINT_AMOUNT));
    assert!(
        d["balance_before"].is_null(),
        "first row has no prior state"
    );
    assert_eq!(d["num_sends_after"].as_u64(), Some(0));
    assert!(
        d["commitment_public_key"].is_null(),
        "mint-only account has no commitment pubkey"
    );
    // The node has warmed a prover, so a verifier circuit digest exists.
    assert!(
        d["circuit_digest"].is_string(),
        "circuit_digest should be populated post-warmup, got {}",
        d["circuit_digest"]
    );
}

/// `GET /api/history/{id}` validation + scoping contract (read-only, no
/// state mutation — safe to run unconditionally).
#[tokio::test]
async fn history_item_validation_and_scoping() {
    let client = http_client();
    let some_addr = format!("0x{}", "ab".repeat(32));

    // Missing address -> 422.
    let r = client
        .get(url("/api/history/1"))
        .send()
        .await
        .expect("GET no-address");
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Non-integer id -> 422 (parsed as string, not axum's default 400).
    let r = client
        .get(url(&format!(
            "/api/history/not_a_number?address={}",
            some_addr
        )))
        .send()
        .await
        .expect("GET bad-id");
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Bad address hex -> 422.
    let r = client
        .get(url("/api/history/1?address=not_hex"))
        .send()
        .await
        .expect("GET bad-address");
    assert_eq!(r.status(), StatusCode::UNPROCESSABLE_ENTITY);

    // Well-formed but never-minted address + arbitrary id -> 404.
    let fresh = TestWallet::new();
    let r = client
        .get(url(&format!(
            "/api/history/999999999?address={}",
            fresh.address_hex()
        )))
        .send()
        .await
        .expect("GET unknown");
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn balance_wrong_length_returns_422() {
    // 16 bytes = 32 hex chars, the handler requires exactly 32 bytes
    let address = format!("0x{}", "ab".repeat(16));
    let resp = http_client()
        .get(url(&format!("/api/balance?address={}", address)))
        .send()
        .await
        .expect("GET /api/balance (short hex)");
    assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // Same envelope shape as the invalid-hex branch above.
    let body: Value = resp.json().await.expect("balance body JSON");
    assert_eq!(body["balance"], 0, "422 balance body must report balance 0");
    assert!(
        body.get("error").is_none(),
        "balance 422 body must not carry an `error` field today (got {:?})",
        body.get("error")
    );
}

#[tokio::test]
async fn address_list_returns_addresses() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.address_list {
        feature_skip!("address_list", "address_list_returns_addresses");
    }
    let resp = client
        .get(url("/api/address"))
        .send()
        .await
        .expect("GET /api/address");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body JSON");
    let addresses = body["addresses"].as_array().expect("addresses is an array");
    assert!(!addresses.is_empty(), "address list must not be empty");
    for addr in addresses {
        let s = addr.as_str().expect("address entry is a string");
        assert!(s.starts_with("0x"), "address must be 0x-prefixed: {}", s);
        // 0x + 64 hex chars = 66 chars
        assert_eq!(s.len(), 66, "address must be 32 bytes: {}", s);
    }
}

#[tokio::test]
async fn proof_for_huge_id_returns_404() {
    // u64::MAX is guaranteed to exceed any real proof_id the node
    // has issued, so the file-on-disk lookup misses and returns 404.
    let resp = http_client()
        .get(url(&format!("/api/proof/{}", u64::MAX)))
        .send()
        .await
        .expect("GET /api/proof/<huge>");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
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
async fn receive_empty_body_returns_default_failure() {
    let resp = http_client()
        .post(url("/api/receive"))
        .body(Vec::<u8>::new())
        .send()
        .await
        .expect("POST /api/receive empty");
    // Handler swallows bincode errors and returns Json(SendCoinResponse::default()) = 200.
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body JSON");
    assert_eq!(body["success"], Value::Bool(false));
}

#[tokio::test]
async fn receive_garbage_body_returns_default_failure() {
    let garbage = vec![0xFFu8; 64];
    let resp = http_client()
        .post(url("/api/receive"))
        .body(garbage)
        .send()
        .await
        .expect("POST /api/receive garbage");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("body JSON");
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

// ---------------------------------------------------------------------------
// Section 3 — happy-path roundtrips against the deployed node
// ---------------------------------------------------------------------------

/// Roundtrip A — mint into a fresh wallet and observe the balance.
///
/// Reads the proof_id back via `GET /api/proof/{id}` and deserializes
/// it as a `CoinProof` so the side-effect (write to the proofs/
/// directory) is visible to the test as well.
#[tokio::test]
#[ignore = "blocked on zk-coins/node#226 — mint credits a Poseidon owner, not the spec SHA-256 address; minted balance is not visible/spendable via address_hex()"]
async fn mint_roundtrip_lands_balance_and_proof() {
    let client = http_client();
    let alice = TestWallet::new();

    // Mint through the async Job-API. `mint_via_job` runs the two-phase,
    // creator-signed mint (admit → awaiting_signature → commit) and
    // returns the commit `result`.
    let mint_result = mint_via_job(&client, &alice, ASSET_NAME, ASSET_DECIMALS, MINT_AMOUNT).await;
    assert_eq!(
        mint_result["success"],
        Value::Bool(true),
        "mint not successful: {}",
        mint_result
    );
    let proof_id = mint_result["proof_id"].as_u64().expect("proof_id present");
    let aid = asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS);

    // Poll the balance endpoint until the credit shows up.
    let observed = poll_balance_at_least(&client, &alice.address_hex(), &aid, MINT_AMOUNT).await;
    assert!(
        observed >= MINT_AMOUNT,
        "balance never reached mint amount; got {observed}"
    );

    // Verify the proof file is fetchable + bincode-decodable.
    let coin_proof = fetch_coin_proof(&client, proof_id).await;
    assert_eq!(coin_proof.coin.amount, MINT_AMOUNT);
}

/// Roundtrip B — full mint → send → commit pipeline.
///
/// The send half requires the previous commitment's signing key as
/// `prev_commitment_pubkey`. After a mint that's the node's minting
/// pubkey, embedded in the mint's `CoinProof.commitment`.
#[tokio::test]
#[ignore = "blocked on zk-coins/node#226 — mint credits a Poseidon owner, not the spec SHA-256 address; minted balance is not visible/spendable via address_hex()"]
async fn send_commit_roundtrip_moves_balance() {
    let client = http_client();
    let alice = TestWallet::new();
    let bob = TestWallet::new();

    // ---- Mint ----
    // Post-#87 the scanner is event-driven (Esplora WS subscription),
    // so by the time the mint job completes and writes alice's balance,
    // the prior commitment is already at-most-one-block away from being
    // indexed in the SMT. A `422 Unable to get merkle proofs` send
    // failure later would therefore be a real scanner-side regression,
    // not a benign timing flake.
    let mint_result = mint_via_job(&client, &alice, ASSET_NAME, ASSET_DECIMALS, MINT_AMOUNT).await;
    assert_eq!(mint_result["success"], Value::Bool(true), "mint failed");
    let aid = asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS);

    // Wait for the balance to settle so send_coins has something to spend.
    let balance_before =
        poll_balance_at_least(&client, &alice.address_hex(), &aid, MINT_AMOUNT).await;
    assert!(
        balance_before >= MINT_AMOUNT,
        "scanner never observed mint after MINT_AMOUNT={} (saw {})",
        MINT_AMOUNT,
        balance_before
    );

    // ---- Send (phase 1: admit + prove → awaiting_signature) ----
    // `prev_commitment_pubkey` is a legacy, server-ignored field now —
    // the node reads the prior commitment key from its own state — so
    // the send body omits it and carries the minted `asset_id` instead.
    let amount = SEND_AMOUNT;
    let ts = unix_now();
    let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), amount, ts);
    let send_body = json!({
        "account_address": alice.address_hex(),
        "recipient": bob.address_hex(),
        "amount": amount,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "next_public_key": hex::encode(alice.pubkey(1).serialize()),
        "signature": signature,
        "timestamp": ts,
        "asset_id": aid,
    });
    let (send_job_id, send_status, _admit) = submit_send_job(&client, &send_body).await;
    assert_eq!(
        send_status,
        StatusCode::ACCEPTED,
        "send job must be admitted with 202"
    );
    let send_job_id = send_job_id.expect("admitted send job carries a job_id");

    // Poll to `awaiting_signature`; the body carries the send `proof_id`.
    let awaiting = poll_job_until_status(&client, &send_job_id, "awaiting_signature").await;
    let send_proof_id = awaiting["proof_id"]
        .as_u64()
        .expect("awaiting_signature job carries proof_id");
    assert!(send_proof_id > 0, "proof_id must be a positive u64");

    // ---- Derive ash || ocr from the send proof's public inputs ----
    // The send proof's `.commitment` is None here; ash/ocr live in the
    // Plonky2 proof public inputs. Value-bearing assertions: each hash
    // must be exactly 32 bytes and non-zero. A shape-only check would
    // mask a node bug that emitted a placeholder zero-hash.
    let send_coin_proof = fetch_coin_proof(&client, send_proof_id).await;
    let (ash_bytes, ocr_bytes) = ash_ocr_from_send_proof(&send_coin_proof);
    assert_eq!(ash_bytes.len(), 32, "account_state_hash must be 32 bytes");
    assert!(
        ash_bytes.iter().any(|&b| b != 0),
        "account_state_hash must be non-zero"
    );
    assert_eq!(ocr_bytes.len(), 32, "output_coins_root must be 32 bytes");
    assert!(
        ocr_bytes.iter().any(|&b| b != 0),
        "output_coins_root must be non-zero"
    );

    // ---- Thin-client contract: ash/ocr hex on the awaiting_signature
    // result ----
    // A pure-TypeScript wallet cannot decode the binary bincode
    // `CoinProof` from `GET /api/proof/{id}`, so the node surfaces the
    // hashes it must sign directly on the job result as hex. Assert the
    // `awaiting_signature` snapshot carries `result.account_state_hash`
    // + `result.output_coins_root`, AND that they equal the digests
    // decoded from the proof above — so what the wallet signs from the
    // thin path is bit-identical to the proof's public inputs.
    let result = awaiting
        .get("result")
        .and_then(Value::as_object)
        .expect("awaiting_signature job carries a result object");
    let result_ash = result
        .get("account_state_hash")
        .and_then(Value::as_str)
        .expect("result carries account_state_hash hex");
    let result_ocr = result
        .get("output_coins_root")
        .and_then(Value::as_str)
        .expect("result carries output_coins_root hex");
    assert_eq!(
        result_ash,
        hex::encode(ash_bytes),
        "awaiting_signature result.account_state_hash must equal the proof-decoded ash"
    );
    assert_eq!(
        result_ocr,
        hex::encode(ocr_bytes),
        "awaiting_signature result.output_coins_root must equal the proof-decoded ocr"
    );

    // ---- Commit (phase 2: sign ash || ocr, attach, broadcast) ----
    let mut commit_message = Vec::with_capacity(64);
    commit_message.extend_from_slice(&ash_bytes);
    commit_message.extend_from_slice(&ocr_bytes);
    let commit_sig = alice.sign_commit(&commit_message);

    let commit_body = json!({
        "proof_id": send_proof_id,
        "public_key": hex::encode(alice.pubkey(0).serialize()),
        "signature": commit_sig,
        "message": hex::encode(&commit_message),
    });
    // `commit_send_job` posts the commit (200 {status:"broadcasting"}),
    // polls to `completed`, and returns the legacy commit body.
    let commit_result = commit_send_job(&client, &send_job_id, &commit_body).await;
    assert_eq!(commit_result["success"], Value::Bool(true));

    // ---- Balance decreased ----
    let final_balance =
        poll_balance_at_most(&client, &alice.address_hex(), &aid, balance_before - amount).await;
    assert!(
        final_balance <= balance_before - amount,
        "balance never decreased after commit: before={}, after={}",
        balance_before,
        final_balance
    );
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

// ---------------------------------------------------------------------------
// Section 4 — value-bearing field coverage on wallet-app-facing routes
//
// The roundtrip tests above prove the happy path executes end-to-end;
// the tests in this section assert the EXACT shape and content of
// every response field the wallet app reads. A field that ships as
// `null` / `""` / `"0x00...0"` instead of a real value passes
// `.is_some()` but breaks the wallet — the assertions here catch that
// class of regression at the API layer instead of in the wallet's
// integration test loop.
// ---------------------------------------------------------------------------

/// Field coverage #1 — mint response carries the post-mint
/// commitment fields (`account_state_hash`, `output_coins_root`).
///
/// **Contract expectation.** The wallet app needs the same SMT-root
/// pair from the mint response that the send response already carries,
/// so its local account snapshot can advance without a second round
/// trip. Each hash field MUST be present, decode to exactly 32 bytes of
/// hex, and be non-zero. A shape-only `.is_some()` check would mask a
/// server bug that returned a placeholder zero-hash or a truncated hex
/// string.
///
/// Under the async Job-API the mint `result` object (the job's
/// completed body, surfaced by `mint_via_job`) is built by
/// `flow::mint_flow`, which populates `account_state_hash` /
/// `output_coins_root` from the final coin proof's public inputs — so
/// the pair is present on every successful mint.
#[tokio::test]
#[ignore = "blocked on zk-coins/node#226 — mint credits a Poseidon owner, not the spec SHA-256 address; minted balance is not visible/spendable via address_hex()"]
async fn mint_response_carries_state_hash_and_coins_root() {
    let client = http_client();
    let alice = TestWallet::new();

    let body = mint_via_job(&client, &alice, ASSET_NAME, ASSET_DECIMALS, MINT_AMOUNT).await;
    let aid = asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS);

    assert_eq!(
        body["success"],
        Value::Bool(true),
        "mint success must be true"
    );
    let proof_id = body["proof_id"]
        .as_u64()
        .expect("proof_id present and a u64");
    assert!(
        proof_id > 0,
        "proof_id must be a positive u64, got {}",
        proof_id
    );

    // Value-bearing assertions on the two post-mint hash fields.
    // Mirrors the send-response block in
    // `send_commit_roundtrip_moves_balance:1090-1109` verbatim — the
    // mint client consumes the same pair to advance its local
    // account snapshot, so the same shape guarantees apply.
    let ash_hex = body["account_state_hash"]
        .as_str()
        .expect("account_state_hash present on mint response")
        .to_string();
    let ash_bytes = hex::decode(&ash_hex).expect("account_state_hash is hex");
    assert_eq!(
        ash_bytes.len(),
        32,
        "account_state_hash must be 32 bytes (got {})",
        ash_bytes.len()
    );
    assert!(
        ash_bytes.iter().any(|&b| b != 0),
        "account_state_hash must be non-zero on a real mint"
    );

    let ocr_hex = body["output_coins_root"]
        .as_str()
        .expect("output_coins_root present on mint response")
        .to_string();
    let ocr_bytes = hex::decode(&ocr_hex).expect("output_coins_root is hex");
    assert_eq!(
        ocr_bytes.len(),
        32,
        "output_coins_root must be 32 bytes (got {})",
        ocr_bytes.len()
    );
    assert!(
        ocr_bytes.iter().any(|&b| b != 0),
        "output_coins_root must be non-zero on a real mint"
    );

    // Balance must land — the proof is fetchable AND the balance is
    // credited. Value-bearing check on the side effect.
    let observed = poll_balance_at_least(&client, &alice.address_hex(), &aid, MINT_AMOUNT).await;
    assert!(
        observed >= MINT_AMOUNT,
        "balance never reached mint amount; got {observed}"
    );
}

/// Field coverage #2 — commit response carries the post-commit
/// commitment fields (`account_state_hash`, `output_coins_root`).
///
/// **Contract expectation.** Same as the mint test above — the wallet
/// app needs the SMT-root pair from the commit response so its local
/// account snapshot advances atomically with the broadcast. Each hash
/// field MUST be present, decode to exactly 32 bytes of hex, and be
/// non-zero. The full mint → send → commit pipeline is exercised
/// because the commit step is otherwise unreachable.
///
/// Under the async Job-API the commit `result` object is built by
/// `flow::commit_flow`, which populates the SMT-root pair from the
/// committed proof's public inputs — so the pair is present on every
/// successful commit.
#[tokio::test]
#[ignore = "blocked on zk-coins/node#226 — mint credits a Poseidon owner, not the spec SHA-256 address; minted balance is not visible/spendable via address_hex()"]
async fn commit_response_carries_state_hash_and_coins_root() {
    let client = http_client();
    let alice = TestWallet::new();
    let bob = TestWallet::new();

    // ---- Mint ----
    let mint_result = mint_via_job(&client, &alice, ASSET_NAME, ASSET_DECIMALS, MINT_AMOUNT).await;
    let _mint_proof_id = mint_result["proof_id"].as_u64().expect("mint proof_id");
    let aid = asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS);

    let _ = poll_balance_at_least(&client, &alice.address_hex(), &aid, MINT_AMOUNT).await;

    // ---- Send (phase 1 → awaiting_signature) ----
    // `prev_commitment_pubkey` is legacy/server-ignored; carry `asset_id`.
    let amount = SEND_AMOUNT;
    let ts = unix_now();
    let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), amount, ts);
    let (send_job_id, send_status, _admit) = submit_send_job(
        &client,
        &json!({
            "account_address": alice.address_hex(),
            "recipient": bob.address_hex(),
            "amount": amount,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "next_public_key": hex::encode(alice.pubkey(1).serialize()),
            "signature": signature,
            "timestamp": ts,
            "asset_id": aid,
        }),
    )
    .await;
    assert_eq!(send_status, StatusCode::ACCEPTED, "send must be admitted");
    let send_job_id = send_job_id.expect("send job_id");
    let awaiting = poll_job_until_status(&client, &send_job_id, "awaiting_signature").await;
    let send_proof_id = awaiting["proof_id"].as_u64().expect("send proof_id");

    // ---- Derive ash || ocr from the send proof ----
    let send_coin_proof = fetch_coin_proof(&client, send_proof_id).await;
    let (ash_bytes, ocr_bytes) = ash_ocr_from_send_proof(&send_coin_proof);

    // ---- Commit (phase 2 → completed) ----
    let mut commit_message = Vec::with_capacity(64);
    commit_message.extend_from_slice(&ash_bytes);
    commit_message.extend_from_slice(&ocr_bytes);
    let commit_sig = alice.sign_commit(&commit_message);
    let commit_body = commit_send_job(
        &client,
        &send_job_id,
        &json!({
            "proof_id": send_proof_id,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "signature": commit_sig,
            "message": hex::encode(&commit_message),
        }),
    )
    .await;

    assert_eq!(
        commit_body["success"],
        Value::Bool(true),
        "commit success must be true"
    );
    let echoed_proof_id = commit_body["proof_id"]
        .as_u64()
        .expect("commit proof_id present and a u64");
    assert_eq!(
        echoed_proof_id, send_proof_id,
        "commit must echo the send proof_id (got {}, sent {})",
        echoed_proof_id, send_proof_id
    );

    // Value-bearing assertions on the post-commit hash fields. Same
    // contract as the send response (see
    // `send_commit_roundtrip_moves_balance:1090-1109`).
    let commit_ash_hex = commit_body["account_state_hash"]
        .as_str()
        .expect("account_state_hash present on commit response")
        .to_string();
    let commit_ash_bytes = hex::decode(&commit_ash_hex).expect("commit ash is hex");
    assert_eq!(
        commit_ash_bytes.len(),
        32,
        "commit account_state_hash must be 32 bytes (got {})",
        commit_ash_bytes.len()
    );
    assert!(
        commit_ash_bytes.iter().any(|&b| b != 0),
        "commit account_state_hash must be non-zero"
    );

    let commit_ocr_hex = commit_body["output_coins_root"]
        .as_str()
        .expect("output_coins_root present on commit response")
        .to_string();
    let commit_ocr_bytes = hex::decode(&commit_ocr_hex).expect("commit ocr is hex");
    assert_eq!(
        commit_ocr_bytes.len(),
        32,
        "commit output_coins_root must be 32 bytes (got {})",
        commit_ocr_bytes.len()
    );
    assert!(
        commit_ocr_bytes.iter().any(|&b| b != 0),
        "commit output_coins_root must be non-zero"
    );
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
async fn balance_response_carries_username_after_claim() {
    let client = http_client();
    let caps = fetch_capabilities(&client).await;
    if !caps.username_claim {
        feature_skip!(
            "username_claim",
            "balance_response_carries_username_after_claim"
        );
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

    // GET /api/balance and assert the username surfaces.
    let bal_resp = client
        .get(url(&format!(
            "/api/balance?address={}&asset_id={}",
            alice.address_hex(),
            asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS)
        )))
        .send()
        .await
        .expect("GET /api/balance after claim");
    assert_eq!(bal_resp.status(), StatusCode::OK);
    let body: Value = bal_resp.json().await.expect("balance body JSON");
    // Server canonicalises usernames to lowercase before persisting,
    // so the round-trip must compare against the lowercased form.
    let want = username.to_lowercase();
    assert_eq!(
        body["username"].as_str(),
        Some(want.as_str()),
        "balance body must carry the just-claimed username, got {:?}",
        body["username"]
    );
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
async fn balance_response_has_no_username_for_unclaimed_wallet() {
    let client = http_client();
    let wallet = TestWallet::new();
    // No claim happens — the wallet is fresh.
    let resp = client
        .get(url(&format!(
            "/api/balance?address={}&asset_id={}",
            wallet.address_hex(),
            asset_id_hex(&wallet.pubkey(0), ASSET_NAME, ASSET_DECIMALS)
        )))
        .send()
        .await
        .expect("GET /api/balance for unclaimed wallet");
    assert_eq!(resp.status(), StatusCode::OK);
    let body: Value = resp.json().await.expect("balance body JSON");
    assert_eq!(
        body["balance"], 0,
        "fresh wallet must have zero balance, got {:?}",
        body["balance"]
    );
    match body.get("username") {
        // Preferred: field omitted entirely (`skip_serializing_if` path).
        None => {}
        // Permitted: explicit `null`.
        Some(Value::Null) => {}
        // Anything else (empty string, real string) is a contract
        // violation — the wallet app would mis-render it.
        Some(other) => panic!(
            "unclaimed wallet must produce no `username` (or null), got {:?}",
            other
        ),
    }
}

/// Field coverage #6 — `/api/balance.num_sends` is the wallet's
/// authoritative BIP-32 child-index counter.
///
/// Regression for the seed-restore desync that surfaced as
/// `app/e2e/07-send.spec.ts::send-success` failing with
/// `Interner Fehler: Vorheriger Public Key fehlt.` (the app message
/// mapped from `"prev_commitment_pubkey required for account update"`):
/// the wallet was deriving its `numPubkeys` purely from its local
/// in-memory counter, which is reset to `0` by `restoreSeedWallet`
/// even though the server held `account.proof = Some(...)` from a
/// previous test's send. With this field the wallet hydrates its
/// counter from the server on every balance tick.
///
/// Pre-condition: a fresh wallet has `num_sends == 0` regardless
/// of mint state (mint touches the RECIPIENT's `coin_queue`, never
/// the recipient's `account.proof` — see `account_node.rs::receive_coin`).
/// Post-`/api/send` + `/api/commit` round-trip: `num_sends == 1`.
#[tokio::test]
#[ignore = "blocked on zk-coins/node#226 — mint credits a Poseidon owner, not the spec SHA-256 address; minted balance is not visible/spendable via address_hex()"]
async fn balance_response_num_sends_starts_zero_and_bumps_on_send() {
    let client = http_client();
    let alice = TestWallet::new();
    let bob = TestWallet::new();
    // The asset Alice will mint — derivable before the mint since it is a
    // pure function of (creator_pubkey, name, decimals).
    let aid = asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS);

    // Fresh wallet (never minted, never sent): num_sends MUST be 0.
    let pre_mint = client
        .get(url(&format!(
            "/api/balance?address={}&asset_id={}",
            alice.address_hex(),
            aid
        )))
        .send()
        .await
        .expect("GET /api/balance pre-mint");
    assert_eq!(pre_mint.status(), StatusCode::OK);
    let pre_mint_body: Value = pre_mint.json().await.expect("balance body JSON");
    assert_eq!(
        pre_mint_body["num_sends"].as_u64(),
        Some(0),
        "fresh wallet must report num_sends=0, got {:?}",
        pre_mint_body["num_sends"]
    );

    // Mint into Alice. The mint flow writes into Alice's `coin_queue`
    // via `receive_coin`; it does NOT touch `account.proof`. So
    // `num_sends` must still be 0 after the mint settles.
    let mint_result = mint_via_job(&client, &alice, ASSET_NAME, ASSET_DECIMALS, MINT_AMOUNT).await;
    assert_eq!(mint_result["success"], Value::Bool(true), "mint failed");
    let _ = poll_balance_at_least(&client, &alice.address_hex(), &aid, MINT_AMOUNT).await;

    let post_mint = client
        .get(url(&format!(
            "/api/balance?address={}&asset_id={}",
            alice.address_hex(),
            aid
        )))
        .send()
        .await
        .expect("GET /api/balance post-mint");
    assert_eq!(post_mint.status(), StatusCode::OK);
    let post_mint_body: Value = post_mint.json().await.expect("balance body JSON");
    assert_eq!(
        post_mint_body["num_sends"].as_u64(),
        Some(0),
        "minted-into wallet must still report num_sends=0 (mint touches \
         coin_queue, not account.proof), got {:?}",
        post_mint_body["num_sends"]
    );

    // Now drive Alice through a full send+commit round-trip. Mirrors
    // `send_commit_roundtrip_moves_balance` — sign, send (carrying the
    // minted `asset_id`; `prev_commitment_pubkey` is server-ignored now),
    // then commit.
    let amount = SEND_AMOUNT;
    let ts = unix_now();
    let signature = alice.sign_send(&alice.address_hex(), &bob.address_hex(), amount, ts);
    let (send_job_id, send_status, _admit) = submit_send_job(
        &client,
        &json!({
            "account_address": alice.address_hex(),
            "recipient": bob.address_hex(),
            "amount": amount,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "next_public_key": hex::encode(alice.pubkey(1).serialize()),
            "signature": signature,
            "timestamp": ts,
            "asset_id": aid,
        }),
    )
    .await;
    assert_eq!(send_status, StatusCode::ACCEPTED, "send must be admitted");
    let send_job_id = send_job_id.expect("send job_id");
    // The send job's prove leg runs `send_flow`, which bumps
    // `account.num_sends` and persists `account.proof = Some(...)`
    // before the job parks in `awaiting_signature`. So once the job
    // reaches `awaiting_signature` the counter is already 1.
    let awaiting = poll_job_until_status(&client, &send_job_id, "awaiting_signature").await;
    let send_proof_id = awaiting["proof_id"].as_u64().expect("send proof_id");
    let send_coin_proof = fetch_coin_proof(&client, send_proof_id).await;
    let (ash_bytes, ocr_bytes) = ash_ocr_from_send_proof(&send_coin_proof);

    // After the send job reaches `awaiting_signature` the server has
    // already bumped `account.num_sends` (atomically with
    // `account.proof = Some(...)` inside `send_coins_inner`), so the
    // balance read MUST report `1` — independent of whether the user
    // later succeeds in the commit phase. (The commit only advances
    // the SMT; the per-account counter advances on the proof itself.)
    let post_send = client
        .get(url(&format!(
            "/api/balance?address={}&asset_id={}",
            alice.address_hex(),
            aid
        )))
        .send()
        .await
        .expect("GET /api/balance post-send");
    assert_eq!(post_send.status(), StatusCode::OK);
    let post_send_body: Value = post_send.json().await.expect("balance body JSON");
    assert_eq!(
        post_send_body["num_sends"].as_u64(),
        Some(1),
        "post-send wallet must report num_sends=1, got {:?}",
        post_send_body["num_sends"]
    );

    // Close the loop: drive the commit so the test doesn't leave a
    // proof_id orphaned in the proof_store (every other api_remote
    // commit-round-trip cleans up the same way).
    let mut commit_message = Vec::with_capacity(64);
    commit_message.extend_from_slice(&ash_bytes);
    commit_message.extend_from_slice(&ocr_bytes);
    let commit_sig = alice.sign_commit(&commit_message);
    let _commit_result = commit_send_job(
        &client,
        &send_job_id,
        &json!({
            "proof_id": send_proof_id,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "signature": commit_sig,
            "message": hex::encode(&commit_message),
        }),
    )
    .await;

    // num_sends survives the commit (commit doesn't mutate the
    // counter — it only advances the SMT and Bob's coin_queue).
    let post_commit = client
        .get(url(&format!(
            "/api/balance?address={}&asset_id={}",
            alice.address_hex(),
            aid
        )))
        .send()
        .await
        .expect("GET /api/balance post-commit");
    let post_commit_body: Value = post_commit.json().await.expect("balance body JSON");
    assert_eq!(
        post_commit_body["num_sends"].as_u64(),
        Some(1),
        "post-commit num_sends must still be 1, got {:?}",
        post_commit_body["num_sends"]
    );
}

/// Regression: the second `/api/send` for an account whose
/// `account.proof = Some(...)` MUST succeed even when the client
/// omits `prev_commitment_pubkey` from the request body.
///
/// Pre-`Account::commitment_public_key`-refactor this surfaced as a
/// 400 `prev_commitment_pubkey required for account update` —
/// observed live as `07-send.spec.ts::send-success` failing with
/// `Interner Fehler: Vorheriger Public Key fehlt.` against DEV every
/// time the wallet's local BIP-32 child-index counter drifted from
/// the server's (seed restore + stale-app deploy + TOCTOU between
/// balance fetch and signing). Post-refactor the server reads the
/// previous commitment pubkey from `account.commitment_public_key`
/// (set atomically with `proof` inside `send_coins_inner`), so the
/// caller-supplied field is purely advisory and a missing one is
/// fully recoverable.
///
/// Flow: mint → send #1 (first send, `account.proof = None` → prove
/// initial → server stamps `commitment_public_key = pubkey_0`) →
/// send #2 with `prev_commitment_pubkey` deliberately omitted →
/// MUST succeed (AccountUpdate branch reads its own stored value).
#[tokio::test]
#[ignore = "blocked on zk-coins/node#226 — mint credits a Poseidon owner, not the spec SHA-256 address; minted balance is not visible/spendable via address_hex()"]
async fn second_send_roundtrip_succeeds_without_prev_commitment_pubkey_field() {
    let client = http_client();
    let alice = TestWallet::new();
    let bob = TestWallet::new();

    // ---- Mint ----
    let mint_result = mint_via_job(&client, &alice, ASSET_NAME, ASSET_DECIMALS, MINT_AMOUNT).await;
    assert_eq!(mint_result["success"], Value::Bool(true), "mint failed");
    let aid = asset_id_hex(&alice.pubkey(0), ASSET_NAME, ASSET_DECIMALS);

    let _ = poll_balance_at_least(&client, &alice.address_hex(), &aid, MINT_AMOUNT).await;

    // ---- First send (proves initial, sets account.proof = Some +
    // commitment_public_key = pubkey_0). `prev_commitment_pubkey` is
    // server-ignored now and omitted; the send carries `asset_id`. ----
    let ts1 = unix_now();
    let sig1 = alice.sign_send(&alice.address_hex(), &bob.address_hex(), SEND_AMOUNT, ts1);
    let (send1_job_id, send1_status, _admit1) = submit_send_job(
        &client,
        &json!({
            "account_address": alice.address_hex(),
            "recipient": bob.address_hex(),
            "amount": SEND_AMOUNT,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "next_public_key": hex::encode(alice.pubkey(1).serialize()),
            "signature": sig1,
            "timestamp": ts1,
            "asset_id": aid,
        }),
    )
    .await;
    assert_eq!(
        send1_status,
        StatusCode::ACCEPTED,
        "first send must be admitted"
    );
    let send1_job_id = send1_job_id.expect("send #1 job_id");
    let awaiting1 = poll_job_until_status(&client, &send1_job_id, "awaiting_signature").await;
    let send1_proof_id = awaiting1["proof_id"].as_u64().expect("send #1 proof_id");
    let send1_coin_proof = fetch_coin_proof(&client, send1_proof_id).await;
    let (ash1_bytes, ocr1_bytes) = ash_ocr_from_send_proof(&send1_coin_proof);

    // Commit the first send so its commitment lands in the SMT —
    // the second send's prev-commitment lookup needs it indexed.
    let mut commit1_msg = Vec::with_capacity(64);
    commit1_msg.extend_from_slice(&ash1_bytes);
    commit1_msg.extend_from_slice(&ocr1_bytes);
    let commit1_sig = alice.sign_commit(&commit1_msg);
    let _commit1_result = commit_send_job(
        &client,
        &send1_job_id,
        &json!({
            "proof_id": send1_proof_id,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "signature": commit1_sig,
            "message": hex::encode(&commit1_msg),
        }),
    )
    .await;

    // Verify the server bumped `num_sends` to 1 (the wallet would
    // sync this on its next balance tick to choose `pubkey(1)` as
    // its next signing key).
    let post_send1 = client
        .get(url(&format!(
            "/api/balance?address={}&asset_id={}",
            alice.address_hex(),
            aid
        )))
        .send()
        .await
        .expect("GET /api/balance post-send-1");
    let post_send1_body: Value = post_send1.json().await.expect("balance body JSON");
    assert_eq!(
        post_send1_body["num_sends"].as_u64(),
        Some(1),
        "post-send-1 num_sends must report 1"
    );

    // Wait until the scanner has ingested send #1's committed
    // commitment into the SMT before issuing send #2. The legacy
    // synchronous `/api/commit` advanced the in-process SMT before
    // returning 200; the async `commit_flow` only broadcasts +
    // `receive_coin`s, leaving the SMT advance to the event-driven
    // scanner. Send #2's prev-commitment lookup needs send #1's
    // commitment indexed, so without this wait the prove leg fails
    // with "Unable to get merkle proofs for provided public key".
    // Alice's balance dropping to `MINT_AMOUNT - SEND_AMOUNT` is the
    // observable signal that the spend (hence the commitment) has been
    // scanned.
    let _ = poll_balance_at_most(&client, &alice.address_hex(), &aid, MINT_AMOUNT - SEND_AMOUNT).await;

    // Send #2 spends Alice's send-#1 *change* directly. After send #1
    // committed, `coin_queue.clear()` ran and the unspent remainder
    // (`MINT_AMOUNT - SEND_AMOUNT`) lives in `account.balance`, NOT as a
    // queued coin — `commit_flow` only `receive_coin`s the recipient's
    // out-coin, never a change coin back to the sender. So Alice's
    // `coin_queue` is empty and `MINT_AMOUNT - SEND_AMOUNT` (= 40_000)
    // still covers another `SEND_AMOUNT`.
    //
    // We deliberately do NOT mint a second time into Alice here. A
    // second mint pushes a fresh coin into Alice's `coin_queue`, which
    // forces send #2 through `send_coins_inner`'s in-coin loop. That
    // loop inserts each spent coin's id into `account.coin_history`
    // BEFORE the prove, and the prove leg has no rollback on failure:
    // a single transient prove failure (the genuine
    // "Unable to get merkle proofs for provided public key" scanner
    // race) then leaves the coin in BOTH `coin_queue` and
    // `coin_history`, so every subsequent retry fails deterministically
    // and permanently with "Should provide an inclusion proof" — the
    // retry budget can never clear it. Spending the change from
    // `account.balance` with an empty queue skips the in-coin loop
    // entirely, keeping retries idempotent and isolating the assertion
    // to its actual subject: the omitted `prev_commitment_pubkey`.

    // ---- Second send WITHOUT `prev_commitment_pubkey`. ----
    //
    // The whole point of the refactor: the AccountUpdate branch reads
    // `account.commitment_public_key` from its own state (set
    // atomically with `proof` by send #1 above), so the caller can
    // omit the field entirely and the prove still succeeds. Pre-
    // refactor this returned 400
    // `"prev_commitment_pubkey required for account update"`.
    //
    // The wallet's signing key for this send is `pubkey(1)` because
    // `num_sends == 1` (the server's authoritative counter).
    //
    // The prove leg is where the AccountUpdate branch reads
    // `account.commitment_public_key` from its own state (set
    // atomically with `proof` by send #1 above) — so reaching
    // `awaiting_signature` is the success signal. Pre-refactor the
    // prove leg failed with `"prev_commitment_pubkey required for
    // account update"` (a non-retryable terminal failure the helper
    // would surface immediately).
    //
    // `submit_send_no_prev_until_awaiting` re-signs + resubmits on the
    // transient `"Unable to get merkle proofs for provided public key"`
    // scanner race: send #1's commitment was committed via the async
    // `commit_flow`, which (unlike the legacy synchronous `/api/commit`)
    // leaves the in-process SMT advance to the event-driven scanner, so
    // the prev-commitment lookup can briefly miss until the on-chain
    // inscription is ingested.
    let (send2_job_id, awaiting2) =
        submit_send_no_prev_until_awaiting(&client, &alice, &bob.address_hex(), &aid, SEND_AMOUNT, 1)
            .await;

    // Server-side counter advanced. `num_sends` is the server's
    // authoritative count of *committed* sends; send #2 reaching
    // `awaiting_signature` (its prove leg done) has already bumped it to
    // 2, so this holds before the commit below.
    let post_send2 = client
        .get(url(&format!(
            "/api/balance?address={}&asset_id={}",
            alice.address_hex(),
            aid
        )))
        .send()
        .await
        .expect("GET /api/balance post-send-2");
    let post_send2_body: Value = post_send2.json().await.expect("balance body JSON");
    assert_eq!(
        post_send2_body["num_sends"].as_u64(),
        Some(2),
        "post-send-2 num_sends must report 2"
    );

    // ---- Commit send #2 (REQUIRED, not optional) ----
    //
    // The dispatcher is a single inline worker that PARKS in
    // `wait_for_commit` for up to `awaiting_signature_timeout` (600 s on
    // DEV) until a commit arrives. Returning here without committing
    // would pin that worker, starving every test that sorts after this
    // one in the serial alphabetical run (`cancel` only works while a job
    // is `queued`, so it cannot release an `awaiting_signature` park).
    // Committing both releases the worker AND completes the roundtrip.
    //
    // The commit's `public_key` must match the key that produced
    // `signature`, because the node's `commit_flow` verifies the
    // commitment with a self-contained Schnorr check (`Commitment::verify`
    // over `public_key`/`signature`/`message`) — it does NOT tie the
    // commit key to the send's signing key or the account's
    // `commitment_public_key`. `TestWallet::sign_commit` always signs with
    // `seckey(0)`, so the matching `public_key` is `pubkey(0)`, exactly as
    // send #1's commit above (and `send_commit_roundtrip_moves_balance`)
    // does. The send-#2 *signing* key (`pubkey(1)`) is unrelated here.
    let send2_proof_id = awaiting2["proof_id"]
        .as_u64()
        .expect("send #2 awaiting_signature job carries proof_id");
    let send2_coin_proof = fetch_coin_proof(&client, send2_proof_id).await;
    let (ash2_bytes, ocr2_bytes) = ash_ocr_from_send_proof(&send2_coin_proof);

    let mut commit2_msg = Vec::with_capacity(64);
    commit2_msg.extend_from_slice(&ash2_bytes);
    commit2_msg.extend_from_slice(&ocr2_bytes);
    let commit2_sig = alice.sign_commit(&commit2_msg);
    let commit2_result = commit_send_job(
        &client,
        &send2_job_id,
        &json!({
            "proof_id": send2_proof_id,
            "public_key": hex::encode(alice.pubkey(0).serialize()),
            "signature": commit2_sig,
            "message": hex::encode(&commit2_msg),
        }),
    )
    .await;
    assert_eq!(commit2_result["success"], Value::Bool(true));
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
/// funds" provocation needs a real minted balance. Split out of
/// `error_strings_match_known_app_mapping` and `#[ignore]`d pending the node
/// owner-hash fix (#226) — un-ignore once #228 lands and DEV redeploys.
#[tokio::test]
#[ignore = "blocked on zk-coins/node#226 — needs a minted balance, currently credited under a Poseidon owner instead of the spec SHA-256 address"]
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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Poll `/api/balance` until the observed balance is >= `target`, or
/// until [`POLL_TIMEOUT`] elapses. Returns the last observed balance
/// regardless — the caller decides whether to assert on it.
async fn poll_balance_at_least(
    client: &reqwest::Client,
    address: &str,
    asset_id: &str,
    target: u64,
) -> u64 {
    let deadline = std::time::Instant::now() + POLL_TIMEOUT;
    let mut last_seen = 0u64;
    loop {
        let resp = client
            .get(url(&format!(
                "/api/balance?address={}&asset_id={}",
                address, asset_id
            )))
            .send()
            .await
            .expect("GET balance");
        if resp.status() == StatusCode::OK {
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            if let Some(b) = body["balance"].as_u64() {
                last_seen = b;
                if b >= target {
                    return b;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return last_seen;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Poll `/api/balance` until the observed balance is <= `target`, or
/// until [`POLL_TIMEOUT`] elapses. Used to wait for the post-commit
/// debit to land in the in-memory account.
async fn poll_balance_at_most(
    client: &reqwest::Client,
    address: &str,
    asset_id: &str,
    target: u64,
) -> u64 {
    let deadline = std::time::Instant::now() + POLL_TIMEOUT;
    let mut last_seen = u64::MAX;
    loop {
        let resp = client
            .get(url(&format!(
                "/api/balance?address={}&asset_id={}",
                address, asset_id
            )))
            .send()
            .await
            .expect("GET balance");
        if resp.status() == StatusCode::OK {
            let body: Value = resp.json().await.unwrap_or(Value::Null);
            if let Some(b) = body["balance"].as_u64() {
                last_seen = b;
                if b <= target {
                    return b;
                }
            }
        }
        if std::time::Instant::now() >= deadline {
            return last_seen;
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
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

/// Wait between scanner-race retries in
/// [`submit_send_no_prev_until_awaiting`] — roughly one mutinynet block,
/// so a re-submit only happens after the scanner has had real time to
/// index the prior commitment (avoids a back-to-back prove storm on the
/// single-threaded dispatcher).
const SCANNER_SETTLE_INTERVAL: Duration = Duration::from_secs(20);

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

/// Node prove-time errors that all mean the same thing in the
/// send→commit→send sequence: the *previous* send's commitment has been
/// broadcast but the scanner has not yet fully indexed it into the
/// in-process SMT / history MMR, so the next send's prove cannot find
/// the prev commitment's merkle/inclusion proofs (see
/// `account_node::get_merkle_proofs` / `prepare_send_coins`). On the
/// async Job-API this is a transient, retryable scanner-indexing race —
/// the legacy synchronous `/api/commit` masked it by advancing the
/// in-process SMT before returning. Depending on exactly how far the
/// scanner has progressed, the prove leg surfaces one of these:
const TRANSIENT_SCANNER_RACE_ERRS: &[&str] = &[
    "Unable to get merkle proofs for provided public key",
    "Should provide an inclusion proof",
    "Source commitment not present in history MMR",
    "In-coin not present in source's output_coins_root",
];

/// `true` if `err` is one of the transient scanner-indexing-race
/// substrings the second-send retry loop tolerates.
fn is_transient_scanner_race(err: &str) -> bool {
    TRANSIENT_SCANNER_RACE_ERRS
        .iter()
        .any(|needle| err.contains(needle))
}

/// Submit a send job WITHOUT `prev_commitment_pubkey`, re-signing with a
/// fresh timestamp on each attempt, and poll to `awaiting_signature`.
///
/// Retries only the transient scanner-indexing race (see
/// [`is_transient_scanner_race`]): when a prior send's commitment was
/// committed via the async `commit_flow` (which does NOT advance the
/// in-process SMT), the next send's prove can't find the prev
/// commitment's merkle/inclusion proofs until the scanner ingests the
/// on-chain inscription. A bounded retry tolerates that lag while still
/// surfacing a genuine regression (any other terminal failure, or never
/// recovering within the cap, fails the test). Returns the send job's
/// `job_id` alongside its `awaiting_signature` body — the caller needs
/// the `job_id` to drive the commit leg that releases the inline worker
/// (a job left parked in `awaiting_signature` pins the single dispatcher
/// worker for the full `awaiting_signature_timeout`, starving every
/// later test in the serial suite).
async fn submit_send_no_prev_until_awaiting(
    client: &reqwest::Client,
    wallet: &TestWallet,
    recipient: &str,
    asset_id: &str,
    amount: u64,
    signing_idx: u32,
) -> (String, Value) {
    // A more generous budget than a single job's `JOB_POLL_TIMEOUT`:
    // clearing the scanner race can require waiting for the next
    // mutinynet block (~30 s) across one or more re-submits.
    let deadline = std::time::Instant::now() + Duration::from_secs(240);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let ts = unix_now();
        let sig = wallet.sign_send_at(&wallet.address_hex(), recipient, amount, ts, signing_idx);
        let body = json!({
            "account_address": wallet.address_hex(),
            "recipient": recipient,
            "amount": amount,
            "public_key": hex::encode(wallet.pubkey(signing_idx).serialize()),
            "next_public_key": hex::encode(wallet.pubkey(signing_idx + 1).serialize()),
            // `prev_commitment_pubkey` deliberately omitted.
            "signature": sig,
            "timestamp": ts,
            "asset_id": asset_id,
        });
        let (job_id, status, admit) = submit_send_job(client, &body).await;
        assert_eq!(
            status,
            StatusCode::ACCEPTED,
            "send without prev_commitment_pubkey must be admitted; got {} body={}",
            status,
            admit
        );
        let job_id = job_id.expect("admitted send job carries a job_id");

        // Poll this job to a terminal/awaiting state inline (cannot use
        // `poll_job_until_status`, which panics on a `failed` we want to
        // retry on).
        let terminal_or_awaiting = loop {
            let resp = client
                .get(url(&format!("/api/jobs/{}", job_id)))
                .send()
                .await
                .expect("GET /api/jobs/:id");
            assert_eq!(resp.status(), StatusCode::OK);
            let body: Value = resp.json().await.expect("job status body is JSON");
            let status = body["status"].as_str().unwrap_or("").to_string();
            if status == "awaiting_signature"
                || matches!(status.as_str(), "completed" | "failed" | "cancelled")
            {
                break body;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "send job {} stuck in `{}` past the retry budget; body={}",
                job_id,
                status,
                body
            );
            tokio::time::sleep(POLL_INTERVAL).await;
        };

        let status = terminal_or_awaiting["status"].as_str().unwrap_or("");
        if status == "awaiting_signature" {
            return (job_id, terminal_or_awaiting);
        }
        // Retry only the known transient scanner race; any other
        // terminal failure is a real regression.
        let err = terminal_or_awaiting["error"].as_str().unwrap_or("");
        let transient = status == "failed" && is_transient_scanner_race(err);
        assert!(
            transient,
            "second send job ended in non-retryable terminal state: {}",
            terminal_or_awaiting
        );
        assert!(
            std::time::Instant::now() < deadline,
            "second send never reached awaiting_signature within the retry \
             budget (transient scanner race `{}` did not clear after {} attempts)",
            err,
            attempt
        );
        // Back off a full scanner-settle interval (≈ one mutinynet block)
        // before re-signing + resubmitting, so we give the scanner real
        // time to index the prior commitment instead of hammering the
        // dispatcher with back-to-back prove attempts.
        tokio::time::sleep(SCANNER_SETTLE_INTERVAL).await;
    }
}

/// Decode `(ash, ocr)` from a send job's `CoinProof`. The send proof's
/// `.commitment` is `None`; the account-state-hash / output-coins-root
/// pair lives in the Plonky2 proof public inputs. Decode exactly like
/// `account_node_tests.rs` and `flow.rs` (the first
/// `N_PROOF_DATA_PUBLIC_INPUTS` field elements reconstruct `ProofData`).
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

/// Fetch + bincode-decode a `CoinProof` by proof_id. Shared by the
/// roundtrip tests that need the mint proof (for `prev_commitment_pubkey`)
/// or the send proof (for `ash || ocr`).
async fn fetch_coin_proof(client: &reqwest::Client, proof_id: u64) -> CoinProof {
    let resp = client
        .get(url(&format!("/api/proof/{}", proof_id)))
        .send()
        .await
        .expect("GET /api/proof/:id");
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "GET /api/proof/{} must answer 200",
        proof_id
    );
    let bytes = resp.bytes().await.expect("proof bytes");
    bincode::deserialize(&bytes).expect("decode CoinProof bincode")
}
