//! Library crate root for `node`.
//!
//! The node is primarily a binary (`main.rs`), but a few pieces of
//! it must be reachable from out-of-tree integration tests
//! (`node/tests/api_remote.rs` in particular). Exposing those
//! modules through a `lib` target keeps the binary side of the crate
//! untouched while letting the integration suite import the
//! `Capabilities` struct (for feature-gate detection on `/api/info`)
//! and the `CoinProof` struct used to decode the binary blobs
//! returned by `GET /api/proof/:id`. Other response types remain
//! reachable through their owning modules but are not currently
//! consumed by the suite.
//!
//! Everything declared here is also `use`d from `main.rs` so the
//! production binary keeps working with no change in behaviour.

// Opt in to the unstable `coverage_attribute` feature only when
// `cargo llvm-cov` defines the `coverage_nightly` cfg (it injects the
// flag automatically on a nightly toolchain). The `coverage(off)`
// annotations on the platform-`_impl` helpers in `r2_probe.rs` rely on
// this feature being enabled; the same pattern is used in
// `program-plonky2/src/lib.rs` and `script-plonky2/src/lib.rs`. Without
// the cfg gate the stable toolchain would refuse to compile the crate.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// `Account::new()` and `State::new()` are visible from the lib root
// after the binary → bin+lib split. Clippy's `new_without_default`
// lint did not fire while these types lived in a `bin` target — the
// lint is library-target sensitive. Adding `Default` impls would
// change the public API of the crate (downstream callers could pick
// `Default::default()` over `::new()`), which is out of scope for
// this refactor. Suppress at the crate root so the lint stays off
// for the new lib target while the existing call sites stay
// untouched.
#![allow(clippy::new_without_default)]

pub mod account_node;
pub mod audit;
pub mod db;
/// Node-side Esplora boundary: re-exports the `esplora-bound` facade
/// (sole owner of `esplora-client`) and stack-gates legacy broadcast.
pub mod esplora_bound;
pub mod flow;
pub mod job_dispatcher;
pub mod job_store;
pub mod openapi;
pub mod prover_health;
pub mod publisher;
pub mod r2_budgets;
pub mod r2_probe;
pub mod router;
pub mod runtime;
pub mod scanner;
pub mod scanner_runtime;
pub mod scanner_ws;
pub mod scanner_ws_parse;
pub mod self_heal;
pub mod state;
pub mod username;
/// v1.1 StateEngine adapter, shadow persistence (Stage 1), and exclusive
/// publisher/scanner dual stack (Stage 2). Behind `ZKCOINS_V11_SHADOW=1`;
/// default remains the legacy Commitment/SMT stack. Proving stays legacy
/// until Stage 3.
pub mod v11;

use crate::publisher::EsploraConfig;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use lazy_static::lazy_static;
use sqlx::PgPool;
use std::str::FromStr;
use zkcoins_program::hash::HashDigest;

/// Pure builder for `NETWORK_CONFIG`. Extracted so the env-resolution
/// logic — in particular the panic-on-missing rules below — is
/// unit-testable without touching the process-wide environment or the
/// `lazy_static` cell (whose state would leak across tests in the same
/// binary).
///
/// ## No silent chain defaults
///
/// Three env vars shape the chain the node binds to:
///
/// - `IS_MAINNET` (`true` | `false`)
/// - `ESPLORA_URL` (HTTP Esplora endpoint)
/// - `ESPLORA_WS_URL` (mempool.space-compatible WS endpoint)
///
/// All three are **required, with no default** — the builder panics if
/// any one is missing or empty. This matches the existing pattern for
/// `PUBLISHER_KEY`, `USERNAME_DOMAIN`, and `DATABASE_URL`, and exists
/// because the previous "default to Mutinynet" fallbacks created two
/// distinct silent footguns:
///
/// 1. A Mainnet deployment that forgot `ESPLORA_URL` / `ESPLORA_WS_URL`
///    would silently scan Mutinynet and answer `/api/info` as Mainnet —
///    visible only as a 5 s HTTP-retry loop on `scanner_runtime` with a
///    green `/health/ready` (zk-coins/node #84).
/// 2. A Mutinynet deployment that left `ESPLORA_WS_URL` unset would
///    couple itself to the public `wss://mutinynet.com/api/v1/ws`
///    endpoint we do not operate — DEV's entire WS observability would
///    hang on a third-party host going offline.
///
/// Removing the defaults closes both. Every stage (PRD, DEV,
/// integration tests, the local dev loop, self-hosters) must state
/// explicitly which chain it serves and which endpoints it reaches.
///
/// `IS_MAINNET` accepts only the exact strings `"true"` or `"false"`;
/// anything else panics. This prevents the historical class of
/// "I typed `1`, `TRUE`, or `yes`, it was silently treated as Mutinynet"
/// bugs.
///
/// Empty-string values (`ESPLORA_URL=` in a compose file) are treated
/// as unset so they panic with the same diagnostic instead of
/// silently producing `EsploraConfig.url = ""`.
///
/// `NETWORK_NAME` remains a derived label for `/api/info` only — it
/// has no behavioural effect on the scanner, publisher, or address
/// derivation, so it keeps a default of `"Mainnet"` / `"Mutinynet"`
/// derived from `IS_MAINNET`.
///
/// ## Single source of truth
///
/// `NETWORK_CONFIG.url` and `NETWORK_CONFIG.ws_url` are the only
/// places these endpoints are read. `scanner_ws::ScannerWsConfig` is
/// constructed via `from_network_config(&EsploraConfig)`; the
/// publisher consumes the same struct. There is no second `env::var`
/// path that could fall back to a hardcoded chain URL.
pub fn build_network_config_from_env<F>(env: F) -> EsploraConfig
where
    F: Fn(&str) -> Option<String>,
{
    // Treat empty / whitespace-only strings as "unset" so an
    // `ESPLORA_URL=` line in a compose file panics with the same
    // diagnostic as a missing variable instead of silently producing
    // an empty URL — same class of silent misconfiguration.
    let env_or_unset = |k: &str| env(k).filter(|v| !v.trim().is_empty());

    let is_mainnet_raw = env_or_unset("IS_MAINNET").expect(
        "IS_MAINNET env var must be set explicitly to `true` or `false` — \
         no default exists. PRD sets `IS_MAINNET=true`, DEV sets \
         `IS_MAINNET=false`. Self-hosters and integration tests must \
         set it explicitly too.",
    );
    let is_mainnet = match is_mainnet_raw.as_str() {
        "true" => true,
        "false" => false,
        other => panic!(
            "IS_MAINNET must be exactly `true` or `false`, got `{}`. \
             Truthy values like `1`, `TRUE`, or `yes` are rejected to \
             prevent silent misconfiguration (a typo used to land you \
             on Mutinynet).",
            other
        ),
    };

    let url = env_or_unset("ESPLORA_URL").expect(
        "ESPLORA_URL env var must be set — no default exists. Set it \
         to the HTTP Esplora endpoint for the chain this stage serves; \
         see README §Configuration for the per-stage endpoints.",
    );

    let ws_url = env_or_unset("ESPLORA_WS_URL").expect(
        "ESPLORA_WS_URL env var must be set — no default exists. Set \
         it to the Esplora-compatible WebSocket endpoint for the \
         chain this stage serves; see README §Configuration for the \
         per-stage endpoints. The previous default fell back to a \
         public third-party host, coupling availability to a service \
         we do not operate (zk-coins/node #84).",
    );

    let network_name = env_or_unset("NETWORK_NAME").unwrap_or_else(|| {
        if is_mainnet {
            "Mainnet".to_string()
        } else {
            "Mutinynet".to_string()
        }
    });
    println!("Network config: {} ({}) ws={}", network_name, url, ws_url);
    EsploraConfig {
        url,
        is_mainnet,
        network_name,
        ws_url: Some(ws_url),
    }
}

lazy_static! {
    pub static ref NETWORK_CONFIG: EsploraConfig =
        build_network_config_from_env(|k| std::env::var(k).ok());

    /// Domain used by the client to render `<hex|username>@<domain>`.
    /// Distinct from `network_name` because the same Bitcoin network
    /// (e.g. Mutinynet) is served from two isolated test worlds
    /// (`dev.zkcoins.app`, `zkcoins.app`) — the client needs the
    /// stage's external hostname, not the chain identifier.
    pub static ref USERNAME_DOMAIN: String = {
        let domain = std::env::var("USERNAME_DOMAIN").expect(
            "USERNAME_DOMAIN env var must be set (e.g. `zkcoins.app` on PRD, \
             `dev.zkcoins.app` on DEV) — see #95 for the cross-network rationale",
        );
        println!("Username domain: {}", domain);
        domain
    };

    /// Publisher Bitcoin private key (32-byte hex). REQUIRED env var.
    /// No fallback default exists: the previous `1234567890abcdef…`
    /// placeholder was a publicly-known test key that drainer bots
    /// swept within minutes of any on-chain top-up. The matching
    /// public address is exposed by `GET /health/publisher`.
    pub static ref PUBLISHER_KEY: String = std::env::var("PUBLISHER_KEY")
        .expect("PUBLISHER_KEY env var must be set — no default exists. \
                 Generate a 32-byte hex secret via `openssl rand -hex 32`.");

    /// Taproot publisher address derived once at startup from
    /// `PUBLISHER_KEY` against the configured `NETWORK_CONFIG`. Folding
    /// the secp256k1 work into `lazy_static` keeps the request path of
    /// `publisher_health_handler` pure I/O (no per-request `SecretKey
    /// ::from_str` / `Address::p2tr`) and removes a structurally
    /// unreachable `Err` arm — `PUBLISHER_KEY` is validated here, so
    /// an invalid key panics at startup, not on the first health
    /// probe. Log-only, NOT a secret (the matching key lives in
    /// `PUBLISHER_KEY`).
    pub static ref PUBLISHER_ADDRESS: bitcoin::Address = {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_str(&PUBLISHER_KEY)
            .expect("PUBLISHER_KEY must be a valid 32-byte hex secp256k1 secret");
        let key_pair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
        bitcoin::Address::p2tr(&secp, xonly, None, NETWORK_CONFIG.network())
    };

    /// Postgres connection string for the state-layer. Required; the
    /// bootstrap refuses to start without it because there is no
    /// sensible default for a database URL.
    pub static ref DATABASE_URL: String = {
        std::env::var("DATABASE_URL").expect(
            "DATABASE_URL env var must be set (e.g. \
             postgresql://zkcoins:<pw>@postgres:5432/zkcoins)",
        )
    };
}

/// Run `db::persist_state_tx` from a *synchronous* context that already
/// lives on a tokio worker thread.
///
/// The scanner's `InscriptionCallback` is a sync `Fn`, but
/// `persist_state_tx` is async. The naive bridge —
/// `Handle::current().block_on(future)` — panics on the multi_thread
/// flavor. `block_in_place` is the documented sync-in-async escape
/// hatch for multi_thread runtimes.
///
/// `root_index_entry` carries the freshly-inserted `mmr_root_index`
/// row so the Phase-C write lands in the SAME Postgres transaction as
/// the SMT/MMR/latest_block snapshot — see the doc-comment on
/// `db::persist_state_tx` for the heal-on-restart rationale.
pub fn persist_state_from_sync_context(
    pool: &PgPool,
    smt: &[u8],
    mmr: &[u8],
    latest_block: &[u8; 32],
    root_index_entry: Option<(&HashDigest, &HashDigest, u64)>,
) -> Result<(), sqlx::Error> {
    tokio::task::block_in_place(|| {
        tokio::runtime::Handle::current().block_on(db::persist_state_tx(
            pool,
            smt,
            mmr,
            latest_block,
            root_index_entry,
        ))
    })
}

#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

// Shared-Postgres test infrastructure (issue #181 Optimisation B):
// one container per test binary, per-test schema isolation. Internal
// to the test layer; module docs in `test_db.rs` explain the design.
#[cfg(test)]
pub(crate) mod test_db;
