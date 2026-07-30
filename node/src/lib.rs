//! Library crate root for `node`.
//!
//! # Public surface — Stage 3 Runde 8 positive list
//!
//! The default is **crate-private**. Only the items below are `pub`, and
//! each has a **single, item-specific** reason to stay on the external
//! edge. Sammelbegründungen that only cover a subset of the listed names
//! are forbidden. Everything else is `pub(crate)` or private. Derive
//! additions from the compiler (`cargo check --workspace --all-targets`),
//! not from guesswork: a failed external use is either a legitimate list
//! entry or a wrong caller.
//!
//! **Runde 8:** documented surface ≡ real surface. External consumers are
//! exclusively `main.rs`, `probe_r2`, `recover_inscription`,
//! `downstream-boundary`, and `node/tests/`. Crate-internal unit tests are
//! **not** a reason to keep `pub`. A rustdoc-JSON coverage test
//! (`tests/public_surface_coverage.rs`) fails when a public item lacks a
//! list entry.
//!
//! ## Modules (and why they are public)
//!
//! - [`account_node`] — binary `AccountNode::load_ledger_from_pg` (+
//!   `LoadAccountNodeError`); integration `api_remote` deserialises
//!   [`account_node::CoinProof`]; `CanaryOutcome` is in the public
//!   signature of [`self_heal::heal_circuit_digest`]. Compile-fail probes
//!   name sealed methods on `AccountNode`. **Not** public: `new`,
//!   `import_account`, `persist_account`, mutative `state()`, send/mint/
//!   receive, SMT helpers.
//! - [`db`] — binary `connect_and_migrate` only. All residual read helpers
//!   and legacy **write** sinks are `pub(crate)` (boot load goes through
//!   `State` / `AccountNode` / `UsernameStore` methods).
//! - [`runtime`] — binary `start_rest_node` / `V1Readiness`.
//! - [`kernel_rpc`] — binary env edge `KERNEL_GRPC_ADDR_ENV` /
//!   `kernel_grpc_addr_from_env` / `KernelGrpcStartError`. The gRPC server
//!   itself is crate-private (`serve_kernel_grpc_with_domain`) and is
//!   started only from `start_rest_node` with the shared job store + notify
//!   map + pending-sign map (no pool-only silent-stream boot). `GetJob` /
//!   `StreamJob` / `CancelJob` / `SignTransition` are wired; remaining
//!   procedures stay unimplemented until a faithful §7.8 mapping exists.
//! - [`state`] — binary `State::load_from_pg` (+ `LoadStateError`). The
//!   type is public so the binary can hold `Arc<Mutex<State>>`. **Not**
//!   public: `new`, `update`, `serialize_for_persist`,
//!   `update_and_snapshot_for_persist`, merkle helpers, fields,
//!   `derive_num_pubkeys_from_smt`.
//! - [`username`] — binary `UsernameStore::load_from_pg` (+
//!   `LoadUsernameStoreError`). Claim/resolve stay `pub(crate)`.
//! - [`v1`] — binary exclusive-stack boot/scanner/resume edge
//!   (`EngineAdapter`, `ScanStackMode`, `V1ShadowMode`, boot pins,
//!   live-digest and canary, tip reconcile and fold apply, publisher
//!   connect and resume, `db_v1::list_resumable_pending_publishes` /
//!   `PendingPublishRow`, `enforce_stack_scan_mode`,
//!   `claim_process_stack_from_v1_shadow_env` for `recover_inscription`).
//!   **Kernel-API (§7.5)** for the forthcoming gRPC layer: receive
//!   (`verify_and_begin_receive`, `execute_v1_receive`,
//!   `finalise_publish_persist`, `commit_proved_receive`,
//!   `resume_pending_publish` and request/outcome types), mint/send begin
//!   (`begin_v1_mint`, `begin_v1_send`), and sign/finalise
//!   (`durable_finalisation_with_signature`,
//!   `finalise_with_accepted_signature`,
//!   `finalise_accepted_prove_outside_lock`,
//!   `register_live_pending_after_begin`, `FinaliseOutcome`,
//!   `PendingSignEntry`, `WalletSignSubmission`, …). Sealed mint/provenance
//!   engine sinks and process-control helpers stay non-public.
//!   `downstream-boundary` compile-fail matrix names sealed sinks on this
//!   module tree.
//! - [`self_heal`] — binary `heal_circuit_digest` / `ResetDecision`.
//! - [`openapi`] — integration `openapi_smoke` reads `openapi_json` /
//!   `DOCS_HTML` only; route handlers stay `pub(crate)`.
//! - [`router`] — integration `api_remote` needs [`router::Capabilities`].
//!   Request/response DTOs and handlers are `pub(crate)`.
//! - [`r2_budgets`] / [`r2_probe`] — `probe_r2` binary (`ProverMode`,
//!   `R2BudgetSet`, `budgets_for_mode` / `resolve_prover_mode`, host/run
//!   persistence). Calibration internals are `pub(crate)`.
//! - [`publisher`] — `recover_inscription` needs `build_reveal_only` and
//!   the re-exported `LegacyBroadcastClient`. `EsploraConfig` and
//!   broadcast/resume helpers are `pub(crate)`.
//! - [`legacy_commitment_scan`] — type named only so compile-fail matrices
//!   prove the scan cap is unconstructible; `mint_for_test` and the scan
//!   loop are `pub(crate)` (no production mint of the cap).
//!
//! ## Crate-root items
//!
//! - [`DATABASE_URL`] — binary `main.rs` boot (`connect_and_migrate`).
//!
//! **Not** public (crate-internal only): `build_network_config_from_env`,
//! `NETWORK_CONFIG`, `USERNAME_DOMAIN`, `PUBLISHER_KEY`,
//! `PUBLISHER_ADDRESS`. `probe_r2` / `recover_inscription` read their env
//! themselves; health/config handlers use the lazy cells via `pub(crate)`.
//!
//! Modules **not** on this list (`audit`, `flow`, `job_*`, `scanner*`,
//! `prover_health`, `esplora_bound`, `persist_state_from_sync_context`, …)
//! are `pub(crate)`.
//!
//! Spec: §7.5 — the node is a kernel (gRPC); public clients talk to the API
//! layer. Capability-bound `read.account` is not “knows an address”.

// Opt in to the unstable `coverage_attribute` feature only when
// `cargo llvm-cov` defines the `coverage_nightly` cfg (it injects the
// flag automatically on a nightly toolchain). The `coverage(off)`
// annotations on the platform-`_impl` helpers in `r2_probe.rs` rely on
// this feature being enabled; the same pattern is used in
// `program-plonky2/src/lib.rs` and `script-plonky2/src/lib.rs`. Without
// the cfg gate the stable toolchain would refuse to compile the crate.
#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// Residual `new()` constructors remain crate-visible (`pub(crate)`) on
// types that never got `Default`. Clippy's `new_without_default` is
// library-target sensitive; suppress at the crate root so the lint
// stays off while call sites keep using `::new()` rather than adding
// a decorative `Default` impl.
#![allow(clippy::new_without_default)]

pub mod account_node;
/// Quarantined legacy job façades (ash‖ocr commit, …). Not §7.8 procedures.
pub(crate) mod application;
pub(crate) mod audit;
pub mod db;
/// Node-side Esplora boundary: re-exports the `esplora-bound` facade
/// (sole owner of `esplora-client`) and stack-gates legacy broadcast.
/// Crate-private: external edge reaches `LegacyBroadcastClient` only via
/// the `publisher` re-export used by `recover_inscription`.
pub(crate) mod esplora_bound;
pub(crate) mod flow;
pub(crate) mod job_dispatcher;
pub(crate) mod job_store;
/// Transport-free kernel domain (§6.1 / §7.8). Crate-private so the
/// public-surface allowlist does not move.
pub(crate) mod kernel;
/// `kernel.v1` gRPC edge (§7.8). Public for the binary env parse
/// (`kernel_grpc_addr_from_env`); serve path is crate-private and only
/// wired from `start_rest_node` with a shared domain façade.
pub mod kernel_rpc;
/// Stage-3 sealed legacy Commitment → SMT/MMR scan sink (Stage 4 deletes).
/// Public only so compile-fail matrices can name the sealed cap type.
pub mod legacy_commitment_scan;
pub mod openapi;
pub(crate) mod prover_health;
pub mod publisher;
pub mod r2_budgets;
pub mod r2_probe;
pub mod router;
pub mod runtime;
pub mod self_heal;
pub mod state;
/// Shared transport error contract + (later) HTTP/gRPC adapters.
pub(crate) mod transport;
pub mod username;
/// v1.1 StateEngine adapter + exclusive stack (Stage 2/3).
pub mod v1;

use crate::publisher::EsploraConfig;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use lazy_static::lazy_static;
use std::str::FromStr;

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
pub(crate) fn build_network_config_from_env<F>(env: F) -> EsploraConfig
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
    let cfg = EsploraConfig {
        url,
        is_mainnet,
        network_name,
        ws_url: Some(ws_url),
    };
    // Read `ws_url` from the struct (sole store of ESPLORA_WS_URL after
    // build) so the field is not a write-only residual after the legacy
    // scanner deletion.
    println!(
        "Network config: {} ({}) ws={}",
        cfg.network_name,
        cfg.url,
        cfg.ws_url
            .as_deref()
            .expect("ESPLORA_WS_URL was required above"),
    );
    cfg
}

lazy_static! {
    pub(crate) static ref NETWORK_CONFIG: EsploraConfig =
        build_network_config_from_env(|k| std::env::var(k).ok());

    /// Domain used by the client to render `<hex|username>@<domain>`.
    /// Distinct from `network_name` because the same Bitcoin network
    /// (e.g. Mutinynet) is served from two isolated test worlds
    /// (`dev.zkcoins.app`, `zkcoins.app`) — the client needs the
    /// stage's external hostname, not the chain identifier.
    pub(crate) static ref USERNAME_DOMAIN: String = {
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
    pub(crate) static ref PUBLISHER_KEY: String = std::env::var("PUBLISHER_KEY")
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
    pub(crate) static ref PUBLISHER_ADDRESS: bitcoin::Address = {
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
    ///
    /// Public: binary `main.rs` is the sole external consumer
    /// (`connect_and_migrate`). Other binaries read `DATABASE_URL` from
    /// the environment themselves.
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
#[cfg(test)]
#[path = "main_tests.rs"]
mod tests;

// Shared-Postgres test infrastructure (issue #181 Optimisation B):
// one container per test binary, per-test schema isolation. Internal
// to the test layer; module docs in `test_db.rs` explain the design.
#[cfg(test)]
pub(crate) mod test_db;
