//! High-level host-side modules for the Plonky2 backend.
//!
//! ## Architecture (Stage 3)
//!
//! Production proving goes through [`prover_bridge::ProverBridge`] and
//! [`state_engine::StateEngine`] (circuit `C`). The legacy
//! `circuit::main` / `Prover` surface has been **deleted** (not sealed):
//! free builders `build_circuit` / `prove_*` / `verify` are **deleted**
//! (Stage 4), not sealed — nothing to re-export.
//!
//! ## Public surface — Stage 3 Runde 8 positive list
//!
//! Default is crate-private. Public modules/items are the host
//! prove/scan/publish edge consumed by the `node` kernel binary,
//! `probe_r2`, and compile-fail fixtures. Each entry has its own reason:
//!
//! - [`prover_bridge`] — `ProverBridge`, `TransitionWitness` (byte load only
//!   via [`prover_bridge::TransitionWitness::decode_bound`]; no public
//!   `Deserialize`; private wire type; no public `From`/`TryFrom`), prove/
//!   verify/bind APIs. Cross-crate receive edge:
//!   - [`prover_bridge::ProverBridge::load_transition_proof_bytes`] — node
//!     §2.3.3 step 2 loads `CoinProof.proof` as **native** Plonky2 wire
//!     (`ProofWithPublicInputs::from_bytes`), not bincode. The node already
//!     holds the raw bytes after bundle decode, but only the bridge owns
//!     circuit `C` common data + cyclic-tail bind; `bind_loaded_prev_proof`
//!     is the durable-account bincode path and cannot accept §1.7.9 wire.
//!     Full `verify_transition` remains a separate call.
//!   - [`prover_bridge::validate_prover_lease_path_at_boot`] — boot-time
//!     validation of the host-wide proving-lease path for `node/src/main.rs`.
//! - [`prover_bridge::test_signing`] — `TestSignature`, `deterministic_secret`,
//!   `normalized_key`, `sign_transition`: **required by `probe_r2`** for
//!   host-valid clause-10 fixtures (not a production wallet API).
//! - [`state_engine`] — `StateEngine` orchestration; `FinalisationCapability`
//!   durable load binds embedded proofs; read-only `pending()` for external
//!   inspection (no mutable pending accessor — durable load gate stays closed).
//! - [`publisher`] — production `Publisher` / batch types +
//!   `BLOCK_ANCHOR_INCLUSION_DELAY_MARGIN` (node `V1PublisherEnv` wiring).
//!   Internal constants (`NUMS_*`, `MAX_STANDARD_TX_WEIGHT`,
//!   `BLOCK_ANCHOR_MAX_GAP`, `BLOCK_ANCHOR_PUBLISH_MAX_GAP`) and free
//!   helpers (`ensure_deterministic_funding` … `note_fee_state`) are
//!   `pub(crate)`.
//! - [`scanner`] — production `Scanner` / config / report types used by
//!   the node binary. Free helpers and test/fault-injection hooks are
//!   `pub(crate)`. Catalog edge required by the node crate (cross-crate;
//!   `pub(crate)` cannot span the boundary):
//!   - [`scanner::ScannedInscription`] (+ its fields) — accepted
//!     inscription after §3.6 steps 1–3; node maps it into the durable
//!     catalog (`CatalogInscription::from_scanned`) and ListInscriptions.
//!     Fields are the minimal set the node reads (height/tx/vin,
//!     reveal_txid, format, members, block_anchor); no extra accessors.
//!   - [`scanner::Scanner::accepted_inscriptions`] — read the post-scan
//!     accepted stream (including first-occurrence losers the NfLog
//!     ignores) so the node can fold catalog + NfLog in one apply.
//!   - [`scanner::evaluate_anchor_bound`] — pure §3.5 `block_anchor` bound
//!     predicate (strict ancestor, `MAX_ANCHOR_GAP`, hash match); node's
//!     §4.5 SDR replay reuses it for check (vi).
//! - [`half_agg`] — production half-aggregation edge (untouched this round).
//! - [`circuit_identity`] — `require_live_digests_match_pins` (node boot
//!   canary). `require_one_live_digest_matches_pin` is `pub(crate)`.
//!
//! Residual type aliases: [`Proof`] (ledger / residual host),
//! [`InCoinSourceWitness`] (named by provenance compile-fail fixtures).
//! `MintWitness` is not re-exported — no external consumer type.
//!
//! [`inscription`] is `pub(crate)` (only publisher/scanner inside this crate).
//!
//! ## Toolchain
//!
//! This crate inherits its nightly toolchain from
//! [`program-plonky2/rust-toolchain.toml`](../program-plonky2/rust-toolchain.toml)
//! via a symlink — Plonky2 requires `feature(specialization)`.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]
// Exclude the whole prover/circuit crate from coverage instrumentation: it is
// justifiably excluded from the coverage floor (docs/coverage-baseline.md), and
// instrumenting the ~1.38M-gate C construction makes an instrumented node build
// too slow to run the integration-coverage journey. No effect on normal builds.
#![cfg_attr(coverage_nightly, coverage(off))]

pub mod circuit_identity;
pub mod half_agg;
pub(crate) mod inscription;
pub mod prover_bridge;
mod prover_lease;
pub mod publisher;
pub mod scanner;
pub mod state_engine;
pub mod verifier_cache;

use plonky2::plonk::proof::ProofWithPublicInputs;

use zkcoins_program_plonky2::{C, D, F};

// Residual type aliases / witnesses still referenced by the legacy
// Account ledger types (`Account` / `CoinProof`) and residual host
// helpers. The **builders** that produced those proofs are gone.
//
// `InCoinSourceWitness` stays public: provenance compile-fail fixtures
// name `zkcoins_prover::InCoinSourceWitness` to prove it is not on the
// v1 orchestration surface (while still obtainable as a type path).
// `MintWitness` is not re-exported: no external consumer names it, and
// no in-crate path outside `program-plonky2` needs the alias.
pub use zkcoins_program_plonky2::circuit::main::InCoinSourceWitness;

/// Type alias: a Plonky2 proof with public inputs (shared shell type for
/// residual ledger blobs). Not a capability to build a legacy circuit.
pub type Proof = ProofWithPublicInputs<F, C, D>;
