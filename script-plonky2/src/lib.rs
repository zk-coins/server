//! High-level host-side modules for the Plonky2 backend.
//!
//! ## Architecture (Stage 3)
//!
//! Production proving goes through [`prover_bridge::ProverBridge`] and
//! [`state_engine::StateEngine`] (circuit `C`). The legacy
//! `circuit::main` / `Prover` surface has been **deleted** (not sealed):
//! free builders `build_circuit` / `prove_*` / `verify` are crate-private
//! inside `program-plonky2` and no host wrapper re-exports them.
//!
//! ## Public surface — Stage 3 Runde 6 positive list
//!
//! Default is crate-private. Public modules are the host prove/scan/publish
//! edge consumed by the `node` kernel binary and its integration tests:
//!
//! - [`prover_bridge`] — `ProverBridge`, `TransitionWitness` (byte load only
//!   via [`prover_bridge::TransitionWitness::decode_bound`]; no public
//!   `Deserialize`; private wire type; no public `From`/`TryFrom`), prove/
//!   verify/bind APIs.
//! - [`state_engine`] — `StateEngine` orchestration; `FinalisationCapability`
//!   durable load binds embedded proofs; `pending_mut` is `pub(crate)`.
//! - [`publisher`] / [`scanner`] / [`inscription`] / [`half_agg`] /
//!   [`circuit_identity`] — production publisher/scanner/identity edge.
//!
//! Residual type aliases (`Proof`, `InCoinSourceWitness`, `MintWitness`) stay
//! for ledger blobs; they are not capabilities to build a legacy circuit.
//!
//! ## Toolchain
//!
//! This crate inherits its nightly toolchain from
//! [`program-plonky2/rust-toolchain.toml`](../program-plonky2/rust-toolchain.toml)
//! via a symlink — Plonky2 requires `feature(specialization)`.

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod circuit_identity;
pub mod half_agg;
pub mod inscription;
pub mod prover_bridge;
pub mod publisher;
pub mod scanner;
pub mod state_engine;

use plonky2::plonk::proof::ProofWithPublicInputs;

use zkcoins_program_plonky2::{C, D, F};

// Residual type aliases / witnesses still referenced by the legacy
// Account ledger types (`Account` / `CoinProof`) and residual host
// helpers. The **builders** that produced those proofs are gone.
pub use zkcoins_program_plonky2::circuit::main::{InCoinSourceWitness, MintWitness};

/// Type alias: a Plonky2 proof with public inputs (shared shell type for
/// residual ledger blobs). Not a capability to build a legacy circuit.
pub type Proof = ProofWithPublicInputs<F, C, D>;
