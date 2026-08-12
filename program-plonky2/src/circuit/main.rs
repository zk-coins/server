//! Residual host-facing constants and types after deletion of the legacy
//! Poseidon state-transition circuit body.
//!
//! ## What was removed (Stage 4)
//!
//! The monolithic cyclic-recursive circuit formerly built by
//! `build_circuit` / `prove_initial*` / `prove_account_update*` / `verify`
//! (and its witness helpers, recursion-shape plumbing, and slot targets)
//! is gone. Production proving goes through circuit **C**
//! ([`crate::circuit::compliance`]) and **C_balance**
//! ([`crate::circuit::balance`]) via `ProverBridge` / `StateEngine`.
//!
//! ## What remains here
//!
//! Residual ledger / host code still needs:
//! - public-input width for decoding residual Plonky2 proof blobs
//! - fixed MMR path length used when extending off-circuit MMR proofs
//! - slot-count constants that residual host guards and fixtures name
//! - [`InCoinSourceWitness`] as a named type path for provenance
//!   compile-fail fixtures (not a capability to build legacy proofs)

use plonky2::plonk::proof::ProofWithPublicInputs;

use crate::inputs::CommitmentMerkleProofs;
use crate::merkle::merkle_mountain_range::MMR_MAX_DEPTH;
use crate::merkle::sparse_merkle_tree::InclusionProof;
use crate::{C, D, F};

/// Public-input count carried by the residual `ProofData` payload:
/// `4 (account_state_hash) + 4 (output_coins_root) + 4 (commitment_history_root)
/// + 4 (coin_history_root) + 4` (layout width historically 20 field elements).
///
/// Mirrors [`crate::types::ProofData::to_field_elements`]'s output length.
pub const N_PROOF_DATA_PUBLIC_INPUTS: usize = 20;

/// Fixed off-circuit / residual MMR proof path length. Equal to
/// `MMR_MAX_DEPTH - 1` because an MMR proof has one sibling per level
/// from the leaf's parent (level 1) to the root (level `MMR_MAX_DEPTH - 1`).
pub const MMR_PROOF_PATH_LEN: usize = MMR_MAX_DEPTH - 1;

/// Historical in-coin slot capacity of the deleted legacy circuit.
/// Residual host guards and fixtures still name this bound.
pub const MAX_IN_COINS: usize = 8;

/// Historical out-coin slot capacity of the deleted legacy circuit.
/// Residual host guards and fixtures still name this bound.
pub const MAX_OUT_COINS: usize = 8;

/// Legacy spend-provenance witness bundle.
///
/// Named by provenance compile-fail fixtures and residual type re-exports.
/// The builders that consumed this type (`prove_*_and_sources`, the source
/// aggregator) are deleted — holding a value is not a capability to prove.
pub struct InCoinSourceWitness<'a> {
    pub source_proof: &'a ProofWithPublicInputs<F, C, D>,
    pub source_inclusion: &'a InclusionProof,
    pub source_cmp: &'a CommitmentMerkleProofs,
}
