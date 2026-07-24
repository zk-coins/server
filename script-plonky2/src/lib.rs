//! High-level host-side prover wrapper for the Plonky2 state-transition
//! circuit. Companion to the SP1-era `script/` crate.
//!
//! ## Architecture
//!
//! - [`Prover`] owns the heavy `StateTransitionCircuit` build (one
//!   per process — typically created at node startup).
//! - [`Prover::prove_initial`] / [`Prover::prove_account_update`] are
//!   thin convenience wrappers over the low-level
//!   [`zkcoins_program_plonky2::circuit::main`] APIs that thread
//!   through the common Init/Update arguments without re-exposing
//!   slot-witness construction.
//! - [`Prover::verify`] runs both the circuit-data verification AND
//!   the cyclic-verifier-data digest cross-check that
//!   [`zkcoins_program_plonky2::circuit::main::verify`] performs
//!   internally.
//!
//! ## Toolchain
//!
//! This crate inherits its nightly toolchain from
//! [`program-plonky2/rust-toolchain.toml`](../program-plonky2/rust-toolchain.toml)
//! via a symlink — Plonky2 requires `feature(specialization)`.
//! Callers from stable-toolchain crates (e.g. the SP1-era `node/`
//! crate) must invoke this via a subprocess boundary (a `[[bin]]`
//! target ships in a future iteration).

#![cfg_attr(coverage_nightly, feature(coverage_attribute))]

pub mod half_agg;
pub mod prover_bridge;
pub mod state_engine;

use anyhow::Result;
use plonky2::plonk::proof::ProofWithPublicInputs;

use zkcoins_program_plonky2::circuit::main::{
    build_circuit, prove_account_update, prove_account_update_with_in_and_out_coins,
    prove_account_update_with_in_and_out_coins_and_sources, prove_account_update_with_in_coins,
    prove_initial, prove_initial_with_in_and_out_coins,
    prove_initial_with_in_and_out_coins_and_sources, prove_initial_with_in_coins, verify,
    StateTransitionCircuit,
};
use zkcoins_program_plonky2::hash::HashDigest;
use zkcoins_program_plonky2::inputs::CommitmentMerkleProofs;
use zkcoins_program_plonky2::merkle::sparse_merkle_tree::NonInclusionProof;
use zkcoins_program_plonky2::types::{AccountState, Coin, PublicKey};
use zkcoins_program_plonky2::{C, D, F};

// Re-export so node callers don't have to depend on
// `zkcoins-program-plonky2` directly for the source-witness / mint-witness types.
pub use zkcoins_program_plonky2::circuit::main::{InCoinSourceWitness, MintWitness};

/// Type alias: a single state-transition proof carrying the
/// `ProofData` public inputs plus the cyclic verifier-data digest.
pub type Proof = ProofWithPublicInputs<F, C, D>;

/// Host-side prover. Owns the built state-transition circuit
/// (proving + verification keys, common data) so that successive
/// `prove_*` calls amortise the ~10 s build cost.
///
/// The circuit is cyclic — its `verifier_data.circuit_digest` is
/// pinned in every proof's public inputs, enforcing that all proofs
/// the node emits are verifiable by the SAME circuit instance.
pub struct Prover {
    pub circuit: StateTransitionCircuit,
}

impl Default for Prover {
    fn default() -> Self {
        Self::new()
    }
}

impl Prover {
    /// Build the state-transition circuit. Expensive (~10 s wall on
    /// the M3 Ultra at production parameters: `MAX_IN_COINS` =
    /// `MAX_OUT_COINS` = 8, `INNER_PAD_BITS_STAGE_5D_NEXT_5 = 15`
    /// — Phase 2b outer at degree 16). Call once per process and
    /// share via `Arc<Prover>` across request handlers; the
    /// fixed-point loop that converges aggregator + outer common
    /// inside `build_circuit` runs on each instantiation.
    pub fn new() -> Self {
        Self {
            circuit: build_circuit(),
        }
    }

    /// Prove an Initial-branch state transition with all in-coin
    /// slots inactive and no out-coins.
    pub fn prove_initial(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        asset_id: HashDigest,
        mint: Option<MintWitness>,
    ) -> Result<Proof> {
        prove_initial(&self.circuit, account_state, history_root, asset_id, mint)
    }

    /// Prove an Initial-branch transition with caller-supplied
    /// in-coin slot witnesses. Each tuple is
    /// `(active, &coin, &non_inclusion_proof)`. The caller MUST
    /// supply exactly `MAX_IN_COINS` tuples.
    ///
    /// Delegates through to the `_and_sources` core with all-`None`
    /// sources — only suitable for transitions whose `in_coins` are
    /// ALL inactive. Active in-coin slots require the
    /// [`Self::prove_initial_with_in_and_out_coins_and_sources`]
    /// variant.
    pub fn prove_initial_with_in_coins(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
        asset_id: HashDigest,
        mint: Option<MintWitness>,
    ) -> Result<Proof> {
        prove_initial_with_in_coins(
            &self.circuit,
            account_state,
            history_root,
            in_coins,
            asset_id,
            mint,
        )
    }

    /// Full-control Initial-branch prove: in-coin tuples, out-coin
    /// tuples, and explicit `next_public_key` rotation. Each
    /// `out_coins` tuple is
    /// `(active, out_coin_identifier, amount, &non_inclusion_proof)`.
    /// Delegates to the `_and_sources` variant with all-`None`
    /// sources — only suitable for transitions whose `in_coins` are
    /// ALL inactive. Active in-coin slots require the
    /// [`Self::prove_initial_with_in_and_out_coins_and_sources`]
    /// variant.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_initial_with_in_and_out_coins(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
        out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
        next_public_key: &PublicKey,
        asset_id: HashDigest,
        mint: Option<MintWitness>,
    ) -> Result<Proof> {
        prove_initial_with_in_and_out_coins(
            &self.circuit,
            account_state,
            history_root,
            in_coins,
            out_coins,
            next_public_key,
            asset_id,
            mint,
        )
    }

    /// Prove an AccountUpdate transition consuming `prev` as the
    /// recursive inner proof, with all in-coin slots inactive.
    pub fn prove_account_update(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        prev: &Proof,
        cmp: &CommitmentMerkleProofs,
        asset_id: HashDigest,
    ) -> Result<Proof> {
        prove_account_update(
            &self.circuit,
            account_state,
            history_root,
            prev,
            cmp,
            asset_id,
        )
    }

    /// Prove an AccountUpdate transition with caller-supplied
    /// in-coin slot witnesses.
    ///
    /// Delegates through to the `_and_sources` core with all-`None`
    /// sources — only suitable for transitions whose `in_coins` are
    /// ALL inactive. Active in-coin slots require the
    /// [`Self::prove_account_update_with_in_and_out_coins_and_sources`]
    /// variant.
    pub fn prove_account_update_with_in_coins(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        prev: &Proof,
        cmp: &CommitmentMerkleProofs,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
        asset_id: HashDigest,
    ) -> Result<Proof> {
        prove_account_update_with_in_coins(
            &self.circuit,
            account_state,
            history_root,
            prev,
            cmp,
            in_coins,
            asset_id,
        )
    }

    /// Full-control AccountUpdate prove: in-coin tuples, out-coin
    /// tuples, and explicit `next_public_key` rotation. Delegates to
    /// the `_and_sources` variant with all-`None` sources — only
    /// suitable for transitions whose `in_coins` are ALL inactive.
    /// Active in-coin slots require the
    /// [`Self::prove_account_update_with_in_and_out_coins_and_sources`]
    /// variant.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_account_update_with_in_and_out_coins(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        prev: &Proof,
        cmp: &CommitmentMerkleProofs,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
        out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
        next_public_key: &PublicKey,
        asset_id: HashDigest,
    ) -> Result<Proof> {
        prove_account_update_with_in_and_out_coins(
            &self.circuit,
            account_state,
            history_root,
            prev,
            cmp,
            in_coins,
            out_coins,
            next_public_key,
            asset_id,
        )
    }

    /// Stage 5d-next-5 Phase 2b Initial-branch prove with per-slot
    /// source witnesses for active in-coins. `sources.len()` must
    /// equal `MAX_IN_COINS`; `Some(_)` ↔ active source proof,
    /// `None` ↔ inactive slot.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_initial_with_in_and_out_coins_and_sources(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
        out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
        next_public_key: &PublicKey,
        sources: &[Option<InCoinSourceWitness>],
        asset_id: HashDigest,
        mint: Option<MintWitness>,
    ) -> Result<Proof> {
        prove_initial_with_in_and_out_coins_and_sources(
            &self.circuit,
            account_state,
            history_root,
            in_coins,
            out_coins,
            next_public_key,
            sources,
            asset_id,
            mint,
        )
    }

    /// Stage 5d-next-5 Phase 2b AccountUpdate-branch prove with
    /// per-slot source witnesses for active in-coins. Symmetric
    /// shape with [`Self::prove_initial_with_in_and_out_coins_and_sources`].
    #[allow(clippy::too_many_arguments)]
    pub fn prove_account_update_with_in_and_out_coins_and_sources(
        &self,
        account_state: &AccountState,
        history_root: HashDigest,
        prev: &Proof,
        cmp: &CommitmentMerkleProofs,
        in_coins: &[(bool, &Coin, &NonInclusionProof)],
        out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
        next_public_key: &PublicKey,
        sources: &[Option<InCoinSourceWitness>],
        asset_id: HashDigest,
    ) -> Result<Proof> {
        prove_account_update_with_in_and_out_coins_and_sources(
            &self.circuit,
            account_state,
            history_root,
            prev,
            cmp,
            in_coins,
            out_coins,
            next_public_key,
            sources,
            asset_id,
        )
    }

    /// Verify a proof against the prover's circuit. Runs both
    /// `check_cyclic_proof_verifier_data` (cross-check that the
    /// proof's pinned `circuit_digest` matches this circuit's own)
    /// and the underlying Plonky2 `data.verify`.
    pub fn verify(&self, proof: &Proof) -> Result<()> {
        verify(&self.circuit, proof)
    }

    /// Stable byte encoding of this circuit's verifier-key
    /// `circuit_digest` (the cyclic recursion's fixed-point digest,
    /// a `HashOut<F>` of 4 Goldilocks field elements).
    ///
    /// The node persists this at boot and compares it against the digest
    /// of the previously-running build as the cheap steady-state
    /// staleness fast path (`node::self_heal::reset_decision`). The
    /// digest is `Poseidon(constants_sigmas_cap || domain_separator ||
    /// degree_bits)` — it is **deterministic across separate builds of
    /// identical circuit code** (no timestamp / nonce; verified against
    /// the live DEV dump, whose proofs carried a byte-identical digest to
    /// a later rebuild). A digest change therefore reliably signals a
    /// circuit change.
    ///
    /// The converse does NOT hold: the digest does **not** encode the
    /// gate *constraints* (see upstream `circuit_builder.rs` "TODO: This
    /// should also include an encoding of gate constraints"), so a change
    /// that alters constraint behaviour while preserving the
    /// constants/sigmas cap + degree leaves the digest UNCHANGED yet can
    /// still break recursion. That blind spot is why the boot self-heal
    /// pairs this comparison with a canary recursion probe on the
    /// adoption boundary — see `node::self_heal` and
    /// `node::account_node::AccountNode::canary_recursion`.
    ///
    /// The encoding is `bincode::serialize` of the `HashOut`; the bytes
    /// are opaque to the comparison — only equality matters.
    pub fn circuit_digest_bytes(&self) -> Vec<u8> {
        bincode::serialize(&self.circuit.data.verifier_only.circuit_digest)
            .expect("HashOut<F> bincode-serialize is infallible")
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use zkcoins_program_plonky2::types::{calculate_asset_id, calculate_name_hash};

    fn dummy_pubkey(seed: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        for (i, b) in pk.iter_mut().enumerate().skip(1) {
            *b = seed.wrapping_add(i as u8);
        }
        pk
    }

    /// Smoke test: build a `Prover`, prove an empty Init transition,
    /// verify it. Validates the wrapper compiles + threads through
    /// the underlying program-plonky2 APIs end-to-end.
    ///
    /// Heavy (~3-15 min wall at production parameters MAX=8); flagged
    /// `#[ignore]` so the routine `cargo test` sweep skips it. Run
    /// explicitly via `cargo test --release prover_init_roundtrip --
    /// --ignored --nocapture`.
    #[test]
    #[ignore]
    fn prover_init_roundtrip() {
        let prover = Prover::new();
        // Issuer-mint: the account is the creator of its own asset, so a
        // non-zero initial supply is accepted by the issuer gate.
        let creator_pubkey = dummy_pubkey(7);
        let name_hash = calculate_name_hash("TEST");
        let asset_id = calculate_asset_id(&creator_pubkey, &name_hash, 8);
        let mut account_state = AccountState::new(creator_pubkey, asset_id);
        account_state.balance = 100;
        let mint = MintWitness {
            creator_pubkey,
            name_hash,
            decimals: 8,
        };

        let history_root = zkcoins_program_plonky2::hash::hash_bytes(b"prover-test-history");
        let proof = prover
            .prove_initial(&account_state, history_root, asset_id, Some(mint))
            .expect("prove initial");
        prover.verify(&proof).expect("verify");
    }
}
