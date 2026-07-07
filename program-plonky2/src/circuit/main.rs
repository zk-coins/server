//! Monolithic state-transition circuit for zkCoins (Plonky2 backend).
//!
//! Mirrors `program/src/main.rs` (the SP1 entrypoint), but built as a
//! Plonky2 cyclic-recursive circuit per the protocol specification
//! §8 / §10 (<https://docs.zkcoins.app/specification>).
//!
//! ## Stage status
//!
//! - **5a — recursion plumbing PoC**: done in commit `83fa0c1`,
//!   superseded by 5b.
//! - **5b — Initial branch with real predicate**: done in commit
//!   `d167237`.
//! - **5c — AccountUpdate branch**: done in commit `bba6470`. SPEC §8
//!   (a) + (b) wired, `coin_history` carry-over, mint exception
//!   masked.
//! - **5c+ — CommitmentMerkleProofs in-circuit** ✅ this revision.
//!   SPEC §8 (c)(d)(e) wired against fixed-shape SMT + MMR proofs.
//!   Specifically: (c) is `account_state.hash() ==
//!   mp.commitment_account_state_hash` via element-wise difference
//!   masked with `condition`; (d) is `mp.verify_commitment(history_root)`,
//!   which is an in-circuit SMT inclusion of `commitment = h(asth || ocr)`
//!   in `commitment_root` followed by MMR inclusion of
//!   `h(commitment_root || commitment_root_mmr_sibling)` in `history_root`;
//!   (e) is `mp.verify_previous_root(prev.commitment_history_root,
//!   history_root)`, i.e. MMR inclusion of `h(previous_root_history_proof.0
//!   || prev.commitment_history_root)` in `history_root`.
//!   Every (c)(d)(e) check is masked: each `connect_hashes(computed,
//!   expected)` is re-targeted as `connect_hashes(computed,
//!   select_hash(condition, expected_witness, computed))`. When
//!   `condition = false` the `select` collapses to `computed` and the
//!   constraint is trivially satisfied; when `condition = true` it
//!   reduces to the honest check.
//! - **5d / 5e** — see ROADMAP "In Progress" section.
//!
//! ## Public-input layout (unchanged from 5b)
//!
//! 16 `ProofData` field elements + verifier-data slots. Layout per
//! [`crate::types::ProofData::to_field_elements`]:
//!
//! | slot range | meaning                  |
//! |------------|--------------------------|
//! | 0..4       | account_state_hash       |
//! | 4..8       | output_coins_root        |
//! | 8..12      | commitment_history_root  |
//! | 12..16     | coin_history_root        |
//!
//! ## Fixed-shape requirements
//!
//! The circuit consumes:
//! - One SMT inclusion proof of depth [`TREE_DEPTH`] = 256.
//! - Two MMR inclusion proofs of depth [`MMR_PROOF_PATH_LEN`] =
//!   `MMR_MAX_DEPTH - 1` = 31.
//!
//! Off-circuit producers must extend their (variable-depth) proofs to
//! these fixed depths before witnessing — see
//! [`crate::merkle::merkle_mountain_range::MMRProof::extend_to`] and
//! [`crate::merkle::merkle_mountain_range::MerkleMountainRange::root_extended`]
//! for the MMR helper. The SMT is already uncompressed-fixed-depth by
//! construction (see the SMT redesign commit).
//!
//! ## Branch selection via `condition`
//!
//! - `false` → Initial (dummy inner; cyclic verify uses dummy; all
//!   AccountUpdate-only constraints — state continuity, (c)(d)(e),
//!   coin_history carry-over — are masked off).
//! - `true`  → AccountUpdate (real prev proof in inner slot; all
//!   AccountUpdate-only constraints fire; mint exception masked off).

use anyhow::Result;
use plonky2::field::types::Field;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOut, HashOutTarget};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget,
};
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;

use crate::circuit::mmr::mmr_inclusion_root;
use crate::circuit::smt::{hash_up_full_path, key_bits_msb_first, smt_inclusion_root};
use crate::circuit::source_aggregator::{
    build_source_aggregator_circuit, prove_aggregator, AggregatorSlotWitness,
    SourceAggregatorCircuit, N_ST_VK_DIGEST_PIS, PER_SLOT_PIS,
};
use crate::hash::{digest_from_bytes, HashDigest, ZERO_HASH};
use crate::inputs::CommitmentMerkleProofs;
use crate::merkle::merkle_mountain_range::MMR_MAX_DEPTH;
use crate::merkle::sparse_merkle_tree::{
    InclusionProof, NonInclusionProof, DEFAULT_HASHES, TREE_DEPTH,
};
use crate::types::{AccountState, Coin, PublicKey, ASSET_GENESIS_DOMAIN_TAG};
use crate::{C, D, F};

/// Public-input count carried by the `ProofData` payload:
/// `4 (account_state_hash) + 4 (output_coins_root) + 4 (commitment_history_root) + 4 (coin_history_root)`.
///
/// Mirrors [`crate::types::ProofData::to_field_elements`]'s output length;
/// the verifier-data slots added by `add_verifier_data_public_inputs`
/// follow these and are not counted here.
pub const N_PROOF_DATA_PUBLIC_INPUTS: usize = 20;

/// Fixed in-circuit MMR proof path length. Equal to
/// `MMR_MAX_DEPTH - 1` because an MMR proof has one sibling per level
/// from the leaf's parent (level 1) to the root (level
/// `MMR_MAX_DEPTH - 1`).
pub const MMR_PROOF_PATH_LEN: usize = MMR_MAX_DEPTH - 1;

/// Number of in-coin slots the circuit reserves. The state transition
/// processes `MAX_IN_COINS` slots in fixed order; inactive slots are
/// no-ops (masked by their per-slot `active` bit). Matches SPEC §13's
/// production target. Each extra slot adds ~512 Poseidon hashes
/// (the in-circuit SMT non-inclusion + insert walks at `TREE_DEPTH =
/// 256`) plus ~80 arithmetic gates for the recipient + balance
/// checks. The cyclic-recursion `common_data_for_recursion_c`
/// padding must be sized to accommodate the resulting outer-circuit
/// gate count — see that function for the current setting.
pub const MAX_IN_COINS: usize = 8;

/// Number of out-coin slots the circuit reserves. Each active slot
/// inserts the coin's identifier into the running `output_coins_root`
/// SMT and subtracts its amount from the running balance with an
/// underflow check. After the out-coin loop, the slot's
/// `out_coin.identifier` is asserted to equal
/// `Poseidon(interim_account_state_hash || slot_index)`, mirroring
/// the off-circuit [`crate::types::calculate_coin_identifier`].
/// Matches SPEC §13's production target of 8. Each extra slot costs
/// ~512 Poseidon hashes + ~80 arithmetic gates; the cyclic-recursion
/// `common_data_for_recursion_c` padding must be sized to accommodate
/// the resulting outer-circuit gate count.
pub const MAX_OUT_COINS: usize = 8;

/// Build the `CommonCircuitData` that the cyclic circuit references
/// when verifying its own prior proof.
///
/// Faithful port of Plonky2 1.1.0's own
/// `recursion::cyclic_recursion::tests::common_data_for_recursion`:
///
/// 1. An empty circuit, to seed `data.common`.
/// 2. A circuit that calls `verify_proof` once against the seed; this
///    establishes a verifier shape stable enough to be its own input.
/// 3. A third pass that verifies once and pads the gate set up to
///    2^12 gates with `NoopGate`. The padding fixes the circuit size
///    so the cyclic recursion fixed-point is reachable.
///
/// The final `.common` is the `CommonCircuitData` we hand to
/// `conditionally_verify_cyclic_proof_or_dummy`. It encodes everything
/// the verifier needs to know about the circuit it's about to verify
/// (gate set, public-input count, FRI parameters).
///
/// **Why faithful-port and not the BitVM/zkCoins reference variant:**
/// BitVM was on Plonky2 0.2.0; its `common_data_for_recursion` used
/// 2–3 `verify_proof` calls per pass plus a `ConstantGate`. In
/// Plonky2 1.1.0 that shape no longer matches what
/// `conditionally_verify_cyclic_proof_or_dummy` produces, and the
/// outer `builder.build::<C>()` fails with "Failed to build circuit"
/// (gate-set / public-input shape mismatch). The 1.1.0 canonical
/// shape — one verify_proof + NoopGate padding to 2^12 — is what the
/// library's own tests use.
fn common_data_for_recursion_c() -> CommonCircuitData<F, D> {
    common_data_for_recursion_c_inner(None, INNER_PAD_BITS_STAGE_5D_NEXT_3)
}

/// INNER_PAD_BITS used by the Stage 5d-next-3 1-verify helper. Outer
/// gate count is ~8–10 k → 2^14 = 16384.
const INNER_PAD_BITS_STAGE_5D_NEXT_3: usize = 14;

/// INNER_PAD_BITS used by the Stage 5d-next-5 2-verify helper (cyclic
/// `prev_account` + non-cyclic aggregator). Despite adding
/// `verify_proof(agg)` to the outer, the helper-degree
/// = `pad_bits + 1` relationship combined with the full outer's
/// natural degree drives the choice of constant. The empirical
/// relation was characterised by
/// `recursion_shape_probe::dump_phase_2a_pad_bits_sweep`.
///
/// **Phase 2a (`b5be37a`)**: Stage 5d-next-3 base ~10 k +
/// `verify_proof(agg)` ~10 k + `_or_dummy` overhead → ~30 k, fitting
/// at `degree_bits = 15`. `pad_bits = 14` made helper-degree (15)
/// match outer-degree (15).
///
/// **Phase 2b (this revision)**: per-slot source-side gates add ~20 k
/// gates (8 slots × {SMT inclusion ~1 k + SPEC (c)(d)(e) chain ~1.5 k}).
/// Outer total ~50 k → `degree_bits = 16`. `pad_bits` bumps to 15 so
/// helper-degree (16) matches outer-degree (16). If a future stage
/// crosses `2^16 = 65 536` gates, the helper must bump to `pad_bits =
/// 16` (and a similar pattern continues per power-of-two threshold);
/// re-run `dump_phase_2a_pad_bits_sweep` to confirm.
const INNER_PAD_BITS_STAGE_5D_NEXT_5: usize = 15;

/// Total public-input count exposed by the state-transition circuit:
/// 16 `ProofData` elements + the cyclic verifier_data public inputs
/// (4 elements for circuit_digest + 4 per cap entry). Used to
/// pre-size `bootstrap_st_common.num_public_inputs` so the
/// aggregator's virtual proof targets allocate the right-size PI
/// vector before the outer is built.
fn state_transition_num_pis() -> usize {
    let cap_elements = CircuitConfig::standard_recursion_config()
        .fri_config
        .num_cap_elements();
    N_PROOF_DATA_PUBLIC_INPUTS + 4 + 4 * cap_elements
}

/// Stage 5d-next-5 generalisation of [`common_data_for_recursion_c`].
///
/// `aggregator = Some(_)` makes pass 2 and 3 each add a second
/// `verify_proof` against `agg.common` (with
/// `constant_verifier_data(agg.verifier_only)` to pin the aggregator's
/// vd as a circuit constant). Pass 3 also injects ONE explicit
/// `ConstantGate{num_consts: 2}` instance before the NoopGate pad —
/// without it, the helper's `gates` list lacks `ConstantGate` while
/// `dummy_circuit`'s rebuild and the outer's own build both emit one
/// (via the `ConstantGate::new(2)` injection in `build_circuit`),
/// failing the cyclic fixed-point check. See
/// `MIGRATION_RESEARCH.md` §7.22 and `recursion_shape_probe` for the
/// empirical derivation of both the ConstantGate-injection trick and
/// the pad-bits → helper-degree relationship.
fn common_data_for_recursion_c_inner(
    aggregator: Option<&CircuitData<F, C, D>>,
    inner_pad_bits: usize,
) -> CommonCircuitData<F, D> {
    // Pass 1: empty seed circuit.
    let config = CircuitConfig::standard_recursion_config();
    let builder = CircuitBuilder::<F, D>::new(config);
    let data = builder.build::<C>();

    // Pass 2: verify the seed circuit once (+ optionally verify the
    // aggregator's shape once).
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    if let Some(agg) = aggregator {
        let agg_proof = builder.add_virtual_proof_with_pis(&agg.common);
        let agg_vd = builder.constant_verifier_data(&agg.verifier_only);
        builder.verify_proof::<C>(&agg_proof, &agg_vd, &agg.common);
    }
    let data = builder.build::<C>();

    // Pass 3: verify pass-2's shape + optionally verify aggregator +
    // ConstantGate injection (only when modelling the 2-verify outer)
    // + NoopGate pad to `inner_pad_bits`.
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);
    let proof = builder.add_virtual_proof_with_pis(&data.common);
    let verifier_data = builder.add_virtual_verifier_data(data.common.config.fri_config.cap_height);
    builder.verify_proof::<C>(&proof, &verifier_data, &data.common);
    if let Some(agg) = aggregator {
        let agg_proof = builder.add_virtual_proof_with_pis(&agg.common);
        let agg_vd = builder.constant_verifier_data(&agg.verifier_only);
        builder.verify_proof::<C>(&agg_proof, &agg_vd, &agg.common);
        // Inject one `ConstantGate{num_consts:2}` so pass-3's gates
        // list matches the outer's emitted shape (the outer's
        // `build_circuit` adds the same instance right before
        // `_or_dummy`). Zero constants — only the instance existence
        // matters for the gate-set equality check.
        builder.add_gate(ConstantGate::new(2), vec![F::ZERO, F::ZERO]);
    }
    while builder.num_gates() < 1 << inner_pad_bits {
        builder.add_gate(NoopGate, vec![]);
    }
    builder.build::<C>().common
}

/// Element-wise `select` over a `HashOutTarget`. Returns `if_true` if
/// `cond` is true, else `if_false`. Used to mask off conditional
/// constraints by retargetting `connect_hashes(computed, expected)` to
/// `connect_hashes(computed, select_hash(cond, expected_witness,
/// computed))` — when `cond = false` the resulting target collapses to
/// `computed` and the constraint is trivially satisfied.
fn select_hash(
    builder: &mut CircuitBuilder<F, D>,
    cond: BoolTarget,
    if_true: HashOutTarget,
    if_false: HashOutTarget,
) -> HashOutTarget {
    let mut out = [builder.zero(); 4];
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = builder.select(cond, if_true.elements[i], if_false.elements[i]);
    }
    HashOutTarget { elements: out }
}

/// Witness targets for one out-coin slot. Each `StateTransitionCircuit`
/// reserves [`MAX_OUT_COINS`] of these and processes them after the
/// in-coins loop. An active slot:
/// - proves SMT non-inclusion of `out_coin_identifier` at the running
///   `output_coins_root` and computes the new root after inserting it;
/// - subtracts the coin's amount from the running balance with a
///   64-bit underflow check;
/// - asserts `out_coin_identifier == Poseidon(interim_asth ||
///   slot_index)` where `interim_asth` is the account-state hash
///   computed after the in-coins loop with the INITIAL pubkey
///   (mirroring the off-circuit `calculate_coin_identifier`).
///
/// Inactive slots are masked no-ops on all three constraints.
pub struct OutCoinSlotTargets {
    /// 1 → this slot is processed; 0 → no-op.
    pub active: BoolTarget,
    /// Coin's identifier. Must equal `Poseidon(interim_asth || index)`
    /// for an active slot; the in-circuit equality check is masked.
    pub out_coin_identifier: HashOutTarget,
    /// Lower 32 bits of the coin's amount.
    pub out_coin_amount_lo: Target,
    /// Upper 32 bits of the coin's amount.
    pub out_coin_amount_hi: Target,
    /// 256 SMT siblings proving non-inclusion of `out_coin_identifier`
    /// at the running `output_coins_root` *before* the insert.
    pub nip_path: Vec<HashOutTarget>,
}

/// Witness targets for one in-coin slot. Each `StateTransitionCircuit`
/// reserves [`MAX_IN_COINS`] of these and processes them in order; an
/// `active = false` slot is a no-op that passes both `coin_history_root`
/// and `account_state.balance` through unchanged.
///
/// Per SPEC §8 stage 5d-next-3 the slot wires the **coin-history side**
/// of the in-coins predicate (SMT non-inclusion-then-insert) plus the
/// per-coin `apply_coin` semantics (`coin.recipient == account.owner`
/// and a balance-overflow-checked add). Stage 5d-next-5 Phase 2b
/// extends each slot with the **source-side** checks (SPEC §8 step 2):
/// SMT inclusion of `coin.identifier` in the source proof's
/// `output_coins_root`, plus the SPEC §8 (c)(d)(e) chain for the
/// source's own commitment in `history_root`. All Phase 2b constraints
/// are masked by `active`, so an inactive slot remains a vacuous no-op
/// with arbitrary witness values.
pub struct InCoinSlotTargets {
    /// 1 → this slot inserts `coin_identifier` into `coin_history_root`,
    /// applies the coin to the running balance, AND requires the
    /// aggregator's slot-`i` source proof to verify against this
    /// circuit's verifier-key and to satisfy every Phase 2b source-side
    /// check listed below.
    /// 0 → slot is a no-op (all in-circuit constraints masked off).
    ///
    /// This bit is `connect`-bound to the aggregator's slot-`i`
    /// `active` PI, so the in-coin loop and the aggregator stay in
    /// lockstep: there is no way to consume an in-coin without a
    /// verified source proof.
    pub active: BoolTarget,
    /// Coin's unique identifier. Used both as the SMT *key* (its 256
    /// bits select the leaf position) and the SMT *value* (so the
    /// coin_history SMT acts as a SET membership structure). In Phase
    /// 2b the same identifier is the SMT key in the SOURCE's
    /// `output_coins_root` inclusion check.
    pub coin_identifier: HashOutTarget,
    /// Recipient address the coin claims to be sent to. The
    /// `apply_coin` predicate enforces `recipient == account.owner` —
    /// only the owning account can absorb a coin. Masked by `active`.
    pub coin_recipient: HashOutTarget,
    /// Lower 32 bits of the coin's amount (u64 packed as 2× 32-bit
    /// limbs, matching the off-circuit `AccountState::hash` layout).
    pub coin_amount_lo: Target,
    /// Upper 32 bits of the coin's amount.
    pub coin_amount_hi: Target,
    /// 256 SMT siblings proving non-inclusion of `coin_identifier` at
    /// `coin_history_root` *before* the insert. The same path is then
    /// used to compute the new root after inserting the coin.
    pub nip_path: Vec<HashOutTarget>,
    /// Stage 5d-next-5 Phase 2b: 256 SMT siblings proving inclusion of
    /// `coin_identifier` in the SOURCE proof's `output_coins_root`
    /// (extracted from the aggregator's slot-`i` PIs). Masked by
    /// `active`. Leaf value is `Poseidon(coin_identifier ||
    /// coin_identifier)`, matching the set-membership SMT convention
    /// used throughout the project.
    pub source_inclusion_path: Vec<HashOutTarget>,
    /// Stage 5d-next-5 Phase 2b: full `CommitmentMerkleProofs` bundle
    /// for the SOURCE proof's commitment in the global `history_root`.
    /// Shape matches the outer's prev-account [`cmp`]; the in-circuit
    /// (c)(d)(e) chain is replicated against these targets, all masked
    /// by `active`.
    ///
    /// [`cmp`]: StateTransitionCircuit::cmp
    pub source_cmp: CommitmentMerkleProofsTargets,
}

/// Witness targets for the SPEC §8 `CommitmentMerkleProofs` predicate,
/// bundled so they can be threaded through [`StateTransitionCircuit`]
/// and [`set_cmp_witness`] in one shot.
///
/// Sizes are pinned to the fixed-shape constants
/// ([`TREE_DEPTH`] for the SMT, [`MMR_PROOF_PATH_LEN`] for the MMR
/// proofs) so the verifier circuit has a stable `circuit_digest`.
pub struct CommitmentMerkleProofsTargets {
    /// SMT root containing the prev proof's commitment leaf.
    pub commitment_root: HashOutTarget,
    /// SMT key at which the commitment is stored (= hash of prev pubkey).
    pub smt_key: HashOutTarget,
    /// 256 sibling hashes along the SMT path (level 0 = topmost).
    pub smt_path: Vec<HashOutTarget>,
    /// MMR-proof (d) index: leaf position of `(commitment_root,
    /// commitment_root_mmr_sibling)` in the history MMR.
    pub mmr_a_index: Target,
    /// MMR-proof (d) path: 31 sibling hashes.
    pub mmr_a_path: Vec<HashOutTarget>,
    /// The previous MMR root at the time `commitment_root` was folded
    /// in — paired with `commitment_root` to form the MMR leaf for (d).
    pub commitment_root_mmr_sibling: HashOutTarget,
    /// The SMT root committed to the MMR alongside `prev.commitment_history_root`
    /// for proof (e).
    pub prev_smt_in_mmr_leaf: HashOutTarget,
    /// MMR-proof (e) index.
    pub mmr_b_index: Target,
    /// MMR-proof (e) path: 31 sibling hashes.
    pub mmr_b_path: Vec<HashOutTarget>,
    /// Witness for SPEC §8 (c): the account-state-hash committed to by
    /// the prev proof. Constrained to equal `account_state_hash`
    /// in-circuit (under `condition`).
    pub commitment_account_state_hash: HashOutTarget,
    /// Witness for the second half of the commitment preimage:
    /// `commitment = h(asth || ocr)`. Constrained implicitly by the
    /// SMT inclusion check — the commitment value computed in-circuit
    /// must match what the SMT stores.
    pub commitment_out_coins_root: HashOutTarget,
}

/// Handle to the built state-transition circuit plus the witness
/// targets a caller needs to populate when proving.
///
/// `data.verifier_only.circuit_digest` is the verifier-key digest that
/// gets pinned as a public input via [`Self::verifier_data_target`];
/// binding this digest is what makes the recursion *cyclic*: a proof of
/// this circuit can only be verified by this same circuit.
pub struct StateTransitionCircuit {
    /// Built circuit (proving + verification keys, common data).
    pub data: CircuitData<F, C, D>,
    /// Verifier shape that recursive inner proofs are checked against.
    /// Equal to `data.common` up to the cyclic-recursion fixed-point.
    pub common_data: CommonCircuitData<F, D>,
    /// Public-input slots reserved for the verifier-key digest +
    /// constants-sigmas cap (set via `set_verifier_data_target` each
    /// prove).
    pub verifier_data_target: VerifierCircuitTarget,
    /// Branch selector. `false` → Initial (dummy inner), `true` →
    /// AccountUpdate (real inner). Free witness as of Stage 5c.
    pub condition: BoolTarget,
    /// Inner proof slot. Initial uses [`cyclic_base_proof`] dummy;
    /// AccountUpdate uses a real prev `ProofWithPublicInputs`.
    pub inner_proof_target: ProofWithPublicInputsTarget<D>,
    /// 20 public-input slots for `ProofData::to_field_elements`.
    pub proof_data_pis: [Target; N_PROOF_DATA_PUBLIC_INPUTS],
    /// Witness target: `account_state.owner` (4 field elements).
    pub owner: HashOutTarget,
    /// Witness target: balance lower 32 bits.
    pub balance_lo: Target,
    /// Witness target: balance upper 32 bits.
    pub balance_hi: Target,
    /// Witness targets: 33-byte compressed pubkey packed as 5×56-bit
    /// limbs (the last limb holds the trailing 5 bytes + 3 zero pads).
    pub pubkey_limbs: [Target; 5],
    /// Witness target: the current commitment-history root.
    pub history_root: HashOutTarget,
    /// CommitmentMerkleProofs witness bundle. Constraints fire only
    /// when `condition = true` (AccountUpdate branch).
    pub cmp: CommitmentMerkleProofsTargets,
    /// `MAX_IN_COINS` in-coin slot witnesses processed in order.
    /// Active slots advance `coin_history_root` via SMT non-inclusion
    /// + insert; inactive slots pass it through unchanged.
    pub in_coin_slots: Vec<InCoinSlotTargets>,
    /// `MAX_OUT_COINS` out-coin slot witnesses processed in order
    /// after the in-coins loop. Active slots advance
    /// `output_coins_root` and subtract the coin amount from the
    /// running balance.
    pub out_coin_slots: Vec<OutCoinSlotTargets>,
    /// 5×56-bit limbs of the new account public key the proof rotates
    /// to. The FINAL `account_state_hash` (committed to `ProofData`)
    /// uses these limbs; `pubkey_limbs` (the INITIAL pubkey) is used
    /// only for SPEC §8 (b)+(c) checks and for the interim hash
    /// driving out-coin identifier derivation.
    pub next_public_key_limbs: [Target; 5],

    // ===== Issuer-gated mint witnesses (neutral multi-asset) =====
    /// 5×56-bit limbs of the asset creator's public key. Private
    /// witness (NOT a public input). Used by the issuer gate to derive
    /// the asset id and to bind `account.public_key == creator_pubkey`.
    /// For a legitimate issuer-mint these limbs are the minting account's
    /// initial pubkey; for non-mint transitions they are unconstrained
    /// (the gate they feed is masked off when `is_minting = false`).
    pub creator_pubkey_limbs: [Target; 5],
    /// The asset's name hash (4 elements). Private witness. Folds into
    /// the in-circuit `derived_asset_id` preimage.
    pub name_hash: HashOutTarget,
    /// The asset's decimals (range-checked to 8 bits). Private witness.
    pub decimals: Target,
    /// The account's own `asset_id` (4 elements). Private witness, fed
    /// into the 15-F `account_state_hash` and bound to
    /// `transition_asset_id` so the account can only hold its own asset.
    pub account_asset_id: HashOutTarget,

    // ===== Stage 5d-next-5 additions =====
    /// Source-proof aggregator circuit built against this circuit's
    /// `common_data`. The outer verifies an aggregator proof via the
    /// `aggregator_proof_target` slot below and `connect_hashes`-binds
    /// the aggregator's claimed state-transition `verifier_data` to
    /// its own.
    pub aggregator: SourceAggregatorCircuit,
    /// Witness target for the aggregator's proof. The outer verifies
    /// this proof against the aggregator's fixed (constant-baked)
    /// `verifier_data`. Its public inputs carry per-slot source
    /// `ProofData` and the claimed state-transition `verifier_data`
    /// that the outer `connect_hashes`-binds to its own.
    pub aggregator_proof_target: ProofWithPublicInputsTarget<D>,
}

/// Build the Stage-5c+ state-transition circuit.
///
/// Beyond the 5b/5c predicate, this revision wires SPEC §8 (c)(d)(e)
/// against fixed-shape SMT + MMR inclusion proofs. See module docstring
/// for the constraint breakdown and the masking pattern.
pub fn build_circuit() -> StateTransitionCircuit {
    // ===== Build aggregator + state-transition common via fixed-point =====
    //
    // Both shapes depend on each other: the aggregator's source-proof
    // targets are sized by st_common; the outer's
    // `verify_proof(aggregator_proof)` is sized by agg.common.
    //
    // Bootstrap with the Stage 5d-next-3 shape (`dummy_circuit`-safe
    // by construction). Compute the Stage 5d-next-5 `common_data`
    // (which embeds a `verify_proof(agg)` + a `ConstantGate`
    // injection). Rebuild the aggregator against the final
    // `common_data` so its source-proof targets fit the outer's
    // actual cyclic shape, then verify the fixed point converged.
    let outer_num_pis = state_transition_num_pis();
    let mut bootstrap_st_common = common_data_for_recursion_c();
    bootstrap_st_common.num_public_inputs = outer_num_pis;
    let mut aggregator = build_source_aggregator_circuit(&bootstrap_st_common);
    let mut common_data =
        common_data_for_recursion_c_inner(Some(&aggregator.data), INNER_PAD_BITS_STAGE_5D_NEXT_5);
    common_data.num_public_inputs = outer_num_pis;
    aggregator = build_source_aggregator_circuit(&common_data);
    let mut next_common_data =
        common_data_for_recursion_c_inner(Some(&aggregator.data), INNER_PAD_BITS_STAGE_5D_NEXT_5);
    next_common_data.num_public_inputs = outer_num_pis;
    assert_eq!(
        common_data, next_common_data,
        "Stage 5d-next-5 fixed-point did not converge in 2 iterations — \
         aggregator common shape unstable across rebuilds"
    );

    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // Regular public inputs first — must precede
    // `add_verifier_data_public_inputs` per Plonky2 contract.
    let proof_data_pis: [Target; N_PROOF_DATA_PUBLIC_INPUTS] =
        std::array::from_fn(|_| builder.add_virtual_public_input());

    let transition_asset_id = HashOutTarget {
        elements: [
            proof_data_pis[16],
            proof_data_pis[17],
            proof_data_pis[18],
            proof_data_pis[19],
        ],
    };

    let verifier_data_target = builder.add_verifier_data_public_inputs();
    debug_assert_eq!(
        builder.num_public_inputs(),
        outer_num_pis,
        "outer's PI count must match the value used to size st_common"
    );
    common_data.num_public_inputs = builder.num_public_inputs();

    let condition = builder.add_virtual_bool_target_safe();
    let inner_proof_target = builder.add_virtual_proof_with_pis(&common_data);

    // Extract prev's ProofData fields from the inner proof's PI slots.
    let prev_account_state_hash = HashOutTarget {
        elements: [
            inner_proof_target.public_inputs[0],
            inner_proof_target.public_inputs[1],
            inner_proof_target.public_inputs[2],
            inner_proof_target.public_inputs[3],
        ],
    };
    let prev_commitment_history_root = HashOutTarget {
        elements: [
            inner_proof_target.public_inputs[8],
            inner_proof_target.public_inputs[9],
            inner_proof_target.public_inputs[10],
            inner_proof_target.public_inputs[11],
        ],
    };
    let prev_coin_history_root = HashOutTarget {
        elements: [
            inner_proof_target.public_inputs[12],
            inner_proof_target.public_inputs[13],
            inner_proof_target.public_inputs[14],
            inner_proof_target.public_inputs[15],
        ],
    };

    // ===== Witness AccountState + history =====

    let owner = builder.add_virtual_hash();
    let balance_lo = builder.add_virtual_target();
    let balance_hi = builder.add_virtual_target();
    builder.range_check(balance_lo, 32);
    builder.range_check(balance_hi, 32);

    let pubkey_limbs: [Target; 5] = std::array::from_fn(|_| {
        let t = builder.add_virtual_target();
        builder.range_check(t, 56);
        t
    });

    let history_root = builder.add_virtual_hash();

    // The account's own asset_id (witnessed) and the global transition
    // asset_id (a public input). They must coincide: an account only
    // ever holds its own asset. This binding is UNMASKED — it holds for
    // BOTH Initial and AccountUpdate branches.
    let account_asset_id = builder.add_virtual_hash();
    for i in 0..4 {
        builder.connect(
            account_asset_id.elements[i],
            transition_asset_id.elements[i],
        );
    }

    // ===== Issuer-gated mint predicate (neutral, permissionless) =====
    //
    // There is no privileged minting authority. The "mint exception"
    // (relaxing the "Initial balance must be 0" rule) is granted ONLY to
    // an account that proves it is the legitimate issuer of its own
    // asset, i.e.:
    //   transition_aid     == calculate_asset_id(creator_pubkey, name_hash, decimals)
    //   account.public_key == creator_pubkey
    // Both are checked cheaply in-circuit from private witnesses
    // (`creator_pubkey_limbs`, `name_hash`, `decimals`). Anyone can mint
    // THEIR OWN asset; nobody can forge or inflate someone else's, because
    // forging would require a `creator_pubkey` that both derives the
    // victim's `asset_id` AND equals the account's own commitment key.
    //
    // The account `owner` is the protocol address `H(Pk₀) = SHA-256(pubkey)`
    // (off-circuit, #226); it is NOT bound to the creator key here. (The
    // legacy in-circuit `owner == Poseidon(creator_pubkey)` binding was
    // removed — Variant B — to make the owner consistent with the SHA-256
    // address used by the wallet/SDK, username-claim and SMT.)
    let creator_pubkey_limbs: [Target; 5] = std::array::from_fn(|_| {
        let t = builder.add_virtual_target();
        builder.range_check(t, 56);
        t
    });
    let name_hash = builder.add_virtual_hash();
    let decimals = builder.add_virtual_target();
    builder.range_check(decimals, 8);

    // derived_asset_id = Poseidon(genesis_tag[4] || creator_pubkey[5] ||
    // name_hash[4] || decimals[1]) — matches off-circuit
    // `crate::types::calculate_asset_id` (14-element fixed-width preimage).
    let genesis_tag = builder.constant_hash(HashOut {
        elements: ASSET_GENESIS_DOMAIN_TAG.elements,
    });
    let mut derived_aid_input: Vec<Target> = Vec::with_capacity(14);
    derived_aid_input.extend_from_slice(&genesis_tag.elements);
    derived_aid_input.extend_from_slice(&creator_pubkey_limbs);
    derived_aid_input.extend_from_slice(&name_hash.elements);
    derived_aid_input.push(decimals);
    let derived_asset_id = builder.hash_n_to_hash_no_pad::<PoseidonHash>(derived_aid_input);

    // asset_ok   = AND over 4 elems (derived_asset_id == transition_asset_id)
    // is_minting = asset_ok AND (account.public_key == creator_pubkey, below)
    //
    // The `owner == Poseidon(creator_pubkey)` binding was removed (#226,
    // Variant B): `owner` is the off-circuit SHA-256 address, so it cannot
    // be cheaply re-derived in-circuit, and forge protection is fully held
    // by the asset_id derivation here plus the `public_key == creator`
    // binding below (and the off-circuit creator signature at commit time).
    let mut is_minting = builder._true();
    for i in 0..4 {
        let aid_eq = builder.is_equal(
            derived_asset_id.elements[i],
            transition_asset_id.elements[i],
        );
        is_minting = builder.and(is_minting, aid_eq);
    }
    // Bind the creator key to the account's own commitment key. The
    // account's `public_key` (`pubkey_limbs`) is the key that signs the
    // Bitcoin commitment verified at scan time; a mint may only be
    // authorized by the asset's creator, so that signer MUST be the
    // creator. Without this, a forger could witness owner==H(victim_pk)
    // and asset_id==calculate_asset_id(victim_pk, ...) (both attacker-
    // chosen public values) while signing the commitment with their OWN
    // key — minting/inflating a foreign asset. Folding pubkey==creator
    // into `is_minting` closes that path: the mint exception is then
    // only granted when the commitment signer is provably the creator.
    for j in 0..5 {
        let pk_eq = builder.is_equal(creator_pubkey_limbs[j], pubkey_limbs[j]);
        is_minting = builder.and(is_minting, pk_eq);
    }
    let not_minting = builder.not(is_minting);
    let not_condition = builder.not(condition);

    // Mint exception (Initial-only): a non-mint Initial account must
    // start with balance 0; only a valid issuer-mint may start with a
    // non-zero (minted) supply.
    let mint_mask = builder.mul(not_condition.target, not_minting.target);
    let mul_lo = builder.mul(mint_mask, balance_lo);
    builder.assert_zero(mul_lo);
    let mul_hi = builder.mul(mint_mask, balance_hi);
    builder.assert_zero(mul_hi);

    // Compute in-circuit account_state_hash. Layout per
    // AccountState::hash: owner (4) + balance_lo + balance_hi + pubkey
    // (5) + asset_id (4) = 15 F.
    let mut state_elements: Vec<Target> = Vec::with_capacity(15);
    state_elements.extend_from_slice(&owner.elements);
    state_elements.push(balance_lo);
    state_elements.push(balance_hi);
    state_elements.extend_from_slice(&pubkey_limbs);
    state_elements.extend_from_slice(&account_asset_id.elements);
    let account_state_hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(state_elements);

    // SPEC §8 (b) — state continuity (AccountUpdate-only):
    for i in 0..4 {
        let diff = builder.sub(
            account_state_hash.elements[i],
            prev_account_state_hash.elements[i],
        );
        let masked = builder.mul(condition.target, diff);
        builder.assert_zero(masked);
    }

    // ===== CommitmentMerkleProofs witness bundle =====

    let cmp = CommitmentMerkleProofsTargets {
        commitment_root: builder.add_virtual_hash(),
        smt_key: builder.add_virtual_hash(),
        smt_path: (0..TREE_DEPTH)
            .map(|_| builder.add_virtual_hash())
            .collect(),
        mmr_a_index: builder.add_virtual_target(),
        mmr_a_path: (0..MMR_PROOF_PATH_LEN)
            .map(|_| builder.add_virtual_hash())
            .collect(),
        commitment_root_mmr_sibling: builder.add_virtual_hash(),
        prev_smt_in_mmr_leaf: builder.add_virtual_hash(),
        mmr_b_index: builder.add_virtual_target(),
        mmr_b_path: (0..MMR_PROOF_PATH_LEN)
            .map(|_| builder.add_virtual_hash())
            .collect(),
        commitment_account_state_hash: builder.add_virtual_hash(),
        commitment_out_coins_root: builder.add_virtual_hash(),
    };

    // SPEC §8 (c): account_state_hash == cmp.commitment_account_state_hash,
    // masked with `condition`.
    for i in 0..4 {
        let diff = builder.sub(
            account_state_hash.elements[i],
            cmp.commitment_account_state_hash.elements[i],
        );
        let masked = builder.mul(condition.target, diff);
        builder.assert_zero(masked);
    }

    // SPEC §8 (d), first half: commitment = h(asth || ocr), SMT inclusion
    // of `commitment` at `smt_key` in `commitment_root`.
    let mut commitment_input = Vec::with_capacity(8);
    commitment_input.extend_from_slice(&cmp.commitment_account_state_hash.elements);
    commitment_input.extend_from_slice(&cmp.commitment_out_coins_root.elements);
    let commitment = builder.hash_n_to_hash_no_pad::<PoseidonHash>(commitment_input);

    let smt_key_bits = key_bits_msb_first(&mut builder, cmp.smt_key);
    let smt_computed_root = smt_inclusion_root(
        &mut builder,
        commitment,
        cmp.smt_key,
        &smt_key_bits,
        &cmp.smt_path,
    );
    let smt_target_root = select_hash(
        &mut builder,
        condition,
        cmp.commitment_root,
        smt_computed_root,
    );
    builder.connect_hashes(smt_computed_root, smt_target_root);

    // SPEC §8 (d), second half: MMR inclusion of
    // h(commitment_root || commitment_root_mmr_sibling) in history_root.
    let mut mmr_a_leaf_input = Vec::with_capacity(8);
    mmr_a_leaf_input.extend_from_slice(&cmp.commitment_root.elements);
    mmr_a_leaf_input.extend_from_slice(&cmp.commitment_root_mmr_sibling.elements);
    let mmr_a_leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(mmr_a_leaf_input);
    let mmr_a_index_bits = builder.split_le(cmp.mmr_a_index, MMR_PROOF_PATH_LEN);
    let mmr_a_computed =
        mmr_inclusion_root(&mut builder, mmr_a_leaf, &mmr_a_index_bits, &cmp.mmr_a_path);
    let mmr_a_target = select_hash(&mut builder, condition, history_root, mmr_a_computed);
    builder.connect_hashes(mmr_a_computed, mmr_a_target);

    // SPEC §8 (e): MMR inclusion of
    // h(prev_smt_in_mmr_leaf || prev.commitment_history_root) in history_root.
    let mut mmr_b_leaf_input = Vec::with_capacity(8);
    mmr_b_leaf_input.extend_from_slice(&cmp.prev_smt_in_mmr_leaf.elements);
    mmr_b_leaf_input.extend_from_slice(&prev_commitment_history_root.elements);
    let mmr_b_leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(mmr_b_leaf_input);
    let mmr_b_index_bits = builder.split_le(cmp.mmr_b_index, MMR_PROOF_PATH_LEN);
    let mmr_b_computed =
        mmr_inclusion_root(&mut builder, mmr_b_leaf, &mmr_b_index_bits, &cmp.mmr_b_path);
    let mmr_b_target = select_hash(&mut builder, condition, history_root, mmr_b_computed);
    builder.connect_hashes(mmr_b_computed, mmr_b_target);

    // ===== Stage 5d-next-5: hoisted aggregator-verify + vk binding =====
    //
    // Hoisted BEFORE the in-coin loop so each slot can read its source
    // proof's `ProofData` straight off the aggregator's per-slot PIs.
    //
    // Verify the aggregator proof against the aggregator's
    // constant-baked verifier_data. `connect_hashes` then binds the
    // aggregator's claimed state-transition verifier_data to the
    // outer's OWN `verifier_data_target` — a wrong-vk aggregator proof
    // (one whose `conditionally_verify_proof` ran against a different
    // state-transition circuit's `verifier_only`) carries a different
    // claimed digest and fails this binding.
    let aggregator_proof_target = builder.add_virtual_proof_with_pis(&aggregator.data.common);
    let aggregator_vd_target = builder.constant_verifier_data(&aggregator.data.verifier_only);
    builder.verify_proof::<C>(
        &aggregator_proof_target,
        &aggregator_vd_target,
        &aggregator.data.common,
    );

    let st_vk_offset = MAX_IN_COINS * PER_SLOT_PIS;
    let claimed_st_digest = HashOutTarget {
        elements: [
            aggregator_proof_target.public_inputs[st_vk_offset],
            aggregator_proof_target.public_inputs[st_vk_offset + 1],
            aggregator_proof_target.public_inputs[st_vk_offset + 2],
            aggregator_proof_target.public_inputs[st_vk_offset + 3],
        ],
    };
    builder.connect_hashes(claimed_st_digest, verifier_data_target.circuit_digest);

    let sigmas_cap_offset = st_vk_offset + N_ST_VK_DIGEST_PIS;
    for (i, cap_hash) in verifier_data_target
        .constants_sigmas_cap
        .0
        .iter()
        .enumerate()
    {
        let base = sigmas_cap_offset + 4 * i;
        let claimed = HashOutTarget {
            elements: [
                aggregator_proof_target.public_inputs[base],
                aggregator_proof_target.public_inputs[base + 1],
                aggregator_proof_target.public_inputs[base + 2],
                aggregator_proof_target.public_inputs[base + 3],
            ],
        };
        builder.connect_hashes(claimed, *cap_hash);
    }

    // Coin-history carry-over: starting value picks prev's
    // coin_history_root for AccountUpdate, empty SMT root for Initial.
    let empty_root = builder.constant_hash(DEFAULT_HASHES[0]);
    let empty_leaf_default = builder.constant_hash(DEFAULT_HASHES[TREE_DEPTH]);
    let mut running_coin_history_elements = [builder.zero(); 4];
    for (i, slot) in running_coin_history_elements.iter_mut().enumerate() {
        *slot = builder.select(
            condition,
            prev_coin_history_root.elements[i],
            empty_root.elements[i],
        );
    }
    let mut running_coin_history = HashOutTarget {
        elements: running_coin_history_elements,
    };

    // Per-slot in-coin processing. Each active slot:
    //   - proves SMT non-inclusion of `coin_identifier` at
    //     `running_coin_history` and inserts it (set-membership SMT);
    //   - asserts `coin_recipient == account.owner` (apply_coin);
    //   - adds `coin_amount` to the running balance with a 32-bit
    //     limb-by-limb add + carry, asserting no top-level overflow.
    // Inactive slots are masked no-ops on both `coin_history_root` and
    // `(balance_lo, balance_hi)`.
    let in_coin_slots: Vec<InCoinSlotTargets> = (0..MAX_IN_COINS)
        .map(|_| InCoinSlotTargets {
            active: builder.add_virtual_bool_target_safe(),
            coin_identifier: builder.add_virtual_hash(),
            coin_recipient: builder.add_virtual_hash(),
            coin_amount_lo: {
                let t = builder.add_virtual_target();
                builder.range_check(t, 32);
                t
            },
            coin_amount_hi: {
                let t = builder.add_virtual_target();
                builder.range_check(t, 32);
                t
            },
            nip_path: (0..TREE_DEPTH)
                .map(|_| builder.add_virtual_hash())
                .collect(),
            // Stage 5d-next-5 Phase 2b: per-slot source-side witnesses.
            // SMT inclusion path + full CMP bundle for the source proof's
            // commitment chain. Allocated once per slot; the source-side
            // gates fire inside the in-coin loop below, masked by
            // `active` so inactive slots are vacuous no-ops.
            source_inclusion_path: (0..TREE_DEPTH)
                .map(|_| builder.add_virtual_hash())
                .collect(),
            source_cmp: CommitmentMerkleProofsTargets {
                commitment_root: builder.add_virtual_hash(),
                smt_key: builder.add_virtual_hash(),
                smt_path: (0..TREE_DEPTH)
                    .map(|_| builder.add_virtual_hash())
                    .collect(),
                mmr_a_index: builder.add_virtual_target(),
                mmr_a_path: (0..MMR_PROOF_PATH_LEN)
                    .map(|_| builder.add_virtual_hash())
                    .collect(),
                commitment_root_mmr_sibling: builder.add_virtual_hash(),
                prev_smt_in_mmr_leaf: builder.add_virtual_hash(),
                mmr_b_index: builder.add_virtual_target(),
                mmr_b_path: (0..MMR_PROOF_PATH_LEN)
                    .map(|_| builder.add_virtual_hash())
                    .collect(),
                commitment_account_state_hash: builder.add_virtual_hash(),
                commitment_out_coins_root: builder.add_virtual_hash(),
            },
        })
        .collect();

    // Running balance evolves through the slots; starts at the
    // witnessed `(balance_lo, balance_hi)` — which is INITIAL state
    // per SPEC §8 (the balance the prev proof committed to on
    // AccountUpdate, or the start balance on Initial).
    let mut running_balance_lo = balance_lo;
    let mut running_balance_hi = balance_hi;
    let two_pow_32 = builder.constant(F::from_canonical_u64(1u64 << 32));

    for (slot_idx, slot) in in_coin_slots.iter().enumerate() {
        let coin_id_bits = key_bits_msb_first(&mut builder, slot.coin_identifier);

        // --- Coin-history non-inclusion + insert (masked) ---
        let computed_old = hash_up_full_path(
            &mut builder,
            empty_leaf_default,
            &coin_id_bits,
            &slot.nip_path,
        );
        let target_old = select_hash(
            &mut builder,
            slot.active,
            running_coin_history,
            computed_old,
        );
        builder.connect_hashes(computed_old, target_old);

        let mut new_leaf_input = Vec::with_capacity(8);
        new_leaf_input.extend_from_slice(&slot.coin_identifier.elements);
        new_leaf_input.extend_from_slice(&slot.coin_identifier.elements);
        let new_leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(new_leaf_input);
        let computed_new = hash_up_full_path(&mut builder, new_leaf, &coin_id_bits, &slot.nip_path);
        running_coin_history = select_hash(
            &mut builder,
            slot.active,
            computed_new,
            running_coin_history,
        );

        // --- Recipient check (masked) ---
        // `active * (coin_recipient[i] - owner[i]) == 0` for i in 0..4.
        for i in 0..4 {
            let diff = builder.sub(slot.coin_recipient.elements[i], owner.elements[i]);
            let masked = builder.mul(slot.active.target, diff);
            builder.assert_zero(masked);
        }

        // --- Balance addition with overflow check (masked) ---
        // u64 balance = balance_hi * 2^32 + balance_lo. Add active *
        // coin_amount via limb-by-limb with carry; assert top-level
        // overflow is zero. For inactive slots, masked_amount is 0 and
        // the carry/overflow bits settle to zero, leaving the running
        // balance unchanged.
        //
        // `split_le(sum, 33)` decomposes a value in [0, 2^33) into 33
        // bits; bits are auto-witnessed by Plonky2's `BaseSumGate`
        // generator. The high bit at index 32 is the carry / overflow.
        // We reconstitute `new_lo = sum_lo - 2^32 * carry` via
        // subtraction, which is exactly the low 32 bits of `sum_lo`.
        let active_t = slot.active.target;
        let masked_amount_lo = builder.mul(active_t, slot.coin_amount_lo);
        let masked_amount_hi = builder.mul(active_t, slot.coin_amount_hi);

        let sum_lo = builder.add(running_balance_lo, masked_amount_lo);
        let lo_bits = builder.split_le(sum_lo, 33);
        let carry = lo_bits[32];
        let carry_shifted = builder.mul(two_pow_32, carry.target);
        let new_lo = builder.sub(sum_lo, carry_shifted);

        let sum_hi_pre = builder.add(running_balance_hi, masked_amount_hi);
        let sum_hi = builder.add(sum_hi_pre, carry.target);
        let hi_bits = builder.split_le(sum_hi, 33);
        let overflow = hi_bits[32];
        let overflow_shifted = builder.mul(two_pow_32, overflow.target);
        let new_hi = builder.sub(sum_hi, overflow_shifted);
        // No top-level overflow allowed.
        builder.assert_zero(overflow.target);

        running_balance_lo = new_lo;
        running_balance_hi = new_hi;

        // ===== Stage 5d-next-5 Phase 2b: per-slot source-side checks =====
        //
        // Per SPEC §8 step 2 every active in-coin slot must witness a
        // source state-transition proof whose `output_coins_root`
        // contains `coin_identifier`, AND that source proof's
        // commitment must be published in the global `history_root` via
        // the (c)(d)(e) chain.
        //
        // The aggregator (verified at outer build via `verify_proof(agg)`
        // hoisted above the in-coin loop) exposes per-slot source
        // `ProofData` as PIs at offset `slot_idx * PER_SLOT_PIS`.
        //
        // Every gate below is masked by `slot.active` so inactive slots
        // are vacuous: the aggregator's slot bit is `connect`-bound to
        // `slot.active`, so an inactive slot necessarily has the
        // aggregator's matching `active` PI = 0 and a dummy proof on
        // the aggregator side.

        let agg_base = slot_idx * PER_SLOT_PIS;
        let source_account_state_hash = HashOutTarget {
            elements: [
                aggregator_proof_target.public_inputs[agg_base],
                aggregator_proof_target.public_inputs[agg_base + 1],
                aggregator_proof_target.public_inputs[agg_base + 2],
                aggregator_proof_target.public_inputs[agg_base + 3],
            ],
        };
        let source_output_coins_root = HashOutTarget {
            elements: [
                aggregator_proof_target.public_inputs[agg_base + 4],
                aggregator_proof_target.public_inputs[agg_base + 5],
                aggregator_proof_target.public_inputs[agg_base + 6],
                aggregator_proof_target.public_inputs[agg_base + 7],
            ],
        };
        let source_commitment_history_root = HashOutTarget {
            elements: [
                aggregator_proof_target.public_inputs[agg_base + 8],
                aggregator_proof_target.public_inputs[agg_base + 9],
                aggregator_proof_target.public_inputs[agg_base + 10],
                aggregator_proof_target.public_inputs[agg_base + 11],
            ],
        };
        // `[agg_base + 12 .. agg_base + 16]` is the source's
        // `coin_history_root` — unused for §8 step 2 (it only ever
        // matters for an account's OWN in-coins).
        // `[agg_base + 16 .. agg_base + 20]` is the source's `asset_id`.
        let source_active_pi = aggregator_proof_target.public_inputs[agg_base + 20];

        let source_asset_id = HashOutTarget {
            elements: [
                aggregator_proof_target.public_inputs[agg_base + 16],
                aggregator_proof_target.public_inputs[agg_base + 17],
                aggregator_proof_target.public_inputs[agg_base + 18],
                aggregator_proof_target.public_inputs[agg_base + 19],
            ],
        };
        for j in 0..4 {
            let diff = builder.sub(source_asset_id.elements[j], transition_asset_id.elements[j]);
            let masked = builder.mul(slot.active.target, diff);
            builder.assert_zero(masked);
        }

        // Bind outer-slot active <-> aggregator-slot active. Both are
        // bool-constrained by their respective allocators, so this
        // collapses to a strict equality. There is no way to consume
        // an in-coin without the aggregator verifying its source proof.
        builder.connect(slot.active.target, source_active_pi);

        // --- SMT inclusion of coin.identifier in source.output_coins_root ---
        //
        // The source's out-coin loop computes its new
        // `output_coins_root` via `hash_up_full_path(new_leaf,
        // id_bits, nip_path)` where `new_leaf = h(id || id)` —
        // i.e. the SMT leaf at depth `TREE_DEPTH` is the
        // pre-hashed `h(id || id)` directly, NOT
        // `smt_leaf_hash(value, key) = h(value || key)`. The off-circuit
        // [`InclusionProof::verify`] mirrors that: it computes
        // `start = leaf_hash(leaf=id, key=id) = h(id || id)`. So the
        // consumer must use the same `start` (one Poseidon hash of
        // `id || id`) — calling `smt_inclusion_root` here would
        // introduce an extra `smt_leaf_hash` step, producing a wire
        // conflict against the source's published OCR.
        let mut source_set_leaf_input = Vec::with_capacity(8);
        source_set_leaf_input.extend_from_slice(&slot.coin_identifier.elements);
        source_set_leaf_input.extend_from_slice(&slot.coin_identifier.elements);
        let source_set_leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(source_set_leaf_input);
        let source_inclusion_computed = hash_up_full_path(
            &mut builder,
            source_set_leaf,
            &coin_id_bits,
            &slot.source_inclusion_path,
        );
        let source_inclusion_target = select_hash(
            &mut builder,
            slot.active,
            source_output_coins_root,
            source_inclusion_computed,
        );
        builder.connect_hashes(source_inclusion_computed, source_inclusion_target);

        // --- Coupling: source.output_coins_root == source_cmp.commitment_out_coins_root ---
        //
        // Without this check the witnessed CMP could open the
        // commitment SMT against a DIFFERENT `output_coins_root` than
        // the one the source proof actually committed to, breaking the
        // binding between the inclusion check above and the (d) chain
        // below.
        for j in 0..4 {
            let diff = builder.sub(
                source_output_coins_root.elements[j],
                slot.source_cmp.commitment_out_coins_root.elements[j],
            );
            let masked = builder.mul(slot.active.target, diff);
            builder.assert_zero(masked);
        }

        // --- SPEC §8 (c): source.account_state_hash == source_cmp.commitment_account_state_hash ---
        for j in 0..4 {
            let diff = builder.sub(
                source_account_state_hash.elements[j],
                slot.source_cmp.commitment_account_state_hash.elements[j],
            );
            let masked = builder.mul(slot.active.target, diff);
            builder.assert_zero(masked);
        }

        // --- SPEC §8 (d), first half: SMT inclusion of commitment ---
        //
        // commitment = h(commitment_account_state_hash || commitment_out_coins_root)
        // — by (c) above and the coupling check, the in-circuit value
        // equals h(source.asth || source.ocr), which is the source
        // proof's published commitment.
        let mut source_commitment_input = Vec::with_capacity(8);
        source_commitment_input
            .extend_from_slice(&slot.source_cmp.commitment_account_state_hash.elements);
        source_commitment_input
            .extend_from_slice(&slot.source_cmp.commitment_out_coins_root.elements);
        let source_commitment =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(source_commitment_input);
        let source_smt_key_bits = key_bits_msb_first(&mut builder, slot.source_cmp.smt_key);
        let source_smt_computed = smt_inclusion_root(
            &mut builder,
            source_commitment,
            slot.source_cmp.smt_key,
            &source_smt_key_bits,
            &slot.source_cmp.smt_path,
        );
        let source_smt_target = select_hash(
            &mut builder,
            slot.active,
            slot.source_cmp.commitment_root,
            source_smt_computed,
        );
        builder.connect_hashes(source_smt_computed, source_smt_target);

        // --- SPEC §8 (d), second half: MMR inclusion of commitment_root ---
        let mut source_mmr_a_leaf_input = Vec::with_capacity(8);
        source_mmr_a_leaf_input.extend_from_slice(&slot.source_cmp.commitment_root.elements);
        source_mmr_a_leaf_input
            .extend_from_slice(&slot.source_cmp.commitment_root_mmr_sibling.elements);
        let source_mmr_a_leaf =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(source_mmr_a_leaf_input);
        let source_mmr_a_index_bits =
            builder.split_le(slot.source_cmp.mmr_a_index, MMR_PROOF_PATH_LEN);
        let source_mmr_a_computed = mmr_inclusion_root(
            &mut builder,
            source_mmr_a_leaf,
            &source_mmr_a_index_bits,
            &slot.source_cmp.mmr_a_path,
        );
        let source_mmr_a_target = select_hash(
            &mut builder,
            slot.active,
            history_root,
            source_mmr_a_computed,
        );
        builder.connect_hashes(source_mmr_a_computed, source_mmr_a_target);

        // --- SPEC §8 (e): MMR inclusion of source's prior history root ---
        //
        // Leaf shape: `h(prev_smt_in_mmr_leaf || source.commitment_history_root)`,
        // where `source.commitment_history_root` is extracted from the
        // aggregator's slot-`i` PIs (the source's prior view of
        // history at the time it was proved).
        let mut source_mmr_b_leaf_input = Vec::with_capacity(8);
        source_mmr_b_leaf_input.extend_from_slice(&slot.source_cmp.prev_smt_in_mmr_leaf.elements);
        source_mmr_b_leaf_input.extend_from_slice(&source_commitment_history_root.elements);
        let source_mmr_b_leaf =
            builder.hash_n_to_hash_no_pad::<PoseidonHash>(source_mmr_b_leaf_input);
        let source_mmr_b_index_bits =
            builder.split_le(slot.source_cmp.mmr_b_index, MMR_PROOF_PATH_LEN);
        let source_mmr_b_computed = mmr_inclusion_root(
            &mut builder,
            source_mmr_b_leaf,
            &source_mmr_b_index_bits,
            &slot.source_cmp.mmr_b_path,
        );
        let source_mmr_b_target = select_hash(
            &mut builder,
            slot.active,
            history_root,
            source_mmr_b_computed,
        );
        builder.connect_hashes(source_mmr_b_computed, source_mmr_b_target);
    }

    let output_coin_history_root = running_coin_history;

    // ===== Out-coins processing =====
    //
    // Per SPEC §8 step 3, the out-coins loop:
    // 1. For each (out_coin, ncl_proof): verify non-inclusion in the
    //    running `output_coins_root`, insert the identifier, subtract
    //    the amount from the running balance with an underflow check.
    // 2. Compute `interim_asth = H(owner || running_balance ||
    //    pubkey_limbs)` — the account-state hash at this point, with
    //    the INITIAL pubkey (no rotation yet).
    // 3. For each (i, out_coin): assert `out_coin.identifier ==
    //    H(interim_asth || u32(i))`, mirroring the off-circuit
    //    `calculate_coin_identifier`.
    // 4. Rotate pubkey: the FINAL `account_state_hash` (= the public
    //    output) uses `next_public_key_limbs` in place of
    //    `pubkey_limbs`.
    //
    // All in-circuit checks are masked by each slot's `active` bit,
    // so an empty out-coins loop is a no-op (running root stays at
    // `DEFAULT_HASHES[0]`, balance unchanged, identifier check
    // trivially satisfied).

    let next_public_key_limbs: [Target; 5] = std::array::from_fn(|_| {
        let t = builder.add_virtual_target();
        builder.range_check(t, 56);
        t
    });

    let out_coin_slots: Vec<OutCoinSlotTargets> = (0..MAX_OUT_COINS)
        .map(|_| OutCoinSlotTargets {
            active: builder.add_virtual_bool_target_safe(),
            out_coin_identifier: builder.add_virtual_hash(),
            out_coin_amount_lo: {
                let t = builder.add_virtual_target();
                builder.range_check(t, 32);
                t
            },
            out_coin_amount_hi: {
                let t = builder.add_virtual_target();
                builder.range_check(t, 32);
                t
            },
            nip_path: (0..TREE_DEPTH)
                .map(|_| builder.add_virtual_hash())
                .collect(),
        })
        .collect();

    let mut running_output_coins_root = empty_root;

    for slot in &out_coin_slots {
        let id_bits = key_bits_msb_first(&mut builder, slot.out_coin_identifier);

        // --- SMT non-inclusion + insert into running_output_coins_root ---
        let computed_old =
            hash_up_full_path(&mut builder, empty_leaf_default, &id_bits, &slot.nip_path);
        let target_old = select_hash(
            &mut builder,
            slot.active,
            running_output_coins_root,
            computed_old,
        );
        builder.connect_hashes(computed_old, target_old);

        let mut new_leaf_input = Vec::with_capacity(8);
        new_leaf_input.extend_from_slice(&slot.out_coin_identifier.elements);
        new_leaf_input.extend_from_slice(&slot.out_coin_identifier.elements);
        let new_leaf = builder.hash_n_to_hash_no_pad::<PoseidonHash>(new_leaf_input);
        let computed_new = hash_up_full_path(&mut builder, new_leaf, &id_bits, &slot.nip_path);
        running_output_coins_root = select_hash(
            &mut builder,
            slot.active,
            computed_new,
            running_output_coins_root,
        );

        // --- Balance subtraction with underflow check (masked) ---
        // `balance_u64 = balance_hi * 2^32 + balance_lo` and same for
        // `amount_u64`. `diff = balance_u64 - active * amount_u64`
        // must be in `[0, 2^64)` — `split_le(diff, 64)` constrains
        // exactly that. When inactive, `active * amount = 0` so
        // `diff = balance_u64` (unchanged) and the bits trivially
        // decompose it.
        let balance_u64 = builder.mul_add(running_balance_hi, two_pow_32, running_balance_lo);
        let amount_lo_masked = builder.mul(slot.active.target, slot.out_coin_amount_lo);
        let amount_hi_masked = builder.mul(slot.active.target, slot.out_coin_amount_hi);
        let amount_u64 = builder.mul_add(amount_hi_masked, two_pow_32, amount_lo_masked);
        let diff = builder.sub(balance_u64, amount_u64);
        let diff_bits = builder.split_le(diff, 64);
        // Recompose into 32-bit halves. `le_sum` weights bits by
        // ascending powers of 2 starting at 0; the [0..32) slice gives
        // the low 32 bits and [0..32) of the [32..64) slice gives the
        // high half (also weighted from 2^0 because `le_sum` doesn't
        // know about offsets — that's the intended bottom-up sum).
        let new_lo = builder.le_sum(diff_bits[..32].iter());
        let new_hi = builder.le_sum(diff_bits[32..].iter());
        running_balance_lo = new_lo;
        running_balance_hi = new_hi;
    }

    let final_balance_lo = running_balance_lo;
    let final_balance_hi = running_balance_hi;

    // Interim account-state hash: owner + post-subtraction balance +
    // INITIAL pubkey + asset_id. Drives out-coin identifier derivation.
    // 15-F layout matches AccountState::hash.
    let mut interim_state_elements: Vec<Target> = Vec::with_capacity(15);
    interim_state_elements.extend_from_slice(&owner.elements);
    interim_state_elements.push(final_balance_lo);
    interim_state_elements.push(final_balance_hi);
    interim_state_elements.extend_from_slice(&pubkey_limbs);
    interim_state_elements.extend_from_slice(&account_asset_id.elements);
    let interim_account_state_hash =
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(interim_state_elements);

    // Identifier derivation per out-coin slot.
    // Expected: out_coin.identifier == H(interim_asth || u32(slot_index))
    // (matches off-circuit [`crate::types::calculate_coin_identifier`]).
    // Masked by `active` so inactive slots' identifiers don't need to
    // match anything.
    for (i, slot) in out_coin_slots.iter().enumerate() {
        let i_const = builder.constant(F::from_canonical_u32(i as u32));
        let mut id_input = Vec::with_capacity(9);
        id_input.extend_from_slice(&interim_account_state_hash.elements);
        id_input.extend_from_slice(&transition_asset_id.elements);
        id_input.push(i_const);
        let computed_id = builder.hash_n_to_hash_no_pad::<PoseidonHash>(id_input);
        for j in 0..4 {
            let diff = builder.sub(
                slot.out_coin_identifier.elements[j],
                computed_id.elements[j],
            );
            let masked = builder.mul(slot.active.target, diff);
            builder.assert_zero(masked);
        }
    }

    // FINAL account-state hash: owner + post-subtraction balance + NEW
    // pubkey. Committed as `ProofData.account_state_hash`. If the
    // caller wants no rotation (e.g., Initial / Account-update without
    // out-coins), they set `next_public_key_limbs` to the same value
    // as `pubkey_limbs` and the final hash matches the initial-pubkey
    // hash.
    let mut final_state_elements: Vec<Target> = Vec::with_capacity(15);
    final_state_elements.extend_from_slice(&owner.elements);
    final_state_elements.push(final_balance_lo);
    final_state_elements.push(final_balance_hi);
    final_state_elements.extend_from_slice(&next_public_key_limbs);
    final_state_elements.extend_from_slice(&account_asset_id.elements);
    let final_account_state_hash =
        builder.hash_n_to_hash_no_pad::<PoseidonHash>(final_state_elements);

    // Connect `ProofData` public inputs slot-by-slot.
    for i in 0..4 {
        builder.connect(proof_data_pis[i], final_account_state_hash.elements[i]);
        builder.connect(proof_data_pis[4 + i], running_output_coins_root.elements[i]);
        builder.connect(proof_data_pis[8 + i], history_root.elements[i]);
        builder.connect(proof_data_pis[12 + i], output_coin_history_root.elements[i]);
    }

    // Shape lock — must match the helper's pass-3 injection (see
    // `common_data_for_recursion_c_inner`). Without it, the outer's
    // gates list lacks `ConstantGate` even though the helper's
    // pass-3 has it (and `dummy_circuit`'s rebuild always emits one),
    // failing the cyclic fixed-point check at
    // `plonk/circuit_builder.rs:1067`. The aggregator-verify itself
    // is hoisted above the in-coin loop so per-slot source-side gates
    // can read the aggregator's PIs.
    builder.add_gate(ConstantGate::new(2), vec![F::ZERO, F::ZERO]);

    // Cyclic verification (Stage 5d-next-3 + Stage 5d-next-5 shape:
    // the cyclic fixed-point is reached because pass 3 of
    // `common_data_for_recursion_c_inner` models exactly this
    // `_or_dummy` (1 verify_proof internally) + the
    // `verify_proof(aggregator)` + the `ConstantGate` injection
    // above. Their gate-set, selectors_info, num_constants and
    // degree_bits all coincide — see
    // `MIGRATION_RESEARCH.md` §7.22 for the empirical derivation.
    builder
        .conditionally_verify_cyclic_proof_or_dummy::<C>(
            condition,
            &inner_proof_target,
            &common_data,
        )
        .expect("conditionally_verify_cyclic_proof_or_dummy: common_data is well-formed by construction");

    let data = builder.build::<C>();
    StateTransitionCircuit {
        data,
        common_data,
        verifier_data_target,
        condition,
        inner_proof_target,
        proof_data_pis,
        owner,
        balance_lo,
        balance_hi,
        pubkey_limbs,
        history_root,
        cmp,
        in_coin_slots,
        out_coin_slots,
        next_public_key_limbs,
        creator_pubkey_limbs,
        name_hash,
        decimals,
        account_asset_id,
        aggregator,
        aggregator_proof_target,
    }
}

/// Set the witnesses for the `AccountState` fields. Shared between
/// [`prove_initial`] and [`prove_account_update`] because both branches
/// witness the same fields in the same way.
fn set_account_state_witness(
    pw: &mut PartialWitness<F>,
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
) {
    pw.set_hash_target(circuit.owner, account_state.owner)
        .unwrap();

    let balance = account_state.balance;
    pw.set_target(
        circuit.balance_lo,
        F::from_canonical_u32((balance & 0xFFFF_FFFF) as u32),
    )
    .unwrap();
    pw.set_target(
        circuit.balance_hi,
        F::from_canonical_u32((balance >> 32) as u32),
    )
    .unwrap();

    for (i, chunk) in account_state.public_key.chunks(7).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        pw.set_target(
            circuit.pubkey_limbs[i],
            F::from_canonical_u64(u64::from_le_bytes(buf)),
        )
        .unwrap();
    }

    // The account's own asset_id. The in-circuit `connect(account_asset_id,
    // transition_asset_id)` ties this to the proof-data asset_id, so the
    // caller must pass the SAME asset_id to the prove entrypoint.
    pw.set_hash_target(circuit.account_asset_id, account_state.asset_id)
        .unwrap();
}

/// Issuer-mint witness for the [`crate::circuit::main`] mint gate: the
/// asset creator's pubkey, the asset name hash, and the decimals. Supply
/// `Some(_)` when proving a legitimate issuer-mint (an Initial proof
/// whose account starts with a non-zero, freshly-minted supply); the
/// gate then checks `account.public_key == creator_pubkey` and
/// `calculate_asset_id(creator_pubkey, name_hash, decimals) ==
/// transition_asset_id` to grant the balance-may-be-nonzero exception.
/// (The `owner` is the off-circuit SHA-256 address and is NOT bound in
/// the gate — #226, Variant B.)
///
/// For every non-mint path (send/receive/account-update, or an Initial
/// proof with zero balance) pass `None` — the gate is masked off and the
/// witnesses default to a deterministic placeholder.
#[derive(Clone, Copy)]
pub struct MintWitness {
    pub creator_pubkey: PublicKey,
    pub name_hash: HashDigest,
    pub decimals: u8,
}

/// Set the issuer-mint witnesses (`creator_pubkey_limbs`, `name_hash`,
/// `decimals`). When `mint` is `None`, deterministic placeholders are
/// written: the gate they feed is masked off (`is_minting` cannot be
/// satisfied by the placeholder against a real account), so the values
/// are irrelevant to soundness — they only need to be assigned so the
/// witness is complete.
fn set_mint_witness(
    pw: &mut PartialWitness<F>,
    circuit: &StateTransitionCircuit,
    mint: Option<MintWitness>,
) {
    let (creator_pubkey, name_hash, decimals) = match mint {
        Some(m) => (m.creator_pubkey, m.name_hash, m.decimals),
        None => ([0u8; 33], ZERO_HASH, 0u8),
    };
    for (i, chunk) in creator_pubkey.chunks(7).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        pw.set_target(
            circuit.creator_pubkey_limbs[i],
            F::from_canonical_u64(u64::from_le_bytes(buf)),
        )
        .unwrap();
    }
    pw.set_hash_target(circuit.name_hash, name_hash).unwrap();
    pw.set_target(circuit.decimals, F::from_canonical_u32(decimals as u32))
        .unwrap();
}

/// Set the witnesses for a `CommitmentMerkleProofsTargets` bundle.
///
/// Shared between the outer prev-account CMP and the per-in-coin-slot
/// source CMP (Stage 5d-next-5 Phase 2b). Off-circuit producers MUST
/// pre-pad SMT / MMR paths to the fixed in-circuit shapes
/// ([`TREE_DEPTH`] / [`MMR_PROOF_PATH_LEN`]); the asserts here catch
/// malformed witnesses early before any expensive proving work.
fn set_cmp_targets_witness(
    pw: &mut PartialWitness<F>,
    targets: &CommitmentMerkleProofsTargets,
    cmp: &CommitmentMerkleProofs,
) {
    pw.set_hash_target(targets.commitment_root, cmp.commitment_root)
        .unwrap();
    pw.set_hash_target(
        targets.smt_key,
        digest_from_bytes(&cmp.commitment_proof.key),
    )
    .unwrap();
    assert_eq!(
        cmp.commitment_proof.siblings.len(),
        TREE_DEPTH,
        "CommitmentMerkleProofs: SMT inclusion proof must be padded to TREE_DEPTH siblings"
    );
    for (i, sib) in cmp.commitment_proof.siblings.iter().enumerate() {
        pw.set_hash_target(targets.smt_path[i], *sib).unwrap();
    }
    pw.set_target(
        targets.mmr_a_index,
        F::from_canonical_u32(cmp.commitment_root_history_proof.index),
    )
    .unwrap();
    assert_eq!(
        cmp.commitment_root_history_proof.path.len(),
        MMR_PROOF_PATH_LEN,
        "CommitmentMerkleProofs: MMR proof (d) must be extended to MMR_PROOF_PATH_LEN siblings"
    );
    for (i, sib) in cmp.commitment_root_history_proof.path.iter().enumerate() {
        pw.set_hash_target(targets.mmr_a_path[i], *sib).unwrap();
    }
    pw.set_hash_target(
        targets.commitment_root_mmr_sibling,
        cmp.commitment_root_mmr_sibling,
    )
    .unwrap();
    pw.set_hash_target(
        targets.prev_smt_in_mmr_leaf,
        cmp.previous_root_history_proof.0,
    )
    .unwrap();
    pw.set_target(
        targets.mmr_b_index,
        F::from_canonical_u32(cmp.previous_root_history_proof.1.index),
    )
    .unwrap();
    assert_eq!(
        cmp.previous_root_history_proof.1.path.len(),
        MMR_PROOF_PATH_LEN,
        "CommitmentMerkleProofs: MMR proof (e) must be extended to MMR_PROOF_PATH_LEN siblings"
    );
    for (i, sib) in cmp.previous_root_history_proof.1.path.iter().enumerate() {
        pw.set_hash_target(targets.mmr_b_path[i], *sib).unwrap();
    }
    pw.set_hash_target(
        targets.commitment_account_state_hash,
        cmp.commitment_account_state_hash,
    )
    .unwrap();
    pw.set_hash_target(
        targets.commitment_out_coins_root,
        cmp.commitment_out_coins_root,
    )
    .unwrap();
}

/// Set the witnesses for the prev-account `CommitmentMerkleProofs`
/// bundle. Thin wrapper around [`set_cmp_targets_witness`] that
/// targets `circuit.cmp`.
///
/// Used by both proving paths:
/// - `prove_initial` calls this with a *dummy* `cmp` ([`dummy_cmp`]),
///   since the masked constraints are trivially satisfied with
///   `condition = false` for any witness.
/// - `prove_account_update` calls this with the real `cmp` matching
///   the prev proof and current history.
fn set_cmp_witness(
    pw: &mut PartialWitness<F>,
    circuit: &StateTransitionCircuit,
    cmp: &CommitmentMerkleProofs,
) {
    set_cmp_targets_witness(pw, &circuit.cmp, cmp);
}

/// Build a syntactically-valid but semantically-empty
/// `CommitmentMerkleProofs` for use as the dummy witness in
/// [`prove_initial`] and the per-in-coin-slot source CMP of inactive
/// slots (Stage 5d-next-5 Phase 2b). Every field gets a deterministic
/// placeholder (mostly `ZERO_HASH`); the masked constraints in the
/// circuit ignore the values whenever their guard bit is `0`.
fn dummy_cmp() -> CommitmentMerkleProofs {
    use crate::merkle::merkle_mountain_range::MMRProof;
    CommitmentMerkleProofs {
        commitment_root: ZERO_HASH,
        commitment_proof: InclusionProof {
            key: [0u8; 32],
            siblings: vec![ZERO_HASH; TREE_DEPTH],
        },
        commitment_root_history_proof: MMRProof::new(vec![ZERO_HASH; MMR_PROOF_PATH_LEN], 0),
        commitment_root_mmr_sibling: ZERO_HASH,
        previous_root_history_proof: (
            ZERO_HASH,
            MMRProof::new(vec![ZERO_HASH; MMR_PROOF_PATH_LEN], 0),
        ),
        commitment_account_state_hash: ZERO_HASH,
        commitment_out_coins_root: ZERO_HASH,
    }
}

/// Build a syntactically-valid but semantically-empty
/// [`InclusionProof`] for use as the dummy source-inclusion-path
/// witness on inactive in-coin slots (Stage 5d-next-5 Phase 2b).
///
/// `siblings.len() == TREE_DEPTH` so the witness-setter's length
/// assert passes; values are all `ZERO_HASH` and the in-circuit
/// inclusion check is masked off by `slot.active = 0`.
///
/// [`InclusionProof`]: crate::merkle::sparse_merkle_tree::InclusionProof
fn dummy_inclusion_proof() -> InclusionProof {
    InclusionProof {
        key: [0u8; 32],
        siblings: vec![ZERO_HASH; TREE_DEPTH],
    }
}

/// Set the coin-history-side witnesses for one in-coin slot
/// (Stage 5d-next-3 surface — `active`, identifier, recipient, amount,
/// non-inclusion path in the running `coin_history_root`).
///
/// Stage 5d-next-5 Phase 2b's source-side witnesses
/// (`source_inclusion_path`, `source_cmp`) are set separately by
/// [`set_source_inclusion_witness`] + [`set_cmp_targets_witness`].
/// This split keeps the (still cheap) coin-history-side independent
/// of the (substantially bigger) source-side witness bundle.
///
/// Inactive slots get a dummy non-inclusion proof against an arbitrary
/// (zeroed) `coin_history_root` plus zero recipient/amount; the masked
/// checks are satisfied vacuously by the slot's `active = false` bit.
fn set_in_coin_slot_witness(
    pw: &mut PartialWitness<F>,
    slot: &InCoinSlotTargets,
    active: bool,
    coin_identifier: HashDigest,
    coin_recipient: HashDigest,
    coin_amount: u64,
    nip: &NonInclusionProof,
) {
    pw.set_bool_target(slot.active, active).unwrap();
    pw.set_hash_target(slot.coin_identifier, coin_identifier)
        .unwrap();
    pw.set_hash_target(slot.coin_recipient, coin_recipient)
        .unwrap();
    pw.set_target(
        slot.coin_amount_lo,
        F::from_canonical_u32((coin_amount & 0xFFFF_FFFF) as u32),
    )
    .unwrap();
    pw.set_target(
        slot.coin_amount_hi,
        F::from_canonical_u32((coin_amount >> 32) as u32),
    )
    .unwrap();
    assert_eq!(
        nip.siblings.len(),
        TREE_DEPTH,
        "InCoinSlot: non-inclusion proof must be padded to TREE_DEPTH siblings"
    );
    for (i, sib) in nip.siblings.iter().enumerate() {
        pw.set_hash_target(slot.nip_path[i], *sib).unwrap();
    }
}

/// Set the source-side SMT-inclusion-path witness for one in-coin slot
/// (Stage 5d-next-5 Phase 2b). Mirrors [`set_in_coin_slot_witness`]'s
/// `nip` handling: the path must be padded to [`TREE_DEPTH`] siblings;
/// the in-circuit SMT inclusion check fires only when `slot.active = 1`.
fn set_source_inclusion_witness(
    pw: &mut PartialWitness<F>,
    slot: &InCoinSlotTargets,
    inclusion: &InclusionProof,
) {
    assert_eq!(
        inclusion.siblings.len(),
        TREE_DEPTH,
        "InCoinSlot: source inclusion proof must be padded to TREE_DEPTH siblings"
    );
    for (i, sib) in inclusion.siblings.iter().enumerate() {
        pw.set_hash_target(slot.source_inclusion_path[i], *sib)
            .unwrap();
    }
}

/// Per-active-in-coin-slot witness bundle for Phase 2b proves. Mirrors
/// what the off-circuit producer must supply to satisfy the SPEC §8
/// step 2 source-side checks:
///
/// - `source_proof`: the source state-transition proof whose
///   `output_coins_root` contains the in-coin's `identifier`. Verified
///   through the aggregator's slot-`i` `conditionally_verify_proof`.
/// - `source_inclusion`: SMT inclusion of the in-coin's `identifier`
///   in `source_proof`'s `output_coins_root` (`siblings.len() ==
///   TREE_DEPTH`).
/// - `source_cmp`: [`CommitmentMerkleProofs`] establishing that the
///   source proof's commitment `h(asth || ocr)` is published in the
///   global `history_root` per SPEC §8 (c)(d)(e).
pub struct InCoinSourceWitness<'a> {
    pub source_proof: &'a ProofWithPublicInputs<F, C, D>,
    pub source_inclusion: &'a InclusionProof,
    pub source_cmp: &'a CommitmentMerkleProofs,
}

/// Build a dummy `Coin` for populating inactive in-coin slot
/// witnesses. The slot's `active = false` bit masks off the
/// recipient and balance-update constraints, so the values are
/// irrelevant — `ZERO_HASH` identifier / `ZERO_HASH` recipient /
/// `amount = 0` is the cheapest placeholder.
fn dummy_coin() -> Coin {
    Coin {
        identifier: ZERO_HASH,
        recipient: ZERO_HASH,
        amount: 0,
        asset_id: ZERO_HASH,
    }
}

/// Set the witnesses for one out-coin slot. Inactive slots use the
/// `dummy_coin` + `dummy_non_inclusion_proof` placeholders.
fn set_out_coin_slot_witness(
    pw: &mut PartialWitness<F>,
    slot: &OutCoinSlotTargets,
    active: bool,
    out_coin_identifier: HashDigest,
    out_coin_amount: u64,
    nip: &NonInclusionProof,
) {
    pw.set_bool_target(slot.active, active).unwrap();
    pw.set_hash_target(slot.out_coin_identifier, out_coin_identifier)
        .unwrap();
    pw.set_target(
        slot.out_coin_amount_lo,
        F::from_canonical_u32((out_coin_amount & 0xFFFF_FFFF) as u32),
    )
    .unwrap();
    pw.set_target(
        slot.out_coin_amount_hi,
        F::from_canonical_u32((out_coin_amount >> 32) as u32),
    )
    .unwrap();
    assert_eq!(
        nip.siblings.len(),
        TREE_DEPTH,
        "OutCoinSlot: non-inclusion proof must be padded to TREE_DEPTH siblings"
    );
    for (i, sib) in nip.siblings.iter().enumerate() {
        pw.set_hash_target(slot.nip_path[i], *sib).unwrap();
    }
}

/// Set the witnesses for the rotated public key. Used by all prove
/// paths. If the caller doesn't want pubkey rotation (e.g., Initial
/// proof without out-coins), pass `account_state.public_key` to keep
/// the final `account_state_hash` aligned with the off-circuit
/// `AccountState::hash`.
fn set_next_public_key_witness(
    pw: &mut PartialWitness<F>,
    circuit: &StateTransitionCircuit,
    next_public_key: &PublicKey,
) {
    for (i, chunk) in next_public_key.chunks(7).enumerate() {
        let mut buf = [0u8; 8];
        buf[..chunk.len()].copy_from_slice(chunk);
        pw.set_target(
            circuit.next_public_key_limbs[i],
            F::from_canonical_u64(u64::from_le_bytes(buf)),
        )
        .unwrap();
    }
}

/// Build a dummy `NonInclusionProof` for populating inactive in-coin
/// slot witnesses. Every sibling is `ZERO_HASH`; the slot's `active`
/// bit being `false` masks off the in-circuit checks regardless.
fn dummy_non_inclusion_proof() -> NonInclusionProof {
    NonInclusionProof {
        key: [0u8; 32],
        root: ZERO_HASH,
        siblings: vec![ZERO_HASH; TREE_DEPTH],
    }
}

/// Prove the Initial-branch state transition for a given `account_state`
/// and `history_root`.
///
/// All `MAX_IN_COINS` slots are populated with inactive dummies — Stage 5d
/// could in principle allow Init proofs to also receive in-coins (per
/// SPEC §8 the Initial branch falls through to the in-coins loop), but
/// the test fixtures here demonstrate only the empty-in-coins case.
/// To prove an Initial proof with active in-coin slots, use
/// [`prove_initial_with_in_coins`].
pub fn prove_initial(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    asset_id: HashDigest,
    mint: Option<MintWitness>,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let dummy_nip = dummy_non_inclusion_proof();
    let dummy_coin = dummy_coin();
    let inactive_slots: Vec<(bool, &Coin, &NonInclusionProof)> = (0..MAX_IN_COINS)
        .map(|_| (false, &dummy_coin, &dummy_nip))
        .collect();
    prove_initial_with_in_coins(
        circuit,
        account_state,
        history_root,
        &inactive_slots,
        asset_id,
        mint,
    )
}

/// Like [`prove_initial`] but with caller-supplied in-coin slot
/// witnesses. Each tuple is `(active, &coin, &non_inclusion_proof)`;
/// the caller MUST supply exactly `MAX_IN_COINS` tuples. Inactive slots
/// can pass the [`dummy_coin`] / [`dummy_non_inclusion_proof`]
/// placeholders regardless of the current `coin_history_root` and
/// running balance — the slot's `active = false` bit masks all
/// in-circuit checks.
pub fn prove_initial_with_in_coins(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    in_coins: &[(bool, &Coin, &NonInclusionProof)],
    asset_id: HashDigest,
    mint: Option<MintWitness>,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    assert_eq!(
        in_coins.len(),
        MAX_IN_COINS,
        "prove_initial_with_in_coins: caller must supply exactly MAX_IN_COINS slot witnesses"
    );
    let dummy_nip = dummy_non_inclusion_proof();
    let inactive_out_coins: Vec<(bool, HashDigest, u64, &NonInclusionProof)> = (0..MAX_OUT_COINS)
        .map(|_| (false, ZERO_HASH, 0u64, &dummy_nip))
        .collect();
    prove_initial_with_in_and_out_coins(
        circuit,
        account_state,
        history_root,
        in_coins,
        &inactive_out_coins,
        &account_state.public_key,
        asset_id,
        mint,
    )
}

/// Like [`prove_initial`] but with caller-supplied in-coin AND
/// out-coin slot witnesses, plus an explicit `next_public_key` the
/// account rotates to.
///
/// Stage 5d-next-5 Phase 2b note: this entry point delegates to
/// [`prove_initial_with_in_and_out_coins_and_sources`] with
/// all-`None` sources. It is therefore only suitable for Initial
/// transitions whose `in_coins` are ALL inactive — an active in-coin
/// slot without a source witness fails the `connect(slot.active,
/// source.active)` constraint at proof time. Tests and producers that
/// need an active in-coin must call the `_and_sources` variant.
#[allow(clippy::too_many_arguments)]
pub fn prove_initial_with_in_and_out_coins(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    in_coins: &[(bool, &Coin, &NonInclusionProof)],
    out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
    next_public_key: &PublicKey,
    asset_id: HashDigest,
    mint: Option<MintWitness>,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let sources: Vec<Option<InCoinSourceWitness>> = (0..MAX_IN_COINS).map(|_| None).collect();
    prove_initial_with_in_and_out_coins_and_sources(
        circuit,
        account_state,
        history_root,
        in_coins,
        out_coins,
        next_public_key,
        &sources,
        asset_id,
        mint,
    )
}

/// Stage 5d-next-5 Phase 2b: prove an Initial-branch transition with
/// caller-supplied in-coin AND out-coin slot witnesses AND a per-slot
/// source witness bundle for active in-coin slots.
///
/// `sources.len()` must equal [`MAX_IN_COINS`]. Each entry corresponds
/// positionally to the `in_coins` entry of the same index: `Some(_)`
/// supplies the source proof / inclusion / CMP for an active slot;
/// `None` indicates the slot is inactive (in which case
/// `in_coins[i].0` must also be `false`, else the source-side
/// constraints reject).
///
/// The aggregator's per-slot active bits are derived from `sources`
/// (every `Some(_)` becomes an active aggregator slot with the
/// supplied `source_proof`); the in-circuit `connect(slot.active,
/// aggregator.slot.active)` enforces consistency with the
/// caller-supplied `in_coins` active bits.
#[allow(clippy::too_many_arguments)]
pub fn prove_initial_with_in_and_out_coins_and_sources(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    in_coins: &[(bool, &Coin, &NonInclusionProof)],
    out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
    next_public_key: &PublicKey,
    sources: &[Option<InCoinSourceWitness>],
    asset_id: HashDigest,
    mint: Option<MintWitness>,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    assert_eq!(
        in_coins.len(),
        MAX_IN_COINS,
        "prove_initial_with_in_and_out_coins_and_sources: caller must supply exactly MAX_IN_COINS in-coin slot witnesses"
    );
    assert_eq!(
        out_coins.len(),
        MAX_OUT_COINS,
        "prove_initial_with_in_and_out_coins_and_sources: caller must supply exactly MAX_OUT_COINS out-coin slot witnesses"
    );
    assert_eq!(
        sources.len(),
        MAX_IN_COINS,
        "prove_initial_with_in_and_out_coins_and_sources: caller must supply exactly MAX_IN_COINS source witnesses"
    );

    let mut pw = PartialWitness::new();
    pw.set_bool_target(circuit.condition, false).unwrap();
    set_account_state_witness(&mut pw, circuit, account_state);
    set_mint_witness(&mut pw, circuit, mint);
    pw.set_hash_target(circuit.history_root, history_root)
        .unwrap();
    for i in 0..4 {
        pw.set_target(circuit.proof_data_pis[16 + i], asset_id.elements[i])
            .unwrap();
    }
    set_cmp_witness(&mut pw, circuit, &dummy_cmp());
    for (slot_targets, (active, coin, nip)) in circuit.in_coin_slots.iter().zip(in_coins.iter()) {
        set_in_coin_slot_witness(
            &mut pw,
            slot_targets,
            *active,
            coin.identifier,
            coin.recipient,
            coin.amount,
            nip,
        );
    }
    set_per_slot_source_witnesses(&mut pw, circuit, sources);
    for (slot_targets, (active, identifier, amount, nip)) in
        circuit.out_coin_slots.iter().zip(out_coins.iter())
    {
        set_out_coin_slot_witness(&mut pw, slot_targets, *active, *identifier, *amount, nip);
    }
    set_next_public_key_witness(&mut pw, circuit, next_public_key);
    set_aggregator_proof_witness_from_sources(&mut pw, circuit, sources)?;

    // Dummy inner proof for the cyclic-recursion slot.
    let inner_pis = std::iter::empty::<(usize, F)>().collect();
    pw.set_proof_with_pis_target::<C, D>(
        &circuit.inner_proof_target,
        &cyclic_base_proof(&circuit.common_data, &circuit.data.verifier_only, inner_pis),
    )
    .unwrap();
    pw.set_verifier_data_target(&circuit.verifier_data_target, &circuit.data.verifier_only)
        .unwrap();

    circuit.data.prove(pw)
}

/// Per-slot Phase 2b source-witness setter. Walks `sources` and
/// writes the source-inclusion path + source CMP for each slot —
/// `Some(_)` entries get the caller-supplied witnesses, `None`
/// entries get [`dummy_inclusion_proof`] + [`dummy_cmp`]. The
/// in-circuit checks are masked by the slot's `active` bit so dummy
/// witnesses on inactive slots are vacuous.
fn set_per_slot_source_witnesses(
    pw: &mut PartialWitness<F>,
    circuit: &StateTransitionCircuit,
    sources: &[Option<InCoinSourceWitness>],
) {
    let dummy_incl = dummy_inclusion_proof();
    let dummy_c = dummy_cmp();
    for (slot_targets, source) in circuit.in_coin_slots.iter().zip(sources.iter()) {
        match source {
            Some(s) => {
                set_source_inclusion_witness(pw, slot_targets, s.source_inclusion);
                set_cmp_targets_witness(pw, &slot_targets.source_cmp, s.source_cmp);
            }
            None => {
                set_source_inclusion_witness(pw, slot_targets, &dummy_incl);
                set_cmp_targets_witness(pw, &slot_targets.source_cmp, &dummy_c);
            }
        }
    }
}

/// Stage 5d-next-5 Phase 2b aggregator-witness setter. Builds an
/// aggregator proof from the per-slot source witnesses: every
/// `Some(_)` entry becomes an active aggregator slot with the
/// supplied `source_proof`; every `None` entry an inactive slot.
fn set_aggregator_proof_witness_from_sources(
    pw: &mut PartialWitness<F>,
    circuit: &StateTransitionCircuit,
    sources: &[Option<InCoinSourceWitness>],
) -> Result<()> {
    let slot_witnesses: Vec<AggregatorSlotWitness> = sources
        .iter()
        .map(|s| match s {
            Some(src) => AggregatorSlotWitness {
                active: true,
                real_proof: Some(src.source_proof),
            },
            None => AggregatorSlotWitness {
                active: false,
                real_proof: None,
            },
        })
        .collect();
    let agg_proof = prove_aggregator(
        &circuit.aggregator,
        &circuit.data.verifier_only,
        &slot_witnesses,
    )?;
    pw.set_proof_with_pis_target::<C, D>(&circuit.aggregator_proof_target, &agg_proof)
        .unwrap();
    Ok(())
}

/// Prove an AccountUpdate transition consuming `prev` as the recursive
/// inner proof plus a [`CommitmentMerkleProofs`] witnessing that `prev`
/// is published in the global history at `history_root`.
///
/// The proof's history-side fields (SMT inclusion path, MMR inclusion
/// paths) must be pre-padded to the fixed shape the circuit expects:
/// - `commitment_proof.siblings.len() == TREE_DEPTH = 256`
/// - `commitment_root_history_proof.path.len() == MMR_PROOF_PATH_LEN = 31`
/// - `previous_root_history_proof.1.path.len() == MMR_PROOF_PATH_LEN = 31`
///
/// The `history_root` parameter must be
/// `mmr.root_extended(MMR_PROOF_PATH_LEN)` for the same MMR depth
/// (see [`crate::merkle::merkle_mountain_range::MerkleMountainRange::root_extended`]).
pub fn prove_account_update(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    prev: &ProofWithPublicInputs<F, C, D>,
    cmp: &CommitmentMerkleProofs,
    asset_id: HashDigest,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let dummy_nip = dummy_non_inclusion_proof();
    let dummy_coin = dummy_coin();
    let inactive_slots: Vec<(bool, &Coin, &NonInclusionProof)> = (0..MAX_IN_COINS)
        .map(|_| (false, &dummy_coin, &dummy_nip))
        .collect();
    prove_account_update_with_in_coins(
        circuit,
        account_state,
        history_root,
        prev,
        cmp,
        &inactive_slots,
        asset_id,
    )
}

/// Like [`prove_account_update`] but with caller-supplied in-coin slot
/// witnesses. See [`prove_initial_with_in_coins`] for the contract on
/// the `in_coins` slice.
pub fn prove_account_update_with_in_coins(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    prev: &ProofWithPublicInputs<F, C, D>,
    cmp: &CommitmentMerkleProofs,
    in_coins: &[(bool, &Coin, &NonInclusionProof)],
    asset_id: HashDigest,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    assert_eq!(
        in_coins.len(),
        MAX_IN_COINS,
        "prove_account_update_with_in_coins: caller must supply exactly MAX_IN_COINS slot witnesses"
    );
    let dummy_nip = dummy_non_inclusion_proof();
    let inactive_out_coins: Vec<(bool, HashDigest, u64, &NonInclusionProof)> = (0..MAX_OUT_COINS)
        .map(|_| (false, ZERO_HASH, 0u64, &dummy_nip))
        .collect();
    prove_account_update_with_in_and_out_coins(
        circuit,
        account_state,
        history_root,
        prev,
        cmp,
        in_coins,
        &inactive_out_coins,
        &account_state.public_key,
        asset_id,
    )
}

/// Like [`prove_account_update`] but with caller-supplied in-coin AND
/// out-coin slot witnesses, plus an explicit `next_public_key`.
///
/// Stage 5d-next-5 Phase 2b note: this entry point delegates to
/// [`prove_account_update_with_in_and_out_coins_and_sources`] with
/// all-`None` sources. Only suitable for AccountUpdate transitions
/// whose `in_coins` are ALL inactive.
#[allow(clippy::too_many_arguments)]
pub fn prove_account_update_with_in_and_out_coins(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    prev: &ProofWithPublicInputs<F, C, D>,
    cmp: &CommitmentMerkleProofs,
    in_coins: &[(bool, &Coin, &NonInclusionProof)],
    out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
    next_public_key: &PublicKey,
    asset_id: HashDigest,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    let sources: Vec<Option<InCoinSourceWitness>> = (0..MAX_IN_COINS).map(|_| None).collect();
    prove_account_update_with_in_and_out_coins_and_sources(
        circuit,
        account_state,
        history_root,
        prev,
        cmp,
        in_coins,
        out_coins,
        next_public_key,
        &sources,
        asset_id,
    )
}

/// Stage 5d-next-5 Phase 2b: prove an AccountUpdate-branch transition
/// with caller-supplied in-coin AND out-coin slot witnesses AND a
/// per-slot source witness bundle for active in-coin slots.
///
/// Contract is symmetric with
/// [`prove_initial_with_in_and_out_coins_and_sources`]: `sources.len()
/// == MAX_IN_COINS`; `Some(_)` ⇔ active slot with real source proof;
/// `None` ⇔ inactive slot.
#[allow(clippy::too_many_arguments)]
pub fn prove_account_update_with_in_and_out_coins_and_sources(
    circuit: &StateTransitionCircuit,
    account_state: &AccountState,
    history_root: HashDigest,
    prev: &ProofWithPublicInputs<F, C, D>,
    cmp: &CommitmentMerkleProofs,
    in_coins: &[(bool, &Coin, &NonInclusionProof)],
    out_coins: &[(bool, HashDigest, u64, &NonInclusionProof)],
    next_public_key: &PublicKey,
    sources: &[Option<InCoinSourceWitness>],
    asset_id: HashDigest,
) -> Result<ProofWithPublicInputs<F, C, D>> {
    assert_eq!(
        in_coins.len(),
        MAX_IN_COINS,
        "prove_account_update_with_in_and_out_coins_and_sources: caller must supply exactly MAX_IN_COINS in-coin slot witnesses"
    );
    assert_eq!(
        out_coins.len(),
        MAX_OUT_COINS,
        "prove_account_update_with_in_and_out_coins_and_sources: caller must supply exactly MAX_OUT_COINS out-coin slot witnesses"
    );
    assert_eq!(
        sources.len(),
        MAX_IN_COINS,
        "prove_account_update_with_in_and_out_coins_and_sources: caller must supply exactly MAX_IN_COINS source witnesses"
    );

    let mut pw = PartialWitness::new();
    pw.set_bool_target(circuit.condition, true).unwrap();
    set_account_state_witness(&mut pw, circuit, account_state);
    // AccountUpdate never mints: the mint gate is masked off when
    // `condition = true`, so the witnesses are placeholders.
    set_mint_witness(&mut pw, circuit, None);
    pw.set_hash_target(circuit.history_root, history_root)
        .unwrap();
    for i in 0..4 {
        pw.set_target(circuit.proof_data_pis[16 + i], asset_id.elements[i])
            .unwrap();
    }
    set_cmp_witness(&mut pw, circuit, cmp);
    for (slot_targets, (active, coin, nip)) in circuit.in_coin_slots.iter().zip(in_coins.iter()) {
        set_in_coin_slot_witness(
            &mut pw,
            slot_targets,
            *active,
            coin.identifier,
            coin.recipient,
            coin.amount,
            nip,
        );
    }
    set_per_slot_source_witnesses(&mut pw, circuit, sources);
    for (slot_targets, (active, identifier, amount, nip)) in
        circuit.out_coin_slots.iter().zip(out_coins.iter())
    {
        set_out_coin_slot_witness(&mut pw, slot_targets, *active, *identifier, *amount, nip);
    }
    set_next_public_key_witness(&mut pw, circuit, next_public_key);
    set_aggregator_proof_witness_from_sources(&mut pw, circuit, sources)?;

    pw.set_proof_with_pis_target::<C, D>(&circuit.inner_proof_target, prev)
        .unwrap();
    pw.set_verifier_data_target(&circuit.verifier_data_target, &circuit.data.verifier_only)
        .unwrap();

    circuit.data.prove(pw)
}

/// Verify a state-transition proof, including the cross-check that its
/// embedded verifier-data digest matches the circuit's own.
pub fn verify(
    circuit: &StateTransitionCircuit,
    proof: &ProofWithPublicInputs<F, C, D>,
) -> Result<()> {
    check_cyclic_proof_verifier_data(proof, &circuit.data.verifier_only, &circuit.data.common)?;
    circuit.data.verify(proof.clone())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash::{digest_to_bytes, hash_bytes, hash_concat};
    use crate::inputs::CommitmentMerkleProofs;
    use crate::merkle::merkle_mountain_range::MerkleMountainRange;
    use crate::merkle::sparse_merkle_tree::SparseMerkleTree;
    use crate::types::ProofData;

    fn dummy_pubkey(seed: u8) -> [u8; 33] {
        let mut pk = [0u8; 33];
        pk[0] = 0x02;
        for (i, b) in pk.iter_mut().enumerate().skip(1) {
            *b = seed.wrapping_add(i as u8);
        }
        pk
    }

    /// Build a self-consistent issuer-mint fixture: an account that is
    /// the legitimate issuer of its own asset. Its `public_key` is the
    /// creator key and its `asset_id` equals
    /// `calculate_asset_id(creator_pubkey, name_hash, decimals)`, so the
    /// in-circuit issuer gate (`public_key == creator` ∧ asset_id match)
    /// grants the mint (balance-may-be-nonzero) exception. The `owner` is
    /// the off-circuit SHA-256 address `AccountState::new` sets and is NOT
    /// gate-relevant (#226, Variant B). Returns the account, its asset_id,
    /// and the matching `MintWitness`. The creator pubkey is the account's
    /// own pubkey.
    fn mint_account(seed: u8, balance: u64) -> (AccountState, HashDigest, MintWitness) {
        let creator_pubkey = dummy_pubkey(seed);
        let name_hash = crate::types::calculate_name_hash("TEST");
        let decimals = 8u8;
        let asset_id = crate::types::calculate_asset_id(&creator_pubkey, &name_hash, decimals);
        let mut account = AccountState::new(creator_pubkey, asset_id);
        account.balance = balance;
        let mint = MintWitness {
            creator_pubkey,
            name_hash,
            decimals,
        };
        (account, asset_id, mint)
    }

    /// Build a non-mint account that does NOT satisfy the issuer gate:
    /// its `owner` is `SHA-256(own pubkey)` but its `asset_id` is one
    /// it did NOT create (derived from a *different* creator key). Such
    /// an account is a legitimate holder of someone else's asset and may
    /// receive coins, but it cannot grant itself the mint exception.
    fn non_mint_account(seed: u8, asset_id: HashDigest) -> AccountState {
        AccountState::new(dummy_pubkey(seed), asset_id)
    }

    /// An asset_id created by some *other* party — i.e. not derivable
    /// from `dummy_pubkey(holder_seed)`. Used to populate non-mint
    /// accounts that merely hold an asset they didn't issue.
    fn foreign_asset_id() -> HashDigest {
        crate::types::calculate_asset_id_from_name(&dummy_pubkey(250), "FOREIGN", 8)
    }

    fn pis_as_proof_data(proof: &ProofWithPublicInputs<F, C, D>) -> ProofData {
        let pis: [F; N_PROOF_DATA_PUBLIC_INPUTS] = proof.public_inputs
            [..N_PROOF_DATA_PUBLIC_INPUTS]
            .try_into()
            .unwrap();
        ProofData::from_field_elements(&pis)
    }

    /// Test helper: build a `MAX_IN_COINS`-length slot array with the
    /// first slot active (`(true, coin, nip)`) and all remaining slots
    /// inactive (`(false, dummy_coin, dummy_nip)`). Callers must pin
    /// the dummy values in local variables so their references outlive
    /// the returned vector.
    fn slots_first_active<'a>(
        coin: &'a Coin,
        nip: &'a NonInclusionProof,
        dummy_coin: &'a Coin,
        dummy_nip: &'a NonInclusionProof,
    ) -> Vec<(bool, &'a Coin, &'a NonInclusionProof)> {
        let mut v = Vec::with_capacity(MAX_IN_COINS);
        v.push((true, coin, nip));
        for _ in 1..MAX_IN_COINS {
            v.push((false, dummy_coin, dummy_nip));
        }
        v
    }

    /// Phase 2b test helper: build a `MAX_IN_COINS`-length source
    /// witness array with the first slot populated (`Some(_)`) and the
    /// rest inactive (`None`).
    fn sources_first_active<'a>(
        source: &'a InCoinSourceWitness<'a>,
    ) -> Vec<Option<InCoinSourceWitness<'a>>> {
        let mut v: Vec<Option<InCoinSourceWitness<'a>>> = Vec::with_capacity(MAX_IN_COINS);
        v.push(Some(InCoinSourceWitness {
            source_proof: source.source_proof,
            source_inclusion: source.source_inclusion,
            source_cmp: source.source_cmp,
        }));
        for _ in 1..MAX_IN_COINS {
            v.push(None);
        }
        v
    }

    /// Phase 2b test fixture for AccountUpdate-with-source: build a
    /// source state-transition proof AND a prev-account Initial proof,
    /// fold BOTH commitments into a shared history MMR (source at leaf
    /// 0, prev-account at leaf 1), and return CMPs + an inclusion
    /// proof for the source-emitted coin in the source's `OCR`.
    ///
    /// Returns: `(source_proof, coin_identifier, source_inclusion,
    /// source_cmp, prev_proof, consumer_cmp, history_root_extended)`.
    ///
    /// Wall-time: ~80 s on M3 (two Init proves: one source, one
    /// consumer prev).
    #[allow(clippy::type_complexity)]
    fn build_test_source_and_prev_witnesses(
        circuit: &StateTransitionCircuit,
        source_seed: u8,
        consumer_account_state: &AccountState,
        consumer_mint: Option<MintWitness>,
        out_amount: u64,
    ) -> (
        ProofWithPublicInputs<F, C, D>,
        HashDigest,
        InclusionProof,
        CommitmentMerkleProofs,
        ProofWithPublicInputs<F, C, D>,
        CommitmentMerkleProofs,
        HashDigest,
    ) {
        // 1. Source: issuer-mint account emitting one out-coin. The
        //    consumer must hold the SAME asset the source mints, so the
        //    fixture mints the consumer's asset.
        let asset_id = consumer_account_state.asset_id;
        let (mut source_account, source_mint) = {
            let creator_pubkey = dummy_pubkey(source_seed);
            // The consumer's asset_id MUST be the one this source mints,
            // else the per-slot `source_asset_id == transition_asset_id`
            // gate rejects.
            let mint = MintWitness {
                creator_pubkey,
                name_hash: crate::types::calculate_name_hash("TEST"),
                decimals: 8,
            };
            let acct = AccountState::new(creator_pubkey, asset_id);
            (acct, mint)
        };
        // Sanity: the consumer's asset really is this source's minted id.
        assert_eq!(
            asset_id,
            crate::types::calculate_asset_id(
                &source_mint.creator_pubkey,
                &source_mint.name_hash,
                source_mint.decimals,
            ),
            "fixture misuse: consumer asset_id must equal the source's minted asset_id"
        );
        source_account.balance = out_amount + 1_000;
        let mut post_source = source_account.clone();
        post_source.balance -= out_amount;
        let interim_source_asth = post_source.hash();
        let coin_id = crate::types::calculate_coin_identifier(interim_source_asth, asset_id, 0);
        let out_id_key = digest_to_bytes(&coin_id);
        let empty_smt = SparseMerkleTree::new();
        let out_nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins_inactive: Vec<(bool, &Coin, &NonInclusionProof)> = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect();
        let out_coins_source = out_slots_first_active(coin_id, out_amount, &out_nip, &dummy_nip);
        let source_proof = prove_initial_with_in_and_out_coins(
            circuit,
            &source_account,
            ZERO_HASH,
            &in_coins_inactive,
            &out_coins_source,
            &source_account.public_key,
            asset_id,
            Some(source_mint),
        )
        .expect("prove source Init");

        // 2. Consumer prev: Initial with all-inactive in/out-coins.
        //    Goes against empty history (same bootstrap pattern as
        //    source). The consumer holds the source's asset with an
        //    initial balance of 0 — a plain non-mint Initial.
        let prev_proof = prove_initial(
            circuit,
            consumer_account_state,
            ZERO_HASH,
            asset_id,
            consumer_mint,
        )
        .expect("prove consumer prev Init");

        // 3. Source's commitment SMT.
        let source_pd = pis_as_proof_data(&source_proof);
        let source_asth = source_pd.account_state_hash;
        let source_ocr = source_pd.output_coins_root;
        let source_pk_hash = hash_bytes(b"phase-2b-source-pk-hash");
        let source_pk_key = digest_to_bytes(&source_pk_hash);
        let source_commitment = hash_concat(&source_asth, &source_ocr);
        let mut source_smt = SparseMerkleTree::new();
        source_smt.insert(source_pk_key, source_commitment).unwrap();
        let source_smt_root = source_smt.root();
        let (source_smt_incl, _) = source_smt.generate_inclusion_proof(&source_pk_key).unwrap();

        // 4. Consumer prev's commitment SMT.
        let prev_pd = pis_as_proof_data(&prev_proof);
        let prev_asth = prev_pd.account_state_hash;
        let prev_ocr = prev_pd.output_coins_root;
        let consumer_pk_hash = hash_bytes(b"phase-2b-consumer-pk-hash");
        let consumer_pk_key = digest_to_bytes(&consumer_pk_hash);
        let consumer_commitment = hash_concat(&prev_asth, &prev_ocr);
        let mut consumer_smt = SparseMerkleTree::new();
        consumer_smt
            .insert(consumer_pk_key, consumer_commitment)
            .unwrap();
        let consumer_smt_root = consumer_smt.root();
        let (consumer_smt_incl, _) = consumer_smt
            .generate_inclusion_proof(&consumer_pk_key)
            .unwrap();

        // 5. Two-leaf MMR. Both source and consumer prev proved against
        //    ZERO_HASH (empty history) — bootstrap pattern. The (e)
        //    check `h(prev_smt_in_mmr_leaf || prev.commitment_history_root)`
        //    expects a leaf of shape `h(X || ZERO_HASH)` in the MMR.
        //    Only the FIRST-folded leaf has that shape (sibling =
        //    empty MMR root = ZERO_HASH). To make BOTH CMPs verifiable
        //    against the same MMR, we:
        //
        //    - Fold consumer at index 0 (sibling = ZERO_HASH);
        //      consumer's CMP (d) and (e) use index 0 — standard
        //      bootstrap.
        //    - Fold source at index 1 (sibling =
        //      `mmr_root_after_consumer_in_tree`); source's CMP (d)
        //      uses index 1.
        //    - Source's (e) "borrows" consumer's bootstrap shape:
        //      since source.commitment_history_root = ZERO_HASH and
        //      consumer's leaf is the ONLY h(? || ZERO_HASH) leaf in
        //      the MMR, source.prev_smt_in_mmr_leaf =
        //      consumer_smt_root and source.previous_root_history_proof.1
        //      = consumer_mmr_proof. The (e) check witnesses "some
        //      h(_ || ZERO_HASH) leaf exists in history" — semantically
        //      verifying that empty history is a prefix of current
        //      history, which is trivially true here.
        let mut mmr = MerkleMountainRange::new();
        let mmr_leaf_consumer = hash_concat(&consumer_smt_root, &ZERO_HASH);
        mmr.append(mmr_leaf_consumer);
        let mmr_root_after_consumer = mmr.root();
        let mmr_leaf_source = hash_concat(&source_smt_root, &mmr_root_after_consumer);
        mmr.append(mmr_leaf_source);
        let history_root_ext = mmr.root_extended(MMR_PROOF_PATH_LEN);
        let consumer_mmr_proof = mmr.get_proof(0).unwrap().extend_to(MMR_PROOF_PATH_LEN);
        let source_mmr_proof = mmr.get_proof(1).unwrap().extend_to(MMR_PROOF_PATH_LEN);
        assert!(consumer_mmr_proof.verify(mmr_leaf_consumer, history_root_ext));
        assert!(source_mmr_proof.verify(mmr_leaf_source, history_root_ext));

        // 6. Source's CMP. (d) at index 1 with sibling = post-consumer
        //    MMR root; (e) borrows consumer's bootstrap leaf at index
        //    0 since source's prior history was also empty.
        let source_cmp = CommitmentMerkleProofs {
            commitment_root: source_smt_root,
            commitment_proof: source_smt_incl,
            commitment_root_history_proof: source_mmr_proof,
            commitment_root_mmr_sibling: mmr_root_after_consumer,
            previous_root_history_proof: (consumer_smt_root, consumer_mmr_proof.clone()),
            commitment_account_state_hash: source_asth,
            commitment_out_coins_root: source_ocr,
        };

        // 7. Consumer prev's CMP. Standard bootstrap at MMR index 0:
        //    (d) and (e) both use the same leaf since
        //    prev.commitment_history_root = ZERO_HASH.
        let consumer_cmp = CommitmentMerkleProofs {
            commitment_root: consumer_smt_root,
            commitment_proof: consumer_smt_incl,
            commitment_root_history_proof: consumer_mmr_proof.clone(),
            commitment_root_mmr_sibling: ZERO_HASH,
            previous_root_history_proof: (consumer_smt_root, consumer_mmr_proof),
            commitment_account_state_hash: prev_asth,
            commitment_out_coins_root: prev_ocr,
        };

        // 8. Source's inclusion proof for coin_id in source.OCR.
        let coin_key = digest_to_bytes(&coin_id);
        let source_inclusion = InclusionProof {
            key: coin_key,
            siblings: out_nip.siblings.clone(),
        };
        assert!(
            source_inclusion.verify(coin_id, source_ocr),
            "source inclusion proof off-circuit verify must match source's published OCR"
        );

        (
            source_proof,
            coin_id,
            source_inclusion,
            source_cmp,
            prev_proof,
            consumer_cmp,
            history_root_ext,
        )
    }

    /// Phase 2b test fixture: build a real source state-transition
    /// proof emitting one out-coin, along with the
    /// SMT-inclusion-of-coin-in-source-OCR proof, the source's
    /// [`CommitmentMerkleProofs`] published in a fresh history MMR,
    /// and the extended `history_root` the consumer must prove
    /// against.
    ///
    /// Returns: `(source_proof, coin_identifier, source_inclusion,
    /// source_cmp, history_root_extended, source_post_account_state)`.
    /// The `source_post_account_state` is the source's
    /// post-out-coin-subtraction `AccountState` (with original
    /// pubkey) — useful for fixtures that need to chain further
    /// updates on the source side.
    ///
    /// Wall-time: ~40 s on M3 (one extra Init prove).
    #[allow(clippy::type_complexity)]
    fn build_test_source_witness(
        circuit: &StateTransitionCircuit,
        source_seed: u8,
        out_amount: u64,
    ) -> (
        ProofWithPublicInputs<F, C, D>,
        HashDigest,
        InclusionProof,
        CommitmentMerkleProofs,
        HashDigest,
        AccountState,
        HashDigest,
    ) {
        // 1. Source: issuer-mint account with enough balance to emit
        //    out_amount. The minted `asset_id` is returned so the
        //    consumer can hold the same asset.
        let (source_account, asset_id, source_mint) = mint_account(source_seed, out_amount + 1_000);

        // 2. Compute interim asth (post out-coin subtraction, pre pubkey
        //    rotation) and derive the source's slot-0 out-coin identifier.
        let mut post_source = source_account.clone();
        post_source.balance -= out_amount;
        let interim_asth = post_source.hash();
        let coin_id = crate::types::calculate_coin_identifier(interim_asth, asset_id, 0);

        // 3. Build the source's out-coin NIP in the empty SMT.
        let out_id_key = digest_to_bytes(&coin_id);
        let empty_smt = SparseMerkleTree::new();
        let out_nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();

        // 4. Slot arrays: no in-coins, slot 0 out-coin active.
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins: Vec<(bool, &Coin, &NonInclusionProof)> = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect();
        let out_coins = out_slots_first_active(coin_id, out_amount, &out_nip, &dummy_nip);

        // 5. Prove source Init against empty history.
        let source_proof = prove_initial_with_in_and_out_coins(
            circuit,
            &source_account,
            ZERO_HASH,
            &in_coins,
            &out_coins,
            &source_account.public_key,
            asset_id,
            Some(source_mint),
        )
        .expect("prove source Init");

        // 6. Extract source's ProofData from PIs.
        let source_pd = pis_as_proof_data(&source_proof);
        let source_asth = source_pd.account_state_hash;
        let source_ocr = source_pd.output_coins_root;

        // 7. Build source's CMP: commitment is in a freshly-folded
        //    history MMR. Bootstrap pattern (same shape as
        //    `build_test_commitment_witness`).
        let source_pk_hash = hash_bytes(b"phase-2b-source-pk-hash");
        let source_pk_key = digest_to_bytes(&source_pk_hash);
        let source_commitment = hash_concat(&source_asth, &source_ocr);
        let mut smt = SparseMerkleTree::new();
        smt.insert(source_pk_key, source_commitment).unwrap();
        let smt_root = smt.root();
        let (smt_incl, _) = smt.generate_inclusion_proof(&source_pk_key).unwrap();

        let prev_mmr_root = ZERO_HASH;
        let mmr_leaf = hash_concat(&smt_root, &prev_mmr_root);
        let mut mmr = MerkleMountainRange::new();
        mmr.append(mmr_leaf);
        let history_root_ext = mmr.root_extended(MMR_PROOF_PATH_LEN);
        let mmr_proof = mmr.get_proof(0).unwrap().extend_to(MMR_PROOF_PATH_LEN);
        assert!(mmr_proof.verify(mmr_leaf, history_root_ext));

        let source_cmp = CommitmentMerkleProofs {
            commitment_root: smt_root,
            commitment_proof: smt_incl,
            commitment_root_history_proof: mmr_proof.clone(),
            commitment_root_mmr_sibling: prev_mmr_root,
            previous_root_history_proof: (smt_root, mmr_proof),
            commitment_account_state_hash: source_asth,
            commitment_out_coins_root: source_ocr,
        };

        // 8. Build source's inclusion proof for coin_id in
        //    source.output_coins_root.
        //
        // **Slot-0 / single-out-coin fixture only.** This helper
        // emits exactly one out-coin (slot 0) into an empty SMT, so
        // the inclusion-proof siblings equal the non-inclusion-proof
        // siblings (the empty-tree path is unchanged outside the
        // leaf's position). If this fixture is ever extended to
        // produce multi-out-coin sources (slots > 0), the inclusion
        // siblings MUST be re-derived from the SMT *after* each
        // prior-slot insert — see
        // [`SparseMerkleTree::generate_inclusion_proof`] which
        // returns the correct siblings against the tree's current
        // state. Production [`account_node::send_coins`] already
        // does this correctly via `out_coins_tree.generate_inclusion_proof`
        // on the final tree; this restriction is fixture-only.
        //
        // TODO(stage-5d-next-5-followup): extend this fixture for
        // multi-out-coin sources once a test scenario requires it.
        let coin_key = digest_to_bytes(&coin_id);
        let source_inclusion = InclusionProof {
            key: coin_key,
            siblings: out_nip.siblings.clone(),
        };
        // Off-circuit sanity: the inclusion proof verifies against the
        // source's claimed `output_coins_root`.
        assert!(
            source_inclusion.verify(coin_id, source_ocr),
            "source inclusion proof off-circuit verify must match source's published OCR"
        );

        (
            source_proof,
            coin_id,
            source_inclusion,
            source_cmp,
            history_root_ext,
            post_source,
            asset_id,
        )
    }

    /// Stage 5c+ Initial-side smoke test (unchanged behaviour from 5c):
    /// a non-mint account with `balance = 0` is accepted, and the
    /// public-input `ProofData` matches the off-circuit reconstruction.
    /// The CommitmentMerkleProofs witness is the empty dummy.
    #[test]
    fn stage_5c_plus_initial_non_mint_zero_balance_accepted() {
        let circuit = build_circuit();
        // A holder of a foreign asset with balance 0 — does NOT satisfy
        // the issuer gate, but balance 0 needs no mint exception.
        let asset_id = foreign_asset_id();
        let account_state = non_mint_account(7, asset_id);

        let history_root = hash_bytes(b"history@5c+-init");
        let proof = prove_initial(&circuit, &account_state, history_root, asset_id, None)
            .expect("prove initial");
        verify(&circuit, &proof).expect("verify initial");

        let recovered = pis_as_proof_data(&proof);
        assert_eq!(recovered.account_state_hash, account_state.hash());
        assert_eq!(recovered.coin_history_root, DEFAULT_HASHES[0]);
        assert_eq!(recovered.asset_id, asset_id);
    }

    /// Mint exception under the issuer gate: the account is the
    /// legitimate issuer of its own asset, so a non-zero initial supply
    /// is accepted.
    #[test]
    fn stage_5c_plus_initial_mint_with_balance_accepted() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(99, 21_000_000_000_000);

        let history_root = hash_bytes(b"history@5c+-mint");
        let proof = prove_initial(&circuit, &account_state, history_root, asset_id, Some(mint))
            .expect("prove mint");
        verify(&circuit, &proof).expect("verify mint");
    }

    /// Mint-exception negative: a non-issuer account (holds a foreign
    /// asset) with a non-zero initial balance is rejected — only the
    /// asset's creator may bring supply into existence.
    #[test]
    fn stage_5c_plus_initial_non_mint_nonzero_balance_rejected() {
        let circuit = build_circuit();
        let asset_id = foreign_asset_id();
        let mut account_state = non_mint_account(7, asset_id);
        account_state.balance = 1;

        let history_root = hash_bytes(b"history@5c+-illegal");
        assert!(prove_initial(&circuit, &account_state, history_root, asset_id, None).is_err());
    }

    /// Issuer gate positive: account.public_key == creator_pk AND
    /// transition asset_id == calculate_asset_id(creator_pk, name_hash,
    /// decimals), Initial with non-zero balance → proof builds/verifies.
    /// (Owner is the off-circuit SHA-256 address and is not gated — #226.)
    #[test]
    fn issuer_gated_mint_accepted() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(45, 1_000_000);
        // Precondition: the gate's bindings hold for this fixture, and the
        // owner is the SHA-256 address (not the Poseidon image).
        assert_eq!(account_state.public_key, mint.creator_pubkey);
        assert_eq!(account_state.owner, crate::hash::sha256_to_digest(&mint.creator_pubkey));
        assert_eq!(
            asset_id,
            crate::types::calculate_asset_id(&mint.creator_pubkey, &mint.name_hash, mint.decimals)
        );

        let proof = prove_initial(
            &circuit,
            &account_state,
            hash_bytes(b"issuer-gated-mint"),
            asset_id,
            Some(mint),
        )
        .expect("issuer-gated mint must prove");
        verify(&circuit, &proof).expect("verify");
        assert_eq!(
            pis_as_proof_data(&proof).account_state_hash,
            account_state.hash()
        );
    }

    /// Variant B (#226): `owner` is the off-circuit SHA-256 address and is
    /// NOT bound in the mint gate. A legitimate mint (asset_id derives from
    /// the creator key AND account.public_key == creator) must still verify
    /// when `owner` is an arbitrary value != SHA-256(creator). Pins the
    /// removed `owner == Poseidon(creator)` binding so it cannot silently
    /// return (forge protection rides on asset_id ∧ public_key, not owner).
    #[test]
    fn mint_accepted_with_arbitrary_owner() {
        let circuit = build_circuit();
        let (mut account_state, asset_id, mint) = mint_account(46, 1_000_000);
        // Deliberately give the account an owner that is NOT the spec
        // SHA-256(creator) address (an unrelated Poseidon digest). Variant B:
        // the mint gate no longer binds owner.
        account_state.owner = hash_bytes(b"arbitrary-non-spec-owner");
        assert_ne!(
            account_state.owner,
            crate::hash::sha256_to_digest(&mint.creator_pubkey)
        );
        // The gate's actual bindings still hold for this fixture.
        assert_eq!(account_state.public_key, mint.creator_pubkey);

        let proof = prove_initial(
            &circuit,
            &account_state,
            hash_bytes(b"arbitrary-owner-mint"),
            asset_id,
            Some(mint),
        )
        .expect("mint must verify with an arbitrary owner — owner is not gated (Variant B)");
        verify(&circuit, &proof).expect("verify");
    }

    /// Issuer gate negative: the account's `public_key` is NOT the asset's
    /// creator key. `asset_ok` holds (the asset_id derives from the creator
    /// key) but the in-circuit `public_key == creator_pubkey` binding fails
    /// → no mint exception → the non-zero Initial balance is rejected.
    /// Post-#226 this `public_key == creator` binding is the forge guard the
    /// removed `owner == Poseidon(creator)` binding used to provide.
    #[test]
    fn mint_rejected_when_pubkey_not_creator() {
        let circuit = build_circuit();
        // Build a self-consistent asset_id for `creator_pubkey`, but make
        // the ACCOUNT keyed by a DIFFERENT pubkey. asset_ok holds, the
        // pubkey binding does not.
        let creator_pubkey = dummy_pubkey(70);
        let name_hash = crate::types::calculate_name_hash("TEST");
        let asset_id = crate::types::calculate_asset_id(&creator_pubkey, &name_hash, 8);
        // Account whose own pubkey is a different key (71) but claims the
        // creator's asset.
        let mut account_state = AccountState::new(dummy_pubkey(71), asset_id);
        account_state.balance = 1;
        assert_ne!(account_state.public_key, creator_pubkey);

        let mint = MintWitness {
            creator_pubkey,
            name_hash,
            decimals: 8,
        };
        assert!(prove_initial(
            &circuit,
            &account_state,
            hash_bytes(b"pubkey-not-creator"),
            asset_id,
            Some(mint),
        )
        .is_err());
    }

    /// Issuer gate negative: transition asset_id is NOT
    /// calculate_asset_id(creator_pk, ...). The pubkey binding holds
    /// (account.public_key == creator_pk) but asset_ok does not → no
    /// exception → the non-zero Initial balance is rejected.
    #[test]
    fn mint_rejected_when_asset_id_not_derived_from_creator() {
        let circuit = build_circuit();
        let creator_pubkey = dummy_pubkey(72);
        // The account is owned by creator_pubkey, but its asset_id is a
        // FOREIGN one (not derivable from creator_pubkey).
        let asset_id = foreign_asset_id();
        let mut account_state = AccountState::new(creator_pubkey, asset_id);
        account_state.balance = 1;
        assert_eq!(account_state.public_key, creator_pubkey);
        assert_ne!(
            asset_id,
            crate::types::calculate_asset_id(
                &creator_pubkey,
                &crate::types::calculate_name_hash("TEST"),
                8
            )
        );

        let mint = MintWitness {
            creator_pubkey,
            name_hash: crate::types::calculate_name_hash("TEST"),
            decimals: 8,
        };
        assert!(prove_initial(
            &circuit,
            &account_state,
            hash_bytes(b"asset-not-derived"),
            asset_id,
            Some(mint),
        )
        .is_err());
    }

    /// Issuer gate negative (forged inflation): owner == H(creator_pk)
    /// AND asset_id == calculate_asset_id(creator_pk, ...) both hold, but
    /// the account's own `public_key` — the key that signs the Bitcoin
    /// commitment verified at scan time — is a DIFFERENT key. This is the
    /// forgery an attacker would attempt: pick the victim's public
    /// owner/asset values, sign with your own key. The pubkey==creator
    /// binding makes `is_minting` false, so the non-zero Initial balance
    /// is rejected.
    #[test]
    fn mint_rejected_when_commitment_key_not_creator() {
        let circuit = build_circuit();
        let creator_pubkey = dummy_pubkey(73);
        let name_hash = crate::types::calculate_name_hash("TEST");
        let asset_id = crate::types::calculate_asset_id(&creator_pubkey, &name_hash, 8);
        // owner == H(creator_pk) and asset_id derives from creator_pk, but
        // the account's signing key is a different pubkey.
        let mut account_state = AccountState::new(creator_pubkey, asset_id);
        account_state.public_key = dummy_pubkey(74);
        account_state.balance = 1;
        assert_eq!(account_state.owner, crate::hash::sha256_to_digest(&creator_pubkey));
        assert_ne!(account_state.public_key, creator_pubkey);

        let mint = MintWitness {
            creator_pubkey,
            name_hash,
            decimals: 8,
        };
        assert!(prove_initial(
            &circuit,
            &account_state,
            hash_bytes(b"commitment-key-not-creator"),
            asset_id,
            Some(mint),
        )
        .is_err());
    }

    /// Account-asset binding negative: the witnessed `account_asset_id`
    /// (from `account_state.asset_id`) differs from the
    /// `transition_asset_id` public input. The unmasked
    /// `connect(account_asset_id, transition_asset_id)` constraint fires
    /// at prove time. Uses a zero-balance non-mint account so the only
    /// failing constraint is the asset binding.
    #[test]
    fn account_asset_id_must_equal_transition_asset_id() {
        let circuit = build_circuit();
        let account_asset = foreign_asset_id();
        let account_state = non_mint_account(7, account_asset);
        // Pass a DIFFERENT transition asset_id than the account holds.
        let transition_asset =
            crate::types::calculate_asset_id_from_name(&dummy_pubkey(251), "DIFFERENT", 8);
        assert_ne!(account_asset, transition_asset);

        assert!(prove_initial(
            &circuit,
            &account_state,
            hash_bytes(b"asset-binding"),
            transition_asset,
            None,
        )
        .is_err());
    }

    /// Build a `CommitmentMerkleProofs` witness for an Initial → AccountUpdate
    /// chain on the same account state.
    ///
    /// The off-circuit setup mirrors what the node scanner would do:
    /// 1. Build the commitment value `c = h(asth || ocr)` for the prev proof.
    /// 2. Build the SMT containing `(pk_hash → c)`.
    /// 3. Fold the SMT root into the history MMR alongside the empty prev
    ///    MMR root.
    /// 4. Build extended MMR proofs (a) and (e) at depth
    ///    `MMR_PROOF_PATH_LEN`.
    ///
    /// Returns `(cmp, extended_history_root)`.
    fn build_test_commitment_witness(
        prev_asth: HashDigest,
        prev_ocr: HashDigest,
    ) -> (CommitmentMerkleProofs, HashDigest) {
        // SMT key derived from the prev pubkey hash (placeholder bytes).
        let pk_hash = hash_bytes(b"5c+-test-pubkey");
        let pk_key = digest_to_bytes(&pk_hash);

        // Commitment value committed to in the SMT.
        let commitment = hash_concat(&prev_asth, &prev_ocr);

        let mut smt = SparseMerkleTree::new();
        smt.insert(pk_key, commitment).unwrap();
        let smt_root = smt.root();
        let (smt_inclusion, _) = smt.generate_inclusion_proof(&pk_key).unwrap();

        // History MMR: fold `(smt_root, ZERO_HASH)` as the first leaf.
        // The bootstrap pattern: Init was proved against the empty
        // history (`prev.commitment_history_root == ZERO_HASH`), so the
        // (e) MMR leaf `h(smt_root || prev.commitment_history_root)`
        // coincides with the (d) MMR leaf `h(smt_root || prev_mmr_root)`.
        // Both MMR proofs point to the same MMR leaf at index 0.
        let prev_mmr_root = ZERO_HASH;
        let mmr_leaf = hash_concat(&smt_root, &prev_mmr_root);
        let mut mmr = MerkleMountainRange::new();
        mmr.append(mmr_leaf);
        let history_root_extended = mmr.root_extended(MMR_PROOF_PATH_LEN);
        let mmr_proof = mmr.get_proof(0).unwrap().extend_to(MMR_PROOF_PATH_LEN);
        assert!(mmr_proof.verify(mmr_leaf, history_root_extended));

        let cmp = CommitmentMerkleProofs {
            commitment_root: smt_root,
            commitment_proof: smt_inclusion,
            commitment_root_history_proof: mmr_proof.clone(),
            commitment_root_mmr_sibling: prev_mmr_root,
            previous_root_history_proof: (smt_root, mmr_proof),
            commitment_account_state_hash: prev_asth,
            commitment_out_coins_root: prev_ocr,
        };
        (cmp, history_root_extended)
    }

    /// Primary 5c+ positive test: an Initial → AccountUpdate chain with a
    /// real `CommitmentMerkleProofs` witness. The prev proof's commitment
    /// is published in the SMT, the SMT is folded into the MMR, and the
    /// AccountUpdate proof verifies the (c)(d)(e) chain in-circuit.
    #[test]
    fn stage_5c_plus_initial_then_account_update_with_commitment_proofs() {
        let circuit = build_circuit();

        // Initial proof: issuer-mint account.
        let (account_state, asset_id, mint) = mint_account(11, 1_000_000);

        // Bootstrap pattern: Init commits to the EMPTY history
        // (`prev.commitment_history_root == ZERO_HASH`); after Init the
        // node folds its commitment into the MMR, giving the
        // post-fold `history_root_extended` against which Update is
        // proved. The fixture matches that exact layout — (e)'s leaf
        // shape `h(smt_root || ZERO_HASH)` coincides with (d)'s leaf.
        let prev_asth = account_state.hash();
        let prev_ocr = DEFAULT_HASHES[0];
        let (cmp, history_root_extended) = build_test_commitment_witness(prev_asth, prev_ocr);

        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH, asset_id, Some(mint))
            .expect("prove init");
        verify(&circuit, &init_proof).expect("verify init");

        let update_proof = prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
            asset_id,
        )
        .expect("prove update");
        verify(&circuit, &update_proof).expect("verify update");

        // Carry-over: update.coin_history_root == init.coin_history_root.
        let init_pd = pis_as_proof_data(&init_proof);
        let update_pd = pis_as_proof_data(&update_proof);
        assert_eq!(update_pd.coin_history_root, init_pd.coin_history_root);
        assert_eq!(update_pd.account_state_hash, account_state.hash());
        assert_eq!(update_pd.commitment_history_root, history_root_extended);
    }

    /// Stage 5c+ negative: AccountUpdate where the current account_state
    /// hashes to something different from prev's `account_state_hash` →
    /// rejected by (b).
    #[test]
    fn stage_5c_plus_account_update_state_discontinuity_rejected() {
        let circuit = build_circuit();

        let (prev_state, asset_id, mint) = mint_account(42, 500);

        let prev_asth = prev_state.hash();
        let (cmp, history_root_extended) =
            build_test_commitment_witness(prev_asth, DEFAULT_HASHES[0]);
        let prev_proof = prove_initial(&circuit, &prev_state, ZERO_HASH, asset_id, Some(mint))
            .expect("prove prev init");

        // Try to update with a DIFFERENT account_state.
        let mut next_state = prev_state.clone();
        next_state.balance += 1;
        assert!(prove_account_update(
            &circuit,
            &next_state,
            history_root_extended,
            &prev_proof,
            &cmp,
            asset_id,
        )
        .is_err());
    }

    /// Stage 5c+ negative (c): AccountUpdate where mp.commitment_account_state_hash
    /// is lied about so it no longer matches `account_state.hash()`.
    #[test]
    fn stage_5c_plus_account_update_wrong_commitment_account_state_hash_rejected() {
        let circuit = build_circuit();

        let (account_state, asset_id, mint) = mint_account(123, 1);

        let true_asth = account_state.hash();
        let (mut cmp, history_root_extended) =
            build_test_commitment_witness(true_asth, DEFAULT_HASHES[0]);

        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH, asset_id, Some(mint))
            .expect("prove init");

        // Mutate ONLY the witnessed commitment_account_state_hash; leave
        // the SMT (which still contains the honest commitment) intact.
        // (c) catches the mismatch via the masked equality constraint.
        cmp.commitment_account_state_hash = hash_bytes(b"lying-asth");

        assert!(prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
            asset_id,
        )
        .is_err());
    }

    /// Build-time assertion: `set_cmp_witness` rejects a `cmp` whose
    /// SMT inclusion proof is short of `TREE_DEPTH` siblings — the
    /// in-circuit gadget is built against a fixed 256-level shape, so
    /// a malformed witness would silently skip levels.
    #[test]
    #[should_panic(expected = "SMT inclusion proof must be padded to TREE_DEPTH siblings")]
    fn stage_5c_plus_set_cmp_witness_panics_on_short_smt_path() {
        let circuit = build_circuit();
        let mut cmp = dummy_cmp();
        cmp.commitment_proof.siblings.truncate(TREE_DEPTH - 1);
        let mut pw = PartialWitness::new();
        set_cmp_witness(&mut pw, &circuit, &cmp);
    }

    /// Build-time assertion: `set_cmp_witness` rejects a `cmp` whose
    /// MMR (d) path is short of `MMR_PROOF_PATH_LEN` siblings.
    #[test]
    #[should_panic(expected = "MMR proof (d) must be extended to MMR_PROOF_PATH_LEN siblings")]
    fn stage_5c_plus_set_cmp_witness_panics_on_short_mmr_a_path() {
        let circuit = build_circuit();
        let mut cmp = dummy_cmp();
        cmp.commitment_root_history_proof
            .path
            .truncate(MMR_PROOF_PATH_LEN - 1);
        let mut pw = PartialWitness::new();
        set_cmp_witness(&mut pw, &circuit, &cmp);
    }

    /// Build-time assertion: `set_cmp_witness` rejects a `cmp` whose
    /// MMR (e) path is short of `MMR_PROOF_PATH_LEN` siblings.
    #[test]
    #[should_panic(expected = "MMR proof (e) must be extended to MMR_PROOF_PATH_LEN siblings")]
    fn stage_5c_plus_set_cmp_witness_panics_on_short_mmr_b_path() {
        let circuit = build_circuit();
        let mut cmp = dummy_cmp();
        cmp.previous_root_history_proof
            .1
            .path
            .truncate(MMR_PROOF_PATH_LEN - 1);
        let mut pw = PartialWitness::new();
        set_cmp_witness(&mut pw, &circuit, &cmp);
    }

    /// Stage 5d-next-5 Phase 2b positive: Initial proof with one
    /// active in-coin slot whose source is a real state-transition
    /// proof.
    ///
    /// Validates the full §8 step 2 chain end-to-end:
    /// - Aggregator verifies the source proof against the cyclic vk
    ///   (`connect_hashes(claimed_st_digest, ...)` binding holds);
    /// - SMT inclusion of `coin_identifier` in the source's
    ///   `output_coins_root` succeeds;
    /// - SPEC §8 (c)(d)(e) chain plus the OCR-coupling check succeeds
    ///   against the consumer's `history_root` (the same history into
    ///   which the source's commitment was folded);
    /// - The unchanged 5d-next-3 coin-history side: insertion +
    ///   apply_coin balance-add.
    ///
    /// Output `ProofData`:
    /// - `coin_history_root == nip.insert(source-emitted coin_id)`;
    /// - `account_state_hash == final_state.hash()` (balance += amount).
    #[test]
    fn stage_5d_next_5_phase_2b_initial_with_one_active_in_coin_and_source() {
        let circuit = build_circuit();

        // Build the source side: a mint account emits one out-coin
        // worth `out_amount`. Returns the source proof + inclusion +
        // CMP + the extended history_root the consumer must use.
        let out_amount: u64 = 42;
        let (
            source_proof,
            coin_identifier,
            source_inclusion,
            source_cmp,
            history_root,
            _post,
            asset_id,
        ) = build_test_source_witness(&circuit, 11, out_amount);

        // Consumer: a non-mint account holding the SOURCE's asset,
        // absorbing the source's coin.
        let mut account_state = non_mint_account(111, asset_id);
        account_state.balance = 0;

        // Off-circuit coin-history NIP for the source-emitted
        // `coin_identifier` in the consumer's (empty) coin_history SMT.
        let coin_key = digest_to_bytes(&coin_identifier);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();
        assert!(nip.verify(), "off-circuit non-inclusion sanity");
        let expected_new_coin_history = nip.insert(coin_identifier);

        let coin = Coin {
            identifier: coin_identifier,
            recipient: account_state.owner,
            amount: out_amount,
            asset_id,
        };
        let mut final_account_state = account_state.clone();
        final_account_state.balance += coin.amount;

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&coin, &nip, &dummy_c, &dummy_nip);
        let inactive_out_coins: Vec<(bool, HashDigest, u64, &NonInclusionProof)> = (0
            ..MAX_OUT_COINS)
            .map(|_| (false, ZERO_HASH, 0u64, &dummy_nip))
            .collect();
        let source_witness = InCoinSourceWitness {
            source_proof: &source_proof,
            source_inclusion: &source_inclusion,
            source_cmp: &source_cmp,
        };
        let sources = sources_first_active(&source_witness);

        let proof = prove_initial_with_in_and_out_coins_and_sources(
            &circuit,
            &account_state,
            history_root,
            &in_coins,
            &inactive_out_coins,
            &account_state.public_key,
            &sources,
            asset_id,
            None,
        )
        .expect("prove init with active in-coin + source");
        verify(&circuit, &proof).expect("verify");

        let recovered = pis_as_proof_data(&proof);
        assert_eq!(recovered.coin_history_root, expected_new_coin_history);
        assert_eq!(recovered.account_state_hash, final_account_state.hash());
        assert_eq!(recovered.commitment_history_root, history_root);
    }

    /// Stage 5d negative: a tampered non-inclusion path on an active
    /// slot must fail to prove (the `connect_hashes(computed_old,
    /// running)` constraint rejects).
    #[test]
    fn stage_5d_initial_with_tampered_nip_path_rejected() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(11, 1);

        let coin_identifier = hash_bytes(b"5d-tampered");
        let coin_key = digest_to_bytes(&coin_identifier);
        let empty_smt = SparseMerkleTree::new();
        let mut nip = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();
        // Tamper a sibling — the recomputed root won't match
        // `DEFAULT_HASHES[0]` and the in-circuit check fires.
        nip.siblings[0] = hash_bytes(b"lying-sibling");

        let coin = Coin {
            identifier: coin_identifier,
            recipient: account_state.owner,
            amount: 0,
            asset_id,
        };
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&coin, &nip, &dummy_c, &dummy_nip);
        assert!(prove_initial_with_in_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
            asset_id,
            Some(mint),
        )
        .is_err());
    }

    /// Stage 5d apply_coin negative: an in-coin with `recipient !=
    /// account.owner` is rejected by the recipient-equality
    /// constraint.
    #[test]
    fn stage_5d_initial_in_coin_wrong_recipient_rejected() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(11, 1);

        let coin_identifier = hash_bytes(b"5d-wrong-recipient");
        let coin_key = digest_to_bytes(&coin_identifier);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();

        let coin = Coin {
            identifier: coin_identifier,
            // Lie: this coin is addressed to a different account.
            recipient: hash_bytes(b"some-other-owner"),
            amount: 1,
            asset_id,
        };
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&coin, &nip, &dummy_c, &dummy_nip);
        assert!(prove_initial_with_in_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
            asset_id,
            Some(mint),
        )
        .is_err());
    }

    /// Stage 5d apply_coin negative: adding a coin whose amount would
    /// overflow `u64` is rejected by the balance-overflow-check.
    #[test]
    fn stage_5d_initial_in_coin_overflow_rejected() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(11, u64::MAX);

        let coin_identifier = hash_bytes(b"5d-overflow");
        let coin_key = digest_to_bytes(&coin_identifier);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();

        let coin = Coin {
            identifier: coin_identifier,
            recipient: account_state.owner,
            // u64::MAX + 1 overflows.
            amount: 1,
            asset_id,
        };
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&coin, &nip, &dummy_c, &dummy_nip);
        assert!(prove_initial_with_in_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
            asset_id,
            Some(mint),
        )
        .is_err());
    }

    /// Test helper: build a `MAX_OUT_COINS`-length out-coin slot
    /// array with the first slot active (`(true, identifier, amount,
    /// nip)`) and the rest inactive.
    fn out_slots_first_active<'a>(
        identifier: HashDigest,
        amount: u64,
        nip: &'a NonInclusionProof,
        dummy_nip: &'a NonInclusionProof,
    ) -> Vec<(bool, HashDigest, u64, &'a NonInclusionProof)> {
        let mut v = Vec::with_capacity(MAX_OUT_COINS);
        v.push((true, identifier, amount, nip));
        for _ in 1..MAX_OUT_COINS {
            v.push((false, ZERO_HASH, 0u64, dummy_nip));
        }
        v
    }

    /// Stage 5d-next-3 positive: Initial proof emits one out-coin.
    /// The interim account-state hash (post in-coins, before pubkey
    /// rotation) drives `out_coin_identifier = H(interim_asth || 0)`.
    /// Output `ProofData`:
    /// - `account_state_hash` is the FINAL hash (with the rotated
    ///   pubkey and the post-subtraction balance);
    /// - `output_coins_root` is the SMT after inserting the
    ///   out-coin's identifier;
    /// - `coin_history_root` is `DEFAULT_HASHES[0]` (no in-coins).
    #[test]
    fn stage_5d_next_3_initial_with_one_active_out_coin() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(21, 100);

        // Per SPEC §8 `send_coins`, the interim account-state hash
        // (used for identifier derivation) is computed AFTER balance
        // subtractions but BEFORE pubkey rotation. So for an out-coin
        // amount of 30, the interim balance is 70 and the interim
        // pubkey is the INITIAL one.
        let out_coin_amount: u64 = 30;
        let mut interim_account_state = account_state.clone();
        interim_account_state.balance -= out_coin_amount;
        let interim_asth = interim_account_state.hash();
        let expected_out_id = crate::types::calculate_coin_identifier(interim_asth, asset_id, 0);

        // Off-circuit: non-inclusion of expected_out_id in empty SMT.
        let out_id_key = digest_to_bytes(&expected_out_id);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();
        let expected_out_root = nip.insert(expected_out_id);

        // Rotate pubkey: next_public_key chosen by the prover.
        let next_pubkey = dummy_pubkey(122);

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect::<Vec<_>>();
        let out_coins = out_slots_first_active(expected_out_id, out_coin_amount, &nip, &dummy_nip);

        let history_root = hash_bytes(b"history@5d-next-3-out");
        let proof = prove_initial_with_in_and_out_coins(
            &circuit,
            &account_state,
            history_root,
            &in_coins,
            &out_coins,
            &next_pubkey,
            asset_id,
            Some(mint),
        )
        .expect("prove init with out-coin");
        verify(&circuit, &proof).expect("verify");

        let recovered = pis_as_proof_data(&proof);

        // FINAL account_state: balance = 100 - 30 = 70, with rotated pubkey.
        let mut final_account_state = interim_account_state.clone();
        final_account_state.public_key = next_pubkey;
        assert_eq!(recovered.account_state_hash, final_account_state.hash());
        assert_eq!(recovered.output_coins_root, expected_out_root);
        assert_eq!(recovered.coin_history_root, DEFAULT_HASHES[0]);
        assert_eq!(recovered.commitment_history_root, history_root);
    }

    /// Stage 5d-next-3 negative: out-coin whose `identifier` does not
    /// equal `H(interim_asth || index)` is rejected by the masked
    /// identifier-equality constraint.
    #[test]
    fn stage_5d_next_3_initial_out_coin_wrong_identifier_rejected() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(22, 100);

        // A lying identifier that is NOT `H(interim_asth || asset_id || 0)`.
        let lying_id = hash_bytes(b"5d-next-3-lying-out-id");
        let out_id_key = digest_to_bytes(&lying_id);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect::<Vec<_>>();
        let out_coins = out_slots_first_active(lying_id, 1, &nip, &dummy_nip);

        let next_pubkey = account_state.public_key;
        assert!(prove_initial_with_in_and_out_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
            &out_coins,
            &next_pubkey,
            asset_id,
            Some(mint),
        )
        .is_err());
    }

    /// Stage 5d-next-3 negative: out-coin amount exceeding the
    /// account balance is rejected by the underflow check.
    #[test]
    fn stage_5d_next_3_initial_out_coin_underflow_rejected() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(23, 5); // balance < requested out amount

        // Compute the expected identifier so identifier-eq passes; the
        // underflow check is what should fire.
        let interim_asth = account_state.hash();
        let expected_out_id = crate::types::calculate_coin_identifier(interim_asth, asset_id, 0);
        let out_id_key = digest_to_bytes(&expected_out_id);
        let empty_smt = SparseMerkleTree::new();
        let nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect::<Vec<_>>();
        let out_coins = out_slots_first_active(expected_out_id, 10, &nip, &dummy_nip);

        let next_pubkey = account_state.public_key;
        assert!(prove_initial_with_in_and_out_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
            &out_coins,
            &next_pubkey,
            asset_id,
            Some(mint),
        )
        .is_err());
    }

    /// Build-time assertion: `set_out_coin_slot_witness` rejects a
    /// non-inclusion proof of the wrong length.
    #[test]
    #[should_panic(
        expected = "OutCoinSlot: non-inclusion proof must be padded to TREE_DEPTH siblings"
    )]
    fn stage_5d_next_3_set_out_coin_slot_witness_panics_on_short_nip_path() {
        let circuit = build_circuit();
        let mut nip = dummy_non_inclusion_proof();
        nip.siblings.truncate(TREE_DEPTH - 1);
        let mut pw = PartialWitness::new();
        set_out_coin_slot_witness(
            &mut pw,
            &circuit.out_coin_slots[0],
            true,
            ZERO_HASH,
            0,
            &nip,
        );
    }

    /// Build-time assertion: out-coin slot count guard on
    /// `prove_initial_with_in_and_out_coins`.
    #[test]
    #[should_panic(
        expected = "prove_initial_with_in_and_out_coins_and_sources: caller must supply exactly MAX_OUT_COINS out-coin slot witnesses"
    )]
    fn stage_5d_next_3_prove_initial_panics_on_wrong_out_slot_count() {
        let circuit = build_circuit();
        let account_state = non_mint_account(7, foreign_asset_id());
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect::<Vec<_>>();
        let _ = prove_initial_with_in_and_out_coins(
            &circuit,
            &account_state,
            ZERO_HASH,
            &in_coins,
            &[], // 0 out-coin slots, expected MAX_OUT_COINS
            &account_state.public_key,
            ZERO_HASH,
            None,
        );
    }

    /// Build-time assertion: in-coin slot count guard on
    /// `prove_initial_with_in_and_out_coins`.
    #[test]
    #[should_panic(
        expected = "prove_initial_with_in_and_out_coins_and_sources: caller must supply exactly MAX_IN_COINS in-coin slot witnesses"
    )]
    fn stage_5d_next_3_prove_initial_panics_on_wrong_in_slot_count() {
        let circuit = build_circuit();
        let account_state = non_mint_account(7, foreign_asset_id());
        let dummy_nip = dummy_non_inclusion_proof();
        let out_coins = (0..MAX_OUT_COINS)
            .map(|_| (false, ZERO_HASH, 0u64, &dummy_nip))
            .collect::<Vec<_>>();
        let _ = prove_initial_with_in_and_out_coins(
            &circuit,
            &account_state,
            ZERO_HASH,
            &[], // 0 in-coin slots, expected MAX_IN_COINS
            &out_coins,
            &account_state.public_key,
            ZERO_HASH,
            None,
        );
    }

    /// Build-time assertion: in-coin slot count guard on
    /// `prove_account_update_with_in_and_out_coins`.
    #[test]
    #[should_panic(
        expected = "prove_account_update_with_in_and_out_coins_and_sources: caller must supply exactly MAX_IN_COINS in-coin slot witnesses"
    )]
    fn stage_5d_next_3_prove_account_update_panics_on_wrong_in_slot_count() {
        // The slot-count `assert_eq!` fires at the top of the function,
        // before any witness setting or proving. Hand it a
        // `cyclic_base_proof` dummy for `prev` instead of paying ~13 min
        // to generate a real Init proof — the panic short-circuits
        // before `prev` is consumed.
        let circuit = build_circuit();
        let account_state = non_mint_account(8, foreign_asset_id());
        let cmp = dummy_cmp();
        let dummy_inner_pis = std::iter::empty::<(usize, F)>().collect();
        let dummy_prev = cyclic_base_proof(
            &circuit.common_data,
            &circuit.data.verifier_only,
            dummy_inner_pis,
        );
        let dummy_nip = dummy_non_inclusion_proof();
        let out_coins = (0..MAX_OUT_COINS)
            .map(|_| (false, ZERO_HASH, 0u64, &dummy_nip))
            .collect::<Vec<_>>();
        let _ = prove_account_update_with_in_and_out_coins(
            &circuit,
            &account_state,
            ZERO_HASH,
            &dummy_prev,
            &cmp,
            &[], // wrong: expected MAX_IN_COINS
            &out_coins,
            &account_state.public_key,
            ZERO_HASH,
        );
    }

    /// Build-time assertion: out-coin slot count guard on
    /// `prove_account_update_with_in_and_out_coins`.
    #[test]
    #[should_panic(
        expected = "prove_account_update_with_in_and_out_coins_and_sources: caller must supply exactly MAX_OUT_COINS out-coin slot witnesses"
    )]
    fn stage_5d_next_3_prove_account_update_panics_on_wrong_out_slot_count() {
        // Same `cyclic_base_proof` short-circuit as the in-slot test.
        let circuit = build_circuit();
        let account_state = non_mint_account(9, foreign_asset_id());
        let cmp = dummy_cmp();
        let dummy_inner_pis = std::iter::empty::<(usize, F)>().collect();
        let dummy_prev = cyclic_base_proof(
            &circuit.common_data,
            &circuit.data.verifier_only,
            dummy_inner_pis,
        );
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = (0..MAX_IN_COINS)
            .map(|_| (false, &dummy_c, &dummy_nip))
            .collect::<Vec<_>>();
        let _ = prove_account_update_with_in_and_out_coins(
            &circuit,
            &account_state,
            ZERO_HASH,
            &dummy_prev,
            &cmp,
            &in_coins,
            &[], // wrong: expected MAX_OUT_COINS
            &account_state.public_key,
            ZERO_HASH,
        );
    }

    /// Build-time assertion: `set_in_coin_slot_witness` rejects a
    /// non-inclusion proof of the wrong length — the in-circuit gadget
    /// expects exactly `TREE_DEPTH` siblings.
    #[test]
    #[should_panic(
        expected = "InCoinSlot: non-inclusion proof must be padded to TREE_DEPTH siblings"
    )]
    fn stage_5d_set_in_coin_slot_witness_panics_on_short_nip_path() {
        let circuit = build_circuit();
        let mut nip = dummy_non_inclusion_proof();
        nip.siblings.truncate(TREE_DEPTH - 1);
        let mut pw = PartialWitness::new();
        set_in_coin_slot_witness(
            &mut pw,
            &circuit.in_coin_slots[0],
            true,
            ZERO_HASH,
            ZERO_HASH,
            0,
            &nip,
        );
    }

    /// Build-time assertion: `prove_initial_with_in_coins` rejects a
    /// caller that doesn't supply exactly `MAX_IN_COINS` slot witnesses.
    #[test]
    #[should_panic(
        expected = "prove_initial_with_in_coins: caller must supply exactly MAX_IN_COINS slot witnesses"
    )]
    fn stage_5d_prove_initial_panics_on_wrong_slot_count() {
        let circuit = build_circuit();
        let account_state = non_mint_account(7, foreign_asset_id());
        let _ = prove_initial_with_in_coins(
            &circuit,
            &account_state,
            ZERO_HASH,
            &[], // 0 slots, expected MAX_IN_COINS = 1
            ZERO_HASH,
            None,
        );
    }

    /// Build-time assertion: `prove_account_update_with_in_coins`
    /// rejects a caller that doesn't supply exactly `MAX_IN_COINS`
    /// slot witnesses.
    #[test]
    #[should_panic(
        expected = "prove_account_update_with_in_coins: caller must supply exactly MAX_IN_COINS slot witnesses"
    )]
    fn stage_5d_prove_account_update_panics_on_wrong_slot_count() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(11, 1);
        let (cmp, history_root_extended) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH, asset_id, Some(mint))
            .expect("prove init");
        let _ = prove_account_update_with_in_coins(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
            &[], // 0 slots, expected MAX_IN_COINS = 1
            asset_id,
        );
    }

    /// Stage 5e (SPEC §13): tampered MMR-(d) path — proof that the
    /// commitment_root sits in `history_root` is invalid. The
    /// in-circuit check rejects.
    #[test]
    fn stage_5e_account_update_tampered_mmr_a_path_rejected() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(31, 1);

        let (mut cmp, history_root_extended) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH, asset_id, Some(mint))
            .expect("prove init");
        cmp.commitment_root_history_proof.path[0] = hash_bytes(b"lying-mmr-a-sib");
        assert!(prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
            asset_id,
        )
        .is_err());
    }

    /// Stage 5e (SPEC §13): tampered MMR-(e) path — proof that prev's
    /// committed history is a prefix of `history_root` is invalid.
    #[test]
    fn stage_5e_account_update_tampered_mmr_b_path_rejected() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(32, 1);

        let (mut cmp, history_root_extended) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH, asset_id, Some(mint))
            .expect("prove init");
        cmp.previous_root_history_proof.1.path[0] = hash_bytes(b"lying-mmr-b-sib");
        assert!(prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
            asset_id,
        )
        .is_err());
    }

    /// Stage 5e (SPEC §13): wrong `commitment_root_mmr_sibling` — the
    /// MMR-(d) leaf no longer hashes to the witnessed `commitment_root`
    /// path, so the MMR-(d) verification fails.
    #[test]
    fn stage_5e_account_update_wrong_mmr_sibling_rejected() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(33, 1);

        let (mut cmp, history_root_extended) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH, asset_id, Some(mint))
            .expect("prove init");
        cmp.commitment_root_mmr_sibling = hash_bytes(b"lying-prev-mmr-root");
        assert!(prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
            asset_id,
        )
        .is_err());
    }

    /// Stage 5e (SPEC §13): AccountUpdate proved against a
    /// `history_root` that the real MMR does not match. With (d)+(e)
    /// wired, both MMR proofs would have to reconstruct to the lying
    /// `history_root` — they can't, so the proof fails.
    #[test]
    fn stage_5e_account_update_wrong_history_root_rejected() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(34, 1);

        let (cmp, _real_history_root) =
            build_test_commitment_witness(account_state.hash(), DEFAULT_HASHES[0]);
        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH, asset_id, Some(mint))
            .expect("prove init");
        // Lie about the history_root — neither MMR proof reconstructs to it.
        let lying_history_root = hash_bytes(b"lying-history");
        assert!(prove_account_update(
            &circuit,
            &account_state,
            lying_history_root,
            &init_proof,
            &cmp,
            asset_id,
        )
        .is_err());
    }

    /// Stage 5d-next-5 Phase 2b integration: a single Initial proof
    /// exercising BOTH the in-coins AND the out-coins loops in one
    /// transition, with a real source proof backing the in-coin.
    /// Composes the full SPEC §8 flow end-to-end:
    ///
    /// 1. Source: mint account emits one out-coin (slot 0) worth 30.
    /// 2. Consumer: mint account with initial balance 100.
    /// 3. One active in-coin = source's emitted out-coin (id derived
    ///    from source's interim asth, amount 30) — running balance
    ///    100 + 30 = 130, coin_history advances.
    /// 4. One active out-coin (id derived from the *consumer's*
    ///    interim asth, amount 50, sent to a rotated pubkey) —
    ///    running balance 80, output_coins_root advances.
    /// 5. Final `ProofData.account_state_hash` reflects the rotated
    ///    pubkey and balance 80.
    /// 6. Source's commitment is published in `history_root`; the
    ///    in-coin's source-side §8 chain verifies against it.
    #[test]
    fn stage_5d_next_5_phase_2b_initial_combined_in_and_out_coin_with_source() {
        let circuit = build_circuit();

        let in_coin_amount: u64 = 30;
        let (source_proof, in_coin_id, source_inclusion, source_cmp, history_root, _post, asset_id) =
            build_test_source_witness(&circuit, 60, in_coin_amount);

        // Consumer holds the SOURCE's asset and is its issuer-mint (the
        // consumer also starts with a freshly-minted supply of 100). The
        // consumer's owner must therefore be the asset's creator. Build
        // the consumer as the issuer of `asset_id`: same creator key the
        // source used (dummy_pubkey(60)).
        let creator_pubkey = dummy_pubkey(60);
        let mint = MintWitness {
            creator_pubkey,
            name_hash: crate::types::calculate_name_hash("TEST"),
            decimals: 8,
        };
        let mut account_state = AccountState::new(creator_pubkey, asset_id);
        account_state.balance = 100;

        // ===== Consumer's in-coin side =====
        let in_coin_key = digest_to_bytes(&in_coin_id);
        let empty_smt = SparseMerkleTree::new();
        let in_nip = empty_smt.generate_non_inclusion_proof(in_coin_key).unwrap();
        let in_coin = Coin {
            identifier: in_coin_id,
            recipient: account_state.owner,
            amount: in_coin_amount,
            asset_id,
        };
        let expected_coin_history_root = in_nip.insert(in_coin_id);

        // ===== Consumer's out-coin side =====
        // Post-in-coins, pre-out-coin balance is 130; the in-circuit
        // running balance subtracts 50 → 80; interim_asth uses balance
        // 80 + INITIAL pubkey.
        let out_coin_amount: u64 = 50;
        let mut interim_account_state = account_state.clone();
        interim_account_state.balance = account_state.balance + in_coin.amount - out_coin_amount;
        let interim_asth = interim_account_state.hash();
        let expected_out_id = crate::types::calculate_coin_identifier(interim_asth, asset_id, 0);

        let out_id_key = digest_to_bytes(&expected_out_id);
        let out_nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();
        let expected_output_coins_root = out_nip.insert(expected_out_id);

        let next_pubkey = dummy_pubkey(161);

        // ===== Slot arrays =====
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&in_coin, &in_nip, &dummy_c, &dummy_nip);
        let out_coins =
            out_slots_first_active(expected_out_id, out_coin_amount, &out_nip, &dummy_nip);
        let source_witness = InCoinSourceWitness {
            source_proof: &source_proof,
            source_inclusion: &source_inclusion,
            source_cmp: &source_cmp,
        };
        let sources = sources_first_active(&source_witness);

        let proof = prove_initial_with_in_and_out_coins_and_sources(
            &circuit,
            &account_state,
            history_root,
            &in_coins,
            &out_coins,
            &next_pubkey,
            &sources,
            asset_id,
            Some(mint),
        )
        .expect("prove init combined with source");
        verify(&circuit, &proof).expect("verify");

        let recovered = pis_as_proof_data(&proof);

        // FINAL account_state: balance = 80, pubkey = next_pubkey.
        let mut final_account_state = interim_account_state.clone();
        final_account_state.public_key = next_pubkey;
        assert_eq!(recovered.account_state_hash, final_account_state.hash());
        assert_eq!(recovered.output_coins_root, expected_output_coins_root);
        assert_eq!(recovered.commitment_history_root, history_root);
        assert_eq!(recovered.coin_history_root, expected_coin_history_root);
    }

    /// Stage 5d-next-5 Phase 2b end-to-end: AccountUpdate proof
    /// with BOTH in-coins + out-coins loops AND a real source proof
    /// backing the in-coin. Exercises the cyclic-recursion path
    /// (`condition = true`), the SPEC §8 (c)(d)(e) chain for the
    /// PREV-account commitment, the per-slot §8 step 2 chain for the
    /// SOURCE commitment, and the apply_coin + send_coins logic — all
    /// against a single shared `history_root` that holds BOTH
    /// commitments at distinct MMR leaves.
    #[test]
    fn stage_5d_next_5_phase_2b_account_update_combined_in_and_out_coin_with_source() {
        let circuit = build_circuit();

        let in_coin_amount: u64 = 30;
        // The consumer holds (and here is also the issuer of) the asset
        // the source mints. The source fixture mints with creator
        // dummy_pubkey(61), so the consumer's asset_id must be that
        // creator's asset and the consumer is owned by that same key.
        let creator_pubkey = dummy_pubkey(61);
        let asset_id = crate::types::calculate_asset_id(
            &creator_pubkey,
            &crate::types::calculate_name_hash("TEST"),
            8,
        );
        let mut account_state = AccountState::new(creator_pubkey, asset_id);
        account_state.balance = 100;
        let consumer_mint = MintWitness {
            creator_pubkey,
            name_hash: crate::types::calculate_name_hash("TEST"),
            decimals: 8,
        };

        let (
            source_proof,
            in_coin_id,
            source_inclusion,
            source_cmp,
            prev_proof,
            consumer_cmp,
            history_root_ext,
        ) = build_test_source_and_prev_witnesses(
            &circuit,
            61,
            &account_state,
            Some(consumer_mint),
            in_coin_amount,
        );

        // ===== Consumer's in-coin side =====
        let in_coin_key = digest_to_bytes(&in_coin_id);
        let empty_smt = SparseMerkleTree::new();
        let in_nip = empty_smt.generate_non_inclusion_proof(in_coin_key).unwrap();
        let in_coin = Coin {
            identifier: in_coin_id,
            recipient: account_state.owner,
            amount: in_coin_amount,
            asset_id,
        };
        let expected_coin_history_root = in_nip.insert(in_coin_id);

        // ===== Consumer's out-coin side =====
        let out_coin_amount: u64 = 50;
        let mut interim_account_state = account_state.clone();
        interim_account_state.balance = account_state.balance + in_coin.amount - out_coin_amount;
        let interim_asth = interim_account_state.hash();
        let expected_out_id = crate::types::calculate_coin_identifier(interim_asth, asset_id, 0);
        let out_id_key = digest_to_bytes(&expected_out_id);
        let out_nip = empty_smt.generate_non_inclusion_proof(out_id_key).unwrap();
        let expected_output_coins_root = out_nip.insert(expected_out_id);

        let next_pubkey = dummy_pubkey(162);

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&in_coin, &in_nip, &dummy_c, &dummy_nip);
        let out_coins =
            out_slots_first_active(expected_out_id, out_coin_amount, &out_nip, &dummy_nip);
        let source_witness = InCoinSourceWitness {
            source_proof: &source_proof,
            source_inclusion: &source_inclusion,
            source_cmp: &source_cmp,
        };
        let sources = sources_first_active(&source_witness);

        let update_proof = prove_account_update_with_in_and_out_coins_and_sources(
            &circuit,
            &account_state,
            history_root_ext,
            &prev_proof,
            &consumer_cmp,
            &in_coins,
            &out_coins,
            &next_pubkey,
            &sources,
            asset_id,
        )
        .expect("prove account_update combined with source");
        verify(&circuit, &update_proof).expect("verify update");

        let recovered = pis_as_proof_data(&update_proof);
        let mut final_account_state = interim_account_state.clone();
        final_account_state.public_key = next_pubkey;
        assert_eq!(recovered.account_state_hash, final_account_state.hash());
        assert_eq!(recovered.output_coins_root, expected_output_coins_root);
        assert_eq!(recovered.commitment_history_root, history_root_ext);
        assert_eq!(recovered.coin_history_root, expected_coin_history_root);
    }

    /// Stage 5e SPEC §13 — double-spend: two active in-coin slots
    /// presenting the SAME `coin_identifier`. The first slot inserts
    /// into the coin_history SMT successfully. The second slot's
    /// non-inclusion proof must be against the post-first-insert
    /// root, but the coin IS now in that root, so any non-inclusion
    /// proof against it is necessarily invalid — the in-circuit
    /// `connect_hashes(computed_old, running)` check catches the lie.
    #[test]
    fn stage_5e_double_spend_same_coin_twice_rejected() {
        let circuit = build_circuit();
        let (account_state, asset_id, mint) = mint_account(50, 100);

        // First in-coin: non-inclusion in empty SMT.
        let coin_id = hash_bytes(b"5e-double-spend");
        let coin_key = digest_to_bytes(&coin_id);
        let empty_smt = SparseMerkleTree::new();
        let nip1 = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();

        // Pretend-second in-coin: SAME identifier. The honest prover
        // can't generate a non-inclusion proof against the
        // post-first-insert root (the coin IS there now), so we
        // supply the SAME proof as `nip1`. That proof is valid for
        // the pre-insert (empty) root but invalid for the
        // post-insert running root — the in-circuit check fires on
        // slot 2 because `computed_old == empty_root` but
        // `running_coin_history` has advanced to the post-insert
        // root.
        let coin1 = Coin {
            identifier: coin_id,
            recipient: account_state.owner,
            amount: 1,
            asset_id,
        };
        let coin2 = Coin {
            identifier: coin_id,
            recipient: account_state.owner,
            amount: 1,
            asset_id,
        };
        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let mut in_coins: Vec<(bool, &Coin, &NonInclusionProof)> = Vec::with_capacity(MAX_IN_COINS);
        in_coins.push((true, &coin1, &nip1));
        in_coins.push((true, &coin2, &nip1));
        for _ in 2..MAX_IN_COINS {
            in_coins.push((false, &dummy_c, &dummy_nip));
        }

        assert!(prove_initial_with_in_coins(
            &circuit,
            &account_state,
            hash_bytes(b"history"),
            &in_coins,
            asset_id,
            Some(mint),
        )
        .is_err());
    }

    /// Stage 5c+ negative (d): AccountUpdate where the SMT inclusion path
    /// has been tampered with. (d) catches it via `connect_hashes`.
    #[test]
    fn stage_5c_plus_account_update_tampered_smt_path_rejected() {
        let circuit = build_circuit();

        let (account_state, asset_id, mint) = mint_account(77, 1);

        let true_asth = account_state.hash();
        let (mut cmp, history_root_extended) =
            build_test_commitment_witness(true_asth, DEFAULT_HASHES[0]);

        let init_proof = prove_initial(&circuit, &account_state, ZERO_HASH, asset_id, Some(mint))
            .expect("prove init");

        // Tamper a sibling deep in the SMT path — the computed
        // commitment_root will differ from the witnessed one.
        cmp.commitment_proof.siblings[0] = hash_bytes(b"lying-sibling");

        assert!(prove_account_update(
            &circuit,
            &account_state,
            history_root_extended,
            &init_proof,
            &cmp,
            asset_id,
        )
        .is_err());
    }

    // =========================================================================
    // Stage 5d-next-5 Phase 3 — SPEC §13 source-side negatives
    //
    // Each test exercises a specific attack vector against the per-slot
    // §8 step 2 chain wired by Phase 2b. Tests use real source proofs
    // (via [`build_test_source_witness`]) and isolate the failure to a
    // single tampered field, so the assertion identifies which
    // constraint catches the lie.
    // =========================================================================

    /// SPEC §13 negative: the source's commitment is NOT in the global
    /// history (tampered MMR-(e) path). Phase 2b's per-slot (e) check
    /// requires `mmr_inclusion(h(prev_smt_in_mmr_leaf ||
    /// source.commitment_history_root), …) == history_root`. Tampering
    /// the path breaks `connect_hashes` on the recomputed root.
    #[test]
    fn stage_5d_next_5_phase_3_source_not_in_history_rejected() {
        let circuit = build_circuit();

        let in_coin_amount: u64 = 7;
        let (
            source_proof,
            in_coin_id,
            source_inclusion,
            mut source_cmp,
            history_root,
            _post,
            asset_id,
        ) = build_test_source_witness(&circuit, 201, in_coin_amount);

        // Tamper the (e) MMR path — claim source's commitment_history
        // is somewhere it is not. The masked `mmr_b_computed ==
        // history_root` check rejects.
        source_cmp.previous_root_history_proof.1.path[0] =
            hash_bytes(b"phase-3-lying-source-mmr-e-sib");

        // Consumer holds the source's asset, balance 0 (non-mint).
        let mut account_state = non_mint_account(202, asset_id);
        account_state.balance = 0;

        let coin_key = digest_to_bytes(&in_coin_id);
        let empty_smt = SparseMerkleTree::new();
        let in_nip = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();
        let in_coin = Coin {
            identifier: in_coin_id,
            recipient: account_state.owner,
            amount: in_coin_amount,
            asset_id,
        };

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&in_coin, &in_nip, &dummy_c, &dummy_nip);
        let inactive_out_coins: Vec<(bool, HashDigest, u64, &NonInclusionProof)> = (0
            ..MAX_OUT_COINS)
            .map(|_| (false, ZERO_HASH, 0u64, &dummy_nip))
            .collect();
        let source_witness = InCoinSourceWitness {
            source_proof: &source_proof,
            source_inclusion: &source_inclusion,
            source_cmp: &source_cmp,
        };
        let sources = sources_first_active(&source_witness);

        assert!(prove_initial_with_in_and_out_coins_and_sources(
            &circuit,
            &account_state,
            history_root,
            &in_coins,
            &inactive_out_coins,
            &account_state.public_key,
            &sources,
            asset_id,
            None,
        )
        .is_err());
    }

    /// SPEC §13 negative: the in-coin's `coin_identifier` is NOT in the
    /// source's `output_coins_root` (tampered SMT inclusion path).
    /// Phase 2b's per-slot SMT inclusion check requires
    /// `hash_up_full_path(h(id || id), id_bits, source_inclusion_path)
    /// == source.output_coins_root`. Tampering rejects.
    #[test]
    fn stage_5d_next_5_phase_3_coin_not_in_source_ocr_rejected() {
        let circuit = build_circuit();

        let in_coin_amount: u64 = 9;
        let (
            source_proof,
            in_coin_id,
            mut source_inclusion,
            source_cmp,
            history_root,
            _post,
            asset_id,
        ) = build_test_source_witness(&circuit, 211, in_coin_amount);

        // Tamper the inclusion proof's first sibling — the recomputed
        // source-OCR no longer matches what the source actually published.
        source_inclusion.siblings[0] = hash_bytes(b"phase-3-lying-source-incl-sib");

        // Consumer holds the source's asset, balance 0 (non-mint).
        let mut account_state = non_mint_account(212, asset_id);
        account_state.balance = 0;

        let coin_key = digest_to_bytes(&in_coin_id);
        let empty_smt = SparseMerkleTree::new();
        let in_nip = empty_smt.generate_non_inclusion_proof(coin_key).unwrap();
        let in_coin = Coin {
            identifier: in_coin_id,
            recipient: account_state.owner,
            amount: in_coin_amount,
            asset_id,
        };

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        let in_coins = slots_first_active(&in_coin, &in_nip, &dummy_c, &dummy_nip);
        let inactive_out_coins: Vec<(bool, HashDigest, u64, &NonInclusionProof)> = (0
            ..MAX_OUT_COINS)
            .map(|_| (false, ZERO_HASH, 0u64, &dummy_nip))
            .collect();
        let source_witness = InCoinSourceWitness {
            source_proof: &source_proof,
            source_inclusion: &source_inclusion,
            source_cmp: &source_cmp,
        };
        let sources = sources_first_active(&source_witness);

        assert!(prove_initial_with_in_and_out_coins_and_sources(
            &circuit,
            &account_state,
            history_root,
            &in_coins,
            &inactive_out_coins,
            &account_state.public_key,
            &sources,
            asset_id,
            None,
        )
        .is_err());
    }

    /// SPEC §13 negative: the aggregator's witnessed
    /// `st_verifier_data` is a LIE (claims a different state-transition
    /// circuit than the outer's actual one). Phase 2a's
    /// `connect_hashes(claimed_st_digest, outer_vd.circuit_digest)`
    /// rejects.
    ///
    /// Construction: forge an aggregator proof with the
    /// dummy-circuit's `verifier_only` (any non-outer vd would work —
    /// the dummy is convenient and exists as a side product). All
    /// slots inactive so `conditionally_verify_proof` never actually
    /// uses the witnessed vd for verification; only the PIs reflect
    /// the lie. Then plug into the outer manually.
    #[test]
    fn stage_5d_next_5_phase_3_wrong_st_vk_on_aggregator_rejected() {
        let circuit = build_circuit();

        // Forge: aggregator proof claiming the dummy circuit's vd as
        // its st_verifier_data. Safe to build with all slots inactive.
        let lying_st_verifier_only = circuit.aggregator.dummy_st_verifier_only.clone();
        let all_inactive_slot_witnesses: Vec<AggregatorSlotWitness> = (0..MAX_IN_COINS)
            .map(|_| AggregatorSlotWitness {
                active: false,
                real_proof: None,
            })
            .collect();
        let lying_agg_proof = prove_aggregator(
            &circuit.aggregator,
            &lying_st_verifier_only,
            &all_inactive_slot_witnesses,
        )
        .expect("can build lying aggregator proof — all slots inactive so the witnessed vd is never actually used to verify");

        // Sanity: the lying aggregator proof verifies as an aggregator
        // proof (the aggregator circuit doesn't enforce that the
        // witnessed vd matches anything specific) — the lie surfaces
        // only at the outer's connect_hashes.
        circuit
            .aggregator
            .data
            .verify(lying_agg_proof.clone())
            .expect("lying aggregator proof is structurally valid");

        // Now construct the outer witness manually so we can plug in
        // the lying aggregator proof instead of an honest one. The
        // account holds the ZERO_HASH asset (balance 0, non-mint) so the
        // `account_asset_id == transition_asset_id (== ZERO_HASH)`
        // binding and the mint exception are both satisfied — the ONLY
        // failing constraint is the vk mismatch.
        let account_state = AccountState::new(dummy_pubkey(221), ZERO_HASH);
        let mut pw = PartialWitness::new();
        pw.set_bool_target(circuit.condition, false).unwrap();
        set_account_state_witness(&mut pw, &circuit, &account_state);
        set_mint_witness(&mut pw, &circuit, None);
        pw.set_hash_target(circuit.history_root, ZERO_HASH).unwrap();
        for i in 0..4 {
            pw.set_target(circuit.proof_data_pis[16 + i], ZERO_HASH.elements[i])
                .unwrap();
        }
        set_cmp_witness(&mut pw, &circuit, &dummy_cmp());

        let dummy_nip = dummy_non_inclusion_proof();
        let dummy_c = dummy_coin();
        for (slot_targets, ()) in circuit.in_coin_slots.iter().zip(std::iter::repeat(())) {
            set_in_coin_slot_witness(
                &mut pw,
                slot_targets,
                false,
                ZERO_HASH,
                ZERO_HASH,
                0,
                &dummy_nip,
            );
        }
        let all_none_sources: Vec<Option<InCoinSourceWitness>> =
            (0..MAX_IN_COINS).map(|_| None).collect();
        set_per_slot_source_witnesses(&mut pw, &circuit, &all_none_sources);
        for slot_targets in circuit.out_coin_slots.iter() {
            set_out_coin_slot_witness(&mut pw, slot_targets, false, ZERO_HASH, 0, &dummy_nip);
        }
        set_next_public_key_witness(&mut pw, &circuit, &account_state.public_key);

        // Plug the LYING aggregator proof in place of an honest one.
        pw.set_proof_with_pis_target::<C, D>(&circuit.aggregator_proof_target, &lying_agg_proof)
            .unwrap();

        let inner_pis = std::iter::empty::<(usize, F)>().collect();
        pw.set_proof_with_pis_target::<C, D>(
            &circuit.inner_proof_target,
            &cyclic_base_proof(&circuit.common_data, &circuit.data.verifier_only, inner_pis),
        )
        .unwrap();
        pw.set_verifier_data_target(&circuit.verifier_data_target, &circuit.data.verifier_only)
            .unwrap();

        // The outer's `connect_hashes(claimed_st_digest, outer_vd.digest)`
        // (and the parallel sigmas_cap binding) fires on the mismatch:
        // claimed_digest == dummy_circuit_digest != outer_circuit_digest.
        // Unused suppression: `dummy_c` lives only to satisfy older
        // helper bindings if needed downstream.
        let _ = dummy_c;
        assert!(circuit.data.prove(pw).is_err());
    }
}
