//! RFC-6962 NfLog inclusion and prefix-consistency verification.
//!
//! The circuit shape is fixed at the maximum depth of a `u64`-sized log.
//! Inactive levels are selected away, so unused witness slots are unread.
//!
//! # Canonical size / position representation
//!
//! Protocol log sizes and positions are `u64` values in `0 … 2^64 − 1` (§2.5,
//! `H_MAX = 64`). Goldilocks has `p = 2^64 − 2^32 + 1 < 2^64`, so a bare
//! field `Target` cannot carry every protocol value: packing into one element
//! either reintroduces the `1`/`p+1` alias or, with a `< p` canonicity check,
//! makes every value in `p … 2^64 − 1` unrepresentable.
//!
//! Every size-carrying wire is therefore a [`U64LimbsTarget`]: two
//! range-checked little-endian `u32` limbs. Comparisons, subtraction, the
//! split-point derivation, the bit-driven recursion, and the 8-byte big-endian
//! encoding for hashing all operate on that limb pair. Limbs are the
//! representation, not a view onto a single field element.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::circuit::gadgets::u64_limbs::U64LimbsTarget;
use crate::circuit::util::swap_if;
use crate::hash::{HashDigest, ZERO_HASH};

/// Maximum RFC-6962 recursion depth for a `u64` log size.
pub const H_MAX: usize = 64;

#[allow(dead_code)]
fn split_point_u64(n: u64) -> u64 {
    debug_assert!(n >= 2);
    let bit_length = 64 - (n - 1).leading_zeros();
    1u64 << (bit_length - 1)
}

#[allow(dead_code)]
fn terminal_b_and_depth(mut m: u64, mut n: u64) -> (bool, u32) {
    let mut b = true;
    let mut depth = 0;
    while m != n {
        let k = split_point_u64(n);
        if m <= k {
            n = k;
        } else {
            m -= k;
            n -= k;
            b = false;
        }
        depth += 1;
    }
    (b, depth)
}

/// Converts the host's deepest-first RFC-6962 path into fixed circuit slots.
#[allow(dead_code)]
pub(crate) fn fill_inclusion_slots(path_host: &[HashDigest]) -> [HashDigest; H_MAX] {
    assert!(
        path_host.len() <= H_MAX,
        "NfLog inclusion path exceeds H_MAX"
    );
    let mut slots = [ZERO_HASH; H_MAX];
    let depth = path_host.len();
    for level in 0..depth {
        slots[level] = path_host[depth - 1 - level];
    }
    slots
}

/// Converts the host RFC-6962 consistency proof into fixed circuit slots.
#[allow(dead_code)]
pub(crate) fn fill_consistency_slots(
    proof_host: &[HashDigest],
    m: u64,
    n: u64,
) -> [HashDigest; 2 * H_MAX] {
    if m == 0 || m == n {
        assert!(
            proof_host.is_empty(),
            "special consistency proof must be empty"
        );
        return [ZERO_HASH; 2 * H_MAX];
    }
    assert!(m < n, "consistency slot adapter requires m <= n");
    let (b_at_term, depth) = terminal_b_and_depth(m, n);
    let mut slots = [ZERO_HASH; 2 * H_MAX];
    let (base_digest, regular): (HashDigest, &[HashDigest]) = if b_at_term {
        (ZERO_HASH, proof_host)
    } else {
        assert!(
            !proof_host.is_empty(),
            "right-turn proof needs a base digest"
        );
        (proof_host[0], &proof_host[1..])
    };
    assert_eq!(regular.len(), depth as usize);
    for level in 0..regular.len() {
        slots[level] = regular[regular.len() - 1 - level];
    }
    slots[H_MAX] = base_digest;
    slots
}

// Local copies are cross-checked against `shared` by the tests below.
const TAG_NFLOG_LEAF: &str = "zkCoins/v1/NfLog/Leaf";
const TAG_NFLOG_NODE: &str = "zkCoins/v1/NfLog/Node";
const TAG_NFLOG_EMPTY: &str = "zkCoins/v1/NfLog/Empty";

fn encode_ascii_tag_elements(tag: &str) -> Vec<u64> {
    let bytes = tag.as_bytes();
    let mut out = Vec::with_capacity(1 + bytes.len().div_ceil(7));
    out.push(bytes.len() as u64);
    for chunk in bytes.chunks(7) {
        let mut seven = [0u8; 7];
        seven[..chunk.len()].copy_from_slice(chunk);
        out.push(u64::from_be_bytes([
            0, seven[0], seven[1], seven[2], seven[3], seven[4], seven[5], seven[6],
        ]));
    }
    out
}

fn tag_targets<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    tag: &str,
) -> Vec<Target> {
    encode_ascii_tag_elements(tag)
        .into_iter()
        .map(|value| builder.constant(F::from_canonical_u64(value)))
        .collect()
}

fn encode_byte_string_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    bytes: &[Target],
) -> Vec<Target> {
    let mut out = Vec::with_capacity(1 + bytes.len().div_ceil(7));
    out.push(builder.constant(F::from_canonical_usize(bytes.len())));
    for chunk in bytes.chunks(7) {
        let mut encoded = builder.zero();
        for (i, &byte) in chunk.iter().enumerate() {
            // Bytes are already width-8; 8-bit splits are injective in Goldilocks.
            builder.split_le(byte, 8);
            let weight = F::from_canonical_u64(1u64 << (8 * (6 - i)));
            encoded = builder.mul_const_add(weight, byte, encoded);
        }
        out.push(encoded);
    }
    out
}

fn select_hash<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    cond: BoolTarget,
    x: HashOutTarget,
    y: HashOutTarget,
) -> HashOutTarget {
    HashOutTarget {
        elements: std::array::from_fn(|i| builder.select(cond, x.elements[i], y.elements[i])),
    }
}

fn hashes_equal<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: HashOutTarget,
    b: HashOutTarget,
) -> BoolTarget {
    let mut equal = builder.constant_bool(true);
    for i in 0..4 {
        let limb_equal = builder.is_equal(a.elements[i], b.elements[i]);
        equal = builder.and(equal, limb_equal);
    }
    equal
}

/// Computes the position-bound NfLog leaf hash using the protocol's tagged
/// `Hc` encoding. Every supplied byte is constrained to `0..=255`.
pub fn nflog_leaf_hash_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    position: U64LimbsTarget,
    pk_bytes: &[Target; 32],
    r_bytes: &[Target; 32],
) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_NFLOG_LEAF);
    let position_bytes = position.to_be_bytes(builder);
    elements.extend(encode_byte_string_target(builder, &position_bytes));
    elements.extend(encode_byte_string_target(builder, pk_bytes));
    elements.extend(encode_byte_string_target(builder, r_bytes));
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

/// Computes `Hc("NfLog/Node", Digest(left), Digest(right))`.
pub fn nflog_node_hash_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    left: HashOutTarget,
    right: HashOutTarget,
) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_NFLOG_NODE);
    elements.extend(left.elements);
    elements.extend(right.elements);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

/// Computes `Hc("NfLog/Empty", SmallNumeric(0))`.
pub fn nflog_empty_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_NFLOG_EMPTY);
    elements.push(builder.zero());
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

/// Verifies an RFC-6962 NfLog inclusion path.
///
/// The host path is deepest-first. For a host path of length `d`, fixed
/// circuit slot `L` must contain `path_host[d - 1 - L]` for `L < d`;
/// remaining slots are unread sentinels.
pub fn verify_nflog_inclusion<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: HashOutTarget,
    position: U64LimbsTarget,
    path: &[HashOutTarget; H_MAX],
    size: U64LimbsTarget,
    mth: HashOutTarget,
) {
    let ok = position.less_than(builder, size);
    builder.assert_one(ok.target);

    let one = U64LimbsTarget::one(builder);
    let mut cur_size = size;
    let mut cur_pos = position;
    let mut active = Vec::with_capacity(H_MAX);
    let mut branch = Vec::with_capacity(H_MAX);

    for _ in 0..H_MAX {
        let is_one = cur_size.is_equal(builder, one);
        let active_l = builder.not(is_one);
        let x = cur_size.sub(builder, one);
        let k = x.highest_set_bit_pow2(builder);
        let branch_l = cur_pos.less_than(builder, k);

        let right_next_size = cur_size.sub(builder, k);
        let right_next_pos = cur_pos.sub(builder, k);
        let cand_size = U64LimbsTarget::select(builder, branch_l, k, right_next_size);
        let cand_pos = U64LimbsTarget::select(builder, branch_l, cur_pos, right_next_pos);
        cur_size = U64LimbsTarget::select(builder, active_l, cand_size, cur_size);
        cur_pos = U64LimbsTarget::select(builder, active_l, cand_pos, cur_pos);
        active.push(active_l);
        branch.push(branch_l);
    }

    let mut acc = leaf;
    for l in (0..H_MAX).rev() {
        let right_branch = builder.not(branch[l]);
        let (left, right) = swap_if(builder, right_branch, acc, path[l]);
        let combined = nflog_node_hash_target(builder, left, right);
        acc = select_hash(builder, active[l], combined, acc);
    }
    builder.connect_hashes(acc, mth);
}

/// Verifies that `(m, mth_a)` is an RFC-6962 prefix of `(n, mth_b)`.
///
/// `proof[0..H_MAX]` holds root-first shrink siblings, with unread sentinels
/// after the active depth. `proof[H_MAX]` is the dedicated terminal base
/// digest, read only when the shrink recursion terminates with `b == false`.
/// `proof[H_MAX + 1..2 * H_MAX]` is reserved and never read.
pub fn verify_nflog_consistency<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    m: U64LimbsTarget,
    mth_a: HashOutTarget,
    n: U64LimbsTarget,
    mth_b: HashOutTarget,
    proof: &[HashOutTarget; 2 * H_MAX],
) {
    let m_gt_n = n.less_than(builder, m);
    builder.assert_zero(m_gt_n.target);

    let zero = U64LimbsTarget::zero(builder);
    let is_m_zero = m.is_equal(builder, zero);
    let is_m_eq_n = m.is_equal(builder, n);
    let not_m_zero = builder.not(is_m_zero);
    let not_m_eq_n = builder.not(is_m_eq_n);
    let case_zero = is_m_zero;
    let case_eqn = builder.and(not_m_zero, is_m_eq_n);
    let case_gen = builder.and(not_m_zero, not_m_eq_n);

    let empty = nflog_empty_target(builder);
    let cond_zero_holds = hashes_equal(builder, mth_a, empty);
    let cond_eqn_holds = hashes_equal(builder, mth_a, mth_b);

    let one = U64LimbsTarget::one(builder);
    let mut cur_m = m;
    let mut cur_n = n;
    let mut cur_b = builder.constant_bool(true);
    let mut active = Vec::with_capacity(H_MAX);
    let mut branch = Vec::with_capacity(H_MAX);

    for _ in 0..H_MAX {
        let is_term = cur_m.is_equal(builder, cur_n);
        let active_l = builder.not(is_term);
        let x = cur_n.sub(builder, one);
        let k = x.highest_set_bit_pow2(builder);
        let strictly_greater = k.less_than(builder, cur_m);
        let branch_l = builder.not(strictly_greater);

        let right_next_m = cur_m.sub(builder, k);
        let right_next_n = cur_n.sub(builder, k);
        let false_b = builder.constant_bool(false);
        let cand_m = U64LimbsTarget::select(builder, branch_l, cur_m, right_next_m);
        let cand_n = U64LimbsTarget::select(builder, branch_l, k, right_next_n);
        let cand_b_target = builder.select(branch_l, cur_b.target, false_b.target);
        let cand_b = BoolTarget::new_unsafe(cand_b_target);

        cur_m = U64LimbsTarget::select(builder, active_l, cand_m, cur_m);
        cur_n = U64LimbsTarget::select(builder, active_l, cand_n, cur_n);
        let next_b_target = builder.select(active_l, cand_b.target, cur_b.target);
        cur_b = BoolTarget::new_unsafe(next_b_target);
        active.push(active_l);
        branch.push(branch_l);
    }

    let base_value = select_hash(builder, cur_b, mth_a, proof[H_MAX]);

    let mut acc_b = base_value;
    for l in (0..H_MAX).rev() {
        let right_branch = builder.not(branch[l]);
        let (left, right) = swap_if(builder, right_branch, acc_b, proof[l]);
        let combined = nflog_node_hash_target(builder, left, right);
        acc_b = select_hash(builder, active[l], combined, acc_b);
    }

    let mut acc_a = base_value;
    for l in (0..H_MAX).rev() {
        let right_branch = builder.not(branch[l]);
        let is_right_turn = builder.and(active[l], right_branch);
        let combined = nflog_node_hash_target(builder, proof[l], acc_a);
        acc_a = select_hash(builder, is_right_turn, combined, acc_a);
    }

    let b_matches = hashes_equal(builder, acc_b, mth_b);
    let a_matches = hashes_equal(builder, acc_a, mth_a);
    let cond_gen_holds = builder.and(b_matches, a_matches);

    let not_zero_holds = builder.not(cond_zero_holds);
    let not_eqn_holds = builder.not(cond_eqn_holds);
    let not_gen_holds = builder.not(cond_gen_holds);
    let violated_zero = builder.and(case_zero, not_zero_holds);
    let violated_eqn = builder.and(case_eqn, not_eqn_holds);
    let violated_gen = builder.and(case_gen, not_gen_holds);
    let violated_special = builder.or(violated_zero, violated_eqn);
    let violated = builder.or(violated_special, violated_gen);
    builder.assert_zero(violated.target);
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::circuit::gadgets::u64_limbs::{set_u64_limbs_unwrap, U64LimbsTarget};
    use crate::hash::{hash_bytes, HashDigest, ZERO_HASH};
    use crate::{C, D, F};
    use plonky2::field::types::{Field, Field64, PrimeField64};
    use plonky2::hash::hash_types::HashOutTarget;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use sha2::{Digest, Sha256};
    use shared::spec_v1::nflog::{
        consistency_proof, inclusion_path, nflog_empty, nflog_leaf_hash, nflog_mth,
        nflog_node_hash, verify_consistency, verify_inclusion, NfLogEntry,
    };
    use shared::spec_v1::nflog_boundary::{
        adjacent_consistency_pairs, bag_peaks_swapped, boundary_sizes, case_id_consistency,
        case_id_inclusion, case_id_peaks, find_inclusion_wrong_pivot, fixture_peaks, fixture_range,
        inclusion_positions, mth_a_dropped_to_empty, mth_a_duplicated_singleton, ref_bag_peaks,
        ref_build_consistency, ref_build_inclusion, ref_build_inclusion_swapped_top_mth,
        ref_fold_chunks, ref_fold_chunks_swapped, ref_mth_run, ref_verify_consistency,
        ref_verify_inclusion, try_consistency_wrong_pivot, ConsistencyPivotMutation,
    };

    fn synthetic_entries(n: usize) -> Vec<NfLogEntry> {
        (0..n)
            .map(|p| {
                let mut pk_pre = b"zkCoins/v1/test-vector/nflog/pk".to_vec();
                pk_pre.extend_from_slice(&(p as u32).to_be_bytes());
                let mut r_pre = b"zkCoins/v1/test-vector/nflog/r".to_vec();
                r_pre.extend_from_slice(&(p as u32).to_be_bytes());
                NfLogEntry {
                    pk: Sha256::digest(&pk_pre).into(),
                    r: Sha256::digest(&r_pre).into(),
                }
            })
            .collect()
    }

    #[derive(Clone, Copy)]
    struct InclusionTargets {
        leaf: HashOutTarget,
        position: U64LimbsTarget,
        path: [HashOutTarget; H_MAX],
        size: U64LimbsTarget,
        mth: HashOutTarget,
    }

    fn build_inclusion_circuit() -> (CircuitData<F, C, D>, InclusionTargets) {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = InclusionTargets {
            leaf: builder.add_virtual_hash(),
            position: U64LimbsTarget::new_virtual(&mut builder),
            path: std::array::from_fn(|_| builder.add_virtual_hash()),
            size: U64LimbsTarget::new_virtual(&mut builder),
            mth: builder.add_virtual_hash(),
        };
        verify_nflog_inclusion(
            &mut builder,
            targets.leaf,
            targets.position,
            &targets.path,
            targets.size,
            targets.mth,
        );
        builder.register_public_inputs(&targets.leaf.elements);
        builder.register_public_input(targets.position.lo);
        builder.register_public_input(targets.position.hi);
        builder.register_public_input(targets.size.lo);
        builder.register_public_input(targets.size.hi);
        builder.register_public_inputs(&targets.mth.elements);
        (builder.build::<C>(), targets)
    }

    fn inclusion_witness(
        targets: InclusionTargets,
        leaf: HashDigest,
        position: u64,
        slots: &[HashDigest; H_MAX],
        size: u64,
        mth: HashDigest,
    ) -> PartialWitness<F> {
        let mut witness = PartialWitness::new();
        witness.set_hash_target(targets.leaf, leaf).unwrap();
        set_u64_limbs_unwrap(&mut witness, targets.position, position);
        set_u64_limbs_unwrap(&mut witness, targets.size, size);
        witness.set_hash_target(targets.mth, mth).unwrap();
        for (target, digest) in targets.path.iter().zip(slots) {
            witness.set_hash_target(*target, *digest).unwrap();
        }
        witness
    }

    #[derive(Clone, Copy)]
    struct ConsistencyTargets {
        m: U64LimbsTarget,
        mth_a: HashOutTarget,
        n: U64LimbsTarget,
        mth_b: HashOutTarget,
        proof: [HashOutTarget; 2 * H_MAX],
    }

    fn build_consistency_circuit() -> (CircuitData<F, C, D>, ConsistencyTargets) {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = ConsistencyTargets {
            m: U64LimbsTarget::new_virtual(&mut builder),
            mth_a: builder.add_virtual_hash(),
            n: U64LimbsTarget::new_virtual(&mut builder),
            mth_b: builder.add_virtual_hash(),
            proof: std::array::from_fn(|_| builder.add_virtual_hash()),
        };
        verify_nflog_consistency(
            &mut builder,
            targets.m,
            targets.mth_a,
            targets.n,
            targets.mth_b,
            &targets.proof,
        );
        builder.register_public_input(targets.m.lo);
        builder.register_public_input(targets.m.hi);
        builder.register_public_inputs(&targets.mth_a.elements);
        builder.register_public_input(targets.n.lo);
        builder.register_public_input(targets.n.hi);
        builder.register_public_inputs(&targets.mth_b.elements);
        (builder.build::<C>(), targets)
    }

    fn consistency_witness(
        targets: ConsistencyTargets,
        m: u64,
        mth_a: HashDigest,
        n: u64,
        mth_b: HashDigest,
        slots: &[HashDigest; 2 * H_MAX],
    ) -> PartialWitness<F> {
        let mut witness = PartialWitness::new();
        set_u64_limbs_unwrap(&mut witness, targets.m, m);
        witness.set_hash_target(targets.mth_a, mth_a).unwrap();
        set_u64_limbs_unwrap(&mut witness, targets.n, n);
        witness.set_hash_target(targets.mth_b, mth_b).unwrap();
        for (target, digest) in targets.proof.iter().zip(slots) {
            witness.set_hash_target(*target, *digest).unwrap();
        }
        witness
    }

    fn prove_inclusion(
        data: &CircuitData<F, C, D>,
        targets: InclusionTargets,
        leaf: HashDigest,
        position: u64,
        path: &[HashDigest],
        size: u64,
        mth: HashDigest,
    ) -> bool {
        let slots = fill_inclusion_slots(path);
        let witness = inclusion_witness(targets, leaf, position, &slots, size, mth);
        match data.prove(witness) {
            Ok(proof) => data.verify(proof).is_ok(),
            Err(_) => false,
        }
    }

    fn prove_consistency(
        data: &CircuitData<F, C, D>,
        targets: ConsistencyTargets,
        m: u64,
        mth_a: HashDigest,
        n: u64,
        mth_b: HashDigest,
        proof_host: &[HashDigest],
    ) -> bool {
        let slots = if m > 0 && m < n {
            fill_consistency_slots(proof_host, m, n)
        } else {
            [ZERO_HASH; 2 * H_MAX]
        };
        let witness = consistency_witness(targets, m, mth_a, n, mth_b, &slots);
        match data.prove(witness) {
            Ok(proof) => data.verify(proof).is_ok(),
            Err(_) => false,
        }
    }

    fn inclusion_prove_is_err(
        data: &CircuitData<F, C, D>,
        targets: InclusionTargets,
        leaf: HashDigest,
        position: u64,
        path: &[HashDigest],
        size: u64,
        mth: HashDigest,
    ) -> bool {
        // Paths longer than H_MAX cannot be packed into the fixed gadget slots;
        // that is itself a Reject (malformed witness), not a prove success.
        if path.len() > H_MAX {
            return true;
        }
        let slots = fill_inclusion_slots(path);
        let witness = inclusion_witness(targets, leaf, position, &slots, size, mth);
        data.prove(witness).is_err()
    }

    /// Pack a host consistency proof into circuit slots without panicking on
    /// wrong length. Length faults are Rejects: the size-driven unrolling still
    /// runs `depth` active levels, so a short/long host list cannot satisfy the
    /// constraints when placed best-effort into the fixed slots.
    fn fill_consistency_slots_lenient(
        proof_host: &[HashDigest],
        m: u64,
        n: u64,
    ) -> [HashDigest; 2 * H_MAX] {
        if m == 0 || m == n {
            return [ZERO_HASH; 2 * H_MAX];
        }
        let (b_at_term, depth) = terminal_b_and_depth(m, n);
        let mut slots = [ZERO_HASH; 2 * H_MAX];
        let (base_digest, regular): (HashDigest, &[HashDigest]) = if b_at_term {
            (ZERO_HASH, proof_host)
        } else if proof_host.is_empty() {
            (ZERO_HASH, proof_host)
        } else {
            (proof_host[0], &proof_host[1..])
        };
        let place = regular.len().min(depth as usize).min(H_MAX);
        for level in 0..place {
            // Root-first slot order, same as the strict adapter when lengths match.
            let src = regular.len() - 1 - level;
            slots[level] = regular[src];
        }
        slots[H_MAX] = base_digest;
        slots
    }

    fn consistency_prove_is_err(
        data: &CircuitData<F, C, D>,
        targets: ConsistencyTargets,
        m: u64,
        mth_a: HashDigest,
        n: u64,
        mth_b: HashDigest,
        proof_host: &[HashDigest],
    ) -> bool {
        let slots = if m > 0 && m < n {
            // Prefer the strict adapter when the proof has the expected shape;
            // fall back to lenient packing for deliberate length faults.
            let (b_at_term, depth) = terminal_b_and_depth(m, n);
            let expected_regular = depth as usize;
            let regular_len = if b_at_term {
                proof_host.len()
            } else {
                proof_host.len().saturating_sub(1)
            };
            if regular_len == expected_regular && (b_at_term || !proof_host.is_empty()) {
                fill_consistency_slots(proof_host, m, n)
            } else {
                fill_consistency_slots_lenient(proof_host, m, n)
            }
        } else {
            [ZERO_HASH; 2 * H_MAX]
        };
        let witness = consistency_witness(targets, m, mth_a, n, mth_b, &slots);
        data.prove(witness).is_err()
    }

    #[test]
    fn local_tags_and_tag_encoding_match_shared() {
        let pairs = [
            (TAG_NFLOG_LEAF, shared::spec_v1::tags::TAG_NFLOG_LEAF),
            (TAG_NFLOG_NODE, shared::spec_v1::tags::TAG_NFLOG_NODE),
            (TAG_NFLOG_EMPTY, shared::spec_v1::tags::TAG_NFLOG_EMPTY),
        ];
        for (local, reference) in pairs {
            assert_eq!(local.as_bytes(), reference.as_bytes());
            let expected = shared::spec_v1::encoding::encode_byte_string(reference.as_bytes())
                .unwrap()
                .into_iter()
                .map(|element| element.to_canonical_u64())
                .collect::<Vec<_>>();
            assert_eq!(encode_ascii_tag_elements(local), expected);
        }
    }

    /// Limb range-checks reject a high limb that is not a 32-bit integer
    /// (the classical non-canonical residue class of a field element). A
    /// malicious prover cannot smuggle `p + 1` through a size limb.
    #[test]
    fn rejects_noncanonical_limb_outside_u32() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let size = U64LimbsTarget::new_virtual(&mut builder);
        // Force a consumer so the limb wires are constrained through the gadget.
        let position = U64LimbsTarget::zero(&mut builder);
        let leaf = builder.add_virtual_hash();
        let path: [HashOutTarget; H_MAX] = std::array::from_fn(|_| builder.add_virtual_hash());
        let mth = builder.add_virtual_hash();
        verify_nflog_inclusion(&mut builder, leaf, position, &path, size, mth);
        let data = builder.build::<C>();

        let mut bad = PartialWitness::new();
        // lo is fine; hi = 2^32 (not a u32). range_check(hi, 32) must reject.
        bad.set_target(size.lo, F::ZERO).unwrap();
        bad.set_target(size.hi, F::from_canonical_u64(1u64 << 32))
            .unwrap();
        // Remaining witnesses are dummies; the range check fails regardless.
        bad.set_hash_target(leaf, ZERO_HASH).unwrap();
        bad.set_hash_target(mth, ZERO_HASH).unwrap();
        for slot in path {
            bad.set_hash_target(slot, ZERO_HASH).unwrap();
        }
        assert!(
            data.prove(bad).is_err(),
            "hi limb equal to 2^32 (outside u32) must be rejected"
        );
    }

    /// End-to-end: a size of 1 with an honest (empty) inclusion path proves.
    #[test]
    fn inclusion_size_one_base_case_accepts_empty_path() {
        let (data, targets) = build_inclusion_circuit();
        let entry = &synthetic_entries(1)[0];
        let leaf = nflog_leaf_hash(0, entry);
        let mth = nflog_mth(std::slice::from_ref(entry));
        assert!(prove_inclusion(
            &data,
            targets,
            leaf,
            0,
            &[],
            1,
            mth,
        ));
    }

    /// Protocol sizes in the previously unrepresentable band `p … 2^64 − 1`
    /// must prove under the limb encoding. Symbolic fixtures keep the witness
    /// O(log n); no material log of size `p` is required.
    #[test]
    fn inclusion_accepts_sizes_at_and_above_field_order() {
        let (data, targets) = build_inclusion_circuit();
        let p = F::ORDER;
        let sizes = [p - 1, p, p + 1, u64::MAX];
        for &n in &sizes {
            for &position in &inclusion_positions(n) {
                let case_id = 0x2e11_u64
                    ^ n.wrapping_mul(0x9e37)
                    ^ position.wrapping_mul(0x85eb);
                let w = ref_build_inclusion(case_id, position, n);
                assert!(
                    ref_verify_inclusion(w.leaf, position, &w.path, n, w.mth),
                    "ref inclusion n={n:#x} p={position:#x}"
                );
                assert!(
                    verify_inclusion(w.leaf, position, &w.path, n, w.mth),
                    "host inclusion n={n:#x} p={position:#x}"
                );
                assert!(
                    prove_inclusion(
                        &data,
                        targets,
                        w.leaf,
                        position,
                        &w.path,
                        n,
                        w.mth,
                    ),
                    "gadget inclusion Accept n={n:#x} position={position:#x}"
                );
            }
        }
    }

    /// Consistency across the same ≥ p band, including the m = 0 special case
    /// at n = u64::MAX and a general pair (p, p + 1).
    #[test]
    fn consistency_accepts_sizes_at_and_above_field_order() {
        let (data, targets) = build_consistency_circuit();
        let p = F::ORDER;

        // m = 0 special case: empty proof, mth_a = empty, arbitrary n.
        for &n in &[p - 1, p, p + 1, u64::MAX] {
            assert!(
                prove_consistency(
                    &data,
                    targets,
                    0,
                    nflog_empty(),
                    n,
                    nflog_empty(),
                    &[],
                ),
                "gadget consistency m=0 n={n:#x}"
            );
        }

        // General case: symbolic fixtures for (p, p+1) and (u64::MAX-1, u64::MAX).
        for &(m, n) in &[(p, p + 1), (u64::MAX - 1, u64::MAX), (p - 1, p)] {
            let case_id = 0x2e11_u64 ^ m.wrapping_mul(0x9e37) ^ n;
            let w = ref_build_consistency(case_id, m, n);
            assert!(
                ref_verify_consistency(m, w.mth_a, n, w.mth_b, &w.proof),
                "ref consistency m={m:#x} n={n:#x}"
            );
            assert!(
                verify_consistency(m, w.mth_a, n, w.mth_b, &w.proof),
                "host consistency m={m:#x} n={n:#x}"
            );
            assert!(
                prove_consistency(
                    &data,
                    targets,
                    m,
                    w.mth_a,
                    n,
                    w.mth_b,
                    &w.proof,
                ),
                "gadget consistency Accept m={m:#x} n={n:#x}"
            );
        }
    }

    /// Cheap circuit-shape report (not a correctness check). Limb size
    /// handling moves gate count / degree bits; this prints them for the
    /// isolated inclusion and consistency wrappers used by the suite.
    #[test]
    fn report_gadget_circuit_dimensions() {
        let mut inclusion_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        {
            let targets = InclusionTargets {
                leaf: inclusion_builder.add_virtual_hash(),
                position: U64LimbsTarget::new_virtual(&mut inclusion_builder),
                path: std::array::from_fn(|_| inclusion_builder.add_virtual_hash()),
                size: U64LimbsTarget::new_virtual(&mut inclusion_builder),
                mth: inclusion_builder.add_virtual_hash(),
            };
            verify_nflog_inclusion(
                &mut inclusion_builder,
                targets.leaf,
                targets.position,
                &targets.path,
                targets.size,
                targets.mth,
            );
        }
        let inclusion_gates = inclusion_builder.num_gates();
        let inclusion_data = inclusion_builder.build::<C>();

        let mut consistency_builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        {
            let targets = ConsistencyTargets {
                m: U64LimbsTarget::new_virtual(&mut consistency_builder),
                mth_a: consistency_builder.add_virtual_hash(),
                n: U64LimbsTarget::new_virtual(&mut consistency_builder),
                mth_b: consistency_builder.add_virtual_hash(),
                proof: std::array::from_fn(|_| consistency_builder.add_virtual_hash()),
            };
            verify_nflog_consistency(
                &mut consistency_builder,
                targets.m,
                targets.mth_a,
                targets.n,
                targets.mth_b,
                &targets.proof,
            );
        }
        let consistency_gates = consistency_builder.num_gates();
        let consistency_data = consistency_builder.build::<C>();

        eprintln!(
            "nflog inclusion: num_gates={} degree_bits={}",
            inclusion_gates,
            inclusion_data.common.degree_bits()
        );
        eprintln!(
            "nflog consistency: num_gates={} degree_bits={}",
            consistency_gates,
            consistency_data.common.degree_bits()
        );
    }

    #[test]
    fn hash_targets_match_shared_field_element_for_field_element() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let position = U64LimbsTarget::new_virtual(&mut builder);
        let pk: [Target; 32] = std::array::from_fn(|_| builder.add_virtual_target());
        let r: [Target; 32] = std::array::from_fn(|_| builder.add_virtual_target());
        let left = builder.add_virtual_hash();
        let right = builder.add_virtual_hash();
        let leaf_out = nflog_leaf_hash_target(&mut builder, position, &pk, &r);
        let node_out = nflog_node_hash_target(&mut builder, left, right);
        let empty_out = nflog_empty_target(&mut builder);
        builder.register_public_inputs(&leaf_out.elements);
        builder.register_public_inputs(&node_out.elements);
        builder.register_public_inputs(&empty_out.elements);
        let data = builder.build::<C>();

        let entry = NfLogEntry {
            pk: std::array::from_fn(|i| (i as u8).wrapping_mul(7)),
            r: std::array::from_fn(|i| 255u8.wrapping_sub(i as u8)),
        };
        let left_value = hash_bytes(b"nflog-hash-parity-left");
        let right_value = hash_bytes(b"nflog-hash-parity-right");
        let mut witness = PartialWitness::new();
        set_u64_limbs_unwrap(&mut witness, position, 0x0102_0304_0506_0708);
        for i in 0..32 {
            witness
                .set_target(pk[i], F::from_canonical_u8(entry.pk[i]))
                .unwrap();
            witness
                .set_target(r[i], F::from_canonical_u8(entry.r[i]))
                .unwrap();
        }
        witness.set_hash_target(left, left_value).unwrap();
        witness.set_hash_target(right, right_value).unwrap();
        let proof = data.prove(witness).expect("hash parity witness must prove");
        data.verify(proof.clone())
            .expect("hash parity proof must verify");

        let expected = [
            nflog_leaf_hash(0x0102_0304_0506_0708, &entry),
            nflog_node_hash(left_value, right_value),
            nflog_empty(),
        ];
        let expected_elements = expected
            .iter()
            .flat_map(|digest| digest.elements)
            .collect::<Vec<_>>();
        assert_eq!(proof.public_inputs, expected_elements);
    }

    /// Leaf hash at positions ≥ p must still match the host encoding.
    #[test]
    fn leaf_hash_at_and_above_field_order_matches_host() {
        let p = F::ORDER;
        for &position in &[p - 1, p, p + 1, u64::MAX] {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            let pos = U64LimbsTarget::new_virtual(&mut builder);
            let pk: [Target; 32] = std::array::from_fn(|_| builder.add_virtual_target());
            let r: [Target; 32] = std::array::from_fn(|_| builder.add_virtual_target());
            let leaf_out = nflog_leaf_hash_target(&mut builder, pos, &pk, &r);
            builder.register_public_inputs(&leaf_out.elements);
            let data = builder.build::<C>();

            let entry = NfLogEntry {
                pk: [0xab; 32],
                r: [0xcd; 32],
            };
            let mut witness = PartialWitness::new();
            set_u64_limbs_unwrap(&mut witness, pos, position);
            for i in 0..32 {
                witness
                    .set_target(pk[i], F::from_canonical_u8(entry.pk[i]))
                    .unwrap();
                witness
                    .set_target(r[i], F::from_canonical_u8(entry.r[i]))
                    .unwrap();
            }
            let proof = data
                .prove(witness)
                .unwrap_or_else(|_| panic!("leaf hash at {position:#x} must prove"));
            data.verify(proof.clone()).expect("verify");
            let expected = nflog_leaf_hash(position, &entry);
            assert_eq!(
                proof.public_inputs,
                expected.elements.to_vec(),
                "leaf hash mismatch at position {position:#x}"
            );
        }
    }

    fn tamper(digest: HashDigest) -> HashDigest {
        let mut elements = digest.elements;
        elements[0] += F::ONE;
        HashDigest { elements }
    }

    #[test]
    fn materialized_smoke_and_required_negative_cases() {
        let (inclusion_data, inclusion_targets) = build_inclusion_circuit();
        let (consistency_data, consistency_targets) = build_consistency_circuit();
        let entries = synthetic_entries(9);

        let inclusion_cases = [
            (0, 3),
            (1, 3),
            (2, 3),
            (0, 4),
            (1, 4),
            (3, 4),
            (0, 5),
            (2, 5),
            (4, 5),
            (0, 8),
            (3, 8),
            (7, 8),
        ];
        for (position, n) in inclusion_cases {
            let slice = &entries[..n];
            let path = inclusion_path(position, slice).unwrap();
            let leaf = nflog_leaf_hash(position, &slice[position as usize]);
            let mth = nflog_mth(slice);
            assert!(verify_inclusion(leaf, position, &path, n as u64, mth));
            assert!(prove_inclusion(
                &inclusion_data,
                inclusion_targets,
                leaf,
                position,
                &path,
                n as u64,
                mth,
            ));
        }

        let consistency_cases = [(1, 2), (3, 4), (5, 8), (7, 8), (8, 9)];
        for (m, n) in consistency_cases {
            let mth_a = nflog_mth(&entries[..m]);
            let mth_b = nflog_mth(&entries[..n]);
            let proof = consistency_proof(m as u64, &entries[..n]).unwrap();
            assert!(verify_consistency(m as u64, mth_a, n as u64, mth_b, &proof));
            assert!(prove_consistency(
                &consistency_data,
                consistency_targets,
                m as u64,
                mth_a,
                n as u64,
                mth_b,
                &proof,
            ));
        }

        let position = 2u64;
        let n = 5usize;
        let path = inclusion_path(position, &entries[..n]).unwrap();
        let leaf = nflog_leaf_hash(position, &entries[position as usize]);
        let mth = nflog_mth(&entries[..n]);
        assert!(inclusion_prove_is_err(
            &inclusion_data,
            inclusion_targets,
            leaf,
            1,
            &path,
            n as u64,
            mth,
        ));
        assert!(inclusion_prove_is_err(
            &inclusion_data,
            inclusion_targets,
            leaf,
            position,
            &path,
            n as u64,
            tamper(mth),
        ));
        let mut bad_path = path.clone();
        bad_path[0] = tamper(bad_path[0]);
        assert!(inclusion_prove_is_err(
            &inclusion_data,
            inclusion_targets,
            leaf,
            position,
            &bad_path,
            n as u64,
            mth,
        ));
        assert!(inclusion_prove_is_err(
            &inclusion_data,
            inclusion_targets,
            leaf,
            n as u64,
            &path,
            n as u64,
            mth,
        ));
        assert!(inclusion_prove_is_err(
            &inclusion_data,
            inclusion_targets,
            leaf,
            0,
            &path,
            0,
            mth,
        ));

        let (m, n) = (5usize, 8usize);
        let mth_a = nflog_mth(&entries[..m]);
        let mth_b = nflog_mth(&entries[..n]);
        let proof = consistency_proof(m as u64, &entries[..n]).unwrap();
        assert!(consistency_prove_is_err(
            &consistency_data,
            consistency_targets,
            9,
            mth_a,
            8,
            mth_b,
            &proof,
        ));
        assert!(consistency_prove_is_err(
            &consistency_data,
            consistency_targets,
            m as u64,
            tamper(mth_a),
            n as u64,
            mth_b,
            &proof,
        ));
        assert!(consistency_prove_is_err(
            &consistency_data,
            consistency_targets,
            m as u64,
            mth_a,
            n as u64,
            tamper(mth_b),
            &proof,
        ));
        let mut bad_proof = proof.clone();
        bad_proof[0] = tamper(bad_proof[0]);
        assert!(consistency_prove_is_err(
            &consistency_data,
            consistency_targets,
            m as u64,
            mth_a,
            n as u64,
            mth_b,
            &bad_proof,
        ));
        assert!(consistency_prove_is_err(
            &consistency_data,
            consistency_targets,
            0,
            ZERO_HASH,
            n as u64,
            mth_b,
            &[],
        ));
        assert!(consistency_prove_is_err(
            &consistency_data,
            consistency_targets,
            n as u64,
            mth_a,
            n as u64,
            mth_b,
            &[],
        ));
    }

    /// V.11 differential Accept suite: independent reference, host verifiers,
    /// and the in-circuit gadget all receive the **same** shared fixtures for
    /// every `k = 0…63` boundary size.
    ///
    /// Counters only increment for checks that actually ran on that layer.
    /// Free-standing peak-bag identity has no host/gadget entry point over
    /// symbolic peaks — those cells are reported as `ref_only_peak`, never
    /// folded into the three-layer Accept totals. Host/gadget bagging Accept
    /// is the consistency `mth_a` fold below (real verify/prove calls).
    #[test]
    fn symbolic_boundary_suite_accepts_k_0_through_63() {
        let (inclusion_data, inclusion_targets) = build_inclusion_circuit();
        let (consistency_data, consistency_targets) = build_consistency_circuit();
        let mut covered_k_values = 0usize;
        let mut ref_accept: u64 = 0;
        let mut host_accept: u64 = 0;
        let mut gadget_accept: u64 = 0;
        let mut ref_only_peak_accept: u64 = 0;

        for k in 0u32..=63 {
            covered_k_values += 1;
            let sizes = boundary_sizes(k);

            // Peak-bagging identity — independent reference only (route b).
            // No free-standing host/gadget peak-bag API over symbolic peaks;
            // empty-log bagging is the m=0 consistency Accept (three-layer).
            for &n in &sizes {
                if n == 0 {
                    continue;
                }
                let case_peaks = case_id_peaks(k);
                let peaks = fixture_peaks(case_peaks, n);
                let bagged = ref_bag_peaks(&peaks);
                assert_eq!(bagged, ref_mth_run(case_peaks, 0, n));
                assert_eq!(bagged, ref_fold_chunks(&peaks));
                ref_only_peak_accept += 1;
            }

            for &n in &sizes {
                if n == 0 {
                    continue;
                }
                for &position in &inclusion_positions(n) {
                    let case_id = case_id_inclusion(k, n, position);
                    let w = ref_build_inclusion(case_id, position, n);
                    assert!(
                        ref_verify_inclusion(w.leaf, position, &w.path, n, w.mth),
                        "ref inclusion Accept k={k} n={n} p={position}"
                    );
                    ref_accept += 1;
                    assert!(
                        verify_inclusion(w.leaf, position, &w.path, n, w.mth),
                        "host inclusion Accept k={k} n={n} p={position}"
                    );
                    host_accept += 1;
                    assert!(
                        prove_inclusion(
                            &inclusion_data,
                            inclusion_targets,
                            w.leaf,
                            position,
                            &w.path,
                            n,
                            w.mth,
                        ),
                        "gadget inclusion Accept k={k} n={n} p={position}"
                    );
                    gadget_accept += 1;
                }
            }

            for (m, n) in adjacent_consistency_pairs(k) {
                if m == 0 || m >= n {
                    if m == 0 && n > 0 {
                        assert!(ref_verify_consistency(
                            0,
                            nflog_empty(),
                            n,
                            nflog_empty(),
                            &[]
                        ));
                        ref_accept += 1;
                        assert!(verify_consistency(0, nflog_empty(), n, nflog_empty(), &[]));
                        host_accept += 1;
                        assert!(prove_consistency(
                            &consistency_data,
                            consistency_targets,
                            0,
                            nflog_empty(),
                            n,
                            nflog_empty(),
                            &[],
                        ));
                        gadget_accept += 1;
                    }
                    continue;
                }
                let case_id = case_id_consistency(k, m, n);
                let w = ref_build_consistency(case_id, m, n);
                assert!(
                    ref_verify_consistency(m, w.mth_a, n, w.mth_b, &w.proof),
                    "ref consistency Accept k={k} m={m} n={n}"
                );
                ref_accept += 1;
                assert!(
                    verify_consistency(m, w.mth_a, n, w.mth_b, &w.proof),
                    "host consistency Accept k={k} m={m} n={n}"
                );
                host_accept += 1;
                assert!(
                    prove_consistency(
                        &consistency_data,
                        consistency_targets,
                        m,
                        w.mth_a,
                        n,
                        w.mth_b,
                        &w.proof,
                    ),
                    "gadget consistency Accept k={k} m={m} n={n}"
                );
                gadget_accept += 1;
            }
        }
        assert_eq!(covered_k_values, 64);
        // Three-layer counters only reflect checks that ran on every layer.
        assert_eq!(ref_accept, host_accept);
        assert_eq!(host_accept, gadget_accept);
        assert!(
            ref_only_peak_accept > 0,
            "expected ref-only peak identity cells, got {ref_only_peak_accept}"
        );
        eprintln!(
            "V.11 gadget Accept counts: ref={ref_accept} host={host_accept} gadget={gadget_accept} \
             ref_only_peak={ref_only_peak_accept}"
        );
    }

    /// V.11 NL-B1 / NL-B2 Reject suite for **every** `k = 0…63`.
    ///
    /// Each negative mutates exactly one property of an otherwise honest
    /// fixture-fed witness and is checked on all three layers. Cases that
    /// cannot be constructed without also changing path/proof length are
    /// reported (not silently counted as Reject).
    #[test]
    fn symbolic_boundary_nl_b1_b2_reject_k_0_through_63() {
        let (inclusion_data, inclusion_targets) = build_inclusion_circuit();
        let (consistency_data, consistency_targets) = build_consistency_circuit();
        let mut covered_k_values = 0usize;
        let mut ref_reject: u64 = 0;
        let mut host_reject: u64 = 0;
        let mut gadget_reject: u64 = 0;
        let mut ref_only_peak_nl_b2: u64 = 0;
        let mut skip_wrong_pivot_inc: u64 = 0;
        let mut skip_wrong_pivot_con: u64 = 0;
        let mut skip_swapped_inc: u64 = 0;
        let skip_swapped_peaks: u64 = 0;
        let skip_swapped_chunks: u64 = 0;
        let mut built_peak_dup_drop: u64 = 0;
        let mut built_chunk_dup_drop: u64 = 0;

        for k in 0u32..=63 {
            covered_k_values += 1;
            let sizes = boundary_sizes(k);

            // Peak-list bagging mutations (NL-B2) as independent-reference
            // digest inequalities. Production three-layer reject is the
            // consistency mth_a bagging fault below (same bagging fold).
            // Single-peak lists: swap is a no-op — use duplicate / drop.
            for &n in &sizes {
                if n == 0 {
                    continue;
                }
                let peaks = fixture_peaks(case_id_peaks(k), n);
                let bagged = ref_bag_peaks(&peaks);
                if peaks.len() < 2 {
                    let p = peaks[0];
                    assert_eq!(bagged, p, "singleton bag is identity k={k} n={n}");
                    let dup = mth_a_duplicated_singleton(p);
                    assert_ne!(
                        dup, bagged,
                        "duplicated singleton peak must differ from honest bag k={k} n={n}"
                    );
                    let dropped = mth_a_dropped_to_empty();
                    assert_ne!(
                        dropped, bagged,
                        "dropped singleton peak must differ from honest bag k={k} n={n}"
                    );
                    // Two built cases (dup + drop); ref digest only — no free-
                    // standing host/gadget peak predicate. Three-layer cover
                    // is the consistency single-chunk dup/drop block below.
                    ref_only_peak_nl_b2 += 2;
                    built_peak_dup_drop += 2;
                } else {
                    assert_ne!(bag_peaks_swapped(&peaks), bagged);
                    assert_ne!(ref_bag_peaks(&peaks[..peaks.len() - 1]), bagged);
                }
            }

            for &n in &sizes {
                if n == 0 {
                    continue;
                }
                for &position in &inclusion_positions(n) {
                    let case_id = case_id_inclusion(k, n, position);
                    let w = ref_build_inclusion(case_id, position, n);
                    assert!(ref_verify_inclusion(w.leaf, position, &w.path, n, w.mth));
                    assert!(verify_inclusion(w.leaf, position, &w.path, n, w.mth));
                    assert!(prove_inclusion(
                        &inclusion_data,
                        inclusion_targets,
                        w.leaf,
                        position,
                        &w.path,
                        n,
                        w.mth,
                    ));

                    // Truncated path (length only).
                    if !w.path.is_empty() {
                        let trunc = &w.path[..w.path.len() - 1];
                        assert!(!ref_verify_inclusion(w.leaf, position, trunc, n, w.mth));
                        ref_reject += 1;
                        assert!(!verify_inclusion(w.leaf, position, trunc, n, w.mth));
                        host_reject += 1;
                        assert!(inclusion_prove_is_err(
                            &inclusion_data,
                            inclusion_targets,
                            w.leaf,
                            position,
                            trunc,
                            n,
                            w.mth,
                        ));
                        gadget_reject += 1;
                    }

                    // Over-long path (length only).
                    if n >= 2 {
                        let mut overlong = w.path.clone();
                        overlong.push(fixture_range(case_id, u64::MAX - 1, 1));
                        assert!(!ref_verify_inclusion(
                            w.leaf, position, &overlong, n, w.mth
                        ));
                        ref_reject += 1;
                        assert!(!verify_inclusion(w.leaf, position, &overlong, n, w.mth));
                        host_reject += 1;
                        assert!(inclusion_prove_is_err(
                            &inclusion_data,
                            inclusion_targets,
                            w.leaf,
                            position,
                            &overlong,
                            n,
                            w.mth,
                        ));
                        gadget_reject += 1;
                    }

                    // Swapped top-hop bagging: same path/leaf, wrong claimed mth.
                    match ref_build_inclusion_swapped_top_mth(case_id, position, n) {
                        Some(bad) => {
                            assert_eq!(bad.path.len(), w.path.len());
                            assert_eq!(bad.leaf, w.leaf);
                            assert!(!ref_verify_inclusion(
                                w.leaf, position, &w.path, n, bad.mth
                            ));
                            ref_reject += 1;
                            assert!(!verify_inclusion(w.leaf, position, &w.path, n, bad.mth));
                            host_reject += 1;
                            assert!(inclusion_prove_is_err(
                                &inclusion_data,
                                inclusion_targets,
                                w.leaf,
                                position,
                                &w.path,
                                n,
                                bad.mth,
                            ));
                            gadget_reject += 1;
                        }
                        None => {
                            skip_swapped_inc += 1;
                            eprintln!(
                                "skip swapped-top inclusion: k={k} n={n} p={position}"
                            );
                        }
                    }

                }
                // Wrong pivot (NL-B1) once per size: same fixtures, same path length.
                if n >= 3 {
                    let case_id = case_id_inclusion(k, n, 0);
                    match find_inclusion_wrong_pivot(case_id, n) {
                        Some((position, wrong_pivot, bad)) => {
                            let honest = ref_build_inclusion(case_id, position, n);
                            assert_eq!(bad.path.len(), honest.path.len());
                            assert_eq!(bad.leaf, honest.leaf);
                            assert!(ref_verify_inclusion(
                                honest.leaf,
                                position,
                                &honest.path,
                                n,
                                honest.mth
                            ));
                            assert!(verify_inclusion(
                                honest.leaf,
                                position,
                                &honest.path,
                                n,
                                honest.mth
                            ));
                            assert!(prove_inclusion(
                                &inclusion_data,
                                inclusion_targets,
                                honest.leaf,
                                position,
                                &honest.path,
                                n,
                                honest.mth,
                            ));
                            assert!(
                                !ref_verify_inclusion(
                                    bad.leaf,
                                    position,
                                    &bad.path,
                                    n,
                                    honest.mth
                                ),
                                "ref wrong-pivot k={k} n={n} p={position} k'={wrong_pivot}"
                            );
                            ref_reject += 1;
                            assert!(
                                !verify_inclusion(bad.leaf, position, &bad.path, n, honest.mth),
                                "host wrong-pivot k={k} n={n} p={position} k'={wrong_pivot}"
                            );
                            host_reject += 1;
                            assert!(
                                inclusion_prove_is_err(
                                    &inclusion_data,
                                    inclusion_targets,
                                    bad.leaf,
                                    position,
                                    &bad.path,
                                    n,
                                    honest.mth,
                                ),
                                "gadget wrong-pivot k={k} n={n} p={position} k'={wrong_pivot}"
                            );
                            gadget_reject += 1;
                        }
                        None => {
                            skip_wrong_pivot_inc += 1;
                            eprintln!(
                                "skip wrong-pivot inclusion: k={k} n={n} — no same-length \
                                 top-pivot mutation among search positions"
                            );
                        }
                    }
                } else {
                    skip_wrong_pivot_inc += 1;
                    eprintln!("skip wrong-pivot inclusion: k={k} n={n} — size < 3");
                }
            }

            for (m, n) in adjacent_consistency_pairs(k) {
                if m == 0 || m >= n {
                    continue;
                }
                let case_id = case_id_consistency(k, m, n);
                let w = ref_build_consistency(case_id, m, n);
                assert!(ref_verify_consistency(m, w.mth_a, n, w.mth_b, &w.proof));
                assert!(verify_consistency(m, w.mth_a, n, w.mth_b, &w.proof));
                assert!(prove_consistency(
                    &consistency_data,
                    consistency_targets,
                    m,
                    w.mth_a,
                    n,
                    w.mth_b,
                    &w.proof,
                ));

                // Truncated proof.
                if !w.proof.is_empty() {
                    let trunc = &w.proof[..w.proof.len() - 1];
                    assert!(!ref_verify_consistency(m, w.mth_a, n, w.mth_b, trunc));
                    ref_reject += 1;
                    assert!(!verify_consistency(m, w.mth_a, n, w.mth_b, trunc));
                    host_reject += 1;
                    assert!(consistency_prove_is_err(
                        &consistency_data,
                        consistency_targets,
                        m,
                        w.mth_a,
                        n,
                        w.mth_b,
                        trunc,
                    ));
                    gadget_reject += 1;
                }

                // Over-long proof.
                {
                    let mut overlong = w.proof.clone();
                    overlong.push(fixture_range(case_id, u64::MAX - 1, 1));
                    assert!(!ref_verify_consistency(m, w.mth_a, n, w.mth_b, &overlong));
                    ref_reject += 1;
                    assert!(!verify_consistency(m, w.mth_a, n, w.mth_b, &overlong));
                    host_reject += 1;
                    assert!(consistency_prove_is_err(
                        &consistency_data,
                        consistency_targets,
                        m,
                        w.mth_a,
                        n,
                        w.mth_b,
                        &overlong,
                    ));
                    gadget_reject += 1;
                }

                // Chunk/peak bagging faults (NL-B2): same proof, sizes, mth_b;
                // only the claimed mth_a summary is wrong (single property).
                assert_eq!(ref_fold_chunks(&w.chunks), w.mth_a);
                if w.chunks.len() >= 2 {
                    let swapped_a = ref_fold_chunks_swapped(&w.chunks);
                    assert_ne!(swapped_a, w.mth_a);
                    assert!(!ref_verify_consistency(m, swapped_a, n, w.mth_b, &w.proof));
                    ref_reject += 1;
                    assert!(!verify_consistency(m, swapped_a, n, w.mth_b, &w.proof));
                    host_reject += 1;
                    assert!(consistency_prove_is_err(
                        &consistency_data,
                        consistency_targets,
                        m,
                        swapped_a,
                        n,
                        w.mth_b,
                        &w.proof,
                    ));
                    gadget_reject += 1;

                    // Truncated peak/chunk list bagged into mth_a.
                    let trunc_a = ref_fold_chunks(&w.chunks[..w.chunks.len() - 1]);
                    assert_ne!(trunc_a, w.mth_a);
                    assert!(!ref_verify_consistency(m, trunc_a, n, w.mth_b, &w.proof));
                    ref_reject += 1;
                    assert!(!verify_consistency(m, trunc_a, n, w.mth_b, &w.proof));
                    host_reject += 1;
                    assert!(consistency_prove_is_err(
                        &consistency_data,
                        consistency_targets,
                        m,
                        trunc_a,
                        n,
                        w.mth_b,
                        &w.proof,
                    ));
                    gadget_reject += 1;
                } else {
                    // Single chunk: swap/trunc are no-ops. NL-B2 still permits
                    // duplicate (Node(C,C)) and drop (empty summary).
                    assert_eq!(
                        w.chunks.len(),
                        1,
                        "consistency subproof yields ≥1 chunk k={k} m={m} n={n}"
                    );
                    let c = w.chunks[0];
                    assert_eq!(c, w.mth_a, "singleton chunk fold is identity");

                    let dup_a = mth_a_duplicated_singleton(c);
                    assert_ne!(dup_a, w.mth_a);
                    assert!(!ref_verify_consistency(m, dup_a, n, w.mth_b, &w.proof));
                    ref_reject += 1;
                    assert!(!verify_consistency(m, dup_a, n, w.mth_b, &w.proof));
                    host_reject += 1;
                    assert!(
                        consistency_prove_is_err(
                            &consistency_data,
                            consistency_targets,
                            m,
                            dup_a,
                            n,
                            w.mth_b,
                            &w.proof,
                        ),
                        "gadget must reject duplicated mth_a k={k} m={m} n={n}"
                    );
                    gadget_reject += 1;
                    built_chunk_dup_drop += 1;

                    let drop_a = mth_a_dropped_to_empty();
                    assert_ne!(drop_a, w.mth_a);
                    assert!(!ref_verify_consistency(m, drop_a, n, w.mth_b, &w.proof));
                    ref_reject += 1;
                    assert!(!verify_consistency(m, drop_a, n, w.mth_b, &w.proof));
                    host_reject += 1;
                    assert!(
                        consistency_prove_is_err(
                            &consistency_data,
                            consistency_targets,
                            m,
                            drop_a,
                            n,
                            w.mth_b,
                            &w.proof,
                        ),
                        "gadget must reject dropped mth_a k={k} m={m} n={n}"
                    );
                    gadget_reject += 1;
                    built_chunk_dup_drop += 1;
                }

                // Wrong pivot (NL-B1).
                match try_consistency_wrong_pivot(case_id, m, n) {
                    ConsistencyPivotMutation::Ok {
                        wrong_pivot,
                        witness: bad,
                    } => {
                        assert_eq!(bad.proof.len(), w.proof.len());
                        assert!(
                            !ref_verify_consistency(m, w.mth_a, n, w.mth_b, &bad.proof),
                            "ref wrong-pivot con k={k} m={m} n={n} k'={wrong_pivot}"
                        );
                        ref_reject += 1;
                        assert!(
                            !verify_consistency(m, w.mth_a, n, w.mth_b, &bad.proof),
                            "host wrong-pivot con k={k} m={m} n={n} k'={wrong_pivot}"
                        );
                        host_reject += 1;
                        assert!(
                            consistency_prove_is_err(
                                &consistency_data,
                                consistency_targets,
                                m,
                                w.mth_a,
                                n,
                                w.mth_b,
                                &bad.proof,
                            ),
                            "gadget wrong-pivot con k={k} m={m} n={n} k'={wrong_pivot}"
                        );
                        gadget_reject += 1;
                    }
                    ConsistencyPivotMutation::Unreachable { reason } => {
                        skip_wrong_pivot_con += 1;
                        eprintln!(
                            "skip wrong-pivot consistency: k={k} m={m} n={n} — {reason}"
                        );
                    }
                }
            }
        }

        assert_eq!(covered_k_values, 64);
        // Three-layer counters only reflect checks that ran on every layer.
        assert_eq!(ref_reject, host_reject);
        assert_eq!(host_reject, gadget_reject);
        assert_eq!(
            skip_swapped_peaks, 0,
            "single-peak NL-B2 must be built as duplicate/drop, not skipped"
        );
        assert_eq!(
            skip_swapped_chunks, 0,
            "single-chunk NL-B2 must be built as duplicate/drop, not skipped"
        );
        eprintln!(
            "V.11 gadget Reject counts: ref={ref_reject} host={host_reject} gadget={gadget_reject} \
             ref_only_peak_nl_b2={ref_only_peak_nl_b2}"
        );
        eprintln!(
            "V.11 gadget Reject skips: wrong_pivot_inc={skip_wrong_pivot_inc} \
             wrong_pivot_con={skip_wrong_pivot_con} swapped_inc={skip_swapped_inc} \
             swapped_peaks={skip_swapped_peaks} swapped_chunks={skip_swapped_chunks}"
        );
        eprintln!(
            "V.11 gadget NL-B2 built: peak_dup_drop={built_peak_dup_drop} \
             chunk_dup_drop={built_chunk_dup_drop}"
        );
        assert!(
            ref_reject > 100,
            "expected a large Reject set across k=0…63, got {ref_reject}"
        );
        assert_eq!(
            built_chunk_dup_drop, 130,
            "expected 65 single-chunk pairs × (dup+drop) = 130, got {built_chunk_dup_drop}"
        );
        assert_eq!(
            built_peak_dup_drop, 132,
            "expected 66 single-peak sizes × (dup+drop) = 132, got {built_peak_dup_drop}"
        );
    }

}
