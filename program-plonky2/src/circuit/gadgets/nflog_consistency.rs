//! RFC-6962 NfLog inclusion and prefix-consistency verification.
//!
//! The circuit shape is fixed at the maximum depth of a `u64`-sized log.
//! Inactive levels are selected away, so unused witness slots are unread.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::circuit::util::swap_if;

/// Maximum RFC-6962 recursion depth for a `u64` log size.
pub const H_MAX: usize = 64;

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
            builder.split_le(byte, 8);
            let weight = F::from_canonical_u64(1u64 << (8 * (6 - i)));
            encoded = builder.mul_const_add(weight, byte, encoded);
        }
        out.push(encoded);
    }
    out
}

fn u64_to_be_bytes_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    value: Target,
) -> [Target; 8] {
    let bits = builder.split_le(value, 64);
    std::array::from_fn(|i| {
        let hi = 63 - i * 8;
        let lo = hi - 7;
        builder.le_sum(bits[lo..=hi].iter())
    })
}

/// Computes the position-bound NfLog leaf hash using the protocol's tagged
/// `Hc` encoding. Every supplied byte is constrained to `0..=255`.
pub fn nflog_leaf_hash_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    position: Target,
    pk_bytes: &[Target; 32],
    r_bytes: &[Target; 32],
) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_NFLOG_LEAF);
    let position_bytes = u64_to_be_bytes_target(builder, position);
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

/// Highest set bit of `x`, represented as its power-of-two value.
fn highest_set_bit_pow2<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    x: Target,
) -> Target {
    let bits = builder.split_le(x, 64);
    let mut any_higher = builder.constant_bool(false);
    let mut result = builder.zero();
    for j in (0..64).rev() {
        let not_higher = builder.not(any_higher);
        let is_msb_j = builder.and(bits[j], not_higher);
        result = builder.mul_const_add(F::from_canonical_u64(1u64 << j), is_msb_j.target, result);
        any_higher = builder.or(any_higher, bits[j]);
    }
    result
}

/// Strict 64-bit comparison using an MSB-first Boolean scan.
fn less_than_64<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    a: Target,
    b: Target,
) -> BoolTarget {
    let a_bits = builder.split_le(a, 64);
    let b_bits = builder.split_le(b, 64);
    let mut equal_so_far = builder.constant_bool(true);
    let mut a_less = builder.constant_bool(false);
    for i in (0..64).rev() {
        let not_a = builder.not(a_bits[i]);
        let less_at_bit = builder.and(not_a, b_bits[i]);
        let first_diff_less = builder.and(equal_so_far, less_at_bit);
        a_less = builder.or(a_less, first_diff_less);
        let bits_equal = builder.is_equal(a_bits[i].target, b_bits[i].target);
        equal_so_far = builder.and(equal_so_far, bits_equal);
    }
    a_less
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

/// Verifies an RFC-6962 NfLog inclusion path.
///
/// The host path is deepest-first. For a host path of length `d`, fixed
/// circuit slot `L` must contain `path_host[d - 1 - L]` for `L < d`;
/// remaining slots are unread sentinels.
pub fn verify_nflog_inclusion<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    leaf: HashOutTarget,
    position: Target,
    path: &[HashOutTarget; H_MAX],
    size: Target,
    mth: HashOutTarget,
) {
    let ok = less_than_64(builder, position, size);
    builder.assert_one(ok.target);

    let one = builder.one();
    let mut cur_size = size;
    let mut cur_pos = position;
    let mut active = Vec::with_capacity(H_MAX);
    let mut branch = Vec::with_capacity(H_MAX);

    for _ in 0..H_MAX {
        let is_one = builder.is_equal(cur_size, one);
        let active_l = builder.not(is_one);
        let x = builder.sub(cur_size, one);
        let k = highest_set_bit_pow2(builder, x);
        let branch_l = less_than_64(builder, cur_pos, k);

        let right_next_size = builder.sub(cur_size, k);
        let right_next_pos = builder.sub(cur_pos, k);
        let cand_size = builder.select(branch_l, k, right_next_size);
        let cand_pos = builder.select(branch_l, cur_pos, right_next_pos);
        cur_size = builder.select(active_l, cand_size, cur_size);
        cur_pos = builder.select(active_l, cand_pos, cur_pos);
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
    m: Target,
    mth_a: HashOutTarget,
    n: Target,
    mth_b: HashOutTarget,
    proof: &[HashOutTarget; 2 * H_MAX],
) {
    let m_gt_n = less_than_64(builder, n, m);
    builder.assert_zero(m_gt_n.target);

    let zero = builder.zero();
    let is_m_zero = builder.is_equal(m, zero);
    let is_m_eq_n = builder.is_equal(m, n);
    let not_m_zero = builder.not(is_m_zero);
    let not_m_eq_n = builder.not(is_m_eq_n);
    let case_zero = is_m_zero;
    let case_eqn = builder.and(not_m_zero, is_m_eq_n);
    let case_gen = builder.and(not_m_zero, not_m_eq_n);

    let empty = nflog_empty_target(builder);
    let cond_zero_holds = hashes_equal(builder, mth_a, empty);
    let cond_eqn_holds = hashes_equal(builder, mth_a, mth_b);

    let one = builder.one();
    let mut cur_m = m;
    let mut cur_n = n;
    let mut cur_b = builder.constant_bool(true);
    let mut active = Vec::with_capacity(H_MAX);
    let mut branch = Vec::with_capacity(H_MAX);

    for _ in 0..H_MAX {
        let is_term = builder.is_equal(cur_m, cur_n);
        let active_l = builder.not(is_term);
        let x = builder.sub(cur_n, one);
        let k = highest_set_bit_pow2(builder, x);
        let strictly_greater = less_than_64(builder, k, cur_m);
        let branch_l = builder.not(strictly_greater);

        let right_next_m = builder.sub(cur_m, k);
        let right_next_n = builder.sub(cur_n, k);
        let false_b = builder.constant_bool(false);
        let cand_m = builder.select(branch_l, cur_m, right_next_m);
        let cand_n = builder.select(branch_l, k, right_next_n);
        let cand_b_target = builder.select(branch_l, cur_b.target, false_b.target);
        let cand_b = BoolTarget::new_unsafe(cand_b_target);

        cur_m = builder.select(active_l, cand_m, cur_m);
        cur_n = builder.select(active_l, cand_n, cur_n);
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
    use crate::hash::{hash_bytes, HashDigest, ZERO_HASH};
    use crate::{C, D, F};
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::hash::hash_types::HashOutTarget;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use sha2::{Digest, Sha256};
    use shared::spec_v1::nflog::{
        consistency_proof, inclusion_path, nflog_empty, nflog_leaf_hash, nflog_mth,
        nflog_node_hash, verify_consistency, verify_inclusion, NfLogEntry,
    };

    fn split_point_u64(n: u64) -> u64 {
        debug_assert!(n >= 2);
        let bit_length = 64 - (n - 1).leading_zeros();
        1u64 << (bit_length - 1)
    }

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

    fn fill_inclusion_slots(path_host: &[HashDigest]) -> [HashDigest; H_MAX] {
        let mut slots = [ZERO_HASH; H_MAX];
        let d = path_host.len();
        for l in 0..d {
            slots[l] = path_host[d - 1 - l];
        }
        slots
    }

    fn fill_consistency_slots(
        proof_host: &[HashDigest],
        m: u64,
        n: u64,
    ) -> [HashDigest; 2 * H_MAX] {
        let (b_at_term, depth) = terminal_b_and_depth(m, n);
        let mut slots = [ZERO_HASH; 2 * H_MAX];
        let (base_digest, regular): (HashDigest, &[HashDigest]) = if b_at_term {
            (ZERO_HASH, proof_host)
        } else {
            (proof_host[0], &proof_host[1..])
        };
        assert_eq!(regular.len(), depth as usize);
        for l in 0..regular.len() {
            slots[l] = regular[regular.len() - 1 - l];
        }
        slots[H_MAX] = base_digest;
        slots
    }

    fn symbolic_path(
        rel_pos: u64,
        n: u64,
        fresh: &mut impl FnMut() -> HashDigest,
    ) -> (Vec<HashDigest>, HashDigest, HashDigest) {
        if n == 1 {
            let leaf = fresh();
            return (vec![], leaf, leaf);
        }
        let k = split_point_u64(n);
        if rel_pos < k {
            let (mut path, leaf, left) = symbolic_path(rel_pos, k, fresh);
            let right = fresh();
            path.push(right);
            (path, leaf, nflog_node_hash(left, right))
        } else {
            let (mut path, leaf, right) = symbolic_path(rel_pos - k, n - k, fresh);
            let left = fresh();
            path.push(left);
            (path, leaf, nflog_node_hash(left, right))
        }
    }

    fn symbolic_subproof(
        m: u64,
        n: u64,
        b: bool,
        fresh: &mut impl FnMut() -> HashDigest,
    ) -> (Vec<HashDigest>, HashDigest, HashDigest) {
        if m == n {
            let value = fresh();
            return if b {
                (vec![], value, value)
            } else {
                (vec![value], value, value)
            };
        }
        let k = split_point_u64(n);
        if m <= k {
            let (mut proof, mth_a, left) = symbolic_subproof(m, k, b, fresh);
            let right = fresh();
            proof.push(right);
            (proof, mth_a, nflog_node_hash(left, right))
        } else {
            let (mut proof, mth_a_inner, right) = symbolic_subproof(m - k, n - k, false, fresh);
            let left = fresh();
            // This append is the ordering used by the normative
            // `subproof_range`; the verifier consumes siblings from the end.
            proof.push(left);
            let mth_a = nflog_node_hash(left, mth_a_inner);
            (proof, mth_a, nflog_node_hash(left, right))
        }
    }

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
        position: Target,
        path: [HashOutTarget; H_MAX],
        size: Target,
        mth: HashOutTarget,
    }

    fn build_inclusion_circuit() -> (CircuitData<F, C, D>, InclusionTargets) {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = InclusionTargets {
            leaf: builder.add_virtual_hash(),
            position: builder.add_virtual_target(),
            path: std::array::from_fn(|_| builder.add_virtual_hash()),
            size: builder.add_virtual_target(),
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
        builder.register_public_input(targets.position);
        builder.register_public_input(targets.size);
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
        witness
            .set_target(targets.position, F::from_canonical_u64(position))
            .unwrap();
        witness
            .set_target(targets.size, F::from_canonical_u64(size))
            .unwrap();
        witness.set_hash_target(targets.mth, mth).unwrap();
        for (target, digest) in targets.path.iter().zip(slots) {
            witness.set_hash_target(*target, *digest).unwrap();
        }
        witness
    }

    #[derive(Clone, Copy)]
    struct ConsistencyTargets {
        m: Target,
        mth_a: HashOutTarget,
        n: Target,
        mth_b: HashOutTarget,
        proof: [HashOutTarget; 2 * H_MAX],
    }

    fn build_consistency_circuit() -> (CircuitData<F, C, D>, ConsistencyTargets) {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let targets = ConsistencyTargets {
            m: builder.add_virtual_target(),
            mth_a: builder.add_virtual_hash(),
            n: builder.add_virtual_target(),
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
        builder.register_public_input(targets.m);
        builder.register_public_inputs(&targets.mth_a.elements);
        builder.register_public_input(targets.n);
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
        witness
            .set_target(targets.m, F::from_canonical_u64(m))
            .unwrap();
        witness.set_hash_target(targets.mth_a, mth_a).unwrap();
        witness
            .set_target(targets.n, F::from_canonical_u64(n))
            .unwrap();
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
        let slots = fill_inclusion_slots(path);
        let witness = inclusion_witness(targets, leaf, position, &slots, size, mth);
        data.prove(witness).is_err()
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
            fill_consistency_slots(proof_host, m, n)
        } else {
            [ZERO_HASH; 2 * H_MAX]
        };
        let witness = consistency_witness(targets, m, mth_a, n, mth_b, &slots);
        data.prove(witness).is_err()
    }

    fn fresh_factory() -> impl FnMut() -> HashDigest {
        let mut counter = 0u64;
        move || {
            let digest = hash_bytes(format!("nflog-symbolic-fixture-{counter}").as_bytes());
            counter += 1;
            digest
        }
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

    #[test]
    fn hash_targets_match_shared_field_element_for_field_element() {
        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let position = builder.add_virtual_target();
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
        witness
            .set_target(position, F::from_canonical_u64(0x0102_0304_0506_0708))
            .unwrap();
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

    #[test]
    fn symbolic_boundary_suite_accepts_k_0_through_63() {
        let (inclusion_data, inclusion_targets) = build_inclusion_circuit();
        let (consistency_data, consistency_targets) = build_consistency_circuit();
        let mut covered_k_values = 0usize;

        for k in 0u32..=63 {
            covered_k_values += 1;
            let pivot = 1u64 << k;
            let mut sizes = vec![pivot, pivot.saturating_sub(1)];
            if let Some(above) = pivot.checked_add(1) {
                sizes.push(above);
            }
            sizes.sort_unstable();
            sizes.dedup();
            sizes.retain(|&n| n != 0);

            for n in sizes {
                let mut positions = vec![0, n - 1];
                if n >= 2 {
                    positions.push(1u64 << (63 - (n - 1).leading_zeros()));
                }
                positions.sort_unstable();
                positions.dedup();
                for position in positions {
                    let mut fresh = fresh_factory();
                    let (path, leaf, mth) = symbolic_path(position, n, &mut fresh);
                    assert!(
                        verify_inclusion(leaf, position, &path, n, mth),
                        "host inclusion rejected k={k} n={n} p={position}"
                    );
                    assert!(
                        prove_inclusion(
                            &inclusion_data,
                            inclusion_targets,
                            leaf,
                            position,
                            &path,
                            n,
                            mth,
                        ),
                        "circuit inclusion rejected k={k} n={n} p={position}"
                    );
                }
            }

            let pairs = [
                (pivot.saturating_sub(1), pivot),
                (pivot, pivot.checked_add(1).unwrap_or(pivot)),
            ];
            for (m, n) in pairs {
                if m == 0 || m == n {
                    continue;
                }
                let mut fresh = fresh_factory();
                let (proof, mth_a, mth_b) = symbolic_subproof(m, n, true, &mut fresh);
                assert!(
                    verify_consistency(m, mth_a, n, mth_b, &proof),
                    "host consistency rejected k={k} m={m} n={n}"
                );
                assert!(
                    prove_consistency(
                        &consistency_data,
                        consistency_targets,
                        m,
                        mth_a,
                        n,
                        mth_b,
                        &proof,
                    ),
                    "circuit consistency rejected k={k} m={m} n={n}"
                );
            }
        }
        assert_eq!(covered_k_values, 64);
    }

    #[test]
    fn symbolic_boundary_nl_b1_b2_reject_k_0_1_2_3_32_62_63() {
        let (inclusion_data, inclusion_targets) = build_inclusion_circuit();
        let (consistency_data, consistency_targets) = build_consistency_circuit();
        let mut covered_k_values = 0usize;

        for k in [0u32, 1, 2, 3, 32, 62, 63] {
            covered_k_values += 1;
            let pivot = 1u64 << k;
            let n = pivot.checked_add(1).unwrap_or(pivot);
            if n == pivot {
                // At k=63, 2^63+1 is representable and checked_add succeeds.
                unreachable!();
            }

            // NL-B1: cross-feed a path generated for the adjacent tree size.
            // The claimed `(n, root)` still uses the genuine `n` fixture, so
            // the sibling sequence embodies a different root split.
            let mut genuine_fresh = fresh_factory();
            let (genuine_path, leaf, mth) = symbolic_path(0, n, &mut genuine_fresh);
            let other_n = pivot.max(1);
            let mut wrong_fresh = fresh_factory();
            let (wrong_path, _, _) = symbolic_path(0, other_n, &mut wrong_fresh);
            assert!(verify_inclusion(leaf, 0, &genuine_path, n, mth));
            assert!(!verify_inclusion(leaf, 0, &wrong_path, n, mth));
            assert!(inclusion_prove_is_err(
                &inclusion_data,
                inclusion_targets,
                leaf,
                0,
                &wrong_path,
                n,
                mth,
            ));

            // NL-B2: corrupt one genuine sibling/peak digest.
            let mut corrupt_path = genuine_path.clone();
            corrupt_path[0] = tamper(corrupt_path[0]);
            assert!(!verify_inclusion(leaf, 0, &corrupt_path, n, mth));
            assert!(inclusion_prove_is_err(
                &inclusion_data,
                inclusion_targets,
                leaf,
                0,
                &corrupt_path,
                n,
                mth,
            ));

            let m = pivot;
            let mut fresh = fresh_factory();
            let (proof, mth_a, mth_b) = symbolic_subproof(m, n, true, &mut fresh);
            assert!(verify_consistency(m, mth_a, n, mth_b, &proof));
            let mut corrupt_proof = proof.clone();
            corrupt_proof[0] = tamper(corrupt_proof[0]);
            assert!(!verify_consistency(m, mth_a, n, mth_b, &corrupt_proof));
            assert!(consistency_prove_is_err(
                &consistency_data,
                consistency_targets,
                m,
                mth_a,
                n,
                mth_b,
                &corrupt_proof,
            ));
        }
        assert_eq!(covered_k_values, 7);
    }
}
