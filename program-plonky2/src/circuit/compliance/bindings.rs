//! Clause-2/4 derivations shared by the full circuit and parity tests.

use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::circuit::gadgets::sha256::sha256;
use crate::circuit::gadgets::u128_arith::U128Target;
use crate::{D, F};

use super::serialize::{
    digest_to_be_bytes_target, encode_byte_string_target, tag_targets, u128_to_be_bytes_target,
    u64_to_be_bytes_target,
};
use super::targets::{InputAuthTarget, InputCoinTarget, NavTarget, ProofDataTarget};
use super::{
    TAG_COIN, TAG_NAV_COMMIT, TAG_NFLOG_ROOT, TAG_NK_COMMIT, TAG_NULLIFIER,
    TAG_NULLIFIERS_ROOT_LEAF, TAG_NULLIFIERS_ROOT_NODE,
};

fn select_hash(
    builder: &mut CircuitBuilder<F, D>,
    condition: BoolTarget,
    when_true: HashOutTarget,
    when_false: HashOutTarget,
) -> HashOutTarget {
    HashOutTarget {
        elements: std::array::from_fn(|i| {
            builder.select(condition, when_true.elements[i], when_false.elements[i])
        }),
    }
}

fn select_exact_hash(
    builder: &mut CircuitBuilder<F, D>,
    count: Target,
    candidates: &[HashOutTarget],
) -> HashOutTarget {
    let mut selected = candidates[0];
    let mut selectors = Vec::with_capacity(candidates.len());
    for (index, &candidate) in candidates.iter().enumerate() {
        let index_target = builder.constant(F::from_canonical_usize(index));
        let is_index = builder.is_equal(count, index_target);
        selected = select_hash(builder, is_index, candidate, selected);
        selectors.push(is_index.target);
    }
    let selector_sum = builder.add_many(selectors);
    builder.assert_one(selector_sum);
    selected
}

fn hashes_equal(
    builder: &mut CircuitBuilder<F, D>,
    lhs: HashOutTarget,
    rhs: HashOutTarget,
) -> BoolTarget {
    let mut equal = builder.constant_bool(true);
    for (&lhs_element, &rhs_element) in lhs.elements.iter().zip(&rhs.elements) {
        let element_equal = builder.is_equal(lhs_element, rhs_element);
        equal = builder.and(equal, element_equal);
    }
    equal
}

fn bytes_equal(
    builder: &mut CircuitBuilder<F, D>,
    lhs: &[Target; 32],
    rhs: &[Target; 32],
) -> BoolTarget {
    let mut equal = builder.constant_bool(true);
    for (&lhs_byte, &rhs_byte) in lhs.iter().zip(rhs) {
        let byte_equal = builder.is_equal(lhs_byte, rhs_byte);
        equal = builder.and(equal, byte_equal);
    }
    equal
}

pub(crate) fn coin_identifier_with_index_target(
    builder: &mut CircuitBuilder<F, D>,
    prev_account_state_hash: HashOutTarget,
    recipient: &[Target; 32],
    asset_id: HashOutTarget,
    amount: U128Target,
    coin_index: Target,
) -> HashOutTarget {
    let amount_bytes = u128_to_be_bytes_target(builder, amount);
    let mut elements = tag_targets(builder, TAG_COIN);
    elements.extend(prev_account_state_hash.elements);
    elements.extend(encode_byte_string_target(builder, recipient));
    elements.extend(asset_id.elements);
    elements.extend(encode_byte_string_target(builder, &amount_bytes));
    elements.push(coin_index);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

pub(crate) fn nk_commit_target(
    builder: &mut CircuitBuilder<F, D>,
    nk: &[Target; 32],
) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_NK_COMMIT);
    elements.extend(encode_byte_string_target(builder, nk));
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

pub(crate) fn nav_root_target(builder: &mut CircuitBuilder<F, D>, nav: NavTarget) -> HashOutTarget {
    let size_bytes = u64_to_be_bytes_target(builder, nav.size);
    let mut elements = tag_targets(builder, TAG_NFLOG_ROOT);
    elements.extend(encode_byte_string_target(builder, &size_bytes));
    elements.extend(nav.mth.elements);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

pub(crate) fn nav_commitment_target(
    builder: &mut CircuitBuilder<F, D>,
    nav: NavTarget,
    nav_rand: &[Target; 32],
) -> HashOutTarget {
    let nav_root = nav_root_target(builder, nav);
    let mut elements = tag_targets(builder, TAG_NAV_COMMIT);
    elements.extend(nav_root.elements);
    elements.extend(encode_byte_string_target(builder, nav_rand));
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

pub(crate) fn nullifier_target(
    builder: &mut CircuitBuilder<F, D>,
    nk: &[Target; 32],
    coin_identifier: HashOutTarget,
) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_NULLIFIER);
    elements.extend(encode_byte_string_target(builder, nk));
    elements.extend(coin_identifier.elements);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

fn nullifiers_leaf_hash(builder: &mut CircuitBuilder<F, D>, value: HashOutTarget) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_NULLIFIERS_ROOT_LEAF);
    elements.extend(value.elements);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

fn nullifiers_node_hash(
    builder: &mut CircuitBuilder<F, D>,
    left: HashOutTarget,
    right: HashOutTarget,
) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_NULLIFIERS_ROOT_NODE);
    elements.extend(left.elements);
    elements.extend(right.elements);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

pub(crate) fn input_nullifiers_root_target<const N: usize>(
    builder: &mut CircuitBuilder<F, D>,
    nk: &[Target; 32],
    active: &[BoolTarget; N],
    coin_identifiers: &[HashOutTarget; N],
) -> (HashOutTarget, [HashOutTarget; N], Target) {
    for index in 0..N - 1 {
        let not_current = builder.not(active[index]);
        let gap = builder.and(not_current, active[index + 1]);
        builder.assert_zero(gap.target);
    }
    let count = builder.add_many(active.map(|slot| slot.target));
    let nullifiers = coin_identifiers.map(|identifier| nullifier_target(builder, nk, identifier));

    for left in 0..N {
        for right in left + 1..N {
            let both_active = builder.and(active[left], active[right]);
            let equal = hashes_equal(builder, nullifiers[left], nullifiers[right]);
            let duplicate = builder.and(both_active, equal);
            builder.assert_zero(duplicate.target);
        }
    }

    let zero_digest = HashOutTarget {
        elements: [builder.zero(); 4],
    };
    let empty_leaf = nullifiers_leaf_hash(builder, zero_digest);
    let leaves = nullifiers.map(|nullifier| nullifiers_leaf_hash(builder, nullifier));
    let mut candidates = Vec::with_capacity(N + 1);
    candidates.push(empty_leaf);
    for active_count in 1..=N {
        let width = active_count.next_power_of_two();
        let mut level = Vec::with_capacity(width);
        level.extend_from_slice(&leaves[..active_count]);
        level.resize(width, empty_leaf);
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks_exact(2) {
                next.push(nullifiers_node_hash(builder, pair[0], pair[1]));
            }
            level = next;
        }
        candidates.push(level[0]);
    }
    (
        select_exact_hash(builder, count, &candidates),
        nullifiers,
        count,
    )
}

pub(crate) fn enforce_input_coin_bindings<const N: usize>(
    builder: &mut CircuitBuilder<F, D>,
    owner: &[Target; 32],
    input_coins: &[InputCoinTarget; N],
    input_auth: &[InputAuthTarget; N],
) {
    for index in 0..N {
        let coin = input_coins[index];
        let recomputed = coin_identifier_with_index_target(
            builder,
            input_auth[index].creating_prev_ash,
            &coin.recipient,
            coin.asset_id,
            coin.amount,
            input_auth[index].coin_index,
        );
        let identifier_equal = hashes_equal(builder, recomputed, coin.identifier);
        let identifier_not_equal = builder.not(identifier_equal);
        let bad_identifier = builder.and(coin.active, identifier_not_equal);
        builder.assert_zero(bad_identifier.target);

        let owner_equal = bytes_equal(builder, &coin.recipient, owner);
        let owner_not_equal = builder.not(owner_equal);
        let bad_owner = builder.and(coin.active, owner_not_equal);
        builder.assert_zero(bad_owner.target);
    }
}

pub(crate) fn hash_proof_data_target(
    builder: &mut CircuitBuilder<F, D>,
    proof_data: &ProofDataTarget,
) -> [Target; 32] {
    let mut serialized = Vec::with_capacity(192);
    for digest in [
        proof_data.new_account_state_hash,
        proof_data.output_coins_root,
        proof_data.input_nullifiers_root,
        proof_data.coin_history_root,
        proof_data.nav_commitment,
    ] {
        serialized.extend_from_slice(&digest_to_be_bytes_target(builder, digest));
    }
    serialized.extend_from_slice(&proof_data.npk_commit);
    assert_eq!(
        serialized.len(),
        192,
        "ProofData serialization must contain exactly six 32-byte fields"
    );
    sha256(builder, &serialized)
}
