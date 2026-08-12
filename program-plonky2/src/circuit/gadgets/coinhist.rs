//! Fixed-depth sparse-Merkle update gadget for the per-account coin history.

use plonky2::field::extension::Extendable;
use plonky2::hash::hash_types::{HashOutTarget, RichField};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;

use crate::circuit::util::swap_if;

pub const COINHIST_DEPTH: usize = 256;

// Local copies keep this reusable gadget independent from compliance/shared.
const TAG_COINHIST_LEAF: &str = "zkCoins/v1/CoinHist/Leaf";
const TAG_COINHIST_NODE: &str = "zkCoins/v1/CoinHist/Node";

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

/// Computes `Hc("CoinHist/Leaf", SmallNumeric(state))`.
pub fn coinhist_leaf_hash_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    state: Target,
) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_COINHIST_LEAF);
    elements.push(state);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

/// Computes `Hc("CoinHist/Node", SmallNumeric(level), Digest(left), Digest(right))`.
pub fn coinhist_node_hash_target<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    level: u32,
    left: HashOutTarget,
    right: HashOutTarget,
) -> HashOutTarget {
    assert!(level <= COINHIST_DEPTH as u32);
    let mut elements = tag_targets(builder, TAG_COINHIST_NODE);
    elements.push(builder.constant(F::from_canonical_u32(level)));
    elements.extend(left.elements);
    elements.extend(right.elements);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

/// Recomputes old/new roots over the same bottom-to-top 256-sibling path.
pub fn coinhist_update_roots<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    key_be_bytes: &[Target; 32],
    old_state: u8,
    new_state: u8,
    siblings: &[HashOutTarget; COINHIST_DEPTH],
) -> (HashOutTarget, HashOutTarget) {
    let byte_bits = key_be_bytes.map(|byte| builder.split_le(byte, 8));
    let old_state = builder.constant(F::from_canonical_u8(old_state));
    let new_state = builder.constant(F::from_canonical_u8(new_state));
    let mut old_cur = coinhist_leaf_hash_target(builder, old_state);
    let mut new_cur = coinhist_leaf_hash_target(builder, new_state);

    for level in 1..=COINHIST_DEPTH {
        let bit_index = level - 1;
        let key_byte = (255 - bit_index) / 8;
        let bit_in_byte = bit_index % 8;
        let bit = byte_bits[key_byte][bit_in_byte];
        let (old_left, old_right) = swap_if(builder, bit, old_cur, siblings[level - 1]);
        let (new_left, new_right) = swap_if(builder, bit, new_cur, siblings[level - 1]);
        old_cur = coinhist_node_hash_target(builder, level as u32, old_left, old_right);
        new_cur = coinhist_node_hash_target(builder, level as u32, new_left, new_right);
    }
    (old_cur, new_cur)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{C, D, F};
    use plonky2::field::types::{Field, PrimeField64};
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_data::CircuitConfig;
    use shared::spec_v1::{self as host, CoinHistState, CoinHistTree, HashDigest};

    fn set_key(w: &mut PartialWitness<F>, targets: &[Target; 32], key: &[u8; 32]) {
        for (&target, &byte) in targets.iter().zip(key) {
            w.set_target(target, F::from_canonical_u8(byte)).unwrap();
        }
    }

    fn set_path(
        w: &mut PartialWitness<F>,
        targets: &[HashOutTarget; COINHIST_DEPTH],
        siblings: &[HashDigest],
    ) {
        assert_eq!(siblings.len(), COINHIST_DEPTH);
        for (&target, &sibling) in targets.iter().zip(siblings) {
            w.set_hash_target(target, sibling).unwrap();
        }
    }

    #[test]
    fn compliance_coinhist_local_tags_and_small_numeric_encoding_match_shared() {
        for (local, shared) in [
            (TAG_COINHIST_LEAF, host::TAG_COINHIST_LEAF),
            (TAG_COINHIST_NODE, host::TAG_COINHIST_NODE),
        ] {
            assert_eq!(local, shared);
            let local = encode_ascii_tag_elements(local);
            let shared = host::encode_byte_string(shared.as_bytes())
                .unwrap()
                .into_iter()
                .map(|x| x.to_canonical_u64())
                .collect::<Vec<_>>();
            assert_eq!(local, shared);
        }
        assert_eq!(
            host::encode_small_numeric(256).unwrap().to_canonical_u64(),
            256
        );
    }

    #[test]
    fn compliance_coinhist_leaf_and_node_hash_targets_match_shared() {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let state = builder.add_virtual_target();
        let left = builder.add_virtual_hash();
        let right = builder.add_virtual_hash();
        let leaf = coinhist_leaf_hash_target(&mut builder, state);
        let node = coinhist_node_hash_target(&mut builder, 173, left, right);
        builder.register_public_inputs(&leaf.elements);
        builder.register_public_inputs(&node.elements);
        let data = builder.build::<C>();

        let left_value = host::coinhist_leaf_hash(CoinHistState::Admitted);
        let right_value = host::coinhist_leaf_hash(CoinHistState::Spent);
        let expected_leaf = host::coinhist_leaf_hash(CoinHistState::Spent);
        let expected_node = host::coinhist_node_hash(173, left_value, right_value).unwrap();
        let mut witness = PartialWitness::new();
        witness.set_target(state, F::from_canonical_u8(2)).unwrap();
        witness.set_hash_target(left, left_value).unwrap();
        witness.set_hash_target(right, right_value).unwrap();
        let proof = data.prove(witness).unwrap();
        assert_eq!(
            proof.public_inputs,
            [expected_leaf.elements, expected_node.elements].concat()
        );
        data.verify(proof).unwrap();
        println!("coinhist leaf/node host parity: PASS");
    }

    fn build_update_circuit() -> (
        plonky2::plonk::circuit_data::CircuitData<F, C, D>,
        [Target; 32],
        [HashOutTarget; COINHIST_DEPTH],
    ) {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let key = builder.add_virtual_target_arr();
        for byte in key {
            builder.range_check(byte, 8);
        }
        let siblings = std::array::from_fn(|_| builder.add_virtual_hash());
        let (old_root, new_root) = coinhist_update_roots(
            &mut builder,
            &key,
            CoinHistState::Absent as u8,
            CoinHistState::Admitted as u8,
            &siblings,
        );
        builder.register_public_inputs(&old_root.elements);
        builder.register_public_inputs(&new_root.elements);
        (builder.build::<C>(), key, siblings)
    }

    #[test]
    fn compliance_coinhist_first_insert_matches_empty_tree_reference() {
        let (data, key_target, path_target) = build_update_circuit();
        let mut key = [0u8; 32];
        key[0] = 0x91;
        key[17] = 0xa4;
        key[31] = 0x03;
        let empty = host::coinhist_empty_subtree_roots();
        let mut witness = PartialWitness::new();
        set_key(&mut witness, &key_target, &key);
        set_path(&mut witness, &path_target, &empty[..COINHIST_DEPTH]);
        let proof = data.prove(witness).unwrap();
        let expected_new = host::coinhist_root_after_first_insert(&key, CoinHistState::Admitted);
        assert_eq!(
            proof.public_inputs,
            [host::coinhist_empty_root().elements, expected_new.elements].concat()
        );
        data.verify(proof).unwrap();
        println!("coinhist first-insert root host parity: PASS");
    }

    fn prove_transition(
        old_state: CoinHistState,
        new_state: CoinHistState,
        key: [u8; 32],
        siblings_value: &[HashDigest],
        expected_old: HashDigest,
        expected_new: HashDigest,
    ) {
        let mut builder =
            CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
        let key_target = builder.add_virtual_target_arr();
        for byte in key_target {
            builder.range_check(byte, 8);
        }
        let path_target = std::array::from_fn(|_| builder.add_virtual_hash());
        let (old_root, new_root) = coinhist_update_roots(
            &mut builder,
            &key_target,
            old_state as u8,
            new_state as u8,
            &path_target,
        );
        builder.register_public_inputs(&old_root.elements);
        builder.register_public_inputs(&new_root.elements);
        let data = builder.build::<C>();
        let mut witness = PartialWitness::new();
        set_key(&mut witness, &key_target, &key);
        set_path(&mut witness, &path_target, siblings_value);
        let proof = data.prove(witness).unwrap();
        assert_eq!(
            proof.public_inputs,
            [expected_old.elements, expected_new.elements].concat()
        );
        data.verify(proof).unwrap();
    }

    #[test]
    fn compliance_coinhist_stateful_admit_then_spend_matches_tree() {
        let mut key = [0u8; 32];
        key[0] = 0xe3;
        key[31] = 0x57;
        let mut tree = CoinHistTree::new();

        let before_admit = tree.root();
        let admit_path = tree.prove(key);
        tree.admit(key).unwrap();
        let after_admit = tree.root();
        prove_transition(
            CoinHistState::Absent,
            CoinHistState::Admitted,
            key,
            &admit_path.siblings,
            before_admit,
            after_admit,
        );

        let spend_path = tree.prove(key);
        tree.spend(key).unwrap();
        let after_spend = tree.root();
        prove_transition(
            CoinHistState::Admitted,
            CoinHistState::Spent,
            key,
            &spend_path.siblings,
            after_admit,
            after_spend,
        );
        println!("coinhist stateful admit/spend host parity: PASS");
    }
}
