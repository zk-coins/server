use plonky2::field::secp256k1_base::Secp256K1Base;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, Field64};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};

use crate::circuit::gadgets::bip340::{be_bytes32_to_nonnative, bip340_verify_with_s2c};
use crate::circuit::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::circuit::gadgets::curve_types::Secp256K1;
use crate::circuit::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use crate::circuit::gadgets::sha256::sha256;
use crate::{C, D, F};

use super::bindings::{
    coin_identifier_with_index_target, enforce_input_coin_bindings, hash_proof_data_target,
    input_nullifiers_root_target, nk_commit_target,
};
use super::serialize::{
    be_bytes32_to_u32_limbs, digest_to_be_bytes_target, encode_byte_string_target,
    strict_be_bytes_less_than, tag_targets, u128_to_be_bytes_target, u64_to_be_bytes_target,
};
use super::targets::{
    virtual_bytes, AccountStateTarget, CoinTarget, InputAuthTarget, InputCoinTarget,
    OutputTemplateTarget, ProofDataTarget, MAX_ACCOUNT_ASSETS,
};
use super::{
    M_STATE_MAINNET, M_STATE_REGTEST, M_STATE_TESTNET, NETWORK_TAG_MAINNET, NETWORK_TAG_REGTEST,
    NETWORK_TAG_TESTNET, TAG_ACCOUNT_STATE, TAG_COINS_ROOT_LEAF, TAG_COINS_ROOT_NODE, TAG_NETWORK,
    TAG_NPK_COMMIT,
};

/// Fixed input-slot bound from spec §2.5.
pub const MAX_TX_INPUTS: usize = 8;

/// Fixed output-slot bound from spec §2.5.
pub const MAX_TX_OUTPUTS: usize = 8;

/// Compile-time network selected for a compliance-circuit build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Network {
    Mainnet,
    Testnet,
    Regtest,
}

impl Network {
    fn tag_bytes(self) -> &'static [u8] {
        match self {
            Self::Mainnet => NETWORK_TAG_MAINNET,
            Self::Testnet => NETWORK_TAG_TESTNET,
            Self::Regtest => NETWORK_TAG_REGTEST,
        }
    }

    pub fn m_state_bytes(self) -> &'static [u8] {
        match self {
            Self::Mainnet => M_STATE_MAINNET,
            Self::Testnet => M_STATE_TESTNET,
            Self::Regtest => M_STATE_REGTEST,
        }
    }
}

/// All witness and derived targets exposed to a host-side witness setter.
#[derive(Clone, Debug)]
pub struct ComplianceTargets {
    pub prev_account_state: AccountStateTarget,
    pub new_account_state: AccountStateTarget,
    pub prev_account_state_hash: HashOutTarget,
    pub nk: [Target; 32],
    pub input_coins: [InputCoinTarget; MAX_TX_INPUTS],
    pub input_auth: [InputAuthTarget; MAX_TX_INPUTS],
    pub output_templates: [OutputTemplateTarget; MAX_TX_OUTPUTS],
    pub output_coins: [CoinTarget; MAX_TX_OUTPUTS],
    pub next_pubkey: [Target; 32],
    pub npk_rand: [Target; 32],
    pub txn_sig_rx: NonNativeTarget<Secp256K1Base>,
    pub txn_sig_s: NonNativeTarget<Secp256K1Scalar>,
    pub s2c_r_prime: AffinePointTarget<Secp256K1>,
    pub proof_data: ProofDataTarget,
    pub consumed_pubkey: [Target; 32],
    pub network_id: HashOutTarget,
    pub balance_count: Target,
    pub output_count: Target,
}

/// Built skeleton plus its pre-padding gate count.
pub struct SkeletonCircuit {
    pub data: CircuitData<F, C, D>,
    pub targets: ComplianceTargets,
    pub gate_count: usize,
}

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
    let mut selector_targets = Vec::with_capacity(candidates.len());
    for (index, &candidate) in candidates.iter().enumerate() {
        let index_target = builder.constant(F::from_canonical_usize(index));
        let is_index = builder.is_equal(count, index_target);
        selected = select_hash(builder, is_index, candidate, selected);
        selector_targets.push(is_index.target);
    }
    let selector_sum = builder.add_many(selector_targets);
    builder.assert_one(selector_sum);
    selected
}

fn assert_active_implies_nonzero_amount(
    builder: &mut CircuitBuilder<F, D>,
    active: BoolTarget,
    amount: crate::circuit::gadgets::u128_arith::U128Target,
) {
    let zero = builder.zero();
    let mut all_zero = builder.constant_bool(true);
    for limb in amount.limbs {
        let limb_zero = builder.is_equal(limb, zero);
        all_zero = builder.and(all_zero, limb_zero);
    }
    let invalid = builder.and(active, all_zero);
    builder.assert_zero(invalid.target);
}

fn enforce_balance_discipline(
    builder: &mut CircuitBuilder<F, D>,
    state: &AccountStateTarget,
    asset_id_bytes: &[[Target; 32]; MAX_ACCOUNT_ASSETS],
) -> Target {
    for slot in state.balances {
        assert_active_implies_nonzero_amount(builder, slot.active, slot.amount);
    }
    for index in 0..MAX_ACCOUNT_ASSETS - 1 {
        // A false slot forces every later slot false.
        let not_current = builder.not(state.balances[index].active);
        let gap = builder.and(not_current, state.balances[index + 1].active);
        builder.assert_zero(gap.target);

        let both_active = builder.and(
            state.balances[index].active,
            state.balances[index + 1].active,
        );
        let ascending =
            strict_be_bytes_less_than(builder, &asset_id_bytes[index], &asset_id_bytes[index + 1]);
        let not_ascending = builder.not(ascending);
        let bad_order = builder.and(both_active, not_ascending);
        builder.assert_zero(bad_order.target);
    }
    builder.add_many(state.balances.map(|slot| slot.active.target))
}

fn account_state_hash_target(
    builder: &mut CircuitBuilder<F, D>,
    state: &AccountStateTarget,
) -> (HashOutTarget, Target) {
    let nk_commit_bytes = digest_to_be_bytes_target(builder, state.nk_commit);
    let send_counter_bytes = u64_to_be_bytes_target(builder, state.send_counter);
    let history_root_bytes = digest_to_be_bytes_target(builder, state.coin_history_root);
    let asset_id_bytes =
        std::array::from_fn(|i| digest_to_be_bytes_target(builder, state.balances[i].asset_id));
    let amount_bytes: [[Target; 16]; MAX_ACCOUNT_ASSETS] =
        std::array::from_fn(|i| u128_to_be_bytes_target(builder, state.balances[i].amount));
    let count = enforce_balance_discipline(builder, state, &asset_id_bytes);

    let mut fixed_prefix = Vec::with_capacity(136);
    fixed_prefix.extend_from_slice(&state.owner);
    fixed_prefix.extend_from_slice(&nk_commit_bytes);
    fixed_prefix.extend_from_slice(&state.current_pubkey);
    fixed_prefix.extend_from_slice(&send_counter_bytes);
    fixed_prefix.extend_from_slice(&history_root_bytes);
    assert_eq!(
        fixed_prefix.len(),
        136,
        "AccountState prefix before balances_count must be 136 bytes"
    );

    let tag = tag_targets(builder, TAG_ACCOUNT_STATE);
    let mut candidates = Vec::with_capacity(MAX_ACCOUNT_ASSETS + 1);
    for active_count in 0..=MAX_ACCOUNT_ASSETS {
        let mut bytes = Vec::with_capacity(140 + 48 * active_count);
        bytes.extend_from_slice(&fixed_prefix);
        for byte in (active_count as u32).to_be_bytes() {
            bytes.push(builder.constant(F::from_canonical_u8(byte)));
        }
        for index in 0..active_count {
            bytes.extend_from_slice(&asset_id_bytes[index]);
            bytes.extend_from_slice(&amount_bytes[index]);
        }
        assert_eq!(
            bytes.len(),
            140 + 48 * active_count,
            "AccountState candidate serialization has the normative length"
        );
        let mut elements = tag.clone();
        elements.extend(encode_byte_string_target(builder, &bytes));
        candidates.push(builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements));
    }
    (select_exact_hash(builder, count, &candidates), count)
}

pub(crate) fn coin_identifier_target(
    builder: &mut CircuitBuilder<F, D>,
    prev_account_state_hash: HashOutTarget,
    template: OutputTemplateTarget,
    coin_index: usize,
) -> HashOutTarget {
    let coin_index = builder.constant(F::from_canonical_usize(coin_index));
    coin_identifier_with_index_target(
        builder,
        prev_account_state_hash,
        &template.recipient,
        template.asset_id,
        template.amount,
        coin_index,
    )
}

fn coins_leaf_hash(builder: &mut CircuitBuilder<F, D>, value: HashOutTarget) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_COINS_ROOT_LEAF);
    elements.extend(value.elements);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

fn coins_node_hash(
    builder: &mut CircuitBuilder<F, D>,
    left: HashOutTarget,
    right: HashOutTarget,
) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_COINS_ROOT_NODE);
    elements.extend(left.elements);
    elements.extend(right.elements);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

fn output_coins_root_target(
    builder: &mut CircuitBuilder<F, D>,
    templates: &[OutputTemplateTarget; MAX_TX_OUTPUTS],
    coins: &[CoinTarget; MAX_TX_OUTPUTS],
) -> (HashOutTarget, Target) {
    for index in 0..MAX_TX_OUTPUTS - 1 {
        let not_current = builder.not(templates[index].active);
        let gap = builder.and(not_current, templates[index + 1].active);
        builder.assert_zero(gap.target);
    }
    let count = builder.add_many(templates.map(|template| template.active.target));

    let zero_digest = HashOutTarget {
        elements: [builder.zero(); 4],
    };
    let empty_leaf = coins_leaf_hash(builder, zero_digest);
    let leaves = coins.map(|coin| coins_leaf_hash(builder, coin.identifier));
    let mut candidates = Vec::with_capacity(MAX_TX_OUTPUTS + 1);
    candidates.push(empty_leaf);
    for active_count in 1..=MAX_TX_OUTPUTS {
        let width = active_count.next_power_of_two();
        let mut level = Vec::with_capacity(width);
        level.extend_from_slice(&leaves[..active_count]);
        level.resize(width, empty_leaf);
        while level.len() > 1 {
            let mut next = Vec::with_capacity(level.len() / 2);
            for pair in level.chunks_exact(2) {
                next.push(coins_node_hash(builder, pair[0], pair[1]));
            }
            level = next;
        }
        candidates.push(level[0]);
    }
    (select_exact_hash(builder, count, &candidates), count)
}

fn connect_bytes(builder: &mut CircuitBuilder<F, D>, lhs: &[Target; 32], rhs: &[Target; 32]) {
    for (&lhs_byte, &rhs_byte) in lhs.iter().zip(rhs) {
        builder.connect(lhs_byte, rhs_byte);
    }
}

fn connect_unchanged_state(
    builder: &mut CircuitBuilder<F, D>,
    previous: &AccountStateTarget,
    new: &AccountStateTarget,
    next_pubkey: &[Target; 32],
) {
    connect_bytes(builder, &previous.owner, &new.owner);
    builder.connect_hashes(previous.nk_commit, new.nk_commit);
    for (previous_slot, new_slot) in previous.balances.iter().zip(&new.balances) {
        builder.connect(previous_slot.active.target, new_slot.active.target);
        builder.connect_hashes(previous_slot.asset_id, new_slot.asset_id);
        for (&previous_limb, &new_limb) in previous_slot
            .amount
            .limbs
            .iter()
            .zip(&new_slot.amount.limbs)
        {
            builder.connect(previous_limb, new_limb);
        }
    }
    connect_bytes(builder, &new.current_pubkey, next_pubkey);

    // Both counters are canonical Goldilocks integers and the predecessor
    // cannot be ORDER-1, so field addition is exact integer `+ 1`.
    let _previous_counter_bytes = u64_to_be_bytes_target(builder, previous.send_counter);
    let largest = builder.constant(F::from_canonical_u64(F::ORDER - 1));
    let at_largest = builder.is_equal(previous.send_counter, largest);
    builder.assert_zero(at_largest.target);
    let incremented = builder.add_const(previous.send_counter, F::ONE);
    builder.connect(new.send_counter, incremented);
}

fn network_id_target(builder: &mut CircuitBuilder<F, D>, network: Network) -> HashOutTarget {
    let tag_bytes: Vec<Target> = network
        .tag_bytes()
        .iter()
        .map(|&byte| builder.constant(F::from_canonical_u8(byte)))
        .collect();
    let mut elements = tag_targets(builder, TAG_NETWORK);
    elements.extend(encode_byte_string_target(builder, &tag_bytes));
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

/// Builds the real, non-recursive compliance skeleton for one network.
pub fn build_skeleton_circuit(config: CircuitConfig, network: Network) -> SkeletonCircuit {
    let mut builder = CircuitBuilder::<F, D>::new(config);

    let prev_account_state = AccountStateTarget::new_virtual(&mut builder);
    let new_account_state = AccountStateTarget::new_virtual(&mut builder);
    let prev_account_state_hash = builder.add_virtual_hash();
    let nk = virtual_bytes(&mut builder);
    let input_coins = std::array::from_fn(|_| InputCoinTarget::new_virtual(&mut builder));
    let input_auth = std::array::from_fn(|_| InputAuthTarget::new_virtual(&mut builder));
    let output_templates = std::array::from_fn(|_| OutputTemplateTarget::new_virtual(&mut builder));
    let next_pubkey = virtual_bytes(&mut builder);
    let npk_rand = virtual_bytes(&mut builder);
    let consumed_pubkey = virtual_bytes(&mut builder);
    let txn_sig_rx = builder.add_virtual_nonnative_target();
    let txn_sig_s = builder.add_virtual_nonnative_target();
    let s2c_r_prime = builder.add_virtual_affine_point_target();

    connect_unchanged_state(
        &mut builder,
        &prev_account_state,
        &new_account_state,
        &next_pubkey,
    );
    connect_bytes(
        &mut builder,
        &consumed_pubkey,
        &prev_account_state.current_pubkey,
    );
    let computed_nk_commit = nk_commit_target(&mut builder, &nk);
    builder.connect_hashes(computed_nk_commit, prev_account_state.nk_commit);
    enforce_input_coin_bindings(
        &mut builder,
        &prev_account_state.owner,
        &input_coins,
        &input_auth,
    );

    let input_active = input_coins.map(|coin| coin.active);
    let input_identifiers = input_coins.map(|coin| coin.identifier);
    let (input_nullifiers_root, _nullifiers, _input_count) =
        input_nullifiers_root_target(&mut builder, &nk, &input_active, &input_identifiers);

    let output_coins = std::array::from_fn(|index| {
        let template = output_templates[index];
        CoinTarget {
            identifier: coin_identifier_target(
                &mut builder,
                prev_account_state_hash,
                template,
                index,
            ),
            recipient: template.recipient,
            amount: template.amount,
            asset_id: template.asset_id,
        }
    });
    let (output_coins_root, output_count) =
        output_coins_root_target(&mut builder, &output_templates, &output_coins);
    let (new_account_state_hash, balance_count) =
        account_state_hash_target(&mut builder, &new_account_state);

    let tag_targets: Vec<Target> = TAG_NPK_COMMIT
        .iter()
        .map(|&byte| builder.constant(F::from_canonical_u8(byte)))
        .collect();
    let mut npk_preimage = Vec::with_capacity(TAG_NPK_COMMIT.len() + 64);
    npk_preimage.extend_from_slice(&tag_targets);
    npk_preimage.extend_from_slice(&next_pubkey);
    npk_preimage.extend_from_slice(&npk_rand);
    let npk_commit = sha256(&mut builder, &npk_preimage);

    let proof_data = ProofDataTarget {
        new_account_state_hash,
        output_coins_root,
        input_nullifiers_root,
        coin_history_root: builder.add_virtual_hash(),
        nav_commitment: builder.add_virtual_hash(),
        npk_commit,
    };
    let h_proof_data = hash_proof_data_target(&mut builder, &proof_data);
    let pk_x = be_bytes32_to_nonnative::<Secp256K1Base, F, D>(&mut builder, &consumed_pubkey);
    let _signature_opening = bip340_verify_with_s2c(
        &mut builder,
        &pk_x,
        &txn_sig_rx,
        &txn_sig_s,
        network.m_state_bytes(),
        &s2c_r_prime,
        &h_proof_data,
    );
    let network_id = network_id_target(&mut builder, network);

    // Clause-9 application PI order: 20 native Poseidon elements, then the
    // SHA-256 commitment and consumed key as little-endian u32 limbs, then
    // the native four-element network digest.
    for digest in [
        proof_data.new_account_state_hash,
        proof_data.output_coins_root,
        proof_data.input_nullifiers_root,
        proof_data.coin_history_root,
        proof_data.nav_commitment,
    ] {
        builder.register_public_inputs(&digest.elements);
    }
    let npk_limbs = be_bytes32_to_u32_limbs(&mut builder, &proof_data.npk_commit);
    builder.register_public_inputs(&npk_limbs);
    let consumed_pubkey_limbs = be_bytes32_to_u32_limbs(&mut builder, &consumed_pubkey);
    builder.register_public_inputs(&consumed_pubkey_limbs);
    builder.register_public_inputs(&network_id.elements);
    assert_eq!(
        builder.num_public_inputs(),
        40,
        "compliance skeleton must expose exactly 40 application public inputs"
    );

    let targets = ComplianceTargets {
        prev_account_state,
        new_account_state,
        prev_account_state_hash,
        nk,
        input_coins,
        input_auth,
        output_templates,
        output_coins,
        next_pubkey,
        npk_rand,
        txn_sig_rx,
        txn_sig_s,
        s2c_r_prime,
        proof_data,
        consumed_pubkey,
        network_id,
        balance_count,
        output_count,
    };
    let gate_count = builder.num_gates();
    let data = builder.build::<C>();
    SkeletonCircuit {
        data,
        targets,
        gate_count,
    }
}
