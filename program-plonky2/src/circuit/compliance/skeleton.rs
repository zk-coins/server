use plonky2::field::secp256k1_base::Secp256K1Base;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, Field64};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};

use crate::circuit::gadgets::bip340::{be_bytes32_to_nonnative, bip340_verify_with_s2c};
use crate::circuit::gadgets::coinhist::coinhist_update_roots;
use crate::circuit::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::circuit::gadgets::curve_types::Secp256K1;
use crate::circuit::gadgets::nonnative::{CircuitBuilderNonNative, NonNativeTarget};
use crate::circuit::gadgets::sha256::sha256;
use crate::circuit::gadgets::u128_arith::{
    accumulate, add_wide, connect_wide, geq, select_wide, zero_wide, U128Target, WideSum,
};
use crate::{C, D, F};

use super::bindings::{
    coin_identifier_with_index_target, enforce_input_coin_bindings, hash_proof_data_target,
    input_nullifiers_root_target, nk_commit_target,
};
use super::serialize::{
    address_from_pk0_and_nk_commit, be_bytes32_to_u32_limbs, digest_to_be_bytes_target,
    encode_byte_string_target, strict_be_bytes_less_than, tag_targets, u128_to_be_bytes_target,
    u64_to_be_bytes_target,
};
use super::targets::{
    virtual_bytes, AccountStateTarget, AssetIssuanceTarget, BalanceSlotTarget, CoinTarget,
    HistoryUpdatePathTarget, InputAuthTarget, InputCoinTarget, OutputTemplateTarget,
    ProofDataTarget, MAX_ACCOUNT_ASSETS, MAX_HISTORY_UPDATES_D3,
};
use super::{
    GENESIS_TAG, M_STATE_MAINNET, M_STATE_REGTEST, M_STATE_TESTNET, NETWORK_TAG_MAINNET,
    NETWORK_TAG_REGTEST, NETWORK_TAG_TESTNET, TAG_ACCOUNT_STATE, TAG_ASSET_ID, TAG_ASSET_ID_V2,
    TAG_COINS_ROOT_LEAF, TAG_COINS_ROOT_NODE, TAG_ISSUANCE_TERMS, TAG_ISSUANCE_TERMS_V2,
    TAG_NETWORK, TAG_NPK_COMMIT,
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
    pub asset_issuance: AssetIssuanceTarget,
    pub history_update_paths: [HistoryUpdatePathTarget; MAX_HISTORY_UPDATES_D3],
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
    balances: &[BalanceSlotTarget; MAX_ACCOUNT_ASSETS],
    asset_id_bytes: &[[Target; 32]; MAX_ACCOUNT_ASSETS],
) -> Target {
    for slot in *balances {
        assert_active_implies_nonzero_amount(builder, slot.active, slot.amount);
    }
    for index in 0..MAX_ACCOUNT_ASSETS - 1 {
        // A false slot forces every later slot false.
        let not_current = builder.not(balances[index].active);
        let gap = builder.and(not_current, balances[index + 1].active);
        builder.assert_zero(gap.target);

        let both_active = builder.and(balances[index].active, balances[index + 1].active);
        let ascending =
            strict_be_bytes_less_than(builder, &asset_id_bytes[index], &asset_id_bytes[index + 1]);
        let not_ascending = builder.not(ascending);
        let bad_order = builder.and(both_active, not_ascending);
        builder.assert_zero(bad_order.target);
    }
    builder.add_many(balances.map(|slot| slot.active.target))
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
    let count = enforce_balance_discipline(builder, &state.balances, &asset_id_bytes);

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

fn masked_balance_sum(
    builder: &mut CircuitBuilder<F, D>,
    balances: &[BalanceSlotTarget; MAX_ACCOUNT_ASSETS],
    asset_id: HashOutTarget,
) -> WideSum {
    let masked: [U128Target; MAX_ACCOUNT_ASSETS] = balances.map(|slot| {
        let same_asset = hashes_equal(builder, slot.asset_id, asset_id);
        let include = builder.and(slot.active, same_asset);
        U128Target::mask(builder, include, &slot.amount)
    });
    let partials: [WideSum; 4] =
        std::array::from_fn(|i| accumulate(builder, &masked[i * 8..(i + 1) * 8]));
    let left = add_wide(builder, &partials[0], &partials[1]);
    let right = add_wide(builder, &partials[2], &partials[3]);
    add_wide(builder, &left, &right)
}

fn masked_input_sum(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[InputCoinTarget; MAX_TX_INPUTS],
    asset_id: HashOutTarget,
) -> WideSum {
    let masked = inputs.map(|coin| {
        let same_asset = hashes_equal(builder, coin.asset_id, asset_id);
        let include = builder.and(coin.active, same_asset);
        U128Target::mask(builder, include, &coin.amount)
    });
    accumulate(builder, &masked)
}

fn masked_output_sum(
    builder: &mut CircuitBuilder<F, D>,
    outputs: &[OutputTemplateTarget; MAX_TX_OUTPUTS],
    owner: Option<&[Target; 32]>,
    asset_id: HashOutTarget,
) -> WideSum {
    let masked = outputs.map(|output| {
        let same_asset = hashes_equal(builder, output.asset_id, asset_id);
        let mut include = builder.and(output.active, same_asset);
        if let Some(owner) = owner {
            let is_self = bytes_equal(builder, &output.recipient, owner);
            include = builder.and(include, is_self);
        }
        U128Target::mask(builder, include, &output.amount)
    });
    accumulate(builder, &masked)
}

fn masked_mint_sum(
    builder: &mut CircuitBuilder<F, D>,
    issuance: &AssetIssuanceTarget,
    asset_id: HashOutTarget,
) -> WideSum {
    let same_asset = hashes_equal(builder, issuance.asset_id, asset_id);
    let include = builder.and(issuance.present, same_asset);
    let masked = U128Target::mask(builder, include, &issuance.amount);
    WideSum::from_u128(builder, &masked)
}

fn asset_id_v1_target(
    builder: &mut CircuitBuilder<F, D>,
    issuance: &AssetIssuanceTarget,
) -> HashOutTarget {
    let genesis: Vec<_> = GENESIS_TAG
        .iter()
        .map(|&byte| builder.constant(F::from_canonical_u8(byte)))
        .collect();
    let mut elements = tag_targets(builder, TAG_ASSET_ID);
    elements.extend(encode_byte_string_target(builder, &genesis));
    elements.extend(encode_byte_string_target(builder, &issuance.creator_pubkey));
    elements.extend(encode_byte_string_target(builder, &issuance.name_hash));
    elements.push(issuance.decimals);
    elements.push(issuance.issuance_version);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

fn asset_id_v2_target(
    builder: &mut CircuitBuilder<F, D>,
    issuance: &AssetIssuanceTarget,
) -> HashOutTarget {
    let genesis: Vec<_> = GENESIS_TAG
        .iter()
        .map(|&byte| builder.constant(F::from_canonical_u8(byte)))
        .collect();
    let cap_bytes = u128_to_be_bytes_target(builder, issuance.cap_total);
    let mut elements = tag_targets(builder, TAG_ASSET_ID_V2);
    elements.extend(encode_byte_string_target(builder, &genesis));
    elements.extend(encode_byte_string_target(builder, &issuance.creator_pubkey));
    elements.extend(encode_byte_string_target(builder, &issuance.name_hash));
    elements.push(issuance.decimals);
    elements.push(issuance.issuance_version);
    elements.extend(encode_byte_string_target(builder, &cap_bytes));
    elements.extend(encode_byte_string_target(builder, &issuance.terms_salt));
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

fn terms_hash_v1_target(
    builder: &mut CircuitBuilder<F, D>,
    issuance: &AssetIssuanceTarget,
) -> HashOutTarget {
    let mut elements = tag_targets(builder, TAG_ISSUANCE_TERMS);
    elements.extend(issuance.asset_id.elements);
    elements.push(issuance.issuance_version);
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

fn terms_hash_v2_target(
    builder: &mut CircuitBuilder<F, D>,
    issuance: &AssetIssuanceTarget,
) -> HashOutTarget {
    let cap_bytes = u128_to_be_bytes_target(builder, issuance.cap_total);
    let mut elements = tag_targets(builder, TAG_ISSUANCE_TERMS_V2);
    elements.extend(issuance.asset_id.elements);
    elements.push(issuance.issuance_version);
    elements.extend(encode_byte_string_target(builder, &cap_bytes));
    elements.extend(encode_byte_string_target(builder, &issuance.terms_salt));
    builder.hash_n_to_hash_no_pad::<PoseidonHash>(elements)
}

fn enforce_mint(
    builder: &mut CircuitBuilder<F, D>,
    issuance: &AssetIssuanceTarget,
    previous: &AccountStateTarget,
    outputs: &[OutputTemplateTarget; MAX_TX_OUTPUTS],
    inputs: &[InputCoinTarget; MAX_TX_INPUTS],
) {
    let one = builder.one();
    let two = builder.constant(F::from_canonical_u8(2));
    let is_v1 = builder.is_equal(issuance.issuance_version, one);
    let is_v2 = builder.is_equal(issuance.issuance_version, two);
    let supported = builder.or(is_v1, is_v2);
    let unsupported = builder.not(supported);
    let bad_version = builder.and(issuance.present, unsupported);
    builder.assert_zero(bad_version.target);

    let creator_address =
        address_from_pk0_and_nk_commit(builder, &issuance.creator_pubkey, previous.nk_commit);
    let owner_matches = bytes_equal(builder, &creator_address, &previous.owner);
    let owner_mismatch = builder.not(owner_matches);
    let bad_owner = builder.and(issuance.present, owner_mismatch);
    builder.assert_zero(bad_owner.target);

    let asset_v1 = asset_id_v1_target(builder, issuance);
    let asset_v2 = asset_id_v2_target(builder, issuance);
    let expected_asset = select_hash(builder, is_v1, asset_v1, asset_v2);
    let selected_asset = select_hash(builder, issuance.present, issuance.asset_id, expected_asset);
    builder.connect_hashes(selected_asset, expected_asset);

    let terms_v1 = terms_hash_v1_target(builder, issuance);
    let terms_v2 = terms_hash_v2_target(builder, issuance);
    let expected_terms = select_hash(builder, is_v1, terms_v1, terms_v2);
    let selected_terms = select_hash(
        builder,
        issuance.present,
        issuance.terms_hash,
        expected_terms,
    );
    builder.connect_hashes(selected_terms, expected_terms);

    let apply_v2 = builder.and(issuance.present, is_v2);
    let cap = WideSum::from_u128(builder, &issuance.cap_total);
    let amount = WideSum::from_u128(builder, &issuance.amount);
    let cap_holds = geq(builder, &cap, &amount);
    let cap_fails = builder.not(cap_holds);
    let bad_cap = builder.and(apply_v2, cap_fails);
    builder.assert_zero(bad_cap.target);

    let zero_target = builder.zero();
    let counter_zero = builder.is_equal(previous.send_counter, zero_target);
    let counter_nonzero = builder.not(counter_zero);
    let bad_counter = builder.and(apply_v2, counter_nonzero);
    builder.assert_zero(bad_counter.target);
    let creator_is_current =
        bytes_equal(builder, &previous.current_pubkey, &issuance.creator_pubkey);
    let creator_not_current = builder.not(creator_is_current);
    let bad_current = builder.and(apply_v2, creator_not_current);
    builder.assert_zero(bad_current.target);

    let out = masked_output_sum(builder, outputs, None, issuance.asset_id);
    let selected_out = select_wide(builder, apply_v2, &out, &amount);
    connect_wide(builder, &selected_out, &amount);
    let input = masked_input_sum(builder, inputs, issuance.asset_id);
    let zero = zero_wide(builder);
    let selected_input = select_wide(builder, apply_v2, &input, &zero);
    connect_wide(builder, &selected_input, &zero);

    for output in outputs {
        let same_asset = hashes_equal(builder, output.asset_id, issuance.asset_id);
        let self_addressed = bytes_equal(builder, &output.recipient, &previous.owner);
        let active_asset = builder.and(output.active, same_asset);
        let forbidden_output = builder.and(active_asset, self_addressed);
        let forbidden_v2 = builder.and(apply_v2, forbidden_output);
        builder.assert_zero(forbidden_v2.target);
    }
}

fn enforce_conservation(
    builder: &mut CircuitBuilder<F, D>,
    inputs: &[InputCoinTarget; MAX_TX_INPUTS],
    outputs: &[OutputTemplateTarget; MAX_TX_OUTPUTS],
    issuance: &AssetIssuanceTarget,
) {
    let candidates: [HashOutTarget; 2 * MAX_TX_INPUTS + 1] = std::array::from_fn(|i| {
        if i < MAX_TX_INPUTS {
            inputs[i].asset_id
        } else if i < MAX_TX_INPUTS + MAX_TX_OUTPUTS {
            outputs[i - MAX_TX_INPUTS].asset_id
        } else {
            issuance.asset_id
        }
    });
    for asset_id in candidates {
        let input = masked_input_sum(builder, inputs, asset_id);
        let mint = masked_mint_sum(builder, issuance, asset_id);
        let output = masked_output_sum(builder, outputs, None, asset_id);
        let available = add_wide(builder, &input, &mint);
        let holds = geq(builder, &available, &output);
        builder.assert_one(holds.target);
    }
}

fn enforce_balance_fold(
    builder: &mut CircuitBuilder<F, D>,
    previous: &AccountStateTarget,
    new: &AccountStateTarget,
    inputs: &[InputCoinTarget; MAX_TX_INPUTS],
    outputs: &[OutputTemplateTarget; MAX_TX_OUTPUTS],
) {
    let candidates: [HashOutTarget; 2 * MAX_ACCOUNT_ASSETS + 2 * MAX_TX_INPUTS] =
        std::array::from_fn(|i| {
            if i < MAX_ACCOUNT_ASSETS {
                previous.balances[i].asset_id
            } else if i < 2 * MAX_ACCOUNT_ASSETS {
                new.balances[i - MAX_ACCOUNT_ASSETS].asset_id
            } else if i < 2 * MAX_ACCOUNT_ASSETS + MAX_TX_INPUTS {
                inputs[i - 2 * MAX_ACCOUNT_ASSETS].asset_id
            } else {
                outputs[i - 2 * MAX_ACCOUNT_ASSETS - MAX_TX_INPUTS].asset_id
            }
        });
    for asset_id in candidates {
        let prev = masked_balance_sum(builder, &previous.balances, asset_id);
        let new = masked_balance_sum(builder, &new.balances, asset_id);
        let input = masked_input_sum(builder, inputs, asset_id);
        let self_output = masked_output_sum(builder, outputs, Some(&previous.owner), asset_id);
        let lhs = add_wide(builder, &prev, &self_output);
        let rhs = add_wide(builder, &new, &input);
        connect_wide(builder, &lhs, &rhs);
    }
}

fn coin_history_update_target(
    builder: &mut CircuitBuilder<F, D>,
    previous: &AccountStateTarget,
    new: &AccountStateTarget,
    inputs: &[InputCoinTarget; MAX_TX_INPUTS],
    outputs: &[OutputTemplateTarget; MAX_TX_OUTPUTS],
    output_coins: &[CoinTarget; MAX_TX_OUTPUTS],
    paths: &[HistoryUpdatePathTarget; MAX_HISTORY_UPDATES_D3],
) -> HashOutTarget {
    let mut current_root = previous.coin_history_root;
    for index in 0..MAX_HISTORY_UPDATES_D3 {
        let (key, old_state, new_state, apply) = if index < MAX_TX_INPUTS {
            (inputs[index].identifier, 1, 2, inputs[index].active)
        } else {
            let output_index = index - MAX_TX_INPUTS;
            let is_self = bytes_equal(builder, &outputs[output_index].recipient, &previous.owner);
            (
                output_coins[output_index].identifier,
                0,
                1,
                builder.and(outputs[output_index].active, is_self),
            )
        };
        let key_bytes = digest_to_be_bytes_target(builder, key);
        let (root_old, root_new) = coinhist_update_roots(
            builder,
            &key_bytes,
            old_state,
            new_state,
            &paths[index].siblings,
        );
        let required_old = select_hash(builder, apply, current_root, root_old);
        builder.connect_hashes(root_old, required_old);
        current_root = select_hash(builder, apply, root_new, current_root);
    }
    builder.connect_hashes(current_root, new.coin_history_root);
    current_root
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
    let asset_issuance = AssetIssuanceTarget::new_virtual(&mut builder);
    let history_update_paths =
        std::array::from_fn(|_| HistoryUpdatePathTarget::new_virtual(&mut builder));
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
    let prev_asset_id_bytes = std::array::from_fn(|i| {
        digest_to_be_bytes_target(&mut builder, prev_account_state.balances[i].asset_id)
    });
    let _prev_balance_count = enforce_balance_discipline(
        &mut builder,
        &prev_account_state.balances,
        &prev_asset_id_bytes,
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
    enforce_mint(
        &mut builder,
        &asset_issuance,
        &prev_account_state,
        &output_templates,
        &input_coins,
    );
    enforce_conservation(
        &mut builder,
        &input_coins,
        &output_templates,
        &asset_issuance,
    );
    enforce_balance_fold(
        &mut builder,
        &prev_account_state,
        &new_account_state,
        &input_coins,
        &output_templates,
    );
    let coin_history_root = coin_history_update_target(
        &mut builder,
        &prev_account_state,
        &new_account_state,
        &input_coins,
        &output_templates,
        &output_coins,
        &history_update_paths,
    );
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
        coin_history_root,
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
        asset_issuance,
        history_update_paths,
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
