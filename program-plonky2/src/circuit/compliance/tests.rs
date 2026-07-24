use std::collections::BTreeMap;
use std::time::Instant;

use plonky2::field::types::{Field, PrimeField64};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;

use shared::spec_v1::{
    self as host, AccountState, Address, CoinTemplate, HashDigest, HcInput, TreeKind, ZERO_HASH,
};

use crate::circuit::gadgets::u128_arith::U128Target;
use crate::{C, D, F};

use super::serialize::encode_ascii_tag_elements;
use super::skeleton::coin_identifier_target;
use super::targets::{AccountStateTarget, OutputTemplateTarget};
use super::*;

fn digest(label: &[u8]) -> HashDigest {
    host::hc(
        "zkCoins/v1/ComplianceSkeleton/TestDigest",
        &[HcInput::ByteString(label)],
    )
    .expect("fixed test label must encode")
}

fn digest_limbs(digest: HashDigest) -> [u64; 4] {
    digest.elements.map(|element| element.to_canonical_u64())
}

fn set_bytes(witness: &mut PartialWitness<F>, targets: &[Target; 32], bytes: &[u8; 32]) {
    for (&target, &byte) in targets.iter().zip(bytes) {
        witness
            .set_target(target, F::from_canonical_u8(byte))
            .expect("byte witness assignment must succeed");
    }
}

fn set_u128(witness: &mut PartialWitness<F>, target: U128Target, value: u128) {
    for (index, limb) in target.limbs.into_iter().enumerate() {
        let value = ((value >> (32 * index)) & u128::from(u32::MAX)) as u32;
        witness
            .set_target(limb, F::from_canonical_u32(value))
            .expect("u128 limb witness assignment must succeed");
    }
}

fn set_account_state_fixed(
    witness: &mut PartialWitness<F>,
    target: AccountStateTarget,
    state: &AccountState,
) {
    set_bytes(witness, &target.owner, &state.owner.0);
    witness
        .set_hash_target(target.nk_commit, state.nk_commit)
        .expect("nk_commit witness assignment must succeed");
    set_bytes(witness, &target.current_pubkey, &state.current_pubkey);
    witness
        .set_target(
            target.send_counter,
            F::from_canonical_u64(state.send_counter),
        )
        .expect("send_counter witness assignment must succeed");
    witness
        .set_hash_target(target.coin_history_root, state.coin_history_root)
        .expect("coin-history-root witness assignment must succeed");
}

#[derive(Clone, Copy)]
enum BalanceLayout {
    Valid,
    Gap,
    Descending,
}

fn set_account_balances(
    witness: &mut PartialWitness<F>,
    target: AccountStateTarget,
    state: &AccountState,
    layout: BalanceLayout,
) {
    let entries: Vec<_> = state.balances.iter().collect();
    for (index, slot) in target.balances.into_iter().enumerate() {
        let source_index = match (layout, index) {
            (BalanceLayout::Descending, 0) => 1,
            (BalanceLayout::Descending, 1) => 0,
            _ => index,
        };
        if let Some((asset_bytes, amount)) = entries.get(source_index).copied() {
            let asset_id =
                host::digest_from_bytes(asset_bytes).expect("test asset digest must be canonical");
            let active = !matches!(layout, BalanceLayout::Gap) || index != 1;
            witness
                .set_bool_target(slot.active, active)
                .expect("active balance assignment must succeed");
            witness
                .set_hash_target(slot.asset_id, asset_id)
                .expect("asset-id witness assignment must succeed");
            set_u128(witness, slot.amount, *amount);
        } else {
            witness
                .set_bool_target(slot.active, false)
                .expect("inactive balance assignment must succeed");
            witness
                .set_hash_target(slot.asset_id, ZERO_HASH)
                .expect("inactive asset-id assignment must succeed");
            set_u128(witness, slot.amount, 0);
        }
    }
}

fn set_output_templates(
    witness: &mut PartialWitness<F>,
    targets: &[OutputTemplateTarget; MAX_TX_OUTPUTS],
    templates: &[CoinTemplate],
) {
    for (index, target) in targets.iter().copied().enumerate() {
        if let Some(template) = templates.get(index) {
            witness
                .set_bool_target(target.active, true)
                .expect("active output assignment must succeed");
            set_bytes(witness, &target.recipient, &template.recipient.0);
            set_u128(witness, target.amount, template.amount);
            witness
                .set_hash_target(target.asset_id, template.asset_id)
                .expect("output asset-id assignment must succeed");
        } else {
            witness
                .set_bool_target(target.active, false)
                .expect("inactive output assignment must succeed");
            set_bytes(witness, &target.recipient, &[0u8; 32]);
            set_u128(witness, target.amount, 0);
            witness
                .set_hash_target(target.asset_id, ZERO_HASH)
                .expect("inactive output asset-id assignment must succeed");
        }
    }
}

fn bytes_as_u32_le_limbs(bytes: &[u8; 32]) -> [F; 8] {
    std::array::from_fn(|index| {
        let start = 28 - 4 * index;
        let word = u32::from_be_bytes(
            bytes[start..start + 4]
                .try_into()
                .expect("four-byte limb slice"),
        );
        F::from_canonical_u32(word)
    })
}

fn sample_balances() -> (BTreeMap<[u8; 32], u128>, Vec<HashDigest>) {
    let mut assets = vec![
        digest(b"partial-balance-c"),
        digest(b"partial-balance-a"),
        digest(b"partial-balance-b"),
    ];
    assets.sort_by_key(host::digest_to_bytes);
    let amounts = [17u128, (1u128 << 96) + 29, u128::MAX - 41];
    let balances = assets
        .iter()
        .zip(amounts)
        .map(|(&asset_id, amount)| (host::digest_to_bytes(&asset_id), amount))
        .collect();
    (balances, assets)
}

#[test]
fn local_tags_and_tag_encoding_match_shared() {
    let string_tags = [
        (TAG_ACCOUNT_STATE, host::TAG_ACCOUNT_STATE),
        (TAG_COIN, host::TAG_COIN),
        (TAG_COINS_ROOT_LEAF, host::TAG_COINS_ROOT_LEAF),
        (TAG_COINS_ROOT_NODE, host::TAG_COINS_ROOT_NODE),
        (TAG_NETWORK, host::TAG_NETWORK),
    ];
    for (local, shared) in string_tags {
        assert_eq!(local.as_bytes(), shared.as_bytes());
        let local_elements = encode_ascii_tag_elements(local);
        let shared_elements = host::encode_byte_string(shared.as_bytes())
            .expect("shared tag encoding must succeed")
            .into_iter()
            .map(|element| element.to_canonical_u64())
            .collect::<Vec<_>>();
        assert_eq!(local_elements, shared_elements);
    }
    assert_eq!(TAG_NPK_COMMIT, host::TAG_NPK_COMMIT);
    assert_eq!(NETWORK_TAG_MAINNET, host::NETWORK_TAG_MAINNET);
    assert_eq!(NETWORK_TAG_TESTNET, host::NETWORK_TAG_TESTNET);
    assert_eq!(NETWORK_TAG_REGTEST, host::NETWORK_TAG_REGTEST);
    assert_eq!(MAX_ACCOUNT_ASSETS, host::MAX_ACCOUNT_ASSETS);
}

#[test]
fn compliance_address_gadget_matches_host() {
    let pk0 = [0x53u8; 32];
    let nk_commit = digest(b"address-nk-commit");
    let expected = host::address(&pk0, nk_commit);

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let pk0_target = super::targets::virtual_bytes(&mut builder);
    let nk_commit_target = builder.add_virtual_hash();
    let address_target =
        address_from_pk0_and_nk_commit(&mut builder, &pk0_target, nk_commit_target);
    builder.register_public_inputs(&address_target);
    let data = builder.build::<C>();

    let mut witness = PartialWitness::new();
    set_bytes(&mut witness, &pk0_target, &pk0);
    witness
        .set_hash_target(nk_commit_target, nk_commit)
        .expect("nk_commit witness assignment must succeed");
    let proof = data
        .prove(witness)
        .expect("address parity circuit must prove");
    assert_eq!(
        proof.public_inputs,
        expected.map(F::from_canonical_u8).to_vec()
    );
    data.verify(proof)
        .expect("address parity proof must verify");
    println!("compliance address parity: {}", hex_bytes(&expected));
}

#[test]
fn compliance_coin_identifier_matches_host() {
    let prev_ash = digest(b"coin-prev-ash");
    let template = CoinTemplate {
        recipient: Address([0x71u8; 32]),
        amount: (1u128 << 120) + 0x1234_5678,
        asset_id: digest(b"coin-asset"),
    };
    let coin_index = 3;
    let expected = host::coin_identifier(
        prev_ash,
        &template.recipient.0,
        template.asset_id,
        template.amount,
        coin_index as u32,
    );

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
    let prev_ash_target = builder.add_virtual_hash();
    let template_target = OutputTemplateTarget::new_virtual(&mut builder);
    let identifier =
        coin_identifier_target(&mut builder, prev_ash_target, template_target, coin_index);
    builder.register_public_inputs(&identifier.elements);
    let data = builder.build::<C>();

    let mut witness = PartialWitness::new();
    witness
        .set_hash_target(prev_ash_target, prev_ash)
        .expect("prev ash witness assignment must succeed");
    witness
        .set_bool_target(template_target.active, true)
        .expect("output active assignment must succeed");
    set_bytes(
        &mut witness,
        &template_target.recipient,
        &template.recipient.0,
    );
    set_u128(&mut witness, template_target.amount, template.amount);
    witness
        .set_hash_target(template_target.asset_id, template.asset_id)
        .expect("asset-id witness assignment must succeed");

    let proof = data
        .prove(witness)
        .expect("coin-identifier parity circuit must prove");
    assert_eq!(proof.public_inputs, expected.elements.to_vec());
    data.verify(proof)
        .expect("coin-identifier parity proof must verify");
    println!(
        "compliance coin.identifier parity: {:?}",
        digest_limbs(expected)
    );
}

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[test]
fn compliance_skeleton_proves_host_parity_pi_layout_and_network_binding() {
    let build_timer = Instant::now();
    let circuit =
        build_skeleton_circuit(CircuitConfig::standard_recursion_config(), Network::Testnet);
    let build_time = build_timer.elapsed();

    let (balances, _assets) = sample_balances();
    assert_eq!(
        balances.len(),
        3,
        "fixture must exercise a partial slot count"
    );
    let owner = Address([0x19u8; 32]);
    let nk_commit = digest(b"account-nk-commit");
    let current_pubkey = [0x2au8; 32];
    let next_pubkey = [0x3bu8; 32];
    let prev_state = AccountState::new(
        owner,
        nk_commit,
        balances.clone(),
        current_pubkey,
        41,
        digest(b"previous-coin-history-root"),
    )
    .expect("valid previous account state");
    let new_state = AccountState::new(
        owner,
        nk_commit,
        balances,
        next_pubkey,
        42,
        digest(b"new-coin-history-root"),
    )
    .expect("valid new account state");
    let prev_ash = host::account_state_hash(&prev_state).expect("previous ash must compute");
    let expected_new_ash = host::account_state_hash(&new_state).expect("new ash must compute");

    let templates = vec![
        CoinTemplate {
            recipient: Address([0x81u8; 32]),
            amount: 5,
            asset_id: digest(b"output-asset-0"),
        },
        CoinTemplate {
            recipient: Address([0x82u8; 32]),
            amount: (1u128 << 88) + 7,
            asset_id: digest(b"output-asset-1"),
        },
        CoinTemplate {
            recipient: Address([0x83u8; 32]),
            amount: u128::MAX - 9,
            asset_id: digest(b"output-asset-2"),
        },
    ];
    let expected_coin_ids: Vec<HashDigest> = templates
        .iter()
        .enumerate()
        .map(|(index, template)| {
            host::coin_identifier(
                prev_ash,
                &template.recipient.0,
                template.asset_id,
                template.amount,
                index as u32,
            )
        })
        .collect();
    let expected_ocr = host::merkle_root(TreeKind::CoinsRoot, &expected_coin_ids);
    let input_nullifiers_root = digest(b"pass-through-inr");
    let proof_coin_history_root = digest(b"pass-through-proof-coin-history-root");
    let nav_commitment = digest(b"pass-through-nav-commitment");
    let npk_rand = [0xa5u8; 32];
    let expected_npk_commit = host::npk_commit(&next_pubkey, &npk_rand);
    let expected_network_id = host::network_id_testnet();

    let targets = circuit.targets;
    let mut common_witness = PartialWitness::new();
    set_account_state_fixed(&mut common_witness, targets.prev_account_state, &prev_state);
    set_account_state_fixed(&mut common_witness, targets.new_account_state, &new_state);
    common_witness
        .set_hash_target(targets.prev_account_state_hash, prev_ash)
        .expect("prev ash witness assignment must succeed");
    set_output_templates(&mut common_witness, &targets.output_templates, &templates);
    set_bytes(&mut common_witness, &targets.next_pubkey, &next_pubkey);
    set_bytes(&mut common_witness, &targets.npk_rand, &npk_rand);
    set_bytes(
        &mut common_witness,
        &targets.consumed_pubkey,
        &current_pubkey,
    );
    common_witness
        .set_hash_target(
            targets.proof_data.input_nullifiers_root,
            input_nullifiers_root,
        )
        .expect("input-nullifiers-root assignment must succeed");
    common_witness
        .set_hash_target(
            targets.proof_data.coin_history_root,
            proof_coin_history_root,
        )
        .expect("proof coin-history-root assignment must succeed");
    common_witness
        .set_hash_target(targets.proof_data.nav_commitment, nav_commitment)
        .expect("nav-commitment assignment must succeed");

    let mut gapped_balance_witness = common_witness.clone();
    set_account_balances(
        &mut gapped_balance_witness,
        targets.prev_account_state,
        &prev_state,
        BalanceLayout::Gap,
    );
    set_account_balances(
        &mut gapped_balance_witness,
        targets.new_account_state,
        &new_state,
        BalanceLayout::Gap,
    );
    assert!(
        circuit.data.prove(gapped_balance_witness).is_err(),
        "a non-left-aligned active-balance layout must not prove"
    );

    let mut descending_balance_witness = common_witness.clone();
    set_account_balances(
        &mut descending_balance_witness,
        targets.prev_account_state,
        &prev_state,
        BalanceLayout::Descending,
    );
    set_account_balances(
        &mut descending_balance_witness,
        targets.new_account_state,
        &new_state,
        BalanceLayout::Descending,
    );
    assert!(
        circuit.data.prove(descending_balance_witness).is_err(),
        "a non-ascending active-balance layout must not prove"
    );

    let mut witness = common_witness;
    set_account_balances(
        &mut witness,
        targets.prev_account_state,
        &prev_state,
        BalanceLayout::Valid,
    );
    set_account_balances(
        &mut witness,
        targets.new_account_state,
        &new_state,
        BalanceLayout::Valid,
    );
    assert_eq!(
        new_state.balances.len(),
        3,
        "valid witness must retain the partial balance fixture"
    );

    let prove_timer = Instant::now();
    let proof = circuit
        .data
        .prove(witness)
        .expect("valid compliance skeleton witness must prove");
    let prove_time = prove_timer.elapsed();
    let build_and_prove = build_time + prove_time;
    assert_eq!(proof.public_inputs.len(), 40);

    let expected_digests = [
        expected_new_ash,
        expected_ocr,
        input_nullifiers_root,
        proof_coin_history_root,
        nav_commitment,
    ];
    let mut expected_public_inputs = Vec::with_capacity(40);
    for digest in expected_digests {
        expected_public_inputs.extend(digest.elements);
    }
    expected_public_inputs.extend(bytes_as_u32_le_limbs(&expected_npk_commit));
    expected_public_inputs.extend(bytes_as_u32_le_limbs(&current_pubkey));
    expected_public_inputs.extend(expected_network_id.elements);
    assert_eq!(proof.public_inputs, expected_public_inputs);

    let mut wrong_network_proof = proof.clone();
    wrong_network_proof.public_inputs[36..40].copy_from_slice(&host::network_id_regtest().elements);
    assert!(
        circuit.data.verify(wrong_network_proof).is_err(),
        "tampering testnet proof public inputs to regtest network_id must fail"
    );
    circuit
        .data
        .verify(proof)
        .expect("valid compliance skeleton proof must verify");

    println!(
        "compliance host parity: balances=3/32 ash={:?} coin.identifier[0]={:?} ocr={:?}",
        digest_limbs(expected_new_ash),
        digest_limbs(expected_coin_ids[0]),
        digest_limbs(expected_ocr)
    );
    println!(
        "compliance PI layout: 40 elements (ProofData=28, consumed_pubkey=8, network_id=4); wrong-network verification rejected"
    );
    println!(
        "compliance skeleton metrics: gates={} build={:?} prove={:?} build+prove={:?}",
        circuit.gate_count, build_time, prove_time, build_and_prove
    );
}
