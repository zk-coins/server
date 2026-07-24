use std::collections::BTreeMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use num::BigUint;
use plonky2::field::secp256k1_base::Secp256K1Base;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField, PrimeField64};
use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::CircuitConfig;
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use sha2::{Digest, Sha256};

use shared::spec_v1::{
    self as host, AccountState, Address, Coin, CoinTemplate, HashDigest, HcInput, ProofData,
    TreeKind, ZERO_HASH,
};

use crate::circuit::gadgets::biguint::WitnessBigUint;
use crate::circuit::gadgets::curve::AffinePointTarget;
use crate::circuit::gadgets::curve_types::{AffinePoint, Curve, CurveScalar, Secp256K1};
use crate::circuit::gadgets::nflog_consistency::{
    fill_consistency_slots, fill_inclusion_slots, H_MAX,
};
use crate::circuit::gadgets::nonnative::NonNativeTarget;
use crate::circuit::gadgets::u128_arith::U128Target;
use crate::{C, D, F};

use super::bindings::{
    hash_proof_data_target, input_nullifiers_root_target, nav_commitment_target, nav_root_target,
    nk_commit_target, nullifier_target,
};
use super::serialize::encode_ascii_tag_elements;
use super::skeleton::coin_identifier_target;
use super::targets::{
    AccountStateTarget, AssetIssuanceTarget, InputAuthTarget, InputCoinTarget,
    OutputTemplateTarget, ProofDataTarget, ReceivedAuthTarget, ReceivedCoinTarget,
};
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
            (BalanceLayout::Gap, 0) => usize::MAX,
            (BalanceLayout::Gap, 1) => 0,
            _ => index,
        };
        if let Some((asset_bytes, amount)) = entries.get(source_index).copied() {
            let asset_id =
                host::digest_from_bytes(asset_bytes).expect("test asset digest must be canonical");
            let active = !matches!(layout, BalanceLayout::Gap) || index == 1;
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

fn set_input_slot(
    witness: &mut PartialWitness<F>,
    coin_target: InputCoinTarget,
    auth_target: InputAuthTarget,
    input: Option<&InputFixture>,
) {
    if let Some(input) = input {
        witness
            .set_bool_target(coin_target.active, true)
            .expect("active input assignment must succeed");
        witness
            .set_hash_target(coin_target.identifier, input.coin.identifier)
            .expect("input identifier assignment must succeed");
        set_bytes(witness, &coin_target.recipient, &input.coin.recipient.0);
        set_u128(witness, coin_target.amount, input.coin.amount);
        witness
            .set_hash_target(coin_target.asset_id, input.coin.asset_id)
            .expect("input asset-id assignment must succeed");
        witness
            .set_hash_target(auth_target.creating_prev_ash, input.creating_prev_ash)
            .expect("creating prev ash assignment must succeed");
        witness
            .set_target(
                auth_target.coin_index,
                F::from_canonical_u32(input.coin_index),
            )
            .expect("coin index assignment must succeed");
    } else {
        witness
            .set_bool_target(coin_target.active, false)
            .expect("inactive input assignment must succeed");
        witness
            .set_hash_target(coin_target.identifier, ZERO_HASH)
            .expect("inactive input identifier assignment must succeed");
        set_bytes(witness, &coin_target.recipient, &[0u8; 32]);
        set_u128(witness, coin_target.amount, 0);
        witness
            .set_hash_target(coin_target.asset_id, ZERO_HASH)
            .expect("inactive input asset-id assignment must succeed");
        witness
            .set_hash_target(auth_target.creating_prev_ash, ZERO_HASH)
            .expect("inactive creating prev ash assignment must succeed");
        witness
            .set_target(auth_target.coin_index, F::ZERO)
            .expect("inactive coin index assignment must succeed");
    }
}

fn set_received_slot(
    witness: &mut PartialWitness<F>,
    coin_target: ReceivedCoinTarget,
    auth_target: &ReceivedAuthTarget,
    received: Option<&ReceivedFixture>,
    circuit: &SkeletonCircuit,
    mutation: WitnessMutation,
) {
    let active = received.is_some();
    witness
        .set_bool_target(coin_target.active, active)
        .expect("received active assignment");
    let coin = received.map(|received| &received.coin);
    let mut identifier = coin.map_or(ZERO_HASH, |coin| coin.identifier);
    if active && matches!(mutation, WitnessMutation::WrongReceivedIdentifier) {
        identifier.elements[0] += F::ONE;
    }
    witness
        .set_hash_target(coin_target.identifier, identifier)
        .expect("received identifier assignment");
    set_bytes(
        witness,
        &coin_target.recipient,
        &coin.map_or([0u8; 32], |coin| coin.recipient.0),
    );
    set_u128(
        witness,
        coin_target.amount,
        coin.map_or(0, |coin| coin.amount),
    );
    witness
        .set_hash_target(
            coin_target.asset_id,
            coin.map_or(ZERO_HASH, |coin| coin.asset_id),
        )
        .expect("received asset assignment");

    let mut creating_proof = received
        .map(|received| &received.creating_proof)
        .unwrap_or(&circuit.base_proof)
        .clone();
    if active && matches!(mutation, WitnessMutation::ForgedCreatingProof) {
        creating_proof.public_inputs[0] += F::ONE;
    }
    witness
        .set_proof_with_pis_target(&auth_target.creating_proof, &creating_proof)
        .expect("creating proof assignment");
    witness
        .set_target(
            auth_target.inclusion_leaf_index,
            F::from_canonical_u32(received.map_or(0, |received| received.leaf_index)),
        )
        .expect("received inclusion index assignment");
    witness
        .set_target(
            auth_target.inclusion_depth,
            F::from_canonical_u8(received.map_or(0, |received| received.depth)),
        )
        .expect("received inclusion depth assignment");
    for (index, &target) in auth_target.inclusion_siblings.iter().enumerate() {
        witness
            .set_hash_target(
                target,
                received.map_or(ZERO_HASH, |received| received.inclusion_siblings[index]),
            )
            .expect("received output inclusion sibling assignment");
    }
    witness
        .set_hash_target(
            auth_target.creating_prev_ash,
            received.map_or(ZERO_HASH, |received| received.creating_prev_ash),
        )
        .expect("received creating prev ash assignment");
    set_bytes(
        witness,
        &auth_target.pk_create,
        &received.map_or([0u8; 32], |received| received.pk_create),
    );
    set_bytes(
        witness,
        &auth_target.r_create,
        &received.map_or([0u8; 32], |received| received.r_create),
    );
    set_point(
        witness,
        &auth_target.r_prime_create,
        received.map_or(Secp256K1::GENERATOR_AFFINE, |received| {
            received.r_prime_create
        }),
    );
    for (index, &target) in auth_target.creating_nav_inclusion.iter().enumerate() {
        witness
            .set_hash_target(
                target,
                received.map_or(ZERO_HASH, |received| received.nav_inclusion[index]),
            )
            .expect("received NAV inclusion assignment");
    }
    witness
        .set_target(
            auth_target.pos_create,
            F::from_canonical_u64(received.map_or(0, |received| {
                if matches!(mutation, WitnessMutation::CreatingPositionOutOfRange) {
                    2
                } else {
                    received.pos_create
                }
            })),
        )
        .expect("received creating position assignment");
    let creating_nav = received.map_or(
        host::Nav {
            size: 0,
            mth: host::nflog_empty(),
        },
        |received| received.creating_nav,
    );
    witness
        .set_target(
            auth_target.creating_nav_opening.nav.size,
            F::from_canonical_u64(creating_nav.size),
        )
        .expect("received creating NAV size assignment");
    witness
        .set_hash_target(auth_target.creating_nav_opening.nav.mth, creating_nav.mth)
        .expect("received creating NAV mth assignment");
    set_bytes(
        witness,
        &auth_target.creating_nav_opening.nav_rand,
        &received.map_or([0u8; 32], |received| received.creating_nav_rand),
    );
    for (index, &target) in auth_target.creating_nav_consistency.iter().enumerate() {
        witness
            .set_hash_target(
                target,
                received.map_or(ZERO_HASH, |received| received.nav_consistency[index]),
            )
            .expect("received NAV consistency assignment");
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

fn hex_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn field_bytes<FF: PrimeField>(value: FF) -> [u8; 32] {
    let encoded = value.to_canonical_biguint().to_bytes_be();
    assert!(encoded.len() <= 32, "secp256k1 field value fits 32 bytes");
    let mut bytes = [0u8; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    bytes
}

fn is_odd<FF: PrimeField>(value: FF) -> bool {
    (&value.to_canonical_biguint() & BigUint::from(1u8)) == BigUint::from(1u8)
}

fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
    let tag_hash = Sha256::digest(tag);
    let mut preimage = Vec::with_capacity(64 + message.len());
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(&tag_hash);
    preimage.extend_from_slice(message);
    Sha256::digest(preimage).into()
}

fn deterministic_secret(label: &[u8]) -> Secp256K1Scalar {
    let bytes = Sha256::digest(label);
    let scalar = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&bytes));
    assert!(scalar.is_nonzero(), "deterministic secret must be non-zero");
    scalar
}

fn receive_owner() -> Address {
    let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/compliance-receive/receiver-nk").into();
    let (_, _, current_pubkey) = normalized_key(deterministic_secret(
        b"zkCoins/v1/compliance-receive/receiver-spend-key-0",
    ));
    Address(host::address(&current_pubkey, host::nk_commit(&nk)))
}

fn normalized_key(secret: Secp256K1Scalar) -> (Secp256K1Scalar, AffinePoint<Secp256K1>, [u8; 32]) {
    let mut normalized_secret = secret;
    let mut public = (CurveScalar(normalized_secret) * Secp256K1::GENERATOR_PROJECTIVE).to_affine();
    assert!(!public.zero, "non-zero secret produces a public key");
    if is_odd(public.y) {
        normalized_secret = -normalized_secret;
        public = -public;
    }
    assert!(!is_odd(public.y), "BIP-340 public key must have even y");
    (normalized_secret, public, field_bytes(public.x))
}

#[derive(Clone)]
struct TransitionSignature {
    rx: Secp256K1Base,
    s: Secp256K1Scalar,
    r_prime: AffinePoint<Secp256K1>,
}

fn sign_transition(
    secret: Secp256K1Scalar,
    public: AffinePoint<Secp256K1>,
    h_proof_data: &[u8; 32],
) -> TransitionSignature {
    let pk_bytes = field_bytes(public.x);
    for nonce_counter in 1u64.. {
        let mut k_prime = Secp256K1Scalar::from_canonical_u64(nonce_counter);
        let mut r_prime = (CurveScalar(k_prime) * Secp256K1::GENERATOR_PROJECTIVE).to_affine();
        if is_odd(r_prime.y) {
            k_prime = -k_prime;
            r_prime = -r_prime;
        }

        let r_prime_bytes = field_bytes(r_prime.x);
        let mut tweak_preimage = Vec::with_capacity(64);
        tweak_preimage.extend_from_slice(&r_prime_bytes);
        tweak_preimage.extend_from_slice(h_proof_data);
        let tweak_bytes: [u8; 32] = Sha256::digest(tweak_preimage).into();
        let tweak_integer = BigUint::from_bytes_be(&tweak_bytes);
        if tweak_integer >= Secp256K1Scalar::order() {
            continue;
        }
        let tweak = Secp256K1Scalar::from_noncanonical_biguint(tweak_integer);
        let r = (r_prime + (CurveScalar(tweak) * Secp256K1::GENERATOR_PROJECTIVE).to_affine())
            .to_affine();
        if r.zero || is_odd(r.y) {
            continue;
        }

        let rx_bytes = field_bytes(r.x);
        let mut challenge_preimage = Vec::with_capacity(64 + M_STATE_TESTNET.len());
        challenge_preimage.extend_from_slice(&rx_bytes);
        challenge_preimage.extend_from_slice(&pk_bytes);
        challenge_preimage.extend_from_slice(M_STATE_TESTNET);
        let challenge_bytes = tagged_hash(b"BIP0340/challenge", &challenge_preimage);
        let challenge =
            Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&challenge_bytes));
        let s = k_prime + tweak + challenge * secret;
        if s.is_zero() {
            continue;
        }

        let candidate = ((CurveScalar(s) * Secp256K1::GENERATOR_PROJECTIVE)
            + (CurveScalar(challenge) * (-public).to_projective()))
        .to_affine();
        assert_eq!(candidate, r, "fresh host signature must satisfy BIP-340");
        return TransitionSignature {
            rx: r.x,
            s,
            r_prime,
        };
    }
    unreachable!("deterministic nonce redraw must eventually succeed")
}

fn set_nonnative<FF: PrimeField>(
    witness: &mut PartialWitness<F>,
    target: &NonNativeTarget<FF>,
    value: FF,
) {
    witness
        .set_biguint_target(&target.value, &value.to_canonical_biguint())
        .expect("set nonnative witness");
}

fn set_point(
    witness: &mut PartialWitness<F>,
    target: &AffinePointTarget<Secp256K1>,
    point: AffinePoint<Secp256K1>,
) {
    set_nonnative(witness, &target.x, point.x);
    set_nonnative(witness, &target.y, point.y);
}

#[derive(Clone)]
struct InputFixture {
    coin: Coin,
    creating_prev_ash: HashDigest,
    coin_index: u32,
}

#[derive(Clone)]
struct ReceivedFixture {
    coin: Coin,
    creating_proof: ProofWithPublicInputs<F, C, D>,
    leaf_index: u32,
    depth: u8,
    inclusion_siblings: [HashDigest; MAX_OUTPUT_MERKLE_DEPTH],
    creating_prev_ash: HashDigest,
    pk_create: [u8; 32],
    r_create: [u8; 32],
    r_prime_create: AffinePoint<Secp256K1>,
    nav_inclusion: [HashDigest; H_MAX],
    pos_create: u64,
    creating_nav: host::Nav,
    creating_nav_rand: [u8; 32],
    nav_consistency: [HashDigest; 2 * H_MAX],
}

#[derive(Clone)]
struct IssuanceFixture {
    present: bool,
    asset_id: HashDigest,
    creator_pubkey: [u8; 32],
    issuance_version: u8,
    name_hash: [u8; 32],
    decimals: u8,
    amount: u128,
    terms_hash: HashDigest,
    cap_total: u128,
    terms_salt: [u8; 32],
}

fn set_issuance(
    witness: &mut PartialWitness<F>,
    target: AssetIssuanceTarget,
    issuance: &IssuanceFixture,
) {
    witness
        .set_bool_target(target.present, issuance.present)
        .expect("issuance presence assignment");
    witness
        .set_hash_target(target.asset_id, issuance.asset_id)
        .expect("issuance asset assignment");
    set_bytes(witness, &target.creator_pubkey, &issuance.creator_pubkey);
    witness
        .set_target(
            target.issuance_version,
            F::from_canonical_u8(issuance.issuance_version),
        )
        .expect("issuance version assignment");
    set_bytes(witness, &target.name_hash, &issuance.name_hash);
    witness
        .set_target(target.decimals, F::from_canonical_u8(issuance.decimals))
        .expect("decimals assignment");
    set_u128(witness, target.amount, issuance.amount);
    witness
        .set_hash_target(target.terms_hash, issuance.terms_hash)
        .expect("terms hash assignment");
    set_u128(witness, target.cap_total, issuance.cap_total);
    set_bytes(witness, &target.terms_salt, &issuance.terms_salt);
}

#[derive(Clone)]
struct ComplianceFixture {
    prev_state: AccountState,
    new_state: AccountState,
    prev_ash: HashDigest,
    templates: Vec<CoinTemplate>,
    expected_coin_ids: Vec<HashDigest>,
    inputs: Vec<InputFixture>,
    received: Vec<ReceivedFixture>,
    issuance: IssuanceFixture,
    history_paths: Vec<Vec<HashDigest>>,
    nk: [u8; 32],
    next_pubkey: [u8; 32],
    npk_rand: [u8; 32],
    proof_data: ProofData,
    signature: TransitionSignature,
    wrong_pubkey: [u8; 32],
    is_account_update: bool,
    nav: host::Nav,
    nav_rand: [u8; 32],
    prev_nav: host::Nav,
    prev_nav_rand: [u8; 32],
    nav_consistency: [HashDigest; 2 * H_MAX],
    prev_nullifier_pk: [u8; 32],
    prev_nullifier_r: [u8; 32],
    prev_nullifier_r_prime: AffinePoint<Secp256K1>,
    prev_nullifier_inclusion: [HashDigest; H_MAX],
    prev_nullifier_pos: u64,
}

#[derive(Clone, Copy)]
enum MintCase {
    ValidV2,
    BadVersion,
    BadCreator,
    BadAssetId,
    BadCap,
    BadGenesisCounter,
    BadGenesisKey,
}

impl ComplianceFixture {
    fn new() -> Self {
        Self::new_with_history_fault(false, false)
    }

    fn new_with_replayed_self_output(replay_self_output: bool) -> Self {
        Self::new_with_history_fault(replay_self_output, false)
    }

    fn new_with_absent_spend() -> Self {
        Self::new_with_history_fault(false, true)
    }

    fn without_mint() -> Self {
        Self::new()
    }

    fn new_with_history_fault(replay_self_output: bool, absent_first_input: bool) -> Self {
        let genesis = Self::genesis_fixture();
        let prev_state = genesis.new_state.clone();
        let prev_ash = genesis.proof_data.new_account_state_hash;
        let owner = prev_state.owner;
        let asset_id = genesis.issuance.asset_id;
        let input = InputFixture {
            coin: Coin {
                identifier: genesis.expected_coin_ids[0],
                recipient: owner,
                amount: 100,
                asset_id,
            },
            creating_prev_ash: genesis.prev_ash,
            coin_index: 0,
        };
        let inputs = vec![input.clone()];
        let templates = vec![
            CoinTemplate {
                recipient: owner,
                amount: 70,
                asset_id,
            },
            CoinTemplate {
                recipient: Address([0x82u8; 32]),
                amount: 30,
                asset_id,
            },
        ];
        let expected_coin_ids: Vec<_> = templates
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

        let mut history = host::CoinHistTree::new();
        history
            .admit(host::digest_to_bytes(&input.coin.identifier))
            .expect("genesis self output admission");
        assert_eq!(history.root(), prev_state.coin_history_root);
        let input_key = host::digest_to_bytes(&input.coin.identifier);
        let mut input_path = history.prove(input_key).siblings;
        if absent_first_input {
            input_path[0].elements[0] += F::ONE;
        }
        history.spend(input_key).expect("spend genesis coin");
        let output_key = host::digest_to_bytes(&expected_coin_ids[0]);
        let mut output_path = history.prove(output_key).siblings;
        if replay_self_output {
            output_path[0].elements[0] += F::ONE;
        }
        history.admit(output_key).expect("admit update change");
        let mut history_paths = vec![input_path];
        history_paths.resize(MAX_TX_INPUTS, vec![ZERO_HASH; 256]);
        history_paths.push(output_path);
        history_paths.push(vec![ZERO_HASH; 256]);
        history_paths.resize(MAX_HISTORY_UPDATES, vec![ZERO_HASH; 256]);

        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), 70);
        let (secret, public, current_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-1",
        ));
        assert_eq!(current_pubkey, prev_state.current_pubkey);
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-2",
        ));
        let (_, _, wrong_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/wrong-spend-key",
        ));
        let new_state = AccountState::new(
            owner,
            prev_state.nk_commit,
            balances,
            next_pubkey,
            2,
            history.root(),
        )
        .expect("update state");

        let prefix_entry = host::NfLogEntry {
            pk: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-pk").into(),
            r: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-r").into(),
        };
        let entry = host::NfLogEntry {
            pk: genesis.prev_state.current_pubkey,
            r: field_bytes(genesis.signature.rx),
        };
        let entries = [prefix_entry, entry];
        let nav = host::Nav {
            size: 2,
            mth: host::nflog_mth(&entries),
        };
        let nav_rand = [0x3cu8; 32];
        let npk_rand = [0xa5u8; 32];
        let issuance = IssuanceFixture {
            present: false,
            asset_id: ZERO_HASH,
            creator_pubkey: [0u8; 32],
            issuance_version: 0,
            name_hash: [0u8; 32],
            decimals: 0,
            amount: 0,
            terms_hash: ZERO_HASH,
            cap_total: 0,
            terms_salt: [0u8; 32],
        };
        let proof_data = ProofData {
            new_account_state_hash: host::account_state_hash(&new_state).unwrap(),
            output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &expected_coin_ids),
            input_nullifiers_root: host::merkle_root(
                TreeKind::NullifiersRoot,
                &[host::nullifier(&genesis.nk, input.coin.identifier)],
            ),
            coin_history_root: new_state.coin_history_root,
            nav_commitment: host::nav_commitment(nav.root(), &nav_rand),
            npk_commit: host::npk_commit(&next_pubkey, &npk_rand),
        };
        let signature = sign_transition(
            secret,
            public,
            &host::hash_proof_data(&host::serialize_proof_data(&proof_data)),
        );
        Self {
            prev_state,
            new_state,
            prev_ash,
            templates,
            expected_coin_ids,
            inputs,
            received: Vec::new(),
            issuance,
            history_paths,
            nk: genesis.nk,
            next_pubkey,
            npk_rand,
            proof_data,
            signature,
            wrong_pubkey,
            is_account_update: true,
            nav,
            nav_rand,
            prev_nav: genesis.nav,
            prev_nav_rand: genesis.nav_rand,
            nav_consistency: fill_consistency_slots(
                &host::consistency_proof(1, &entries).unwrap(),
                1,
                2,
            ),
            prev_nullifier_pk: entry.pk,
            prev_nullifier_r: entry.r,
            prev_nullifier_r_prime: genesis.signature.r_prime,
            prev_nullifier_inclusion: fill_inclusion_slots(
                &host::inclusion_path(1, &entries).unwrap(),
            ),
            prev_nullifier_pos: 1,
        }
    }

    fn receive_prefix_entry() -> host::NfLogEntry {
        host::NfLogEntry {
            pk: Sha256::digest(b"zkCoins/v1/compliance-receive/creating-prefix-pk").into(),
            r: Sha256::digest(b"zkCoins/v1/compliance-receive/creating-prefix-r").into(),
        }
    }

    fn creating_receive_fixture(recipient: Address) -> Self {
        let mut fixture = Self::mint_case(MintCase::ValidV2);
        fixture.templates[0].recipient = recipient;
        fixture.expected_coin_ids[0] = host::coin_identifier(
            fixture.prev_ash,
            &recipient.0,
            fixture.templates[0].asset_id,
            fixture.templates[0].amount,
            0,
        );
        fixture.proof_data.output_coins_root =
            host::merkle_root(TreeKind::CoinsRoot, &fixture.expected_coin_ids);
        let prefix = Self::receive_prefix_entry();
        fixture.nav = host::Nav {
            size: 1,
            mth: host::nflog_mth(&[prefix]),
        };
        fixture.proof_data.nav_commitment =
            host::nav_commitment(fixture.nav.root(), &fixture.nav_rand);
        let (secret, public, _) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-mint-case/creator",
        ));
        fixture.signature = sign_transition(
            secret,
            public,
            &host::hash_proof_data(&host::serialize_proof_data(&fixture.proof_data)),
        );
        fixture
    }

    fn receive_fixture(
        creating: &ComplianceFixture,
        creating_proof: ProofWithPublicInputs<F, C, D>,
    ) -> Self {
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/compliance-receive/receiver-nk").into();
        let nk_commit = host::nk_commit(&nk);
        let (secret, public, current_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-receive/receiver-spend-key-0",
        ));
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-receive/receiver-spend-key-1",
        ));
        let (_, _, wrong_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-receive/receiver-wrong-key",
        ));
        let owner = Address(host::address(&current_pubkey, nk_commit));
        assert_eq!(
            creating.templates[0].recipient, owner,
            "creating proof must address its output to the receiver"
        );
        let coin = Coin {
            identifier: creating.expected_coin_ids[0],
            recipient: owner,
            amount: creating.templates[0].amount,
            asset_id: creating.templates[0].asset_id,
        };
        let prev_state = AccountState::new(
            owner,
            nk_commit,
            BTreeMap::new(),
            current_pubkey,
            0,
            host::coinhist_empty_root(),
        )
        .expect("receiver canonical empty state");
        let prev_ash = host::account_state_hash(&prev_state).expect("receiver previous ash");

        let mut history = host::CoinHistTree::new();
        let received_path = history
            .prove(host::digest_to_bytes(&coin.identifier))
            .siblings;
        history
            .admit(host::digest_to_bytes(&coin.identifier))
            .expect("receiver admits creating coin");
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&coin.asset_id), coin.amount);
        let new_state =
            AccountState::new(owner, nk_commit, balances, next_pubkey, 1, history.root())
                .expect("receiver credited state");

        let prefix = Self::receive_prefix_entry();
        let creating_nullifier = host::NfLogEntry {
            pk: creating.prev_state.current_pubkey,
            r: field_bytes(creating.signature.rx),
        };
        let entries = [prefix, creating_nullifier];
        assert_eq!(
            creating.nav.mth,
            host::nflog_mth(&entries[..1]),
            "creating proof NAV must be the receiver NAV prefix"
        );
        let nav = host::Nav {
            size: 2,
            mth: host::nflog_mth(&entries),
        };
        let nav_rand = [0x8du8; 32];
        let npk_rand = [0x6eu8; 32];
        let proof_data = ProofData {
            new_account_state_hash: host::account_state_hash(&new_state).expect("receiver new ash"),
            output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &[]),
            input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
            coin_history_root: new_state.coin_history_root,
            nav_commitment: host::nav_commitment(nav.root(), &nav_rand),
            npk_commit: host::npk_commit(&next_pubkey, &npk_rand),
        };
        let signature = sign_transition(
            secret,
            public,
            &host::hash_proof_data(&host::serialize_proof_data(&proof_data)),
        );
        let mut history_paths = vec![vec![ZERO_HASH; 256]; MAX_TX_INPUTS + MAX_TX_OUTPUTS];
        history_paths.push(received_path);
        history_paths.resize(MAX_HISTORY_UPDATES, vec![ZERO_HASH; 256]);
        let received = ReceivedFixture {
            coin,
            creating_proof,
            leaf_index: 0,
            depth: 0,
            inclusion_siblings: [ZERO_HASH; MAX_OUTPUT_MERKLE_DEPTH],
            creating_prev_ash: creating.prev_ash,
            pk_create: creating_nullifier.pk,
            r_create: creating_nullifier.r,
            r_prime_create: creating.signature.r_prime,
            nav_inclusion: fill_inclusion_slots(
                &host::inclusion_path(1, &entries).expect("creating nullifier inclusion"),
            ),
            pos_create: 1,
            creating_nav: creating.nav,
            creating_nav_rand: creating.nav_rand,
            nav_consistency: fill_consistency_slots(
                &host::consistency_proof(1, &entries).expect("creating NAV consistency"),
                1,
                2,
            ),
        };
        let issuance = IssuanceFixture {
            present: false,
            asset_id: ZERO_HASH,
            creator_pubkey: [0u8; 32],
            issuance_version: 0,
            name_hash: [0u8; 32],
            decimals: 0,
            amount: 0,
            terms_hash: ZERO_HASH,
            cap_total: 0,
            terms_salt: [0u8; 32],
        };
        Self {
            prev_state,
            new_state,
            prev_ash,
            templates: Vec::new(),
            expected_coin_ids: Vec::new(),
            inputs: Vec::new(),
            received: vec![received],
            issuance,
            history_paths,
            nk,
            next_pubkey,
            npk_rand,
            proof_data,
            signature,
            wrong_pubkey,
            is_account_update: false,
            nav,
            nav_rand,
            prev_nav: host::Nav {
                size: 0,
                mth: host::nflog_empty(),
            },
            prev_nav_rand: [0u8; 32],
            nav_consistency: [ZERO_HASH; 2 * H_MAX],
            prev_nullifier_pk: [0u8; 32],
            prev_nullifier_r: [0u8; 32],
            prev_nullifier_r_prime: Secp256K1::GENERATOR_AFFINE,
            prev_nullifier_inclusion: [ZERO_HASH; H_MAX],
            prev_nullifier_pos: 0,
        }
    }

    fn resign_receive(&mut self) {
        self.proof_data.new_account_state_hash =
            host::account_state_hash(&self.new_state).expect("receiver new ash");
        self.proof_data.coin_history_root = self.new_state.coin_history_root;
        self.proof_data.nav_commitment = host::nav_commitment(self.nav.root(), &self.nav_rand);
        let (secret, public, _) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-receive/receiver-spend-key-0",
        ));
        self.signature = sign_transition(
            secret,
            public,
            &host::hash_proof_data(&host::serialize_proof_data(&self.proof_data)),
        );
    }

    fn rebuild_receive_nav(&mut self, prefix: host::NfLogEntry) {
        let received = &mut self.received[0];
        let creating_entry = host::NfLogEntry {
            pk: received.pk_create,
            r: received.r_create,
        };
        let entries = [prefix, creating_entry];
        self.nav = host::Nav {
            size: 2,
            mth: host::nflog_mth(&entries),
        };
        received.nav_inclusion = fill_inclusion_slots(
            &host::inclusion_path(1, &entries).expect("mutated creating inclusion"),
        );
        received.nav_consistency = fill_consistency_slots(
            &host::consistency_proof(1, &entries).expect("mutated creating consistency"),
            1,
            2,
        );
        self.resign_receive();
    }

    fn receive_non_prefix_case(mut self) -> Self {
        let different_prefix = host::NfLogEntry {
            pk: Sha256::digest(b"zkCoins/v1/compliance-receive/non-prefix-pk").into(),
            r: Sha256::digest(b"zkCoins/v1/compliance-receive/non-prefix-r").into(),
        };
        self.rebuild_receive_nav(different_prefix);
        self
    }

    fn receive_wrong_pk_case(mut self) -> Self {
        self.received[0].pk_create =
            Sha256::digest(b"zkCoins/v1/compliance-receive/wrong-create-pk").into();
        self.rebuild_receive_nav(Self::receive_prefix_entry());
        self
    }

    fn receive_wrong_r_case(mut self) -> Self {
        self.received[0].r_create =
            Sha256::digest(b"zkCoins/v1/compliance-receive/wrong-create-r").into();
        self.rebuild_receive_nav(Self::receive_prefix_entry());
        self
    }

    fn genesis_fixture() -> Self {
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/compliance-chain/nk").into();
        let nk_commit = host::nk_commit(&nk);
        let (secret, public, current_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-0",
        ));
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-1",
        ));
        let (_, _, wrong_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/wrong-spend-key",
        ));
        let owner = Address(host::address(&current_pubkey, nk_commit));
        let name_hash: [u8; 32] = Sha256::digest(b"Recursive Fixture Asset").into();
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &current_pubkey, &name_hash, 2, 1);
        let issuance = IssuanceFixture {
            present: true,
            asset_id,
            creator_pubkey: current_pubkey,
            issuance_version: 1,
            name_hash,
            decimals: 2,
            amount: 100,
            terms_hash: host::terms_hash_v1(asset_id, 1),
            cap_total: 0,
            terms_salt: [0u8; 32],
        };
        let prev_state = AccountState::new(
            owner,
            nk_commit,
            BTreeMap::new(),
            current_pubkey,
            0,
            host::coinhist_empty_root(),
        )
        .unwrap();
        let prev_ash = host::account_state_hash(&prev_state).unwrap();
        let templates = vec![CoinTemplate {
            recipient: owner,
            amount: 100,
            asset_id,
        }];
        let expected_coin_ids = vec![host::coin_identifier(prev_ash, &owner.0, asset_id, 100, 0)];
        let mut history = host::CoinHistTree::new();
        let output_path = history
            .prove(host::digest_to_bytes(&expected_coin_ids[0]))
            .siblings;
        history
            .admit(host::digest_to_bytes(&expected_coin_ids[0]))
            .unwrap();
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), 100);
        let new_state =
            AccountState::new(owner, nk_commit, balances, next_pubkey, 1, history.root()).unwrap();
        let mut history_paths = vec![vec![ZERO_HASH; 256]; MAX_TX_INPUTS];
        history_paths.push(output_path);
        history_paths.resize(MAX_HISTORY_UPDATES, vec![ZERO_HASH; 256]);
        let prefix_entry = host::NfLogEntry {
            pk: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-pk").into(),
            r: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-r").into(),
        };
        let nav = host::Nav {
            size: 1,
            mth: host::nflog_mth(&[prefix_entry]),
        };
        let nav_rand = [0x2bu8; 32];
        let npk_rand = [0x4du8; 32];
        let proof_data = ProofData {
            new_account_state_hash: host::account_state_hash(&new_state).unwrap(),
            output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &expected_coin_ids),
            input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
            coin_history_root: new_state.coin_history_root,
            nav_commitment: host::nav_commitment(nav.root(), &nav_rand),
            npk_commit: host::npk_commit(&next_pubkey, &npk_rand),
        };
        let signature = sign_transition(
            secret,
            public,
            &host::hash_proof_data(&host::serialize_proof_data(&proof_data)),
        );
        Self {
            prev_state,
            new_state,
            prev_ash,
            templates,
            expected_coin_ids,
            inputs: vec![],
            received: Vec::new(),
            issuance,
            history_paths,
            nk,
            next_pubkey,
            npk_rand,
            proof_data,
            signature,
            wrong_pubkey,
            is_account_update: false,
            nav,
            nav_rand,
            prev_nav: host::Nav {
                size: 0,
                mth: host::nflog_empty(),
            },
            prev_nav_rand: [0u8; 32],
            nav_consistency: [ZERO_HASH; 2 * H_MAX],
            prev_nullifier_pk: [0u8; 32],
            prev_nullifier_r: [0u8; 32],
            prev_nullifier_r_prime: Secp256K1::GENERATOR_AFFINE,
            prev_nullifier_inclusion: [ZERO_HASH; H_MAX],
            prev_nullifier_pos: 0,
        }
    }

    fn resign_update(&mut self) {
        self.proof_data.nav_commitment = host::nav_commitment(self.nav.root(), &self.nav_rand);
        let (secret, public, _) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-1",
        ));
        self.signature = sign_transition(
            secret,
            public,
            &host::hash_proof_data(&host::serialize_proof_data(&self.proof_data)),
        );
    }

    fn non_prefix_case() -> Self {
        let mut fixture = Self::new();
        let different_prefix = host::NfLogEntry {
            pk: Sha256::digest(b"zkCoins/v1/compliance-chain/non-prefix-pk").into(),
            r: Sha256::digest(b"zkCoins/v1/compliance-chain/non-prefix-r").into(),
        };
        let predecessor = host::NfLogEntry {
            pk: fixture.prev_nullifier_pk,
            r: fixture.prev_nullifier_r,
        };
        let entries = [different_prefix, predecessor];
        fixture.nav.mth = host::nflog_mth(&entries);
        fixture.nav_consistency =
            fill_consistency_slots(&host::consistency_proof(1, &entries).unwrap(), 1, 2);
        fixture.prev_nullifier_inclusion =
            fill_inclusion_slots(&host::inclusion_path(1, &entries).unwrap());
        fixture.resign_update();
        fixture
    }

    fn wrong_prev_pk_case() -> Self {
        let mut fixture = Self::new();
        fixture.prev_nullifier_pk =
            Sha256::digest(b"zkCoins/v1/compliance-chain/substituted-prev-pk").into();
        let prefix = host::NfLogEntry {
            pk: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-pk").into(),
            r: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-r").into(),
        };
        let substituted = host::NfLogEntry {
            pk: fixture.prev_nullifier_pk,
            r: fixture.prev_nullifier_r,
        };
        let entries = [prefix, substituted];
        fixture.nav.mth = host::nflog_mth(&entries);
        fixture.nav_consistency =
            fill_consistency_slots(&host::consistency_proof(1, &entries).unwrap(), 1, 2);
        fixture.prev_nullifier_inclusion =
            fill_inclusion_slots(&host::inclusion_path(1, &entries).unwrap());
        fixture.resign_update();
        fixture
    }

    fn mint_case(case: MintCase) -> Self {
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/compliance-mint-case/nk").into();
        let nk_commit = host::nk_commit(&nk);
        let (creator_secret, creator_public, creator_pubkey) = normalized_key(
            deterministic_secret(b"zkCoins/v1/compliance-mint-case/creator"),
        );
        let (other_secret, other_public, other_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-mint-case/other",
        ));
        let use_other_key = matches!(case, MintCase::BadGenesisKey);
        let (signing_secret, signing_public, current_pubkey) = if use_other_key {
            (other_secret, other_public, other_pubkey)
        } else {
            (creator_secret, creator_public, creator_pubkey)
        };
        let owner = Address(host::address(&creator_pubkey, nk_commit));
        let next_pubkey: [u8; 32] = Sha256::digest(b"zkCoins/v1/compliance-mint-case/next").into();
        let npk_rand = [0x5au8; 32];
        let name_hash: [u8; 32] = Sha256::digest(b"Fixture Mint V2").into();
        let terms_salt: [u8; 32] = Sha256::digest(b"Fixture Mint V2 salt").into();
        let amount = 25u128;
        let cap_total = if matches!(case, MintCase::BadCap) {
            amount - 1
        } else {
            100
        };
        let issuance_version = if matches!(case, MintCase::BadVersion) {
            3
        } else {
            2
        };
        let mut witnessed_creator = creator_pubkey;
        if matches!(case, MintCase::BadCreator) {
            witnessed_creator = other_pubkey;
        }
        let mut asset_id = host::asset_id_v2(
            host::GENESIS_TAG,
            &witnessed_creator,
            &name_hash,
            4,
            issuance_version,
            cap_total,
            &terms_salt,
        );
        if matches!(case, MintCase::BadAssetId) {
            asset_id.elements[0] += F::ONE;
        }
        let terms_hash = host::terms_hash_v2(asset_id, issuance_version, cap_total, &terms_salt);
        let issuance = IssuanceFixture {
            present: true,
            asset_id,
            creator_pubkey: witnessed_creator,
            issuance_version,
            name_hash,
            decimals: 4,
            amount,
            terms_hash,
            cap_total,
            terms_salt,
        };
        let counter = if matches!(case, MintCase::BadGenesisCounter) {
            1
        } else {
            0
        };
        let balances = BTreeMap::new();
        let empty_history = host::coinhist_empty_root();
        let prev_state = AccountState::new(
            owner,
            nk_commit,
            balances.clone(),
            current_pubkey,
            counter,
            empty_history,
        )
        .expect("mint previous state");
        let prev_ash = host::account_state_hash(&prev_state).expect("mint previous ash");
        let new_state = AccountState::new(
            owner,
            nk_commit,
            balances,
            next_pubkey,
            counter + 1,
            empty_history,
        )
        .expect("mint new state");
        let templates = vec![CoinTemplate {
            recipient: Address([0xb7u8; 32]),
            amount,
            asset_id,
        }];
        let expected_coin_ids = vec![host::coin_identifier(
            prev_ash,
            &templates[0].recipient.0,
            asset_id,
            amount,
            0,
        )];
        let output_coins_root = host::merkle_root(TreeKind::CoinsRoot, &expected_coin_ids);
        let input_nullifiers_root = host::merkle_root(TreeKind::NullifiersRoot, &[]);
        let nav = host::Nav {
            size: 0,
            mth: host::nflog_empty(),
        };
        let nav_rand = [0x69u8; 32];
        let proof_data = ProofData {
            new_account_state_hash: host::account_state_hash(&new_state).expect("mint new ash"),
            output_coins_root,
            input_nullifiers_root,
            coin_history_root: empty_history,
            nav_commitment: host::nav_commitment(nav.root(), &nav_rand),
            npk_commit: host::npk_commit(&next_pubkey, &npk_rand),
        };
        let signature = sign_transition(
            signing_secret,
            signing_public,
            &host::hash_proof_data(&host::serialize_proof_data(&proof_data)),
        );
        Self {
            prev_state,
            new_state,
            prev_ash,
            templates,
            expected_coin_ids,
            inputs: Vec::new(),
            received: Vec::new(),
            issuance,
            history_paths: vec![vec![ZERO_HASH; 256]; MAX_HISTORY_UPDATES],
            nk,
            next_pubkey,
            npk_rand,
            proof_data,
            signature,
            wrong_pubkey: other_pubkey,
            is_account_update: false,
            nav,
            nav_rand,
            prev_nav: nav,
            prev_nav_rand: [0u8; 32],
            nav_consistency: [ZERO_HASH; 2 * H_MAX],
            prev_nullifier_pk: [0u8; 32],
            prev_nullifier_r: [0u8; 32],
            prev_nullifier_r_prime: Secp256K1::GENERATOR_AFFINE,
            prev_nullifier_inclusion: [ZERO_HASH; H_MAX],
            prev_nullifier_pos: 0,
        }
    }

    fn witness(
        &self,
        circuit: &SkeletonCircuit,
        layout: BalanceLayout,
        mutation: WitnessMutation,
    ) -> PartialWitness<F> {
        let targets = &circuit.targets;
        let mut witness = PartialWitness::new();
        let mut prev_state = self.prev_state.clone();
        let mut new_state = self.new_state.clone();
        if matches!(mutation, WitnessMutation::WrongPublicKey) {
            prev_state.current_pubkey = self.wrong_pubkey;
        }
        if matches!(mutation, WitnessMutation::WrongNewBalance) {
            let first = new_state
                .balances
                .values_mut()
                .next()
                .expect("fixture has balances");
            *first += 1;
        }
        set_account_state_fixed(&mut witness, targets.prev_account_state, &prev_state);
        set_account_state_fixed(&mut witness, targets.new_account_state, &new_state);
        set_account_balances(
            &mut witness,
            targets.prev_account_state,
            &prev_state,
            layout,
        );
        set_account_balances(&mut witness, targets.new_account_state, &new_state, layout);
        witness
            .set_hash_target(targets.prev_account_state_hash, self.prev_ash)
            .expect("prev ash witness assignment must succeed");

        let mut witnessed_nk = self.nk;
        if matches!(mutation, WitnessMutation::WrongNk) {
            witnessed_nk[0] ^= 1;
        }
        set_bytes(&mut witness, &targets.nk, &witnessed_nk);

        let wrong_input = if matches!(mutation, WitnessMutation::WrongInputIdentifier) {
            let mut input = self.inputs[0].clone();
            input.coin.identifier.elements[0] += F::ONE;
            Some(input)
        } else if matches!(mutation, WitnessMutation::BalanceUnderflow) {
            let mut input = self.inputs[0].clone();
            input.coin.amount = 111;
            input.coin.identifier = host::coin_identifier(
                input.creating_prev_ash,
                &input.coin.recipient.0,
                input.coin.asset_id,
                input.coin.amount,
                input.coin_index,
            );
            Some(input)
        } else {
            None
        };
        for index in 0..MAX_TX_INPUTS {
            let source = if index == 0 {
                wrong_input.as_ref().or_else(|| self.inputs.first())
            } else if matches!(mutation, WitnessMutation::DuplicateNullifier) && index == 1 {
                self.inputs.first()
            } else {
                self.inputs.get(index)
            };
            set_input_slot(
                &mut witness,
                targets.input_coins[index],
                targets.input_auth[index],
                source,
            );
        }
        for index in 0..MAX_RX_COINS {
            set_received_slot(
                &mut witness,
                targets.received_coins[index],
                &targets.received_auth[index],
                self.received.get(index),
                circuit,
                mutation,
            );
        }

        let mut templates = self.templates.clone();
        if matches!(mutation, WitnessMutation::ConservationViolation) {
            templates[1].amount = 31;
        }
        if matches!(mutation, WitnessMutation::ConservationWraparound) {
            templates[0].recipient = Address([0x91u8; 32]);
            templates[0].amount = u128::MAX;
            templates[1].amount = 2;
            templates[1].asset_id = templates[0].asset_id;
        }
        set_output_templates(&mut witness, &targets.output_templates, &templates);
        set_issuance(&mut witness, targets.asset_issuance, &self.issuance);
        for (path_target, siblings) in targets.history_update_paths.iter().zip(&self.history_paths)
        {
            assert_eq!(siblings.len(), 256);
            for (&target, &sibling) in path_target.siblings.iter().zip(siblings) {
                witness
                    .set_hash_target(target, sibling)
                    .expect("history sibling assignment");
            }
        }
        set_bytes(&mut witness, &targets.next_pubkey, &self.next_pubkey);
        set_bytes(&mut witness, &targets.npk_rand, &self.npk_rand);
        set_bytes(
            &mut witness,
            &targets.consumed_pubkey,
            &prev_state.current_pubkey,
        );
        witness
            .set_hash_target(
                targets.proof_data.coin_history_root,
                self.proof_data.coin_history_root,
            )
            .expect("proof coin-history-root assignment must succeed");
        witness
            .set_hash_target(
                targets.proof_data.nav_commitment,
                self.proof_data.nav_commitment,
            )
            .expect("nav-commitment assignment must succeed");

        set_nonnative(&mut witness, &targets.txn_sig_rx, self.signature.rx);
        let signature_s = if matches!(mutation, WitnessMutation::WrongSignature) {
            self.signature.s + Secp256K1Scalar::ONE
        } else {
            self.signature.s
        };
        set_nonnative(&mut witness, &targets.txn_sig_s, signature_s);
        set_point(&mut witness, &targets.s2c_r_prime, self.signature.r_prime);
        witness
            .set_bool_target(targets.recursion.is_account_update, self.is_account_update)
            .expect("proof branch assignment");
        let mut predecessor = if self.is_account_update {
            shared_genesis_proof(circuit).clone()
        } else {
            circuit.base_proof.clone()
        };
        if matches!(mutation, WitnessMutation::ForgedPrevProof) {
            predecessor.public_inputs[0] += F::ONE;
        }
        witness
            .set_proof_with_pis_target(&targets.recursion.prev_proof, &predecessor)
            .expect("base predecessor assignment");
        witness
            .set_proof_with_pis_target(&targets.recursion.base_proof, &circuit.base_proof)
            .expect("conditional base proof assignment");
        witness
            .set_verifier_data_target(
                &targets.recursion.base_verifier_data,
                &circuit.base_verifier_data,
            )
            .expect("base verifier-data assignment");
        witness
            .set_verifier_data_target(
                &targets.recursion.own_verifier_data,
                &circuit.data.verifier_only,
            )
            .expect("own verifier-data assignment");
        witness
            .set_target(targets.nav.size, F::from_canonical_u64(self.nav.size))
            .expect("nav size assignment");
        witness
            .set_hash_target(targets.nav.mth, self.nav.mth)
            .expect("nav mth assignment");
        let mut nav_rand = self.nav_rand;
        if matches!(mutation, WitnessMutation::WrongNavRand) {
            nav_rand[0] ^= 1;
        }
        set_bytes(&mut witness, &targets.nav_rand, &nav_rand);
        witness
            .set_target(
                targets.prev_nav_opening.nav.size,
                F::from_canonical_u64(self.prev_nav.size),
            )
            .expect("previous nav size assignment");
        witness
            .set_hash_target(targets.prev_nav_opening.nav.mth, self.prev_nav.mth)
            .expect("previous nav mth assignment");
        set_bytes(
            &mut witness,
            &targets.prev_nav_opening.nav_rand,
            &self.prev_nav_rand,
        );
        for (&target, &value) in targets.nav_consistency.iter().zip(&self.nav_consistency) {
            witness
                .set_hash_target(target, value)
                .expect("nav consistency assignment");
        }
        set_bytes(
            &mut witness,
            &targets.prev_state_nullifier.pk_prev,
            &self.prev_nullifier_pk,
        );
        set_bytes(
            &mut witness,
            &targets.prev_state_nullifier.r_prev,
            &self.prev_nullifier_r,
        );
        let r_prime_prev = if matches!(mutation, WitnessMutation::WrongPrevRPrime) {
            normalized_key(deterministic_secret(
                b"zkCoins/v1/compliance-chain/wrong-prev-r-prime",
            ))
            .1
        } else {
            self.prev_nullifier_r_prime
        };
        set_point(
            &mut witness,
            &targets.prev_state_nullifier.r_prime_prev,
            r_prime_prev,
        );
        for (&target, &value) in targets
            .prev_state_nullifier
            .nav_inclusion
            .iter()
            .zip(&self.prev_nullifier_inclusion)
        {
            witness
                .set_hash_target(target, value)
                .expect("predecessor inclusion assignment");
        }
        witness
            .set_target(
                targets.prev_state_nullifier.pos_prev,
                F::from_canonical_u64(
                    if matches!(mutation, WitnessMutation::PrevPositionOutOfRange) {
                        self.nav.size
                    } else {
                        self.prev_nullifier_pos
                    },
                ),
            )
            .expect("predecessor position assignment");
        witness
    }

    fn expected_public_inputs(&self, circuit: &SkeletonCircuit) -> Vec<F> {
        let mut expected = Vec::with_capacity(108);
        for digest in [
            self.proof_data.new_account_state_hash,
            self.proof_data.output_coins_root,
            self.proof_data.input_nullifiers_root,
            self.proof_data.coin_history_root,
            self.proof_data.nav_commitment,
        ] {
            expected.extend(digest.elements);
        }
        expected.extend(bytes_as_u32_le_limbs(&self.proof_data.npk_commit));
        expected.extend(bytes_as_u32_le_limbs(&self.prev_state.current_pubkey));
        expected.extend(host::network_id_testnet().elements);
        expected.extend(circuit.data.verifier_only.circuit_digest.elements);
        for digest in &circuit.data.verifier_only.constants_sigmas_cap.0 {
            expected.extend(digest.elements);
        }
        expected
    }
}

#[derive(Clone, Copy)]
enum WitnessMutation {
    None,
    WrongSignature,
    WrongPublicKey,
    WrongNk,
    DuplicateNullifier,
    WrongInputIdentifier,
    ConservationViolation,
    ConservationWraparound,
    WrongNewBalance,
    BalanceUnderflow,
    ForgedPrevProof,
    WrongNavRand,
    WrongPrevRPrime,
    PrevPositionOutOfRange,
    ForgedCreatingProof,
    WrongReceivedIdentifier,
    CreatingPositionOutOfRange,
}

struct SharedCircuit {
    circuit: SkeletonCircuit,
    build_time: Duration,
}

struct SharedGenesisProof {
    proof: ProofWithPublicInputs<F, C, D>,
    prove_time: Duration,
}

static SHARED_CIRCUIT: OnceLock<SharedCircuit> = OnceLock::new();
static GENESIS_PROOF: OnceLock<SharedGenesisProof> = OnceLock::new();
static FULL_CIRCUIT_TEST_LOCK: Mutex<()> = Mutex::new(());

fn shared_circuit() -> &'static SharedCircuit {
    SHARED_CIRCUIT.get_or_init(|| {
        let started = Instant::now();
        let circuit = build_skeleton_circuit(
            CircuitConfig::standard_recursion_zk_config(),
            Network::Testnet,
        );
        SharedCircuit {
            circuit,
            build_time: started.elapsed(),
        }
    })
}

fn shared_genesis_proof(circuit: &SkeletonCircuit) -> &'static ProofWithPublicInputs<F, C, D> {
    &GENESIS_PROOF
        .get_or_init(|| {
            let fixture = ComplianceFixture::genesis_fixture();
            let witness = fixture.witness(circuit, BalanceLayout::Valid, WitnessMutation::None);
            let started = Instant::now();
            let proof = circuit
                .data
                .prove(witness)
                .expect("canonical genesis fixture must prove");
            let prove_time = started.elapsed();
            check_cyclic_proof_verifier_data(
                &proof,
                &circuit.data.verifier_only,
                &circuit.data.common,
            )
            .expect("genesis proof must pin cyclic verifier data");
            circuit
                .data
                .verify(proof.clone())
                .expect("canonical genesis fixture must verify");
            println!("recursive genesis InitialProof: PASS");
            SharedGenesisProof { proof, prove_time }
        })
        .proof
}

/// Test-only view of D.5's one cached, genuine compliance proof.
///
/// `C_balance` uses this rather than re-proving `C` for each positive or
/// negative case.
pub(crate) struct BalanceComplianceTestFixture {
    pub circuit: &'static SkeletonCircuit,
    pub proof: &'static ProofWithPublicInputs<F, C, D>,
    pub account_state: AccountState,
    pub proof_data: ProofData,
    pub asset_id: HashDigest,
    pub balance: u128,
    pub nav: host::Nav,
    pub nav_rand: [u8; 32],
    pub consumed_pubkey: [u8; 32],
    pub r_anchor: [u8; 32],
    pub r_prime: AffinePoint<Secp256K1>,
    pub c_build_time: Duration,
    pub c_prove_time: Duration,
}

pub(crate) fn balance_compliance_test_fixture() -> BalanceComplianceTestFixture {
    let shared = shared_circuit();
    let proof = shared_genesis_proof(&shared.circuit);
    let fixture = ComplianceFixture::genesis_fixture();
    let (&asset_id_bytes, &balance) = fixture
        .new_state
        .balances
        .iter()
        .next()
        .expect("D.5 genesis fixture must carry one non-zero balance");
    let asset_id =
        host::digest_from_bytes(&asset_id_bytes).expect("fixture asset_id must be canonical");
    BalanceComplianceTestFixture {
        circuit: &shared.circuit,
        proof,
        account_state: fixture.new_state,
        proof_data: fixture.proof_data,
        asset_id,
        balance,
        nav: fixture.nav,
        nav_rand: fixture.nav_rand,
        consumed_pubkey: fixture.prev_state.current_pubkey,
        r_anchor: field_bytes(fixture.signature.rx),
        r_prime: fixture.signature.r_prime,
        c_build_time: shared.build_time,
        c_prove_time: GENESIS_PROOF
            .get()
            .expect("shared genesis proof was initialized")
            .prove_time,
    }
}

fn assert_rejected(label: &str, mutation: WitnessMutation) {
    assert_fixture_rejected(label, ComplianceFixture::without_mint(), mutation);
}

fn assert_fixture_rejected(label: &str, fixture: ComplianceFixture, mutation: WitnessMutation) {
    let shared = shared_circuit();
    let witness = fixture.witness(&shared.circuit, BalanceLayout::Valid, mutation);
    let result = catch_unwind(AssertUnwindSafe(|| shared.circuit.data.prove(witness)));
    match result {
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok(proof)) => {
            assert!(
                shared.circuit.data.verify(proof).is_err(),
                "{label}: tampered witness unexpectedly proved and verified"
            );
        }
    }
    println!("{label}: PASS (rejected)");
}

#[test]
fn local_tags_and_tag_encoding_match_shared() {
    let string_tags = [
        (TAG_ACCOUNT_STATE, host::TAG_ACCOUNT_STATE),
        (TAG_COIN, host::TAG_COIN),
        (TAG_COINS_ROOT_LEAF, host::TAG_COINS_ROOT_LEAF),
        (TAG_COINS_ROOT_NODE, host::TAG_COINS_ROOT_NODE),
        (TAG_NK_COMMIT, host::TAG_NK_COMMIT),
        (TAG_NULLIFIER, host::TAG_NULLIFIER),
        (TAG_NULLIFIERS_ROOT_LEAF, host::TAG_NULLIFIERS_ROOT_LEAF),
        (TAG_NULLIFIERS_ROOT_NODE, host::TAG_NULLIFIERS_ROOT_NODE),
        (TAG_NETWORK, host::TAG_NETWORK),
        (TAG_ASSET_ID, host::TAG_ASSET_ID),
        (TAG_ASSET_ID_V2, host::TAG_ASSET_ID_V2),
        (TAG_ISSUANCE_TERMS, host::TAG_ISSUANCE_TERMS),
        (TAG_ISSUANCE_TERMS_V2, host::TAG_ISSUANCE_TERMS_V2),
        (TAG_NAV_COMMIT, host::TAG_NAV_COMMIT),
        (TAG_NFLOG_ROOT, host::TAG_NFLOG_ROOT),
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
    assert_eq!(GENESIS_TAG, host::GENESIS_TAG);
    assert_eq!(NETWORK_TAG_MAINNET, host::NETWORK_TAG_MAINNET);
    assert_eq!(NETWORK_TAG_TESTNET, host::NETWORK_TAG_TESTNET);
    assert_eq!(NETWORK_TAG_REGTEST, host::NETWORK_TAG_REGTEST);
    assert_eq!(MAX_ACCOUNT_ASSETS, host::MAX_ACCOUNT_ASSETS);
    assert_eq!(MAX_TX_INPUTS, 8);
    assert_eq!(MAX_TX_OUTPUTS, 8);
    assert_eq!(MAX_HISTORY_UPDATES, 20);
    assert_eq!(MAX_RX_COINS, 4);
}

#[test]
fn compliance_address_gadget_matches_host() {
    let pk0 = [0x53u8; 32];
    let nk_commit = digest(b"address-nk-commit");
    let expected = host::address(&pk0, nk_commit);

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
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

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
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

#[test]
fn compliance_nullifier_gadget_matches_host() {
    let nk: [u8; 32] = Sha256::digest(b"compliance-nf-parity-nk").into();
    let identifier = digest(b"compliance-nf-parity-coin");
    let expected = host::nullifier(&nk, identifier);

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let nk_target = super::targets::virtual_bytes(&mut builder);
    let identifier_target = builder.add_virtual_hash();
    let nf = nullifier_target(&mut builder, &nk_target, identifier_target);
    builder.register_public_inputs(&nf.elements);
    let data = builder.build::<C>();

    let mut witness = PartialWitness::new();
    set_bytes(&mut witness, &nk_target, &nk);
    witness
        .set_hash_target(identifier_target, identifier)
        .expect("identifier witness assignment must succeed");
    let proof = data.prove(witness).expect("nf parity circuit must prove");
    assert_eq!(proof.public_inputs, expected.elements.to_vec());
    data.verify(proof).expect("nf parity proof must verify");
    println!(
        "compliance nf host parity: PASS {:?}",
        digest_limbs(expected)
    );
}

#[test]
fn compliance_nk_commit_gadget_matches_host() {
    let nk: [u8; 32] = Sha256::digest(b"compliance-nk-commit-parity").into();
    let expected = host::nk_commit(&nk);

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let nk_target = super::targets::virtual_bytes(&mut builder);
    let commitment = nk_commit_target(&mut builder, &nk_target);
    builder.register_public_inputs(&commitment.elements);
    let data = builder.build::<C>();

    let mut witness = PartialWitness::new();
    set_bytes(&mut witness, &nk_target, &nk);
    let proof = data
        .prove(witness)
        .expect("nk_commit parity circuit must prove");
    assert_eq!(proof.public_inputs, expected.elements.to_vec());
    data.verify(proof)
        .expect("nk_commit parity proof must verify");
    println!(
        "compliance nk_commit host parity: PASS {:?}",
        digest_limbs(expected)
    );
}

#[test]
fn compliance_nav_binding_gadgets_match_host() {
    let entries = [
        host::NfLogEntry {
            pk: [0x31; 32],
            r: [0x41; 32],
        },
        host::NfLogEntry {
            pk: [0x51; 32],
            r: [0x61; 32],
        },
    ];
    let nav = host::Nav {
        size: entries.len() as u64,
        mth: host::nflog_mth(&entries),
    };
    let nav_rand = [0x72; 32];
    let expected_root = nav.root();
    let expected_commitment = host::nav_commitment(expected_root, &nav_rand);

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let nav_target = NavTarget::new_virtual(&mut builder);
    let rand_target = super::targets::virtual_bytes(&mut builder);
    let root = nav_root_target(&mut builder, nav_target);
    let commitment = nav_commitment_target(&mut builder, nav_target, &rand_target);
    builder.register_public_inputs(&root.elements);
    builder.register_public_inputs(&commitment.elements);
    let data = builder.build::<C>();

    let mut witness = PartialWitness::new();
    witness
        .set_target(nav_target.size, F::from_canonical_u64(nav.size))
        .unwrap();
    witness.set_hash_target(nav_target.mth, nav.mth).unwrap();
    set_bytes(&mut witness, &rand_target, &nav_rand);
    let proof = data.prove(witness).expect("NAV parity witness must prove");
    assert_eq!(
        proof.public_inputs,
        [expected_root.elements, expected_commitment.elements].concat()
    );
    data.verify(proof).expect("NAV parity proof must verify");
    println!("compliance NAV root/commitment host parity: PASS");
}

#[test]
fn compliance_hash_proof_data_gadget_matches_host() {
    let pd = ProofData {
        new_account_state_hash: digest(b"hpd-new-ash"),
        output_coins_root: digest(b"hpd-ocr"),
        input_nullifiers_root: digest(b"hpd-inr"),
        coin_history_root: digest(b"hpd-history"),
        nav_commitment: digest(b"hpd-nav"),
        npk_commit: Sha256::digest(b"hpd-npk").into(),
    };
    let expected = host::hash_proof_data(&host::serialize_proof_data(&pd));

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let target = ProofDataTarget {
        new_account_state_hash: builder.add_virtual_hash(),
        output_coins_root: builder.add_virtual_hash(),
        input_nullifiers_root: builder.add_virtual_hash(),
        coin_history_root: builder.add_virtual_hash(),
        nav_commitment: builder.add_virtual_hash(),
        npk_commit: super::targets::virtual_bytes(&mut builder),
    };
    let hash = hash_proof_data_target(&mut builder, &target);
    builder.register_public_inputs(&hash);
    let data = builder.build::<C>();

    let mut witness = PartialWitness::new();
    witness
        .set_hash_target(target.new_account_state_hash, pd.new_account_state_hash)
        .expect("new ash assignment");
    witness
        .set_hash_target(target.output_coins_root, pd.output_coins_root)
        .expect("ocr assignment");
    witness
        .set_hash_target(target.input_nullifiers_root, pd.input_nullifiers_root)
        .expect("inr assignment");
    witness
        .set_hash_target(target.coin_history_root, pd.coin_history_root)
        .expect("history assignment");
    witness
        .set_hash_target(target.nav_commitment, pd.nav_commitment)
        .expect("nav assignment");
    set_bytes(&mut witness, &target.npk_commit, &pd.npk_commit);
    let proof = data
        .prove(witness)
        .expect("H(ProofData) parity circuit must prove");
    assert_eq!(
        proof.public_inputs,
        expected.map(F::from_canonical_u8).to_vec()
    );
    data.verify(proof)
        .expect("H(ProofData) parity proof must verify");
    println!(
        "compliance H(ProofData) host parity: PASS {}",
        hex_bytes(&expected)
    );
}

#[test]
fn compliance_input_nullifiers_root_gadget_matches_host_for_empty_one_and_partial() {
    let nk: [u8; 32] = Sha256::digest(b"compliance-inr-parity-nk").into();
    let identifiers: [HashDigest; MAX_TX_INPUTS] =
        std::array::from_fn(|index| digest(format!("inr-identifier-{index}").as_bytes()));

    let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_zk_config());
    let nk_target = super::targets::virtual_bytes(&mut builder);
    let active: [BoolTarget; MAX_TX_INPUTS] =
        std::array::from_fn(|_| builder.add_virtual_bool_target_safe());
    let identifier_targets: [HashOutTarget; MAX_TX_INPUTS] =
        std::array::from_fn(|_| builder.add_virtual_hash());
    let (root, _, _) =
        input_nullifiers_root_target(&mut builder, &nk_target, &active, &identifier_targets);
    builder.register_public_inputs(&root.elements);
    let data = builder.build::<C>();

    for active_count in [0usize, 1, 3] {
        let mut witness = PartialWitness::new();
        set_bytes(&mut witness, &nk_target, &nk);
        for index in 0..MAX_TX_INPUTS {
            witness
                .set_bool_target(active[index], index < active_count)
                .expect("active assignment");
            witness
                .set_hash_target(identifier_targets[index], identifiers[index])
                .expect("identifier assignment");
        }
        let nullifiers: Vec<_> = identifiers[..active_count]
            .iter()
            .map(|&identifier| host::nullifier(&nk, identifier))
            .collect();
        let expected = host::merkle_root(TreeKind::NullifiersRoot, &nullifiers);
        let proof = data
            .prove(witness)
            .expect("input-nullifiers-root parity circuit must prove");
        assert_eq!(proof.public_inputs, expected.elements.to_vec());
        data.verify(proof)
            .expect("input-nullifiers-root parity proof must verify");
        println!(
            "compliance input_nullifiers_root host parity count={active_count}: PASS {:?}",
            digest_limbs(expected)
        );
    }
}

#[test]
fn compliance_skeleton_proves_host_parity_pi_layout_and_network_binding() {
    let _guard = FULL_CIRCUIT_TEST_LOCK
        .lock()
        .expect("full-circuit test lock");
    let shared = shared_circuit();
    let circuit = &shared.circuit;
    let fixture = ComplianceFixture::without_mint();

    let gapped_balance_witness =
        fixture.witness(circuit, BalanceLayout::Gap, WitnessMutation::None);
    assert!(
        circuit.data.prove(gapped_balance_witness).is_err(),
        "a non-left-aligned active-balance layout must not prove"
    );
    println!("balance-gap negative: PASS (rejected)");

    let descending_balance_witness =
        fixture.witness(circuit, BalanceLayout::Descending, WitnessMutation::None);
    assert!(
        circuit.data.prove(descending_balance_witness).is_err(),
        "a non-ascending active-balance layout must not prove"
    );
    println!("balance-descending negative: PASS (rejected)");

    let witness = fixture.witness(circuit, BalanceLayout::Valid, WitnessMutation::None);
    assert_eq!(
        fixture.new_state.balances.len(),
        1,
        "valid witness must retain the recursive balance fixture"
    );

    let prove_timer = Instant::now();
    let proof = circuit
        .data
        .prove(witness)
        .expect("valid compliance skeleton witness must prove");
    let prove_time = prove_timer.elapsed();
    assert_eq!(proof.public_inputs.len(), 108);
    assert_eq!(proof.public_inputs, fixture.expected_public_inputs(circuit));

    let mut wrong_network_proof = proof.clone();
    wrong_network_proof.public_inputs[36..40].copy_from_slice(&host::network_id_regtest().elements);
    assert!(
        circuit.data.verify(wrong_network_proof).is_err(),
        "tampering testnet proof public inputs to regtest network_id must fail"
    );
    println!("wrong network_id PI-tamper: PASS (rejected)");

    let mut wrong_npk_commit_proof = proof.clone();
    wrong_npk_commit_proof.public_inputs[20] += F::ONE;
    assert!(
        circuit.data.verify(wrong_npk_commit_proof).is_err(),
        "tampering the npk_commit public-input limb must fail"
    );
    println!("wrong npk_commit PI-tamper: PASS (rejected)");

    let mut wrong_coin_history_root_proof = proof.clone();
    wrong_coin_history_root_proof.public_inputs[12] += F::ONE;
    assert!(
        circuit.data.verify(wrong_coin_history_root_proof).is_err(),
        "tampering the final coin-history root public input must fail"
    );
    println!("wrong coin_history_root PI-tamper: PASS (rejected)");

    check_cyclic_proof_verifier_data(&proof, &circuit.data.verifier_only, &circuit.data.common)
        .expect("valid compliance proof must pin cyclic verifier data");
    circuit
        .data
        .verify(proof)
        .expect("valid compliance skeleton proof must verify");
    println!("valid compliance witness prove+verify: PASS");
    println!(
        "genuine 2-hop cyclic chain InitialProof -> AccountUpdateProof with predecessor NfLog/S2C anchoring: PASS"
    );
    println!(
        "compliance host parity: balances=2/32 ash={:?} coin.identifier[0]={:?} ocr={:?} inr={:?}",
        digest_limbs(fixture.proof_data.new_account_state_hash),
        digest_limbs(fixture.expected_coin_ids[0]),
        digest_limbs(fixture.proof_data.output_coins_root),
        digest_limbs(fixture.proof_data.input_nullifiers_root),
    );
    println!(
        "compliance PI layout: 108 elements (application=40, verifier_data=68); network_id and npk_commit PI tampering rejected"
    );
    println!(
        "compliance skeleton metrics: gates={} build={:?} prove={:?} build+prove={:?}",
        circuit.gate_count,
        shared.build_time,
        prove_time,
        shared.build_time + prove_time
    );
    println!(
        "compliance skeleton degree_bits: {}",
        circuit.data.common.degree_bits()
    );
}

#[test]
fn compliance_v1_mint_proves() {
    let _guard = FULL_CIRCUIT_TEST_LOCK
        .lock()
        .expect("full-circuit test lock");
    let shared = shared_circuit();
    let fixture = ComplianceFixture::genesis_fixture();
    let witness = fixture.witness(&shared.circuit, BalanceLayout::Valid, WitnessMutation::None);
    let proof = shared
        .circuit
        .data
        .prove(witness)
        .expect("valid v1 mint must prove");
    assert_eq!(
        proof.public_inputs,
        fixture.expected_public_inputs(&shared.circuit)
    );
    check_cyclic_proof_verifier_data(
        &proof,
        &shared.circuit.data.verifier_only,
        &shared.circuit.data.common,
    )
    .expect("v1 genesis must pin cyclic verifier data");
    shared
        .circuit
        .data
        .verify(proof)
        .expect("valid v1 verifies");
    println!("valid token-standard-1 mint: PASS");
}

#[test]
fn compliance_two_hop_recursive_chain_proves() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    let shared = shared_circuit();
    let fixture = ComplianceFixture::new();
    let witness = fixture.witness(&shared.circuit, BalanceLayout::Valid, WitnessMutation::None);
    let proof = shared
        .circuit
        .data
        .prove(witness)
        .expect("anchored AccountUpdateProof must prove");
    check_cyclic_proof_verifier_data(
        &proof,
        &shared.circuit.data.verifier_only,
        &shared.circuit.data.common,
    )
    .expect("two-hop proof must pin cyclic verifier data");
    shared
        .circuit
        .data
        .verify(proof)
        .expect("anchored AccountUpdateProof must verify");
    println!(
        "genuine 2-hop cyclic chain InitialProof -> AccountUpdateProof with predecessor NfLog/S2C anchoring: PASS"
    );
}

#[test]
fn compliance_clause_10_valid_receive_and_required_negatives() {
    let _guard = FULL_CIRCUIT_TEST_LOCK
        .lock()
        .expect("full-circuit test lock");
    let shared = shared_circuit();
    let circuit = &shared.circuit;

    let creating_fixture = ComplianceFixture::creating_receive_fixture(receive_owner());
    let creating_witness =
        creating_fixture.witness(circuit, BalanceLayout::Valid, WitnessMutation::None);
    let creating_proof = circuit
        .data
        .prove(creating_witness)
        .expect("genuine cross-account creating transition must prove");
    check_cyclic_proof_verifier_data(
        &creating_proof,
        &circuit.data.verifier_only,
        &circuit.data.common,
    )
    .expect("creating proof must pin cyclic verifier data");
    circuit
        .data
        .verify(creating_proof.clone())
        .expect("genuine creating transition must verify");
    println!("clause 10 genuine creating_proof: PASS");

    let fixture = ComplianceFixture::receive_fixture(&creating_fixture, creating_proof);
    let witness = fixture.witness(circuit, BalanceLayout::Valid, WitnessMutation::None);
    let prove_started = Instant::now();
    let proof = circuit
        .data
        .prove(witness)
        .expect("valid one-coin receive transition must prove");
    let prove_time = prove_started.elapsed();
    assert_eq!(proof.public_inputs, fixture.expected_public_inputs(circuit));
    check_cyclic_proof_verifier_data(&proof, &circuit.data.verifier_only, &circuit.data.common)
        .expect("receive proof must pin cyclic verifier data");
    circuit
        .data
        .verify(proof)
        .expect("valid one-coin receive transition must verify");
    println!(
        "clause 10 valid receive: PASS (creating recursion, coin binding, NAV prefix, creating-nullifier key+leaf anchoring, Recv balance, history 0->1)"
    );

    assert_fixture_rejected(
        "forged/altered creating_proof",
        fixture.clone(),
        WitnessMutation::ForgedCreatingProof,
    );
    assert_fixture_rejected(
        "wrong recomputed received coin.identifier",
        fixture.clone(),
        WitnessMutation::WrongReceivedIdentifier,
    );
    assert_fixture_rejected(
        "non-prefix creating r_nav",
        fixture.clone().receive_non_prefix_case(),
        WitnessMutation::None,
    );
    assert_fixture_rejected(
        "Pk_create != creating_proof.consumed_pubkey",
        fixture.clone().receive_wrong_pk_case(),
        WitnessMutation::None,
    );
    assert_fixture_rejected(
        "wrong R_create S2C opening",
        fixture.clone().receive_wrong_r_case(),
        WitnessMutation::None,
    );
    assert_fixture_rejected(
        "pos_create >= nav.size",
        fixture,
        WitnessMutation::CreatingPositionOutOfRange,
    );
    println!(
        "FULL C metrics: gates={} degree_bits={} build={:?} valid_receive_prove={:?}",
        circuit.gate_count,
        circuit.data.common.degree_bits(),
        shared.build_time,
        prove_time
    );
}

#[test]
fn compliance_v2_mint_proves() {
    let _guard = FULL_CIRCUIT_TEST_LOCK
        .lock()
        .expect("full-circuit test lock");
    let shared = shared_circuit();
    let fixture = ComplianceFixture::mint_case(MintCase::ValidV2);
    let witness = fixture.witness(&shared.circuit, BalanceLayout::Valid, WitnessMutation::None);
    let proof = shared
        .circuit
        .data
        .prove(witness)
        .expect("valid v2 mint must prove");
    assert_eq!(
        proof.public_inputs,
        fixture.expected_public_inputs(&shared.circuit)
    );
    check_cyclic_proof_verifier_data(
        &proof,
        &shared.circuit.data.verifier_only,
        &shared.circuit.data.common,
    )
    .expect("v2 genesis must pin cyclic verifier data");
    shared
        .circuit
        .data
        .verify(proof)
        .expect("valid v2 verifies");
    println!("valid token-standard-2 mint: PASS");
}

#[test]
fn compliance_rejects_conservation_violation() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_rejected(
        "conservation Out > In + Mint",
        WitnessMutation::ConservationViolation,
    );
}

#[test]
fn compliance_rejects_conservation_u128_wraparound() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_rejected(
        "wide conservation u128 wraparound",
        WitnessMutation::ConservationWraparound,
    );
}

#[test]
fn compliance_rejects_wrong_new_balance() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_rejected("wrong new balance fold", WitnessMutation::WrongNewBalance);
}

#[test]
fn compliance_rejects_balance_underflow() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_rejected("balance underflow", WitnessMutation::BalanceUnderflow);
}

#[test]
fn compliance_rejects_bad_issuance_version() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_fixture_rejected(
        "bad issuance_version",
        ComplianceFixture::mint_case(MintCase::BadVersion),
        WitnessMutation::None,
    );
}

#[test]
fn compliance_rejects_bad_creator_pubkey() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_fixture_rejected(
        "bad mint creator_pubkey",
        ComplianceFixture::mint_case(MintCase::BadCreator),
        WitnessMutation::None,
    );
}

#[test]
fn compliance_rejects_bad_mint_asset_id() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_fixture_rejected(
        "bad mint asset_id",
        ComplianceFixture::mint_case(MintCase::BadAssetId),
        WitnessMutation::None,
    );
}

#[test]
fn compliance_rejects_v2_cap_below_amount() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_fixture_rejected(
        "v2 cap_total below amount",
        ComplianceFixture::mint_case(MintCase::BadCap),
        WitnessMutation::None,
    );
}

#[test]
fn compliance_rejects_v2_nonzero_genesis_counter() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_fixture_rejected(
        "v2 nonzero genesis send_counter",
        ComplianceFixture::mint_case(MintCase::BadGenesisCounter),
        WitnessMutation::None,
    );
}

#[test]
fn compliance_rejects_v2_wrong_genesis_key() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_fixture_rejected(
        "v2 current_pubkey != creator_pubkey",
        ComplianceFixture::mint_case(MintCase::BadGenesisKey),
        WitnessMutation::None,
    );
}

#[test]
fn compliance_rejects_spend_of_absent_coin() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_fixture_rejected(
        "coin-history spend Absent -> Spent",
        ComplianceFixture::new_with_absent_spend(),
        WitnessMutation::None,
    );
}

#[test]
fn compliance_rejects_readmission_replay() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_fixture_rejected(
        "coin-history re-admit Admitted coin",
        ComplianceFixture::new_with_replayed_self_output(true),
        WitnessMutation::None,
    );
}

#[test]
fn compliance_rejects_wrong_signature() {
    let _guard = FULL_CIRCUIT_TEST_LOCK
        .lock()
        .expect("full-circuit test lock");
    assert_rejected("wrong signature", WitnessMutation::WrongSignature);
}

#[test]
fn compliance_rejects_wrong_consumed_public_key() {
    let _guard = FULL_CIRCUIT_TEST_LOCK
        .lock()
        .expect("full-circuit test lock");
    assert_rejected("wrong Pk_i", WitnessMutation::WrongPublicKey);
}

#[test]
fn compliance_rejects_wrong_nk() {
    let _guard = FULL_CIRCUIT_TEST_LOCK
        .lock()
        .expect("full-circuit test lock");
    assert_rejected("wrong nk", WitnessMutation::WrongNk);
}

#[test]
fn compliance_rejects_duplicate_nullifier() {
    let _guard = FULL_CIRCUIT_TEST_LOCK
        .lock()
        .expect("full-circuit test lock");
    assert_rejected("duplicate nf", WitnessMutation::DuplicateNullifier);
}

#[test]
fn compliance_rejects_wrong_input_coin_identifier() {
    let _guard = FULL_CIRCUIT_TEST_LOCK
        .lock()
        .expect("full-circuit test lock");
    assert_rejected(
        "wrong input coin.identifier",
        WitnessMutation::WrongInputIdentifier,
    );
}

#[test]
fn compliance_rejects_forged_recursive_predecessor_proof() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_rejected(
        "forged prev_proof public input",
        WitnessMutation::ForgedPrevProof,
    );
}

#[test]
fn compliance_rejects_wrong_nav_commitment_opening() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_rejected("wrong nav_rand opening", WitnessMutation::WrongNavRand);
}

#[test]
fn compliance_rejects_non_prefix_nav() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_fixture_rejected(
        "non-prefix predecessor nav",
        ComplianceFixture::non_prefix_case(),
        WitnessMutation::None,
    );
}

#[test]
fn compliance_rejects_predecessor_key_substitution() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_fixture_rejected(
        "Pk_prev != prev_proof.consumed_pubkey",
        ComplianceFixture::wrong_prev_pk_case(),
        WitnessMutation::None,
    );
}

#[test]
fn compliance_rejects_wrong_predecessor_s2c_opening() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_rejected(
        "wrong R_prime_prev S2C opening",
        WitnessMutation::WrongPrevRPrime,
    );
}

#[test]
fn compliance_rejects_predecessor_position_out_of_range() {
    let _guard = FULL_CIRCUIT_TEST_LOCK.lock().unwrap();
    assert_rejected(
        "pos_prev >= nav.size",
        WitnessMutation::PrevPositionOutOfRange,
    );
}
