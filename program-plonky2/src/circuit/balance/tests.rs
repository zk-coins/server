use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

use plonky2::field::types::{Field, Field64, PrimeField};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use sha2::{Digest, Sha256};

use shared::spec_v1::{self as host, AccountState, ZERO_HASH};

use crate::circuit::compliance::tests::{
    balance_compliance_test_fixture, BalanceComplianceTestFixture,
};
use crate::circuit::compliance::{AccountStateTarget, Network, MAX_ACCOUNT_ASSETS};
use crate::circuit::gadgets::biguint::WitnessBigUint;
use crate::circuit::gadgets::curve::AffinePointTarget;
use crate::circuit::gadgets::curve_types::{AffinePoint, Secp256K1};
use crate::circuit::gadgets::nflog_consistency::{fill_consistency_slots, H_MAX};
use crate::circuit::gadgets::u128_arith::U128Target;
use crate::circuit::gadgets::u64_limbs::set_u64_limbs_unwrap;
use crate::F;

use super::{build_c_balance_circuit, BalanceCircuit};

fn set_bytes(witness: &mut PartialWitness<F>, targets: &[Target; 32], bytes: &[u8; 32]) {
    for (&target, &byte) in targets.iter().zip(bytes) {
        witness
            .set_target(target, F::from_canonical_u8(byte))
            .expect("byte witness assignment");
    }
}

fn set_u128(witness: &mut PartialWitness<F>, target: U128Target, value: u128) {
    for (index, limb) in target.limbs.into_iter().enumerate() {
        witness
            .set_target(limb, F::from_canonical_u32((value >> (index * 32)) as u32))
            .expect("u128 witness assignment");
    }
}

fn set_account_state(
    witness: &mut PartialWitness<F>,
    target: AccountStateTarget,
    state: &AccountState,
) {
    set_bytes(witness, &target.owner, &state.owner.0);
    witness
        .set_hash_target(target.nk_commit, state.nk_commit)
        .expect("nk_commit assignment");
    set_bytes(witness, &target.current_pubkey, &state.current_pubkey);
    set_u64_limbs_unwrap(witness, target.send_counter, state.send_counter);
    witness
        .set_hash_target(target.coin_history_root, state.coin_history_root)
        .expect("coin_history_root assignment");

    let balances: Vec<_> = state.balances.iter().collect();
    assert!(balances.len() <= MAX_ACCOUNT_ASSETS);
    for (index, slot) in target.balances.into_iter().enumerate() {
        if let Some((&asset_bytes, &amount)) = balances.get(index).copied() {
            let asset =
                host::digest_from_bytes(&asset_bytes).expect("balance asset must be canonical");
            witness
                .set_bool_target(slot.active, true)
                .expect("active balance assignment");
            witness
                .set_hash_target(slot.asset_id, asset)
                .expect("balance asset assignment");
            set_u128(witness, slot.amount, amount);
        } else {
            witness
                .set_bool_target(slot.active, false)
                .expect("inactive balance assignment");
            witness
                .set_hash_target(slot.asset_id, ZERO_HASH)
                .expect("inactive asset assignment");
            set_u128(witness, slot.amount, 0);
        }
    }
}

fn set_point(
    witness: &mut PartialWitness<F>,
    target: &AffinePointTarget<Secp256K1>,
    point: AffinePoint<Secp256K1>,
) {
    witness
        .set_biguint_target(&target.x.value, &point.x.to_canonical_biguint())
        .expect("R' x assignment");
    witness
        .set_biguint_target(&target.y.value, &point.y.to_canonical_biguint())
        .expect("R' y assignment");
}

#[derive(Clone, Copy, Debug)]
enum Mutation {
    None,
    WrongBalance,
    WrongAnchorPk,
    WrongAnchorR,
    SizeExceedsCeiling,
    WrongNetwork,
    AlteredComplianceAsh,
    TamperedComplianceVerifierData,
    NonCanonicalSizeCeiling,
}

fn mutation_label(mutation: Mutation) -> &'static str {
    match mutation {
        Mutation::None => "valid balance attestation",
        Mutation::WrongBalance => "wrong balance B (statement 2)",
        Mutation::WrongAnchorPk => "Pk_anchor != pi.consumed_pubkey (statement 5)",
        Mutation::WrongAnchorR => "R_anchor not S2C opening H(ProofData) (statement 4)",
        Mutation::SizeExceedsCeiling => "size > size_ceiling / non-prefix NAV (statement 6)",
        Mutation::WrongNetwork => "wrong network_id (statement 7)",
        Mutation::AlteredComplianceAsh => {
            "altered pi.new_account_state_hash != ash(S) (statement 3)"
        }
        Mutation::TamperedComplianceVerifierData => "tampered C proof verifier-data tail",
        Mutation::NonCanonicalSizeCeiling => "non-canonical public size_ceiling encoding",
    }
}

fn valid_ceiling(
    fixture: &BalanceComplianceTestFixture,
) -> (u64, host::HashDigest, [host::HashDigest; 2 * H_MAX]) {
    let prefix_entry = host::NfLogEntry {
        pk: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-pk").into(),
        r: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-r").into(),
    };
    assert_eq!(
        host::nflog_mth(&[prefix_entry]),
        fixture.nav.mth,
        "the exported D.5 nav must match its deterministic first entry"
    );
    let ceiling_entry = host::NfLogEntry {
        pk: Sha256::digest(b"zkCoins/v1/balance/ceiling-pk").into(),
        r: Sha256::digest(b"zkCoins/v1/balance/ceiling-r").into(),
    };
    let entries = [prefix_entry, ceiling_entry];
    let consistency = host::consistency_proof(1, &entries).expect("1 -> 2 prefix proof");
    (
        2,
        host::nflog_mth(&entries),
        fill_consistency_slots(&consistency, 1, 2),
    )
}

fn balance_witness(
    balance: &BalanceCircuit,
    fixture: &BalanceComplianceTestFixture,
    mutation: Mutation,
) -> PartialWitness<F> {
    let targets = &balance.targets;
    let mut witness = PartialWitness::new();

    let claimed_balance = if matches!(mutation, Mutation::WrongBalance) {
        fixture.balance + 1
    } else {
        fixture.balance
    };
    let mut anchor_pk = fixture.consumed_pubkey;
    if matches!(mutation, Mutation::WrongAnchorPk) {
        anchor_pk[0] ^= 1;
    }
    let mut anchor_r = fixture.r_anchor;
    if matches!(mutation, Mutation::WrongAnchorR) {
        anchor_r[0] ^= 1;
    }
    let (valid_size_ceiling, valid_mth_ceiling, valid_consistency) = valid_ceiling(fixture);
    let (size_ceiling, mth_ceiling, nav_consistency) =
        if matches!(mutation, Mutation::SizeExceedsCeiling) {
            (0, host::nflog_empty(), [ZERO_HASH; 2 * H_MAX])
        } else {
            (valid_size_ceiling, valid_mth_ceiling, valid_consistency)
        };
    let nav_ceiling = host::nflog_root(size_ceiling, mth_ceiling);
    let network_id = if matches!(mutation, Mutation::WrongNetwork) {
        host::network_id_regtest()
    } else {
        host::network_id_testnet()
    };

    set_bytes(
        &mut witness,
        &targets.public.subject,
        &fixture.account_state.owner.0,
    );
    witness
        .set_hash_target(targets.public.asset_id, fixture.asset_id)
        .expect("asset_id assignment");
    set_u128(&mut witness, targets.public.balance, claimed_balance);
    witness
        .set_hash_target(targets.public.nav_ceiling, nav_ceiling)
        .expect("nav_ceiling assignment");
    // Limbs are the size_ceiling representation. The NonCanonical mutation
    // still assigns a wrong pair (valid_size + p) so the consistency proof
    // built for the honest ceiling cannot satisfy the limb-driven recursion.
    let assigned_ceiling = if matches!(mutation, Mutation::NonCanonicalSizeCeiling) {
        let noncanonical = size_ceiling as u128 + F::ORDER as u128;
        assert!(noncanonical <= u64::MAX as u128);
        noncanonical as u64
    } else {
        size_ceiling
    };
    set_u64_limbs_unwrap(&mut witness, targets.public.size_ceiling, assigned_ceiling);
    set_bytes(&mut witness, &targets.public.anchor_txid, &[0x31; 32]);
    set_bytes(&mut witness, &targets.public.anchor_block_hash, &[0x42; 32]);
    witness
        .set_target(
            targets.public.anchor_height_limbs[0],
            F::from_canonical_u32(840_000),
        )
        .expect("anchor height low limb");
    witness
        .set_target(targets.public.anchor_height_limbs[1], F::ZERO)
        .expect("anchor height high limb");
    set_bytes(&mut witness, &targets.public.anchor_pk, &anchor_pk);
    set_bytes(&mut witness, &targets.public.anchor_r, &anchor_r);
    witness
        .set_hash_target(targets.public.network_id, network_id)
        .expect("network_id assignment");

    set_account_state(
        &mut witness,
        targets.witness.account_state,
        &fixture.account_state,
    );
    let mut compliance_proof = fixture.proof.clone();
    if matches!(mutation, Mutation::AlteredComplianceAsh) {
        compliance_proof.public_inputs[0] += F::ONE;
    }
    if matches!(mutation, Mutation::TamperedComplianceVerifierData) {
        let cap_elements = fixture
            .circuit
            .data
            .common
            .config
            .fri_config
            .num_cap_elements();
        let verifier_data_offset = compliance_proof.public_inputs.len() - 4 - 4 * cap_elements;
        compliance_proof.public_inputs[verifier_data_offset] += F::ONE;
    }
    witness
        .set_proof_with_pis_target(&targets.witness.compliance_proof, &compliance_proof)
        .expect("C proof assignment");
    set_u64_limbs_unwrap(&mut witness, targets.witness.nav.size, fixture.nav.size);
    witness
        .set_hash_target(targets.witness.nav.mth, fixture.nav.mth)
        .expect("nav mth assignment");
    set_bytes(&mut witness, &targets.witness.nav_rand, &fixture.nav_rand);
    for (target, value) in targets
        .witness
        .nav_consistency
        .into_iter()
        .zip(nav_consistency)
    {
        witness
            .set_hash_target(target, value)
            .expect("consistency proof assignment");
    }
    witness
        .set_hash_target(targets.witness.mth_ceiling, mth_ceiling)
        .expect("ceiling mth assignment");
    set_bytes(
        &mut witness,
        &targets.witness.spend_record.public_key,
        &anchor_pk,
    );
    set_bytes(
        &mut witness,
        &targets.witness.spend_record.signature_r,
        &anchor_r,
    );
    set_point(&mut witness, &targets.witness.r_prime, fixture.r_prime);
    witness
}

fn bytes_as_u32_le_limbs(bytes: &[u8; 32]) -> [F; 8] {
    std::array::from_fn(|index| {
        let start = 28 - index * 4;
        F::from_canonical_u32(u32::from_be_bytes(
            bytes[start..start + 4].try_into().unwrap(),
        ))
    })
}

fn expected_public_inputs(fixture: &BalanceComplianceTestFixture) -> Vec<F> {
    let (size_ceiling, mth_ceiling, _) = valid_ceiling(fixture);
    let mut expected = Vec::with_capacity(60);
    expected.extend(bytes_as_u32_le_limbs(&fixture.account_state.owner.0));
    expected.extend(fixture.asset_id.elements);
    expected.extend([
        F::from_canonical_u32(fixture.balance as u32),
        F::from_canonical_u32((fixture.balance >> 32) as u32),
        F::from_canonical_u32((fixture.balance >> 64) as u32),
        F::from_canonical_u32((fixture.balance >> 96) as u32),
    ]);
    expected.extend(host::nflog_root(size_ceiling, mth_ceiling).elements);
    expected.extend([
        F::from_canonical_u32(size_ceiling as u32),
        F::from_canonical_u32((size_ceiling >> 32) as u32),
    ]);
    expected.extend(bytes_as_u32_le_limbs(&[0x31; 32]));
    expected.extend(bytes_as_u32_le_limbs(&[0x42; 32]));
    expected.extend([F::from_canonical_u32(840_000), F::ZERO]);
    expected.extend(bytes_as_u32_le_limbs(&fixture.consumed_pubkey));
    expected.extend(bytes_as_u32_le_limbs(&fixture.r_anchor));
    expected.extend(host::network_id_testnet().elements);
    assert_eq!(expected.len(), 60);
    expected
}

fn assert_rejected(
    balance: &BalanceCircuit,
    fixture: &BalanceComplianceTestFixture,
    mutation: Mutation,
) {
    let witness = balance_witness(balance, fixture, mutation);
    let result = catch_unwind(AssertUnwindSafe(|| balance.data.prove(witness)));
    match result {
        Err(_) | Ok(Err(_)) => {}
        Ok(Ok(proof)) => {
            assert!(
                balance.data.verify(proof).is_err(),
                "{} unexpectedly proved and verified",
                mutation_label(mutation)
            );
        }
    }
    println!("{}: PASS (rejected)", mutation_label(mutation));
}

#[test]
fn balance_real_c_proof_valid_and_eight_negatives() {
    let fixture = balance_compliance_test_fixture();
    assert_eq!(
        fixture.proof_data.new_account_state_hash,
        host::account_state_hash(&fixture.account_state).expect("fixture ash"),
    );
    fixture
        .circuit
        .data
        .verify(fixture.proof.clone())
        .expect("cached fixture must be a genuine verifying C proof");

    let build_started = Instant::now();
    let balance = build_c_balance_circuit(fixture.circuit, Network::Testnet);
    let build_time = build_started.elapsed();
    assert!(
        balance.data.common.config.zero_knowledge,
        "C_balance proof configuration must have ZK enabled"
    );
    assert_eq!(balance.data.common.num_public_inputs, 60);

    let valid_witness = balance_witness(&balance, &fixture, Mutation::None);
    let prove_started = Instant::now();
    let valid_proof = balance
        .data
        .prove(valid_witness)
        .expect("valid C_balance attestation must prove");
    let prove_time = prove_started.elapsed();
    assert_eq!(valid_proof.public_inputs, expected_public_inputs(&fixture));
    balance
        .data
        .verify(valid_proof)
        .expect("valid C_balance attestation must verify");
    println!("valid balance attestation with genuine C proof: PASS (proved and verified)");

    for mutation in [
        Mutation::WrongBalance,
        Mutation::WrongAnchorPk,
        Mutation::WrongAnchorR,
        Mutation::SizeExceedsCeiling,
        Mutation::WrongNetwork,
        Mutation::AlteredComplianceAsh,
        Mutation::TamperedComplianceVerifierData,
        Mutation::NonCanonicalSizeCeiling,
    ] {
        assert_rejected(&balance, &fixture, mutation);
    }

    println!(
        "C fixture metrics: gates={} degree_bits={} build={:?} prove={:?}",
        fixture.circuit.gate_count,
        fixture.circuit.data.common.degree_bits(),
        fixture.c_build_time,
        fixture.c_prove_time,
    );
    println!(
        "C_balance metrics: gates={} degree_bits={} build={:?} prove={:?}",
        balance.gate_count,
        balance.data.common.degree_bits(),
        build_time,
        prove_time,
    );
    println!(
        "C_balance PI layout: 60 elements; subject=8u32 asset_id=4fe balance=4u32 nav_ceiling=4fe size_ceiling=2u32 txid=8u32 block_hash=8u32 height=2u32 Pk_anchor=8u32 R_anchor=8u32 network_id=4fe"
    );
}
