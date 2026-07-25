use plonky2::hash::hash_types::HashOutTarget;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{CommonCircuitData, VerifierOnlyCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputsTarget;

use crate::circuit::compliance::{
    account_balance_target, account_state_hash_target, be_bytes32_to_u32_limbs,
    hash_proof_data_target, nav_commitment_target, nav_root_target, network_id_target,
    unpack_compliance_proof_pis, AccountStateTarget, NavTarget, Network,
};
use crate::circuit::gadgets::bip340::s2c_open_with_point;
use crate::circuit::gadgets::curve::{AffinePointTarget, CircuitBuilderCurve};
use crate::circuit::gadgets::curve_types::Secp256K1;
use crate::circuit::gadgets::nflog_consistency::{verify_nflog_consistency, H_MAX};
use crate::circuit::gadgets::u128_arith::U128Target;
use crate::circuit::gadgets::u64_limbs::U64LimbsTarget;
use crate::{C, D, F};

/// The frozen 60-element application public-input layout of `C_balance`.
#[derive(Clone, Copy, Debug)]
pub struct BalancePublicInputsTarget {
    pub subject: [Target; 32],
    pub asset_id: HashOutTarget,
    pub balance: U128Target,
    pub nav_ceiling: HashOutTarget,
    /// Protocol size ceiling as two little-endian u32 limbs (also the public
    /// PI pair). Limbs are the representation — not a view of a single field
    /// element — so the full `0 … 2^64 − 1` domain is available.
    pub size_ceiling: U64LimbsTarget,
    pub anchor_txid: [Target; 32],
    pub anchor_block_hash: [Target; 32],
    pub anchor_height_limbs: [Target; 2],
    pub anchor_pk: [Target; 32],
    pub anchor_r: [Target; 32],
    pub network_id: HashOutTarget,
}

/// The portion of a SpendRecord consumed by the normative balance relation.
///
/// `C_balance` proves the S2C `CommVerify` relation over the signature nonce
/// `R`; the aggregate/signature validity check itself is performed by the
/// scanner as part of the host-side anchor checks. Consequently the scalar
/// `s` is not an operand of this circuit and is deliberately not allocated as
/// a free, unconstrained witness.
#[derive(Clone, Copy, Debug)]
pub struct SpendRecordTarget {
    pub public_key: [Target; 32],
    pub signature_r: [Target; 32],
}

/// All hidden witnesses used by the seven normative statement clauses.
#[derive(Clone, Debug)]
pub struct BalanceWitnessTargets {
    pub account_state: AccountStateTarget,
    pub compliance_proof: ProofWithPublicInputsTarget<D>,
    pub nav: NavTarget,
    pub nav_rand: [Target; 32],
    pub nav_consistency: [HashOutTarget; 2 * H_MAX],
    pub mth_ceiling: HashOutTarget,
    pub spend_record: SpendRecordTarget,
    pub r_prime: AffinePointTarget<Secp256K1>,
}

/// Host-side Bitcoin inclusion, first-occurrence, `completed`-state, and
/// canonical-`nav_ceiling` checks are intentionally outside `C_balance`.
/// Callers must perform all §5.7 "Host-side anchor checks" before accepting an
/// attestation.
#[derive(Clone, Debug)]
pub struct BalanceTargets {
    pub public: BalancePublicInputsTarget,
    pub witness: BalanceWitnessTargets,
}

fn virtual_bytes(builder: &mut CircuitBuilder<F, D>) -> [Target; 32] {
    let bytes = builder.add_virtual_target_arr();
    for byte in bytes {
        builder.range_check(byte, 8);
    }
    bytes
}

fn connect_bytes(builder: &mut CircuitBuilder<F, D>, lhs: &[Target; 32], rhs: &[Target; 32]) {
    for (&lhs, &rhs) in lhs.iter().zip(rhs) {
        builder.connect(lhs, rhs);
    }
}

fn pin_compliance_verifier_data_tail(
    builder: &mut CircuitBuilder<F, D>,
    proof: &ProofWithPublicInputsTarget<D>,
    common: &CommonCircuitData<F, D>,
    canonical: &plonky2::plonk::circuit_data::VerifierCircuitTarget,
) {
    let embedded = builder.add_virtual_verifier_data(common.config.fri_config.cap_height);
    let cap_elements = common.config.fri_config.num_cap_elements();
    assert_eq!(embedded.constants_sigmas_cap.0.len(), cap_elements);

    // `add_verifier_data_public_inputs` appends
    // `[circuit_digest, constants_sigmas_cap]` in exactly this order.
    let tail_len = 4 + 4 * cap_elements;
    let tail_start = proof
        .public_inputs
        .len()
        .checked_sub(tail_len)
        .expect("cyclic C proof must contain its verifier-data PI tail");
    for (&pi, target) in proof.public_inputs[tail_start..tail_start + 4]
        .iter()
        .zip(embedded.circuit_digest.elements)
    {
        builder.connect(pi, target);
    }
    for (embedded_hash, pi_hash) in embedded.constants_sigmas_cap.0.iter().zip(
        proof.public_inputs[tail_start + 4..]
            .chunks_exact(4)
            .map(|elements| HashOutTarget {
                elements: elements
                    .try_into()
                    .expect("a verifier-data cap element has four limbs"),
            }),
    ) {
        builder.connect_hashes(*embedded_hash, pi_hash);
    }

    builder.connect_hashes(embedded.circuit_digest, canonical.circuit_digest);
    assert_eq!(
        embedded.constants_sigmas_cap.0.len(),
        canonical.constants_sigmas_cap.0.len(),
        "C proof and canonical verifier cap heights must match"
    );
    for (&embedded_hash, &canonical_hash) in embedded
        .constants_sigmas_cap
        .0
        .iter()
        .zip(&canonical.constants_sigmas_cap.0)
    {
        builder.connect_hashes(embedded_hash, canonical_hash);
    }
}

pub(super) fn add_balance_statement(
    builder: &mut CircuitBuilder<F, D>,
    compliance_common: &CommonCircuitData<F, D>,
    compliance_verifier: &VerifierOnlyCircuitData<C, D>,
    network: Network,
) -> BalanceTargets {
    assert_eq!(
        compliance_common.num_public_inputs, 108,
        "C_balance requires C's frozen 108-element proof layout"
    );

    let subject = virtual_bytes(builder);
    let asset_id = builder.add_virtual_hash();
    let nav_ceiling = builder.add_virtual_hash();
    // Limbs first: the public size_ceiling is the limb pair itself.
    let size_ceiling = U64LimbsTarget::new_virtual(builder);
    let anchor_txid = virtual_bytes(builder);
    let anchor_block_hash = virtual_bytes(builder);
    let anchor_height_limbs = builder.add_virtual_target_arr();
    for limb in anchor_height_limbs {
        builder.range_check(limb, 32);
    }
    let anchor_pk = virtual_bytes(builder);
    let anchor_r = virtual_bytes(builder);
    let network_id = builder.add_virtual_hash();

    let account_state = AccountStateTarget::new_virtual(builder);
    let compliance_proof = builder.add_virtual_proof_with_pis(compliance_common);
    let nav = NavTarget::new_virtual(builder);
    let nav_rand = virtual_bytes(builder);
    let nav_consistency = std::array::from_fn(|_| builder.add_virtual_hash());
    let mth_ceiling = builder.add_virtual_hash();
    let spend_record = SpendRecordTarget {
        public_key: virtual_bytes(builder),
        signature_r: virtual_bytes(builder),
    };
    let r_prime = builder.add_virtual_affine_point_target();

    // 1. The disclosed subject is exactly the owner in the hidden state.
    connect_bytes(builder, &account_state.owner, &subject);

    // The canonical AccountState gadget enforces the one encoding shared with
    // C, including its balance-slot discipline.
    let (account_state_hash, _balance_count) = account_state_hash_target(builder, &account_state);

    // 2. Reuse C's exact masked balance lookup. An absent asset maps to zero.
    let balance = account_balance_target(builder, &account_state, asset_id);

    // 3. Plain, non-cyclic verification of exactly one C proof under constant
    // pinned foreign verifier data. Also pin the cyclic verifier-data tail
    // carried by C's own public inputs, then bind the attested ash.
    let constant_c_verifier = builder.constant_verifier_data(compliance_verifier);
    pin_compliance_verifier_data_tail(
        builder,
        &compliance_proof,
        compliance_common,
        &constant_c_verifier,
    );
    builder.verify_proof::<C>(&compliance_proof, &constant_c_verifier, compliance_common);
    let compliance_pis = unpack_compliance_proof_pis(builder, &compliance_proof);
    builder.connect_hashes(
        compliance_pis.proof_data.new_account_state_hash,
        account_state_hash,
    );

    // 4. Recompute the canonical 192-byte ProofData serialization from π's
    // public inputs, SHA-256 it, and open the signature nonce via C's S2C
    // gadget. Both hidden SpendRecord fields are copy-constrained to anchor.
    let h_proof_data = hash_proof_data_target(builder, &compliance_pis.proof_data);
    let opening = s2c_open_with_point(builder, &r_prime, &h_proof_data);
    connect_bytes(builder, &opening.rx_bytes, &spend_record.signature_r);
    connect_bytes(builder, &spend_record.signature_r, &anchor_r);

    // 5. Bind the anchored key to both the SpendRecord and C's consumed-key PI.
    connect_bytes(builder, &spend_record.public_key, &anchor_pk);
    connect_bytes(builder, &anchor_pk, &compliance_pis.consumed_pubkey);

    // 6. Open π.nav_commitment, bind both log roots, and prove the hidden nav
    // is an RFC-6962 prefix of the public ceiling. Size wires stay as limbs.
    let opened_nav_commitment = nav_commitment_target(builder, nav, &nav_rand);
    builder.connect_hashes(
        compliance_pis.proof_data.nav_commitment,
        opened_nav_commitment,
    );
    let ceiling_nav = NavTarget {
        size: size_ceiling,
        mth: mth_ceiling,
    };
    let computed_nav_ceiling = nav_root_target(builder, ceiling_nav);
    builder.connect_hashes(nav_ceiling, computed_nav_ceiling);
    verify_nflog_consistency(
        builder,
        nav.size,
        nav.mth,
        size_ceiling,
        mth_ceiling,
        &nav_consistency,
    );

    // 7. The last PI is fixed to this build's compile-time network.
    let expected_network_id = network_id_target(builder, network);
    builder.connect_hashes(network_id, expected_network_id);

    // Frozen declaration order from §2.5. Non-Poseidon byte strings are
    // big-endian integers exposed as little-endian u32 limbs.
    let subject_limbs = be_bytes32_to_u32_limbs(builder, &subject);
    let txid_limbs = be_bytes32_to_u32_limbs(builder, &anchor_txid);
    let block_hash_limbs = be_bytes32_to_u32_limbs(builder, &anchor_block_hash);
    let anchor_pk_limbs = be_bytes32_to_u32_limbs(builder, &anchor_pk);
    let anchor_r_limbs = be_bytes32_to_u32_limbs(builder, &anchor_r);
    builder.register_public_inputs(&subject_limbs);
    builder.register_public_inputs(&asset_id.elements);
    builder.register_public_inputs(&balance.limbs);
    builder.register_public_inputs(&nav_ceiling.elements);
    builder.register_public_input(size_ceiling.lo);
    builder.register_public_input(size_ceiling.hi);
    builder.register_public_inputs(&txid_limbs);
    builder.register_public_inputs(&block_hash_limbs);
    builder.register_public_inputs(&anchor_height_limbs);
    builder.register_public_inputs(&anchor_pk_limbs);
    builder.register_public_inputs(&anchor_r_limbs);
    builder.register_public_inputs(&network_id.elements);
    assert_eq!(
        builder.num_public_inputs(),
        60,
        "C_balance must expose exactly 60 application public inputs"
    );

    BalanceTargets {
        public: BalancePublicInputsTarget {
            subject,
            asset_id,
            balance,
            nav_ceiling,
            size_ceiling,
            anchor_txid,
            anchor_block_hash,
            anchor_height_limbs,
            anchor_pk,
            anchor_r,
            network_id,
        },
        witness: BalanceWitnessTargets {
            account_state,
            compliance_proof,
            nav,
            nav_rand,
            nav_consistency,
            mth_ceiling,
            spend_record,
            r_prime,
        },
    }
}
