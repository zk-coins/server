//! Production host bridge for the frozen spec-v1.1 `C` and `C_balance`
//! circuits.
//!
//! The witness setters in this module are the production counterparts of the
//! original compliance and balance circuit fixtures. They deliberately build
//! no constraints: the frozen circuits remain owned by
//! `zkcoins-program-plonky2`.

use std::sync::OnceLock;

use anyhow::{bail, ensure, Context, Result};
use num::BigUint;
use plonky2::field::secp256k1_base::Secp256K1Base;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField, PrimeField64};
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierOnlyCircuitData};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
use sha2::{Digest, Sha256};

use shared::spec_v1::{
    self as host, AccountState, Address, Coin, CoinHistProof, CoinHistState, CoinTemplate,
    HashDigest, Nav, ProofData, TreeKind, ZERO_HASH,
};
use zkcoins_program_plonky2::circuit::balance::{build_c_balance_circuit, BalanceCircuit};
use zkcoins_program_plonky2::circuit::compliance::{
    build_skeleton_circuit, AccountStateTarget, AssetIssuanceTarget, InputAuthTarget,
    InputCoinTarget, Network, OutputTemplateTarget, ReceivedAuthTarget, ReceivedCoinTarget,
    SkeletonCircuit, MAX_ACCOUNT_ASSETS, MAX_OUTPUT_MERKLE_DEPTH, MAX_RX_COINS, MAX_TX_INPUTS,
    MAX_TX_OUTPUTS,
};
use zkcoins_program_plonky2::circuit::gadgets::biguint::WitnessBigUint;
use zkcoins_program_plonky2::circuit::gadgets::curve::AffinePointTarget;
use zkcoins_program_plonky2::circuit::gadgets::curve_types::{
    lift_x_even_y, AffinePoint, Curve, CurveScalar, Secp256K1,
};
use zkcoins_program_plonky2::circuit::gadgets::nflog_consistency::H_MAX;
use zkcoins_program_plonky2::circuit::gadgets::nonnative::NonNativeTarget;
use zkcoins_program_plonky2::circuit::gadgets::u128_arith::U128Target;
use zkcoins_program_plonky2::{C, D, F};

/// A proof emitted by the frozen cyclic compliance circuit `C`.
pub type ComplianceProof = ProofWithPublicInputs<F, C, D>;

/// A proof emitted by the frozen non-cyclic balance circuit `C_balance`.
pub type BalanceProof = ProofWithPublicInputs<F, C, D>;

/// The recursive branch selected for a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TransitionMode {
    InitialProof,
    AccountUpdateProof,
}

/// A conditional-NAV commitment opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NavOpening {
    pub nav: Nav,
    pub nav_rand: [u8; 32],
}

/// Clause-2 authorization and clause-8 history evidence for one spent coin.
#[derive(Clone, Debug)]
pub struct InputAuthorization {
    pub creating_prev_ash: HashDigest,
    pub coin_index: u32,
    pub history_proof: CoinHistProof,
}

/// Membership of an output coin in its creating proof's output tree.
#[derive(Clone, Debug)]
pub struct OutputInclusionProof {
    pub leaf_index: u32,
    pub depth: u8,
    /// Bottom-to-top siblings. At most `MAX_OUTPUT_MERKLE_DEPTH`.
    pub siblings: Vec<HashDigest>,
}

/// The on-chain nullifier and sign-to-contract opening for a transition.
#[derive(Clone, Debug)]
pub struct NullifierOpening {
    pub public_key: [u8; 32],
    pub signature_r: [u8; 32],
    /// X-only, even-y encoding of the pre-tweak point `R'`.
    pub r_prime: [u8; 32],
}

/// Clause-10 provenance, accumulator, and history evidence for one receipt.
#[derive(Clone, Debug)]
pub struct ReceivedAuthorization {
    pub creating_proof: ComplianceProof,
    pub output_inclusion: OutputInclusionProof,
    pub creating_prev_ash: HashDigest,
    pub creating_nullifier: NullifierOpening,
    /// Host-format RFC-6962 path (deepest/leaf-first).
    pub creating_nav_inclusion: Vec<HashDigest>,
    pub pos_create: u64,
    pub creating_nav_opening: NavOpening,
    /// Host-format RFC-6962 consistency proof.
    pub creating_nav_consistency: Vec<HashDigest>,
    pub history_proof: CoinHistProof,
}

/// Optional token-standard-1/2 issuance witness.
#[derive(Clone, Debug)]
pub struct AssetIssuance {
    pub asset_id: HashDigest,
    pub creator_pubkey: [u8; 32],
    pub issuance_version: u8,
    pub name_hash: [u8; 32],
    pub decimals: u8,
    pub amount: u128,
    pub terms_hash: HashDigest,
    /// Zero for token standard 1.
    pub cap_total: u128,
    /// All-zero for token standard 1.
    pub terms_salt: [u8; 32],
}

/// Wallet-produced BIP-340+S2C authorization.
#[derive(Clone, Debug)]
pub struct TransitionSignature {
    /// The x-only key `Pk_i`; it must equal
    /// `prev_account_state.current_pubkey`.
    pub pk_i: [u8; 32],
    /// Canonical BIP-340 signature `bytes(R) || bytes(s)`.
    pub signature: [u8; 64],
    /// X-only, even-y encoding of the S2C pre-tweak point `R'`.
    pub r_prime: [u8; 32],
}

impl TransitionSignature {
    pub fn signature_r(&self) -> [u8; 32] {
        self.signature[..32]
            .try_into()
            .expect("a 64-byte signature has a 32-byte R")
    }

    pub fn signature_s(&self) -> [u8; 32] {
        self.signature[32..]
            .try_into()
            .expect("a 64-byte signature has a 32-byte s")
    }
}

/// Clause-1 predecessor anchoring for an account-update proof.
#[derive(Clone, Debug)]
pub struct PredecessorNullifier {
    pub nullifier: NullifierOpening,
    /// Host-format RFC-6962 path (deepest/leaf-first).
    pub nav_inclusion: Vec<HashDigest>,
    pub position: u64,
}

/// Complete host witness for one mint, send, or receive transition.
///
/// Compact vectors represent active-prefix circuit slots. Inactive slots are
/// filled canonically by the bridge. Coin-history proofs retain their semantic
/// locations: inputs occupy slots 0..8, outputs 8..16, and receipts 16..20.
#[derive(Clone, Debug)]
pub struct TransitionWitness {
    pub mode: TransitionMode,
    pub prev_account_state: AccountState,
    pub new_account_state: AccountState,
    pub input_coins: Vec<Coin>,
    pub input_auth: Vec<InputAuthorization>,
    pub output_templates: Vec<CoinTemplate>,
    pub output_coins: Vec<Coin>,
    /// One entry per output. A self-output requires `Some(Absent)`; an
    /// external output must use `None` because clause 8 does not admit it.
    pub output_history_proofs: Vec<Option<CoinHistProof>>,
    pub received_coins: Vec<Coin>,
    pub received_auth: Vec<ReceivedAuthorization>,
    pub asset_issuance: Option<AssetIssuance>,
    pub nk: [u8; 32],
    pub nav: Nav,
    pub nav_rand: [u8; 32],
    pub prev_nav_opening: Option<NavOpening>,
    /// Host-format RFC-6962 consistency proof from the predecessor NAV to
    /// `nav`; empty for `InitialProof`.
    pub nav_consistency: Vec<HashDigest>,
    pub next_pubkey: [u8; 32],
    pub npk_rand: [u8; 32],
    pub transition_signature: TransitionSignature,
    /// Required and genuine for `AccountUpdateProof`; absent for
    /// `InitialProof`, where the bridge installs the circuit's base proof.
    pub prev_proof: Option<ComplianceProof>,
    pub predecessor_nullifier: Option<PredecessorNullifier>,
}

/// A genuine transition proof and its application public outputs.
#[derive(Clone, Debug)]
pub struct ProvedTransition {
    pub proof: ComplianceProof,
    /// Extracted from `proof.public_inputs`, not trusted from the witness.
    pub proof_data: ProofData,
    pub consumed_pubkey: [u8; 32],
    pub network_id: HashDigest,
}

/// Public Bitcoin anchor metadata disclosed by a balance attestation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceAnchor {
    pub txid: [u8; 32],
    pub block_hash: [u8; 32],
    pub height: u64,
    pub public_key: [u8; 32],
    pub signature_r: [u8; 32],
}

/// Public statement carried by `C_balance`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalanceAttestationStatement {
    pub subject: Address,
    pub asset_id: HashDigest,
    pub balance: u128,
    pub nav_ceiling: Nav,
    pub anchor: BalanceAnchor,
}

/// Complete hidden/public witness for `C_balance`.
#[derive(Clone, Debug)]
pub struct AttestationWitness {
    pub statement: BalanceAttestationStatement,
    pub account_state: AccountState,
    pub compliance_proof: ComplianceProof,
    pub nav_opening: NavOpening,
    /// Host-format RFC-6962 consistency proof from `nav_opening.nav` to
    /// `statement.nav_ceiling`.
    pub nav_consistency: Vec<HashDigest>,
    /// X-only, even-y S2C opening of `statement.anchor.signature_r`.
    pub r_prime: [u8; 32],
}

/// A genuine balance proof and the public statement it attests.
#[derive(Clone, Debug)]
pub struct ProvedAttestation {
    pub proof: BalanceProof,
    pub statement: BalanceAttestationStatement,
    pub network_id: HashDigest,
}

/// Cached production prover/verifier for one compile-time network.
///
/// `C` and `C_balance` are each built at most once per network per process.
#[derive(Clone, Copy, Debug)]
pub struct ProverBridge {
    network: Network,
}

impl ProverBridge {
    /// Select a network and eagerly initialize its cached compliance circuit.
    pub fn new(network: Network) -> Self {
        let _ = compliance_circuit(network);
        Self { network }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn compliance_gate_count(&self) -> usize {
        compliance_circuit(self.network).gate_count
    }

    pub fn balance_gate_count(&self) -> usize {
        balance_circuit(self.network).gate_count
    }

    /// Assemble all `ComplianceTargets`, then produce a genuine cyclic proof.
    pub fn prove_transition(&self, witness: &TransitionWitness) -> Result<ProvedTransition> {
        let circuit = compliance_circuit(self.network);
        if let Some(predecessor) = &witness.prev_proof {
            self.verify_transition(predecessor)
                .context("transition predecessor proof is unacceptable")?;
        }
        for (index, received) in witness.received_auth.iter().enumerate() {
            self.verify_transition(&received.creating_proof)
                .with_context(|| format!("received coin {index} creating proof is unacceptable"))?;
        }
        let expected = validate_transition(witness, self.network)?;
        let partial = assemble_transition_witness(circuit, witness, &circuit.data.verifier_only)?;
        let proof = circuit
            .data
            .prove(partial)
            .context("compliance proving failed")?;
        let (proof_data, consumed_pubkey, proof_network_id) =
            extract_transition_public_inputs(&proof)?;
        ensure!(
            proof_data == expected,
            "proved transition public inputs differ from host-derived ProofData"
        );
        ensure!(
            consumed_pubkey == witness.prev_account_state.current_pubkey,
            "proved consumed_pubkey differs from the consumed account key"
        );
        ensure!(
            proof_network_id == network_id(self.network),
            "proved network_id differs from the bridge network"
        );
        Ok(ProvedTransition {
            proof,
            proof_data,
            consumed_pubkey,
            network_id: proof_network_id,
        })
    }

    /// Verify a cyclic transition proof under both mandatory acceptance
    /// obligations: ordinary Plonky2 verification and explicit cyclic
    /// verifier-data pinning.
    ///
    /// This is necessary but not sufficient for node acceptance. The caller
    /// **must additionally** open `ProofData.nav_commitment` and compare its
    /// `(size, mth)` with the caller's own >=6-confirmation-final canonical
    /// NfLog, and perform the applicable first-occurrence on-chain anchor
    /// checks. Those host/node responsibilities are outside this bridge
    /// (P1-E.2/P1-G).
    pub fn verify_transition(&self, proof: &ComplianceProof) -> Result<()> {
        let circuit = compliance_circuit(self.network);
        circuit
            .data
            .verify(proof.clone())
            .context("compliance proof verification failed")?;
        check_cyclic_proof_verifier_data(proof, &circuit.data.verifier_only, &circuit.data.common)
            .context("compliance proof cyclic verifier-data tail is not canonical")?;
        Ok(())
    }

    /// Re-extract every application public input from the proof and bind it
    /// to the convenience fields carried by `ProvedTransition`.
    ///
    /// Callers must run this before trusting `proof_data`, `consumed_pubkey`,
    /// or `network_id`: those wrapper fields are independently mutable and
    /// are not authenticated unless compared with `proof.public_inputs`.
    pub(crate) fn verify_proved_transition_wrapper(
        &self,
        proved: &ProvedTransition,
    ) -> Result<ProofData> {
        let (proof_data, consumed_pubkey, proof_network_id) =
            extract_transition_public_inputs(&proved.proof)
                .context("re-extract proved transition public inputs")?;
        ensure!(
            proof_data == proved.proof_data,
            "ProvedTransition.proof_data differs from proof public inputs"
        );
        ensure!(
            consumed_pubkey == proved.consumed_pubkey,
            "ProvedTransition.consumed_pubkey differs from proof public inputs"
        );
        ensure!(
            proof_network_id == proved.network_id,
            "ProvedTransition.network_id differs from proof public inputs"
        );
        ensure!(
            proof_network_id == network_id(self.network),
            "proved transition network_id differs from the bridge network"
        );
        Ok(proof_data)
    }

    /// Assemble every `C_balance` target and produce a genuine non-cyclic
    /// balance-attestation proof.
    pub fn prove_attestation(&self, witness: &AttestationWitness) -> Result<ProvedAttestation> {
        self.verify_transition(&witness.compliance_proof)
            .context("attestation embeds an unacceptable compliance proof")?;
        validate_attestation(witness)?;
        let circuit = balance_circuit(self.network);
        let partial = assemble_attestation_witness(circuit, witness, self.network)?;
        let proof = circuit
            .data
            .prove(partial)
            .context("balance-attestation proving failed")?;
        Ok(ProvedAttestation {
            proof,
            statement: witness.statement,
            network_id: network_id(self.network),
        })
    }

    /// Verify a non-cyclic `C_balance` proof with ordinary Plonky2
    /// verification. `C_balance` itself pins the embedded `C` proof's
    /// verifier-data tail, so no outer cyclic-tail check applies here.
    ///
    /// This is necessary but not sufficient for acceptance. The caller
    /// **must additionally** establish from its own >=6-confirmation-final
    /// scan that `nav_ceiling`/`size_ceiling` is canonical, and that the
    /// disclosed `(Pk_anchor, R_anchor)` is the completed first occurrence at
    /// the disclosed Bitcoin anchor. Those §5.7 host checks are outside this
    /// bridge (P1-E.2/P1-G).
    pub fn verify_attestation(&self, proof: &BalanceProof) -> Result<()> {
        balance_circuit(self.network)
            .data
            .verify(proof.clone())
            .context("balance-attestation proof verification failed")
    }
}

fn compliance_circuit(network: Network) -> &'static SkeletonCircuit {
    static MAINNET: OnceLock<SkeletonCircuit> = OnceLock::new();
    static TESTNET: OnceLock<SkeletonCircuit> = OnceLock::new();
    static REGTEST: OnceLock<SkeletonCircuit> = OnceLock::new();
    let cache = match network {
        Network::Mainnet => &MAINNET,
        Network::Testnet => &TESTNET,
        Network::Regtest => &REGTEST,
    };
    cache.get_or_init(|| {
        build_skeleton_circuit(CircuitConfig::standard_recursion_zk_config(), network)
    })
}

fn balance_circuit(network: Network) -> &'static BalanceCircuit {
    static MAINNET: OnceLock<BalanceCircuit> = OnceLock::new();
    static TESTNET: OnceLock<BalanceCircuit> = OnceLock::new();
    static REGTEST: OnceLock<BalanceCircuit> = OnceLock::new();
    let cache = match network {
        Network::Mainnet => &MAINNET,
        Network::Testnet => &TESTNET,
        Network::Regtest => &REGTEST,
    };
    cache.get_or_init(|| build_c_balance_circuit(compliance_circuit(network), network))
}

fn network_id(network: Network) -> HashDigest {
    match network {
        Network::Mainnet => host::network_id_mainnet(),
        Network::Testnet => host::network_id_testnet(),
        Network::Regtest => host::network_id_regtest(),
    }
}

fn validate_transition(w: &TransitionWitness, network: Network) -> Result<ProofData> {
    ensure!(
        w.input_coins.len() <= MAX_TX_INPUTS,
        "too many input coins: {} > {}",
        w.input_coins.len(),
        MAX_TX_INPUTS
    );
    ensure!(
        w.input_auth.len() == w.input_coins.len(),
        "input_auth length must equal input_coins length"
    );
    ensure!(
        w.output_templates.len() <= MAX_TX_OUTPUTS,
        "too many outputs: {} > {}",
        w.output_templates.len(),
        MAX_TX_OUTPUTS
    );
    ensure!(
        w.output_coins.len() == w.output_templates.len(),
        "output_coins length must equal output_templates length"
    );
    ensure!(
        w.output_history_proofs.len() == w.output_templates.len(),
        "output_history_proofs length must equal output_templates length"
    );
    ensure!(
        w.received_coins.len() <= MAX_RX_COINS,
        "too many received coins: {} > {}",
        w.received_coins.len(),
        MAX_RX_COINS
    );
    ensure!(
        w.received_auth.len() == w.received_coins.len(),
        "received_auth length must equal received_coins length"
    );
    ensure!(
        w.prev_account_state.balances.len() <= MAX_ACCOUNT_ASSETS
            && w.new_account_state.balances.len() <= MAX_ACCOUNT_ASSETS,
        "account balance count exceeds the circuit maximum"
    );
    ensure!(
        w.transition_signature.pk_i == w.prev_account_state.current_pubkey,
        "transition signature pk_i does not equal prev_account_state.current_pubkey"
    );
    ensure!(
        w.next_pubkey == w.new_account_state.current_pubkey,
        "next_pubkey does not equal new_account_state.current_pubkey"
    );
    ensure!(
        w.prev_account_state.owner == w.new_account_state.owner,
        "account owner changed across transition"
    );
    ensure!(
        w.prev_account_state.nk_commit == w.new_account_state.nk_commit,
        "nk_commit changed across transition"
    );
    ensure!(
        w.new_account_state.send_counter
            == w.prev_account_state
                .send_counter
                .checked_add(1)
                .context("send_counter overflow")?,
        "new send_counter must increment by exactly one"
    );
    ensure!(
        host::nk_commit(&w.nk) == w.prev_account_state.nk_commit,
        "nk does not open prev_account_state.nk_commit"
    );

    match w.mode {
        TransitionMode::InitialProof => {
            ensure!(
                w.prev_proof.is_none(),
                "InitialProof must not carry prev_proof"
            );
            ensure!(
                w.prev_nav_opening.is_none(),
                "InitialProof must not carry prev_nav_opening"
            );
            ensure!(
                w.predecessor_nullifier.is_none(),
                "InitialProof must not carry predecessor_nullifier"
            );
            ensure!(
                w.nav_consistency.is_empty(),
                "InitialProof empty-prefix consistency proof must be empty"
            );
        }
        TransitionMode::AccountUpdateProof => {
            ensure!(
                w.prev_proof.is_some(),
                "AccountUpdateProof requires a genuine prev_proof"
            );
            let prev_nav = w
                .prev_nav_opening
                .context("AccountUpdateProof requires prev_nav_opening")?;
            ensure!(
                w.predecessor_nullifier.is_some(),
                "AccountUpdateProof requires predecessor_nullifier"
            );
            validate_consistency_proof(
                &w.nav_consistency,
                prev_nav.nav.size,
                w.nav.size,
                "predecessor NAV",
            )?;
        }
    }

    canonical_x_point(&w.transition_signature.pk_i, "transition public key")?;
    canonical_base(&w.transition_signature.signature_r(), "signature R")?;
    let s = canonical_scalar(&w.transition_signature.signature_s(), "signature s")?;
    ensure!(!s.is_zero(), "signature s must be non-zero");
    canonical_x_point(&w.transition_signature.r_prime, "signature R'")?;

    let prev_ash =
        host::account_state_hash(&w.prev_account_state).context("hash previous account state")?;
    for (index, ((template, coin), history)) in w
        .output_templates
        .iter()
        .zip(&w.output_coins)
        .zip(&w.output_history_proofs)
        .enumerate()
    {
        let expected = Coin {
            identifier: host::coin_identifier(
                prev_ash,
                &template.recipient.0,
                template.asset_id,
                template.amount,
                index as u32,
            ),
            recipient: template.recipient,
            amount: template.amount,
            asset_id: template.asset_id,
        };
        ensure!(
            *coin == expected,
            "output coin {index} does not match its template and creating prev_ash"
        );
        let is_self = template.recipient == w.prev_account_state.owner;
        ensure!(
            is_self == history.is_some(),
            "output {index} history proof must be present exactly for self outputs"
        );
        if let Some(proof) = history {
            validate_history_proof(proof, CoinHistState::Absent, "self-output history proof")?;
        }
    }
    for auth in &w.input_auth {
        validate_history_proof(
            &auth.history_proof,
            CoinHistState::Admitted,
            "input history proof",
        )?;
    }
    for auth in &w.received_auth {
        validate_history_proof(
            &auth.history_proof,
            CoinHistState::Absent,
            "received history proof",
        )?;
        ensure!(
            auth.output_inclusion.siblings.len() <= MAX_OUTPUT_MERKLE_DEPTH,
            "received output inclusion path exceeds circuit depth"
        );
        ensure!(
            usize::from(auth.output_inclusion.depth) == auth.output_inclusion.siblings.len(),
            "received output inclusion depth does not match sibling count"
        );
        fill_inclusion_slots(&auth.creating_nav_inclusion)?;
        validate_consistency_proof(
            &auth.creating_nav_consistency,
            auth.creating_nav_opening.nav.size,
            w.nav.size,
            "creating NAV",
        )?;
        canonical_x_point(
            &auth.creating_nullifier.public_key,
            "creating nullifier public key",
        )?;
        canonical_base(&auth.creating_nullifier.signature_r, "creating nullifier R")?;
        canonical_x_point(&auth.creating_nullifier.r_prime, "creating nullifier R'")?;
    }
    if let Some(predecessor) = &w.predecessor_nullifier {
        fill_inclusion_slots(&predecessor.nav_inclusion)?;
        canonical_x_point(
            &predecessor.nullifier.public_key,
            "predecessor nullifier public key",
        )?;
        canonical_base(
            &predecessor.nullifier.signature_r,
            "predecessor nullifier R",
        )?;
        canonical_x_point(&predecessor.nullifier.r_prime, "predecessor nullifier R'")?;
    }
    if matches!(w.mode, TransitionMode::InitialProof) {
        validate_consistency_proof(&w.nav_consistency, 0, w.nav.size, "initial NAV")?;
    }
    if let Some(issuance) = &w.asset_issuance {
        ensure!(
            matches!(issuance.issuance_version, 1 | 2),
            "unsupported issuance version {}",
            issuance.issuance_version
        );
    }

    let output_ids: Vec<_> = w.output_coins.iter().map(|coin| coin.identifier).collect();
    let nullifiers: Vec<_> = w
        .input_coins
        .iter()
        .map(|coin| host::nullifier(&w.nk, coin.identifier))
        .collect();
    let proof_data = ProofData {
        new_account_state_hash: host::account_state_hash(&w.new_account_state)
            .context("hash new account state")?,
        output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &output_ids),
        input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &nullifiers),
        coin_history_root: w.new_account_state.coin_history_root,
        nav_commitment: host::nav_commitment(w.nav.root(), &w.nav_rand),
        npk_commit: host::npk_commit(&w.next_pubkey, &w.npk_rand),
    };

    // Host preflight: fail fast on an invalid or wrong-network BIP-340+S2C
    // signature before the expensive prover. `C` remains the authoritative
    // in-circuit verifier.
    let h_proof_data = host::hash_proof_data(&host::serialize_proof_data(&proof_data));
    verify_transition_signature(
        &w.transition_signature,
        &h_proof_data,
        network.m_state_bytes(),
    )?;
    Ok(proof_data)
}

fn validate_attestation(w: &AttestationWitness) -> Result<()> {
    ensure!(
        w.statement.subject == w.account_state.owner,
        "attestation subject does not equal account owner"
    );
    let expected_balance = w
        .account_state
        .balances
        .get(&host::digest_to_bytes(&w.statement.asset_id))
        .copied()
        .unwrap_or(0);
    ensure!(
        w.statement.balance == expected_balance,
        "claimed balance does not equal the account-state balance"
    );
    ensure!(
        w.nav_opening.nav.size <= w.statement.nav_ceiling.size,
        "attested NAV exceeds the disclosed ceiling"
    );
    validate_consistency_proof(
        &w.nav_consistency,
        w.nav_opening.nav.size,
        w.statement.nav_ceiling.size,
        "attestation NAV",
    )?;
    ensure!(
        w.statement.anchor.height <= u64::MAX,
        "anchor height is not a u64"
    );
    canonical_x_point(&w.statement.anchor.public_key, "attestation anchor key")?;
    canonical_base(&w.statement.anchor.signature_r, "attestation anchor R")?;
    canonical_x_point(&w.r_prime, "attestation R'")?;
    Ok(())
}

fn validate_history_proof(
    proof: &CoinHistProof,
    expected: CoinHistState,
    label: &str,
) -> Result<()> {
    ensure!(
        proof.state == expected,
        "{label} has state {:?}, expected {:?}",
        proof.state,
        expected
    );
    ensure!(
        proof.siblings.len() == 256,
        "{label} must contain exactly 256 siblings"
    );
    Ok(())
}

fn validate_consistency_proof(proof: &[HashDigest], m: u64, n: u64, label: &str) -> Result<()> {
    ensure!(m <= n, "{label} prefix size {m} exceeds final size {n}");
    if m == 0 || m == n {
        ensure!(
            proof.is_empty(),
            "{label} special-case consistency proof must be empty"
        );
    } else {
        ensure!(
            proof.len() <= H_MAX + 1,
            "{label} consistency proof exceeds H_MAX"
        );
    }
    Ok(())
}

fn assemble_transition_witness(
    circuit: &SkeletonCircuit,
    w: &TransitionWitness,
    own_verifier_data: &VerifierOnlyCircuitData<C, D>,
) -> Result<PartialWitness<F>> {
    let targets = &circuit.targets;
    let mut witness = PartialWitness::new();
    set_account_state(
        &mut witness,
        targets.prev_account_state,
        &w.prev_account_state,
    )?;
    set_account_state(
        &mut witness,
        targets.new_account_state,
        &w.new_account_state,
    )?;
    witness.set_hash_target(
        targets.prev_account_state_hash,
        host::account_state_hash(&w.prev_account_state)
            .context("hash previous account state for witness")?,
    )?;
    set_bytes(&mut witness, &targets.nk, &w.nk)?;

    for index in 0..MAX_TX_INPUTS {
        set_input_slot(
            &mut witness,
            targets.input_coins[index],
            targets.input_auth[index],
            w.input_coins.get(index).zip(w.input_auth.get(index)),
        )?;
    }
    for index in 0..MAX_RX_COINS {
        set_received_slot(
            &mut witness,
            targets.received_coins[index],
            &targets.received_auth[index],
            w.received_coins.get(index).zip(w.received_auth.get(index)),
            circuit,
            w.nav.size,
        )?;
    }
    set_output_templates(&mut witness, &targets.output_templates, &w.output_templates)?;
    set_issuance(
        &mut witness,
        targets.asset_issuance,
        w.asset_issuance.as_ref(),
    )?;

    let zero_history = vec![ZERO_HASH; 256];
    for index in 0..MAX_TX_INPUTS {
        let siblings = w
            .input_auth
            .get(index)
            .map(|auth| auth.history_proof.siblings.as_slice())
            .unwrap_or(&zero_history);
        set_history_path(
            &mut witness,
            &targets.history_update_paths[index].siblings,
            siblings,
        )?;
    }
    for index in 0..MAX_TX_OUTPUTS {
        let siblings = w
            .output_history_proofs
            .get(index)
            .and_then(Option::as_ref)
            .map(|proof| proof.siblings.as_slice())
            .unwrap_or(&zero_history);
        set_history_path(
            &mut witness,
            &targets.history_update_paths[MAX_TX_INPUTS + index].siblings,
            siblings,
        )?;
    }
    for index in 0..MAX_RX_COINS {
        let siblings = w
            .received_auth
            .get(index)
            .map(|auth| auth.history_proof.siblings.as_slice())
            .unwrap_or(&zero_history);
        set_history_path(
            &mut witness,
            &targets.history_update_paths[MAX_TX_INPUTS + MAX_TX_OUTPUTS + index].siblings,
            siblings,
        )?;
    }

    set_bytes(&mut witness, &targets.next_pubkey, &w.next_pubkey)?;
    set_bytes(&mut witness, &targets.npk_rand, &w.npk_rand)?;
    set_bytes(
        &mut witness,
        &targets.consumed_pubkey,
        &w.prev_account_state.current_pubkey,
    )?;
    witness.set_hash_target(
        targets.proof_data.coin_history_root,
        w.new_account_state.coin_history_root,
    )?;
    witness.set_hash_target(
        targets.proof_data.nav_commitment,
        host::nav_commitment(w.nav.root(), &w.nav_rand),
    )?;

    set_nonnative(
        &mut witness,
        &targets.txn_sig_rx,
        canonical_base(&w.transition_signature.signature_r(), "signature R")?,
    )?;
    set_nonnative(
        &mut witness,
        &targets.txn_sig_s,
        canonical_scalar(&w.transition_signature.signature_s(), "signature s")?,
    )?;
    set_point(
        &mut witness,
        &targets.s2c_r_prime,
        canonical_x_point(&w.transition_signature.r_prime, "signature R'")?,
    )?;

    let is_update = matches!(w.mode, TransitionMode::AccountUpdateProof);
    witness.set_bool_target(targets.recursion.is_account_update, is_update)?;
    let predecessor = w.prev_proof.as_ref().unwrap_or(&circuit.base_proof);
    witness.set_proof_with_pis_target(&targets.recursion.prev_proof, predecessor)?;
    witness.set_proof_with_pis_target(&targets.recursion.base_proof, &circuit.base_proof)?;
    witness.set_verifier_data_target(
        &targets.recursion.base_verifier_data,
        &circuit.base_verifier_data,
    )?;
    witness.set_verifier_data_target(&targets.recursion.own_verifier_data, own_verifier_data)?;

    witness.set_target(targets.nav.size, F::from_canonical_u64(w.nav.size))?;
    witness.set_hash_target(targets.nav.mth, w.nav.mth)?;
    set_bytes(&mut witness, &targets.nav_rand, &w.nav_rand)?;
    let prev_nav = w.prev_nav_opening.unwrap_or(NavOpening {
        nav: Nav {
            size: 0,
            mth: host::nflog_empty(),
        },
        nav_rand: [0u8; 32],
    });
    witness.set_target(
        targets.prev_nav_opening.nav.size,
        F::from_canonical_u64(prev_nav.nav.size),
    )?;
    witness.set_hash_target(targets.prev_nav_opening.nav.mth, prev_nav.nav.mth)?;
    set_bytes(
        &mut witness,
        &targets.prev_nav_opening.nav_rand,
        &prev_nav.nav_rand,
    )?;
    let consistency = fill_consistency_slots(&w.nav_consistency, prev_nav.nav.size, w.nav.size)?;
    for (&target, &value) in targets.nav_consistency.iter().zip(&consistency) {
        witness.set_hash_target(target, value)?;
    }

    let predecessor = w.predecessor_nullifier.as_ref();
    set_bytes(
        &mut witness,
        &targets.prev_state_nullifier.pk_prev,
        &predecessor.map_or([0u8; 32], |value| value.nullifier.public_key),
    )?;
    set_bytes(
        &mut witness,
        &targets.prev_state_nullifier.r_prev,
        &predecessor.map_or([0u8; 32], |value| value.nullifier.signature_r),
    )?;
    let predecessor_r_prime = predecessor
        .map(|value| canonical_x_point(&value.nullifier.r_prime, "predecessor R'"))
        .transpose()?
        .unwrap_or(Secp256K1::GENERATOR_AFFINE);
    set_point(
        &mut witness,
        &targets.prev_state_nullifier.r_prime_prev,
        predecessor_r_prime,
    )?;
    let inclusion = predecessor
        .map(|value| fill_inclusion_slots(&value.nav_inclusion))
        .transpose()?
        .unwrap_or([ZERO_HASH; H_MAX]);
    for (&target, &value) in targets
        .prev_state_nullifier
        .nav_inclusion
        .iter()
        .zip(&inclusion)
    {
        witness.set_hash_target(target, value)?;
    }
    witness.set_target(
        targets.prev_state_nullifier.pos_prev,
        F::from_canonical_u64(predecessor.map_or(0, |value| value.position)),
    )?;
    Ok(witness)
}

fn assemble_attestation_witness(
    circuit: &BalanceCircuit,
    w: &AttestationWitness,
    network: Network,
) -> Result<PartialWitness<F>> {
    let targets = &circuit.targets;
    let mut witness = PartialWitness::new();
    set_bytes(
        &mut witness,
        &targets.public.subject,
        &w.statement.subject.0,
    )?;
    witness.set_hash_target(targets.public.asset_id, w.statement.asset_id)?;
    set_u128(&mut witness, targets.public.balance, w.statement.balance)?;
    witness.set_hash_target(targets.public.nav_ceiling, w.statement.nav_ceiling.root())?;
    witness.set_target(
        targets.public.size_ceiling,
        F::from_canonical_u64(w.statement.nav_ceiling.size),
    )?;
    set_bytes(
        &mut witness,
        &targets.public.anchor_txid,
        &w.statement.anchor.txid,
    )?;
    set_bytes(
        &mut witness,
        &targets.public.anchor_block_hash,
        &w.statement.anchor.block_hash,
    )?;
    witness.set_target(
        targets.public.anchor_height_limbs[0],
        F::from_canonical_u32(w.statement.anchor.height as u32),
    )?;
    witness.set_target(
        targets.public.anchor_height_limbs[1],
        F::from_canonical_u32((w.statement.anchor.height >> 32) as u32),
    )?;
    set_bytes(
        &mut witness,
        &targets.public.anchor_pk,
        &w.statement.anchor.public_key,
    )?;
    set_bytes(
        &mut witness,
        &targets.public.anchor_r,
        &w.statement.anchor.signature_r,
    )?;
    witness.set_hash_target(targets.public.network_id, network_id(network))?;

    set_account_state(
        &mut witness,
        targets.witness.account_state,
        &w.account_state,
    )?;
    witness.set_proof_with_pis_target(&targets.witness.compliance_proof, &w.compliance_proof)?;
    witness.set_target(
        targets.witness.nav.size,
        F::from_canonical_u64(w.nav_opening.nav.size),
    )?;
    witness.set_hash_target(targets.witness.nav.mth, w.nav_opening.nav.mth)?;
    set_bytes(
        &mut witness,
        &targets.witness.nav_rand,
        &w.nav_opening.nav_rand,
    )?;
    let consistency = fill_consistency_slots(
        &w.nav_consistency,
        w.nav_opening.nav.size,
        w.statement.nav_ceiling.size,
    )?;
    for (target, value) in targets.witness.nav_consistency.into_iter().zip(consistency) {
        witness.set_hash_target(target, value)?;
    }
    witness.set_hash_target(targets.witness.mth_ceiling, w.statement.nav_ceiling.mth)?;
    set_bytes(
        &mut witness,
        &targets.witness.spend_record.public_key,
        &w.statement.anchor.public_key,
    )?;
    set_bytes(
        &mut witness,
        &targets.witness.spend_record.signature_r,
        &w.statement.anchor.signature_r,
    )?;
    set_point(
        &mut witness,
        &targets.witness.r_prime,
        canonical_x_point(&w.r_prime, "attestation R'")?,
    )?;
    Ok(witness)
}

fn set_bytes(
    witness: &mut PartialWitness<F>,
    targets: &[Target; 32],
    bytes: &[u8; 32],
) -> Result<()> {
    for (&target, &byte) in targets.iter().zip(bytes) {
        witness.set_target(target, F::from_canonical_u8(byte))?;
    }
    Ok(())
}

fn set_u128(witness: &mut PartialWitness<F>, target: U128Target, value: u128) -> Result<()> {
    for (index, limb) in target.limbs.into_iter().enumerate() {
        witness.set_target(limb, F::from_canonical_u32((value >> (32 * index)) as u32))?;
    }
    Ok(())
}

fn set_account_state(
    witness: &mut PartialWitness<F>,
    target: AccountStateTarget,
    state: &AccountState,
) -> Result<()> {
    set_bytes(witness, &target.owner, &state.owner.0)?;
    witness.set_hash_target(target.nk_commit, state.nk_commit)?;
    set_bytes(witness, &target.current_pubkey, &state.current_pubkey)?;
    witness.set_target(
        target.send_counter,
        F::from_canonical_u64(state.send_counter),
    )?;
    witness.set_hash_target(target.coin_history_root, state.coin_history_root)?;
    let balances: Vec<_> = state.balances.iter().collect();
    ensure!(
        balances.len() <= MAX_ACCOUNT_ASSETS,
        "account has too many balances"
    );
    for (index, slot) in target.balances.into_iter().enumerate() {
        if let Some((&asset_bytes, &amount)) = balances.get(index).copied() {
            let asset = host::digest_from_bytes(&asset_bytes)
                .context("account balance key is not a canonical digest")?;
            witness.set_bool_target(slot.active, true)?;
            witness.set_hash_target(slot.asset_id, asset)?;
            set_u128(witness, slot.amount, amount)?;
        } else {
            witness.set_bool_target(slot.active, false)?;
            witness.set_hash_target(slot.asset_id, ZERO_HASH)?;
            set_u128(witness, slot.amount, 0)?;
        }
    }
    Ok(())
}

fn set_input_slot(
    witness: &mut PartialWitness<F>,
    coin_target: InputCoinTarget,
    auth_target: InputAuthTarget,
    input: Option<(&Coin, &InputAuthorization)>,
) -> Result<()> {
    if let Some((coin, auth)) = input {
        witness.set_bool_target(coin_target.active, true)?;
        witness.set_hash_target(coin_target.identifier, coin.identifier)?;
        set_bytes(witness, &coin_target.recipient, &coin.recipient.0)?;
        set_u128(witness, coin_target.amount, coin.amount)?;
        witness.set_hash_target(coin_target.asset_id, coin.asset_id)?;
        witness.set_hash_target(auth_target.creating_prev_ash, auth.creating_prev_ash)?;
        witness.set_target(
            auth_target.coin_index,
            F::from_canonical_u32(auth.coin_index),
        )?;
    } else {
        witness.set_bool_target(coin_target.active, false)?;
        witness.set_hash_target(coin_target.identifier, ZERO_HASH)?;
        set_bytes(witness, &coin_target.recipient, &[0u8; 32])?;
        set_u128(witness, coin_target.amount, 0)?;
        witness.set_hash_target(coin_target.asset_id, ZERO_HASH)?;
        witness.set_hash_target(auth_target.creating_prev_ash, ZERO_HASH)?;
        witness.set_target(auth_target.coin_index, F::ZERO)?;
    }
    Ok(())
}

fn set_received_slot(
    witness: &mut PartialWitness<F>,
    coin_target: ReceivedCoinTarget,
    auth_target: &ReceivedAuthTarget,
    received: Option<(&Coin, &ReceivedAuthorization)>,
    circuit: &SkeletonCircuit,
    final_nav_size: u64,
) -> Result<()> {
    witness.set_bool_target(coin_target.active, received.is_some())?;
    let coin = received.map(|(coin, _)| coin);
    witness.set_hash_target(
        coin_target.identifier,
        coin.map_or(ZERO_HASH, |coin| coin.identifier),
    )?;
    set_bytes(
        witness,
        &coin_target.recipient,
        &coin.map_or([0u8; 32], |coin| coin.recipient.0),
    )?;
    set_u128(
        witness,
        coin_target.amount,
        coin.map_or(0, |coin| coin.amount),
    )?;
    witness.set_hash_target(
        coin_target.asset_id,
        coin.map_or(ZERO_HASH, |coin| coin.asset_id),
    )?;

    let auth = received.map(|(_, auth)| auth);
    witness.set_proof_with_pis_target(
        &auth_target.creating_proof,
        auth.map_or(&circuit.base_proof, |auth| &auth.creating_proof),
    )?;
    witness.set_target(
        auth_target.inclusion_leaf_index,
        F::from_canonical_u32(auth.map_or(0, |auth| auth.output_inclusion.leaf_index)),
    )?;
    witness.set_target(
        auth_target.inclusion_depth,
        F::from_canonical_u8(auth.map_or(0, |auth| auth.output_inclusion.depth)),
    )?;
    for (index, &target) in auth_target.inclusion_siblings.iter().enumerate() {
        witness.set_hash_target(
            target,
            auth.and_then(|auth| auth.output_inclusion.siblings.get(index))
                .copied()
                .unwrap_or(ZERO_HASH),
        )?;
    }
    witness.set_hash_target(
        auth_target.creating_prev_ash,
        auth.map_or(ZERO_HASH, |auth| auth.creating_prev_ash),
    )?;
    set_bytes(
        witness,
        &auth_target.pk_create,
        &auth.map_or([0u8; 32], |auth| auth.creating_nullifier.public_key),
    )?;
    set_bytes(
        witness,
        &auth_target.r_create,
        &auth.map_or([0u8; 32], |auth| auth.creating_nullifier.signature_r),
    )?;
    set_point(
        witness,
        &auth_target.r_prime_create,
        auth.map(|auth| canonical_x_point(&auth.creating_nullifier.r_prime, "creating R'"))
            .transpose()?
            .unwrap_or(Secp256K1::GENERATOR_AFFINE),
    )?;
    let inclusion = auth
        .map(|auth| fill_inclusion_slots(&auth.creating_nav_inclusion))
        .transpose()?
        .unwrap_or([ZERO_HASH; H_MAX]);
    for (&target, &value) in auth_target.creating_nav_inclusion.iter().zip(&inclusion) {
        witness.set_hash_target(target, value)?;
    }
    witness.set_target(
        auth_target.pos_create,
        F::from_canonical_u64(auth.map_or(0, |auth| auth.pos_create)),
    )?;
    let creating_nav = auth.map_or(
        Nav {
            size: 0,
            mth: host::nflog_empty(),
        },
        |auth| auth.creating_nav_opening.nav,
    );
    witness.set_target(
        auth_target.creating_nav_opening.nav.size,
        F::from_canonical_u64(creating_nav.size),
    )?;
    witness.set_hash_target(auth_target.creating_nav_opening.nav.mth, creating_nav.mth)?;
    set_bytes(
        witness,
        &auth_target.creating_nav_opening.nav_rand,
        &auth.map_or([0u8; 32], |auth| auth.creating_nav_opening.nav_rand),
    )?;
    let consistency = auth
        .map(|auth| {
            fill_consistency_slots(
                &auth.creating_nav_consistency,
                auth.creating_nav_opening.nav.size,
                final_nav_size,
            )
        })
        .transpose()?
        .unwrap_or([ZERO_HASH; 2 * H_MAX]);
    for (&target, &value) in auth_target
        .creating_nav_consistency
        .iter()
        .zip(&consistency)
    {
        witness.set_hash_target(target, value)?;
    }
    Ok(())
}

fn set_output_templates(
    witness: &mut PartialWitness<F>,
    targets: &[OutputTemplateTarget; MAX_TX_OUTPUTS],
    templates: &[CoinTemplate],
) -> Result<()> {
    for (index, target) in targets.iter().copied().enumerate() {
        if let Some(template) = templates.get(index) {
            witness.set_bool_target(target.active, true)?;
            set_bytes(witness, &target.recipient, &template.recipient.0)?;
            set_u128(witness, target.amount, template.amount)?;
            witness.set_hash_target(target.asset_id, template.asset_id)?;
        } else {
            witness.set_bool_target(target.active, false)?;
            set_bytes(witness, &target.recipient, &[0u8; 32])?;
            set_u128(witness, target.amount, 0)?;
            witness.set_hash_target(target.asset_id, ZERO_HASH)?;
        }
    }
    Ok(())
}

fn set_issuance(
    witness: &mut PartialWitness<F>,
    target: AssetIssuanceTarget,
    issuance: Option<&AssetIssuance>,
) -> Result<()> {
    witness.set_bool_target(target.present, issuance.is_some())?;
    witness.set_hash_target(
        target.asset_id,
        issuance.map_or(ZERO_HASH, |issuance| issuance.asset_id),
    )?;
    set_bytes(
        witness,
        &target.creator_pubkey,
        &issuance.map_or([0u8; 32], |issuance| issuance.creator_pubkey),
    )?;
    witness.set_target(
        target.issuance_version,
        F::from_canonical_u8(issuance.map_or(0, |issuance| issuance.issuance_version)),
    )?;
    set_bytes(
        witness,
        &target.name_hash,
        &issuance.map_or([0u8; 32], |issuance| issuance.name_hash),
    )?;
    witness.set_target(
        target.decimals,
        F::from_canonical_u8(issuance.map_or(0, |issuance| issuance.decimals)),
    )?;
    set_u128(
        witness,
        target.amount,
        issuance.map_or(0, |issuance| issuance.amount),
    )?;
    witness.set_hash_target(
        target.terms_hash,
        issuance.map_or(ZERO_HASH, |issuance| issuance.terms_hash),
    )?;
    set_u128(
        witness,
        target.cap_total,
        issuance.map_or(0, |issuance| issuance.cap_total),
    )?;
    set_bytes(
        witness,
        &target.terms_salt,
        &issuance.map_or([0u8; 32], |issuance| issuance.terms_salt),
    )?;
    Ok(())
}

fn set_history_path(
    witness: &mut PartialWitness<F>,
    targets: &[plonky2::hash::hash_types::HashOutTarget; 256],
    siblings: &[HashDigest],
) -> Result<()> {
    ensure!(
        siblings.len() == 256,
        "coin-history proof must have 256 siblings"
    );
    for (&target, &sibling) in targets.iter().zip(siblings) {
        witness.set_hash_target(target, sibling)?;
    }
    Ok(())
}

fn set_nonnative<FF: PrimeField>(
    witness: &mut PartialWitness<F>,
    target: &NonNativeTarget<FF>,
    value: FF,
) -> Result<()> {
    witness
        .set_biguint_target(target.value(), &value.to_canonical_biguint())
        .context("set non-native field witness")
}

fn set_point(
    witness: &mut PartialWitness<F>,
    target: &AffinePointTarget<Secp256K1>,
    point: AffinePoint<Secp256K1>,
) -> Result<()> {
    set_nonnative(witness, &target.x, point.x)?;
    set_nonnative(witness, &target.y, point.y)
}

fn field_bytes<FF: PrimeField>(value: FF) -> [u8; 32] {
    let encoded = value.to_canonical_biguint().to_bytes_be();
    assert!(encoded.len() <= 32);
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

/// Host-side BIP-340 + sign-to-contract preflight for a transition signature.
///
/// Accepts exactly the signatures produced by the test / wallet signer
/// (`R' + t·G` S2C tweak, even-y `R`, BIP-340 challenge over `m_state`).
fn verify_transition_signature(
    sig: &TransitionSignature,
    h_proof_data: &[u8; 32],
    m_state: &[u8],
) -> Result<()> {
    let mut tweak_preimage = Vec::with_capacity(64);
    tweak_preimage.extend_from_slice(&sig.r_prime);
    tweak_preimage.extend_from_slice(h_proof_data);
    let tweak_bytes: [u8; 32] = Sha256::digest(tweak_preimage).into();
    let tweak_integer = BigUint::from_bytes_be(&tweak_bytes);
    ensure!(
        tweak_integer < Secp256K1Scalar::order(),
        "transition signature S2C tweak is not a canonical secp256k1 scalar"
    );
    let tweak = Secp256K1Scalar::from_noncanonical_biguint(tweak_integer);

    let r_prime = canonical_x_point(&sig.r_prime, "transition signature R'")?;
    let r = (r_prime + (CurveScalar(tweak) * Secp256K1::GENERATOR_PROJECTIVE).to_affine())
        .to_affine();
    ensure!(
        !r.zero,
        "transition signature S2C nonce is the point at infinity"
    );
    ensure!(!is_odd(r.y), "transition signature S2C nonce has odd y");

    let rx_bytes = field_bytes(r.x);
    ensure!(
        rx_bytes.as_slice() == &sig.signature[..32],
        "transition signature R does not match S2C-tweaked nonce"
    );

    let mut challenge_preimage = Vec::with_capacity(64 + m_state.len());
    challenge_preimage.extend_from_slice(&rx_bytes);
    challenge_preimage.extend_from_slice(&sig.pk_i);
    challenge_preimage.extend_from_slice(m_state);
    let e = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(
        &tagged_hash(b"BIP0340/challenge", &challenge_preimage),
    ));

    let p = canonical_x_point(&sig.pk_i, "transition signature Pk_i")?;
    let s = canonical_scalar(&sig.signature_s(), "transition signature s")?;

    let s_g = (CurveScalar(s) * Secp256K1::GENERATOR_PROJECTIVE).to_affine();
    let rhs = (r + (CurveScalar(e) * p.to_projective()).to_affine()).to_affine();
    ensure!(s_g == rhs, "invalid transition signature");
    Ok(())
}

fn canonical_base(bytes: &[u8; 32], label: &str) -> Result<Secp256K1Base> {
    let integer = BigUint::from_bytes_be(bytes);
    ensure!(
        integer < Secp256K1Base::order(),
        "{label} is not a canonical secp256k1 base-field encoding"
    );
    Ok(Secp256K1Base::from_noncanonical_biguint(integer))
}

fn canonical_scalar(bytes: &[u8; 32], label: &str) -> Result<Secp256K1Scalar> {
    let integer = BigUint::from_bytes_be(bytes);
    ensure!(
        integer < Secp256K1Scalar::order(),
        "{label} is not a canonical secp256k1 scalar"
    );
    Ok(Secp256K1Scalar::from_noncanonical_biguint(integer))
}

fn canonical_x_point(bytes: &[u8; 32], label: &str) -> Result<AffinePoint<Secp256K1>> {
    lift_x_even_y(canonical_base(bytes, label)?)
        .with_context(|| format!("{label} does not lift to an even-y secp256k1 point"))
}

fn fill_inclusion_slots(path: &[HashDigest]) -> Result<[HashDigest; H_MAX]> {
    ensure!(path.len() <= H_MAX, "NfLog inclusion path exceeds H_MAX");
    let mut slots = [ZERO_HASH; H_MAX];
    for level in 0..path.len() {
        slots[level] = path[path.len() - 1 - level];
    }
    Ok(slots)
}

fn fill_consistency_slots(
    proof: &[HashDigest],
    mut m: u64,
    mut n: u64,
) -> Result<[HashDigest; 2 * H_MAX]> {
    ensure!(m <= n, "NfLog consistency prefix size exceeds final size");
    if m == 0 || m == n {
        ensure!(
            proof.is_empty(),
            "special NfLog consistency proof must be empty"
        );
        return Ok([ZERO_HASH; 2 * H_MAX]);
    }
    let mut b_at_terminal = true;
    let mut depth = 0usize;
    while m != n {
        let k = 1u64 << (64 - (n - 1).leading_zeros() - 1);
        if m <= k {
            n = k;
        } else {
            m -= k;
            n -= k;
            b_at_terminal = false;
        }
        depth += 1;
    }
    let mut slots = [ZERO_HASH; 2 * H_MAX];
    let (base, regular) = if b_at_terminal {
        (ZERO_HASH, proof)
    } else {
        ensure!(
            !proof.is_empty(),
            "right-turn consistency proof is missing its base digest"
        );
        (proof[0], &proof[1..])
    };
    ensure!(
        regular.len() == depth,
        "NfLog consistency proof length does not match its sizes"
    );
    ensure!(regular.len() <= H_MAX, "NfLog consistency proof too deep");
    for level in 0..regular.len() {
        slots[level] = regular[regular.len() - 1 - level];
    }
    slots[H_MAX] = base;
    Ok(slots)
}

fn extract_transition_public_inputs(
    proof: &ComplianceProof,
) -> Result<(ProofData, [u8; 32], HashDigest)> {
    ensure!(
        proof.public_inputs.len() == 108,
        "compliance proof has {} public inputs, expected 108",
        proof.public_inputs.len()
    );
    let digest = |offset: usize| HashOut {
        elements: proof.public_inputs[offset..offset + 4]
            .try_into()
            .expect("validated PI slice length"),
    };
    let proof_data = ProofData {
        new_account_state_hash: digest(0),
        output_coins_root: digest(4),
        input_nullifiers_root: digest(8),
        coin_history_root: digest(12),
        nav_commitment: digest(16),
        npk_commit: bytes_from_u32_le_limbs(&proof.public_inputs[20..28])?,
    };
    let consumed_pubkey = bytes_from_u32_le_limbs(&proof.public_inputs[28..36])?;
    Ok((proof_data, consumed_pubkey, digest(36)))
}

fn bytes_from_u32_le_limbs(limbs: &[F]) -> Result<[u8; 32]> {
    ensure!(limbs.len() == 8, "expected eight u32 limbs");
    let mut bytes = [0u8; 32];
    for (index, limb) in limbs.iter().enumerate() {
        let value = limb.to_canonical_u64();
        if value > u64::from(u32::MAX) {
            bail!("public byte-string limb is not a canonical u32");
        }
        let start = 28 - 4 * index;
        bytes[start..start + 4].copy_from_slice(&(value as u32).to_be_bytes());
    }
    Ok(bytes)
}

/// Crate-internal test helpers for BIP-340 + sign-to-contract transition signing.
///
/// Used by `state_engine` tests and the bridge's own fixtures so both share one
/// S2C+BIP-340 implementation rather than reimplementing the wallet signer.
#[cfg(test)]
pub(crate) mod test_signing {
    use num::BigUint;
    use plonky2::field::types::Field;
    use sha2::{Digest, Sha256};

    use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
    use zkcoins_program_plonky2::circuit::gadgets::curve_types::{
        AffinePoint, Curve, CurveScalar, Secp256K1,
    };

    use super::{
        extract_transition_public_inputs, field_bytes, is_odd, tagged_hash, Network, ProofData,
        ProvedTransition, TransitionSignature,
    };
    use shared::spec_v1 as host;

    #[derive(Clone)]
    pub(crate) struct TestSignature {
        pub(crate) transition: TransitionSignature,
        pub(crate) r_prime_point: AffinePoint<Secp256K1>,
    }

    pub(crate) fn deterministic_secret(label: &[u8]) -> Secp256K1Scalar {
        let digest = Sha256::digest(label);
        let scalar = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&digest));
        assert!(scalar.is_nonzero());
        scalar
    }

    pub(crate) fn normalized_key(
        secret: Secp256K1Scalar,
    ) -> (Secp256K1Scalar, AffinePoint<Secp256K1>, [u8; 32]) {
        let mut normalized_secret = secret;
        let mut public =
            (CurveScalar(normalized_secret) * Secp256K1::GENERATOR_PROJECTIVE).to_affine();
        if is_odd(public.y) {
            normalized_secret = -normalized_secret;
            public = -public;
        }
        (normalized_secret, public, field_bytes(public.x))
    }

    /// Sign `H(ProofData)` with BIP-340 + S2C for the given network's `m_state`.
    pub(crate) fn sign_transition(
        secret: Secp256K1Scalar,
        public: AffinePoint<Secp256K1>,
        proof_data: &ProofData,
        network: Network,
    ) -> TestSignature {
        let pk_bytes = field_bytes(public.x);
        let h_proof_data = host::hash_proof_data(&host::serialize_proof_data(proof_data));
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
            tweak_preimage.extend_from_slice(&h_proof_data);
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
            let mut challenge_preimage = Vec::with_capacity(64 + 32);
            challenge_preimage.extend_from_slice(&rx_bytes);
            challenge_preimage.extend_from_slice(&pk_bytes);
            challenge_preimage.extend_from_slice(network.m_state_bytes());
            let challenge = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(
                &tagged_hash(b"BIP0340/challenge", &challenge_preimage),
            ));
            let s = k_prime + tweak + challenge * secret;
            if s.is_zero() {
                continue;
            }
            let mut signature = [0u8; 64];
            signature[..32].copy_from_slice(&rx_bytes);
            signature[32..].copy_from_slice(&field_bytes(s));
            return TestSignature {
                transition: TransitionSignature {
                    pk_i: pk_bytes,
                    signature,
                    r_prime: r_prime_bytes,
                },
                r_prime_point: r_prime,
            };
        }
        unreachable!("deterministic nonce sequence must eventually sign")
    }

    /// A correctly shaped dummy recursion-base proof and wrapper. It is not a
    /// real transition proof, but is sufficient for host-only tests that must
    /// reject wrapper/public-input mismatches before cryptographic verify.
    pub(crate) fn base_proved_transition(network: Network) -> ProvedTransition {
        let proof = super::compliance_circuit(network).base_proof.clone();
        let (proof_data, consumed_pubkey, network_id) =
            extract_transition_public_inputs(&proof).expect("base proof public-input shape");
        ProvedTransition {
            proof,
            proof_data,
            consumed_pubkey,
            network_id,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use plonky2::field::types::Field;
    use sha2::{Digest, Sha256};

    use super::test_signing::{
        deterministic_secret, normalized_key, sign_transition, TestSignature,
    };
    use super::*;

    #[derive(Clone)]
    struct GenesisFixture {
        witness: TransitionWitness,
        output_coin: Coin,
        asset_id: HashDigest,
        nav_opening: NavOpening,
        signature: TestSignature,
    }

    fn genesis_fixture() -> GenesisFixture {
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/compliance-chain/nk").into();
        let nk_commit = host::nk_commit(&nk);
        let (secret, public, current_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-0",
        ));
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-1",
        ));
        let owner = Address(host::address(&current_pubkey, nk_commit));
        let name_hash: [u8; 32] = Sha256::digest(b"Recursive Fixture Asset").into();
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &current_pubkey, &name_hash, 2, 1);
        let issuance = AssetIssuance {
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
        let prev_account_state = AccountState::new(
            owner,
            nk_commit,
            BTreeMap::new(),
            current_pubkey,
            0,
            host::coinhist_empty_root(),
        )
        .unwrap();
        let prev_ash = host::account_state_hash(&prev_account_state).unwrap();
        let output_template = CoinTemplate {
            recipient: owner,
            amount: 100,
            asset_id,
        };
        let output_coin = Coin {
            identifier: host::coin_identifier(prev_ash, &owner.0, asset_id, 100, 0),
            recipient: owner,
            amount: 100,
            asset_id,
        };
        let mut history = host::CoinHistTree::new();
        let output_history = history.prove(host::digest_to_bytes(&output_coin.identifier));
        history
            .admit(host::digest_to_bytes(&output_coin.identifier))
            .unwrap();
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), 100);
        let new_account_state =
            AccountState::new(owner, nk_commit, balances, next_pubkey, 1, history.root()).unwrap();
        let prefix_entry = host::NfLogEntry {
            pk: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-pk").into(),
            r: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-r").into(),
        };
        let nav_opening = NavOpening {
            nav: Nav {
                size: 1,
                mth: host::nflog_mth(&[prefix_entry]),
            },
            nav_rand: [0x2bu8; 32],
        };
        let npk_rand = [0x4du8; 32];
        let proof_data = ProofData {
            new_account_state_hash: host::account_state_hash(&new_account_state).unwrap(),
            output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &[output_coin.identifier]),
            input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
            coin_history_root: new_account_state.coin_history_root,
            nav_commitment: host::nav_commitment(nav_opening.nav.root(), &nav_opening.nav_rand),
            npk_commit: host::npk_commit(&next_pubkey, &npk_rand),
        };
        let signature = sign_transition(secret, public, &proof_data, Network::Testnet);
        GenesisFixture {
            witness: TransitionWitness {
                mode: TransitionMode::InitialProof,
                prev_account_state,
                new_account_state,
                input_coins: Vec::new(),
                input_auth: Vec::new(),
                output_templates: vec![output_template],
                output_coins: vec![output_coin.clone()],
                output_history_proofs: vec![Some(output_history)],
                received_coins: Vec::new(),
                received_auth: Vec::new(),
                asset_issuance: Some(issuance),
                nk,
                nav: nav_opening.nav,
                nav_rand: nav_opening.nav_rand,
                prev_nav_opening: None,
                nav_consistency: Vec::new(),
                next_pubkey,
                npk_rand,
                transition_signature: signature.transition.clone(),
                prev_proof: None,
                predecessor_nullifier: None,
            },
            output_coin,
            asset_id,
            nav_opening,
            signature,
        }
    }

    fn send_witness(
        genesis: &GenesisFixture,
        genesis_proof: &ProvedTransition,
    ) -> TransitionWitness {
        let prev_account_state = genesis.witness.new_account_state.clone();
        let prev_ash = genesis_proof.proof_data.new_account_state_hash;
        let input_coin = genesis.output_coin.clone();
        let input_auth_creating_prev_ash =
            host::account_state_hash(&genesis.witness.prev_account_state).unwrap();
        let owner = prev_account_state.owner;
        let templates = vec![
            CoinTemplate {
                recipient: owner,
                amount: 70,
                asset_id: genesis.asset_id,
            },
            CoinTemplate {
                recipient: Address([0x82u8; 32]),
                amount: 30,
                asset_id: genesis.asset_id,
            },
        ];
        let output_coins: Vec<_> = templates
            .iter()
            .enumerate()
            .map(|(index, template)| Coin {
                identifier: host::coin_identifier(
                    prev_ash,
                    &template.recipient.0,
                    template.asset_id,
                    template.amount,
                    index as u32,
                ),
                recipient: template.recipient,
                amount: template.amount,
                asset_id: template.asset_id,
            })
            .collect();
        let mut history = host::CoinHistTree::new();
        history
            .admit(host::digest_to_bytes(&input_coin.identifier))
            .unwrap();
        let input_history = history.prove(host::digest_to_bytes(&input_coin.identifier));
        history
            .spend(host::digest_to_bytes(&input_coin.identifier))
            .unwrap();
        let self_output_history = history.prove(host::digest_to_bytes(&output_coins[0].identifier));
        history
            .admit(host::digest_to_bytes(&output_coins[0].identifier))
            .unwrap();
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&genesis.asset_id), 70);
        let (secret, public, current_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-1",
        ));
        assert_eq!(current_pubkey, prev_account_state.current_pubkey);
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-2",
        ));
        let new_account_state = AccountState::new(
            owner,
            prev_account_state.nk_commit,
            balances,
            next_pubkey,
            2,
            history.root(),
        )
        .unwrap();
        let prefix_entry = host::NfLogEntry {
            pk: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-pk").into(),
            r: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-r").into(),
        };
        let predecessor_entry = host::NfLogEntry {
            pk: genesis.witness.prev_account_state.current_pubkey,
            r: genesis.signature.transition.signature_r(),
        };
        let entries = [prefix_entry, predecessor_entry];
        let nav = Nav {
            size: 2,
            mth: host::nflog_mth(&entries),
        };
        let nav_rand = [0x3cu8; 32];
        let npk_rand = [0xa5u8; 32];
        let output_ids: Vec<_> = output_coins.iter().map(|coin| coin.identifier).collect();
        let proof_data = ProofData {
            new_account_state_hash: host::account_state_hash(&new_account_state).unwrap(),
            output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &output_ids),
            input_nullifiers_root: host::merkle_root(
                TreeKind::NullifiersRoot,
                &[host::nullifier(&genesis.witness.nk, input_coin.identifier)],
            ),
            coin_history_root: new_account_state.coin_history_root,
            nav_commitment: host::nav_commitment(nav.root(), &nav_rand),
            npk_commit: host::npk_commit(&next_pubkey, &npk_rand),
        };
        let signature = sign_transition(secret, public, &proof_data, Network::Testnet);
        TransitionWitness {
            mode: TransitionMode::AccountUpdateProof,
            prev_account_state,
            new_account_state,
            input_coins: vec![input_coin],
            input_auth: vec![InputAuthorization {
                creating_prev_ash: input_auth_creating_prev_ash,
                coin_index: 0,
                history_proof: input_history,
            }],
            output_templates: templates,
            output_coins,
            output_history_proofs: vec![Some(self_output_history), None],
            received_coins: Vec::new(),
            received_auth: Vec::new(),
            asset_issuance: None,
            nk: genesis.witness.nk,
            nav,
            nav_rand,
            prev_nav_opening: Some(genesis.nav_opening),
            nav_consistency: host::consistency_proof(1, &entries).unwrap(),
            next_pubkey,
            npk_rand,
            transition_signature: signature.transition,
            prev_proof: Some(genesis_proof.proof.clone()),
            predecessor_nullifier: Some(PredecessorNullifier {
                nullifier: NullifierOpening {
                    public_key: predecessor_entry.pk,
                    signature_r: predecessor_entry.r,
                    r_prime: field_bytes(genesis.signature.r_prime_point.x),
                },
                nav_inclusion: host::inclusion_path(1, &entries).unwrap(),
                position: 1,
            }),
        }
    }

    fn attestation_witness(
        genesis: &GenesisFixture,
        genesis_proof: &ProvedTransition,
    ) -> AttestationWitness {
        let prefix_entry = host::NfLogEntry {
            pk: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-pk").into(),
            r: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-r").into(),
        };
        let ceiling_entry = host::NfLogEntry {
            pk: Sha256::digest(b"zkCoins/v1/balance/ceiling-pk").into(),
            r: Sha256::digest(b"zkCoins/v1/balance/ceiling-r").into(),
        };
        let entries = [prefix_entry, ceiling_entry];
        AttestationWitness {
            statement: BalanceAttestationStatement {
                subject: genesis.witness.new_account_state.owner,
                asset_id: genesis.asset_id,
                balance: 100,
                nav_ceiling: Nav {
                    size: 2,
                    mth: host::nflog_mth(&entries),
                },
                anchor: BalanceAnchor {
                    txid: [0x31; 32],
                    block_hash: [0x42; 32],
                    height: 840_000,
                    public_key: genesis_proof.consumed_pubkey,
                    signature_r: genesis.signature.transition.signature_r(),
                },
            },
            account_state: genesis.witness.new_account_state.clone(),
            compliance_proof: genesis_proof.proof.clone(),
            nav_opening: genesis.nav_opening,
            nav_consistency: host::consistency_proof(1, &entries).unwrap(),
            r_prime: field_bytes(genesis.signature.r_prime_point.x),
        }
    }

    #[test]
    fn prover_bridge_real_end_to_end() {
        let bridge = ProverBridge::new(Network::Testnet);
        assert_eq!(bridge.compliance_gate_count(), 1_403_783);

        let genesis = genesis_fixture();
        let proved_genesis = bridge
            .prove_transition(&genesis.witness)
            .expect("genuine genesis/mint proof");
        bridge
            .verify_transition(&proved_genesis.proof)
            .expect("genesis proof passes verify + cyclic pin");
        println!("prover bridge genesis/mint: PASS (proved and verified)");

        let send = send_witness(&genesis, &proved_genesis);
        let proved_send = bridge
            .prove_transition(&send)
            .expect("genuine recursive send proof");
        bridge
            .verify_transition(&proved_send.proof)
            .expect("send proof passes verify + cyclic pin");
        println!("prover bridge send: PASS (proved and verified)");

        let mut tampered_tail = proved_send.proof.clone();
        let tail_start = 40;
        tampered_tail.public_inputs[tail_start] += F::ONE;
        assert!(
            bridge.verify_transition(&tampered_tail).is_err(),
            "tampered cyclic verifier-data tail must be rejected"
        );
        println!("prover bridge tampered cyclic tail: PASS (rejected)");

        let attestation = attestation_witness(&genesis, &proved_genesis);
        let proved_attestation = bridge
            .prove_attestation(&attestation)
            .expect("genuine C_balance proof");
        bridge
            .verify_attestation(&proved_attestation.proof)
            .expect("valid C_balance proof");
        assert_eq!(bridge.balance_gate_count(), 193_437);
        println!("prover bridge balance attestation: PASS (proved and verified)");
        println!(
            "prover bridge gates: C={} C_balance={}",
            bridge.compliance_gate_count(),
            bridge.balance_gate_count()
        );
    }
}
