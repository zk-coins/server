//! Production host bridge for the frozen spec-v1.2 `C` and `C_balance`
//! circuits.
//!
//! The witness setters in this module are the production counterparts of the
//! original compliance and balance circuit fixtures. They deliberately build
//! no constraints: the frozen circuits remain owned by
//! `zkcoins-program-plonky2`.
//!
//! ## Circuit identity (§1.7.9)
//!
//! `C` and `C_balance` are built lazily on first use (prove / verify /
//! digest). When the operator has registered §3.6 pins via
//! [`ProverBridge::install_network_pins`], each construction **immediately**
//! digests the circuit that was just built and compares it to the pin.
//! A mismatch is a hard refusal — not a warning and not a degrade path.
//!
//! Until both circuits for a pinned network have been built and checked,
//! every proving / verifying entry point refuses so a divergent binary
//! cannot serve proofs under matching env pins.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use anyhow::{bail, ensure, Context, Result};
use num::BigUint;
use plonky2::field::secp256k1_base::Secp256K1Base;
use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2::field::types::{Field, PrimeField, PrimeField64};
use plonky2::hash::hash_types::HashOut;
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_data::{CircuitConfig, VerifierCircuitData, VerifierOnlyCircuitData};
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
use zkcoins_program_plonky2::circuit::gadgets::u64_limbs::set_u64_limbs;
use zkcoins_program_plonky2::{C, D, F};

/// A proof emitted by the frozen cyclic compliance circuit `C`.
pub type ComplianceProof = ProofWithPublicInputs<F, C, D>;

/// A proof emitted by the frozen non-cyclic balance circuit `C_balance`.
pub type BalanceProof = ProofWithPublicInputs<F, C, D>;

/// The recursive branch selected for a transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum TransitionMode {
    InitialProof,
    AccountUpdateProof,
}

/// A conditional-NAV commitment opening.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NavOpening {
    pub nav: Nav,
    pub nav_rand: [u8; 32],
}

/// Clause-2 authorization and clause-8 history evidence for one spent coin.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct InputAuthorization {
    pub creating_prev_ash: HashDigest,
    pub coin_index: u32,
    pub history_proof: CoinHistProof,
}

/// Membership of an output coin in its creating proof's output tree.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct OutputInclusionProof {
    pub leaf_index: u32,
    pub depth: u8,
    /// Bottom-to-top siblings. At most `MAX_OUTPUT_MERKLE_DEPTH`.
    pub siblings: Vec<HashDigest>,
}

/// The on-chain nullifier and sign-to-contract opening for a transition.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct NullifierOpening {
    pub public_key: [u8; 32],
    pub signature_r: [u8; 32],
    /// X-only, even-y encoding of the pre-tweak point `R'`.
    pub r_prime: [u8; 32],
}

/// Clause-10 provenance, accumulator, and history evidence for one receipt.
///
/// **No public `Deserialize` (Stage 3 Runde 5):** `creating_proof` must not
/// load unbound via a free serde entry. Nested durable decode goes through
/// [`TransitionWitness::decode_bound`] / the private wire used by
/// `FinalisationCapability::from_durable_bytes`, which bind identity.
#[derive(Clone, Debug, serde::Serialize)]
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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TransitionSignature {
    /// The x-only key `Pk_i`; it must equal
    /// `prev_account_state.current_pubkey`.
    pub pk_i: [u8; 32],
    /// Canonical BIP-340 signature `bytes(R) || bytes(s)`.
    /// Serde's array limit is 32; use a tuple helper for the 64-byte field.
    #[serde(with = "big_array_64")]
    pub signature: [u8; 64],
    /// X-only, even-y encoding of the S2C pre-tweak point `R'`.
    pub r_prime: [u8; 32],
}

/// Serde helper for `[u8; 64]` (serde only derives arrays up to 32 by default).
mod big_array_64 {
    use serde::de::{self, SeqAccess, Visitor};
    use serde::ser::SerializeTuple;
    use serde::{Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(v: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        let mut tup = s.serialize_tuple(64)?;
        for b in v.iter() {
            tup.serialize_element(b)?;
        }
        tup.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = [u8; 64];
            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                f.write_str("a 64-byte sequence")
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<[u8; 64], A::Error> {
                let mut out = [0u8; 64];
                for (i, slot) in out.iter_mut().enumerate() {
                    *slot = seq
                        .next_element()?
                        .ok_or_else(|| de::Error::invalid_length(i, &self))?;
                }
                if seq.next_element::<u8>()?.is_some() {
                    return Err(de::Error::invalid_length(65, &self));
                }
                Ok(out)
            }
        }
        d.deserialize_tuple(64, V)
    }
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
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
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
///
/// ## Load gate (Stage 3 Runde 5)
///
/// This type deliberately does **not** derive `Deserialize`. A free
/// `bincode::deserialize::<TransitionWitness>(…)` would accept a well-formed
/// proof of another circuit in `prev_proof` / `received_auth[].creating_proof`
/// without identity bind. The only supported byte → witness path is
/// [`TransitionWitness::decode_bound`] (or durable resume via
/// `FinalisationCapability::from_durable_bytes`, which uses the same bind).
/// Construction in-process (StateEngine `begin_*`) remains a plain struct
/// literal — no serde.
#[derive(Clone, Debug, serde::Serialize)]
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

/// Crate-private bincode layout for [`TransitionWitness`] / nested
/// [`ReceivedAuthorization`]. Field order matches the historical derived
/// `Serialize`/`Deserialize` layout so durable `FinalisationCapability`
/// blobs remain loadable. Not part of the public API — external crates
/// use [`TransitionWitness::decode_bound`] only.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub(crate) struct TransitionWitnessWire {
    mode: TransitionMode,
    prev_account_state: AccountState,
    new_account_state: AccountState,
    input_coins: Vec<Coin>,
    input_auth: Vec<InputAuthorization>,
    output_templates: Vec<CoinTemplate>,
    output_coins: Vec<Coin>,
    output_history_proofs: Vec<Option<CoinHistProof>>,
    received_coins: Vec<Coin>,
    received_auth: Vec<ReceivedAuthorizationWire>,
    asset_issuance: Option<AssetIssuance>,
    nk: [u8; 32],
    nav: Nav,
    nav_rand: [u8; 32],
    prev_nav_opening: Option<NavOpening>,
    nav_consistency: Vec<HashDigest>,
    next_pubkey: [u8; 32],
    npk_rand: [u8; 32],
    transition_signature: TransitionSignature,
    prev_proof: Option<ComplianceProof>,
    predecessor_nullifier: Option<PredecessorNullifier>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ReceivedAuthorizationWire {
    creating_proof: ComplianceProof,
    output_inclusion: OutputInclusionProof,
    creating_prev_ash: HashDigest,
    creating_nullifier: NullifierOpening,
    creating_nav_inclusion: Vec<HashDigest>,
    pos_create: u64,
    creating_nav_opening: NavOpening,
    creating_nav_consistency: Vec<HashDigest>,
    history_proof: CoinHistProof,
}

impl TransitionWitness {
    pub(crate) fn to_wire(&self) -> TransitionWitnessWire {
        TransitionWitnessWire {
            mode: self.mode,
            prev_account_state: self.prev_account_state.clone(),
            new_account_state: self.new_account_state.clone(),
            input_coins: self.input_coins.clone(),
            input_auth: self.input_auth.clone(),
            output_templates: self.output_templates.clone(),
            output_coins: self.output_coins.clone(),
            output_history_proofs: self.output_history_proofs.clone(),
            received_coins: self.received_coins.clone(),
            received_auth: self
                .received_auth
                .iter()
                .map(ReceivedAuthorization::to_wire)
                .collect(),
            asset_issuance: self.asset_issuance.clone(),
            nk: self.nk,
            nav: self.nav,
            nav_rand: self.nav_rand,
            prev_nav_opening: self.prev_nav_opening,
            nav_consistency: self.nav_consistency.clone(),
            next_pubkey: self.next_pubkey,
            npk_rand: self.npk_rand,
            transition_signature: self.transition_signature.clone(),
            prev_proof: self.prev_proof.clone(),
            predecessor_nullifier: self.predecessor_nullifier.clone(),
        }
    }

    pub(crate) fn from_wire(wire: TransitionWitnessWire) -> Self {
        Self {
            mode: wire.mode,
            prev_account_state: wire.prev_account_state,
            new_account_state: wire.new_account_state,
            input_coins: wire.input_coins,
            input_auth: wire.input_auth,
            output_templates: wire.output_templates,
            output_coins: wire.output_coins,
            output_history_proofs: wire.output_history_proofs,
            received_coins: wire.received_coins,
            received_auth: wire
                .received_auth
                .into_iter()
                .map(ReceivedAuthorization::from_wire)
                .collect(),
            asset_issuance: wire.asset_issuance,
            nk: wire.nk,
            nav: wire.nav,
            nav_rand: wire.nav_rand,
            prev_nav_opening: wire.prev_nav_opening,
            nav_consistency: wire.nav_consistency,
            next_pubkey: wire.next_pubkey,
            npk_rand: wire.npk_rand,
            transition_signature: wire.transition_signature,
            prev_proof: wire.prev_proof,
            predecessor_nullifier: wire.predecessor_nullifier,
        }
    }

    /// Deserialize a witness from bincode and **bind every embedded
    /// compliance proof** to `bridge`'s circuit `C` identity.
    ///
    /// This is the sole public byte → [`TransitionWitness`] entry. Bare
    /// `bincode::deserialize::<TransitionWitness>` no longer compiles
    /// (no `Deserialize` impl). Binds:
    /// - `prev_proof` when present
    /// - every `received_auth[i].creating_proof`
    ///
    /// A well-formed proof of another circuit fails the same shape /
    /// cyclic-tail gate as [`ProverBridge::bind_prev_proof_identity`].
    pub fn decode_bound(bytes: &[u8], bridge: &ProverBridge) -> Result<Self> {
        let wire: TransitionWitnessWire = bincode::deserialize(bytes).context(
            "deserialize TransitionWitness wire (bincode); refusing unbound free Deserialize",
        )?;
        let witness = Self::from_wire(wire);
        witness.bind_embedded_proofs(bridge)?;
        Ok(witness)
    }

    /// Bind `prev_proof` and every receipt `creating_proof` already present
    /// on this value (used after private-wire rehydrate).
    pub(crate) fn bind_embedded_proofs(&self, bridge: &ProverBridge) -> Result<()> {
        if let Some(ref proof) = self.prev_proof {
            bridge.bind_prev_proof_identity(proof).context(
                "TransitionWitness load: prev_proof failed circuit-C identity bind \
                 (refusing as prev_proof)",
            )?;
        }
        for (index, auth) in self.received_auth.iter().enumerate() {
            bridge
                .bind_prev_proof_identity(&auth.creating_proof)
                .with_context(|| {
                    format!(
                        "TransitionWitness load: received_auth[{index}].creating_proof \
                         failed circuit-C identity bind (refusing as creating_proof)"
                    )
                })?;
        }
        Ok(())
    }
}

impl ReceivedAuthorization {
    fn to_wire(&self) -> ReceivedAuthorizationWire {
        ReceivedAuthorizationWire {
            creating_proof: self.creating_proof.clone(),
            output_inclusion: self.output_inclusion.clone(),
            creating_prev_ash: self.creating_prev_ash,
            creating_nullifier: self.creating_nullifier.clone(),
            creating_nav_inclusion: self.creating_nav_inclusion.clone(),
            pos_create: self.pos_create,
            creating_nav_opening: self.creating_nav_opening,
            creating_nav_consistency: self.creating_nav_consistency.clone(),
            history_proof: self.history_proof.clone(),
        }
    }

    fn from_wire(wire: ReceivedAuthorizationWire) -> Self {
        Self {
            creating_proof: wire.creating_proof,
            output_inclusion: wire.output_inclusion,
            creating_prev_ash: wire.creating_prev_ash,
            creating_nullifier: wire.creating_nullifier,
            creating_nav_inclusion: wire.creating_nav_inclusion,
            pos_create: wire.pos_create,
            creating_nav_opening: wire.creating_nav_opening,
            creating_nav_consistency: wire.creating_nav_consistency,
            history_proof: wire.history_proof,
        }
    }
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

/// §3.6 pins for one network, registered before the first circuit build.
#[derive(Clone, Copy, Debug)]
struct NetworkPins {
    c: [u8; 32],
    c_balance: [u8; 32],
}

fn pins_slot(network: Network) -> &'static OnceLock<NetworkPins> {
    static MAINNET: OnceLock<NetworkPins> = OnceLock::new();
    static TESTNET: OnceLock<NetworkPins> = OnceLock::new();
    static REGTEST: OnceLock<NetworkPins> = OnceLock::new();
    match network {
        Network::Mainnet => &MAINNET,
        Network::Testnet => &TESTNET,
        Network::Regtest => &REGTEST,
    }
}

fn c_verified_flag(network: Network) -> &'static AtomicBool {
    static MAINNET: AtomicBool = AtomicBool::new(false);
    static TESTNET: AtomicBool = AtomicBool::new(false);
    static REGTEST: AtomicBool = AtomicBool::new(false);
    match network {
        Network::Mainnet => &MAINNET,
        Network::Testnet => &TESTNET,
        Network::Regtest => &REGTEST,
    }
}

fn balance_verified_flag(network: Network) -> &'static AtomicBool {
    static MAINNET: AtomicBool = AtomicBool::new(false);
    static TESTNET: AtomicBool = AtomicBool::new(false);
    static REGTEST: AtomicBool = AtomicBool::new(false);
    match network {
        Network::Mainnet => &MAINNET,
        Network::Testnet => &TESTNET,
        Network::Regtest => &REGTEST,
    }
}

/// Process-global slot for a cache-verified `C` `VerifierCircuitData`, populated by
/// [`ProverBridge::mark_compliance_verifier_from_cache`]. When this is populated,
/// `verify_transition` / `load_transition_proof_bytes` / `bind_prev_proof_identity` verify
/// against it instead of building the full `C` `CircuitData` via `compliance_circuit`.
fn compliance_verifier_slot(network: Network) -> &'static OnceLock<VerifierCircuitData<F, C, D>> {
    static MAINNET: OnceLock<VerifierCircuitData<F, C, D>> = OnceLock::new();
    static TESTNET: OnceLock<VerifierCircuitData<F, C, D>> = OnceLock::new();
    static REGTEST: OnceLock<VerifierCircuitData<F, C, D>> = OnceLock::new();
    match network {
        Network::Mainnet => &MAINNET,
        Network::Testnet => &TESTNET,
        Network::Regtest => &REGTEST,
    }
}

/// State of a circuit cache slot: a transient build marker, the completed
/// circuit, or a cached construction-time identity refusal.
///
/// `Ready` holds an [`Arc`] so the multi-megabyte circuit body never crosses a
/// thread join / cache boundary as a by-value stack object
/// (the test-runner default stack is ~2 MiB; returning `SkeletonCircuit` by
/// value there aborts with stack overflow before the 64 MiB build worker
/// finishes transferring the result). Reference counting also lets the idle
/// reaper inspect real residency while any caller keeps its own circuit
/// reference alive until completion. `Building` blocks lease release without
/// retaining a circuit and is reset by [`BuildingSlotGuard`] on unwind.
enum CircuitSlot<T> {
    Building,
    Ready(Arc<T>),
    Refused(String),
}

/// Result of atomically inspecting a circuit slot and, when it is empty,
/// reserving it for the caller's build. In particular, a `Ready` result lets
/// dependency-heavy builders return before acquiring or reconstructing any
/// dependency that the completed circuit does not retain.
enum CircuitSlotClaim<T: 'static, D> {
    Ready(Arc<T>),
    Refused(String),
    Building,
    Claimed {
        building: BuildingSlotGuard<T>,
        dependency: D,
    },
}

/// Lazily resident production prover/verifier for one compile-time network.
///
/// `C` and `C_balance` are reference-counted and evicted after the proving
/// lease's idle TTL. When pins are installed, every fresh construction digests
/// the just-built circuit and refuses on pin mismatch (§1.7.9).
#[derive(Clone, Copy, Debug)]
pub struct ProverBridge {
    network: Network,
}

impl ProverBridge {
    /// Select a network. The compliance / balance circuits are built on first
    /// use (prove, verify, digest, or gate-count) and kept process-wide until
    /// the proving-lease idle reaper evicts the resident cache references.
    ///
    /// Construction itself is cheap so persistence / adapter tests can hold a
    /// bridge handle without paying the multi-minute circuit build. The §1.7.9
    /// pin check runs at the moment construction completes (see module docs).
    pub fn new(network: Network) -> Self {
        Self { network }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    /// Register §3.6 pins for `network` before the first circuit construction.
    ///
    /// Production boot under v1.1 **must** call this with the env pins so the
    /// construction-time check has something to compare the real circuit
    /// against. Idempotent when the same pair is re-installed; refuses if a
    /// different pair is attempted (no silent overwrite).
    pub fn install_network_pins(
        network: Network,
        pin_c: [u8; 32],
        pin_c_balance: [u8; 32],
    ) -> Result<()> {
        let pins = NetworkPins {
            c: pin_c,
            c_balance: pin_c_balance,
        };
        match pins_slot(network).set(pins) {
            Ok(()) => Ok(()),
            Err(_rejected) => {
                // OnceLock::set returns Err(the value we passed), NOT the stored value.
                // Read the actually-stored pins to compare (no silent pin swap).
                let stored = pins_slot(network)
                    .get()
                    .expect("pins slot is initialised after set() was rejected");
                if stored.c == pin_c && stored.c_balance == pin_c_balance {
                    Ok(())
                } else {
                    bail!(
                        "circuit pins for {:?} already installed with a different pair; \
                         refusing to overwrite (no silent pin swap)",
                        network
                    )
                }
            }
        }
    }

    /// Record that C_balance's construction-time identity is satisfied for
    /// `network` from a verified verifier-data cache (§1.7.9). The caller MUST
    /// have loaded the cache through `verifier_cache::load_balance_verifier_cache_checked`,
    /// which recomputes C_balance's circuit_digest from the loaded constants and
    /// requires it to equal the pinned digest — cryptographically equivalent to a
    /// local build's digest check. This lets a secondary node satisfy the balance
    /// identity gate WITHOUT rebuilding
    /// `C_balance` (2^18, 191,268 gates — the lighter of the two circuits; `C` at 2^21 /
    /// 1,382,481 gates is the one in the ~90-100 GiB range per `docs/build-report.md`. The
    /// analogous cache for `C` is `mark_compliance_verifier_from_cache`, below). The actual
    /// prover circuit is still built lazily if this node ever PROVES a balance statement (see
    /// `balance_circuit`).
    pub fn mark_balance_identity_verified_from_cache(
        network: Network,
        verified_c_balance_digest: [u8; 32],
    ) -> Result<()> {
        // Belt-and-suspenders: the cache-verified digest must match the installed pin.
        match pins_slot(network).get() {
            Some(pins) => {
                if pins.c_balance != verified_c_balance_digest {
                    bail!(
                        "cache-verified C_balance digest does not match installed pin for \
                         {:?}; refusing to mark verified",
                        network
                    );
                }
            }
            None => {
                bail!(
                    "install_network_pins must run before \
                     mark_balance_identity_verified_from_cache for {:?}",
                    network
                );
            }
        }
        balance_verified_flag(network).store(true, Ordering::Release);
        Ok(())
    }

    /// Record that `C`'s construction-time identity is satisfied for `network` from a verified
    /// verifier-data cache (§1.7.9), AND install the cache-loaded `VerifierCircuitData` as this
    /// process's verifier for `C`. The caller MUST have loaded the cache through
    /// `verifier_cache::load_compliance_verifier_cache_checked`, which recomputes `C`'s
    /// circuit_digest from the loaded constants and requires it to equal the pinned digest —
    /// cryptographically equivalent to a local build's digest check. This lets a secondary node
    /// satisfy the compliance identity gate AND verify cyclic transition proofs WITHOUT ever
    /// building the ~1.38M-gate (2^21), ~90-100 GiB `C` circuit. If this node ever PROVES a
    /// transition (which a secondary never does), `compliance_circuit` still builds `C` lazily at
    /// that point — this slot only carries verifier-only data, not a prover key.
    ///
    /// In addition to matching `verified_c_digest` against the installed pin, this function
    /// asserts that `verifier_data`'s own embedded `verifier_only.circuit_digest` equals
    /// `verified_c_digest` before installing (self-bound invariant — the two parameters can never
    /// be allowed to disagree).
    pub fn mark_compliance_verifier_from_cache(
        network: Network,
        verified_c_digest: [u8; 32],
        verifier_data: VerifierCircuitData<F, C, D>,
    ) -> Result<()> {
        match pins_slot(network).get() {
            Some(pins) => {
                if pins.c != verified_c_digest {
                    bail!(
                        "cache-verified C digest does not match installed pin for \
                         {:?}; refusing to mark verified",
                        network
                    );
                }
            }
            None => {
                bail!(
                    "install_network_pins must run before \
                     mark_compliance_verifier_from_cache for {:?}",
                    network
                );
            }
        }
        ensure!(
            host::digest_to_bytes(&verifier_data.verifier_only.circuit_digest) == verified_c_digest,
            "cache-verified C digest does not match verifier_data's own circuit_digest for \
             {:?} (verified_c_digest and verifier_data disagree even though verified_c_digest \
             matches the installed pin); refusing to install a verifier whose embedded \
             identity disagrees with the digest it was marked with — self-bound invariant",
            network
        );
        compliance_verifier_slot(network)
            .set(verifier_data)
            .map_err(|_| {
                anyhow::anyhow!(
                    "compliance verifier cache already marked for {:?}; refusing to overwrite \
                 (no silent replace)",
                    network
                )
            })?;
        c_verified_flag(network).store(true, Ordering::Release);
        Ok(())
    }

    /// Whether both circuits for this network have been built and pin-checked
    /// (or built with no pins registered — unpinned test paths).
    ///
    /// When pins **are** registered, proving paths must not run until this
    /// is true (construction is the check). Unpinned: always `true` once
    /// both caches are warm, else `false` until first use warms them.
    pub fn identity_ready(&self) -> bool {
        match pins_slot(self.network).get() {
            Some(_) => {
                c_verified_flag(self.network).load(Ordering::Acquire)
                    && balance_verified_flag(self.network).load(Ordering::Acquire)
            }
            None => true, // no pins → no identity gate
        }
    }

    /// Force-build both circuits for this network and run the construction-
    /// time pin check. Returns the live §1.7.1 digests.
    ///
    /// This is the honest self-heal / boot path: digests come from the
    /// circuits that were just constructed, not from an embedded text file
    /// or from re-encoding the pins.
    pub fn require_live_identity(&self) -> Result<([u8; 32], [u8; 32])> {
        let c = self.circuit_digest_bytes_result()?;
        let b = self.balance_circuit_digest_bytes_result()?;
        if let Some(pins) = pins_slot(self.network).get() {
            crate::circuit_identity::require_live_digests_match_pins(
                &c,
                &b,
                &pins.c,
                &pins.c_balance,
                self.network,
            )
            .map_err(|e| anyhow::anyhow!(e))?;
        }
        Ok((c, b))
    }

    pub fn compliance_gate_count(&self) -> usize {
        compliance_circuit(self.network)
            .expect("compliance circuit identity")
            .gate_count
    }

    pub fn balance_gate_count(&self) -> usize {
        balance_circuit(self.network)
            .expect("balance circuit identity")
            .gate_count
    }

    /// §1.7.1 32-byte encoding of `C`'s `verifier_only.circuit_digest`.
    ///
    /// **Encoding differs from the legacy [`crate::Prover::circuit_digest_bytes`]:**
    /// that method returns `bincode::serialize(HashOut)` (opaque field limbs),
    /// while this method returns the canonical protocol encoding
    /// (`shared::spec_v1::digest_to_bytes`: each limb `to_canonical_u64` as
    /// 8-byte big-endian). Callers that compare against a pinned network
    /// constant or `/v1/info.circuit_digests.C` MUST use this form.
    ///
    /// Builds `C` on first use. When pins are installed, construction
    /// refuses if the just-built digest does not match the pin.
    pub fn circuit_digest_bytes(&self) -> [u8; 32] {
        self.circuit_digest_bytes_result()
            .expect("compliance circuit identity")
    }

    /// Fallible form of [`Self::circuit_digest_bytes`] for boot / self-heal.
    pub fn circuit_digest_bytes_result(&self) -> Result<[u8; 32]> {
        let circuit = compliance_circuit(self.network)?;
        Ok(host::digest_to_bytes(
            &circuit.data.verifier_only.circuit_digest,
        ))
    }

    /// §1.7.1 32-byte encoding of `C_balance`'s `verifier_only.circuit_digest`.
    ///
    /// Same encoding contract as [`Self::circuit_digest_bytes`]. Eagerly
    /// initializes the cached balance circuit for this network if needed.
    pub fn balance_circuit_digest_bytes(&self) -> [u8; 32] {
        self.balance_circuit_digest_bytes_result()
            .expect("balance circuit identity")
    }

    /// Fallible form of [`Self::balance_circuit_digest_bytes`] for boot / self-heal.
    pub fn balance_circuit_digest_bytes_result(&self) -> Result<[u8; 32]> {
        let circuit = balance_circuit(self.network)?;
        Ok(host::digest_to_bytes(
            &circuit.data.verifier_only.circuit_digest,
        ))
    }

    /// Refuse proving when pins are installed but construction-time identity
    /// has not passed for both circuits yet.
    fn ensure_proving_identity(&self) -> Result<()> {
        if pins_slot(self.network).get().is_some() {
            if !c_verified_flag(self.network).load(Ordering::Acquire) {
                // Builds C and runs the construction-time pin check; sets c_verified_flag.
                let _ = self.circuit_digest_bytes_result()?;
            }
            if !balance_verified_flag(self.network).load(Ordering::Acquire) {
                // Builds C_balance and runs the pin check; sets balance_verified_flag
                // (unless already set by mark_balance_identity_verified_from_cache).
                let _ = self.balance_circuit_digest_bytes_result()?;
            }
        }
        if pins_slot(self.network).get().is_some() && !self.identity_ready() {
            bail!(
                "circuit identity for {:?} is not ready — refusing proving path \
                 until construction-time pin check passes (§1.7.9)",
                self.network
            );
        }
        Ok(())
    }

    /// Assemble all `ComplianceTargets`, then produce a genuine cyclic proof.
    pub fn prove_transition(&self, witness: &TransitionWitness) -> Result<ProvedTransition> {
        self.ensure_proving_identity()?;
        let circuit = compliance_circuit(self.network)?;
        if let Some(predecessor) = &witness.prev_proof {
            self.verify_transition(predecessor)
                .context("transition predecessor proof is unacceptable")?;
        }
        for (index, received) in witness.received_auth.iter().enumerate() {
            self.verify_transition(&received.creating_proof)
                .with_context(|| format!("received coin {index} creating proof is unacceptable"))?;
        }
        let expected = validate_transition(witness, self.network)?;
        let partial =
            assemble_transition_witness(&circuit, witness, &circuit.data.verifier_only)?;
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
        self.ensure_proving_identity()?;
        if let Some(cached) = compliance_verifier_slot(self.network).get() {
            cached
                .verify(proof.clone())
                .context("compliance proof verification failed (cached verifier)")?;
            check_cyclic_proof_verifier_data(proof, &cached.verifier_only, &cached.common)
                .context("compliance proof cyclic verifier-data tail is not canonical")?;
            return Ok(());
        }
        let circuit = compliance_circuit(self.network)?;
        circuit
            .data
            .verify(proof.clone())
            .context("compliance proof verification failed")?;
        check_cyclic_proof_verifier_data(proof, &circuit.data.verifier_only, &circuit.data.common)
            .context("compliance proof cyclic verifier-data tail is not canonical")?;
        Ok(())
    }

    /// Deserialize durable `last_proof` / `prev_proof` bytes and **bind them
    /// to this bridge's circuit `C` identity**.
    ///
    /// Uses the same construction-time pin path as proving: `C` is built
    /// (pin-checked when pins are installed), then
    /// [`check_cyclic_proof_verifier_data`] refuses any proof whose cyclic
    /// verifier-data tail is not that of `C`. A well-formed **legacy**
    /// `zkcoins_prover::Proof` (same Rust type alias, different circuit)
    /// deserializes via bincode but fails this bind — that is the Stage-3
    /// load gate. Garbage bytes fail at deserialize.
    ///
    /// Does not re-run full Plonky2 `verify` (that stays on the prove /
    /// slow-canary path). Identity is the circuit-digest tail bound at
    /// construction; nothing parallel is invented here.
    pub fn bind_loaded_prev_proof(&self, bytes: &[u8]) -> Result<ComplianceProof> {
        let proof: ComplianceProof = bincode::deserialize(bytes)
            .context("deserialize last_proof / prev_proof as ComplianceProof (bincode)")?;
        self.bind_prev_proof_identity(&proof)?;
        Ok(proof)
    }

    /// Load a §1.7.9 native wire proof (`ProofWithPublicInputs::to_bytes`)
    /// and bind it to circuit `C` identity.
    ///
    /// This is the receive-path port for `CoinProof.proof` bytes: the
    /// sender places Plonky2 native encoding in the bundle (§1.7.9), not
    /// bincode. Full Plonky2 `verify` is a separate call
    /// ([`Self::verify_transition`]) — identity bind alone is not credit.
    pub fn load_transition_proof_bytes(&self, bytes: &[u8]) -> Result<ComplianceProof> {
        self.ensure_proving_identity()?;
        let proof = if let Some(cached) = compliance_verifier_slot(self.network).get() {
            ComplianceProof::from_bytes(bytes.to_vec(), &cached.common)
                .context("native Plonky2 proof bytes rejected by from_bytes (CoinProof.proof)")?
        } else {
            let circuit = compliance_circuit(self.network)?;
            ComplianceProof::from_bytes(bytes.to_vec(), &circuit.data.common)
                .context("native Plonky2 proof bytes rejected by from_bytes (CoinProof.proof)")?
        };
        self.bind_prev_proof_identity(&proof)?;
        Ok(proof)
    }

    /// Load a §1.7.9 native wire `C_balance` proof (`ProofWithPublicInputs::to_bytes` encoding,
    /// the same encoding `encode_c_balance_proof_bytes` in node's attest.rs produces) and parse it
    /// against this bridge's network's balance circuit. Does NOT run Plonky2 `verify` — call
    /// `verify_attestation` separately. Mirrors `load_transition_proof_bytes` but for `C_balance`.
    pub fn load_balance_proof_bytes(&self, bytes: &[u8]) -> Result<BalanceProof> {
        self.ensure_proving_identity()?;
        let circuit = balance_circuit(self.network)?;
        BalanceProof::from_bytes(bytes.to_vec(), &circuit.data.common).context(
            "native Plonky2 proof bytes rejected by from_bytes (C_balance attestation proof)",
        )
    }

    /// Bind an already-deserialized proof to circuit `C` identity (same
    /// gate as [`Self::bind_loaded_prev_proof`]).
    pub fn bind_prev_proof_identity(&self, proof: &ComplianceProof) -> Result<()> {
        // Cheap shape gate **before** constructing `C`. Legacy outer proofs
        // share the Rust type but not the PI length; refuse them without
        // paying circuit build (and without requiring a large process stack
        // for the cyclic-identity path). Wrong-shape is the Stage-3 threat
        // model for "well-formed proof of another circuit".
        ensure!(
            proof.public_inputs.len() == 108,
            "last_proof / prev_proof has {} public inputs (expected 108 for circuit C); \
             refusing as prev_proof — well-formed proofs of another circuit are not loadable",
            proof.public_inputs.len()
        );
        self.ensure_proving_identity()?;
        if let Some(cached) = compliance_verifier_slot(self.network).get() {
            check_cyclic_proof_verifier_data(proof, &cached.verifier_only, &cached.common)
                .context(
                    "last_proof / prev_proof is not bound to circuit C identity \
                     (wrong circuit or corrupt verifier-data tail); refusing as prev_proof",
                )?;
            return Ok(());
        }
        let circuit = compliance_circuit(self.network)?;
        check_cyclic_proof_verifier_data(proof, &circuit.data.verifier_only, &circuit.data.common)
            .context(
                "last_proof / prev_proof is not bound to circuit C identity \
                 (wrong circuit or corrupt verifier-data tail); refusing as prev_proof",
            )?;
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
        self.ensure_proving_identity()?;
        self.verify_transition(&witness.compliance_proof)
            .context("attestation embeds an unacceptable compliance proof")?;
        validate_attestation(witness)?;
        let circuit = balance_circuit(self.network)?;
        let partial = assemble_attestation_witness(&circuit, witness, self.network)?;
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

    /// Verify a non-cyclic `C_balance` proof with ordinary Plonky2 verification, THEN re-extract its
    /// own public inputs and return them. `C_balance` itself pins the embedded `C` proof's
    /// verifier-data tail, so no outer cyclic-tail check applies here.
    ///
    /// Returning the extracted [`BalancePublicStatement`] (rather than `()`) makes it structurally
    /// hard for a caller to skip binding a claimed header to the proof that actually proves it — the
    /// same pattern [`Self::verify_proved_transition_wrapper`] documents for `C`. This is still
    /// necessary but not sufficient for acceptance on its own: the caller must additionally bind
    /// every field of the returned statement to whatever header it is validating (never trust a
    /// separately-carried header/wrapper value without this comparison), and must additionally
    /// establish from its own >=6-confirmation-final scan that `nav_ceiling`/`size_ceiling` is
    /// canonical and that the disclosed `(Pk_anchor, R_anchor)` is the completed first occurrence at
    /// the disclosed Bitcoin anchor. Those §5.7 host checks are outside this bridge (P1-E.2/P1-G).
    pub fn verify_attestation(&self, proof: &BalanceProof) -> Result<BalancePublicStatement> {
        self.ensure_proving_identity()?;
        balance_circuit(self.network)?
            .data
            .verify(proof.clone())
            .context("balance-attestation proof verification failed")?;
        extract_balance_public_inputs(proof)
    }
}

fn compliance_circuit_slot(
    network: Network,
) -> &'static Mutex<Option<CircuitSlot<SkeletonCircuit>>> {
    static MAINNET: Mutex<Option<CircuitSlot<SkeletonCircuit>>> = Mutex::new(None);
    static TESTNET: Mutex<Option<CircuitSlot<SkeletonCircuit>>> = Mutex::new(None);
    static REGTEST: Mutex<Option<CircuitSlot<SkeletonCircuit>>> = Mutex::new(None);
    match network {
        Network::Mainnet => &MAINNET,
        Network::Testnet => &TESTNET,
        Network::Regtest => &REGTEST,
    }
}

fn balance_circuit_slot(network: Network) -> &'static Mutex<Option<CircuitSlot<BalanceCircuit>>> {
    static MAINNET: Mutex<Option<CircuitSlot<BalanceCircuit>>> = Mutex::new(None);
    static TESTNET: Mutex<Option<CircuitSlot<BalanceCircuit>>> = Mutex::new(None);
    static REGTEST: Mutex<Option<CircuitSlot<BalanceCircuit>>> = Mutex::new(None);
    match network {
        Network::Mainnet => &MAINNET,
        Network::Testnet => &TESTNET,
        Network::Regtest => &REGTEST,
    }
}

fn lock_circuit_slot<T>(
    slot: &Mutex<Option<CircuitSlot<T>>>,
) -> std::sync::MutexGuard<'_, Option<CircuitSlot<T>>> {
    // Slot guards never span circuit construction or thread join, so a panic
    // cannot leave a partially-written circuit in the protected value.
    // Recovering poison therefore preserves the last complete state and avoids
    // cascading a build-worker panic into the independent reaper thread.
    slot.lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Inspect a slot and install `Building` as one atomic operation. `on_claim`
/// runs under the slot lock immediately before publication of that marker, so
/// generation-local verification state cannot lag behind a visible build.
/// Only the thread that claims an empty slot runs `prepare_dependency`, after
/// dropping the slot lock and under a [`BuildingSlotGuard`].
fn claim_circuit_build<T: 'static, D>(
    slot: &'static Mutex<Option<CircuitSlot<T>>>,
    on_claim: impl FnOnce(),
    prepare_dependency: impl FnOnce() -> D,
) -> CircuitSlotClaim<T, D> {
    let mut cache = lock_circuit_slot(slot);
    match cache.as_ref() {
        Some(CircuitSlot::Ready(circuit)) => {
            return CircuitSlotClaim::Ready(Arc::clone(circuit));
        }
        Some(CircuitSlot::Refused(error)) => {
            return CircuitSlotClaim::Refused(error.clone());
        }
        Some(CircuitSlot::Building) => return CircuitSlotClaim::Building,
        None => {
            on_claim();
            *cache = Some(CircuitSlot::Building);
        }
    }
    drop(cache);

    let building = BuildingSlotGuard::new(slot);
    let dependency = prepare_dependency();
    CircuitSlotClaim::Claimed {
        building,
        dependency,
    }
}

/// Panic guard for the transient `Building` marker.
///
/// A worker panic is deliberately resumed on the caller, but it must not make
/// every later caller wait forever. Unless the completed slot replaces the
/// marker and disarms this guard, unwinding restores the slot to `None`.
struct BuildingSlotGuard<T: 'static> {
    slot: &'static Mutex<Option<CircuitSlot<T>>>,
    armed: bool,
}

impl<T: 'static> BuildingSlotGuard<T> {
    fn new(slot: &'static Mutex<Option<CircuitSlot<T>>>) -> Self {
        Self { slot, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl<T: 'static> Drop for BuildingSlotGuard<T> {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let mut slot = lock_circuit_slot(self.slot);
        if matches!(slot.as_ref(), Some(CircuitSlot::Building)) {
            *slot = None;
        }
    }
}

/// Evict one cache-owned circuit only when no external [`Arc`] still uses it.
/// `Refused` contains no circuit memory and therefore never pins the host lease.
fn try_evict_slot<T>(slot: &Mutex<Option<CircuitSlot<T>>>) -> bool {
    let mut slot = lock_circuit_slot(slot);
    match slot.as_ref() {
        None | Some(CircuitSlot::Refused(_)) => true,
        Some(CircuitSlot::Building) => false,
        Some(CircuitSlot::Ready(circuit)) if Arc::strong_count(circuit) == 1 => {
            *slot = None;
            true
        }
        Some(CircuitSlot::Ready(_)) => false,
    }
}

/// Build or clone the resident `C` for one network. When pins are installed,
/// every fresh build immediately compares the just-built digest to its pin —
/// the §1.7.9 check, not an embedded text file or pins compared to themselves.
pub(crate) fn compliance_circuit(network: Network) -> Result<Arc<SkeletonCircuit>> {
    let slot = compliance_circuit_slot(network);
    loop {
        let mut cache = lock_circuit_slot(slot);
        match cache.as_ref() {
            Some(CircuitSlot::Ready(circuit)) => {
                let circuit = Arc::clone(circuit);
                drop(cache);
                crate::prover_lease::note_active();
                return Ok(circuit);
            }
            Some(CircuitSlot::Refused(error)) => {
                let error = error.clone();
                drop(cache);
                return Err(anyhow::anyhow!(error));
            }
            Some(CircuitSlot::Building) => {
                // A short poll keeps the state machine simple while ensuring
                // no waiter retains the slot lock during the expensive build.
                drop(cache);
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            None => {
                // A prior resident generation may have set this flag. Every
                // fresh generation must earn it again via its own pin check.
                c_verified_flag(network).store(false, Ordering::Release);
                *cache = Some(CircuitSlot::Building);
                drop(cache);
                break;
            }
        }
    }

    let mut building = BuildingSlotGuard::new(slot);
    crate::prover_lease::acquire_host_lease()?;
    // This is intentionally before spawn/join: if the worker panics, the RAII
    // guard clears `Building` and an already-running reaper can release flock.
    crate::prover_lease::ensure_reaper_started()?;

    // Build + pin-check on a large stack; only the completed circuit or a
    // refusal string crosses back to the caller (the test-runner stack is too
    // small for by-value `SkeletonCircuit`; see `CircuitSlot` docs).
    let built = std::thread::Builder::new()
        .name("zkcoins-compliance-cache".to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let circuit =
                build_skeleton_circuit(CircuitConfig::standard_recursion_zk_config(), network);
            let digest = host::digest_to_bytes(&circuit.data.verifier_only.circuit_digest);
            if let Some(pins) = pins_slot(network).get() {
                crate::circuit_identity::require_one_live_digest_matches_pin(
                    "C", &digest, &pins.c, network,
                )?;
            }
            c_verified_flag(network).store(true, Ordering::Release);
            Ok::<_, String>(circuit)
        })
        .context("spawn compliance cache worker")?
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));

    let mut cache = lock_circuit_slot(slot);
    let result = match built {
        Ok(circuit) => {
            let circuit = Arc::new(circuit);
            *cache = Some(CircuitSlot::Ready(Arc::clone(&circuit)));
            Ok(circuit)
        }
        Err(error) => {
            *cache = Some(CircuitSlot::Refused(error.clone()));
            Err(anyhow::anyhow!(error))
        }
    };
    building.disarm();
    drop(cache);
    crate::prover_lease::note_active();
    result
}

/// Build or clone the resident `C_balance` for one network. A ready balance
/// circuit does not retain `C`, so its slot is checked before `C` is requested;
/// only a newly claimed balance build keeps `C` resident for construction and
/// the construction-time pin check shared with [`compliance_circuit`].
pub(crate) fn balance_circuit(network: Network) -> Result<Arc<BalanceCircuit>> {
    let slot = balance_circuit_slot(network);
    let (mut building, compliance) = loop {
        match claim_circuit_build(
            slot,
            || {
                balance_verified_flag(network).store(false, Ordering::Release);
            },
            || {
                crate::prover_lease::acquire_host_lease()?;
                crate::prover_lease::ensure_reaper_started()?;
                // `C_balance` copies only C's common/verifier data during
                // construction and retains no C reference. This dependency
                // preparation runs only for the claimed build, so a ready
                // balance hit neither reconstructs C nor marks C active.
                compliance_circuit(network)
            },
        ) {
            CircuitSlotClaim::Ready(circuit) => {
                crate::prover_lease::note_active();
                return Ok(circuit);
            }
            CircuitSlotClaim::Refused(error) => return Err(anyhow::anyhow!(error)),
            CircuitSlotClaim::Building => {
                // A short poll keeps the state machine simple while ensuring
                // no waiter retains the slot lock during the expensive build.
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            CircuitSlotClaim::Claimed {
                building,
                dependency,
            } => {
                let compliance = dependency?;
                break (building, compliance);
            }
        }
    };

    let built = std::thread::Builder::new()
        .name("zkcoins-balance-cache".to_owned())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let circuit = build_c_balance_circuit(&compliance, network);
            let digest = host::digest_to_bytes(&circuit.data.verifier_only.circuit_digest);
            if let Some(pins) = pins_slot(network).get() {
                crate::circuit_identity::require_one_live_digest_matches_pin(
                    "C_balance",
                    &digest,
                    &pins.c_balance,
                    network,
                )?;
            }
            balance_verified_flag(network).store(true, Ordering::Release);
            Ok::<_, String>(circuit)
        })
        .context("spawn balance cache worker")?
        .join()
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic));

    let mut cache = lock_circuit_slot(slot);
    let result = match built {
        Ok(circuit) => {
            let circuit = Arc::new(circuit);
            *cache = Some(CircuitSlot::Ready(Arc::clone(&circuit)));
            Ok(circuit)
        }
        Err(error) => {
            *cache = Some(CircuitSlot::Refused(error.clone()));
            Err(anyhow::anyhow!(error))
        }
    };
    building.disarm();
    drop(cache);
    crate::prover_lease::note_active();
    result
}

/// Evict every cache-owned circuit whose slot is its only remaining [`Arc`].
/// Returns true only when all six slots are empty in the lease sense.
pub(crate) fn try_evict_all_unreferenced() -> bool {
    let mut all_empty = true;
    // Inspect every slot even after one blocks release: other unreferenced
    // circuits should still be reclaimed during this pass.
    for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
        all_empty &= try_evict_slot(balance_circuit_slot(network));
        all_empty &= try_evict_slot(compliance_circuit_slot(network));
    }
    all_empty
}

/// Validate that the mandatory host-wide proving-lease file can be opened or
/// created at boot. The exclusive flock itself is acquired by the first build.
pub fn validate_prover_lease_path_at_boot() -> Result<()> {
    crate::prover_lease::ensure_lease_path_ready()
}

#[cfg(test)]
mod prover_lease_tests {
    use super::{claim_circuit_build, try_evict_slot, CircuitSlot, CircuitSlotClaim};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    #[test]
    fn ready_balance_slot_does_not_enter_dependency_build_branch() {
        // `BalanceCircuit` cannot be constructed cheaply in a unit test. This
        // stand-in exercises the same generic slot decision used before the
        // production `compliance_circuit` call; only `Claimed` may enter that
        // dependency-build branch.
        let slot: &'static Mutex<Option<CircuitSlot<u8>>> = Box::leak(Box::new(Mutex::new(
            Some(CircuitSlot::Ready(Arc::new(7_u8))),
        )));
        let compliance_builds = AtomicUsize::new(0);

        let circuit = match claim_circuit_build(
            slot,
            || {},
            || {
                compliance_builds.fetch_add(1, Ordering::Relaxed);
            },
        ) {
            CircuitSlotClaim::Ready(circuit) => circuit,
            CircuitSlotClaim::Claimed { .. } => {
                panic!("ready balance slot must not claim a build")
            }
            CircuitSlotClaim::Building => panic!("ready balance slot reported Building"),
            CircuitSlotClaim::Refused(error) => panic!("ready balance slot refused: {error}"),
        };

        assert_eq!(*circuit, 7);
        assert_eq!(compliance_builds.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn sole_cache_reference_is_evicted_and_empty() {
        let slot = Mutex::new(Some(CircuitSlot::Ready(Arc::new(7_u8))));

        assert!(try_evict_slot(&slot));
        assert!(slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none());
    }

    #[test]
    fn external_reference_blocks_release_until_dropped() {
        let resident = Arc::new(7_u8);
        let external = Arc::clone(&resident);
        let slot = Mutex::new(Some(CircuitSlot::Ready(resident)));

        assert!(
            !try_evict_slot(&slot),
            "the reaper must retain flock while an external circuit Arc lives"
        );
        drop(external);
        assert!(try_evict_slot(&slot));
        assert!(slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none());
    }

    #[test]
    fn nonresident_states_are_empty_but_building_blocks_release() {
        let none = Mutex::<Option<CircuitSlot<u8>>>::new(None);
        let refused = Mutex::new(Some(CircuitSlot::<u8>::Refused("pin mismatch".to_owned())));
        let building = Mutex::new(Some(CircuitSlot::<u8>::Building));

        assert!(try_evict_slot(&none));
        assert!(try_evict_slot(&refused));
        assert!(!try_evict_slot(&building));
    }

    #[test]
    fn building_guard_restores_slot_after_unwind_path() {
        let slot: &'static Mutex<Option<CircuitSlot<u8>>> =
            Box::leak(Box::new(Mutex::new(Some(CircuitSlot::Building))));
        {
            let _building = super::BuildingSlotGuard::new(slot);
        }

        assert!(slot
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_none());
    }
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
    // `anchor.height` is already `u64`; no range check is expressible here.
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

    set_u64_limbs(&mut witness, targets.nav.size, w.nav.size)?;
    witness.set_hash_target(targets.nav.mth, w.nav.mth)?;
    set_bytes(&mut witness, &targets.nav_rand, &w.nav_rand)?;
    let prev_nav = w.prev_nav_opening.unwrap_or(NavOpening {
        nav: Nav {
            size: 0,
            mth: host::nflog_empty(),
        },
        nav_rand: [0u8; 32],
    });
    set_u64_limbs(
        &mut witness,
        targets.prev_nav_opening.nav.size,
        prev_nav.nav.size,
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
    set_u64_limbs(
        &mut witness,
        targets.prev_state_nullifier.pos_prev,
        predecessor.map_or(0, |value| value.position),
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
    set_u64_limbs(
        &mut witness,
        targets.public.size_ceiling,
        w.statement.nav_ceiling.size,
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
    set_u64_limbs(
        &mut witness,
        targets.witness.nav.size,
        w.nav_opening.nav.size,
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
    set_u64_limbs(witness, target.send_counter, state.send_counter)?;
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
    set_u64_limbs(
        witness,
        auth_target.pos_create,
        auth.map_or(0, |auth| auth.pos_create),
    )?;
    let creating_nav = auth.map_or(
        Nav {
            size: 0,
            mth: host::nflog_empty(),
        },
        |auth| auth.creating_nav_opening.nav,
    );
    set_u64_limbs(
        witness,
        auth_target.creating_nav_opening.nav.size,
        creating_nav.size,
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

pub(crate) fn field_bytes<FF: PrimeField>(value: FF) -> [u8; 32] {
    let encoded = value.to_canonical_biguint().to_bytes_be();
    assert!(encoded.len() <= 32);
    let mut bytes = [0u8; 32];
    bytes[32 - encoded.len()..].copy_from_slice(&encoded);
    bytes
}

pub(crate) fn is_odd<FF: PrimeField>(value: FF) -> bool {
    (&value.to_canonical_biguint() & BigUint::from(1u8)) == BigUint::from(1u8)
}

pub(crate) fn tagged_hash(tag: &[u8], message: &[u8]) -> [u8; 32] {
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
    let r =
        (r_prime + (CurveScalar(tweak) * Secp256K1::GENERATOR_PROJECTIVE).to_affine()).to_affine();
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
    let e = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&tagged_hash(
        b"BIP0340/challenge",
        &challenge_preimage,
    )));

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

pub(crate) fn canonical_scalar(bytes: &[u8; 32], label: &str) -> Result<Secp256K1Scalar> {
    let integer = BigUint::from_bytes_be(bytes);
    ensure!(
        integer < Secp256K1Scalar::order(),
        "{label} is not a canonical secp256k1 scalar"
    );
    Ok(Secp256K1Scalar::from_noncanonical_biguint(integer))
}

pub(crate) fn canonical_x_point(bytes: &[u8; 32], label: &str) -> Result<AffinePoint<Secp256K1>> {
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

/// Every `C_balance` application public input (§2.5), decoded from the proof itself — never
/// from a wrapper/header value supplied alongside it. `nav_ceiling` is the disclosed accumulator
/// ROOT digest (matches `BalanceAttestationStatement.nav_ceiling.root()`, NOT a raw `mth`).
/// Must be `pub`: it is the `Ok` type of the `pub fn verify_attestation`, so Rust's
/// private-type-in-public-interface rule forces it public (mirrors why `DecodedBalanceAttestation`
/// / `VerifyBalanceAttestationError` had to be `pub` in `node`'s `attest_verify` module last round).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BalancePublicStatement {
    pub subject: Address,
    pub asset_id: HashDigest,
    pub balance: u128,
    pub nav_ceiling: HashDigest,
    pub size_ceiling: u64,
    pub anchor: BalanceAnchor,
    pub network_id: HashDigest,
}

/// Decode the frozen 60-element `C_balance` public-input vector (order fixed by
/// `program-plonky2/src/circuit/balance/targets.rs:251-262`) into a typed statement. Mirrors
/// `extract_transition_public_inputs` exactly (same `digest()` closure shape, same
/// `bytes_from_u32_le_limbs` reuse for 32-byte fields); stays a crate-private free fn so the
/// checked verifier-cache wrapper can reuse exactly the same extraction logic.
pub(crate) fn extract_balance_public_inputs(
    proof: &BalanceProof,
) -> Result<BalancePublicStatement> {
    ensure!(
        proof.public_inputs.len() == 60,
        "balance-attestation proof has {} public inputs, expected 60",
        proof.public_inputs.len()
    );
    let pi = &proof.public_inputs;
    let digest = |offset: usize| HashOut {
        elements: pi[offset..offset + 4]
            .try_into()
            .expect("validated PI slice length"),
    };
    let u32_limb = |t: F| -> Result<u64> {
        let v = t.to_canonical_u64();
        ensure!(
            v <= u64::from(u32::MAX),
            "public input limb is not a canonical u32"
        );
        Ok(v)
    };
    let subject_bytes = bytes_from_u32_le_limbs(&pi[0..8])?;
    let asset_id = digest(8);
    let mut balance: u128 = 0;
    for index in 0..4 {
        balance |= (u32_limb(pi[12 + index])? as u128) << (32 * index);
    }
    let nav_ceiling = digest(16);
    let size_ceiling = u32_limb(pi[20])? | (u32_limb(pi[21])? << 32);
    let anchor_txid = bytes_from_u32_le_limbs(&pi[22..30])?;
    let anchor_block_hash = bytes_from_u32_le_limbs(&pi[30..38])?;
    let anchor_height = u32_limb(pi[38])? | (u32_limb(pi[39])? << 32);
    let anchor_pk = bytes_from_u32_le_limbs(&pi[40..48])?;
    let anchor_r = bytes_from_u32_le_limbs(&pi[48..56])?;
    let network_id = digest(56);
    Ok(BalancePublicStatement {
        subject: Address(subject_bytes),
        asset_id,
        balance,
        nav_ceiling,
        size_ceiling,
        anchor: BalanceAnchor {
            txid: anchor_txid,
            block_hash: anchor_block_hash,
            height: anchor_height,
            public_key: anchor_pk,
            signature_r: anchor_r,
        },
        network_id,
    })
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

/// Deterministic BIP-340 + sign-to-contract helpers for host integration
/// tests and ignored multi-minute prove fixtures.
///
/// **Not a production wallet API.** Exposed (not `cfg(test)`) so dependent
/// crates such as `node` can build host-valid clause-10 fixtures without
/// reimplementing S2C. Production signing remains Gap G4 (wallet-side).
pub mod test_signing {
    use num::BigUint;
    use plonky2::field::types::Field;
    use sha2::{Digest, Sha256};

    use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
    use zkcoins_program_plonky2::circuit::gadgets::curve_types::{
        AffinePoint, Curve, CurveScalar, Secp256K1,
    };

    #[cfg(test)]
    use super::{extract_transition_public_inputs, ProvedTransition};
    use super::{field_bytes, is_odd, tagged_hash, Network, ProofData, TransitionSignature};
    use shared::spec_v1 as host;

    #[derive(Clone)]
    pub struct TestSignature {
        pub transition: TransitionSignature,
        pub r_prime_point: AffinePoint<Secp256K1>,
    }

    pub fn deterministic_secret(label: &[u8]) -> Secp256K1Scalar {
        let digest = Sha256::digest(label);
        let scalar = Secp256K1Scalar::from_noncanonical_biguint(BigUint::from_bytes_be(&digest));
        assert!(scalar.is_nonzero());
        scalar
    }

    pub fn normalized_key(
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
    pub fn sign_transition(
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
    ///
    /// Builds the compliance circuit (expensive). Prefer a host-only empty
    /// `ProofWithPublicInputs` for begin_* host tests that only need
    /// `last_proof: Some(_)` and never prove.
    ///
    /// Crate-private test helper only (Stage 3 Runde 4: no residual production use).
    #[cfg(test)]
    pub(crate) fn base_proved_transition(network: Network) -> ProvedTransition {
        let proof = super::compliance_circuit(network)
            .expect("compliance circuit")
            .base_proof
            .clone();
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
pub(crate) mod tests {
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

    /// Shape metrics from the committed digests file — the same file
    /// `tests/generated_circuit_digests_test.rs` regenerates and verifies.
    /// That integration test has no shared parse helper (it rebuilds the
    /// whole file and does string equality), so unit tests here cannot
    /// import it; look up the key instead of hard-coding a second number.
    fn pinned_circuit_metric(key: &str) -> usize {
        const PINNED_DIGESTS: &str = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/generated_circuit_digests.txt"
        ));
        for line in PINNED_DIGESTS.lines() {
            let Some((k, v)) = line.split_once(" = ") else {
                continue;
            };
            if k == key {
                return v.parse::<usize>().unwrap_or_else(|e| {
                    panic!("pinned digests: key `{key}` has non-usize value `{v}`: {e}");
                });
            }
        }
        panic!("pinned digests file missing required key `{key}`");
    }

    pub(crate) fn real_balance_attestation_fixture(
    ) -> (ProverBridge, ProvedAttestation, BalanceAttestationStatement) {
        let bridge = ProverBridge::new(Network::Testnet);
        let genesis = genesis_fixture();
        let proved_genesis = bridge
            .prove_transition(&genesis.witness)
            .expect("genuine genesis/mint proof for verifier-cache fixture");
        let witness = attestation_witness(&genesis, &proved_genesis);
        let expected_statement = witness.statement;
        let proved_attestation = bridge
            .prove_attestation(&witness)
            .expect("genuine C_balance proof for verifier-cache fixture");
        (bridge, proved_attestation, expected_statement)
    }

    /// A genuine `(ProverBridge, ProvedTransition)` pair for the compliance verifier-cache
    /// round-trip test in `verifier_cache.rs` — same pattern as
    /// `real_balance_attestation_fixture`, but for circuit `C` itself.
    pub(crate) fn real_transition_fixture() -> (ProverBridge, ProvedTransition) {
        let bridge = ProverBridge::new(Network::Testnet);
        let genesis = genesis_fixture();
        let proved_genesis = bridge
            .prove_transition(&genesis.witness)
            .expect("genuine genesis/mint proof for verifier-cache fixture");
        (bridge, proved_genesis)
    }

    #[test]
    #[ignore = "heavy: real Plonky2 prove end-to-end (minutes); run with --ignored --release"]
    fn prover_bridge_real_end_to_end() {
        let bridge = ProverBridge::new(Network::Testnet);
        assert_eq!(
            bridge.compliance_gate_count(),
            pinned_circuit_metric("circuit_c_gates"),
        );

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
        let extracted_public_inputs = bridge
            .verify_attestation(&proved_attestation.proof)
            .expect("valid C_balance proof");
        assert_eq!(
            extracted_public_inputs.subject,
            attestation.statement.subject
        );
        assert_eq!(
            extracted_public_inputs.asset_id,
            attestation.statement.asset_id
        );
        assert_eq!(
            extracted_public_inputs.balance,
            attestation.statement.balance
        );
        assert_eq!(
            extracted_public_inputs.nav_ceiling,
            attestation.statement.nav_ceiling.root()
        );
        assert_eq!(
            extracted_public_inputs.size_ceiling,
            attestation.statement.nav_ceiling.size
        );
        assert_eq!(extracted_public_inputs.anchor, attestation.statement.anchor);
        assert_eq!(
            extracted_public_inputs.network_id,
            network_id(bridge.network())
        );
        assert_eq!(
            bridge.balance_gate_count(),
            pinned_circuit_metric("circuit_c_balance_gates"),
        );
        println!("prover bridge balance attestation: PASS (proved and verified)");
        println!(
            "prover bridge gates: C={} C_balance={}",
            bridge.compliance_gate_count(),
            bridge.balance_gate_count()
        );
    }

    /// `install_network_pins` is idempotent for the same pair and refuses a
    /// different pair. Uses `Network::Mainnet` because no other non-ignored
    /// test in this binary installs Mainnet pins (ignored circuit-build tests
    /// that do are outside the default suite). Touches only the pins
    /// `OnceLock` — no circuit construction.
    #[test]
    fn install_network_pins_idempotent_same_pair_refuses_different() {
        // Distinct from any real pin so a collision with a prior install of
        // production digests would still surface as a hard error rather than
        // a silent pass.
        let pin_c = [0xAAu8; 32];
        let pin_c_balance = [0xBBu8; 32];
        let network = Network::Mainnet;

        ProverBridge::install_network_pins(network, pin_c, pin_c_balance)
            .expect("first install of synthetic Mainnet pins must succeed");
        ProverBridge::install_network_pins(network, pin_c, pin_c_balance)
            .expect("re-install of the identical pin pair must be idempotent Ok");

        let mut different_c = pin_c;
        different_c[0] ^= 0xFF;
        let err = ProverBridge::install_network_pins(network, different_c, pin_c_balance)
            .expect_err("installing a different pin pair must refuse overwrite");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("already installed") || msg.contains("refusing to overwrite"),
            "error must name the no-overwrite refusal: {msg}"
        );
    }

    /// `mark_balance_identity_verified_from_cache` refuses without pins / on
    /// digest mismatch, and sets `balance_verified_flag` only when the
    /// cache-verified digest matches the installed `c_balance` pin.
    /// Uses `Network::Regtest` so the process-global Mainnet pins of
    /// `install_network_pins_idempotent_same_pair_refuses_different` are
    /// never touched. Synthetic digests only — no circuit construction.
    #[test]
    fn mark_balance_identity_verified_from_cache_requires_matching_pin() {
        use std::sync::atomic::Ordering;

        let pin_c = [0xCCu8; 32];
        let pin_c_balance = [0xDDu8; 32];
        let network = Network::Regtest;

        let err_no_pins =
            ProverBridge::mark_balance_identity_verified_from_cache(network, pin_c_balance)
                .expect_err("mark without install_network_pins must refuse");
        let msg_no_pins = format!("{err_no_pins:#}");
        assert!(
            msg_no_pins.contains("install_network_pins must run before"),
            "error must name the missing-pins refusal: {msg_no_pins}"
        );

        ProverBridge::install_network_pins(network, pin_c, pin_c_balance)
            .expect("first install of synthetic Regtest pins must succeed");

        let mut wrong_balance = pin_c_balance;
        wrong_balance[0] ^= 0xFF;
        let err_mismatch =
            ProverBridge::mark_balance_identity_verified_from_cache(network, wrong_balance)
                .expect_err("mark with digest ≠ installed c_balance pin must refuse");
        let msg_mismatch = format!("{err_mismatch:#}");
        assert!(
            msg_mismatch.contains("does not match installed pin")
                || msg_mismatch.contains("refusing to mark verified"),
            "error must name the pin-mismatch refusal: {msg_mismatch}"
        );
        assert!(
            !super::balance_verified_flag(network).load(Ordering::Acquire),
            "balance_verified_flag must stay false after a refused mark"
        );

        ProverBridge::mark_balance_identity_verified_from_cache(network, pin_c_balance)
            .expect("mark with digest == installed c_balance pin must succeed");
        assert!(
            super::balance_verified_flag(network).load(Ordering::Acquire),
            "balance_verified_flag must be true after a successful cache-backed mark"
        );
    }

    /// `mark_compliance_verifier_from_cache` refuses without pins / on pin
    /// mismatch / on a FIX3 self-bind digest mismatch (verified_c_digest
    /// matches the installed pin but disagrees with verifier_data's OWN
    /// embedded circuit_digest), and installs the verifier + sets
    /// `c_verified_flag` only when all three agree. A second mark call after
    /// a successful one refuses (no silent replace). Uses `Network::Testnet`
    /// — see the module-level comment above this test for why. Dummy
    /// circuits only (built via a bare `CircuitBuilder`, not
    /// `compliance_circuit`) — no real ~1.38M-gate circuit construction.
    #[test]
    fn mark_compliance_verifier_from_cache_requires_matching_pin_and_self_bound_digest() {
        use plonky2::plonk::circuit_builder::CircuitBuilder;

        fn dummy_compliance_verifier_data(
            num_public_inputs: usize,
        ) -> VerifierCircuitData<F, C, D> {
            let mut builder =
                CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
            for _ in 0..num_public_inputs {
                let target = builder.add_virtual_target();
                builder.register_public_input(target);
            }
            builder.build::<C>().verifier_data()
        }

        let network = Network::Testnet;
        let matching = dummy_compliance_verifier_data(1);
        let matching_digest = host::digest_to_bytes(&matching.verifier_only.circuit_digest);
        let mismatched = dummy_compliance_verifier_data(3);
        let mismatched_digest = host::digest_to_bytes(&mismatched.verifier_only.circuit_digest);
        assert_ne!(
            matching_digest, mismatched_digest,
            "the two dummy circuits must have distinct digests for this test to mean anything"
        );

        let err_no_pins = ProverBridge::mark_compliance_verifier_from_cache(
            network,
            matching_digest,
            matching.clone(),
        )
        .expect_err("mark without install_network_pins must refuse");
        assert!(
            format!("{err_no_pins:#}").contains("install_network_pins must run before"),
            "error must name the missing-pins refusal: {err_no_pins:#}"
        );

        // Install Testnet pins with pin_c pinned to `matching`'s own real
        // digest (pin_c_balance is irrelevant to this function; any value).
        ProverBridge::install_network_pins(network, matching_digest, [0x11u8; 32])
            .expect("install synthetic Testnet pins pinned to the dummy circuit's real digest");

        let mut wrong_pin_digest = matching_digest;
        wrong_pin_digest[0] ^= 0xFF;
        let err_pin_mismatch = ProverBridge::mark_compliance_verifier_from_cache(
            network,
            wrong_pin_digest,
            matching.clone(),
        )
        .expect_err("verified_c_digest != installed pin must refuse");
        assert!(
            format!("{err_pin_mismatch:#}").contains("does not match installed pin"),
            "error must name the pin-mismatch refusal: {err_pin_mismatch:#}"
        );

        // FIX3: verified_c_digest matches the installed pin, but disagrees
        // with verifier_data's OWN embedded circuit_digest.
        let err_self_bind =
            ProverBridge::mark_compliance_verifier_from_cache(network, matching_digest, mismatched)
                .expect_err("verifier_data digest disagreeing with verified_c_digest must refuse");
        assert!(
            format!("{err_self_bind:#}").contains("verifier_data's own circuit_digest"),
            "error must name the self-bind refusal: {err_self_bind:#}"
        );
        assert!(
            !super::c_verified_flag(network).load(std::sync::atomic::Ordering::Acquire),
            "c_verified_flag must stay false after every refused mark above"
        );

        // All three agree: succeeds.
        ProverBridge::mark_compliance_verifier_from_cache(network, matching_digest, matching)
            .expect("matching digest + matching verifier_data must succeed");
        assert!(
            super::c_verified_flag(network).load(std::sync::atomic::Ordering::Acquire),
            "c_verified_flag must be true after a successful cache-backed mark"
        );

        // Double mark: the OnceLock slot refuses a second install (same
        // digest as `matching`, so this exercises ONLY the no-overwrite path,
        // not a fresh pin/self-bind refusal).
        let second = dummy_compliance_verifier_data(1);
        let err_double =
            ProverBridge::mark_compliance_verifier_from_cache(network, matching_digest, second)
                .expect_err("a second mark for the same network must refuse (no silent replace)");
        assert!(
            format!("{err_double:#}").contains("already marked"),
            "error must name the no-overwrite refusal: {err_double:#}"
        );
    }

    /// Exercises `verify_transition` / `load_transition_proof_bytes` /
    /// `bind_prev_proof_identity`'s CACHED-slot branch (populated via
    /// `mark_compliance_verifier_from_cache`) with a genuine proof (must
    /// accept) and a tampered proof (must reject on all three). The existing
    /// `verifier_cache.rs` real round-trip test covers
    /// `CachedComplianceVerifier` directly; this test covers `ProverBridge`'s
    /// own cached-slot methods, which is the code path Secondary boots
    /// actually use. Heavy: builds the real ~1.38M-gate (2^21) `C` circuit.
    #[test]
    #[ignore = "heavy: real Plonky2 C build + prove, exercises ProverBridge's cached-verifier-slot \
                verify paths (minutes; C is ~1.38M gates / ~90-100 GiB per docs/build-report.md)"]
    fn mark_compliance_verifier_from_cache_exercises_cached_verify_paths() {
        fn pinned_digest_32(key: &str) -> [u8; 32] {
            const PINNED_DIGESTS: &str = include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/generated_circuit_digests.txt"
            ));
            let value = PINNED_DIGESTS
                .lines()
                .find_map(|line| {
                    let (candidate, value) = line.split_once(" = ")?;
                    (candidate == key).then_some(value)
                })
                .unwrap_or_else(|| panic!("pinned digests file missing required key `{key}`"));
            let hex = value
                .strip_prefix("0x")
                .unwrap_or_else(|| panic!("pinned digest `{key}` lacks 0x prefix"));
            assert_eq!(hex.len(), 64, "pinned digest `{key}` must contain 32 bytes");
            let mut out = [0u8; 32];
            for (index, byte) in out.iter_mut().enumerate() {
                *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16)
                    .unwrap_or_else(|e| panic!("pinned digest `{key}` has invalid hex: {e}"));
            }
            out
        }

        let network = Network::Testnet;
        let pin_c = pinned_digest_32("circuit_digest_c_testnet");
        let pin_c_balance = pinned_digest_32("circuit_digest_c_balance_testnet");
        ProverBridge::install_network_pins(network, pin_c, pin_c_balance)
            .expect("install matching testnet circuit pins before construction");

        // Genuine proof through the warm real circuit — same fixture the
        // verifier_cache.rs real round-trip test uses.
        let (bridge, proved_genesis) = real_transition_fixture();

        let circuit = compliance_circuit(network).expect("C already built above");
        let verifier_data = circuit.data.verifier_data();
        let verified_c_digest = host::digest_to_bytes(&verifier_data.verifier_only.circuit_digest);
        assert_eq!(verified_c_digest, pin_c);
        ProverBridge::mark_compliance_verifier_from_cache(
            network,
            verified_c_digest,
            verifier_data,
        )
        .expect("mark the real C verifier data into the cached slot");

        bridge
            .verify_transition(&proved_genesis.proof)
            .expect("genuine proof must verify through the cached-slot path");

        let wire_bytes = proved_genesis.proof.to_bytes();
        let loaded = bridge
            .load_transition_proof_bytes(&wire_bytes)
            .expect("genuine wire-encoded proof must load + bind through the cached-slot path");
        assert_eq!(loaded.public_inputs, proved_genesis.proof.public_inputs);

        bridge
            .bind_prev_proof_identity(&proved_genesis.proof)
            .expect("genuine proof must bind to C identity through the cached-slot path");

        let mut tampered = proved_genesis.proof.clone();
        tampered.public_inputs[40] += F::ONE;
        assert!(
            bridge.verify_transition(&tampered).is_err(),
            "tampered proof must fail verify_transition through the cached-slot path"
        );
        assert!(
            bridge.bind_prev_proof_identity(&tampered).is_err(),
            "tampered proof must fail bind_prev_proof_identity through the cached-slot path"
        );
        let tampered_wire_bytes = tampered.to_bytes();
        assert!(
            bridge
                .load_transition_proof_bytes(&tampered_wire_bytes)
                .is_err(),
            "tampered wire-encoded proof must be rejected by load_transition_proof_bytes \
             through the cached-slot path"
        );

        println!(
            "prover bridge cached-verifier-slot paths: PASS (genuine accepted, tampered rejected)"
        );
    }
}
