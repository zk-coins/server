//! In-memory zkCoins state-transition engine (P1-E.2).
//!
//! Wires host state primitives (`AccountState`, per-account `CoinHistTree`,
//! global `NfLogAccumulator`) to the P1-E.1 [`ProverBridge`] and drives the
//! §2.3 two-phase lifecycle (`request` → `awaiting_signature` → `finalise`)
//! for mint / send / receive.
//!
//! # Scope / non-scope
//!
//! - Purely in-memory: no DB, no I/O, no REST (those are P1-G).
//! - Fail-loud: every invalid state returns `Err`; checks are never skipped.
//! - **Receive path assumption:** [`StateEngine::begin_receive`] admits an
//!   already-verified received coin. The caller's node is responsible for
//!   decrypting the `CoinProof` bundle and re-verifying the creating proof /
//!   Bitcoin first-occurrence scan **before** calling `begin_receive`. Bundle
//!   decrypt and Bitcoin scan belong to P1-G.
//! - **Incoming-transition host checks:** [`StateEngine::verify_incoming_transition`]
//!   runs bridge verify + cyclic-tail pin and the canonical-NAV / `size_final`
//!   precondition (D.5 Caveat A). The Bitcoin first-occurrence anchor check for
//!   a foreign `(Pk, R)` needs the chain scanner and is **out of scope here**
//!   (P1-G).

use std::collections::{BTreeMap, BTreeSet, HashMap};

use anyhow::{bail, ensure, Context, Result};
use shared::spec_v1::{
    self as host, AccountState, Address, ChainPosition, Coin, CoinHistTree, CoinTemplate,
    FoldOutcome, HashDigest, LookupResult, Nav, NfLogAccumulator, NfLogEntry, ProofData,
    PublishedNullifier, TreeKind,
};
use zkcoins_program_plonky2::circuit::compliance::{
    Network, MAX_ACCOUNT_ASSETS, MAX_RX_COINS, MAX_TX_INPUTS, MAX_TX_OUTPUTS,
};

use crate::prover_bridge::{
    AssetIssuance, ComplianceProof, InputAuthorization, NavOpening, NullifierOpening,
    PredecessorNullifier, ProvedTransition, ProverBridge, ReceivedAuthorization, TransitionMode,
    TransitionSignature, TransitionWitness,
};

// ---------------------------------------------------------------------------
// Scanner-only NfLog append capability
// ---------------------------------------------------------------------------

/// Capability token proving a nullifier was observed on the scan path.
///
/// Fields are private. The sole production constructor is
/// [`ScannedNullifier::from_survivor`], which takes a
/// [`PublishedNullifier`] emitted by the scanner (or by the node-side
/// fold of scanner survivors). A free-floating [`ChainPosition`] cannot
/// reach [`StateEngine::append_nullifier`] — possession of this type is
/// the proof the position came through the scan path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScannedNullifier {
    chain_pos: ChainPosition,
    pk: [u8; 32],
    r: [u8; 32],
}

impl ScannedNullifier {
    /// Mint a scan-path capability from a survivor observed on chain.
    ///
    /// This is the only production constructor. Callers outside the scan
    /// fold must not invent positions; they hold a survivor the scanner
    /// (or `members_to_published` of a scanned inscription) produced.
    pub fn from_survivor(nf: &PublishedNullifier) -> Self {
        Self {
            chain_pos: nf.chain_pos,
            pk: nf.pk,
            r: nf.r,
        }
    }

    pub fn chain_pos(self) -> ChainPosition {
        self.chain_pos
    }

    pub fn pk(self) -> [u8; 32] {
        self.pk
    }

    pub fn r(self) -> [u8; 32] {
        self.r
    }
}

// ---------------------------------------------------------------------------
// Request types (wallet → engine)
// ---------------------------------------------------------------------------

/// §2.3.1 mint / issuance intent.
#[derive(Clone, Debug)]
pub struct MintRequest {
    pub owner: Address,
    /// Operational nullifier key (node operational bundle).
    pub nk: [u8; 32],
    /// Nav-rand secret (A/4'; operational bundle). Keys deterministic `nav_rand`.
    /// Debug-redacted via [`OpSecret`]; never caller-supplied as `nav_rand`.
    pub op_secret: OpSecret,
    /// Consumed spend key `Pkᵢ` (`Pk₀` for a genesis mint).
    pub current_pubkey: [u8; 32],
    /// Rotated spend key `Pkᵢ₊₁` folded into `new_account_state`.
    pub next_pubkey: [u8; 32],
    /// Human-readable asset name (hashed; never on-chain).
    pub name: Vec<u8>,
    pub decimals: u8,
    pub amount: u128,
    /// Token standard: `1` (default / uncapped) or `2` (capped).
    pub issuance_version: u8,
    /// Token-standard-2 supply cap; must be `0` for standard 1.
    pub cap_total: u128,
    /// Token-standard-2 terms salt; all-zero for standard 1.
    pub terms_salt: [u8; 32],
    pub npk_rand: [u8; 32],
}

/// §2.3.2 send intent. Change outputs are computed by the engine.
///
/// `nav_rand` is **not** a request field: the engine derives it from the
/// account's stored `op_secret` and the entry `send_counter` of the pending
/// transition (§1.4 / Requirement 10).
#[derive(Clone, Debug)]
pub struct SendRequest {
    pub owner: Address,
    /// Identifiers of spendable coins the account owns (state-`1`).
    pub input_coin_ids: Vec<HashDigest>,
    /// Recipient output templates (before per-asset change).
    pub output_templates: Vec<CoinTemplate>,
    pub next_pubkey: [u8; 32],
    pub npk_rand: [u8; 32],
}

/// §2.3.3 receive intent.
///
/// **Precondition (caller):** each entry of `received_coins` / `received_auth`
/// comes from a `CoinProof` the caller has already decrypted and fully
/// re-verified (creating proof + clause-10 host material). Bundle decrypt and
/// the Bitcoin first-occurrence scan are P1-G responsibilities — this engine
/// only folds the verified receipt into the account state.
///
/// `nav_rand` is derived inside the engine from `op_secret` and the entry
/// `send_counter` — it is not representable on this type.
#[derive(Clone, Debug)]
pub struct ReceiveRequest {
    pub owner: Address,
    /// Operational nullifier key. Required so a first receive can construct
    /// the canonical empty account for the `InitialProof` path.
    pub nk: [u8; 32],
    /// Nav-rand secret (A/4'; operational bundle). Required on every receive
    /// so a first-transition account can be created and so a registered
    /// account can refuse a mismatched bundle.
    pub op_secret: OpSecret,
    /// Consumed spend key `Pkᵢ` (`Pk₀` for a first-transition receive).
    pub current_pubkey: [u8; 32],
    pub received_coins: Vec<Coin>,
    pub received_auth: Vec<ReceivedAuthorization>,
    pub next_pubkey: [u8; 32],
    pub npk_rand: [u8; 32],
}

/// Operational nav-rand secret (`A/4'`, §1.2). Part of the operational bundle
/// entrusted to the account's **own** node — never sent to a foreign node,
/// never logged, and never formatted as raw bytes.
///
/// ## Formatting / outward surfaces
///
/// - [`Debug`] and [`Display`] always print `OpSecret([REDACTED])` so any
///   `{:?}` / `{}` on a request, pending transition, capability, or account
///   record is safe by construction (including nested `Job` / panic paths).
/// - [`serde::Serialize`] / [`serde::Deserialize`] intentionally carry the
///   raw 32 bytes: durable finalisation persists
///   `bincode(FinalisationCapability)` (which embeds this secret) and the
///   account row stores it as `BYTEA`. Those paths are storage, not logs.
///   Callers that embed the serialized form in a `Debug` surface (e.g. hex
///   of the capability blob) must redact at *that* type — see
///   `DurableFinalisationPersist` / `Job`.
#[derive(Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OpSecret(pub [u8; 32]);

impl OpSecret {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for OpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpSecret([REDACTED])")
    }
}

impl std::fmt::Display for OpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OpSecret([REDACTED])")
    }
}

// ---------------------------------------------------------------------------
// State model
// ---------------------------------------------------------------------------

/// Metadata needed to spend a state-`1` coin (clause-2 auth + history).
#[derive(Clone, Debug)]
pub struct TrackedCoin {
    pub coin: Coin,
    /// `prev_ash` of the transition that created this coin (clause 2 / 5).
    pub creating_prev_ash: HashDigest,
    /// Output index within the creating transition.
    pub coin_index: u32,
}

/// Per-account in-memory record.
pub struct AccountRecord {
    pub state: AccountState,
    pub coinhist: CoinHistTree,
    /// Account nullifier key (operational bundle).
    pub nk: [u8; 32],
    /// Nav-rand secret (A/4'; operational bundle). `None` only for pre-migration
    /// rows that never received a bundle write — any transition that needs
    /// `nav_rand` **refuses** rather than inventing a value.
    pub op_secret: Option<OpSecret>,
    /// Address-bound genesis spend key `Pk₀`.
    pub genesis_pubkey: [u8; 32],
    /// Spendable (state-`1`) coins keyed by `digest_to_bytes(identifier)`.
    pub spendable: BTreeMap<[u8; 32], TrackedCoin>,
    /// Spent (state-`2`) coin ids retained so the coin-history SMT can be
    /// rebuilt without cloning `CoinHistTree`.
    pub spent_ids: BTreeSet<[u8; 32]>,
    /// Last compliance proof (required for `AccountUpdateProof`).
    pub last_proof: Option<ComplianceProof>,
    pub last_nav_opening: Option<NavOpening>,
    pub last_nullifier: Option<NullifierOpening>,
    pub last_nullifier_pos: Option<u64>,
}

/// Phase-1 output: witness ready for the wallet to sign (`awaiting_signature`).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct PendingTransition {
    /// Full `TransitionWitness` with a placeholder signature; `finalise`
    /// overwrites `transition_signature` before proving.
    pub witness_wip: TransitionWitness,
    pub proof_data: ProofData,
    pub proof_data_hash: [u8; 32],
    pub mode: TransitionMode,
    /// Account this transition advances.
    pub owner: Address,
    /// NAV opening used for this transition (stored on apply).
    pub nav_opening: NavOpening,
    /// Operational nav-rand secret resolved for this transition (bundle).
    /// Persisted onto the account on apply; Debug-redacted.
    pub op_secret: OpSecret,
}

/// Durable, engine-owned finalisation capability for **prove + apply**.
///
/// Contains **everything** [`StateEngine::finalise`] /
/// [`StateEngine::prove_pending_transition_detached`] +
/// [`StateEngine::apply_proved_transition`] need from the host side.
///
/// Host-side publication of the §7.5 job result and job completion carry
/// additional durable fields on the node envelope (`completion_result` /
/// `completion_status` / `publisher_pubkey`) — derived the same way, from
/// what those steps depend on including handed-in values. This engine type
/// deliberately stops at prove/apply; the node composes the full path.
///
/// ## Contents (derived from what prove/apply depends on)
///
/// | Field | Why it is here |
/// |-------|----------------|
/// | `pending` (full [`PendingTransition`]) | prove installs the signature on the full host witness; apply re-validates live deps against it |
/// | `signature` (once accepted) | caller-supplied wallet authorisation; prove binds it into the witness |
///
/// Live engine state (account tip, NfLog size, CoinHist, own-Pk absence) is
/// **not** snapshotted here: apply re-validates those against the live engine
/// after prove (same invariant as the receive path).
///
/// ## Idempotency of consumers
///
/// This type is pure data. Callers make resume safe with an **exclusive
/// status claim** (only one resumer may enter finalise) and by persisting
/// the completion surface after apply so a second resume publishes and
/// completes without re-applying. The engine itself fails loud on a second
/// apply against a moved account head.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct FinalisationCapability {
    pending: PendingTransition,
    signature: Option<TransitionSignature>,
}

impl FinalisationCapability {
    /// Stage a pending transition produced by `begin_*` (unsigned).
    pub fn stage(pending: PendingTransition) -> Self {
        Self {
            pending,
            signature: None,
        }
    }

    /// Install a wallet signature that already passed host verification.
    ///
    /// Fails loud if `sig.pk_i` does not match the pending account head —
    /// never stores a signature that cannot authorise this transition.
    pub fn install_signature(&mut self, sig: TransitionSignature) -> Result<()> {
        ensure!(
            sig.pk_i == self.pending.witness_wip.prev_account_state.current_pubkey,
            "FinalisationCapability::install_signature: pk_i does not match \
             pending prev_account_state.current_pubkey"
        );
        self.signature = Some(sig);
        Ok(())
    }

    pub fn pending(&self) -> &PendingTransition {
        &self.pending
    }

    pub fn pending_mut(&mut self) -> &mut PendingTransition {
        &mut self.pending
    }

    pub fn signature(&self) -> Option<&TransitionSignature> {
        self.signature.as_ref()
    }

    pub fn is_signed(&self) -> bool {
        self.signature.is_some()
    }

    /// Split into the `(pending, signature)` pair finalise consumes.
    ///
    /// Fails if no signature has been installed — never invents a zero sig.
    pub fn into_finalise_parts(self) -> Result<(PendingTransition, TransitionSignature)> {
        let sig = self.signature.ok_or_else(|| {
            anyhow::anyhow!(
                "FinalisationCapability::into_finalise_parts: no signature installed"
            )
        })?;
        Ok((self.pending, sig))
    }
}

/// Capability token: a pending transition that has been **proved**.
///
/// Fields are private. The sole production constructors are
/// [`StateEngine::prove_pending_transition`] and
/// [`StateEngine::prove_pending_transition_detached`]. Possession of this
/// type is the proof a real prove ran — callers of
/// [`StateEngine::apply_proved_transition`] (and node
/// `commit_proved_receive`) cannot fabricate a hollow envelope.
///
/// A test-only hollow mint exists under **`#[cfg(test)]` in this crate only**
/// so unit tests here can inject concurrent scan work between prove and apply
/// without a multi-minute circuit. `cfg(test)` is never true for a dependency
/// library build — external crates (including `node` integration tests) cannot
/// enable it via features, transitive activation, or any Cargo flag.
#[derive(Clone, Debug)]
pub struct ProvedPendingTransition {
    pending: PendingTransition,
    proved: ProvedTransition,
    signature: TransitionSignature,
}

impl ProvedPendingTransition {
    /// Assemble a proved envelope from parts that already match each other.
    ///
    /// Performs only self-consistency checks (signature ↔ prev pubkey,
    /// proved `ProofData` ↔ pending). **Does not** consult live engine state
    /// — that is [`StateEngine::apply_proved_transition`]'s job after any
    /// concurrent scan work.
    ///
    /// **Private:** only the prove path in this module may mint the
    /// capability. External crates cannot construct a hollow envelope.
    fn from_parts(
        mut pending: PendingTransition,
        proved: ProvedTransition,
        signature: TransitionSignature,
    ) -> Result<Self> {
        ensure!(
            signature.pk_i == pending.witness_wip.prev_account_state.current_pubkey,
            "signature pk_i does not equal prev_account_state.current_pubkey"
        );
        ensure!(
            pending.proof_data_hash
                == host::hash_proof_data(&host::serialize_proof_data(&pending.proof_data)),
            "pending proof_data_hash does not match proof_data"
        );
        ensure!(
            proved.proof_data == pending.proof_data,
            "proved ProofData differs from pending ProofData"
        );
        pending.witness_wip.transition_signature = signature.clone();
        Ok(Self {
            pending,
            proved,
            signature,
        })
    }

    /// Test-only hollow mint for unit tests **in this crate**.
    ///
    /// Gated solely on `#[cfg(test)]` of the defining crate. That cfg is
    /// never set when this library is compiled as a dependency — no Cargo
    /// feature, no transitive activation, and no external test target can
    /// open this door. External tests that need a proved envelope must use
    /// a real prove ([`StateEngine::prove_pending_transition`] /
    /// [`StateEngine::prove_pending_transition_detached`]).
    #[cfg(test)]
    pub fn from_parts_for_test(
        pending: PendingTransition,
        proved: ProvedTransition,
        signature: TransitionSignature,
    ) -> Result<Self> {
        Self::from_parts(pending, proved, signature)
    }

    pub fn pending(&self) -> &PendingTransition {
        &self.pending
    }

    pub fn proved(&self) -> &ProvedTransition {
        &self.proved
    }

    pub fn signature(&self) -> &TransitionSignature {
        &self.signature
    }
}

/// Phase-2 output after a successful prove + atomic state apply.
///
/// **Capability token.** Fields are private. The sole production constructors
/// are [`StateEngine::apply_proved_transition`], [`StateEngine::finalise`],
/// and [`StateEngine::finalise_pending_chain_nullifier`] (the latter two go
/// through prove → apply). Possession means a real apply ran against a
/// [`ProvedPendingTransition`]; external crates cannot fabricate a hollow
/// applied transition to drive publish / durable-state helpers.
#[derive(Clone, Debug)]
pub struct AppliedTransition {
    proved: ProvedTransition,
    /// On-chain nullifier `(Pkᵢ, R)` extracted from the transition signature.
    nullifier: ([u8; 32], [u8; 32]),
}

impl AppliedTransition {
    pub fn proved(&self) -> &ProvedTransition {
        &self.proved
    }

    /// On-chain nullifier `(Pkᵢ, R)`.
    pub fn nullifier(&self) -> ([u8; 32], [u8; 32]) {
        self.nullifier
    }
}

/// In-memory state-transition engine.
pub struct StateEngine {
    bridge: ProverBridge,
    network: Network,
    accounts: HashMap<Address, AccountRecord>,
    activation_height: u64,
    nflog: NfLogAccumulator,
    /// Mirror of folded `NfLogEntry` values (for `size_final` NAV / inclusion
    /// / consistency proofs — the accumulator does not expose its log).
    nflog_entries: Vec<NfLogEntry>,
    /// Canonical positions parallel to `nflog_entries`. Retained so finalise
    /// can replay the accumulator transactionally before committing a fold.
    nflog_positions: Vec<ChainPosition>,
    tip_height: u64,
    /// Strictly-increasing fold ordinal at the current tip (as `tx_index`).
    fold_seq: u32,
}

impl StateEngine {
    /// Construct an empty engine for `network` with NfLog activation height.
    pub fn new(network: Network, activation_height: u64) -> Self {
        Self {
            bridge: ProverBridge::new(network),
            network,
            accounts: HashMap::new(),
            activation_height,
            nflog: NfLogAccumulator::new(activation_height),
            nflog_entries: Vec::new(),
            nflog_positions: Vec::new(),
            tip_height: 0,
            fold_seq: 0,
        }
    }

    pub fn network(&self) -> Network {
        self.network
    }

    pub fn tip_height(&self) -> u64 {
        self.tip_height
    }

    /// Advance the Bitcoin tip used for `size_final` (scanner / tests).
    pub fn set_tip_height(&mut self, tip_height: u64) {
        self.tip_height = tip_height;
        self.fold_seq = 0;
    }

    pub fn account(&self, owner: &Address) -> Option<&AccountRecord> {
        self.accounts.get(owner)
    }

    pub fn nflog(&self) -> &NfLogAccumulator {
        &self.nflog
    }

    pub fn activation_height(&self) -> u64 {
        self.activation_height
    }

    pub fn fold_seq(&self) -> u32 {
        self.fold_seq
    }

    pub fn bridge(&self) -> &ProverBridge {
        &self.bridge
    }

    /// NfLog mirror in absolute position order: `(ChainPosition, entry)`.
    ///
    /// The sequence is the normative reconstruction input: reloading by
    /// folding these pairs in order yields a byte-identical NfLog root.
    pub fn nflog_mirror(&self) -> Vec<(ChainPosition, NfLogEntry)> {
        self.nflog_positions
            .iter()
            .copied()
            .zip(self.nflog_entries.iter().copied())
            .collect()
    }

    /// Iterate accounts currently held by the engine.
    pub fn accounts(&self) -> impl Iterator<Item = (&Address, &AccountRecord)> {
        self.accounts.iter()
    }

    /// Rebuild an engine from a complete persisted snapshot.
    ///
    /// Fails loud if:
    /// - NfLog positions are not a dense `0..n` sequence when folded,
    /// - any fold is duplicate / pre-activation,
    /// - account coinhist roots disagree with `AccountState`,
    /// - the rebuilt NfLog root disagrees with the source entries.
    ///
    /// Does **not** fall back to an empty engine on partial data.
    pub fn from_persisted(
        network: Network,
        activation_height: u64,
        tip_height: u64,
        fold_seq: u32,
        nflog: Vec<(ChainPosition, NfLogEntry)>,
        accounts: Vec<(Address, AccountRecord)>,
    ) -> Result<Self> {
        let mut engine = Self::new(network, activation_height);
        // Do not call `set_tip_height` here: it zeroes `fold_seq`.
        engine.tip_height = tip_height;
        engine.fold_seq = fold_seq;

        for (expected_pos, (chain_pos, entry)) in nflog.iter().copied().enumerate() {
            match engine
                .nflog
                .fold(chain_pos, entry.pk, entry.r)
                .context("from_persisted: NfLog fold failed")?
            {
                FoldOutcome::Appended(pos) => ensure!(
                    pos == expected_pos as u64,
                    "from_persisted: NfLog position gap or reorder at expected {expected_pos}, got {pos}"
                ),
                FoldOutcome::DuplicateIgnored => {
                    bail!("from_persisted: NfLog snapshot contains a duplicate Pk at position {expected_pos}")
                }
                FoldOutcome::BelowActivationHeight => {
                    bail!(
                        "from_persisted: NfLog snapshot entry at position {expected_pos} \
                         is below activation_height {activation_height}"
                    )
                }
            }
            engine.nflog_entries.push(entry);
            engine.nflog_positions.push(chain_pos);
        }

        ensure!(
            engine.nflog.nav().size == engine.nflog_entries.len() as u64,
            "from_persisted: NfLog size drifted from entry count"
        );
        ensure!(
            engine.nflog.nav().mth == host::nflog_mth(&engine.nflog_entries),
            "from_persisted: NfLog MTH disagrees with full-sequence recomputation"
        );

        for (owner, record) in accounts {
            engine.insert_account(owner, record)?;
        }
        Ok(engine)
    }

    /// Append a nullifier that was **observed by the scan path**.
    ///
    /// Requires a [`ScannedNullifier`] capability token — a bare
    /// [`ChainPosition`] is not accepted. Possession of the token is proof
    /// the position came from a scanner-emitted survivor (or an explicit
    /// test mint of that survivor type). Updates the live accumulator and
    /// its entry/position mirrors together. Fails loud on out-of-order
    /// positions, pre-activation folds, and first-occurrence duplicates
    /// (does not silently ignore duplicates — the scanner is expected to
    /// classify those before calling this).
    pub fn append_nullifier(&mut self, scanned: ScannedNullifier) -> Result<u64> {
        let chain_pos = scanned.chain_pos;
        let pk = scanned.pk;
        let r = scanned.r;
        let expected_pos = self.nflog_entries.len() as u64;
        match self
            .nflog
            .fold(chain_pos, pk, r)
            .context("append_nullifier: fold failed")?
        {
            FoldOutcome::Appended(pos) => {
                ensure!(
                    pos == expected_pos,
                    "append_nullifier: position mismatch expected {expected_pos}, got {pos}"
                );
                self.nflog_entries.push(NfLogEntry { pk, r });
                self.nflog_positions.push(chain_pos);
                Ok(pos)
            }
            FoldOutcome::DuplicateIgnored => {
                bail!("append_nullifier: Pk already present (first-occurrence would ignore)")
            }
            FoldOutcome::BelowActivationHeight => {
                bail!(
                    "append_nullifier: height {} is below activation_height {}",
                    chain_pos.height,
                    self.activation_height
                )
            }
        }
    }

    /// Insert a pre-built account (e.g. funded fixture for tests / recovery).
    ///
    /// Fails if `owner` is already present.
    pub fn insert_account(&mut self, owner: Address, record: AccountRecord) -> Result<()> {
        ensure!(
            record.state.owner == owner,
            "AccountRecord.owner does not match insert key"
        );
        ensure!(
            !self.accounts.contains_key(&owner),
            "account already present in the engine"
        );
        ensure!(
            record.coinhist.root() == record.state.coin_history_root,
            "coinhist root does not match AccountState.coin_history_root"
        );
        self.accounts.insert(owner, record);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // §2.3.1 Mint
    // -----------------------------------------------------------------------

    /// Phase 1 of token-standard-1 mint / issuance (§2.3.1): empty inputs,
    /// one self-output, `asset_issuance`, `nav = size_final`, six
    /// `ProofData` fields.
    ///
    /// Token-standard 2 is rejected until the request can name its mandatory
    /// explicit non-owner emission recipient. Producing the current self
    /// output would violate the frozen v2 constraints (no self-credit and no
    /// same-transition CoinHist admission), so this path fails loudly rather
    /// than constructing an unprovable witness.
    pub fn begin_mint(&self, req: MintRequest) -> Result<PendingTransition> {
        ensure!(
            matches!(req.issuance_version, 1 | 2),
            "unsupported issuance_version {}",
            req.issuance_version
        );
        if req.issuance_version == 2 {
            bail!(
                "token-standard-2 mint requires an explicit non-owner emission recipient; \
                 P1-E.2 MintRequest does not yet carry one"
            );
        }
        ensure!(req.amount > 0, "mint amount must be non-zero");
        ensure!(
            req.cap_total == 0,
            "token-standard-1 mint requires cap_total == 0"
        );
        ensure!(
            req.terms_salt == [0u8; 32],
            "token-standard-1 mint requires all-zero terms_salt"
        );

        let nk_commit = host::nk_commit(&req.nk);
        // For genesis, owner = H(Pk₀ ‖ nk_commit). For a follow-up mint the
        // address is still bound to Pk₀, not the rotated current_pubkey — the
        // request carries the durable owner identity.
        if let Some(existing) = self.accounts.get(&req.owner) {
            ensure!(existing.state.owner == req.owner, "account owner mismatch");
            ensure!(
                existing.nk == req.nk,
                "nk does not match the registered account"
            );
            match existing.op_secret {
                None => {
                    bail!(
                        "mint: op_secret missing for account — refusing (no silent default)"
                    );
                }
                Some(stored) => {
                    ensure!(
                        req.op_secret == stored,
                        "op_secret does not match the registered account"
                    );
                }
            }
            ensure!(
                existing.state.current_pubkey == req.current_pubkey,
                "current_pubkey does not match the registered account"
            );
            ensure!(
                host::nk_commit(&req.nk) == existing.state.nk_commit,
                "nk does not open the registered nk_commit"
            );
        } else {
            let expected_owner = Address(host::address(&req.current_pubkey, nk_commit));
            ensure!(
                req.owner == expected_owner,
                "owner must equal H(current_pubkey ‖ nk_commit) for a genesis mint"
            );
        }

        let name_hash = host::name_hash(&req.name).context("name_hash")?;
        let creator_pubkey = match self.accounts.get(&req.owner) {
            Some(rec) => rec.genesis_pubkey,
            None => req.current_pubkey,
        };
        let asset_id = host::asset_id_v1(
            host::GENESIS_TAG,
            &creator_pubkey,
            &name_hash,
            req.decimals,
            1,
        );
        let terms_hash = host::terms_hash_v1(asset_id, 1);
        let issuance = AssetIssuance {
            asset_id,
            creator_pubkey,
            issuance_version: req.issuance_version,
            name_hash,
            decimals: req.decimals,
            amount: req.amount,
            terms_hash,
            cap_total: req.cap_total,
            terms_salt: req.terms_salt,
        };

        let (
            mode,
            prev_account_state,
            prev_proof,
            prev_nav_opening,
            predecessor_nullifier,
            nav_consistency,
            mut hist_leaves,
        ) = self.account_transition_context(&req.owner, &req.nk, req.current_pubkey)?;

        let prev_ash =
            host::account_state_hash(&prev_account_state).context("hash prev account state")?;
        let output_template = CoinTemplate {
            recipient: req.owner,
            amount: req.amount,
            asset_id,
        };
        let output_coin = Coin {
            identifier: host::coin_identifier(prev_ash, &req.owner.0, asset_id, req.amount, 0),
            recipient: req.owner,
            amount: req.amount,
            asset_id,
        };

        // History: admit self-output 0→1 (no inputs / receives).
        let output_id = host::digest_to_bytes(&output_coin.identifier);
        let output_history = {
            let hist = rebuild_coinhist(&hist_leaves)?;
            hist.non_inclusion(output_id)
                .context("self-output coin_id already present in coinhist")?
        };
        hist_leaves.insert(output_id, host::CoinHistState::Admitted);
        let new_hist = rebuild_coinhist(&hist_leaves)?;
        let new_root = new_hist.root();

        let mut new_balances = prev_account_state.balances.clone();
        credit_balance(&mut new_balances, asset_id, req.amount)?;
        let entry_send_counter = prev_account_state.send_counter;
        let new_send = entry_send_counter
            .checked_add(1)
            .context("send_counter overflow")?;
        let new_account_state = AccountState::new(
            req.owner,
            prev_account_state.nk_commit,
            new_balances,
            req.next_pubkey,
            new_send,
            new_root,
        )
        .context("construct new AccountState after mint")?;

        let nav_rand = host::derive_nav_rand(req.op_secret.as_bytes(), entry_send_counter);
        let nav = self.size_final_nav()?;
        let nav_opening = NavOpening {
            nav,
            nav_rand,
        };
        let proof_data = compute_proof_data(
            &new_account_state,
            &[output_coin.clone()],
            &[],
            &req.nk,
            nav,
            &nav_rand,
            &req.next_pubkey,
            &req.npk_rand,
        )?;
        let proof_data_hash = host::hash_proof_data(&host::serialize_proof_data(&proof_data));

        let witness_wip = TransitionWitness {
            mode,
            prev_account_state,
            new_account_state,
            input_coins: Vec::new(),
            input_auth: Vec::new(),
            output_templates: vec![output_template],
            output_coins: vec![output_coin],
            output_history_proofs: vec![Some(output_history)],
            received_coins: Vec::new(),
            received_auth: Vec::new(),
            asset_issuance: Some(issuance),
            nk: req.nk,
            nav,
            nav_rand,
            prev_nav_opening,
            nav_consistency,
            next_pubkey: req.next_pubkey,
            npk_rand: req.npk_rand,
            transition_signature: placeholder_signature(req.current_pubkey),
            prev_proof,
            predecessor_nullifier,
        };

        Ok(PendingTransition {
            witness_wip,
            proof_data,
            proof_data_hash,
            mode,
            owner: req.owner,
            nav_opening,
            op_secret: req.op_secret,
        })
    }

    // -----------------------------------------------------------------------
    // §2.3.2 Send
    // -----------------------------------------------------------------------

    /// Phase 1 of send (§2.3.2): spend inputs, derive nullifiers, add
    /// per-asset change so `In(a)+Mint(a) == Out(a)`, `nav = size_final`.
    pub fn begin_send(&self, req: SendRequest) -> Result<PendingTransition> {
        let record = self
            .accounts
            .get(&req.owner)
            .context("send: account not found")?;
        ensure!(record.state.owner == req.owner, "account owner mismatch");
        let op_secret = record.op_secret.context(
            "send: op_secret missing for account — refusing (no silent default)",
        )?;
        ensure!(
            !req.input_coin_ids.is_empty(),
            "send requires at least one input coin"
        );
        ensure!(
            req.input_coin_ids.len() <= MAX_TX_INPUTS,
            "too many input coins: {} > {}",
            req.input_coin_ids.len(),
            MAX_TX_INPUTS
        );
        ensure!(
            req.output_templates.len() <= MAX_TX_OUTPUTS,
            "too many output templates: {} > {}",
            req.output_templates.len(),
            MAX_TX_OUTPUTS
        );

        // Resolve inputs and enforce conservation *before* any proving material
        // or predecessor wiring, so over-spend fails fast and loud.
        let mut input_coins = Vec::with_capacity(req.input_coin_ids.len());
        let mut in_by_asset: BTreeMap<[u8; 32], u128> = BTreeMap::new();
        let mut seen_inputs = BTreeSet::new();
        for coin_id in &req.input_coin_ids {
            let id_bytes = host::digest_to_bytes(coin_id);
            ensure!(seen_inputs.insert(id_bytes), "duplicate input coin_id");
            let tracked = record
                .spendable
                .get(&id_bytes)
                .context("input coin is not spendable on this account")?;
            ensure!(
                tracked.coin.identifier == *coin_id,
                "tracked coin identifier mismatch"
            );
            ensure!(
                tracked.coin.recipient == req.owner,
                "input coin recipient is not the spending account"
            );
            let asset_key = host::digest_to_bytes(&tracked.coin.asset_id);
            let entry = in_by_asset.entry(asset_key).or_insert(0);
            *entry = entry
                .checked_add(tracked.coin.amount)
                .context("In(a) amount overflow")?;
            input_coins.push(tracked.clone());
        }

        let mut out_by_asset: BTreeMap<[u8; 32], u128> = BTreeMap::new();
        for template in &req.output_templates {
            ensure!(
                template.amount > 0,
                "output template amount must be non-zero"
            );
            let asset_key = host::digest_to_bytes(&template.asset_id);
            let entry = out_by_asset.entry(asset_key).or_insert(0);
            *entry = entry
                .checked_add(template.amount)
                .context("Out(a) amount overflow")?;
        }

        // Per-asset change: amount = In(a) − Out(a) (no mint on send).
        let mut change_templates: Vec<CoinTemplate> = Vec::new();
        let all_assets: BTreeSet<[u8; 32]> = in_by_asset
            .keys()
            .chain(out_by_asset.keys())
            .copied()
            .collect();
        for asset_key in all_assets {
            let inn = match in_by_asset.get(&asset_key) {
                Some(&v) => v,
                None => 0,
            };
            let out = match out_by_asset.get(&asset_key) {
                Some(&v) => v,
                None => 0,
            };
            ensure!(
                inn >= out,
                "over-spend: outputs exceed inputs for an asset (In={inn}, Out={out})"
            );
            let change = inn - out;
            if change > 0 {
                let asset_id = host::digest_from_bytes(&asset_key)
                    .context("reconstruct asset_id from balance key")?;
                change_templates.push(CoinTemplate {
                    recipient: req.owner,
                    amount: change,
                    asset_id,
                });
            }
        }
        // Canonical order: caller recipient templates, then change by
        // ascending asset_id (change_templates already sorted via BTreeSet).
        let mut all_templates = req.output_templates.clone();
        all_templates.extend(change_templates);
        ensure!(
            all_templates.len() <= MAX_TX_OUTPUTS,
            "outputs including change exceed MAX_TX_OUTPUTS: {} > {}",
            all_templates.len(),
            MAX_TX_OUTPUTS
        );

        let (
            mode,
            prev_account_state,
            prev_proof,
            prev_nav_opening,
            predecessor_nullifier,
            nav_consistency,
            mut hist_leaves,
        ) = self.account_transition_context(&req.owner, &record.nk, record.state.current_pubkey)?;
        ensure!(
            matches!(mode, TransitionMode::AccountUpdateProof),
            "send requires a prior account transition (AccountUpdateProof)"
        );

        // Clause 8 consumes active history paths sequentially. Generate each
        // 1→2 opening against the current intermediate root, then apply the
        // spend immediately before constructing the next input's path.
        let mut hist_for_proofs = rebuild_coinhist(&hist_leaves)?;
        let mut input_auth = Vec::with_capacity(input_coins.len());
        let mut resolved_inputs = Vec::with_capacity(input_coins.len());
        for tracked in &input_coins {
            let id_bytes = host::digest_to_bytes(&tracked.coin.identifier);
            let history_proof = hist_for_proofs.prove(id_bytes);
            ensure!(
                history_proof.state == host::CoinHistState::Admitted,
                "input coin is not Admitted in coinhist"
            );
            ensure!(
                history_proof.verify(&id_bytes, hist_for_proofs.root()),
                "input history proof does not open the current sequential coin-history root"
            );
            input_auth.push(InputAuthorization {
                creating_prev_ash: tracked.creating_prev_ash,
                coin_index: tracked.coin_index,
                history_proof,
            });
            resolved_inputs.push(tracked.coin.clone());
            hist_for_proofs
                .spend(id_bytes)
                .context("apply sequential input spend to temporary coinhist")?;
            hist_leaves.insert(id_bytes, host::CoinHistState::Spent);
        }
        let input_coins = resolved_inputs;

        let prev_ash =
            host::account_state_hash(&prev_account_state).context("hash prev account state")?;
        let mut output_coins = Vec::with_capacity(all_templates.len());
        let mut output_history_proofs = Vec::with_capacity(all_templates.len());

        // Continue from the post-spend intermediate tree for self-output
        // admissions, matching the circuit's input → output slot order.
        for (index, template) in all_templates.iter().enumerate() {
            let coin = Coin {
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
            let is_self = template.recipient == req.owner;
            if is_self {
                let id = host::digest_to_bytes(&coin.identifier);
                let proof = hist_for_proofs
                    .non_inclusion(id)
                    .context("self-output coin_id already present")?;
                ensure!(
                    proof.verify(&id, hist_for_proofs.root()),
                    "self-output history proof does not open the current sequential root"
                );
                output_history_proofs.push(Some(proof));
                hist_for_proofs
                    .admit(id)
                    .context("apply sequential self-output admission to temporary coinhist")?;
                hist_leaves.insert(id, host::CoinHistState::Admitted);
            } else {
                output_history_proofs.push(None);
            }
            output_coins.push(coin);
        }

        let new_hist = rebuild_coinhist(&hist_leaves)?;
        ensure!(
            hist_for_proofs.root() == new_hist.root(),
            "temporary sequential coinhist diverges from rebuilt final tree"
        );
        let new_root = new_hist.root();

        // balances: prev − In + Self (change / self-retained).
        let mut new_balances = prev_account_state.balances.clone();
        for coin in &input_coins {
            debit_balance(&mut new_balances, coin.asset_id, coin.amount)?;
        }
        for (template, coin) in all_templates.iter().zip(&output_coins) {
            if template.recipient == req.owner {
                credit_balance(&mut new_balances, coin.asset_id, coin.amount)?;
            }
        }
        let entry_send_counter = prev_account_state.send_counter;
        let new_send = entry_send_counter
            .checked_add(1)
            .context("send_counter overflow")?;
        let new_account_state = AccountState::new(
            req.owner,
            prev_account_state.nk_commit,
            new_balances,
            req.next_pubkey,
            new_send,
            new_root,
        )
        .context("construct new AccountState after send")?;

        let nav_rand = host::derive_nav_rand(op_secret.as_bytes(), entry_send_counter);
        let nav = self.size_final_nav()?;
        let nav_opening = NavOpening {
            nav,
            nav_rand,
        };
        let proof_data = compute_proof_data(
            &new_account_state,
            &output_coins,
            &input_coins,
            &record.nk,
            nav,
            &nav_rand,
            &req.next_pubkey,
            &req.npk_rand,
        )?;
        let proof_data_hash = host::hash_proof_data(&host::serialize_proof_data(&proof_data));

        let witness_wip = TransitionWitness {
            mode,
            prev_account_state,
            new_account_state,
            input_coins,
            input_auth,
            output_templates: all_templates,
            output_coins,
            output_history_proofs,
            received_coins: Vec::new(),
            received_auth: Vec::new(),
            asset_issuance: None,
            nk: record.nk,
            nav,
            nav_rand,
            prev_nav_opening,
            nav_consistency,
            next_pubkey: req.next_pubkey,
            npk_rand: req.npk_rand,
            transition_signature: placeholder_signature(record.state.current_pubkey),
            prev_proof,
            predecessor_nullifier,
        };

        Ok(PendingTransition {
            witness_wip,
            proof_data,
            proof_data_hash,
            mode,
            owner: req.owner,
            nav_opening,
            op_secret,
        })
    }

    // -----------------------------------------------------------------------
    // §2.3.3 Receive
    // -----------------------------------------------------------------------

    /// Phase 1 of receive (§2.3.3): admit already-verified received coins,
    /// clause-10 auth from the request, `nav = size_final`.
    ///
    /// See module docs for the pre-verified `CoinProof` assumption (P1-G).
    pub fn begin_receive(&self, req: ReceiveRequest) -> Result<PendingTransition> {
        ensure!(
            req.received_coins.len() == req.received_auth.len(),
            "received_coins / received_auth length mismatch"
        );
        ensure!(
            !req.received_coins.is_empty(),
            "receive requires at least one received coin"
        );
        ensure!(
            req.received_coins.len() <= MAX_RX_COINS,
            "too many received coins: {} > {}",
            req.received_coins.len(),
            MAX_RX_COINS
        );

        if let Some(record) = self.accounts.get(&req.owner) {
            ensure!(
                req.nk == record.nk,
                "receive: nk does not match the registered account"
            );
            match record.op_secret {
                None => {
                    bail!(
                        "receive: op_secret missing for account — refusing (no silent default)"
                    );
                }
                Some(stored) => {
                    ensure!(
                        req.op_secret == stored,
                        "receive: op_secret does not match the registered account"
                    );
                }
            }
            ensure!(
                req.current_pubkey == record.state.current_pubkey,
                "receive: current_pubkey does not match the registered account"
            );
        } else {
            let expected_owner =
                Address(host::address(&req.current_pubkey, host::nk_commit(&req.nk)));
            ensure!(
                req.owner == expected_owner,
                "receive: owner must equal H(current_pubkey ‖ nk_commit) for an InitialProof"
            );
        }

        let (
            mode,
            prev_account_state,
            prev_proof,
            prev_nav_opening,
            predecessor_nullifier,
            nav_consistency,
            mut hist_leaves,
        ) = self.account_transition_context(&req.owner, &req.nk, req.current_pubkey)?;

        for coin in &req.received_coins {
            ensure!(
                coin.recipient == req.owner,
                "received coin recipient is not the receiving account"
            );
            ensure!(coin.amount > 0, "received coin amount must be non-zero");
        }

        // Clause 8 consumes active receipt paths sequentially. Generate each
        // 0→1 opening against the current intermediate root and admit it
        // before constructing the next receipt's path.
        let mut hist_for_proofs = rebuild_coinhist(&hist_leaves)?;
        let mut auth_with_history = Vec::with_capacity(req.received_auth.len());
        for (coin, mut auth) in req.received_coins.iter().zip(req.received_auth.into_iter()) {
            let id = host::digest_to_bytes(&coin.identifier);
            let proof = hist_for_proofs
                .non_inclusion(id)
                .context("received coin_id already present in coinhist")?;
            ensure!(
                proof.verify(&id, hist_for_proofs.root()),
                "received history proof does not open the current sequential coin-history root"
            );
            auth.history_proof = proof;
            auth_with_history.push(auth);
            hist_for_proofs
                .admit(id)
                .context("apply sequential receipt admission to temporary coinhist")?;
            hist_leaves.insert(id, host::CoinHistState::Admitted);
        }

        let new_hist = rebuild_coinhist(&hist_leaves)?;
        ensure!(
            hist_for_proofs.root() == new_hist.root(),
            "temporary sequential receive coinhist diverges from rebuilt final tree"
        );
        let new_root = new_hist.root();
        let mut new_balances = prev_account_state.balances.clone();
        for coin in &req.received_coins {
            credit_balance(&mut new_balances, coin.asset_id, coin.amount)?;
        }
        let entry_send_counter = prev_account_state.send_counter;
        let new_send = entry_send_counter
            .checked_add(1)
            .context("send_counter overflow")?;
        let new_account_state = AccountState::new(
            req.owner,
            prev_account_state.nk_commit,
            new_balances,
            req.next_pubkey,
            new_send,
            new_root,
        )
        .context("construct new AccountState after receive")?;

        let nav_rand = host::derive_nav_rand(req.op_secret.as_bytes(), entry_send_counter);
        let nav = self.size_final_nav()?;
        let nav_opening = NavOpening {
            nav,
            nav_rand,
        };
        let proof_data = compute_proof_data(
            &new_account_state,
            &[],
            &[],
            &req.nk,
            nav,
            &nav_rand,
            &req.next_pubkey,
            &req.npk_rand,
        )?;
        let proof_data_hash = host::hash_proof_data(&host::serialize_proof_data(&proof_data));

        let witness_wip = TransitionWitness {
            mode,
            prev_account_state,
            new_account_state,
            input_coins: Vec::new(),
            input_auth: Vec::new(),
            output_templates: Vec::new(),
            output_coins: Vec::new(),
            output_history_proofs: Vec::new(),
            received_coins: req.received_coins,
            received_auth: auth_with_history,
            asset_issuance: None,
            nk: req.nk,
            nav,
            nav_rand,
            prev_nav_opening,
            nav_consistency,
            next_pubkey: req.next_pubkey,
            npk_rand: req.npk_rand,
            transition_signature: placeholder_signature(req.current_pubkey),
            prev_proof,
            predecessor_nullifier,
        };

        Ok(PendingTransition {
            witness_wip,
            proof_data,
            proof_data_hash,
            mode,
            owner: req.owner,
            nav_opening,
            op_secret: req.op_secret,
        })
    }

    // -----------------------------------------------------------------------
    // Phase 2: finalise
    // -----------------------------------------------------------------------

    /// Phase 2: install the wallet signature, prove via the bridge, then
    /// **atomically** apply the new account state / CoinHist.
    /// On proving failure the engine state is left unchanged.
    ///
    /// ## Engine invariant — no synthetic NfLog positions
    ///
    /// The canonical NfLog is a pure function of Bitcoin (§3.6). This method
    /// **never** folds the transition's own nullifier into the accumulator
    /// and never invents a local `(tip_height, fold_seq)` position. The
    /// account records `last_nullifier = Some` / `last_nullifier_pos = None`
    /// until the scanner folds the confirmed on-chain survivor at its real
    /// `(height, tx_index, vin_index, member_index)`.
    ///
    /// Applies equally to mint, send, and receive: a public finalise path
    /// that could invent a position would also fool the absent-lookup guard
    /// and permanently desync after a later canonical scan-fold.
    pub fn finalise(
        &mut self,
        pending: PendingTransition,
        signature: TransitionSignature,
    ) -> Result<AppliedTransition> {
        let proved = self.prove_pending_transition(pending, signature)?;
        self.apply_proved_transition(proved)
    }

    /// Prove + apply account/CoinHist **without** folding the own nullifier
    /// into the canonical NfLog.
    ///
    /// Identical to [`Self::finalise`]: retained as a named alias so receive
    /// call sites document that the chain (via the scanner) places the
    /// nullifier. There is no alternate "synthetic local" outcome.
    pub fn finalise_pending_chain_nullifier(
        &mut self,
        pending: PendingTransition,
        signature: TransitionSignature,
    ) -> Result<AppliedTransition> {
        let proved = self.prove_pending_transition(pending, signature)?;
        self.apply_proved_transition(proved)
    }

    /// Phase 2a: prove only. **Does not mutate** the engine.
    ///
    /// Validates the envelope against **this** engine, then proves via the
    /// bridge. Callers that must not hold any engine lock across proving
    /// should use [`Self::prove_pending_transition_detached`] instead and
    /// re-validate on [`Self::apply_proved_transition`].
    pub fn prove_pending_transition(
        &self,
        pending: PendingTransition,
        signature: TransitionSignature,
    ) -> Result<ProvedPendingTransition> {
        self.validate_pending_envelope(&pending)?;
        Self::prove_pending_transition_detached(&self.bridge, pending, signature)
    }

    /// Prove a pending transition **without reading engine state**.
    ///
    /// The pending witness already carries everything the prover needs.
    /// Live-state re-validation (account, tip/`size_final`, receiver NAV
    /// canonicity, creating anchors, own-Pk absence) happens only in
    /// [`Self::apply_proved_transition`] after the caller re-acquires the
    /// engine mutex. This is the production receive path: prove holds
    /// neither `write_gate` nor the live-engine mutex.
    pub fn prove_pending_transition_detached(
        bridge: &ProverBridge,
        mut pending: PendingTransition,
        signature: TransitionSignature,
    ) -> Result<ProvedPendingTransition> {
        ensure!(
            signature.pk_i == pending.witness_wip.prev_account_state.current_pubkey,
            "signature pk_i does not equal prev_account_state.current_pubkey"
        );
        ensure!(
            pending.proof_data_hash
                == host::hash_proof_data(&host::serialize_proof_data(&pending.proof_data)),
            "pending proof_data_hash does not match proof_data"
        );

        pending.witness_wip.transition_signature = signature.clone();
        let proved = bridge
            .prove_transition(&pending.witness_wip)
            .context("prove_pending_transition: prove_transition failed (state unchanged)")?;
        ensure!(
            proved.proof_data == pending.proof_data,
            "proved ProofData differs from pending ProofData"
        );
        ProvedPendingTransition::from_parts(pending, proved, signature)
    }

    /// Phase 2b: apply a previously proved pending transition.
    ///
    /// Mutates account/CoinHist only — never the canonical NfLog.
    /// Re-validates **every live dependency** the prove-time decision read
    /// so a concurrent scanner fold during unlocked prove fails loud
    /// rather than committing against a moved tip / size_final / anchor.
    pub fn apply_proved_transition(
        &mut self,
        proved_pending: ProvedPendingTransition,
    ) -> Result<AppliedTransition> {
        let ProvedPendingTransition {
            pending,
            proved,
            signature,
        } = proved_pending;
        // Full live re-validation after any concurrent scan work during prove.
        self.revalidate_pending_against_live(&pending)?;
        ensure!(
            signature.pk_i == pending.witness_wip.prev_account_state.current_pubkey,
            "apply: signature pk_i does not equal prev_account_state.current_pubkey"
        );
        ensure!(
            proved.proof_data == pending.proof_data,
            "apply: proved ProofData differs from pending ProofData"
        );
        ensure!(
            pending.witness_wip.transition_signature.pk_i == signature.pk_i
                && pending.witness_wip.transition_signature.signature == signature.signature
                && pending.witness_wip.transition_signature.r_prime == signature.r_prime,
            "apply: pending witness signature does not match proved envelope"
        );

        let witness = &pending.witness_wip;
        let pk_i = signature.pk_i;
        let r = signature.signature_r();
        let nullifier_opening = NullifierOpening {
            public_key: pk_i,
            signature_r: r,
            r_prime: signature.r_prime,
        };

        // Apply atomically: if anything below fails after prove, we still
        // return Err — callers must not observe partial account/Nflog state.
        // Build the post-state, then swap in one go.
        let prev_ash = host::account_state_hash(&witness.prev_account_state)
            .context("hash prev account state for apply")?;

        let mut next_spendable: BTreeMap<[u8; 32], TrackedCoin>;
        let mut next_spent: BTreeSet<[u8; 32]>;
        let next_hist: CoinHistTree;
        let genesis_pubkey: [u8; 32];
        let nk = witness.nk;

        if let Some(existing) = self.accounts.get(&pending.owner) {
            next_spendable = existing.spendable.clone();
            next_spent = existing.spent_ids.clone();
            genesis_pubkey = existing.genesis_pubkey;
            // Start from a rebuilt tree so we re-validate the clause-8 path.
            let mut leaves = leaves_from_sets(&next_spendable, &next_spent);
            for coin in &witness.input_coins {
                let id = host::digest_to_bytes(&coin.identifier);
                ensure!(
                    next_spendable.remove(&id).is_some(),
                    "apply: spent input missing from spendable set"
                );
                ensure!(
                    leaves.get(&id) == Some(&host::CoinHistState::Admitted),
                    "apply: input not Admitted"
                );
                leaves.insert(id, host::CoinHistState::Spent);
                next_spent.insert(id);
            }
            for (index, (template, coin)) in witness
                .output_templates
                .iter()
                .zip(&witness.output_coins)
                .enumerate()
            {
                if template.recipient == pending.owner {
                    let id = host::digest_to_bytes(&coin.identifier);
                    ensure!(
                        !leaves.contains_key(&id),
                        "apply: self-output already in coinhist"
                    );
                    leaves.insert(id, host::CoinHistState::Admitted);
                    next_spendable.insert(
                        id,
                        TrackedCoin {
                            coin: coin.clone(),
                            creating_prev_ash: prev_ash,
                            coin_index: index as u32,
                        },
                    );
                }
            }
            for (index, coin) in witness.received_coins.iter().enumerate() {
                let id = host::digest_to_bytes(&coin.identifier);
                ensure!(
                    !leaves.contains_key(&id),
                    "apply: received coin already in coinhist"
                );
                leaves.insert(id, host::CoinHistState::Admitted);
                // Received coins use creating_prev_ash from auth when present.
                let creating_prev_ash = witness
                    .received_auth
                    .get(index)
                    .map(|a| a.creating_prev_ash)
                    .context("apply: missing received_auth for received coin")?;
                let coin_index = witness
                    .received_auth
                    .get(index)
                    .map(|a| a.output_inclusion.leaf_index)
                    .context("apply: missing output_inclusion for received coin")?;
                next_spendable.insert(
                    id,
                    TrackedCoin {
                        coin: coin.clone(),
                        creating_prev_ash,
                        coin_index,
                    },
                );
            }
            next_hist = rebuild_coinhist(&leaves)?;
        } else {
            // First transition: genesis mint or InitialProof receive.
            ensure!(
                matches!(pending.mode, TransitionMode::InitialProof),
                "missing account requires InitialProof mode"
            );
            ensure!(
                witness.input_coins.is_empty(),
                "InitialProof transition cannot spend inputs"
            );
            genesis_pubkey = witness.prev_account_state.current_pubkey;
            next_spendable = BTreeMap::new();
            next_spent = BTreeSet::new();
            let mut leaves = BTreeMap::new();
            for (index, (template, coin)) in witness
                .output_templates
                .iter()
                .zip(&witness.output_coins)
                .enumerate()
            {
                if template.recipient == pending.owner {
                    let id = host::digest_to_bytes(&coin.identifier);
                    leaves.insert(id, host::CoinHistState::Admitted);
                    next_spendable.insert(
                        id,
                        TrackedCoin {
                            coin: coin.clone(),
                            creating_prev_ash: prev_ash,
                            coin_index: index as u32,
                        },
                    );
                }
            }
            for (index, coin) in witness.received_coins.iter().enumerate() {
                let id = host::digest_to_bytes(&coin.identifier);
                ensure!(
                    !leaves.contains_key(&id),
                    "apply: received coin already in initial coinhist"
                );
                leaves.insert(id, host::CoinHistState::Admitted);
                let auth = witness
                    .received_auth
                    .get(index)
                    .context("apply: missing received_auth for initial received coin")?;
                next_spendable.insert(
                    id,
                    TrackedCoin {
                        coin: coin.clone(),
                        creating_prev_ash: auth.creating_prev_ash,
                        coin_index: auth.output_inclusion.leaf_index,
                    },
                );
            }
            next_hist = rebuild_coinhist(&leaves)?;
        }

        ensure!(
            next_hist.root() == witness.new_account_state.coin_history_root,
            "apply: coinhist root diverges from new_account_state"
        );

        // Engine invariant: never invent a local NfLog position. Refuse if
        // the own Pk is already present (double-spend / republish). The
        // scanner alone may fold this nullifier at a real chain position.
        ensure!(
            matches!(self.nflog.lookup(pk_i), LookupResult::Absent),
            "apply: deferred nullifier Pk already present on canonical NfLog \
             (double-spend / republish)"
        );

        // All fallible checks are complete. Commit the account record only —
        // the canonical NfLog is untouched.
        //
        // `op_secret` is engine-local operational material: never invent a
        // value here. Carry the secret resolved at begin_* (request or prior
        // record); a fresh node rebuilds openings from the restored bundle.
        let record = AccountRecord {
            state: witness.new_account_state.clone(),
            coinhist: next_hist,
            nk,
            op_secret: Some(pending.op_secret),
            genesis_pubkey,
            spendable: next_spendable,
            spent_ids: next_spent,
            last_proof: Some(proved.proof.clone()),
            last_nav_opening: Some(pending.nav_opening),
            last_nullifier: Some(nullifier_opening),
            last_nullifier_pos: None,
        };
        self.accounts.insert(pending.owner, record);

        Ok(AppliedTransition {
            proved,
            nullifier: (pk_i, r),
        })
    }

    // -----------------------------------------------------------------------
    // Host acceptance (D.5 Caveat A)
    // -----------------------------------------------------------------------

    /// Node-side acceptance for an incoming proved transition:
    /// 1. bridge `verify_transition` (Plonky2 verify + cyclic-tail pin);
    /// 2. open `proof_data.nav_commitment` with `nav_opening`;
    /// 3. require the opened `(size, mth)` is **canonical** on this engine's
    ///    NfLog and `size ≤ size_final(tip_height)`.
    ///
    /// The Bitcoin first-occurrence anchor check for the transition's own
    /// `(Pkᵢ, R)` (or a creating nullifier) requires the scanner and is
    /// deferred to P1-G.
    pub fn verify_incoming_transition(
        &self,
        proved: &ProvedTransition,
        nav_opening: &NavOpening,
    ) -> Result<()> {
        let extracted_proof_data = self
            .bridge
            .verify_proved_transition_wrapper(proved)
            .context("incoming transition: wrapper/public-input mismatch")?;
        self.bridge
            .verify_transition(&proved.proof)
            .context("incoming transition: bridge verify failed")?;

        let expected_commit = host::nav_commitment(nav_opening.nav.root(), &nav_opening.nav_rand);
        ensure!(
            expected_commit == extracted_proof_data.nav_commitment,
            "incoming transition: nav_opening does not open proof_data.nav_commitment"
        );

        let size = nav_opening.nav.size;
        let mth = nav_opening.nav.mth;
        ensure!(
            self.nflog.is_canonical(size, mth),
            "incoming transition: nav (size, mth) is not canonical on this NfLog"
        );
        let size_final = self.nflog.size_final(self.tip_height);
        ensure!(
            size <= size_final,
            "incoming transition: nav.size {size} exceeds size_final {size_final}"
        );
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn validate_pending_envelope(&self, pending: &PendingTransition) -> Result<()> {
        let witness = &pending.witness_wip;
        ensure!(
            pending.owner == witness.prev_account_state.owner,
            "pending envelope owner differs from witness.prev_account_state.owner"
        );
        ensure!(
            pending.owner == witness.new_account_state.owner,
            "pending envelope owner differs from witness.new_account_state.owner"
        );
        ensure!(
            pending.mode == witness.mode,
            "pending envelope mode differs from witness.mode"
        );
        ensure!(
            pending.nav_opening
                == (NavOpening {
                    nav: witness.nav,
                    nav_rand: witness.nav_rand,
                }),
            "pending envelope nav_opening differs from witness nav/nav_rand"
        );

        match self.accounts.get(&pending.owner) {
            Some(record) => {
                ensure!(
                    matches!(pending.mode, TransitionMode::AccountUpdateProof),
                    "present account requires AccountUpdateProof mode"
                );
                ensure!(
                    record.state == witness.prev_account_state,
                    "stored account state differs from witness.prev_account_state"
                );
            }
            None => {
                ensure!(
                    matches!(pending.mode, TransitionMode::InitialProof),
                    "absent account requires InitialProof mode"
                );
            }
        }
        Ok(())
    }

    /// Re-check every live-engine input that `begin_*` / clause-10 / prove
    /// decisions depend on. Derived by tracing what the **commit depends on**
    /// (engine reads from pending construction through apply), not by
    /// extending an ad-hoc checklist.
    ///
    /// **Scope of this method:** live engine state only. Caller-supplied
    /// durable fields that never touch the engine (e.g. receive-path
    /// `build_tip` vs adapter tip identity, commit signature vs proved
    /// envelope) are revalidated at the node commit boundary — see
    /// `node::v11::receive::commit_proved_receive`. A pure "what did we
    /// read?" derivation misses those; the full method is "everything the
    /// durable commit depends on".
    ///
    /// | Live read | Where baked | Re-check here |
    /// |-----------|-------------|---------------|
    /// | account `state` / presence / mode | envelope + coinhist | `validate_pending_envelope` |
    /// | `tip_height` → `size_final` | `pending.nav` | `nav.size ≤ size_final(tip)` |
    /// | canonical receiver NAV (size, mth) | `pending.nav` | `is_canonical` |
    /// | predecessor nullifier pos/R | witness (AccountUpdate) | still Present at pos |
    /// | creating nullifier anchors | `received_auth` | still Present at `pos_create` + inclusion |
    /// | creating NAV canonicity / prefix | `received_auth` | `is_canonical` + consistency |
    /// | own Pk absent (apply guard) | — | checked later in apply body |
    /// | CoinHist leaf collisions / root | apply body | sequential rebuild below |
    ///
    /// Tip is not compared for equality here: the only tip-dependent *engine*
    /// decision is `size_final(tip)`, which is rechecked directly. A concurrent
    /// tip advance that only grows `size_final` leaves a still-valid proved NAV
    /// as a canonical prefix (`size ≤ size_final`). (Caller-supplied
    /// `build_tip` identity is a separate node-layer check.)
    fn revalidate_pending_against_live(&self, pending: &PendingTransition) -> Result<()> {
        self.validate_pending_envelope(pending)?;

        let receiver_nav = pending.nav_opening.nav;
        let size_final = self.nflog.size_final(self.tip_height);
        ensure!(
            receiver_nav.size <= size_final,
            "apply: pending receiver nav.size {} exceeds live size_final {} at tip {} \
             (tip/`size_final` moved under the proved NAV)",
            receiver_nav.size,
            size_final,
            self.tip_height
        );
        ensure!(
            self.nflog
                .is_canonical(receiver_nav.size, receiver_nav.mth),
            "apply: pending receiver nav is no longer canonical on the live NfLog \
             (tip={}, size_final={})",
            self.tip_height,
            size_final
        );

        if let Some(pred) = &pending.witness_wip.predecessor_nullifier {
            match self.nflog.lookup(pred.nullifier.public_key) {
                LookupResult::Present { pos, r, .. } => {
                    ensure!(
                        r == pred.nullifier.signature_r,
                        "apply: predecessor nullifier R on live NfLog does not match witness"
                    );
                    ensure!(
                        pos == pred.position,
                        "apply: predecessor nullifier position moved \
                         (witness {witness_pos} → live {pos})",
                        witness_pos = pred.position
                    );
                    ensure!(
                        pos < receiver_nav.size,
                        "apply: predecessor position {pos} is not covered by \
                         pending receiver nav.size {}",
                        receiver_nav.size
                    );
                    let leaf = host::nflog_leaf_hash(
                        pos,
                        &NfLogEntry {
                            pk: pred.nullifier.public_key,
                            r: pred.nullifier.signature_r,
                        },
                    );
                    ensure!(
                        host::verify_inclusion(
                            leaf,
                            pos,
                            &pred.nav_inclusion,
                            receiver_nav.size,
                            receiver_nav.mth,
                        ),
                        "apply: predecessor inclusion path no longer opens pending receiver nav"
                    );
                }
                LookupResult::Absent => {
                    bail!(
                        "apply: predecessor nullifier is no longer on the live NfLog \
                         (reorg / un-fold during prove)"
                    );
                }
            }
        }

        for (index, auth) in pending.witness_wip.received_auth.iter().enumerate() {
            match self.nflog.lookup(auth.creating_nullifier.public_key) {
                LookupResult::Present { pos, r, .. } => {
                    ensure!(
                        r == auth.creating_nullifier.signature_r,
                        "apply: creating nullifier R mismatch for received slot {index}"
                    );
                    ensure!(
                        pos == auth.pos_create,
                        "apply: creating nullifier position moved for received slot {index} \
                         (witness {} → live {pos})",
                        auth.pos_create
                    );
                    ensure!(
                        pos < receiver_nav.size,
                        "apply: creating nullifier position {pos} for slot {index} is not \
                         covered by pending receiver nav.size {}",
                        receiver_nav.size
                    );
                }
                LookupResult::Absent => {
                    bail!(
                        "apply: creating nullifier for received slot {index} is no longer \
                         on the live NfLog (reorg / un-fold during prove)"
                    );
                }
            }

            ensure!(
                self.nflog.is_canonical(
                    auth.creating_nav_opening.nav.size,
                    auth.creating_nav_opening.nav.mth
                ),
                "apply: creating nav for received slot {index} is no longer canonical"
            );

            let leaf = host::nflog_leaf_hash(
                auth.pos_create,
                &NfLogEntry {
                    pk: auth.creating_nullifier.public_key,
                    r: auth.creating_nullifier.signature_r,
                },
            );
            ensure!(
                host::verify_inclusion(
                    leaf,
                    auth.pos_create,
                    &auth.creating_nav_inclusion,
                    receiver_nav.size,
                    receiver_nav.mth,
                ),
                "apply: creating nullifier inclusion path no longer opens pending receiver \
                 nav for slot {index}"
            );
            ensure!(
                host::verify_consistency(
                    auth.creating_nav_opening.nav.size,
                    auth.creating_nav_opening.nav.mth,
                    receiver_nav.size,
                    receiver_nav.mth,
                    &auth.creating_nav_consistency,
                ),
                "apply: creating nav is no longer a prefix of pending receiver nav for slot {index}"
            );
        }

        Ok(())
    }

    /// Shared setup for begin_*: mode, prev state, recursion material, and a
    /// mutable coinhist leaf map for sequential clause-8 updates.
    fn account_transition_context(
        &self,
        owner: &Address,
        nk: &[u8; 32],
        current_pubkey: [u8; 32],
    ) -> Result<(
        TransitionMode,
        AccountState,
        Option<ComplianceProof>,
        Option<NavOpening>,
        Option<PredecessorNullifier>,
        Vec<HashDigest>,
        BTreeMap<[u8; 32], host::CoinHistState>,
    )> {
        let nav = self.size_final_nav()?;

        if let Some(record) = self.accounts.get(owner) {
            ensure!(record.nk == *nk, "nk does not match registered account");
            ensure!(
                record.state.current_pubkey == current_pubkey,
                "current_pubkey does not match registered account"
            );
            let prev_proof = record
                .last_proof
                .clone()
                .context("AccountUpdateProof requires last_proof on the account")?;
            let prev_nav_opening = record
                .last_nav_opening
                .context("AccountUpdateProof requires last_nav_opening")?;
            let last_nf = record
                .last_nullifier
                .clone()
                .context("AccountUpdateProof requires last_nullifier")?;
            // Canonical position is what the chain-derived NfLog says (§3.6),
            // never a locally invented fold ordinal. A receive that has been
            // applied but not yet scan-folded has last_nullifier_pos = None
            // and must fail here until inclusion (fail-closed, no silent skip).
            let pos = match self.nflog.lookup(last_nf.public_key) {
                LookupResult::Present { pos, r, .. } => {
                    ensure!(
                        r == last_nf.signature_r,
                        "predecessor nullifier R on NfLog does not match account last_nullifier.R"
                    );
                    if let Some(cached) = record.last_nullifier_pos {
                        ensure!(
                            cached == pos,
                            "account last_nullifier_pos {cached} diverges from canonical \
                             NfLog position {pos} — refusing to prove on a stale cache"
                        );
                    }
                    pos
                }
                LookupResult::Absent => {
                    bail!(
                        "predecessor nullifier is not in the canonical NfLog \
                         (awaiting on-chain inclusion / scan-fold); refusing AccountUpdateProof"
                    );
                }
            };

            ensure!(
                pos < nav.size,
                "predecessor nullifier position {pos} is not covered by size_final nav.size {}",
                nav.size
            );
            // Inclusion path over the size_final prefix.
            let prefix = &self.nflog_entries[..nav.size as usize];
            let nav_inclusion = host::inclusion_path(pos, prefix)
                .context("predecessor nullifier inclusion path")?;
            let nav_consistency = host::consistency_proof(prev_nav_opening.nav.size, prefix)
                .context("nav consistency proof")?;

            let leaves = leaves_from_sets(&record.spendable, &record.spent_ids);
            Ok((
                TransitionMode::AccountUpdateProof,
                record.state.clone(),
                Some(prev_proof),
                Some(prev_nav_opening),
                Some(PredecessorNullifier {
                    nullifier: last_nf,
                    nav_inclusion,
                    position: pos,
                }),
                nav_consistency,
                leaves,
            ))
        } else {
            // Genesis / first transition: canonical empty account.
            let nk_commit = host::nk_commit(nk);
            let prev = AccountState::new(
                *owner,
                nk_commit,
                BTreeMap::new(),
                current_pubkey,
                0,
                host::coinhist_empty_root(),
            )
            .context("construct empty genesis AccountState")?;
            // InitialProof: empty consistency from 0 → nav.size (special-cased empty).
            ensure!(
                nav.size == 0
                    || host::consistency_proof(0, &self.nflog_entries[..nav.size as usize]).is_ok(),
                "initial nav consistency pre-check failed"
            );
            let nav_consistency = if nav.size == 0 {
                Vec::new()
            } else {
                // m == 0 ⇒ empty proof per validate_consistency_proof.
                Vec::new()
            };
            Ok((
                TransitionMode::InitialProof,
                prev,
                None,
                None,
                None,
                nav_consistency,
                BTreeMap::new(),
            ))
        }
    }

    /// `nav = size_final` at the current tip (§2.3.2 step 5 / §3.9).
    fn size_final_nav(&self) -> Result<Nav> {
        let size = self.nflog.size_final(self.tip_height);
        let full = self.nflog.nav();
        ensure!(
            size <= full.size,
            "size_final {size} exceeds accumulator size {}",
            full.size
        );
        if size == 0 {
            return Ok(Nav {
                size: 0,
                mth: host::nflog_empty(),
            });
        }
        if size == full.size {
            return Ok(full);
        }
        ensure!(
            self.nflog_entries.len() as u64 >= size,
            "nflog_entries shorter than size_final"
        );
        let mth = host::nflog_mth(&self.nflog_entries[..size as usize]);
        ensure!(
            self.nflog.is_canonical(size, mth),
            "computed size_final mth is not canonical"
        );
        Ok(Nav { size, mth })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn placeholder_signature(pk_i: [u8; 32]) -> TransitionSignature {
    TransitionSignature {
        pk_i,
        signature: [0u8; 64],
        r_prime: [0u8; 32],
    }
}

fn compute_proof_data(
    new_account_state: &AccountState,
    output_coins: &[Coin],
    input_coins: &[Coin],
    nk: &[u8; 32],
    nav: Nav,
    nav_rand: &[u8; 32],
    next_pubkey: &[u8; 32],
    npk_rand: &[u8; 32],
) -> Result<ProofData> {
    let output_ids: Vec<HashDigest> = output_coins.iter().map(|c| c.identifier).collect();
    let nullifiers: Vec<HashDigest> = input_coins
        .iter()
        .map(|c| host::nullifier(nk, c.identifier))
        .collect();
    Ok(ProofData {
        new_account_state_hash: host::account_state_hash(new_account_state)
            .context("hash new account state")?,
        output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &output_ids),
        input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &nullifiers),
        coin_history_root: new_account_state.coin_history_root,
        nav_commitment: host::nav_commitment(nav.root(), nav_rand),
        npk_commit: host::npk_commit(next_pubkey, npk_rand),
    })
}

fn leaves_from_sets(
    spendable: &BTreeMap<[u8; 32], TrackedCoin>,
    spent_ids: &BTreeSet<[u8; 32]>,
) -> BTreeMap<[u8; 32], host::CoinHistState> {
    let mut leaves = BTreeMap::new();
    for id in spent_ids {
        leaves.insert(*id, host::CoinHistState::Spent);
    }
    for id in spendable.keys() {
        leaves.insert(*id, host::CoinHistState::Admitted);
    }
    leaves
}

fn rebuild_coinhist(leaves: &BTreeMap<[u8; 32], host::CoinHistState>) -> Result<CoinHistTree> {
    let mut hist = CoinHistTree::new();
    for (&id, &state) in leaves {
        match state {
            host::CoinHistState::Admitted => {
                hist.admit(id).context("rebuild admit")?;
            }
            host::CoinHistState::Spent => {
                hist.admit(id).context("rebuild admit-before-spend")?;
                hist.spend(id).context("rebuild spend")?;
            }
            host::CoinHistState::Absent => {
                bail!("Absent must not appear in coinhist leaf map");
            }
        }
    }
    Ok(hist)
}

fn credit_balance(
    balances: &mut BTreeMap<[u8; 32], u128>,
    asset_id: HashDigest,
    amount: u128,
) -> Result<()> {
    ensure!(amount > 0, "credit amount must be non-zero");
    let key = host::digest_to_bytes(&asset_id);
    let entry = balances.entry(key).or_insert(0);
    *entry = entry
        .checked_add(amount)
        .context("balance credit overflow")?;
    ensure!(
        balances.len() <= MAX_ACCOUNT_ASSETS,
        "account balance count exceeds MAX_ACCOUNT_ASSETS"
    );
    Ok(())
}

fn debit_balance(
    balances: &mut BTreeMap<[u8; 32], u128>,
    asset_id: HashDigest,
    amount: u128,
) -> Result<()> {
    ensure!(amount > 0, "debit amount must be non-zero");
    let key = host::digest_to_bytes(&asset_id);
    let cur = balances
        .get(&key)
        .copied()
        .context("debit: asset not present in balances")?;
    ensure!(cur >= amount, "debit: insufficient balance");
    let next = cur - amount;
    if next == 0 {
        balances.remove(&key);
    } else {
        balances.insert(key, next);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prover_bridge::test_signing::{
        base_proved_transition, deterministic_secret, normalized_key, sign_transition,
    };
    use crate::prover_bridge::{OutputInclusionProof, ReceivedAuthorization};
    use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
    use sha2::{Digest, Sha256};
    use zkcoins_program_plonky2::circuit::gadgets::curve_types::{AffinePoint, Secp256K1};

    /// Deterministic keys / coin construction matching `prover_bridge` fixtures.
    struct FundedFixture {
        owner: Address,
        nk: [u8; 32],
        op_secret: OpSecret,
        asset_id: HashDigest,
        input_coin: Coin,
        /// Secret for the account's *current* spend key (post-mint = spend-key-1).
        spend_secret: Secp256K1Scalar,
        spend_public: AffinePoint<Secp256K1>,
        next_pubkey: [u8; 32],
        genesis_proof: ProvedTransition,
        genesis_nav_opening: NavOpening,
        genesis_nullifier: NullifierOpening,
    }

    fn label_op_secret(label: &[u8]) -> OpSecret {
        OpSecret(Sha256::digest(label).into())
    }

    fn build_funded_fixture(bridge: &ProverBridge) -> FundedFixture {
        // --- genesis mint witness (same pattern as prover_bridge::genesis_fixture) ---
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/compliance-chain/nk").into();
        let nk_commit = host::nk_commit(&nk);
        let (secret0, public0, pk0) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-0",
        ));
        let (_, _, pk1) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-1",
        ));
        let owner = Address(host::address(&pk0, nk_commit));
        let name_hash: [u8; 32] = Sha256::digest(b"Recursive Fixture Asset").into();
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &pk0, &name_hash, 2, 1);
        let issuance = AssetIssuance {
            asset_id,
            creator_pubkey: pk0,
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
            pk0,
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
        let mut history = CoinHistTree::new();
        let output_history = history.prove(host::digest_to_bytes(&output_coin.identifier));
        history
            .admit(host::digest_to_bytes(&output_coin.identifier))
            .unwrap();
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), 100);
        let new_account_state =
            AccountState::new(owner, nk_commit, balances, pk1, 1, history.root()).unwrap();
        // Fresh-net mint: nav = size_final = empty.
        let nav_opening = NavOpening {
            nav: Nav {
                size: 0,
                mth: host::nflog_empty(),
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
            npk_commit: host::npk_commit(&pk1, &npk_rand),
        };
        let signature = sign_transition(secret0, public0, &proof_data, Network::Testnet);
        let witness = TransitionWitness {
            mode: TransitionMode::InitialProof,
            prev_account_state,
            new_account_state: new_account_state.clone(),
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
            next_pubkey: pk1,
            npk_rand,
            transition_signature: signature.transition.clone(),
            prev_proof: None,
            predecessor_nullifier: None,
        };
        let genesis_proof = bridge
            .prove_transition(&witness)
            .expect("fixture genesis/mint proof");

        let (spend_secret, spend_public, pk1_check) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-1",
        ));
        assert_eq!(pk1_check, pk1);
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-2",
        ));

        FundedFixture {
            owner,
            nk,
            op_secret: label_op_secret(b"zkCoins/v1/compliance-chain/op_secret"),
            asset_id,
            input_coin: output_coin,
            spend_secret,
            spend_public,
            next_pubkey,
            genesis_proof,
            genesis_nav_opening: nav_opening,
            genesis_nullifier: NullifierOpening {
                public_key: signature.transition.pk_i,
                signature_r: signature.transition.signature_r(),
                r_prime: signature.transition.r_prime,
            },
        }
    }

    fn engine_with_funded_account(fixture: &FundedFixture) -> StateEngine {
        let mut engine = StateEngine::new(Network::Testnet, 0);
        // Fold the genesis nullifier at height 100, then tip past finality so
        // size_final covers it (predecessor dependency for the send).
        engine.set_tip_height(100);
        let genesis_position = ChainPosition {
            height: 100,
            tx_index: 0,
            vin_index: 0,
            member_index: 0,
        };
        let fold = engine
            .nflog
            .fold(
                genesis_position,
                fixture.genesis_nullifier.public_key,
                fixture.genesis_nullifier.signature_r,
            )
            .expect("fold genesis nullifier");
        let pos = match fold {
            FoldOutcome::Appended(p) => p,
            other => panic!("expected Appended, got {other:?}"),
        };
        engine.nflog_entries.push(NfLogEntry {
            pk: fixture.genesis_nullifier.public_key,
            r: fixture.genesis_nullifier.signature_r,
        });
        engine.nflog_positions.push(genesis_position);
        engine.fold_seq = 1;
        // tip ≥ height + 5 ⇒ size_final includes the entry.
        engine.set_tip_height(105);

        let mut coinhist = CoinHistTree::new();
        let id = host::digest_to_bytes(&fixture.input_coin.identifier);
        coinhist.admit(id).unwrap();
        let mut spendable = BTreeMap::new();
        let creating_prev_ash = {
            // prev_ash of the genesis mint (empty → minted state).
            let nk_commit = host::nk_commit(&fixture.nk);
            let (_s, _p, pk0) = normalized_key(deterministic_secret(
                b"zkCoins/v1/compliance-chain/spend-key-0",
            ));
            let empty = AccountState::new(
                fixture.owner,
                nk_commit,
                BTreeMap::new(),
                pk0,
                0,
                host::coinhist_empty_root(),
            )
            .unwrap();
            host::account_state_hash(&empty).unwrap()
        };
        spendable.insert(
            id,
            TrackedCoin {
                coin: fixture.input_coin.clone(),
                creating_prev_ash,
                coin_index: 0,
            },
        );
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&fixture.asset_id), 100);
        let (_s, _p, pk1) = normalized_key(deterministic_secret(
            b"zkCoins/v1/compliance-chain/spend-key-1",
        ));
        let state = AccountState::new(
            fixture.owner,
            host::nk_commit(&fixture.nk),
            balances,
            pk1,
            1,
            coinhist.root(),
        )
        .unwrap();
        let record = AccountRecord {
            state,
            coinhist,
            nk: fixture.nk,
            op_secret: Some(fixture.op_secret),
            genesis_pubkey: {
                let (_s, _p, pk0) = normalized_key(deterministic_secret(
                    b"zkCoins/v1/compliance-chain/spend-key-0",
                ));
                pk0
            },
            spendable,
            spent_ids: BTreeSet::new(),
            last_proof: Some(fixture.genesis_proof.proof.clone()),
            last_nav_opening: Some(fixture.genesis_nav_opening),
            last_nullifier: Some(fixture.genesis_nullifier.clone()),
            last_nullifier_pos: Some(pos),
        };
        engine.insert_account(fixture.owner, record).unwrap();
        let _ = pos;
        engine
    }

    fn test_mint_request(issuance_version: u8) -> MintRequest {
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/state-engine/test-mint/nk").into();
        let (_, _, current_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/test-mint/pk0",
        ));
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/test-mint/pk1",
        ));
        MintRequest {
            owner: Address(host::address(&current_pubkey, host::nk_commit(&nk))),
            nk,
            op_secret: label_op_secret(b"zkCoins/v1/state-engine/test-mint/op_secret"),
            current_pubkey,
            next_pubkey,
            name: b"State Engine Test Asset".to_vec(),
            decimals: 2,
            amount: 100,
            issuance_version,
            cap_total: if issuance_version == 2 { 100 } else { 0 },
            terms_salt: if issuance_version == 2 {
                [0x44; 32]
            } else {
                [0; 32]
            },
            npk_rand: [0x22; 32],
        }
    }

    fn dummy_received_auth(
        creating_proof: ComplianceProof,
        creating_prev_ash: HashDigest,
        leaf_index: u32,
    ) -> ReceivedAuthorization {
        let empty_nav = Nav {
            size: 0,
            mth: host::nflog_empty(),
        };
        ReceivedAuthorization {
            creating_proof,
            output_inclusion: crate::prover_bridge::OutputInclusionProof {
                leaf_index,
                depth: 0,
                siblings: Vec::new(),
            },
            creating_prev_ash,
            creating_nullifier: NullifierOpening {
                public_key: [0; 32],
                signature_r: [0; 32],
                r_prime: [0; 32],
            },
            creating_nav_inclusion: Vec::new(),
            pos_create: 0,
            creating_nav_opening: NavOpening {
                nav: empty_nav,
                nav_rand: [0; 32],
            },
            creating_nav_consistency: Vec::new(),
            history_proof: CoinHistTree::new().prove([0; 32]),
        }
    }

    #[test]
    fn begin_mint_rejects_token_standard_2_without_explicit_recipient() {
        let engine = StateEngine::new(Network::Testnet, 0);
        let err = engine
            .begin_mint(test_mint_request(2))
            .expect_err("v2 mint must fail loudly");
        assert!(
            format!("{err:#}").contains("explicit non-owner emission recipient"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn begin_receive_initial_proof_uses_sequential_history_roots() {
        let mut engine = StateEngine::new(Network::Testnet, 0);
        engine.set_tip_height(0);

        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/state-engine/initial-receive/nk").into();
        let (_, _, current_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/initial-receive/pk0",
        ));
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/initial-receive/pk1",
        ));
        let owner = Address(host::address(&current_pubkey, host::nk_commit(&nk)));
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &current_pubkey, &[0x31; 32], 2, 1);
        let initial_state = AccountState::new(
            owner,
            host::nk_commit(&nk),
            BTreeMap::new(),
            current_pubkey,
            0,
            host::coinhist_empty_root(),
        )
        .unwrap();
        let creating_prev_ash = host::account_state_hash(&initial_state).unwrap();
        let coins = vec![
            Coin {
                identifier: host::coin_identifier(creating_prev_ash, &owner.0, asset_id, 40, 0),
                recipient: owner,
                amount: 40,
                asset_id,
            },
            Coin {
                identifier: host::coin_identifier(creating_prev_ash, &owner.0, asset_id, 60, 1),
                recipient: owner,
                amount: 60,
                asset_id,
            },
        ];
        let base = base_proved_transition(Network::Testnet);
        let auth = vec![
            dummy_received_auth(base.proof.clone(), creating_prev_ash, 0),
            dummy_received_auth(base.proof, creating_prev_ash, 1),
        ];

        let pending = engine
            .begin_receive(ReceiveRequest {
                owner,
                nk,
                op_secret: label_op_secret(b"zkCoins/v1/state-engine/initial-receive/op_secret"),
                current_pubkey,
                received_coins: coins.clone(),
                received_auth: auth,
                next_pubkey,
                npk_rand: [0x42; 32],
            })
            .expect("first-transition batched receive");
        assert_eq!(pending.mode, TransitionMode::InitialProof);
        assert!(pending.witness_wip.prev_proof.is_none());

        let first_id = host::digest_to_bytes(&coins[0].identifier);
        let second_id = host::digest_to_bytes(&coins[1].identifier);
        let first_proof = &pending.witness_wip.received_auth[0].history_proof;
        let second_proof = &pending.witness_wip.received_auth[1].history_proof;
        assert!(first_proof.verify(&first_id, host::coinhist_empty_root()));
        assert!(!second_proof.verify(&second_id, host::coinhist_empty_root()));
        let mut intermediate = CoinHistTree::new();
        intermediate.admit(first_id).unwrap();
        assert!(second_proof.verify(&second_id, intermediate.root()));
        intermediate.admit(second_id).unwrap();
        assert_eq!(
            intermediate.root(),
            pending.witness_wip.new_account_state.coin_history_root
        );
    }

    #[test]
    fn begin_send_multi_input_uses_sequential_history_roots() {
        let mut engine = StateEngine::new(Network::Testnet, 0);
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/state-engine/multi-send/nk").into();
        let (_, _, genesis_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/multi-send/pk0",
        ));
        let (_, _, current_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/multi-send/pk1",
        ));
        let (_, _, next_pubkey) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/multi-send/pk2",
        ));
        let owner = Address(host::address(&genesis_pubkey, host::nk_commit(&nk)));
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &genesis_pubkey, &[0x52; 32], 2, 1);
        let creating_state = AccountState::new(
            owner,
            host::nk_commit(&nk),
            BTreeMap::new(),
            genesis_pubkey,
            0,
            host::coinhist_empty_root(),
        )
        .unwrap();
        let creating_prev_ash = host::account_state_hash(&creating_state).unwrap();
        let coins = vec![
            Coin {
                identifier: host::coin_identifier(creating_prev_ash, &owner.0, asset_id, 40, 0),
                recipient: owner,
                amount: 40,
                asset_id,
            },
            Coin {
                identifier: host::coin_identifier(creating_prev_ash, &owner.0, asset_id, 60, 1),
                recipient: owner,
                amount: 60,
                asset_id,
            },
        ];
        let mut coinhist = CoinHistTree::new();
        let mut spendable = BTreeMap::new();
        for (index, coin) in coins.iter().enumerate() {
            let id = host::digest_to_bytes(&coin.identifier);
            coinhist.admit(id).unwrap();
            spendable.insert(
                id,
                TrackedCoin {
                    coin: coin.clone(),
                    creating_prev_ash,
                    coin_index: index as u32,
                },
            );
        }
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), 100);
        let state = AccountState::new(
            owner,
            host::nk_commit(&nk),
            balances,
            current_pubkey,
            1,
            coinhist.root(),
        )
        .unwrap();

        let predecessor_position = ChainPosition {
            height: 10,
            tx_index: 0,
            vin_index: 0,
            member_index: 0,
        };
        let predecessor_entry = NfLogEntry {
            pk: genesis_pubkey,
            r: [0x61; 32],
        };
        engine.set_tip_height(10);
        assert_eq!(
            engine
                .nflog
                .fold(
                    predecessor_position,
                    predecessor_entry.pk,
                    predecessor_entry.r,
                )
                .unwrap(),
            FoldOutcome::Appended(0)
        );
        engine.nflog_entries.push(predecessor_entry);
        engine.nflog_positions.push(predecessor_position);
        engine.set_tip_height(15);
        engine
            .insert_account(
                owner,
                AccountRecord {
                    state: state.clone(),
                    coinhist,
                    nk,
                    op_secret: Some(label_op_secret(
                        b"zkCoins/v1/state-engine/multi-send/op_secret",
                    )),
                    genesis_pubkey,
                    spendable,
                    spent_ids: BTreeSet::new(),
                    last_proof: Some(base_proved_transition(Network::Testnet).proof),
                    last_nav_opening: Some(NavOpening {
                        nav: Nav {
                            size: 0,
                            mth: host::nflog_empty(),
                        },
                        nav_rand: [0; 32],
                    }),
                    last_nullifier: Some(NullifierOpening {
                        public_key: predecessor_entry.pk,
                        signature_r: predecessor_entry.r,
                        r_prime: [0; 32],
                    }),
                    last_nullifier_pos: Some(0),
                },
            )
            .unwrap();

        let pending = engine
            .begin_send(SendRequest {
                owner,
                input_coin_ids: coins.iter().map(|coin| coin.identifier).collect(),
                output_templates: vec![CoinTemplate {
                    recipient: Address([0x71; 32]),
                    amount: 100,
                    asset_id,
                }],
                next_pubkey,
                npk_rand: [0x73; 32],
            })
            .expect("multi-input begin_send");

        let first_id = host::digest_to_bytes(&coins[0].identifier);
        let second_id = host::digest_to_bytes(&coins[1].identifier);
        let first_proof = &pending.witness_wip.input_auth[0].history_proof;
        let second_proof = &pending.witness_wip.input_auth[1].history_proof;
        assert!(first_proof.verify(&first_id, state.coin_history_root));
        assert!(!second_proof.verify(&second_id, state.coin_history_root));
        let mut intermediate = rebuild_coinhist(&leaves_from_sets(
            &engine.account(&owner).unwrap().spendable,
            &BTreeSet::new(),
        ))
        .unwrap();
        intermediate.spend(first_id).unwrap();
        assert!(second_proof.verify(&second_id, intermediate.root()));
        intermediate.spend(second_id).unwrap();
        assert_eq!(
            intermediate.root(),
            pending.witness_wip.new_account_state.coin_history_root
        );
    }

    #[test]
    fn finalise_rejects_pending_envelope_mismatches_before_proving() {
        let engine = StateEngine::new(Network::Testnet, 0);
        let pending = engine
            .begin_mint(test_mint_request(1))
            .expect("begin token-standard-1 mint");
        let signature =
            placeholder_signature(pending.witness_wip.prev_account_state.current_pubkey);

        let mut wrong_owner = pending.clone();
        wrong_owner.owner = Address([0x91; 32]);
        let mut owner_engine = engine;
        let err = owner_engine
            .finalise(wrong_owner, signature.clone())
            .expect_err("wrong envelope owner must fail before proving");
        assert!(format!("{err:#}").contains("envelope owner"));

        let mut wrong_mode = pending.clone();
        wrong_mode.mode = TransitionMode::AccountUpdateProof;
        let mut mode_engine = StateEngine::new(Network::Testnet, 0);
        let err = mode_engine
            .finalise(wrong_mode, signature.clone())
            .expect_err("wrong envelope mode must fail before proving");
        assert!(format!("{err:#}").contains("envelope mode"));

        let mut stale_pending = pending.clone();
        stale_pending.mode = TransitionMode::AccountUpdateProof;
        stale_pending.witness_wip.mode = TransitionMode::AccountUpdateProof;
        let mut stale_state = stale_pending.witness_wip.prev_account_state.clone();
        stale_state.send_counter = 1;
        let stale_owner = stale_pending.owner;
        let mut stale_engine = StateEngine::new(Network::Testnet, 0);
        stale_engine
            .insert_account(
                stale_owner,
                AccountRecord {
                    state: stale_state,
                    coinhist: CoinHistTree::new(),
                    nk: stale_pending.witness_wip.nk,
                    op_secret: Some(stale_pending.op_secret),
                    genesis_pubkey: stale_pending.witness_wip.prev_account_state.current_pubkey,
                    spendable: BTreeMap::new(),
                    spent_ids: BTreeSet::new(),
                    last_proof: None,
                    last_nav_opening: None,
                    last_nullifier: None,
                    last_nullifier_pos: None,
                },
            )
            .unwrap();
        let err = stale_engine
            .finalise(stale_pending, signature.clone())
            .expect_err("stale witness prev_account_state must fail before proving");
        assert!(format!("{err:#}").contains("stored account state"));

        let mut wrong_nav = pending;
        wrong_nav.nav_opening.nav_rand[0] ^= 1;
        let mut nav_engine = StateEngine::new(Network::Testnet, 0);
        let err = nav_engine
            .finalise(wrong_nav, signature)
            .expect_err("wrong envelope NAV must fail before proving");
        assert!(format!("{err:#}").contains("envelope nav_opening"));
    }

    /// Public finalise and the receive-named alias are the same deferred-only
    /// path: neither can invent a synthetic NfLog position.
    ///
    /// Uses a cheap envelope-mismatch rejection (before prove) so the default
    /// suite does not build the compliance circuit. Success-path proof that
    /// mint/send leave the log untouched lives in the ignored send e2e.
    #[test]
    fn public_finalise_api_is_deferred_only_and_leaves_nflog_untouched_on_prove_fail() {
        let mut via_finalise = StateEngine::new(Network::Testnet, 0);
        let mut via_alias = StateEngine::new(Network::Testnet, 0);
        let req = test_mint_request(1);
        let pending_a = via_finalise
            .begin_mint(req.clone())
            .expect("begin mint A");
        let pending_b = via_alias.begin_mint(req).expect("begin mint B");
        let signature =
            placeholder_signature(pending_a.witness_wip.prev_account_state.current_pubkey);

        assert_eq!(via_finalise.nflog.nav().size, 0);
        assert_eq!(via_alias.nflog.nav().size, 0);

        // Envelope mismatch fails before prove — both public entry points
        // must leave the canonical NfLog untouched (no SyntheticLocal fold).
        let mut wrong_a = pending_a;
        wrong_a.owner = Address([0x91u8; 32]);
        let mut wrong_b = pending_b;
        wrong_b.owner = Address([0x92u8; 32]);
        via_finalise
            .finalise(wrong_a, signature.clone())
            .expect_err("finalise must reject envelope mismatch");
        via_alias
            .finalise_pending_chain_nullifier(wrong_b, signature)
            .expect_err("alias must reject envelope mismatch");
        assert_eq!(via_finalise.nflog.nav().size, 0);
        assert_eq!(via_alias.nflog.nav().size, 0);
        assert!(via_finalise.accounts.is_empty());
        assert!(via_alias.accounts.is_empty());
    }

    #[test]
    fn verify_incoming_rejects_forged_wrapper_proof_data_before_verify() {
        let engine = StateEngine::new(Network::Testnet, 0);
        let nav_opening = NavOpening {
            nav: Nav {
                size: 0,
                mth: host::nflog_empty(),
            },
            nav_rand: [0xc1; 32],
        };
        let mut proved = base_proved_transition(Network::Testnet);
        proved.proof_data.nav_commitment =
            host::nav_commitment(nav_opening.nav.root(), &nav_opening.nav_rand);

        let err = engine
            .verify_incoming_transition(&proved, &nav_opening)
            .expect_err("forged ProofData wrapper must not be trusted");
        let message = format!("{err:#}");
        assert!(
            message.contains("wrapper/public-input mismatch")
                && message.contains("proof_data differs"),
            "unexpected error: {message}"
        );
    }

    /// Fast: `begin_send` with outputs > inputs returns Err before proving.
    /// Conservation is checked before predecessor / last_proof wiring.
    #[test]
    fn begin_send_overspend_returns_err() {
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/state-engine/overspend/nk").into();
        let nk_commit = host::nk_commit(&nk);
        let (_s, _p, pk) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/overspend/pk",
        ));
        let owner = Address(host::address(&pk, nk_commit));
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &pk, &[7u8; 32], 2, 1);
        let empty = AccountState::new(
            owner,
            nk_commit,
            BTreeMap::new(),
            pk,
            0,
            host::coinhist_empty_root(),
        )
        .expect("empty");
        let empty_ash = host::account_state_hash(&empty).expect("ash");
        let coin = Coin {
            identifier: host::coin_identifier(empty_ash, &owner.0, asset_id, 50, 0),
            recipient: owner,
            amount: 50,
            asset_id,
        };
        let mut coinhist = CoinHistTree::new();
        let id = host::digest_to_bytes(&coin.identifier);
        coinhist.admit(id).expect("admit");
        let mut spendable = BTreeMap::new();
        spendable.insert(
            id,
            TrackedCoin {
                coin: coin.clone(),
                creating_prev_ash: empty_ash,
                coin_index: 0,
            },
        );
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), 50);
        let state =
            AccountState::new(owner, nk_commit, balances, pk, 1, coinhist.root()).expect("state");
        let record = AccountRecord {
            state,
            coinhist,
            nk,
            op_secret: Some(label_op_secret(b"zkCoins/v1/state-engine/overspend/op_secret")),
            genesis_pubkey: pk,
            spendable,
            spent_ids: BTreeSet::new(),
            // No last_proof — overspend is checked first and must fail loud.
            last_proof: None,
            last_nav_opening: None,
            last_nullifier: None,
            last_nullifier_pos: None,
        };
        let mut engine = StateEngine::new(Network::Testnet, 0);
        engine.insert_account(owner, record).expect("insert");

        let err = engine
            .begin_send(SendRequest {
                owner,
                input_coin_ids: vec![coin.identifier],
                output_templates: vec![CoinTemplate {
                    recipient: Address([0x99u8; 32]),
                    amount: 51, // > 50
                    asset_id,
                }],
                next_pubkey: [0x55u8; 32],
                npk_rand: [0x22u8; 32],
            })
            .expect_err("overspend must fail");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("over-spend"),
            "expected over-spend error, got: {msg}"
        );
    }

    /// End-to-end SEND through the engine (one engine `finalise` prove).
    ///
    /// Fixture setup proves a genesis mint once via the bridge so the account
    /// carries a genuine `last_proof`; the engine path under test is the send.
    #[test]
    #[ignore = "heavy: real Plonky2 prove (minutes); run with --ignored --release"]
    fn state_engine_send_end_to_end() {
        let bridge = ProverBridge::new(Network::Testnet);
        let fixture = build_funded_fixture(&bridge);
        let mut engine = engine_with_funded_account(&fixture);

        let external = Address([0x82u8; 32]);
        let pending = engine
            .begin_send(SendRequest {
                owner: fixture.owner,
                input_coin_ids: vec![fixture.input_coin.identifier],
                output_templates: vec![CoinTemplate {
                    recipient: external,
                    amount: 30,
                    asset_id: fixture.asset_id,
                }],
                next_pubkey: fixture.next_pubkey,
                npk_rand: [0xa5u8; 32],
            })
            .expect("begin_send");

        // Expected ProofData: change 70 self + 30 external.
        assert_eq!(pending.mode, TransitionMode::AccountUpdateProof);
        assert_eq!(pending.witness_wip.input_coins.len(), 1);
        assert_eq!(pending.witness_wip.output_coins.len(), 2);
        // Canonical order: recipient templates first, then change.
        assert_eq!(pending.witness_wip.output_templates[0].recipient, external);
        assert_eq!(pending.witness_wip.output_templates[0].amount, 30);
        assert_eq!(
            pending.witness_wip.output_templates[1].recipient,
            fixture.owner
        );
        assert_eq!(pending.witness_wip.output_templates[1].amount, 70);

        let expected_pd = compute_proof_data(
            &pending.witness_wip.new_account_state,
            &pending.witness_wip.output_coins,
            &pending.witness_wip.input_coins,
            &fixture.nk,
            pending.nav_opening.nav,
            &pending.nav_opening.nav_rand,
            &fixture.next_pubkey,
            &pending.witness_wip.npk_rand,
        )
        .unwrap();
        assert_eq!(pending.proof_data, expected_pd);
        assert_eq!(
            pending.proof_data_hash,
            host::hash_proof_data(&host::serialize_proof_data(&expected_pd))
        );

        // size_final nav must cover the predecessor.
        assert_eq!(pending.nav_opening.nav.size, 1);
        assert!(engine
            .nflog
            .is_canonical(pending.nav_opening.nav.size, pending.nav_opening.nav.mth));

        let sig = sign_transition(
            fixture.spend_secret,
            fixture.spend_public,
            &pending.proof_data,
            Network::Testnet,
        );
        let nflog_size_before = engine.nflog.nav().size;
        assert_eq!(nflog_size_before, 1, "only the funded genesis nullifier");

        let applied = engine
            .finalise(pending, sig.transition)
            .expect("finalise send");

        // Account state: balance 70, send_counter 2, current_pubkey rotated.
        let rec = engine.account(&fixture.owner).expect("account present");
        assert_eq!(rec.state.send_counter, 2);
        assert_eq!(rec.state.current_pubkey, fixture.next_pubkey);
        assert_eq!(
            rec.state
                .balances
                .get(&host::digest_to_bytes(&fixture.asset_id)),
            Some(&70)
        );
        assert_eq!(rec.coinhist.root(), rec.state.coin_history_root);
        // Input spent, change admitted.
        let in_id = host::digest_to_bytes(&fixture.input_coin.identifier);
        assert!(rec.spent_ids.contains(&in_id));
        assert!(!rec.spendable.contains_key(&in_id));
        assert_eq!(rec.spendable.len(), 1);
        let change = rec.spendable.values().next().unwrap();
        assert_eq!(change.coin.amount, 70);
        assert_eq!(change.coin.recipient, fixture.owner);

        // Engine invariant: send finalise must not invent a synthetic NfLog
        // entry. Own nullifier is pending until a real chain position is folded.
        assert_eq!(applied.nullifier.0, applied.proved.consumed_pubkey);
        assert_eq!(
            engine.nflog.nav().size,
            nflog_size_before,
            "finalise must not grow the canonical NfLog"
        );
        assert!(
            matches!(engine.nflog.lookup(applied.nullifier.0), LookupResult::Absent),
            "send own nullifier must stay absent until scan-fold"
        );
        assert!(
            rec.last_nullifier_pos.is_none(),
            "last_nullifier_pos must stay None until scan-fold"
        );
        assert!(rec.last_nullifier.is_some());

        // Scanner places the nullifier at a real chain position (not tip/fold_seq).
        // Must be strictly after the genesis fold at height 100.
        let scanned = ScannedNullifier::from_survivor(&PublishedNullifier {
            chain_pos: ChainPosition {
                height: 110,
                tx_index: 3,
                vin_index: 0,
                member_index: 0,
            },
            pk: applied.nullifier.0,
            r: applied.nullifier.1,
        });
        let pos = engine
            .append_nullifier(scanned)
            .expect("scan-fold send nullifier");
        assert_eq!(pos, 1);
        assert_eq!(engine.nflog.nav().size, 2);
        assert_eq!(engine.nflog_entries[1].pk, applied.nullifier.0);
        assert_eq!(engine.nflog_entries[1].r, applied.nullifier.1);

        // Host acceptance: the send's nav was size_final=1 at prove time; after
        // scan-fold size grows, but the proved nav remains a canonical prefix.
        // send_counter at entry is 1 (post-mint); nav_rand is derived, not caller-set.
        let expected_send_nav_rand = host::derive_nav_rand(fixture.op_secret.as_bytes(), 1);
        engine
            .verify_incoming_transition(
                &applied.proved,
                &NavOpening {
                    nav: Nav {
                        size: 1,
                        mth: host::nflog_mth(&engine.nflog_entries[..1]),
                    },
                    nav_rand: expected_send_nav_rand,
                },
            )
            .expect("verify_incoming_transition on applied send");
    }

    /// End-to-end RECEIVE through the engine with a **genuine creating proof**.
    ///
    /// Reuses [`build_funded_fixture`] (real genesis/mint prove) + a real send
    /// prove to Bob, then Bob's receive prove via `begin_receive` + `finalise`.
    /// Asserts:
    /// - receive finalise credits Bob's CoinHist / balance;
    /// - the canonical NfLog is **not** grown by receive finalise;
    /// - `last_nullifier_pos` stays `None` until a scan-path
    ///   [`ScannedNullifier`] append.
    ///
    /// Marked `#[ignore]`: three real Plonky2 proves (mint + send + receive).
    #[test]
    #[ignore = "heavy: real Plonky2 prove for mint+send+receive (minutes); run with --ignored --release"]
    fn state_engine_receive_end_to_end_with_genuine_creating_proof() {
        let bridge = ProverBridge::new(Network::Testnet);
        let fixture = build_funded_fixture(&bridge);
        let mut engine = engine_with_funded_account(&fixture);

        // Bob's keys (distinct from Alice).
        let bob_nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/state-engine/receive-e2e/bob-nk").into();
        let (bob_secret0, bob_public0, bob_pk0) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/receive-e2e/bob-sk0",
        ));
        let (_, _, bob_pk1) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/receive-e2e/bob-sk1",
        ));
        let bob_owner = Address(host::address(&bob_pk0, host::nk_commit(&bob_nk)));

        // Alice sends 30 to Bob (genuine recursive prove).
        let pending_send = engine
            .begin_send(SendRequest {
                owner: fixture.owner,
                input_coin_ids: vec![fixture.input_coin.identifier],
                output_templates: vec![CoinTemplate {
                    recipient: bob_owner,
                    amount: 30,
                    asset_id: fixture.asset_id,
                }],
                next_pubkey: fixture.next_pubkey,
                npk_rand: [0xa5u8; 32],
            })
            .expect("begin_send to Bob");
        let bob_coin = pending_send
            .witness_wip
            .output_coins
            .iter()
            .find(|c| c.recipient == bob_owner)
            .cloned()
            .expect("Bob's coin in send outputs");
        let bob_coin_index = pending_send
            .witness_wip
            .output_coins
            .iter()
            .position(|c| c.recipient == bob_owner)
            .expect("index") as u32;
        let send_creating_prev_ash =
            host::account_state_hash(&pending_send.witness_wip.prev_account_state).unwrap();
        let send_nav_opening = pending_send.nav_opening;
        let send_sig = sign_transition(
            fixture.spend_secret,
            fixture.spend_public,
            &pending_send.proof_data,
            Network::Testnet,
        );
        let nflog_before_send = engine.nflog.nav().size;
        let applied_send = engine
            .finalise(pending_send, send_sig.transition.clone())
            .expect("finalise send to Bob");
        assert_eq!(
            engine.nflog.nav().size,
            nflog_before_send,
            "send finalise must not grow NfLog"
        );

        // Scanner folds Alice's send nullifier so Bob's clause-10 can open it.
        let send_scanned = ScannedNullifier::from_survivor(&PublishedNullifier {
            chain_pos: ChainPosition {
                height: 110,
                tx_index: 1,
                vin_index: 0,
                member_index: 0,
            },
            pk: applied_send.nullifier.0,
            r: applied_send.nullifier.1,
        });
        let send_pos = engine
            .append_nullifier(send_scanned)
            .expect("scan-fold send nullifier");
        engine.set_tip_height(120); // past finality for send height 110

        // Output inclusion of Bob's coin in the send's output tree (2 leaves).
        let alice_change_id = {
            let rec = engine.account(&fixture.owner).expect("alice");
            rec.spendable
                .values()
                .next()
                .expect("change")
                .coin
                .identifier
        };
        // Order matches begin_send: recipient templates first, then change.
        let all_output_ids = vec![bob_coin.identifier, alice_change_id];
        let ocr = host::merkle_root(TreeKind::CoinsRoot, &all_output_ids);
        assert_eq!(ocr, applied_send.proved.proof_data.output_coins_root);
        let sibling = host::leaf_hash(TreeKind::CoinsRoot, all_output_ids[1]);
        let output_inclusion = OutputInclusionProof {
            leaf_index: bob_coin_index,
            depth: 1,
            siblings: vec![sibling],
        };

        // Receiver nav = size_final covering genesis + send.
        let size_final = engine.nflog.size_final(engine.tip_height());
        assert!(size_final >= 2);
        let creating_nav_inclusion =
            host::inclusion_path(send_pos, &engine.nflog_entries).expect("inclusion");
        let creating_nav_consistency =
            host::consistency_proof(send_nav_opening.nav.size, &engine.nflog_entries)
                .expect("consistency");

        let received_auth = ReceivedAuthorization {
            creating_proof: applied_send.proved.proof.clone(),
            output_inclusion,
            creating_prev_ash: send_creating_prev_ash,
            creating_nullifier: NullifierOpening {
                public_key: applied_send.nullifier.0,
                signature_r: applied_send.nullifier.1,
                r_prime: send_sig.transition.r_prime,
            },
            creating_nav_inclusion,
            pos_create: send_pos,
            creating_nav_opening: send_nav_opening,
            creating_nav_consistency,
            history_proof: host::CoinHistTree::new().prove([0u8; 32]),
        };

        let pending_rx = engine
            .begin_receive(ReceiveRequest {
                owner: bob_owner,
                nk: bob_nk,
                op_secret: label_op_secret(b"zkCoins/v1/state-engine/receive-e2e/bob-op_secret"),
                current_pubkey: bob_pk0,
                received_coins: vec![bob_coin.clone()],
                received_auth: vec![received_auth],
                next_pubkey: bob_pk1,
                npk_rand: [0x42u8; 32],
            })
            .expect("begin_receive Bob");
        assert_eq!(pending_rx.mode, TransitionMode::InitialProof);
        assert_eq!(pending_rx.nav_opening.nav.size, size_final);

        let bob_sig = sign_transition(
            bob_secret0,
            bob_public0,
            &pending_rx.proof_data,
            Network::Testnet,
        );
        let nflog_before_rx = engine.nflog.nav().size;
        let applied_rx = engine
            .finalise(pending_rx, bob_sig.transition)
            .expect("finalise receive with genuine creating proof");

        // Assertions requested by the fix brief.
        assert_eq!(
            engine.nflog.nav().size,
            nflog_before_rx,
            "receive finalise must not grow the canonical NfLog"
        );
        let bob = engine.account(&bob_owner).expect("Bob account");
        assert_eq!(bob.state.send_counter, 1);
        assert_eq!(bob.state.current_pubkey, bob_pk1);
        assert_eq!(
            bob.state
                .balances
                .get(&host::digest_to_bytes(&fixture.asset_id)),
            Some(&30)
        );
        assert!(bob.last_nullifier.is_some());
        assert!(
            bob.last_nullifier_pos.is_none(),
            "last_nullifier_pos stays None until scan-fold"
        );
        assert_eq!(applied_rx.nullifier.0, bob_pk0);
        assert!(matches!(
            engine.nflog.lookup(bob_pk0),
            LookupResult::Absent
        ));

        // Scanner places Bob's receive nullifier at a real chain position.
        let rx_scanned = ScannedNullifier::from_survivor(&PublishedNullifier {
            chain_pos: ChainPosition {
                height: 115,
                tx_index: 0,
                vin_index: 0,
                member_index: 0,
            },
            pk: applied_rx.nullifier.0,
            r: applied_rx.nullifier.1,
        });
        let rx_pos = engine
            .append_nullifier(rx_scanned)
            .expect("scan-fold receive nullifier");
        assert_eq!(rx_pos, nflog_before_rx);
        assert_eq!(engine.nflog.nav().size, nflog_before_rx + 1);
    }

    /// Same account + same entry `send_counter` reproduce identical `nav_rand`;
    /// a different counter yields a different one. Red if derivation ignored
    /// the counter or accepted a caller-supplied constant.
    #[test]
    fn nav_rand_derived_deterministically_from_op_secret_and_send_counter() {
        let engine = StateEngine::new(Network::Testnet, 0);
        let req = test_mint_request(1);
        let pending_a = engine.begin_mint(req.clone()).expect("mint a");
        let pending_b = engine.begin_mint(req.clone()).expect("mint b");
        assert_eq!(
            pending_a.nav_opening.nav_rand, pending_b.nav_opening.nav_rand,
            "identical (op_secret, entry send_counter=0) must match"
        );
        let expected = host::derive_nav_rand(req.op_secret.as_bytes(), 0);
        assert_eq!(pending_a.nav_opening.nav_rand, expected);
        assert_ne!(
            pending_a.nav_opening.nav_rand,
            host::derive_nav_rand(req.op_secret.as_bytes(), 1),
            "different send_counter must change nav_rand"
        );
        // OpSecret must never Debug-/Display-print raw bytes — including when
        // nested under a derived-Debug request type.
        let dbg = format!("{:?}", req.op_secret);
        assert_eq!(dbg, "OpSecret([REDACTED])");
        assert_eq!(format!("{}", req.op_secret), "OpSecret([REDACTED])");
        let raw = format!("{:?}", req.op_secret.as_bytes());
        assert!(
            !dbg.contains(&raw),
            "Debug must not embed the raw secret bytes"
        );
        let req_dbg = format!("{req:?}");
        assert!(
            req_dbg.contains("OpSecret([REDACTED])"),
            "MintRequest Debug must redact op_secret; got: {req_dbg}"
        );
        assert!(
            !req_dbg.contains(&raw),
            "MintRequest Debug must not embed raw op_secret bytes"
        );
    }

    /// Missing `op_secret` on a registered account refuses a send — no zero
    /// default, no generated secret. Red if begin_send invents a value.
    #[test]
    fn begin_send_refuses_when_op_secret_missing() {
        let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/state-engine/missing-op/nk").into();
        let (_, _, pk) = normalized_key(deterministic_secret(
            b"zkCoins/v1/state-engine/missing-op/pk0",
        ));
        let owner = Address(host::address(&pk, host::nk_commit(&nk)));
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &pk, &[0x11; 32], 2, 1);
        let coin = Coin {
            identifier: host::coin_identifier(
                host::account_state_hash(
                    &AccountState::new(
                        owner,
                        host::nk_commit(&nk),
                        BTreeMap::new(),
                        pk,
                        0,
                        host::coinhist_empty_root(),
                    )
                    .unwrap(),
                )
                .unwrap(),
                &owner.0,
                asset_id,
                50,
                0,
            ),
            recipient: owner,
            amount: 50,
            asset_id,
        };
        let mut coinhist = CoinHistTree::new();
        let id = host::digest_to_bytes(&coin.identifier);
        coinhist.admit(id).unwrap();
        let mut spendable = BTreeMap::new();
        spendable.insert(
            id,
            TrackedCoin {
                coin: coin.clone(),
                creating_prev_ash: host::ZERO_HASH,
                coin_index: 0,
            },
        );
        let mut balances = BTreeMap::new();
        balances.insert(host::digest_to_bytes(&asset_id), 50);
        let state =
            AccountState::new(owner, host::nk_commit(&nk), balances, pk, 1, coinhist.root())
                .unwrap();
        let mut engine = StateEngine::new(Network::Testnet, 0);
        engine
            .insert_account(
                owner,
                AccountRecord {
                    state,
                    coinhist,
                    nk,
                    op_secret: None, // the defect under test
                    genesis_pubkey: pk,
                    spendable,
                    spent_ids: BTreeSet::new(),
                    // last_proof deliberately None: op_secret is checked first
                    // (must not reach AccountUpdateProof wiring / circuit).
                    last_proof: None,
                    last_nav_opening: None,
                    last_nullifier: None,
                    last_nullifier_pos: None,
                },
            )
            .unwrap();

        let err = engine
            .begin_send(SendRequest {
                owner,
                input_coin_ids: vec![coin.identifier],
                output_templates: vec![CoinTemplate {
                    recipient: Address([0x99; 32]),
                    amount: 10,
                    asset_id,
                }],
                next_pubkey: [0x55; 32],
                npk_rand: [0x22; 32],
            })
            .expect_err("missing op_secret must refuse");
        let msg = format!("{err:#}");
        assert!(
            msg.contains("op_secret missing"),
            "expected missing-op_secret refusal, got: {msg}"
        );
    }

    /// Requirement 10 (engine-level): drop the live engine, rebuild from a
    /// persisted-shaped [`AccountRecord`] that carries the operational
    /// bundle (`op_secret` + `send_counter` history), and reproduce the
    /// prior opening from the **restored** secret — not from the original
    /// request still held in locals. Red if `op_secret` were omitted from
    /// the restored record.
    ///
    /// The DB-backed form (persist → `load_engine_snapshot` → `into_engine`)
    /// lives in `node::v11::tests` so forcing `op_secret: None` on load
    /// actually fails the suite.
    #[test]
    fn fresh_node_with_restored_bundle_reproduces_prior_nav_rand_opening() {
        let engine = StateEngine::new(Network::Testnet, 0);
        let req = test_mint_request(1);
        let pending = engine.begin_mint(req.clone()).expect("mint");
        let issued_nav_rand = pending.nav_opening.nav_rand;
        let entry_counter = pending.witness_wip.prev_account_state.send_counter;
        assert_eq!(entry_counter, 0);
        // Capture only what a durable account row would hold; drop every
        // live handle that still carries the original request secret.
        let owner = req.owner;
        let nk = req.nk;
        let current_pubkey = req.current_pubkey;
        let next_pubkey = req.next_pubkey;
        let name = req.name.clone();
        let persisted_op_secret = req.op_secret;
        drop(engine);
        drop(pending);
        drop(req);

        let cold_state = AccountState::new(
            owner,
            host::nk_commit(&nk),
            BTreeMap::new(),
            current_pubkey,
            entry_counter,
            host::coinhist_empty_root(),
        )
        .expect("restored empty account state");
        let cold = StateEngine::from_persisted(
            Network::Testnet,
            0,
            0,
            0,
            vec![],
            vec![(
                owner,
                AccountRecord {
                    state: cold_state,
                    coinhist: CoinHistTree::new(),
                    nk,
                    op_secret: Some(persisted_op_secret),
                    genesis_pubkey: current_pubkey,
                    spendable: BTreeMap::new(),
                    spent_ids: BTreeSet::new(),
                    last_proof: None,
                    last_nav_opening: None,
                    last_nullifier: None,
                    last_nullifier_pos: None,
                },
            )],
        )
        .expect("reconstruct engine from restored bundle");
        // Do not use `persisted_op_secret` below — only the copy inside `cold`.
        let _ = persisted_op_secret;

        let restored = cold
            .account(&owner)
            .expect("account present after restore")
            .op_secret
            .expect("op_secret must be present on restored record");
        // Equality against the inserted value proves from_persisted kept it;
        // the bytes for derivation come only from `restored`.
        assert_eq!(restored, persisted_op_secret);
        let rebuilt = host::derive_nav_rand(restored.as_bytes(), entry_counter);
        assert_eq!(
            rebuilt, issued_nav_rand,
            "restored bundle must rebuild the opening's nav_rand"
        );

        // Re-issue on a brand-new empty engine using only the secret read
        // back from the reconstructed record (genesis path; the cold
        // account is deliberately not used for AccountUpdateProof).
        let reissued = StateEngine::new(Network::Testnet, 0)
            .begin_mint(MintRequest {
                owner,
                nk,
                op_secret: restored,
                current_pubkey,
                next_pubkey,
                name,
                decimals: 2,
                amount: 100,
                issuance_version: 1,
                cap_total: 0,
                terms_salt: [0; 32],
                npk_rand: [0x22; 32],
            })
            .expect("re-mint from restored secret");
        assert_eq!(
            reissued.nav_opening.nav_rand, issued_nav_rand,
            "fresh engine keyed by restored op_secret must re-issue the same opening"
        );
        assert_ne!(
            host::derive_nav_rand(restored.as_bytes(), 1),
            issued_nav_rand,
            "a different send_counter must not reproduce the prior opening"
        );
    }
}
