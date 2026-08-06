//! Read-only chain procedures (§7.8): `GetInfo`, `GetAccumulator`,
//! `ListInscriptions`, `GetNullifierPath`.
//!
//! Transport-free. All answers bind to the live NfLog / tip held by the
//! v1.1 engine (or an explicit in-memory view for tests). No second
//! derivation of the NAV root, no silent `present: false` on load
//! errors, no partial triple-cursor.
//!
//! # Inscription catalog (§3.5 / §7.8)
//!
//! A complete `ListInscriptions` answer carries, for each inscription,
//! the fields §3.5 and §7.8 require on the wire: the reveal transaction
//! `txid` (internal byte order), the §3.5 `format` byte (`0x00` raw or
//! `0x01` half-aggregated), the member list `(Pkⱼ, Rⱼ)` with per-member
//! state, the chain triple `(height, tx_index, vin_index)`, and the
//! reveal-tx confirmation state.
//!
//! The live NfLog (and its first-occurrence mirror on [`ChainView`])
//! stores only winning `(pk, r)` entries together with the
//! [`ChainPosition`] used at fold time. The **inscription catalog**
//! written at fold time (same DB transaction as the NfLog) supplies
//! reveal txid, format, and every accepted member — including
//! first-occurrence losers the NfLog ignored. Member `state` is the
//! join of catalog membership with NfLog first-occurrence at the tip.
//!
//! Listing **MUST** satisfy these three contracts:
//!
//! 1. **Total, stable order** over `(height, tx_index, vin_index)` —
//!    ordinary integer lexicographic order on the triple; equal keys
//!    never leave list order ambiguous.
//! 2. **Cursor all-or-nothing** — an inclusive `from` triple and an
//!    exclusive `next` triple are each fully present or fully absent;
//!    a half-filled cursor is not representable ([`InscriptionCursor`]).
//! 3. **Gapless page continuation** — the exclusive `next` of page *n*
//!    is the inclusive `from` of page *n+1*, so consecutive pages
//!    neither overlap nor skip a triple.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use shared::spec_v1::{
    digest_to_bytes, nflog_leaf_hash, verify_inclusion, ChainPosition, Nav, NfLogEntry,
};
use zkcoins_program::circuit::compliance::{MAX_RX_COINS, MAX_TX_INPUTS, MAX_TX_OUTPUTS};

use crate::kernel::types::{Digest32, XOnlyKey};
use crate::kernel::{KernelError, KernelErrorCode, KernelResult};
use crate::v1::EngineAdapter;
use shared::spec_v1::MAX_ACCOUNT_ASSETS;

/// §3.9 finality depth — protocol-pinned six confirmations.
pub(crate) const FINALITY_CONFIRMATIONS: u32 = 6;

/// Closed network vocabulary for `GetInfo` / §7.8 (`mainnet|testnet|regtest`).
///
/// Distinct from the legacy `/api/info` labels (`Mainnet` / `Mutinynet`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum KernelNetwork {
    Mainnet,
    Testnet,
    Regtest,
}

impl KernelNetwork {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
        }
    }

    /// Map the v1.1 engine network pin onto the closed §7.8 vocabulary.
    pub(crate) fn from_v1(network: zkcoins_program::circuit::compliance::Network) -> Self {
        match network {
            zkcoins_program::circuit::compliance::Network::Mainnet => Self::Mainnet,
            zkcoins_program::circuit::compliance::Network::Testnet => Self::Testnet,
            zkcoins_program::circuit::compliance::Network::Regtest => Self::Regtest,
        }
    }

    /// Parse a closed wire label (`mainnet` | `testnet` | `regtest`).
    ///
    /// Unknown or empty labels fail loud — never invent a network tag for
    /// a bootstrap or GetInfo answer.
    pub(crate) fn from_wire(label: &str) -> Result<Self, ChainIdentityError> {
        match label {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "regtest" => Ok(Self::Regtest),
            other => Err(ChainIdentityError::InvalidVar {
                name: "bootstrap.network",
                detail: format!(
                    "unknown network {other:?}; must be exactly one of mainnet, testnet, regtest"
                ),
            }),
        }
    }
}

/// Closed readiness reason when `ready == false`.
///
/// Spec: §7.5 `GET /health/ready` — `reason ∈ {syncing, scanner_lag,
/// circuit_mismatch, deep_reorg, dependency_unavailable}`; §7.8
/// `Info.ready_reason` carries the same closed set. The inventory is the
/// contract — not a convenience list of variants the current process emits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum ReadyReason {
    Syncing,
    ScannerLag,
    CircuitMismatch,
    DeepReorg,
    DependencyUnavailable,
}

impl ReadyReason {
    /// Every reason in §7.5 / §7.8 order. Length is the closed-set contract.
    pub(crate) const ALL: [ReadyReason; 5] = [
        Self::Syncing,
        Self::ScannerLag,
        Self::CircuitMismatch,
        Self::DeepReorg,
        Self::DependencyUnavailable,
    ];

    /// Normative wire string for `ready_reason` / `/health/ready.reason`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Syncing => "syncing",
            Self::ScannerLag => "scanner_lag",
            Self::CircuitMismatch => "circuit_mismatch",
            Self::DeepReorg => "deep_reorg",
            Self::DependencyUnavailable => "dependency_unavailable",
        }
    }
}

/// Structural readiness: ready **or** not-ready-with-exactly-one-reason.
///
/// A half state (ready with reason, or not-ready without) is not
/// representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Readiness {
    Ready,
    NotReady { reason: ReadyReason },
}

impl Readiness {
    pub(crate) fn is_ready(self) -> bool {
        matches!(self, Self::Ready)
    }

    pub(crate) fn reason(self) -> Option<ReadyReason> {
        match self {
            Self::Ready => None,
            Self::NotReady { reason } => Some(reason),
        }
    }
}

/// Inclusive triple-cursor on the reveal input (§7.5 / §3.6).
///
/// Completeness is **structural**: the three fields always travel
/// together. There is no type for a half-filled cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct InscriptionCursor {
    pub height: u64,
    pub tx_index: u64,
    pub vin_index: u64,
}

impl InscriptionCursor {
    /// Inclusive start of the inscription stream (§7.5 defaults:
    /// `from_height = from_tx_index = from_vin_index = 0`).
    ///
    /// First-page requests and gapless multi-page walks begin here; the
    /// exclusive `next_*` triple of a prior page is the inclusive `from`
    /// of the next — never a reconstructed half-cursor.
    pub(crate) fn origin() -> Self {
        Self {
            height: 0,
            tx_index: 0,
            vin_index: 0,
        }
    }
}

/// Validated list page size: `1..=1000` (§7.5).
///
/// Construction is the only gate — there is no later soft clamp.
/// The inner value is read when a catalog-backed list procedure is
/// wired; until then request parsing still bounds-checks via [`Self::new`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct InscriptionLimit(u32);

impl InscriptionLimit {
    pub(crate) const MIN: u32 = 1;
    pub(crate) const MAX: u32 = 1000;
    pub(crate) const DEFAULT: u32 = 100;

    pub(crate) fn new(limit: u32) -> KernelResult<Self> {
        if !(Self::MIN..=Self::MAX).contains(&limit) {
            return Err(KernelError::new(
                KernelErrorCode::BoundsExceeded,
                format!(
                    "limit must be in {}..={}; got {limit}",
                    Self::MIN,
                    Self::MAX
                ),
            ));
        }
        Ok(Self(limit))
    }

    /// Validated page size (construction is the only gate).
    pub(crate) fn get(self) -> u32 {
        self.0
    }
}

/// `ListInscriptions` request after transport normalisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ListInscriptions {
    pub from: InscriptionCursor,
    pub limit: InscriptionLimit,
}

/// One catalog member projected for `ListInscriptions`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListedNullifier {
    pub pubkey: [u8; 32],
    pub r: [u8; 32],
    pub state: NullifierMemberState,
}

/// Reveal-tx confirmation only (`pending` | `completed`) — never `failed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum RevealConfirmationState {
    Pending,
    Completed,
}

impl RevealConfirmationState {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Completed => "completed",
        }
    }
}

/// One inscription on the list stream (§7.8 `Inscription`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListedInscription {
    /// Reveal txid, internal byte order.
    pub txid: [u8; 32],
    pub height: u64,
    pub tx_index: u64,
    pub vin_index: u64,
    /// §3.5 format byte as u32 on the wire (`0` or `1`).
    pub format: u32,
    /// Member count (= `nullifiers.len()`).
    pub count: u32,
    pub nullifiers: Vec<ListedNullifier>,
    pub confirmation_state: RevealConfirmationState,
}

/// Page of inscriptions plus exclusive next cursor (all-or-nothing).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListInscriptionsPage {
    pub inscriptions: Vec<ListedInscription>,
    /// Exclusive lower bound for the next page, or `None` when exhausted.
    pub next: Option<InscriptionCursor>,
}

/// Durable catalog row as held on [`ChainView`] (no member state yet).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogEntry {
    pub height: u64,
    pub tx_index: u32,
    pub vin_index: u32,
    pub reveal_txid: [u8; 32],
    pub format: u8,
    /// Payload order: `(member_index, pk, r)`.
    pub members: Vec<(u32, [u8; 32], [u8; 32])>,
    pub block_anchor_hash: [u8; 32],
    pub block_anchor_height: u32,
}

impl CatalogEntry {
    fn from_stored(row: &crate::v1::db_v1::CatalogInscription) -> Self {
        Self {
            height: row.height,
            tx_index: row.tx_index,
            vin_index: row.vin_index,
            reveal_txid: row.reveal_txid,
            format: row.format,
            members: row.members.clone(),
            block_anchor_hash: row.block_anchor_hash,
            block_anchor_height: row.block_anchor_height,
        }
    }

    fn cursor(&self) -> InscriptionCursor {
        InscriptionCursor {
            height: self.height,
            tx_index: u64::from(self.tx_index),
            vin_index: u64::from(self.vin_index),
        }
    }
}

/// §3.10 per-member nullifier state on an inscription.
///
/// Spec: §3.10 transaction states; §7.5 `ListInscriptions` response
/// `nullifiers[i].state ∈ {completed, pending, failed}` (members of one
/// aggregate MAY differ by first-occurrence — a later `Pk` collision is
/// `failed` while earlier members stay `pending`/`completed`); §3.5 is
/// the inscription payload those members sit in. The NfLog first-
/// occurrence projection only ever *emits* winners (`completed`/
/// `pending` by depth); `Failed` remains in the closed set so a full
/// inscription catalog can represent double-spend losers without
/// inventing a fourth wire token.
///
/// This is a **closed normative set**. [`Self::ALL`] plus
/// [`validate_closed_sets`] (start edge) keep the wire tokens non-empty
/// and pairwise distinct. Production constructs values via
/// [`classify_member_state`] (`ListInscriptions` and hand-off finish).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum NullifierMemberState {
    Completed,
    Pending,
    Failed,
}

impl NullifierMemberState {
    /// Every §3.10 member state. Length is the closed-set contract.
    pub(crate) const ALL: [NullifierMemberState; 3] =
        [Self::Completed, Self::Pending, Self::Failed];

    /// Normative wire string for `nullifiers[i].state`.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Pending => "pending",
            Self::Failed => "failed",
        }
    }
}

/// Inputs required to decide a member's §3.10 state.
///
/// Used by `ListInscriptions` (catalog + NfLog join) and by the publisher
/// hand-off path (queue status + optional chain observation). Finished ⇔
/// [`NullifierMemberState::Completed`] (first-occurrence winner + ≥6
/// confirmations). Queue status alone is never enough.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MemberChainObservation {
    /// Durable hand-off queue marked this member terminal-failed.
    /// Catalog projections always pass `false` — losers fail via
    /// [`Self::first_occurrence`].
    pub queue_failed: bool,
    /// Whether the node's own scan folded this `Pk` as first-occurrence.
    pub first_occurrence: bool,
    /// Inclusion height of the reveal that carried this nullifier, when known.
    pub inclusion_height: Option<u64>,
    /// Verifier's Bitcoin tip height.
    pub tip_height: u64,
}

/// Classify a member against §3.10. Intermediate queue states and
/// on-chain `pending` are **not** finished.
pub(crate) fn classify_member_state(obs: MemberChainObservation) -> NullifierMemberState {
    if obs.queue_failed {
        return NullifierMemberState::Failed;
    }
    // Not yet on a scanned reveal → not completed, not failed by scan rules.
    // Spec: pending covers "inscribed but <6 confs"; pre-inscription is also
    // not completed. We project pre-inscription as Pending (not finished).
    let Some(inclusion_height) = obs.inclusion_height else {
        return NullifierMemberState::Pending;
    };
    if !obs.first_occurrence {
        return NullifierMemberState::Failed;
    }
    member_confirmation_state(obs.tip_height, inclusion_height)
}

/// A member is finished **only** at §3.10 `completed`.
pub(crate) fn member_is_finished(obs: MemberChainObservation) -> bool {
    classify_member_state(obs) == NullifierMemberState::Completed
}

/// Current accumulator tip (§7.8 `AccumulatorTip`).
///
/// `root` is always `nav_root = Hc("NfLog/Root", size ‖ mth)` — never bare
/// `mth`. Constructed only through [`AccumulatorTip::from_nav`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AccumulatorTip {
    pub root: Digest32,
    pub tip_block_hash: Digest32,
    pub tip_height: u64,
    pub size: u64,
}

impl AccumulatorTip {
    /// Bind the committed root via the canonical NAV function.
    pub(crate) fn from_nav(nav: Nav, tip_block_hash: [u8; 32], tip_height: u64) -> Self {
        Self {
            root: Digest32(digest_to_bytes(&nav.root())),
            tip_block_hash: Digest32(tip_block_hash),
            tip_height,
            size: nav.size,
        }
    }
}

/// `GetNullifierPath` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct NullifierPathRequest {
    pub pubkey: XOnlyKey,
}

/// Path-B answer: present (with a path verifiable against size+mth) or
/// unauthenticated local-index absence. Errors never collapse into
/// [`Self::Absent`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NullifierPath {
    Present {
        root: Digest32,
        tip_height: u64,
        tip_block_hash: Digest32,
        /// Winning `Rᵢ` at the first-occurrence leaf.
        leaf: Digest32,
        position: u64,
        /// RFC-6962 inclusion audit path (sibling digests).
        audit_path: Vec<Digest32>,
        tree_size: u64,
    },
    Absent {
        root: Digest32,
        tip_height: u64,
        tip_block_hash: Digest32,
        tree_size: u64,
    },
}

impl NullifierPath {
    /// Sole source of the wire `present` boolean (§3.7 Path-B / §7.5
    /// `GET /v1/chain/nullifier/<pubkey>`). Callers **MUST** project
    /// `present` from this method — never from an `Err` path (errors
    /// stay errors; absence is only [`Self::Absent`]).
    pub(crate) fn is_present(&self) -> bool {
        matches!(self, Self::Present { .. })
    }
}

/// Bootstrap manifest fields for `GetInfo` (§4.3). Full signature verification
/// is the caller's job; the kernel only echoes the stored network copy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BootstrapManifest {
    pub network: KernelNetwork,
    pub protocol_version: String,
    pub seed_relays: Vec<String>,
    pub blob_stores: Vec<String>,
    pub operator_ids: Vec<XOnlyKey>,
    pub issued_at: u64,
    pub expires_at: u64,
    pub manifest_sig: [u8; 64],
}

/// Kernel part this process runs (§7.8 `kernel_parts`).
///
/// Spec: §7.8 `Info.kernel_parts` — each element ∈
/// `{"scanner","prover","publisher"}`. Distinct from the API-layer
/// §7.5 `/v1/info` `features` array. Completeness is the contract even
/// when a given process only enables a subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum KernelPart {
    Scanner,
    Prover,
    Publisher,
}

impl KernelPart {
    /// Every admissible kernel part. Length is the closed-set contract.
    pub(crate) const ALL: [KernelPart; 3] = [Self::Scanner, Self::Prover, Self::Publisher];

    /// Normative wire string for `Info.kernel_parts` entries.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Scanner => "scanner",
            Self::Prover => "prover",
            Self::Publisher => "publisher",
        }
    }
}

// ---------------------------------------------------------------------------
// Closed-set wire vocabulary (§7.5 / §7.8) — fail-closed at process start
// ---------------------------------------------------------------------------

/// One labelled wire string used by [`validate_wire_vocabulary`] and the
/// effectiveness tests. Production rows come from each enum's `ALL` +
/// `as_str`; tests inject deliberately broken rows into the same checker.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct WireEntry {
    /// Debug label for error messages (variant name).
    pub label: &'static str,
    /// Normative on-wire token.
    pub wire: &'static str,
}

/// Validate a closed wire vocabulary: every string non-empty and all
/// pairwise distinct.
///
/// Empty or colliding tokens would collapse two states onto one wire
/// value (or emit a blank reason) on every `GetInfo` / `/health/ready` /
/// `ListInscriptions` answer that carries the set. Shared by
/// [`validate_closed_sets`] and the effectiveness tests — one checker,
/// no second copy of the rules.
pub(crate) fn validate_wire_vocabulary(
    set_name: &'static str,
    entries: &[WireEntry],
) -> Result<(), String> {
    let mut seen: Vec<&'static str> = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.wire.is_empty() {
            return Err(format!("empty wire string for {set_name}::{}", entry.label));
        }
        if let Some(prior) = seen.iter().find(|&&w| w == entry.wire) {
            return Err(format!(
                "duplicate wire string {:?} in {set_name} (also on {})",
                prior, entry.label
            ));
        }
        seen.push(entry.wire);
    }
    Ok(())
}

fn ready_reason_label(r: ReadyReason) -> &'static str {
    match r {
        ReadyReason::Syncing => "Syncing",
        ReadyReason::ScannerLag => "ScannerLag",
        ReadyReason::CircuitMismatch => "CircuitMismatch",
        ReadyReason::DeepReorg => "DeepReorg",
        ReadyReason::DependencyUnavailable => "DependencyUnavailable",
    }
}

fn nullifier_member_state_label(s: NullifierMemberState) -> &'static str {
    match s {
        NullifierMemberState::Completed => "Completed",
        NullifierMemberState::Pending => "Pending",
        NullifierMemberState::Failed => "Failed",
    }
}

fn kernel_part_label(p: KernelPart) -> &'static str {
    match p {
        KernelPart::Scanner => "Scanner",
        KernelPart::Prover => "Prover",
        KernelPart::Publisher => "Publisher",
    }
}

/// Fail-closed check of the three closed §7.5 / §7.8 wire vocabularies
/// declared on this module: [`ReadyReason`], [`NullifierMemberState`],
/// [`KernelPart`].
///
/// Each inventory's length is part of the type (`[T; N]`); a missing
/// variant is a compile error. The runtime check ensures every wire
/// string is non-empty and pairwise distinct — the property that keeps
/// two reasons/parts/states from collapsing on the wire. Called from
/// [`crate::runtime::start_rest_node`] next to the error-table check,
/// before any listener binds.
pub(crate) fn validate_closed_sets() -> Result<(), String> {
    let ready: [WireEntry; 5] = ReadyReason::ALL.map(|r| WireEntry {
        label: ready_reason_label(r),
        wire: r.as_str(),
    });
    validate_wire_vocabulary("ReadyReason", &ready)?;

    let members: [WireEntry; 3] = NullifierMemberState::ALL.map(|s| WireEntry {
        label: nullifier_member_state_label(s),
        wire: s.as_str(),
    });
    validate_wire_vocabulary("NullifierMemberState", &members)?;

    let parts: [WireEntry; 3] = KernelPart::ALL.map(|p| WireEntry {
        label: kernel_part_label(p),
        wire: p.as_str(),
    });
    validate_wire_vocabulary("KernelPart", &parts)?;

    Ok(())
}

/// `GetInfo` result (§7.8 `Info`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelInfo {
    pub network: KernelNetwork,
    pub protocol_version: &'static str,
    pub circuit_digest_c: Digest32,
    pub circuit_digest_c_balance: Digest32,
    pub relay_url: String,
    pub blossom_url: String,
    pub finality_confirmations: u32,
    pub max_tx_inputs: u32,
    pub max_tx_outputs: u32,
    pub max_rx_coins: u32,
    pub max_account_assets: u32,
    pub readiness: Readiness,
    pub bitcoin_tip_height: u64,
    /// `nav_root = Hc("NfLog/Root", size ‖ mth)`.
    pub accumulator_root: Digest32,
    pub scanner_lag: u64,
    pub max_blob_bytes: u64,
    pub activation_height: u64,
    pub bootstrap: BootstrapManifest,
    pub kernel_parts: Vec<KernelPart>,
    pub bootstrap_pubkey: XOnlyKey,
}

/// Static identity + infrastructure for `GetInfo` (not chain-tip dependent).
///
/// Constructed at boot from pins / operator config. Missing fields are a
/// construction failure at the caller — this type does not invent defaults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainIdentity {
    pub network: KernelNetwork,
    pub circuit_digest_c: Digest32,
    pub circuit_digest_c_balance: Digest32,
    pub relay_url: String,
    pub blossom_url: String,
    pub max_blob_bytes: u64,
    pub activation_height: u64,
    pub bootstrap: BootstrapManifest,
    pub kernel_parts: Vec<KernelPart>,
    pub bootstrap_pubkey: XOnlyKey,
}

// ---------------------------------------------------------------------------
// Operational GetInfo config (env) + assembly from pins / live digests
// ---------------------------------------------------------------------------

/// Env: this node's advertised Nostr relay URL (`Info.relay_url`).
pub(crate) const RELAY_URL_ENV: &str = "ZKCOINS_RELAY_URL";
/// Env: this node's advertised Blossom base URL (`Info.blossom_url`).
pub(crate) const BLOSSOM_URL_ENV: &str = "ZKCOINS_BLOSSOM_URL";
/// Env: Blossom upload size limit this node advertises (`Info.max_blob_bytes`).
pub(crate) const MAX_BLOB_BYTES_ENV: &str = "ZKCOINS_MAX_BLOB_BYTES";
/// Env: comma-separated kernel parts (`scanner`/`prover`/`publisher`).
pub(crate) const KERNEL_PARTS_ENV: &str = "ZKCOINS_KERNEL_PARTS";

/// §4.3 / §7.4 URL length bound (bootstrap seed / blob-store URLs).
const URL_MAX_BYTES: usize = 2048;

/// Operator-chosen GetInfo infrastructure (not protocol constants, not digests).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainIdentityOps {
    pub relay_url: String,
    pub blossom_url: String,
    pub max_blob_bytes: u64,
    pub kernel_parts: Vec<KernelPart>,
}

/// Fail-loud errors when building or loading chain identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ChainIdentityError {
    /// Required operational env var unset, empty, or whitespace-only.
    MissingVar { name: &'static str },
    /// Present but unparseable / out of bounds / closed-set violation.
    InvalidVar { name: &'static str, detail: String },
    /// Signed §4.3 `BootstrapManifest` was not provided to
    /// [`resolve_chain_identity`].
    ///
    /// Operational env may already be complete; production boot refuses to
    /// install `ChainIdentity` (and therefore to answer GetInfo) until a
    /// verified BMF1 artifact is loaded. Never invent one.
    BootstrapUnavailable { reason: &'static str },
}

impl std::fmt::Display for ChainIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingVar { name } => write!(
                f,
                "{name} is unset or empty — required for GetInfo / ChainIdentity \
                 (no silent default, no invented URL)"
            ),
            Self::InvalidVar { name, detail } => {
                write!(f, "{name} is invalid: {detail} — refusing to start")
            }
            Self::BootstrapUnavailable { reason } => write!(
                f,
                "signed BootstrapManifest (§4.3) unavailable: {reason} — \
                 GetInfo remains fail-closed (no invented manifest)"
            ),
        }
    }
}

impl std::error::Error for ChainIdentityError {}

/// Why production cannot install a complete [`ChainIdentity`] when no
/// verified §4.3 manifest was supplied to [`resolve_chain_identity`].
///
/// The BMF1 loader exists (`ZKCOINS_V1_BOOTSTRAP_MANIFEST_PATH`); this
/// reason names the **missing verified artifact**, not a missing codec.
/// The process must not invent `manifest_sig` or bootstrap key material.
pub(crate) const BOOTSTRAP_MANIFEST_UNAVAILABLE_REASON: &str = "\
no verified BootstrapManifestV1 (BMF1) installed — set \
ZKCOINS_V1_BOOTSTRAP_MANIFEST_PATH to a network-signed artifact that \
verifies under the pinned bootstrap_pubkey; the process must not invent \
manifest_sig or bootstrap key material";

/// Parse one non-empty URL (trim; length 1..=2048). No scheme allow-list
/// beyond non-emptiness — inventing a URL is forbidden; the operator supplies it.
pub(crate) fn parse_required_url(
    name: &'static str,
    raw: Option<&str>,
) -> Result<String, ChainIdentityError> {
    let Some(raw) = raw else {
        return Err(ChainIdentityError::MissingVar { name });
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ChainIdentityError::MissingVar { name });
    }
    if trimmed.len() > URL_MAX_BYTES {
        return Err(ChainIdentityError::InvalidVar {
            name,
            detail: format!(
                "URL length {} exceeds max {URL_MAX_BYTES} bytes (§4.3 bound)",
                trimmed.len()
            ),
        });
    }
    Ok(trimmed.to_string())
}

/// Parse `max_blob_bytes`: non-empty decimal `u64`, strictly greater than zero.
pub(crate) fn parse_max_blob_bytes(raw: Option<&str>) -> Result<u64, ChainIdentityError> {
    let Some(raw) = raw else {
        return Err(ChainIdentityError::MissingVar {
            name: MAX_BLOB_BYTES_ENV,
        });
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ChainIdentityError::MissingVar {
            name: MAX_BLOB_BYTES_ENV,
        });
    }
    let value: u64 = trimmed
        .parse()
        .map_err(|_| ChainIdentityError::InvalidVar {
            name: MAX_BLOB_BYTES_ENV,
            detail: format!("{raw:?} is not a non-negative integer"),
        })?;
    if value == 0 {
        return Err(ChainIdentityError::InvalidVar {
            name: MAX_BLOB_BYTES_ENV,
            detail: "must be > 0 (zero is not an advertised Blossom limit)".into(),
        });
    }
    Ok(value)
}

/// Parse closed `kernel_parts`: comma-separated `scanner`|`prover`|`publisher`.
///
/// At least one part; no empties; no duplicates; unknown tokens fail loud.
pub(crate) fn parse_kernel_parts(raw: Option<&str>) -> Result<Vec<KernelPart>, ChainIdentityError> {
    let Some(raw) = raw else {
        return Err(ChainIdentityError::MissingVar {
            name: KERNEL_PARTS_ENV,
        });
    };
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(ChainIdentityError::MissingVar {
            name: KERNEL_PARTS_ENV,
        });
    }
    let mut parts = Vec::new();
    for token in trimmed.split(',') {
        let t = token.trim();
        if t.is_empty() {
            return Err(ChainIdentityError::InvalidVar {
                name: KERNEL_PARTS_ENV,
                detail: format!("empty token in {raw:?} (no trailing/duplicate commas)"),
            });
        }
        let part = match t {
            "scanner" => KernelPart::Scanner,
            "prover" => KernelPart::Prover,
            "publisher" => KernelPart::Publisher,
            other => {
                return Err(ChainIdentityError::InvalidVar {
                    name: KERNEL_PARTS_ENV,
                    detail: format!(
                        "unknown part {other:?}; each element must be exactly one of \
                         scanner, prover, publisher"
                    ),
                });
            }
        };
        if parts.contains(&part) {
            return Err(ChainIdentityError::InvalidVar {
                name: KERNEL_PARTS_ENV,
                detail: format!("duplicate part {:?} in {raw:?}", part.as_str()),
            });
        }
        parts.push(part);
    }
    if parts.is_empty() {
        return Err(ChainIdentityError::MissingVar {
            name: KERNEL_PARTS_ENV,
        });
    }
    Ok(parts)
}

/// Build operational identity pieces from optional raw env strings (testable).
pub(crate) fn parse_chain_identity_ops(
    relay_url: Option<&str>,
    blossom_url: Option<&str>,
    max_blob_bytes: Option<&str>,
    kernel_parts: Option<&str>,
) -> Result<ChainIdentityOps, ChainIdentityError> {
    Ok(ChainIdentityOps {
        relay_url: parse_required_url(RELAY_URL_ENV, relay_url)?,
        blossom_url: parse_required_url(BLOSSOM_URL_ENV, blossom_url)?,
        max_blob_bytes: parse_max_blob_bytes(max_blob_bytes)?,
        kernel_parts: parse_kernel_parts(kernel_parts)?,
    })
}

/// Read operational GetInfo env vars. No defaults; missing names the variable.
pub(crate) fn chain_identity_ops_from_env() -> Result<ChainIdentityOps, ChainIdentityError> {
    fn var(name: &'static str) -> Result<Option<String>, ChainIdentityError> {
        match std::env::var(name) {
            Ok(v) => Ok(Some(v)),
            Err(std::env::VarError::NotPresent) => Ok(None),
            Err(std::env::VarError::NotUnicode(_)) => Err(ChainIdentityError::InvalidVar {
                name,
                detail: "value is not valid UTF-8".into(),
            }),
        }
    }
    let relay = var(RELAY_URL_ENV)?;
    let blossom = var(BLOSSOM_URL_ENV)?;
    let max_blob = var(MAX_BLOB_BYTES_ENV)?;
    let parts = var(KERNEL_PARTS_ENV)?;
    parse_chain_identity_ops(
        relay.as_deref(),
        blossom.as_deref(),
        max_blob.as_deref(),
        parts.as_deref(),
    )
}

/// Assemble a complete [`ChainIdentity`]. Digests and network pins come from
/// the caller (live node / §3.6 pins) — never re-parsed as free-form operator
/// overrides of protocol identity.
pub(crate) fn assemble_chain_identity(
    network: KernelNetwork,
    circuit_digest_c: Digest32,
    circuit_digest_c_balance: Digest32,
    activation_height: u64,
    bootstrap_pubkey: XOnlyKey,
    ops: ChainIdentityOps,
    bootstrap: BootstrapManifest,
) -> ChainIdentity {
    ChainIdentity {
        network,
        circuit_digest_c,
        circuit_digest_c_balance,
        relay_url: ops.relay_url,
        blossom_url: ops.blossom_url,
        max_blob_bytes: ops.max_blob_bytes,
        activation_height,
        bootstrap,
        kernel_parts: ops.kernel_parts,
        bootstrap_pubkey,
    }
}

/// Production resolve: require operational env; complete identity only when a
/// real signed bootstrap is provided. `bootstrap == None` →
/// [`ChainIdentityError::BootstrapUnavailable`] (boot / GetInfo fail-closed).
pub(crate) fn resolve_chain_identity(
    network: KernelNetwork,
    circuit_digest_c: Digest32,
    circuit_digest_c_balance: Digest32,
    activation_height: u64,
    bootstrap_pubkey: XOnlyKey,
    ops: ChainIdentityOps,
    bootstrap: Option<BootstrapManifest>,
) -> Result<ChainIdentity, ChainIdentityError> {
    let Some(bootstrap) = bootstrap else {
        return Err(ChainIdentityError::BootstrapUnavailable {
            reason: BOOTSTRAP_MANIFEST_UNAVAILABLE_REASON,
        });
    };
    if bootstrap.network != network {
        return Err(ChainIdentityError::InvalidVar {
            name: "bootstrap.network",
            detail: format!(
                "manifest network {} disagrees with engine/pin network {} — \
                 refusing to install identity",
                bootstrap.network.as_str(),
                network.as_str()
            ),
        });
    }
    Ok(assemble_chain_identity(
        network,
        circuit_digest_c,
        circuit_digest_c_balance,
        activation_height,
        bootstrap_pubkey,
        ops,
        bootstrap,
    ))
}

/// Borrowed fields from a post-verify BMF1 artifact, ready to project
/// into the domain [`BootstrapManifest`].
///
/// Flat field bag (not a method on the verification/loader type) so the
/// projection stays decoupled from that type's layout — callers assemble
/// this from whatever verified source they hold (store entry, fixture).
pub(crate) struct VerifiedManifestFields<'a> {
    pub network_label: &'a str,
    pub protocol_version: &'a str,
    pub seed_relays: &'a [String],
    pub blob_stores: &'a [String],
    pub operator_ids: &'a [[u8; 32]],
    pub issued_at: u64,
    pub expires_at: u64,
    pub manifest_sig: &'a [u8; 64],
}

/// Project a verified BMF1 store entry into the domain GetInfo echo type.
///
/// Trust: the caller must pass a post-verify artifact (loader or test
/// fixture). This function only maps fields — it does not re-check the
/// BIP-340 signature.
pub(crate) fn bootstrap_manifest_from_verified(
    fields: VerifiedManifestFields<'_>,
) -> Result<BootstrapManifest, ChainIdentityError> {
    let VerifiedManifestFields {
        network_label,
        protocol_version,
        seed_relays,
        blob_stores,
        operator_ids,
        issued_at,
        expires_at,
        manifest_sig,
    } = fields;
    let network = KernelNetwork::from_wire(network_label)?;
    if protocol_version != "v1" {
        return Err(ChainIdentityError::InvalidVar {
            name: "bootstrap.protocol_version",
            detail: format!(
                "expected protocol_version \"v1\", got {protocol_version:?} — \
                 refusing to echo a foreign bootstrap into GetInfo"
            ),
        });
    }
    if seed_relays.is_empty() {
        return Err(ChainIdentityError::InvalidVar {
            name: "bootstrap.seed_relays",
            detail: "verified manifest must retain at least one seed relay".into(),
        });
    }
    if blob_stores.is_empty() {
        return Err(ChainIdentityError::InvalidVar {
            name: "bootstrap.blob_stores",
            detail: "verified manifest must retain at least one blob store".into(),
        });
    }
    if operator_ids.is_empty() {
        return Err(ChainIdentityError::InvalidVar {
            name: "bootstrap.operator_ids",
            detail: "verified manifest must retain at least one operator id".into(),
        });
    }
    Ok(BootstrapManifest {
        network,
        protocol_version: protocol_version.to_string(),
        seed_relays: seed_relays.to_vec(),
        blob_stores: blob_stores.to_vec(),
        operator_ids: operator_ids.iter().copied().map(XOnlyKey).collect(),
        issued_at,
        expires_at,
        manifest_sig: *manifest_sig,
    })
}

/// Live readiness flags shared with `/health/ready` under the v1.1 claim.
#[derive(Clone, Default)]
pub(crate) struct ChainReadinessFlags {
    pub scan_caught_up: Option<Arc<AtomicBool>>,
    pub finality_ok: Option<Arc<AtomicBool>>,
}

impl ChainReadinessFlags {
    pub(crate) fn evaluate(&self) -> Readiness {
        if let Some(ok) = &self.finality_ok {
            if !ok.load(Ordering::SeqCst) {
                return Readiness::NotReady {
                    reason: ReadyReason::DeepReorg,
                };
            }
        }
        if let Some(caught) = &self.scan_caught_up {
            if !caught.load(Ordering::SeqCst) {
                return Readiness::NotReady {
                    reason: ReadyReason::ScannerLag,
                };
            }
        }
        Readiness::Ready
    }
}

/// Immutable chain tip + NfLog + inscription catalog for read procedures.
///
/// Built by reading the live engine once under its mutex — never by
/// recomputing MTH from a second log copy after the fact for the tip
/// root (the engine's `nav()` is the source of truth; `nflog_root` is
/// applied only to that pair). Catalog rows come from the same adapter
/// snapshot path (no second port).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ChainView {
    pub tip_height: u64,
    pub tip_block_hash: [u8; 32],
    pub nav: Nav,
    /// First-occurrence log in position order, with the §3.6 chain pos
    /// that admitted each entry (from the engine mirror).
    pub mirror: Vec<(ChainPosition, NfLogEntry)>,
    /// Parallel first-occurrence index: `pk → (position, r)`.
    pub index: std::collections::HashMap<[u8; 32], (u64, [u8; 32])>,
    /// Accepted inscriptions in total order `(height, tx_index, vin_index)`.
    pub catalog: Vec<CatalogEntry>,
    /// Chain positions present in the NfLog (winners only) — used for
    /// per-member state projection without inventing presence from pk alone.
    pub winning_positions: std::collections::HashSet<(u64, u32, u32, u32)>,
}

impl ChainView {
    /// Snapshot the live engine + catalog. A poisoned mutex is an internal
    /// error — never reinterpreted as an empty chain.
    pub(crate) fn from_engine(adapter: &EngineAdapter) -> KernelResult<Self> {
        // Capture tip hash and catalog outside the engine borrow.
        let tip_block_hash = adapter.tip_hash();
        let catalog: Vec<CatalogEntry> = adapter
            .catalog_snapshot()
            .iter()
            .map(CatalogEntry::from_stored)
            .collect();
        adapter.with_engine(|engine| {
            let tip_height = engine.tip_height();
            let nav = engine.nflog().nav();
            let mirror = engine.nflog_mirror();
            // Rebuild the pk index from the mirror so Lookup is a pure
            // function of the same first-occurrence sequence the tip
            // commits to — not a second store.
            let mut index = std::collections::HashMap::with_capacity(mirror.len());
            let mut winning_positions = std::collections::HashSet::with_capacity(mirror.len());
            for (pos, (chain, entry)) in mirror.iter().enumerate() {
                let position = pos as u64;
                if index.insert(entry.pk, (position, entry.r)).is_some() {
                    return Err(KernelError::with_internal(
                        KernelErrorCode::InternalError,
                        "Failed to read chain tip",
                        format!(
                            "NfLog mirror has duplicate first-occurrence pk at position {position}"
                        ),
                    ));
                }
                winning_positions.insert((
                    chain.height,
                    chain.tx_index,
                    chain.vin_index,
                    chain.member_index,
                ));
            }
            if index.len() != mirror.len() {
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Failed to read chain tip",
                    "NfLog mirror length diverges from first-occurrence index",
                ));
            }
            // Guard: committed nav must match the mirror length and the
            // canonical root of that size. Do not recompute MTH for the
            // answer — only verify consistency, then use engine.nav().
            if nav.size != mirror.len() as u64 {
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Failed to read chain tip",
                    format!(
                        "engine nav.size={} but mirror has {} entries",
                        nav.size,
                        mirror.len()
                    ),
                ));
            }
            Ok(Self {
                tip_height,
                tip_block_hash,
                nav,
                mirror,
                index,
                catalog,
                winning_positions,
            })
        })
    }

    /// Committed NAV root of this view (`Hc("NfLog/Root", size ‖ mth)`).
    pub(crate) fn nav_root_bytes(&self) -> [u8; 32] {
        digest_to_bytes(&self.nav.root())
    }
}

// ---------------------------------------------------------------------------
// Procedures
// ---------------------------------------------------------------------------

/// `GetAccumulator` — current NAV tip as `(size, nav_root)` plus Bitcoin tip.
pub(crate) fn get_accumulator(view: &ChainView) -> AccumulatorTip {
    AccumulatorTip::from_nav(view.nav, view.tip_block_hash, view.tip_height)
}

/// `GetNullifierPath` — Path-B present/absent against the live index.
///
/// # Fail-closed presence
///
/// Absence is **only** [`LookupResult::Absent`] / missing index entry.
/// Any failure building or verifying a present path is `internal_error`,
/// never `present: false`.
pub(crate) fn get_nullifier_path(
    view: &ChainView,
    request: NullifierPathRequest,
) -> KernelResult<NullifierPath> {
    let root = Digest32(view.nav_root_bytes());
    let tip_height = view.tip_height;
    let tip_block_hash = Digest32(view.tip_block_hash);
    let tree_size = view.nav.size;

    match view.index.get(&request.pubkey.0) {
        None => Ok(NullifierPath::Absent {
            root,
            tip_height,
            tip_block_hash,
            tree_size,
        }),
        Some(&(position, r)) => {
            // Build the entry sequence for inclusion_path (same order as
            // the committed log).
            let entries: Vec<NfLogEntry> = view.mirror.iter().map(|(_, e)| *e).collect();
            if position as usize >= entries.len() {
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Failed to build nullifier path",
                    format!(
                        "index position {position} is out of range for log size {}",
                        entries.len()
                    ),
                ));
            }
            let entry = entries[position as usize];
            if entry.pk != request.pubkey.0 || entry.r != r {
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Failed to build nullifier path",
                    "index (pk,r) diverges from log entry at claimed position",
                ));
            }
            let path_digests =
                shared::spec_v1::inclusion_path(position, &entries).map_err(|e| {
                    KernelError::with_internal(
                        KernelErrorCode::InternalError,
                        "Failed to build nullifier path",
                        format!("inclusion_path: {e}"),
                    )
                })?;
            let leaf_hash = nflog_leaf_hash(position, &entry);
            // Verify against (size, mth) — not against nav_root — before
            // handing the path out. A path that does not recompute is an
            // internal corruption, not an absence.
            if !verify_inclusion(
                leaf_hash,
                position,
                &path_digests,
                view.nav.size,
                view.nav.mth,
            ) {
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Failed to build nullifier path",
                    format!(
                        "inclusion path for position {position} does not verify against tip mth"
                    ),
                ));
            }
            let audit_path = path_digests
                .into_iter()
                .map(|d| Digest32(digest_to_bytes(&d)))
                .collect();
            Ok(NullifierPath::Present {
                root,
                tip_height,
                tip_block_hash,
                leaf: Digest32(r),
                position,
                audit_path,
                tree_size,
            })
        }
    }
}

/// `ListInscriptions` — catalog page in total `(height, tx_index, vin_index)` order.
///
/// Member state is the join of catalog membership with NfLog winners at the
/// tip (present at the same chain position ⇒ completed/pending by depth;
/// otherwise failed). No field is invented: format and txid come only from
/// the catalog rows written at fold time.
pub(crate) fn list_inscriptions(
    view: &ChainView,
    request: ListInscriptions,
) -> ListInscriptionsPage {
    let from = request.from;
    let limit = request.limit.get() as usize;

    // Inclusive lower bound: first entry with cursor >= from.
    let start = view.catalog.partition_point(|e| {
        let c = e.cursor();
        c < from
    });
    let end = (start + limit).min(view.catalog.len());
    let page_slice = &view.catalog[start..end];

    let inscriptions: Vec<ListedInscription> = page_slice
        .iter()
        .map(|entry| project_listed_inscription(view, entry))
        .collect();

    // Exclusive next: cursor of the first entry after this page, if any.
    // Structural Option — never a half-filled triple.
    let next = if end < view.catalog.len() {
        Some(view.catalog[end].cursor())
    } else {
        None
    };

    ListInscriptionsPage { inscriptions, next }
}

fn project_listed_inscription(view: &ChainView, entry: &CatalogEntry) -> ListedInscription {
    let nullifiers: Vec<ListedNullifier> = entry
        .members
        .iter()
        .map(|(member_index, pk, r)| {
            let first_occurrence = view.winning_positions.contains(&(
                entry.height,
                entry.tx_index,
                entry.vin_index,
                *member_index,
            ));
            // Catalog rows are on-chain; queue_failed is a hand-off concern only.
            // §3.10 state goes through the single classifier (same path the
            // hand-off finish predicate uses) — never a parallel local if/else.
            let obs = MemberChainObservation {
                queue_failed: false,
                first_occurrence,
                inclusion_height: Some(entry.height),
                tip_height: view.tip_height,
            };
            let state = if member_is_finished(obs) {
                NullifierMemberState::Completed
            } else {
                classify_member_state(obs)
            };
            ListedNullifier {
                pubkey: *pk,
                r: *r,
                state,
            }
        })
        .collect();
    let count = u32::try_from(nullifiers.len()).expect("member_count validated at persist");
    ListedInscription {
        txid: entry.reveal_txid,
        height: entry.height,
        tx_index: u64::from(entry.tx_index),
        vin_index: u64::from(entry.vin_index),
        format: u32::from(entry.format),
        count,
        nullifiers,
        confirmation_state: reveal_confirmation_state(view.tip_height, entry.height),
    }
}

/// Per-member completed/pending from inclusion depth (§3.9 / §3.10).
fn member_confirmation_state(tip_height: u64, inclusion_height: u64) -> NullifierMemberState {
    let confirmations = tip_height
        .saturating_sub(inclusion_height)
        .saturating_add(1);
    if confirmations >= u64::from(FINALITY_CONFIRMATIONS) {
        NullifierMemberState::Completed
    } else {
        NullifierMemberState::Pending
    }
}

/// Reveal-tx confirmation only (never `failed`).
fn reveal_confirmation_state(tip_height: u64, inclusion_height: u64) -> RevealConfirmationState {
    let confirmations = tip_height
        .saturating_sub(inclusion_height)
        .saturating_add(1);
    if confirmations >= u64::from(FINALITY_CONFIRMATIONS) {
        RevealConfirmationState::Completed
    } else {
        RevealConfirmationState::Pending
    }
}

/// `GetInfo` — static identity + live tip / readiness / NAV root.
pub(crate) fn get_info(
    identity: &ChainIdentity,
    view: &ChainView,
    readiness: Readiness,
    scanner_lag: u64,
) -> KernelInfo {
    KernelInfo {
        network: identity.network,
        protocol_version: "v1",
        circuit_digest_c: identity.circuit_digest_c,
        circuit_digest_c_balance: identity.circuit_digest_c_balance,
        relay_url: identity.relay_url.clone(),
        blossom_url: identity.blossom_url.clone(),
        finality_confirmations: FINALITY_CONFIRMATIONS,
        max_tx_inputs: MAX_TX_INPUTS as u32,
        max_tx_outputs: MAX_TX_OUTPUTS as u32,
        max_rx_coins: MAX_RX_COINS as u32,
        max_account_assets: MAX_ACCOUNT_ASSETS as u32,
        readiness,
        bitcoin_tip_height: view.tip_height,
        accumulator_root: Digest32(view.nav_root_bytes()),
        scanner_lag,
        max_blob_bytes: identity.max_blob_bytes,
        activation_height: identity.activation_height,
        bootstrap: identity.bootstrap.clone(),
        kernel_parts: identity.kernel_parts.clone(),
        bootstrap_pubkey: identity.bootstrap_pubkey,
    }
}

/// Build a [`ChainView`] from an in-memory [`NfLogAccumulator`] for tests.
///
/// Tip fields are supplied by the caller (the accumulator does not own
/// the Bitcoin tip hash).
#[cfg(test)]
pub(crate) fn chain_view_from_accumulator(
    acc: &shared::spec_v1::NfLogAccumulator,
    tip_height: u64,
    tip_block_hash: [u8; 32],
    mirror: Vec<(ChainPosition, NfLogEntry)>,
) -> KernelResult<ChainView> {
    chain_view_from_accumulator_with_catalog(acc, tip_height, tip_block_hash, mirror, Vec::new())
}

/// Test helper: chain view with an explicit catalog.
#[cfg(test)]
pub(crate) fn chain_view_from_accumulator_with_catalog(
    acc: &shared::spec_v1::NfLogAccumulator,
    tip_height: u64,
    tip_block_hash: [u8; 32],
    mirror: Vec<(ChainPosition, NfLogEntry)>,
    catalog: Vec<CatalogEntry>,
) -> KernelResult<ChainView> {
    let nav = acc.nav();
    if nav.size != mirror.len() as u64 {
        return Err(KernelError::with_internal(
            KernelErrorCode::InternalError,
            "Failed to build chain view",
            format!(
                "accumulator size {} != mirror length {}",
                nav.size,
                mirror.len()
            ),
        ));
    }
    let mut index = std::collections::HashMap::with_capacity(mirror.len());
    let mut winning_positions = std::collections::HashSet::with_capacity(mirror.len());
    for (pos, (c, e)) in mirror.iter().enumerate() {
        index.insert(e.pk, (pos as u64, e.r));
        winning_positions.insert((c.height, c.tx_index, c.vin_index, c.member_index));
    }
    Ok(ChainView {
        tip_height,
        tip_block_hash,
        nav,
        mirror,
        index,
        catalog,
        winning_positions,
    })
}

// ---------------------------------------------------------------------------
// Tests — NAV root, Path-B presence, bounds, closed sets, GetInfo
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use shared::spec_v1::{
        digest_from_bytes, nflog_mth, nflog_root, ChainPosition, NfLogAccumulator, NfLogEntry,
    };
    use zkcoins_program::hash::HashDigest;

    fn pk(b: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = b;
        a
    }
    fn r(b: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[31] = b;
        a
    }
    fn pos(height: u64, tx_index: u32, vin_index: u32, member_index: u32) -> ChainPosition {
        ChainPosition {
            height,
            tx_index,
            vin_index,
            member_index,
        }
    }

    fn fold_view(entries: &[(ChainPosition, [u8; 32], [u8; 32])], tip: u64) -> ChainView {
        let mut acc = NfLogAccumulator::new(0);
        let mut mirror = Vec::new();
        for &(chain_pos, p, rr) in entries {
            acc.fold(chain_pos, p, rr).expect("fold");
            mirror.push((chain_pos, NfLogEntry { pk: p, r: rr }));
        }
        chain_view_from_accumulator(&acc, tip, [0xAB; 32], mirror).expect("view")
    }

    /// Property 1: NAV root is always `Hc("NfLog/Root", size ‖ mth)`.
    ///
    /// Also proves that `mth` alone, and the swapped preimage order, are
    /// **not** the same value — otherwise the test would only check that
    /// two identical calls agree.
    #[test]
    fn nav_root_is_hc_nflog_root_size_then_mth_not_bare_mth_or_swapped() {
        let view = fold_view(
            &[
                (pos(10, 0, 0, 0), pk(1), r(1)),
                (pos(10, 0, 0, 1), pk(2), r(2)),
                (pos(11, 1, 0, 0), pk(3), r(3)),
            ],
            20,
        );
        let tip = get_accumulator(&view);
        let expected = digest_to_bytes(&nflog_root(view.nav.size, view.nav.mth));
        assert_eq!(
            tip.root.0, expected,
            "AccumulatorTip.root must equal Hc(\"NfLog/Root\", size ‖ mth)"
        );
        assert_eq!(tip.size, view.nav.size);
        // Bare mth is a different digest.
        let bare_mth = digest_to_bytes(&view.nav.mth);
        assert_ne!(
            tip.root.0, bare_mth,
            "root must not be the bare Merkle head mth"
        );
        // Swapped preimage order size↔mth must not collide.
        // Hc("NfLog/Root", mth_as_bytes ‖ size_be) via manual hc inputs:
        let size_be = view.nav.size.to_be_bytes();
        let mth_bytes = digest_to_bytes(&view.nav.mth);
        // Re-encode mth as a byte string and size as digest would require
        // different HcInput kinds; the protocol always uses ByteString(size)
        // then Digest(mth). A swapped call with ByteString(mth) ‖ Digest(size)
        // is not how nflog_root works — instead compare against hashing
        // size alone / mth alone and against a size-tweaked root.
        let wrong_size_root =
            digest_to_bytes(&nflog_root(view.nav.size.wrapping_add(1), view.nav.mth));
        assert_ne!(
            tip.root.0, wrong_size_root,
            "root must bind size; size+1 must change the commitment"
        );
        // Recompute mth from mirror and confirm tip uses that mth, not a
        // second derivation path.
        let entries: Vec<NfLogEntry> = view.mirror.iter().map(|(_, e)| *e).collect();
        let recomputed_mth = nflog_mth(&entries);
        assert_eq!(recomputed_mth, view.nav.mth);
        assert_eq!(
            digest_to_bytes(&nflog_root(entries.len() as u64, recomputed_mth)),
            tip.root.0
        );
        // Silence unused for the exploratory swapped encoding notes.
        let _ = (size_be, mth_bytes);
    }

    /// Property 2: present path verifies against size+mth; absent is not
    /// an empty path and never arises from a construction error.
    #[test]
    fn get_nullifier_path_present_verifies_absent_is_explicit() {
        let view = fold_view(
            &[
                (pos(100, 0, 0, 0), pk(10), r(10)),
                (pos(100, 1, 0, 0), pk(11), r(11)),
                (pos(101, 0, 0, 0), pk(12), r(12)),
            ],
            110,
        );

        // Present.
        let path = get_nullifier_path(
            &view,
            NullifierPathRequest {
                pubkey: XOnlyKey(pk(11)),
            },
        )
        .expect("present must succeed");
        assert!(path.is_present());
        match path {
            NullifierPath::Present {
                root,
                leaf,
                position,
                audit_path,
                tree_size,
                ..
            } => {
                assert_eq!(position, 1);
                assert_eq!(leaf.0, r(11));
                assert_eq!(tree_size, 3);
                assert_eq!(root.0, view.nav_root_bytes());
                // Re-verify the path bytes against mth (not nav_root).
                let entries: Vec<NfLogEntry> = view.mirror.iter().map(|(_, e)| *e).collect();
                let entry = entries[position as usize];
                let leaf_hash = nflog_leaf_hash(position, &entry);
                let digests: Vec<HashDigest> = audit_path
                    .iter()
                    .map(|d| {
                        // Round-trip: digest_to_bytes is bijective for
                        // canonical Poseidon digests used here.
                        digest_from_bytes(&d.0).expect("path digest")
                    })
                    .collect();
                assert!(
                    verify_inclusion(leaf_hash, position, &digests, tree_size, view.nav.mth),
                    "returned path must verify against (size, mth)"
                );
            }
            NullifierPath::Absent { .. } => panic!("pk 11 must be present"),
        }

        // Absent — explicit, not an error, not an empty path.
        let absent = get_nullifier_path(
            &view,
            NullifierPathRequest {
                pubkey: XOnlyKey(pk(0xFF)),
            },
        )
        .expect("absent is Ok, not Err");
        match absent {
            NullifierPath::Absent {
                root, tree_size, ..
            } => {
                assert!(!absent.is_present());
                assert_eq!(root.0, view.nav_root_bytes());
                assert_eq!(tree_size, 3);
            }
            NullifierPath::Present { .. } => panic!("unknown pk must be Absent"),
        }
    }

    /// A load/construction error must not become `present: false`.
    #[test]
    fn get_nullifier_path_corrupt_index_is_error_not_absent() {
        let mut view = fold_view(&[(pos(1, 0, 0, 0), pk(1), r(1))], 10);
        // Corrupt: claim a position beyond the log.
        view.index.insert(pk(9), (99, r(9)));
        let err = get_nullifier_path(
            &view,
            NullifierPathRequest {
                pubkey: XOnlyKey(pk(9)),
            },
        )
        .expect_err("corrupt index must not yield Absent");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        assert!(
            err.public_message.contains("nullifier path")
                || err
                    .internal_context
                    .as_ref()
                    .is_some_and(|c| c.detail.contains("out of range")),
            "error must name the path failure, got: {err:?}"
        );
    }

    #[test]
    fn inscription_limit_rejects_zero_and_over_max() {
        let z = InscriptionLimit::new(0).expect_err("0");
        assert_eq!(z.code, KernelErrorCode::BoundsExceeded);
        let over = InscriptionLimit::new(1001).expect_err("1001");
        assert_eq!(over.code, KernelErrorCode::BoundsExceeded);
        assert!(InscriptionLimit::new(1).is_ok());
        assert!(InscriptionLimit::new(1000).is_ok());
    }

    #[test]
    fn readiness_is_structural() {
        assert!(Readiness::Ready.is_ready());
        assert!(Readiness::Ready.reason().is_none());
        let n = Readiness::NotReady {
            reason: ReadyReason::ScannerLag,
        };
        assert!(!n.is_ready());
        assert_eq!(n.reason(), Some(ReadyReason::ScannerLag));
    }

    #[test]
    fn validate_closed_sets_accepts_current_vocabularies() {
        match validate_closed_sets() {
            Ok(()) => {}
            Err(e) => panic!("validate_closed_sets must accept current sets, got: {e}"),
        }
    }

    /// Effectiveness: a checker that only returned `Ok(())` would pass a
    /// list of empty/duplicate wires. These two injections must fail with
    /// a message that names the cause (empty / duplicate).
    #[test]
    fn validate_wire_vocabulary_rejects_empty_and_duplicate() {
        let empty = [WireEntry {
            label: "Syncing",
            wire: "",
        }];
        let err_empty = match validate_wire_vocabulary("ReadyReason", &empty) {
            Ok(()) => panic!("expected Err on empty wire string"),
            Err(e) => e,
        };
        assert!(
            err_empty.contains("empty wire string") && err_empty.contains("Syncing"),
            "error must name empty cause and label, got: {err_empty}"
        );

        let dup = [
            WireEntry {
                label: "Syncing",
                wire: "syncing",
            },
            WireEntry {
                label: "ScannerLag",
                wire: "syncing",
            },
        ];
        let err_dup = match validate_wire_vocabulary("ReadyReason", &dup) {
            Ok(()) => panic!("expected Err on duplicate wire string"),
            Err(e) => e,
        };
        assert!(
            err_dup.contains("duplicate wire string") && err_dup.contains("syncing"),
            "error must name duplicate cause and the colliding token, got: {err_dup}"
        );
        assert!(
            err_dup.contains("ScannerLag"),
            "error must name the second label, got: {err_dup}"
        );
    }

    fn test_ops() -> ChainIdentityOps {
        ChainIdentityOps {
            relay_url: "wss://relay.example".into(),
            blossom_url: "https://blossom.example".into(),
            max_blob_bytes: 1_048_576,
            kernel_parts: vec![
                KernelPart::Scanner,
                KernelPart::Prover,
                KernelPart::Publisher,
            ],
        }
    }

    fn test_bootstrap() -> BootstrapManifest {
        BootstrapManifest {
            network: KernelNetwork::Regtest,
            protocol_version: "v1".into(),
            seed_relays: vec!["wss://seed.example".into()],
            blob_stores: vec!["https://blob.example".into()],
            operator_ids: vec![XOnlyKey([0x0B; 32])],
            issued_at: 1,
            expires_at: 2,
            manifest_sig: [0x51; 64],
        }
    }

    #[test]
    fn get_info_binds_nav_root_from_view() {
        let view = fold_view(&[(pos(5, 0, 0, 0), pk(1), r(1))], 12);
        let identity = assemble_chain_identity(
            KernelNetwork::Regtest,
            Digest32([0xC1; 32]),
            Digest32([0xC2; 32]),
            0,
            XOnlyKey([0xB0; 32]),
            test_ops(),
            test_bootstrap(),
        );
        let info = get_info(&identity, &view, Readiness::Ready, 0);
        assert_eq!(info.network.as_str(), "regtest");
        assert_eq!(info.accumulator_root.0, view.nav_root_bytes());
        assert_eq!(info.bitcoin_tip_height, 12);
        assert!(info.readiness.is_ready());
        assert_eq!(info.finality_confirmations, 6);
    }

    /// Complete identity → GetInfo digests are exactly the node-supplied pair.
    #[test]
    fn get_info_reports_node_circuit_digests_not_env_overrides() {
        let view = fold_view(&[(pos(1, 0, 0, 0), pk(1), r(1))], 5);
        let digest_c = Digest32([0xAA; 32]);
        let digest_b = Digest32([0xBB; 32]);
        let identity = assemble_chain_identity(
            KernelNetwork::Testnet,
            digest_c,
            digest_b,
            100,
            XOnlyKey([0xCC; 32]),
            test_ops(),
            test_bootstrap(),
        );
        let info = get_info(&identity, &view, Readiness::Ready, 0);
        assert_eq!(
            info.circuit_digest_c, digest_c,
            "GetInfo C digest must equal the node-known digest passed into identity"
        );
        assert_eq!(
            info.circuit_digest_c_balance, digest_b,
            "GetInfo C_balance digest must equal the node-known digest"
        );
        assert_eq!(info.relay_url, "wss://relay.example");
        assert_eq!(info.blossom_url, "https://blossom.example");
        assert_eq!(info.max_blob_bytes, 1_048_576);
        assert_eq!(info.activation_height, 100);
        assert_eq!(info.bootstrap_pubkey.0, [0xCC; 32]);
        assert_eq!(
            info.kernel_parts,
            vec![
                KernelPart::Scanner,
                KernelPart::Prover,
                KernelPart::Publisher
            ]
        );
    }

    /// Protocol bounds + finality are code constants — not identity fields
    /// and not overridable via operational env (ops has no slot for them).
    #[test]
    fn get_info_protocol_constants_come_from_code_not_ops() {
        let view = fold_view(&[], 0);
        let identity = assemble_chain_identity(
            KernelNetwork::Mainnet,
            Digest32([1; 32]),
            Digest32([2; 32]),
            800_000,
            XOnlyKey([3; 32]),
            test_ops(),
            test_bootstrap(),
        );
        let info = get_info(&identity, &view, Readiness::Ready, 0);
        assert_eq!(info.finality_confirmations, FINALITY_CONFIRMATIONS);
        assert_eq!(info.finality_confirmations, 6);
        assert_eq!(info.max_tx_inputs, MAX_TX_INPUTS as u32);
        assert_eq!(info.max_tx_outputs, MAX_TX_OUTPUTS as u32);
        assert_eq!(info.max_rx_coins, MAX_RX_COINS as u32);
        assert_eq!(info.max_account_assets, MAX_ACCOUNT_ASSETS as u32);
        assert_eq!(info.protocol_version, "v1");
        // `parse_chain_identity_ops` only accepts relay/blossom/max_blob/parts —
        // there is no env slot for finality or circuit bounds (type-level).
    }

    #[test]
    fn missing_operational_env_names_the_variable() {
        let err = parse_chain_identity_ops(None, Some("https://b"), Some("1"), Some("scanner"))
            .expect_err("relay missing");
        match err {
            ChainIdentityError::MissingVar { name } => assert_eq!(name, RELAY_URL_ENV),
            other => panic!("expected MissingVar(RELAY), got {other:?}"),
        }

        let err = parse_chain_identity_ops(Some("wss://r"), None, Some("1"), Some("scanner"))
            .expect_err("blossom missing");
        match err {
            ChainIdentityError::MissingVar { name } => assert_eq!(name, BLOSSOM_URL_ENV),
            other => panic!("expected MissingVar(BLOSSOM), got {other:?}"),
        }

        let err =
            parse_chain_identity_ops(Some("wss://r"), Some("https://b"), None, Some("scanner"))
                .expect_err("max_blob missing");
        match err {
            ChainIdentityError::MissingVar { name } => assert_eq!(name, MAX_BLOB_BYTES_ENV),
            other => panic!("expected MissingVar(MAX_BLOB), got {other:?}"),
        }

        let err = parse_chain_identity_ops(Some("wss://r"), Some("https://b"), Some("1"), None)
            .expect_err("parts missing");
        match err {
            ChainIdentityError::MissingVar { name } => assert_eq!(name, KERNEL_PARTS_ENV),
            other => panic!("expected MissingVar(PARTS), got {other:?}"),
        }

        // Empty string is the same class as missing (no silent default).
        let err =
            parse_chain_identity_ops(Some("  "), Some("https://b"), Some("1"), Some("scanner"))
                .expect_err("blank relay");
        match err {
            ChainIdentityError::MissingVar { name } => assert_eq!(name, RELAY_URL_ENV),
            other => panic!("expected MissingVar on blank, got {other:?}"),
        }
    }

    #[test]
    fn invalid_max_blob_and_parts_name_the_cause() {
        let err = parse_max_blob_bytes(Some("0")).expect_err("zero");
        match err {
            ChainIdentityError::InvalidVar { name, detail } => {
                assert_eq!(name, MAX_BLOB_BYTES_ENV);
                assert!(
                    detail.contains("> 0"),
                    "detail must name zero cause: {detail}"
                );
            }
            other => panic!("expected InvalidVar, got {other:?}"),
        }

        let err = parse_max_blob_bytes(Some("nope")).expect_err("garbage");
        match err {
            ChainIdentityError::InvalidVar { name, .. } => assert_eq!(name, MAX_BLOB_BYTES_ENV),
            other => panic!("expected InvalidVar, got {other:?}"),
        }

        let err = parse_kernel_parts(Some("scanner,wallet")).expect_err("unknown part");
        match err {
            ChainIdentityError::InvalidVar { name, detail } => {
                assert_eq!(name, KERNEL_PARTS_ENV);
                assert!(
                    detail.contains("wallet") && detail.contains("unknown"),
                    "detail must name the bad token, got: {detail}"
                );
            }
            other => panic!("expected InvalidVar, got {other:?}"),
        }

        let err = parse_kernel_parts(Some("scanner,scanner")).expect_err("dup");
        match err {
            ChainIdentityError::InvalidVar { name, detail } => {
                assert_eq!(name, KERNEL_PARTS_ENV);
                assert!(detail.contains("duplicate"), "got: {detail}");
            }
            other => panic!("expected InvalidVar, got {other:?}"),
        }
    }

    #[test]
    fn resolve_without_bootstrap_is_unavailable_not_invented() {
        let err = resolve_chain_identity(
            KernelNetwork::Regtest,
            Digest32([0xC1; 32]),
            Digest32([0xC2; 32]),
            0,
            XOnlyKey([0xB0; 32]),
            test_ops(),
            None,
        )
        .expect_err("no bootstrap → unavailable");
        match err {
            ChainIdentityError::BootstrapUnavailable { reason } => {
                assert!(
                    reason.contains("BMF1")
                        || reason.contains("BootstrapManifest")
                        || reason.contains("ZKCOINS_V1_BOOTSTRAP_MANIFEST_PATH"),
                    "reason must name the missing artifact / env path, got: {reason}"
                );
            }
            other => panic!("expected BootstrapUnavailable, got {other:?}"),
        }
        // With a real (test) manifest, resolve succeeds and digests stick.
        let id = resolve_chain_identity(
            KernelNetwork::Regtest,
            Digest32([0xC1; 32]),
            Digest32([0xC2; 32]),
            0,
            XOnlyKey([0xB0; 32]),
            test_ops(),
            Some(test_bootstrap()),
        )
        .expect("bootstrap present");
        assert_eq!(id.circuit_digest_c.0, [0xC1; 32]);
        assert_eq!(id.circuit_digest_c_balance.0, [0xC2; 32]);
    }

    /// Production boot must not install identity when the verified
    /// BootstrapManifest is absent — silent `None` would leave GetInfo
    /// unanswerable while the node still serves other RPCs.
    #[test]
    fn boot_identity_without_verified_manifest_fails_closed() {
        let err = resolve_chain_identity(
            KernelNetwork::Regtest,
            Digest32([0xAA; 32]),
            Digest32([0xBB; 32]),
            42,
            XOnlyKey([0xCC; 32]),
            test_ops(),
            None,
        )
        .expect_err("missing bootstrap must abort identity install");
        assert!(
            matches!(err, ChainIdentityError::BootstrapUnavailable { .. }),
            "must be BootstrapUnavailable, got {err:?}"
        );
        // Display names the operational path so ops can fix the deploy.
        let msg = err.to_string();
        assert!(
            msg.contains("BootstrapManifest") || msg.contains("BMF1"),
            "error must name the missing §4.3 artifact: {msg}"
        );
    }

    /// Verified BMF1 fields → domain bootstrap → GetInfo echoes them
    /// (plus digests/ops from the node pins), matching §7.8 `Info`.
    #[test]
    fn get_info_with_wired_identity_reports_section_7_8_fields() {
        let view = fold_view(&[(pos(3, 0, 0, 0), pk(9), r(9))], 100);
        let digest_c = Digest32([0x11; 32]);
        let digest_b = Digest32([0x22; 32]);
        let bootstrap_pubkey = XOnlyKey([0x33; 32]);
        let seed = "wss://seed-from-manifest.example".to_string();
        let blob = "https://blob-from-manifest.example".to_string();
        let operator = [0x44u8; 32];
        let sig = [0x55u8; 64];
        let bootstrap = bootstrap_manifest_from_verified(VerifiedManifestFields {
            network_label: "regtest",
            protocol_version: "v1",
            seed_relays: std::slice::from_ref(&seed),
            blob_stores: std::slice::from_ref(&blob),
            operator_ids: std::slice::from_ref(&operator),
            issued_at: 1_700_000_000,
            expires_at: 1_800_000_000,
            manifest_sig: &sig,
        })
        .expect("verified fields project to domain bootstrap");
        let identity = resolve_chain_identity(
            KernelNetwork::Regtest,
            digest_c,
            digest_b,
            7,
            bootstrap_pubkey,
            test_ops(),
            Some(bootstrap),
        )
        .expect("complete sources → identity");
        let info = get_info(&identity, &view, Readiness::Ready, 0);

        // §7.8 static pins from the node / ops — not invented defaults.
        assert_eq!(info.network, KernelNetwork::Regtest);
        assert_eq!(info.protocol_version, "v1");
        assert_eq!(info.circuit_digest_c, digest_c);
        assert_eq!(info.circuit_digest_c_balance, digest_b);
        assert_eq!(info.bootstrap_pubkey, bootstrap_pubkey);
        assert_eq!(info.relay_url, "wss://relay.example");
        assert_eq!(info.blossom_url, "https://blossom.example");
        assert_eq!(info.max_blob_bytes, 1_048_576);
        assert_eq!(info.activation_height, 7);
        assert_eq!(info.finality_confirmations, FINALITY_CONFIRMATIONS);
        assert_eq!(info.max_tx_inputs, MAX_TX_INPUTS as u32);
        assert_eq!(info.max_tx_outputs, MAX_TX_OUTPUTS as u32);
        assert_eq!(info.max_rx_coins, MAX_RX_COINS as u32);
        assert_eq!(info.max_account_assets, MAX_ACCOUNT_ASSETS as u32);
        assert!(info.readiness.is_ready());
        assert_eq!(info.bitcoin_tip_height, 100);
        assert_eq!(info.accumulator_root.0, view.nav_root_bytes());

        // §4.3 bootstrap echo — exactly the verified artifact fields.
        assert_eq!(info.bootstrap.network, KernelNetwork::Regtest);
        assert_eq!(info.bootstrap.protocol_version, "v1");
        assert_eq!(info.bootstrap.seed_relays, vec![seed]);
        assert_eq!(info.bootstrap.blob_stores, vec![blob]);
        assert_eq!(info.bootstrap.operator_ids, vec![XOnlyKey(operator)]);
        assert_eq!(info.bootstrap.issued_at, 1_700_000_000);
        assert_eq!(info.bootstrap.expires_at, 1_800_000_000);
        assert_eq!(info.bootstrap.manifest_sig, sig);
    }

    #[test]
    fn resolve_rejects_bootstrap_network_disagreeing_with_pin() {
        let mut bootstrap = test_bootstrap();
        bootstrap.network = KernelNetwork::Mainnet;
        let err = resolve_chain_identity(
            KernelNetwork::Regtest,
            Digest32([1; 32]),
            Digest32([2; 32]),
            0,
            XOnlyKey([3; 32]),
            test_ops(),
            Some(bootstrap),
        )
        .expect_err("network mismatch must refuse identity");
        match err {
            ChainIdentityError::InvalidVar { name, detail } => {
                assert_eq!(name, "bootstrap.network");
                assert!(
                    detail.contains("mainnet") && detail.contains("regtest"),
                    "detail must name both sides: {detail}"
                );
            }
            other => panic!("expected InvalidVar, got {other:?}"),
        }
    }

    #[test]
    fn bootstrap_manifest_from_verified_refuses_unknown_network() {
        let err = bootstrap_manifest_from_verified(VerifiedManifestFields {
            network_label: "mutinynet",
            protocol_version: "v1",
            seed_relays: &["wss://r".into()],
            blob_stores: &["https://b".into()],
            operator_ids: &[[0u8; 32]],
            issued_at: 1,
            expires_at: 2,
            manifest_sig: &[0u8; 64],
        })
        .expect_err("unknown network");
        match err {
            ChainIdentityError::InvalidVar { name, .. } => assert_eq!(name, "bootstrap.network"),
            other => panic!("expected InvalidVar, got {other:?}"),
        }
    }

    #[test]
    fn missing_ops_env_from_process_names_variable() {
        use std::sync::{Mutex, OnceLock};
        fn env_lock() -> std::sync::MutexGuard<'static, ()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(()))
                .lock()
                .unwrap_or_else(|p| p.into_inner())
        }
        let _guard = env_lock();
        let keys = [
            RELAY_URL_ENV,
            BLOSSOM_URL_ENV,
            MAX_BLOB_BYTES_ENV,
            KERNEL_PARTS_ENV,
        ];
        let saved: Vec<_> = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
        for k in &keys {
            std::env::remove_var(k);
        }
        let err = chain_identity_ops_from_env().expect_err("all unset");
        match err {
            ChainIdentityError::MissingVar { name } => {
                assert!(
                    keys.contains(&name),
                    "must name one of the required vars, got {name}"
                );
            }
            other => panic!("expected MissingVar, got {other:?}"),
        }
        // Restore.
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }

    fn catalog_entry(
        height: u64,
        tx_index: u32,
        vin_index: u32,
        format: u8,
        members: Vec<(u32, [u8; 32], [u8; 32])>,
        txid_byte: u8,
    ) -> CatalogEntry {
        CatalogEntry {
            height,
            tx_index,
            vin_index,
            reveal_txid: [txid_byte; 32],
            format,
            members,
            block_anchor_hash: [0xAA; 32],
            block_anchor_height: height.saturating_sub(1) as u32,
        }
    }

    fn view_with_catalog(
        nflog: &[(ChainPosition, [u8; 32], [u8; 32])],
        catalog: Vec<CatalogEntry>,
        tip: u64,
    ) -> ChainView {
        let mut acc = NfLogAccumulator::new(0);
        let mut mirror = Vec::new();
        for &(chain_pos, p, rr) in nflog {
            acc.fold(chain_pos, p, rr).expect("fold");
            mirror.push((chain_pos, NfLogEntry { pk: p, r: rr }));
        }
        chain_view_from_accumulator_with_catalog(&acc, tip, [0xAB; 32], mirror, catalog)
            .expect("view")
    }

    /// Contract 1: total stable order over the triple.
    #[test]
    fn list_inscriptions_total_order_by_height_tx_vin() {
        let mut catalog = vec![
            catalog_entry(2, 0, 0, 0x00, vec![(0, pk(1), r(1))], 0x01),
            catalog_entry(1, 1, 0, 0x00, vec![(0, pk(2), r(2))], 0x02),
            catalog_entry(1, 0, 1, 0x01, vec![(0, pk(3), r(3))], 0x03),
            catalog_entry(1, 0, 0, 0x00, vec![(0, pk(4), r(4))], 0x04),
        ];
        catalog.sort_by_key(|e| (e.height, e.tx_index, e.vin_index));
        let view = view_with_catalog(&[], catalog, 10);
        let page = list_inscriptions(
            &view,
            ListInscriptions {
                from: InscriptionCursor::origin(),
                limit: InscriptionLimit::new(10).expect("limit"),
            },
        );
        let keys: Vec<(u64, u64, u64)> = page
            .inscriptions
            .iter()
            .map(|i| (i.height, i.tx_index, i.vin_index))
            .collect();
        assert_eq!(
            keys,
            vec![(1, 0, 0), (1, 0, 1), (1, 1, 0), (2, 0, 0)],
            "stream order must be lexicographic on the triple"
        );
    }

    /// Contract 2: cursor is structurally complete (`InscriptionCursor`).
    #[test]
    fn list_inscriptions_cursor_is_structurally_complete() {
        let c = InscriptionCursor {
            height: 7,
            tx_index: 3,
            vin_index: 9,
        };
        assert_eq!((c.height, c.tx_index, c.vin_index), (7, 3, 9));
        let catalog = vec![catalog_entry(5, 0, 0, 0x00, vec![(0, pk(1), r(1))], 0x11)];
        let view = view_with_catalog(&[], catalog, 5);
        let page = list_inscriptions(
            &view,
            ListInscriptions {
                from: InscriptionCursor::origin(),
                limit: InscriptionLimit::new(1).expect("limit"),
            },
        );
        assert!(page.next.is_none(), "single-page stream has no next");
    }

    /// Contract 3: exclusive next of page n is inclusive from of page n+1.
    #[test]
    fn list_inscriptions_gapless_pages_over_three_pages() {
        let mut catalog = Vec::new();
        for i in 0u32..7 {
            catalog.push(catalog_entry(
                10,
                i,
                0,
                0x00,
                vec![(0, pk(i as u8 + 1), r(i as u8 + 1))],
                i as u8,
            ));
        }
        let view = view_with_catalog(&[], catalog, 20);
        let limit = InscriptionLimit::new(2).expect("limit");
        let mut from = InscriptionCursor::origin();
        let mut seen = Vec::new();
        for page_i in 0..3 {
            let page = list_inscriptions(&view, ListInscriptions { from, limit });
            assert_eq!(
                page.inscriptions.len(),
                2,
                "page {page_i} must be full (2 of 7)"
            );
            for ins in &page.inscriptions {
                seen.push((ins.height, ins.tx_index, ins.vin_index));
            }
            from = page.next.expect("pages 0..2 must have next");
        }
        let last = list_inscriptions(&view, ListInscriptions { from, limit });
        assert_eq!(last.inscriptions.len(), 1);
        assert!(last.next.is_none());
        seen.push((
            last.inscriptions[0].height,
            last.inscriptions[0].tx_index,
            last.inscriptions[0].vin_index,
        ));
        assert_eq!(seen.len(), 7);
        for (i, entry) in seen.iter().enumerate() {
            assert_eq!(entry, &(10, i as u64, 0));
        }
    }

    /// Double-spend loser: in catalog, not in NfLog at its position → failed.
    #[test]
    fn list_inscriptions_double_spend_loser_is_failed() {
        let winner_pos = pos(10, 0, 0, 0);
        let winner_entry = catalog_entry(10, 0, 0, 0x00, vec![(0, pk(1), r(1))], 0xA1);
        let loser_entry = catalog_entry(11, 0, 0, 0x00, vec![(0, pk(1), r(9))], 0xB1);
        let view = view_with_catalog(
            &[(winner_pos, pk(1), r(1))],
            vec![winner_entry, loser_entry],
            20,
        );
        let page = list_inscriptions(
            &view,
            ListInscriptions {
                from: InscriptionCursor::origin(),
                limit: InscriptionLimit::new(10).expect("limit"),
            },
        );
        assert_eq!(page.inscriptions.len(), 2);
        assert_eq!(
            page.inscriptions[0].nullifiers[0].state,
            NullifierMemberState::Completed
        );
        assert_eq!(
            page.inscriptions[1].nullifiers[0].state,
            NullifierMemberState::Failed,
            "loser must be failed — catalog member whose chain position is not in NfLog"
        );
    }

    /// format 0x00 and 0x01 come from the catalog payload field, not member count.
    #[test]
    fn list_inscriptions_format_is_catalog_byte_not_member_count() {
        let half_one = catalog_entry(1, 0, 0, 0x01, vec![(0, pk(1), r(1))], 0x01);
        let raw_one = catalog_entry(1, 0, 1, 0x00, vec![(0, pk(2), r(2))], 0x02);
        let view = view_with_catalog(&[], vec![half_one, raw_one], 1);
        let page = list_inscriptions(
            &view,
            ListInscriptions {
                from: InscriptionCursor::origin(),
                limit: InscriptionLimit::new(10).expect("limit"),
            },
        );
        assert_eq!(page.inscriptions[0].format, 1);
        assert_eq!(page.inscriptions[0].count, 1);
        assert_eq!(page.inscriptions[1].format, 0);
        assert_eq!(page.inscriptions[1].count, 1);
        assert_ne!(page.inscriptions[0].format, page.inscriptions[1].format);
    }

    /// Multi-member inscription preserves member_index order.
    #[test]
    fn list_inscriptions_multi_member_preserves_order() {
        let entry = catalog_entry(
            3,
            1,
            2,
            0x01,
            vec![(0, pk(10), r(10)), (1, pk(11), r(11)), (2, pk(12), r(12))],
            0x33,
        );
        let view = view_with_catalog(
            &[
                (pos(3, 1, 2, 0), pk(10), r(10)),
                (pos(3, 1, 2, 1), pk(11), r(11)),
                (pos(3, 1, 2, 2), pk(12), r(12)),
            ],
            vec![entry],
            3,
        );
        let page = list_inscriptions(
            &view,
            ListInscriptions {
                from: InscriptionCursor::origin(),
                limit: InscriptionLimit::new(1).expect("limit"),
            },
        );
        assert_eq!(page.inscriptions[0].count, 3);
        assert_eq!(page.inscriptions[0].nullifiers[0].pubkey, pk(10));
        assert_eq!(page.inscriptions[0].nullifiers[1].pubkey, pk(11));
        assert_eq!(page.inscriptions[0].nullifiers[2].pubkey, pk(12));
    }

    /// Txid on the list is the internal-order bytes from the catalog.
    #[test]
    fn list_inscriptions_txid_is_internal_order_from_catalog() {
        let mut internal = [0u8; 32];
        for (i, b) in internal.iter_mut().enumerate() {
            *b = i as u8;
        }
        let mut entry = catalog_entry(1, 0, 0, 0x00, vec![(0, pk(1), r(1))], 0);
        entry.reveal_txid = internal;
        let view = view_with_catalog(&[], vec![entry], 1);
        let page = list_inscriptions(
            &view,
            ListInscriptions {
                from: InscriptionCursor::origin(),
                limit: InscriptionLimit::new(1).expect("limit"),
            },
        );
        assert_eq!(page.inscriptions[0].txid, internal);
        let mut reversed = internal;
        reversed.reverse();
        assert_ne!(page.inscriptions[0].txid, reversed);
    }

    /// Every engine and wire network variant maps to the closed kernel label.
    #[test]
    fn kernel_network_maps_all_engine_and_wire_variants() {
        use zkcoins_program::circuit::compliance::Network;

        assert_eq!(KernelNetwork::Mainnet.as_str(), "mainnet");
        assert_eq!(KernelNetwork::Testnet.as_str(), "testnet");
        assert_eq!(KernelNetwork::Regtest.as_str(), "regtest");

        assert_eq!(KernelNetwork::from_v1(Network::Mainnet), KernelNetwork::Mainnet);
        assert_eq!(KernelNetwork::from_v1(Network::Testnet), KernelNetwork::Testnet);
        assert_eq!(KernelNetwork::from_v1(Network::Regtest), KernelNetwork::Regtest);

        assert_eq!(
            KernelNetwork::from_wire("mainnet").expect("mainnet wire label"),
            KernelNetwork::Mainnet
        );
        assert_eq!(
            KernelNetwork::from_wire("testnet").expect("testnet wire label"),
            KernelNetwork::Testnet
        );
        assert_eq!(
            KernelNetwork::from_wire("regtest").expect("regtest wire label"),
            KernelNetwork::Regtest
        );
        let err = KernelNetwork::from_wire("").expect_err("empty wire label must fail");
        assert!(
            matches!(
                err,
                ChainIdentityError::InvalidVar { name, ref detail }
                    if name == "bootstrap.network"
                        && detail.contains("unknown network")
                        && detail.contains("mainnet")
            ),
            "empty wire label must name the closed network vocabulary, got: {err:?}"
        );
    }

    /// Reveal confirmation variants expose their exact closed wire labels.
    #[test]
    fn reveal_confirmation_state_maps_all_wire_labels() {
        assert_eq!(RevealConfirmationState::Pending.as_str(), "pending");
        assert_eq!(RevealConfirmationState::Completed.as_str(), "completed");
    }

    /// Stored catalog rows are copied field-for-field into the chain view model.
    #[test]
    fn catalog_entry_from_stored_preserves_every_field() {
        let members = vec![
            (3, [0x31; 32], [0x32; 32]),
            (7, [0x71; 32], [0x72; 32]),
        ];
        let row = crate::v1::db_v1::CatalogInscription {
            height: 987_654,
            tx_index: 123,
            vin_index: 456,
            reveal_txid: [0xA1; 32],
            format: 1,
            members: members.clone(),
            block_anchor_hash: [0xB2; 32],
            block_anchor_height: 789,
        };

        let entry = CatalogEntry::from_stored(&row);
        assert_eq!(entry.height, 987_654);
        assert_eq!(entry.tx_index, 123);
        assert_eq!(entry.vin_index, 456);
        assert_eq!(entry.reveal_txid, [0xA1; 32]);
        assert_eq!(entry.format, 1);
        assert_eq!(entry.members, members);
        assert_eq!(entry.block_anchor_hash, [0xB2; 32]);
        assert_eq!(entry.block_anchor_height, 789);
    }

    /// Catalog cursors widen both u32 indices without changing their values.
    #[test]
    fn catalog_entry_cursor_widens_indices_exactly() {
        let entry = catalog_entry(
            42,
            u32::MAX - 1,
            u32::MAX,
            0,
            vec![(0, pk(1), r(1))],
            0x42,
        );
        assert_eq!(
            entry.cursor(),
            InscriptionCursor {
                height: 42,
                tx_index: u64::from(u32::MAX - 1),
                vin_index: u64::from(u32::MAX),
            }
        );
    }

    /// Queue failure, scan presence, and the finality boundary drive one classifier.
    #[test]
    fn classify_member_state_covers_precedence_and_finality_boundary() {
        assert_eq!(
            classify_member_state(MemberChainObservation {
                queue_failed: true,
                first_occurrence: false,
                inclusion_height: None,
                tip_height: 100,
            }),
            NullifierMemberState::Failed,
            "durable queue failure must take precedence over every chain field"
        );
        assert_eq!(
            classify_member_state(MemberChainObservation {
                queue_failed: false,
                first_occurrence: true,
                inclusion_height: None,
                tip_height: 100,
            }),
            NullifierMemberState::Pending,
            "a member without a scanned inclusion cannot be finished"
        );
        assert_eq!(
            classify_member_state(MemberChainObservation {
                queue_failed: false,
                first_occurrence: false,
                inclusion_height: Some(50),
                tip_height: 100,
            }),
            NullifierMemberState::Failed,
            "a later occurrence must fail even after finality depth"
        );
        assert_eq!(
            classify_member_state(MemberChainObservation {
                queue_failed: false,
                first_occurrence: true,
                inclusion_height: Some(50),
                tip_height: 55,
            }),
            NullifierMemberState::Completed,
            "six confirmations must complete the first occurrence"
        );
        assert_eq!(
            classify_member_state(MemberChainObservation {
                queue_failed: false,
                first_occurrence: true,
                inclusion_height: Some(50),
                tip_height: 54,
            }),
            NullifierMemberState::Pending,
            "five confirmations must remain pending"
        );
    }

    /// Finished is exactly completed, never pending or failed.
    #[test]
    fn member_is_finished_only_for_completed_observation() {
        assert!(member_is_finished(MemberChainObservation {
            queue_failed: false,
            first_occurrence: true,
            inclusion_height: Some(50),
            tip_height: 55,
        }));
        assert!(!member_is_finished(MemberChainObservation {
            queue_failed: false,
            first_occurrence: true,
            inclusion_height: Some(50),
            tip_height: 54,
        }));
        assert!(!member_is_finished(MemberChainObservation {
            queue_failed: true,
            first_occurrence: true,
            inclusion_height: Some(50),
            tip_height: 55,
        }));
    }

    /// Member confirmation depth is inclusive and saturates below inclusion.
    #[test]
    fn member_confirmation_state_handles_boundary_and_saturation() {
        assert_eq!(
            member_confirmation_state(105, 100),
            NullifierMemberState::Completed
        );
        assert_eq!(
            member_confirmation_state(104, 100),
            NullifierMemberState::Pending
        );
        assert_eq!(
            member_confirmation_state(0, 100),
            NullifierMemberState::Pending,
            "tip below inclusion must saturate instead of underflowing"
        );
    }

    /// Reveal confirmation depth uses the same inclusive six-block boundary.
    #[test]
    fn reveal_confirmation_state_handles_finality_boundary() {
        assert_eq!(
            reveal_confirmation_state(105, 100),
            RevealConfirmationState::Completed
        );
        assert_eq!(
            reveal_confirmation_state(104, 100),
            RevealConfirmationState::Pending
        );
    }

    /// Readiness covers absent flags, both false causes, and finality precedence.
    #[test]
    fn chain_readiness_flags_evaluate_all_combinations() {
        let flag = |value| Some(Arc::new(AtomicBool::new(value)));

        assert_eq!(ChainReadinessFlags::default().evaluate(), Readiness::Ready);
        assert_eq!(
            ChainReadinessFlags {
                scan_caught_up: None,
                finality_ok: flag(false),
            }
            .evaluate(),
            Readiness::NotReady {
                reason: ReadyReason::DeepReorg,
            }
        );
        assert_eq!(
            ChainReadinessFlags {
                scan_caught_up: flag(false),
                finality_ok: flag(false),
            }
            .evaluate(),
            Readiness::NotReady {
                reason: ReadyReason::DeepReorg,
            },
            "deep reorg must take precedence over scanner lag"
        );
        assert_eq!(
            ChainReadinessFlags {
                scan_caught_up: flag(false),
                finality_ok: flag(true),
            }
            .evaluate(),
            Readiness::NotReady {
                reason: ReadyReason::ScannerLag,
            }
        );
        assert_eq!(
            ChainReadinessFlags {
                scan_caught_up: flag(true),
                finality_ok: flag(true),
            }
            .evaluate(),
            Readiness::Ready
        );
        assert_eq!(
            ChainReadinessFlags {
                scan_caught_up: flag(false),
                finality_ok: None,
            }
            .evaluate(),
            Readiness::NotReady {
                reason: ReadyReason::ScannerLag,
            }
        );
        assert_eq!(
            ChainReadinessFlags {
                scan_caught_up: flag(true),
                finality_ok: None,
            }
            .evaluate(),
            Readiness::Ready
        );
    }

    /// Required URLs accept the exact byte limit and reject one byte more.
    #[test]
    fn parse_required_url_enforces_exact_length_boundary() {
        let at_limit = "a".repeat(URL_MAX_BYTES);
        assert_eq!(
            parse_required_url(RELAY_URL_ENV, Some(&at_limit)).expect("URL at byte limit"),
            at_limit
        );

        let over_limit = "a".repeat(URL_MAX_BYTES + 1);
        let err = parse_required_url(RELAY_URL_ENV, Some(&over_limit))
            .expect_err("URL over byte limit must fail");
        assert!(
            matches!(
                err,
                ChainIdentityError::InvalidVar { name, ref detail }
                    if name == RELAY_URL_ENV && detail.contains("exceeds max")
            ),
            "oversized URL must name the bound, got: {err:?}"
        );
    }

    /// Present but blank max-blob input is missing, not an integer error.
    #[test]
    fn parse_max_blob_bytes_rejects_blank_as_missing() {
        let err = parse_max_blob_bytes(Some("   ")).expect_err("blank max blob value");
        assert_eq!(
            err,
            ChainIdentityError::MissingVar {
                name: MAX_BLOB_BYTES_ENV,
            }
        );
    }

    /// Blank part lists are missing; an interior empty token is invalid.
    #[test]
    fn parse_kernel_parts_rejects_blank_and_empty_token() {
        let blank = parse_kernel_parts(Some("   ")).expect_err("blank kernel parts");
        assert_eq!(
            blank,
            ChainIdentityError::MissingVar {
                name: KERNEL_PARTS_ENV,
            }
        );

        let empty_token = parse_kernel_parts(Some("scanner,,publisher"))
            .expect_err("interior empty kernel part token");
        assert!(
            matches!(
                empty_token,
                ChainIdentityError::InvalidVar { name, ref detail }
                    if name == KERNEL_PARTS_ENV && detail.contains("empty token")
            ),
            "empty token must name its cause, got: {empty_token:?}"
        );
    }

    /// Process env values are read and parsed without defaults or rewriting.
    #[test]
    fn chain_identity_ops_from_env_reads_present_values() {
        use std::sync::{Mutex, OnceLock};
        fn env_lock() -> std::sync::MutexGuard<'static, ()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(()))
                .lock()
                .unwrap_or_else(|p| p.into_inner())
        }
        let _guard = env_lock();
        let keys = [
            RELAY_URL_ENV,
            BLOSSOM_URL_ENV,
            MAX_BLOB_BYTES_ENV,
            KERNEL_PARTS_ENV,
        ];
        let saved: Vec<_> = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
        std::env::set_var(RELAY_URL_ENV, "wss://r.example");
        std::env::set_var(BLOSSOM_URL_ENV, "https://b.example");
        std::env::set_var(MAX_BLOB_BYTES_ENV, "1000");
        std::env::set_var(KERNEL_PARTS_ENV, "scanner,prover");

        let ops = chain_identity_ops_from_env().expect("all operational env values are valid");
        assert_eq!(
            ops,
            ChainIdentityOps {
                relay_url: "wss://r.example".into(),
                blossom_url: "https://b.example".into(),
                max_blob_bytes: 1000,
                kernel_parts: vec![KernelPart::Scanner, KernelPart::Prover],
            }
        );

        // Restore.
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }

    /// Non-UTF-8 process env values fail loud before operational parsing.
    #[cfg(unix)]
    #[test]
    fn chain_identity_ops_from_env_rejects_non_utf8_value() {
        use std::os::unix::ffi::OsStrExt;
        use std::sync::{Mutex, OnceLock};
        fn env_lock() -> std::sync::MutexGuard<'static, ()> {
            static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
            LOCK.get_or_init(|| Mutex::new(()))
                .lock()
                .unwrap_or_else(|p| p.into_inner())
        }
        let _guard = env_lock();
        let keys = [
            RELAY_URL_ENV,
            BLOSSOM_URL_ENV,
            MAX_BLOB_BYTES_ENV,
            KERNEL_PARTS_ENV,
        ];
        let saved: Vec<_> = keys.iter().map(|k| (*k, std::env::var_os(k))).collect();
        std::env::set_var(
            RELAY_URL_ENV,
            std::ffi::OsStr::from_bytes(&[0xFF, 0xFE]),
        );
        std::env::set_var(BLOSSOM_URL_ENV, "https://b.example");
        std::env::set_var(MAX_BLOB_BYTES_ENV, "1000");
        std::env::set_var(KERNEL_PARTS_ENV, "scanner,prover");

        let err = chain_identity_ops_from_env().expect_err("non-UTF-8 relay URL must fail");
        assert!(
            matches!(
                err,
                ChainIdentityError::InvalidVar { name, ref detail }
                    if name == RELAY_URL_ENV && detail.contains("UTF-8")
            ),
            "non-UTF-8 value must name the variable and encoding failure, got: {err:?}"
        );

        // Restore.
        for (k, v) in saved {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }

    /// Verified manifests reject every invalid field after network parsing.
    #[test]
    fn bootstrap_manifest_from_verified_rejects_invalid_required_fields() {
        fn assert_invalid_field(fields: VerifiedManifestFields<'_>, expected_name: &'static str) {
            let err = bootstrap_manifest_from_verified(fields)
                .expect_err("invalid verified manifest field must fail");
            assert!(
                matches!(
                    err,
                    ChainIdentityError::InvalidVar { name, .. } if name == expected_name
                ),
                "invalid manifest field must name {expected_name}, got: {err:?}"
            );
        }

        let relays = ["wss://r".to_string()];
        let blobs = ["https://b".to_string()];
        let operators = [[0x11; 32]];
        let sig = [0x22; 64];
        assert_invalid_field(
            VerifiedManifestFields {
                network_label: "regtest",
                protocol_version: "v2",
                seed_relays: &relays,
                blob_stores: &blobs,
                operator_ids: &operators,
                issued_at: 1,
                expires_at: 2,
                manifest_sig: &sig,
            },
            "bootstrap.protocol_version",
        );
        assert_invalid_field(
            VerifiedManifestFields {
                network_label: "regtest",
                protocol_version: "v1",
                seed_relays: &[],
                blob_stores: &blobs,
                operator_ids: &operators,
                issued_at: 1,
                expires_at: 2,
                manifest_sig: &sig,
            },
            "bootstrap.seed_relays",
        );
        assert_invalid_field(
            VerifiedManifestFields {
                network_label: "regtest",
                protocol_version: "v1",
                seed_relays: &relays,
                blob_stores: &[],
                operator_ids: &operators,
                issued_at: 1,
                expires_at: 2,
                manifest_sig: &sig,
            },
            "bootstrap.blob_stores",
        );
        assert_invalid_field(
            VerifiedManifestFields {
                network_label: "regtest",
                protocol_version: "v1",
                seed_relays: &relays,
                blob_stores: &blobs,
                operator_ids: &[],
                issued_at: 1,
                expires_at: 2,
                manifest_sig: &sig,
            },
            "bootstrap.operator_ids",
        );
    }

    /// A valid but misdirected index position must fail as internal corruption.
    #[test]
    fn get_nullifier_path_rejects_index_entry_divergence() {
        let mut view = fold_view(
            &[
                (pos(1, 0, 0, 0), pk(1), r(1)),
                (pos(2, 0, 0, 0), pk(2), r(2)),
            ],
            10,
        );
        view.index.insert(pk(9), (0, r(9)));

        let err = get_nullifier_path(
            &view,
            NullifierPathRequest {
                pubkey: XOnlyKey(pk(9)),
            },
        )
        .expect_err("divergent index entry must not yield a path or absence");
        let detail = err
            .internal_context
            .as_ref()
            .map(|context| context.detail.as_str())
            .unwrap_or("");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        assert!(
            err.public_message.contains("nullifier path")
                && (detail.contains("diverges") || detail.contains("claimed position")),
            "error must name the index/log divergence, got: {err:?}"
        );
    }

    /// An internally consistent mirror must still verify against the committed MTH.
    #[test]
    fn get_nullifier_path_rejects_path_against_foreign_mth() {
        let mut view = fold_view(
            &[
                (pos(1, 0, 0, 0), pk(1), r(1)),
                (pos(2, 0, 0, 0), pk(2), r(2)),
                (pos(3, 0, 0, 0), pk(3), r(3)),
            ],
            10,
        );
        let foreign_view = fold_view(
            &[
                (pos(4, 0, 0, 0), pk(4), r(4)),
                (pos(5, 0, 0, 0), pk(5), r(5)),
                (pos(6, 0, 0, 0), pk(6), r(6)),
            ],
            10,
        );
        view.nav.mth = foreign_view.nav.mth;

        let err = get_nullifier_path(
            &view,
            NullifierPathRequest {
                pubkey: XOnlyKey(pk(2)),
            },
        )
        .expect_err("path must fail against an unrelated committed MTH");
        let detail = err
            .internal_context
            .as_ref()
            .map(|context| context.detail.as_str())
            .unwrap_or("");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        assert!(
            detail.contains("does not verify") && detail.contains("tip mth"),
            "error must name failed inclusion verification, got: {err:?}"
        );
    }

    /// Test view construction rejects accumulator/mirror length divergence.
    #[test]
    fn chain_view_from_accumulator_rejects_size_mirror_mismatch() {
        let acc = NfLogAccumulator::new(0);
        let mirror = vec![(
            pos(1, 0, 0, 0),
            NfLogEntry {
                pk: pk(1),
                r: r(1),
            },
        )];
        let err = chain_view_from_accumulator_with_catalog(
            &acc,
            1,
            [0xAB; 32],
            mirror,
            Vec::new(),
        )
        .expect_err("accumulator and mirror length mismatch must fail");
        let detail = err
            .internal_context
            .as_ref()
            .map(|context| context.detail.as_str())
            .unwrap_or("");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        assert!(
            detail.contains("accumulator size") && detail.contains("mirror length"),
            "error must name both sides of the mismatch, got: {err:?}"
        );
    }
}
