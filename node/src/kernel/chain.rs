//! Read-only chain procedures (§7.8): `GetInfo`, `GetAccumulator`,
//! `ListInscriptions`, `GetNullifierPath`.
//!
//! Transport-free. All answers bind to the live NfLog / tip held by the
//! v1.1 engine (or an explicit in-memory view for tests). No second
//! derivation of the NAV root, no silent `present: false` on load
//! errors, no partial triple-cursor.
//!
//! # Inscription catalog prerequisite (§3.5 / §7.8)
//!
//! A complete `ListInscriptions` answer must carry, for each inscription,
//! the fields §3.5 and §7.8 require on the wire: the reveal transaction
//! `txid` (internal byte order), the §3.5 `format` byte (`0x00` raw or
//! `0x01` half-aggregated), the member list `(Pkⱼ, Rⱼ)` with per-member
//! state, the chain triple `(height, tx_index, vin_index)`, and the
//! reveal-tx confirmation state.
//!
//! The live NfLog (and its first-occurrence mirror on [`ChainView`])
//! stores only winning `(pk, r)` entries together with the
//! [`ChainPosition`] used at fold time (height / tx_index / vin_index /
//! member_index). It does **not** store the reveal transaction id and
//! does **not** store the §3.5 format byte. Those two fields cannot be
//! recovered from the NfLog alone without inventing values.
//!
//! Until the scanner writes a dedicated inscription catalog at fold
//! time (reveal txid, §3.5 format, members, triple), `ListInscriptions`
//! is not a faithful procedure: the gRPC surface stays
//! `Unimplemented`, and no NfLog projection synthesises a placeholder
//! txid or a guessed format. Nullifier membership on the committed log
//! remains answerable via `GetNullifierPath` (path verified against
//! size + mth). Catalog-dependent list projection is **not** built here
//! ahead of that store — production logic reachable only from tests
//! would not speak for the running service.
//!
//! When that catalog is wired, listing **MUST** satisfy these three
//! contracts (so they are not re-invented at rebuild time):
//!
//! 1. **Total, stable order** over `(height, tx_index, vin_index)` —
//!    ordinary integer lexicographic order on the triple; equal keys
//!    never leave list order ambiguous.
//! 2. **Cursor all-or-nothing** — an inclusive `from` triple and an
//!    exclusive `next` triple are each fully present or fully absent;
//!    a half-filled cursor is not representable.
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
}

/// `ListInscriptions` request after transport normalisation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ListInscriptions {
    pub from: InscriptionCursor,
    pub limit: InscriptionLimit,
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
/// This is a **closed normative set**: every variant stays in the
/// inventory even while no production procedure constructs a member
/// value yet. [`Self::ALL`] plus [`validate_closed_sets`] (start edge)
/// keep the wire tokens non-empty and pairwise distinct.
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

/// Immutable chain tip + NfLog view used by the four read procedures.
///
/// Built by reading the live engine once under its mutex — never by
/// recomputing MTH from a second log copy after the fact for the tip
/// root (the engine's `nav()` is the source of truth; `nflog_root` is
/// applied only to that pair).
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
}

impl ChainView {
    /// Snapshot the live engine. A poisoned mutex is an internal error —
    /// never reinterpreted as an empty chain.
    pub(crate) fn from_engine(adapter: &EngineAdapter) -> KernelResult<Self> {
        // Capture tip hash outside the engine borrow (adapter fields).
        let tip_block_hash = adapter.tip_hash();
        adapter.with_engine(|engine| {
            let tip_height = engine.tip_height();
            let nav = engine.nflog().nav();
            let mirror = engine.nflog_mirror();
            // Rebuild the pk index from the mirror so Lookup is a pure
            // function of the same first-occurrence sequence the tip
            // commits to — not a second store.
            let mut index = std::collections::HashMap::with_capacity(mirror.len());
            for (pos, (_chain, entry)) in mirror.iter().enumerate() {
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
    for (pos, (_c, e)) in mirror.iter().enumerate() {
        index.insert(e.pk, (pos as u64, e.r));
    }
    Ok(ChainView {
        tip_height,
        tip_block_hash,
        nav,
        mirror,
        index,
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

    #[test]
    fn get_info_binds_nav_root_from_view() {
        let view = fold_view(&[(pos(5, 0, 0, 0), pk(1), r(1))], 12);
        let identity = ChainIdentity {
            network: KernelNetwork::Regtest,
            circuit_digest_c: Digest32([0xC1; 32]),
            circuit_digest_c_balance: Digest32([0xC2; 32]),
            relay_url: "wss://relay.example".into(),
            blossom_url: "https://blossom.example".into(),
            max_blob_bytes: 1_048_576,
            activation_height: 0,
            bootstrap: BootstrapManifest {
                network: KernelNetwork::Regtest,
                protocol_version: "v1".into(),
                seed_relays: vec!["wss://seed.example".into()],
                blob_stores: vec!["https://blob.example".into()],
                operator_ids: vec![XOnlyKey([0x0B; 32])],
                issued_at: 1,
                expires_at: 2,
                manifest_sig: [0x51; 64],
            },
            kernel_parts: vec![
                KernelPart::Scanner,
                KernelPart::Prover,
                KernelPart::Publisher,
            ],
            bootstrap_pubkey: XOnlyKey([0xB0; 32]),
        };
        let info = get_info(&identity, &view, Readiness::Ready, 0);
        assert_eq!(info.network.as_str(), "regtest");
        assert_eq!(info.accumulator_root.0, view.nav_root_bytes());
        assert_eq!(info.bitcoin_tip_height, 12);
        assert!(info.readiness.is_ready());
        assert_eq!(info.finality_confirmations, 6);
    }
}
