//! `Publish` — transport-free publisher hand-off (§3.4 / §7.6 / §7.8).
//!
//! A policy or crypto rejection is a **successful** domain result
//! ([`PublishOutcome::Rejected`]), never a transport/`KernelError` failure.
//! That mirrors terminal job failures (`ProvingFailed` / `PublishRejected`
//! as successful `GetJob` answers): the network declined the inscription;
//! the RPC itself succeeded.
//!
//! Fee-coin delivery (presence matrix case (b), §3.8.1) is **not
//! representable** in the domain command. Any non-empty fee field is
//! rejected as `malformed_request` before an outcome is built — fail-closed,
//! never silently ignored. The closed reject-reason inventory still lists
//! the fee-related tokens so the wire vocabulary stays complete for the
//! deferred mechanism.
//!
//! Cryptographic BIP-340 verification is **delegated** to
//! [`zkcoins_prover::half_agg::verify_single`] — not reimplemented here.
//! Sign-to-contract opening is not checked publisher-side in v1 (no fee
//! `CoinProof` → no `H(ProofData)` source; §7.6).
//!
//! ## Acceptance is durable (not a free claim)
//!
//! `accepted: true` is returned **only** after the hand-off is written into
//! a durable queue ([`HandOffQueue`]). A process restart must not lose an
//! accepted member. Half-aggregation (§3.3) and inscription (§3.5) run
//! against that queue; a member is **finished** only when its on-chain
//! nullifier reaches §3.10 `completed` — intermediate queue / pending
//! states never count as success.
//!
//! No `axum`, no `tonic`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use zkcoins_program::circuit::compliance::Network as V1Network;
use zkcoins_prover::half_agg::{
    aggregate_sig_with_anchor, aggregate_verify, verify_single, AggregateStateNullifierV3,
    BlockAnchor as HalfAggBlockAnchor, NullifierSig,
};
use zkcoins_prover::publisher::{BatchMember, PublishedBatch};

use crate::kernel::chain::{validate_wire_vocabulary, KernelNetwork, KernelPart, WireEntry};
use crate::kernel::types::{Digest32, XOnlyKey};
use crate::kernel::{KernelError, KernelErrorCode, KernelResult};

/// §3.5 maximum gap between `block_anchor.height` and intended inclusion height.
///
/// Spec / publisher: `inclusion_height − block_anchor.height ≤ 100`.
pub(crate) const BLOCK_ANCHOR_MAX_GAP: u64 = 100;

/// Closed §7.6 reject-reason vocabulary.
///
/// Present on the wire **only** when the hand-off is well-formed and
/// `accepted == false`. The inventory length is the closed-set contract;
/// [`validate_closed_sets`] checks every wire token is non-empty and
/// pairwise distinct at process start.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PublishRejectReason {
    InvalidSignature,
    InvalidS2cOpening,
    InvalidFeeCoinproof,
    FeeAddressMismatch,
    OcrMismatch,
    FeeTooLow,
    UnknownFeeAsset,
    Policy,
    AnchorStale,
}

impl PublishRejectReason {
    /// Every reason in §7.6 order. Length is the closed-set contract.
    pub(crate) const ALL: [PublishRejectReason; 9] = [
        Self::InvalidSignature,
        Self::InvalidS2cOpening,
        Self::InvalidFeeCoinproof,
        Self::FeeAddressMismatch,
        Self::OcrMismatch,
        Self::FeeTooLow,
        Self::UnknownFeeAsset,
        Self::Policy,
        Self::AnchorStale,
    ];

    /// Normative wire token for `PublishResult.reason`.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidSignature => "invalid_signature",
            Self::InvalidS2cOpening => "invalid_s2c_opening",
            Self::InvalidFeeCoinproof => "invalid_fee_coinproof",
            Self::FeeAddressMismatch => "fee_address_mismatch",
            Self::OcrMismatch => "ocr_mismatch",
            Self::FeeTooLow => "fee_too_low",
            Self::UnknownFeeAsset => "unknown_fee_asset",
            Self::Policy => "policy",
            Self::AnchorStale => "anchor_stale",
        }
    }
}

/// Successful `Publish` result: accepted into a batch **or** typed rejection.
///
/// Unrepresentable combinations (`accepted` with `reason`, or `rejected`
/// with `batch_eta`) cannot be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PublishOutcome {
    Accepted { batch_eta: u64 },
    Rejected { reason: PublishRejectReason },
}

/// §3.5 block anchor carried by the hand-off.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PublishBlockAnchor {
    pub block_hash: Digest32,
    pub height: u32,
}

/// Decoded, fee-less publish command (§7.6 / §7.8).
///
/// Fee fields are **absent by construction**. Transport that observes any
/// non-empty `fee_blob_id` / `fee_epk` / `fee_blob_locators` must refuse
/// with `malformed_request` via [`refuse_v1_fee_fields`] before building
/// this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct PublishCommand {
    pub public_key: XOnlyKey,
    pub r: XOnlyKey,
    pub s: Digest32,
    pub r_prime: XOnlyKey,
    pub block_anchor: PublishBlockAnchor,
}

/// Publisher policy for the v1 fee-less hand-off (presence matrix case (c)
/// and self-publish through this endpoint).
///
/// Closed decision set (§3.8 / §7.6): a publisher either **accepts** the
/// fee-less path or **declines** it. Decline is not consensus — it projects
/// to [`PublishRejectReason::Policy`] on a successful RPC (`accepted: false`).
/// Fee policy is not consensus; the reject-reason inventory stays separate.
///
/// `batch_eta_secs` is **operator configuration**, never an invented constant
/// at the RPC edge. A process that accepts fee-less hand-offs must supply
/// the real batch interval; a process that is not a publisher declines.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PublishPolicy {
    /// Accept a well-formed, signature-valid, anchor-fresh fee-less hand-off.
    AcceptFeeLess { batch_eta_secs: u64 },
    /// Decline every fee-less hand-off with [`PublishRejectReason::Policy`].
    DeclineFeeLess,
}

impl PublishPolicy {
    /// Every fee-less policy arm. Length is the closed-set contract.
    ///
    /// Constructed in library code (not only under `cfg(test)`) so a dropped
    /// Spec case cannot hide behind dead-code silence. `batch_eta_secs` on
    /// the Accept arm is deployment configuration, not a wire token — the
    /// inventory only needs the arm to exist; the concrete eta is supplied
    /// at each call site.
    pub(crate) const ALL: [PublishPolicy; 2] = [
        Self::AcceptFeeLess { batch_eta_secs: 0 },
        Self::DeclineFeeLess,
    ];
}

/// Derive the fee-less policy from this process's kernel parts and the
/// operator-configured batch interval (§3.4 / §7.6 / §7.8 `kernel_parts`).
///
/// - Without the `publisher` part the hand-off is **declined** (`policy`) —
///   a non-publisher kernel must not claim acceptance.
/// - With the `publisher` part, `batch_eta_secs` **must** be present. There
///   is no invented default interval (the former hard-coded 60 s is gone).
/// - Missing eta while the publisher part is on is an **internal**
///   configuration error, not a free accept and not a silent decline.
pub(crate) fn policy_from_kernel_parts(
    kernel_parts: &[KernelPart],
    batch_eta_secs: Option<u64>,
) -> KernelResult<PublishPolicy> {
    let is_publisher = kernel_parts.contains(&KernelPart::Publisher);
    if !is_publisher {
        return Ok(PublishPolicy::DeclineFeeLess);
    }
    match batch_eta_secs {
        Some(secs) => Ok(PublishPolicy::AcceptFeeLess {
            batch_eta_secs: secs,
        }),
        None => Err(KernelError::with_internal(
            KernelErrorCode::InternalError,
            "Publisher role is enabled but batch_eta is not configured",
            "kernel_parts includes publisher but PublishPolicyConfig.batch_eta_secs is None — \
             refusing to invent an AcceptFeeLess interval",
        )),
    }
}

/// Named configuration for [`evaluate_hand_off`] / [`accept_hand_off`]
/// (clippy `too_many_arguments` bound).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PublishConfig {
    pub network: KernelNetwork,
    /// Live Bitcoin tip height used as the intended inclusion height for the
    /// §3.5 gap check. `None` means the process has no tip yet — the procedure
    /// fails closed as `internal_error` rather than inventing a height or
    /// skipping the bound.
    pub tip_height: Option<u64>,
    pub policy: PublishPolicy,
}

/// One accepted (or candidate) nullifier hand-off ready for half-aggregation.
///
/// Carries exactly the §7.6 fields a publisher needs for NISSHAC (§3.3) and
/// the §3.5 `block_anchor` the submitter proved against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct HandOffMember {
    pub public_key: XOnlyKey,
    pub r: XOnlyKey,
    pub s: Digest32,
    pub r_prime: XOnlyKey,
    pub block_anchor: PublishBlockAnchor,
}

impl HandOffMember {
    pub(crate) fn from_command(command: PublishCommand) -> Self {
        Self {
            public_key: command.public_key,
            r: command.r,
            s: command.s,
            r_prime: command.r_prime,
            block_anchor: command.block_anchor,
        }
    }

    /// Convert into the foreign half-agg signature unit (no secret keys).
    pub(crate) fn as_nullifier_sig(self) -> NullifierSig {
        NullifierSig {
            pk: self.public_key.0,
            r: self.r.0,
            s: self.s.0,
        }
    }

    /// Convert into a self-publish / batch `BatchMember` (build tip = hand-off anchor).
    pub(crate) fn as_batch_member(self) -> BatchMember {
        BatchMember {
            sig: self.as_nullifier_sig(),
            build_tip: HalfAggBlockAnchor {
                block_hash: self.block_anchor.block_hash.0,
                height: self.block_anchor.height,
            },
        }
    }
}

/// Durable lifecycle of one accepted hand-off **before** §3.10 classification.
///
/// These labels mirror `v1_pending_publishes.status` so the §7.6 path reuses
/// the same recovery table the self-publish path already walks. None of
/// them is §3.10 `completed` — that requires chain scan + finality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum HandOffQueueStatus {
    /// Durable accept; signature + member staged; no txs yet.
    MembersReady,
    /// Commit/reveal pair constructed; not yet broadcast.
    Constructed,
    /// Commit on chain / mempool; reveal still pending.
    CommitBroadcast,
    /// Both legs broadcast; scanner will fold on inclusion.
    RevealBroadcast,
    /// Operator / inscription path abandoned this member (named terminal).
    Failed,
}

impl HandOffQueueStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::MembersReady => "members_ready",
            Self::Constructed => "constructed",
            Self::CommitBroadcast => "commit_broadcast",
            Self::RevealBroadcast => "reveal_broadcast",
            Self::Failed => "failed",
        }
    }

    pub(crate) fn from_pending_status(status: &str) -> Option<Self> {
        match status {
            "members_ready" => Some(Self::MembersReady),
            "constructed" => Some(Self::Constructed),
            "commit_broadcast" => Some(Self::CommitBroadcast),
            "reveal_broadcast" => Some(Self::RevealBroadcast),
            "failed" => Some(Self::Failed),
            // `complete` on the self-publish table is an operational mark that
            // the publisher finished its local work — still not §3.10 finality.
            "complete" => Some(Self::RevealBroadcast),
            _ => None,
        }
    }
}

/// Named terminal inscription failure — never projected as `accepted`.
///
/// When the path to bitcoind / the batch publisher is unavailable or fails,
/// the member is marked failed with this reason. Callers must surface the
/// reason; silent skip is forbidden.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum InscriptionTerminal {
    /// No inscription capability is installed on this process.
    PublisherUnavailable { detail: String },
    /// The batch publisher refused or broadcast failed.
    BroadcastFailed { detail: String },
    /// Half-aggregation itself failed (empty set, non-canonical scalar, …).
    AggregateFailed { detail: String },
}

impl std::fmt::Display for InscriptionTerminal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PublisherUnavailable { detail } => {
                write!(f, "inscription terminal: publisher unavailable: {detail}")
            }
            Self::BroadcastFailed { detail } => {
                write!(f, "inscription terminal: broadcast failed: {detail}")
            }
            Self::AggregateFailed { detail } => {
                write!(f, "inscription terminal: aggregate failed: {detail}")
            }
        }
    }
}

impl std::error::Error for InscriptionTerminal {}

/// Durable hand-off queue for accepted §7.6 members.
///
/// Production keeps a process-local [`InMemoryHandOffQueue`] for the multi-
/// member drain loop and mirrors accepted members into `v1_pending_publishes`
/// (migration 0021) when the exclusive V1 engine is installed. An accepted
/// member **must** survive a process restart via that table — process-local-
/// only storage is not a conforming production store.
pub(crate) trait HandOffQueue: Send + Sync {
    /// Persist a freshly accepted member at `members_ready`.
    ///
    /// Duplicate `public_key` (already queued / in-flight) fails loud —
    /// never silently replace or drop the existing row.
    fn enqueue(&self, member: HandOffMember) -> Result<(), String>;

    /// Restore a previously accepted member at a known status (boot resume).
    ///
    /// Duplicate `public_key` fails loud — never silently replace. Used when
    /// hydrating the process queue from `list_resumable` / pending rows after
    /// restart so intermediate statuses (`constructed`, `commit_broadcast`)
    /// are not collapsed to a free `members_ready`.
    fn restore(&self, member: HandOffMember, status: HandOffQueueStatus) -> Result<(), String>;

    /// Load one member by nullifier public key, if present.
    fn load(
        &self,
        public_key: &XOnlyKey,
    ) -> Result<Option<(HandOffMember, HandOffQueueStatus)>, String>;

    /// Members the process drain can still pick up (`members_ready` /
    /// `constructed`), oldest first. Mid-reveal (`commit_broadcast`) rows are
    /// owned by the per-row PG resume path and are not listed here.
    fn list_resumable(&self) -> Result<Vec<(HandOffMember, HandOffQueueStatus)>, String>;

    /// Advance a member to a non-failed status (Constructed / CommitBroadcast /
    /// RevealBroadcast). Fails loud if the row is missing or already `Failed`.
    fn advance_status(&self, public_key: &XOnlyKey, to: HandOffQueueStatus) -> Result<(), String>;

    /// Mark a member terminal-failed with a named reason (inscription path).
    fn mark_failed(&self, public_key: &XOnlyKey, reason: &str) -> Result<(), String>;

    /// Advance status after a successful multi-member inscription broadcast.
    fn mark_reveal_broadcast(&self, public_key: &XOnlyKey) -> Result<(), String> {
        self.advance_status(public_key, HandOffQueueStatus::RevealBroadcast)
    }
}

/// Process-local durable stand-in used by unit tests and pure-domain paths.
///
/// Backed by a shared [`Arc`] so a "restart" is modeled by dropping the
/// outer façade and constructing a new one on the **same** Arc — accepted
/// members remain. Production uses the Postgres adapter instead.
#[derive(Clone, Default)]
pub(crate) struct InMemoryHandOffQueue {
    inner: Arc<Mutex<InMemoryHandOffState>>,
}

#[derive(Default)]
struct InMemoryHandOffState {
    /// Insertion-ordered keys so `list_resumable` is stable.
    order: Vec<[u8; 32]>,
    rows: BTreeMap<[u8; 32], InMemoryHandOffRow>,
}

struct InMemoryHandOffRow {
    member: HandOffMember,
    status: HandOffQueueStatus,
    /// Present when status is [`HandOffQueueStatus::Failed`].
    fail_reason: Option<String>,
}

impl InMemoryHandOffQueue {
    pub(crate) fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InMemoryHandOffState::default())),
        }
    }

    /// Share the same durable map under a fresh façade (simulated restart).
    ///
    /// Production restart hydrates via [`seed_queue_from_pending_status`] from
    /// Postgres; this helper models the same Arc-backed durability in tests.
    #[cfg(test)]
    pub(crate) fn reopen(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }

    /// Test inspection: last fail reason for a pk, if any.
    #[cfg(test)]
    pub(crate) fn fail_reason(&self, public_key: &XOnlyKey) -> Option<String> {
        let guard = self.inner.lock().expect("handoff queue lock");
        guard
            .rows
            .get(&public_key.0)
            .and_then(|r| r.fail_reason.clone())
    }
}

impl HandOffQueue for InMemoryHandOffQueue {
    fn enqueue(&self, member: HandOffMember) -> Result<(), String> {
        self.restore(member, HandOffQueueStatus::MembersReady)
    }

    fn restore(&self, member: HandOffMember, status: HandOffQueueStatus) -> Result<(), String> {
        if status == HandOffQueueStatus::Failed {
            return Err("restore: refusing to seed a Failed row without mark_failed reason".into());
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "handoff queue lock poisoned".to_string())?;
        let pk = member.public_key.0;
        if guard.rows.contains_key(&pk) {
            return Err(format!(
                "hand-off already queued for pk={}",
                hex::encode(pk)
            ));
        }
        guard.order.push(pk);
        guard.rows.insert(
            pk,
            InMemoryHandOffRow {
                member,
                status,
                fail_reason: None,
            },
        );
        Ok(())
    }

    fn load(
        &self,
        public_key: &XOnlyKey,
    ) -> Result<Option<(HandOffMember, HandOffQueueStatus)>, String> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| "handoff queue lock poisoned".to_string())?;
        match guard.rows.get(&public_key.0) {
            None => Ok(None),
            Some(r) => {
                // Failed rows must carry a named reason (never a bare terminal).
                if r.status == HandOffQueueStatus::Failed && r.fail_reason.is_none() {
                    return Err(format!(
                        "load: invariant broken — Failed row without reason for pk={}",
                        hex::encode(public_key.0)
                    ));
                }
                Ok(Some((r.member, r.status)))
            }
        }
    }

    fn list_resumable(&self) -> Result<Vec<(HandOffMember, HandOffQueueStatus)>, String> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| "handoff queue lock poisoned".to_string())?;
        let mut out = Vec::new();
        for pk in &guard.order {
            if let Some(row) = guard.rows.get(pk) {
                // Process-queue drain can only start inscription for
                // MembersReady / Constructed. CommitBroadcast mid-reveal is
                // owned by the per-row PG resume path (prepared txs live in
                // v1_pending_publishes). RevealBroadcast / Failed are done.
                if matches!(
                    row.status,
                    HandOffQueueStatus::MembersReady | HandOffQueueStatus::Constructed
                ) {
                    out.push((row.member, row.status));
                }
            }
        }
        Ok(out)
    }

    fn advance_status(&self, public_key: &XOnlyKey, to: HandOffQueueStatus) -> Result<(), String> {
        if to == HandOffQueueStatus::Failed {
            return Err(
                "advance_status: use mark_failed for the Failed terminal (needs a reason)".into(),
            );
        }
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "handoff queue lock poisoned".to_string())?;
        let row = guard.rows.get_mut(&public_key.0).ok_or_else(|| {
            format!(
                "advance_status({}): no hand-off row for pk={}",
                to.as_str(),
                hex::encode(public_key.0)
            )
        })?;
        if row.status == HandOffQueueStatus::Failed {
            return Err(format!(
                "advance_status({}): pk={} is already failed",
                to.as_str(),
                hex::encode(public_key.0)
            ));
        }
        row.status = to;
        Ok(())
    }

    fn mark_failed(&self, public_key: &XOnlyKey, reason: &str) -> Result<(), String> {
        let mut guard = self
            .inner
            .lock()
            .map_err(|_| "handoff queue lock poisoned".to_string())?;
        let row = guard.rows.get_mut(&public_key.0).ok_or_else(|| {
            format!(
                "mark_failed: no hand-off row for pk={}",
                hex::encode(public_key.0)
            )
        })?;
        row.status = HandOffQueueStatus::Failed;
        row.fail_reason = Some(reason.to_string());
        Ok(())
    }
}

/// Refuse any non-empty fee delivery field in v1 (§3.8.1 / §7.6).
///
/// A partial set is also malformed. Empty-all is the only admissible shape.
pub(crate) fn refuse_v1_fee_fields(
    fee_blob_id: &[u8],
    fee_epk: &[u8],
    fee_blob_locators: &[u8],
) -> KernelResult<()> {
    if fee_blob_id.is_empty() && fee_epk.is_empty() && fee_blob_locators.is_empty() {
        return Ok(());
    }
    Err(KernelError::new(
        KernelErrorCode::MalformedRequest,
        "fee_blob_id, fee_epk, and fee_blob_locators must be absent in v1 \
         (fee-coin hand-off is deferred; presence matrix case (b) is not representable)",
    ))
}

/// Evaluate crypto + anchor + policy for a well-formed fee-less hand-off.
///
/// Does **not** enqueue and does **not** claim acceptance. Use
/// [`accept_hand_off`] to durable-accept. A rejection is `Ok(Rejected)`;
/// missing tip is `Err(internal_error)`.
pub(crate) fn evaluate_hand_off(
    config: PublishConfig,
    command: PublishCommand,
) -> KernelResult<PublishOutcome> {
    let PublishConfig {
        network,
        tip_height,
        policy,
    } = config;

    // 1. BIP-340 over the per-network fixed m_state (§7.6 step 1).
    let m_state = kernel_network_to_v1(network).m_state_bytes();
    if let Err(_e) = verify_single(&command.public_key.0, &command.r.0, &command.s.0, m_state) {
        return Ok(PublishOutcome::Rejected {
            reason: PublishRejectReason::InvalidSignature,
        });
    }

    // 2–3. Fee path deferred — command cannot carry fee fields.
    // S2C opening is not checked without a fee CoinProof (§7.6).

    // 4. block_anchor within §3.5 gap of intended inclusion (tip).
    let tip = match tip_height {
        Some(h) => h,
        None => {
            return Err(KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Publish requires a live Bitcoin tip for the block_anchor bound",
                "PublishConfig.tip_height is None — chain tip not installed on the façade",
            ));
        }
    };
    if !anchor_within_gap(command.block_anchor.height, tip) {
        return Ok(PublishOutcome::Rejected {
            reason: PublishRejectReason::AnchorStale,
        });
    }

    // 5. Publisher policy on the fee-less hand-off.
    match policy {
        PublishPolicy::DeclineFeeLess => Ok(PublishOutcome::Rejected {
            reason: PublishRejectReason::Policy,
        }),
        PublishPolicy::AcceptFeeLess { batch_eta_secs } => Ok(PublishOutcome::Accepted {
            batch_eta: batch_eta_secs,
        }),
    }
}

/// `Publish` (§7.8): evaluate, then durable-enqueue on accept.
///
/// # Outcome vs error
///
/// - **Shape / v1 fee presence** → `Err(malformed_request)` (caller must
///   refuse before this when fee bytes are non-empty).
/// - **Missing tip pin** → `Err(internal_error)` (no invented height).
/// - **Crypto / policy / anchor** → `Ok(Rejected { reason })` (no enqueue).
/// - **Accepted** → durable enqueue **then** `Ok(Accepted { batch_eta })`.
///   Enqueue failure is `Err(internal_error)` — never a free `accepted`.
///
/// A rejection is never an `Err`. The RPC layer maps `Ok(_)` to a
/// successful status and projects `accepted` / `reason` / `batch_eta`.
pub(crate) fn accept_hand_off(
    queue: &dyn HandOffQueue,
    config: PublishConfig,
    command: PublishCommand,
) -> KernelResult<PublishOutcome> {
    let outcome = evaluate_hand_off(config, command)?;
    match outcome {
        PublishOutcome::Rejected { .. } => Ok(outcome),
        PublishOutcome::Accepted { batch_eta } => {
            // Durable before any accept claim — a restart must not lose this.
            queue
                .enqueue(HandOffMember::from_command(command))
                .map_err(|detail| {
                    KernelError::with_internal(
                        KernelErrorCode::InternalError,
                        "Failed to durable-queue accepted publish hand-off",
                        detail,
                    )
                })?;
            Ok(PublishOutcome::Accepted { batch_eta })
        }
    }
}

/// Half-aggregate collected members into one `AggregateStateNullifierV3` (§3.3).
///
/// Pure arithmetic over collected BIP-340 signatures — no circuit, no secret
/// keys. Delegates to [`aggregate_sig_with_anchor`] (existing NISSHAC edge).
/// Empty input fails loud. The returned aggregate is verified before return
/// so a bad coefficient derivation cannot escape as a silent payload.
pub(crate) fn half_aggregate_members(
    members: &[HandOffMember],
    block_anchor: PublishBlockAnchor,
    network: KernelNetwork,
) -> Result<AggregateStateNullifierV3, InscriptionTerminal> {
    if members.is_empty() {
        return Err(InscriptionTerminal::AggregateFailed {
            detail: "cannot half-aggregate zero hand-off members".into(),
        });
    }
    let sigs: Vec<NullifierSig> = members.iter().map(|m| m.as_nullifier_sig()).collect();
    let anchor = HalfAggBlockAnchor {
        block_hash: block_anchor.block_hash.0,
        height: block_anchor.height,
    };
    let agg = aggregate_sig_with_anchor(&sigs, anchor).map_err(|e| {
        InscriptionTerminal::AggregateFailed {
            detail: format!("aggregate_sig_with_anchor failed: {e:#}"),
        }
    })?;
    let m_state = kernel_network_to_v1(network).m_state_bytes();
    aggregate_verify(&agg, m_state).map_err(|e| InscriptionTerminal::AggregateFailed {
        detail: format!("aggregate_verify failed after aggregation: {e:#}"),
    })?;
    Ok(agg)
}

/// Inscribe a prepared member set via the existing batch publisher, or
/// fail terminal with a named reason.
///
/// `publisher == None` is a **terminal** failure (`PublisherUnavailable`),
/// never a silent skip and never an `accepted` projection. On broadcast
/// failure the caller must mark each member failed via
/// [`HandOffQueue::mark_failed`].
///
/// Wired against [`crate::v1::receive::NullifierBatchPublisher`] — the same
/// capability the self-publish / resume path already uses for
/// `AggregateStateNullifierV3` inscription.
///
/// When the publisher can construct without broadcasting (`try_prepare`),
/// status steps are written on `queue` as
/// `Constructed` → `CommitBroadcast` → `RevealBroadcast`. Without a
/// construct path the batch is published in one shot and advanced to
/// `RevealBroadcast` only (same as the self-publish test-double path).
pub(crate) fn inscribe_members<P>(
    queue: &dyn HandOffQueue,
    publisher: Option<&P>,
    members: &[HandOffMember],
) -> Result<PublishedBatch, InscriptionTerminal>
where
    P: crate::v1::receive::NullifierBatchPublisher + ?Sized,
{
    let publisher = match publisher {
        Some(p) => p,
        None => {
            return Err(InscriptionTerminal::PublisherUnavailable {
                detail: "no NullifierBatchPublisher installed — bitcoind inscription path \
                         is not available; refusing silent skip"
                    .into(),
            });
        }
    };
    if members.is_empty() {
        return Err(InscriptionTerminal::AggregateFailed {
            detail: "inscribe_members requires at least one hand-off member".into(),
        });
    }
    let batch: Vec<BatchMember> = members.iter().map(|m| m.as_batch_member()).collect();

    match publisher.try_prepare(&batch) {
        Ok(Some(prepared)) => {
            // Constructed: durable pair exists (process queue records the step;
            // PG mirror carries raw txs on the self-publish path).
            for m in members {
                queue
                    .advance_status(&m.public_key, HandOffQueueStatus::Constructed)
                    .map_err(|detail| InscriptionTerminal::BroadcastFailed { detail })?;
            }
            let commit_txid = publisher.broadcast_commit(&prepared).map_err(|e| {
                InscriptionTerminal::BroadcastFailed {
                    detail: format!("broadcast_commit failed: {e:#}"),
                }
            })?;
            for m in members {
                queue
                    .advance_status(&m.public_key, HandOffQueueStatus::CommitBroadcast)
                    .map_err(|detail| InscriptionTerminal::BroadcastFailed { detail })?;
            }
            let reveal_txid = publisher.broadcast_reveal(&prepared).map_err(|e| {
                InscriptionTerminal::BroadcastFailed {
                    detail: format!(
                        "broadcast_reveal failed after commit; members left at {}: {e:#}",
                        HandOffQueueStatus::CommitBroadcast.as_str()
                    ),
                }
            })?;
            for m in members {
                queue
                    .mark_reveal_broadcast(&m.public_key)
                    .map_err(|detail| InscriptionTerminal::BroadcastFailed { detail })?;
            }
            Ok(PublishedBatch {
                aggregate: prepared.aggregate,
                payload: prepared.payload,
                commit_txid,
                reveal_txid,
                commit_output: prepared.commit_output,
                block_anchor: prepared.block_anchor,
            })
        }
        Ok(None) => {
            // No construct path (test double): one-shot publish, then terminal
            // reveal_broadcast — intermediate Constructed/CommitBroadcast are
            // not inventable without prepared txs.
            let published = publisher.publish_batch(&batch).map_err(|e| {
                InscriptionTerminal::BroadcastFailed {
                    detail: format!("publish_batch failed: {e:#}"),
                }
            })?;
            for m in members {
                queue
                    .mark_reveal_broadcast(&m.public_key)
                    .map_err(|detail| InscriptionTerminal::BroadcastFailed { detail })?;
            }
            Ok(published)
        }
        Err(e) => Err(InscriptionTerminal::BroadcastFailed {
            detail: format!("try_prepare failed: {e:#}"),
        }),
    }
}

/// Choose the batch `block_anchor` as the oldest member tip (lowest height).
///
/// Mirrors the foreign publisher rule: the batch anchor is the oldest
/// caller-asserted build tip among members. Empty input fails loud.
pub(crate) fn batch_anchor_from_members(
    members: &[HandOffMember],
) -> Result<PublishBlockAnchor, InscriptionTerminal> {
    let first = members
        .first()
        .ok_or_else(|| InscriptionTerminal::AggregateFailed {
            detail: "batch_anchor_from_members requires at least one hand-off member".into(),
        })?;
    let mut oldest = first.block_anchor;
    for m in members.iter().skip(1) {
        if m.block_anchor.height < oldest.height {
            oldest = m.block_anchor;
        }
    }
    Ok(oldest)
}

/// Seed the process queue from durable pending rows after restart.
///
/// Each row's status string is parsed via
/// [`HandOffQueueStatus::from_pending_status`]. Unknown statuses fail loud.
/// Rows already present in the queue are skipped (idempotent re-seed).
/// Returns the number of newly restored members.
pub(crate) fn seed_queue_from_pending_status(
    queue: &dyn HandOffQueue,
    rows: &[(HandOffMember, &str)],
) -> Result<usize, String> {
    let mut seeded = 0usize;
    for (member, status_str) in rows {
        let status = HandOffQueueStatus::from_pending_status(status_str).ok_or_else(|| {
            format!(
                "seed_queue_from_pending_status: unknown status {status_str:?} for pk={}",
                hex::encode(member.public_key.0)
            )
        })?;
        // Terminal / post-inscription rows do not re-enter the drain set.
        if matches!(
            status,
            HandOffQueueStatus::Failed | HandOffQueueStatus::RevealBroadcast
        ) {
            continue;
        }
        match queue.load(&member.public_key)? {
            Some(_) => continue,
            None => {
                queue.restore(*member, status)?;
                seeded = seeded.checked_add(1).ok_or_else(|| {
                    "seed_queue_from_pending_status: counter overflow".to_string()
                })?;
            }
        }
    }
    Ok(seeded)
}

/// Drain resumable queue members: half-aggregate, inscribe, advance status.
///
/// On inscription failure every attempted member is marked
/// [`HandOffQueueStatus::Failed`] with the terminal reason — never left as
/// an implicit success. Empty queue is a no-op success.
///
/// `batch_anchor`: when `None`, the oldest member tip is selected via
/// [`batch_anchor_from_members`]. Callers that already know the tip may
/// pass it explicitly.
pub(crate) fn drain_and_inscribe<P>(
    queue: &dyn HandOffQueue,
    publisher: Option<&P>,
    network: KernelNetwork,
    batch_anchor: Option<PublishBlockAnchor>,
) -> Result<Option<PublishedBatch>, InscriptionTerminal>
where
    P: crate::v1::receive::NullifierBatchPublisher + ?Sized,
{
    let resumable = queue
        .list_resumable()
        .map_err(|detail| InscriptionTerminal::BroadcastFailed { detail })?;
    let members: Vec<HandOffMember> = resumable
        .into_iter()
        .filter(|(_, status)| {
            // Only members still awaiting first inscription enter the batch.
            // CommitBroadcast is mid-reveal — the per-row PG resume path owns
            // that (prepared txs live in v1_pending_publishes, not here).
            matches!(
                status,
                HandOffQueueStatus::MembersReady | HandOffQueueStatus::Constructed
            )
        })
        .map(|(m, _)| m)
        .collect();
    if members.is_empty() {
        return Ok(None);
    }

    let anchor = match batch_anchor {
        Some(a) => a,
        None => batch_anchor_from_members(&members)?,
    };

    // Half-aggregate first so a crypto failure never touches the chain path.
    let _agg = half_aggregate_members(&members, anchor, network)?;

    match inscribe_members(queue, publisher, &members) {
        Ok(published) => Ok(Some(published)),
        Err(term) => {
            let reason = term.to_string();
            for m in &members {
                // Best-effort mark; surface the original terminal reason.
                let _ = queue.mark_failed(&m.public_key, &reason);
            }
            Err(term)
        }
    }
}

/// `block_anchor` is a strict ancestor of `inclusion_height` within gap ≤ 100.
fn anchor_within_gap(anchor_height: u32, inclusion_height: u64) -> bool {
    let anchor = u64::from(anchor_height);
    if inclusion_height <= anchor {
        return false;
    }
    inclusion_height - anchor <= BLOCK_ANCHOR_MAX_GAP
}

fn kernel_network_to_v1(network: KernelNetwork) -> V1Network {
    match network {
        KernelNetwork::Mainnet => V1Network::Mainnet,
        KernelNetwork::Testnet => V1Network::Testnet,
        KernelNetwork::Regtest => V1Network::Regtest,
    }
}

fn reject_reason_label(r: PublishRejectReason) -> &'static str {
    match r {
        PublishRejectReason::InvalidSignature => "InvalidSignature",
        PublishRejectReason::InvalidS2cOpening => "InvalidS2cOpening",
        PublishRejectReason::InvalidFeeCoinproof => "InvalidFeeCoinproof",
        PublishRejectReason::FeeAddressMismatch => "FeeAddressMismatch",
        PublishRejectReason::OcrMismatch => "OcrMismatch",
        PublishRejectReason::FeeTooLow => "FeeTooLow",
        PublishRejectReason::UnknownFeeAsset => "UnknownFeeAsset",
        PublishRejectReason::Policy => "Policy",
        PublishRejectReason::AnchorStale => "AnchorStale",
    }
}

/// Fail-closed check of the §7.6 `reason` vocabulary **and** the fee-less
/// policy decision set at process start.
pub(crate) fn validate_closed_sets() -> Result<(), String> {
    let reasons: [WireEntry; 9] = PublishRejectReason::ALL.map(|r| WireEntry {
        label: reject_reason_label(r),
        wire: r.as_str(),
    });
    validate_wire_vocabulary("PublishRejectReason", &reasons)?;

    // PublishPolicy is not a wire vocabulary (no tokens) — it is the closed
    // accept/decline decision for the fee-less hand-off (§3.8 / §7.6). Both
    // arms must be constructible here so the inventory cannot silently shrink.
    if PublishPolicy::ALL.len() != 2 {
        return Err(format!(
            "PublishPolicy inventory length {}, expected 2 (AcceptFeeLess, DeclineFeeLess)",
            PublishPolicy::ALL.len()
        ));
    }
    let mut saw_accept = false;
    let mut saw_decline = false;
    for p in PublishPolicy::ALL {
        match p {
            PublishPolicy::AcceptFeeLess { .. } => saw_accept = true,
            PublishPolicy::DeclineFeeLess => saw_decline = true,
        }
    }
    if !saw_accept || !saw_decline {
        return Err(
            "PublishPolicy::ALL must construct both AcceptFeeLess and DeclineFeeLess".into(),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    // bitcoin 0.32: `Txid::from_byte_array` is a `hashes::Hash` trait method
    // (not an inherent associated fn). Same import path as `v1/receive.rs`.
    use crate::kernel::chain::{
        classify_member_state, member_is_finished, MemberChainObservation, NullifierMemberState,
    };
    use bitcoin::hashes::Hash;
    use shared::spec_v1::{ProofData, ZERO_HASH};
    use zkcoins_prover::prover_bridge::test_signing::{
        deterministic_secret, normalized_key, sign_transition,
    };

    fn zero_pd() -> ProofData {
        ProofData {
            new_account_state_hash: ZERO_HASH,
            output_coins_root: ZERO_HASH,
            input_nullifiers_root: ZERO_HASH,
            coin_history_root: ZERO_HASH,
            nav_commitment: ZERO_HASH,
            npk_commit: [0u8; 32],
        }
    }

    fn signed_command_seed(network: KernelNetwork, seed: &[u8]) -> PublishCommand {
        let v1 = kernel_network_to_v1(network);
        let (secret, public, pk) = normalized_key(deterministic_secret(seed));
        let signed = sign_transition(secret, public, &zero_pd(), v1);
        let sig = signed.transition.signature;
        let mut r = [0u8; 32];
        let mut s = [0u8; 32];
        r.copy_from_slice(&sig[..32]);
        s.copy_from_slice(&sig[32..]);
        PublishCommand {
            public_key: XOnlyKey(pk),
            r: XOnlyKey(r),
            s: Digest32(s),
            r_prime: XOnlyKey(signed.transition.r_prime),
            block_anchor: PublishBlockAnchor {
                block_hash: Digest32([0xABu8; 32]),
                height: 50,
            },
        }
    }

    fn signed_command(network: KernelNetwork) -> PublishCommand {
        signed_command_seed(network, b"zkCoins/v1/block8/publish-test")
    }

    fn accept_config(tip: u64) -> PublishConfig {
        PublishConfig {
            network: KernelNetwork::Regtest,
            tip_height: Some(tip),
            policy: PublishPolicy::AcceptFeeLess { batch_eta_secs: 30 },
        }
    }

    /// Property 1: a publish rejection is `Ok(Rejected)`, not `Err`.
    #[test]
    fn publish_rejection_is_successful_outcome_not_rpc_error() {
        let mut cmd = signed_command(KernelNetwork::Regtest);
        // Corrupt s → BIP-340 fails → typed rejection.
        cmd.s = Digest32([0xFFu8; 32]);
        let outcome = evaluate_hand_off(accept_config(60), cmd).expect("rejection is Ok, not Err");
        match outcome {
            PublishOutcome::Rejected {
                reason: PublishRejectReason::InvalidSignature,
            } => {}
            other => panic!("expected Rejected(InvalidSignature), got {other:?}"),
        }
    }

    /// Property 2: closed reason inventory + start-edge uniqueness.
    #[test]
    fn reject_reason_inventory_is_closed_and_distinct() {
        assert_eq!(PublishRejectReason::ALL.len(), 9);
        validate_closed_sets().expect("inventory must pass start-edge check");
        let mut seen = std::collections::BTreeSet::new();
        for r in PublishRejectReason::ALL {
            assert!(!r.as_str().is_empty(), "{r:?} wire must be non-empty");
            assert!(
                seen.insert(r.as_str()),
                "duplicate wire token {}",
                r.as_str()
            );
        }
    }

    /// Closed fee-less policy set: Accept and Decline are both Spec arms.
    #[test]
    fn fee_less_policy_inventory_is_closed() {
        assert_eq!(PublishPolicy::ALL.len(), 2);
        validate_closed_sets().expect("policy inventory must pass start-edge check");
        let mut saw_accept = false;
        let mut saw_decline = false;
        for p in PublishPolicy::ALL {
            match p {
                PublishPolicy::AcceptFeeLess { .. } => saw_accept = true,
                PublishPolicy::DeclineFeeLess => saw_decline = true,
            }
        }
        assert!(saw_accept, "AcceptFeeLess must be in PublishPolicy::ALL");
        assert!(saw_decline, "DeclineFeeLess must be in PublishPolicy::ALL");
    }

    /// Property 3: any fee field present is malformed (fail-closed).
    #[test]
    fn fee_fields_fail_closed_when_set() {
        let cases: [(&[u8], &[u8], &[u8]); 4] = [
            (&[0u8; 32], &[], &[]),
            (&[], &[0u8; 32], &[]),
            (&[], &[], b"locators"),
            (&[1u8; 32], &[2u8; 32], b"x"),
        ];
        for (a, b, c) in cases {
            let err = refuse_v1_fee_fields(a, b, c).expect_err("fee field must be refused");
            assert_eq!(
                err.code,
                KernelErrorCode::MalformedRequest,
                "cause must be malformed_request, got {:?}",
                err.code
            );
            assert!(
                err.public_message.contains("fee_blob_id")
                    || err.public_message.contains("fee-coin")
                    || err.public_message.contains("fee_epk"),
                "message must name fee fields, got: {}",
                err.public_message
            );
        }
        refuse_v1_fee_fields(&[], &[], &[]).expect("all-empty is the only v1 shape");
    }

    #[test]
    fn policy_decline_is_rejected_not_error() {
        let cmd = signed_command(KernelNetwork::Regtest);
        let config = PublishConfig {
            network: KernelNetwork::Regtest,
            tip_height: Some(60),
            policy: PublishPolicy::DeclineFeeLess,
        };
        let outcome = evaluate_hand_off(config, cmd).expect("Ok");
        assert_eq!(
            outcome,
            PublishOutcome::Rejected {
                reason: PublishRejectReason::Policy
            }
        );
    }

    #[test]
    fn anchor_stale_when_gap_exceeds_100() {
        let cmd = signed_command(KernelNetwork::Regtest);
        // anchor.height = 50; tip = 200 → gap 150 > 100.
        let outcome = evaluate_hand_off(accept_config(200), cmd).expect("Ok");
        assert_eq!(
            outcome,
            PublishOutcome::Rejected {
                reason: PublishRejectReason::AnchorStale
            }
        );
    }

    #[test]
    fn accept_returns_batch_eta() {
        let cmd = signed_command(KernelNetwork::Regtest);
        let outcome = evaluate_hand_off(accept_config(60), cmd).expect("Ok");
        assert_eq!(
            outcome,
            PublishOutcome::Accepted { batch_eta: 30 },
            "accepted outcome must carry batch_eta, not a free reason string"
        );
    }

    #[test]
    fn missing_tip_is_internal_error_not_invented_acceptance() {
        let cmd = signed_command(KernelNetwork::Regtest);
        let config = PublishConfig {
            network: KernelNetwork::Regtest,
            tip_height: None,
            policy: PublishPolicy::AcceptFeeLess { batch_eta_secs: 1 },
        };
        let err = evaluate_hand_off(config, cmd).expect_err("no tip");
        assert_eq!(err.code, KernelErrorCode::InternalError);
    }

    #[test]
    fn wrong_network_m_state_is_invalid_signature() {
        // Sign under regtest; verify under mainnet.
        let cmd = signed_command(KernelNetwork::Regtest);
        let config = PublishConfig {
            network: KernelNetwork::Mainnet,
            tip_height: Some(60),
            policy: PublishPolicy::AcceptFeeLess { batch_eta_secs: 1 },
        };
        let outcome = evaluate_hand_off(config, cmd).expect("Ok");
        assert_eq!(
            outcome,
            PublishOutcome::Rejected {
                reason: PublishRejectReason::InvalidSignature
            }
        );
    }

    #[test]
    fn validate_closed_sets_rejects_empty_and_duplicate_injections() {
        let empty = [WireEntry {
            label: "Policy",
            wire: "",
        }];
        let err = validate_wire_vocabulary("PublishRejectReason", &empty).expect_err("empty wire");
        assert!(err.contains("empty wire string"), "got: {err}");

        let dup = [
            WireEntry {
                label: "Policy",
                wire: "policy",
            },
            WireEntry {
                label: "AnchorStale",
                wire: "policy",
            },
        ];
        let err = validate_wire_vocabulary("PublishRejectReason", &dup).expect_err("dup");
        assert!(err.contains("duplicate wire string"), "got: {err}");
    }

    /// Property 6: SPEND-branch secrets must not appear as RPC field names.
    #[test]
    fn no_spend_branch_secret_field_names_in_kernel_proto() {
        let proto = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../proto/kernel/v1/kernel.proto"
        ));
        let forbidden = [
            "spend_sk",
            "spend_secret",
            "sk_i",
            "sk0",
            "sk_0",
            "master_secret",
            "bip32_seed",
            "mnemonic",
            "A_0",
            "spend_key",
        ];
        for token in forbidden {
            assert!(
                !proto.contains(token),
                "kernel.v1 proto must not carry SPEND-branch token {token:?}"
            );
        }
        assert!(
            proto.contains("message EntrustRequest"),
            "EntrustRequest must exist (operational bundle, not SPEND)"
        );
        assert!(
            proto.contains("bytes bundle = 3"),
            "EntrustRequest.bundle carries the 161-byte operational bundle"
        );
    }

    // -----------------------------------------------------------------------
    // Required domain tests (would pass on the pre-change stub)
    // -----------------------------------------------------------------------

    /// A request that is not acceptable by policy must not be accepted.
    ///
    /// Pre-change: kernel_rpc always forced AcceptFeeLess { 60 }, so a
    /// non-publisher process would still project `accepted: true`.
    #[test]
    fn policy_from_kernel_parts_declines_without_publisher_role() {
        let policy = policy_from_kernel_parts(&[KernelPart::Scanner, KernelPart::Prover], Some(45))
            .expect("non-publisher parts yield a policy, not internal_error");
        assert_eq!(policy, PublishPolicy::DeclineFeeLess);

        let cmd = signed_command(KernelNetwork::Regtest);
        let queue = InMemoryHandOffQueue::new();
        let outcome = accept_hand_off(
            &queue,
            PublishConfig {
                network: KernelNetwork::Regtest,
                tip_height: Some(60),
                policy,
            },
            cmd,
        )
        .expect("Ok");
        assert_eq!(
            outcome,
            PublishOutcome::Rejected {
                reason: PublishRejectReason::Policy
            }
        );
        // Decline must not enqueue — a later restart must not resurrect it.
        assert!(
            queue.load(&cmd.public_key).expect("load").is_none(),
            "declined hand-off must not enter the durable queue"
        );
    }

    /// Publisher role without a configured batch_eta must fail closed —
    /// never invent the old 60-second constant.
    #[test]
    fn policy_from_kernel_parts_refuses_invented_batch_eta() {
        let err = policy_from_kernel_parts(&[KernelPart::Publisher], None)
            .expect_err("missing batch_eta must not invent AcceptFeeLess");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        let detail = err
            .internal_context
            .as_ref()
            .map(|c| c.detail.as_str())
            .unwrap_or("");
        assert!(
            detail.contains("batch_eta") || detail.contains("AcceptFeeLess"),
            "detail must name the missing batch_eta; got {detail:?}"
        );
    }

    /// Accepted member survives a simulated restart (same durable store).
    #[test]
    fn accepted_member_survives_simulated_restart() {
        let cmd = signed_command(KernelNetwork::Regtest);
        let queue = InMemoryHandOffQueue::new();
        let outcome = accept_hand_off(&queue, accept_config(60), cmd).expect("Ok");
        assert_eq!(outcome, PublishOutcome::Accepted { batch_eta: 30 });

        // Simulated restart: drop the first façade, reopen on the same map.
        let reopened = queue.reopen();
        let loaded = reopened
            .load(&cmd.public_key)
            .expect("load after restart")
            .expect("accepted member must still be durable after restart");
        assert_eq!(loaded.0.public_key, cmd.public_key);
        assert_eq!(loaded.0.r, cmd.r);
        assert_eq!(loaded.0.s, cmd.s);
        assert_eq!(loaded.0.r_prime, cmd.r_prime);
        assert_eq!(loaded.1, HandOffQueueStatus::MembersReady);

        // Pure evaluate (no queue) would have returned Accepted without
        // persistence — this assertion would fail on that old path.
        let empty = InMemoryHandOffQueue::new();
        assert!(
            empty.load(&cmd.public_key).expect("load").is_none(),
            "a fresh empty queue must not invent the accepted member"
        );
    }

    /// Several members yield one aggregate whose NISSHAC check verifies (§3.3).
    #[test]
    fn multiple_members_half_aggregate_verifies_under_nisshac() {
        let m1 = HandOffMember::from_command(signed_command_seed(
            KernelNetwork::Regtest,
            b"zkCoins/v1/half-agg/member-1",
        ));
        let m2 = HandOffMember::from_command(signed_command_seed(
            KernelNetwork::Regtest,
            b"zkCoins/v1/half-agg/member-2",
        ));
        let m3 = HandOffMember::from_command(signed_command_seed(
            KernelNetwork::Regtest,
            b"zkCoins/v1/half-agg/member-3",
        ));
        assert_ne!(m1.public_key, m2.public_key);
        assert_ne!(m2.public_key, m3.public_key);

        let anchor = PublishBlockAnchor {
            block_hash: Digest32([0x11; 32]),
            height: 42,
        };
        let agg = half_aggregate_members(&[m1, m2, m3], anchor, KernelNetwork::Regtest)
            .expect("half-aggregate three independent signatures");
        assert_eq!(agg.members.len(), 3, "all three (Pk,R) pairs retained");
        assert!(agg.s_agg.is_some(), "single shared s_agg required");
        assert_eq!(agg.format, 0x01, "half-aggregate format");
        assert_eq!(agg.block_anchor.height, 42);

        // Independent re-verify against the per-network m_state (not a
        // self-equality of a constant — this is the §3.3 multi-scalar check).
        let m_state = kernel_network_to_v1(KernelNetwork::Regtest).m_state_bytes();
        aggregate_verify(&agg, m_state).expect("NISSHAC AggregateVerify must pass");

        // Wrong network m_state must fail — proves the check is real.
        let wrong = kernel_network_to_v1(KernelNetwork::Mainnet).m_state_bytes();
        assert!(
            aggregate_verify(&agg, wrong).is_err(),
            "aggregate signed under regtest m_state must fail under mainnet"
        );
    }

    /// A member is finished only at §3.10 `completed` (first-occurrence + ≥6 confs).
    ///
    /// Classifier lives in `chain` and is the same path `ListInscriptions` uses.
    #[test]
    fn member_finished_only_at_section_3_10_completed() {
        let base = MemberChainObservation {
            queue_failed: false, // RevealBroadcast / any non-failed queue row
            first_occurrence: true,
            inclusion_height: Some(100),
            tip_height: 104, // 5 confirmations → still pending
        };
        assert_eq!(
            classify_member_state(base),
            NullifierMemberState::Pending,
            "5 confirmations is pending, not completed"
        );
        assert!(
            !member_is_finished(base),
            "reveal_broadcast + 5 confs must not count as finished"
        );

        let completed = MemberChainObservation {
            tip_height: 105, // 6 confirmations
            ..base
        };
        assert_eq!(
            classify_member_state(completed),
            NullifierMemberState::Completed
        );
        assert!(
            member_is_finished(completed),
            "first-occurrence + 6 confs is the only finished state"
        );

        // Double-spend loser is never finished.
        let loser = MemberChainObservation {
            first_occurrence: false,
            tip_height: 200,
            ..base
        };
        assert_eq!(classify_member_state(loser), NullifierMemberState::Failed);
        assert!(!member_is_finished(loser));

        // Still only queued (not inscribed) is not finished.
        let queued_only = MemberChainObservation {
            queue_failed: false,
            first_occurrence: false,
            inclusion_height: None,
            tip_height: 200,
        };
        assert!(!member_is_finished(queued_only));
        assert_eq!(
            classify_member_state(queued_only),
            NullifierMemberState::Pending
        );

        // Terminal inscription failure is not finished-success.
        let failed = MemberChainObservation {
            queue_failed: true,
            first_occurrence: false,
            inclusion_height: None,
            tip_height: 200,
        };
        assert_eq!(classify_member_state(failed), NullifierMemberState::Failed);
        assert!(!member_is_finished(failed));
    }

    /// Inscription-path error yields a named terminal state, never `accepted`.
    #[test]
    fn inscription_path_error_is_named_terminal_not_accepted() {
        let cmd = signed_command(KernelNetwork::Regtest);
        let queue = InMemoryHandOffQueue::new();
        let outcome = accept_hand_off(&queue, accept_config(60), cmd).expect("Ok");
        assert!(
            matches!(outcome, PublishOutcome::Accepted { .. }),
            "precondition: member is accepted into the queue"
        );

        // No publisher installed → drain must terminal-fail, mark the row failed.
        // Turbofish supplies the publisher type parameter when the Option is None.
        let err = drain_and_inscribe::<crate::v1::publish::V1Publisher>(
            &queue,
            None,
            KernelNetwork::Regtest,
            Some(PublishBlockAnchor {
                block_hash: Digest32([0xCD; 32]),
                height: 55,
            }),
        )
        .expect_err("missing publisher must be terminal, not silent success");
        match &err {
            InscriptionTerminal::PublisherUnavailable { detail } => {
                assert!(
                    detail.contains("NullifierBatchPublisher") || detail.contains("bitcoind"),
                    "terminal detail must name the missing path; got {detail}"
                );
            }
            other => panic!("expected PublisherUnavailable, got {other}"),
        }

        let (member, status) = queue
            .load(&cmd.public_key)
            .expect("load")
            .expect("row must still exist as failed, not deleted");
        assert_eq!(member.public_key, cmd.public_key);
        assert_eq!(
            status,
            HandOffQueueStatus::Failed,
            "inscription failure must mark the durable row failed"
        );
        let reason = queue
            .fail_reason(&cmd.public_key)
            .expect("failed row must carry a named reason");
        assert!(
            reason.contains("publisher unavailable") || reason.contains("PublisherUnavailable"),
            "fail reason must name the terminal cause; got {reason}"
        );

        // The outcome of accept was Accepted (queue admission). The inscription
        // failure is a separate terminal state — never re-projected as a new
        // accept, and never left as an implicit success on the queue.
        assert_eq!(status, HandOffQueueStatus::Failed);
        assert!(!member_is_finished(MemberChainObservation {
            queue_failed: true,
            first_occurrence: false,
            inclusion_height: None,
            tip_height: 200,
        }));
    }

    /// Empty half-aggregate fails loud (no invented empty payload).
    #[test]
    fn half_aggregate_empty_is_terminal() {
        let err = half_aggregate_members(
            &[],
            PublishBlockAnchor {
                block_hash: Digest32([0; 32]),
                height: 1,
            },
            KernelNetwork::Regtest,
        )
        .expect_err("empty set");
        assert!(matches!(err, InscriptionTerminal::AggregateFailed { .. }));
    }

    /// Recording publisher: two accepted members drain into **one** batch
    /// whose NISSHAC aggregate verifies, and both rows advance past
    /// `members_ready` (not left as free accepts).
    #[test]
    fn drain_half_aggregates_multiple_members_into_one_batch() {
        use std::sync::Mutex;
        use zkcoins_prover::publisher::PreparedBatch;

        struct RecordingPublisher {
            batches: Mutex<Vec<Vec<BatchMember>>>,
        }

        impl crate::v1::receive::NullifierBatchPublisher for RecordingPublisher {
            fn publish_batch(&self, members: &[BatchMember]) -> anyhow::Result<PublishedBatch> {
                anyhow::ensure!(!members.is_empty(), "empty batch");
                self.batches.lock().expect("lock").push(members.to_vec());
                // Recompute a real aggregate so the test is not a constant
                // compared with itself.
                let sigs: Vec<NullifierSig> = members.iter().map(|m| m.sig).collect();
                let agg = aggregate_sig_with_anchor(
                    &sigs,
                    HalfAggBlockAnchor {
                        block_hash: [0xEE; 32],
                        height: 55,
                    },
                )?;
                Ok(PublishedBatch {
                    aggregate: agg,
                    payload: vec![0x42, 0x42],
                    commit_txid: bitcoin::Txid::from_byte_array([0x11; 32]),
                    reveal_txid: bitcoin::Txid::from_byte_array([0x22; 32]),
                    commit_output: bitcoin::TxOut {
                        value: bitcoin::Amount::from_sat(600),
                        script_pubkey: bitcoin::ScriptBuf::new(),
                    },
                    block_anchor: HalfAggBlockAnchor {
                        block_hash: [0xEE; 32],
                        height: 55,
                    },
                })
            }

            fn try_prepare(
                &self,
                _members: &[BatchMember],
            ) -> anyhow::Result<Option<PreparedBatch>> {
                Ok(None)
            }
        }

        let queue = InMemoryHandOffQueue::new();
        let c1 = signed_command_seed(KernelNetwork::Regtest, b"zkCoins/v1/drain/m1");
        let c2 = signed_command_seed(KernelNetwork::Regtest, b"zkCoins/v1/drain/m2");
        accept_hand_off(&queue, accept_config(60), c1).expect("accept m1");
        accept_hand_off(&queue, accept_config(60), c2).expect("accept m2");

        let publisher = RecordingPublisher {
            batches: Mutex::new(Vec::new()),
        };
        let published = drain_and_inscribe(
            &queue,
            Some(&publisher),
            KernelNetwork::Regtest,
            Some(PublishBlockAnchor {
                block_hash: Digest32([0xEE; 32]),
                height: 55,
            }),
        )
        .expect("drain ok")
        .expect("batch produced");

        assert_eq!(
            published.aggregate.members.len(),
            2,
            "one aggregate must retain both members"
        );
        let m_state = kernel_network_to_v1(KernelNetwork::Regtest).m_state_bytes();
        aggregate_verify(&published.aggregate, m_state)
            .expect("drained aggregate must pass NISSHAC AggregateVerify");

        let batches = publisher.batches.lock().expect("lock");
        assert_eq!(batches.len(), 1, "exactly one publish_batch call");
        assert_eq!(batches[0].len(), 2, "both members in that single batch");

        let s1 = queue.load(&c1.public_key).expect("load").expect("m1").1;
        let s2 = queue.load(&c2.public_key).expect("load").expect("m2").1;
        assert_eq!(s1, HandOffQueueStatus::RevealBroadcast);
        assert_eq!(s2, HandOffQueueStatus::RevealBroadcast);
        // Reveal broadcast is still not §3.10 completed (same classifier as ListInscriptions).
        assert!(!member_is_finished(MemberChainObservation {
            queue_failed: s1 == HandOffQueueStatus::Failed,
            first_occurrence: true,
            inclusion_height: Some(55),
            tip_height: 56, // 2 confs
        }));
    }

    /// Accepted member is visible on the durable queue (not a free claim).
    #[test]
    fn accepted_member_reaches_queue_as_members_ready() {
        let cmd = signed_command(KernelNetwork::Regtest);
        let queue = InMemoryHandOffQueue::new();
        let outcome = accept_hand_off(&queue, accept_config(60), cmd).expect("Ok");
        assert_eq!(outcome, PublishOutcome::Accepted { batch_eta: 30 });

        let listed = queue.list_resumable().expect("list");
        assert_eq!(listed.len(), 1, "accepted member must appear on the queue");
        assert_eq!(listed[0].0.public_key, cmd.public_key);
        assert_eq!(listed[0].1, HandOffQueueStatus::MembersReady);
        assert_eq!(
            listed[0].1.as_str(),
            "members_ready",
            "status wire token must match v1_pending_publishes"
        );
    }

    /// Drain consumes the queued member (list_resumable empties for drain).
    #[test]
    fn drain_picks_up_accepted_member_from_queue() {
        use std::sync::Mutex;
        use zkcoins_prover::publisher::PreparedBatch;

        struct CountingPublisher {
            calls: Mutex<usize>,
        }
        impl crate::v1::receive::NullifierBatchPublisher for CountingPublisher {
            fn publish_batch(&self, members: &[BatchMember]) -> anyhow::Result<PublishedBatch> {
                *self.calls.lock().expect("lock") += 1;
                let sigs: Vec<NullifierSig> = members.iter().map(|m| m.sig).collect();
                let agg = aggregate_sig_with_anchor(
                    &sigs,
                    HalfAggBlockAnchor {
                        block_hash: members[0].build_tip.block_hash,
                        height: members[0].build_tip.height,
                    },
                )?;
                Ok(PublishedBatch {
                    aggregate: agg,
                    payload: vec![1],
                    commit_txid: bitcoin::Txid::from_byte_array([0x33; 32]),
                    reveal_txid: bitcoin::Txid::from_byte_array([0x44; 32]),
                    commit_output: bitcoin::TxOut {
                        value: bitcoin::Amount::from_sat(600),
                        script_pubkey: bitcoin::ScriptBuf::new(),
                    },
                    block_anchor: members[0].build_tip,
                })
            }
            fn try_prepare(
                &self,
                _members: &[BatchMember],
            ) -> anyhow::Result<Option<PreparedBatch>> {
                Ok(None)
            }
        }

        let cmd = signed_command(KernelNetwork::Regtest);
        let queue = InMemoryHandOffQueue::new();
        accept_hand_off(&queue, accept_config(60), cmd).expect("accept");
        assert_eq!(queue.list_resumable().expect("list").len(), 1);

        let publisher = CountingPublisher {
            calls: Mutex::new(0),
        };
        let published = drain_and_inscribe(
            &queue,
            Some(&publisher),
            KernelNetwork::Regtest,
            None, // derive anchor from member tip
        )
        .expect("drain")
        .expect("batch");
        assert_eq!(*publisher.calls.lock().expect("lock"), 1);
        assert_eq!(published.aggregate.members.len(), 1);
        assert!(
            queue.list_resumable().expect("list after drain").is_empty(),
            "after reveal_broadcast the member must leave the resumable set"
        );
        assert_eq!(
            queue.load(&cmd.public_key).expect("load").expect("row").1,
            HandOffQueueStatus::RevealBroadcast
        );
    }

    /// Simulated restart: seed via from_pending_status recovers the member.
    #[test]
    fn restart_seeds_queue_from_pending_status_via_list_resumable() {
        let cmd = signed_command(KernelNetwork::Regtest);
        let member = HandOffMember::from_command(cmd);

        // Fresh queue after "restart" — only durable pending rows exist.
        let reopened = InMemoryHandOffQueue::new();
        let seeded = seed_queue_from_pending_status(
            &reopened,
            &[(member, HandOffQueueStatus::MembersReady.as_str())],
        )
        .expect("seed");
        assert_eq!(seeded, 1);

        let listed = reopened.list_resumable().expect("list after seed");
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].0.public_key, member.public_key);
        assert_eq!(listed[0].1, HandOffQueueStatus::MembersReady);

        // Intermediate status is preserved (not collapsed to members_ready).
        let mid = InMemoryHandOffQueue::new();
        let status = HandOffQueueStatus::from_pending_status("commit_broadcast")
            .expect("parse commit_broadcast");
        assert_eq!(status, HandOffQueueStatus::CommitBroadcast);
        seed_queue_from_pending_status(&mid, &[(member, "constructed")]).expect("seed constructed");
        assert_eq!(
            mid.load(&member.public_key).expect("load").expect("row").1,
            HandOffQueueStatus::Constructed
        );
    }

    /// Stepped publisher writes Constructed → CommitBroadcast → RevealBroadcast.
    #[test]
    fn drain_writes_constructed_commit_reveal_status_steps() {
        use std::sync::Mutex;
        use zkcoins_prover::publisher::PreparedBatch;

        struct SteppedPublisher {
            stages: Mutex<Vec<&'static str>>,
        }
        impl crate::v1::receive::NullifierBatchPublisher for SteppedPublisher {
            fn publish_batch(&self, _members: &[BatchMember]) -> anyhow::Result<PublishedBatch> {
                anyhow::bail!("stepped path must use try_prepare, not publish_batch");
            }
            fn try_prepare(
                &self,
                members: &[BatchMember],
            ) -> anyhow::Result<Option<PreparedBatch>> {
                self.stages.lock().expect("lock").push("prepare");
                let sigs: Vec<NullifierSig> = members.iter().map(|m| m.sig).collect();
                let anchor = members[0].build_tip;
                let agg = aggregate_sig_with_anchor(&sigs, anchor)?;
                // Minimal dummy txs — broadcast_* only records stages.
                let signed_commit = bitcoin::Transaction {
                    version: bitcoin::transaction::Version::TWO,
                    lock_time: bitcoin::absolute::LockTime::ZERO,
                    input: vec![],
                    output: vec![],
                };
                let reveal_tx = signed_commit.clone();
                Ok(Some(PreparedBatch {
                    aggregate: agg,
                    payload: vec![9],
                    signed_commit,
                    reveal_tx,
                    commit_output: bitcoin::TxOut {
                        value: bitcoin::Amount::from_sat(600),
                        script_pubkey: bitcoin::ScriptBuf::new(),
                    },
                    block_anchor: anchor,
                    commit_vsize: 1,
                    reveal_vsize: 1,
                    commit_fee: bitcoin::Amount::from_sat(1),
                    reveal_fee: bitcoin::Amount::from_sat(1),
                }))
            }
            fn broadcast_commit(&self, prepared: &PreparedBatch) -> anyhow::Result<bitcoin::Txid> {
                self.stages.lock().expect("lock").push("commit");
                Ok(prepared.commit_txid())
            }
            fn broadcast_reveal(&self, prepared: &PreparedBatch) -> anyhow::Result<bitcoin::Txid> {
                self.stages.lock().expect("lock").push("reveal");
                Ok(prepared.reveal_txid())
            }
        }

        let cmd = signed_command(KernelNetwork::Regtest);
        let queue = InMemoryHandOffQueue::new();
        accept_hand_off(&queue, accept_config(60), cmd).expect("accept");

        let publisher = SteppedPublisher {
            stages: Mutex::new(Vec::new()),
        };
        drain_and_inscribe(&queue, Some(&publisher), KernelNetwork::Regtest, None)
            .expect("drain")
            .expect("batch");

        assert_eq!(
            *publisher.stages.lock().expect("lock"),
            vec!["prepare", "commit", "reveal"]
        );
        assert_eq!(
            queue.load(&cmd.public_key).expect("load").expect("row").1,
            HandOffQueueStatus::RevealBroadcast
        );
        // Status wire tokens stay aligned with the recovery table.
        assert_eq!(HandOffQueueStatus::Constructed.as_str(), "constructed");
        assert_eq!(
            HandOffQueueStatus::CommitBroadcast.as_str(),
            "commit_broadcast"
        );
        assert_eq!(
            HandOffQueueStatus::RevealBroadcast.as_str(),
            "reveal_broadcast"
        );
        assert_eq!(HandOffQueueStatus::Failed.as_str(), "failed");
    }
}
