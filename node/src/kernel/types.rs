//! Transport-free kernel types for job procedures (Block 1–4).
//!
//! [`TransitionCommand`] / [`SignTransition`] / job projection types live
//! here. Pull / session / record types live in [`crate::kernel::access`].
//! This module must not import `axum` or `tonic`.

use std::pin::Pin;

use futures_util::Stream;
use uuid::Uuid;

use crate::job_store;
use crate::kernel::KernelResult;
use crate::v1::WalletSignSubmission;

/// Server-stream item type for kernel procedures (`StreamJob`, …).
pub(crate) type KernelStream<T> = Pin<Box<dyn Stream<Item = KernelResult<T>> + Send + 'static>>;

/// Public job identifier (UUID on the wire).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct JobId(pub Uuid);

impl JobId {
    pub(crate) fn as_uuid(self) -> Uuid {
        self.0
    }
}

/// Request for `GetJob` / `StreamJob` / `CancelJob`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct JobRequest {
    pub id: JobId,
}

/// Job kind as persisted (`mint` | `send` | `attest_balance` | `receive`).
///
/// Wire `kind` is the same string set as §7.5 / §7.8 (`"receive"` for the
/// fold-in transition). Store kind includes `receive` since migration 0029.
/// Projection maps 1:1 from [`job_store::JobKind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobKind {
    Mint,
    Send,
    AttestBalance,
    /// §7.5 / §7.8 `kind == "receive"`.
    Receive,
}

impl JobKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Send => "send",
            Self::AttestBalance => "attest_balance",
            Self::Receive => "receive",
        }
    }

    pub(crate) fn from_store(kind: job_store::JobKind) -> Self {
        match kind {
            job_store::JobKind::Mint => Self::Mint,
            job_store::JobKind::Send => Self::Send,
            job_store::JobKind::AttestBalance => Self::AttestBalance,
            job_store::JobKind::Receive => Self::Receive,
        }
    }
}

/// 32-byte digest (coin id, asset id, `npk_rand`, …) already decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct Digest32(pub [u8; 32]);

/// x-only BIP-340 public key (32 bytes), already decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct XOnlyKey(pub [u8; 32]);

/// Account address as 32 raw bytes (Bech32m decode is transport-side).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct SubjectAddress(pub [u8; 32]);

/// Opaque 32-byte channel-binding token (§5.1 `chan_bind`).
///
/// The kernel never derives this from request metadata; the API layer
/// (or a trusted gRPC caller) supplies it as an equality token. Clearnet
/// form is `H("zkCoins/v1/PullHost" ‖ host)`; Tor form is the v3 onion
/// Ed25519 public key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct ChanBind(pub [u8; 32]);

/// Opaque client idempotency key (≤ 64 bytes per §7.5).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct IdempotencyKey(pub String);

impl IdempotencyKey {
    /// Construct from a non-empty key already checked for length ≤ 64.
    pub(crate) fn from_validated(key: String) -> Self {
        Self(key)
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

/// Closed publisher / fee-address presence for v1 (§7.5 matrix).
///
/// Case (b) (publisher + fee_address) is **not representable**: v1 forbids
/// `fee_address`. Transport that sees `fee_address` present must reject
/// with `malformed_request` before building this type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PublisherChoice {
    /// Case (a): self-publish — no `publisher_pubkey`, no `fee_address`.
    SelfPublish,
    /// Case (c): fee-less external hand-off — `publisher_pubkey` present,
    /// `fee_address` absent.
    FeeLessHandOff { publisher_pubkey: XOnlyKey },
}

/// Closed §7.5 `DeliveryCredential` carried on a non-self
/// [`OutputTemplate`] (and optionally on a self-output).
///
/// Wire `oneof` is closed: invoice | profile. Verification is kernel-only
/// and reuses the §4.3 checklists in `v1::nostr::profile`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DeliveryCredential {
    /// Full §1.5 / §4.3 amount-specific Invoice.
    Invoice(crate::v1::PaymentInvoice),
    /// Full canonical kind-0 event (author, created_at, Nostr signature).
    Profile(crate::v1::nostr::event::Event),
}

/// One output template (§7.5 `OutputTemplate`); amount is a decoded `u128`.
///
/// `delivery` is required for every non-self output (§7.5 presence rule).
/// A self-output **MAY** omit it; when present it must still satisfy the
/// matching checklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OutputTemplate {
    pub recipient: SubjectAddress,
    pub asset_id: Digest32,
    pub amount: u128,
    pub delivery: Option<DeliveryCredential>,
}

/// Issuance block for `kind == mint` (§7.5 / §6.5).
///
/// Closed: version 1 has no cap/salt; version 2 requires both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Issuance {
    /// `issuance_version == 1` — no `cap_total` / `terms_salt`.
    V1 {
        name: String,
        decimals: u8,
        amount: u128,
        /// Genesis spend key `Pk₀` (asset creator); required by the spec.
        creator_pubkey: XOnlyKey,
    },
    /// `issuance_version == 2` — `cap_total` and `terms_salt` required.
    V2 {
        name: String,
        decimals: u8,
        amount: u128,
        cap_total: u128,
        terms_salt: Digest32,
        /// Genesis spend key `Pk₀` (asset creator); required by the spec.
        creator_pubkey: XOnlyKey,
    },
}

/// Fields common to every transition kind (decoded, required).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TransitionCommon {
    pub subject: SubjectAddress,
    pub next_pubkey: XOnlyKey,
    pub npk_rand: Digest32,
    pub publisher: PublisherChoice,
    pub idempotency_key: IdempotencyKey,
}

/// Closed `TransitionCommand` for `SubmitTransition` (§7.8 / §7.5).
///
/// Presence matrix is **structural**: forbidden fields for a kind are not
/// members of that variant. Bounds and remaining shape checks live in
/// [`crate::kernel::jobs::submit::validate_transition_command`].
///
/// This is not a `serde_json::Value` deferred check — a send without
/// `input_coins` cannot be constructed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum TransitionCommand {
    /// `kind == "mint"`: `issuance` + `output_templates` required;
    /// `input_coins` / `fold_coin_ids` absent by construction.
    Mint {
        common: TransitionCommon,
        issuance: Issuance,
        output_templates: Vec<OutputTemplate>,
    },
    /// `kind == "send"`: `input_coins` + `output_templates` required;
    /// `issuance` / `fold_coin_ids` absent by construction.
    Send {
        common: TransitionCommon,
        input_coins: Vec<Digest32>,
        output_templates: Vec<OutputTemplate>,
    },
    /// `kind == "receive"`: `fold_coin_ids` required;
    /// `input_coins` / `output_templates` / `issuance` absent by construction.
    /// `genesis_pubkey` is optional and conditionally required (required for a
    /// genesis receive — the account's first transition; MUST be absent
    /// otherwise, §7.5).
    ///
    /// Shape validation and job admission share the mint/send path.
    /// Clause-10 slots, the operational bundle, and the wallet signature
    /// are assembled later (dispatcher / `v1::receive`) — they are not
    /// carried on this command.
    Receive {
        common: TransitionCommon,
        fold_coin_ids: Vec<Digest32>,
        /// Recipient's genesis Pk₀ — REQUIRED for a genesis receive (the
        /// account's first transition); MUST be absent otherwise (§7.5).
        /// Symmetric to `Issuance::{V1,V2}.creator_pubkey`.
        genesis_pubkey: Option<XOnlyKey>,
    },
}

impl TransitionCommand {
    pub(crate) fn common(&self) -> &TransitionCommon {
        match self {
            Self::Mint { common, .. }
            | Self::Send { common, .. }
            | Self::Receive { common, .. } => common,
        }
    }

    pub(crate) fn kind_str(&self) -> &'static str {
        match self {
            Self::Mint { .. } => "mint",
            Self::Send { .. } => "send",
            Self::Receive { .. } => "receive",
        }
    }
}

/// Normative job status after store aliases are applied.
///
/// Single place for `queued → accepted` and `broadcasting → publishing`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NormativeJobStatus {
    Accepted,
    Proving,
    AwaitingSignature,
    Publishing,
    Completed,
    Failed,
    Cancelled,
}

impl NormativeJobStatus {
    /// Map a persistence-row status onto the closed normative set.
    ///
    /// Status aliases live **only** here:
    /// - `queued` → `Accepted`
    /// - `broadcasting` → `Publishing`
    ///
    /// SSE and poll both project through this mapping (via
    /// [`Job::normative_status`] / [`Self::as_v1_str`]), so the two
    /// transports cannot drift on alias expansion.
    pub(crate) fn from_store(status: job_store::JobStatus) -> Self {
        match status {
            job_store::JobStatus::Queued => Self::Accepted,
            job_store::JobStatus::Proving => Self::Proving,
            job_store::JobStatus::AwaitingSignature => Self::AwaitingSignature,
            job_store::JobStatus::Broadcasting => Self::Publishing,
            job_store::JobStatus::Completed => Self::Completed,
            job_store::JobStatus::Failed => Self::Failed,
            job_store::JobStatus::Cancelled => Self::Cancelled,
        }
    }

    /// §7.5 / §7.8 wire status string (`accepted`, `publishing`, …).
    pub(crate) fn as_v1_str(self) -> &'static str {
        match self {
            Self::Accepted => "accepted",
            Self::Proving => "proving",
            Self::AwaitingSignature => "awaiting_signature",
            Self::Publishing => "publishing",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    /// Legacy `/api/jobs/:id` wire status (`queued`, `broadcasting`, …).
    pub(crate) fn as_legacy_str(self) -> &'static str {
        match self {
            Self::Accepted => "queued",
            Self::Proving => "proving",
            Self::AwaitingSignature => "awaiting_signature",
            Self::Publishing => "broadcasting",
            Self::Completed => "completed",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
        }
    }

    pub(crate) fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

/// Opaque job-phase payload carried by the store as free JSON.
///
/// Block 1 keeps the raw value so HTTP projections stay byte-equal for
/// well-formed rows. Structural decode into digests / attestation bytes
/// is a later block; presence is already fail-closed (see `job_projection`).
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct JobPayload(pub serde_json::Value);

/// Typed job state. Impossible half-states are not representable:
/// - `Completed` without a result
/// - `AwaitingSignature` without a payload
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum JobState {
    Accepted,
    Proving,
    AwaitingSignature {
        payload: JobPayload,
        /// Legacy `proof_id` column; projected only on `/api/jobs/:id`.
        proof_id: Option<i64>,
    },
    Publishing,
    Completed {
        result: JobPayload,
    },
    Failed {
        /// Raw store error text (free string or JSON). Projection maps it.
        error: Option<String>,
    },
    Cancelled {
        error: Option<String>,
    },
}

impl JobState {
    pub(crate) fn normative(&self) -> NormativeJobStatus {
        match self {
            Self::Accepted => NormativeJobStatus::Accepted,
            Self::Proving => NormativeJobStatus::Proving,
            Self::AwaitingSignature { .. } => NormativeJobStatus::AwaitingSignature,
            Self::Publishing => NormativeJobStatus::Publishing,
            Self::Completed { .. } => NormativeJobStatus::Completed,
            Self::Failed { .. } => NormativeJobStatus::Failed,
            Self::Cancelled { .. } => NormativeJobStatus::Cancelled,
        }
    }

    pub(crate) fn is_terminal(&self) -> bool {
        self.normative().is_terminal()
    }
}

/// Fully projected domain job returned by `GetJob`.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Job {
    pub id: JobId,
    pub kind: JobKind,
    /// Raw phase string from the store (legacy wire always emits it).
    pub phase: String,
    /// Progress 0–100 from the store (v1 converts to a float in the adapter).
    pub progress: i16,
    pub state: JobState,
}

impl Job {
    pub(crate) fn normative_status(&self) -> NormativeJobStatus {
        self.state.normative()
    }
}

/// Transport-neutral job event (`StreamJob`, Entwurf §3).
///
/// No SSE frame names, no `axum::response::sse::Event`, no proto types.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct JobEvent {
    pub kind: JobEventKind,
    pub job: Job,
}

/// Closed set of stream event kinds. HTTP maps these to SSE `event:` names
/// (legacy maps `Error` → `complete`; v1 maps 1:1). gRPC maps to
/// `kernel.v1.JobEvent.event`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum JobEventKind {
    Phase,
    Complete,
    Error,
}

impl JobEventKind {
    /// Normative / v1 SSE and gRPC event name.
    pub(crate) fn as_v1_str(self) -> &'static str {
        match self {
            Self::Phase => "phase",
            Self::Complete => "complete",
            Self::Error => "error",
        }
    }

    /// Legacy `/api/jobs/:id/stream` event name: all terminals are `complete`.
    pub(crate) fn as_legacy_str(self) -> &'static str {
        match self {
            Self::Phase => "phase",
            Self::Complete | Self::Error => "complete",
        }
    }

    pub(crate) fn from_job_state(state: &JobState) -> Self {
        match state {
            JobState::Completed { .. } => Self::Complete,
            JobState::Failed { .. } | JobState::Cancelled { .. } => Self::Error,
            JobState::Accepted
            | JobState::Proving
            | JobState::AwaitingSignature { .. }
            | JobState::Publishing => Self::Phase,
        }
    }
}

impl JobEvent {
    pub(crate) fn from_job(job: Job) -> Self {
        let kind = JobEventKind::from_job_state(&job.state);
        Self { kind, job }
    }
}

/// Cancel policy — Legacy and §7.5 differ and must not be collapsed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CancelPolicy {
    /// `/api/jobs/:id/cancel` — only `queued` (`Accepted`) is cancellable.
    LegacyQueuedOnly,
    /// `/v1/jobs/:id/cancel` / `CancelJob` — cancellable until immediately
    /// before `publishing` (i.e. while still `accepted`/`queued`, `proving`,
    /// or `awaiting_signature`).
    NotYetPublished,
}

/// Request for `SignTransition` (§7.8 / §3.2).
///
/// Binary widths are already checked at the transport boundary
/// (`signature` = 64 bytes, `s2c_nonce` = 32 bytes). The domain does not
/// re-parse hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SignTransition {
    pub id: JobId,
    pub submission: WalletSignSubmission,
}
