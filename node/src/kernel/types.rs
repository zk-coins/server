//! Transport-free kernel types for job procedures (Block 1–2).
//!
//! Full TransitionCommand / Challenge / Pull types land with later blocks.
//! This module must not import `axum` or `tonic`.

use std::pin::Pin;

use futures_util::Stream;
use uuid::Uuid;

use crate::job_store;
use crate::kernel::error::KernelResult;

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

/// Job kind as persisted today (`mint` | `send` | `attest_balance`).
///
/// Normative `receive` is not yet admitted by the store; Block 4 introduces
/// it with `SubmitTransition`. Inventing a `Receive` variant without a
/// write path would only paper over the gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum JobKind {
    Mint,
    Send,
    AttestBalance,
}

impl JobKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Mint => "mint",
            Self::Send => "send",
            Self::AttestBalance => "attest_balance",
        }
    }

    pub(crate) fn from_store(kind: job_store::JobKind) -> Self {
        match kind {
            job_store::JobKind::Mint => Self::Mint,
            job_store::JobKind::Send => Self::Send,
            job_store::JobKind::AttestBalance => Self::AttestBalance,
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
