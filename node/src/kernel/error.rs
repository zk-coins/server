//! Transport-free kernel error codes (§7.8 / Entwurf Abschnitt 2).
//!
//! HTTP status and gRPC `Status` / `ErrorInfo` are derived only through
//! [`crate::transport::error_contract`]. This module must not import
//! `axum` or `tonic`.

use std::fmt;

/// Closed set of public kernel error reasons.
///
/// `ProvingFailed` and `PublishRejected` are **not** RPC failures: they
/// appear as successful `GetJob` / `StreamJob` results with a terminal
/// job state. `FeatureDisabled` is an API-layer gate, not a kernel code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum KernelErrorCode {
    MalformedRequest,
    BoundsExceeded,
    InvalidInputCoin,
    InsufficientBalance,
    UnknownPublisher,
    JobNotFound,
    NotFound,
    WrongPhase,
    StaleMessage,
    InvalidSignature,
    DependencyNotFinal,
    IdempotencyConflict,
    Unauthorized,
    ChallengeExpired,
    SessionExpired,
    ScopeExceeded,
    RateLimited,
    PayloadTooLarge,
    CircuitDigestMismatch,
    InternalError,
}

impl KernelErrorCode {
    /// Every code in §7.8 order. The closed set is the contract, so this
    /// inventory is what makes it checkable — not a convenience list.
    pub(crate) const ALL: [KernelErrorCode; 20] = [
        Self::MalformedRequest,
        Self::BoundsExceeded,
        Self::InvalidInputCoin,
        Self::InsufficientBalance,
        Self::UnknownPublisher,
        Self::JobNotFound,
        Self::NotFound,
        Self::WrongPhase,
        Self::StaleMessage,
        Self::InvalidSignature,
        Self::DependencyNotFinal,
        Self::IdempotencyConflict,
        Self::Unauthorized,
        Self::ChallengeExpired,
        Self::SessionExpired,
        Self::ScopeExceeded,
        Self::RateLimited,
        Self::PayloadTooLarge,
        Self::CircuitDigestMismatch,
        Self::InternalError,
    ];

    /// Normative machine-code string (§7.5 / §7.8 `ErrorInfo.reason`).
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::MalformedRequest => "malformed_request",
            Self::BoundsExceeded => "bounds_exceeded",
            Self::InvalidInputCoin => "invalid_input_coin",
            Self::InsufficientBalance => "insufficient_balance",
            Self::UnknownPublisher => "unknown_publisher",
            Self::JobNotFound => "job_not_found",
            Self::NotFound => "not_found",
            Self::WrongPhase => "wrong_phase",
            Self::StaleMessage => "stale_message",
            Self::InvalidSignature => "invalid_signature",
            Self::DependencyNotFinal => "dependency_not_final",
            Self::IdempotencyConflict => "idempotency_conflict",
            Self::Unauthorized => "unauthorized",
            Self::ChallengeExpired => "challenge_expired",
            Self::SessionExpired => "session_expired",
            Self::ScopeExceeded => "scope_exceeded",
            Self::RateLimited => "rate_limited",
            Self::PayloadTooLarge => "payload_too_large",
            Self::CircuitDigestMismatch => "circuit_digest_mismatch",
            Self::InternalError => "internal_error",
        }
    }
}

/// Operator-facing detail that must never be serialised onto the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InternalContext {
    pub detail: String,
}

/// Domain error returned by every `KernelService` operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KernelError {
    pub code: KernelErrorCode,
    pub public_message: String,
    pub internal_context: Option<InternalContext>,
}

impl KernelError {
    pub(crate) fn new(code: KernelErrorCode, public_message: impl Into<String>) -> Self {
        Self {
            code,
            public_message: public_message.into(),
            internal_context: None,
        }
    }

    pub(crate) fn with_internal(
        code: KernelErrorCode,
        public_message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            code,
            public_message: public_message.into(),
            internal_context: Some(InternalContext {
                detail: detail.into(),
            }),
        }
    }

    pub(crate) fn job_not_found() -> Self {
        Self::new(KernelErrorCode::JobNotFound, "Job not found")
    }

    /// Backend-Korrektheit ist fail-closed: lieber ein Fehler als ein Wert,
    /// der Vollständigkeit vortäuscht (halbe Antwort, die wie Erfolg wirkt).
    pub(crate) fn corrupt_job_row(detail: impl Into<String>) -> Self {
        Self::with_internal(KernelErrorCode::InternalError, "Failed to load job", detail)
    }

    pub(crate) fn store_load_failed(detail: impl Into<String>) -> Self {
        Self::with_internal(KernelErrorCode::InternalError, "Failed to load job", detail)
    }

    pub(crate) fn store_cancel_failed(detail: impl Into<String>) -> Self {
        Self::with_internal(
            KernelErrorCode::InternalError,
            "Failed to cancel job",
            detail,
        )
    }

    /// Job is past the status set that accepts this operation (§7.5 `wrong_phase`).
    pub(crate) fn wrong_phase(public_message: impl Into<String>) -> Self {
        Self::new(KernelErrorCode::WrongPhase, public_message)
    }

    /// Phase broadcast channel lagged or closed mid-stream.
    pub(crate) fn stream_channel_failed(detail: impl Into<String>) -> Self {
        Self::with_internal(
            KernelErrorCode::InternalError,
            "Job event stream failed",
            detail,
        )
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.reason(), self.public_message)
    }
}

impl std::error::Error for KernelError {}

pub(crate) type KernelResult<T> = Result<T, KernelError>;
