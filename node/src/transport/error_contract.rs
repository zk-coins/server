//! Total mapping `KernelErrorCode` → HTTP status / gRPC code / ErrorInfo.
//!
//! Single source of truth for both transports. Exhaustive `match` with no
//! wildcard — adding a code is a compile failure until this table is updated.
//!
//! This module intentionally does **not** import `tonic` or `axum`. The
//! gRPC adapter converts [`GrpcStatusCode`] into `tonic::Code`; the HTTP
//! adapter uses [`ErrorDescriptor::http_status`] as `u16`.

use crate::kernel::error::KernelErrorCode;

/// Normative `ErrorInfo.domain` for every kernel.v1 failure (§7.8).
pub(crate) const ERROR_INFO_DOMAIN: &str = "kernel.v1";

/// Transport-neutral stand-in for the eight admissible gRPC status codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum GrpcStatusCode {
    InvalidArgument,
    NotFound,
    FailedPrecondition,
    Unauthenticated,
    PermissionDenied,
    ResourceExhausted,
    Unavailable,
    Internal,
}

impl GrpcStatusCode {
    /// Stable name matching `tonic::Code` / gRPC status code identifiers.
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::InvalidArgument => "INVALID_ARGUMENT",
            Self::NotFound => "NOT_FOUND",
            Self::FailedPrecondition => "FAILED_PRECONDITION",
            Self::Unauthenticated => "UNAUTHENTICATED",
            Self::PermissionDenied => "PERMISSION_DENIED",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::Unavailable => "UNAVAILABLE",
            Self::Internal => "INTERNAL",
        }
    }
}

/// Fully determined error triple for one `KernelErrorCode`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct ErrorDescriptor {
    /// §7.5 machine code / `ErrorInfo.reason`.
    pub reason: &'static str,
    /// Decimal HTTP status used both on REST and in `ErrorInfo.metadata["http_status"]`.
    pub http_status: u16,
    /// gRPC primary status code.
    pub grpc_code: GrpcStatusCode,
}

impl ErrorDescriptor {
    /// `ErrorInfo.metadata["http_status"]` value (decimal string).
    pub(crate) fn http_status_metadata(self) -> String {
        self.http_status.to_string()
    }
}

/// Total, deterministic mapping. No `_` arm.
pub(crate) fn describe(code: KernelErrorCode) -> ErrorDescriptor {
    match code {
        KernelErrorCode::MalformedRequest => ErrorDescriptor {
            reason: "malformed_request",
            http_status: 400,
            grpc_code: GrpcStatusCode::InvalidArgument,
        },
        KernelErrorCode::BoundsExceeded => ErrorDescriptor {
            reason: "bounds_exceeded",
            http_status: 400,
            grpc_code: GrpcStatusCode::InvalidArgument,
        },
        KernelErrorCode::InvalidInputCoin => ErrorDescriptor {
            reason: "invalid_input_coin",
            http_status: 400,
            grpc_code: GrpcStatusCode::InvalidArgument,
        },
        KernelErrorCode::InsufficientBalance => ErrorDescriptor {
            reason: "insufficient_balance",
            http_status: 400,
            grpc_code: GrpcStatusCode::InvalidArgument,
        },
        KernelErrorCode::UnknownPublisher => ErrorDescriptor {
            reason: "unknown_publisher",
            http_status: 400,
            grpc_code: GrpcStatusCode::InvalidArgument,
        },
        KernelErrorCode::JobNotFound => ErrorDescriptor {
            reason: "job_not_found",
            http_status: 404,
            grpc_code: GrpcStatusCode::NotFound,
        },
        KernelErrorCode::NotFound => ErrorDescriptor {
            reason: "not_found",
            http_status: 404,
            grpc_code: GrpcStatusCode::NotFound,
        },
        KernelErrorCode::WrongPhase => ErrorDescriptor {
            reason: "wrong_phase",
            http_status: 409,
            grpc_code: GrpcStatusCode::FailedPrecondition,
        },
        KernelErrorCode::StaleMessage => ErrorDescriptor {
            reason: "stale_message",
            http_status: 409,
            grpc_code: GrpcStatusCode::FailedPrecondition,
        },
        KernelErrorCode::InvalidSignature => ErrorDescriptor {
            reason: "invalid_signature",
            http_status: 409,
            grpc_code: GrpcStatusCode::FailedPrecondition,
        },
        KernelErrorCode::RetentionHold => ErrorDescriptor {
            reason: "retention_hold",
            http_status: 409,
            grpc_code: GrpcStatusCode::FailedPrecondition,
        },
        KernelErrorCode::DependencyNotFinal => ErrorDescriptor {
            reason: "dependency_not_final",
            http_status: 409,
            grpc_code: GrpcStatusCode::FailedPrecondition,
        },
        KernelErrorCode::IdempotencyConflict => ErrorDescriptor {
            reason: "idempotency_conflict",
            http_status: 409,
            grpc_code: GrpcStatusCode::FailedPrecondition,
        },
        KernelErrorCode::Unauthorized => ErrorDescriptor {
            reason: "unauthorized",
            http_status: 401,
            grpc_code: GrpcStatusCode::Unauthenticated,
        },
        // 410 special cases: same gRPC class as unauthorized, distinct HTTP.
        KernelErrorCode::ChallengeExpired => ErrorDescriptor {
            reason: "challenge_expired",
            http_status: 410,
            grpc_code: GrpcStatusCode::Unauthenticated,
        },
        KernelErrorCode::SessionExpired => ErrorDescriptor {
            reason: "session_expired",
            http_status: 410,
            grpc_code: GrpcStatusCode::Unauthenticated,
        },
        KernelErrorCode::ScopeExceeded => ErrorDescriptor {
            reason: "scope_exceeded",
            http_status: 403,
            grpc_code: GrpcStatusCode::PermissionDenied,
        },
        KernelErrorCode::RateLimited => ErrorDescriptor {
            reason: "rate_limited",
            http_status: 429,
            grpc_code: GrpcStatusCode::ResourceExhausted,
        },
        KernelErrorCode::PayloadTooLarge => ErrorDescriptor {
            reason: "payload_too_large",
            http_status: 413,
            grpc_code: GrpcStatusCode::ResourceExhausted,
        },
        KernelErrorCode::CircuitDigestMismatch => ErrorDescriptor {
            reason: "circuit_digest_mismatch",
            http_status: 503,
            grpc_code: GrpcStatusCode::Unavailable,
        },
        KernelErrorCode::InternalError => ErrorDescriptor {
            reason: "internal_error",
            http_status: 500,
            grpc_code: GrpcStatusCode::Internal,
        },
    }
}

/// Convenience: reason string equals `KernelErrorCode::reason()`.
pub(crate) fn reason(code: KernelErrorCode) -> &'static str {
    describe(code).reason
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::error::KernelErrorCode;

    /// Every code once — pins the full Entwurf / §7.8 table.
    fn all_codes() -> [KernelErrorCode; 21] {
        [
            KernelErrorCode::MalformedRequest,
            KernelErrorCode::BoundsExceeded,
            KernelErrorCode::InvalidInputCoin,
            KernelErrorCode::InsufficientBalance,
            KernelErrorCode::UnknownPublisher,
            KernelErrorCode::JobNotFound,
            KernelErrorCode::NotFound,
            KernelErrorCode::WrongPhase,
            KernelErrorCode::StaleMessage,
            KernelErrorCode::InvalidSignature,
            KernelErrorCode::RetentionHold,
            KernelErrorCode::DependencyNotFinal,
            KernelErrorCode::IdempotencyConflict,
            KernelErrorCode::Unauthorized,
            KernelErrorCode::ChallengeExpired,
            KernelErrorCode::SessionExpired,
            KernelErrorCode::ScopeExceeded,
            KernelErrorCode::RateLimited,
            KernelErrorCode::PayloadTooLarge,
            KernelErrorCode::CircuitDigestMismatch,
            KernelErrorCode::InternalError,
        ]
    }

    #[test]
    fn mapping_is_total_and_reason_matches_code() {
        for code in all_codes() {
            let d = describe(code);
            assert_eq!(d.reason, code.reason());
            assert!(
                (400..=599).contains(&d.http_status),
                "http_status out of range for {:?}: {}",
                code,
                d.http_status
            );
        }
    }

    #[test]
    fn get_job_relevant_triples() {
        // GetJob may emit: malformed, job_not_found, rate_limited, internal.
        let d = describe(KernelErrorCode::JobNotFound);
        assert_eq!(d.reason, "job_not_found");
        assert_eq!(d.http_status, 404);
        assert_eq!(d.grpc_code, GrpcStatusCode::NotFound);

        let d = describe(KernelErrorCode::MalformedRequest);
        assert_eq!(d.reason, "malformed_request");
        assert_eq!(d.http_status, 400);
        assert_eq!(d.grpc_code, GrpcStatusCode::InvalidArgument);

        let d = describe(KernelErrorCode::RateLimited);
        assert_eq!(d.reason, "rate_limited");
        assert_eq!(d.http_status, 429);
        assert_eq!(d.grpc_code, GrpcStatusCode::ResourceExhausted);

        let d = describe(KernelErrorCode::InternalError);
        assert_eq!(d.reason, "internal_error");
        assert_eq!(d.http_status, 500);
        assert_eq!(d.grpc_code, GrpcStatusCode::Internal);
    }

    /// N-20: session_expired → UNAUTHENTICATED + http_status 410 (never 401).
    #[test]
    fn n20_session_expired_is_410_unauthenticated() {
        let d = describe(KernelErrorCode::SessionExpired);
        assert_eq!(d.reason, "session_expired");
        assert_eq!(d.http_status, 410);
        assert_eq!(d.grpc_code, GrpcStatusCode::Unauthenticated);
        assert_eq!(d.http_status_metadata(), "410");
        assert_eq!(ERROR_INFO_DOMAIN, "kernel.v1");
    }

    /// N-21: unauthorized → UNAUTHENTICATED + 401.
    #[test]
    fn n21_unauthorized_is_401_unauthenticated() {
        let d = describe(KernelErrorCode::Unauthorized);
        assert_eq!(d.reason, "unauthorized");
        assert_eq!(d.http_status, 401);
        assert_eq!(d.grpc_code, GrpcStatusCode::Unauthenticated);
    }

    /// N-22: wrong_phase → FAILED_PRECONDITION + 409.
    #[test]
    fn n22_wrong_phase_is_409_failed_precondition() {
        let d = describe(KernelErrorCode::WrongPhase);
        assert_eq!(d.reason, "wrong_phase");
        assert_eq!(d.http_status, 409);
        assert_eq!(d.grpc_code, GrpcStatusCode::FailedPrecondition);
    }

    /// N-23: job_not_found on GetJob → NOT_FOUND + 404.
    #[test]
    fn n23_job_not_found_is_404_not_found() {
        let d = describe(KernelErrorCode::JobNotFound);
        assert_eq!(d.reason, "job_not_found");
        assert_eq!(d.http_status, 404);
        assert_eq!(d.grpc_code, GrpcStatusCode::NotFound);
        assert_eq!(d.grpc_code.as_str(), "NOT_FOUND");
    }

    /// N-24: bounds_exceeded → INVALID_ARGUMENT + 400.
    #[test]
    fn n24_bounds_exceeded_is_400_invalid_argument() {
        let d = describe(KernelErrorCode::BoundsExceeded);
        assert_eq!(d.reason, "bounds_exceeded");
        assert_eq!(d.http_status, 400);
        assert_eq!(d.grpc_code, GrpcStatusCode::InvalidArgument);
    }

    /// N-25: scope_exceeded → PERMISSION_DENIED + 403.
    #[test]
    fn n25_scope_exceeded_is_403_permission_denied() {
        let d = describe(KernelErrorCode::ScopeExceeded);
        assert_eq!(d.reason, "scope_exceeded");
        assert_eq!(d.http_status, 403);
        assert_eq!(d.grpc_code, GrpcStatusCode::PermissionDenied);
    }

    /// N-26: rate_limited → RESOURCE_EXHAUSTED + 429.
    #[test]
    fn n26_rate_limited_is_429_resource_exhausted() {
        let d = describe(KernelErrorCode::RateLimited);
        assert_eq!(d.reason, "rate_limited");
        assert_eq!(d.http_status, 429);
        assert_eq!(d.grpc_code, GrpcStatusCode::ResourceExhausted);
    }

    /// N-27: circuit_digest_mismatch → UNAVAILABLE + 503.
    #[test]
    fn n27_circuit_digest_mismatch_is_503_unavailable() {
        let d = describe(KernelErrorCode::CircuitDigestMismatch);
        assert_eq!(d.reason, "circuit_digest_mismatch");
        assert_eq!(d.http_status, 503);
        assert_eq!(d.grpc_code, GrpcStatusCode::Unavailable);
    }

    /// N-28: same triple is deterministic across repeated describe() calls.
    #[test]
    fn n28_mapping_is_byte_identical_across_calls() {
        for code in all_codes() {
            let a = describe(code);
            let b = describe(code);
            assert_eq!(a, b);
            assert_eq!(a.reason, b.reason);
            assert_eq!(a.http_status_metadata(), b.http_status_metadata());
            assert_eq!(a.grpc_code.as_str(), b.grpc_code.as_str());
        }
    }

    #[test]
    fn challenge_expired_shares_unauthenticated_but_not_401() {
        let d = describe(KernelErrorCode::ChallengeExpired);
        assert_eq!(d.http_status, 410);
        assert_eq!(d.grpc_code, GrpcStatusCode::Unauthenticated);
        assert_ne!(
            d.http_status,
            describe(KernelErrorCode::Unauthorized).http_status
        );
    }
}
