//! Map [`KernelError`] → `tonic::Status` with normative `ErrorInfo`.
//!
//! Uses the shared [`crate::transport::error_contract`] table — no second
//! reason/HTTP/gRPC vocabulary. Wire shape is the gRPC richer-error model:
//! a single `google.rpc.ErrorInfo` packed into `google.rpc.Status.details`
//! (via `tonic-types`), never ad-hoc trailing metadata headers.

use std::collections::HashMap;

use crate::kernel::KernelError;
use crate::transport::error_contract::{self, GrpcStatusCode, ERROR_INFO_DOMAIN};
use tonic::{Code, Status};
use tonic_types::{ErrorDetails, StatusExt};

/// Build a gRPC status for a domain error (unary or stream-terminal).
///
/// Packs **exactly one** `google.rpc.ErrorInfo` into `Status.details` with:
/// - `reason` = normative machine code from [`error_contract::describe`]
/// - `domain` = [`ERROR_INFO_DOMAIN`] (`"kernel.v1"`)
/// - `metadata["http_status"]` = decimal HTTP status string from the same
///   table (e.g. `"404"`, `"410"` for the UNAUTHENTICATED special cases)
///
/// Operator `InternalContext` is **never** serialised onto the wire; it is
/// logged by the caller when present. Non-normative trailing metadata
/// headers (`error-reason` / `error-domain` / `error-http-status`) are
/// intentionally **not** set — the Spec names only the `ErrorInfo` detail
/// as the contract, and a second channel would re-create dual truth.
pub(crate) fn kernel_error_to_status(err: &KernelError) -> Status {
    let desc = error_contract::describe(err.code);
    let code = grpc_code(desc.grpc_code);

    let mut metadata = HashMap::with_capacity(1);
    metadata.insert("http_status".to_string(), desc.http_status_metadata());

    let details = ErrorDetails::with_error_info(desc.reason, ERROR_INFO_DOMAIN, metadata);

    // `StatusExt::with_error_details` encodes `google.rpc.Status` with the
    // ErrorInfo as the sole `details` Any into the binary details field.
    // Encoding of these fixed structs does not return a fallible result;
    // a post-pack decode check below fails closed if the wire bytes were
    // ever empty or unreadable (would be a tonic-types / prost bug).
    let status = Status::with_error_details(code, err.public_message.clone(), details);
    let expected_http = desc.http_status_metadata();

    match status.check_error_details() {
        Ok(decoded) => match decoded.error_info() {
            Some(info)
                if info.reason == desc.reason
                    && info.domain == ERROR_INFO_DOMAIN
                    && info.metadata.get("http_status").map(String::as_str)
                        == Some(expected_http.as_str()) =>
            {
                status
            }
            Some(info) => {
                // Packed, but not the triple we asked for — surface as a
                // hard internal failure rather than emit a wrong contract.
                tracing::error!(
                    reason = %info.reason,
                    domain = %info.domain,
                    expected_reason = desc.reason,
                    "kernel ErrorInfo pack produced mismatched detail"
                );
                packing_failure_status()
            }
            None => {
                tracing::error!("kernel ErrorInfo pack produced Status without ErrorInfo detail");
                packing_failure_status()
            }
        },
        Err(decode_err) => {
            tracing::error!(
                error = %decode_err,
                "kernel ErrorInfo pack produced undecodable Status.details"
            );
            packing_failure_status()
        }
    }
}

/// Last-resort status when packing/verification of the normative ErrorInfo
/// failed. Still carries a real ErrorInfo (from the same table) so the
/// wire never returns a bare `Status` without the required detail.
fn packing_failure_status() -> Status {
    let desc = error_contract::describe(crate::kernel::KernelErrorCode::InternalError);
    let mut metadata = HashMap::with_capacity(1);
    metadata.insert("http_status".to_string(), desc.http_status_metadata());
    let details = ErrorDetails::with_error_info(desc.reason, ERROR_INFO_DOMAIN, metadata);
    Status::with_error_details(Code::Internal, "Failed to encode error detail", details)
}

fn grpc_code(code: GrpcStatusCode) -> Code {
    match code {
        GrpcStatusCode::InvalidArgument => Code::InvalidArgument,
        GrpcStatusCode::NotFound => Code::NotFound,
        GrpcStatusCode::FailedPrecondition => Code::FailedPrecondition,
        GrpcStatusCode::Unauthenticated => Code::Unauthenticated,
        GrpcStatusCode::PermissionDenied => Code::PermissionDenied,
        GrpcStatusCode::ResourceExhausted => Code::ResourceExhausted,
        GrpcStatusCode::Unavailable => Code::Unavailable,
        GrpcStatusCode::Internal => Code::Internal,
    }
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::{KernelError, KernelErrorCode};
    use tonic_types::ErrorDetail;

    /// Decode and assert the normative ErrorInfo shape; returns the info
    /// for further field checks. Fails on zero/multiple details or missing
    /// ErrorInfo — never treats absence as a soft skip.
    fn require_single_error_info(st: &Status) -> tonic_types::ErrorInfo {
        let details = st
            .check_error_details_vec()
            .expect("Status.details must decode as google.rpc.Status details");
        assert_eq!(
            details.len(),
            1,
            "Status.details must carry exactly one ErrorDetail, got {details:?}"
        );
        match &details[0] {
            ErrorDetail::ErrorInfo(info) => info.clone(),
            other => panic!("expected ErrorInfo as sole detail, got {other:?}"),
        }
    }

    fn assert_matches_describe(st: &Status, code: KernelErrorCode) {
        let desc = error_contract::describe(code);
        assert_eq!(st.code(), grpc_code(desc.grpc_code));
        let info = require_single_error_info(st);
        assert_eq!(
            info.reason, desc.reason,
            "ErrorInfo.reason must match describe()"
        );
        assert_eq!(
            info.domain, ERROR_INFO_DOMAIN,
            "ErrorInfo.domain must be kernel.v1"
        );
        assert_eq!(
            info.metadata.get("http_status").map(String::as_str),
            Some(desc.http_status_metadata().as_str()),
            "ErrorInfo.metadata[http_status] must match describe()"
        );
        // Spec path only — no second channel via trailing metadata.
        assert!(
            st.metadata().get("error-reason").is_none(),
            "non-normative error-reason metadata must not be set"
        );
        assert!(
            st.metadata().get("error-domain").is_none(),
            "non-normative error-domain metadata must not be set"
        );
        assert!(
            st.metadata().get("error-http-status").is_none(),
            "non-normative error-http-status metadata must not be set"
        );
    }

    #[test]
    fn job_not_found_carries_error_info_404() {
        let err = KernelError::job_not_found();
        let st = kernel_error_to_status(&err);
        assert_eq!(st.message(), "Job not found");
        assert_matches_describe(&st, KernelErrorCode::JobNotFound);
    }

    #[test]
    fn wrong_phase_carries_error_info_409() {
        let err = KernelError::wrong_phase("Job is no longer in a cancellable state");
        let st = kernel_error_to_status(&err);
        assert_matches_describe(&st, KernelErrorCode::WrongPhase);
    }

    #[test]
    fn challenge_expired_is_unauthenticated_410_not_401() {
        let err = KernelError::new(KernelErrorCode::ChallengeExpired, "challenge expired");
        let st = kernel_error_to_status(&err);
        assert_eq!(st.code(), Code::Unauthenticated);
        assert_matches_describe(&st, KernelErrorCode::ChallengeExpired);
        let info = require_single_error_info(&st);
        assert_eq!(
            info.metadata.get("http_status").map(String::as_str),
            Some("410")
        );
        assert_ne!(
            info.metadata.get("http_status").map(String::as_str),
            Some("401"),
            "challenge_expired must not collapse to HTTP 401"
        );
    }

    #[test]
    fn session_expired_is_unauthenticated_410_not_401() {
        let err = KernelError::new(KernelErrorCode::SessionExpired, "session expired");
        let st = kernel_error_to_status(&err);
        assert_eq!(st.code(), Code::Unauthenticated);
        assert_matches_describe(&st, KernelErrorCode::SessionExpired);
        let info = require_single_error_info(&st);
        assert_eq!(
            info.metadata.get("http_status").map(String::as_str),
            Some("410")
        );
        assert_ne!(
            info.metadata.get("http_status").map(String::as_str),
            Some("401"),
            "session_expired must not collapse to HTTP 401"
        );
    }

    #[test]
    fn unauthorized_is_unauthenticated_401() {
        let err = KernelError::new(KernelErrorCode::Unauthorized, "missing capability");
        let st = kernel_error_to_status(&err);
        assert_matches_describe(&st, KernelErrorCode::Unauthorized);
        let info = require_single_error_info(&st);
        assert_eq!(
            info.metadata.get("http_status").map(String::as_str),
            Some("401")
        );
    }

    #[test]
    fn exactly_one_error_info_detail() {
        let err = KernelError::job_not_found();
        let st = kernel_error_to_status(&err);
        let details = st.check_error_details_vec().expect("details must decode");
        assert_eq!(
            details.len(),
            1,
            "must be exactly one detail, not zero or two"
        );
        assert!(
            matches!(details[0], ErrorDetail::ErrorInfo(_)),
            "sole detail must be ErrorInfo"
        );
        // Binary details field must be non-empty (the packed google.rpc.Status).
        assert!(
            !st.details().is_empty(),
            "Status.details bytes must not be empty when ErrorInfo is packed"
        );
    }

    #[test]
    fn stream_terminal_status_uses_same_error_info_form() {
        // StreamJob open failure and mid-stream `yield Err(...)` both go
        // through `map_domain_err` → `kernel_error_to_status`. The terminal
        // Status shape is therefore identical to unary.
        let open = kernel_error_to_status(&KernelError::job_not_found());
        let mid =
            kernel_error_to_status(&KernelError::stream_channel_failed("phase channel closed"));
        assert_matches_describe(&open, KernelErrorCode::JobNotFound);
        assert_matches_describe(&mid, KernelErrorCode::InternalError);
        // Both carry exactly one ErrorInfo (no stream-only vocabulary).
        assert_eq!(open.check_error_details_vec().expect("decode").len(), 1);
        assert_eq!(mid.check_error_details_vec().expect("decode").len(), 1);
    }

    #[test]
    fn internal_error_never_leaks_operator_detail() {
        let secret = "completed job is missing response_body result";
        let err = KernelError::corrupt_job_row(secret);
        let st = kernel_error_to_status(&err);
        assert_eq!(st.code(), Code::Internal);
        assert_eq!(st.message(), "Failed to load job");
        assert!(
            !st.message().contains("response_body"),
            "operator detail must not appear in Status.message"
        );
        assert!(
            !st.message().contains(secret),
            "operator context must not appear in Status.message"
        );

        let info = require_single_error_info(&st);
        assert_eq!(info.reason, "internal_error");
        assert_eq!(info.domain, ERROR_INFO_DOMAIN);
        assert_eq!(
            info.metadata.get("http_status").map(String::as_str),
            Some("500")
        );
        // Context must not leak into any ErrorInfo field or the raw bytes
        // as UTF-8 of the secret string.
        assert!(!info.reason.contains(secret));
        assert!(!info.domain.contains(secret));
        for (k, v) in &info.metadata {
            assert!(!k.contains(secret), "metadata key leaked context");
            assert!(!v.contains(secret), "metadata value leaked context");
            assert!(
                !v.contains("response_body"),
                "metadata value leaked operator detail"
            );
        }
        let details_utf8 = String::from_utf8_lossy(st.details());
        assert!(
            !details_utf8.contains(secret),
            "operator context must not appear in Status.details bytes"
        );
        assert!(
            !details_utf8.contains("response_body"),
            "operator detail must not appear in Status.details bytes"
        );
        assert_eq!(err.code, KernelErrorCode::InternalError);
        assert!(err.internal_context.is_some());
    }

    #[test]
    fn four_plus_codes_match_describe_table() {
        // Closed set of codes required by the contract tests, including both
        // 410 special cases that share UNAUTHENTICATED with unauthorized.
        let cases = [
            KernelErrorCode::JobNotFound,
            KernelErrorCode::WrongPhase,
            KernelErrorCode::ChallengeExpired,
            KernelErrorCode::SessionExpired,
            KernelErrorCode::Unauthorized,
            KernelErrorCode::MalformedRequest,
        ];
        for code in cases {
            let err = KernelError::new(code, "public");
            let st = kernel_error_to_status(&err);
            assert_matches_describe(&st, code);
        }
    }
}
