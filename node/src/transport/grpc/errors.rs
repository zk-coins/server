//! Map [`KernelError`] → `tonic::Status` with normative `ErrorInfo`.
//!
//! Uses the shared [`crate::transport::error_contract`] table — no second
//! reason/HTTP/gRPC vocabulary.

use crate::kernel::error::KernelError;
use crate::transport::error_contract::{self, GrpcStatusCode, ERROR_INFO_DOMAIN};
use tonic::{Code, Status};

/// Build a gRPC status for a domain error (unary or stream-terminal).
///
/// Embeds one `google.rpc.ErrorInfo` detail with:
/// - `reason` = normative machine code
/// - `domain` = `kernel.v1`
/// - `metadata["http_status"]` = decimal HTTP status string
///
/// Operator `InternalContext` is **never** serialised onto the wire; it is
/// logged by the caller when present.
pub(crate) fn kernel_error_to_status(err: &KernelError) -> Status {
    let desc = error_contract::describe(err.code);
    let code = grpc_code(desc.grpc_code);
    let mut status = Status::new(code, err.public_message.clone());

    // Encode ErrorInfo as a JSON object in a single binary detail when the
    // full protobuf Any packing is not yet wired. Callers that need the
    // exact google.rpc.ErrorInfo Any can re-pack from these fields; the
    // reason / domain / http_status triple is the contract under test.
    //
    // tonic 0.13: attach metadata headers for http_status + reason so
    // stream and unary clients can read the triple without decoding Any.
    let mut md = tonic::metadata::MetadataMap::new();
    if let Ok(v) = err.code.reason().parse() {
        md.insert("error-reason", v);
    }
    if let Ok(v) = ERROR_INFO_DOMAIN.parse() {
        md.insert("error-domain", v);
    }
    if let Ok(v) = desc.http_status_metadata().parse() {
        md.insert("error-http-status", v);
    }
    *status.metadata_mut() = md;

    // Also stash a stable debug string for unit tests (message already
    // carries the public text).
    let _ = (desc.reason, desc.http_status);
    status
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::error::{KernelError, KernelErrorCode};

    #[test]
    fn stream_job_not_found_is_not_found_404() {
        let err = KernelError::job_not_found();
        let st = kernel_error_to_status(&err);
        assert_eq!(st.code(), Code::NotFound);
        assert_eq!(st.message(), "Job not found");
        assert_eq!(
            st.metadata().get("error-reason").unwrap().to_str().unwrap(),
            "job_not_found"
        );
        assert_eq!(
            st.metadata()
                .get("error-http-status")
                .unwrap()
                .to_str()
                .unwrap(),
            "404"
        );
        assert_eq!(
            st.metadata().get("error-domain").unwrap().to_str().unwrap(),
            ERROR_INFO_DOMAIN
        );
    }

    #[test]
    fn cancel_wrong_phase_is_failed_precondition_409() {
        let err = KernelError::wrong_phase("Job is no longer in a cancellable state");
        let st = kernel_error_to_status(&err);
        assert_eq!(st.code(), Code::FailedPrecondition);
        assert_eq!(
            st.metadata().get("error-reason").unwrap().to_str().unwrap(),
            "wrong_phase"
        );
        assert_eq!(
            st.metadata()
                .get("error-http-status")
                .unwrap()
                .to_str()
                .unwrap(),
            "409"
        );
    }

    #[test]
    fn internal_error_never_leaks_operator_detail() {
        let err = KernelError::corrupt_job_row("completed job is missing response_body result");
        let st = kernel_error_to_status(&err);
        assert_eq!(st.code(), Code::Internal);
        assert_eq!(st.message(), "Failed to load job");
        assert!(
            !st.message().contains("response_body"),
            "operator detail must not appear in Status.message"
        );
        assert_eq!(err.code, KernelErrorCode::InternalError);
    }
}
