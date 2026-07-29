//! Strict `job_store::Job` → `kernel::types::Job` mapper.
//!
//! A row that cannot be represented as a complete domain job is an
//! `internal_error`, never a partial success. No silent omission of
//! required payloads, no `unwrap_or` defaults, no JSON `null` stand-ins.

use crate::job_store;
use crate::kernel::error::{KernelError, KernelResult};
use crate::kernel::types::{Job, JobId, JobKind, JobPayload, JobState, NormativeJobStatus};

/// Project a persistence row into a typed domain job.
///
/// # Fail-closed payloads
///
/// Backend correctness is fail-closed: prefer an error over a value that
/// pretends completeness. A `completed` or `awaiting_signature` row without
/// a real `response_body` is corrupt data, not a contract shape — exactly
/// the half-success pattern this kernel split exists to eliminate.
pub(crate) fn project_job_row(row: &job_store::Job) -> KernelResult<Job> {
    let kind = JobKind::from_store(row.kind);
    let normative = NormativeJobStatus::from_store(row.status);
    let state = match normative {
        NormativeJobStatus::Accepted => JobState::Accepted,
        NormativeJobStatus::Proving => JobState::Proving,
        NormativeJobStatus::Publishing => JobState::Publishing,
        NormativeJobStatus::AwaitingSignature => {
            let payload = require_response_payload(
                &row.response_body,
                "awaiting_signature job is missing response_body payload",
            )?;
            JobState::AwaitingSignature {
                payload,
                proof_id: row.proof_id,
            }
        }
        NormativeJobStatus::Completed => {
            let result = require_response_payload(
                &row.response_body,
                "completed job is missing response_body result",
            )?;
            JobState::Completed { result }
        }
        NormativeJobStatus::Failed => JobState::Failed {
            error: row.error.clone(),
        },
        NormativeJobStatus::Cancelled => JobState::Cancelled {
            error: row.error.clone(),
        },
    };

    Ok(Job {
        id: JobId(row.public_id),
        kind,
        phase: row.phase.clone(),
        progress: row.progress,
        state,
    })
}

/// Require a non-null JSON payload. SQL NULL and JSON `null` are both
/// corrupt for states that carry a result / signature surface.
fn require_response_payload(
    body: &Option<serde_json::Value>,
    detail: &'static str,
) -> KernelResult<JobPayload> {
    match body {
        Some(value) if !value.is_null() => Ok(JobPayload(value.clone())),
        Some(_) => Err(KernelError::corrupt_job_row(format!(
            "{detail}: response_body is JSON null"
        ))),
        None => Err(KernelError::corrupt_job_row(detail)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job_store::{Job as StoreJob, JobKind as StoreKind, JobStatus as StoreStatus};
    use crate::kernel::error::KernelErrorCode;
    use chrono::Utc;
    use uuid::Uuid;

    fn base_row(status: StoreStatus) -> StoreJob {
        StoreJob {
            id: 1,
            public_id: Uuid::from_u128(0x1111_2222_3333_4444_5555_6666_7777_8888),
            kind: StoreKind::Mint,
            status,
            phase: status.as_str().to_string(),
            account_address: [0xABu8; 32],
            idempotency_key: Some("k".to_string()),
            request_body: serde_json::json!({}),
            response_body: None,
            response_status: None,
            proof_id: None,
            error: None,
            progress: 0,
            reset_generation: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            completed_at: None,
        }
    }

    #[test]
    fn maps_queued_to_accepted_alias() {
        let row = base_row(StoreStatus::Queued);
        let job = project_job_row(&row).expect("queued is well-formed");
        assert_eq!(job.state, JobState::Accepted);
        assert_eq!(job.normative_status().as_v1_str(), "accepted");
        assert_eq!(job.normative_status().as_legacy_str(), "queued");
        assert!(!job.state.is_terminal());
    }

    #[test]
    fn maps_proving() {
        let mut row = base_row(StoreStatus::Proving);
        row.phase = "proving_circuit".to_string();
        row.progress = 40;
        let job = project_job_row(&row).expect("proving");
        assert_eq!(job.state, JobState::Proving);
        assert_eq!(job.phase, "proving_circuit");
        assert_eq!(job.progress, 40);
        assert_eq!(job.normative_status().as_v1_str(), "proving");
        assert_eq!(job.normative_status().as_legacy_str(), "proving");
    }

    #[test]
    fn maps_awaiting_signature_with_payload_and_proof_id() {
        let mut row = base_row(StoreStatus::AwaitingSignature);
        row.kind = StoreKind::Send;
        row.proof_id = Some(42);
        row.response_body = Some(serde_json::json!({
            "account_state_hash": "aa".repeat(32),
            "output_coins_root": "bb".repeat(32),
        }));
        let job = project_job_row(&row).expect("awaiting_signature");
        match &job.state {
            JobState::AwaitingSignature { payload, proof_id } => {
                assert_eq!(*proof_id, Some(42));
                assert_eq!(payload.0["account_state_hash"], "aa".repeat(32));
            }
            other => panic!("expected AwaitingSignature, got {other:?}"),
        }
        assert_eq!(job.kind, JobKind::Send);
        assert_eq!(job.normative_status().as_v1_str(), "awaiting_signature");
    }

    #[test]
    fn maps_broadcasting_to_publishing_alias() {
        let mut row = base_row(StoreStatus::Broadcasting);
        row.phase = "publishing".to_string();
        let job = project_job_row(&row).expect("broadcasting");
        assert_eq!(job.state, JobState::Publishing);
        assert_eq!(job.normative_status().as_v1_str(), "publishing");
        assert_eq!(job.normative_status().as_legacy_str(), "broadcasting");
    }

    #[test]
    fn maps_completed_with_result() {
        let mut row = base_row(StoreStatus::Completed);
        row.progress = 100;
        row.response_body = Some(serde_json::json!({"success": true, "proof_id": 7}));
        let job = project_job_row(&row).expect("completed");
        match &job.state {
            JobState::Completed { result } => {
                assert_eq!(result.0["proof_id"], 7);
                assert_eq!(result.0["success"], true);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
        assert!(job.state.is_terminal());
        assert_eq!(job.normative_status().as_v1_str(), "completed");
    }

    #[test]
    fn maps_failed_with_error_text() {
        let mut row = base_row(StoreStatus::Failed);
        row.error = Some("synthetic error".to_string());
        let job = project_job_row(&row).expect("failed");
        match &job.state {
            JobState::Failed { error } => {
                assert_eq!(error.as_deref(), Some("synthetic error"));
            }
            other => panic!("expected Failed, got {other:?}"),
        }
        assert_eq!(job.normative_status().as_v1_str(), "failed");
    }

    #[test]
    fn maps_cancelled() {
        let row = base_row(StoreStatus::Cancelled);
        let job = project_job_row(&row).expect("cancelled");
        match &job.state {
            JobState::Cancelled { error } => assert_eq!(*error, None),
            other => panic!("expected Cancelled, got {other:?}"),
        }
        assert_eq!(job.normative_status().as_v1_str(), "cancelled");
        assert_eq!(job.normative_status().as_legacy_str(), "cancelled");
    }

    #[test]
    fn completed_without_response_body_is_internal_error() {
        // Against today's handler this would have been HTTP 200 without
        // `result`. The domain mapper must refuse the half-state.
        let row = base_row(StoreStatus::Completed);
        let err = project_job_row(&row).expect_err("missing result must fail");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        let detail = err
            .internal_context
            .as_ref()
            .expect("internal context required")
            .detail
            .as_str();
        assert!(
            detail.contains("completed") && detail.contains("response_body"),
            "detail must name the cause, got: {detail}"
        );
    }

    #[test]
    fn completed_with_json_null_response_body_is_internal_error() {
        let mut row = base_row(StoreStatus::Completed);
        row.response_body = Some(serde_json::Value::Null);
        let err = project_job_row(&row).expect_err("JSON null is not a result");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        let detail = &err.internal_context.expect("context").detail;
        assert!(
            detail.contains("null"),
            "detail must name JSON null, got: {detail}"
        );
    }

    #[test]
    fn awaiting_signature_without_response_body_is_internal_error() {
        let row = base_row(StoreStatus::AwaitingSignature);
        let err = project_job_row(&row).expect_err("missing payload must fail");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        let detail = &err.internal_context.expect("context").detail;
        assert!(
            detail.contains("awaiting_signature") && detail.contains("response_body"),
            "detail must name the cause, got: {detail}"
        );
    }

    #[test]
    fn maps_attest_balance_kind() {
        let mut row = base_row(StoreStatus::Queued);
        row.kind = StoreKind::AttestBalance;
        let job = project_job_row(&row).expect("attest");
        assert_eq!(job.kind, JobKind::AttestBalance);
        assert_eq!(job.kind.as_str(), "attest_balance");
    }
}
