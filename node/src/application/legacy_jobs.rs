//! Legacy ash‖ocr job surfaces — transport-neutral, not normative §7.8.
//!
//! [`commit_legacy`] is the quarantined `POST /api/jobs/:id/commit` path.
//! It is **not** `SignTransition`: it never installs a §3.2
//! `TransitionSignature` into the durable finalisation capability and
//! therefore cannot drive `drive_v1_finalise`. Under a v1.1 process claim
//! it is refused at the entry gate ([`refuse_legacy_commitment_under_v1`]);
//! `commit_flow` / `mint_commit_flow` re-check the same gate.

use serde_json::Value;
use uuid::Uuid;

use crate::job_dispatcher::JobNotifyMap;
use crate::job_store::{JobStatus, JobStore};
use crate::v1;

/// Outcome of a successful legacy commit handoff.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LegacyCommitAccepted;

/// Failures of the legacy commit façade (free-text wire, not §7.5 codes).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum LegacyCommitError {
    /// Process is on the v1.1 claim — residual ash‖ocr is refused.
    RefusedUnderV1 {
        message: String,
    },
    NotFound,
    /// Job exists but is not in `awaiting_signature`, or status-CAS lost.
    Conflict {
        message: String,
    },
    /// Store load / persist failure.
    Internal {
        message: String,
    },
    /// No parked dispatcher, or handoff CAS lost after persist.
    NoDispatcherWaiting,
}

/// Legacy `POST /api/jobs/:id/commit` domain path.
///
/// # What this cannot do
///
/// - It does **not** call `accept_wallet_transition_signature`.
/// - It writes only the ash‖ocr `commit` key into `request_body`, never
///   `finalisation.signature` / a `TransitionSignature`.
/// - Under `ScanStackMode::V1` it returns [`LegacyCommitError::RefusedUnderV1`]
///   before any persist or wake — so a v1.1 boot cannot finalise via this
///   route. Even if a notifier were signalled under V1 without a signed
///   capability, the dispatcher prefers `drive_v1_finalise` only when a
///   signature is present, and `commit_flow` / `mint_commit_flow` refuse
///   the legacy Commitment under the same process claim.
///
/// # Ordering
///
/// Persist the merged `commit` body under status-CAS, then
/// `try_signal_accept` + `notify_one` — same handoff shape as the
/// normative sign path, without S2C verification.
pub(crate) async fn commit_legacy(
    store: &JobStore,
    notify_map: &JobNotifyMap,
    id: Uuid,
    commit_value: Value,
) -> Result<LegacyCommitAccepted, LegacyCommitError> {
    if let Err(e) = v1::refuse_legacy_commitment_under_v1() {
        return Err(LegacyCommitError::RefusedUnderV1 {
            message: e.to_string(),
        });
    }

    let job = match store.load(id).await {
        Ok(Some(j)) => j,
        Ok(None) => return Err(LegacyCommitError::NotFound),
        Err(e) => {
            tracing::error!("JobStore::load failed in legacy commit: {}", e);
            return Err(LegacyCommitError::Internal {
                message: "Failed to load job".to_string(),
            });
        }
    };

    if job.status != JobStatus::AwaitingSignature {
        return Err(LegacyCommitError::Conflict {
            message: format!(
                "Job is in status `{}`, not `awaiting_signature`",
                job.status.as_str()
            ),
        });
    }

    let mut merged = job.request_body.clone();
    let obj = match merged.as_object_mut() {
        Some(o) => o,
        None => {
            // Admit handlers only insert objects; a non-object is corrupt.
            // Fail closed rather than inventing `{"commit": ...}` around it.
            return Err(LegacyCommitError::Internal {
                message: "Failed to persist commit payload".to_string(),
            });
        }
    };
    obj.insert("commit".to_string(), commit_value);

    match store
        .replace_request_body_if_status(id, JobStatus::AwaitingSignature, &merged)
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            return Err(LegacyCommitError::Conflict {
                message: "Job is no longer awaiting signature (or was invalidated by a reset)"
                    .to_string(),
            });
        }
        Err(e) => {
            tracing::error!("Failed to merge commit payload into job row: {}", e);
            return Err(LegacyCommitError::Internal {
                message: "Failed to persist commit payload".to_string(),
            });
        }
    }

    let notifier = notify_map.get(&id).map(|e| e.value().clone());
    match notifier {
        Some(n) if n.try_signal_accept() => {
            n.commit_wake.notify_one();
            Ok(LegacyCommitAccepted)
        }
        Some(_) | None => Err(LegacyCommitError::NoDispatcherWaiting),
    }
}
