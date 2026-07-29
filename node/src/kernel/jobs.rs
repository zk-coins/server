//! Job-family kernel operations (`GetJob`, `StreamJob`, `CancelJob`).

use std::sync::Arc;

use crate::job_store::{JobStatus, JobStore};
use crate::kernel::error::{KernelError, KernelResult};
use crate::kernel::job_events::JobEventHub;
use crate::kernel::job_projection::project_job_row;
use crate::kernel::types::{
    CancelPolicy, Job, JobEvent, JobRequest, KernelStream, NormativeJobStatus,
};

/// Load and strictly project a single job (`GetJob`, §7.8).
///
/// Allowed public errors for this procedure: `malformed_request`,
/// `job_not_found`, `rate_limited`, `internal_error`. This path emits
/// `job_not_found` and `internal_error`; UUID shape is enforced by the
/// transport adapter before the call.
pub(crate) async fn get_job(store: &JobStore, request: JobRequest) -> KernelResult<Job> {
    let row = match store.load(request.id.as_uuid()).await {
        Ok(Some(job)) => job,
        Ok(None) => return Err(KernelError::job_not_found()),
        Err(e) => {
            tracing::error!("JobStore::load failed: {}", e);
            return Err(KernelError::store_load_failed(e.to_string()));
        }
    };
    project_job_row(&row)
}

/// Convenience when the caller already holds an `Arc<JobStore>`.
pub(crate) async fn get_job_arc(store: &Arc<JobStore>, request: JobRequest) -> KernelResult<Job> {
    get_job(store.as_ref(), request).await
}

/// `StreamJob` — typed event stream (snapshot, then changes).
pub(crate) async fn stream_job(
    store: &JobStore,
    hub: &JobEventHub,
    request: JobRequest,
) -> KernelResult<KernelStream<JobEvent>> {
    hub.subscribe(store, request).await
}

pub(crate) async fn stream_job_arc(
    store: &Arc<JobStore>,
    hub: &JobEventHub,
    request: JobRequest,
) -> KernelResult<KernelStream<JobEvent>> {
    stream_job(store.as_ref(), hub, request).await
}

/// Whether a store status is cancellable under the normative §7.5 policy
/// ("not-yet-published" / immediately before `publishing`).
///
/// Cancellable: `queued`/`accepted`, `proving`, `awaiting_signature`.
/// Not cancellable: `broadcasting`/`publishing` and every terminal.
pub(crate) fn is_cancellable_not_yet_published(status: JobStatus) -> bool {
    matches!(
        status,
        JobStatus::Queued | JobStatus::Proving | JobStatus::AwaitingSignature
    )
}

/// `CancelJob` with an explicit policy so Legacy and v1 stay distinct.
///
/// - [`CancelPolicy::LegacyQueuedOnly`]: only `queued`; does not distinguish
///   unknown vs wrong-phase at the store layer (`cancel` returns `false` for
///   both) — after a successful load we still call `cancel` and map races to
///   `wrong_phase`. Unknown id → `job_not_found` (legacy HTTP maps both to 409).
/// - [`CancelPolicy::NotYetPublished`]: §7.5 set; `wrong_phase` when past it.
pub(crate) async fn cancel_job(
    store: &JobStore,
    request: JobRequest,
    policy: CancelPolicy,
) -> KernelResult<Job> {
    let id = request.id.as_uuid();
    let row = match store.load(id).await {
        Ok(Some(job)) => job,
        Ok(None) => return Err(KernelError::job_not_found()),
        Err(e) => {
            tracing::error!("JobStore::load failed in CancelJob: {}", e);
            return Err(KernelError::store_load_failed(e.to_string()));
        }
    };

    match policy {
        CancelPolicy::LegacyQueuedOnly => {
            if row.status != JobStatus::Queued {
                return Err(KernelError::wrong_phase(
                    "Job is not in a cancellable state",
                ));
            }
            match store.cancel(id).await {
                Ok(true) => {}
                Ok(false) => {
                    // Lost race with dispatcher between load and update.
                    return Err(KernelError::wrong_phase(
                        "Job is not in a cancellable state",
                    ));
                }
                Err(e) => {
                    tracing::error!("JobStore::cancel failed: {}", e);
                    return Err(KernelError::store_cancel_failed(e.to_string()));
                }
            }
        }
        CancelPolicy::NotYetPublished => {
            if !is_cancellable_not_yet_published(row.status) {
                let wire = NormativeJobStatus::from_store(row.status).as_v1_str();
                return Err(KernelError::wrong_phase(format!(
                    "Job is in status `{wire}` and is no longer cancellable \
                     (nullifier already published or terminal)"
                )));
            }
            match store.cancel_not_yet_published(id).await {
                Ok(true) => {}
                Ok(false) => {
                    return Err(KernelError::wrong_phase(
                        "Job is no longer in a cancellable state",
                    ));
                }
                Err(e) => {
                    tracing::error!("JobStore::cancel_not_yet_published failed: {}", e);
                    return Err(KernelError::store_cancel_failed(e.to_string()));
                }
            }
        }
    }

    // Reload the cancelled row and project (terminal Cancelled is always
    // well-formed — no required payload).
    get_job(store, request).await
}

pub(crate) async fn cancel_job_arc(
    store: &Arc<JobStore>,
    request: JobRequest,
    policy: CancelPolicy,
) -> KernelResult<Job> {
    cancel_job(store.as_ref(), request, policy).await
}

#[cfg(test)]
mod cancel_tests {
    use super::*;
    use crate::job_store::JobKind as StoreKind;
    use crate::kernel::error::KernelErrorCode;
    use crate::kernel::types::{JobId, JobState};
    use crate::test_db::{setup_pool, SchemaScope};
    use std::sync::Arc;

    async fn fresh_store() -> (Arc<JobStore>, SchemaScope) {
        let scope = setup_pool().await;
        (Arc::new(JobStore::new(scope.pool.clone())), scope)
    }

    #[tokio::test]
    async fn legacy_cancel_queued_ok() {
        let (store, _db) = fresh_store().await;
        let created = store
            .create(
                StoreKind::Mint,
                &[0x21u8; 32],
                Some("k-c-leg"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        let job = cancel_job(
            store.as_ref(),
            JobRequest { id: JobId(id) },
            CancelPolicy::LegacyQueuedOnly,
        )
        .await
        .expect("cancel");
        assert!(matches!(job.state, JobState::Cancelled { .. }));
    }

    #[tokio::test]
    async fn legacy_cancel_proving_is_wrong_phase() {
        let (store, _db) = fresh_store().await;
        let created = store
            .create(
                StoreKind::Mint,
                &[0x22u8; 32],
                Some("k-c-leg-p"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        store
            .set_status(id, JobStatus::Proving, "proving")
            .await
            .expect("proving");
        let err = cancel_job(
            store.as_ref(),
            JobRequest { id: JobId(id) },
            CancelPolicy::LegacyQueuedOnly,
        )
        .await
        .expect_err("proving");
        assert_eq!(err.code, KernelErrorCode::WrongPhase);
    }

    #[tokio::test]
    async fn v1_cancel_proving_ok_publishing_wrong_phase() {
        let (store, _db) = fresh_store().await;
        let created = store
            .create(
                StoreKind::Send,
                &[0x23u8; 32],
                Some("k-c-v1-p"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        store
            .set_status(id, JobStatus::Proving, "proving")
            .await
            .expect("proving");
        let job = cancel_job(
            store.as_ref(),
            JobRequest { id: JobId(id) },
            CancelPolicy::NotYetPublished,
        )
        .await
        .expect("v1 cancel proving");
        assert!(matches!(job.state, JobState::Cancelled { .. }));

        let created = store
            .create(
                StoreKind::Send,
                &[0x24u8; 32],
                Some("k-c-v1-b"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let pub_id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        store
            .set_status(pub_id, JobStatus::Broadcasting, "broadcasting")
            .await
            .expect("broadcasting");
        let err = cancel_job(
            store.as_ref(),
            JobRequest { id: JobId(pub_id) },
            CancelPolicy::NotYetPublished,
        )
        .await
        .expect_err("publishing");
        assert_eq!(err.code, KernelErrorCode::WrongPhase);
        assert!(
            err.public_message.contains("publishing") || err.public_message.contains("no longer")
        );
    }

    #[tokio::test]
    async fn cancel_unknown_is_job_not_found() {
        let (store, _db) = fresh_store().await;
        let err = cancel_job(
            store.as_ref(),
            JobRequest {
                id: JobId(uuid::Uuid::new_v4()),
            },
            CancelPolicy::NotYetPublished,
        )
        .await
        .expect_err("missing");
        assert_eq!(err.code, KernelErrorCode::JobNotFound);
    }
}
