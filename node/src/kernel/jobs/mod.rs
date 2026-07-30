//! Job-family kernel operations (`GetJob`, `StreamJob`, `CancelJob`, `SignTransition`).

use std::sync::Arc;

use crate::job_store::{JobStatus, JobStore};
use crate::kernel::error::KernelResult;
use crate::kernel::job_projection::project_job_row;
use crate::kernel::types::{KernelStream, NormativeJobStatus};
use crate::kernel::{CancelPolicy, Job, JobEvent, JobEventHub, JobRequest, KernelError};

pub(crate) mod sign;

pub(crate) use sign::sign_transition;

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

    // Cancel already committed. Project from the pre-loaded row with the
    // store's known cancel effects — do **not** reload. A second load that
    // fails would turn an irreversible success into a client-visible error.
    //
    // `cancel` / `cancel_not_yet_published` (job_store.rs) set:
    //   status = 'cancelled', phase = 'cancelled',
    //   request_body strips finalisation keys,
    //   updated_at = NOW(), completed_at = NOW().
    // They do **not** write `error` or `progress`. Terminal Cancelled needs
    // no payload; `request_body` / timestamps are unused by projection.
    project_cancelled_from_pre_cancel_row(row)
}

/// Apply the known post-cancel row effects and project a domain job.
///
/// Pure: no store I/O. Call only after `cancel` / `cancel_not_yet_published`
/// returned `Ok(true)`.
fn project_cancelled_from_pre_cancel_row(mut row: crate::job_store::Job) -> KernelResult<Job> {
    row.status = JobStatus::Cancelled;
    row.phase = "cancelled".to_string();
    // Terminal Cancelled is always well-formed — no required payload.
    project_job_row(&row)
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
    use crate::kernel::{JobId, JobState, KernelErrorCode};
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
            .set_status(id, JobStatus::Queued, JobStatus::Proving, "proving")
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
            .set_status(id, JobStatus::Queued, JobStatus::Proving, "proving")
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
            .set_status(
                pub_id,
                JobStatus::Queued,
                JobStatus::Broadcasting,
                "broadcasting",
            )
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

    /// Successful cancel must never surface as a cancel/load error just
    /// because a subsequent store read would fail.
    ///
    /// Against the previous `get_job` reload at the end of `cancel_job`,
    /// arming a load failure after the pre-check load made this test red:
    /// cancel committed, reload returned `store_load_failed` / internal
    /// error, and the caller saw failure for an irreversible success.
    #[tokio::test]
    async fn successful_cancel_is_not_error_when_subsequent_load_would_fail() {
        let (store, _db) = fresh_store().await;
        let created = store
            .create(
                StoreKind::Mint,
                &[0x25u8; 32],
                Some("k-c-no-reload"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!("expected Fresh"),
        };
        // Non-zero progress + non-default phase: store cancel does not
        // rewrite progress; projection must keep it and set phase only.
        store
            .set_status(id, JobStatus::Queued, JobStatus::Proving, "proving_circuit")
            .await
            .expect("proving");
        // Plant progress directly — set_status does not take progress.
        sqlx::query("UPDATE jobs SET progress = $1 WHERE public_id = $2")
            .bind(40i16)
            .bind(id)
            .execute(store.pool())
            .await
            .expect("progress");

        // First load (cancel pre-check) succeeds; any later load fails.
        store.arm_load_failures_after_ok_count(1);

        let job = cancel_job(
            store.as_ref(),
            JobRequest { id: JobId(id) },
            CancelPolicy::NotYetPublished,
        )
        .await
        .expect(
            "successful cancel must return Ok even when a post-cancel \
             reload would fail",
        );

        // Cause, not mere is_ok: terminal Cancelled with store-true fields.
        match &job.state {
            JobState::Cancelled { error } => {
                assert_eq!(
                    error, &None,
                    "store cancel does not write error; projection must not invent one"
                );
            }
            other => panic!("expected Cancelled after successful cancel, got {other:?}"),
        }
        assert_eq!(job.phase, "cancelled");
        assert_eq!(
            job.progress, 40,
            "store cancel leaves progress untouched; response must reflect that"
        );

        // Cancel is durable in the store (disarm so we can observe it).
        store.disarm_load_failures();
        let after = store.load(id).await.expect("load").expect("row");
        assert_eq!(after.status, JobStatus::Cancelled);
        assert_eq!(after.phase, "cancelled");
        assert_eq!(after.progress, 40);
        assert!(after.completed_at.is_some());
        assert_eq!(after.error, None);
    }

    #[test]
    fn project_cancelled_applies_known_store_effects_only() {
        use crate::job_store::{Job as StoreJob, JobKind as StoreKind};
        use chrono::Utc;
        use uuid::Uuid;

        let row = StoreJob {
            id: 1,
            public_id: Uuid::from_u128(0xabcd),
            kind: StoreKind::Send,
            status: JobStatus::Proving,
            phase: "proving_circuit".to_string(),
            account_address: [0x11u8; 32],
            idempotency_key: None,
            request_body: serde_json::json!({"pending_sign": {"mode": "initial"}}),
            response_body: None,
            response_status: None,
            proof_id: None,
            error: None,
            progress: 55,
            reset_generation: 0,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            completed_at: None,
        };
        let job = project_cancelled_from_pre_cancel_row(row).expect("cancelled projects");
        assert!(matches!(job.state, JobState::Cancelled { error: None }));
        assert_eq!(job.phase, "cancelled");
        assert_eq!(job.progress, 55);
        assert_eq!(job.kind, crate::kernel::types::JobKind::Send);
        assert_eq!(job.id.as_uuid(), Uuid::from_u128(0xabcd));
    }
}
