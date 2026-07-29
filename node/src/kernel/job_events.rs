//! Transport-neutral job event source (`StreamJob`, Entwurf §3).
//!
//! Subscribers receive a typed snapshot immediately, then phase changes.
//! Heartbeats / SSE `KeepAlive` are HTTP-only and do **not** appear here.
//! This module must not import `axum` or `tonic`.

use std::sync::Arc;

use tokio::sync::broadcast;
use uuid::Uuid;

use crate::job_dispatcher::{JobNotifier, JobNotifyMap, JobPhaseEvent};
use crate::job_store::JobStore;
use crate::kernel::error::{KernelError, KernelResult};
use crate::kernel::job_projection::{project_job_row, project_phase_event};
use crate::kernel::types::{JobEvent, JobRequest, KernelStream};

/// Fan-out hub over the per-job phase broadcast channels.
///
/// Wraps the existing dispatcher notify map so admission-time notifiers
/// and SSE/gRPC subscribers share one channel. Published values on the
/// wire channel are still [`JobPhaseEvent`] (dispatcher contract); the
/// hub decodes them once via [`project_phase_event`] into domain
/// [`JobEvent`]s.
#[derive(Clone)]
pub(crate) struct JobEventHub {
    notify_map: JobNotifyMap,
}

impl JobEventHub {
    pub(crate) fn new(notify_map: JobNotifyMap) -> Self {
        Self { notify_map }
    }

    /// Ensure a notifier exists for `job_id` and return a fresh subscriber.
    ///
    /// Created at subscribe time when the dispatcher has not yet inserted
    /// an entry (still `queued`). Mirrors the pre-split stream handlers.
    pub(crate) fn subscribe_phase_rx(&self, job_id: Uuid) -> broadcast::Receiver<JobPhaseEvent> {
        let notifier = self
            .notify_map
            .entry(job_id)
            .or_insert_with(|| Arc::new(JobNotifier::new()))
            .clone();
        notifier.phase_tx.subscribe()
    }

    /// `StreamJob`: load + project snapshot, then forward phase changes.
    ///
    /// # Stream contract
    ///
    /// 1. First item is the current typed snapshot.
    /// 2. Further items are `Phase` / terminal `Complete` / `Error`.
    /// 3. Terminal event is the last item; then the stream ends.
    /// 4. Decode / channel failures surface as `Err(KernelError)` then end.
    ///
    /// A late subscriber that joins after a transition still gets a
    /// **consistent** snapshot from the store (not a half-history replay).
    pub(crate) async fn subscribe(
        &self,
        store: &JobStore,
        request: JobRequest,
    ) -> KernelResult<KernelStream<JobEvent>> {
        let id = request.id;
        let row = match store.load(id.as_uuid()).await {
            Ok(Some(job)) => job,
            Ok(None) => return Err(KernelError::job_not_found()),
            Err(e) => {
                tracing::error!("JobStore::load failed in StreamJob: {}", e);
                return Err(KernelError::store_load_failed(e.to_string()));
            }
        };

        // Subscribe before projecting so transitions that land during
        // projection still queue on this receiver (same race window as
        // the pre-split handler).
        let mut rx = self.subscribe_phase_rx(id.as_uuid());

        let snapshot = project_job_row(&row)?;
        let kind_fixed = snapshot.kind;
        let id_fixed = snapshot.id;
        let is_terminal = snapshot.state.is_terminal();
        let initial = JobEvent::from_job(snapshot);

        let stream = async_stream::stream! {
            yield Ok(initial);
            if is_terminal {
                return;
            }
            loop {
                match rx.recv().await {
                    Ok(phase) => {
                        // Mid-stream progress is not carried on JobPhaseEvent;
                        // v1 SSE historically hard-coded 0.0 — keep that.
                        match project_phase_event(id_fixed, kind_fixed, 0, &phase) {
                            Ok(job) => {
                                let terminal = job.state.is_terminal();
                                yield Ok(JobEvent::from_job(job));
                                if terminal {
                                    return;
                                }
                            }
                            Err(e) => {
                                // Fail-closed: do not emit a half-frame.
                                tracing::error!(
                                    "StreamJob phase decode failed for {}: {}",
                                    id_fixed.as_uuid(),
                                    e
                                );
                                yield Err(e);
                                return;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::error!(
                            "StreamJob phase channel lagged by {} for {}",
                            n,
                            id_fixed.as_uuid()
                        );
                        yield Err(KernelError::stream_channel_failed(format!(
                            "phase channel lagged by {n}"
                        )));
                        return;
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        tracing::error!(
                            "StreamJob phase channel closed for {}",
                            id_fixed.as_uuid()
                        );
                        // Pre-split closed silently; we log, then end without
                        // a fabricated domain event (no half-success frame).
                        return;
                    }
                }
            }
        };

        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::job_dispatcher::{publish_phase, JobPhaseEvent};
    use crate::job_store::{JobKind as StoreKind, JobStatus as StoreStatus};
    use crate::kernel::error::KernelErrorCode;
    use crate::kernel::types::{JobEventKind, JobId, JobKind, JobState};
    use crate::test_db::{setup_pool, SchemaScope};
    use futures_util::StreamExt;
    use std::sync::Arc;

    /// Collect until terminal Ok, Err, or stream end.
    async fn collect_stream(mut stream: KernelStream<JobEvent>) -> Vec<KernelResult<JobEvent>> {
        let mut out = Vec::new();
        while let Some(item) = stream.next().await {
            let terminal_ok = matches!(&item, Ok(ev) if ev.job.state.is_terminal());
            let is_err = item.is_err();
            out.push(item);
            if terminal_ok || is_err {
                break;
            }
        }
        out
    }

    async fn store_and_hub() -> (Arc<JobStore>, JobEventHub, SchemaScope) {
        let scope = setup_pool().await;
        let store = Arc::new(JobStore::new(scope.pool.clone()));
        let hub = JobEventHub::new(Arc::new(dashmap::DashMap::new()));
        (store, hub, scope)
    }

    #[tokio::test]
    async fn subscribe_unknown_is_job_not_found() {
        let (store, hub, _db) = store_and_hub().await;
        // Match without `Debug` on the Ok stream type (same shape as
        // `kernel_rpc::expect_unimplemented`).
        let err = match hub
            .subscribe(
                store.as_ref(),
                JobRequest {
                    id: JobId(uuid::Uuid::new_v4()),
                },
            )
            .await
        {
            Ok(_) => panic!("unknown job must not return Ok stream"),
            Err(e) => e,
        };
        assert_eq!(err.code, KernelErrorCode::JobNotFound);
    }

    #[tokio::test]
    async fn subscribe_terminal_completed_emits_single_complete() {
        let (store, hub, _db) = store_and_hub().await;
        let created = store
            .create(
                StoreKind::Mint,
                &[0x11u8; 32],
                Some("k-stream-snap"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!("fresh"),
        };
        store
            .complete(id, serde_json::json!({"success": true, "proof_id": 9}), 200)
            .await
            .expect("complete");

        let stream = hub
            .subscribe(store.as_ref(), JobRequest { id: JobId(id) })
            .await
            .expect("subscribe");
        let items = collect_stream(stream).await;
        assert_eq!(items.len(), 1, "terminal snapshot only");
        let ev = items[0].as_ref().expect("ok");
        assert_eq!(ev.kind, JobEventKind::Complete);
        match &ev.job.state {
            JobState::Completed { result } => {
                assert_eq!(result.0["proof_id"], 9);
            }
            other => panic!("expected Completed, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn subscribe_each_terminal_kind() {
        let (store, hub, _db) = store_and_hub().await;

        // Failed
        let created = store
            .create(
                StoreKind::Mint,
                &[0x12u8; 32],
                Some("k-stream-fail"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let fail_id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        store.fail(fail_id, "boom").await.expect("fail");
        let stream = hub
            .subscribe(store.as_ref(), JobRequest { id: JobId(fail_id) })
            .await
            .expect("sub");
        let items = collect_stream(stream).await;
        assert_eq!(items[0].as_ref().unwrap().kind, JobEventKind::Error);
        assert!(matches!(
            items[0].as_ref().unwrap().job.state,
            JobState::Failed { .. }
        ));

        // Cancelled
        let created = store
            .create(
                StoreKind::Mint,
                &[0x13u8; 32],
                Some("k-stream-cancel"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let cancel_id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        assert!(store.cancel(cancel_id).await.expect("cancel"));
        let stream = hub
            .subscribe(
                store.as_ref(),
                JobRequest {
                    id: JobId(cancel_id),
                },
            )
            .await
            .expect("sub");
        let items = collect_stream(stream).await;
        assert_eq!(items[0].as_ref().unwrap().kind, JobEventKind::Error);
        assert!(matches!(
            items[0].as_ref().unwrap().job.state,
            JobState::Cancelled { .. }
        ));
    }

    #[tokio::test]
    async fn late_subscriber_gets_consistent_snapshot_not_half_history() {
        // Job advances queued → proving in the store. A subscriber that
        // joins afterwards must see proving as the snapshot, not a
        // reconstructed queued→proving replay.
        let (store, hub, _db) = store_and_hub().await;
        let created = store
            .create(
                StoreKind::Send,
                &[0x14u8; 32],
                Some("k-late-join"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        store
            .set_status(id, StoreStatus::Proving, "proving_circuit")
            .await
            .expect("proving");

        let stream = hub
            .subscribe(store.as_ref(), JobRequest { id: JobId(id) })
            .await
            .expect("subscribe");
        let items = collect_stream_until_n(stream, 1).await;
        let ev = items[0].as_ref().expect("ok");
        assert_eq!(ev.kind, JobEventKind::Phase);
        assert_eq!(ev.job.state, JobState::Proving);
        assert_eq!(ev.job.phase, "proving_circuit");
        assert_eq!(ev.job.kind, JobKind::Send);
        // No prior queued event in the stream.
        assert_eq!(items.len(), 1);
    }

    #[tokio::test]
    async fn phase_events_forward_and_terminal_closes() {
        let (store, hub, _db) = store_and_hub().await;
        let created = store
            .create(
                StoreKind::Mint,
                &[0x15u8; 32],
                Some("k-forward"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };

        // Pre-arm notifier so publish_phase is not a no-op.
        let _rx_keep = hub.subscribe_phase_rx(id);

        let stream = hub
            .subscribe(store.as_ref(), JobRequest { id: JobId(id) })
            .await
            .expect("subscribe");

        let collect = tokio::spawn(async move { collect_stream(stream).await });

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        publish_phase(
            &hub.notify_map,
            id,
            JobPhaseEvent {
                status: StoreStatus::Proving,
                phase: "proving".to_string(),
                proof_id: None,
                result: None,
                error: None,
            },
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        publish_phase(
            &hub.notify_map,
            id,
            JobPhaseEvent {
                status: StoreStatus::Completed,
                phase: "completed".to_string(),
                proof_id: None,
                result: Some(serde_json::json!({"ok": true})),
                error: None,
            },
        );

        let items = tokio::time::timeout(std::time::Duration::from_secs(10), collect)
            .await
            .expect("timeout")
            .expect("join");
        assert!(
            items.len() >= 2,
            "snapshot + at least terminal; got {}",
            items.len()
        );
        let last = items.last().unwrap().as_ref().unwrap();
        assert_eq!(last.kind, JobEventKind::Complete);
        assert!(matches!(last.job.state, JobState::Completed { .. }));
    }

    #[tokio::test]
    async fn completed_without_result_on_phase_is_stream_error() {
        // Would have been a complete frame with result:null on the old path.
        let (store, hub, _db) = store_and_hub().await;
        let created = store
            .create(
                StoreKind::Mint,
                &[0x16u8; 32],
                Some("k-mask-complete"),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let id = match created {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!(),
        };
        let _rx_keep = hub.subscribe_phase_rx(id);
        let stream = hub
            .subscribe(store.as_ref(), JobRequest { id: JobId(id) })
            .await
            .expect("subscribe");
        let collect = tokio::spawn(async move { collect_stream(stream).await });
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        publish_phase(
            &hub.notify_map,
            id,
            JobPhaseEvent {
                status: StoreStatus::Completed,
                phase: "completed".to_string(),
                proof_id: None,
                result: None, // MASKING
                error: None,
            },
        );
        let items = tokio::time::timeout(std::time::Duration::from_secs(10), collect)
            .await
            .expect("timeout")
            .expect("join");
        // Snapshot (queued) then Err for corrupt complete.
        assert!(items.len() >= 2);
        let err = items
            .last()
            .unwrap()
            .as_ref()
            .expect_err("must fail closed");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        let detail = &err.internal_context.as_ref().expect("ctx").detail;
        assert!(
            detail.contains("completed") && detail.contains("response_body"),
            "detail={detail}"
        );
    }

    #[tokio::test]
    async fn completed_row_without_body_refuses_subscribe() {
        let (store, hub, scope) = store_and_hub().await;
        let job_id = uuid::Uuid::new_v4();
        sqlx::query(
            "INSERT INTO jobs \
             (public_id, kind, status, phase, account_address, idempotency_key, request_body, \
              progress, reset_generation) \
             VALUES ($1, 'mint', 'completed', 'completed', $2, $3, '{}'::jsonb, 100, 0)",
        )
        .bind(job_id)
        .bind(&[0x17u8; 32][..])
        .bind("k-corrupt-snap")
        .execute(&scope.pool)
        .await
        .expect("plant");

        // Match without `Debug` on the Ok stream type (same shape as
        // `kernel_rpc::expect_unimplemented`).
        let err = match hub
            .subscribe(store.as_ref(), JobRequest { id: JobId(job_id) })
            .await
        {
            Ok(_) => panic!("corrupt completed row must not return Ok stream"),
            Err(e) => e,
        };
        assert_eq!(err.code, KernelErrorCode::InternalError);
    }

    /// Drain at most `n` items without requiring terminal.
    async fn collect_stream_until_n(
        mut stream: KernelStream<JobEvent>,
        n: usize,
    ) -> Vec<KernelResult<JobEvent>> {
        let mut out = Vec::new();
        while out.len() < n {
            match stream.next().await {
                Some(item) => out.push(item),
                None => break,
            }
        }
        out
    }
}
