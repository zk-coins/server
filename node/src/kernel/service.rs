//! Kernel service façade.
//!
//! Block 1–3 expose `get_job`, `stream_job`, `cancel_job`, and
//! `sign_transition`. The remaining §7.8 procedures land in later blocks
//! on this same type — they are intentionally absent here rather than stubbed.

use std::sync::Arc;

use crate::job_dispatcher::JobNotifyMap;
use crate::job_store::JobStore;
use crate::kernel::error::KernelResult;
use crate::kernel::jobs;
use crate::kernel::jobs::sign::SignTransitionDeps;
use crate::kernel::types::KernelStream;
use crate::kernel::{CancelPolicy, Job, JobEvent, JobEventHub, JobRequest, SignTransition};
use crate::v1::PendingSignMap;

/// Crate-private kernel façade.
#[derive(Clone)]
pub(crate) struct KernelService {
    job_store: Arc<JobStore>,
    job_events: JobEventHub,
    pending_sign_map: PendingSignMap,
    /// Shared with the dispatcher / SSE path. Sign looks up a parked
    /// notifier without creating one; StreamJob may create on subscribe.
    notify_map: JobNotifyMap,
}

impl KernelService {
    pub(crate) fn new(
        job_store: Arc<JobStore>,
        job_events: JobEventHub,
        pending_sign_map: PendingSignMap,
        notify_map: JobNotifyMap,
    ) -> Self {
        Self {
            job_store,
            job_events,
            pending_sign_map,
            notify_map,
        }
    }

    /// Convenience when only store-backed read/cancel procedures are needed
    /// and the caller has no sign/stream maps (or empty ones for pure load).
    pub(crate) fn from_store(job_store: Arc<JobStore>) -> Self {
        let notify_map: JobNotifyMap = Arc::new(dashmap::DashMap::new());
        Self::new(
            job_store,
            JobEventHub::new(Arc::clone(&notify_map)),
            Arc::new(dashmap::DashMap::new()),
            notify_map,
        )
    }

    /// Production / gRPC boot: store + shared notify map + pending-sign map.
    pub(crate) fn from_parts(
        job_store: Arc<JobStore>,
        notify_map: JobNotifyMap,
        pending_sign_map: PendingSignMap,
    ) -> Self {
        Self::new(
            job_store,
            JobEventHub::new(Arc::clone(&notify_map)),
            pending_sign_map,
            notify_map,
        )
    }

    /// `GetJob` — load and strictly project one job.
    pub(crate) async fn get_job(&self, request: JobRequest) -> KernelResult<Job> {
        jobs::get_job_arc(&self.job_store, request).await
    }

    /// `StreamJob` — snapshot then phase changes as domain events.
    pub(crate) async fn stream_job(
        &self,
        request: JobRequest,
    ) -> KernelResult<KernelStream<JobEvent>> {
        jobs::stream_job_arc(&self.job_store, &self.job_events, request).await
    }

    /// `CancelJob` with an explicit policy (Legacy vs normative).
    pub(crate) async fn cancel_job(
        &self,
        request: JobRequest,
        policy: CancelPolicy,
    ) -> KernelResult<Job> {
        jobs::cancel_job_arc(&self.job_store, request, policy).await
    }

    /// `SignTransition` — verify wallet S2C/BIP-340, durable persist, handoff.
    pub(crate) async fn sign_transition(&self, request: SignTransition) -> KernelResult<Job> {
        jobs::sign_transition(
            SignTransitionDeps {
                store: self.job_store.as_ref(),
                pending_sign_map: &self.pending_sign_map,
                notify_map: &self.notify_map,
            },
            request,
        )
        .await
    }
}
