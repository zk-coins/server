//! Kernel service façade.
//!
//! Block 1–2 expose `get_job`, `stream_job`, and `cancel_job`. The remaining
//! §7.8 procedures land in later blocks on this same type — they are
//! intentionally absent here rather than stubbed.

use std::sync::Arc;

use crate::job_store::JobStore;
use crate::kernel::error::KernelResult;
use crate::kernel::job_events::JobEventHub;
use crate::kernel::jobs;
use crate::kernel::types::{CancelPolicy, Job, JobEvent, JobRequest, KernelStream};

/// Crate-private kernel façade.
#[derive(Clone)]
pub(crate) struct KernelService {
    job_store: Arc<JobStore>,
    job_events: JobEventHub,
}

impl KernelService {
    pub(crate) fn new(job_store: Arc<JobStore>, job_events: JobEventHub) -> Self {
        Self {
            job_store,
            job_events,
        }
    }

    /// Convenience when only store-backed procedures are needed and the
    /// caller has a notify map (or an empty one for pure load paths).
    pub(crate) fn from_store(job_store: Arc<JobStore>) -> Self {
        Self::new(
            job_store,
            JobEventHub::new(Arc::new(dashmap::DashMap::new())),
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
}
