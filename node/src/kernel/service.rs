//! Kernel service façade.
//!
//! Block 1 exposes only `get_job`. The remaining §7.8 procedures land in
//! later blocks on this same type — they are intentionally absent here
//! rather than stubbed, so a caller cannot pretend they are implemented.

use std::sync::Arc;

use crate::job_store::JobStore;
use crate::kernel::error::KernelResult;
use crate::kernel::jobs;
use crate::kernel::types::{Job, JobRequest};

/// Crate-private kernel façade. Holds only the dependencies Block 1 needs.
#[derive(Clone)]
pub(crate) struct KernelService {
    job_store: Arc<JobStore>,
}

impl KernelService {
    pub(crate) fn new(job_store: Arc<JobStore>) -> Self {
        Self { job_store }
    }

    /// `GetJob` — load and strictly project one job.
    pub(crate) async fn get_job(&self, request: JobRequest) -> KernelResult<Job> {
        jobs::get_job_arc(&self.job_store, request).await
    }
}
