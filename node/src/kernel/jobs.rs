//! Job-family kernel operations (Block 1: `GetJob` only).

use std::sync::Arc;

use crate::job_store::JobStore;
use crate::kernel::error::{KernelError, KernelResult};
use crate::kernel::job_projection::project_job_row;
use crate::kernel::types::{Job, JobRequest};

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
