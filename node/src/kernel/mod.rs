//! Transport-free kernel domain layer (§6.1 / §7.8).
//!
//! Visibility is `pub(crate)` throughout so the public-surface allowlist
//! does not move. This tree must not depend on `axum` or `tonic`.

pub(crate) mod error;
pub(crate) mod job_events;
pub(crate) mod job_projection;
pub(crate) mod jobs;
pub(crate) mod service;
pub(crate) mod types;

pub(crate) use error::{KernelError, KernelErrorCode};
pub(crate) use job_events::JobEventHub;
pub(crate) use service::KernelService;
pub(crate) use types::{
    CancelPolicy, Job, JobEvent, JobId, JobRequest, JobState, NormativeJobStatus,
};
