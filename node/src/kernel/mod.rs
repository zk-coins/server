//! Transport-free kernel domain layer (§6.1 / §7.8).
//!
//! Visibility is `pub(crate)` throughout so the public-surface allowlist
//! does not move. This tree must not depend on `axum` or `tonic`.

pub(crate) mod error;
pub(crate) mod job_projection;
pub(crate) mod jobs;
pub(crate) mod service;
pub(crate) mod types;

pub(crate) use error::{KernelError, KernelErrorCode, KernelResult};
pub(crate) use service::KernelService;
pub(crate) use types::{Job, JobId, JobKind, JobRequest, JobState, NormativeJobStatus};
