//! Transport-free kernel domain layer (§6.1 / §7.8).
//!
//! Visibility is `pub(crate)` throughout so the public-surface allowlist
//! does not move. This tree must not depend on `axum` or `tonic`.

pub(crate) mod access;
pub(crate) mod attestation;
pub(crate) mod bootstrap;
pub(crate) mod chain;
pub(crate) mod error;
pub(crate) mod grants;
pub(crate) mod job_events;
pub(crate) mod job_projection;
pub(crate) mod jobs;
pub(crate) mod publish;
pub(crate) mod service;
pub(crate) mod types;

/// Crate-private kernel façade re-exports.
///
/// Invariant: **what is listed here is used via this façade
/// (`crate::kernel::…`); what is used via this façade is listed here.**
/// Callers must not reach the same names through a defining-module path
/// (`crate::kernel::error::…`, `crate::kernel::types::…`, …). A name used
/// only from `#[cfg(test)]` code does not belong on this list — tests
/// import it from the defining module when needed.
pub(crate) use chain::{
    AccumulatorTip, ChainIdentity, ChainReadinessFlags, ChainView, KernelInfo, KernelNetwork,
    ListInscriptions, NullifierPath, NullifierPathRequest,
};
pub(crate) use error::{KernelError, KernelErrorCode, KernelResult};
pub(crate) use job_events::JobEventHub;
pub(crate) use service::{ChainHandle, KernelService};
pub(crate) use types::{
    CancelPolicy, Job, JobEvent, JobId, JobRequest, JobState, KernelStream, SignTransition,
    TransitionCommand,
};
