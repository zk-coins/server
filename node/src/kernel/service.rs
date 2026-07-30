//! Kernel service façade.
//!
//! Block 1–4: `get_job`, `stream_job`, `cancel_job`, `sign_transition`,
//! `submit_transition`. Block 5: `attest_balance`, `issue_view_grant`,
//! and the shared challenge-store issue helpers. Remaining §7.8
//! procedures land in later blocks on this same type — they are
//! intentionally absent here rather than stubbed.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::job_dispatcher::{JobEnvelope, JobNotifyMap};
use crate::job_store::JobStore;
use crate::kernel::attestation::{self, AttestBalanceCommand, AttestBalanceDeps};
use crate::kernel::bootstrap::ChallengeStore;
use crate::kernel::grants::{self, IssueViewGrantCommand, IssueViewGrantDeps, ViewGrantIssued};
use crate::kernel::jobs;
use crate::kernel::jobs::sign::SignTransitionDeps;
use crate::kernel::jobs::submit::SubmitTransitionDeps;
use crate::kernel::{
    CancelPolicy, Job, JobEvent, JobEventHub, JobRequest, KernelResult, KernelStream,
    SignTransition, TransitionCommand,
};
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
    /// Shared action-bound challenge store (AttestBalance / IssueViewGrant).
    challenges: Arc<ChallengeStore>,
}

impl KernelService {
    pub(crate) fn new(
        job_store: Arc<JobStore>,
        job_events: JobEventHub,
        pending_sign_map: PendingSignMap,
        notify_map: JobNotifyMap,
        challenges: Arc<ChallengeStore>,
    ) -> Self {
        Self {
            job_store,
            job_events,
            pending_sign_map,
            notify_map,
            challenges,
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
            ChallengeStore::shared(),
        )
    }

    /// Production / gRPC boot: store + shared notify map + pending-sign map
    /// + shared challenge store (same instance as HTTP `AppState`).
    pub(crate) fn from_parts(
        job_store: Arc<JobStore>,
        notify_map: JobNotifyMap,
        pending_sign_map: PendingSignMap,
        challenges: Arc<ChallengeStore>,
    ) -> Self {
        Self::new(
            job_store,
            JobEventHub::new(Arc::clone(&notify_map)),
            pending_sign_map,
            notify_map,
            challenges,
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

    /// `SubmitTransition` — presence/bounds validate, admit, dispatcher handoff.
    ///
    /// `job_tx` is the same admit queue the legacy mint/send routes use.
    /// Kept as a method argument (not stored on the service) so read-only
    /// `from_store` constructions stay free of a channel.
    pub(crate) async fn submit_transition(
        &self,
        job_tx: &mpsc::Sender<JobEnvelope>,
        request: TransitionCommand,
    ) -> KernelResult<Job> {
        jobs::submit_transition(
            SubmitTransitionDeps {
                store: self.job_store.as_ref(),
                job_tx,
            },
            request,
        )
        .await
    }

    /// `AttestBalance` — consume challenge, admit `attest_balance` job.
    ///
    /// Caller has already verified the action-bound OwnershipProof.
    pub(crate) async fn attest_balance(
        &self,
        job_tx: &mpsc::Sender<JobEnvelope>,
        allowed_chan_binds: &[[u8; 32]],
        now: u64,
        command: AttestBalanceCommand,
    ) -> KernelResult<Job> {
        attestation::attest_balance(
            AttestBalanceDeps {
                challenges: self.challenges.as_ref(),
                store: self.job_store.as_ref(),
                job_tx,
                allowed_chan_binds,
                now,
            },
            command,
        )
        .await
    }

    /// `IssueViewGrant` — consume challenge, sign §5.2 grant with `op`.
    ///
    /// Caller has already verified the action-bound OwnershipProof.
    /// `op_sk` is the account's operational BIP-340 secret when entrusted.
    pub(crate) fn issue_view_grant(
        &self,
        allowed_chan_binds: &[[u8; 32]],
        now: u64,
        op_sk: Option<&[u8; 32]>,
        command: IssueViewGrantCommand,
    ) -> KernelResult<ViewGrantIssued> {
        grants::issue_view_grant(
            IssueViewGrantDeps {
                challenges: self.challenges.as_ref(),
                allowed_chan_binds,
                now,
                op_sk,
            },
            command,
        )
    }
}
