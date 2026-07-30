//! Kernel service façade.
//!
//! Block 1–4: `get_job`, `stream_job`, `cancel_job`, `sign_transition`,
//! `submit_transition`. Block 5: `attest_balance`, `issue_view_grant`,
//! and the shared challenge-store issue helpers. Block 6: read-only chain
//! (`get_info`, `get_accumulator`, `get_nullifier_path`).
//! `ListInscriptions` waits on a scanner-written inscription catalog
//! (reveal txid + §3.5 format are not on the NfLog) — gRPC answers
//! `Unimplemented`; there is no domain projection that invents those
//! fields. Remaining §7.8 procedures land in later blocks on this same
//! type — they are intentionally absent here rather than stubbed.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::job_dispatcher::{JobEnvelope, JobNotifyMap};
use crate::job_store::JobStore;
use crate::kernel::attestation::{self, AttestBalanceCommand, AttestBalanceDeps};
use crate::kernel::bootstrap::ChallengeStore;
use crate::kernel::chain;
use crate::kernel::grants::{self, IssueViewGrantCommand, IssueViewGrantDeps, ViewGrantIssued};
use crate::kernel::jobs;
use crate::kernel::jobs::sign::SignTransitionDeps;
use crate::kernel::jobs::submit::SubmitTransitionDeps;
use crate::kernel::{
    AccumulatorTip, CancelPolicy, ChainIdentity, ChainReadinessFlags, ChainView, Job, JobEvent,
    JobEventHub, JobRequest, KernelError, KernelErrorCode, KernelInfo, KernelNetwork, KernelResult,
    KernelStream, NullifierPath, NullifierPathRequest, SignTransition, TransitionCommand,
};
use crate::v1::{EngineAdapter, PendingSignMap};

/// Optional live chain handle for the four Block-6 read procedures.
///
/// Absent only in unit tests that exercise pure job procedures. Production
/// always installs the v1.1 engine + identity when the exclusive stack is
/// claimed.
#[derive(Clone, Default)]
pub(crate) struct ChainHandle {
    pub engine: Option<Arc<EngineAdapter>>,
    pub identity: Option<ChainIdentity>,
    pub readiness: ChainReadinessFlags,
    /// Engine network pin, when the exclusive stack is installed.
    /// Checked against [`ChainIdentity::network`] on `GetInfo` so a
    /// mismatched boot object cannot silently answer under the wrong tag.
    pub network: Option<KernelNetwork>,
}

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
    /// Live NfLog / tip / identity for read-only chain procedures.
    chain: ChainHandle,
}

impl KernelService {
    pub(crate) fn new(
        job_store: Arc<JobStore>,
        job_events: JobEventHub,
        pending_sign_map: PendingSignMap,
        notify_map: JobNotifyMap,
        challenges: Arc<ChallengeStore>,
        chain: ChainHandle,
    ) -> Self {
        Self {
            job_store,
            job_events,
            pending_sign_map,
            notify_map,
            challenges,
            chain,
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
            ChainHandle::default(),
        )
    }

    /// Production / gRPC boot: store + shared notify map + pending-sign map
    /// + shared challenge store (same instance as HTTP `AppState`).
    ///
    /// Chain procedures need [`Self::with_chain`] (or the longer
    /// [`Self::from_parts_with_chain`]) — job-only boots keep an empty
    /// [`ChainHandle`] so missing-engine reads fail closed.
    pub(crate) fn from_parts(
        job_store: Arc<JobStore>,
        notify_map: JobNotifyMap,
        pending_sign_map: PendingSignMap,
        challenges: Arc<ChallengeStore>,
    ) -> Self {
        Self::from_parts_with_chain(
            job_store,
            notify_map,
            pending_sign_map,
            challenges,
            ChainHandle::default(),
        )
    }

    /// Production boot with a live chain view (engine + identity + readiness).
    pub(crate) fn from_parts_with_chain(
        job_store: Arc<JobStore>,
        notify_map: JobNotifyMap,
        pending_sign_map: PendingSignMap,
        challenges: Arc<ChallengeStore>,
        chain: ChainHandle,
    ) -> Self {
        Self::new(
            job_store,
            JobEventHub::new(Arc::clone(&notify_map)),
            pending_sign_map,
            notify_map,
            challenges,
            chain,
        )
    }

    /// Attach / replace the chain handle (tests and late wiring).
    pub(crate) fn with_chain(mut self, chain: ChainHandle) -> Self {
        self.chain = chain;
        self
    }

    fn require_chain_view(&self) -> KernelResult<ChainView> {
        let engine = self.chain.engine.as_ref().ok_or_else(|| {
            KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Chain view unavailable",
                "KernelService has no EngineAdapter — exclusive v1.1 stack not installed",
            )
        })?;
        ChainView::from_engine(engine.as_ref())
    }

    fn require_identity(&self) -> KernelResult<&ChainIdentity> {
        self.chain.identity.as_ref().ok_or_else(|| {
            KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Chain identity unavailable",
                "KernelService has no ChainIdentity — boot pins not installed on the façade",
            )
        })
    }

    /// `GetInfo` — network pins, bounds, readiness, tip, NAV root.
    pub(crate) fn get_info(&self) -> KernelResult<KernelInfo> {
        let identity = self.require_identity()?;
        if let Some(engine_network) = self.chain.network {
            if engine_network != identity.network {
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Chain identity disagrees with engine network pin",
                    format!(
                        "identity.network={} engine.network={}",
                        identity.network.as_str(),
                        engine_network.as_str()
                    ),
                ));
            }
        }
        let view = self.require_chain_view()?;
        let readiness = self.chain.readiness.evaluate();
        // scanner_lag: when not caught up we report lag as 1 (boolean
        // readiness today has no height delta). Zero when ready on the
        // scan axis. Not invented from tip height — only from the flag.
        let scanner_lag = match &self.chain.readiness.scan_caught_up {
            Some(flag) if !flag.load(std::sync::atomic::Ordering::SeqCst) => 1,
            _ => 0,
        };
        Ok(chain::get_info(identity, &view, readiness, scanner_lag))
    }

    /// `GetAccumulator` — `(size, nav_root)` plus Bitcoin tip.
    pub(crate) fn get_accumulator(&self) -> KernelResult<AccumulatorTip> {
        let view = self.require_chain_view()?;
        Ok(chain::get_accumulator(&view))
    }

    /// `GetNullifierPath` — Path-B present/absent against the live index.
    pub(crate) fn get_nullifier_path(
        &self,
        request: NullifierPathRequest,
    ) -> KernelResult<NullifierPath> {
        let view = self.require_chain_view()?;
        chain::get_nullifier_path(&view, request)
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
