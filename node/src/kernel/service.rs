//! Kernel service façade.
//!
//! Block 1–4: `get_job`, `stream_job`, `cancel_job`, `sign_transition`,
//! `submit_transition`. Block 5: `attest_balance`, `issue_view_grant`,
//! and the shared challenge-store issue helpers. Block 6: read-only chain
//! (`get_info`, `get_accumulator`, `get_nullifier_path`).
//! Block 7: `open_pull_challenge`, `pull`, `get_record`, `get_coin_proof`,
//! `get_account_state`. Block 8: `publish`, `entrust_operational_bundle`,
//! `revoke_operational_bundle`. `SubscribeReceipts` is not a façade method:
//! there is no production credit writer after durable persist (§4.8 / §4.9),
//! so gRPC answers `Unimplemented` (see `access::receipts` writer contract)
//! rather than accepting a silent empty stream. `ListInscriptions` waits
//! on a scanner-written inscription catalog (reveal txid + §3.5 format are
//! not on the NfLog).

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::job_dispatcher::{JobEnvelope, JobNotifyMap};
use crate::job_store::JobStore;
use crate::kernel::access::{
    self, AccountStateView, GetCoinProofCommand, GetRecordCommand, InMemoryPrivateIndex,
    PrivateIndex, PullCommand, PullResult, RecordBlob, SessionBoundRequest, SessionStore,
};
use crate::kernel::attestation::{self, AttestBalanceCommand, AttestBalanceDeps};
use crate::kernel::bootstrap::{
    self as bootstrap, BundleProcedureDeps, BundleStore, ChallengeAction, ChallengeStore,
    EntrustCommand, EntrustResult, IssuedChallenge, RevokeCommand, RevokeResult,
};
use crate::kernel::chain;
use crate::kernel::grants::{
    self, GrantScope, IssueViewGrantCommand, IssueViewGrantDeps, ViewGrantIssued,
};
use crate::kernel::jobs;
use crate::kernel::jobs::sign::SignTransitionDeps;
use crate::kernel::jobs::submit::SubmitTransitionDeps;
use crate::kernel::publish::{self, PublishCommand, PublishConfig, PublishOutcome, PublishPolicy};
use crate::kernel::types::SubjectAddress;
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

/// Construction inputs for [`KernelService::new`].
///
/// Bundled (and destructured at the call site) so a new field is a compile
/// error at every construction site — same discipline as
/// [`crate::runtime::RestNodeConfig`].
pub(crate) struct KernelServiceConfig {
    /// Durable job store for GetJob / StreamJob / admit paths.
    pub job_store: Arc<JobStore>,
    /// Phase-event fan-out shared with the dispatcher (`StreamJob` live path).
    pub job_events: JobEventHub,
    /// Parked wallet-sign waiters keyed by job id.
    pub pending_sign_map: PendingSignMap,
    /// Shared with the dispatcher / SSE path. Sign looks up a parked
    /// notifier without creating one; StreamJob may create on subscribe.
    pub notify_map: JobNotifyMap,
    /// Shared action-bound challenge store (Pull / AttestBalance / IssueViewGrant /
    /// Entrust / Revoke).
    pub challenges: Arc<ChallengeStore>,
    /// Process-local operational-bundle store (Block 8; no durable table yet).
    pub bundles: Arc<BundleStore>,
    /// Pull sessions (process-local; no durable table yet).
    pub sessions: Arc<SessionStore>,
    /// Private-record + account-state index (empty in-memory until catalog).
    pub private_index: Arc<InMemoryPrivateIndex>,
    /// Live NfLog / tip / identity for read-only chain procedures.
    pub chain: ChainHandle,
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
    /// Shared action-bound challenge store (Pull / AttestBalance / IssueViewGrant /
    /// Entrust / Revoke).
    challenges: Arc<ChallengeStore>,
    /// Process-local operational-bundle store (Block 8).
    bundles: Arc<BundleStore>,
    /// Pull sessions (process-local; no durable table yet).
    sessions: Arc<SessionStore>,
    /// Private-record + account-state index (empty in-memory until catalog).
    private_index: Arc<InMemoryPrivateIndex>,
    /// Live NfLog / tip / identity for read-only chain procedures.
    chain: ChainHandle,
}

impl KernelService {
    pub(crate) fn new(
        KernelServiceConfig {
            job_store,
            job_events,
            pending_sign_map,
            notify_map,
            challenges,
            bundles,
            sessions,
            private_index,
            chain,
        }: KernelServiceConfig,
    ) -> Self {
        Self {
            job_store,
            job_events,
            pending_sign_map,
            notify_map,
            challenges,
            bundles,
            sessions,
            private_index,
            chain,
        }
    }

    /// Convenience when only store-backed read/cancel procedures are needed
    /// and the caller has no sign/stream maps (or empty ones for pure load).
    pub(crate) fn from_store(job_store: Arc<JobStore>) -> Self {
        let notify_map: JobNotifyMap = Arc::new(dashmap::DashMap::new());
        Self::new(KernelServiceConfig {
            job_store,
            job_events: JobEventHub::new(Arc::clone(&notify_map)),
            pending_sign_map: Arc::new(dashmap::DashMap::new()),
            notify_map,
            challenges: ChallengeStore::shared(),
            bundles: BundleStore::shared(),
            sessions: SessionStore::shared(),
            private_index: InMemoryPrivateIndex::shared(),
            chain: ChainHandle::default(),
        })
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
        Self::new(KernelServiceConfig {
            job_store,
            job_events: JobEventHub::new(Arc::clone(&notify_map)),
            pending_sign_map,
            notify_map,
            challenges,
            bundles: BundleStore::shared(),
            sessions: SessionStore::shared(),
            private_index: InMemoryPrivateIndex::shared(),
            chain,
        })
    }

    /// Attach / replace the chain handle (tests and late wiring).
    pub(crate) fn with_chain(mut self, chain: ChainHandle) -> Self {
        self.chain = chain;
        self
    }

    /// Private-record index handle for the production decrypt-index writer
    /// (when wired). Empty until a catalog exists; still reachable so the
    /// Arc field is not library-dead.
    pub(crate) fn private_record_index(&self) -> &Arc<InMemoryPrivateIndex> {
        &self.private_index
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
    /// The operational signing key is loaded from the process-local
    /// [`BundleStore`] (set by `EntrustOperationalBundle`). Missing bundle
    /// fails closed inside the domain before challenge consume.
    pub(crate) fn issue_view_grant(
        &self,
        allowed_chan_binds: &[[u8; 32]],
        now: u64,
        command: IssueViewGrantCommand,
    ) -> KernelResult<ViewGrantIssued> {
        let op_owned = self.bundles.op_sk(&command.subject);
        grants::issue_view_grant(
            IssueViewGrantDeps {
                challenges: self.challenges.as_ref(),
                allowed_chan_binds,
                now,
                op_sk: op_owned.as_ref(),
            },
            command,
        )
    }

    fn access_deps<'a>(
        &'a self,
        allowed_chan_binds: &'a [[u8; 32]],
        now: u64,
    ) -> access::AccessDeps<'a> {
        access::AccessDeps {
            challenges: self.challenges.as_ref(),
            sessions: self.sessions.as_ref(),
            index: self.private_index.as_ref() as &dyn PrivateIndex,
            allowed_chan_binds,
            now,
        }
    }

    /// `OpenPullChallenge` — issue a single-use challenge for `action`.
    ///
    /// For [`ChallengeAction::Pull`] the challenge binds `requested_scope`.
    /// Owner-action challenges ignore scope (attest / issue-grant).
    pub(crate) fn open_pull_challenge(
        &self,
        now: u64,
        action: ChallengeAction,
        subject: SubjectAddress,
        requested_scope: GrantScope,
    ) -> IssuedChallenge {
        access::open_pull_challenge(
            self.challenges.as_ref(),
            action,
            subject,
            requested_scope,
            now,
        )
    }

    /// `Pull` — consume pull challenge, list in-scope refs, issue session.
    ///
    /// Caller has already verified OwnershipProof or GrantProof and set
    /// [`PullCommand::authority`] accordingly.
    pub(crate) fn pull(
        &self,
        allowed_chan_binds: &[[u8; 32]],
        now: u64,
        command: PullCommand,
    ) -> KernelResult<PullResult> {
        access::pull(self.access_deps(allowed_chan_binds, now), command)
    }

    /// `GetRecord` — one Private record within a still-valid pull session.
    ///
    /// Session `chan_bind` equality is checked against the session record
    /// (not the node's host set); the host set is only used when redeeming
    /// challenges.
    pub(crate) fn get_record(
        &self,
        now: u64,
        command: GetRecordCommand,
    ) -> KernelResult<RecordBlob> {
        access::get_record(self.access_deps(&[], now), command)
    }

    /// `GetCoinProof` — one CoinProof within a still-valid pull session.
    pub(crate) fn get_coin_proof(
        &self,
        now: u64,
        command: GetCoinProofCommand,
    ) -> KernelResult<Vec<u8>> {
        access::get_coin_proof(self.access_deps(&[], now), command)
    }

    /// `GetAccountState` — ownership pull session only.
    pub(crate) fn get_account_state(
        &self,
        now: u64,
        request: SessionBoundRequest,
    ) -> KernelResult<AccountStateView> {
        access::get_account_state(self.access_deps(&[], now), request)
    }

    /// `Publish` — fee-less publisher hand-off (§7.6 / §7.8).
    ///
    /// Policy/crypto rejections are [`PublishOutcome::Rejected`] (successful
    /// domain result). Fee fields must already have been refused at the
    /// transport edge via [`publish::refuse_v1_fee_fields`].
    ///
    /// `policy` is supplied by the caller (gRPC edge / tests) so a node that
    /// is not acting as a publisher can decline without inventing acceptance.
    pub(crate) fn publish(
        &self,
        policy: PublishPolicy,
        command: PublishCommand,
    ) -> KernelResult<PublishOutcome> {
        let network = match self.chain.network {
            Some(n) => n,
            None => match self.chain.identity.as_ref() {
                Some(id) => id.network,
                None => {
                    return Err(KernelError::with_internal(
                        KernelErrorCode::InternalError,
                        "Publish requires a network pin",
                        "KernelService has no chain.network / identity.network",
                    ));
                }
            },
        };
        let tip_height = match self.require_chain_view() {
            Ok(view) => Some(view.tip_height),
            Err(_) => None,
        };
        publish::publish(
            PublishConfig {
                network,
                tip_height,
                policy,
            },
            command,
        )
    }

    /// `EntrustOperationalBundle` — store the §7.7 bundle after challenge consume.
    pub(crate) fn entrust_operational_bundle(
        &self,
        allowed_chan_binds: &[[u8; 32]],
        now: u64,
        command: EntrustCommand,
    ) -> KernelResult<EntrustResult> {
        bootstrap::entrust_operational_bundle(
            BundleProcedureDeps {
                challenges: self.challenges.as_ref(),
                bundles: self.bundles.as_ref(),
                allowed_chan_binds,
                now,
            },
            command,
        )
    }

    /// `RevokeOperationalBundle` — irreversible erase + tombstone.
    pub(crate) fn revoke_operational_bundle(
        &self,
        allowed_chan_binds: &[[u8; 32]],
        now: u64,
        command: RevokeCommand,
    ) -> KernelResult<RevokeResult> {
        bootstrap::revoke_operational_bundle(
            BundleProcedureDeps {
                challenges: self.challenges.as_ref(),
                bundles: self.bundles.as_ref(),
                allowed_chan_binds,
                now,
            },
            command,
        )
    }
}
