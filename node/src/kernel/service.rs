//! Kernel service façade.
//!
//! Block 1–4: `get_job`, `stream_job`, `cancel_job`, `sign_transition`,
//! `submit_transition`. Block 5: `attest_balance`, `issue_view_grant`,
//! and the shared challenge-store issue helpers. Block 6: read-only chain
//! (`get_info`, `get_accumulator`, `get_nullifier_path`, `list_inscriptions`).
//! Block 7: `open_pull_challenge`, `pull`, `get_record`, `get_coin_proof`,
//! `get_account_state`, `subscribe_receipts`. Block 8: `publish`,
//! `entrust_operational_bundle`, `revoke_operational_bundle`.
//! `SubscribeReceipts` is the filtered push stream over the receipt hub;
//! the receive path publishes after durable decrypt-index persist (§4.8 /
//! §4.9). `ListInscriptions` reads the scanner-written inscription catalog
//! via [`ChainView`].

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::job_dispatcher::{JobEnvelope, JobNotifyMap};
use crate::job_store::JobStore;
use crate::kernel::access::{
    self, AccountStateView, CreditReceipt, GetCoinProofCommand, GetRecordCommand,
    InMemoryPrivateIndex, PrivateIndex, PullCommand, PullResult, ReceiptHub, RecordBlob,
    SessionBoundRequest, SessionStore,
};
use crate::kernel::attestation::{self, AttestBalanceCommand, AttestBalanceDeps};
use crate::kernel::bootstrap::{
    self as bootstrap, BundleProcedureDeps, BundleStore, ChallengeAction, ChallengeStore,
    EntrustCommand, EntrustResult, IssuedChallenge, ManifestStore, RevokeCommand, RevokeResult,
};
use crate::kernel::chain;
use crate::kernel::chain::KernelPart;
use crate::kernel::grants::{
    self, GrantScope, IssueViewGrantCommand, IssueViewGrantDeps, ViewGrantIssued,
};
use crate::kernel::jobs;
use crate::kernel::jobs::sign::SignTransitionDeps;
use crate::kernel::jobs::submit::SubmitTransitionDeps;
use crate::kernel::publish::{
    accept_hand_off, drain_and_inscribe, policy_from_kernel_parts, seed_queue_from_pending_status,
    HandOffMember, HandOffQueue, InMemoryHandOffQueue, PublishBlockAnchor, PublishCommand,
    PublishConfig, PublishOutcome, PublishPolicy,
};
use crate::kernel::types::SubjectAddress;
use crate::kernel::{
    AccumulatorTip, CancelPolicy, ChainIdentity, ChainReadinessFlags, ChainView, Job, JobEvent,
    JobEventHub, JobRequest, KernelError, KernelErrorCode, KernelInfo, KernelNetwork, KernelResult,
    KernelStream, ListInscriptions, ListInscriptionsPage, NullifierPath, NullifierPathRequest,
    SignTransition, TransitionCommand,
};
use crate::v1::{EngineAdapter, PendingSignMap};
use shared::spec_v1::Address;

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
    /// Optional verified §4.3 bootstrap manifest (BMF1 loader at boot).
    pub manifests: Arc<ManifestStore>,
    /// Pull sessions (process-local; no durable table yet).
    pub sessions: Arc<SessionStore>,
    /// Private-record + account-state index (process mirror of
    /// `v1_decrypt_index`; filled by the §4.4 receive path after durable write).
    pub private_index: Arc<InMemoryPrivateIndex>,
    /// Credit-receipt fan-out: receive path publishes after dual persist;
    /// `SubscribeReceipts` filters by server-side session subject + scope.
    pub receipt_hub: Arc<ReceiptHub>,
    /// Live NfLog / tip / identity for read-only chain procedures.
    pub chain: ChainHandle,
    /// Operator-configured seconds until the next expected inscription batch.
    ///
    /// Required when `kernel_parts` includes `publisher`. Never invent a
    /// default (the former hard-coded 60 s at the gRPC edge is gone).
    pub publish_batch_eta_secs: Option<u64>,
    /// Durable §7.6 hand-off queue. Defaults to an in-memory store for pure
    /// domain tests; production additionally mirrors accepted members into
    /// `v1_pending_publishes` when the exclusive V1 engine is installed.
    pub handoff_queue: Arc<InMemoryHandOffQueue>,
    /// Verified delivery targets filled by `SubmitTransition` credential checks.
    pub delivery_targets: Arc<crate::v1::DeliveryTargetStore>,
    /// Relay-relative kind-0 high-water for profile delivery freshness.
    pub profile_high_water: Arc<crate::kernel::jobs::ProfileHighWaterStore>,
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
    /// Optional verified §4.3 bootstrap manifest (BMF1).
    manifests: Arc<ManifestStore>,
    /// Pull sessions (process-local; no durable table yet).
    sessions: Arc<SessionStore>,
    /// Private-record + account-state index (process mirror of durable decrypt index).
    private_index: Arc<InMemoryPrivateIndex>,
    /// Credit-receipt fan-out shared with the §4.4 receive scanner.
    receipt_hub: Arc<ReceiptHub>,
    /// Live NfLog / tip / identity for read-only chain procedures.
    chain: ChainHandle,
    /// Operator-configured batch interval for fee-less AcceptFeeLess.
    publish_batch_eta_secs: Option<u64>,
    /// Durable §7.6 hand-off queue (see [`KernelServiceConfig::handoff_queue`]).
    handoff_queue: Arc<InMemoryHandOffQueue>,
    /// Verified delivery targets (see [`KernelServiceConfig::delivery_targets`]).
    delivery_targets: Arc<crate::v1::DeliveryTargetStore>,
    /// Profile high-water (see [`KernelServiceConfig::profile_high_water`]).
    profile_high_water: Arc<crate::kernel::jobs::ProfileHighWaterStore>,
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
            manifests,
            sessions,
            private_index,
            receipt_hub,
            chain,
            publish_batch_eta_secs,
            handoff_queue,
            delivery_targets,
            profile_high_water,
        }: KernelServiceConfig,
    ) -> Self {
        Self {
            job_store,
            job_events,
            pending_sign_map,
            notify_map,
            challenges,
            bundles,
            manifests,
            sessions,
            private_index,
            receipt_hub,
            chain,
            publish_batch_eta_secs,
            handoff_queue,
            delivery_targets,
            profile_high_water,
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
            manifests: ManifestStore::shared(),
            sessions: SessionStore::shared(),
            private_index: InMemoryPrivateIndex::shared(),
            receipt_hub: ReceiptHub::shared(),
            chain: ChainHandle::default(),
            publish_batch_eta_secs: None,
            handoff_queue: Arc::new(InMemoryHandOffQueue::new()),
            delivery_targets: crate::v1::DeliveryTargetStore::shared(),
            profile_high_water: crate::kernel::jobs::ProfileHighWaterStore::shared(),
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
            manifests: ManifestStore::shared(),
            sessions: SessionStore::shared(),
            private_index: InMemoryPrivateIndex::shared(),
            receipt_hub: ReceiptHub::shared(),
            chain,
            publish_batch_eta_secs: None,
            handoff_queue: Arc::new(InMemoryHandOffQueue::new()),
            delivery_targets: crate::v1::DeliveryTargetStore::shared(),
            profile_high_water: crate::kernel::jobs::ProfileHighWaterStore::shared(),
        })
    }

    /// Install the operator-configured publish batch interval (seconds).
    ///
    /// Required for `AcceptFeeLess` when the process advertises the
    /// `publisher` kernel part. Missing eta with publisher enabled fails
    /// closed at publish time (no invented default).
    pub(crate) fn with_publish_batch_eta_secs(mut self, secs: Option<u64>) -> Self {
        self.publish_batch_eta_secs = secs;
        self
    }

    /// Shared hand-off queue handle (drain / resume / tests).
    pub(crate) fn handoff_queue(&self) -> &Arc<InMemoryHandOffQueue> {
        &self.handoff_queue
    }

    /// Network pin used by the publish drain loop (`None` until chain identity
    /// / engine is installed).
    pub(crate) fn publish_network(&self) -> Option<KernelNetwork> {
        self.chain
            .network
            .or_else(|| self.chain.identity.as_ref().map(|id| id.network))
    }

    /// Optional exclusive V1 engine (PG dual-write / boot hydrate).
    pub(crate) fn chain_engine(&self) -> Option<&Arc<EngineAdapter>> {
        self.chain.engine.as_ref()
    }

    /// Attach / replace the chain handle (tests and late wiring).
    pub(crate) fn with_chain(mut self, chain: ChainHandle) -> Self {
        self.chain = chain;
        self
    }

    /// Install the process-local operational-bundle store shared with the
    /// post-persist delivery path (same entrust/revoke map the mesh uses).
    pub(crate) fn with_bundle_store(mut self, bundles: Arc<BundleStore>) -> Self {
        self.bundles = bundles;
        self
    }

    /// Install the shared delivery-target store used by mesh send and by
    /// `SubmitTransition` credential verification.
    pub(crate) fn with_delivery_targets(
        mut self,
        targets: Arc<crate::v1::DeliveryTargetStore>,
    ) -> Self {
        self.delivery_targets = targets;
        self
    }

    /// Shared delivery-target store handle (tests / mesh wiring).
    pub(crate) fn delivery_targets(&self) -> &Arc<crate::v1::DeliveryTargetStore> {
        &self.delivery_targets
    }

    /// Install the boot-time verified bootstrap-manifest store (or empty).
    ///
    /// Called from the REST/gRPC boot edge after the optional BMF1 load.
    /// GetInfo mirroring of the manifest is **not** wired here — callers
    /// use [`Self::manifest_store`] when they assemble `ChainIdentity`.
    pub(crate) fn with_manifest_store(mut self, manifests: Arc<ManifestStore>) -> Self {
        self.manifests = manifests;
        self
    }

    /// Private-record index handle for the production decrypt-index writer
    /// (§4.4 scanner → durable `v1_decrypt_index` → this process mirror).
    pub(crate) fn private_record_index(&self) -> &Arc<InMemoryPrivateIndex> {
        &self.private_index
    }

    /// Install a shared private-record index (same Arc the receive scanner writes).
    pub(crate) fn with_private_index(mut self, index: Arc<InMemoryPrivateIndex>) -> Self {
        self.private_index = index;
        self
    }

    /// Credit-receipt hub shared with the §4.4 receive path (emit after persist).
    pub(crate) fn receipt_hub(&self) -> &Arc<ReceiptHub> {
        &self.receipt_hub
    }

    /// Install the shared receipt hub (same Arc the receive scanner publishes on).
    pub(crate) fn with_receipt_hub(mut self, hub: Arc<ReceiptHub>) -> Self {
        self.receipt_hub = hub;
        self
    }

    /// Verified bootstrap-manifest store used at boot to assemble
    /// `ChainIdentity` for GetInfo.
    ///
    /// Production with the exclusive v1 engine refuses to start when this
    /// store is empty (`ZKCOINS_V1_BOOTSTRAP_MANIFEST_PATH` unset / unloadable).
    pub(crate) fn manifest_store(&self) -> &Arc<ManifestStore> {
        &self.manifests
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

    /// `ListInscriptions` — catalog page; requires engine (catalog lives there).
    pub(crate) fn list_inscriptions(
        &self,
        request: ListInscriptions,
    ) -> KernelResult<ListInscriptionsPage> {
        let view = self.require_chain_view()?;
        Ok(chain::list_inscriptions(&view, request))
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

    /// `SubmitTransition` — presence/bounds validate, delivery credential
    /// checklists + store fill, admit, dispatcher handoff.
    ///
    /// `job_tx` is the same admit queue the legacy mint/send routes use.
    /// Kept as a method argument (not stored on the service) so read-only
    /// `from_store` constructions stay free of a channel.
    pub(crate) async fn submit_transition(
        &self,
        job_tx: &mpsc::Sender<JobEnvelope>,
        request: TransitionCommand,
    ) -> KernelResult<Job> {
        let subject = request.common().subject;
        let subject_owner = self.lookup_account_owner(&subject);
        // Network pin is required for any profile credential (zkcoins.network
        // check). Invoice-only paths still need a closed label for the deps
        // struct — fail loud when a profile is present and no pin exists.
        let needs_network = match &request {
            TransitionCommand::Mint {
                output_templates, ..
            }
            | TransitionCommand::Send {
                output_templates, ..
            } => output_templates.iter().any(|t| {
                matches!(
                    t.delivery,
                    Some(crate::kernel::types::DeliveryCredential::Profile(_))
                )
            }),
            TransitionCommand::Receive { .. } => false,
        };
        let network = match self.publish_network() {
            Some(n) => n,
            None if needs_network => {
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Network pin required for profile delivery credentials",
                    "KernelService has no chain.network / identity.network for \
                     profile zkcoins.network check",
                ));
            }
            // Invoice-only / receive / self-output: network is unused by the
            // checklist. Regtest is a closed label placeholder only — never
            // a silent default for a profile path (guarded above).
            None => crate::kernel::chain::KernelNetwork::Regtest,
        };
        // Wall clock → ManifestClock at the service edge (same pattern as
        // bootstrap-manifest load). The credential check is fail-closed on
        // Unavailable; we do not skip the profile age window.
        let clock = match std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH) {
            Ok(d) => shared::spec_v1::ManifestClock::UnixSeconds(d.as_secs()),
            Err(_) => shared::spec_v1::ManifestClock::Unavailable,
        };
        jobs::submit_transition(
            SubmitTransitionDeps {
                store: self.job_store.as_ref(),
                job_tx,
                bundles: self.bundles.as_ref(),
                // Same process-local store the finalise/mesh path reads via
                // [`Self::delivery_targets`] (runtime installs one Arc on both).
                delivery_targets: self.delivery_targets().as_ref(),
                profile_high_water: self.profile_high_water.as_ref(),
                subject_owner,
                network,
                clock,
            },
            request,
        )
        .await
    }

    /// Persisted `AccountState.owner` for `subject`, when the private index
    /// holds a canonical serialisation. Absence means the self-output owner
    /// leg cannot hold (fail-closed: not self without a known owner).
    fn lookup_account_owner(
        &self,
        subject: &crate::kernel::types::SubjectAddress,
    ) -> Option<[u8; 32]> {
        use crate::kernel::access::PrivateIndex;
        let view = self.private_index.get_account_state(subject).ok()?;
        // Canonical §1.7.4 layout: owner is the first 32 bytes; min length 140.
        if view.account_state.len() < 140 {
            return None;
        }
        let mut owner = [0u8; 32];
        owner.copy_from_slice(&view.account_state[0..32]);
        Some(owner)
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

    /// `SubscribeReceipts` — server-stream of verified credits for the
    /// pull session's stored subject + resolved scope (ownership **or** grant).
    ///
    /// Subject/scope come only from the server-side session. Emission is the
    /// receive path after durable dual-persist via
    /// [`access::publish_credit_if_inserted`].
    pub(crate) fn subscribe_receipts(
        &self,
        now: u64,
        request: SessionBoundRequest,
    ) -> KernelResult<KernelStream<CreditReceipt>> {
        access::subscribe_receipts(
            self.sessions.as_ref(),
            self.receipt_hub.as_ref(),
            request,
            now,
        )
    }

    /// Resolve the fee-less publish policy from this process's kernel parts
    /// and the operator-configured batch interval — never a hard-coded
    /// `AcceptFeeLess { 60 }` at the transport edge.
    pub(crate) fn resolve_publish_policy(&self) -> KernelResult<PublishPolicy> {
        let parts: &[KernelPart] = match self.chain.identity.as_ref() {
            Some(id) => id.kernel_parts.as_slice(),
            // No identity yet: not a publisher surface — decline rather than
            // invent AcceptFeeLess. Callers that need accept in unit tests
            // install an identity with the publisher part + batch eta.
            None => &[],
        };
        policy_from_kernel_parts(parts, self.publish_batch_eta_secs)
    }

    /// `Publish` — fee-less publisher hand-off (§7.6 / §7.8).
    ///
    /// Policy is derived from kernel_parts + configured batch eta (see
    /// [`Self::resolve_publish_policy`]). Crypto / policy rejections are
    /// [`PublishOutcome::Rejected`] (successful domain result). Acceptance
    /// is returned **only** after durable enqueue via [`accept_hand_off`]
    /// (and, when the V1 engine is installed, a mirror into
    /// `v1_pending_publishes`). Never a free `accepted` without a queue write.
    ///
    /// Fee fields must already have been refused at the transport edge via
    /// [`crate::kernel::publish::refuse_v1_fee_fields`].
    pub(crate) async fn publish(&self, command: PublishCommand) -> KernelResult<PublishOutcome> {
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
        let policy = self.resolve_publish_policy()?;
        let config = PublishConfig {
            network,
            tip_height,
            policy,
        };

        // Domain accept: evaluate + durable process-queue enqueue. Rejections
        // never touch the queue; enqueue failure is internal_error (never a
        // free accepted claim).
        let outcome = accept_hand_off(self.handoff_queue.as_ref(), config, command)?;
        let PublishOutcome::Accepted { batch_eta } = outcome else {
            return Ok(outcome);
        };

        // Mirror into v1_pending_publishes when the exclusive V1 engine is
        // installed so a real process restart can re-seed the drain queue
        // (and the existing resume path can finish mid-flight rows).
        if let Some(engine) = self.chain.engine.as_ref() {
            let member = HandOffMember::from_command(command);
            // External §7.6 hand-offs do not know the account owner; the
            // recovery table requires a 32-byte owner column — store the
            // nullifier pk as a non-account sentinel so the row stays
            // addressable by pk alone.
            let owner = Address(member.public_key.0);
            if let Err(e) = crate::v1::db_v1::insert_pending_publish_members_ready(
                engine.pool(),
                owner,
                member.public_key.0,
                member.r.0,
                member.s.0,
                member.r_prime.0,
                member.block_anchor.height,
                member.block_anchor.block_hash.0,
            )
            .await
            {
                // Process queue already holds the accept — mark it failed so
                // the drain cannot inscribe a member PG never recorded, and
                // never project Accepted to the caller.
                let reason = format!("pg durable mirror failed: {e:#}");
                self.handoff_queue
                    .mark_failed(&member.public_key, &reason)
                    .map_err(|detail| {
                        KernelError::with_internal(
                            KernelErrorCode::InternalError,
                            "Failed to mark hand-off failed after PG mirror error",
                            detail,
                        )
                    })?;
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Failed to durable-queue publish hand-off into v1_pending_publishes",
                    format!("{e:#}"),
                ));
            }
        }

        Ok(PublishOutcome::Accepted { batch_eta })
    }

    /// One drain cycle for the process hand-off queue: half-aggregate +
    /// inscribe via the installed batch publisher.
    ///
    /// `publisher == None` is a **named terminal** failure for every
    /// resumable member (`InscriptionTerminal::PublisherUnavailable`) —
    /// never a silent skip and never re-projected as `accepted`. Callers
    /// that only have a transient bitcoind outage must **not** pass `None`;
    /// they should skip the cycle and retry (see the runtime drain loop).
    pub(crate) fn drain_handoff_queue<P>(
        &self,
        publisher: Option<&P>,
        batch_anchor: Option<PublishBlockAnchor>,
    ) -> Result<
        Option<zkcoins_prover::publisher::PublishedBatch>,
        crate::kernel::publish::InscriptionTerminal,
    >
    where
        P: crate::v1::receive::NullifierBatchPublisher + ?Sized,
    {
        let network = self.publish_network().ok_or_else(|| {
            crate::kernel::publish::InscriptionTerminal::PublisherUnavailable {
                detail: "drain_handoff_queue: no network pin on KernelService — \
                         cannot half-aggregate under an unknown m_state"
                    .into(),
            }
        })?;
        drain_and_inscribe(
            self.handoff_queue.as_ref(),
            publisher,
            network,
            batch_anchor,
        )
    }

    /// Hydrate the process hand-off queue from durable pending rows
    /// (`list_resumable` / `v1_pending_publishes`) after restart.
    ///
    /// Uses [`seed_queue_from_pending_status`] so status labels
    /// (`members_ready`, `constructed`, …) are preserved via
    /// [`crate::kernel::publish::HandOffQueueStatus::from_pending_status`].
    pub(crate) fn seed_handoff_queue_from_pending_rows(
        &self,
        rows: &[(HandOffMember, &str)],
    ) -> Result<usize, String> {
        seed_queue_from_pending_status(self.handoff_queue.as_ref(), rows)
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
