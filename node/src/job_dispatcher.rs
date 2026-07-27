//! Background dispatcher that drives queued jobs through the
//! mint/send/commit state machine.
//!
//! ## Architecture
//!
//! The dispatcher is a long-lived tokio task spawned by
//! [`spawn`]. It owns a single mpsc receiver of [`JobEnvelope`]s
//! produced by the admit-side routes in `router.rs`
//! (`POST /api/jobs/mint`, `POST /api/jobs/send`). On each envelope
//! it loads the matching `Job` row, walks the state machine one
//! step forward via the `flow::*` helpers, and persists the
//! transition into Postgres via the [`JobStore`].
//!
//! ## Single worker
//!
//! Mint and send proofs run in Plonky2's Rayon worker pool; that
//! pool already saturates every available CPU core during a prove.
//! Running two proves in parallel would only thrash the cache —
//! each individual prove would slow down proportionally and the
//! wallclock throughput would not improve. We therefore drive the
//! state machine on a *single* worker. The mpsc channel becomes
//! the queue; the natural happens-before of channel ordering
//! becomes the schedule. The implication for the operator: queue
//! depth equals user-observable latency, and the resumer's
//! "queue=N waiting" metric is the right thing to monitor.
//!
//! ## Awaiting signature
//!
//! A `send` job, after the prove leg, transitions to
//! `awaiting_signature` and the dispatcher *parks* on a per-job
//! `tokio::sync::Notify` channel registered in the shared
//! [`notify_map`]. The wallet's `POST /api/jobs/:id/commit` handler
//! looks up the same `Notify` entry and calls `notify_one()` after
//! persisting the signature payload — that is the wake edge the
//! dispatcher uses to resume the broadcast leg.
//!
//! The wait is bounded by `awaiting_signature_timeout` (default 10
//! minutes — long enough for a hardware-wallet sign-then-confirm
//! UX with retries, short enough that an abandoned proof file
//! doesn't pin the dispatcher forever). Timing out moves the job
//! to `failed` with `"awaiting_signature timeout"` so the wallet's
//! next poll observes the terminal status.
//!
//! ## Coverage scope
//!
//! Excluded from the 100% line / function gate (alongside
//! `runtime.rs`) via the CI `--ignore-filename-regex` flag. The
//! dispatcher is the integration glue between the (already-covered)
//! `JobStore`, the (already-covered) `flow::*` helpers, and the
//! tokio runtime; its critical paths surface as end-to-end behaviour
//! that the `/api/jobs/*` integration tests in `router_tests.rs`
//! verify against a real testcontainer Postgres.

use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use tokio::sync::{broadcast, mpsc, Notify};
use uuid::Uuid;

use crate::flow::{commit_flow, mint_commit_flow, mint_flow, send_flow, FlowError};
use crate::job_store::{Job, JobKind, JobStatus, JobStore};
use crate::router::{AppState, CommitRequest, MintRequest, SendCoinRequest};

// `DashMap` and `Notify` are used inside the public types
// (`JobNotifyMap`, `JobNotifier::commit_wake`) defined below — the
// re-exports stay even though the dispatcher's per-task code paths no
// longer reference the bare types directly.

/// Per-job fan-out broadcast capacity. Phase events are sparse (a job
/// transits at most through `proving → awaiting_signature →
/// broadcasting → completed|failed|cancelled` — five events worst
/// case), so 32 is comfortably above any realistic burst even if a
/// boot-time resumer + the dispatcher both fire near the same instant.
/// Sized to match the `tokio::sync::mpsc::channel(32)` already used by
/// the admit-side queue (`runtime::start_rest_node`).
pub(crate) const PHASE_CHANNEL_CAPACITY: usize = 32;

/// Per-job fan-out subscription used by the SSE stream handler in
/// `router::stream_job_handler`.
///
/// Combines the two coordination primitives the dispatcher needs to
/// coexist on the same map entry:
///
/// * `commit_wake` — the single `Notify` the `send`-flow dispatcher
///   parks on between `awaiting_signature` and `broadcasting`. The
///   `POST /api/jobs/:id/commit` handler calls `notify_one()` on this
///   to wake the dispatcher. Pre-PR2 this was the only field; the
///   commit-route's wake path is unchanged.
/// * `phase_tx` — a multi-subscriber `broadcast::Sender` used by every
///   SSE listener to receive real-time phase updates as the
///   dispatcher walks the job through its state machine. The
///   dispatcher publishes one event after every status persistence
///   site; subscribers receive each event without blocking the
///   dispatcher (the broadcast channel is bounded but a slow consumer
///   only gets `Lagged` back, the dispatcher's `.send().ok()` ignores
///   that arm).
///
/// Handoff state between `/sign` (or legacy `/commit`) and a parked
/// dispatcher. CAS closes the race where the handler clones a notifier,
/// the dispatcher times out and leaves, and the handler still reports
/// acceptance.
pub const HANDOFF_WAITING: u8 = 0;
pub const HANDOFF_SIGNALED: u8 = 1;
pub const HANDOFF_TIMED_OUT: u8 = 2;

/// Held inside `Arc<JobNotifier>` so cloning the map entry is cheap
/// and the broadcast channel survives until every receiver drops.
#[derive(Debug)]
pub struct JobNotifier {
    /// Single-shot wake channel for the dispatcher's `wait_for_commit`
    /// task. The `commit` handler calls `notify_one()`; the dispatcher
    /// resumes from `.notified().await`. Identical semantics to the
    /// pre-PR2 `Arc<Notify>` directly held in the notify-map.
    pub commit_wake: Arc<Notify>,
    /// Fan-out channel for SSE subscribers. Capacity
    /// [`PHASE_CHANNEL_CAPACITY`]; phase events are sparse so a lagged
    /// subscriber would only happen under pathological scheduling
    /// pressure — and the SSE stream's initial-state push covers any
    /// event the listener missed before subscribing.
    pub phase_tx: broadcast::Sender<JobPhaseEvent>,
    /// Atomic handoff: only one of route-signal / dispatcher-timeout wins.
    /// Acceptance requires a successful CAS from [`HANDOFF_WAITING`] to
    /// [`HANDOFF_SIGNALED`] at the moment of the wake — not a clone that
    /// was valid a moment earlier.
    pub handoff: AtomicU8,
}

impl JobNotifier {
    /// Build a fresh notifier with an empty `Notify` and a broadcast
    /// channel sized for [`PHASE_CHANNEL_CAPACITY`].
    pub fn new() -> Self {
        let (phase_tx, _rx) = broadcast::channel(PHASE_CHANNEL_CAPACITY);
        Self {
            commit_wake: Arc::new(Notify::new()),
            phase_tx,
            handoff: AtomicU8::new(HANDOFF_WAITING),
        }
    }

    /// Route-side claim: the verified signature (or legacy commit) is
    /// about to wake the dispatcher. Returns `true` only when the
    /// dispatcher is still waiting — a timed-out or already-signaled
    /// handoff refuses so the caller cannot report acceptance for work
    /// that will never run.
    pub fn try_signal_accept(&self) -> bool {
        self.handoff
            .compare_exchange(
                HANDOFF_WAITING,
                HANDOFF_SIGNALED,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }

    /// Dispatcher-side claim: the awaiting-signature wait timed out.
    /// Returns `true` only when no route has already claimed the handoff.
    pub fn try_claim_timeout(&self) -> bool {
        self.handoff
            .compare_exchange(
                HANDOFF_WAITING,
                HANDOFF_TIMED_OUT,
                Ordering::SeqCst,
                Ordering::SeqCst,
            )
            .is_ok()
    }
}

impl Default for JobNotifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Status-transition event published by the dispatcher on every
/// persistence site (`set_status`, `set_awaiting_signature`,
/// `complete`, `fail`). The SSE handler in `router::stream_job_handler`
/// translates these into `event: phase` / `event: complete` frames.
///
/// `Clone` is required by `tokio::sync::broadcast::Sender` (fan-out
/// hands each subscriber its own copy). The payload is small —
/// `(JobStatus, String, Option<i64>, Option<Value>, Option<String>)` —
/// so cloning is cheap.
#[derive(Debug, Clone)]
pub struct JobPhaseEvent {
    /// Coarse machine-readable status the wallet UI keys on.
    pub status: JobStatus,
    /// Free-form refinement persisted alongside `status` in the
    /// `jobs.phase` column. Mirrors the GET-handler's `phase` field.
    pub phase: String,
    /// Set only when `status = AwaitingSignature` so the wallet can
    /// download the proof file via `/api/proof/:id` without an extra
    /// poll.
    pub proof_id: Option<i64>,
    /// Cached response body, set on an `awaiting_signature` transition
    /// (the `account_state_hash` / `output_coins_root` hex the wallet
    /// signs) and on a `completed` transition (the terminal body).
    /// Shape matches the `JobStatusResponse` field-for-field so the
    /// SSE consumer's parse path mirrors the existing GET 200 parse
    /// path.
    pub result: Option<serde_json::Value>,
    /// Error string set only on a `failed` transition. Surfaced
    /// verbatim into the SSE complete event so the wallet's
    /// `KNOWN_SERVER_ERRORS` mapping table receives the same input
    /// either way (poll or push).
    pub error: Option<String>,
}

/// Concurrent-map type used to share `JobNotifier` instances across
/// every handler and the dispatcher. Replaces the pre-PR2
/// `DashMap<Uuid, Arc<Notify>>` shape; the SSE stream handler holds a
/// fresh broadcast `Receiver` per open stream, the commit handler
/// holds the `Arc<Notify>` it always held.
pub type JobNotifyMap = Arc<DashMap<Uuid, Arc<JobNotifier>>>;

/// Publish a phase-transition event to every SSE subscriber for
/// `public_id`. No-op when no entry exists in the notify-map (e.g. a
/// completed-from-cache idempotent replay, or a job that had no SSE
/// subscribers). The `.send().ok()` swallow covers the
/// "no active receivers" arm — the broadcast channel returns
/// `Err(SendError)` in that case, which is not a dispatcher failure.
pub(crate) fn publish_phase(notify_map: &JobNotifyMap, public_id: Uuid, event: JobPhaseEvent) {
    if let Some(entry) = notify_map.get(&public_id) {
        // `send` returns Err only when there are no active receivers;
        // that arm is the common case (no SSE client connected) and
        // is not an error.
        let _ = entry.phase_tx.send(event);
    }
}

/// Default time the dispatcher will park on the `awaiting_signature`
/// `Notify` channel before timing out the job. Picked to comfortably
/// span a hardware-wallet sign-then-confirm UX (60-120 s on Ledger /
/// BitBox plus user attention) with a generous retry budget.
pub const DEFAULT_AWAITING_SIGNATURE_TIMEOUT: Duration = Duration::from_secs(600);

/// Envelope handed to the dispatcher on every state-machine wake
/// edge. The dispatcher reads `public_id`, loads the `Job` from
/// Postgres, and consults `status` to decide which `flow::*` helper
/// to invoke.
#[derive(Debug, Clone)]
pub struct JobEnvelope {
    pub public_id: Uuid,
}

/// Spawn the dispatcher as a long-lived background tokio task.
///
/// The caller owns the channel: it pairs an `mpsc::Sender<JobEnvelope>`
/// (handed verbatim to every admit handler through the
/// `AppState.job_tx` field) with the matching `mpsc::Receiver`
/// (consumed by the spawned task). The dispatcher terminates when
/// every sender clone has been dropped (graceful shutdown signal).
///
/// ## Parameters
///
/// - `job_store` — JobStore handle for status persistence + load.
/// - `app_state` — shared application state; passed verbatim into
///   the `flow::*` helpers so the dispatcher does not have to
///   thread every dependency (account_node, publisher_config,
///   pool, proof_store) through its own argument list.
/// - `notify_map` — per-job `Notify` channels; populated by the
///   send-flow dispatcher leg before parking, drained by the
///   `commit_handler`'s notify call.
/// - `awaiting_signature_timeout` — cap on the dispatcher's wait
///   for a `commit` signal before timing the job out.
/// - `job_rx` — receiver half of the mpsc channel paired with the
///   `AppState.job_tx` sender.
pub fn spawn(
    job_store: Arc<JobStore>,
    app_state: AppState,
    notify_map: JobNotifyMap,
    awaiting_signature_timeout: Duration,
    mut rx: mpsc::Receiver<JobEnvelope>,
) {
    tokio::spawn(async move {
        tracing::info!("Job dispatcher started");
        while let Some(env) = rx.recv().await {
            let job_store = job_store.clone();
            let app_state = app_state.clone();
            let notify_map = notify_map.clone();
            let timeout = awaiting_signature_timeout;
            // Process serially: one prove at a time (see module
            // doc-comment for the Rayon-pool rationale). We do NOT
            // `tokio::spawn` here — that would defeat the
            // single-worker invariant.
            if let Err(e) =
                process_envelope(&job_store, &app_state, &notify_map, timeout, env).await
            {
                tracing::error!("Job dispatcher: process_envelope error: {}", e);
            }
        }
        tracing::info!("Job dispatcher channel closed; exiting");
    });
}

/// Drive a single envelope through one state-machine step. The
/// outer loop in [`spawn`] calls this for every received envelope.
///
/// Test-visible so boot-resume / crash-window recovery can be exercised
/// without spinning the full dispatcher channel.
#[cfg(test)]
pub(crate) async fn process_envelope_for_test(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &JobNotifyMap,
    awaiting_signature_timeout: Duration,
    env: JobEnvelope,
) -> anyhow::Result<()> {
    process_envelope(
        job_store,
        app_state,
        notify_map,
        awaiting_signature_timeout,
        env,
    )
    .await
}

async fn process_envelope(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &JobNotifyMap,
    awaiting_signature_timeout: Duration,
    env: JobEnvelope,
) -> anyhow::Result<()> {
    let job = match job_store.load(env.public_id).await? {
        Some(j) => j,
        None => {
            tracing::warn!(
                "Job dispatcher: envelope for unknown public_id {}",
                env.public_id
            );
            return Ok(());
        }
    };

    if job.status.is_terminal() {
        tracing::debug!(
            "Job dispatcher: envelope for terminal job {} ({:?}); skipping",
            env.public_id,
            job.status
        );
        return Ok(());
    }

    match (job.kind, job.status) {
        (JobKind::Mint, JobStatus::Queued) => {
            process_mint(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        (JobKind::Mint, JobStatus::AwaitingSignature) => {
            process_mint_resume(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        (JobKind::Send, JobStatus::Queued) => {
            process_send_initial(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        (JobKind::Send, JobStatus::AwaitingSignature) => {
            process_send_resume(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        // Mid-finalise crash: durable signed capability + broadcasting.
        // Resume finalise without re-parking on /sign.
        (JobKind::Mint | JobKind::Send, JobStatus::Broadcasting)
            if crate::v11::v11_sign_route_active() =>
        {
            drive_v11_finalise(job_store, app_state, notify_map, env.public_id, &job).await
        }
        _ => {
            tracing::debug!(
                "Job dispatcher: envelope for {} in unexpected state {:?}; skipping",
                env.public_id,
                job.status
            );
            Ok(())
        }
    }
}

/// Feed a prove leg's outcome into the runtime prover-health signal.
///
/// `Ok(())` (any successful prove — a completed mint, or a send reaching
/// `awaiting_signature`) clears the consecutive-failure streak. `Err` is
/// only treated as a prove-health failure when the message is the
/// collapsed `"prove failed"` — request-level errors (insufficient
/// funds, unknown account, bad hex, …) have their own messages and must
/// not move the streak, or a burst of bad client requests could falsely
/// arm the self-heal. On the failure that first reaches
/// [`crate::prover_health::PROVE_FAILURE_THRESHOLD`] this clears the
/// persisted circuit digest, which *arms* the boot self-heal: the next
/// restart runs the canary recursion and resets to genesis only if the
/// persisted proofs are genuinely stale (so a transient prover blip that
/// is over by the restart re-baselines with no reset). `/health/ready`
/// reports `prover: failing` for the whole streak.
async fn note_prove_outcome(app_state: &AppState, outcome: Result<(), &str>) {
    match outcome {
        Ok(()) => app_state.prover_health.note_success(),
        Err("prove failed") => {
            if app_state.prover_health.note_failure() {
                if let Err(e) = crate::db::clear_circuit_digest(&app_state.pool).await {
                    tracing::warn!(
                        "prover-health: failed to clear circuit digest to arm boot self-heal: {}",
                        e
                    );
                }
                tracing::warn!(
                    "prover-health: {} consecutive prove failures — /health/ready now reports \
                     the prover failing; armed boot self-heal (cleared persisted circuit digest, \
                     next restart's canary re-checks + resets iff the proofs are stale)",
                    crate::prover_health::PROVE_FAILURE_THRESHOLD
                );
            }
        }
        Err(_) => { /* non-prove flow error: leave the failure streak unchanged */ }
    }
}

/// Drive a mint job from `queued` through the issuer-mint prove leg to
/// `awaiting_signature`, then park on the per-job `Notify` channel
/// until the wallet returns the creator-signed commitment (or the
/// timeout fires). Two-phase, mirroring [`process_send_initial`]: the
/// neutral, permissionless mint is creator-signed, so the wallet — not
/// the node — supplies the commitment.
async fn process_mint(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &JobNotifyMap,
    awaiting_signature_timeout: Duration,
    job: Job,
) -> anyhow::Result<()> {
    let public_id = job.public_id;
    if !job_store
        .set_status(public_id, JobStatus::Proving, "proving")
        .await?
    {
        // Zero rows: generation fence or concurrent terminal — do not prove
        // against wiped / foreign state (no silent fallback).
        tracing::warn!(
            "Job dispatcher: mint job {} set_status(proving) matched 0 rows; aborting",
            public_id
        );
        notify_map.remove(&public_id);
        return Ok(());
    }
    publish_phase(
        notify_map,
        public_id,
        JobPhaseEvent {
            status: JobStatus::Proving,
            phase: "proving".to_string(),
            proof_id: None,
            result: None,
            error: None,
        },
    );

    let request: MintRequest = match serde_json::from_value(job.request_body.clone()) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("invalid mint request body: {}", e);
            if !job_store.fail(public_id, &msg).await? {
                tracing::warn!(
                    "Job dispatcher: fail matched 0 rows; not publishing failed event"
                );
                cleanup_pending_sign(job_store, app_state, public_id).await;
                notify_map.remove(&public_id);
                return Ok(());
            }
            publish_phase(
                notify_map,
                public_id,
                JobPhaseEvent {
                    status: JobStatus::Failed,
                    phase: "failed".to_string(),
                    proof_id: None,
                    result: None,
                    error: Some(msg),
                },
            );
            return Ok(());
        }
    };

    let (proof_id, commit_hashes) = match mint_flow(app_state, request).await {
        Ok(out) => {
            note_prove_outcome(app_state, Ok(())).await;
            out
        }
        Err(FlowError { status, message }) => {
            tracing::warn!(
                "Job dispatcher: mint job {} prove leg failed ({}): {}",
                public_id,
                status.as_u16(),
                message
            );
            note_prove_outcome(app_state, Err(message.as_str())).await;
            // Cancel may have won while proving; do not overwrite cancelled.
            if let Ok(Some(j)) = job_store.load(public_id).await {
                if j.status == JobStatus::Cancelled {
                    cleanup_pending_sign(job_store, app_state, public_id).await;
                    notify_map.remove(&public_id);
                    return Ok(());
                }
            }
            if !job_store.fail(public_id, &message).await? {
                tracing::warn!(
                    "Job dispatcher: fail matched 0 rows; not publishing failed event"
                );
                cleanup_pending_sign(job_store, app_state, public_id).await;
                notify_map.remove(&public_id);
                return Ok(());
            }
            publish_phase(
                notify_map,
                public_id,
                JobPhaseEvent {
                    status: JobStatus::Failed,
                    phase: "failed".to_string(),
                    proof_id: None,
                    result: None,
                    error: Some(message),
                },
            );
            return Ok(());
        }
    };

    // Cancel may have won during the prove leg.
    if let Ok(Some(j)) = job_store.load(public_id).await {
        if j.status == JobStatus::Cancelled {
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
    }

    let notifier = notify_map
        .entry(public_id)
        .or_insert_with(|| Arc::new(JobNotifier::new()))
        .clone();

    // Production staging site: under v1.1 a live PendingTransition must be
    // staged via stage_pending_sign before the job advertises. Source is the
    // post-begin registry (begin_* → register_live_pending_after_begin) or
    // the optional test hook.
    let live_pending = resolve_live_pending_after_prove(app_state, public_id);
    let result = match stage_and_select_awaiting_signature(
        job_store,
        app_state,
        public_id,
        &commit_hashes.account_state_hash,
        &commit_hashes.output_coins_root,
        live_pending,
    )
    .await
    {
        Ok(v) => v,
        Err(msg) => {
            tracing::warn!(
                "Job dispatcher: mint job {} refused awaiting_signature advertisement: {}",
                public_id,
                msg
            );
            let err = fail_error_string(&msg);
            if !job_store.fail(public_id, &err).await? {
                tracing::warn!(
                    "Job dispatcher: fail matched 0 rows; not publishing failed event"
                );
                cleanup_pending_sign(job_store, app_state, public_id).await;
                notify_map.remove(&public_id);
                return Ok(());
            }
            publish_phase(
                notify_map,
                public_id,
                JobPhaseEvent {
                    status: JobStatus::Failed,
                    phase: "failed".to_string(),
                    proof_id: None,
                    result: None,
                    error: Some(err),
                },
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
    };
    match job_store
        .set_awaiting_signature(public_id, proof_id as i64, result.clone())
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            // Zero rows: cancel / generation fence / concurrent advance.
            // Staged map + envelope + notifier must not survive.
            tracing::warn!(
                "Job dispatcher: mint job {} set_awaiting_signature matched 0 rows; cleaning up",
                public_id
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
        Err(e) => {
            // Defect 3: staged map + envelope + notifier must not survive a
            // failed status transition.
            tracing::error!(
                "Job dispatcher: mint job {} set_awaiting_signature failed: {}",
                public_id,
                e
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Err(e.into());
        }
    }
    // Cancel may have won between stage and status write (WHERE filters).
    match job_store.load(public_id).await? {
        Some(j) if j.status == JobStatus::AwaitingSignature => {}
        Some(j) if j.status == JobStatus::Cancelled => {
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
        other => {
            tracing::warn!(
                "Job dispatcher: mint job {} not in awaiting_signature after set ({:?}); cleaning up",
                public_id,
                other.map(|j| j.status)
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
    }
    publish_phase(
        notify_map,
        public_id,
        JobPhaseEvent {
            status: JobStatus::AwaitingSignature,
            phase: "awaiting_signature".to_string(),
            proof_id: Some(proof_id as i64),
            result: Some(result),
            error: None,
        },
    );
    tracing::info!(
        "Job dispatcher: mint job {} reached awaiting_signature (proof_id={})",
        public_id,
        proof_id
    );

    wait_for_commit(
        job_store,
        app_state,
        notify_map,
        awaiting_signature_timeout,
        public_id,
        JobKind::Mint,
        notifier,
    )
    .await
}

/// Resume a mint job that was already `awaiting_signature` when the
/// process restarted. Note: the staged-mint proof lives in process
/// memory ([`crate::router::MintStore`]) and is lost across a restart,
/// so the wallet's commit will fail with "Unknown or expired mint
/// proof_id" and the creator must re-submit — the same boot-resume
/// semantics a send has when its `ProofStore` entry survives but the
/// timestamp window has lapsed.
async fn process_mint_resume(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &JobNotifyMap,
    awaiting_signature_timeout: Duration,
    job: Job,
) -> anyhow::Result<()> {
    let public_id = job.public_id;
    rehydrate_pending_sign_into_map(app_state, public_id, &job);
    let notifier = notify_map
        .entry(public_id)
        .or_insert_with(|| Arc::new(JobNotifier::new()))
        .clone();
    tracing::info!(
        "Job dispatcher: resuming mint job {} in awaiting_signature",
        public_id
    );
    publish_phase(
        notify_map,
        public_id,
        JobPhaseEvent {
            status: JobStatus::AwaitingSignature,
            phase: "awaiting_signature".to_string(),
            proof_id: job.proof_id,
            result: job.response_body.clone(),
            error: None,
        },
    );
    wait_for_commit(
        job_store,
        app_state,
        notify_map,
        awaiting_signature_timeout,
        public_id,
        JobKind::Mint,
        notifier,
    )
    .await
}

/// Merge the durable finalisation capability into `jobs.request_body`.
///
/// Status-qualified: only writes while the job is still `queued` or
/// `proving` (the statuses from which we enter `awaiting_signature`). If
/// cancel won the race, the write fails loud rather than stamping a
/// finalisation envelope onto a terminal row.
async fn persist_pending_sign_on_job(
    job_store: &JobStore,
    public_id: Uuid,
    entry: &crate::v11::PendingSignEntry,
) -> anyhow::Result<()> {
    let job = job_store
        .load(public_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("job {public_id} missing while staging finalisation"))?;
    let mut body = job.request_body;
    let persist = crate::v11::DurableFinalisationPersist::from_entry(entry)
        .map_err(|e| anyhow::anyhow!("encode durable finalisation: {e}"))?;
    let value = serde_json::to_value(persist)?;
    let obj = body
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("jobs.request_body is not an object"))?;
    obj.insert(crate::v11::FINALISATION_BODY_KEY.to_string(), value);
    // Drop legacy split keys if a previous build left them.
    obj.remove(crate::v11::PENDING_SIGN_BODY_KEY);
    obj.remove("sign");
    // Prefer proving; fall back to queued (create leaves queued).
    let applied = if job.status == JobStatus::Proving {
        job_store
            .replace_request_body_if_status(public_id, JobStatus::Proving, &body)
            .await?
    } else if job.status == JobStatus::Queued {
        job_store
            .replace_request_body_if_status(public_id, JobStatus::Queued, &body)
            .await?
    } else {
        false
    };
    if !applied {
        anyhow::bail!(
            "refusing to persist finalisation capability: job {public_id} status \
             moved off {:?} before write (status-qualified update)",
            job.status
        );
    }
    Ok(())
}

/// Resolve a live pending after the prove / begin leg under a v1.1 claim.
///
/// Production path: consume a [`PendingSignEntry`] that `StateEngine::begin_*`
/// registered via [`crate::v11::register_live_pending_after_begin`] into
/// [`crate::router::AppState::v11_live_pending_after_begin`]. The pending is
/// self-contained (witness + ProofData); finalise re-validates live
/// dependencies rather than re-reading a snapshot a concurrent scan can move.
///
/// Under `cfg(test)` an optional fixture hook may also supply an entry.
/// Missing the production registry fails closed at
/// [`stage_and_select_awaiting_signature`] (no silent ash‖ocr).
fn resolve_live_pending_after_prove(
    app_state: &AppState,
    public_id: Uuid,
) -> Option<crate::v11::PendingSignEntry> {
    if !crate::v11::v11_sign_route_active() {
        return None;
    }
    if let Some(entry) = crate::v11::take_live_pending_after_begin(
        &app_state.v11_live_pending_after_begin,
        public_id,
    ) {
        return Some(entry);
    }
    #[cfg(test)]
    {
        if let Some(entry) = app_state
            .v11_pending_after_prove
            .as_ref()
            .and_then(|hook| hook(public_id))
        {
            return Some(entry);
        }
    }
    None
}

/// Test-visible alias of [`resolve_live_pending_after_prove`].
#[cfg(test)]
pub(crate) fn resolve_live_pending_after_prove_for_test(
    app_state: &AppState,
    public_id: Uuid,
) -> Option<crate::v11::PendingSignEntry> {
    resolve_live_pending_after_prove(app_state, public_id)
}

/// Production staging site for a job entering `awaiting_signature`.
///
/// Under a v1.1 claim this is the **only** path that writes
/// `pending_sign_map` for a live job: it calls [`crate::v11::stage_pending_sign`],
/// persists the restart envelope, and builds the §7.5 advertisement.
/// Flag-off ignores `pending` and returns legacy ash‖ocr.
///
/// On any failure after `stage_pending_sign`, the map entry is cleaned
/// up before returning `Err` (Defect 3 — no best-effort leftover).
pub(crate) async fn stage_and_select_awaiting_signature(
    job_store: &JobStore,
    app_state: &AppState,
    public_id: Uuid,
    legacy_ash: &str,
    legacy_ocr: &str,
    pending: Option<crate::v11::PendingSignEntry>,
) -> Result<serde_json::Value, String> {
    let staged_ref = if let Some(mut entry) = pending {
        // Capture caller-supplied publisher_pubkey from the job row so the
        // durable capability carries everything job completion needs.
        if let Ok(Some(job)) = job_store.load(public_id).await {
            match crate::v11::publisher_pubkey_from_request_body(&job.request_body) {
                Ok(pk) => entry = entry.with_publisher_pubkey(pk),
                Err(msg) => {
                    return Err(format!(
                        "publisher_pubkey on transition request is malformed: {msg}"
                    ));
                }
            }
        }
        // Canonical production writer — tests must not insert into the
        // map by hand if they want to exercise this path.
        let _persist_json =
            crate::v11::stage_pending_sign(&app_state.pending_sign_map, public_id, entry);
        let Some(guard) = app_state.pending_sign_map.get(&public_id) else {
            return Err(
                "stage_pending_sign did not leave a map entry (internal lifecycle bug)"
                    .to_string(),
            );
        };
        let entry_clone = guard.clone();
        drop(guard);
        if let Err(e) = persist_pending_sign_on_job(job_store, public_id, &entry_clone).await {
            app_state.pending_sign_map.remove(&public_id);
            return Err(format!(
                "failed to persist durable finalisation for restart safety: {e}"
            ));
        }
        Some(entry_clone)
    } else {
        None
    };

    match crate::v11::select_awaiting_signature_result(
        legacy_ash,
        legacy_ocr,
        staged_ref.as_ref(),
    ) {
        Ok(v) => Ok(v),
        Err(e) => {
            // v1.1 without a staged pending — clean any partial state.
            app_state.pending_sign_map.remove(&public_id);
            Err(e.to_string())
        }
    }
}

/// Job `error` column for a failed transition into awaiting_signature.
/// Structured JSON under v1.1; plain string under flag-off (legacy).
fn fail_error_string(message: &str) -> String {
    if crate::v11::v11_sign_route_active() {
        crate::v11::encode_job_error("proving_failed", message)
    } else {
        message.to_string()
    }
}

/// In-memory staging cleanup after a job leaves the sign handoff.
///
/// Terminal status transitions (`fail` / `complete` /
/// `cancel` / `cancel_not_yet_published`) strip `pending_sign` and
/// `sign` from `request_body` **atomically** with the status flip
/// (Defect 3). This helper therefore only drops the in-memory map
/// entry for those paths.
///
/// When the status did **not** transition (e.g. `set_awaiting_signature`
/// failed after `stage_pending_sign`, or cancel won and left the row
/// cancelled via a separate path), this also best-effort strips any
/// leftover envelope — **but only while the row is not under an exclusive
/// finalise claim**. After `set_awaiting_signature` another process can
/// sign + claim before this worker's confirmation load; the unexpected-
/// status branch must not rewrite that claimed row (see
/// [`JobStore::replace_request_body_if_cleanup_safe`]).
///
/// A leftover on a non-`awaiting_signature`, unclaimed row is harmless:
/// boot resume and `/sign` only rehydrate when status is
/// `awaiting_signature`, so a stale envelope cannot resurrect a job.
async fn cleanup_pending_sign(
    job_store: &JobStore,
    app_state: &AppState,
    public_id: Uuid,
) {
    app_state.pending_sign_map.remove(&public_id);
    let Ok(Some(job)) = job_store.load(public_id).await else {
        return;
    };
    // Live sign handoff: leave the envelope for the wallet / /sign path.
    if job.status == JobStatus::AwaitingSignature {
        return;
    }
    // Exclusive finalise claim: never rewrite the claim holder's body
    // (even if a concurrent claim raced past our confirmation load).
    if job.phase == crate::job_store::FINALISE_CLAIM_PHASE {
        return;
    }
    let mut body = job.request_body;
    if !crate::v11::strip_pending_sign_from_body(&mut body) {
        // Also drop a durable `sign` blob if present without pending_sign.
        if body
            .as_object_mut()
            .map(|o| o.remove("sign").is_some())
            .unwrap_or(false)
        {
            // fall through to persist
        } else {
            return;
        }
    } else {
        let _ = body.as_object_mut().map(|o| o.remove("sign"));
    }
    // Fence is in the SQL: refuses awaiting_signature and FINALISE_CLAIM_PHASE.
    match job_store
        .replace_request_body_if_cleanup_safe(public_id, &body)
        .await
    {
        Ok(false) => {
            tracing::info!(
                "Job dispatcher: cleanup body rewrite skipped for job {} \
                 (awaiting_signature or claimed since load)",
                public_id
            );
        }
        Ok(true) => {}
        Err(e) => {
            tracing::warn!(
                "Job dispatcher: best-effort strip of leftover pending_sign for job {} failed: {} \
                 (harmless: rehydrate is gated on awaiting_signature)",
                public_id,
                e
            );
        }
    }
}

/// Rehydrate `pending_sign_map` from the job row after a process restart.
fn rehydrate_pending_sign_into_map(app_state: &AppState, public_id: Uuid, job: &Job) {
    if app_state.pending_sign_map.contains_key(&public_id) {
        return;
    }
    match crate::v11::rehydrate_pending_sign(&job.request_body) {
        Ok(Some(entry)) => {
            tracing::info!(
                "Job dispatcher: rehydrated pending_sign for job {} after restart \
                 (send_counter={})",
                public_id,
                entry.send_counter()
            );
            app_state.pending_sign_map.insert(public_id, entry);
        }
        Ok(None) => {
            if crate::v11::v11_sign_route_active() {
                tracing::warn!(
                    "Job dispatcher: job {} resumed awaiting_signature under v1.1 \
                     but request_body has no pending_sign envelope — /sign will fail",
                    public_id
                );
            }
        }
        Err(e) => {
            tracing::error!(
                "Job dispatcher: failed to rehydrate pending_sign for job {}: {}",
                public_id,
                e
            );
        }
    }
}

/// Drive a send job from `queued` through the prove leg to
/// `awaiting_signature`, then park on the per-job `Notify` channel
/// until the wallet's `commit_handler` signals (or the timeout
/// fires).
async fn process_send_initial(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &JobNotifyMap,
    awaiting_signature_timeout: Duration,
    job: Job,
) -> anyhow::Result<()> {
    let public_id = job.public_id;
    if !job_store
        .set_status(public_id, JobStatus::Proving, "proving")
        .await?
    {
        tracing::warn!(
            "Job dispatcher: send job {} set_status(proving) matched 0 rows; aborting",
            public_id
        );
        notify_map.remove(&public_id);
        return Ok(());
    }
    publish_phase(
        notify_map,
        public_id,
        JobPhaseEvent {
            status: JobStatus::Proving,
            phase: "proving".to_string(),
            proof_id: None,
            result: None,
            error: None,
        },
    );

    let request: SendCoinRequest = match serde_json::from_value(job.request_body.clone()) {
        Ok(r) => r,
        Err(e) => {
            let msg = format!("invalid send request body: {}", e);
            if !job_store.fail(public_id, &msg).await? {
                tracing::warn!(
                    "Job dispatcher: fail matched 0 rows; not publishing failed event"
                );
                cleanup_pending_sign(job_store, app_state, public_id).await;
                notify_map.remove(&public_id);
                return Ok(());
            }
            publish_phase(
                notify_map,
                public_id,
                JobPhaseEvent {
                    status: JobStatus::Failed,
                    phase: "failed".to_string(),
                    proof_id: None,
                    result: None,
                    error: Some(msg),
                },
            );
            return Ok(());
        }
    };

    let (proof_id, commit_hashes) = match send_flow(app_state, request).await {
        Ok(out) => {
            // The prove leg succeeded (the job reaches awaiting_signature).
            note_prove_outcome(app_state, Ok(())).await;
            out
        }
        Err(FlowError { status, message }) => {
            tracing::warn!(
                "Job dispatcher: send job {} prove leg failed ({}): {}",
                public_id,
                status.as_u16(),
                message
            );
            note_prove_outcome(app_state, Err(message.as_str())).await;
            if let Ok(Some(j)) = job_store.load(public_id).await {
                if j.status == JobStatus::Cancelled {
                    cleanup_pending_sign(job_store, app_state, public_id).await;
                    notify_map.remove(&public_id);
                    return Ok(());
                }
            }
            if !job_store.fail(public_id, &message).await? {
                tracing::warn!(
                    "Job dispatcher: fail matched 0 rows; not publishing failed event"
                );
                cleanup_pending_sign(job_store, app_state, public_id).await;
                notify_map.remove(&public_id);
                return Ok(());
            }
            publish_phase(
                notify_map,
                public_id,
                JobPhaseEvent {
                    status: JobStatus::Failed,
                    phase: "failed".to_string(),
                    proof_id: None,
                    result: None,
                    error: Some(message),
                },
            );
            return Ok(());
        }
    };

    // Cancel may have won during the prove leg.
    if let Ok(Some(j)) = job_store.load(public_id).await {
        if j.status == JobStatus::Cancelled {
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
    }

    // Register a JobNotifier *before* persisting `awaiting_signature`
    // so a fast wallet that polls and POSTs `/commit` immediately
    // observes a ready channel. `entry().or_insert_with()` is used so
    // an SSE listener that subscribed earlier (and created the entry
    // itself) keeps its existing broadcast subscribers — replacing the
    // entry here would silently disconnect every active SSE stream.
    let notifier = notify_map
        .entry(public_id)
        .or_insert_with(|| Arc::new(JobNotifier::new()))
        .clone();

    // Under a v1.1 claim the job advertises the §7.5 ProofData surface
    // (from a staged PendingSignEntry), not legacy ash/ocr — a wallet
    // that signed ash/ocr would be rejected at `/sign`. Flag-off keeps
    // the legacy ash/ocr fields unchanged. Staging goes through
    // stage_pending_sign (the only production writer of pending_sign_map).
    let live_pending = resolve_live_pending_after_prove(app_state, public_id);
    let result = match stage_and_select_awaiting_signature(
        job_store,
        app_state,
        public_id,
        &commit_hashes.account_state_hash,
        &commit_hashes.output_coins_root,
        live_pending,
    )
    .await
    {
        Ok(v) => v,
        Err(msg) => {
            tracing::warn!(
                "Job dispatcher: send job {} refused awaiting_signature advertisement: {}",
                public_id,
                msg
            );
            let err = fail_error_string(&msg);
            if !job_store.fail(public_id, &err).await? {
                tracing::warn!(
                    "Job dispatcher: fail matched 0 rows; not publishing failed event"
                );
                cleanup_pending_sign(job_store, app_state, public_id).await;
                notify_map.remove(&public_id);
                return Ok(());
            }
            publish_phase(
                notify_map,
                public_id,
                JobPhaseEvent {
                    status: JobStatus::Failed,
                    phase: "failed".to_string(),
                    proof_id: None,
                    result: None,
                    error: Some(err),
                },
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
    };
    match job_store
        .set_awaiting_signature(public_id, proof_id as i64, result.clone())
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                "Job dispatcher: send job {} set_awaiting_signature matched 0 rows; cleaning up",
                public_id
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
        Err(e) => {
            // Defect 3: staged map + envelope + notifier must not survive a
            // failed status transition.
            tracing::error!(
                "Job dispatcher: send job {} set_awaiting_signature failed: {}",
                public_id,
                e
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Err(e.into());
        }
    }
    match job_store.load(public_id).await? {
        Some(j) if j.status == JobStatus::AwaitingSignature => {}
        Some(j) if j.status == JobStatus::Cancelled => {
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
        other => {
            tracing::warn!(
                "Job dispatcher: send job {} not in awaiting_signature after set ({:?}); cleaning up",
                public_id,
                other.map(|j| j.status)
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
    }
    publish_phase(
        notify_map,
        public_id,
        JobPhaseEvent {
            status: JobStatus::AwaitingSignature,
            phase: "awaiting_signature".to_string(),
            proof_id: Some(proof_id as i64),
            result: Some(result),
            error: None,
        },
    );
    tracing::info!(
        "Job dispatcher: send job {} reached awaiting_signature (proof_id={})",
        public_id,
        proof_id
    );

    wait_for_commit(
        job_store,
        app_state,
        notify_map,
        awaiting_signature_timeout,
        public_id,
        JobKind::Send,
        notifier,
    )
    .await
}

/// Resume a send job that was already `awaiting_signature` when the
/// process restarted. The boot-time resumer in `runtime.rs`
/// pre-populates a fresh `Notify` in the map so the dispatcher can
/// park on it the same way the in-process flow does.
async fn process_send_resume(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &JobNotifyMap,
    awaiting_signature_timeout: Duration,
    job: Job,
) -> anyhow::Result<()> {
    let public_id = job.public_id;
    // Defect 4: rehydrate staged pending so /sign works after a restart.
    rehydrate_pending_sign_into_map(app_state, public_id, &job);
    let notifier = notify_map
        .entry(public_id)
        .or_insert_with(|| Arc::new(JobNotifier::new()))
        .clone();
    tracing::info!(
        "Job dispatcher: resuming send job {} in awaiting_signature",
        public_id
    );
    // Re-publish the awaiting_signature event so a freshly-connected
    // SSE stream sees the current phase even if its initial-state
    // push fired before the dispatcher reached this function. The
    // surface persisted on the row at the original
    // `set_awaiting_signature` is carried through so a wallet that
    // reconnects after a node restart still gets the hex to sign
    // without an extra round-trip.
    publish_phase(
        notify_map,
        public_id,
        JobPhaseEvent {
            status: JobStatus::AwaitingSignature,
            phase: "awaiting_signature".to_string(),
            proof_id: job.proof_id,
            result: job.response_body.clone(),
            error: None,
        },
    );
    wait_for_commit(
        job_store,
        app_state,
        notify_map,
        awaiting_signature_timeout,
        public_id,
        JobKind::Send,
        notifier,
    )
    .await
}

/// Park on the `notify` channel for the given `public_id`. On wake,
/// load the (now-updated) job, parse the `CommitRequest` the
/// commit-route persisted into the job's `request_body`, and drive
/// the broadcast leg via the kind-appropriate flow: [`mint_commit_flow`]
/// for a `Mint` job (which runs the soundness gate), [`commit_flow`]
/// for a `Send`. On timeout, fail the job.
///
/// ## Crash recovery — durable finalisation capability
///
/// `/sign` installs the verified signature into the durable
/// [`FinalisationCapability`] **before** CAS/notify. If the process dies
/// after that persist, boot resume re-enqueues the job and this function
/// sees a **signed** capability **before** parking: it drives finalise
/// immediately so a job the wallet already saw as `signature_accepted` is
/// not left waiting for a second `/sign`.
///
/// Resume reads the capability alone — no in-memory map required (true cold
/// boot). Each step is status-guarded so a second attempt is harmless.
async fn wait_for_commit(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &JobNotifyMap,
    awaiting_signature_timeout: Duration,
    public_id: Uuid,
    kind: JobKind,
    notifier: Arc<JobNotifier>,
) -> anyhow::Result<()> {
    // Signed durable capability already on the row (crash after persist /
    // CAS / notify, or boot resume of a signed job). Drive finalise without
    // waiting for another wallet round-trip.
    if crate::v11::v11_sign_route_active() {
        if let Ok(Some(job)) = job_store.load(public_id).await {
            if matches!(
                job.status,
                JobStatus::AwaitingSignature | JobStatus::Broadcasting
            ) {
                if let Ok(Some(entry)) = crate::v11::rehydrate_pending_sign(&job.request_body) {
                    if entry.signature.is_some() {
                        tracing::info!(
                            "Job dispatcher: job {} has signed durable finalisation on resume \
                             — driving finalise",
                            public_id
                        );
                        return drive_v11_finalise(
                            job_store,
                            app_state,
                            notify_map,
                            public_id,
                            &job,
                        )
                        .await;
                    }
                }
            }
        }
    }

    // Park until the route signals (CAS → notify) or the timeout claims
    // the handoff. The CAS on JobNotifier::handoff closes the race where
    // the route clones a live notifier, the dispatcher times out, and
    // the route still reports acceptance.
    let outcome = tokio::select! {
        _ = notifier.commit_wake.notified() => SignalOutcome::Signaled,
        _ = tokio::time::sleep(awaiting_signature_timeout) => {
            if notifier.try_claim_timeout() {
                SignalOutcome::TimedOut
            } else {
                // Route already claimed SIGNALED (possibly mid-race with
                // this timeout). Process the signature; do not fail.
                SignalOutcome::Signaled
            }
        }
    };

    match outcome {
        SignalOutcome::TimedOut => {
            tracing::warn!(
                "Job dispatcher: send job {} timed out in awaiting_signature",
                public_id
            );
            // Defect 5: flag-off stores the plain legacy string byte-for-byte.
            // v1.1 uses the structured §7.5 {error, message} JSON (no dedicated
            // timeout code → internal_error).
            let err = if crate::v11::v11_sign_route_active() {
                crate::v11::encode_job_error("internal_error", "awaiting_signature timeout")
            } else {
                "awaiting_signature timeout".to_string()
            };
            // Fence-aware terminate: only unclaimed `awaiting_signature`.
            // An exclusive finalise claim (any fence, including a newer epoch
            // after reclaim) must not be killed by this timeout — bare
            // `JobStore::fail` would ignore the claim and terminate the winner.
            let failed = job_store
                .fail_if_status(public_id, &[JobStatus::AwaitingSignature], &err)
                .await?;
            if !failed {
                tracing::info!(
                    "Job dispatcher: job {} awaiting_signature timeout was a no-op \
                     (status moved or exclusive finalise claim holds); \
                     leaving shared notify state intact",
                    public_id
                );
                return Ok(());
            }
            // Publish the terminal `failed` event BEFORE removing the
            // notify-map entry so an attached SSE stream receives the
            // final phase frame. The remove() runs after — once every
            // subscriber has been handed the event, the map entry no
            // longer needs to exist.
            publish_phase(
                notify_map,
                public_id,
                JobPhaseEvent {
                    status: JobStatus::Failed,
                    phase: "failed".to_string(),
                    proof_id: None,
                    result: None,
                    error: Some(err),
                },
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
        SignalOutcome::Signaled => {}
    }

    let job = match job_store.load(public_id).await? {
        Some(j) => j,
        None => {
            tracing::warn!("Job dispatcher: post-signal load missed job {}", public_id);
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
    };

    // Cancel won the race (wallet cancelled while we were parked, or
    // the cancel handler claimed the handoff and woke us). Do not
    // overwrite a cancelled row with fail/complete.
    if job.status == JobStatus::Cancelled || job.status.is_terminal() {
        tracing::info!(
            "Job dispatcher: job {} is terminal ({:?}) after handoff wake; exiting",
            public_id,
            job.status
        );
        cleanup_pending_sign(job_store, app_state, public_id).await;
        notify_map.remove(&public_id);
        return Ok(());
    }

    // v1.1 path: `/v1/jobs/{id}/sign` already verified and installed the
    // signature into the durable FinalisationCapability. Drive finalise —
    // never complete the job with the signature material alone.
    if crate::v11::v11_sign_route_active() {
        if let Ok(Some(entry)) = crate::v11::rehydrate_pending_sign(&job.request_body) {
            if entry.signature.is_some() {
                return drive_v11_finalise(job_store, app_state, notify_map, public_id, &job)
                    .await;
            }
        }
        // In-memory map may hold the signature if persist rehydrate raced.
        if let Some(entry) = app_state.pending_sign_map.get(&public_id) {
            if entry.signature.is_some() {
                return drive_v11_finalise(job_store, app_state, notify_map, public_id, &job)
                    .await;
            }
        }
    }

    // Legacy path: the commit-route persists the wallet-provided
    // `CommitRequest` into the job's `request_body` under a
    // `commit` key alongside the original send body. Pull it out
    // and feed it to `commit_flow`.
    let commit_value = job
        .request_body
        .get("commit")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let commit_request: CommitRequest = match serde_json::from_value(commit_value) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid commit body: {}", e);
            if !job_store.fail(public_id, &msg).await? {
                tracing::warn!(
                    "Job dispatcher: fail matched 0 rows; not publishing failed event"
                );
                cleanup_pending_sign(job_store, app_state, public_id).await;
                notify_map.remove(&public_id);
                return Ok(());
            }
            publish_phase(
                notify_map,
                public_id,
                JobPhaseEvent {
                    status: JobStatus::Failed,
                    phase: "failed".to_string(),
                    proof_id: None,
                    result: None,
                    error: Some(msg),
                },
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
    };

    if !job_store
        .set_status(public_id, JobStatus::Broadcasting, "broadcasting")
        .await?
    {
        // Zero rows: self-heal fence / missing row. Never run commit flows
        // against wiped proof state after a silent no-op status write.
        tracing::warn!(
            "Job dispatcher: job {} set_status(broadcasting) matched 0 rows; \
             refusing mint_commit_flow/commit_flow",
            public_id
        );
        cleanup_pending_sign(job_store, app_state, public_id).await;
        notify_map.remove(&public_id);
        return Ok(());
    }
    publish_phase(
        notify_map,
        public_id,
        JobPhaseEvent {
            status: JobStatus::Broadcasting,
            phase: "broadcasting".to_string(),
            proof_id: None,
            result: None,
            error: None,
        },
    );

    let commit_outcome = match kind {
        JobKind::Mint => mint_commit_flow(app_state, commit_request).await,
        JobKind::Send => commit_flow(app_state, commit_request).await,
    };
    match commit_outcome {
        Ok((response_body, response_status)) => {
            if !job_store
                .complete(public_id, response_body.clone(), response_status as i16)
                .await?
            {
                // Zero rows: generation fence / terminal / missing. Never
                // publish completed against a row that did not advance
                // (e.g. reset failed the job while commit_flow was in flight).
                tracing::warn!(
                    "Job dispatcher: job {} complete matched 0 rows; refusing completed event",
                    public_id
                );
                cleanup_pending_sign(job_store, app_state, public_id).await;
                notify_map.remove(&public_id);
                return Ok(());
            }
            publish_phase(
                notify_map,
                public_id,
                JobPhaseEvent {
                    status: JobStatus::Completed,
                    phase: "completed".to_string(),
                    proof_id: None,
                    result: Some(response_body),
                    error: None,
                },
            );
            tracing::info!("Job dispatcher: send job {} completed", public_id);
        }
        Err(FlowError { status, message }) => {
            tracing::warn!(
                "Job dispatcher: send job {} commit leg failed ({}): {}",
                public_id,
                status.as_u16(),
                message
            );
            if !job_store.fail(public_id, &message).await? {
                tracing::warn!(
                    "Job dispatcher: job {} fail matched 0 rows after commit error; \
                     not publishing failed event",
                    public_id
                );
                cleanup_pending_sign(job_store, app_state, public_id).await;
                notify_map.remove(&public_id);
                return Ok(());
            }
            publish_phase(
                notify_map,
                public_id,
                JobPhaseEvent {
                    status: JobStatus::Failed,
                    phase: "failed".to_string(),
                    proof_id: None,
                    result: None,
                    error: Some(message),
                },
            );
        }
    }

    // Drop the notify-map entry now that the job has reached a
    // terminal state. The broadcast channel inside the dropped
    // `JobNotifier` keeps existing receivers alive long enough to
    // observe the final event (they each hold their own `Receiver`),
    // but no new SSE subscriber can attach after this point — the
    // `stream_job_handler` would see the terminal row on its
    // initial-state push and close immediately.
    cleanup_pending_sign(job_store, app_state, public_id).await;
    notify_map.remove(&public_id);

    Ok(())
}

enum SignalOutcome {
    Signaled,
    TimedOut,
}

/// Why finalise lost demonstrable lease liveness mid-operation.
///
/// Losing the lease is not a warning: the owner no longer has the right to
/// apply results. Every variant is fail-closed — work aborts, the result is
/// discarded, and the job is left for a later resumer once the claim is free.
///
/// Dropping the work future is only cooperative (Rust cancel at the next
/// `.await`). Durable transition commits are fenced separately by
/// **fencing-token + lease** writes ([`JobStore::merge_finalisation_if_finalise_owner`],
/// [`JobStore::complete_if_finalise_owner`]) so a worker that keeps running
/// after loss — even under the same owner UUID after reclaim — still cannot
/// commit with a stale fence.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FinaliseLeaseLivenessLost {
    /// `renew_finalise_claim` returned `Ok(false)` — ownership is gone.
    RenewReturnedFalse,
    /// Database / storage error while renewing; liveness cannot be proved.
    RenewError(String),
    /// A single renew await exceeded its deadline — stalled renew is loss.
    RenewTimedOut,
    /// The heartbeat task ended (panic or silent exit) while work was in flight.
    HeartbeatTaskEnded,
}

impl std::fmt::Display for FinaliseLeaseLivenessLost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RenewReturnedFalse => {
                write!(f, "finalise lease renew returned false (ownership lost)")
            }
            Self::RenewError(e) => write!(f, "finalise lease renew failed: {e}"),
            Self::RenewTimedOut => {
                write!(f, "finalise lease renew timed out (stalled renew is loss)")
            }
            Self::HeartbeatTaskEnded => {
                write!(f, "finalise lease heartbeat task ended while work in flight")
            }
        }
    }
}

/// Run `work` while periodically renewing the exclusive finalise lease.
///
/// A lease that is only asserted once before a multi-minute prove expires
/// while the owner is still alive; a boot sweep then frees it and a second
/// resumer double-executes. This heartbeat proves liveness continuously.
///
/// **Fail closed:** if renewal returns `Ok(false)`, a renew error occurs, a
/// renew await exceeds `renew_timeout`, or the heartbeat task disappears,
/// this future resolves to [`Err`]`(`[`FinaliseLeaseLivenessLost`]`)` and
/// drops `work` without yielding its result. Drop is cooperative — durable
/// commits still require the claim fence (token + unexpired lease).
///
/// `renew_every` should be well under `lease` (production uses
/// [`crate::job_store::FINALISE_CLAIM_RENEW_INTERVAL`]). `renew_timeout`
/// bounds each renew await (production:
/// [`crate::job_store::FINALISE_CLAIM_RENEW_TIMEOUT`]). Renewals write
/// `NOW() + lease` in Postgres — same clock as claim create and stale release
/// — and must match the acquisition `fence`.
///
/// `work` must yield to the async runtime (await points / `spawn_blocking`
/// for CPU-bound prove) so the heartbeat task can run. Production covers
/// prove **and** host-edge completion writes under this heartbeat.
pub(crate) async fn with_finalise_lease_heartbeat<F, T>(
    job_store: &JobStore,
    public_id: Uuid,
    owner: Uuid,
    fence: i64,
    lease: std::time::Duration,
    renew_every: std::time::Duration,
    renew_timeout: std::time::Duration,
    work: F,
) -> Result<T, FinaliseLeaseLivenessLost>
where
    F: std::future::Future<Output = T>,
{
    let store = job_store.clone();
    with_finalise_lease_heartbeat_renew(
        renew_every,
        renew_timeout,
        move || {
            let store = store.clone();
            async move {
                store
                    .renew_finalise_claim(public_id, owner, fence, lease)
                    .await
                    .map_err(|e| e.to_string())
            }
        },
        work,
    )
    .await
}

/// Core fail-closed heartbeat loop. `renew` is called on each tick; production
/// wires [`JobStore::renew_finalise_claim`], tests inject failures.
///
/// Each `renew()` await is bounded by `renew_timeout`. A stalled renew is
/// treated as ownership loss — not an unbounded pause while work runs on.
pub(crate) async fn with_finalise_lease_heartbeat_renew<R, Fut, F, T>(
    renew_every: std::time::Duration,
    renew_timeout: std::time::Duration,
    mut renew: R,
    work: F,
) -> Result<T, FinaliseLeaseLivenessLost>
where
    R: FnMut() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<bool, String>> + Send,
    F: std::future::Future<Output = T>,
{
    let (cancel_tx, mut cancel_rx) = tokio::sync::oneshot::channel::<()>();
    // Heartbeat reports loss on this channel. Dropping the sender without a
    // value (panic / silent exit) is itself a liveness failure.
    let (lost_tx, mut lost_rx) = tokio::sync::oneshot::channel::<FinaliseLeaseLivenessLost>();

    let heartbeat = tokio::spawn(async move {
        let mut ticker = tokio::time::interval(renew_every);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // First `tick` completes immediately; skip so we do not double-renew
        // at t=0 (caller already renewed after claim).
        ticker.tick().await;
        loop {
            tokio::select! {
                _ = &mut cancel_rx => {
                    // Clean stop after work completed; do not signal loss.
                    // Dropping lost_tx without send is fine — receiver is gone.
                    return;
                }
                _ = ticker.tick() => {
                    // Bound the renew await: a hung DB must not pause fail-closed
                    // while work continues past lease expiry.
                    match tokio::time::timeout(renew_timeout, renew()).await {
                        Err(_) => {
                            tracing::error!(
                                timeout_secs = renew_timeout.as_secs(),
                                "finalise lease renew timed out mid-operation — aborting work"
                            );
                            let _ = lost_tx.send(FinaliseLeaseLivenessLost::RenewTimedOut);
                            return;
                        }
                        Ok(Ok(true)) => {
                            tracing::debug!("finalise lease renewed during long operation");
                        }
                        Ok(Ok(false)) => {
                            tracing::error!(
                                "finalise lease renew lost ownership mid-operation — aborting work"
                            );
                            let _ = lost_tx.send(FinaliseLeaseLivenessLost::RenewReturnedFalse);
                            return;
                        }
                        Ok(Err(e)) => {
                            tracing::error!(
                                error = %e,
                                "finalise lease renew failed mid-operation — aborting work"
                            );
                            let _ = lost_tx.send(FinaliseLeaseLivenessLost::RenewError(e));
                            return;
                        }
                    }
                }
            }
        }
    });

    // Pin work so we can cancel it by dropping when liveness is lost.
    tokio::pin!(work);

    // Two completion paths only:
    // 1. `lost_rx` fires → ownership gone, renew error/timeout, or heartbeat died
    //    (sender dropped without a value). Drop `work` and discard its result.
    // 2. `work` finishes first → stop heartbeat cleanly, return Ok(result)
    //    only if no loss raced in and the heartbeat task did not panic.
    //
    // Heartbeat panics drop `lost_tx` without send → `lost_rx` yields `Err`,
    // which is the "task disappeared" signal. `biased` prefers the loss arm
    // when both are ready so a just-lost lease never publishes a result.
    //
    // Dropping `work` is cooperative: CPU-bound segments between `.await`
    // points may still run. Durable writes must themselves require ownership.
    tokio::select! {
        biased;
        lost = &mut lost_rx => {
            // Liveness can no longer be demonstrated: drop `work`, discard result.
            drop(work);
            let _ = heartbeat.await;
            match lost {
                Ok(reason) => Err(reason),
                // Sender dropped without a value → heartbeat task disappeared.
                Err(_) => Err(FinaliseLeaseLivenessLost::HeartbeatTaskEnded),
            }
        }
        result = &mut work => {
            // Check loss *before* cancelling the heartbeat: a clean cancel
            // drops `lost_tx` and would otherwise look like "task disappeared".
            match lost_rx.try_recv() {
                Ok(reason) => {
                    let _ = cancel_tx.send(());
                    let _ = heartbeat.await;
                    return Err(reason);
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    let _ = cancel_tx.send(());
                    let _ = heartbeat.await;
                    return Err(FinaliseLeaseLivenessLost::HeartbeatTaskEnded);
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {}
            }
            let _ = cancel_tx.send(());
            match heartbeat.await {
                Ok(()) => Ok(result),
                // Heartbeat panicked after work completed: still fail closed —
                // we cannot assert the lease was live for the whole operation.
                Err(join_err) => {
                    tracing::error!(
                        error = %join_err,
                        "finalise lease heartbeat panicked after work completed — discarding result"
                    );
                    Err(FinaliseLeaseLivenessLost::HeartbeatTaskEnded)
                }
            }
        }
    }
}

/// Documented host edge of the job-path finalise resume.
///
/// ## Where completion ends (and why)
///
/// [`drive_v11_finalise`] drives a job through:
///
/// 1. exclusive claim (owner + lease, renewed during long prove)
/// 2. prove + apply + **durable** engine snapshot + `v11_pending_publishes`
///    (`members_ready`) via [`crate::router::V11FinaliseHook`] **or** skip
///    when `completion_result` is already durable (crash after stage)
/// 3. persist the §7.5 completion surface on the durable capability
/// 4. [`JobStore::complete_if_finalise_owner`] — §7.5 result published onto the job row
///
/// That is the **host edge**. The production hook
/// ([`crate::v11::finalise_accepted_prove_persist_and_stage`]) leaves the
/// applied account and a `members_ready` rebroadcast intent on disk so a
/// restarted node — or later publisher wiring — finds the job exactly at
/// this edge. On-chain AggregateStateNullifierV3 **broadcast** still needs
/// a live bitcoind wallet ([`crate::v11::V11Publisher`]); that is outside
/// the host edge, not a silent skip of durability up to it.
///
/// Resume is covered durably up to this edge so a job can be driven to exactly
/// the point where chain-publish takes over.
pub const JOB_FINALISE_HOST_EDGE: &str =
    "job_result_published_after_durable_engine_and_members_ready; on-chain AggregateStateNullifierV3 broadcast requires bitcoind (publisher not driven by this path)";

/// Drive an accepted v1.1 signature through the durable host path up to
/// [`JOB_FINALISE_HOST_EDGE`].
///
/// ## Sweep: every SQL write that mutates a job row
///
/// **Derivation method (do not compose from memory):**
/// `rg -n 'UPDATE jobs SET|INSERT INTO jobs' node/src --glob '!**/*_tests.rs'`
/// then open each hit and quote the actual `WHERE` (or admit lock). A table
/// assembled from recollection is the same class of evidence as a test that
/// checks its own logic. Two prior hand sweeps each missed entries.
///
/// Every job-advancing write below opens a transaction, takes
/// `SELECT generation … FOR UPDATE` on `self_heal_reset_meta` (same construct
/// as admit / reset bump — mutual exclusion, not an unlocked MVCC snapshot),
/// and binds the locked generation into `reset_generation = $N`. A bare
/// scalar subquery is **not** a fence.
///
/// Zero-row audit: every write reports visibility (`bool`, `FinaliseClaim`,
/// or `CreateResult`). Callers must act on zero rows — silent `Ok(())` is
/// forbidden.
///
/// | Write | Actual `WHERE` / lock (ground truth) | Zero-row report |
/// |-------|--------------------------------------|-----------------|
/// | [`JobStore::create`] (`INSERT`) | tx: `SELECT generation … FOR UPDATE` then `INSERT … reset_generation = $8` | `CreateResult` |
/// | [`JobStore::set_status`] | lock gen; `WHERE public_id AND reset_generation = $4 AND status NOT IN (terminal)` | **bool** |
/// | [`JobStore::set_status_if`] | lock gen; `WHERE public_id AND status = $4 AND reset_generation = $5` | **bool** |
/// | [`JobStore::set_awaiting_signature`] | lock gen; `WHERE public_id AND status IN (queued,proving) AND reset_generation = $4` | **bool** |
/// | [`JobStore::complete`] | lock gen; `WHERE public_id AND reset_generation = $4 AND status NOT IN (terminal)` | **bool** |
/// | [`JobStore::complete_if_status`] | lock gen; status ANY + not claim phase + `reset_generation = $6` | **bool** |
/// | [`JobStore::complete_if_finalise_owner`] | lock gen; claim fence + lease + `reset_generation = $7` | **bool** |
/// | [`JobStore::fail`] | lock gen; `WHERE public_id AND reset_generation = $3 AND status NOT IN (terminal)` | **bool** |
/// | [`JobStore::fail_if_status`] | lock gen; status ANY + not claim phase + `reset_generation = $5` | **bool** |
/// | [`JobStore::fail_if_finalise_owner`] | lock gen; claim fence + lease + `reset_generation = $6` | **bool** |
/// | [`JobStore::claim_finalise_exclusive`] path A/B | lock gen once; status/phase CAS + `reset_generation = $N`; **mints** fence | `FinaliseClaim` |
/// | [`JobStore::renew_finalise_claim`] | lock gen; claim owner+fence + `reset_generation = $7` | **bool** |
/// | [`JobStore::release_stale_finalise_claim`] | lock gen; abandoned lease + `reset_generation = $3` | **bool** |
/// | [`JobStore::replace_request_body_if_status`] | lock gen; status CAS + `reset_generation = $4` | **bool** |
/// | [`JobStore::replace_request_body_if_cleanup_safe`] | lock gen; not handoff + not claim + `reset_generation = $4` | **bool** |
/// | [`JobStore::merge_finalisation_if_finalise_owner`] | lock gen; claim fence + lease + `reset_generation = $7` | **bool** |
/// | [`JobStore::cancel`] | lock gen; queued + `reset_generation = $2` | **bool** |
/// | [`JobStore::cancel_not_yet_published`] | lock gen; cancellable set + `reset_generation = $2` | **bool** |
/// | Legacy commit-payload (`router` → [`JobStore::replace_request_body_if_status`]) | same as replace_request_body_if_status | **bool** |
/// | Self-heal fail non-terminal (`db::fail_non_terminal_jobs_for_self_heal_in_tx`) | `WHERE status IN (non-terminal)` inside reset tx (holds meta lock via bump) | bulk reset path |
/// | Finalise hook → engine snapshot + `members_ready` | (not a `jobs` row write) | fence via [`crate::v11::finalise_accepted_prove_persist_and_stage`] |
///
/// After the claim is won, durable transition commits are fenced on the
/// **acquisition fencing token** plus a still-valid lease — not on owner
/// identity or status alone. Dropping a future after lease loss is only
/// cooperative; the write predicates are the safety mechanism.
///
/// `broadcasting` is an **exclusive claim**, not a permission: exactly one
/// resumer wins the CAS; the loser observes [`FinaliseClaim::Lost`] and must
/// not continue into side effects **and must not mutate shared notify state**.
async fn drive_v11_finalise(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &JobNotifyMap,
    public_id: Uuid,
    job: &Job,
) -> anyhow::Result<()> {
    use crate::job_store::FinaliseClaim;

    // Helper: fail with a §7.5 machine code, clean envelopes, drop notify.
    // Pre-claim only: status-qualified and **never** touches a claimed row
    // (`fail_if_status` refuses [`FINALISE_CLAIM_PHASE`]). Terminal writes
    // on an owned epoch must use the fence path below.
    async fn fail_v11(
        job_store: &JobStore,
        app_state: &AppState,
        notify_map: &JobNotifyMap,
        public_id: Uuid,
        code: &str,
        message: String,
    ) -> anyhow::Result<()> {
        let err = crate::v11::encode_job_error(code, message.clone());
        // Unclaimed only: do not terminate a row another epoch owns.
        let failed = job_store
            .fail_if_status(
                public_id,
                &[JobStatus::AwaitingSignature, JobStatus::Broadcasting],
                &err,
            )
            .await?;
        if !failed {
            // Row is terminal, claimed, or already moved — do not strip
            // notify that may belong to a live claim holder.
            tracing::info!(
                %public_id,
                "Job dispatcher: pre-claim fail_if_status was a no-op \
                 (owned, terminal, or moved); leaving shared notify intact"
            );
            return Ok(());
        }
        publish_phase(
            notify_map,
            public_id,
            JobPhaseEvent {
                status: JobStatus::Failed,
                phase: "failed".to_string(),
                proof_id: None,
                result: None,
                error: Some(err),
            },
        );
        cleanup_pending_sign(job_store, app_state, public_id).await;
        notify_map.remove(&public_id);
        Ok(())
    }

    // Post-claim fail: fence-qualified so a lost/stale worker cannot fail a
    // job another epoch holds (including same-owner reclaim). `Ok(false)` is
    // quiet loss — leave notify.
    async fn fail_v11_as_owner(
        job_store: &JobStore,
        app_state: &AppState,
        notify_map: &JobNotifyMap,
        public_id: Uuid,
        owner: Uuid,
        fence: i64,
        code: &str,
        message: String,
    ) -> anyhow::Result<()> {
        let err = crate::v11::encode_job_error(code, message.clone());
        let failed = job_store
            .fail_if_finalise_owner(public_id, owner, fence, &err)
            .await?;
        if !failed {
            tracing::info!(
                %public_id,
                %owner,
                fence,
                "Job dispatcher: fail_if_finalise_owner was a no-op (fence/lease lost); \
                 leaving shared notify state intact"
            );
            return Ok(());
        }
        publish_phase(
            notify_map,
            public_id,
            JobPhaseEvent {
                status: JobStatus::Failed,
                phase: "failed".to_string(),
                proof_id: None,
                result: None,
                error: Some(err),
            },
        );
        cleanup_pending_sign(job_store, app_state, public_id).await;
        notify_map.remove(&public_id);
        Ok(())
    }

    // Idempotent resume: terminal jobs are done.
    if job.status.is_terminal() {
        tracing::info!(
            "Job dispatcher: job {} already terminal ({:?}); finalise resume is a no-op",
            public_id,
            job.status
        );
        cleanup_pending_sign(job_store, app_state, public_id).await;
        notify_map.remove(&public_id);
        return Ok(());
    }

    // Prefer durable capability (cold boot). In-memory map is only a warm
    // cache of the same envelope — never a substitute for missing fields.
    let mut entry = match crate::v11::rehydrate_pending_sign(&job.request_body) {
        Ok(Some(e)) => e,
        Ok(None) => match app_state.pending_sign_map.get(&public_id).map(|e| e.clone()) {
            Some(e) => e,
            None => {
                return fail_v11(
                    job_store,
                    app_state,
                    notify_map,
                    public_id,
                    "internal_error",
                    "v1.1 finalise: no durable FinalisationCapability on job \
                     (and pending_sign_map empty)"
                        .to_string(),
                )
                .await;
            }
        },
        Err(e) => {
            return fail_v11(
                job_store,
                app_state,
                notify_map,
                public_id,
                "internal_error",
                format!("v1.1 finalise: rehydrate finalisation failed: {e}"),
            )
            .await;
        }
    };

    // Prove+apply readiness (signature). Completion surface may still be absent.
    if let Err(msg) = crate::v11::ensure_finalise_ready(&entry) {
        return fail_v11(
            job_store,
            app_state,
            notify_map,
            public_id,
            "internal_error",
            format!("v1.1 finalise: {msg}"),
        )
        .await;
    }

    // Exclusive claim — broadcasting is ownership, not permission. The fence
    // token minted here is the only credential durable writes accept.
    let claim_fence = match job_store.claim_finalise_exclusive(public_id).await? {
        FinaliseClaim::Won { fence } => {
            tracing::info!(
                "Job dispatcher: job {} won exclusive finalise claim (owner={}, fence={})",
                public_id,
                job_store.process_owner(),
                fence
            );
            // Full lease window from Postgres NOW() before the long path.
            let renewed = job_store
                .renew_finalise_claim(
                    public_id,
                    job_store.process_owner(),
                    fence,
                    crate::job_store::FINALISE_CLAIM_LEASE,
                )
                .await?;
            if !renewed {
                // Already claimed then lost before prove — fence if we still
                // hold this epoch; otherwise quiet exit.
                return fail_v11_as_owner(
                    job_store,
                    app_state,
                    notify_map,
                    public_id,
                    job_store.process_owner(),
                    fence,
                    "internal_error",
                    "v1.1 finalise: won claim but immediate lease renew failed \
                     (lost ownership before prove)"
                        .to_string(),
                )
                .await;
            }
            fence
        }
        FinaliseClaim::Lost { observed } => {
            if observed.is_terminal() {
                tracing::info!(
                    "Job dispatcher: job {} finalise claim lost; already terminal ({:?})",
                    public_id,
                    observed
                );
                // Terminal: no winner is mid-flight. Safe to drop local maps.
                cleanup_pending_sign(job_store, app_state, public_id).await;
                notify_map.remove(&public_id);
                return Ok(());
            }
            // Another resumer owns this job — observe the loss and stop.
            // Do **not** continue just because status is broadcasting.
            // Do **not** remove notify_map: that entry now belongs to the
            // winner (or the live dispatcher that still parks the wallet).
            tracing::info!(
                "Job dispatcher: job {} finalise claim lost (observed {:?}); \
                 refusing side effects; leaving shared notify state intact",
                public_id,
                observed
            );
            return Ok(());
        }
    };

    let claim_owner = job_store.process_owner();

    publish_phase(
        notify_map,
        public_id,
        JobPhaseEvent {
            status: JobStatus::Broadcasting,
            phase: crate::job_store::FINALISE_CLAIM_PHASE.to_string(),
            proof_id: None,
            result: None,
            error: None,
        },
    );

    // Heartbeat covers prove **and** host-edge completion writes. Dropping
    // the work future on lease loss is cooperative only; fence + lease
    // durable writes are the real barrier for anything that still runs.
    //
    // What a worker can still do with a stale fence / expired lease:
    // pure in-process work (CPU prove segments between `.await`s, in-memory
    // apply under a local write gate). It must not commit durable transitions
    // — engine/`members_ready` stage, completion persist, terminal complete,
    // and fence-scoped fail all require the current fence token and an
    // unexpired lease.
    let owned_drive = async {
        // If prove+apply already recorded the §7.5 surface, skip the hook and
        // only publish + complete (crash window after durable stage + completion
        // persist, before terminal complete).
        if !entry.has_completion() {
            let signature = entry
                .signature
                .clone()
                .expect("ensure_finalise_ready checked signature");
            let Some(hook) = app_state.v11_finalise.as_ref() else {
                return fail_v11_as_owner(
                    job_store,
                    app_state,
                    notify_map,
                    public_id,
                    claim_owner,
                    claim_fence,
                    "internal_error",
                    "v1.1 finalise: no finalise driver and no durable completion_result \
                     — cannot prove/apply or complete (incomplete capability path; \
                     refusing to half-finish)"
                        .to_string(),
                )
                .await;
            };

            // publisher_pubkey is only the staged capability field — no silent
            // fall-back to a root request_body key.
            let publisher_pubkey = entry.publisher_pubkey;
            let claim = crate::job_store::FinaliseFence {
                job_id: public_id,
                owner: claim_owner,
                fence: claim_fence,
            };
            // Fence reaches the hook: production stages engine + members_ready
            // only while this acquisition epoch still holds.
            let hook_result = hook(entry.pending.clone(), signature, claim).await;
            match hook_result {
                Ok(mut outcome) => {
                    if outcome.publisher_pubkey.is_none() {
                        outcome.publisher_pubkey = publisher_pubkey;
                    }
                    let response_body = outcome.to_result_json();
                    if let Err(e) = entry.install_completion(response_body, 200) {
                        return fail_v11_as_owner(
                            job_store,
                            app_state,
                            notify_map,
                            public_id,
                            claim_owner,
                            claim_fence,
                            "internal_error",
                            format!("v1.1 finalise: install_completion failed: {e}"),
                        )
                        .await;
                    }
                    // Persist completion onto the durable capability **before**
                    // the terminal complete flip so a crash here is resumable.
                    // Fence-qualified jsonb_set: stale epochs cannot commit;
                    // concurrent lease renew is not clobbered.
                    let persist = match crate::v11::DurableFinalisationPersist::from_entry(&entry)
                    {
                        Ok(p) => p,
                        Err(e) => {
                            return fail_v11_as_owner(
                                job_store,
                                app_state,
                                notify_map,
                                public_id,
                                claim_owner,
                                claim_fence,
                                "internal_error",
                                format!("v1.1 finalise: encode completion capability: {e}"),
                            )
                            .await;
                        }
                    };
                    let persist_val = match serde_json::to_value(&persist) {
                        Ok(v) => v,
                        Err(e) => {
                            return fail_v11_as_owner(
                                job_store,
                                app_state,
                                notify_map,
                                public_id,
                                claim_owner,
                                claim_fence,
                                "internal_error",
                                format!(
                                    "v1.1 finalise: json-encode completion capability: {e}"
                                ),
                            )
                            .await;
                        }
                    };
                    let wrote = job_store
                        .merge_finalisation_if_finalise_owner(
                            public_id,
                            claim_owner,
                            claim_fence,
                            &persist_val,
                        )
                        .await?;
                    if !wrote {
                        tracing::info!(
                            "Job dispatcher: job {} completion persist was a no-op \
                             (fence/lease lost or claim free); exiting without re-complete",
                            public_id
                        );
                        // Do not strip notify — may belong to a new epoch.
                        return Ok(());
                    }
                    app_state.pending_sign_map.insert(public_id, entry.clone());
                }
                Err(e) if e == crate::job_store::FINALISE_FENCE_LOST => {
                    // Stale epoch lost the engine/members_ready commit (or the
                    // resume shortcut). Quiet exit — do not terminal-fail a
                    // job another fence may hold.
                    tracing::info!(
                        "Job dispatcher: job {} finalise hook refused durable stage \
                         (fence/lease lost); leaving shared notify state intact",
                        public_id
                    );
                    return Ok(());
                }
                Err(e) => {
                    let msg = format!("v1.1 finalise failed: {e}");
                    tracing::warn!("Job dispatcher: job {} {}", public_id, msg);
                    return fail_v11_as_owner(
                        job_store,
                        app_state,
                        notify_map,
                        public_id,
                        claim_owner,
                        claim_fence,
                        "proving_failed",
                        msg,
                    )
                    .await;
                }
            }
        }

        // Host §7.5 job-result publication + terminal complete.
        // This is [`JOB_FINALISE_HOST_EDGE`] — not on-chain AggregateStateNullifierV3.
        // Fence is claim token + unexpired lease, not status or owner alone.
        if let Err(msg) = crate::v11::ensure_completion_ready(&entry) {
            return fail_v11_as_owner(
                job_store,
                app_state,
                notify_map,
                public_id,
                claim_owner,
                claim_fence,
                "internal_error",
                format!("v1.1 finalise: incomplete capability for host complete: {msg}"),
            )
            .await;
        }
        let response_body = entry
            .completion_result
            .clone()
            .expect("ensure_completion_ready checked");
        let response_status = entry
            .completion_status
            .expect("ensure_completion_ready checked");
        let completed = job_store
            .complete_if_finalise_owner(
                public_id,
                claim_owner,
                claim_fence,
                response_body.clone(),
                response_status,
            )
            .await?;
        if completed {
            publish_phase(
                notify_map,
                public_id,
                JobPhaseEvent {
                    status: JobStatus::Completed,
                    phase: "completed".to_string(),
                    proof_id: None,
                    result: Some(response_body),
                    error: None,
                },
            );
            tracing::info!(
                "Job dispatcher: job {} reached host finalise edge ({}); \
                 on-chain nullifier publish is not driven by this path",
                public_id,
                JOB_FINALISE_HOST_EDGE
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
        } else {
            tracing::info!(
                "Job dispatcher: job {} complete_if_finalise_owner was a no-op \
                 (fence/lease lost or already terminal); leaving shared notify intact",
                public_id
            );
        }
        Ok(())
    };

    match with_finalise_lease_heartbeat(
        job_store,
        public_id,
        claim_owner,
        claim_fence,
        crate::job_store::FINALISE_CLAIM_LEASE,
        crate::job_store::FINALISE_CLAIM_RENEW_INTERVAL,
        crate::job_store::FINALISE_CLAIM_RENEW_TIMEOUT,
        owned_drive,
    )
    .await
    {
        Ok(inner) => inner,
        Err(lost) => {
            // Lease liveness failed: discard any in-flight prove result,
            // do not fail the job (another resumer must be able to pick
            // it up once the claim is free), leave shared notify intact.
            // Even if work segments still run until the next `.await`,
            // fence-qualified writes refuse commits from this epoch.
            tracing::error!(
                %public_id,
                reason = %lost,
                "Job dispatcher: finalise aborted — lease liveness lost mid-operation; \
                 result discarded; job left for a later resumer"
            );
            Ok(())
        }
    }
}

// Retained for any residual call sites; production path uses the capability.
#[allow(dead_code)]
fn parse_persisted_transition_signature(
    sign_val: &serde_json::Value,
) -> Result<zkcoins_prover::prover_bridge::TransitionSignature, String> {
    let pk_hex = sign_val
        .get("pk_i")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "persisted sign.pk_i missing".to_string())?;
    let sig_hex = sign_val
        .get("signature")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "persisted sign.signature missing".to_string())?;
    let r_hex = sign_val
        .get("r_prime")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "persisted sign.r_prime missing".to_string())?;
    let pk_i: [u8; 32] = hex::decode(pk_hex)
        .map_err(|e| format!("sign.pk_i hex: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("sign.pk_i length {}", v.len()))?;
    let signature: [u8; 64] = hex::decode(sig_hex)
        .map_err(|e| format!("sign.signature hex: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("sign.signature length {}", v.len()))?;
    let r_prime: [u8; 32] = hex::decode(r_hex)
        .map_err(|e| format!("sign.r_prime hex: {e}"))?
        .try_into()
        .map_err(|v: Vec<u8>| format!("sign.r_prime length {}", v.len()))?;
    Ok(zkcoins_prover::prover_bridge::TransitionSignature {
        pk_i,
        signature,
        r_prime,
    })
}
