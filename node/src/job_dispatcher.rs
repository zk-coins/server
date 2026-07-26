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
}

impl JobNotifier {
    /// Build a fresh notifier with an empty `Notify` and a broadcast
    /// channel sized for [`PHASE_CHANNEL_CAPACITY`].
    pub fn new() -> Self {
        let (phase_tx, _rx) = broadcast::channel(PHASE_CHANNEL_CAPACITY);
        Self {
            commit_wake: Arc::new(Notify::new()),
            phase_tx,
        }
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
    job_store
        .set_status(public_id, JobStatus::Proving, "proving")
        .await?;
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
            job_store.fail(public_id, &msg).await?;
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
            job_store.fail(public_id, &message).await?;
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

    let notifier = notify_map
        .entry(public_id)
        .or_insert_with(|| Arc::new(JobNotifier::new()))
        .clone();

    let pending = app_state
        .pending_sign_map
        .get(&public_id)
        .map(|e| e.clone());
    let result = match crate::v11::select_awaiting_signature_result(
        &commit_hashes.account_state_hash,
        &commit_hashes.output_coins_root,
        pending.as_ref(),
    ) {
        Ok(v) => v,
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(
                "Job dispatcher: mint job {} refused awaiting_signature advertisement: {}",
                public_id,
                msg
            );
            job_store.fail(public_id, &msg).await?;
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
            notify_map.remove(&public_id);
            return Ok(());
        }
    };
    job_store
        .set_awaiting_signature(public_id, proof_id as i64, result.clone())
        .await?;
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
    job_store
        .set_status(public_id, JobStatus::Proving, "proving")
        .await?;
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
            job_store.fail(public_id, &msg).await?;
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
            job_store.fail(public_id, &message).await?;
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
    // the legacy ash/ocr fields unchanged.
    let pending = app_state
        .pending_sign_map
        .get(&public_id)
        .map(|e| e.clone());
    let result = match crate::v11::select_awaiting_signature_result(
        &commit_hashes.account_state_hash,
        &commit_hashes.output_coins_root,
        pending.as_ref(),
    ) {
        Ok(v) => v,
        Err(e) => {
            let msg = e.to_string();
            tracing::warn!(
                "Job dispatcher: send job {} refused awaiting_signature advertisement: {}",
                public_id,
                msg
            );
            job_store.fail(public_id, &msg).await?;
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
            notify_map.remove(&public_id);
            return Ok(());
        }
    };
    job_store
        .set_awaiting_signature(public_id, proof_id as i64, result.clone())
        .await?;
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
    // ash/ocr result persisted on the row at the original
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
async fn wait_for_commit(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &JobNotifyMap,
    awaiting_signature_timeout: Duration,
    public_id: Uuid,
    kind: JobKind,
    notifier: Arc<JobNotifier>,
) -> anyhow::Result<()> {
    let outcome = tokio::select! {
        _ = notifier.commit_wake.notified() => SignalOutcome::Signaled,
        _ = tokio::time::sleep(awaiting_signature_timeout) => SignalOutcome::TimedOut,
    };

    match outcome {
        SignalOutcome::TimedOut => {
            tracing::warn!(
                "Job dispatcher: send job {} timed out in awaiting_signature",
                public_id
            );
            job_store
                .fail(public_id, "awaiting_signature timeout")
                .await?;
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
                    error: Some("awaiting_signature timeout".to_string()),
                },
            );
            notify_map.remove(&public_id);
            return Ok(());
        }
        SignalOutcome::Signaled => {}
    }

    let job = match job_store.load(public_id).await? {
        Some(j) => j,
        None => {
            tracing::warn!("Job dispatcher: post-signal load missed job {}", public_id);
            notify_map.remove(&public_id);
            return Ok(());
        }
    };

    // v1.1 path: `/sign` already verified via accept_wallet_transition_signature
    // and persisted the TransitionSignature under `sign`. Stage 3 will own the
    // prove+publish finalise; until then a verified signature is a successful
    // authorisation gate and the job completes with that material.
    if crate::v11::v11_sign_route_active() {
        if let Some(sign_val) = job.request_body.get("sign").cloned() {
            let response_body = serde_json::json!({
                "success": true,
                "signature_accepted": true,
                "sign": sign_val,
            });
            job_store
                .complete(public_id, response_body.clone(), 200)
                .await?;
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
                "Job dispatcher: job {} completed after verified v1.1 /sign",
                public_id
            );
            notify_map.remove(&public_id);
            return Ok(());
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
            job_store.fail(public_id, &msg).await?;
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
            notify_map.remove(&public_id);
            return Ok(());
        }
    };

    job_store
        .set_status(public_id, JobStatus::Broadcasting, "broadcasting")
        .await?;
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
            job_store
                .complete(public_id, response_body.clone(), response_status as i16)
                .await?;
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
            job_store.fail(public_id, &message).await?;
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
    notify_map.remove(&public_id);

    Ok(())
}

enum SignalOutcome {
    Signaled,
    TimedOut,
}
