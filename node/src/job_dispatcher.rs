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

use crate::flow::{commit_flow, mint_commit_flow, FlowError};
use crate::job_store::{Job, JobKind, JobStatus, JobStore};
use crate::router::{AppState, CommitRequest};

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

/// Pure decision for one non-terminal dispatcher envelope.
///
/// Terminal statuses are filtered before this is consulted. The table is
/// exhaustive over `(JobKind, JobStatus)` so a future kind/status cannot
/// silently become `Ok(())`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DispatcherEnvelopeAction {
    ProcessMintQueued,
    ProcessMintAwaitingSignature,
    ProcessSendQueued,
    ProcessSendAwaitingSignature,
    ProcessReceiveQueued,
    ProcessReceiveAwaitingSignature,
    ProcessAttest,
    DriveV1Finalise,
    /// Prove already in flight (re-delivered envelope / concurrent owner).
    SkipConcurrentProving,
    /// Broadcast/finalise already in flight without v1 re-entry.
    SkipConcurrentBroadcasting,
    /// Non-terminal combo that must not hang — terminal fail.
    FailUnexpectedNonTerminal,
}

/// Decision table for [`process_envelope`]. Pure; no I/O.
///
/// `v1_sign_route_active` gates the mint/send/receive broadcasting re-entry
/// that drives durable finalise without re-parking on `/sign`.
pub(crate) fn dispatcher_envelope_action(
    kind: JobKind,
    status: JobStatus,
    v1_sign_route_active: bool,
) -> DispatcherEnvelopeAction {
    use DispatcherEnvelopeAction::*;
    match (kind, status) {
        (JobKind::Mint, JobStatus::Queued) => ProcessMintQueued,
        (JobKind::Mint, JobStatus::AwaitingSignature) => ProcessMintAwaitingSignature,
        (JobKind::Send, JobStatus::Queued) => ProcessSendQueued,
        (JobKind::Send, JobStatus::AwaitingSignature) => ProcessSendAwaitingSignature,
        (JobKind::Receive, JobStatus::Queued) => ProcessReceiveQueued,
        (JobKind::Receive, JobStatus::AwaitingSignature) => ProcessReceiveAwaitingSignature,
        // Gap G6: attest_balance has no awaiting_signature phase (§7.5).
        (JobKind::AttestBalance, JobStatus::Queued | JobStatus::Proving) => ProcessAttest,
        // Mid-finalise crash: durable signed capability + broadcasting.
        (JobKind::Mint | JobKind::Send | JobKind::Receive, JobStatus::Broadcasting)
            if v1_sign_route_active =>
        {
            DriveV1Finalise
        }
        // Re-delivered envelope while prove owns the row — do not re-start.
        (JobKind::Mint | JobKind::Send | JobKind::Receive, JobStatus::Proving) => {
            SkipConcurrentProving
        }
        // Legacy in-process commit continues from AwaitingSignature; an
        // orphaned broadcasting envelope is concurrent mid-commit.
        (JobKind::Mint | JobKind::Send | JobKind::Receive, JobStatus::Broadcasting) => {
            SkipConcurrentBroadcasting
        }
        // Terminal statuses are filtered before this function; named so a
        // caller that forgets the filter still does not invent work.
        (
            JobKind::Mint | JobKind::Send | JobKind::AttestBalance | JobKind::Receive,
            JobStatus::Completed | JobStatus::Failed | JobStatus::Cancelled,
        ) => FailUnexpectedNonTerminal,
        // Attest never enters signature/broadcast; silent skip would hang.
        (JobKind::AttestBalance, JobStatus::AwaitingSignature | JobStatus::Broadcasting) => {
            FailUnexpectedNonTerminal
        }
    }
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

    let action =
        dispatcher_envelope_action(job.kind, job.status, crate::v1::v1_sign_route_active());
    match action {
        DispatcherEnvelopeAction::ProcessMintQueued => {
            process_mint(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        DispatcherEnvelopeAction::ProcessMintAwaitingSignature => {
            process_mint_resume(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        DispatcherEnvelopeAction::ProcessSendQueued => {
            process_send_initial(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        DispatcherEnvelopeAction::ProcessSendAwaitingSignature => {
            process_send_resume(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        DispatcherEnvelopeAction::ProcessReceiveQueued => {
            process_receive_initial(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        DispatcherEnvelopeAction::ProcessReceiveAwaitingSignature => {
            process_receive_resume(
                job_store,
                app_state,
                notify_map,
                awaiting_signature_timeout,
                job,
            )
            .await
        }
        DispatcherEnvelopeAction::ProcessAttest => {
            process_attest_balance(job_store, app_state, notify_map, job).await
        }
        DispatcherEnvelopeAction::DriveV1Finalise => {
            drive_v1_finalise(job_store, app_state, notify_map, env.public_id, &job).await
        }
        DispatcherEnvelopeAction::SkipConcurrentProving => {
            // Named intentional skip: prove CAS already advanced the row.
            tracing::debug!(
                "Job dispatcher: envelope for {} kind={} status=proving \
                 (concurrent mid-flight prove); skipping without re-start",
                env.public_id,
                job.kind.as_str()
            );
            Ok(())
        }
        DispatcherEnvelopeAction::SkipConcurrentBroadcasting => {
            // Named intentional skip: broadcast/commit owns the row
            // in-process (legacy) or another resumer holds finalise.
            tracing::debug!(
                "Job dispatcher: envelope for {} kind={} status=broadcasting \
                 (concurrent mid-flight broadcast; v1 finalise re-entry inactive); \
                 skipping",
                env.public_id,
                job.kind.as_str()
            );
            Ok(())
        }
        DispatcherEnvelopeAction::FailUnexpectedNonTerminal => {
            fail_unexpected_non_terminal_envelope(job_store, notify_map, job).await
        }
    }
}

/// Terminal-fail a non-terminal `(kind, status)` that has no named skip.
async fn fail_unexpected_non_terminal_envelope(
    job_store: &JobStore,
    notify_map: &JobNotifyMap,
    job: Job,
) -> anyhow::Result<()> {
    let public_id = job.public_id;
    let from = job.status;
    let msg = crate::v1::encode_job_error(
        "internal_error",
        format!(
            "Job dispatcher: unexpected non-terminal state kind={} status={:?}; \
             refusing silent skip (would leave job hung)",
            job.kind.as_str(),
            from
        ),
    );
    tracing::error!(
        "Job dispatcher: job {} unexpected non-terminal kind={} status={:?}; failing",
        public_id,
        job.kind.as_str(),
        from
    );
    if !job_store.fail(public_id, from, &msg).await? {
        tracing::warn!(
            "Job dispatcher: job {} fail({:?}→failed) for unexpected state matched 0 rows; \
             not publishing failed event",
            public_id,
            from
        );
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
    notify_map.remove(&public_id);
    Ok(())
}

/// Drive an `attest_balance` job: `proving → completed` with
/// `result.attestation`, or `failed`. No wallet signature phase.
///
/// EDGE: see [`crate::v1::ATTEST_ANCHOR_LOCATOR_EDGE`] when the Bitcoin
/// inscription locator cannot be resolved from engine + pending-publish
/// state. A failed prove never invents an empty attestation.
async fn process_attest_balance(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &JobNotifyMap,
    job: Job,
) -> anyhow::Result<()> {
    let public_id = job.public_id;
    // Allowed transition: queued → proving. Miss = someone else advanced.
    if !job_store
        .set_status(public_id, JobStatus::Queued, JobStatus::Proving, "proving")
        .await?
    {
        tracing::warn!(
            "Job dispatcher: attest job {} set_status(queued→proving) matched 0 rows; \
             aborting without event",
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

    let body: crate::v1::AttestJobBody = match serde_json::from_value(job.request_body.clone()) {
        Ok(b) => b,
        Err(e) => {
            let msg = crate::v1::encode_job_error(
                "proving_failed",
                format!("invalid attest job body: {e}"),
            );
            // Allowed: proving → failed. Miss: no failed event.
            if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
                tracing::warn!(
                    "Job dispatcher: attest job {} fail(proving) matched 0 rows; \
                     not publishing failed event",
                    public_id
                );
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

    let adapter = match &app_state.v1_engine {
        Some(a) => a,
        None => {
            let msg = crate::v1::encode_job_error(
                "internal_error",
                "v1 EngineAdapter missing for attest_balance job",
            );
            if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
                tracing::warn!(
                    "Job dispatcher: attest job {} fail(proving) matched 0 rows; \
                     not publishing failed event",
                    public_id
                );
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

    // prove_attestation_for_job is async (DB locator lookup) and internally
    // runs the multi-minute C_balance prove on the caller's thread. The
    // single-worker dispatcher already serialises proves, so we await it
    // directly rather than nesting a second runtime.
    let outcome = crate::v1::prove_attestation_for_job(adapter.as_ref(), &body).await;

    match outcome {
        Ok(proved) => {
            note_prove_outcome(app_state, Ok(())).await;
            let bytes = match crate::v1::serialize_balance_attestation(
                &proved.statement,
                adapter.network(),
                &proved.proof,
            ) {
                Ok(b) => b,
                Err(e) => {
                    let msg = crate::v1::encode_job_error("proving_failed", e.message());
                    if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
                        tracing::warn!(
                            "Job dispatcher: attest job {} fail(proving) matched 0 rows; \
                             not publishing failed event",
                            public_id
                        );
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
            // §7.5 result for attest_balance: only `attestation` is present.
            // Allowed: proving → completed.
            let result = crate::v1::completed_attest_result(&bytes);
            if !job_store
                .complete(public_id, JobStatus::Proving, result.clone(), 200)
                .await?
            {
                tracing::warn!(
                    "Job dispatcher: attest job {} complete(proving) matched 0 rows; \
                     not publishing completed event",
                    public_id
                );
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
                    result: Some(result),
                    error: None,
                },
            );
            tracing::info!("Job dispatcher: attest_balance job {} completed", public_id);
            Ok(())
        }
        Err(e) => {
            let (code, message) = match &e {
                crate::v1::AttestError::CircuitDigestMismatch(m) => {
                    ("circuit_digest_mismatch", m.clone())
                }
                crate::v1::AttestError::ProvingFailed(m) => ("proving_failed", m.clone()),
                crate::v1::AttestError::Internal(m) => ("internal_error", m.clone()),
                other => ("proving_failed", other.message().to_string()),
            };
            note_prove_outcome(app_state, Err("prove failed")).await;
            let msg = crate::v1::encode_job_error(code, message);
            if let Ok(Some(j)) = job_store.load(public_id).await {
                if j.status == JobStatus::Cancelled {
                    notify_map.remove(&public_id);
                    return Ok(());
                }
            }
            if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
                tracing::warn!(
                    "Job dispatcher: attest job {} fail(proving) matched 0 rows; \
                     not publishing failed event",
                    public_id
                );
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
    // Allowed: queued → proving. Miss = concurrent advance / fence — stop.
    if !job_store
        .set_status(public_id, JobStatus::Queued, JobStatus::Proving, "proving")
        .await?
    {
        // Zero rows: wrong status, claim phase, generation fence — do not prove
        // against wiped / foreign state (no silent fallback).
        tracing::warn!(
            "Job dispatcher: mint job {} set_status(queued→proving) matched 0 rows; aborting",
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

    let (
        subject,
        next_pubkey,
        npk_rand,
        issuance_name,
        decimals,
        amount,
        issuance_version,
        cap_total,
        terms_salt,
        creator_pubkey,
        output_templates_raw,
    ) = match parse_mint_job_body(&job.request_body) {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("invalid mint request body: {e}");
            // Allowed: proving → failed.
            if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
                tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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

    let (nk, op_secret, current_pubkey) =
        match resolve_mint_auth_keys(app_state, &subject, creator_pubkey) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("invalid mint request body: {e}");
                if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
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

    let adapter = match &app_state.v1_engine {
        Some(a) => a,
        None => {
            let msg = "v1 EngineAdapter missing for mint job".to_string();
            if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
                tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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

    let output_templates: Result<Vec<_>, String> = output_templates_raw
        .into_iter()
        .enumerate()
        .map(|(i, (recipient, asset_id_bytes, amount))| {
            let asset_id = shared::spec_v1::encoding::digest_from_bytes(&asset_id_bytes)
                .map_err(|e| format!("output_templates[{i}].asset_id: digest_from_bytes: {e}"))?;
            Ok(shared::spec_v1::CoinTemplate {
                recipient: shared::spec_v1::Address(recipient),
                amount,
                asset_id,
            })
        })
        .collect();
    let output_templates = match output_templates {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("invalid mint request body: {e}");
            if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
                tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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

    let mint_name_bytes = issuance_name.clone().into_bytes();
    let mint_req = zkcoins_prover::state_engine::MintRequest {
        owner: shared::spec_v1::Address(subject.0),
        nk,
        op_secret,
        current_pubkey,
        next_pubkey,
        name: issuance_name.into_bytes(),
        decimals,
        amount,
        issuance_version,
        cap_total,
        terms_salt,
        output_templates,
        npk_rand,
    };

    let begin_result = adapter.with_engine(|engine| crate::v1::begin_v1_mint(engine, mint_req));
    let pending = match begin_result {
        Ok(p) => {
            note_prove_outcome(app_state, Ok(())).await;
            p
        }
        Err(e) => {
            tracing::warn!(
                "Job dispatcher: mint job {} prove leg failed: {:#}",
                public_id,
                e
            );
            note_prove_outcome(app_state, Err("prove failed")).await;
            // Cancel may have won while proving; do not overwrite cancelled.
            if let Ok(Some(j)) = job_store.load(public_id).await {
                if j.status == JobStatus::Cancelled {
                    cleanup_pending_sign(job_store, app_state, public_id).await;
                    notify_map.remove(&public_id);
                    return Ok(());
                }
            }
            let message = fail_error_string(&format!("begin_v1_mint: {e:#}"));
            // Allowed: proving → failed.
            if !job_store
                .fail(public_id, JobStatus::Proving, &message)
                .await?
            {
                tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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

    let mint_terms_stage = async {
        let ai = pending
            .witness_wip
            .asset_issuance
            .as_ref()
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "begin_v1_mint returned a transition without asset_issuance witness"
                )
            })?;
        let issuance_terms = shared::spec_v1::bundle::IssuanceTerms {
            creator_pubkey: ai.creator_pubkey,
            decimals: ai.decimals,
            issuance_version: ai.issuance_version,
            name: mint_name_bytes,
            cap_total: (ai.issuance_version == 2).then_some(ai.cap_total),
            terms_salt: (ai.issuance_version == 2).then_some(ai.terms_salt),
        };
        crate::v1::db_mint_terms_staging::stage_mint_issuance_terms(
            adapter.pool(),
            public_id,
            &issuance_terms,
        )
        .await
        .map_err(|e| anyhow::anyhow!("stage mint IssuanceTerms: {e:#}"))?;
        Ok::<(), anyhow::Error>(())
    }
    .await;
    if let Err(e) = mint_terms_stage {
        tracing::warn!(
            "Job dispatcher: mint job {} IssuanceTerms staging failed: {:#}",
            public_id,
            e
        );
        // Cancel may have won while staging; do not overwrite cancelled.
        if let Ok(Some(j)) = job_store.load(public_id).await {
            if j.status == JobStatus::Cancelled {
                cleanup_pending_sign(job_store, app_state, public_id).await;
                notify_map.remove(&public_id);
                return Ok(());
            }
        }
        let message = fail_error_string(&format!("mint IssuanceTerms staging: {e:#}"));
        // Allowed: proving → failed.
        if !job_store
            .fail(public_id, JobStatus::Proving, &message)
            .await?
        {
            tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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

    // Cancel may have won during the prove leg.
    if let Ok(Some(j)) = job_store.load(public_id).await {
        if j.status == JobStatus::Cancelled {
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
    }

    // Register live pending for stage_and_select_awaiting_signature (same
    // receive handshake). Network from the exclusive engine.
    let network = adapter.network();
    let entry = crate::v1::PendingSignEntry::new(pending, network);
    crate::v1::register_live_pending_after_begin(
        &app_state.v1_live_pending_after_begin,
        public_id,
        entry,
    );

    let notifier = notify_map
        .entry(public_id)
        .or_insert_with(|| Arc::new(JobNotifier::new()))
        .clone();

    // Production staging site: under v1.1 a live PendingTransition must be
    // staged via stage_pending_sign before the job advertises. Source is the
    // post-begin registry (begin_* → register_live_pending_after_begin) or
    // the optional test hook.
    let live_pending = resolve_live_pending_after_prove(app_state, public_id);
    // Mint has no legacy ash/ocr surface — empty placeholders; under v1
    // the staged PendingSignEntry supplies the §7.5 ProofData advertisement.
    let result = match stage_and_select_awaiting_signature(
        job_store,
        app_state,
        public_id,
        "",
        "",
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
            // Allowed: proving → failed (still on prove path).
            if !job_store.fail(public_id, JobStatus::Proving, &err).await? {
                tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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
    // no file ProofStore id — use 0 as the sentinel already used for
    // staged-only transitions
    let proof_id: i64 = 0;
    match job_store
        .set_awaiting_signature(public_id, proof_id, result.clone())
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
            proof_id: Some(proof_id),
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
    entry: &crate::v1::PendingSignEntry,
) -> anyhow::Result<()> {
    let job = job_store
        .load(public_id)
        .await?
        .ok_or_else(|| anyhow::anyhow!("job {public_id} missing while staging finalisation"))?;
    let mut body = job.request_body;
    let persist = crate::v1::DurableFinalisationPersist::from_entry(entry)
        .map_err(|e| anyhow::anyhow!("encode durable finalisation: {e}"))?;
    let value = serde_json::to_value(persist)?;
    let obj = body
        .as_object_mut()
        .ok_or_else(|| anyhow::anyhow!("jobs.request_body is not an object"))?;
    obj.insert(crate::v1::FINALISATION_BODY_KEY.to_string(), value);
    // Drop legacy split keys if a previous build left them.
    obj.remove(crate::v1::PENDING_SIGN_BODY_KEY);
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
/// registered via [`crate::v1::register_live_pending_after_begin`] into
/// [`crate::router::AppState::v1_live_pending_after_begin`]. The pending is
/// self-contained (witness + ProofData); finalise re-validates live
/// dependencies rather than re-reading a snapshot a concurrent scan can move.
///
/// Under `cfg(test)` an optional fixture hook may also supply an entry.
/// Missing the production registry fails closed at
/// [`stage_and_select_awaiting_signature`] (no silent ash‖ocr).
fn resolve_live_pending_after_prove(
    app_state: &AppState,
    public_id: Uuid,
) -> Option<crate::v1::PendingSignEntry> {
    if !crate::v1::v1_sign_route_active() {
        return None;
    }
    if let Some(entry) =
        crate::v1::take_live_pending_after_begin(&app_state.v1_live_pending_after_begin, public_id)
    {
        return Some(entry);
    }
    #[cfg(test)]
    {
        if let Some(entry) = app_state
            .v1_pending_after_prove
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
) -> Option<crate::v1::PendingSignEntry> {
    resolve_live_pending_after_prove(app_state, public_id)
}

/// Production staging site for a job entering `awaiting_signature`.
///
/// Under a v1.1 claim this is the **only** path that writes
/// `pending_sign_map` for a live job: it calls [`crate::v1::stage_pending_sign`],
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
    pending: Option<crate::v1::PendingSignEntry>,
) -> Result<serde_json::Value, String> {
    let staged_ref = if let Some(mut entry) = pending {
        // Capture caller-supplied publisher_pubkey from the job row so the
        // durable capability carries everything job completion needs.
        if let Ok(Some(job)) = job_store.load(public_id).await {
            match crate::v1::publisher_pubkey_from_request_body(&job.request_body) {
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
            crate::v1::stage_pending_sign(&app_state.pending_sign_map, public_id, entry);
        let Some(guard) = app_state.pending_sign_map.get(&public_id) else {
            return Err(
                "stage_pending_sign did not leave a map entry (internal lifecycle bug)".to_string(),
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

    match crate::v1::select_awaiting_signature_result(legacy_ash, legacy_ocr, staged_ref.as_ref()) {
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
    if crate::v1::v1_sign_route_active() {
        crate::v1::encode_job_error("proving_failed", message)
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
async fn cleanup_pending_sign(job_store: &JobStore, app_state: &AppState, public_id: Uuid) {
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
    if !crate::v1::strip_pending_sign_from_body(&mut body) {
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
    match crate::v1::rehydrate_pending_sign(&job.request_body) {
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
            if crate::v1::v1_sign_route_active() {
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
    // Allowed: queued → proving. Miss = concurrent advance / fence — stop.
    if !job_store
        .set_status(public_id, JobStatus::Queued, JobStatus::Proving, "proving")
        .await?
    {
        tracing::warn!(
            "Job dispatcher: send job {} set_status(queued→proving) matched 0 rows; aborting",
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

    let (subject, next_pubkey, npk_rand, input_coins, output_templates_raw) =
        match parse_send_job_body(&job.request_body) {
            Ok(v) => v,
            Err(e) => {
                let msg = format!("invalid send request body: {e}");
                // Allowed: proving → failed.
                if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
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

    // Account must already exist (no genesis send). Engine reads nk/op_secret
    // from the stored record — SendRequest carries neither.
    if let Err(e) = resolve_send_auth_keys(app_state, &subject) {
        let msg = format!("invalid send request body: {e}");
        if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
            tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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

    let adapter = match &app_state.v1_engine {
        Some(a) => a,
        None => {
            let msg = "v1 EngineAdapter missing for send job".to_string();
            if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
                tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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

    let input_coin_ids: Result<Vec<_>, String> = input_coins
        .iter()
        .enumerate()
        .map(|(i, bytes)| {
            shared::spec_v1::encoding::digest_from_bytes(bytes)
                .map_err(|e| format!("input_coins[{i}]: digest_from_bytes: {e}"))
        })
        .collect();
    let input_coin_ids = match input_coin_ids {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("invalid send request body: {e}");
            if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
                tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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

    let output_templates: Result<Vec<_>, String> = output_templates_raw
        .into_iter()
        .enumerate()
        .map(|(i, (recipient, asset_id_bytes, amount))| {
            let asset_id = shared::spec_v1::encoding::digest_from_bytes(&asset_id_bytes)
                .map_err(|e| format!("output_templates[{i}].asset_id: digest_from_bytes: {e}"))?;
            Ok(shared::spec_v1::CoinTemplate {
                recipient: shared::spec_v1::Address(recipient),
                amount,
                asset_id,
            })
        })
        .collect();
    let output_templates = match output_templates {
        Ok(v) => v,
        Err(e) => {
            let msg = format!("invalid send request body: {e}");
            if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
                tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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

    let send_req = zkcoins_prover::state_engine::SendRequest {
        owner: shared::spec_v1::Address(subject.0),
        input_coin_ids,
        output_templates,
        next_pubkey,
        npk_rand,
    };

    let begin_result = adapter.with_engine(|engine| crate::v1::begin_v1_send(engine, send_req));
    let pending = match begin_result {
        Ok(p) => {
            // The prove leg succeeded (the job reaches awaiting_signature).
            note_prove_outcome(app_state, Ok(())).await;
            p
        }
        Err(e) => {
            tracing::warn!(
                "Job dispatcher: send job {} prove leg failed: {:#}",
                public_id,
                e
            );
            note_prove_outcome(app_state, Err("prove failed")).await;
            if let Ok(Some(j)) = job_store.load(public_id).await {
                if j.status == JobStatus::Cancelled {
                    cleanup_pending_sign(job_store, app_state, public_id).await;
                    notify_map.remove(&public_id);
                    return Ok(());
                }
            }
            let message = fail_error_string(&format!("begin_v1_send: {e:#}"));
            // Allowed: proving → failed.
            if !job_store
                .fail(public_id, JobStatus::Proving, &message)
                .await?
            {
                tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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

    // Register live pending for stage_and_select_awaiting_signature.
    let network = adapter.network();
    let entry = crate::v1::PendingSignEntry::new(pending, network);
    crate::v1::register_live_pending_after_begin(
        &app_state.v1_live_pending_after_begin,
        public_id,
        entry,
    );

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
    // that signed ash/ocr would be rejected at `/sign`. Staging goes through
    // stage_pending_sign (the only production writer of pending_sign_map).
    let live_pending = resolve_live_pending_after_prove(app_state, public_id);
    // Send has no legacy ash/ocr surface — empty placeholders; under v1
    // the staged PendingSignEntry supplies the §7.5 ProofData advertisement.
    let result = match stage_and_select_awaiting_signature(
        job_store,
        app_state,
        public_id,
        "",
        "",
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
            // Allowed: proving → failed.
            if !job_store.fail(public_id, JobStatus::Proving, &err).await? {
                tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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
    // no file ProofStore id — use 0 as the sentinel already used for
    // staged-only transitions
    let proof_id: i64 = 0;
    match job_store
        .set_awaiting_signature(public_id, proof_id, result.clone())
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
            proof_id: Some(proof_id),
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

// ---------------------------------------------------------------------------
// Mint / Send (§2.3.1 / §2.3.2) — parse normative job body + auth resolution
// ---------------------------------------------------------------------------

/// Parsed mint job body from `encode_normative_request_body` / `encode_issuance`.
///
/// `(subject, next_pubkey, npk_rand, name, decimals, amount, issuance_version,
///  cap_total, terms_salt, creator_pubkey, output_templates)` where each output
/// template is `(recipient_raw32, asset_id_raw32, amount)`.
type ParsedMintJobBody = (
    crate::kernel::types::SubjectAddress,
    [u8; 32],
    [u8; 32],
    String,
    u8,
    u128,
    u8,
    u128,
    [u8; 32],
    [u8; 32],
    Vec<([u8; 32], [u8; 32], u128)>,
);

/// Auth material for mint begin: nk, op_secret, current_pubkey.
type MintAuthKeys = ([u8; 32], zkcoins_prover::state_engine::OpSecret, [u8; 32]);

/// Parsed send job body from `encode_normative_request_body`.
///
/// `(subject, next_pubkey, npk_rand, input_coins, output_templates)` where each
/// output template is `(recipient_raw32, asset_id_raw32, amount)`.
type ParsedSendJobBody = (
    crate::kernel::types::SubjectAddress,
    [u8; 32],
    [u8; 32],
    Vec<[u8; 32]>,
    Vec<([u8; 32], [u8; 32], u128)>,
);

fn parse_u128_decimal_field(s: &str, field: &str) -> Result<u128, String> {
    s.parse::<u128>().map_err(|e| format!("{field}: {e}"))
}

/// Parse the normative mint job body that [`crate::kernel::jobs::submit`] encodes.
fn parse_mint_job_body(body: &serde_json::Value) -> Result<ParsedMintJobBody, String> {
    let obj = body
        .as_object()
        .ok_or_else(|| "mint job body is not a JSON object".to_string())?;
    let subject_hex = obj
        .get("subject")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "mint job body missing subject".to_string())?;
    let next_hex = obj
        .get("next_pubkey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "mint job body missing next_pubkey".to_string())?;
    let npk_hex = obj
        .get("npk_rand")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "mint job body missing npk_rand".to_string())?;
    let iss = obj
        .get("issuance")
        .and_then(|v| v.as_object())
        .ok_or_else(|| "mint job body missing issuance object".to_string())?;
    let out_arr = obj
        .get("output_templates")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "mint job body missing output_templates".to_string())?;

    let subject = parse_hex32_field(subject_hex, "subject")?;
    let next_pubkey = parse_hex32_field(next_hex, "next_pubkey")?;
    let npk_rand = parse_hex32_field(npk_hex, "npk_rand")?;

    let mut output_templates = Vec::with_capacity(out_arr.len());
    for (i, v) in out_arr.iter().enumerate() {
        let t = v
            .as_object()
            .ok_or_else(|| format!("output_templates[{i}] is not an object"))?;
        // encode_output_templates hex-encodes the raw 32-byte address (not Bech32m).
        let recipient_hex = t
            .get("recipient")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("output_templates[{i}].recipient missing"))?;
        let asset_hex = t
            .get("asset_id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("output_templates[{i}].asset_id missing"))?;
        let amount_str = t
            .get("amount")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("output_templates[{i}].amount missing"))?;
        // has_delivery is admission-only; prove leg ignores it.
        let recipient =
            parse_hex32_field(recipient_hex, &format!("output_templates[{i}].recipient"))?;
        let asset_id = parse_hex32_field(asset_hex, &format!("output_templates[{i}].asset_id"))?;
        let amount =
            parse_u128_decimal_field(amount_str, &format!("output_templates[{i}].amount"))?;
        output_templates.push((recipient, asset_id, amount));
    }

    let name = iss
        .get("name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "issuance.name missing".to_string())?
        .to_string();
    let decimals_u64 = iss
        .get("decimals")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "issuance.decimals missing or not a number".to_string())?;
    let decimals = u8::try_from(decimals_u64)
        .map_err(|_| format!("issuance.decimals must fit u8; got {decimals_u64}"))?;
    let amount_str = iss
        .get("amount")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "issuance.amount missing".to_string())?;
    let amount = parse_u128_decimal_field(amount_str, "issuance.amount")?;
    let version_u64 = iss
        .get("issuance_version")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| "issuance.issuance_version missing or not a number".to_string())?;
    let issuance_version = u8::try_from(version_u64)
        .map_err(|_| format!("issuance.issuance_version must fit u8; got {version_u64}"))?;
    if issuance_version != 1 && issuance_version != 2 {
        return Err(format!(
            "issuance.issuance_version must be 1 or 2; got {issuance_version}"
        ));
    }
    let creator_hex = iss
        .get("creator_pubkey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "issuance.creator_pubkey missing".to_string())?;
    let creator_pubkey = parse_hex32_field(creator_hex, "issuance.creator_pubkey")?;

    let (cap_total, terms_salt) = if issuance_version == 2 {
        let cap_str = iss
            .get("cap_total")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "issuance.cap_total required when issuance_version=2".to_string())?;
        let cap = parse_u128_decimal_field(cap_str, "issuance.cap_total")?;
        let salt_hex = iss
            .get("terms_salt")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "issuance.terms_salt required when issuance_version=2".to_string())?;
        let salt = parse_hex32_field(salt_hex, "issuance.terms_salt")?;
        (cap, salt)
    } else {
        // Standard-1: engine requires cap_total=0 and all-zero terms_salt.
        (0u128, [0u8; 32])
    };

    Ok((
        crate::kernel::types::SubjectAddress(subject),
        next_pubkey,
        npk_rand,
        name,
        decimals,
        amount,
        issuance_version,
        cap_total,
        terms_salt,
        creator_pubkey,
        output_templates,
    ))
}

/// Resolve `nk` / `op_secret` / `current_pubkey` for a mint begin.
///
/// - Registered engine account (remint) → live rotated `current_pubkey`.
/// - No account yet (genesis) → `creator_pubkey` (= Pk₀ from issuance).
fn resolve_mint_auth_keys(
    app_state: &AppState,
    subject: &crate::kernel::types::SubjectAddress,
    creator_pubkey: [u8; 32],
) -> Result<MintAuthKeys, String> {
    let bundle = app_state.bundles.get_active(subject).ok_or_else(|| {
        format!(
            "mint: no active operational bundle for subject {} (§7.7)",
            hex::encode(subject.0)
        )
    })?;
    let op_secret = zkcoins_prover::state_engine::OpSecret::new(bundle.op_secret);
    let owner = shared::spec_v1::Address(subject.0);

    let adapter = app_state
        .v1_engine
        .as_ref()
        .ok_or_else(|| "mint: v1 EngineAdapter missing".to_string())?;

    adapter.with_engine(|engine| {
        if let Some(rec) = engine.account(&owner) {
            // REMINT: wire current_pubkey is the live rotated key, not genesis.
            if rec.nk != bundle.nk {
                return Err(
                    "mint: operational-bundle nk does not match registered account nk".into(),
                );
            }
            if let Some(stored) = rec.op_secret {
                if stored != op_secret {
                    return Err(
                        "mint: operational-bundle op_secret does not match registered account"
                            .into(),
                    );
                }
            }
            return Ok((rec.nk, op_secret, rec.state.current_pubkey));
        }
        // GENESIS: engine verifies owner == H(creator_pubkey ‖ nk_commit)
        // inside begin_mint (state_engine.rs); a wrong value fails closed there.
        Ok((bundle.nk, op_secret, creator_pubkey))
    })
}

/// Parse the normative send job body that [`crate::kernel::jobs::submit`] encodes.
fn parse_send_job_body(body: &serde_json::Value) -> Result<ParsedSendJobBody, String> {
    let obj = body
        .as_object()
        .ok_or_else(|| "send job body is not a JSON object".to_string())?;
    let subject_hex = obj
        .get("subject")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "send job body missing subject".to_string())?;
    let next_hex = obj
        .get("next_pubkey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "send job body missing next_pubkey".to_string())?;
    let npk_hex = obj
        .get("npk_rand")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "send job body missing npk_rand".to_string())?;
    let input_arr = obj
        .get("input_coins")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "send job body missing input_coins".to_string())?;
    let out_arr = obj
        .get("output_templates")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "send job body missing output_templates".to_string())?;

    let subject = parse_hex32_field(subject_hex, "subject")?;
    let next_pubkey = parse_hex32_field(next_hex, "next_pubkey")?;
    let npk_rand = parse_hex32_field(npk_hex, "npk_rand")?;

    let mut input_coins = Vec::with_capacity(input_arr.len());
    for (i, v) in input_arr.iter().enumerate() {
        let h = v
            .as_str()
            .ok_or_else(|| format!("input_coins[{i}] is not a hex string"))?;
        input_coins.push(parse_hex32_field(h, &format!("input_coins[{i}]"))?);
    }

    let mut output_templates = Vec::with_capacity(out_arr.len());
    for (i, v) in out_arr.iter().enumerate() {
        let t = v
            .as_object()
            .ok_or_else(|| format!("output_templates[{i}] is not an object"))?;
        // encode_output_templates hex-encodes the raw 32-byte address (not Bech32m).
        let recipient_hex = t
            .get("recipient")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("output_templates[{i}].recipient missing"))?;
        let asset_hex = t
            .get("asset_id")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("output_templates[{i}].asset_id missing"))?;
        let amount_str = t
            .get("amount")
            .and_then(|x| x.as_str())
            .ok_or_else(|| format!("output_templates[{i}].amount missing"))?;
        // has_delivery is admission-only; prove leg ignores it.
        let recipient =
            parse_hex32_field(recipient_hex, &format!("output_templates[{i}].recipient"))?;
        let asset_id = parse_hex32_field(asset_hex, &format!("output_templates[{i}].asset_id"))?;
        let amount =
            parse_u128_decimal_field(amount_str, &format!("output_templates[{i}].amount"))?;
        output_templates.push((recipient, asset_id, amount));
    }

    Ok((
        crate::kernel::types::SubjectAddress(subject),
        next_pubkey,
        npk_rand,
        input_coins,
        output_templates,
    ))
}

/// Resolve that a send subject has an active operational bundle and a
/// registered engine account whose nk/op_secret match the bundle.
///
/// Returns the live `current_pubkey` (not placed on `SendRequest` — the engine
/// reads nk/op_secret/current_pubkey from its own store). Fail-closed when the
/// subject has no active bundle or no engine account (no genesis send).
fn resolve_send_auth_keys(
    app_state: &AppState,
    subject: &crate::kernel::types::SubjectAddress,
) -> Result<[u8; 32], String> {
    let bundle = app_state.bundles.get_active(subject).ok_or_else(|| {
        format!(
            "send: no active operational bundle for subject {} (§7.7)",
            hex::encode(subject.0)
        )
    })?;
    let op_secret = zkcoins_prover::state_engine::OpSecret::new(bundle.op_secret);
    let owner = shared::spec_v1::Address(subject.0);

    let adapter = app_state
        .v1_engine
        .as_ref()
        .ok_or_else(|| "send: v1 EngineAdapter missing".to_string())?;

    adapter.with_engine(|engine| {
        let rec = engine.account(&owner).ok_or_else(|| {
            format!(
                "send: no registered account for subject {} — cannot send without a prior mint or receive",
                hex::encode(subject.0)
            )
        })?;
        if rec.nk != bundle.nk {
            return Err(
                "send: operational-bundle nk does not match registered account nk".into(),
            );
        }
        if let Some(stored) = rec.op_secret {
            if stored != op_secret {
                return Err(
                    "send: operational-bundle op_secret does not match registered account".into(),
                );
            }
        }
        Ok(rec.state.current_pubkey)
    })
}

// ---------------------------------------------------------------------------
// Receive (§2.3.3 / D11) — reconstitute slots → begin → awaiting_signature
// ---------------------------------------------------------------------------

/// Parsed receive job body: subject, next_pubkey, npk_rand, fold_coin_ids,
/// optional genesis_pubkey.
type ParsedReceiveJobBody = (
    crate::kernel::types::SubjectAddress,
    [u8; 32],
    [u8; 32],
    Vec<[u8; 32]>,
    Option<[u8; 32]>,
);

/// Auth material for receive begin: nk, op_secret, current_pubkey.
type ReceiveAuthKeys = ([u8; 32], zkcoins_prover::state_engine::OpSecret, [u8; 32]);

/// Parse the normative receive job body (`subject`, `next_pubkey`,
/// `npk_rand`, `fold_coin_ids`, optional `genesis_pubkey`) that
/// [`crate::kernel::jobs::submit`] encodes.
fn parse_receive_job_body(body: &serde_json::Value) -> Result<ParsedReceiveJobBody, String> {
    let obj = body
        .as_object()
        .ok_or_else(|| "receive job body is not a JSON object".to_string())?;
    let subject_hex = obj
        .get("subject")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "receive job body missing subject".to_string())?;
    let next_hex = obj
        .get("next_pubkey")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "receive job body missing next_pubkey".to_string())?;
    let npk_hex = obj
        .get("npk_rand")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "receive job body missing npk_rand".to_string())?;
    let fold_arr = obj
        .get("fold_coin_ids")
        .and_then(|v| v.as_array())
        .ok_or_else(|| "receive job body missing fold_coin_ids".to_string())?;

    let subject = parse_hex32_field(subject_hex, "subject")?;
    let next_pubkey = parse_hex32_field(next_hex, "next_pubkey")?;
    let npk_rand = parse_hex32_field(npk_hex, "npk_rand")?;
    let mut fold_coin_ids = Vec::with_capacity(fold_arr.len());
    for (i, v) in fold_arr.iter().enumerate() {
        let h = v
            .as_str()
            .ok_or_else(|| format!("fold_coin_ids[{i}] is not a hex string"))?;
        fold_coin_ids.push(parse_hex32_field(h, &format!("fold_coin_ids[{i}]"))?);
    }
    let genesis_pubkey = match obj.get("genesis_pubkey") {
        Some(v) => {
            let h = v
                .as_str()
                .ok_or_else(|| "genesis_pubkey is not a hex string".to_string())?;
            Some(parse_hex32_field(h, "genesis_pubkey")?)
        }
        None => None,
    };
    Ok((
        crate::kernel::types::SubjectAddress(subject),
        next_pubkey,
        npk_rand,
        fold_coin_ids,
        genesis_pubkey,
    ))
}

fn parse_hex32_field(hex_str: &str, field: &str) -> Result<[u8; 32], String> {
    if hex_str.len() != 64 {
        return Err(format!(
            "{field} must be 64 hex chars, got {}",
            hex_str.len()
        ));
    }
    let bytes = hex::decode(hex_str).map_err(|e| format!("{field} hex decode: {e}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{field} must decode to 32 bytes"))?;
    Ok(arr)
}

/// Resolve `nk` / `op_secret` / `current_pubkey` for a receive begin.
///
/// - Registered engine account → live rotated `current_pubkey`;
///   `genesis_pubkey` MUST be absent (§7.5 presence rule) — refused if present.
/// - Fresh account (InitialProof, no engine record yet) → the client-supplied
///   `genesis_pubkey` (required). The engine's own `begin_receive` (in
///   `script-plonky2/src/state_engine.rs`) independently re-checks
///   `owner == H(current_pubkey ‖ nk_commit)` and fails closed on mismatch —
///   this function does not duplicate that cryptographic check, it only
///   resolves which value to hand the engine. Matches how
///   `resolve_mint_auth_keys` uses `creator_pubkey`.
fn resolve_receive_auth_keys(
    app_state: &AppState,
    subject: &crate::kernel::types::SubjectAddress,
    genesis_pubkey: Option<[u8; 32]>,
) -> Result<ReceiveAuthKeys, String> {
    let bundle = app_state.bundles.get_active(subject).ok_or_else(|| {
        format!(
            "receive: no active operational bundle for subject {} (§7.7)",
            hex::encode(subject.0)
        )
    })?;
    let op_secret = zkcoins_prover::state_engine::OpSecret::new(bundle.op_secret);
    let owner = shared::spec_v1::Address(subject.0);

    let adapter = app_state
        .v1_engine
        .as_ref()
        .ok_or_else(|| "receive: v1 EngineAdapter missing".to_string())?;

    adapter.with_engine(|engine| {
        if let Some(rec) = engine.account(&owner) {
            if rec.nk != bundle.nk {
                return Err(
                    "receive: operational-bundle nk does not match registered account nk".into(),
                );
            }
            if let Some(stored) = rec.op_secret {
                if stored != op_secret {
                    return Err(
                        "receive: operational-bundle op_secret does not match registered account"
                            .into(),
                    );
                }
            }
            if genesis_pubkey.is_some() {
                return Err(
                    "receive: genesis_pubkey must be absent for a registered (non-genesis) account (§7.5)"
                        .into(),
                );
            }
            return Ok((rec.nk, op_secret, rec.state.current_pubkey));
        }
        // GENESIS: engine verifies owner == H(genesis_pubkey ‖ nk_commit)
        // inside begin_receive (state_engine.rs); a wrong value fails closed there.
        match genesis_pubkey {
            Some(pk) => Ok((bundle.nk, op_secret, pk)),
            None => Err(
                "receive: genesis_pubkey required for InitialProof (account's first transition) (§7.5)"
                    .into(),
            ),
        }
    })
}

/// Host begin of a receive job: reconstitute clause-10 slots →
/// [`crate::v1::verify_and_begin_receive`] → stage live pending for
/// `awaiting_signature`. Same handshake as mint/send (§7.5).
async fn process_receive_initial(
    job_store: &JobStore,
    app_state: &AppState,
    notify_map: &JobNotifyMap,
    awaiting_signature_timeout: Duration,
    job: Job,
) -> anyhow::Result<()> {
    let public_id = job.public_id;
    if !job_store
        .set_status(public_id, JobStatus::Queued, JobStatus::Proving, "proving")
        .await?
    {
        tracing::warn!(
            "Job dispatcher: receive job {} set_status(queued→proving) matched 0 rows; aborting",
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

    // Fail helper: proving → failed with §7.5 machine code.
    async fn fail_receive(
        job_store: &JobStore,
        app_state: &AppState,
        notify_map: &JobNotifyMap,
        public_id: Uuid,
        code: &str,
        message: String,
    ) -> anyhow::Result<()> {
        let msg = crate::v1::encode_job_error(code, message);
        if !job_store.fail(public_id, JobStatus::Proving, &msg).await? {
            tracing::warn!(
                "Job dispatcher: receive job {} fail(proving) matched 0 rows",
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
                error: Some(msg),
            },
        );
        cleanup_pending_sign(job_store, app_state, public_id).await;
        notify_map.remove(&public_id);
        Ok(())
    }

    let (subject, next_pubkey, npk_rand, fold_coin_ids, genesis_pubkey) =
        match parse_receive_job_body(&job.request_body) {
            Ok(v) => v,
            Err(e) => {
                return fail_receive(
                    job_store,
                    app_state,
                    notify_map,
                    public_id,
                    "malformed_request",
                    format!("invalid receive request body: {e}"),
                )
                .await;
            }
        };

    let adapter = match &app_state.v1_engine {
        Some(a) => a,
        None => {
            return fail_receive(
                job_store,
                app_state,
                notify_map,
                public_id,
                "internal_error",
                "v1 EngineAdapter missing for receive job".into(),
            )
            .await;
        }
    };

    let (nk, op_secret, current_pubkey) =
        match resolve_receive_auth_keys(app_state, &subject, genesis_pubkey) {
            Ok(v) => v,
            Err(e) => {
                return fail_receive(
                    job_store,
                    app_state,
                    notify_map,
                    public_id,
                    "internal_error",
                    e,
                )
                .await;
            }
        };

    // Reconstitute clause-10 slots (private index + live NfLog). MAX_RX_COINS
    // is enforced inside validate_fold_coin_ids_shape / reconstitute.
    let slots = match reconstitute_receive_slots_locked(
        app_state,
        adapter.as_ref(),
        &subject,
        &fold_coin_ids,
    )
    .await
    {
        Ok(s) => s,
        Err(e) => {
            return fail_receive(
                job_store,
                app_state,
                notify_map,
                public_id,
                e.code(),
                e.to_string(),
            )
            .await;
        }
    };

    let begin_result = adapter.with_engine(|engine| {
        crate::v1::verify_and_begin_receive(
            engine,
            crate::v1::V1ReceiveRequest {
                owner: shared::spec_v1::Address(subject.0),
                nk,
                op_secret,
                current_pubkey,
                slots,
                next_pubkey,
                npk_rand,
            },
        )
    });

    let pending = match begin_result {
        Ok(p) => {
            note_prove_outcome(app_state, Ok(())).await;
            p
        }
        Err(e) => {
            note_prove_outcome(app_state, Err("prove failed")).await;
            return fail_receive(
                job_store,
                app_state,
                notify_map,
                public_id,
                "proving_failed",
                format!("verify_and_begin_receive: {e:#}"),
            )
            .await;
        }
    };

    if let Ok(Some(j)) = job_store.load(public_id).await {
        if j.status == JobStatus::Cancelled {
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
    }

    // Register live pending for stage_and_select_awaiting_signature (same
    // mint/send handshake). Network from the exclusive engine.
    let network = adapter.network();
    let entry = crate::v1::PendingSignEntry::new(pending, network);
    crate::v1::register_live_pending_after_begin(
        &app_state.v1_live_pending_after_begin,
        public_id,
        entry,
    );

    let notifier = notify_map
        .entry(public_id)
        .or_insert_with(|| Arc::new(JobNotifier::new()))
        .clone();

    let live_pending = resolve_live_pending_after_prove(app_state, public_id);
    // Receive has no legacy ash/ocr surface — empty placeholders; under v1
    // the staged PendingSignEntry supplies the §7.5 ProofData advertisement.
    let result = match stage_and_select_awaiting_signature(
        job_store,
        app_state,
        public_id,
        "",
        "",
        live_pending,
    )
    .await
    {
        Ok(v) => v,
        Err(msg) => {
            return fail_receive(
                job_store,
                app_state,
                notify_map,
                public_id,
                "internal_error",
                msg,
            )
            .await;
        }
    };

    // proof_id: receive has no file ProofStore id — use 0 as the sentinel
    // already used for staged-only transitions (attest uses none).
    let proof_id: i64 = 0;
    match job_store
        .set_awaiting_signature(public_id, proof_id, result.clone())
        .await
    {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(
                "Job dispatcher: receive job {} set_awaiting_signature matched 0 rows; cleaning up",
                public_id
            );
            cleanup_pending_sign(job_store, app_state, public_id).await;
            notify_map.remove(&public_id);
            return Ok(());
        }
        Err(e) => {
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
                "Job dispatcher: receive job {} not in awaiting_signature after set ({:?})",
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
            proof_id: Some(proof_id),
            result: Some(result),
            error: None,
        },
    );
    tracing::info!(
        "Job dispatcher: receive job {} reached awaiting_signature",
        public_id
    );

    wait_for_commit(
        job_store,
        app_state,
        notify_map,
        awaiting_signature_timeout,
        public_id,
        JobKind::Receive,
        notifier,
    )
    .await
}

/// Async reconstitution under a short engine read lock for NfLog paths.
async fn reconstitute_receive_slots_locked(
    app_state: &AppState,
    adapter: &crate::v1::EngineAdapter,
    subject: &crate::kernel::types::SubjectAddress,
    fold_coin_ids: &[[u8; 32]],
) -> Result<Vec<crate::v1::ReceivedCoinSlot>, crate::v1::ReconstituteError> {
    use crate::v1::reconstitute::{
        load_coin_proof_canonical, reconstitute_received_slots_with_loader,
        validate_fold_coin_ids_shape,
    };
    validate_fold_coin_ids_shape(fold_coin_ids)?;

    let mut canonicals: Vec<([u8; 32], Vec<u8>)> = Vec::with_capacity(fold_coin_ids.len());
    for coin_id in fold_coin_ids {
        let bytes = load_coin_proof_canonical(
            app_state.private_index.as_ref(),
            app_state.pool.as_ref(),
            subject,
            coin_id,
        )
        .await?;
        canonicals.push((*coin_id, bytes));
    }

    let bridge = adapter.bridge();
    #[cfg(test)]
    let test_loader = app_state.receive_creating_proof_loader.clone();

    adapter.with_engine(|engine| {
        reconstitute_received_slots_with_loader(
            engine,
            &subject.0,
            fold_coin_ids,
            |id| {
                canonicals
                    .iter()
                    .find(|(cid, _)| cid == id)
                    .map(|(_, b)| b.clone())
                    .ok_or(crate::v1::ReconstituteError::UnknownCoinId { coin_id: *id })
            },
            |proof_bytes| {
                #[cfg(test)]
                if let Some(loader) = test_loader.as_ref() {
                    return loader(proof_bytes).map_err(|detail| {
                        crate::v1::ReconstituteError::CreatingProofLoad {
                            coin_id: [0u8; 32],
                            detail,
                        }
                    });
                }
                bridge
                    .load_transition_proof_bytes(proof_bytes)
                    .map_err(|e| crate::v1::ReconstituteError::CreatingProofLoad {
                        coin_id: [0u8; 32],
                        detail: format!("{e:#}"),
                    })
            },
        )
    })
}

/// Resume a receive job already at `awaiting_signature` (boot / re-enqueue).
async fn process_receive_resume(
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
        "Job dispatcher: resuming receive job {} in awaiting_signature",
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
        JobKind::Receive,
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
    //
    // Load / rehydrate errors must **not** fall through to the legacy
    // commit path: a transient DB fault is not "no signature present".
    if crate::v1::v1_sign_route_active() {
        match job_store.load(public_id).await {
            Ok(Some(job)) => {
                if matches!(
                    job.status,
                    JobStatus::AwaitingSignature | JobStatus::Broadcasting
                ) {
                    match crate::v1::rehydrate_pending_sign(&job.request_body) {
                        Ok(Some(entry)) if entry.signature.is_some() => {
                            tracing::info!(
                                "Job dispatcher: job {} has signed durable finalisation on resume \
                                 — driving finalise",
                                public_id
                            );
                            return drive_v1_finalise(
                                job_store, app_state, notify_map, public_id, &job,
                            )
                            .await;
                        }
                        Ok(Some(_)) => {
                            // Durable entry present but unsigned — normal
                            // pre-sign handoff; park below.
                        }
                        Ok(None) => {
                            // No durable finalisation on the row — normal
                            // before the wallet has signed (or legacy shape).
                        }
                        Err(e) => {
                            return Err(anyhow::anyhow!(
                                "Job dispatcher: could not rehydrate pending sign for job \
                                 {public_id} during signed-capability resume check: {e}"
                            ));
                        }
                    }
                }
            }
            Ok(None) => {
                // Job row genuinely absent — resume cannot drive finalise
                // from durable state; park path below will re-load and exit.
                tracing::warn!(
                    "Job dispatcher: job {} missing during signed-capability resume check",
                    public_id
                );
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Job dispatcher: could not load job {public_id} for signed-capability \
                     resume check: {e}"
                ));
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
            let err = if crate::v1::v1_sign_route_active() {
                crate::v1::encode_job_error("internal_error", "awaiting_signature timeout")
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
    // Rehydrate Err must not fall through into the legacy commit branch.
    if crate::v1::v1_sign_route_active() {
        match crate::v1::rehydrate_pending_sign(&job.request_body) {
            Ok(Some(entry)) if entry.signature.is_some() => {
                return drive_v1_finalise(job_store, app_state, notify_map, public_id, &job).await;
            }
            Ok(Some(_)) => {
                // Unsigned durable entry — check warm map, else no v1 sign yet.
            }
            Ok(None) => {
                // No durable finalisation — check warm map below.
            }
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "Job dispatcher: could not rehydrate pending sign for job \
                     {public_id} after handoff wake: {e}"
                ));
            }
        }
        // In-memory map may hold the signature if persist rehydrate raced.
        if let Some(entry) = app_state.pending_sign_map.get(&public_id) {
            if entry.signature.is_some() {
                return drive_v1_finalise(job_store, app_state, notify_map, public_id, &job).await;
            }
        }
    }

    // Legacy path: the commit-route persists the wallet-provided
    // `CommitRequest` into the job's `request_body` under a
    // `commit` key alongside the original send body. Pull it out
    // and feed it to `commit_flow`.
    // Missing `commit` key → Null (parse fails loud below); not a Result mask.
    let commit_value = job
        .request_body
        .get("commit")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    let commit_request: CommitRequest = match serde_json::from_value(commit_value) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("invalid commit body: {}", e);
            // Allowed: awaiting_signature → failed (still pre-broadcast).
            if !job_store
                .fail(public_id, JobStatus::AwaitingSignature, &msg)
                .await?
            {
                tracing::warn!("Job dispatcher: fail matched 0 rows; not publishing failed event");
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

    // Allowed: awaiting_signature → broadcasting (legacy post-sign path).
    if !job_store
        .set_status(
            public_id,
            JobStatus::AwaitingSignature,
            JobStatus::Broadcasting,
            "broadcasting",
        )
        .await?
    {
        // Zero rows: wrong status / claim phase / generation fence. Never run
        // commit flows against wiped proof state after a silent no-op write.
        tracing::warn!(
            "Job dispatcher: job {} set_status(awaiting_signature→broadcasting) matched 0 rows; \
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
        // Attest jobs have no awaiting_signature / commit leg (§7.5).
        JobKind::AttestBalance => {
            return Err(anyhow::anyhow!(
                "Job dispatcher: attest_balance has no commit/broadcast leg"
            ));
        }
        // Receive is v1-only: `/sign` + drive_v1_finalise (above). Legacy
        // CommitRequest ash‖ocr is not a receive surface.
        JobKind::Receive => {
            return Err(anyhow::anyhow!(
                "Job dispatcher: receive has no legacy commit/broadcast leg — \
                 finalise must run via drive_v1_finalise after /sign \
                 (v1_sign_route_active); refused silent fall-through"
            ));
        }
    };
    match commit_outcome {
        Ok((response_body, response_status)) => {
            // Allowed: broadcasting → completed (legacy; not finalise_claimed).
            if !job_store
                .complete(
                    public_id,
                    JobStatus::Broadcasting,
                    response_body.clone(),
                    response_status as i16,
                )
                .await?
            {
                // Zero rows: generation fence / claim phase / terminal / missing.
                // Never publish completed against a row that did not advance.
                tracing::warn!(
                    "Job dispatcher: job {} complete(broadcasting) matched 0 rows; \
                     refusing completed event",
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
            // Allowed: broadcasting → failed (legacy).
            if !job_store
                .fail(public_id, JobStatus::Broadcasting, &message)
                .await?
            {
                tracing::warn!(
                    "Job dispatcher: job {} fail(broadcasting) matched 0 rows after commit error; \
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
                write!(
                    f,
                    "finalise lease heartbeat task ended while work in flight"
                )
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
// Clippy too_many_arguments: packing lease/renew/fence into a struct would
// reshuffle a durable finalise-claim call surface without safety gain.
#[allow(clippy::too_many_arguments)]
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
            // Liveness can no longer be demonstrated: discard `work` (and its
            // result) by letting the pinned future go out of scope. `work` is
            // a plain future and does not implement `Drop`; an explicit
            // `drop(work)` would only extend lifetimes without side effects.
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

/// Encode a finalise-hook failure for the job `error` column.
///
/// Uses the typed host helpers only:
/// - [`crate::v1::signature::machine_code_from_engine_error`] — downcast
/// - [`crate::v1::signature::encode_job_error_from_anyhow`] — structured JSON
/// - [`crate::v1::signature::http_status_for_machine_code`] — RPC table for
///   KernelErrorCode reasons (`dependency_not_final` → 409); job-body-only
///   codes (`publish_rejected`, default `proving_failed`) return `None`
///
/// Free-form text is **not** classified by substring: without a typed cause
/// the stored code is `proving_failed`.
fn encoded_finalise_hook_failure(err: &anyhow::Error) -> String {
    use crate::v1::signature::{
        encode_job_error_from_anyhow, http_status_for_machine_code, machine_code_from_engine_error,
    };

    if let Some(code) = machine_code_from_engine_error(err) {
        // Pin the single transport table for KernelErrorCode reasons. Absence
        // means job-body-only code (poll HTTP stays 200) — not an inventable status.
        if let Some(rpc_http) = http_status_for_machine_code(code) {
            tracing::debug!(
                code,
                rpc_http,
                "typed finalise cause maps to KernelErrorCode RPC status"
            );
        }
    }
    encode_job_error_from_anyhow(err)
}

/// Documented host edge of the job-path finalise resume.
///
/// ## Where completion ends (and why)
///
/// [`drive_v1_finalise`] drives a job through:
///
/// 1. exclusive claim (owner + lease, renewed during long prove)
/// 2. prove + apply + **durable** engine snapshot + `v1_pending_publishes`
///    (`members_ready`) + **durable nullifier publish handoff** via
///    [`crate::router::V1FinaliseHook`] **or** skip prove when
///    `completion_result` is already durable (crash after host work)
/// 3. persist the §7.5 completion surface on the durable capability
/// 4. refuse terminal complete while a pending publish is still only
///    `members_ready` (handoff not yet recorded)
/// 5. [`JobStore::complete_if_finalise_owner`] — §7.5 result published onto the job row
///
/// That is the **host edge**. The production hook
/// ([`crate::v1::finalise_accepted_prove_persist_and_stage`]) stages the
/// applied account, then hands the same row to
/// [`crate::v1::resume_pending_publish`] (construct/broadcast) before
/// returning Ok — the same order as the direct receive path. A job is not
/// `completed` while the intent remains `members_ready`. NfLog scan-fold
/// after on-chain confirmation remains outside this edge.
///
/// Resume is covered durably up to this edge so a crash mid-handoff leaves
/// a progressive `v1_pending_publishes` row; boot still runs
/// `resume_all_pending_publishes` for any leftover mid-broadcast status.
pub const JOB_FINALISE_HOST_EDGE: &str =
    "job_result_published_after_durable_engine_members_ready_and_nullifier_broadcast_handoff; on-chain AggregateStateNullifierV3 confirmation / NfLog scan-fold still needs bitcoind scanner (not a silent skip of publish handoff)";

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
/// | [`JobStore::set_status`] | lock gen; `WHERE public_id AND status = $from AND phase ≠ finalise_claimed AND reset_generation = $N` | **bool** |
/// | [`JobStore::set_awaiting_signature`] | lock gen; `WHERE public_id AND status IN (queued,proving) AND reset_generation = $4` | **bool** |
/// | [`JobStore::complete`] | lock gen; `WHERE public_id AND status = $from AND phase ≠ finalise_claimed AND reset_generation = $N` | **bool** |
/// | [`JobStore::complete_if_status`] | lock gen; status ANY + not claim phase + `reset_generation = $6` | **bool** |
/// | [`JobStore::complete_if_finalise_owner`] | lock gen; claim fence + lease + `reset_generation = $7` | **bool** |
/// | [`JobStore::fail`] | lock gen; `WHERE public_id AND status = $from AND phase ≠ finalise_claimed AND reset_generation = $N` | **bool** |
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
/// | Finalise hook → engine snapshot + `members_ready` | (not a `jobs` row write) | fence via [`crate::v1::finalise_accepted_prove_persist_and_stage`] |
///
/// After the claim is won, durable transition commits are fenced on the
/// **acquisition fencing token** plus a still-valid lease — not on owner
/// identity or status alone. Dropping a future after lease loss is only
/// cooperative; the write predicates are the safety mechanism.
///
/// `broadcasting` is an **exclusive claim**, not a permission: exactly one
/// resumer wins the CAS; the loser observes [`FinaliseClaim::Lost`] and must
/// not continue into side effects **and must not mutate shared notify state**.
async fn drive_v1_finalise(
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
    async fn fail_v1(
        job_store: &JobStore,
        app_state: &AppState,
        notify_map: &JobNotifyMap,
        public_id: Uuid,
        code: &str,
        message: String,
    ) -> anyhow::Result<()> {
        let err = crate::v1::encode_job_error(code, message.clone());
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
    // Clippy too_many_arguments: args identify the fenced durable job-fail
    // write; bundling would change a lease-sensitive call surface.
    #[allow(clippy::too_many_arguments)]
    async fn fail_v1_as_owner(
        job_store: &JobStore,
        app_state: &AppState,
        notify_map: &JobNotifyMap,
        public_id: Uuid,
        owner: Uuid,
        fence: i64,
        code: &str,
        message: String,
    ) -> anyhow::Result<()> {
        let err = crate::v1::encode_job_error(code, message.clone());
        fail_v1_as_owner_encoded(
            job_store, app_state, notify_map, public_id, owner, fence, err,
        )
        .await
    }

    /// Fence-qualified fail with a pre-encoded §7.5 `{error, message}` JSON
    /// string (from [`crate::v1::signature::encode_job_error_from_anyhow`] or
    /// [`crate::v1::encode_job_error`]).
    #[allow(clippy::too_many_arguments)]
    async fn fail_v1_as_owner_encoded(
        job_store: &JobStore,
        app_state: &AppState,
        notify_map: &JobNotifyMap,
        public_id: Uuid,
        owner: Uuid,
        fence: i64,
        err: String,
    ) -> anyhow::Result<()> {
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
    let mut entry = match crate::v1::rehydrate_pending_sign(&job.request_body) {
        Ok(Some(e)) => e,
        Ok(None) => match app_state
            .pending_sign_map
            .get(&public_id)
            .map(|e| e.clone())
        {
            Some(e) => e,
            None => {
                return fail_v1(
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
            return fail_v1(
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
    if let Err(msg) = crate::v1::ensure_finalise_ready(&entry) {
        return fail_v1(
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
                return fail_v1_as_owner(
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
            let Some(hook) = app_state.v1_finalise.as_ref() else {
                return fail_v1_as_owner(
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
                        return fail_v1_as_owner(
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
                    let persist = match crate::v1::DurableFinalisationPersist::from_entry(&entry) {
                        Ok(p) => p,
                        Err(e) => {
                            return fail_v1_as_owner(
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
                            return fail_v1_as_owner(
                                job_store,
                                app_state,
                                notify_map,
                                public_id,
                                claim_owner,
                                claim_fence,
                                "internal_error",
                                format!("v1.1 finalise: json-encode completion capability: {e}"),
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
                Err(e)
                    if e.to_string() == crate::job_store::FINALISE_FENCE_LOST
                        || e.chain()
                            .any(|c| c.to_string() == crate::job_store::FINALISE_FENCE_LOST) =>
                {
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
                    // Typed causes (`PublishRejected`, `DependencyNotFinal`)
                    // classify via downcast — never by message substring.
                    // Free-form text with the same wording stores
                    // `proving_failed` (encode_job_error_from_anyhow default).
                    let err = e.context("v1.1 finalise failed");
                    tracing::warn!("Job dispatcher: job {} {err:#}", public_id);
                    let encoded = encoded_finalise_hook_failure(&err);
                    return fail_v1_as_owner_encoded(
                        job_store,
                        app_state,
                        notify_map,
                        public_id,
                        claim_owner,
                        claim_fence,
                        encoded,
                    )
                    .await;
                }
            }
        }

        // Host §7.5 job-result publication + terminal complete.
        // This is [`JOB_FINALISE_HOST_EDGE`] — after durable publish handoff.
        // Fence is claim token + unexpired lease, not status or owner alone.
        if let Err(msg) = crate::v1::ensure_completion_ready(&entry) {
            return fail_v1_as_owner(
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
        // Refuse completed while the staged nullifier is still only
        // members_ready (broadcast handoff not recorded). The production
        // hook advances the row before returning Ok; a crash/test double
        // that left members_ready must not claim host completion.
        if let Some(sig) = entry.signature.as_ref() {
            match crate::v1::db_v1::load_pending_publish(&app_state.pool, sig.pk_i).await {
                Ok(Some(row)) if row.status == crate::v1::db_v1::PENDING_PUBLISH_MEMBERS_READY => {
                    return fail_v1_as_owner(
                        job_store,
                        app_state,
                        notify_map,
                        public_id,
                        claim_owner,
                        claim_fence,
                        "publish_rejected",
                        // Diagnostic message only — the stored machine code is
                        // the explicit `code` argument above, not parsed from
                        // this text (no `publish_rejected:` prefix contract).
                        format!(
                            "v1.1 finalise refuses completed while \
                             pending publish for pk={} is still members_ready \
                             (broadcast handoff not recorded; row retained)",
                            hex::encode(sig.pk_i)
                        ),
                    )
                    .await;
                }
                Ok(_) => {}
                Err(e) => {
                    return fail_v1_as_owner(
                        job_store,
                        app_state,
                        notify_map,
                        public_id,
                        claim_owner,
                        claim_fence,
                        "internal_error",
                        format!(
                            "v1.1 finalise: cannot load pending publish before complete: {e:#}"
                        ),
                    )
                    .await;
                }
            }
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
                "Job dispatcher: job {} reached host finalise edge ({})",
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

#[cfg(test)]
mod finalise_publish_handoff_tests {
    //! Host-edge publish handoff (Befund 1): job completion is gated on a
    //! recorded broadcast handoff, not on `members_ready` alone.

    use super::*;
    use crate::publisher::EsploraConfig;
    use crate::router::{AppState, ProofStore};
    use crate::v1::{
        claim_stack_scan_mode, set_process_stack_mode, FinaliseOutcome, ScanStackMode,
    };
    use std::sync::{Arc, Mutex};
    use std::time::Duration;
    use zkcoins_program::circuit::compliance::Network;
    use zkcoins_prover::half_agg::AggregateStateNullifierV3;
    use zkcoins_prover::publisher::{BatchMember, PublishedBatch};
    /// Recording double mirroring receive-path `RecordingPublisher` without
    /// construct/broadcast legs (`try_prepare` → `None` → `publish_batch`).
    struct RecordingPublisher {
        batches: Mutex<Vec<Vec<BatchMember>>>,
        fail: bool,
    }

    impl RecordingPublisher {
        fn ok() -> Self {
            Self {
                batches: Mutex::new(Vec::new()),
                fail: false,
            }
        }
        fn failing() -> Self {
            Self {
                batches: Mutex::new(Vec::new()),
                fail: true,
            }
        }
        fn published_count(&self) -> usize {
            self.batches
                .lock()
                .expect("lock")
                .iter()
                .map(|b| b.len())
                .sum()
        }
    }

    impl crate::v1::receive::NullifierBatchPublisher for RecordingPublisher {
        fn publish_batch(&self, members: &[BatchMember]) -> anyhow::Result<PublishedBatch> {
            if self.fail {
                anyhow::bail!("recording publisher: forced broadcast handoff failure");
            }
            anyhow::ensure!(!members.is_empty(), "recording publisher: empty batch");
            self.batches.lock().expect("lock").push(members.to_vec());
            let agg = AggregateStateNullifierV3 {
                version: 3,
                format: 0x01,
                block_anchor: members[0].build_tip,
                members: members.iter().map(|m| (m.sig.pk, m.sig.r)).collect(),
                raw_s: None,
                s_agg: Some([0xAB; 32]),
            };
            Ok(PublishedBatch {
                aggregate: agg,
                payload: vec![0x42],
                commit_txid: bitcoin::Txid::from_raw_hash(
                    <bitcoin::hashes::sha256d::Hash as bitcoin::hashes::Hash>::from_byte_array(
                        [0x11; 32],
                    ),
                ),
                reveal_txid: bitcoin::Txid::from_raw_hash(
                    <bitcoin::hashes::sha256d::Hash as bitcoin::hashes::Hash>::from_byte_array(
                        [0x22; 32],
                    ),
                ),
                commit_output: bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(600),
                    script_pubkey: bitcoin::ScriptBuf::new(),
                },
                block_anchor: members[0].build_tip,
            })
        }
    }

    fn test_app_state(pool: Arc<sqlx::PgPool>) -> AppState {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proof_dir = tmp.path().to_str().expect("utf8").to_string();
        std::mem::forget(tmp);
        let state_arc = Arc::new(Mutex::new(crate::state::State::new()));
        AppState {
            account_node: Arc::new(Mutex::new(crate::account_node::AccountNode::new(state_arc))),
            proof_store: Arc::new(ProofStore::new(&proof_dir)),
            mint_store: Arc::new(crate::router::MintStore::new()),
            username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
            pool: Arc::clone(&pool),
            esplora_config: Arc::new(EsploraConfig {
                url: "http://127.0.0.1:1".to_string(),
                is_mainnet: false,
                network_name: "Regtest".to_string(),
                ws_url: None,
            }),
            prover_warm: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            prover_health: Arc::new(crate::prover_health::ProverHealth::new()),
            job_store: Arc::new(crate::job_store::JobStore::new((*pool).clone())),
            job_tx: tokio::sync::mpsc::channel::<JobEnvelope>(8).0,
            job_notify_map: Arc::new(dashmap::DashMap::new()),
            v1_scan_caught_up: None,
            v1_finality_ok: None,
            pending_sign_map: Arc::new(dashmap::DashMap::new()),
            v1_finalise: None,
            v1_live_pending_after_begin: Arc::new(dashmap::DashMap::new()),
            v1_pending_after_prove: None,
            receive_creating_proof_loader: None,
            v1_engine: None,
            private_index: crate::kernel::access::InMemoryPrivateIndex::shared(),
            bundles: crate::kernel::bootstrap::BundleStore::shared(),
            attest_challenges: crate::kernel::bootstrap::ChallengeStore::shared(),
            public_hosts: Arc::new(vec!["node.test".to_string()]),
        }
    }

    async fn plant_signed_broadcasting_job(
        store: &JobStore,
        owner_tag: u8,
        idem: &str,
        with_completion: bool,
    ) -> (uuid::Uuid, crate::v1::PendingSignEntry) {
        let result = store
            .create(
                JobKind::Send,
                &[owner_tag; 32],
                Some(idem),
                serde_json::json!({}),
            )
            .await
            .expect("create");
        let job_id = match result {
            crate::job_store::CreateResult::Fresh(j) => j.public_id,
            _ => panic!("expected fresh job"),
        };
        let (mut entry, submission) =
            crate::v1::signature::test_fixtures::v5_mainnet_entry_and_submission();
        let advertised = crate::v1::awaiting_signature_result_json(&entry);
        let accepted = crate::v1::accept_wallet_transition_signature(
            crate::v1::V1ShadowMode::On,
            entry.network,
            &entry.pending,
            &submission,
        )
        .expect("verify");
        entry.install_signature(accepted).expect("install");
        if with_completion {
            let outcome = FinaliseOutcome::from_pending_proof_data_with_publisher(
                &entry.pending,
                entry.publisher_pubkey,
            );
            entry
                .install_completion(outcome.to_result_json(), 200)
                .expect("install completion");
        }
        let persist = crate::v1::DurableFinalisationPersist::from_entry(&entry).expect("encode");
        let mut body = serde_json::json!({});
        body.as_object_mut().unwrap().insert(
            crate::v1::FINALISATION_BODY_KEY.to_string(),
            serde_json::to_value(&persist).unwrap(),
        );
        sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
            .bind(&body)
            .bind(job_id)
            .execute(store.pool())
            .await
            .expect("plant body");
        store
            .set_awaiting_signature(job_id, 1, advertised)
            .await
            .expect("awaiting_signature");
        // Re-plant durable capability after status flip (same as router tests).
        let row = store.load(job_id).await.expect("load").expect("row");
        let mut body = row.request_body;
        body.as_object_mut().unwrap().insert(
            crate::v1::FINALISATION_BODY_KEY.to_string(),
            serde_json::to_value(&persist).unwrap(),
        );
        sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
            .bind(&body)
            .bind(job_id)
            .execute(store.pool())
            .await
            .expect("replant durable");
        (job_id, entry)
    }

    /// While the intent is only `members_ready`, the job must not complete.
    #[tokio::test]
    async fn job_not_completed_while_members_ready_without_handoff() {
        set_process_stack_mode(ScanStackMode::V1);
        let scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(scope.pool.clone());
        claim_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect("claim v1");

        let mut state = test_app_state(Arc::clone(&pool));
        let (job_id, entry) =
            plant_signed_broadcasting_job(&state.job_store, 0xA1, "mr-no-handoff", true).await;
        let sig = entry.signature.clone().expect("signed");
        crate::v1::db_v1::insert_pending_publish_members_ready(
            &pool,
            entry.pending.owner,
            sig.pk_i,
            sig.signature_r(),
            sig.signature_s(),
            sig.r_prime,
            0,
            [0u8; 32],
        )
        .await
        .expect("stage members_ready");

        // Hook must not run (completion already durable); gate still applies.
        state.v1_finalise = Some(Arc::new(move |pending, _sig, _fence| {
            Box::pin(async move { Ok(FinaliseOutcome::from_pending_proof_data(&pending)) })
        }));

        process_envelope_for_test(
            &state.job_store,
            &state,
            &state.job_notify_map,
            Duration::from_secs(30),
            JobEnvelope { public_id: job_id },
        )
        .await
        .expect("drive");

        let after = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_ne!(
            after.status,
            JobStatus::Completed,
            "must not complete while members_ready; status={:?} err={:?}",
            after.status,
            after.error
        );
        let pending = crate::v1::db_v1::load_pending_publish(&pool, sig.pk_i)
            .await
            .expect("load")
            .expect("row retained");
        assert_eq!(
            pending.status,
            crate::v1::db_v1::PENDING_PUBLISH_MEMBERS_READY
        );
        drop(scope);
    }

    /// Successful recorded broadcast handoff allows host completion.
    #[tokio::test]
    async fn job_completes_after_recorded_broadcast_handoff() {
        set_process_stack_mode(ScanStackMode::V1);
        let scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(scope.pool.clone());
        claim_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect("claim v1");

        let adapter = Arc::new(
            crate::v1::EngineAdapter::load_or_create((*pool).clone(), Network::Regtest, 0)
                .await
                .expect("adapter"),
        );
        let recorder = Arc::new(RecordingPublisher::ok());
        let mut state = test_app_state(Arc::clone(&pool));
        let (job_id, entry) =
            plant_signed_broadcasting_job(&state.job_store, 0xA2, "mr-handoff-ok", false).await;
        let sig = entry.signature.clone().expect("signed");
        let owner = entry.pending.owner;
        let recorder_h = Arc::clone(&recorder);
        let adapter_h = Arc::clone(&adapter);
        state.v1_finalise = Some(Arc::new(move |pending, signature, fence| {
            let recorder_h = Arc::clone(&recorder_h);
            let adapter_h = Arc::clone(&adapter_h);
            let pool_h = adapter_h.pool().clone();
            Box::pin(async move {
                let staged =
                    crate::v1::db_v1::persist_engine_with_pending_members_ready_if_finalise_fence(
                        &pool_h,
                        &crate::v1::db_v1::EngineSnapshot {
                            network: Network::Regtest,
                            activation_height: 0,
                            tip_height: 0,
                            tip_hash: [0u8; 32],
                            fold_seq: 0,
                            nflog: vec![],
                            accounts: vec![],
                            inscriptions: vec![],
                        },
                        pending.owner,
                        signature.pk_i,
                        signature.signature_r(),
                        signature.signature_s(),
                        signature.r_prime,
                        0,
                        [0u8; 32],
                        fence,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("stage: {e:#}"))?;
                if !staged {
                    return Err(anyhow::Error::msg(crate::job_store::FINALISE_FENCE_LOST));
                }
                // Same handoff the production finalise helper uses.
                crate::v1::receive::resume_pending_publish_with(
                    adapter_h.as_ref(),
                    recorder_h.as_ref(),
                    signature.pk_i,
                )
                .await
                .map_err(|e| {
                    anyhow::Error::new(
                        crate::v1::signature::PublishRejected::DurableHandoffFailed {
                            detail: format!("{e:#}"),
                        },
                    )
                })?;
                Ok(FinaliseOutcome::from_pending_proof_data(&pending))
            })
        }));

        process_envelope_for_test(
            &state.job_store,
            &state,
            &state.job_notify_map,
            Duration::from_secs(30),
            JobEnvelope { public_id: job_id },
        )
        .await
        .expect("drive");

        assert_eq!(
            recorder.published_count(),
            1,
            "recording publisher must observe the broadcast handoff"
        );
        let after = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_eq!(
            after.status,
            JobStatus::Completed,
            "status={:?} err={:?}",
            after.status,
            after.error
        );
        let pending = crate::v1::db_v1::load_pending_publish(&pool, sig.pk_i)
            .await
            .expect("load")
            .expect("row");
        assert_ne!(
            pending.status,
            crate::v1::db_v1::PENDING_PUBLISH_MEMBERS_READY,
            "handoff must advance status past members_ready; got {}",
            pending.status
        );
        assert_eq!(pending.owner, owner);
        drop(scope);
    }

    /// Failed handoff keeps `members_ready` and refuses `completed`.
    #[tokio::test]
    async fn failed_handoff_keeps_members_ready_and_job_not_completed() {
        set_process_stack_mode(ScanStackMode::V1);
        let scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(scope.pool.clone());
        claim_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect("claim v1");

        let adapter = Arc::new(
            crate::v1::EngineAdapter::load_or_create((*pool).clone(), Network::Regtest, 0)
                .await
                .expect("adapter"),
        );
        let recorder = Arc::new(RecordingPublisher::failing());
        let mut state = test_app_state(Arc::clone(&pool));
        let (job_id, entry) =
            plant_signed_broadcasting_job(&state.job_store, 0xA3, "mr-handoff-fail", false).await;
        let sig = entry.signature.clone().expect("signed");
        let recorder_h = Arc::clone(&recorder);
        let adapter_h = Arc::clone(&adapter);
        state.v1_finalise = Some(Arc::new(move |pending, signature, fence| {
            let recorder_h = Arc::clone(&recorder_h);
            let adapter_h = Arc::clone(&adapter_h);
            let pool_h = adapter_h.pool().clone();
            Box::pin(async move {
                let staged =
                    crate::v1::db_v1::persist_engine_with_pending_members_ready_if_finalise_fence(
                        &pool_h,
                        &crate::v1::db_v1::EngineSnapshot {
                            network: Network::Regtest,
                            activation_height: 0,
                            tip_height: 0,
                            tip_hash: [0u8; 32],
                            fold_seq: 0,
                            nflog: vec![],
                            accounts: vec![],
                            inscriptions: vec![],
                        },
                        pending.owner,
                        signature.pk_i,
                        signature.signature_r(),
                        signature.signature_s(),
                        signature.r_prime,
                        0,
                        [0u8; 32],
                        fence,
                    )
                    .await
                    .map_err(|e| anyhow::anyhow!("stage: {e:#}"))?;
                if !staged {
                    return Err(anyhow::Error::msg(crate::job_store::FINALISE_FENCE_LOST));
                }
                crate::v1::receive::resume_pending_publish_with(
                    adapter_h.as_ref(),
                    recorder_h.as_ref(),
                    signature.pk_i,
                )
                .await
                .map_err(|e| {
                    anyhow::Error::new(
                        crate::v1::signature::PublishRejected::DurableHandoffFailed {
                            detail: format!("{e:#}"),
                        },
                    )
                })?;
                Ok(FinaliseOutcome::from_pending_proof_data(&pending))
            })
        }));

        process_envelope_for_test(
            &state.job_store,
            &state,
            &state.job_notify_map,
            Duration::from_secs(30),
            JobEnvelope { public_id: job_id },
        )
        .await
        .expect("drive");

        let after = state
            .job_store
            .load(job_id)
            .await
            .expect("load")
            .expect("row");
        assert_ne!(
            after.status,
            JobStatus::Completed,
            "failed handoff must not complete; status={:?} err={:?}",
            after.status,
            after.error
        );
        assert_eq!(
            after.status,
            JobStatus::Failed,
            "failed handoff must be terminal-failed as retryable publish_rejected; got {:?}",
            after.status
        );
        let err = after.error.as_deref().unwrap_or("");
        let outward = crate::v1::decode_job_error(Some(err), JobStatus::Failed);
        assert_eq!(
            outward["error"], "publish_rejected",
            "outward code must be publish_rejected (retryable handoff failure); got {err}"
        );
        let pending = crate::v1::db_v1::load_pending_publish(&pool, sig.pk_i)
            .await
            .expect("load")
            .expect("members_ready row must be retained");
        assert_eq!(
            pending.status,
            crate::v1::db_v1::PENDING_PUBLISH_MEMBERS_READY,
            "failed handoff must not delete or mark the intent done"
        );
        assert_eq!(recorder.published_count(), 0);
        drop(scope);
    }

    /// Typed finalise-hook cause → same stored §7.5 code as before; free-form
    /// text with the same wording does **not** classify (substring bridge gone).
    #[test]
    fn typed_finalise_cause_encodes_publish_rejected_free_form_does_not() {
        use crate::v1::signature::PublishRejected;

        let typed = anyhow::Error::new(PublishRejected::DurableHandoffFailed {
            detail: "recording publisher: forced broadcast handoff failure".to_string(),
        })
        .context("v1.1 finalise failed");
        let encoded = encoded_finalise_hook_failure(&typed);
        let outward = crate::v1::decode_job_error(Some(&encoded), JobStatus::Failed);
        assert_eq!(
            outward["error"], "publish_rejected",
            "typed PublishRejected must store publish_rejected; got {encoded}"
        );

        // Same diagnostic wording, no typed cause in the chain.
        let free = anyhow::anyhow!(
            "v1.1 finalise failed: publish_rejected: v1.1 finalise durable nullifier \
             publish after members_ready failed (row retained for resume): \
             recording publisher: forced broadcast handoff failure"
        );
        let free_encoded = encoded_finalise_hook_failure(&free);
        let free_outward = crate::v1::decode_job_error(Some(&free_encoded), JobStatus::Failed);
        assert_eq!(
            free_outward["error"], "proving_failed",
            "free-form text with publish_rejected wording must NOT classify; got {free_encoded}"
        );

        // Typed DependencyNotFinal still maps (downcast path, not substring).
        let dep = anyhow::Error::new(
            zkcoins_prover::state_engine::DependencyNotFinal::PredecessorAbsentFromCanonicalNfLog,
        )
        .context("v1.1 finalise failed");
        let dep_encoded = encoded_finalise_hook_failure(&dep);
        let dep_outward = crate::v1::decode_job_error(Some(&dep_encoded), JobStatus::Failed);
        assert_eq!(
            dep_outward["error"], "dependency_not_final",
            "typed DependencyNotFinal must store dependency_not_final; got {dep_encoded}"
        );
        assert_eq!(
            crate::v1::signature::http_status_for_machine_code("dependency_not_final"),
            Some(409),
            "RPC table for dependency_not_final stays 409"
        );
    }
}

/// `wait_for_commit` must fail closed on store load errors under V1 —
/// never treat a load fault as "no signed capability" and fall through
/// into the legacy commit branch.
#[cfg(test)]
mod wait_for_commit_fail_closed_tests {
    use super::*;
    use crate::job_store::{CreateResult, JobKind, JobStatus, JobStore};
    use crate::publisher::EsploraConfig;
    use crate::router::{AppState, ProofStore};
    use crate::v1::{claim_stack_scan_mode, set_process_stack_mode, ScanStackMode};
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    fn test_app_state(pool: Arc<sqlx::PgPool>, job_store: Arc<JobStore>) -> AppState {
        let tmp = tempfile::tempdir().expect("tempdir");
        let proof_dir = tmp.path().to_str().expect("utf8").to_string();
        std::mem::forget(tmp);
        let state_arc = Arc::new(Mutex::new(crate::state::State::new()));
        AppState {
            account_node: Arc::new(Mutex::new(crate::account_node::AccountNode::new(state_arc))),
            proof_store: Arc::new(ProofStore::new(&proof_dir)),
            mint_store: Arc::new(crate::router::MintStore::new()),
            username_store: Arc::new(Mutex::new(crate::username::UsernameStore::new())),
            pool: Arc::clone(&pool),
            esplora_config: Arc::new(EsploraConfig {
                url: "http://127.0.0.1:1".to_string(),
                is_mainnet: false,
                network_name: "Regtest".to_string(),
                ws_url: None,
            }),
            prover_warm: Arc::new(std::sync::atomic::AtomicBool::new(true)),
            prover_health: Arc::new(crate::prover_health::ProverHealth::new()),
            job_store,
            job_tx: tokio::sync::mpsc::channel::<JobEnvelope>(8).0,
            job_notify_map: Arc::new(dashmap::DashMap::new()),
            v1_scan_caught_up: None,
            v1_finality_ok: None,
            pending_sign_map: Arc::new(dashmap::DashMap::new()),
            v1_finalise: None,
            v1_live_pending_after_begin: Arc::new(dashmap::DashMap::new()),
            v1_pending_after_prove: None,
            receive_creating_proof_loader: None,
            v1_engine: None,
            private_index: crate::kernel::access::InMemoryPrivateIndex::shared(),
            bundles: crate::kernel::bootstrap::BundleStore::shared(),
            attest_challenges: crate::kernel::bootstrap::ChallengeStore::shared(),
            public_hosts: Arc::new(vec!["node.test".to_string()]),
        }
    }

    /// Injected load failure at the signed-capability resume check must
    /// abort loudly. Against the previous `if let Ok(Some(_))` mask this
    /// was green only after parking / timeout (or, after a wake, the
    /// legacy commit branch) — never a fail-closed Err at the gate.
    #[tokio::test]
    async fn load_failure_under_v1_fails_closed_without_legacy_commit() {
        set_process_stack_mode(ScanStackMode::V1);
        let scope = crate::test_db::setup_pool().await;
        let pool = Arc::new(scope.pool.clone());
        claim_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect("claim v1");

        let store = Arc::new(JobStore::new((*pool).clone()));
        let created = store
            .create(
                JobKind::Send,
                &[0xF1u8; 32],
                Some("k-wait-load-fail"),
                serde_json::json!({
                    // No `commit` key: if the legacy branch were entered it
                    // would parse Null and fail the job with "invalid commit body".
                }),
            )
            .await
            .expect("create");
        let job_id = match created {
            CreateResult::Fresh(j) => j.public_id,
            _ => panic!("expected Fresh"),
        };
        store
            .set_awaiting_signature(
                job_id,
                1,
                serde_json::json!({
                    "account_state_hash": "aa".repeat(32),
                    "output_coins_root": "bb".repeat(32),
                }),
            )
            .await
            .expect("awaiting_signature");

        let state = test_app_state(Arc::clone(&pool), Arc::clone(&store));

        // `process_envelope` load succeeds (budget 1); `wait_for_commit`
        // signed-capability check load fails (budget 0). Reuses the
        // cancel-path `cfg(test)` load-fail budget — no new harness.
        store.arm_load_failures_after_ok_count(1);

        let err = process_envelope_for_test(
            store.as_ref(),
            &state,
            &state.job_notify_map,
            // Short timeout would only matter if the old mask parked;
            // fail-closed must return before parking.
            Duration::from_millis(50),
            JobEnvelope { public_id: job_id },
        )
        .await
        .expect_err("load failure under v1 must fail closed");

        let msg = format!("{err:#}");
        assert!(
            msg.contains("could not load job") && msg.contains("signed-capability resume"),
            "error must name the load failure cause, got {msg}"
        );
        assert!(
            !msg.contains("invalid commit body"),
            "legacy commit branch must not be entered; got {msg}"
        );

        store.disarm_load_failures();
        let after = store.load(job_id).await.expect("load").expect("row");
        assert_eq!(
            after.status,
            JobStatus::AwaitingSignature,
            "load failure must not advance or fail the job via legacy/timeout; got {:?}",
            after.status
        );
        assert_ne!(
            after.status,
            JobStatus::Broadcasting,
            "legacy path set_status(awaiting_signature→broadcasting) must not run"
        );
        assert!(
            after.error.is_none(),
            "legacy invalid-commit fail must not write error; got {:?}",
            after.error
        );
        drop(scope);
    }
}

/// from-CAS: a write that does not match must not publish a phase event.
#[cfg(test)]
mod from_cas_no_event_tests {
    use super::*;
    use crate::job_store::{CreateResult, JobKind, JobStatus, JobStore, FINALISE_CLAIM_PHASE};
    use std::time::Duration;

    #[tokio::test]
    async fn cas_miss_does_not_publish_phase_event() {
        let scope = crate::test_db::setup_pool().await;
        let store = JobStore::new(scope.pool.clone());
        let CreateResult::Fresh(job) = store
            .create(
                JobKind::Mint,
                &[0xCAu8; 32],
                Some("cas-no-event"),
                serde_json::json!({}),
            )
            .await
            .expect("create")
        else {
            panic!("expected Fresh");
        };
        let job_id = job.public_id;

        // Advance to awaiting_signature and win finalise claim (foreign owner).
        assert!(store
            .set_awaiting_signature(job_id, 1, serde_json::json!({}))
            .await
            .expect("asig"));
        let fence = match store.claim_finalise_exclusive(job_id).await.expect("claim") {
            crate::job_store::FinaliseClaim::Won { fence } => fence,
            other => panic!("expected Won, got {other:?}"),
        };
        let _ = fence;
        let claimed = store.load(job_id).await.expect("load").expect("row");
        assert_eq!(claimed.phase, FINALISE_CLAIM_PHASE);

        // Subscriber is parked before any write attempt.
        let notify_map: JobNotifyMap = std::sync::Arc::new(dashmap::DashMap::new());
        let notifier = std::sync::Arc::new(JobNotifier::new());
        let mut rx = notifier.phase_tx.subscribe();
        notify_map.insert(job_id, std::sync::Arc::clone(&notifier));

        // Same pattern as process_mint/process_attest: only publish on CAS hit.
        let applied = store
            .set_status(job_id, JobStatus::Queued, JobStatus::Proving, "proving")
            .await
            .expect("set_status");
        assert!(
            !applied,
            "late queued→proving must miss under finalise claim"
        );
        // Production gates: `if !applied { return }` — never publish on miss.
        // Call publish only on hit so a regression that returns true would
        // also fail the no-event assertion below.
        // Non-hit branch: warn path only (no event, no invented success) —
        // same as production `if !applied { tracing::warn!(...); return }`.
        if applied {
            publish_phase(
                &notify_map,
                job_id,
                JobPhaseEvent {
                    status: JobStatus::Proving,
                    phase: "proving".to_string(),
                    proof_id: None,
                    result: None,
                    error: None,
                },
            );
        }

        let applied_fail = store
            .fail(job_id, JobStatus::Proving, "late fail")
            .await
            .expect("fail");
        assert!(!applied_fail, "late proving→failed must miss");
        if applied_fail {
            publish_phase(
                &notify_map,
                job_id,
                JobPhaseEvent {
                    status: JobStatus::Failed,
                    phase: "failed".to_string(),
                    proof_id: None,
                    result: None,
                    error: Some("late fail".into()),
                },
            );
        }

        // No event may have been delivered.
        match tokio::time::timeout(Duration::from_millis(50), rx.recv()).await {
            Err(_) => {} // timeout: no event — expected
            Ok(Ok(ev)) => panic!("CAS miss must not publish phase event; got {ev:?}"),
            Ok(Err(e)) => panic!("unexpected recv error: {e}"),
        }

        // Claimed fields still intact.
        let after = store.load(job_id).await.expect("load").expect("row");
        assert_eq!(after.status, JobStatus::Broadcasting);
        assert_eq!(after.phase, FINALISE_CLAIM_PHASE);
        drop(scope);
    }
}

/// Receive job-path wiring + dispatcher decision table (no Plonky2).
#[cfg(test)]
mod receive_job_path_and_decision_table_tests {
    use super::*;
    use crate::job_store::{CreateResult, JobKind, JobStatus, JobStore};
    use std::time::Duration;

    /// Pure decision table: every `(kind, status)` is named — none falls
    /// through a silent catch-all. Pattern mirrors
    /// `boot_finalise_action_decision_table`.
    #[test]
    fn dispatcher_envelope_action_decision_table() {
        use DispatcherEnvelopeAction::*;

        let kinds = [
            JobKind::Mint,
            JobKind::Send,
            JobKind::AttestBalance,
            JobKind::Receive,
        ];
        let statuses = [
            JobStatus::Queued,
            JobStatus::Proving,
            JobStatus::AwaitingSignature,
            JobStatus::Broadcasting,
            JobStatus::Completed,
            JobStatus::Failed,
            JobStatus::Cancelled,
        ];

        for kind in kinds {
            for status in statuses {
                for v1 in [false, true] {
                    let action = dispatcher_envelope_action(kind, status, v1);
                    let expected = match (kind, status, v1) {
                        (JobKind::Mint, JobStatus::Queued, _) => ProcessMintQueued,
                        (JobKind::Mint, JobStatus::AwaitingSignature, _) => {
                            ProcessMintAwaitingSignature
                        }
                        (JobKind::Send, JobStatus::Queued, _) => ProcessSendQueued,
                        (JobKind::Send, JobStatus::AwaitingSignature, _) => {
                            ProcessSendAwaitingSignature
                        }
                        (JobKind::Receive, JobStatus::Queued, _) => ProcessReceiveQueued,
                        (JobKind::Receive, JobStatus::AwaitingSignature, _) => {
                            ProcessReceiveAwaitingSignature
                        }
                        (JobKind::AttestBalance, JobStatus::Queued | JobStatus::Proving, _) => {
                            ProcessAttest
                        }
                        (
                            JobKind::Mint | JobKind::Send | JobKind::Receive,
                            JobStatus::Broadcasting,
                            true,
                        ) => DriveV1Finalise,
                        (
                            JobKind::Mint | JobKind::Send | JobKind::Receive,
                            JobStatus::Proving,
                            _,
                        ) => SkipConcurrentProving,
                        (
                            JobKind::Mint | JobKind::Send | JobKind::Receive,
                            JobStatus::Broadcasting,
                            false,
                        ) => SkipConcurrentBroadcasting,
                        (_, s, _) if s.is_terminal() => FailUnexpectedNonTerminal,
                        (JobKind::AttestBalance, _, _) => FailUnexpectedNonTerminal,
                        // Exhaustive over the closed product above.
                        _ => panic!("decision table missing arm for {kind:?} {status:?} v1={v1}"),
                    };
                    assert_eq!(
                        action, expected,
                        "kind={kind:?} status={status:?} v1={v1}: got {action:?}, want {expected:?}"
                    );
                }
            }
        }

        // Named intentional skips stay skips (not Fail / not Process).
        assert_eq!(
            dispatcher_envelope_action(JobKind::Mint, JobStatus::Proving, false),
            SkipConcurrentProving
        );
        assert_eq!(
            dispatcher_envelope_action(JobKind::Send, JobStatus::Broadcasting, false),
            SkipConcurrentBroadcasting
        );
        // Receive is a real path — queued begins, proving is concurrent skip.
        assert_eq!(
            dispatcher_envelope_action(JobKind::Receive, JobStatus::Queued, false),
            ProcessReceiveQueued
        );
        assert_eq!(
            dispatcher_envelope_action(JobKind::Receive, JobStatus::Proving, true),
            SkipConcurrentProving
        );
        assert_eq!(
            dispatcher_envelope_action(JobKind::Receive, JobStatus::AwaitingSignature, true),
            ProcessReceiveAwaitingSignature
        );
    }

    /// Receive with unknown fold coin fails terminal (named), never hangs
    /// in `queued` and never invents success.
    #[tokio::test]
    async fn receive_unknown_coin_terminal_fails_with_named_error() {
        use crate::kernel::access::{AccountStateView, InMemoryPrivateIndex};
        use crate::kernel::bootstrap::{BundleStore, OperationalBundle};
        use crate::kernel::types::{Digest32, SubjectAddress};
        use crate::v1::separation::{claim_stack_scan_mode, set_process_stack_mode, ScanStackMode};
        use zkcoins_program::circuit::compliance::Network;
        use zkcoins_prover::prover_bridge::test_signing::{deterministic_secret, normalized_key};

        set_process_stack_mode(ScanStackMode::V1);
        let scope = crate::test_db::setup_pool().await;
        // Exclusive DB marker before any v1 write — load_or_create persists
        // an empty genesis snapshot and refuses without this claim.
        claim_stack_scan_mode(&scope.pool, ScanStackMode::V1)
            .await
            .expect("claim stack_scan_mode v1");
        let store = JobStore::new(scope.pool.clone());

        let nk = [4u8; 32];
        let (_sk0, _pt, pk0) = normalized_key(deterministic_secret(b"rx-unk-pk0"));
        let subject = shared::spec_v1::address(&pk0, shared::spec_v1::nk_commit(&nk));
        let fold_hex = "22".repeat(32);
        let CreateResult::Fresh(job) = store
            .create(
                JobKind::Receive,
                &subject,
                Some("k-rx-unknown"),
                serde_json::json!({
                    "kind": "receive",
                    "subject": hex::encode(subject),
                    "next_pubkey": hex::encode([0x11u8; 32]),
                    "npk_rand": hex::encode([0x22u8; 32]),
                    "fold_coin_ids": [fold_hex],
                    "genesis_pubkey": hex::encode(pk0),
                }),
            )
            .await
            .expect("create")
        else {
            panic!("expected Fresh");
        };
        let job_id = job.public_id;

        let pool = std::sync::Arc::new(scope.pool.clone());
        let job_store = std::sync::Arc::new(store);
        let adapter =
            crate::v1::EngineAdapter::load_or_create((*pool).clone(), Network::Regtest, 0)
                .await
                .expect("adapter");

        let bundles = BundleStore::shared();
        bundles.install_for_test(
            &SubjectAddress(subject),
            OperationalBundle {
                ivk: [1; 32],
                ovk: [2; 32],
                op: [3; 32],
                nk,
                op_secret: [5; 32],
            },
        );
        let private_index = InMemoryPrivateIndex::shared();
        private_index
            .insert_account(
                SubjectAddress(subject),
                AccountStateView {
                    account_state: vec![0u8; 140],
                    state_head: Digest32([0; 32]),
                    head_record_id: None,
                    send_counter: 0,
                    current_pubkey: pk0,
                    last_nullifier_pk: None,
                    last_nullifier_r: None,
                },
            )
            .expect("insert account state fixture");

        let tmp = tempfile::tempdir().expect("tempdir");
        let proof_dir = tmp.path().to_str().expect("utf8").to_string();
        std::mem::forget(tmp);
        let state_arc = std::sync::Arc::new(std::sync::Mutex::new(crate::state::State::new()));
        let app_state = crate::router::AppState {
            account_node: std::sync::Arc::new(std::sync::Mutex::new(
                crate::account_node::AccountNode::new(state_arc),
            )),
            proof_store: std::sync::Arc::new(crate::router::ProofStore::new(&proof_dir)),
            mint_store: std::sync::Arc::new(crate::router::MintStore::new()),
            username_store: std::sync::Arc::new(std::sync::Mutex::new(
                crate::username::UsernameStore::new(),
            )),
            pool: std::sync::Arc::clone(&pool),
            esplora_config: std::sync::Arc::new(crate::publisher::EsploraConfig {
                url: "http://127.0.0.1:1".to_string(),
                is_mainnet: false,
                network_name: "Regtest".to_string(),
                ws_url: None,
            }),
            prover_warm: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            prover_health: std::sync::Arc::new(crate::prover_health::ProverHealth::new()),
            job_store: std::sync::Arc::clone(&job_store),
            job_tx: tokio::sync::mpsc::channel::<JobEnvelope>(8).0,
            job_notify_map: std::sync::Arc::new(dashmap::DashMap::new()),
            v1_scan_caught_up: None,
            v1_finality_ok: None,
            pending_sign_map: std::sync::Arc::new(dashmap::DashMap::new()),
            v1_finalise: None,
            v1_live_pending_after_begin: std::sync::Arc::new(dashmap::DashMap::new()),
            v1_pending_after_prove: None,
            receive_creating_proof_loader: None,
            v1_engine: Some(std::sync::Arc::new(adapter)),
            private_index,
            bundles,
            attest_challenges: crate::kernel::bootstrap::ChallengeStore::shared(),
            public_hosts: std::sync::Arc::new(vec!["node.test".to_string()]),
        };

        process_envelope_for_test(
            job_store.as_ref(),
            &app_state,
            &app_state.job_notify_map,
            Duration::from_millis(50),
            JobEnvelope { public_id: job_id },
        )
        .await
        .expect("dispatcher returns Ok after terminal fail");

        let after = job_store.load(job_id).await.expect("load").expect("row");
        assert_eq!(
            after.status,
            JobStatus::Failed,
            "unknown coin must terminal-fail; got {:?}",
            after.status
        );
        let err = after.error.as_deref().expect("error");
        assert!(
            err.contains("unknown coin") || err.contains("unknown_coin"),
            "must name unknown-coin cause; got {err}"
        );
        drop(scope);
    }

    /// End-to-end: `submit_transition` → dispatcher tick → `awaiting_signature`.
    ///
    /// Hits the **same** production path as the live receive job:
    /// `process_receive_initial` → `reconstitute_receive_slots_locked` →
    /// `validate_fold_coin_ids_shape` + `reconstitute_received_slots_with_loader`
    /// → `verify_and_begin_receive` → stage pending → `set_awaiting_signature`.
    ///
    /// Creating-proof load uses the test hollow loader; the wall time is the
    /// genuine `verify_and_begin_receive` circuit build (~6 min measured), not
    /// a prove — which still puts this run in the heavy class. The fast
    /// negative/presence tests above cover the wiring in the default suite.
    #[tokio::test]
    #[ignore = "heavy: real receive circuit build in verify_and_begin (minutes); run with --ignored --release"]
    async fn receive_submit_transition_reaches_awaiting_signature() {
        use crate::kernel::access::{
            AccountStateView, InMemoryPrivateIndex, IndexedRecord, RecordType,
        };
        use crate::kernel::bootstrap::{BundleStore, OperationalBundle};
        use crate::kernel::jobs::submit::{submit_transition, SubmitTransitionDeps};
        use crate::kernel::jobs::ProfileHighWaterStore;
        use crate::kernel::types::{
            Digest32, IdempotencyKey, PublisherChoice, SubjectAddress, TransitionCommand,
            TransitionCommon, XOnlyKey,
        };
        use crate::v1::separation::{claim_stack_scan_mode, set_process_stack_mode, ScanStackMode};
        use crate::v1::DeliveryTargetStore;
        use shared::spec_v1::bundle::serialize_coin_proof;
        use shared::spec_v1::encoding::digest_to_bytes;
        use shared::spec_v1::ManifestClock;
        use zkcoins_program::circuit::compliance::Network;
        use zkcoins_prover::prover_bridge::test_signing::{deterministic_secret, normalized_key};
        use zkcoins_prover::state_engine::{ScannedNullifier, StateEngine};

        set_process_stack_mode(ScanStackMode::V1);
        let scope = crate::test_db::setup_pool().await;
        // Exclusive DB marker before any v1 write — load_or_create persists
        // an empty genesis snapshot and refuses without this claim.
        claim_stack_scan_mode(&scope.pool, ScanStackMode::V1)
            .await
            .expect("claim stack_scan_mode v1");
        let store = std::sync::Arc::new(JobStore::new(scope.pool.clone()));

        let nk = [0x41u8; 32];
        let op_secret_bytes = [0x42u8; 32];
        let (_sk0, _pt, pk0) = normalized_key(deterministic_secret(b"rx-await-pk0"));
        let subject = shared::spec_v1::address(&pk0, shared::spec_v1::nk_commit(&nk));
        let owner = shared::spec_v1::Address(subject);

        // Plant folded coin + hollow CoinProof (same fixture as reconstitute tests).
        let mut eng = StateEngine::new(Network::Regtest, 0);
        let (cp, hollow_proof, coin_id) = {
            // Inline minimal plant (mirrors reconstitute::tests::plant_folded_coin).
            use plonky2::field::polynomial::PolynomialCoeffs;
            use plonky2::field::types::Field;
            use plonky2::fri::proof::FriProof;
            use plonky2::hash::merkle_tree::MerkleCap;
            use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};
            use shared::spec_v1::bundle::{CreatingNullifier, NavOpening as BundleNav};
            use shared::spec_v1::{self as host, Coin, ProofData, TreeKind};
            use zkcoins_program::F;
            use zkcoins_prover::prover_bridge::test_signing::sign_transition;
            use zkcoins_prover::prover_bridge::ComplianceProof;

            let tag = 7u8;
            let (sk, pk_pt, create_pk) =
                normalized_key(deterministic_secret(&[b'K', tag, b's', b'k']));
            let creating_prev_ash = host::digest_from_bytes(&[
                b'p', tag, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0,
            ])
            .unwrap();
            let asset_id = host::asset_id_v1(host::GENESIS_TAG, &create_pk, &[tag; 32], 2, 1);
            let amount = 17u128;
            let coin_identifier =
                host::coin_identifier(creating_prev_ash, &owner.0, asset_id, amount, 0);
            let coin = Coin {
                identifier: coin_identifier,
                recipient: owner,
                amount,
                asset_id,
            };
            let ocr = host::merkle_root(TreeKind::CoinsRoot, &[coin_identifier]);
            let empty_nav = host::Nav {
                size: 0,
                mth: host::nflog_empty(),
            };
            let nav_rand = [tag; 32];
            let pd = ProofData {
                new_account_state_hash: host::digest_from_bytes(&[b'a'; 32]).unwrap(),
                output_coins_root: ocr,
                input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
                coin_history_root: host::coinhist_empty_root(),
                nav_commitment: host::nav_commitment(empty_nav.root(), &nav_rand),
                npk_commit: [tag; 32],
            };
            let sig = sign_transition(sk, pk_pt, &pd, Network::Regtest);
            let r = sig.transition.signature_r();
            let r_prime = sig.transition.r_prime;
            eng.append_nullifier(ScannedNullifier::from_survivor(
                &shared::spec_v1::PublishedNullifier {
                    chain_pos: host::ChainPosition {
                        height: 30,
                        tx_index: 0,
                        vin_index: 0,
                        member_index: 0,
                    },
                    pk: create_pk,
                    r,
                },
            ))
            .expect("fold");
            eng.set_tip_height(40);

            let mut public_inputs = vec![F::ZERO; 108];
            let write_digest = |pis: &mut [F], offset: usize, d: host::HashDigest| {
                for (i, el) in d.elements.iter().enumerate() {
                    pis[offset + i] = *el;
                }
            };
            write_digest(&mut public_inputs, 0, pd.new_account_state_hash);
            write_digest(&mut public_inputs, 4, pd.output_coins_root);
            write_digest(&mut public_inputs, 8, pd.input_nullifiers_root);
            write_digest(&mut public_inputs, 12, pd.coin_history_root);
            write_digest(&mut public_inputs, 16, pd.nav_commitment);
            for i in 0..8 {
                let start = 28 - 4 * i;
                let limb = u32::from_be_bytes(pd.npk_commit[start..start + 4].try_into().unwrap());
                public_inputs[20 + i] = F::from_canonical_u32(limb);
            }
            for i in 0..8 {
                let start = 28 - 4 * i;
                let limb = u32::from_be_bytes(create_pk[start..start + 4].try_into().unwrap());
                public_inputs[28 + i] = F::from_canonical_u32(limb);
            }
            let hollow: ComplianceProof = ProofWithPublicInputs {
                proof: Proof {
                    wires_cap: MerkleCap(vec![]),
                    plonk_zs_partial_products_cap: MerkleCap(vec![]),
                    quotient_polys_cap: MerkleCap(vec![]),
                    openings: OpeningSet {
                        constants: vec![],
                        plonk_sigmas: vec![],
                        wires: vec![],
                        plonk_zs: vec![],
                        plonk_zs_next: vec![],
                        partial_products: vec![],
                        quotient_polys: vec![],
                        lookup_zs: vec![],
                        lookup_zs_next: vec![],
                    },
                    opening_proof: FriProof {
                        commit_phase_merkle_caps: vec![],
                        query_round_proofs: vec![],
                        final_poly: PolynomialCoeffs::new(vec![]),
                        pow_witness: F::ZERO,
                    },
                },
                public_inputs,
            };
            let mut incl_wire = Vec::new();
            incl_wire.extend_from_slice(&0u32.to_be_bytes());
            incl_wire.push(0);
            let cp = shared::spec_v1::bundle::CoinProof {
                coin,
                proof: vec![tag],
                inclusion_proof: incl_wire,
                creating_prev_ash,
                creating_nullifier: CreatingNullifier {
                    pk_create: create_pk,
                    r_create: r,
                    r_prime_create: r_prime,
                },
                nav_opening: BundleNav {
                    size: empty_nav.size,
                    mth: empty_nav.mth,
                    nav_rand,
                },
                asset_terms: None,
                epk: [tag | 0x80; 32],
                ciphertext: vec![1, 2],
                detect_tag: host::digest_from_bytes(&[b'd'; 32]).unwrap(),
            };
            (cp, hollow, digest_to_bytes(&coin_identifier))
        };

        let canonical = serialize_coin_proof(&cp).expect("ser");

        // Install the folded engine into the adapter before admit/tick.
        let adapter =
            crate::v1::EngineAdapter::load_or_create(scope.pool.clone(), Network::Regtest, 0)
                .await
                .expect("adapter");
        adapter
            .with_engine_mut(|engine| {
                *engine = eng;
            })
            .expect("install engine");

        let private_index = InMemoryPrivateIndex::shared();
        private_index
            .insert_record(IndexedRecord {
                subject: SubjectAddress(subject),
                record_id: Digest32([0x01; 32]),
                asset_id: Digest32(digest_to_bytes(&cp.coin.asset_id)),
                occurred_at: 1,
                record_type: RecordType::CoinProof,
                transition_kind: None,
                blob_id: Digest32([0x02; 32]),
                canonical: Some(canonical),
                coin_id: Some(Digest32(coin_id)),
            })
            .expect("insert coin");
        private_index
            .insert_account(
                SubjectAddress(subject),
                AccountStateView {
                    account_state: vec![0u8; 140],
                    state_head: Digest32([0; 32]),
                    head_record_id: None,
                    send_counter: 0,
                    current_pubkey: pk0,
                    last_nullifier_pk: None,
                    last_nullifier_r: None,
                },
            )
            .expect("insert account state fixture");
        let bundles = BundleStore::shared();
        bundles.install_for_test(
            &SubjectAddress(subject),
            OperationalBundle {
                ivk: [1; 32],
                ovk: [2; 32],
                op: [3; 32],
                nk,
                op_secret: op_secret_bytes,
            },
        );

        // Normative admit: same body shape the production gRPC/HTTP edge
        // encodes, then dispatcher enqueue via job_tx.
        let (job_tx, mut job_rx) = tokio::sync::mpsc::channel::<JobEnvelope>(8);
        let targets = DeliveryTargetStore::new();
        let hw = ProfileHighWaterStore::new();
        let projected = submit_transition(
            SubmitTransitionDeps {
                store: store.as_ref(),
                job_tx: &job_tx,
                bundles: &bundles,
                delivery_targets: &targets,
                profile_high_water: &hw,
                subject_owner: Some(subject),
                network: crate::kernel::chain::KernelNetwork::Regtest,
                clock: ManifestClock::UnixSeconds(1_700_000_000),
            },
            TransitionCommand::Receive {
                common: TransitionCommon {
                    subject: SubjectAddress(subject),
                    next_pubkey: XOnlyKey([0x55; 32]),
                    npk_rand: Digest32([0x66; 32]),
                    publisher: PublisherChoice::SelfPublish,
                    idempotency_key: IdempotencyKey::from_validated("k-rx-await".to_string()),
                },
                fold_coin_ids: vec![Digest32(coin_id)],
                genesis_pubkey: Some(XOnlyKey(pk0)),
            },
        )
        .await
        .expect("submit_transition must admit receive");
        let job_id = projected.id.as_uuid();

        // Drain the admit enqueue so the channel stays live; we drive the
        // envelope ourselves so the witness is one explicit dispatcher tick.
        let enqueued = job_rx.recv().await.expect("admit must enqueue envelope");
        assert_eq!(enqueued.public_id, job_id);

        let hollow_for_loader = hollow_proof.clone();
        let pool = std::sync::Arc::new(scope.pool.clone());
        let tmp = tempfile::tempdir().expect("tempdir");
        let proof_dir = tmp.path().to_str().expect("utf8").to_string();
        std::mem::forget(tmp);
        let state_arc = std::sync::Arc::new(std::sync::Mutex::new(crate::state::State::new()));
        let app_state = crate::router::AppState {
            account_node: std::sync::Arc::new(std::sync::Mutex::new(
                crate::account_node::AccountNode::new(state_arc),
            )),
            proof_store: std::sync::Arc::new(crate::router::ProofStore::new(&proof_dir)),
            mint_store: std::sync::Arc::new(crate::router::MintStore::new()),
            username_store: std::sync::Arc::new(std::sync::Mutex::new(
                crate::username::UsernameStore::new(),
            )),
            pool: std::sync::Arc::clone(&pool),
            esplora_config: std::sync::Arc::new(crate::publisher::EsploraConfig {
                url: "http://127.0.0.1:1".to_string(),
                is_mainnet: false,
                network_name: "Regtest".to_string(),
                ws_url: None,
            }),
            prover_warm: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
            prover_health: std::sync::Arc::new(crate::prover_health::ProverHealth::new()),
            job_store: std::sync::Arc::clone(&store),
            job_tx,
            job_notify_map: std::sync::Arc::new(dashmap::DashMap::new()),
            v1_scan_caught_up: None,
            v1_finality_ok: None,
            pending_sign_map: std::sync::Arc::new(dashmap::DashMap::new()),
            v1_finalise: None,
            v1_live_pending_after_begin: std::sync::Arc::new(dashmap::DashMap::new()),
            v1_pending_after_prove: None,
            receive_creating_proof_loader: Some(std::sync::Arc::new(move |_| {
                Ok(hollow_for_loader.clone())
            })),
            v1_engine: Some(std::sync::Arc::new(adapter)),
            private_index,
            bundles,
            attest_challenges: crate::kernel::bootstrap::ChallengeStore::shared(),
            public_hosts: std::sync::Arc::new(vec!["node.test".to_string()]),
        };

        // Dispatcher tick parks on awaiting_signature; poll until that status
        // then abort the park. Short park bound: this is not a multi-minute
        // prove (hollow creating-proof loader); a long timeout only masks hangs.
        let js = std::sync::Arc::clone(&store);
        let as_state = app_state.clone();
        let tick = tokio::spawn(async move {
            process_envelope_for_test(
                js.as_ref(),
                &as_state,
                &as_state.job_notify_map,
                Duration::from_secs(2),
                JobEnvelope { public_id: job_id },
            )
            .await
        });

        let mut saw_awaiting = false;
        for _ in 0..80 {
            tokio::time::sleep(Duration::from_millis(25)).await;
            let row = store.load(job_id).await.expect("load").expect("row");
            if row.status == JobStatus::AwaitingSignature {
                saw_awaiting = true;
                break;
            }
            if row.status.is_terminal() {
                panic!(
                    "receive went terminal before awaiting_signature: {:?} err={:?}",
                    row.status, row.error
                );
            }
        }
        assert!(
            saw_awaiting,
            "submit_transition + dispatcher tick must reach awaiting_signature"
        );
        // Unblock the parked dispatcher (timeout path is fine).
        tick.abort();
        drop(scope);
    }
}
