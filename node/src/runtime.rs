//! Runtime bootstrap: binds a TCP listener and runs the Axum app.
//!
//! This file is intentionally excluded from the coverage scope. The
//! function below cannot be exercised by unit tests — it owns the
//! process lifecycle (port binding, signal-driven shutdown via axum)
//! and exists purely to wire the dependency graph defined in
//! `router.rs` to a real network socket.
//!
//! Anything that is testable in isolation (handlers, helpers, the
//! router construction in `create_router`) stays in `router.rs` and
//! is measured normally.

use dashmap::DashMap;
use sqlx::PgPool;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use tokio::net::TcpListener;

use crate::job_dispatcher::{self, JobNotifier, DEFAULT_AWAITING_SIGNATURE_TIMEOUT};
use crate::job_store::{JobStatus, JobStore};
use crate::publisher::resume_pending_inscriptions;
use crate::v1::{process_stack_mode, ScanStackMode};
use crate::NETWORK_CONFIG;

use crate::account_node::AccountNode;
use crate::router::{create_router, AppState, ProofStore};
use crate::username::UsernameStore;

/// Optional v1.1 readiness handles shared with the exclusive scan loop.
///
/// Under the legacy stack both fields are `None` and readiness ignores
/// NfLog catch-up / deep-reorg. Under `ZKCOINS_V1_SHADOW=1` main wires
/// `Some` atomics so `/health/ready` reflects the NfLog view.
#[derive(Clone, Default)]
pub struct V1Readiness {
    pub scan_caught_up: Option<Arc<AtomicBool>>,
    pub finality_ok: Option<Arc<AtomicBool>>,
}

/// Everything `start_rest_node` needs, resolved at the binary edge.
pub struct RestNodeConfig {
    pub account_node: AccountNode,
    pub username_store: UsernameStore,
    /// REST listen address, parsed inside `start_rest_node`.
    pub addr: String,
    pub pool: Arc<PgPool>,
    /// Proof-store directory. The env read (`PROOFS_DIR`) stays at the
    /// binary edge so parallel test binaries (`runtime_tests.rs` under
    /// issue #181 Opt A's `--test-threads=8`) each pass their own
    /// `tempfile::tempdir()` path instead of racing on a process-wide
    /// env var. Proof files keep using a local directory — the proof
    /// store is append-only and the proofs themselves are large
    /// (bincode-serialized Plonky2 proofs) so a `BYTEA` column would
    /// balloon the Postgres image.
    pub proofs_dir: String,
    pub v1_readiness: V1Readiness,
    /// Shared v1.1 engine (when `ZKCOINS_V1_SHADOW=1`). Used to drive
    /// `StateEngine::finalise` after an accepted `/v1/jobs/{id}/sign`.
    pub v1_engine: Option<Arc<crate::v1::EngineAdapter>>,
    /// Kernel gRPC listen address (**required**, no default).
    /// Validated at the binary edge via `KERNEL_GRPC_ADDR` before this
    /// is called. Served with the same job store + notify map as REST
    /// so `StreamJob` subscribers see dispatcher phase events.
    pub kernel_grpc_addr: SocketAddr,
}

/// Bind REST + job dispatcher + kernel gRPC, sharing one job store and notify map.
///
/// The normative error table and the closed §7.5 / §7.8 wire vocabularies
/// are hand-written. [`crate::transport::error_contract::validate_table`]
/// and [`crate::kernel::chain::validate_closed_sets`] run before the REST
/// socket is bound so a release built without green tests cannot ship
/// wrong codes or collapsed readiness/part/member tokens. The checks are
/// microseconds once and fail closed.
pub async fn start_rest_node(config: RestNodeConfig) -> anyhow::Result<()> {
    let RestNodeConfig {
        account_node,
        username_store,
        addr,
        pool,
        proofs_dir,
        v1_readiness,
        v1_engine,
        kernel_grpc_addr,
    } = config;

    // Fail closed on a drifted §7.8 error table before any listener binds.
    if let Err(e) = crate::transport::error_contract::validate_table() {
        anyhow::bail!("kernel error contract invalid: {e}");
    }
    // Same start edge: closed ReadyReason / NullifierMemberState / KernelPart
    // wire strings must be non-empty and pairwise distinct.
    if let Err(e) = crate::kernel::chain::validate_closed_sets() {
        anyhow::bail!("kernel closed-set contract invalid: {e}");
    }

    let socket_addr = addr
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("Failed to parse address: {}", e))?;

    let shared_account_node = Arc::new(Mutex::new(account_node));

    let proof_store = Arc::new(ProofStore::new(&proofs_dir));

    // Neutral, permissionless model (Milestone 2): there is NO central
    // minting authority. The node holds no minting key and bootstraps
    // no privileged minting account — anyone creates their own asset
    // and mints their own supply via the creator-signed two-phase mint
    // flow. The legacy `minting_secret.bin` + `MINTING_ADDRESS`
    // bootstrap is therefore gone.

    let shared_username_store = Arc::new(Mutex::new(username_store));

    // Background-warmup readiness flag. Default `false`; flipped to
    // `true` by either the background `spawn_blocking` task below (once
    // `AccountNode::warmup_prover` returns Ok) or immediately if the
    // operator set `ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1`. Consumed by
    // `/health/ready`; see the field doc on `AppState::prover_warm`.
    let prover_warm = Arc::new(AtomicBool::new(false));

    // Job-API state-layer. The dispatcher is spawned below once
    // the AppState is fully populated; the mpsc channel is owned
    // by `start_rest_node` so the sender clone can be threaded
    // into the AppState before the dispatcher takes ownership of
    // the receiver half.
    let job_store = Arc::new(JobStore::new((*pool).clone()));
    let job_notify_map = Arc::new(DashMap::new());
    let (job_tx, job_rx) = tokio::sync::mpsc::channel::<crate::job_dispatcher::JobEnvelope>(32);

    let state = AppState {
        account_node: Arc::clone(&shared_account_node),
        proof_store,
        mint_store: Arc::new(crate::router::MintStore::new()),
        username_store: shared_username_store,
        pool: Arc::clone(&pool),
        // The readiness probe uses this to ping Esplora; in production
        // it points at the same `ESPLORA_URL` as the scanner / publisher.
        esplora_config: Arc::new(NETWORK_CONFIG.clone()),
        prover_warm: Arc::clone(&prover_warm),
        prover_health: Arc::new(crate::prover_health::ProverHealth::new()),
        job_store: Arc::clone(&job_store),
        job_tx: job_tx.clone(),
        job_notify_map: Arc::clone(&job_notify_map),
        v1_scan_caught_up: v1_readiness.scan_caught_up,
        v1_finality_ok: v1_readiness.finality_ok,
        pending_sign_map: Arc::new(DashMap::new()),
        // Production finalise: prove outside the engine lock, then apply
        // with live re-validation (receive-path invariant), stage
        // members_ready, then durable-publish that row — same order as the
        // direct receive path. Under the v1.1 claim a missing driver fails
        // the job loud rather than short-circuiting to "signature_accepted"
        // alone. The publisher handle is connected once at boot so the hook
        // can reach durable_publish without breaking the AppState layering
        // (AppState / V1FinaliseHook still carry no publisher type).
        v1_finalise: v1_engine.as_ref().map(|adapter| {
            let adapter = Arc::clone(adapter);
            let network = adapter.network();
            // Fail-loud connect once. An incomplete env / bitcoind outage
            // yields Err on every finalise (after members_ready stage when
            // prove already ran on a prior attempt that left a row — the
            // resume path still stages first). No silent skip of publish.
            //
            // Classification uses a typed [`crate::v1::signature::PublishRejected`]
            // cause so the dispatcher stores `publish_rejected` via downcast —
            // same outward code as a mid-finalise handoff failure. Display
            // text is **diagnostic only**, not a machine-code contract (no
            // `publish_rejected:` prefix dependency).
            //
            // Why `PublishRejected` and not a separate config code: a missing
            // publisher at boot makes the durable nullifier handoff impossible
            // for every finalise; the §7.5 surface the wallet already treats
            // as retryable publish failure is `publish_rejected`. Inventing
            // `internal_error` would change the outward code for the same
            // operational fact (handoff cannot run).
            let publisher_slot: Arc<
                Result<crate::v1::V1Publisher, crate::v1::signature::PublishRejected>,
            > = Arc::new(
                crate::v1::v1_publisher_env_from_env(network)
                    .and_then(crate::v1::connect_v1_publisher)
                    .map_err(
                        |e| crate::v1::signature::PublishRejected::DurableHandoffFailed {
                            detail: format!(
                                "v1.1 finalise publisher unavailable at REST boot \
                                 (nullifier handoff cannot run): {e:#}"
                            ),
                        },
                    ),
            );
            let hook: crate::router::V1FinaliseHook = Arc::new(move |pending, signature, fence| {
                let adapter = Arc::clone(&adapter);
                let publisher_slot = Arc::clone(&publisher_slot);
                // publisher_pubkey is filled by the dispatcher from the job
                // request_body after the hook returns.
                // Durable + fenced: prove → apply → engine snapshot +
                // members_ready → durable publish handoff, only while this
                // claim epoch still holds for the persist step.
                Box::pin(async move {
                    let publisher = match publisher_slot.as_ref() {
                        Ok(p) => p,
                        // Preserve the typed cause for dispatcher downcast.
                        Err(cause) => return Err(anyhow::Error::new(cause.clone())),
                    };
                    crate::v1::finalise_accepted_prove_persist_and_stage(
                        &adapter, pending, signature, None, fence, publisher,
                    )
                    .await
                })
            });
            hook
        }),
        // Production post-begin registry: `StateEngine::begin_*` writes a
        // live PendingSignEntry here; the dispatcher takes it when the job
        // enters awaiting_signature and stages via stage_pending_sign.
        // Under the legacy stack the map stays empty and is unused.
        v1_live_pending_after_begin: Arc::new(DashMap::new()),
        // Test-only injection point (Defect 4): never installed in production.
        #[cfg(test)]
        v1_pending_after_prove: None,
        v1_engine: v1_engine.clone(),
        attest_challenges: crate::kernel::bootstrap::ChallengeStore::shared(),
        public_hosts: Arc::new(crate::v1::public_hosts_from_env()),
    };

    // No minting-account bootstrap: the neutral model has no
    // privileged minting account. Accounts come into existence lazily
    // — an issuer's first mint creates their `(owner, asset_id)`
    // account; a recipient's first receive creates theirs.

    // Phase D removed the startup `check_minting_state_invariant`:
    // `num_pubkeys` is now derived from SMT membership at runtime
    // (`state::derive_num_pubkeys_from_smt`), so the predicate the
    // check measured ("every pubkey_idx ∈ 0..num_pubkeys has a
    // commitment in the SMT") is a tautology by construction. The
    // pre-Phase-D check existed only because the counter and the SMT
    // could disagree — collapsing them into one removes the disagree
    // mode and the check that measured it.

    // Phase B: re-broadcast any pending inscriptions left over from
    // a previous boot. A crash between commit-broadcast and
    // reveal-broadcast (or between construction and either broadcast)
    // leaves a row in `pending_inscriptions` with status != complete;
    // walk each one to completion before opening the listener so
    // operators do not see a stuck UTXO until the next mint triggers
    // the resumer.
    //
    // Under the v1.1 stack claim this path is **skipped**: resuming
    // would broadcast stored bincode Commitments into a database claimed
    // for AggregateStateNullifierV3. The function itself also refuses
    // (defense in depth); we skip here so boot logs stay clean.
    //
    // Failures here are LOGGED and SWALLOWED — the operator's escape
    // hatch is the PR #106 CLI recovery tool, and a transient
    // Esplora outage on boot must not crash-loop the container.
    if matches!(process_stack_mode(), Some(ScanStackMode::V1)) {
        println!(
            "resume_pending_inscriptions: skipped (process claimed v1.1 scan stack; \
             legacy Commitment recovery is forbidden)"
        );
    } else if let Err(e) = resume_pending_inscriptions(&pool, &NETWORK_CONFIG).await {
        eprintln!(
            "Failed to resume pending inscriptions on bootstrap (continuing anyway): {}",
            e
        );
    }

    // Job-API boot-time resumer. The dispatcher walks each job
    // through the state machine; if the process restarts mid-way
    // through a `proving` / `broadcasting` row, the in-process
    // Plonky2 prover state is lost and the signed wallet payload's
    // timestamp window has expired by the time anyone notices. The
    // safest action is to mark every interrupted row `failed`
    // before serving so the wallet observes a terminal status on
    // its next poll and can re-submit (with a fresh timestamp +
    // fresh idempotency key). Jobs already at `awaiting_signature`
    // are different — the wallet may still come back with a valid
    // signature, so we re-arm the per-job `Notify` channel and
    // hand the public_id back to the dispatcher to park on. See
    // the `list_interrupted_for_resume` doc-comment for the
    // partitioning rationale.
    if let Err(e) = boot_resume_jobs(&job_store, &job_notify_map, &job_tx).await {
        eprintln!("Job-API boot-time resume failed (continuing anyway): {}", e);
    }

    // Spawn the dispatcher. Owns the `mpsc::Receiver` half of the
    // channel created above; the matching senders are held by
    // every cloned `AppState`. Closes cleanly when the last sender
    // is dropped (process shutdown).
    job_dispatcher::spawn(
        Arc::clone(&job_store),
        state.clone(),
        Arc::clone(&job_notify_map),
        DEFAULT_AWAITING_SIGNATURE_TIMEOUT,
        job_rx,
    );

    // Additive kernel.v1 gRPC edge (§7.8). Shares job store + notify map
    // with REST/dispatcher so StreamJob is live, not snapshot-only.
    // Fail-closed: domain façade is constructed with real state only.
    // Block 6: when the exclusive v1.1 engine is present, install it on
    // the façade so GetAccumulator / GetNullifierPath / GetInfo read the
    // live NfLog — never a second derivation. ListInscriptions stays
    // Unimplemented until a scanner-written catalog exists (NfLog has no
    // reveal txid / §3.5 format).
    {
        let mut domain = crate::kernel_rpc::domain_from_parts(
            Arc::clone(&job_store),
            Arc::clone(&job_notify_map),
            Arc::clone(&state.pending_sign_map),
            Arc::clone(&state.attest_challenges),
        );
        if let Some(engine) = v1_engine.as_ref() {
            use crate::kernel::{ChainHandle, ChainReadinessFlags, KernelNetwork};

            // Engine + readiness + network pin. GetInfo also needs a
            // complete ChainIdentity (relay/blossom/manifest/max_blob/
            // digests); those sources are not yet a single boot object —
            // leave identity = None so GetInfo fails closed rather than
            // inventing empty infra URLs. Accumulator / path read the
            // live NfLog from the engine alone.
            domain = domain.with_chain(ChainHandle {
                engine: Some(Arc::clone(engine)),
                identity: None,
                readiness: ChainReadinessFlags {
                    scan_caught_up: state.v1_scan_caught_up.clone(),
                    finality_ok: state.v1_finality_ok.clone(),
                },
                network: Some(KernelNetwork::from_v1(engine.network())),
            });
        }
        let job_tx_grpc = job_tx.clone();
        tokio::spawn(async move {
            if let Err(e) = crate::kernel_rpc::serve_kernel_grpc_with_domain(
                kernel_grpc_addr,
                domain,
                job_tx_grpc,
            )
            .await
            {
                eprintln!("Kernel gRPC error: {}", e);
                std::process::exit(1);
            }
        });
    }

    let app = create_router(state);

    // boot_log: announce the startup event with the connected network,
    // node version, listen address, and process pid. Best-effort —
    // a failed boot_log insert must NOT prevent the node from
    // starting (the operator would lose access to a real recovery
    // path on a transient DB blip).
    {
        let boot_entry = crate::db::BootLogEntry {
            event_type: "startup".to_string(),
            message: format!(
                "zkcoins-node {} starting on {} (network={})",
                env!("CARGO_PKG_VERSION"),
                socket_addr,
                NETWORK_CONFIG.network_name,
            ),
            metadata: Some(serde_json::json!({
                "version": env!("CARGO_PKG_VERSION"),
                "network": NETWORK_CONFIG.network_name,
                "socket_addr": socket_addr.to_string(),
                "pid": std::process::id(),
                "is_mainnet": NETWORK_CONFIG.is_mainnet,
            })),
        };
        if let Err(e) = crate::db::insert_boot_log(&pool, &boot_entry).await {
            eprintln!("Failed to persist boot_log startup event: {}", e);
        }
    }

    println!("REST API started at {}", socket_addr);
    let listener = TcpListener::bind(socket_addr).await?;
    tracing::info!("Listener bound on {socket_addr}; API is reachable");

    // Background-warmup. A fresh `Prover` carries a cold Rayon worker
    // pool and uninitialised AOT-compiled Plonky2 evaluator caches;
    // empirically (DEV-host R2 probe, 2026-05-31) the first
    // `prove_initial` after `Prover::new()` takes ~7012 ms vs the
    // steady-state p50 of ~4777 ms for every subsequent call.
    //
    // The previous shape (PR #147, closed) paid that tax synchronously
    // before binding the listener and pushed API offline time per
    // deploy from ~14 s to ~21 s. This shape instead binds the
    // listener FIRST (the API is reachable at ~0.1 s), then spawns
    // `AccountNode::warmup_prover` in a `spawn_blocking` task so the
    // tokio worker that runs `axum::serve` is not starved by the
    // CPU-bound Plonky2 prove. While the task is running a user
    // request still serves correctly — it just pays the ~7 s cold tax
    // — and `/health/ready` returns 503 with `prover: warming` so an
    // LB / Kuma can hold traffic on the previous-gen pod during a
    // rolling deploy.
    //
    // Opt-out via `ZKCOINS_SKIP_BOOTSTRAP_WARMUP=1`: the smoke tests
    // in `runtime_tests.rs` set this so each `start_rest_node_*` test
    // does not pay the ~7 s prove tax twice over. When set,
    // `prover_warm` is flipped to `true` immediately so the readiness
    // probe matches the production-ready shape.
    let skip_warmup = std::env::var("ZKCOINS_SKIP_BOOTSTRAP_WARMUP")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let warmup_handle = if skip_warmup {
        tracing::info!(
            "Bootstrap warmup skipped via ZKCOINS_SKIP_BOOTSTRAP_WARMUP; \
             prover_warm = true (first user request will pay the ~7 s cold tax)"
        );
        prover_warm.store(true, Ordering::SeqCst);
        None
    } else {
        let account_node_for_warmup = Arc::clone(&shared_account_node);
        let prover_warm_flag = Arc::clone(&prover_warm);
        let handle = tokio::task::spawn_blocking(move || {
            let warmup_t = std::time::Instant::now();
            // Hold the sync `Mutex` only for the duration of the
            // prove call. The scanner — spawned in parallel by
            // `main.rs` — locks `state`, not `account_node`, so it
            // does not contend with this guard. The only realistic
            // contender is a user request that lands during the
            // ~7 s warmup window; that request blocks on
            // `account_node.lock()` for the remainder of the warmup
            // (then runs warm), which is the accepted trade-off
            // documented in the function comment. The block is
            // shorter (and aborts cleanly on shutdown) than the
            // previous synchronous-bootstrap shape.
            let result = {
                let guard = account_node_for_warmup
                    .lock()
                    .expect("AccountNode mutex poisoned before bootstrap warmup");
                guard.warmup_prover()
            };
            match result {
                Ok(()) => {
                    tracing::info!(
                        elapsed_ms = warmup_t.elapsed().as_millis() as u64,
                        "Background warmup complete; prover ready"
                    );
                    prover_warm_flag.store(true, Ordering::SeqCst);
                }
                Err(e) => {
                    // Same severity as the previous synchronous
                    // `expect()` — the same Prover serves every
                    // subsequent user request, so a warmup failure
                    // means production requests would also fail.
                    // Crash-loop the container rather than running
                    // a node that serves 5xx for the prove path.
                    tracing::error!(error = %e, "Background warmup failed — exiting");
                    std::process::exit(1);
                }
            }
        });
        tracing::info!("Bootstrap warmup spawned in background; listener serving now");
        Some(handle)
    };
    // `warmup_handle` is intentionally not awaited: `axum::serve`
    // owns the foreground future and the warmup runs to completion
    // on its own. On graceful shutdown `axum::serve` returns first;
    // the warmup task either completes naturally or is dropped when
    // the tokio runtime shuts down. The binding keeps the JoinHandle
    // alive (vs. `let _ =`) so a future shutdown signal can call
    // `.abort()` once a signal handler is wired in.
    let _warmup_handle = warmup_handle;

    // `into_make_service_with_connect_info::<SocketAddr>()` exposes the
    // peer's TCP socket to extractors — the audit middleware reads it
    // through `ConnectInfo<SocketAddr>` and writes it to
    // `request_log.remote_addr`. Without this the audit row's
    // `remote_addr` column is always NULL (the default `into_make_service`
    // never inserts a `ConnectInfo` extension).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await?;

    Ok(())
}

async fn rearm_and_enqueue_v1_finalise(
    public_id: uuid::Uuid,
    job_notify_map: &DashMap<uuid::Uuid, Arc<JobNotifier>>,
    job_tx: &tokio::sync::mpsc::Sender<crate::job_dispatcher::JobEnvelope>,
) {
    let notifier = Arc::new(JobNotifier::new());
    job_notify_map.insert(public_id, notifier);
    if let Err(e) = job_tx
        .send(crate::job_dispatcher::JobEnvelope { public_id })
        .await
    {
        eprintln!(
            "boot_resume_jobs: enqueue signed broadcasting {public_id} failed: {e} (continuing)"
        );
    } else {
        tracing::info!(
            "boot_resume_jobs: re-armed signed broadcasting job {public_id} for finalise resume"
        );
    }
}

/// Poll until the exclusive finalise claim is abandoned (or the job leaves
/// broadcasting), then release + enqueue. Prevents stranding after an
/// immediate restart while a dead owner's lease has not yet expired.
///
/// **Durable:** no fixed deadline. A slow-dying owner (lease still renewing
/// or wall-clock lag before abandonment) must not cause silent job loss.
/// This task keeps trying until the claim is free, the job is terminal /
/// non-broadcasting, or the process exits. A later boot re-lists interrupted
/// `broadcasting` rows and schedules reclaim again if needed.
fn spawn_deferred_finalise_reclaim(
    job_store: Arc<JobStore>,
    job_notify_map: Arc<DashMap<uuid::Uuid, Arc<JobNotifier>>>,
    job_tx: tokio::sync::mpsc::Sender<crate::job_dispatcher::JobEnvelope>,
    public_id: uuid::Uuid,
) {
    tokio::spawn(async move {
        // Poll frequently enough that a short test lease is reclaimed promptly.
        // No wall-clock deadline: abandoning after N minutes was silent loss.
        let poll = std::time::Duration::from_millis(200);
        loop {
            tokio::time::sleep(poll).await;

            let row = match job_store.load(public_id).await {
                Ok(Some(j)) => j,
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!(
                        %public_id,
                        error = %e,
                        "boot_resume_jobs: deferred reclaim load failed; retrying"
                    );
                    continue;
                }
            };
            if row.status.is_terminal() {
                return;
            }
            if row.status != JobStatus::Broadcasting {
                return;
            }

            let released = match job_store.release_stale_finalise_claim(public_id).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        %public_id,
                        error = %e,
                        "boot_resume_jobs: deferred release_stale failed; retrying"
                    );
                    continue;
                }
            };
            // When release succeeds the claim is free — enqueue without a
            // second load (a DB error on re-load must not strand a freed row).
            if released {
                tracing::info!(
                    %public_id,
                    "boot_resume_jobs: deferred reclaim — claim free, enqueueing"
                );
                rearm_and_enqueue_v1_finalise(public_id, &job_notify_map, &job_tx).await;
                return;
            }
            // Re-load phase after a no-op release (still need free-vs-owned).
            let phase = match job_store.load(public_id).await {
                Ok(Some(j)) => j.phase,
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!(
                        %public_id,
                        error = %e,
                        "boot_resume_jobs: deferred reclaim phase reload failed; retrying"
                    );
                    continue;
                }
            };
            match boot_finalise_action_after_release(false, JobStatus::Broadcasting, &phase) {
                BootFinaliseAction::EnqueueNow => {
                    tracing::info!(
                        %public_id,
                        "boot_resume_jobs: deferred reclaim — claim free, enqueueing"
                    );
                    rearm_and_enqueue_v1_finalise(public_id, &job_notify_map, &job_tx).await;
                    return;
                }
                BootFinaliseAction::DeferUntilAbandoned => {
                    // Still live — keep waiting for abandonment evidence.
                }
                BootFinaliseAction::Skip => return,
            }
        }
    });
}

/// Boot decision after a `release_stale_finalise_claim` attempt on a
/// resumable v1.1 broadcasting job.
///
/// | Prior phase | Release result | Action |
/// |-------------|----------------|--------|
/// | `finalise_claimed` | `Ok(true)` (abandoned) | [`BootFinaliseAction::EnqueueNow`] — claim freed |
/// | `finalise_claimed` | `Ok(false)` (lease still live) | [`BootFinaliseAction::DeferUntilAbandoned`] — still owned; do **not** enqueue as free |
/// | `publishing` / `broadcasting` | `Ok(false)` (nothing to release) | [`BootFinaliseAction::EnqueueNow`] — already free |
/// | any free/terminal after error recovery | — | [`BootFinaliseAction::Skip`] |
/// | any | `Err(_)` | caller must not enqueue (fail closed for that row) |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootFinaliseAction {
    /// Claim is free — boot may re-arm notify and enqueue for finalise.
    EnqueueNow,
    /// Exclusive claim still held under a live lease. Do not enqueue; a
    /// deferred reclaim must wait for abandonment evidence.
    DeferUntilAbandoned,
    /// Job is no longer a broadcasting finalise candidate.
    Skip,
}

/// Decide boot action from the release outcome and the job row **after**
/// the release attempt. Pure decision table — no I/O.
pub(crate) fn boot_finalise_action_after_release(
    released: bool,
    status: JobStatus,
    phase: &str,
) -> BootFinaliseAction {
    if status != JobStatus::Broadcasting {
        return BootFinaliseAction::Skip;
    }
    if released {
        // Abandoned claim stripped; phase is `publishing`.
        return BootFinaliseAction::EnqueueNow;
    }
    // Ok(false): either still exclusively claimed, or already free.
    if phase == crate::job_store::FINALISE_CLAIM_PHASE {
        BootFinaliseAction::DeferUntilAbandoned
    } else if phase == "publishing" || phase == "broadcasting" {
        BootFinaliseAction::EnqueueNow
    } else {
        // Unknown phase under broadcasting — do not pretend it is free.
        BootFinaliseAction::Skip
    }
}

/// Boot disposition for one interrupted v1.1 edge row, including DB-error
/// paths. Pure — no I/O.
///
/// | `release` | `phase_reload` (only if `Ok(false)`) | Disposition |
/// |-----------|--------------------------------------|-------------|
/// | `Err` | — | [`BootRowDisposition::LeaveUntouchedForRetry`] — no mutation |
/// | `Ok(true)` | ignored | [`BootRowDisposition::Act`]`(EnqueueNow)` — claim freed; enqueue without second load |
/// | `Ok(false)` | `Err` | [`BootRowDisposition::LeaveUntouchedForRetry`] — row not mutated by release |
/// | `Ok(false)` | `Ok(None)` | [`BootRowDisposition::Act`]`(Skip)` — row vanished |
/// | `Ok(false)` | `Ok(Some(phase))` | [`BootRowDisposition::Act`]`(`[`boot_finalise_action_after_release`]`)` |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BootRowDisposition {
    /// Database error before or without a successful mutation — leave the
    /// row as-is for a later boot/retry. Never half-process.
    LeaveUntouchedForRetry,
    /// A defined action for this row.
    Act(BootFinaliseAction),
}

/// Pure error-path + success-path decision for one resumable v1.1 edge row.
pub(crate) fn boot_finalise_disposition(
    release: Result<bool, ()>,
    phase_reload: Result<Option<&str>, ()>,
) -> BootRowDisposition {
    match release {
        Err(()) => BootRowDisposition::LeaveUntouchedForRetry,
        Ok(true) => BootRowDisposition::Act(BootFinaliseAction::EnqueueNow),
        Ok(false) => match phase_reload {
            Err(()) => BootRowDisposition::LeaveUntouchedForRetry,
            Ok(None) => BootRowDisposition::Act(BootFinaliseAction::Skip),
            Ok(Some(phase)) => BootRowDisposition::Act(boot_finalise_action_after_release(
                false,
                JobStatus::Broadcasting,
                phase,
            )),
        },
    }
}

/// Job-API boot-time resumer. Walks every non-terminal row in the
/// `jobs` table and applies the partition described in
/// `JobStore::list_interrupted_for_resume` /
/// `list_non_terminal_for_resume`:
///
/// * `proving` / `broadcasting` — interrupted in flight; the
///   in-process prover / publisher state is gone. Mark `failed`
///   with a wallet-facing message so the next poll observes a
///   terminal status.
/// * `queued` — the signed payload's timestamp window has expired
///   (the wallet's timestamp gate is 5 minutes, the server may
///   have been down longer). Mark `failed` for the same reason.
/// * `awaiting_signature` — the wallet may still come back with
///   the signature. Re-arm a fresh `Notify` entry and hand the
///   public_id back to the dispatcher so it parks on the channel
///   the same way it did pre-restart.
pub(crate) async fn boot_resume_jobs(
    job_store: &Arc<JobStore>,
    job_notify_map: &Arc<DashMap<uuid::Uuid, Arc<JobNotifier>>>,
    job_tx: &tokio::sync::mpsc::Sender<crate::job_dispatcher::JobEnvelope>,
) -> anyhow::Result<()> {
    // Interrupted in-flight rows. Legacy / unsigned work cannot resume
    // (prove output lived only in process memory) → mark failed.
    // v1.1 jobs with a **signed durable FinalisationCapability** can
    // resume finalise after a mid-prove crash (status broadcasting):
    // re-arm and enqueue instead of failing.
    let interrupted = job_store.list_interrupted_for_resume().await?;
    for job in interrupted {
        let resumable_v1 = crate::v1::v1_sign_route_active()
            && job.status == JobStatus::Broadcasting
            && matches!(
                crate::v1::rehydrate_pending_sign(&job.request_body),
                Ok(Some(e)) if e.signature.is_some()
            );
        if resumable_v1 {
            // Honour release_stale: only enqueue when the claim is free.
            // Ignoring Ok(false) re-enqueued still-owned jobs; the loser
            // then exited and the edge job was stranded forever.
            //
            // On a database error the row must stay **entirely untouched**
            // and be retried (next boot) — never half-process (e.g. release
            // then abort before enqueue via `?` on a subsequent load).
            // Decision table: [`boot_finalise_disposition`].
            let release_result = match job_store.release_stale_finalise_claim(job.public_id).await {
                Ok(r) => Ok(r),
                Err(e) => {
                    eprintln!(
                        "boot_resume_jobs: release_stale_finalise_claim({}) failed: {} \
                         (row left untouched for retry; fail closed)",
                        job.public_id, e
                    );
                    Err(())
                }
            };

            // Phase reload only when release was Ok(false). On Ok(true) the
            // disposition enqueues without a second load so a load error
            // cannot strand a just-freed claim.
            let phase_reload: Result<Option<String>, ()> = match release_result {
                Ok(false) => match job_store.load(job.public_id).await {
                    Ok(Some(j)) => Ok(Some(j.phase)),
                    Ok(None) => {
                        tracing::warn!(
                            "boot_resume_jobs: job {} vanished after release attempt",
                            job.public_id
                        );
                        Ok(None)
                    }
                    Err(e) => {
                        eprintln!(
                            "boot_resume_jobs: load({}) after release_stale failed: {} \
                             (row left untouched for retry; fail closed)",
                            job.public_id, e
                        );
                        Err(())
                    }
                },
                // Not consulted when release is Err or Ok(true).
                _ => Ok(None),
            };

            let disposition = boot_finalise_disposition(
                release_result,
                phase_reload.as_ref().map(|o| o.as_deref()).map_err(|_| ()),
            );
            match disposition {
                BootRowDisposition::LeaveUntouchedForRetry => {
                    // Already logged; continue to next interrupted row.
                }
                BootRowDisposition::Act(BootFinaliseAction::EnqueueNow) => {
                    rearm_and_enqueue_v1_finalise(job.public_id, job_notify_map, job_tx).await;
                }
                BootRowDisposition::Act(BootFinaliseAction::DeferUntilAbandoned) => {
                    let phase = phase_reload
                        .ok()
                        .flatten()
                        .unwrap_or_else(|| crate::job_store::FINALISE_CLAIM_PHASE.to_string());
                    tracing::info!(
                        "boot_resume_jobs: job {} still under a live finalise claim \
                         (phase={}); not enqueueing as free — scheduling reclaim",
                        job.public_id,
                        phase
                    );
                    spawn_deferred_finalise_reclaim(
                        Arc::clone(job_store),
                        Arc::clone(job_notify_map),
                        job_tx.clone(),
                        job.public_id,
                    );
                }
                BootRowDisposition::Act(BootFinaliseAction::Skip) => {
                    tracing::info!(
                        "boot_resume_jobs: job {} not enqueued after release \
                         (disposition=Skip)",
                        job.public_id
                    );
                }
            }
            continue;
        }
        // Status-qualified fail against the status observed in this
        // snapshot — never bare `fail`. Between list and write another
        // process can advance the row to `awaiting_signature` and win a
        // finalise claim; bare fail would then terminate an owned epoch.
        // `fail_if_status` refuses any held claim (`phase IS DISTINCT FROM
        // FINALISE_CLAIM_PHASE`) and is a no-op when status has moved on.
        match job_store
            .fail_if_status(
                job.public_id,
                &[job.status],
                "server restarted before processing — please retry",
            )
            .await
        {
            Ok(true) => {
                tracing::info!(
                    "boot_resume_jobs: marked {} ({:?}) failed",
                    job.public_id,
                    job.status
                );
            }
            Ok(false) => {
                tracing::info!(
                    "boot_resume_jobs: skip fail for {} (snapshot status={:?}; \
                     row moved or claimed since list)",
                    job.public_id,
                    job.status
                );
            }
            Err(e) => {
                eprintln!(
                    "boot_resume_jobs: fail_if_status({}) failed: {} (continuing)",
                    job.public_id, e
                );
            }
        }
    }

    // Non-terminal rows still in admit-side states.
    let pending = job_store.list_non_terminal_for_resume().await?;
    for job in pending {
        match job.status {
            JobStatus::Queued => {
                // Same fence as interrupted: snapshot said `queued`, but a
                // concurrent worker may have proven, advertised, signed and
                // claimed before this write. Status-qualified only.
                match job_store
                    .fail_if_status(
                        job.public_id,
                        &[JobStatus::Queued],
                        "server restarted before processing — please retry",
                    )
                    .await
                {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::info!(
                            "boot_resume_jobs: skip fail for queued {} \
                             (moved or claimed since list)",
                            job.public_id
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "boot_resume_jobs: fail_if_status({}) failed: {} (continuing)",
                            job.public_id, e
                        );
                    }
                }
            }
            JobStatus::AwaitingSignature => {
                let notifier = Arc::new(JobNotifier::new());
                job_notify_map.insert(job.public_id, notifier);
                if let Err(e) = job_tx
                    .send(crate::job_dispatcher::JobEnvelope {
                        public_id: job.public_id,
                    })
                    .await
                {
                    eprintln!(
                        "boot_resume_jobs: enqueue({}) failed: {} (continuing)",
                        job.public_id, e
                    );
                } else {
                    tracing::info!(
                        "boot_resume_jobs: re-armed awaiting_signature job {}",
                        job.public_id
                    );
                }
            }
            _ => {}
        }
    }

    Ok(())
}

#[cfg(test)]
#[path = "runtime_tests.rs"]
mod tests;
