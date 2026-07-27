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
use crate::v11::{process_stack_mode, ScanStackMode};
use crate::NETWORK_CONFIG;

use crate::account_node::AccountNode;
use crate::router::{create_router, AppState, ProofStore};
use crate::username::UsernameStore;

/// Optional v1.1 readiness handles shared with the exclusive scan loop.
///
/// Under the legacy stack both fields are `None` and readiness ignores
/// NfLog catch-up / deep-reorg. Under `ZKCOINS_V11_SHADOW=1` main wires
/// `Some` atomics so `/health/ready` reflects the NfLog view.
#[derive(Clone, Default)]
pub struct V11Readiness {
    pub scan_caught_up: Option<Arc<AtomicBool>>,
    pub finality_ok: Option<Arc<AtomicBool>>,
}

pub async fn start_rest_node(
    account_node: AccountNode,
    username_store: UsernameStore,
    addr: &str,
    pool: Arc<PgPool>,
    proofs_dir: &str,
    v11_readiness: V11Readiness,
    // Shared v1.1 engine (when `ZKCOINS_V11_SHADOW=1`). Used to drive
    // `StateEngine::finalise` after an accepted `/v1/jobs/{id}/sign`.
    v11_engine: Option<Arc<crate::v11::EngineAdapter>>,
) -> anyhow::Result<()> {
    let socket_addr = addr
        .parse::<SocketAddr>()
        .map_err(|e| anyhow::anyhow!("Failed to parse address: {}", e))?;

    let shared_account_node = Arc::new(Mutex::new(account_node));

    // Proof files keep using a local directory — the proof store is
    // append-only and the proofs themselves are large (bincode-
    // serialized Plonky2 proofs) so a `BYTEA` column would balloon the
    // Postgres image. The `proofs_dir` arrives as a parameter from the
    // binary edge (`main.rs` reads the `PROOFS_DIR` env var and passes
    // the resolved value through) — keeping the env read out of this
    // function lets parallel test binaries (`runtime_tests.rs` under
    // issue #181 Opt A's `--test-threads=8`) each pass their own
    // `tempfile::tempdir()` path instead of racing on a process-wide
    // env var.
    let proof_store = Arc::new(ProofStore::new(proofs_dir));

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
        v11_scan_caught_up: v11_readiness.scan_caught_up,
        v11_finality_ok: v11_readiness.finality_ok,
        pending_sign_map: Arc::new(DashMap::new()),
        // Production finalise: prove outside the engine lock, then apply
        // with live re-validation (receive-path invariant). Under the v1.1
        // claim a missing driver fails the job loud rather than
        // short-circuiting to "signature_accepted" alone.
        v11_finalise: v11_engine.as_ref().map(|adapter| {
            let adapter = Arc::clone(adapter);
            let hook: crate::router::V11FinaliseHook = Arc::new(move |pending, signature| {
                // publisher_pubkey is filled by the dispatcher from the job
                // request_body after the hook returns (hook has no job ctx).
                crate::v11::finalise_accepted_prove_outside_lock(
                    &adapter, pending, signature, None,
                )
            });
            hook
        }),
        // Production post-begin registry: `StateEngine::begin_*` writes a
        // live PendingSignEntry here; the dispatcher takes it when the job
        // enters awaiting_signature and stages via stage_pending_sign.
        // Under the legacy stack the map stays empty and is unused.
        v11_live_pending_after_begin: Arc::new(DashMap::new()),
        // Test-only injection point (Defect 4): never installed in production.
        #[cfg(test)]
        v11_pending_after_prove: None,
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
    if matches!(process_stack_mode(), Some(ScanStackMode::V11)) {
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
async fn boot_resume_jobs(
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
        let resumable_v11 = crate::v11::v11_sign_route_active()
            && job.status == JobStatus::Broadcasting
            && matches!(
                crate::v11::rehydrate_pending_sign(&job.request_body),
                Ok(Some(e)) if e.signature.is_some()
            );
        if resumable_v11 {
            // Dead process may have left phase = finalise_claimed; release so
            // the single boot resumer can re-acquire the exclusive claim.
            if let Err(e) = job_store
                .release_stale_finalise_claim(job.public_id)
                .await
            {
                eprintln!(
                    "boot_resume_jobs: release_stale_finalise_claim({}) failed: {} (continuing)",
                    job.public_id, e
                );
            }
            let notifier = Arc::new(JobNotifier::new());
            job_notify_map.insert(job.public_id, notifier);
            if let Err(e) = job_tx
                .send(crate::job_dispatcher::JobEnvelope {
                    public_id: job.public_id,
                })
                .await
            {
                eprintln!(
                    "boot_resume_jobs: enqueue signed broadcasting {} failed: {} (continuing)",
                    job.public_id, e
                );
            } else {
                tracing::info!(
                    "boot_resume_jobs: re-armed signed broadcasting job {} for finalise resume",
                    job.public_id
                );
            }
            continue;
        }
        if let Err(e) = job_store
            .fail(
                job.public_id,
                "server restarted before processing — please retry",
            )
            .await
        {
            eprintln!(
                "boot_resume_jobs: fail({}) failed: {} (continuing)",
                job.public_id, e
            );
        } else {
            tracing::info!(
                "boot_resume_jobs: marked {} ({:?}) failed",
                job.public_id,
                job.status
            );
        }
    }

    // Non-terminal rows still in admit-side states.
    let pending = job_store.list_non_terminal_for_resume().await?;
    for job in pending {
        match job.status {
            JobStatus::Queued => {
                if let Err(e) = job_store
                    .fail(
                        job.public_id,
                        "server restarted before processing — please retry",
                    )
                    .await
                {
                    eprintln!(
                        "boot_resume_jobs: fail({}) failed: {} (continuing)",
                        job.public_id, e
                    );
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
