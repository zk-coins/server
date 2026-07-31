//! Binary entrypoint for `node`.
//!
//! Modules live in `lib.rs`; this file only wires the bootstrap
//! (panic hook, Postgres pool, scanner task, REST listener) together.
//! Splitting the modules out of the binary lets out-of-tree
//! integration tests (`node/tests/api_remote.rs`) import the
//! handler response types and the `CoinProof` struct without
//! duplicating definitions or making the binary itself reachable
//! from a `cargo test --test ...` target.

// mimalloc replaces the default allocator process-wide. Scoped to the
// binary (`main.rs`) so the `node` library crate, integration tests,
// and the `program-plonky2` / `script-plonky2` crates continue to use
// the system allocator — keeps unit-test behaviour identical to CI
// and avoids pulling a C build dependency into every test target.
// See the comment on the `mimalloc` line in `node/Cargo.toml` for the
// rationale.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use node::account_node;
use node::db;
use node::kernel_rpc;
use node::runtime::{
    require_chain_identity_ops_from_env, start_rest_node, RestNodeConfig, V1Readiness,
};
use node::state::State;
use node::username;
use node::v1::{self, ScanStackMode, V1ShadowMode};
use node::DATABASE_URL;
use std::error::Error as StdError;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

// Postgres state-layer carries every persistent slice of node state
// after PR-A3: SMT / MMR / latest_block (PR-A2), accounts + usernames
// (PR-A3), and the minting account's `minting_meta.num_pubkeys` counter
// (PR-A3). The `accounts.bin`, `usernames.bin`, and
// `minting_num_pubkeys.bin` sibling files no longer exist, and the
// `atomic_write` helper that supported them is removed — the only
// remaining on-disk writes are the per-proof files under
// `${PROOFS_DIR:-./proofs}/{id}.bin`, owned by `ProofStore` in
// `router.rs`.
const ACCOUNT_NODE_ADDR: &str = "0.0.0.0:4242";

use bitcoin::hashes::Hash;
use bitcoin::BlockHash;

#[tokio::main]
async fn main() -> Result<(), Box<dyn StdError>> {
    // A panic in any tokio worker — for example the bootstrap task that
    // owns the HTTP listener — by default only kills that task. The rest
    // of the process (notably the chain scanner) keeps running, the
    // container stays `Up`, but the REST port is never bound. Cloudflare
    // sees the upstream as alive-but-unresponsive and serves 502s for
    // hours. Override the panic hook so any panic anywhere aborts the
    // whole process; `restart: unless-stopped` in compose then crash-
    // loops the container until the underlying cause is fixed, which is
    // far easier to spot than a silent zombie.
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        default_panic_hook(info);
        std::process::exit(1);
    }));

    // Install a `tracing` subscriber so the API handlers' structured
    // `tracing::info!` / `tracing::error!` calls actually emit. Without
    // a subscriber every `tracing::*` macro is a silent no-op, which
    // would drop the request-path logs entirely after the migration
    // away from `eprintln!`. The `fmt` layer writes to stdout and the
    // `env-filter` layer honours `RUST_LOG` (default `info`, matching
    // the previous documented baseline in `CONTRIBUTING.md`). Both
    // crates are direct deps in `node/Cargo.toml`.
    //
    // `try_init` (not `init`) so a test binary that already installed
    // its own subscriber — or a second main invocation in a test
    // harness — does not panic the bootstrap.
    //
    // Partial-migration subscriber: routes `tracing::*` calls through fmt+EnvFilter.
    // Many call sites in this crate still use `println!`/`eprintln!` (see TODO in
    // scanner_ws.rs:11). Those continue to write directly to stdout/stderr and are
    // not affected by RUST_LOG. The 4xx-validation paths in router.rs and
    // account_node.rs are the first wave of the migration.
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(env_filter)
        .with_target(false)
        .try_init();

    // Fail-loud on the kernel gRPC bind address before any expensive
    // bootstrap work. `KERNEL_GRPC_ADDR` has no default host/port
    // (same posture as `DATABASE_URL` / `PUBLISHER_KEY`). The listener
    // itself is spawned later next to the REST router.
    let kernel_grpc_addr = kernel_rpc::kernel_grpc_addr_from_env().unwrap_or_else(|e| {
        panic!("{e}");
    });

    // GetInfo operational pins (relay / blossom / max_blob_bytes /
    // kernel_parts): required, no defaults — same posture as the gRPC
    // addr. Missing variable names itself. A complete ChainIdentity still
    // needs a signed §4.3 BootstrapManifest (not loadable yet); that one
    // field keeps GetInfo fail-closed after boot, without inventing URLs.
    require_chain_identity_ops_from_env().unwrap_or_else(|e| {
        panic!("{e}");
    });

    // Open the Postgres pool and run pending migrations BEFORE any
    // state load — `connect_and_migrate` is idempotent (sqlx tracks
    // applied migrations in `_sqlx_migrations`) and so safe to call on
    // every boot. A connect failure here aborts the whole bootstrap;
    // there is no useful "degraded" mode without persistent state.
    let pool = Arc::new(
        db::connect_and_migrate(&DATABASE_URL)
            .await
            .expect("connect and migrate database"),
    );
    println!("Connected to Postgres state-layer");

    // Cutover Stage 3 — **atomic default switch**.
    //
    // The production binary always claims the exclusive v1 stack
    // (AggregateStateNullifierV3 → NfLog). There is no dual-stack
    // fall-back to the legacy Commitment/SMT scanner or to
    // `Prover::new()` / `circuit::main`. Missing §3.6 pins fail loud.
    //
    // `ZKCOINS_V1_SHADOW=off` is refused at the binary edge: Stage 3
    // makes the legacy prover unreachable from this path, not merely
    // unused. Legacy code remains in the tree for Stage 4 deletion and
    // for unit tests that construct `AccountNode::new()` explicitly.
    let shadow_mode = v1::mode::v1_shadow_mode_from_env().unwrap_or_else(|e| {
        panic!("{e}");
    });
    match shadow_mode {
        V1ShadowMode::On => {}
        V1ShadowMode::Off => {
            panic!(
                "Stage 3 binary refuses the legacy dual stack \
                 (ZKCOINS_V1_SHADOW unset/empty/off). Set ZKCOINS_V1_SHADOW=1 \
                 and the §3.6 pin env vars. Rollback after cutover requires a \
                 pre-cutover DB restore — not a flag flip (wallets may already \
                 have published v1 nullifiers)."
            );
        }
    }

    // Exclusive claim before any NfLog write.
    v1::enforce_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("v1 stack separation gate");
    println!(
        "Stage 3 v1 stack: AggregateStateNullifierV3 publisher + NfLog scanner; \
         prove path = StateEngine / ProverBridge (legacy Prover::new is not on \
         the binary path)"
    );
    let v1_adapter = Arc::new(
        node::v1::EngineAdapter::load_or_create_from_env((*pool).clone())
            .await
            .expect("v1 EngineAdapter bootstrap"),
    );
    println!(
        "v1 EngineAdapter ready (network={:?}, activation_height={})",
        v1_adapter.network(),
        v1_adapter.activation_height()
    );

    // Stage 3: do **not** call `Prover::new()`. The legacy AccountNode
    // ledger is still rehydrated for residual balance/history REST, but
    // without a legacy circuit. Prove work is Engine/Bridge only.
    let state = Arc::new(Mutex::new(
        State::load_from_pg(&pool)
            .await
            .expect("load state from Postgres"),
    ));
    println!("Loaded State from Postgres (residual SMT/MMR tables; v1 uses NfLog)");

    let account_node = account_node::AccountNode::load_ledger_from_pg(Arc::clone(&state), &pool)
        .await
        .expect("load account node ledger from Postgres (no legacy Prover)");
    println!("Loaded AccountNode ledger (no Prover::new)");

    // Self-heal: digest = tagged §1.7.1 `C || C_balance` of the circuits
    // just built through ProverBridge; canary = v1 structural / slow path.
    // On mismatch this uses the G5 generation fence (`reset_v1_proof_dependent_state_tx`):
    // bump `self_heal_reset_meta.generation`, fail non-terminal jobs (leave
    // their `reset_generation` behind the live epoch), wipe v1 proof state.
    // Jobs in flight across the reset cannot advance (generation CAS).
    let proofs_dir = std::env::var("PROOFS_DIR").unwrap_or_else(|_| "./proofs".to_string());

    let pins = v1::mode::v1_boot_pins_from_env().expect("v1 pins re-read after adapter boot");
    let live_digest = v1::resolve_v1_live_digest(
        pins.network,
        &pins.network_params.circuit_digest_c(),
        &pins.network_params.circuit_digest_c_balance(),
    )
    .unwrap_or_else(|e| {
        panic!("v1 live circuit digest (just-built circuit vs §3.6 pins): {e}");
    });
    println!(
        "v1 self-heal: live digest = tagged C||C_balance from the circuits \
         just built through ProverBridge (matched §3.6 pins at construction; \
         set ZKCOINS_V1_SLOW_CANARY=1 for verify_transition canary)"
    );
    let heal_decision =
        node::self_heal::heal_circuit_digest(&pool, &live_digest, &proofs_dir, &|| {
            v1::v1_canary_for_heal(&v1_adapter)
        })
        .await
        .expect("v1 circuit-digest self-heal");
    println!("Circuit-digest self-heal: {:?}", heal_decision);

    // On a reset the in-memory ledger + engine were rehydrated from
    // pre-reset rows; reload empty genesis and re-init the engine.
    // Jobs that were in flight across the reset are left behind the
    // G5 generation fence (failed + pre-bump reset_generation) and
    // cannot complete against wiped state.
    // `state` is owned by AccountNode after load; the outer Arc is only
    // needed when reloading after a self-heal wipe (and by the residual
    // uncalled legacy scan function).
    let account_node = if heal_decision == node::self_heal::ResetDecision::Reset {
        let state = Arc::new(Mutex::new(
            State::load_from_pg(&pool)
                .await
                .expect("reload state after self-heal reset"),
        ));
        let account_node =
            account_node::AccountNode::load_ledger_from_pg(Arc::clone(&state), &pool)
                .await
                .expect("reload account node ledger after self-heal reset");
        v1_adapter
            .reinit_after_self_heal_reset()
            .await
            .expect("reinit v1 engine after self-heal reset");
        println!(
            "Re-inited v1 EngineAdapter + AccountNode ledger to empty genesis after self-heal reset"
        );
        account_node
    } else {
        // Drop the outer state Arc — AccountNode already holds its clone.
        drop(state);
        account_node
    };

    let username_store = username::UsernameStore::load_from_pg(&pool)
        .await
        .expect("load username store from Postgres");
    println!("Loaded UsernameStore from Postgres");

    // Spawn the account_node as a separate task. A bootstrap error
    // here (Postgres unreachable, listener bind failure) used to be
    // `eprintln!`'d and dropped on the floor by this `tokio::spawn`
    // block — the scanner kept running, the container stayed `Up`,
    // and Cloudflare served 502s for hours because nothing was bound
    // to the listener port. Aborting the whole process on bootstrap
    // failure means the orchestrator crash-loops the container and
    // alerting fires on the loop, matching the panic-hook behaviour
    // above (zk-coins/node#89 round-2 MAJOR 2).
    let pool_for_rest = Arc::clone(&pool);
    // Stage 3: always exclusive NfLog stack. REST binds before the scanner
    // connects/catches up; `/health/ready` stays 503 until the first
    // successful apply and trips on `finality_broken`.
    let caught_up = Arc::new(AtomicBool::new(false));
    let finality_ok = Arc::new(AtomicBool::new(true));
    let v1_readiness = V1Readiness {
        scan_caught_up: Some(Arc::clone(&caught_up)),
        finality_ok: Some(Arc::clone(&finality_ok)),
    };
    let v1_scan_caught_up = Some(caught_up);
    let v1_finality_ok = Some(finality_ok);
    // `proofs_dir` was already read at the binary edge above (for the
    // self-heal proof-store cleanup) and is moved into the spawned
    // task here. `start_rest_node` no longer touches `std::env` so the
    // runtime tests can each pass their own `tempfile::tempdir()` path
    // instead of racing on the process-wide env var under
    // `--test-threads=8` (issue #181 Opt A).
    let v1_engine_for_rest = Some(Arc::clone(&v1_adapter));

    // Boot-time pending-publish resume **before** REST accepts work. If the
    // node cannot determine whether mid-flight AggregateStateNullifierV3
    // publishes remain (or cannot recover them when the publisher is up),
    // refuse to bind the listener — never a short window of accept-then-exit.
    boot_resume_pending_publishes(&v1_adapter, pins.network).await?;

    // REST + kernel.v1 gRPC share one job store / notify map inside
    // `start_rest_node` (StreamJob must see dispatcher phase events).
    // `KERNEL_GRPC_ADDR` was validated at boot — no default host/port.
    tokio::spawn(async move {
        if let Err(e) = start_rest_node(RestNodeConfig {
            account_node,
            username_store,
            addr: ACCOUNT_NODE_ADDR.to_string(),
            pool: pool_for_rest,
            proofs_dir,
            v1_readiness,
            v1_engine: v1_engine_for_rest,
            kernel_grpc_addr,
        })
        .await
        {
            eprintln!("Account node error: {}", e);
            std::process::exit(1);
        }
    });

    // In-process resumer for members_ready / progressive rows left after a
    // failed finalise handoff. Own task — must not share the scan loop's
    // await points (a hung bitcoind scan must not delay rebroadcast, and a
    // slow rebroadcast must not block tip fold).
    {
        let adapter_for_resumer = Arc::clone(&v1_adapter);
        let network = pins.network;
        tokio::spawn(async move {
            run_pending_publish_resumer(adapter_for_resumer, network).await;
        });
    }

    // Stage 3: only the v1 NfLog scanner. The legacy Commitment/SMT
    // Esplora path lives behind `LegacyCommitmentScanCap` (sealed; no
    // production mint) — not reachable from this binary.
    run_v1_scan_loop(v1_adapter, v1_scan_caught_up, v1_finality_ok).await?;
    Ok(())
}

/// Interval for the in-process AggregateStateNullifierV3 pending-publish
/// resumer.
///
/// Matches the v1 scan-loop idle backoff (`Duration::from_secs(5)` after each
/// successful `scan_to_tip`) and the recon incomplete-view backoff
/// (`RECON_RETRY_BACKOFF` in [`run_v1_scan_loop`]) so a stranded
/// `members_ready` row is retried on the same order of magnitude as tip
/// observation — without a tight spin that would flood logs on a permanent
/// publisher / bitcoind outage.
const PENDING_PUBLISH_RESUME_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// Boot-time resume of durable AggregateStateNullifierV3 publishes left
/// mid-flight by a previous crash (or a failed finalise handoff).
///
/// Fail-closed: publisher connect failure with pending work is fatal; a
/// non-determinable pending-row list is fatal (never treated as empty).
/// With a confirmed empty table, connect failure is logged loud and boot
/// continues (receive/finalise paths will need the publisher later).
async fn boot_resume_pending_publishes(
    adapter: &node::v1::EngineAdapter,
    network: zkcoins_program::circuit::compliance::Network,
) -> Result<(), Box<dyn StdError>> {
    use v1::{connect_v1_publisher, resume_all_pending_publishes, v1_publisher_env_from_env};

    match v1_publisher_env_from_env(network) {
        Ok(env) => match connect_v1_publisher(env) {
            Ok(publisher) => match resume_all_pending_publishes(adapter, &publisher).await {
                Ok(0) => println!("v1.1 resume_all_pending_publishes: nothing pending"),
                Ok(n) => {
                    println!("v1.1 resume_all_pending_publishes: completed {n} pending publish(es)")
                }
                Err(e) => {
                    return Err(format!(
                        "v1.1 resume_all_pending_publishes failed: {e:#} — refusing to \
                         continue with unrecovered mid-flight nullifier publishes"
                    )
                    .into());
                }
            },
            Err(e) => {
                let pending =
                    match node::v1::db_v1::list_resumable_pending_publishes(adapter.pool()).await {
                        Ok(rows) => rows.len(),
                        Err(list_err) => {
                            return Err(format!(
                                "v1.1 publisher connect failed and resumable pending \
                             publishes are not determinable ({list_err:#}); original \
                             connect error: {e:#} — refusing to start without \
                             knowing whether mid-flight nullifier publishes remain"
                            )
                            .into());
                        }
                    };
                if pending > 0 {
                    return Err(format!(
                        "v1.1 publisher connect failed with {pending} resumable \
                         pending publish(es): {e:#}"
                    )
                    .into());
                }
                eprintln!(
                    "v1.1 publisher connect failed (no pending publishes; continuing boot): {e:#}"
                );
            }
        },
        Err(e) => {
            let pending =
                match node::v1::db_v1::list_resumable_pending_publishes(adapter.pool()).await {
                    Ok(rows) => rows.len(),
                    Err(list_err) => {
                        return Err(format!(
                            "v1.1 publisher env incomplete and resumable pending \
                         publishes are not determinable ({list_err:#}); original \
                         env error: {e:#} — refusing to start without \
                         knowing whether mid-flight nullifier publishes remain"
                        )
                        .into());
                    }
                };
            if pending > 0 {
                return Err(format!(
                    "v1.1 publisher env incomplete with {pending} resumable \
                     pending publish(es): {e:#}"
                )
                .into());
            }
            eprintln!(
                "v1.1 publisher env incomplete (no pending publishes; continuing boot): {e:#}"
            );
        }
    }
    Ok(())
}

/// Periodic in-process resumer: same work as boot [`boot_resume_pending_publishes`],
/// without aborting the process on a single failed sweep.
///
/// On durable publisher / bitcoind outage the open row count is logged and the
/// next interval retries — never silent drop, never tight-loop flood.
async fn run_pending_publish_resumer(
    adapter: Arc<node::v1::EngineAdapter>,
    network: zkcoins_program::circuit::compliance::Network,
) {
    use v1::{connect_v1_publisher, resume_all_pending_publishes, v1_publisher_env_from_env};

    loop {
        // scanner-polling-ok: pending-publish resume idle backoff (same form
        // as v1 scan_to_tip idle sleep — named const, not a magic body literal)
        tokio::time::sleep(PENDING_PUBLISH_RESUME_INTERVAL).await;

        // Fail-closed list: undeterminable is an error, not "nothing pending".
        let open = match node::v1::db_v1::list_resumable_pending_publishes(adapter.pool()).await {
            Ok(rows) => rows.len(),
            Err(list_err) => {
                eprintln!(
                    "v1.1 pending-publish resumer: open rows not determinable \
                     ({list_err:#}) — not treating as empty; will retry next interval"
                );
                continue;
            }
        };
        if open == 0 {
            continue;
        }

        let env = match v1_publisher_env_from_env(network) {
            Ok(env) => env,
            Err(e) => {
                eprintln!(
                    "v1.1 pending-publish resumer: {open} open row(s); publisher \
                     env incomplete ({e:#}) — will retry next interval"
                );
                continue;
            }
        };
        let publisher = match connect_v1_publisher(env) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "v1.1 pending-publish resumer: {open} open row(s); publisher \
                     connect failed ({e:#}) — will retry next interval"
                );
                continue;
            }
        };

        // Same pickup path as boot — no second rebroadcast logic beside
        // `resume_all_pending_publishes` / `resume_pending_publish`.
        match resume_all_pending_publishes(adapter.as_ref(), &publisher).await {
            Ok(0) => {
                // Listed open rows, then none completed: another writer may
                // have advanced them between list and resume, or statuses
                // moved to non-resumable. Log the earlier open count.
                println!(
                    "v1.1 pending-publish resumer: saw {open} open row(s); \
                     resume pass completed 0 (rows may have advanced concurrently)"
                );
            }
            Ok(n) => println!(
                "v1.1 pending-publish resumer: completed {n} of {open} open pending publish(es)"
            ),
            Err(e) => {
                eprintln!(
                    "v1.1 pending-publish resumer: failed with {open} open row(s) \
                     still pending ({e:#}) — will retry next interval; rows left as-is"
                );
            }
        }
    }
}

/// Stage 2 v1.1 exclusive scan loop: bitcoind RPC + script-plonky2
/// [`zkcoins_prover::scanner::Scanner`] → NfLog fold on [`EngineAdapter`].
///
/// **Never** falls back to the Esplora Commitment scanner. Missing RPC
/// pins, connect failures, or infrastructure errors abort the process.
///
/// ## Reorg (live)
/// When `scan_to_tip` reports a reorg, the full post-reorg survivor stream
/// replaces the engine NfLog ([`v1::apply_canonical_survivors`]). Forward
/// progress without reorg appends only newly seen survivors.
/// `ReorgOutcome::finality_broken` stops crediting and fails readiness.
///
/// ## Reorg (restart while down)
/// A fresh scanner has no checkpoint, so a reorg that happened offline is
/// invisible to `report.reorg`. Reconciliation and the first scan are
/// therefore **one observation**: scan first, reconcile the persisted tip
/// against that scan's tip, re-verify the tip is unchanged, then apply
/// from the same survivors. A reorg between a free-standing recon and a
/// later scan cannot slip through — there is no free-standing recon.
async fn run_v1_scan_loop(
    adapter: Arc<node::v1::EngineAdapter>,
    scan_caught_up: Option<Arc<AtomicBool>>,
    finality_ok: Option<Arc<AtomicBool>>,
) -> Result<(), Box<dyn StdError>> {
    use std::collections::HashSet;
    use std::time::Duration;
    use v1::{
        first_boot_requires_full_replace, folded_keys_from_nflog_mirror,
        observation_tip_still_live, reconcile_persisted_tip, PersistedTipReconciliation,
        TipReconcileOutcome,
    };

    let pins = v1::mode::v1_boot_pins_from_env().map_err(|e| e.to_string())?;
    let (rpc_url, cookie_path) = v1::scan::v1_bitcoind_rpc_from_env().map_err(|e| e.to_string())?;

    let scanner_config = zkcoins_prover::scanner::ScannerConfig {
        rpc_url: rpc_url.clone(),
        cookie_path: cookie_path.clone(),
        network: pins.network,
        activation_height: pins.activation_height,
        network_params: pins.network_params.clone(),
        expected_params_identifier: pins.expected_params_identifier,
    };

    println!(
        "v1.1 scanner: connecting bitcoind RPC for AggregateStateNullifierV3 / NfLog \
         (network={:?}, activation_height={})",
        pins.network, pins.activation_height
    );

    // Boot-time pending-publish resume runs in `main` *before* REST bind
    // (and a periodic resumer runs beside this loop). The scanner path
    // only folds NfLog — it must not be the sole pickup for stranded
    // members_ready rows.

    // Connect is synchronous (blocking RPC). Keep it off the async worker.
    let mut scanner = tokio::task::spawn_blocking(move || {
        zkcoins_prover::scanner::Scanner::connect(scanner_config)
    })
    .await
    .map_err(|e| format!("v1.1 scanner connect join: {e}"))?
    .map_err(|e| {
        format!(
            "v1.1 Scanner::connect failed: {e:#} — refusing to fall back to the \
             legacy Esplora commitment scanner"
        )
    })?;

    // Track which survivor chain positions we have already folded so a
    // re-scan of the same tip does not re-append (append_nullifier is
    // strict). Reorg / full-replace clears this set and rebuilds.
    let mut folded_keys: HashSet<(u64, u32, u32, u32, [u8; 32])> = HashSet::new();
    // First observation unit not yet committed: recon + first scan share
    // one tip. After commit, the scanner has a checkpoint and `report.reorg`
    // is trustworthy.
    let mut boot_observation_committed = false;
    let activation_height = pins.activation_height;
    // Transient incomplete-view backoff (RPC behind). Not a chain-tip poll.
    const RECON_RETRY_BACKOFF: Duration = Duration::from_secs(5);

    loop {
        let scan_result = tokio::task::spawn_blocking(move || {
            let report = scanner.scan_to_tip();
            (scanner, report)
        })
        .await
        .map_err(|e| format!("v1.1 scan_to_tip join: {e}"))?;

        scanner = scan_result.0;
        let report = match scan_result.1 {
            Ok(r) => r,
            Err(e) => {
                // Infrastructure failure: fail loud (no legacy fall-back).
                return Err(format!(
                    "v1.1 scanner infrastructure failure: {e:#} — refusing to \
                     fall back to the legacy commitment scanner"
                )
                .into());
            }
        };

        // §3.9: finality_broken means callers must stop crediting and
        // readiness must fail. Honour the contract — do not continue the
        // fold loop after a deep reorg displaces final positions.
        if let Some(ref reorg) = report.reorg {
            if reorg.finality_broken {
                if let Some(flag) = &finality_ok {
                    flag.store(false, Ordering::SeqCst);
                }
                return Err(format!(
                    "v1.1 scanner: FINALITY BROKEN after reorg \
                     (displaced_final_count={}) — stopping NfLog credit and \
                     failing readiness (deep_reorg). Manual recovery required; \
                     refusing to continue folding",
                    reorg.displaced_final_count
                )
                .into());
            }
        }

        let tip = scanner
            .scanned_through()
            .ok_or("v1.1 scanner has no scanned_through tip after successful scan_to_tip")?;
        let tip_height = tip.0;
        let tip_hash = tip.1.to_byte_array();
        // Scanner streams only: accepted inscriptions + survivors. Expansion
        // and coupling live inside apply_canonical_survivors /
        // apply_forward_scan (immediately before mutate) so a second caller
        // cannot skip them. The binary does not re-derive the fold source.
        let accepted_inscriptions = scanner.accepted_inscriptions().to_vec();
        let survivors = scanner.survivors().to_vec();

        // —— Boot observation unit: bind recon to THIS scan's tip ——
        // Window is closed, not narrowed: we never seed folded keys or
        // choose forward vs full-replace from a recon that observed a
        // different chain than the survivors we are about to apply.
        let mut force_full_replace = report.reorg.is_some();
        if !boot_observation_committed {
            let persisted_height = adapter.with_engine(|e| e.tip_height());
            let persisted_hash = adapter.tip_hash();
            let scan_tip_height = tip_height;
            let scan_tip_hash = tip_hash;
            let rpc_url_b = rpc_url.clone();
            let cookie_path_b = cookie_path.clone();

            let recon_result = tokio::task::spawn_blocking(move || {
                use bitcoincore_rpc::RpcApi;
                use v1::scan::ResolvedBlock;

                let open_client = || {
                    bitcoincore_rpc::Client::new(
                        rpc_url_b.trim_end_matches('/'),
                        bitcoincore_rpc::Auth::CookieFile(cookie_path_b.clone()),
                    )
                    .map_err(|e| anyhow::anyhow!("bitcoind RPC open for tip recon: {e}"))
                };

                // Recon classifies against the **immutable ancestry of the
                // captured scan-tip hash** (resolve by hash / prev links) —
                // never against mutable getblockhash(height) of the live tip.
                // A→B→A cannot flip StillCanonical under a fixed observation.
                let resolve_hash = |block_hash: [u8; 32]| -> anyhow::Result<Option<ResolvedBlock>> {
                    let client = open_client()?;
                    let bh = BlockHash::from_byte_array(block_hash);
                    match client.get_block_header_info(&bh) {
                        Ok(info) => {
                            let height = u64::try_from(info.height).map_err(|_| {
                                anyhow::anyhow!(
                                    "getblockheader height {} does not fit u64",
                                    info.height
                                )
                            })?;
                            let prev_hash = info
                                .previous_block_hash
                                .map(|p| p.to_byte_array())
                                .unwrap_or([0u8; 32]);
                            Ok(Some(ResolvedBlock { height, prev_hash }))
                        }
                        Err(e) => {
                            let msg = e.to_string();
                            let unknown = msg.contains("Block not found")
                                || msg.contains("Block header not found")
                                || msg.contains("not found")
                                || msg.contains("-5");
                            if unknown {
                                Ok(None)
                            } else {
                                Err(anyhow::anyhow!("getblockheader for tip recon: {e}"))
                            }
                        }
                    }
                };

                let live_node_height = {
                    let client = open_client()?;
                    client
                        .get_block_count()
                        .map_err(|e| anyhow::anyhow!("getblockcount for tip recon: {e}"))?
                };

                let outcome = reconcile_persisted_tip(
                    persisted_height,
                    persisted_hash,
                    activation_height,
                    scan_tip_height,
                    scan_tip_hash,
                    live_node_height,
                    resolve_hash,
                )?;

                // Secondary pin: if the live tip at the scan height moved
                // away from the captured scan hash, re-observe. Not the
                // A→B→A defence (that is ancestry-based recon above).
                let live_at_scan = {
                    let client = open_client()?;
                    let tip = client
                        .get_block_count()
                        .map_err(|e| anyhow::anyhow!("getblockcount for tip pin: {e}"))?;
                    if scan_tip_height > tip {
                        None
                    } else {
                        let hash = client.get_block_hash(scan_tip_height).map_err(|e| {
                            anyhow::anyhow!("getblockhash({scan_tip_height}) for tip pin: {e}")
                        })?;
                        Some(hash.to_byte_array())
                    }
                };
                let stable = observation_tip_still_live(scan_tip_hash, live_at_scan);
                Ok::<_, anyhow::Error>((outcome, stable))
            })
            .await
            .map_err(|e| format!("v1.1 tip reconciliation join: {e}"))?;

            let (outcome, tip_stable) = match recon_result {
                Ok(v) => v,
                Err(e) => {
                    // Fatal only (deep reorg / unresolvable / corruption).
                    if let Some(flag) = &finality_ok {
                        flag.store(false, Ordering::SeqCst);
                    }
                    return Err(format!("v1.1 tip reconciliation failed: {e:#}").into());
                }
            };

            if !tip_stable {
                println!(
                    "v1.1 boot tip: scan tip height={} hash={} moved during \
                     reconciliation — discarding observation and retrying \
                     (bound recon+scan window closed, not narrowed)",
                    tip_height,
                    hex::encode(tip_hash)
                );
                // scanner-polling-ok: v1 bound-observation tip-stability retry
                tokio::time::sleep(RECON_RETRY_BACKOFF).await;
                continue;
            }

            match outcome {
                TipReconcileOutcome::RetryableIncompleteView {
                    queried_height,
                    detail,
                } => {
                    // Transient: RPC behind. Stay unready, leave finality_ok
                    // alone, never assume canonical or divergent.
                    println!(
                        "v1.1 boot tip: incomplete live view at height \
                         {queried_height} — {detail}; staying unready and retrying"
                    );
                    // scanner-polling-ok: v1 incomplete-view RPC-behind backoff
                    tokio::time::sleep(RECON_RETRY_BACKOFF).await;
                    continue;
                }
                TipReconcileOutcome::Ready(PersistedTipReconciliation::Fresh) => {
                    println!(
                        "v1.1 boot tip: fresh engine (no persisted tip); applying \
                         first scan observation (tip={tip_height})"
                    );
                }
                TipReconcileOutcome::Ready(PersistedTipReconciliation::StillCanonical {
                    tip_height: ph,
                    tip_hash: p_hash,
                }) => {
                    let mirror = adapter.with_engine(|e| e.nflog_mirror());
                    folded_keys = folded_keys_from_nflog_mirror(&mirror);
                    println!(
                        "v1.1 boot tip: still canonical at height={} hash={} \
                         (seeded {} folded keys; bound to scan tip={tip_height})",
                        ph,
                        hex::encode(p_hash),
                        folded_keys.len()
                    );
                }
                TipReconcileOutcome::Ready(PersistedTipReconciliation::ShallowReorg {
                    ancestor_height,
                    ancestor_hash,
                    reorg_depth,
                    persisted_height,
                    persisted_hash,
                }) => {
                    force_full_replace = true;
                    println!(
                        "v1.1 boot tip: shallow offline reorg depth={} (persisted \
                         height={} hash={} → common ancestor height={} hash={}); \
                         full-replace NfLog from this scan's survivors (bound \
                         observation; §3.9 ≤5-block window)",
                        reorg_depth,
                        persisted_height,
                        hex::encode(persisted_hash),
                        ancestor_height,
                        hex::encode(ancestor_hash)
                    );
                    debug_assert!(first_boot_requires_full_replace(
                        &PersistedTipReconciliation::ShallowReorg {
                            ancestor_height,
                            ancestor_hash,
                            reorg_depth,
                            persisted_height,
                            persisted_hash,
                        }
                    ));
                }
            }
            boot_observation_committed = true;
        }

        let do_full_replace = force_full_replace;
        if do_full_replace {
            // Full replace: scanner survivors + accepted inscriptions are the
            // canonical streams (catalog carries losers NfLog ignores).
            // Expansion + coupling run inside apply (sole fold source).
            let stats = v1::apply_canonical_survivors(
                &adapter,
                tip_height,
                tip_hash,
                &survivors,
                &accepted_inscriptions,
            )
            .await
            .map_err(|e| format!("v1.1 reorg/full-replace NfLog apply failed: {e:#}"))?;
            folded_keys.clear();
            for nf in &survivors {
                folded_keys.insert((
                    nf.chain_pos.height,
                    nf.chain_pos.tx_index,
                    nf.chain_pos.vin_index,
                    nf.chain_pos.member_index,
                    nf.pk,
                ));
            }
            println!(
                "v1.1 scanner full-replace applied: tip={} hash={} appended={} dup_ignored={}",
                tip_height, tip.1, stats.appended, stats.duplicate_ignored
            );
        } else {
            // Gate only: apply_forward_scan owns expansion, coupling, and the
            // fold delta against `folded_keys`. Catalog delta is crate-private.
            let has_new = survivors.iter().any(|nf| {
                !folded_keys.contains(&(
                    nf.chain_pos.height,
                    nf.chain_pos.tx_index,
                    nf.chain_pos.vin_index,
                    nf.chain_pos.member_index,
                    nf.pk,
                ))
            });
            if has_new || tip_height > adapter.with_engine(|e| e.tip_height()) {
                let stats = v1::apply_forward_scan(
                    &adapter,
                    tip_height,
                    tip_hash,
                    &survivors,
                    &accepted_inscriptions,
                    &folded_keys,
                )
                .await
                .map_err(|e| format!("v1.1 forward NfLog apply failed: {e:#}"))?;
                for nf in &survivors {
                    folded_keys.insert((
                        nf.chain_pos.height,
                        nf.chain_pos.tx_index,
                        nf.chain_pos.vin_index,
                        nf.chain_pos.member_index,
                        nf.pk,
                    ));
                }
                if stats.appended > 0 || stats.duplicate_ignored > 0 {
                    println!(
                        "v1.1 scanner folded: tip={} appended={} dup_ignored={} below_act={}",
                        tip_height, stats.appended, stats.duplicate_ignored, stats.below_activation
                    );
                }
            }
        }

        // First successful catch-up after a committed boot observation:
        // mark readiness so load balancers can send traffic once the NfLog
        // view reflects the chain tip. Incomplete-view retries never reach
        // here (they `continue` before apply / before this flag).
        if let Some(flag) = &scan_caught_up {
            if !flag.load(Ordering::SeqCst) {
                flag.store(true, Ordering::SeqCst);
                println!("v1.1 scanner: catch-up complete; readiness may pass v1_scan gate");
            }
        }

        // Event-driven tip advance is owned by bitcoind; poll interval is a
        // last-resort backoff between successful scan_to_tip calls (no
        // Esplora WS on this path). Marked so CI lint grandfathering matches
        // scanner_runtime's HTTP backoff token style.
        // scanner-polling-ok: v1 bitcoind scan_to_tip idle backoff
        tokio::time::sleep(Duration::from_secs(5)).await;
    }
}
