//! Smoke tests that exercise the runtime bootstrap end-to-end.
//!
//! `runtime.rs` itself is excluded from the coverage scope (it
//! binds a real socket and owns the process lifecycle), but its
//! bootstrap path carries regressions that the 100% MVP-scope gate
//! cannot catch. Each test here covers a specific failure mode that
//! production has hit (or would hit on the next migration in the same
//! class):
//!
//! - `start_rest_node_binds_and_serves_health` — the Plonky2-migration
//!   outage. An `assert_eq!` against `MINTING_ADDRESS` panicked the
//!   tokio worker that owned the HTTP listener while the scanner worker
//!   kept running. Container stayed `Up`, Cloudflare served 502s for
//!   hours. The test probes `/health`; a bootstrap panic manifests as
//!   a TCP connect timeout and fails the test with a clear diagnostic.
//!
//! - `bootstrap_initial_minting_account_balance_is_goldilocks_safe` —
//!   guards the `1u64 << 48` constant for the seeded minting balance.
//!   `u64::MAX` (the pre-Plonky2 value) reduces mod the Goldilocks
//!   prime inside the state-transition circuit and trips a
//!   "wire set twice" panic on every mint. The test probes
//!   `/api/balance?address=<MINTING_ADDRESS hex>` and asserts the
//!   returned balance stays in the Goldilocks-safe range.
//!
//! Both tests share the same probe-port / spawn / wait / cleanup
//! shape; once a third bootstrap test lands the duplicated setup is
//! worth extracting into a helper.

use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::account_node::AccountNode;
use crate::job_store::{
    CreateResult, FinaliseClaim, JobKind, JobStatus, JobStore, FINALISE_CLAIM_PHASE,
};
use crate::runtime::{
    boot_finalise_action_after_release, boot_finalise_disposition, boot_resume_jobs,
    start_rest_node, BootFinaliseAction, BootRowDisposition,
};
use crate::state::State;
use crate::test_db::setup_pool;
use crate::username::UsernameStore;
use crate::v1::{set_process_stack_mode, ScanStackMode};
use dashmap::DashMap;

// Shared-Postgres test infra (issue #181 Optimisation B): see
// `crate::test_db`. The previous file-local `setup_pool` is gone
// in favour of the shared helper; callers now keep the
// `SchemaScope` alive for the test's lifetime so its `Drop` can
// clean up the per-test schema after teardown.

/// Initialise the process-wide env vars the bootstrap reads through
/// `lazy_static` cells (`NETWORK_CONFIG`, `USERNAME_DOMAIN`) and the
/// `ZKCOINS_SKIP_BOOTSTRAP_WARMUP` opt-out exactly once per test
/// binary. The lazy_static cells freeze the values they observe on
/// first touch, so racing two `set_var` callers from different tests
/// is a use-after-free in spirit — issue #181 Opt A flips
/// `--test-threads=8`, which makes that race deterministic.
///
/// `OnceLock` gives a single "happens-before" barrier: the first
/// caller through here runs the `set_var` block, every subsequent
/// caller observes the initialised cell and returns immediately
/// without touching env. The `set_var` calls themselves are
/// idempotent — they only set if currently unset — so a host that
/// exports these via the pre-push hook keeps its own values.
///
/// `PROOFS_DIR` is intentionally NOT set here. Each test passes its
/// own `tempfile::tempdir()` path into `start_rest_node` as a
/// parameter so parallel tests cannot trample each other's proof
/// store. The env-read used to live inside `runtime::start_rest_node`;
/// it now lives at the binary edge in `main.rs` only.
fn ensure_test_env() {
    static INIT: OnceLock<()> = OnceLock::new();
    INIT.get_or_init(|| {
        // Set each var only if currently unset — preserves whatever
        // the pre-push hook / CI workflow exported.
        let defaults: &[(&str, &str)] = &[
            ("USERNAME_DOMAIN", "test.zkcoins.local"),
            ("IS_MAINNET", "false"),
            ("ESPLORA_URL", "http://127.0.0.1:1/api"),
            ("ESPLORA_WS_URL", "ws://127.0.0.1:1/api/v1/ws"),
            // Smoke tests only need the listener to bind and serve
            // `/health` / `/api/balance`; they MUST NOT pay the
            // ~7 s background warmup tax (would double pre-push
            // wall and add nothing to the bootstrap failure-mode
            // coverage this file owns). With this flag set,
            // `prover_warm` is flipped to `true` immediately at
            // bootstrap and no `spawn_blocking` task is started.
            ("ZKCOINS_SKIP_BOOTSTRAP_WARMUP", "1"),
        ];
        for (k, v) in defaults {
            if std::env::var_os(k).is_none() {
                std::env::set_var(k, v);
            }
        }
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn start_rest_node_binds_and_serves_health() {
    // Pick a free ephemeral port by binding/dropping a probe listener.
    // The race window between drop and rebind is irrelevant in CI and
    // pre-push (no other process listens on this port); a collision
    // would surface as a deterministic bind error below, not silent
    // corruption.
    let probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind probe");
    let port = probe.local_addr().expect("probe addr").port();
    drop(probe);
    let addr = format!("127.0.0.1:{}", port);

    // Process-wide env init (idempotent + once-only). Replaces the
    // earlier per-test `std::env::set_var` block — under
    // `--test-threads=8` (issue #181 Opt A) two concurrent tests
    // would race on the lazy_static-frozen NETWORK_CONFIG values.
    ensure_test_env();

    // Per-test proofs dir — passed as a parameter to `start_rest_node`
    // so it does NOT touch process-wide env. `tempfile::tempdir`
    // removes the directory on Drop even when the test panics, so no
    // /tmp/zkcoins-* tree leaks on failure.
    let tmp = tempfile::tempdir().expect("create proofs tempdir");
    let proofs_dir = tmp.path().to_string_lossy().into_owned();

    // Mimic main.rs wiring: fresh State and empty AccountNode /
    // UsernameStore, so the bootstrap exercises the "no saved state"
    // branch that was the production failure mode.
    let state = Arc::new(Mutex::new(State::new()));
    let account_node = AccountNode::new(Arc::clone(&state));
    let username_store = UsernameStore::new();

    let scope = setup_pool().await;
    let pool = Arc::new(scope.pool.clone());

    // Ephemeral kernel gRPC port (same race window as the REST probe).
    let grpc_probe = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind grpc probe");
    let kernel_grpc_addr = grpc_probe.local_addr().expect("grpc probe addr");
    drop(grpc_probe);

    let handle = tokio::spawn(async move {
        start_rest_node(crate::runtime::RestNodeConfig {
            account_node,
            username_store,
            addr,
            pool,
            proofs_dir,
            v1_readiness: crate::runtime::V1Readiness::default(),
            v1_engine: None,
            kernel_grpc_addr,
        })
        .await
    });

    // Wait for the listener to come up. axum binds within ~hundreds of
    // ms on a warm cargo cache; cap the wait at 5 s so a regression
    // fails fast instead of hanging the whole suite.
    let mut last_err: Option<std::io::Error> = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        match tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port)).await {
            Ok(mut stream) => {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                stream
                    .write_all(b"GET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
                    .await
                    .expect("write probe");
                let mut buf = vec![0u8; 1024];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                let resp = String::from_utf8_lossy(&buf[..n]).into_owned();
                handle.abort();
                // `tmp` (a `TempDir`) cleans itself up on Drop at
                // function return — no explicit `remove_dir_all`.
                assert!(
                    resp.starts_with("HTTP/1.1 200"),
                    "expected 200 on /health, got: {}",
                    &resp[..resp.len().min(300)]
                );
                // `/health` is the documented liveness probe whose
                // body is the literal string "ok" (see the route
                // registration in `router::create_router`). A 200
                // status with a different body would still satisfy
                // the old assertion but signal a regression in the
                // contract Kuma watches.
                let body = resp
                    .split("\r\n\r\n")
                    .nth(1)
                    .unwrap_or("")
                    .trim_end_matches('\0')
                    .trim();
                assert!(
                    body.starts_with("ok"),
                    "expected /health body to start with `ok`, got: {:?}",
                    body
                );
                return;
            }
            Err(e) => last_err = Some(e),
        }
    }
    handle.abort();
    panic!(
        "start_rest_node never bound on 127.0.0.1:{} within 5 s; last connect error: {:?}",
        port, last_err
    );
}

// Milestone 2 removed the bootstrap minting-account seeding entirely:
// the neutral, permissionless model has no privileged minting account,
// so there is no bootstrap balance to assert Goldilocks-safety on. The
// test that exercised that path
// (`bootstrap_initial_minting_account_balance_is_goldilocks_safe`) is
// gone with it; account balances now only ever come from a
// creator-signed mint into the creator's own account, whose amount is
// bounded by the issuer at request time.

// Phase D removed the startup `check_minting_state_invariant` check.
// `num_pubkeys` is now derived from SMT membership at runtime
// (`state::derive_num_pubkeys_from_smt`), which is the same source the
// pre-Phase-D check measured the counter *against*. With the counter
// and the SMT collapsed into one value the desync mode the check
// guarded against can no longer arise, so the test that exercised the
// `CRITICAL: minting state desync` Err arm is gone too.

static V1_STACK_TEST_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Acquire the process-global stack-mode serialisation lock.
///
/// Held across `.await` points on purpose: these tests touch shared
/// process state (`PROCESS_STACK_MODE` / the shared container) and
/// must not interleave. `tokio::sync::Mutex` is the correct tool for
/// that (unlike `std::sync::MutexGuard`, which is thread-bound).
///
/// `tokio::sync::Mutex` has no poison flag — a panicking holder does
/// not permanently lock out later tests. That resilience used to be
/// expressed via `unwrap_or_else(|poisoned| poisoned.into_inner())` on
/// `std::sync::Mutex`; do not reintroduce a poison recovery path.
async fn lock_v1_stack_for_test() -> tokio::sync::MutexGuard<'static, ()> {
    V1_STACK_TEST_LOCK.lock().await
}

/// Defect 2 (P0): pure decision table — boot action by release result + phase.
#[test]
fn boot_finalise_action_decision_table() {
    // Abandoned claim released → enqueue.
    assert_eq!(
        boot_finalise_action_after_release(true, JobStatus::Broadcasting, "publishing"),
        BootFinaliseAction::EnqueueNow
    );
    // Still exclusively claimed under a live lease → do not enqueue as free.
    assert_eq!(
        boot_finalise_action_after_release(false, JobStatus::Broadcasting, FINALISE_CLAIM_PHASE),
        BootFinaliseAction::DeferUntilAbandoned
    );
    // Already free (nothing to release) → enqueue.
    assert_eq!(
        boot_finalise_action_after_release(false, JobStatus::Broadcasting, "publishing"),
        BootFinaliseAction::EnqueueNow
    );
    assert_eq!(
        boot_finalise_action_after_release(false, JobStatus::Broadcasting, "broadcasting"),
        BootFinaliseAction::EnqueueNow
    );
    // Terminal / wrong status → skip.
    assert_eq!(
        boot_finalise_action_after_release(false, JobStatus::Completed, "completed"),
        BootFinaliseAction::Skip
    );
    // Unknown phase under broadcasting → skip (do not pretend free).
    assert_eq!(
        boot_finalise_action_after_release(false, JobStatus::Broadcasting, "weird_phase"),
        BootFinaliseAction::Skip
    );
}

/// Plant a signed v1.1 job at the host edge under `broadcasting`, with an
/// exclusive finalise claim owned by `claim_owner` and the given lease.
async fn plant_edge_job_with_claim(
    store: &JobStore,
    claim_owner: uuid::Uuid,
    lease: std::time::Duration,
    idem: &str,
) -> uuid::Uuid {
    let result = store
        .create(
            JobKind::Send,
            &[0xEDu8; 32],
            Some(idem),
            serde_json::json!({}),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
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
    let outcome = crate::v1::FinaliseOutcome::from_pending_proof_data_with_publisher(
        &entry.pending,
        entry.publisher_pubkey,
    );
    entry
        .install_completion(outcome.to_result_json(), 200)
        .expect("install completion");
    let persist = crate::v1::DurableFinalisationPersist::from_entry(&entry).expect("encode");

    store
        .set_awaiting_signature(job_id, 1, advertised)
        .await
        .expect("awaiting_signature");
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
        .expect("plant finalisation");

    assert!(
        matches!(
            store
                .claim_finalise_exclusive_as(job_id, claim_owner, lease)
                .await
                .expect("claim"),
            FinaliseClaim::Won { .. }
        ),
        "plant claim must win"
    );
    job_id
}

/// Defect 2 (P0): immediate restart of an edge job whose claim is abandoned
/// (expired lease) must release + enqueue so the dispatcher can drive it —
/// not strand it by pretending a still-owned claim is free, nor skip free work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn immediate_restart_drives_abandoned_edge_job_forward() {
    let _guard = lock_v1_stack_for_test().await;
    set_process_stack_mode(ScanStackMode::V1);

    let scope = setup_pool().await;
    let dead_owner = uuid::Uuid::new_v4();
    let plant_store = JobStore::with_process_owner(scope.pool.clone(), dead_owner);
    let job_id = plant_edge_job_with_claim(
        &plant_store,
        dead_owner,
        std::time::Duration::from_secs(60),
        "k-boot-edge-abandoned",
    )
    .await;

    // Dead process left an exclusive claim; lease is expired → abandonment.
    sqlx::query(
        "UPDATE jobs SET request_body = jsonb_set( \
             COALESCE(request_body, '{}'::jsonb), \
             '{finalise_claim,lease_expires_at}', \
             to_jsonb('1970-01-01T00:00:00Z'::text), \
             true \
         ) WHERE public_id = $1",
    )
    .bind(job_id)
    .execute(plant_store.pool())
    .await
    .expect("expire lease");

    // Fresh process-generation JobStore (immediate restart).
    let boot_store = Arc::new(JobStore::new(scope.pool.clone()));
    let notify_map: Arc<DashMap<uuid::Uuid, Arc<crate::job_dispatcher::JobNotifier>>> =
        Arc::new(DashMap::new());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);

    boot_resume_jobs(&boot_store, &notify_map, &tx)
        .await
        .expect("boot_resume_jobs");

    let env = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("boot must enqueue abandoned edge job within 2s")
        .expect("channel open");
    assert_eq!(env.public_id, job_id, "boot must re-arm the edge job");

    // Claim is free for the new process.
    assert!(
        matches!(
            boot_store
                .claim_finalise_exclusive(job_id)
                .await
                .expect("claim after boot"),
            FinaliseClaim::Won { .. }
        ),
        "claim after boot must win"
    );

    drop(scope);
}

/// Defect 2 (P0): a still-live claim must not be enqueued as free; once the
/// lease expires the deferred reclaim drives the edge job forward.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn live_claim_not_enqueued_then_deferred_reclaim_after_expiry() {
    let _guard = lock_v1_stack_for_test().await;
    set_process_stack_mode(ScanStackMode::V1);

    let scope = setup_pool().await;
    let dead_owner = uuid::Uuid::new_v4();
    let plant_store = JobStore::with_process_owner(scope.pool.clone(), dead_owner);
    // Long enough that boot sees a live lease (not already abandoned).
    let lease = std::time::Duration::from_secs(60);
    let job_id = plant_edge_job_with_claim(
        &plant_store,
        dead_owner,
        lease,
        "k-boot-edge-live-then-expire",
    )
    .await;

    let boot_store = Arc::new(JobStore::new(scope.pool.clone()));
    let notify_map: Arc<DashMap<uuid::Uuid, Arc<crate::job_dispatcher::JobNotifier>>> =
        Arc::new(DashMap::new());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);

    boot_resume_jobs(&boot_store, &notify_map, &tx)
        .await
        .expect("boot_resume_jobs");

    // Immediate: live lease → must NOT enqueue as free.
    let early = tokio::time::timeout(Duration::from_millis(250), rx.recv()).await;
    assert!(
        early.is_err(),
        "live claim must not be enqueued immediately; got {:?}",
        early.ok().flatten().map(|e| e.public_id)
    );

    // Simulate lease expiry (dead owner stopped renewing). Deferred reclaim
    // must then release + enqueue.
    sqlx::query(
        "UPDATE jobs SET request_body = jsonb_set( \
             COALESCE(request_body, '{}'::jsonb), \
             '{finalise_claim,lease_expires_at}', \
             to_jsonb('1970-01-01T00:00:00Z'::text), \
             true \
         ) WHERE public_id = $1",
    )
    .bind(job_id)
    .execute(boot_store.pool())
    .await
    .expect("expire lease after boot");

    let env = tokio::time::timeout(Duration::from_secs(3), rx.recv())
        .await
        .expect("deferred reclaim must enqueue after lease expiry")
        .expect("channel open");
    assert_eq!(env.public_id, job_id);

    assert!(
        matches!(
            boot_store
                .claim_finalise_exclusive(job_id)
                .await
                .expect("claim after deferred reclaim"),
            FinaliseClaim::Won { .. }
        ),
        "claim after deferred reclaim must win"
    );

    drop(scope);
}

/// Defect 2 (P0): a database error at boot leaves the row untouched for
/// retry — pure disposition table (same decisions `boot_resume_jobs` applies).
#[test]
fn boot_db_error_disposition_leaves_row_untouched_for_retry() {
    // release_stale DB error → no mutation, no enqueue, retry later.
    assert_eq!(
        boot_finalise_disposition(Err(()), Ok(None)),
        BootRowDisposition::LeaveUntouchedForRetry
    );
    // release Ok(false) but phase reload DB error → release did not mutate;
    // leave untouched (do not invent free/owned).
    assert_eq!(
        boot_finalise_disposition(Err(()), Err(())),
        BootRowDisposition::LeaveUntouchedForRetry
    );
    assert_eq!(
        boot_finalise_disposition(Ok(false), Err(())),
        BootRowDisposition::LeaveUntouchedForRetry
    );
    // Successful release → enqueue without needing phase (avoids half-handle
    // if a subsequent load would have failed under the old `?` path).
    assert_eq!(
        boot_finalise_disposition(Ok(true), Err(())),
        BootRowDisposition::Act(BootFinaliseAction::EnqueueNow)
    );
    assert_eq!(
        boot_finalise_disposition(Ok(true), Ok(None)),
        BootRowDisposition::Act(BootFinaliseAction::EnqueueNow)
    );
    // Ok(false) + still claimed → defer (not free).
    assert_eq!(
        boot_finalise_disposition(Ok(false), Ok(Some(FINALISE_CLAIM_PHASE))),
        BootRowDisposition::Act(BootFinaliseAction::DeferUntilAbandoned)
    );
    // Ok(false) + free phase → enqueue.
    assert_eq!(
        boot_finalise_disposition(Ok(false), Ok(Some("publishing"))),
        BootRowDisposition::Act(BootFinaliseAction::EnqueueNow)
    );
    // Ok(false) + vanished → skip.
    assert_eq!(
        boot_finalise_disposition(Ok(false), Ok(None)),
        BootRowDisposition::Act(BootFinaliseAction::Skip)
    );
}

/// Defect 2 (P0): free-phase edge job (no exclusive claim) is enqueued even
/// though `release_stale` returns `Ok(false)` — nothing to release is not
/// ownership.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn free_phase_edge_job_enqueued_despite_release_false() {
    let _guard = lock_v1_stack_for_test().await;
    set_process_stack_mode(ScanStackMode::V1);

    let scope = setup_pool().await;
    let store = JobStore::new(scope.pool.clone());
    let job_id = plant_edge_job_with_claim(
        &store,
        store.process_owner(),
        std::time::Duration::from_secs(60),
        "k-boot-edge-free-phase",
    )
    .await;
    // Strip claim → phase `publishing`, still broadcasting + signed capability.
    // (Force strip: live lease would refuse release_stale; free phase is the
    // state under test, not the release path.)
    sqlx::query(
        "UPDATE jobs SET phase = 'publishing', \
                request_body = COALESCE(request_body, '{}'::jsonb) - 'finalise_claim' \
         WHERE public_id = $1",
    )
    .bind(job_id)
    .execute(store.pool())
    .await
    .expect("force free phase");
    assert!(
        !store
            .release_stale_finalise_claim(job_id)
            .await
            .expect("release on free phase"),
        "precondition: free phase yields Ok(false) from release_stale"
    );

    let boot_store = Arc::new(JobStore::new(scope.pool.clone()));
    let notify_map: Arc<DashMap<uuid::Uuid, Arc<crate::job_dispatcher::JobNotifier>>> =
        Arc::new(DashMap::new());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);

    boot_resume_jobs(&boot_store, &notify_map, &tx)
        .await
        .expect("boot_resume_jobs");

    let env = tokio::time::timeout(Duration::from_secs(2), rx.recv())
        .await
        .expect("free-phase edge job must be enqueued")
        .expect("channel open");
    assert_eq!(env.public_id, job_id);

    drop(scope);
}

/// P0: `boot_resume_jobs` must not terminate a job that was claimed after
/// the interrupted-list snapshot was taken. Bare `fail` would rewrite any
/// row by `public_id`; the boot path uses `fail_if_status` against the
/// snapshot status (and refuses [`FINALISE_CLAIM_PHASE`]).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn boot_resume_cannot_fail_job_claimed_since_snapshot() {
    use std::time::Duration as StdDuration;

    let _guard = lock_v1_stack_for_test().await;
    set_process_stack_mode(ScanStackMode::V1);

    let scope = setup_pool().await;
    let owner = uuid::Uuid::new_v4();
    let store = JobStore::with_process_owner(scope.pool.clone(), owner);

    let result = store
        .create(
            JobKind::Send,
            &[0xB1; 32],
            Some("k-boot-fail-claimed-since-snapshot"),
            serde_json::json!({}),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
    };

    // Snapshot status boot would have observed for an interrupted prove.
    store
        .set_status(job_id, JobStatus::Proving, "proving")
        .await
        .expect("set proving");
    let snapshot_status = JobStatus::Proving;

    // Concurrent progress after the snapshot: advertise → exclusive claim.
    store
        .set_awaiting_signature(job_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");
    let fence = match store
        .claim_finalise_exclusive_as(job_id, owner, StdDuration::from_secs(60))
        .await
        .expect("claim")
    {
        FinaliseClaim::Won { fence } => fence,
        other => panic!("expected Won, got {other:?}"),
    };

    // Exact predicate boot uses for the interrupted non-resumable arm.
    assert!(
        !store
            .fail_if_status(
                job_id,
                &[snapshot_status],
                "server restarted before processing — please retry",
            )
            .await
            .expect("fail_if_status"),
        "snapshot-status fail must be a no-op once the row has moved and been claimed"
    );

    // Full boot path: unsigned claimed broadcasting is not v1-resumable,
    // so it takes the fail arm — which must still refuse the claim.
    let boot_store = Arc::new(JobStore::new(scope.pool.clone()));
    let notify_map: Arc<DashMap<uuid::Uuid, Arc<crate::job_dispatcher::JobNotifier>>> =
        Arc::new(DashMap::new());
    let (tx, mut rx) = tokio::sync::mpsc::channel(8);

    boot_resume_jobs(&boot_store, &notify_map, &tx)
        .await
        .expect("boot_resume_jobs");

    // Must not enqueue (not free) and must not have failed the row.
    let early = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
    assert!(
        early.is_err(),
        "claimed non-resumable job must not be enqueued; got {:?}",
        early.ok().flatten().map(|e| e.public_id)
    );

    let row = boot_store.load(job_id).await.expect("load").expect("row");
    assert_eq!(
        row.status,
        JobStatus::Broadcasting,
        "boot must not fail a job claimed since the snapshot"
    );
    assert_eq!(row.phase, FINALISE_CLAIM_PHASE);
    assert!(
        row.error.is_none(),
        "claimed row must not carry a boot error"
    );
    assert_eq!(
        row.request_body
            .get("finalise_claim")
            .and_then(|c| c.get("fence"))
            .and_then(|f| f.as_i64()),
        Some(fence),
        "claim fence must remain current after boot"
    );

    drop(scope);
}
