//! Tests for the circuit-digest self-heal (`self_heal.rs`).
//!
//! Two tiers:
//!
//! * **Pure**: [`reset_decision`] and [`reset_proof_store_dir`] are
//!   build-free and I/O-light, so they are exhaustively unit-tested
//!   (every match arm, every filesystem outcome) without a circuit build
//!   or a database.
//! * **Integration**: [`heal_circuit_digest`] is driven against a
//!   per-test Postgres schema (shared `postgres:17` container, issue
//!   #181 Opt B) with SYNTHETIC digests + a stub canary outcome — the
//!   heal logic never needs a real `Prover`, so the tests stay fast
//!   while exercising every decision path end-to-end (rows actually
//!   wiped / preserved / baselined, digest actually stored, both
//!   detectors driven).
//!
//! This file is excluded from the coverage measurement (the gate's
//! `--ignore-filename-regex` matches `_tests\.rs$`); it exists to drive
//! the gated `self_heal.rs` to 100% lines + functions. The real
//! canary-recursion detector ([`AccountNode::canary_recursion`]) is
//! validated by the live boot-gate repro against the DEV dump documented
//! in the PR; here it is stubbed because building the ~14 s circuit (and
//! a recursable proof) inside a unit test is neither cheap nor what this
//! module's logic needs to cover.

use super::*;
use crate::v11::{
    claim_stack_scan_mode, set_process_stack_mode, ScanStackMode,
};
use crate::account_node::CanaryOutcome;
use crate::test_db::setup_pool;

// ----------------------------------------------------------------------
// reset_decision — pure, every match arm
// ----------------------------------------------------------------------

#[test]
fn reset_decision_equal_digest_is_keep() {
    // Persisted digest equals the live one: proofs compatible, no reset.
    // The canary is ignored on this branch (detector 1 wins).
    let digest = vec![1u8, 2, 3, 4];
    assert_eq!(
        reset_decision(Some(&digest), &digest, CanaryOutcome::NoSample),
        ResetDecision::Keep
    );
    assert_eq!(
        reset_decision(Some(&digest), &digest, CanaryOutcome::Stale),
        ResetDecision::Keep,
        "a matching digest keeps regardless of the canary signal"
    );
}

#[test]
fn reset_decision_different_digest_is_reset() {
    // Persisted digest differs: detector 1 trips a reset, canary ignored.
    assert_eq!(
        reset_decision(
            Some(b"old-digest"),
            b"new-digest",
            CanaryOutcome::Compatible
        ),
        ResetDecision::Reset
    );
}

#[test]
fn reset_decision_same_length_different_bytes_is_reset() {
    // Equal length, differing content → byte-for-byte comparison resets.
    assert_eq!(
        reset_decision(Some(&[0u8; 4]), &[0u8, 0, 0, 1], CanaryOutcome::Compatible),
        ResetDecision::Reset
    );
}

#[test]
fn reset_decision_no_digest_compatible_canary_is_baseline() {
    // No baseline + the canary recurses cleanly: record baseline.
    assert_eq!(
        reset_decision(None, b"live-digest", CanaryOutcome::Compatible),
        ResetDecision::Baseline
    );
}

#[test]
fn reset_decision_no_digest_no_sample_is_baseline() {
    // No baseline + nothing to probe (fresh DB): record baseline.
    assert_eq!(
        reset_decision(None, b"live-digest", CanaryOutcome::NoSample),
        ResetDecision::Baseline
    );
}

#[test]
fn reset_decision_no_digest_stale_canary_is_reset() {
    // No baseline BUT a persisted proof failed to recurse (adoption
    // boundary): reset.
    assert_eq!(
        reset_decision(None, b"live-digest", CanaryOutcome::Stale),
        ResetDecision::Reset
    );
}

// ----------------------------------------------------------------------
// reset_proof_store_dir — pure-ish (tempdir), every outcome
// ----------------------------------------------------------------------

#[test]
fn reset_proof_store_dir_removes_existing_dir_with_files() {
    let dir = tempfile::tempdir().expect("tempdir");
    let proofs = dir.path().join("proofs");
    std::fs::create_dir_all(&proofs).expect("mkdir proofs");
    std::fs::write(proofs.join("0.bin"), b"stale-proof").expect("write proof file");
    assert!(proofs.exists());

    reset_proof_store_dir(proofs.to_str().unwrap()).expect("remove ok");

    assert!(!proofs.exists(), "proof-store dir must be gone after reset");
}

#[test]
fn reset_proof_store_dir_missing_dir_is_ok() {
    let dir = tempfile::tempdir().expect("tempdir");
    let missing = dir.path().join("does-not-exist");
    assert!(!missing.exists());

    // NotFound is mapped to Ok — nothing to clean is success.
    reset_proof_store_dir(missing.to_str().unwrap()).expect("missing dir is ok");
}

#[test]
fn reset_proof_store_dir_propagates_non_notfound_error() {
    // A path whose PARENT is a regular file (not a directory) makes
    // `remove_dir_all` fail with an error that is NOT NotFound
    // (NotADirectory / other), exercising the error-propagation arm.
    let dir = tempfile::tempdir().expect("tempdir");
    let file = dir.path().join("regular-file");
    std::fs::write(&file, b"i am a file").expect("write file");
    let bogus = file.join("child"); // <file>/child — parent is a file

    let err = reset_proof_store_dir(bogus.to_str().unwrap())
        .expect_err("removing a path under a regular file must error");
    assert_ne!(
        err.kind(),
        std::io::ErrorKind::NotFound,
        "error must be the propagated non-NotFound variant, got {:?}",
        err
    );
}

// ----------------------------------------------------------------------
// heal_circuit_digest — integration against per-test Postgres schema,
// synthetic digests + stub canary (no Prover build needed)
// ----------------------------------------------------------------------

/// Seed one account + an SMT/MMR snapshot so the Reset path has
/// something to actually wipe.
async fn seed_proof_dependent_state(pool: &sqlx::PgPool) {
    // `accounts.address` stores the 64-byte `owner ‖ asset_id` composite
    // key since migration 0017 (`accounts_address_length` CHECK = 64);
    // the synthetic blob does not need to decode, but the key must be a
    // well-formed composite.
    let owner = zkcoins_program::hash::digest_from_bytes(&[7u8; 32]);
    let asset_id = zkcoins_program::hash::digest_from_bytes(&[8u8; 32]);
    let key = crate::account_node::account_key_bytes(&owner, &asset_id);
    db::upsert_account(pool, &key, b"stale-account-blob")
        .await
        .expect("seed account");
    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0x10u8; 32]);
    let smt_root = zkcoins_program::hash::digest_from_bytes(&[0x20u8; 32]);
    claim_stack_scan_mode(pool, ScanStackMode::Legacy)
        .await
        .expect("claim legacy for self_heal seed");
    db::persist_state_tx(
        pool,
        b"smt-blob",
        b"mmr-blob",
        &[0xCCu8; 32],
        Some((&prev_root, &smt_root, 3)),
    )
    .await
    .expect("seed state");
}

async fn count_accounts(pool: &sqlx::PgPool) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM accounts")
        .fetch_one(pool)
        .await
        .expect("count accounts");
    n
}

/// A canary stub that fails the test if it is ever called — used to
/// assert the digest-present fast path never runs the (expensive) probe.
fn canary_must_not_run() -> CanaryOutcome {
    panic!("canary must NOT run when a digest is already persisted");
}

#[tokio::test]
async fn heal_baseline_compatible_canary_stores_digest_without_wiping_state() {
    // No persisted digest, the canary recurses cleanly (Compatible):
    // record baseline, do NOT wipe.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_dir = proofs.path().to_str().unwrap();

    seed_proof_dependent_state(&pool).await;
    assert_eq!(count_accounts(&pool).await, 1);

    let live = b"digest-A";
    let decision = heal_circuit_digest(&pool, live, proofs_dir, &|| CanaryOutcome::Compatible)
        .await
        .expect("heal ok");

    assert_eq!(decision, ResetDecision::Baseline);
    assert_eq!(
        db::load_circuit_digest(&pool).await.unwrap().as_deref(),
        Some(&live[..])
    );
    assert_eq!(count_accounts(&pool).await, 1);
}

#[tokio::test]
async fn clear_circuit_digest_removes_the_persisted_row_idempotently() {
    // The runtime prover-health watchdog clears the persisted digest to
    // arm the boot self-heal. After clearing, `load_circuit_digest` must
    // return `None` so the next boot routes through the canary branch
    // (not the `Keep` fast path); a second clear is a no-op.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    db::store_circuit_digest(&pool, b"live-digest")
        .await
        .expect("store digest");
    assert!(db::load_circuit_digest(&pool).await.unwrap().is_some());

    db::clear_circuit_digest(&pool).await.expect("clear digest");
    assert_eq!(db::load_circuit_digest(&pool).await.unwrap(), None);

    // Idempotent: clearing an already-absent row succeeds and stays None.
    db::clear_circuit_digest(&pool)
        .await
        .expect("clear digest (idempotent)");
    assert_eq!(db::load_circuit_digest(&pool).await.unwrap(), None);
}

#[tokio::test]
async fn heal_baseline_no_sample_records_digest() {
    // No persisted digest and the canary has no sample (truly fresh DB):
    // baseline. Drives the `NoSample` arm.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_dir = proofs.path().to_str().unwrap();

    let live = b"fresh-digest";
    let decision = heal_circuit_digest(&pool, live, proofs_dir, &|| CanaryOutcome::NoSample)
        .await
        .expect("heal ok");

    assert_eq!(decision, ResetDecision::Baseline);
    assert_eq!(
        db::load_circuit_digest(&pool).await.unwrap().as_deref(),
        Some(&live[..])
    );
}

#[tokio::test]
async fn heal_keep_leaves_everything_untouched_and_skips_canary() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_dir = proofs.path().to_str().unwrap();

    let live = b"digest-MATCH";
    db::store_circuit_digest(&pool, live)
        .await
        .expect("store digest");
    seed_proof_dependent_state(&pool).await;
    assert_eq!(count_accounts(&pool).await, 1);

    // The canary panics if run — a persisted digest is present, so
    // detector 2 must be skipped and the matching digest keeps.
    let decision = heal_circuit_digest(&pool, live, proofs_dir, &canary_must_not_run)
        .await
        .expect("heal ok");

    assert_eq!(decision, ResetDecision::Keep);
    assert_eq!(
        db::load_circuit_digest(&pool).await.unwrap().as_deref(),
        Some(&live[..])
    );
    assert_eq!(count_accounts(&pool).await, 1);
}

#[tokio::test]
async fn heal_reset_on_digest_mismatch_wipes_state_and_skips_canary() {
    // Detector 1: a persisted digest differs from the live one. Wipe,
    // and the canary must NOT run (detector 1 is authoritative).
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_subdir = proofs.path().join("proofs");
    std::fs::create_dir_all(&proofs_subdir).expect("mkdir");
    std::fs::write(proofs_subdir.join("0.bin"), b"stale").expect("write");
    let proofs_dir = proofs_subdir.to_str().unwrap();

    db::store_circuit_digest(&pool, b"OLD")
        .await
        .expect("store old");
    seed_proof_dependent_state(&pool).await;
    assert_eq!(count_accounts(&pool).await, 1);

    let decision = heal_circuit_digest(&pool, b"NEW", proofs_dir, &canary_must_not_run)
        .await
        .expect("heal ok");

    assert_eq!(decision, ResetDecision::Reset);
    assert_eq!(count_accounts(&pool).await, 0, "stale account discarded");
    assert_eq!(db::load_smt(&pool).await.unwrap(), None);
    assert_eq!(db::load_mmr(&pool).await.unwrap(), None);
    assert_eq!(db::load_latest_block(&pool).await.unwrap(), None);
    assert!(db::load_root_indices(&pool).await.unwrap().is_empty());
    assert_eq!(
        db::load_circuit_digest(&pool).await.unwrap().as_deref(),
        Some(&b"NEW"[..])
    );
    assert!(!proofs_subdir.exists(), "proof-store dir wiped");
}

/// Defect 2 (round 6): under a v1.1 process claim, Reset must clear
/// legacy proof-bearing `accounts` (what the reset exists to drop) while
/// leaving structures v1.1 does not use (SMT/MMR/latest_block) intact.
#[tokio::test]
async fn heal_reset_under_v11_clears_accounts_preserves_unused_legacy_structures() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_subdir = proofs.path().join("proofs");
    std::fs::create_dir_all(&proofs_subdir).expect("mkdir");
    std::fs::write(proofs_subdir.join("0.bin"), b"stale").expect("write");
    let proofs_dir = proofs_subdir.to_str().unwrap();

    // Claim v1.1 (empty DB). Seed proof-bearing accounts + orphan SMT/MMR
    // rows via raw SQL (structures v1.1 does not use — must survive reset).
    claim_stack_scan_mode(&pool, ScanStackMode::V11)
        .await
        .expect("claim v11");
    set_process_stack_mode(ScanStackMode::V11);

    let owner = zkcoins_program::hash::digest_from_bytes(&[7u8; 32]);
    let asset_id = zkcoins_program::hash::digest_from_bytes(&[8u8; 32]);
    let key = crate::account_node::account_key_bytes(&owner, &asset_id);
    db::upsert_account(&pool, &key, b"stale-v11-account-blob")
        .await
        .expect("seed account under v11");
    // Bypass stack writers: raw insert of structures v1.1 never reads.
    sqlx::query(
        "INSERT INTO smt_state (id, data, updated_at) VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data",
    )
    .bind([0x51u8; 8].as_slice())
    .execute(&pool)
    .await
    .expect("seed smt_state");
    sqlx::query(
        "INSERT INTO mmr_state (id, data, updated_at) VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data",
    )
    .bind([0x52u8; 8].as_slice())
    .execute(&pool)
    .await
    .expect("seed mmr_state");
    sqlx::query(
        "INSERT INTO latest_block (id, block_hash, updated_at) VALUES (1, $1, NOW()) \
         ON CONFLICT (id) DO UPDATE SET block_hash = EXCLUDED.block_hash",
    )
    .bind([0x53u8; 32].as_slice())
    .execute(&pool)
    .await
    .expect("seed latest_block");

    db::store_circuit_digest(&pool, b"OLD-V11")
        .await
        .expect("store old digest");
    assert_eq!(count_accounts(&pool).await, 1);

    let decision = heal_circuit_digest(&pool, b"NEW-V11", proofs_dir, &canary_must_not_run)
        .await
        .expect("heal ok under v11");

    assert_eq!(decision, ResetDecision::Reset);
    assert_eq!(
        count_accounts(&pool).await,
        0,
        "v1.1 reset must clear legacy proof-bearing accounts"
    );
    assert_eq!(
        db::load_circuit_digest(&pool).await.unwrap().as_deref(),
        Some(&b"NEW-V11"[..]),
        "digest must update"
    );
    // Structures v1.1 does not use must remain (not a full legacy wipe).
    assert_eq!(
        db::load_smt(&pool).await.unwrap().as_deref(),
        Some([0x51u8; 8].as_slice()),
        "smt_state must be preserved under v1.1 reset"
    );
    assert_eq!(
        db::load_mmr(&pool).await.unwrap().as_deref(),
        Some([0x52u8; 8].as_slice()),
        "mmr_state must be preserved under v1.1 reset"
    );
    assert_eq!(
        db::load_latest_block(&pool).await.unwrap(),
        Some([0x53u8; 32]),
        "latest_block must be preserved under v1.1 reset"
    );
    assert!(!proofs_subdir.exists(), "proof-store dir wiped");
}

#[tokio::test]
async fn heal_reset_on_adoption_boundary_stale_canary() {
    // THE adoption-boundary case (the real DEV-dump scenario): NO
    // persisted digest, but the canary recursion of a persisted proof
    // fails (Stale). Detector 2 trips a full reset so the next mint/send
    // proves on the clean Initial branch.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_dir = proofs.path().to_str().unwrap();

    seed_proof_dependent_state(&pool).await;
    assert_eq!(count_accounts(&pool).await, 1);

    let live = b"current-digest";
    let decision = heal_circuit_digest(&pool, live, proofs_dir, &|| CanaryOutcome::Stale)
        .await
        .expect("heal ok");

    assert_eq!(decision, ResetDecision::Reset);
    assert_eq!(count_accounts(&pool).await, 0, "stale account wiped");
    assert_eq!(db::load_smt(&pool).await.unwrap(), None);
    assert_eq!(
        db::load_circuit_digest(&pool).await.unwrap().as_deref(),
        Some(&live[..])
    );
}

#[tokio::test]
async fn heal_reset_swallows_proof_store_cleanup_error() {
    // The Postgres reset is transactional and must succeed; a failure to
    // drop the proof-store directory is logged and swallowed. Point the
    // proofs_dir at a path under a regular file so `remove_dir_all`
    // returns a non-NotFound error; heal must still return Ok(Reset).
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let tmp = tempfile::tempdir().expect("tempdir");
    let file = tmp.path().join("not-a-dir");
    std::fs::write(&file, b"file").expect("write file");
    let bogus = file.join("child");
    let bogus_dir = bogus.to_str().unwrap();

    db::store_circuit_digest(&pool, b"OLD")
        .await
        .expect("store old");
    seed_proof_dependent_state(&pool).await;

    let decision = heal_circuit_digest(&pool, b"NEW", bogus_dir, &canary_must_not_run)
        .await
        .expect("heal still Ok despite proof-store cleanup error");

    assert_eq!(decision, ResetDecision::Reset);
    assert_eq!(count_accounts(&pool).await, 0);
}

#[tokio::test]
async fn heal_propagates_db_error() {
    // A DB error on the digest load aborts and propagates.
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(std::time::Duration::from_millis(100))
        .connect_lazy("postgres://postgres:postgres@127.0.0.1:1/postgres")
        .expect("connect_lazy never fails");

    let err = heal_circuit_digest(&pool, b"live", "/tmp/whatever", &|| CanaryOutcome::NoSample)
        .await
        .expect_err("heal must fail when DB is unreachable");
    assert!(
        matches!(
            err,
            sqlx::Error::PoolTimedOut | sqlx::Error::Io(_) | sqlx::Error::Database(_)
        ),
        "unexpected error: {:?}",
        err
    );
}

// The two tests below cover the `?` error-propagation arms of the
// `db::*` calls INSIDE `heal_circuit_digest` (the digest load succeeds, a
// LATER call fails). Each manipulates the schema after the digest load so
// the targeted inner query errors on a live connection — the only way to
// reach these arms without a flaky mid-flight disconnect.

#[tokio::test]
async fn heal_propagates_error_from_store_digest_on_baseline() {
    // Baseline path (no persisted digest, canary NoSample) →
    // `db::store_circuit_digest` runs. The digest LOAD must still succeed
    // (return None), so we cannot drop the table — instead install a
    // BEFORE INSERT trigger that raises, so SELECT (the load) works but
    // INSERT (the store) errors and the `?` on `db::store_circuit_digest`
    // propagates.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    sqlx::query(
        "CREATE FUNCTION reject_digest_insert() RETURNS trigger AS \
         $$ BEGIN RAISE EXCEPTION 'no inserts allowed'; END; $$ LANGUAGE plpgsql",
    )
    .execute(&pool)
    .await
    .expect("create trigger fn");
    sqlx::query(
        "CREATE TRIGGER reject_digest_insert_trg BEFORE INSERT ON circuit_digest_meta \
         FOR EACH ROW EXECUTE FUNCTION reject_digest_insert()",
    )
    .execute(&pool)
    .await
    .expect("create trigger");

    let err = heal_circuit_digest(&pool, b"live", "/tmp/whatever", &|| CanaryOutcome::NoSample)
        .await
        .expect_err("heal must propagate the store-digest error");
    assert!(
        matches!(err, sqlx::Error::Database(_)),
        "unexpected: {:?}",
        err
    );
}

#[tokio::test]
async fn heal_propagates_error_from_reset_tx() {
    // Detector 1 trips a reset (persisted digest differs). Drop the
    // `accounts` table so the reset transaction's DELETE errors and the
    // `?` on `db::reset_proof_dependent_state_tx` propagates. Claim the
    // legacy stack first so the failure is the DROP (not the capability
    // gate — that path has its own test).
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_stack_scan_mode(&pool, ScanStackMode::Legacy)
        .await
        .expect("claim legacy for reset-error test");
    db::store_circuit_digest(&pool, b"OLD")
        .await
        .expect("store old digest");
    sqlx::query("DROP TABLE accounts CASCADE")
        .execute(&pool)
        .await
        .expect("drop accounts");

    let err = heal_circuit_digest(&pool, b"NEW", "/tmp/whatever", &canary_must_not_run)
        .await
        .expect_err("heal must propagate the reset-tx error");
    assert!(
        matches!(err, sqlx::Error::Database(_)),
        "unexpected: {:?}",
        err
    );
}
