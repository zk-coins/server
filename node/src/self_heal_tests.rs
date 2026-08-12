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
//!   while exercising every decision path end-to-end (rows canonically
//!   archived / preserved / baselined, digest actually stored, both
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
use crate::account_node::CanaryOutcome;
use crate::test_db::setup_pool;
use crate::v1::{claim_stack_scan_mode, set_process_stack_mode, ScanStackMode};

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
/// something to archive.
async fn seed_proof_dependent_state(pool: &sqlx::PgPool) {
    // Stage 3 stack separation: exclusive claim before any write to
    // legacy scan/account tables (fail-closed, no claim-from-write).
    claim_stack_scan_mode(pool, ScanStackMode::Legacy)
        .await
        .expect("claim legacy for self_heal seed");
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
    let (n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM accounts \
         WHERE state_epoch = (SELECT epoch FROM derived_state_epoch_meta WHERE id = 1)",
    )
    .fetch_one(pool)
    .await
    .expect("count canonical accounts");
    n
}

async fn count_physical_accounts(pool: &sqlx::PgPool) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM accounts")
        .fetch_one(pool)
        .await
        .expect("count physical accounts");
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
async fn heal_reset_on_digest_mismatch_archives_state_and_skips_canary() {
    // Detector 1: a persisted digest differs from the live one. Archive,
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
    assert_eq!(count_accounts(&pool).await, 0, "canonical account archived");
    assert!(
        count_physical_accounts(&pool).await >= 1,
        "archived account must remain physically stored"
    );
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

/// Under a v1.1 process claim, Reset archives every epoch-scoped v1 and
/// legacy row. The new canonical head is empty while old rows remain stored.
#[tokio::test]
async fn heal_reset_under_v1_archives_all_epoch_scoped_state() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_subdir = proofs.path().join("proofs");
    std::fs::create_dir_all(&proofs_subdir).expect("mkdir");
    std::fs::write(proofs_subdir.join("0.bin"), b"stale").expect("write");
    let proofs_dir = proofs_subdir.to_str().unwrap();

    // Claim v1.1 (empty DB). Seed proof-bearing accounts + orphan SMT/MMR
    // rows via raw SQL; every row must survive physically after reset.
    claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");
    set_process_stack_mode(ScanStackMode::V1);

    // Bypass stack writers: under a v1 claim `db::upsert_account` refuses
    // legacy `accounts` writes (Stage 3 stack separation). Seed the leftover
    // legacy row with raw SQL so the epoch transition has something to archive.
    let owner = zkcoins_program::hash::digest_from_bytes(&[7u8; 32]);
    let asset_id = zkcoins_program::hash::digest_from_bytes(&[8u8; 32]);
    let key = crate::account_node::account_key_bytes(&owner, &asset_id);
    sqlx::query(
        "INSERT INTO accounts (address, data, updated_at) VALUES ($1, $2, NOW()) \
         ON CONFLICT (state_epoch, address) DO UPDATE \
         SET data = EXCLUDED.data, updated_at = NOW()",
    )
    .bind(key.as_slice())
    .bind(b"stale-v1-account-blob".as_slice())
    .execute(&pool)
    .await
    .expect("seed leftover legacy account under v1 via raw SQL");
    // Seed minimal v1 engine meta + one nflog row for archival.
    sqlx::query(
        "INSERT INTO v1_engine_meta \
         (id, network, activation_height, tip_height, tip_hash, fold_seq, updated_at) \
         VALUES (1, 'regtest', 0, 1, $1, 0, NOW())",
    )
    .bind([0xAAu8; 32].as_slice())
    .execute(&pool)
    .await
    .expect("seed v1_engine_meta");
    sqlx::query(
        "INSERT INTO v1_nflog_entries \
         (position, height, tx_index, vin_index, member_index, pk, r) \
         VALUES (0, 1, 0, 0, 0, $1, $2)",
    )
    .bind([0xBBu8; 32].as_slice())
    .bind([0xCCu8; 32].as_slice())
    .execute(&pool)
    .await
    .expect("seed v1_nflog_entries");
    sqlx::query(
        "INSERT INTO v1_accounts \
         (owner, account_state, nk, genesis_pubkey, last_proof, \
          last_nav_opening, last_nullifier, last_nullifier_pos, \
          coin_history_root, updated_at) \
         VALUES ($1, $2, $3, $4, $5, NULL, NULL, NULL, $6, NOW())",
    )
    .bind([0xDDu8; 32].as_slice())
    .bind([0x01u8; 4].as_slice()) // garbage account_state blob — archival only
    .bind([0x02u8; 32].as_slice())
    .bind([0x03u8; 32].as_slice())
    .bind([0x04u8; 8].as_slice()) // last_proof present → proof-bearing
    .bind([0x05u8; 32].as_slice())
    .execute(&pool)
    .await
    .expect("seed v1_accounts");
    // Bypass stack writers: raw insert of structures v1.1 never reads.
    sqlx::query(
        "INSERT INTO smt_state (id, data, updated_at) VALUES (1, $1, NOW()) \
         ON CONFLICT (state_epoch, id) DO UPDATE SET data = EXCLUDED.data",
    )
    .bind([0x51u8; 8].as_slice())
    .execute(&pool)
    .await
    .expect("seed smt_state");
    sqlx::query(
        "INSERT INTO mmr_state (id, data, updated_at) VALUES (1, $1, NOW()) \
         ON CONFLICT (state_epoch, id) DO UPDATE SET data = EXCLUDED.data",
    )
    .bind([0x52u8; 8].as_slice())
    .execute(&pool)
    .await
    .expect("seed mmr_state");
    sqlx::query(
        "INSERT INTO latest_block (id, block_hash, updated_at) VALUES (1, $1, NOW()) \
         ON CONFLICT (state_epoch, id) DO UPDATE SET block_hash = EXCLUDED.block_hash",
    )
    .bind([0x53u8; 32].as_slice())
    .execute(&pool)
    .await
    .expect("seed latest_block");

    // Changed digest (tagged v1 shape so the test documents the real blob).
    let old = crate::v1::encode_v1_live_digest(&[0x11; 32], &[0x22; 32]);
    let new = crate::v1::encode_v1_live_digest(&[0x33; 32], &[0x44; 32]);
    assert_ne!(old, new, "test oracle: digests must differ");
    db::store_circuit_digest(&pool, &old)
        .await
        .expect("store old digest");
    assert_eq!(count_accounts(&pool).await, 1);

    let decision = heal_circuit_digest(&pool, &new, proofs_dir, &canary_must_not_run)
        .await
        .expect("heal ok under v1");

    assert_eq!(decision, ResetDecision::Reset);
    assert_eq!(
        count_accounts(&pool).await,
        0,
        "v1.1 reset must archive legacy proof-bearing accounts (canonical empty)"
    );
    assert!(
        count_physical_accounts(&pool).await >= 1,
        "archived legacy accounts must remain physically stored"
    );
    assert_eq!(
        db::load_circuit_digest(&pool).await.unwrap().as_deref(),
        Some(new.as_slice()),
        "digest must update to the live pin encoding"
    );
    // Canonical head empty after shared-epoch archive (changed digest → reset).
    let (v1_meta,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM v1_engine_meta \
         WHERE state_epoch = (SELECT epoch FROM derived_state_epoch_meta WHERE id = 1)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let (v1_nflog,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM v1_nflog_entries \
         WHERE state_epoch = (SELECT epoch FROM derived_state_epoch_meta WHERE id = 1)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    let (v1_acc,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM v1_accounts \
         WHERE state_epoch = (SELECT epoch FROM derived_state_epoch_meta WHERE id = 1)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        v1_meta, 0,
        "v1_engine_meta archived (canonical epoch empty) on digest mismatch"
    );
    assert_eq!(
        v1_nflog, 0,
        "v1_nflog_entries archived (canonical epoch empty) on digest mismatch"
    );
    assert_eq!(
        v1_acc, 0,
        "v1_accounts archived (canonical epoch empty) on digest mismatch"
    );
    // Physical retention: prior-epoch rows stay stored.
    let (v1_meta_phys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM v1_engine_meta")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (v1_nflog_phys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM v1_nflog_entries")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (v1_acc_phys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM v1_accounts")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        v1_meta_phys >= 1,
        "archived v1_engine_meta must remain physically stored"
    );
    assert!(
        v1_nflog_phys >= 1,
        "archived v1_nflog_entries must remain physically stored"
    );
    assert!(
        v1_acc_phys >= 1,
        "archived v1_accounts must remain physically stored"
    );
    // Shared-epoch archive: legacy smt/mmr/latest_block are canonically empty
    // but rows remain physically stored.
    assert_eq!(
        db::load_smt(&pool).await.unwrap(),
        None,
        "smt_state canonical head empty after shared-epoch archive"
    );
    assert_eq!(
        db::load_mmr(&pool).await.unwrap(),
        None,
        "mmr_state canonical head empty after shared-epoch archive"
    );
    assert_eq!(
        db::load_latest_block(&pool).await.unwrap(),
        None,
        "latest_block canonical head empty after shared-epoch archive"
    );
    let (smt_phys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM smt_state")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (mmr_phys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM mmr_state")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (latest_block_phys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM latest_block")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        smt_phys >= 1,
        "archived smt_state must remain physically stored"
    );
    assert!(
        mmr_phys >= 1,
        "archived mmr_state must remain physically stored"
    );
    assert!(
        latest_block_phys >= 1,
        "archived latest_block must remain physically stored"
    );
    assert!(!proofs_subdir.exists(), "proof-store dir wiped");
}

/// Would go red if a changed digest were treated as Keep / ignored.
#[tokio::test]
async fn heal_v1_changed_digest_triggers_reset_not_ignore() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_dir = proofs.path().to_str().unwrap();

    claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");
    set_process_stack_mode(ScanStackMode::V1);

    let old = crate::v1::encode_v1_live_digest(&[0x01; 32], &[0x02; 32]);
    let new = crate::v1::encode_v1_live_digest(&[0x01; 32], &[0xFF; 32]); // C_balance only
    db::store_circuit_digest(&pool, &old).await.unwrap();

    let decision = heal_circuit_digest(&pool, &new, proofs_dir, &canary_must_not_run)
        .await
        .unwrap();
    assert_eq!(
        decision,
        ResetDecision::Reset,
        "C_balance change alone must reset (not Keep)"
    );
    assert_eq!(
        db::load_circuit_digest(&pool).await.unwrap().as_deref(),
        Some(new.as_slice())
    );
}

/// A v1.1 reset must leave no job that can later report `completed` for a
/// transition whose engine state the reset archived. Plants a `broadcasting`
/// job with durable finalisation + cached `completion_result` (the resume
/// fast path that skips prove/apply), runs a digest-mismatch heal, and
/// asserts the row is `failed` with the finalisation envelope stripped.
///
/// Would go red if reset only archived v1 state and left jobs rows intact.
#[tokio::test]
async fn heal_v1_reset_fails_jobs_so_they_cannot_complete_for_wiped_work() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_dir = proofs.path().to_str().unwrap();

    claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");
    set_process_stack_mode(ScanStackMode::V1);

    let store = crate::job_store::JobStore::new(pool.clone());
    let account = [0xABu8; 32];
    // Durable finalisation with a cached completion_result — exactly the
    // envelope that would let the dispatcher skip prove/apply and mark
    // completed after a cold resume.
    let body = serde_json::json!({
        "finalisation": {
            "network": "regtest",
            "capability_bincode_hex": "00",
            "publisher_pubkey": null,
            "completion_result": {
                "new_account_state_hash": "00".repeat(32),
                "ok": true
            },
            "completion_status": 200
        },
        "finalise_claim": {
            "owner": "00000000-0000-0000-0000-000000000001",
            "fence": 1,
            "lease_expires_at": "2099-01-01T00:00:00Z"
        }
    });
    let created = store
        .create(
            crate::job_store::JobKind::Send,
            &account,
            Some("self-heal-reset-job"),
            body,
        )
        .await
        .expect("create job");
    let job_id = match created {
        crate::job_store::CreateResult::Fresh(j) => j.public_id,
        crate::job_store::CreateResult::IdempotentReplay(j) => j.public_id,
        crate::job_store::CreateResult::IdempotencyConflict => {
            panic!("unexpected IdempotencyConflict")
        }
    };
    store
        .set_status(
            job_id,
            crate::job_store::JobStatus::Queued,
            crate::job_store::JobStatus::Broadcasting,
            crate::job_store::FINALISE_CLAIM_PHASE,
        )
        .await
        .expect("advance to broadcasting + claimed");

    let old = crate::v1::encode_v1_live_digest(&[0x11; 32], &[0x22; 32]);
    let new = crate::v1::encode_v1_live_digest(&[0x33; 32], &[0x44; 32]);
    db::store_circuit_digest(&pool, &old).await.unwrap();

    let decision = heal_circuit_digest(&pool, &new, proofs_dir, &canary_must_not_run)
        .await
        .expect("heal ok");
    assert_eq!(decision, ResetDecision::Reset);

    let row = store.load(job_id).await.expect("load").expect("job row");
    assert_eq!(
        row.status,
        crate::job_store::JobStatus::Failed,
        "reset must terminal-fail the job so resume cannot report completed"
    );
    assert_eq!(
        row.error.as_deref(),
        Some(db::SELF_HEAL_RESET_JOB_ERROR),
        "operator must see the self-heal archive reason"
    );
    assert!(
        row.request_body.get("finalisation").is_none(),
        "finalisation + completion_result must be stripped"
    );
    assert!(
        row.request_body.get("finalise_claim").is_none(),
        "exclusive finalise claim must be stripped"
    );
    // A post-reset complete attempt cannot succeed for a failed row.
    let completed = store
        .complete_if_status(
            job_id,
            &[
                crate::job_store::JobStatus::Broadcasting,
                crate::job_store::JobStatus::Proving,
            ],
            serde_json::json!({"stolen": true}),
            200,
        )
        .await
        .expect("complete_if_status");
    assert!(
        !completed,
        "a failed job must not accept completion after the reset archived its transition"
    );
    let again = store.load(job_id).await.unwrap().unwrap();
    assert_eq!(again.status, crate::job_store::JobStatus::Failed);
    assert_ne!(
        again.status,
        crate::job_store::JobStatus::Completed,
        "job must not report completed for archived work"
    );
}

/// Defect 2: pre-reset worker cannot resurrect a job after the v1.1 reset.
///
/// Interleaving: A loads a queued job → B commits the reset (bumps generation,
/// fails non-terminal) → A calls unconditional `set_status` / `complete`
/// matching `public_id` only. Without the generation fence those writes
/// resurrect the row as proving/completed against archived state.
///
/// Would go red if `set_status` / `complete` matched `public_id` only.
#[tokio::test]
async fn heal_v1_reset_fences_pre_loaded_job_resurrection() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_dir = proofs.path().to_str().unwrap();

    claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");
    set_process_stack_mode(ScanStackMode::V1);

    let store = crate::job_store::JobStore::new(pool.clone());
    let account = [0xCDu8; 32];
    let created = store
        .create(
            crate::job_store::JobKind::Mint,
            &account,
            Some("pre-reset-load"),
            serde_json::json!({}),
        )
        .await
        .expect("create");
    let job = match created {
        crate::job_store::CreateResult::Fresh(j) => j,
        crate::job_store::CreateResult::IdempotentReplay(j) => j,
        crate::job_store::CreateResult::IdempotencyConflict => {
            panic!("unexpected IdempotencyConflict")
        }
    };
    let job_id = job.public_id;
    let gen_before = job.reset_generation;
    // Stage-3 migration 0028 one-shot genesis reset bumps generation at
    // migrate time (sqlx `_sqlx_migrations` — once per DB, not every boot).
    // A post-switch "fresh" migrated schema therefore starts at 1, not 0.
    // Pre-Stage-3 premise "fresh DB starts at generation 0" is stale.
    let live_at_admit = db::load_self_heal_reset_generation(&pool)
        .await
        .expect("load live generation after migrations");
    assert_eq!(
        gen_before, live_at_admit,
        "admitted job must stamp the live meta generation"
    );
    assert_eq!(
        live_at_admit, 1,
        "post-Stage-3 migrated DB starts at generation 1 \
         (0024 seed 0 + 0028 one-shot cutover bump); not re-bumped on boot"
    );

    // Simulate worker A holding the loaded public_id (status still queued).
    let old = crate::v1::encode_v1_live_digest(&[0x01; 32], &[0x02; 32]);
    let new = crate::v1::encode_v1_live_digest(&[0x03; 32], &[0x04; 32]);
    db::store_circuit_digest(&pool, &old).await.unwrap();

    let decision = heal_circuit_digest(&pool, &new, proofs_dir, &canary_must_not_run)
        .await
        .expect("heal ok");
    assert_eq!(decision, ResetDecision::Reset);

    let gen_after = db::load_self_heal_reset_generation(&pool)
        .await
        .expect("load gen");
    assert_eq!(gen_after, gen_before + 1, "reset must bump generation");

    let row = store.load(job_id).await.unwrap().unwrap();
    assert_eq!(row.status, crate::job_store::JobStatus::Failed);
    assert_eq!(
        row.reset_generation, gen_before,
        "failed job keeps its pre-reset generation (left behind the live epoch)"
    );

    // Worker A's set_status must report zero rows and not resurrect.
    let advanced = store
        .set_status(
            job_id,
            crate::job_store::JobStatus::Queued,
            crate::job_store::JobStatus::Proving,
            "proving",
        )
        .await
        .expect("set_status query ok");
    assert!(
        !advanced,
        "set_status must return false when the generation fence matches 0 rows"
    );
    let after_status = store.load(job_id).await.unwrap().unwrap();
    assert_eq!(
        after_status.status,
        crate::job_store::JobStatus::Failed,
        "set_status must not resurrect a pre-reset job after generation bump"
    );

    // Worker A's unconditional complete must report zero rows and not mark
    // completed either.
    let completed = store
        .complete(
            job_id,
            crate::job_store::JobStatus::Queued,
            serde_json::json!({"stolen": true}),
            200,
        )
        .await
        .expect("complete query ok");
    assert!(
        !completed,
        "complete must return false when the generation fence matches 0 rows"
    );
    let after_complete = store.load(job_id).await.unwrap().unwrap();
    assert_eq!(
        after_complete.status,
        crate::job_store::JobStatus::Failed,
        "complete must not succeed for a pre-reset generation"
    );
    assert_ne!(
        after_complete.status,
        crate::job_store::JobStatus::Completed
    );
}

/// Defect 2: a job stamped with a stale generation after the reset cannot
/// complete against archived state (simulates an admit that raced past the
/// fail-UPDATE with a pre-bump generation read).
///
/// Would go red if job-advancing writes ignored `reset_generation`.
#[tokio::test]
async fn heal_v1_reset_fences_stale_generation_admit() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_dir = proofs.path().to_str().unwrap();

    claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");
    set_process_stack_mode(ScanStackMode::V1);

    let old = crate::v1::encode_v1_live_digest(&[0x11; 32], &[0x22; 32]);
    let new = crate::v1::encode_v1_live_digest(&[0x33; 32], &[0x44; 32]);
    db::store_circuit_digest(&pool, &old).await.unwrap();
    let decision = heal_circuit_digest(&pool, &new, proofs_dir, &canary_must_not_run)
        .await
        .expect("heal ok");
    assert_eq!(decision, ResetDecision::Reset);
    let live_gen = db::load_self_heal_reset_generation(&pool).await.unwrap();
    assert!(live_gen > 0);

    // Plant a job with a *stale* generation (the race: INSERT saw old gen).
    let public_id = uuid::Uuid::new_v4();
    let account = [0xEFu8; 32];
    sqlx::query(
        "INSERT INTO jobs \
         (public_id, kind, status, phase, account_address, request_body, reset_generation) \
         VALUES ($1, 'mint', 'queued', 'queued', $2, '{}'::jsonb, $3)",
    )
    .bind(public_id)
    .bind(&account[..])
    .bind(live_gen - 1)
    .execute(&pool)
    .await
    .expect("plant stale-gen job");

    let store = crate::job_store::JobStore::new(pool.clone());
    let stale_advanced = store
        .set_status(
            public_id,
            crate::job_store::JobStatus::Queued,
            crate::job_store::JobStatus::Proving,
            "proving",
        )
        .await
        .expect("set_status query ok");
    assert!(
        !stale_advanced,
        "stale-generation set_status must report 0 rows (false)"
    );
    let completed = store
        .complete(
            public_id,
            crate::job_store::JobStatus::Queued,
            serde_json::json!({"nope": true}),
            200,
        )
        .await
        .expect("complete query ok");
    assert!(!completed, "stale-generation complete must report 0 rows");
    let row = store.load(public_id).await.unwrap().unwrap();
    assert_eq!(
        row.status,
        crate::job_store::JobStatus::Queued,
        "stale-generation job must not advance after reset"
    );
    assert_ne!(row.status, crate::job_store::JobStatus::Completed);

    // A legitimate post-reset admit stamps the live generation and can advance.
    let fresh = store
        .create(
            crate::job_store::JobKind::Mint,
            &account,
            Some("post-reset-fresh"),
            serde_json::json!({}),
        )
        .await
        .expect("create");
    let fresh_job = match fresh {
        crate::job_store::CreateResult::Fresh(j) => j,
        crate::job_store::CreateResult::IdempotentReplay(j) => j,
        crate::job_store::CreateResult::IdempotencyConflict => {
            panic!("unexpected IdempotencyConflict")
        }
    };
    assert_eq!(fresh_job.reset_generation, live_gen);
    let advanced_ok = store
        .set_status(
            fresh_job.public_id,
            crate::job_store::JobStatus::Queued,
            crate::job_store::JobStatus::Proving,
            "proving",
        )
        .await
        .expect("post-reset set_status query");
    assert!(advanced_ok, "live-generation set_status must update 1 row");
    let advanced = store.load(fresh_job.public_id).await.unwrap().unwrap();
    assert_eq!(advanced.status, crate::job_store::JobStatus::Proving);
}

/// Defect 3: legacy reset must fence jobs the same way (generation bump +
/// fail non-terminal + generation fence on advancing writes).
///
/// Would go red if `reset_proof_dependent_state_tx` still left jobs
/// untouched / unfenced.
#[tokio::test]
async fn heal_legacy_reset_fences_pre_loaded_job_resurrection() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_dir = proofs.path().to_str().unwrap();

    claim_stack_scan_mode(&pool, ScanStackMode::Legacy)
        .await
        .expect("claim legacy");
    set_process_stack_mode(ScanStackMode::Legacy);

    let store = crate::job_store::JobStore::new(pool.clone());
    let account = [0x77u8; 32];
    let created = store
        .create(
            crate::job_store::JobKind::Send,
            &account,
            Some("legacy-pre-reset"),
            serde_json::json!({}),
        )
        .await
        .expect("create");
    let job = match created {
        crate::job_store::CreateResult::Fresh(j) => j,
        crate::job_store::CreateResult::IdempotentReplay(j) => j,
        crate::job_store::CreateResult::IdempotencyConflict => {
            panic!("unexpected IdempotencyConflict")
        }
    };
    let job_id = job.public_id;
    let gen_before = job.reset_generation;

    db::store_circuit_digest(&pool, b"OLD-LEGACY")
        .await
        .unwrap();
    let decision = heal_circuit_digest(&pool, b"NEW-LEGACY", proofs_dir, &canary_must_not_run)
        .await
        .expect("heal ok");
    assert_eq!(decision, ResetDecision::Reset);

    let gen_after = db::load_self_heal_reset_generation(&pool).await.unwrap();
    assert_eq!(gen_after, gen_before + 1);

    let row = store.load(job_id).await.unwrap().unwrap();
    assert_eq!(
        row.status,
        crate::job_store::JobStatus::Failed,
        "legacy reset must fail non-terminal jobs"
    );
    assert_eq!(
        row.error.as_deref(),
        Some(db::SELF_HEAL_RESET_JOB_ERROR),
        "operator must see the self-heal archive reason on the legacy path too"
    );

    let resurrected = store
        .set_status(
            job_id,
            crate::job_store::JobStatus::Queued,
            crate::job_store::JobStatus::Proving,
            "proving",
        )
        .await
        .expect("set_status query ok");
    assert!(
        !resurrected,
        "legacy pre-reset set_status must report 0 rows"
    );
    let completed = store
        .complete(
            job_id,
            crate::job_store::JobStatus::Queued,
            serde_json::json!({"legacy_stolen": true}),
            200,
        )
        .await
        .expect("complete query ok");
    assert!(!completed, "legacy pre-reset complete must report 0 rows");
    let after = store.load(job_id).await.unwrap().unwrap();
    assert_eq!(
        after.status,
        crate::job_store::JobStatus::Failed,
        "legacy pre-reset worker must not complete after generation bump"
    );
}

/// Defect 1: admit and reset are mutually exclusive via a row lock on
/// `self_heal_reset_meta`, not merely ordered under MVCC.
///
/// Interleaving that **used** to be possible: reset UPDATE bumps generation
/// (uncommitted) → concurrent `create` reads committed gen via plain SELECT
/// → INSERT stamps the stale gen → reset commits. That window is closed by
/// `SELECT … FOR UPDATE` on admit against the same row the reset UPDATEs.
///
/// This test holds an open bump transaction and shows create only completes
/// after the bump commits, stamping the **new** generation. The old "admit
/// after UPDATE, before COMMIT" race cannot be constructed without the
/// admit blocking on the lock.
#[tokio::test]
async fn heal_admit_blocks_until_open_generation_bump_commits() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    let gen_before = db::load_self_heal_reset_generation(&pool)
        .await
        .expect("load gen");

    // Open reset-shaped tx: bump generation, hold the row lock, do not commit yet.
    let mut reset_tx = pool.begin().await.expect("begin reset tx");
    let bumped = db::bump_self_heal_reset_generation_in_tx(&mut reset_tx)
        .await
        .expect("bump");
    assert_eq!(bumped, gen_before + 1);

    let store = crate::job_store::JobStore::new(pool.clone());
    let account = [0xABu8; 32];
    let create_fut = store.create(
        crate::job_store::JobKind::Mint,
        &account,
        Some("admit-during-open-bump"),
        serde_json::json!({}),
    );

    // While the bump holds FOR UPDATE / exclusive lock, admit must not finish
    // under the old generation. Give it a short window; it should still be
    // pending when we poll with a timeout.
    tokio::pin!(create_fut);
    let blocked =
        tokio::time::timeout(std::time::Duration::from_millis(200), &mut create_fut).await;
    assert!(
        blocked.is_err(),
        "create must block on self_heal_reset_meta while reset holds the row lock"
    );

    // Commit the bump — admit should proceed and stamp the new generation.
    reset_tx.commit().await.expect("commit bump");
    let created = create_fut.await.expect("create after commit");
    let job = match created {
        crate::job_store::CreateResult::Fresh(j) => j,
        crate::job_store::CreateResult::IdempotentReplay(j) => j,
        crate::job_store::CreateResult::IdempotencyConflict => {
            panic!("unexpected IdempotencyConflict")
        }
    };
    assert_eq!(
        job.reset_generation, bumped,
        "admit after open bump must stamp the post-bump generation, never the pre-bump snapshot"
    );
}

/// Defect 1 (advancing writers): `set_status` takes the same meta-row lock as
/// admit before evaluating generation. An open reset bump therefore blocks
/// the advancing write; after commit the write sees the post-bump generation
/// and cannot resurrect a job left behind (or still at gen 0).
///
/// The old interleaving (statement starts with unlocked subquery snapshot of
/// gen 0 → blocks on jobs row → reset commits → UPDATE resumes with stale
/// gen 0 and rewrites reset-failed → broadcasting) cannot be constructed:
/// the write never evaluates generation without holding the meta lock that
/// serialises with the bump.
///
/// Would go red if `set_status` still used an unlocked scalar subquery.
#[tokio::test]
async fn heal_set_status_blocks_until_open_generation_bump_commits() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    let store = crate::job_store::JobStore::new(pool.clone());
    let account = [0xDEu8; 32];
    let created = store
        .create(
            crate::job_store::JobKind::Mint,
            &account,
            Some("advance-during-open-bump"),
            serde_json::json!({}),
        )
        .await
        .expect("create");
    let job = match created {
        crate::job_store::CreateResult::Fresh(j) => j,
        crate::job_store::CreateResult::IdempotentReplay(j) => j,
        crate::job_store::CreateResult::IdempotencyConflict => {
            panic!("unexpected IdempotencyConflict")
        }
    };
    let job_id = job.public_id;
    let gen_before = job.reset_generation;

    // Open reset-shaped tx: bump + fail non-terminal (same order as production
    // reset), hold locks, do not commit yet.
    let mut reset_tx = pool.begin().await.expect("begin reset tx");
    let bumped = db::bump_self_heal_reset_generation_in_tx(&mut reset_tx)
        .await
        .expect("bump");
    assert_eq!(bumped, gen_before + 1);
    // Fail the job while holding the meta lock (mirrors reset path).
    sqlx::query(
        "UPDATE jobs SET status = 'failed', phase = 'failed', \
                          error = $1, updated_at = NOW(), completed_at = NOW() \
         WHERE public_id = $2 \
           AND status IN ('queued', 'proving', 'awaiting_signature', 'broadcasting')",
    )
    .bind(db::SELF_HEAL_RESET_JOB_ERROR)
    .bind(job_id)
    .execute(&mut *reset_tx)
    .await
    .expect("fail job in open reset");

    let set_fut = store.set_status(
        job_id,
        crate::job_store::JobStatus::Queued,
        crate::job_store::JobStatus::Broadcasting,
        "broadcasting",
    );
    tokio::pin!(set_fut);
    let blocked = tokio::time::timeout(std::time::Duration::from_millis(200), &mut set_fut).await;
    assert!(
        blocked.is_err(),
        "set_status must block on self_heal_reset_meta while reset holds the row lock"
    );

    reset_tx.commit().await.expect("commit reset");
    let applied = set_fut.await.expect("set_status after commit");
    assert!(
        !applied,
        "after open bump commits, set_status must see post-bump generation and match 0 rows"
    );
    let row = store.load(job_id).await.unwrap().unwrap();
    assert_eq!(
        row.status,
        crate::job_store::JobStatus::Failed,
        "advancing write must not resurrect a job failed by the concurrent reset"
    );
    assert_eq!(row.reset_generation, gen_before);
}

/// Zero-row `complete` is reported (`false`) so callers refuse completed
/// events / results. Would go red if `complete` still returned `Ok(())`
/// unconditionally on a generation-fence miss.
#[tokio::test]
async fn heal_complete_reports_zero_rows_and_no_completed_event() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");
    set_process_stack_mode(ScanStackMode::V1);

    let store = crate::job_store::JobStore::new(pool.clone());
    let account = [0xCEu8; 32];
    let created = store
        .create(
            crate::job_store::JobKind::Send,
            &account,
            Some("zero-row-complete"),
            serde_json::json!({}),
        )
        .await
        .expect("create");
    let job = match created {
        crate::job_store::CreateResult::Fresh(j) => j,
        crate::job_store::CreateResult::IdempotentReplay(j) => j,
        crate::job_store::CreateResult::IdempotencyConflict => {
            panic!("unexpected IdempotencyConflict")
        }
    };
    let job_id = job.public_id;

    // Advance to a non-terminal status so a bug that ignored the generation
    // fence would actually flip the row to completed.
    assert!(store
        .set_status(
            job_id,
            crate::job_store::JobStatus::Queued,
            crate::job_store::JobStatus::Broadcasting,
            "broadcasting",
        )
        .await
        .expect("set broadcasting"));

    // Bump generation without bulk-fail — isolates the fence.
    let mut tx = pool.begin().await.expect("begin");
    db::bump_self_heal_reset_generation_in_tx(&mut tx)
        .await
        .expect("bump");
    tx.commit().await.expect("commit");

    // Subscriber setup mirrors the dispatcher: only publish completed when
    // complete returns true.
    let notifier = std::sync::Arc::new(crate::job_dispatcher::JobNotifier::new());
    let mut phase_rx = notifier.phase_tx.subscribe();
    let notify_map: crate::job_dispatcher::JobNotifyMap =
        std::sync::Arc::new(dashmap::DashMap::new());
    notify_map.insert(job_id, notifier);

    let applied = store
        .complete(
            job_id,
            crate::job_store::JobStatus::Broadcasting,
            serde_json::json!({"stolen": true}),
            200,
        )
        .await
        .expect("complete query ok");
    assert!(
        !applied,
        "generation fence must yield Ok(false) from complete, not silent Ok(())"
    );

    // Dispatcher contract (process_send_commit): publish completed only on true.
    if applied {
        crate::job_dispatcher::publish_phase(
            &notify_map,
            job_id,
            crate::job_dispatcher::JobPhaseEvent {
                status: crate::job_store::JobStatus::Completed,
                phase: "completed".to_string(),
                proof_id: None,
                result: Some(serde_json::json!({"stolen": true})),
                error: None,
            },
        );
    }

    assert!(
        phase_rx.try_recv().is_err(),
        "no completed phase event must be published when complete matches 0 rows"
    );
    let row = store.load(job_id).await.unwrap().unwrap();
    assert_eq!(
        row.status,
        crate::job_store::JobStatus::Broadcasting,
        "zero-row complete must leave the durable row untouched"
    );
    assert_ne!(row.status, crate::job_store::JobStatus::Completed);
}

/// Zero-row `set_status` is reported (`false`) so callers can refuse side
/// effects. Would go red if `set_status` still returned `Ok(())` unconditionally.
#[tokio::test]
async fn heal_set_status_reports_zero_rows_on_generation_fence() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");
    set_process_stack_mode(ScanStackMode::V1);

    let store = crate::job_store::JobStore::new(pool.clone());
    let account = [0x99u8; 32];
    let created = store
        .create(
            crate::job_store::JobKind::Mint,
            &account,
            Some("zero-row-set-status"),
            serde_json::json!({}),
        )
        .await
        .expect("create");
    let job = match created {
        crate::job_store::CreateResult::Fresh(j) => j,
        crate::job_store::CreateResult::IdempotentReplay(j) => j,
        crate::job_store::CreateResult::IdempotencyConflict => {
            panic!("unexpected IdempotencyConflict")
        }
    };

    // Bump generation without failing the job — isolates the fence from the
    // bulk fail-UPDATE so we know false is from the generation predicate.
    let mut tx = pool.begin().await.expect("begin");
    db::bump_self_heal_reset_generation_in_tx(&mut tx)
        .await
        .expect("bump");
    tx.commit().await.expect("commit");

    let applied = store
        .set_status(
            job.public_id,
            crate::job_store::JobStatus::Queued,
            crate::job_store::JobStatus::Proving,
            "proving",
        )
        .await
        .expect("query ok");
    assert!(
        !applied,
        "generation fence must yield Ok(false), not silent Ok"
    );
    let row = store.load(job.public_id).await.unwrap().unwrap();
    assert_eq!(
        row.status,
        crate::job_store::JobStatus::Queued,
        "zero-row set_status must leave the row untouched"
    );
}

/// Flag-off path: process not claimed v1 → full legacy archive (epoch bump)
/// on mismatch. Would go red if the v1-only archive path were applied under
/// flag-off.
#[tokio::test]
async fn heal_flag_off_self_heal_still_full_legacy_wipe() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_dir = proofs.path().to_str().unwrap();

    // Explicit legacy claim (flag-off process).
    claim_stack_scan_mode(&pool, ScanStackMode::Legacy)
        .await
        .expect("claim legacy");
    set_process_stack_mode(ScanStackMode::Legacy);

    seed_proof_dependent_state(&pool).await;
    db::store_circuit_digest(&pool, b"OLD-LEGACY")
        .await
        .unwrap();

    let decision = heal_circuit_digest(&pool, b"NEW-LEGACY", proofs_dir, &canary_must_not_run)
        .await
        .unwrap();
    assert_eq!(decision, ResetDecision::Reset);
    assert_eq!(count_accounts(&pool).await, 0);
    assert!(
        count_physical_accounts(&pool).await >= 1,
        "archived accounts must remain physically stored"
    );
    assert_eq!(db::load_smt(&pool).await.unwrap(), None);
    assert_eq!(db::load_mmr(&pool).await.unwrap(), None);
    assert_eq!(db::load_latest_block(&pool).await.unwrap(), None);
    let (smt_phys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM smt_state")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (mmr_phys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM mmr_state")
        .fetch_one(&pool)
        .await
        .unwrap();
    let (latest_block_phys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM latest_block")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        smt_phys >= 1,
        "archived smt_state must remain physically stored"
    );
    assert!(
        mmr_phys >= 1,
        "archived mmr_state must remain physically stored"
    );
    assert!(
        latest_block_phys >= 1,
        "archived latest_block must remain physically stored"
    );
    assert_eq!(
        db::load_circuit_digest(&pool).await.unwrap().as_deref(),
        Some(&b"NEW-LEGACY"[..])
    );
}

/// Adoption-boundary canary Stale under v1 must archive v1 state.
#[tokio::test]
async fn heal_v1_stale_canary_resets_v1_state() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let proofs = tempfile::tempdir().expect("tempdir");
    let proofs_dir = proofs.path().to_str().unwrap();

    claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");
    set_process_stack_mode(ScanStackMode::V1);

    sqlx::query(
        "INSERT INTO v1_engine_meta \
         (id, network, activation_height, tip_height, tip_hash, fold_seq, updated_at) \
         VALUES (1, 'regtest', 0, 0, $1, 0, NOW())",
    )
    .bind([0u8; 32].as_slice())
    .execute(&pool)
    .await
    .unwrap();

    // No persisted digest → canary consulted.
    let live = crate::v1::encode_v1_live_digest(&[0xAA; 32], &[0xBB; 32]);
    let decision = heal_circuit_digest(&pool, &live, proofs_dir, &|| CanaryOutcome::Stale)
        .await
        .unwrap();
    assert_eq!(decision, ResetDecision::Reset);
    let (v1_meta,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM v1_engine_meta \
         WHERE state_epoch = (SELECT epoch FROM derived_state_epoch_meta WHERE id = 1)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(
        v1_meta, 0,
        "stale canary must archive v1_engine_meta (canonical epoch empty)"
    );
    let (v1_meta_phys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM v1_engine_meta")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(
        v1_meta_phys >= 1,
        "archived v1_engine_meta must remain physically stored"
    );
    assert_eq!(
        db::load_circuit_digest(&pool).await.unwrap().as_deref(),
        Some(live.as_slice())
    );
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
    assert_eq!(count_accounts(&pool).await, 0, "stale account archived");
    assert!(
        count_physical_accounts(&pool).await >= 1,
        "archived account must remain physically stored"
    );
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

// The tests below cover the `?` error-propagation arms of the
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
    // Detector 1 trips a reset (persisted digest differs). Under Data
    // Permanence the reset no longer DELETEs derived state — it bumps the
    // `derived_state_epoch_meta` epoch first (archive-and-recompute). Drop
    // that table so the reset transaction's first write errors and the `?`
    // on `db::reset_proof_dependent_state_tx` propagates. Claim the legacy
    // stack first so the failure is the DROP (not the capability gate —
    // that path has its own test).
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_stack_scan_mode(&pool, ScanStackMode::Legacy)
        .await
        .expect("claim legacy for reset-error test");
    db::store_circuit_digest(&pool, b"OLD")
        .await
        .expect("store old digest");
    sqlx::query("DROP TABLE derived_state_epoch_meta CASCADE")
        .execute(&pool)
        .await
        .expect("drop derived_state_epoch_meta");

    let err = heal_circuit_digest(&pool, b"NEW", "/tmp/whatever", &canary_must_not_run)
        .await
        .expect_err("heal must propagate the reset-tx error");
    assert!(
        matches!(err, sqlx::Error::Database(_)),
        "unexpected: {:?}",
        err
    );
}

#[tokio::test]
async fn heal_v1_propagates_error_from_reset_tx() {
    // Detector 1 trips the v1 reset branch. Drop the epoch metadata only
    // after both the v1 capability claim and old-digest store have used it,
    // so `bump_derived_state_epoch_in_tx` fails inside
    // `reset_v1_proof_dependent_state_tx` and its dedicated `?` propagates.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1 for reset-error test");
    set_process_stack_mode(ScanStackMode::V1);

    let old = crate::v1::encode_v1_live_digest(&[0x01; 32], &[0x02; 32]);
    let new = crate::v1::encode_v1_live_digest(&[0x03; 32], &[0x04; 32]);
    db::store_circuit_digest(&pool, &old)
        .await
        .expect("store old v1 digest");
    sqlx::query("DROP TABLE derived_state_epoch_meta CASCADE")
        .execute(&pool)
        .await
        .expect("drop derived_state_epoch_meta");

    let err = heal_circuit_digest(&pool, &new, "/tmp/whatever", &canary_must_not_run)
        .await
        .expect_err("heal must propagate the v1 reset-tx error");
    assert!(
        matches!(&err, sqlx::Error::Database(_)),
        "unexpected: {:?}",
        err
    );
}

#[tokio::test]
async fn heal_legacy_reset_refuses_missing_stack_mode_marker() {
    // Leave both the process mode and DB capability marker unclaimed. A
    // digest mismatch selects the legacy fallback, whose first transaction
    // operation must fail closed at the capability gate before any reset
    // write or proof-store cleanup can occur.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    db::store_circuit_digest(&pool, b"OLD")
        .await
        .expect("store old digest without claiming stack mode");

    let err = heal_circuit_digest(&pool, b"NEW", "/tmp/whatever", &canary_must_not_run)
        .await
        .expect_err("heal must propagate the missing stack-mode capability error");
    assert!(
        matches!(&err, sqlx::Error::Protocol(_)),
        "missing capability marker must map to Protocol, got {:?}",
        err
    );
    assert!(
        err.to_string()
            .contains("stack_scan_mode marker is missing"),
        "unexpected capability-gate error: {}",
        err
    );
}
