// JobStore tests against a real Postgres 17 testcontainer.
//
// Pattern mirrors `db_tests.rs`: every test gets its own UUID-named
// schema inside a shared `postgres:17` container (see
// `crate::test_db` for the shared-container implementation and
// issue #181). Migrations are applied per-schema by
// `crate::test_db::setup_pool`, suite runs under `--test-threads=1`
// like the rest of the node test gate.
//
// Each test asserts a single invariant on the public API surface so
// the failure mode points at the broken method, not at a composite
// scenario. The dispatcher integration is exercised separately in
// `job_dispatcher_tests.rs`.

use super::*;
use crate::test_db::{setup_pool, SchemaScope};

async fn setup_store() -> (JobStore, SchemaScope) {
    let scope = setup_pool().await;
    let store = JobStore::new(scope.pool.clone());
    (store, scope)
}

fn account_addr(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn sample_mint_body() -> serde_json::Value {
    serde_json::json!({
        "account_address": "0xaa".to_string() + &"aa".repeat(31),
        "amount": 1u64,
    })
}

#[tokio::test]
async fn create_fresh_returns_queued_row() {
    let (store, _c) = setup_store().await;
    let result = store
        .create(JobKind::Mint, &account_addr(1), None, sample_mint_body())
        .await
        .expect("create");
    match result {
        CreateResult::Fresh(job) => {
            assert_eq!(job.kind, JobKind::Mint);
            assert_eq!(job.status, JobStatus::Queued);
            assert_eq!(job.phase, "queued");
            assert_eq!(job.account_address, account_addr(1));
            assert!(job.idempotency_key.is_none());
            assert!(job.response_body.is_none());
            assert!(job.response_status.is_none());
            assert!(job.proof_id.is_none());
            assert!(job.error.is_none());
            assert_eq!(job.progress, 0);
            assert!(job.completed_at.is_none());
        }
        CreateResult::IdempotentReplay(_) => panic!("expected Fresh, got IdempotentReplay"),
    }
}

#[tokio::test]
async fn create_with_same_idem_key_returns_replay() {
    let (store, _c) = setup_store().await;
    let account = account_addr(2);
    let first = store
        .create(JobKind::Send, &account, Some("idem-1"), sample_mint_body())
        .await
        .expect("create first");
    let first_id = match &first {
        CreateResult::Fresh(j) => j.public_id,
        CreateResult::IdempotentReplay(_) => panic!("first call must be Fresh"),
    };

    let second = store
        .create(JobKind::Send, &account, Some("idem-1"), sample_mint_body())
        .await
        .expect("create second");
    match second {
        CreateResult::IdempotentReplay(j) => {
            assert_eq!(j.public_id, first_id, "must return the original row");
        }
        CreateResult::Fresh(_) => panic!("second call must be IdempotentReplay"),
    }
}

#[tokio::test]
async fn create_without_idem_key_inserts_multiple_rows() {
    // Partial UNIQUE index only fires when idempotency_key IS NOT
    // NULL: callers that omit the key can admit independent jobs
    // without the second one collapsing onto the first.
    let (store, _c) = setup_store().await;
    let account = account_addr(3);
    let a = store
        .create(JobKind::Mint, &account, None, sample_mint_body())
        .await
        .expect("first");
    let b = store
        .create(JobKind::Mint, &account, None, sample_mint_body())
        .await
        .expect("second");
    match (a, b) {
        (CreateResult::Fresh(x), CreateResult::Fresh(y)) => {
            assert_ne!(x.public_id, y.public_id);
        }
        _ => panic!("both calls must be Fresh when no idem_key is supplied"),
    }
}

#[tokio::test]
async fn create_different_idem_keys_for_same_account_are_distinct() {
    let (store, _c) = setup_store().await;
    let account = account_addr(4);
    let a = store
        .create(JobKind::Send, &account, Some("k1"), sample_mint_body())
        .await
        .expect("k1");
    let b = store
        .create(JobKind::Send, &account, Some("k2"), sample_mint_body())
        .await
        .expect("k2");
    match (a, b) {
        (CreateResult::Fresh(_), CreateResult::Fresh(_)) => {}
        _ => panic!("distinct idem_keys must both insert"),
    }
}

#[tokio::test]
async fn create_same_idem_key_different_accounts_are_distinct() {
    // The partial UNIQUE is (account_address, idempotency_key), so
    // the same key from a different account is a different row.
    let (store, _c) = setup_store().await;
    let a = store
        .create(
            JobKind::Send,
            &account_addr(5),
            Some("k"),
            sample_mint_body(),
        )
        .await
        .expect("acct 5");
    let b = store
        .create(
            JobKind::Send,
            &account_addr(6),
            Some("k"),
            sample_mint_body(),
        )
        .await
        .expect("acct 6");
    match (a, b) {
        (CreateResult::Fresh(_), CreateResult::Fresh(_)) => {}
        _ => panic!("identical idem_key on different accounts must both insert"),
    }
}

#[tokio::test]
async fn load_returns_none_for_unknown_uuid() {
    let (store, _c) = setup_store().await;
    let unknown = uuid::Uuid::new_v4();
    assert!(store.load(unknown).await.expect("load").is_none());
}

#[tokio::test]
async fn load_returns_existing_row() {
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(job) = store
        .create(JobKind::Mint, &account_addr(7), None, sample_mint_body())
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    let loaded = store
        .load(job.public_id)
        .await
        .expect("load")
        .expect("Some");
    assert_eq!(loaded.public_id, job.public_id);
    assert_eq!(loaded.status, JobStatus::Queued);
}

#[tokio::test]
async fn load_by_idem_returns_existing_row() {
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(job) = store
        .create(
            JobKind::Send,
            &account_addr(8),
            Some("idem-load"),
            sample_mint_body(),
        )
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    let loaded = store
        .load_by_idem(&account_addr(8), "idem-load")
        .await
        .expect("load_by_idem")
        .expect("Some");
    assert_eq!(loaded.public_id, job.public_id);
}

#[tokio::test]
async fn load_by_idem_returns_none_when_missing() {
    let (store, _c) = setup_store().await;
    assert!(store
        .load_by_idem(&account_addr(9), "nope")
        .await
        .expect("load_by_idem")
        .is_none());
}

#[tokio::test]
async fn set_status_advances_status_and_phase() {
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(job) = store
        .create(JobKind::Send, &account_addr(10), None, sample_mint_body())
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    store
        .set_status(job.public_id, JobStatus::Proving, "running_prover")
        .await
        .expect("set_status");
    let after = store.load(job.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Proving);
    assert_eq!(after.phase, "running_prover");
}

#[tokio::test]
async fn set_awaiting_signature_persists_proof_id() {
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(job) = store
        .create(JobKind::Send, &account_addr(11), None, sample_mint_body())
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    let result = serde_json::json!({
        "account_state_hash": "aa".repeat(32),
        "output_coins_root": "bb".repeat(32),
    });
    store
        .set_awaiting_signature(job.public_id, 42, result.clone())
        .await
        .expect("set_awaiting_signature");
    let after = store.load(job.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::AwaitingSignature);
    assert_eq!(after.phase, "awaiting_signature");
    assert_eq!(after.proof_id, Some(42));
    // The ash/ocr hex the wallet must sign is persisted on the row so
    // `GET /api/jobs/:id` (and an SSE reconnect after a node restart)
    // can surface it without re-deriving from the binary proof.
    assert_eq!(after.response_body, Some(result));
}

#[tokio::test]
async fn complete_persists_response_body_and_status() {
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(job) = store
        .create(JobKind::Mint, &account_addr(12), None, sample_mint_body())
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    let body = serde_json::json!({"success": true, "proof_id": 7});
    store
        .complete(job.public_id, body.clone(), 200)
        .await
        .expect("complete");
    let after = store.load(job.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Completed);
    assert_eq!(after.phase, "completed");
    assert_eq!(after.response_body, Some(body));
    assert_eq!(after.response_status, Some(200));
    assert_eq!(after.progress, 100);
    assert!(after.completed_at.is_some());
}

#[tokio::test]
async fn fail_persists_error_and_completed_at() {
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(job) = store
        .create(JobKind::Mint, &account_addr(13), None, sample_mint_body())
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    store
        .fail(job.public_id, "Insufficient funds")
        .await
        .expect("fail");
    let after = store.load(job.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Failed);
    assert_eq!(after.error.as_deref(), Some("Insufficient funds"));
    assert!(after.completed_at.is_some());
}

#[tokio::test]
async fn cancel_from_queued_returns_true_and_marks_cancelled() {
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(job) = store
        .create(JobKind::Mint, &account_addr(14), None, sample_mint_body())
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    let applied = store.cancel(job.public_id).await.expect("cancel");
    assert!(applied);
    let after = store.load(job.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Cancelled);
    assert!(after.completed_at.is_some());
}

#[tokio::test]
async fn cancel_from_proving_returns_true_and_marks_cancelled() {
    // §7.5: proving is not-yet-published — cancel must apply.
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(job) = store
        .create(JobKind::Mint, &account_addr(15), None, sample_mint_body())
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    store
        .set_status(job.public_id, JobStatus::Proving, "proving")
        .await
        .expect("set proving");
    let applied = store.cancel(job.public_id).await.expect("cancel");
    assert!(applied, "cancel from proving must apply (§7.5 not-yet-published)");
    let after = store.load(job.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Cancelled);
}

#[tokio::test]
async fn cancel_from_broadcasting_returns_false_and_leaves_status_untouched() {
    // Nullifier is in flight / published — cancel must refuse.
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(job) = store
        .create(JobKind::Mint, &account_addr(115), None, sample_mint_body())
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    store
        .set_status(job.public_id, JobStatus::Broadcasting, "broadcasting")
        .await
        .expect("set broadcasting");
    let applied = store.cancel(job.public_id).await.expect("cancel");
    assert!(!applied, "cancel from broadcasting must not apply");
    let after = store.load(job.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Broadcasting);
}

#[tokio::test]
async fn cancel_unknown_uuid_returns_false() {
    let (store, _c) = setup_store().await;
    let applied = store.cancel(uuid::Uuid::new_v4()).await.expect("cancel");
    assert!(!applied);
}

#[tokio::test]
async fn queue_depth_counts_queued_and_proving_only() {
    let (store, _c) = setup_store().await;
    // 2 queued
    let q1 = match store
        .create(JobKind::Mint, &account_addr(20), None, sample_mint_body())
        .await
        .expect("q1")
    {
        CreateResult::Fresh(j) => j,
        _ => panic!(),
    };
    let _q2 = store
        .create(JobKind::Mint, &account_addr(21), None, sample_mint_body())
        .await
        .expect("q2");
    // promote one to proving
    store
        .set_status(q1.public_id, JobStatus::Proving, "proving")
        .await
        .unwrap();
    // one completed (must not count)
    let CreateResult::Fresh(done) = store
        .create(JobKind::Mint, &account_addr(22), None, sample_mint_body())
        .await
        .expect("done")
    else {
        panic!()
    };
    store
        .complete(done.public_id, serde_json::json!({}), 200)
        .await
        .unwrap();
    // one cancelled (must not count)
    let CreateResult::Fresh(cx) = store
        .create(JobKind::Mint, &account_addr(23), None, sample_mint_body())
        .await
        .expect("cx")
    else {
        panic!()
    };
    store.cancel(cx.public_id).await.unwrap();
    // one awaiting_signature (must not count — dispatcher is
    // already attached, this is in-flight not depth)
    let CreateResult::Fresh(asig) = store
        .create(JobKind::Send, &account_addr(24), None, sample_mint_body())
        .await
        .expect("awaiting")
    else {
        panic!()
    };
    store
        .set_awaiting_signature(asig.public_id, 1, serde_json::json!({}))
        .await
        .unwrap();

    let depth = store.queue_depth().await.expect("queue_depth");
    assert_eq!(
        depth, 2,
        "1 queued + 1 proving (idempotency: no double-count from set_status)"
    );
}

#[tokio::test]
async fn list_non_terminal_for_resume_returns_queued_and_awaiting() {
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(qd) = store
        .create(JobKind::Mint, &account_addr(30), None, sample_mint_body())
        .await
        .expect("qd")
    else {
        panic!()
    };
    let CreateResult::Fresh(awaiting) = store
        .create(JobKind::Send, &account_addr(31), None, sample_mint_body())
        .await
        .expect("awaiting")
    else {
        panic!()
    };
    store
        .set_awaiting_signature(awaiting.public_id, 99, serde_json::json!({}))
        .await
        .unwrap();
    let CreateResult::Fresh(done) = store
        .create(JobKind::Mint, &account_addr(32), None, sample_mint_body())
        .await
        .expect("done")
    else {
        panic!()
    };
    store
        .complete(done.public_id, serde_json::json!({}), 200)
        .await
        .unwrap();
    let CreateResult::Fresh(broadcasting) = store
        .create(JobKind::Mint, &account_addr(33), None, sample_mint_body())
        .await
        .expect("br")
    else {
        panic!()
    };
    store
        .set_status(
            broadcasting.public_id,
            JobStatus::Broadcasting,
            "broadcasting",
        )
        .await
        .unwrap();

    let rows = store
        .list_non_terminal_for_resume()
        .await
        .expect("list_non_terminal_for_resume");
    let ids: Vec<_> = rows.iter().map(|j| j.public_id).collect();
    assert!(ids.contains(&qd.public_id));
    assert!(ids.contains(&awaiting.public_id));
    assert!(!ids.contains(&done.public_id));
    assert!(
        !ids.contains(&broadcasting.public_id),
        "broadcasting is handled via list_interrupted_for_resume, not the non-terminal list"
    );
}

#[tokio::test]
async fn list_interrupted_for_resume_returns_proving_and_broadcasting() {
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(p) = store
        .create(JobKind::Mint, &account_addr(40), None, sample_mint_body())
        .await
        .expect("p")
    else {
        panic!()
    };
    store
        .set_status(p.public_id, JobStatus::Proving, "proving")
        .await
        .unwrap();
    let CreateResult::Fresh(b) = store
        .create(JobKind::Mint, &account_addr(41), None, sample_mint_body())
        .await
        .expect("b")
    else {
        panic!()
    };
    store
        .set_status(b.public_id, JobStatus::Broadcasting, "broadcasting")
        .await
        .unwrap();
    let CreateResult::Fresh(q) = store
        .create(JobKind::Mint, &account_addr(42), None, sample_mint_body())
        .await
        .expect("q")
    else {
        panic!()
    };

    let rows = store.list_interrupted_for_resume().await.expect("list");
    let ids: Vec<_> = rows.iter().map(|j| j.public_id).collect();
    assert!(ids.contains(&p.public_id));
    assert!(ids.contains(&b.public_id));
    assert!(!ids.contains(&q.public_id));
}

#[tokio::test]
async fn job_status_round_trip_covers_all_variants() {
    // Quick exhaustive coverage of the `JobStatus::as_str` /
    // `from_db_str` pair so a future variant addition is forced to
    // update both halves.
    for s in [
        JobStatus::Queued,
        JobStatus::Proving,
        JobStatus::AwaitingSignature,
        JobStatus::Broadcasting,
        JobStatus::Completed,
        JobStatus::Failed,
        JobStatus::Cancelled,
    ] {
        assert_eq!(JobStatus::from_db_str(s.as_str()), Some(s));
    }
    assert!(JobStatus::from_db_str("nonsense").is_none());
}

#[tokio::test]
async fn job_kind_round_trip_covers_all_variants() {
    for k in [JobKind::Mint, JobKind::Send] {
        assert_eq!(JobKind::from_db_str(k.as_str()), Some(k));
    }
    assert!(JobKind::from_db_str("nonsense").is_none());
}

// -----------------------------------------------------------------
// `Job::from_row` decode-error coverage
// -----------------------------------------------------------------
//
// Production `INSERT` paths cannot reach these three error arms
// because the `jobs` table CHECKs reject bad `kind` / `status` /
// `octet_length(account_address)` at the database before `from_row`
// ever runs (migration 0014). The arms still exist as defence-in-
// depth: a future migration that adds a `kind` or `status` variant
// without backporting `JobKind::from_db_str` /
// `JobStatus::from_db_str` would otherwise crash inside `try_get` on
// every read. The tests below build a synthetic row via raw `SELECT`
// (no INSERT → no CHECK), call `Job::from_row` directly, and assert
// the error message so the 100%-coverage gate is satisfied without
// dropping the CHECK constraints in production.

#[tokio::test]
async fn from_row_returns_decode_error_for_short_account_address() {
    let (store, _c) = setup_store().await;
    let row = sqlx::query(
        "SELECT 'mint'::text AS kind, \
                'queued'::text AS status, \
                '\\x01'::bytea AS account_address",
    )
    .fetch_one(store.pool())
    .await
    .expect("select");
    let err = Job::from_row(&row).expect_err("expected decode error");
    let msg = err.to_string();
    assert!(
        msg.contains("account_address has unexpected length"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn from_row_returns_decode_error_for_unknown_kind() {
    let (store, _c) = setup_store().await;
    let row = sqlx::query(
        "SELECT 'cancel'::text AS kind, \
                'queued'::text AS status, \
                decode(repeat('00', 32), 'hex') AS account_address",
    )
    .fetch_one(store.pool())
    .await
    .expect("select");
    let err = Job::from_row(&row).expect_err("expected decode error");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown jobs.kind: cancel"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn from_row_returns_decode_error_for_unknown_status() {
    let (store, _c) = setup_store().await;
    let row = sqlx::query(
        "SELECT 'mint'::text AS kind, \
                'archived'::text AS status, \
                decode(repeat('00', 32), 'hex') AS account_address",
    )
    .fetch_one(store.pool())
    .await
    .expect("select");
    let err = Job::from_row(&row).expect_err("expected decode error");
    let msg = err.to_string();
    assert!(
        msg.contains("unknown jobs.status: archived"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn is_terminal_matches_terminal_states_only() {
    assert!(!JobStatus::Queued.is_terminal());
    assert!(!JobStatus::Proving.is_terminal());
    assert!(!JobStatus::AwaitingSignature.is_terminal());
    assert!(!JobStatus::Broadcasting.is_terminal());
    assert!(JobStatus::Completed.is_terminal());
    assert!(JobStatus::Failed.is_terminal());
    assert!(JobStatus::Cancelled.is_terminal());
}
