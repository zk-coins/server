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

/// Assert [`FinaliseClaim::Won`] and return its fencing token.
fn expect_won(claim: FinaliseClaim) -> i64 {
    match claim {
        FinaliseClaim::Won { fence } => fence,
        other => panic!("expected FinaliseClaim::Won, got {other:?}"),
    }
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
async fn cancel_legacy_rejects_proving_and_awaiting_signature() {
    // Defect 1: shared JobStore::cancel stays queued-only under flag-off /
    // legacy `/api` path — proving and awaiting_signature must refuse.
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(proving) = store
        .create(JobKind::Mint, &account_addr(15), None, sample_mint_body())
        .await
        .expect("create proving")
    else {
        panic!("expected Fresh");
    };
    store
        .set_status(proving.public_id, JobStatus::Proving, "proving")
        .await
        .expect("set proving");
    let applied = store.cancel(proving.public_id).await.expect("cancel");
    assert!(
        !applied,
        "legacy cancel must reject proving (pre-v1.1 byte-identical)"
    );
    let after = store.load(proving.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Proving);

    let CreateResult::Fresh(asig) = store
        .create(JobKind::Mint, &account_addr(16), None, sample_mint_body())
        .await
        .expect("create awaiting")
    else {
        panic!("expected Fresh");
    };
    store
        .set_awaiting_signature(asig.public_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");
    let applied = store.cancel(asig.public_id).await.expect("cancel");
    assert!(
        !applied,
        "legacy cancel must reject awaiting_signature"
    );
    let after = store.load(asig.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::AwaitingSignature);
}

#[tokio::test]
async fn cancel_not_yet_published_accepts_proving_and_awaiting_signature() {
    // §7.5 / v1.1 path only: proving and awaiting_signature are cancellable.
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(job) = store
        .create(JobKind::Mint, &account_addr(17), None, sample_mint_body())
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    store
        .set_status(job.public_id, JobStatus::Proving, "proving")
        .await
        .expect("set proving");
    let applied = store
        .cancel_not_yet_published(job.public_id)
        .await
        .expect("cancel_not_yet_published");
    assert!(
        applied,
        "v1.1 cancel from proving must apply (§7.5 not-yet-published)"
    );
    let after = store.load(job.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Cancelled);

    let CreateResult::Fresh(asig) = store
        .create(JobKind::Mint, &account_addr(18), None, sample_mint_body())
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    // Plant a restart envelope so the atomic strip is observable.
    sqlx::query(
        "UPDATE jobs SET request_body = $1 WHERE public_id = $2",
    )
    .bind(serde_json::json!({
        "pending_sign": {"mode": "initial"},
        "sign": {"pk_i": "00"}
    }))
    .bind(asig.public_id)
    .execute(store.pool())
    .await
    .expect("plant envelope");
    store
        .set_awaiting_signature(asig.public_id, 2, serde_json::json!({}))
        .await
        .expect("awaiting_signature");
    // set_awaiting_signature does not clear request_body; re-plant after.
    sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
        .bind(serde_json::json!({
            "pending_sign": {"mode": "initial"},
            "sign": {"pk_i": "00"}
        }))
        .bind(asig.public_id)
        .execute(store.pool())
        .await
        .expect("replant");
    let applied = store
        .cancel_not_yet_published(asig.public_id)
        .await
        .expect("cancel awaiting");
    assert!(applied);
    let after = store.load(asig.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Cancelled);
    assert!(
        after.request_body.get("pending_sign").is_none(),
        "atomic cancel must strip pending_sign: {:?}",
        after.request_body
    );
    assert!(
        after.request_body.get("sign").is_none(),
        "atomic cancel must strip sign: {:?}",
        after.request_body
    );
}

#[tokio::test]
async fn fail_atomically_strips_pending_sign_envelope() {
    // Defect 3: fail must not leave a restart envelope that boot could
    // rehydrate. Strip is atomic with the status flip.
    let (store, _c) = setup_store().await;
    let CreateResult::Fresh(job) = store
        .create(JobKind::Send, &account_addr(19), None, sample_mint_body())
        .await
        .expect("create")
    else {
        panic!("expected Fresh");
    };
    sqlx::query("UPDATE jobs SET request_body = $1 WHERE public_id = $2")
        .bind(serde_json::json!({
            "pending_sign": {"mode": "initial", "network": "mainnet"},
            "other": "kept"
        }))
        .bind(job.public_id)
        .execute(store.pool())
        .await
        .expect("plant");
    store
        .fail(job.public_id, "awaiting_signature timeout")
        .await
        .expect("fail");
    let after = store.load(job.public_id).await.unwrap().unwrap();
    assert_eq!(after.status, JobStatus::Failed);
    assert!(
        after.request_body.get("pending_sign").is_none(),
        "fail must atomically strip pending_sign: {:?}",
        after.request_body
    );
    assert_eq!(
        after.request_body.get("other").and_then(|v| v.as_str()),
        Some("kept"),
        "unrelated keys must survive: {:?}",
        after.request_body
    );
}

#[tokio::test]
async fn claim_finalise_exclusive_only_one_winner_from_awaiting_signature() {
    let (store, _c) = setup_store().await;
    let result = store
        .create(
            JobKind::Send,
            &account_addr(0xCA),
            Some("k-claim-exclusive"),
            sample_mint_body(),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
    };
    store
        .set_awaiting_signature(job_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");

    let a = store.claim_finalise_exclusive(job_id).await.expect("claim a");
    let b = store.claim_finalise_exclusive(job_id).await.expect("claim b");
    let fence_a = expect_won(a);
    assert!(
        matches!(
            b,
            FinaliseClaim::Lost {
                observed: JobStatus::Broadcasting
            }
        ),
        "second claim must lose with observed broadcasting; got {b:?}"
    );
    let row = store.load(job_id).await.expect("load").expect("row");
    assert_eq!(row.status, JobStatus::Broadcasting);
    assert_eq!(row.phase, FINALISE_CLAIM_PHASE);
    let claim = row
        .request_body
        .get(FINALISE_CLAIM_BODY_KEY)
        .expect("won claim must plant finalise_claim");
    let owner_str = store.process_owner().to_string();
    assert_eq!(
        claim.get("owner").and_then(|v| v.as_str()),
        Some(owner_str.as_str()),
        "claim owner must be this store's process_owner"
    );
    assert_eq!(
        claim.get("fence").and_then(|v| v.as_i64()),
        Some(fence_a),
        "claim fence must match Won token"
    );
    assert!(
        claim.get("lease_expires_at").and_then(|v| v.as_str()).is_some(),
        "claim must carry lease_expires_at"
    );

    // Live (unexpired) lease must survive a boot-style release sweep.
    assert!(
        !store
            .release_stale_finalise_claim(job_id)
            .await
            .expect("release live"),
        "live owner lease must not be released by boot sweep"
    );

    // Expire the lease — evidence the owner abandoned.
    expire_finalise_claim_lease(store.pool(), job_id).await;
    assert!(
        store
            .release_stale_finalise_claim(job_id)
            .await
            .expect("release expired"),
        "expired lease is evidence of abandonment"
    );
    let c = store.claim_finalise_exclusive(job_id).await.expect("claim c");
    let fence_c = expect_won(c);
    assert!(
        fence_c > fence_a,
        "reclaim must mint a strictly newer fencing token; old={fence_a} new={fence_c}"
    );
    let d = store.claim_finalise_exclusive(job_id).await.expect("claim d");
    assert!(
        matches!(d, FinaliseClaim::Lost { .. }),
        "second after re-claim must lose; got {d:?}"
    );
}

/// Plant an expired lease on a `finalise_claimed` row (test helper).
async fn expire_finalise_claim_lease(pool: &sqlx::PgPool, job_id: uuid::Uuid) {
    sqlx::query(
        "UPDATE jobs SET request_body = jsonb_set( \
             COALESCE(request_body, '{}'::jsonb), \
             '{finalise_claim,lease_expires_at}', \
             to_jsonb('1970-01-01T00:00:00Z'::text), \
             true \
         ) WHERE public_id = $1",
    )
    .bind(job_id)
    .execute(pool)
    .await
    .expect("expire lease");
}

/// Defect 2: a live owner's claim survives a boot release sweep; only an
/// expired lease (abandonment evidence) is reclaimable.
#[tokio::test]
async fn live_owner_claim_survives_boot_release_sweep() {
    let scope = setup_pool().await;
    let owner_live = uuid::Uuid::new_v4();
    let owner_boot = uuid::Uuid::new_v4();
    let live_store = JobStore::with_process_owner(scope.pool.clone(), owner_live);
    let boot_store = JobStore::with_process_owner(scope.pool.clone(), owner_boot);

    let result = live_store
        .create(
            JobKind::Send,
            &account_addr(0xCB),
            Some("k-live-lease"),
            sample_mint_body(),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
    };
    live_store
        .set_awaiting_signature(job_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");

    let live_fence = expect_won(
        live_store
            .claim_finalise_exclusive(job_id)
            .await
            .expect("live claim"),
    );

    // Boot sweep in a *different* process must not free a live lease.
    assert!(
        !boot_store
            .release_stale_finalise_claim(job_id)
            .await
            .expect("boot release"),
        "boot must not release a live owner's unexpired claim"
    );
    assert!(
        matches!(
            boot_store
                .claim_finalise_exclusive(job_id)
                .await
                .expect("boot re-claim"),
            FinaliseClaim::Lost {
                observed: JobStatus::Broadcasting
            }
        ),
        "second process must lose while live lease holds"
    );

    // Live owner can renew under its fence.
    assert!(
        live_store
            .renew_finalise_claim(job_id, owner_live, live_fence, FINALISE_CLAIM_LEASE)
            .await
            .expect("renew"),
        "live owner must renew its own claim"
    );
    // Foreign owner cannot renew (wrong owner + wrong fence).
    assert!(
        !boot_store
            .renew_finalise_claim(job_id, owner_boot, live_fence, FINALISE_CLAIM_LEASE)
            .await
            .expect("foreign renew"),
        "non-owner must not renew"
    );
    // Stale fence cannot renew even with the right owner.
    assert!(
        !live_store
            .renew_finalise_claim(job_id, owner_live, live_fence - 1, FINALISE_CLAIM_LEASE)
            .await
            .expect("stale fence renew"),
        "stale fence must not renew"
    );

    // After lease expiry, boot may release with abandonment evidence.
    expire_finalise_claim_lease(live_store.pool(), job_id).await;
    assert!(
        boot_store
            .release_stale_finalise_claim(job_id)
            .await
            .expect("release after expiry"),
        "expired lease is abandonment evidence"
    );
    expect_won(
        boot_store
            .claim_finalise_exclusive(job_id)
            .await
            .expect("boot claim after release"),
    );

    drop(scope);
}

/// Defect 2 (P0): lease expiry is created with Postgres `NOW()`, not host
/// `Utc::now()`. Host/DB clock skew cannot manufacture abandonment of a
/// still-live owner because create and evaluate share one clock.
#[tokio::test]
async fn finalise_claim_lease_uses_database_clock_not_host() {
    let (store, _c) = setup_store().await;
    let result = store
        .create(
            JobKind::Send,
            &account_addr(0xCC),
            Some("k-db-clock"),
            sample_mint_body(),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
    };
    store
        .set_awaiting_signature(job_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");

    let lease = std::time::Duration::from_secs(300);
    expect_won(
        store
            .claim_finalise_exclusive_as(job_id, store.process_owner(), lease)
            .await
            .expect("claim"),
    );

    // Remaining lease lifetime measured against DB NOW() must be ≈ lease.
    let remaining_secs: f64 = sqlx::query_scalar(
        "SELECT EXTRACT(EPOCH FROM ( \
             (request_body #>> '{finalise_claim,lease_expires_at}')::timestamptz \
             - NOW() \
         ))::float8 \
         FROM jobs WHERE public_id = $1",
    )
    .bind(job_id)
    .fetch_one(store.pool())
    .await
    .expect("remaining lease");
    assert!(
        (remaining_secs - 300.0).abs() < 3.0,
        "lease_expires_at must be NOW()+lease on the database clock; remaining={remaining_secs}s"
    );

    // Live under DB comparison — boot cannot free it.
    assert!(
        !store
            .release_stale_finalise_claim(job_id)
            .await
            .expect("release"),
        "DB-live lease must not be released"
    );
}

/// Defect 2 (P0): host clock cannot expire a lease that is still live on
/// the database clock. Plant an expiry that is still `> NOW()` in Postgres;
/// release_stale must refuse regardless of what the host wall clock says.
#[tokio::test]
async fn host_db_clock_skew_cannot_expire_live_lease() {
    let (store, _c) = setup_store().await;
    let result = store
        .create(
            JobKind::Send,
            &account_addr(0xCD),
            Some("k-clock-skew"),
            sample_mint_body(),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
    };
    store
        .set_awaiting_signature(job_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");
    expect_won(store.claim_finalise_exclusive(job_id).await.expect("claim"));

    // Force expiry to a value that is unambiguously live on the DB clock
    // (NOW() + 1 hour). Even if the host clock were hours ahead, release
    // only consults Postgres NOW().
    sqlx::query(
        "UPDATE jobs SET request_body = jsonb_set( \
             COALESCE(request_body, '{}'::jsonb), \
             '{finalise_claim,lease_expires_at}', \
             to_jsonb((NOW() + interval '1 hour')::text), \
             true \
         ) WHERE public_id = $1",
    )
    .bind(job_id)
    .execute(store.pool())
    .await
    .expect("plant DB-future expiry");

    assert!(
        !store
            .release_stale_finalise_claim(job_id)
            .await
            .expect("release"),
        "lease still live on database clock must survive release sweep"
    );
    // Second process still loses the exclusive claim.
    let other = JobStore::with_process_owner(store.pool().clone(), uuid::Uuid::new_v4());
    assert!(
        matches!(
            other.claim_finalise_exclusive(job_id).await.expect("other claim"),
            FinaliseClaim::Lost {
                observed: JobStatus::Broadcasting
            }
        ),
        "second resumer must lose while DB-live lease holds"
    );
}

/// Defect 2 (P0): a "prove" longer than the lease period does **not** let a
/// second resumer in, because the owner renews during the long operation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prove_longer_than_lease_period_blocks_second_resumer() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let scope = setup_pool().await;
    let owner = uuid::Uuid::new_v4();
    let store = JobStore::with_process_owner(scope.pool.clone(), owner);
    let other = JobStore::with_process_owner(scope.pool.clone(), uuid::Uuid::new_v4());

    let result = store
        .create(
            JobKind::Send,
            &account_addr(0xCE),
            Some("k-long-prove-lease"),
            sample_mint_body(),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
    };
    store
        .set_awaiting_signature(job_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");

    // Short lease so the test budget is seconds, not minutes.
    let lease = Duration::from_secs(1);
    let renew_every = Duration::from_millis(250);
    let fence = expect_won(
        store
            .claim_finalise_exclusive_as(job_id, owner, lease)
            .await
            .expect("claim"),
    );

    let stop = Arc::new(AtomicBool::new(false));
    let stop_probe = Arc::clone(&stop);
    let other_store = other.clone();
    // Probe: while the long operation runs, a second process must never
    // free + win the claim.
    let probe = tokio::spawn(async move {
        let mut saw_live_block = false;
        while !stop_probe.load(Ordering::SeqCst) {
            let released = other_store
                .release_stale_finalise_claim(job_id)
                .await
                .expect("release probe");
            if released {
                let claim = other_store
                    .claim_finalise_exclusive_as(job_id, other_store.process_owner(), lease)
                    .await
                    .expect("claim probe");
                if matches!(claim, FinaliseClaim::Won { .. }) {
                    return Err("second resumer won claim during live long prove".to_string());
                }
            } else {
                saw_live_block = true;
            }
            tokio::time::sleep(Duration::from_millis(150)).await;
        }
        if !saw_live_block {
            return Err("probe never observed a live (unreleased) lease".to_string());
        }
        Ok(())
    });

    // Long operation > lease period, with heartbeat renewals (production shape).
    let long_prove = Duration::from_secs(3);
    assert!(
        long_prove > lease,
        "test requires prove longer than lease"
    );
    crate::job_dispatcher::with_finalise_lease_heartbeat(
        &store,
        job_id,
        owner,
        fence,
        lease,
        renew_every,
        Duration::from_secs(5),
        async {
            tokio::time::sleep(long_prove).await;
        },
    )
    .await
    .expect("long prove must complete while lease is kept alive by heartbeat");

    stop.store(true, Ordering::SeqCst);
    probe.await.expect("join probe").expect("probe ok");

    // After the owner stops renewing, the short lease expires and boot may free.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        other
            .release_stale_finalise_claim(job_id)
            .await
            .expect("release after abandon"),
        "expired lease after owner stopped renewing is abandonment evidence"
    );
    expect_won(
        other
            .claim_finalise_exclusive_as(job_id, other.process_owner(), lease)
            .await
            .expect("claim after abandon"),
    );

    drop(scope);
}

/// Defect 1 (P0): a renewal that returns `Ok(false)` mid-prove aborts the
/// operation and discards the result — fail closed, not a logged warning.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heartbeat_renew_false_aborts_work_and_discards_result() {
    use crate::job_dispatcher::{
        with_finalise_lease_heartbeat_renew, FinaliseLeaseLivenessLost,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let renew_calls = Arc::new(AtomicUsize::new(0));
    let work_finished = Arc::new(AtomicBool::new(false));
    let renew_calls_h = Arc::clone(&renew_calls);
    let work_finished_h = Arc::clone(&work_finished);

    let result = with_finalise_lease_heartbeat_renew(
        Duration::from_millis(50),
        Duration::from_secs(5),
        move || {
            let renew_calls_h = Arc::clone(&renew_calls_h);
            async move {
                renew_calls_h.fetch_add(1, Ordering::SeqCst);
                // Every renew loses ownership — fail closed on first tick.
                Ok(false)
            }
        },
        async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            work_finished_h.store(true, Ordering::SeqCst);
            "should_not_be_returned"
        },
    )
    .await;

    assert_eq!(
        result,
        Err(FinaliseLeaseLivenessLost::RenewReturnedFalse),
        "Ok(false) renew must abort with RenewReturnedFalse"
    );
    assert!(
        !work_finished.load(Ordering::SeqCst),
        "work must be cancelled — result discarded, not completed"
    );
    assert!(
        renew_calls.load(Ordering::SeqCst) >= 1,
        "renew must have been attempted"
    );
}

/// Defect 1 (P0): a renew database/storage error mid-prove aborts work.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heartbeat_renew_error_aborts_work_and_discards_result() {
    use crate::job_dispatcher::{
        with_finalise_lease_heartbeat_renew, FinaliseLeaseLivenessLost,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let work_finished = Arc::new(AtomicBool::new(false));
    let work_finished_h = Arc::clone(&work_finished);

    let result = with_finalise_lease_heartbeat_renew(
        Duration::from_millis(50),
        Duration::from_secs(5),
        || async { Err("simulated db error".to_string()) },
        async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            work_finished_h.store(true, Ordering::SeqCst);
            42
        },
    )
    .await;

    match result {
        Err(FinaliseLeaseLivenessLost::RenewError(msg)) => {
            assert!(
                msg.contains("simulated db error"),
                "error text must surface; got {msg}"
            );
        }
        other => panic!("expected RenewError, got {other:?}"),
    }
    assert!(
        !work_finished.load(Ordering::SeqCst),
        "work must stop when renew errors"
    );
}

/// Defect 1 (P0): if the heartbeat task dies silently, work must stop.
/// A panic inside renew drops the loss channel without a value — the same
/// signal as a task that disappears.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn heartbeat_task_death_aborts_work_and_discards_result() {
    use crate::job_dispatcher::{
        with_finalise_lease_heartbeat_renew, FinaliseLeaseLivenessLost,
    };
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let work_finished = Arc::new(AtomicBool::new(false));
    let work_finished_h = Arc::clone(&work_finished);
    let calls = Arc::new(AtomicUsize::new(0));
    let calls_h = Arc::clone(&calls);

    let result = with_finalise_lease_heartbeat_renew(
        Duration::from_millis(50),
        Duration::from_secs(5),
        move || {
            let calls_h = Arc::clone(&calls_h);
            async move {
                let n = calls_h.fetch_add(1, Ordering::SeqCst);
                if n == 0 {
                    // Panic on the first real renew: heartbeat task dies.
                    panic!("simulated heartbeat task death");
                }
                Ok(true)
            }
        },
        async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            work_finished_h.store(true, Ordering::SeqCst);
            "should_not_complete"
        },
    )
    .await;

    assert_eq!(
        result,
        Err(FinaliseLeaseLivenessLost::HeartbeatTaskEnded),
        "heartbeat death must surface as HeartbeatTaskEnded"
    );
    assert!(
        !work_finished.load(Ordering::SeqCst),
        "work must stop when the heartbeat task disappears"
    );
}

/// Defect 1 (P0): integration — steal the claim mid-operation so
/// `renew_finalise_claim` returns `Ok(false)`; the heartbeat wrapper aborts.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mid_prove_lease_loss_aborts_via_real_store_renew() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let scope = setup_pool().await;
    let owner = uuid::Uuid::new_v4();
    let store = JobStore::with_process_owner(scope.pool.clone(), owner);

    let result = store
        .create(
            JobKind::Send,
            &account_addr(0xCF),
            Some("k-mid-prove-loss"),
            sample_mint_body(),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
    };
    store
        .set_awaiting_signature(job_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");

    let lease = Duration::from_secs(30);
    let renew_every = Duration::from_millis(80);
    let fence = expect_won(
        store
            .claim_finalise_exclusive_as(job_id, owner, lease)
            .await
            .expect("claim"),
    );

    // After a short delay, strip the claim so the next renew returns false.
    let pool = scope.pool.clone();
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(120)).await;
        sqlx::query(
            "UPDATE jobs SET phase = 'publishing', \
                    request_body = COALESCE(request_body, '{}'::jsonb) - 'finalise_claim' \
             WHERE public_id = $1",
        )
        .bind(job_id)
        .execute(&pool)
        .await
        .expect("steal claim");
    });

    let work_finished = Arc::new(AtomicBool::new(false));
    let work_finished_h = Arc::clone(&work_finished);
    let outcome = crate::job_dispatcher::with_finalise_lease_heartbeat(
        &store,
        job_id,
        owner,
        fence,
        lease,
        renew_every,
        Duration::from_secs(5),
        async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            work_finished_h.store(true, Ordering::SeqCst);
            "applied"
        },
    )
    .await;

    assert_eq!(
        outcome,
        Err(crate::job_dispatcher::FinaliseLeaseLivenessLost::RenewReturnedFalse),
        "stolen claim must abort the in-flight operation"
    );
    assert!(
        !work_finished.load(Ordering::SeqCst),
        "prove work must not complete after lease loss"
    );

    drop(scope);
}

/// Defect 1 (P0): a stalled `renew()` await is treated as ownership loss,
/// not an unbounded pause while work keeps running.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn stalled_renew_is_treated_as_liveness_loss() {
    use crate::job_dispatcher::{
        with_finalise_lease_heartbeat_renew, FinaliseLeaseLivenessLost,
    };
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    let work_finished = Arc::new(AtomicBool::new(false));
    let work_finished_h = Arc::clone(&work_finished);

    let result = with_finalise_lease_heartbeat_renew(
        Duration::from_millis(30),
        Duration::from_millis(80),
        || async {
            // Never completes — simulates a hung database round-trip.
            std::future::pending::<Result<bool, String>>().await
        },
        async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            work_finished_h.store(true, Ordering::SeqCst);
            "should_not_complete"
        },
    )
    .await;

    assert_eq!(
        result,
        Err(FinaliseLeaseLivenessLost::RenewTimedOut),
        "stalled renew must surface as RenewTimedOut"
    );
    assert!(
        !work_finished.load(Ordering::SeqCst),
        "work must abort when renew stalls past the bound"
    );
}

/// Defect 1 (P0): a worker that lost its lease cannot commit completion
/// (or terminal complete) even if it keeps running — the fence is the
/// fencing token + lease, not cooperative cancellation.
#[tokio::test]
async fn lost_lease_worker_cannot_commit_completion_or_complete() {
    use std::time::Duration;

    let scope = setup_pool().await;
    let loser = uuid::Uuid::new_v4();
    let winner = uuid::Uuid::new_v4();
    let loser_store = JobStore::with_process_owner(scope.pool.clone(), loser);
    let winner_store = JobStore::with_process_owner(scope.pool.clone(), winner);

    let result = loser_store
        .create(
            JobKind::Send,
            &account_addr(0xD1),
            Some("k-lost-cannot-commit"),
            sample_mint_body(),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
    };
    loser_store
        .set_awaiting_signature(job_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");

    let loser_fence = expect_won(
        loser_store
            .claim_finalise_exclusive_as(job_id, loser, Duration::from_secs(60))
            .await
            .expect("loser claim"),
    );

    // Steal the claim for another owner (lease expiry + release + re-claim).
    sqlx::query(
        "UPDATE jobs SET request_body = jsonb_set( \
             COALESCE(request_body, '{}'::jsonb), \
             '{finalise_claim,lease_expires_at}', \
             to_jsonb('1970-01-01T00:00:00Z'::text), \
             true \
         ) WHERE public_id = $1",
    )
    .bind(job_id)
    .execute(loser_store.pool())
    .await
    .expect("expire loser lease");
    assert!(
        winner_store
            .release_stale_finalise_claim(job_id)
            .await
            .expect("release stale"),
        "expired claim must release"
    );
    let winner_fence = expect_won(
        winner_store
            .claim_finalise_exclusive_as(job_id, winner, Duration::from_secs(60))
            .await
            .expect("winner claim"),
    );
    assert!(
        winner_fence > loser_fence,
        "winner fence must be newer than loser's; loser={loser_fence} winner={winner_fence}"
    );

    // Contrast: status alone is not the fence. Loser "kept running" and
    // tries fence-qualified commits with its stale token — must not apply.
    let completion = serde_json::json!({
        "pending": {"fake": true},
        "signature": null,
        "completion_result": {"ok": true},
        "completion_status": 200
    });
    assert!(
        !loser_store
            .merge_finalisation_if_finalise_owner(job_id, loser, loser_fence, &completion)
            .await
            .expect("merge attempt"),
        "stale fence must not persist completion capability"
    );
    assert!(
        !loser_store
            .complete_if_finalise_owner(
                job_id,
                loser,
                loser_fence,
                serde_json::json!({"stolen": true}),
                200
            )
            .await
            .expect("complete attempt"),
        "stale fence must not complete the job"
    );
    assert!(
        !loser_store
            .fail_if_finalise_owner(
                job_id,
                loser,
                loser_fence,
                "loser must not fail winner's job"
            )
            .await
            .expect("fail attempt"),
        "stale fence must not fail the job"
    );

    let row = winner_store.load(job_id).await.expect("load").expect("row");
    assert_eq!(row.status, JobStatus::Broadcasting);
    assert_eq!(row.phase, FINALISE_CLAIM_PHASE);
    let winner_s = winner.to_string();
    let claim_owner = row
        .request_body
        .get("finalise_claim")
        .and_then(|c| c.get("owner"))
        .and_then(|o| o.as_str());
    assert_eq!(claim_owner, Some(winner_s.as_str()));
    assert_eq!(
        row.request_body
            .get("finalise_claim")
            .and_then(|c| c.get("fence"))
            .and_then(|f| f.as_i64()),
        Some(winner_fence)
    );
    assert!(
        row.request_body.get("finalisation").is_none(),
        "loser must not have written finalisation"
    );

    // Winner can still commit under the current fence + live lease.
    assert!(
        winner_store
            .merge_finalisation_if_finalise_owner(job_id, winner, winner_fence, &completion)
            .await
            .expect("winner merge"),
        "current fence must persist completion"
    );
    assert!(
        winner_store
            .complete_if_finalise_owner(
                job_id,
                winner,
                winner_fence,
                serde_json::json!({"ok": true}),
                200
            )
            .await
            .expect("winner complete"),
        "current fence must complete"
    );
    let done = winner_store.load(job_id).await.expect("load").expect("row");
    assert_eq!(done.status, JobStatus::Completed);

    drop(scope);
}

/// Same process reclaims after lease expiry: old epoch fence must lose even
/// though the owner UUID is unchanged. Identity is not the fence.
#[tokio::test]
async fn same_owner_reclaim_rejects_stale_fence_writes() {
    use std::time::Duration;

    let scope = setup_pool().await;
    let owner = uuid::Uuid::new_v4();
    let store = JobStore::with_process_owner(scope.pool.clone(), owner);

    let result = store
        .create(
            JobKind::Send,
            &account_addr(0xD2),
            Some("k-same-owner-reclaim"),
            sample_mint_body(),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
    };
    store
        .set_awaiting_signature(job_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");

    let old_fence = expect_won(
        store
            .claim_finalise_exclusive_as(job_id, owner, Duration::from_secs(60))
            .await
            .expect("first claim"),
    );

    // Lease lapses; same owner reclaims (new acquisition epoch).
    expire_finalise_claim_lease(store.pool(), job_id).await;
    assert!(
        store
            .release_stale_finalise_claim(job_id)
            .await
            .expect("release"),
        "expired lease must release"
    );
    let new_fence = expect_won(
        store
            .claim_finalise_exclusive_as(job_id, owner, Duration::from_secs(60))
            .await
            .expect("same-owner reclaim"),
    );
    assert!(
        new_fence > old_fence,
        "reclaim must mint a newer fence; old={old_fence} new={new_fence}"
    );

    let completion = serde_json::json!({
        "pending": {"fake": true},
        "signature": null,
        "completion_result": {"ok": true},
        "completion_status": 200
    });
    // Stale epoch (old fence) — owner still matches, but fence must lose.
    assert!(
        !store
            .merge_finalisation_if_finalise_owner(job_id, owner, old_fence, &completion)
            .await
            .expect("stale merge"),
        "stale fence must not merge after same-owner reclaim"
    );
    assert!(
        !store
            .complete_if_finalise_owner(
                job_id,
                owner,
                old_fence,
                serde_json::json!({"stolen": true}),
                200
            )
            .await
            .expect("stale complete"),
        "stale fence must not complete after same-owner reclaim"
    );
    assert!(
        !store
            .fail_if_finalise_owner(job_id, owner, old_fence, "stale fail")
            .await
            .expect("stale fail"),
        "stale fence must not fail after same-owner reclaim"
    );
    assert!(
        !store
            .renew_finalise_claim(job_id, owner, old_fence, Duration::from_secs(60))
            .await
            .expect("stale renew"),
        "stale fence must not renew the new epoch"
    );

    // Current epoch still works.
    assert!(
        store
            .merge_finalisation_if_finalise_owner(job_id, owner, new_fence, &completion)
            .await
            .expect("new merge"),
        "current fence must merge"
    );
    assert!(
        store
            .complete_if_finalise_owner(
                job_id,
                owner,
                new_fence,
                serde_json::json!({"ok": true}),
                200
            )
            .await
            .expect("new complete"),
        "current fence must complete"
    );
    let done = store.load(job_id).await.expect("load").expect("row");
    assert_eq!(done.status, JobStatus::Completed);

    drop(scope);
}

/// A current fencing token whose lease has expired cannot commit.
#[tokio::test]
async fn current_fence_with_expired_lease_cannot_commit() {
    use std::time::Duration;

    let scope = setup_pool().await;
    let owner = uuid::Uuid::new_v4();
    let store = JobStore::with_process_owner(scope.pool.clone(), owner);

    let result = store
        .create(
            JobKind::Send,
            &account_addr(0xD3),
            Some("k-expired-lease-fence"),
            sample_mint_body(),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
    };
    store
        .set_awaiting_signature(job_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");

    let fence = expect_won(
        store
            .claim_finalise_exclusive_as(job_id, owner, Duration::from_secs(60))
            .await
            .expect("claim"),
    );

    // Lease expires while the fence is still the current token on the row
    // (no release / reclaim yet).
    expire_finalise_claim_lease(store.pool(), job_id).await;

    let completion = serde_json::json!({
        "pending": {"fake": true},
        "signature": null,
        "completion_result": {"ok": true},
        "completion_status": 200
    });
    assert!(
        !store
            .merge_finalisation_if_finalise_owner(job_id, owner, fence, &completion)
            .await
            .expect("merge"),
        "expired lease must block completion persist even with current fence"
    );
    assert!(
        !store
            .complete_if_finalise_owner(
                job_id,
                owner,
                fence,
                serde_json::json!({"ok": true}),
                200
            )
            .await
            .expect("complete"),
        "expired lease must block terminal complete even with current fence"
    );
    assert!(
        !store
            .fail_if_finalise_owner(job_id, owner, fence, "expired fail")
            .await
            .expect("fail"),
        "expired lease must block terminal fail even with current fence"
    );

    let row = store.load(job_id).await.expect("load").expect("row");
    assert_eq!(row.status, JobStatus::Broadcasting);
    assert_eq!(row.phase, FINALISE_CLAIM_PHASE);
    assert_eq!(
        row.request_body
            .get("finalise_claim")
            .and_then(|c| c.get("fence"))
            .and_then(|f| f.as_i64()),
        Some(fence),
        "row still holds the same fence; only lease validity blocks the write"
    );

    drop(scope);
}

/// Pre-claim status-only fail must not terminate a row under exclusive claim.
#[tokio::test]
async fn pre_claim_fail_if_status_cannot_terminate_owned_row() {
    use std::time::Duration;

    let scope = setup_pool().await;
    let owner = uuid::Uuid::new_v4();
    let store = JobStore::with_process_owner(scope.pool.clone(), owner);

    let result = store
        .create(
            JobKind::Send,
            &account_addr(0xD4),
            Some("k-preclaim-fail-owned"),
            sample_mint_body(),
        )
        .await
        .expect("create");
    let job_id = match result {
        CreateResult::Fresh(j) => j.public_id,
        _ => panic!("expected Fresh"),
    };
    store
        .set_awaiting_signature(job_id, 1, serde_json::json!({}))
        .await
        .expect("awaiting_signature");

    let fence = expect_won(
        store
            .claim_finalise_exclusive_as(job_id, owner, Duration::from_secs(60))
            .await
            .expect("claim"),
    );

    // Mirrors the pre-claim helper's status set (includes Broadcasting).
    assert!(
        !store
            .fail_if_status(
                job_id,
                &[JobStatus::AwaitingSignature, JobStatus::Broadcasting],
                "pre-claim must not kill owned job",
            )
            .await
            .expect("fail_if_status"),
        "status-only fail must refuse a finalise_claimed row"
    );
    // Same shape for status-only complete.
    assert!(
        !store
            .complete_if_status(
                job_id,
                &[JobStatus::Broadcasting],
                serde_json::json!({"no": true}),
                200,
            )
            .await
            .expect("complete_if_status"),
        "status-only complete must refuse a finalise_claimed row"
    );

    let row = store.load(job_id).await.expect("load").expect("row");
    assert_eq!(row.status, JobStatus::Broadcasting);
    assert_eq!(row.phase, FINALISE_CLAIM_PHASE);
    assert!(row.error.is_none(), "owned row must not be failed via status");
    assert_eq!(
        row.request_body
            .get("finalise_claim")
            .and_then(|c| c.get("fence"))
            .and_then(|f| f.as_i64()),
        Some(fence)
    );

    // Unclaimed broadcasting (phase free) remains fail-able for pre-claim recovery.
    sqlx::query(
        "UPDATE jobs SET phase = 'publishing', \
                request_body = COALESCE(request_body, '{}'::jsonb) - 'finalise_claim' \
         WHERE public_id = $1",
    )
    .bind(job_id)
    .execute(store.pool())
    .await
    .expect("free claim");
    assert!(
        store
            .fail_if_status(
                job_id,
                &[JobStatus::AwaitingSignature, JobStatus::Broadcasting],
                "unclaimed broadcasting may fail",
            )
            .await
            .expect("fail unclaimed"),
        "unclaimed broadcasting row must still be fail-able"
    );
    let failed = store.load(job_id).await.expect("load").expect("row");
    assert_eq!(failed.status, JobStatus::Failed);

    drop(scope);
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
