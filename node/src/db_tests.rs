// Postgres state-layer tests for `db.rs`.
//
// Strategy: every test gets its own UUID-named schema inside a
// shared `postgres:17` container (one per test binary). Per-test
// isolation is preserved — no shared state, no `truncate_all`
// ordering, no risk of cross-test contamination — but the ~3 s
// container-boot cost is paid once per binary instead of once per
// test. See `crate::test_db` for the implementation and the link
// to issue #181.
//
// Migrations are applied inside the per-test schema via
// `sqlx::migrate!` driven by `test_db::setup_pool`, mirroring the
// schema the production `db::connect_and_migrate` produces.

use super::*;
use crate::test_db::setup_pool;
use crate::v1::{claim_stack_scan_mode, ScanStackMode};
use sqlx::Row;

/// Claim the legacy stack marker so `persist_state_tx` / related writers
/// pass the in-transaction capability check (boot does this via
/// `enforce_stack_scan_mode` in production).
async fn claim_legacy_stack(pool: &sqlx::PgPool) {
    claim_stack_scan_mode(pool, ScanStackMode::Legacy)
        .await
        .expect("claim legacy stack for test");
}

#[tokio::test]
async fn connect_and_migrate_creates_all_tables() {
    // Route the test through `db::connect_and_migrate` so its
    // success path (`Ok(pool)` return) stays covered under the
    // shared-container model. We still want per-test schema
    // isolation, so we take a `SchemaScope` from `setup_pool()`
    // and feed `connect_and_migrate` the shared base URL with an
    // `options=-c search_path=<schema>` libpq parameter — the
    // same pattern `connect_and_migrate_propagates_migration_failure`
    // already uses to land sqlx migrations inside the per-test
    // schema. The migrations are idempotent: `setup_pool` ran
    // them once during scope creation, and the second pass through
    // `connect_and_migrate` is a no-op via `_sqlx_migrations`
    // bookkeeping while still exercising the full success path.
    let scope = setup_pool().await;
    let url = format!(
        "{}?options=-c%20search_path%3D{}",
        scope.base_url(),
        scope.schema(),
    );
    let pool = connect_and_migrate(&url)
        .await
        .expect("connect_and_migrate ok");
    // Introspect via `information_schema.tables` — works on any
    // Postgres 9+ and avoids hard-coding pg_catalog quirks. Scoped
    // to the per-test schema (issue #181 Opt B): under the shared-
    // container model migrations run inside `<scope.schema()>`,
    // not `public`.
    let rows = sqlx::query(
        "SELECT table_name FROM information_schema.tables \
         WHERE table_schema = $1 \
         ORDER BY table_name",
    )
    .bind(scope.schema())
    .fetch_all(&pool)
    .await
    .expect("introspection query failed");
    let names: Vec<String> = rows.into_iter().map(|r| r.get::<String, _>(0)).collect();
    // Full expected schema after all migrations 0001-0014 (alphabetic
    // by `ORDER BY table_name`). `_sqlx_migrations` is created
    // implicitly by `sqlx::migrate!`. `minting_meta` (0002) is
    // dropped by 0005 (Phase D), absent from the final schema.
    //
    // Counts:
    //   * Pre-#113 schema (0001-0005):   8 tables
    //   * After 0006 (kind):             8 tables (ALTER only)
    //   * After 0007 (request_log):      9 tables
    //   * After 0008 (full DB trail):   19 tables + 1 trigger
    //   * After 0009 / 0010:            19 tables (polish only)
    //   * After 0013 (R2 probe results): 22 tables + 1 view
    //     (`r2_probe_runs_summary` is a VIEW from migration 0013.
    //     Postgres lists views in BOTH `information_schema.views` AND
    //     `information_schema.tables` (with `table_type = 'VIEW'`), so
    //     it shows up here when introspecting without a `table_type`
    //     filter — included at the correct alphabetic position below.)
    //   * After 0014 (jobs):             23 tables + 1 view (#161
    //     introduces the async Job-API state table.)
    //   * After 0015 (circuit digest):   24 tables + 1 view (the
    //     circuit-digest self-heal singleton — sorts between
    //     `boot_log` and `coin_proof_store`.)
    //   * After 0018 (asset_creators):   25 tables + 1 view (the
    //     off-circuit per-asset creator binding — sorts between
    //     `accounts` and `block_log`.)
    //   * After 0019 (v1 persistence): 31 tables + 1 view (additive
    //     NfLog / CoinHist / multi-asset account tables; created as
    //     historical `v11_*`, renamed to `v1_*` by 0027).
    //   * After 0020 (stack_scan_mode):  32 tables + 1 view (exclusive
    //     legacy vs v1 scan-stack claim for Cutover Stage 2).
    //   * After 0021 (pending_publishes): 33 tables + 1 view
    //     (durable AggregateStateNullifierV3 rebroadcast intent).
    //   * After 0023 (op_secret): ALTER-only.
    //   * After 0024 (self_heal_reset_meta): 34 tables + 1 view
    //     (self-heal reset-generation fence for job-advancing writes).
    //   * After 0025 (jobs kind attest_balance): ALTER-only.
    //   * After 0026 (r2 probe columns): ALTER + view recreate
    //     (no new table names; prover_mode / shape columns on runs).
    //   * After 0027 (rename v11_* → v1_*): same count; renames stack
    //     tables/indexes + stack_scan_mode / prover_mode labels.
    assert_eq!(
        names,
        vec![
            "_sqlx_migrations".to_string(),
            "account_history".to_string(),
            "accounts".to_string(),
            "asset_creators".to_string(),
            "block_log".to_string(),
            "boot_log".to_string(),
            "circuit_digest_meta".to_string(),
            "coin_proof_store".to_string(),
            "error_log".to_string(),
            "esplora_log".to_string(),
            "jobs".to_string(),
            "latest_block".to_string(),
            "mmr_root_index".to_string(),
            "mmr_state".to_string(),
            "observed_inscriptions".to_string(),
            "pending_inscriptions".to_string(),
            "r2_probe_hosts".to_string(),
            "r2_probe_runs".to_string(),
            "r2_probe_runs_summary".to_string(),
            "r2_probe_warm_calls".to_string(),
            "request_log".to_string(),
            "self_heal_reset_meta".to_string(),
            "smt_state".to_string(),
            "stack_scan_mode".to_string(),
            "state_update_log".to_string(),
            "tx_mining_log".to_string(),
            "username_claim_log".to_string(),
            "usernames".to_string(),
            "v1_accounts".to_string(),
            "v1_engine_meta".to_string(),
            "v1_nflog_entries".to_string(),
            "v1_nullifier_index".to_string(),
            "v1_pending_publishes".to_string(),
            "v1_spendable_coins".to_string(),
            "v1_spent_coins".to_string(),
        ]
    );
}

#[tokio::test]
async fn load_smt_returns_none_initially() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    assert!(load_smt(&pool).await.expect("load_smt failed").is_none());
}

#[tokio::test]
async fn load_mmr_returns_none_initially() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    assert!(load_mmr(&pool).await.expect("load_mmr failed").is_none());
}

#[tokio::test]
async fn load_latest_block_returns_none_initially() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    assert!(load_latest_block(&pool)
        .await
        .expect("load_latest_block failed")
        .is_none());
}

#[tokio::test]
async fn persist_state_tx_writes_smt_mmr_block_atomically() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let smt = vec![0xAAu8; 64];
    let mmr = vec![0xBBu8; 128];
    let block = [0xCCu8; 32];
    persist_state_tx(&pool, &smt, &mmr, &block, None)
        .await
        .expect("persist_state_tx failed");

    assert_eq!(load_smt(&pool).await.unwrap(), Some(smt));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(mmr));
    assert_eq!(load_latest_block(&pool).await.unwrap(), Some(block));
}

#[tokio::test]
async fn persist_state_tx_is_idempotent_on_conflict() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let smt1 = vec![1u8; 16];
    let mmr1 = vec![2u8; 16];
    let block1 = [3u8; 32];
    persist_state_tx(&pool, &smt1, &mmr1, &block1, None)
        .await
        .unwrap();

    let smt2 = vec![4u8; 32];
    let mmr2 = vec![5u8; 32];
    let block2 = [6u8; 32];
    persist_state_tx(&pool, &smt2, &mmr2, &block2, None)
        .await
        .unwrap();

    assert_eq!(load_smt(&pool).await.unwrap(), Some(smt2));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(mmr2));
    assert_eq!(load_latest_block(&pool).await.unwrap(), Some(block2));
}

#[tokio::test]
async fn persist_state_tx_writes_root_index_in_same_transaction() {
    // Phase-C atomicity guarantee: the `mmr_root_index` row rides
    // along inside the same Postgres transaction as SMT/MMR/
    // latest_block. Closing the crash window between the snapshot
    // and the standalone INSERT is the whole point — see the
    // doc-comment on `persist_state_tx` for the heal-on-restart
    // story. This test asserts all four landed from one call.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let smt = vec![0xAAu8; 64];
    let mmr = vec![0xBBu8; 128];
    let block = [0xCCu8; 32];
    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0x10u8; 32]);
    let smt_root = zkcoins_program::hash::digest_from_bytes(&[0x20u8; 32]);
    persist_state_tx(&pool, &smt, &mmr, &block, Some((&prev_root, &smt_root, 7)))
        .await
        .expect("persist_state_tx failed");

    assert_eq!(load_smt(&pool).await.unwrap(), Some(smt));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(mmr));
    assert_eq!(load_latest_block(&pool).await.unwrap(), Some(block));
    let entries = load_root_indices(&pool).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], (prev_root, smt_root, 7));
}

#[tokio::test]
async fn persist_state_tx_root_index_on_conflict_does_nothing() {
    // Re-scanning the same commit tx after a crash MUST be a no-op on
    // the root_index row — `update()` is replayed against the same
    // unchanged MMR and the (prev_mmr_root, smt_root, leaf_index)
    // tuple is identical, so `ON CONFLICT (prev_mmr_root) DO NOTHING`
    // keeps the original row authoritative. Belt-and-braces: the
    // second call's `smt_root` differs to prove that the conflict
    // branch genuinely takes the DO NOTHING path (otherwise the row
    // would be silently mutated).
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let smt = vec![1u8; 16];
    let mmr = vec![2u8; 16];
    let block = [3u8; 32];
    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0x10u8; 32]);
    let original_smt_root = zkcoins_program::hash::digest_from_bytes(&[0x20u8; 32]);
    let different_smt_root = zkcoins_program::hash::digest_from_bytes(&[0x99u8; 32]);

    persist_state_tx(
        &pool,
        &smt,
        &mmr,
        &block,
        Some((&prev_root, &original_smt_root, 0)),
    )
    .await
    .unwrap();
    persist_state_tx(
        &pool,
        &smt,
        &mmr,
        &block,
        Some((&prev_root, &different_smt_root, 0)),
    )
    .await
    .unwrap();

    let entries = load_root_indices(&pool).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].1, original_smt_root,
        "second call must DO NOTHING, original row stays authoritative"
    );
}

#[tokio::test]
async fn load_latest_block_rejects_wrong_length() {
    // Defensive branch in `load_latest_block`: the application only
    // writes 32-byte values via `persist_state_tx`, but BYTEA accepts
    // any length. Insert a deliberately wrong-length row directly
    // and assert the loader returns an `sqlx::Error::Decode` rather
    // than panicking or silently truncating.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    // Drop the 0010 length CHECK so the corrupt-row plant succeeds;
    // the subject of this test is the Rust-side defense in
    // `load_latest_block`, not the DB-level CHECK.
    sqlx::query("ALTER TABLE latest_block DROP CONSTRAINT latest_block_hash_length")
        .execute(&pool)
        .await
        .expect("drop latest_block_hash_length");
    sqlx::query("INSERT INTO latest_block (id, block_hash) VALUES (1, $1)")
        .bind(vec![0u8; 7])
        .execute(&pool)
        .await
        .unwrap();
    let err = load_latest_block(&pool)
        .await
        .expect_err("expected decode error");
    assert!(
        matches!(err, sqlx::Error::Decode(_)),
        "unexpected: {:?}",
        err
    );
}

#[tokio::test]
async fn load_all_accounts_returns_empty_initially() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let rows = load_all_accounts(&pool).await.unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn upsert_account_inserts_then_updates() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    // 64-byte composite (owner||asset_id) account key (Model B).
    let addr = vec![0xAAu8; 64];
    upsert_account(&pool, &addr, b"first").await.unwrap();
    let rows = load_all_accounts(&pool).await.unwrap();
    assert_eq!(rows, vec![(addr.clone(), b"first".to_vec())]);

    upsert_account(&pool, &addr, b"second").await.unwrap();
    let rows = load_all_accounts(&pool).await.unwrap();
    assert_eq!(rows, vec![(addr, b"second".to_vec())]);
}

// ---- Circuit-digest self-heal -------------------------------------------

#[tokio::test]
async fn load_circuit_digest_returns_none_initially() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    assert_eq!(load_circuit_digest(&pool).await.unwrap(), None);
}

#[tokio::test]
async fn store_circuit_digest_inserts_then_updates_on_conflict() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    store_circuit_digest(&pool, b"first-digest").await.unwrap();
    assert_eq!(
        load_circuit_digest(&pool).await.unwrap(),
        Some(b"first-digest".to_vec())
    );
    // Second call hits the `ON CONFLICT (id) DO UPDATE` arm.
    store_circuit_digest(&pool, b"second-digest").await.unwrap();
    assert_eq!(
        load_circuit_digest(&pool).await.unwrap(),
        Some(b"second-digest".to_vec())
    );
}

#[tokio::test]
async fn reset_proof_dependent_state_tx_wipes_state_and_stores_digest() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;

    // Seed every table the reset touches.
    upsert_account(&pool, &[9u8; 64], b"acct").await.unwrap();
    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0x11u8; 32]);
    let smt_root = zkcoins_program::hash::digest_from_bytes(&[0x22u8; 32]);
    persist_state_tx(
        &pool,
        b"smt",
        b"mmr",
        &[0xCCu8; 32],
        Some((&prev_root, &smt_root, 5)),
    )
    .await
    .unwrap();
    store_circuit_digest(&pool, b"OLD").await.unwrap();

    // Sanity: everything present before the reset.
    assert_eq!(load_all_accounts(&pool).await.unwrap().len(), 1);
    assert!(load_smt(&pool).await.unwrap().is_some());
    assert!(load_mmr(&pool).await.unwrap().is_some());
    assert!(load_latest_block(&pool).await.unwrap().is_some());
    assert_eq!(load_root_indices(&pool).await.unwrap().len(), 1);

    reset_proof_dependent_state_tx(&pool, b"NEW").await.unwrap();

    // All proof-dependent state gone, new digest stored, atomically.
    assert!(load_all_accounts(&pool).await.unwrap().is_empty());
    assert_eq!(load_smt(&pool).await.unwrap(), None);
    assert_eq!(load_mmr(&pool).await.unwrap(), None);
    assert_eq!(load_latest_block(&pool).await.unwrap(), None);
    assert!(load_root_indices(&pool).await.unwrap().is_empty());
    assert_eq!(
        load_circuit_digest(&pool).await.unwrap(),
        Some(b"NEW".to_vec())
    );
}

#[tokio::test]
async fn reset_proof_dependent_state_tx_overwrites_existing_digest_row() {
    // The reset's digest INSERT must hit the ON CONFLICT update arm when
    // a digest row already exists (the common case: a build was running
    // before, so a row is present).
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    store_circuit_digest(&pool, b"PREEXISTING").await.unwrap();
    reset_proof_dependent_state_tx(&pool, b"AFTER-RESET")
        .await
        .unwrap();
    assert_eq!(
        load_circuit_digest(&pool).await.unwrap(),
        Some(b"AFTER-RESET".to_vec())
    );
}

#[tokio::test]
async fn load_all_accounts_returns_all_inserted() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let a1 = vec![0x01u8; 64];
    let a2 = vec![0x02u8; 64];
    let a3 = vec![0x03u8; 64];
    upsert_account(&pool, &a1, b"d1").await.unwrap();
    upsert_account(&pool, &a2, b"d2").await.unwrap();
    upsert_account(&pool, &a3, b"d3").await.unwrap();
    let mut rows = load_all_accounts(&pool).await.unwrap();
    rows.sort();
    assert_eq!(
        rows,
        vec![
            (a1, b"d1".to_vec()),
            (a2, b"d2".to_vec()),
            (a3, b"d3".to_vec()),
        ]
    );
}

#[tokio::test]
async fn load_all_usernames_returns_empty_initially() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let rows = load_all_usernames(&pool).await.unwrap();
    assert!(rows.is_empty());
}

#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_returns_true_on_new() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let addr = vec![0xAAu8; 32];
    let ok = claim_username(&pool, "alice", &addr).await.unwrap();
    assert!(ok);
    let rows = load_all_usernames(&pool).await.unwrap();
    assert_eq!(rows, vec![("alice".to_string(), addr)]);
}

#[cfg(feature = "username-claim")]
#[tokio::test]
async fn claim_username_returns_false_on_conflict() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let addr1 = vec![0xAAu8; 32];
    let addr2 = vec![0xBBu8; 32];
    assert!(claim_username(&pool, "alice", &addr1).await.unwrap());
    // Second claim with a different address must NOT overwrite.
    assert!(!claim_username(&pool, "alice", &addr2).await.unwrap());
    // The original binding must survive.
    let rows = load_all_usernames(&pool).await.unwrap();
    assert_eq!(rows, vec![("alice".to_string(), addr1)]);
}

// Setup uses `claim_username` to seed a row, so this test only runs
// when the claim path is compiled in. The pure resolve-by-raw-INSERT
// path is exercised by `resolve_username_returns_none_for_unknown`
// plus the `username_tests.rs::resolve_*` cases.
#[cfg(feature = "username-claim")]
#[tokio::test]
async fn resolve_username_returns_address_for_claimed_name() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let addr = vec![0xABu8; 32];
    claim_username(&pool, "bob", &addr).await.unwrap();
    let resolved = resolve_username(&pool, "bob").await.unwrap();
    assert_eq!(resolved, Some(addr));
}

#[tokio::test]
async fn resolve_username_returns_none_for_unknown() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let resolved = resolve_username(&pool, "nobody").await.unwrap();
    assert!(resolved.is_none());
}

#[tokio::test]
async fn connect_and_migrate_propagates_connect_failure() {
    // Unresolvable host + explicit libpq `connect_timeout` so the error
    // path fails in seconds rather than hanging on OS TCP blackholes
    // (seen with low-numbered ports on some macOS/Docker setups where
    // `127.0.0.1:1` never surfaces a refused connection to sqlx).
    // Exercises the otherwise-unreached error branch in
    // `connect_and_migrate`.
    let err = connect_and_migrate(
        "postgres://postgres:postgres@invalid.invalid:5432/postgres?connect_timeout=2",
    )
    .await
    .expect_err("expected connect failure");
    assert!(
        matches!(
            err,
            sqlx::Error::Io(_)
                | sqlx::Error::PoolTimedOut
                | sqlx::Error::Tls(_)
                | sqlx::Error::Protocol(_)
                | sqlx::Error::Configuration(_)
        ),
        "unexpected: {:?}",
        err
    );
}

/// Happy-path: `commit_mint_tx` upserts every account in the bundle in
/// a single transaction. Phase D collapsed the optimistic counter bump
/// out of this helper (the minting account's `num_pubkeys` is now
/// derived from SMT membership at runtime), so the only assertion left
/// is "every row in the input slice round-trips through `accounts`".
/// Multi-row exercises the loop body that the old single-account
/// fixture never visited.
#[tokio::test]
async fn commit_mint_tx_upserts_every_account_atomically() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let addr_a = [0xAAu8; 64];
    let data_a = vec![0xA1u8; 8];
    let addr_b = [0xBBu8; 64];
    let data_b = vec![0xB1u8; 12];
    let accounts: Vec<(&[u8], &[u8])> = vec![(&addr_a[..], &data_a), (&addr_b[..], &data_b)];
    commit_mint_tx(&pool, &accounts)
        .await
        .expect("commit_mint_tx must succeed");

    let rows = load_all_accounts(&pool).await.unwrap();
    let mut got: Vec<(Vec<u8>, Vec<u8>)> = rows.into_iter().collect();
    got.sort();
    let mut want = vec![
        (addr_a.to_vec(), data_a.clone()),
        (addr_b.to_vec(), data_b.clone()),
    ];
    want.sort();
    assert_eq!(got, want, "all accounts in the bundle must round-trip");
}

/// Second call with the same address overwrites the prior payload via
/// the `ON CONFLICT (address) DO UPDATE` branch. Exercises the
/// idempotent-replay shape the post-Phase-D mint flow relies on (a
/// concurrent receive between the snapshot and the commit will retry
/// with the latest serialized Account on the next mint).
#[tokio::test]
async fn commit_mint_tx_is_idempotent_on_conflict() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let addr = [0xCCu8; 64];
    let first = vec![0x01u8; 16];
    let second = vec![0x02u8; 24];

    commit_mint_tx(&pool, &[(&addr[..], &first)])
        .await
        .expect("first commit");
    commit_mint_tx(&pool, &[(&addr[..], &second)])
        .await
        .expect("second commit");

    let rows = load_all_accounts(&pool).await.unwrap();
    assert_eq!(rows, vec![(addr.to_vec(), second.clone())]);
}

/// Empty input slice → empty transaction, no UPSERTs, no error. Pins
/// the no-op shape so a future refactor that turns the empty case into
/// a panic or error surfaces here rather than at a live caller.
#[tokio::test]
async fn commit_mint_tx_with_empty_accounts_is_noop() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    commit_mint_tx(&pool, &[])
        .await
        .expect("empty commit must succeed");
    let rows = load_all_accounts(&pool).await.unwrap();
    assert!(rows.is_empty());
}

#[tokio::test]
async fn connect_and_migrate_propagates_migration_failure() {
    // Apply our migrations, then poison the `_sqlx_migrations` table
    // so the next `connect_and_migrate` re-run sees a checksum
    // mismatch and bails out via the `sqlx::Error::Migrate` branch.
    // This is the only sqlx-native way to force a deterministic
    // migration error without writing a second `.sql` file solely
    // for the test (which would itself drift from the real schema).
    //
    // Under the shared-container model (issue #181 Opt B) the
    // per-test isolated schema lives inside the shared container.
    // To make `db::connect_and_migrate` (which knows nothing about
    // our `SchemaScope`) target that same schema, we feed it the
    // shared base URL with an `options=-c search_path=<schema>`
    // libpq parameter so the migration runner lands inside the
    // poisoned `_sqlx_migrations` table.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1")
        .bind(vec![0u8; 32])
        .execute(&pool)
        .await
        .unwrap();
    let url = format!(
        "{}?options=-c%20search_path%3D{}",
        scope.base_url(),
        scope.schema()
    );
    let err = connect_and_migrate(&url)
        .await
        .expect_err("expected migration failure");
    assert!(
        matches!(err, sqlx::Error::Migrate(_)),
        "unexpected: {:?}",
        err
    );
}

// ---- Phase E: pending_inscription_status_by_commit_txid ------------------

#[tokio::test]
async fn pending_inscription_status_by_commit_txid_returns_none_for_unknown_txid() {
    // Scanner's pre-state.update lookup: an external / out-of-band
    // inscription (not produced by this node's mint flow) has no
    // `pending_inscriptions` row. The helper must return `None` so the
    // scanner falls through to its normal state.update path instead of
    // short-circuiting.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let status = pending_inscription_status_by_commit_txid(&pool, &[0xABu8; 32])
        .await
        .expect("lookup must not error on missing row");
    assert!(status.is_none());
}

#[tokio::test]
async fn pending_inscription_status_by_commit_txid_returns_current_status() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let commit_txid = [0xCDu8; 32];
    let reveal_txid = [0xCEu8; 32];
    let commitment = b"test-commitment";
    let commit_tx = b"test-commit-tx";
    let reveal_tx = b"test-reveal-tx";
    insert_pending_inscription(
        &pool,
        &commit_txid,
        &reveal_txid,
        InscriptionKind::Mint,
        commitment,
        commit_tx,
        reveal_tx,
        12_345,
    )
    .await
    .expect("insert must succeed");
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_CONSTRUCTED.to_string())
    );

    update_pending_status(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST)
        .await
        .unwrap();
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_REVEAL_BROADCAST.to_string())
    );

    update_pending_status(&pool, &commit_txid, PENDING_STATUS_COMPLETE)
        .await
        .unwrap();
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_COMPLETE.to_string())
    );
}

// ---- Phase E: persist_state_and_mark_complete_tx -------------------------

/// Helper: insert a `pending_inscriptions` row in the given starting
/// status so the atomic-tx tests can exercise the mark-complete step.
async fn seed_pending_row(pool: &PgPool, commit_txid: &[u8], status: &str) {
    claim_legacy_stack(pool).await;

    // Synthetic reveal txid for tests — not derived from the seed
    // bytes since this helper is only used to drive the status state
    // machine, not the reveal-txid lookup.
    let reveal_txid: [u8; 32] = [0xAB; 32];
    insert_pending_inscription(
        pool,
        commit_txid,
        &reveal_txid,
        InscriptionKind::Mint,
        b"test-commitment",
        b"test-commit-tx",
        b"test-reveal-tx",
        12_345,
    )
    .await
    .expect("insert pending row");
    update_pending_status(pool, commit_txid, status)
        .await
        .expect("seed status");
}

#[tokio::test]
async fn persist_state_and_mark_complete_tx_writes_state_and_advances_row() {
    // The atomic Phase-E helper writes SMT/MMR/root_index AND marks the
    // pending row `complete` in one transaction. `latest_block` is left
    // untouched (the scanner is the only legitimate writer).
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let commit_txid = [0x55u8; 32];
    seed_pending_row(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST).await;

    let smt = vec![0x11u8; 64];
    let mmr = vec![0x22u8; 128];
    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0x40u8; 32]);
    let smt_root = zkcoins_program::hash::digest_from_bytes(&[0x50u8; 32]);

    persist_state_and_mark_complete_tx(
        &pool,
        &smt,
        &mmr,
        Some((&prev_root, &smt_root, 3)),
        &commit_txid,
    )
    .await
    .expect("persist_state_and_mark_complete_tx must succeed");

    assert_eq!(load_smt(&pool).await.unwrap(), Some(smt));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(mmr));
    assert_eq!(load_latest_block(&pool).await.unwrap(), None);
    let entries = load_root_indices(&pool).await.unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0], (prev_root, smt_root, 3));
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_COMPLETE.to_string())
    );
}

#[tokio::test]
async fn persist_state_and_mark_complete_tx_preserves_existing_latest_block() {
    // A scanner sweep landed a `latest_block` before the mint flow ever
    // ran. The mint flow's atomic persist call must NOT rewind that
    // pointer back to the genesis fallback — the helper is responsible
    // for SMT/MMR/root_index/pending_inscriptions only.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let scanner_block = [0x77u8; 32];
    persist_state_tx(&pool, b"old-smt", b"old-mmr", &scanner_block, None)
        .await
        .unwrap();

    let commit_txid = [0x66u8; 32];
    seed_pending_row(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST).await;

    persist_state_and_mark_complete_tx(&pool, b"new-smt", b"new-mmr", None, &commit_txid)
        .await
        .unwrap();

    assert_eq!(load_smt(&pool).await.unwrap(), Some(b"new-smt".to_vec()));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(b"new-mmr".to_vec()));
    assert_eq!(
        load_latest_block(&pool).await.unwrap(),
        Some(scanner_block),
        "latest_block must remain untouched"
    );
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_COMPLETE.to_string())
    );
}

#[tokio::test]
async fn persist_state_and_mark_complete_tx_accepts_no_root_index() {
    // Mirror the `persist_state_tx` no-root-index branch: a call with
    // `None` writes SMT + MMR + the row advance only. The
    // mmr_root_index table stays empty, no error, latest_block untouched.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let commit_txid = [0x88u8; 32];
    seed_pending_row(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST).await;

    persist_state_and_mark_complete_tx(&pool, b"smt-only", b"mmr-only", None, &commit_txid)
        .await
        .expect("no-root-index path must succeed");

    assert_eq!(load_smt(&pool).await.unwrap(), Some(b"smt-only".to_vec()));
    assert_eq!(load_mmr(&pool).await.unwrap(), Some(b"mmr-only".to_vec()));
    assert!(load_root_indices(&pool).await.unwrap().is_empty());
    assert_eq!(load_latest_block(&pool).await.unwrap(), None);
    assert_eq!(
        pending_inscription_status_by_commit_txid(&pool, &commit_txid)
            .await
            .unwrap(),
        Some(PENDING_STATUS_COMPLETE.to_string())
    );
}

#[tokio::test]
async fn persist_state_and_mark_complete_tx_rollback_on_failure_leaves_state_untouched() {
    // The BLOCKER fix's load-bearing invariant: when the atomic tx
    // fails, NOTHING lands on disk — not the SMT, not the MMR, not the
    // root_index row, and crucially the pending row stays at its prior
    // status (so scanner-replay will integrate the inscription and
    // mark complete itself, never doubling up).
    //
    // We synthesize a tx failure by passing a `commit_txid` that
    // violates the BYTEA length expectation: the `pending_inscriptions.commit_txid`
    // column is `BYTEA NOT NULL` with no length check at the SQL
    // level, so we instead force a constraint violation by writing the
    // mmr_root_index row twice with conflicting payloads — wait, the
    // helper uses ON CONFLICT DO NOTHING. The cleanest way to force a
    // mid-tx failure is a leaf_index value that does not fit i64; the
    // helper's `i64::try_from(u64)` returns `sqlx::Error::Encode`
    // BEFORE the BEGIN, so that wouldn't actually exercise the
    // rollback path. Instead, drop the pending_inscriptions table
    // between the seed and the call so the UPDATE inside the tx
    // surfaces a sqlx::Error and the BEGIN/COMMIT envelope rolls
    // SMT/MMR back.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let commit_txid = [0x99u8; 32];
    seed_pending_row(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST).await;

    // Pre-call snapshot: nothing in the state tables yet.
    assert_eq!(load_smt(&pool).await.unwrap(), None);
    assert_eq!(load_mmr(&pool).await.unwrap(), None);

    // Force a mid-tx failure by dropping `pending_inscriptions`. The
    // UPDATE inside the helper will fail with "relation does not
    // exist", the transaction rolls back, and the smt/mmr UPSERTs
    // performed earlier in the same tx are undone.
    //
    // CASCADE is required after migration 0010 added FK constraints
    // from `tx_mining_log.commit_txid` and
    // `coin_proof_store.consumed_by_commit_txid` to
    // `pending_inscriptions(commit_txid)`. Without CASCADE the DROP
    // is rejected by Postgres with "cannot drop table … because
    // other objects depend on it". The dependent tables and their FK
    // constraints get dropped along with the parent — fine for this
    // test, which is exercising a synthetic mid-tx failure, not a
    // real schema change.
    sqlx::query("DROP TABLE pending_inscriptions CASCADE")
        .execute(&pool)
        .await
        .unwrap();

    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0xA0u8; 32]);
    let smt_root = zkcoins_program::hash::digest_from_bytes(&[0xB0u8; 32]);
    let res = persist_state_and_mark_complete_tx(
        &pool,
        b"would-be-smt",
        b"would-be-mmr",
        Some((&prev_root, &smt_root, 7)),
        &commit_txid,
    )
    .await;
    assert!(
        res.is_err(),
        "atomic helper must surface the UPDATE failure"
    );

    // Post-call invariant: SMT/MMR did NOT advance. The
    // BEGIN/COMMIT envelope rolled the earlier UPSERTs back.
    assert_eq!(
        load_smt(&pool).await.unwrap(),
        None,
        "atomic-tx rollback must leave smt_state untouched"
    );
    assert_eq!(
        load_mmr(&pool).await.unwrap(),
        None,
        "atomic-tx rollback must leave mmr_state untouched"
    );
    assert!(
        load_root_indices(&pool).await.unwrap().is_empty(),
        "atomic-tx rollback must leave mmr_root_index untouched"
    );
}

#[tokio::test]
async fn persist_state_and_mark_complete_tx_idempotent_on_already_complete_row() {
    // The UPDATE guard `status <> 'complete'` keeps the helper
    // idempotent: a retry against a row that is already `complete`
    // re-runs the SMT/MMR/root_index UPSERTs (identical bytes, no-op
    // semantically) but does NOT bump `updated_at` on the pending
    // row. This matters for the audit log on scanner-replay edge
    // cases where the mint flow's tx committed but a transient client
    // error caused the caller to retry.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let commit_txid = [0xAAu8; 32];
    seed_pending_row(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST).await;

    let prev_root = zkcoins_program::hash::digest_from_bytes(&[0x10u8; 32]);
    let smt_root = zkcoins_program::hash::digest_from_bytes(&[0x20u8; 32]);
    persist_state_and_mark_complete_tx(
        &pool,
        b"smt-1",
        b"mmr-1",
        Some((&prev_root, &smt_root, 1)),
        &commit_txid,
    )
    .await
    .expect("first call must succeed");

    // Record the row's updated_at after the first complete advance.
    // We compare as text to avoid pulling chrono into the test build —
    // TIMESTAMPTZ::text round-trips losslessly.
    let (first_updated_at,): (String,) =
        sqlx::query_as("SELECT updated_at::text FROM pending_inscriptions WHERE commit_txid = $1")
            .bind(&commit_txid[..])
            .fetch_one(&pool)
            .await
            .unwrap();

    // A second invocation against the same (already-complete) row
    // must succeed and leave the row's updated_at untouched.
    persist_state_and_mark_complete_tx(
        &pool,
        b"smt-1",
        b"mmr-1",
        Some((&prev_root, &smt_root, 1)),
        &commit_txid,
    )
    .await
    .expect("retry against already-complete row must succeed");

    let (second_updated_at,): (String,) =
        sqlx::query_as("SELECT updated_at::text FROM pending_inscriptions WHERE commit_txid = $1")
            .bind(&commit_txid[..])
            .fetch_one(&pool)
            .await
            .unwrap();

    assert_eq!(
        first_updated_at, second_updated_at,
        "guarded UPDATE must NOT bump updated_at on already-complete row"
    );
}

// ============================================================================
// Coverage tests for migration 0006-0010 helpers (added in this PR stack).
// Each test exercises one insert path against a fresh test container so the
// 100% line/function gate stays green.
// ============================================================================

#[test]
fn inscription_kind_from_db_str_returns_none_for_invalid() {
    // The `_ => None` arm in `from_db_str` is reached only by bogus
    // input — every DB row goes through the CHECK constraint
    // ('mint' | 'send'). Tested directly.
    assert!(InscriptionKind::from_db_str("nope").is_none());
    assert!(InscriptionKind::from_db_str("").is_none());
}

#[tokio::test]
async fn insert_request_log_writes_row() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let entry = RequestLogEntry {
        method: "POST".into(),
        path: "/api/mint".into(),
        query: Some("debug=1".into()),
        remote_addr: Some("127.0.0.1:54321".into()),
        client_ip: Some("203.0.113.7".into()),
        user_agent: Some("wallet/1.0".into()),
        request_headers: serde_json::json!({"content-type": "application/json"}),
        request_body: b"{}".to_vec(),
        response_status: 200,
        response_headers: serde_json::json!({"x-trace-id": "abc"}),
        response_body: b"{\"ok\":true}".to_vec(),
        duration_us: 1234,
    };
    insert_request_log(&pool, &entry).await.unwrap();
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM request_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn insert_esplora_log_writes_row() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let entry = EsploraLogEntry {
        direction: "outbound_http",
        method: Some("POST".into()),
        url: "http://example/tx".into(),
        request_body: Some(b"raw".to_vec()),
        response_status: Some(200),
        response_body: Some(b"ok".to_vec()),
        duration_us: Some(42),
        trigger_source: Some("mint".into()),
        triggering_request_log_id: None,
    };
    insert_esplora_log(&pool, &entry).await.unwrap();
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM esplora_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn insert_error_log_writes_row() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let entry = ErrorLogEntry {
        severity: "error",
        source: "publisher::broadcast".into(),
        message: "broadcast failed".into(),
        error_chain: Some("io: connection refused".into()),
        request_log_id: None,
    };
    insert_error_log(&pool, &entry).await.unwrap();
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM error_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn insert_block_log_writes_row_and_is_idempotent() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let entry = BlockLogEntry {
        block_hash: vec![0x11; 32],
        block_height: Some(7),
        inscription_count: 2,
        processing_duration_us: Some(99),
    };
    insert_block_log(&pool, &entry).await.unwrap();
    // ON CONFLICT (block_hash) DO NOTHING — second insert is a no-op.
    insert_block_log(&pool, &entry).await.unwrap();
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM block_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn insert_observed_inscription_and_mark_integrated() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let commit_txid = vec![0x22; 32];
    let entry = ObservedInscriptionEntry {
        commit_txid: commit_txid.clone(),
        block_hash: Some(vec![0x33; 32]),
        block_height: Some(42),
        source: "external",
        commitment: vec![0xAA; 145],
        public_key: vec![0x03; 33],
        integrated: false,
    };
    insert_observed_inscription(&pool, &entry).await.unwrap();
    // Idempotent ON CONFLICT — second insert is a no-op.
    insert_observed_inscription(&pool, &entry).await.unwrap();

    // Pre-flip: integrated=false, integrated_at IS NULL.
    let (pre_integrated,): (bool,) =
        sqlx::query_as("SELECT integrated FROM observed_inscriptions WHERE commit_txid = $1")
            .bind(&commit_txid[..])
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(!pre_integrated);

    mark_observed_inscription_integrated(&pool, &commit_txid)
        .await
        .unwrap();

    // Post-flip: both columns advanced; the logical-pair CHECK from 0010
    // would have rejected a half-update.
    let (post_integrated, has_ts): (bool, bool) = sqlx::query_as(
        "SELECT integrated, integrated_at IS NOT NULL FROM observed_inscriptions WHERE commit_txid = $1",
    )
    .bind(&commit_txid[..])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert!(post_integrated);
    assert!(has_ts);

    // Second flip is a no-op (WHERE integrated = FALSE filter).
    mark_observed_inscription_integrated(&pool, &commit_txid)
        .await
        .unwrap();
}

#[tokio::test]
async fn insert_state_update_log_writes_row() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let entry = StateUpdateLogEntry {
        trigger_source: "mint",
        commit_txid: Some(vec![0x44; 32]),
        prev_mmr_root: vec![0x55; 32],
        new_mmr_root: vec![0x66; 32],
        smt_root_before: vec![0x77; 32],
        smt_root_after: vec![0x88; 32],
        commitment_count: 1,
    };
    insert_state_update_log(&pool, &entry).await.unwrap();
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM state_update_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn insert_account_history_writes_row_directly() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let entry = AccountHistoryEntry {
        address: vec![0x99; 32],
        prev_data: None,
        new_data: b"new-blob".to_vec(),
        source: "recovery",
        triggering_commit_txid: None,
        triggering_request_log_id: None,
    };
    insert_account_history(&pool, &entry).await.unwrap();
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM account_history")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn insert_username_claim_log_writes_row() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let entry = UsernameClaimLogEntry {
        requested_username: "Alice".into(),
        normalized_username: "alice".into(),
        address: vec![0xAA; 32],
        signature: vec![0xBB; 64],
        success: true,
        reject_reason: None,
        request_log_id: None,
    };
    insert_username_claim_log(&pool, &entry).await.unwrap();
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM username_claim_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn insert_tx_mining_log_writes_row() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    // The 0010 FK from `tx_mining_log.commit_txid` to
    // `pending_inscriptions(commit_txid)` requires the parent row first.
    let commit_txid = [0xCC; 32];
    let reveal_txid = [0xDD; 32];
    insert_pending_inscription(
        &pool,
        &commit_txid,
        &reveal_txid,
        InscriptionKind::Mint,
        b"commitment",
        b"commit-tx",
        b"reveal-tx",
        1000,
    )
    .await
    .unwrap();

    let entry = TxMiningLogEntry {
        target_prefix: "4242".into(),
        nonces_tried: 100,
        duration_us: 1234,
        final_nonce: Some(99),
        final_txid: vec![0xEE; 32],
        commit_txid: Some(commit_txid.to_vec()),
    };
    insert_tx_mining_log(&pool, &entry).await.unwrap();
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tx_mining_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn insert_boot_log_writes_row() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let entry = BootLogEntry {
        event_type: "startup".into(),
        message: "node started".into(),
        metadata: Some(serde_json::json!({"pid": 42})),
    };
    insert_boot_log(&pool, &entry).await.unwrap();
    let (count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM boot_log")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn update_pending_failure_reason_records_error_without_changing_status() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let commit_txid = [0x77; 32];
    let reveal_txid = [0x78; 32];
    insert_pending_inscription(
        &pool,
        &commit_txid,
        &reveal_txid,
        InscriptionKind::Send,
        b"c",
        b"ctx",
        b"rtx",
        500,
    )
    .await
    .unwrap();
    update_pending_status(&pool, &commit_txid, PENDING_STATUS_COMMIT_BROADCAST)
        .await
        .unwrap();

    update_pending_failure_reason(&pool, &commit_txid, "boom")
        .await
        .unwrap();

    let (status, reason): (String, Option<String>) = sqlx::query_as(
        "SELECT status, failure_reason FROM pending_inscriptions WHERE commit_txid = $1",
    )
    .bind(&commit_txid[..])
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(status, PENDING_STATUS_COMMIT_BROADCAST);
    assert_eq!(reason.as_deref(), Some("boom"));
}

#[tokio::test]
async fn upsert_account_with_source_tags_history_via_trigger() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    // The `accounts.address` is the 64-byte composite owner||asset_id
    // key (Model B). The history-capture trigger writes only the 32-byte
    // OWNER prefix into `account_history.address`, so the history queries
    // below resolve by that owner prefix.
    let mut address = vec![0x10u8; 32]; // owner
    address.extend_from_slice(&[0x20u8; 32]); // asset_id
    let owner_prefix = &address[..32];
    upsert_account_with_source(&pool, &address, b"v1", "mint")
        .await
        .unwrap();
    let (src, prev_data): (String, Option<Vec<u8>>) =
        sqlx::query_as("SELECT source, prev_data FROM account_history WHERE address = $1")
            .bind(owner_prefix)
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(src, "mint");
    assert!(prev_data.is_none(), "first insert has no prev_data");

    // Second upsert: trigger sees TG_OP='UPDATE' and OLD.data != NEW.data,
    // writes another row with prev_data=Some(b"v1").
    upsert_account_with_source(&pool, &address, b"v2", "send")
        .await
        .unwrap();
    let rows: Vec<(String, Option<Vec<u8>>)> = sqlx::query_as(
        "SELECT source, prev_data FROM account_history WHERE address = $1 ORDER BY id",
    )
    .bind(owner_prefix)
    .fetch_all(&pool)
    .await
    .unwrap();
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].0, "send");
    assert_eq!(rows[1].1.as_deref(), Some(b"v1".as_ref()));
}

#[tokio::test]
async fn get_inscription_summary_returns_none_for_unknown_txid() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let res = get_inscription_summary_by_commit_txid(&pool, &[0xFE; 32])
        .await
        .unwrap();
    assert!(res.is_none());
}

#[tokio::test]
async fn get_inscription_summary_returns_full_row() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let commit_txid = [0x12; 32];
    let reveal_txid = [0x34; 32];
    insert_pending_inscription(
        &pool,
        &commit_txid,
        &reveal_txid,
        InscriptionKind::Mint,
        b"c",
        b"ctx",
        b"rtx",
        9_001,
    )
    .await
    .unwrap();
    update_pending_failure_reason(&pool, &commit_txid, "transient esplora 503")
        .await
        .unwrap();

    let summary = get_inscription_summary_by_commit_txid(&pool, &commit_txid)
        .await
        .unwrap()
        .expect("row must be returned");
    // Display form: reverse of stored bytes.
    let mut display = commit_txid.to_vec();
    display.reverse();
    assert_eq!(summary.commit_txid, hex::encode(display));
    let mut reveal_display = reveal_txid.to_vec();
    reveal_display.reverse();
    assert_eq!(
        summary.reveal_txid.as_deref(),
        Some(hex::encode(reveal_display).as_str())
    );
    assert_eq!(summary.kind, InscriptionKind::Mint);
    assert_eq!(summary.status, PENDING_STATUS_CONSTRUCTED);
    assert_eq!(summary.commit_output_value, 9_001);
    assert_eq!(
        summary.failure_reason.as_deref(),
        Some("transient esplora 503")
    );
    // Timestamps formatted via to_char — same shape on both columns.
    assert!(summary.created_at.ends_with('Z'));
    assert!(summary.updated_at.ends_with('Z'));
}

#[tokio::test]
async fn load_pending_in_progress_rejects_invalid_kind_in_row() {
    // The Rust-side `InscriptionKind::from_db_str` defence in
    // `load_pending_in_progress` only fires when the DB row contains
    // a `kind` value outside the CHECK enum. Drop the CHECK first
    // so we can plant a corrupt row, then assert the loader surfaces
    // `sqlx::Error::Decode`.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    sqlx::query(
        "ALTER TABLE pending_inscriptions DROP CONSTRAINT pending_inscriptions_status_check",
    )
    .execute(&pool)
    .await
    .expect("drop status check");
    sqlx::query("ALTER TABLE pending_inscriptions DROP CONSTRAINT pending_inscriptions_kind_check")
        .execute(&pool)
        .await
        .expect("drop kind check");
    sqlx::query(
        "INSERT INTO pending_inscriptions \
         (commit_txid, reveal_txid, status, kind, commitment, commit_tx, reveal_tx, commit_output_value) \
         VALUES ($1, $2, 'constructed', 'bogus', $3, $4, $5, 0)",
    )
    .bind(&[0x10u8; 32][..])
    .bind(&[0x11u8; 32][..])
    .bind(b"c".to_vec())
    .bind(b"ctx".to_vec())
    .bind(b"rtx".to_vec())
    .execute(&pool)
    .await
    .expect("plant row");

    let err = load_pending_in_progress(&pool)
        .await
        .expect_err("loader must reject bogus kind");
    assert!(matches!(err, sqlx::Error::Decode(_)));
}

#[tokio::test]
async fn get_inscription_summary_rejects_invalid_kind_in_row() {
    // Same defensive branch but inside the single-row lookup used by
    // the `GET /api/inscriptions/:txid` handler.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    sqlx::query(
        "ALTER TABLE pending_inscriptions DROP CONSTRAINT pending_inscriptions_status_check",
    )
    .execute(&pool)
    .await
    .expect("drop status check");
    sqlx::query("ALTER TABLE pending_inscriptions DROP CONSTRAINT pending_inscriptions_kind_check")
        .execute(&pool)
        .await
        .expect("drop kind check");
    let commit_txid = [0x20u8; 32];
    sqlx::query(
        "INSERT INTO pending_inscriptions \
         (commit_txid, reveal_txid, status, kind, commitment, commit_tx, reveal_tx, commit_output_value) \
         VALUES ($1, $2, 'constructed', 'bogus', $3, $4, $5, 0)",
    )
    .bind(&commit_txid[..])
    .bind(&[0x21u8; 32][..])
    .bind(b"c".to_vec())
    .bind(b"ctx".to_vec())
    .bind(b"rtx".to_vec())
    .execute(&pool)
    .await
    .expect("plant row");

    let err = get_inscription_summary_by_commit_txid(&pool, &commit_txid)
        .await
        .expect_err("summary must reject bogus kind");
    assert!(matches!(err, sqlx::Error::Decode(_)));
}

// ---- list_account_history (issue #153) ------------------------------------

/// Insert a synthetic `account_history` row directly so the test can
/// pin the timestamp ordering without racing the trigger-driven path.
async fn plant_history_row(
    pool: &PgPool,
    address: &[u8],
    source: &str,
    new_balance: u64,
    seconds_ago: i64,
) {
    use crate::account_node::Account;
    let mut a = Account::new();
    a.balance = new_balance;
    let new_data = bincode::serialize(&a).expect("serialize account");
    sqlx::query(
        "INSERT INTO account_history \
         (address, prev_data, new_data, source, changed_at) \
         VALUES ($1, NULL, $2, $3, NOW() - ($4 || ' seconds')::INTERVAL)",
    )
    .bind(address)
    .bind(&new_data)
    .bind(source)
    .bind(seconds_ago.to_string())
    .execute(pool)
    .await
    .expect("insert account_history row");
}

#[tokio::test]
async fn list_account_history_empty_returns_zero_total() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let address = [0xaau8; 32];
    let (rows, total) = list_account_history(&pool, &address[..], 50, 0)
        .await
        .expect("list returns Ok");
    assert!(rows.is_empty());
    assert_eq!(total, 0);
}

#[tokio::test]
async fn list_account_history_orders_newest_first_and_paginates() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let address = [0xbbu8; 32];
    // Plant rows at 30 s, 20 s, 10 s ago — list must order
    // newest-first (10 s, 20 s, 30 s).
    plant_history_row(&pool, &address[..], "mint", 100, 30).await;
    plant_history_row(&pool, &address[..], "receive", 200, 20).await;
    plant_history_row(&pool, &address[..], "send", 150, 10).await;

    let (page, total) = list_account_history(&pool, &address[..], 50, 0)
        .await
        .unwrap();
    assert_eq!(total, 3);
    assert_eq!(page.len(), 3);
    assert_eq!(page[0].source, "send", "newest first");
    assert_eq!(page[1].source, "receive");
    assert_eq!(page[2].source, "mint");

    // Limit + offset
    let (page, total) = list_account_history(&pool, &address[..], 1, 1)
        .await
        .unwrap();
    assert_eq!(page.len(), 1);
    assert_eq!(page[0].source, "receive");
    assert_eq!(total, 3, "total stays consistent across pages");

    // Offset past total
    let (page, total) = list_account_history(&pool, &address[..], 10, 99)
        .await
        .unwrap();
    assert!(page.is_empty());
    assert_eq!(
        total, 3,
        "empty page still surfaces the real total (no second-query branch needed)"
    );

    // Other address never appears.
    let other = [0xccu8; 32];
    let (page, total) = list_account_history(&pool, &other[..], 10, 0)
        .await
        .unwrap();
    assert!(page.is_empty());
    assert_eq!(total, 0);
}

#[tokio::test]
async fn list_account_history_surfaces_blob_and_metadata() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let address = [0xddu8; 32];
    plant_history_row(&pool, &address[..], "mint", 12_345, 1).await;
    let (rows, total) = list_account_history(&pool, &address[..], 10, 0)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(total, 1);
    let row = &rows[0];
    assert_eq!(row.source, "mint");
    assert!(row.prev_data.is_none(), "first INSERT has no prev_data");
    assert!(row.commit_txid.is_none());
    assert!(row.block_height.is_none());
    assert!(row.pending_status.is_none());
    assert!(row.timestamp_secs > 0, "timestamp epoch derived");
    // new_data round-trips through bincode -> Account
    let decoded: crate::account_node::Account =
        bincode::deserialize(&row.new_data).expect("decode Account");
    assert_eq!(decoded.balance, 12_345);
}

#[tokio::test]
async fn list_account_history_filters_scanner_and_recovery_in_sql() {
    // Scanner / recovery rows must be filtered in SQL — pushing the
    // filter into the query is what keeps `total` and the page length
    // honest (a post-fetch filter on the page would drop rows AFTER the
    // LIMIT and break pagination math). Issue #153 round-2 review fix.
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let address = [0xeeu8; 32];
    plant_history_row(&pool, &address[..], "scanner", 50, 50).await;
    plant_history_row(&pool, &address[..], "mint", 100, 40).await;
    plant_history_row(&pool, &address[..], "recovery", 110, 30).await;
    plant_history_row(&pool, &address[..], "send", 90, 20).await;
    plant_history_row(&pool, &address[..], "receive", 200, 10).await;

    let (rows, total) = list_account_history(&pool, &address[..], 50, 0)
        .await
        .unwrap();
    assert_eq!(
        total, 3,
        "total = filtered count (mint + send + receive), excludes scanner/recovery"
    );
    assert_eq!(rows.len(), 3);
    let sources: Vec<&str> = rows.iter().map(|r| r.source.as_str()).collect();
    // Newest-first ordering preserved within the filter.
    assert_eq!(sources, vec!["receive", "send", "mint"]);
    assert!(
        sources
            .iter()
            .all(|s| matches!(*s, "mint" | "send" | "receive")),
        "no scanner / recovery rows leak past the SQL filter"
    );
}

// ---- get_account_history_item (tx-detail endpoint) -------------------------

#[tokio::test]
async fn get_account_history_item_fetches_scoped_row_with_inscription_join() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let address = [0x1au8; 32];
    let commit_txid = [0x77u8; 32];

    // Plant an account_history row that carries a commit_txid, plus the
    // matching pending_inscriptions row (commit_output_value = 12_345 via
    // `seed_pending_row`) so the detail-only join column lights up.
    let mut a = crate::account_node::Account::new();
    a.balance = 9_000;
    let new_data = bincode::serialize(&a).expect("serialize account");
    let (id,): (i64,) = sqlx::query_as(
        "INSERT INTO account_history \
         (address, prev_data, new_data, source, triggering_commit_txid) \
         VALUES ($1, NULL, $2, 'mint', $3) RETURNING id",
    )
    .bind(&address[..])
    .bind(&new_data)
    .bind(&commit_txid[..])
    .fetch_one(&pool)
    .await
    .expect("insert history row");
    seed_pending_row(&pool, &commit_txid, PENDING_STATUS_REVEAL_BROADCAST).await;

    let row = get_account_history_item(&pool, &address[..], id)
        .await
        .expect("query ok")
        .expect("row found");
    assert_eq!(row.id, id);
    assert_eq!(row.source, "mint");
    assert_eq!(row.commit_txid.as_deref(), Some(&commit_txid[..]));
    assert_eq!(
        row.commit_output_value,
        Some(12_345),
        "detail query surfaces pending_inscriptions.commit_output_value"
    );
    assert_eq!(row.pending_status.as_deref(), Some("reveal_broadcast"));
    let decoded: crate::account_node::Account =
        bincode::deserialize(&row.new_data).expect("decode Account");
    assert_eq!(decoded.balance, 9_000);
}

#[tokio::test]
async fn get_account_history_item_scopes_by_address_and_filters_internal() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    let address = [0x2bu8; 32];
    let other = [0x3cu8; 32];

    plant_history_row(&pool, &address[..], "mint", 100, 10).await;
    plant_history_row(&pool, &address[..], "scanner", 110, 5).await;
    let (rows, _) = list_account_history(&pool, &address[..], 10, 0)
        .await
        .unwrap();
    let mint_id = rows[0].id;

    // Fetch with the right address — found.
    assert!(get_account_history_item(&pool, &address[..], mint_id)
        .await
        .unwrap()
        .is_some());
    // Same id, different address — scoped out (IDOR guard).
    assert!(get_account_history_item(&pool, &other[..], mint_id)
        .await
        .unwrap()
        .is_none());
    // Unknown id — None.
    assert!(
        get_account_history_item(&pool, &address[..], mint_id + 9_999)
            .await
            .unwrap()
            .is_none()
    );

    // The scanner row exists in the table but is internal — fetch its id
    // directly and assert the item query refuses to surface it.
    let (scanner_id,): (i64,) =
        sqlx::query_as("SELECT id FROM account_history WHERE address = $1 AND source = 'scanner'")
            .bind(&address[..])
            .fetch_one(&pool)
            .await
            .expect("scanner row id");
    assert!(get_account_history_item(&pool, &address[..], scanner_id)
        .await
        .unwrap()
        .is_none());
}

// ---- Per-asset creator binding (off-circuit) ----------------------------

#[tokio::test]
async fn asset_creator_register_then_query_is_idempotent() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let asset_id = vec![0x11u8; 32];
    let creator = vec![0x02u8; 33];

    // Unregistered asset: no conflict (a fresh mint is allowed).
    assert!(!asset_creator_conflict(&pool, &asset_id, &creator)
        .await
        .unwrap());

    // Register, then a matching creator is still not a conflict.
    register_asset_creator(&pool, &asset_id, &creator)
        .await
        .unwrap();
    assert!(!asset_creator_conflict(&pool, &asset_id, &creator)
        .await
        .unwrap());

    // Registration is idempotent on conflict: a second insert with a
    // DIFFERENT creator is a no-op (ON CONFLICT DO NOTHING), so the
    // original creator still owns the asset.
    let other = vec![0x03u8; 33];
    register_asset_creator(&pool, &asset_id, &other)
        .await
        .unwrap();
    assert!(!asset_creator_conflict(&pool, &asset_id, &creator)
        .await
        .unwrap());
}

#[tokio::test]
async fn asset_creator_conflict_true_for_different_creator() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_legacy_stack(&pool).await;
    let asset_id = vec![0x22u8; 32];
    let creator = vec![0x02u8; 33];
    let other = vec![0x03u8; 33];

    register_asset_creator(&pool, &asset_id, &creator)
        .await
        .unwrap();
    // A different creator for the same asset_id is a conflict.
    assert!(asset_creator_conflict(&pool, &asset_id, &other)
        .await
        .unwrap());
    // A different asset_id is independent — no conflict.
    let fresh_asset = vec![0x33u8; 32];
    assert!(!asset_creator_conflict(&pool, &fresh_asset, &other)
        .await
        .unwrap());
}
