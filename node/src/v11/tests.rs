//! Stage-1 v1.1 shadow persistence + flag tests.
//!
//! The restart-identity test builds a non-trivial NfLog + CoinHist state,
//! persists it, reloads into a fresh engine, and asserts byte-identical
//! NfLog root and per-account CoinHist roots.

use shared::spec_v1::{
    self as host, network_params::NetworkParams, AccountState, Address, ChainPosition, Coin,
    CoinHistTree, HashDigest, NfLogEntry, ZERO_HASH,
};
use std::collections::{BTreeMap, BTreeSet};
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::state_engine::{AccountRecord, StateEngine, TrackedCoin};

use super::db_v11::{self, EngineSnapshot};
use super::mode::{
    network_tag_for, resolve_v11_shadow_mode, validate_v11_boot_pins, V11ShadowMode,
};
use super::EngineAdapter;
use crate::test_db::setup_pool;

fn pk(byte: u8) -> [u8; 32] {
    let mut p = [0u8; 32];
    p[0] = byte;
    p
}

fn r_val(byte: u8) -> [u8; 32] {
    let mut v = [0u8; 32];
    v[31] = byte;
    v
}

fn pos(height: u64, tx_index: u32) -> ChainPosition {
    ChainPosition {
        height,
        tx_index,
        vin_index: 0,
        member_index: 0,
    }
}

fn coin_id(byte: u8) -> [u8; 32] {
    let mut id = [0u8; 32];
    id[0] = 0xC0;
    id[1] = byte;
    id
}

fn digest_from_key(key: [u8; 32]) -> HashDigest {
    host::digest_from_bytes(&key).expect("32-byte key is a valid digest encoding")
}

/// Build a StateEngine with two folded nullifiers and one multi-asset
/// account whose CoinHist has one admitted + one spent leaf.
fn seeded_engine() -> StateEngine {
    let activation_height = 10;
    let mut engine = StateEngine::new(Network::Regtest, activation_height);
    engine.set_tip_height(100);
    // set_tip_height zeroes fold_seq; restore a non-zero cursor so the
    // round-trip exercises fold_seq persistence too.
    // (from_persisted sets fold_seq directly.)
    // We re-set via from_persisted path after appends by reconstructing...
    // Actually append_nullifier does not touch fold_seq. Set it by building
    // via from_persisted at the end? Simpler: append, then use snapshot
    // mutation. Easiest: use from_persisted with explicit fold_seq.

    let nflog = vec![
        (
            pos(20, 0),
            NfLogEntry {
                pk: pk(1),
                r: r_val(11),
            },
        ),
        (
            pos(21, 3),
            NfLogEntry {
                pk: pk(2),
                r: r_val(22),
            },
        ),
        (
            pos(25, 1),
            NfLogEntry {
                pk: pk(3),
                r: r_val(33),
            },
        ),
    ];

    let owner = Address(pk(0xA1));
    let admitted = coin_id(1);
    let spent = coin_id(2);
    let mut hist = CoinHistTree::new();
    hist.admit(admitted).expect("admit");
    hist.admit(spent).expect("admit spent leaf");
    hist.spend(spent).expect("spend");
    let ch_root = hist.root();

    let mut balances = BTreeMap::new();
    let asset_key = coin_id(0xAA);
    balances.insert(asset_key, 42u128);

    let state =
        AccountState::new(owner, ZERO_HASH, balances, pk(0xB1), 7, ch_root).expect("AccountState");

    let mut spendable = BTreeMap::new();
    spendable.insert(
        admitted,
        TrackedCoin {
            coin: Coin {
                identifier: digest_from_key(admitted),
                recipient: owner,
                amount: 42,
                asset_id: digest_from_key(asset_key),
            },
            creating_prev_ash: ZERO_HASH,
            coin_index: 0,
        },
    );
    let mut spent_ids = BTreeSet::new();
    spent_ids.insert(spent);

    let record = AccountRecord {
        state,
        coinhist: hist,
        nk: pk(0xD1),
        genesis_pubkey: pk(0xB0),
        spendable,
        spent_ids,
        last_proof: None,
        last_nav_opening: None,
        last_nullifier: None,
        last_nullifier_pos: None,
    };

    StateEngine::from_persisted(
        Network::Regtest,
        activation_height,
        100,
        5, // non-zero fold_seq
        nflog,
        vec![(owner, record)],
    )
    .expect("seeded engine")
}

#[test]
fn flag_defaults_to_off_when_unset() {
    // Normative default: the pure resolver maps "env unset" → Off.
    // (Process-env is not mutated here so parallel tests cannot race.)
    assert_eq!(
        resolve_v11_shadow_mode(None).expect("unset"),
        V11ShadowMode::Off
    );
    assert_eq!(
        resolve_v11_shadow_mode(Some("")).expect("empty"),
        V11ShadowMode::Off
    );
    assert_eq!(
        resolve_v11_shadow_mode(Some("off")).expect("off"),
        V11ShadowMode::Off
    );
    // Only the exact token "1" enables shadow persistence.
    assert_eq!(
        resolve_v11_shadow_mode(Some("1")).expect("1"),
        V11ShadowMode::On
    );
    // Any other value fails loud — never silently treated as off.
    // Includes the retired ZKCOINS_PROVER=v11 token and case/whitespace variants.
    assert!(resolve_v11_shadow_mode(Some("v11")).is_err());
    assert!(resolve_v11_shadow_mode(Some("ON")).is_err());
    assert!(resolve_v11_shadow_mode(Some("true")).is_err());
    assert!(resolve_v11_shadow_mode(Some("1 ")).is_err());
    assert!(resolve_v11_shadow_mode(Some("legacy")).is_err());
}

/// Defect 2: a parameter set that does not match its published identifier
/// must be rejected at boot — even when activation_height is self-consistent
/// with the (wrong) parameter set.
#[test]
fn boot_rejects_params_that_miss_published_identifier() {
    let tag = network_tag_for(Network::Testnet).expect("tag");
    let published = NetworkParams::new(
        tag.to_string(),
        [1u8; 32],
        [2u8; 32],
        2_500_000,
        6,
        [3u8; 32],
    )
    .expect("published");
    let published_id = published.identifier().expect("id");

    // Self-consistent wrong pin: height 99 matches config field, other fields
    // identical to published — but identifier differs because height differs.
    let wrong =
        NetworkParams::new(tag.to_string(), [1u8; 32], [2u8; 32], 99, 6, [3u8; 32]).expect("wrong");
    assert_ne!(
        wrong.identifier().expect("id"),
        published_id,
        "height change must change the content-addressed identifier"
    );

    let err = validate_v11_boot_pins(Network::Testnet, 99, &wrong, published_id)
        .expect_err("self-consistent unpublished set must fail");
    assert!(
        err.contains("expected_params_identifier") || err.contains("identifier"),
        "must fail on identifier mismatch; got: {err}"
    );
    // Must not pass the identifier check and only fail later on height equality.
    assert!(
        !err.contains("does not match network_params.activation_height"),
        "identifier arm must fire first; got: {err}"
    );
}

#[tokio::test]
async fn restart_identity_nflog_and_coinhist_roots() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    let engine = seeded_engine();
    let before_nav = engine.nflog().nav();
    let before_nflog_root = host::digest_to_bytes(&before_nav.root());
    let before_mth = host::digest_to_bytes(&before_nav.mth);
    let before_size = before_nav.size;
    assert_eq!(before_size, 3, "seeded engine must have three NfLog leaves");

    let mut before_coinhist: Vec<([u8; 32], [u8; 32])> = engine
        .accounts()
        .map(|(owner, rec)| (owner.0, host::digest_to_bytes(&rec.coinhist.root())))
        .collect();
    before_coinhist.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(before_coinhist.len(), 1);
    // Non-empty CoinHist (not the empty root) so the test is not vacuous.
    assert_ne!(
        before_coinhist[0].1,
        host::digest_to_bytes(&host::coinhist_empty_root())
    );

    let before_fold_seq = engine.fold_seq();
    let before_tip = engine.tip_height();
    let before_mirror = engine.nflog_mirror();
    let tip_hash = [0xAB; 32];

    let snap = EngineSnapshot::from_engine_with_tip_hash(&engine, tip_hash);
    assert_eq!(snap.tip_hash, tip_hash);
    db_v11::persist_engine_snapshot(&pool, &snap)
        .await
        .expect("persist snapshot");

    // Fresh reconstruction path A: load snapshot → into_engine.
    let loaded = db_v11::load_engine_snapshot(&pool)
        .await
        .expect("load snapshot")
        .expect("meta must exist after persist");
    assert_eq!(loaded.fold_seq, before_fold_seq);
    assert_eq!(loaded.tip_height, before_tip);
    assert_eq!(loaded.tip_hash, tip_hash, "tip_hash must survive restart");
    assert_eq!(loaded.nflog, before_mirror);

    let rebuilt = loaded.into_engine().expect("into_engine");
    let after_nav = rebuilt.nflog().nav();
    assert_eq!(after_nav.size, before_size);
    assert_eq!(host::digest_to_bytes(&after_nav.mth), before_mth);
    assert_eq!(
        host::digest_to_bytes(&after_nav.root()),
        before_nflog_root,
        "NfLog nav root must be byte-identical after restart"
    );

    let mut after_coinhist: Vec<([u8; 32], [u8; 32])> = rebuilt
        .accounts()
        .map(|(owner, rec)| (owner.0, host::digest_to_bytes(&rec.coinhist.root())))
        .collect();
    after_coinhist.sort_by(|a, b| a.0.cmp(&b.0));
    assert_eq!(
        after_coinhist, before_coinhist,
        "per-account CoinHist roots must be byte-identical after restart"
    );

    // Path B: EngineAdapter reload_from_db identity fingerprints.
    let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 10)
        .await
        .expect("adapter load");
    assert_eq!(adapter.tip_hash(), tip_hash);
    let (adapter_nflog, adapter_ch) = adapter.identity_roots();
    assert_eq!(adapter_nflog, before_nflog_root);
    assert_eq!(adapter_ch, before_coinhist);

    // Mutate in memory, persist, reload — identity tracks the new state.
    adapter.with_engine_mut(|eng| {
        eng.append_nullifier(pos(30, 0), pk(9), r_val(99))
            .expect("append fourth nullifier");
    });
    let (mid_nflog, mid_ch) = adapter.identity_roots();
    assert_ne!(mid_nflog, before_nflog_root);
    assert_eq!(mid_ch, before_coinhist); // accounts unchanged
    adapter.persist().await.expect("persist after append");
    adapter.reload_from_db().await.expect("reload");
    let (final_nflog, final_ch) = adapter.identity_roots();
    assert_eq!(final_nflog, mid_nflog);
    assert_eq!(final_ch, mid_ch);
    assert_eq!(adapter.tip_hash(), tip_hash);
}

#[tokio::test]
async fn load_or_create_fresh_db_then_reload_empty_identity() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Testnet, 0)
        .await
        .expect("create empty");
    let (root, accounts) = adapter.identity_roots();
    assert_eq!(
        root,
        host::digest_to_bytes(&host::NfLogAccumulator::new(0).nav().root())
    );
    assert!(accounts.is_empty());
    assert_eq!(adapter.tip_hash(), [0u8; 32]);

    // Second boot against the same DB reconstructs the empty engine.
    let adapter2 = EngineAdapter::load_or_create(pool, Network::Testnet, 0)
        .await
        .expect("second load");
    assert_eq!(adapter2.identity_roots(), (root, accounts));
}

#[tokio::test]
async fn pin_mismatch_fails_loud() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
        .await
        .expect("seed");

    match EngineAdapter::load_or_create(pool.clone(), Network::Testnet, 0).await {
        Ok(_) => panic!("network mismatch must fail"),
        Err(err) => assert!(
            err.to_string().contains("persisted network"),
            "unexpected error: {err}"
        ),
    }

    match EngineAdapter::load_or_create(pool, Network::Regtest, 99).await {
        Ok(_) => panic!("activation mismatch must fail"),
        Err(err) => assert!(
            err.to_string().contains("activation_height"),
            "unexpected error: {err}"
        ),
    }
}

/// Defect 4: a database with v1.1 data rows but no meta row must **fail**,
/// not load as an empty engine.
#[tokio::test]
async fn missing_meta_with_data_rows_fails_loud() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    // Seed a complete snapshot so child tables have rows.
    let engine = seeded_engine();
    let snap = EngineSnapshot::from_engine_with_tip_hash(&engine, [0x11; 32]);
    db_v11::persist_engine_snapshot(&pool, &snap)
        .await
        .expect("persist");

    // Delete only the singleton meta row — data remains.
    let deleted = sqlx::query("DELETE FROM v11_engine_meta WHERE id = 1")
        .execute(&pool)
        .await
        .expect("delete meta");
    assert_eq!(deleted.rows_affected(), 1, "meta row must have existed");

    // Sanity: data rows still present.
    let (nflog_n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM v11_nflog_entries")
        .fetch_one(&pool)
        .await
        .expect("count nflog");
    assert!(nflog_n > 0, "test setup requires leftover nflog rows");

    let err = db_v11::load_engine_snapshot(&pool)
        .await
        .expect_err("meta missing with data must fail, not return empty");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("inconsistent") && msg.contains("missing"),
        "error must name the inconsistency; got: {msg}"
    );
    assert!(
        msg.contains("refusing to load as an empty engine") || msg.contains("no silent fall-back"),
        "must refuse the silent empty-engine fallback; got: {msg}"
    );

    // Adapter path must also refuse (no silent re-init).
    match EngineAdapter::load_or_create(pool, Network::Regtest, 10).await {
        Ok(_) => panic!("adapter must not create empty over inconsistent DB"),
        Err(adapter_err) => {
            let adapter_msg = format!("{adapter_err:#}");
            assert!(
                adapter_msg.contains("inconsistent") || adapter_msg.contains("missing"),
                "adapter error must surface inconsistency; got: {adapter_msg}"
            );
        }
    }
}

/// Tip hash round-trip: equal-height forks are distinguishable after reload.
#[tokio::test]
async fn tip_hash_survives_persist_reload() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
        .await
        .expect("create");
    let fork_a = [0xAA; 32];
    let fork_b = [0xBB; 32];
    assert_ne!(fork_a, fork_b);

    adapter.with_engine_mut(|eng| eng.set_tip_height(42));
    adapter.set_tip_hash(fork_a);
    adapter.persist().await.expect("persist fork A");

    let loaded = db_v11::load_engine_snapshot(&pool)
        .await
        .expect("load")
        .expect("meta");
    assert_eq!(loaded.tip_height, 42);
    assert_eq!(loaded.tip_hash, fork_a);

    // Same height, different hash — the whole point of storing tip_hash.
    adapter.set_tip_hash(fork_b);
    adapter.persist().await.expect("persist fork B");
    adapter.reload_from_db().await.expect("reload");
    assert_eq!(adapter.tip_hash(), fork_b);
    assert_eq!(
        adapter.with_engine(|e| e.tip_height()),
        42,
        "height alone cannot distinguish the fork"
    );
}

// ---------------------------------------------------------------------------
// Stage 2 — hard separation + §3.6 scan-fold
// ---------------------------------------------------------------------------

use super::scan::{fold_survivors_into_engine, members_to_published, sort_canonical};
use super::separation::{
    clear_process_stack_mode_for_test, enforce_stack_scan_mode, ensure_legacy_publisher_allowed,
    ensure_v11_publisher_allowed, ScanStackMode, STACK_SEPARATION_REFUSAL,
};
use shared::spec_v1::{LookupResult, PublishedNullifier};

/// Seed one `mmr_root_index` row — the durable signal of legacy scan activity.
async fn seed_legacy_scan_state(pool: &sqlx::PgPool) {
    sqlx::query(
        "INSERT INTO mmr_root_index (prev_mmr_root, smt_root, leaf_index, created_at) \
         VALUES ($1, $2, 0, NOW())",
    )
    .bind([0x11u8; 32].as_slice())
    .bind([0x22u8; 32].as_slice())
    .execute(pool)
    .await
    .expect("seed mmr_root_index");
}

/// Seed one NfLog entry — the durable signal of v1.1 scan activity.
async fn seed_v11_scan_state(pool: &sqlx::PgPool) {
    // Meta is required for a coherent snapshot, but separation only checks
    // v11_nflog_entries count.
    sqlx::query(
        "INSERT INTO v11_engine_meta \
         (id, network, activation_height, tip_height, tip_hash, fold_seq, updated_at) \
         VALUES (1, 'regtest', 0, 1, $1, 0, NOW())",
    )
    .bind([0u8; 32].as_slice())
    .execute(pool)
    .await
    .expect("seed v11 meta");
    sqlx::query(
        "INSERT INTO v11_nflog_entries \
         (position, height, tx_index, vin_index, member_index, pk, r) \
         VALUES (0, 1, 0, 0, 0, $1, $2)",
    )
    .bind(pk(1).as_slice())
    .bind(r_val(1).as_slice())
    .execute(pool)
    .await
    .expect("seed v11_nflog_entries");
}

/// Hard separation: v1.1 path must fail against a DB with legacy scan state,
/// and the reverse must fail too. Assert the failure (not merely observe it).
#[tokio::test]
async fn hard_separation_refuses_cross_stack_boot() {
    clear_process_stack_mode_for_test();

    // --- legacy data blocks v1.1 ---
    {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        seed_legacy_scan_state(&pool).await;

        let err = enforce_stack_scan_mode(&pool, ScanStackMode::V11)
            .await
            .expect_err("v1.1 must refuse a DB with mmr_root_index rows");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(STACK_SEPARATION_REFUSAL),
            "must use the canonical refusal prefix; got: {msg}"
        );
        assert!(
            msg.contains("legacy") || msg.contains("mmr_root_index"),
            "must name the legacy scan state; got: {msg}"
        );

        // Same DB: legacy path is still allowed and claims the marker.
        enforce_stack_scan_mode(&pool, ScanStackMode::Legacy)
            .await
            .expect("legacy path must accept its own scan state");
        clear_process_stack_mode_for_test();
    }

    // --- v1.1 data blocks legacy ---
    {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        seed_v11_scan_state(&pool).await;

        let err = enforce_stack_scan_mode(&pool, ScanStackMode::Legacy)
            .await
            .expect_err("legacy must refuse a DB with v11_nflog_entries");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(STACK_SEPARATION_REFUSAL),
            "must use the canonical refusal prefix; got: {msg}"
        );
        assert!(
            msg.contains("v11") || msg.contains("NfLog") || msg.contains("nflog"),
            "must name the v1.1 scan state; got: {msg}"
        );

        enforce_stack_scan_mode(&pool, ScanStackMode::V11)
            .await
            .expect("v1.1 path must accept its own scan state");
        clear_process_stack_mode_for_test();
    }

    // --- marker alone blocks the opposite path (empty opposite data) ---
    {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        enforce_stack_scan_mode(&pool, ScanStackMode::Legacy)
            .await
            .expect("fresh DB claims legacy");
        clear_process_stack_mode_for_test();

        let err = enforce_stack_scan_mode(&pool, ScanStackMode::V11)
            .await
            .expect_err("v1.1 must refuse a DB claimed as legacy");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(STACK_SEPARATION_REFUSAL) && msg.contains("claimed as legacy"),
            "marker mismatch must refuse; got: {msg}"
        );
        clear_process_stack_mode_for_test();
    }

    // Publisher guards follow the process claim.
    {
        clear_process_stack_mode_for_test();
        let scope = setup_pool().await;
        enforce_stack_scan_mode(&scope.pool, ScanStackMode::V11)
            .await
            .expect("claim v11");
        let legacy_err = ensure_legacy_publisher_allowed().expect_err("legacy publish under v11");
        assert!(
            legacy_err.to_string().contains(STACK_SEPARATION_REFUSAL),
            "legacy publisher must refuse under v11 claim"
        );
        ensure_v11_publisher_allowed().expect("v11 publisher under v11 claim");
        clear_process_stack_mode_for_test();
    }
}

/// §3.6: multi-member inscription folded in canonical
/// `(height, tx_index, vin_index, member_index)` order; duplicate `Pk`
/// keeps the **first** occurrence's `R`.
#[test]
fn v11_scan_fold_canonical_order_first_occurrence_wins() {
    // Three members in one inscription, deliberately **not** in member
    // order in the input vector — plus a fourth survivor that reuses Pk
    // of member 0 with a different R (must lose).
    let pk_a = pk(0xA0);
    let pk_b = pk(0xB0);
    let pk_c = pk(0xC0);
    let r_a_first = r_val(1);
    let r_a_dup = r_val(99); // loser
    let r_b = r_val(2);
    let r_c = r_val(3);

    // Synthetic multi-member inscription at height 50, tx 3, vin 1:
    // members (A, B, C) then a later tx that republishes A with different R.
    let mut members = members_to_published(
        50,
        3,
        1,
        &[(pk_a, r_a_first), (pk_b, r_b), (pk_c, r_c)],
    )
    .expect("members");
    // Shuffle so the fold path must sort by ChainPosition, not input order.
    members.swap(0, 2); // C, B, A by member_index after swap of ends
    assert_eq!(members[0].pk, pk_c);
    assert_eq!(members[2].pk, pk_a);

    // Second inscription later in the block with duplicate Pk=A.
    let mut later = members_to_published(50, 3, 2, &[(pk_a, r_a_dup)]).expect("later");
    members.append(&mut later);

    // Also include an earlier height with pk_b so overall stream is out of
    // height order until sort_canonical runs.
    let earlier = PublishedNullifier {
        chain_pos: ChainPosition {
            height: 49,
            tx_index: 0,
            vin_index: 0,
            member_index: 0,
        },
        pk: pk(0xE0),
        r: r_val(0xE),
    };
    members.insert(0, earlier);

    // Prove the pure sort key is §3.6.
    let mut sorted = members.clone();
    sort_canonical(&mut sorted);
    let keys: Vec<_> = sorted
        .iter()
        .map(|n| {
            (
                n.chain_pos.height,
                n.chain_pos.tx_index,
                n.chain_pos.vin_index,
                n.chain_pos.member_index,
            )
        })
        .collect();
    assert_eq!(
        keys,
        vec![
            (49, 0, 0, 0),
            (50, 3, 1, 0), // A first occurrence
            (50, 3, 1, 1), // B
            (50, 3, 1, 2), // C
            (50, 3, 2, 0), // A duplicate — later
        ]
    );

    let mut engine = StateEngine::new(Network::Regtest, 0);
    let stats = fold_survivors_into_engine(&mut engine, &members).expect("fold");
    assert_eq!(stats.appended, 4, "E, A, B, C — not the A duplicate");
    assert_eq!(stats.duplicate_ignored, 1, "second A must be ignored");

    // First occurrence of A wins with r_a_first.
    match engine.nflog().lookup(pk_a) {
        LookupResult::Present { pos, r, .. } => {
            assert_eq!(r, r_a_first, "first occurrence R must win");
            assert_eq!(pos, 1, "A is second leaf after earlier E");
        }
        LookupResult::Absent => panic!("pk_a must be present"),
    }
    // Duplicate R must not be the winner.
    assert_ne!(
        match engine.nflog().lookup(pk_a) {
            LookupResult::Present { r, .. } => r,
            LookupResult::Absent => panic!("present"),
        },
        r_a_dup
    );

    // NAV size = four first-occurrence winners.
    assert_eq!(engine.nflog().nav().size, 4);

    // Mirror order matches absolute positions.
    let mirror = engine.nflog_mirror();
    assert_eq!(mirror[0].1.pk, pk(0xE0));
    assert_eq!(mirror[1].1.pk, pk_a);
    assert_eq!(mirror[1].1.r, r_a_first);
    assert_eq!(mirror[2].1.pk, pk_b);
    assert_eq!(mirror[3].1.pk, pk_c);
}

/// Flag-off default: pure resolver stays Off; legacy publisher allowed
/// when process has not claimed v11 (and after an explicit legacy claim).
#[test]
fn flag_off_leaves_legacy_publisher_allowed() {
    clear_process_stack_mode_for_test();
    assert_eq!(
        resolve_v11_shadow_mode(None).expect("unset"),
        V11ShadowMode::Off
    );
    // Unclaimed process: legacy publish still allowed (unit-test / pre-boot).
    ensure_legacy_publisher_allowed().expect("legacy ok when unclaimed");
    // v1.1 publisher requires an exclusive claim — no silent open.
    assert!(ensure_v11_publisher_allowed().is_err());
}
