//! Stage-1 v1.1 shadow persistence + flag tests.
//!
//! The restart-identity test builds a non-trivial NfLog + CoinHist state,
//! persists it, reloads into a fresh engine, and asserts byte-identical
//! NfLog root and per-account CoinHist roots.

use shared::spec_v1::{
    self as host, network_params::NetworkParams, AccountState, Address, ChainPosition, Coin,
    CoinHistTree, HashDigest, NfLogEntry, PublishedNullifier, ZERO_HASH,
};
use std::collections::{BTreeMap, BTreeSet};
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::state_engine::{
    AccountRecord, MintRequest, OpSecret, ScannedNullifier, StateEngine, TrackedCoin,
};

use super::db_v1::{self, EngineSnapshot};
use super::mode::{network_tag_for, resolve_v1_shadow_mode, validate_v1_boot_pins, V1ShadowMode};
use super::separation::{
    claim_stack_scan_mode, enforce_stack_scan_mode, load_stack_scan_mode, set_process_stack_mode,
    ScanStackMode, STACK_CAPABILITY_REFUSAL, STACK_SEPARATION_REFUSAL,
};
use super::EngineAdapter;
use crate::test_db::setup_pool;

/// Claim the v1.1 stack marker on a fresh pool (DB row only; no process
/// mode side-effect unless the caller also calls `set_process_stack_mode`).
async fn claim_v1_marker(pool: &sqlx::PgPool) {
    claim_stack_scan_mode(pool, ScanStackMode::V1)
        .await
        .expect("claim v1 marker");
}

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

fn scanned(height: u64, tx_index: u32, pk: [u8; 32], r: [u8; 32]) -> ScannedNullifier {
    ScannedNullifier::from_survivor(&PublishedNullifier {
        chain_pos: pos(height, tx_index),
        pk,
        r,
    })
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
        op_secret: Some(zkcoins_prover::state_engine::OpSecret::new(pk(0xD2))),
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
        resolve_v1_shadow_mode(None).expect("unset"),
        V1ShadowMode::Off
    );
    assert_eq!(
        resolve_v1_shadow_mode(Some("")).expect("empty"),
        V1ShadowMode::Off
    );
    assert_eq!(
        resolve_v1_shadow_mode(Some("off")).expect("off"),
        V1ShadowMode::Off
    );
    // Only the exact token "1" enables shadow persistence.
    assert_eq!(
        resolve_v1_shadow_mode(Some("1")).expect("1"),
        V1ShadowMode::On
    );
    // Any other value fails loud — never silently treated as off.
    // Includes the retired ZKCOINS_PROVER=v1 token and case/whitespace variants.
    assert!(resolve_v1_shadow_mode(Some("v1")).is_err());
    assert!(resolve_v1_shadow_mode(Some("ON")).is_err());
    assert!(resolve_v1_shadow_mode(Some("true")).is_err());
    assert!(resolve_v1_shadow_mode(Some("1 ")).is_err());
    assert!(resolve_v1_shadow_mode(Some("legacy")).is_err());
}

/// Requirement 10: persist the operational bundle, drop local state, restore
/// via [`db_v1::load_engine_snapshot`], reconstruct the engine, and reproduce
/// a **prior** `nav_rand` opening from the restored `op_secret`.
///
/// Red if `load_engine_snapshot` dropped `op_secret` (e.g. restored as `None`):
/// the cold engine would then have no secret to re-derive the opening with.
#[tokio::test]
async fn fresh_node_with_restored_bundle_reproduces_prior_nav_rand_opening() {
    use sha2::{Digest, Sha256};
    use zkcoins_prover::prover_bridge::test_signing::{deterministic_secret, normalized_key};

    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_v1_marker(&pool).await;

    let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/req10/restore/nk").into();
    let (_, _, current_pubkey) =
        normalized_key(deterministic_secret(b"zkCoins/v1/req10/restore/pk0"));
    let (_, _, next_pubkey) = normalized_key(deterministic_secret(b"zkCoins/v1/req10/restore/pk1"));
    let op_secret = OpSecret::new(Sha256::digest(b"zkCoins/v1/req10/restore/op_secret").into());
    let owner = Address(host::address(&current_pubkey, host::nk_commit(&nk)));

    // --- Live node issues an opening (genesis mint, entry send_counter = 0) ---
    let engine = StateEngine::new(Network::Testnet, 0);
    let mint_name_hash = host::name_hash(b"Req10 Restore Asset").expect("name_hash");
    let mint_asset_id =
        host::asset_id_v1(host::GENESIS_TAG, &current_pubkey, &mint_name_hash, 2, 1);
    let mint_req = MintRequest {
        owner,
        nk,
        op_secret,
        current_pubkey,
        next_pubkey,
        name: b"Req10 Restore Asset".to_vec(),
        decimals: 2,
        amount: 100,
        issuance_version: 1,
        cap_total: 0,
        terms_salt: [0u8; 32],
        output_templates: vec![host::CoinTemplate {
            recipient: owner,
            amount: 100,
            asset_id: mint_asset_id,
        }],
        npk_rand: [0x22; 32],
    };
    let pending = engine.begin_mint(mint_req).expect("begin_mint");
    let issued_nav_rand = pending.nav_opening.nav_rand;
    let entry_counter = pending.witness_wip.prev_account_state.send_counter;
    assert_eq!(entry_counter, 0, "genesis mint must open at send_counter 0");

    // Persist the operational bundle the way apply would leave it on the
    // account row: op_secret stored, send_counter advanced past the opening.
    let mut balances = BTreeMap::new();
    let minted = pending
        .witness_wip
        .output_coins
        .first()
        .expect("mint produces one output");
    balances.insert(host::digest_to_bytes(&minted.asset_id), minted.amount);
    let mut coinhist = CoinHistTree::new();
    let coin_id = host::digest_to_bytes(&minted.identifier);
    coinhist.admit(coin_id).expect("admit minted coin");
    let post_state = AccountState::new(
        owner,
        host::nk_commit(&nk),
        balances,
        next_pubkey,
        entry_counter + 1,
        coinhist.root(),
    )
    .expect("post-mint AccountState");
    let mut spendable = BTreeMap::new();
    spendable.insert(
        coin_id,
        TrackedCoin {
            coin: minted.clone(),
            creating_prev_ash: host::account_state_hash(&pending.witness_wip.prev_account_state)
                .expect("prev ash"),
            coin_index: 0,
        },
    );
    let mut live = StateEngine::new(Network::Testnet, 0);
    live.insert_account(
        owner,
        AccountRecord {
            state: post_state,
            coinhist,
            nk,
            op_secret: Some(op_secret),
            genesis_pubkey: current_pubkey,
            spendable,
            spent_ids: BTreeSet::new(),
            last_proof: None,
            last_nav_opening: Some(pending.nav_opening),
            last_nullifier: None,
            last_nullifier_pos: None,
        },
    )
    .expect("insert account with operational bundle");

    let snap = EngineSnapshot::from_engine_with_tip_hash(&live, [0x10; 32], Vec::new());
    db_v1::persist_engine_snapshot(&pool, &snap)
        .await
        .expect("persist engine snapshot with op_secret");

    // --- Drop every local handle that still knows the secret / opening ---
    drop(pending);
    drop(live);
    drop(snap);
    drop(engine);

    // --- Fresh node: load snapshot, reconstruct engine, reproduce opening ---
    let loaded = db_v1::load_engine_snapshot(&pool)
        .await
        .expect("load_engine_snapshot")
        .expect("snapshot must exist after persist");
    let restored_engine = loaded.into_engine().expect("into_engine");
    let restored_secret = restored_engine
        .account(&owner)
        .expect("account survived restore")
        .op_secret
        .expect("op_secret must survive load_engine_snapshot");

    let rebuilt = restored_secret.derive_nav_rand(entry_counter);
    assert_eq!(
        rebuilt, issued_nav_rand,
        "restored op_secret + prior send_counter must reproduce the opening's nav_rand"
    );
    assert_ne!(
        restored_secret.derive_nav_rand(entry_counter + 1),
        issued_nav_rand,
        "a later send_counter must not reproduce the prior opening"
    );
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

    let err = validate_v1_boot_pins(Network::Testnet, 99, &wrong, published_id)
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
    claim_v1_marker(&pool).await;

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
    before_coinhist.sort_by_key(|a| a.0);
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

    let snap = EngineSnapshot::from_engine_with_tip_hash(&engine, tip_hash, Vec::new());
    assert_eq!(snap.tip_hash, tip_hash);
    db_v1::persist_engine_snapshot(&pool, &snap)
        .await
        .expect("persist snapshot");

    // Fresh reconstruction path A: load snapshot → into_engine.
    let loaded = db_v1::load_engine_snapshot(&pool)
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
    after_coinhist.sort_by_key(|a| a.0);
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
    // with_engine_mut requires a v1.1 process claim.
    set_process_stack_mode(ScanStackMode::V1);
    adapter
        .with_engine_mut(|eng| {
            eng.append_nullifier(scanned(30, 0, pk(9), r_val(99)))
                .expect("append fourth nullifier");
        })
        .expect("with_engine_mut under v1 claim");
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
    claim_v1_marker(&pool).await;

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
    claim_v1_marker(&pool).await;

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
    claim_v1_marker(&pool).await;

    // Seed a complete snapshot so child tables have rows.
    let engine = seeded_engine();
    let snap = EngineSnapshot::from_engine_with_tip_hash(&engine, [0x11; 32], Vec::new());
    db_v1::persist_engine_snapshot(&pool, &snap)
        .await
        .expect("persist");

    // Delete only the singleton meta row — data remains.
    let deleted = sqlx::query(
        "DELETE FROM v1_engine_meta \
         WHERE id = 1 \
           AND state_epoch = (SELECT epoch FROM derived_state_epoch_meta WHERE id = 1)",
    )
    .execute(&pool)
    .await
    .expect("delete meta");
    assert_eq!(deleted.rows_affected(), 1, "meta row must have existed");

    // Sanity: data rows still present.
    let (nflog_n,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM v1_nflog_entries \
         WHERE state_epoch = (SELECT epoch FROM derived_state_epoch_meta WHERE id = 1)",
    )
    .fetch_one(&pool)
    .await
    .expect("count nflog");
    assert!(nflog_n > 0, "test setup requires leftover nflog rows");

    let err = db_v1::load_engine_snapshot(&pool)
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
    claim_v1_marker(&pool).await;

    let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
        .await
        .expect("create");
    let fork_a = [0xAA; 32];
    let fork_b = [0xBB; 32];
    assert_ne!(fork_a, fork_b);

    set_process_stack_mode(ScanStackMode::V1);
    adapter
        .with_engine_mut(|eng| eng.set_tip_height(42))
        .expect("with_engine_mut under v1 claim");
    adapter
        .set_tip_hash(fork_a)
        .expect("set_tip_hash under v1 claim");
    adapter.persist().await.expect("persist fork A");

    let loaded = db_v1::load_engine_snapshot(&pool)
        .await
        .expect("load")
        .expect("meta");
    assert_eq!(loaded.tip_height, 42);
    assert_eq!(loaded.tip_hash, fork_a);

    // Same height, different hash — the whole point of storing tip_hash.
    adapter
        .set_tip_hash(fork_b)
        .expect("set_tip_hash under v1 claim");
    adapter.persist().await.expect("persist fork B");
    adapter.reload_from_db().await.expect("reload");
    assert_eq!(adapter.tip_hash(), fork_b);
    assert_eq!(
        adapter.with_engine(|e| e.tip_height()),
        42,
        "height alone cannot distinguish the fork"
    );
}

/// Data permanence: engine full-replace bumps state_epoch; old rows stay;
/// load returns only the new canonical snapshot.
#[tokio::test]
async fn engine_snapshot_replace_archives_prior_epoch() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_v1_marker(&pool).await;

    // Snapshot A: empty/minimal engine, tip_hash H1.
    let engine_a = StateEngine::new(Network::Regtest, 0);
    let tip_a = [0xA1u8; 32];
    let snap_a = EngineSnapshot::from_engine_with_tip_hash(&engine_a, tip_a, Vec::new());
    db_v1::persist_engine_snapshot(&pool, &snap_a)
        .await
        .expect("persist A");

    let loaded_a = db_v1::load_engine_snapshot(&pool)
        .await
        .expect("load")
        .expect("meta A");
    assert_eq!(loaded_a.tip_hash, tip_a);

    // Snapshot B: different tip_hash (empty nflog ok if tip differs).
    let engine_b = StateEngine::new(Network::Regtest, 0);
    let tip_b = [0xB2u8; 32];
    assert_ne!(tip_a, tip_b);
    let snap_b = EngineSnapshot::from_engine_with_tip_hash(&engine_b, tip_b, Vec::new());
    db_v1::persist_engine_snapshot(&pool, &snap_b)
        .await
        .expect("persist B");

    let loaded_b = db_v1::load_engine_snapshot(&pool)
        .await
        .expect("load")
        .expect("meta B");
    assert_eq!(
        loaded_b.tip_hash, tip_b,
        "load returns only the new canonical snapshot"
    );

    // Physical: ≥ 2 meta rows across epochs.
    let (phys,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM v1_engine_meta")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert!(phys >= 2, "prior epoch rows must remain physically stored");

    // Canonical: exactly 1 meta row on current epoch.
    let (canon,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*) FROM v1_engine_meta \
         WHERE state_epoch = (SELECT epoch FROM derived_state_epoch_meta WHERE id = 1)",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(canon, 1, "exactly one canonical v1_engine_meta row");
}

// ---------------------------------------------------------------------------
// Stage 2 — hard separation + §3.6 scan-fold
// ---------------------------------------------------------------------------

use super::scan::{
    apply_canonical_survivors, ensure_accepted_survivor_coupling, first_boot_requires_full_replace,
    fold_survivors_into_engine, members_to_published, observation_tip_still_live,
    reconcile_persisted_tip, sort_canonical, survivors_from_accepted_inscriptions,
    PersistedTipReconciliation, ResolvedBlock, TipReconcileOutcome, MAX_RECOVERABLE_REORG_DEPTH,
};
use super::separation::{
    claim_process_stack_from_shadow_mode, ensure_legacy_publisher_allowed,
    ensure_v1_publisher_allowed,
};
use shared::spec_v1::LookupResult;

/// Unwrap a ready recon for tests that expect a non-retry classification.
fn expect_ready(outcome: TipReconcileOutcome) -> PersistedTipReconciliation {
    match outcome {
        TipReconcileOutcome::Ready(r) => r,
        TipReconcileOutcome::RetryableIncompleteView { detail, .. } => {
            panic!("expected Ready recon, got RetryableIncompleteView: {detail}")
        }
    }
}

/// Synthetic accepted inscription matching `members_to_published` for coupling tests.
fn scanned_inscription(
    height: u64,
    tx_index: u32,
    vin_index: u32,
    members: Vec<([u8; 32], [u8; 32])>,
) -> zkcoins_prover::scanner::ScannedInscription {
    use zkcoins_prover::half_agg::BlockAnchor;
    zkcoins_prover::scanner::ScannedInscription {
        height,
        tx_index,
        vin_index,
        reveal_txid: {
            let mut t = [0u8; 32];
            t[0] = height as u8;
            t[1] = tx_index as u8;
            t[2] = vin_index as u8;
            t
        },
        format: 0x00,
        members,
        block_anchor: BlockAnchor::default(),
    }
}

/// Test double: a linear "old" chain of block hashes for offline recon.
/// `chain[h]` is the hash at height h; parents link via prev = chain[h-1].
fn mock_chain(len: usize, seed: u8) -> Vec<[u8; 32]> {
    (0..len)
        .map(|h| {
            let mut hash = [0u8; 32];
            hash[0] = seed;
            hash[1] = (h & 0xff) as u8;
            hash[2] = ((h >> 8) & 0xff) as u8;
            hash
        })
        .collect()
}

fn resolve_from_chain(chain: &[[u8; 32]], hash: [u8; 32]) -> anyhow::Result<Option<ResolvedBlock>> {
    match chain.iter().position(|h| *h == hash) {
        None => Ok(None),
        Some(height) => {
            let prev_hash = if height == 0 {
                [0u8; 32]
            } else {
                chain[height - 1]
            };
            Ok(Some(ResolvedBlock {
                height: height as u64,
                prev_hash,
            }))
        }
    }
}

/// Resolve across several chains (e.g. old fork + new tip for reorg tests).
fn resolve_from_chains(
    chains: &[&[[u8; 32]]],
    hash: [u8; 32],
) -> anyhow::Result<Option<ResolvedBlock>> {
    for chain in chains {
        if let Some(b) = resolve_from_chain(chain, hash)? {
            return Ok(Some(b));
        }
    }
    Ok(None)
}

/// Restored/syncing node: only headers up to `max_known_height` exist.
fn resolve_up_to(
    chain: &[[u8; 32]],
    max_known_height: u64,
    hash: [u8; 32],
) -> anyhow::Result<Option<ResolvedBlock>> {
    match chain.iter().position(|h| *h == hash) {
        None => Ok(None),
        Some(height) if (height as u64) > max_known_height => Ok(None),
        Some(height) => {
            let prev_hash = if height == 0 {
                [0u8; 32]
            } else {
                chain[height - 1]
            };
            Ok(Some(ResolvedBlock {
                height: height as u64,
                prev_hash,
            }))
        }
    }
}

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
/// Does **not** set the stack_scan_mode marker (for missing-marker tests).
async fn seed_v1_scan_state_without_marker(pool: &sqlx::PgPool) {
    sqlx::query(
        "INSERT INTO v1_engine_meta \
         (id, network, activation_height, tip_height, tip_hash, fold_seq, updated_at) \
         VALUES (1, 'regtest', 0, 1, $1, 0, NOW())",
    )
    .bind([0u8; 32].as_slice())
    .execute(pool)
    .await
    .expect("seed v1 meta");
    sqlx::query(
        "INSERT INTO v1_nflog_entries \
         (position, height, tx_index, vin_index, member_index, pk, r) \
         VALUES (0, 1, 0, 0, 0, $1, $2)",
    )
    .bind(pk(1).as_slice())
    .bind(r_val(1).as_slice())
    .execute(pool)
    .await
    .expect("seed v1_nflog_entries");
}

/// Hard separation: data without a marker is refused on both sides — no
/// auto-claim from contents. Failures never set the process claim, so both
/// sides can be probed in one process.
#[tokio::test]
async fn hard_separation_refuses_data_without_marker() {
    {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        seed_legacy_scan_state(&pool).await;

        let err_v1 = enforce_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect_err("v1.1 must refuse missing marker + legacy data");
        let msg = format!("{err_v1:#}");
        assert!(
            msg.contains(STACK_SEPARATION_REFUSAL) && msg.contains("marker is missing"),
            "missing marker + data must refuse without claiming; got: {msg}"
        );

        let err_legacy = enforce_stack_scan_mode(&pool, ScanStackMode::Legacy)
            .await
            .expect_err("legacy must also refuse missing marker + data");
        assert!(
            format!("{err_legacy:#}").contains("marker is missing"),
            "same-side data without marker must not auto-claim; got: {err_legacy:#}"
        );
    }

    {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        seed_v1_scan_state_without_marker(&pool).await;

        let err_legacy = enforce_stack_scan_mode(&pool, ScanStackMode::Legacy)
            .await
            .expect_err("legacy must refuse missing marker + v1 data");
        assert!(
            format!("{err_legacy:#}").contains(STACK_SEPARATION_REFUSAL),
            "got: {err_legacy:#}"
        );

        let err_v1 = enforce_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect_err("v1.1 must refuse missing marker even with same-side data");
        assert!(
            format!("{err_v1:#}").contains("marker is missing"),
            "no claim-from-data; got: {err_v1:#}"
        );
    }
}

/// Hard separation under a Legacy process claim (monotonic; nextest isolates
/// from V1-claim cases). Same-side data accepted; opposite path refused.
#[tokio::test]
async fn hard_separation_legacy_claim_accepts_own_refuses_v1() {
    // Claimed + same-side data: accepted; opposite refuses at the DB gate
    // (never reaches set_process_stack_mode for V1).
    {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        enforce_stack_scan_mode(&pool, ScanStackMode::Legacy)
            .await
            .expect("fresh DB claims legacy");
        seed_legacy_scan_state(&pool).await;
        enforce_stack_scan_mode(&pool, ScanStackMode::Legacy)
            .await
            .expect("legacy re-boot with own marker + data");

        let err = enforce_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect_err("v1.1 must refuse legacy claim + data");
        assert!(
            format!("{err:#}").contains(STACK_SEPARATION_REFUSAL),
            "got: {err:#}"
        );
    }

    // Marker alone blocks the opposite path (empty opposite data).
    {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        // Re-affirm Legacy (already claimed above) on a fresh DB marker.
        enforce_stack_scan_mode(&pool, ScanStackMode::Legacy)
            .await
            .expect("fresh DB claims legacy");

        let err = enforce_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect_err("v1.1 must refuse a DB claimed as legacy");
        let msg = format!("{err:#}");
        assert!(
            msg.contains(STACK_SEPARATION_REFUSAL) && msg.contains("claimed as legacy"),
            "marker mismatch must refuse; got: {msg}"
        );
    }
}

/// Hard separation under a V1 process claim (split from the Legacy case:
/// process claim is monotonic and un-clearable outside stack-policy).
#[tokio::test]
async fn hard_separation_v1_claim_accepts_own_refuses_legacy() {
    {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        enforce_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect("fresh DB claims v1");
        // Persist a real snapshot under the claim (transactional writer).
        let engine = StateEngine::new(Network::Regtest, 0);
        let snap = EngineSnapshot::from_engine_with_tip_hash(&engine, [0u8; 32], Vec::new());
        db_v1::persist_engine_snapshot(&pool, &snap)
            .await
            .expect("persist under v1 claim");
        enforce_stack_scan_mode(&pool, ScanStackMode::V1)
            .await
            .expect("v1.1 re-boot with own marker + data");

        let err = enforce_stack_scan_mode(&pool, ScanStackMode::Legacy)
            .await
            .expect_err("legacy must refuse v1 claim + data");
        assert!(
            format!("{err:#}").contains(STACK_SEPARATION_REFUSAL),
            "got: {err:#}"
        );
    }

    // Publisher guards follow the process claim.
    {
        let scope = setup_pool().await;
        enforce_stack_scan_mode(&scope.pool, ScanStackMode::V1)
            .await
            .expect("claim v1");
        let legacy_err = ensure_legacy_publisher_allowed().expect_err("legacy publish under v1");
        assert!(
            legacy_err.to_string().contains(STACK_SEPARATION_REFUSAL),
            "legacy publisher must refuse under v1 claim"
        );
        ensure_v1_publisher_allowed().expect("v1 publisher under v1 claim");
    }
}

/// Defect 1: a write to a v1.1 table under a mismatching (or missing)
/// marker fails **inside** the transaction — nothing is committed.
#[tokio::test]
async fn v1_persist_refuses_under_mismatching_marker_in_transaction() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    // Claim legacy first so any v1 write is a capability mismatch.
    enforce_stack_scan_mode(&pool, ScanStackMode::Legacy)
        .await
        .expect("claim legacy");

    let engine = StateEngine::new(Network::Regtest, 0);
    let snap = EngineSnapshot::from_engine_with_tip_hash(&engine, [0x42; 32], Vec::new());
    let err = db_v1::persist_engine_snapshot(&pool, &snap)
        .await
        .expect_err("v1 persist under legacy marker must fail");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(STACK_CAPABILITY_REFUSAL) || msg.contains("stack_scan_mode"),
        "must refuse on capability check; got: {msg}"
    );

    // Transaction rolled back: no v1 meta row committed.
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM v1_engine_meta")
        .fetch_one(&pool)
        .await
        .expect("count meta");
    assert_eq!(n, 0, "failed persist must leave v1 tables empty");

    // Missing marker is also refusal (no silent claim-from-write).
    let scope2 = setup_pool().await;
    let pool2 = scope2.pool.clone();
    let err2 = db_v1::persist_engine_snapshot(&pool2, &snap)
        .await
        .expect_err("v1 persist without marker must fail");
    assert!(
        format!("{err2:#}").contains("marker is missing")
            || format!("{err2:#}").contains(STACK_CAPABILITY_REFUSAL),
        "got: {err2:#}"
    );
}

/// Defect 2: `resume_pending_inscriptions` refuses under a v1.1 process claim.
#[tokio::test]
async fn resume_pending_inscriptions_refuses_under_v1_claim() {
    let scope = setup_pool().await;
    enforce_stack_scan_mode(&scope.pool, ScanStackMode::V1)
        .await
        .expect("claim v1");

    let config = crate::publisher::EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "regtest".to_string(),
        ws_url: None,
    };
    let err = crate::publisher::resume_pending_inscriptions(&scope.pool, &config)
        .await
        .expect_err("resume must refuse under v1 claim");
    let msg = err.to_string();
    assert!(
        msg.contains(STACK_SEPARATION_REFUSAL) || msg.contains("v1.1"),
        "must name stack separation; got: {msg}"
    );
}

/// Offline reorg of depth ≤ 5: restart rebuilds NfLog to match an
/// **independent** continuous-node oracle (sequential fold, never the
/// restart/replace path under test).
#[tokio::test]
async fn restart_across_reorg_rebuilds_nflog_to_continuous_node() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    enforce_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");

    // Shared prefix heights 0..=10; height 11 diverges (depth-1 shallow reorg).
    let mut old_chain = mock_chain(12, 0xAA);
    let mut new_chain = mock_chain(12, 0xBB);
    for h in 0..=10 {
        let shared = {
            let mut hash = [0u8; 32];
            hash[0] = 0x11;
            hash[1] = h as u8;
            hash
        };
        old_chain[h] = shared;
        new_chain[h] = shared;
    }
    old_chain[11] = {
        let mut h = [0u8; 32];
        h[0] = 0xAA;
        h[1] = 11;
        h
    };
    new_chain[11] = {
        let mut h = [0u8; 32];
        h[0] = 0xBB;
        h[1] = 11;
        h
    };
    let old_tip_hash = old_chain[11];
    let new_tip_hash = new_chain[11];
    assert_ne!(old_tip_hash, new_tip_hash);

    // --- Persist old-fork state (what a node would hold before crash) ---
    let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
        .await
        .expect("adapter");
    let fork_members = vec![(pk(1), r_val(1)), (pk(2), r_val(2))];
    let orphan_members = vec![(pk(3), r_val(3))];
    let fork_survivors = members_to_published(10, 0, 0, &fork_members).expect("old fork members");
    let mut orphaned = members_to_published(11, 0, 0, &orphan_members).expect("orphan");
    let mut old_stream = fork_survivors.clone();
    old_stream.append(&mut orphaned);
    let old_inscriptions = vec![
        scanned_inscription(10, 0, 0, fork_members.clone()),
        scanned_inscription(11, 0, 0, orphan_members),
    ];

    apply_canonical_survivors(&adapter, 11, old_tip_hash, &old_stream, &old_inscriptions)
        .await
        .expect("persist old fork");
    let (old_root, _) = adapter.identity_roots();
    assert_eq!(adapter.with_engine(|e| e.nflog().nav().size), 3);

    // --- New canonical stream after reorg (pk3 orphaned, pk4 wins at 11) ---
    let replacement_members = vec![(pk(4), r_val(4))];
    let mut new_stream = fork_survivors;
    let mut replacement =
        members_to_published(11, 0, 0, &replacement_members).expect("replacement");
    new_stream.append(&mut replacement);
    let new_inscriptions = vec![
        scanned_inscription(10, 0, 0, fork_members),
        scanned_inscription(11, 0, 0, replacement_members),
    ];

    // Independent continuous-node oracle: sequential first-occurrence fold
    // the way a node that never restarted would accumulate — never calls
    // replace_engine_nflog_from_survivors (the path under test).
    let mut continuous_engine = StateEngine::new(Network::Regtest, 0);
    continuous_engine.set_tip_height(11);
    let cont_stats = fold_survivors_into_engine(&mut continuous_engine, &new_stream)
        .expect("continuous sequential fold");
    assert_eq!(cont_stats.appended, 3);
    let continuous_root = host::digest_to_bytes(&continuous_engine.nflog().nav().root());
    assert_eq!(continuous_engine.nflog().nav().size, 3);
    assert!(matches!(
        continuous_engine.nflog().lookup(pk(3)),
        LookupResult::Absent
    ));
    assert!(matches!(
        continuous_engine.nflog().lookup(pk(4)),
        LookupResult::Present { .. }
    ));
    assert_ne!(
        continuous_root, old_root,
        "reorg must change the NfLog root"
    );

    // --- Restart path: reconciling the persisted tip sees a shallow reorg ---
    // Observation = new (scan) tip; classify against its immutable ancestry.
    let recon = expect_ready(
        reconcile_persisted_tip(11, old_tip_hash, 0, 11, new_tip_hash, 11, |hash| {
            resolve_from_chains(&[&old_chain, &new_chain], hash)
        })
        .expect("shallow recon"),
    );
    match recon {
        PersistedTipReconciliation::ShallowReorg {
            reorg_depth,
            ancestor_height,
            ..
        } => {
            assert_eq!(reorg_depth, 1, "single-block tip reorg");
            assert_eq!(ancestor_height, 10);
        }
        other => panic!("expected ShallowReorg, got {other:?}"),
    }

    // Fresh adapter load (simulates process restart) still holds old tip.
    let restarted = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
        .await
        .expect("restart load");
    assert_eq!(restarted.tip_hash(), old_tip_hash);
    assert_eq!(restarted.identity_roots().0, old_root);

    // Shallow apply — must match the independent sequential oracle.
    apply_canonical_survivors(&restarted, 11, new_tip_hash, &new_stream, &new_inscriptions)
        .await
        .expect("restart full replace");

    let (restarted_root, _) = restarted.identity_roots();
    assert_eq!(
        restarted_root, continuous_root,
        "restarted node must match independent continuous-node NfLog after reorg"
    );
    assert_eq!(restarted.tip_hash(), new_tip_hash);
    restarted.with_engine(|e| {
        assert!(matches!(e.nflog().lookup(pk(3)), LookupResult::Absent));
        assert!(matches!(
            e.nflog().lookup(pk(4)),
            LookupResult::Present { .. }
        ));
    });

    // Still-canonical tip: forward path is selected (no full replace).
    let recon_ok = expect_ready(
        reconcile_persisted_tip(11, new_tip_hash, 0, 11, new_tip_hash, 11, |hash| {
            resolve_from_chain(&new_chain, hash)
        })
        .expect("still canonical"),
    );
    assert!(matches!(
        recon_ok,
        PersistedTipReconciliation::StillCanonical { .. }
    ));
    assert!(!first_boot_requires_full_replace(&recon_ok));

    // Ambiguous tip (height>0, zero hash) refuses.
    let err = reconcile_persisted_tip(5, [0u8; 32], 0, 5, [1u8; 32], 5, |_| Ok(None))
        .expect_err("zero hash with height must refuse");
    assert!(format!("{err:#}").contains("all-zero"), "got: {err:#}");
}

/// Catalog reorg cut: entries above the ancestor are dropped with the NfLog
/// full-replace; entries at/below the ancestor remain.
#[tokio::test]
async fn catalog_reorg_truncates_above_ancestor_with_nflog() {
    use zkcoins_prover::half_agg::BlockAnchor;
    use zkcoins_prover::scanner::ScannedInscription;

    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    enforce_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");

    let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
        .await
        .expect("adapter");

    let below = ScannedInscription {
        height: 10,
        tx_index: 0,
        vin_index: 0,
        reveal_txid: [0x10; 32],
        format: 0x00,
        members: vec![([0x01; 32], [0x11; 32])],
        block_anchor: BlockAnchor {
            block_hash: [0xAA; 32],
            height: 9,
        },
    };
    let above = ScannedInscription {
        height: 11,
        tx_index: 0,
        vin_index: 0,
        reveal_txid: [0x11; 32],
        format: 0x00,
        members: vec![([0x02; 32], [0x22; 32])],
        block_anchor: BlockAnchor {
            block_hash: [0xBB; 32],
            height: 10,
        },
    };
    let mut survivors_old =
        members_to_published(10, 0, 0, &[([0x01; 32], [0x11; 32])]).expect("below");
    survivors_old
        .extend(members_to_published(11, 0, 0, &[([0x02; 32], [0x22; 32])]).expect("above"));

    apply_canonical_survivors(
        &adapter,
        11,
        [0x0D; 32],
        &survivors_old,
        &[below.clone(), above],
    )
    .await
    .expect("seed catalog");
    assert_eq!(adapter.catalog_snapshot().len(), 2);

    // Reorg: keep only height ≤ 10, replace tip.
    let survivors_new =
        members_to_published(10, 0, 0, &[([0x01; 32], [0x11; 32])]).expect("retained");
    apply_canonical_survivors(&adapter, 10, [0x0C; 32], &survivors_new, &[below])
        .await
        .expect("reorg catalog");

    let cat = adapter.catalog_snapshot();
    assert_eq!(cat.len(), 1, "entry above ancestor must be gone");
    assert_eq!(cat[0].height, 10);
    assert_eq!(cat[0].reveal_txid, [0x10; 32]);
    // Durable: reload must match.
    let reloaded = EngineAdapter::load_or_create(pool, Network::Regtest, 0)
        .await
        .expect("reload");
    assert_eq!(reloaded.catalog_snapshot().len(), 1);
    assert_eq!(reloaded.catalog_snapshot()[0].height, 10);
}

/// Atomizität: failed durable write restores pre-mutation catalog (and NfLog).
#[tokio::test]
async fn catalog_restore_after_failed_mutate_keeps_prior_rows() {
    use zkcoins_prover::half_agg::BlockAnchor;
    use zkcoins_prover::scanner::ScannedInscription;

    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    enforce_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");

    let adapter = EngineAdapter::load_or_create(pool, Network::Regtest, 0)
        .await
        .expect("adapter");
    let seed = ScannedInscription {
        height: 5,
        tx_index: 0,
        vin_index: 0,
        reveal_txid: [0x55; 32],
        format: 0x01,
        members: vec![([0x0A; 32], [0x0B; 32])],
        block_anchor: BlockAnchor::default(),
    };
    let survivors =
        members_to_published(5, 0, 0, &[([0x0A; 32], [0x0B; 32])]).expect("seed survivors");
    apply_canonical_survivors(&adapter, 5, [0x05; 32], &survivors, &[seed])
        .await
        .expect("seed");
    assert_eq!(adapter.catalog_snapshot().len(), 1);

    // Snapshot → mutate catalog → restore without persist (simulates failed write).
    let backup = adapter.snapshot_live();
    let ghost = crate::v1::db_v1::CatalogInscription {
        height: 99,
        tx_index: 0,
        vin_index: 0,
        reveal_txid: [0x99; 32],
        format: 0x00,
        members: vec![(0, [0x99; 32], [0x98; 32])],
        block_anchor_hash: [0; 32],
        block_anchor_height: 0,
    };
    adapter.append_catalog(&[ghost]).expect("in-memory append");
    assert_eq!(adapter.catalog_snapshot().len(), 2);
    adapter.restore_live(backup).expect("restore");
    let cat = adapter.catalog_snapshot();
    assert_eq!(
        cat.len(),
        1,
        "restore after failed fold must drop uncommitted catalog rows"
    );
    assert_eq!(cat[0].height, 5);
    assert_eq!(cat[0].reveal_txid, [0x55; 32]);
}

/// Path-2 construction: survivors are exactly the member expansion of
/// accepted inscriptions (order and content).
#[test]
fn survivors_from_accepted_match_member_expansion() {
    let inscriptions = vec![
        scanned_inscription(10, 0, 0, vec![(pk(1), r_val(1)), (pk(2), r_val(2))]),
        scanned_inscription(11, 1, 0, vec![(pk(3), r_val(3))]),
    ];
    let derived = survivors_from_accepted_inscriptions(&inscriptions).expect("expand");
    let expected = {
        let mut v =
            members_to_published(10, 0, 0, &[(pk(1), r_val(1)), (pk(2), r_val(2))]).expect("a");
        v.extend(members_to_published(11, 1, 0, &[(pk(3), r_val(3))]).expect("b"));
        v
    };
    assert_eq!(derived, expected);
    ensure_accepted_survivor_coupling(&derived, &inscriptions).expect("coupled");
}

/// Decoupled streams refuse with both counts in the message.
///
/// Against a build that only *assumed* scanner coupling, this would pass
/// apply with a silent catalog/NfLog skew — today it must fail loud.
#[test]
fn decoupled_survivor_without_inscription_refuses() {
    let survivors = members_to_published(10, 0, 0, &[(pk(1), r_val(1))]).expect("s");
    let err = ensure_accepted_survivor_coupling(&survivors, &[])
        .expect_err("survivors without inscriptions must refuse");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("survivor_count=1") && msg.contains("inscription_member_count=0"),
        "must report both counts; got: {msg}"
    );
}

/// Inscription members with no survivor rows refuse (other drift direction).
#[test]
fn decoupled_inscription_without_survivor_refuses() {
    let inscriptions = vec![scanned_inscription(10, 0, 0, vec![(pk(1), r_val(1))])];
    let err = ensure_accepted_survivor_coupling(&[], &inscriptions)
        .expect_err("inscriptions without survivors must refuse");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("survivor_count=0") && msg.contains("inscription_member_count=1"),
        "must report both counts; got: {msg}"
    );
}

/// Full-replace apply refuses decoupled streams (not only the pure helper).
#[tokio::test]
async fn apply_canonical_refuses_decoupled_streams() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    enforce_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1");
    let adapter = EngineAdapter::load_or_create(pool, Network::Regtest, 0)
        .await
        .expect("adapter");
    let survivors = members_to_published(5, 0, 0, &[(pk(1), r_val(1))]).expect("s");
    // Empty inscriptions while survivors non-empty — pre-coupling this would
    // fold NfLog and replace catalog with [] (silent catalog wipe relative to
    // the survivor feed).
    let err = apply_canonical_survivors(&adapter, 5, [0x05; 32], &survivors, &[])
        .await
        .expect_err("decoupled apply must refuse");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("coupling") || msg.contains("survivor_count"),
        "must name coupling failure; got: {msg}"
    );
    assert_eq!(
        adapter.with_engine(|e| e.nflog().nav().size),
        0,
        "refused apply must not fold"
    );
}

/// Defect 1: offline reorg deeper than the recoverable limit (§3.9 ≥6)
/// refuses — no fold, explicit error (fail-stop, not silent recovery).
#[test]
fn offline_reorg_deeper_than_recoverable_limit_refuses() {
    // Old tip at height 20; live chain diverged from height 14 upward
    // → common ancestor at 14 → depth = 6 > MAX_RECOVERABLE_REORG_DEPTH (5).
    let mut old_chain = mock_chain(21, 0xAA);
    let mut live_chain = mock_chain(21, 0xBB);
    for h in 0..=14 {
        let shared = {
            let mut hash = [0u8; 32];
            hash[0] = 0x11;
            hash[1] = h as u8;
            hash
        };
        old_chain[h] = shared;
        live_chain[h] = shared;
    }
    // Heights 15..=20 diverge.
    for h in 15..=20 {
        old_chain[h] = {
            let mut hash = [0u8; 32];
            hash[0] = 0xAA;
            hash[1] = h as u8;
            hash
        };
        live_chain[h] = {
            let mut hash = [0u8; 32];
            hash[0] = 0xBB;
            hash[1] = h as u8;
            hash
        };
    }
    let old_tip = old_chain[20];
    let live_tip = live_chain[20];
    let err = reconcile_persisted_tip(20, old_tip, 0, 20, live_tip, 20, |hash| {
        resolve_from_chains(&[&old_chain, &live_chain], hash)
    })
    .expect_err("depth-6 offline reorg must refuse");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("exceeds recoverable limit")
            || msg.contains("deep_reorg")
            || msg.contains("≥6")
            || msg.contains("no recovery"),
        "must name §3.9 fail-stop; got: {msg}"
    );
    assert!(
        msg.contains(&MAX_RECOVERABLE_REORG_DEPTH.to_string()) || msg.contains("depth 6"),
        "must mention depth/limit; got: {msg}"
    );
}

/// Unresolvable persisted tip (unknown / pruned hash) refuses — not a
/// silent shallow-reorg assumption — **when** the live node is already at
/// or beyond the persisted height.
#[test]
fn unresolvable_persisted_tip_refuses() {
    let obs = [0xADu8; 32];
    let err = reconcile_persisted_tip(
        10,
        [0xDE; 32],
        0,
        10,
        obs,
        10, // live already at height → unknown is fatal
        |hash| {
            if hash == obs {
                Ok(Some(ResolvedBlock {
                    height: 10,
                    prev_hash: [0u8; 32],
                }))
            } else {
                Ok(None) // persisted hash unknown
            }
        },
    )
    .expect_err("unknown tip hash must refuse when live is at height");
    let msg = format!("{err:#}");
    assert!(
        msg.contains("unknown") || msg.contains("pruned") || msg.contains("unresolvable"),
        "got: {msg}"
    );
}

/// Defect 2: legacy DB with only smt_state / mmr_state / latest_block
/// (no mmr_root_index) cannot be claimed by v1.1.
#[tokio::test]
async fn legacy_smt_mmr_latest_block_without_root_index_blocks_v1_claim() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    // Seed durable legacy state the way persist_state_tx does when the
    // optional root-index argument is None — no mmr_root_index row.
    sqlx::query(
        "INSERT INTO smt_state (id, data, updated_at) VALUES (1, $1, NOW()) \
         ON CONFLICT (state_epoch, id) DO UPDATE SET data = EXCLUDED.data",
    )
    .bind([0x51u8; 16].as_slice())
    .execute(&pool)
    .await
    .expect("seed smt_state");
    sqlx::query(
        "INSERT INTO mmr_state (id, data, updated_at) VALUES (1, $1, NOW()) \
         ON CONFLICT (state_epoch, id) DO UPDATE SET data = EXCLUDED.data",
    )
    .bind([0x52u8; 16].as_slice())
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

    // Sanity: mmr_root_index is still empty (the hole the old guard missed).
    let (root_n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM mmr_root_index")
        .fetch_one(&pool)
        .await
        .expect("count root index");
    assert_eq!(root_n, 0, "test requires no mmr_root_index rows");

    let err = enforce_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect_err("v1.1 must refuse legacy smt/mmr/latest_block without root index");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(STACK_SEPARATION_REFUSAL),
        "must refuse with stack separation; got: {msg}"
    );
    assert!(
        msg.contains("smt_state")
            || msg.contains("mmr_state")
            || msg.contains("latest_block")
            || msg.contains("legacy"),
        "must name legacy durable tables; got: {msg}"
    );

    // Marker must not have been claimed.
    let marker = load_stack_scan_mode(&pool).await.expect("load marker");
    assert!(marker.is_none(), "failed claim must leave marker unset");
}

// Defect 3: both unguarded-looking broadcast entry points refuse under a
// v1.1 process claim (structural guard at the Esplora choke point).

/// Crate-internal `with_engine_mut` refuses without a v1.1 process claim.
/// (The method is sealed from downstream crates; this covers the runtime gate.)
#[tokio::test]
async fn with_engine_mut_refuses_without_v1_claim() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    claim_v1_marker(&pool).await;

    let adapter = EngineAdapter::load_or_create(pool, Network::Regtest, 0)
        .await
        .expect("adapter");
    let err = adapter
        .with_engine_mut(|eng| eng.set_tip_height(1))
        .expect_err("unguarded mut must refuse");
    assert!(
        format!("{err:#}").contains("refusing") || format!("{err:#}").contains("claim"),
        "got: {err:#}"
    );
}

/// Defect 1 (round 4): a legacy write attempted while a v1.1 claim is
/// mid-flight (emptiness observed, marker not yet committed) must not
/// produce a mixed database. Writers require the marker inside their own
/// transaction, so the interleaving cannot land SMT/MMR under a later v1
/// claim.
#[tokio::test]
async fn legacy_write_between_emptiness_check_and_v1_claim_cannot_mix_db() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    // Simulate the claim transaction after emptiness check, before marker
    // insert: an open transaction that has counted both stacks as empty.
    let mut claim_tx = pool.begin().await.expect("begin claim-like tx");
    let (legacy_n,): (i64,) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM mmr_root_index) \
           + (SELECT COUNT(*) FROM smt_state) \
           + (SELECT COUNT(*) FROM mmr_state) \
           + (SELECT COUNT(*) FROM latest_block)",
    )
    .fetch_one(&mut *claim_tx)
    .await
    .expect("count legacy");
    let (v1_n,): (i64,) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM v1_engine_meta) \
           + (SELECT COUNT(*) FROM v1_nflog_entries) \
           + (SELECT COUNT(*) FROM v1_nullifier_index) \
           + (SELECT COUNT(*) FROM v1_accounts) \
           + (SELECT COUNT(*) FROM v1_spendable_coins) \
           + (SELECT COUNT(*) FROM v1_spent_coins)",
    )
    .fetch_one(&mut *claim_tx)
    .await
    .expect("count v1");
    assert_eq!(legacy_n, 0);
    assert_eq!(v1_n, 0);

    // Concurrent legacy writer (separate connection): must refuse — no
    // matching stack_scan_mode marker yet.
    let err = crate::db::persist_state_tx(&pool, b"smt-race", b"mmr-race", &[0xAAu8; 32], None)
        .await
        .expect_err("legacy write without marker must refuse");
    let msg = err.to_string();
    assert!(
        msg.contains(STACK_CAPABILITY_REFUSAL) || msg.contains("marker is missing"),
        "must refuse capability; got: {msg}"
    );

    // Claim completes as v1.
    sqlx::query(
        "INSERT INTO stack_scan_mode (id, mode, claimed_at) VALUES (1, 'v1', NOW()) \
         ON CONFLICT (id) DO NOTHING",
    )
    .execute(&mut *claim_tx)
    .await
    .expect("insert marker");
    claim_tx.commit().await.expect("commit claim");
    set_process_stack_mode(ScanStackMode::V1);

    // Marker is v1; another legacy write still refuses.
    let err2 = crate::db::persist_state_tx(&pool, b"smt-late", b"mmr-late", &[0xBBu8; 32], None)
        .await
        .expect_err("legacy write under v1 marker must refuse");
    assert!(
        err2.to_string().contains(STACK_CAPABILITY_REFUSAL)
            || err2.to_string().contains("claimed as"),
        "got: {err2}"
    );

    // No mixed DB: no legacy scan rows; marker is v1.
    let (legacy_after,): (i64,) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM mmr_root_index) \
           + (SELECT COUNT(*) FROM smt_state) \
           + (SELECT COUNT(*) FROM mmr_state) \
           + (SELECT COUNT(*) FROM latest_block)",
    )
    .fetch_one(&pool)
    .await
    .expect("recount legacy");
    assert_eq!(legacy_after, 0, "legacy write must not have committed");
    let marker = load_stack_scan_mode(&pool).await.expect("load marker");
    assert_eq!(marker, Some(ScanStackMode::V1));
}

/// Defect 2 (round 5): exercise the **recovery binary's** stack-claim path
/// (`claim_process_stack_from_shadow_mode` / `ZKCOINS_V1_SHADOW=1`), not a
/// hand-set `set_process_stack_mode(V1)`. Under that claim,
/// `LegacyBroadcastClient::connect` refuses before any Esplora I/O.
#[test]
fn recover_inscription_binary_path_refuses_under_v1_shadow() {
    // Same pure step the binary runs after reading ZKCOINS_V1_SHADOW=1.
    claim_process_stack_from_shadow_mode(super::mode::V1ShadowMode::On);
    let err = crate::publisher::LegacyBroadcastClient::connect("http://127.0.0.1:1/api")
        .expect_err("recover path must refuse under v1 shadow claim");
    let msg = err.to_string();
    assert!(
        msg.contains(STACK_SEPARATION_REFUSAL) || msg.contains("v1.1"),
        "got: {msg}"
    );
}

/// Defect 1 (round 5 + 6): A→B→A defeats any pin based on mutable
/// `getblockhash(height)`. Recon must classify against the **immutable
/// ancestry of the captured scan-tip hash**, never against live tip samples.
///
/// Sequence that used to pass incorrectly:
/// 1. persisted state belongs to B,
/// 2. first scan captures A,
/// 3. mutable recon observes B → StillCanonical,
/// 4. chain returns to A; pin sees A and passes,
/// 5. stale B fold keys + A survivors → permanent mixed accumulator.
///
/// With observation ancestry of A, step 3 is ShallowReorg (full-replace)
/// regardless of what the live tip is doing during recon.
#[test]
fn aba_race_caught_by_immutable_scan_tip_ancestry() {
    // Shared prefix 0..=9; tips at height 10 diverge (A vs B).
    let mut chain_a = mock_chain(11, 0xAA);
    let mut chain_b = mock_chain(11, 0xBB);
    for h in 0..=9 {
        let shared = {
            let mut hash = [0u8; 32];
            hash[0] = 0x11;
            hash[1] = h as u8;
            hash
        };
        chain_a[h] = shared;
        chain_b[h] = shared;
    }
    let persisted_b = chain_b[10];
    let scan_tip_a = chain_a[10];

    // Boot binds recon to the **scan tip A** ancestry. Persisted B is not
    // on that ancestry → ShallowReorg. Mutable live tip may be B or A
    // mid-recon; classification does not consult it.
    let bound_to_scan_a = expect_ready(
        reconcile_persisted_tip(10, persisted_b, 0, 10, scan_tip_a, 10, |hash| {
            resolve_from_chains(&[&chain_a, &chain_b], hash)
        })
        .expect("recon bound to scan tip A"),
    );
    assert!(
        matches!(
            bound_to_scan_a,
            PersistedTipReconciliation::ShallowReorg { .. }
        ),
        "persisted B vs scan-tip A ancestry must be ShallowReorg; got {bound_to_scan_a:?}"
    );
    assert!(
        first_boot_requires_full_replace(&bound_to_scan_a),
        "first boot must full-replace — never seed B fold keys onto A survivors"
    );

    // Same recon with observation = B would be StillCanonical (dangerous
    // if the scan had actually captured A). Boot never does this: it always
    // passes the scan tip as the observation.
    let free_standing_b = expect_ready(
        reconcile_persisted_tip(10, persisted_b, 0, 10, persisted_b, 10, |hash| {
            resolve_from_chain(&chain_b, hash)
        })
        .expect("recon observation=B"),
    );
    assert!(
        matches!(
            free_standing_b,
            PersistedTipReconciliation::StillCanonical { .. }
        ),
        "observation=B + persisted=B is StillCanonical (why binding to scan tip matters)"
    );

    // Secondary pin still rejects applying when live hash ≠ scan tip.
    assert!(
        !observation_tip_still_live(scan_tip_a, Some(persisted_b)),
        "live at B while scan was A → discard"
    );
    assert!(
        observation_tip_still_live(scan_tip_a, Some(scan_tip_a)),
        "matching pin allows apply"
    );
}

/// Defect 3 (round 5): `claim_stack_scan_mode` refuses when stack data is
/// present without a marker (same invariant as enforce — no auto-claim).
#[tokio::test]
async fn claim_stack_scan_mode_refuses_without_emptiness_invariant() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();

    seed_v1_scan_state_without_marker(&pool).await;

    let err = claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect_err("claim over existing data must refuse");
    let msg = format!("{err:#}");
    assert!(
        msg.contains(STACK_SEPARATION_REFUSAL)
            || msg.contains("already exist")
            || msg.contains("auto-claim")
            || msg.contains("marker is missing"),
        "got: {msg}"
    );
}

/// Defect 3 (round 5): `reset_proof_dependent_state_tx` refuses without a
/// legacy stack marker (capability check).
#[tokio::test]
async fn reset_proof_dependent_state_tx_refuses_without_legacy_marker() {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    // No marker at all.
    let err = crate::db::reset_proof_dependent_state_tx(&pool, b"DIGEST")
        .await
        .expect_err("reset without marker must refuse");
    let msg = err.to_string();
    assert!(
        msg.contains(STACK_CAPABILITY_REFUSAL)
            || msg.contains("stack_scan_mode")
            || msg.contains("marker"),
        "got: {msg}"
    );

    // V1 marker also refuses (legacy-table mutator).
    claim_stack_scan_mode(&pool, ScanStackMode::V1)
        .await
        .expect("claim v1 on empty");
    let err2 = crate::db::reset_proof_dependent_state_tx(&pool, b"DIGEST")
        .await
        .expect_err("reset under v1 marker must refuse");
    let msg2 = err2.to_string();
    assert!(
        msg2.contains(STACK_CAPABILITY_REFUSAL) || msg2.contains("v1") || msg2.contains("legacy"),
        "got: {msg2}"
    );
}

/// Defect 3A (round 4): one-block reorg of the activation block has common
/// ancestor `activation_height − 1` and must **replay** (ShallowReorg), not
/// refuse solely because the ancestor is below activation.
#[test]
fn one_block_reorg_at_activation_boundary_replays() {
    let activation = 100u64;
    // Old tip = activation block; parent is activation − 1 (shared).
    let mut old_chain = mock_chain((activation as usize) + 1, 0xAA);
    let mut live_chain = mock_chain((activation as usize) + 1, 0xBB);
    // Shared prefix through activation − 1.
    for h in 0..activation as usize {
        let shared = {
            let mut hash = [0u8; 32];
            hash[0] = 0x11;
            hash[1] = (h & 0xff) as u8;
            hash[2] = ((h >> 8) & 0xff) as u8;
            hash
        };
        old_chain[h] = shared;
        live_chain[h] = shared;
    }
    // Activation height diverges (one-block reorg of the activation block).
    old_chain[activation as usize] = {
        let mut h = [0u8; 32];
        h[0] = 0xAA;
        h[1] = 0xAC;
        h
    };
    live_chain[activation as usize] = {
        let mut h = [0u8; 32];
        h[0] = 0xBB;
        h[1] = 0xAC;
        h
    };
    let old_tip = old_chain[activation as usize];
    let live_tip = live_chain[activation as usize];
    let recon = expect_ready(
        reconcile_persisted_tip(
            activation,
            old_tip,
            activation,
            activation,
            live_tip,
            activation,
            |hash| resolve_from_chains(&[&old_chain, &live_chain], hash),
        )
        .expect("activation-boundary one-block reorg must replay"),
    );
    match recon {
        PersistedTipReconciliation::ShallowReorg {
            reorg_depth,
            ancestor_height,
            ..
        } => {
            assert_eq!(reorg_depth, 1);
            assert_eq!(ancestor_height, activation - 1);
            assert!(first_boot_requires_full_replace(&recon));
        }
        other => panic!("expected ShallowReorg at activation boundary, got {other:?}"),
    }
}

/// Defect 3 (round 6): a restored bitcoind that is legitimately behind
/// must be **retryable**, not fatal. The resolver itself does not know
/// the later blocks (unlike an older test that only stubbed `live_hash_at`
/// while the resolver still knew height 10).
#[test]
fn restored_node_behind_persisted_height_is_retryable_not_fatal() {
    let chain = mock_chain(11, 0xAA); // tip height 10
    let tip_hash = chain[10];
    let max_known = 8u64;
    // Observation tip is whatever the restored node could scan (height 8).
    let obs_hash = chain[max_known as usize];

    let outcome = reconcile_persisted_tip(
        10,
        tip_hash,
        0,
        max_known,
        obs_hash,
        max_known, // live_node_height behind persisted
        |hash| resolve_up_to(&chain, max_known, hash),
    )
    .expect("behind restored node must not be a fatal Err");
    match outcome {
        TipReconcileOutcome::RetryableIncompleteView {
            queried_height,
            detail,
        } => {
            assert_eq!(queried_height, 10);
            assert!(
                detail.contains("behind")
                    || detail.contains("incomplete")
                    || detail.contains("retry"),
                "must name incomplete/behind view; got: {detail}"
            );
        }
        TipReconcileOutcome::Ready(r) => {
            panic!("behind restored node must not classify as Ready({r:?})")
        }
    }

    // Even if a buggy caller claimed live_node_height >= tip while the
    // resolver still lacked the headers, unknown would be fatal — the
    // height gate is what makes restored nodes safe. Catch-up works:
    let caught_up = expect_ready(
        reconcile_persisted_tip(10, tip_hash, 0, 10, tip_hash, 10, |hash| {
            resolve_from_chain(&chain, hash)
        })
        .expect("catch-up recon"),
    );
    assert!(matches!(
        caught_up,
        PersistedTipReconciliation::StillCanonical { .. }
    ));
}

/// §3.6: multi-member inscription folded in canonical
/// `(height, tx_index, vin_index, member_index)` order; duplicate `Pk`
/// keeps the **first** occurrence's `R`.
#[test]
fn v1_scan_fold_canonical_order_first_occurrence_wins() {
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
    let mut members =
        members_to_published(50, 3, 1, &[(pk_a, r_a_first), (pk_b, r_b), (pk_c, r_c)])
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
/// when process has not claimed v1 (and after an explicit legacy claim).
#[test]
fn flag_off_leaves_legacy_publisher_allowed() {
    assert_eq!(
        resolve_v1_shadow_mode(None).expect("unset"),
        V1ShadowMode::Off
    );
    // Unclaimed process: legacy publish still allowed (unit-test / pre-boot).
    ensure_legacy_publisher_allowed().expect("legacy ok when unclaimed");
    // v1.1 publisher requires an exclusive claim — no silent open.
    assert!(ensure_v1_publisher_allowed().is_err());
}
