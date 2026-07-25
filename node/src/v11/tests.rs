//! Stage-1 v1.1 persistence + flag tests.
//!
//! The restart-identity test builds a non-trivial NfLog + CoinHist state,
//! persists it, reloads into a fresh engine, and asserts byte-identical
//! NfLog root and per-account CoinHist roots.

use shared::spec_v1::{
    self as host, AccountState, Address, ChainPosition, Coin, CoinHistTree, HashDigest, NfLogEntry,
    ZERO_HASH,
};
use std::collections::{BTreeMap, BTreeSet};
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::state_engine::{AccountRecord, StateEngine, TrackedCoin};

use super::db_v11::{self, EngineSnapshot};
use super::mode::{resolve_prover_mode, ProverMode};
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

    let state = AccountState::new(
        owner,
        ZERO_HASH,
        balances,
        pk(0xB1),
        7,
        ch_root,
    )
    .expect("AccountState");

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
fn flag_defaults_to_legacy_when_unset() {
    // Normative default: the pure resolver maps "env unset" → Legacy.
    // (Process-env is not mutated here so parallel tests cannot race.)
    assert_eq!(
        resolve_prover_mode(None).expect("unset"),
        ProverMode::Legacy
    );
    assert_eq!(
        resolve_prover_mode(Some("")).expect("empty"),
        ProverMode::Legacy
    );
    assert_eq!(
        resolve_prover_mode(Some("legacy")).expect("legacy"),
        ProverMode::Legacy
    );
    // Only the exact token "v11" selects the new path.
    assert_eq!(resolve_prover_mode(Some("v11")).expect("v11"), ProverMode::V11);
    // Any other value fails loud — never silently treated as legacy.
    assert!(resolve_prover_mode(Some("V11")).is_err());
    assert!(resolve_prover_mode(Some("bridge")).is_err());
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

    let snap = EngineSnapshot::from_engine(&engine);
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
