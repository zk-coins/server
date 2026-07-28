//! Tests for `publisher.rs`.
//!
//! The pure inscription building / Schnorr signing / witness mining logic
//! in `inscription_txs` is exercised end-to-end with deterministic inputs.
//! The Esplora-touching helpers (`get_publisher_utxo`,
//! `broadcast_inscription_txs`, `create_and_broadcast_inscription`) are
//! exercised against a `wiremock` mock server so no real network is hit.

use super::*;
use crate::db;
use bitcoin::blockdata::opcodes;
use bitcoin::hashes::Hash;
use bitcoin::script::Instruction;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Address, Network, OutPoint, Txid, XOnlyPublicKey};
use serde_json::json;
use std::str::FromStr;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::test_db::{setup_pool, SchemaScope};

/// Claim the legacy process stack for publisher unit tests.
///
/// The claim is monotonic and cannot be withdrawn outside `stack-policy`'s
/// own `#[cfg(test)]`. Under process-per-test (nextest) the process starts
/// unclaimed; this re-affirms Legacy so broadcast construction is allowed.
/// A pre-existing V1 claim panics (fail loud) rather than silently clearing.
fn ensure_legacy_process_for_publisher_test() {
    use crate::v1::{set_process_stack_mode, ScanStackMode};
    set_process_stack_mode(ScanStackMode::Legacy);
}

/// Test publisher key used to produce deterministic Taproot addresses
/// and signatures. The production `PUBLISHER_KEY` is now a required env
/// var with no default (see `lib.rs`); this constant is a local
/// test-only placeholder passed directly into `inscription_txs` and
/// never reaches the global `crate::PUBLISHER_KEY` resolution. Matches
/// the CI test value in `.github/workflows/ci.yaml`.
const TEST_PUBLISHER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000001";

fn test_publisher_address(network: Network) -> Address {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_str(TEST_PUBLISHER_KEY).unwrap();
    let key_pair = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = XOnlyPublicKey::from_keypair(&key_pair);
    Address::p2tr(&secp, xonly, None, network)
}

/// Build an arbitrary deterministic outpoint with all-zero txid and the
/// given vout. Good enough for tests — nothing on chain is verified.
fn fake_outpoint(vout: u32) -> OutPoint {
    OutPoint::new(Txid::all_zeros(), vout)
}

/// Spin up a wiremock server and produce an `EsploraConfig` that points
/// the publisher code at it. The WS endpoint is left unset because most
/// HTTP-only tests never reach the broadcast path.
async fn setup_mock_esplora() -> (MockServer, EsploraConfig) {
    let mock_server = MockServer::start().await;
    let config = EsploraConfig {
        url: mock_server.uri(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
    };
    (mock_server, config)
}

// -----------------------------------------------------------------------------
// Pure logic: inscription_txs
// -----------------------------------------------------------------------------

/// The reveal transaction's txid must start with the `INSCRIPTION_MARKER_PREFIX`
/// (the scanner relies on this prefix to find inscriptions in the chain).
#[test]
fn inscription_txs_produces_taproot_commit_and_reveal_with_marker_prefix() {
    let config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
    };
    let publisher_address = test_publisher_address(config.network());
    let outpoints = vec![(fake_outpoint(0), 100_000u64)];

    let (commit_tx, reveal_tx, _stats) = inscription_txs(
        b"Hello, zkCoins!",
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );

    // commit_tx must spend the supplied outpoint.
    assert_eq!(commit_tx.input.len(), 1);
    assert_eq!(commit_tx.input[0].previous_output, fake_outpoint(0));

    // reveal_tx txid starts with the marker prefix (so the scanner picks
    // it up). `hex::decode` is the canonical inverse of the publisher's
    // own check.
    let target = hex::decode(INSCRIPTION_MARKER_PREFIX).unwrap();
    let txid_bytes = reveal_tx.compute_txid().as_byte_array().to_vec();
    assert!(
        txid_bytes.starts_with(&target),
        "reveal txid {} does not start with {}",
        reveal_tx.compute_txid(),
        INSCRIPTION_MARKER_PREFIX
    );
}

/// Reveal-script witness must embed the commitment payload bytes verbatim.
/// In a Taproot script-spend the witness layout is `[sig, script, control]`,
/// so the script is the second-to-last witness item.
#[test]
fn inscription_txs_embeds_commitment_data_in_reveal_script() {
    let config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
    };
    let publisher_address = test_publisher_address(config.network());
    let payload = b"Hello, zkCoins!".to_vec();
    let outpoints = vec![(fake_outpoint(0), 100_000u64)];

    let (_commit_tx, reveal_tx, _stats) = inscription_txs(
        &payload,
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );

    let witness_items: Vec<Vec<u8>> = reveal_tx.input[0]
        .witness
        .iter()
        .map(|w| w.to_vec())
        .collect();
    assert_eq!(
        witness_items.len(),
        3,
        "reveal witness must be [sig, script, control_block]"
    );

    // The script lives at index `len - 2`. Walk its push-data chunks and
    // collect them to reconstruct the embedded payload.
    let script_bytes = &witness_items[witness_items.len() - 2];
    let script = bitcoin::ScriptBuf::from_bytes(script_bytes.clone());

    let mut collected = Vec::new();
    let mut prev_was_op_false = false;
    let mut inside = false;
    for ins in script.instructions().flatten() {
        if inside {
            match ins {
                Instruction::PushBytes(b) => collected.extend_from_slice(b.as_bytes()),
                Instruction::Op(op) if op == opcodes::all::OP_ENDIF => break,
                _ => {}
            }
        } else {
            match ins {
                Instruction::PushBytes(b) if b.is_empty() => prev_was_op_false = true,
                Instruction::Op(op) if op == opcodes::all::OP_IF && prev_was_op_false => {
                    inside = true;
                }
                _ => prev_was_op_false = false,
            }
        }
    }

    assert_eq!(
        collected, payload,
        "reveal script must embed the exact commitment data"
    );
}

/// Commitment payloads larger than `MAX_CHUNK_SIZE` (520 bytes) must be
/// split into multiple push-data chunks inside the reveal script.
#[test]
fn inscription_txs_chunks_large_commitment_data() {
    let config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
    };
    let publisher_address = test_publisher_address(config.network());
    // 600 bytes of repeating non-zero pattern (zero bytes would collide
    // with the OP_FALSE delimiter inside the loop below).
    let payload: Vec<u8> = (0..600).map(|i| (i % 255 + 1) as u8).collect();
    let outpoints = vec![(fake_outpoint(0), 200_000u64)];

    let (_commit_tx, reveal_tx, _stats) = inscription_txs(
        &payload,
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );

    let witness_items: Vec<Vec<u8>> = reveal_tx.input[0]
        .witness
        .iter()
        .map(|w| w.to_vec())
        .collect();
    let script_bytes = &witness_items[witness_items.len() - 2];
    let script = bitcoin::ScriptBuf::from_bytes(script_bytes.clone());

    // Count push-data chunks inside the OP_FALSE / OP_IF envelope.
    let mut prev_was_op_false = false;
    let mut inside = false;
    let mut chunk_count = 0usize;
    for ins in script.instructions().flatten() {
        if inside {
            match ins {
                Instruction::PushBytes(_) => chunk_count += 1,
                Instruction::Op(op) if op == opcodes::all::OP_ENDIF => break,
                _ => {}
            }
        } else {
            match ins {
                Instruction::PushBytes(b) if b.is_empty() => prev_was_op_false = true,
                Instruction::Op(op) if op == opcodes::all::OP_IF && prev_was_op_false => {
                    inside = true;
                }
                _ => prev_was_op_false = false,
            }
        }
    }

    // 600 bytes / 520 per chunk = 2 chunks (520 + 80).
    assert_eq!(
        chunk_count, 2,
        "600-byte payload must be split into exactly 2 push_slice chunks"
    );
}

/// The commit transaction's input witness must carry a 64-byte BIP-340
/// Schnorr signature (key-spend, default sighash → no sighash flag byte).
#[test]
fn inscription_txs_signs_commit_input_with_taproot_keyspend() {
    let config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
    };
    let publisher_address = test_publisher_address(config.network());
    let outpoints = vec![(fake_outpoint(0), 100_000u64)];

    let (commit_tx, _reveal_tx, _stats) = inscription_txs(
        b"Hello, zkCoins!",
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );

    let witness_items: Vec<Vec<u8>> = commit_tx.input[0]
        .witness
        .iter()
        .map(|w| w.to_vec())
        .collect();
    assert_eq!(
        witness_items.len(),
        1,
        "key-spend witness must be exactly [signature]"
    );
    assert_eq!(
        witness_items[0].len(),
        64,
        "BIP-340 Schnorr signature with default sighash is 64 bytes (no sighash flag)"
    );
}

/// `EsploraConfig::network()` must map `is_mainnet=false` to `Signet`.
/// The publisher derives the commit/publisher address from this network,
/// so an off-by-one here would silently broadcast to the wrong chain.
#[test]
fn inscription_txs_uses_signet_when_is_mainnet_false() {
    let config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
    };
    assert_eq!(config.network(), Network::Signet);

    // And the mainnet branch — guards the bool-flip too.
    let mainnet_config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: true,
        network_name: "Mainnet".to_string(),
        ws_url: None,
    };
    assert_eq!(mainnet_config.network(), Network::Bitcoin);
}

// -----------------------------------------------------------------------------
// Esplora HTTP, mocked via wiremock
// -----------------------------------------------------------------------------

#[tokio::test]
async fn get_publisher_utxo_returns_empty_when_address_has_no_utxos() {
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let result = get_publisher_utxo(&publisher_address, &config, None)
        .await
        .expect("call should succeed");
    assert!(result.is_empty(), "empty Esplora response → empty Vec");
}

#[tokio::test]
async fn get_publisher_utxo_returns_utxos_with_value() {
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    let txid_hex = "1111111111111111111111111111111111111111111111111111111111111111";
    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "txid": txid_hex,
                "vout": 3,
                "value": 1000,
                "status": { "confirmed": true, "block_height": 100, "block_hash": "0000000000000000000000000000000000000000000000000000000000000001", "block_time": 1700000000 }
            }
        ])))
        .mount(&server)
        .await;

    let result = get_publisher_utxo(&publisher_address, &config, None)
        .await
        .expect("call should succeed");

    assert_eq!(result.len(), 1, "exactly one UTXO is mapped through");
    let (outpoint, sats) = result[0];
    assert_eq!(sats, 1000);
    assert_eq!(outpoint.vout, 3);
    assert_eq!(outpoint.txid, Txid::from_str(txid_hex).unwrap());
}

#[tokio::test]
async fn get_publisher_utxo_returns_empty_when_total_below_minimum() {
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    let txid_hex = "2222222222222222222222222222222222222222222222222222222222222222";
    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "txid": txid_hex,
                "vout": 0,
                "value": 500,
                "status": { "confirmed": true, "block_height": 100, "block_hash": "0000000000000000000000000000000000000000000000000000000000000001", "block_time": 1700000000 }
            }
        ])))
        .mount(&server)
        .await;

    // 500 sats present, but caller demands at least 1000 → wallet is
    // declared empty (publisher will refuse to broadcast).
    let result = get_publisher_utxo(&publisher_address, &config, Some(1000))
        .await
        .expect("call should succeed");
    assert!(
        result.is_empty(),
        "total below minimum must collapse to an empty vec"
    );
}



// -----------------------------------------------------------------------------
// create_and_broadcast_inscription — integration over the mocked HTTP layer
// -----------------------------------------------------------------------------

#[tokio::test]
async fn create_and_broadcast_inscription_fails_when_no_utxos() {
    ensure_legacy_process_for_publisher_test();
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&server)
        .await;

    let err = create_and_broadcast_inscription(
        b"Hello, zkCoins!",
        db::InscriptionKind::Mint,
        &config,
        None,
    )
    .await
    .expect_err("empty wallet must produce an Err");

    assert!(
        err.to_string().contains("No UTXOs available"),
        "error should describe the empty-wallet condition, got: {}",
        err
    );
}

#[tokio::test]
async fn create_and_broadcast_inscription_succeeds_end_to_end_with_mocked_esplora() {
    ensure_legacy_process_for_publisher_test();
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    // 1) Address-UTXO lookup — return one UTXO with enough sats to cover
    //    both commit + reveal fees.
    let funding_txid = "3333333333333333333333333333333333333333333333333333333333333333";
    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "txid": funding_txid,
                "vout": 0,
                "value": 100_000,
                "status": { "confirmed": true, "block_height": 100, "block_hash": "0000000000000000000000000000000000000000000000000000000000000001", "block_time": 1700000000 }
            }
        ])))
        .mount(&server)
        .await;

    // 2) Broadcast — accept both commit and reveal POSTs.
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let (commit_txid, reveal_txid) = create_and_broadcast_inscription(
        b"Hello, zkCoins!",
        db::InscriptionKind::Mint,
        &config,
        None,
    )
    .await
    .expect("end-to-end inscription should succeed against mocked Esplora");
    assert_ne!(
        commit_txid, reveal_txid,
        "commit and reveal must be distinct transactions"
    );

    // Reveal txid must carry the inscription marker prefix.
    let target = hex::decode(INSCRIPTION_MARKER_PREFIX).unwrap();
    assert!(
        reveal_txid.as_byte_array().starts_with(&target),
        "reveal txid {} must start with marker {}",
        reveal_txid,
        INSCRIPTION_MARKER_PREFIX
    );
}

// -----------------------------------------------------------------------------
// Phase B: pending_inscriptions persistence + resume
// -----------------------------------------------------------------------------
//
// These tests pair a real Postgres 17 container (via testcontainers) with
// wiremock-mocked Esplora. They exercise:
//
//   1-3) Forward path: `create_and_broadcast_inscription` persists a
//        `constructed` row BEFORE the commit broadcast, advances it to
//        `commit_broadcast`, `reveal_broadcast`, and finally `complete`
//        as each step lands.
//   4-7) Resume path: `resume_pending_inscriptions` walks each non-
//        complete row to `complete` regardless of starting status, skips
//        completed rows, and is idempotent when called a second time.
//   8)   Resume path tolerance: a `bad-txns-inputs-missingorspent`
//        rejection from Esplora's commit-broadcast on resume means the
//        commit already landed on a previous attempt; the resumer
//        advances and continues with the reveal instead of bailing.

/// Hand back a migrated pool scoped to a fresh per-test schema inside
/// the shared `postgres:17` container (issue #181 Opt B). The
/// `SchemaScope` is returned alongside so the caller keeps it alive
/// for the duration of the test — its `Drop` cleans up the schema
/// after the test finishes.
async fn setup_phaseb_pool() -> (PgPool, SchemaScope) {
    let scope = setup_pool().await;
    let pool = scope.pool.clone();
    // Stage 3 Runde 6: pending_inscriptions writers are gated at the SQL
    // sink — claim legacy so phase-B seed/resume tests can exercise them.
    crate::v1::claim_stack_scan_mode(&pool, crate::v1::ScanStackMode::Legacy)
        .await
        .expect("claim legacy stack for publisher phase-B tests");
    (pool, scope)
}

/// Read the current status of a pending row by `commit_txid`. Panics if
/// no row exists — the caller is asserting that one is present.
async fn fetch_pending_status(pool: &PgPool, commit_txid: &[u8]) -> String {
    let row: (String,) =
        sqlx::query_as("SELECT status FROM pending_inscriptions WHERE commit_txid = $1")
            .bind(commit_txid)
            .fetch_one(pool)
            .await
            .expect("pending row should exist");
    row.0
}

/// Count rows in `pending_inscriptions` (any status).
async fn count_pending_rows(pool: &PgPool) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM pending_inscriptions")
        .fetch_one(pool)
        .await
        .expect("count query");
    n
}

/// Build a (commit, reveal) pair using the test publisher key against the
/// supplied UTXO. The mining loop inside `inscription_txs` is
/// deterministic for a given input set so the test can recompute either
/// txid from the returned txs.
fn build_test_pair(commitment_data: &[u8]) -> (Transaction, Transaction) {
    let config = EsploraConfig {
        url: "http://127.0.0.1:1/api".to_string(),
        is_mainnet: false,
        network_name: "Mutinynet".to_string(),
        ws_url: None,
    };
    let publisher_address = test_publisher_address(config.network());
    let outpoints = vec![(fake_outpoint(0), 100_000u64)];
    let (commit_tx, reveal_tx, _stats) = inscription_txs(
        commitment_data,
        &publisher_address,
        outpoints,
        TEST_PUBLISHER_KEY,
        &config,
    );
    (commit_tx, reveal_tx)
}

/// Insert a row in the supplied state directly via the db helper. Used
/// to seed the resume tests without going through the forward path.
async fn seed_pending_row(
    pool: &PgPool,
    commit_tx: &Transaction,
    reveal_tx: &Transaction,
    commitment_data: &[u8],
    status: &str,
) {
    let commit_txid = commit_tx.compute_txid();
    let reveal_txid = reveal_tx.compute_txid();
    let commit_tx_bytes = bitcoin::consensus::serialize(commit_tx);
    let reveal_tx_bytes = bitcoin::consensus::serialize(reveal_tx);
    let commit_output_value = commit_tx.output[0].value.to_sat() as i64;
    let inserted = db::insert_pending_inscription(
        pool,
        commit_txid.as_byte_array(),
        reveal_txid.as_byte_array(),
        db::InscriptionKind::Mint,
        commitment_data,
        &commit_tx_bytes,
        &reveal_tx_bytes,
        commit_output_value,
    )
    .await
    .expect("seed insert");
    assert!(inserted, "fresh insert should succeed");
    if status != db::PENDING_STATUS_CONSTRUCTED {
        db::update_pending_status(pool, commit_txid.as_byte_array(), status)
            .await
            .expect("seed status update");
    }
}

#[tokio::test]
async fn broadcast_persists_constructed_row_before_commit_broadcast() {
    ensure_legacy_process_for_publisher_test();
    let (pool, _container) = setup_phaseb_pool().await;
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    let funding_txid = "3333333333333333333333333333333333333333333333333333333333333333";
    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "txid": funding_txid,
                "vout": 0,
                "value": 100_000,
                "status": { "confirmed": true, "block_height": 100, "block_hash": "0000000000000000000000000000000000000000000000000000000000000001", "block_time": 1700000000 }
            }
        ])))
        .mount(&server)
        .await;
    // Reject every POST /tx so the broadcast fails AFTER the
    // constructed row was persisted. The assertion is that the row
    // landed on disk BEFORE the broadcast attempt — i.e. it is present
    // even though the broadcast errored out.
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(400).set_body_string("simulated broadcast failure"))
        .mount(&server)
        .await;

    let _err = create_and_broadcast_inscription(
        b"phaseb-1",
        db::InscriptionKind::Mint,
        &config,
        Some(&pool),
    )
    .await
    .expect_err("broadcast must fail (400)");

    // Exactly one row, status = constructed (commit broadcast failed
    // so the advance to `commit_broadcast` never fired).
    assert_eq!(count_pending_rows(&pool).await, 1);
    let row = sqlx::query_as::<_, (String, Vec<u8>, Vec<u8>, Vec<u8>)>(
        "SELECT status, commit_tx, reveal_tx, commitment FROM pending_inscriptions",
    )
    .fetch_one(&pool)
    .await
    .unwrap();
    assert_eq!(row.0, db::PENDING_STATUS_CONSTRUCTED);
    assert!(
        !row.1.is_empty() && !row.2.is_empty(),
        "commit_tx and reveal_tx must be persisted as non-empty blobs"
    );
    assert_eq!(row.3, b"phaseb-1");
}

#[tokio::test]
async fn broadcast_advances_to_commit_broadcast_after_commit_success() {
    ensure_legacy_process_for_publisher_test();
    let (pool, _container) = setup_phaseb_pool().await;
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "txid": "3333333333333333333333333333333333333333333333333333333333333333",
                "vout": 0,
                "value": 100_000,
                "status": { "confirmed": true, "block_height": 100, "block_hash": "0000000000000000000000000000000000000000000000000000000000000001", "block_time": 1700000000 }
            }
        ])))
        .mount(&server)
        .await;
    // Two POST /tx mocks differentiated by explicit `with_priority`
    // (lower number = higher priority in wiremock; default is 5). The
    // high-priority `up_to_n_times(1)` 200 matches the commit POST;
    // after it is consumed, subsequent POSTs fall through to the
    // lower-priority 400 fallback (the reveal POST is rejected so the
    // broadcast errors after advancing the row to `commit_broadcast`).
    // The post-broadcast WS wait was removed alongside `track-tx`, so
    // this layered mock is now the only way to observe the
    // intermediate `commit_broadcast` status.
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .up_to_n_times(1)
        .with_priority(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(400).set_body_string("simulated reveal failure"))
        .with_priority(2)
        .mount(&server)
        .await;

    let _err = create_and_broadcast_inscription(
        b"phaseb-2",
        db::InscriptionKind::Mint,
        &config,
        Some(&pool),
    )
    .await
    .expect_err("reveal POST 400 must surface as Err");

    // One row, advanced from `constructed` to `commit_broadcast` by
    // the commit-OK hook but stuck there because the reveal step
    // failed.
    assert_eq!(count_pending_rows(&pool).await, 1);
    let (commit_txid_bytes,): (Vec<u8>,) =
        sqlx::query_as("SELECT commit_txid FROM pending_inscriptions")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert_eq!(
        fetch_pending_status(&pool, &commit_txid_bytes).await,
        db::PENDING_STATUS_COMMIT_BROADCAST
    );
}

#[tokio::test]
async fn broadcast_advances_to_reveal_broadcast_after_reveal_success() {
    ensure_legacy_process_for_publisher_test();
    // Phase E: `complete` now means "SMT/MMR contain this inscription's
    // entry", not "reveal landed on chain". The broadcast leg stops at
    // `reveal_broadcast`; the caller (`mint_handler`) advances the row
    // to `complete` only after running `state.update` in-process. This
    // test exercises the publisher in isolation (no mint flow), so the
    // expected terminal status here is `reveal_broadcast`.
    let (pool, _container) = setup_phaseb_pool().await;
    let (server, config) = setup_mock_esplora().await;
    let publisher_address = test_publisher_address(config.network());

    Mock::given(method("GET"))
        .and(path(format!("/address/{}/utxo", publisher_address)))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            {
                "txid": "3333333333333333333333333333333333333333333333333333333333333333",
                "vout": 0,
                "value": 100_000,
                "status": { "confirmed": true, "block_height": 100, "block_hash": "0000000000000000000000000000000000000000000000000000000000000001", "block_time": 1700000000 }
            }
        ])))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    let _result = create_and_broadcast_inscription(
        b"phaseb-3",
        db::InscriptionKind::Mint,
        &config,
        Some(&pool),
    )
    .await
    .expect("happy path must succeed");

    // Final state is `reveal_broadcast` — see Phase E note above.
    assert_eq!(count_pending_rows(&pool).await, 1);
    let (status,): (String,) = sqlx::query_as("SELECT status FROM pending_inscriptions")
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(status, db::PENDING_STATUS_REVEAL_BROADCAST);
}

#[tokio::test]
async fn resume_from_commit_broadcast_rebroadcasts_reveal_only() {
    ensure_legacy_process_for_publisher_test();
    let (pool, _container) = setup_phaseb_pool().await;
    let (server, config) = setup_mock_esplora().await;

    let (commit_tx, reveal_tx) = build_test_pair(b"resume-cb");
    seed_pending_row(
        &pool,
        &commit_tx,
        &reveal_tx,
        b"resume-cb",
        db::PENDING_STATUS_COMMIT_BROADCAST,
    )
    .await;

    // Accept POST /tx (the resumer only broadcasts the reveal here).
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    resume_pending_inscriptions(&pool, &config)
        .await
        .expect("resume must succeed");

    let commit_txid_bytes = commit_tx.compute_txid().as_byte_array().to_vec();
    // Phase E: resume stops at `reveal_broadcast` — the scanner will
    // run state.update against the on-chain inscription and mark the
    // row `complete` after the SMT/MMR are updated.
    assert_eq!(
        fetch_pending_status(&pool, &commit_txid_bytes).await,
        db::PENDING_STATUS_REVEAL_BROADCAST
    );

    // Exactly one POST /tx (the reveal). The commit was already on
    // chain by the time we crashed, so the resumer must not broadcast
    // it again — that would consume a fresh publisher-wallet UTXO.
    let received = server.received_requests().await.unwrap();
    let post_tx_count = received
        .iter()
        .filter(|r| r.method == wiremock::http::Method::POST && r.url.path() == "/tx")
        .count();
    assert_eq!(
        post_tx_count, 1,
        "resume(commit_broadcast) must POST /tx exactly once (the reveal)"
    );
}

#[tokio::test]
async fn resume_from_constructed_rebroadcasts_both() {
    ensure_legacy_process_for_publisher_test();
    let (pool, _container) = setup_phaseb_pool().await;
    let (server, config) = setup_mock_esplora().await;

    let (commit_tx, reveal_tx) = build_test_pair(b"resume-co");
    seed_pending_row(
        &pool,
        &commit_tx,
        &reveal_tx,
        b"resume-co",
        db::PENDING_STATUS_CONSTRUCTED,
    )
    .await;

    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    resume_pending_inscriptions(&pool, &config)
        .await
        .expect("resume must succeed");

    let commit_txid_bytes = commit_tx.compute_txid().as_byte_array().to_vec();
    // Phase E: see the `commit_broadcast` resume test above — terminal
    // status from a resume-driven re-broadcast is `reveal_broadcast`;
    // the scanner's state.update is what flips it to `complete`.
    assert_eq!(
        fetch_pending_status(&pool, &commit_txid_bytes).await,
        db::PENDING_STATUS_REVEAL_BROADCAST
    );

    // Two POSTs (commit + reveal).
    let received = server.received_requests().await.unwrap();
    let post_tx_count = received
        .iter()
        .filter(|r| r.method == wiremock::http::Method::POST && r.url.path() == "/tx")
        .count();
    assert_eq!(
        post_tx_count, 2,
        "resume(constructed) must POST /tx twice (commit + reveal)"
    );
}

#[tokio::test]
async fn resume_skips_complete_rows() {
    ensure_legacy_process_for_publisher_test();
    let (pool, _container) = setup_phaseb_pool().await;
    let (server, config) = setup_mock_esplora().await;

    let (commit_tx, reveal_tx) = build_test_pair(b"resume-skip");
    seed_pending_row(
        &pool,
        &commit_tx,
        &reveal_tx,
        b"resume-skip",
        db::PENDING_STATUS_COMPLETE,
    )
    .await;

    // No mocks mounted on POST /tx — if the resumer touches Esplora at
    // all the call will surface as a wiremock-unmatched 404 and the
    // status flip below would fail because the reveal broadcast would
    // error out and roll the row back. We assert the resumer is a
    // no-op by checking the post-state matches the seeded state
    // exactly.
    resume_pending_inscriptions(&pool, &config)
        .await
        .expect("resume must succeed (no-op)");

    let commit_txid_bytes = commit_tx.compute_txid().as_byte_array().to_vec();
    assert_eq!(
        fetch_pending_status(&pool, &commit_txid_bytes).await,
        db::PENDING_STATUS_COMPLETE
    );
    let received = server.received_requests().await.unwrap();
    assert!(
        received.is_empty(),
        "resume(complete) must not hit Esplora; got {} requests",
        received.len()
    );
}

#[tokio::test]
async fn resume_is_idempotent_when_called_twice() {
    ensure_legacy_process_for_publisher_test();
    let (pool, _container) = setup_phaseb_pool().await;
    let (server, config) = setup_mock_esplora().await;

    let (commit_tx, reveal_tx) = build_test_pair(b"resume-idem");
    seed_pending_row(
        &pool,
        &commit_tx,
        &reveal_tx,
        b"resume-idem",
        db::PENDING_STATUS_REVEAL_BROADCAST,
    )
    .await;

    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;

    // First call: walks the row from `reveal_broadcast` and re-
    // broadcasts the reveal. Phase E: the resumer leaves the row at
    // `reveal_broadcast` (the scanner is what marks it `complete`
    // after running state.update), so the assertion below pins the
    // pre-scanner status, not `complete`. Idempotency is exercised
    // by the second call below.
    resume_pending_inscriptions(&pool, &config)
        .await
        .expect("first resume must succeed");
    let commit_txid_bytes = commit_tx.compute_txid().as_byte_array().to_vec();
    assert_eq!(
        fetch_pending_status(&pool, &commit_txid_bytes).await,
        db::PENDING_STATUS_REVEAL_BROADCAST
    );

    let after_first = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method == wiremock::http::Method::POST && r.url.path() == "/tx")
        .count();

    // Second call: row is still `reveal_broadcast`. The resumer re-
    // dispatches into the same `reveal_broadcast` branch and re-
    // broadcasts the reveal a second time — Esplora returns `txn-
    // already-known` (200 in the wiremock fallback) and the row stays
    // at `reveal_broadcast`. The idempotency invariant the test pins
    // is now "no error path, end status unchanged".
    resume_pending_inscriptions(&pool, &config)
        .await
        .expect("second resume must succeed");
    assert_eq!(
        fetch_pending_status(&pool, &commit_txid_bytes).await,
        db::PENDING_STATUS_REVEAL_BROADCAST
    );
    let after_second = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method == wiremock::http::Method::POST && r.url.path() == "/tx")
        .count();
    // Phase E: the resumer re-broadcasts the reveal on every call to
    // the `reveal_broadcast` branch, since it no longer flips the row
    // to `complete`. This matches the documented idempotency contract
    // (`txn-already-known` from Esplora) and is harmless at the chain
    // layer.
    assert_eq!(
        after_second,
        after_first + 1,
        "second resume must POST /tx exactly once more (the idempotent reveal re-broadcast)"
    );
}

#[tokio::test]
async fn resume_tolerates_bad_inputs_error_on_double_spend() {
    ensure_legacy_process_for_publisher_test();
    // The `constructed` retry case: a previous attempt's commit
    // landed on chain (so the input UTXO is already spent) but we
    // crashed before recording the success. The resumer re-tries
    // the commit, Esplora replies 400 with
    // `bad-txns-inputs-missingorspent`, the resumer must advance
    // the row and proceed to broadcast the reveal.
    let (pool, _container) = setup_phaseb_pool().await;
    let (server, config) = setup_mock_esplora().await;

    let (commit_tx, reveal_tx) = build_test_pair(b"resume-doublespend");
    seed_pending_row(
        &pool,
        &commit_tx,
        &reveal_tx,
        b"resume-doublespend",
        db::PENDING_STATUS_CONSTRUCTED,
    )
    .await;

    // Two stacked mocks on the same path: the FIRST request is matched
    // by the `up_to_n_times(1)` mock (returns 400 +
    // bad-txns-inputs-missingorspent — the commit-re-broadcast hits
    // this), every subsequent request falls through to the fallback
    // mock (200 — the reveal broadcast hits this).
    //
    // wiremock matches mocks in LIFO insertion order, so we mount the
    // fallback FIRST and the up-to-1 rejection second.
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/tx"))
        .respond_with(
            ResponseTemplate::new(400)
                .set_body_string("sendrawtransaction RPC error: bad-txns-inputs-missingorspent"),
        )
        .up_to_n_times(1)
        .mount(&server)
        .await;

    resume_pending_inscriptions(&pool, &config)
        .await
        .expect("resume must tolerate the bad-inputs rejection on commit");

    let commit_txid_bytes = commit_tx.compute_txid().as_byte_array().to_vec();
    // Phase E: the resumer stops at `reveal_broadcast`; the scanner is
    // what flips the row to `complete` after running state.update on
    // the on-chain inscription. This test exercises the publisher in
    // isolation, so the expected terminal status is `reveal_broadcast`.
    assert_eq!(
        fetch_pending_status(&pool, &commit_txid_bytes).await,
        db::PENDING_STATUS_REVEAL_BROADCAST,
        "row must end in reveal_broadcast after the resumer absorbs the double-spend signal and broadcasts the reveal"
    );
    let post_tx_count = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method == wiremock::http::Method::POST && r.url.path() == "/tx")
        .count();
    assert_eq!(
        post_tx_count, 2,
        "resume must POST /tx twice: rejected commit + accepted reveal"
    );
}

// -----------------------------------------------------------------------------
// Phase E: mint_handler advances state synchronously after broadcast
// -----------------------------------------------------------------------------
//
// The three tests below pin the Phase-E contract:
//
//   1. The publisher leg stops at `reveal_broadcast` — `mint_handler`
//      drives the advance to `complete` only after `state.update`
//      has been applied in-process. This complements
//      `broadcast_advances_to_reveal_broadcast_after_reveal_success`
//      above by making the contract explicit in test name + assertion.
//
//   2. Scanner-side: a row at `complete` short-circuits the scanner's
//      `state.update` step — the lookup helper returns the marker the
//      scanner checks, and `should_skip_scanner_state_update` returns
//      true for that marker only.
//
//   3. Scanner-side fallback: an in-progress row (or no row at all)
//      lets the scanner run `state.update` itself — the recovery /
//      external-mint path stays intact.



