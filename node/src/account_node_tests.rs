use super::*;
use crate::state::State;
use bitcoin::{
    bip32::{ChildNumber, Xpriv, Xpub},
    key::Secp256k1,
    secp256k1::{All, PublicKey as BitcoinPublicKey},
    Network,
};
use lazy_static::lazy_static;
use zkcoins_program::hash::{digest_from_bytes, sha256_to_digest, ZERO_HASH};

lazy_static! {
    static ref SECP256K1_TEST_CTX: Secp256k1<All> = Secp256k1::new();
}

/// A deterministic, non-zero asset_id used across these fixtures.
/// Derived from the fixture creator key (`TestAccountData::new_minting_account()`'s
/// index-0 pubkey) with name "TestCoin" / 8 decimals so it matches
/// `calculate_asset_id(creator_pubkey, H(name), decimals)`.
fn test_asset_id() -> AssetId {
    let secret = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(Network::Bitcoin, secret)
        .expect("Failed to create private key for test asset derivation.");
    let pk0 = generate_test_public_key(&xpriv, 0).serialize();
    zkcoins_program::types::calculate_asset_id_from_name(&pk0, "TestCoin", 8)
}

/// Build an `Account` pre-seeded with `balance` of [`test_asset_id`].
fn seeded_account(balance: u64) -> Account {
    let mut a = Account::new_for_asset(test_asset_id());
    a.balance = balance;
    a
}

fn generate_test_public_key(private_key: &Xpriv, index: u32) -> BitcoinPublicKey {
    Xpub::from_priv(&SECP256K1_TEST_CTX, private_key)
        .derive_pub(&SECP256K1_TEST_CTX, &[ChildNumber::Normal { index }])
        .expect("Failed to derive public key for test")
        .public_key
}

struct TestAccountData {
    xpriv: Xpriv,
    address: Address,
}

impl TestAccountData {
    /// Ordinary funded-sender fixture (no privileged minting account).
    fn new_minting_account() -> Self {
        let secret = include_bytes!("../minting_secret.bin");
        let xpriv = Xpriv::new_master(Network::Bitcoin, secret)
            .expect("Failed to create private key for source account.");
        let initial_pk_bytes = generate_test_public_key(&xpriv, 0).serialize().to_vec();
        // Address = H(Pk₀) = SHA-256(pubkey) per spec (#226).
        let address = sha256_to_digest(&initial_pk_bytes);

        TestAccountData { xpriv, address }
    }

    fn new_generic(seed: &[u8; 32], network: Network) -> Self {
        let xpriv = Xpriv::new_master(network, seed)
            .expect("Failed to create private key for generic account.");

        let initial_pk_bytes = generate_test_public_key(&xpriv, 0).serialize().to_vec();
        // Address = H(Pk₀) = SHA-256(pubkey) per spec (#226).
        let address = sha256_to_digest(&initial_pk_bytes);

        TestAccountData { xpriv, address }
    }
}

/// `zero_asset_id` is the serde default for `Account.asset_id` on blobs
/// persisted before the multi-asset migration. No such blob exists in
/// the closed test environment (so the default never fires through
/// deserialization), but the gate measures the helper — pin its
/// contract directly.
#[test]
fn zero_asset_id_default_is_zero_hash() {
    assert_eq!(zero_asset_id(), ZERO_HASH);
}

#[test]
fn test_import_funded_account() {
    // Neutral model: importing a funded `(owner, asset_id)` account is
    // just an ordinary ledger insert — there is no privileged minting
    // account to bootstrap. Verifies import + per-asset balance lookup.
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(state_arc);

    let account_data = TestAccountData::new_minting_account();
    node.import_account(account_data.address, seeded_account(10_000));
    assert_eq!(
        node.get_account_balance(&account_data.address, &test_asset_id())
            .unwrap(),
        10_000
    );
}

/// PR-A3 replacement for the previous file-based `save_and_load_roundtrip`:
/// persist an imported account via `persist_account` (the same helper
/// the handler sites call), then rebuild a fresh `AccountNode` via
/// `load_from_pg` and assert the imported account survived round-trip.
#[tokio::test]
async fn test_persist_and_load_from_pg_roundtrip() {
    // Shared Postgres container + per-test schema (issue #181 Opt B);
    // see `crate::test_db` for the design.
    let scope = crate::test_db::setup_pool().await;
    let pool = scope.pool.clone();
    crate::v1::claim_stack_scan_mode(&pool, crate::v1::ScanStackMode::Legacy)
        .await
        .expect("claim legacy stack for persist_account sink gate");

    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let address: HashDigest = digest_from_bytes(&[42u8; 32]);
    let asset_id = test_asset_id();
    let mut acct = Account::new_for_asset(asset_id);
    acct.balance = 11;
    node.import_account(address, acct);

    // Snapshot + upsert mirrors the handler-site pattern.
    let account_snapshot = node.get_account(&address, &asset_id).cloned_via_bincode();
    crate::account_node::persist_account(&pool, &address, &account_snapshot)
        .await
        .expect("persist_account ok");

    // Rebuild from PG and verify the row came back (keyed by the
    // 64-byte (owner, asset_id) composite). The prover is injected
    // (built once by the bootstrap in production) — see
    // `AccountNode::load_from_pg`.
    let loaded = AccountNode::load_from_pg(state_arc, &pool, None)
        .await
        .expect("load_from_pg ok");
    assert_eq!(loaded.get_account_balance(&address, &asset_id).unwrap(), 11);
}

/// `Account` does not implement `Clone` (its inner Plonky2 proof types
/// are sealed). The test above only needs an owned copy for the
/// persistence call, so bounce it through bincode locally. Kept as a
/// trait extension to keep the test body readable without polluting
/// the production `Account` API.
trait CloneViaBincode {
    fn cloned_via_bincode(self) -> Account;
}

impl CloneViaBincode for Option<&Account> {
    fn cloned_via_bincode(self) -> Account {
        let a = self.expect("account present");
        let bytes = bincode::serialize(a).expect("serialize");
        bincode::deserialize(&bytes).expect("deserialize")
    }
}

#[test]
fn test_assets_for_owner_empty_when_not_imported() {
    // Neutral model: there is no minting account to look up. An
    // unobserved owner simply holds no assets.
    let state_arc = Arc::new(Mutex::new(State::new()));
    let node = AccountNode::new(state_arc);
    let unknown: Address = digest_from_bytes(&[7u8; 32]);
    assert!(node.assets_for_owner(&unknown).is_empty());
}

#[test]
fn test_get_account_balance_returns_err_for_unknown_address() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let node = AccountNode::new(state_arc);
    let unknown: Address = digest_from_bytes(&[7u8; 32]);
    assert!(node
        .get_account_balance(&unknown, &test_asset_id())
        .is_err());
}

/// PR-A3 replacement for the previous `test_load_from_file_rejects_corrupted_bytes`:
/// plant a row whose `data` blob is not valid bincode and assert
/// `load_from_pg` surfaces the corruption as `LoadAccountNodeError
/// ::Deserialize` rather than panicking or silently dropping the row.
#[tokio::test]
async fn test_load_from_pg_rejects_corrupted_blob() {
    // Shared Postgres container + per-test schema (issue #181 Opt B);
    // see `crate::test_db` for the design.
    let scope = crate::test_db::setup_pool().await;
    let pool = scope.pool.clone();

    // 64-byte composite (owner||asset_id) key so the row passes the
    // length guard and the loader reaches the bincode-deserialize step.
    let bad_addr = vec![0xAAu8; 64];
    sqlx::query("INSERT INTO accounts (address, data) VALUES ($1, $2)")
        .bind(&bad_addr)
        .bind(b"not bincode".to_vec())
        .execute(&pool)
        .await
        .unwrap();

    let state_arc = Arc::new(Mutex::new(State::new()));
    // `AccountNode` is intentionally not `Debug`, so `expect_err`
    // isn't available; match the Result instead.
    match AccountNode::load_from_pg(state_arc, &pool, None).await {
        Ok(_) => panic!("expected deserialize error"),
        Err(err) => assert!(
            matches!(
                err,
                crate::account_node::LoadAccountNodeError::Deserialize(_)
            ),
            "unexpected: {:?}",
            err
        ),
    }
}

/// PR-A3 negative test: plant a row whose `address` column is not the
/// expected 64 bytes (composite `owner(32) || asset_id(32)` key) and
/// assert the loader surfaces the mismatch as
/// `LoadAccountNodeError::BadAddressLength`.
#[tokio::test]
async fn test_load_from_pg_rejects_wrong_address_length() {
    // Shared Postgres container + per-test schema (issue #181 Opt B);
    // see `crate::test_db` for the design.
    let scope = crate::test_db::setup_pool().await;
    let pool = scope.pool.clone();

    // The 0010 CHECK constraint `accounts_address_length` would
    // otherwise reject the wrong-length row at insert time, masking
    // the actual subject of this test: the Rust-side
    // `LoadAccountNodeError::BadAddressLength` defense in
    // `load_from_pg`. Drop the constraint inside this per-test
    // container so the corrupt-row plant succeeds. The 0008
    // `accounts_history_trigger` would also fail on the matching
    // `account_history_address_length` CHECK if it fired against
    // the 7-byte address, so disable the trigger for this test —
    // we are not exercising the history path here.
    sqlx::query("ALTER TABLE accounts DISABLE TRIGGER accounts_history_trigger")
        .execute(&pool)
        .await
        .expect("disable accounts_history_trigger");
    sqlx::query("ALTER TABLE accounts DROP CONSTRAINT accounts_address_length")
        .execute(&pool)
        .await
        .expect("drop accounts_address_length");

    sqlx::query("INSERT INTO accounts (address, data) VALUES ($1, $2)")
        .bind(vec![0u8; 7]) // wrong length
        .bind(b"anything".to_vec())
        .execute(&pool)
        .await
        .unwrap();

    let state_arc = Arc::new(Mutex::new(State::new()));
    match AccountNode::load_from_pg(state_arc, &pool, None).await {
        Ok(_) => panic!("expected bad-address length"),
        Err(err) => assert!(
            matches!(
                err,
                crate::account_node::LoadAccountNodeError::BadAddressLength(7)
            ),
            "unexpected: {:?}",
            err
        ),
    }
}

#[test]
fn test_send_coins_returns_err_for_unknown_account() {
    // Stage 3: `send_coins` is a refuse stub (legacy prove path deleted).
    // The loud Stage-3 message supersedes the old "Unknown account" arm.
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(state_arc);
    let account_data = TestAccountData::new_generic(&[1u8; 32], Network::Bitcoin);

    let recipient: Address = digest_from_bytes(&[2u8; 32]);
    let invoice = Invoice::new(1, recipient, test_asset_id());

    let current_pk = generate_test_public_key(&account_data.xpriv, 0);
    let next_pk = generate_test_public_key(&account_data.xpriv, 1);

    let result = node.send_coins(
        vec![invoice],
        account_data.address,
        current_pk,
        next_pk,
        None,
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("legacy send_coins deleted") || err.contains("Stage 3"),
        "send_coins must refuse loud after Stage 3; got {err}"
    );
}

#[test]
fn test_send_coins_returns_err_insufficient_funds() {
    // Stage 3: `send_coins` refuses before any funds check. Pin the
    // loud deletion message rather than the pre-cutover "Insufficient funds".
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(state_arc);
    let account_data = TestAccountData::new_generic(&[1u8; 32], Network::Bitcoin);
    node.import_account(
        account_data.address,
        Account::new_for_asset(test_asset_id()),
    );

    let recipient: Address = digest_from_bytes(&[2u8; 32]);
    let invoice = Invoice::new(100, recipient, test_asset_id());

    let current_pk = generate_test_public_key(&account_data.xpriv, 0);
    let next_pk = generate_test_public_key(&account_data.xpriv, 1);

    let result = node.send_coins(
        vec![invoice],
        account_data.address,
        current_pk,
        next_pk,
        None,
    );
    let err = result.unwrap_err();
    assert!(
        err.contains("legacy send_coins deleted") || err.contains("Stage 3"),
        "send_coins must refuse loud after Stage 3; got {err}"
    );
}

/// `warmup_prover` runs a synthetic `prove_initial` against a fresh
/// `AccountState` and discards the proof. It must return Ok on a
/// freshly-constructed `AccountNode` — that is the production
/// invariant: the same `Prover` will serve every subsequent
/// user-facing request, so a warmup failure means production requests
/// would also fail, and the bootstrap exits the process rather than
/// binding a listener that would serve 500s. This test exercises the
/// success arm. Kept in the default suite because the coverage gate
/// would otherwise treat the helper as unreached.
#[test]
fn warmup_prover_completes_successfully() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let node = AccountNode::new(Arc::clone(&state_arc));
    node.warmup_prover()
        .expect("warmup_prover must succeed on a fresh AccountNode");
}
