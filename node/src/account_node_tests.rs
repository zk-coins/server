use std::time::Instant;

use super::*;
use crate::state::State;
use bitcoin::{
    bip32::{ChildNumber, Xpriv, Xpub},
    key::Secp256k1,
    secp256k1::{All, PublicKey as BitcoinPublicKey, SecretKey},
    Network,
};
use lazy_static::lazy_static;
use shared::{commitment::Commitment, ProofData};
use zkcoins_program::hash::{
    digest_from_bytes, digest_to_bytes, hash_bytes, hash_concat, sha256_to_digest, ZERO_HASH,
};

lazy_static! {
    static ref SECP256K1_TEST_CTX: Secp256k1<All> = Secp256k1::new();
}

/// A deterministic, non-zero asset_id used across these prover-driven
/// fixtures now that there is no privileged native asset. Every test
/// account holds this single asset; send/receive route by it.
/// The asset every funded-sender fixture in this file mints and moves:
/// the asset DERIVED from the fixture creator key
/// (`TestAccountData::new_minting_account()`'s index-0 pubkey) with
/// name "TestCoin" / 8 decimals. Under the neutral model an asset_id is
/// not an arbitrary digest — it must equal
/// `calculate_asset_id(creator_pubkey, H(name), decimals)` for the
/// issuer gate to admit the mint that brings the balance into
/// existence. Deriving the shared test asset from the same key
/// [`mint_funded_asset`] mints with keeps every existing
/// invoice/assertion in this file consistent with the real provenance.
fn test_asset_id() -> AssetId {
    let secret = include_bytes!("../minting_secret.bin");
    let xpriv = Xpriv::new_master(Network::Bitcoin, secret)
        .expect("Failed to create private key for test asset derivation.");
    let pk0 = generate_test_public_key(&xpriv, 0).serialize();
    zkcoins_program::types::calculate_asset_id_from_name(&pk0, "TestCoin", 8)
}

/// Build an `Account` pre-seeded with `balance` of [`test_asset_id`].
/// Replaces the old centrally-minted account fixtures: under the
/// neutral model an account is just an `(owner, asset_id)` ledger, so a
/// test that needs a funded sender imports one of these directly
/// (the funds' provenance is irrelevant to the send-path under test).
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

fn derive_test_secret_key(private_key: &Xpriv, index: u32) -> SecretKey {
    private_key
        .derive_priv(&SECP256K1_TEST_CTX, &[ChildNumber::Normal { index }])
        .expect("Unable to derive private key for test")
        .private_key
}

struct TestAccountData {
    xpriv: Xpriv,
    address: Address,
    num_pubkeys: u32,
}

impl TestAccountData {
    /// A funded source account fixture. Under the neutral model there
    /// is no privileged minting account — this is just a generic
    /// account whose address is derived (like any wallet) from its
    /// first child pubkey. Tests that previously relied on the
    /// "minting account" semantics now treat it as an ordinary funded
    /// sender of [`test_asset_id`].
    fn new_minting_account() -> Self {
        let secret = include_bytes!("../minting_secret.bin");
        let xpriv = Xpriv::new_master(Network::Bitcoin, secret)
            .expect("Failed to create private key for source account.");
        let initial_pk_bytes = generate_test_public_key(&xpriv, 0).serialize().to_vec();
        // Address = H(Pk₀) = SHA-256(pubkey) per spec (#226), matching the
        // owner the node mint/account model now derives.
        let address = sha256_to_digest(&initial_pk_bytes);

        TestAccountData {
            xpriv,
            address,
            num_pubkeys: 0,
        }
    }

    fn new_generic(seed: &[u8; 32], network: Network) -> Self {
        let xpriv = Xpriv::new_master(network, seed)
            .expect("Failed to create private key for generic account.");

        let initial_pk_bytes = generate_test_public_key(&xpriv, 0).serialize().to_vec();
        // Address = H(Pk₀) = SHA-256(pubkey) per spec (#226).
        let address = sha256_to_digest(&initial_pk_bytes);

        TestAccountData {
            xpriv,
            address,
            num_pubkeys: 0,
        }
    }

    fn execute_send_coins(
        &mut self,
        node: &mut AccountNode,
        invoices: Vec<Invoice>,
    ) -> Result<Vec<CoinProof>, String> {
        let current_pk = generate_test_public_key(&self.xpriv, self.num_pubkeys);
        let next_pk = generate_test_public_key(&self.xpriv, self.num_pubkeys + 1);
        let prev_pk = if self.num_pubkeys > 0 {
            Some(generate_test_public_key(&self.xpriv, self.num_pubkeys - 1))
        } else {
            None
        };

        let mut coin_proofs =
            node.send_coins(invoices, self.address, current_pk, next_pk, prev_pk)?;

        // The key used for the commitment corresponds to current_pk
        let signing_secret_key = derive_test_secret_key(&self.xpriv, self.num_pubkeys);

        self.num_pubkeys += 1; // Increment after deriving signing key for current op, before it's used for next op

        for cp in &mut coin_proofs {
            // Plonky2 bridge: SP1's `proof.public_values: Vec<u8>` (bincode
            // blob) is replaced by `proof.public_inputs: Vec<F>` (Goldilocks
            // field elements). The first
            // `N_PROOF_DATA_PUBLIC_INPUTS = 20` slots reconstruct `ProofData`.
            let pis: [zkcoins_program::F;
                zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] = cp
                .proof
                .public_inputs[..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
                .try_into()
                .expect("Proof public_inputs too short");
            let proof_data = ProofData::from_field_elements(&pis);
            let commitment_hash_input = hash_concat(
                &proof_data.account_state_hash,
                &proof_data.output_coins_root,
            );
            cp.commitment = Some(
                Commitment::new(
                    &signing_secret_key,
                    digest_to_bytes(&commitment_hash_input).to_vec(),
                )
                .expect("Failed to create commitment for coin proof in test"),
            );
        }
        Ok(coin_proofs)
    }
}

/// Fund `acct`'s own `(owner, derived_asset_id)` account by running a
/// REAL issuer mint — the only legitimate way to bring a non-zero
/// balance into existence under the neutral model. A directly-seeded
/// `Account { balance, proof: None }` has no circuit provenance, so the
/// first `send`'s `prove_initial` (no in-coins, no `MintWitness`)
/// rejects it; minting produces a valid `account.proof` so the send
/// chains an AccountUpdate instead.
///
/// Drives the same prove → commit → state-advance → apply sequence as
/// `flow::{mint_flow, mint_commit_flow}`: builds the issuer-mint proof
/// (`prepare_mint`), signs the commitment with the creator key
/// (index 0 — the commit leg binds `commitment.public_key ==
/// creator_pubkey` off-circuit), advances the global SMT/MMR,
/// and installs the funded account (`commit_mint`). Bumps
/// `acct.num_pubkeys` to 1 (the mint consumed the index-0 creator key
/// as the commitment key and rotated `next_public_key` to index 1, so
/// the next `execute_send_coins` derives index 1). Returns the
/// DERIVED `asset_id` — callers must use it for that account's invoices
/// and assertions (it is not `test_asset_id()`).
fn mint_funded_asset(
    node: &mut AccountNode,
    state_arc: &Arc<Mutex<State>>,
    acct: &mut TestAccountData,
    name: &str,
    decimals: u8,
    amount: u64,
) -> AssetId {
    // `prepare_mint` re-derives owner/asset_id from the 33-byte
    // compressed bytes; `commit_mint` records the secp `PublicKey`
    // object as the account's commitment key. Keep both forms.
    let creator_pk_obj = generate_test_public_key(&acct.xpriv, 0);
    let creator_pk = creator_pk_obj.serialize();
    // The mint rotates to a fresh wallet key (index 1) so the creator's
    // first follow-up send commits under a fresh map key.
    let next_pk = generate_test_public_key(&acct.xpriv, 1).serialize();
    let prepared = node
        .prepare_mint(&creator_pk, name, decimals, amount, &next_pk)
        .expect("prepare_mint should succeed for a fresh issuer account");

    // Re-derive the hashes the creator signs (same path the commit leg
    // re-derives), build the creator-signed commitment, and advance the
    // global state with it before installing the account.
    let pis: [zkcoins_program::F; zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] =
        prepared.proof.public_inputs[..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
            .try_into()
            .expect("mint proof public_inputs too short");
    let pd = ProofData::from_field_elements(&pis);
    let commitment_hash_input = hash_concat(&pd.account_state_hash, &pd.output_coins_root);
    let secret = derive_test_secret_key(&acct.xpriv, 0);
    let commitment = Commitment::new(&secret, digest_to_bytes(&commitment_hash_input).to_vec())
        .expect("mint commitment");
    state_arc
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .update(std::slice::from_ref(&commitment))
        .expect("state.update for mint commitment");

    let asset_id = prepared.asset_id;
    node.commit_mint(prepared.owner, prepared.mutated_account, creator_pk_obj);
    // The mint consumed index 0 as the commitment key and rotated
    // `next_public_key` to index 1, so the next `execute_send_coins` on
    // this account derives index 1.
    acct.num_pubkeys = 1;
    asset_id
}

/// A second issuer mint into the SAME `(owner, asset_id)` account is
/// explicitly rejected: `prepare_mint`'s AccountUpdate branch does not
/// thread a `MintWitness` through the current circuit API, so it
/// refuses rather than silently proving a non-mint update the issuer
/// gate would not authorise. Covers the `Some(account_proof)` arm of
/// `prepare_mint` (the happy `None` arm is covered by every
/// [`mint_funded_asset`] caller).
#[test]
fn prepare_mint_rejects_remint_into_existing_asset_account() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(&mut node, &state_arc, &mut minting, "TestCoin", 8, 10_000);

    let creator_pk = generate_test_public_key(&minting.xpriv, 0).serialize();
    let next_pk = generate_test_public_key(&minting.xpriv, 1).serialize();
    let result = node.prepare_mint(&creator_pk, "TestCoin", 8, 5_000, &next_pk);
    assert_eq!(
        result.err(),
        Some("Re-mint into an existing asset account is not supported"),
    );
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
fn test_wallet_operations() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    mint_funded_asset(
        &mut node,
        &state_arc,
        &mut minting_account_data,
        "TestCoin",
        8,
        10_000,
    );
    // The funded source account is now an ordinary (owner, asset_id)
    // ledger — there is no privileged minting address to assert.
    assert_eq!(
        node.get_account_balance(&minting_account_data.address, &test_asset_id())
            .unwrap(),
        10_000
    );

    let mut account_1_data = TestAccountData::new_generic(&[1u8; 32], Network::Signet);
    let mut account_2_data = TestAccountData::new_generic(&[2u8; 32], Network::Signet);

    assert_eq!(
        node.get_account_balance(&minting_account_data.address, &test_asset_id())
            .unwrap(),
        10_000
    );
    assert!(node
        .get_account_balance(&account_1_data.address, &test_asset_id())
        .is_err());
    assert!(node
        .get_account_balance(&account_2_data.address, &test_asset_id())
        .is_err());

    // Note: Invoices use addresses.
    let account_2_invoice = Invoice::new(100, account_2_data.address, test_asset_id());
    let account_1_invoice = Invoice::new(100, account_1_data.address, test_asset_id());

    let mut coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![account_2_invoice, account_1_invoice])
        .unwrap();

    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();

    node.receive_coin(coin_proofs.pop().unwrap()) // Order might matter if tied to invoice order
        .expect("Unable to receive coin for account_1_invoice"); // Assuming account_1_invoice was last in vec or order doesn't strictly map here
    node.receive_coin(coin_proofs.pop().unwrap())
        .expect("Unable to receive coin for account_2_invoice");

    assert_eq!(
        node.get_account_balance(&account_1_data.address, &test_asset_id())
            .unwrap(),
        100
    );
    assert_eq!(
        node.get_account_balance(&account_2_data.address, &test_asset_id())
            .unwrap(),
        100
    );
    println!("Minting successful");

    let mut coin_proofs_from_acc2 = account_2_data
        .execute_send_coins(&mut node, vec![account_1_invoice]) // account_2 sends to account_1
        .expect("Unable to send coin from account_2");

    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs_from_acc2
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    // Balances before receiving the new coin by account_1
    assert_eq!(
        node.get_account_balance(&account_1_data.address, &test_asset_id())
            .unwrap(),
        100
    );
    assert_eq!(
        node.get_account_balance(&account_2_data.address, &test_asset_id())
            .unwrap(),
        0
    ); // account_2's balance reduced after send

    node.receive_coin(coin_proofs_from_acc2.pop().unwrap())
        .expect("Unable to receive coin by account_1 from account_2");
    assert_eq!(
        node.get_account_balance(&account_1_data.address, &test_asset_id())
            .unwrap(),
        200
    );
    assert_eq!(
        node.get_account_balance(&account_2_data.address, &test_asset_id())
            .unwrap(),
        0
    );

    // Send with timer
    let start_time = Instant::now();
    let mut coin_proofs_from_acc1 = account_1_data
        .execute_send_coins(&mut node, vec![account_2_invoice]) // account_1 sends to account_2
        .expect("Unable to send coin from account_1");
    let duration = start_time.elapsed();

    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs_from_acc1
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();
    println!("TIME ELAPSED FOR ONE RECURSIVE SEND: {:?}", duration);
    node.receive_coin(coin_proofs_from_acc1.pop().unwrap())
        .expect("Unable to receive coin by account_2 from account_1");
    assert_eq!(
        node.get_account_balance(&account_1_data.address, &test_asset_id())
            .unwrap(),
        100
    ); // 200 - 100
    assert_eq!(
        node.get_account_balance(&account_2_data.address, &test_asset_id())
            .unwrap(),
        100
    ); // 0 + 100
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

#[test]
fn test_mint_single_invoice() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    mint_funded_asset(
        &mut node,
        &state_arc,
        &mut minting_account_data,
        "TestCoin",
        8,
        10_000,
    );

    let account_1_data = TestAccountData::new_generic(&[1u8; 32], Network::Signet);
    let invoice = Invoice::new(100, account_1_data.address, test_asset_id());

    let coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![invoice])
        .expect("Mint with single invoice failed");

    assert_eq!(coin_proofs.len(), 1);
}

#[test]
fn test_receive_duplicate_coin_rejected() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    mint_funded_asset(
        &mut node,
        &state_arc,
        &mut minting_account_data,
        "TestCoin",
        8,
        10_000,
    );

    let account_1_data = TestAccountData::new_generic(&[1u8; 32], Network::Signet);
    let invoice = Invoice::new(100, account_1_data.address, test_asset_id());

    let coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![invoice])
        .expect("Mint failed");

    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();

    let coin_proof = coin_proofs.into_iter().next().unwrap();
    let duplicate = coin_proof.clone();

    // First receive should succeed
    node.receive_coin(coin_proof)
        .expect("First receive should succeed");

    // Second receive of the same coin should be rejected
    let result = node.receive_coin(duplicate);
    assert!(result.is_err(), "Duplicate coin receive must be rejected");
}

#[test]
fn test_receive_updates_balance() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    mint_funded_asset(
        &mut node,
        &state_arc,
        &mut minting_account_data,
        "TestCoin",
        8,
        10_000,
    );

    let account_1_data = TestAccountData::new_generic(&[1u8; 32], Network::Signet);
    let invoice = Invoice::new(250, account_1_data.address, test_asset_id());

    // Balance should not exist before any receive
    assert!(
        node.get_account_balance(&account_1_data.address, &test_asset_id())
            .is_err(),
        "Account should not exist before receiving coins"
    );

    let coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![invoice])
        .expect("Mint failed");

    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();

    for cp in coin_proofs {
        node.receive_coin(cp).expect("Receive should succeed");
    }

    // Balance should reflect the received coin amount
    let balance = node
        .get_account_balance(&account_1_data.address, &test_asset_id())
        .expect("Account should exist after receive");
    assert_eq!(
        balance, 250,
        "Balance should equal the received coin amount"
    );
}

/// Reproduces the exact configuration of /api/mint on the live DEV node:
/// recipient = raw [1u8; 32] bytes, amount = 1.
#[test]
fn test_mint_repro_live_setup() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    mint_funded_asset(
        &mut node,
        &state_arc,
        &mut minting_account_data,
        "TestCoin",
        8,
        1_000_000,
    );

    let recipient: Address = digest_from_bytes(&[1u8; 32]);
    let invoice = Invoice::new(1, recipient, test_asset_id());

    let coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![invoice])
        .expect("Mint repro failed");

    assert_eq!(coin_proofs.len(), 1);
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
    let loaded = AccountNode::load_from_pg(state_arc, &pool, Prover::new())
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
    match AccountNode::load_from_pg(state_arc, &pool, Prover::new()).await {
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
    match AccountNode::load_from_pg(state_arc, &pool, Prover::new()).await {
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
    assert_eq!(result.unwrap_err(), "Unknown account address");
}

#[test]
fn test_send_coins_returns_err_insufficient_funds() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(state_arc);
    let account_data = TestAccountData::new_generic(&[1u8; 32], Network::Bitcoin);
    // Key the empty account under the SAME asset the invoice moves —
    // accounts are per-(owner, asset_id) (Model B), so an account
    // imported under `ZERO_HASH` would miss the lookup and surface
    // "Unknown account address" instead of the funds check under test.
    // The insufficient-funds guard fires before any prove, so no mint
    // provenance is needed here.
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
    assert_eq!(result.unwrap_err(), "Insufficient funds");
}

#[test]
fn test_receive_coin_rejects_invalid_inclusion_proof() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    mint_funded_asset(
        &mut node,
        &state_arc,
        &mut minting_account_data,
        "TestCoin",
        8,
        10_000,
    );

    let recipient: Address = digest_from_bytes(&[1u8; 32]);
    let invoice = Invoice::new(100, recipient, test_asset_id());

    let mut coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![invoice])
        .expect("send_coins should succeed");

    // Tamper with the coin identifier so the existing inclusion proof
    // no longer verifies against it. receive_coin must reject.
    let mut coin_proof = coin_proofs.pop().unwrap();
    coin_proof.coin.identifier = digest_from_bytes(&[99u8; 32]);

    let result = node.receive_coin(coin_proof);
    assert_eq!(
        result.unwrap_err(),
        "Coin inclusion proof verification failed"
    );
}

#[test]
fn test_send_coins_twice_from_same_account_uses_update_account() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(&mut node, &state_arc, &mut minting, "TestCoin", 8, 10_000);

    let recipient: Address = digest_from_bytes(&[42u8; 32]);

    // The issuer mint already set `account.proof = Some` (and bumped
    // num_sends to 1), so BOTH of the following sends take the
    // AccountUpdate branch — the neutral model has no balance-without-a-
    // proof state for the create branch to fund a settled-balance send
    // from. (The send create/prove_initial branch is covered via the
    // receive-then-send flow in `test_wallet_operations`.)
    let coin_proofs_1 = minting
        .execute_send_coins(
            &mut node,
            vec![Invoice::new(100, recipient, test_asset_id())],
        )
        .expect("first send should succeed");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs_1
                .iter()
                .map(|cp| cp.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();

    // A second send from the same account also takes the
    // AccountUpdateProof branch (update_account).
    let coin_proofs_2 = minting
        .execute_send_coins(
            &mut node,
            vec![Invoice::new(50, recipient, test_asset_id())],
        )
        .expect("second send should succeed (update_account path)");
    assert_eq!(coin_proofs_2.len(), 1);

    // Invariant check: after the mint + two sends the three coupled
    // fields are all "updated" — `proof = Some`, `num_sends = 3` (one
    // bump per successful mint/send), and
    // `commitment_public_key = Some(pubkey_used_in_send_2)`. The
    // AccountUpdate branch reads this last value (not a caller
    // parameter) on the NEXT send, so its presence here is the
    // load-bearing post-condition.
    let acct = node
        .get_account(&minting.address, &test_asset_id())
        .expect("minting account still in map after send");
    assert!(
        acct.proof.is_some(),
        "account.proof must be Some after send"
    );
    assert_eq!(
        acct.num_sends, 3,
        "num_sends bumps once per successful mint + send_coins_inner"
    );
    let expected_cpk =
        generate_test_public_key(&minting.xpriv, minting.num_pubkeys.saturating_sub(1));
    assert_eq!(
        acct.commitment_public_key,
        Some(expected_cpk),
        "commitment_public_key holds the pubkey used in the most recent send"
    );
}

/// Regression: a second `send_coins` from an account whose
/// `account.proof = Some(...)` MUST succeed when the caller passes
/// `None` for `prev_commitment_pubkey` — the AccountUpdate branch
/// reads `account.commitment_public_key` from its own state instead
/// of consulting the caller-supplied parameter. Pre-refactor this
/// returned the 400-mapped error
/// `"prev_commitment_pubkey required for account update"`.
///
/// Live-server analogue is the api_remote test
/// `second_send_roundtrip_succeeds_without_prev_commitment_pubkey_field` —
/// this one drives the same code path through `account_node` directly
/// (no prover, no HTTP) so the contract is pinned even when the
/// `api_remote` suite is skipped (slim CI).
#[test]
fn test_send_coins_second_send_succeeds_without_prev_commitment_pubkey() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(&mut node, &state_arc, &mut minting, "TestCoin", 8, 10_000);

    let recipient: Address = digest_from_bytes(&[43u8; 32]);

    // First send: account.proof is None -> prove_initial branch.
    // The caller-supplied prev_commitment_pubkey is ignored on this
    // branch (it's only consulted on the AccountUpdate branch, and
    // post-refactor not even there); pass None to make that explicit.
    let coin_proofs_1 = minting
        .execute_send_coins(
            &mut node,
            vec![Invoice::new(100, recipient, test_asset_id())],
        )
        .expect("first send should succeed");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs_1
                .iter()
                .map(|cp| cp.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .unwrap();

    // Second send WITHOUT prev_commitment_pubkey. Pre-refactor this
    // returned `"prev_commitment_pubkey required for account update"`
    // and was mapped to 400 by `map_send_coins_error`. Post-refactor
    // the AccountUpdate branch reads `account.commitment_public_key`
    // (set atomically in the first send) and the prove succeeds.
    let current_pk = generate_test_public_key(&minting.xpriv, minting.num_pubkeys);
    let next_pk = generate_test_public_key(&minting.xpriv, minting.num_pubkeys + 1);
    let coin_proofs_2 = node
        .send_coins(
            vec![Invoice::new(50, recipient, test_asset_id())],
            minting.address,
            current_pk,
            next_pk,
            None, // <-- the contract under test: prev_commitment_pubkey omitted
        )
        .expect("second send must succeed without prev_commitment_pubkey");
    assert_eq!(coin_proofs_2.len(), 1);

    let acct = node
        .get_account(&minting.address, &test_asset_id())
        .expect("minting account still in map after send");
    // mint (1) + first send (2) + second send (3).
    assert_eq!(acct.num_sends, 3);
    assert_eq!(acct.commitment_public_key, Some(current_pk));
}

#[test]
fn test_receive_coin_rejects_replay_via_coin_history() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(&mut node, &state_arc, &mut minting, "TestCoin", 8, 10_000);
    let recipient: Address = digest_from_bytes(&[9u8; 32]);
    let coin_proofs = minting
        .execute_send_coins(
            &mut node,
            vec![Invoice::new(50, recipient, test_asset_id())],
        )
        .unwrap();
    let coin_proof = coin_proofs[0].clone();
    let coin_id = coin_proof.coin.identifier;

    // First receive — succeeds, coin lands in the recipient's coin_queue.
    node.receive_coin(coin_proof.clone()).unwrap();

    // Simulate the recipient having spent the coin: identifier goes
    // from coin_queue into coin_history.
    {
        let recipient_account = node
            .accounts
            .get_mut(&(recipient, test_asset_id()))
            .unwrap();
        recipient_account
            .coin_history
            .insert(digest_to_bytes(&coin_id), coin_id)
            .unwrap();
        recipient_account
            .coin_queue
            .retain(|cp| cp.coin.identifier != coin_id);
    }

    // Replay: receiving the same coin again must be rejected via the
    // coin_history check rather than the coin_queue check.
    let result = node.receive_coin(coin_proof);
    assert_eq!(result.unwrap_err(), "Coin already spent (replay)");
}

/// Stage 5d-next-5 Phase 2b negative regression: an in-coin whose
/// off-circuit `source_inclusion` siblings have been tampered with
/// must NOT make it to the prover. The defense-in-depth shim in
/// `send_coins` fast-fails with the documented error string;
/// without the shim the in-circuit SMT-inclusion check would still
/// reject, but only after a minute-scale prove.
///
/// Construction: do a real mint → recipient receive flow so that
/// the recipient's `account.coin_queue[0]` carries an HONEST
/// `inclusion_proof` produced by `out_coins_tree.generate_inclusion_proof`.
/// Then reach into the node's internal `accounts` map and flip
/// one sibling on the queued entry's `inclusion_proof`. The next
/// `send_coins` call from that recipient must surface the
/// "In-coin not present in source's output_coins_root" error.
#[test]
fn test_send_coins_rejects_tampered_source_proof_inclusion() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(&mut node, &state_arc, &mut minting, "TestCoin", 8, 10_000);

    // Real recipient with a deterministic seed; pin the address so
    // we can reach back into `node.accounts` after `receive_coin`.
    let recipient_data = TestAccountData::new_generic(&[42u8; 32], Network::Signet);
    let recipient_addr = recipient_data.address;

    // Mint emits one coin to the recipient — honest end-to-end flow,
    // so the `inclusion_proof` returned in `CoinProof` is well-formed
    // by construction.
    let mut coin_proofs = minting
        .execute_send_coins(
            &mut node,
            vec![Invoice::new(100, recipient_addr, test_asset_id())],
        )
        .expect("mint send_coins");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .expect("state.update");

    node.receive_coin(coin_proofs.pop().expect("at least one coin"))
        .expect("recipient receive_coin");

    // Tamper the queued `inclusion_proof.siblings[0]` directly on the
    // node's internal `accounts` map. The honest off-circuit
    // `source_inclusion.verify` walks the path siblings; flipping
    // the topmost sibling produces a recomputed root that doesn't
    // match the source's committed `output_coins_root`.
    {
        let account = node
            .accounts
            .get_mut(&(recipient_addr, test_asset_id()))
            .expect("recipient account present after receive_coin");
        assert_eq!(
            account.coin_queue.len(),
            1,
            "recipient has exactly one queued in-coin after a single mint"
        );
        account.coin_queue[0].inclusion_proof.siblings[0] = hash_bytes(b"tampered-sibling");
    }

    // The defense-in-depth off-circuit pre-check fires before the
    // expensive prove and surfaces the specific rejection string.
    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(
            1,
            digest_from_bytes(&[99u8; 32]),
            test_asset_id(),
        )],
        recipient_addr,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(
        result.unwrap_err(),
        "In-coin not present in source's output_coins_root",
        "tampered source-inclusion siblings must surface the off-circuit defense-in-depth rejection"
    );
}

/// Slot-count guard: `invoices.len() > MAX_OUT_COINS` fires at the
/// top of `send_coins` before the heavy in-coin loop and prove cost.
/// Empty account + (`MAX_OUT_COINS + 1`) invoices triggers it
/// without paying a prove.
#[test]
fn test_send_coins_rejects_too_many_invoices() {
    use zkcoins_program::circuit::main::MAX_OUT_COINS;
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));
    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(
        &mut node,
        &state_arc,
        &mut minting,
        "TestCoin",
        8,
        1_000_000,
    );

    let invoices: Vec<Invoice> = (0..(MAX_OUT_COINS + 1) as u8)
        .map(|i| Invoice::new(1, digest_from_bytes(&[i; 32]), test_asset_id()))
        .collect();

    let current_pk = generate_test_public_key(&minting.xpriv, minting.num_pubkeys);
    let next_pk = generate_test_public_key(&minting.xpriv, minting.num_pubkeys + 1);
    let result = node.send_coins(invoices, minting.address, current_pk, next_pk, None);
    assert_eq!(result.unwrap_err(), "Too many out-coins for one transition");
}

/// Slot-count guard: `account.coin_queue.len() > MAX_IN_COINS` fires
/// at the top of `send_coins` before the heavy in-coin loop and
/// prove cost. We mint one coin honestly (one Init prove), then
/// clone it `MAX_IN_COINS + 1` times into the recipient's
/// `coin_queue` and confirm send_coins fails fast.
#[test]
fn test_send_coins_rejects_too_many_coins_in_queue() {
    use zkcoins_program::circuit::main::MAX_IN_COINS;
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(&mut node, &state_arc, &mut minting, "TestCoin", 8, 10_000);
    let recipient_data = TestAccountData::new_generic(&[20u8; 32], Network::Signet);
    let recipient_addr = recipient_data.address;

    // One honest mint produces one valid CoinProof we can clone.
    let mut coin_proofs = minting
        .execute_send_coins(
            &mut node,
            vec![Invoice::new(100, recipient_addr, test_asset_id())],
        )
        .expect("mint send_coins");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .expect("state.update");

    let cp = coin_proofs.pop().expect("at least one coin");
    node.receive_coin(cp.clone())
        .expect("recipient receive_coin");

    // Force `coin_queue.len()` past the budget by cloning the single
    // honest entry. The slot-count guard fires before any siblings
    // are walked or any prove is attempted, so the clones being
    // identical doesn't matter.
    {
        let account = node
            .accounts
            .get_mut(&(recipient_addr, test_asset_id()))
            .expect("recipient account present after receive_coin");
        for _ in 0..MAX_IN_COINS {
            account.coin_queue.push(cp.clone());
        }
        assert!(
            account.coin_queue.len() > MAX_IN_COINS,
            "test fixture must overflow the in-coin slot budget"
        );
    }

    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(
            1,
            digest_from_bytes(&[99u8; 32]),
            test_asset_id(),
        )],
        recipient_addr,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(result.unwrap_err(), "Too many in-coins for one transition");
}

/// In-coin loop: a queued `CoinProof` whose `commitment.public_key`
/// is not registered in `state.commitment_proofs` makes
/// `get_merkle_proofs` return its "Unable to get merkle proofs..."
/// error string. Set up by minting → receiving WITHOUT calling
/// `state.update` first, so the recipient's queue entry references a
/// commitment public_key the state never indexed.
#[test]
fn test_send_coins_errors_when_state_lacks_commitment_for_in_coin() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(&mut node, &state_arc, &mut minting, "TestCoin", 8, 10_000);
    let recipient_data = TestAccountData::new_generic(&[21u8; 32], Network::Signet);
    let recipient_addr = recipient_data.address;

    let mut coin_proofs = minting
        .execute_send_coins(
            &mut node,
            vec![Invoice::new(75, recipient_addr, test_asset_id())],
        )
        .expect("mint send_coins");
    // Intentionally SKIP `state_arc.update(...)` — state never sees
    // the minting account's commitment, so get_merkle_proofs cannot
    // look up the commitment proof on the recipient's send_coins call.
    node.receive_coin(coin_proofs.pop().expect("at least one coin"))
        .expect("recipient receive_coin");

    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(
            1,
            digest_from_bytes(&[99u8; 32]),
            test_asset_id(),
        )],
        recipient_addr,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(
        result.unwrap_err(),
        "Unable to get merkle proofs for provided public key"
    );
}

/// AccountUpdate branch: when `account.proof = Some(...)` and the
/// account's stored `commitment_public_key` is for a commitment that
/// the state's commitment-proof index does not contain, the second
/// call to `get_merkle_proofs` (inside the AccountUpdate-prove
/// preparation) surfaces "Unable to get merkle proofs..." just like
/// the in-coin loop's call. Set up via one honest mint + receive +
/// state.update; then forge an `account.proof = Some(...)` plus a
/// `commitment_public_key` that is fresh and not indexed in the SMT.
///
/// As of the `Account::commitment_public_key` refactor the
/// AccountUpdate branch reads the previous commitment pubkey from the
/// account itself (not from a caller-supplied parameter), so the test
/// drives the failure through that field.
#[test]
fn test_send_coins_errors_when_state_lacks_commitment_for_prev_account_proof() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(&mut node, &state_arc, &mut minting, "TestCoin", 8, 10_000);
    let recipient_data = TestAccountData::new_generic(&[22u8; 32], Network::Signet);
    let recipient_addr = recipient_data.address;

    let mut coin_proofs = minting
        .execute_send_coins(
            &mut node,
            vec![Invoice::new(50, recipient_addr, test_asset_id())],
        )
        .expect("mint send_coins");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .expect("state.update");
    node.receive_coin(coin_proofs.pop().expect("at least one coin"))
        .expect("recipient receive_coin");

    // Forge an `account.proof = Some(...)` on the recipient by reusing
    // the minting account's proof we just produced (signature
    // verification doesn't happen on this path — `get_merkle_proofs`
    // only consults state for the commitment-pubkey lookup).
    //
    // To drive the "Unable to get merkle proofs..." error path we
    // also set the recipient's `commitment_public_key` to a fresh,
    // never-indexed pubkey. Post-refactor the AccountUpdate branch
    // reads THIS field (not a caller parameter) for the lookup, so
    // the unknown pubkey lives on the account itself.
    let stranger_seed = Xpriv::new_master(Network::Signet, &[99u8; 32]).expect("stranger xpriv");
    let unknown_commitment_pk = generate_test_public_key(&stranger_seed, 0);
    {
        let mint_account = node
            .accounts
            .get_mut(&(minting.address, test_asset_id()))
            .expect("minting account present");
        let proof = mint_account.proof.clone();
        let recipient_account = node
            .accounts
            .get_mut(&(recipient_addr, test_asset_id()))
            .expect("recipient account present after receive_coin");
        recipient_account.proof = proof;
        // Maintain the invariant documented on `Account`:
        // `proof.is_some() iff num_sends > 0 iff
        // commitment_public_key.is_some()`. Forging only `proof`
        // would leave an inconsistent shape that the balance handler
        // would mis-emit AND that the AccountUpdate branch would
        // panic on (the field's `expect` guards the invariant).
        recipient_account.num_sends = 1;
        recipient_account.commitment_public_key = Some(unknown_commitment_pk);
    }

    // Caller-supplied `prev_commitment_pubkey` is ignored by the
    // post-refactor server — pass `None` here to make that explicit.
    // The AccountUpdate branch reads the recipient's stored
    // `commitment_public_key` (the stranger pubkey installed above),
    // hits the SMT lookup miss, and surfaces "Unable to get merkle
    // proofs...". The HTTP mapping in `map_send_coins_error`
    // translates this to 422 (caller-fixable).
    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(
            1,
            digest_from_bytes(&[99u8; 32]),
            test_asset_id(),
        )],
        recipient_addr,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(
        result.unwrap_err(),
        "Unable to get merkle proofs for provided public key"
    );
}

#[test]
fn test_send_coins_rejects_coin_queue_entry_without_commitment() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(&mut node, &state_arc, &mut minting, "TestCoin", 8, 10_000);
    let recipient: Address = digest_from_bytes(&[10u8; 32]);
    let coin_proofs = minting
        .execute_send_coins(
            &mut node,
            vec![Invoice::new(50, recipient, test_asset_id())],
        )
        .unwrap();
    let mut coin_proof = coin_proofs[0].clone();
    // Strip the commitment so the next send attempt from the recipient
    // hits the "Coin is missing commitment" branch.
    coin_proof.commitment = None;

    node.receive_coin(coin_proof).unwrap();

    let mut recipient_data = TestAccountData::new_generic(&[10u8; 32], bitcoin::Network::Signet);
    // Force the test data to use the same address as the recipient.
    recipient_data.address = recipient;

    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(
            1,
            digest_from_bytes(&[11u8; 32]),
            test_asset_id(),
        )],
        recipient_data.address,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(result.unwrap_err(), "Coin is missing commitment");
}

/// In-coin loop: when the off-circuit pre-check at
/// `account_node.rs:419` rebuilds a source `CommitmentMerkleProofs`
/// whose `commitment_root_mmr_sibling` does not match the actual
/// MMR leaf for that source, `verify_commitment` returns false and
/// `send_coins` surfaces "Source commitment not present in history
/// MMR". This is the companion of
/// `test_send_coins_rejects_tampered_source_proof_inclusion`: it
/// closes the line-419 error branch the way the inclusion-proof
/// test closes the line-416 branch, and it is the off-circuit
/// defense-in-depth analogue of the in-circuit history-MMR check.
///
/// Construction: honest mint → `state.update` → recipient
/// `receive_coin`, so the recipient's `coin_queue[0]` carries a
/// well-formed `inclusion_proof` (line 416 passes) and the source
/// commitment is genuinely indexed in `state.smt` / `state.mmr`
/// (line-241 `get_mmr_inclusion_proof` lookup succeeds). Then
/// overwrite `state.prev_mmr_root` with `ZERO_HASH` directly. The
/// `get_merkle_proofs` builder reads that field verbatim into
/// `commitment_root_mmr_sibling`, so the source CMP recomputes a
/// leaf `hash_concat(commitment_root, ZERO_HASH)` that does not
/// appear in `state.mmr`. The genuine MMR proof is still threaded
/// through, so the recomputed root mismatches the actual history
/// root and only the MMR half of `verify_commitment` rejects —
/// leaving the line-416 SMT-out_coins-inclusion path untouched,
/// which is exactly the branch line 419 is meant to gate.
#[test]
fn test_send_coins_rejects_source_commitment_missing_from_history_mmr() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(&mut node, &state_arc, &mut minting, "TestCoin", 8, 10_000);

    let recipient_data = TestAccountData::new_generic(&[43u8; 32], Network::Signet);
    let recipient_addr = recipient_data.address;

    let mut coin_proofs = minting
        .execute_send_coins(
            &mut node,
            vec![Invoice::new(100, recipient_addr, test_asset_id())],
        )
        .expect("mint send_coins");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .expect("state.update");

    node.receive_coin(coin_proofs.pop().expect("at least one coin"))
        .expect("recipient receive_coin");

    // Desync `state.prev_mmr_root` from the actual history-MMR
    // leaf. `get_merkle_proofs` writes this verbatim into source
    // CMP's `commitment_root_mmr_sibling`, so the off-circuit
    // `verify_commitment_root` recomputes a leaf that doesn't
    // appear in `state.mmr` — without touching the out-coins SMT
    // inclusion path that line 416 gates.
    {
        let mut state = state_arc.lock().unwrap();
        state.prev_mmr_root = ZERO_HASH;
    }

    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(
            1,
            digest_from_bytes(&[99u8; 32]),
            test_asset_id(),
        )],
        recipient_addr,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(
        result.unwrap_err(),
        "Source commitment not present in history MMR",
        "desynced `state.prev_mmr_root` must surface the off-circuit history-MMR rejection at account_node.rs:419",
    );
}

/// `warmup_prover` runs a synthetic `prove_initial` against a fresh
/// `AccountState` and discards the proof. It must return Ok on a
/// freshly-constructed `AccountNode` — that is the production
/// invariant: the same `Prover` will serve every subsequent
/// user-facing request, so a warmup failure means production requests
/// would also fail, and the bootstrap exits the process rather than
/// binding a listener that would serve 500s. This test exercises the
/// success arm. Pinned `#[ignore]`-able via cargo flags but kept in
/// the default suite because the coverage gate would otherwise treat
/// the helper as unreached.
#[test]
fn warmup_prover_completes_successfully() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let node = AccountNode::new(Arc::clone(&state_arc));
    node.warmup_prover()
        .expect("warmup_prover must succeed on a fresh AccountNode");
}

/// Pins the **queue-only** shape produced by the production mint /
/// receive paths: the credited coin lives in `Account.coin_queue` while
/// `Account.balance` remains `0` until a subsequent send drains the
/// queue. `router::balance_from_account_blob` must mirror
/// `Account::get_balance()` and surface the sum, otherwise the
/// `/api/history` row for a first mint reports `amount = 0` (the bug
/// the `history_after_mint_records_mint_row` E2E flagged on PR #166).
///
/// Lives in `account_node_tests` because constructing a realistic
/// `CoinProof` requires the full prover + state fixtures — the lighter
/// settled-balance shape (`balance > 0, coin_queue == []`) is still
/// covered in `router_tests::history_row_to_item_handles_first_row_with_no_prev_data`.
#[test]
fn history_row_to_item_balance_from_coin_queue_only() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting = TestAccountData::new_minting_account();
    mint_funded_asset(
        &mut node,
        &state_arc,
        &mut minting,
        "TestCoin",
        8,
        1_000_000,
    );

    let recipient = TestAccountData::new_generic(&[42u8; 32], Network::Signet);
    const MINT_AMOUNT: u64 = 50_000;

    // Mint flow: the minting account sends MINT_AMOUNT to a fresh
    // recipient. `receive_coin` then pushes the resulting `CoinProof`
    // into the recipient's `coin_queue` without touching `balance` —
    // this is the exact write `commit_mint_tx` produces for a real
    // first-mint history row.
    let mut coin_proofs = minting
        .execute_send_coins(
            &mut node,
            vec![Invoice::new(
                MINT_AMOUNT,
                recipient.address,
                test_asset_id(),
            )],
        )
        .expect("mint send_coins");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .expect("state.update");
    node.receive_coin(coin_proofs.pop().expect("at least one coin"))
        .expect("recipient receive_coin");

    let recipient_account = node
        .accounts
        .get(&(recipient.address, test_asset_id()))
        .expect("recipient account present after receive_coin");
    assert_eq!(
        recipient_account.balance, 0,
        "settled balance is still 0 — the credit sits in coin_queue"
    );
    assert_eq!(
        recipient_account.coin_queue.len(),
        1,
        "exactly one queued coin"
    );
    assert_eq!(recipient_account.coin_queue[0].coin.amount, MINT_AMOUNT);

    // Direct helper assertion: balance_from_account_blob must include
    // the queue contribution.
    let new_data = bincode::serialize(recipient_account).expect("bincode serialize");
    assert_eq!(
        crate::router::balance_from_account_blob(&new_data),
        Some(MINT_AMOUNT),
        "balance_from_account_blob must sum balance + coin_queue (mirrors Account::get_balance)"
    );

    // End-to-end through history_row_to_item: a first mint row
    // (prev_data = None) must surface `amount = MINT_AMOUNT`.
    let row = crate::db::AccountHistoryRow {
        id: 7,
        timestamp_secs: 1_700_000_000,
        source: "mint".to_string(),
        prev_data: None,
        new_data,
        commit_txid: None,
        block_height: None,
        pending_status: None,
        commit_output_value: None,
    };
    let item = crate::router::history_row_to_item(&row).expect("item produced");
    assert_eq!(item.id, 7);
    assert_eq!(item.direction, "mint");
    assert_eq!(
        item.amount, MINT_AMOUNT,
        "first mint must surface the full credit (regression: was 0 when balance_from_account_blob read only Account.balance)"
    );
}

/// Covers the in-coin asset guard's **queue branch** in
/// `send_coins_inner` (a coin already sitting in `account.coin_queue`
/// whose `asset_id` differs from the transition asset). The sibling
/// `send_coins_rejects_mixed_asset_invoices` exercises the *invoices*
/// branch; this one mints a NATIVE coin into a recipient's queue and
/// then attempts to send a NON-native invoice, so the transition asset
/// (taken from the invoice) mismatches the queued coin. The guard must
/// reject before any prove is attempted.
#[test]
fn send_coins_rejects_queued_coin_with_foreign_asset() {
    let state_arc = Arc::new(Mutex::new(State::new()));
    let mut node = AccountNode::new(Arc::clone(&state_arc));

    let mut minting_account_data = TestAccountData::new_minting_account();
    mint_funded_asset(
        &mut node,
        &state_arc,
        &mut minting_account_data,
        "TestCoin",
        8,
        10_000,
    );

    // Send a TestCoin coin to a fresh recipient and let them receive it,
    // so the recipient's `(recipient, TestCoin)` account holds one
    // TestCoin coin in its queue.
    let recipient_data = TestAccountData::new_generic(&[7u8; 32], Network::Signet);
    let invoice = Invoice::new(100, recipient_data.address, test_asset_id());
    let mut coin_proofs = minting_account_data
        .execute_send_coins(&mut node, vec![invoice])
        .expect("mint send_coins");
    state_arc
        .lock()
        .unwrap()
        .update(
            &coin_proofs
                .iter()
                .map(|x| x.commitment.clone().unwrap())
                .collect::<Vec<_>>(),
        )
        .expect("state.update");
    // Keep a clone of the received coin proof, but re-stamp its asset_id
    // to a FOREIGN asset. Under Model B `receive_coin` routes a coin to
    // its own `(recipient, asset_id)` account, so a foreign coin can
    // never land in a TestCoin account's queue through the normal path —
    // the queue-branch guard is defense-in-depth for a state that the
    // routing makes unreachable. We inject it directly to drive the
    // guard.
    let mut foreign_cp = coin_proofs[0].clone();
    foreign_cp.coin.asset_id = hash_bytes(b"foreign-asset");
    node.receive_coin(coin_proofs.pop().expect("one coin"))
        .expect("recipient receive_coin");
    node.accounts
        .get_mut(&(recipient_data.address, test_asset_id()))
        .expect("recipient TestCoin account present after receive")
        .coin_queue
        .push(foreign_cp);

    // Send a TestCoin invoice from the recipient: transition_asset_id =
    // TestCoin, the account is found, but the manually-injected foreign
    // coin in the queue mismatches the transition asset, so the
    // queue-branch guard rejects before any prove.
    let current_pk = generate_test_public_key(&recipient_data.xpriv, 0);
    let next_pk = generate_test_public_key(&recipient_data.xpriv, 1);
    let result = node.send_coins(
        vec![Invoice::new(
            1,
            digest_from_bytes(&[9u8; 32]),
            test_asset_id(),
        )],
        recipient_data.address,
        current_pk,
        next_pk,
        None,
    );
    assert_eq!(result.unwrap_err(), "Mixed assets in single transition");
}
