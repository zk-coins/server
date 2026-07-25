//! Generates `shared/tests/generated_poseidon_vectors.txt` from the live
//! Poseidon/`Hc` primitives (V.4 `<REGEN>` table).
//!
//! Values are **computed**, never hand-copied. Re-run with `cargo test -p shared`
//! to refresh the file.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use sha2::{Digest, Sha256};
use shared::spec_v1::{
    account_state_hash, address, asset_id_v1, asset_id_v2, coinhist_empty_root,
    coinhist_root_after_first_insert, coin_identifier, detect_tag, digest_to_bytes, hash_proof_data,
    merkle_root, name_hash, nav_commitment, network_id_mainnet, network_id_regtest,
    network_id_testnet, nflog_empty, nflog_root, nk_commit, npk_commit, nullifier,
    serialize_proof_data, terms_hash_v1, terms_hash_v2, AccountState, Address, CoinHistState,
    ProofData, TreeKind, GENESIS_TAG,
};

fn sha256_label(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

fn hex32(bytes: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn hex_digest(d: &shared::spec_v1::HashDigest) -> String {
    hex32(&digest_to_bytes(d))
}

#[test]
fn generate_poseidon_vectors_file() {
    let pk0 = sha256_label("zkCoins/v1/test-vector/Pk0");
    let pk1 = sha256_label("zkCoins/v1/test-vector/Pk1");
    let nk = sha256_label("zkCoins/v1/test-vector/nk");
    let npk_rand = sha256_label("zkCoins/v1/test-vector/npk_rand");
    let nav_rand = sha256_label("zkCoins/v1/test-vector/nav_rand");
    // Independent SHA-256 pin (sanity check before further use).
    assert_eq!(
        hex::encode(nav_rand),
        "e3b0e624bff8dbe486dd0761c14dcb84b4ccaf026fc60c58b69d653e6f656560"
    );
    let terms_salt = sha256_label("zkCoins/v1/test-vector/terms_salt");
    let name_hash_usd = name_hash(b"USD-Demo").expect("USD-Demo name ok");
    let name_hash_eur = name_hash(b"EUR-Demo").expect("EUR-Demo name ok");
    let npk_commit_0 = npk_commit(&pk1, &npk_rand);
    assert_eq!(
        hex::encode(npk_commit_0),
        "7d014dfd4b58080f7a68124ef28936c8da039135a8b7e0b25ce14e287e6d7026"
    );

    // 1
    let nflog_empty_v = nflog_empty();
    assert_eq!(
        hex_digest(&nflog_empty_v),
        "0xf7599780b12dc6120b6e305e77feb04d1db533fbeb19f3fd25ca22b5b222c2bc",
        "V.4 anchor pin: nflog_empty regressed"
    );
    // 2
    let coinhist_empty = coinhist_empty_root();
    assert_eq!(
        hex_digest(&coinhist_empty),
        "0x7d558733b6f685d85aff62341e3d017234056105bced89ce0319166dc90a6dcf",
        "V.4 anchor pin: coinhist_empty_root regressed"
    );
    // 3
    let nk_commit_sample = nk_commit(&nk);
    assert_eq!(
        hex_digest(&nk_commit_sample),
        "0x444981ebd6edc1116dc1a13d51e7ed2c47988cc66ad5fb95c12de4f2efa4456e",
        "V.4 anchor pin: nk_commit_sample regressed"
    );
    // 4
    let asset_id = asset_id_v1(GENESIS_TAG, &pk0, &name_hash_usd, 2, 1);
    // 5
    let addr_bytes = address(&pk0, nk_commit_sample);
    let addr = Address(addr_bytes);
    // 6
    let zk_bech32m = addr.to_bech32m();
    // 7 — canonical empty account (§2.2)
    let ash_empty = account_state_hash(
        &AccountState::new(
            addr,
            nk_commit_sample,
            BTreeMap::new(),
            pk0,
            0,
            coinhist_empty,
        )
        .expect("empty account"),
    )
    .expect("hash empty account");
    assert_eq!(
        hex_digest(&ash_empty),
        "0xef56b9ac8dc7a119c9d2679164b91f341d785e9649470158c2661cfd4f71b61b",
        "V.4 anchor pin: ash_empty regressed"
    );
    // 8
    let coin_identifier_0 =
        coin_identifier(ash_empty, &addr_bytes, asset_id, 1_000_000_000u128, 0u32);
    // 9
    let coin_history_root_0 = coinhist_root_after_first_insert(
        &digest_to_bytes(&coin_identifier_0),
        CoinHistState::Admitted,
    );
    // 10 — account after first transition
    let mut balances = BTreeMap::new();
    balances.insert(digest_to_bytes(&asset_id), 1_000_000_000u128);
    let ash_0 = account_state_hash(
        &AccountState::new(
            addr,
            nk_commit_sample,
            balances,
            pk1,
            1,
            coin_history_root_0,
        )
        .expect("ash_0 account"),
    )
    .expect("hash ash_0 account");
    // 11
    let nf_sample = nullifier(&nk, coin_identifier_0);
    // 12
    let ocr_0 = merkle_root(TreeKind::CoinsRoot, &[coin_identifier_0]);
    // 13
    let inr_0 = merkle_root(TreeKind::NullifiersRoot, &[]);
    // 14
    let nav_root_empty = nflog_root(0, nflog_empty_v);
    // 15
    let nav_commitment_0 = nav_commitment(nav_root_empty, &nav_rand);
    assert_eq!(
        hex_digest(&nav_commitment_0),
        "0xeec40cabb6cece9f2c76cd3fde2f55c2bf193def66c4482bd94f1cb44acbe34d",
        "V.4 anchor pin: nav_commitment_0 regressed"
    );
    // 16
    let h_proof_data_0 = hash_proof_data(&serialize_proof_data(&ProofData {
        new_account_state_hash: ash_0,
        output_coins_root: ocr_0,
        input_nullifiers_root: inr_0,
        coin_history_root: coin_history_root_0,
        nav_commitment: nav_commitment_0,
        npk_commit: npk_commit_0,
    }));
    // 17
    let network_id_mainnet_v = network_id_mainnet();
    assert_eq!(
        hex_digest(&network_id_mainnet_v),
        "0xfb5080433fbd3d5c9ed7aad0e1feced2954859c4492ecb0880b0713f6b09ec8c",
        "V.4 anchor pin: network_id_mainnet regressed"
    );
    let network_id_testnet_v = network_id_testnet();
    let network_id_regtest_v = network_id_regtest();
    // 18 — V.10 note-encryption fixture pins (spec V.10; fully pinned SHA-256/HKDF/secp256k1)
    // ss  = ECDH(esk, IVPK) = x(esk·lift_x(IVPK))
    // epk = x-only(esk·G)
    let v10_ss: [u8; 32] = hex::decode(
        "842f5821fa577c0374ae48e4c5afa887e3e0900df7245370e5675d88466fa05f",
    )
    .expect("V.10 ss hex")
    .try_into()
    .expect("V.10 ss is 32 bytes");
    let v10_epk: [u8; 32] = hex::decode(
        "e15129c95c4e7528810d91bdc9312389a1c6466bee0237147540c426926af154",
    )
    .expect("V.10 epk hex")
    .try_into()
    .expect("V.10 epk is 32 bytes");
    let detect_tag_fixture = detect_tag(&v10_ss, &v10_epk);
    // 19
    let asset_id_v2_v = asset_id_v2(
        GENESIS_TAG,
        &pk0,
        &name_hash_eur,
        2,
        2,
        500_000_000u128,
        &terms_salt,
    );
    // 20
    let terms_hash_v1_v = terms_hash_v1(asset_id, 1);
    // 21
    let terms_hash_v2_v = terms_hash_v2(asset_id_v2_v, 2, 500_000_000u128, &terms_salt);

    let mut lines = Vec::new();
    lines.push(format!("nflog_empty = {}", hex_digest(&nflog_empty_v)));
    lines.push(format!(
        "coinhist_empty_root = {}",
        hex_digest(&coinhist_empty)
    ));
    lines.push(format!(
        "nk_commit_sample = {}",
        hex_digest(&nk_commit_sample)
    ));
    lines.push(format!("asset_id = {}", hex_digest(&asset_id)));
    lines.push(format!("address = {}", hex32(&addr_bytes)));
    lines.push(format!("zk_bech32m = {zk_bech32m}"));
    lines.push(format!("ash_empty = {}", hex_digest(&ash_empty)));
    lines.push(format!(
        "coin_identifier_0 = {}",
        hex_digest(&coin_identifier_0)
    ));
    lines.push(format!(
        "coin_history_root_0 = {}",
        hex_digest(&coin_history_root_0)
    ));
    lines.push(format!("ash_0 = {}", hex_digest(&ash_0)));
    lines.push(format!("nf_sample = {}", hex_digest(&nf_sample)));
    lines.push(format!("ocr_0 = {}", hex_digest(&ocr_0)));
    lines.push(format!("inr_0 = {}", hex_digest(&inr_0)));
    lines.push(format!(
        "nav_root_empty = {}",
        hex_digest(&nav_root_empty)
    ));
    lines.push(format!(
        "nav_commitment_0 = {}",
        hex_digest(&nav_commitment_0)
    ));
    lines.push(format!(
        "h_proof_data_0 = {}",
        hex32(&h_proof_data_0)
    ));
    lines.push(format!(
        "network_id_mainnet = {}",
        hex_digest(&network_id_mainnet_v)
    ));
    lines.push(format!(
        "network_id_testnet = {}",
        hex_digest(&network_id_testnet_v)
    ));
    lines.push(format!(
        "network_id_regtest = {}",
        hex_digest(&network_id_regtest_v)
    ));
    lines.push(format!(
        "detect_tag_fixture = {}",
        hex_digest(&detect_tag_fixture)
    ));
    lines.push(format!("asset_id_v2 = {}", hex_digest(&asset_id_v2_v)));
    lines.push(format!(
        "terms_hash_v1 = {}",
        hex_digest(&terms_hash_v1_v)
    ));
    lines.push(format!(
        "terms_hash_v2 = {}",
        hex_digest(&terms_hash_v2_v)
    ));
    lines.push(String::new()); // trailing newline

    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/generated_poseidon_vectors.txt"
    ));
    fs::write(&path, lines.join("\n")).expect("write generated_poseidon_vectors.txt");

    // File must exist and contain every label.
    let written = fs::read_to_string(&path).expect("read back vectors file");
    for label in [
        "nflog_empty",
        "coinhist_empty_root",
        "nk_commit_sample",
        "asset_id",
        "address",
        "zk_bech32m",
        "ash_empty",
        "coin_identifier_0",
        "coin_history_root_0",
        "ash_0",
        "nf_sample",
        "ocr_0",
        "inr_0",
        "nav_root_empty",
        "nav_commitment_0",
        "h_proof_data_0",
        "network_id_mainnet",
        "network_id_testnet",
        "network_id_regtest",
        "detect_tag_fixture",
        "asset_id_v2",
        "terms_hash_v1",
        "terms_hash_v2",
    ] {
        assert!(
            written.contains(label),
            "generated file missing label {label}"
        );
    }
}
