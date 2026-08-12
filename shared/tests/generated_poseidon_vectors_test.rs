//! Generates / verifies `shared/tests/generated_poseidon_vectors.txt` from the
//! live Poseidon/`Hc` primitives (V.4 `<REGEN>` table), the V.10 note-encryption
//! envelope preimages (`coin_bytes` / `coin_plain`), and the V.12 NameConsent
//! framing vector.
//!
//! Values are **computed**, never hand-copied.
//!
//! ## CI / default
//!
//! Without an env var the test **verifies** live digests against the committed
//! file and fails on drift. Local regen (writes the vector file):
//! `REGEN_POSEIDON_VECTORS=1 cargo test -p shared --test generated_poseidon_vectors_test -- --nocapture`

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use shared::spec_v1::{
    account_state_hash, address, asset_id_v1, asset_id_v2, coin_identifier, coinhist_empty_root,
    coinhist_root_after_first_insert, detect_tag, digest_to_bytes, hash_proof_data, merkle_root,
    name_consent_preimage, name_hash, name_message, nav_commitment, network_id_mainnet,
    network_id_regtest, network_id_testnet, nflog_empty, nflog_root, nk_commit, npk_commit,
    nullifier, serialize_coin, serialize_proof_data, terms_hash_v1, terms_hash_v2, AccountState,
    Address, Coin, CoinHistState, ProofData, TreeKind, GENESIS_TAG,
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

fn hex_bytes(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

/// V.2-ext `op` secret (`m/1798'/0'/2'`) — pinned in the spec V.2-ext table.
const V2EXT_OP_SECRET_HEX: &str =
    "6516c985b442d51f1e91760c9327a593ddcb7fe06b363aa5b2b8547cc61d7395";
/// Expected BIP-340 x-only public key for the V.2-ext `op` secret (sanity pin).
const V2EXT_OP_PUBKEY_HEX: &str =
    "6424b41eea59c6a3aa6169b802c96ff5194962d3bf5f941130e4ebc86de3b485";

fn parse_hex32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).unwrap_or_else(|e| {
        panic!("fixture hex decode failed for {hex_str}: {e}");
    });
    <[u8; 32]>::try_from(bytes.as_slice()).unwrap_or_else(|_| {
        panic!(
            "fixture must be 32 bytes, got {} for {hex_str}",
            bytes.len()
        );
    })
}

/// BIP-340 x-only public key from a 32-byte secret (even-y normalisation).
fn xonly_from_secret(secret_hex: &str) -> [u8; 32] {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&parse_hex32(secret_hex))
        .unwrap_or_else(|e| panic!("V.2-ext secret is not a valid secp256k1 key: {e}"));
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    xonly.serialize()
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
    // 8 — V.4 `coin.identifier@0`: amount is the V.3 supply (1_000_000_000).
    let amount_0 = 1_000_000_000u128;
    let coin_identifier_0 = coin_identifier(ash_empty, &addr_bytes, asset_id, amount_0, 0u32);
    // 9
    let coin_history_root_0 = coinhist_root_after_first_insert(
        &digest_to_bytes(&coin_identifier_0),
        CoinHistState::Admitted,
    );
    // 10 — account after first transition
    let mut balances = BTreeMap::new();
    balances.insert(digest_to_bytes(&asset_id), amount_0);
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
    let v10_ss: [u8; 32] =
        hex::decode("842f5821fa577c0374ae48e4c5afa887e3e0900df7245370e5675d88466fa05f")
            .expect("V.10 ss hex")
            .try_into()
            .expect("V.10 ss is 32 bytes");
    let v10_epk: [u8; 32] =
        hex::decode("e15129c95c4e7528810d91bdc9312389a1c6466bee0237147540c426926af154")
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

    // 22 — V.12 NameConsent framing (spec §4.3): V.2-ext op_pubkey, network=regtest,
    //      name=alice@example.com → 82-byte preimage + SHA-256 digest.
    // 22 — V.12 name-consent framing. Inputs: V.2-ext (sk₀, pk0, op_pubkey),
    // network = "regtest", name = alice@example.com. op_pubkey is derived from
    // the pinned V.2-ext `op` secret (BIP-340 x-only), not hand-copied.
    let v12_op_pubkey = xonly_from_secret(V2EXT_OP_SECRET_HEX);
    assert_eq!(
        hex::encode(v12_op_pubkey),
        V2EXT_OP_PUBKEY_HEX,
        "V.2-ext op → op_pubkey x-only derivation regressed"
    );
    let v12_preimage = name_consent_preimage("regtest", "alice@example.com", &v12_op_pubkey)
        .expect("V.12 NameConsent preimage");
    assert_eq!(
        v12_preimage.len(),
        82,
        "V.12 preimage must be 22+7+4+17+32 = 82 bytes"
    );
    let v12_name_message =
        name_message("regtest", "alice@example.com", &v12_op_pubkey).expect("V.12 name_message");
    println!("name_consent_preimage = {}", hex_bytes(&v12_preimage));
    println!("name_message = {}", hex32(&v12_name_message));

    // 23 — V.10 envelope preimages: fixture Coin is exactly V.4 coin.identifier@0
    //      (same identifier, recipient=address, amount, asset_id). serialize_coin
    //      is the sole layout source (32 ‖ 32 ‖ 16-be ‖ 32 = 112). coin_plain is
    //      the NIP44Binary UTF-8 plaintext under K_tx (label "coin").
    let fixture_coin = Coin {
        identifier: coin_identifier_0,
        recipient: addr,
        amount: amount_0,
        asset_id,
    };
    let coin_bytes = serialize_coin(&fixture_coin);
    assert_eq!(
        coin_bytes.len(),
        112,
        "serialize(Coin) must be 112 bytes (identifier32 ‖ recipient32 ‖ amount16 ‖ asset_id32)"
    );
    let coin_plain = format!("zkcoins-bin-v1:coin:{}", URL_SAFE_NO_PAD.encode(coin_bytes));
    println!("coin_bytes = {}", hex_bytes(&coin_bytes));
    println!("coin_plain = {coin_plain}");

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
    lines.push(format!("nav_root_empty = {}", hex_digest(&nav_root_empty)));
    lines.push(format!(
        "nav_commitment_0 = {}",
        hex_digest(&nav_commitment_0)
    ));
    lines.push(format!("h_proof_data_0 = {}", hex32(&h_proof_data_0)));
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
    lines.push(format!("terms_hash_v1 = {}", hex_digest(&terms_hash_v1_v)));
    lines.push(format!("terms_hash_v2 = {}", hex_digest(&terms_hash_v2_v)));
    lines.push(format!(
        "name_consent_preimage = {}",
        hex_bytes(&v12_preimage)
    ));
    lines.push(format!("name_message = {}", hex32(&v12_name_message)));
    lines.push(format!("coin_bytes = {}", hex_bytes(&coin_bytes)));
    lines.push(format!("coin_plain = {coin_plain}"));
    lines.push(String::new()); // trailing newline

    let generated = lines.join("\n");

    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/generated_poseidon_vectors.txt"
    ));

    // Default: verify the committed file matches live digests.
    // REGEN_POSEIDON_VECTORS=1: rewrite the file (after a real primitive change).
    let regen = matches!(std::env::var("REGEN_POSEIDON_VECTORS").as_deref(), Ok("1"));
    if regen {
        fs::write(&path, &generated).expect("write generated_poseidon_vectors.txt");
        println!("REGEN: wrote {}", path.display());
    } else {
        let committed = fs::read_to_string(&path).unwrap_or_else(|e| {
            panic!(
                "cannot read committed poseidon vectors file {}: {e} \
                 (set REGEN_POSEIDON_VECTORS=1 to create it)",
                path.display()
            )
        });
        assert_eq!(
            committed, generated,
            "live Poseidon/V.12 digests diverge from committed generated_poseidon_vectors.txt — \
             either a domain tag / Hc encoding / NameConsent framing changed \
             (run with REGEN_POSEIDON_VECTORS=1 and commit) \
             or the generator no longer matches the production primitives"
        );
        println!("verified {} matches live primitives", path.display());
    }

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
        "name_consent_preimage",
        "name_message",
        "coin_bytes",
        "coin_plain",
    ] {
        assert!(
            written.contains(label),
            "generated file missing label {label}"
        );
    }
}
