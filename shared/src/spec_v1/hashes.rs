//! Derivation functions built on `Hc` and the SHA-256 boundary helpers.
//!
//! Poseidon (`Hc`) call sites follow the §1.7.3 encoding classification table
//! exactly. SHA-256 sites use plain byte concatenation — no `E(·)`.
//! HKDF sites use the §1.1 mapping (salt = 0x00×32, info = tag, L = 32).

use hkdf::Hkdf;
use sha2::{Digest, Sha256};

use super::datastructures::AccountState;
use super::encoding::{digest_to_bytes, hc, HcInput};
use super::error::SpecError;
use super::tags::{
    NETWORK_TAG_MAINNET, NETWORK_TAG_REGTEST, NETWORK_TAG_TESTNET, TAG_ACCOUNT_STATE, TAG_ASSET_ID,
    TAG_ASSET_ID_V2, TAG_COIN, TAG_DETECT_TAG, TAG_ISSUANCE_TERMS, TAG_ISSUANCE_TERMS_V2,
    TAG_NAME_CONSENT, TAG_NAV_COMMIT, TAG_NAV_RAND, TAG_NETWORK, TAG_NK_COMMIT, TAG_NPK_COMMIT,
    TAG_NULLIFIER,
};
use zkcoins_program::hash::HashDigest;

// ---------------------------------------------------------------------------
// Poseidon / Hc derivations
// ---------------------------------------------------------------------------

/// `nk_commit = Hc("NkCommit", ByteString(nk))`.
pub fn nk_commit(nk: &[u8; 32]) -> HashDigest {
    hc(TAG_NK_COMMIT, &[HcInput::ByteString(nk)]).expect("nk is fixed 32 bytes")
}

/// `nf = Hc("Nullifier", ByteString(nk), Digest(coin_identifier))`.
pub fn nullifier(nk: &[u8; 32], coin_identifier: HashDigest) -> HashDigest {
    hc(
        TAG_NULLIFIER,
        &[HcInput::ByteString(nk), HcInput::Digest(coin_identifier)],
    )
    .expect("fixed-size inputs")
}

/// `ash = Hc("AccountState", serialize(AccountState))`. Takes the typed
/// `AccountState` (not raw bytes) so the canonical wire layout — including
/// FIX 4's strictly-ascending-balances guarantee — is enforced by
/// construction via `serialize_account_state`, never bypassable by hashing
/// arbitrary bytes.
pub fn account_state_hash(state: &AccountState) -> Result<HashDigest, SpecError> {
    let bytes = super::serialize::serialize_account_state(state)?;
    Ok(hc(TAG_ACCOUNT_STATE, &[HcInput::ByteString(&bytes)])
        .expect("account state serialization is well below 2^56 bytes"))
}

/// `coin.identifier = Hc("Coin", Digest(prev_ash), ByteString(recipient), Digest(asset_id),
///                       ByteString(amount_be16), SmallNumeric(coin_index))`.
pub fn coin_identifier(
    prev_account_state_hash: HashDigest,
    recipient: &[u8; 32],
    asset_id: HashDigest,
    amount: u128,
    coin_index: u32,
) -> HashDigest {
    let amount_be = amount.to_be_bytes();
    hc(
        TAG_COIN,
        &[
            HcInput::Digest(prev_account_state_hash),
            HcInput::ByteString(recipient),
            HcInput::Digest(asset_id),
            HcInput::ByteString(&amount_be),
            HcInput::SmallNumeric(coin_index as u64),
        ],
    )
    .expect("fixed-size inputs")
}

/// Token-standard-1 `asset_id`.
pub fn asset_id_v1(
    genesis_tag: &[u8],
    creator_pubkey: &[u8; 32],
    name_hash: &[u8; 32],
    decimals: u8,
    issuance_version: u8,
) -> HashDigest {
    hc(
        TAG_ASSET_ID,
        &[
            HcInput::ByteString(genesis_tag),
            HcInput::ByteString(creator_pubkey),
            HcInput::ByteString(name_hash),
            HcInput::SmallNumeric(decimals as u64),
            HcInput::SmallNumeric(issuance_version as u64),
        ],
    )
    .expect("fixed-size inputs")
}

/// Token-standard-2 `asset_id` (binds `cap_total` and `terms_salt`).
pub fn asset_id_v2(
    genesis_tag: &[u8],
    creator_pubkey: &[u8; 32],
    name_hash: &[u8; 32],
    decimals: u8,
    issuance_version: u8,
    cap_total: u128,
    terms_salt: &[u8; 32],
) -> HashDigest {
    let cap_be = cap_total.to_be_bytes();
    hc(
        TAG_ASSET_ID_V2,
        &[
            HcInput::ByteString(genesis_tag),
            HcInput::ByteString(creator_pubkey),
            HcInput::ByteString(name_hash),
            HcInput::SmallNumeric(decimals as u64),
            HcInput::SmallNumeric(issuance_version as u64),
            HcInput::ByteString(&cap_be),
            HcInput::ByteString(terms_salt),
        ],
    )
    .expect("fixed-size inputs")
}

/// `terms_hash` for token-standard-1: `Hc("IssuanceTerms", Digest(asset_id), SmallNumeric(v))`.
pub fn terms_hash_v1(asset_id: HashDigest, issuance_version: u8) -> HashDigest {
    hc(
        TAG_ISSUANCE_TERMS,
        &[
            HcInput::Digest(asset_id),
            HcInput::SmallNumeric(issuance_version as u64),
        ],
    )
    .expect("fixed-size inputs")
}

/// `terms_hash` for token-standard-2.
pub fn terms_hash_v2(
    asset_id: HashDigest,
    issuance_version: u8,
    cap_total: u128,
    terms_salt: &[u8; 32],
) -> HashDigest {
    let cap_be = cap_total.to_be_bytes();
    hc(
        TAG_ISSUANCE_TERMS_V2,
        &[
            HcInput::Digest(asset_id),
            HcInput::SmallNumeric(issuance_version as u64),
            HcInput::ByteString(&cap_be),
            HcInput::ByteString(terms_salt),
        ],
    )
    .expect("fixed-size inputs")
}

/// `network_id = Hc("Network", ByteString(network_tag_ascii))`.
pub fn network_id(network_tag_ascii: &[u8]) -> HashDigest {
    hc(TAG_NETWORK, &[HcInput::ByteString(network_tag_ascii)])
        .expect("network tags are short ASCII")
}

/// Convenience: `network_id` for mainnet / testnet / regtest.
pub fn network_id_mainnet() -> HashDigest {
    network_id(NETWORK_TAG_MAINNET)
}

pub fn network_id_testnet() -> HashDigest {
    network_id(NETWORK_TAG_TESTNET)
}

pub fn network_id_regtest() -> HashDigest {
    network_id(NETWORK_TAG_REGTEST)
}

/// `nav_commitment = Hc("NavCommit", Digest(nav_root), ByteString(nav_rand))`.
///
/// `nav_rand` is HKDF-derived (raw 32 bytes), **not** an `Hc` output.
pub fn nav_commitment(nav_root: HashDigest, nav_rand: &[u8; 32]) -> HashDigest {
    hc(
        TAG_NAV_COMMIT,
        &[HcInput::Digest(nav_root), HcInput::ByteString(nav_rand)],
    )
    .expect("fixed-size inputs")
}

/// §1.1 / §1.4 HKDF-SHA-256 mapping:
/// `HKDF(tag, material) = HKDF-Expand(HKDF-Extract(salt = 0x00×32, IKM = material), info = tag, L = 32)`.
pub fn hkdf_sha256(tag: &str, material: &[u8]) -> [u8; 32] {
    let salt = [0u8; 32];
    let hk = Hkdf::<Sha256>::new(Some(&salt), material);
    let mut okm = [0u8; 32];
    hk.expand(tag.as_bytes(), &mut okm)
        .expect("HKDF-Expand L=32 is always valid for SHA-256");
    okm
}

/// `nav_rand = HKDF("zkCoins/v1/NavRand", op_secret ‖ u64-be(send_counter))` (§1.4).
///
/// Deterministic per operational bundle and entry `send_counter`. **MUST NOT**
/// be derived from `nav`. Callers supply neither the output nor an independent
/// counter — both come from the account's `op_secret` and the transition being
/// built.
pub fn derive_nav_rand(op_secret: &[u8; 32], send_counter: u64) -> [u8; 32] {
    let mut material = [0u8; 40];
    material[..32].copy_from_slice(op_secret);
    material[32..].copy_from_slice(&send_counter.to_be_bytes());
    hkdf_sha256(TAG_NAV_RAND, &material)
}

/// `detect_tag = Hc("DetectTag", ByteString(ss), ByteString(epk))` (§1.3).
///
/// Per §1.7.2, `‖` inside an `Hc` call site separates the input list — each of
/// `ss` and `epk` is absorbed as its own 32-byte byte-string input (not as a
/// single 64-byte concatenation). Both are raw ECDH/x-only material, not prior
/// `Hc` digests.
pub fn detect_tag(ss: &[u8; 32], epk: &[u8; 32]) -> HashDigest {
    hc(
        TAG_DETECT_TAG,
        &[HcInput::ByteString(ss), HcInput::ByteString(epk)],
    )
    .expect("ss and epk are fixed 32 bytes")
}

/// Asset name hash: `H(name) = SHA-256(name)`. Rejects names longer than 255 bytes.
pub fn name_hash(name: &[u8]) -> Result<[u8; 32], SpecError> {
    if name.len() > 255 {
        return Err(SpecError::NameTooLong { len: name.len() });
    }
    let dig = Sha256::digest(name);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Name consent framing (§4.3 / V.12) — plain SHA-256 concatenation
// ---------------------------------------------------------------------------

/// §4.3 identifier normalization: lowercase ASCII before validation/comparison.
///
/// `Alice@Example.COM` and `alice@example.com` produce the same preimage.
/// The §4.3 grammar admits only ASCII, so ASCII case folding is the whole
/// normalization for every conforming name.
pub fn normalize_name(name: &str) -> String {
    name.to_ascii_lowercase()
}

/// Build the §4.3 / V.12 `name_message` preimage:
/// `"zkCoins/v1/NameConsent" ‖ network ‖ u32-be(name_len) ‖ UTF-8(name) ‖ op_pubkey`.
///
/// `name` is normalized first (§4.3). `name_len` is the canonical UTF-8
/// **byte** length of that normalized name (not character count). Empty
/// `network` or empty normalized name is an error — no silent default.
pub fn name_consent_preimage(
    network: &str,
    name: &str,
    op_pubkey: &[u8; 32],
) -> Result<Vec<u8>, SpecError> {
    if network.is_empty() {
        return Err(SpecError::NetworkEmpty);
    }
    let normalized = normalize_name(name);
    if normalized.is_empty() {
        return Err(SpecError::NameEmpty);
    }
    let name_bytes = normalized.as_bytes();
    let name_len = u32::try_from(name_bytes.len()).map_err(|_| SpecError::NameTooLong {
        len: name_bytes.len(),
    })?;

    let mut preimage = Vec::with_capacity(
        TAG_NAME_CONSENT.len() + network.len() + 4 + name_bytes.len() + op_pubkey.len(),
    );
    preimage.extend_from_slice(TAG_NAME_CONSENT);
    preimage.extend_from_slice(network.as_bytes());
    preimage.extend_from_slice(&name_len.to_be_bytes());
    preimage.extend_from_slice(name_bytes);
    preimage.extend_from_slice(op_pubkey);
    Ok(preimage)
}

/// `name_message = SHA-256(name_consent_preimage(…))` (§4.3 / V.12).
pub fn name_message(
    network: &str,
    name: &str,
    op_pubkey: &[u8; 32],
) -> Result<[u8; 32], SpecError> {
    let preimage = name_consent_preimage(network, name, op_pubkey)?;
    let dig = Sha256::digest(&preimage);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    Ok(out)
}

// ---------------------------------------------------------------------------
// SHA-256 boundary (plain byte concatenation — no Hc / E(·))
// ---------------------------------------------------------------------------

/// `address = SHA256(Pk₀ ‖ digest_to_bytes(nk_commit))` — 64-byte preimage, no tag (§1.4).
pub fn address(pk0_x_only: &[u8; 32], nk_commit: HashDigest) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pk0_x_only);
    hasher.update(digest_to_bytes(&nk_commit));
    let dig = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

/// `H(ProofData) = SHA256(serialize(ProofData))` over the fixed 192-byte layout.
pub fn hash_proof_data(serialized_proof_data: &[u8; 192]) -> [u8; 32] {
    let dig = Sha256::digest(serialized_proof_data);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

/// `npk_commit = SHA256(b"zkCoins/v1/NpkCommit" ‖ next_pubkey ‖ npk_rand)`.
pub fn npk_commit(next_pubkey: &[u8; 32], npk_rand: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(TAG_NPK_COMMIT);
    hasher.update(next_pubkey);
    hasher.update(npk_rand);
    let dig = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&dig);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    fn sha256_label(label: &str) -> [u8; 32] {
        let dig = Sha256::digest(label.as_bytes());
        let mut out = [0u8; 32];
        out.copy_from_slice(&dig);
        out
    }

    #[test]
    fn v1_sample_constants_sha256_pinned() {
        assert_eq!(
            hex::encode(sha256_label("zkCoins/v1/test-vector/Pk0")),
            "5dcffebb708081e3cc78b22f54d260467022c095a67da835f50713a36ee40746"
        );
        assert_eq!(
            hex::encode(sha256_label("zkCoins/v1/test-vector/Pk1")),
            "fba3ea150382de6f39a07348d327b1efa8c120da1ee599148ff6fed7803465fb"
        );
        assert_eq!(
            hex::encode(sha256_label("zkCoins/v1/test-vector/nk")),
            "2dc00b27c0d2991514b1b997af97b0e12c5da159b5726481124032c1578115b2"
        );
        assert_eq!(
            hex::encode(sha256_label("zkCoins/v1/test-vector/npk_rand")),
            "a04b10a7ac57db9e12b2cac644653f97ffdfc4911935f21f027936f60c543b98"
        );
        assert_eq!(
            hex::encode(name_hash(b"USD-Demo").unwrap()),
            "aff024cf2705e0450bfb51b461a1ed90c125efe0e43554191380b69a6a6be313"
        );
        assert_eq!(
            hex::encode(super::super::tags::GENESIS_TAG),
            "7a6b436f696e732f76312f67656e65736973"
        );
        assert_eq!(super::super::tags::GENESIS_TAG.len(), 18);

        let pk1 = sha256_label("zkCoins/v1/test-vector/Pk1");
        let npk_rand = sha256_label("zkCoins/v1/test-vector/npk_rand");
        assert_eq!(
            hex::encode(npk_commit(&pk1, &npk_rand)),
            "7d014dfd4b58080f7a68124ef28936c8da039135a8b7e0b25ce14e287e6d7026"
        );
    }

    #[test]
    fn name_hash_rejects_over_255() {
        let long = vec![b'a'; 256];
        assert!(matches!(
            name_hash(&long),
            Err(SpecError::NameTooLong { len: 256 })
        ));
        assert!(name_hash(&vec![b'a'; 255]).is_ok());
    }

    // V.2-ext op secret → x-only op_pubkey (BIP-340 even-y).
    // Derived independently; used only as the V.12 framing fixture key.
    const V2EXT_OP_PUBKEY_HEX: &str =
        "6424b41eea59c6a3aa6169b802c96ff5194962d3bf5f941130e4ebc86de3b485";
    // V.2-ext Pk₀ — a different valid x-only key for the op_pubkey mutation.
    const V2EXT_PK0_HEX: &str = "7c9cdde9b8cb1e33a48a5c2b6ab1fa6fd753fa1762f56c0b3e8169e4f2d54630";

    fn parse_hex32(hex_str: &str) -> [u8; 32] {
        let bytes = hex::decode(hex_str).expect("fixture hex");
        <[u8; 32]>::try_from(bytes.as_slice()).expect("32 bytes")
    }

    /// Manual preimage builder for mutation tests — bypasses the production
    /// name_len / normalization so each framing field can be corrupted alone.
    fn raw_name_consent_preimage(
        network: &str,
        name_len_be: [u8; 4],
        name_bytes: &[u8],
        op_pubkey: &[u8; 32],
    ) -> Vec<u8> {
        let mut preimage =
            Vec::with_capacity(TAG_NAME_CONSENT.len() + network.len() + 4 + name_bytes.len() + 32);
        preimage.extend_from_slice(TAG_NAME_CONSENT);
        preimage.extend_from_slice(network.as_bytes());
        preimage.extend_from_slice(&name_len_be);
        preimage.extend_from_slice(name_bytes);
        preimage.extend_from_slice(op_pubkey);
        preimage
    }

    fn sha256_bytes(bytes: &[u8]) -> [u8; 32] {
        Sha256::digest(bytes).into()
    }

    #[test]
    fn name_consent_v12_fixture_preimage_is_82_bytes() {
        let op_pubkey = parse_hex32(V2EXT_OP_PUBKEY_HEX);
        let preimage = name_consent_preimage("regtest", "alice@example.com", &op_pubkey)
            .expect("fixture preimage");
        assert_eq!(preimage.len(), 82, "V.12: 22 + 7 + 4 + 17 + 32 = 82 bytes");
        assert_eq!(&preimage[..22], TAG_NAME_CONSENT);
        assert_eq!(&preimage[22..29], b"regtest");
        assert_eq!(&preimage[29..33], &17u32.to_be_bytes());
        assert_eq!(&preimage[33..50], b"alice@example.com");
        assert_eq!(&preimage[50..82], &op_pubkey);
    }

    #[test]
    fn name_consent_unnormalized_control_is_identical() {
        let op_pubkey = parse_hex32(V2EXT_OP_PUBKEY_HEX);
        let a = name_consent_preimage("regtest", "alice@example.com", &op_pubkey).unwrap();
        let b = name_consent_preimage("regtest", "Alice@Example.COM", &op_pubkey).unwrap();
        assert_eq!(a, b, "§4.3 normalization must fold case");
        assert_eq!(
            name_message("regtest", "alice@example.com", &op_pubkey).unwrap(),
            name_message("regtest", "Alice@Example.COM", &op_pubkey).unwrap(),
        );
    }

    #[test]
    fn name_consent_mutation_different_network_changes_digest() {
        let op_pubkey = parse_hex32(V2EXT_OP_PUBKEY_HEX);
        let base = name_message("regtest", "alice@example.com", &op_pubkey).unwrap();
        let mut_net = name_message("testnet", "alice@example.com", &op_pubkey).unwrap();
        assert_ne!(base, mut_net, "different network must change name_message");
    }

    #[test]
    fn name_consent_mutation_name_len_little_endian_changes_digest() {
        let op_pubkey = parse_hex32(V2EXT_OP_PUBKEY_HEX);
        let name = b"alice@example.com";
        let base = name_message("regtest", "alice@example.com", &op_pubkey).unwrap();
        let le_pre = raw_name_consent_preimage("regtest", 17u32.to_le_bytes(), name, &op_pubkey);
        let le_dig = sha256_bytes(&le_pre);
        assert_ne!(
            base, le_dig,
            "little-endian name_len must change name_message"
        );
    }

    #[test]
    fn name_consent_mutation_name_len_plus_one_changes_digest() {
        let op_pubkey = parse_hex32(V2EXT_OP_PUBKEY_HEX);
        let name = b"alice@example.com";
        let base = name_message("regtest", "alice@example.com", &op_pubkey).unwrap();
        let pre = raw_name_consent_preimage("regtest", 18u32.to_be_bytes(), name, &op_pubkey);
        assert_ne!(
            base,
            sha256_bytes(&pre),
            "name_len + 1 must change name_message"
        );
    }

    #[test]
    fn name_consent_mutation_name_len_minus_one_changes_digest() {
        let op_pubkey = parse_hex32(V2EXT_OP_PUBKEY_HEX);
        let name = b"alice@example.com";
        let base = name_message("regtest", "alice@example.com", &op_pubkey).unwrap();
        let pre = raw_name_consent_preimage("regtest", 16u32.to_be_bytes(), name, &op_pubkey);
        assert_ne!(
            base,
            sha256_bytes(&pre),
            "name_len - 1 must change name_message"
        );
    }

    #[test]
    fn name_consent_mutation_different_op_pubkey_changes_digest() {
        let op_pubkey = parse_hex32(V2EXT_OP_PUBKEY_HEX);
        let other = parse_hex32(V2EXT_PK0_HEX);
        let base = name_message("regtest", "alice@example.com", &op_pubkey).unwrap();
        let mut_pk = name_message("regtest", "alice@example.com", &other).unwrap();
        assert_ne!(base, mut_pk, "different op_pubkey must change name_message");
    }

    #[test]
    fn name_consent_rejects_empty_name() {
        let op_pubkey = parse_hex32(V2EXT_OP_PUBKEY_HEX);
        assert!(matches!(
            name_consent_preimage("regtest", "", &op_pubkey),
            Err(SpecError::NameEmpty)
        ));
        assert!(matches!(
            name_message("regtest", "", &op_pubkey),
            Err(SpecError::NameEmpty)
        ));
    }

    #[test]
    fn name_consent_rejects_empty_network() {
        let op_pubkey = parse_hex32(V2EXT_OP_PUBKEY_HEX);
        assert!(matches!(
            name_consent_preimage("", "alice@example.com", &op_pubkey),
            Err(SpecError::NetworkEmpty)
        ));
        assert!(matches!(
            name_message("", "alice@example.com", &op_pubkey),
            Err(SpecError::NetworkEmpty)
        ));
    }

    /// V.12: `name_sig = BIP-340(sk₀, name_message)` is verified under `pk0`,
    /// not byte-compared (nonce derivation includes auxiliary randomness).
    /// Uses the already-wired `bitcoin` Schnorr path — no new signing stack.
    #[test]
    fn name_consent_bip340_sig_verifies_under_pk0() {
        use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey};

        // V.2-ext sk₀ / Pk₀ (pinned).
        const V2EXT_SK0_HEX: &str =
            "4a8e3a83404f1aa99e89af57179dcf033820b816c0d78ac94fcb322d6ee85649";
        let sk0_bytes = parse_hex32(V2EXT_SK0_HEX);
        let pk0 = parse_hex32(V2EXT_PK0_HEX);
        let op_pubkey = parse_hex32(V2EXT_OP_PUBKEY_HEX);

        let msg = name_message("regtest", "alice@example.com", &op_pubkey).unwrap();
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&sk0_bytes).expect("V.2-ext sk₀");
        let keypair = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _parity) = keypair.x_only_public_key();
        assert_eq!(
            xonly.serialize(),
            pk0,
            "V.2-ext sk₀ must derive the pinned Pk₀"
        );

        let message = Message::from_digest(msg);
        // Deterministic aux for the test only — production may use random aux;
        // either way the signature is verified, never byte-compared.
        let sig = secp.sign_schnorr_no_aux_rand(&message, &keypair);
        let xonly_pk0 = XOnlyPublicKey::from_slice(&pk0).expect("pk0 is x-only");
        secp.verify_schnorr(&sig, &message, &xonly_pk0)
            .expect("name_sig must verify under pk0 over name_message");

        // Negative: same signature must not verify under op_pubkey (the
        // node-held key) — the V.12 reject case "sig under op rather than pk0".
        let xonly_op = XOnlyPublicKey::from_slice(&op_pubkey).expect("op_pubkey is x-only");
        assert!(
            secp.verify_schnorr(&sig, &message, &xonly_op).is_err(),
            "name_sig under pk0 must not verify under op_pubkey"
        );
    }

    #[test]
    fn nav_rand_sample_sha256_pinned() {
        assert_eq!(
            hex::encode(sha256_label("zkCoins/v1/test-vector/nav_rand")),
            "e3b0e624bff8dbe486dd0761c14dcb84b4ccaf026fc60c58b69d653e6f656560"
        );
    }

    #[test]
    fn derive_nav_rand_is_deterministic_and_counter_sensitive() {
        let op_secret = sha256_label("zkCoins/v1/test-vector/op_secret");
        let a = derive_nav_rand(&op_secret, 0);
        let b = derive_nav_rand(&op_secret, 0);
        let c = derive_nav_rand(&op_secret, 1);
        assert_eq!(
            a, b,
            "same (op_secret, send_counter) must reproduce nav_rand"
        );
        assert_ne!(a, c, "different send_counter must yield different nav_rand");
        // Wrong counter material (little-endian) must not match for a
        // multi-byte counter where BE ≠ LE (counter 0 is identical in both).
        let be = derive_nav_rand(&op_secret, 1);
        let mut le_material = [0u8; 40];
        le_material[..32].copy_from_slice(&op_secret);
        le_material[32..].copy_from_slice(&1u64.to_le_bytes());
        assert_ne!(be, hkdf_sha256(TAG_NAV_RAND, &le_material));
    }

    #[test]
    fn address_preimage_is_64_byte_concat() {
        let pk0 = sha256_label("zkCoins/v1/test-vector/Pk0");
        let nk = sha256_label("zkCoins/v1/test-vector/nk");
        let nkc = nk_commit(&nk);
        let addr = address(&pk0, nkc);

        // Structural: preimage = Pk0(32) || digest_to_bytes(nk_commit)(32)
        let mut preimage = [0u8; 64];
        preimage[..32].copy_from_slice(&pk0);
        preimage[32..].copy_from_slice(&digest_to_bytes(&nkc));
        let mut hasher = Sha256::new();
        hasher.update(preimage);
        let expected: [u8; 32] = hasher.finalize().into();
        assert_eq!(addr, expected);
    }

    #[test]
    fn account_state_hash_matches_hc_over_canonical_bytes() {
        use crate::spec_v1::datastructures::Address;
        use crate::spec_v1::serialize::serialize_account_state;
        use std::collections::BTreeMap;
        use zkcoins_program::hash::ZERO_HASH;

        let state = AccountState::new(
            Address([0u8; 32]),
            ZERO_HASH,
            BTreeMap::new(),
            [0u8; 32],
            0,
            ZERO_HASH,
        )
        .unwrap();
        let via_fn = account_state_hash(&state).unwrap();
        let ser = serialize_account_state(&state).unwrap();
        let via_hc = hc(TAG_ACCOUNT_STATE, &[HcInput::ByteString(&ser)]).unwrap();
        assert_eq!(via_fn, via_hc);
    }

    #[test]
    fn account_state_hash_propagates_serialize_error() {
        use crate::spec_v1::datastructures::{Address, MAX_ACCOUNT_ASSETS};
        use std::collections::BTreeMap;
        use zkcoins_program::hash::ZERO_HASH;

        let mut balances = BTreeMap::new();
        for i in 0..=MAX_ACCOUNT_ASSETS {
            let mut k = [0u8; 32];
            k[31] = i as u8;
            balances.insert(k, 1);
        }
        let bad = AccountState {
            owner: Address([0u8; 32]),
            nk_commit: ZERO_HASH,
            balances,
            current_pubkey: [0u8; 32],
            send_counter: 0,
            coin_history_root: ZERO_HASH,
        };
        assert!(matches!(
            account_state_hash(&bad),
            Err(SpecError::TooManyBalances { .. })
        ));
    }
}
