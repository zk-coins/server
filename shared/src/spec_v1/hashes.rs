//! Derivation functions built on `Hc` and the SHA-256 boundary helpers.
//!
//! Poseidon (`Hc`) call sites follow the §1.7.3 encoding classification table
//! exactly. SHA-256 sites use plain byte concatenation — no `E(·)`.

use sha2::{Digest, Sha256};

use super::encoding::{hc, HcInput};
use super::error::SpecError;
use super::tags::{
    NETWORK_TAG_MAINNET, NETWORK_TAG_REGTEST, NETWORK_TAG_TESTNET, TAG_ACCOUNT_STATE, TAG_ASSET_ID,
    TAG_ASSET_ID_V2, TAG_COIN, TAG_ISSUANCE_TERMS, TAG_ISSUANCE_TERMS_V2, TAG_NAV_COMMIT,
    TAG_NETWORK, TAG_NK_COMMIT, TAG_NPK_COMMIT, TAG_NULLIFIER,
};
use zkcoins_program::hash::{digest_to_bytes, HashDigest};

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
        &[
            HcInput::ByteString(nk),
            HcInput::Digest(coin_identifier),
        ],
    )
    .expect("fixed-size inputs")
}

/// `ash = Hc("AccountState", ByteString(serialize(AccountState)))`.
pub fn account_state_hash(serialized_account_state: &[u8]) -> HashDigest {
    hc(
        TAG_ACCOUNT_STATE,
        &[HcInput::ByteString(serialized_account_state)],
    )
    .expect("account state serialization is well below 2^56 bytes")
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
        &[
            HcInput::Digest(nav_root),
            HcInput::ByteString(nav_rand),
        ],
    )
    .expect("fixed-size inputs")
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

    #[test]
    fn nav_rand_sample_sha256_pinned() {
        assert_eq!(
            hex::encode(sha256_label("zkCoins/v1/test-vector/nav_rand")),
            "e3b0e624bff8dbe486dd0761c14dcb84b4ccaf026fc60c58b69d653e6f656560"
        );
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
}
