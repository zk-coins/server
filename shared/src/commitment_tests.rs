//! Negative-path tests for the BIP-340 Schnorr `Commitment`.
//!
//! `Commitment::verify` is security-critical: it gates whether a signed
//! account state will be accepted by the node. These tests exercise it
//! in isolation (no node, no SMT) and pin down the boundaries between
//! the "raw 32-byte digest" code path and the "SHA256-hashed message"
//! code path inside `Commitment::new` / `Commitment::verify`.

use super::*;
use bitcoin::secp256k1::{Keypair, PublicKey, SecretKey};
use sha2::{Digest, Sha256};

/// Deterministic secret key A used as the canonical signer in these tests.
fn secret_key_a() -> SecretKey {
    SecretKey::from_slice(&[1u8; 32]).expect("valid non-zero scalar")
}

/// Deterministic secret key B, used to swap in a wrong public key.
fn secret_key_b() -> SecretKey {
    SecretKey::from_slice(&[2u8; 32]).expect("valid non-zero scalar")
}

fn public_key_for(sk: &SecretKey) -> PublicKey {
    Keypair::from_secret_key(&SECP256K1, sk).public_key()
}

#[test]
fn verify_accepts_freshly_signed_commitment() {
    let commitment =
        Commitment::new(&secret_key_a(), b"hello zkcoins".to_vec()).expect("sign succeeds");
    assert!(
        commitment.verify(),
        "freshly signed commitment must verify against its own public key"
    );
}

#[test]
fn verify_rejects_signature_for_wrong_public_key() {
    let mut commitment =
        Commitment::new(&secret_key_a(), b"swap pubkey".to_vec()).expect("sign succeeds");
    // Replace the embedded public key with a different one (key B). The
    // signature was produced by key A, so verification must fail.
    commitment.public_key = public_key_for(&secret_key_b());
    assert!(
        !commitment.verify(),
        "verification must fail when public_key does not match the signing key"
    );
}

#[test]
fn verify_rejects_tampered_message() {
    let mut commitment =
        Commitment::new(&secret_key_a(), b"original message".to_vec()).expect("sign succeeds");
    assert!(commitment.verify(), "sanity: original verifies");

    // Flip bits in the first byte of the message.
    commitment.message[0] ^= 0xFF;
    assert!(
        !commitment.verify(),
        "verification must fail after the message has been tampered with"
    );
}

#[test]
fn verify_rejects_zero_signature() {
    let mut commitment =
        Commitment::new(&secret_key_a(), b"zeroed signature".to_vec()).expect("sign succeeds");

    // Construct an all-zero 64-byte Schnorr signature. `Signature::from_slice`
    // accepts any 64 bytes (validity is checked at verification time), so this
    // is a valid way to forge a syntactically-correct but cryptographically
    // invalid signature.
    let zero_sig = bitcoin::secp256k1::schnorr::Signature::from_slice(&[0u8; 64])
        .expect("64 zero bytes parse as a Signature");
    commitment.signature = zero_sig;

    assert!(
        !commitment.verify(),
        "verification must fail for an all-zero Schnorr signature"
    );
}

#[test]
fn verify_rejects_truncated_message() {
    let mut commitment =
        Commitment::new(&secret_key_a(), b"truncate me please".to_vec()).expect("sign succeeds");

    // Drop the last byte: this both changes the SHA256 hash and the length,
    // so the verification path must reject it.
    commitment.message.pop();
    assert!(
        !commitment.verify(),
        "verification must fail after the message has been truncated"
    );
}

#[test]
fn verify_rejects_extended_message() {
    let mut commitment =
        Commitment::new(&secret_key_a(), b"extend me please".to_vec()).expect("sign succeeds");

    // Append junk: changes the SHA256 hash that gets fed into verify_schnorr.
    commitment.message.extend_from_slice(b"!!!");
    assert!(
        !commitment.verify(),
        "verification must fail after extra bytes have been appended to the message"
    );
}

#[test]
fn verify_accepts_32_byte_message_as_raw_digest() {
    // When `message.len() == 32` both `new` and `verify` skip the SHA256
    // step and feed the 32 raw bytes straight into BIP-340. We exercise
    // that branch with a deterministic 32-byte payload.
    let raw_digest: Vec<u8> = (0u8..32).collect();
    let commitment = Commitment::new(&secret_key_a(), raw_digest.clone()).expect("sign succeeds");

    assert_eq!(commitment.message, raw_digest);
    assert!(
        commitment.verify(),
        "commitment over a 32-byte raw digest must verify"
    );
    assert_eq!(
        commitment.get_account_state_hash().to_vec(),
        raw_digest,
        "32-byte messages must be returned verbatim by get_account_state_hash"
    );
}

#[test]
fn verify_handles_non_32_byte_message_via_sha256() {
    // 31 bytes (just under the raw-digest boundary).
    let short_msg: Vec<u8> = (0u8..31).collect();
    let short_commitment =
        Commitment::new(&secret_key_a(), short_msg.clone()).expect("sign succeeds");
    assert!(
        short_commitment.verify(),
        "round-trip with a 31-byte message must verify (SHA256 path)"
    );

    // 64 bytes (just over the raw-digest boundary).
    let long_msg: Vec<u8> = (0u8..64).collect();
    let long_commitment =
        Commitment::new(&secret_key_a(), long_msg.clone()).expect("sign succeeds");
    assert!(
        long_commitment.verify(),
        "round-trip with a 64-byte message must verify (SHA256 path)"
    );
}

#[test]
fn verify_rejects_signature_swapped_between_messages() {
    // Sign message M1 with key A, then transplant that signature onto
    // a Commitment whose `message` is a different M2. Both messages take
    // the SHA256 path, so the digests differ and verification must fail.
    let m1 = Commitment::new(&secret_key_a(), b"message one".to_vec()).expect("sign succeeds");
    let mut m2 = Commitment::new(&secret_key_a(), b"message two".to_vec()).expect("sign succeeds");

    m2.signature = m1.signature;
    assert!(
        !m2.verify(),
        "a signature lifted from a different message must not verify"
    );
}

#[test]
fn get_account_state_hash_matches_internal_hash_path() {
    // For len != 32: returned hash must equal SHA256(message).
    let msg = b"non-32-byte payload".to_vec();
    let commitment = Commitment::new(&secret_key_a(), msg.clone()).expect("sign succeeds");

    let mut hasher = Sha256::new();
    hasher.update(&msg);
    let expected: [u8; 32] = hasher.finalize().into();

    assert_eq!(
        commitment.get_account_state_hash(),
        expected,
        "get_account_state_hash must equal SHA256(message) for non-32-byte messages"
    );

    // For len == 32: returned hash must equal the message verbatim.
    let raw_digest: Vec<u8> = (10u8..42).collect();
    let raw_commitment =
        Commitment::new(&secret_key_a(), raw_digest.clone()).expect("sign succeeds");
    assert_eq!(
        raw_commitment.get_account_state_hash().to_vec(),
        raw_digest,
        "get_account_state_hash must return a 32-byte message verbatim"
    );
}

#[test]
fn commitment_serde_roundtrip_preserves_verification() {
    let original =
        Commitment::new(&secret_key_a(), b"serde roundtrip".to_vec()).expect("sign succeeds");
    assert!(original.verify(), "sanity: original verifies");

    let encoded = bincode::serialize(&original).expect("bincode serialize");
    let decoded: Commitment = bincode::deserialize(&encoded).expect("bincode deserialize");

    assert_eq!(decoded.public_key, original.public_key);
    assert_eq!(decoded.signature, original.signature);
    assert_eq!(decoded.message, original.message);
    assert!(
        decoded.verify(),
        "deserialized commitment must still verify"
    );
}

#[test]
fn commitment_debug_contains_fields() {
    let commitment =
        Commitment::new(&secret_key_a(), b"debug fields".to_vec()).expect("sign succeeds");
    let dbg = format!("{:?}", commitment);
    assert!(dbg.contains("Commitment"), "got {dbg}");
    assert!(
        dbg.contains(&commitment.public_key.to_string()),
        "public_key missing from {dbg}"
    );
    assert!(
        dbg.contains(&hex::encode(commitment.signature.as_ref())),
        "signature missing from {dbg}"
    );
    assert!(
        dbg.contains(&hex::encode(&commitment.message)),
        "message missing from {dbg}"
    );
}
