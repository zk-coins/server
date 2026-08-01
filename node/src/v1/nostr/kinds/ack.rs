//! Kind `1421` — zkCoins ACK rumor (§4.2 ACK rule / §7.3).
//!
//! Content is exactly four closed fields:
//! `{detect_tag, blob_id, ack_nonce, op_sig}` — all lowercase hex.
//!
//! `op_sig` is BIP-340 over
//! `ack_message = H("zkCoins/v1/Ack" ‖ detect_tag ‖ blob_id ‖ ack_nonce)`
//! where the three fields enter as **raw 32-byte** values, **not** hex.

use std::fmt;

use bitcoin::secp256k1::{
    schnorr::Signature as SchnorrSignature, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::nip59::Rumor;

/// zkCoins ACK rumor kind (§7.3).
pub(crate) const KIND_ACK: u32 = 1421;

/// Domain tag for the ACK signature preimage (§4.2).
const TAG_ACK: &[u8] = b"zkCoins/v1/Ack";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AckError {
    InvalidJson,
    MissingField {
        field: &'static str,
    },
    ExtraField {
        field: String,
    },
    InvalidHex {
        field: &'static str,
        reason: &'static str,
    },
    InvalidSecretKey,
    InvalidPublicKey,
    /// `op_sig` does not verify under the given `op` pubkey over `ack_message`.
    BadOpSignature,
    MalformedSignature,
}

impl fmt::Display for AckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AckError::InvalidJson => write!(f, "ACK content is not valid JSON"),
            AckError::MissingField { field } => write!(f, "ACK missing field {field}"),
            AckError::ExtraField { field } => write!(f, "ACK has extra field {field}"),
            AckError::InvalidHex { field, reason } => {
                write!(f, "ACK field {field}: {reason}")
            }
            AckError::InvalidSecretKey => write!(f, "invalid op secret key"),
            AckError::InvalidPublicKey => write!(f, "invalid op public key"),
            AckError::BadOpSignature => write!(f, "ACK op_sig verification failed"),
            AckError::MalformedSignature => write!(f, "ACK op_sig is not a 64-byte Schnorr sig"),
        }
    }
}

impl std::error::Error for AckError {}

// ---------------------------------------------------------------------------
// Content
// ---------------------------------------------------------------------------

/// The four closed ACK fields (decoded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct AckContent {
    pub detect_tag: [u8; 32],
    pub blob_id: [u8; 32],
    pub ack_nonce: [u8; 32],
    /// 64-byte BIP-340 signature by the recipient's `op`.
    pub op_sig: [u8; 64],
}

#[derive(Debug, Serialize, Deserialize)]
struct AckJson {
    detect_tag: String,
    blob_id: String,
    ack_nonce: String,
    op_sig: String,
}

fn parse_hex_lower<const N: usize>(s: &str, field: &'static str) -> Result<[u8; N], AckError> {
    if s.len() != N * 2 {
        return Err(AckError::InvalidHex {
            field,
            reason: "wrong hex width",
        });
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(AckError::InvalidHex {
            field,
            reason: "must be lowercase hex",
        });
    }
    let bytes = hex::decode(s).map_err(|_| AckError::InvalidHex {
        field,
        reason: "hex decode failed",
    })?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `ack_message = H("zkCoins/v1/Ack" ‖ detect_tag ‖ blob_id ‖ ack_nonce)`.
///
/// Inputs are **raw 32-byte** fields — never their hex encoding. Two
/// implementations that hash hex strings will diverge silently here.
pub(crate) fn ack_message(
    detect_tag: &[u8; 32],
    blob_id: &[u8; 32],
    ack_nonce: &[u8; 32],
) -> [u8; 32] {
    let mut preimage = Vec::with_capacity(TAG_ACK.len() + 32 + 32 + 32);
    preimage.extend_from_slice(TAG_ACK);
    preimage.extend_from_slice(detect_tag);
    preimage.extend_from_slice(blob_id);
    preimage.extend_from_slice(ack_nonce);
    Sha256::digest(&preimage).into()
}

/// Sign the four-field ACK under the recipient's `op` secret.
pub(crate) fn sign_ack(
    op_sk: &[u8; 32],
    detect_tag: &[u8; 32],
    blob_id: &[u8; 32],
    ack_nonce: &[u8; 32],
) -> Result<AckContent, AckError> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(op_sk).map_err(|_| AckError::InvalidSecretKey)?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let msg = Message::from_digest(ack_message(detect_tag, blob_id, ack_nonce));
    let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
    let mut op_sig = [0u8; 64];
    op_sig.copy_from_slice(sig.as_ref());
    Ok(AckContent {
        detect_tag: *detect_tag,
        blob_id: *blob_id,
        ack_nonce: *ack_nonce,
        op_sig,
    })
}

/// Verify `op_sig` under `op_pk` over the raw-byte `ack_message`.
pub(crate) fn verify_ack_sig(op_pk: &[u8; 32], content: &AckContent) -> Result<(), AckError> {
    let xonly = XOnlyPublicKey::from_slice(op_pk).map_err(|_| AckError::InvalidPublicKey)?;
    let signature =
        SchnorrSignature::from_slice(&content.op_sig).map_err(|_| AckError::MalformedSignature)?;
    let msg = Message::from_digest(ack_message(
        &content.detect_tag,
        &content.blob_id,
        &content.ack_nonce,
    ));
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&signature, &msg, &xonly)
        .map_err(|_| AckError::BadOpSignature)?;
    Ok(())
}

/// Encode the four closed fields as compact JSON (lowercase hex).
pub(crate) fn encode_ack_content(content: &AckContent) -> String {
    let j = AckJson {
        detect_tag: hex::encode(content.detect_tag),
        blob_id: hex::encode(content.blob_id),
        ack_nonce: hex::encode(content.ack_nonce),
        op_sig: hex::encode(content.op_sig),
    };
    // Four fields only — serde serializes exactly the struct members.
    serde_json::to_string(&j).expect("AckJson is always serializable")
}

/// Decode ACK JSON. **Closed**: missing or extra fields are rejection.
pub(crate) fn decode_ack_content(content: &str) -> Result<AckContent, AckError> {
    let value: serde_json::Value =
        serde_json::from_str(content).map_err(|_| AckError::InvalidJson)?;
    let obj = value.as_object().ok_or(AckError::InvalidJson)?;

    const REQUIRED: [&str; 4] = ["detect_tag", "blob_id", "ack_nonce", "op_sig"];
    for key in obj.keys() {
        if !REQUIRED.contains(&key.as_str()) {
            return Err(AckError::ExtraField { field: key.clone() });
        }
    }
    for field in REQUIRED {
        if !obj.contains_key(field) {
            return Err(AckError::MissingField { field });
        }
    }

    let j: AckJson = serde_json::from_value(value).map_err(|_| AckError::InvalidJson)?;
    Ok(AckContent {
        detect_tag: parse_hex_lower(&j.detect_tag, "detect_tag")?,
        blob_id: parse_hex_lower(&j.blob_id, "blob_id")?,
        ack_nonce: parse_hex_lower(&j.ack_nonce, "ack_nonce")?,
        op_sig: parse_hex_lower(&j.op_sig, "op_sig")?,
    })
}

/// Build an unsigned kind-1421 rumor from signed ACK content.
pub(crate) fn ack_rumor(author_pubkey: [u8; 32], created_at: u64, content: &AckContent) -> Rumor {
    Rumor::create(
        author_pubkey,
        created_at,
        KIND_ACK,
        vec![],
        encode_ack_content(content),
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};

    fn fixture_sk(label: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut seed = Sha256::digest(label).to_vec();
        let secp = Secp256k1::new();
        loop {
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&seed[..32]);
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                let kp = Keypair::from_secret_key(&secp, &sk);
                let (xonly, _) = kp.x_only_public_key();
                return (sk_bytes, xonly.serialize());
            }
            seed = Sha256::digest(&seed).to_vec();
        }
    }

    #[test]
    fn sign_verify_roundtrip_raw_bytes_preimage() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test/ack/op");
        let detect = [0xAAu8; 32];
        let blob = [0xBBu8; 32];
        let nonce = [0xCCu8; 32];
        let content = sign_ack(&sk, &detect, &blob, &nonce).expect("sign");
        verify_ack_sig(&pk, &content).expect("verify");

        // Preimage uses raw bytes: hashing hex strings must produce a
        // different digest (and therefore a non-verifying signature path).
        let mut hex_preimage = Vec::new();
        hex_preimage.extend_from_slice(TAG_ACK);
        hex_preimage.extend_from_slice(hex::encode(detect).as_bytes());
        hex_preimage.extend_from_slice(hex::encode(blob).as_bytes());
        hex_preimage.extend_from_slice(hex::encode(nonce).as_bytes());
        let hex_digest: [u8; 32] = Sha256::digest(&hex_preimage).into();
        let raw = ack_message(&detect, &blob, &nonce);
        assert_ne!(
            hex_digest, raw,
            "hex-encoded fields must not be used in ack_message"
        );
    }

    #[test]
    fn encode_decode_closed_four_fields() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test/ack/op");
        let content = sign_ack(&sk, &[1u8; 32], &[2u8; 32], &[3u8; 32]).expect("sign");
        let json = encode_ack_content(&content);
        let back = decode_ack_content(&json).expect("decode");
        assert_eq!(back, content);
        verify_ack_sig(&pk, &back).expect("verify after roundtrip");

        // Exactly four keys.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.len(), 4);
        assert!(obj.contains_key("detect_tag"));
        assert!(obj.contains_key("blob_id"));
        assert!(obj.contains_key("ack_nonce"));
        assert!(obj.contains_key("op_sig"));
    }

    #[test]
    fn rejects_fifth_field() {
        let (sk, _) = fixture_sk(b"zkCoins/v1/test/ack/op");
        let content = sign_ack(&sk, &[1u8; 32], &[2u8; 32], &[3u8; 32]).expect("sign");
        let json = encode_ack_content(&content);
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("extra".into(), serde_json::json!("nope"));
        let err = decode_ack_content(&v.to_string()).expect_err("fifth field");
        match err {
            AckError::ExtraField { field } => assert_eq!(field, "extra"),
            other => panic!("expected ExtraField, got {other:?}"),
        }
    }

    #[test]
    fn rejects_missing_field() {
        let json = r#"{"detect_tag":"aa","blob_id":"bb","ack_nonce":"cc"}"#;
        // Wrong widths too, but missing op_sig is the first structural fail
        // we care about after key scan — actually widths fail after keys.
        // Build a structurally complete-keys set minus one:
        let (sk, _) = fixture_sk(b"zkCoins/v1/test/ack/op");
        let content = sign_ack(&sk, &[1u8; 32], &[2u8; 32], &[3u8; 32]).expect("sign");
        let full = encode_ack_content(&content);
        let mut v: serde_json::Value = serde_json::from_str(&full).unwrap();
        v.as_object_mut().unwrap().remove("op_sig");
        let err = decode_ack_content(&v.to_string()).expect_err("missing");
        match err {
            AckError::MissingField { field } => assert_eq!(field, "op_sig"),
            other => panic!("expected MissingField, got {other:?}"),
        }
        let _ = json;
    }

    #[test]
    fn rejects_uppercase_hex_and_wrong_sig_width() {
        // Inputs must contain a-f so `.to_uppercase()` actually changes the
        // string. All-digit fixtures (e.g. [1u8; 32] → "01"…) are a no-op
        // under uppercasing and never reach the lowercase-hex branch.
        let (sk, _) = fixture_sk(b"zkCoins/v1/test/ack/op");
        let detect = [0xabu8; 32];
        let blob = [0xcdu8; 32];
        let nonce = [0xefu8; 32];
        let content = sign_ack(&sk, &detect, &blob, &nonce).expect("sign");
        let full = encode_ack_content(&content);
        let lower = hex::encode(content.detect_tag);
        assert!(
            lower.bytes().any(|b| matches!(b, b'a'..=b'f')),
            "fixture detect_tag hex must contain a-f so uppercase is observable"
        );
        let mut v: serde_json::Value = serde_json::from_str(&full).unwrap();
        v["detect_tag"] = serde_json::json!(lower.to_uppercase());
        let err = decode_ack_content(&v.to_string()).expect_err("upper");
        match err {
            AckError::InvalidHex { field, reason } => {
                assert_eq!(field, "detect_tag");
                assert!(reason.contains("lowercase"), "{reason}");
            }
            other => panic!("expected InvalidHex, got {other:?}"),
        }

        let mut v: serde_json::Value = serde_json::from_str(&full).unwrap();
        // 32 bytes → 64 hex chars; op_sig requires 64 bytes → 128 chars.
        v["op_sig"] = serde_json::json!(hex::encode([0u8; 32]));
        let err = decode_ack_content(&v.to_string()).expect_err("short sig");
        match err {
            AckError::InvalidHex { field, reason } => {
                assert_eq!(field, "op_sig");
                assert!(reason.contains("width"), "{reason}");
            }
            other => panic!("expected InvalidHex width, got {other:?}"),
        }
    }

    #[test]
    fn bad_signature_named_error() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test/ack/op");
        let mut content = sign_ack(&sk, &[1u8; 32], &[2u8; 32], &[3u8; 32]).expect("sign");
        content.op_sig[0] ^= 0xff;
        let err = verify_ack_sig(&pk, &content).expect_err("flipped sig");
        assert_eq!(err, AckError::BadOpSignature);
    }

    #[test]
    fn ack_rumor_kind() {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test/ack/op");
        let content = sign_ack(&sk, &[9u8; 32], &[8u8; 32], &[7u8; 32]).expect("sign");
        let rumor = ack_rumor(pk, 99, &content);
        assert_eq!(rumor.kind, KIND_ACK);
        assert_eq!(rumor.pubkey, pk);
        let decoded = decode_ack_content(&rumor.content).expect("decode");
        assert_eq!(decoded, content);
    }
}
