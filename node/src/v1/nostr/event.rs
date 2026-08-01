//! NIP-01 event core: canonical id serialization, BIP-340 sign / verify.
//!
//! # Id serialization (normative)
//!
//! The event `id` is `SHA-256(utf8(compact_json([0, pubkey_hex, created_at,
//! kind, tags, content])))`. Compact JSON means **no whitespace**.
//!
//! String escaping is the classical NIP-01 trap. Only these seven sequences
//! are emitted; every other code point — including non-ASCII and non-BMP —
//! is written as raw UTF-8. In particular there is **no** `\uXXXX` form.
//! A stock JSON encoder produces a different byte string and therefore a
//! different `id` the moment `content` holds an umlaut or an emoji.
//!
//! | Code point | Escape |
//! |---|---|
//! | `U+0022` `"` | `\"` |
//! | `U+005C` `\` | `\\` |
//! | `U+000A` LF | `\n` |
//! | `U+000D` CR | `\r` |
//! | `U+0009` HT | `\t` |
//! | `U+0008` BS | `\b` |
//! | `U+000C` FF | `\f` |
//! | everything else | literal UTF-8 |
//!
//! # Trust boundary
//!
//! - **Outbound:** [`Event::sign`] computes `id` and `sig` from the fields
//!   and the author secret. Callers never supply either.
//! - **Inbound:** [`Event::verify_parts`] recomputes `id` and checks the
//!   BIP-340 signature. Claimed `id` / `sig` values are never believed.

use std::fmt;

use bitcoin::secp256k1::{
    schnorr::Signature as SchnorrSignature, Keypair, Message, Secp256k1, SecretKey, XOnlyPublicKey,
};
use sha2::{Digest, Sha256};

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Fail-closed reasons for NIP-01 event construction and verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum EventError {
    /// Secret scalar is not a valid secp256k1 key (`0` or `≥ n`).
    InvalidSecretKey,
    /// Author pubkey is not a canonical 32-byte x-only key.
    InvalidPublicKey,
    /// Claimed `id` does not equal `SHA-256` of the canonical preimage.
    IdMismatch {
        claimed: [u8; 32],
        computed: [u8; 32],
    },
    /// Signature bytes are not a 64-byte Schnorr signature encoding.
    MalformedSignature,
    /// BIP-340 verification failed under the author pubkey over `id`.
    BadSignature,
}

impl fmt::Display for EventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EventError::InvalidSecretKey => write!(f, "invalid secp256k1 secret key"),
            EventError::InvalidPublicKey => write!(f, "invalid x-only public key"),
            EventError::IdMismatch { claimed, computed } => write!(
                f,
                "event id mismatch: claimed={}, computed={}",
                hex::encode(claimed),
                hex::encode(computed)
            ),
            EventError::MalformedSignature => write!(f, "malformed BIP-340 signature encoding"),
            EventError::BadSignature => {
                write!(f, "BIP-340 signature verification failed")
            }
        }
    }
}

impl std::error::Error for EventError {}

// ---------------------------------------------------------------------------
// Canonical NIP-01 string escaping + id preimage
// ---------------------------------------------------------------------------

/// Escape a string under the NIP-01 id-serialization rule and wrap it in
/// double quotes.
///
/// Only `\n`, `\"`, `\\`, `\r`, `\t`, `\b`, `\f` become escapes. Every other
/// Unicode scalar value is emitted as its UTF-8 bytes unchanged — no
/// `\uXXXX`, no control-character filtering.
pub(crate) fn escape_nip01_string(s: &str) -> String {
    // Worst case: every byte becomes a two-byte escape (`\\` / `\n` / …).
    let mut out = String::with_capacity(s.len().saturating_mul(2).saturating_add(2));
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{000C}' => out.push_str("\\f"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Append a JSON number (unsigned) with no whitespace or leading zeros
/// (other than the single digit `0`).
fn push_u64(out: &mut String, n: u64) {
    // `Display` for integers matches the compact JSON form (no underscores,
    // no leading zeros except the number zero itself).
    out.push_str(&n.to_string());
}

/// Canonical NIP-01 id preimage:
/// `[0,<pubkey_hex>,<created_at>,<kind>,<tags>,<content>]` as compact JSON.
///
/// `pubkey` is the raw 32-byte x-only key; it is lower-hex-encoded here.
/// Tags are an array of arrays of strings; each string uses
/// [`escape_nip01_string`].
pub(crate) fn serialize_id_preimage(
    pubkey: &[u8; 32],
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> String {
    let mut out = String::with_capacity(64 + content.len() + tags.len().saturating_mul(32));
    out.push_str("[0,");
    out.push_str(&escape_nip01_string(&hex::encode(pubkey)));
    out.push(',');
    push_u64(&mut out, created_at);
    out.push(',');
    push_u64(&mut out, u64::from(kind));
    out.push(',');
    out.push('[');
    for (i, tag) in tags.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push('[');
        for (j, elem) in tag.iter().enumerate() {
            if j > 0 {
                out.push(',');
            }
            out.push_str(&escape_nip01_string(elem));
        }
        out.push(']');
    }
    out.push(']');
    out.push(',');
    out.push_str(&escape_nip01_string(content));
    out.push(']');
    out
}

/// `id = SHA-256(utf8(serialize_id_preimage(...)))`.
pub(crate) fn compute_event_id(
    pubkey: &[u8; 32],
    created_at: u64,
    kind: u32,
    tags: &[Vec<String>],
    content: &str,
) -> [u8; 32] {
    let preimage = serialize_id_preimage(pubkey, created_at, kind, tags, content);
    Sha256::digest(preimage.as_bytes()).into()
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

/// A fully signed NIP-01 event.
///
/// `id` and `sig` are always derived or verified — never trusted as inputs
/// without a check. Construct via [`Event::sign`] (outbound) or
/// [`Event::verify_parts`] (inbound).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Event {
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: [u8; 64],
}

/// Wire fields of an inbound event before verification.
///
/// Callers that decoded a relay/`EVENT` frame fill this and pass it to
/// [`Event::verify_parts`]. There is no path that turns these fields into
/// an [`Event`] without recomputing the id and checking the signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EventParts {
    pub id: [u8; 32],
    pub pubkey: [u8; 32],
    pub created_at: u64,
    pub kind: u32,
    pub tags: Vec<Vec<String>>,
    pub content: String,
    pub sig: [u8; 64],
}

impl Event {
    /// Build a signed event: compute `id` from the fields, BIP-340-sign it
    /// under `secret_key`, set `pubkey` from the key. Callers never supply
    /// `id` or `sig`.
    pub(crate) fn sign(
        secret_key: &[u8; 32],
        created_at: u64,
        kind: u32,
        tags: Vec<Vec<String>>,
        content: String,
    ) -> Result<Self, EventError> {
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(secret_key).map_err(|_| EventError::InvalidSecretKey)?;
        let keypair = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _parity) = keypair.x_only_public_key();
        let pubkey = xonly.serialize();

        let id = compute_event_id(&pubkey, created_at, kind, &tags, &content);
        let msg = Message::from_digest(id);
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &keypair);
        let mut sig_bytes = [0u8; 64];
        sig_bytes.copy_from_slice(sig.as_ref());

        Ok(Event {
            id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig: sig_bytes,
        })
    }

    /// Recompute `id` and verify the BIP-340 signature. Fail-closed: a
    /// mismatch or a bad signature returns a typed error and never an
    /// [`Event`].
    pub(crate) fn verify_parts(parts: EventParts) -> Result<Self, EventError> {
        let EventParts {
            id: claimed_id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig,
        } = parts;

        // Reject a non-canonical x-only pubkey before hashing or verifying.
        XOnlyPublicKey::from_slice(&pubkey).map_err(|_| EventError::InvalidPublicKey)?;

        let computed_id = compute_event_id(&pubkey, created_at, kind, &tags, &content);
        if computed_id != claimed_id {
            return Err(EventError::IdMismatch {
                claimed: claimed_id,
                computed: computed_id,
            });
        }

        let xonly =
            XOnlyPublicKey::from_slice(&pubkey).map_err(|_| EventError::InvalidPublicKey)?;
        let signature =
            SchnorrSignature::from_slice(&sig).map_err(|_| EventError::MalformedSignature)?;
        let msg = Message::from_digest(computed_id);
        let secp = Secp256k1::verification_only();
        secp.verify_schnorr(&signature, &msg, &xonly)
            .map_err(|_| EventError::BadSignature)?;

        Ok(Event {
            id: computed_id,
            pubkey,
            created_at,
            kind,
            tags,
            content,
            sig,
        })
    }

    /// Re-verify `self` (recompute id + check signature). Useful when an
    /// [`Event`] has been deserialized from a trusted-looking store.
    pub(crate) fn verify(&self) -> Result<(), EventError> {
        Self::verify_parts(EventParts {
            id: self.id,
            pubkey: self.pubkey,
            created_at: self.created_at,
            kind: self.kind,
            tags: self.tags.clone(),
            content: self.content.clone(),
            sig: self.sig,
        })?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};

    /// Deterministic test key: SHA-256 of a fixed label, re-hashed until it
    /// lands in `[1, n)`.
    fn fixture_sk(label: &[u8]) -> [u8; 32] {
        let mut seed = Sha256::digest(label).to_vec();
        let secp = Secp256k1::new();
        loop {
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&seed[..32]);
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                // Force the BIP-340 even-y keypair path to exist (side-effect free).
                let _ = Keypair::from_secret_key(&secp, &sk);
                return sk_bytes;
            }
            seed = Sha256::digest(&seed).to_vec();
        }
    }

    fn fixture_pubkey(sk: &[u8; 32]) -> [u8; 32] {
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(sk).expect("fixture sk");
        let kp = Keypair::from_secret_key(&secp, &secret);
        let (xonly, _) = kp.x_only_public_key();
        xonly.serialize()
    }

    // -----------------------------------------------------------------------
    // Escaping table
    // -----------------------------------------------------------------------

    #[test]
    fn escape_quote() {
        assert_eq!(escape_nip01_string("a\"b"), r#""a\"b""#);
    }

    #[test]
    fn escape_backslash() {
        assert_eq!(escape_nip01_string(r"a\b"), r#""a\\b""#);
    }

    #[test]
    fn escape_newline() {
        assert_eq!(escape_nip01_string("a\nb"), r#""a\nb""#);
    }

    #[test]
    fn escape_carriage_return() {
        assert_eq!(escape_nip01_string("a\rb"), r#""a\rb""#);
    }

    #[test]
    fn escape_tab() {
        assert_eq!(escape_nip01_string("a\tb"), r#""a\tb""#);
    }

    #[test]
    fn escape_backspace() {
        assert_eq!(escape_nip01_string("a\u{0008}b"), r#""a\bb""#);
    }

    #[test]
    fn escape_form_feed() {
        assert_eq!(escape_nip01_string("a\u{000C}b"), r#""a\fb""#);
    }

    #[test]
    fn escape_non_ascii_umlaut_is_literal_utf8() {
        // U+00E4 LATIN SMALL LETTER A WITH DIAERESIS — must NOT become \u00e4.
        let escaped = escape_nip01_string("ä");
        assert_eq!(escaped, "\"ä\"");
        assert_eq!(escaped.as_bytes(), b"\"\xc3\xa4\"");
        assert!(
            !escaped.contains("\\u"),
            "NIP-01 forbids \\uXXXX for non-ASCII; got {escaped:?}"
        );
    }

    #[test]
    fn escape_non_bmp_emoji_is_literal_utf8() {
        // U+1F600 GRINNING FACE — four UTF-8 bytes, no surrogate pair escape.
        let escaped = escape_nip01_string("😀");
        assert_eq!(escaped, "\"😀\"");
        assert_eq!(escaped.as_bytes(), b"\"\xf0\x9f\x98\x80\"");
        assert!(
            !escaped.contains("\\u"),
            "NIP-01 forbids \\uXXXX for non-BMP; got {escaped:?}"
        );
    }

    /// Pin the NIP-01 form of non-ASCII so a future swap to a stock JSON
    /// encoder cannot silently change event ids. Bytes are the contract;
    /// the Display form is a readability check on top.
    #[test]
    fn non_ascii_escape_bytes_are_raw_utf8_not_u_escapes() {
        let content = "ä😀";
        let ours = escape_nip01_string(content);
        assert_eq!(ours.as_bytes(), b"\"\xc3\xa4\xf0\x9f\x98\x80\"");
        assert_eq!(ours, "\"ä😀\"");
        assert!(
            !ours.as_bytes().windows(2).any(|w| w == b"\\u"),
            "must not emit \\uXXXX: {ours:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Id preimage + hash
    // -----------------------------------------------------------------------

    #[test]
    fn id_preimage_empty_tags_plain_content() {
        let pk = [0xab; 32];
        let preimage = serialize_id_preimage(&pk, 1_700_000_000, 1, &[], "hello");
        let expected = format!("[0,\"{}\",1700000000,1,[],\"hello\"]", hex::encode(pk));
        assert_eq!(preimage, expected);
        let id = compute_event_id(&pk, 1_700_000_000, 1, &[], "hello");
        let expected_id: [u8; 32] = Sha256::digest(expected.as_bytes()).into();
        assert_eq!(id, expected_id);
    }

    #[test]
    fn id_preimage_with_tags() {
        let pk = [0x01; 32];
        let tags = vec![
            vec!["e".to_string(), "aa".to_string()],
            vec!["p".to_string(), "bb".to_string(), "wss://r".to_string()],
        ];
        let preimage = serialize_id_preimage(&pk, 42, 0, &tags, "");
        let expected = format!(
            "[0,\"{}\",42,0,[[\"e\",\"aa\"],[\"p\",\"bb\",\"wss://r\"]],\"\"]",
            hex::encode(pk)
        );
        assert_eq!(preimage, expected);
    }

    #[test]
    fn id_preimage_escapes_content_specials_and_non_ascii() {
        let pk = [0xcd; 32];
        // Content exercises every escape plus a non-ASCII char and a non-BMP
        // emoji — the classical failure mode of a stock JSON encoder.
        let content = "line1\nquote\"bs\\tab\there\tä😀";
        let preimage = serialize_id_preimage(&pk, 99, 14, &[], content);
        let expected = format!(
            "[0,\"{}\",99,14,[],\"line1\\nquote\\\"bs\\\\tab\\there\\tä😀\"]",
            hex::encode(pk)
        );
        assert_eq!(preimage, expected);
        // Raw UTF-8 of ä (c3 a4) and 😀 (f0 9f 98 80) must appear in the
        // preimage bytes — not \u00e4 / \ud83d\ude00.
        let bytes = preimage.as_bytes();
        assert!(
            bytes.windows(2).any(|w| w == b"\xc3\xa4"),
            "umlaut must be raw UTF-8 in the id preimage"
        );
        assert!(
            bytes.windows(4).any(|w| w == b"\xf0\x9f\x98\x80"),
            "emoji must be raw UTF-8 in the id preimage"
        );
        assert!(
            !preimage.contains("\\u"),
            "id preimage must not contain \\uXXXX escapes: {preimage}"
        );
    }

    #[test]
    fn id_changes_when_content_changes() {
        let pk = [0x11; 32];
        let a = compute_event_id(&pk, 1, 1, &[], "a");
        let b = compute_event_id(&pk, 1, 1, &[], "b");
        assert_ne!(a, b);
    }

    // -----------------------------------------------------------------------
    // Sign / verify
    // -----------------------------------------------------------------------

    #[test]
    fn sign_computes_id_and_sig_verify_accepts() {
        let sk = fixture_sk(b"zkCoins/v1/test-vector/nostr/nip01-sk");
        let content = "hello\nworld \"ä\" 😀";
        let tags = vec![vec!["p".to_string(), hex::encode([0x22; 32])]];
        let event =
            Event::sign(&sk, 1_700_000_001, 1, tags.clone(), content.to_string()).expect("sign");

        let pk = fixture_pubkey(&sk);
        assert_eq!(event.pubkey, pk);
        assert_eq!(
            event.id,
            compute_event_id(&pk, 1_700_000_001, 1, &tags, content)
        );
        event.verify().expect("self-verify");

        let accepted = Event::verify_parts(EventParts {
            id: event.id,
            pubkey: event.pubkey,
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags.clone(),
            content: event.content.clone(),
            sig: event.sig,
        })
        .expect("verify_parts");
        assert_eq!(accepted, event);
    }

    #[test]
    fn verify_rejects_tampered_content_with_id_mismatch() {
        let sk = fixture_sk(b"zkCoins/v1/test-vector/nostr/nip01-sk");
        let event = Event::sign(&sk, 10, 1, vec![], "original".to_string()).expect("sign");

        let err = Event::verify_parts(EventParts {
            id: event.id, // claimed id still the original
            pubkey: event.pubkey,
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags.clone(),
            content: "tampered".to_string(),
            sig: event.sig,
        })
        .expect_err("tampered content must fail");

        match err {
            EventError::IdMismatch { claimed, computed } => {
                assert_eq!(claimed, event.id);
                let expect = compute_event_id(
                    &event.pubkey,
                    event.created_at,
                    event.kind,
                    &event.tags,
                    "tampered",
                );
                assert_eq!(computed, expect);
                assert_ne!(claimed, computed);
            }
            other => panic!("expected IdMismatch, got {other:?}"),
        }
    }

    #[test]
    fn verify_rejects_bad_signature_with_typed_error() {
        let sk = fixture_sk(b"zkCoins/v1/test-vector/nostr/nip01-sk");
        let event = Event::sign(&sk, 10, 1, vec![], "sig-check".to_string()).expect("sign");

        let mut bad_sig = event.sig;
        bad_sig[0] ^= 0xff;

        let err = Event::verify_parts(EventParts {
            id: event.id,
            pubkey: event.pubkey,
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags.clone(),
            content: event.content.clone(),
            sig: bad_sig,
        })
        .expect_err("flipped signature must fail");

        assert_eq!(err, EventError::BadSignature);
    }

    #[test]
    fn verify_rejects_wrong_pubkey_with_typed_error() {
        let sk = fixture_sk(b"zkCoins/v1/test-vector/nostr/nip01-sk");
        let other_sk = fixture_sk(b"zkCoins/v1/test-vector/nostr/nip01-sk-other");
        let event = Event::sign(&sk, 10, 1, vec![], "pk-check".to_string()).expect("sign");
        let other_pk = fixture_pubkey(&other_sk);

        // Id is bound to the author pubkey, so swapping pubkey alone fails
        // the id check first (fail-closed on the first disagreement).
        let err = Event::verify_parts(EventParts {
            id: event.id,
            pubkey: other_pk,
            created_at: event.created_at,
            kind: event.kind,
            tags: event.tags.clone(),
            content: event.content.clone(),
            sig: event.sig,
        })
        .expect_err("foreign pubkey must fail");

        match err {
            EventError::IdMismatch { .. } => {}
            other => panic!("expected IdMismatch for swapped pubkey, got {other:?}"),
        }
    }

    #[test]
    fn sign_rejects_invalid_secret_key() {
        let err = Event::sign(&[0u8; 32], 1, 1, vec![], "x".to_string())
            .expect_err("zero scalar is not a key");
        assert_eq!(err, EventError::InvalidSecretKey);
    }

    #[test]
    fn verify_rejects_off_curve_pubkey() {
        // 32 zero bytes are not a valid x-only secp256k1 point.
        let err = Event::verify_parts(EventParts {
            id: [0u8; 32],
            pubkey: [0u8; 32],
            created_at: 1,
            kind: 1,
            tags: vec![],
            content: String::new(),
            sig: [0u8; 64],
        })
        .expect_err("off-curve pubkey must fail");
        assert_eq!(err, EventError::InvalidPublicKey);
    }
}
