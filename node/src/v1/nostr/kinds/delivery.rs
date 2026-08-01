//! Kind `1420` — zkCoins delivery rumor (`DeliveryEvent.payload`, §4.2 / §7.3).
//!
//! The rumor is unsigned ([`Rumor`]); seal + gift-wrap live in [`super::super::nip59`].
//! This module owns only the closed JSON payload and the kind-1420 rumor builder.

use std::fmt;

use serde::{Deserialize, Serialize};
use shared::spec_v1::note_encryption::{base64url_decode_no_pad, base64url_encode_no_pad};

use super::super::nip59::Rumor;

/// zkCoins delivery rumor kind (§7.3).
pub(crate) const KIND_DELIVERY: u32 = 1420;

/// §7.1 `MAX_BLOB_HOLDERS`.
const MAX_BLOB_HOLDERS: usize = 16;
/// §7.1 `MAX_HOLDER_URL_LEN`.
const MAX_HOLDER_URL_LEN: usize = 2048;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryPayloadError {
    /// JSON is not an object / not parseable.
    InvalidJson,
    /// A required field is missing.
    MissingField { field: &'static str },
    /// An unknown field is present (closed object on this path).
    ExtraField { field: String },
    /// Hex field is not lowercase hex of the required width.
    InvalidHex {
        field: &'static str,
        reason: &'static str,
    },
    /// `blob_locators` failed base64url-no-pad or BlobLocatorSet parse.
    InvalidBlobLocators { reason: &'static str },
    /// `record_kind` is present but not one of the closed string literals.
    InvalidRecordKind { got: String },
}

impl fmt::Display for DeliveryPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeliveryPayloadError::InvalidJson => write!(f, "delivery payload is not valid JSON"),
            DeliveryPayloadError::MissingField { field } => {
                write!(f, "delivery payload missing field {field}")
            }
            DeliveryPayloadError::ExtraField { field } => {
                write!(f, "delivery payload has extra field {field}")
            }
            DeliveryPayloadError::InvalidHex { field, reason } => {
                write!(f, "delivery payload field {field}: {reason}")
            }
            DeliveryPayloadError::InvalidBlobLocators { reason } => {
                write!(f, "delivery payload blob_locators: {reason}")
            }
            DeliveryPayloadError::InvalidRecordKind { got } => {
                write!(
                    f,
                    "delivery payload record_kind must be mint|send|receive, got {got:?}"
                )
            }
        }
    }
}

impl std::error::Error for DeliveryPayloadError {}

// ---------------------------------------------------------------------------
// record_kind
// ---------------------------------------------------------------------------

/// Closed `record_kind` for self-delivery payloads (§7.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RecordKind {
    Mint,
    Send,
    Receive,
}

impl RecordKind {
    fn as_str(self) -> &'static str {
        match self {
            RecordKind::Mint => "mint",
            RecordKind::Send => "send",
            RecordKind::Receive => "receive",
        }
    }

    fn parse(s: &str) -> Result<Self, DeliveryPayloadError> {
        match s {
            "mint" => Ok(RecordKind::Mint),
            "send" => Ok(RecordKind::Send),
            "receive" => Ok(RecordKind::Receive),
            other => Err(DeliveryPayloadError::InvalidRecordKind {
                got: other.to_string(),
            }),
        }
    }
}

// ---------------------------------------------------------------------------
// Payload
// ---------------------------------------------------------------------------

/// Decoded `DeliveryEvent.payload` (§4.2 step 3 / §7.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeliveryPayload {
    pub blob_id: [u8; 32],
    /// Ordered holder base URLs from `serialize(BlobLocatorSet)`.
    pub holders: Vec<String>,
    pub ack_nonce: [u8; 32],
    /// Present only for `SelfDeliveryRecordV1` blobs.
    pub record_kind: Option<RecordKind>,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeliveryPayloadJson {
    blob_id: String,
    blob_locators: String,
    ack_nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    record_kind: Option<String>,
}

fn parse_hex32_lower(s: &str, field: &'static str) -> Result<[u8; 32], DeliveryPayloadError> {
    if s.len() != 64 {
        return Err(DeliveryPayloadError::InvalidHex {
            field,
            reason: "expected 64 lowercase hex chars (32 bytes)",
        });
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(DeliveryPayloadError::InvalidHex {
            field,
            reason: "must be lowercase hex",
        });
    }
    let bytes = hex::decode(s).map_err(|_| DeliveryPayloadError::InvalidHex {
        field,
        reason: "hex decode failed",
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Parse `serialize(BlobLocatorSet)` (§7.1):
/// `u16-be count ‖ count × (u16-be url_len ‖ UTF-8 url)`.
fn parse_blob_locator_set(bytes: &[u8]) -> Result<Vec<String>, DeliveryPayloadError> {
    if bytes.len() < 2 {
        return Err(DeliveryPayloadError::InvalidBlobLocators {
            reason: "truncated (missing holder_count)",
        });
    }
    let count = u16::from_be_bytes([bytes[0], bytes[1]]) as usize;
    if count == 0 {
        return Err(DeliveryPayloadError::InvalidBlobLocators {
            reason: "holder_count must be >= 1",
        });
    }
    if count > MAX_BLOB_HOLDERS {
        return Err(DeliveryPayloadError::InvalidBlobLocators {
            reason: "holder_count exceeds MAX_BLOB_HOLDERS (16)",
        });
    }
    let mut cur = &bytes[2..];
    let mut holders = Vec::with_capacity(count);
    for _ in 0..count {
        if cur.len() < 2 {
            return Err(DeliveryPayloadError::InvalidBlobLocators {
                reason: "truncated (missing url_len)",
            });
        }
        let url_len = u16::from_be_bytes([cur[0], cur[1]]) as usize;
        cur = &cur[2..];
        if url_len == 0 {
            return Err(DeliveryPayloadError::InvalidBlobLocators {
                reason: "url_len must be >= 1",
            });
        }
        if url_len > MAX_HOLDER_URL_LEN {
            return Err(DeliveryPayloadError::InvalidBlobLocators {
                reason: "url_len exceeds MAX_HOLDER_URL_LEN (2048)",
            });
        }
        if cur.len() < url_len {
            return Err(DeliveryPayloadError::InvalidBlobLocators {
                reason: "truncated (url bytes)",
            });
        }
        let url_bytes = &cur[..url_len];
        cur = &cur[url_len..];
        let url = std::str::from_utf8(url_bytes).map_err(|_| {
            DeliveryPayloadError::InvalidBlobLocators {
                reason: "holder url is not UTF-8",
            }
        })?;
        holders.push(url.to_string());
    }
    if !cur.is_empty() {
        return Err(DeliveryPayloadError::InvalidBlobLocators {
            reason: "trailing bytes after BlobLocatorSet",
        });
    }
    Ok(holders)
}

fn serialize_blob_locator_set(holders: &[String]) -> Result<Vec<u8>, DeliveryPayloadError> {
    if holders.is_empty() {
        return Err(DeliveryPayloadError::InvalidBlobLocators {
            reason: "holder_count must be >= 1",
        });
    }
    if holders.len() > MAX_BLOB_HOLDERS {
        return Err(DeliveryPayloadError::InvalidBlobLocators {
            reason: "holder_count exceeds MAX_BLOB_HOLDERS (16)",
        });
    }
    let mut out = Vec::new();
    let count =
        u16::try_from(holders.len()).map_err(|_| DeliveryPayloadError::InvalidBlobLocators {
            reason: "holder_count exceeds u16",
        })?;
    out.extend_from_slice(&count.to_be_bytes());
    for url in holders {
        let bytes = url.as_bytes();
        if bytes.is_empty() {
            return Err(DeliveryPayloadError::InvalidBlobLocators {
                reason: "url_len must be >= 1",
            });
        }
        if bytes.len() > MAX_HOLDER_URL_LEN {
            return Err(DeliveryPayloadError::InvalidBlobLocators {
                reason: "url_len exceeds MAX_HOLDER_URL_LEN (2048)",
            });
        }
        let len =
            u16::try_from(bytes.len()).map_err(|_| DeliveryPayloadError::InvalidBlobLocators {
                reason: "url_len exceeds u16",
            })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    Ok(out)
}

/// Encode payload → compact JSON content string.
pub(crate) fn encode_delivery_payload(
    payload: &DeliveryPayload,
) -> Result<String, DeliveryPayloadError> {
    let framed = serialize_blob_locator_set(&payload.holders)?;
    let blob_locators = base64url_encode_no_pad(&framed);
    let j = DeliveryPayloadJson {
        blob_id: hex::encode(payload.blob_id),
        blob_locators,
        ack_nonce: hex::encode(payload.ack_nonce),
        record_kind: payload.record_kind.map(|k| k.as_str().to_string()),
    };
    serde_json::to_string(&j).map_err(|_| DeliveryPayloadError::InvalidJson)
}

/// Decode JSON content → payload. Closed fields; `record_kind` optional.
pub(crate) fn decode_delivery_payload(
    content: &str,
) -> Result<DeliveryPayload, DeliveryPayloadError> {
    let value: serde_json::Value =
        serde_json::from_str(content).map_err(|_| DeliveryPayloadError::InvalidJson)?;
    let obj = value.as_object().ok_or(DeliveryPayloadError::InvalidJson)?;

    // Closed-ish: required three + optional record_kind; reject anything else.
    for key in obj.keys() {
        match key.as_str() {
            "blob_id" | "blob_locators" | "ack_nonce" | "record_kind" => {}
            other => {
                return Err(DeliveryPayloadError::ExtraField {
                    field: other.to_string(),
                });
            }
        }
    }
    for required in ["blob_id", "blob_locators", "ack_nonce"] {
        if !obj.contains_key(required) {
            return Err(DeliveryPayloadError::MissingField { field: required });
        }
    }

    let j: DeliveryPayloadJson =
        serde_json::from_value(value).map_err(|_| DeliveryPayloadError::InvalidJson)?;

    let blob_id = parse_hex32_lower(&j.blob_id, "blob_id")?;
    let ack_nonce = parse_hex32_lower(&j.ack_nonce, "ack_nonce")?;

    let raw = base64url_decode_no_pad(&j.blob_locators).map_err(|_| {
        DeliveryPayloadError::InvalidBlobLocators {
            reason: "base64url-no-pad decode failed (alphabet, padding, or non-canonical)",
        }
    })?;
    let holders = parse_blob_locator_set(&raw)?;

    let record_kind = match j.record_kind {
        None => None,
        Some(s) => Some(RecordKind::parse(&s)?),
    };

    Ok(DeliveryPayload {
        blob_id,
        holders,
        ack_nonce,
        record_kind,
    })
}

/// Build an unsigned kind-1420 rumor from a payload.
pub(crate) fn delivery_rumor(
    author_pubkey: [u8; 32],
    created_at: u64,
    payload: &DeliveryPayload,
) -> Result<Rumor, DeliveryPayloadError> {
    let content = encode_delivery_payload(payload)?;
    Ok(Rumor::create(
        author_pubkey,
        created_at,
        KIND_DELIVERY,
        vec![],
        content,
    ))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> DeliveryPayload {
        // Bytes whose hex encoding contains a-f. All-digit fixtures (e.g.
        // [0x11; 32] → "11"…) are a no-op under `.to_uppercase()` and never
        // reach the lowercase-hex rejection branch in `parse_hex32_lower`.
        DeliveryPayload {
            blob_id: [0xab; 32],
            holders: vec![
                "https://blossom.example.com".to_string(),
                "https://blob2.example.com".to_string(),
            ],
            ack_nonce: [0xcd; 32],
            record_kind: None,
        }
    }

    #[test]
    fn encode_decode_roundtrip() {
        let p = sample_payload();
        let json = encode_delivery_payload(&p).expect("encode");
        let back = decode_delivery_payload(&json).expect("decode");
        assert_eq!(back, p);
        // Producer emits exactly the three required fields (no record_kind).
        assert!(!json.contains("record_kind"));
        assert!(json.contains("blob_id"));
        assert!(json.contains("blob_locators"));
        assert!(json.contains("ack_nonce"));
    }

    #[test]
    fn record_kind_roundtrip() {
        let mut p = sample_payload();
        p.record_kind = Some(RecordKind::Receive);
        let json = encode_delivery_payload(&p).expect("encode");
        let back = decode_delivery_payload(&json).expect("decode");
        assert_eq!(back.record_kind, Some(RecordKind::Receive));
    }

    #[test]
    fn rejects_extra_field() {
        let p = sample_payload();
        let json = encode_delivery_payload(&p).expect("encode");
        // Inject a fifth field.
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v.as_object_mut()
            .unwrap()
            .insert("evil".into(), serde_json::json!("x"));
        let err = decode_delivery_payload(&v.to_string()).expect_err("extra");
        match err {
            DeliveryPayloadError::ExtraField { field } => assert_eq!(field, "evil"),
            other => panic!("expected ExtraField, got {other:?}"),
        }
    }

    /// Both 32-byte hex fields go through `parse_hex32_lower` (§7.1). One
    /// test per field so a regression on either path is named, not folded.
    fn assert_rejects_uppercase_field(field: &str, raw: &[u8; 32]) {
        let lower = hex::encode(raw);
        assert!(
            lower.bytes().any(|b| matches!(b, b'a'..=b'f')),
            "fixture {field} hex must contain a-f so uppercase is observable"
        );
        let p = sample_payload();
        let json = encode_delivery_payload(&p).expect("encode");
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v[field] = serde_json::json!(lower.to_uppercase());
        let err = decode_delivery_payload(&v.to_string()).expect_err("upper");
        match err {
            DeliveryPayloadError::InvalidHex { field: got, reason } => {
                assert_eq!(got, field);
                assert!(reason.contains("lowercase"), "{reason}");
            }
            other => panic!("expected InvalidHex for {field}, got {other:?}"),
        }
    }

    #[test]
    fn rejects_uppercase_blob_id() {
        let p = sample_payload();
        assert_rejects_uppercase_field("blob_id", &p.blob_id);
    }

    #[test]
    fn rejects_uppercase_ack_nonce() {
        let p = sample_payload();
        assert_rejects_uppercase_field("ack_nonce", &p.ack_nonce);
    }

    #[test]
    fn rejects_free_json_array_locators() {
        // A free JSON array of URLs is not a conforming encoding (§7.3).
        let v = serde_json::json!({
            "blob_id": hex::encode([0x11u8; 32]),
            "blob_locators": ["https://a.example"],
            "ack_nonce": hex::encode([0x22u8; 32]),
        });
        // blob_locators must be a string; wrong type fails the typed decode.
        let err = decode_delivery_payload(&v.to_string()).expect_err("array");
        match err {
            DeliveryPayloadError::InvalidJson
            | DeliveryPayloadError::InvalidBlobLocators { .. } => {}
            other => panic!("expected InvalidJson/InvalidBlobLocators, got {other:?}"),
        }
        // Explicit non-base64 string:
        let v2 = serde_json::json!({
            "blob_id": hex::encode([0x11u8; 32]),
            "blob_locators": "not!!valid",
            "ack_nonce": hex::encode([0x22u8; 32]),
        });
        let err = decode_delivery_payload(&v2.to_string()).expect_err("bad b64");
        match err {
            DeliveryPayloadError::InvalidBlobLocators { reason } => {
                assert!(
                    reason.contains("base64url"),
                    "reason should name base64url: {reason}"
                );
            }
            other => panic!("expected InvalidBlobLocators, got {other:?}"),
        }
    }

    #[test]
    fn rejects_invalid_record_kind() {
        let p = sample_payload();
        let json = encode_delivery_payload(&p).expect("encode");
        let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
        v["record_kind"] = serde_json::json!("burn");
        let err = decode_delivery_payload(&v.to_string()).expect_err("burn");
        match err {
            DeliveryPayloadError::InvalidRecordKind { got } => assert_eq!(got, "burn"),
            other => panic!("expected InvalidRecordKind, got {other:?}"),
        }
    }

    #[test]
    fn delivery_rumor_kind_and_content() {
        let author = [0xAAu8; 32];
        let p = sample_payload();
        let rumor = delivery_rumor(author, 42, &p).expect("rumor");
        assert_eq!(rumor.kind, KIND_DELIVERY);
        assert_eq!(rumor.pubkey, author);
        assert_eq!(rumor.created_at, 42);
        assert!(rumor.tags.is_empty());
        let decoded = decode_delivery_payload(&rumor.content).expect("content");
        assert_eq!(decoded, p);
    }
}
