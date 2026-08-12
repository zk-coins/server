//! Kind `30423` — addressable bootstrap manifest event (§4.3 / §7.3).
//!
//! Content is the signed `BootstrapManifestV1` as JSON (keys and signatures
//! lowercase hex per §7.1). The `d` tag is the network tag and **MUST** equal
//! `manifest.network`. The event author is the network's pinned bootstrap
//! key — the only authority that may sign the BMF1 body.

use std::fmt;

use serde::{Deserialize, Serialize};
use shared::spec_v1::bootstrap_manifest::{
    verify_bootstrap_manifest, BootstrapManifestV1, ManifestClock, VerifyBootstrapManifest,
    BOOTSTRAP_PROTOCOL_VERSION,
};
use shared::spec_v1::SpecError;

use super::super::event::{Event, EventError, EventParts};

/// zkCoins bootstrap-manifest addressable event kind (§7.3).
pub(crate) const KIND_BOOTSTRAP_MANIFEST: u32 = 30423;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum BootstrapEventError {
    /// NIP-01 event construction / verification failed.
    Event(EventError),
    /// BMF1 trust-anchor / structure check failed.
    Manifest(SpecError),
    /// Event kind is not 30423.
    WrongKind { kind: u32 },
    /// `d` tag absent, duplicated, or not equal to `manifest.network`.
    DTagMismatch {
        d_tag: Option<String>,
        network: String,
    },
    /// Event author is not the pinned bootstrap pubkey.
    AuthorMismatch {
        event_pubkey: [u8; 32],
        pinned: [u8; 32],
    },
    /// Content is not valid BootstrapManifestV1 JSON.
    InvalidContentJson { reason: &'static str },
    /// Hex field inside content failed width / alphabet checks.
    InvalidHex {
        field: &'static str,
        reason: &'static str,
    },
    /// Content JSON carried an unknown field (closed producer surface).
    ExtraField { field: String },
    /// Signing key does not match the pinned bootstrap pubkey.
    SignerNotPinned {
        signer_pubkey: [u8; 32],
        pinned: [u8; 32],
    },
}

impl fmt::Display for BootstrapEventError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BootstrapEventError::Event(e) => write!(f, "event error: {e}"),
            BootstrapEventError::Manifest(e) => write!(f, "manifest error: {e}"),
            BootstrapEventError::WrongKind { kind } => {
                write!(f, "expected kind {KIND_BOOTSTRAP_MANIFEST}, got {kind}")
            }
            BootstrapEventError::DTagMismatch { d_tag, network } => write!(
                f,
                "d-tag {:?} does not match manifest network {network}",
                d_tag
            ),
            BootstrapEventError::AuthorMismatch {
                event_pubkey,
                pinned,
            } => write!(
                f,
                "event author {} is not pinned bootstrap key {}",
                hex::encode(event_pubkey),
                hex::encode(pinned)
            ),
            BootstrapEventError::InvalidContentJson { reason } => {
                write!(f, "bootstrap event content JSON: {reason}")
            }
            BootstrapEventError::InvalidHex { field, reason } => {
                write!(f, "bootstrap content field {field}: {reason}")
            }
            BootstrapEventError::ExtraField { field } => {
                write!(f, "bootstrap content has extra field {field}")
            }
            BootstrapEventError::SignerNotPinned {
                signer_pubkey,
                pinned,
            } => write!(
                f,
                "signer {} is not pinned bootstrap key {}",
                hex::encode(signer_pubkey),
                hex::encode(pinned)
            ),
        }
    }
}

impl std::error::Error for BootstrapEventError {}

impl From<EventError> for BootstrapEventError {
    fn from(value: EventError) -> Self {
        BootstrapEventError::Event(value)
    }
}

impl From<SpecError> for BootstrapEventError {
    fn from(value: SpecError) -> Self {
        BootstrapEventError::Manifest(value)
    }
}

// ---------------------------------------------------------------------------
// JSON content
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize)]
struct ManifestJson {
    network: String,
    protocol_version: String,
    seed_relays: Vec<String>,
    blob_stores: Vec<String>,
    operator_ids: Vec<String>,
    issued_at: u64,
    expires_at: u64,
    manifest_sig: String,
}

fn parse_hex_lower<const N: usize>(
    s: &str,
    field: &'static str,
) -> Result<[u8; N], BootstrapEventError> {
    if s.len() != N * 2 {
        return Err(BootstrapEventError::InvalidHex {
            field,
            reason: "wrong hex width",
        });
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(BootstrapEventError::InvalidHex {
            field,
            reason: "must be lowercase hex",
        });
    }
    let bytes = hex::decode(s).map_err(|_| BootstrapEventError::InvalidHex {
        field,
        reason: "hex decode failed",
    })?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn manifest_to_json(m: &BootstrapManifestV1) -> Result<String, BootstrapEventError> {
    let j = ManifestJson {
        network: m.network.clone(),
        protocol_version: m.protocol_version.clone(),
        seed_relays: m.seed_relays.clone(),
        blob_stores: m.blob_stores.clone(),
        operator_ids: m.operator_ids.iter().map(hex::encode).collect(),
        issued_at: m.issued_at,
        expires_at: m.expires_at,
        manifest_sig: hex::encode(m.manifest_sig),
    };
    serde_json::to_string(&j).map_err(|_| BootstrapEventError::InvalidContentJson {
        reason: "serialize failed",
    })
}

fn manifest_from_json(content: &str) -> Result<BootstrapManifestV1, BootstrapEventError> {
    let value: serde_json::Value = serde_json::from_str(content)
        .map_err(|_| BootstrapEventError::InvalidContentJson { reason: "not JSON" })?;
    let obj = value
        .as_object()
        .ok_or(BootstrapEventError::InvalidContentJson {
            reason: "not an object",
        })?;

    const ALLOWED: [&str; 8] = [
        "network",
        "protocol_version",
        "seed_relays",
        "blob_stores",
        "operator_ids",
        "issued_at",
        "expires_at",
        "manifest_sig",
    ];
    for key in obj.keys() {
        if !ALLOWED.contains(&key.as_str()) {
            return Err(BootstrapEventError::ExtraField { field: key.clone() });
        }
    }
    for field in ALLOWED {
        if !obj.contains_key(field) {
            return Err(BootstrapEventError::InvalidContentJson {
                reason: "missing required field",
            });
        }
    }

    let j: ManifestJson =
        serde_json::from_value(value).map_err(|_| BootstrapEventError::InvalidContentJson {
            reason: "shape mismatch",
        })?;

    let mut operator_ids = Vec::with_capacity(j.operator_ids.len());
    for (i, hex_pk) in j.operator_ids.iter().enumerate() {
        // Field name is shared; index only in panic paths of tests.
        let _ = i;
        operator_ids.push(parse_hex_lower(hex_pk, "operator_ids")?);
    }
    let manifest_sig = parse_hex_lower(&j.manifest_sig, "manifest_sig")?;

    Ok(BootstrapManifestV1 {
        network: j.network,
        protocol_version: j.protocol_version,
        seed_relays: j.seed_relays,
        blob_stores: j.blob_stores,
        operator_ids,
        issued_at: j.issued_at,
        expires_at: j.expires_at,
        manifest_sig,
    })
}

fn d_tag_value(tags: &[Vec<String>]) -> Option<&str> {
    let mut found: Option<&str> = None;
    for tag in tags {
        if tag.first().map(String::as_str) == Some("d") {
            let v = tag.get(1).map(String::as_str)?;
            if found.is_some() {
                // Duplicate d-tag — treat as absent/invalid.
                return None;
            }
            found = Some(v);
        }
    }
    found
}

fn xonly_from_sk(sk: &[u8; 32]) -> Result<[u8; 32], BootstrapEventError> {
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    let secp = Secp256k1::new();
    let secret = SecretKey::from_slice(sk)
        .map_err(|_| BootstrapEventError::Event(EventError::InvalidSecretKey))?;
    let kp = Keypair::from_secret_key(&secp, &secret);
    let (xonly, _) = kp.x_only_public_key();
    Ok(xonly.serialize())
}

// ---------------------------------------------------------------------------
// Encoder / decoder
// ---------------------------------------------------------------------------

/// Encode a **verified** bootstrap manifest as a kind-30423 addressable event.
///
/// Steps:
/// 1. Re-run [`verify_bootstrap_manifest`] under the pin (fail closed).
/// 2. Require `bootstrap_sk` derives the pinned pubkey.
/// 3. Content = JSON of the manifest; tags = `[["d", network]]`.
/// 4. Sign the Nostr event with `bootstrap_sk`.
pub(crate) fn encode_bootstrap_manifest_event(
    manifest: &BootstrapManifestV1,
    pinned_bootstrap_pubkey: &[u8; 32],
    expected_network: &str,
    clock: ManifestClock,
    bootstrap_sk: &[u8; 32],
    created_at: u64,
) -> Result<Event, BootstrapEventError> {
    verify_bootstrap_manifest(
        manifest,
        VerifyBootstrapManifest {
            pinned_bootstrap_pubkey,
            expected_network,
            expected_protocol_version: BOOTSTRAP_PROTOCOL_VERSION,
            clock,
        },
    )?;

    let signer_pk = xonly_from_sk(bootstrap_sk)?;
    if &signer_pk != pinned_bootstrap_pubkey {
        return Err(BootstrapEventError::SignerNotPinned {
            signer_pubkey: signer_pk,
            pinned: *pinned_bootstrap_pubkey,
        });
    }

    let content = manifest_to_json(manifest)?;
    let tags = vec![vec!["d".to_string(), manifest.network.clone()]];
    Event::sign(
        bootstrap_sk,
        created_at,
        KIND_BOOTSTRAP_MANIFEST,
        tags,
        content,
    )
    .map_err(BootstrapEventError::from)
}

/// Decode and verify a kind-30423 event back to a trust-anchored manifest.
///
/// Checks, in order:
/// 1. Event id + BIP-340 under its author.
/// 2. `kind == 30423`.
/// 3. Author equals the pinned bootstrap pubkey.
/// 4. Content parses as `BootstrapManifestV1` JSON.
/// 5. `verify_bootstrap_manifest` under the pin.
/// 6. Single `d` tag equals `manifest.network` (and the expected network).
pub(crate) fn decode_bootstrap_manifest_event(
    parts: EventParts,
    pinned_bootstrap_pubkey: &[u8; 32],
    expected_network: &str,
    clock: ManifestClock,
) -> Result<(Event, BootstrapManifestV1), BootstrapEventError> {
    let event = Event::verify_parts(parts)?;
    if event.kind != KIND_BOOTSTRAP_MANIFEST {
        return Err(BootstrapEventError::WrongKind { kind: event.kind });
    }
    if &event.pubkey != pinned_bootstrap_pubkey {
        return Err(BootstrapEventError::AuthorMismatch {
            event_pubkey: event.pubkey,
            pinned: *pinned_bootstrap_pubkey,
        });
    }

    let manifest = manifest_from_json(&event.content)?;
    verify_bootstrap_manifest(
        &manifest,
        VerifyBootstrapManifest {
            pinned_bootstrap_pubkey,
            expected_network,
            expected_protocol_version: BOOTSTRAP_PROTOCOL_VERSION,
            clock,
        },
    )?;

    let d = d_tag_value(&event.tags);
    if d != Some(manifest.network.as_str()) {
        return Err(BootstrapEventError::DTagMismatch {
            d_tag: d.map(str::to_string),
            network: manifest.network.clone(),
        });
    }
    if d != Some(expected_network) {
        return Err(BootstrapEventError::DTagMismatch {
            d_tag: d.map(str::to_string),
            network: expected_network.to_string(),
        });
    }

    Ok((event, manifest))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};
    use shared::spec_v1::bootstrap_manifest::{bootstrap_message, BOOTSTRAP_PROTOCOL_VERSION};

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

    fn sample_signed_manifest() -> (BootstrapManifestV1, [u8; 32], [u8; 32]) {
        let (sk, pk) = fixture_sk(b"zkCoins/v1/test/bootstrap-event/pubkey");
        let mut m = BootstrapManifestV1 {
            network: "regtest".to_string(),
            protocol_version: BOOTSTRAP_PROTOCOL_VERSION.to_string(),
            seed_relays: vec!["wss://relay.example.com".to_string()],
            blob_stores: vec!["https://blossom.example.com".to_string()],
            operator_ids: vec![[0x11; 32]],
            issued_at: 1_700_000_000,
            expires_at: 1_800_000_000,
            manifest_sig: [0u8; 64],
        };
        let secp = Secp256k1::new();
        let secret = SecretKey::from_slice(&sk).expect("sk");
        let kp = Keypair::from_secret_key(&secp, &secret);
        let msg = bootstrap_message(&m).expect("msg");
        let sig = secp.sign_schnorr_no_aux_rand(&Message::from_digest(msg), &kp);
        m.manifest_sig = *sig.as_ref();
        (m, sk, pk)
    }

    #[test]
    fn encode_decode_roundtrip() {
        let (m, sk, pk) = sample_signed_manifest();
        let event = encode_bootstrap_manifest_event(
            &m,
            &pk,
            "regtest",
            ManifestClock::UnixSeconds(1_750_000_000),
            &sk,
            1_750_000_000,
        )
        .expect("encode");

        assert_eq!(event.kind, KIND_BOOTSTRAP_MANIFEST);
        assert_eq!(event.pubkey, pk);
        assert_eq!(
            event.tags,
            vec![vec!["d".to_string(), "regtest".to_string()]]
        );

        let (back_event, back_m) = decode_bootstrap_manifest_event(
            EventParts {
                id: event.id,
                pubkey: event.pubkey,
                created_at: event.created_at,
                kind: event.kind,
                tags: event.tags.clone(),
                content: event.content.clone(),
                sig: event.sig,
            },
            &pk,
            "regtest",
            ManifestClock::UnixSeconds(1_750_000_000),
        )
        .expect("decode");
        assert_eq!(back_event, event);
        assert_eq!(back_m, m);
    }

    #[test]
    fn rejects_d_tag_network_mismatch() {
        let (m, sk, pk) = sample_signed_manifest();
        let mut event =
            encode_bootstrap_manifest_event(&m, &pk, "regtest", ManifestClock::Unavailable, &sk, 1)
                .expect("encode");
        // Tamper d-tag after signing → id no longer matches; verify_parts fails
        // first. Instead re-sign with a wrong d-tag deliberately:
        event = Event::sign(
            &sk,
            1,
            KIND_BOOTSTRAP_MANIFEST,
            vec![vec!["d".to_string(), "mainnet".to_string()]],
            event.content.clone(),
        )
        .expect("resign");

        let err = decode_bootstrap_manifest_event(
            EventParts {
                id: event.id,
                pubkey: event.pubkey,
                created_at: event.created_at,
                kind: event.kind,
                tags: event.tags.clone(),
                content: event.content.clone(),
                sig: event.sig,
            },
            &pk,
            "regtest",
            ManifestClock::Unavailable,
        )
        .expect_err("d-tag mainnet vs network regtest");
        match err {
            BootstrapEventError::DTagMismatch { d_tag, network } => {
                assert_eq!(d_tag.as_deref(), Some("mainnet"));
                // network in the error is manifest.network (regtest)
                assert_eq!(network, "regtest");
            }
            other => panic!("expected DTagMismatch, got {other:?}"),
        }
    }

    #[test]
    fn rejects_wrong_author() {
        let (m, sk, pk) = sample_signed_manifest();
        let (other_sk, other_pk) = fixture_sk(b"zkCoins/v1/test/bootstrap-event/other");
        // Sign event with a non-pinned key — encoder refuses.
        let err = encode_bootstrap_manifest_event(
            &m,
            &pk,
            "regtest",
            ManifestClock::Unavailable,
            &other_sk,
            1,
        )
        .expect_err("foreign signer");
        match err {
            BootstrapEventError::SignerNotPinned {
                signer_pubkey,
                pinned,
            } => {
                assert_eq!(signer_pubkey, other_pk);
                assert_eq!(pinned, pk);
            }
            other => panic!("expected SignerNotPinned, got {other:?}"),
        }
        let _ = sk;
    }

    #[test]
    fn rejects_tampered_manifest_sig_inside_content() {
        let (m, sk, pk) = sample_signed_manifest();
        let event =
            encode_bootstrap_manifest_event(&m, &pk, "regtest", ManifestClock::Unavailable, &sk, 1)
                .expect("encode");
        let mut v: serde_json::Value = serde_json::from_str(&event.content).unwrap();
        let mut bad_sig = m.manifest_sig;
        bad_sig[0] ^= 0xff;
        v["manifest_sig"] = serde_json::json!(hex::encode(bad_sig));
        let bad_content = v.to_string();
        // Re-sign the Nostr event over the tampered content so event sig is ok
        // but BMF1 verify fails.
        let tampered = Event::sign(
            &sk,
            1,
            KIND_BOOTSTRAP_MANIFEST,
            vec![vec!["d".to_string(), "regtest".to_string()]],
            bad_content,
        )
        .expect("resign");

        let err = decode_bootstrap_manifest_event(
            EventParts {
                id: tampered.id,
                pubkey: tampered.pubkey,
                created_at: tampered.created_at,
                kind: tampered.kind,
                tags: tampered.tags.clone(),
                content: tampered.content.clone(),
                sig: tampered.sig,
            },
            &pk,
            "regtest",
            ManifestClock::Unavailable,
        )
        .expect_err("bad manifest_sig");
        match err {
            BootstrapEventError::Manifest(SpecError::BootstrapSignatureInvalid) => {}
            other => panic!("expected Manifest(BootstrapSignatureInvalid), got {other:?}"),
        }
    }
}
