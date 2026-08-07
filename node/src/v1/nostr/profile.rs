//! Kind-0 `zkcoins` payment-object resolution and `Invoice` verification (§4.3 / §7.3).
//!
//! The node obtains a recipient `IVPK` (and relay set) only from:
//!
//! 1. A verified kind-0 `zkcoins` object, reached by **`op_pubkey`** (relay
//!    query), or
//! 2. A verified amount-specific [`PaymentInvoice`] inserted by the API layer
//!    via [`crate::v1::delivery::DeliveryTargetStore::insert_verified_invoice`].
//!
//! **Names / NIP-05 do not run in the node.** §7.5
//! `TransitionRequest.output_templates[].recipient` is a zk-address only;
//! §4.3 forbids bare-address resolution. Name → profile discovery lives in
//! the API/SDK layer (other repo), which then hands the node a verified
//! Invoice or calls `insert_verified_invoice` / stores a profile target.
//!
//! # Checklists (normative order)
//!
//! *Payment-object* (§7.3): (1) kind-0 signature under the arrived `op_pubkey`,
//! (2) closed object shape / widths / network / Bech32m / relays, (3)
//! `H(pk0 ‖ nk_commit) == address`, (4) `addr_sig` under `pk0` over the
//! profile-fixed `invoice_message`. Optional *name checklist* (reverse
//! `nip05` + `name_sig`) remains available when a caller supplies a name —
//! the node itself has no NIP-05 HTTP path.
//!
//! *Invoice* (§4.3): (i) address preimage, (ii) `addr_sig` under `pk0`,
//! (iii) `sig` under `op_pubkey` — same `invoice_message` framing.
//!
//! # Out of scope
//!
//! NIP-05 HTTP resolution (API layer), payment-identity pinning storage,
//! Lightning/`lud16`, kind-10050 messaging readiness.

use std::fmt;

use bitcoin::secp256k1::{
    schnorr::Signature as SchnorrSignature, Message, Secp256k1, XOnlyPublicKey,
};
#[cfg(test)]
use bitcoin::secp256k1::{Keypair, SecretKey};
use serde_json::Value;
use sha2::{Digest, Sha256};
use shared::spec_v1::datastructures::Address;
use shared::spec_v1::hashes::{name_message, normalize_name};

use super::event::{Event, EventError};
use super::relay::{Filter, RelayPool, RelayQueryOutcome};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Nostr user-metadata kind (§7.3).
pub(crate) const KIND_METADATA: u32 = 0;

/// Domain tag for `invoice_message` (§4.3).
const TAG_INVOICE: &[u8] = b"zkCoins/v1/Invoice";

/// Closed `zkcoins.network` labels (§7.3).
const NETWORKS: [&str; 3] = ["mainnet", "testnet", "regtest"];

/// Closed field set of the kind-0 `zkcoins` object (§7.3).
const ZKCOINS_FIELDS: [&str; 9] = [
    "version",
    "network",
    "address",
    "pk0",
    "nk_commit",
    "ivpk",
    "relays",
    "addr_sig",
    "name_sig",
];

// ---------------------------------------------------------------------------
// Errors — payment-object checklist (numbered)
// ---------------------------------------------------------------------------

/// Fail-closed reasons for the §7.3 payment-object / name checklists.
///
/// Every rejection names the **check number** that failed so callers and
/// tests assert the cause, not merely `is_err()`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProfileCheckError {
    /// Check 1: event is not kind 0.
    Check1WrongKind { kind: u32 },
    /// Check 1: event author ≠ arrived `op_pubkey`.
    Check1AuthorMismatch {
        event_pubkey: [u8; 32],
        expected_op: [u8; 32],
    },
    /// Check 1: NIP-01 id / BIP-340 verification failed.
    Check1BadSignature(EventError),
    /// Check 2: kind-0 `content` is not a JSON object.
    Check2InvalidContentJson { reason: &'static str },
    /// Check 2: `zkcoins` object missing.
    Check2MissingZkcoins,
    /// Check 2: `zkcoins` is not a JSON object.
    Check2ZkcoinsNotObject,
    /// Check 2: unknown field inside `zkcoins` (closed surface).
    Check2ExtraField { field: String },
    /// Check 2: `op_pubkey` must not be duplicated inside `zkcoins`.
    Check2OpPubkeyDuplicated,
    /// Check 2: required field missing.
    Check2MissingField { field: &'static str },
    /// Check 2: `version` is not the JSON number `1`.
    Check2Version { got: String },
    /// Check 2: `network` is not the caller's expected closed label.
    Check2Network { expected: String, got: String },
    /// Check 2: hex field width / alphabet wrong.
    Check2InvalidHex {
        field: &'static str,
        reason: &'static str,
    },
    /// Check 2: `address` is not valid Bech32m under HRP `zk` with 32-byte payload.
    Check2InvalidAddress { reason: String },
    /// Check 2: `relays` empty or not an array of URL strings.
    Check2InvalidRelays { reason: &'static str },
    /// Check 2: a relay URL is not `ws://` / `wss://`.
    Check2InvalidRelayUrl { url: String },
    /// Check 3: `H(pk0 ‖ nk_commit) ≠ address`.
    Check3AddressMismatch {
        claimed: [u8; 32],
        computed: [u8; 32],
    },
    /// Check 4: `addr_sig` does not verify under `pk0` over the profile-fixed
    /// `invoice_message` (the address ↔ rest binding, including `ivpk`).
    Check4BadAddrSig,
    /// Check 4: `pk0` is not a canonical x-only key, or `addr_sig` is malformed.
    Check4Malformed { reason: &'static str },
    /// Name checklist: profile `nip05` absent or ≠ normalized resolved name.
    NameReverseMismatch {
        expected: String,
        got: Option<String>,
    },
    /// Check 5: `name_sig` does not verify under `pk0` over `name_message`.
    Check5BadNameSig,
    /// Check 5: `name_message` preimage construction failed (name / network).
    Check5NameMessage { reason: String },
    /// Check 5: `pk0` / `name_sig` encoding error.
    Check5Malformed { reason: &'static str },
}

impl fmt::Display for ProfileCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileCheckError::Check1WrongKind { kind } => {
                write!(f, "profile check 1: expected kind 0, got {kind}")
            }
            ProfileCheckError::Check1AuthorMismatch {
                event_pubkey,
                expected_op,
            } => write!(
                f,
                "profile check 1: event author {} ≠ arrived op_pubkey {}",
                hex::encode(event_pubkey),
                hex::encode(expected_op)
            ),
            ProfileCheckError::Check1BadSignature(e) => {
                write!(f, "profile check 1: event signature failed: {e}")
            }
            ProfileCheckError::Check2InvalidContentJson { reason } => {
                write!(f, "profile check 2: content JSON: {reason}")
            }
            ProfileCheckError::Check2MissingZkcoins => {
                write!(f, "profile check 2: missing zkcoins object")
            }
            ProfileCheckError::Check2ZkcoinsNotObject => {
                write!(f, "profile check 2: zkcoins is not an object")
            }
            ProfileCheckError::Check2ExtraField { field } => {
                write!(f, "profile check 2: unknown zkcoins field {field}")
            }
            ProfileCheckError::Check2OpPubkeyDuplicated => {
                write!(
                    f,
                    "profile check 2: op_pubkey must not appear inside zkcoins"
                )
            }
            ProfileCheckError::Check2MissingField { field } => {
                write!(f, "profile check 2: missing field {field}")
            }
            ProfileCheckError::Check2Version { got } => {
                write!(f, "profile check 2: version must be 1, got {got}")
            }
            ProfileCheckError::Check2Network { expected, got } => {
                write!(f, "profile check 2: network expected {expected}, got {got}")
            }
            ProfileCheckError::Check2InvalidHex { field, reason } => {
                write!(f, "profile check 2: field {field}: {reason}")
            }
            ProfileCheckError::Check2InvalidAddress { reason } => {
                write!(f, "profile check 2: invalid address: {reason}")
            }
            ProfileCheckError::Check2InvalidRelays { reason } => {
                write!(f, "profile check 2: relays: {reason}")
            }
            ProfileCheckError::Check2InvalidRelayUrl { url } => {
                write!(f, "profile check 2: invalid relay URL {url}")
            }
            ProfileCheckError::Check3AddressMismatch { claimed, computed } => write!(
                f,
                "profile check 3: H(pk0‖nk_commit) mismatch: claimed={}, computed={}",
                hex::encode(claimed),
                hex::encode(computed)
            ),
            ProfileCheckError::Check4BadAddrSig => {
                write!(f, "profile check 4: addr_sig verification failed under pk0")
            }
            ProfileCheckError::Check4Malformed { reason } => {
                write!(f, "profile check 4: {reason}")
            }
            ProfileCheckError::NameReverseMismatch { expected, got } => {
                write!(
                    f,
                    "name reverse check: expected nip05={expected}, got={got:?}"
                )
            }
            ProfileCheckError::Check5BadNameSig => {
                write!(f, "profile check 5: name_sig verification failed under pk0")
            }
            ProfileCheckError::Check5NameMessage { reason } => {
                write!(f, "profile check 5: name_message: {reason}")
            }
            ProfileCheckError::Check5Malformed { reason } => {
                write!(f, "profile check 5: {reason}")
            }
        }
    }
}

impl std::error::Error for ProfileCheckError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProfileCheckError::Check1BadSignature(e) => Some(e),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Errors — Invoice checklist (i)/(ii)/(iii)
// ---------------------------------------------------------------------------

/// Fail-closed reasons for §4.3 `Invoice` verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum InvoiceCheckError {
    /// (i) `H(pk0 ‖ nk_commit) ≠ recipient`.
    Check1AddressMismatch {
        claimed: [u8; 32],
        computed: [u8; 32],
    },
    /// (ii) `addr_sig` does not verify under `pk0` over `invoice_message`.
    Check2BadAddrSig,
    /// (ii) malformed `pk0` / `addr_sig`.
    Check2Malformed {
        reason: &'static str,
    },
    /// (iii) `sig` does not verify under `op_pubkey` over `invoice_message`.
    Check3BadOpSig,
    /// (iii) malformed `op_pubkey` / `sig`.
    Check3Malformed {
        reason: &'static str,
    },
    /// Structural: empty relays or invalid relay URL (no silent default).
    InvalidRelays {
        reason: &'static str,
    },
    InvalidRelayUrl {
        url: String,
    },
}

impl fmt::Display for InvoiceCheckError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InvoiceCheckError::Check1AddressMismatch { claimed, computed } => write!(
                f,
                "invoice check (i): H(pk0‖nk_commit) mismatch: claimed={}, computed={}",
                hex::encode(claimed),
                hex::encode(computed)
            ),
            InvoiceCheckError::Check2BadAddrSig => {
                write!(
                    f,
                    "invoice check (ii): addr_sig verification failed under pk0"
                )
            }
            InvoiceCheckError::Check2Malformed { reason } => {
                write!(f, "invoice check (ii): {reason}")
            }
            InvoiceCheckError::Check3BadOpSig => {
                write!(
                    f,
                    "invoice check (iii): sig verification failed under op_pubkey"
                )
            }
            InvoiceCheckError::Check3Malformed { reason } => {
                write!(f, "invoice check (iii): {reason}")
            }
            InvoiceCheckError::InvalidRelays { reason } => {
                write!(f, "invoice relays: {reason}")
            }
            InvoiceCheckError::InvalidRelayUrl { url } => {
                write!(f, "invoice invalid relay URL: {url}")
            }
        }
    }
}

impl std::error::Error for InvoiceCheckError {}

// ---------------------------------------------------------------------------
// Errors — resolution / NIP-05
// ---------------------------------------------------------------------------

/// Fail-closed reasons for profile resolution over relays.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ProfileResolveError {
    /// No kind-0 event from the author survived NIP-01 verification.
    NoKind0Event,
    /// Kind-0 events exist, but none passed the payment-object checklist.
    NoValidPaymentProfile { last: ProfileCheckError },
    /// Relay pool had no usable connection (every URL failed).
    AllRelaysFailed,
}

impl fmt::Display for ProfileResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProfileResolveError::NoKind0Event => {
                write!(f, "no verified kind-0 event for author")
            }
            ProfileResolveError::NoValidPaymentProfile { last } => {
                write!(f, "no valid payment profile among kind-0 events: {last}")
            }
            ProfileResolveError::AllRelaysFailed => {
                write!(f, "every relay in the discovery set failed")
            }
        }
    }
}

impl std::error::Error for ProfileResolveError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ProfileResolveError::NoValidPaymentProfile { last } => Some(last),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Decoded objects
// ---------------------------------------------------------------------------

/// Closed kind-0 `zkcoins` object after structural decode (checklist step 2).
///
/// Binding checks (3)/(4)/(5) are separate — a decoded object is not yet a
/// payment target.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ZkcoinsObject {
    pub network: String,
    /// 32-byte address payload (decoded from Bech32m).
    pub address: [u8; 32],
    /// Original Bech32m string from the object (preserved for diagnostics).
    pub address_bech32: String,
    pub pk0: [u8; 32],
    pub nk_commit: [u8; 32],
    pub ivpk: [u8; 32],
    pub relays: Vec<String>,
    pub addr_sig: [u8; 64],
    pub name_sig: [u8; 64],
}

/// Payment identity extracted from a fully verified kind-0 profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedPaymentProfile {
    pub op_pubkey: [u8; 32],
    pub address: [u8; 32],
    pub pk0: [u8; 32],
    pub nk_commit: [u8; 32],
    pub ivpk: [u8; 32],
    pub relays: Vec<String>,
    pub network: String,
    /// The kind-0 event that carried the object (already NIP-01 verified).
    pub event: Event,
}

/// §4.3 amount-specific `Invoice` with transport fields (decoded).
///
/// **Public for the API/SDK layer** (other repo): wallets construct a
/// verified invoice and the API calls
/// [`crate::v1::DeliveryTargetStore::insert_verified_invoice`] before
/// prove/finalise. §7.5 carries only a bare address — no `ivpk` — so this
/// type is the only mesh-delivery carrier. No in-crate production
/// constructor; that is intentional (C).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentInvoice {
    pub amount: u128,
    pub recipient: [u8; 32],
    pub asset_id: [u8; 32],
    pub memo: Option<String>,
    pub pk0: [u8; 32],
    pub nk_commit: [u8; 32],
    pub ivpk: [u8; 32],
    pub op_pubkey: [u8; 32],
    pub relays: Vec<String>,
    pub addr_sig: [u8; 64],
    /// Per-issuance `op` signature over `invoice_message`.
    pub sig: [u8; 64],
}

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

fn parse_hex_lower<const N: usize>(
    s: &str,
    field: &'static str,
) -> Result<[u8; N], ProfileCheckError> {
    if s.len() != N * 2 {
        return Err(ProfileCheckError::Check2InvalidHex {
            field,
            reason: "wrong hex width",
        });
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(ProfileCheckError::Check2InvalidHex {
            field,
            reason: "must be lowercase hex",
        });
    }
    let bytes = hex::decode(s).map_err(|_| ProfileCheckError::Check2InvalidHex {
        field,
        reason: "hex decode failed",
    })?;
    let mut out = [0u8; N];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn validate_relay_url(url: &str) -> Result<(), ProfileCheckError> {
    if url.is_empty() || !(url.starts_with("ws://") || url.starts_with("wss://")) {
        return Err(ProfileCheckError::Check2InvalidRelayUrl {
            url: url.to_string(),
        });
    }
    Ok(())
}

fn validate_relay_url_invoice(url: &str) -> Result<(), InvoiceCheckError> {
    if url.is_empty() || !(url.starts_with("ws://") || url.starts_with("wss://")) {
        return Err(InvoiceCheckError::InvalidRelayUrl {
            url: url.to_string(),
        });
    }
    Ok(())
}

fn is_closed_network(network: &str) -> bool {
    NETWORKS.contains(&network)
}

// ---------------------------------------------------------------------------
// invoice_message / address preimage
// ---------------------------------------------------------------------------

/// `address = SHA-256(pk0 ‖ nk_commit)` — 64-byte preimage, no domain tag (§1.4).
pub(crate) fn address_from_parts(pk0: &[u8; 32], nk_commit: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(pk0);
    hasher.update(nk_commit);
    hasher.finalize().into()
}

/// `invoice_message = H("zkCoins/v1/Invoice" ‖ amount ‖ recipient ‖ pk0 ‖
/// nk_commit ‖ asset_id ‖ memo ‖ ivpk ‖ op_pubkey ‖ relays)` (§4.3).
///
/// Framing (normative): `amount` 16-byte BE `u128`; `memo` = `u32-be len ‖
/// UTF-8` (len 0 when absent); `relays` = `u16-be count ‖` each
/// `u32-be len ‖ UTF-8`; fixed fields at 32 bytes. Order is the formula, not
/// the struct layout.
/// Inputs for [`invoice_message`] (destructured at the call site).
///
/// Groups the §4.3 preimage fields so clippy's `too_many_arguments` gate
/// stays clear and a new field is a compile error at every construction site.
/// `pk0` + `nk_commit` form the address preimage; `amount` / `asset_id` /
/// `memo` are the invoice value; `ivpk` / `op_pubkey` / `relays` are transport.
#[derive(Debug, Clone, Copy)]
pub(crate) struct InvoiceMessageParts<'a> {
    pub amount: u128,
    pub recipient: &'a [u8; 32],
    pub pk0: &'a [u8; 32],
    pub nk_commit: &'a [u8; 32],
    pub asset_id: &'a [u8; 32],
    pub memo: Option<&'a str>,
    pub ivpk: &'a [u8; 32],
    pub op_pubkey: &'a [u8; 32],
    pub relays: &'a [String],
}

pub(crate) fn invoice_message(
    InvoiceMessageParts {
        amount,
        recipient,
        pk0,
        nk_commit,
        asset_id,
        memo,
        ivpk,
        op_pubkey,
        relays,
    }: InvoiceMessageParts<'_>,
) -> [u8; 32] {
    let memo_bytes: &[u8] = match memo {
        Some(s) => s.as_bytes(),
        None => &[],
    };
    let memo_len = u32::try_from(memo_bytes.len()).expect("memo length fits u32");
    let relay_count = u16::try_from(relays.len()).expect("relay count fits u16");

    let mut preimage = Vec::with_capacity(
        TAG_INVOICE.len()
            + 16
            + 32
            + 32
            + 32
            + 32
            + 4
            + memo_bytes.len()
            + 32
            + 32
            + 2
            + relays.iter().map(|r| 4 + r.len()).sum::<usize>(),
    );
    preimage.extend_from_slice(TAG_INVOICE);
    preimage.extend_from_slice(&amount.to_be_bytes());
    preimage.extend_from_slice(recipient);
    preimage.extend_from_slice(pk0);
    preimage.extend_from_slice(nk_commit);
    preimage.extend_from_slice(asset_id);
    preimage.extend_from_slice(&memo_len.to_be_bytes());
    preimage.extend_from_slice(memo_bytes);
    preimage.extend_from_slice(ivpk);
    preimage.extend_from_slice(op_pubkey);
    preimage.extend_from_slice(&relay_count.to_be_bytes());
    for r in relays {
        let len = u32::try_from(r.len()).expect("relay URL length fits u32");
        preimage.extend_from_slice(&len.to_be_bytes());
        preimage.extend_from_slice(r.as_bytes());
    }
    Sha256::digest(&preimage).into()
}

/// Profile-fixed `invoice_message`: `amount = 0`, all-zero `asset_id`, empty memo.
pub(crate) fn profile_invoice_message(
    address: &[u8; 32],
    pk0: &[u8; 32],
    nk_commit: &[u8; 32],
    ivpk: &[u8; 32],
    op_pubkey: &[u8; 32],
    relays: &[String],
) -> [u8; 32] {
    invoice_message(InvoiceMessageParts {
        amount: 0,
        recipient: address,
        pk0,
        nk_commit,
        asset_id: &[0u8; 32],
        memo: None,
        ivpk,
        op_pubkey,
        relays,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Bip340Error {
    InvalidPublicKey,
    MalformedSignature,
    BadSignature,
}

fn verify_bip340(pubkey: &[u8; 32], msg: &[u8; 32], sig: &[u8; 64]) -> Result<(), Bip340Error> {
    let xonly = XOnlyPublicKey::from_slice(pubkey).map_err(|_| Bip340Error::InvalidPublicKey)?;
    let signature =
        SchnorrSignature::from_slice(sig).map_err(|_| Bip340Error::MalformedSignature)?;
    let message = Message::from_digest(*msg);
    let secp = Secp256k1::verification_only();
    secp.verify_schnorr(&signature, &message, &xonly)
        .map_err(|_| Bip340Error::BadSignature)?;
    Ok(())
}

/// BIP-340 sign helper for unit-test fixtures (wallet issuance lives in the
/// API/SDK layer — this crate only **verifies** invoice signatures).
#[cfg(test)]
pub(crate) fn sign_bip340(secret_key: &[u8; 32], msg: &[u8; 32]) -> Result<[u8; 64], EventError> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(secret_key).map_err(|_| EventError::InvalidSecretKey)?;
    let keypair = Keypair::from_secret_key(&secp, &sk);
    let signature = secp.sign_schnorr_no_aux_rand(&Message::from_digest(*msg), &keypair);
    let mut out = [0u8; 64];
    out.copy_from_slice(signature.as_ref());
    Ok(out)
}

// ---------------------------------------------------------------------------
// Parse zkcoins object (checklist step 2 material)
// ---------------------------------------------------------------------------

/// Decode the closed `zkcoins` object from a kind-0 content JSON value.
///
/// Unknown fields and a duplicated `op_pubkey` are rejection. Does **not**
/// run binding checks (3)/(4)/(5).
pub(crate) fn parse_zkcoins_object(
    content_json: &Value,
    expected_network: &str,
) -> Result<ZkcoinsObject, ProfileCheckError> {
    let root = content_json
        .as_object()
        .ok_or(ProfileCheckError::Check2InvalidContentJson {
            reason: "content is not a JSON object",
        })?;

    let zk = root
        .get("zkcoins")
        .ok_or(ProfileCheckError::Check2MissingZkcoins)?;
    let obj = zk
        .as_object()
        .ok_or(ProfileCheckError::Check2ZkcoinsNotObject)?;

    // Closed surface: unknown field → reject (including a duplicated op_pubkey).
    for key in obj.keys() {
        if key == "op_pubkey" {
            return Err(ProfileCheckError::Check2OpPubkeyDuplicated);
        }
        if !ZKCOINS_FIELDS.contains(&key.as_str()) {
            return Err(ProfileCheckError::Check2ExtraField { field: key.clone() });
        }
    }
    for field in ZKCOINS_FIELDS {
        if !obj.contains_key(field) {
            return Err(ProfileCheckError::Check2MissingField { field });
        }
    }

    // version = JSON number 1 (not string "1").
    let version_val = obj.get("version").expect("checked present");
    let version = version_val
        .as_u64()
        .ok_or_else(|| ProfileCheckError::Check2Version {
            got: version_val.to_string(),
        })?;
    if version != 1 {
        return Err(ProfileCheckError::Check2Version {
            got: version.to_string(),
        });
    }

    let network = obj
        .get("network")
        .and_then(|v| v.as_str())
        .ok_or(ProfileCheckError::Check2MissingField { field: "network" })?
        .to_string();
    if !is_closed_network(&network) || network != expected_network {
        return Err(ProfileCheckError::Check2Network {
            expected: expected_network.to_string(),
            got: network,
        });
    }

    let address_bech32 = obj
        .get("address")
        .and_then(|v| v.as_str())
        .ok_or(ProfileCheckError::Check2MissingField { field: "address" })?
        .to_string();
    let address = Address::from_bech32m(&address_bech32)
        .map(|a| a.0)
        .map_err(|e| ProfileCheckError::Check2InvalidAddress {
            reason: e.to_string(),
        })?;

    let pk0 = parse_hex_lower(
        obj.get("pk0")
            .and_then(|v| v.as_str())
            .ok_or(ProfileCheckError::Check2MissingField { field: "pk0" })?,
        "pk0",
    )?;
    let nk_commit = parse_hex_lower(
        obj.get("nk_commit")
            .and_then(|v| v.as_str())
            .ok_or(ProfileCheckError::Check2MissingField { field: "nk_commit" })?,
        "nk_commit",
    )?;
    let ivpk = parse_hex_lower(
        obj.get("ivpk")
            .and_then(|v| v.as_str())
            .ok_or(ProfileCheckError::Check2MissingField { field: "ivpk" })?,
        "ivpk",
    )?;
    let addr_sig = parse_hex_lower(
        obj.get("addr_sig")
            .and_then(|v| v.as_str())
            .ok_or(ProfileCheckError::Check2MissingField { field: "addr_sig" })?,
        "addr_sig",
    )?;
    let name_sig = parse_hex_lower(
        obj.get("name_sig")
            .and_then(|v| v.as_str())
            .ok_or(ProfileCheckError::Check2MissingField { field: "name_sig" })?,
        "name_sig",
    )?;

    let relays_val = obj
        .get("relays")
        .ok_or(ProfileCheckError::Check2MissingField { field: "relays" })?;
    let relays_arr = relays_val
        .as_array()
        .ok_or(ProfileCheckError::Check2InvalidRelays {
            reason: "relays is not an array",
        })?;
    if relays_arr.is_empty() {
        return Err(ProfileCheckError::Check2InvalidRelays {
            reason: "relays must be non-empty",
        });
    }
    let mut relays = Vec::with_capacity(relays_arr.len());
    for r in relays_arr {
        let url = r
            .as_str()
            .ok_or(ProfileCheckError::Check2InvalidRelays {
                reason: "relay entry is not a string",
            })?
            .to_string();
        validate_relay_url(&url)?;
        relays.push(url);
    }

    Ok(ZkcoinsObject {
        network,
        address,
        address_bech32,
        pk0,
        nk_commit,
        ivpk,
        relays,
        addr_sig,
        name_sig,
    })
}

// ---------------------------------------------------------------------------
// Payment-object checklist (ordered)
// ---------------------------------------------------------------------------

/// Run the §7.3 payment-object checklist (and optional name checklist).
///
/// `expected_op` is the key the consumer arrived with (pinned contact,
/// nprofile, addressable event, or NIP-05 mapped key). `expected_network`
/// is the verifier's network — never defaulted. When `resolved_name` is
/// `Some`, the reverse `nip05` check and check 5 (`name_sig`) run as well.
pub(crate) fn verify_payment_profile(
    event: &Event,
    expected_op: &[u8; 32],
    expected_network: &str,
    resolved_name: Option<&str>,
) -> Result<VerifiedPaymentProfile, ProfileCheckError> {
    // ---- Check 1: kind-0 signature under arrived op_pubkey ----
    if event.kind != KIND_METADATA {
        return Err(ProfileCheckError::Check1WrongKind { kind: event.kind });
    }
    if &event.pubkey != expected_op {
        return Err(ProfileCheckError::Check1AuthorMismatch {
            event_pubkey: event.pubkey,
            expected_op: *expected_op,
        });
    }
    event
        .verify()
        .map_err(ProfileCheckError::Check1BadSignature)?;

    // ---- Check 2: closed object shape ----
    let content_json: Value = serde_json::from_str(&event.content).map_err(|_| {
        ProfileCheckError::Check2InvalidContentJson {
            reason: "content is not JSON",
        }
    })?;
    let zk = parse_zkcoins_object(&content_json, expected_network)?;

    // ---- Check 3: H(pk0 ‖ nk_commit) == address ----
    let computed = address_from_parts(&zk.pk0, &zk.nk_commit);
    if computed != zk.address {
        return Err(ProfileCheckError::Check3AddressMismatch {
            claimed: zk.address,
            computed,
        });
    }

    // ---- Check 4: addr_sig under pk0 over profile-fixed invoice_message ----
    let msg = profile_invoice_message(
        &zk.address,
        &zk.pk0,
        &zk.nk_commit,
        &zk.ivpk,
        expected_op,
        &zk.relays,
    );
    match verify_bip340(&zk.pk0, &msg, &zk.addr_sig) {
        Ok(()) => {}
        Err(Bip340Error::BadSignature) => return Err(ProfileCheckError::Check4BadAddrSig),
        Err(Bip340Error::InvalidPublicKey) => {
            return Err(ProfileCheckError::Check4Malformed {
                reason: "invalid x-only public key",
            })
        }
        Err(Bip340Error::MalformedSignature) => {
            return Err(ProfileCheckError::Check4Malformed {
                reason: "malformed BIP-340 signature",
            })
        }
    }

    // ---- Name checklist (only when reached by name) ----
    if let Some(name) = resolved_name {
        let normalized = normalize_name(name);
        let nip05 = content_json
            .get("nip05")
            .and_then(|v| v.as_str())
            .map(normalize_name);
        if nip05.as_deref() != Some(normalized.as_str()) {
            return Err(ProfileCheckError::NameReverseMismatch {
                expected: normalized,
                got: nip05,
            });
        }
        let name_msg = name_message(&zk.network, &normalized, expected_op).map_err(|e| {
            ProfileCheckError::Check5NameMessage {
                reason: e.to_string(),
            }
        })?;
        match verify_bip340(&zk.pk0, &name_msg, &zk.name_sig) {
            Ok(()) => {}
            Err(Bip340Error::BadSignature) => return Err(ProfileCheckError::Check5BadNameSig),
            Err(Bip340Error::InvalidPublicKey) => {
                return Err(ProfileCheckError::Check5Malformed {
                    reason: "invalid x-only public key",
                })
            }
            Err(Bip340Error::MalformedSignature) => {
                return Err(ProfileCheckError::Check5Malformed {
                    reason: "malformed BIP-340 signature",
                })
            }
        }
    }

    Ok(VerifiedPaymentProfile {
        op_pubkey: *expected_op,
        address: zk.address,
        pk0: zk.pk0,
        nk_commit: zk.nk_commit,
        ivpk: zk.ivpk,
        relays: zk.relays,
        network: zk.network,
        event: event.clone(),
    })
}

// ---------------------------------------------------------------------------
// Invoice checklist (i)/(ii)/(iii)
// ---------------------------------------------------------------------------

/// Verify a §4.3 `Invoice` in order: (i) address preimage, (ii) `addr_sig`
/// under `pk0`, (iii) `sig` under `op_pubkey`.
pub(crate) fn verify_invoice(invoice: &PaymentInvoice) -> Result<(), InvoiceCheckError> {
    if invoice.relays.is_empty() {
        return Err(InvoiceCheckError::InvalidRelays {
            reason: "relays must be non-empty",
        });
    }
    for url in &invoice.relays {
        validate_relay_url_invoice(url)?;
    }

    // (i)
    let computed = address_from_parts(&invoice.pk0, &invoice.nk_commit);
    if computed != invoice.recipient {
        return Err(InvoiceCheckError::Check1AddressMismatch {
            claimed: invoice.recipient,
            computed,
        });
    }

    let msg = invoice_message(InvoiceMessageParts {
        amount: invoice.amount,
        recipient: &invoice.recipient,
        pk0: &invoice.pk0,
        nk_commit: &invoice.nk_commit,
        asset_id: &invoice.asset_id,
        memo: invoice.memo.as_deref(),
        ivpk: &invoice.ivpk,
        op_pubkey: &invoice.op_pubkey,
        relays: &invoice.relays,
    });

    // (ii)
    match verify_bip340(&invoice.pk0, &msg, &invoice.addr_sig) {
        Ok(()) => {}
        Err(Bip340Error::BadSignature) => return Err(InvoiceCheckError::Check2BadAddrSig),
        Err(Bip340Error::InvalidPublicKey) => {
            return Err(InvoiceCheckError::Check2Malformed {
                reason: "invalid x-only public key",
            })
        }
        Err(Bip340Error::MalformedSignature) => {
            return Err(InvoiceCheckError::Check2Malformed {
                reason: "malformed BIP-340 signature",
            })
        }
    }

    // (iii)
    match verify_bip340(&invoice.op_pubkey, &msg, &invoice.sig) {
        Ok(()) => {}
        Err(Bip340Error::BadSignature) => return Err(InvoiceCheckError::Check3BadOpSig),
        Err(Bip340Error::InvalidPublicKey) => {
            return Err(InvoiceCheckError::Check3Malformed {
                reason: "invalid x-only public key",
            })
        }
        Err(Bip340Error::MalformedSignature) => {
            return Err(InvoiceCheckError::Check3Malformed {
                reason: "malformed BIP-340 signature",
            })
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Newest valid kind-0 selection (replaceable class)
// ---------------------------------------------------------------------------

/// NIP-01 replaceable ordering: higher `created_at` wins; on a timestamp
/// tie the **lowest** `id` (first in lexical / byte-wise order) is retained
/// and is therefore treated as newer. Only **already NIP-01-verified**
/// events may enter.
///
/// A lying relay cannot influence selection by injecting an event whose
/// signature does not verify — such events never appear in the pool's
/// aggregate (see [`RelayPool::query_all`]).
pub(crate) fn newer_replaceable(a: &Event, b: &Event) -> bool {
    match a.created_at.cmp(&b.created_at) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        // NIP-01: same timestamp → lowest id retained (first in lexical order).
        std::cmp::Ordering::Equal => a.id < b.id,
    }
}

/// Among NIP-01-verified kind-0 events by `op_pubkey`, walk newest-first and
/// return the first that passes the payment-object checklist.
pub(crate) fn select_newest_valid_payment_profile(
    events: &[Event],
    op_pubkey: &[u8; 32],
    expected_network: &str,
    resolved_name: Option<&str>,
) -> Result<VerifiedPaymentProfile, ProfileResolveError> {
    let mut candidates: Vec<&Event> = events
        .iter()
        .filter(|e| e.kind == KIND_METADATA && &e.pubkey == op_pubkey)
        .collect();
    if candidates.is_empty() {
        return Err(ProfileResolveError::NoKind0Event);
    }
    candidates.sort_by(|a, b| {
        // Newest first via the shared replaceable order (§ NIP-01).
        match (newer_replaceable(a, b), newer_replaceable(b, a)) {
            (true, false) => std::cmp::Ordering::Less, // a newer → a first
            (false, true) => std::cmp::Ordering::Greater, // b newer → b first
            _ => std::cmp::Ordering::Equal,
        }
    });

    let mut last_err: Option<ProfileCheckError> = None;
    for event in candidates {
        match verify_payment_profile(event, op_pubkey, expected_network, resolved_name) {
            Ok(v) => return Ok(v),
            Err(e) => last_err = Some(e),
        }
    }
    Err(ProfileResolveError::NoValidPaymentProfile {
        last: last_err.expect("candidates non-empty"),
    })
}

// ---------------------------------------------------------------------------
// Resolve by op_pubkey (relay pool)
// ---------------------------------------------------------------------------

/// Fetch kind-0 for `op_pubkey` from the relay pool and run the payment
/// checklist. Union + per-event NIP-01 verify is done by the pool; this
/// layer only selects the newest valid payment object.
pub(crate) async fn resolve_profile_by_op_pubkey(
    pool: &RelayPool,
    op_pubkey: &[u8; 32],
    expected_network: &str,
) -> Result<VerifiedPaymentProfile, ProfileResolveError> {
    let filter = Filter {
        authors: Some(vec![*op_pubkey]),
        kinds: Some(vec![KIND_METADATA]),
        ..Filter::default()
    };
    let aggregate = pool.query_all(&[filter]).await;

    let any_ok = aggregate
        .per_relay
        .iter()
        .any(|o| matches!(o, RelayQueryOutcome::Ok { .. }));
    if !any_ok {
        return Err(ProfileResolveError::AllRelaysFailed);
    }

    select_newest_valid_payment_profile(&aggregate.events, op_pubkey, expected_network, None)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use serde_json::json;
    use shared::spec_v1::datastructures::Address;

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

    struct AccountKeys {
        sk0: [u8; 32],
        pk0: [u8; 32],
        op_sk: [u8; 32],
        op_pk: [u8; 32],
        nk_commit: [u8; 32],
        ivpk: [u8; 32],
        address: [u8; 32],
        address_bech32: String,
    }

    fn sample_account(label: &str) -> AccountKeys {
        let (sk0, pk0) = fixture_sk(format!("zkCoins/v1/test/profile/{label}/sk0").as_bytes());
        let (op_sk, op_pk) = fixture_sk(format!("zkCoins/v1/test/profile/{label}/op").as_bytes());
        let nk_commit = {
            let d: [u8; 32] = Sha256::digest(format!("nk-{label}").as_bytes()).into();
            d
        };
        let ivpk = {
            let (_, pk) = fixture_sk(format!("zkCoins/v1/test/profile/{label}/ivk").as_bytes());
            pk
        };
        let address = address_from_parts(&pk0, &nk_commit);
        let address_bech32 = Address(address).to_bech32m();
        AccountKeys {
            sk0,
            pk0,
            op_sk,
            op_pk,
            nk_commit,
            ivpk,
            address,
            address_bech32,
        }
    }

    fn build_zkcoins_json(
        acct: &AccountKeys,
        network: &str,
        relays: &[&str],
        ivpk: &[u8; 32],
        name: Option<&str>,
    ) -> (Value, [u8; 64], [u8; 64]) {
        let relays_owned: Vec<String> = relays.iter().map(|s| (*s).to_string()).collect();
        let inv_msg = profile_invoice_message(
            &acct.address,
            &acct.pk0,
            &acct.nk_commit,
            ivpk,
            &acct.op_pk,
            &relays_owned,
        );
        let addr_sig = sign_bip340(&acct.sk0, &inv_msg).expect("addr_sig");
        let name = name.unwrap_or("alice@example.com");
        let nm = name_message(network, name, &acct.op_pk).expect("name_message");
        let name_sig = sign_bip340(&acct.sk0, &nm).expect("name_sig");
        let obj = json!({
            "version": 1,
            "network": network,
            "address": acct.address_bech32,
            "pk0": hex::encode(acct.pk0),
            "nk_commit": hex::encode(acct.nk_commit),
            "ivpk": hex::encode(ivpk),
            "relays": relays,
            "addr_sig": hex::encode(addr_sig),
            "name_sig": hex::encode(name_sig),
        });
        (obj, addr_sig, name_sig)
    }

    fn sign_kind0(op_sk: &[u8; 32], created_at: u64, nip05: &str, zkcoins: &Value) -> Event {
        let content = json!({
            "name": "Alice",
            "nip05": nip05,
            "zkcoins": zkcoins,
        })
        .to_string();
        Event::sign(op_sk, created_at, KIND_METADATA, vec![], content).expect("sign kind-0")
    }

    // -----------------------------------------------------------------------
    // Check 2: closed content / zkcoins shape
    // -----------------------------------------------------------------------

    #[test]
    fn parse_zkcoins_object_rejects_non_object_content() {
        let err = parse_zkcoins_object(&json!([1, 2, 3]), "regtest")
            .expect_err("content root must be an object");
        assert_eq!(
            err,
            ProfileCheckError::Check2InvalidContentJson {
                reason: "content is not a JSON object",
            }
        );
    }

    #[test]
    fn parse_zkcoins_object_rejects_missing_zkcoins_key() {
        let err = parse_zkcoins_object(&json!({"name": "Alice"}), "regtest")
            .expect_err("zkcoins key must be present");
        assert_eq!(err, ProfileCheckError::Check2MissingZkcoins);
    }

    #[test]
    fn parse_zkcoins_object_rejects_non_object_zkcoins() {
        let err = parse_zkcoins_object(&json!({"zkcoins": "not an object"}), "regtest")
            .expect_err("zkcoins must be an object");
        assert_eq!(err, ProfileCheckError::Check2ZkcoinsNotObject);
    }

    #[test]
    fn parse_zkcoins_object_rejects_each_missing_required_field() {
        let acct = sample_account("missing-fields");
        let (zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );

        for field in ZKCOINS_FIELDS {
            let mut missing = zk.clone();
            let removed = missing
                .as_object_mut()
                .expect("fixture zkcoins is an object")
                .remove(field);
            assert!(removed.is_some(), "fixture must contain {field}");

            let err = parse_zkcoins_object(&json!({"zkcoins": missing}), "regtest")
                .expect_err("required field removal must fail");
            assert_eq!(
                err,
                ProfileCheckError::Check2MissingField { field },
                "wrong error for missing field {field}"
            );
        }
    }

    // -----------------------------------------------------------------------
    // Check 2: field validation
    // -----------------------------------------------------------------------

    #[test]
    fn parse_zkcoins_object_rejects_numeric_version_two() {
        let acct = sample_account("version-two");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk["version"] = json!(2);

        let err = parse_zkcoins_object(&json!({"zkcoins": zk}), "regtest")
            .expect_err("version 2 must fail");
        assert_eq!(
            err,
            ProfileCheckError::Check2Version {
                got: "2".to_string(),
            }
        );
    }

    #[test]
    fn parse_zkcoins_object_rejects_string_version_one() {
        let acct = sample_account("version-string");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk["version"] = json!("1");

        let err = parse_zkcoins_object(&json!({"zkcoins": zk}), "regtest")
            .expect_err("string version must fail");
        assert_eq!(
            err,
            ProfileCheckError::Check2Version {
                got: "\"1\"".to_string(),
            }
        );
    }

    #[test]
    fn parse_zkcoins_object_rejects_unknown_network_even_when_expected() {
        let acct = sample_account("closed-network");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk["network"] = json!("unknown");

        let err = parse_zkcoins_object(&json!({"zkcoins": zk}), "unknown")
            .expect_err("network labels are a closed set");
        assert_eq!(
            err,
            ProfileCheckError::Check2Network {
                expected: "unknown".to_string(),
                got: "unknown".to_string(),
            }
        );
    }

    #[test]
    fn parse_zkcoins_object_rejects_wrong_hex_width_with_field_name() {
        let acct = sample_account("hex-width");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk["pk0"] = json!("a".repeat(63));

        let err = parse_zkcoins_object(&json!({"zkcoins": zk}), "regtest")
            .expect_err("pk0 width must be exact");
        assert_eq!(
            err,
            ProfileCheckError::Check2InvalidHex {
                field: "pk0",
                reason: "wrong hex width",
            }
        );
    }

    #[test]
    fn parse_zkcoins_object_rejects_uppercase_hex_with_field_name() {
        let acct = sample_account("hex-uppercase");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk["nk_commit"] = json!("A".repeat(64));

        let err = parse_zkcoins_object(&json!({"zkcoins": zk}), "regtest")
            .expect_err("nk_commit must use lowercase hex");
        assert_eq!(
            err,
            ProfileCheckError::Check2InvalidHex {
                field: "nk_commit",
                reason: "must be lowercase hex",
            }
        );
    }

    #[test]
    fn parse_zkcoins_object_rejects_invalid_bech32m_address() {
        let acct = sample_account("invalid-address");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk["address"] = json!("not-an-address");

        let err = parse_zkcoins_object(&json!({"zkcoins": zk}), "regtest")
            .expect_err("address must be valid Bech32m");
        assert_eq!(
            err,
            ProfileCheckError::Check2InvalidAddress {
                reason: "bech32m decode error: parse failed".to_string(),
            }
        );
    }

    #[test]
    fn parse_zkcoins_object_rejects_non_array_relays() {
        let acct = sample_account("relays-not-array");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk["relays"] = json!("wss://relay.example.com");

        let err = parse_zkcoins_object(&json!({"zkcoins": zk}), "regtest")
            .expect_err("relays must be an array");
        assert_eq!(
            err,
            ProfileCheckError::Check2InvalidRelays {
                reason: "relays is not an array",
            }
        );
    }

    #[test]
    fn parse_zkcoins_object_rejects_empty_relays() {
        let acct = sample_account("relays-empty");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk["relays"] = json!([]);

        let err = parse_zkcoins_object(&json!({"zkcoins": zk}), "regtest")
            .expect_err("relays must be non-empty");
        assert_eq!(
            err,
            ProfileCheckError::Check2InvalidRelays {
                reason: "relays must be non-empty",
            }
        );
    }

    #[test]
    fn parse_zkcoins_object_rejects_non_string_relay_entry() {
        let acct = sample_account("relay-not-string");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk["relays"] = json!([123]);

        let err = parse_zkcoins_object(&json!({"zkcoins": zk}), "regtest")
            .expect_err("relay entries must be strings");
        assert_eq!(
            err,
            ProfileCheckError::Check2InvalidRelays {
                reason: "relay entry is not a string",
            }
        );
    }

    #[test]
    fn parse_zkcoins_object_rejects_non_websocket_relay_url() {
        let acct = sample_account("relay-url");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk["relays"] = json!(["http://bad"]);

        let err = parse_zkcoins_object(&json!({"zkcoins": zk}), "regtest")
            .expect_err("relay URL must use WebSocket transport");
        assert_eq!(
            err,
            ProfileCheckError::Check2InvalidRelayUrl {
                url: "http://bad".to_string(),
            }
        );
    }

    // -----------------------------------------------------------------------
    // Check 4: foreign ivpk attack
    // -----------------------------------------------------------------------

    /// Attacker reuses a real `address`/`pk0`/`nk_commit` (public) but
    /// substitutes their own `ivpk`. The original `addr_sig` covered a
    /// different `invoice_message` (different `ivpk`), so check 4 rejects.
    /// Without `sk0`, the attacker cannot produce a new valid `addr_sig`.
    #[test]
    fn foreign_ivpk_rejected_at_check_4() {
        let victim = sample_account("victim");
        let attacker_ivpk = {
            let (_, pk) = fixture_sk(b"zkCoins/v1/test/profile/attacker-ivpk");
            pk
        };
        let relays = ["wss://relay.example.com"];

        // Legitimate profile (honest ivpk) — produces a real addr_sig.
        let (honest_zk, honest_addr_sig, _) =
            build_zkcoins_json(&victim, "regtest", &relays, &victim.ivpk, None);

        // Malicious object: same address/pk0/nk_commit, foreign ivpk, **reused**
        // honest addr_sig (valid BIP-340 bytes, wrong message).
        let mut evil_zk = honest_zk;
        evil_zk["ivpk"] = json!(hex::encode(attacker_ivpk));
        evil_zk["addr_sig"] = json!(hex::encode(honest_addr_sig));

        // Event signed under victim's op (or attacker's — either way check 4
        // is the binding that fails). Use victim op so check 1 passes.
        let event = sign_kind0(&victim.op_sk, 1_700_000_000, "alice@example.com", &evil_zk);

        let err = verify_payment_profile(&event, &victim.op_pk, "regtest", None)
            .expect_err("foreign ivpk must fail");
        assert!(
            matches!(err, ProfileCheckError::Check4BadAddrSig),
            "expected Check4BadAddrSig (address↔ivpk binding), got {err:?}"
        );

        // Confirm checks 1–3 would pass for the same material with honest sig:
        let (good_zk, _, _) = build_zkcoins_json(&victim, "regtest", &relays, &victim.ivpk, None);
        let good = sign_kind0(&victim.op_sk, 1_700_000_001, "alice@example.com", &good_zk);
        let verified =
            verify_payment_profile(&good, &victim.op_pk, "regtest", None).expect("honest ok");
        assert_eq!(verified.ivpk, victim.ivpk);
        assert_eq!(verified.address, victim.address);
    }

    /// Same attack with a **fresh** BIP-340 signature under an attacker key
    /// (not `pk0`): still fails check 4 — the sig must be under `pk0`.
    #[test]
    fn foreign_ivpk_signed_by_attacker_key_rejected_at_check_4() {
        let victim = sample_account("victim2");
        let (attacker_sk, attacker_ivpk) = fixture_sk(b"zkCoins/v1/test/profile/attacker-sk");
        let relays = ["wss://relay.example.com"];
        let relays_owned = vec![relays[0].to_string()];
        let msg = profile_invoice_message(
            &victim.address,
            &victim.pk0,
            &victim.nk_commit,
            &attacker_ivpk,
            &victim.op_pk,
            &relays_owned,
        );
        // Sign under attacker key — valid Schnorr, wrong public key for check 4.
        let evil_sig = sign_bip340(&attacker_sk, &msg).expect("attacker sig");
        let zk = json!({
            "version": 1,
            "network": "regtest",
            "address": victim.address_bech32,
            "pk0": hex::encode(victim.pk0),
            "nk_commit": hex::encode(victim.nk_commit),
            "ivpk": hex::encode(attacker_ivpk),
            "relays": relays,
            "addr_sig": hex::encode(evil_sig),
            "name_sig": hex::encode([0u8; 64]),
        });
        let event = sign_kind0(&victim.op_sk, 1, "alice@example.com", &zk);
        let err = verify_payment_profile(&event, &victim.op_pk, "regtest", None)
            .expect_err("must fail check 4");
        assert!(
            matches!(err, ProfileCheckError::Check4BadAddrSig),
            "got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Checklist ordering / structure
    // -----------------------------------------------------------------------

    #[test]
    fn check_1_rejects_wrong_event_kind() {
        let acct = sample_account("wrong-kind");
        let event = Event::sign(&acct.op_sk, 1, 1, vec![], "{}".to_string())
            .expect("sign kind-1 event");

        let err = verify_payment_profile(&event, &acct.op_pk, "regtest", None)
            .expect_err("kind 1 must fail profile check 1");
        assert_eq!(err, ProfileCheckError::Check1WrongKind { kind: 1 });
    }

    #[test]
    fn check_1_rejects_author_mismatch() {
        let acct = sample_account("auth");
        let (zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        let event = sign_kind0(&acct.op_sk, 1, "alice@example.com", &zk);
        let other = sample_account("other");
        let err = verify_payment_profile(&event, &other.op_pk, "regtest", None)
            .expect_err("author mismatch");
        match err {
            ProfileCheckError::Check1AuthorMismatch {
                event_pubkey,
                expected_op,
            } => {
                assert_eq!(event_pubkey, acct.op_pk);
                assert_eq!(expected_op, other.op_pk);
            }
            other => panic!("expected Check1AuthorMismatch, got {other:?}"),
        }
    }

    #[test]
    fn check_1_rejects_content_mutated_after_signing_as_id_mismatch() {
        let acct = sample_account("mutated-content");
        let (zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        let mut event = sign_kind0(&acct.op_sk, 1, "alice@example.com", &zk);
        let signed_id = event.id;
        event.content.push(' ');

        let err = verify_payment_profile(&event, &acct.op_pk, "regtest", None)
            .expect_err("mutated signed content must fail NIP-01 verification");
        match err {
            ProfileCheckError::Check1BadSignature(EventError::IdMismatch {
                claimed,
                computed,
            }) => {
                assert_eq!(claimed, signed_id);
                assert_ne!(computed, claimed);
            }
            other => panic!("expected Check1BadSignature(IdMismatch), got {other:?}"),
        }
    }

    #[test]
    fn check_2_rejects_non_json_event_content() {
        let acct = sample_account("non-json-content");
        let event = Event::sign(
            &acct.op_sk,
            1,
            KIND_METADATA,
            vec![],
            "not json {".to_string(),
        )
        .expect("sign kind-0 with non-JSON content");

        let err = verify_payment_profile(&event, &acct.op_pk, "regtest", None)
            .expect_err("non-JSON event content must fail check 2");
        assert_eq!(
            err,
            ProfileCheckError::Check2InvalidContentJson {
                reason: "content is not JSON",
            }
        );
    }

    #[test]
    fn check_2_rejects_unknown_field_and_op_pubkey_duplicate() {
        let acct = sample_account("extra");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk["surprise"] = json!(true);
        let event = sign_kind0(&acct.op_sk, 1, "alice@example.com", &zk);
        let err = verify_payment_profile(&event, &acct.op_pk, "regtest", None).unwrap_err();
        match err {
            ProfileCheckError::Check2ExtraField { field } => assert_eq!(field, "surprise"),
            other => panic!("expected Check2ExtraField, got {other:?}"),
        }

        let (mut zk2, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        zk2["op_pubkey"] = json!(hex::encode(acct.op_pk));
        let event2 = sign_kind0(&acct.op_sk, 2, "alice@example.com", &zk2);
        let err2 = verify_payment_profile(&event2, &acct.op_pk, "regtest", None).unwrap_err();
        assert!(
            matches!(err2, ProfileCheckError::Check2OpPubkeyDuplicated),
            "got {err2:?}"
        );
    }

    #[test]
    fn check_2_rejects_wrong_network_no_default() {
        let acct = sample_account("net");
        let (zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        let event = sign_kind0(&acct.op_sk, 1, "alice@example.com", &zk);
        // Caller expects mainnet; profile says regtest — no silent accept.
        let err = verify_payment_profile(&event, &acct.op_pk, "mainnet", None).unwrap_err();
        match err {
            ProfileCheckError::Check2Network { expected, got } => {
                assert_eq!(expected, "mainnet");
                assert_eq!(got, "regtest");
            }
            other => panic!("expected Check2Network, got {other:?}"),
        }
    }

    #[test]
    fn check_3_rejects_address_not_preimage() {
        let acct = sample_account("preimage");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        // Keep pk0/nk_commit but replace address with an unrelated Bech32m value.
        let fake = Address([0x42; 32]).to_bech32m();
        zk["address"] = json!(fake);
        // Re-sign addr_sig would still be over real address in honest path;
        // here we only care that check 3 fires before check 4. Rebuild event.
        let event = sign_kind0(&acct.op_sk, 1, "alice@example.com", &zk);
        let err = verify_payment_profile(&event, &acct.op_pk, "regtest", None).unwrap_err();
        match err {
            ProfileCheckError::Check3AddressMismatch { claimed, computed } => {
                assert_eq!(claimed, [0x42; 32]);
                assert_eq!(computed, acct.address);
            }
            other => panic!("expected Check3AddressMismatch, got {other:?}"),
        }
    }

    #[test]
    fn check_4_rejects_invalid_xonly_pk0_after_consistent_address_check() {
        let acct = sample_account("invalid-pk0");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        let invalid_pk0 = [0u8; 32];
        let consistent_address = address_from_parts(&invalid_pk0, &acct.nk_commit);
        zk["pk0"] = json!(hex::encode(invalid_pk0));
        zk["address"] = json!(Address(consistent_address).to_bech32m());
        let event = sign_kind0(&acct.op_sk, 1, "alice@example.com", &zk);

        let err = verify_payment_profile(&event, &acct.op_pk, "regtest", None)
            .expect_err("invalid x-only pk0 must fail check 4");
        assert_eq!(
            err,
            ProfileCheckError::Check4Malformed {
                reason: "invalid x-only public key",
            }
        );
    }

    #[test]
    fn name_checklist_requires_reverse_nip05_and_name_sig() {
        let acct = sample_account("name");
        let (zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            Some("alice@example.com"),
        );
        let event = sign_kind0(&acct.op_sk, 1, "alice@example.com", &zk);

        // By op_pubkey only — name checklist not run.
        verify_payment_profile(&event, &acct.op_pk, "regtest", None).expect("op path");

        // By name — reverse match + name_sig.
        verify_payment_profile(
            &event,
            &acct.op_pk,
            "regtest",
            Some("Alice@Example.com"), // normalized
        )
        .expect("name path");

        // Wrong nip05 in content.
        let event_bad = sign_kind0(&acct.op_sk, 2, "bob@evil.com", &zk);
        let err = verify_payment_profile(
            &event_bad,
            &acct.op_pk,
            "regtest",
            Some("alice@example.com"),
        )
        .unwrap_err();
        match err {
            ProfileCheckError::NameReverseMismatch { expected, got } => {
                assert_eq!(expected, "alice@example.com");
                assert_eq!(got.as_deref(), Some("bob@evil.com"));
            }
            other => panic!("expected NameReverseMismatch, got {other:?}"),
        }
    }

    #[test]
    fn check_5_rejects_invalid_name_message_syntax() {
        let acct = sample_account("invalid-name-message");
        let (zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        let event = sign_kind0(&acct.op_sk, 1, "invalid", &zk);

        let err = verify_payment_profile(
            &event,
            &acct.op_pk,
            "regtest",
            Some("invalid"),
        )
        .expect_err("name without @ must fail name-message construction");
        assert_eq!(
            err,
            ProfileCheckError::Check5NameMessage {
                reason: "identifier missing '@' separator (§4.3)".to_string(),
            }
        );
    }

    #[test]
    fn name_sig_failure_is_check_5() {
        let acct = sample_account("namesig");
        let (mut zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            Some("alice@example.com"),
        );
        zk["name_sig"] = json!(hex::encode([0xabu8; 64]));
        let event = sign_kind0(&acct.op_sk, 1, "alice@example.com", &zk);
        let err = verify_payment_profile(&event, &acct.op_pk, "regtest", Some("alice@example.com"))
            .unwrap_err();
        assert!(
            matches!(
                err,
                ProfileCheckError::Check5BadNameSig | ProfileCheckError::Check5Malformed { .. }
            ),
            "got {err:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Newest valid kind-0 / lying relay
    // -----------------------------------------------------------------------

    #[test]
    fn newest_valid_kind0_reports_no_kind0_event_for_empty_input() {
        let acct = sample_account("no-kind0");
        let err = select_newest_valid_payment_profile(
            &[],
            &acct.op_pk,
            "regtest",
            None,
        )
        .expect_err("empty input has no kind-0 candidate");
        assert_eq!(err, ProfileResolveError::NoKind0Event);
    }

    #[test]
    fn newest_valid_kind0_reports_last_concrete_profile_error() {
        let acct = sample_account("no-valid-profile");
        let (zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        let event = sign_kind0(&acct.op_sk, 1, "alice@example.com", &zk);

        let err = select_newest_valid_payment_profile(
            &[event],
            &acct.op_pk,
            "mainnet",
            None,
        )
        .expect_err("wrong-network candidate must not resolve");
        assert_eq!(
            err,
            ProfileResolveError::NoValidPaymentProfile {
                last: ProfileCheckError::Check2Network {
                    expected: "mainnet".to_string(),
                    got: "regtest".to_string(),
                },
            }
        );
    }

    #[test]
    fn newest_valid_kind0_ignores_unverified_and_picks_by_created_at() {
        let acct = sample_account("newest");
        let (zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        let older = sign_kind0(&acct.op_sk, 100, "alice@example.com", &zk);
        let newer = sign_kind0(&acct.op_sk, 200, "alice@example.com", &zk);

        // Only verified events are in the input (pool contract). Newest wins.
        let v = select_newest_valid_payment_profile(
            &[older.clone(), newer.clone()],
            &acct.op_pk,
            "regtest",
            None,
        )
        .expect("select");
        assert_eq!(v.event.created_at, 200);
        assert_eq!(v.event.id, newer.id);

        // A foreign author event must not be selected even if newer.
        let other = sample_account("intruder");
        let (zk_o, _, _) = build_zkcoins_json(
            &other,
            "regtest",
            &["wss://relay.example.com"],
            &other.ivpk,
            None,
        );
        let intruder = sign_kind0(&other.op_sk, 999, "eve@evil.com", &zk_o);
        let v2 = select_newest_valid_payment_profile(
            &[older, newer, intruder],
            &acct.op_pk,
            "regtest",
            None,
        )
        .expect("select");
        assert_eq!(v2.event.created_at, 200);
        assert_eq!(v2.op_pubkey, acct.op_pk);
    }

    #[test]
    fn newer_replaceable_orders_by_created_at_then_id() {
        let acct = sample_account("order");
        let (zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        // Same created_at, different content → different NIP-01 id (sig is not
        // in the id preimage; content is). Lowest id is retained (NIP-01).
        let a = sign_kind0(&acct.op_sk, 50, "alice@example.com", &zk);
        let b = sign_kind0(&acct.op_sk, 50, "bob@example.com", &zk);
        assert_ne!(
            a.id, b.id,
            "content differs so NIP-01 ids must differ; otherwise the tie branch is never reached"
        );
        if a.id < b.id {
            assert!(
                newer_replaceable(&a, &b),
                "same created_at: lower id must win"
            );
            assert!(!newer_replaceable(&b, &a));
        } else {
            assert!(
                newer_replaceable(&b, &a),
                "same created_at: lower id must win"
            );
            assert!(!newer_replaceable(&a, &b));
        }
        let c = sign_kind0(&acct.op_sk, 51, "alice@example.com", &zk);
        assert!(newer_replaceable(&c, &a));
        assert!(!newer_replaceable(&a, &c));
    }

    #[test]
    fn newer_replaceable_identical_events_neither_newer() {
        let acct = sample_account("order-ident");
        let (zk, _, _) = build_zkcoins_json(
            &acct,
            "regtest",
            &["wss://relay.example.com"],
            &acct.ivpk,
            None,
        );
        // Same pubkey/created_at/kind/tags/content → same id (sig not hashed).
        let a = sign_kind0(&acct.op_sk, 50, "alice@example.com", &zk);
        let b = sign_kind0(&acct.op_sk, 50, "alice@example.com", &zk);
        assert_eq!(
            a.id, b.id,
            "identical id-preimage fields must yield identical NIP-01 ids"
        );
        assert!(!newer_replaceable(&a, &b));
        assert!(!newer_replaceable(&b, &a));
    }

    // -----------------------------------------------------------------------
    // Invoice (i)/(ii)/(iii)
    // -----------------------------------------------------------------------

    fn sample_invoice(acct: &AccountKeys) -> PaymentInvoice {
        let relays = vec!["wss://relay.example.com".to_string()];
        let amount = 42u128;
        let asset_id = [0x07u8; 32];
        let memo = Some("coffee".to_string());
        let msg = invoice_message(InvoiceMessageParts {
            amount,
            recipient: &acct.address,
            pk0: &acct.pk0,
            nk_commit: &acct.nk_commit,
            asset_id: &asset_id,
            memo: memo.as_deref(),
            ivpk: &acct.ivpk,
            op_pubkey: &acct.op_pk,
            relays: &relays,
        });
        let addr_sig = sign_bip340(&acct.sk0, &msg).expect("addr_sig");
        let sig = sign_bip340(&acct.op_sk, &msg).expect("op sig");
        PaymentInvoice {
            amount,
            recipient: acct.address,
            asset_id,
            memo,
            pk0: acct.pk0,
            nk_commit: acct.nk_commit,
            ivpk: acct.ivpk,
            op_pubkey: acct.op_pk,
            relays,
            addr_sig,
            sig,
        }
    }

    #[test]
    fn invoice_roundtrip_accepts_honest() {
        let acct = sample_account("inv");
        let inv = sample_invoice(&acct);
        verify_invoice(&inv).expect("honest invoice");
    }

    #[test]
    fn invoice_rejects_empty_relays() {
        let acct = sample_account("inv-empty-relays");
        let mut inv = sample_invoice(&acct);
        inv.relays.clear();

        let err = verify_invoice(&inv).expect_err("invoice relays must be non-empty");
        assert_eq!(
            err,
            InvoiceCheckError::InvalidRelays {
                reason: "relays must be non-empty",
            }
        );
    }

    #[test]
    fn invoice_rejects_non_websocket_relay_url() {
        let acct = sample_account("inv-relay-url");
        let mut inv = sample_invoice(&acct);
        inv.relays = vec!["http://bad".to_string()];

        let err =
            verify_invoice(&inv).expect_err("invoice relay URL must use WebSocket transport");
        assert_eq!(
            err,
            InvoiceCheckError::InvalidRelayUrl {
                url: "http://bad".to_string(),
            }
        );
    }

    #[test]
    fn invoice_check_ii_rejects_invalid_xonly_pk0_after_consistent_address_check() {
        let acct = sample_account("inv-invalid-pk0");
        let mut inv = sample_invoice(&acct);
        inv.pk0 = [0u8; 32];
        inv.recipient = address_from_parts(&inv.pk0, &inv.nk_commit);

        let err =
            verify_invoice(&inv).expect_err("invalid x-only pk0 must fail check (ii)");
        assert_eq!(
            err,
            InvoiceCheckError::Check2Malformed {
                reason: "invalid x-only public key",
            }
        );
    }

    #[test]
    fn invoice_check_iii_rejects_invalid_xonly_op_pubkey() {
        let acct = sample_account("inv-invalid-op");
        let mut inv = sample_invoice(&acct);
        inv.op_pubkey = [0u8; 32];
        let msg = invoice_message(InvoiceMessageParts {
            amount: inv.amount,
            recipient: &inv.recipient,
            pk0: &inv.pk0,
            nk_commit: &inv.nk_commit,
            asset_id: &inv.asset_id,
            memo: inv.memo.as_deref(),
            ivpk: &inv.ivpk,
            op_pubkey: &inv.op_pubkey,
            relays: &inv.relays,
        });
        inv.addr_sig = sign_bip340(&acct.sk0, &msg).expect("re-sign check (ii) message");

        let err =
            verify_invoice(&inv).expect_err("invalid x-only op_pubkey must fail check (iii)");
        assert_eq!(
            err,
            InvoiceCheckError::Check3Malformed {
                reason: "invalid x-only public key",
            }
        );
    }

    #[test]
    fn invoice_foreign_ivpk_fails_check_ii() {
        let acct = sample_account("inv-ivpk");
        let mut inv = sample_invoice(&acct);
        inv.ivpk = [0x99; 32];
        // Keep original addr_sig (bound to old ivpk) → (ii) fails.
        let err = verify_invoice(&inv).expect_err("ivpk swap");
        assert!(
            matches!(err, InvoiceCheckError::Check2BadAddrSig),
            "got {err:?}"
        );
    }

    #[test]
    fn invoice_address_mismatch_fails_check_i() {
        let acct = sample_account("inv-addr");
        let mut inv = sample_invoice(&acct);
        inv.recipient = [0x01; 32];
        let err = verify_invoice(&inv).expect_err("addr");
        match err {
            InvoiceCheckError::Check1AddressMismatch { claimed, computed } => {
                assert_eq!(claimed, [0x01; 32]);
                assert_eq!(computed, acct.address);
            }
            other => panic!("expected Check1AddressMismatch, got {other:?}"),
        }
    }

    #[test]
    fn invoice_bad_op_sig_fails_check_iii() {
        let acct = sample_account("inv-op");
        let mut inv = sample_invoice(&acct);
        inv.sig = [0xcc; 64];
        let err = verify_invoice(&inv).expect_err("op sig");
        assert!(
            matches!(
                err,
                InvoiceCheckError::Check3BadOpSig | InvoiceCheckError::Check3Malformed { .. }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn invoice_message_framing_is_order_sensitive() {
        let acct = sample_account("frame");
        let relays = vec!["wss://a".into(), "wss://b".into()];
        let a = invoice_message(InvoiceMessageParts {
            amount: 1,
            recipient: &acct.address,
            pk0: &acct.pk0,
            nk_commit: &acct.nk_commit,
            asset_id: &[0; 32],
            memo: Some("x"),
            ivpk: &acct.ivpk,
            op_pubkey: &acct.op_pk,
            relays: &relays,
        });
        let reversed = ["wss://b".into(), "wss://a".into()];
        let b = invoice_message(InvoiceMessageParts {
            amount: 1,
            recipient: &acct.address,
            pk0: &acct.pk0,
            nk_commit: &acct.nk_commit,
            asset_id: &[0; 32],
            memo: Some("x"),
            ivpk: &acct.ivpk,
            op_pubkey: &acct.op_pk,
            relays: &reversed,
        });
        assert_ne!(a, b, "relay order is part of the preimage");
        let c = invoice_message(InvoiceMessageParts {
            amount: 1,
            recipient: &acct.address,
            pk0: &acct.pk0,
            nk_commit: &acct.nk_commit,
            asset_id: &[0; 32],
            memo: None,
            ivpk: &acct.ivpk,
            op_pubkey: &acct.op_pk,
            relays: &relays,
        });
        assert_ne!(a, c, "memo presence changes the preimage");
    }
}
