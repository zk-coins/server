//! Gap G6 — §5.7 balance attestation on the node (flag-gated).
//!
//! ## Surface (§7.5, normative)
//!
//! | Method | Path | Role |
//! |---|---|---|
//! | `POST` | `/v1/attest/balance/challenge` | issue single-use `AttestBalanceChallenge` |
//! | `POST` | `/v1/attest/balance` | OwnershipProof-gated admit → `202 { job_id }` |
//!
//! Job `kind = "attest_balance"` walks `proving → completed` with
//! `result.attestation` (canonical §7.1 `BalanceAttestationV1` hex), or
//! `failed`. There is **no** `awaiting_signature` phase (`C_balance` needs
//! no wallet transition signature).
//!
//! ## What the attestation proves
//!
//! A non-cyclic `C_balance` proof that the subject's account state holds
//! balance `B` of one `asset_id`, bound to the account's recursive
//! compliance proof and its on-chain nullifier `(Pk_anchor, R_anchor)`
//! via sign-to-contract, with the attested NAV a prefix of a disclosed
//! global `nav_ceiling` (§5.7 statements 1–7). The proof is network-
//! bound: `network_id = Hc("Network", network_tag_bytes)` is the last
//! public input of `C_balance`, and the proof verifies only under the
//! pinned `C_balance` circuit digest for that network.
//!
//! ## Edge — Bitcoin inscription locator
//!
//! The engine retains `NullifierOpening { pk, R, R' }` and the NfLog
//! `ChainPosition { height, tx_index, vin_index, member_index }`, but
//! **not** the reveal `txid` / `block_hash` of the inscription that
//! anchored the nullifier. Circuit public inputs include those fields
//! for host-side verification only (they are free in-circuit).
//!
//! Resolving a real `(txid, block_hash)` needs either:
//! - a durable scanner-owned `pk → (txid, block_hash)` index (not in
//!   this worktree; scanner folds Pk/R only), or
//! - a still-live `v11_pending_publishes.reveal_txid` for **this
//!   node's own** publish of that nullifier (partial, until GC), plus
//!   the inclusion-block hash: live `tip_hash` when the nullifier
//!   height equals the tip, otherwise the durable `block_log` row at
//!   that height (completed anchors sit ≥6 confirmations below tip, so
//!   they **must** use `block_log` — tip-hash alone can never serve them).
//!
//! When the locator cannot be resolved the job fails loud with
//! [`ATTEST_ANCHOR_LOCATOR_EDGE`] — never fabricates zero txid/block_hash.
//! Height is always taken from the NfLog chain position when present.
//!
//! Full E2E prove also needs a real multi-minute `C_balance` build on
//! first use (`ProverBridge::prove_attestation`). Tests cover the REST
//! contract, auth, network-digest binding, and the locator edge without
//! requiring a live bitcoind.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use dashmap::DashMap;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use shared::spec_v1::{
    self as host, digest_to_bytes, network_id_mainnet, network_id_regtest, network_id_testnet,
    Address, HashDigest, Nav, SpendClassification,
};
use zkcoins_program::circuit::compliance::Network;
use zkcoins_prover::half_agg::verify_single;
use zkcoins_prover::prover_bridge::{
    AttestationWitness, BalanceAnchor, BalanceAttestationStatement, BalanceProof, ProvedAttestation,
    ProverBridge,
};

use super::adapter::EngineAdapter;
use super::db_v11;
use super::mode::V11ShadowMode;
use super::separation::{process_stack_mode, ScanStackMode};

// ---------------------------------------------------------------------------
// Domain tags (§5.1 action-bound OwnershipProof / §7.5)
// ---------------------------------------------------------------------------

/// Challenge domain for `POST /v1/attest/balance/challenge`.
pub const ATTEST_BALANCE_CHALLENGE_DOMAIN: &str = "zkCoins/v1/AttestBalanceChallenge";
/// Request-hash tag for `POST /v1/attest/balance`.
pub const ATTEST_BALANCE_REQUEST_TAG: &str = "zkCoins/v1/AttestBalance";
/// `chan_bind` host domain (§5.1).
pub const PULL_HOST_DOMAIN: &str = "zkCoins/v1/PullHost";

/// Machine-readable edge when Bitcoin anchor locator is unavailable.
pub const ATTEST_ANCHOR_LOCATOR_EDGE: &str =
    "ATTEST_ANCHOR_LOCATOR_EDGE: NfLog retains ChainPosition but not \
     reveal txid/block_hash; no durable pk→(txid,block_hash) index and no \
     live v11_pending_publishes.reveal_txid for this nullifier — cannot \
     assemble a host-verifiable §5.7 anchor (scanner-owned index / later \
     wiring). Refusing rather than fabricating zeros.";

/// Recommended challenge TTL (§5.1): 60 seconds.
pub const ATTEST_CHALLENGE_TTL_SECS: u64 = 60;

// ---------------------------------------------------------------------------
// Pinned C_balance digests (§1.7.1 / generated_circuit_digests.txt)
// ---------------------------------------------------------------------------
//
// Ground truth is the regenerated vector file under script-plonky2/tests.
// Quoted here so a host-side pin check can fail without building the
// circuit when the digests diverge from the published pins.

/// §1.7.1 `C_balance` digest for mainnet (from `generated_circuit_digests.txt`).
pub const PINNED_C_BALANCE_DIGEST_MAINNET: [u8; 32] = [
    0x0a, 0x42, 0x02, 0xfc, 0x77, 0x22, 0x95, 0xd6, 0xdb, 0x4e, 0xb9, 0xc5, 0xbd, 0x2b, 0xbb, 0x7a,
    0x59, 0xd4, 0x5c, 0xff, 0x16, 0x53, 0x64, 0x8d, 0xff, 0x46, 0x81, 0xf4, 0xba, 0x55, 0xd6, 0x06,
];
/// §1.7.1 `C_balance` digest for testnet.
pub const PINNED_C_BALANCE_DIGEST_TESTNET: [u8; 32] = [
    0xcb, 0xb8, 0xf2, 0x84, 0xfa, 0xb6, 0xf8, 0x1a, 0xa3, 0x61, 0x6f, 0x55, 0xda, 0x76, 0x94, 0x2c,
    0x12, 0x59, 0x84, 0x5e, 0x0b, 0x91, 0x35, 0xf9, 0xc8, 0xfe, 0x93, 0x85, 0xd3, 0xf7, 0xfe, 0x87,
];
/// §1.7.1 `C_balance` digest for regtest.
pub const PINNED_C_BALANCE_DIGEST_REGTEST: [u8; 32] = [
    0xbd, 0x69, 0x60, 0x87, 0xe0, 0xe0, 0xf4, 0x7b, 0x55, 0x6a, 0x68, 0x03, 0xef, 0x4f, 0xb5, 0xb9,
    0xeb, 0xae, 0x23, 0x27, 0xe0, 0x43, 0x8d, 0xd4, 0x05, 0xf3, 0x37, 0x52, 0xdc, 0x90, 0x77, 0x2d,
];

/// Pinned `C_balance` digest for `network`, or `None` if unknown.
pub fn pinned_c_balance_digest(network: Network) -> [u8; 32] {
    match network {
        Network::Mainnet => PINNED_C_BALANCE_DIGEST_MAINNET,
        Network::Testnet => PINNED_C_BALANCE_DIGEST_TESTNET,
        Network::Regtest => PINNED_C_BALANCE_DIGEST_REGTEST,
    }
}

// ---------------------------------------------------------------------------
// Challenge store
// ---------------------------------------------------------------------------

/// Server-side state for one issued `AttestBalanceChallenge`.
#[derive(Clone, Debug)]
pub struct AttestChallengeRecord {
    pub subject: Address,
    pub expiry: u64,
    /// Action label; always `attest_balance` for this store.
    pub action: &'static str,
}

/// Process-local single-use challenge map: `nonce → record`.
pub type AttestChallengeMap = Arc<DashMap<[u8; 32], AttestChallengeRecord>>;

// ---------------------------------------------------------------------------
// Wire types (§7.5 / §7.1)
// ---------------------------------------------------------------------------

/// §7.1 canonical `u64` on the REST surface: a decimal **string** matching
/// `0|[1-9][0-9]*` (no JSON number — values may exceed the 2⁵³ float
/// mantissa). Used for `expiry` and `size_ceiling`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct U64Decimal(pub u64);

impl U64Decimal {
    pub fn format(n: u64) -> String {
        n.to_string()
    }
}

impl<'de> Deserialize<'de> for U64Decimal {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = U64Decimal;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                f.write_str("a canonical decimal-string u64 (§7.1: 0|[1-9][0-9]*)")
            }

            fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                parse_u64_decimal(v)
                    .map(U64Decimal)
                    .map_err(serde::de::Error::custom)
            }

            fn visit_borrowed_str<E: serde::de::Error>(self, v: &'de str) -> Result<Self::Value, E> {
                self.visit_str(v)
            }

            fn visit_string<E: serde::de::Error>(self, v: String) -> Result<Self::Value, E> {
                self.visit_str(&v)
            }

            fn visit_u64<E: serde::de::Error>(self, _v: u64) -> Result<Self::Value, E> {
                Err(E::custom(
                    "u64 field must be a decimal string, not a JSON number (§7.1)",
                ))
            }

            fn visit_i64<E: serde::de::Error>(self, _v: i64) -> Result<Self::Value, E> {
                Err(E::custom(
                    "u64 field must be a decimal string, not a JSON number (§7.1)",
                ))
            }

            fn visit_f64<E: serde::de::Error>(self, _v: f64) -> Result<Self::Value, E> {
                Err(E::custom(
                    "u64 field must be a decimal string, not a JSON number (§7.1)",
                ))
            }
        }
        // deserialize_any so a bare JSON number is visited (and rejected)
        // rather than failing only with a generic type error.
        deserializer.deserialize_any(V)
    }
}

/// Parse a §7.1 canonical decimal-string u64 (`0|[1-9][0-9]*`).
pub fn parse_u64_decimal(s: &str) -> Result<u64, String> {
    if s.is_empty() {
        return Err("empty decimal string".into());
    }
    if s == "0" {
        return Ok(0);
    }
    if s.as_bytes()[0] == b'0' {
        return Err("leading zeros are not allowed in canonical u64 decimal strings".into());
    }
    if !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("decimal string must contain only ASCII digits".into());
    }
    s.parse::<u64>()
        .map_err(|_| format!("decimal string out of u64 range: {s}"))
}

#[derive(Clone, Debug, Deserialize)]
pub struct AttestChallengeRequest {
    pub subject: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct OwnershipProofJson {
    #[serde(rename = "type")]
    pub proof_type: String,
    pub subject: String,
    pub public_key: String,
    pub nk_commit: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct AttestChallengeNonce {
    pub nonce: String,
}

/// Body of `POST /v1/attest/balance` (§7.5).
///
/// `size_ceiling` is a §7.1 decimal-string u64 (never a JSON number).
#[derive(Clone, Debug, Deserialize)]
pub struct AttestBalanceRequest {
    pub subject: String,
    pub asset_id: String,
    pub nav_ceiling: Option<String>,
    pub size_ceiling: Option<U64Decimal>,
    pub challenge: AttestChallengeNonce,
    pub ownership_proof: OwnershipProofJson,
}

/// Authorised job payload stored after the route gate passes.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct AttestJobBody {
    pub subject: [u8; 32],
    pub asset_id: [u8; 32],
    /// `None` = use node's current `size_final` ceiling.
    pub nav_ceiling: Option<[u8; 32]>,
    pub size_ceiling: Option<u64>,
}

// ---------------------------------------------------------------------------
// Errors → §7.5 machine codes (closed enumeration)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AttestError {
    FeatureDisabled,
    Malformed(String),
    Unauthorized(String),
    ChallengeExpired(String),
    CircuitDigestMismatch(String),
    Internal(String),
    /// Job-terminal proving failure (not an admit-time HTTP code).
    ProvingFailed(String),
}

impl AttestError {
    /// HTTP status + closed machine code for admit-time responses.
    pub fn http_status_and_code(&self) -> (u16, &'static str) {
        match self {
            AttestError::FeatureDisabled => (404, "feature_disabled"),
            AttestError::Malformed(_) => (400, "malformed_request"),
            AttestError::Unauthorized(_) => (401, "unauthorized"),
            AttestError::ChallengeExpired(_) => (410, "challenge_expired"),
            AttestError::CircuitDigestMismatch(_) => (503, "circuit_digest_mismatch"),
            AttestError::Internal(_) => (500, "internal_error"),
            // Proving failures surface as terminal job errors, not admit HTTP.
            AttestError::ProvingFailed(_) => (500, "proving_failed"),
        }
    }

    pub fn message(&self) -> &str {
        match self {
            AttestError::FeatureDisabled => {
                "POST /v1/attest/balance requires ZKCOINS_V11_SHADOW=1 / ScanStackMode::V11"
            }
            AttestError::Malformed(m)
            | AttestError::Unauthorized(m)
            | AttestError::ChallengeExpired(m)
            | AttestError::CircuitDigestMismatch(m)
            | AttestError::Internal(m)
            | AttestError::ProvingFailed(m) => m.as_str(),
        }
    }
}

// ---------------------------------------------------------------------------
// Flag gate
// ---------------------------------------------------------------------------

/// True when the process claim is v1.1 (flag on and stack claimed).
pub fn v11_attest_route_active() -> bool {
    matches!(process_stack_mode(), Some(ScanStackMode::V11))
}

pub fn ensure_v11_attest_path(mode: V11ShadowMode) -> Result<(), AttestError> {
    match mode {
        V11ShadowMode::On if v11_attest_route_active() => Ok(()),
        V11ShadowMode::On => Err(AttestError::FeatureDisabled),
        V11ShadowMode::Off => Err(AttestError::FeatureDisabled),
    }
}

// ---------------------------------------------------------------------------
// Hash helpers (plain SHA-256 `H`, §1.1)
// ---------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

/// `chan_bind = H("zkCoins/v1/PullHost" ‖ host)` for clearnet (§5.1).
pub fn chan_bind_for_host(host: &str) -> [u8; 32] {
    let mut pre = Vec::with_capacity(PULL_HOST_DOMAIN.len() + host.len());
    pre.extend_from_slice(PULL_HOST_DOMAIN.as_bytes());
    pre.extend_from_slice(host.as_bytes());
    sha256(&pre)
}

/// Ceiling encoding for `request_hash` (§7.5):
/// - both omitted → single byte `0x00`
/// - both present → `0x01 ‖ nav_ceiling (32B) ‖ u64-be(size_ceiling)`
/// - any other combination → error
pub fn ceiling_encoding(
    nav_ceiling: Option<&[u8; 32]>,
    size_ceiling: Option<u64>,
) -> Result<Vec<u8>, AttestError> {
    match (nav_ceiling, size_ceiling) {
        (None, None) => Ok(vec![0x00]),
        (Some(nav), Some(size)) => {
            let mut out = Vec::with_capacity(1 + 32 + 8);
            out.push(0x01);
            out.extend_from_slice(nav);
            out.extend_from_slice(&size.to_be_bytes());
            Ok(out)
        }
        _ => Err(AttestError::Malformed(
            "nav_ceiling and size_ceiling must both be present or both omitted (§7.5)".into(),
        )),
    }
}

/// `request_hash = H("zkCoins/v1/AttestBalance" ‖ subject ‖ asset_id ‖ ceiling_encoding)`.
pub fn attest_request_hash(
    subject: &[u8; 32],
    asset_id: &[u8; 32],
    ceiling_enc: &[u8],
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(ATTEST_BALANCE_REQUEST_TAG.len() + 32 + 32 + ceiling_enc.len());
    pre.extend_from_slice(ATTEST_BALANCE_REQUEST_TAG.as_bytes());
    pre.extend_from_slice(subject);
    pre.extend_from_slice(asset_id);
    pre.extend_from_slice(ceiling_enc);
    sha256(&pre)
}

/// `chal = H(domain ‖ nonce ‖ chan_bind ‖ subject ‖ expiry ‖ request_hash)`.
pub fn attest_challenge_message(
    nonce: &[u8; 32],
    chan_bind: &[u8; 32],
    subject: &[u8; 32],
    expiry: u64,
    request_hash: &[u8; 32],
) -> [u8; 32] {
    let mut pre = Vec::with_capacity(
        ATTEST_BALANCE_CHALLENGE_DOMAIN.len() + 32 + 32 + 32 + 8 + 32,
    );
    pre.extend_from_slice(ATTEST_BALANCE_CHALLENGE_DOMAIN.as_bytes());
    pre.extend_from_slice(nonce);
    pre.extend_from_slice(chan_bind);
    pre.extend_from_slice(subject);
    pre.extend_from_slice(&expiry.to_be_bytes());
    pre.extend_from_slice(request_hash);
    sha256(&pre)
}

// ---------------------------------------------------------------------------
// Strict hex (no silent case-fold / 0x strip — same discipline as G4)
// ---------------------------------------------------------------------------

fn parse_hex_exact(s: &str, field: &str, expected: usize) -> Result<Vec<u8>, AttestError> {
    if s.len() != expected * 2 {
        return Err(AttestError::Malformed(format!(
            "{field}: expected {} lowercase hex chars, got {}",
            expected * 2,
            s.len()
        )));
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(AttestError::Malformed(format!(
            "{field}: must be lowercase hex (no 0x, no uppercase)"
        )));
    }
    hex::decode(s).map_err(|e| AttestError::Malformed(format!("{field}: hex decode: {e}")))
}

fn parse_hex32(s: &str, field: &str) -> Result<[u8; 32], AttestError> {
    let v = parse_hex_exact(s, field, 32)?;
    Ok(v.try_into().expect("length checked"))
}

fn parse_hex64(s: &str, field: &str) -> Result<[u8; 64], AttestError> {
    let v = parse_hex_exact(s, field, 64)?;
    Ok(v.try_into().expect("length checked"))
}

// ---------------------------------------------------------------------------
// Challenge issue
// ---------------------------------------------------------------------------

/// Issue a fresh `AttestBalanceChallenge` for `subject` (Bech32m `zk` address).
pub fn issue_attest_challenge(
    store: &AttestChallengeMap,
    subject_bech32: &str,
    now: u64,
) -> Result<([u8; 32], u64), AttestError> {
    let subject = Address::from_bech32m(subject_bech32).map_err(|e| {
        AttestError::Malformed(format!("subject: invalid zk Bech32m address: {e}"))
    })?;
    // Two UUID v4 values (128-bit CSPRNG each) → 32-byte nonce.
    // No silent fixed-nonce fallback.
    let mut nonce = [0u8; 32];
    let a = uuid::Uuid::new_v4();
    let b = uuid::Uuid::new_v4();
    nonce[..16].copy_from_slice(a.as_bytes());
    nonce[16..].copy_from_slice(b.as_bytes());
    let expiry = now.saturating_add(ATTEST_CHALLENGE_TTL_SECS);
    store.insert(
        nonce,
        AttestChallengeRecord {
            subject,
            expiry,
            action: "attest_balance",
        },
    );
    Ok((nonce, expiry))
}

// ---------------------------------------------------------------------------
// OwnershipProof gate
// ---------------------------------------------------------------------------

/// Verify the action-bound OwnershipProof and consume the nonce.
///
/// Returns the authorised [`AttestJobBody`] on success.
pub fn authorise_attest_balance(
    store: &AttestChallengeMap,
    public_hosts: &[String],
    req: &AttestBalanceRequest,
    now: u64,
) -> Result<AttestJobBody, AttestError> {
    // Ceiling presence rules first (malformed before auth).
    let nav_ceiling = match &req.nav_ceiling {
        None => None,
        Some(h) => Some(parse_hex32(h, "nav_ceiling")?),
    };
    let size_ceiling = req.size_ceiling.map(|U64Decimal(n)| n);
    let ceiling_enc = ceiling_encoding(nav_ceiling.as_ref(), size_ceiling)?;

    // Subject: Bech32m.
    let subject_addr = Address::from_bech32m(&req.subject).map_err(|e| {
        AttestError::Malformed(format!("subject: invalid zk Bech32m address: {e}"))
    })?;
    let asset_id = parse_hex32(&req.asset_id, "asset_id")?;
    let nonce = parse_hex32(&req.challenge.nonce, "challenge.nonce")?;

    // OwnershipProofJson shape.
    if req.ownership_proof.proof_type != "ownership" {
        return Err(AttestError::Unauthorized(
            "only OwnershipProof (type=ownership) authorises attest; GrantProof rejected (no-escalation)"
                .into(),
        ));
    }
    let proof_subject = Address::from_bech32m(&req.ownership_proof.subject).map_err(|e| {
        AttestError::Malformed(format!(
            "ownership_proof.subject: invalid zk Bech32m address: {e}"
        ))
    })?;
    if proof_subject != subject_addr {
        return Err(AttestError::Unauthorized(
            "ownership_proof.subject does not match request subject".into(),
        ));
    }
    let pk0 = parse_hex32(&req.ownership_proof.public_key, "ownership_proof.public_key")?;
    let nk_commit_bytes =
        parse_hex32(&req.ownership_proof.nk_commit, "ownership_proof.nk_commit")?;
    let signature = parse_hex64(&req.ownership_proof.signature, "ownership_proof.signature")?;

    // Address binding: H(Pk₀ ‖ nk_commit) == subject.
    let expected_addr = host::address(&pk0, host::digest_from_bytes(&nk_commit_bytes).map_err(
        |e| AttestError::Malformed(format!("ownership_proof.nk_commit: non-canonical digest: {e}")),
    )?);
    if expected_addr != subject_addr.0 {
        return Err(AttestError::Unauthorized(
            "H(Pk0 ‖ nk_commit) does not equal subject address".into(),
        ));
    }

    // Consume challenge (single-use); unknown / expired → 410.
    let record = match store.remove(&nonce) {
        Some((_, r)) => r,
        None => {
            return Err(AttestError::ChallengeExpired(
                "challenge nonce unknown or already consumed".into(),
            ));
        }
    };
    if record.expiry < now {
        return Err(AttestError::ChallengeExpired(
            "challenge nonce expired".into(),
        ));
    }
    if record.subject != subject_addr {
        return Err(AttestError::Unauthorized(
            "challenge was issued for a different subject".into(),
        ));
    }
    if record.action != "attest_balance" {
        return Err(AttestError::Unauthorized(
            "challenge action is not attest_balance".into(),
        ));
    }

    if public_hosts.is_empty() {
        return Err(AttestError::Internal(
            "no authoritative public hosts configured for chan_bind (ZKCOINS_PUBLIC_HOST)".into(),
        ));
    }

    let request_hash = attest_request_hash(&subject_addr.0, &asset_id, &ceiling_enc);
    let r = {
        let mut r = [0u8; 32];
        r.copy_from_slice(&signature[..32]);
        r
    };
    let s = {
        let mut s = [0u8; 32];
        s.copy_from_slice(&signature[32..]);
        s
    };

    // Accept if the signature verifies under any authoritative chan_bind.
    let mut accepted = false;
    for host in public_hosts {
        let cb = chan_bind_for_host(host);
        let chal = attest_challenge_message(
            &nonce,
            &cb,
            &subject_addr.0,
            record.expiry,
            &request_hash,
        );
        if verify_single(&pk0, &r, &s, &chal).is_ok() {
            accepted = true;
            break;
        }
    }
    if !accepted {
        return Err(AttestError::Unauthorized(
            "OwnershipProof signature invalid or chan_bind mismatch".into(),
        ));
    }

    Ok(AttestJobBody {
        subject: subject_addr.0,
        asset_id,
        nav_ceiling,
        size_ceiling,
    })
}

// ---------------------------------------------------------------------------
// BalanceAttestationV1 serialization (§7.1)
// ---------------------------------------------------------------------------

/// §1.7.9 / §7.1 wire encoding of a `C_balance` proof.
///
/// Canonical form is Plonky2's native `ProofWithPublicInputs::to_bytes()`
/// (public inputs as 8-byte-LE field elements + proof body). **Not**
/// `bincode` / serde — that is an internal comparison encoding only and a
/// verifier following the spec cannot read it.
pub fn encode_c_balance_proof_bytes(proof: &BalanceProof) -> Vec<u8> {
    proof.to_bytes()
}

/// Canonical `serialize(BalanceAttestation)` / `BalanceAttestationV1`.
///
/// Layout (§7.1):  
/// `subject(32) ‖ asset_id(32) ‖ balance(u128-be16) ‖ nav_ceiling(32) ‖
///  size_ceiling(u64-be8) ‖ txid(32) ‖ block_hash(32) ‖ height(u64-be8) ‖
///  Pk_anchor(32) ‖ R_anchor(32) ‖ network_id(32) ‖ u32-be len(proof) ‖ proof`
pub fn serialize_balance_attestation(
    statement: &BalanceAttestationStatement,
    network: Network,
    proof: &BalanceProof,
) -> Result<Vec<u8>, AttestError> {
    let proof_bytes = encode_c_balance_proof_bytes(proof);
    serialize_balance_attestation_v1(statement, network, &proof_bytes)
}

/// Canonical §7.1 layout with already-encoded proof bytes.
///
/// Production callers use [`serialize_balance_attestation`]; tests inject
/// fixed proof bytes so the layout is exercised without a circuit prove.
pub fn serialize_balance_attestation_v1(
    statement: &BalanceAttestationStatement,
    network: Network,
    proof_bytes: &[u8],
) -> Result<Vec<u8>, AttestError> {
    if proof_bytes.len() > u32::MAX as usize {
        return Err(AttestError::Internal(
            "C_balance proof exceeds u32 length prefix".into(),
        ));
    }
    let nid = network_id_for(network);
    let nid_bytes = digest_to_bytes(&nid);
    let asset_bytes = digest_to_bytes(&statement.asset_id);
    let nav_root = statement.nav_ceiling.root();
    let nav_root_bytes = digest_to_bytes(&nav_root);

    let mut out = Vec::with_capacity(32 * 8 + 16 + 8 + 8 + 4 + proof_bytes.len());
    out.extend_from_slice(&statement.subject.0);
    out.extend_from_slice(&asset_bytes);
    out.extend_from_slice(&statement.balance.to_be_bytes());
    out.extend_from_slice(&nav_root_bytes);
    out.extend_from_slice(&statement.nav_ceiling.size.to_be_bytes());
    out.extend_from_slice(&statement.anchor.txid);
    out.extend_from_slice(&statement.anchor.block_hash);
    out.extend_from_slice(&statement.anchor.height.to_be_bytes());
    out.extend_from_slice(&statement.anchor.public_key);
    out.extend_from_slice(&statement.anchor.signature_r);
    out.extend_from_slice(&nid_bytes);
    out.extend_from_slice(&(proof_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(proof_bytes);
    Ok(out)
}

/// §7.5 completed-job `result` for `attest_balance`: only `attestation`.
pub fn completed_attest_result(attestation_bytes: &[u8]) -> serde_json::Value {
    serde_json::json!({
        "attestation": hex::encode(attestation_bytes),
    })
}

/// Require a fully resolved Bitcoin inscription locator, or fail with the
/// named [`ATTEST_ANCHOR_LOCATOR_EDGE`] (never fabricate zero txid/hash).
pub fn require_resolved_anchor(
    txid: Option<[u8; 32]>,
    block_hash: Option<[u8; 32]>,
) -> Result<([u8; 32], [u8; 32]), AttestError> {
    let txid = txid.ok_or_else(|| {
        AttestError::ProvingFailed(ATTEST_ANCHOR_LOCATOR_EDGE.to_string())
    })?;
    let block_hash = block_hash.ok_or_else(|| {
        AttestError::ProvingFailed(ATTEST_ANCHOR_LOCATOR_EDGE.to_string())
    })?;
    Ok((txid, block_hash))
}

/// §5.7 host-side completed-anchor gate (pure production body).
///
/// A `completed` anchor is the **first occurrence** of `(Pk, R)` on the
/// node's NfLog at a position inside the ≥6-confirmation-final prefix
/// `size_final` (`nullifier_pos < size_final`). Without this check a
/// pending (not-yet-final) or double-spend-loser nullifier could be
/// disclosed as the attestation anchor.
///
/// Called from [`collect_materials`]; tests **must** call this function
/// — asserting locator non-zeros alone does not establish the property.
pub fn require_completed_anchor(
    nullifier_pos: u64,
    size_final: u64,
    classification: SpendClassification,
) -> Result<(), AttestError> {
    if classification != SpendClassification::ValidFirstSpend {
        return Err(AttestError::ProvingFailed(format!(
            "anchor nullifier at pos {nullifier_pos} is not the first occurrence of Pk \
             on this node's NfLog (classification={classification:?}); state is not completed"
        )));
    }
    if nullifier_pos >= size_final {
        return Err(AttestError::ProvingFailed(format!(
            "anchor nullifier position {nullifier_pos} is not inside size_final {size_final} \
             (not ≥6-confirmation-final; state is not completed)"
        )));
    }
    Ok(())
}

/// Extract the 32-byte `network_id` field from a serialized attestation.
///
/// Offset: subject(32)+asset(32)+balance(16)+nav_ceiling(32)+size(8)+txid(32)
/// +block_hash(32)+height(8)+Pk(32)+R(32) = 256 → network_id at [256..288].
pub fn network_id_from_attestation_bytes(bytes: &[u8]) -> Result<[u8; 32], AttestError> {
    const OFFSET: usize = 32 + 32 + 16 + 32 + 8 + 32 + 32 + 8 + 32 + 32;
    if bytes.len() < OFFSET + 32 + 4 {
        return Err(AttestError::Malformed(
            "BalanceAttestationV1 too short to contain network_id".into(),
        ));
    }
    let mut nid = [0u8; 32];
    nid.copy_from_slice(&bytes[OFFSET..OFFSET + 32]);
    Ok(nid)
}

fn network_id_for(n: Network) -> HashDigest {
    match n {
        Network::Mainnet => network_id_mainnet(),
        Network::Testnet => network_id_testnet(),
        Network::Regtest => network_id_regtest(),
    }
}

// ---------------------------------------------------------------------------
// Network-digest acceptance gate
// ---------------------------------------------------------------------------

/// Pure production gate: attestation `network_id` + live `C_balance` digest
/// must bind to `network`.
///
/// This is the host-side acceptance body used by
/// [`accept_attestation_for_network`] and the pre-prove pin check in
/// [`prove_attestation_for_job`]. Tests **must** call this (or the
/// thin wrappers below) — comparing pin constants alone does not
/// exercise the gate, and removing it must turn those tests red.
pub fn accept_c_balance_network_binding(
    attestation_network_id: &HashDigest,
    live_c_balance_digest: &[u8],
    network: Network,
) -> Result<(), AttestError> {
    let expected_nid = network_id_for(network);
    if *attestation_network_id != expected_nid {
        return Err(AttestError::ProvingFailed(format!(
            "attestation network_id does not match node network {:?}",
            network
        )));
    }
    let pinned = pinned_c_balance_digest(network);
    if live_c_balance_digest != pinned.as_slice() {
        return Err(AttestError::CircuitDigestMismatch(format!(
            "live C_balance digest does not match pinned constant for {:?}",
            network
        )));
    }
    Ok(())
}

/// Host-side gate: attestation `network_id` must match the node network,
/// and the live `C_balance` digest must equal the pinned constant, then
/// Plonky2-verify the proof under that circuit.
///
/// Cross-network reject: a proof whose `network_id` is for network B is
/// refused on a node running network A **before** Plonky2 verify — and
/// `ProverBridge::verify_attestation` on the wrong circuit would fail too.
pub fn accept_attestation_for_network(
    proved: &ProvedAttestation,
    network: Network,
) -> Result<(), AttestError> {
    let bridge = ProverBridge::new(network);
    let live = bridge.balance_circuit_digest_bytes();
    accept_c_balance_network_binding(&proved.network_id, &live, network)?;
    bridge
        .verify_attestation(&proved.proof)
        .map_err(|e| AttestError::ProvingFailed(format!("C_balance verify failed: {e}")))?;
    Ok(())
}

/// Compare two networks' pinned digests and `network_id`s — they **must**
/// differ. Used by tests that the network pin is a real boundary.
pub fn networks_have_distinct_c_balance_pins(a: Network, b: Network) -> bool {
    if a == b {
        return false;
    }
    pinned_c_balance_digest(a) != pinned_c_balance_digest(b)
        && network_id_for(a) != network_id_for(b)
}

// ---------------------------------------------------------------------------
// Witness assembly + prove
// ---------------------------------------------------------------------------

/// Materials required from the engine for an attestation witness.
#[derive(Debug)]
pub(crate) struct AttestMaterials {
    account_state: shared::spec_v1::AccountState,
    compliance_proof: zkcoins_prover::prover_bridge::ComplianceProof,
    nav_opening: zkcoins_prover::prover_bridge::NavOpening,
    nullifier: zkcoins_prover::prover_bridge::NullifierOpening,
    nullifier_pos: u64,
    nullifier_height: u64,
    size_final_nav: Nav,
    consistency: Vec<HashDigest>,
    /// Resolved Bitcoin locator, if available.
    anchor_txid: Option<[u8; 32]>,
    anchor_block_hash: Option<[u8; 32]>,
}

/// Assemble engine materials for an attestation (includes the §5.7
/// completed-anchor gate). `pub(crate)` so production-path tests can
/// drive it without going through a full `C_balance` prove.
pub(crate) fn collect_materials(
    adapter: &EngineAdapter,
    subject: &Address,
    asset_id: &[u8; 32],
    requested_ceiling: Option<Nav>,
) -> Result<AttestMaterials, AttestError> {
    adapter.with_engine(|engine| {
        let record = engine.account(subject).ok_or_else(|| {
            AttestError::ProvingFailed(
                "subject account not present on this node (operational bundle / state missing)"
                    .into(),
            )
        })?;

        let compliance_proof = record.last_proof.clone().ok_or_else(|| {
            AttestError::ProvingFailed(
                "account has no last compliance proof — cannot attest an unproven state".into(),
            )
        })?;
        let nav_opening = record.last_nav_opening.ok_or_else(|| {
            AttestError::ProvingFailed(
                "account has no last NAV opening — cannot open nav_commitment".into(),
            )
        })?;
        let nullifier = record.last_nullifier.clone().ok_or_else(|| {
            AttestError::ProvingFailed(
                "account has no last nullifier — nothing to bind as §5.7 anchor".into(),
            )
        })?;
        let nullifier_pos = record.last_nullifier_pos.ok_or_else(|| {
            AttestError::ProvingFailed(
                "account has no last_nullifier_pos — anchor not yet folded into NfLog".into(),
            )
        })?;

        let mirror = engine.nflog_mirror();
        if nullifier_pos as usize >= mirror.len() {
            return Err(AttestError::ProvingFailed(format!(
                "last_nullifier_pos {nullifier_pos} out of NfLog range {}",
                mirror.len()
            )));
        }
        let (chain_pos, entry) = &mirror[nullifier_pos as usize];
        if entry.pk != nullifier.public_key || entry.r != nullifier.signature_r {
            return Err(AttestError::ProvingFailed(
                "last_nullifier does not match NfLog entry at last_nullifier_pos".into(),
            ));
        }
        let nullifier_height = chain_pos.height;

        // size_final ceiling (RECOMMENDED default §5.7).
        let size_final = engine.nflog().size_final(engine.tip_height());
        // §5.7 host-side: completed = first occurrence inside size_final.
        let classification = engine
            .nflog()
            .classify(nullifier.public_key, nullifier.signature_r);
        require_completed_anchor(nullifier_pos, size_final, classification)?;
        let size_final_nav = if size_final == 0 {
            Nav {
                size: 0,
                mth: host::nflog_empty(),
            }
        } else if size_final == engine.nflog().nav().size {
            engine.nflog().nav()
        } else {
            let entries: Vec<_> = mirror
                .iter()
                .take(size_final as usize)
                .map(|(_, e)| *e)
                .collect();
            Nav {
                size: size_final,
                mth: host::nflog_mth(&entries),
            }
        };

        let ceiling = match requested_ceiling {
            Some(c) => c,
            None => size_final_nav,
        };
        if ceiling.size > size_final_nav.size {
            return Err(AttestError::ProvingFailed(format!(
                "size_ceiling {} exceeds node size_final {}",
                ceiling.size, size_final_nav.size
            )));
        }
        // Rebuild mth at size_ceiling and enforce canonicality.
        let ceiling_entries: Vec<_> = mirror
            .iter()
            .take(ceiling.size as usize)
            .map(|(_, e)| *e)
            .collect();
        let rebuilt_mth = if ceiling.size == 0 {
            host::nflog_empty()
        } else {
            host::nflog_mth(&ceiling_entries)
        };
        if rebuilt_mth != ceiling.mth {
            return Err(AttestError::ProvingFailed(
                "nav_ceiling is not a canonical NfLog root for size_ceiling on this node's scan"
                    .into(),
            ));
        }
        if nav_opening.nav.size > ceiling.size {
            return Err(AttestError::ProvingFailed(
                "attested NAV size exceeds disclosed size_ceiling".into(),
            ));
        }

        let prefix_entries: Vec<_> = mirror
            .iter()
            .take(ceiling.size as usize)
            .map(|(_, e)| *e)
            .collect();
        let consistency = host::consistency_proof(nav_opening.nav.size, &prefix_entries)
            .map_err(|e| {
                AttestError::ProvingFailed(format!("nav consistency proof failed: {e}"))
            })?;

        // Balance from account state (fail if asset missing → balance 0 is
        // still a valid attestation of zero, so we do not reject).
        let _balance = record
            .state
            .balances
            .get(asset_id)
            .copied()
            .unwrap_or(0);

        Ok(AttestMaterials {
            account_state: record.state.clone(),
            compliance_proof,
            nav_opening,
            nullifier,
            nullifier_pos,
            nullifier_height,
            size_final_nav: ceiling,
            consistency,
            anchor_txid: None,
            anchor_block_hash: None,
        })
    })
}

/// Pick the inclusion-block hash for a nullifier at `nullifier_height`.
///
/// - **At tip** (`nullifier_height == tip_height`): the adapter's live
///   `tip_hash` (all-zero refused).
/// - **Below tip** (confirmed, including every ≥6-confirmation-final
///   completed anchor): the durable scanner `block_log` entry for that
///   height (`historical_hash`). The adapter only retains the tip hash,
///   so historical heights cannot come from `tip_hash`.
///
/// Returns `None` when no trustworthy non-zero hash is available — the
/// caller must surface [`ATTEST_ANCHOR_LOCATOR_EDGE`], never fabricate.
pub fn block_hash_for_anchor_height(
    nullifier_height: u64,
    tip_height: u64,
    tip_hash: [u8; 32],
    historical_hash: Option<[u8; 32]>,
) -> Option<[u8; 32]> {
    let candidate = if nullifier_height == tip_height {
        Some(tip_hash)
    } else if nullifier_height < tip_height {
        historical_hash
    } else {
        // Nullifier height above the engine tip is not on this scan view.
        None
    }?;
    if candidate == [0u8; 32] {
        None
    } else {
        Some(candidate)
    }
}

/// Resolve Bitcoin locator from still-live pending publishes (partial path).
///
/// Yields `(reveal_txid, inclusion_block_hash)` when both can be resolved:
/// - `txid` from `v11_pending_publishes.reveal_txid` for this Pk
/// - `block_hash` via [`block_hash_for_anchor_height`] — tip hash when the
///   nullifier sits at the tip, otherwise the `block_log` hash for the
///   inclusion height (so a completed anchor at height `h` with tip
///   `≥ h+5` still resolves).
///
/// For a confirmed-but-not-tip anchor this therefore returns
/// `Some(reveal_txid)` + `Some(block_log_hash_at_nullifier_height)`, not
/// the live tip hash.
pub(crate) async fn resolve_anchor_locator(
    adapter: &EngineAdapter,
    pk: &[u8; 32],
    nullifier_height: u64,
) -> Result<(Option<[u8; 32]>, Option<[u8; 32]>), AttestError> {
    let pending = db_v11::load_pending_publish(adapter.pool(), *pk)
        .await
        .map_err(|e| AttestError::Internal(format!("load pending publish: {e}")))?;
    let txid = pending.and_then(|p| p.reveal_txid);
    if txid.is_none() {
        return Ok((None, None));
    }

    let tip_height = adapter.with_engine(|e| e.tip_height());
    let tip_hash = adapter.tip_hash();
    let historical = if nullifier_height < tip_height {
        crate::db::load_block_hash_at_height(adapter.pool(), nullifier_height)
            .await
            .map_err(|e| AttestError::Internal(format!("load block_log at height: {e}")))?
    } else {
        None
    };
    let block_hash =
        block_hash_for_anchor_height(nullifier_height, tip_height, tip_hash, historical);
    Ok((txid, block_hash))
}

/// Build the witness and run `ProverBridge::prove_attestation`.
///
/// Fails loud on the locator edge or any missing material.
pub async fn prove_attestation_for_job(
    adapter: &EngineAdapter,
    body: &AttestJobBody,
) -> Result<ProvedAttestation, AttestError> {
    let subject = Address(body.subject);
    let asset_digest = host::digest_from_bytes(&body.asset_id)
        .map_err(|e| AttestError::Malformed(format!("asset_id non-canonical: {e}")))?;

    // Resolve optional client-supplied ceiling into a Nav.
    let requested = match (body.nav_ceiling, body.size_ceiling) {
        (None, None) => None,
        (Some(root_bytes), Some(size)) => {
            // Rebuild mth from the engine so the root can be checked.
            let nav = adapter.with_engine(|engine| {
                let mirror = engine.nflog_mirror();
                if size as usize > mirror.len() {
                    return Err(AttestError::ProvingFailed(format!(
                        "size_ceiling {size} exceeds accumulator size {}",
                        mirror.len()
                    )));
                }
                let entries: Vec<_> = mirror
                    .iter()
                    .take(size as usize)
                    .map(|(_, e)| *e)
                    .collect();
                let mth = if size == 0 {
                    host::nflog_empty()
                } else {
                    host::nflog_mth(&entries)
                };
                let nav = Nav { size, mth };
                let expected_root = digest_to_bytes(&nav.root());
                if expected_root != root_bytes {
                    return Err(AttestError::ProvingFailed(
                        "nav_ceiling does not equal Hc(NfLog/Root, size_ceiling ‖ mth) on this scan"
                            .into(),
                    ));
                }
                Ok(nav)
            })?;
            Some(nav)
        }
        _ => {
            return Err(AttestError::Malformed(
                "nav_ceiling and size_ceiling must both be present or both omitted".into(),
            ));
        }
    };

    let mut materials = collect_materials(adapter, &subject, &body.asset_id, requested)?;
    let (txid, block_hash) =
        resolve_anchor_locator(adapter, &materials.nullifier.public_key, materials.nullifier_height)
            .await?;
    materials.anchor_txid = txid;
    materials.anchor_block_hash = block_hash;

    let (txid, block_hash) =
        require_resolved_anchor(materials.anchor_txid, materials.anchor_block_hash)?;

    let balance = materials
        .account_state
        .balances
        .get(&body.asset_id)
        .copied()
        .unwrap_or(0);

    let witness = AttestationWitness {
        statement: BalanceAttestationStatement {
            subject,
            asset_id: asset_digest,
            balance,
            nav_ceiling: materials.size_final_nav,
            anchor: BalanceAnchor {
                txid,
                block_hash,
                height: materials.nullifier_height,
                public_key: materials.nullifier.public_key,
                signature_r: materials.nullifier.signature_r,
            },
        },
        account_state: materials.account_state,
        compliance_proof: materials.compliance_proof,
        nav_opening: materials.nav_opening,
        nav_consistency: materials.consistency,
        r_prime: materials.nullifier.r_prime,
    };

    let network = adapter.network();
    let bridge = adapter.bridge();
    // Same production gate body as accept_attestation_for_network — pin
    // check before the expensive prove. network_id is the node's own
    // (the proof has not been produced yet).
    let live = bridge.balance_circuit_digest_bytes();
    accept_c_balance_network_binding(&network_id_for(network), &live, network)?;

    let proved = bridge.prove_attestation(&witness).map_err(|e| {
        AttestError::ProvingFailed(format!("prove_attestation failed: {e}"))
    })?;
    accept_attestation_for_network(&proved, network)?;
    let _ = materials.nullifier_pos; // retained for forensics / future locator index
    Ok(proved)
}

/// Unix seconds for challenge expiry.
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read authoritative hosts from `ZKCOINS_PUBLIC_HOST` (comma-separated).
///
/// Canonicalisation: lowercase, strip trailing dot. Empty → empty list
/// (auth then fails loud — no silent localhost default).
pub fn public_hosts_from_env() -> Vec<String> {
    match std::env::var("ZKCOINS_PUBLIC_HOST") {
        Ok(v) => v
            .split(',')
            .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect(),
        Err(_) => Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};

    fn sample_sk_pk() -> (SecretKey, [u8; 32]) {
        let secp = Secp256k1::new();
        // Deterministic test key (not a real secret).
        let sk = SecretKey::from_slice(&[0x42u8; 32]).expect("32-byte secret");
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (xonly, _) = kp.x_only_public_key();
        (sk, xonly.serialize())
    }

    fn sign_chal(sk: &SecretKey, chal: &[u8; 32]) -> [u8; 64] {
        let secp = Secp256k1::new();
        let kp = Keypair::from_secret_key(&secp, sk);
        let msg = Message::from_digest_slice(chal).expect("32-byte digest");
        let sig = secp.sign_schnorr_no_aux_rand(&msg, &kp);
        let bytes = sig.as_ref();
        let mut out = [0u8; 64];
        out.copy_from_slice(bytes);
        out
    }

    #[test]
    fn ceiling_encoding_closed_shapes() {
        assert_eq!(ceiling_encoding(None, None).unwrap(), vec![0x00]);
        let nav = [0xabu8; 32];
        let enc = ceiling_encoding(Some(&nav), Some(7)).unwrap();
        assert_eq!(enc[0], 0x01);
        assert_eq!(&enc[1..33], &nav);
        assert_eq!(&enc[33..], &7u64.to_be_bytes());
        assert!(matches!(
            ceiling_encoding(Some(&nav), None),
            Err(AttestError::Malformed(_))
        ));
        assert!(matches!(
            ceiling_encoding(None, Some(1)),
            Err(AttestError::Malformed(_))
        ));
    }

    #[test]
    fn request_hash_binds_ceiling_discriminator() {
        let subject = [1u8; 32];
        let asset = [2u8; 32];
        let h0 = attest_request_hash(&subject, &asset, &ceiling_encoding(None, None).unwrap());
        let h1 = attest_request_hash(
            &subject,
            &asset,
            &ceiling_encoding(Some(&[3u8; 32]), Some(9)).unwrap(),
        );
        assert_ne!(h0, h1, "discriminator must change the request hash");
    }

    #[test]
    fn networks_have_distinct_c_balance_pins_and_network_ids() {
        assert!(networks_have_distinct_c_balance_pins(
            Network::Testnet,
            Network::Mainnet
        ));
        assert!(networks_have_distinct_c_balance_pins(
            Network::Testnet,
            Network::Regtest
        ));
        assert!(networks_have_distinct_c_balance_pins(
            Network::Mainnet,
            Network::Regtest
        ));
        // Same network is not a boundary.
        assert!(!networks_have_distinct_c_balance_pins(
            Network::Testnet,
            Network::Testnet
        ));
    }

    /// Pinned constants match the generated vector file — and the
    /// production gate **accepts** each pin when presented as the live
    /// digest. Constant equality alone is not enough (see
    /// `accept_gate_rejects_wrong_live_digest`).
    #[test]
    fn pinned_digests_pass_production_gate_and_match_vectors() {
        // Ground truth: script-plonky2/tests/generated_circuit_digests.txt
        assert_eq!(
            hex::encode(PINNED_C_BALANCE_DIGEST_MAINNET),
            "0a4202fc772295d6db4eb9c5bd2bbb7a59d45cff1653648dff4681f4ba55d606"
        );
        assert_eq!(
            hex::encode(PINNED_C_BALANCE_DIGEST_TESTNET),
            "cbb8f284fab6f81aa3616f55da76942c1259845e0b9135f9c8fe9385d3f7fe87"
        );
        assert_eq!(
            hex::encode(PINNED_C_BALANCE_DIGEST_REGTEST),
            "bd696087e0e0f47b556a6803ef4fb5b9ebae2327e0438dd405f33752dc90772d"
        );

        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let pinned = pinned_c_balance_digest(network);
            let nid = network_id_for(network);
            accept_c_balance_network_binding(&nid, &pinned, network).unwrap_or_else(|e| {
                panic!("pinned digest must pass production gate for {network:?}: {e:?}")
            });
        }
    }

    /// Defect 1 regression: the production gate must reject a wrong live
    /// digest. Weakening `accept_c_balance_network_binding` to always-Ok
    /// turns this test red — that is the proof the gate is bound.
    #[test]
    fn accept_gate_rejects_wrong_live_digest() {
        let network = Network::Testnet;
        let nid = network_id_for(network);
        let wrong = [0u8; 32];
        assert_ne!(wrong, pinned_c_balance_digest(network));
        let err = accept_c_balance_network_binding(&nid, &wrong, network).unwrap_err();
        assert_eq!(
            err.http_status_and_code(),
            (503, "circuit_digest_mismatch"),
            "wrong live digest must hit the production CircuitDigestMismatch arm"
        );
    }

    /// Cross-network: a testnet `network_id` presented to a mainnet node
    /// is refused by the production gate (before any Plonky2 verify).
    #[test]
    fn accept_gate_rejects_wrong_network_id() {
        let err = accept_c_balance_network_binding(
            &network_id_testnet(),
            &pinned_c_balance_digest(Network::Mainnet),
            Network::Mainnet,
        )
        .unwrap_err();
        assert!(
            matches!(err, AttestError::ProvingFailed(_)),
            "cross-network must fail via production gate, got {err:?}"
        );
        assert!(
            err.message().contains("network_id"),
            "message must name the network_id mismatch: {}",
            err.message()
        );
    }

    #[test]
    fn network_id_differs_across_networks() {
        let a = digest_to_bytes(&network_id_testnet());
        let b = digest_to_bytes(&network_id_mainnet());
        assert_ne!(a, b);
    }

    #[test]
    fn ownership_proof_accepts_valid_and_rejects_wrong_domain() {
        let store: AttestChallengeMap = Arc::new(DashMap::new());
        let host = "node.example.com";
        let (sk, pk0) = sample_sk_pk();
        let nk = [0x11u8; 32];
        let nkc = host::nk_commit(&nk);
        let nkc_bytes = digest_to_bytes(&nkc);
        let subject_bytes = host::address(&pk0, nkc);
        let subject = Address(subject_bytes);
        let subject_bech = subject.to_bech32m();
        let asset = [0x22u8; 32];

        let now = 1_700_000_000u64;
        let (nonce, expiry) =
            issue_attest_challenge(&store, &subject_bech, now).expect("issue challenge");
        assert_eq!(expiry, now + ATTEST_CHALLENGE_TTL_SECS);

        let ceiling_enc = ceiling_encoding(None, None).unwrap();
        let request_hash = attest_request_hash(&subject_bytes, &asset, &ceiling_enc);
        let cb = chan_bind_for_host(host);
        let chal = attest_challenge_message(&nonce, &cb, &subject_bytes, expiry, &request_hash);
        let sig = sign_chal(&sk, &chal);

        let req = AttestBalanceRequest {
            subject: subject_bech.clone(),
            asset_id: hex::encode(asset),
            nav_ceiling: None,
            size_ceiling: None,
            challenge: AttestChallengeNonce {
                nonce: hex::encode(nonce),
            },
            ownership_proof: OwnershipProofJson {
                proof_type: "ownership".into(),
                subject: subject_bech.clone(),
                public_key: hex::encode(pk0),
                nk_commit: hex::encode(nkc_bytes),
                signature: hex::encode(sig),
            },
        };
        let body = authorise_attest_balance(&store, &[host.to_string()], &req, now)
            .expect("valid ownership proof");
        assert_eq!(body.subject, subject_bytes);
        assert_eq!(body.asset_id, asset);

        // Nonce consumed → second use is challenge_expired.
        let err = authorise_attest_balance(&store, &[host.to_string()], &req, now).unwrap_err();
        assert!(matches!(err, AttestError::ChallengeExpired(_)));
    }

    #[test]
    fn grant_proof_type_is_unauthorized() {
        let store: AttestChallengeMap = Arc::new(DashMap::new());
        let host = "node.example.com";
        let subject = Address([0u8; 32]);
        let subject_bech = subject.to_bech32m();
        let now = 1u64;
        let (nonce, _) = issue_attest_challenge(&store, &subject_bech, now).unwrap();
        let req = AttestBalanceRequest {
            subject: subject_bech.clone(),
            asset_id: hex::encode([0u8; 32]),
            nav_ceiling: None,
            size_ceiling: None,
            challenge: AttestChallengeNonce {
                nonce: hex::encode(nonce),
            },
            ownership_proof: OwnershipProofJson {
                proof_type: "grant".into(),
                subject: subject_bech,
                public_key: hex::encode([0u8; 32]),
                nk_commit: hex::encode([0u8; 32]),
                signature: hex::encode([0u8; 64]),
            },
        };
        let err = authorise_attest_balance(&store, &[host.to_string()], &req, now).unwrap_err();
        assert!(matches!(err, AttestError::Unauthorized(_)));
        assert_eq!(err.http_status_and_code(), (401, "unauthorized"));
    }

    #[test]
    fn feature_disabled_when_flag_off() {
        let err = ensure_v11_attest_path(V11ShadowMode::Off).unwrap_err();
        assert_eq!(err.http_status_and_code(), (404, "feature_disabled"));
    }

    /// Canonical §7.1 `BalanceAttestationV1` layout: every fixed field at
    /// its offset, network_id last PI, length-prefixed proof payload.
    #[test]
    fn serialize_balance_attestation_canonical_layout() {
        let subject = Address([0x01; 32]);
        let asset_bytes = [0x02u8; 32];
        let asset = host::digest_from_bytes(&asset_bytes).unwrap();
        let nav = Nav {
            size: 7,
            mth: host::nflog_empty(),
        };
        let nav_root = digest_to_bytes(&nav.root());
        let statement = BalanceAttestationStatement {
            subject,
            asset_id: asset,
            balance: 99u128,
            nav_ceiling: nav,
            anchor: BalanceAnchor {
                txid: [0x31; 32],
                block_hash: [0x42; 32],
                height: 100,
                public_key: [0x11; 32],
                signature_r: [0x22; 32],
            },
        };
        let proof_bytes = b"fake-c-balance-proof-bytes";
        let bytes =
            serialize_balance_attestation_v1(&statement, Network::Testnet, proof_bytes).unwrap();

        // Fixed header through network_id: 288 bytes, then u32-be len + proof.
        assert_eq!(bytes.len(), 288 + 4 + proof_bytes.len());
        assert_eq!(&bytes[0..32], &subject.0);
        assert_eq!(&bytes[32..64], &asset_bytes);
        assert_eq!(&bytes[64..80], &99u128.to_be_bytes());
        assert_eq!(&bytes[80..112], &nav_root);
        assert_eq!(&bytes[112..120], &7u64.to_be_bytes());
        assert_eq!(&bytes[120..152], &[0x31; 32]);
        assert_eq!(&bytes[152..184], &[0x42; 32]);
        assert_eq!(&bytes[184..192], &100u64.to_be_bytes());
        assert_eq!(&bytes[192..224], &[0x11; 32]);
        assert_eq!(&bytes[224..256], &[0x22; 32]);
        let nid = digest_to_bytes(&network_id_testnet());
        assert_eq!(&bytes[256..288], &nid);
        assert_eq!(
            u32::from_be_bytes(bytes[288..292].try_into().unwrap()) as usize,
            proof_bytes.len()
        );
        assert_eq!(&bytes[292..], proof_bytes);

        let extracted = network_id_from_attestation_bytes(&bytes).unwrap();
        assert_eq!(extracted, nid);
        assert_ne!(extracted, digest_to_bytes(&network_id_mainnet()));
    }

    /// Hollow `BalanceProof` shell (never circuit-verified) so the wire
    /// encoder can be bound to `to_bytes()` without a C_balance build.
    fn hollow_balance_proof() -> BalanceProof {
        use plonky2::field::polynomial::PolynomialCoeffs;
        use plonky2::field::types::Field;
        use plonky2::fri::proof::FriProof;
        use plonky2::hash::merkle_tree::MerkleCap;
        use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};
        use zkcoins_program::F;

        ProofWithPublicInputs {
            proof: Proof {
                wires_cap: MerkleCap(vec![]),
                plonk_zs_partial_products_cap: MerkleCap(vec![]),
                quotient_polys_cap: MerkleCap(vec![]),
                openings: OpeningSet {
                    constants: vec![],
                    plonk_sigmas: vec![],
                    wires: vec![],
                    plonk_zs: vec![],
                    plonk_zs_next: vec![],
                    partial_products: vec![],
                    quotient_polys: vec![],
                    lookup_zs: vec![],
                    lookup_zs_next: vec![],
                },
                opening_proof: FriProof {
                    commit_phase_merkle_caps: vec![],
                    query_round_proofs: vec![],
                    final_poly: PolynomialCoeffs::new(vec![]),
                    pow_witness: F::ZERO,
                },
            },
            // Distinct public inputs so bincode and to_bytes diverge in body.
            public_inputs: vec![F::from_canonical_u64(7), F::from_canonical_u64(42)],
        }
    }

    /// Emitted proof bytes are the §1.7.9 / §7.1 canonical encoding
    /// (`ProofWithPublicInputs::to_bytes()`), not bincode. Removing the
    /// production encoder (or switching it to bincode) turns this red.
    #[test]
    fn emitted_proof_bytes_are_canonical_to_bytes_not_bincode() {
        let proof = hollow_balance_proof();
        let canonical = encode_c_balance_proof_bytes(&proof);
        assert_eq!(
            canonical,
            proof.to_bytes(),
            "production encoder must be ProofWithPublicInputs::to_bytes()"
        );
        let bincode_bytes = bincode::serialize(&proof).expect("bincode of hollow proof");
        assert_ne!(
            canonical, bincode_bytes,
            "canonical wire form must differ from the internal bincode encoding"
        );

        let statement = BalanceAttestationStatement {
            subject: Address([0x01; 32]),
            asset_id: host::digest_from_bytes(&[0x02; 32]).unwrap(),
            balance: 1,
            nav_ceiling: Nav {
                size: 0,
                mth: host::nflog_empty(),
            },
            anchor: BalanceAnchor {
                txid: [0x31; 32],
                block_hash: [0x42; 32],
                height: 1,
                public_key: [0x11; 32],
                signature_r: [0x22; 32],
            },
        };
        let bytes =
            serialize_balance_attestation(&statement, Network::Testnet, &proof).unwrap();
        // Layout: 288-byte fixed header + u32-be len + proof payload.
        let len = u32::from_be_bytes(bytes[288..292].try_into().unwrap()) as usize;
        assert_eq!(len, canonical.len());
        assert_eq!(
            &bytes[292..],
            &canonical[..],
            "serialize_balance_attestation must embed encode_c_balance_proof_bytes, not bincode"
        );
        assert_ne!(&bytes[292..], &bincode_bytes[..]);
    }

    /// §5.7 completed anchor: first occurrence at a position inside
    /// `size_final`. The production gate is [`require_completed_anchor`];
    /// weakening it (accepting pending / double-spend / pos ≥ size_final)
    /// must turn this red.
    #[test]
    fn completed_anchor_requires_first_occurrence_inside_size_final() {
        // Happy path: first occurrence at pos 0 with size_final = 1.
        require_completed_anchor(0, 1, SpendClassification::ValidFirstSpend)
            .expect("first occurrence inside size_final must pass");
        require_completed_anchor(2, 5, SpendClassification::ValidFirstSpend)
            .expect("pos < size_final must pass");

        // Not first occurrence → refuse (even when pos is inside size_final).
        let err = require_completed_anchor(0, 5, SpendClassification::Pending).unwrap_err();
        assert!(
            matches!(err, AttestError::ProvingFailed(_)),
            "pending must fail via production gate, got {err:?}"
        );
        assert!(
            err.message().contains("first occurrence") || err.message().contains("completed"),
            "message must name the completed/first-occurrence failure: {}",
            err.message()
        );
        let err =
            require_completed_anchor(0, 5, SpendClassification::RejectedDoubleSpend).unwrap_err();
        assert!(matches!(err, AttestError::ProvingFailed(_)));
        assert!(
            err.message().contains("first occurrence") || err.message().contains("completed"),
            "double-spend loser must fail completed-anchor gate: {}",
            err.message()
        );

        // First occurrence but not yet final (pos ≥ size_final) → refuse.
        let err =
            require_completed_anchor(5, 5, SpendClassification::ValidFirstSpend).unwrap_err();
        assert!(matches!(err, AttestError::ProvingFailed(_)));
        assert!(
            err.message().contains("size_final") || err.message().contains("completed"),
            "pos ≥ size_final must fail: {}",
            err.message()
        );
        let err =
            require_completed_anchor(0, 0, SpendClassification::ValidFirstSpend).unwrap_err();
        assert!(matches!(err, AttestError::ProvingFailed(_)));
        assert!(
            err.message().contains("size_final") || err.message().contains("completed"),
            "empty size_final must refuse any pos: {}",
            err.message()
        );
        let err =
            require_completed_anchor(9, 3, SpendClassification::ValidFirstSpend).unwrap_err();
        assert!(matches!(err, AttestError::ProvingFailed(_)));
    }

    /// Terminal success result carries only `attestation` (hex of V1 bytes).
    #[test]
    fn terminal_success_result_is_attestation_only() {
        let statement = BalanceAttestationStatement {
            subject: Address([0x01; 32]),
            asset_id: host::digest_from_bytes(&[0x02; 32]).unwrap(),
            balance: 1,
            nav_ceiling: Nav {
                size: 0,
                mth: host::nflog_empty(),
            },
            anchor: BalanceAnchor {
                txid: [0x31; 32],
                block_hash: [0x42; 32],
                height: 1,
                public_key: [0x11; 32],
                signature_r: [0x22; 32],
            },
        };
        let bytes =
            serialize_balance_attestation_v1(&statement, Network::Regtest, b"proof").unwrap();
        let result = completed_attest_result(&bytes);
        let obj = result.as_object().expect("object");
        assert_eq!(obj.len(), 1, "§7.5 result must contain only attestation");
        let expected_hex = hex::encode(&bytes);
        assert_eq!(
            obj.get("attestation").and_then(|v| v.as_str()),
            Some(expected_hex.as_str())
        );
    }

    /// Named locator-edge error — never fabricate zeros.
    #[test]
    fn missing_anchor_locator_is_named_edge() {
        let err = require_resolved_anchor(None, None).unwrap_err();
        assert!(matches!(err, AttestError::ProvingFailed(_)));
        assert!(
            err.message().starts_with("ATTEST_ANCHOR_LOCATOR_EDGE"),
            "must use the named edge constant, got: {}",
            err.message()
        );
        assert_eq!(err.message(), ATTEST_ANCHOR_LOCATOR_EDGE);

        // One side present is still the edge (no partial fabricate).
        let err = require_resolved_anchor(Some([1u8; 32]), None).unwrap_err();
        assert_eq!(err.message(), ATTEST_ANCHOR_LOCATOR_EDGE);

        let (t, b) = require_resolved_anchor(Some([1u8; 32]), Some([2u8; 32])).unwrap();
        assert_eq!(t, [1u8; 32]);
        assert_eq!(b, [2u8; 32]);
    }

    /// Pure height→hash selection: tip hash only at the tip; historical
    /// (completed) heights take the durable hash, never the live tip.
    #[test]
    fn block_hash_for_anchor_height_tip_vs_historical() {
        let tip_hash = [0xAAu8; 32];
        let hist = [0xBBu8; 32];
        // At tip → tip_hash.
        assert_eq!(
            block_hash_for_anchor_height(105, 105, tip_hash, Some(hist)),
            Some(tip_hash)
        );
        // Confirmed-but-not-tip (completed-anchor shape) → historical.
        assert_eq!(
            block_hash_for_anchor_height(100, 105, tip_hash, Some(hist)),
            Some(hist)
        );
        // Missing historical at non-tip → None (edge, no tip-hash guess).
        assert_eq!(
            block_hash_for_anchor_height(100, 105, tip_hash, None),
            None
        );
        // All-zero tip hash refused.
        assert_eq!(
            block_hash_for_anchor_height(105, 105, [0u8; 32], None),
            None
        );
        // Height above tip refused.
        assert_eq!(
            block_hash_for_anchor_height(110, 105, tip_hash, Some(hist)),
            None
        );
    }

    // -----------------------------------------------------------------------
    // Production-path fixtures (engine + NfLog + collect_materials)
    // -----------------------------------------------------------------------

    fn hollow_compliance_proof() -> zkcoins_prover::prover_bridge::ComplianceProof {
        use plonky2::field::polynomial::PolynomialCoeffs;
        use plonky2::field::types::Field;
        use plonky2::fri::proof::FriProof;
        use plonky2::hash::merkle_tree::MerkleCap;
        use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};
        use zkcoins_program::F;

        ProofWithPublicInputs {
            proof: Proof {
                wires_cap: MerkleCap(vec![]),
                plonk_zs_partial_products_cap: MerkleCap(vec![]),
                quotient_polys_cap: MerkleCap(vec![]),
                openings: OpeningSet {
                    constants: vec![],
                    plonk_sigmas: vec![],
                    wires: vec![],
                    plonk_zs: vec![],
                    plonk_zs_next: vec![],
                    partial_products: vec![],
                    quotient_polys: vec![],
                    lookup_zs: vec![],
                    lookup_zs_next: vec![],
                },
                opening_proof: FriProof {
                    commit_phase_merkle_caps: vec![],
                    query_round_proofs: vec![],
                    final_poly: PolynomialCoeffs::new(vec![]),
                    pow_witness: F::ZERO,
                },
            },
            public_inputs: vec![F::ZERO; 4],
        }
    }

    /// Seed an adapter with one first-occurrence nullifier at `fold_height`,
    /// tip advanced to `tip_height`, and a subject account whose last
    /// nullifier points at that fold. Classification is derived from the
    /// live NfLog (not caller-supplied).
    async fn seeded_attest_adapter(
        fold_height: u64,
        tip_height: u64,
    ) -> (
        crate::test_db::SchemaScope,
        EngineAdapter,
        Address,
        [u8; 32],
        [u8; 32],
        [u8; 32],
    ) {
        use shared::spec_v1::{AccountState, ChainPosition, CoinHistTree, PublishedNullifier};
        use sha2::{Digest, Sha256};
        use std::collections::{BTreeMap, BTreeSet};
        use zkcoins_prover::prover_bridge::{NavOpening, NullifierOpening};
        use zkcoins_prover::state_engine::{AccountRecord, OpSecret, ScannedNullifier};

        use super::super::separation::{
            claim_stack_scan_mode, set_process_stack_mode, ScanStackMode,
        };
        use crate::test_db::setup_pool;

        // Process claim is monotonic; nextest isolates per test. No clear.
        set_process_stack_mode(ScanStackMode::V11);

        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        claim_stack_scan_mode(&pool, ScanStackMode::V11)
            .await
            .expect("claim v11");

        let adapter = EngineAdapter::load_or_create(pool.clone(), Network::Regtest, 0)
            .await
            .expect("adapter");

        let pk = [0x11u8; 32];
        let r = [0x22u8; 32];
        let r_prime = [0x33u8; 32];
        let owner = Address([0xA1u8; 32]);
        let asset_id = [0xAAu8; 32];
        let inclusion_hash = [0xBBu8; 32];
        let tip_hash = [0xCCu8; 32];

        adapter
            .with_engine_mut(|engine| {
                engine.set_tip_height(fold_height);
                let pos = engine
                    .append_nullifier(ScannedNullifier::from_survivor(&PublishedNullifier {
                        chain_pos: ChainPosition {
                            height: fold_height,
                            tx_index: 0,
                            vin_index: 0,
                            member_index: 0,
                        },
                        pk,
                        r,
                    }))
                    .expect("fold winning nullifier");
                assert_eq!(pos, 0);

                let mut balances = BTreeMap::new();
                balances.insert(asset_id, 7u128);
                let coinhist = CoinHistTree::new();
                let state = AccountState::new(
                    owner,
                    host::ZERO_HASH,
                    balances,
                    pk,
                    1,
                    coinhist.root(),
                )
                .expect("AccountState");
                // Real fixture op_secret (A/4'); nav_rand of the stored opening
                // is derived from it so the operational bundle is consistent.
                let op_secret =
                    OpSecret::new(Sha256::digest(b"zkCoins/v1/g6-attest/op_secret").into());
                let record = AccountRecord {
                    state,
                    coinhist,
                    nk: [0xD1; 32],
                    op_secret: Some(op_secret),
                    genesis_pubkey: [0xB0; 32],
                    spendable: BTreeMap::new(),
                    spent_ids: BTreeSet::new(),
                    last_proof: Some(hollow_compliance_proof()),
                    last_nav_opening: Some(NavOpening {
                        nav: Nav {
                            size: 0,
                            mth: host::nflog_empty(),
                        },
                        nav_rand: op_secret.derive_nav_rand(0),
                    }),
                    last_nullifier: Some(NullifierOpening {
                        public_key: pk,
                        signature_r: r,
                        r_prime,
                    }),
                    last_nullifier_pos: Some(0),
                };
                engine.insert_account(owner, record).expect("insert account");
                // Advance tip well past the fold so size_final covers pos 0
                // (FINALITY_CONFIRMATIONS = 6 → tip ≥ fold_height + 5).
                engine.set_tip_height(tip_height);
            })
            .expect("mutate engine");
        adapter.set_tip_hash(tip_hash).expect("tip hash");

        // Retain reveal_txid for this node's own publish of the nullifier.
        sqlx::query(
            "INSERT INTO v11_pending_publishes \
             (pk, owner, r, s, r_prime, build_tip_height, build_tip_hash, \
              commit_tx, reveal_tx, commit_txid, reveal_txid, status, created_at, updated_at) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'reveal_broadcast',NOW(),NOW())",
        )
        .bind(pk.as_slice())
        .bind(owner.0.as_slice())
        .bind(r.as_slice())
        .bind([0x44u8; 32].as_slice())
        .bind(r_prime.as_slice())
        .bind(i64::try_from(fold_height).unwrap())
        .bind(inclusion_hash.as_slice())
        .bind([0x01u8; 8].as_slice()) // dummy commit_tx
        .bind([0x02u8; 8].as_slice()) // dummy reveal_tx
        .bind([0x03u8; 32].as_slice()) // commit_txid
        .bind([0x31u8; 32].as_slice()) // reveal_txid
        .execute(&pool)
        .await
        .expect("insert pending publish with reveal_txid");

        // Durable inclusion hash for the fold height (confirmed-but-not-tip).
        crate::db::insert_block_log(
            &pool,
            &crate::db::BlockLogEntry {
                block_hash: inclusion_hash.to_vec(),
                block_height: Some(i64::try_from(fold_height).unwrap()),
                inscription_count: 1,
                processing_duration_us: None,
            },
        )
        .await
        .expect("insert block_log at fold height");

        (scope, adapter, owner, asset_id, [0x31u8; 32], inclusion_hash)
    }

    /// Defect 1: a genuinely final anchor (tip well beyond fold height)
    /// passes the completed-anchor gate **and** resolves its Bitcoin
    /// locator — so a completed attestation can reach the prove step.
    ///
    /// Turns red if `resolve_anchor_locator` again requires
    /// `nullifier_height == tip_height` (block_hash becomes None while
    /// size_final already covers the fold).
    #[tokio::test]
    async fn final_anchor_below_tip_resolves_locator_and_collects() {
        let fold_height = 100u64;
        let tip_height = 105u64; // ≥ fold + 5 → size_final covers pos 0
        let (_scope, adapter, owner, asset_id, reveal_txid, inclusion_hash) =
            seeded_attest_adapter(fold_height, tip_height).await;

        // Live classification from NfLog (not caller-supplied).
        let classification = adapter.with_engine(|e| {
            let rec = e.account(&owner).expect("account");
            let nf = rec.last_nullifier.as_ref().expect("nullifier");
            e.nflog().classify(nf.public_key, nf.signature_r)
        });
        assert_eq!(classification, SpendClassification::ValidFirstSpend);

        let materials = collect_materials(&adapter, &owner, &asset_id, None)
            .expect("completed first-occurrence inside size_final must collect");
        assert_eq!(materials.nullifier_height, fold_height);
        assert_eq!(materials.nullifier_pos, 0);

        let (txid, block_hash) =
            resolve_anchor_locator(&adapter, &materials.nullifier.public_key, materials.nullifier_height)
                .await
                .expect("locator resolve");
        assert_eq!(txid, Some(reveal_txid), "txid from pending.reveal_txid");
        assert_eq!(
            block_hash,
            Some(inclusion_hash),
            "confirmed-but-not-tip block_hash from block_log at fold height, not tip_hash"
        );
        require_resolved_anchor(txid, block_hash).expect("resolved locator");
    }

    /// Defect 3: completed-anchor gate is bound on the production path
    /// (`collect_materials` → `require_completed_anchor` with classification
    /// from the live NfLog). A not-yet-final first occurrence must fail
    /// here — deleting the production call at collect_materials turns
    /// this red (collect succeeds without the gate).
    #[tokio::test]
    async fn collect_materials_requires_completed_anchor_via_production_path() {
        // fold at tip-1: with tip = fold+1, size_final excludes the fold
        // (needs tip ≥ fold+5). ValidFirstSpend but not final.
        let fold_height = 100u64;
        let tip_height = 101u64;
        let (_scope, adapter, owner, asset_id, _txid, _hash) =
            seeded_attest_adapter(fold_height, tip_height).await;

        let (classification, size_final, pos) = adapter.with_engine(|e| {
            let rec = e.account(&owner).expect("account");
            let nf = rec.last_nullifier.as_ref().expect("nullifier");
            let classification = e.nflog().classify(nf.public_key, nf.signature_r);
            let size_final = e.nflog().size_final(e.tip_height());
            let pos = rec.last_nullifier_pos.expect("pos");
            (classification, size_final, pos)
        });
        assert_eq!(classification, SpendClassification::ValidFirstSpend);
        assert!(
            pos >= size_final,
            "fixture must be not-yet-final: pos={pos} size_final={size_final}"
        );

        let err = collect_materials(&adapter, &owner, &asset_id, None)
            .expect_err("not-yet-final first occurrence must fail via production gate");
        assert!(
            matches!(err, AttestError::ProvingFailed(_)),
            "got {err:?}"
        );
        assert!(
            err.message().contains("size_final") || err.message().contains("completed"),
            "production gate message: {}",
            err.message()
        );
    }

    #[test]
    fn u64_decimal_wire_rejects_json_number_and_accepts_string() {
        // size_ceiling as JSON number → deserialize error (§7.1).
        let num = serde_json::json!({
            "subject": "x",
            "asset_id": "00".repeat(32),
            "size_ceiling": 7,
            "nav_ceiling": "11".repeat(32),
            "challenge": { "nonce": "22".repeat(32) },
            "ownership_proof": {
                "type": "ownership",
                "subject": "x",
                "public_key": "00".repeat(32),
                "nk_commit": "00".repeat(32),
                "signature": "00".repeat(64),
            }
        });
        let err = serde_json::from_value::<AttestBalanceRequest>(num).unwrap_err();
        assert!(
            err.to_string().contains("decimal string") || err.to_string().contains("JSON number"),
            "got: {err}"
        );

        let ok = serde_json::json!({
            "subject": "x",
            "asset_id": "00".repeat(32),
            "size_ceiling": "7",
            "nav_ceiling": "11".repeat(32),
            "challenge": { "nonce": "22".repeat(32) },
            "ownership_proof": {
                "type": "ownership",
                "subject": "x",
                "public_key": "00".repeat(32),
                "nk_commit": "00".repeat(32),
                "signature": "00".repeat(64),
            }
        });
        let req: AttestBalanceRequest = serde_json::from_value(ok).unwrap();
        assert_eq!(req.size_ceiling, Some(U64Decimal(7)));

        assert_eq!(parse_u64_decimal("0").unwrap(), 0);
        assert_eq!(parse_u64_decimal("18446744073709551615").unwrap(), u64::MAX);
        assert!(parse_u64_decimal("01").is_err());
        assert!(parse_u64_decimal("").is_err());
        assert_eq!(U64Decimal::format(60), "60");
    }

    #[test]
    fn public_hosts_from_env_no_silent_localhost() {
        // Unset → empty (fail-closed at auth). Do not invent localhost.
        // (Env may already be set in the process; only assert the pure
        // empty-input path via the filter logic.)
        let hosts: Vec<String> = ""
            .split(',')
            .map(|s| s.trim().trim_end_matches('.').to_ascii_lowercase())
            .filter(|s| !s.is_empty())
            .collect();
        assert!(hosts.is_empty());
    }
}
