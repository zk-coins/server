//! §4.2 send-path delivery: finished transition → gift-wrapped kind-1059.
//!
//! # What this module owns
//!
//! The production path that turns an **already-proved, already-persisted**
//! transition's outgoing coins into:
//!
//! 1. per-coin keys (`esk`/`epk`/`K_tx`/`detect_tag` via
//!    [`shared::spec_v1::note_encryption`]),
//! 2. `CoinProof.ciphertext` = **NIP44Binary** under `K_tx` (the note
//!    envelope — **not** the ZBE blob ciphertext; both are informally called
//!    "ciphertext" and must not be confused; only the ZBE output is hashed
//!    for `blob_id`),
//! 3. `serialize(CoinProof)` → **ZBE** under `K_tx` → `(zbe_ciphertext, blob_id)`,
//! 4. Blossom upload under the account `op` key (kind-24242),
//! 5. `DeliveryEvent.payload` → NIP-44 to the recipient's **IVPK** → NIP-59
//!    gift-wrap with **exactly** the two cleartext outer tags `zkdt` / `zkepk`,
//! 6. publish to the recipient's relays with **per-relay** outcomes,
//! 7. durable outbox row (migration 0032) inserted **atomically with**
//!    transition persist; first mesh publish marks `awaiting_ack`;
//! 8. ACK return path: poll gift-wraps, unwrap under sender `ivk`, verify
//!    kind-1421 (`op_sig` under published recipient `op` **and** nonce
//!    binding), advance outbox to `completed` (valid ACK ends the delivery
//!    state machine; the row and blob/SDR stay stored — data permanence);
//! 9. runtime tick republishes due `pending` / `awaiting_ack` rows with
//!    §4.2 exponential backoff (30 s → double → cap 1 h); terminal publish
//!    failures (`DeliveryError::is_terminal_outbox_failure`) call
//!    `db_outbox::mark_failed` so the row leaves the drive loop with a
//!    named `fail_reason` (never silent eternal republish).
//!
//! # Port boundary
//!
//! The kernel never sees axum/tonic/relay/HTTP types. Runtime supplies an
//! [`OutgoingDeliveryPort`]; finalise inserts outbox rows in the same TX as
//! engine persist, then the port drives mesh publish. Missing operational
//! bundle or missing recipient IVPK is a **named error** — never a silent
//! skip that pretends delivery succeeded.
//!
//! Delivery targets are filled from fully verified profiles / Invoices
//! **before** prove/persist ([`ensure_delivery_targets_before_finalise`]).
//!
//! # Self-delivery
//!
//! Outbox `kind = self_delivery` is §4.2 Phase B: after first-occurrence
//! MTP the scanner hook ([`super::sdr::finalize_due_phase_b_adapter`]) seals
//! `SelfDeliveryRecordV1` and inserts via [`insert_sdr_outbox_pending`].
//! Drive/Resume/Backoff is the **same** [`drive_due_outbox_entries`] path
//! as external coins. Recovery SDR **replay** remains
//! [`crate::v1::recovery::SdrReplayStatus::Unavailable`].
//!
//! Spec: §1.3, §2.3.2, §4.2, §4.2.1, §4.3, §7.1, §7.3.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use shared::spec_v1::bundle::{
    serialize_blob_locator_set, serialize_coin_proof, BlobLocatorSet, CoinProof, CreatingNullifier,
    IssuanceTerms, NavOpening as BundleNavOpening,
};
use shared::spec_v1::datastructures::Coin;
use shared::spec_v1::encoding::digest_to_bytes;
use shared::spec_v1::hashes::detect_tag as poseidon_detect_tag;
use shared::spec_v1::note_encryption::{
    derive_note_key, derive_out_key, envelope_seal, shared_secret_sender, xonly_pubkey, zbe_seal,
    ENVELOPE_LABEL_COIN, ENVELOPE_LABEL_K_TX,
};
use shared::spec_v1::serialize::serialize_coin;
use shared::spec_v1::trees::{empty_leaf_hash, leaf_hash, node_hash, TreeKind};
use shared::spec_v1::{HashDigest, SpecError};

use super::blossom::{blob_id_of, BlossomClient, BlossomError, RetentionClass, UploadBinding};
use super::db_outbox::{self, OutboxInsert, OutboxKind, OutboxRow, PublishArtefacts};
use super::nostr::event::Event;
use super::nostr::kinds::ack::{
    decode_ack_content, verify_ack_sig, AckContent, AckError, KIND_ACK,
};
use super::nostr::kinds::delivery::{delivery_rumor, DeliveryPayload, DeliveryPayloadError};
use super::nostr::nip44::{self, Nip44Error};
use super::nostr::nip59::{
    delivery_scan_tags, seal_and_wrap, unwrap_gift, Nip59Error, SecureRandom, KIND_GIFT_WRAP,
};
use super::nostr::profile::{
    resolve_profile_by_op_pubkey, verify_invoice, PaymentInvoice, ProfileResolveError,
    VerifiedPaymentProfile,
};
use super::nostr::relay::{Filter, RelayPool, RelayPublishResult};
use super::outbox_material::ExternalOutboxMaterial;
use crate::kernel::bootstrap::ManifestStore;
use sqlx::PgPool;

// ---------------------------------------------------------------------------
// Errors — named causes, never a bare `is_err()` contract
// ---------------------------------------------------------------------------

/// Fail-closed reasons for the §4.2 send delivery path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DeliveryError {
    /// CSPRNG refused entropy (fresh `esk` / `ack_nonce` / NIP-44 nonces).
    RandomSourceFailed,
    /// Scalar / x-only / ECDH / HKDF / envelope / ZBE failure from `spec_v1`.
    Spec(SpecError),
    /// NIP-44 AEAD (coin note or delivery payload) failed.
    Nip44(Nip44Error),
    /// NIP-59 seal / gift-wrap failed.
    Nip59(Nip59Error),
    /// Kind-1420 payload encode failed.
    Payload(DeliveryPayloadError),
    /// Operational bundle (`op` / `ovk` / `ivk`) is not process-local.
    ///
    /// BundleStore is process-memory only; a restart leaves it empty. Never
    /// invent keys.
    OperationalBundleMissing { subject: [u8; 32] },
    /// Recipient address has no verified IVPK (profile or Invoice).
    ///
    /// Must not skip the recipient and report success.
    RecipientIvpkUnavailable { recipient: [u8; 32] },
    /// Recipient has no advertised relay set (empty list).
    RecipientRelaysEmpty { recipient: [u8; 32] },
    /// No Blossom holder base URL was configured for this delivery.
    BlobHoldersEmpty,
    /// The wall clock cannot produce a valid unix timestamp for Blossom auth.
    BlossomAuthClockBeforeUnixEpoch,
    /// Blossom upload failed for one holder.
    Blossom { holder: String, error: BlossomError },
    /// No verified-manifest Blossom store accepted the recovery overlap blob.
    OverlapBlobStore {
        attempted: usize,
        results: Vec<BlossomOutcomeSummary>,
    },
    /// Relay pool construction / empty list.
    Relay(String),
    /// Every relay rejected or was unreachable — nothing accepted the wrap.
    NoRelayAccepted { results: Vec<RelayOutcomeSummary> },
    /// No verified-manifest seed relay accepted the recovery overlap wrap.
    OverlapSeedRelay { results: Vec<RelayOutcomeSummary> },
    /// Wire framing / length error while building inclusion_proof.
    InclusionProof(String),
    /// Plonky2 proof serialisation failed.
    ProofBytes(String),
    /// SDR Phase-A `output_ref` could not be built from delivery material
    /// (empty holders and/or empty `out_ciphertext`).
    SdrOutputRef(String),
    /// Durable/local disclosure indexing of a self-delivered coin failed.
    SelfDeliveryIndex(String),
    /// Outer gift-wrap tags are not exactly `zkdt` + `zkepk`.
    OuterTagsInvalid { detail: String },
    /// Profile / Invoice resolution failed for a recipient (named check).
    ProfileResolve { recipient: [u8; 32], detail: String },
    /// Delivery-target entry expired (replaceable profile; must re-resolve).
    RecipientTargetExpired {
        recipient: [u8; 32],
        expired_at: u64,
        now: u64,
    },
}

/// Compact per-relay outcome for error reporting (no transport types).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RelayOutcomeSummary {
    pub relay_url: String,
    pub accepted: bool,
    pub detail: String,
}

/// Per-store failure detail for a recovery-overlap Blossom attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct BlossomOutcomeSummary {
    pub holder: String,
    pub detail: String,
}

impl fmt::Display for DeliveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DeliveryError::RandomSourceFailed => {
                write!(f, "delivery CSPRNG failed (no silent zero key)")
            }
            DeliveryError::Spec(e) => write!(f, "delivery crypto/codec: {e}"),
            DeliveryError::Nip44(e) => write!(f, "delivery NIP-44: {e}"),
            DeliveryError::Nip59(e) => write!(f, "delivery NIP-59: {e}"),
            DeliveryError::Payload(e) => write!(f, "delivery payload: {e}"),
            DeliveryError::OperationalBundleMissing { subject } => write!(
                f,
                "operational bundle missing for subject {} \
                 (process-local BundleStore; no default keys)",
                hex::encode(subject)
            ),
            DeliveryError::RecipientIvpkUnavailable { recipient } => write!(
                f,
                "recipient {} has no verified IVPK (profile or Invoice required; \
                 refusing silent skip)",
                hex::encode(recipient)
            ),
            DeliveryError::RecipientRelaysEmpty { recipient } => write!(
                f,
                "recipient {} has empty relay set (no default relay)",
                hex::encode(recipient)
            ),
            DeliveryError::BlobHoldersEmpty => {
                write!(f, "blob holder list is empty (no default Blossom store)")
            }
            DeliveryError::BlossomAuthClockBeforeUnixEpoch => write!(
                f,
                "Blossom auth wall clock before UNIX epoch (no timestamp fallback)"
            ),
            DeliveryError::Blossom { holder, error } => {
                write!(f, "Blossom upload to {holder}: {error}")
            }
            DeliveryError::OverlapBlobStore { attempted, results } => write!(
                f,
                "no verified-manifest blob store accepted the recovery overlap blob \
                 ({attempted} attempted, {} failures)",
                results.len()
            ),
            DeliveryError::Relay(msg) => write!(f, "relay pool: {msg}"),
            DeliveryError::NoRelayAccepted { results } => {
                write!(
                    f,
                    "no relay accepted the gift-wrap ({} outcomes)",
                    results.len()
                )
            }
            DeliveryError::OverlapSeedRelay { results } => write!(
                f,
                "no verified-manifest seed relay accepted the recovery overlap gift-wrap \
                 ({} outcomes)",
                results.len()
            ),
            DeliveryError::InclusionProof(msg) => write!(f, "inclusion_proof: {msg}"),
            DeliveryError::ProofBytes(msg) => write!(f, "proof bytes: {msg}"),
            DeliveryError::SdrOutputRef(msg) => write!(f, "SDR output_ref: {msg}"),
            DeliveryError::SelfDeliveryIndex(msg) => {
                write!(f, "self-delivery private index: {msg}")
            }
            DeliveryError::OuterTagsInvalid { detail } => {
                write!(f, "gift-wrap outer tags invalid: {detail}")
            }
            DeliveryError::ProfileResolve { recipient, detail } => write!(
                f,
                "profile/invoice resolution for recipient {} failed: {detail}",
                hex::encode(recipient)
            ),
            DeliveryError::RecipientTargetExpired {
                recipient,
                expired_at,
                now,
            } => write!(
                f,
                "delivery target for recipient {} expired at {expired_at} (now={now}); \
                 re-resolve profile (no silent reuse of stale relays)",
                hex::encode(recipient)
            ),
        }
    }
}

impl std::error::Error for DeliveryError {}

impl DeliveryError {
    /// Whether an outbox publish failure is **terminal** (row must leave the
    /// drive loop via [`db_outbox::mark_failed`]) vs **transient** (retain
    /// and republish under §4.2 backoff).
    ///
    /// §4.2 RECOMMENDED freezes delay growth (30 s → double → cap 1 h) but
    /// does **not** hard-cap attempt count: pure network/relay unavailability
    /// keeps retrying at the 1 h cap. Terminal means the same durable
    /// material / config / rejected target cannot recover by waiting —
    /// crypto/codec on fixed bytes, empty holder/relay sets, permanent
    /// Blossom policy rejects (403/401/…), profile/IVPK refusal.
    ///
    /// `attempt_n` only advances on **successful** mesh publish
    /// ([`db_outbox::mark_published`]); it is not a failed-attempt counter,
    /// so classification is by error kind, not attempt threshold.
    pub(crate) fn is_terminal_outbox_failure(&self) -> bool {
        match self {
            // OS entropy can recover; do not bury the row.
            DeliveryError::RandomSourceFailed => false,
            // A broken wall clock may be corrected; retain the row for retry.
            DeliveryError::BlossomAuthClockBeforeUnixEpoch => false,
            // Process-local BundleStore may be refilled after restart/load.
            DeliveryError::OperationalBundleMissing { .. } => false,
            // Peer/network: all relays down or rejecting is usually temporary.
            DeliveryError::NoRelayAccepted { .. }
            | DeliveryError::OverlapBlobStore { .. }
            | DeliveryError::OverlapSeedRelay { .. } => false,
            // DB / pool / mark_published wiring after a mesh attempt — retry.
            DeliveryError::Relay(_) => false,
            // Database/mirror availability may recover on finalise resume.
            DeliveryError::SelfDeliveryIndex(_) => false,
            // Fixed material / local construction: waiting never helps.
            DeliveryError::Spec(_)
            | DeliveryError::Nip44(_)
            | DeliveryError::Nip59(_)
            | DeliveryError::Payload(_)
            | DeliveryError::InclusionProof(_)
            | DeliveryError::ProofBytes(_)
            | DeliveryError::SdrOutputRef(_)
            | DeliveryError::OuterTagsInvalid { .. }
            | DeliveryError::RecipientIvpkUnavailable { .. }
            | DeliveryError::RecipientRelaysEmpty { .. }
            | DeliveryError::BlobHoldersEmpty
            | DeliveryError::ProfileResolve { .. }
            | DeliveryError::RecipientTargetExpired { .. } => true,
            DeliveryError::Blossom { error, .. } => error.is_terminal(),
        }
    }
}

impl From<SpecError> for DeliveryError {
    fn from(value: SpecError) -> Self {
        DeliveryError::Spec(value)
    }
}

impl From<Nip44Error> for DeliveryError {
    fn from(value: Nip44Error) -> Self {
        DeliveryError::Nip44(value)
    }
}

impl From<Nip59Error> for DeliveryError {
    fn from(value: Nip59Error) -> Self {
        DeliveryError::Nip59(value)
    }
}

impl From<DeliveryPayloadError> for DeliveryError {
    fn from(value: DeliveryPayloadError) -> Self {
        DeliveryError::Payload(value)
    }
}

// ---------------------------------------------------------------------------
// ACK verification (sender side) — nonce binding is mandatory
// ---------------------------------------------------------------------------

/// Why a presented ACK is not accepted for **this** delivery attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AckVerifyError {
    /// Field decode failed (closed four fields / hex).
    Decode(AckError),
    /// `op_sig` does not verify under the recipient's published `op` pubkey.
    BadOpSignature,
    /// Echoed `ack_nonce` is not the nonce chosen for **this** attempt.
    ///
    /// This is what makes a captured ACK from attempt 1 worthless against
    /// attempt 2 (fresh `ack_nonce` per retry, §4.2).
    AckNonceMismatch { expected: [u8; 32], got: [u8; 32] },
    /// ACK `detect_tag` / `blob_id` do not match the retained attempt.
    FieldMismatch { field: &'static str },
}

impl fmt::Display for AckVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AckVerifyError::Decode(e) => write!(f, "ACK decode: {e}"),
            AckVerifyError::BadOpSignature => {
                write!(f, "ACK op_sig verification failed under recipient op")
            }
            AckVerifyError::AckNonceMismatch { expected, got } => write!(
                f,
                "ACK ack_nonce mismatch: expected={}, got={} \
                 (stale ACK from another attempt)",
                hex::encode(expected),
                hex::encode(got)
            ),
            AckVerifyError::FieldMismatch { field } => {
                write!(f, "ACK field {field} does not match retained attempt")
            }
        }
    }
}

impl std::error::Error for AckVerifyError {}

/// Verify a decoded ACK against the sender's retained attempt state.
///
/// Both checks are mandatory (§4.2):
/// 1. `op_sig` under the recipient's **published** `op` pubkey over
///    `ack_message = H("zkCoins/v1/Ack" ‖ detect_tag ‖ blob_id ‖ ack_nonce)`
///    (raw 32-byte fields);
/// 2. echoed `ack_nonce` equals the nonce this attempt chose.
pub(crate) fn verify_delivery_ack(
    recipient_op_pk: &[u8; 32],
    expected_detect_tag: &[u8; 32],
    expected_blob_id: &[u8; 32],
    expected_ack_nonce: &[u8; 32],
    content: &AckContent,
) -> Result<(), AckVerifyError> {
    if &content.detect_tag != expected_detect_tag {
        return Err(AckVerifyError::FieldMismatch {
            field: "detect_tag",
        });
    }
    if &content.blob_id != expected_blob_id {
        return Err(AckVerifyError::FieldMismatch { field: "blob_id" });
    }
    // (ii) nonce binding — checked **before** signature so a replay against
    // a later attempt is named as nonce mismatch, not a generic bad sig.
    if &content.ack_nonce != expected_ack_nonce {
        return Err(AckVerifyError::AckNonceMismatch {
            expected: *expected_ack_nonce,
            got: content.ack_nonce,
        });
    }
    // (i) op_sig under published op.
    verify_ack_sig(recipient_op_pk, content).map_err(|e| match e {
        AckError::BadOpSignature => AckVerifyError::BadOpSignature,
        other => AckVerifyError::Decode(other),
    })?;
    Ok(())
}

/// Decode ACK JSON then [`verify_delivery_ack`].
pub(crate) fn verify_delivery_ack_json(
    recipient_op_pk: &[u8; 32],
    expected_detect_tag: &[u8; 32],
    expected_blob_id: &[u8; 32],
    expected_ack_nonce: &[u8; 32],
    json: &str,
) -> Result<(), AckVerifyError> {
    let content = decode_ack_content(json).map_err(AckVerifyError::Decode)?;
    verify_delivery_ack(
        recipient_op_pk,
        expected_detect_tag,
        expected_blob_id,
        expected_ack_nonce,
        &content,
    )
}

// ---------------------------------------------------------------------------
// Per-coin keys (§1.3) — always via note_encryption, never a second derivation
// ---------------------------------------------------------------------------

/// Fresh per-coin note keys. `esk` **must** be unique per coin: reusing it
/// links `K_tx` / `detect_tag` publicly and repeats `(kb, nonce)` in ZBE
/// (§4.2.1 forbids).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PerCoinKeys {
    pub esk: [u8; 32],
    pub epk: [u8; 32],
    pub ss: [u8; 32],
    pub k_tx: [u8; 32],
    /// Poseidon digest bytes of `detect_tag` (on-wire / tag form).
    pub detect_tag: [u8; 32],
    /// Typed Poseidon digest (for `CoinProof.detect_tag`).
    pub detect_tag_digest: HashDigest,
}

/// Draw a fresh secp256k1 scalar from `rng` (bounded rejection sampling).
///
/// On CSPRNG failure returns [`DeliveryError::RandomSourceFailed`] — never a
/// zero or partially filled key.
pub(crate) fn fresh_esk(rng: &mut dyn SecureRandom) -> Result<[u8; 32], DeliveryError> {
    use bitcoin::secp256k1::SecretKey;
    for _ in 0..64 {
        let mut bytes = [0u8; 32];
        rng.fill_bytes(&mut bytes)
            .map_err(|_| DeliveryError::RandomSourceFailed)?;
        if SecretKey::from_slice(&bytes).is_ok() {
            return Ok(bytes);
        }
    }
    Err(DeliveryError::RandomSourceFailed)
}

/// `esk` → `epk` / `ss` / `K_tx` / `detect_tag` for one recipient IVPK.
pub(crate) fn derive_per_coin_keys(
    esk: &[u8; 32],
    recipient_ivpk: &[u8; 32],
) -> Result<PerCoinKeys, DeliveryError> {
    let epk = xonly_pubkey(esk)?;
    let ss = shared_secret_sender(esk, recipient_ivpk)?;
    let k_tx = derive_note_key(&ss, &epk)?;
    let detect_tag_digest = poseidon_detect_tag(&ss, &epk);
    let detect_tag = digest_to_bytes(&detect_tag_digest);
    Ok(PerCoinKeys {
        esk: *esk,
        epk,
        ss,
        k_tx,
        detect_tag,
        detect_tag_digest,
    })
}

// ---------------------------------------------------------------------------
// Coin note ciphertext vs ZBE blob ciphertext (do not confuse)
// ---------------------------------------------------------------------------

/// `CoinProof.ciphertext` = NIP44Binary(`K_tx`, `"coin"`, `serialize(Coin)`).
///
/// This is the **note-level** ciphertext stored **inside** the CoinProof
/// plaintext. It is **not** the ZBE blob envelope: the ZBE ciphertext is
/// produced later by [`zbe_seal`] over `serialize(CoinProof)` and is the only
/// byte string whose SHA-256 is `blob_id` (§4.2.1).
///
/// Returns the UTF-8 bytes of NIP-44's standard-Base64 AEAD payload (stored-
/// field discipline of `note_encryption`).
pub(crate) fn seal_coin_note_ciphertext(
    k_tx: &[u8; 32],
    coin: &Coin,
    nip44_nonce: &[u8; 32],
) -> Result<Vec<u8>, DeliveryError> {
    let coin_bytes = serialize_coin(coin);
    // Inner envelope plaintext (UTF-8) → NIP-44 under K_tx as conversation key.
    let envelope = envelope_seal(ENVELOPE_LABEL_COIN, &coin_bytes)?;
    let payload = nip44::encrypt(k_tx, &envelope, nip44_nonce)?;
    Ok(payload.into_bytes())
}

/// `out_ciphertext` for an SDR `output_ref`: NIP44Binary(`K_out`, `"K_tx"`, `K_tx`).
///
/// `K_out = HKDF("zkCoins/v1/OutKey", ovk ‖ epk)`. Used by self-delivery /
/// outgoing recovery; not placed on the mesh delivery event.
pub(crate) fn out_ciphertext_for_output_ref(
    ovk: &[u8; 32],
    epk: &[u8; 32],
    k_tx: &[u8; 32],
    nip44_nonce: &[u8; 32],
) -> Result<Vec<u8>, DeliveryError> {
    let k_out = derive_out_key(ovk, epk)?;
    let envelope = envelope_seal(ENVELOPE_LABEL_K_TX, k_tx)?;
    let payload = nip44::encrypt(&k_out, &envelope, nip44_nonce)?;
    Ok(payload.into_bytes())
}

// ---------------------------------------------------------------------------
// inclusion_proof wire (§1.7.5)
// ---------------------------------------------------------------------------

/// Canonical `inclusion_proof` bytes for leaf `leaf_index` among `leaves`
/// (coin identifiers as digests, pre-padding order).
pub(crate) fn serialize_coins_root_inclusion_proof(
    leaves: &[HashDigest],
    leaf_index: u32,
) -> Result<Vec<u8>, DeliveryError> {
    if leaves.is_empty() {
        return Err(DeliveryError::InclusionProof(
            "empty output list has no membership proof".into(),
        ));
    }
    if leaf_index as usize >= leaves.len() {
        return Err(DeliveryError::InclusionProof(format!(
            "leaf_index {leaf_index} out of range for {} leaves",
            leaves.len()
        )));
    }
    let pad = empty_leaf_hash(TreeKind::CoinsRoot);
    let mut level: Vec<HashDigest> = leaves
        .iter()
        .copied()
        .map(|v| leaf_hash(TreeKind::CoinsRoot, v))
        .collect();
    let target = level.len().next_power_of_two();
    level.resize(target, pad);
    // depth = log2(padded count); 0 for a single-leaf tree.
    let depth = target.trailing_zeros() as u8;
    let mut siblings = Vec::with_capacity(depth as usize);
    let mut idx = leaf_index as usize;
    let mut cur = level;
    for _ in 0..depth {
        let sibling_idx = idx ^ 1;
        siblings.push(cur[sibling_idx]);
        let mut next = Vec::with_capacity(cur.len() / 2);
        for pair in cur.chunks_exact(2) {
            next.push(node_hash(TreeKind::CoinsRoot, pair[0], pair[1]));
        }
        cur = next;
        idx /= 2;
    }
    let mut out = Vec::with_capacity(4 + 1 + siblings.len() * 32);
    out.extend_from_slice(&leaf_index.to_be_bytes());
    out.push(depth);
    for s in &siblings {
        out.extend_from_slice(&digest_to_bytes(s));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Materials for one outgoing recipient coin
// ---------------------------------------------------------------------------

/// Everything needed to build one CoinProof + deliver it, after prove/persist.
#[derive(Clone, Debug)]
pub(crate) struct OutgoingCoinMaterial {
    pub coin: Coin,
    /// Leaf index in this transition's `output_coins` (§1.7.5 / coin_index).
    pub leaf_index: u32,
    /// All output-coin identifiers of the creating transition (for inclusion).
    pub all_output_ids: Vec<HashDigest>,
    /// Recursive proof bytes (`ProofWithPublicInputs::to_bytes()`).
    pub proof_bytes: Vec<u8>,
    pub creating_prev_ash: HashDigest,
    pub creating_nullifier: CreatingNullifier,
    pub nav_opening: BundleNavOpening,
    pub asset_terms: Option<IssuanceTerms>,
    /// Verified recipient IVPK (from profile or Invoice) — never invented.
    pub recipient_ivpk: [u8; 32],
    /// Recipient's published `op` x-only pubkey (ACK verification).
    pub recipient_op_pk: [u8; 32],
    /// Recipient advertised relays (`ws://` / `wss://`).
    pub recipient_relays: Vec<String>,
}

/// Operator-local upload / holder context for one delivery attempt.
#[derive(Clone, Debug)]
pub(crate) struct DeliveryOperatorContext {
    /// Account operational signing key (Blossom kind-24242 + NIP-59 sealer).
    pub op_sk: [u8; 32],
    /// Outgoing-view key — seals `out_ciphertext` for SDR output_refs (§1.3).
    pub ovk: [u8; 32],
    /// Ordered Blossom base URLs that will hold the blob (holders only).
    pub blob_holders: Vec<String>,
    /// From `/v1/info` — required, no default.
    pub max_blob_bytes: u64,
    /// Wall clock for delivery-event / seal `created_at`.
    pub now: u64,
}

// ---------------------------------------------------------------------------
// Built (but not yet published) per-coin delivery
// ---------------------------------------------------------------------------

/// Result of the pure build steps for one coin (before network I/O).
///
/// The canonical serialized `CoinProof` is retained byte-for-byte so a local
/// self-delivery can be durably disclosed without attempting to reconstruct
/// randomized note-encryption material. `out_ciphertext` is retained on
/// [`RetainedDeliveryAttempt`] (SDR / §1.3), not here.
#[derive(Clone, Debug)]
pub(crate) struct BuiltCoinDelivery {
    pub keys: PerCoinKeys,
    /// Canonical §7.1 `serialize(CoinProof)` bytes sealed by ZBE below.
    pub canonical: Vec<u8>,
    /// ZBE ciphertext — the only blob hashed for `blob_id`.
    pub zbe_ciphertext: Vec<u8>,
    pub blob_id: [u8; 32],
    pub ack_nonce: [u8; 32],
    /// `out_ciphertext` for SDR output_ref (`NIP44Binary(K_out, "K_tx", K_tx)`).
    pub out_ciphertext: Vec<u8>,
    /// Outer kind-1059 gift-wrap ready to publish.
    pub gift_wrap: super::nostr::event::Event,
    pub recipient_op_pk: [u8; 32],
    pub recipient_relays: Vec<String>,
    pub blob_holders: Vec<String>,
}

/// Build keys + CoinProof + ZBE + gift-wrap for one outgoing coin.
///
/// Does **not** upload or publish. Fresh `esk` and `ack_nonce` from `rng`.
///
/// `ovk` is required for the SDR `out_ciphertext` envelope (§1.3 / §4.2
/// output_ref); never invented — missing ovk is a caller bug (operational
/// bundle always carries it when delivery is allowed).
///
/// `rng` is a trait object so the production port can share one
/// `Box<dyn SecureRandom + Send>` under a mutex without guessing how many
/// pointer layers to peel at the call site (`rng.as_mut()`).
pub(crate) fn build_coin_delivery(
    material: &OutgoingCoinMaterial,
    op_sk: &[u8; 32],
    ovk: &[u8; 32],
    blob_holders: &[String],
    now: u64,
    rng: &mut dyn SecureRandom,
) -> Result<BuiltCoinDelivery, DeliveryError> {
    if blob_holders.is_empty() {
        return Err(DeliveryError::BlobHoldersEmpty);
    }
    if material.recipient_relays.is_empty() {
        return Err(DeliveryError::RecipientRelaysEmpty {
            recipient: material.coin.recipient.0,
        });
    }

    // 1. Fresh per-coin esk — never reused across coins.
    let esk = fresh_esk(rng)?;
    let keys = derive_per_coin_keys(&esk, &material.recipient_ivpk)?;

    // 2. Coin note ciphertext (NIP44Binary) — NOT the ZBE blob.
    let mut note_nonce = [0u8; 32];
    rng.fill_bytes(&mut note_nonce)
        .map_err(|_| DeliveryError::RandomSourceFailed)?;
    let note_ciphertext = seal_coin_note_ciphertext(&keys.k_tx, &material.coin, &note_nonce)?;

    // 3. inclusion_proof + CoinProof + ZBE under K_tx.
    let inclusion_proof =
        serialize_coins_root_inclusion_proof(&material.all_output_ids, material.leaf_index)?;
    let coin_proof = CoinProof {
        coin: material.coin.clone(),
        proof: material.proof_bytes.clone(),
        inclusion_proof,
        creating_prev_ash: material.creating_prev_ash,
        creating_nullifier: material.creating_nullifier,
        nav_opening: material.nav_opening,
        asset_terms: material.asset_terms.clone(),
        epk: keys.epk,
        ciphertext: note_ciphertext,
        detect_tag: keys.detect_tag_digest,
    };
    let bundle_plaintext = serialize_coin_proof(&coin_proof)?;
    let (zbe_ciphertext, blob_id) = zbe_seal(&keys.k_tx, &bundle_plaintext)?;

    // 3b. out_ciphertext for SDR output_ref (sender ovk recovers K_tx).
    let mut out_nonce = [0u8; 32];
    rng.fill_bytes(&mut out_nonce)
        .map_err(|_| DeliveryError::RandomSourceFailed)?;
    let out_ciphertext = out_ciphertext_for_output_ref(ovk, &keys.epk, &keys.k_tx, &out_nonce)?;

    // 4. DeliveryEvent.payload (holders only; blob_id is context beside the set).
    let mut ack_nonce = [0u8; 32];
    rng.fill_bytes(&mut ack_nonce)
        .map_err(|_| DeliveryError::RandomSourceFailed)?;
    let holders: Vec<String> = blob_holders.to_vec();
    // Validate framing via the shared codec (holders only).
    let _framed = serialize_blob_locator_set(&BlobLocatorSet {
        holders: holders.clone(),
    })?;
    let payload = DeliveryPayload {
        blob_id,
        holders: holders.clone(),
        ack_nonce,
        record_kind: None,
    };

    // 5. NIP-44 to IVPK, then NIP-59 gift-wrap under fresh ephemeral key.
    //    Outer tags: exactly zkdt + zkepk (§4.2 step 4 / §7.3).
    let op_pk = xonly_pubkey(op_sk)?;
    let rumor = delivery_rumor(op_pk, now, &payload)?;
    let outer_tags = delivery_scan_tags(&keys.detect_tag, &keys.epk);
    let gift_wrap = seal_and_wrap(
        &rumor,
        op_sk,
        &material.recipient_ivpk,
        outer_tags,
        now,
        rng,
    )?;

    // Hard invariant: outer kind-1059 carries exactly the two scan tags.
    assert_outer_tags_are_exactly_delivery_scan(&gift_wrap.tags, &keys.detect_tag, &keys.epk)?;

    Ok(BuiltCoinDelivery {
        keys,
        canonical: bundle_plaintext,
        zbe_ciphertext,
        blob_id,
        ack_nonce,
        out_ciphertext,
        gift_wrap,
        recipient_op_pk: material.recipient_op_pk,
        recipient_relays: material.recipient_relays.clone(),
        blob_holders: holders,
    })
}

/// Fail-closed check used by build and by the tag-set unit test.
fn assert_outer_tags_are_exactly_delivery_scan(
    tags: &[Vec<String>],
    detect_tag: &[u8; 32],
    epk: &[u8; 32],
) -> Result<(), DeliveryError> {
    let expected = delivery_scan_tags(detect_tag, epk);
    if tags.len() != 2 {
        return Err(DeliveryError::OuterTagsInvalid {
            detail: format!("expected exactly 2 tags, got {}", tags.len()),
        });
    }
    if tags != expected.as_slice() {
        return Err(DeliveryError::OuterTagsInvalid {
            detail: format!(
                "expected zkdt+zkepk scan tags, got {:?}",
                tags.iter().map(|t| t.first().cloned()).collect::<Vec<_>>()
            ),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Network publish: Blossom + relays
// ---------------------------------------------------------------------------

/// Per-coin publish report (no aggregated success bool).
///
/// Empty marker so call sites keep a typed success value; relay/blossom
/// detail is logged at the call site when needed.
#[derive(Clone, Debug, Default)]
pub(crate) struct CoinDeliveryReport {}

/// Upload a built coin's ZBE blob to every holder.
pub(crate) async fn upload_built_coin_blob(
    built: &BuiltCoinDelivery,
    op_sk: &[u8; 32],
    max_blob_bytes: u64,
) -> Result<(), DeliveryError> {
    let client = BlossomClient::new(max_blob_bytes).map_err(|e| DeliveryError::Blossom {
        holder: String::new(),
        error: e,
    })?;

    // Binding headers: event id + attempt nonce + indefinite retention
    // (data permanence — holders MUST NOT drop the blob).
    let binding = UploadBinding {
        event_id: built.gift_wrap.id,
        attempt_nonce: built.ack_nonce,
        retention: RetentionClass::Indefinite,
    };

    for holder in &built.blob_holders {
        // The build/finalise timestamp may precede multi-minute proving. Read
        // the wall clock at the network boundary for every kind-24242 event.
        let (auth_created_at, auth_expiration) = fresh_blossom_auth_timestamps()?;
        let _upload = client
            .upload(
                holder,
                &built.zbe_ciphertext,
                Some(&binding),
                op_sk,
                auth_created_at,
                auth_expiration,
            )
            .await
            .map_err(|e| DeliveryError::Blossom {
                holder: holder.clone(),
                error: e,
            })?;
    }

    Ok(())
}

/// Return a fresh kind-24242 auth window for an imminent Blossom upload.
///
/// This stays outside [`BlossomClient::upload`] so that the HTTP client keeps
/// its explicit timestamp injection boundary for deterministic unit tests.
pub(crate) fn fresh_blossom_auth_timestamps() -> Result<(u64, u64), DeliveryError> {
    blossom_auth_timestamps_at(SystemTime::now())
}

fn blossom_auth_timestamps_at(wall_clock: SystemTime) -> Result<(u64, u64), DeliveryError> {
    let created_at = wall_clock
        .duration_since(UNIX_EPOCH)
        .map_err(|_| DeliveryError::BlossomAuthClockBeforeUnixEpoch)?
        .as_secs();
    let expiration = created_at.saturating_add(super::blossom::AUTH_REPLAY_WINDOW_SECS);
    Ok((created_at, expiration))
}

/// Place the recovery-discoverable copy on both verified-manifest planes.
///
/// Every manifest Blob store is attempted, even after one succeeds. This
/// mirrors relay `publish_all`, preserves per-store diagnostics, and keeps a
/// single slow/unhealthy store visible without making it a delivery failure
/// once another verified-manifest store accepted the blob.
pub(crate) async fn publish_recovery_overlap(
    manifest_blob_stores: &[String],
    manifest_seed_relays: &[String],
    zbe_ciphertext: &[u8],
    gift_wrap: &Event,
    ack_nonce: [u8; 32],
    op_sk: &[u8; 32],
    max_blob_bytes: u64,
) -> Result<(), DeliveryError> {
    if manifest_blob_stores.is_empty() {
        return Err(DeliveryError::OverlapBlobStore {
            attempted: 0,
            results: Vec::new(),
        });
    }

    let client =
        BlossomClient::new(max_blob_bytes).map_err(|error| DeliveryError::OverlapBlobStore {
            attempted: 0,
            results: vec![BlossomOutcomeSummary {
                holder: String::new(),
                detail: error.to_string(),
            }],
        })?;
    let binding = UploadBinding {
        event_id: gift_wrap.id,
        attempt_nonce: ack_nonce,
        retention: RetentionClass::Indefinite,
    };
    let mut attempted = 0usize;
    let mut accepted = 0usize;
    let mut blob_results = Vec::new();
    for holder in manifest_blob_stores {
        attempted = attempted.saturating_add(1);
        let timestamps = fresh_blossom_auth_timestamps();
        let upload = match timestamps {
            Ok((created_at, expiration)) => client
                .upload(
                    holder,
                    zbe_ciphertext,
                    Some(&binding),
                    op_sk,
                    created_at,
                    expiration,
                )
                .await
                .map(|_| ())
                .map_err(|error| error.to_string()),
            Err(error) => Err(error.to_string()),
        };
        match upload {
            Ok(()) => accepted = accepted.saturating_add(1),
            Err(detail) => blob_results.push(BlossomOutcomeSummary {
                holder: holder.clone(),
                detail,
            }),
        }
    }
    if accepted == 0 {
        return Err(DeliveryError::OverlapBlobStore {
            attempted,
            results: blob_results,
        });
    }

    if manifest_seed_relays.is_empty() {
        return Err(DeliveryError::OverlapSeedRelay {
            results: Vec::new(),
        });
    }
    let pool = RelayPool::new(manifest_seed_relays.to_vec()).map_err(|error| {
        DeliveryError::OverlapSeedRelay {
            results: manifest_seed_relays
                .iter()
                .map(|relay_url| RelayOutcomeSummary {
                    relay_url: relay_url.clone(),
                    accepted: false,
                    detail: error.to_string(),
                })
                .collect(),
        }
    })?;
    let relay_results = pool.publish_all(gift_wrap).await;
    let any_accepted = relay_results
        .iter()
        .any(|result| matches!(result, RelayPublishResult::Accepted { .. }));
    if !any_accepted {
        return Err(DeliveryError::OverlapSeedRelay {
            results: relay_outcome_summaries(&relay_results),
        });
    }

    Ok(())
}

fn relay_outcome_summaries(results: &[RelayPublishResult]) -> Vec<RelayOutcomeSummary> {
    results
        .iter()
        .map(|result| match result {
            RelayPublishResult::Accepted { relay_url, message } => RelayOutcomeSummary {
                relay_url: relay_url.clone(),
                accepted: true,
                detail: message.clone(),
            },
            RelayPublishResult::Rejected { relay_url, message } => RelayOutcomeSummary {
                relay_url: relay_url.clone(),
                accepted: false,
                detail: message.clone(),
            },
            RelayPublishResult::Unreachable { relay_url, error } => RelayOutcomeSummary {
                relay_url: relay_url.clone(),
                accepted: false,
                detail: error.to_string(),
            },
        })
        .collect()
}

/// One-connection NIP-01 relay used by delivery/SDR overlap tests.
#[cfg(test)]
pub(crate) async fn start_overlap_test_relay(
    accepted: bool,
) -> (String, Arc<Mutex<Vec<[u8; 32]>>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind overlap test relay");
    let address = listener.local_addr().expect("overlap test relay address");
    let events = Arc::new(Mutex::new(Vec::new()));
    let captured = Arc::clone(&events);
    tokio::spawn(async move {
        use futures_util::{SinkExt as _, StreamExt as _};
        use tokio_tungstenite::tungstenite::Message;

        let (stream, _) = listener.accept().await.expect("accept relay client");
        let mut websocket = tokio_tungstenite::accept_async(stream)
            .await
            .expect("accept websocket handshake");
        while let Some(frame) = websocket.next().await {
            let Message::Text(text) = frame.expect("read relay frame") else {
                continue;
            };
            let value: serde_json::Value =
                serde_json::from_str(&text).expect("parse NIP-01 client frame");
            if value.get(0).and_then(serde_json::Value::as_str) != Some("EVENT") {
                continue;
            }
            let event_id_hex = value
                .get(1)
                .and_then(|event| event.get("id"))
                .and_then(serde_json::Value::as_str)
                .expect("EVENT id");
            let event_id: [u8; 32] = hex::decode(event_id_hex)
                .expect("EVENT id hex")
                .try_into()
                .expect("EVENT id length");
            captured.lock().expect("capture relay event").push(event_id);
            let response = serde_json::json!([
                "OK",
                event_id_hex,
                accepted,
                if accepted {
                    "stored"
                } else {
                    "rejected by test relay"
                }
            ])
            .to_string();
            websocket
                .send(Message::Text(response))
                .await
                .expect("send relay OK");
            break;
        }
    });
    (format!("ws://{address}/"), events)
}

/// Upload ZBE blob to every holder, then publish gift-wrap to every relay.
pub(crate) async fn publish_built_delivery(
    built: &BuiltCoinDelivery,
    op_sk: &[u8; 32],
    max_blob_bytes: u64,
    manifest_blob_stores: &[String],
    manifest_seed_relays: &[String],
) -> Result<CoinDeliveryReport, DeliveryError> {
    upload_built_coin_blob(built, op_sk, max_blob_bytes).await?;

    let pool = RelayPool::new(built.recipient_relays.clone())
        .map_err(|e| DeliveryError::Relay(e.to_string()))?;
    let relay_results = pool.publish_all(&built.gift_wrap).await;

    let any_accepted = relay_results
        .iter()
        .any(|r| matches!(r, RelayPublishResult::Accepted { .. }));
    if !any_accepted {
        let results = relay_results
            .iter()
            .map(|r| match r {
                RelayPublishResult::Accepted { relay_url, message } => RelayOutcomeSummary {
                    relay_url: relay_url.clone(),
                    accepted: true,
                    detail: message.clone(),
                },
                RelayPublishResult::Rejected { relay_url, message } => RelayOutcomeSummary {
                    relay_url: relay_url.clone(),
                    accepted: false,
                    detail: message.clone(),
                },
                RelayPublishResult::Unreachable { relay_url, error } => RelayOutcomeSummary {
                    relay_url: relay_url.clone(),
                    accepted: false,
                    detail: error.to_string(),
                },
            })
            .collect();
        return Err(DeliveryError::NoRelayAccepted { results });
    }

    publish_recovery_overlap(
        manifest_blob_stores,
        manifest_seed_relays,
        &built.zbe_ciphertext,
        &built.gift_wrap,
        built.ack_nonce,
        op_sk,
        max_blob_bytes,
    )
    .await?;

    Ok(CoinDeliveryReport {})
}

// ---------------------------------------------------------------------------
// Process-local ACK cache (unit tests + optional mirror of durable outbox)
// ---------------------------------------------------------------------------

/// One retained delivery attempt for ACK verification (process-local mirror).
///
/// Production durability is `v1_delivery_outbox` (migration 0032). This store
/// remains for pure unit tests of ACK crypto without Postgres. A valid ACK
/// **marks** the attempt accepted; the retained copy is never dropped here
/// (data permanence — process-local mirror of the durable log).
#[derive(Clone, Debug)]
pub(crate) struct RetainedDeliveryAttempt {
    pub blob_id: [u8; 32],
    pub detect_tag: [u8; 32],
    pub k_tx: [u8; 32],
    pub ack_nonce: [u8; 32],
    pub zbe_ciphertext: Vec<u8>,
    pub out_ciphertext: Vec<u8>,
    pub recipient_op_pk: [u8; 32],
    /// True after a valid ACK; copy stays retained (data permanence).
    pub ack_accepted: bool,
}

/// Process-local pending-ACK store. Keyed by `(blob_id, ack_nonce)`.
#[derive(Debug, Default)]
pub(crate) struct PendingDeliveryStore {
    by_attempt: Mutex<HashMap<[u8; 64], RetainedDeliveryAttempt>>,
}

impl PendingDeliveryStore {
    pub(crate) fn new() -> Self {
        Self {
            by_attempt: Mutex::new(HashMap::new()),
        }
    }

    pub(crate) fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    fn attempt_key(blob_id: &[u8; 32], ack_nonce: &[u8; 32]) -> [u8; 64] {
        let mut k = [0u8; 64];
        k[..32].copy_from_slice(blob_id);
        k[32..].copy_from_slice(ack_nonce);
        k
    }

    pub(crate) fn retain(&self, mut attempt: RetainedDeliveryAttempt) {
        attempt.ack_accepted = false;
        let key = Self::attempt_key(&attempt.blob_id, &attempt.ack_nonce);
        let mut guard = self
            .by_attempt
            .lock()
            .expect("PendingDeliveryStore mutex poisoned");
        guard.insert(key, attempt);
    }

    pub(crate) fn get(
        &self,
        blob_id: &[u8; 32],
        ack_nonce: &[u8; 32],
    ) -> Option<RetainedDeliveryAttempt> {
        let key = Self::attempt_key(blob_id, ack_nonce);
        let guard = self
            .by_attempt
            .lock()
            .expect("PendingDeliveryStore mutex poisoned");
        guard.get(&key).cloned()
    }

    /// Verify ACK for this attempt and mark `ack_accepted`. Does **not** drop
    /// the retained copy (data permanence).
    pub(crate) fn accept_ack_json(
        &self,
        blob_id: &[u8; 32],
        ack_nonce: &[u8; 32],
        json: &str,
    ) -> Result<(), AckVerifyError> {
        let attempt = self
            .get(blob_id, ack_nonce)
            .ok_or(AckVerifyError::FieldMismatch {
                field: "blob_id|ack_nonce",
            })?;
        // Integrity of the retained §4.2 hold: ZBE body still content-addresses
        // to blob_id; out_ciphertext was sealed under ovk (non-empty).
        if blob_id_of(&attempt.zbe_ciphertext) != attempt.blob_id {
            return Err(AckVerifyError::FieldMismatch {
                field: "zbe_ciphertext/blob_id",
            });
        }
        if attempt.out_ciphertext.is_empty() {
            return Err(AckVerifyError::FieldMismatch {
                field: "out_ciphertext",
            });
        }
        // k_tx is the note key used to open the ZBE; refuse a zeroed retain.
        if attempt.k_tx == [0u8; 32] {
            return Err(AckVerifyError::FieldMismatch { field: "k_tx" });
        }
        verify_delivery_ack_json(
            &attempt.recipient_op_pk,
            &attempt.detect_tag,
            &attempt.blob_id,
            &attempt.ack_nonce,
            json,
        )?;
        let key = Self::attempt_key(blob_id, ack_nonce);
        let mut guard = self
            .by_attempt
            .lock()
            .expect("PendingDeliveryStore mutex poisoned");
        if let Some(entry) = guard.get_mut(&key) {
            entry.ack_accepted = true;
        }
        Ok(())
    }

    pub(crate) fn len(&self) -> usize {
        self.by_attempt
            .lock()
            .expect("PendingDeliveryStore mutex poisoned")
            .len()
    }
}

// ---------------------------------------------------------------------------
// Port — runtime supplies this; kernel stays transport-free
// ---------------------------------------------------------------------------

/// Inputs for delivering all external-recipient coins of one transition.
#[derive(Clone, Debug)]
pub(crate) struct TransitionDeliveryRequest {
    /// Account subject — logged on each published coin (audit trail).
    pub subject: [u8; 32],
    pub coins: Vec<OutgoingCoinMaterial>,
    pub operator: DeliveryOperatorContext,
}

/// Aggregated report after mesh delivery of every external coin.
///
/// Per-coin detail is logged at publish time (relay outcomes, holders);
/// the return value is the count of successfully published coins so the
/// finalise path can name how many mesh sends completed without carrying
/// unread field bags.
#[derive(Clone, Debug, Default)]
pub(crate) struct TransitionDeliveryReport {
    pub delivered: usize,
}

/// Runtime-provided port for post-persist delivery (§4.2).
///
/// Same pattern as [`super::receive::NullifierBatchPublisher`]: the finalise
/// path depends only on this trait; production wires Blossom + relay pool in
/// `runtime.rs`.
pub(crate) trait OutgoingDeliveryPort: Send + Sync {
    fn deliver_outgoing(
        &self,
        request: TransitionDeliveryRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<TransitionDeliveryReport, DeliveryError>>
                + Send
                + '_,
        >,
    >;
}

/// Production port: build → upload → publish → durable outbox mark_published.
///
/// Outbox rows are inserted **atomically with transition persist** (before
/// this port runs). The port drives pending / due rows to mesh publish.
pub(crate) struct MeshDeliveryPort {
    pub pool: PgPool,
    /// Process-local holder of the boot-verified §4.3 manifest.
    pub manifest_store: Arc<ManifestStore>,
    /// Optional process-local mirror for unit tests of ACK unwrap without SQL.
    pub retention: Arc<PendingDeliveryStore>,
    /// Secure random — production uses [`super::nostr::nip59::OsSecureRandom`].
    /// Held behind a mutex so the port is `Sync`.
    pub rng: Arc<Mutex<Box<dyn SecureRandom + Send>>>,
}

impl MeshDeliveryPort {
    pub(crate) fn new(
        pool: PgPool,
        retention: Arc<PendingDeliveryStore>,
        rng: Box<dyn SecureRandom + Send>,
        manifest_store: Arc<ManifestStore>,
    ) -> Self {
        Self {
            pool,
            manifest_store,
            retention,
            rng: Arc::new(Mutex::new(rng)),
        }
    }
}

impl OutgoingDeliveryPort for MeshDeliveryPort {
    fn deliver_outgoing(
        &self,
        request: TransitionDeliveryRequest,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<TransitionDeliveryReport, DeliveryError>>
                + Send
                + '_,
        >,
    > {
        Box::pin(async move {
            // Pure receive / mint-to-self: no external coins → nothing to mesh-deliver.
            if request.coins.is_empty() {
                return Ok(TransitionDeliveryReport::default());
            }
            if request.operator.blob_holders.is_empty() {
                return Err(DeliveryError::BlobHoldersEmpty);
            }

            let (manifest_blob_stores, manifest_seed_relays) =
                manifest_overlap_targets(self.manifest_store.as_ref());
            let mut report = TransitionDeliveryReport { delivered: 0 };

            for material in &request.coins {
                // Ensure a durable pending row exists (idempotent if finalise
                // already inserted atomically with engine persist).
                let material_dto = ExternalOutboxMaterial::from_outgoing(
                    material,
                    &request.operator.blob_holders,
                    request.operator.max_blob_bytes,
                );
                let material_bytes = material_dto
                    .encode()
                    .map_err(|e| DeliveryError::Relay(format!("outbox material encode: {e:#}")))?;
                let coin_id = shared::spec_v1::encoding::digest_to_bytes(&material.coin.identifier);
                let transition_pk = material.creating_nullifier.pk_create;
                let insert = OutboxInsert {
                    kind: OutboxKind::ExternalCoin,
                    subject: request.subject,
                    transition_pk,
                    coin_id,
                    material: material_bytes,
                };
                db_outbox::insert_pending(&self.pool, &[insert])
                    .await
                    .map_err(|e| DeliveryError::Relay(format!("outbox insert: {e:#}")))?;

                let outbox_id = db_outbox::outbox_id(
                    OutboxKind::ExternalCoin,
                    &request.subject,
                    &coin_id,
                    &transition_pk,
                );
                let row = db_outbox::get_by_id(&self.pool, &outbox_id)
                    .await
                    .map_err(|e| DeliveryError::Relay(format!("outbox load: {e:#}")))?
                    .ok_or_else(|| {
                        DeliveryError::Relay("outbox row missing after insert".into())
                    })?;
                if row.status.is_terminal() {
                    // Completed/failed: never republish.
                    continue;
                }

                publish_outbox_row(
                    &self.pool,
                    &row,
                    material,
                    &request.operator,
                    self.retention.as_ref(),
                    self.rng.as_ref(),
                    manifest_blob_stores,
                    manifest_seed_relays,
                )
                .await?;

                tracing::info!(
                    subject = %hex::encode(request.subject),
                    outbox_id = %hex::encode(outbox_id),
                    coin_id = %hex::encode(coin_id),
                    "mesh delivery published for outbox coin"
                );
                report.delivered = report.delivered.saturating_add(1);
            }
            Ok(report)
        })
    }
}

/// Build + network-publish one outbox row; mark_published.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn publish_outbox_row(
    pool: &PgPool,
    row: &OutboxRow,
    material: &OutgoingCoinMaterial,
    operator: &DeliveryOperatorContext,
    retention: &PendingDeliveryStore,
    rng: &Mutex<Box<dyn SecureRandom + Send>>,
    manifest_blob_stores: &[String],
    manifest_seed_relays: &[String],
) -> Result<CoinDeliveryReport, DeliveryError> {
    if row.status.is_terminal() {
        return Err(DeliveryError::Relay(
            "refuse publish of terminal outbox row".into(),
        ));
    }

    let built = {
        let mut rng = rng.lock().expect("delivery rng mutex poisoned");
        build_coin_delivery(
            material,
            &operator.op_sk,
            &operator.ovk,
            &operator.blob_holders,
            operator.now,
            rng.as_mut(),
        )?
    };

    let coin_report = publish_built_delivery(
        &built,
        &operator.op_sk,
        operator.max_blob_bytes,
        manifest_blob_stores,
        manifest_seed_relays,
    )
    .await?;

    let artefacts = PublishArtefacts {
        blob_id: built.blob_id,
        detect_tag: built.keys.detect_tag,
        epk: built.keys.epk,
        k_tx: built.keys.k_tx,
        ack_nonce: built.ack_nonce,
        event_id: built.gift_wrap.id,
        zbe_ciphertext: built.zbe_ciphertext.clone(),
        out_ciphertext: built.out_ciphertext.clone(),
        recipient_op_pk: built.recipient_op_pk,
    };
    db_outbox::mark_published(pool, &row.outbox_id, &artefacts)
        .await
        .map_err(|e| DeliveryError::Relay(format!("outbox mark_published: {e:#}")))?;

    // Process-local mirror for ACK unwrap helpers that still take the store.
    retention.retain(RetainedDeliveryAttempt {
        blob_id: built.blob_id,
        detect_tag: built.keys.detect_tag,
        k_tx: built.keys.k_tx,
        ack_nonce: built.ack_nonce,
        zbe_ciphertext: built.zbe_ciphertext,
        out_ciphertext: built.out_ciphertext,
        recipient_op_pk: built.recipient_op_pk,
        ack_accepted: false,
    });

    Ok(coin_report)
}

/// Drive due open outbox rows (runtime republish + resume).
///
/// Requires the operational bundle (`op_sk` / `ovk`) for rebuild. Rows whose
/// subject has no active bundle are skipped with a named log (fail closed on
/// that subject, not a silent invent of keys).
///
/// Publish failures are classified via
/// [`DeliveryError::is_terminal_outbox_failure`]: terminal →
/// [`db_outbox::mark_failed`] (status `failed` + named `fail_reason`, leaves
/// `list_due`); transient → warn and keep for §4.2 backoff republish.
pub(crate) async fn drive_due_outbox_entries(
    pool: &PgPool,
    bundles: &crate::kernel::bootstrap::BundleStore,
    retention: &PendingDeliveryStore,
    rng: &Mutex<Box<dyn SecureRandom + Send>>,
    manifest_store: &ManifestStore,
    now: u64,
) -> Result<usize, DeliveryError> {
    let (manifest_blob_stores, manifest_seed_relays) = manifest_overlap_targets(manifest_store);
    let due = db_outbox::list_due(pool)
        .await
        .map_err(|e| DeliveryError::Relay(format!("list_due: {e:#}")))?;
    let mut driven = 0usize;
    for row in due {
        let subject = crate::kernel::types::SubjectAddress(row.subject);
        let Some(bundle) = bundles.get_active(&subject) else {
            tracing::warn!(
                subject = %hex::encode(row.subject),
                outbox_id = %hex::encode(row.outbox_id),
                "outbox due but operational bundle missing — skip (no invented keys)"
            );
            continue;
        };

        match row.kind {
            OutboxKind::SelfDelivery => {
                // Mutex is locked only inside publish_sdr_outbox_row for the
                // sync seal; never hold a std MutexGuard across this .await.
                match super::sdr::publish_sdr_outbox_row(
                    pool,
                    &row,
                    &bundle.op,
                    now,
                    rng,
                    manifest_blob_stores,
                    manifest_seed_relays,
                )
                .await
                {
                    Ok(()) => {
                        driven = driven.saturating_add(1);
                    }
                    Err(e) if e.is_terminal_outbox_failure() => {
                        mark_outbox_failed(pool, &row.outbox_id, &e.to_string()).await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            outbox_id = %hex::encode(row.outbox_id),
                            error = %e,
                            "SDR outbox publish attempt failed (transient; row retained for retry)"
                        );
                    }
                }
            }
            OutboxKind::ExternalCoin => {
                // Corrupt durable material never heals by waiting — mark failed
                // per-row so one bad row cannot abort the rest of the due set.
                let mat = match ExternalOutboxMaterial::decode(&row.material) {
                    Ok(m) => m,
                    Err(e) => {
                        mark_outbox_failed(
                            pool,
                            &row.outbox_id,
                            &format!("outbox material decode: {e:#}"),
                        )
                        .await;
                        continue;
                    }
                };
                let outgoing = match mat.to_outgoing() {
                    Ok(o) => o,
                    Err(e) => {
                        mark_outbox_failed(
                            pool,
                            &row.outbox_id,
                            &format!("outbox material to_outgoing: {e:#}"),
                        )
                        .await;
                        continue;
                    }
                };
                let operator = DeliveryOperatorContext {
                    op_sk: bundle.op,
                    ovk: bundle.ovk,
                    blob_holders: mat.blob_holders.clone(),
                    max_blob_bytes: mat.max_blob_bytes,
                    now,
                };
                match publish_outbox_row(
                    pool,
                    &row,
                    &outgoing,
                    &operator,
                    retention,
                    rng,
                    manifest_blob_stores,
                    manifest_seed_relays,
                )
                .await
                {
                    Ok(_) => {
                        driven = driven.saturating_add(1);
                    }
                    Err(e) if e.is_terminal_outbox_failure() => {
                        mark_outbox_failed(pool, &row.outbox_id, &e.to_string()).await;
                    }
                    Err(e) => {
                        tracing::warn!(
                            outbox_id = %hex::encode(row.outbox_id),
                            error = %e,
                            "outbox publish attempt failed (transient; row retained for retry)"
                        );
                    }
                }
            }
        }
    }
    Ok(driven)
}

/// Resolve only boot-verified overlap targets. An empty store deliberately
/// becomes two empty slices; the shared publisher turns that into the named,
/// transient fail-closed overlap error instead of treating it as an opt-out.
fn manifest_overlap_targets(manifest_store: &ManifestStore) -> (&[String], &[String]) {
    match manifest_store.get() {
        Some(manifest) => (manifest.blob_stores(), manifest.seed_relays()),
        None => (&[], &[]),
    }
}

/// Persist terminal outbox failure (named reason). Logs hard if the write
/// itself fails — the row may still be due; never invent a soft "not due".
async fn mark_outbox_failed(pool: &PgPool, outbox_id: &[u8; 32], reason: &str) {
    match db_outbox::mark_failed(pool, outbox_id, reason).await {
        Ok(()) => {
            tracing::error!(
                outbox_id = %hex::encode(outbox_id),
                reason,
                "outbox permanently failed (status=failed; left drive loop)"
            );
        }
        Err(e) => {
            tracing::error!(
                outbox_id = %hex::encode(outbox_id),
                reason,
                error = %e,
                "outbox mark_failed write failed (row may remain due)"
            );
        }
    }
}

/// Insert a Phase-B `SelfDeliveryRecordV1` outbox row (after first-occurrence MTP).
///
/// Call this **only** once the final SDR ciphertext is sealed (§4.2 Phase B).
/// Phase A must never write a provisional SDR outbox entry. The recovery
/// path that **replays** recovered SDRs is still
/// [`crate::v1::recovery::SdrReplayStatus::Unavailable`] — this helper only
/// queues **outbound** self-delivery.
pub(crate) async fn insert_sdr_outbox_pending(
    pool: &PgPool,
    subject: [u8; 32],
    transition_pk: [u8; 32],
    material: &super::outbox_material::SdrOutboxMaterial,
) -> Result<[u8; 32], DeliveryError> {
    let material_bytes = material
        .encode()
        .map_err(|e| DeliveryError::Relay(format!("SDR material encode: {e:#}")))?;
    // SDR has no coin_id — zero sentinel. Per-transition dedup comes from
    // outbox_id (SHA-256(kind ‖ subject ‖ coin_id ‖ transition_pk), the
    // PRIMARY KEY, via ON CONFLICT DO NOTHING) and the
    // (subject, coin_id, kind, transition_pk) UNIQUE constraint (migration
    // 0035) — NOT from (subject, coin_id, kind) alone, which allowed only
    // one self_delivery row ever per subject (fixed in 0035).
    let coin_id = [0u8; 32];
    let id = db_outbox::outbox_id(OutboxKind::SelfDelivery, &subject, &coin_id, &transition_pk);
    db_outbox::insert_pending(
        pool,
        &[OutboxInsert {
            kind: OutboxKind::SelfDelivery,
            subject,
            transition_pk,
            coin_id,
            material: material_bytes,
        }],
    )
    .await
    .map_err(|e| DeliveryError::Relay(format!("SDR outbox insert: {e:#}")))?;
    Ok(id)
}

/// Build outbox insert payloads for external coins of one transition.
///
/// Called from finalise so inserts share the engine+members_ready transaction.
pub(crate) fn external_outbox_inserts(
    subject: [u8; 32],
    transition_pk: [u8; 32],
    coins: &[OutgoingCoinMaterial],
    blob_holders: &[String],
    max_blob_bytes: u64,
) -> Result<Vec<OutboxInsert>, DeliveryError> {
    let mut out = Vec::with_capacity(coins.len());
    for material in coins {
        let dto = ExternalOutboxMaterial::from_outgoing(material, blob_holders, max_blob_bytes);
        let material_bytes = dto
            .encode()
            .map_err(|e| DeliveryError::Relay(format!("outbox material encode: {e:#}")))?;
        let coin_id = shared::spec_v1::encoding::digest_to_bytes(&material.coin.identifier);
        out.push(OutboxInsert {
            kind: OutboxKind::ExternalCoin,
            subject,
            transition_pk,
            coin_id,
            material: material_bytes,
        });
    }
    Ok(out)
}

/// Durable ACK accept: verify against outbox artefacts, advance to
/// `completed` (valid ACK ends the delivery state machine; row retained).
pub(crate) async fn accept_outbox_ack_json(
    pool: &PgPool,
    blob_id: &[u8; 32],
    ack_nonce: &[u8; 32],
    json: &str,
) -> Result<[u8; 32], AckVerifyError> {
    let row = db_outbox::get_by_blob_and_ack_nonce(pool, blob_id, ack_nonce)
        .await
        .map_err(|_| AckVerifyError::FieldMismatch {
            field: "blob_id|ack_nonce",
        })?
        .ok_or(AckVerifyError::FieldMismatch {
            field: "blob_id|ack_nonce",
        })?;
    let detect_tag = row.detect_tag.ok_or(AckVerifyError::FieldMismatch {
        field: "detect_tag",
    })?;
    let k_tx = row
        .k_tx
        .ok_or(AckVerifyError::FieldMismatch { field: "k_tx" })?;
    let recipient_op_pk = row.recipient_op_pk.ok_or(AckVerifyError::FieldMismatch {
        field: "recipient_op_pk",
    })?;
    let zbe = row
        .zbe_ciphertext
        .as_ref()
        .ok_or(AckVerifyError::FieldMismatch {
            field: "zbe_ciphertext",
        })?;
    let out_ct = row
        .out_ciphertext
        .as_ref()
        .ok_or(AckVerifyError::FieldMismatch {
            field: "out_ciphertext",
        })?;
    let row_blob = row
        .blob_id
        .ok_or(AckVerifyError::FieldMismatch { field: "blob_id" })?;
    if blob_id_of(zbe) != row_blob {
        return Err(AckVerifyError::FieldMismatch {
            field: "zbe_ciphertext/blob_id",
        });
    }
    // External coins: out_ciphertext is the ovk recovery envelope (required).
    // Self-delivery SDR rows seal the whole record under ZBE; no per-coin
    // out_ciphertext is owed — empty is expected for kind = self_delivery.
    if out_ct.is_empty() && row.kind != db_outbox::OutboxKind::SelfDelivery {
        return Err(AckVerifyError::FieldMismatch {
            field: "out_ciphertext",
        });
    }
    if k_tx == [0u8; 32] {
        return Err(AckVerifyError::FieldMismatch { field: "k_tx" });
    }
    verify_delivery_ack_json(&recipient_op_pk, &detect_tag, blob_id, ack_nonce, json)?;
    db_outbox::mark_ack_received(pool, &row.outbox_id)
        .await
        .map_err(|_| AckVerifyError::FieldMismatch {
            field: "outbox_status",
        })?;
    Ok(row.outbox_id)
}

// ---------------------------------------------------------------------------
// Recipient directory — IVPK from profile / Invoice only
// ---------------------------------------------------------------------------

/// How long a verified delivery-target entry remains usable.
///
/// Kind-0 profiles are **replaceable**: relays and (with confirmation)
/// payment fields can change. An entry that never expires would keep
/// publishing gift-wraps to relays the recipient left.
///
/// **Choice: 3600 s (1 h).** Aligns with the §4.2 ACK retry cap
/// (RECOMMENDED exponential backoff capped at 1 h): within one delivery
/// campaign the target stays stable, but a new finalise after the hour
/// must re-resolve. Shorter than a day (stale risk) and longer than the
/// initial 30 s retry (avoids hammering NIP-05 / discovery relays every
/// attempt). No silent extension — expiry is a hard fail, re-resolve
/// or refuse.
pub(crate) const DELIVERY_TARGET_TTL_SECS: u64 = 3_600;

/// Verified delivery target for one payment address.
///
/// Only produced from a fully checked §7.3 profile or §4.3 `Invoice`.
/// `blob_stores` is the recipient-advertised Blossom base list when known;
/// profile/Invoice currently carry **relays only**, so this is empty unless
/// a future carrier supplies it — never invented from relay URLs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DeliveryTarget {
    pub ivpk: [u8; 32],
    pub op_pk: [u8; 32],
    pub relays: Vec<String>,
    /// Recipient Blossom bases when explicitly known; empty is not a default
    /// store — the sender still uses its own operator holders for upload.
    pub blob_stores: Vec<String>,
    /// Absolute unix-seconds when this entry becomes unusable.
    pub expires_at: u64,
}

impl DeliveryTarget {
    pub(crate) fn is_expired(&self, now: u64) -> bool {
        now >= self.expires_at
    }
}

/// Process-local map address → verified target (filled by profile/Invoice
/// resolution **before** finalise). Missing or expired entry ⇒
/// [`DeliveryError::RecipientIvpkUnavailable`] /
/// [`DeliveryError::RecipientTargetExpired`].
///
/// **Public** so the API/SDK layer can call
/// [`Self::insert_verified_invoice`] (see that method's production-caller
/// note). Construction for the node process stays on [`Self::shared`].
#[derive(Debug, Default)]
pub struct DeliveryTargetStore {
    by_address: Mutex<HashMap<[u8; 32], DeliveryTarget>>,
}

impl DeliveryTargetStore {
    pub fn new() -> Self {
        Self {
            by_address: Mutex::new(HashMap::new()),
        }
    }

    pub fn shared() -> Arc<Self> {
        Arc::new(Self::new())
    }

    /// Record a verified target. Call only after the full §7.3 / §4.3 checklist.
    pub(crate) fn insert(&self, address: [u8; 32], target: DeliveryTarget) {
        let mut guard = self
            .by_address
            .lock()
            .expect("DeliveryTargetStore mutex poisoned");
        guard.insert(address, target);
    }

    /// Insert from a fully verified kind-0 payment profile (§7.3 checklist).
    ///
    /// Partial / failed profiles never reach this function — the caller must
    /// only pass [`VerifiedPaymentProfile`] from `verify_payment_profile` /
    /// `resolve_profile_*`.
    pub(crate) fn insert_verified_profile(
        &self,
        profile: &VerifiedPaymentProfile,
        now: u64,
    ) -> Result<(), DeliveryError> {
        if profile.relays.is_empty() {
            return Err(DeliveryError::RecipientRelaysEmpty {
                recipient: profile.address,
            });
        }
        let expires_at = now.saturating_add(DELIVERY_TARGET_TTL_SECS);
        self.insert(
            profile.address,
            DeliveryTarget {
                ivpk: profile.ivpk,
                op_pk: profile.op_pubkey,
                relays: profile.relays.clone(),
                // Profile object has no Blossom base list (§7.3 closed fields).
                blob_stores: Vec::new(),
                expires_at,
            },
        );
        Ok(())
    }

    /// Insert from a fully verified §4.3 `Invoice` (checks i–iii already run).
    ///
    /// # Production caller
    ///
    /// Kernel `SubmitTransition` verifies `OutputTemplate.delivery` (invoice
    /// or profile) and calls this path (or [`Self::insert_verified_profile`])
    /// **before** admit/prove so the mesh send path has a [`DeliveryTarget`].
    /// The API/SDK layer may also call this façade after its own checks; the
    /// node never sees names (NIP-05 lives in that layer). Only
    /// `{ivpk, op_pubkey, relays}` (+ TTL) are retained — `pk0`, `nk_commit`,
    /// `memo`, and signatures are discarded (§7.5 retention).
    ///
    /// Public error type is a display string so the API layer does not depend
    /// on crate-private [`DeliveryError`] variants. Checklist failures and
    /// empty-relay refusals are named in the string (no silent skip).
    pub fn insert_verified_invoice(
        &self,
        invoice: &PaymentInvoice,
        now: u64,
    ) -> Result<(), String> {
        self.insert_verified_invoice_inner(invoice, now)
            .map_err(|e| e.to_string())
    }

    pub(crate) fn insert_verified_invoice_inner(
        &self,
        invoice: &PaymentInvoice,
        now: u64,
    ) -> Result<(), DeliveryError> {
        // Re-run the checklist here so a partially-built Invoice cannot slip in.
        verify_invoice(invoice).map_err(|e| DeliveryError::ProfileResolve {
            recipient: invoice.recipient,
            detail: e.to_string(),
        })?;
        if invoice.relays.is_empty() {
            return Err(DeliveryError::RecipientRelaysEmpty {
                recipient: invoice.recipient,
            });
        }
        let expires_at = now.saturating_add(DELIVERY_TARGET_TTL_SECS);
        self.insert(
            invoice.recipient,
            DeliveryTarget {
                ivpk: invoice.ivpk,
                op_pk: invoice.op_pubkey,
                relays: invoice.relays.clone(),
                blob_stores: Vec::new(),
                expires_at,
            },
        );
        Ok(())
    }

    pub(crate) fn get(&self, address: &[u8; 32]) -> Option<DeliveryTarget> {
        let guard = self
            .by_address
            .lock()
            .expect("DeliveryTargetStore mutex poisoned");
        guard.get(address).cloned()
    }

    /// Require a **non-expired** verified target. Fail-closed on missing or stale.
    pub(crate) fn require(
        &self,
        address: &[u8; 32],
        now: u64,
    ) -> Result<DeliveryTarget, DeliveryError> {
        match self.get(address) {
            None => Err(DeliveryError::RecipientIvpkUnavailable {
                recipient: *address,
            }),
            Some(t) if t.is_expired(now) => Err(DeliveryError::RecipientTargetExpired {
                recipient: *address,
                expired_at: t.expires_at,
                now,
            }),
            Some(t) => Ok(t),
        }
    }
}

// ---------------------------------------------------------------------------
// Profile / Invoice → store (callers of resolve_profile_*)
// ---------------------------------------------------------------------------

/// Resolve kind-0 by `op_pubkey`, run the payment-object checklist, insert.
///
/// Fails loud with the checklist step in the message — never inserts a
/// half-checked profile.
pub(crate) async fn resolve_and_store_profile_by_op_pubkey(
    store: &DeliveryTargetStore,
    pool: &RelayPool,
    op_pubkey: &[u8; 32],
    expected_network: &str,
    now: u64,
) -> Result<VerifiedPaymentProfile, DeliveryError> {
    let profile = resolve_profile_by_op_pubkey(pool, op_pubkey, expected_network)
        .await
        .map_err(|e| map_profile_resolve(op_pubkey, e))?;
    store.insert_verified_profile(&profile, now)?;
    Ok(profile)
}

fn map_profile_resolve(op_hint: &[u8; 32], e: ProfileResolveError) -> DeliveryError {
    // Prefer a stable recipient field when the error names an address later;
    // for op-path failures we only have the op key as diagnostic context.
    DeliveryError::ProfileResolve {
        recipient: *op_hint,
        detail: e.to_string(),
    }
}

/// Ensure every external output recipient has a fresh target **before**
/// durable finalise (prove/persist). Missing/expired ⇒ named error; no
/// mid-delivery discovery.
pub(crate) fn ensure_delivery_targets_before_finalise(
    owner: &[u8; 32],
    output_coins: &[Coin],
    targets: &DeliveryTargetStore,
    now: u64,
) -> Result<(), DeliveryError> {
    for (_, coin) in external_delivery_coins(owner, output_coins) {
        let t = targets.require(&coin.recipient.0, now)?;
        if t.relays.is_empty() {
            return Err(DeliveryError::RecipientRelaysEmpty {
                recipient: coin.recipient.0,
            });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ACK return path — unwrap own gift-wraps, free PendingDeliveryStore
// ---------------------------------------------------------------------------

/// Outcome of presenting one gift-wrap candidate to the ACK acceptor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum AckInboxResult {
    /// Not a gift-wrap we could open, or not kind-1421 — ignored.
    Ignored { reason: &'static str },
    /// Valid ACK: outbox advanced to `completed` (row retained as log).
    Accepted {
        blob_id: [u8; 32],
        ack_nonce: [u8; 32],
    },
    /// Opened kind-1421 but verification failed (named cause).
    Rejected { error: AckVerifyError },
}

/// Try to unwrap a gift-wrap under the sender's `ivk` and accept a kind-1421 ACK.
///
/// The recipient's `op` for signature check comes from the **retained**
/// attempt (verified profile/Invoice) — never from the ACK body.
pub(crate) fn process_gift_wrap_for_ack(
    wrap: &Event,
    sender_ivk: &[u8; 32],
    store: &PendingDeliveryStore,
) -> AckInboxResult {
    match open_ack_content(wrap, sender_ivk) {
        OpenAck::Ignored { reason } => AckInboxResult::Ignored { reason },
        OpenAck::Rejected { error } => AckInboxResult::Rejected { error },
        OpenAck::Content {
            blob_id,
            ack_nonce,
            json,
        } => match store.accept_ack_json(&blob_id, &ack_nonce, &json) {
            Ok(()) => AckInboxResult::Accepted { blob_id, ack_nonce },
            Err(e) => AckInboxResult::Rejected { error: e },
        },
    }
}

/// Durable variant: ACK advances `v1_delivery_outbox` to `completed`.
pub(crate) async fn process_gift_wrap_for_ack_durable(
    wrap: &Event,
    sender_ivk: &[u8; 32],
    pg: &PgPool,
) -> AckInboxResult {
    match open_ack_content(wrap, sender_ivk) {
        OpenAck::Ignored { reason } => AckInboxResult::Ignored { reason },
        OpenAck::Rejected { error } => AckInboxResult::Rejected { error },
        OpenAck::Content {
            blob_id,
            ack_nonce,
            json,
        } => match accept_outbox_ack_json(pg, &blob_id, &ack_nonce, &json).await {
            Ok(_outbox_id) => AckInboxResult::Accepted { blob_id, ack_nonce },
            Err(e) => AckInboxResult::Rejected { error: e },
        },
    }
}

enum OpenAck {
    Ignored {
        reason: &'static str,
    },
    Rejected {
        error: AckVerifyError,
    },
    Content {
        blob_id: [u8; 32],
        ack_nonce: [u8; 32],
        json: String,
    },
}

fn open_ack_content(wrap: &Event, sender_ivk: &[u8; 32]) -> OpenAck {
    if wrap.kind != KIND_GIFT_WRAP {
        return OpenAck::Ignored {
            reason: "not gift-wrap kind",
        };
    }
    let unwrapped = match unwrap_gift(wrap, sender_ivk) {
        Ok(u) => u,
        Err(_) => {
            return OpenAck::Ignored {
                reason: "unwrap failed (not for us or corrupt)",
            };
        }
    };
    if unwrapped.rumor.kind != KIND_ACK {
        return OpenAck::Ignored {
            reason: "inner rumor not kind 1421",
        };
    }
    match decode_ack_content(&unwrapped.rumor.content) {
        Ok(c) => OpenAck::Content {
            blob_id: c.blob_id,
            ack_nonce: c.ack_nonce,
            json: unwrapped.rumor.content,
        },
        Err(e) => OpenAck::Rejected {
            error: AckVerifyError::Decode(e),
        },
    }
}

/// Query relays for kind-1059 gift-wraps and accept ACKs.
///
/// When `pg` is `Some`, the durable outbox is the source of truth (ACK →
/// `completed`). Republish of due rows is a **separate** runtime tick
/// ([`drive_due_outbox_entries`]) — this function only consumes ACKs.
pub(crate) async fn poll_incoming_acks(
    relay_pool: &RelayPool,
    sender_ivk: &[u8; 32],
    store: &PendingDeliveryStore,
    pg: Option<&PgPool>,
    since: Option<u64>,
) -> Result<Vec<AckInboxResult>, DeliveryError> {
    let filter = Filter {
        kinds: Some(vec![KIND_GIFT_WRAP]),
        since,
        ..Filter::default()
    };
    let aggregate = relay_pool.query_all(&[filter]).await;
    let mut out = Vec::with_capacity(aggregate.events.len());
    for event in &aggregate.events {
        if let Some(pg) = pg {
            out.push(process_gift_wrap_for_ack_durable(event, sender_ivk, pg).await);
        } else {
            out.push(process_gift_wrap_for_ack(event, sender_ivk, store));
        }
    }
    Ok(out)
}

/// After a successful mesh send, refresh the recipient's delivery target from
/// their published kind-0 (same relays used for the delivery attempt).
///
/// Keeps the target store honest against replaceable profiles without
/// inventing a default relay list. Failures are returned named — the
/// pending delivery is already retained and independent of this refresh.
pub(crate) async fn refresh_target_from_recipient_profile(
    store: &DeliveryTargetStore,
    recipient_op_pk: &[u8; 32],
    recipient_relays: &[String],
    expected_network: &str,
    now: u64,
) -> Result<VerifiedPaymentProfile, DeliveryError> {
    if recipient_relays.is_empty() {
        return Err(DeliveryError::RecipientRelaysEmpty {
            recipient: *recipient_op_pk,
        });
    }
    let pool =
        RelayPool::new(recipient_relays.to_vec()).map_err(|e| DeliveryError::ProfileResolve {
            recipient: *recipient_op_pk,
            detail: e.to_string(),
        })?;
    resolve_and_store_profile_by_op_pubkey(store, &pool, recipient_op_pk, expected_network, now)
        .await
}

// ---------------------------------------------------------------------------
// Helpers for finalise wiring
// ---------------------------------------------------------------------------

/// Which output coins of a finished transition must be mesh-delivered (§2.3.2).
///
/// Recipient coins only. Change (and any self-output) is retained locally and
/// travels via `SelfDeliveryRecordV1`, not as a foreign delivery event.
pub(crate) fn external_delivery_coins<'a>(
    owner: &[u8; 32],
    output_coins: &'a [Coin],
) -> Vec<(usize, &'a Coin)> {
    output_coins
        .iter()
        .enumerate()
        .filter(|(_, c)| c.recipient.0 != *owner)
        .collect()
}

/// Map prover/host `NavOpening` into the bundle wire shape.
pub(crate) fn bundle_nav_opening(
    size: u64,
    mth: HashDigest,
    nav_rand: [u8; 32],
) -> BundleNavOpening {
    BundleNavOpening {
        size,
        mth,
        nav_rand,
    }
}

/// Map nullifier opening into `CreatingNullifier`.
pub(crate) fn creating_nullifier_from_parts(
    pk: [u8; 32],
    r: [u8; 32],
    r_prime: [u8; 32],
) -> CreatingNullifier {
    CreatingNullifier {
        pk_create: pk,
        r_create: r,
        r_prime_create: r_prime,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::access::{InMemoryPrivateIndex, ReceiptHub};
    use crate::test_db::setup_pool;
    use crate::v1::adapter::EngineAdapter;
    use crate::v1::db_decrypt_index::{
        decrypt_record_id, insert_verified_coin_proof_in_tx, DecryptIndexRow,
        DecryptVerificationStatus,
    };
    use crate::v1::db_outbox::OutboxStatus;
    use crate::v1::incoming::{
        process_delivery_candidate, AckClock, CandidateNetwork, CandidateOutcome, CandidateSecrets,
        CandidateStores, HolderOutcome,
    };
    use crate::v1::nostr::kinds::ack::sign_ack;
    use crate::v1::nostr::kinds::delivery::encode_delivery_payload;
    use crate::v1::nostr::nip59::OsSecureRandom;
    use crate::v1::nostr::profile::{
        address_from_parts, profile_invoice_message, sign_bip340, KIND_METADATA,
    };
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use serde_json::Value;
    use sha2::{Digest, Sha256};
    use shared::spec_v1::datastructures::Address;
    use shared::spec_v1::note_encryption::zbe_open;
    use std::time::Duration;
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};
    use zkcoins_program::circuit::compliance::Network;
    use zkcoins_program::hash::ZERO_HASH;

    /// Deterministic CSPRNG for tests (not for production).
    struct ChainRng {
        state: [u8; 32],
        counter: u64,
    }

    impl ChainRng {
        fn new(seed: &[u8]) -> Self {
            let mut state = [0u8; 32];
            let d = Sha256::digest(seed);
            state.copy_from_slice(&d);
            Self { state, counter: 0 }
        }
    }

    impl SecureRandom for ChainRng {
        fn fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Nip59Error> {
            let mut filled = 0;
            while filled < dest.len() {
                let mut block = Vec::with_capacity(40);
                block.extend_from_slice(&self.state);
                block.extend_from_slice(&self.counter.to_be_bytes());
                let next = Sha256::digest(&block);
                self.state.copy_from_slice(&next);
                self.counter = self.counter.wrapping_add(1);
                let n = (dest.len() - filled).min(32);
                dest[filled..filled + n].copy_from_slice(&self.state[..n]);
                filled += n;
            }
            Ok(())
        }
    }

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

    fn sample_coin(recipient: [u8; 32]) -> Coin {
        Coin {
            identifier: ZERO_HASH,
            recipient: Address(recipient),
            amount: 1_000,
            asset_id: ZERO_HASH,
        }
    }

    fn sample_material(ivpk: [u8; 32], op_pk: [u8; 32]) -> OutgoingCoinMaterial {
        let coin = sample_coin([0x71; 32]);
        OutgoingCoinMaterial {
            all_output_ids: vec![coin.identifier],
            leaf_index: 0,
            coin,
            proof_bytes: vec![0xDE, 0xAD],
            creating_prev_ash: ZERO_HASH,
            creating_nullifier: CreatingNullifier {
                pk_create: [0xA1; 32],
                r_create: [0xA2; 32],
                r_prime_create: [0xA3; 32],
            },
            nav_opening: BundleNavOpening {
                size: 1,
                mth: ZERO_HASH,
                nav_rand: [0xB0; 32],
            },
            asset_terms: None,
            recipient_ivpk: ivpk,
            recipient_op_pk: op_pk,
            recipient_relays: vec!["ws://127.0.0.1:9/".into()],
        }
    }

    fn build_overlap_fixture(
        recipient_holder: String,
        recipient_relay: String,
    ) -> (BuiltCoinDelivery, [u8; 32]) {
        let (op_sk, _) = fixture_sk(b"zkCoins/v1/test/delivery/overlap-op");
        let (ovk, _) = fixture_sk(b"zkCoins/v1/test/delivery/overlap-ovk");
        let (_, recipient_ivpk) = fixture_sk(b"zkCoins/v1/test/delivery/overlap-ivk");
        let (_, recipient_op_pk) = fixture_sk(b"zkCoins/v1/test/delivery/overlap-recipient-op");
        let mut material = sample_material(recipient_ivpk, recipient_op_pk);
        material.recipient_relays = vec![recipient_relay];
        let mut rng = ChainRng::new(b"zkCoins/v1/test/delivery/overlap-rng");
        let built = build_coin_delivery(
            &material,
            &op_sk,
            &ovk,
            &[recipient_holder],
            1_700_000_000,
            &mut rng,
        )
        .expect("build overlap fixture");
        (built, op_sk)
    }

    async fn start_profile_discovery_relay(profile: Event) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind profile discovery relay");
        let address = listener
            .local_addr()
            .expect("profile discovery relay address");
        tokio::spawn(async move {
            use futures_util::{SinkExt as _, StreamExt as _};
            use tokio_tungstenite::tungstenite::Message;

            let (stream, _) = listener.accept().await.expect("accept profile query");
            let mut websocket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("accept profile websocket handshake");
            let request = websocket
                .next()
                .await
                .expect("profile REQ frame")
                .expect("read profile REQ frame");
            let Message::Text(request) = request else {
                panic!("profile relay expected text REQ");
            };
            let request: serde_json::Value =
                serde_json::from_str(&request).expect("parse profile REQ");
            assert_eq!(
                request.get(0).and_then(serde_json::Value::as_str),
                Some("REQ")
            );
            let subscription_id = request
                .get(1)
                .and_then(serde_json::Value::as_str)
                .expect("profile subscription id")
                .to_owned();
            let profile_json = serde_json::json!({
                "id": hex::encode(profile.id),
                "pubkey": hex::encode(profile.pubkey),
                "created_at": profile.created_at,
                "kind": profile.kind,
                "tags": profile.tags,
                "content": profile.content,
                "sig": hex::encode(profile.sig),
            });
            websocket
                .send(Message::Text(
                    serde_json::json!(["EVENT", &subscription_id, profile_json]).to_string(),
                ))
                .await
                .expect("send sender profile");
            websocket
                .send(Message::Text(
                    serde_json::json!(["EOSE", subscription_id]).to_string(),
                ))
                .await
                .expect("send profile EOSE");
        });
        format!("ws://{address}/")
    }

    async fn mount_overlap_blossom(server: &MockServer, blob_id: [u8; 32], status: u16) {
        let response = if status == 200 {
            ResponseTemplate::new(status).set_body_json(serde_json::json!({
                "blob_id": hex::encode(blob_id),
            }))
        } else {
            ResponseTemplate::new(status)
        };
        Mock::given(method("PUT"))
            .and(path("/blossom/upload"))
            .respond_with(response)
            .expect(1)
            .mount(server)
            .await;
    }

    struct CapturingBlossomUpload {
        auth: Arc<Mutex<Option<String>>>,
        blob_id_hex: String,
    }

    struct SuccessfulBlossomUpload;

    impl Respond for SuccessfulBlossomUpload {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "blob_id": hex::encode(blob_id_of(&request.body)),
            }))
        }
    }

    impl Respond for CapturingBlossomUpload {
        fn respond(&self, request: &Request) -> ResponseTemplate {
            let auth = request
                .headers
                .get("authorization")
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned);
            *self.auth.lock().expect("auth capture lock") = auth;
            ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "blob_id": self.blob_id_hex,
            }))
        }
    }

    #[tokio::test]
    async fn blossom_auth_timestamps_are_refreshed_at_upload_boundary() {
        let server = MockServer::start().await;
        let (op_sk, _) = fixture_sk(b"zkCoins/v1/test/delivery/fresh-auth-op");
        let (ovk, _) = fixture_sk(b"zkCoins/v1/test/delivery/fresh-auth-ovk");
        let (_, recipient_ivpk) = fixture_sk(b"zkCoins/v1/test/delivery/fresh-auth-ivk");
        let (_, recipient_op_pk) = fixture_sk(b"zkCoins/v1/test/delivery/fresh-auth-recipient-op");

        let before_build = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test wall clock after UNIX epoch")
            .as_secs();
        let stale_hook_entry =
            before_build.saturating_sub(super::super::blossom::AUTH_REPLAY_WINDOW_SECS + 60);
        let material = sample_material(recipient_ivpk, recipient_op_pk);
        let mut rng = ChainRng::new(b"zkCoins/v1/test/delivery/fresh-auth-rng");
        let built = build_coin_delivery(
            &material,
            &op_sk,
            &ovk,
            &[server.uri()],
            stale_hook_entry,
            &mut rng,
        )
        .expect("build with deliberately stale finalise timestamp");

        let captured_auth = Arc::new(Mutex::new(None));
        Mock::given(method("PUT"))
            .and(path("/blossom/upload"))
            .respond_with(CapturingBlossomUpload {
                auth: Arc::clone(&captured_auth),
                blob_id_hex: hex::encode(built.blob_id),
            })
            .mount(&server)
            .await;

        let before_upload = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test wall clock after UNIX epoch")
            .as_secs();
        upload_built_coin_blob(&built, &op_sk, 1_048_576)
            .await
            .expect("upload");
        let after_upload = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test wall clock after UNIX epoch")
            .as_secs();

        let auth = captured_auth
            .lock()
            .expect("auth capture lock")
            .clone()
            .expect("Authorization header");
        let event_bytes = B64
            .decode(auth.strip_prefix("Nostr ").expect("Nostr auth scheme"))
            .expect("base64 auth event");
        let event: Value = serde_json::from_slice(&event_bytes).expect("auth event JSON");
        let created_at = event["created_at"].as_u64().expect("created_at u64");
        let expiration = event["tags"]
            .as_array()
            .expect("tags array")
            .iter()
            .find(|tag| tag[0] == "expiration")
            .and_then(|tag| tag[1].as_str())
            .expect("expiration tag")
            .parse::<u64>()
            .expect("expiration u64");

        assert!(
            (before_upload..=after_upload).contains(&created_at),
            "auth created_at must come from the upload boundary: \
             stale_hook_entry={stale_hook_entry}, before={before_upload}, \
             created_at={created_at}, after={after_upload}"
        );
        assert!(
            created_at.saturating_sub(stale_hook_entry)
                > super::super::blossom::AUTH_REPLAY_WINDOW_SECS,
            "the deliberately stale hook-entry timestamp must not reach Blossom auth"
        );
        assert_eq!(
            expiration,
            created_at.saturating_add(super::super::blossom::AUTH_REPLAY_WINDOW_SECS),
            "expiration must be derived from the same fresh upload timestamp"
        );
    }

    #[tokio::test]
    async fn overlap_delivery_reaches_recipient_and_manifest_on_both_planes() {
        let recipient_store = MockServer::start().await;
        let unhealthy_manifest_store = MockServer::start().await;
        let manifest_store = MockServer::start().await;
        let (recipient_relay, recipient_events) = start_overlap_test_relay(true).await;
        let (seed_relay, seed_events) = start_overlap_test_relay(true).await;
        let (built, op_sk) = build_overlap_fixture(recipient_store.uri(), recipient_relay);
        mount_overlap_blossom(&recipient_store, built.blob_id, 200).await;
        mount_overlap_blossom(&unhealthy_manifest_store, built.blob_id, 500).await;
        mount_overlap_blossom(&manifest_store, built.blob_id, 200).await;

        publish_built_delivery(
            &built,
            &op_sk,
            1_048_576,
            &[unhealthy_manifest_store.uri(), manifest_store.uri()],
            &[seed_relay],
        )
        .await
        .expect("recipient and recovery overlap placement");

        assert_eq!(
            recipient_events
                .lock()
                .expect("recipient events")
                .as_slice(),
            &[built.gift_wrap.id]
        );
        assert_eq!(
            seed_events.lock().expect("seed events").as_slice(),
            &[built.gift_wrap.id]
        );
        assert_eq!(
            recipient_store
                .received_requests()
                .await
                .expect("recipient Blossom requests")
                .len(),
            1
        );
        assert_eq!(
            unhealthy_manifest_store
                .received_requests()
                .await
                .expect("unhealthy manifest Blossom requests")
                .len(),
            1,
            "all manifest stores remain observable after one failure"
        );
        assert_eq!(
            manifest_store
                .received_requests()
                .await
                .expect("accepted manifest Blossom requests")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn incoming_coinproof_falls_back_to_manifest_blob_store() {
        let unavailable_holder = MockServer::start().await;
        let manifest_store = MockServer::start().await;
        let (ack_relay, _) = start_overlap_test_relay(true).await;
        let (sender_op, sender_op_pk) =
            fixture_sk(b"zkCoins/v1/test/delivery/incoming-fallback-sender-op");
        let (sender_pk0_sk, sender_pk0) =
            fixture_sk(b"zkCoins/v1/test/delivery/incoming-fallback-sender-pk0");
        let (_, sender_ivpk) = fixture_sk(b"zkCoins/v1/test/delivery/incoming-fallback-sender-ivk");
        let (recipient_ivk, recipient_ivpk) =
            fixture_sk(b"zkCoins/v1/test/delivery/incoming-fallback-recipient-ivk");
        let (recipient_op, recipient_op_pk) =
            fixture_sk(b"zkCoins/v1/test/delivery/incoming-fallback-recipient-op");
        let (ovk, _) = fixture_sk(b"zkCoins/v1/test/delivery/incoming-fallback-ovk");
        let mut material = sample_material(recipient_ivpk, recipient_op_pk);
        material.proof_bytes.clear();
        let subject = material.coin.recipient.0;
        let coin_id = digest_to_bytes(&material.coin.identifier);
        let now = 1_700_000_000;
        let mut build_rng = ChainRng::new(b"zkCoins/v1/test/delivery/incoming-fallback-build");
        let built = build_coin_delivery(
            &material,
            &sender_op,
            &ovk,
            &[unavailable_holder.uri()],
            now,
            &mut build_rng,
        )
        .expect("build fallback delivery");

        Mock::given(method("GET"))
            .and(path(format!("/blossom/{}", hex::encode(built.blob_id))))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(built.zbe_ciphertext.clone()),
            )
            .expect(1)
            .mount(&manifest_store)
            .await;

        let nk_commit: [u8; 32] =
            Sha256::digest(b"zkCoins/v1/test/delivery/incoming-fallback-nk").into();
        let sender_address = address_from_parts(&sender_pk0, &nk_commit);
        let sender_relays = vec![ack_relay];
        let addr_sig = sign_bip340(
            &sender_pk0_sk,
            &profile_invoice_message(
                &sender_address,
                &sender_pk0,
                &nk_commit,
                &sender_ivpk,
                &sender_op_pk,
                &sender_relays,
            ),
        )
        .expect("sign sender profile binding");
        let profile = Event::sign(
            &sender_op,
            now,
            KIND_METADATA,
            vec![],
            serde_json::json!({
                "name": "Fallback Sender",
                "zkcoins": {
                    "version": 1,
                    "network": "regtest",
                    "address": Address(sender_address).to_bech32m(),
                    "pk0": hex::encode(sender_pk0),
                    "nk_commit": hex::encode(nk_commit),
                    "ivpk": hex::encode(sender_ivpk),
                    "relays": sender_relays,
                    "addr_sig": hex::encode(addr_sig),
                    "name_sig": hex::encode([0u8; 64]),
                }
            })
            .to_string(),
        )
        .expect("sign sender profile event");
        let discovery_relays = vec![start_profile_discovery_relay(profile).await];
        let manifest_blob_stores = vec![manifest_store.uri()];

        let scope = setup_pool().await;
        {
            // EngineAdapter::persist refuses to write v1 scan state without an
            // exclusive stack claim (no silent claim-from-write); claim it for
            // this fixture, exactly as the recovery-path adapter fixtures do.
            use crate::v1::separation::{
                claim_stack_scan_mode, set_process_stack_mode, ScanStackMode,
            };
            set_process_stack_mode(ScanStackMode::V1);
            claim_stack_scan_mode(&scope.pool, ScanStackMode::V1)
                .await
                .expect("claim v1 stack mode for EngineAdapter fixture");
        }
        let stored_blob_id = [0xD1; 32];
        assert_ne!(stored_blob_id, built.blob_id);
        let stored_record_id = decrypt_record_id(&subject, &coin_id, &stored_blob_id);
        let mut tx = scope.pool.begin().await.expect("begin replay seed tx");
        insert_verified_coin_proof_in_tx(
            &mut tx,
            &DecryptIndexRow {
                record_id: stored_record_id,
                subject,
                coin_id,
                blob_id: stored_blob_id,
                detect_tag: [0xD2; 32],
                canonical: vec![0xD3],
                asset_id: [0xD4; 32],
                verification_status: DecryptVerificationStatus::Verified,
                delivery_event_id: [0xD5; 32],
                ack_nonce: [0xD6; 32],
                occurred_at: now,
            },
        )
        .await
        .expect("insert coin-level replay row");
        tx.commit().await.expect("commit replay seed tx");

        let adapter = EngineAdapter::load_or_create(scope.pool.clone(), Network::Regtest, 0)
            .await
            .expect("load test engine adapter");
        let index = InMemoryPrivateIndex::new();
        let receipts = ReceiptHub::new();
        let mut ack_rng = ChainRng::new(b"zkCoins/v1/test/delivery/incoming-fallback-ack");
        let outcome = process_delivery_candidate(
            &built.gift_wrap,
            CandidateSecrets {
                subject: &subject,
                ivk: &recipient_ivk,
                op: &recipient_op,
            },
            CandidateStores {
                adapter: &adapter,
                pool: &scope.pool,
                index: &index,
                receipts: &receipts,
            },
            CandidateNetwork {
                max_blob_bytes: 1_048_576,
                manifest_blob_stores: &manifest_blob_stores,
                discovery_relays: &discovery_relays,
                expected_network: "regtest",
            },
            AckClock {
                now,
                rng: &mut ack_rng,
            },
        )
        .await;

        let CandidateOutcome::Accepted {
            replay,
            holder_attempts,
            ..
        } = outcome
        else {
            panic!("manifest fallback must accept replayed CoinProof: {outcome:?}");
        };
        assert!(replay);
        assert_eq!(holder_attempts.len(), 2);
        assert_eq!(holder_attempts[0].holder, unavailable_holder.uri());
        assert!(matches!(
            &holder_attempts[0].outcome,
            HolderOutcome::FetchError { .. }
        ));
        assert_eq!(holder_attempts[1].holder, manifest_store.uri());
        assert_eq!(
            holder_attempts[1].outcome,
            HolderOutcome::Ok {
                body_len: built.zbe_ciphertext.len()
            }
        );
    }

    #[tokio::test]
    async fn overlap_delivery_fails_closed_when_all_manifest_blob_stores_fail() {
        let recipient_store = MockServer::start().await;
        let manifest_store = MockServer::start().await;
        let (recipient_relay, _) = start_overlap_test_relay(true).await;
        let (built, op_sk) = build_overlap_fixture(recipient_store.uri(), recipient_relay);
        mount_overlap_blossom(&recipient_store, built.blob_id, 200).await;
        mount_overlap_blossom(&manifest_store, built.blob_id, 500).await;

        let error = publish_built_delivery(
            &built,
            &op_sk,
            1_048_576,
            &[manifest_store.uri()],
            &["ws://127.0.0.1:1/".into()],
        )
        .await
        .expect_err("recipient placement alone must not satisfy blob overlap");
        match error {
            DeliveryError::OverlapBlobStore { attempted, results } => {
                assert_eq!(attempted, 1);
                assert_eq!(results.len(), 1);
                assert_eq!(results[0].holder, manifest_store.uri());
            }
            other => panic!("expected OverlapBlobStore, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn overlap_delivery_blob_failure_leaves_outbox_unpublished() {
        let scope = setup_pool().await;
        let recipient_store = MockServer::start().await;
        let manifest_store = MockServer::start().await;
        let (recipient_relay, _) = start_overlap_test_relay(true).await;
        Mock::given(method("PUT"))
            .and(path("/blossom/upload"))
            .respond_with(SuccessfulBlossomUpload)
            .mount(&recipient_store)
            .await;
        Mock::given(method("PUT"))
            .and(path("/blossom/upload"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&manifest_store)
            .await;

        let (op_sk, _) = fixture_sk(b"zkCoins/v1/test/delivery/outbox-overlap-op");
        let (ovk, _) = fixture_sk(b"zkCoins/v1/test/delivery/outbox-overlap-ovk");
        let (_, recipient_ivpk) = fixture_sk(b"zkCoins/v1/test/delivery/outbox-overlap-ivk");
        let (_, recipient_op_pk) =
            fixture_sk(b"zkCoins/v1/test/delivery/outbox-overlap-recipient-op");
        let mut material = sample_material(recipient_ivpk, recipient_op_pk);
        material.recipient_relays = vec![recipient_relay];
        let subject = [0x91; 32];
        let coin_id = digest_to_bytes(&material.coin.identifier);
        let transition_pk = material.creating_nullifier.pk_create;
        db_outbox::insert_pending(
            &scope.pool,
            &[OutboxInsert {
                kind: OutboxKind::ExternalCoin,
                subject,
                transition_pk,
                coin_id,
                material: vec![0x01],
            }],
        )
        .await
        .expect("insert external overlap fixture");
        let outbox_id =
            db_outbox::outbox_id(OutboxKind::ExternalCoin, &subject, &coin_id, &transition_pk);
        let row = db_outbox::get_by_id(&scope.pool, &outbox_id)
            .await
            .expect("load external overlap fixture")
            .expect("inserted external overlap row");
        let operator = DeliveryOperatorContext {
            op_sk,
            ovk,
            blob_holders: vec![recipient_store.uri()],
            max_blob_bytes: 1_048_576,
            now: 1_700_000_000,
        };
        let retention = PendingDeliveryStore::new();
        let rng: Mutex<Box<dyn SecureRandom + Send>> =
            Mutex::new(Box::new(ChainRng::new(b"outbox-overlap-rng")));

        let error = publish_outbox_row(
            &scope.pool,
            &row,
            &material,
            &operator,
            &retention,
            &rng,
            &[manifest_store.uri()],
            &["ws://127.0.0.1:1/".into()],
        )
        .await
        .expect_err("overlap failure must precede mark_published");
        assert!(matches!(error, DeliveryError::OverlapBlobStore { .. }));
        let unchanged = db_outbox::get_by_id(&scope.pool, &outbox_id)
            .await
            .expect("reload failed external delivery")
            .expect("failed external row retained");
        assert_eq!(unchanged.status, OutboxStatus::Pending);
        assert_eq!(unchanged.attempt_n, 0);
        assert!(unchanged.event_id.is_none());
        assert_eq!(retention.len(), 0);
    }

    #[tokio::test]
    async fn overlap_delivery_fails_closed_when_all_manifest_seed_relays_reject() {
        let recipient_store = MockServer::start().await;
        let manifest_store = MockServer::start().await;
        let (recipient_relay, _) = start_overlap_test_relay(true).await;
        let (seed_relay, _) = start_overlap_test_relay(false).await;
        let (built, op_sk) = build_overlap_fixture(recipient_store.uri(), recipient_relay);
        mount_overlap_blossom(&recipient_store, built.blob_id, 200).await;
        mount_overlap_blossom(&manifest_store, built.blob_id, 200).await;

        let error = publish_built_delivery(
            &built,
            &op_sk,
            1_048_576,
            &[manifest_store.uri()],
            std::slice::from_ref(&seed_relay),
        )
        .await
        .expect_err("recipient placement alone must not satisfy relay overlap");
        match error {
            DeliveryError::OverlapSeedRelay { results } => {
                assert_eq!(results.len(), 1);
                assert_eq!(results[0].relay_url, seed_relay);
                assert!(!results[0].accepted);
            }
            other => panic!("expected OverlapSeedRelay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn overlap_delivery_without_loaded_manifest_fails_closed() {
        let recipient_store = MockServer::start().await;
        let (recipient_relay, _) = start_overlap_test_relay(true).await;
        let (built, op_sk) = build_overlap_fixture(recipient_store.uri(), recipient_relay);
        mount_overlap_blossom(&recipient_store, built.blob_id, 200).await;

        let error = publish_built_delivery(&built, &op_sk, 1_048_576, &[], &[])
            .await
            .expect_err("an unloaded manifest is not an overlap opt-out");
        assert_eq!(
            error,
            DeliveryError::OverlapBlobStore {
                attempted: 0,
                results: Vec::new(),
            }
        );
    }

    #[tokio::test]
    async fn overlap_delivery_without_manifest_seed_relays_fails_closed() {
        let recipient_store = MockServer::start().await;
        let manifest_store = MockServer::start().await;
        let (recipient_relay, _) = start_overlap_test_relay(true).await;
        let (built, op_sk) = build_overlap_fixture(recipient_store.uri(), recipient_relay);
        mount_overlap_blossom(&recipient_store, built.blob_id, 200).await;
        mount_overlap_blossom(&manifest_store, built.blob_id, 200).await;

        let error = publish_built_delivery(&built, &op_sk, 1_048_576, &[manifest_store.uri()], &[])
            .await
            .expect_err("a manifest without seed relays cannot satisfy event overlap");
        assert_eq!(
            error,
            DeliveryError::OverlapSeedRelay {
                results: Vec::new(),
            }
        );
    }

    #[test]
    fn overlap_failures_are_transient_for_outbox_retry() {
        let blob = DeliveryError::OverlapBlobStore {
            attempted: 0,
            results: Vec::new(),
        };
        let relay = DeliveryError::OverlapSeedRelay {
            results: Vec::new(),
        };
        assert!(!blob.is_terminal_outbox_failure());
        assert!(!relay.is_terminal_outbox_failure());
    }

    #[test]
    fn blossom_auth_clock_before_unix_epoch_is_named_and_fail_closed() {
        let before_epoch = UNIX_EPOCH
            .checked_sub(Duration::from_secs(1))
            .expect("representable pre-epoch test time");
        let err = blossom_auth_timestamps_at(before_epoch)
            .expect_err("pre-epoch clock must not invent auth timestamps");
        assert_eq!(err, DeliveryError::BlossomAuthClockBeforeUnixEpoch);
        assert!(err.to_string().contains("no timestamp fallback"));
    }

    // -----------------------------------------------------------------------
    // Outer tag set exactly zkdt + zkepk
    // -----------------------------------------------------------------------

    #[test]
    fn gift_wrap_outer_tags_are_exactly_zkdt_and_zkepk() {
        let (op_sk, _) = fixture_sk(b"zkCoins/v1/test/delivery/op");
        let (ivk, ivpk) = fixture_sk(b"zkCoins/v1/test/delivery/ivk");
        let (_, op_pk_recip) = fixture_sk(b"zkCoins/v1/test/delivery/recip-op");
        let _ = ivk;

        let material = sample_material(ivpk, op_pk_recip);
        let mut rng = ChainRng::new(b"zkCoins/v1/test/delivery/tags-rng");
        let (ovk, _) = fixture_sk(b"zkCoins/v1/test/delivery/ovk");
        let built = build_coin_delivery(
            &material,
            &op_sk,
            &ovk,
            &["https://blossom.example".into()],
            1_800_000_000,
            &mut rng,
        )
        .expect("build");
        assert!(
            !built.out_ciphertext.is_empty(),
            "out_ciphertext must be sealed for SDR output_ref"
        );
        assert_eq!(
            zbe_open(&built.keys.k_tx, &built.zbe_ciphertext).expect("open built ZBE"),
            built.canonical,
            "retained canonical body must be the exact plaintext sealed into the blob"
        );

        // Kind is gift-wrap.
        assert_eq!(built.gift_wrap.kind, KIND_GIFT_WRAP);

        // Exactly two tags, names and values pinned.
        assert_eq!(
            built.gift_wrap.tags.len(),
            2,
            "outer gift-wrap must carry exactly two cleartext tags"
        );
        assert_eq!(built.gift_wrap.tags[0].len(), 2);
        assert_eq!(built.gift_wrap.tags[0][0], "zkdt");
        assert_eq!(
            built.gift_wrap.tags[0][1],
            hex::encode(built.keys.detect_tag)
        );
        assert_eq!(built.gift_wrap.tags[1].len(), 2);
        assert_eq!(built.gift_wrap.tags[1][0], "zkepk");
        assert_eq!(built.gift_wrap.tags[1][1], hex::encode(built.keys.epk));

        // No third tag of any name (p, blob_id, e, …).
        let names: Vec<&str> = built.gift_wrap.tags.iter().map(|t| t[0].as_str()).collect();
        assert_eq!(names, vec!["zkdt", "zkepk"]);
        assert!(!names.contains(&"p"));
        assert!(!names.contains(&"blob_id"));
        assert!(!names.contains(&"e"));
    }

    // -----------------------------------------------------------------------
    // Fresh esk per coin
    // -----------------------------------------------------------------------

    #[test]
    fn esk_is_fresh_per_coin_when_rng_advances() {
        let (_, ivpk) = fixture_sk(b"zkCoins/v1/test/delivery/ivk2");
        let mut rng = ChainRng::new(b"zkCoins/v1/test/delivery/esk-rng");
        let esk1 = fresh_esk(&mut rng).expect("esk1");
        let esk2 = fresh_esk(&mut rng).expect("esk2");
        assert_ne!(esk1, esk2, "two draws from a working CSPRNG must differ");

        let k1 = derive_per_coin_keys(&esk1, &ivpk).expect("k1");
        let k2 = derive_per_coin_keys(&esk2, &ivpk).expect("k2");
        assert_ne!(k1.k_tx, k2.k_tx);
        assert_ne!(k1.detect_tag, k2.detect_tag);
        assert_ne!(k1.epk, k2.epk);
    }

    #[test]
    fn random_source_failure_is_named() {
        struct FailRng;
        impl SecureRandom for FailRng {
            fn fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), Nip59Error> {
                Err(Nip59Error::RandomSourceFailed)
            }
        }
        let err = fresh_esk(&mut FailRng).expect_err("must fail");
        assert_eq!(err, DeliveryError::RandomSourceFailed);
    }

    // -----------------------------------------------------------------------
    // ACK replay: attempt-1 ACK against attempt-2 nonce → rejected
    // -----------------------------------------------------------------------

    #[test]
    fn ack_from_attempt_one_rejected_against_attempt_two() {
        let (recip_op_sk, recip_op_pk) = fixture_sk(b"zkCoins/v1/test/delivery/ack-op");
        let detect = [0x11u8; 32];
        let blob = [0x22u8; 32];
        let nonce_attempt_1 = [0x33u8; 32];
        let nonce_attempt_2 = [0x44u8; 32];

        // Recipient signs ACK for attempt 1.
        let ack_attempt_1 = sign_ack(&recip_op_sk, &detect, &blob, &nonce_attempt_1).expect("sign");
        let json = crate::v1::nostr::kinds::ack::encode_ack_content(&ack_attempt_1);

        // Attempt 1 verifies.
        verify_delivery_ack_json(&recip_op_pk, &detect, &blob, &nonce_attempt_1, &json)
            .expect("attempt 1 ACK must verify");

        // Same ACK body presented against attempt 2 → nonce mismatch (not
        // merely is_err: the cause is AckNonceMismatch).
        let err = verify_delivery_ack_json(&recip_op_pk, &detect, &blob, &nonce_attempt_2, &json)
            .expect_err("stale ACK must fail");
        match err {
            AckVerifyError::AckNonceMismatch { expected, got } => {
                assert_eq!(expected, nonce_attempt_2);
                assert_eq!(got, nonce_attempt_1);
            }
            other => panic!("expected AckNonceMismatch, got {other:?}"),
        }

        // Retention store: retain attempt 2, present attempt-1 ACK → reject.
        let store = PendingDeliveryStore::new();
        let zbe = vec![0x01u8, 0x02, 0x03];
        let blob = blob_id_of(&zbe);
        // Re-sign ACK against the content-addressed blob id.
        let ack_attempt_1 = sign_ack(&recip_op_sk, &detect, &blob, &nonce_attempt_1).expect("sign");
        let json = crate::v1::nostr::kinds::ack::encode_ack_content(&ack_attempt_1);
        store.retain(RetainedDeliveryAttempt {
            blob_id: blob,
            detect_tag: detect,
            k_tx: [0x66; 32],
            ack_nonce: nonce_attempt_2,
            zbe_ciphertext: zbe,
            out_ciphertext: vec![0xAA],
            recipient_op_pk: recip_op_pk,
            ack_accepted: false,
        });
        let err = store
            .accept_ack_json(&blob, &nonce_attempt_2, &json)
            .expect_err("store must reject stale ACK");
        match err {
            AckVerifyError::AckNonceMismatch { .. } => {}
            other => panic!("expected AckNonceMismatch via store, got {other:?}"),
        }
        assert_eq!(store.len(), 1, "failed ACK must not drop retention");
    }

    #[test]
    fn valid_ack_marks_accepted_but_does_not_drop() {
        // Data permanence: ACK never discards the retained copy.
        let (recip_op_sk, recip_op_pk) = fixture_sk(b"zkCoins/v1/test/delivery/ack-op2");
        let detect = [0xAAu8; 32];
        let zbe = b"retained-zbe-body".to_vec();
        let blob = blob_id_of(&zbe);
        let nonce = [0xCCu8; 32];
        let ack = sign_ack(&recip_op_sk, &detect, &blob, &nonce).expect("sign");
        let json = crate::v1::nostr::kinds::ack::encode_ack_content(&ack);

        let store = PendingDeliveryStore::new();
        store.retain(RetainedDeliveryAttempt {
            blob_id: blob,
            detect_tag: detect,
            k_tx: [1; 32],
            ack_nonce: nonce,
            zbe_ciphertext: zbe,
            out_ciphertext: vec![0xBB],
            recipient_op_pk: recip_op_pk,
            ack_accepted: false,
        });
        store
            .accept_ack_json(&blob, &nonce, &json)
            .expect("valid ACK");
        assert_eq!(store.len(), 1, "ACK must retain the copy (data permanence)");
        let held = store.get(&blob, &nonce).expect("still held");
        assert!(held.ack_accepted);
    }

    // -----------------------------------------------------------------------
    // Coin note ciphertext ≠ ZBE ciphertext
    // -----------------------------------------------------------------------

    #[test]
    fn coin_note_ciphertext_is_not_zbe_blob() {
        let (_, ivpk) = fixture_sk(b"zkCoins/v1/test/delivery/ivk3");
        let mut rng = ChainRng::new(b"zkCoins/v1/test/delivery/ct-rng");
        let esk = fresh_esk(&mut rng).expect("esk");
        let keys = derive_per_coin_keys(&esk, &ivpk).expect("keys");
        let coin = sample_coin([0x71; 32]);
        let mut nonce = [0u8; 32];
        rng.fill_bytes(&mut nonce).unwrap();
        let note_ct = seal_coin_note_ciphertext(&keys.k_tx, &coin, &nonce).expect("note");
        // ZBE of anything starts with magic "ZBE1".
        let (zbe_ct, _) = zbe_seal(&keys.k_tx, b"not-a-bundle").expect("zbe");
        assert_ne!(
            note_ct, zbe_ct,
            "note NIP44Binary and ZBE blob must be distinct byte strings"
        );
        assert_eq!(&zbe_ct[..4], b"ZBE1");
        // Note ciphertext is Base64 AEAD payload UTF-8 — not ZBE-framed.
        assert_ne!(&note_ct[..4.min(note_ct.len())], b"ZBE1");
    }

    // -----------------------------------------------------------------------
    // external delivery filter (§2.3.2)
    // -----------------------------------------------------------------------

    #[test]
    fn external_delivery_skips_change_to_owner() {
        let owner = [0x01u8; 32];
        let coins = vec![
            sample_coin([0x71; 32]),
            sample_coin(owner),
            sample_coin([0x72; 32]),
        ];
        let ext = external_delivery_coins(&owner, &coins);
        assert_eq!(ext.len(), 2);
        assert_eq!(ext[0].0, 0);
        assert_eq!(ext[1].0, 2);
    }

    #[test]
    fn missing_recipient_ivpk_is_named() {
        let store = DeliveryTargetStore::new();
        let err = store
            .require(&[0xAB; 32], 1_700_000_000)
            .expect_err("missing");
        match err {
            DeliveryError::RecipientIvpkUnavailable { recipient } => {
                assert_eq!(recipient, [0xAB; 32]);
            }
            other => panic!("expected RecipientIvpkUnavailable, got {other:?}"),
        }
    }

    #[test]
    fn expired_delivery_target_is_named_not_reused() {
        let store = DeliveryTargetStore::new();
        let address = [0xCDu8; 32];
        let now = 1_700_000_000u64;
        store.insert(
            address,
            DeliveryTarget {
                ivpk: [1; 32],
                op_pk: [2; 32],
                relays: vec!["wss://relay.example".into()],
                blob_stores: Vec::new(),
                expires_at: now + 10,
            },
        );
        store.require(&address, now + 5).expect("still within TTL");
        let err = store
            .require(&address, now + 10)
            .expect_err("at expires_at must fail");
        match err {
            DeliveryError::RecipientTargetExpired {
                recipient,
                expired_at,
                now: n,
            } => {
                assert_eq!(recipient, address);
                assert_eq!(expired_at, now + 10);
                assert_eq!(n, now + 10);
            }
            other => panic!("expected RecipientTargetExpired, got {other:?}"),
        }
        // No silent fall-back to the stale entry.
        assert!(store.get(&address).is_some(), "raw get still has the row");
        assert!(
            store.require(&address, now + 11).is_err(),
            "require must keep refusing after expiry"
        );
    }

    #[test]
    fn insert_verified_invoice_runs_checklist() {
        use crate::v1::nostr::profile::{
            address_from_parts, invoice_message, sign_bip340, InvoiceMessageParts, PaymentInvoice,
        };
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

        let (sk0, pk0) = fixture_sk(b"zkCoins/v1/test/delivery/inv-sk0");
        let (op_sk, op_pk) = fixture_sk(b"zkCoins/v1/test/delivery/inv-op");
        let (_, ivpk) = fixture_sk(b"zkCoins/v1/test/delivery/inv-ivk");
        let nk = Sha256::digest(b"nk-inv").into();
        let address = address_from_parts(&pk0, &nk);
        let relays = vec!["wss://relay.example".to_string()];
        let amount = 42u128;
        let asset = [0xABu8; 32];
        let msg = invoice_message(InvoiceMessageParts {
            amount,
            recipient: &address,
            pk0: &pk0,
            nk_commit: &nk,
            asset_id: &asset,
            memo: None,
            ivpk: &ivpk,
            op_pubkey: &op_pk,
            relays: &relays,
        });
        let addr_sig = sign_bip340(&sk0, &msg).expect("addr_sig");
        let sig = sign_bip340(&op_sk, &msg).expect("op sig");
        let invoice = PaymentInvoice {
            amount,
            recipient: address,
            asset_id: asset,
            memo: None,
            pk0,
            nk_commit: nk,
            ivpk,
            op_pubkey: op_pk,
            relays: relays.clone(),
            addr_sig,
            sig,
        };
        let store = DeliveryTargetStore::new();
        let now = 1_800_000_000u64;
        store
            .insert_verified_invoice(&invoice, now)
            .expect("verified invoice");
        let t = store.require(&address, now).expect("target");
        assert_eq!(t.ivpk, ivpk);
        assert_eq!(t.op_pk, op_pk);
        assert_eq!(t.relays, relays);
        assert!(t.blob_stores.is_empty());
        assert_eq!(t.expires_at, now + DELIVERY_TARGET_TTL_SECS);

        // Tampered invoice (empty relays after construct) is refused.
        let mut bad = invoice.clone();
        bad.relays.clear();
        let err = store
            .insert_verified_invoice(&bad, now)
            .expect_err("empty relays");
        assert!(
            err.contains("empty relay") || err.contains("relay"),
            "got {err}"
        );
    }

    #[test]
    fn terminal_vs_transient_outbox_publish_classification() {
        // Transient: network / peer / entropy / missing process-local bundle.
        assert!(!DeliveryError::RandomSourceFailed.is_terminal_outbox_failure());
        assert!(
            !DeliveryError::OperationalBundleMissing { subject: [0; 32] }
                .is_terminal_outbox_failure()
        );
        assert!(!DeliveryError::NoRelayAccepted { results: vec![] }.is_terminal_outbox_failure());
        assert!(!DeliveryError::Relay("db blip".into()).is_terminal_outbox_failure());
        assert!(!DeliveryError::Blossom {
            holder: "https://h.example".into(),
            error: BlossomError::Timeout,
        }
        .is_terminal_outbox_failure());
        assert!(!DeliveryError::Blossom {
            holder: "https://h.example".into(),
            error: BlossomError::Transport {
                message: "connection reset".into()
            },
        }
        .is_terminal_outbox_failure());
        assert!(!DeliveryError::Blossom {
            holder: "https://h.example".into(),
            error: BlossomError::UnexpectedStatus { status: 503 },
        }
        .is_terminal_outbox_failure());

        // Terminal: maligned/rejected target, empty config, fixed-material crypto.
        assert!(DeliveryError::BlobHoldersEmpty.is_terminal_outbox_failure());
        assert!(
            DeliveryError::RecipientRelaysEmpty { recipient: [1; 32] }.is_terminal_outbox_failure()
        );
        assert!(
            DeliveryError::RecipientIvpkUnavailable { recipient: [2; 32] }
                .is_terminal_outbox_failure()
        );
        assert!(DeliveryError::Blossom {
            holder: "https://h.example".into(),
            error: BlossomError::Forbidden,
        }
        .is_terminal_outbox_failure());
        assert!(DeliveryError::Blossom {
            holder: "https://h.example".into(),
            error: BlossomError::Unauthorized,
        }
        .is_terminal_outbox_failure());
        assert!(DeliveryError::Blossom {
            holder: "https://h.example".into(),
            error: BlossomError::InvalidBaseUrl {
                url: "not-a-url".into()
            },
        }
        .is_terminal_outbox_failure());
        assert!(DeliveryError::OuterTagsInvalid {
            detail: "missing zkdt".into()
        }
        .is_terminal_outbox_failure());
        assert!(DeliveryError::InclusionProof("bad length".into()).is_terminal_outbox_failure());
        assert!(DeliveryError::ProofBytes("empty proof".into()).is_terminal_outbox_failure());
        assert!(
            DeliveryError::SdrOutputRef("SDR output_ref: empty holders".into())
                .is_terminal_outbox_failure()
        );
    }

    #[test]
    fn process_gift_wrap_accepts_valid_ack_and_rejects_replay() {
        use crate::v1::nostr::kinds::ack::{ack_rumor, sign_ack};
        use crate::v1::nostr::nip59::seal_and_wrap;

        let (recip_op_sk, recip_op_pk) = fixture_sk(b"zkCoins/v1/test/delivery/ack-inbox-op");
        let (sender_ivk, sender_ivpk) = fixture_sk(b"zkCoins/v1/test/delivery/ack-inbox-ivk");
        let detect = [0x11u8; 32];
        let nonce_1 = [0x33u8; 32];
        let nonce_2 = [0x44u8; 32];

        let store = PendingDeliveryStore::new();
        // Only attempt 2 is pending (as after a retry).
        let zbe = vec![0x01u8, 0x02, 0x03];
        let blob = blob_id_of(&zbe);
        store.retain(RetainedDeliveryAttempt {
            blob_id: blob,
            detect_tag: detect,
            k_tx: [0x66; 32],
            ack_nonce: nonce_2,
            zbe_ciphertext: zbe,
            out_ciphertext: vec![0xCC],
            recipient_op_pk: recip_op_pk,
            ack_accepted: false,
        });

        // Gift-wrap an ACK for attempt 1 (stale) → must not free attempt 2.
        let ack1 = sign_ack(&recip_op_sk, &detect, &blob, &nonce_1).expect("sign1");
        let rumor1 = ack_rumor(recip_op_pk, 100, &ack1);
        let mut rng = ChainRng::new(b"zkCoins/v1/test/delivery/ack-inbox-rng");
        let wrap1 = seal_and_wrap(&rumor1, &recip_op_sk, &sender_ivpk, vec![], 100, &mut rng)
            .expect("wrap1");
        let r1 = process_gift_wrap_for_ack(&wrap1, &sender_ivk, &store);
        match r1 {
            AckInboxResult::Rejected { error } => {
                // Lookup key is (blob, nonce_1) — no such attempt, or if
                // content decoded and keyed by nonce_1: FieldMismatch.
                // Either way the store must keep attempt 2.
                let _ = error;
            }
            other => panic!("stale ACK must be rejected/ignored, got {other:?}"),
        }
        assert_eq!(store.len(), 1, "attempt 2 must remain after stale ACK");

        // Valid ACK for attempt 2 → mark accepted, still retain (data permanence).
        let ack2 = sign_ack(&recip_op_sk, &detect, &blob, &nonce_2).expect("sign2");
        let rumor2 = ack_rumor(recip_op_pk, 101, &ack2);
        let wrap2 = seal_and_wrap(&rumor2, &recip_op_sk, &sender_ivpk, vec![], 101, &mut rng)
            .expect("wrap2");
        let r2 = process_gift_wrap_for_ack(&wrap2, &sender_ivk, &store);
        match r2 {
            AckInboxResult::Accepted { blob_id, ack_nonce } => {
                assert_eq!(blob_id, blob);
                assert_eq!(ack_nonce, nonce_2);
            }
            other => panic!("valid ACK must be accepted, got {other:?}"),
        }
        assert_eq!(
            store.len(),
            1,
            "ACK must not drop retention (data permanence)"
        );
        assert!(store.get(&blob, &nonce_2).expect("held").ack_accepted);
    }

    #[test]
    fn payload_blob_locators_are_holders_only() {
        // Encode a payload and check blob_locators decode without embedding blob_id.
        let payload = DeliveryPayload {
            blob_id: [0x11; 32],
            holders: vec!["https://a.example".into(), "https://b.example".into()],
            ack_nonce: [0x22; 32],
            record_kind: None,
        };
        let json = encode_delivery_payload(&payload).expect("enc");
        // blob_id is a sibling field; holders framing is base64 of count+urls only.
        assert!(json.contains("blob_id"));
        assert!(json.contains("blob_locators"));
        let back = crate::v1::nostr::kinds::delivery::decode_delivery_payload(&json).expect("dec");
        assert_eq!(back.holders, payload.holders);
        assert_eq!(back.blob_id, payload.blob_id);
    }

    /// OsSecureRandom is constructible (production path); smoke only.
    #[test]
    fn os_secure_random_produces_esk() {
        let mut rng = OsSecureRandom;
        let esk = fresh_esk(&mut rng).expect("os rng");
        assert_ne!(esk, [0u8; 32]);
    }
}
