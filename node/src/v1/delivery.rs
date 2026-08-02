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
//! 7. retain `(blob, K_tx, ack_nonce, …)` until a valid ACK arrives;
//! 8. ACK return path: poll gift-wraps, unwrap under sender `ivk`, verify
//!    kind-1421 (`op_sig` under published recipient `op` **and** nonce
//!    binding), drop retention on success.
//!
//! # Port boundary
//!
//! The kernel never sees axum/tonic/relay/HTTP types. Runtime supplies an
//! [`OutgoingDeliveryPort`]; finalise calls it **after** durable persistence
//! (never before). Missing operational bundle or missing recipient IVPK is a
//! **named error** — never a silent skip that pretends delivery succeeded.
//!
//! Delivery targets are filled from fully verified profiles / Invoices
//! **before** prove/persist ([`ensure_delivery_targets_before_finalise`]).
//!
//! # Self-delivery
//!
//! The full `SelfDeliveryRecordV1` two-phase path (§4.2 Phase A/B) is a
//! separate block (needs first-occurrence MTP). This module exposes
//! [`out_ciphertext_for_output_ref`] for `K_out` envelopes that an SDR would
//! carry; the SDR itself is not finalised here.
//!
//! Spec: §1.3, §2.3.2, §4.2, §4.2.1, §4.3, §7.1, §7.3.

use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

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
    /// Blossom upload failed for one holder.
    Blossom { holder: String, error: BlossomError },
    /// Relay pool construction / empty list.
    Relay(String),
    /// Every relay rejected or was unreachable — nothing accepted the wrap.
    NoRelayAccepted { results: Vec<RelayOutcomeSummary> },
    /// Wire framing / length error while building inclusion_proof.
    InclusionProof(String),
    /// Plonky2 proof serialisation failed.
    ProofBytes(String),
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
            DeliveryError::Blossom { holder, error } => {
                write!(f, "Blossom upload to {holder}: {error}")
            }
            DeliveryError::Relay(msg) => write!(f, "relay pool: {msg}"),
            DeliveryError::NoRelayAccepted { results } => {
                write!(
                    f,
                    "no relay accepted the gift-wrap ({} outcomes)",
                    results.len()
                )
            }
            DeliveryError::InclusionProof(msg) => write!(f, "inclusion_proof: {msg}"),
            DeliveryError::ProofBytes(msg) => write!(f, "proof bytes: {msg}"),
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
    /// Wall clock for auth / seal `created_at` upper bound.
    pub now: u64,
    /// Kind-24242 auth expiration (absolute unix seconds).
    pub auth_expiration: u64,
}

// ---------------------------------------------------------------------------
// Built (but not yet published) per-coin delivery
// ---------------------------------------------------------------------------

/// Result of the pure build steps for one coin (before network I/O).
///
/// Intermediate `CoinProof` is sealed into `zbe_ciphertext` and not retained
/// as a separate field — re-open via ZBE under `k_tx` if needed. `out_ciphertext`
/// is retained on [`RetainedDeliveryAttempt`] (SDR / §1.3), not here.
#[derive(Clone, Debug)]
pub(crate) struct BuiltCoinDelivery {
    pub keys: PerCoinKeys,
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
#[derive(Clone, Debug)]
pub(crate) struct CoinDeliveryReport {
    pub blob_id: [u8; 32],
    pub detect_tag: [u8; 32],
    pub epk: [u8; 32],
    pub ack_nonce: [u8; 32],
    pub gift_wrap_id: [u8; 32],
    /// One outcome per holder base URL, in order.
    pub blossom_ok: Vec<String>,
    /// One outcome per relay URL, in order — never collapsed.
    pub relay_results: Vec<RelayPublishResult>,
}

/// Upload ZBE blob to every holder, then publish gift-wrap to every relay.
pub(crate) async fn publish_built_delivery(
    built: &BuiltCoinDelivery,
    op_sk: &[u8; 32],
    max_blob_bytes: u64,
    now: u64,
    auth_expiration: u64,
) -> Result<CoinDeliveryReport, DeliveryError> {
    let client = BlossomClient::new(max_blob_bytes).map_err(|e| DeliveryError::Blossom {
        holder: String::new(),
        error: e,
    })?;

    // Binding headers: all three together (event id + attempt nonce + retention).
    let binding = UploadBinding {
        event_id: built.gift_wrap.id,
        attempt_nonce: built.ack_nonce,
        retention: RetentionClass::Indefinite,
    };

    let mut blossom_ok = Vec::with_capacity(built.blob_holders.len());
    for holder in &built.blob_holders {
        client
            .upload(
                holder,
                &built.zbe_ciphertext,
                Some(&binding),
                op_sk,
                now,
                auth_expiration,
            )
            .await
            .map_err(|e| DeliveryError::Blossom {
                holder: holder.clone(),
                error: e,
            })?;
        blossom_ok.push(holder.clone());
    }

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

    Ok(CoinDeliveryReport {
        blob_id: built.blob_id,
        detect_tag: built.keys.detect_tag,
        epk: built.keys.epk,
        ack_nonce: built.ack_nonce,
        gift_wrap_id: built.gift_wrap.id,
        blossom_ok,
        relay_results,
    })
}

// ---------------------------------------------------------------------------
// Retention until ACK (§4.2) — process-local; no SQL migration in this block
// ---------------------------------------------------------------------------

/// One retained delivery attempt awaiting a valid ACK.
///
/// Durable storage would need a migration — **not** created here. Process
/// memory is the same durability class as `BundleStore`; restart loses the
/// queue and the operator must re-drive delivery from value-bearing artefacts.
///
/// Fields are exactly what ACK verification and post-ACK integrity need:
/// identity of the attempt, the sealed ZBE body (content-address checked on
/// accept), `K_tx` + `out_ciphertext` for §4.2 / §1.3 re-open, and the
/// recipient `op` that must verify `op_sig`. Retransmit to relays/holders is
/// a separate gap (no caller re-publishes yet).
#[derive(Clone, Debug)]
pub(crate) struct RetainedDeliveryAttempt {
    pub blob_id: [u8; 32],
    pub detect_tag: [u8; 32],
    pub k_tx: [u8; 32],
    pub ack_nonce: [u8; 32],
    pub zbe_ciphertext: Vec<u8>,
    pub out_ciphertext: Vec<u8>,
    pub recipient_op_pk: [u8; 32],
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

    pub(crate) fn retain(&self, attempt: RetainedDeliveryAttempt) {
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

    /// Accept ACK for this attempt and drop the retained copy when both
    /// signature and nonce checks pass.
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
        guard.remove(&key);
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

/// Production port: build → upload → publish → retain until ACK.
pub(crate) struct MeshDeliveryPort {
    pub retention: Arc<PendingDeliveryStore>,
    /// Secure random — production uses [`super::nostr::nip59::OsSecureRandom`].
    /// Held behind a mutex so the port is `Sync`.
    pub rng: Arc<Mutex<Box<dyn SecureRandom + Send>>>,
}

impl MeshDeliveryPort {
    pub(crate) fn new(
        retention: Arc<PendingDeliveryStore>,
        rng: Box<dyn SecureRandom + Send>,
    ) -> Self {
        Self {
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

            let mut report = TransitionDeliveryReport { delivered: 0 };

            for material in &request.coins {
                // Draw all CSPRNG material under the mutex, then drop the
                // guard *before* Blossom upload / relay publish. Holding the
                // guard across those awaits would serialise every concurrent
                // delivery on the slowest peer.
                let built = {
                    // Mutex: MeshDeliveryPort is Sync and shared across concurrent
                    // deliveries; SecureRandom::fill_bytes needs exclusive &mut,
                    // including stateful test RNGs behind the same dyn box.
                    let mut rng = self.rng.lock().expect("delivery rng mutex poisoned");
                    build_coin_delivery(
                        material,
                        &request.operator.op_sk,
                        &request.operator.ovk,
                        &request.operator.blob_holders,
                        request.operator.now,
                        rng.as_mut(),
                    )?
                }; // MutexGuard dropped here — before any network await.

                let coin_report = publish_built_delivery(
                    &built,
                    &request.operator.op_sk,
                    request.operator.max_blob_bytes,
                    request.operator.now,
                    request.operator.auth_expiration,
                )
                .await?;

                // Retain until ACK (§4.2). Process-local only — no migration.
                self.retention.retain(RetainedDeliveryAttempt {
                    blob_id: built.blob_id,
                    detect_tag: built.keys.detect_tag,
                    k_tx: built.keys.k_tx,
                    ack_nonce: built.ack_nonce,
                    zbe_ciphertext: built.zbe_ciphertext.clone(),
                    out_ciphertext: built.out_ciphertext.clone(),
                    recipient_op_pk: built.recipient_op_pk,
                });

                tracing::info!(
                    subject = %hex::encode(request.subject),
                    blob_id = %hex::encode(coin_report.blob_id),
                    detect_tag = %hex::encode(coin_report.detect_tag),
                    epk = %hex::encode(coin_report.epk),
                    ack_nonce = %hex::encode(coin_report.ack_nonce),
                    gift_wrap_id = %hex::encode(coin_report.gift_wrap_id),
                    blossom_holders = coin_report.blossom_ok.len(),
                    relay_outcomes = coin_report.relay_results.len(),
                    "mesh delivery published for coin"
                );
                report.delivered = report.delivered.saturating_add(1);
            }
            Ok(report)
        })
    }
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
    /// Valid ACK: retention entry dropped.
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
    if wrap.kind != KIND_GIFT_WRAP {
        return AckInboxResult::Ignored {
            reason: "not gift-wrap kind",
        };
    }
    let unwrapped = match unwrap_gift(wrap, sender_ivk) {
        Ok(u) => u,
        Err(_) => {
            return AckInboxResult::Ignored {
                reason: "unwrap failed (not for us or corrupt)",
            };
        }
    };
    if unwrapped.rumor.kind != KIND_ACK {
        return AckInboxResult::Ignored {
            reason: "inner rumor not kind 1421",
        };
    }
    let content = match decode_ack_content(&unwrapped.rumor.content) {
        Ok(c) => c,
        Err(e) => {
            return AckInboxResult::Rejected {
                error: AckVerifyError::Decode(e),
            };
        }
    };
    // Look up by the ACK's own (blob_id, ack_nonce). Attempt-1 nonce against
    // a store holding only attempt 2 → missing key (FieldMismatch) or, if
    // caller used attempt-2 key with attempt-1 body, AckNonceMismatch.
    match store.accept_ack_json(
        &content.blob_id,
        &content.ack_nonce,
        &unwrapped.rumor.content,
    ) {
        Ok(()) => AckInboxResult::Accepted {
            blob_id: content.blob_id,
            ack_nonce: content.ack_nonce,
        },
        Err(e) => AckInboxResult::Rejected { error: e },
    }
}

/// Query relays for kind-1059 gift-wraps and run [`process_gift_wrap_for_ack`]
/// on each verified event. No exponential backoff republish here (GAP).
pub(crate) async fn poll_incoming_acks(
    pool: &RelayPool,
    sender_ivk: &[u8; 32],
    store: &PendingDeliveryStore,
    since: Option<u64>,
) -> Result<Vec<AckInboxResult>, DeliveryError> {
    let filter = Filter {
        kinds: Some(vec![KIND_GIFT_WRAP]),
        since,
        ..Filter::default()
    };
    let aggregate = pool.query_all(&[filter]).await;
    let mut out = Vec::with_capacity(aggregate.events.len());
    for event in &aggregate.events {
        out.push(process_gift_wrap_for_ack(event, sender_ivk, store));
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::v1::nostr::kinds::ack::sign_ack;
    use crate::v1::nostr::kinds::delivery::encode_delivery_payload;
    use crate::v1::nostr::nip59::OsSecureRandom;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::{Digest, Sha256};
    use shared::spec_v1::datastructures::Address;
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
    fn valid_ack_drops_retention() {
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
        });
        store
            .accept_ack_json(&blob, &nonce, &json)
            .expect("valid ACK");
        assert_eq!(store.len(), 0);
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

        // Valid ACK for attempt 2 → free.
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
        assert_eq!(store.len(), 0);
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
