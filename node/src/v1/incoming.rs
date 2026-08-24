//! §4.4 note discovery → §2.3.3 verify → durable decrypt index → §4.2 ACK.
//!
//! # Pipeline (fail-closed)
//!
//! 1. **Scan** — pull kind-1059 gift-wraps from the account's relays; for each
//!    candidate extract outer `zkepk` / `zkdt`, recompute
//!    `ss = ECDH(ivk, epk)`, `detect_tag = Hc(…, ss ‖ epk)`, match.
//!    Non-matches cost one ECDH + one hash and stop — no unwrap, no blob.
//! 2. **Unpack** — NIP-59 unwrap (seal author == rumor author); kind-1420
//!    delivery payload.
//! 3. **Blob fetch** — holders in order; each response is content-address
//!    checked. A lying holder is a **named** outcome; the next holder is
//!    tried only after that outcome is recorded.
//! 4. **ZBE-Open** under `K_tx` — any tag failure aborts (no partial plaintext).
//! 5. **Decode + verify** (§7.1 / §2.3.3 steps 2–6) via the compliance
//!    [`ProverBridge`] port (recursive verify, output inclusion, S2C open of
//!    `H(ProofData)`, first-occurrence, `asset_terms` self-auth).
//! 6. **Durable persist** — `v1_decrypt_index` then process-local index.
//! 7. **Receipt push** — after a fresh dual insert only, publish a
//!    [`CreditReceipt`] on the shared [`ReceiptHub`] (§4.9 / §7.8
//!    `SubscribeReceipts`). Never before persist; never on replay.
//! 8. **ACK** — kind-1421 gift-wrap back to the sender's IVPK, echoing
//!    `ack_nonce` **unchanged**.
//!
//! No credit, no receipt, and no ACK on any failure. ACK is the promise
//! "verified and durable" — never "I saw something". Order is always
//! persist → publish → ACK.
//!
//! Kernel stays transport-free: this module is the port that fills
//! [`crate::kernel::access::InMemoryPrivateIndex`] and emits on
//! [`crate::kernel::access::ReceiptHub`].

use std::fmt;

use shared::spec_v1::bundle::{deserialize_coin_proof, CoinProof, IssuanceTerms};
use shared::spec_v1::encoding::{digest_from_bytes, digest_to_bytes};
use shared::spec_v1::hashes::{
    asset_id_v1, asset_id_v2, detect_tag as poseidon_detect_tag, hash_proof_data, name_hash,
    nav_commitment,
};
use shared::spec_v1::note_encryption::{
    derive_note_key, shared_secret_receiver, xonly_pubkey, zbe_open,
};
use shared::spec_v1::serialize::serialize_proof_data;
use shared::spec_v1::tags::GENESIS_TAG;
use shared::spec_v1::{self as host, HashDigest, LookupResult, SpecError, SpendClassification};
use sqlx::PgPool;
use zkcoins_program::circuit::compliance::MAX_OUTPUT_MERKLE_DEPTH;
use zkcoins_prover::half_agg::comm_verify;
use zkcoins_prover::prover_bridge::{OutputInclusionProof, ProverBridge};
use zkcoins_prover::state_engine::StateEngine;

use super::adapter::EngineAdapter;
use super::blossom::{blob_id_of, verify_content_address, BlossomClient, BlossomError};
use super::db_decrypt_index::{
    decrypt_record_id, get_by_blob_id, get_by_subject_coin, insert_verified_coin_proof_in_tx,
    mark_acked, to_indexed_record, DecryptIndexRow, DecryptVerificationStatus,
};
use super::db_token_provenance::insert_token_provenance_in_tx;
use super::nostr::event::Event;
use super::nostr::kinds::ack::{ack_rumor, encode_ack_content, sign_ack, KIND_ACK};
use super::nostr::kinds::delivery::{decode_delivery_payload, KIND_DELIVERY};
use super::nostr::nip59::{seal_and_wrap, unwrap_gift, SecureRandom, KIND_GIFT_WRAP};
use super::nostr::profile::resolve_profile_by_op_pubkey;
use super::nostr::relay::{Filter, RelayPool};
use super::receive::{extract_compliance_public_inputs, verify_output_inclusion};
use super::recovery::recovery_blob_holders;
use crate::kernel::access::{
    publish_credit_if_inserted, CreditReceipt, InMemoryPrivateIndex, InsertRecordOutcome,
    ReceiptHub, ReceiptState,
};
use crate::kernel::types::{Digest32, SubjectAddress};

// ---------------------------------------------------------------------------
// Errors — named causes, never a bare is_err contract
// ---------------------------------------------------------------------------

/// Fail-closed reasons for the §4.4 / §2.3.3 receive pipeline.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum IncomingError {
    /// Outer tags missing / wrong width / not lowercase hex.
    ScanTags { detail: String },
    /// ECDH / detect_tag recompute failed (bad epk or ivk).
    DetectCrypto(SpecError),
    /// Recomputed detect_tag ≠ outer `zkdt` — not for this ivk.
    DetectTagMismatch {
        claimed: [u8; 32],
        recomputed: [u8; 32],
    },
    /// NIP-59 unwrap failed (wrong recipient, corrupt, or forge).
    Nip59(String),
    /// Seal author ≠ rumor author (forgery check).
    SealAuthorMismatch {
        seal_pubkey: [u8; 32],
        rumor_pubkey: [u8; 32],
    },
    /// Delivery payload decode failed.
    Payload(String),
    /// No advertised or manifest blob holders configured (both merged sets are empty).
    HoldersEmpty,
    /// Every holder failed; last error named. Lying holders are listed.
    AllHoldersFailed { attempts: Vec<HolderAttempt> },
    /// ZBE open failed (auth tag / framing).
    Zbe(SpecError),
    /// Bundle codec failed.
    Bundle(SpecError),
    /// Native Plonky2 proof bytes rejected.
    ProofBytes(String),
    /// Recursive / clause-10 / asset_terms verification failed.
    Verification(String),
    /// Durable SQL write failed.
    Persist(String),
    /// Process-local index insert failed.
    Index(String),
    /// Sender IVPK / relays unavailable for ACK wrap.
    AckDestination { detail: String },
    /// ACK sign / wrap / publish failed.
    AckSend { detail: String },
    /// Relay pool construction / query failed.
    Relay(String),
}

/// One Blossom holder attempt — lying stores are **named**, never silent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HolderAttempt {
    pub holder: String,
    pub outcome: HolderOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum HolderOutcome {
    /// Content-address mismatch: store returned different bytes.
    ContentAddressLie {
        expected: [u8; 32],
        actual: [u8; 32],
    },
    /// Transport / HTTP / not-found / size.
    FetchError { message: String },
    /// Verified body accepted.
    Ok { body_len: usize },
}

impl fmt::Display for IncomingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IncomingError::ScanTags { detail } => write!(f, "scan tags: {detail}"),
            IncomingError::DetectCrypto(e) => write!(f, "detect-tag crypto: {e}"),
            IncomingError::DetectTagMismatch {
                claimed,
                recomputed,
            } => write!(
                f,
                "detect_tag mismatch: claimed={}, recomputed={}",
                hex::encode(claimed),
                hex::encode(recomputed)
            ),
            IncomingError::Nip59(msg) => write!(f, "NIP-59 unwrap: {msg}"),
            IncomingError::SealAuthorMismatch {
                seal_pubkey,
                rumor_pubkey,
            } => write!(
                f,
                "seal author {} ≠ rumor pubkey {} (forged sender)",
                hex::encode(seal_pubkey),
                hex::encode(rumor_pubkey)
            ),
            IncomingError::Payload(msg) => write!(f, "delivery payload: {msg}"),
            IncomingError::HoldersEmpty => {
                write!(f, "no advertised or manifest blob holders configured")
            }
            IncomingError::AllHoldersFailed { attempts } => {
                write!(f, "all {} holders failed:", attempts.len())?;
                for a in attempts {
                    write!(f, " [{} → {}]", a.holder, a.outcome)?;
                }
                Ok(())
            }
            IncomingError::Zbe(e) => write!(f, "ZBE open: {e}"),
            IncomingError::Bundle(e) => write!(f, "CoinProof decode: {e}"),
            IncomingError::ProofBytes(msg) => write!(f, "proof bytes: {msg}"),
            IncomingError::Verification(msg) => write!(f, "verification: {msg}"),
            IncomingError::Persist(msg) => write!(f, "durable persist: {msg}"),
            IncomingError::Index(msg) => write!(f, "process index: {msg}"),
            IncomingError::AckDestination { detail } => {
                write!(f, "ACK destination: {detail}")
            }
            IncomingError::AckSend { detail } => write!(f, "ACK send: {detail}"),
            IncomingError::Relay(msg) => write!(f, "relay: {msg}"),
        }
    }
}

impl fmt::Display for HolderOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HolderOutcome::ContentAddressLie { expected, actual } => write!(
                f,
                "CONTENT_ADDRESS_LIE expected={} actual={}",
                hex::encode(expected),
                hex::encode(actual)
            ),
            HolderOutcome::FetchError { message } => write!(f, "fetch_error: {message}"),
            HolderOutcome::Ok { body_len } => write!(f, "ok body_len={body_len}"),
        }
    }
}

impl std::error::Error for IncomingError {}

// ---------------------------------------------------------------------------
// Scan tags from outer gift-wrap
// ---------------------------------------------------------------------------

/// Extract `zkdt` / `zkepk` from outer tags. Both required, lowercase hex 32B.
///
/// These tags are cleartext for the **recipient's local** detection scan, not
/// for the relay. NIP-01 does not index multi-letter tag names, so `#zkdt` /
/// `#zkepk` are deliberately not server-side filterable (§4.4). The scan
/// therefore pulls the full kind-1059 candidate set and matches here.
pub(crate) fn extract_scan_tags(
    tags: &[Vec<String>],
) -> Result<([u8; 32], [u8; 32]), IncomingError> {
    let mut detect: Option<[u8; 32]> = None;
    let mut epk: Option<[u8; 32]> = None;
    for tag in tags {
        if tag.len() < 2 {
            continue;
        }
        match tag[0].as_str() {
            "zkdt" => {
                detect = Some(parse_hex32_tag(&tag[1], "zkdt")?);
            }
            "zkepk" => {
                epk = Some(parse_hex32_tag(&tag[1], "zkepk")?);
            }
            _ => {}
        }
    }
    let detect_tag = detect.ok_or_else(|| IncomingError::ScanTags {
        detail: "missing zkdt tag".into(),
    })?;
    let epk = epk.ok_or_else(|| IncomingError::ScanTags {
        detail: "missing zkepk tag".into(),
    })?;
    Ok((detect_tag, epk))
}

fn parse_hex32_tag(s: &str, field: &str) -> Result<[u8; 32], IncomingError> {
    if s.len() != 64 || !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return Err(IncomingError::ScanTags {
            detail: format!("{field} must be 64 lowercase hex chars"),
        });
    }
    let bytes = hex::decode(s).map_err(|_| IncomingError::ScanTags {
        detail: format!("{field} hex decode failed"),
    })?;
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Cheap §4.4 match: recompute detect_tag under `ivk` and compare.
///
/// Returns `(ss, epk, detect_tag)` on match. Non-match is
/// [`IncomingError::DetectTagMismatch`] — not an unwrap candidate.
pub(crate) fn match_detect_tag(
    ivk: &[u8; 32],
    outer_detect_tag: &[u8; 32],
    epk: &[u8; 32],
) -> Result<([u8; 32], [u8; 32]), IncomingError> {
    let ss = shared_secret_receiver(ivk, epk).map_err(IncomingError::DetectCrypto)?;
    let recomputed = digest_to_bytes(&poseidon_detect_tag(&ss, epk));
    if &recomputed != outer_detect_tag {
        return Err(IncomingError::DetectTagMismatch {
            claimed: *outer_detect_tag,
            recomputed,
        });
    }
    Ok((ss, recomputed))
}

// ---------------------------------------------------------------------------
// Blob fetch with named lying holders
// ---------------------------------------------------------------------------

/// Fetch `blob_id` from holders in order. Content-address is checked per
/// holder. A lie is recorded and the next holder is tried — never silently.
pub(crate) async fn fetch_blob_from_holders(
    client: &BlossomClient,
    blob_id: &[u8; 32],
    holders: &[String],
) -> Result<(Vec<u8>, Vec<HolderAttempt>), IncomingError> {
    if holders.is_empty() {
        return Err(IncomingError::HoldersEmpty);
    }
    let mut attempts = Vec::with_capacity(holders.len());
    for holder in holders {
        match client.fetch(holder, blob_id).await {
            Ok(body) => {
                // fetch already calls verify_content_address; re-assert so a
                // future fetch regression cannot drop the check silently.
                if let Err(BlossomError::ContentAddressMismatch { expected, actual }) =
                    verify_content_address(blob_id, &body)
                {
                    attempts.push(HolderAttempt {
                        holder: holder.clone(),
                        outcome: HolderOutcome::ContentAddressLie { expected, actual },
                    });
                    continue;
                }
                // Also recompute explicitly for the attempt log.
                let actual = blob_id_of(&body);
                if &actual != blob_id {
                    attempts.push(HolderAttempt {
                        holder: holder.clone(),
                        outcome: HolderOutcome::ContentAddressLie {
                            expected: *blob_id,
                            actual,
                        },
                    });
                    continue;
                }
                attempts.push(HolderAttempt {
                    holder: holder.clone(),
                    outcome: HolderOutcome::Ok {
                        body_len: body.len(),
                    },
                });
                return Ok((body, attempts));
            }
            Err(BlossomError::ContentAddressMismatch { expected, actual }) => {
                attempts.push(HolderAttempt {
                    holder: holder.clone(),
                    outcome: HolderOutcome::ContentAddressLie { expected, actual },
                });
            }
            Err(e) => {
                attempts.push(HolderAttempt {
                    holder: holder.clone(),
                    outcome: HolderOutcome::FetchError {
                        message: e.to_string(),
                    },
                });
            }
        }
    }
    Err(IncomingError::AllHoldersFailed { attempts })
}

// ---------------------------------------------------------------------------
// inclusion_proof wire → OutputInclusionProof
// ---------------------------------------------------------------------------

/// Parse §1.7.5 wire: `u32be leaf_index ‖ u8 depth ‖ depth × 32 sibling digests`.
pub(crate) fn parse_inclusion_proof_wire(
    bytes: &[u8],
) -> Result<OutputInclusionProof, IncomingError> {
    if bytes.len() < 5 {
        return Err(IncomingError::Verification(
            "inclusion_proof truncated (need leaf_index + depth)".into(),
        ));
    }
    let leaf_index = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let depth = bytes[4];
    if depth as usize > MAX_OUTPUT_MERKLE_DEPTH {
        return Err(IncomingError::Verification(format!(
            "inclusion_proof depth {depth} exceeds MAX_OUTPUT_MERKLE_DEPTH"
        )));
    }
    let expected_len = 5 + (depth as usize) * 32;
    if bytes.len() != expected_len {
        return Err(IncomingError::Verification(format!(
            "inclusion_proof length {} ≠ expected {expected_len} for depth {depth}",
            bytes.len()
        )));
    }
    let mut siblings = Vec::with_capacity(depth as usize);
    let mut cur = &bytes[5..];
    for _ in 0..depth {
        let mut dig = [0u8; 32];
        dig.copy_from_slice(&cur[..32]);
        siblings
            .push(digest_from_bytes(&dig).map_err(|e| IncomingError::Verification(e.to_string()))?);
        cur = &cur[32..];
    }
    Ok(OutputInclusionProof {
        leaf_index,
        depth,
        siblings,
    })
}

// ---------------------------------------------------------------------------
// asset_terms self-authentication (§2.3.3 step 6)
// ---------------------------------------------------------------------------

/// Recompute `asset_id` from terms and require equality with `coin.asset_id`.
pub(crate) fn verify_asset_terms_self_auth(
    coin_asset_id: HashDigest,
    terms: &IssuanceTerms,
) -> Result<(), IncomingError> {
    let nh = name_hash(&terms.name)
        .map_err(|e| IncomingError::Verification(format!("asset_terms name_hash: {e}")))?;
    let recomputed = match terms.issuance_version {
        1 => {
            if terms.cap_total.is_some() || terms.terms_salt.is_some() {
                return Err(IncomingError::Verification(
                    "asset_terms v1 must not carry cap_total/terms_salt".into(),
                ));
            }
            asset_id_v1(GENESIS_TAG, &terms.creator_pubkey, &nh, terms.decimals, 1)
        }
        2 => {
            let cap = terms.cap_total.ok_or_else(|| {
                IncomingError::Verification("asset_terms v2 missing cap_total".into())
            })?;
            let salt = terms.terms_salt.ok_or_else(|| {
                IncomingError::Verification("asset_terms v2 missing terms_salt".into())
            })?;
            asset_id_v2(
                GENESIS_TAG,
                &terms.creator_pubkey,
                &nh,
                terms.decimals,
                2,
                cap,
                &salt,
            )
        }
        other => {
            return Err(IncomingError::Verification(format!(
                "asset_terms issuance_version {other} is neither 1 nor 2 — refuse whole bundle"
            )));
        }
    };
    if recomputed != coin_asset_id {
        return Err(IncomingError::Verification(
            "asset_terms self-auth failed: recomputed asset_id ≠ coin.asset_id".to_string(),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Host verification of a decrypted CoinProof (§2.3.3 steps 2–6)
// ---------------------------------------------------------------------------

/// Classify + finality-gate the creating nullifier's first-occurrence entry on
/// the receiver's own NfLog (§3.7 classify, §3.9 size_final). This is the
/// store-and-ACK gate's finality check — mirrors the idiom already used at
/// `receive.rs::verify_creating_first_occurrence` (`pos < receiver_nav.size`
/// where `receiver_nav = size_final_nav(engine)`, i.e. `receiver_nav.size ==
/// size_final`) and at `reconstitute.rs::live_nflog_paths` (`pos_create >=
/// receiver_nav.size` => `CreatingNullifierNotCompleted`). Both of those are
/// already correct; this function brings incoming.rs's store-and-ACK gate up
/// to the same standard.
fn verify_creating_nullifier_final(
    engine: &StateEngine,
    pk_create: [u8; 32],
    r_create: [u8; 32],
) -> Result<(), IncomingError> {
    match engine.nflog().classify(pk_create, r_create) {
        SpendClassification::ValidFirstSpend => {}
        SpendClassification::RejectedDoubleSpend => {
            return Err(IncomingError::Verification(
                "creating Pk is present with a different R (double-spend loser)".into(),
            ));
        }
        SpendClassification::Pending => {
            return Err(IncomingError::Verification(
                "creating nullifier is not a first-occurrence on receiver NfLog".into(),
            ));
        }
    }
    match engine.nflog().lookup(pk_create) {
        LookupResult::Present { pos, r, .. } => {
            if r != r_create {
                return Err(IncomingError::Verification(
                    "NfLog first-occurrence R mismatches creating_nullifier.R".into(),
                ));
            }
            let size_final = engine.nflog().size_final(engine.tip_height());
            if pos >= size_final {
                return Err(IncomingError::Verification(format!(
                    "creating nullifier position {pos} is not yet final (size_final \
                     {size_final}); refusing credit until §3.9 finality (6 confirmations)"
                )));
            }
        }
        LookupResult::Absent => {
            return Err(IncomingError::Verification(
                "creating Pk vanished between classify and lookup".into(),
            ));
        }
    }
    Ok(())
}

/// Verify a decrypted bundle against the local engine + proof port.
///
/// Does **not** run the receive transition (step 7) — that is a separate
/// credit path. This is the store-and-ACK gate.
pub(crate) fn verify_coin_proof_for_index(
    engine: &StateEngine,
    bridge: &ProverBridge,
    cp: &CoinProof,
    subject: &[u8; 32],
) -> Result<(), IncomingError> {
    // Recipient binding: coin must name this subject.
    if &cp.coin.recipient.0 != subject {
        return Err(IncomingError::Verification(format!(
            "coin.recipient {} ≠ subject {}",
            hex::encode(cp.coin.recipient.0),
            hex::encode(subject)
        )));
    }

    // Step 6 — asset_terms self-auth when present.
    if let Some(terms) = &cp.asset_terms {
        verify_asset_terms_self_auth(cp.coin.asset_id, terms)?;
    }

    // Step 2 — load + recursive verify under circuit C (port).
    let creating_proof = bridge
        .load_transition_proof_bytes(&cp.proof)
        .map_err(|e| IncomingError::ProofBytes(format!("{e:#}")))?;
    bridge
        .verify_transition(&creating_proof)
        .map_err(|e| IncomingError::Verification(format!("recursive proof: {e:#}")))?;

    let (creating_pd, consumed_pubkey, _network_id) =
        extract_compliance_public_inputs(&creating_proof).map_err(|e| {
            IncomingError::Verification(format!("creating proof public inputs: {e:#}"))
        })?;

    // Step 2 continued — open nav_commitment with bundle nav_opening.
    let nav_root = host::nflog_root(cp.nav_opening.size, cp.nav_opening.mth);
    let expected_commit = nav_commitment(nav_root, &cp.nav_opening.nav_rand);
    if expected_commit != creating_pd.nav_commitment {
        return Err(IncomingError::Verification(
            "nav_opening does not open creating proof nav_commitment".into(),
        ));
    }
    if !engine
        .nflog()
        .is_canonical(cp.nav_opening.size, cp.nav_opening.mth)
    {
        return Err(IncomingError::Verification(
            "nav (size, mth) is not canonical on receiver NfLog".into(),
        ));
    }
    let size_final = engine.nflog().size_final(engine.tip_height());
    if cp.nav_opening.size > size_final {
        return Err(IncomingError::Verification(format!(
            "nav.size {} exceeds size_final {size_final}",
            cp.nav_opening.size
        )));
    }

    // Step 3 — output inclusion.
    let inclusion = parse_inclusion_proof_wire(&cp.inclusion_proof)?;
    verify_output_inclusion(
        cp.coin.identifier,
        &inclusion,
        creating_pd.output_coins_root,
    )
    .map_err(|e| IncomingError::Verification(format!("output inclusion: {e:#}")))?;

    // Step 4 — S2C open of creating nullifier against H(ProofData) + first-occurrence.
    if consumed_pubkey != cp.creating_nullifier.pk_create {
        return Err(IncomingError::Verification(
            "creating_nullifier.Pk ≠ creating_proof.consumed_pubkey".into(),
        ));
    }
    let h_pd = hash_proof_data(&serialize_proof_data(&creating_pd));
    comm_verify(
        &cp.creating_nullifier.r_create,
        &h_pd,
        &cp.creating_nullifier.r_prime_create,
    )
    .map_err(|e| {
        IncomingError::Verification(format!(
            "S2C opening does not bind H(creating ProofData): {e:#}"
        ))
    })?;

    verify_creating_nullifier_final(
        engine,
        cp.creating_nullifier.pk_create,
        cp.creating_nullifier.r_create,
    )?;

    // Step 5 — local replay: already held coin is refused for a second credit
    // path; the durable index UNIQUE is the durable half of this check.
    // (Coin-history membership for already-credited coins is enforced at
    // begin_receive; here we only gate the decrypt index.)

    // 10(b) identifier recompute (host early reject, same as receive.rs).
    let expected_id = host::coin_identifier(
        cp.creating_prev_ash,
        &cp.coin.recipient.0,
        cp.coin.asset_id,
        cp.coin.amount,
        inclusion.leaf_index,
    );
    if cp.coin.identifier != expected_id {
        return Err(IncomingError::Verification(
            "coin.identifier does not recompute from creating_prev_ash (clause 10(b))".into(),
        ));
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// ACK after durable persist — named argument groups (clippy too_many_arguments)
// ---------------------------------------------------------------------------

/// Four closed ACK fields signed under the recipient `op` key.
///
/// No [`Debug`]: `op_sk` is signing material — never log this bag.
#[derive(Clone, Copy)]
pub(crate) struct AckIdentity<'a> {
    pub op_sk: &'a [u8; 32],
    pub detect_tag: &'a [u8; 32],
    pub blob_id: &'a [u8; 32],
    pub ack_nonce: &'a [u8; 32],
}

/// ACK gift-wrap destination: sender IVPK + their advertised relays.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AckDestinationTarget<'a> {
    pub sender_ivpk: &'a [u8; 32],
    pub sender_relays: &'a [String],
}

/// Wall clock + CSPRNG for seal/wrap (never held across network awaits).
pub(crate) struct AckClock<'a> {
    pub now: u64,
    pub rng: &'a mut dyn SecureRandom,
}

/// Subject + receive secrets (ivk scans, op signs ACK).
///
/// No [`Debug`]: `ivk` / `op` are secrets (never log this bag).
#[derive(Clone, Copy)]
pub(crate) struct CandidateSecrets<'a> {
    pub subject: &'a [u8; 32],
    pub ivk: &'a [u8; 32],
    pub op: &'a [u8; 32],
}

/// Durable SQL + process-local index + receipt hub + engine port.
///
/// Argument group (clippy `too_many_arguments`), not pure config: `adapter`
/// is a live engine dependency. No [`Debug`] — nothing formats this bag, and
/// `EngineAdapter` must not grow a derived `Debug` (balances / NfLog / proofs).
#[derive(Clone, Copy)]
pub(crate) struct CandidateStores<'a> {
    pub adapter: &'a EngineAdapter,
    pub pool: &'a PgPool,
    pub index: &'a InMemoryPrivateIndex,
    /// Shared with kernel `SubscribeReceipts`; publish only after dual persist.
    pub receipts: &'a ReceiptHub,
}

/// Blob size bound, recovery stores, discovery relays, closed network label.
#[derive(Clone, Copy, Debug)]
pub(crate) struct CandidateNetwork<'a> {
    pub max_blob_bytes: u64,
    pub manifest_blob_stores: &'a [String],
    pub discovery_relays: &'a [String],
    pub expected_network: &'a str,
}

/// Inputs for one inbound poll over a subject's relay set.
pub(crate) struct IncomingPoll<'a> {
    pub relays: &'a [String],
    pub secrets: CandidateSecrets<'a>,
    pub stores: CandidateStores<'a>,
    pub max_blob_bytes: u64,
    pub manifest_blob_stores: &'a [String],
    pub expected_network: &'a str,
    pub now: u64,
    pub rng: &'a mut dyn SecureRandom,
    pub since: Option<u64>,
}

/// Build and publish a kind-1421 ACK gift-wrapped to the sender's IVPK.
///
/// `ack_nonce` is echoed **byte-identical** from the delivery payload.
///
/// `rng` is consumed only for the local `seal_and_wrap` step; the subsequent
/// relay publish does not touch it (no lock held across that await).
pub(crate) async fn send_delivery_ack(
    AckIdentity {
        op_sk,
        detect_tag,
        blob_id,
        ack_nonce,
    }: AckIdentity<'_>,
    AckDestinationTarget {
        sender_ivpk,
        sender_relays,
    }: AckDestinationTarget<'_>,
    AckClock { now, rng }: AckClock<'_>,
) -> Result<Event, IncomingError> {
    if sender_relays.is_empty() {
        return Err(IncomingError::AckDestination {
            detail: "sender relay set empty".into(),
        });
    }
    let content =
        sign_ack(op_sk, detect_tag, blob_id, ack_nonce).map_err(|e| IncomingError::AckSend {
            detail: format!("sign_ack: {e}"),
        })?;
    // encode_ack_content is the closed four-field JSON (also used by ack_rumor).
    let _json = encode_ack_content(&content);
    let op_pk = xonly_pubkey(op_sk).map_err(|e| IncomingError::AckSend {
        detail: format!("op xonly: {e}"),
    })?;
    let rumor = ack_rumor(op_pk, now, &content);
    if rumor.kind != KIND_ACK {
        return Err(IncomingError::AckSend {
            detail: format!("ack_rumor kind {}", rumor.kind),
        });
    }
    // Draw seal/wrap material *before* any network await.
    let wrap = seal_and_wrap(&rumor, op_sk, sender_ivpk, vec![], now, rng).map_err(|e| {
        IncomingError::AckSend {
            detail: format!("gift-wrap ACK: {e}"),
        }
    })?;
    let pool =
        RelayPool::new(sender_relays.to_vec()).map_err(|e| IncomingError::Relay(e.to_string()))?;
    let results = pool.publish_all(&wrap).await;
    let any_ok = results
        .iter()
        .any(|r| matches!(r, super::nostr::relay::RelayPublishResult::Accepted { .. }));
    if !any_ok {
        return Err(IncomingError::AckSend {
            detail: format!("no relay accepted ACK ({} outcomes)", results.len()),
        });
    }
    Ok(wrap)
}

// ---------------------------------------------------------------------------
// One candidate through the full pipeline
// ---------------------------------------------------------------------------

/// Outcome of processing one gift-wrap candidate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum CandidateOutcome {
    /// Not for us (detect_tag) or not a delivery — ignore.
    Ignored { reason: &'static str },
    /// Verified, durable, ACK sent (or re-ACK on replay).
    Accepted {
        coin_id: [u8; 32],
        blob_id: [u8; 32],
        record_id: [u8; 32],
        replay: bool,
        holder_attempts: Vec<HolderAttempt>,
    },
    /// Matched detect_tag but a later step failed — no credit, no ACK.
    Rejected { error: IncomingError },
}

/// Process one outer gift-wrap for one subject.
///
/// Secrets in: `ivk` (scan + NIP-59 unwrap) and `op` (ACK sign). The rest of
/// the operational bundle (`ovk`, `nk`, `op_secret`) is never touched here.
pub(crate) async fn process_delivery_candidate(
    wrap: &Event,
    secrets: CandidateSecrets<'_>,
    stores: CandidateStores<'_>,
    network: CandidateNetwork<'_>,
    clock: AckClock<'_>,
) -> CandidateOutcome {
    match process_delivery_candidate_inner(wrap, secrets, stores, network, clock).await {
        Ok(o) => o,
        Err(e) => CandidateOutcome::Rejected { error: e },
    }
}

async fn process_delivery_candidate_inner(
    wrap: &Event,
    CandidateSecrets { subject, ivk, op }: CandidateSecrets<'_>,
    CandidateStores {
        adapter,
        pool,
        index,
        receipts,
    }: CandidateStores<'_>,
    CandidateNetwork {
        max_blob_bytes,
        manifest_blob_stores,
        discovery_relays,
        expected_network,
    }: CandidateNetwork<'_>,
    AckClock { now, rng }: AckClock<'_>,
) -> Result<CandidateOutcome, IncomingError> {
    if wrap.kind != KIND_GIFT_WRAP {
        return Ok(CandidateOutcome::Ignored {
            reason: "not gift-wrap kind",
        });
    }

    // 1. Scan tags + detect_tag match (cheap prefilter).
    let (outer_dt, epk) = match extract_scan_tags(&wrap.tags) {
        Ok(t) => t,
        Err(_) => {
            return Ok(CandidateOutcome::Ignored {
                reason: "missing or invalid zkdt/zkepk",
            });
        }
    };
    let (ss, detect_tag) = match match_detect_tag(ivk, &outer_dt, &epk) {
        Ok(v) => v,
        Err(IncomingError::DetectTagMismatch { .. }) => {
            return Ok(CandidateOutcome::Ignored {
                reason: "detect_tag not for this ivk",
            });
        }
        Err(e) => return Err(e),
    };

    // 2. NIP-59 unwrap + forgery check (seal.pubkey == rumor.pubkey is inside unwrap_gift).
    let unwrapped = unwrap_gift(wrap, ivk).map_err(|e| match e {
        super::nostr::nip59::Nip59Error::SealAuthorMismatch {
            seal_pubkey,
            rumor_pubkey,
        } => IncomingError::SealAuthorMismatch {
            seal_pubkey,
            rumor_pubkey,
        },
        other => IncomingError::Nip59(other.to_string()),
    })?;
    if unwrapped.rumor.kind != KIND_DELIVERY {
        return Ok(CandidateOutcome::Ignored {
            reason: "inner rumor not kind 1420",
        });
    }
    let payload = decode_delivery_payload(&unwrapped.rumor.content)
        .map_err(|e| IncomingError::Payload(e.to_string()))?;

    // Self-delivery records are a separate block (SDR Phase B); this path
    // accepts only CoinProof deliveries (no record_kind).
    if payload.record_kind.is_some() {
        return Ok(CandidateOutcome::Ignored {
            reason: "self-delivery record_kind — not CoinProof receive path",
        });
    }

    // Replay short-circuit: already durable by blob_id → re-ACK with the
    // **current** payload's ack_nonce (retries use a fresh nonce; echoing the
    // stored one would leave the sender retrying forever).
    if let Some(existing) = get_by_blob_id(pool, &payload.blob_id)
        .await
        .map_err(|e| IncomingError::Persist(format!("{e:#}")))?
    {
        if &existing.subject == subject {
            re_ack_for_attempt(
                AckIdentity {
                    op_sk: op,
                    detect_tag: &detect_tag,
                    blob_id: &payload.blob_id,
                    ack_nonce: &payload.ack_nonce,
                },
                &unwrapped.seal.pubkey,
                discovery_relays,
                expected_network,
                AckClock { now, rng },
            )
            .await?;
            return Ok(CandidateOutcome::Accepted {
                coin_id: existing.coin_id,
                blob_id: existing.blob_id,
                record_id: existing.record_id,
                replay: true,
                holder_attempts: vec![],
            });
        }
    }

    // 3. Blob fetch with named lying holders.
    let client =
        BlossomClient::new(max_blob_bytes).map_err(|e| IncomingError::AllHoldersFailed {
            attempts: vec![HolderAttempt {
                holder: String::new(),
                outcome: HolderOutcome::FetchError {
                    message: e.to_string(),
                },
            }],
        })?;
    // Optional probe of the first holder (surfaces size before GET body).
    if let Some(first) = payload.holders.first() {
        let _ = client.probe(first, &payload.blob_id).await;
    }
    let holders = recovery_blob_holders(&payload.holders, manifest_blob_stores);
    let (zbe_ciphertext, holder_attempts) =
        fetch_blob_from_holders(&client, &payload.blob_id, &holders).await?;

    // 4. K_tx + ZBE-Open.
    let k_tx = derive_note_key(&ss, &epk).map_err(IncomingError::DetectCrypto)?;
    let plaintext = zbe_open(&k_tx, &zbe_ciphertext).map_err(IncomingError::Zbe)?;

    // 5. Decode + verify.
    let cp = deserialize_coin_proof(&plaintext).map_err(IncomingError::Bundle)?;
    // Bundle epk / detect_tag must agree with the outer scan tags.
    if cp.epk != epk {
        return Err(IncomingError::Verification(
            "CoinProof.epk ≠ outer zkepk".into(),
        ));
    }
    if digest_to_bytes(&cp.detect_tag) != detect_tag {
        return Err(IncomingError::Verification(
            "CoinProof.detect_tag ≠ outer zkdt".into(),
        ));
    }

    let coin_id = digest_to_bytes(&cp.coin.identifier);
    // Coin-level replay (same subject + coin_id, possibly different blob /
    // fresh ack_nonce). No second credit; ACK the **current** attempt.
    if let Some(existing) = get_by_subject_coin(pool, subject, &coin_id)
        .await
        .map_err(|e| IncomingError::Persist(format!("{e:#}")))?
    {
        re_ack_for_attempt(
            AckIdentity {
                op_sk: op,
                detect_tag: &detect_tag,
                blob_id: &payload.blob_id,
                ack_nonce: &payload.ack_nonce,
            },
            &unwrapped.seal.pubkey,
            discovery_relays,
            expected_network,
            AckClock { now, rng },
        )
        .await?;
        return Ok(CandidateOutcome::Accepted {
            coin_id: existing.coin_id,
            blob_id: existing.blob_id,
            record_id: existing.record_id,
            replay: true,
            holder_attempts,
        });
    }

    let bridge = adapter.bridge();

    // 6. Finality verification and durable persist share the scanner write
    // gate. A reorg restore therefore cannot invalidate the creating
    // nullifier between the live-engine check and the durable credit.
    let (row, sql_outcome) = {
        let _write_gate = adapter.lock_writes().await;
        adapter.with_engine(|engine| verify_coin_proof_for_index(engine, &bridge, &cp, subject))?;

        let asset_id = digest_to_bytes(&cp.coin.asset_id);
        let record_id = decrypt_record_id(subject, &coin_id, &payload.blob_id);
        let row = DecryptIndexRow {
            record_id,
            subject: *subject,
            coin_id,
            blob_id: payload.blob_id,
            detect_tag,
            canonical: plaintext,
            asset_id,
            verification_status: DecryptVerificationStatus::Verified,
            delivery_event_id: wrap.id,
            ack_nonce: payload.ack_nonce,
            occurred_at: 0,
        };

        // Re-check the cheap finality-only predicate immediately before the
        // SQL insert while the same write gate is still held.
        adapter.with_engine(|engine| {
            verify_creating_nullifier_final(
                engine,
                cp.creating_nullifier.pk_create,
                cp.creating_nullifier.r_create,
            )
        })?;
        let sql_outcome =
            persist_verified_coin_and_provenance(pool, &row, cp.asset_terms.as_ref()).await?;

        // Durable credit is fixed. Release the gate before process-local and
        // network work so the scanner can proceed.
        (row, sql_outcome)
    };
    let asset_id = row.asset_id;
    let record_id = row.record_id;
    let indexed = to_indexed_record(&row);
    let mem_outcome = index
        .insert_record(indexed)
        .map_err(|e| IncomingError::Index(e.to_string()))?;
    let replay = matches!(
        (sql_outcome, mem_outcome),
        (InsertRecordOutcome::AlreadyPresent, _) | (_, InsertRecordOutcome::AlreadyPresent)
    );

    // 7. Receipt push — only after durable dual insert, never on replay,
    // never before persist. Does not sit between persist and this point
    // as a blocking gate: publish is non-blocking (bounded fan-out).
    // Creating nullifier is ValidFirstSpend at this point; wire state is
    // §3.10 `completed` (first-occurrence verified before credit).
    publish_credit_if_inserted(
        sql_outcome,
        mem_outcome,
        receipts,
        CreditReceipt {
            subject: SubjectAddress(*subject),
            coin_id: Digest32(coin_id),
            asset_id: Digest32(asset_id),
            amount: cp.coin.amount,
            state: ReceiptState::Completed,
            credited_at: now,
        },
    );

    // 8. ACK after durable persist (+ receipt publish).
    send_ack_to_seal_author(
        AckIdentity {
            op_sk: op,
            detect_tag: &detect_tag,
            blob_id: &payload.blob_id,
            ack_nonce: &payload.ack_nonce,
        },
        &unwrapped.seal.pubkey,
        discovery_relays,
        expected_network,
        AckClock { now, rng },
    )
    .await?;
    mark_acked(pool, &record_id)
        .await
        .map_err(|e| IncomingError::Persist(format!("mark_acked: {e:#}")))?;

    Ok(CandidateOutcome::Accepted {
        coin_id,
        blob_id: payload.blob_id,
        record_id,
        replay,
        holder_attempts,
    })
}

/// Atomically persist the verified private CoinProof and any self-authenticated
/// Class-B terms it carried (§4.6 / §4.8).
///
/// `None` is intentionally opaque and writes no provenance row. A conflicting
/// existing provenance value aborts the whole transaction before ACK; it is
/// never overwritten and the CoinProof row is not partially committed.
async fn persist_verified_coin_and_provenance(
    pool: &PgPool,
    row: &DecryptIndexRow,
    asset_terms: Option<&IssuanceTerms>,
) -> Result<InsertRecordOutcome, IncomingError> {
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| IncomingError::Persist(format!("store-and-ACK transaction begin: {e:#}")))?;
    if let Some(terms) = asset_terms {
        insert_token_provenance_in_tx(&mut tx, &row.asset_id, terms)
            .await
            .map_err(|e| IncomingError::Persist(format!("token provenance: {e:#}")))?;
    }
    let outcome = insert_verified_coin_proof_in_tx(&mut tx, row)
        .await
        .map_err(|e| IncomingError::Persist(format!("CoinProof index: {e:#}")))?;
    tx.commit()
        .await
        .map_err(|e| IncomingError::Persist(format!("store-and-ACK transaction commit: {e:#}")))?;
    Ok(outcome)
}

/// Re-ACK a delivery attempt without re-crediting. Always echoes the
/// **attempt's** `ack_nonce` / `blob_id` / `detect_tag` (not a stale stored
/// nonce from an earlier retry).
async fn re_ack_for_attempt(
    identity: AckIdentity<'_>,
    seal_author_op: &[u8; 32],
    discovery_relays: &[String],
    expected_network: &str,
    clock: AckClock<'_>,
) -> Result<(), IncomingError> {
    send_ack_to_seal_author(
        identity,
        seal_author_op,
        discovery_relays,
        expected_network,
        clock,
    )
    .await
}

async fn send_ack_to_seal_author(
    identity: AckIdentity<'_>,
    seal_author_op: &[u8; 32],
    discovery_relays: &[String],
    expected_network: &str,
    clock: AckClock<'_>,
) -> Result<(), IncomingError> {
    // Sender's IVPK comes from their kind-0 profile under the seal author
    // (op). Names never reach this path (§4.3 / §7.5).
    if discovery_relays.is_empty() {
        return Err(IncomingError::AckDestination {
            detail: "no discovery relays to resolve sender profile".into(),
        });
    }
    let pool = RelayPool::new(discovery_relays.to_vec())
        .map_err(|e| IncomingError::Relay(e.to_string()))?;
    let profile = resolve_profile_by_op_pubkey(&pool, seal_author_op, expected_network)
        .await
        .map_err(|e| IncomingError::AckDestination {
            detail: format!("sender profile by op: {e}"),
        })?;
    send_delivery_ack(
        identity,
        AckDestinationTarget {
            sender_ivpk: &profile.ivpk,
            sender_relays: &profile.relays,
        },
        clock,
    )
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Poll loop entry (runtime)
// ---------------------------------------------------------------------------

/// Query relays for kind-1059 events and run the pipeline for one subject.
///
/// Secrets in: `ivk` + `op` only (see [`process_delivery_candidate`]).
///
/// `rng` is **not** used while querying relays; it is required later to
/// gift-wrap kind-1421 ACKs for accepted (or replay re-ACK) candidates.
/// The source is held across those post-query awaits, so implementations
/// must be [`Send`] (see [`SecureRandom`]).
pub(crate) async fn poll_incoming_deliveries(
    IncomingPoll {
        relays,
        secrets,
        stores,
        max_blob_bytes,
        manifest_blob_stores,
        expected_network,
        now,
        rng,
        since,
    }: IncomingPoll<'_>,
) -> Result<Vec<CandidateOutcome>, IncomingError> {
    if relays.is_empty() {
        return Err(IncomingError::Relay("empty relay list".into()));
    }
    let relay_pool =
        RelayPool::new(relays.to_vec()).map_err(|e| IncomingError::Relay(e.to_string()))?;
    // §4.4: the relay cannot pre-filter for the recipient (it holds neither
    // `ivk` nor the sender's `esk`). `zkdt` / `zkepk` are cleartext tags for
    // the *recipient*, not the relay — multi-letter on purpose so NIP-01 does
    // not index them. Detection is not server-side filterable: pull the full
    // kind-1059 candidate set and match locally (one ECDH + one Poseidon hash
    // per scanned event). Leaving `tags` empty is intentional, not a missed
    // optimisation.
    let filter = Filter {
        kinds: Some(vec![KIND_GIFT_WRAP]),
        since,
        tags: vec![],
        ..Filter::default()
    };
    let aggregate = relay_pool.query_all(&[filter]).await;
    let mut out = Vec::with_capacity(aggregate.events.len());
    for event in &aggregate.events {
        out.push(
            process_delivery_candidate(
                event,
                secrets,
                stores,
                CandidateNetwork {
                    max_blob_bytes,
                    manifest_blob_stores,
                    discovery_relays: relays,
                    expected_network,
                },
                // Reborrow per candidate so the loop does not move `rng`.
                AckClock {
                    now,
                    rng: &mut *rng,
                },
            )
            .await,
        );
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Tests — pure steps plus an ignored real-proof pipeline fixture
// ---------------------------------------------------------------------------

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
    use sha2::{Digest as _, Sha256};
    use zkcoins_program::circuit::compliance::Network;

    trait IntoFixtureEngine {
        fn into_fixture_engine(self) -> StateEngine;
    }

    impl IntoFixtureEngine for StateEngine {
        fn into_fixture_engine(self) -> StateEngine {
            self
        }
    }

    impl<E: std::fmt::Debug> IntoFixtureEngine for Result<StateEngine, E> {
        fn into_fixture_engine(self) -> StateEngine {
            match self {
                Ok(engine) => engine,
                Err(err) => panic!("failed to build StateEngine fixture: {err:?}"),
            }
        }
    }

    fn nullifier_entry(pk: [u8; 32], r: [u8; 32]) -> (host::ChainPosition, host::NfLogEntry) {
        (
            host::ChainPosition {
                height: 0,
                tx_index: 0,
                vin_index: 0,
                member_index: 0,
            },
            host::NfLogEntry { pk, r },
        )
    }

    /// Deterministic CSPRNG for delivery fixtures (never production use).
    struct PipelineRng {
        state: [u8; 32],
        counter: u64,
    }

    impl PipelineRng {
        fn new(seed: &[u8]) -> Self {
            Self {
                state: Sha256::digest(seed).into(),
                counter: 0,
            }
        }
    }

    impl SecureRandom for PipelineRng {
        fn fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), crate::v1::nostr::nip59::Nip59Error> {
            let mut filled = 0;
            while filled < dest.len() {
                let mut block = Vec::with_capacity(40);
                block.extend_from_slice(&self.state);
                block.extend_from_slice(&self.counter.to_be_bytes());
                self.state = Sha256::digest(&block).into();
                self.counter = self.counter.wrapping_add(1);
                let take = (dest.len() - filled).min(self.state.len());
                dest[filled..filled + take].copy_from_slice(&self.state[..take]);
                filled += take;
            }
            Ok(())
        }
    }

    fn pipeline_fixture_sk(label: &[u8]) -> ([u8; 32], [u8; 32]) {
        let mut seed = Sha256::digest(label).to_vec();
        let secp = Secp256k1::new();
        loop {
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&seed[..32]);
            if let Ok(sk) = SecretKey::from_slice(&sk_bytes) {
                let keypair = Keypair::from_secret_key(&secp, &sk);
                let (xonly, _) = keypair.x_only_public_key();
                return (sk_bytes, xonly.serialize());
            }
            seed = Sha256::digest(&seed).to_vec();
        }
    }

    /// The store-and-ACK path deliberately implements DEFER, not a durable
    /// `Pending` receipt: an error stores, ACKs, and credits nothing, while the
    /// existing unconditional relay re-poll naturally retries the delivery.
    #[test]
    fn creating_nullifier_present_not_final_is_rejected() {
        let pk = [0x11; 32];
        let r = [0x22; 32];
        let engine = StateEngine::from_persisted(
            Network::Regtest,
            0,
            0,
            0,
            vec![nullifier_entry(pk, r)],
            vec![],
        )
        .into_fixture_engine();

        let err = verify_creating_nullifier_final(&engine, pk, r)
            .expect_err("an unfinalized creating nullifier must be deferred");
        let message = err.to_string();
        assert!(message.contains("not yet final"));
        assert!(!message.contains("double-spend"));
        assert!(!message.contains("vanished"));
    }

    /// The same delivery accepted after finality demonstrates promotion by
    /// natural re-drive, without introducing a durable `Pending` receipt.
    #[test]
    fn creating_nullifier_present_and_final_is_accepted() {
        let pk = [0x11; 32];
        let r = [0x22; 32];
        let engine = StateEngine::from_persisted(
            Network::Regtest,
            0,
            6,
            0,
            vec![nullifier_entry(pk, r)],
            vec![],
        )
        .into_fixture_engine();

        assert!(verify_creating_nullifier_final(&engine, pk, r).is_ok());
    }

    /// Together with the non-final and later-final tests, this proves that a
    /// creating nullifier orphaned before finality never passes the gate: no
    /// durable insert, ACK, or live `Completed` credit is reachable for it.
    #[test]
    fn orphaned_not_final_nullifier_never_yields_live_credit() {
        let pk = [0x11; 32];
        let r = [0x22; 32];
        let engine = StateEngine::from_persisted(Network::Regtest, 0, 1, 0, vec![], vec![])
            .into_fixture_engine();

        let err = verify_creating_nullifier_final(&engine, pk, r)
            .expect_err("an orphaned creating nullifier must remain deferred");
        assert!(err
            .to_string()
            .contains("creating nullifier is not a first-occurrence on receiver NfLog"));
    }

    #[test]
    fn creating_nullifier_double_spend_loser_is_still_rejected() {
        let pk = [0x11; 32];
        let r_winner = [0x22; 32];
        let r_loser = [0x33; 32];
        let engine = StateEngine::from_persisted(
            Network::Regtest,
            0,
            6,
            0,
            vec![nullifier_entry(pk, r_winner)],
            vec![],
        )
        .into_fixture_engine();

        let err = verify_creating_nullifier_final(&engine, pk, r_loser)
            .expect_err("a double-spend loser must remain rejected");
        assert!(err
            .to_string()
            .contains("creating Pk is present with a different R (double-spend loser)"));
    }

    use crate::test_db::setup_pool;
    use shared::spec_v1::bundle::IssuanceTerms;
    use shared::spec_v1::encoding::digest_to_bytes;
    use shared::spec_v1::hashes::name_hash;
    use shared::spec_v1::tags::GENESIS_TAG;

    #[test]
    fn extract_scan_tags_requires_both() {
        let tags = vec![
            vec!["zkdt".into(), hex::encode([0xAAu8; 32])],
            vec!["zkepk".into(), hex::encode([0xBBu8; 32])],
        ];
        let (dt, epk) = extract_scan_tags(&tags).expect("both tags");
        assert_eq!(dt, [0xAA; 32]);
        assert_eq!(epk, [0xBB; 32]);
    }

    #[test]
    fn extract_scan_tags_rejects_uppercase_hex() {
        let tags = vec![
            vec!["zkdt".into(), "AA".repeat(32)],
            vec!["zkepk".into(), hex::encode([0xBB; 32])],
        ];
        let err = extract_scan_tags(&tags).expect_err("uppercase");
        assert!(matches!(err, IncomingError::ScanTags { .. }));
    }

    #[test]
    fn extract_scan_tags_missing_zkepk() {
        let tags = vec![vec!["zkdt".into(), hex::encode([0xAAu8; 32])]];
        let err = extract_scan_tags(&tags).expect_err("missing zkepk");
        assert!(matches!(err, IncomingError::ScanTags { .. }));
        let IncomingError::ScanTags { detail } = err else {
            unreachable!("expected scan tags error");
        };
        assert_eq!(detail, "missing zkepk tag");
    }

    #[test]
    fn extract_scan_tags_missing_zkdt() {
        let tags = vec![vec!["zkepk".into(), hex::encode([0xBBu8; 32])]];
        let err = extract_scan_tags(&tags).expect_err("missing zkdt");
        assert!(matches!(err, IncomingError::ScanTags { .. }));
        let IncomingError::ScanTags { detail } = err else {
            unreachable!("expected scan tags error");
        };
        assert_eq!(detail, "missing zkdt tag");
    }

    #[test]
    fn extract_scan_tags_empty_list_missing_zkdt() {
        let tags = vec![];
        let err = extract_scan_tags(&tags).expect_err("missing zkdt");
        assert!(matches!(err, IncomingError::ScanTags { .. }));
        let IncomingError::ScanTags { detail } = err else {
            unreachable!("expected scan tags error");
        };
        assert_eq!(detail, "missing zkdt tag");
    }

    #[test]
    fn extract_scan_tags_ignores_unknown_tag_when_both_present() {
        let tags = vec![
            vec!["unknown".into(), "deadbeef".into()],
            vec!["zkdt".into(), hex::encode([0xAAu8; 32])],
            vec!["zkepk".into(), hex::encode([0xBBu8; 32])],
        ];
        let (dt, epk) = extract_scan_tags(&tags).expect("both tags");
        assert_eq!(dt, [0xAA; 32]);
        assert_eq!(epk, [0xBB; 32]);
    }

    #[test]
    fn extract_scan_tags_skips_len_one_tag() {
        let tags = vec![
            vec!["zkdt".into()],
            vec!["zkdt".into(), hex::encode([0xAAu8; 32])],
            vec!["zkepk".into(), hex::encode([0xBBu8; 32])],
        ];
        let (dt, epk) = extract_scan_tags(&tags).expect("both tags");
        assert_eq!(dt, [0xAA; 32]);
        assert_eq!(epk, [0xBB; 32]);
    }

    #[test]
    fn extract_scan_tags_rejects_zkdt_len_63() {
        let tags = vec![
            vec!["zkdt".into(), "a".repeat(63)],
            vec!["zkepk".into(), hex::encode([0xBBu8; 32])],
        ];
        let err = extract_scan_tags(&tags).expect_err("zkdt length 63");
        assert!(matches!(err, IncomingError::ScanTags { .. }));
        let IncomingError::ScanTags { detail } = err else {
            unreachable!("expected scan tags error");
        };
        assert_eq!(detail, "zkdt must be 64 lowercase hex chars");
    }

    #[test]
    fn extract_scan_tags_rejects_zkepk_short_aaa() {
        let tags = vec![
            vec!["zkdt".into(), hex::encode([0xAAu8; 32])],
            vec!["zkepk".into(), "aaa".into()],
        ];
        let err = extract_scan_tags(&tags).expect_err("short zkepk");
        assert!(matches!(err, IncomingError::ScanTags { .. }));
        let IncomingError::ScanTags { detail } = err else {
            unreachable!("expected scan tags error");
        };
        assert_eq!(detail, "zkepk must be 64 lowercase hex chars");
    }

    #[test]
    fn extract_scan_tags_last_zkdt_wins() {
        let tags = vec![
            vec!["zkdt".into(), hex::encode([0xAAu8; 32])],
            vec!["zkdt".into(), hex::encode([0xCCu8; 32])],
            vec!["zkepk".into(), hex::encode([0xBBu8; 32])],
        ];
        let (dt, epk) = extract_scan_tags(&tags).expect("both tags");
        assert_eq!(dt, [0xCC; 32]);
        assert_eq!(epk, [0xBB; 32]);
    }

    #[test]
    fn extract_scan_tags_last_zkepk_wins() {
        let tags = vec![
            vec!["zkdt".into(), hex::encode([0xAAu8; 32])],
            vec!["zkepk".into(), hex::encode([0xBBu8; 32])],
            vec!["zkepk".into(), hex::encode([0xDDu8; 32])],
        ];
        let (dt, epk) = extract_scan_tags(&tags).expect("both tags");
        assert_eq!(dt, [0xAA; 32]);
        assert_eq!(epk, [0xDD; 32]);
    }

    #[test]
    fn extract_scan_tags_skips_empty_inner_tag() {
        let tags = vec![
            vec![],
            vec!["zkdt".into(), hex::encode([0xAAu8; 32])],
            vec!["zkepk".into(), hex::encode([0xBBu8; 32])],
        ];
        let (dt, epk) = extract_scan_tags(&tags).expect("both tags");
        assert_eq!(dt, [0xAA; 32]);
        assert_eq!(epk, [0xBB; 32]);
    }

    #[test]
    fn match_detect_tag_honest_roundtrip() {
        use shared::spec_v1::note_encryption::{shared_secret_sender, xonly_pubkey};
        let ivk = {
            // Valid scalar from fixed seed.
            let mut s = [0u8; 32];
            s[31] = 7;
            s
        };
        let esk = {
            let mut s = [0u8; 32];
            s[31] = 9;
            s
        };
        let ivpk = xonly_pubkey(&ivk).expect("ivpk");
        let epk = xonly_pubkey(&esk).expect("epk");
        let ss_s = shared_secret_sender(&esk, &ivpk).expect("ss sender");
        let ss_r = shared_secret_receiver(&ivk, &epk).expect("ss receiver");
        assert_eq!(ss_s, ss_r);
        let tag = digest_to_bytes(&poseidon_detect_tag(&ss_r, &epk));
        let (ss2, tag2) = match_detect_tag(&ivk, &tag, &epk).expect("match");
        assert_eq!(ss2, ss_r);
        assert_eq!(tag2, tag);
    }

    #[test]
    fn match_detect_tag_rejects_wrong_tag() {
        let ivk = {
            let mut s = [0u8; 32];
            s[31] = 7;
            s
        };
        let epk = xonly_pubkey(&{
            let mut s = [0u8; 32];
            s[31] = 9;
            s
        })
        .expect("epk");
        let err = match_detect_tag(&ivk, &[0xFF; 32], &epk).expect_err("wrong tag");
        assert!(matches!(err, IncomingError::DetectTagMismatch { .. }));
    }

    #[test]
    fn asset_terms_v1_self_auth_accepts_and_rejects() {
        let name = b"USD-Demo";
        let nh = name_hash(name).expect("name");
        let creator = [0x11u8; 32];
        let id = asset_id_v1(GENESIS_TAG, &creator, &nh, 2, 1);
        let terms = IssuanceTerms {
            creator_pubkey: creator,
            decimals: 2,
            issuance_version: 1,
            name: name.to_vec(),
            cap_total: None,
            terms_salt: None,
        };
        verify_asset_terms_self_auth(id, &terms).expect("honest terms");
        let mut bad = terms.clone();
        bad.decimals = 3;
        let err = verify_asset_terms_self_auth(id, &bad).expect_err("wrong decimals");
        assert_eq!(
            err,
            IncomingError::Verification(
                "asset_terms self-auth failed: recomputed asset_id ≠ coin.asset_id".into(),
            ),
        );
    }

    #[test]
    fn asset_terms_unknown_version_refuses_bundle() {
        let terms = IssuanceTerms {
            creator_pubkey: [0x11u8; 32],
            decimals: 2,
            issuance_version: 9,
            name: b"x".to_vec(),
            cap_total: None,
            terms_salt: None,
        };
        let err = verify_asset_terms_self_auth(shared::spec_v1::ZERO_HASH, &terms).expect_err("v9");
        assert_eq!(
            err,
            IncomingError::Verification(
                "asset_terms issuance_version 9 is neither 1 nor 2 — refuse whole bundle".into(),
            ),
        );
    }

    #[test]
    fn asset_terms_v1_rejects_cap_total() {
        let name = b"USD-Demo";
        let nh = name_hash(name).expect("name");
        let creator = [0x11u8; 32];
        let id = asset_id_v1(GENESIS_TAG, &creator, &nh, 2, 1);
        let terms = IssuanceTerms {
            creator_pubkey: creator,
            decimals: 2,
            issuance_version: 1,
            name: name.to_vec(),
            cap_total: Some(1),
            terms_salt: None,
        };
        let err = verify_asset_terms_self_auth(id, &terms).expect_err("v1 with cap_total");
        assert_eq!(
            err,
            IncomingError::Verification(
                "asset_terms v1 must not carry cap_total/terms_salt".into(),
            ),
        );
    }

    #[test]
    fn asset_terms_v1_rejects_terms_salt() {
        let name = b"USD-Demo";
        let nh = name_hash(name).expect("name");
        let creator = [0x11u8; 32];
        let id = asset_id_v1(GENESIS_TAG, &creator, &nh, 2, 1);
        let terms = IssuanceTerms {
            creator_pubkey: creator,
            decimals: 2,
            issuance_version: 1,
            name: name.to_vec(),
            cap_total: None,
            terms_salt: Some([0xAB; 32]),
        };
        let err = verify_asset_terms_self_auth(id, &terms).expect_err("v1 with terms_salt");
        assert_eq!(
            err,
            IncomingError::Verification(
                "asset_terms v1 must not carry cap_total/terms_salt".into(),
            ),
        );
    }

    #[test]
    fn asset_terms_v2_accepts_honest() {
        let name = b"USD-Demo";
        let nh = name_hash(name).expect("name");
        let creator = [0x11u8; 32];
        let id = asset_id_v2(GENESIS_TAG, &creator, &nh, 2, 2, 1_000_000u128, &[0xCD; 32]);
        let terms = IssuanceTerms {
            creator_pubkey: creator,
            decimals: 2,
            issuance_version: 2,
            name: name.to_vec(),
            cap_total: Some(1_000_000u128),
            terms_salt: Some([0xCD; 32]),
        };
        verify_asset_terms_self_auth(id, &terms).expect("honest v2 terms");
    }

    #[test]
    fn asset_terms_v2_missing_cap_total() {
        let terms = IssuanceTerms {
            creator_pubkey: [0x11u8; 32],
            decimals: 2,
            issuance_version: 2,
            name: b"USD-Demo".to_vec(),
            cap_total: None,
            terms_salt: Some([0xCD; 32]),
        };
        let err = verify_asset_terms_self_auth(shared::spec_v1::ZERO_HASH, &terms)
            .expect_err("v2 missing cap_total");
        assert_eq!(
            err,
            IncomingError::Verification("asset_terms v2 missing cap_total".into()),
        );
    }

    #[test]
    fn asset_terms_v2_missing_terms_salt() {
        let terms = IssuanceTerms {
            creator_pubkey: [0x11u8; 32],
            decimals: 2,
            issuance_version: 2,
            name: b"USD-Demo".to_vec(),
            cap_total: Some(1),
            terms_salt: None,
        };
        let err = verify_asset_terms_self_auth(shared::spec_v1::ZERO_HASH, &terms)
            .expect_err("v2 missing terms_salt");
        assert_eq!(
            err,
            IncomingError::Verification("asset_terms v2 missing terms_salt".into()),
        );
    }

    #[test]
    fn asset_terms_v2_self_auth_rejects_mismatch() {
        let name = b"USD-Demo";
        let creator = [0x11u8; 32];
        let terms = IssuanceTerms {
            creator_pubkey: creator,
            decimals: 2,
            issuance_version: 2,
            name: name.to_vec(),
            cap_total: Some(1_000_000u128),
            terms_salt: Some([0xCD; 32]),
        };
        let err = verify_asset_terms_self_auth(shared::spec_v1::ZERO_HASH, &terms)
            .expect_err("v2 mismatch");
        assert_eq!(
            err,
            IncomingError::Verification(
                "asset_terms self-auth failed: recomputed asset_id ≠ coin.asset_id".into(),
            ),
        );
    }

    #[test]
    fn asset_terms_name_too_long_is_verification() {
        let terms = IssuanceTerms {
            creator_pubkey: [0x11u8; 32],
            decimals: 2,
            issuance_version: 1,
            name: vec![b'x'; 256],
            cap_total: None,
            terms_salt: None,
        };
        let err = verify_asset_terms_self_auth(shared::spec_v1::ZERO_HASH, &terms)
            .expect_err("name too long");
        assert_eq!(
            err,
            IncomingError::Verification(
                "asset_terms name_hash: asset name too long: 256 bytes (max 255)".into(),
            ),
        );
    }

    #[test]
    fn inclusion_proof_wire_roundtrip_depth0() {
        // leaf_index=0, depth=0, no siblings — exact 5-byte wire, no mutation.
        let wire = vec![0u8, 0, 0, 0, 0];
        let p = parse_inclusion_proof_wire(&wire).expect("parse");
        assert_eq!(p.leaf_index, 0);
        assert_eq!(p.depth, 0);
        assert!(p.siblings.is_empty());
    }

    #[test]
    fn inclusion_proof_wire_rejects_truncated_prefix() {
        let err = parse_inclusion_proof_wire(&[0u8; 4])
            .expect_err("truncated inclusion proof must be rejected");

        assert_eq!(
            err,
            IncomingError::Verification(
                "inclusion_proof truncated (need leaf_index + depth)".into(),
            ),
        );
    }

    #[test]
    fn inclusion_proof_wire_rejects_depth_above_max() {
        let bytes = vec![0, 0, 0, 0, (MAX_OUTPUT_MERKLE_DEPTH as u8) + 1];
        let err = parse_inclusion_proof_wire(&bytes)
            .expect_err("inclusion proof depth above the maximum must be rejected");

        assert_eq!(
            err,
            IncomingError::Verification(format!(
                "inclusion_proof depth {} exceeds MAX_OUTPUT_MERKLE_DEPTH",
                (MAX_OUTPUT_MERKLE_DEPTH as u8) + 1
            )),
        );
    }

    #[test]
    fn inclusion_proof_wire_rejects_extra_byte_at_depth0() {
        let bytes = vec![0u8, 0, 0, 0, 0, 0xff];
        let err = parse_inclusion_proof_wire(&bytes).expect_err("extra byte must be rejected");
        assert_eq!(
            err,
            IncomingError::Verification("inclusion_proof length 6 ≠ expected 5 for depth 0".into()),
        );
    }

    #[test]
    fn inclusion_proof_wire_rejects_length_mismatch() {
        let bytes = vec![0, 0, 0, 0, 1];
        let err = parse_inclusion_proof_wire(&bytes)
            .expect_err("inclusion proof with mismatched length must be rejected");

        assert_eq!(
            err,
            IncomingError::Verification(
                "inclusion_proof length 5 ≠ expected 37 for depth 1".into(),
            ),
        );
    }

    #[test]
    fn inclusion_proof_wire_rejects_noncanonical_sibling() {
        use plonky2::field::types::Field64;
        use zkcoins_program::F;

        let mut bytes = vec![0, 0, 0, 0, 1];
        bytes.extend_from_slice(&F::ORDER.to_be_bytes());
        bytes.extend_from_slice(&[0u8; 24]);

        let err = parse_inclusion_proof_wire(&bytes)
            .expect_err("non-canonical sibling digest must be rejected");
        assert_eq!(
            err,
            IncomingError::Verification(format!(
                "non-canonical digest limb 0: {:#x} >= p (GoldilocksField::ORDER)",
                F::ORDER
            )),
        );
    }

    #[test]
    fn inclusion_proof_wire_rejects_extra_byte_at_depth1() {
        let mut bytes = vec![0, 0, 0, 0, 1];
        bytes.extend_from_slice(&[0x11u8; 32]);
        bytes.push(0xff);
        let err = parse_inclusion_proof_wire(&bytes)
            .expect_err("extra byte at depth 1 must be rejected");
        assert_eq!(
            err,
            IncomingError::Verification(
                "inclusion_proof length 38 ≠ expected 37 for depth 1".into(),
            ),
        );
    }

    #[test]
    fn inclusion_proof_wire_roundtrip_depth1() {
        let mut bytes = Vec::with_capacity(37);
        bytes.extend_from_slice(&7u32.to_be_bytes());
        bytes.push(1);
        bytes.extend_from_slice(&[0x11u8; 32]);

        let p = parse_inclusion_proof_wire(&bytes).expect("depth-1 inclusion proof must parse");
        assert_eq!(p.leaf_index, 7);
        assert_eq!(p.depth, 1);
        assert_eq!(p.siblings.len(), 1);
        assert_eq!(digest_to_bytes(&p.siblings[0]), [0x11u8; 32]);
    }

    #[test]
    fn holder_outcome_display_names_content_address_lie() {
        let o = HolderOutcome::ContentAddressLie {
            expected: [0x01; 32],
            actual: [0x02; 32],
        };
        let s = o.to_string();
        assert!(s.contains("CONTENT_ADDRESS_LIE"), "{s}");
        assert!(s.contains(&hex::encode([0x01; 32])));
        assert!(s.contains(&hex::encode([0x02; 32])));
    }

    #[test]
    fn holder_outcome_display_names_fetch_error() {
        let o = HolderOutcome::FetchError {
            message: "holder https://example.invalid/ returned 404".into(),
        };
        assert_eq!(
            o.to_string(),
            "fetch_error: holder https://example.invalid/ returned 404",
        );
    }

    #[test]
    fn holder_outcome_display_names_ok() {
        let o = HolderOutcome::Ok { body_len: 64 };
        assert_eq!(o.to_string(), "ok body_len=64");
    }

    #[test]
    fn incoming_error_holders_empty_display_names_cause() {
        assert_eq!(
            IncomingError::HoldersEmpty.to_string(),
            "no advertised or manifest blob holders configured",
        );
    }

    #[test]
    fn incoming_error_all_holders_failed_names_each_attempt() {
        let err = IncomingError::AllHoldersFailed {
            attempts: vec![
                HolderAttempt {
                    holder: "https://a.example.invalid/".into(),
                    outcome: HolderOutcome::FetchError {
                        message: "404".into(),
                    },
                },
                HolderAttempt {
                    holder: "https://b.example.invalid/".into(),
                    outcome: HolderOutcome::ContentAddressLie {
                        expected: [0x01; 32],
                        actual: [0x02; 32],
                    },
                },
            ],
        };
        let s = err.to_string();
        assert_eq!(
            s,
            format!(
                concat!(
                    "all 2 holders failed: ",
                    "[https://a.example.invalid/ → fetch_error: 404] ",
                    "[https://b.example.invalid/ → CONTENT_ADDRESS_LIE expected={} actual={}]",
                ),
                hex::encode([0x01; 32]),
                hex::encode([0x02; 32]),
            ),
        );
    }

    #[test]
    fn incoming_error_scan_tags_display_names_detail() {
        let err = IncomingError::ScanTags {
            detail: "missing zkepk tag".into(),
        };
        assert_eq!(err.to_string(), "scan tags: missing zkepk tag");
    }

    #[test]
    fn incoming_error_detect_tag_mismatch_display_names_both_digests() {
        let err = IncomingError::DetectTagMismatch {
            claimed: [0xAA; 32],
            recomputed: [0xBB; 32],
        };
        assert_eq!(
            err.to_string(),
            format!(
                "detect_tag mismatch: claimed={}, recomputed={}",
                hex::encode([0xAA; 32]),
                hex::encode([0xBB; 32]),
            ),
        );
    }

    #[test]
    fn incoming_error_nip59_display_names_cause() {
        let err = IncomingError::Nip59("bad mac".into());
        assert_eq!(err.to_string(), "NIP-59 unwrap: bad mac");
    }

    #[test]
    fn incoming_error_seal_author_mismatch_display_names_both_keys() {
        let err = IncomingError::SealAuthorMismatch {
            seal_pubkey: [0x11; 32],
            rumor_pubkey: [0x22; 32],
        };
        assert_eq!(
            err.to_string(),
            format!(
                "seal author {} ≠ rumor pubkey {} (forged sender)",
                hex::encode([0x11; 32]),
                hex::encode([0x22; 32]),
            ),
        );
    }

    #[test]
    fn incoming_error_payload_display_names_cause() {
        let err = IncomingError::Payload("truncated rumor".into());
        assert_eq!(err.to_string(), "delivery payload: truncated rumor");
    }

    #[test]
    fn incoming_error_ack_destination_display_names_detail() {
        let err = IncomingError::AckDestination {
            detail: "no sender ivpk".into(),
        };
        assert_eq!(err.to_string(), "ACK destination: no sender ivpk");
    }

    #[test]
    fn incoming_error_ack_send_display_names_detail() {
        let err = IncomingError::AckSend {
            detail: "wrap failed".into(),
        };
        assert_eq!(err.to_string(), "ACK send: wrap failed");
    }

    #[test]
    fn incoming_error_relay_display_names_cause() {
        let err = IncomingError::Relay("empty relay list".into());
        assert_eq!(err.to_string(), "relay: empty relay list");
    }

    #[test]
    fn decrypt_record_id_is_stable() {
        let a = decrypt_record_id(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        let b = decrypt_record_id(&[1u8; 32], &[2u8; 32], &[3u8; 32]);
        assert_eq!(a, b);
        let c = decrypt_record_id(&[1u8; 32], &[2u8; 32], &[4u8; 32]);
        assert_ne!(a, c);
    }

    fn persistence_test_row(asset_id: [u8; 32], seed: u8) -> DecryptIndexRow {
        let subject = [seed; 32];
        let coin_id = [seed + 1; 32];
        let blob_id = [seed + 2; 32];
        DecryptIndexRow {
            record_id: decrypt_record_id(&subject, &coin_id, &blob_id),
            subject,
            coin_id,
            blob_id,
            detect_tag: [seed + 3; 32],
            canonical: vec![seed + 4],
            asset_id,
            verification_status: DecryptVerificationStatus::Verified,
            delivery_event_id: [seed + 5; 32],
            ack_nonce: [seed + 6; 32],
            occurred_at: 0,
        }
    }

    #[tokio::test]
    #[ignore = "heavy: real Plonky2 prove; run with --ignored --release"]
    async fn store_and_ack_finality_gate_blocks_credit_until_final() {
        use crate::kernel::grants::{GrantAssetScope, GrantScope, SCOPE_NOT_AFTER_UNBOUNDED};
        use crate::v1::delivery::{
            build_coin_delivery, bundle_nav_opening, creating_nullifier_from_parts,
            OutgoingCoinMaterial,
        };
        use crate::v1::separation::{claim_stack_scan_mode, set_process_stack_mode, ScanStackMode};
        use futures_util::StreamExt as _;
        use shared::spec_v1::datastructures::Address;
        use std::time::Duration;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};
        use zkcoins_prover::prover_bridge::test_signing::{
            deterministic_secret, normalized_key, sign_transition,
        };
        use zkcoins_prover::state_engine::{MintRequest, OpSecret, ScannedNullifier, SendRequest};

        set_process_stack_mode(ScanStackMode::V1);
        let scope = setup_pool().await;
        claim_stack_scan_mode(&scope.pool, ScanStackMode::V1)
            .await
            .expect("claim v1 stack mode for incoming pipeline fixture");
        let adapter = EngineAdapter::load_or_create(scope.pool.clone(), Network::Regtest, 0)
            .await
            .expect("load incoming pipeline engine adapter");

        let alice_nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/incoming-finality/alice-nk").into();
        let (alice_secret0, alice_public0, alice_pk0) = normalized_key(deterministic_secret(
            b"zkCoins/v1/incoming-finality/alice-sk0",
        ));
        let (_, _, alice_pk1) = normalized_key(deterministic_secret(
            b"zkCoins/v1/incoming-finality/alice-sk1",
        ));
        let alice_owner = Address(host::address(&alice_pk0, host::nk_commit(&alice_nk)));
        let mint_name_hash = host::name_hash(b"incoming finality asset").expect("mint name hash");
        let mint_asset_id = host::asset_id_v1(host::GENESIS_TAG, &alice_pk0, &mint_name_hash, 2, 1);
        let mint_pending = adapter
            .with_engine(|engine| {
                engine.begin_mint(MintRequest {
                    owner: alice_owner,
                    nk: alice_nk,
                    op_secret: OpSecret::new(
                        Sha256::digest(b"zkCoins/v1/incoming-finality/alice-op-secret").into(),
                    ),
                    current_pubkey: alice_pk0,
                    next_pubkey: alice_pk1,
                    name: b"incoming finality asset".to_vec(),
                    decimals: 2,
                    amount: 100,
                    issuance_version: 1,
                    cap_total: 0,
                    terms_salt: [0u8; 32],
                    output_templates: vec![host::CoinTemplate {
                        recipient: alice_owner,
                        amount: 100,
                        asset_id: mint_asset_id,
                    }],
                    npk_rand: [0x22; 32],
                })
            })
            .expect("begin genuine mint");
        let minted_coin_id = mint_pending
            .witness_wip
            .output_coins
            .first()
            .expect("mint output")
            .identifier;
        let mint_sig = sign_transition(
            alice_secret0,
            alice_public0,
            &mint_pending.proof_data,
            Network::Regtest,
        );
        let applied_mint = adapter
            .with_engine_mut(|engine| {
                engine
                    .finalise(mint_pending, mint_sig.transition)
                    .expect("prove and finalise mint")
            })
            .expect("apply mint");
        adapter
            .with_engine_mut(|engine| {
                engine
                    .append_nullifier(ScannedNullifier::from_survivor(
                        &shared::spec_v1::PublishedNullifier {
                            chain_pos: host::ChainPosition {
                                height: 100,
                                tx_index: 0,
                                vin_index: 0,
                                member_index: 0,
                            },
                            pk: applied_mint.nullifier().0,
                            r: applied_mint.nullifier().1,
                        },
                    ))
                    .expect("fold mint nullifier");
                engine.set_tip_height(110);
            })
            .expect("prepare final mint anchor");

        let (alice_secret1, alice_public1, alice_pk1_check) = normalized_key(deterministic_secret(
            b"zkCoins/v1/incoming-finality/alice-sk1",
        ));
        assert_eq!(alice_pk1_check, alice_pk1);
        let (_, _, alice_pk2) = normalized_key(deterministic_secret(
            b"zkCoins/v1/incoming-finality/alice-sk2",
        ));
        let bob_nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/incoming-finality/bob-nk").into();
        let (_, _, bob_pk0) = normalized_key(deterministic_secret(
            b"zkCoins/v1/incoming-finality/bob-sk0",
        ));
        let bob_owner = Address(host::address(&bob_pk0, host::nk_commit(&bob_nk)));

        let send_pending = adapter
            .with_engine(|engine| {
                engine.begin_send(SendRequest {
                    owner: alice_owner,
                    input_coin_ids: vec![minted_coin_id],
                    output_templates: vec![host::CoinTemplate {
                        recipient: bob_owner,
                        amount: 30,
                        asset_id: mint_asset_id,
                    }],
                    next_pubkey: alice_pk2,
                    npk_rand: [0xA5; 32],
                })
            })
            .expect("begin genuine send");
        let bob_coin = send_pending
            .witness_wip
            .output_coins
            .iter()
            .find(|coin| coin.recipient == bob_owner)
            .cloned()
            .expect("Bob output coin");
        let bob_coin_index = send_pending
            .witness_wip
            .output_coins
            .iter()
            .position(|coin| coin.recipient == bob_owner)
            .expect("Bob output index") as u32;
        let all_output_ids = send_pending
            .witness_wip
            .output_coins
            .iter()
            .map(|coin| coin.identifier)
            .collect::<Vec<_>>();
        let creating_prev_ash =
            host::account_state_hash(&send_pending.witness_wip.prev_account_state)
                .expect("send creating_prev_ash");
        let send_nav_opening = send_pending.nav_opening;
        let send_sig = sign_transition(
            alice_secret1,
            alice_public1,
            &send_pending.proof_data,
            Network::Regtest,
        );
        let send_r_prime = send_sig.transition.r_prime;
        let applied_send = adapter
            .with_engine_mut(|engine| {
                engine
                    .finalise(send_pending, send_sig.transition)
                    .expect("prove and finalise send")
            })
            .expect("apply send");
        let send_nullifier = applied_send.nullifier();
        adapter
            .with_engine_mut(|engine| {
                let position = engine
                    .append_nullifier(ScannedNullifier::from_survivor(
                        &shared::spec_v1::PublishedNullifier {
                            chain_pos: host::ChainPosition {
                                height: 110,
                                tx_index: 1,
                                vin_index: 0,
                                member_index: 0,
                            },
                            pk: send_nullifier.0,
                            r: send_nullifier.1,
                        },
                    ))
                    .expect("fold send nullifier");
                assert_eq!(position, 1, "send must be the second NfLog entry");
                engine.set_tip_height(114);
                assert_eq!(engine.nflog().size_final(engine.tip_height()), 1);
            })
            .expect("prepare non-final send anchor");

        let blob_store = MockServer::start().await;
        let (sender_op, _) = pipeline_fixture_sk(b"zkCoins/v1/incoming-finality/sender-op");
        let (recipient_ivk, recipient_ivpk) =
            pipeline_fixture_sk(b"zkCoins/v1/incoming-finality/recipient-ivk");
        let (recipient_op, recipient_op_pk) =
            pipeline_fixture_sk(b"zkCoins/v1/incoming-finality/recipient-op");
        let (ovk, _) = pipeline_fixture_sk(b"zkCoins/v1/incoming-finality/ovk");
        let expected_coin_id = digest_to_bytes(&bob_coin.identifier);
        let expected_asset_id = digest_to_bytes(&bob_coin.asset_id);
        let expected_amount = bob_coin.amount;
        let material = OutgoingCoinMaterial {
            coin: bob_coin,
            leaf_index: bob_coin_index,
            all_output_ids,
            proof_bytes: applied_send.proved().proof.to_bytes(),
            creating_prev_ash,
            creating_nullifier: creating_nullifier_from_parts(
                send_nullifier.0,
                send_nullifier.1,
                send_r_prime,
            ),
            nav_opening: bundle_nav_opening(
                send_nav_opening.nav.size,
                send_nav_opening.nav.mth,
                send_nav_opening.nav_rand,
            ),
            asset_terms: None,
            recipient_ivpk,
            recipient_op_pk,
            recipient_relays: vec!["ws://127.0.0.1:9/".into()],
        };
        let now = 1_700_000_000;
        let mut build_rng = PipelineRng::new(b"zkCoins/v1/incoming-finality/build-delivery");
        let built = build_coin_delivery(
            &material,
            &sender_op,
            &ovk,
            &[blob_store.uri()],
            now,
            &mut build_rng,
        )
        .expect("build genuine incoming delivery");
        Mock::given(method("GET"))
            .and(path(format!("/blossom/{}", hex::encode(built.blob_id))))
            .respond_with(
                ResponseTemplate::new(200)
                    .insert_header("content-type", "application/octet-stream")
                    .set_body_bytes(built.zbe_ciphertext.clone()),
            )
            .expect(2)
            .mount(&blob_store)
            .await;

        let index = InMemoryPrivateIndex::new();
        let receipts = ReceiptHub::new();
        let mut receipt_stream = receipts.subscribe(
            SubjectAddress(bob_owner.0),
            GrantScope {
                assets: GrantAssetScope::All,
                not_before: 0,
                not_after: SCOPE_NOT_AFTER_UNBOUNDED,
            },
        );
        let mut first_ack_rng = PipelineRng::new(b"zkCoins/v1/incoming-finality/non-final-ack");
        let first = process_delivery_candidate(
            &built.gift_wrap,
            CandidateSecrets {
                subject: &bob_owner.0,
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
                manifest_blob_stores: &[],
                discovery_relays: &[],
                expected_network: "regtest",
            },
            AckClock {
                now,
                rng: &mut first_ack_rng,
            },
        )
        .await;
        let CandidateOutcome::Rejected { error } = first else {
            panic!("non-final delivery must be rejected by the real pipeline: {first:?}");
        };
        assert!(
            error.to_string().contains("not yet final"),
            "unexpected non-final rejection: {error}"
        );
        assert!(
            get_by_blob_id(&scope.pool, &built.blob_id)
                .await
                .expect("query non-final durable row")
                .is_none(),
            "non-final delivery must not be persisted"
        );
        let idle = tokio::time::timeout(Duration::from_millis(30), receipt_stream.next()).await;
        assert!(
            idle.is_err(),
            "non-final delivery must not publish a Completed receipt: {idle:?}"
        );

        adapter
            .with_engine_mut(|engine| {
                engine.set_tip_height(115);
                assert_eq!(engine.nflog().size_final(engine.tip_height()), 2);
            })
            .expect("advance creating nullifier through finality");

        // Holding the same gate as the scanner makes the production
        // candidate wait before verification/persist. Removing the F2 gate
        // would let this warmed second attempt complete and credit here.
        let held_write_gate = adapter.lock_writes().await;
        let mut final_ack_rng = PipelineRng::new(b"zkCoins/v1/incoming-finality/final-ack");
        let mut final_attempt = Box::pin(process_delivery_candidate(
            &built.gift_wrap,
            CandidateSecrets {
                subject: &bob_owner.0,
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
                manifest_blob_stores: &[],
                discovery_relays: &[],
                expected_network: "regtest",
            },
            AckClock {
                now,
                rng: &mut final_ack_rng,
            },
        ));
        let blocked = tokio::time::timeout(Duration::from_secs(10), &mut final_attempt).await;
        assert!(
            blocked.is_err(),
            "candidate bypassed the scanner write gate: {blocked:?}"
        );
        assert!(
            get_by_blob_id(&scope.pool, &built.blob_id)
                .await
                .expect("query write-gated durable row")
                .is_none(),
            "write-gated candidate must not persist before the gate is released"
        );
        let idle = tokio::time::timeout(Duration::from_millis(30), receipt_stream.next()).await;
        assert!(
            idle.is_err(),
            "write-gated candidate must not publish before durable persist: {idle:?}"
        );
        drop(held_write_gate);

        // Empty discovery relays deliberately make the later ACK stage fail;
        // durable insert and receipt publication precede that expected error.
        let _final_outcome = final_attempt.await;
        let stored = get_by_blob_id(&scope.pool, &built.blob_id)
            .await
            .expect("query final durable row")
            .expect("final delivery must be durably inserted");
        assert_eq!(stored.coin_id, expected_coin_id);
        assert_eq!(stored.asset_id, expected_asset_id);
        let receipt = tokio::time::timeout(Duration::from_secs(1), receipt_stream.next())
            .await
            .expect("final receipt timeout")
            .expect("final receipt stream ended")
            .expect("final receipt error");
        assert_eq!(receipt.subject, SubjectAddress(bob_owner.0));
        assert_eq!(receipt.coin_id, Digest32(expected_coin_id));
        assert_eq!(receipt.asset_id, Digest32(expected_asset_id));
        assert_eq!(receipt.amount, expected_amount);
        assert_eq!(receipt.state, ReceiptState::Completed);
    }

    #[tokio::test]
    async fn receive_persist_with_no_asset_terms_keeps_coin_opaque() {
        let scope = setup_pool().await;
        let asset_id = [0x71; 32];
        let row = persistence_test_row(asset_id, 0x10);

        assert_eq!(
            persist_verified_coin_and_provenance(&scope.pool, &row, None)
                .await
                .expect("persist opaque received CoinProof"),
            InsertRecordOutcome::Inserted
        );
        assert!(get_by_blob_id(&scope.pool, &row.blob_id)
            .await
            .expect("load durable CoinProof")
            .is_some());
        assert_eq!(
            super::super::db_token_provenance::get_token_provenance(&scope.pool, &asset_id)
                .await
                .expect("lookup absent provenance"),
            None
        );
    }

    #[tokio::test]
    async fn receive_persist_commits_verified_coin_and_terms_together() {
        let scope = setup_pool().await;
        let terms = IssuanceTerms {
            creator_pubkey: [0x31; 32],
            decimals: 3,
            issuance_version: 1,
            name: b"atomic".to_vec(),
            cap_total: None,
            terms_salt: None,
        };
        let name_hash = name_hash(&terms.name).expect("test name");
        let asset_id = digest_to_bytes(&asset_id_v1(
            GENESIS_TAG,
            &terms.creator_pubkey,
            &name_hash,
            terms.decimals,
            terms.issuance_version,
        ));
        let row = persistence_test_row(asset_id, 0x20);

        persist_verified_coin_and_provenance(&scope.pool, &row, Some(&terms))
            .await
            .expect("atomic received persist");
        assert!(get_by_blob_id(&scope.pool, &row.blob_id)
            .await
            .expect("load durable CoinProof")
            .is_some());
        assert_eq!(
            super::super::db_token_provenance::get_token_provenance(&scope.pool, &asset_id)
                .await
                .expect("load durable terms"),
            Some(terms)
        );
    }

    #[tokio::test]
    async fn fetch_blob_from_holders_empty_list_is_holders_empty() {
        let client = BlossomClient::new(1024).expect("reqwest client");
        let blob_id = [0u8; 32];
        let holders: &[String] = &[];

        let err = fetch_blob_from_holders(&client, &blob_id, holders)
            .await
            .expect_err("empty holders must fail before HTTP");

        assert!(matches!(err, IncomingError::HoldersEmpty));
    }
}
