//! Bundle wire codecs: `CoinProof`, `SelfDeliveryRecordV1`, `BlobLocatorSet` (§7.1).
//!
//! These layouts are the **content-addressed plaintexts** that ZBE encrypts
//! ([§4.2.1](https://docs.zkcoins.app)): `blob_id = H(ZBE(serialize(bundle)))`.
//! The rules below fix **exactly one** byte string per value so two honest
//! senders of the same bundle under the same key produce the same `blob_id`.
//!
//! # Stored-field discipline (`ciphertext` / `out_ciphertext`)
//!
//! Same rule as [`super::note_encryption`]: wire `ciphertext` and
//! `out_ciphertext` store the **UTF-8 of NIP-44's Base64 AEAD payload** from
//! `NIP44Binary(...)`, never the decoded AEAD raw bytes and never the binary
//! plaintext. The codec treats them as opaque length-prefixed byte strings.
//!
//! # `BlobLocatorSet` and `blob_id`
//!
//! [`BlobLocatorSet`] carries **only ordered holder base-URLs**. The 32-byte
//! `blob_id` is **context beside the set** (delivery payload, `output_ref`,
//! self-delivery content address, publisher fee hand-off) — never a field of
//! the set. Putting `blob_id` into the set would break the §4.3 privacy
//! boundary (holder hints must not become a public blob directory).

use super::datastructures::{AccountState, Coin, ProofData};
use super::encoding::{digest_from_bytes, digest_to_bytes};
use super::error::SpecError;
use super::serialize::{
    deserialize_coin, deserialize_proof_data, parse_account_state, serialize_account_state,
    serialize_coin, serialize_proof_data,
};
use zkcoins_program::hash::HashDigest;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// ASCII magic of `serialize(SelfDeliveryRecordV1)`.
pub const SDR1_MAGIC: &[u8; 4] = b"SDR1";
/// Sole accepted SDR version byte.
pub const SDR1_VERSION: u8 = 0x01;

/// §7.1 upper bound on `BlobLocatorSet` holder count.
pub const MAX_BLOB_HOLDERS: usize = 16;
/// §7.1 upper bound on a single holder base-URL length (bytes).
pub const MAX_HOLDER_URL_LEN: usize = 2048;
/// §1.5 / §7.1 upper bound on `asset_terms.name` (bytes).
pub const MAX_ASSET_NAME_LEN: usize = 255;

/// `serialize(Coin)` fixed width (§1.5 / §1.7.3).
pub const COIN_WIRE_LEN: usize = 112;
/// `serialize(ProofData)` fixed width (§1.4).
pub const PROOF_DATA_WIRE_LEN: usize = 192;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Creating transition's on-chain nullifier triple (§1.5 / §7.1).
///
/// Wire: `Pk_create (32) ‖ R_create (32) ‖ R'_create (32)` — no extra framing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CreatingNullifier {
    pub pk_create: [u8; 32],
    pub r_create: [u8; 32],
    pub r_prime_create: [u8; 32],
}

/// Conditional-NAV opening carried in a `CoinProof` (§1.5 / §7.1).
///
/// Wire: `size (8, u64 be) ‖ mth (32) ‖ nav_rand (32)`.
/// `nav = (size, mth)`; `nav_root = Hc("NfLog/Root", size ‖ mth)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NavOpening {
    pub size: u64,
    pub mth: HashDigest,
    pub nav_rand: [u8; 32],
}

/// Optional plaintext `IssuanceTerms` of `coin.asset_id` (§1.5 / §6.5 / §7.1).
///
/// `name` is a **raw byte string** — UTF-8 validity is display-only. At most
/// [`MAX_ASSET_NAME_LEN`] bytes.
///
/// Version-dispatched trailing fields:
/// - `issuance_version == 1` → `cap_total` and `terms_salt` **must both be
///   `None`**
/// - `issuance_version == 2` → both **must be `Some`**
/// - any other version → malformed
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuanceTerms {
    pub creator_pubkey: [u8; 32],
    pub decimals: u8,
    pub issuance_version: u8,
    pub name: Vec<u8>,
    pub cap_total: Option<u128>,
    pub terms_salt: Option<[u8; 32]>,
}

/// Value-bearing off-chain bundle (§1.5), length-prefixed per §7.1.
///
/// Field order is declaration order. `proof` / `inclusion_proof` /
/// `ciphertext` are opaque byte strings (no Plonky2 parse here).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoinProof {
    pub coin: Coin,
    /// Opaque recursive validity proof bytes (§1.7.9) — not verified here.
    pub proof: Vec<u8>,
    /// Opaque membership proof of `coin` in `output_coins_root`.
    pub inclusion_proof: Vec<u8>,
    pub creating_prev_ash: HashDigest,
    pub creating_nullifier: CreatingNullifier,
    pub nav_opening: NavOpening,
    pub asset_terms: Option<IssuanceTerms>,
    pub epk: [u8; 32],
    /// UTF-8 of NIP-44 Base64 payload: `NIP44Binary(K_tx, "coin", serialize(Coin))`.
    pub ciphertext: Vec<u8>,
    pub detect_tag: HashDigest,
}

/// Ordered holder-hint list for one content-addressed blob (§7.1 / §4.3).
///
/// **Only `holders`.** The 32-byte `blob_id` lives **beside** this set in the
/// surrounding context — never inside it. Do not add a `blob_id` field: that
/// would break the §4.3 privacy boundary (encrypted holder hints must not
/// become a correlatable public directory of blob identifiers).
///
/// Order is significant (first entry is the preferred fetch target). This
/// codec **does not** sort or deduplicate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlobLocatorSet {
    pub holders: Vec<String>,
}

/// Bitcoin block reference used in SDR anchors (§4.2 / §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockAnchor {
    pub block_hash: [u8; 32],
    pub height: u32,
}

/// One outgoing coin reference inside a self-delivery record (§4.2 / §7.1).
///
/// `out_ciphertext` is the UTF-8 of the NIP-44 Base64 payload from
/// `NIP44Binary(K_out, "K_tx", K_tx)` — same stored-field discipline as
/// [`super::note_encryption`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputRef {
    pub coin_id: [u8; 32],
    pub blob_id: [u8; 32],
    pub epk: [u8; 32],
    pub out_ciphertext: Vec<u8>,
    pub blob_locators: BlobLocatorSet,
}

/// Transition class discriminator on `SelfDeliveryRecordV1` (§4.2 / §7.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RecordKind {
    Mint = 0x01,
    Send = 0x02,
    Receive = 0x03,
}

impl RecordKind {
    fn from_u8(v: u8) -> Result<Self, SpecError> {
        match v {
            0x01 => Ok(Self::Mint),
            0x02 => Ok(Self::Send),
            0x03 => Ok(Self::Receive),
            got => Err(SpecError::SdrRecordKindInvalid { got }),
        }
    }

    fn to_u8(self) -> u8 {
        self as u8
    }
}

/// Account self-addressed state/transition record (§4.2 / §7.1).
///
/// Fully length-prefixed so a pure receive (`M = 0` output refs) remains
/// fully replayable without any outgoing `CoinProof`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SelfDeliveryRecordV1 {
    pub record_kind: RecordKind,
    pub send_counter: u64,
    pub prev_state_head: HashDigest,
    pub account_state: AccountState,
    /// Opaque recursive proof bytes of this transition — not verified here.
    pub recursive_proof: Vec<u8>,
    pub proof_data: ProofData,
    pub own_nullifier: CreatingNullifier,
    pub proof_block_anchor: BlockAnchor,
    pub inclusion_block: BlockAnchor,
    pub occurred_at: u64,
    pub spent_or_folded_coin_ids: Vec<[u8; 32]>,
    pub output_refs: Vec<OutputRef>,
    /// Holders of **this** SelfDeliveryRecordV1 ZBE blob.
    pub self_blob_locators: BlobLocatorSet,
}

// ---------------------------------------------------------------------------
// BlobLocatorSet
// ---------------------------------------------------------------------------

/// `serialize(BlobLocatorSet)` — holders only; `blob_id` is context, not here.
pub fn serialize_blob_locator_set(set: &BlobLocatorSet) -> Result<Vec<u8>, SpecError> {
    validate_blob_locator_set(set)?;
    let mut out = Vec::new();
    write_blob_locator_set(set, &mut out)?;
    Ok(out)
}

/// Inverse of [`serialize_blob_locator_set`]. Rejects trailing bytes.
pub fn deserialize_blob_locator_set(bytes: &[u8]) -> Result<BlobLocatorSet, SpecError> {
    let mut cur = bytes;
    let set = read_blob_locator_set(&mut cur)?;
    if !cur.is_empty() {
        return Err(SpecError::BundleTrailingBytes {
            context: "BlobLocatorSet",
            remaining: cur.len(),
        });
    }
    Ok(set)
}

fn validate_blob_locator_set(set: &BlobLocatorSet) -> Result<(), SpecError> {
    if set.holders.is_empty() {
        return Err(SpecError::BlobLocatorCountZero);
    }
    if set.holders.len() > MAX_BLOB_HOLDERS {
        // Refuse — never clamp the count into a wire width. A clamped count
        // would write a frame whose holder_count disagrees with the entries
        // that follow, breaking the "exactly one byte string per set" promise.
        return Err(SpecError::BlobLocatorCountTooHigh {
            count: set.holders.len(),
            max: MAX_BLOB_HOLDERS,
        });
    }
    for (index, url) in set.holders.iter().enumerate() {
        let bytes = url.as_bytes();
        if bytes.is_empty() {
            return Err(SpecError::BlobLocatorUrlEmpty { index });
        }
        if bytes.len() > MAX_HOLDER_URL_LEN {
            return Err(SpecError::BlobLocatorUrlTooLong {
                index,
                len: bytes.len(),
            });
        }
        if bytes.contains(&0) {
            return Err(SpecError::BlobLocatorUrlContainsNul { index });
        }
    }
    Ok(())
}

fn write_blob_locator_set(set: &BlobLocatorSet, out: &mut Vec<u8>) -> Result<(), SpecError> {
    // `validate_blob_locator_set` already rejects count > MAX_BLOB_HOLDERS
    // (16 ≪ u16::MAX). Re-check with the true count so a future caller that
    // skips validation still cannot emit a clamped, self-inconsistent frame.
    let count =
        u16::try_from(set.holders.len()).map_err(|_| SpecError::BlobLocatorCountTooHigh {
            count: set.holders.len(),
            max: MAX_BLOB_HOLDERS,
        })?;
    if set.holders.len() > MAX_BLOB_HOLDERS {
        return Err(SpecError::BlobLocatorCountTooHigh {
            count: set.holders.len(),
            max: MAX_BLOB_HOLDERS,
        });
    }
    out.extend_from_slice(&count.to_be_bytes());
    for (index, url) in set.holders.iter().enumerate() {
        let bytes = url.as_bytes();
        let len = u16::try_from(bytes.len()).map_err(|_| SpecError::BlobLocatorUrlTooLong {
            index,
            len: bytes.len(),
        })?;
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(bytes);
    }
    Ok(())
}

fn read_blob_locator_set(cur: &mut &[u8]) -> Result<BlobLocatorSet, SpecError> {
    let count_raw = read_exact(cur, 2, "BlobLocatorSet.holder_count")?;
    let count = u16::from_be_bytes([count_raw[0], count_raw[1]]);
    if count == 0 {
        return Err(SpecError::BlobLocatorCountZero);
    }
    if count as usize > MAX_BLOB_HOLDERS {
        return Err(SpecError::BlobLocatorCountTooHigh {
            count: count as usize,
            max: MAX_BLOB_HOLDERS,
        });
    }
    let mut holders = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        let len_raw = read_exact(cur, 2, "BlobLocatorSet.url_len")?;
        let url_len = u16::from_be_bytes([len_raw[0], len_raw[1]]) as usize;
        if url_len == 0 {
            return Err(SpecError::BlobLocatorUrlEmpty { index });
        }
        if url_len > MAX_HOLDER_URL_LEN {
            return Err(SpecError::BlobLocatorUrlTooLong {
                index,
                len: url_len,
            });
        }
        let url_bytes = read_len_prefixed(cur, url_len as u32, "BlobLocatorSet.url")?;
        if url_bytes.contains(&0) {
            return Err(SpecError::BlobLocatorUrlContainsNul { index });
        }
        let url = std::str::from_utf8(url_bytes)
            .map_err(|_| SpecError::BlobLocatorInvalidUtf8 { index })?;
        holders.push(url.to_string());
    }
    Ok(BlobLocatorSet { holders })
}

// ---------------------------------------------------------------------------
// CoinProof
// ---------------------------------------------------------------------------

/// `serialize(CoinProof)` — length-prefixed concatenation in §1.5 order.
pub fn serialize_coin_proof(cp: &CoinProof) -> Result<Vec<u8>, SpecError> {
    if let Some(terms) = &cp.asset_terms {
        validate_issuance_terms(terms)?;
    }
    let mut out = Vec::new();
    out.extend_from_slice(&serialize_coin(&cp.coin));
    write_u32_bytes(&cp.proof, &mut out, "CoinProof.proof")?;
    write_u32_bytes(&cp.inclusion_proof, &mut out, "CoinProof.inclusion_proof")?;
    out.extend_from_slice(&digest_to_bytes(&cp.creating_prev_ash));
    write_creating_nullifier(&cp.creating_nullifier, &mut out);
    write_nav_opening(&cp.nav_opening, &mut out);
    match &cp.asset_terms {
        None => out.push(0x00),
        Some(terms) => {
            out.push(0x01);
            write_issuance_terms(terms, &mut out)?;
        }
    }
    out.extend_from_slice(&cp.epk);
    write_u32_bytes(&cp.ciphertext, &mut out, "CoinProof.ciphertext")?;
    out.extend_from_slice(&digest_to_bytes(&cp.detect_tag));
    Ok(out)
}

/// Inverse of [`serialize_coin_proof`]. Rejects every §7.1 malformation.
pub fn deserialize_coin_proof(bytes: &[u8]) -> Result<CoinProof, SpecError> {
    let mut cur = bytes;

    let coin_raw = read_exact(&mut cur, COIN_WIRE_LEN, "CoinProof.coin")?;
    let coin = deserialize_coin(coin_raw)?;

    let proof = read_u32_bytes(&mut cur, "CoinProof.proof")?.to_vec();
    let inclusion_proof = read_u32_bytes(&mut cur, "CoinProof.inclusion_proof")?.to_vec();

    let prev_raw = read_exact(&mut cur, 32, "CoinProof.creating_prev_ash")?;
    let mut prev_arr = [0u8; 32];
    prev_arr.copy_from_slice(prev_raw);
    let creating_prev_ash = digest_from_bytes(&prev_arr)?;

    let creating_nullifier = read_creating_nullifier(&mut cur)?;
    let nav_opening = read_nav_opening(&mut cur)?;

    let presence = read_exact(&mut cur, 1, "CoinProof.asset_terms.presence")?[0];
    let asset_terms = match presence {
        0x00 => None,
        0x01 => Some(read_issuance_terms(&mut cur)?),
        got => return Err(SpecError::CoinProofPresenceInvalid { got }),
    };

    let epk_raw = read_exact(&mut cur, 32, "CoinProof.epk")?;
    let mut epk = [0u8; 32];
    epk.copy_from_slice(epk_raw);

    let ciphertext = read_u32_bytes(&mut cur, "CoinProof.ciphertext")?.to_vec();

    let tag_raw = read_exact(&mut cur, 32, "CoinProof.detect_tag")?;
    let mut tag_arr = [0u8; 32];
    tag_arr.copy_from_slice(tag_raw);
    let detect_tag = digest_from_bytes(&tag_arr)?;

    if !cur.is_empty() {
        return Err(SpecError::BundleTrailingBytes {
            context: "CoinProof",
            remaining: cur.len(),
        });
    }

    Ok(CoinProof {
        coin,
        proof,
        inclusion_proof,
        creating_prev_ash,
        creating_nullifier,
        nav_opening,
        asset_terms,
        epk,
        ciphertext,
        detect_tag,
    })
}

fn validate_issuance_terms(terms: &IssuanceTerms) -> Result<(), SpecError> {
    if terms.name.len() > MAX_ASSET_NAME_LEN {
        return Err(SpecError::NameTooLong {
            len: terms.name.len(),
        });
    }
    match terms.issuance_version {
        0x01 => {
            if terms.cap_total.is_some() || terms.terms_salt.is_some() {
                return Err(SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                    issuance_version: 1,
                    cap_fields_present: true,
                });
            }
        }
        0x02 => {
            if terms.cap_total.is_none() || terms.terms_salt.is_none() {
                return Err(SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                    issuance_version: 2,
                    cap_fields_present: false,
                });
            }
        }
        got => return Err(SpecError::CoinProofIssuanceVersionInvalid { got }),
    }
    Ok(())
}

fn write_issuance_terms(terms: &IssuanceTerms, out: &mut Vec<u8>) -> Result<(), SpecError> {
    validate_issuance_terms(terms)?;
    out.extend_from_slice(&terms.creator_pubkey);
    out.push(terms.decimals);
    out.push(terms.issuance_version);
    write_u32_bytes(&terms.name, out, "asset_terms.name")?;
    if terms.issuance_version == 0x02 {
        // validate_issuance_terms already required both Options to be Some.
        let Some(cap) = terms.cap_total else {
            return Err(SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                issuance_version: 2,
                cap_fields_present: false,
            });
        };
        let Some(salt) = terms.terms_salt else {
            return Err(SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                issuance_version: 2,
                cap_fields_present: false,
            });
        };
        out.extend_from_slice(&cap.to_be_bytes());
        out.extend_from_slice(&salt);
    }
    Ok(())
}

fn read_issuance_terms(cur: &mut &[u8]) -> Result<IssuanceTerms, SpecError> {
    let pk_raw = read_exact(cur, 32, "asset_terms.creator_pubkey")?;
    let mut creator_pubkey = [0u8; 32];
    creator_pubkey.copy_from_slice(pk_raw);

    let decimals = read_exact(cur, 1, "asset_terms.decimals")?[0];
    let issuance_version = read_exact(cur, 1, "asset_terms.issuance_version")?[0];

    let name = read_u32_bytes(cur, "asset_terms.name")?.to_vec();
    if name.len() > MAX_ASSET_NAME_LEN {
        return Err(SpecError::NameTooLong { len: name.len() });
    }

    let (cap_total, terms_salt) = match issuance_version {
        0x01 => (None, None),
        0x02 => {
            let cap_raw = match read_exact(cur, 16, "asset_terms.cap_total") {
                Ok(b) => b,
                Err(SpecError::BundleTruncated { .. }) => {
                    return Err(SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                        issuance_version: 2,
                        cap_fields_present: false,
                    });
                }
                Err(e) => return Err(e),
            };
            let mut cap_be = [0u8; 16];
            cap_be.copy_from_slice(cap_raw);
            let salt_raw = match read_exact(cur, 32, "asset_terms.terms_salt") {
                Ok(b) => b,
                Err(SpecError::BundleTruncated { .. }) => {
                    return Err(SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                        issuance_version: 2,
                        cap_fields_present: false,
                    });
                }
                Err(e) => return Err(e),
            };
            let mut terms_salt = [0u8; 32];
            terms_salt.copy_from_slice(salt_raw);
            (Some(u128::from_be_bytes(cap_be)), Some(terms_salt))
        }
        got => return Err(SpecError::CoinProofIssuanceVersionInvalid { got }),
    };

    Ok(IssuanceTerms {
        creator_pubkey,
        decimals,
        issuance_version,
        name,
        cap_total,
        terms_salt,
    })
}

fn write_creating_nullifier(n: &CreatingNullifier, out: &mut Vec<u8>) {
    out.extend_from_slice(&n.pk_create);
    out.extend_from_slice(&n.r_create);
    out.extend_from_slice(&n.r_prime_create);
}

fn read_creating_nullifier(cur: &mut &[u8]) -> Result<CreatingNullifier, SpecError> {
    let pk = read_exact(cur, 32, "creating_nullifier.Pk")?;
    let r = read_exact(cur, 32, "creating_nullifier.R")?;
    let rp = read_exact(cur, 32, "creating_nullifier.R'")?;
    let mut pk_create = [0u8; 32];
    let mut r_create = [0u8; 32];
    let mut r_prime_create = [0u8; 32];
    pk_create.copy_from_slice(pk);
    r_create.copy_from_slice(r);
    r_prime_create.copy_from_slice(rp);
    Ok(CreatingNullifier {
        pk_create,
        r_create,
        r_prime_create,
    })
}

fn write_nav_opening(n: &NavOpening, out: &mut Vec<u8>) {
    out.extend_from_slice(&n.size.to_be_bytes());
    out.extend_from_slice(&digest_to_bytes(&n.mth));
    out.extend_from_slice(&n.nav_rand);
}

fn read_nav_opening(cur: &mut &[u8]) -> Result<NavOpening, SpecError> {
    let size_raw = read_exact(cur, 8, "nav_opening.size")?;
    let mut size_be = [0u8; 8];
    size_be.copy_from_slice(size_raw);
    let mth_raw = read_exact(cur, 32, "nav_opening.mth")?;
    let mut mth_arr = [0u8; 32];
    mth_arr.copy_from_slice(mth_raw);
    let rand_raw = read_exact(cur, 32, "nav_opening.nav_rand")?;
    let mut nav_rand = [0u8; 32];
    nav_rand.copy_from_slice(rand_raw);
    Ok(NavOpening {
        size: u64::from_be_bytes(size_be),
        mth: digest_from_bytes(&mth_arr)?,
        nav_rand,
    })
}

// ---------------------------------------------------------------------------
// SelfDeliveryRecordV1
// ---------------------------------------------------------------------------

/// `serialize(SelfDeliveryRecordV1)` — tagged, fully length-prefixed (§7.1).
pub fn serialize_self_delivery_record(r: &SelfDeliveryRecordV1) -> Result<Vec<u8>, SpecError> {
    validate_blob_locator_set(&r.self_blob_locators)?;
    for oref in &r.output_refs {
        validate_blob_locator_set(&oref.blob_locators)?;
        if oref.out_ciphertext.len() > usize::from(u16::MAX) {
            return Err(SpecError::ByteStringTooLong {
                len: oref.out_ciphertext.len(),
            });
        }
    }
    if r.spent_or_folded_coin_ids.len() > u16::MAX as usize {
        return Err(SpecError::ByteStringTooLong {
            len: r.spent_or_folded_coin_ids.len(),
        });
    }
    if r.output_refs.len() > u16::MAX as usize {
        return Err(SpecError::ByteStringTooLong {
            len: r.output_refs.len(),
        });
    }

    let mut out = Vec::new();
    out.extend_from_slice(SDR1_MAGIC);
    out.push(SDR1_VERSION);
    out.push(r.record_kind.to_u8());
    out.extend_from_slice(&r.send_counter.to_be_bytes());
    out.extend_from_slice(&digest_to_bytes(&r.prev_state_head));

    let state_bytes = serialize_account_state(&r.account_state)?;
    write_u32_bytes(&state_bytes, &mut out, "SDR.AccountState")?;
    write_u32_bytes(&r.recursive_proof, &mut out, "SDR.recursive_proof")?;
    out.extend_from_slice(&serialize_proof_data(&r.proof_data));
    write_creating_nullifier(&r.own_nullifier, &mut out);
    write_block_anchor(&r.proof_block_anchor, &mut out);
    write_block_anchor(&r.inclusion_block, &mut out);
    out.extend_from_slice(&r.occurred_at.to_be_bytes());

    let n_spent = u16::try_from(r.spent_or_folded_coin_ids.len()).map_err(|_| {
        SpecError::ByteStringTooLong {
            len: r.spent_or_folded_coin_ids.len(),
        }
    })?;
    out.extend_from_slice(&n_spent.to_be_bytes());
    for id in &r.spent_or_folded_coin_ids {
        out.extend_from_slice(id);
    }

    let m = u16::try_from(r.output_refs.len()).map_err(|_| SpecError::ByteStringTooLong {
        len: r.output_refs.len(),
    })?;
    out.extend_from_slice(&m.to_be_bytes());
    for oref in &r.output_refs {
        write_output_ref(oref, &mut out)?;
    }

    write_blob_locator_set(&r.self_blob_locators, &mut out)?;
    Ok(out)
}

/// Inverse of [`serialize_self_delivery_record`]. Rejects every §7.1 malformation.
pub fn deserialize_self_delivery_record(bytes: &[u8]) -> Result<SelfDeliveryRecordV1, SpecError> {
    let mut cur = bytes;

    let magic_raw = read_exact(&mut cur, 4, "SDR.magic")?;
    let mut magic = [0u8; 4];
    magic.copy_from_slice(magic_raw);
    if &magic != SDR1_MAGIC {
        return Err(SpecError::SdrMagicInvalid { got: magic });
    }

    let version = read_exact(&mut cur, 1, "SDR.version")?[0];
    if version != SDR1_VERSION {
        return Err(SpecError::SdrVersionInvalid { got: version });
    }

    let kind_byte = read_exact(&mut cur, 1, "SDR.record_kind")?[0];
    let record_kind = RecordKind::from_u8(kind_byte)?;

    let sc_raw = read_exact(&mut cur, 8, "SDR.send_counter")?;
    let mut sc_be = [0u8; 8];
    sc_be.copy_from_slice(sc_raw);
    let send_counter = u64::from_be_bytes(sc_be);

    let head_raw = read_exact(&mut cur, 32, "SDR.prev_state_head")?;
    let mut head_arr = [0u8; 32];
    head_arr.copy_from_slice(head_raw);
    let prev_state_head = digest_from_bytes(&head_arr)?;

    let state_raw = read_u32_bytes(&mut cur, "SDR.AccountState")?;
    let account_state = parse_account_state(state_raw)?;

    let recursive_proof = read_u32_bytes(&mut cur, "SDR.recursive_proof")?.to_vec();

    let pd_raw = read_exact(&mut cur, PROOF_DATA_WIRE_LEN, "SDR.ProofData")?;
    let proof_data = deserialize_proof_data(pd_raw)?;

    let own_nullifier = read_creating_nullifier(&mut cur)?;
    let proof_block_anchor = read_block_anchor(&mut cur, "SDR.proof_block_anchor")?;
    let inclusion_block = read_block_anchor(&mut cur, "SDR.inclusion_block")?;

    let occ_raw = read_exact(&mut cur, 8, "SDR.occurred_at")?;
    let mut occ_be = [0u8; 8];
    occ_be.copy_from_slice(occ_raw);
    let occurred_at = u64::from_be_bytes(occ_be);

    let n_raw = read_exact(&mut cur, 2, "SDR.N_spent")?;
    let n_spent = u16::from_be_bytes([n_raw[0], n_raw[1]]) as usize;
    let mut spent_or_folded_coin_ids = Vec::with_capacity(n_spent);
    for _ in 0..n_spent {
        let id_raw = read_exact(&mut cur, 32, "SDR.spent_coin_id")?;
        let mut id = [0u8; 32];
        id.copy_from_slice(id_raw);
        spent_or_folded_coin_ids.push(id);
    }

    let m_raw = read_exact(&mut cur, 2, "SDR.M")?;
    let m = u16::from_be_bytes([m_raw[0], m_raw[1]]) as usize;
    let mut output_refs = Vec::with_capacity(m);
    for _ in 0..m {
        output_refs.push(read_output_ref(&mut cur)?);
    }

    let self_blob_locators = read_blob_locator_set(&mut cur)?;

    if !cur.is_empty() {
        return Err(SpecError::BundleTrailingBytes {
            context: "SelfDeliveryRecordV1",
            remaining: cur.len(),
        });
    }

    Ok(SelfDeliveryRecordV1 {
        record_kind,
        send_counter,
        prev_state_head,
        account_state,
        recursive_proof,
        proof_data,
        own_nullifier,
        proof_block_anchor,
        inclusion_block,
        occurred_at,
        spent_or_folded_coin_ids,
        output_refs,
        self_blob_locators,
    })
}

fn write_block_anchor(a: &BlockAnchor, out: &mut Vec<u8>) {
    out.extend_from_slice(&a.block_hash);
    out.extend_from_slice(&a.height.to_be_bytes());
}

fn read_block_anchor(cur: &mut &[u8], context: &'static str) -> Result<BlockAnchor, SpecError> {
    let hash_raw = read_exact(cur, 32, context)?;
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(hash_raw);
    let h_raw = read_exact(cur, 4, context)?;
    let height = u32::from_be_bytes([h_raw[0], h_raw[1], h_raw[2], h_raw[3]]);
    Ok(BlockAnchor { block_hash, height })
}

fn write_output_ref(oref: &OutputRef, out: &mut Vec<u8>) -> Result<(), SpecError> {
    out.extend_from_slice(&oref.coin_id);
    out.extend_from_slice(&oref.blob_id);
    out.extend_from_slice(&oref.epk);
    let len =
        u16::try_from(oref.out_ciphertext.len()).map_err(|_| SpecError::ByteStringTooLong {
            len: oref.out_ciphertext.len(),
        })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&oref.out_ciphertext);
    write_blob_locator_set(&oref.blob_locators, out)?;
    Ok(())
}

fn read_output_ref(cur: &mut &[u8]) -> Result<OutputRef, SpecError> {
    let coin_raw = read_exact(cur, 32, "output_ref.coin_id")?;
    let blob_raw = read_exact(cur, 32, "output_ref.blob_id")?;
    let epk_raw = read_exact(cur, 32, "output_ref.epk")?;
    let mut coin_id = [0u8; 32];
    let mut blob_id = [0u8; 32];
    let mut epk = [0u8; 32];
    coin_id.copy_from_slice(coin_raw);
    blob_id.copy_from_slice(blob_raw);
    epk.copy_from_slice(epk_raw);

    let len_raw = read_exact(cur, 2, "output_ref.out_ciphertext_len")?;
    let ct_len = u16::from_be_bytes([len_raw[0], len_raw[1]]) as u32;
    let out_ciphertext = read_len_prefixed(cur, ct_len, "output_ref.out_ciphertext")?.to_vec();
    let blob_locators = read_blob_locator_set(cur)?;
    Ok(OutputRef {
        coin_id,
        blob_id,
        epk,
        out_ciphertext,
        blob_locators,
    })
}

// ---------------------------------------------------------------------------
// Cursor helpers
// ---------------------------------------------------------------------------

fn read_exact<'a>(
    cur: &mut &'a [u8],
    n: usize,
    context: &'static str,
) -> Result<&'a [u8], SpecError> {
    if cur.len() < n {
        return Err(SpecError::BundleTruncated {
            context,
            needed: n,
            remaining: cur.len(),
        });
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

fn read_len_prefixed<'a>(
    cur: &mut &'a [u8],
    declared: u32,
    context: &'static str,
) -> Result<&'a [u8], SpecError> {
    let n = declared as usize;
    if cur.len() < n {
        return Err(SpecError::BundleLengthOverrun {
            context,
            declared,
            remaining: cur.len(),
        });
    }
    let (head, tail) = cur.split_at(n);
    *cur = tail;
    Ok(head)
}

fn read_u32_bytes<'a>(cur: &mut &'a [u8], context: &'static str) -> Result<&'a [u8], SpecError> {
    let len_raw = read_exact(cur, 4, context)?;
    let declared = u32::from_be_bytes([len_raw[0], len_raw[1], len_raw[2], len_raw[3]]);
    read_len_prefixed(cur, declared, context)
}

fn write_u32_bytes(
    bytes: &[u8],
    out: &mut Vec<u8>,
    _context: &'static str,
) -> Result<(), SpecError> {
    let len = u32::try_from(bytes.len())
        .map_err(|_| SpecError::ByteStringTooLong { len: bytes.len() })?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec_v1::datastructures::Address;
    use crate::spec_v1::serialize::serialize_coin;
    use std::collections::BTreeMap;
    use zkcoins_program::hash::ZERO_HASH;

    // V.10 coin_bytes pin (generated_poseidon_vectors.txt / note_encryption).
    const V10_COIN_BYTES: &str = "a1cc00c5a5c0fa499664ca891690c3bde52a4c9326f6794659f8ad1926288790e38121742a22e04e51175eb3e38a66df7e7e691c0041c169bc3a2592696f803d0000000000000000000000003b9aca00da7deb2e2d8ad91a2ec9e2aafc6756b2b11f092c79650ce313658f3a9b2ab7cf";

    fn parse_hex(s: &str) -> Vec<u8> {
        hex::decode(s).expect("fixture hex")
    }

    fn sample_coin() -> Coin {
        Coin {
            identifier: ZERO_HASH,
            recipient: Address([0x11; 32]),
            amount: 1_000_000_000,
            asset_id: ZERO_HASH,
        }
    }

    fn sample_nullifier() -> CreatingNullifier {
        CreatingNullifier {
            pk_create: [0xA1; 32],
            r_create: [0xA2; 32],
            r_prime_create: [0xA3; 32],
        }
    }

    fn sample_nav() -> NavOpening {
        NavOpening {
            size: 7,
            mth: ZERO_HASH,
            nav_rand: [0xB0; 32],
        }
    }

    fn sample_holders() -> BlobLocatorSet {
        BlobLocatorSet {
            holders: vec![
                "https://blob.example/a".into(),
                "https://blob.example/b".into(),
            ],
        }
    }

    fn sample_coin_proof(terms: Option<IssuanceTerms>) -> CoinProof {
        CoinProof {
            coin: sample_coin(),
            proof: vec![0x01, 0x02, 0x03],
            inclusion_proof: vec![0xAA],
            creating_prev_ash: ZERO_HASH,
            creating_nullifier: sample_nullifier(),
            nav_opening: sample_nav(),
            asset_terms: terms,
            epk: [0xE0; 32],
            // Opaque UTF-8 of a NIP-44 Base64 payload (not real AEAD).
            ciphertext: b"AgAAAAfakeNip44Base64Payload".to_vec(),
            detect_tag: ZERO_HASH,
        }
    }

    fn sample_account_state() -> AccountState {
        let mut balances = BTreeMap::new();
        balances.insert([0x01; 32], 42u128);
        AccountState::new(
            Address([0x22; 32]),
            ZERO_HASH,
            balances,
            [0x33; 32],
            5,
            ZERO_HASH,
        )
        .expect("valid account state")
    }

    fn sample_proof_data() -> ProofData {
        ProofData {
            new_account_state_hash: ZERO_HASH,
            output_coins_root: ZERO_HASH,
            input_nullifiers_root: ZERO_HASH,
            coin_history_root: ZERO_HASH,
            nav_commitment: ZERO_HASH,
            npk_commit: [0x44; 32],
        }
    }

    fn sample_sdr(
        kind: RecordKind,
        spent: Vec<[u8; 32]>,
        outputs: Vec<OutputRef>,
    ) -> SelfDeliveryRecordV1 {
        SelfDeliveryRecordV1 {
            record_kind: kind,
            send_counter: 5,
            prev_state_head: ZERO_HASH,
            account_state: sample_account_state(),
            recursive_proof: vec![0xDE, 0xAD],
            proof_data: sample_proof_data(),
            own_nullifier: sample_nullifier(),
            proof_block_anchor: BlockAnchor {
                block_hash: [0x50; 32],
                height: 100,
            },
            inclusion_block: BlockAnchor {
                block_hash: [0x51; 32],
                height: 106,
            },
            occurred_at: 1_700_000_000,
            spent_or_folded_coin_ids: spent,
            output_refs: outputs,
            self_blob_locators: sample_holders(),
        }
    }

    fn sample_output_ref() -> OutputRef {
        OutputRef {
            coin_id: [0xC0; 32],
            blob_id: [0xC1; 32],
            epk: [0xC2; 32],
            out_ciphertext: b"outCipherNip44Base64".to_vec(),
            blob_locators: sample_holders(),
        }
    }

    // -----------------------------------------------------------------------
    // Auftrag 1 — Coin 112-byte layout vs V.10
    // -----------------------------------------------------------------------

    #[test]
    fn coin_serialize_is_exactly_112_bytes() {
        let bytes = serialize_coin(&sample_coin());
        assert_eq!(bytes.len(), COIN_WIRE_LEN);
        assert_eq!(deserialize_coin(&bytes).expect("roundtrip"), sample_coin());
    }

    #[test]
    fn coin_v10_fixture_bit_for_bit() {
        let expected = parse_hex(V10_COIN_BYTES);
        assert_eq!(expected.len(), COIN_WIRE_LEN);
        // Rebuild from the fixture fields and re-serialize.
        let coin = deserialize_coin(&expected).expect("V.10 coin_bytes must parse");
        let again = serialize_coin(&coin);
        assert_eq!(again.as_slice(), expected.as_slice());
        // amount pin: 1_000_000_000 = 0x3b9aca00
        assert_eq!(coin.amount, 1_000_000_000);
    }

    // -----------------------------------------------------------------------
    // Roundtrip + determinism (blob_id promise)
    // -----------------------------------------------------------------------

    #[test]
    fn coin_proof_roundtrip_and_determinism_no_terms() {
        let cp = sample_coin_proof(None);
        let a = serialize_coin_proof(&cp).expect("ser");
        let b = serialize_coin_proof(&cp).expect("ser again");
        assert_eq!(
            a, b,
            "serialize twice must yield identical bytes (§4.2.1 blob_id)"
        );
        let back = deserialize_coin_proof(&a).expect("de");
        assert_eq!(back, cp);
    }

    #[test]
    fn coin_proof_roundtrip_terms_v1() {
        let terms = IssuanceTerms {
            creator_pubkey: [0x01; 32],
            decimals: 8,
            issuance_version: 1,
            name: b"zkUSD".to_vec(),
            cap_total: None,
            terms_salt: None,
        };
        let cp = sample_coin_proof(Some(terms));
        let bytes = serialize_coin_proof(&cp).expect("ser");
        assert_eq!(deserialize_coin_proof(&bytes).expect("de"), cp);
        assert_eq!(serialize_coin_proof(&cp).expect("ser2"), bytes);
    }

    #[test]
    fn coin_proof_roundtrip_terms_v2() {
        let terms = IssuanceTerms {
            creator_pubkey: [0x02; 32],
            decimals: 2,
            issuance_version: 2,
            name: b"CAPPED".to_vec(),
            cap_total: Some(1_000_000),
            terms_salt: Some([0x55; 32]),
        };
        let cp = sample_coin_proof(Some(terms));
        let bytes = serialize_coin_proof(&cp).expect("ser");
        assert_eq!(deserialize_coin_proof(&bytes).expect("de"), cp);
    }

    #[test]
    fn blob_locator_set_roundtrip_and_determinism() {
        let set = sample_holders();
        let a = serialize_blob_locator_set(&set).expect("ser");
        let b = serialize_blob_locator_set(&set).expect("ser2");
        assert_eq!(a, b);
        assert_eq!(deserialize_blob_locator_set(&a).expect("de"), set);
        // Order preserved — not sorted.
        let reversed = BlobLocatorSet {
            holders: vec![
                "https://blob.example/b".into(),
                "https://blob.example/a".into(),
            ],
        };
        assert_ne!(
            serialize_blob_locator_set(&reversed).unwrap(),
            a,
            "order is significant"
        );
    }

    #[test]
    fn sdr_roundtrip_pure_receive_m_zero() {
        // Pure receive: M = 0, may have spent/folded ids.
        let sdr = sample_sdr(RecordKind::Receive, vec![[0xF1; 32]], vec![]);
        let a = serialize_self_delivery_record(&sdr).expect("ser");
        let b = serialize_self_delivery_record(&sdr).expect("ser2");
        assert_eq!(a, b, "determinism");
        assert_eq!(deserialize_self_delivery_record(&a).expect("de"), sdr);
    }

    #[test]
    fn sdr_roundtrip_pure_mint_n_spent_zero() {
        let sdr = sample_sdr(RecordKind::Mint, vec![], vec![sample_output_ref()]);
        let bytes = serialize_self_delivery_record(&sdr).expect("ser");
        assert_eq!(deserialize_self_delivery_record(&bytes).expect("de"), sdr);
    }

    #[test]
    fn sdr_roundtrip_send_with_outputs() {
        let sdr = sample_sdr(
            RecordKind::Send,
            vec![[0x01; 32], [0x02; 32]],
            vec![sample_output_ref()],
        );
        let bytes = serialize_self_delivery_record(&sdr).expect("ser");
        assert_eq!(deserialize_self_delivery_record(&bytes).expect("de"), sdr);
    }

    // -----------------------------------------------------------------------
    // asset_terms — name bounds, non-UTF-8, Kreuzfälle
    // -----------------------------------------------------------------------

    #[test]
    fn asset_terms_name_empty_and_255_ok() {
        for name in [Vec::new(), vec![0x41u8; 255]] {
            let terms = IssuanceTerms {
                creator_pubkey: [0; 32],
                decimals: 0,
                issuance_version: 1,
                name,
                cap_total: None,
                terms_salt: None,
            };
            let cp = sample_coin_proof(Some(terms));
            let bytes = serialize_coin_proof(&cp).expect("ser");
            assert_eq!(deserialize_coin_proof(&bytes).expect("de"), cp);
        }
    }

    #[test]
    fn asset_terms_name_256_malformed() {
        let terms = IssuanceTerms {
            creator_pubkey: [0; 32],
            decimals: 0,
            issuance_version: 1,
            name: vec![0x42u8; 256],
            cap_total: None,
            terms_salt: None,
        };
        let err = serialize_coin_proof(&sample_coin_proof(Some(terms))).expect_err("256");
        assert_eq!(err, SpecError::NameTooLong { len: 256 });
    }

    #[test]
    fn asset_terms_name_non_utf8_accepted() {
        // Display is not the codec's job (§1.5): raw bytes, including invalid UTF-8.
        let terms = IssuanceTerms {
            creator_pubkey: [0; 32],
            decimals: 0,
            issuance_version: 1,
            name: vec![0xFF, 0xFE, 0xFD],
            cap_total: None,
            terms_salt: None,
        };
        assert!(std::str::from_utf8(&terms.name).is_err());
        let cp = sample_coin_proof(Some(terms));
        let bytes = serialize_coin_proof(&cp).expect("ser");
        let back = deserialize_coin_proof(&bytes).expect("de");
        assert_eq!(back, cp);
        assert_eq!(
            back.asset_terms.as_ref().map(|t| t.name.as_slice()),
            Some([0xFF, 0xFE, 0xFD].as_slice())
        );
    }

    #[test]
    fn asset_terms_v1_with_cap_malformed_on_serialize() {
        let terms = IssuanceTerms {
            creator_pubkey: [0; 32],
            decimals: 0,
            issuance_version: 1,
            name: b"x".to_vec(),
            cap_total: Some(99),
            terms_salt: Some([1; 32]),
        };
        let err = serialize_coin_proof(&sample_coin_proof(Some(terms))).expect_err("kreuz v1");
        assert_eq!(
            err,
            SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                issuance_version: 1,
                cap_fields_present: true,
            }
        );
    }

    #[test]
    fn asset_terms_v2_without_cap_malformed_on_serialize() {
        let terms = IssuanceTerms {
            creator_pubkey: [0; 32],
            decimals: 0,
            issuance_version: 2,
            name: b"x".to_vec(),
            cap_total: None,
            terms_salt: None,
        };
        let err = serialize_coin_proof(&sample_coin_proof(Some(terms))).expect_err("kreuz v2");
        assert_eq!(
            err,
            SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                issuance_version: 2,
                cap_fields_present: false,
            }
        );
    }

    #[test]
    fn asset_terms_v1_with_cap_on_wire_misaligns_and_rejects() {
        // Kreuzfall on the wire: issuance_version=1 but cap_total‖terms_salt
        // still follow `name`. Decoder consumes only the v1 layout, so the
        // trailing 48 bytes shift every subsequent field and the frame fails
        // closed (length overrun or trailing) — never silently accepted.
        let terms = IssuanceTerms {
            creator_pubkey: [0x0A; 32],
            decimals: 0,
            issuance_version: 1,
            name: b"x".to_vec(),
            cap_total: None,
            terms_salt: None,
        };
        let bytes = serialize_coin_proof(&sample_coin_proof(Some(terms))).expect("ser");
        // Insert 48 bytes of fake cap‖salt immediately after `name` (before epk).
        // presence(1)+creator(32)+decimals(1)+version(1)+u32(4)+name(1) = 40 after presence.
        let proof_len = 3usize;
        let incl_len = 1usize;
        let presence_off = 112 + 4 + proof_len + 4 + incl_len + 32 + 96 + 72;
        let after_name = presence_off + 1 + 32 + 1 + 1 + 4 + 1; // ends after name byte
        let mut injected = Vec::new();
        injected.extend_from_slice(&bytes[..after_name]);
        injected.extend_from_slice(&[0xCC; 48]); // fake cap_total ‖ terms_salt
        injected.extend_from_slice(&bytes[after_name..]);
        let err = deserialize_coin_proof(&injected).expect_err("v1+cap wire");
        assert!(
            matches!(err, SpecError::BundleLengthOverrun { .. } | SpecError::BundleTrailingBytes { .. } | SpecError::BundleTruncated { .. } | SpecError::NonCanonicalDigestLimb { .. }),
            "v1+cap wire must not parse cleanly, got {err:?}"
        );
    }

    #[test]
    fn asset_terms_v2_truncated_cap_on_wire_malformed() {
        // Valid v2 wire ends: … name ‖ cap(16) ‖ salt(32) ‖ epk(32) ‖ u32‖ct ‖ tag(32).
        // Truncate immediately before cap so `read_issuance_terms` sees
        // issuance_version=2 and then BundleTruncated on cap_total — which the
        // decoder maps to CoinProofAssetTermsVersionFieldsMismatch
        // { cap_fields_present: false } (not a later epk/ciphertext truncate).
        let terms = IssuanceTerms {
            creator_pubkey: [0x09; 32],
            decimals: 1,
            issuance_version: 2,
            name: b"T".to_vec(),
            cap_total: Some(7),
            terms_salt: Some([0x77; 32]),
        };
        let mut bytes = serialize_coin_proof(&sample_coin_proof(Some(terms))).expect("ser");
        let ct_len = sample_coin_proof(None).ciphertext.len();
        let tail = 16 + 32 + 32 + 4 + ct_len + 32;
        assert!(bytes.len() > tail);
        bytes.truncate(bytes.len() - tail); // cut before cap
        let err = deserialize_coin_proof(&bytes).expect_err("truncated v2");
        assert_eq!(
            err,
            SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                issuance_version: 2,
                cap_fields_present: false,
            }
        );
    }

    #[test]
    fn asset_terms_issuance_version_zero_malformed() {
        let terms = IssuanceTerms {
            creator_pubkey: [0; 32],
            decimals: 0,
            issuance_version: 0,
            name: b"x".to_vec(),
            cap_total: None,
            terms_salt: None,
        };
        let err = serialize_coin_proof(&sample_coin_proof(Some(terms))).expect_err("v0");
        assert_eq!(err, SpecError::CoinProofIssuanceVersionInvalid { got: 0 });
    }

    #[test]
    fn asset_terms_issuance_version_three_on_wire_malformed() {
        let terms = IssuanceTerms {
            creator_pubkey: [0; 32],
            decimals: 0,
            issuance_version: 1,
            name: b"x".to_vec(),
            cap_total: None,
            terms_salt: None,
        };
        let mut bytes = serialize_coin_proof(&sample_coin_proof(Some(terms))).expect("ser");
        // Presence 0x01 then creator(32) decimals(1) version(1) — flip version to 3.
        // coin(112) + proof len+3 + incl len+1 + prev(32) + null(96) + nav(72) + presence(1)
        // + creator(32) + decimals(1) = offset of version byte.
        let proof_len = 3usize;
        let incl_len = 1usize;
        let off = 112 + 4 + proof_len + 4 + incl_len + 32 + 96 + 72 + 1 + 32 + 1;
        assert_eq!(bytes[off], 1);
        bytes[off] = 3;
        let err = deserialize_coin_proof(&bytes).expect_err("v3");
        assert_eq!(err, SpecError::CoinProofIssuanceVersionInvalid { got: 3 });
    }

    // -----------------------------------------------------------------------
    // CoinProof malformed conditions (§7.1)
    // -----------------------------------------------------------------------

    #[test]
    fn coin_proof_presence_byte_two_malformed() {
        let mut bytes = serialize_coin_proof(&sample_coin_proof(None)).expect("ser");
        let proof_len = 3usize;
        let incl_len = 1usize;
        let presence_off = 112 + 4 + proof_len + 4 + incl_len + 32 + 96 + 72;
        assert_eq!(bytes[presence_off], 0x00);
        bytes[presence_off] = 0x02;
        let err = deserialize_coin_proof(&bytes).expect_err("presence");
        assert_eq!(err, SpecError::CoinProofPresenceInvalid { got: 0x02 });
    }

    #[test]
    fn coin_proof_length_prefix_overrun_malformed() {
        let mut bytes = serialize_coin_proof(&sample_coin_proof(None)).expect("ser");
        // Overwrite proof length (at offset 112) to claim more than remains.
        bytes[112..116].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = deserialize_coin_proof(&bytes).expect_err("overrun");
        assert!(
            matches!(
                err,
                SpecError::BundleLengthOverrun {
                    context: "CoinProof.proof",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn coin_proof_trailing_bytes_malformed() {
        let mut bytes = serialize_coin_proof(&sample_coin_proof(None)).expect("ser");
        bytes.push(0xFF);
        let err = deserialize_coin_proof(&bytes).expect_err("trailing");
        assert_eq!(
            err,
            SpecError::BundleTrailingBytes {
                context: "CoinProof",
                remaining: 1,
            }
        );
    }

    #[test]
    fn coin_proof_truncated_fixed_field_malformed() {
        let bytes = serialize_coin_proof(&sample_coin_proof(None)).expect("ser");
        let err = deserialize_coin_proof(&bytes[..50]).expect_err("trunc");
        assert!(
            matches!(
                err,
                SpecError::BundleTruncated {
                    context: "CoinProof.coin",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn coin_proof_name_len_256_on_wire_malformed() {
        // Hand-build asset_terms with name len 256 after a valid prefix.
        let base = sample_coin_proof(None);
        let mut bytes = serialize_coin_proof(&base).expect("ser");
        // Replace presence 0x00 with full terms that have overlong name.
        let proof_len = base.proof.len();
        let incl_len = base.inclusion_proof.len();
        let presence_off = 112 + 4 + proof_len + 4 + incl_len + 32 + 96 + 72;
        let tail_from_epk = &bytes[presence_off + 1..].to_vec();
        bytes.truncate(presence_off);
        bytes.push(0x01);
        bytes.extend_from_slice(&[0xAB; 32]); // creator
        bytes.push(0); // decimals
        bytes.push(1); // version
        bytes.extend_from_slice(&256u32.to_be_bytes());
        bytes.extend_from_slice(&vec![0x41u8; 256]);
        bytes.extend_from_slice(tail_from_epk);
        let err = deserialize_coin_proof(&bytes).expect_err("name 256");
        assert_eq!(err, SpecError::NameTooLong { len: 256 });
    }

    // -----------------------------------------------------------------------
    // BlobLocatorSet malformed
    // -----------------------------------------------------------------------

    #[test]
    fn blob_locator_count_zero_malformed() {
        let err =
            serialize_blob_locator_set(&BlobLocatorSet { holders: vec![] }).expect_err("empty");
        assert_eq!(err, SpecError::BlobLocatorCountZero);
        let err = deserialize_blob_locator_set(&[0x00, 0x00]).expect_err("wire zero");
        assert_eq!(err, SpecError::BlobLocatorCountZero);
    }

    #[test]
    fn blob_locator_count_too_high_malformed() {
        let holders = (0..17).map(|i| format!("https://h{i}.example")).collect();
        let err = serialize_blob_locator_set(&BlobLocatorSet { holders }).expect_err("17");
        assert_eq!(
            err,
            SpecError::BlobLocatorCountTooHigh {
                count: 17,
                max: MAX_BLOB_HOLDERS,
            }
        );
    }

    /// More holders than `u16::MAX` must name the **true** count — never
    /// clamp to `u16::MAX` and pretend the frame is merely "too high by 16".
    #[test]
    fn blob_locator_count_above_u16_reports_actual_len() {
        // Construct without going through serialize's holder URL loops for
        // every entry: validation runs on `holders.len()` first.
        let holders = vec!["https://x.example".into(); (u16::MAX as usize) + 1];
        let err = serialize_blob_locator_set(&BlobLocatorSet { holders }).expect_err("u16+1");
        assert!(
            matches!(
                &err,
                SpecError::BlobLocatorCountTooHigh { count, max }
                    if *count == (u16::MAX as usize) + 1 && *max == MAX_BLOB_HOLDERS
            ),
            "expected BlobLocatorCountTooHigh with actual count, got {err:?}"
        );
    }

    #[test]
    fn blob_locator_url_empty_malformed() {
        let set = BlobLocatorSet {
            holders: vec!["".into()],
        };
        let err = serialize_blob_locator_set(&set).expect_err("empty url");
        assert_eq!(err, SpecError::BlobLocatorUrlEmpty { index: 0 });
        // Wire: holder_count=1, url_len=0.
        let err = deserialize_blob_locator_set(&[0x00, 0x01, 0x00, 0x00]).expect_err("wire empty");
        assert_eq!(err, SpecError::BlobLocatorUrlEmpty { index: 0 });
    }

    #[test]
    fn blob_locator_url_too_long_malformed() {
        let set = BlobLocatorSet {
            holders: vec!["x".repeat(MAX_HOLDER_URL_LEN + 1)],
        };
        let err = serialize_blob_locator_set(&set).expect_err("long");
        assert_eq!(
            err,
            SpecError::BlobLocatorUrlTooLong {
                index: 0,
                len: MAX_HOLDER_URL_LEN + 1,
            }
        );
    }

    #[test]
    fn blob_locator_url_len_overrun_malformed() {
        // count=1, url_len=5, only 2 bytes of URL.
        let bytes = [0x00, 0x01, 0x00, 0x05, b'a', b'b'];
        let err = deserialize_blob_locator_set(&bytes).expect_err("overrun");
        assert!(
            matches!(
                err,
                SpecError::BundleLengthOverrun {
                    context: "BlobLocatorSet.url",
                    declared: 5,
                    remaining: 2,
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn blob_locator_non_utf8_malformed() {
        let bytes = [0x00, 0x01, 0x00, 0x02, 0xFF, 0xFE];
        let err = deserialize_blob_locator_set(&bytes).expect_err("utf8");
        assert_eq!(err, SpecError::BlobLocatorInvalidUtf8 { index: 0 });
    }

    #[test]
    fn blob_locator_nul_malformed() {
        let set = BlobLocatorSet {
            holders: vec!["https://x\0y".into()],
        };
        // String can't hold NUL via normal UTF-8 Rust string from literal with \0 —
        // actually "\0" is valid in Rust strings.
        let err = serialize_blob_locator_set(&set).expect_err("nul");
        assert_eq!(err, SpecError::BlobLocatorUrlContainsNul { index: 0 });
    }

    #[test]
    fn blob_locator_trailing_bytes_malformed() {
        let mut bytes = serialize_blob_locator_set(&sample_holders()).expect("ser");
        bytes.push(0x00);
        let err = deserialize_blob_locator_set(&bytes).expect_err("trail");
        assert_eq!(
            err,
            SpecError::BundleTrailingBytes {
                context: "BlobLocatorSet",
                remaining: 1,
            }
        );
    }

    // -----------------------------------------------------------------------
    // SelfDeliveryRecordV1 malformed
    // -----------------------------------------------------------------------

    #[test]
    fn sdr_bad_magic_malformed() {
        let mut bytes =
            serialize_self_delivery_record(&sample_sdr(RecordKind::Receive, vec![], vec![]))
                .expect("ser");
        bytes[0] = b'X';
        let err = deserialize_self_delivery_record(&bytes).expect_err("magic");
        assert!(
            matches!(err, SpecError::SdrMagicInvalid { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn sdr_bad_version_malformed() {
        let mut bytes =
            serialize_self_delivery_record(&sample_sdr(RecordKind::Receive, vec![], vec![]))
                .expect("ser");
        bytes[4] = 0x02;
        let err = deserialize_self_delivery_record(&bytes).expect_err("version");
        assert_eq!(err, SpecError::SdrVersionInvalid { got: 0x02 });
    }

    #[test]
    fn sdr_bad_record_kind_malformed() {
        let mut bytes =
            serialize_self_delivery_record(&sample_sdr(RecordKind::Receive, vec![], vec![]))
                .expect("ser");
        bytes[5] = 0x00;
        let err = deserialize_self_delivery_record(&bytes).expect_err("kind");
        assert_eq!(err, SpecError::SdrRecordKindInvalid { got: 0x00 });
    }

    #[test]
    fn sdr_trailing_bytes_malformed() {
        let mut bytes =
            serialize_self_delivery_record(&sample_sdr(RecordKind::Receive, vec![], vec![]))
                .expect("ser");
        bytes.push(0xEE);
        let err = deserialize_self_delivery_record(&bytes).expect_err("trail");
        assert_eq!(
            err,
            SpecError::BundleTrailingBytes {
                context: "SelfDeliveryRecordV1",
                remaining: 1,
            }
        );
    }

    #[test]
    fn sdr_length_prefix_overrun_malformed() {
        let mut bytes =
            serialize_self_delivery_record(&sample_sdr(RecordKind::Mint, vec![], vec![]))
                .expect("ser");
        // magic(4)+ver(1)+kind(1)+counter(8)+prev(32) = 46; next is u32 AccountState len.
        bytes[46..50].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = deserialize_self_delivery_record(&bytes).expect_err("overrun");
        assert!(
            matches!(
                err,
                SpecError::BundleLengthOverrun {
                    context: "SDR.AccountState",
                    ..
                }
            ),
            "got {err:?}"
        );
    }

    #[test]
    fn sdr_truncated_fixed_field_malformed() {
        let bytes =
            serialize_self_delivery_record(&sample_sdr(RecordKind::Receive, vec![], vec![]))
                .expect("ser");
        let err = deserialize_self_delivery_record(&bytes[..10]).expect_err("trunc");
        assert!(
            matches!(err, SpecError::BundleTruncated { .. }),
            "got {err:?}"
        );
    }

    #[test]
    fn sdr_malformed_nested_blob_locator_set() {
        // Corrupt self_blob_locators: set holder_count to 0 at the end.
        let mut bytes =
            serialize_self_delivery_record(&sample_sdr(RecordKind::Receive, vec![], vec![]))
                .expect("ser");
        // Last BlobLocatorSet starts with u16 count; overwrite last-N.
        // sample_holders has 2 URLs; find the final count by re-parsing isn't
        // needed — the set is at the end, first two bytes of the set are count.
        // Compute set length from a known serialize.
        let set_bytes = serialize_blob_locator_set(&sample_holders()).unwrap();
        let set_start = bytes.len() - set_bytes.len();
        bytes[set_start] = 0;
        bytes[set_start + 1] = 0;
        let err = deserialize_self_delivery_record(&bytes).expect_err("nested bls");
        assert_eq!(err, SpecError::BlobLocatorCountZero);
    }

    #[test]
    fn sdr_wrong_width_account_state_inside_length_prefix() {
        // Valid outer length but inner AccountState wrong size.
        let sdr = sample_sdr(RecordKind::Receive, vec![], vec![]);
        let mut bytes = serialize_self_delivery_record(&sdr).expect("ser");
        // Replace AccountState payload with 3 zero bytes but keep a matching length.
        // Offset 46 = start of u32 len; set len=3, payload=3 zeros, then rest must
        // be rebuilt — simpler: parse_account_state rejects short body.
        let state = serialize_account_state(&sdr.account_state).unwrap();
        let state_off = 46;
        assert_eq!(
            u32::from_be_bytes(bytes[state_off..state_off + 4].try_into().unwrap()) as usize,
            state.len()
        );
        // Shrink declared length to 3 and leave garbage — overrun of subsequent
        // fields is fine; we want WrongLength from parse_account_state.
        bytes[state_off..state_off + 4].copy_from_slice(&3u32.to_be_bytes());
        // Don't remove payload bytes — length prefix says 3, so only 3 consumed.
        let err = deserialize_self_delivery_record(&bytes).expect_err("short state");
        assert!(matches!(err, SpecError::WrongLength { .. }), "got {err:?}");
    }

    /// Determinism is the `blob_id` promise: identical plaintext ⇒ identical
    /// ZBE ciphertext under the same `K_tx` ⇒ identical `blob_id = H(ct)`.
    #[test]
    fn determinism_underpins_blob_id_content_addressing() {
        let cp = sample_coin_proof(Some(IssuanceTerms {
            creator_pubkey: [9; 32],
            decimals: 8,
            issuance_version: 2,
            name: b"DET".to_vec(),
            cap_total: Some(100),
            terms_salt: Some([8; 32]),
        }));
        let s1 = serialize_coin_proof(&cp).unwrap();
        let s2 = serialize_coin_proof(&cp).unwrap();
        assert_eq!(s1, s2);
        // Same for the SDR path that content-addresses self-delivery.
        let sdr = sample_sdr(RecordKind::Send, vec![[1; 32]], vec![sample_output_ref()]);
        assert_eq!(
            serialize_self_delivery_record(&sdr).unwrap(),
            serialize_self_delivery_record(&sdr).unwrap()
        );
    }

    // -----------------------------------------------------------------------
    // Direct private-writer / edge-path coverage (validation-bypass arms)
    // -----------------------------------------------------------------------

    /// `write_blob_locator_set` re-checks count after a future caller skips
    /// `validate_blob_locator_set`: holders.len() in (MAX_BLOB_HOLDERS, u16::MAX].
    #[test]
    fn write_blob_locator_set_rejects_count_above_max_holders() {
        let holders = vec!["https://x.example".into(); MAX_BLOB_HOLDERS + 1];
        let set = BlobLocatorSet { holders };
        let mut out = Vec::new();
        let err = write_blob_locator_set(&set, &mut out).expect_err("max+1");
        assert_eq!(
            err,
            SpecError::BlobLocatorCountTooHigh {
                count: MAX_BLOB_HOLDERS + 1,
                max: MAX_BLOB_HOLDERS,
            }
        );
    }

    /// Same private writer: holders.len() > u16::MAX hits the try_from arm.
    #[test]
    fn write_blob_locator_set_rejects_count_above_u16() {
        let holders = vec!["https://x.example".into(); (u16::MAX as usize) + 1];
        let set = BlobLocatorSet { holders };
        let mut out = Vec::new();
        let err = write_blob_locator_set(&set, &mut out).expect_err("u16+1");
        assert_eq!(
            err,
            SpecError::BlobLocatorCountTooHigh {
                count: (u16::MAX as usize) + 1,
                max: MAX_BLOB_HOLDERS,
            }
        );
    }

    /// Holder URL whose UTF-8 byte length exceeds u16::MAX (validation bypass).
    #[test]
    fn write_blob_locator_set_rejects_url_above_u16() {
        let set = BlobLocatorSet {
            holders: vec!["x".repeat((u16::MAX as usize) + 1)],
        };
        let mut out = Vec::new();
        let err = write_blob_locator_set(&set, &mut out).expect_err("url u16+");
        assert_eq!(
            err,
            SpecError::BlobLocatorUrlTooLong {
                index: 0,
                len: (u16::MAX as usize) + 1,
            }
        );
    }

    /// Wire count > MAX_BLOB_HOLDERS is rejected on read (not only on write).
    #[test]
    fn read_blob_locator_set_count_above_max_holders() {
        // count = MAX_BLOB_HOLDERS + 1 = 17, no holder payloads needed.
        let bytes = [0x00, 0x11]; // u16 BE = 17
        let mut cur: &[u8] = &bytes;
        let err = read_blob_locator_set(&mut cur).expect_err("count 17");
        assert_eq!(
            err,
            SpecError::BlobLocatorCountTooHigh {
                count: MAX_BLOB_HOLDERS + 1,
                max: MAX_BLOB_HOLDERS,
            }
        );
    }

    /// Wire url_len > MAX_HOLDER_URL_LEN is rejected before reading the body.
    #[test]
    fn read_blob_locator_set_url_len_above_max() {
        let url_len = (MAX_HOLDER_URL_LEN + 1) as u16;
        let mut bytes = vec![0x00, 0x01]; // count = 1
        bytes.extend_from_slice(&url_len.to_be_bytes());
        // No body bytes — length check fires first.
        let mut cur: &[u8] = &bytes;
        let err = read_blob_locator_set(&mut cur).expect_err("url_len");
        assert_eq!(
            err,
            SpecError::BlobLocatorUrlTooLong {
                index: 0,
                len: MAX_HOLDER_URL_LEN + 1,
            }
        );
    }

    /// Wire URL containing a NUL byte is rejected.
    #[test]
    fn read_blob_locator_set_url_contains_nul() {
        let bytes = [0x00, 0x01, 0x00, 0x03, b'a', 0x00, b'b'];
        let mut cur: &[u8] = &bytes;
        let err = read_blob_locator_set(&mut cur).expect_err("nul");
        assert_eq!(err, SpecError::BlobLocatorUrlContainsNul { index: 0 });
    }

    /// v2 wire truncated after cap_total but before terms_salt maps to
    /// CoinProofAssetTermsVersionFieldsMismatch (not a generic truncate).
    #[test]
    fn asset_terms_v2_truncated_salt_on_wire_malformed() {
        let terms = IssuanceTerms {
            creator_pubkey: [0x09; 32],
            decimals: 1,
            issuance_version: 2,
            name: b"T".to_vec(),
            cap_total: Some(7),
            terms_salt: Some([0x77; 32]),
        };
        let mut bytes = serialize_coin_proof(&sample_coin_proof(Some(terms))).expect("ser");
        let ct_len = sample_coin_proof(None).ciphertext.len();
        // Keep cap(16), drop salt(32)+epk(32)+u32+ct+tag(32).
        let tail_after_cap = 32 + 32 + 4 + ct_len + 32;
        assert!(bytes.len() > tail_after_cap);
        bytes.truncate(bytes.len() - tail_after_cap);
        let err = deserialize_coin_proof(&bytes).expect_err("truncated salt");
        assert_eq!(
            err,
            SpecError::CoinProofAssetTermsVersionFieldsMismatch {
                issuance_version: 2,
                cap_fields_present: false,
            }
        );
    }

    /// out_ciphertext longer than u16::MAX is rejected on SDR serialize.
    #[test]
    fn sdr_output_ciphertext_above_u16_rejected() {
        let mut oref = sample_output_ref();
        oref.out_ciphertext = vec![0xAB; (u16::MAX as usize) + 1];
        let sdr = sample_sdr(RecordKind::Send, vec![], vec![oref]);
        let err = serialize_self_delivery_record(&sdr).expect_err("ct u16+");
        assert_eq!(
            err,
            SpecError::ByteStringTooLong {
                len: (u16::MAX as usize) + 1,
            }
        );
    }

    /// spent_or_folded_coin_ids longer than u16::MAX is rejected.
    #[test]
    fn sdr_spent_ids_above_u16_rejected() {
        let spent = vec![[0u8; 32]; (u16::MAX as usize) + 1];
        let sdr = sample_sdr(RecordKind::Send, spent, vec![]);
        let err = serialize_self_delivery_record(&sdr).expect_err("spent u16+");
        assert_eq!(
            err,
            SpecError::ByteStringTooLong {
                len: (u16::MAX as usize) + 1,
            }
        );
    }

    /// output_refs longer than u16::MAX is rejected.
    #[test]
    fn sdr_output_refs_above_u16_rejected() {
        let minimal = OutputRef {
            coin_id: [0; 32],
            blob_id: [0; 32],
            epk: [0; 32],
            out_ciphertext: vec![0x01],
            blob_locators: BlobLocatorSet {
                holders: vec!["h".into()],
            },
        };
        let outputs = vec![minimal; (u16::MAX as usize) + 1];
        let sdr = sample_sdr(RecordKind::Send, vec![], outputs);
        let err = serialize_self_delivery_record(&sdr).expect_err("refs u16+");
        assert_eq!(
            err,
            SpecError::ByteStringTooLong {
                len: (u16::MAX as usize) + 1,
            }
        );
    }

    /// `write_output_ref` rejects out_ciphertext longer than u16::MAX.
    #[test]
    fn write_output_ref_ciphertext_above_u16() {
        let oref = OutputRef {
            coin_id: [0; 32],
            blob_id: [0; 32],
            epk: [0; 32],
            out_ciphertext: vec![0xCD; (u16::MAX as usize) + 1],
            blob_locators: sample_holders(),
        };
        let mut out = Vec::new();
        let err = write_output_ref(&oref, &mut out).expect_err("ct");
        assert_eq!(
            err,
            SpecError::ByteStringTooLong {
                len: (u16::MAX as usize) + 1,
            }
        );
    }
}
