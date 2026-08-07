//! Trustless node-side verifier for `BalanceAttestationV1` (§5.7 / §7.1).
//!
//! G1: exact inverse of `serialize_balance_attestation_v1`.
//! G2: independent host checks against the caller's own fresh `Scanner`
//! scan — never against producer-node state or attestation-supplied authority
//! for its own anchor/nav_ceiling facts.
//!
//! `decoded.balance` (and every other wire-header field) is intentionally not
//! re-derived host-side from private account state: it is bound by re-extracting
//! the proof's own 60 public inputs and comparing them field-by-field to the
//! decoded header (check 2.5). Without that binding, a valid proof for statement
//! X could be paired with a header claiming statement Y. There is no host-visible
//! per-account NAV opening on the wire.

use bitcoin::hashes::Hash;
use shared::spec_v1::{digest_from_bytes, Address, HashDigest};
use zkcoins_prover::prover_bridge::{BalanceAnchor, BalancePublicStatement};
use zkcoins_prover::scanner::Scanner;
use zkcoins_prover::verifier_cache::CachedBalanceVerifier;

use super::attest::{
    accept_c_balance_network_binding, require_completed_anchor_independent, AttestError,
};

/// Decoded `BalanceAttestationV1` (§7.1 wire form), the exact inverse of
/// `node::v1::attest::serialize_balance_attestation_v1`.
///
/// `nav_ceiling_root` is the disclosed 32-byte accumulator ROOT digest
/// (`Nav::root()` = `nflog_root(size, mth)`), NOT a raw `mth` — the wire format never carries
/// `mth` directly. `proof_bytes` is the RAW, still-undecoded `C_balance` proof encoding —
/// decoding it into a typed `BalanceProof` requires a network-specific
/// `CachedBalanceVerifier` (Plonky2's `ProofWithPublicInputs::from_bytes` needs
/// `CommonCircuitData`), so that step is deferred to
/// `verify_balance_attestation`, which already takes a `&CachedBalanceVerifier`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedBalanceAttestation {
    pub subject: Address,
    pub asset_id: HashDigest,
    pub balance: u128,
    pub nav_ceiling_root: HashDigest,
    pub size_ceiling: u64,
    pub anchor: BalanceAnchor,
    pub network_id: HashDigest,
    pub proof_bytes: Vec<u8>,
}

/// Decode failures for `BalanceAttestationV1` (fail-closed, named per class).
#[derive(Debug)]
pub enum DecodeBalanceAttestationError {
    /// Byte slice shorter than the fixed 292-byte prefix, or shorter than
    /// `292 + declared proof_len`.
    Truncated { need: usize, have: usize },
    /// Byte slice longer than `292 + declared proof_len` — no trailing-byte tolerance.
    TrailingBytes { expected_total: usize, have: usize },
    /// `asset_id` / `nav_ceiling_root` / `network_id` field failed the canonical
    /// Poseidon-digest decode (`shared::spec_v1::digest_from_bytes`: a limb was >= field order).
    NonCanonicalDigest {
        field: &'static str,
        source: shared::spec_v1::SpecError,
    },
}

impl std::fmt::Display for DecodeBalanceAttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeBalanceAttestationError::Truncated { need, have } => {
                write!(
                    f,
                    "BalanceAttestationV1 truncated: need at least {need} bytes, have {have}"
                )
            }
            DecodeBalanceAttestationError::TrailingBytes {
                expected_total,
                have,
            } => {
                write!(
                    f,
                    "BalanceAttestationV1 has trailing bytes: expected total {expected_total}, have {have}"
                )
            }
            DecodeBalanceAttestationError::NonCanonicalDigest { field, source } => {
                write!(
                    f,
                    "BalanceAttestationV1 field `{field}` is not a canonical Poseidon digest: {source}"
                )
            }
        }
    }
}

impl std::error::Error for DecodeBalanceAttestationError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            DecodeBalanceAttestationError::NonCanonicalDigest { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Exact byte-offset table this function inverts (fixed 292-byte prefix + `proof_len` trailing
/// bytes), copied from `serialize_balance_attestation_v1` (node/src/v1/attest.rs:663-694):
///
/// | field            | offset | len | source in serializer                                    |
/// |------------------|-------:|----:|----------------------------------------------------------|
/// | subject          |      0 |  32 | `statement.subject.0`                                    |
/// | asset_id         |     32 |  32 | `digest_to_bytes(&statement.asset_id)`                   |
/// | balance          |     64 |  16 | `statement.balance.to_be_bytes()` (u128 BE)              |
/// | nav_ceiling_root |     80 |  32 | `digest_to_bytes(&statement.nav_ceiling.root())`         |
/// | size_ceiling     |    112 |   8 | `statement.nav_ceiling.size.to_be_bytes()` (u64 BE)      |
/// | anchor.txid      |    120 |  32 | `statement.anchor.txid` (raw)                            |
/// | anchor.block_hash|    152 |  32 | `statement.anchor.block_hash` (raw)                      |
/// | anchor.height    |    184 |   8 | `statement.anchor.height.to_be_bytes()` (u64 BE)         |
/// | anchor.public_key|    192 |  32 | `statement.anchor.public_key` (raw)                      |
/// | anchor.signature_r|   224 |  32 | `statement.anchor.signature_r` (raw)                     |
/// | network_id       |    256 |  32 | `digest_to_bytes(&nid)`                                  |
/// | proof_len        |    288 |   4 | `(proof_bytes.len() as u32).to_be_bytes()` (u32 BE)      |
/// | proof            |    292 | proof_len | raw `proof_bytes`                                  |
///
/// Strict: rejects if `bytes.len() < 292`, rejects if `bytes.len() != 292 + proof_len` (no
/// trailing-byte tolerance either direction), rejects if any of the three digest fields is not a
/// canonical Poseidon digest (via `shared::spec_v1::digest_from_bytes`, which already rejects any
/// 8-byte BE limb >= the Goldilocks field order — do not re-implement that check, call it).
pub fn decode_balance_attestation_v1(
    bytes: &[u8],
) -> Result<DecodedBalanceAttestation, DecodeBalanceAttestationError> {
    const FIXED_PREFIX: usize = 292;

    if bytes.len() < FIXED_PREFIX {
        return Err(DecodeBalanceAttestationError::Truncated {
            need: FIXED_PREFIX,
            have: bytes.len(),
        });
    }

    let mut subject_arr = [0u8; 32];
    subject_arr.copy_from_slice(&bytes[0..32]);

    let mut asset_id_arr = [0u8; 32];
    asset_id_arr.copy_from_slice(&bytes[32..64]);
    let asset_id = digest_from_bytes(&asset_id_arr).map_err(|source| {
        DecodeBalanceAttestationError::NonCanonicalDigest {
            field: "asset_id",
            source,
        }
    })?;

    let mut balance_arr = [0u8; 16];
    balance_arr.copy_from_slice(&bytes[64..80]);
    let balance = u128::from_be_bytes(balance_arr);

    let mut nav_root_arr = [0u8; 32];
    nav_root_arr.copy_from_slice(&bytes[80..112]);
    let nav_ceiling_root = digest_from_bytes(&nav_root_arr).map_err(|source| {
        DecodeBalanceAttestationError::NonCanonicalDigest {
            field: "nav_ceiling_root",
            source,
        }
    })?;

    let mut size_arr = [0u8; 8];
    size_arr.copy_from_slice(&bytes[112..120]);
    let size_ceiling = u64::from_be_bytes(size_arr);

    let mut txid = [0u8; 32];
    txid.copy_from_slice(&bytes[120..152]);
    let mut block_hash = [0u8; 32];
    block_hash.copy_from_slice(&bytes[152..184]);
    let mut height_arr = [0u8; 8];
    height_arr.copy_from_slice(&bytes[184..192]);
    let height = u64::from_be_bytes(height_arr);
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes[192..224]);
    let mut signature_r = [0u8; 32];
    signature_r.copy_from_slice(&bytes[224..256]);

    let mut network_id_arr = [0u8; 32];
    network_id_arr.copy_from_slice(&bytes[256..288]);
    let network_id = digest_from_bytes(&network_id_arr).map_err(|source| {
        DecodeBalanceAttestationError::NonCanonicalDigest {
            field: "network_id",
            source,
        }
    })?;

    let mut proof_len_arr = [0u8; 4];
    proof_len_arr.copy_from_slice(&bytes[288..292]);
    let proof_len = u32::from_be_bytes(proof_len_arr) as usize;
    let expected_total = FIXED_PREFIX
        .checked_add(proof_len)
        .expect("proof_len as usize cannot overflow FIXED_PREFIX + proof_len on 64-bit");
    if bytes.len() < expected_total {
        return Err(DecodeBalanceAttestationError::Truncated {
            need: expected_total,
            have: bytes.len(),
        });
    }
    if bytes.len() > expected_total {
        return Err(DecodeBalanceAttestationError::TrailingBytes {
            expected_total,
            have: bytes.len(),
        });
    }

    let proof_bytes = bytes[FIXED_PREFIX..expected_total].to_vec();

    Ok(DecodedBalanceAttestation {
        subject: Address(subject_arr),
        asset_id,
        balance,
        nav_ceiling_root,
        size_ceiling,
        anchor: BalanceAnchor {
            txid,
            block_hash,
            height,
            public_key,
            signature_r,
        },
        network_id,
        proof_bytes,
    })
}

/// Verify failures for the §5.7 host checks (named per check / sub-check class).
#[derive(Debug, PartialEq, Eq)]
pub enum VerifyBalanceAttestationError {
    /// Check 1: network_id mismatch or live circuit digest != pinned digest for `network`.
    NetworkBinding(String),
    /// Check 2: proof bytes did not parse against the pinned circuit, or Plonky2 verify failed.
    ProofInvalid(String),
    /// The proof's OWN public inputs (re-extracted, never trusted from the header) do not equal the
    /// corresponding decoded header field — the proof proves a different statement than the header
    /// claims. `field` names exactly one of: subject, asset_id, balance, nav_ceiling, size_ceiling,
    /// anchor_txid, anchor_block_hash, anchor_height, anchor_pk, anchor_r, network_id.
    PublicInputMismatch { field: &'static str },
    /// Check 3, first-occurrence/finality sub-check (delegates to
    /// `require_completed_anchor_independent`).
    AnchorNotCompleted(String),
    /// Check 3, chain-position tie sub-check: disclosed (txid, block_hash, height) does not match
    /// what the independent scan actually observed for the winning (Pk_anchor, R_anchor).
    AnchorLocatorMismatch(String),
    /// Check 4a: `size_ceiling` exceeds the independent scan's own `size_final`.
    SizeCeilingExceedsFinal(String),
    /// Check 4b: `nav_ceiling_root` is not the canonical root the independent scan computes for
    /// `size_ceiling`.
    NavCeilingNotCanonical(String),
}

impl std::fmt::Display for VerifyBalanceAttestationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyBalanceAttestationError::NetworkBinding(m) => {
                write!(f, "network binding check failed: {m}")
            }
            VerifyBalanceAttestationError::ProofInvalid(m) => {
                write!(f, "C_balance proof invalid: {m}")
            }
            VerifyBalanceAttestationError::PublicInputMismatch { field } => {
                write!(
                    f,
                    "proof public input `{field}` does not match the decoded header"
                )
            }
            VerifyBalanceAttestationError::AnchorNotCompleted(m) => {
                write!(f, "anchor is not completed on independent scan: {m}")
            }
            VerifyBalanceAttestationError::AnchorLocatorMismatch(m) => {
                write!(f, "anchor locator mismatch vs independent scan: {m}")
            }
            VerifyBalanceAttestationError::SizeCeilingExceedsFinal(m) => {
                write!(f, "size_ceiling exceeds independent size_final: {m}")
            }
            VerifyBalanceAttestationError::NavCeilingNotCanonical(m) => {
                write!(
                    f,
                    "nav_ceiling_root is not canonical on independent scan: {m}"
                )
            }
        }
    }
}

impl std::error::Error for VerifyBalanceAttestationError {}

/// Bind every one of the `C_balance` proof's own 60 public inputs (as re-extracted by
/// `CachedBalanceVerifier::verify_attestation`, never a header/wrapper claim) to the decoded wire
/// header.
/// Without this, a valid proof for statement X could be paired with a header claiming statement
/// Y and pass every other check — see module-level exploit note above `verify_balance_attestation`.
fn public_inputs_match_header(
    extracted: &BalancePublicStatement,
    decoded: &DecodedBalanceAttestation,
) -> Result<(), VerifyBalanceAttestationError> {
    if extracted.subject != decoded.subject {
        return Err(VerifyBalanceAttestationError::PublicInputMismatch { field: "subject" });
    }
    if extracted.asset_id != decoded.asset_id {
        return Err(VerifyBalanceAttestationError::PublicInputMismatch { field: "asset_id" });
    }
    if extracted.balance != decoded.balance {
        return Err(VerifyBalanceAttestationError::PublicInputMismatch { field: "balance" });
    }
    if extracted.nav_ceiling != decoded.nav_ceiling_root {
        return Err(VerifyBalanceAttestationError::PublicInputMismatch {
            field: "nav_ceiling",
        });
    }
    if extracted.size_ceiling != decoded.size_ceiling {
        return Err(VerifyBalanceAttestationError::PublicInputMismatch {
            field: "size_ceiling",
        });
    }
    if extracted.anchor.txid != decoded.anchor.txid {
        return Err(VerifyBalanceAttestationError::PublicInputMismatch {
            field: "anchor_txid",
        });
    }
    if extracted.anchor.block_hash != decoded.anchor.block_hash {
        return Err(VerifyBalanceAttestationError::PublicInputMismatch {
            field: "anchor_block_hash",
        });
    }
    if extracted.anchor.height != decoded.anchor.height {
        return Err(VerifyBalanceAttestationError::PublicInputMismatch {
            field: "anchor_height",
        });
    }
    if extracted.anchor.public_key != decoded.anchor.public_key {
        return Err(VerifyBalanceAttestationError::PublicInputMismatch { field: "anchor_pk" });
    }
    if extracted.anchor.signature_r != decoded.anchor.signature_r {
        return Err(VerifyBalanceAttestationError::PublicInputMismatch { field: "anchor_r" });
    }
    if extracted.network_id != decoded.network_id {
        return Err(VerifyBalanceAttestationError::PublicInputMismatch {
            field: "network_id",
        });
    }
    Ok(())
}

/// Independently verify a decoded `BalanceAttestationV1` against `scanner` — a `Scanner` the
/// CALLER connected and scanned itself (its own bitcoind RPC, its own fresh
/// `NfLogAccumulator`). `tip_height` is the height that scan reached (e.g. `ScanReport.tip_height`
/// from the `scan_to_tip()` call that produced `scanner`'s current state) — passed explicitly
/// (not re-derived inside this function) so the caller controls exactly which scan state this
/// check runs against and the function stays a pure, testable predicate over its inputs.
/// `bridge` must be a `CachedBalanceVerifier` for the SAME network the attestation claims; this
/// function does not construct one — `network` is read from `bridge.network()`, never taken as a
/// separate parameter (avoids a `network != bridge.network()` inconsistency).
///
/// Runs, in order, fail-closed at the first failure (§5.7):
/// 1. network binding — `decoded.network_id` matches `bridge.network()` AND
///    `bridge.balance_circuit_digest_bytes()` matches the pinned `C_balance` digest for that
///    network (reuses `attest::accept_c_balance_network_binding`, the SAME gate the producer
///    uses — not a re-implementation).
/// 2. Plonky2 proof validity — `bridge.load_balance_proof_bytes(&decoded.proof_bytes)` then
///    `bridge.verify_attestation(&proof)`, which re-extracts the proof's own 60 public inputs.
/// 2.5. public-input ↔ header binding — every field of the extracted
///    [`BalancePublicStatement`] must equal the corresponding decoded header field. Without this,
///    a valid proof for statement X can be paired with a header claiming statement Y (anchor/NAV
///    checks only validate the header against the chain, not that the header is the statement the
///    proof actually proves).
/// 3. anchor host-check, entirely against `scanner`'s own independent state:
///    a. `attest::require_completed_anchor_independent(decoded.anchor.public_key,
///       decoded.anchor.signature_r, scanner.accumulator(), tip_height)` — first occurrence +
///       inside size_final (the SAME logic the producer's `require_completed_anchor` encodes,
///       generalised to an independent accumulator handle).
///    b. `scanner.winner_chain_position(decoded.anchor.public_key)` must be `Some(chain_pos)`
///       with `chain_pos.height == decoded.anchor.height`.
///    c. among `scanner.accepted_inscriptions()`, find the one with matching
///       `(height, tx_index, vin_index) == (chain_pos.height, chain_pos.tx_index,
///       chain_pos.vin_index)`; its `members[chain_pos.member_index as usize]` must equal
///       `(decoded.anchor.public_key, decoded.anchor.signature_r)`; its `reveal_txid` must equal
///       `decoded.anchor.txid`.
///    d. `scanner.block_hash_at_height(chain_pos.height)` must be `Some(hash)` with
///       `hash.to_byte_array() == decoded.anchor.block_hash`.
/// 4. nav_ceiling canonicality, entirely against `scanner.accumulator()`:
///    a. `decoded.size_ceiling <= scanner.accumulator().size_final(tip_height)`.
///    b. `scanner.accumulator().root_at(decoded.size_ceiling)` must be `Some(root)` with
///       `root == decoded.nav_ceiling_root`.
///
/// # Exploit closed by check 2.5
///
/// An adversary who has one honestly-produced valid `C_balance` proof for a trivial self-
/// attestation could previously re-serialize a `BalanceAttestationV1` with a different header
/// (victim subject, inflated balance, a different but genuinely-completed anchor, a different
/// but genuinely-canonical NAV) and the same unmodified proof bytes. Checks 1–4 would all pass
/// because 2 only verified proof validity and 3/4 only checked the header against independent
/// chain facts. Binding every proof public input to the header closes that gap.
// The doc above is an intentional nested check list (steps 1, 2, 2.5, 3a-d,
// 4a-b): the sub-item continuations are indented to line up under their
// parent for source readability, which clippy's overindented-list-items
// style lint flags without any rustdoc rendering problem. Allowed here only.
#[allow(clippy::doc_overindented_list_items, clippy::doc_lazy_continuation)]
pub fn verify_balance_attestation(
    decoded: &DecodedBalanceAttestation,
    scanner: &Scanner,
    tip_height: u64,
    bridge: &CachedBalanceVerifier,
) -> Result<(), VerifyBalanceAttestationError> {
    // --- Check 1: network binding (reuse producer gate) ---
    let network = bridge.network();
    let live = bridge.balance_circuit_digest_bytes();
    accept_c_balance_network_binding(&decoded.network_id, &live, network).map_err(|e| match e {
        AttestError::ProvingFailed(m) | AttestError::CircuitDigestMismatch(m) => {
            VerifyBalanceAttestationError::NetworkBinding(m)
        }
        other => VerifyBalanceAttestationError::NetworkBinding(other.message().to_string()),
    })?;

    // --- Check 2: Plonky2 proof parse + verify (returns proof's own public inputs) ---
    let proof = bridge
        .load_balance_proof_bytes(&decoded.proof_bytes)
        .map_err(|e| {
            VerifyBalanceAttestationError::ProofInvalid(format!(
                "load_balance_proof_bytes failed: {e:#}"
            ))
        })?;
    let extracted = bridge.verify_attestation(&proof).map_err(|e| {
        VerifyBalanceAttestationError::ProofInvalid(format!("verify_attestation failed: {e:#}"))
    })?;

    // --- Check 2.5: bind every proof public input to the decoded header (see module doc /
    // PublicInputMismatch doc — without this a valid proof for a different statement could be
    // paired with this header and pass every other check). ---
    public_inputs_match_header(&extracted, decoded)?;

    // --- Check 3a: completed first-occurrence anchor on independent NfLog ---
    require_completed_anchor_independent(
        decoded.anchor.public_key,
        decoded.anchor.signature_r,
        scanner.accumulator(),
        tip_height,
    )
    .map_err(|e| match e {
        AttestError::ProvingFailed(m) | AttestError::Internal(m) => {
            VerifyBalanceAttestationError::AnchorNotCompleted(m)
        }
        other => VerifyBalanceAttestationError::AnchorNotCompleted(other.message().to_string()),
    })?;

    // --- Check 3b: winner chain position height matches disclosed height ---
    let chain_pos = scanner
        .winner_chain_position(decoded.anchor.public_key)
        .ok_or_else(|| {
            VerifyBalanceAttestationError::AnchorLocatorMismatch(
                "independent scan has no winner_chain_position for disclosed Pk_anchor".into(),
            )
        })?;
    if chain_pos.height != decoded.anchor.height {
        return Err(VerifyBalanceAttestationError::AnchorLocatorMismatch(
            format!(
                "independent winner height {} != disclosed anchor.height {}",
                chain_pos.height, decoded.anchor.height
            ),
        ));
    }

    // --- Check 3c: inscription (txid, members) at winner (height, tx_index, vin_index) ---
    let inscription = scanner
        .accepted_inscriptions()
        .iter()
        .find(|ins| {
            ins.height == chain_pos.height
                && ins.tx_index == chain_pos.tx_index
                && ins.vin_index == chain_pos.vin_index
        })
        .ok_or_else(|| {
            VerifyBalanceAttestationError::AnchorLocatorMismatch(format!(
                "no accepted_inscription at independent winner position \
                 height={} tx_index={} vin_index={}",
                chain_pos.height, chain_pos.tx_index, chain_pos.vin_index
            ))
        })?;

    let member_index = chain_pos.member_index as usize;
    let (member_pk, member_r) = inscription.members.get(member_index).ok_or_else(|| {
        VerifyBalanceAttestationError::AnchorLocatorMismatch(format!(
            "inscription at winner position has {} members; member_index {member_index} out of range",
            inscription.members.len()
        ))
    })?;
    if *member_pk != decoded.anchor.public_key || *member_r != decoded.anchor.signature_r {
        return Err(VerifyBalanceAttestationError::AnchorLocatorMismatch(
            format!(
            "inscription members[{member_index}] does not equal disclosed (Pk_anchor, R_anchor)"
        ),
        ));
    }
    if inscription.reveal_txid != decoded.anchor.txid {
        return Err(VerifyBalanceAttestationError::AnchorLocatorMismatch(
            "inscription reveal_txid does not equal disclosed anchor.txid".into(),
        ));
    }

    // --- Check 3d: block hash observed by THIS scan at winner height ---
    let observed_hash = scanner
        .block_hash_at_height(chain_pos.height)
        .ok_or_else(|| {
            VerifyBalanceAttestationError::AnchorLocatorMismatch(format!(
                "independent scan has no block_hash_at_height for winner height {}",
                chain_pos.height
            ))
        })?;
    if observed_hash.to_byte_array() != decoded.anchor.block_hash {
        return Err(VerifyBalanceAttestationError::AnchorLocatorMismatch(
            "independent scan block hash at winner height does not equal disclosed \
             anchor.block_hash"
                .into(),
        ));
    }

    // --- Check 4a: size_ceiling within independent size_final ---
    let size_final = scanner.accumulator().size_final(tip_height);
    if decoded.size_ceiling > size_final {
        return Err(VerifyBalanceAttestationError::SizeCeilingExceedsFinal(
            format!(
                "disclosed size_ceiling {} > independent size_final {size_final} \
                 (tip_height={tip_height})",
                decoded.size_ceiling
            ),
        ));
    }

    // --- Check 4b: nav_ceiling_root is the independent canonical root at size_ceiling ---
    let expected_root = scanner
        .accumulator()
        .root_at(decoded.size_ceiling)
        .ok_or_else(|| {
            VerifyBalanceAttestationError::NavCeilingNotCanonical(format!(
                "independent accumulator root_at({}) returned None \
                 (size exceeds folded log length)",
                decoded.size_ceiling
            ))
        })?;
    if expected_root != decoded.nav_ceiling_root {
        return Err(VerifyBalanceAttestationError::NavCeilingNotCanonical(
            format!(
                "disclosed nav_ceiling_root does not match independent root_at({})",
                decoded.size_ceiling
            ),
        ));
    }

    Ok(())
}

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;

    fn sample_public_statement() -> BalancePublicStatement {
        BalancePublicStatement {
            subject: Address([0x01u8; 32]),
            asset_id: digest_from_bytes(&[0x02u8; 32]).expect("canonical"),
            balance: 100u128,
            nav_ceiling: digest_from_bytes(&[0x03u8; 32]).expect("canonical"),
            size_ceiling: 7u64,
            anchor: BalanceAnchor {
                txid: [0x31u8; 32],
                block_hash: [0x42u8; 32],
                height: 555u64,
                public_key: [0x11u8; 32],
                signature_r: [0x22u8; 32],
            },
            network_id: digest_from_bytes(&[0x04u8; 32]).expect("canonical"),
        }
    }

    /// Header that exactly matches `sample_public_statement()` field-for-field. `proof_bytes` is
    /// irrelevant to this pure check — empty is fine.
    fn matching_decoded(extracted: &BalancePublicStatement) -> DecodedBalanceAttestation {
        DecodedBalanceAttestation {
            subject: extracted.subject,
            asset_id: extracted.asset_id,
            balance: extracted.balance,
            nav_ceiling_root: extracted.nav_ceiling,
            size_ceiling: extracted.size_ceiling,
            anchor: extracted.anchor,
            network_id: extracted.network_id,
            proof_bytes: Vec::new(),
        }
    }

    #[test]
    fn public_inputs_match_header_accepts_exact_match() {
        let extracted = sample_public_statement();
        let decoded = matching_decoded(&extracted);
        assert_eq!(public_inputs_match_header(&extracted, &decoded), Ok(()));
    }

    #[test]
    fn public_inputs_match_header_rejects_tampered_subject() {
        let extracted = sample_public_statement();
        let mut decoded = matching_decoded(&extracted);
        decoded.subject = Address([0xffu8; 32]);
        assert_eq!(
            public_inputs_match_header(&extracted, &decoded),
            Err(VerifyBalanceAttestationError::PublicInputMismatch { field: "subject" })
        );
    }

    #[test]
    fn public_inputs_match_header_rejects_tampered_asset_id() {
        let extracted = sample_public_statement();
        let mut decoded = matching_decoded(&extracted);
        decoded.asset_id = digest_from_bytes(&[0xEEu8; 32]).expect("canonical");
        assert_eq!(
            public_inputs_match_header(&extracted, &decoded),
            Err(VerifyBalanceAttestationError::PublicInputMismatch { field: "asset_id" })
        );
    }

    #[test]
    fn public_inputs_match_header_rejects_tampered_balance() {
        let extracted = sample_public_statement();
        let mut decoded = matching_decoded(&extracted);
        decoded.balance = u128::MAX;
        assert_eq!(
            public_inputs_match_header(&extracted, &decoded),
            Err(VerifyBalanceAttestationError::PublicInputMismatch { field: "balance" })
        );
    }

    #[test]
    fn public_inputs_match_header_rejects_tampered_nav_ceiling() {
        let extracted = sample_public_statement();
        let mut decoded = matching_decoded(&extracted);
        decoded.nav_ceiling_root = digest_from_bytes(&[0xDDu8; 32]).expect("canonical");
        assert_eq!(
            public_inputs_match_header(&extracted, &decoded),
            Err(VerifyBalanceAttestationError::PublicInputMismatch {
                field: "nav_ceiling"
            })
        );
    }

    #[test]
    fn public_inputs_match_header_rejects_tampered_size_ceiling() {
        let extracted = sample_public_statement();
        let mut decoded = matching_decoded(&extracted);
        decoded.size_ceiling = u64::MAX;
        assert_eq!(
            public_inputs_match_header(&extracted, &decoded),
            Err(VerifyBalanceAttestationError::PublicInputMismatch {
                field: "size_ceiling"
            })
        );
    }

    #[test]
    fn public_inputs_match_header_rejects_tampered_anchor_txid() {
        let extracted = sample_public_statement();
        let mut decoded = matching_decoded(&extracted);
        decoded.anchor.txid = [0xffu8; 32];
        assert_eq!(
            public_inputs_match_header(&extracted, &decoded),
            Err(VerifyBalanceAttestationError::PublicInputMismatch {
                field: "anchor_txid"
            })
        );
    }

    #[test]
    fn public_inputs_match_header_rejects_tampered_anchor_block_hash() {
        let extracted = sample_public_statement();
        let mut decoded = matching_decoded(&extracted);
        decoded.anchor.block_hash = [0xffu8; 32];
        assert_eq!(
            public_inputs_match_header(&extracted, &decoded),
            Err(VerifyBalanceAttestationError::PublicInputMismatch {
                field: "anchor_block_hash"
            })
        );
    }

    #[test]
    fn public_inputs_match_header_rejects_tampered_anchor_height() {
        let extracted = sample_public_statement();
        let mut decoded = matching_decoded(&extracted);
        decoded.anchor.height = u64::MAX;
        assert_eq!(
            public_inputs_match_header(&extracted, &decoded),
            Err(VerifyBalanceAttestationError::PublicInputMismatch {
                field: "anchor_height"
            })
        );
    }

    #[test]
    fn public_inputs_match_header_rejects_tampered_anchor_pk() {
        let extracted = sample_public_statement();
        let mut decoded = matching_decoded(&extracted);
        decoded.anchor.public_key = [0xffu8; 32];
        assert_eq!(
            public_inputs_match_header(&extracted, &decoded),
            Err(VerifyBalanceAttestationError::PublicInputMismatch { field: "anchor_pk" })
        );
    }

    #[test]
    fn public_inputs_match_header_rejects_tampered_anchor_r() {
        let extracted = sample_public_statement();
        let mut decoded = matching_decoded(&extracted);
        decoded.anchor.signature_r = [0xffu8; 32];
        assert_eq!(
            public_inputs_match_header(&extracted, &decoded),
            Err(VerifyBalanceAttestationError::PublicInputMismatch { field: "anchor_r" })
        );
    }

    #[test]
    fn public_inputs_match_header_rejects_tampered_network_id() {
        let extracted = sample_public_statement();
        let mut decoded = matching_decoded(&extracted);
        decoded.network_id = digest_from_bytes(&[0xCCu8; 32]).expect("canonical");
        assert_eq!(
            public_inputs_match_header(&extracted, &decoded),
            Err(VerifyBalanceAttestationError::PublicInputMismatch {
                field: "network_id"
            })
        );
    }
}
