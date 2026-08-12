//! Reconstitute clause-10 [`ReceivedCoinSlot`]s from `fold_coin_ids`.
//!
//! ## Sources (normative split)
//!
//! From the **private-record store** (process mirror of `v1_decrypt_index`,
//! filled by the §4.4 path after durable write) — the §7.1 canonical
//! [`CoinProof`] for each coin id:
//!
//! - `coin`, `creating_proof` bytes, `inclusion_proof`, `creating_prev_ash`,
//!   `creating_nullifier`, `creating_nav_opening` (six of nine slot fields)
//!
//! From the **live NfLog** of this node's own scan (never from the CoinProof,
//! which does not and must not carry them):
//!
//! - `pos_create`, `creating_nav_inclusion`, `creating_nav_consistency`
//!
//! Missing any ingredient is a **named terminal** failure for the whole job —
//! no partial fold, no silent skip of a single coin (§2.1 clause 10).

use shared::spec_v1::bundle::{deserialize_coin_proof, CoinProof};
use shared::spec_v1::encoding::digest_to_bytes;
use shared::spec_v1::{self as host, LookupResult, NfLogEntry, SpendClassification};
use zkcoins_program::circuit::compliance::MAX_RX_COINS;
use zkcoins_prover::prover_bridge::{ComplianceProof, NavOpening, NullifierOpening};
use zkcoins_prover::state_engine::StateEngine;

use super::incoming::parse_inclusion_proof_wire;
use super::receive::{size_final_nav, ReceivedCoinSlot};
use crate::kernel::access::InMemoryPrivateIndex;
use crate::kernel::types::SubjectAddress;
use crate::v1::db_decrypt_index::get_by_subject_coin;
use sqlx::PgPool;

/// Live NfLog paths for one creating nullifier: position + inclusion + consistency.
type LiveNfLogPaths = (u64, Vec<host::HashDigest>, Vec<host::HashDigest>);

// ---------------------------------------------------------------------------
// Named errors — terminal job causes (never silent)
// ---------------------------------------------------------------------------

/// Why fold-coin reconstitution refused the whole transition.
///
/// Display text is diagnostic. Outward job classification uses the enum
/// identity (or a stable prefix in the encoded job error message).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReconstituteError {
    /// `fold_coin_ids` empty (admit should have refused; defence in depth).
    EmptyFoldCoinIds,
    /// More than [`MAX_RX_COINS`] fold ids (D11 / §2.5).
    TooManyFoldCoinIds { count: usize },
    /// Same coin id appears twice in `fold_coin_ids`.
    DuplicateCoinId { coin_id: [u8; 32] },
    /// No CoinProof for this id under the subject (process index + SQL).
    UnknownCoinId { coin_id: [u8; 32] },
    /// Creating nullifier is not §3.10 `completed` on the live NfLog
    /// (absent, wrong R, or not covered by `size_final`).
    CreatingNullifierNotCompleted { coin_id: [u8; 32], detail: String },
    /// CoinProof body decode / shape failure.
    CoinProofCorrupt { coin_id: [u8; 32], detail: String },
    /// Creating proof bytes rejected by the proof port.
    CreatingProofLoad { coin_id: [u8; 32], detail: String },
    /// Output inclusion wire / host bind failure.
    OutputInclusion { coin_id: [u8; 32], detail: String },
    /// NAV path construction failed against the live log.
    NavPath { coin_id: [u8; 32], detail: String },
    /// Coin recipient is not the receiving subject.
    RecipientMismatch {
        coin_id: [u8; 32],
        recipient: [u8; 32],
        subject: [u8; 32],
    },
    /// Durable store / index I/O.
    Store { detail: String },
}

impl std::fmt::Display for ReconstituteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyFoldCoinIds => {
                write!(f, "reconstitute: fold_coin_ids is empty")
            }
            Self::TooManyFoldCoinIds { count } => write!(
                f,
                "reconstitute: fold_coin_ids length {count} exceeds MAX_RX_COINS={MAX_RX_COINS} \
                 (D11 / §2.5); refusing (no silent truncate)"
            ),
            Self::DuplicateCoinId { coin_id } => write!(
                f,
                "reconstitute: duplicate fold_coin_id {}",
                hex::encode(coin_id)
            ),
            Self::UnknownCoinId { coin_id } => write!(
                f,
                "reconstitute: unknown coin_id {} (no CoinProof in private index / \
                 v1_decrypt_index for subject)",
                hex::encode(coin_id)
            ),
            Self::CreatingNullifierNotCompleted { coin_id, detail } => write!(
                f,
                "reconstitute: creating nullifier for coin {} is not completed on live NfLog: {detail}",
                hex::encode(coin_id)
            ),
            Self::CoinProofCorrupt { coin_id, detail } => write!(
                f,
                "reconstitute: CoinProof for {} corrupt: {detail}",
                hex::encode(coin_id)
            ),
            Self::CreatingProofLoad { coin_id, detail } => write!(
                f,
                "reconstitute: creating proof load for {} failed: {detail}",
                hex::encode(coin_id)
            ),
            Self::OutputInclusion { coin_id, detail } => write!(
                f,
                "reconstitute: output inclusion for {} failed: {detail}",
                hex::encode(coin_id)
            ),
            Self::NavPath { coin_id, detail } => write!(
                f,
                "reconstitute: NAV path for {} failed: {detail}",
                hex::encode(coin_id)
            ),
            Self::RecipientMismatch {
                coin_id,
                recipient,
                subject,
            } => write!(
                f,
                "reconstitute: coin {} recipient {} ≠ subject {}",
                hex::encode(coin_id),
                hex::encode(recipient),
                hex::encode(subject)
            ),
            Self::Store { detail } => write!(f, "reconstitute: store error: {detail}"),
        }
    }
}

impl std::error::Error for ReconstituteError {}

impl ReconstituteError {
    /// Stable machine-facing prefix for job error encoding (not parsed for
    /// control flow — identity is the enum / full Display).
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::EmptyFoldCoinIds
            | Self::TooManyFoldCoinIds { .. }
            | Self::DuplicateCoinId { .. } => "bounds_exceeded",
            Self::UnknownCoinId { .. } => "unknown_coin",
            Self::CreatingNullifierNotCompleted { .. } => "dependency_not_final",
            Self::RecipientMismatch { .. } => "malformed_request",
            Self::CoinProofCorrupt { .. }
            | Self::CreatingProofLoad { .. }
            | Self::OutputInclusion { .. }
            | Self::NavPath { .. }
            | Self::Store { .. } => "internal_error",
        }
    }
}

// ---------------------------------------------------------------------------
// fold_coin_ids shape (Begin-time MAX_RX_COINS gate — D11)
// ---------------------------------------------------------------------------

/// Validate fold-id list shape before any store / NfLog access.
pub(crate) fn validate_fold_coin_ids_shape(ids: &[[u8; 32]]) -> Result<(), ReconstituteError> {
    if ids.is_empty() {
        return Err(ReconstituteError::EmptyFoldCoinIds);
    }
    if ids.len() > MAX_RX_COINS {
        return Err(ReconstituteError::TooManyFoldCoinIds { count: ids.len() });
    }
    let mut seen = std::collections::BTreeSet::new();
    for id in ids {
        if !seen.insert(*id) {
            return Err(ReconstituteError::DuplicateCoinId { coin_id: *id });
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Canonical CoinProof load (process index → durable SQL)
// ---------------------------------------------------------------------------

/// Load §7.1 CoinProof bytes for `(subject, coin_id)`.
///
/// Process mirror first; durable `v1_decrypt_index` on miss so a cold process
/// still finds a verified receipt. Missing both → [`ReconstituteError::UnknownCoinId`].
pub(crate) async fn load_coin_proof_canonical(
    index: &InMemoryPrivateIndex,
    pool: &PgPool,
    subject: &SubjectAddress,
    coin_id: &[u8; 32],
) -> Result<Vec<u8>, ReconstituteError> {
    if let Some(bytes) = index
        .load_coin_proof_canonical(subject, coin_id)
        .map_err(|e| ReconstituteError::Store {
            detail: e.to_string(),
        })?
    {
        return Ok(bytes);
    }
    match get_by_subject_coin(pool, &subject.0, coin_id)
        .await
        .map_err(|e| ReconstituteError::Store {
            detail: format!("v1_decrypt_index: {e:#}"),
        })? {
        Some(row) => {
            if row.canonical.is_empty() {
                return Err(ReconstituteError::CoinProofCorrupt {
                    coin_id: *coin_id,
                    detail: "durable row has empty canonical body".into(),
                });
            }
            // Re-mirror so subsequent folds hit the process index.
            if let Err(mirror_err) =
                index.insert_record(crate::v1::db_decrypt_index::to_indexed_record(&row))
            {
                tracing::warn!(
                    coin_id = %hex::encode(coin_id),
                    error = %mirror_err,
                    "reconstitute: failed to re-mirror canonical CoinProof into process index (cache only)"
                );
            }
            Ok(row.canonical)
        }
        None => Err(ReconstituteError::UnknownCoinId { coin_id: *coin_id }),
    }
}

// ---------------------------------------------------------------------------
// Slot reconstitution
// ---------------------------------------------------------------------------

/// Build one [`ReceivedCoinSlot`] from a verified CoinProof + live NfLog.
///
/// `creating_proof` is already loaded via the production proof port
/// ([`ProverBridge::load_transition_proof_bytes`]) or a test-provided hollow
/// shell with the same public-input layout host clause-10 reads.
pub(crate) fn reconstitute_slot_from_coin_proof(
    engine: &StateEngine,
    cp: &CoinProof,
    creating_proof: ComplianceProof,
    subject: &[u8; 32],
) -> Result<ReceivedCoinSlot, ReconstituteError> {
    let coin_id = digest_to_bytes(&cp.coin.identifier);

    if &cp.coin.recipient.0 != subject {
        return Err(ReconstituteError::RecipientMismatch {
            coin_id,
            recipient: cp.coin.recipient.0,
            subject: *subject,
        });
    }

    let output_inclusion = parse_inclusion_proof_wire(&cp.inclusion_proof).map_err(|e| {
        ReconstituteError::OutputInclusion {
            coin_id,
            detail: e.to_string(),
        }
    })?;

    let creating_nullifier = NullifierOpening {
        public_key: cp.creating_nullifier.pk_create,
        signature_r: cp.creating_nullifier.r_create,
        r_prime: cp.creating_nullifier.r_prime_create,
    };

    let creating_nav_opening = NavOpening {
        nav: host::Nav {
            size: cp.nav_opening.size,
            mth: cp.nav_opening.mth,
        },
        nav_rand: cp.nav_opening.nav_rand,
    };

    let (pos_create, creating_nav_inclusion, creating_nav_consistency) =
        live_nflog_paths(engine, &creating_nullifier, &creating_nav_opening, &coin_id)?;

    Ok(ReceivedCoinSlot {
        coin: cp.coin.clone(),
        creating_proof,
        output_inclusion,
        creating_prev_ash: cp.creating_prev_ash,
        creating_nullifier,
        creating_nav_inclusion,
        pos_create,
        creating_nav_opening,
        creating_nav_consistency,
    })
}

/// `pos_create` + inclusion + consistency paths from the **live** NfLog only.
fn live_nflog_paths(
    engine: &StateEngine,
    creating_nullifier: &NullifierOpening,
    creating_nav_opening: &NavOpening,
    coin_id: &[u8; 32],
) -> Result<LiveNfLogPaths, ReconstituteError> {
    // §3.10 completed: first-occurrence of (Pk, R) AND covered by size_final.
    match engine.nflog().classify(
        creating_nullifier.public_key,
        creating_nullifier.signature_r,
    ) {
        SpendClassification::ValidFirstSpend => {}
        SpendClassification::RejectedDoubleSpend => {
            return Err(ReconstituteError::CreatingNullifierNotCompleted {
                coin_id: *coin_id,
                detail: "creating Pk present with a different R (double-spend loser)".into(),
            });
        }
        SpendClassification::Pending => {
            return Err(ReconstituteError::CreatingNullifierNotCompleted {
                coin_id: *coin_id,
                detail: "creating (Pk, R) absent from receiver NfLog (pending / not anchored)"
                    .into(),
            });
        }
    }

    let pos_create = match engine.nflog().lookup(creating_nullifier.public_key) {
        LookupResult::Present { pos, r, .. } => {
            if r != creating_nullifier.signature_r {
                return Err(ReconstituteError::CreatingNullifierNotCompleted {
                    coin_id: *coin_id,
                    detail: "NfLog first-occurrence R mismatches creating_nullifier.R".into(),
                });
            }
            pos
        }
        LookupResult::Absent => {
            return Err(ReconstituteError::CreatingNullifierNotCompleted {
                coin_id: *coin_id,
                detail: "creating Pk vanished between classify and lookup".into(),
            });
        }
    };

    let receiver_nav = size_final_nav(engine).map_err(|e| ReconstituteError::NavPath {
        coin_id: *coin_id,
        detail: format!("size_final_nav: {e:#}"),
    })?;

    if pos_create >= receiver_nav.size {
        return Err(ReconstituteError::CreatingNullifierNotCompleted {
            coin_id: *coin_id,
            detail: format!(
                "creating nullifier position {pos_create} not covered by size_final nav.size {} \
                 (not yet §3.10 completed / 6-confirmation-final)",
                receiver_nav.size
            ),
        });
    }

    let mirror = engine.nflog_mirror();
    if (mirror.len() as u64) < receiver_nav.size {
        return Err(ReconstituteError::NavPath {
            coin_id: *coin_id,
            detail: format!(
                "NfLog mirror length {} < size_final {}",
                mirror.len(),
                receiver_nav.size
            ),
        });
    }
    let prefix: Vec<NfLogEntry> = mirror
        .iter()
        .take(receiver_nav.size as usize)
        .map(|(_, e)| *e)
        .collect();

    let creating_nav_inclusion =
        host::inclusion_path(pos_create, &prefix).map_err(|e| ReconstituteError::NavPath {
            coin_id: *coin_id,
            detail: format!("inclusion_path(pos={pos_create}): {e}"),
        })?;

    let creating_nav_consistency = host::consistency_proof(creating_nav_opening.nav.size, &prefix)
        .map_err(|e| ReconstituteError::NavPath {
            coin_id: *coin_id,
            detail: format!(
                "consistency_proof(creating_nav.size={}): {e}",
                creating_nav_opening.nav.size
            ),
        })?;

    Ok((pos_create, creating_nav_inclusion, creating_nav_consistency))
}

/// Reconstitute every fold id into a clause-10 slot (ordered, all-or-nothing).
///
/// `load_proof` is the production proof port
/// ([`ProverBridge::load_transition_proof_bytes`]); tests inject a hollow
/// loader so host-only fixtures exercise the same NfLog path without a
/// multi-minute circuit build.
pub(crate) fn reconstitute_received_slots_with_loader<F, L>(
    engine: &StateEngine,
    subject: &[u8; 32],
    fold_coin_ids: &[[u8; 32]],
    mut load_canonical: L,
    mut load_proof: F,
) -> Result<Vec<ReceivedCoinSlot>, ReconstituteError>
where
    L: FnMut(&[u8; 32]) -> Result<Vec<u8>, ReconstituteError>,
    F: FnMut(&[u8]) -> Result<ComplianceProof, ReconstituteError>,
{
    validate_fold_coin_ids_shape(fold_coin_ids)?;

    let mut slots = Vec::with_capacity(fold_coin_ids.len());
    for coin_id in fold_coin_ids {
        let canonical = load_canonical(coin_id)?;
        let cp = deserialize_coin_proof(&canonical).map_err(|e| {
            ReconstituteError::CoinProofCorrupt {
                coin_id: *coin_id,
                detail: e.to_string(),
            }
        })?;
        let wire_id = digest_to_bytes(&cp.coin.identifier);
        if &wire_id != coin_id {
            return Err(ReconstituteError::CoinProofCorrupt {
                coin_id: *coin_id,
                detail: format!(
                    "canonical CoinProof.identifier {} ≠ fold_coin_id {}",
                    hex::encode(wire_id),
                    hex::encode(coin_id)
                ),
            });
        }
        let creating_proof = load_proof(&cp.proof).map_err(|e| match e {
            ReconstituteError::CreatingProofLoad { .. } => e,
            other => ReconstituteError::CreatingProofLoad {
                coin_id: *coin_id,
                detail: other.to_string(),
            },
        })?;
        let slot = reconstitute_slot_from_coin_proof(engine, &cp, creating_proof, subject)?;
        slots.push(slot);
    }
    Ok(slots)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::access::{IndexedRecord, InsertRecordOutcome, RecordType};
    use crate::kernel::types::Digest32;
    use crate::v1::separation::{set_process_stack_mode, ScanStackMode};
    use plonky2::field::polynomial::PolynomialCoeffs;
    use plonky2::field::types::Field;
    use plonky2::fri::proof::FriProof;
    use plonky2::hash::merkle_tree::MerkleCap;
    use plonky2::plonk::proof::{OpeningSet, Proof, ProofWithPublicInputs};
    use shared::spec_v1::bundle::{
        serialize_coin_proof, CreatingNullifier, NavOpening as BundleNav,
    };
    use shared::spec_v1::{Address, Coin, ProofData, TreeKind};
    use zkcoins_program::circuit::compliance::Network;
    use zkcoins_program::F;
    use zkcoins_prover::prover_bridge::test_signing::{
        deterministic_secret, normalized_key, sign_transition,
    };
    use zkcoins_prover::prover_bridge::OutputInclusionProof;
    use zkcoins_prover::state_engine::{ScannedNullifier, StateEngine};

    fn digest_label(tag: &[u8]) -> host::HashDigest {
        host::digest_from_bytes(&{
            let mut h = [0u8; 32];
            let n = tag.len().min(32);
            h[..n].copy_from_slice(&tag[..n]);
            h
        })
        .expect("digest")
    }

    fn hollow_proof(pd: &ProofData, consumed_pubkey: [u8; 32]) -> ComplianceProof {
        let mut public_inputs = vec![F::ZERO; 108];
        let write_digest = |pis: &mut [F], offset: usize, d: host::HashDigest| {
            for (i, el) in d.elements.iter().enumerate() {
                pis[offset + i] = *el;
            }
        };
        write_digest(&mut public_inputs, 0, pd.new_account_state_hash);
        write_digest(&mut public_inputs, 4, pd.output_coins_root);
        write_digest(&mut public_inputs, 8, pd.input_nullifiers_root);
        write_digest(&mut public_inputs, 12, pd.coin_history_root);
        write_digest(&mut public_inputs, 16, pd.nav_commitment);
        for i in 0..8 {
            let start = 28 - 4 * i;
            let limb = u32::from_be_bytes(pd.npk_commit[start..start + 4].try_into().unwrap());
            public_inputs[20 + i] = F::from_canonical_u32(limb);
        }
        for i in 0..8 {
            let start = 28 - 4 * i;
            let limb = u32::from_be_bytes(consumed_pubkey[start..start + 4].try_into().unwrap());
            public_inputs[28 + i] = F::from_canonical_u32(limb);
        }
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
            public_inputs,
        }
    }

    fn serialize_inclusion_wire(incl: &OutputInclusionProof) -> Vec<u8> {
        let mut out = Vec::with_capacity(5 + incl.siblings.len() * 32);
        out.extend_from_slice(&incl.leaf_index.to_be_bytes());
        out.push(incl.depth);
        for s in &incl.siblings {
            out.extend_from_slice(&digest_to_bytes(s));
        }
        out
    }

    /// Host-valid coin + folded creating nullifier (same fixture shape as
    /// `receive::tests::slot_host_valid_from_folded`).
    fn plant_folded_coin(
        engine: &mut StateEngine,
        owner: Address,
        tag: u8,
    ) -> (CoinProof, ComplianceProof, [u8; 32]) {
        let (sk, pk_pt, create_pk) = normalized_key(deterministic_secret(&[b'K', tag, b's', b'k']));
        let creating_prev_ash = digest_label(&[b'p', tag]);
        let asset_id = host::asset_id_v1(host::GENESIS_TAG, &create_pk, &[tag; 32], 2, 1);
        let amount = 10u128 + u128::from(tag);
        let coin_id = host::coin_identifier(creating_prev_ash, &owner.0, asset_id, amount, 0);
        let coin = Coin {
            identifier: coin_id,
            recipient: owner,
            amount,
            asset_id,
        };
        let ocr = host::merkle_root(TreeKind::CoinsRoot, &[coin_id]);
        let empty_nav = host::Nav {
            size: 0,
            mth: host::nflog_empty(),
        };
        let nav_rand = [tag; 32];
        let pd = ProofData {
            new_account_state_hash: digest_label(&[b'a', tag]),
            output_coins_root: ocr,
            input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
            coin_history_root: host::coinhist_empty_root(),
            nav_commitment: host::nav_commitment(empty_nav.root(), &nav_rand),
            npk_commit: [tag; 32],
        };
        let sig = sign_transition(sk, pk_pt, &pd, Network::Regtest);
        let r = sig.transition.signature_r();
        let r_prime = sig.transition.r_prime;
        assert_eq!(sig.transition.pk_i, create_pk);

        // Fold creating nullifier with tip past finality.
        // ChainPosition.height / StateEngine tip are u64 (scan heights).
        let height = 20u64 + u64::from(tag);
        engine
            .append_nullifier(ScannedNullifier::from_survivor(
                &shared::spec_v1::PublishedNullifier {
                    chain_pos: host::ChainPosition {
                        height,
                        tx_index: 0,
                        vin_index: 0,
                        member_index: 0,
                    },
                    pk: create_pk,
                    r,
                },
            ))
            .expect("fold");
        engine.set_tip_height(height + 10);

        let creating_proof = hollow_proof(&pd, create_pk);
        let inclusion = OutputInclusionProof {
            leaf_index: 0,
            depth: 0,
            siblings: Vec::new(),
        };
        let cp = CoinProof {
            coin,
            proof: vec![tag], // opaque; loader supplies hollow_proof
            inclusion_proof: serialize_inclusion_wire(&inclusion),
            creating_prev_ash,
            creating_nullifier: CreatingNullifier {
                pk_create: create_pk,
                r_create: r,
                r_prime_create: r_prime,
            },
            nav_opening: BundleNav {
                size: empty_nav.size,
                mth: empty_nav.mth,
                nav_rand,
            },
            asset_terms: None,
            epk: [tag | 0x80; 32],
            ciphertext: vec![0x01, 0x02],
            detect_tag: digest_label(&[b'd', tag]),
        };
        let id_bytes = digest_to_bytes(&coin_id);
        (cp, creating_proof, id_bytes)
    }

    #[test]
    fn shape_rejects_empty_too_many_and_duplicate() {
        assert!(matches!(
            validate_fold_coin_ids_shape(&[]),
            Err(ReconstituteError::EmptyFoldCoinIds)
        ));
        let many: Vec<[u8; 32]> = (0..=MAX_RX_COINS as u8).map(|i| [i; 32]).collect();
        assert!(matches!(
            validate_fold_coin_ids_shape(&many),
            Err(ReconstituteError::TooManyFoldCoinIds { count }) if count == MAX_RX_COINS + 1
        ));
        let dup = [[0xABu8; 32], [0xABu8; 32]];
        assert!(matches!(
            validate_fold_coin_ids_shape(&dup),
            Err(ReconstituteError::DuplicateCoinId { .. })
        ));
    }

    #[test]
    fn positive_reconstitute_completed_nullifier_yields_full_slot_and_begin() {
        set_process_stack_mode(ScanStackMode::V1);
        let mut engine = StateEngine::new(Network::Regtest, 0);
        let owner = Address([0xB0; 32]);
        let (cp, creating_proof, coin_id) = plant_folded_coin(&mut engine, owner, 1);
        let hollow = creating_proof.clone();

        let canonical = serialize_coin_proof(&cp).expect("ser");
        let slots = reconstitute_received_slots_with_loader(
            &engine,
            &owner.0,
            &[coin_id],
            |_| Ok(canonical.clone()),
            |_| Ok(hollow.clone()),
        )
        .expect("reconstitute");
        assert_eq!(slots.len(), 1);
        let slot = &slots[0];
        assert_eq!(digest_to_bytes(&slot.coin.identifier), coin_id);
        // Live NfLog position — not invented.
        match engine.nflog().lookup(cp.creating_nullifier.pk_create) {
            LookupResult::Present { pos, .. } => assert_eq!(slot.pos_create, pos),
            other => panic!("expected Present, got {other:?}"),
        }
        assert!(!slot.creating_nav_inclusion.is_empty() || slot.pos_create == 0);
        // Consistency path for empty creating nav is empty (m==0).
        assert!(slot.creating_nav_consistency.is_empty());

        // Same begin path as production_path_receive_with_genuine_prove_via_verify_and_begin.
        let nk = [0x11u8; 32];
        let op_secret = zkcoins_prover::state_engine::OpSecret::new([0x22; 32]);
        // InitialProof: owner must equal H(current_pubkey ‖ nk_commit).
        let (sk0, pk0_pt, pk0) = normalized_key(deterministic_secret(b"rx-recon-pk0"));
        let owner_bound = Address(host::address(&pk0, host::nk_commit(&nk)));
        // Re-plant coin for bound owner.
        let mut engine2 = StateEngine::new(Network::Regtest, 0);
        let (cp2, proof2, id2) = plant_folded_coin(&mut engine2, owner_bound, 2);
        let can2 = serialize_coin_proof(&cp2).expect("ser");
        let slots2 = reconstitute_received_slots_with_loader(
            &engine2,
            &owner_bound.0,
            &[id2],
            |_| Ok(can2.clone()),
            |_| Ok(proof2.clone()),
        )
        .expect("reconstitute bound");
        let pending = crate::v1::verify_and_begin_receive(
            &engine2,
            crate::v1::V1ReceiveRequest {
                owner: owner_bound,
                nk,
                op_secret,
                current_pubkey: pk0,
                slots: slots2,
                next_pubkey: [0x33; 32],
                npk_rand: [0x44; 32],
            },
        )
        .expect("verify_and_begin_receive is the production begin path");
        assert_eq!(
            pending.mode,
            zkcoins_prover::prover_bridge::TransitionMode::InitialProof
        );
        let _ = (sk0, pk0_pt); // signing reserved for ignore-tests
    }

    #[test]
    fn unknown_coin_id_is_named() {
        set_process_stack_mode(ScanStackMode::V1);
        let engine = StateEngine::new(Network::Regtest, 0);
        let subject = [0x5Au8; 32];
        let missing = [0xDE; 32];
        let err = reconstitute_received_slots_with_loader(
            &engine,
            &subject,
            &[missing],
            |_| Err(ReconstituteError::UnknownCoinId { coin_id: missing }),
            |_| unreachable!("must not load proof for unknown coin"),
        )
        .expect_err("unknown");
        assert!(matches!(
            err,
            ReconstituteError::UnknownCoinId { coin_id } if coin_id == missing
        ));
        assert!(err.to_string().contains("unknown coin_id"));
    }

    #[test]
    fn nullifier_not_completed_is_named() {
        set_process_stack_mode(ScanStackMode::V1);
        // Engine with tip but no fold of the creating nullifier.
        let engine = StateEngine::new(Network::Regtest, 0);
        let owner = Address([0xB1; 32]);
        let mut engine_plant = StateEngine::new(Network::Regtest, 0);
        let (cp, proof, coin_id) = plant_folded_coin(&mut engine_plant, owner, 3);
        // Use cp/proof against empty engine → creating nullifier pending.
        let can = serialize_coin_proof(&cp).expect("ser");
        let err = reconstitute_received_slots_with_loader(
            &engine,
            &owner.0,
            &[coin_id],
            |_| Ok(can.clone()),
            |_| Ok(proof.clone()),
        )
        .expect_err("not completed");
        assert!(matches!(
            err,
            ReconstituteError::CreatingNullifierNotCompleted { .. }
        ));
        assert!(err.to_string().contains("not completed"));
    }

    #[test]
    fn process_index_load_finds_planted_coin() {
        let index = InMemoryPrivateIndex::new();
        let subject = SubjectAddress([0xCCu8; 32]);
        let coin_id = Digest32([0xDDu8; 32]);
        let body = vec![0x01, 0x02, 0x03];
        let rec = IndexedRecord {
            subject,
            record_id: Digest32([0x01; 32]),
            asset_id: Digest32([0x02; 32]),
            occurred_at: 1,
            record_type: RecordType::CoinProof,
            transition_kind: None,
            blob_id: Digest32([0x03; 32]),
            canonical: Some(body.clone()),
            coin_id: Some(coin_id),
        };
        assert_eq!(
            index.insert_record(rec).expect("insert"),
            InsertRecordOutcome::Inserted
        );
        let loaded = index
            .load_coin_proof_canonical(&subject, &coin_id.0)
            .expect("load")
            .expect("present");
        assert_eq!(loaded, body);
        let missing = index
            .load_coin_proof_canonical(&subject, &[0xEE; 32])
            .expect("load miss");
        assert!(missing.is_none());
    }
}
