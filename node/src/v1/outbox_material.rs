//! Versioned rebuild material for durable outbox rows.
//!
//! Stored as JSON (UTF-8) under `v1_delivery_outbox.material`. Opaque proof
//! bytes and fixed-width digests are lowercase hex — never invented keys.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use shared::spec_v1::bundle::{CreatingNullifier, NavOpening as BundleNavOpening};
use shared::spec_v1::datastructures::Coin;
use shared::spec_v1::encoding::{digest_from_bytes, digest_to_bytes};
use shared::spec_v1::serialize::{deserialize_coin, serialize_coin};

use super::delivery::OutgoingCoinMaterial;

/// Wire version tag — bump only with a matching decoder branch.
const MATERIAL_VERSION: u8 = 1;

/// External-coin rebuild material (no operational secrets).
///
/// `op_sk` / `ovk` stay process-local in BundleStore; resume requires a
/// re-entrusted operational bundle for `subject`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct ExternalOutboxMaterial {
    pub v: u8,
    /// `serialize(Coin)` — 112-byte hex.
    pub coin_hex: String,
    pub leaf_index: u32,
    /// Output-coin identifiers of the creating transition (32-byte hex each).
    pub all_output_ids_hex: Vec<String>,
    pub proof_bytes_hex: String,
    pub creating_prev_ash_hex: String,
    pub creating_nullifier_hex: String,
    pub nav_size: u64,
    pub nav_mth_hex: String,
    pub nav_rand_hex: String,
    pub recipient_ivpk_hex: String,
    pub recipient_op_pk_hex: String,
    pub recipient_relays: Vec<String>,
    pub blob_holders: Vec<String>,
    pub max_blob_bytes: u64,
}

/// One SDR `output_ref` staged at Phase A (blob already content-addressed).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SdrPhaseAOutputRef {
    pub coin_id_hex: String,
    pub blob_id_hex: String,
    pub epk_hex: String,
    /// UTF-8 of NIP-44 Base64 payload (`out_ciphertext`).
    pub out_ciphertext_hex: String,
    pub holders: Vec<String>,
}

/// Phase-A staging material: everything known before first-occurrence MTP.
///
/// Keyed in Postgres by `transition_pk` (nullifier Pk). Phase B fills
/// `inclusion_block` + `occurred_at`, seals `serialize(SelfDeliveryRecordV1)`,
/// and inserts [`SdrOutboxMaterial`] into the delivery outbox.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SdrPhaseAMaterial {
    pub v: u8,
    pub subject_hex: String,
    pub transition_pk_hex: String,
    /// `RecordKind` wire byte: 0x01 mint / 0x02 send / 0x03 receive.
    pub record_kind: u8,
    /// Post-transition `send_counter` on the new account state.
    pub send_counter: u64,
    pub prev_state_head_hex: String,
    /// `serialize(AccountState)` of the post-transition state.
    pub account_state_hex: String,
    pub recursive_proof_hex: String,
    /// 192-byte `serialize(ProofData)`.
    pub proof_data_hex: String,
    pub own_nullifier_pk_hex: String,
    pub own_nullifier_r_hex: String,
    pub own_nullifier_r_prime_hex: String,
    pub proof_block_anchor_hash_hex: String,
    pub proof_block_anchor_height: u32,
    pub spent_or_folded_coin_ids_hex: Vec<String>,
    pub output_refs: Vec<SdrPhaseAOutputRef>,
    pub blob_holders: Vec<String>,
    pub max_blob_bytes: u64,
    pub recipient_ivpk_hex: String,
    pub recipient_op_pk_hex: String,
    pub recipient_relays: Vec<String>,
}

/// SDR Phase-B material: already-finalised ZBE ciphertext + delivery targets.
///
/// Inserted only after first-occurrence MTP is known and
/// `serialize(SelfDeliveryRecordV1)` has been sealed (§4.2 Phase B). The
/// recovery *replay* path that reloads SDR replicas remains a named gap
/// (`recovery::SdrReplayStatus::Unavailable`).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub(crate) struct SdrOutboxMaterial {
    pub v: u8,
    pub zbe_ciphertext_hex: String,
    pub blob_id_hex: String,
    pub detect_tag_hex: String,
    /// Ephemeral x-only pubkey that produced `detect_tag` / `k_tx` (scan tags).
    pub epk_hex: String,
    pub k_tx_hex: String,
    pub recipient_ivpk_hex: String,
    pub recipient_op_pk_hex: String,
    pub recipient_relays: Vec<String>,
    pub blob_holders: Vec<String>,
    pub max_blob_bytes: u64,
    /// Post-transition send_counter (audit / ordering).
    pub send_counter: u64,
    /// `RecordKind` wire byte for the kind-1420 payload (0x01/0x02/0x03).
    pub record_kind: u8,
}

impl ExternalOutboxMaterial {
    pub(crate) fn from_outgoing(
        material: &OutgoingCoinMaterial,
        blob_holders: &[String],
        max_blob_bytes: u64,
    ) -> Self {
        let coin_bytes = serialize_coin(&material.coin);
        let mut nf = [0u8; 96];
        nf[..32].copy_from_slice(&material.creating_nullifier.pk_create);
        nf[32..64].copy_from_slice(&material.creating_nullifier.r_create);
        nf[64..].copy_from_slice(&material.creating_nullifier.r_prime_create);
        Self {
            v: MATERIAL_VERSION,
            coin_hex: hex::encode(coin_bytes),
            leaf_index: material.leaf_index,
            all_output_ids_hex: material
                .all_output_ids
                .iter()
                .map(|d| hex::encode(digest_to_bytes(d)))
                .collect(),
            proof_bytes_hex: hex::encode(&material.proof_bytes),
            creating_prev_ash_hex: hex::encode(digest_to_bytes(&material.creating_prev_ash)),
            creating_nullifier_hex: hex::encode(nf),
            nav_size: material.nav_opening.size,
            nav_mth_hex: hex::encode(digest_to_bytes(&material.nav_opening.mth)),
            nav_rand_hex: hex::encode(material.nav_opening.nav_rand),
            recipient_ivpk_hex: hex::encode(material.recipient_ivpk),
            recipient_op_pk_hex: hex::encode(material.recipient_op_pk),
            recipient_relays: material.recipient_relays.clone(),
            blob_holders: blob_holders.to_vec(),
            max_blob_bytes,
        }
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if self.v != MATERIAL_VERSION {
            bail!(
                "ExternalOutboxMaterial: refuse encode of unexpected version {}",
                self.v
            );
        }
        serde_json::to_vec(self).context("encode ExternalOutboxMaterial JSON")
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let m: Self =
            serde_json::from_slice(bytes).context("decode ExternalOutboxMaterial JSON")?;
        if m.v != MATERIAL_VERSION {
            bail!(
                "ExternalOutboxMaterial: unsupported version {} (want {MATERIAL_VERSION})",
                m.v
            );
        }
        Ok(m)
    }

    /// Rebuild [`OutgoingCoinMaterial`] for mesh publish / republish.
    pub(crate) fn to_outgoing(&self) -> Result<OutgoingCoinMaterial> {
        let coin_bytes = parse_hex_fixed::<112>(&self.coin_hex, "coin")?;
        let coin: Coin = deserialize_coin(&coin_bytes)
            .map_err(|e| anyhow::anyhow!("ExternalOutboxMaterial coin: {e}"))?;
        let mut all_output_ids = Vec::with_capacity(self.all_output_ids_hex.len());
        for (i, h) in self.all_output_ids_hex.iter().enumerate() {
            let b = parse_hex32(h).with_context(|| format!("all_output_ids[{i}]"))?;
            all_output_ids.push(
                digest_from_bytes(&b)
                    .map_err(|e| anyhow::anyhow!("all_output_ids[{i}] digest: {e}"))?,
            );
        }
        let proof_bytes = parse_hex_vec(&self.proof_bytes_hex, "proof_bytes")?;
        if proof_bytes.is_empty() {
            bail!("ExternalOutboxMaterial: empty proof_bytes");
        }
        let prev = parse_hex32(&self.creating_prev_ash_hex).context("creating_prev_ash")?;
        let creating_prev_ash = digest_from_bytes(&prev)
            .map_err(|e| anyhow::anyhow!("creating_prev_ash digest: {e}"))?;
        let nf = parse_hex_fixed::<96>(&self.creating_nullifier_hex, "creating_nullifier")?;
        let mut pk_create = [0u8; 32];
        let mut r_create = [0u8; 32];
        let mut r_prime_create = [0u8; 32];
        pk_create.copy_from_slice(&nf[..32]);
        r_create.copy_from_slice(&nf[32..64]);
        r_prime_create.copy_from_slice(&nf[64..]);
        let nav_mth_b = parse_hex32(&self.nav_mth_hex).context("nav_mth")?;
        let nav_mth =
            digest_from_bytes(&nav_mth_b).map_err(|e| anyhow::anyhow!("nav_mth digest: {e}"))?;
        let nav_rand = parse_hex32(&self.nav_rand_hex).context("nav_rand")?;
        let recipient_ivpk = parse_hex32(&self.recipient_ivpk_hex).context("recipient_ivpk")?;
        let recipient_op_pk = parse_hex32(&self.recipient_op_pk_hex).context("recipient_op_pk")?;
        if self.recipient_relays.is_empty() {
            bail!("ExternalOutboxMaterial: empty recipient_relays");
        }
        if self.blob_holders.is_empty() {
            bail!("ExternalOutboxMaterial: empty blob_holders");
        }
        Ok(OutgoingCoinMaterial {
            coin,
            leaf_index: self.leaf_index,
            all_output_ids,
            proof_bytes,
            creating_prev_ash,
            creating_nullifier: CreatingNullifier {
                pk_create,
                r_create,
                r_prime_create,
            },
            nav_opening: BundleNavOpening {
                size: self.nav_size,
                mth: nav_mth,
                nav_rand,
            },
            asset_terms: None,
            recipient_ivpk,
            recipient_op_pk,
            recipient_relays: self.recipient_relays.clone(),
        })
    }
}

impl SdrPhaseAMaterial {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate_complete()
            .context("SdrPhaseAMaterial: refuse encode of incomplete material")?;
        if self.v != MATERIAL_VERSION {
            bail!(
                "SdrPhaseAMaterial: refuse encode of unexpected version {}",
                self.v
            );
        }
        serde_json::to_vec(self).context("encode SdrPhaseAMaterial JSON")
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let m: Self = serde_json::from_slice(bytes).context("decode SdrPhaseAMaterial JSON")?;
        if m.v != MATERIAL_VERSION {
            bail!(
                "SdrPhaseAMaterial: unsupported version {} (want {MATERIAL_VERSION})",
                m.v
            );
        }
        m.validate_complete()
            .context("SdrPhaseAMaterial: incomplete after decode")?;
        Ok(m)
    }

    /// Fail-closed completeness gate: every field Phase B needs must be present.
    pub(crate) fn validate_complete(&self) -> Result<()> {
        if self.subject_hex.is_empty()
            || self.transition_pk_hex.is_empty()
            || self.prev_state_head_hex.is_empty()
            || self.account_state_hex.is_empty()
            || self.recursive_proof_hex.is_empty()
            || self.proof_data_hex.is_empty()
            || self.own_nullifier_pk_hex.is_empty()
            || self.own_nullifier_r_hex.is_empty()
            || self.own_nullifier_r_prime_hex.is_empty()
            || self.proof_block_anchor_hash_hex.is_empty()
            || self.recipient_ivpk_hex.is_empty()
            || self.recipient_op_pk_hex.is_empty()
        {
            bail!("SdrPhaseAMaterial: required hex field empty");
        }
        if !matches!(self.record_kind, 0x01..=0x03) {
            bail!(
                "SdrPhaseAMaterial: record_kind 0x{:02x} not mint/send/receive",
                self.record_kind
            );
        }
        if self.recipient_relays.is_empty() {
            bail!("SdrPhaseAMaterial: empty recipient_relays");
        }
        if self.blob_holders.is_empty() {
            bail!("SdrPhaseAMaterial: empty blob_holders");
        }
        for (i, o) in self.output_refs.iter().enumerate() {
            if o.coin_id_hex.is_empty()
                || o.blob_id_hex.is_empty()
                || o.epk_hex.is_empty()
                || o.out_ciphertext_hex.is_empty()
                || o.holders.is_empty()
            {
                bail!("SdrPhaseAMaterial: output_refs[{i}] incomplete");
            }
        }
        Ok(())
    }
}

impl SdrOutboxMaterial {
    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        if self.v != MATERIAL_VERSION {
            bail!(
                "SdrOutboxMaterial: refuse encode of unexpected version {}",
                self.v
            );
        }
        if self.zbe_ciphertext_hex.is_empty()
            || self.blob_id_hex.is_empty()
            || self.detect_tag_hex.is_empty()
            || self.epk_hex.is_empty()
            || self.k_tx_hex.is_empty()
            || self.recipient_ivpk_hex.is_empty()
            || self.recipient_op_pk_hex.is_empty()
            || self.recipient_relays.is_empty()
            || self.blob_holders.is_empty()
        {
            bail!("SdrOutboxMaterial: refuse encode of incomplete material");
        }
        if !matches!(self.record_kind, 0x01..=0x03) {
            bail!(
                "SdrOutboxMaterial: record_kind 0x{:02x} not mint/send/receive",
                self.record_kind
            );
        }
        serde_json::to_vec(self).context("encode SdrOutboxMaterial JSON")
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let m: Self = serde_json::from_slice(bytes).context("decode SdrOutboxMaterial JSON")?;
        if m.v != MATERIAL_VERSION {
            bail!(
                "SdrOutboxMaterial: unsupported version {} (want {MATERIAL_VERSION})",
                m.v
            );
        }
        if m.zbe_ciphertext_hex.is_empty()
            || m.blob_id_hex.is_empty()
            || m.detect_tag_hex.is_empty()
            || m.epk_hex.is_empty()
            || m.k_tx_hex.is_empty()
            || m.recipient_ivpk_hex.is_empty()
            || m.recipient_op_pk_hex.is_empty()
            || m.recipient_relays.is_empty()
            || m.blob_holders.is_empty()
        {
            bail!("SdrOutboxMaterial: incomplete after decode");
        }
        if !matches!(m.record_kind, 0x01..=0x03) {
            bail!(
                "SdrOutboxMaterial: record_kind 0x{:02x} not mint/send/receive",
                m.record_kind
            );
        }
        Ok(m)
    }
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex_vec(s, "hex32")?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes, got {}", bytes.len()))?;
    Ok(arr)
}

fn parse_hex_fixed<const N: usize>(s: &str, field: &str) -> Result<[u8; N]> {
    let bytes = parse_hex_vec(s, field)?;
    let arr: [u8; N] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field}: expected {N} bytes, got {}", bytes.len()))?;
    Ok(arr)
}

fn parse_hex_vec(s: &str, field: &str) -> Result<Vec<u8>> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    if !s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        bail!("{field}: non-lowercase-hex");
    }
    hex::decode(s).with_context(|| format!("{field}: hex decode"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared::spec_v1::datastructures::Address;
    use shared::spec_v1::encoding::digest_from_bytes;

    fn sample_outgoing() -> OutgoingCoinMaterial {
        let id = digest_from_bytes(&[0x71; 32]).expect("id");
        let asset = digest_from_bytes(&[0xA1; 32]).expect("asset");
        let prev = digest_from_bytes(&[0xB1; 32]).expect("prev");
        let mth = digest_from_bytes(&[0xC1; 32]).expect("mth");
        OutgoingCoinMaterial {
            coin: Coin {
                identifier: id,
                recipient: Address([0x52; 32]),
                amount: 7,
                asset_id: asset,
            },
            leaf_index: 0,
            all_output_ids: vec![id],
            proof_bytes: vec![0x01, 0x02, 0x03],
            creating_prev_ash: prev,
            creating_nullifier: CreatingNullifier {
                pk_create: [0x11; 32],
                r_create: [0x22; 32],
                r_prime_create: [0x33; 32],
            },
            nav_opening: BundleNavOpening {
                size: 9,
                mth,
                nav_rand: [0x44; 32],
            },
            asset_terms: None,
            recipient_ivpk: [0x55; 32],
            recipient_op_pk: [0x66; 32],
            recipient_relays: vec!["wss://relay.example".into()],
        }
    }

    #[test]
    fn external_material_roundtrip() {
        let out = sample_outgoing();
        let m = ExternalOutboxMaterial::from_outgoing(
            &out,
            &["https://blossom.example".into()],
            1_048_576,
        );
        let bytes = m.encode().expect("encode");
        let back = ExternalOutboxMaterial::decode(&bytes).expect("decode");
        let rebuilt = back.to_outgoing().expect("to_outgoing");
        assert_eq!(rebuilt.coin, out.coin);
        assert_eq!(rebuilt.leaf_index, out.leaf_index);
        assert_eq!(rebuilt.proof_bytes, out.proof_bytes);
        assert_eq!(rebuilt.recipient_ivpk, out.recipient_ivpk);
        assert_eq!(rebuilt.recipient_relays, out.recipient_relays);
        assert_eq!(
            back.blob_holders,
            vec!["https://blossom.example".to_string()]
        );
        assert_eq!(back.max_blob_bytes, 1_048_576);
    }

    #[test]
    fn external_material_rejects_bad_version() {
        let mut m = ExternalOutboxMaterial::from_outgoing(
            &sample_outgoing(),
            &["https://h.example".into()],
            100,
        );
        m.v = 99;
        let bytes = serde_json::to_vec(&m).expect("ser");
        let err = ExternalOutboxMaterial::decode(&bytes).expect_err("version");
        assert!(err.to_string().contains("unsupported version"));
    }

    fn sample_sdr_phase_a() -> SdrPhaseAMaterial {
        SdrPhaseAMaterial {
            v: MATERIAL_VERSION,
            subject_hex: hex::encode([0x11u8; 32]),
            transition_pk_hex: hex::encode([0x22u8; 32]),
            record_kind: 0x02,
            send_counter: 3,
            prev_state_head_hex: hex::encode([0x33u8; 32]),
            account_state_hex: hex::encode([0xAAu8; 140]),
            recursive_proof_hex: hex::encode([0x01u8, 0x02, 0x03]),
            proof_data_hex: hex::encode([0xBBu8; 192]),
            own_nullifier_pk_hex: hex::encode([0x22u8; 32]),
            own_nullifier_r_hex: hex::encode([0x44u8; 32]),
            own_nullifier_r_prime_hex: hex::encode([0x55u8; 32]),
            proof_block_anchor_hash_hex: hex::encode([0x66u8; 32]),
            proof_block_anchor_height: 100,
            spent_or_folded_coin_ids_hex: vec![hex::encode([0x77u8; 32])],
            output_refs: vec![SdrPhaseAOutputRef {
                coin_id_hex: hex::encode([0x88u8; 32]),
                blob_id_hex: hex::encode([0x99u8; 32]),
                epk_hex: hex::encode([0xAAu8; 32]),
                out_ciphertext_hex: hex::encode(b"out-ct"),
                holders: vec!["https://blossom.example".into()],
            }],
            blob_holders: vec!["https://blossom.example".into()],
            max_blob_bytes: 1_048_576,
            recipient_ivpk_hex: hex::encode([0xBBu8; 32]),
            recipient_op_pk_hex: hex::encode([0xCCu8; 32]),
            recipient_relays: vec!["wss://relay.example".into()],
        }
    }

    #[test]
    fn sdr_phase_a_roundtrip() {
        let m = sample_sdr_phase_a();
        let bytes = m.encode().expect("encode");
        let back = SdrPhaseAMaterial::decode(&bytes).expect("decode");
        assert_eq!(back, m);
    }

    #[test]
    fn sdr_phase_a_refuses_incomplete() {
        let mut m = sample_sdr_phase_a();
        m.account_state_hex.clear();
        let err = m.encode().expect_err("incomplete");
        assert!(
            err.to_string().contains("incomplete") || err.to_string().contains("empty"),
            "got {err}"
        );
    }

    #[test]
    fn sdr_outbox_material_roundtrip() {
        let m = SdrOutboxMaterial {
            v: MATERIAL_VERSION,
            zbe_ciphertext_hex: hex::encode([0x01u8, 0x02, 0x03]),
            blob_id_hex: hex::encode([0xAAu8; 32]),
            detect_tag_hex: hex::encode([0xBBu8; 32]),
            epk_hex: hex::encode([0xEFu8; 32]),
            k_tx_hex: hex::encode([0xCCu8; 32]),
            recipient_ivpk_hex: hex::encode([0xDDu8; 32]),
            recipient_op_pk_hex: hex::encode([0xEEu8; 32]),
            recipient_relays: vec!["wss://r.example".into()],
            blob_holders: vec!["https://h.example".into()],
            max_blob_bytes: 1024,
            send_counter: 7,
            record_kind: 0x02,
        };
        let bytes = m.encode().expect("encode");
        let back = SdrOutboxMaterial::decode(&bytes).expect("decode");
        assert_eq!(back, m);
    }

    #[test]
    fn sdr_outbox_material_refuses_incomplete() {
        let m = SdrOutboxMaterial {
            v: MATERIAL_VERSION,
            zbe_ciphertext_hex: String::new(),
            blob_id_hex: hex::encode([0xAAu8; 32]),
            detect_tag_hex: hex::encode([0xBBu8; 32]),
            epk_hex: hex::encode([0xEFu8; 32]),
            k_tx_hex: hex::encode([0xCCu8; 32]),
            recipient_ivpk_hex: hex::encode([0xDDu8; 32]),
            recipient_op_pk_hex: hex::encode([0xEEu8; 32]),
            recipient_relays: vec!["wss://r.example".into()],
            blob_holders: vec!["https://h.example".into()],
            max_blob_bytes: 1024,
            send_counter: 7,
            record_kind: 0x02,
        };
        let err = m.encode().expect_err("incomplete");
        assert!(err.to_string().contains("incomplete"), "got {err}");
    }
}
