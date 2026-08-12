//! §4.2 SelfDeliveryRecordV1 two-phase finalisation.
//!
//! **Phase A** (finalise / send time): stage durable material keyed by the
//! transition nullifier Pk — everything known before first-occurrence MTP.
//!
//! **Phase B** (scanner hook): when the account's own nullifier is a
//! first-occurrence winner inside `size_final` (§3.10 `completed`), fill
//! `inclusion_block` + `occurred_at = MTP`, seal `serialize(SelfDeliveryRecordV1)`
//! under ZBE, and insert a `self_delivery` outbox row so the existing
//! Drive/Resume/Backoff machine publishes it.

use anyhow::{bail, Context, Result};
use bitcoin::hashes::Hash;
use bitcoin::BlockHash;
use bitcoincore_rpc::RpcApi;
use shared::spec_v1::accumulator::{LookupResult, SpendClassification};
use shared::spec_v1::bundle::BlobLocatorSet;
use shared::spec_v1::bundle::{
    serialize_self_delivery_record, BlockAnchor, CreatingNullifier, OutputRef, RecordKind,
    SelfDeliveryRecordV1,
};
use shared::spec_v1::encoding::{digest_from_bytes, digest_to_bytes};
use shared::spec_v1::hashes::detect_tag as poseidon_detect_tag;
use shared::spec_v1::note_encryption::{
    derive_note_key, shared_secret_sender, xonly_pubkey, zbe_seal,
};
use shared::spec_v1::serialize::{
    deserialize_proof_data, parse_account_state, serialize_proof_data,
};
use sqlx::PgPool;
use zkcoins_program::circuit::compliance::Network;

use super::adapter::EngineAdapter;
use super::db_outbox::OutboxKind;
use super::db_sdr;
use super::delivery::{fresh_esk, insert_sdr_outbox_pending, DeliveryError};
use super::nostr::nip59::SecureRandom;
use super::outbox_material::{SdrOutboxMaterial, SdrPhaseAMaterial, SdrPhaseAOutputRef};
use super::OsSecureRandom;

/// Stable token in the mainnet provisional-MTP refusal message (tests + logs).
pub(crate) const PROVISIONAL_MTP_MAINNET_REFUSED: &str = "PROVISIONAL_MTP_MAINNET_REFUSED";

/// Protocol-pinned finality depth (§3.9): six confirmations.
///
/// This mirrors the protocol-pinned §3.9 depth also enforced independently by
/// `shared::spec_v1::accumulator::FINALITY_CONFIRMATIONS`, which is private to
/// `shared` and cannot be imported here. Keep the two constants in sync by
/// hand.
pub(crate) const FINALITY_CONFIRMATIONS: u64 = 6;

/// Build the **named provisional** Inclusion/MTP stand-in used until
/// bitcoind first-occurrence inclusion + BIP-113 MTP is wired.
///
/// **Fail-closed on mainnet:** provisional tip-hash + wall-clock must never
/// seal a SelfDeliveryRecord on mainnet. Regtest and testnet may use the
/// stand-in (still named provisional in logs / docs).
pub(crate) fn provisional_inclusion_mtp_for_network(
    network: Network,
    tip_hash: [u8; 32],
    occurred_at: u64,
) -> Result<FixedInclusionMtp> {
    match network {
        Network::Mainnet => bail!(
            "SDR Phase B refused: {PROVISIONAL_MTP_MAINNET_REFUSED}: provisional \
             Inclusion/MTP (tip_hash + wall-clock) is forbidden on mainnet; \
             first-occurrence inclusion block and BIP-113 MTP via bitcoind are \
             required before sealing SelfDeliveryRecordV1"
        ),
        Network::Regtest | Network::Testnet => {
            // Named provisional — allowed only off mainnet until BitcoindInclusionMtp ships.
            Ok(FixedInclusionMtp {
                block_hash: tip_hash,
                occurred_at,
            })
        }
    }
}

/// Boxed future returned by [`InclusionMtpSource::inclusion_and_mtp`]: the
/// resolved inclusion [`BlockAnchor`] and its BIP-113 median-time-past.
pub(crate) type InclusionMtpFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<(BlockAnchor, u64)>> + Send + 'a>>;

/// Inclusion block + BIP-113 MTP for a nullifier's first-occurrence height.
///
/// Production supplies bitcoind header resolution; tests inject fixed values.
pub(crate) trait InclusionMtpSource: Send + Sync {
    fn inclusion_and_mtp(&self, height: u64) -> InclusionMtpFuture<'_>;
}

/// Fixed MTP source for unit tests (no bitcoind).
#[derive(Clone, Debug)]
pub(crate) struct FixedInclusionMtp {
    pub block_hash: [u8; 32],
    pub occurred_at: u64,
}

impl InclusionMtpSource for FixedInclusionMtp {
    fn inclusion_and_mtp(&self, height: u64) -> InclusionMtpFuture<'_> {
        let height_u32 = match u32::try_from(height) {
            Ok(h) => h,
            Err(_) => {
                return Box::pin(async move {
                    bail!("inclusion height {height} does not fit u32");
                });
            }
        };
        let anchor = BlockAnchor {
            block_hash: self.block_hash,
            height: height_u32,
        };
        let mtp = self.occurred_at;
        Box::pin(async move { Ok((anchor, mtp)) })
    }
}

/// Header fields needed to validate a canonical inclusion block and obtain its
/// BIP-113 median-time-past.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InclusionBlockHeader {
    height: u64,
    confirmations: i32,
    median_time: Option<u64>,
}

/// Minimal chain boundary used by the production Inclusion/MTP resolver.
///
/// Keeping the blocking RPC calls behind this trait lets unit tests exercise
/// every canonicality and finality branch without a live bitcoind.
trait InclusionChainSource: Send + Sync {
    fn canonical_block_hash(&self, height: u64) -> Result<BlockHash>;
    fn block_header(&self, hash: &BlockHash) -> Result<InclusionBlockHeader>;
}

impl InclusionChainSource for bitcoincore_rpc::Client {
    fn canonical_block_hash(&self, height: u64) -> Result<BlockHash> {
        Ok(self.get_block_hash(height)?)
    }

    fn block_header(&self, hash: &BlockHash) -> Result<InclusionBlockHeader> {
        let header = self.get_block_header_info(hash)?;
        Ok(InclusionBlockHeader {
            height: u64::try_from(header.height).context("getblockheader height exceeds u64")?,
            confirmations: header.confirmations,
            median_time: header
                .median_time
                .map(u64::try_from)
                .transpose()
                .context("getblockheader mediantime exceeds u64")?,
        })
    }
}

/// Production Inclusion/MTP source: bitcoind's canonical block hash at the
/// first-occurrence height plus that block's BIP-113 median-time-past.
/// Fail-closed on RPC errors, non-final/orphaned headers, height mismatches, or
/// absent mediantime — never consults the append-only audit log and never
/// substitutes tip/wall-clock.
pub(crate) struct BitcoindInclusionMtp<'a> {
    chain: &'a dyn InclusionChainSource,
}

impl<'a> BitcoindInclusionMtp<'a> {
    fn new(chain: &'a dyn InclusionChainSource) -> Self {
        Self { chain }
    }
}

impl InclusionMtpSource for BitcoindInclusionMtp<'_> {
    fn inclusion_and_mtp(&self, height: u64) -> InclusionMtpFuture<'_> {
        Box::pin(async move {
            let height_u32 = u32::try_from(height).context("inclusion height exceeds u32")?;
            let (canonical_hash, header) = tokio::task::block_in_place(|| {
                let canonical_hash = self
                    .chain
                    .canonical_block_hash(height)
                    .context("getblockhash for SDR canonical inclusion block")?;
                let header = self
                    .chain
                    .block_header(&canonical_hash)
                    .context("getblockheader for SDR inclusion MTP")?;
                Ok::<_, anyhow::Error>((canonical_hash, header))
            })?;

            if header.height != height {
                bail!(
                    "getblockheader height {} != inclusion height {height}",
                    header.height
                );
            }

            let minimum_confirmations =
                i32::try_from(FINALITY_CONFIRMATIONS).context("SDR finality depth exceeds i32")?;
            if header.confirmations < minimum_confirmations {
                bail!(
                    "getblockheader confirmations {} below required finality depth \
                     {FINALITY_CONFIRMATIONS} at inclusion height {height}",
                    header.confirmations
                );
            }

            let median_time = header.median_time.ok_or_else(|| {
                anyhow::anyhow!(
                    "getblockheader returned no mediantime for inclusion height {height} — \
                     cannot seal SDR without BIP-113 MTP"
                )
            })?;

            Ok((
                BlockAnchor {
                    block_hash: canonical_hash.to_byte_array(),
                    height: height_u32,
                },
                median_time,
            ))
        })
    }
}

/// Map transition witness shape → SDR `RecordKind` (§4.2 / §7.1).
pub(crate) fn record_kind_from_witness(asset_issuance: bool, has_received: bool) -> RecordKind {
    if asset_issuance {
        RecordKind::Mint
    } else if has_received {
        RecordKind::Receive
    } else {
        RecordKind::Send
    }
}

/// Build a Phase-A output_ref from a just-built coin delivery.
pub(crate) fn output_ref_from_built(
    coin_id: [u8; 32],
    blob_id: [u8; 32],
    epk: [u8; 32],
    out_ciphertext: &[u8],
    holders: &[String],
) -> Result<SdrPhaseAOutputRef> {
    if holders.is_empty() {
        bail!("SDR output_ref: empty holders");
    }
    if out_ciphertext.is_empty() {
        bail!("SDR output_ref: empty out_ciphertext");
    }
    Ok(SdrPhaseAOutputRef {
        coin_id_hex: hex::encode(coin_id),
        blob_id_hex: hex::encode(blob_id),
        epk_hex: hex::encode(epk),
        out_ciphertext_hex: hex::encode(out_ciphertext),
        holders: holders.to_vec(),
    })
}

/// Stage Phase A after durable finalise (fail-closed on incomplete material).
pub(crate) async fn stage_phase_a(
    pool: &PgPool,
    material: &SdrPhaseAMaterial,
) -> Result<(), DeliveryError> {
    material
        .validate_complete()
        .map_err(|e| DeliveryError::Relay(format!("SDR Phase A incomplete: {e:#}")))?;
    let transition_pk = parse_hex32_field(&material.transition_pk_hex, "transition_pk")
        .map_err(|e| DeliveryError::Relay(format!("SDR Phase A: {e:#}")))?;
    let subject = parse_hex32_field(&material.subject_hex, "subject")
        .map_err(|e| DeliveryError::Relay(format!("SDR Phase A: {e:#}")))?;
    db_sdr::insert_phase_a(pool, &transition_pk, &subject, material)
        .await
        .map_err(|e| DeliveryError::Relay(format!("SDR Phase A insert: {e:#}")))?;
    Ok(())
}

/// Production scanner hook after each NfLog fold (binary `run_v1_scan_loop`).
///
/// Public so the binary crate can call it; the trait-based core stays
/// crate-private.
///
/// **Inclusion / MTP source.** Resolves bitcoind's canonical block hash at the
/// nullifier's first-occurrence height and its BIP-113 median-time-past,
/// uniformly on every network ([`BitcoindInclusionMtp`]). RPC errors,
/// non-final/orphaned headers, height mismatches, and missing mediantime fail
/// closed (per-row [`db_sdr::mark_failed`]).
///
/// Incomplete material → named [`db_sdr::mark_failed`] (no silent skip).
/// Success → `insert_sdr_outbox_pending` + [`db_sdr::mark_finalised`] so
/// Drive/Resume pick up the sealed SDR.
pub async fn finalize_due_phase_b_adapter(
    adapter: &EngineAdapter,
    client: &bitcoincore_rpc::Client,
) -> Result<usize> {
    let src = BitcoindInclusionMtp::new(client);
    let mut rng = OsSecureRandom;
    finalize_due_phase_b_with_mtp(adapter, &src, &mut rng).await
}

/// Async-friendly Phase-B loop: engine lock is not held across await points.
async fn finalize_due_phase_b_with_mtp(
    adapter: &EngineAdapter,
    mtp: &dyn InclusionMtpSource,
    rng: &mut dyn SecureRandom,
) -> Result<usize> {
    let pool = adapter.pool();
    let open = db_sdr::list_awaiting_first_occurrence(pool)
        .await
        .context("SDR Phase B: list open Phase A")?;
    if open.is_empty() {
        return Ok(0);
    }
    let (tip, size_final) = adapter.with_engine(|engine| {
        let tip = engine.tip_height();
        let size_final = engine.nflog().size_final(tip);
        (tip, size_final)
    });
    let _ = tip;
    let mut finalised = 0usize;
    for row in open {
        // Snapshot the NfLog facts under the engine lock, then await I/O outside.
        let classify = adapter.with_engine(|engine| {
            let pk = parse_hex32_field(&row.material.own_nullifier_pk_hex, "own_nullifier.pk").ok();
            let r = parse_hex32_field(&row.material.own_nullifier_r_hex, "own_nullifier.r").ok();
            match (pk, r) {
                (Some(pk), Some(r)) => {
                    let class = engine.nflog().classify(pk, r);
                    let lookup = engine.nflog().lookup(pk);
                    let inclusion_height = match &lookup {
                        LookupResult::Present { pos, .. } => engine
                            .nflog_mirror()
                            .get(*pos as usize)
                            .map(|(cp, _)| cp.height),
                        LookupResult::Absent => None,
                    };
                    Some((class, lookup, inclusion_height))
                }
                _ => None,
            }
        });
        match try_finalize_one_from_snapshot(pool, size_final, &row.material, classify, mtp, rng)
            .await
        {
            Ok(true) => {
                finalised = finalised
                    .checked_add(1)
                    .context("SDR Phase B finalised counter overflow")?;
            }
            Ok(false) => {}
            Err(e) => {
                let reason = format!("SDR Phase B finalise failed: {e:#}");
                tracing::error!(
                    transition_pk = %hex::encode(row.transition_pk),
                    error = %e,
                    "SDR Phase B: marking Phase A failed (fail-closed; no silent skip)"
                );
                if let Err(mark_err) = db_sdr::mark_failed(pool, &row.transition_pk, &reason).await
                {
                    tracing::error!(
                        transition_pk = %hex::encode(row.transition_pk),
                        error = %mark_err,
                        "SDR Phase B: mark_failed write failed"
                    );
                }
            }
        }
    }
    Ok(finalised)
}

/// Core Phase-B finalise from a pre-taken NfLog snapshot (no engine lock held).
async fn try_finalize_one_from_snapshot(
    pool: &PgPool,
    size_final: u64,
    phase_a: &SdrPhaseAMaterial,
    classify: Option<(SpendClassification, LookupResult, Option<u64>)>,
    mtp: &dyn InclusionMtpSource,
    rng: &mut dyn SecureRandom,
) -> Result<bool> {
    phase_a
        .validate_complete()
        .context("Phase A material incomplete at Phase B")?;

    let r = parse_hex32_field(&phase_a.own_nullifier_r_hex, "own_nullifier.r")?;
    let r_prime = parse_hex32_field(&phase_a.own_nullifier_r_prime_hex, "own_nullifier.r_prime")?;

    let Some((class, lookup, inclusion_height)) = classify else {
        bail!("Phase A own_nullifier hex incomplete");
    };

    match class {
        SpendClassification::ValidFirstSpend => {}
        SpendClassification::Pending => return Ok(false),
        SpendClassification::RejectedDoubleSpend => {
            bail!("own nullifier is a first-occurrence loser (double-spend)");
        }
    }

    let (pos, inclusion_height) = match lookup {
        LookupResult::Present { pos, r: got_r, .. } => {
            if got_r != r {
                bail!("NfLog first-occurrence R mismatches Phase A own_nullifier.R");
            }
            let Some(h) = inclusion_height else {
                bail!("NfLog mirror missing position {pos}");
            };
            (pos, h)
        }
        LookupResult::Absent => return Ok(false),
    };

    if pos >= size_final {
        return Ok(false);
    }

    let (inclusion_block, occurred_at) = mtp
        .inclusion_and_mtp(inclusion_height)
        .await
        .with_context(|| format!("resolve inclusion block + MTP at height {inclusion_height}"))?;

    let sdr = build_self_delivery_record(phase_a, inclusion_block, occurred_at, r_prime)?;
    let plaintext = serialize_self_delivery_record(&sdr)
        .map_err(|e| anyhow::anyhow!("serialize SelfDeliveryRecordV1: {e}"))?;

    let esk = fresh_esk(rng).map_err(|e| anyhow::anyhow!("SDR esk: {e}"))?;
    let recipient_ivpk = parse_hex32_field(&phase_a.recipient_ivpk_hex, "recipient_ivpk")?;
    let ss = shared_secret_sender(&esk, &recipient_ivpk)
        .map_err(|e| anyhow::anyhow!("SDR ECDH: {e}"))?;
    let epk = xonly_pubkey(&esk).map_err(|e| anyhow::anyhow!("SDR epk: {e}"))?;
    let k_tx = derive_note_key(&ss, &epk).map_err(|e| anyhow::anyhow!("SDR K_tx: {e}"))?;
    let detect_tag_digest = poseidon_detect_tag(&ss, &epk);
    let detect_tag = digest_to_bytes(&detect_tag_digest);

    let (zbe_ciphertext, blob_id) =
        zbe_seal(&k_tx, &plaintext).map_err(|e| anyhow::anyhow!("SDR ZBE seal: {e}"))?;

    let material = SdrOutboxMaterial {
        v: 1,
        zbe_ciphertext_hex: hex::encode(&zbe_ciphertext),
        blob_id_hex: hex::encode(blob_id),
        detect_tag_hex: hex::encode(detect_tag),
        epk_hex: hex::encode(epk),
        k_tx_hex: hex::encode(k_tx),
        recipient_ivpk_hex: phase_a.recipient_ivpk_hex.clone(),
        recipient_op_pk_hex: phase_a.recipient_op_pk_hex.clone(),
        recipient_relays: phase_a.recipient_relays.clone(),
        blob_holders: phase_a.blob_holders.clone(),
        max_blob_bytes: phase_a.max_blob_bytes,
        send_counter: phase_a.send_counter,
        record_kind: phase_a.record_kind,
    };
    material
        .encode()
        .context("SdrOutboxMaterial encode after Phase B seal")?;

    let subject = parse_hex32_field(&phase_a.subject_hex, "subject")?;
    let transition_pk = parse_hex32_field(&phase_a.transition_pk_hex, "transition_pk")?;
    insert_sdr_outbox_pending(pool, subject, transition_pk, &material)
        .await
        .map_err(|e| anyhow::anyhow!("insert_sdr_outbox_pending: {e}"))?;

    db_sdr::mark_finalised(pool, &transition_pk)
        .await
        .context("mark Phase A finalised")?;

    tracing::info!(
        transition_pk = %hex::encode(transition_pk),
        blob_id = %hex::encode(blob_id),
        inclusion_height = inclusion_block.height,
        occurred_at,
        "SDR Phase B: sealed SelfDeliveryRecordV1 and queued self_delivery outbox row"
    );
    Ok(true)
}

fn build_self_delivery_record(
    phase_a: &SdrPhaseAMaterial,
    inclusion_block: BlockAnchor,
    occurred_at: u64,
    r_prime: [u8; 32],
) -> Result<SelfDeliveryRecordV1> {
    let record_kind = match phase_a.record_kind {
        0x01 => RecordKind::Mint,
        0x02 => RecordKind::Send,
        0x03 => RecordKind::Receive,
        k => bail!("record_kind 0x{k:02x}"),
    };
    let prev_state_head = digest_from_bytes(&parse_hex32_field(
        &phase_a.prev_state_head_hex,
        "prev_state_head",
    )?)
    .map_err(|e| anyhow::anyhow!("prev_state_head digest: {e}"))?;

    let account_state_bytes = parse_hex_vec(&phase_a.account_state_hex, "account_state")?;
    let account_state = parse_account_state(&account_state_bytes)
        .map_err(|e| anyhow::anyhow!("account_state: {e}"))?;

    let recursive_proof = parse_hex_vec(&phase_a.recursive_proof_hex, "recursive_proof")?;
    if recursive_proof.is_empty() {
        bail!("empty recursive_proof");
    }
    let proof_data_bytes = parse_hex_vec(&phase_a.proof_data_hex, "proof_data")?;
    let proof_data = deserialize_proof_data(&proof_data_bytes)
        .map_err(|e| anyhow::anyhow!("proof_data: {e}"))?;
    // Round-trip guard: canonical form must match staged bytes.
    let reser = serialize_proof_data(&proof_data);
    if reser.as_slice() != proof_data_bytes.as_slice() {
        bail!("proof_data re-serialize mismatch");
    }

    let pk = parse_hex32_field(&phase_a.own_nullifier_pk_hex, "own_nullifier.pk")?;
    let r = parse_hex32_field(&phase_a.own_nullifier_r_hex, "own_nullifier.r")?;
    let proof_anchor_hash = parse_hex32_field(
        &phase_a.proof_block_anchor_hash_hex,
        "proof_block_anchor.hash",
    )?;

    let mut spent = Vec::with_capacity(phase_a.spent_or_folded_coin_ids_hex.len());
    for (i, h) in phase_a.spent_or_folded_coin_ids_hex.iter().enumerate() {
        spent.push(
            parse_hex32_field(h, &format!("spent_or_folded_coin_ids[{i}]"))
                .with_context(|| format!("spent_or_folded_coin_ids[{i}]"))?,
        );
    }

    let mut output_refs = Vec::with_capacity(phase_a.output_refs.len());
    for (i, o) in phase_a.output_refs.iter().enumerate() {
        let coin_id = parse_hex32_field(&o.coin_id_hex, &format!("output_refs[{i}].coin_id"))?;
        let blob_id = parse_hex32_field(&o.blob_id_hex, &format!("output_refs[{i}].blob_id"))?;
        let epk = parse_hex32_field(&o.epk_hex, &format!("output_refs[{i}].epk"))?;
        let out_ciphertext = parse_hex_vec(
            &o.out_ciphertext_hex,
            &format!("output_refs[{i}].out_ciphertext"),
        )?;
        if o.holders.is_empty() {
            bail!("output_refs[{i}]: empty holders");
        }
        output_refs.push(OutputRef {
            coin_id,
            blob_id,
            epk,
            out_ciphertext,
            blob_locators: BlobLocatorSet {
                holders: o.holders.clone(),
            },
        });
    }

    if phase_a.blob_holders.is_empty() {
        bail!("self_blob_locators: empty holders");
    }

    Ok(SelfDeliveryRecordV1 {
        record_kind,
        send_counter: phase_a.send_counter,
        prev_state_head,
        account_state,
        recursive_proof,
        proof_data,
        own_nullifier: CreatingNullifier {
            pk_create: pk,
            r_create: r,
            r_prime_create: r_prime,
        },
        proof_block_anchor: BlockAnchor {
            block_hash: proof_anchor_hash,
            height: phase_a.proof_block_anchor_height,
        },
        inclusion_block,
        occurred_at,
        spent_or_folded_coin_ids: spent,
        output_refs,
        self_blob_locators: BlobLocatorSet {
            holders: phase_a.blob_holders.clone(),
        },
    })
}

fn parse_hex32_field(s: &str, field: &str) -> Result<[u8; 32]> {
    let bytes = parse_hex_vec(s, field)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field}: expected 32 bytes, got {}", bytes.len()))?;
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

/// Publish path for a due `self_delivery` outbox row (same machine as external).
pub(crate) async fn publish_sdr_outbox_row(
    pool: &PgPool,
    row: &super::db_outbox::OutboxRow,
    operator_op_sk: &[u8; 32],
    now: u64,
    rng: &std::sync::Mutex<Box<dyn SecureRandom + Send>>,
    manifest_blob_stores: &[String],
    manifest_seed_relays: &[String],
) -> Result<(), DeliveryError> {
    use super::blossom::{BlossomClient, RetentionClass, UploadBinding};
    use super::db_outbox::{self, PublishArtefacts};
    use super::nostr::kinds::delivery::{
        delivery_rumor, DeliveryPayload, RecordKind as NostrRecordKind,
    };
    use super::nostr::nip59::{delivery_scan_tags, seal_and_wrap};
    use super::nostr::relay::{RelayPool, RelayPublishResult};
    use shared::spec_v1::bundle::serialize_blob_locator_set;

    if row.kind != OutboxKind::SelfDelivery {
        return Err(DeliveryError::Relay(
            "publish_sdr_outbox_row: kind is not self_delivery".into(),
        ));
    }
    if row.status.is_terminal() {
        return Err(DeliveryError::Relay(
            "refuse publish of terminal SDR outbox row".into(),
        ));
    }

    let mat = SdrOutboxMaterial::decode(&row.material)
        .map_err(|e| DeliveryError::Relay(format!("SDR outbox material decode: {e:#}")))?;

    let zbe = parse_hex_vec(&mat.zbe_ciphertext_hex, "zbe_ciphertext")
        .map_err(|e| DeliveryError::Relay(e.to_string()))?;
    let blob_id = parse_hex32_field(&mat.blob_id_hex, "blob_id")
        .map_err(|e| DeliveryError::Relay(e.to_string()))?;
    let detect_tag = parse_hex32_field(&mat.detect_tag_hex, "detect_tag")
        .map_err(|e| DeliveryError::Relay(e.to_string()))?;
    let epk =
        parse_hex32_field(&mat.epk_hex, "epk").map_err(|e| DeliveryError::Relay(e.to_string()))?;
    let k_tx = parse_hex32_field(&mat.k_tx_hex, "k_tx")
        .map_err(|e| DeliveryError::Relay(e.to_string()))?;
    let recipient_ivpk = parse_hex32_field(&mat.recipient_ivpk_hex, "recipient_ivpk")
        .map_err(|e| DeliveryError::Relay(e.to_string()))?;
    let recipient_op_pk = parse_hex32_field(&mat.recipient_op_pk_hex, "recipient_op_pk")
        .map_err(|e| DeliveryError::Relay(e.to_string()))?;

    if mat.recipient_relays.is_empty() {
        return Err(DeliveryError::RecipientRelaysEmpty {
            recipient: recipient_ivpk,
        });
    }
    if mat.blob_holders.is_empty() {
        return Err(DeliveryError::BlobHoldersEmpty);
    }
    if super::blossom::blob_id_of(&zbe) != blob_id {
        return Err(DeliveryError::Relay(
            "SDR material: zbe_ciphertext does not content-address to blob_id".into(),
        ));
    }

    // Validate holder framing (holders only).
    let _framed = serialize_blob_locator_set(&BlobLocatorSet {
        holders: mat.blob_holders.clone(),
    })
    .map_err(DeliveryError::Spec)?;

    let payload_kind = match mat.record_kind {
        0x01 => NostrRecordKind::Mint,
        0x02 => NostrRecordKind::Send,
        0x03 => NostrRecordKind::Receive,
        k => {
            return Err(DeliveryError::Relay(format!(
                "SDR material record_kind 0x{k:02x} not mint/send/receive"
            )));
        }
    };

    // RNG only for ack_nonce + NIP-59 seal (sync). Drop the MutexGuard before
    // any network await — `std::sync::MutexGuard` is !Send and would make the
    // driver future unschedulable under `tokio::spawn` (same pattern as
    // `publish_outbox_row` / external coins).
    let (ack_nonce, gift_wrap) = {
        let mut rng = rng.lock().expect("delivery rng mutex poisoned");
        let mut ack_nonce = [0u8; 32];
        rng.fill_bytes(&mut ack_nonce)
            .map_err(|_| DeliveryError::RandomSourceFailed)?;

        let payload = DeliveryPayload {
            blob_id,
            holders: mat.blob_holders.clone(),
            ack_nonce,
            record_kind: Some(payload_kind),
        };

        let op_pk = xonly_pubkey(operator_op_sk).map_err(DeliveryError::Spec)?;
        let rumor = delivery_rumor(op_pk, now, &payload).map_err(DeliveryError::Payload)?;
        let outer_tags = delivery_scan_tags(&detect_tag, &epk);
        let gift_wrap = seal_and_wrap(
            &rumor,
            operator_op_sk,
            &recipient_ivpk,
            outer_tags,
            now,
            rng.as_mut(),
        )
        .map_err(DeliveryError::Nip59)?;
        (ack_nonce, gift_wrap)
    };

    // Blossom upload to every holder.
    let client = BlossomClient::new(mat.max_blob_bytes).map_err(|e| DeliveryError::Blossom {
        holder: String::new(),
        error: e,
    })?;
    let binding = UploadBinding {
        event_id: gift_wrap.id,
        attempt_nonce: ack_nonce,
        retention: RetentionClass::Indefinite,
    };
    for holder in &mat.blob_holders {
        // `now` above belongs to the delivery event. Blossom auth must be
        // timestamped at each actual HTTP upload, not at driver wake-up.
        let (auth_created_at, auth_expiration) =
            super::delivery::fresh_blossom_auth_timestamps()?;
        let _upload = client
            .upload(
                holder,
                &zbe,
                Some(&binding),
                operator_op_sk,
                auth_created_at,
                auth_expiration,
            )
            .await
            .map_err(|e| DeliveryError::Blossom {
                holder: holder.clone(),
                error: e,
            })?;
    }

    let pool_relays = RelayPool::new(mat.recipient_relays.clone())
        .map_err(|e| DeliveryError::Relay(e.to_string()))?;
    let relay_results = pool_relays.publish_all(&gift_wrap).await;
    let any_accepted = relay_results
        .iter()
        .any(|r| matches!(r, RelayPublishResult::Accepted { .. }));
    if !any_accepted {
        return Err(DeliveryError::NoRelayAccepted {
            results: relay_results
                .iter()
                .map(|r| match r {
                    RelayPublishResult::Accepted { relay_url, message } => {
                        super::delivery::RelayOutcomeSummary {
                            relay_url: relay_url.clone(),
                            accepted: true,
                            detail: message.clone(),
                        }
                    }
                    RelayPublishResult::Rejected { relay_url, message } => {
                        super::delivery::RelayOutcomeSummary {
                            relay_url: relay_url.clone(),
                            accepted: false,
                            detail: message.clone(),
                        }
                    }
                    RelayPublishResult::Unreachable { relay_url, error } => {
                        super::delivery::RelayOutcomeSummary {
                            relay_url: relay_url.clone(),
                            accepted: false,
                            detail: error.to_string(),
                        }
                    }
                })
                .collect(),
        });
    }

    super::delivery::publish_recovery_overlap(
        manifest_blob_stores,
        manifest_seed_relays,
        &zbe,
        &gift_wrap,
        ack_nonce,
        operator_op_sk,
        mat.max_blob_bytes,
    )
    .await?;

    let artefacts = PublishArtefacts {
        blob_id,
        detect_tag,
        epk,
        k_tx,
        ack_nonce,
        event_id: gift_wrap.id,
        zbe_ciphertext: zbe,
        // No per-coin ovk envelope on the SDR path (ACK allows empty for
        // kind = self_delivery).
        out_ciphertext: Vec::new(),
        recipient_op_pk,
    };
    db_outbox::mark_published(pool, &row.outbox_id, &artefacts)
        .await
        .map_err(|e| DeliveryError::Relay(format!("SDR outbox mark_published: {e:#}")))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_db::setup_pool;
    use crate::v1::db_outbox::{self, OutboxKind, OutboxRow, OutboxStatus};
    use crate::v1::db_sdr;
    use crate::v1::outbox_material::{
        SdrOutboxMaterial, SdrPhaseAMaterial, SdrPhaseAOutputRef,
    };
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    /// Deterministic RNG for tests.
    struct StepRng(u8);
    impl SecureRandom for StepRng {
        fn fill_bytes(
            &mut self,
            dest: &mut [u8],
        ) -> Result<(), super::super::nostr::nip59::Nip59Error> {
            for b in dest.iter_mut() {
                *b = self.0;
                self.0 = self.0.wrapping_add(1);
            }
            Ok(())
        }
    }

    struct FakeInclusionChainSource {
        canonical_hash: Option<BlockHash>,
        header: Option<InclusionBlockHeader>,
    }

    impl InclusionChainSource for FakeInclusionChainSource {
        fn canonical_block_hash(&self, height: u64) -> Result<BlockHash> {
            self.canonical_hash.ok_or_else(|| {
                anyhow::anyhow!("fake canonical chain has no block at height {height}")
            })
        }

        fn block_header(&self, _hash: &BlockHash) -> Result<InclusionBlockHeader> {
            self.header
                .ok_or_else(|| anyhow::anyhow!("fake canonical block header is unavailable"))
        }
    }

    fn fake_inclusion_chain(
        canonical_internal: [u8; 32],
        height: u64,
        confirmations: i32,
        median_time: Option<u64>,
    ) -> FakeInclusionChainSource {
        FakeInclusionChainSource {
            canonical_hash: Some(BlockHash::from_byte_array(canonical_internal)),
            header: Some(InclusionBlockHeader {
                height,
                confirmations,
                median_time,
            }),
        }
    }

    fn finality_confirmations_i32() -> i32 {
        i32::try_from(FINALITY_CONFIRMATIONS).expect("protocol finality depth must fit i32")
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoind_inclusion_mtp_happy_path_uses_internal_hash_and_mtp() {
        let canonical_internal = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D,
            0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B,
            0x1C, 0x1D, 0x1E, 0x1F,
        ];
        let source = fake_inclusion_chain(
            canonical_internal,
            840_000,
            finality_confirmations_i32(),
            Some(1_710_000_000),
        );

        let (anchor, median_time) = BitcoindInclusionMtp::new(&source)
            .inclusion_and_mtp(840_000)
            .await
            .expect("final canonical inclusion block must resolve");

        assert_eq!(anchor.block_hash, canonical_internal);
        assert_eq!(anchor.height, 840_000);
        assert_eq!(median_time, 1_710_000_000);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoind_inclusion_mtp_recanonicalizes_flipflop_orphan() {
        // The append-only block_log still contains this later-observed B row,
        // but bitcoind's active chain has flipped back to A at the same height.
        let stale_orphaned_block_log_hash = [0xB2; 32];
        let canonical_internal = [0xA2; 32];
        let source = fake_inclusion_chain(
            canonical_internal,
            840_001,
            finality_confirmations_i32(),
            Some(1_710_000_600),
        );

        let (anchor, _) = BitcoindInclusionMtp::new(&source)
            .inclusion_and_mtp(840_001)
            .await
            .expect("canonical A must self-heal the stale B audit-log observation");

        assert_eq!(anchor.block_hash, canonical_internal);
        assert_ne!(anchor.block_hash, stale_orphaned_block_log_hash);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoind_inclusion_mtp_missing_canonical_block_fails_closed() {
        let source = FakeInclusionChainSource {
            canonical_hash: None,
            header: None,
        };

        let err = BitcoindInclusionMtp::new(&source)
            .inclusion_and_mtp(840_002)
            .await
            .expect_err("missing canonical block must fail closed");

        assert!(err.to_string().contains("getblockhash"), "{err:#}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoind_inclusion_mtp_missing_header_fails_closed() {
        let source = FakeInclusionChainSource {
            canonical_hash: Some(BlockHash::from_byte_array([0xA3; 32])),
            header: None,
        };

        let err = BitcoindInclusionMtp::new(&source)
            .inclusion_and_mtp(840_003)
            .await
            .expect_err("missing canonical header must fail closed");

        assert!(err.to_string().contains("getblockheader"), "{err:#}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoind_inclusion_mtp_header_height_mismatch_fails_closed() {
        let source = fake_inclusion_chain(
            [0xA4; 32],
            840_005,
            finality_confirmations_i32(),
            Some(1_710_001_200),
        );

        let err = BitcoindInclusionMtp::new(&source)
            .inclusion_and_mtp(840_004)
            .await
            .expect_err("mismatched header height must fail closed");

        assert!(
            err.to_string()
                .contains("height 840005 != inclusion height 840004"),
            "{err:#}"
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoind_inclusion_mtp_nonfinal_and_orphaned_headers_fail_closed() {
        for confirmations in [finality_confirmations_i32() - 1, -1] {
            let source =
                fake_inclusion_chain([0xA5; 32], 840_006, confirmations, Some(1_710_001_800));

            let err = BitcoindInclusionMtp::new(&source)
                .inclusion_and_mtp(840_006)
                .await
                .expect_err("non-final or orphaned header must fail closed");

            let expected = format!("below required finality depth {FINALITY_CONFIRMATIONS}");
            assert!(
                err.to_string().contains(&expected),
                "confirmations={confirmations}: {err:#}"
            );
        }
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoind_inclusion_mtp_missing_median_time_fails_closed() {
        let source = fake_inclusion_chain([0xA6; 32], 840_007, finality_confirmations_i32(), None);

        let err = BitcoindInclusionMtp::new(&source)
            .inclusion_and_mtp(840_007)
            .await
            .expect_err("missing BIP-113 MTP must fail closed");

        assert!(err.to_string().contains("no mediantime"), "{err:#}");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn bitcoind_inclusion_mtp_height_above_u32_fails_closed() {
        let source = FakeInclusionChainSource {
            canonical_hash: None,
            header: None,
        };
        let height = u64::from(u32::MAX) + 1;

        let err = BitcoindInclusionMtp::new(&source)
            .inclusion_and_mtp(height)
            .await
            .expect_err("height above the BlockAnchor domain must fail closed");

        assert!(
            err.to_string().contains("inclusion height exceeds u32"),
            "{err:#}"
        );
    }

    fn sample_phase_a(pk: [u8; 32]) -> SdrPhaseAMaterial {
        // Minimal account_state: 140 zero bytes is invalid (zero balances ok if empty).
        // serialize_account_state needs a real AccountState — use zeros for
        // fields that parse accepts (empty balances).
        use shared::spec_v1::datastructures::{AccountState, Address, ProofData};
        use shared::spec_v1::serialize::{serialize_account_state, serialize_proof_data};
        use shared::spec_v1::ZERO_HASH;
        let state = AccountState {
            owner: Address([0x11; 32]),
            nk_commit: ZERO_HASH,
            current_pubkey: [0x99; 32],
            send_counter: 1,
            coin_history_root: ZERO_HASH,
            balances: Default::default(),
        };
        let account_state_bytes = serialize_account_state(&state).expect("ser account");
        let pd = ProofData {
            new_account_state_hash: ZERO_HASH,
            output_coins_root: ZERO_HASH,
            input_nullifiers_root: ZERO_HASH,
            coin_history_root: ZERO_HASH,
            nav_commitment: ZERO_HASH,
            npk_commit: [0u8; 32],
        };
        let pd_bytes = serialize_proof_data(&pd);
        SdrPhaseAMaterial {
            v: 1,
            subject_hex: hex::encode([0x11u8; 32]),
            transition_pk_hex: hex::encode(pk),
            record_kind: 0x02,
            send_counter: 1,
            prev_state_head_hex: hex::encode([0x33u8; 32]),
            account_state_hex: hex::encode(account_state_bytes),
            recursive_proof_hex: hex::encode([0x01u8, 0x02, 0x03, 0x04]),
            proof_data_hex: hex::encode(pd_bytes),
            own_nullifier_pk_hex: hex::encode(pk),
            own_nullifier_r_hex: hex::encode([0x44u8; 32]),
            own_nullifier_r_prime_hex: hex::encode([0x55u8; 32]),
            proof_block_anchor_hash_hex: hex::encode([0x66u8; 32]),
            proof_block_anchor_height: 10,
            spent_or_folded_coin_ids_hex: vec![],
            output_refs: vec![],
            blob_holders: vec!["https://blossom.example".into()],
            max_blob_bytes: 1_048_576,
            recipient_ivpk_hex: hex::encode([0x77u8; 32]),
            recipient_op_pk_hex: hex::encode([0x88u8; 32]),
            recipient_relays: vec!["wss://relay.example".into()],
        }
    }

    fn valid_snapshot(r: [u8; 32]) -> Option<(SpendClassification, LookupResult, Option<u64>)> {
        Some((
            SpendClassification::ValidFirstSpend,
            LookupResult::Present {
                pos: 0,
                r,
                inclusion_proof: vec![],
            },
            Some(100),
        ))
    }

    async fn finalize_material_for_build(
        pool: &PgPool,
        material: &SdrPhaseAMaterial,
    ) -> Result<bool> {
        let mtp = FixedInclusionMtp {
            block_hash: [0xBB; 32],
            occurred_at: 1_700_000_000,
        };
        let mut rng = StepRng(1);
        try_finalize_one_from_snapshot(
            pool,
            1,
            material,
            valid_snapshot([0x44; 32]),
            &mtp,
            &mut rng,
        )
        .await
    }

    fn sample_sdr_outbox_material() -> SdrOutboxMaterial {
        let zbe = b"valid-zbe-ciphertext";
        SdrOutboxMaterial {
            v: 1,
            zbe_ciphertext_hex: hex::encode(zbe),
            blob_id_hex: hex::encode(super::super::blossom::blob_id_of(zbe)),
            detect_tag_hex: hex::encode([0x11; 32]),
            epk_hex: hex::encode([0x22; 32]),
            k_tx_hex: hex::encode([0x33; 32]),
            recipient_ivpk_hex: hex::encode(
                xonly_pubkey(&[0x02; 32]).expect("fixture recipient IVPK"),
            ),
            recipient_op_pk_hex: hex::encode(
                xonly_pubkey(&[0x03; 32]).expect("fixture recipient op key"),
            ),
            recipient_relays: vec!["ws://127.0.0.1:1/".into()],
            blob_holders: vec!["http://127.0.0.1:1".into()],
            max_blob_bytes: 1_048_576,
            send_counter: 7,
            record_kind: 0x02,
        }
    }

    fn outbox_row(kind: OutboxKind, status: OutboxStatus, material: Vec<u8>) -> OutboxRow {
        OutboxRow {
            outbox_id: [0xA0; 32],
            kind,
            subject: [0xA1; 32],
            transition_pk: [0xA2; 32],
            coin_id: [0; 32],
            status,
            material,
            blob_id: None,
            detect_tag: None,
            epk: None,
            k_tx: None,
            ack_nonce: None,
            event_id: None,
            zbe_ciphertext: None,
            out_ciphertext: None,
            recipient_op_pk: None,
            attempt_n: 0,
            fail_reason: None,
        }
    }

    fn publish_rng() -> std::sync::Mutex<Box<dyn SecureRandom + Send>> {
        std::sync::Mutex::new(Box::new(StepRng(1)))
    }

    async fn mount_successful_blossom(server: &MockServer, material: &SdrOutboxMaterial) {
        Mock::given(method("PUT"))
            .and(path("/blossom/upload"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "blob_id": material.blob_id_hex.clone(),
            })))
            .mount(server)
            .await;
    }

    async fn insert_sdr_publish_fixture(
        pool: &sqlx::PgPool,
        material: &SdrOutboxMaterial,
    ) -> OutboxRow {
        let outbox_id = crate::v1::delivery::insert_sdr_outbox_pending(
            pool,
            [0xA1; 32],
            [0xA2; 32],
            material,
        )
        .await
        .expect("insert SDR overlap fixture");
        db_outbox::get_by_id(pool, &outbox_id)
            .await
            .expect("load SDR overlap fixture")
            .expect("inserted SDR overlap row")
    }

    async fn publish_material_error(material: Vec<u8>) -> DeliveryError {
        let scope = setup_pool().await;
        publish_sdr_outbox_row(
            &scope.pool,
            &outbox_row(OutboxKind::SelfDelivery, OutboxStatus::Pending, material),
            &[0x01; 32],
            1_700_000_000,
            &publish_rng(),
            &[],
            &[],
        )
        .await
        .expect_err("fixture is expected to fail closed")
    }

    #[tokio::test]
    async fn first_occurrence_completed_inserts_sdr_outbox() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let pk = [0xAAu8; 32];
        let r = [0x44u8; 32];
        let mat = sample_phase_a(pk);
        db_sdr::insert_phase_a(&pool, &pk, &[0x11u8; 32], &mat)
            .await
            .expect("phase a");

        // Build a minimal engine-like NfLog via try_finalize_one_from_snapshot
        // with a ValidFirstSpend at pos 0, size_final = 1.
        let mtp = FixedInclusionMtp {
            block_hash: [0xBBu8; 32],
            occurred_at: 1_700_000_000,
        };
        let mut rng = StepRng(1);
        let class = SpendClassification::ValidFirstSpend;
        let lookup = LookupResult::Present {
            pos: 0,
            r,
            inclusion_proof: vec![],
        };
        let ok = try_finalize_one_from_snapshot(
            &pool,
            /* size_final */ 1,
            &mat,
            Some((class, lookup, Some(100))),
            &mtp,
            &mut rng,
        )
        .await
        .expect("phase b");
        assert!(ok, "must finalise when completed");

        let row = db_sdr::get_phase_a(&pool, &pk)
            .await
            .expect("get")
            .expect("row");
        assert_eq!(row.status, db_sdr::SdrPhaseAStatus::Finalised);

        let due = db_outbox::list_due(&pool).await.expect("due");
        let sdr_rows: Vec<_> = due
            .iter()
            .filter(|r| r.kind == OutboxKind::SelfDelivery)
            .collect();
        assert_eq!(sdr_rows.len(), 1, "one self_delivery outbox row");
        assert_eq!(sdr_rows[0].status, OutboxStatus::Pending);
        let material = SdrOutboxMaterial::decode(&sdr_rows[0].material).expect("decode sdr mat");
        assert!(!material.zbe_ciphertext_hex.is_empty());
        assert!(!material.blob_id_hex.is_empty());
        assert!(!material.epk_hex.is_empty());
        assert_eq!(material.record_kind, 0x02);
    }

    #[test]
    fn mainnet_refuses_provisional_inclusion_mtp() {
        let err =
            provisional_inclusion_mtp_for_network(Network::Mainnet, [0xAA; 32], 1_700_000_000)
                .expect_err("mainnet must refuse provisional MTP");
        let msg = err.to_string();
        assert!(
            msg.contains(PROVISIONAL_MTP_MAINNET_REFUSED),
            "named token: {msg}"
        );
        assert!(
            msg.contains("mainnet") && msg.contains("BIP-113"),
            "operator-readable refusal: {msg}"
        );
    }

    #[test]
    fn regtest_and_testnet_allow_named_provisional_inclusion_mtp() {
        for network in [Network::Regtest, Network::Testnet] {
            let mtp = provisional_inclusion_mtp_for_network(network, [0xBB; 32], 42)
                .unwrap_or_else(|e| panic!("{network:?} must allow provisional: {e:#}"));
            assert_eq!(mtp.block_hash, [0xBB; 32]);
            assert_eq!(mtp.occurred_at, 42);
        }
    }

    #[tokio::test]
    async fn incomplete_phase_a_is_named_failure_not_silent_skip() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let pk = [0xCCu8; 32];
        let mut mat = sample_phase_a(pk);
        // Break material after insert by writing raw incomplete JSON... insert
        // encodes via validate_complete. Instead call try_finalize with
        // incomplete in-memory material (simulating corrupt durable bytes).
        mat.account_state_hex.clear();
        let mtp = FixedInclusionMtp {
            block_hash: [0x00u8; 32],
            occurred_at: 1,
        };
        let mut rng = StepRng(9);
        let err = try_finalize_one_from_snapshot(
            &pool,
            1,
            &mat,
            Some((
                SpendClassification::ValidFirstSpend,
                LookupResult::Present {
                    pos: 0,
                    r: [0x44; 32],
                    inclusion_proof: vec![],
                },
                Some(10),
            )),
            &mtp,
            &mut rng,
        )
        .await
        .expect_err("incomplete must fail");
        assert!(
            err.to_string().contains("incomplete") || err.to_string().contains("empty"),
            "named incomplete: {err}"
        );
        // No outbox row invented.
        let due = db_outbox::list_due(&pool).await.expect("due");
        assert!(
            due.iter().all(|r| r.kind != OutboxKind::SelfDelivery),
            "no self_delivery on incomplete"
        );
    }

    #[tokio::test]
    async fn not_yet_size_final_leaves_phase_a_open() {
        let scope = setup_pool().await;
        let pool = scope.pool.clone();
        let pk = [0xDDu8; 32];
        let mat = sample_phase_a(pk);
        db_sdr::insert_phase_a(&pool, &pk, &[0x11u8; 32], &mat)
            .await
            .expect("insert");
        let mtp = FixedInclusionMtp {
            block_hash: [0x00u8; 32],
            occurred_at: 1,
        };
        let mut rng = StepRng(3);
        // pos 0 but size_final 0 → not completed.
        let ok = try_finalize_one_from_snapshot(
            &pool,
            0,
            &mat,
            Some((
                SpendClassification::ValidFirstSpend,
                LookupResult::Present {
                    pos: 0,
                    r: [0x44; 32],
                    inclusion_proof: vec![],
                },
                Some(10),
            )),
            &mtp,
            &mut rng,
        )
        .await
        .expect("wait");
        assert!(!ok, "must wait for size_final");
        let open = db_sdr::list_awaiting_first_occurrence(&pool)
            .await
            .expect("list");
        assert_eq!(open.len(), 1);
    }

    #[test]
    fn output_ref_from_built_encodes_every_field() {
        let holders = vec!["https://holder.example".to_string()];
        let got = output_ref_from_built(
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            &[0x44, 0x55],
            &holders,
        )
        .expect("complete output ref");

        assert_eq!(got.coin_id_hex, hex::encode([0x11; 32]));
        assert_eq!(got.blob_id_hex, hex::encode([0x22; 32]));
        assert_eq!(got.epk_hex, hex::encode([0x33; 32]));
        assert_eq!(got.out_ciphertext_hex, "4455");
        assert_eq!(got.holders, holders);
    }

    #[test]
    fn output_ref_from_built_rejects_empty_holders() {
        let err = output_ref_from_built([1; 32], [2; 32], [3; 32], b"ciphertext", &[])
            .expect_err("holders are required");
        assert!(err.to_string().contains("empty holders"), "{err:#}");
    }

    #[test]
    fn output_ref_from_built_rejects_empty_ciphertext() {
        let err = output_ref_from_built(
            [1; 32],
            [2; 32],
            [3; 32],
            &[],
            &["https://holder.example".into()],
        )
        .expect_err("ciphertext is required");
        assert!(
            err.to_string().contains("empty out_ciphertext"),
            "{err:#}"
        );
    }

    #[test]
    fn parse_hex32_field_accepts_exactly_32_bytes() {
        assert_eq!(
            parse_hex32_field(&hex::encode([0xAB; 32]), "field").expect("32-byte hex"),
            [0xAB; 32]
        );
    }

    #[test]
    fn parse_hex32_field_rejects_empty_input_as_wrong_length() {
        let err = parse_hex32_field("", "field").expect_err("empty is not a zero digest");
        assert!(
            err.to_string().contains("expected 32 bytes, got 0"),
            "{err:#}"
        );
    }

    #[test]
    fn parse_hex32_field_rejects_non_lowercase_hex() {
        let err = parse_hex32_field(&"AA".repeat(32), "field")
            .expect_err("uppercase hex is non-canonical");
        assert!(err.to_string().contains("non-lowercase-hex"), "{err:#}");
    }

    #[test]
    fn parse_hex32_field_rejects_31_bytes() {
        let err = parse_hex32_field(&hex::encode([0xAB; 31]), "field")
            .expect_err("31 bytes is not a digest");
        assert!(
            err.to_string().contains("expected 32 bytes, got 31"),
            "{err:#}"
        );
    }

    #[test]
    fn parse_hex_vec_accepts_empty_input() {
        assert_eq!(parse_hex_vec("", "field").expect("empty vector"), Vec::<u8>::new());
    }

    #[test]
    fn parse_hex_vec_rejects_odd_length_hex() {
        let err = parse_hex_vec("abc", "field").expect_err("odd hex length");
        assert!(err.to_string().contains("hex decode"), "{err:#}");
    }

    #[test]
    fn parse_hex_vec_rejects_non_lowercase_hex() {
        let err = parse_hex_vec("aB", "field").expect_err("mixed-case hex");
        assert!(err.to_string().contains("non-lowercase-hex"), "{err:#}");
    }

    #[tokio::test]
    async fn stage_phase_a_roundtrips_complete_material() {
        let scope = setup_pool().await;
        let pk = [0x31; 32];
        let material = sample_phase_a(pk);

        stage_phase_a(&scope.pool, &material)
            .await
            .expect("complete Phase A stages");

        let row = db_sdr::get_phase_a(&scope.pool, &pk)
            .await
            .expect("query staged Phase A")
            .expect("staged row");
        assert_eq!(row.transition_pk, pk);
        assert_eq!(row.subject, [0x11; 32]);
        assert_eq!(row.status, db_sdr::SdrPhaseAStatus::AwaitingFirstOccurrence);
        assert_eq!(row.material, material);
    }

    #[tokio::test]
    async fn stage_phase_a_names_incomplete_material() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x32; 32]);
        material.record_kind = 0;

        let err = stage_phase_a(&scope.pool, &material)
            .await
            .expect_err("invalid record kind must not stage");
        match err {
            DeliveryError::Relay(message) => {
                assert!(message.contains("SDR Phase A incomplete"), "{message}");
                assert!(message.contains("record_kind 0x00"), "{message}");
            }
            other => panic!("expected Relay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stage_phase_a_rejects_non_hex_transition_pk() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x33; 32]);
        material.transition_pk_hex = "zz".into();

        let err = stage_phase_a(&scope.pool, &material)
            .await
            .expect_err("transition key must be canonical hex");
        match err {
            DeliveryError::Relay(message) => {
                assert!(message.contains("transition_pk"), "{message}");
                assert!(message.contains("non-lowercase-hex"), "{message}");
            }
            other => panic!("expected Relay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn stage_phase_a_rejects_non_hex_subject() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x34; 32]);
        material.subject_hex = "zz".into();

        let err = stage_phase_a(&scope.pool, &material)
            .await
            .expect_err("subject must be canonical hex");
        match err {
            DeliveryError::Relay(message) => {
                assert!(message.contains("subject"), "{message}");
                assert!(message.contains("non-lowercase-hex"), "{message}");
            }
            other => panic!("expected Relay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn snapshot_without_classification_fails_named() {
        let scope = setup_pool().await;
        let material = sample_phase_a([0x41; 32]);
        let mtp = FixedInclusionMtp {
            block_hash: [0; 32],
            occurred_at: 1,
        };
        let mut rng = StepRng(1);

        let err = try_finalize_one_from_snapshot(
            &scope.pool,
            1,
            &material,
            None,
            &mtp,
            &mut rng,
        )
        .await
        .expect_err("missing classification must fail closed");
        assert!(
            err.to_string()
                .contains("Phase A own_nullifier hex incomplete"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn pending_classification_leaves_phase_a_open() {
        let scope = setup_pool().await;
        let material = sample_phase_a([0x42; 32]);
        let mtp = FixedInclusionMtp {
            block_hash: [0; 32],
            occurred_at: 1,
        };
        let mut rng = StepRng(1);

        let got = try_finalize_one_from_snapshot(
            &scope.pool,
            1,
            &material,
            Some((SpendClassification::Pending, LookupResult::Absent, None)),
            &mtp,
            &mut rng,
        )
        .await
        .expect("pending is a wait condition");
        assert!(!got);
    }

    #[tokio::test]
    async fn rejected_double_spend_fails_named() {
        let scope = setup_pool().await;
        let material = sample_phase_a([0x43; 32]);
        let mtp = FixedInclusionMtp {
            block_hash: [0; 32],
            occurred_at: 1,
        };
        let mut rng = StepRng(1);

        let err = try_finalize_one_from_snapshot(
            &scope.pool,
            1,
            &material,
            Some((
                SpendClassification::RejectedDoubleSpend,
                LookupResult::Absent,
                None,
            )),
            &mtp,
            &mut rng,
        )
        .await
        .expect_err("first-occurrence loser must fail");
        assert!(
            err.to_string()
                .contains("first-occurrence loser (double-spend)"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn snapshot_r_mismatch_fails_named() {
        let scope = setup_pool().await;
        let material = sample_phase_a([0x44; 32]);
        let mtp = FixedInclusionMtp {
            block_hash: [0; 32],
            occurred_at: 1,
        };
        let mut rng = StepRng(1);

        let err = try_finalize_one_from_snapshot(
            &scope.pool,
            1,
            &material,
            valid_snapshot([0x45; 32]),
            &mtp,
            &mut rng,
        )
        .await
        .expect_err("snapshot R must match staged R");
        assert!(err.to_string().contains("R mismatches"), "{err:#}");
    }

    #[tokio::test]
    async fn snapshot_missing_mirror_position_fails_named() {
        let scope = setup_pool().await;
        let material = sample_phase_a([0x45; 32]);
        let mtp = FixedInclusionMtp {
            block_hash: [0; 32],
            occurred_at: 1,
        };
        let mut rng = StepRng(1);
        let classify = Some((
            SpendClassification::ValidFirstSpend,
            LookupResult::Present {
                pos: 7,
                r: [0x44; 32],
                inclusion_proof: vec![],
            },
            None,
        ));

        let err = try_finalize_one_from_snapshot(
            &scope.pool,
            8,
            &material,
            classify,
            &mtp,
            &mut rng,
        )
        .await
        .expect_err("mirror position is required");
        assert!(
            err.to_string().contains("NfLog mirror missing position 7"),
            "{err:#}"
        );
    }

    #[tokio::test]
    async fn absent_lookup_waits_without_finalising() {
        let scope = setup_pool().await;
        let material = sample_phase_a([0x46; 32]);
        let mtp = FixedInclusionMtp {
            block_hash: [0; 32],
            occurred_at: 1,
        };
        let mut rng = StepRng(1);

        let got = try_finalize_one_from_snapshot(
            &scope.pool,
            1,
            &material,
            Some((
                SpendClassification::ValidFirstSpend,
                LookupResult::Absent,
                None,
            )),
            &mtp,
            &mut rng,
        )
        .await
        .expect("absent lookup is a wait condition");
        assert!(!got);
    }

    #[tokio::test]
    async fn snapshot_inclusion_height_above_u32_fails_with_context() {
        let scope = setup_pool().await;
        let material = sample_phase_a([0x47; 32]);
        let height = u64::from(u32::MAX) + 1;
        let mtp = FixedInclusionMtp {
            block_hash: [0; 32],
            occurred_at: 1,
        };
        let mut rng = StepRng(1);
        let classify = Some((
            SpendClassification::ValidFirstSpend,
            LookupResult::Present {
                pos: 0,
                r: [0x44; 32],
                inclusion_proof: vec![],
            },
            Some(height),
        ));

        let err = try_finalize_one_from_snapshot(
            &scope.pool,
            1,
            &material,
            classify,
            &mtp,
            &mut rng,
        )
        .await
        .expect_err("BlockAnchor height is u32");
        let message = format!("{err:#}");
        assert!(
            message.contains(&format!(
                "resolve inclusion block + MTP at height {height}"
            )),
            "{message}"
        );
        assert!(message.contains("does not fit u32"), "{message}");
    }

    #[tokio::test]
    async fn build_record_rejects_non_hex_prev_state_head() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x51; 32]);
        material.prev_state_head_hex = "zz".into();

        let err = finalize_material_for_build(&scope.pool, &material)
            .await
            .expect_err("previous state head must be canonical hex");
        let message = format!("{err:#}");
        assert!(message.contains("prev_state_head"), "{message}");
        assert!(message.contains("non-lowercase-hex"), "{message}");
    }

    #[tokio::test]
    async fn build_record_rejects_invalid_account_state() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x52; 32]);
        material.account_state_hex = "aabb".into();

        let err = finalize_material_for_build(&scope.pool, &material)
            .await
            .expect_err("account state wire bytes must parse");
        assert!(format!("{err:#}").contains("account_state"), "{err:#}");
    }

    #[tokio::test]
    async fn empty_recursive_proof_is_rejected_by_phase_a_gate() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x53; 32]);
        material.recursive_proof_hex.clear();

        let err = finalize_material_for_build(&scope.pool, &material)
            .await
            .expect_err("recursive proof is required");
        let message = format!("{err:#}");
        assert!(message.contains("Phase A material incomplete"), "{message}");
        assert!(message.contains("required hex field empty"), "{message}");
    }

    #[tokio::test]
    async fn build_record_rejects_invalid_proof_data() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x54; 32]);
        material.proof_data_hex = "aabb".into();

        let err = finalize_material_for_build(&scope.pool, &material)
            .await
            .expect_err("proof data wire bytes must parse");
        assert!(format!("{err:#}").contains("proof_data"), "{err:#}");
    }

    #[tokio::test]
    async fn build_record_rejects_non_hex_spent_coin_id() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x55; 32]);
        material.spent_or_folded_coin_ids_hex = vec!["zz".into()];

        let err = finalize_material_for_build(&scope.pool, &material)
            .await
            .expect_err("spent coin IDs must be canonical hex");
        let message = format!("{err:#}");
        assert!(message.contains("spent_or_folded_coin_ids[0]"), "{message}");
        assert!(message.contains("non-lowercase-hex"), "{message}");
    }

    #[tokio::test]
    async fn build_record_rejects_non_hex_output_coin_id() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x56; 32]);
        material.output_refs = vec![SdrPhaseAOutputRef {
            coin_id_hex: "zz".into(),
            blob_id_hex: hex::encode([2; 32]),
            epk_hex: hex::encode([3; 32]),
            out_ciphertext_hex: hex::encode(b"ciphertext"),
            holders: vec!["https://holder.example".into()],
        }];

        let err = finalize_material_for_build(&scope.pool, &material)
            .await
            .expect_err("output coin IDs must be canonical hex");
        let message = format!("{err:#}");
        assert!(message.contains("output_refs[0].coin_id"), "{message}");
        assert!(message.contains("non-lowercase-hex"), "{message}");
    }

    #[tokio::test]
    async fn empty_output_holders_are_rejected_by_phase_a_gate() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x57; 32]);
        material.output_refs = vec![SdrPhaseAOutputRef {
            coin_id_hex: hex::encode([1; 32]),
            blob_id_hex: hex::encode([2; 32]),
            epk_hex: hex::encode([3; 32]),
            out_ciphertext_hex: hex::encode(b"ciphertext"),
            holders: vec![],
        }];

        let err = finalize_material_for_build(&scope.pool, &material)
            .await
            .expect_err("output holders are required");
        let message = format!("{err:#}");
        assert!(message.contains("output_refs[0] incomplete"), "{message}");
    }

    #[tokio::test]
    async fn empty_self_blob_holders_are_rejected_by_phase_a_gate() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x58; 32]);
        material.blob_holders.clear();

        let err = finalize_material_for_build(&scope.pool, &material)
            .await
            .expect_err("self blob holders are required");
        let message = format!("{err:#}");
        assert!(message.contains("empty blob_holders"), "{message}");
    }

    #[tokio::test]
    async fn invalid_record_kind_is_rejected_by_phase_a_gate() {
        let scope = setup_pool().await;
        let mut material = sample_phase_a([0x59; 32]);
        material.record_kind = 0x09;

        let err = finalize_material_for_build(&scope.pool, &material)
            .await
            .expect_err("record kind must be mint/send/receive");
        assert!(format!("{err:#}").contains("record_kind 0x09"), "{err:#}");
    }

    #[tokio::test]
    async fn finalize_due_phase_b_empty_queue_returns_zero() {
        let scope = setup_pool().await;
        use crate::v1::separation::{claim_stack_scan_mode, set_process_stack_mode, ScanStackMode};

        set_process_stack_mode(ScanStackMode::V1);
        // Exclusive DB marker before any v1 write — load_or_create persists an empty
        // genesis snapshot and refuses without this claim.
        claim_stack_scan_mode(&scope.pool, ScanStackMode::V1)
            .await
            .expect("claim stack_scan_mode v1");
        let adapter = EngineAdapter::load_or_create(scope.pool.clone(), Network::Regtest, 0)
            .await
            .expect("empty regtest engine");
        let mtp = FixedInclusionMtp {
            block_hash: [0x61; 32],
            occurred_at: 1_700_000_000,
        };
        let mut rng = StepRng(1);

        let count = finalize_due_phase_b_with_mtp(&adapter, &mtp, &mut rng)
            .await
            .expect("empty queue is not an error");
        assert_eq!(count, 0);
        assert!(
            db_sdr::list_awaiting_first_occurrence(&scope.pool)
                .await
                .expect("query open Phase A")
                .is_empty()
        );
    }

    #[tokio::test]
    async fn finalize_due_phase_b_marks_unparseable_nullifier_failed() {
        let scope = setup_pool().await;
        use crate::v1::separation::{claim_stack_scan_mode, set_process_stack_mode, ScanStackMode};

        set_process_stack_mode(ScanStackMode::V1);
        // Exclusive DB marker before any v1 write — load_or_create persists an empty
        // genesis snapshot and refuses without this claim.
        claim_stack_scan_mode(&scope.pool, ScanStackMode::V1)
            .await
            .expect("claim stack_scan_mode v1");
        let pk = [0x62; 32];
        let mut material = sample_phase_a(pk);
        material.own_nullifier_r_hex = "zz".into();
        db_sdr::insert_phase_a(&scope.pool, &pk, &[0x11; 32], &material)
            .await
            .expect("non-empty corrupt hex passes completeness staging");
        let adapter = EngineAdapter::load_or_create(scope.pool.clone(), Network::Regtest, 0)
            .await
            .expect("empty regtest engine");
        let mtp = FixedInclusionMtp {
            block_hash: [0x63; 32],
            occurred_at: 1_700_000_000,
        };
        let mut rng = StepRng(1);

        let count = finalize_due_phase_b_with_mtp(&adapter, &mtp, &mut rng)
            .await
            .expect("per-row corruption is recorded, not returned as loop failure");
        assert_eq!(count, 0);

        let row = db_sdr::get_phase_a(&scope.pool, &pk)
            .await
            .expect("query failed Phase A")
            .expect("failed row remains durable");
        assert_eq!(row.status, db_sdr::SdrPhaseAStatus::Failed);
        let reason = row.fail_reason.expect("failure reason is durable");
        assert!(reason.contains("SDR Phase B finalise failed"), "{reason}");
        assert!(reason.contains("own_nullifier.r"), "{reason}");
        assert!(reason.contains("non-lowercase-hex"), "{reason}");
    }

    #[tokio::test]
    async fn publish_sdr_rejects_non_self_delivery_kind() {
        let scope = setup_pool().await;
        let row = outbox_row(OutboxKind::ExternalCoin, OutboxStatus::Pending, vec![]);

        let err = publish_sdr_outbox_row(
            &scope.pool,
            &row,
            &[0x01; 32],
            1_700_000_000,
            &publish_rng(),
            &[],
            &[],
        )
        .await
        .expect_err("external row must not enter SDR publisher");
        assert_eq!(
            err,
            DeliveryError::Relay("publish_sdr_outbox_row: kind is not self_delivery".into())
        );
    }

    #[tokio::test]
    async fn publish_sdr_rejects_both_terminal_statuses() {
        let scope = setup_pool().await;
        for status in [OutboxStatus::Completed, OutboxStatus::Failed] {
            let row = outbox_row(OutboxKind::SelfDelivery, status, vec![]);
            let err = publish_sdr_outbox_row(
                &scope.pool,
                &row,
                &[0x01; 32],
                1_700_000_000,
                &publish_rng(),
                &[],
                &[],
            )
            .await
            .expect_err("terminal SDR rows are never republished");
            assert_eq!(
                err,
                DeliveryError::Relay("refuse publish of terminal SDR outbox row".into()),
                "status={status:?}"
            );
        }
    }

    #[tokio::test]
    async fn publish_sdr_names_material_decode_failure() {
        let err = publish_material_error(b"not-json".to_vec()).await;
        match err {
            DeliveryError::Relay(message) => {
                assert!(message.contains("SDR outbox material decode"), "{message}");
                assert!(message.contains("decode SdrOutboxMaterial JSON"), "{message}");
            }
            other => panic!("expected Relay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_sdr_rejects_non_hex_zbe_ciphertext() {
        let mut material = sample_sdr_outbox_material();
        material.zbe_ciphertext_hex = "zz".into();
        let err = publish_material_error(material.encode().expect("encode fixture")).await;
        assert_eq!(
            err,
            DeliveryError::Relay("zbe_ciphertext: non-lowercase-hex".into())
        );
    }

    #[tokio::test]
    async fn publish_sdr_rejects_short_blob_id() {
        let mut material = sample_sdr_outbox_material();
        material.blob_id_hex = "aa".into();
        let err = publish_material_error(material.encode().expect("encode fixture")).await;
        assert_eq!(
            err,
            DeliveryError::Relay("blob_id: expected 32 bytes, got 1".into())
        );
    }

    #[tokio::test]
    async fn publish_sdr_rejects_short_detect_tag() {
        let mut material = sample_sdr_outbox_material();
        material.detect_tag_hex = "aa".into();
        let err = publish_material_error(material.encode().expect("encode fixture")).await;
        assert_eq!(
            err,
            DeliveryError::Relay("detect_tag: expected 32 bytes, got 1".into())
        );
    }

    #[tokio::test]
    async fn publish_sdr_rejects_short_epk() {
        let mut material = sample_sdr_outbox_material();
        material.epk_hex = "aa".into();
        let err = publish_material_error(material.encode().expect("encode fixture")).await;
        assert_eq!(
            err,
            DeliveryError::Relay("epk: expected 32 bytes, got 1".into())
        );
    }

    #[tokio::test]
    async fn publish_sdr_rejects_short_k_tx() {
        let mut material = sample_sdr_outbox_material();
        material.k_tx_hex = "aa".into();
        let err = publish_material_error(material.encode().expect("encode fixture")).await;
        assert_eq!(
            err,
            DeliveryError::Relay("k_tx: expected 32 bytes, got 1".into())
        );
    }

    #[tokio::test]
    async fn publish_sdr_rejects_short_recipient_ivpk() {
        let mut material = sample_sdr_outbox_material();
        material.recipient_ivpk_hex = "aa".into();
        let err = publish_material_error(material.encode().expect("encode fixture")).await;
        assert_eq!(
            err,
            DeliveryError::Relay("recipient_ivpk: expected 32 bytes, got 1".into())
        );
    }

    #[tokio::test]
    async fn publish_sdr_rejects_short_recipient_op_pk() {
        let mut material = sample_sdr_outbox_material();
        material.recipient_op_pk_hex = "aa".into();
        let err = publish_material_error(material.encode().expect("encode fixture")).await;
        assert_eq!(
            err,
            DeliveryError::Relay("recipient_op_pk: expected 32 bytes, got 1".into())
        );
    }

    #[tokio::test]
    async fn publish_sdr_decode_gate_rejects_empty_recipient_relays() {
        let mut material = sample_sdr_outbox_material();
        material.recipient_relays.clear();
        let bytes = serde_json::to_vec(&material).expect("raw corrupt fixture JSON");

        let err = publish_material_error(bytes).await;
        match err {
            DeliveryError::Relay(message) => {
                assert!(message.contains("SDR outbox material decode"), "{message}");
                assert!(message.contains("incomplete after decode"), "{message}");
            }
            other => panic!("expected Relay decode refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_sdr_decode_gate_rejects_empty_blob_holders() {
        let mut material = sample_sdr_outbox_material();
        material.blob_holders.clear();
        let bytes = serde_json::to_vec(&material).expect("raw corrupt fixture JSON");

        let err = publish_material_error(bytes).await;
        match err {
            DeliveryError::Relay(message) => {
                assert!(message.contains("SDR outbox material decode"), "{message}");
                assert!(message.contains("incomplete after decode"), "{message}");
            }
            other => panic!("expected Relay decode refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_sdr_rejects_content_address_mismatch() {
        let mut material = sample_sdr_outbox_material();
        material.blob_id_hex = hex::encode([0xFF; 32]);

        let err = publish_material_error(material.encode().expect("encode fixture")).await;
        assert_eq!(
            err,
            DeliveryError::Relay(
                "SDR material: zbe_ciphertext does not content-address to blob_id".into()
            )
        );
    }

    #[tokio::test]
    async fn publish_sdr_decode_gate_rejects_invalid_record_kind() {
        let mut material = sample_sdr_outbox_material();
        material.record_kind = 0x09;
        let bytes = serde_json::to_vec(&material).expect("raw corrupt fixture JSON");

        let err = publish_material_error(bytes).await;
        match err {
            DeliveryError::Relay(message) => {
                assert!(message.contains("SDR outbox material decode"), "{message}");
                assert!(message.contains("record_kind 0x09"), "{message}");
                assert!(message.contains("not mint/send/receive"), "{message}");
            }
            other => panic!("expected Relay decode refusal, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_sdr_surfaces_blossom_holder_failure() {
        let scope = setup_pool().await;
        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .and(path("/blossom/upload"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;
        let mut material = sample_sdr_outbox_material();
        material.blob_holders = vec![server.uri()];
        let row = outbox_row(
            OutboxKind::SelfDelivery,
            OutboxStatus::Pending,
            material.encode().expect("encode fixture"),
        );

        let err = publish_sdr_outbox_row(
            &scope.pool,
            &row,
            &[0x01; 32],
            1_700_000_000,
            &publish_rng(),
            &[],
            &[],
        )
        .await
        .expect_err("HTTP 500 must identify its holder");
        match err {
            DeliveryError::Blossom { holder, .. } => assert_eq!(holder, server.uri()),
            other => panic!("expected Blossom, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_sdr_rejects_non_websocket_relay_after_upload() {
        let scope = setup_pool().await;
        let server = MockServer::start().await;
        let mut material = sample_sdr_outbox_material();
        material.blob_holders = vec![server.uri()];
        material.recipient_relays = vec!["https://example.com".into()];
        mount_successful_blossom(&server, &material).await;
        let row = outbox_row(
            OutboxKind::SelfDelivery,
            OutboxStatus::Pending,
            material.encode().expect("encode fixture"),
        );

        let err = publish_sdr_outbox_row(
            &scope.pool,
            &row,
            &[0x01; 32],
            1_700_000_000,
            &publish_rng(),
            &[],
            &[],
        )
        .await
        .expect_err("HTTP relay URL must be refused");
        match err {
            DeliveryError::Relay(message) => {
                assert!(message.contains("invalid relay URL"), "{message}");
                assert!(message.contains("https://example.com"), "{message}");
            }
            other => panic!("expected Relay, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn publish_sdr_reports_when_no_relay_accepts() {
        let scope = setup_pool().await;
        let server = MockServer::start().await;
        let mut material = sample_sdr_outbox_material();
        material.blob_holders = vec![server.uri()];
        material.recipient_relays = vec!["ws://127.0.0.1:1/".into()];
        mount_successful_blossom(&server, &material).await;
        let row = outbox_row(
            OutboxKind::SelfDelivery,
            OutboxStatus::Pending,
            material.encode().expect("encode fixture"),
        );

        let err = publish_sdr_outbox_row(
            &scope.pool,
            &row,
            &[0x01; 32],
            1_700_000_000,
            &publish_rng(),
            &[],
            &[],
        )
        .await
        .expect_err("unreachable relay cannot accept the gift wrap");
        match err {
            DeliveryError::NoRelayAccepted { results } => {
                assert!(!results.is_empty(), "one relay outcome is required");
                assert!(results.iter().all(|result| !result.accepted));
                assert_eq!(results[0].relay_url, "ws://127.0.0.1:1/");
            }
            other => panic!("expected NoRelayAccepted, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn overlap_sdr_reaches_recipient_and_manifest_on_both_planes() {
        let scope = setup_pool().await;
        let recipient_store = MockServer::start().await;
        let manifest_store = MockServer::start().await;
        let (recipient_relay, recipient_events) =
            crate::v1::delivery::start_overlap_test_relay(true).await;
        let (seed_relay, seed_events) =
            crate::v1::delivery::start_overlap_test_relay(true).await;
        let mut material = sample_sdr_outbox_material();
        material.blob_holders = vec![recipient_store.uri()];
        material.recipient_relays = vec![recipient_relay];
        mount_successful_blossom(&recipient_store, &material).await;
        mount_successful_blossom(&manifest_store, &material).await;
        let row = insert_sdr_publish_fixture(&scope.pool, &material).await;

        publish_sdr_outbox_row(
            &scope.pool,
            &row,
            &[0x01; 32],
            1_700_000_000,
            &publish_rng(),
            &[manifest_store.uri()],
            &[seed_relay],
        )
        .await
        .expect("SDR recipient and recovery overlap placement");

        let published = db_outbox::get_by_id(&scope.pool, &row.outbox_id)
            .await
            .expect("reload published SDR")
            .expect("published SDR row");
        assert_eq!(published.status, OutboxStatus::Completed);
        let event_id = published.event_id.expect("published SDR event id");
        assert_eq!(
            recipient_events.lock().expect("recipient events").as_slice(),
            &[event_id]
        );
        assert_eq!(
            seed_events.lock().expect("seed events").as_slice(),
            &[event_id]
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
            manifest_store
                .received_requests()
                .await
                .expect("manifest Blossom requests")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn overlap_sdr_blob_failure_leaves_outbox_unpublished() {
        let scope = setup_pool().await;
        let recipient_store = MockServer::start().await;
        let manifest_store = MockServer::start().await;
        let (recipient_relay, _) =
            crate::v1::delivery::start_overlap_test_relay(true).await;
        let mut material = sample_sdr_outbox_material();
        material.blob_holders = vec![recipient_store.uri()];
        material.recipient_relays = vec![recipient_relay];
        mount_successful_blossom(&recipient_store, &material).await;
        Mock::given(method("PUT"))
            .and(path("/blossom/upload"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&manifest_store)
            .await;
        let row = insert_sdr_publish_fixture(&scope.pool, &material).await;

        let error = publish_sdr_outbox_row(
            &scope.pool,
            &row,
            &[0x01; 32],
            1_700_000_000,
            &publish_rng(),
            &[manifest_store.uri()],
            &["ws://127.0.0.1:1/".into()],
        )
        .await
        .expect_err("recipient placement alone must not satisfy SDR blob overlap");
        assert!(matches!(error, DeliveryError::OverlapBlobStore { .. }));
        let unchanged = db_outbox::get_by_id(&scope.pool, &row.outbox_id)
            .await
            .expect("reload failed SDR")
            .expect("failed SDR row retained");
        assert_eq!(unchanged.status, OutboxStatus::Pending);
        assert_eq!(unchanged.attempt_n, 0);
        assert!(unchanged.event_id.is_none());
    }

    #[tokio::test]
    async fn overlap_sdr_seed_rejection_leaves_outbox_unpublished() {
        let scope = setup_pool().await;
        let recipient_store = MockServer::start().await;
        let manifest_store = MockServer::start().await;
        let (recipient_relay, _) =
            crate::v1::delivery::start_overlap_test_relay(true).await;
        let (seed_relay, _) =
            crate::v1::delivery::start_overlap_test_relay(false).await;
        let mut material = sample_sdr_outbox_material();
        material.blob_holders = vec![recipient_store.uri()];
        material.recipient_relays = vec![recipient_relay];
        mount_successful_blossom(&recipient_store, &material).await;
        mount_successful_blossom(&manifest_store, &material).await;
        let row = insert_sdr_publish_fixture(&scope.pool, &material).await;

        let error = publish_sdr_outbox_row(
            &scope.pool,
            &row,
            &[0x01; 32],
            1_700_000_000,
            &publish_rng(),
            &[manifest_store.uri()],
            &[seed_relay],
        )
        .await
        .expect_err("recipient placement alone must not satisfy SDR relay overlap");
        assert!(matches!(error, DeliveryError::OverlapSeedRelay { .. }));
        let unchanged = db_outbox::get_by_id(&scope.pool, &row.outbox_id)
            .await
            .expect("reload failed SDR")
            .expect("failed SDR row retained");
        assert_eq!(unchanged.status, OutboxStatus::Pending);
        assert_eq!(unchanged.attempt_n, 0);
        assert!(unchanged.event_id.is_none());
    }

    #[test]
    fn record_kind_mapping() {
        assert!(matches!(
            record_kind_from_witness(true, false),
            RecordKind::Mint
        ));
        assert!(matches!(
            record_kind_from_witness(false, true),
            RecordKind::Receive
        ));
        assert!(matches!(
            record_kind_from_witness(false, false),
            RecordKind::Send
        ));
    }
}
