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

use super::adapter::EngineAdapter;
use super::db_outbox::OutboxKind;
use super::db_sdr;
use super::delivery::{fresh_esk, insert_sdr_outbox_pending, DeliveryError};
use super::nostr::nip59::SecureRandom;
use super::outbox_material::{SdrOutboxMaterial, SdrPhaseAMaterial, SdrPhaseAOutputRef};
use super::OsSecureRandom;

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
/// crate-private. Builds a provisional inclusion/MTP source from
/// `tip_hash` + wall-clock `occurred_at` (regtest/dev stand-in until
/// BIP-113 MTP is wired).
///
/// Incomplete material → named [`db_sdr::mark_failed`] (no silent skip).
/// Success → `insert_sdr_outbox_pending` + [`db_sdr::mark_finalised`] so
/// Drive/Resume pick up the sealed SDR.
pub async fn finalize_due_phase_b_adapter(
    adapter: &EngineAdapter,
    tip_hash: [u8; 32],
    occurred_at: u64,
) -> Result<usize> {
    let mtp = FixedInclusionMtp {
        block_hash: tip_hash,
        occurred_at,
    };
    let mut rng = OsSecureRandom;
    finalize_due_phase_b_with_mtp(adapter, &mtp, &mut rng).await
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
    insert_sdr_outbox_pending(
        pool,
        subject,
        transition_pk,
        &material,
        phase_a.replication_k,
    )
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
    auth_expiration: u64,
    rng: &std::sync::Mutex<Box<dyn SecureRandom + Send>>,
) -> Result<(), DeliveryError> {
    use super::blossom::{BlossomClient, RetentionClass, UploadBinding};
    use super::db_outbox::{self, OutboxStatus, PublishArtefacts, StoredReceipt};
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
    if row.status == OutboxStatus::AwaitingReceipts {
        return Err(DeliveryError::Relay(
            "refuse SDR republish after ACK (awaiting_receipts)".into(),
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
    let mut receipts = Vec::new();
    for holder in &mat.blob_holders {
        let upload = client
            .upload(
                holder,
                &zbe,
                Some(&binding),
                operator_op_sk,
                now,
                auth_expiration,
            )
            .await
            .map_err(|e| DeliveryError::Blossom {
                holder: holder.clone(),
                error: e,
            })?;
        if let Some(r) = upload.receipt {
            receipts.push(r);
        }
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

    for r in &receipts {
        db_outbox::store_receipt(
            pool,
            &row.outbox_id,
            &StoredReceipt {
                holder_op_pubkey: r.holder_op_pubkey,
                receipt_json: r.receipt_json.clone(),
                retention_class: r.retention_class.clone(),
                stored_at: r.stored_at,
            },
        )
        .await
        .map_err(|e| DeliveryError::Relay(format!("SDR outbox store_receipt: {e:#}")))?;
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_db::setup_pool;
    use crate::v1::db_outbox::{self, OutboxKind, OutboxStatus};
    use crate::v1::db_sdr;
    use crate::v1::outbox_material::{SdrOutboxMaterial, SdrPhaseAMaterial};

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
            replication_k: 3,
        }
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
