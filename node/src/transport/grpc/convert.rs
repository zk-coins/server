//! Domain `Job` / `JobEvent` / chain types → `kernel.v1` proto messages.
//!
//! Conversion is fail-closed: a domain job that cannot be projected into a
//! **complete** proto `Job` (required digests for `awaiting_signature` /
//! `completed`) yields `KernelError::internal_error` rather than an `Ok`
//! with empty optional fields that pretend the payload is absent.

use uuid::Uuid;

use crate::kernel::access::{
    AccountStateView, CreditReceipt, GetCoinProofCommand, GetRecordCommand, PullCommand,
    PullResult, RecordBlob as DomainRecordBlob, RecordRef, SessionAuthority, SessionBoundRequest,
};
use crate::kernel::attestation::{AttestBalanceCommand, AttestCeiling};
use crate::kernel::bootstrap::{EntrustCommand, RevokeCommand};
use crate::kernel::chain::{
    BootstrapManifest as DomainBootstrapManifest, InscriptionCursor, InscriptionLimit,
};
use crate::kernel::grants::{GrantAssetScope, GrantScope, IssueViewGrantCommand};
use crate::kernel::jobs::submit::parse_idempotency_key;
use crate::kernel::publish::{
    refuse_v1_fee_fields, PublishBlockAnchor, PublishCommand, PublishOutcome,
};
use crate::kernel::types::{
    ChanBind, Digest32, Issuance, JobKind, JobPayload, OutputTemplate, PublisherChoice,
    SubjectAddress, TransitionCommon, XOnlyKey,
};
use crate::kernel::{
    AccumulatorTip as DomainAccumulatorTip, KernelInfo, ListInscriptions as DomainListInscriptions,
    ListedInscription, NullifierPath as DomainNullifierPath,
    NullifierPathRequest as DomainNullifierPathRequest,
};
use crate::kernel::{
    Job, JobEvent, JobId, JobState, KernelError, KernelErrorCode, KernelResult, SignTransition,
    TransitionCommand,
};
use crate::v1::{self, WalletSignSubmission};
use kernel_proto::{
    AccountStateResult as ProtoAccountStateResult, AccumulatorTip as ProtoAccumulatorTip,
    AttestRequest as ProtoAttestRequest, AwaitingSignature as ProtoAwaitingSignature,
    BootstrapManifest as ProtoBootstrapManifest, CoinProofBlob as ProtoCoinProofBlob,
    CoinProofRequest as ProtoCoinProofRequest, EntrustRequest as ProtoEntrustRequest,
    EntrustResult as ProtoEntrustResult, GrantRequest as ProtoGrantRequest, Info as ProtoInfo,
    Issuance as ProtoIssuance, Job as ProtoJob, JobError as ProtoJobError,
    JobEvent as ProtoJobEvent, JobResult as ProtoJobResult,
    ListInscriptionsRequest as ProtoListInscriptionsRequest, NullifierPath as ProtoNullifierPath,
    NullifierPathRequest as ProtoNullifierPathRequest, OutputTemplate as ProtoOutputTemplate,
    PublishRequest as ProtoPublishRequest, PublishResult as ProtoPublishResult,
    PullRequest as ProtoPullRequest, PullResult as ProtoPullResult, Receipt as ProtoReceipt,
    RecordBlob as ProtoRecordBlob, RecordRef as ProtoRecordRef,
    RecordRequest as ProtoRecordRequest, RevokeRequest as ProtoRevokeRequest,
    RevokeResult as ProtoRevokeResult, Scope as ProtoScope, SignRequest as ProtoSignRequest,
    TransitionRequest as ProtoTransitionRequest,
};
use shared::spec_v1::Address;

/// Parse proto `AttestRequest` into a domain [`AttestBalanceCommand`].
///
/// No OwnershipProof fields exist on the proto message (API-layer gate).
/// Width failures → `malformed_request`. Ceiling pair: both empty ⇒
/// node default; both set ⇒ explicit; mixed ⇒ malformed.
pub(crate) fn parse_attest_request(req: ProtoAttestRequest) -> KernelResult<AttestBalanceCommand> {
    let subject = parse_subject_address(&req.subject)?;
    let asset_id = parse_digest32(&req.asset_id, "asset_id")?;
    let nonce = parse_exact_32(&req.nonce, "nonce")?;
    let chan_bind = ChanBind(parse_exact_32(&req.chan_bind, "chan_bind")?);

    // Proto3: empty `nav_ceiling` + `size_ceiling == 0` ⇒ node default.
    // Non-empty nav ⇒ explicit pair (size may be 0). Size without nav is
    // mixed and malformed (§7.5 both-or-neither).
    let ceiling = if req.nav_ceiling.is_empty() {
        if req.size_ceiling != 0 {
            return Err(KernelError::new(
                KernelErrorCode::MalformedRequest,
                "nav_ceiling and size_ceiling must both be present or both omitted",
            ));
        }
        AttestCeiling::NodeDefault
    } else {
        let nav_ceiling = Digest32(parse_exact_32(&req.nav_ceiling, "nav_ceiling")?);
        AttestCeiling::Explicit {
            nav_ceiling,
            size_ceiling: req.size_ceiling,
        }
    };

    Ok(AttestBalanceCommand {
        subject,
        asset_id,
        ceiling,
        nonce,
        chan_bind,
    })
}

/// Parse proto `GrantRequest` into a domain [`IssueViewGrantCommand`].
///
/// No OwnershipProof fields on the proto. Scope sentinels follow §5.1:
/// `all_assets` / empty list, `not_after = 0` is epoch-closed (not
/// unbounded — unbounded is `2⁶³−1`).
pub(crate) fn parse_grant_request(req: ProtoGrantRequest) -> KernelResult<IssueViewGrantCommand> {
    let subject = parse_subject_address(&req.subject)?;
    let grantee_pk = parse_xonly(&req.grantee_pk, "grantee_pk")?;
    let nonce = parse_exact_32(&req.nonce, "nonce")?;
    let chan_bind = ChanBind(parse_exact_32(&req.chan_bind, "chan_bind")?);
    let scope = match req.scope {
        Some(s) => parse_grant_scope(s)?,
        None => {
            return Err(KernelError::new(
                KernelErrorCode::MalformedRequest,
                "scope is required",
            ));
        }
    };

    Ok(IssueViewGrantCommand {
        subject,
        grantee_pk,
        scope,
        expiry: req.expiry,
        nonce,
        chan_bind,
    })
}

fn parse_grant_scope(scope: ProtoScope) -> KernelResult<GrantScope> {
    let assets = if scope.all_assets {
        if !scope.asset_ids.is_empty() {
            return Err(KernelError::new(
                KernelErrorCode::MalformedRequest,
                "scope.all_assets=true must not carry asset_ids",
            ));
        }
        GrantAssetScope::All
    } else if scope.asset_ids.is_empty() {
        // Proto default: empty list without all_assets — treat as malformed
        // rather than inventing "*".
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "scope must set all_assets or a non-empty asset_ids list",
        ));
    } else {
        let mut ids = Vec::with_capacity(scope.asset_ids.len());
        for (i, raw) in scope.asset_ids.iter().enumerate() {
            ids.push(Digest32(parse_exact_32(
                raw,
                &format!("scope.asset_ids[{i}]"),
            )?));
        }
        GrantAssetScope::Selected(ids)
    };

    Ok(GrantScope {
        assets,
        not_before: scope.not_before,
        // Proto3 zero default for not_after is a closed epoch window, not
        // unbounded. Callers that want unbounded must send 2⁶³−1 explicitly
        // (§5.1). We do not rewrite 0 → SCOPE_NOT_AFTER_UNBOUNDED here.
        not_after: scope.not_after,
    })
}

// ---------------------------------------------------------------------------
// Block 7 — Pull / Record / CoinProof / AccountState / Receipts
// ---------------------------------------------------------------------------

/// Parse proto `PullRequest` into a domain [`PullCommand`].
///
/// # Authority (proto GAP)
///
/// Normative `PullRequest` has no ownership/grant discriminator. The trusted
/// API layer that verified the proof **must** pass [`SessionAuthority`] as a
/// separate argument (same trust class as `subject` / `resolved_scope`).
/// This function never invents an authority.
pub(crate) fn parse_pull_request(
    req: ProtoPullRequest,
    authority: SessionAuthority,
) -> KernelResult<PullCommand> {
    let nonce = parse_exact_32(&req.nonce, "nonce")?;
    let subject = parse_subject_address(&req.subject)?;
    let chan_bind = ChanBind(parse_exact_32(&req.chan_bind, "chan_bind")?);
    let resolved_scope = match req.resolved_scope {
        Some(s) => parse_grant_scope(s)?,
        None => {
            return Err(KernelError::new(
                KernelErrorCode::MalformedRequest,
                "resolved_scope is required",
            ));
        }
    };
    Ok(PullCommand {
        nonce,
        subject,
        resolved_scope,
        chan_bind,
        authority,
    })
}

/// Domain [`PullResult`] → proto.
pub(crate) fn pull_result_to_proto(result: &PullResult) -> ProtoPullResult {
    ProtoPullResult {
        records: result.records.iter().map(record_ref_to_proto).collect(),
        session: result.session.as_str().to_string(),
        session_expiry: result.session_expiry,
    }
}

fn record_ref_to_proto(r: &RecordRef) -> ProtoRecordRef {
    ProtoRecordRef {
        record_id: r.record_id.0.to_vec(),
        record_type: r.record_type.as_str().to_string(),
        transition_kind: r
            .transition_kind
            .map(|k| k.as_str().to_string())
            .unwrap_or_default(),
        blob_id: r.blob_id.0.to_vec(),
        occurred_at: r.occurred_at,
    }
}

/// Parse proto `RecordRequest`.
pub(crate) fn parse_record_request(req: ProtoRecordRequest) -> KernelResult<GetRecordCommand> {
    Ok(GetRecordCommand {
        record_id: Digest32(parse_exact_32(&req.record_id, "record_id")?),
        session: req.session,
        chan_bind: ChanBind(parse_exact_32(&req.chan_bind, "chan_bind")?),
    })
}

/// Domain record blob → proto.
pub(crate) fn record_blob_to_proto(blob: &DomainRecordBlob) -> ProtoRecordBlob {
    ProtoRecordBlob {
        canonical: blob.canonical.clone(),
        record_type: blob.record_type.as_str().to_string(),
        transition_kind: blob
            .transition_kind
            .map(|k| k.as_str().to_string())
            .unwrap_or_default(),
    }
}

/// Parse proto `CoinProofRequest`.
pub(crate) fn parse_coin_proof_request(
    req: ProtoCoinProofRequest,
) -> KernelResult<GetCoinProofCommand> {
    Ok(GetCoinProofCommand {
        coin_id: Digest32(parse_exact_32(&req.coin_id, "coin_id")?),
        session: req.session,
        chan_bind: ChanBind(parse_exact_32(&req.chan_bind, "chan_bind")?),
    })
}

/// Canonical coin-proof bytes → proto.
pub(crate) fn coin_proof_blob_to_proto(canonical: Vec<u8>) -> ProtoCoinProofBlob {
    ProtoCoinProofBlob { canonical }
}

/// Parse proto `AccountStateRequest` / `SubscribeReceiptsRequest` shape.
///
/// Shared by `GetAccountState` and `SubscribeReceipts`. Both requests carry
/// **only** `session` + `chan_bind` — no client subject field.
pub(crate) fn parse_session_bound(
    session: String,
    chan_bind: Vec<u8>,
) -> KernelResult<SessionBoundRequest> {
    Ok(SessionBoundRequest {
        session,
        chan_bind: ChanBind(parse_exact_32(&chan_bind, "chan_bind")?),
    })
}

/// Domain credit receipt → proto `Receipt`.
///
/// Server-side `subject` is admission-only and is **not** on the wire
/// message (proto has no subject field). Amount is a decimal `u128` string.
pub(crate) fn receipt_to_proto(receipt: &CreditReceipt) -> ProtoReceipt {
    ProtoReceipt {
        coin_id: receipt.coin_id.0.to_vec(),
        asset_id: receipt.asset_id.0.to_vec(),
        amount: receipt.amount.to_string(),
        state: receipt.state.as_str().to_string(),
        credited_at: receipt.credited_at,
    }
}

/// Domain account-state view → proto.
///
/// Optional fields that are unknown stay **empty bytes** — never a
/// fabricated 32-byte zero nullifier. Spec: empty iff no prior
/// state-advancing transition.
pub(crate) fn account_state_to_proto(
    view: &AccountStateView,
) -> KernelResult<ProtoAccountStateResult> {
    let (pk, r) = match (view.last_nullifier_pk, view.last_nullifier_r) {
        (Some(pk), Some(r)) => (pk.to_vec(), r.to_vec()),
        (None, None) => (Vec::new(), Vec::new()),
        (Some(_), None) | (None, Some(_)) => {
            return Err(KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Corrupt account state",
                "last_nullifier_pk and last_nullifier_r must both be present or both absent",
            ));
        }
    };
    Ok(ProtoAccountStateResult {
        account_state: view.account_state.clone(),
        state_head: view.state_head.0.to_vec(),
        head_record_id: view
            .head_record_id
            .map(|d| d.0.to_vec())
            .unwrap_or_default(),
        send_counter: view.send_counter,
        current_pubkey: view.current_pubkey.to_vec(),
        last_nullifier_pk: pk,
        last_nullifier_r: r,
    })
}

/// Parse session authority wire token (trusted API → kernel).
///
/// Used until the frozen `PullRequest` message gains an authority field.
pub(crate) fn parse_session_authority(raw: &str) -> KernelResult<SessionAuthority> {
    match raw.trim() {
        "ownership" => Ok(SessionAuthority::Ownership),
        "grant" => Ok(SessionAuthority::Grant),
        "" => Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "session authority is required (ownership|grant); normative \
             PullRequest has no field — trusted API must supply it",
        )),
        other => Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("session authority must be ownership|grant; got {other:?}"),
        )),
    }
}

fn parse_exact_32(bytes: &[u8], field: &str) -> KernelResult<[u8; 32]> {
    match bytes.try_into() {
        Ok(a) => Ok(a),
        Err(_) => Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("{field} must be exactly 32 bytes; got {}", bytes.len()),
        )),
    }
}

// ---------------------------------------------------------------------------
// Block 6 — chain read procedures
// ---------------------------------------------------------------------------

/// Parse proto `ListInscriptionsRequest` into a domain request.
///
/// Defaults (proto3 absence): `from_* = 0`, `limit = 100`. An explicit
/// `limit = 0` or `limit > 1000` is `bounds_exceeded` — never silently
/// clamped.
pub(crate) fn parse_list_inscriptions_request(
    req: ProtoListInscriptionsRequest,
) -> KernelResult<DomainListInscriptions> {
    // §7.5: each from_* is optional with default 0. The all-absent case
    // is exactly the inclusive stream origin — one constructor, not three
    // independent zeros that could drift from `InscriptionCursor::origin`.
    let from = match (req.from_height, req.from_tx_index, req.from_vin_index) {
        (None, None, None) => InscriptionCursor::origin(),
        (h, t, v) => InscriptionCursor {
            height: h.unwrap_or(0),
            tx_index: t.unwrap_or(0),
            vin_index: v.unwrap_or(0),
        },
    };
    let limit_raw = match req.limit {
        Some(n) => n,
        None => InscriptionLimit::DEFAULT,
    };
    let limit = InscriptionLimit::new(limit_raw)?;
    Ok(DomainListInscriptions { from, limit })
}

/// Parse proto `NullifierPathRequest` (pubkey width = 32).
pub(crate) fn parse_nullifier_path_request(
    req: ProtoNullifierPathRequest,
) -> KernelResult<DomainNullifierPathRequest> {
    let pubkey = XOnlyKey(parse_exact_32(&req.pubkey, "pubkey")?);
    Ok(DomainNullifierPathRequest { pubkey })
}

/// Domain `AccumulatorTip` → proto.
pub(crate) fn accumulator_tip_to_proto(tip: &DomainAccumulatorTip) -> ProtoAccumulatorTip {
    ProtoAccumulatorTip {
        root: tip.root.0.to_vec(),
        tip_block_hash: tip.tip_block_hash.0.to_vec(),
        tip_height: tip.tip_height,
        size: tip.size,
    }
}

/// Domain listed inscription → proto `Inscription`.
pub(crate) fn inscription_to_proto(ins: &ListedInscription) -> kernel_proto::Inscription {
    kernel_proto::Inscription {
        txid: ins.txid.to_vec(),
        height: ins.height,
        count: ins.count,
        format: ins.format,
        nullifiers: ins
            .nullifiers
            .iter()
            .map(|n| kernel_proto::Nullifier {
                pubkey: n.pubkey.to_vec(),
                r: n.r.to_vec(),
                state: n.state.as_str().to_string(),
            })
            .collect(),
        confirmation_state: ins.confirmation_state.as_str().to_string(),
        tx_index: ins.tx_index,
        vin_index: ins.vin_index,
    }
}

/// Domain `NullifierPath` → proto (`present` bool + empty path when absent).
///
/// `present` is projected **only** via [`DomainNullifierPath::is_present`]
/// so the wire bool and the domain discriminant cannot drift. Callers
/// never pass an `Err` into this function — presence is never derived
/// from a failure.
pub(crate) fn nullifier_path_to_proto(path: &DomainNullifierPath) -> ProtoNullifierPath {
    let present = path.is_present();
    match path {
        DomainNullifierPath::Present {
            root,
            tip_height,
            tip_block_hash,
            leaf,
            position,
            audit_path,
            tree_size,
        } => ProtoNullifierPath {
            root: root.0.to_vec(),
            tip_height: *tip_height,
            present,
            leaf: leaf.0.to_vec(),
            position: *position,
            audit_path: audit_path.iter().map(|d| d.0.to_vec()).collect(),
            tree_size: *tree_size,
            tip_block_hash: tip_block_hash.0.to_vec(),
        },
        DomainNullifierPath::Absent {
            root,
            tip_height,
            tip_block_hash,
            tree_size,
        } => ProtoNullifierPath {
            root: root.0.to_vec(),
            tip_height: *tip_height,
            present,
            leaf: Vec::new(),
            position: 0,
            audit_path: Vec::new(),
            tree_size: *tree_size,
            tip_block_hash: tip_block_hash.0.to_vec(),
        },
    }
}

/// Domain `KernelInfo` → proto `Info`.
pub(crate) fn kernel_info_to_proto(info: &KernelInfo) -> ProtoInfo {
    let mut circuit_digests = std::collections::HashMap::new();
    circuit_digests.insert("C".to_string(), info.circuit_digest_c.0.to_vec());
    circuit_digests.insert(
        "C_balance".to_string(),
        info.circuit_digest_c_balance.0.to_vec(),
    );
    // Single source for both wire fields: `is_ready` + `reason` encode
    // the structural invariant (ready ⇒ no reason; not-ready ⇒ exactly
    // one). A parallel match here would be a second path to the same
    // claim and a drift source.
    let ready = info.readiness.is_ready();
    let ready_reason = info.readiness.reason().map(|r| r.as_str().to_string());
    ProtoInfo {
        network: info.network.as_str().to_string(),
        protocol_version: info.protocol_version.to_string(),
        circuit_digests,
        relay_url: info.relay_url.clone(),
        blossom_url: info.blossom_url.clone(),
        finality_confirmations: info.finality_confirmations,
        max_tx_inputs: info.max_tx_inputs,
        max_tx_outputs: info.max_tx_outputs,
        max_rx_coins: info.max_rx_coins,
        max_account_assets: info.max_account_assets,
        ready,
        bitcoin_tip_height: info.bitcoin_tip_height,
        accumulator_root: info.accumulator_root.0.to_vec(),
        scanner_lag: info.scanner_lag,
        max_blob_bytes: info.max_blob_bytes,
        activation_height: info.activation_height,
        bootstrap: Some(bootstrap_manifest_to_proto(&info.bootstrap)),
        kernel_parts: info
            .kernel_parts
            .iter()
            .map(|p| p.as_str().to_string())
            .collect(),
        ready_reason,
        bootstrap_pubkey: info.bootstrap_pubkey.0.to_vec(),
    }
}

fn bootstrap_manifest_to_proto(m: &DomainBootstrapManifest) -> ProtoBootstrapManifest {
    ProtoBootstrapManifest {
        network: m.network.as_str().to_string(),
        protocol_version: m.protocol_version.clone(),
        seed_relays: m.seed_relays.clone(),
        blob_stores: m.blob_stores.clone(),
        operator_ids: m.operator_ids.iter().map(|k| k.0.to_vec()).collect(),
        issued_at: m.issued_at,
        expires_at: m.expires_at,
        manifest_sig: m.manifest_sig.to_vec(),
    }
}

/// Parse proto `SignRequest` into a domain [`SignTransition`].
///
/// Width checks (proto comment): `signature` **must** be 64 bytes,
/// `s2c_nonce` **must** be 32 bytes — otherwise `malformed_request`.
/// Empty / non-UUID `job_id` is also `malformed_request`.
pub(crate) fn parse_sign_request(req: ProtoSignRequest) -> KernelResult<SignTransition> {
    let raw = req.job_id.trim();
    if raw.is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "job_id is required",
        ));
    }
    let id = Uuid::parse_str(raw).map_err(|_| {
        KernelError::new(KernelErrorCode::MalformedRequest, "job_id must be a UUID")
    })?;

    let signature: [u8; 64] = match req.signature.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            return Err(KernelError::new(
                KernelErrorCode::MalformedRequest,
                format!(
                    "signature must be exactly 64 bytes; got {}",
                    req.signature.len()
                ),
            ));
        }
    };
    let s2c_nonce: [u8; 32] = match req.s2c_nonce.as_slice().try_into() {
        Ok(a) => a,
        Err(_) => {
            return Err(KernelError::new(
                KernelErrorCode::MalformedRequest,
                format!(
                    "s2c_nonce must be exactly 32 bytes; got {}",
                    req.s2c_nonce.len()
                ),
            ));
        }
    };

    Ok(SignTransition {
        id: JobId(id),
        submission: WalletSignSubmission {
            signature,
            s2c_nonce,
        },
    })
}

/// Parse proto `TransitionRequest` into a closed domain [`TransitionCommand`].
///
/// Width / presence failures are `malformed_request`. Bounds
/// (list lengths over max) are left to
/// [`crate::kernel::jobs::submit::validate_transition_command`].
///
/// v1: non-empty `fee_address` is always malformed (§7.5 matrix — case (b)
/// is deferred).
pub(crate) fn parse_transition_request(
    req: ProtoTransitionRequest,
) -> KernelResult<TransitionCommand> {
    let kind = req.kind.trim();
    if kind.is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "kind is required (mint|send|receive)",
        ));
    }

    let idempotency_key = parse_idempotency_key(req.idempotency_key.trim())?;
    let subject = parse_subject_address(&req.subject)?;
    let next_pubkey = parse_xonly(&req.next_pubkey, "next_pubkey")?;
    let npk_rand = parse_digest32(&req.npk_rand, "npk_rand")?;
    let publisher = parse_publisher_choice(&req.publisher_pubkey, &req.fee_address)?;

    let common = TransitionCommon {
        subject,
        next_pubkey,
        npk_rand,
        publisher,
        idempotency_key,
    };

    match kind {
        "mint" => {
            refuse_nonempty_digests(&req.input_coins, "input_coins", "mint")?;
            refuse_nonempty_digests(&req.fold_coin_ids, "fold_coin_ids", "mint")?;
            let issuance = match req.issuance {
                Some(i) => parse_issuance(i)?,
                None => {
                    return Err(KernelError::new(
                        KernelErrorCode::MalformedRequest,
                        "kind=mint requires issuance",
                    ));
                }
            };
            let output_templates = parse_output_templates(&req.output_templates)?;
            Ok(TransitionCommand::Mint {
                common,
                issuance,
                output_templates,
            })
        }
        "send" => {
            refuse_nonempty_digests(&req.fold_coin_ids, "fold_coin_ids", "send")?;
            if req.issuance.is_some() {
                return Err(KernelError::new(
                    KernelErrorCode::MalformedRequest,
                    "kind=send must not carry issuance",
                ));
            }
            let input_coins = parse_digest_list(&req.input_coins, "input_coins")?;
            let output_templates = parse_output_templates(&req.output_templates)?;
            Ok(TransitionCommand::Send {
                common,
                input_coins,
                output_templates,
            })
        }
        "receive" => {
            refuse_nonempty_digests(&req.input_coins, "input_coins", "receive")?;
            if !req.output_templates.is_empty() {
                return Err(KernelError::new(
                    KernelErrorCode::MalformedRequest,
                    "kind=receive must not carry output_templates",
                ));
            }
            if req.issuance.is_some() {
                return Err(KernelError::new(
                    KernelErrorCode::MalformedRequest,
                    "kind=receive must not carry issuance",
                ));
            }
            let fold_coin_ids = parse_digest_list(&req.fold_coin_ids, "fold_coin_ids")?;
            Ok(TransitionCommand::Receive {
                common,
                fold_coin_ids,
            })
        }
        other => Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("kind must be mint|send|receive; got {other:?}"),
        )),
    }
}

fn refuse_nonempty_digests(list: &[Vec<u8>], field: &str, kind: &str) -> KernelResult<()> {
    if list.is_empty() {
        return Ok(());
    }
    Err(KernelError::new(
        KernelErrorCode::MalformedRequest,
        format!("kind={kind} must not carry {field}"),
    ))
}

fn parse_subject_address(raw: &str) -> KernelResult<SubjectAddress> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "subject is required",
        ));
    }
    match Address::from_bech32m(trimmed) {
        Ok(addr) => Ok(SubjectAddress(addr.0)),
        Err(e) => Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("subject must be a Bech32m zk-address: {e}"),
        )),
    }
}

fn parse_xonly(bytes: &[u8], field: &str) -> KernelResult<XOnlyKey> {
    match <[u8; 32]>::try_from(bytes) {
        Ok(a) => Ok(XOnlyKey(a)),
        Err(_) => Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("{field} must be exactly 32 bytes; got {}", bytes.len()),
        )),
    }
}

fn parse_digest32(bytes: &[u8], field: &str) -> KernelResult<Digest32> {
    match <[u8; 32]>::try_from(bytes) {
        Ok(a) => Ok(Digest32(a)),
        Err(_) => Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("{field} must be exactly 32 bytes; got {}", bytes.len()),
        )),
    }
}

fn parse_publisher_choice(
    publisher_pubkey: &[u8],
    fee_address: &str,
) -> KernelResult<PublisherChoice> {
    if !fee_address.trim().is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            "fee_address must be absent in v1 (publisher presence matrix case (b) is deferred)",
        ));
    }
    if publisher_pubkey.is_empty() {
        return Ok(PublisherChoice::SelfPublish);
    }
    let key = parse_xonly(publisher_pubkey, "publisher_pubkey")?;
    Ok(PublisherChoice::FeeLessHandOff {
        publisher_pubkey: key,
    })
}

fn parse_digest_list(list: &[Vec<u8>], field: &str) -> KernelResult<Vec<Digest32>> {
    let mut out = Vec::with_capacity(list.len());
    for (i, item) in list.iter().enumerate() {
        out.push(parse_digest32(item, &format!("{field}[{i}]"))?);
    }
    Ok(out)
}

fn parse_output_templates(list: &[ProtoOutputTemplate]) -> KernelResult<Vec<OutputTemplate>> {
    let mut out = Vec::with_capacity(list.len());
    for (i, t) in list.iter().enumerate() {
        let recipient = parse_subject_address(&t.recipient).map_err(|e| {
            KernelError::new(
                e.code,
                format!("output_templates[{i}].recipient: {}", e.public_message),
            )
        })?;
        let asset_id = parse_digest32(&t.asset_id, &format!("output_templates[{i}].asset_id"))?;
        let amount = parse_u128_decimal(&t.amount, &format!("output_templates[{i}].amount"))?;
        out.push(OutputTemplate {
            recipient,
            asset_id,
            amount,
        });
    }
    Ok(out)
}

fn parse_issuance(i: ProtoIssuance) -> KernelResult<Issuance> {
    let name = i.name;
    let decimals = match u8::try_from(i.decimals) {
        Ok(d) => d,
        Err(_) => {
            return Err(KernelError::new(
                KernelErrorCode::MalformedRequest,
                format!("issuance.decimals must fit u8; got {}", i.decimals),
            ));
        }
    };
    let amount = parse_u128_decimal(&i.amount, "issuance.amount")?;
    match i.issuance_version {
        1 => {
            if !i.cap_total.trim().is_empty() || !i.terms_salt.is_empty() {
                return Err(KernelError::new(
                    KernelErrorCode::MalformedRequest,
                    "issuance_version=1 must not carry cap_total or terms_salt",
                ));
            }
            Ok(Issuance::V1 {
                name,
                decimals,
                amount,
            })
        }
        2 => {
            if i.cap_total.trim().is_empty() {
                return Err(KernelError::new(
                    KernelErrorCode::MalformedRequest,
                    "issuance_version=2 requires cap_total",
                ));
            }
            let cap_total = parse_u128_decimal(&i.cap_total, "issuance.cap_total")?;
            let terms_salt = parse_digest32(&i.terms_salt, "issuance.terms_salt")?;
            Ok(Issuance::V2 {
                name,
                decimals,
                amount,
                cap_total,
                terms_salt,
            })
        }
        other => Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("issuance_version must be 1 or 2; got {other}"),
        )),
    }
}

fn parse_u128_decimal(raw: &str, field: &str) -> KernelResult<u128> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("{field} is required as a decimal string"),
        ));
    }
    trimmed.parse::<u128>().map_err(|_| {
        KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("{field} must be a decimal u128 string; got {trimmed:?}"),
        )
    })
}

/// Map a domain event to `kernel.v1.JobEvent`.
pub(crate) fn job_event_to_proto(event: &JobEvent) -> KernelResult<ProtoJobEvent> {
    Ok(ProtoJobEvent {
        event: event.kind.as_v1_str().to_string(),
        job: Some(job_to_proto(&event.job)?),
    })
}

/// Map a domain job to a complete proto `Job`.
///
/// Required payload fields are decoded from the store's free JSON:
/// - `awaiting_signature` → full §7.5 surface (hex digests + `send_counter`)
/// - `completed` → §7.5 `JobResult` (mint/send digests + ids, or attest-only)
/// - terminal `error` → closed machine code via [`v1::decode_job_error`]
///
/// A half-decodable payload is `Err`, never a half-filled `Ok`.
pub(crate) fn job_to_proto(job: &Job) -> KernelResult<ProtoJob> {
    let status = job.normative_status().as_v1_str().to_string();
    let phase = if job.state.is_terminal() {
        String::new()
    } else {
        job.phase.clone()
    };
    let progress = v1_progress_fraction(job.progress);

    let (awaiting_signature, result, error) = match &job.state {
        JobState::AwaitingSignature { payload, .. } => {
            (Some(decode_awaiting_signature(payload)?), None, None)
        }
        JobState::Completed { result } => (None, Some(decode_job_result(job.kind, result)?), None),
        JobState::Failed { error } => (
            None,
            None,
            Some(proto_job_error(error.as_deref(), /*cancelled*/ false)?),
        ),
        JobState::Cancelled { error } => (
            None,
            None,
            Some(proto_job_error(error.as_deref(), /*cancelled*/ true)?),
        ),
        JobState::Accepted | JobState::Proving | JobState::Publishing => (None, None, None),
    };

    Ok(ProtoJob {
        job_id: job.id.as_uuid().to_string(),
        kind: job.kind.as_str().to_string(),
        status,
        phase,
        progress,
        awaiting_signature,
        result,
        error,
    })
}

fn v1_progress_fraction(progress: i16) -> f32 {
    // Store holds 0–100; §7.5 wire is float in [0, 1].
    (progress as f32) / 100.0
}

fn proto_job_error(raw: Option<&str>, cancelled: bool) -> KernelResult<ProtoJobError> {
    let status = if cancelled {
        crate::job_store::JobStatus::Cancelled
    } else {
        crate::job_store::JobStatus::Failed
    };
    // `decode_job_error` always returns a closed {error, message} object.
    let v = v1::decode_job_error(raw, status);
    let error = match v.get("error").and_then(|e| e.as_str()) {
        Some(code) => code.to_string(),
        None => {
            return Err(KernelError::corrupt_job_row(
                "decode_job_error returned object without error field",
            ));
        }
    };
    let message = match v.get("message").and_then(|m| m.as_str()) {
        Some(m) => m.to_string(),
        None => {
            return Err(KernelError::corrupt_job_row(
                "decode_job_error returned object without message field",
            ));
        }
    };
    Ok(ProtoJobError { error, message })
}

/// §7.5 `awaiting_signature` surface → proto (all digests required).
fn decode_awaiting_signature(payload: &JobPayload) -> KernelResult<ProtoAwaitingSignature> {
    let obj = payload.0.as_object().ok_or_else(|| {
        KernelError::corrupt_job_row("awaiting_signature payload is not a JSON object")
    })?;
    Ok(ProtoAwaitingSignature {
        new_account_state_hash: require_hex_bytes(obj, "new_account_state_hash", 32)?,
        output_coins_root: require_hex_bytes(obj, "output_coins_root", 32)?,
        input_nullifiers_root: require_hex_bytes(obj, "input_nullifiers_root", 32)?,
        coin_history_root: require_hex_bytes(obj, "coin_history_root", 32)?,
        nav_commitment: require_hex_bytes(obj, "nav_commitment", 32)?,
        npk_commit: require_hex_bytes(obj, "npk_commit", 32)?,
        proof_data_hash: require_hex_bytes(obj, "proof_data_hash", 32)?,
        txn_pubkey: require_hex_bytes(obj, "txn_pubkey", 32)?,
        send_counter: require_u64(obj, "send_counter")?,
    })
}

/// §7.5 completed `result` → proto.
///
/// - `attest_balance`: only `attestation` is required; digest fields empty.
/// - mint / send: the three digests + `output_coin_ids` are required;
///   `publisher_pubkey` may be empty (self-publish); `attestation` empty.
fn decode_job_result(kind: JobKind, payload: &JobPayload) -> KernelResult<ProtoJobResult> {
    let obj = payload
        .0
        .as_object()
        .ok_or_else(|| KernelError::corrupt_job_row("completed result is not a JSON object"))?;

    match kind {
        JobKind::AttestBalance => {
            let attestation = require_hex_bytes_unbounded(obj, "attestation")?;
            Ok(ProtoJobResult {
                new_account_state_hash: Vec::new(),
                output_coins_root: Vec::new(),
                input_nullifiers_root: Vec::new(),
                output_coin_ids: Vec::new(),
                publisher_pubkey: Vec::new(),
                attestation,
            })
        }
        // Receive is a state-advancing transition; completed result digests
        // share the mint/send shape (§7.5 `JobResult`). SubmitTransition
        // currently refuses receive at admission, but projection must stay
        // exhaustive for store-kind round-trips.
        JobKind::Mint | JobKind::Send | JobKind::Receive => {
            let output_coin_ids = require_hex_bytes_array(obj, "output_coin_ids", 32)?;
            let publisher_pubkey = optional_hex_bytes(obj, "publisher_pubkey", 32)?;
            Ok(ProtoJobResult {
                new_account_state_hash: require_hex_bytes(obj, "new_account_state_hash", 32)?,
                output_coins_root: require_hex_bytes(obj, "output_coins_root", 32)?,
                input_nullifiers_root: require_hex_bytes(obj, "input_nullifiers_root", 32)?,
                output_coin_ids,
                publisher_pubkey,
                attestation: Vec::new(),
            })
        }
    }
}

fn require_hex_bytes(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    expected_len: usize,
) -> KernelResult<Vec<u8>> {
    let raw = match obj.get(key).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return Err(KernelError::corrupt_job_row(format!(
                "job payload missing required hex field `{key}`"
            )));
        }
    };
    decode_hex_exact(raw, key, expected_len)
}

/// Hex field present and non-empty, length not fixed (attestation blob).
fn require_hex_bytes_unbounded(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
) -> KernelResult<Vec<u8>> {
    let raw = match obj.get(key).and_then(|v| v.as_str()) {
        Some(s) => s,
        None => {
            return Err(KernelError::corrupt_job_row(format!(
                "job payload missing required hex field `{key}`"
            )));
        }
    };
    if raw.is_empty() {
        return Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` is empty hex"
        )));
    }
    if raw.bytes().any(|b| !b.is_ascii_hexdigit()) {
        return Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` is not hex"
        )));
    }
    hex::decode(raw).map_err(|e| {
        KernelError::corrupt_job_row(format!("job payload field `{key}` hex decode failed: {e}"))
    })
}

/// Optional fixed-width hex: absent → empty bytes (self-publish statement).
/// Present but malformed → error (never silently drop).
fn optional_hex_bytes(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    expected_len: usize,
) -> KernelResult<Vec<u8>> {
    match obj.get(key) {
        None => Ok(Vec::new()),
        Some(serde_json::Value::Null) => Ok(Vec::new()),
        Some(v) => {
            let raw = match v.as_str() {
                Some(s) => s,
                None => {
                    return Err(KernelError::corrupt_job_row(format!(
                        "job payload field `{key}` is not a string"
                    )));
                }
            };
            if raw.is_empty() {
                return Ok(Vec::new());
            }
            decode_hex_exact(raw, key, expected_len)
        }
    }
}

fn require_hex_bytes_array(
    obj: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    expected_len: usize,
) -> KernelResult<Vec<Vec<u8>>> {
    let arr = match obj.get(key).and_then(|v| v.as_array()) {
        Some(a) => a,
        None => {
            return Err(KernelError::corrupt_job_row(format!(
                "job payload missing required array field `{key}`"
            )));
        }
    };
    let mut out = Vec::with_capacity(arr.len());
    for (i, item) in arr.iter().enumerate() {
        let raw = match item.as_str() {
            Some(s) => s,
            None => {
                return Err(KernelError::corrupt_job_row(format!(
                    "job payload `{key}[{i}]` is not a hex string"
                )));
            }
        };
        out.push(decode_hex_exact(raw, &format!("{key}[{i}]"), expected_len)?);
    }
    Ok(out)
}

fn require_u64(obj: &serde_json::Map<String, serde_json::Value>, key: &str) -> KernelResult<u64> {
    match obj.get(key) {
        Some(serde_json::Value::Number(n)) => n.as_u64().ok_or_else(|| {
            KernelError::corrupt_job_row(format!(
                "job payload field `{key}` is not a non-negative integer"
            ))
        }),
        Some(_) => Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` is not a number"
        ))),
        None => Err(KernelError::corrupt_job_row(format!(
            "job payload missing required field `{key}`"
        ))),
    }
}

fn decode_hex_exact(raw: &str, key: &str, expected_len: usize) -> KernelResult<Vec<u8>> {
    if raw.len() != expected_len * 2 {
        return Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` must be {} hex chars ({} bytes); got len {}",
            expected_len * 2,
            expected_len,
            raw.len()
        )));
    }
    if raw
        .bytes()
        .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b) && !(b'A'..=b'F').contains(&b))
    {
        return Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` is not hex"
        )));
    }
    let bytes = hex::decode(raw).map_err(|e| {
        KernelError::corrupt_job_row(format!("job payload field `{key}` hex decode failed: {e}"))
    })?;
    if bytes.len() != expected_len {
        return Err(KernelError::corrupt_job_row(format!(
            "job payload field `{key}` decoded to {} bytes, expected {expected_len}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

/// Parse proto `PublishRequest` into a fee-less domain [`PublishCommand`].
///
/// Any non-empty fee field → `malformed_request` (v1 fail-closed). Wrong
/// widths for the four nullifier points/scalars or missing `block_anchor`
/// → `malformed_request`.
pub(crate) fn parse_publish_request(req: ProtoPublishRequest) -> KernelResult<PublishCommand> {
    refuse_v1_fee_fields(&req.fee_blob_id, &req.fee_epk, &req.fee_blob_locators)?;
    let public_key = parse_xonly(&req.public_key, "public_key")?;
    let r = parse_xonly(&req.r, "r")?;
    let s = parse_digest32(&req.s, "s")?;
    let r_prime = parse_xonly(&req.r_prime, "r_prime")?;
    let anchor = match req.block_anchor {
        Some(a) => a,
        None => {
            return Err(KernelError::new(
                KernelErrorCode::MalformedRequest,
                "block_anchor is required",
            ));
        }
    };
    let block_hash = parse_digest32(&anchor.block_hash, "block_anchor.block_hash")?;
    Ok(PublishCommand {
        public_key,
        r,
        s,
        r_prime,
        block_anchor: PublishBlockAnchor {
            block_hash,
            height: anchor.height,
        },
    })
}

/// Project a domain [`PublishOutcome`] onto proto `PublishResult`.
///
/// Presence invariants: `reason` set iff rejected; `batch_eta` set iff accepted.
pub(crate) fn publish_outcome_to_proto(outcome: PublishOutcome) -> ProtoPublishResult {
    match outcome {
        PublishOutcome::Accepted { batch_eta } => ProtoPublishResult {
            accepted: true,
            reason: None,
            batch_eta: Some(batch_eta),
        },
        PublishOutcome::Rejected { reason } => ProtoPublishResult {
            accepted: false,
            reason: Some(reason.as_str().to_string()),
            batch_eta: None,
        },
    }
}

/// Parse proto `EntrustRequest` (raw bundle bytes; length checked in domain).
pub(crate) fn parse_entrust_request(req: ProtoEntrustRequest) -> KernelResult<EntrustCommand> {
    let subject = parse_subject_address(&req.subject)?;
    let nonce = parse_exact_32(&req.nonce, "nonce")?;
    let chan_bind = ChanBind(parse_exact_32(&req.chan_bind, "chan_bind")?);
    Ok(EntrustCommand {
        subject,
        nonce,
        chan_bind,
        bundle_bytes: req.bundle,
    })
}

pub(crate) fn entrust_result_to_proto(
    result: crate::kernel::bootstrap::EntrustResult,
) -> ProtoEntrustResult {
    ProtoEntrustResult {
        accepted: result.accepted,
    }
}

/// Parse proto `RevokeRequest`.
pub(crate) fn parse_revoke_request(req: ProtoRevokeRequest) -> KernelResult<RevokeCommand> {
    let subject = parse_subject_address(&req.subject)?;
    let nonce = parse_exact_32(&req.nonce, "nonce")?;
    let chan_bind = ChanBind(parse_exact_32(&req.chan_bind, "chan_bind")?);
    Ok(RevokeCommand {
        subject,
        nonce,
        chan_bind,
    })
}

pub(crate) fn revoke_result_to_proto(
    result: crate::kernel::bootstrap::RevokeResult,
) -> ProtoRevokeResult {
    ProtoRevokeResult {
        revoked: result.revoked,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::types::{JobEventKind, JobKind, JobPayload, NormativeJobStatus};
    use uuid::Uuid;

    fn hex32(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    fn sample_awaiting_payload() -> JobPayload {
        JobPayload(serde_json::json!({
            "new_account_state_hash": hex32(0x11),
            "output_coins_root": hex32(0x22),
            "input_nullifiers_root": hex32(0x33),
            "coin_history_root": hex32(0x44),
            "nav_commitment": hex32(0x55),
            "npk_commit": hex32(0x66),
            "proof_data_hash": hex32(0x77),
            "txn_pubkey": hex32(0x88),
            "send_counter": 3u64,
        }))
    }

    fn sample_completed_payload() -> JobPayload {
        JobPayload(serde_json::json!({
            "new_account_state_hash": hex32(0xa1),
            "output_coins_root": hex32(0xa2),
            "input_nullifiers_root": hex32(0xa3),
            "output_coin_ids": [hex32(0xb1)],
        }))
    }

    fn sample_completed() -> Job {
        Job {
            id: JobId(Uuid::from_u128(1)),
            kind: JobKind::Mint,
            phase: "completed".to_string(),
            progress: 100,
            state: JobState::Completed {
                result: sample_completed_payload(),
            },
        }
    }

    #[test]
    fn complete_event_maps_event_name_status_and_result() {
        let job = sample_completed();
        let ev = JobEvent {
            kind: JobEventKind::Complete,
            job,
        };
        let proto = job_event_to_proto(&ev).expect("complete is well-formed");
        assert_eq!(proto.event, "complete");
        let j = proto.job.expect("job");
        assert_eq!(j.status, "completed");
        assert_eq!(j.kind, "mint");
        assert!(j.phase.is_empty(), "terminal phase absent");
        assert!((j.progress - 1.0).abs() < f32::EPSILON);
        assert!(j.error.is_none());
        let result = j.result.expect("result required on completed");
        assert_eq!(result.new_account_state_hash, vec![0xa1; 32]);
        assert_eq!(result.output_coin_ids.len(), 1);
        assert_eq!(result.output_coin_ids[0], vec![0xb1; 32]);
        assert!(result.publisher_pubkey.is_empty());
        assert!(result.attestation.is_empty());
    }

    #[test]
    fn failed_event_carries_job_error() {
        let job = Job {
            id: JobId(Uuid::from_u128(2)),
            kind: JobKind::Send,
            phase: "failed".to_string(),
            progress: 40,
            state: JobState::Failed {
                error: Some(v1::encode_job_error("proving_failed", "witness")),
            },
        };
        let ev = JobEvent {
            kind: JobEventKind::Error,
            job,
        };
        let proto = job_event_to_proto(&ev).expect("failed");
        assert_eq!(proto.event, "error");
        let err = proto.job.unwrap().error.unwrap();
        assert_eq!(err.error, "proving_failed");
        assert_eq!(err.message, "witness");
    }

    #[test]
    fn phase_event_uses_accepted_alias() {
        let job = Job {
            id: JobId(Uuid::from_u128(3)),
            kind: JobKind::Mint,
            phase: "queued".to_string(),
            progress: 0,
            state: JobState::Accepted,
        };
        assert_eq!(job.normative_status(), NormativeJobStatus::Accepted);
        let proto = job_to_proto(&job).expect("accepted");
        assert_eq!(proto.status, "accepted");
        assert_eq!(proto.phase, "queued");
        assert!(proto.result.is_none());
        assert!(proto.awaiting_signature.is_none());
        assert!(proto.error.is_none());
    }

    #[test]
    fn awaiting_signature_decodes_full_surface() {
        let job = Job {
            id: JobId(Uuid::from_u128(4)),
            kind: JobKind::Send,
            phase: "awaiting_signature".to_string(),
            progress: 50,
            state: JobState::AwaitingSignature {
                payload: sample_awaiting_payload(),
                proof_id: Some(9),
            },
        };
        let proto = job_to_proto(&job).expect("awaiting");
        assert_eq!(proto.status, "awaiting_signature");
        let ash = proto.awaiting_signature.expect("payload");
        assert_eq!(ash.new_account_state_hash, vec![0x11; 32]);
        assert_eq!(ash.send_counter, 3);
        assert!(proto.result.is_none());
    }

    #[test]
    fn legacy_ash_ocr_awaiting_signature_is_internal_error() {
        // Legacy surface is not a complete §7.8 AwaitingSignature — refuse.
        let job = Job {
            id: JobId(Uuid::from_u128(5)),
            kind: JobKind::Send,
            phase: "awaiting_signature".to_string(),
            progress: 50,
            state: JobState::AwaitingSignature {
                payload: JobPayload(serde_json::json!({
                    "account_state_hash": hex32(0xaa),
                    "output_coins_root": hex32(0xbb),
                })),
                proof_id: Some(1),
            },
        };
        let err = job_to_proto(&job).expect_err("legacy ash‖ocr is incomplete");
        assert_eq!(err.code, KernelErrorCode::InternalError);
    }

    #[test]
    fn completed_without_digests_is_internal_error() {
        // Full mint/send completed surface except one required digest — so the
        // error detail names that field specifically, not whichever happens to
        // be validated first among several absences.
        let job = Job {
            id: JobId(Uuid::from_u128(6)),
            kind: JobKind::Mint,
            phase: "completed".to_string(),
            progress: 100,
            state: JobState::Completed {
                result: JobPayload(serde_json::json!({
                    "output_coins_root": hex32(0xa2),
                    "input_nullifiers_root": hex32(0xa3),
                    "output_coin_ids": [hex32(0xb1)],
                    // deliberately omit `new_account_state_hash`
                })),
            },
        };
        let err = job_to_proto(&job).expect_err("half result");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        let detail = &err.internal_context.expect("ctx").detail;
        assert!(detail.contains("new_account_state_hash"), "detail={detail}");
    }

    #[test]
    fn attest_completed_requires_only_attestation() {
        let job = Job {
            id: JobId(Uuid::from_u128(7)),
            kind: JobKind::AttestBalance,
            phase: "completed".to_string(),
            progress: 100,
            state: JobState::Completed {
                result: JobPayload(serde_json::json!({
                    "attestation": hex::encode([0xCDu8; 16]),
                })),
            },
        };
        let proto = job_to_proto(&job).expect("attest");
        let result = proto.result.expect("result");
        assert_eq!(result.attestation, vec![0xCD; 16]);
        assert!(result.new_account_state_hash.is_empty());
        assert!(result.output_coin_ids.is_empty());
    }

    #[test]
    fn parse_sign_request_accepts_exact_64_and_32() {
        let id = Uuid::from_u128(0x91);
        let req = ProtoSignRequest {
            job_id: id.to_string(),
            signature: vec![0xABu8; 64],
            s2c_nonce: vec![0xCDu8; 32],
        };
        let st = parse_sign_request(req).expect("widths ok");
        assert_eq!(st.id.as_uuid(), id);
        assert_eq!(st.submission.signature, [0xABu8; 64]);
        assert_eq!(st.submission.s2c_nonce, [0xCDu8; 32]);
    }

    #[test]
    fn parse_sign_request_rejects_wrong_signature_width() {
        let req = ProtoSignRequest {
            job_id: Uuid::from_u128(1).to_string(),
            signature: vec![0u8; 32], // 32 ≠ 64
            s2c_nonce: vec![0u8; 32],
        };
        let err = parse_sign_request(req).expect_err("32-byte sig");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("64"),
            "must name required width: {}",
            err.public_message
        );
    }

    #[test]
    fn parse_sign_request_rejects_wrong_s2c_nonce_width() {
        let req = ProtoSignRequest {
            job_id: Uuid::from_u128(1).to_string(),
            signature: vec![0u8; 64],
            s2c_nonce: vec![0u8; 16], // 16 ≠ 32
        };
        let err = parse_sign_request(req).expect_err("16-byte nonce");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("32"),
            "must name required width: {}",
            err.public_message
        );
    }

    #[test]
    fn parse_sign_request_rejects_empty_job_id() {
        let req = ProtoSignRequest {
            job_id: "  ".to_string(),
            signature: vec![0u8; 64],
            s2c_nonce: vec![0u8; 32],
        };
        let err = parse_sign_request(req).expect_err("blank id");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
    }
}
