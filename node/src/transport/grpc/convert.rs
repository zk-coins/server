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
    ChanBind, DeliveryCredential, Digest32, Issuance, JobKind, JobPayload, OutputTemplate,
    PublisherChoice, SubjectAddress, TransitionCommon, XOnlyKey,
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
    CoinProofRequest as ProtoCoinProofRequest, DeliveryCredential as ProtoDeliveryCredential,
    EntrustRequest as ProtoEntrustRequest, EntrustResult as ProtoEntrustResult,
    GetTokenProvenanceRequest as ProtoGetTokenProvenanceRequest,
    GrantRequest as ProtoGrantRequest, Info as ProtoInfo, Invoice as ProtoInvoice,
    Issuance as ProtoIssuance, Job as ProtoJob, JobError as ProtoJobError,
    JobEvent as ProtoJobEvent, JobResult as ProtoJobResult, Kind0Event as ProtoKind0Event,
    ListInscriptionsRequest as ProtoListInscriptionsRequest, NullifierPath as ProtoNullifierPath,
    NullifierPathRequest as ProtoNullifierPathRequest, OutputTemplate as ProtoOutputTemplate,
    PublishRequest as ProtoPublishRequest, PublishResult as ProtoPublishResult,
    PullRequest as ProtoPullRequest, PullResult as ProtoPullResult, Receipt as ProtoReceipt,
    RecordBlob as ProtoRecordBlob, RecordRef as ProtoRecordRef,
    RecordRequest as ProtoRecordRequest, RevokeRequest as ProtoRevokeRequest,
    RevokeResult as ProtoRevokeResult, Scope as ProtoScope, SignRequest as ProtoSignRequest,
    TokenProvenance as ProtoTokenProvenance, TransitionRequest as ProtoTransitionRequest,
};
use shared::spec_v1::bundle::IssuanceTerms;
use shared::spec_v1::Address;

/// Parse proto `GetTokenProvenanceRequest` (`asset_id` width = 32).
pub(crate) fn parse_get_token_provenance_request(
    req: ProtoGetTokenProvenanceRequest,
) -> KernelResult<Digest32> {
    parse_digest32(&req.asset_id, "asset_id")
}

/// Strictly project retained `IssuanceTerms` onto the versioned §7.8 message.
pub(crate) fn token_provenance_to_proto(
    terms: &IssuanceTerms,
) -> KernelResult<ProtoTokenProvenance> {
    let (cap_total, terms_salt) = match terms.issuance_version {
        1 => {
            if terms.cap_total.is_some() || terms.terms_salt.is_some() {
                return Err(KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Corrupt token provenance",
                    "issuance_version=1 carries v2 fields",
                ));
            }
            (String::new(), Vec::new())
        }
        2 => {
            let cap = terms.cap_total.ok_or_else(|| {
                KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Corrupt token provenance",
                    "issuance_version=2 is missing cap_total",
                )
            })?;
            let salt = terms.terms_salt.ok_or_else(|| {
                KernelError::with_internal(
                    KernelErrorCode::InternalError,
                    "Corrupt token provenance",
                    "issuance_version=2 is missing terms_salt",
                )
            })?;
            (cap.to_string(), salt.to_vec())
        }
        other => {
            return Err(KernelError::with_internal(
                KernelErrorCode::InternalError,
                "Corrupt token provenance",
                format!("unsupported issuance_version {other}"),
            ));
        }
    };
    Ok(ProtoTokenProvenance {
        issuance_version: u32::from(terms.issuance_version),
        creator_pubkey: terms.creator_pubkey.to_vec(),
        name: terms.name.clone(),
        decimals: u32::from(terms.decimals),
        cap_total,
        terms_salt,
    })
}

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
            refuse_nonempty_bytes(&req.genesis_pubkey, "genesis_pubkey", "mint")?;
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
            refuse_nonempty_bytes(&req.genesis_pubkey, "genesis_pubkey", "send")?;
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
            let genesis_pubkey = if req.genesis_pubkey.is_empty() {
                None
            } else {
                Some(parse_xonly(&req.genesis_pubkey, "genesis_pubkey")?)
            };
            Ok(TransitionCommand::Receive {
                common,
                fold_coin_ids,
                genesis_pubkey,
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

fn refuse_nonempty_bytes(bytes: &[u8], field: &str, kind: &str) -> KernelResult<()> {
    if bytes.is_empty() {
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
        // Proto3 sub-message: absence is `None`; a present empty oneof body
        // is malformed (same present-but-empty discipline as publisher_pubkey
        // width — never silently treat an empty credential as "absent").
        let delivery = match t.delivery.as_ref() {
            None => None,
            Some(cred) => Some(parse_delivery_credential(cred, i)?),
        };
        out.push(OutputTemplate {
            recipient,
            asset_id,
            amount,
            delivery,
        });
    }
    Ok(out)
}

/// Parse the closed §7.5 `DeliveryCredential` oneof.
///
/// Exactly one arm must be set. A present message with neither arm set is
/// `malformed_request` — not "absent delivery".
fn parse_delivery_credential(
    cred: &ProtoDeliveryCredential,
    output_index: usize,
) -> KernelResult<DeliveryCredential> {
    let prefix = format!("output_templates[{output_index}].delivery");
    match cred.body.as_ref() {
        None => Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("{prefix}: DeliveryCredential oneof body is required (invoice|profile_event)"),
        )),
        Some(kernel_proto::delivery_credential::Body::Invoice(inv)) => Ok(
            DeliveryCredential::Invoice(parse_wire_invoice(inv, &prefix)?),
        ),
        Some(kernel_proto::delivery_credential::Body::ProfileEvent(ev)) => Ok(
            DeliveryCredential::Profile(parse_wire_kind0_event(ev, &prefix)?),
        ),
    }
}

fn parse_wire_invoice(inv: &ProtoInvoice, prefix: &str) -> KernelResult<crate::v1::PaymentInvoice> {
    let amount = parse_u128_decimal(&inv.amount, &format!("{prefix}.invoice.amount"))?;
    let recipient = parse_subject_address(&inv.recipient).map_err(|e| {
        KernelError::new(
            e.code,
            format!("{prefix}.invoice.recipient: {}", e.public_message),
        )
    })?;
    let asset_id = parse_digest32(&inv.asset_id, &format!("{prefix}.invoice.asset_id"))?;
    let pk0 = parse_exact_32(&inv.pk0, &format!("{prefix}.invoice.pk0"))?;
    let nk_commit = parse_exact_32(&inv.nk_commit, &format!("{prefix}.invoice.nk_commit"))?;
    let ivpk = parse_exact_32(&inv.ivpk, &format!("{prefix}.invoice.ivpk"))?;
    let op_pubkey = parse_exact_32(&inv.op_pubkey, &format!("{prefix}.invoice.op_pubkey"))?;
    let addr_sig = parse_exact_64(&inv.addr_sig, &format!("{prefix}.invoice.addr_sig"))?;
    let sig = parse_exact_64(&inv.sig, &format!("{prefix}.invoice.sig"))?;
    // Empty string is the wire encoding of "memo absent" (§7.8 Invoice.memo).
    let memo = {
        let t = inv.memo.trim();
        if t.is_empty() {
            None
        } else {
            Some(t.to_string())
        }
    };
    if inv.relays.is_empty() {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("{prefix}.invoice.relays must contain at least one relay URL"),
        ));
    }
    Ok(crate::v1::PaymentInvoice {
        amount,
        recipient: recipient.0,
        asset_id: asset_id.0,
        memo,
        pk0,
        nk_commit,
        ivpk,
        op_pubkey,
        relays: inv.relays.clone(),
        addr_sig,
        sig,
    })
}

fn parse_wire_kind0_event(
    ev: &ProtoKind0Event,
    prefix: &str,
) -> KernelResult<crate::v1::nostr::event::Event> {
    use crate::v1::nostr::event::{Event, EventParts};

    let id = parse_exact_32(&ev.id, &format!("{prefix}.profile_event.id"))?;
    let pubkey = parse_exact_32(&ev.pubkey, &format!("{prefix}.profile_event.pubkey"))?;
    let sig = parse_exact_64(&ev.sig, &format!("{prefix}.profile_event.sig"))?;
    if ev.kind != 0 {
        return Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!(
                "{prefix}.profile_event.kind must be 0 (kind-0 metadata); got {}",
                ev.kind
            ),
        ));
    }
    let tags: Vec<Vec<String>> = if ev.tags_json.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(ev.tags_json.trim()).map_err(|_| {
            KernelError::new(
                KernelErrorCode::MalformedRequest,
                format!("{prefix}.profile_event.tags_json must be a JSON array of tag arrays"),
            )
        })?
    };
    // verify_parts recomputes id and checks BIP-340 — claimed id/sig are never trusted raw.
    Event::verify_parts(EventParts {
        id,
        pubkey,
        created_at: ev.created_at,
        kind: ev.kind,
        tags,
        content: ev.content.clone(),
        sig,
    })
    .map_err(|e| {
        // Named failure class only — never quote event content / signatures.
        KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("{prefix}.profile_event: kind-0 event failed NIP-01 verification ({e})"),
        )
    })
}

fn parse_exact_64(bytes: &[u8], field: &str) -> KernelResult<[u8; 64]> {
    match <[u8; 64]>::try_from(bytes) {
        Ok(a) => Ok(a),
        Err(_) => Err(KernelError::new(
            KernelErrorCode::MalformedRequest,
            format!("{field} must be exactly 64 bytes; got {}", bytes.len()),
        )),
    }
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
    let creator_pubkey = parse_xonly(&i.creator_pubkey, "issuance.creator_pubkey")?;
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
                creator_pubkey,
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
                creator_pubkey,
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

#[cfg_attr(coverage_nightly, coverage(off))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::kernel::access::{ReceiptState, RecordType, SessionToken, TransitionKind};
    use crate::kernel::bootstrap::{EntrustResult, RevokeResult};
    use crate::kernel::chain::{
        KernelNetwork, KernelPart, ListedNullifier, NullifierMemberState, Readiness,
        ReadyReason, RevealConfirmationState,
    };
    use crate::kernel::publish::PublishRejectReason;
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

    // ---- TransitionRequest presence matrix (receive, §7.5) ----

    fn receive_subject_bech32() -> String {
        shared::spec_v1::Address([0xA1u8; 32]).to_bech32m()
    }

    fn wrong_width_subject_bech32() -> String {
        let hrp = bitcoin::bech32::Hrp::parse("zk").expect("zk HRP");
        bitcoin::bech32::encode::<bitcoin::bech32::Bech32m>(hrp, &[0xA1; 31])
            .expect("31-byte Bech32m payload")
    }

    fn base_receive_request() -> ProtoTransitionRequest {
        ProtoTransitionRequest {
            kind: "receive".into(),
            subject: receive_subject_bech32(),
            next_pubkey: vec![0xB2u8; 32],
            npk_rand: vec![0xC3u8; 32],
            input_coins: vec![],
            output_templates: vec![],
            publisher_pubkey: vec![],
            fee_address: String::new(),
            fold_coin_ids: vec![vec![0x22u8; 32]],
            issuance: None,
            idempotency_key: "k-rx".into(),
            genesis_pubkey: vec![],
        }
    }

    fn all_assets_scope() -> ProtoScope {
        ProtoScope {
            asset_ids: vec![],
            all_assets: true,
            not_before: 7,
            not_after: 99,
        }
    }

    fn base_attest_request() -> ProtoAttestRequest {
        ProtoAttestRequest {
            subject: receive_subject_bech32(),
            asset_id: vec![0x11; 32],
            nav_ceiling: vec![],
            size_ceiling: 0,
            nonce: vec![0x22; 32],
            chan_bind: vec![0x33; 32],
        }
    }

    fn base_grant_request() -> ProtoGrantRequest {
        ProtoGrantRequest {
            subject: receive_subject_bech32(),
            grantee_pk: vec![0x21; 32],
            scope: Some(all_assets_scope()),
            expiry: 123,
            nonce: vec![0x22; 32],
            chan_bind: vec![0x23; 32],
        }
    }

    fn base_pull_request() -> ProtoPullRequest {
        ProtoPullRequest {
            nonce: vec![0x31; 32],
            subject: receive_subject_bech32(),
            resolved_scope: Some(all_assets_scope()),
            chan_bind: vec![0x32; 32],
        }
    }

    fn base_issuance(version: u32) -> ProtoIssuance {
        ProtoIssuance {
            name: "asset".into(),
            decimals: 8,
            issuance_version: version,
            amount: "42".into(),
            cap_total: if version == 2 {
                "1000".into()
            } else {
                String::new()
            },
            terms_salt: if version == 2 {
                vec![0x41; 32]
            } else {
                vec![]
            },
            creator_pubkey: vec![0x42; 32],
        }
    }

    fn base_output_template() -> ProtoOutputTemplate {
        ProtoOutputTemplate {
            recipient: receive_subject_bech32(),
            asset_id: vec![0x51; 32],
            amount: "17".into(),
            delivery: None,
        }
    }

    fn base_mint_request() -> ProtoTransitionRequest {
        ProtoTransitionRequest {
            kind: "mint".into(),
            subject: receive_subject_bech32(),
            next_pubkey: vec![0x52; 32],
            npk_rand: vec![0x53; 32],
            input_coins: vec![],
            output_templates: vec![base_output_template()],
            publisher_pubkey: vec![],
            fee_address: String::new(),
            fold_coin_ids: vec![],
            issuance: Some(base_issuance(1)),
            idempotency_key: "k-mint".into(),
            genesis_pubkey: vec![],
        }
    }

    fn base_send_request() -> ProtoTransitionRequest {
        ProtoTransitionRequest {
            kind: "send".into(),
            subject: receive_subject_bech32(),
            next_pubkey: vec![0x61; 32],
            npk_rand: vec![0x62; 32],
            input_coins: vec![vec![0x63; 32]],
            output_templates: vec![base_output_template()],
            publisher_pubkey: vec![0x64; 32],
            fee_address: String::new(),
            fold_coin_ids: vec![],
            issuance: None,
            idempotency_key: "k-send".into(),
            genesis_pubkey: vec![],
        }
    }

    fn base_invoice() -> ProtoInvoice {
        ProtoInvoice {
            amount: "17".into(),
            recipient: receive_subject_bech32(),
            asset_id: vec![0x51; 32],
            memo: String::new(),
            pk0: vec![0x71; 32],
            nk_commit: vec![0x72; 32],
            ivpk: vec![0x73; 32],
            op_pubkey: vec![0x74; 32],
            relays: vec!["wss://relay.example".into()],
            addr_sig: vec![0x75; 64],
            sig: vec![0x76; 64],
        }
    }

    fn signed_kind0_proto(tags_json_empty: bool) -> ProtoKind0Event {
        let tags = if tags_json_empty {
            vec![]
        } else {
            vec![vec!["p".to_string(), hex32(0x81)]]
        };
        let event = crate::v1::nostr::event::Event::sign(
            &[0x01; 32],
            1_700_000_000,
            0,
            tags.clone(),
            "{\"name\":\"alice\"}".to_string(),
        )
        .expect("deterministic kind-0 signing key");
        ProtoKind0Event {
            id: event.id.to_vec(),
            pubkey: event.pubkey.to_vec(),
            created_at: event.created_at,
            kind: event.kind,
            tags_json: if tags_json_empty {
                String::new()
            } else {
                serde_json::to_string(&tags).expect("serialize tags")
            },
            content: event.content,
            sig: event.sig.to_vec(),
        }
    }

    fn base_publish_request() -> ProtoPublishRequest {
        ProtoPublishRequest {
            public_key: vec![0x91; 32],
            r: vec![0x92; 32],
            s: vec![0x93; 32],
            r_prime: vec![0x94; 32],
            fee_blob_id: vec![],
            block_anchor: Some(kernel_proto::BlockAnchor {
                block_hash: vec![0x95; 32],
                height: 321,
            }),
            fee_epk: vec![],
            fee_blob_locators: vec![],
        }
    }

    fn bootstrap_manifest() -> DomainBootstrapManifest {
        DomainBootstrapManifest {
            network: KernelNetwork::Regtest,
            protocol_version: "v1".into(),
            seed_relays: vec!["wss://seed.example".into()],
            blob_stores: vec!["https://blob.example".into()],
            operator_ids: vec![XOnlyKey([0xA2; 32])],
            issued_at: 10,
            expires_at: 20,
            manifest_sig: [0xA3; 64],
        }
    }

    fn kernel_info(readiness: Readiness) -> KernelInfo {
        KernelInfo {
            network: KernelNetwork::Regtest,
            protocol_version: "v1",
            circuit_digest_c: Digest32([0xA4; 32]),
            circuit_digest_c_balance: Digest32([0xA5; 32]),
            relay_url: "wss://relay.example".into(),
            blossom_url: "https://blob.example".into(),
            finality_confirmations: 6,
            max_tx_inputs: 4,
            max_tx_outputs: 8,
            max_rx_coins: 16,
            max_account_assets: 32,
            readiness,
            bitcoin_tip_height: 1234,
            accumulator_root: Digest32([0xA6; 32]),
            scanner_lag: 2,
            max_blob_bytes: 1_000_000,
            activation_height: 100,
            bootstrap: bootstrap_manifest(),
            kernel_parts: vec![KernelPart::Scanner, KernelPart::Prover],
            bootstrap_pubkey: XOnlyKey([0xA7; 32]),
        }
    }

    #[test]
    fn parse_receive_valid_maps_to_command() {
        let cmd = parse_transition_request(base_receive_request()).expect("valid receive");
        match cmd {
            TransitionCommand::Receive { fold_coin_ids, .. } => {
                assert_eq!(fold_coin_ids.len(), 1);
                assert_eq!(fold_coin_ids[0].0, [0x22u8; 32]);
            }
            other => panic!("expected Receive, got {other:?}"),
        }
    }

    #[test]
    fn parse_receive_with_genesis_pubkey_maps_to_some() {
        let mut req = base_receive_request();
        req.genesis_pubkey = vec![0xD0u8; 32];
        let cmd = parse_transition_request(req).expect("valid receive with genesis_pubkey");
        match cmd {
            TransitionCommand::Receive {
                genesis_pubkey: Some(k),
                ..
            } => {
                assert_eq!(k.0, [0xD0u8; 32]);
            }
            other => panic!("expected Receive with Some(genesis_pubkey), got {other:?}"),
        }
    }

    #[test]
    fn parse_receive_without_genesis_pubkey_maps_to_none() {
        let cmd = parse_transition_request(base_receive_request()).expect("valid receive");
        match cmd {
            TransitionCommand::Receive {
                genesis_pubkey: None,
                ..
            } => {}
            other => panic!("expected Receive with genesis_pubkey: None, got {other:?}"),
        }
    }

    /// Empty `fold_coin_ids` is a shape error at admit time
    /// (`malformed_request`); parse still yields a Receive command with
    /// an empty list so [`validate_transition_command`] is the single
    /// source of the §7.5 empty-list rule.
    #[test]
    fn parse_receive_empty_fold_is_malformed_at_validate() {
        let mut req = base_receive_request();
        req.fold_coin_ids.clear();
        let cmd = parse_transition_request(req).expect("parse allows empty list through");
        let err = crate::kernel::jobs::submit::validate_transition_command(&cmd)
            .expect_err("empty fold_coin_ids is malformed");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("fold_coin_ids"),
            "must name the missing field: {}",
            err.public_message
        );
    }

    #[test]
    fn parse_receive_with_input_coins_is_malformed() {
        let mut req = base_receive_request();
        req.input_coins = vec![vec![0x11u8; 32]];
        let err = parse_transition_request(req).expect_err("input_coins forbidden on receive");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("input_coins"),
            "must name the forbidden field: {}",
            err.public_message
        );
    }

    #[test]
    fn parse_receive_with_output_templates_is_malformed() {
        let mut req = base_receive_request();
        req.output_templates = vec![ProtoOutputTemplate {
            recipient: receive_subject_bech32(),
            asset_id: vec![0xE5u8; 32],
            amount: "1".into(),
            delivery: None,
        }];
        let err = parse_transition_request(req).expect_err("output_templates forbidden on receive");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("output_templates"),
            "must name the forbidden field: {}",
            err.public_message
        );
    }

    #[test]
    fn present_delivery_with_empty_oneof_is_malformed_not_absent() {
        // Present-but-empty discipline: a DeliveryCredential message with
        // neither arm set is not "delivery absent" — it is malformed.
        let mut t = ProtoOutputTemplate {
            recipient: receive_subject_bech32(),
            asset_id: vec![0xE5u8; 32],
            amount: "1".into(),
            delivery: Some(kernel_proto::DeliveryCredential { body: None }),
        };
        let err = parse_output_templates(std::slice::from_ref(&t)).expect_err("empty oneof");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(
            err.public_message.contains("oneof") || err.public_message.contains("body"),
            "{}",
            err.public_message
        );
        // Absent delivery remains Ok at parse (presence rule is admit-time).
        t.delivery = None;
        let ok = parse_output_templates(&[t]).expect("absent delivery parses");
        assert!(ok[0].delivery.is_none());
    }

    #[test]
    fn parse_attest_request_covers_ceiling_shapes_and_all_width_checks() {
        let cmd = parse_attest_request(base_attest_request()).expect("node-default ceiling");
        assert_eq!(cmd.subject, SubjectAddress([0xA1; 32]));
        assert_eq!(cmd.asset_id, Digest32([0x11; 32]));
        assert_eq!(cmd.ceiling, AttestCeiling::NodeDefault);
        assert_eq!(cmd.nonce, [0x22; 32]);
        assert_eq!(cmd.chan_bind, ChanBind([0x33; 32]));

        let mut explicit = base_attest_request();
        explicit.nav_ceiling = vec![0x44; 32];
        explicit.size_ceiling = 55;
        let cmd = parse_attest_request(explicit).expect("explicit ceiling");
        assert_eq!(
            cmd.ceiling,
            AttestCeiling::Explicit {
                nav_ceiling: Digest32([0x44; 32]),
                size_ceiling: 55,
            }
        );

        let mut explicit_zero_size = base_attest_request();
        explicit_zero_size.nav_ceiling = vec![0x45; 32];
        let cmd = parse_attest_request(explicit_zero_size).expect("explicit zero-size ceiling");
        assert_eq!(
            cmd.ceiling,
            AttestCeiling::Explicit {
                nav_ceiling: Digest32([0x45; 32]),
                size_ceiling: 0,
            }
        );

        let mut mixed = base_attest_request();
        mixed.size_ceiling = 1;
        let err = parse_attest_request(mixed).expect_err("size without nav");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(err.public_message.contains("both"));

        for (field, mut req) in [
            ("subject", {
                let mut r = base_attest_request();
                r.subject = wrong_width_subject_bech32();
                r
            }),
            ("asset_id", {
                let mut r = base_attest_request();
                r.asset_id = vec![0; 31];
                r
            }),
            ("nonce", {
                let mut r = base_attest_request();
                r.nonce = vec![0; 31];
                r
            }),
            ("chan_bind", {
                let mut r = base_attest_request();
                r.chan_bind = vec![0; 33];
                r
            }),
            ("nav_ceiling", {
                let mut r = base_attest_request();
                r.nav_ceiling = vec![0; 31];
                r
            }),
        ] {
            let err = parse_attest_request(req).expect_err("invalid attest field");
            assert_eq!(err.code, KernelErrorCode::MalformedRequest);
            assert!(err.public_message.contains(field), "{}", err.public_message);
        }
    }

    #[test]
    fn parse_grant_request_and_scope_cover_all_presence_shapes() {
        let cmd = parse_grant_request(base_grant_request()).expect("valid grant");
        assert_eq!(cmd.subject, SubjectAddress([0xA1; 32]));
        assert_eq!(cmd.grantee_pk, XOnlyKey([0x21; 32]));
        assert_eq!(cmd.scope.assets, GrantAssetScope::All);
        assert_eq!(cmd.scope.not_before, 7);
        assert_eq!(cmd.scope.not_after, 99);
        assert_eq!(cmd.expiry, 123);
        assert_eq!(cmd.nonce, [0x22; 32]);
        assert_eq!(cmd.chan_bind, ChanBind([0x23; 32]));

        let mut missing = base_grant_request();
        missing.scope = None;
        let err = parse_grant_request(missing).expect_err("scope required");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(err.public_message.contains("scope is required"));

        for (field, req) in [
            ("subject", {
                let mut r = base_grant_request();
                r.subject = wrong_width_subject_bech32();
                r
            }),
            ("grantee_pk", {
                let mut r = base_grant_request();
                r.grantee_pk = vec![0; 31];
                r
            }),
            ("nonce", {
                let mut r = base_grant_request();
                r.nonce = vec![0; 31];
                r
            }),
            ("chan_bind", {
                let mut r = base_grant_request();
                r.chan_bind = vec![0; 31];
                r
            }),
        ] {
            let err = parse_grant_request(req).expect_err("invalid grant field");
            assert!(err.public_message.contains(field), "{}", err.public_message);
        }

        let err = parse_grant_scope(ProtoScope {
            asset_ids: vec![vec![0x11; 32]],
            all_assets: true,
            not_before: 0,
            not_after: 0,
        })
        .expect_err("all-assets cannot include ids");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(err.public_message.contains("all_assets=true"));

        let err = parse_grant_scope(ProtoScope {
            asset_ids: vec![],
            all_assets: false,
            not_before: 0,
            not_after: 0,
        })
        .expect_err("selected scope requires ids");
        assert!(err.public_message.contains("non-empty asset_ids"));

        let selected = parse_grant_scope(ProtoScope {
            asset_ids: vec![vec![0x31; 32], vec![0x32; 32]],
            all_assets: false,
            not_before: 1,
            not_after: 2,
        })
        .expect("selected scope");
        assert_eq!(
            selected,
            GrantScope {
                assets: GrantAssetScope::Selected(vec![
                    Digest32([0x31; 32]),
                    Digest32([0x32; 32]),
                ]),
                not_before: 1,
                not_after: 2,
            }
        );

        let err = parse_grant_scope(ProtoScope {
            asset_ids: vec![vec![0x31; 32], vec![0; 31]],
            all_assets: false,
            not_before: 0,
            not_after: 0,
        })
        .expect_err("bad selected id");
        assert!(err.public_message.contains("scope.asset_ids[1]"));
    }

    #[test]
    fn parse_pull_request_preserves_both_authorities_and_requires_scope() {
        for authority in [SessionAuthority::Ownership, SessionAuthority::Grant] {
            let cmd = parse_pull_request(base_pull_request(), authority).expect("valid pull");
            assert_eq!(cmd.nonce, [0x31; 32]);
            assert_eq!(cmd.subject, SubjectAddress([0xA1; 32]));
            assert_eq!(cmd.resolved_scope.assets, GrantAssetScope::All);
            assert_eq!(cmd.chan_bind, ChanBind([0x32; 32]));
            assert_eq!(cmd.authority, authority);
        }
        let mut req = base_pull_request();
        req.resolved_scope = None;
        let err = parse_pull_request(req, SessionAuthority::Ownership).expect_err("scope required");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(err.public_message.contains("resolved_scope is required"));

        for (field, req) in [
            ("nonce", {
                let mut r = base_pull_request();
                r.nonce = vec![0; 31];
                r
            }),
            ("subject", {
                let mut r = base_pull_request();
                r.subject = wrong_width_subject_bech32();
                r
            }),
            ("chan_bind", {
                let mut r = base_pull_request();
                r.chan_bind = vec![0; 31];
                r
            }),
        ] {
            let err = parse_pull_request(req, SessionAuthority::Grant)
                .expect_err("invalid pull field");
            assert!(err.public_message.contains(field), "{}", err.public_message);
        }
    }

    #[test]
    fn pull_record_and_coin_proof_conversions_preserve_fields() {
        let result = PullResult {
            records: vec![
                RecordRef {
                    record_id: Digest32([0x01; 32]),
                    record_type: RecordType::CoinProof,
                    transition_kind: None,
                    blob_id: Digest32([0x02; 32]),
                    occurred_at: 3,
                },
                RecordRef {
                    record_id: Digest32([0x04; 32]),
                    record_type: RecordType::SelfDelivery,
                    transition_kind: Some(TransitionKind::Send),
                    blob_id: Digest32([0x05; 32]),
                    occurred_at: 6,
                },
            ],
            session: SessionToken("session-token".into()),
            session_expiry: 77,
        };
        let proto = pull_result_to_proto(&result);
        assert_eq!(proto.session, "session-token");
        assert_eq!(proto.session_expiry, 77);
        assert_eq!(proto.records[0].record_id, vec![0x01; 32]);
        assert_eq!(proto.records[0].record_type, "coinproof");
        assert_eq!(proto.records[0].transition_kind, "");
        assert_eq!(proto.records[0].blob_id, vec![0x02; 32]);
        assert_eq!(proto.records[0].occurred_at, 3);
        assert_eq!(proto.records[1].transition_kind, "send");

        let record = parse_record_request(ProtoRecordRequest {
            record_id: vec![0x11; 32],
            session: "s".into(),
            chan_bind: vec![0x12; 32],
        })
        .expect("record request");
        assert_eq!(record.record_id, Digest32([0x11; 32]));
        assert_eq!(record.session, "s");
        assert_eq!(record.chan_bind, ChanBind([0x12; 32]));
        let err = parse_record_request(ProtoRecordRequest {
            record_id: vec![0; 31],
            session: String::new(),
            chan_bind: vec![0; 32],
        })
        .expect_err("record id width");
        assert!(err.public_message.contains("record_id"));
        let err = parse_record_request(ProtoRecordRequest {
            record_id: vec![0; 32],
            session: String::new(),
            chan_bind: vec![0; 31],
        })
        .expect_err("record channel width");
        assert!(err.public_message.contains("chan_bind"));

        for transition_kind in [None, Some(TransitionKind::Mint)] {
            let blob = DomainRecordBlob {
                canonical: vec![1, 2, 3],
                record_type: RecordType::SelfDelivery,
                transition_kind,
            };
            let proto = record_blob_to_proto(&blob);
            assert_eq!(proto.canonical, vec![1, 2, 3]);
            assert_eq!(proto.record_type, "self_delivery");
            assert_eq!(
                proto.transition_kind,
                transition_kind.map(|k| k.as_str()).unwrap_or_default()
            );
        }

        let proof = parse_coin_proof_request(ProtoCoinProofRequest {
            coin_id: vec![0x21; 32],
            session: "proof-session".into(),
            chan_bind: vec![0x22; 32],
        })
        .expect("coin proof request");
        assert_eq!(proof.coin_id, Digest32([0x21; 32]));
        assert_eq!(proof.session, "proof-session");
        assert_eq!(proof.chan_bind, ChanBind([0x22; 32]));
        let err = parse_coin_proof_request(ProtoCoinProofRequest {
            coin_id: vec![0; 31],
            session: String::new(),
            chan_bind: vec![0; 32],
        })
        .expect_err("coin id width");
        assert!(err.public_message.contains("coin_id"));
        let err = parse_coin_proof_request(ProtoCoinProofRequest {
            coin_id: vec![0; 32],
            session: String::new(),
            chan_bind: vec![0; 31],
        })
        .expect_err("coin proof channel width");
        assert!(err.public_message.contains("chan_bind"));
        assert_eq!(coin_proof_blob_to_proto(vec![9, 8]).canonical, vec![9, 8]);
    }

    #[test]
    fn session_receipt_and_account_state_conversions_cover_optional_pairs() {
        let bound = parse_session_bound("session".into(), vec![0x31; 32]).expect("session bound");
        assert_eq!(bound.session, "session");
        assert_eq!(bound.chan_bind, ChanBind([0x31; 32]));
        let err = parse_session_bound(String::new(), vec![0; 31]).expect_err("channel width");
        assert!(err.public_message.contains("chan_bind"));

        let receipt = CreditReceipt {
            subject: SubjectAddress([0x32; 32]),
            coin_id: Digest32([0x33; 32]),
            asset_id: Digest32([0x34; 32]),
            amount: u128::MAX,
            state: ReceiptState::Pending,
            credited_at: 35,
        };
        let proto = receipt_to_proto(&receipt);
        assert_eq!(proto.coin_id, vec![0x33; 32]);
        assert_eq!(proto.asset_id, vec![0x34; 32]);
        assert_eq!(proto.amount, u128::MAX.to_string());
        assert_eq!(proto.state, "pending");
        assert_eq!(proto.credited_at, 35);

        let base = AccountStateView {
            account_state: vec![1, 2],
            state_head: Digest32([0x41; 32]),
            head_record_id: Some(Digest32([0x42; 32])),
            send_counter: 43,
            current_pubkey: [0x44; 32],
            last_nullifier_pk: Some([0x45; 32]),
            last_nullifier_r: Some([0x46; 32]),
        };
        let proto = account_state_to_proto(&base).expect("complete state");
        assert_eq!(proto.account_state, vec![1, 2]);
        assert_eq!(proto.state_head, vec![0x41; 32]);
        assert_eq!(proto.head_record_id, vec![0x42; 32]);
        assert_eq!(proto.send_counter, 43);
        assert_eq!(proto.current_pubkey, vec![0x44; 32]);
        assert_eq!(proto.last_nullifier_pk, vec![0x45; 32]);
        assert_eq!(proto.last_nullifier_r, vec![0x46; 32]);

        let mut empty = base.clone();
        empty.head_record_id = None;
        empty.last_nullifier_pk = None;
        empty.last_nullifier_r = None;
        let proto = account_state_to_proto(&empty).expect("absent pair");
        assert!(proto.head_record_id.is_empty());
        assert!(proto.last_nullifier_pk.is_empty());
        assert!(proto.last_nullifier_r.is_empty());

        for (pk, r) in [(Some([1; 32]), None), (None, Some([2; 32]))] {
            let mut corrupt = empty.clone();
            corrupt.last_nullifier_pk = pk;
            corrupt.last_nullifier_r = r;
            let err = account_state_to_proto(&corrupt).expect_err("asymmetric pair");
            assert_eq!(err.code, KernelErrorCode::InternalError);
            assert_eq!(err.public_message, "Corrupt account state");
            assert!(err.internal_context.expect("detail").detail.contains("both"));
        }
    }

    #[test]
    fn session_authority_and_exact_width_parsers_cover_all_arms() {
        assert_eq!(parse_session_authority(" ownership ").unwrap(), SessionAuthority::Ownership);
        assert_eq!(parse_session_authority("\tgrant\n").unwrap(), SessionAuthority::Grant);
        let err = parse_session_authority("  ").expect_err("blank authority");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(err.public_message.contains("required"));
        let err = parse_session_authority(" admin ").expect_err("unknown authority");
        assert!(err.public_message.contains("admin"));

        assert_eq!(parse_subject_address(&format!(" {} ", receive_subject_bech32())).unwrap(), SubjectAddress([0xA1; 32]));
        let err = parse_subject_address(" \t ").expect_err("blank subject");
        assert!(err.public_message.contains("subject is required"));
        let err = parse_subject_address("zk1invalid").expect_err("invalid bech32m");
        assert!(err.public_message.contains("Bech32m"));

        for (field, err) in [
            ("x", parse_xonly(&[0; 31], "x").expect_err("short xonly")),
            ("digest", parse_digest32(&[0; 33], "digest").expect_err("long digest")),
            ("exact32", parse_exact_32(&[0; 31], "exact32").expect_err("short exact32")),
            ("exact64", parse_exact_64(&[0; 63], "exact64").expect_err("short exact64")),
        ] {
            assert_eq!(err.code, KernelErrorCode::MalformedRequest);
            assert!(err.public_message.contains(field));
        }
    }

    #[test]
    fn list_inscriptions_parses_origin_partial_cursors_and_limits() {
        let origin = parse_list_inscriptions_request(ProtoListInscriptionsRequest {
            from_height: None,
            limit: None,
            from_tx_index: None,
            from_vin_index: None,
        })
        .expect("origin defaults");
        assert_eq!(origin.from, InscriptionCursor::origin());
        assert_eq!(origin.limit.get(), 100);

        let partial = parse_list_inscriptions_request(ProtoListInscriptionsRequest {
            from_height: Some(10),
            limit: Some(1000),
            from_tx_index: None,
            from_vin_index: Some(12),
        })
        .expect("partial cursor defaults remaining values");
        assert_eq!(
            partial.from,
            InscriptionCursor {
                height: 10,
                tx_index: 0,
                vin_index: 12,
            }
        );
        assert_eq!(partial.limit.get(), 1000);

        for invalid in [0, 1001] {
            let err = parse_list_inscriptions_request(ProtoListInscriptionsRequest {
                from_height: None,
                limit: Some(invalid),
                from_tx_index: None,
                from_vin_index: None,
            })
            .expect_err("out-of-bounds limit");
            assert_eq!(err.code, KernelErrorCode::BoundsExceeded);
            assert!(err.public_message.contains(&invalid.to_string()));
        }
    }

    #[test]
    fn chain_request_and_projection_helpers_preserve_every_field() {
        let req = parse_nullifier_path_request(ProtoNullifierPathRequest {
            pubkey: vec![0x11; 32],
        })
        .expect("nullifier request");
        assert_eq!(req.pubkey, XOnlyKey([0x11; 32]));
        let err = parse_nullifier_path_request(ProtoNullifierPathRequest {
            pubkey: vec![0; 31],
        })
        .expect_err("pubkey width");
        assert!(err.public_message.contains("pubkey"));

        let tip = DomainAccumulatorTip {
            root: Digest32([0x12; 32]),
            tip_block_hash: Digest32([0x13; 32]),
            tip_height: 14,
            size: 15,
        };
        let proto = accumulator_tip_to_proto(&tip);
        assert_eq!(proto.root, vec![0x12; 32]);
        assert_eq!(proto.tip_block_hash, vec![0x13; 32]);
        assert_eq!(proto.tip_height, 14);
        assert_eq!(proto.size, 15);

        let inscription = ListedInscription {
            txid: [0x21; 32],
            height: 22,
            tx_index: 23,
            vin_index: 24,
            format: 1,
            count: 1,
            nullifiers: vec![ListedNullifier {
                pubkey: [0x25; 32],
                r: [0x26; 32],
                state: NullifierMemberState::Completed,
            }],
            confirmation_state: RevealConfirmationState::Pending,
        };
        let proto = inscription_to_proto(&inscription);
        assert_eq!(proto.txid, vec![0x21; 32]);
        assert_eq!(proto.height, 22);
        assert_eq!(proto.tx_index, 23);
        assert_eq!(proto.vin_index, 24);
        assert_eq!(proto.format, 1);
        assert_eq!(proto.count, 1);
        assert_eq!(proto.nullifiers.len(), 1);
        assert_eq!(proto.nullifiers[0].pubkey, vec![0x25; 32]);
        assert_eq!(proto.nullifiers[0].r, vec![0x26; 32]);
        assert_eq!(proto.nullifiers[0].state, "completed");
        assert_eq!(proto.confirmation_state, "pending");
    }

    #[test]
    fn nullifier_path_projection_covers_present_and_absent_defaults() {
        let present = DomainNullifierPath::Present {
            root: Digest32([0x31; 32]),
            tip_height: 32,
            tip_block_hash: Digest32([0x33; 32]),
            leaf: Digest32([0x34; 32]),
            position: 35,
            audit_path: vec![Digest32([0x36; 32]), Digest32([0x37; 32])],
            tree_size: 38,
        };
        let proto = nullifier_path_to_proto(&present);
        assert_eq!(proto.root, vec![0x31; 32]);
        assert_eq!(proto.tip_height, 32);
        assert!(proto.present);
        assert_eq!(proto.leaf, vec![0x34; 32]);
        assert_eq!(proto.position, 35);
        assert_eq!(proto.audit_path, vec![vec![0x36; 32], vec![0x37; 32]]);
        assert_eq!(proto.tree_size, 38);
        assert_eq!(proto.tip_block_hash, vec![0x33; 32]);

        let absent = DomainNullifierPath::Absent {
            root: Digest32([0x41; 32]),
            tip_height: 42,
            tip_block_hash: Digest32([0x43; 32]),
            tree_size: 44,
        };
        let proto = nullifier_path_to_proto(&absent);
        assert_eq!(proto.root, vec![0x41; 32]);
        assert_eq!(proto.tip_height, 42);
        assert!(!proto.present);
        assert!(proto.leaf.is_empty());
        assert_eq!(proto.position, 0);
        assert!(proto.audit_path.is_empty());
        assert_eq!(proto.tree_size, 44);
        assert_eq!(proto.tip_block_hash, vec![0x43; 32]);
    }

    #[test]
    fn kernel_info_and_bootstrap_projection_cover_readiness_states() {
        let ready = kernel_info_to_proto(&kernel_info(Readiness::Ready));
        assert_eq!(ready.network, "regtest");
        assert_eq!(ready.protocol_version, "v1");
        assert_eq!(ready.circuit_digests.get("C"), Some(&vec![0xA4; 32]));
        assert_eq!(ready.circuit_digests.get("C_balance"), Some(&vec![0xA5; 32]));
        assert_eq!(ready.relay_url, "wss://relay.example");
        assert_eq!(ready.blossom_url, "https://blob.example");
        assert_eq!(ready.finality_confirmations, 6);
        assert_eq!(ready.max_tx_inputs, 4);
        assert_eq!(ready.max_tx_outputs, 8);
        assert_eq!(ready.max_rx_coins, 16);
        assert_eq!(ready.max_account_assets, 32);
        assert!(ready.ready);
        assert_eq!(ready.ready_reason, None);
        assert_eq!(ready.bitcoin_tip_height, 1234);
        assert_eq!(ready.accumulator_root, vec![0xA6; 32]);
        assert_eq!(ready.scanner_lag, 2);
        assert_eq!(ready.max_blob_bytes, 1_000_000);
        assert_eq!(ready.activation_height, 100);
        assert_eq!(ready.kernel_parts, vec!["scanner", "prover"]);
        assert_eq!(ready.bootstrap_pubkey, vec![0xA7; 32]);
        let bootstrap = ready.bootstrap.expect("bootstrap");
        assert_eq!(bootstrap.network, "regtest");
        assert_eq!(bootstrap.protocol_version, "v1");
        assert_eq!(bootstrap.seed_relays, vec!["wss://seed.example"]);
        assert_eq!(bootstrap.blob_stores, vec!["https://blob.example"]);
        assert_eq!(bootstrap.operator_ids, vec![vec![0xA2; 32]]);
        assert_eq!(bootstrap.issued_at, 10);
        assert_eq!(bootstrap.expires_at, 20);
        assert_eq!(bootstrap.manifest_sig, vec![0xA3; 64]);

        let not_ready = kernel_info_to_proto(&kernel_info(Readiness::NotReady {
            reason: ReadyReason::ScannerLag,
        }));
        assert!(!not_ready.ready);
        assert_eq!(not_ready.ready_reason.as_deref(), Some("scanner_lag"));
    }

    #[test]
    fn parse_sign_request_rejects_non_uuid_job_id() {
        let err = parse_sign_request(ProtoSignRequest {
            job_id: "definitely-not-a-uuid".into(),
            signature: vec![0; 64],
            s2c_nonce: vec![0; 32],
        })
        .expect_err("invalid UUID");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert_eq!(err.public_message, "job_id must be a UUID");
    }

    #[test]
    fn parse_mint_and_send_happy_paths_preserve_all_fields() {
        let mint = parse_transition_request(base_mint_request()).expect("mint");
        match mint {
            TransitionCommand::Mint {
                common,
                issuance,
                output_templates,
            } => {
                assert_eq!(common.subject, SubjectAddress([0xA1; 32]));
                assert_eq!(common.next_pubkey, XOnlyKey([0x52; 32]));
                assert_eq!(common.npk_rand, Digest32([0x53; 32]));
                assert_eq!(common.publisher, PublisherChoice::SelfPublish);
                assert_eq!(common.idempotency_key.as_str(), "k-mint");
                assert_eq!(
                    issuance,
                    Issuance::V1 {
                        name: "asset".into(),
                        decimals: 8,
                        amount: 42,
                        creator_pubkey: XOnlyKey([0x42; 32]),
                    }
                );
                assert_eq!(output_templates.len(), 1);
                assert_eq!(output_templates[0].recipient, SubjectAddress([0xA1; 32]));
                assert_eq!(output_templates[0].asset_id, Digest32([0x51; 32]));
                assert_eq!(output_templates[0].amount, 17);
                assert!(output_templates[0].delivery.is_none());
            }
            other => panic!("expected Mint, got {other:?}"),
        }

        let send = parse_transition_request(base_send_request()).expect("send");
        match send {
            TransitionCommand::Send {
                common,
                input_coins,
                output_templates,
            } => {
                assert_eq!(common.subject, SubjectAddress([0xA1; 32]));
                assert_eq!(common.next_pubkey, XOnlyKey([0x61; 32]));
                assert_eq!(common.npk_rand, Digest32([0x62; 32]));
                assert_eq!(
                    common.publisher,
                    PublisherChoice::FeeLessHandOff {
                        publisher_pubkey: XOnlyKey([0x64; 32]),
                    }
                );
                assert_eq!(common.idempotency_key.as_str(), "k-send");
                assert_eq!(input_coins, vec![Digest32([0x63; 32])]);
                assert_eq!(output_templates.len(), 1);
            }
            other => panic!("expected Send, got {other:?}"),
        }
    }

    #[test]
    fn transition_presence_matrix_rejects_every_forbidden_shape_and_kind() {
        for (field, mut req) in [
            ("input_coins", {
                let mut r = base_mint_request();
                r.input_coins = vec![vec![0; 32]];
                r
            }),
            ("fold_coin_ids", {
                let mut r = base_mint_request();
                r.fold_coin_ids = vec![vec![0; 32]];
                r
            }),
            ("genesis_pubkey", {
                let mut r = base_mint_request();
                r.genesis_pubkey = vec![0; 32];
                r
            }),
        ] {
            let err = parse_transition_request(req).expect_err("forbidden mint field");
            assert_eq!(err.code, KernelErrorCode::MalformedRequest);
            assert!(err.public_message.contains(field));
        }
        let mut missing_issuance = base_mint_request();
        missing_issuance.issuance = None;
        let err = parse_transition_request(missing_issuance).expect_err("mint issuance required");
        assert!(err.public_message.contains("requires issuance"));

        let mut send_issuance = base_send_request();
        send_issuance.issuance = Some(base_issuance(1));
        let err = parse_transition_request(send_issuance).expect_err("send issuance forbidden");
        assert!(err.public_message.contains("must not carry issuance"));
        let mut send_fold = base_send_request();
        send_fold.fold_coin_ids = vec![vec![0; 32]];
        let err = parse_transition_request(send_fold).expect_err("send fold forbidden");
        assert!(err.public_message.contains("fold_coin_ids"));
        let mut send_genesis = base_send_request();
        send_genesis.genesis_pubkey = vec![0; 32];
        let err = parse_transition_request(send_genesis).expect_err("send genesis forbidden");
        assert!(err.public_message.contains("genesis_pubkey"));

        let mut receive_issuance = base_receive_request();
        receive_issuance.issuance = Some(base_issuance(1));
        let err = parse_transition_request(receive_issuance).expect_err("receive issuance forbidden");
        assert!(err.public_message.contains("issuance"));

        let mut blank = base_send_request();
        blank.kind = " \t ".into();
        let err = parse_transition_request(blank).expect_err("blank kind");
        assert!(err.public_message.contains("kind is required"));
        let mut unknown = base_send_request();
        unknown.kind = " burn ".into();
        let err = parse_transition_request(unknown).expect_err("unknown kind");
        assert!(err.public_message.contains("burn"));
    }

    #[test]
    fn refusal_helpers_cover_empty_and_nonempty_inputs() {
        assert_eq!(refuse_nonempty_digests(&[], "items", "mint"), Ok(()));
        let err = refuse_nonempty_digests(&[vec![0; 32]], "items", "mint")
            .expect_err("nonempty digests");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(err.public_message.contains("kind=mint"));
        assert!(err.public_message.contains("items"));
        assert_eq!(refuse_nonempty_bytes(&[], "bytes", "send"), Ok(()));
        let err = refuse_nonempty_bytes(&[1], "bytes", "send").expect_err("nonempty bytes");
        assert!(err.public_message.contains("kind=send"));
        assert!(err.public_message.contains("bytes"));
    }

    #[test]
    fn publisher_choice_and_digest_list_cover_all_shapes() {
        let err = parse_publisher_choice(&[], " \t fee ").expect_err("fee address forbidden");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(err.public_message.contains("fee_address"));
        assert_eq!(parse_publisher_choice(&[], "  ").unwrap(), PublisherChoice::SelfPublish);
        assert_eq!(
            parse_publisher_choice(&[0x11; 32], "").unwrap(),
            PublisherChoice::FeeLessHandOff {
                publisher_pubkey: XOnlyKey([0x11; 32]),
            }
        );
        let err = parse_publisher_choice(&[0; 31], "").expect_err("publisher width");
        assert!(err.public_message.contains("publisher_pubkey"));

        assert!(parse_digest_list(&[], "ids").unwrap().is_empty());
        assert_eq!(
            parse_digest_list(&[vec![0x21; 32]], "ids").unwrap(),
            vec![Digest32([0x21; 32])]
        );
        let err = parse_digest_list(&[vec![0; 32], vec![0; 31]], "ids")
            .expect_err("indexed width");
        assert!(err.public_message.contains("ids[1]"));
    }

    #[test]
    fn output_templates_cover_empty_none_invoice_profile_and_field_errors() {
        assert!(parse_output_templates(&[]).unwrap().is_empty());
        let none = parse_output_templates(&[base_output_template()]).expect("no delivery");
        assert_eq!(none.len(), 1);
        assert!(none[0].delivery.is_none());

        let mut invoice_template = base_output_template();
        invoice_template.delivery = Some(ProtoDeliveryCredential {
            body: Some(kernel_proto::delivery_credential::Body::Invoice(base_invoice())),
        });
        let parsed = parse_output_templates(&[invoice_template]).expect("invoice delivery");
        match parsed[0].delivery.as_ref().expect("delivery") {
            DeliveryCredential::Invoice(inv) => {
                assert_eq!(inv.amount, 17);
                assert_eq!(inv.recipient, [0xA1; 32]);
                assert_eq!(inv.asset_id, [0x51; 32]);
            }
            other => panic!("expected invoice, got {other:?}"),
        }

        let mut profile_template = base_output_template();
        profile_template.delivery = Some(ProtoDeliveryCredential {
            body: Some(kernel_proto::delivery_credential::Body::ProfileEvent(
                signed_kind0_proto(false),
            )),
        });
        let parsed = parse_output_templates(&[profile_template]).expect("profile delivery");
        match parsed[0].delivery.as_ref().expect("delivery") {
            DeliveryCredential::Profile(event) => {
                assert_eq!(event.kind, 0);
                assert_eq!(event.tags.len(), 1);
                assert_eq!(event.content, "{\"name\":\"alice\"}");
            }
            other => panic!("expected profile, got {other:?}"),
        }

        let mut bad_recipient = base_output_template();
        bad_recipient.recipient = "bad".into();
        let err = parse_output_templates(&[bad_recipient]).expect_err("recipient error");
        assert!(err.public_message.starts_with("output_templates[0].recipient: "));
        let mut bad_asset = base_output_template();
        bad_asset.asset_id = vec![0; 31];
        let err = parse_output_templates(&[bad_asset]).expect_err("asset error");
        assert!(err.public_message.contains("output_templates[0].asset_id"));
        let mut bad_amount = base_output_template();
        bad_amount.amount = "not-a-number".into();
        let err = parse_output_templates(&[bad_amount]).expect_err("amount error");
        assert!(err.public_message.contains("output_templates[0].amount"));
    }

    #[test]
    fn delivery_credential_directly_covers_invoice_and_profile_arms() {
        let invoice = ProtoDeliveryCredential {
            body: Some(kernel_proto::delivery_credential::Body::Invoice(base_invoice())),
        };
        match parse_delivery_credential(&invoice, 2).expect("invoice arm") {
            DeliveryCredential::Invoice(inv) => assert_eq!(inv.pk0, [0x71; 32]),
            other => panic!("expected invoice, got {other:?}"),
        }
        let profile = ProtoDeliveryCredential {
            body: Some(kernel_proto::delivery_credential::Body::ProfileEvent(
                signed_kind0_proto(true),
            )),
        };
        match parse_delivery_credential(&profile, 3).expect("profile arm") {
            DeliveryCredential::Profile(event) => assert!(event.tags.is_empty()),
            other => panic!("expected profile, got {other:?}"),
        }
    }

    #[test]
    fn wire_invoice_preserves_all_fields_and_memo_presence() {
        let parsed = parse_wire_invoice(&base_invoice(), "out").expect("invoice");
        assert_eq!(parsed.amount, 17);
        assert_eq!(parsed.recipient, [0xA1; 32]);
        assert_eq!(parsed.asset_id, [0x51; 32]);
        assert_eq!(parsed.memo, None);
        assert_eq!(parsed.pk0, [0x71; 32]);
        assert_eq!(parsed.nk_commit, [0x72; 32]);
        assert_eq!(parsed.ivpk, [0x73; 32]);
        assert_eq!(parsed.op_pubkey, [0x74; 32]);
        assert_eq!(parsed.relays, vec!["wss://relay.example"]);
        assert_eq!(parsed.addr_sig, [0x75; 64]);
        assert_eq!(parsed.sig, [0x76; 64]);

        let mut with_memo = base_invoice();
        with_memo.memo = "  hello  ".into();
        let parsed = parse_wire_invoice(&with_memo, "out").expect("memo");
        assert_eq!(parsed.memo.as_deref(), Some("hello"));
    }

    #[test]
    fn wire_invoice_rejects_each_malformed_field() {
        let mut bad_recipient = base_invoice();
        bad_recipient.recipient = "bad".into();
        let err = parse_wire_invoice(&bad_recipient, "out").expect_err("recipient");
        assert!(err.public_message.starts_with("out.invoice.recipient: "));

        let mut bad_amount = base_invoice();
        bad_amount.amount.clear();
        let err = parse_wire_invoice(&bad_amount, "out").expect_err("empty amount");
        assert!(err.public_message.contains("out.invoice.amount"));
        let mut bad_amount = base_invoice();
        bad_amount.amount = "x".into();
        let err = parse_wire_invoice(&bad_amount, "out").expect_err("nonnumeric amount");
        assert!(err.public_message.contains("decimal u128"));

        for (field, inv) in [
            ("asset_id", {
                let mut x = base_invoice();
                x.asset_id = vec![0; 31];
                x
            }),
            ("pk0", {
                let mut x = base_invoice();
                x.pk0 = vec![0; 31];
                x
            }),
            ("nk_commit", {
                let mut x = base_invoice();
                x.nk_commit = vec![0; 31];
                x
            }),
            ("ivpk", {
                let mut x = base_invoice();
                x.ivpk = vec![0; 31];
                x
            }),
            ("op_pubkey", {
                let mut x = base_invoice();
                x.op_pubkey = vec![0; 31];
                x
            }),
            ("addr_sig", {
                let mut x = base_invoice();
                x.addr_sig = vec![0; 63];
                x
            }),
            ("sig", {
                let mut x = base_invoice();
                x.sig = vec![0; 65];
                x
            }),
        ] {
            let err = parse_wire_invoice(&inv, "out").expect_err("invoice width");
            assert_eq!(err.code, KernelErrorCode::MalformedRequest);
            assert!(err.public_message.contains(field), "{}", err.public_message);
        }

        let mut no_relays = base_invoice();
        no_relays.relays.clear();
        let err = parse_wire_invoice(&no_relays, "out").expect_err("relay required");
        assert!(err.public_message.contains("must contain at least one relay URL"));
    }

    #[test]
    fn wire_kind0_event_accepts_signed_events_and_empty_tags_encoding() {
        let tagged = signed_kind0_proto(false);
        let event = parse_wire_kind0_event(&tagged, "out").expect("signed event");
        assert_eq!(event.id.to_vec(), tagged.id);
        assert_eq!(event.pubkey.to_vec(), tagged.pubkey);
        assert_eq!(event.created_at, tagged.created_at);
        assert_eq!(event.kind, 0);
        assert_eq!(event.tags.len(), 1);
        assert_eq!(event.content, tagged.content);
        assert_eq!(event.sig.to_vec(), tagged.sig);

        let empty = signed_kind0_proto(true);
        let event = parse_wire_kind0_event(&empty, "out").expect("empty tags_json");
        assert!(event.tags.is_empty());
    }

    #[test]
    fn wire_kind0_event_rejects_json_kind_width_and_crypto_failures() {
        let mut bad_json = signed_kind0_proto(true);
        bad_json.tags_json = "not-json".into();
        let err = parse_wire_kind0_event(&bad_json, "out").expect_err("invalid tags JSON");
        assert!(err.public_message.contains("JSON array of tag arrays"));

        let mut bad_kind = signed_kind0_proto(true);
        bad_kind.kind = 1;
        let err = parse_wire_kind0_event(&bad_kind, "out").expect_err("wrong kind");
        assert!(err.public_message.contains("got 1"));

        for (field, event) in [
            ("id", {
                let mut e = signed_kind0_proto(true);
                e.id = vec![0; 31];
                e
            }),
            ("pubkey", {
                let mut e = signed_kind0_proto(true);
                e.pubkey = vec![0; 33];
                e
            }),
            ("sig", {
                let mut e = signed_kind0_proto(true);
                e.sig = vec![0; 63];
                e
            }),
        ] {
            let err = parse_wire_kind0_event(&event, "out").expect_err("event width");
            assert!(err.public_message.contains(field));
        }

        let mut wrong_id = signed_kind0_proto(true);
        wrong_id.id = vec![0xFF; 32];
        let err = parse_wire_kind0_event(&wrong_id, "out").expect_err("id mismatch");
        assert!(err.public_message.contains("failed NIP-01 verification"));

        let mut wrong_sig = signed_kind0_proto(true);
        wrong_sig.sig[0] ^= 1;
        let err = parse_wire_kind0_event(&wrong_sig, "out").expect_err("bad signature");
        assert!(err.public_message.contains("failed NIP-01 verification"));
    }

    #[test]
    fn issuance_versions_preserve_fields_and_enforce_presence() {
        assert_eq!(
            parse_issuance(base_issuance(1)).expect("v1 issuance"),
            Issuance::V1 {
                name: "asset".into(),
                decimals: 8,
                amount: 42,
                creator_pubkey: XOnlyKey([0x42; 32]),
            }
        );
        assert_eq!(
            parse_issuance(base_issuance(2)).expect("v2 issuance"),
            Issuance::V2 {
                name: "asset".into(),
                decimals: 8,
                amount: 42,
                cap_total: 1000,
                terms_salt: Digest32([0x41; 32]),
                creator_pubkey: XOnlyKey([0x42; 32]),
            }
        );

        for invalid_v1 in [{
            let mut i = base_issuance(1);
            i.cap_total = "1".into();
            i
        }, {
            let mut i = base_issuance(1);
            i.terms_salt = vec![0; 32];
            i
        }] {
            let err = parse_issuance(invalid_v1).expect_err("v1 extras forbidden");
            assert!(err.public_message.contains("must not carry cap_total or terms_salt"));
        }

        let mut missing_cap = base_issuance(2);
        missing_cap.cap_total = " \t ".into();
        let err = parse_issuance(missing_cap).expect_err("v2 cap required");
        assert!(err.public_message.contains("requires cap_total"));

        let mut unknown = base_issuance(1);
        unknown.issuance_version = 3;
        let err = parse_issuance(unknown).expect_err("unknown issuance version");
        assert!(err.public_message.contains("got 3"));

        let mut decimals = base_issuance(1);
        decimals.decimals = 256;
        let err = parse_issuance(decimals).expect_err("decimals overflow");
        assert!(err.public_message.contains("must fit u8"));

        let mut amount = base_issuance(1);
        amount.amount = "nope".into();
        let err = parse_issuance(amount).expect_err("amount invalid");
        assert!(err.public_message.contains("issuance.amount"));

        let mut creator = base_issuance(1);
        creator.creator_pubkey = vec![0; 31];
        let err = parse_issuance(creator).expect_err("creator width");
        assert!(err.public_message.contains("issuance.creator_pubkey"));

        let mut cap = base_issuance(2);
        cap.cap_total = "nope".into();
        let err = parse_issuance(cap).expect_err("cap invalid");
        assert!(err.public_message.contains("issuance.cap_total"));
        let mut salt = base_issuance(2);
        salt.terms_salt = vec![0; 31];
        let err = parse_issuance(salt).expect_err("salt width");
        assert!(err.public_message.contains("issuance.terms_salt"));
    }

    #[test]
    fn decimal_u128_parser_covers_required_invalid_trimmed_and_max() {
        let err = parse_u128_decimal(" \t ", "amount").expect_err("required decimal");
        assert_eq!(err.code, KernelErrorCode::MalformedRequest);
        assert!(err.public_message.contains("amount is required"));
        let err = parse_u128_decimal("12x", "amount").expect_err("invalid decimal");
        assert!(err.public_message.contains("decimal u128 string"));
        assert_eq!(parse_u128_decimal(" 42 ", "amount").unwrap(), 42);
        assert_eq!(
            parse_u128_decimal(&u128::MAX.to_string(), "amount").unwrap(),
            u128::MAX
        );
    }

    #[test]
    fn job_projection_covers_cancelled_proving_publishing_and_progress_edges() {
        let cancelled = Job {
            id: JobId(Uuid::from_u128(0xC1)),
            kind: JobKind::Send,
            phase: "cancelling".into(),
            progress: 75,
            state: JobState::Cancelled {
                error: Some(v1::encode_job_error("internal_error", "cancelled by user")),
            },
        };
        assert_eq!(cancelled.normative_status(), NormativeJobStatus::Cancelled);
        let proto = job_to_proto(&cancelled).expect("cancelled");
        assert_eq!(proto.status, "cancelled");
        assert!(proto.phase.is_empty());
        assert_eq!(proto.progress, 0.75);
        let error = proto.error.expect("cancelled error");
        assert_eq!(error.error, "internal_error");
        assert_eq!(error.message, "cancelled by user");

        for (state, status, phase) in [
            (JobState::Proving, "proving", "witness"),
            (JobState::Publishing, "publishing", "broadcasting"),
        ] {
            let job = Job {
                id: JobId(Uuid::from_u128(0xC2)),
                kind: JobKind::Receive,
                phase: phase.into(),
                progress: 10,
                state,
            };
            let proto = job_to_proto(&job).expect("nonterminal job");
            assert_eq!(proto.status, status);
            assert_eq!(proto.phase, phase);
            assert!(proto.awaiting_signature.is_none());
            assert!(proto.result.is_none());
            assert!(proto.error.is_none());
        }
        assert_eq!(v1_progress_fraction(0), 0.0);
        assert_eq!(v1_progress_fraction(100), 1.0);
    }

    #[test]
    fn proto_job_error_covers_cancelled_default_and_non_string_message_failure() {
        let cancelled = proto_job_error(None, true).expect("cancelled default");
        assert_eq!(cancelled.error, "internal_error");
        assert_eq!(cancelled.message, "cancelled");

        let raw = r#"{"error":"proving_failed","message":7}"#;
        let err = proto_job_error(Some(raw), false).expect_err("message must be string");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        assert!(
            err.internal_context
                .expect("detail")
                .detail
                .contains("without message field")
        );
    }

    #[test]
    fn awaiting_and_completed_decoders_reject_non_objects_and_cover_receive_publisher() {
        let err = decode_awaiting_signature(&JobPayload(serde_json::json!([1, 2, 3])))
            .expect_err("awaiting object required");
        assert_eq!(err.code, KernelErrorCode::InternalError);
        assert!(err.internal_context.expect("detail").detail.contains("not a JSON object"));

        let err = decode_job_result(JobKind::Send, &JobPayload(serde_json::json!("string")))
            .expect_err("result object required");
        assert!(err.internal_context.expect("detail").detail.contains("not a JSON object"));

        let mut value = sample_completed_payload().0;
        value
            .as_object_mut()
            .expect("sample object")
            .insert("publisher_pubkey".into(), serde_json::json!(hex32(0xD1)));
        let result = decode_job_result(JobKind::Receive, &JobPayload(value)).expect("receive result");
        assert_eq!(result.new_account_state_hash, vec![0xA1; 32]);
        assert_eq!(result.output_coins_root, vec![0xA2; 32]);
        assert_eq!(result.input_nullifiers_root, vec![0xA3; 32]);
        assert_eq!(result.output_coin_ids, vec![vec![0xB1; 32]]);
        assert_eq!(result.publisher_pubkey, vec![0xD1; 32]);
        assert!(result.attestation.is_empty());
    }

    #[test]
    fn required_hex_helpers_cover_missing_empty_invalid_odd_and_success() {
        let object = serde_json::json!({"field": hex32(0x11)});
        let obj = object.as_object().expect("object");
        assert_eq!(require_hex_bytes(obj, "field", 32).unwrap(), vec![0x11; 32]);
        let err = require_hex_bytes(obj, "missing", 32).expect_err("missing fixed hex");
        assert!(err.internal_context.expect("detail").detail.contains("missing"));

        for (value, expected) in [
            (serde_json::json!({}), "missing required hex field"),
            (serde_json::json!({"blob": ""}), "is empty hex"),
            (serde_json::json!({"blob": "zz"}), "is not hex"),
            (serde_json::json!({"blob": "abc"}), "hex decode failed"),
        ] {
            let err = require_hex_bytes_unbounded(value.as_object().unwrap(), "blob")
                .expect_err("invalid unbounded hex");
            assert!(
                err.internal_context.expect("detail").detail.contains(expected),
                "expected {expected}"
            );
        }
        let value = serde_json::json!({"blob": "00ff"});
        assert_eq!(
            require_hex_bytes_unbounded(value.as_object().unwrap(), "blob").unwrap(),
            vec![0, 255]
        );
    }

    #[test]
    fn optional_hex_helper_covers_absent_null_type_empty_valid_and_width_error() {
        for value in [serde_json::json!({}), serde_json::json!({"key": null})] {
            assert!(optional_hex_bytes(value.as_object().unwrap(), "key", 32)
                .unwrap()
                .is_empty());
        }
        let value = serde_json::json!({"key": 1});
        let err = optional_hex_bytes(value.as_object().unwrap(), "key", 32)
            .expect_err("non-string optional hex");
        assert!(err.internal_context.expect("detail").detail.contains("not a string"));
        let value = serde_json::json!({"key": ""});
        assert!(optional_hex_bytes(value.as_object().unwrap(), "key", 32)
            .unwrap()
            .is_empty());
        let value = serde_json::json!({"key": hex32(0x22)});
        assert_eq!(
            optional_hex_bytes(value.as_object().unwrap(), "key", 32).unwrap(),
            vec![0x22; 32]
        );
        let value = serde_json::json!({"key": "00"});
        let err = optional_hex_bytes(value.as_object().unwrap(), "key", 32)
            .expect_err("optional width");
        assert!(err.internal_context.expect("detail").detail.contains("64 hex chars"));
    }

    #[test]
    fn hex_array_and_u64_helpers_cover_every_failure_shape() {
        for value in [serde_json::json!({}), serde_json::json!({"ids": "no"})] {
            let err = require_hex_bytes_array(value.as_object().unwrap(), "ids", 32)
                .expect_err("array required");
            assert!(err.internal_context.expect("detail").detail.contains("array field"));
        }
        let value = serde_json::json!({"ids": [hex32(0x31), 7]});
        let err = require_hex_bytes_array(value.as_object().unwrap(), "ids", 32)
            .expect_err("element string required");
        assert!(err.internal_context.expect("detail").detail.contains("ids[1]"));
        let value = serde_json::json!({"ids": ["00"]});
        let err = require_hex_bytes_array(value.as_object().unwrap(), "ids", 32)
            .expect_err("element width");
        assert!(err.internal_context.expect("detail").detail.contains("ids[0]"));
        let value = serde_json::json!({"ids": [hex32(0x32)]});
        assert_eq!(
            require_hex_bytes_array(value.as_object().unwrap(), "ids", 32).unwrap(),
            vec![vec![0x32; 32]]
        );

        let value = serde_json::json!({});
        let err = require_u64(value.as_object().unwrap(), "n").expect_err("missing u64");
        assert!(err.internal_context.expect("detail").detail.contains("missing required field"));
        let value = serde_json::json!({"n": "1"});
        let err = require_u64(value.as_object().unwrap(), "n").expect_err("number required");
        assert!(err.internal_context.expect("detail").detail.contains("not a number"));
        let value = serde_json::json!({"n": -1});
        let err = require_u64(value.as_object().unwrap(), "n").expect_err("nonnegative required");
        assert!(err.internal_context.expect("detail").detail.contains("non-negative integer"));
        let value = serde_json::json!({"n": 42});
        assert_eq!(require_u64(value.as_object().unwrap(), "n").unwrap(), 42);
    }

    #[test]
    fn decode_hex_exact_covers_length_alphabet_and_success() {
        let err = decode_hex_exact("00", "digest", 32).expect_err("wrong text length");
        assert!(err.internal_context.expect("detail").detail.contains("64 hex chars"));
        let err = decode_hex_exact(&"z".repeat(64), "digest", 32).expect_err("non-hex alphabet");
        assert!(err.internal_context.expect("detail").detail.contains("is not hex"));
        assert_eq!(decode_hex_exact(&hex32(0x41), "digest", 32).unwrap(), vec![0x41; 32]);
    }

    #[test]
    fn publish_request_happy_path_and_fee_rejection_preserve_contract() {
        let cmd = parse_publish_request(base_publish_request()).expect("publish request");
        assert_eq!(cmd.public_key, XOnlyKey([0x91; 32]));
        assert_eq!(cmd.r, XOnlyKey([0x92; 32]));
        assert_eq!(cmd.s, Digest32([0x93; 32]));
        assert_eq!(cmd.r_prime, XOnlyKey([0x94; 32]));
        assert_eq!(cmd.block_anchor.block_hash, Digest32([0x95; 32]));
        assert_eq!(cmd.block_anchor.height, 321);

        for (field, req) in [
            ("fee_blob_id", {
                let mut r = base_publish_request();
                r.fee_blob_id = vec![1];
                r
            }),
            ("fee_epk", {
                let mut r = base_publish_request();
                r.fee_epk = vec![1];
                r
            }),
            ("fee_blob_locators", {
                let mut r = base_publish_request();
                r.fee_blob_locators = vec![1];
                r
            }),
        ] {
            let err = parse_publish_request(req).expect_err("v1 fee fields forbidden");
            assert_eq!(err.code, KernelErrorCode::MalformedRequest);
            assert!(err.public_message.contains(field));
        }
    }

    #[test]
    fn publish_request_rejects_missing_anchor_and_every_width_error() {
        let mut missing = base_publish_request();
        missing.block_anchor = None;
        let err = parse_publish_request(missing).expect_err("anchor required");
        assert!(err.public_message.contains("block_anchor is required"));

        for (field, req) in [
            ("public_key", {
                let mut r = base_publish_request();
                r.public_key = vec![0; 31];
                r
            }),
            ("r", {
                let mut r = base_publish_request();
                r.r = vec![0; 31];
                r
            }),
            ("s", {
                let mut r = base_publish_request();
                r.s = vec![0; 31];
                r
            }),
            ("r_prime", {
                let mut r = base_publish_request();
                r.r_prime = vec![0; 31];
                r
            }),
            ("block_anchor.block_hash", {
                let mut r = base_publish_request();
                r.block_anchor.as_mut().unwrap().block_hash = vec![0; 31];
                r
            }),
        ] {
            let err = parse_publish_request(req).expect_err("publish width");
            assert_eq!(err.code, KernelErrorCode::MalformedRequest);
            assert!(err.public_message.contains(field), "{}", err.public_message);
        }
    }

    #[test]
    fn publish_outcome_projection_covers_accepted_and_rejected() {
        let accepted = publish_outcome_to_proto(PublishOutcome::Accepted { batch_eta: 17 });
        assert!(accepted.accepted);
        assert_eq!(accepted.reason, None);
        assert_eq!(accepted.batch_eta, Some(17));

        let rejected = publish_outcome_to_proto(PublishOutcome::Rejected {
            reason: PublishRejectReason::AnchorStale,
        });
        assert!(!rejected.accepted);
        assert_eq!(rejected.reason.as_deref(), Some("anchor_stale"));
        assert_eq!(rejected.batch_eta, None);
    }

    #[test]
    fn entrust_and_revoke_conversions_cover_success_and_width_failures() {
        let entrust = parse_entrust_request(ProtoEntrustRequest {
            nonce: vec![0x11; 32],
            subject: receive_subject_bech32(),
            bundle: vec![1, 2, 3],
            chan_bind: vec![0x12; 32],
        })
        .expect("entrust");
        assert_eq!(entrust.subject, SubjectAddress([0xA1; 32]));
        assert_eq!(entrust.nonce, [0x11; 32]);
        assert_eq!(entrust.chan_bind, ChanBind([0x12; 32]));
        assert_eq!(entrust.bundle_bytes, vec![1, 2, 3]);
        assert!(entrust_result_to_proto(EntrustResult { accepted: true }).accepted);

        for (field, req) in [
            ("nonce", ProtoEntrustRequest {
                nonce: vec![0; 31],
                subject: receive_subject_bech32(),
                bundle: vec![],
                chan_bind: vec![0; 32],
            }),
            ("chan_bind", ProtoEntrustRequest {
                nonce: vec![0; 32],
                subject: receive_subject_bech32(),
                bundle: vec![],
                chan_bind: vec![0; 31],
            }),
        ] {
            let err = parse_entrust_request(req).expect_err("entrust width");
            assert!(err.public_message.contains(field));
        }

        let revoke = parse_revoke_request(ProtoRevokeRequest {
            nonce: vec![0x21; 32],
            subject: receive_subject_bech32(),
            chan_bind: vec![0x22; 32],
        })
        .expect("revoke");
        assert_eq!(revoke.subject, SubjectAddress([0xA1; 32]));
        assert_eq!(revoke.nonce, [0x21; 32]);
        assert_eq!(revoke.chan_bind, ChanBind([0x22; 32]));
        assert!(revoke_result_to_proto(RevokeResult { revoked: true }).revoked);

        for (field, req) in [
            ("nonce", ProtoRevokeRequest {
                nonce: vec![0; 31],
                subject: receive_subject_bech32(),
                chan_bind: vec![0; 32],
            }),
            ("chan_bind", ProtoRevokeRequest {
                nonce: vec![0; 32],
                subject: receive_subject_bech32(),
                chan_bind: vec![0; 31],
            }),
        ] {
            let err = parse_revoke_request(req).expect_err("revoke width");
            assert!(err.public_message.contains(field));
        }
    }
}
