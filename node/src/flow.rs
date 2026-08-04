//! Mint / send / commit flow bodies extracted from the legacy
//! `mint_handler` / `send_coin_handler` / `commit_handler` route
//! handlers in `router.rs`. The Job-API refactor (PR1) moved every
//! synchronous route off the request thread and into a single-worker
//! background dispatcher (`job_dispatcher.rs`). Legacy prove-leg entry
//! points (`mint_flow` / `send_flow`) are gone — mint/send prove now
//! runs through `begin_v1_mint` / `begin_v1_send`. This module retains
//! admit-time validators plus residual commit legs
//! ([`commit_flow`], [`mint_commit_flow`]).
//!
//! ## Coverage scope
//!
//! This file is excluded from the 100% line / function coverage gate
//! via the CI `--ignore-filename-regex` flag (alongside `runtime.rs`,
//! `publisher.rs`, etc.). Rationale: the flow bodies own the
//! interaction between the publisher (outbound Bitcoin broadcasts) and
//! the database — a surface that is already proven correct by the
//! `mint_*` / `send_*` / `commit_*` integration tests in
//! `router_tests.rs` (driven through the `/api/jobs/*` admit handlers
//! + the dispatcher, end-to-end).

use crate::account_node::{AccountNode, CoinProof};
use crate::db;
use crate::publisher::create_and_broadcast_inscription;
use crate::router::{
    lock_or_recover, AppState, CommitRequest, MintRequest, ProofStore, SendCoinRequest,
};
use crate::NETWORK_CONFIG;
use axum::http::StatusCode;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use serde_json::json;
use shared::commitment::Commitment;
use shared::ProofData;
use std::sync::Arc;
use zkcoins_program::hash::digest_to_bytes;

/// Result of a flow: either a JSON body + 2xx status code, or a
/// (status, error_string) tuple that the dispatcher persists into the
/// row's `error` column + the wallet observes as the final terminal
/// status.
pub(crate) type FlowResult = Result<(serde_json::Value, u16), FlowError>;

/// Failure variant for a mint/send/commit flow. The status code is
/// surfaced to the wallet via `Job.response_status`; the message is
/// surfaced via `Job.error` and recorded in the job row.
#[derive(Debug, Clone)]
pub(crate) struct FlowError {
    pub status: StatusCode,
    pub message: String,
}

impl FlowError {
    pub fn new(status: StatusCode, msg: impl Into<String>) -> Self {
        Self {
            status,
            message: msg.into(),
        }
    }
}

/// The server-derived identity of a mint: the creator's owner address
/// (`H(creator_pubkey)`) and the derived `asset_id`. Both are computed
/// from the signed request, never taken from the wire. The job is
/// scoped to `owner`; `asset_id` is surfaced for callers that want to
/// log or echo the derived asset.
pub(crate) struct MintIdentity {
    pub owner: zkcoins_program::hash::HashDigest,
    #[allow(dead_code)]
    pub asset_id: zkcoins_program::types::AssetId,
}

/// Pre-flight validation of a creator-signed `MintRequest`. Runs in the
/// admit handler before the job is enqueued so a malformed or
/// unauthorised request returns 4xx/401 immediately rather than burning
/// a job row. Mirrors [`validate_send_request`]: timestamp window first
/// (so a stale clock surfaces distinctly), then the BIP-340 Schnorr
/// signature over the mint fields.
///
/// Returns the DERIVED [`MintIdentity`] on success — the owner and
/// asset_id are computed from `creator_pubkey` + `name` + `decimals`,
/// not accepted from the request body.
pub(crate) fn validate_mint_request(req: &MintRequest) -> Result<MintIdentity, FlowError> {
    if let Err(e) = crate::router::check_timestamp_window(req.timestamp) {
        tracing::info!("Mint timestamp window check failed: {}", e);
        return Err(FlowError::new(StatusCode::UNAUTHORIZED, e));
    }
    if let Err(e) = crate::router::verify_mint_signature_pub(req) {
        tracing::info!("Mint signature verification failed: {}", e);
        return Err(FlowError::new(
            StatusCode::UNAUTHORIZED,
            "Signature verification failed",
        ));
    }
    let creator_pubkey = req.creator_pubkey.serialize();
    // owner = protocol address H(Pk₀) = SHA-256(creator_pubkey) (#226),
    // consistent with the wallet/SDK address / username-claim / SMT.
    let owner = zkcoins_program::hash::sha256_to_digest(&creator_pubkey);
    let name_hash = zkcoins_program::types::calculate_name_hash(&req.name);
    let asset_id =
        zkcoins_program::types::calculate_asset_id(&creator_pubkey, &name_hash, req.decimals);
    Ok(MintIdentity { owner, asset_id })
}

/// Pre-flight validation of a `SendCoinRequest` body. The signature +
/// timestamp gates run here so the wallet observes a 401 from
/// `POST /api/jobs/send` before the job is enqueued, matching the
/// pre-refactor `send_coin_handler` behaviour.
pub(crate) fn validate_send_request(
    req: &SendCoinRequest,
) -> Result<([u8; 32], [u8; 32]), FlowError> {
    if req.signature.is_none() || req.timestamp.is_none() {
        return Err(FlowError::new(
            StatusCode::UNAUTHORIZED,
            "Missing signature",
        ));
    }
    let timestamp = req
        .timestamp
        .expect("timestamp presence checked immediately above");
    if let Err(e) = crate::router::check_timestamp_window(timestamp) {
        tracing::info!("Timestamp window check failed: {}", e);
        return Err(FlowError::new(StatusCode::UNAUTHORIZED, e));
    }
    if let Err(e) = crate::router::verify_send_signature_pub(req) {
        tracing::info!("Signature verification failed: {}", e);
        return Err(FlowError::new(
            StatusCode::UNAUTHORIZED,
            "Signature verification failed",
        ));
    }

    let from = hex::decode(req.account_address.trim_start_matches("0x")).map_err(|_| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "account_address is not valid hex",
        )
    })?;
    let to = hex::decode(req.recipient.trim_start_matches("0x")).map_err(|_| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "recipient is not valid hex",
        )
    })?;
    if from.len() != 32 || to.len() != 32 {
        return Err(FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "address must be 32 bytes (64 hex chars)",
        ));
    }
    let mut from_b = [0u8; 32];
    let mut to_b = [0u8; 32];
    from_b.copy_from_slice(&from);
    to_b.copy_from_slice(&to);
    Ok((from_b, to_b))
}

/// Extract the `account_state_hash` / `output_coins_root` a mint proof
/// commits, as lowercase hex (the digests the wallet signs). Shares the
/// `ProofData::from_field_elements` path with [`send_commit_hashes`].
pub(crate) fn mint_proof_commit_hashes(proof: &zkcoins_prover::Proof) -> SendCommitHashes {
    let pis: [zkcoins_program::F; zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] =
        proof.public_inputs[..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
            .try_into()
            .expect("Plonky2 Proof emits N_PROOF_DATA_PUBLIC_INPUTS field elements");
    let proof_data = ProofData::from_field_elements(&pis);
    SendCommitHashes {
        account_state_hash: hex::encode(digest_to_bytes(&proof_data.account_state_hash)),
        output_coins_root: hex::encode(digest_to_bytes(&proof_data.output_coins_root)),
    }
}

/// Drive the COMMIT leg of a two-phase mint (phase 2): verify the
/// creator's signed `Commitment`, ENFORCE the off-circuit creator
/// binding (`commitment.public_key == staged.creator_pubkey`), broadcast
/// the inscription, advance global state, swap the minted account in,
/// and register the asset_id -> creator_pubkey row.
///
/// CREATOR BINDING (MULTI_ASSET.md §5.3): the per-asset creator binding
/// lives off-circuit now (the mint rotates `next_public_key`, so it can
/// no longer ride on the commitment key). Requiring the commitment's
/// signing key to equal the creator key the prove leg derived owner /
/// asset_id from makes the on-chain commitment provably signed by the
/// asset's creator. Without it, a forger could witness `owner =
/// H(victim_pk)` + a victim's asset_id (public values) and sign with
/// their OWN key, forging inflation / theft of a foreign asset.
pub(crate) async fn mint_commit_flow(state: &AppState, request: CommitRequest) -> FlowResult {
    // Gap G4: under a v1.1 process claim the residual ash‖ocr Commitment
    // path is refused. TransitionSignature authorisation goes through
    // `POST /api/jobs/{id}/sign` → `v1::accept_wallet_transition_signature`
    // against the staged pending transition.
    if let Err(e) = crate::v1::refuse_legacy_commitment_under_v1() {
        return Err(FlowError::new(StatusCode::CONFLICT, e.to_string()));
    }

    let staged = match state.mint_store.take(request.proof_id) {
        Some(s) => s,
        None => {
            return Err(FlowError::new(
                StatusCode::NOT_FOUND,
                "Unknown or expired mint proof_id",
            ));
        }
    };

    let message_bytes = hex::decode(&request.message).map_err(|_| {
        FlowError::new(StatusCode::UNPROCESSABLE_ENTITY, "message is not valid hex")
    })?;
    let sig_bytes = hex::decode(&request.signature).map_err(|_| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "signature is not valid hex",
        )
    })?;
    let signature = SchnorrSignature::from_slice(&sig_bytes).map_err(|_| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "signature is not a valid Schnorr signature",
        )
    })?;

    let commitment = Commitment {
        public_key: request.public_key,
        signature,
        message: message_bytes,
    };

    // 1. Self-attested signature check.
    if !commitment.verify() {
        return Err(FlowError::new(
            StatusCode::UNAUTHORIZED,
            "Commitment signature invalid",
        ));
    }

    // 2. OFF-CIRCUIT CREATOR BINDING — the wallet-signed commitment
    //    must be signed by the asset creator's key. MANDATORY for mint.
    //    `staged.creator_pubkey` is the key the prove leg derived owner
    //    and asset_id from; binding the commitment key to it makes the
    //    on-chain commitment provably signed by the asset's creator.
    if commitment.public_key != staged.creator_pubkey {
        return Err(FlowError::new(
            StatusCode::UNAUTHORIZED,
            "Commitment must be signed by the asset creator's key",
        ));
    }

    // 3. BROADCAST phase.
    let commitment_data = bincode::serialize(&commitment).expect("Failed to serialize commitment");
    let broadcast_outcome = create_and_broadcast_inscription(
        &commitment_data,
        crate::db::InscriptionKind::Mint,
        &state.esplora_config,
        Some(&state.pool),
    )
    .await;
    let commit_txid_bytes: [u8; 32] = match broadcast_outcome {
        Ok((commit_txid, _reveal_txid)) => {
            use bitcoin::hashes::Hash as _;
            commit_txid.to_byte_array()
        }
        Err(err) => {
            eprintln!("Error broadcasting mint inscription: {}", err);
            return Err(FlowError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "Failed to broadcast mint inscription on-chain",
            ));
        }
    };

    // 4. STATE_ADVANCE phase.
    let state_advance_outcome = {
        let state_arc_for_advance = {
            let guard = lock_or_recover(&state.account_node);
            guard.state().clone()
        };
        let mut state_guard = lock_or_recover(&state_arc_for_advance);
        state_guard.update_and_snapshot_for_persist(std::slice::from_ref(&commitment))
    };
    let (new_root, smt_bytes, mmr_bytes, root_index_entry) = match state_advance_outcome {
        Ok(snapshot) => snapshot,
        Err(e) => {
            eprintln!(
                "mint_commit_flow: in-process state.update failed: {} (broadcast already landed; scanner-replay will reconcile)",
                e
            );
            return Err(FlowError::new(
                StatusCode::SERVICE_UNAVAILABLE,
                "mint broadcast landed on chain but in-process state advance failed; scanner will reconcile",
            ));
        }
    };
    let root_index_ref = root_index_entry.as_ref().map(|(p, s, i)| (p, s, *i as u64));
    if let Err(e) = db::persist_state_and_mark_complete_tx(
        &state.pool,
        &smt_bytes,
        &mmr_bytes,
        root_index_ref,
        &commit_txid_bytes,
    )
    .await
    {
        eprintln!(
            "mint_commit_flow: atomic persist + mark-complete failed: {} (scanner-replay will heal)",
            e
        );
        return Err(FlowError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "mint broadcast landed on chain but durable state advance failed; scanner will reconcile",
        ));
    }
    println!(
        "mint_commit_flow: state.update persisted + row marked complete. New MMR root: {}",
        hex::encode(digest_to_bytes(&new_root))
    );

    // 5. APPLY phase — swap the minted creator account in, persist it.
    let owner = staged.owner;
    let asset_id = staged.asset_id;
    let signer = commitment.public_key;
    let account_bytes = {
        let mut guard = lock_or_recover(&state.account_node);
        guard.commit_mint(owner, staged.mutated_account, signer);
        guard
            .get_account(&owner, &asset_id)
            .map(AccountNode::serialize_account)
    };
    if let Some(bytes) = account_bytes {
        let key_bytes = crate::account_node::account_key_bytes(&owner, &asset_id);
        if let Err(e) =
            db::upsert_account_with_source(&state.pool, &key_bytes, &bytes, "mint").await
        {
            eprintln!("Failed to upsert minted creator account: {}", e);
        }
    }

    // Record the off-circuit creator binding (MULTI_ASSET.md §5.3) so a
    // later mint of the same asset_id by a different key is rejected.
    // Log-and-continue on error, like the sibling account upsert.
    if let Err(e) = db::register_asset_creator(
        &state.pool,
        &digest_to_bytes(&asset_id),
        &staged.creator_pubkey.serialize(),
    )
    .await
    {
        eprintln!("Failed to register asset creator: {}", e);
    }

    let hashes = mint_proof_commit_hashes(&staged.proof);
    Ok((
        json!({
            "success": true,
            "proof_id": request.proof_id,
            "account_state_hash": hashes.account_state_hash,
            "output_coins_root": hashes.output_coins_root,
        }),
        200,
    ))
}

/// Hashes the wallet must sign to authorise a `send`, derived from the
/// send proof's public inputs.
///
/// A thin pure-TypeScript wallet cannot decode the binary bincode
/// `CoinProof` that `GET /api/proof/{id}` serves, so the dispatcher
/// surfaces these two digests as lowercase hex on the
/// `awaiting_signature` job result instead — the same `account_state_hash`
/// / `output_coins_root` hex the `mint` and `commit` completed results
/// already carry. The wallet signs `SHA256(serialize(ash) ‖ serialize(ocr))`
/// over them (see CONTRIBUTING "Trust model"). Bit-identical to the
/// extraction in [`mint_proof_commit_hashes`] / [`commit_flow`] so the
/// value the wallet signs matches what `commit_flow` re-derives from
/// the same proof.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SendCommitHashes {
    /// `account_state_hash`, 32-byte digest as 64 lowercase hex chars.
    pub account_state_hash: String,
    /// `output_coins_root`, 32-byte digest as 64 lowercase hex chars.
    pub output_coins_root: String,
}

/// Extract `account_state_hash` + `output_coins_root` as lowercase hex
/// from a coin proof's Plonky2 public inputs.
///
/// Reuses the exact `ProofData::from_field_elements` path the
/// `mint`/`commit` completed results use (and the `api_remote`
/// `ash_ocr_from_send_proof` test helper mirrors), so the hex written
/// onto the `awaiting_signature` result is byte-for-byte the value the
/// wallet's `createCommitment` expects and `commit_flow` re-derives.
pub(crate) fn send_commit_hashes(proof: &CoinProof) -> SendCommitHashes {
    let pis: [zkcoins_program::F; zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS] =
        proof.proof.public_inputs[..zkcoins_program::circuit::main::N_PROOF_DATA_PUBLIC_INPUTS]
            .try_into()
            .expect("Plonky2 Proof emits N_PROOF_DATA_PUBLIC_INPUTS field elements");
    let proof_data = ProofData::from_field_elements(&pis);
    SendCommitHashes {
        account_state_hash: hex::encode(digest_to_bytes(&proof_data.account_state_hash)),
        output_coins_root: hex::encode(digest_to_bytes(&proof_data.output_coins_root)),
    }
}

/// Parse + verify a `CommitRequest` and then broadcast the commitment
/// inscription on chain. Drives the second half of the `send` job
/// lifecycle: the dispatcher invokes this when the wallet has
/// signalled the `Notify` channel attached to a job that is currently
/// `awaiting_signature`.
///
/// Under a v1.1 process claim this entry refuses loud — the residual
/// ash‖ocr Commitment is the wrong signing protocol. The v1.1 path
/// authorises via `POST /api/jobs/{id}/sign` →
/// [`crate::v1::accept_wallet_transition_signature`] against the staged
/// pending transition.
pub(crate) async fn commit_flow(state: &AppState, request: CommitRequest) -> FlowResult {
    // Gap G4: refuse legacy Commitment under ScanStackMode::V1.
    if let Err(e) = crate::v1::refuse_legacy_commitment_under_v1() {
        return Err(FlowError::new(StatusCode::CONFLICT, e.to_string()));
    }

    let coin_proof = match state.proof_store.get_proof(request.proof_id) {
        Some(p) => p,
        None => {
            return Err(FlowError::new(StatusCode::NOT_FOUND, "Unknown proof_id"));
        }
    };

    let message_bytes = hex::decode(&request.message).map_err(|_| {
        FlowError::new(StatusCode::UNPROCESSABLE_ENTITY, "message is not valid hex")
    })?;
    let sig_bytes = hex::decode(&request.signature).map_err(|_| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "signature is not valid hex",
        )
    })?;
    let signature = SchnorrSignature::from_slice(&sig_bytes).map_err(|_| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "signature is not a valid Schnorr signature",
        )
    })?;

    let commitment = Commitment {
        public_key: request.public_key,
        signature,
        message: message_bytes,
    };

    if !commitment.verify() {
        return Err(FlowError::new(
            StatusCode::UNAUTHORIZED,
            "Commitment signature invalid",
        ));
    }

    let commitment_data = bincode::serialize(&commitment).expect("Failed to serialize commitment");
    if let Err(err) = create_and_broadcast_inscription(
        &commitment_data,
        crate::db::InscriptionKind::Send,
        &NETWORK_CONFIG,
        Some(&state.pool),
    )
    .await
    {
        eprintln!("Error broadcasting commit inscription: {}", err);
        return Err(FlowError::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "Failed to broadcast commitment inscription on-chain",
        ));
    }

    let mut updated_proof = coin_proof;
    updated_proof.commitment = Some(commitment);
    let hashes = send_commit_hashes(&updated_proof);
    let ash_hex = hashes.account_state_hash;
    let ocr_hex = hashes.output_coins_root;

    let recipient = updated_proof.coin.recipient;
    let asset_id = updated_proof.coin.asset_id;
    let snapshot: Option<Vec<u8>> = {
        let mut guard = lock_or_recover(&state.account_node);
        if let Err(e) = guard.receive_coin(updated_proof) {
            eprintln!("Failed to receive coin after commit: {}", e);
        }
        guard
            .get_account(&recipient, &asset_id)
            .map(AccountNode::serialize_account)
    };
    if let Some(bytes) = snapshot {
        let key_bytes = crate::account_node::account_key_bytes(&recipient, &asset_id);
        if let Err(e) =
            db::upsert_account_with_source(&state.pool, &key_bytes, &bytes, "receive").await
        {
            eprintln!("Failed to upsert account after commit: {}", e);
        }
    }

    Ok((
        json!({
            "success": true,
            "proof_id": request.proof_id,
            "account_state_hash": ash_hex,
            "output_coins_root": ocr_hex,
        }),
        200,
    ))
}

// Silence the unused-import lint when the module is compiled into a
// binary that does not pull every helper through the dispatcher path
// (e.g. a future feature gate that disables one of mint/send/commit).
#[allow(dead_code)]
fn _force_uses() {
    let _ = std::any::type_name::<Arc<ProofStore>>();
}
