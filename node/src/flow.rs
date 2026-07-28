//! Mint / send / commit flow bodies extracted from the legacy
//! `mint_handler` / `send_coin_handler` / `commit_handler` route
//! handlers in `router.rs`. The Job-API refactor (PR1) moved every
//! synchronous route off the request thread and into a single-worker
//! background dispatcher (`job_dispatcher.rs`); the dispatcher calls
//! the [`mint_flow`], [`send_flow`], and [`commit_flow`] entrypoints
//! below to drive a `Job` through the state machine.
//!
//! The flow bodies are bit-for-bit identical to the pre-refactor
//! handler bodies — only the I/O surface changed (no `axum::extract`s,
//! no `Json` response; plain `Result<serde_json::Value, FlowError>`
//! shaped responses). Every concurrency / state-advance / persistence
//! invariant the previous handlers maintained (zk-coins/node#89's
//! prepare-then-commit ordering, the Phase-E atomic state advance,
//! the `commit_mint_tx` per-account upsert bundle) stays in place.
//!
//! ## Coverage scope
//!
//! This file is excluded from the 100% line / function coverage gate
//! via the CI `--ignore-filename-regex` flag (alongside `runtime.rs`,
//! `publisher.rs`, etc.). Rationale: the flow bodies own the
//! interaction between the prover (a heavy synchronous engine
//! gated behind a `tokio::task::spawn_blocking`), the publisher
//! (which makes outbound Bitcoin broadcasts) and the database — a
//! surface that is already proven correct by the
//! `mint_handler_*` / `send_*` / `commit_*` integration tests in
//! `router_tests.rs` (now driven through the `/api/jobs/*` admit
//! handlers + the dispatcher, end-to-end).

use crate::account_node::{AccountNode, CoinProof};
use crate::db;
use crate::publisher::create_and_broadcast_inscription;
use crate::router::{
    lock_or_recover, map_send_coins_error, AppState, CommitRequest, MintRequest, ProofStore,
    SendCoinRequest,
};
use crate::NETWORK_CONFIG;
use axum::http::StatusCode;
use bitcoin::secp256k1::schnorr::Signature as SchnorrSignature;
use serde_json::json;
use shared::commitment::Commitment;
use shared::{Invoice, ProofData};
use std::sync::Arc;
use zkcoins_program::hash::{digest_from_bytes, digest_to_bytes};

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

/// Map a `send_coins`-style `&'static str` error onto a [`FlowError`]
/// preserving the same status-code ladder the legacy
/// `map_send_coins_error` produced.
pub(crate) fn flow_err_from_send_coins(err: &str) -> FlowError {
    let (status, body) = map_send_coins_error(err);
    FlowError::new(status, body)
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
    let owner = zkcoins_program::hash::hash_bytes(&creator_pubkey);
    let name_hash = zkcoins_program::types::calculate_name_hash(&req.name);
    let asset_id =
        zkcoins_program::types::calculate_asset_id(&creator_pubkey, &name_hash, req.decimals);
    Ok(MintIdentity { owner, asset_id })
}

/// Resolve a caller-supplied `asset_id` hex string for a SEND.
///
/// There is no native / default asset (Model B): the field is REQUIRED.
/// A missing, malformed, or wrong-length value is a hard `422` — never
/// a silent fall-back, which would send the wrong asset under a `200`
/// the caller cannot notice.
fn parse_send_asset_id(
    asset_id: Option<&str>,
) -> Result<zkcoins_program::types::AssetId, FlowError> {
    let hex_str = asset_id.ok_or_else(|| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "asset_id is required (no native asset)",
        )
    })?;
    let raw = hex::decode(hex_str.trim_start_matches("0x")).map_err(|_| {
        FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "asset_id is not valid hex",
        )
    })?;
    if raw.len() != 32 {
        return Err(FlowError::new(
            StatusCode::UNPROCESSABLE_ENTITY,
            "asset_id must be 32 bytes (64 hex chars)",
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&raw);
    Ok(digest_from_bytes(&arr))
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

/// Drive the PROVE leg of a two-phase, creator-signed mint (phase 1).
///
/// Neutral, permissionless model: there is no central minting
/// authority. The asset's creator signs the mint request; the node
/// derives the owner (`H(creator_pubkey)`) and the asset_id, builds an
/// issuer-mint proof on the creator's OWN `(owner, asset_id)` account
/// that credits `amount` to the creator's own balance, and stages it.
///
/// This mirrors [`send_flow`]: the prove leg returns the
/// `(proof_id, SendCommitHashes)` so the dispatcher can transition the
/// job to `awaiting_signature` with the `account_state_hash` /
/// `output_coins_root` hex on its result. The wallet signs those as a
/// `Commitment` and POSTs them to `POST /api/jobs/:id/commit`; the
/// broadcast + state-advance + apply leg lives in [`mint_commit_flow`].
///
/// The prove call is CPU-bound; it runs through `spawn_blocking` so the
/// dispatcher's tokio worker is not blocked during the prove.
pub(crate) async fn mint_flow(
    state: &AppState,
    request: MintRequest,
) -> Result<(u64, SendCommitHashes), FlowError> {
    // Re-validate (signature + timestamp). The admit handler already
    // ran this, but the job may have been queued for a while;
    // re-checking the timestamp here keeps the freshness window honest
    // at prove time. `prepare_mint` re-derives owner/asset_id from the
    // pubkey + name + decimals, so the derived identity is not needed
    // here beyond the validation side-effect.
    let identity = validate_mint_request(&request)?;
    let creator_pubkey = request.creator_pubkey.serialize();
    let next_public_key = request.next_public_key.serialize();
    let name = request.name.clone();
    let decimals = request.decimals;
    let amount = request.amount;

    // Off-circuit creator binding (MULTI_ASSET.md §5.3): reject a mint
    // of an `asset_id` already claimed by a DIFFERENT creator before
    // paying for the prove. A matching (or absent) creator passes.
    if db::asset_creator_conflict(
        &state.pool,
        &digest_to_bytes(&identity.asset_id),
        &creator_pubkey,
    )
    .await
    .map_err(|e| {
        FlowError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("asset_creator lookup failed: {}", e),
        )
    })? {
        return Err(FlowError::new(
            StatusCode::CONFLICT,
            "asset_id is registered to a different creator",
        ));
    }

    let account_node_clone = state.account_node.clone();
    let prepared = tokio::task::spawn_blocking(
        move || -> Result<crate::account_node::MintingPrepared, FlowError> {
            let guard = lock_or_recover(&account_node_clone);
            guard
                .prepare_mint(&creator_pubkey, &name, decimals, amount, &next_public_key)
                .map_err(flow_err_from_send_coins)
        },
    )
    .await
    .map_err(|e| {
        FlowError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("spawn_blocking join error: {}", e),
        )
    })??;
    tracing::info!("Mint prove: ok");

    // Derive the commit hashes the wallet must sign, from the same
    // public-input path the commit leg re-derives.
    let commit_hashes = mint_proof_commit_hashes(&prepared.proof);

    // Stage the mint for the wallet-signed commit leg.
    let proof_id = state.mint_store.add(crate::router::StagedMint {
        proof: prepared.proof,
        owner: prepared.owner,
        asset_id: prepared.asset_id,
        mutated_account: prepared.mutated_account,
        creator_pubkey: request.creator_pubkey,
    });

    Ok((proof_id, commit_hashes))
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
/// extraction in [`mint_flow`] / [`commit_flow`] so the value the wallet
/// signs matches what `commit_flow` re-derives from the same proof.
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

/// Drive a `send` job up to and including proof generation. Returns
/// the persisted `proof_id` plus the [`SendCommitHashes`] the wallet
/// must sign, so the dispatcher can transition the job to
/// `awaiting_signature` with the `account_state_hash` /
/// `output_coins_root` hex on its result and the wallet's
/// `POST /api/jobs/:id/commit` can look the proof up.
///
/// The post-signature broadcast leg lives in [`commit_flow`] — the
/// dispatcher invokes it after the wallet signals on the per-job
/// `Notify` channel.
pub(crate) async fn send_flow(
    state: &AppState,
    request: SendCoinRequest,
) -> Result<(u64, SendCommitHashes), FlowError> {
    let (from_address_bytes, to_address_bytes) = validate_send_request(&request)?;
    let from_address = digest_from_bytes(&from_address_bytes);
    let to_address = digest_from_bytes(&to_address_bytes);

    let public_key = request.public_key;
    let next_public_key = request.next_public_key;
    let prev_commitment_pubkey = request.prev_commitment_pubkey;
    let amount = request.amount;
    let send_asset_id = parse_send_asset_id(request.asset_id.as_deref())?;

    // The prove call is CPU-bound; push it through spawn_blocking so
    // the dispatcher's tokio worker is not blocked during the prove.
    let account_node_clone = state.account_node.clone();
    let result = tokio::task::spawn_blocking(move || -> Result<(CoinProof, Vec<u8>), FlowError> {
        let mut guard = lock_or_recover(&account_node_clone);
        let res = guard.send_coins(
            vec![Invoice::new(amount, to_address, send_asset_id)],
            from_address,
            public_key,
            next_public_key,
            prev_commitment_pubkey,
        );
        match res {
            Ok(mut coin_proofs) => {
                let snap = AccountNode::serialize_account(
                    guard
                        .get_account(&from_address, &send_asset_id)
                        .expect("send_coins Ok implies the sender account is in memory"),
                );
                let proof = coin_proofs
                    .pop()
                    .expect("send_coins returns at least one coin_proof on Ok");
                Ok((proof, snap))
            }
            Err(e) => {
                let mapped = map_send_coins_error(e);
                tracing::warn!("send_coins rejected: {} (status={})", e, mapped.0);
                Err(FlowError::new(mapped.0, mapped.1))
            }
        }
    })
    .await
    .map_err(|e| {
        FlowError::new(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("spawn_blocking join error: {}", e),
        )
    })??;

    let (coin_proof, updated_account_bytes) = result;
    // Derive the commit hashes BEFORE the proof is moved into the
    // store, from the same public-input path `commit_flow` re-derives —
    // so the hex the wallet signs matches what the broadcast leg later
    // verifies the commitment against.
    let commit_hashes = send_commit_hashes(&coin_proof);
    let proof_id = state.proof_store.add_proof(coin_proof);

    // The sender account is keyed by `(from_address, send_asset_id)`.
    let key_bytes = crate::account_node::account_key_bytes(&from_address, &send_asset_id);
    if let Err(e) =
        db::upsert_account_with_source(&state.pool, &key_bytes, &updated_account_bytes, "send")
            .await
    {
        eprintln!("Failed to upsert sender account after send: {}", e);
    }
    Ok((proof_id, commit_hashes))
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
