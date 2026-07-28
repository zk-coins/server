//! v1 cutover Stages 1–3: exclusive NfLog / ComplianceProof stack.
//!
//! ## Stage 1–2 (historical)
//! Flag-gated shadow path behind `ZKCOINS_V1_SHADOW=1`. Proving remained
//! legacy until Stage 3.
//!
//! ## Stage 3 (current default)
//! Atomic switch: production binary always claims [`ScanStackMode::V1`].
//! Prove call sites → [`StateEngine`] / [`ProverBridge`]; scanner folds only
//! `AggregateStateNullifierV3`; [`Prover::new`] is not on the binary path.
//! Legacy code remains in the tree for Stage 4 deletion.
//!
//! ## G3 — Receive as a real transition
//! [`receive`] wires `begin_receive` → compliance proof → account apply
//! (NfLog **not** mutated) → persist intent → nullifier publish. The
//! scanner folds the own nullifier into the canonical NfLog at its real
//! §3.6 position on inclusion. Clause-10 creating-proof bindings are
//! mandatory per slot. The legacy `receive_coin_into` bookkeeping path is
//! refused under the v1.1 process claim (no silent fall-back).
//!
//! A commitment and an `AggregateStateNullifierV3` must never share one
//! accumulator or one database; see [`separation`].
//!
//! ## Public surface is orchestration, not raw sinks
//!
//! Raw publish / DB-write / adapter-mutation / scan-apply sinks are
//! `pub(crate)` (crate-private). Downstream crates see only capability-
//! carrying entry points: receive facade, scan apply orchestration, and
//! an opaque [`V1Publisher`] from connect/env. The foreign publisher type
//! never leaves the package; assembling a durable effect from raw parts is
//! a compile error — see the `downstream-boundary` package
//! (`sealed_plumbing_compile_fail_matrix`).
//!
//! ## Gap G4 — transition signature
//! Behind the same flag, wallet authorisation is a §3.2
//! [`TransitionSignature`](zkcoins_prover::prover_bridge::TransitionSignature)
//! (BIP-340 + sign-to-contract over the full canonical `serialize(ProofData)`),
//! verified by [`signature`]. The finalise-path entry takes a
//! [`PendingTransition`](zkcoins_prover::state_engine::PendingTransition) and
//! derives `pk_i` / `ProofData` from it so provenance cannot be decorative.
//! Residual ash‖ocr [`shared::commitment::Commitment`] is refused under a
//! v1.1 process claim ([`refuse_legacy_commitment_under_v1`]); with the
//! flag off the legacy path is untouched.
//!
//! Production caller: flag-gated `POST /v1/jobs/{id}/sign` (§7.5) decodes
//! [`WalletSignSubmission`] at the boundary and verifies via
//! [`accept_wallet_transition_signature`] against a staged
//! [`PendingSignEntry`]. Under a v1.1 claim, `awaiting_signature` advertises
//! the §7.5 ProofData surface (not legacy ash/ocr). An accepted signature
//! is driven into [`StateEngine::finalise`](zkcoins_prover::state_engine::StateEngine::finalise)
//! rather than short-circuited to a status change.
//!
//! ## Gap G7 — re-mint into existing asset accounts
//! [`mint`] exposes the process-claim-gated entry for token-standard-1
//! re-issuance via
//! [`StateEngine::begin_mint`](zkcoins_prover::state_engine::StateEngine::begin_mint)
//! (AccountUpdateProof + `asset_issuance`). The gate is the boot-time
//! [`ScanStackMode::V1`] process claim (from `ZKCOINS_V1_SHADOW=1`) —
//! same registry as publisher / NfLog policy — not a caller-selected mode
//! label. Token-standard-2 re-mint and over-cap mints are refused naming
//! §6.5 clauses (f)/(e). Legacy `prepare_mint` remint refusal is
//! unchanged with the flag off.
//!
//! ## Gap G9 — source provenance (CoinHist / creating proof)
//! Under the v1.1 claim, spend provenance is
//! [`InputAuthorization`](zkcoins_prover::prover_bridge::InputAuthorization)
//! (CoinHist leaf `Admitted` + `creating_prev_ash` / `coin_index`); receive
//! provenance is
//! [`ReceivedAuthorization`](zkcoins_prover::prover_bridge::ReceivedAuthorization)
//! (creating proof + clause-10 bindings). The legacy
//! `InCoinSourceWitness` + source-aggregator path is refused on residual
//! [`crate::account_node::AccountNode::send_coins`]
//! ([`refuse_legacy_send_under_v1`]) and is unrepresentable on
//! [`begin_v1_send`] (no parameter, no field). See [`provenance`].

mod adapter;
pub mod attest;
pub mod db_v1;
pub mod mint;
pub mod mode;
pub mod provenance;
pub mod publish;
pub mod receive;
pub mod scan;
pub mod self_heal;
pub mod separation;
pub mod signature;
// Stage 3 atomic-switch properties (compile/source + load-path pins).
#[cfg(test)]
mod stage3;

pub use adapter::EngineAdapter;
pub use attest::{
    accept_attestation_for_network, accept_c_balance_network_binding, authorise_attest_balance,
    completed_attest_result, encode_c_balance_proof_bytes, ensure_v1_attest_path,
    issue_attest_challenge, networks_have_distinct_c_balance_pins, parse_u64_decimal,
    pinned_c_balance_digest, prove_attestation_for_job, public_hosts_from_env,
    require_completed_anchor, require_resolved_anchor, serialize_balance_attestation,
    serialize_balance_attestation_v1, unix_now, v1_attest_route_active, AttestBalanceRequest,
    AttestChallengeMap, AttestChallengeRequest, AttestError, AttestJobBody, U64Decimal,
    ATTEST_ANCHOR_LOCATOR_EDGE, ATTEST_BALANCE_CHALLENGE_DOMAIN, PINNED_C_BALANCE_DIGEST_MAINNET,
    PINNED_C_BALANCE_DIGEST_REGTEST, PINNED_C_BALANCE_DIGEST_TESTNET,
};
pub use mint::{begin_v1_mint, ensure_v1_mint_path, V1_MINT_SHADOW_OFF};
pub use mode::{
    parse_network_label, resolve_v1_shadow_mode, v1_shadow_mode_from_env, validate_v1_boot_pins,
    V1BootPins, V1ShadowMode, V1_BOOT_CONFIG_ERROR,
};
pub use provenance::{
    assert_receive_provenance_is_creating_proof, begin_v1_send, ensure_v1_provenance_path,
    refuse_legacy_send_under_v1, LEGACY_SEND_REFUSED_UNDER_V1, V1_PROVENANCE_SHADOW_OFF,
};
pub use publish::{connect_v1_publisher, v1_publisher_env_from_env, V1Publisher, V1PublisherEnv};
pub use receive::{
    commit_proved_receive, execute_v1_receive, finalise_publish_persist,
    refuse_legacy_receive_under_v1, resume_all_pending_publishes, resume_pending_publish,
    verify_and_begin_receive, verify_clause10_slot, verify_creating_nullifier_binding,
    ReceivedCoinSlot, V1ReceiveOutcome, V1ReceiveRequest, LEGACY_RECEIVE_REFUSED_UNDER_V1,
};
pub use scan::{
    apply_canonical_survivors, apply_forward_scan, first_boot_requires_full_replace,
    folded_keys_from_nflog_mirror, members_to_published, observation_tip_still_live,
    reconcile_persisted_tip, sort_canonical, FoldStats, MAX_RECOVERABLE_REORG_DEPTH,
    PersistedTipReconciliation, ResolvedBlock, TipReconcileOutcome,
};
pub use self_heal::{
    boot_canary, decode_v1_live_digest, encode_v1_live_digest, evaluate_v1_slow_canary,
    evaluate_v1_structural_canary, resolve_v1_live_digest,
    slow_canary_env_enabled, slow_canary_verify_transition, v1_canary_for_heal,
    V1CanaryNflogView, V1CanarySample, V1StructuralInputs, V1_DIGEST_TAG, V1_LIVE_DIGEST_LEN,
};
pub use separation::{
    claim_process_stack_from_shadow_mode, claim_process_stack_from_v1_shadow_env,
    enforce_stack_scan_mode, ensure_legacy_publisher_allowed, ensure_v1_publisher_allowed,
    legacy_scan_state_present, load_stack_scan_mode, process_stack_mode,
    require_stack_mode_for_update, require_v1_process_for_nflog_write, set_process_stack_mode,
    v1_scan_state_present, ScanStackMode, STACK_CAPABILITY_REFUSAL, STACK_SEPARATION_REFUSAL,
};
pub use signature::{
    accept_wallet_transition_signature, awaiting_signature_result_json, decode_job_error,
    durable_finalisation_with_signature, encode_job_error, ensure_completion_ready,
    ensure_finalise_ready, ensure_v1_signature_path, finalise_accepted_prove_outside_lock,
    finalise_accepted_prove_persist_and_stage, finalise_with_accepted_signature,
    legacy_awaiting_signature_result_json,
    publisher_pubkey_from_request_body, refuse_legacy_commitment_under_v1,
    register_live_pending_after_begin, rehydrate_pending_sign, select_awaiting_signature_result,
    sign_rejection, stage_pending_sign, strip_pending_sign_from_body,
    take_live_pending_after_begin, v1_sign_route_active, verify_transition_signature_material,
    DurableFinalisationPersist, FinaliseOutcome, PendingSignEntry, PendingSignMap, SignatureCheck,
    StagedSignPersist, TransitionSignatureError, WalletSignSubmission, WalletSignSubmissionWire,
    FINALISATION_BODY_KEY, LEGACY_COMMITMENT_REFUSED_UNDER_V1, PENDING_SIGN_BODY_KEY,
};

#[cfg(test)]
pub use separation::claim_stack_scan_mode;

#[cfg(test)]
mod tests;
