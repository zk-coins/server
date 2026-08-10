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
//! `InCoinSourceWitness` + source-aggregator path is unrepresentable on
//! [`begin_v1_send`] (no parameter, no field); residual legacy send prove
//! entries have been removed. See [`provenance`].

mod adapter;
// Orchestration modules: no public items of their own. External edge
// reaches only curated re-exports on `node::v1` (and the few modules
// below that still carry binary/boot types). Compile-fail matrices that
// name sealed sinks via `node::v1::{mint,provenance}::…` still fail
// (module is private).
pub(crate) mod attest;
/// Independent, trustless §5.7 `BalanceAttestationV1` verify (decode + host checks).
pub mod attest_verify;
/// Blossom blob-store client (§7.4): content-addressed fetch/upload against
/// an untrusted peer. Append-only (no DELETE; data permanence).
pub(crate) mod blossom;
/// Durable `v1_decrypt_index` (migration 0031) — SQL half of the private-record catalog.
pub(crate) mod db_decrypt_index;
/// Durable `v1_delivery_outbox` (migration 0032) — mesh delivery state machine.
pub(crate) mod db_outbox;
/// Durable `v1_sdr_phase_a` (migration 0033) — §4.2 SDR Phase-A staging.
pub(crate) mod db_sdr;
/// Durable local self-delivery catalog (migration 0036), without invented ACK fields.
pub(crate) mod db_self_delivery_index;
/// Durable open Class-B `asset_id → IssuanceTerms` store (migration 0037).
pub(crate) mod db_token_provenance;
pub mod db_v1;
/// §4.2 send-path delivery: finished transition → gift-wrapped kind-1059.
/// Port pattern matches the nullifier publisher; kernel stays transport-free.
pub(crate) mod delivery;
/// §4.4 note discovery → §2.3.3 verify → durable index → §4.2 ACK.
pub(crate) mod incoming;
pub(crate) mod mint;
pub mod mode;
/// Nostr transport primitives (NIP-01, NIP-44 v2, NIP-59, kinds 1420/1421,
/// relay client, kind-0 profile resolution + `Invoice`). Crate-private:
/// public-surface allowlists stay still; kernel stays transport-free.
/// Delivery path: [`delivery`] (post-persist mesh send).
/// Receive path: [`incoming`] (scan → verify → durable index → ACK).
/// Kind 30423 bootstrap mirror is unit-tested only until a production
/// Nostr discovery caller exists.
pub(crate) mod nostr;
/// Versioned rebuild material for durable outbox rows.
pub(crate) mod outbox_material;
/// §4.5 emergency recovery (node-side steps 3–5 only): gapless kind-1059
/// scan over seed relays, re-verify via existing §2.3.3 checks, decrypt-index
/// fill. Dense account enumeration (step 1) is wallet-side — SPEND branch
/// `A/0'/i'` never leaves the wallet (§1.2 / §7.7); see module docs.
pub(crate) mod recovery;
/// §4.2 SelfDeliveryRecordV1 two-phase finalisation (Phase A stage + Phase B scanner hook).
pub(crate) mod sdr;
/// Production CSPRNG for mesh delivery / NIP-59 (runtime boot).
pub(crate) use nostr::nip59::OsSecureRandom;
pub(crate) mod provenance;
pub mod publish;
pub mod receive;
/// Clause-10 slot reconstitution from `fold_coin_ids` + private index + live NfLog.
pub(crate) mod reconstitute;
pub mod scan;
pub mod self_heal;
// Crate-private: external edge names only the curated re-exports below
// (`ScanStackMode`, `enforce_stack_scan_mode`,
// `claim_process_stack_from_v1_shadow_env`). Process-control helpers
// (`set_process_stack_mode`, `process_stack_mode`, …) must not be
// reachable as `node::v1::separation::…`.
pub(crate) mod separation;
pub(crate) mod signature;
// Stage 3 atomic-switch properties (compile/source + load-path pins).
#[cfg(test)]
mod stage3;

// Public re-exports: binary boot / scanner / resume edge only.
// Crate-internal orchestration (router, hooks) uses `pub(crate) use`.
// Compile-fail matrices name sealed sinks via module paths; private
// items fail at the package edge as intended.
//
// `pub(crate) use` lists only names referenced as `crate::v1::…` from
// non-test production code. Test-only convenience re-exports live under
// `#[cfg(test)]` below so the lib target stays free of unused-import
// noise. Names that neither production nor tests reach via `crate::v1::`
// are not re-exported — callers use the defining submodule path.
pub use adapter::EngineAdapter;
pub(crate) use attest::{
    authorise_attest_balance, completed_attest_result, issue_attest_challenge,
    prove_attestation_for_job, public_hosts_from_env, serialize_balance_attestation, unix_now,
    v1_attest_route_active, AttestBalanceRequest, AttestChallengeMap, AttestChallengeRequest,
    AttestError, AttestJobBody, U64Decimal, ATTEST_BALANCE_CHALLENGE_DOMAIN,
};
// Delivery port + process-local stores used from `runtime` as `crate::v1::…`.
// Request/report types and `DeliveryTarget` stay on the defining module path
// (`crate::v1::delivery::…` / signature).
//
// `DeliveryTargetStore` + `PaymentInvoice` are **public**: the API/SDK layer
// (other repo) may still insert a verified §4.3 Invoice directly. The
// in-crate production caller is now `SubmitTransition` (§7.5
// `OutputTemplate.delivery` → verified insert after the kernel checklist).
pub use delivery::DeliveryTargetStore;
pub(crate) use delivery::{MeshDeliveryPort, OutgoingDeliveryPort, PendingDeliveryStore};
/// §4.4 receive poll used from `runtime`.
pub(crate) use incoming::poll_incoming_deliveries;
/// Kernel-API (§7.5): gRPC mint begin — process-claim-gated orchestration.
pub use mint::begin_v1_mint;
pub use mode::{
    v1_boot_pins_from_env, v1_shadow_mode_from_env, verifier_cache_role_from_env, V1BootPins,
    V1ShadowMode, VerifierCacheRole,
};
/// §4.3 amount-specific Invoice for [`DeliveryTargetStore::insert_verified_invoice`].
pub use nostr::profile::PaymentInvoice;
/// Kernel-API (§7.5): gRPC send begin — CoinHist provenance orchestration.
pub use provenance::begin_v1_send;
pub use publish::{connect_v1_publisher, v1_publisher_env_from_env, V1Publisher, V1PublisherEnv};
pub(crate) use receive::refuse_legacy_receive_under_v1;
pub use receive::resume_all_pending_publishes;
/// Kernel-API (§7.5): gRPC receive orchestration (begin / finalise / commit /
/// one-shot / single-row resume) and request/outcome types.
pub use receive::{
    commit_proved_receive, execute_v1_receive, finalise_publish_persist, resume_pending_publish,
    verify_and_begin_receive, PublishedBatchSummary, ReceivedCoinSlot, V1ReceiveOutcome,
    V1ReceiveRequest,
};
// Production receive path calls `crate::v1::reconstitute::…` directly
// (`reconstitute_receive_slots_locked` in the job dispatcher). Only the
// error type is re-exported on the facade for `crate::v1::ReconstituteError`.
pub(crate) use reconstitute::ReconstituteError;
pub use scan::{
    apply_canonical_survivors, apply_forward_scan, first_boot_requires_full_replace,
    folded_keys_from_nflog_mirror, observation_tip_still_live, reconcile_persisted_tip,
    record_scanned_block_hashes, FoldStats, PersistedTipReconciliation, ResolvedBlock,
    TipReconcileOutcome,
};
/// §4.2 Phase B: binary scan-loop hook after each NfLog fold.
pub use sdr::finalize_due_phase_b_adapter;
pub use self_heal::{resolve_v1_live_digest, secondary_boot_live_digest, v1_canary_for_heal};
pub use separation::{
    claim_process_stack_from_v1_shadow_env, enforce_stack_scan_mode, ScanStackMode,
};
pub(crate) use separation::{
    ensure_legacy_publisher_allowed, process_stack_mode, require_stack_mode_for_update,
};
// `FinaliseDeliveryDeps` is constructed in `runtime` via
// `crate::v1::signature::FinaliseDeliveryDeps` (not the v1 facade).
pub(crate) use signature::{
    accept_wallet_transition_signature, decode_job_error, encode_job_error,
    ensure_completion_ready, ensure_finalise_ready, finalise_accepted_prove_persist_and_stage,
    publisher_pubkey_from_request_body, refuse_legacy_commitment_under_v1, rehydrate_pending_sign,
    select_awaiting_signature_result, sign_rejection, stage_pending_sign,
    strip_pending_sign_from_body, take_live_pending_after_begin, v1_sign_route_active,
    DurableFinalisationPersist, WalletSignSubmissionWire, FINALISATION_BODY_KEY,
    PENDING_SIGN_BODY_KEY,
};
/// Kernel-API (§7.5): gRPC sign / finalise surface after wallet authorisation.
pub use signature::{
    durable_finalisation_with_signature, finalise_accepted_prove_outside_lock,
    finalise_with_accepted_signature, register_live_pending_after_begin, FinaliseOutcome,
    PendingSignEntry, PendingSignMap, SignatureCheck, TransitionSignatureError,
    WalletSignSubmission,
};

// Test-only re-exports: unit tests reach these as `crate::v1::…` without
// forcing them into the non-test lib re-export surface.
#[cfg(test)]
pub(crate) use attest::{
    accept_c_balance_network_binding, networks_have_distinct_c_balance_pins, parse_u64_decimal,
    pinned_c_balance_digest, PINNED_C_BALANCE_DIGEST_MAINNET, PINNED_C_BALANCE_DIGEST_TESTNET,
};
#[cfg(test)]
pub(crate) use self_heal::encode_v1_live_digest;
#[cfg(test)]
pub(crate) use separation::{claim_stack_scan_mode, set_process_stack_mode};
#[cfg(test)]
pub(crate) use signature::awaiting_signature_result_json;

#[cfg(test)]
mod tests;
