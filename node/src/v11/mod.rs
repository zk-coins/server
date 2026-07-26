//! v1.1 cutover Stages 1–2 (+ G3 receive): flag-gated **shadow** path.
//!
//! ## Stage 1
//! [`StateEngine`] persistence behind `ZKCOINS_V11_SHADOW=1`. Proving remains
//! legacy until Stage 3.
//!
//! ## Stage 2
//! Exclusive dual stack for **publisher + scanner**:
//! - Flag off → legacy Commitment publisher + Esplora SMT scanner (default).
//! - Flag on → script-plonky2 `AggregateStateNullifierV3` publisher + NfLog
//!   scan-fold (§3.6). Missing bitcoind pins fail loud — never fall back.
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
//! an opaque [`V11Publisher`] from connect/env. The foreign publisher type
//! never leaves the package; assembling a durable effect from raw parts is
//! a compile error — see the `downstream-boundary` package
//! (`sealed_plumbing_compile_fail_matrix`).
//!
//! ## Gap G4 — transition signature
//! Behind the same flag, wallet authorisation is a §3.2
//! [`TransitionSignature`](zkcoins_prover::prover_bridge::TransitionSignature)
//! (BIP-340 + sign-to-contract over the full canonical `serialize(ProofData)`),
//! verified by [`signature`]. Legacy ash‖ocr [`shared::commitment::Commitment`]
//! stays the default when the flag is off.

mod adapter;
pub mod db_v11;
pub mod mode;
pub mod publish;
pub mod receive;
pub mod scan;
pub mod separation;
pub mod signature;

pub use adapter::EngineAdapter;
pub use mode::{
    parse_network_label, resolve_v11_shadow_mode, v11_shadow_mode_from_env, validate_v11_boot_pins,
    V11BootPins, V11ShadowMode, V11_BOOT_CONFIG_ERROR,
};
pub use publish::{connect_v11_publisher, v11_publisher_env_from_env, V11Publisher, V11PublisherEnv};
pub use receive::{
    commit_proved_receive, execute_v11_receive, finalise_publish_persist,
    refuse_legacy_receive_under_v11, resume_all_pending_publishes, resume_pending_publish,
    verify_and_begin_receive, verify_clause10_slot, verify_creating_nullifier_binding,
    ReceivedCoinSlot, V11ReceiveOutcome, V11ReceiveRequest, LEGACY_RECEIVE_REFUSED_UNDER_V11,
};
pub use scan::{
    apply_canonical_survivors, apply_forward_scan, first_boot_requires_full_replace,
    folded_keys_from_nflog_mirror, members_to_published, observation_tip_still_live,
    reconcile_persisted_tip, sort_canonical, FoldStats, MAX_RECOVERABLE_REORG_DEPTH,
    PersistedTipReconciliation, ResolvedBlock, TipReconcileOutcome,
};
pub use separation::{
    claim_process_stack_from_shadow_mode, claim_process_stack_from_v11_shadow_env,
    enforce_stack_scan_mode, ensure_legacy_publisher_allowed, ensure_v11_publisher_allowed,
    legacy_scan_state_present, load_stack_scan_mode, process_stack_mode,
    require_stack_mode_for_update, require_v11_process_for_nflog_write, set_process_stack_mode,
    v11_scan_state_present, ScanStackMode, STACK_CAPABILITY_REFUSAL, STACK_SEPARATION_REFUSAL,
};
pub use signature::{
    accept_wallet_transition_signature, ensure_v11_signature_path, verify_transition_signature,
    SignatureCheck, TransitionSignatureError, WalletSignSubmission,
};

#[cfg(test)]
pub use separation::{claim_stack_scan_mode, clear_process_stack_mode_for_test};

#[cfg(test)]
mod tests;
