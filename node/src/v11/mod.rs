//! v1.1 cutover Stages 1–2: flag-gated **shadow** path.
//!
//! ## Stage 1
//! [`StateEngine`] persistence behind `ZKCOINS_V11_SHADOW=1`. Proving remains
//! legacy until Stage 3.
//!
//! ## Stage 2 (this block)
//! Exclusive dual stack for **publisher + scanner**:
//! - Flag off → legacy Commitment publisher + Esplora SMT scanner (default).
//! - Flag on → script-plonky2 `AggregateStateNullifierV3` publisher + NfLog
//!   scan-fold (§3.6). Missing bitcoind pins fail loud — never fall back.
//!
//! A commitment and an `AggregateStateNullifierV3` must never share one
//! accumulator or one database; see [`separation`].

mod adapter;
mod db_v11;
pub mod mode;
pub mod publish;
pub mod scan;
pub mod separation;

pub use adapter::EngineAdapter;
pub use mode::{
    parse_network_label, resolve_v11_shadow_mode, v11_shadow_mode_from_env, validate_v11_boot_pins,
    V11BootPins, V11ShadowMode, V11_BOOT_CONFIG_ERROR,
};
pub use publish::{
    connect_v11_publisher, publish_v11_batch, v11_publisher_env_from_env, V11PublisherEnv,
};
pub use scan::{
    apply_canonical_survivors, apply_forward_scan, fold_survivors_into_engine,
    folded_keys_from_nflog_mirror, members_to_published, reconcile_persisted_tip,
    replace_engine_nflog_from_survivors, sort_canonical, FoldStats, MAX_RECOVERABLE_REORG_DEPTH,
    PersistedTipReconciliation, ResolvedBlock,
};
pub use separation::{
    claim_stack_scan_mode, enforce_stack_scan_mode, ensure_legacy_publisher_allowed,
    ensure_v11_publisher_allowed, legacy_scan_state_present, load_stack_scan_mode,
    process_stack_mode, require_stack_mode_for_update, require_v11_process_for_nflog_write,
    set_process_stack_mode, v11_scan_state_present, ScanStackMode, STACK_CAPABILITY_REFUSAL,
    STACK_SEPARATION_REFUSAL,
};

#[cfg(test)]
pub use separation::clear_process_stack_mode_for_test;

#[cfg(test)]
mod tests;
