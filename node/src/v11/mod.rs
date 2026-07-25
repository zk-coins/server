//! v1.1 cutover Stage 1: flag-gated **shadow** path to [`StateEngine`] + persistence.
//!
//! Default remains the legacy prover / SMT-MMR stack. Selecting the shadow path
//! requires `ZKCOINS_V11_SHADOW=1` **and** the network / activation-height pins
//! plus the published `network-params` identity; any missing piece fails loud —
//! there is no silent fall-back to legacy. Proving remains legacy until Stage 3.

mod adapter;
mod db_v11;
pub mod mode;

pub use adapter::EngineAdapter;
pub use mode::{
    parse_network_label, resolve_v11_shadow_mode, v11_shadow_mode_from_env, validate_v11_boot_pins,
    V11BootPins, V11ShadowMode, V11_BOOT_CONFIG_ERROR,
};

#[cfg(test)]
mod tests;
