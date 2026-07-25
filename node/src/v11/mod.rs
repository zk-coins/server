//! v1.1 cutover Stage 1: flag-gated path to [`StateEngine`] + persistence.
//!
//! Default remains the legacy prover / SMT-MMR stack. Selecting the v1.1 path
//! requires `ZKCOINS_PROVER=v11` **and** the network / activation-height pins;
//! any missing piece fails loud — there is no silent fall-back to legacy.

mod adapter;
mod db_v11;
pub mod mode;

pub use adapter::EngineAdapter;
pub use mode::{
    parse_network_label, prover_mode_from_env, resolve_prover_mode, ProverMode, V11_BOOT_CONFIG_ERROR,
};

#[cfg(test)]
mod tests;
