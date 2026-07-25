//! `ZKCOINS_PROVER` resolution — pure, unit-testable, fail-loud.

use std::env;
use std::fmt;

use zkcoins_program::circuit::compliance::Network;

/// Which prove / state stack the node should boot.
///
/// Default is [`ProverMode::Legacy`]. The v1.1 path is selected only by the
/// exact env value `ZKCOINS_PROVER=v11`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProverMode {
    Legacy,
    V11,
}

/// Error when `ZKCOINS_PROVER` is set to an unsupported value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProverModeError {
    pub raw: String,
}

impl fmt::Display for ProverModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ZKCOINS_PROVER={:?} is not supported — use unset / empty / \"legacy\" \
             for the default legacy stack, or \"v11\" for the Stage-1 StateEngine path. \
             Refusing to start (no silent fall-back)",
            self.raw
        )
    }
}

impl std::error::Error for ProverModeError {}

/// Resolve the prover mode from an optional env string (testable without
/// mutating process env).
///
/// | value | mode |
/// |---|---|
/// | `None` / `""` / `"legacy"` | Legacy |
/// | `"v11"` | V11 |
/// | anything else | `Err` (fail loud) |
pub fn resolve_prover_mode(raw: Option<&str>) -> Result<ProverMode, ProverModeError> {
    match raw {
        None => Ok(ProverMode::Legacy),
        Some(s) if s.is_empty() || s == "legacy" => Ok(ProverMode::Legacy),
        Some("v11") => Ok(ProverMode::V11),
        Some(other) => Err(ProverModeError {
            raw: other.to_string(),
        }),
    }
}

/// Read `ZKCOINS_PROVER` from the process environment.
pub fn prover_mode_from_env() -> Result<ProverMode, ProverModeError> {
    match env::var("ZKCOINS_PROVER") {
        Err(env::VarError::NotPresent) => resolve_prover_mode(None),
        Err(env::VarError::NotUnicode(_)) => Err(ProverModeError {
            raw: "<non-utf8>".to_string(),
        }),
        Ok(v) => resolve_prover_mode(Some(v.as_str())),
    }
}

/// Closed network vocabulary for `ZKCOINS_NETWORK`.
pub fn parse_network_label(s: &str) -> Result<Network, String> {
    match s {
        "mainnet" => Ok(Network::Mainnet),
        "testnet" => Ok(Network::Testnet),
        "regtest" => Ok(Network::Regtest),
        other => Err(format!(
            "ZKCOINS_NETWORK={other:?} is not a known network tag; \
             expected exactly one of mainnet, testnet, regtest (no silent default)"
        )),
    }
}

pub fn network_label(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

/// Human-readable boot-config error for the v1.1 path.
pub const V11_BOOT_CONFIG_ERROR: &str = "\
ZKCOINS_PROVER=v11 requires both ZKCOINS_NETWORK (mainnet|testnet|regtest) and \
ZKCOINS_ACTIVATION_HEIGHT (non-negative integer) to be set. Refusing to fall \
back to the legacy prover — a node that silently proves with the wrong circuit \
is the worst outcome available here.";

/// Load the v1.1 network pin + activation height from the environment.
///
/// Both variables are mandatory when the v1.1 path is selected. There is no
/// default (including no implicit regtest / activation_height=0).
pub fn v11_boot_pins_from_env() -> Result<(Network, u64), String> {
    let network_raw = env::var("ZKCOINS_NETWORK").map_err(|_| V11_BOOT_CONFIG_ERROR.to_string())?;
    if network_raw.trim().is_empty() {
        return Err(V11_BOOT_CONFIG_ERROR.to_string());
    }
    let network = parse_network_label(network_raw.trim())?;

    let height_raw =
        env::var("ZKCOINS_ACTIVATION_HEIGHT").map_err(|_| V11_BOOT_CONFIG_ERROR.to_string())?;
    if height_raw.trim().is_empty() {
        return Err(V11_BOOT_CONFIG_ERROR.to_string());
    }
    let activation_height: u64 = height_raw.trim().parse().map_err(|_| {
        format!(
            "ZKCOINS_ACTIVATION_HEIGHT={height_raw:?} is not a non-negative integer; \
             refusing to start (no silent default)"
        )
    })?;
    Ok((network, activation_height))
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn unset_and_legacy_select_legacy() {
        assert_eq!(resolve_prover_mode(None).unwrap(), ProverMode::Legacy);
        assert_eq!(resolve_prover_mode(Some("")).unwrap(), ProverMode::Legacy);
        assert_eq!(
            resolve_prover_mode(Some("legacy")).unwrap(),
            ProverMode::Legacy
        );
    }

    #[test]
    fn v11_selects_v11() {
        assert_eq!(resolve_prover_mode(Some("v11")).unwrap(), ProverMode::V11);
    }

    #[test]
    fn unknown_value_fails_loud() {
        let err = resolve_prover_mode(Some("v1")).unwrap_err();
        assert!(err.to_string().contains("not supported"));
        // Case-sensitive: "V11" is not accepted (fail loud, no silent normalize).
        assert!(resolve_prover_mode(Some("V11")).is_err());
        assert!(resolve_prover_mode(Some("bridge")).is_err());
    }

    #[test]
    fn network_labels_are_closed() {
        assert_eq!(parse_network_label("regtest").unwrap(), Network::Regtest);
        assert!(parse_network_label("Regtest").is_err());
        assert!(parse_network_label("mutinynet").is_err());
        assert!(parse_network_label("").is_err());
    }
}
