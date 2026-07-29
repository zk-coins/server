//! `ZKCOINS_V1_SHADOW` resolution and §3.6 boot-pin validation.
//!
//! **Stage 3:** the production binary requires `ZKCOINS_V1_SHADOW=1` and
//! always claims the exclusive AggregateStateNullifierV3 / NfLog stack
//! with Engine/Bridge proving. Unset / `off` is refused at the binary
//! edge (not a silent fall-back to legacy). Unit tests may still resolve
//! the flag independently when they do not boot `main`.

use std::env;
use std::fmt;

use shared::spec_v1::network_params::NetworkParams;
use shared::spec_v1::tags::{NETWORK_TAG_MAINNET, NETWORK_TAG_REGTEST, NETWORK_TAG_TESTNET};
use zkcoins_program::circuit::compliance::Network;

/// Whether the v1 exclusive stack is selected for this process.
///
/// Stage 3 production binary requires [`V1ShadowMode::On`]
/// (`ZKCOINS_V1_SHADOW=1`). [`V1ShadowMode::Off`] remains resolvable for
/// residual unit tests and Stage-4 cleanup tooling, but is not a
/// production dual-stack mode anymore.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum V1ShadowMode {
    Off,
    On,
}

/// Error when `ZKCOINS_V1_SHADOW` is set to an unsupported value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1ShadowModeError {
    pub raw: String,
}

impl fmt::Display for V1ShadowModeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ZKCOINS_V1_SHADOW={:?} is not supported — use unset / empty / \"off\" \
             for the legacy Commitment/SMT stack (default), or \"1\" for the exclusive \
             v1.1 AggregateStateNullifierV3/NfLog publisher+scanner (proving remains \
             legacy until Stage 3). Refusing to start (no silent fall-back)",
            self.raw
        )
    }
}

impl std::error::Error for V1ShadowModeError {}

/// Resolve the shadow mode from an optional env string (testable without
/// mutating process env).
///
/// | value | mode |
/// |---|---|
/// | `None` / `""` / `"off"` | Off |
/// | `"1"` | On |
/// | anything else | `Err` (fail loud) |
///
/// Case-sensitive, no whitespace trim: `"1 "` / `"ON"` / `"true"` all fail.
pub(crate) fn resolve_v1_shadow_mode(raw: Option<&str>) -> Result<V1ShadowMode, V1ShadowModeError> {
    match raw {
        None => Ok(V1ShadowMode::Off),
        Some(s) if s.is_empty() || s == "off" => Ok(V1ShadowMode::Off),
        Some("1") => Ok(V1ShadowMode::On),
        Some(other) => Err(V1ShadowModeError {
            raw: other.to_string(),
        }),
    }
}

/// Read `ZKCOINS_V1_SHADOW` from the process environment.
pub fn v1_shadow_mode_from_env() -> Result<V1ShadowMode, V1ShadowModeError> {
    match env::var("ZKCOINS_V1_SHADOW") {
        Err(env::VarError::NotPresent) => resolve_v1_shadow_mode(None),
        Err(env::VarError::NotUnicode(_)) => Err(V1ShadowModeError {
            raw: "<non-utf8>".to_string(),
        }),
        Ok(v) => resolve_v1_shadow_mode(Some(v.as_str())),
    }
}

/// Closed network vocabulary for `ZKCOINS_NETWORK`.
pub(crate) fn parse_network_label(s: &str) -> Result<Network, String> {
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

pub(crate) fn network_label(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

/// Canonical §3.6 network tag string for a [`Network`] configuration value.
pub(crate) fn network_tag_for(network: Network) -> Result<&'static str, String> {
    let bytes = match network {
        Network::Mainnet => NETWORK_TAG_MAINNET,
        Network::Testnet => NETWORK_TAG_TESTNET,
        Network::Regtest => NETWORK_TAG_REGTEST,
    };
    std::str::from_utf8(bytes).map_err(|_| {
        format!("NETWORK_TAG for {network:?} is not valid UTF-8 (internal constant corrupt)")
    })
}

/// Human-readable boot-config error for the v1.1 shadow path.
pub(crate) const V1_BOOT_CONFIG_ERROR: &str = "\
ZKCOINS_V1_SHADOW=1 requires ZKCOINS_NETWORK (mainnet|testnet|regtest), \
ZKCOINS_ACTIVATION_HEIGHT (non-negative integer), ZKCOINS_EXPECTED_PARAMS_IDENTIFIER \
(64 lowercase hex chars — the published network-params.json SHA-256), and the \
parameter-set fields ZKCOINS_CIRCUIT_DIGEST_C, ZKCOINS_CIRCUIT_DIGEST_C_BALANCE, \
and ZKCOINS_BOOTSTRAP_PUBKEY (each 64 lowercase hex chars) so the boot path can \
validate the set against its published identity (§3.6). Refusing to fall back — \
a node that silently maintains state under the wrong network pins is the worst \
outcome available here.";

/// Validated Stage-1 boot pins: network + activation height after §3.6 checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct V1BootPins {
    pub network: Network,
    pub activation_height: u64,
    pub network_params: NetworkParams,
    pub expected_params_identifier: [u8; 32],
}

/// Validate boot pins the same way [`ScannerConfig`] / scanner connect does.
///
/// The identifier check is the cross-node guarantee: `expected_params_identifier`
/// is the **published** `network-params.json` identity, supplied independently
/// of `network_params`. Comparing `activation_height` to
/// `network_params.activation_height()` alone is a tautology when both come
/// from the same caller — a self-consistent but unpublished set must still fail.
///
/// Checks (mirroring scanner):
/// 1. `network_params.identifier() == expected_params_identifier`
/// 2. `network_params.network_tag()` matches the §3.6 tag for `network`
/// 3. regtest pin: `network_params.activation_height() == 0`
/// 4. `activation_height == network_params.activation_height()`
pub(crate) fn validate_v1_boot_pins(
    network: Network,
    activation_height: u64,
    network_params: &NetworkParams,
    expected_params_identifier: [u8; 32],
) -> Result<(), String> {
    // §3.6 content-addressed identity: the published artifact identifier is
    // the guarantee. Height equality alone is caller-supplied on both sides
    // and would accept a self-consistent but unpublished set.
    let actual_id = network_params.identifier().map_err(|e| {
        format!("network_params.identifier() failed (canonical encoding / tag): {e}")
    })?;
    if actual_id != expected_params_identifier {
        return Err(format!(
            "network_params.identifier() {} does not match \
             expected_params_identifier {} \
             (§3.6 content-addressed network-params — refuse to start rather than \
             maintain shadow state under a divergent pin; any field difference \
             including activation_height changes the identifier)",
            bytes_to_hex(&actual_id),
            bytes_to_hex(&expected_params_identifier)
        ));
    }

    let expected_tag = network_tag_for(network)?;
    let actual_tag = network_params.network_tag();
    if actual_tag != expected_tag {
        return Err(format!(
            "network_params.network_tag() {actual_tag:?} does not correspond to \
             network {:?} (expected tag {expected_tag:?}) — refuse to start rather \
             than maintain shadow state under a divergent pin",
            network
        ));
    }

    let pinned = network_params.activation_height();
    // §3.6: regtest activation_height is pinned at 0.
    if network == Network::Regtest && pinned != 0 {
        return Err(format!(
            "network_params.activation_height {pinned} is not the \
             §3.6 regtest pin (0) — refuse to start rather than maintain \
             shadow state under a divergent pin"
        ));
    }
    if activation_height != pinned {
        return Err(format!(
            "activation_height {activation_height} does not match \
             network_params.activation_height {pinned} for {:?} \
             (§3.6 Scan origin — refuse to start rather than maintain \
             shadow state under a divergent pin)",
            network
        ));
    }

    Ok(())
}

/// Lower-hex encoding of a 32-byte identifier for fail-loud error messages.
fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    let mut out = String::with_capacity(64);
    for b in bytes {
        use std::fmt::Write as _;
        let _ = write!(out, "{b:02x}");
    }
    out
}

fn parse_hex_32(raw: &str, env_name: &str) -> Result<[u8; 32], String> {
    let trimmed = raw.trim();
    if trimmed.len() != 64 {
        return Err(format!(
            "{env_name}={raw:?} must be exactly 64 lowercase hex characters \
             (32 bytes); refusing to start (no silent default)"
        ));
    }
    // Reject non-lowercase / non-hex by requiring a full decode of the untrimmed
    // length-checked string; hex::decode accepts A-F too — fail loud on uppercase.
    if trimmed
        .bytes()
        .any(|b| !b.is_ascii_digit() && !(b'a'..=b'f').contains(&b))
    {
        return Err(format!(
            "{env_name}={raw:?} is not lowercase hex; refusing to start \
             (no silent case-fold)"
        ));
    }
    let bytes = hex::decode(trimmed)
        .map_err(|e| format!("{env_name}={raw:?} is not valid hex: {e}; refusing to start"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| format!("{env_name} decoded to the wrong length; refusing to start"))?;
    Ok(arr)
}

/// Load and validate Stage-1 boot pins from the environment.
///
/// Both the parameter set and the **published** identifier are mandatory.
/// There is no default (including no implicit regtest / activation_height=0).
pub fn v1_boot_pins_from_env() -> Result<V1BootPins, String> {
    let network_raw = env::var("ZKCOINS_NETWORK").map_err(|_| V1_BOOT_CONFIG_ERROR.to_string())?;
    if network_raw.trim().is_empty() {
        return Err(V1_BOOT_CONFIG_ERROR.to_string());
    }
    let network = parse_network_label(network_raw.trim())?;

    let height_raw =
        env::var("ZKCOINS_ACTIVATION_HEIGHT").map_err(|_| V1_BOOT_CONFIG_ERROR.to_string())?;
    if height_raw.trim().is_empty() {
        return Err(V1_BOOT_CONFIG_ERROR.to_string());
    }
    let activation_height: u64 = height_raw.trim().parse().map_err(|_| {
        format!(
            "ZKCOINS_ACTIVATION_HEIGHT={height_raw:?} is not a non-negative integer; \
             refusing to start (no silent default)"
        )
    })?;

    let expected_raw = env::var("ZKCOINS_EXPECTED_PARAMS_IDENTIFIER")
        .map_err(|_| V1_BOOT_CONFIG_ERROR.to_string())?;
    if expected_raw.trim().is_empty() {
        return Err(V1_BOOT_CONFIG_ERROR.to_string());
    }
    let expected_params_identifier =
        parse_hex_32(&expected_raw, "ZKCOINS_EXPECTED_PARAMS_IDENTIFIER")?;

    let digest_c_raw =
        env::var("ZKCOINS_CIRCUIT_DIGEST_C").map_err(|_| V1_BOOT_CONFIG_ERROR.to_string())?;
    if digest_c_raw.trim().is_empty() {
        return Err(V1_BOOT_CONFIG_ERROR.to_string());
    }
    let circuit_digest_c = parse_hex_32(&digest_c_raw, "ZKCOINS_CIRCUIT_DIGEST_C")?;

    let digest_bal_raw = env::var("ZKCOINS_CIRCUIT_DIGEST_C_BALANCE")
        .map_err(|_| V1_BOOT_CONFIG_ERROR.to_string())?;
    if digest_bal_raw.trim().is_empty() {
        return Err(V1_BOOT_CONFIG_ERROR.to_string());
    }
    let circuit_digest_c_balance =
        parse_hex_32(&digest_bal_raw, "ZKCOINS_CIRCUIT_DIGEST_C_BALANCE")?;

    let bootstrap_raw =
        env::var("ZKCOINS_BOOTSTRAP_PUBKEY").map_err(|_| V1_BOOT_CONFIG_ERROR.to_string())?;
    if bootstrap_raw.trim().is_empty() {
        return Err(V1_BOOT_CONFIG_ERROR.to_string());
    }
    let bootstrap_pubkey = parse_hex_32(&bootstrap_raw, "ZKCOINS_BOOTSTRAP_PUBKEY")?;

    let network_tag = network_tag_for(network)?.to_string();
    let network_params = NetworkParams::new(
        network_tag,
        circuit_digest_c,
        circuit_digest_c_balance,
        activation_height,
        6, // §3.6 fixed finality_confirmations
        bootstrap_pubkey,
    )
    .map_err(|e| format!("NetworkParams construction failed: {e}"))?;

    validate_v1_boot_pins(
        network,
        activation_height,
        &network_params,
        expected_params_identifier,
    )?;

    Ok(V1BootPins {
        network,
        activation_height,
        network_params,
        expected_params_identifier,
    })
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn unset_empty_and_off_disable_shadow() {
        assert_eq!(resolve_v1_shadow_mode(None).unwrap(), V1ShadowMode::Off);
        assert_eq!(resolve_v1_shadow_mode(Some("")).unwrap(), V1ShadowMode::Off);
        assert_eq!(
            resolve_v1_shadow_mode(Some("off")).unwrap(),
            V1ShadowMode::Off
        );
    }

    #[test]
    fn one_enables_shadow() {
        assert_eq!(resolve_v1_shadow_mode(Some("1")).unwrap(), V1ShadowMode::On);
    }

    #[test]
    fn unknown_value_fails_loud() {
        let err = resolve_v1_shadow_mode(Some("v1")).unwrap_err();
        assert!(err.to_string().contains("not supported"));
        // Case-sensitive / no silent normalize.
        assert!(resolve_v1_shadow_mode(Some("ON")).is_err());
        assert!(resolve_v1_shadow_mode(Some("True")).is_err());
        assert!(resolve_v1_shadow_mode(Some("true")).is_err());
        assert!(resolve_v1_shadow_mode(Some("1 ")).is_err());
        assert!(resolve_v1_shadow_mode(Some(" 1")).is_err());
        assert!(resolve_v1_shadow_mode(Some("legacy")).is_err());
        assert!(resolve_v1_shadow_mode(Some("0")).is_err());
    }

    #[test]
    fn network_labels_are_closed() {
        assert_eq!(parse_network_label("regtest").unwrap(), Network::Regtest);
        assert!(parse_network_label("Regtest").is_err());
        assert!(parse_network_label("mutinynet").is_err());
        assert!(parse_network_label("").is_err());
    }

    fn fixture_params(tag: &str, height: u64) -> NetworkParams {
        NetworkParams::new(tag.to_string(), [1u8; 32], [2u8; 32], height, 6, [3u8; 32])
            .expect("fixture")
    }

    #[test]
    fn boot_pins_accept_matching_published_identifier() {
        let tag = network_tag_for(Network::Testnet).unwrap();
        let params = fixture_params(tag, 2_500_000);
        let id = params.identifier().expect("id");
        validate_v1_boot_pins(Network::Testnet, 2_500_000, &params, id)
            .expect("matching pins must pass");
    }

    #[test]
    fn boot_pins_reject_params_identifier_mismatch() {
        // Self-consistent wrong-height set vs published identifier — the trap
        // the identifier check exists to close.
        let tag = network_tag_for(Network::Testnet).unwrap();
        let published = fixture_params(tag, 2_500_000);
        let published_id = published.identifier().expect("id");
        let wrong = fixture_params(tag, 99);
        assert_ne!(
            wrong.identifier().expect("id"),
            published_id,
            "height change must change the content-addressed identifier"
        );
        let err = validate_v1_boot_pins(Network::Testnet, 99, &wrong, published_id)
            .expect_err("self-consistent unpublished set must fail");
        assert!(
            err.contains("expected_params_identifier") || err.contains("identifier"),
            "must fail on identifier, not only height equality; got: {err}"
        );
        assert!(
            !err.contains("does not match network_params.activation_height"),
            "must not fall through to the height-equality arm first; got: {err}"
        );
    }

    #[test]
    fn boot_pins_reject_height_mismatch_against_params() {
        let tag = network_tag_for(Network::Mainnet).unwrap();
        let params = fixture_params(tag, 840_000);
        let id = params.identifier().expect("id");
        let err = validate_v1_boot_pins(Network::Mainnet, 1, &params, id)
            .expect_err("height mismatch must fail");
        assert!(err.contains("activation_height"), "unexpected error: {err}");
    }

    #[test]
    fn boot_pins_reject_regtest_nonzero_pin() {
        let tag = network_tag_for(Network::Regtest).unwrap();
        let params = fixture_params(tag, 7);
        let id = params.identifier().expect("id");
        let err = validate_v1_boot_pins(Network::Regtest, 7, &params, id)
            .expect_err("regtest non-zero must fail");
        assert!(
            err.contains("regtest") || err.contains("§3.6"),
            "unexpected error: {err}"
        );
    }
}
