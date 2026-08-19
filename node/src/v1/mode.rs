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

/// Boot role for the shared `C_balance` verifier-cache volume.
///
/// | value | role |
/// |---|---|
/// | unset / `"primary"` | Primary — build circuits, write cache |
/// | `"secondary"` | Secondary — load shared C_balance cache (never builds C_balance); still lazily builds the small C circuit on first prove |
/// | anything else (including `""`) | `Err` (fail loud) |
///
/// Unset defaults to Primary so existing production configs that never set
/// `ZKCOINS_VERIFIER_CACHE_ROLE` keep the historical boot path byte-for-byte.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VerifierCacheRole {
    Primary,
    Secondary,
}

/// Error when `ZKCOINS_VERIFIER_CACHE_ROLE` is set to an unsupported value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifierCacheRoleError {
    pub raw: String,
}

impl fmt::Display for VerifierCacheRoleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ZKCOINS_VERIFIER_CACHE_ROLE={:?} is not supported — use unset / \"primary\" \
             for primary boot (build circuits and write the C_balance verifier cache), \
             or \"secondary\" to reuse a shared C_balance verifier cache already written \
             by a primary. Refusing to start (no silent fall-back)",
            self.raw
        )
    }
}

impl std::error::Error for VerifierCacheRoleError {}

/// Resolve the verifier-cache role from an optional env string (testable
/// without mutating process env).
///
/// | value | role |
/// |---|---|
/// | `None` | Primary |
/// | `"primary"` | Primary |
/// | `"secondary"` | Secondary |
/// | anything else (including `""`) | `Err` (fail loud) |
///
/// Case-sensitive, no whitespace trim: `"Primary"` / `" secondary"` all fail.
pub(crate) fn resolve_verifier_cache_role(
    raw: Option<&str>,
) -> Result<VerifierCacheRole, VerifierCacheRoleError> {
    match raw {
        None => Ok(VerifierCacheRole::Primary),
        Some("primary") => Ok(VerifierCacheRole::Primary),
        Some("secondary") => Ok(VerifierCacheRole::Secondary),
        Some(other) => Err(VerifierCacheRoleError {
            raw: other.to_string(),
        }),
    }
}

/// Read `ZKCOINS_VERIFIER_CACHE_ROLE` from the process environment.
pub fn verifier_cache_role_from_env() -> Result<VerifierCacheRole, VerifierCacheRoleError> {
    match env::var("ZKCOINS_VERIFIER_CACHE_ROLE") {
        Err(env::VarError::NotPresent) => resolve_verifier_cache_role(None),
        Err(env::VarError::NotUnicode(_)) => Err(VerifierCacheRoleError {
            raw: "<non-utf8>".to_string(),
        }),
        Ok(v) => resolve_verifier_cache_role(Some(v.as_str())),
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
    fn verifier_cache_role_from_env_defaults_primary_and_parses_secondary() {
        assert_eq!(
            resolve_verifier_cache_role(None).unwrap(),
            VerifierCacheRole::Primary
        );
        assert_eq!(
            resolve_verifier_cache_role(Some("primary")).unwrap(),
            VerifierCacheRole::Primary
        );
        assert_eq!(
            resolve_verifier_cache_role(Some("secondary")).unwrap(),
            VerifierCacheRole::Secondary
        );
    }

    #[test]
    fn verifier_cache_role_unknown_value_fails_loud() {
        let err = resolve_verifier_cache_role(Some("")).unwrap_err();
        assert!(err.to_string().contains("not supported"));
        assert!(err.to_string().contains("no silent fall-back"));
        // Case-sensitive / no silent normalize / no whitespace trim.
        assert!(resolve_verifier_cache_role(Some("Primary")).is_err());
        assert!(resolve_verifier_cache_role(Some("SECONDARY")).is_err());
        assert!(resolve_verifier_cache_role(Some("secondary ")).is_err());
        assert!(resolve_verifier_cache_role(Some(" secondary")).is_err());
        assert!(resolve_verifier_cache_role(Some("standby")).is_err());
        assert!(resolve_verifier_cache_role(Some("1")).is_err());
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

    // --- env mutation serialisation (nextest --test-threads=8) ---

    /// Serialise process-env mutations across tests in this module.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| std::sync::Mutex::new(()))
            .lock()
            .unwrap_or_else(|p| p.into_inner())
    }

    const BOOT_ENV_KEYS: &[&'static str] = &[
        "ZKCOINS_NETWORK",
        "ZKCOINS_ACTIVATION_HEIGHT",
        "ZKCOINS_EXPECTED_PARAMS_IDENTIFIER",
        "ZKCOINS_CIRCUIT_DIGEST_C",
        "ZKCOINS_CIRCUIT_DIGEST_C_BALANCE",
        "ZKCOINS_BOOTSTRAP_PUBKEY",
    ];

    /// Snapshot of env vars restored on drop (panic-safe cleanup).
    struct SavedEnv {
        entries: Vec<(&'static str, Option<std::ffi::OsString>)>,
    }

    impl SavedEnv {
        fn capture(keys: &[&'static str]) -> Self {
            Self {
                entries: keys.iter().map(|&k| (k, std::env::var_os(k))).collect(),
            }
        }
    }

    impl Drop for SavedEnv {
        fn drop(&mut self) {
            for (k, prev) in self.entries.drain(..) {
                match prev {
                    Some(v) => std::env::set_var(k, v),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    /// Fixed digests used by the boot-env baseline (same shape as `fixture_params`).
    const BASE_DIGEST_C: [u8; 32] = [1u8; 32];
    const BASE_DIGEST_BAL: [u8; 32] = [2u8; 32];
    const BASE_BOOTSTRAP: [u8; 32] = [3u8; 32];
    const BASE_HEIGHT: u64 = 2_500_000;

    /// Build a mutually consistent testnet boot-env baseline and install it.
    fn install_testnet_boot_baseline() {
        let tag = network_tag_for(Network::Testnet)
            .expect("testnet tag")
            .to_string();
        let params = NetworkParams::new(
            tag,
            BASE_DIGEST_C,
            BASE_DIGEST_BAL,
            BASE_HEIGHT,
            6,
            BASE_BOOTSTRAP,
        )
        .expect("baseline NetworkParams");
        let expected = hex::encode(params.identifier().expect("baseline identifier"));
        std::env::set_var("ZKCOINS_NETWORK", "testnet");
        std::env::set_var("ZKCOINS_ACTIVATION_HEIGHT", BASE_HEIGHT.to_string());
        std::env::set_var("ZKCOINS_EXPECTED_PARAMS_IDENTIFIER", expected);
        std::env::set_var("ZKCOINS_CIRCUIT_DIGEST_C", hex::encode(BASE_DIGEST_C));
        std::env::set_var(
            "ZKCOINS_CIRCUIT_DIGEST_C_BALANCE",
            hex::encode(BASE_DIGEST_BAL),
        );
        std::env::set_var("ZKCOINS_BOOTSTRAP_PUBKEY", hex::encode(BASE_BOOTSTRAP));
    }

    // --- A. v1_shadow_mode_from_env ---

    #[test]
    fn v1_shadow_mode_from_env_unset_is_off() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(&["ZKCOINS_V1_SHADOW"]);
        std::env::remove_var("ZKCOINS_V1_SHADOW");
        assert_eq!(v1_shadow_mode_from_env().expect("unset"), V1ShadowMode::Off);
    }

    #[test]
    fn v1_shadow_mode_from_env_one_is_on() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(&["ZKCOINS_V1_SHADOW"]);
        std::env::set_var("ZKCOINS_V1_SHADOW", "1");
        assert_eq!(v1_shadow_mode_from_env().expect("1"), V1ShadowMode::On);
    }

    #[test]
    fn v1_shadow_mode_from_env_garbage_fails() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(&["ZKCOINS_V1_SHADOW"]);
        std::env::set_var("ZKCOINS_V1_SHADOW", "garbage");
        let err = v1_shadow_mode_from_env().expect_err("garbage");
        assert_eq!(err.raw, "garbage");
        assert!(err.to_string().contains("not supported"));
    }

    #[cfg(unix)]
    #[test]
    fn v1_shadow_mode_from_env_non_utf8_fails() {
        use std::os::unix::ffi::OsStringExt;
        let _guard = env_lock();
        let _saved = SavedEnv::capture(&["ZKCOINS_V1_SHADOW"]);
        std::env::set_var(
            "ZKCOINS_V1_SHADOW",
            std::ffi::OsString::from_vec(vec![0xff, 0xfe]),
        );
        let err = v1_shadow_mode_from_env().expect_err("non-utf8");
        assert_eq!(err.raw, "<non-utf8>");
    }

    // --- B. verifier_cache_role_from_env ---

    #[test]
    fn verifier_cache_role_from_env_unset_is_primary() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(&["ZKCOINS_VERIFIER_CACHE_ROLE"]);
        std::env::remove_var("ZKCOINS_VERIFIER_CACHE_ROLE");
        assert_eq!(
            verifier_cache_role_from_env().expect("unset"),
            VerifierCacheRole::Primary
        );
    }

    #[test]
    fn verifier_cache_role_from_env_secondary() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(&["ZKCOINS_VERIFIER_CACHE_ROLE"]);
        std::env::set_var("ZKCOINS_VERIFIER_CACHE_ROLE", "secondary");
        assert_eq!(
            verifier_cache_role_from_env().expect("secondary"),
            VerifierCacheRole::Secondary
        );
    }

    #[test]
    fn verifier_cache_role_from_env_bogus_fails() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(&["ZKCOINS_VERIFIER_CACHE_ROLE"]);
        std::env::set_var("ZKCOINS_VERIFIER_CACHE_ROLE", "bogus");
        let err = verifier_cache_role_from_env().expect_err("bogus");
        assert_eq!(err.raw, "bogus");
        assert!(err.to_string().contains("not supported"));
    }

    #[cfg(unix)]
    #[test]
    fn verifier_cache_role_from_env_non_utf8_fails() {
        use std::os::unix::ffi::OsStringExt;
        let _guard = env_lock();
        let _saved = SavedEnv::capture(&["ZKCOINS_VERIFIER_CACHE_ROLE"]);
        std::env::set_var(
            "ZKCOINS_VERIFIER_CACHE_ROLE",
            std::ffi::OsString::from_vec(vec![0xff, 0xfe]),
        );
        let err = verifier_cache_role_from_env().expect_err("non-utf8");
        assert_eq!(err.raw, "<non-utf8>");
    }

    // --- C. network_label ---

    #[test]
    fn network_label_covers_all_variants() {
        assert_eq!(network_label(Network::Mainnet), "mainnet");
        assert_eq!(network_label(Network::Testnet), "testnet");
        assert_eq!(network_label(Network::Regtest), "regtest");
        // parse_network_label mainnet arm (existing tests only exercise regtest success).
        assert_eq!(parse_network_label("mainnet").unwrap(), Network::Mainnet);
        assert_eq!(parse_network_label("testnet").unwrap(), Network::Testnet);
    }

    // --- D. validate_v1_boot_pins tag-mismatch branch ---

    #[test]
    fn boot_pins_reject_network_tag_mismatch() {
        let tag = network_tag_for(Network::Testnet).unwrap();
        let params = fixture_params(tag, 2_500_000);
        let id = params.identifier().expect("id");
        // Identifier matches params, but caller claims Mainnet → tag arm fires.
        let err = validate_v1_boot_pins(Network::Mainnet, 2_500_000, &params, id)
            .expect_err("tag mismatch must fail");
        assert!(
            err.contains("network_tag") || err.contains("correspond"),
            "unexpected error: {err}"
        );
    }

    // --- E. parse_hex_32 (private; reachable via super from this child module) ---

    #[test]
    fn parse_hex_32_valid_and_trimmed() {
        let raw = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let expected = hex::decode(raw).expect("fixture hex");
        let expected: [u8; 32] = expected.try_into().expect("32 bytes");
        assert_eq!(
            super::parse_hex_32(raw, "TEST_HEX").expect("valid"),
            expected
        );
        // Leading/trailing whitespace is trimmed before length/charset checks.
        let padded = format!("  {raw}  ");
        assert_eq!(
            super::parse_hex_32(&padded, "TEST_HEX").expect("trimmed"),
            expected
        );
    }

    #[test]
    fn parse_hex_32_wrong_length_fails() {
        let short = "a".repeat(63);
        let err = super::parse_hex_32(&short, "TEST_HEX").expect_err("too short");
        assert!(
            err.contains("64") || err.contains("lowercase hex characters"),
            "unexpected: {err}"
        );
        let long = "a".repeat(65);
        let err = super::parse_hex_32(&long, "TEST_HEX").expect_err("too long");
        assert!(
            err.contains("64") || err.contains("lowercase hex characters"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn parse_hex_32_uppercase_and_non_hex_fail() {
        let upper = format!("AA{}", "a".repeat(62));
        let err = super::parse_hex_32(&upper, "TEST_HEX").expect_err("uppercase");
        assert!(err.contains("not lowercase hex"), "unexpected: {err}");
        let non_hex = format!("g{}", "a".repeat(63));
        let err = super::parse_hex_32(&non_hex, "TEST_HEX").expect_err("non-hex");
        assert!(err.contains("not lowercase hex"), "unexpected: {err}");
    }

    // --- F. v1_boot_pins_from_env ---

    #[test]
    fn v1_boot_pins_from_env_happy_path() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        let pins = v1_boot_pins_from_env().expect("happy path");
        assert_eq!(pins.network, Network::Testnet);
        assert_eq!(pins.activation_height, BASE_HEIGHT);
        let id = pins.network_params.identifier().expect("id");
        assert_eq!(id, pins.expected_params_identifier);
        let expected_from_env =
            hex::decode(std::env::var("ZKCOINS_EXPECTED_PARAMS_IDENTIFIER").unwrap())
                .expect("env identifier hex");
        assert_eq!(
            pins.expected_params_identifier.as_slice(),
            expected_from_env.as_slice()
        );
    }

    #[test]
    fn v1_boot_pins_from_env_network_unset() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::remove_var("ZKCOINS_NETWORK");
        let err = v1_boot_pins_from_env().expect_err("network unset");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_network_blank() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::set_var("ZKCOINS_NETWORK", "  ");
        let err = v1_boot_pins_from_env().expect_err("network blank");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_network_unknown() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::set_var("ZKCOINS_NETWORK", "notanetwork");
        let err = v1_boot_pins_from_env().expect_err("unknown network");
        assert_ne!(err, V1_BOOT_CONFIG_ERROR.to_string());
        assert!(err.contains("not a known network tag"), "unexpected: {err}");
    }

    #[test]
    fn v1_boot_pins_from_env_height_unset() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::remove_var("ZKCOINS_ACTIVATION_HEIGHT");
        let err = v1_boot_pins_from_env().expect_err("height unset");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_height_blank() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::set_var("ZKCOINS_ACTIVATION_HEIGHT", "");
        let err = v1_boot_pins_from_env().expect_err("height blank");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_height_not_integer() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::set_var("ZKCOINS_ACTIVATION_HEIGHT", "not-a-number");
        let err = v1_boot_pins_from_env().expect_err("height garbage");
        assert_ne!(err, V1_BOOT_CONFIG_ERROR.to_string());
        assert!(
            err.contains("not a non-negative integer"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn v1_boot_pins_from_env_expected_id_unset() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::remove_var("ZKCOINS_EXPECTED_PARAMS_IDENTIFIER");
        let err = v1_boot_pins_from_env().expect_err("expected id unset");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_expected_id_blank() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::set_var("ZKCOINS_EXPECTED_PARAMS_IDENTIFIER", "");
        let err = v1_boot_pins_from_env().expect_err("expected id blank");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_expected_id_too_short() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::set_var("ZKCOINS_EXPECTED_PARAMS_IDENTIFIER", "tooshort");
        let err = v1_boot_pins_from_env().expect_err("expected id short");
        assert_ne!(err, V1_BOOT_CONFIG_ERROR.to_string());
        assert!(
            err.contains("64") || err.contains("lowercase hex"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn v1_boot_pins_from_env_digest_c_unset() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::remove_var("ZKCOINS_CIRCUIT_DIGEST_C");
        let err = v1_boot_pins_from_env().expect_err("digest_c unset");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_digest_c_blank() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::set_var("ZKCOINS_CIRCUIT_DIGEST_C", "");
        let err = v1_boot_pins_from_env().expect_err("digest_c blank");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_digest_c_invalid_hex() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::set_var("ZKCOINS_CIRCUIT_DIGEST_C", format!("zz{}", "0".repeat(62)));
        let err = v1_boot_pins_from_env().expect_err("digest_c bad hex");
        assert_ne!(err, V1_BOOT_CONFIG_ERROR.to_string());
        assert!(
            err.contains("not lowercase hex") || err.contains("ZKCOINS_CIRCUIT_DIGEST_C"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn v1_boot_pins_from_env_digest_balance_unset() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::remove_var("ZKCOINS_CIRCUIT_DIGEST_C_BALANCE");
        let err = v1_boot_pins_from_env().expect_err("digest_bal unset");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_digest_balance_blank() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::set_var("ZKCOINS_CIRCUIT_DIGEST_C_BALANCE", "");
        let err = v1_boot_pins_from_env().expect_err("digest_bal blank");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_bootstrap_unset() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::remove_var("ZKCOINS_BOOTSTRAP_PUBKEY");
        let err = v1_boot_pins_from_env().expect_err("bootstrap unset");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_bootstrap_blank() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        std::env::set_var("ZKCOINS_BOOTSTRAP_PUBKEY", "");
        let err = v1_boot_pins_from_env().expect_err("bootstrap blank");
        assert_eq!(err, V1_BOOT_CONFIG_ERROR.to_string());
    }

    #[test]
    fn v1_boot_pins_from_env_regtest_nonzero_activation_fails() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        // Internally consistent regtest set with nonzero height so validation
        // reaches the §3.6 regtest pin check (not the identifier arm).
        let height = 7u64;
        let tag = network_tag_for(Network::Regtest)
            .expect("regtest tag")
            .to_string();
        let params = NetworkParams::new(
            tag,
            BASE_DIGEST_C,
            BASE_DIGEST_BAL,
            height,
            6,
            BASE_BOOTSTRAP,
        )
        .expect("regtest params");
        let expected = hex::encode(params.identifier().expect("id"));
        std::env::set_var("ZKCOINS_NETWORK", "regtest");
        std::env::set_var("ZKCOINS_ACTIVATION_HEIGHT", height.to_string());
        std::env::set_var("ZKCOINS_EXPECTED_PARAMS_IDENTIFIER", expected);
        std::env::set_var("ZKCOINS_CIRCUIT_DIGEST_C", hex::encode(BASE_DIGEST_C));
        std::env::set_var(
            "ZKCOINS_CIRCUIT_DIGEST_C_BALANCE",
            hex::encode(BASE_DIGEST_BAL),
        );
        std::env::set_var("ZKCOINS_BOOTSTRAP_PUBKEY", hex::encode(BASE_BOOTSTRAP));
        let err = v1_boot_pins_from_env().expect_err("regtest nonzero");
        assert!(
            err.contains("regtest") || err.contains("§3.6"),
            "unexpected: {err}"
        );
    }

    #[test]
    fn v1_boot_pins_from_env_wrong_expected_identifier_fails() {
        let _guard = env_lock();
        let _saved = SavedEnv::capture(BOOT_ENV_KEYS);
        install_testnet_boot_baseline();
        // Well-formed 64-char lowercase hex that does not match the built params.
        std::env::set_var("ZKCOINS_EXPECTED_PARAMS_IDENTIFIER", "00".repeat(32));
        let err = v1_boot_pins_from_env().expect_err("wrong identifier");
        assert!(err.contains("identifier"), "unexpected: {err}");
    }

    // UNREACHABLE: mode.rs:181-183 — network_tag_for map_err body:
    // NETWORK_TAG_{MAINNET,TESTNET,REGTEST} are fixed valid-ASCII literals in
    // shared/src/spec_v1/tags.rs; std::str::from_utf8 on them cannot fail.
    //
    // UNREACHABLE: mode.rs:228-230 — validate_v1_boot_pins identifier().map_err:
    // every NetworkParams obtainable here is built via NetworkParams::new(),
    // which already rejects the only input that could make .identifier() fail
    // (oversized tag) at construction time.
    //
    // UNREACHABLE: mode.rs:305-306 — parse_hex_32 hex::decode map_err:
    // reached only after len==64 and every byte is an ASCII hex digit — which
    // is exactly the set hex::decode always accepts.
    //
    // UNREACHABLE: mode.rs:308-309 — parse_hex_32 try_into map_err:
    // a successful hex::decode of a 64-hex-char string always yields 32 bytes.
    //
    // UNREACHABLE: mode.rs:375 — v1_boot_pins_from_env NetworkParams::new map_err:
    // finality_confirmations is hardcoded 6 and the tag always comes from
    // network_tag_for (one of three short fixed strings under the 255-byte
    // limit); neither of NetworkParams::new's two failure conditions can fire.
}
