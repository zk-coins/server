//! Build-time identity of the circuits this binary contains.
//!
//! Building `C` / `C_balance` at process boot is multi-minute (often ~hour
//! cold). Spec §1.7.9 still requires every node to pin circuit identity and
//! reject mismatches. The honest compromise:
//!
//! 1. Digests are computed offline by
//!    `script-plonky2/tests/generated_circuit_digests_test.rs` (same entry
//!    points as [`crate::prover_bridge::ProverBridge`]).
//! 2. Those bytes are **embedded** into this crate via `include_str!` so
//!    boot can read "the digests of the circuits this binary ships" in O(1).
//! 3. Boot compares the embedded artefact against the §3.6 env pins and
//!    refuses when they differ — never treats "unknown" as fine.
//!
//! Regenerating the vector file after a circuit change is mandatory; an
//! out-of-date embed fails the pin check loudly rather than silently
//! shipping a divergent circuit under matching env pins.

use std::collections::HashMap;
use std::sync::OnceLock;

use zkcoins_program_plonky2::circuit::compliance::Network;

/// Contents of `tests/generated_circuit_digests.txt`, baked into the binary
/// at compile time. Not re-read from disk at boot.
const EMBEDDED_CIRCUIT_DIGESTS_TXT: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/generated_circuit_digests.txt"
));

/// §1.7.1 digests of `C` and `C_balance` for one network tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EmbeddedCircuitDigests {
    pub circuit_digest_c: [u8; 32],
    pub circuit_digest_c_balance: [u8; 32],
}

fn nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        _ => Err(format!(
            "circuit digest hex is not lowercase hex (bad nibble {})",
            b as char
        )),
    }
}

fn parse_hex32(raw: &str) -> Result<[u8; 32], String> {
    let s = raw.trim();
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() != 64 {
        return Err(format!(
            "circuit digest hex must be 64 lowercase hex chars (optional 0x); got len {}",
            s.len()
        ));
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = nibble(bytes[i * 2])?;
        let lo = nibble(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
    }
    Ok(out)
}

fn bytes_to_hex(bytes: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0xf) as usize] as char);
    }
    out
}

fn parse_embedded_table(text: &str) -> Result<HashMap<String, [u8; 32]>, String> {
    let mut map = HashMap::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if !key.starts_with("circuit_digest_") {
            continue;
        }
        let digest = parse_hex32(value.trim()).map_err(|e| {
            format!("embedded circuit digests line {}: {e}", lineno + 1)
        })?;
        map.insert(key.to_string(), digest);
    }
    Ok(map)
}

fn embedded_table() -> Result<&'static HashMap<String, [u8; 32]>, String> {
    static TABLE: OnceLock<Result<HashMap<String, [u8; 32]>, String>> = OnceLock::new();
    match TABLE.get_or_init(|| parse_embedded_table(EMBEDDED_CIRCUIT_DIGESTS_TXT)) {
        Ok(m) => Ok(m),
        Err(e) => Err(e.clone()),
    }
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

/// Digests of the circuits **this binary embeds** for `network`.
///
/// Returns `Err` when the digests cannot be determined (parse failure or
/// missing keys). Callers **must refuse to boot** on `Err` — never treat
/// undetermined identity as compatible.
pub fn embedded_circuit_digests(network: Network) -> Result<EmbeddedCircuitDigests, String> {
    let table = embedded_table()?;
    let label = network_label(network);
    let c_key = format!("circuit_digest_c_{label}");
    let b_key = format!("circuit_digest_c_balance_{label}");
    let circuit_digest_c = *table.get(&c_key).ok_or_else(|| {
        format!(
            "cannot determine live circuit digest: embedded table missing {c_key} \
             (binary circuit identity unknown — refuse to start)"
        )
    })?;
    let circuit_digest_c_balance = *table.get(&b_key).ok_or_else(|| {
        format!(
            "cannot determine live circuit digest: embedded table missing {b_key} \
             (binary circuit identity unknown — refuse to start)"
        )
    })?;
    Ok(EmbeddedCircuitDigests {
        circuit_digest_c,
        circuit_digest_c_balance,
    })
}

/// Compare embedded (binary) digests against operator pins.
///
/// * Both pairs equal → `Ok(EmbeddedCircuitDigests)`
/// * Cannot load embed → `Err` (refusal, not a pass)
/// * Mismatch → `Err` (binary does not match the network pins)
pub fn require_embedded_matches_pins(
    network: Network,
    pin_c: &[u8; 32],
    pin_c_balance: &[u8; 32],
) -> Result<EmbeddedCircuitDigests, String> {
    let embedded = embedded_circuit_digests(network)?;
    if &embedded.circuit_digest_c != pin_c || &embedded.circuit_digest_c_balance != pin_c_balance {
        return Err(format!(
            "binary circuit digests do not match §3.6 boot pins for {} \
             (embedded C={}, C_balance={}; pins C={}, C_balance={}). \
             Refusing to start — a node must not proceed when the circuit \
             it contains is not the pinned network identity (§1.7.9)",
            network_label(network),
            bytes_to_hex(&embedded.circuit_digest_c),
            bytes_to_hex(&embedded.circuit_digest_c_balance),
            bytes_to_hex(pin_c),
            bytes_to_hex(pin_c_balance),
        ));
    }
    Ok(embedded)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_table_loads_all_networks() {
        for network in [Network::Mainnet, Network::Testnet, Network::Regtest] {
            let d = embedded_circuit_digests(network).expect("embedded digests present");
            assert_ne!(d.circuit_digest_c, [0u8; 32]);
            assert_ne!(d.circuit_digest_c_balance, [0u8; 32]);
            assert_ne!(d.circuit_digest_c, d.circuit_digest_c_balance);
        }
    }

    #[test]
    fn require_match_accepts_identical_pins() {
        let d = embedded_circuit_digests(Network::Regtest).unwrap();
        let ok = require_embedded_matches_pins(
            Network::Regtest,
            &d.circuit_digest_c,
            &d.circuit_digest_c_balance,
        );
        assert!(ok.is_ok());
    }

    /// Would go red if mismatch were treated as Ok / silent pass.
    #[test]
    fn require_match_refuses_pin_mismatch() {
        let d = embedded_circuit_digests(Network::Regtest).unwrap();
        let mut bad_c = d.circuit_digest_c;
        bad_c[0] ^= 0xFF;
        let err = require_embedded_matches_pins(
            Network::Regtest,
            &bad_c,
            &d.circuit_digest_c_balance,
        )
        .expect_err("pin/binary mismatch must refuse");
        assert!(
            err.contains("do not match"),
            "error must name the mismatch: {err}"
        );
    }

    #[test]
    fn parse_hex32_rejects_uppercase_and_short() {
        assert!(parse_hex32("AA").is_err());
        assert!(parse_hex32(&"a".repeat(63)).is_err());
        assert!(parse_hex32(&"A".repeat(64)).is_err());
    }
}
