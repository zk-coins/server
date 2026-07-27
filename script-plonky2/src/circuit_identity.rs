//! Circuit-identity helpers for §1.7.9 pin checks.
//!
//! The **live** check against the operator pins happens where the real
//! circuits are constructed ([`crate::prover_bridge`]): after `C` /
//! `C_balance` finish building, their digests are compared to the
//! registered pins. A mismatch refuses to proceed (not a warning).
//!
//! This module holds the pure comparison and hex helpers used at that
//! construction site (and by unit tests that simulate divergence without
//! a multi-minute Plonky2 build). It does **not** supply digests from an
//! embedded text file for boot — that was one indirection further from
//! the compiled circuit and could not catch a constraint change that
//! left a stale embed equal to the pins.

use zkcoins_program_plonky2::circuit::compliance::Network;

/// Network label for error messages (§3.6 pin surface).
pub fn network_label(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
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

/// Compare digests of the circuits that were **just built** against the
/// §3.6 operator pins.
///
/// * Both pairs equal → `Ok(())`
/// * Any mismatch → `Err` (refusal — a node must not proceed under a
///   divergent binary / pin identity, §1.7.9)
///
/// Call this only with digests taken from a real `SkeletonCircuit` /
/// `BalanceCircuit` (or a deliberate test simulation of that pair).
/// Never treat "unknown" as a pass — the caller must not invoke this
/// without concrete built digests.
pub fn require_live_digests_match_pins(
    built_c: &[u8; 32],
    built_c_balance: &[u8; 32],
    pin_c: &[u8; 32],
    pin_c_balance: &[u8; 32],
    network: Network,
) -> Result<(), String> {
    if built_c != pin_c || built_c_balance != pin_c_balance {
        return Err(format!(
            "live circuit digests do not match §3.6 boot pins for {} \
             (built C={}, C_balance={}; pins C={}, C_balance={}). \
             Refusing to proceed — a node must not serve proving paths \
             when the circuit it just constructed is not the pinned \
             network identity (§1.7.9)",
            network_label(network),
            bytes_to_hex(built_c),
            bytes_to_hex(built_c_balance),
            bytes_to_hex(pin_c),
            bytes_to_hex(pin_c_balance),
        ));
    }
    Ok(())
}

/// Compare a single just-built circuit digest against its pin.
///
/// Used when `C` and `C_balance` are constructed separately (each
/// `OnceLock` init): fail as soon as either diverges.
pub fn require_one_live_digest_matches_pin(
    which: &str,
    built: &[u8; 32],
    pin: &[u8; 32],
    network: Network,
) -> Result<(), String> {
    if built != pin {
        return Err(format!(
            "live {which} circuit digest does not match §3.6 boot pin for {} \
             (built={}, pin={}). Refusing to proceed (§1.7.9)",
            network_label(network),
            bytes_to_hex(built),
            bytes_to_hex(pin),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Would go red if a built/pin mismatch were treated as Ok / silent pass.
    #[test]
    fn refuse_when_built_c_differs_from_pin() {
        let built_c = [0x11u8; 32];
        let built_b = [0x22u8; 32];
        let mut pin_c = built_c;
        pin_c[0] ^= 0xFF;
        let err = require_live_digests_match_pins(
            &built_c,
            &built_b,
            &pin_c,
            &built_b,
            Network::Regtest,
        )
        .expect_err("built/pin mismatch must refuse");
        assert!(
            err.contains("do not match") || err.contains("Refusing"),
            "error must name the refusal: {err}"
        );
    }

    #[test]
    fn refuse_when_built_c_balance_differs_from_pin() {
        let built_c = [0x11u8; 32];
        let built_b = [0x22u8; 32];
        let mut pin_b = built_b;
        pin_b[0] ^= 0xFF;
        let err = require_live_digests_match_pins(
            &built_c,
            &built_b,
            &built_c,
            &pin_b,
            Network::Testnet,
        )
        .expect_err("C_balance mismatch must refuse");
        assert!(err.contains("do not match") || err.contains("Refusing"));
    }

    #[test]
    fn accept_when_built_equals_pins() {
        let c = [0xAAu8; 32];
        let b = [0xBBu8; 32];
        require_live_digests_match_pins(&c, &b, &c, &b, Network::Mainnet)
            .expect("identical pair must pass");
    }

    #[test]
    fn one_digest_helper_refuses_mismatch() {
        let built = [1u8; 32];
        let pin = [2u8; 32];
        let err =
            require_one_live_digest_matches_pin("C", &built, &pin, Network::Regtest).unwrap_err();
        assert!(err.contains("C") && err.contains("Refusing"));
    }
}
