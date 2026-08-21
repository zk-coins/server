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
pub(crate) fn require_one_live_digest_matches_pin(
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
    use crate::prover_bridge::ProverBridge;

    fn on_large_stack<F, R>(f: F) -> R
    where
        F: FnOnce() -> R + Send + 'static,
        R: Send + 'static,
    {
        std::thread::Builder::new()
            .name("circuit-identity-bridge".into())
            .stack_size(128 * 1024 * 1024)
            .spawn(f)
            .expect("spawn large-stack thread")
            .join()
            .expect("large-stack thread panicked")
    }

    /// Pure helper still refuses a fabricated mismatch (construction-time
    /// unit). Kept so a regression in the comparison itself is isolated
    /// from bridge cache / pin OnceLock state.
    #[test]
    fn refuse_when_built_c_differs_from_pin_helper() {
        let built_c = [0x11u8; 32];
        let built_b = [0x22u8; 32];
        let mut pin_c = built_c;
        pin_c[0] ^= 0xFF;
        let err =
            require_live_digests_match_pins(&built_c, &built_b, &pin_c, &built_b, Network::Regtest)
                .expect_err("built/pin mismatch must refuse");
        assert!(
            err.contains("do not match") || err.contains("Refusing"),
            "error must name the refusal: {err}"
        );
    }

    /// Production-path refusal via [`ProverBridge::require_live_identity`]:
    /// after an unpinned build, installing pins that differ from the real
    /// digests must refuse. Multi-minute circuit build.
    #[test]
    #[ignore = "multi-minute Plonky2 circuit build via ProverBridge"]
    fn refuse_when_built_c_differs_from_pin() {
        on_large_stack(|| {
            let network = Network::Mainnet;
            let bridge = ProverBridge::new(network);
            let (built_c, built_b) = bridge
                .require_live_identity()
                .expect("unpinned ProverBridge build");
            let mut pin_c = built_c;
            pin_c[0] ^= 0xFF;
            ProverBridge::install_network_pins(network, pin_c, built_b)
                .expect("install divergent C pin after unpinned build");
            let err = bridge
                .require_live_identity()
                .expect_err("built/pin mismatch must refuse through ProverBridge");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("do not match")
                    || msg.contains("Refusing")
                    || msg.contains("does not match"),
                "error must name the refusal: {msg}"
            );
        });
    }

    #[test]
    #[ignore = "multi-minute Plonky2 circuit build via ProverBridge"]
    fn refuse_when_built_c_balance_differs_from_pin() {
        on_large_stack(|| {
            let network = Network::Testnet;
            let bridge = ProverBridge::new(network);
            let (built_c, built_b) = bridge
                .require_live_identity()
                .expect("unpinned ProverBridge build");
            let mut pin_b = built_b;
            pin_b[0] ^= 0xFF;
            ProverBridge::install_network_pins(network, built_c, pin_b)
                .expect("install divergent C_balance pin");
            let err = bridge
                .require_live_identity()
                .expect_err("C_balance mismatch must refuse through ProverBridge");
            let msg = format!("{err:#}");
            assert!(
                msg.contains("do not match")
                    || msg.contains("Refusing")
                    || msg.contains("does not match"),
                "error must name the refusal: {msg}"
            );
        });
    }

    #[test]
    #[ignore = "multi-minute Plonky2 circuit build via ProverBridge"]
    fn accept_when_built_equals_pins() {
        on_large_stack(|| {
            let network = Network::Regtest;
            let bridge = ProverBridge::new(network);
            let (c, b) = bridge
                .require_live_identity()
                .expect("unpinned ProverBridge build");
            ProverBridge::install_network_pins(network, c, b).expect("install matching pins");
            let (c2, b2) = bridge
                .require_live_identity()
                .expect("matching pins must pass through ProverBridge");
            assert_eq!(c2, c);
            assert_eq!(b2, b);
        });
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
