//! Generates `script-plonky2/tests/generated_circuit_digests.txt` from the
//! live frozen circuits `C` and `C_balance` (spec §1.7.9 / V.4 `<REGEN>`).
//!
//! Values are **computed**, never hand-copied. Digests are the circuit's
//! `verifier_only.circuit_digest` (`HashOut`) encoded to 32 bytes per §1.7.1
//! via `shared::spec_v1::digest_to_bytes` — **not** the internal bincode used
//! by `Prover::circuit_digest_bytes`.
//!
//! Construction reuses the same entry points as `prover_bridge`:
//! - `C`: `build_skeleton_circuit(standard_recursion_zk_config(), network)`
//! - `C_balance`: `build_c_balance_circuit(&compliance, network)`
//!
//! Both circuits take a compile-time `Network` and pin `network_id` (and
//! `C_balance` additionally pins `C`'s verifier data), so digests are emitted
//! for each of `Mainnet`, `Testnet`, and `Regtest`.
//!
//! Re-run explicitly (builds real circuits; takes many minutes):
//! `cargo test -p zkcoins-prover-plonky2 --test generated_circuit_digests_test generate_circuit_digests -- --ignored --nocapture`

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use plonky2::plonk::circuit_data::CircuitConfig;
use shared::spec_v1::digest_to_bytes;
use zkcoins_program_plonky2::circuit::balance::build_c_balance_circuit;
use zkcoins_program_plonky2::circuit::compliance::{build_skeleton_circuit, Network};
use zkcoins_program_plonky2::hash::HashDigest;

fn hex32(bytes: &[u8; 32]) -> String {
    format!(
        "0x{}",
        bytes
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>()
    )
}

fn network_label(network: Network) -> &'static str {
    match network {
        Network::Mainnet => "mainnet",
        Network::Testnet => "testnet",
        Network::Regtest => "regtest",
    }
}

/// Encode `verifier_only.circuit_digest` to the §1.7.1 32-byte form.
///
/// Uses `shared::spec_v1::digest_to_bytes` (canonical `to_canonical_u64` +
/// big-endian limbs). Do not substitute `zkcoins_program::hash::digest_to_bytes`
/// (raw `.0`) or `bincode` — those are not the protocol encoding.
fn circuit_digest_hex(digest: &HashDigest) -> String {
    hex32(&digest_to_bytes(digest))
}

/// Builds `C` and `C_balance` for every network tag, extracts digests and
/// build metrics, and writes the sorted `name = value` vector file.
///
/// Flagged `#[ignore]` because each circuit build is multi-minute wall time.
#[test]
#[ignore]
fn generate_circuit_digests() {
    let networks = [Network::Mainnet, Network::Testnet, Network::Regtest];
    assert!(
        CircuitConfig::standard_recursion_zk_config().zero_knowledge,
        "spec §1.7.9 requires standard_recursion_zk_config (zero_knowledge)"
    );

    // Sorted key order for deterministic file output.
    let mut values: BTreeMap<String, String> = BTreeMap::new();

    let mut c_gates: Option<usize> = None;
    let mut c_degree_bits: Option<usize> = None;
    let mut balance_gates: Option<usize> = None;
    let mut balance_degree_bits: Option<usize> = None;

    for network in networks {
        let label = network_label(network);
        println!("building C for {label}…");
        // Same construction as `prover_bridge::compliance_circuit`.
        let compliance = build_skeleton_circuit(
            CircuitConfig::standard_recursion_zk_config(),
            network,
        );
        assert_eq!(
            compliance.network, network,
            "built C network must match requested Network::{label}"
        );

        let c_digest_hex = circuit_digest_hex(&compliance.data.verifier_only.circuit_digest);
        let gates = compliance.gate_count;
        let degree_bits = compliance.data.common.degree_bits();

        match c_gates {
            None => c_gates = Some(gates),
            Some(prev) => assert_eq!(
                prev, gates,
                "C gate count must be network-independent; got {prev} vs {gates} for {label}"
            ),
        }
        match c_degree_bits {
            None => c_degree_bits = Some(degree_bits),
            Some(prev) => assert_eq!(
                prev, degree_bits,
                "C degree_bits must be network-independent; got {prev} vs {degree_bits} for {label}"
            ),
        }

        values.insert(format!("circuit_digest_c_{label}"), c_digest_hex.clone());
        println!("circuit_digest_c_{label} = {c_digest_hex}");
        println!("circuit_c_{label}_gates = {gates} (shape metric; emitted once if equal)");
        println!(
            "circuit_c_{label}_degree_bits = {degree_bits} (shape metric; emitted once if equal)"
        );

        println!("building C_balance for {label}…");
        // Same path as prover_bridge::balance_circuit: pin this network's C.
        let balance = build_c_balance_circuit(&compliance, network);
        let b_digest_hex = circuit_digest_hex(&balance.data.verifier_only.circuit_digest);
        let b_gates = balance.gate_count;
        let b_degree_bits = balance.data.common.degree_bits();

        match balance_gates {
            None => balance_gates = Some(b_gates),
            Some(prev) => assert_eq!(
                prev, b_gates,
                "C_balance gate count must be network-independent; got {prev} vs {b_gates} for {label}"
            ),
        }
        match balance_degree_bits {
            None => balance_degree_bits = Some(b_degree_bits),
            Some(prev) => assert_eq!(
                prev, b_degree_bits,
                "C_balance degree_bits must be network-independent; got {prev} vs {b_degree_bits} for {label}"
            ),
        }

        values.insert(
            format!("circuit_digest_c_balance_{label}"),
            b_digest_hex.clone(),
        );
        println!("circuit_digest_c_balance_{label} = {b_digest_hex}");
        println!("circuit_c_balance_{label}_gates = {b_gates} (shape metric; emitted once if equal)");
        println!(
            "circuit_c_balance_{label}_degree_bits = {b_degree_bits} (shape metric; emitted once if equal)"
        );
    }

    // Shape metrics are network-independent (constants differ; gate count /
    // degree do not). Emit the single recorded values under the build-report
    // names from the task.
    let c_gates = c_gates.expect("C must be built at least once");
    let c_degree_bits = c_degree_bits.expect("C must be built at least once");
    let balance_gates = balance_gates.expect("C_balance must be built at least once");
    let balance_degree_bits = balance_degree_bits.expect("C_balance must be built at least once");

    values.insert("circuit_c_gates".to_string(), c_gates.to_string());
    values.insert(
        "circuit_c_degree_bits".to_string(),
        c_degree_bits.to_string(),
    );
    values.insert(
        "circuit_c_balance_gates".to_string(),
        balance_gates.to_string(),
    );
    values.insert(
        "circuit_c_balance_degree_bits".to_string(),
        balance_degree_bits.to_string(),
    );

    println!("circuit_c_gates = {c_gates}");
    println!("circuit_c_degree_bits = {c_degree_bits}");
    println!("circuit_c_balance_gates = {balance_gates}");
    println!("circuit_c_balance_degree_bits = {balance_degree_bits}");

    // Digests are network-dependent (spec §1.7.9 / V.4: one per network tag).
    let c_main = values
        .get("circuit_digest_c_mainnet")
        .expect("C mainnet digest must be present")
        .clone();
    let c_test = values
        .get("circuit_digest_c_testnet")
        .expect("C testnet digest must be present")
        .clone();
    let c_reg = values
        .get("circuit_digest_c_regtest")
        .expect("C regtest digest must be present")
        .clone();
    assert_ne!(
        c_main, c_test,
        "C digests for distinct networks must differ (network-dependent)"
    );
    assert_ne!(
        c_main, c_reg,
        "C digests for distinct networks must differ (network-dependent)"
    );
    assert_ne!(
        c_test, c_reg,
        "C digests for distinct networks must differ (network-dependent)"
    );

    let bal_main = values
        .get("circuit_digest_c_balance_mainnet")
        .expect("C_balance mainnet digest must be present")
        .clone();
    let bal_test = values
        .get("circuit_digest_c_balance_testnet")
        .expect("C_balance testnet digest must be present")
        .clone();
    let bal_reg = values
        .get("circuit_digest_c_balance_regtest")
        .expect("C_balance regtest digest must be present")
        .clone();
    assert_ne!(
        bal_main, bal_test,
        "C_balance digests for distinct networks must differ (network-dependent)"
    );
    assert_ne!(
        bal_main, bal_reg,
        "C_balance digests for distinct networks must differ (network-dependent)"
    );
    assert_ne!(
        bal_test, bal_reg,
        "C_balance digests for distinct networks must differ (network-dependent)"
    );

    let mut lines: Vec<String> = values
        .iter()
        .map(|(name, value)| format!("{name} = {value}"))
        .collect();
    lines.push(String::new()); // trailing newline

    let path = PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/generated_circuit_digests.txt"
    ));
    fs::write(&path, lines.join("\n")).expect("write generated_circuit_digests.txt");
    println!("wrote {}", path.display());

    let written = fs::read_to_string(&path).expect("read back digests file");
    for label in [
        "circuit_digest_c_mainnet",
        "circuit_digest_c_testnet",
        "circuit_digest_c_regtest",
        "circuit_digest_c_balance_mainnet",
        "circuit_digest_c_balance_testnet",
        "circuit_digest_c_balance_regtest",
        "circuit_c_gates",
        "circuit_c_degree_bits",
        "circuit_c_balance_gates",
        "circuit_c_balance_degree_bits",
    ] {
        assert!(
            written.contains(label),
            "generated file missing label {label}"
        );
    }
}
