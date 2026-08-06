//! Trustless CLI verifier for a `BalanceAttestationV1` (§5.7 / Requirement 9(b)).
//!
//! Decodes the attestation, connects a fresh bitcoind-backed `Scanner` from
//! env pins, scans to tip, and runs the four independent host checks. Never
//! trusts producer-node state or attestation-supplied anchor/nav_ceiling
//! authority for its own verification.
//!
//! Required env vars (no defaults — fail loud if missing):
//!   - `ZKCOINS_V1_SHADOW=1` (process stack claim)
//!   - `ZKCOINS_NETWORK`, `ZKCOINS_ACTIVATION_HEIGHT`,
//!     `ZKCOINS_EXPECTED_PARAMS_IDENTIFIER`, `ZKCOINS_CIRCUIT_DIGEST_C`,
//!     `ZKCOINS_CIRCUIT_DIGEST_C_BALANCE`, `ZKCOINS_BOOTSTRAP_PUBKEY`
//!     (via `v1_boot_pins_from_env`)
//!   - `ZKCOINS_V1_BITCOIND_RPC_URL`, `ZKCOINS_V1_BITCOIND_COOKIE_PATH`
//!     (via `v1_bitcoind_rpc_from_env`)
//!
//! Flags:
//!   - `--attestation-hex <hex>` — optional; if absent, read hex from stdin
//!   - `-h` / `--help`

use std::io::{self, Read};
use std::process::ExitCode;

use node::v1::attest_verify::{decode_balance_attestation_v1, verify_balance_attestation};
use zkcoins_prover::scanner::{Scanner, ScannerConfig};

#[derive(Debug)]
struct CliArgs {
    /// Hex-encoded attestation when supplied via flag; `None` means read stdin.
    attestation_hex: Option<String>,
}

fn print_usage(program: &str) {
    eprintln!(
        "usage: {program} \\
    [--attestation-hex <hex>]

If --attestation-hex is omitted, the hex-encoded BalanceAttestationV1 is read
from stdin (trimmed). Network / bitcoind selection is entirely env-driven.

env (all required, no defaults):
  ZKCOINS_V1_SHADOW=1
  ZKCOINS_NETWORK
  ZKCOINS_ACTIVATION_HEIGHT
  ZKCOINS_EXPECTED_PARAMS_IDENTIFIER
  ZKCOINS_CIRCUIT_DIGEST_C
  ZKCOINS_CIRCUIT_DIGEST_C_BALANCE
  ZKCOINS_BOOTSTRAP_PUBKEY
  ZKCOINS_V1_BITCOIND_RPC_URL
  ZKCOINS_V1_BITCOIND_COOKIE_PATH
"
    );
}

/// Parse argv into a `CliArgs`. Errors carry the user-facing message
/// already formatted; the caller prints them to stderr.
fn parse_args(argv: Vec<String>) -> Result<CliArgs, String> {
    let mut iter = argv.into_iter();
    let program = iter.next().unwrap_or_else(|| "verify_attestation".into());

    let mut attestation_hex: Option<String> = None;

    fn take_value<I: Iterator<Item = String>>(iter: &mut I, flag: &str) -> Result<String, String> {
        iter.next()
            .ok_or_else(|| format!("flag `{flag}` requires a value"))
    }

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--attestation-hex" => {
                attestation_hex = Some(take_value(&mut iter, "--attestation-hex")?)
            }
            "-h" | "--help" => {
                print_usage(&program);
                return Err(String::new());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(CliArgs { attestation_hex })
}

fn read_attestation_hex(args: &CliArgs) -> Result<Vec<u8>, String> {
    let hex_str = match &args.attestation_hex {
        Some(hex) => {
            let trimmed = hex.trim();
            if trimmed.is_empty() {
                return Err("--attestation-hex is empty".into());
            }
            trimmed.to_string()
        }
        None => {
            let mut buf = String::new();
            io::stdin()
                .read_to_string(&mut buf)
                .map_err(|e| format!("failed to read attestation hex from stdin: {e}"))?;
            let trimmed = buf.trim();
            if trimmed.is_empty() {
                return Err(
                    "no --attestation-hex flag and stdin is empty; provide attestation hex".into(),
                );
            }
            trimmed.to_string()
        }
    };
    hex::decode(&hex_str).map_err(|e| format!("attestation hex is not valid hex: {e}"))
}

fn run(args: CliArgs) -> Result<(), String> {
    let attestation_bytes = read_attestation_hex(&args)?;

    node::v1::claim_process_stack_from_v1_shadow_env()
        .map_err(|e| format!("failed to claim process stack from ZKCOINS_V1_SHADOW: {e:#}"))?;

    let pins = node::v1::v1_boot_pins_from_env()
        .map_err(|e| format!("v1_boot_pins_from_env failed: {e}"))?;

    let (rpc_url, cookie_path) = node::v1::scan::v1_bitcoind_rpc_from_env()
        .map_err(|e| format!("v1_bitcoind_rpc_from_env failed: {e:#}"))?;

    let scanner_config = ScannerConfig {
        rpc_url,
        cookie_path,
        network: pins.network,
        activation_height: pins.activation_height,
        network_params: pins.network_params.clone(),
        expected_params_identifier: pins.expected_params_identifier,
    };

    let mut scanner =
        Scanner::connect(scanner_config).map_err(|e| format!("scanner connect failed: {e:#}"))?;

    let report = scanner
        .scan_to_tip()
        .map_err(|e| format!("scan_to_tip failed: {e:#}"))?;

    if report.reorg.as_ref().is_some_and(|r| r.finality_broken) {
        let displaced = report
            .reorg
            .as_ref()
            .map(|r| r.displaced_final_count)
            .expect("finality_broken implies reorg is Some");
        return Err(format!(
            "independent scan observed a broken-finality reorg \
             (displaced_final_count={displaced}) — refusing to verify against unstable state"
        ));
    }

    let tip_height = report.tip_height;

    let decoded =
        decode_balance_attestation_v1(&attestation_bytes).map_err(|e| format!("decode: {e}"))?;

    let cache_dir = std::env::var("ZKCOINS_VERIFIER_CACHE_DIR")
        .map_err(|_| "ZKCOINS_VERIFIER_CACHE_DIR must be set".to_string())?;
    let pinned = pins.network_params.circuit_digest_c_balance();
    let pinned_blob_hash =
        zkcoins_prover::verifier_cache::balance_verifier_blob_hash_for_network(pins.network)
            .map_err(|e| {
                format!(
                    "full-VerifierCircuitData blob-hash pin for C_balance on this network is not \
                     generated yet: {e:#}"
                )
            })?;
    let verifier = zkcoins_prover::verifier_cache::load_balance_verifier_cache_checked(
        pins.network,
        std::path::Path::new(&cache_dir),
        &pinned,
        &pinned_blob_hash,
    )
    .map_err(|e| format!("load_balance_verifier_cache_checked failed: {e:#}"))?;
    verify_balance_attestation(&decoded, &scanner, tip_height, &verifier)
        .map_err(|e| format!("{e}"))?;

    Ok(())
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("verify_attestation: {msg}");
            }
            return ExitCode::from(1);
        }
    };

    match run(args) {
        Ok(()) => {
            println!("verify_attestation: PASS");
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("verify_attestation: FAIL: {msg}");
            ExitCode::from(1)
        }
    }
}
