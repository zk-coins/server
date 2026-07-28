//! Recover a stuck inscription anchor by rebuilding + broadcasting
//! the missing reveal transaction.
//!
//! Use case: the publisher broadcast a script-path Taproot commit
//! transaction but the reveal never made it to the network (process
//! crash between `client.broadcast(commit_tx)` and
//! `client.broadcast(reveal_tx)`, lost reveal bytes, etc.). The
//! commitment is recoverable as long as the operator has saved the
//! 145-byte bincode commitment payload and the commit txid from the
//! node logs.
//!
//! PR #105's REST fallback covers the WS-slow / WS-flaky failure mode
//! during normal operation; this CLI is the escape hatch for any
//! other failure between commit-broadcast and reveal-broadcast.
//!
//! The reveal is reconstructed deterministically from
//! `(commit_txid, commit_value, commitment_data, publisher_key)` via
//! the `publisher::build_reveal_only` helper — the same code path the
//! in-process publisher uses to mine the reveal. The CLI then sanity-
//! checks that the recovered reveal spends the operator-supplied
//! `--anchor-address` (so a wrong commitment payload or wrong network
//! can't produce a transaction that spends to nowhere) and broadcasts
//! via Esplora REST.
//!
//! Required env vars:
//!   - `PUBLISHER_KEY` — 32-byte hex secp256k1 secret, must match the
//!     key that signed the commit.
//!   - `IS_MAINNET` — `"true"` for `Network::Bitcoin`, anything else
//!     resolves to `Network::Signet` (Mutinynet).
//!
//! Optional env vars:
//!   - `NETWORK_NAME` — log-only label.
//!
//! Required flags:
//!   - `--commit-txid <hex>` — the broadcast commit txid (64 hex chars).
//!   - `--commitment-hex <hex>` — the inscription payload (bincode of
//!     `Commitment`) as hex, exactly as logged by the publisher.
//!   - `--commit-value <sats>` — value of the commit's anchor output[0].
//!   - `--anchor-address <addr>` — bech32m P2TR address holding the
//!     funds. Recovery aborts if the recovered reveal does not spend
//!     this address.
//!
//! Required flags (chain endpoint):
//!   - `--esplora-url <url>` — HTTP Esplora endpoint for the chain
//!     the inscription was committed against. Required, no default —
//!     a silent Mutinynet fallback would broadcast a Mainnet recovery
//!     against the wrong chain. Same contract as the node binary's
//!     `ESPLORA_URL` env var (see `lib::build_network_config_from_env`).
//!
//! Optional flags:
//!   - `--dry-run` — log the reveal hex and exit without broadcasting.

use std::process::ExitCode;
use std::str::FromStr;

use bitcoin::consensus::Encodable;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey, XOnlyPublicKey};
use bitcoin::{Address, Network, Txid};

use node::publisher::{self, LegacyBroadcastClient};

#[derive(Debug)]
struct CliArgs {
    commit_txid: String,
    commitment_hex: String,
    commit_value: u64,
    anchor_address: String,
    esplora_url: String,
    dry_run: bool,
}

fn print_usage(program: &str) {
    eprintln!(
        "usage: {program} \\
    --commit-txid <hex> \\
    --commitment-hex <hex> \\
    --commit-value <sats> \\
    --anchor-address <p2tr-addr> \\
    --esplora-url <url> \\
    [--dry-run]

env: PUBLISHER_KEY (required, 32-byte hex), IS_MAINNET (required, true|false)
     NETWORK_NAME (optional, log-only)
"
    );
}

/// Parse argv into a `CliArgs`. Errors carry the user-facing message
/// already formatted; the caller prints them to stderr.
fn parse_args(argv: Vec<String>) -> Result<CliArgs, String> {
    let mut iter = argv.into_iter();
    let program = iter.next().unwrap_or_else(|| "recover_inscription".into());

    let mut commit_txid: Option<String> = None;
    let mut commitment_hex: Option<String> = None;
    let mut commit_value: Option<u64> = None;
    let mut anchor_address: Option<String> = None;
    let mut esplora_url: Option<String> = None;
    let mut dry_run = false;

    fn take_value<I: Iterator<Item = String>>(iter: &mut I, flag: &str) -> Result<String, String> {
        iter.next()
            .ok_or_else(|| format!("flag `{flag}` requires a value"))
    }

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--commit-txid" => commit_txid = Some(take_value(&mut iter, "--commit-txid")?),
            "--commitment-hex" => commitment_hex = Some(take_value(&mut iter, "--commitment-hex")?),
            "--commit-value" => {
                let raw = take_value(&mut iter, "--commit-value")?;
                commit_value = Some(
                    raw.parse::<u64>()
                        .map_err(|e| format!("--commit-value must be a u64 sats value: {e}"))?,
                );
            }
            "--anchor-address" => anchor_address = Some(take_value(&mut iter, "--anchor-address")?),
            "--esplora-url" => esplora_url = Some(take_value(&mut iter, "--esplora-url")?),
            "--dry-run" => dry_run = true,
            "-h" | "--help" => {
                print_usage(&program);
                return Err(String::new());
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    let commit_txid = commit_txid.ok_or_else(|| "--commit-txid is required".to_string())?;
    let commitment_hex =
        commitment_hex.ok_or_else(|| "--commitment-hex is required".to_string())?;
    let commit_value = commit_value.ok_or_else(|| "--commit-value is required".to_string())?;
    let anchor_address =
        anchor_address.ok_or_else(|| "--anchor-address is required".to_string())?;
    let esplora_url = esplora_url.ok_or_else(|| {
        "--esplora-url is required (no default — silent fallback would \
         broadcast against the wrong chain)"
            .to_string()
    })?;

    Ok(CliArgs {
        commit_txid,
        commitment_hex,
        commit_value,
        anchor_address,
        esplora_url,
        dry_run,
    })
}

/// Validate parsed args (txid format, hex, address parses for network).
/// Returns the typed inputs ready for `build_reveal_only`.
struct ValidatedArgs {
    commit_txid: Txid,
    commitment_bytes: Vec<u8>,
    commit_value: u64,
    anchor_address: Address,
    network: Network,
    esplora_url: String,
    dry_run: bool,
}

fn validate_args(args: CliArgs, network: Network) -> Result<ValidatedArgs, String> {
    if args.commit_txid.len() != 64 || !args.commit_txid.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!(
            "--commit-txid must be 64 hex chars, got {} chars",
            args.commit_txid.len()
        ));
    }
    let commit_txid = Txid::from_str(&args.commit_txid)
        .map_err(|e| format!("--commit-txid is not a valid txid: {e}"))?;

    let commitment_bytes = hex::decode(&args.commitment_hex)
        .map_err(|e| format!("--commitment-hex is not valid hex: {e}"))?;
    if commitment_bytes.is_empty() {
        return Err("--commitment-hex decoded to 0 bytes".into());
    }

    if args.commit_value == 0 {
        return Err("--commit-value must be > 0".into());
    }

    let anchor_address = Address::from_str(&args.anchor_address)
        .map_err(|e| format!("--anchor-address is not a valid address: {e}"))?
        .require_network(network)
        .map_err(|e| {
            format!(
                "--anchor-address {} is not valid for network {:?}: {}",
                args.anchor_address, network, e
            )
        })?;

    Ok(ValidatedArgs {
        commit_txid,
        commitment_bytes,
        commit_value: args.commit_value,
        anchor_address,
        network,
        esplora_url: args.esplora_url,
        dry_run: args.dry_run,
    })
}

/// Resolve network from the required `IS_MAINNET` env var (`true` →
/// Bitcoin, `false` → Signet) and log the operator label from
/// `NETWORK_NAME`.
///
/// Panics on missing or ambiguous `IS_MAINNET` — same contract as
/// `lib::build_network_config_from_env`. A recovery tool that
/// silently defaulted to Mutinynet would broadcast a Mainnet recovery
/// against the wrong chain; explicit-or-panic prevents that.
fn resolve_network_from_env() -> Network {
    let is_mainnet_raw = std::env::var("IS_MAINNET").expect(
        "IS_MAINNET env var must be set explicitly to `true` or `false` — \
         no default exists. Match the env of the node whose inscription \
         you are recovering (PRD: true, DEV: false).",
    );
    let is_mainnet = match is_mainnet_raw.as_str() {
        "true" => true,
        "false" => false,
        other => panic!(
            "IS_MAINNET must be exactly `true` or `false`, got `{}`. \
             Truthy values like `1`, `TRUE`, or `yes` are rejected to \
             prevent silent misconfiguration.",
            other
        ),
    };
    let label = std::env::var("NETWORK_NAME").unwrap_or_else(|_| {
        if is_mainnet {
            "Mainnet".to_string()
        } else {
            "Mutinynet".to_string()
        }
    });
    println!("recover_inscription: network={label} is_mainnet={is_mainnet}");
    if is_mainnet {
        Network::Bitcoin
    } else {
        Network::Signet
    }
}

/// Derive the publisher's P2TR (key-spend) address used as the reveal's
/// output. Matches the derivation in `lib::PUBLISHER_ADDRESS`.
fn derive_publisher_address(publisher_key: &str, network: Network) -> Result<Address, String> {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_str(publisher_key)
        .map_err(|e| format!("PUBLISHER_KEY is not a valid 32-byte hex secret: {e}"))?;
    let key_pair = Keypair::from_secret_key(&secp, &sk);
    let (xonly, _parity) = XOnlyPublicKey::from_keypair(&key_pair);
    Ok(Address::p2tr(&secp, xonly, None, network))
}

/// Encode a `Transaction` to its hex serialization (consensus bytes →
/// lowercase hex).
fn serialize_tx_hex(tx: &bitcoin::Transaction) -> String {
    let mut buf = Vec::new();
    tx.consensus_encode(&mut buf)
        .expect("Vec<u8> never fails consensus_encode");
    hex::encode(buf)
}

async fn run(validated: ValidatedArgs, publisher_key: String) -> Result<(), String> {
    // Build the reveal deterministically from the operator-supplied
    // commit txid + value + commitment payload. The publisher's
    // matching `inscription_txs` happy-path goes through the same
    // helper, so this is the identical code path the original mint
    // would have used had the reveal broadcast not failed.
    let publisher_address = derive_publisher_address(&publisher_key, validated.network)?;
    println!(
        "recover_inscription: publisher_address={} commit_txid={} commit_value={}",
        publisher_address, validated.commit_txid, validated.commit_value
    );

    let (reveal_tx, derived_commit_address) = publisher::build_reveal_only(
        validated.commit_txid,
        validated.commit_value,
        &validated.commitment_bytes,
        &publisher_key,
        &publisher_address,
        validated.network,
    );

    // Sanity-check: the script-path commit address we re-derived from
    // the commitment payload + publisher key MUST match the
    // operator-supplied `--anchor-address`. If not, the wrong
    // commitment payload or wrong key was supplied and broadcasting
    // would burn the funds to an address nobody can spend from.
    if derived_commit_address != validated.anchor_address {
        return Err(format!(
            "anchor-address mismatch: derived={derived_commit_address} supplied={} \
             (wrong commitment-hex or publisher key?)",
            validated.anchor_address
        ));
    }
    println!(
        "recover_inscription: derived commit address matches --anchor-address {}",
        validated.anchor_address
    );

    let reveal_txid = reveal_tx.compute_txid();
    let reveal_hex = serialize_tx_hex(&reveal_tx);

    if validated.dry_run {
        println!("recover_inscription: dry-run — reveal_tx_hex={reveal_hex}");
        println!("recover_inscription: dry-run — reveal_txid={reveal_txid}");
        return Ok(());
    }

    // Claim the process stack the same way the node binary does — from
    // `ZKCOINS_V1_SHADOW`. Under `=1` the process is v1.1 and the guarded
    // client refuses before any Esplora I/O. Raw `esplora-client` types are
    // not reachable from this binary (confined to `node::esplora_bound`).
    node::v1::claim_process_stack_from_v1_shadow_env().map_err(|e| {
        format!("recover_inscription: failed to claim process stack from ZKCOINS_V1_SHADOW: {e}")
    })?;

    let client = LegacyBroadcastClient::connect(&validated.esplora_url).map_err(|e| {
        format!(
            "failed to build guarded broadcast client for {}: {e}",
            validated.esplora_url
        )
    })?;

    println!(
        "recover_inscription: broadcasting reveal {} via {}...",
        reveal_txid, validated.esplora_url
    );
    client
        .broadcast(&reveal_tx)
        .await
        .map_err(|e| format!("esplora broadcast failed: {e}"))?;

    // Single GET to confirm the reveal landed in the mempool / a
    // block. Mirrors the REST fallback shape from PR #105 — one GET,
    // not a poll loop (preserves the "No polling — events only"
    // invariant from CONTRIBUTING.md).
    let esplora_status = match client.get_tx(&reveal_txid).await {
        Ok(Some(_)) => "200",
        Ok(None) => "404",
        Err(e) => {
            println!(
                "recover_inscription: reveal broadcast — txid={reveal_txid} esplora-status=error \
                 (GET /tx/{reveal_txid} failed: {e})"
            );
            return Ok(());
        }
    };
    println!(
        "recover_inscription: reveal broadcast — txid={reveal_txid} esplora-status={esplora_status}"
    );
    Ok(())
}

fn run_blocking(validated: ValidatedArgs, publisher_key: String) -> Result<(), String> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("failed to build tokio runtime: {e}"))?;
    runtime.block_on(run(validated, publisher_key))
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().collect();
    let args = match parse_args(argv) {
        Ok(a) => a,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("recover_inscription: {msg}");
            }
            return ExitCode::from(1);
        }
    };

    let publisher_key = match std::env::var("PUBLISHER_KEY") {
        Ok(k) => k,
        Err(_) => {
            eprintln!(
                "recover_inscription: PUBLISHER_KEY env var must be set (32-byte hex secret)"
            );
            return ExitCode::from(1);
        }
    };

    let network = resolve_network_from_env();

    let validated = match validate_args(args, network) {
        Ok(v) => v,
        Err(msg) => {
            eprintln!("recover_inscription: {msg}");
            return ExitCode::from(1);
        }
    };

    match run_blocking(validated, publisher_key) {
        Ok(()) => ExitCode::SUCCESS,
        Err(msg) => {
            eprintln!("recover_inscription: {msg}");
            ExitCode::from(1)
        }
    }
}
