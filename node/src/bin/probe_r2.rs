//! Wall-clock + peak-RSS probe for the Plonky2 prover hot path.
//!
//! ROADMAP step 9 ("R2 — measure on M3 Ultra") tracks three budgets that
//! the node binary must respect. **Which** circuit those budgets apply
//! to depends on the prover mode (see [`node::r2_budgets`]):
//!
//! ## Legacy (default; flag off)
//!
//! Production parameters `MAX_IN_COINS` = `MAX_OUT_COINS` = 8, Phase 2b
//! outer at degree 16, via `zkcoins_prover::Prover`:
//!
//!   - warm `prove_*` wall ≤ 5 s (target ≤ 1 s)
//!   - cold start (`Prover::new` + first prove) ≤ 30 s
//!   - peak resident-set-size < 64 GB
//!
//! Measures: `Prover::new`, `prove_initial`, `prove_account_update`.
//! Schema columns: `max_in_coins` / `max_out_coins` / `inner_pad_bits`.
//!
//! ## v1.1 (`--prover v1` or `ZKCOINS_V1_SHADOW=1`)
//!
//! Real [`ProverBridge`] construction (eager circuit build via
//! `compliance_gate_count`) and real `prove_transition` calls against
//! v1.1 shape parameters (`MAX_TX_INPUTS` / `MAX_TX_OUTPUTS` /
//! `MAX_RX_COINS`). Budgets are **derived from sealed measurement
//! samples** — never scaled guesses of the legacy 5 s / 30 s numbers.
//! If the calibration is missing or under-sampled the probe refuses
//! loudly rather than silently falling back to the legacy budget
//! (that inverted false-red is exactly what G8 prevents).
//!
//! ## Where to run
//!
//! Run **locally** on the Mac Studio M3 Ultra (96 GB) — that is the
//! reference machine ROADMAP step 9 budgets against. Do NOT run this
//! on the self-hosted CI runner: a single warm sweep dominates
//! the m3-ultra runner slot for 5+ minutes and starves PR jobs.
//!
//! ```sh
//! cargo build --release -p node --bin probe_r2
//! RUST_LOG=warn ./target/release/probe_r2 \
//!     --warm-calls 5 \
//!     --output /tmp/r2-probe-$(date +%s).json
//!
//! # v1.1 path (ProverBridge):
//! RUST_LOG=warn ./target/release/probe_r2 \
//!     --prover v1 --warm-calls 5 \
//!     --output /tmp/r2-probe-v1-$(date +%s).json
//! ```
//!
//! ## Persistence (`--persist`)
//!
//! When `--persist` is set the probe writes its results into Postgres
//! via the `node::r2_probe` module (migration 0013 + 0023):
//!
//!   * one row in `r2_probe_hosts` (idempotent on the natural key);
//!   * one row in `r2_probe_runs` with every scalar measurement plus
//!     run-time context (git sha, rustc version, allocator, circuit
//!     params, `prover_mode`), and the R2 budgets the run was checked
//!     against;
//!   * N rows in `r2_probe_warm_calls`, one per warm call.
//!
//! Requires `DATABASE_URL` — same env var the node binary uses; the
//! probe panics on bootstrap if it is unset, mirroring `node::DATABASE_URL`.
//!
//! ## What it intentionally does NOT do
//!
//! - No Esplora HTTP, no WebSocket subscription.
//! - No on-disk state — the witness lives in RAM.
//! - The warm sweep reuses the same prev proof + witness; we want pure
//!   prove-wall, not the per-send bookkeeping overhead the live node
//!   carries (state lookups, MMR/NfLog appends, DB writes).

// Match the production node binary's allocator (see node/src/main.rs
// and PR #134). The R2 budgets gate the PRD binary, so the probe
// must use the same allocator — otherwise warm-wall and peak-RSS
// numbers diverge from what PRD experiences.
#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Instant;

use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use tokio::runtime::Runtime;

use node::r2_budgets::{
    budgets_for_mode, resolve_prover_mode, ProverMode, R2BudgetSet, LEGACY_BUDGET_COLD_START_MS,
    LEGACY_BUDGET_PEAK_RSS_KB, LEGACY_BUDGET_WARM_PROVE_MS,
};
use node::r2_probe::{
    detect, fetch_recent_summary, insert_run, insert_warm_calls, upsert_host, ProbeRun, SummaryRow,
};
use shared::spec_v1 as host;
use shared::spec_v1::{
    AccountState, Address, Coin, CoinHistTree, CoinTemplate, HashDigest, Nav, ProofData, TreeKind,
};
use zkcoins_program::circuit::compliance::{
    Network, MAX_RX_COINS, MAX_TX_INPUTS, MAX_TX_OUTPUTS,
};
use zkcoins_program::circuit::main::{MAX_IN_COINS, MAX_OUT_COINS, MMR_PROOF_PATH_LEN};
use zkcoins_program::hash::{digest_to_bytes, hash_bytes, hash_concat, HashDigest as LegacyHash, ZERO_HASH};
use zkcoins_program::inputs::CommitmentMerkleProofs;
use zkcoins_program::merkle::merkle_mountain_range::MerkleMountainRange;
use zkcoins_program::merkle::sparse_merkle_tree::SparseMerkleTree;
use zkcoins_program::types::{calculate_asset_id, calculate_name_hash, AccountState as LegacyAccountState};
use zkcoins_prover::prover_bridge::test_signing::{
    deterministic_secret, normalized_key, sign_transition, TestSignature,
};
use zkcoins_prover::prover_bridge::{
    AssetIssuance, InputAuthorization, NavOpening, NullifierOpening, PredecessorNullifier,
    ProvedTransition, ProverBridge, TransitionMode, TransitionWitness,
};
use zkcoins_prover::{MintWitness, Prover};

/// Inner-pad-bits constant the active Phase 2b shape was built with
/// (see `INNER_PAD_BITS_STAGE_5D_NEXT_5` in
/// `program-plonky2/src/circuit/main.rs`). Recorded so the R2
/// regression view can later answer "did the prove wall move when
/// we changed pad bits?". Legacy-only; v1.1 has no pad-bits concept.
const INNER_PAD_BITS: i32 = 15;

// ===== CLI =====

#[derive(Debug)]
struct CliArgs {
    warm_calls: usize,
    output: Option<PathBuf>,
    persist: bool,
    notes: Option<String>,
    tags: Vec<String>,
    /// Explicit CLI budget overrides. `None` means "use the mode's
    /// sealed budget set" — never a silent cross-mode fall-back.
    warm_budget_ms: Option<i64>,
    cold_budget_ms: Option<i64>,
    mem_budget_kb: Option<i64>,
    /// `None` → resolve from `ZKCOINS_V1_SHADOW` (default legacy).
    prover: Option<String>,
    /// Network for the v1.1 bridge (default testnet).
    network: Network,
}

fn print_usage(program: &str) {
    eprintln!(
        "usage: {program} [--warm-calls N] [--output <path>] [--persist] \
                [--notes <text>] [--tags a,b,c] \
                [--prover legacy|v1] [--network mainnet|testnet|regtest] \
                [--warm-budget-ms <ms>] [--cold-budget-ms <ms>] [--mem-budget-kb <kb>]

  --warm-calls N      number of warm prove calls (default 5)
  --output PATH       write JSON report to PATH (default: stdout)
  --persist           persist results into Postgres (requires DATABASE_URL)
  --notes TEXT        free-form note attached to the persisted run
  --tags A,B,C        comma-separated tags attached to the persisted run
  --prover MODE       legacy (default) or v1 (ProverBridge). When omitted,
                      ZKCOINS_V1_SHADOW=1 selects v1; unset/empty/off → legacy.
  --network NAME      v1 only: mainnet|testnet|regtest (default testnet)
  --warm-budget-ms N  override warm prove budget for this run only
  --cold-budget-ms N  override cold-start budget for this run only
  --mem-budget-kb N   override peak-RSS budget for this run only

Default budgets (when no override is given) come from the mode's sealed
set in node::r2_budgets — legacy ROADMAP constants, or measurement-derived
v1.1 numbers. Missing v1.1 calibration refuses rather than falling back.

env:
  DATABASE_URL         required when --persist is set
  ZKCOINS_V1_SHADOW   selects v1 when --prover is omitted (1 = v1)
  GIT_SHA              optional override for the recorded git sha
  RUSTC_VERSION        optional override for the recorded rustc version
  RUST_LOG             optional, log level (defaults to off here)

legacy default budgets (flag off):
  warm={warm} ms  cold={cold} ms  mem={mem} KB
",
        warm = LEGACY_BUDGET_WARM_PROVE_MS,
        cold = LEGACY_BUDGET_COLD_START_MS,
        mem = LEGACY_BUDGET_PEAK_RSS_KB
    );
}

fn parse_args(argv: Vec<String>) -> Result<CliArgs, String> {
    let mut iter = argv.into_iter();
    let program = iter.next().unwrap_or_else(|| "probe_r2".into());

    let mut warm_calls: usize = 5;
    let mut output: Option<PathBuf> = None;
    let mut persist = false;
    let mut notes: Option<String> = None;
    let mut tags: Vec<String> = Vec::new();
    let mut warm_budget_ms: Option<i64> = None;
    let mut cold_budget_ms: Option<i64> = None;
    let mut mem_budget_kb: Option<i64> = None;
    let mut prover: Option<String> = None;
    let mut network = Network::Testnet;

    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--warm-calls" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--warm-calls requires a value".to_string())?;
                warm_calls = v
                    .parse::<usize>()
                    .map_err(|e| format!("--warm-calls: {e}"))?;
            }
            "--output" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--output requires a value".to_string())?;
                output = Some(PathBuf::from(v));
            }
            "--persist" => {
                persist = true;
            }
            "--notes" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--notes requires a value".to_string())?;
                notes = Some(v);
            }
            "--tags" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--tags requires a value".to_string())?;
                tags = v
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .collect();
            }
            "--prover" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--prover requires a value".to_string())?;
                prover = Some(v);
            }
            "--network" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--network requires a value".to_string())?;
                network = match v.as_str() {
                    "mainnet" => Network::Mainnet,
                    "testnet" => Network::Testnet,
                    "regtest" => Network::Regtest,
                    other => {
                        return Err(format!(
                            "--network={other:?} is not supported; expected mainnet|testnet|regtest"
                        ))
                    }
                };
            }
            "--warm-budget-ms" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--warm-budget-ms requires a value".to_string())?;
                warm_budget_ms = Some(
                    v.parse::<i64>()
                        .map_err(|e| format!("--warm-budget-ms: {e}"))?,
                );
            }
            "--cold-budget-ms" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--cold-budget-ms requires a value".to_string())?;
                cold_budget_ms = Some(
                    v.parse::<i64>()
                        .map_err(|e| format!("--cold-budget-ms: {e}"))?,
                );
            }
            "--mem-budget-kb" => {
                let v = iter
                    .next()
                    .ok_or_else(|| "--mem-budget-kb requires a value".to_string())?;
                mem_budget_kb = Some(
                    v.parse::<i64>()
                        .map_err(|e| format!("--mem-budget-kb: {e}"))?,
                );
            }
            "-h" | "--help" => {
                print_usage(&program);
                std::process::exit(0);
            }
            other => return Err(format!("unknown argument: {other}")),
        }
    }

    Ok(CliArgs {
        warm_calls,
        output,
        persist,
        notes,
        tags,
        warm_budget_ms,
        cold_budget_ms,
        mem_budget_kb,
        prover,
        network,
    })
}

// ===== Witness construction (legacy) =====

/// Stable test pubkey, mirrors the helper in
/// `script-plonky2/src/lib.rs::tests::dummy_pubkey`.
fn dummy_pubkey(seed: u8) -> [u8; 33] {
    let mut pk = [0u8; 33];
    pk[0] = 0x02;
    for (i, b) in pk.iter_mut().enumerate().skip(1) {
        *b = seed.wrapping_add(i as u8);
    }
    pk
}

/// Off-circuit `CommitmentMerkleProofs` witness. Mirrors the private
/// `build_test_commitment_witness` helper in
/// `program-plonky2/src/circuit/main.rs` (test module — not reachable
/// from this crate). Reproduced here so the probe doesn't need a test
/// re-export.
fn build_commitment_witness(
    prev_asth: LegacyHash,
    prev_ocr: LegacyHash,
) -> (CommitmentMerkleProofs, LegacyHash) {
    let pk_hash = hash_bytes(b"probe-r2-pubkey");
    let pk_key = digest_to_bytes(&pk_hash);

    let commitment = hash_concat(&prev_asth, &prev_ocr);

    let mut smt = SparseMerkleTree::new();
    smt.insert(pk_key, commitment)
        .expect("smt insert (fresh key into fresh tree)");
    let smt_root = smt.root();
    let (smt_inclusion, _) = smt
        .generate_inclusion_proof(&pk_key)
        .expect("smt inclusion proof");

    let prev_mmr_root = ZERO_HASH;
    let mmr_leaf = hash_concat(&smt_root, &prev_mmr_root);
    let mut mmr = MerkleMountainRange::new();
    mmr.append(mmr_leaf);
    let history_root_extended = mmr.root_extended(MMR_PROOF_PATH_LEN);
    let mmr_proof = mmr
        .get_proof(0)
        .expect("mmr proof for leaf 0")
        .extend_to(MMR_PROOF_PATH_LEN);

    let cmp = CommitmentMerkleProofs {
        commitment_root: smt_root,
        commitment_proof: smt_inclusion,
        commitment_root_history_proof: mmr_proof.clone(),
        commitment_root_mmr_sibling: prev_mmr_root,
        previous_root_history_proof: (smt_root, mmr_proof),
        commitment_account_state_hash: prev_asth,
        commitment_out_coins_root: prev_ocr,
    };
    (cmp, history_root_extended)
}

// ===== Witness construction (v1.1) =====

struct V1GenesisFixture {
    witness: TransitionWitness,
    output_coin: Coin,
    asset_id: HashDigest,
    nav_opening: NavOpening,
    signature: TestSignature,
}

/// Host-valid Initial (mint) witness for the probe. Mirrors the
/// `prover_bridge` / `state_engine` genesis fixtures so the timed path
/// is a real `prove_transition`, not a hollow shell.
fn v1_genesis_fixture(network: Network) -> V1GenesisFixture {
    let nk: [u8; 32] = Sha256::digest(b"zkCoins/v1/compliance-chain/nk").into();
    let nk_commit = host::nk_commit(&nk);
    let (secret, public, current_pubkey) = normalized_key(deterministic_secret(
        b"zkCoins/v1/compliance-chain/spend-key-0",
    ));
    let (_, _, next_pubkey) = normalized_key(deterministic_secret(
        b"zkCoins/v1/compliance-chain/spend-key-1",
    ));
    let owner = Address(host::address(&current_pubkey, nk_commit));
    let name_hash: [u8; 32] = Sha256::digest(b"Recursive Fixture Asset").into();
    let asset_id = host::asset_id_v1(host::GENESIS_TAG, &current_pubkey, &name_hash, 2, 1);
    let issuance = AssetIssuance {
        asset_id,
        creator_pubkey: current_pubkey,
        issuance_version: 1,
        name_hash,
        decimals: 2,
        amount: 100,
        terms_hash: host::terms_hash_v1(asset_id, 1),
        cap_total: 0,
        terms_salt: [0u8; 32],
    };
    let prev_account_state = AccountState::new(
        owner,
        nk_commit,
        BTreeMap::new(),
        current_pubkey,
        0,
        host::coinhist_empty_root(),
    )
    .expect("prev account state");
    let prev_ash = host::account_state_hash(&prev_account_state).expect("prev ash");
    let output_template = CoinTemplate {
        recipient: owner,
        amount: 100,
        asset_id,
    };
    let output_coin = Coin {
        identifier: host::coin_identifier(prev_ash, &owner.0, asset_id, 100, 0),
        recipient: owner,
        amount: 100,
        asset_id,
    };
    let mut history = CoinHistTree::new();
    let output_history = history.prove(host::digest_to_bytes(&output_coin.identifier));
    history
        .admit(host::digest_to_bytes(&output_coin.identifier))
        .expect("admit output");
    let mut balances = BTreeMap::new();
    balances.insert(host::digest_to_bytes(&asset_id), 100);
    let new_account_state =
        AccountState::new(owner, nk_commit, balances, next_pubkey, 1, history.root())
            .expect("new account state");
    let prefix_entry = host::NfLogEntry {
        pk: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-pk").into(),
        r: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-r").into(),
    };
    let nav_opening = NavOpening {
        nav: Nav {
            size: 1,
            mth: host::nflog_mth(&[prefix_entry]),
        },
        nav_rand: [0x2bu8; 32],
    };
    let npk_rand = [0x4du8; 32];
    let proof_data = ProofData {
        new_account_state_hash: host::account_state_hash(&new_account_state).expect("new ash"),
        output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &[output_coin.identifier]),
        input_nullifiers_root: host::merkle_root(TreeKind::NullifiersRoot, &[]),
        coin_history_root: new_account_state.coin_history_root,
        nav_commitment: host::nav_commitment(nav_opening.nav.root(), &nav_opening.nav_rand),
        npk_commit: host::npk_commit(&next_pubkey, &npk_rand),
    };
    let signature = sign_transition(secret, public, &proof_data, network);
    V1GenesisFixture {
        witness: TransitionWitness {
            mode: TransitionMode::InitialProof,
            prev_account_state,
            new_account_state,
            input_coins: Vec::new(),
            input_auth: Vec::new(),
            output_templates: vec![output_template],
            output_coins: vec![output_coin.clone()],
            output_history_proofs: vec![Some(output_history)],
            received_coins: Vec::new(),
            received_auth: Vec::new(),
            asset_issuance: Some(issuance),
            nk,
            nav: nav_opening.nav,
            nav_rand: nav_opening.nav_rand,
            prev_nav_opening: None,
            nav_consistency: Vec::new(),
            next_pubkey,
            npk_rand,
            transition_signature: signature.transition.clone(),
            prev_proof: None,
            predecessor_nullifier: None,
        },
        output_coin,
        asset_id,
        nav_opening,
        signature,
    }
}

fn v1_send_witness(
    genesis: &V1GenesisFixture,
    genesis_proof: &ProvedTransition,
    network: Network,
) -> TransitionWitness {
    let prev_account_state = genesis.witness.new_account_state.clone();
    let prev_ash = genesis_proof.proof_data.new_account_state_hash;
    let input_coin = genesis.output_coin.clone();
    let input_auth_creating_prev_ash =
        host::account_state_hash(&genesis.witness.prev_account_state).expect("creating ash");
    let owner = prev_account_state.owner;
    let templates = vec![
        CoinTemplate {
            recipient: owner,
            amount: 70,
            asset_id: genesis.asset_id,
        },
        CoinTemplate {
            recipient: Address([0x82u8; 32]),
            amount: 30,
            asset_id: genesis.asset_id,
        },
    ];
    let output_coins: Vec<_> = templates
        .iter()
        .enumerate()
        .map(|(index, template)| Coin {
            identifier: host::coin_identifier(
                prev_ash,
                &template.recipient.0,
                template.asset_id,
                template.amount,
                index as u32,
            ),
            recipient: template.recipient,
            amount: template.amount,
            asset_id: template.asset_id,
        })
        .collect();
    let mut history = CoinHistTree::new();
    history
        .admit(host::digest_to_bytes(&input_coin.identifier))
        .expect("admit input");
    let input_history = history.prove(host::digest_to_bytes(&input_coin.identifier));
    history
        .spend(host::digest_to_bytes(&input_coin.identifier))
        .expect("spend input");
    let self_output_history = history.prove(host::digest_to_bytes(&output_coins[0].identifier));
    history
        .admit(host::digest_to_bytes(&output_coins[0].identifier))
        .expect("admit self-out");
    let mut balances = BTreeMap::new();
    balances.insert(host::digest_to_bytes(&genesis.asset_id), 70);
    let (secret, public, current_pubkey) = normalized_key(deterministic_secret(
        b"zkCoins/v1/compliance-chain/spend-key-1",
    ));
    assert_eq!(current_pubkey, prev_account_state.current_pubkey);
    let (_, _, next_pubkey) = normalized_key(deterministic_secret(
        b"zkCoins/v1/compliance-chain/spend-key-2",
    ));
    let new_account_state = AccountState::new(
        owner,
        prev_account_state.nk_commit,
        balances,
        next_pubkey,
        2,
        history.root(),
    )
    .expect("send new state");
    let prefix_entry = host::NfLogEntry {
        pk: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-pk").into(),
        r: Sha256::digest(b"zkCoins/v1/compliance-chain/prefix-r").into(),
    };
    let predecessor_entry = host::NfLogEntry {
        pk: genesis.witness.prev_account_state.current_pubkey,
        r: genesis.signature.transition.signature_r(),
    };
    let entries = [prefix_entry, predecessor_entry];
    let nav = Nav {
        size: 2,
        mth: host::nflog_mth(&entries),
    };
    let nav_rand = [0x3cu8; 32];
    let npk_rand = [0xa5u8; 32];
    let output_ids: Vec<_> = output_coins.iter().map(|coin| coin.identifier).collect();
    let proof_data = ProofData {
        new_account_state_hash: host::account_state_hash(&new_account_state).expect("send ash"),
        output_coins_root: host::merkle_root(TreeKind::CoinsRoot, &output_ids),
        input_nullifiers_root: host::merkle_root(
            TreeKind::NullifiersRoot,
            &[host::nullifier(&genesis.witness.nk, input_coin.identifier)],
        ),
        coin_history_root: new_account_state.coin_history_root,
        nav_commitment: host::nav_commitment(nav.root(), &nav_rand),
        npk_commit: host::npk_commit(&next_pubkey, &npk_rand),
    };
    let signature = sign_transition(secret, public, &proof_data, network);
    // S2C opening of the genesis nullifier — already encoded on the
    // transition signature produced by `sign_transition`.
    let r_prime_bytes = genesis.signature.transition.r_prime;

    TransitionWitness {
        mode: TransitionMode::AccountUpdateProof,
        prev_account_state,
        new_account_state,
        input_coins: vec![input_coin],
        input_auth: vec![InputAuthorization {
            creating_prev_ash: input_auth_creating_prev_ash,
            coin_index: 0,
            history_proof: input_history,
        }],
        output_templates: templates,
        output_coins,
        output_history_proofs: vec![Some(self_output_history), None],
        received_coins: Vec::new(),
        received_auth: Vec::new(),
        asset_issuance: None,
        nk: genesis.witness.nk,
        nav,
        nav_rand,
        prev_nav_opening: Some(genesis.nav_opening),
        nav_consistency: host::consistency_proof(1, &entries).expect("nav consistency"),
        next_pubkey,
        npk_rand,
        transition_signature: signature.transition,
        prev_proof: Some(genesis_proof.proof.clone()),
        predecessor_nullifier: Some(PredecessorNullifier {
            nullifier: NullifierOpening {
                public_key: predecessor_entry.pk,
                signature_r: predecessor_entry.r,
                r_prime: r_prime_bytes,
            },
            nav_inclusion: host::inclusion_path(1, &entries).expect("nav inclusion"),
            position: 1,
        }),
    }
}

// ===== RSS sampling =====

/// Return current peak resident-set-size in KB.
///
/// `getrusage(RUSAGE_SELF).ru_maxrss` is the cleanest cross-platform
/// path. The unit differs by OS:
///
///   - Linux: kilobytes (already what we want).
///   - macOS / iOS / FreeBSD: bytes — divide by 1024.
///
/// `ru_maxrss` is the high-water mark over the process lifetime, so
/// calling this once at the end of the run is sufficient — sampling
/// during the prove loop would be wasted work.
fn peak_rss_kb() -> u64 {
    // SAFETY: `getrusage` is a POSIX syscall with no preconditions
    // beyond a valid out-param, which we provide as a fully-initialised
    // zeroed struct.
    let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) };
    if rc != 0 {
        return 0;
    }
    let raw = usage.ru_maxrss as u64;
    if cfg!(target_os = "macos") || cfg!(target_os = "ios") || cfg!(target_os = "freebsd") {
        raw / 1024
    } else {
        raw
    }
}

// ===== Run-time context =====

fn detect_git_sha() -> String {
    if let Ok(v) = std::env::var("GIT_SHA") {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn detect_rustc_version() -> String {
    if let Ok(v) = std::env::var("RUSTC_VERSION") {
        if !v.trim().is_empty() {
            return v.trim().to_string();
        }
    }
    std::process::Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Compute a percentile (0..=100) of `samples` in milliseconds. Uses
/// the nearest-rank method — adequate for the small N this probe
/// captures (typically 5–20 warm calls).
fn percentile_ms(samples: &[i64], p: f64) -> Option<i64> {
    if samples.is_empty() {
        return None;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let n = sorted.len();
    let rank = ((p / 100.0) * n as f64).ceil() as usize;
    let idx = rank.saturating_sub(1).min(n - 1);
    Some(sorted[idx])
}

// ===== Measurement results =====

struct MeasureResult {
    circuit_build_wall_ms: i64,
    prove_cold_wall_ms: i64,
    verify_wall_ms: i64,
    prove_warm_wall_ms: Vec<i64>,
    peak_rss_kb: i64,
    /// Legacy: max_in / max_out / pad. v1: also tx shape + gate count.
    max_in_coins: i32,
    max_out_coins: i32,
    inner_pad_bits: i32,
    max_tx_inputs: Option<i32>,
    max_tx_outputs: Option<i32>,
    max_rx_coins: Option<i32>,
    compliance_gate_count: Option<i32>,
}

fn measure_legacy(warm_calls: usize) -> Result<MeasureResult, String> {
    eprintln!("[probe_r2] mode=legacy — Prover::new + prove_initial / prove_account_update");
    eprintln!(
        "[probe_r2] shape MAX_IN_COINS={MAX_IN_COINS} MAX_OUT_COINS={MAX_OUT_COINS} \
         INNER_PAD_BITS={INNER_PAD_BITS}"
    );

    eprintln!("[probe_r2] building circuit (cold) ...");
    let t = Instant::now();
    let prover = Prover::new();
    let circuit_build_wall_ms = t.elapsed().as_millis() as i64;
    eprintln!("[probe_r2] circuit_build_wall_ms = {circuit_build_wall_ms}");

    let creator_pubkey = dummy_pubkey(7);
    let name_hash = calculate_name_hash("PROBE");
    let decimals: u8 = 8;
    let asset_id = calculate_asset_id(&creator_pubkey, &name_hash, decimals);
    let mut account_state = LegacyAccountState::new(creator_pubkey, asset_id);
    account_state.balance = 1_000_000;
    let mint_witness = MintWitness {
        creator_pubkey,
        name_hash,
        decimals,
    };

    eprintln!("[probe_r2] proving initial (cold) ...");
    let t = Instant::now();
    let init_proof = prover
        .prove_initial(&account_state, ZERO_HASH, asset_id, Some(mint_witness))
        .map_err(|e| format!("prove_initial: {e}"))?;
    let prove_cold_wall_ms = t.elapsed().as_millis() as i64;
    eprintln!("[probe_r2] prove_cold_wall_ms = {prove_cold_wall_ms}");

    let t = Instant::now();
    prover
        .verify(&init_proof)
        .map_err(|e| format!("verify cold init: {e}"))?;
    let verify_wall_ms = t.elapsed().as_millis() as i64;

    let prev_asth = account_state.hash();
    let prev_ocr = init_proof_out_coins_root_from_init(&prev_asth);
    let (cmp, history_root_extended) = build_commitment_witness(prev_asth, prev_ocr);

    let mut prove_warm_wall_ms: Vec<i64> = Vec::with_capacity(warm_calls);
    for i in 0..warm_calls {
        eprintln!("[probe_r2] warm prove {} / {} ...", i + 1, warm_calls);
        let t = Instant::now();
        let update_proof = prover
            .prove_account_update(
                &account_state,
                history_root_extended,
                &init_proof,
                &cmp,
                asset_id,
            )
            .map_err(|e| format!("warm prove_account_update #{i}: {e}"))?;
        let ms = t.elapsed().as_millis() as i64;
        prove_warm_wall_ms.push(ms);
        eprintln!("[probe_r2] warm[{i}] = {ms} ms");

        if i == 0 {
            prover
                .verify(&update_proof)
                .map_err(|e| format!("verify warm #{i}: {e}"))?;
        }
    }

    Ok(MeasureResult {
        circuit_build_wall_ms,
        prove_cold_wall_ms,
        verify_wall_ms,
        prove_warm_wall_ms,
        peak_rss_kb: peak_rss_kb() as i64,
        max_in_coins: MAX_IN_COINS as i32,
        max_out_coins: MAX_OUT_COINS as i32,
        inner_pad_bits: INNER_PAD_BITS,
        max_tx_inputs: None,
        max_tx_outputs: None,
        max_rx_coins: None,
        compliance_gate_count: None,
    })
}

fn measure_v1(warm_calls: usize, network: Network) -> Result<MeasureResult, String> {
    eprintln!(
        "[probe_r2] mode=v1 — ProverBridge + prove_transition (network={network:?})"
    );
    eprintln!(
        "[probe_r2] shape MAX_TX_INPUTS={MAX_TX_INPUTS} MAX_TX_OUTPUTS={MAX_TX_OUTPUTS} \
         MAX_RX_COINS={MAX_RX_COINS}"
    );

    // ProverBridge::new is cheap (stores the network). The real circuit
    // build is deferred to first use — force it via compliance_gate_count
    // so circuit_build_wall_ms is comparable to legacy Prover::new.
    let bridge = ProverBridge::new(network);
    eprintln!("[probe_r2] building C circuit (cold, via compliance_gate_count) ...");
    let t = Instant::now();
    let gate_count = bridge.compliance_gate_count();
    let circuit_build_wall_ms = t.elapsed().as_millis() as i64;
    eprintln!(
        "[probe_r2] circuit_build_wall_ms = {circuit_build_wall_ms} (gates={gate_count})"
    );

    let genesis = v1_genesis_fixture(network);

    eprintln!("[probe_r2] proving transition Initial (cold) ...");
    let t = Instant::now();
    let proved_genesis = bridge
        .prove_transition(&genesis.witness)
        .map_err(|e| format!("prove_transition Initial: {e}"))?;
    let prove_cold_wall_ms = t.elapsed().as_millis() as i64;
    eprintln!("[probe_r2] prove_cold_wall_ms = {prove_cold_wall_ms}");

    let t = Instant::now();
    bridge
        .verify_transition(&proved_genesis.proof)
        .map_err(|e| format!("verify cold Initial: {e}"))?;
    let verify_wall_ms = t.elapsed().as_millis() as i64;

    // Build the AccountUpdate witness ONCE and reuse across warm calls.
    let send = v1_send_witness(&genesis, &proved_genesis, network);

    let mut prove_warm_wall_ms: Vec<i64> = Vec::with_capacity(warm_calls);
    for i in 0..warm_calls {
        eprintln!("[probe_r2] warm prove_transition {} / {} ...", i + 1, warm_calls);
        let t = Instant::now();
        let proved_send = bridge
            .prove_transition(&send)
            .map_err(|e| format!("warm prove_transition AccountUpdate #{i}: {e}"))?;
        let ms = t.elapsed().as_millis() as i64;
        prove_warm_wall_ms.push(ms);
        eprintln!("[probe_r2] warm[{i}] = {ms} ms");

        if i == 0 {
            bridge
                .verify_transition(&proved_send.proof)
                .map_err(|e| format!("verify warm #{i}: {e}"))?;
        }
    }

    Ok(MeasureResult {
        circuit_build_wall_ms,
        prove_cold_wall_ms,
        verify_wall_ms,
        prove_warm_wall_ms,
        peak_rss_kb: peak_rss_kb() as i64,
        // Sibling columns: record the v1.1 shape under both the legacy
        // names (operators grepping max_in_coins still see 8) and the
        // dedicated v1.1 columns.
        max_in_coins: MAX_TX_INPUTS as i32,
        max_out_coins: MAX_TX_OUTPUTS as i32,
        // No pad-bits concept on C; 0 is an explicit "not applicable"
        // marker, distinguished from legacy 15 by prover_mode='v1'.
        inner_pad_bits: 0,
        max_tx_inputs: Some(MAX_TX_INPUTS as i32),
        max_tx_outputs: Some(MAX_TX_OUTPUTS as i32),
        max_rx_coins: Some(MAX_RX_COINS as i32),
        compliance_gate_count: Some(gate_count as i32),
    })
}

/// Resolve the budgets that this run will be checked against.
///
/// * When **all three** CLI overrides are set, use them and skip the
///   sealed set entirely. This is the measurement-campaign path: an
///   operator can collect samples before any v1.1 budget is sealed,
///   without the probe refusing on missing calibration.
/// * Otherwise every unset metric comes from [`budgets_for_mode`],
///   which refuses for v1 when calibration is missing — never a
///   silent fall-back to the legacy ROADMAP numbers for a partial
///   override (that would be the inverted false-red).
fn resolve_run_budgets(mode: ProverMode, args: &CliArgs) -> Result<R2BudgetSet, String> {
    match (
        args.warm_budget_ms,
        args.cold_budget_ms,
        args.mem_budget_kb,
    ) {
        (Some(warm), Some(cold), Some(mem)) => Ok(R2BudgetSet {
            warm_prove_ms: warm,
            cold_start_ms: cold,
            peak_rss_kb: mem,
        }),
        (warm_opt, cold_opt, mem_opt) => {
            let sealed = budgets_for_mode(mode).map_err(|e| {
                format!(
                    "{e}; to run a calibration campaign before sealing, pass all three \
                     of --warm-budget-ms / --cold-budget-ms / --mem-budget-kb (partial \
                     override is refused so a missing metric cannot silently inherit \
                     another circuit's number)"
                )
            })?;
            Ok(R2BudgetSet {
                warm_prove_ms: warm_opt.unwrap_or(sealed.warm_prove_ms),
                cold_start_ms: cold_opt.unwrap_or(sealed.cold_start_ms),
                peak_rss_kb: mem_opt.unwrap_or(sealed.peak_rss_kb),
            })
        }
    }
}

// ===== Main =====

fn run() -> Result<(), String> {
    let args = parse_args(std::env::args().collect())?;

    let shadow_raw = match std::env::var("ZKCOINS_V1_SHADOW") {
        Ok(v) => Some(v),
        Err(std::env::VarError::NotPresent) => None,
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(
                "ZKCOINS_V1_SHADOW is not valid UTF-8; refusing to select a prover mode".into(),
            )
        }
    };
    let mode = resolve_prover_mode(args.prover.as_deref(), shadow_raw.as_deref())?;
    let budgets = resolve_run_budgets(mode, &args)?;

    eprintln!(
        "[probe_r2] starting — mode={mode} warm_calls={} budgets: warm={} cold={} mem={} KB",
        args.warm_calls, budgets.warm_prove_ms, budgets.cold_start_ms, budgets.peak_rss_kb
    );
    eprintln!(
        "[probe_r2] os={} arch={}",
        std::env::consts::OS,
        std::env::consts::ARCH
    );

    let host_info = detect();
    let git_sha = detect_git_sha();
    let rustc_version = detect_rustc_version();

    let measured = match mode {
        ProverMode::Legacy => measure_legacy(args.warm_calls)?,
        ProverMode::V1 => measure_v1(args.warm_calls, args.network)?,
    };

    // ===== Report =====

    let cold_start_ms = measured.circuit_build_wall_ms + measured.prove_cold_wall_ms;
    let warm_p50 = percentile_ms(&measured.prove_warm_wall_ms, 50.0);
    let warm_p90 = percentile_ms(&measured.prove_warm_wall_ms, 90.0);
    let warm_p99 = percentile_ms(&measured.prove_warm_wall_ms, 99.0);
    let warm_min = measured.prove_warm_wall_ms.iter().min().copied().unwrap_or(0);
    let warm_max = measured.prove_warm_wall_ms.iter().max().copied().unwrap_or(0);
    let warm_mean = if measured.prove_warm_wall_ms.is_empty() {
        0
    } else {
        measured.prove_warm_wall_ms.iter().sum::<i64>() / measured.prove_warm_wall_ms.len() as i64
    };

    let report = json!({
        "platform": {
            "os": std::env::consts::OS,
            "arch": std::env::consts::ARCH,
            "hostname": host_info.hostname,
            "cpu_brand": host_info.cpu_brand,
            "cpu_cores": host_info.cpu_cores,
            "total_ram_gb": host_info.total_ram_gb,
        },
        "git_sha": git_sha,
        "rustc_version": rustc_version,
        "build_profile": "release",
        "allocator": "mimalloc",
        "prover_mode": mode.as_str(),
        "max_in_coins": measured.max_in_coins,
        "max_out_coins": measured.max_out_coins,
        "inner_pad_bits": measured.inner_pad_bits,
        "max_tx_inputs": measured.max_tx_inputs,
        "max_tx_outputs": measured.max_tx_outputs,
        "max_rx_coins": measured.max_rx_coins,
        "compliance_gate_count": measured.compliance_gate_count,
        "warm_calls_requested": args.warm_calls,
        "circuit_build_wall_ms": measured.circuit_build_wall_ms,
        "prove_cold_wall_ms": measured.prove_cold_wall_ms,
        "verify_wall_ms": measured.verify_wall_ms,
        "prove_warm_wall_ms": measured.prove_warm_wall_ms,
        "prove_warm_p50_ms": warm_p50,
        "prove_warm_p90_ms": warm_p90,
        "prove_warm_p99_ms": warm_p99,
        "peak_rss_kb": measured.peak_rss_kb,
        "rss_unit_note":
            "macOS reports ru_maxrss in bytes; Linux reports KB. This tool normalises to KB.",
        "budgets": {
            "warm_prove_ms_max": budgets.warm_prove_ms,
            "cold_start_ms_max": budgets.cold_start_ms,
            "peak_rss_kb_max": budgets.peak_rss_kb,
        },
        "notes": args.notes,
        "tags": args.tags,
    });

    let json_text =
        serde_json::to_string_pretty(&report).map_err(|e| format!("serialise report: {e}"))?;

    if let Some(path) = args.output.as_ref() {
        let mut f =
            fs::File::create(path).map_err(|e| format!("create {}: {e}", path.display()))?;
        f.write_all(json_text.as_bytes())
            .map_err(|e| format!("write {}: {e}", path.display()))?;
        f.write_all(b"\n")
            .map_err(|e| format!("write nl {}: {e}", path.display()))?;
        eprintln!("[probe_r2] report -> {}", path.display());
    } else {
        println!("{json_text}");
    }

    // ===== Optional persistence =====

    let mut history_after: Option<Vec<SummaryRow>> = None;
    if args.persist {
        let database_url = std::env::var("DATABASE_URL").map_err(|_| {
            "--persist requires DATABASE_URL to be set (e.g. \
             postgresql://zkcoins:<pw>@postgres:5432/zkcoins)"
                .to_string()
        })?;
        eprintln!("[probe_r2] persisting to DATABASE_URL ...");

        let rt = Runtime::new().map_err(|e| format!("tokio runtime: {e}"))?;
        let rows = rt.block_on(async {
            let pool = PgPoolOptions::new()
                .max_connections(2)
                .connect(&database_url)
                .await
                .map_err(|e| format!("connect DATABASE_URL: {e}"))?;
            let host_id = upsert_host(&pool, &host_info)
                .await
                .map_err(|e| format!("upsert_host: {e}"))?;
            let run_row = ProbeRun {
                host_id,
                git_sha: git_sha.clone(),
                binary_version: env!("CARGO_PKG_VERSION").to_string(),
                rustc_version: rustc_version.clone(),
                build_profile: "release".to_string(),
                allocator: "mimalloc".to_string(),
                prover_mode: mode.as_str().to_string(),
                max_in_coins: measured.max_in_coins,
                max_out_coins: measured.max_out_coins,
                inner_pad_bits: measured.inner_pad_bits,
                max_tx_inputs: measured.max_tx_inputs,
                max_tx_outputs: measured.max_tx_outputs,
                max_rx_coins: measured.max_rx_coins,
                compliance_gate_count: measured.compliance_gate_count,
                warm_calls_requested: args.warm_calls as i32,
                circuit_build_wall_ms: measured.circuit_build_wall_ms,
                prove_cold_wall_ms: measured.prove_cold_wall_ms,
                verify_wall_ms: measured.verify_wall_ms,
                peak_rss_kb: measured.peak_rss_kb,
                prove_warm_p50_ms: warm_p50,
                prove_warm_p90_ms: warm_p90,
                prove_warm_p99_ms: warm_p99,
                succeeded: true,
                error_message: None,
                notes: args.notes.clone(),
                tags: args.tags.clone(),
                r2_warm_budget_ms: budgets.warm_prove_ms,
                r2_cold_budget_ms: budgets.cold_start_ms,
                r2_mem_budget_kb: budgets.peak_rss_kb,
            };
            let run_id = insert_run(&pool, &run_row)
                .await
                .map_err(|e| format!("insert_run: {e}"))?;
            insert_warm_calls(&pool, run_id, &measured.prove_warm_wall_ms)
                .await
                .map_err(|e| format!("insert_warm_calls: {e}"))?;
            let rows = fetch_recent_summary(&pool, 5)
                .await
                .map_err(|e| format!("fetch_recent_summary: {e}"))?;
            Ok::<Vec<SummaryRow>, String>(rows)
        })?;
        eprintln!(
            "[probe_r2] persisted run; {} recent rows read back",
            rows.len()
        );
        history_after = Some(rows);
    }

    // Console verdict against the three ROADMAP budgets for this mode.
    let warm_ok = (warm_p50.unwrap_or(i64::MAX)) <= budgets.warm_prove_ms;
    let cold_ok = cold_start_ms <= budgets.cold_start_ms;
    let rss_ok = measured.peak_rss_kb <= budgets.peak_rss_kb;

    eprintln!();
    eprintln!("===== ROADMAP step 9 budgets (mode={mode}) =====");
    eprintln!(
        "  warm prove p50 over {} calls: {} ms   {}  [budget {} ms]",
        args.warm_calls,
        warm_p50
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".into()),
        check(warm_ok),
        budgets.warm_prove_ms
    );
    eprintln!(
        "  cold start (build + first prove): {} ms   {}  [budget {} ms]",
        cold_start_ms,
        check(cold_ok),
        budgets.cold_start_ms
    );
    eprintln!(
        "  peak RSS: {} KB ({} MiB)   {}  [budget {} KB]",
        measured.peak_rss_kb,
        measured.peak_rss_kb / 1024,
        check(rss_ok),
        budgets.peak_rss_kb
    );
    eprintln!();
    eprintln!(
        "  warm distribution: min {} / mean {} / max {} ms",
        warm_min, warm_mean, warm_max
    );

    if let Some(rows) = history_after.as_ref() {
        print_history_table(rows);
    }

    Ok(())
}

fn check(ok: bool) -> &'static str {
    if ok {
        "PASS"
    } else {
        "FAIL"
    }
}

/// ASCII trend table — last few persisted runs newest first. Width
/// is tuned for an 80-column terminal; the columns map 1:1 to the
/// `r2_probe_runs_summary` view.
///
/// `coldstart_ms` is `circuit_build_wall_ms + prove_cold_wall_ms` to
/// match the cold-start budget. The `C` pass marker in the same row
/// reads the view's `r2_cold_pass` which is computed against the same
/// sum — so the number the operator sees is exactly what the pass/fail
/// is judged against.
fn print_history_table(rows: &[SummaryRow]) {
    eprintln!();
    eprintln!("===== Recent runs (from DB) =====");
    eprintln!(
        "  {:<25} {:<8} {:<14} {:>12} {:>9} {:>10}  W  C  M",
        "ran_at", "mode", "git_sha", "coldstart_ms", "warm_p50", "rss_kb"
    );
    for r in rows {
        let git_sha_short = r.git_sha.chars().take(12).collect::<String>();
        let warm_p50 = r
            .prove_warm_p50_ms
            .map(|v| v.to_string())
            .unwrap_or_else(|| "n/a".into());
        let cold_start_ms = r.circuit_build_wall_ms + r.prove_cold_wall_ms;
        eprintln!(
            "  {:<25} {:<8} {:<14} {:>12} {:>9} {:>10}  {} {} {}",
            r.ran_at,
            r.prover_mode,
            git_sha_short,
            cold_start_ms,
            warm_p50,
            r.peak_rss_kb,
            pass_marker(r.r2_warm_pass),
            pass_marker(r.r2_cold_pass),
            pass_marker(r.r2_mem_pass),
        );
    }
}

fn pass_marker(ok: bool) -> &'static str {
    if ok {
        "+"
    } else {
        "-"
    }
}

/// The post-Init `coin_history_root` is conventionally
/// `DEFAULT_HASHES[0]` — the empty SMT root. Independent of `prev_asth`
/// but kept as a function so the call site reads symmetrically. We
/// hash a sentinel to obtain that empty-tree root without depending on
/// the `DEFAULT_HASHES` private indexing.
fn init_proof_out_coins_root_from_init(_prev_asth: &LegacyHash) -> LegacyHash {
    SparseMerkleTree::new().root()
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("probe_r2: {e}");
            ExitCode::FAILURE
        }
    }
}
