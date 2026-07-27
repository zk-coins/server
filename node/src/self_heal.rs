//! Boot-time self-healing on a breaking circuit change.
//!
//! ## Why this exists
//!
//! The Plonky2 state-transition circuit is *cyclic*: every proof the
//! node emits pins the circuit's `verifier_only.circuit_digest` in its
//! public inputs (`add_verifier_data_public_inputs`) and is fed back as
//! the recursive *inner* proof on the next transition
//! (`account_node::send_coins_inner` →
//! `set_proof_with_pis_target(&inner_proof_target, prev)`). When the
//! circuit changes in a way that breaks recursion, persisted
//! `account.proof` blobs become incompatible: the next AccountUpdate
//! send/mint hands the stale proof to the new circuit's cyclic verifier
//! and the witness generator aborts with a copy-constraint conflict
//! ("Partition … was set twice with different values"), surfaced to the
//! wallet as "prove failed". This took DEV down and previously required
//! a manual `reset-zkcoins-node`.
//!
//! ## What this does
//!
//! At boot the node compares the digest of the circuit the persisted
//! state was produced against with the live circuit's digest, and — on
//! the adoption boundary where no digest is recorded yet — additionally
//! probes whether a persisted proof still recurses through the live
//! circuit. On a mismatch / stale probe the entire proof-dependent
//! state is reset to genesis (the same consistent tabula rasa as
//! `reset-zkcoins-node`) and the new digest is stored. No future
//! circuit change can brick DEV/PRD, and no manual reset is needed.
//!
//! ## The two detectors (and why the canary, not `verify`)
//!
//! 1. **Digest comparison** (the steady-state fast path). Once this fix
//!    is deployed every boot records the live digest; the next boot
//!    compares the live digest against the persisted one in O(1) — no
//!    proof work — and resets iff they differ.
//!
//! 2. **Canary recursion probe** (the adoption boundary). The FIRST boot
//!    after this fix lands runs against a database that has no persisted
//!    digest yet but may already hold stale proofs from a pre-fix
//!    breaking change (exactly the live DEV dump this was validated
//!    against). A pure digest comparison cannot catch that — there is no
//!    baseline. **`Prover::verify` cannot catch it either**: `verify`
//!    only checks the proof's pinned `circuit_digest` against the live
//!    circuit's, and a breaking change that leaves the digest UNCHANGED
//!    (verified against the real DEV dump: embedded digest == live
//!    digest, `verify` passes) slips straight through. The only reliable
//!    signal is to run the actual recursive prove a persisted proof
//!    faces on the next mint/send. So on the no-baseline branch we run
//!    [`crate::account_node::AccountNode::canary_recursion`], which
//!    recurses a persisted proof through the live circuit's AccountUpdate
//!    branch with the REAL commitment-merkle witnesses from the loaded
//!    state. `Stale` → full reset; `Compatible` / `NoSample` → just
//!    record the baseline. After this one-time boot, detector 1 carries
//!    every subsequent boot.
//!
//! ## Why a full reset (and not per-proof invalidation)
//!
//! A circuit change invalidates EVERY proof at once: each
//! `account.proof`, every queued `CoinProof` (whose embedded proof
//! becomes an aggregator *source* proof on the next send), and every
//! proof already distributed to recipients. The global SMT/MMR are
//! append-only and shared across all accounts, keyed by on-chain
//! commitment pubkeys interleaved in MMR-append order — they cannot be
//! partially unwound per account without leaving exactly the
//! global-vs-account mismatch that breaks soundness. A coordinated full
//! reset is therefore the only *provably consistent* recovery, and
//! closed-test-env wipes are permitted (CONTRIBUTING § "Closed test
//! environment"). The reset SQL lives in
//! [`crate::db::reset_proof_dependent_state_tx`]; the matching on-disk
//! proof-store cleanup is [`reset_proof_store_dir`].
//!
//! ## Module layout
//!
//! [`reset_decision`] is the pure, build-free decision function (unit-
//! tested exhaustively). [`heal_circuit_digest`] is the async boot
//! orchestrator that wires the digest comparison + the injected canary
//! against Postgres + the proof-store directory and is exercised by the
//! testcontainer integration tests. All live in this gated module (not
//! `runtime.rs`) so the 100% line + function coverage gate covers the
//! load-bearing logic.

use std::path::Path;

use sqlx::PgPool;
use tracing::{info, warn};

use crate::account_node::CanaryOutcome;
use crate::db;

/// Outcome of the boot-time self-heal evaluation. Returned by
/// [`reset_decision`] and consumed / surfaced by [`heal_circuit_digest`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResetDecision {
    /// The persisted digest equals the live digest: the persisted proofs
    /// are circuit-compatible, leave the state untouched.
    Keep,
    /// There is no persisted digest yet (fresh DB, or a DB last written
    /// by a build that predates the `circuit_digest_meta` table) AND no
    /// stale proof was detected: record the live digest as the baseline,
    /// do NOT reset. A fresh DB has nothing to heal; a pre-fix DB whose
    /// proofs still recurse through the live circuit must not be
    /// needlessly wiped.
    Baseline,
    /// Reset the proof-dependent state to genesis and store the live
    /// digest. Reached either because the persisted digest differs from
    /// the live one (detector 1) or because the canary recursion of a
    /// persisted proof failed against the live circuit (detector 2, the
    /// adoption boundary).
    Reset,
}

/// Pure decision: combine the digest comparison (detector 1) with the
/// canary recursion outcome (detector 2).
///
/// * `persisted == Some(live)`                       → [`ResetDecision::Keep`]
/// * `persisted == Some(other)`                      → [`ResetDecision::Reset`]
/// * `persisted == None` & `canary == Stale`         → [`ResetDecision::Reset`]
/// * `persisted == None` & `Compatible` / `NoSample` → [`ResetDecision::Baseline`]
///
/// `canary` is the outcome of recursing a persisted proof through the
/// live circuit; it is only consulted on the no-persisted-digest branch
/// (when a digest IS persisted, detector 1 is authoritative and far
/// cheaper). No circuit build, no I/O — exhaustively unit-testable.
pub fn reset_decision(
    persisted: Option<&[u8]>,
    live: &[u8],
    canary: CanaryOutcome,
) -> ResetDecision {
    match persisted {
        Some(prev) if prev == live => ResetDecision::Keep,
        Some(_) => ResetDecision::Reset,
        None => match canary {
            CanaryOutcome::Stale => ResetDecision::Reset,
            CanaryOutcome::Compatible | CanaryOutcome::NoSample => ResetDecision::Baseline,
        },
    }
}

/// Drop the on-disk per-proof file store so the proof_id space resets
/// cleanly alongside the Postgres reset.
///
/// The proof store lives outside Postgres (large bincode Plonky2 proof
/// blobs; see CONTRIBUTING § "Persistent State"), so it cannot ride the
/// `reset_proof_dependent_state_tx` transaction. After a reset no
/// surviving row references any proof file, so removing the directory is
/// safe; it is recreated lazily by `ProofStore` on the next write.
///
/// A missing directory is success (nothing to clean). Any other I/O
/// error is returned so the caller can decide — `heal_circuit_digest`
/// logs and continues, because a stale proof file with a fresh DB is
/// inert (no row points at it) and must not crash-loop the container.
pub fn reset_proof_store_dir(proofs_dir: &str) -> std::io::Result<()> {
    let path = Path::new(proofs_dir);
    match std::fs::remove_dir_all(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e),
    }
}

/// Boot-time orchestrator: run both detectors and self-heal on a
/// breaking circuit change.
///
/// `canary` is the live circuit's recursion probe — in production
/// `|| account_node.canary_recursion()` (which recurses a persisted
/// proof through the real AccountUpdate branch; `Stale` ⇔ the persisted
/// proofs are incompatible with the current circuit). It is injected as
/// a closure so this function is free of the ~14 s circuit build and the
/// integration tests can drive both detectors with synthetic digests and
/// a stub outcome. **It is evaluated lazily** — only on the
/// no-persisted-digest branch, so the common steady-state boot pays a
/// single cheap O(1) digest comparison and never runs the (~5 s) probe.
///
/// Returns the [`ResetDecision`] that was taken so the caller can log /
/// surface it. The Postgres reset is transactional — a DB error aborts
/// and propagates, because serving with a half-reset state is worse than
/// failing the boot loudly. Proof-store directory cleanup is best-effort
/// (a failure is logged and swallowed).
///
/// `canary` is a trait object (not a generic bound) on purpose: a
/// generic `impl Fn` is monomorphised once per closure type, and the
/// unit tests drive several distinct closures — the resulting multiple
/// instantiations confuse `llvm-cov`'s line accounting ("mismatched
/// data"). A single `&dyn Fn` keeps one instantiation and clean
/// coverage; the indirect call is irrelevant next to a ~5 s prove.
pub async fn heal_circuit_digest(
    pool: &PgPool,
    live_digest: &[u8],
    proofs_dir: &str,
    canary: &dyn Fn() -> CanaryOutcome,
) -> Result<ResetDecision, sqlx::Error> {
    let persisted = db::load_circuit_digest(pool).await?;

    // Detector 2 (the canary) only matters when there is no persisted
    // digest to compare against — otherwise detector 1 is authoritative
    // and we skip the (~5 s) recursion probe entirely.
    let canary_outcome = if persisted.is_none() {
        let outcome = canary();
        if outcome == CanaryOutcome::Stale {
            warn!(
                "Self-heal: a persisted proof failed to recurse through the current \
                 circuit. Treating persisted state as produced by an incompatible circuit."
            );
        }
        outcome
    } else {
        // Not consulted on the digest-present branch; value is irrelevant.
        CanaryOutcome::NoSample
    };

    let decision = reset_decision(persisted.as_deref(), live_digest, canary_outcome);
    match decision {
        ResetDecision::Keep => {
            info!("Circuit digest matches persisted state; no self-heal needed");
        }
        ResetDecision::Baseline => {
            info!(
                "No persisted circuit digest and persisted proofs (if any) recurse \
                 through the current circuit; recording current digest as baseline"
            );
            db::store_circuit_digest(pool, live_digest).await?;
        }
        ResetDecision::Reset => {
            warn!(
                "Circuit changed since the persisted state was written — persisted \
                 proofs are incompatible with the current circuit. Resetting \
                 proof-dependent state to genesis (self-heal) so the node serves \
                 cleanly. This DESTROYS proof-dependent state (see follow-up \
                 lines for the exact wipe set) and is irreversible without \
                 re-funding / re-minting."
            );
            // Under exclusive v1.1:
            //   * Do NOT wipe SMT/MMR/root-index/latest_block — structures the
            //     v1.1 stack does not use (and that the full legacy wipe would
            //     require a legacy marker to touch).
            //   * DO wipe all v11 proof-dependent tables (NfLog, accounts,
            //     last_proof/openings, pending publishes) plus leftover
            //     legacy `accounts`, fail non-terminal jobs (strip durable
            //     finalisation / completion_result), and store the live
            //     binary digest (`encode_v11_live_digest(C, C_balance)` from
            //     the embed). A digest-only update left stale
            //     ComplianceProofs in place; the next AccountUpdate would
            //     fail to recurse.
            // Legacy (or unclaimed) path keeps the full proof-dependent wipe.
            match crate::v11::process_stack_mode() {
                Some(crate::v11::ScanStackMode::V11) => {
                    warn!(
                        "Self-heal reset (v1.1) will DESTROY: \
                         v11_pending_publishes (stale nullifier publish recovery); \
                         v11_spendable_coins / v11_spent_coins (CoinHist leaves); \
                         v11_accounts (multi-asset state + last_proof / openings); \
                         v11_nullifier_index / v11_nflog_entries (NfLog); \
                         v11_engine_meta (tip / network pin); \
                         leftover legacy accounts rows; \
                         on-disk PROOFS_DIR proof-store files; \
                         and every non-terminal jobs row (queued/proving/\
                         awaiting_signature/broadcasting) is marked failed with \
                         durable finalisation + completion_result stripped so a \
                         wiped transition cannot later report completed. \
                         Leaving smt_state / mmr_state / mmr_root_index / \
                         latest_block untouched (v1.1 does not use them). \
                         Storing the live binary circuit digest."
                    );
                    db::reset_v11_proof_dependent_state_tx(pool, live_digest).await?;
                }
                _ => {
                    warn!(
                        "Self-heal reset (legacy) will DESTROY: \
                         accounts (proof-bearing account blobs); \
                         smt_state / mmr_state / mmr_root_index / latest_block \
                         (global scan state); \
                         on-disk PROOFS_DIR proof-store files; \
                         and every non-terminal jobs row is marked failed with \
                         the self-heal reset generation bumped so a concurrent \
                         writer cannot resurrect or complete wiped work. \
                         Storing the live circuit digest."
                    );
                    db::reset_proof_dependent_state_tx(pool, live_digest).await?;
                }
            }
            if let Err(e) = reset_proof_store_dir(proofs_dir) {
                warn!(
                    "Self-heal: failed to drop proof-store dir {} (continuing — no \
                     surviving row references it): {}",
                    proofs_dir, e
                );
            }
        }
    }
    Ok(decision)
}

#[cfg(test)]
#[path = "self_heal_tests.rs"]
mod tests;
