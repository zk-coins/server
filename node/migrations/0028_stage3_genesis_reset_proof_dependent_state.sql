-- Stage 3 atomic cutover: genesis-reset of proof-dependent state.
--
-- ## Why
--
-- Stage 3 makes the v1 stack (ComplianceProof / NfLog /
-- AggregateStateNullifierV3 / S2C) the only production path. Legacy
-- `circuit::main` proofs, SMT/MMR commitments, and half-cutover hybrid
-- state are incompatible with that path: a hybrid node produces proofs
-- nobody can verify.
--
-- This migration is the one-shot, irreversible wipe (same rationale as
-- 0016). After it applies, rollback is only possible by restoring a
-- pre-cutover backup — not by flipping a flag (wallets may already have
-- published v1 nullifiers).
--
-- ## G5 generation fence (do not invent a second mechanism)
--
-- Concurrent job writers are fenced by the same construct Stage-2 G5
-- introduced (migration 0024):
--
--   1. Bump `self_heal_reset_meta.generation` first (row lock until commit).
--   2. Fail every non-terminal job WITHOUT rewriting `reset_generation`
--      — those rows stay behind the live epoch.
--   3. Wipe proof-dependent tables.
--   4. Clear `circuit_digest_meta` so the next boot records the live
--      C||C_balance digest via the existing self-heal Baseline path.
--
-- A job that was in flight (loaded into a worker before this commit)
-- cannot complete: every job-advancing write requires
-- `reset_generation = $locked_generation` and loses the CAS. The operator
-- sees `failed` with the Stage-3 cutover message; the wallet re-submits
-- after the node is up on clean genesis.
--
-- sqlx applies a migration once per database (`_sqlx_migrations`), so
-- this fires exactly once per environment on first deploy that carries
-- Stage 3. Re-deploys are no-ops.

-- 1. Generation fence first (same order as reset_v1_proof_dependent_state_tx).
UPDATE self_heal_reset_meta
SET generation = generation + 1
WHERE id = 1;

-- 2. Fail non-terminal jobs; leave reset_generation behind the live epoch.
UPDATE jobs
SET status = 'failed',
    phase = 'failed',
    error = 'stage-3 cutover genesis reset: proof-dependent state wiped; resubmit after the node is on the v1 stack',
    request_body = (COALESCE(request_body, '{}'::jsonb)
        - 'finalisation' - 'pending_sign' - 'sign' - 'finalise_claim'),
    updated_at = NOW(),
    completed_at = NOW()
WHERE status IN ('queued', 'proving', 'awaiting_signature', 'broadcasting');

-- 3. Wipe v1 proof-dependent tables (order: children / dependents first).
DELETE FROM v1_pending_publishes;
DELETE FROM v1_spendable_coins;
DELETE FROM v1_spent_coins;
DELETE FROM v1_accounts;
DELETE FROM v1_nullifier_index;
DELETE FROM v1_nflog_entries;
DELETE FROM v1_engine_meta;

-- 4. Wipe residual legacy proof-bearing / scan state so a half-migrated
--    DB cannot mix SMT first-write with NfLog first-occurrence.
DELETE FROM accounts;
DELETE FROM smt_state;
DELETE FROM mmr_state;
DELETE FROM mmr_root_index;
DELETE FROM latest_block;
DELETE FROM pending_inscriptions;
DELETE FROM observed_inscriptions;

-- 5. Clear circuit digest so boot records the live C||C_balance baseline.
DELETE FROM circuit_digest_meta;

-- 6. Drop the stack claim so the Stage-3 binary re-claims ScanStackMode::V1
--    on a genuinely empty database (enforce_stack_scan_mode empty-path).
--    Opposite-side residue is already gone above.
DELETE FROM stack_scan_mode;
