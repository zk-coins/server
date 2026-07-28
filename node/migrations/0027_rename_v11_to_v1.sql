-- Rename the protocol-v1 stack tables/indexes from the historical `v11_*`
-- names to `v1_*`.
--
-- Protocol version is **v1**. Editions of that version are v1.0 / v1.1 /
-- v1.2; a module or table prefix `v11` incorrectly claimed a non-existent
-- protocol version 1.1 and pinned the stack to an edition it no longer
-- tracks (current derivation is spec-v1.2). Stage 3 will make this stack
-- the default — the name must be correct before it freezes in production.
--
-- Migrations 0019–0026 are left byte-identical (may already be applied on
-- live CI nodes). This migration renames in place so both:
--   * a database that already ran 0019–0026, and
--   * a fresh database that just ran them
-- end up with the same `v1_*` schema after sqlx migrate.
--
-- Also rewrites the closed vocabularies that stored the old label:
--   * stack_scan_mode.mode: 'v11' → 'v1' (CHECK constraint refreshed)
--   * r2_probe_runs.prover_mode: 'v11' → 'v1' (app-enforced; no CHECK)

-- Tables (FKs follow the rename in PostgreSQL).
ALTER TABLE v11_engine_meta RENAME TO v1_engine_meta;
ALTER TABLE v11_nflog_entries RENAME TO v1_nflog_entries;
ALTER TABLE v11_nullifier_index RENAME TO v1_nullifier_index;
ALTER TABLE v11_accounts RENAME TO v1_accounts;
ALTER TABLE v11_spendable_coins RENAME TO v1_spendable_coins;
ALTER TABLE v11_spent_coins RENAME TO v1_spent_coins;
ALTER TABLE v11_pending_publishes RENAME TO v1_pending_publishes;

-- Indexes (table rename does not rename index identifiers).
ALTER INDEX v11_nullifier_index_position_idx RENAME TO v1_nullifier_index_position_idx;
ALTER INDEX v11_pending_publishes_commit_txid_uidx RENAME TO v1_pending_publishes_commit_txid_uidx;
ALTER INDEX v11_pending_publishes_status_idx RENAME TO v1_pending_publishes_status_idx;

-- stack_scan_mode closed vocabulary: legacy | v1
ALTER TABLE stack_scan_mode DROP CONSTRAINT stack_scan_mode_mode_check;
UPDATE stack_scan_mode SET mode = 'v1' WHERE mode = 'v11';
ALTER TABLE stack_scan_mode
    ADD CONSTRAINT stack_scan_mode_mode_check
    CHECK (mode IN ('legacy', 'v1'));

-- r2_probe_runs.prover_mode vocabulary (no SQL CHECK; application-enforced).
UPDATE r2_probe_runs SET prover_mode = 'v1' WHERE prover_mode = 'v11';
