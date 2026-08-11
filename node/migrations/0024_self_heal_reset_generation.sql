-- Self-heal reset generation: a fencing token for every job-advancing write.
--
-- A circuit-digest self-heal wipes proof-dependent state and marks non-terminal
-- jobs failed. That alone is not enough against concurrent writers:
--
--   1. Worker A loads a queued job (status + public_id only).
--   2. Boot B commits the reset (fails non-terminal rows, wipes tables).
--   3. A still holds the in-memory job and calls unconditional set_status /
--      complete matching `public_id` only → the row resurrects as proving /
--      completed and can write an engine snapshot back into wiped tables.
--   4. A job INSERT that races after the fail-UPDATE (or is admitted with a
--      stale generation) is not reconciled by the one-shot UPDATE and can
--      reach completed the same way.
--
-- Identity and lease (finalise_claim fence) already fence host-edge writes
-- *within* an acquisition epoch. They do not fence a generation of work that
-- the self-heal tore down. Same construction, different epoch:
--
-- * Singleton `self_heal_reset_meta.generation` is the current admission
--   epoch (starts at 0).
-- * Every `jobs` row is stamped with `reset_generation` at INSERT time from
--   the current meta generation, under `SELECT … FOR UPDATE` on this row so
--   admit and reset are mutually exclusive (plain scalar SELECT would see
--   the last committed generation for the whole uncommitted bump window).
-- * A self-heal reset BUMPS the meta generation first (row lock until commit),
--   then fails non-terminal jobs WITHOUT rewriting their `reset_generation`
--   — those rows are left behind the live epoch.
-- * Every job-advancing write requires
--     `jobs.reset_generation = (SELECT generation FROM self_heal_reset_meta)`
--   so a pre-reset worker (or a stale-generation admit) cannot resurrect or
--   complete work against wiped state. Post-reset admits stamp the new
--   generation and proceed on clean genesis.
--
-- Unqualified names so search_path-scoped test schemas each get their own
-- meta row + column (same discipline as migration 0022).

CREATE TABLE self_heal_reset_meta (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    generation BIGINT NOT NULL DEFAULT 0
);

INSERT INTO self_heal_reset_meta (id, generation) VALUES (1, 0);

ALTER TABLE jobs
    ADD COLUMN reset_generation BIGINT NOT NULL DEFAULT 0;
