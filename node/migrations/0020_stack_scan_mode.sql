-- Exclusive scan-stack mode claim (Cutover Stage 2 / P2-2).
--
-- A commitment (legacy SMT first-write) and an AggregateStateNullifierV3
-- (NfLog first-occurrence) must never share one accumulator or one
-- database. Once a node boots the legacy or the v1.1 scan stack against
-- a given database, that choice is recorded here and the opposite path
-- refuses to start.
--
-- Additive only: legacy tables are untouched. Stage-4 drop is
-- `DROP TABLE stack_scan_mode`.

CREATE TABLE stack_scan_mode (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    -- Closed vocabulary: legacy | v11 (application-enforced).
    mode TEXT NOT NULL CHECK (mode IN ('legacy', 'v11')),
    claimed_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
