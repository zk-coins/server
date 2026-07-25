-- v1.1 (spec) persistence schema — additive Cutover Stage 1 (P2-1).
--
-- The legacy tables (`smt_state`, `mmr_state`, `accounts`, …) stay fully
-- intact and remain the default production path. A v1.1 node runs against a
-- **fresh** database (or empty v11 tables): there is no migration of the old
-- global SMT / MMR model into NfLog / CoinHist — those structures have no
-- successor by design.
--
-- What must survive a restart (reconstruct identical StateEngine state):
--
--   * NfLog append-only log in normative first-occurrence order (§3.6:
--     fold by `(height, tx_index, vin_index, member_index)`). Persistence
--     stores that order as a dense `position` primary key (0..n-1) plus the
--     full `ChainPosition` so a reload can re-fold in the same order and
--     recover the identical RFC-6962 root. Reordering rows would change
--     every subsequent position and is therefore forbidden by PK + load
--     checks (consecutive positions, ORDER BY position ASC).
--   * Per-account multi-asset `AccountState`, CoinHist leaves (derived from
--     spendable + spent coin sets), last `ComplianceProof`, NAV / nullifier
--     openings needed for AccountUpdate recursion.
--   * A Pk-keyed nullifier index for O(1) "has this (Pk, R) been seen?"
--     answers without scanning the log (mirrors NfLogAccumulator::index).
--
-- Naming: every table is prefixed `v11_` so it cannot collide with legacy
-- names and so Stage-4 drop is a mechanical `DROP TABLE v11_*`.

-- Singleton engine meta (network pin + tip cursor).
CREATE TABLE v11_engine_meta (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    -- Closed vocabulary: mainnet | testnet | regtest (application-enforced).
    network TEXT NOT NULL,
    activation_height BIGINT NOT NULL CHECK (activation_height >= 0),
    tip_height BIGINT NOT NULL CHECK (tip_height >= 0),
    -- Engine fold ordinal at the current tip (u32; stored as BIGINT).
    fold_seq BIGINT NOT NULL CHECK (fold_seq >= 0 AND fold_seq <= 4294967295),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Append-only NfLog entries. `position` is the absolute log index and the
-- normative reconstruction order. Chain-position columns are the §3.6 sort
-- key that was used at fold time; they are retained so reorg / scanner
-- Stage-2 work can re-validate order without re-deriving it.
CREATE TABLE v11_nflog_entries (
    position BIGINT PRIMARY KEY CHECK (position >= 0),
    height BIGINT NOT NULL CHECK (height >= 0),
    tx_index BIGINT NOT NULL CHECK (tx_index >= 0 AND tx_index <= 4294967295),
    vin_index BIGINT NOT NULL CHECK (vin_index >= 0 AND vin_index <= 4294967295),
    member_index BIGINT NOT NULL CHECK (member_index >= 0 AND member_index <= 4294967295),
    pk BYTEA NOT NULL CHECK (octet_length(pk) = 32),
    r BYTEA NOT NULL CHECK (octet_length(r) = 32)
);

-- O(1) first-occurrence index: pk → (position, winning R).
-- Maintained in the same transaction as nflog appends. Reload rebuilds it
-- from entries and fails loud if the two diverge.
CREATE TABLE v11_nullifier_index (
    pk BYTEA PRIMARY KEY CHECK (octet_length(pk) = 32),
    position BIGINT NOT NULL REFERENCES v11_nflog_entries (position),
    r BYTEA NOT NULL CHECK (octet_length(r) = 32)
);

CREATE INDEX v11_nullifier_index_position_idx ON v11_nullifier_index (position);

-- Multi-asset account records (v1.1 AccountState + operational secrets +
-- last compliance proof / openings). Distinct from legacy `accounts`
-- (which store the retired single-asset Account + Proof blob).
CREATE TABLE v11_accounts (
    owner BYTEA PRIMARY KEY CHECK (octet_length(owner) = 32),
    -- bincode of shared::spec_v1::AccountState
    account_state BYTEA NOT NULL,
    nk BYTEA NOT NULL CHECK (octet_length(nk) = 32),
    genesis_pubkey BYTEA NOT NULL CHECK (octet_length(genesis_pubkey) = 32),
    -- bincode ComplianceProof (ProofWithPublicInputs); NULL only for a
    -- never-transitioned fixture (production accounts after finalise always
    -- have a last proof).
    last_proof BYTEA,
    -- bincode of NavOpening
    last_nav_opening BYTEA,
    -- bincode of NullifierOpening
    last_nullifier BYTEA,
    last_nullifier_pos BIGINT CHECK (last_nullifier_pos IS NULL OR last_nullifier_pos >= 0),
    -- Cached coin_history_root (§1.7.1 32 bytes) for restart-identity checks
    -- without deserializing account_state first.
    coin_history_root BYTEA NOT NULL CHECK (octet_length(coin_history_root) = 32),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Spendable (CoinHist state = Admitted) coins with spend auth metadata.
CREATE TABLE v11_spendable_coins (
    owner BYTEA NOT NULL REFERENCES v11_accounts (owner) ON DELETE CASCADE,
    coin_id BYTEA NOT NULL CHECK (octet_length(coin_id) = 32),
    -- bincode of shared::spec_v1::Coin
    coin BYTEA NOT NULL,
    creating_prev_ash BYTEA NOT NULL CHECK (octet_length(creating_prev_ash) = 32),
    coin_index INTEGER NOT NULL CHECK (coin_index >= 0),
    PRIMARY KEY (owner, coin_id)
);

-- Spent coin ids (CoinHist state = Spent). Together with spendable rows
-- these reconstruct the per-account CoinHistTree root on load.
CREATE TABLE v11_spent_coins (
    owner BYTEA NOT NULL REFERENCES v11_accounts (owner) ON DELETE CASCADE,
    coin_id BYTEA NOT NULL CHECK (octet_length(coin_id) = 32),
    PRIMARY KEY (owner, coin_id)
);
