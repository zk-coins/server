-- Data Permanence — derived state is never physically deleted. Canonical
-- reads select the rows whose state_epoch matches derived_state_epoch_meta;
-- self-heal and engine replacement archive old rows by bumping that epoch.

CREATE TABLE derived_state_epoch_meta (
    id SMALLINT PRIMARY KEY CHECK (id = 1),
    epoch BIGINT NOT NULL DEFAULT 0
);

INSERT INTO derived_state_epoch_meta (id, epoch) VALUES (1, 0);

ALTER TABLE v1_engine_meta ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE v1_nflog_entries ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE v1_nullifier_index ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE v1_accounts ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE v1_spendable_coins ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE v1_spent_coins ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE v1_inscriptions ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE v1_inscription_members ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;

ALTER TABLE accounts ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE smt_state ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE mmr_state ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE mmr_root_index ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;
ALTER TABLE latest_block ADD COLUMN state_epoch BIGINT NOT NULL DEFAULT 0;

-- Drop child foreign keys before replacing their referenced parent keys.
-- Migration 0027 renamed tables but PostgreSQL retained the v11_* names;
-- accept either spelling so the migration is robust across schema histories.
ALTER TABLE v1_nullifier_index
    DROP CONSTRAINT IF EXISTS v11_nullifier_index_position_fkey,
    DROP CONSTRAINT IF EXISTS v1_nullifier_index_position_fkey;
ALTER TABLE v1_spendable_coins
    DROP CONSTRAINT IF EXISTS v11_spendable_coins_owner_fkey,
    DROP CONSTRAINT IF EXISTS v1_spendable_coins_owner_fkey;
ALTER TABLE v1_spent_coins
    DROP CONSTRAINT IF EXISTS v11_spent_coins_owner_fkey,
    DROP CONSTRAINT IF EXISTS v1_spent_coins_owner_fkey;
ALTER TABLE v1_inscription_members
    DROP CONSTRAINT IF EXISTS v1_inscription_members_head_fk;

ALTER TABLE v1_engine_meta
    DROP CONSTRAINT IF EXISTS v11_engine_meta_pkey,
    DROP CONSTRAINT IF EXISTS v1_engine_meta_pkey;
ALTER TABLE v1_nflog_entries
    DROP CONSTRAINT IF EXISTS v11_nflog_entries_pkey,
    DROP CONSTRAINT IF EXISTS v1_nflog_entries_pkey;
ALTER TABLE v1_nullifier_index
    DROP CONSTRAINT IF EXISTS v11_nullifier_index_pkey,
    DROP CONSTRAINT IF EXISTS v1_nullifier_index_pkey;
ALTER TABLE v1_accounts
    DROP CONSTRAINT IF EXISTS v11_accounts_pkey,
    DROP CONSTRAINT IF EXISTS v1_accounts_pkey;
ALTER TABLE v1_spendable_coins
    DROP CONSTRAINT IF EXISTS v11_spendable_coins_pkey,
    DROP CONSTRAINT IF EXISTS v1_spendable_coins_pkey;
ALTER TABLE v1_spent_coins
    DROP CONSTRAINT IF EXISTS v11_spent_coins_pkey,
    DROP CONSTRAINT IF EXISTS v1_spent_coins_pkey;
ALTER TABLE v1_inscriptions
    DROP CONSTRAINT IF EXISTS v1_inscriptions_pkey;
ALTER TABLE v1_inscription_members
    DROP CONSTRAINT IF EXISTS v1_inscription_members_pkey;

ALTER TABLE accounts DROP CONSTRAINT IF EXISTS accounts_pkey;
ALTER TABLE smt_state DROP CONSTRAINT IF EXISTS smt_state_pkey;
ALTER TABLE mmr_state DROP CONSTRAINT IF EXISTS mmr_state_pkey;
ALTER TABLE mmr_root_index
    DROP CONSTRAINT IF EXISTS mmr_root_index_pkey,
    DROP CONSTRAINT IF EXISTS mmr_root_index_leaf_index_unique;
ALTER TABLE latest_block DROP CONSTRAINT IF EXISTS latest_block_pkey;

-- Recreate parent keys first, then child keys and epoch-qualified FKs.
ALTER TABLE v1_engine_meta
    ADD CONSTRAINT v1_engine_meta_pkey PRIMARY KEY (state_epoch, id);
ALTER TABLE v1_nflog_entries
    ADD CONSTRAINT v1_nflog_entries_pkey PRIMARY KEY (state_epoch, position);
ALTER TABLE v1_accounts
    ADD CONSTRAINT v1_accounts_pkey PRIMARY KEY (state_epoch, owner);
ALTER TABLE v1_inscriptions
    ADD CONSTRAINT v1_inscriptions_pkey
        PRIMARY KEY (state_epoch, height, tx_index, vin_index);

ALTER TABLE v1_nullifier_index
    ADD CONSTRAINT v1_nullifier_index_pkey PRIMARY KEY (state_epoch, pk),
    ADD CONSTRAINT v1_nullifier_index_position_fkey
        FOREIGN KEY (state_epoch, position)
        REFERENCES v1_nflog_entries (state_epoch, position);
ALTER TABLE v1_spendable_coins
    ADD CONSTRAINT v1_spendable_coins_pkey
        PRIMARY KEY (state_epoch, owner, coin_id),
    ADD CONSTRAINT v1_spendable_coins_owner_fkey
        FOREIGN KEY (state_epoch, owner)
        REFERENCES v1_accounts (state_epoch, owner);
ALTER TABLE v1_spent_coins
    ADD CONSTRAINT v1_spent_coins_pkey
        PRIMARY KEY (state_epoch, owner, coin_id),
    ADD CONSTRAINT v1_spent_coins_owner_fkey
        FOREIGN KEY (state_epoch, owner)
        REFERENCES v1_accounts (state_epoch, owner);
ALTER TABLE v1_inscription_members
    ADD CONSTRAINT v1_inscription_members_pkey
        PRIMARY KEY (state_epoch, height, tx_index, vin_index, member_index),
    ADD CONSTRAINT v1_inscription_members_head_fk
        FOREIGN KEY (state_epoch, height, tx_index, vin_index)
        REFERENCES v1_inscriptions (state_epoch, height, tx_index, vin_index);

ALTER TABLE smt_state
    ADD CONSTRAINT smt_state_pkey PRIMARY KEY (state_epoch, id);
ALTER TABLE mmr_state
    ADD CONSTRAINT mmr_state_pkey PRIMARY KEY (state_epoch, id);
ALTER TABLE latest_block
    ADD CONSTRAINT latest_block_pkey PRIMARY KEY (state_epoch, id);
ALTER TABLE accounts
    ADD CONSTRAINT accounts_pkey PRIMARY KEY (state_epoch, address);
ALTER TABLE mmr_root_index
    ADD CONSTRAINT mmr_root_index_pkey PRIMARY KEY (state_epoch, prev_mmr_root),
    ADD CONSTRAINT mmr_root_index_leaf_index_unique UNIQUE (state_epoch, leaf_index);

-- Keep canonical access paths epoch-leading. Pending-publish partial unique
-- indexes are intentionally unchanged because that table is not epoch-scoped.
DROP INDEX IF EXISTS v1_nullifier_index_position_idx;
CREATE INDEX v1_nullifier_index_position_idx
    ON v1_nullifier_index (state_epoch, position);
DROP INDEX IF EXISTS v1_inscriptions_stream_idx;
CREATE INDEX v1_inscriptions_stream_idx
    ON v1_inscriptions (state_epoch, height, tx_index, vin_index);

ALTER TABLE circuit_digest_meta ALTER COLUMN digest DROP NOT NULL;

-- Permanence invariant: old derived rows and the circuit-digest singleton
-- remain stored; changing the canonical view never deletes them.
