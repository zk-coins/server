-- §3.5 / §7.8 inscription catalog written at NfLog fold time.
--
-- The NfLog stores only first-occurrence winners `(pk, r)` plus the chain
-- position used at fold. It does **not** store reveal txid or the §3.5
-- format byte. ListInscriptions needs both, plus every accepted member
-- (including double-spend losers the NfLog ignored).
--
-- Two tables: head keyed by the reveal triple `(height, tx_index, vin_index)`;
-- members keyed by that triple plus `member_index`. FK + ON DELETE CASCADE
-- keeps reorg truncation from leaving orphan members (a head without its
-- members is a corrupt catalog).
--
-- Idempotent: CREATE TABLE IF NOT EXISTS so re-apply on a fresh migration
-- runner is safe; sqlx still records the version once via `_sqlx_migrations`.

CREATE TABLE IF NOT EXISTS v1_inscriptions (
    height BIGINT NOT NULL CHECK (height >= 0),
    tx_index BIGINT NOT NULL CHECK (tx_index >= 0 AND tx_index <= 4294967295),
    vin_index BIGINT NOT NULL CHECK (vin_index >= 0 AND vin_index <= 4294967295),
    -- Reveal transaction id, internal/consensus byte order (32 bytes).
    -- Never the reversed Display/RPC/explorer order.
    reveal_txid BYTEA NOT NULL CHECK (octet_length(reveal_txid) = 32),
    -- §3.5 format byte: 0x00 raw | 0x01 half-aggregated. Stored as SMALLINT
    -- with an explicit closed CHECK — not derived from member_count.
    format SMALLINT NOT NULL CHECK (format IN (0, 1)),
    -- Payload member count (u16 on wire); must equal the number of member rows.
    member_count INTEGER NOT NULL CHECK (member_count > 0 AND member_count <= 65535),
    block_anchor_hash BYTEA NOT NULL CHECK (octet_length(block_anchor_hash) = 32),
    block_anchor_height BIGINT NOT NULL CHECK (block_anchor_height >= 0 AND block_anchor_height <= 4294967295),
    PRIMARY KEY (height, tx_index, vin_index)
);

CREATE TABLE IF NOT EXISTS v1_inscription_members (
    height BIGINT NOT NULL,
    tx_index BIGINT NOT NULL,
    vin_index BIGINT NOT NULL,
    member_index BIGINT NOT NULL CHECK (member_index >= 0 AND member_index <= 4294967295),
    pk BYTEA NOT NULL CHECK (octet_length(pk) = 32),
    r BYTEA NOT NULL CHECK (octet_length(r) = 32),
    PRIMARY KEY (height, tx_index, vin_index, member_index),
    CONSTRAINT v1_inscription_members_head_fk
        FOREIGN KEY (height, tx_index, vin_index)
        REFERENCES v1_inscriptions (height, tx_index, vin_index)
        ON DELETE CASCADE
);

-- Lexicographic stream order for ListInscriptions (matches PK order).
CREATE INDEX IF NOT EXISTS v1_inscriptions_stream_idx
    ON v1_inscriptions (height, tx_index, vin_index);
