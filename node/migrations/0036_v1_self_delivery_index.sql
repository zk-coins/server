-- Durable private-record index for locally finalised self-delivery CoinProofs.
--
-- Unlike v1_decrypt_index, these rows have no incoming gift-wrap event, ACK
-- nonce, or ACK lifecycle.  They are written immediately after the account's
-- own transition has durably finalised, before SDR Phase B / confirmation.

CREATE TABLE IF NOT EXISTS v1_self_delivery_index (
    -- Stable private-record id: SHA-256(subject || coin_id || blob_id).
    record_id BYTEA PRIMARY KEY CHECK (octet_length(record_id) = 32),
    subject BYTEA NOT NULL CHECK (octet_length(subject) = 32),
    coin_id BYTEA NOT NULL CHECK (octet_length(coin_id) = 32),
    -- Local ZBE content address for the byte-identical CoinProof body.
    blob_id BYTEA NOT NULL CHECK (octet_length(blob_id) = 32),
    detect_tag BYTEA NOT NULL CHECK (octet_length(detect_tag) = 32),
    -- Canonical section 7.1 serialize(CoinProof) bytes.
    canonical BYTEA NOT NULL CHECK (octet_length(canonical) > 0),
    asset_id BYTEA NOT NULL CHECK (octet_length(asset_id) = 32),
    transition_kind TEXT NOT NULL
        CHECK (transition_kind IN ('mint', 'send', 'receive')),
    -- Unknown at finalise time; no chain timestamp is invented.
    occurred_at BIGINT NOT NULL DEFAULT 0 CHECK (occurred_at >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT v1_self_delivery_index_subject_coin_uq UNIQUE (subject, coin_id)
);

CREATE INDEX IF NOT EXISTS v1_self_delivery_index_subject_time_idx
    ON v1_self_delivery_index (subject, occurred_at);
