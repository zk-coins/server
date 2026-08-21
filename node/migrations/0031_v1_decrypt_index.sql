-- §4.8 / §4.2 / §5.1 — durable decrypt index for received CoinProof bundles.
--
-- Written only after full §4.4 discovery + §2.3.3 verification (steps 2–6).
-- ACK (§4.2) is sent only after a successful insert into this table.
--
-- Replay (normative, fail-closed):
--   * UNIQUE (blob_id)           — same ZBE ciphertext redelivered (retry / k
--                                  holders) does not create a second credit row
--   * UNIQUE (subject, coin_id)  — same coin cannot be indexed twice for one
--                                  subject (coin-history replay guard complement)
--   * UNIQUE (delivery_event_id) — same outer gift-wrap reprocessed is a no-op
--
-- A redelivery of an already-indexed bundle is detected by the unique
-- constraints: the pipeline re-ACKs (idempotent) but never re-credits.
-- verification_status is closed: 'verified' (durable, ACK pending/in-flight)
-- or 'acked' (ACK published). Failed candidates are never stored.

CREATE TABLE IF NOT EXISTS v1_decrypt_index (
    -- Stable private-record id: SHA-256(subject ‖ coin_id ‖ blob_id).
    record_id BYTEA PRIMARY KEY CHECK (octet_length(record_id) = 32),
    subject BYTEA NOT NULL CHECK (octet_length(subject) = 32),
    coin_id BYTEA NOT NULL CHECK (octet_length(coin_id) = 32),
    -- ZBE content address H(ciphertext) (§4.2.1 / §7.4).
    blob_id BYTEA NOT NULL CHECK (octet_length(blob_id) = 32),
    -- Outer cleartext scan tag that matched (§1.3 / §4.4).
    detect_tag BYTEA NOT NULL CHECK (octet_length(detect_tag) = 32),
    -- Canonical §7.1 serialize(CoinProof) bytes (the Private record body).
    canonical BYTEA NOT NULL CHECK (octet_length(canonical) > 0),
    asset_id BYTEA NOT NULL CHECK (octet_length(asset_id) = 32),
    verification_status TEXT NOT NULL
        CHECK (verification_status IN ('verified', 'acked')),
    -- Outer kind-1059 gift-wrap event id of the delivery that was accepted.
    delivery_event_id BYTEA NOT NULL CHECK (octet_length(delivery_event_id) = 32),
    -- Echoed unchanged into the ACK (§4.2).
    ack_nonce BYTEA NOT NULL CHECK (octet_length(ack_nonce) = 32),
    -- Chain-derived when known; 0 until first-occurrence MTP is observed.
    occurred_at BIGINT NOT NULL DEFAULT 0 CHECK (occurred_at >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    acked_at TIMESTAMPTZ,
    CONSTRAINT v1_decrypt_index_blob_id_uq UNIQUE (blob_id),
    CONSTRAINT v1_decrypt_index_subject_coin_uq UNIQUE (subject, coin_id),
    CONSTRAINT v1_decrypt_index_delivery_event_uq UNIQUE (delivery_event_id)
);

CREATE INDEX IF NOT EXISTS v1_decrypt_index_subject_time_idx
    ON v1_decrypt_index (subject, occurred_at);

CREATE INDEX IF NOT EXISTS v1_decrypt_index_status_idx
    ON v1_decrypt_index (verification_status)
    WHERE verification_status = 'verified';
