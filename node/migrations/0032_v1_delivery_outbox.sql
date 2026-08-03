-- §4.2 durable delivery outbox (data permanence).
--
-- Every outstanding mesh delivery (external CoinProof and SelfDeliveryRecordV1)
-- lands here **before** the first network send attempt. Crash between
-- transition persist and mesh publish is recoverable: resume re-drives every
-- non-terminal row.
--
-- State machine (CHECK-closed):
--   pending       — inserted atomically with the step that owes it;
--                   artefacts (blob_id / zbe / ack_nonce) may be absent
--   awaiting_ack  — published at least once; exponential republish until
--                   a valid recipient ACK (§4.2)
--   completed     — valid ACK in hand; MUST NEVER be republished.
--                   Row is retained indefinitely as a delivery log
--                   (data permanence — no drop of outbox row or blob/SDR).
--   failed        — named permanent failure (operator-visible reason)
--
-- Data permanence: the sender keeps blob/SDR copies indefinitely. Completing
-- an outbox row never deletes stored material. There is no receipt quorum,
-- no k-target, and no drop-after-replication path.
--
-- Backoff parameters (normative RECOMMENDED values from §4.2, frozen in code):
--   initial 30 s, doubling, cap 1 h. Stored as next_attempt_at + attempt_n.

CREATE TABLE IF NOT EXISTS v1_delivery_outbox (
    -- Stable id: SHA-256(kind_tag ‖ subject ‖ coin_id ‖ transition_pk).
    outbox_id BYTEA PRIMARY KEY CHECK (octet_length(outbox_id) = 32),
    -- Closed: external CoinProof vs self-delivery (SDR Phase B).
    kind TEXT NOT NULL CHECK (kind IN ('external_coin', 'self_delivery')),
    subject BYTEA NOT NULL CHECK (octet_length(subject) = 32),
    -- Transition nullifier Pk that owed this delivery (links to pending_publish).
    transition_pk BYTEA NOT NULL CHECK (octet_length(transition_pk) = 32),
    -- External: coin.identifier. SDR: all-zero sentinel (one SDR per transition).
    coin_id BYTEA NOT NULL CHECK (octet_length(coin_id) = 32),
    status TEXT NOT NULL CHECK (status IN (
        'pending',
        'awaiting_ack',
        'completed',
        'failed'
    )),
    -- Rebuild / republish material (versioned JSON DTO — no silent default keys).
    material BYTEA NOT NULL CHECK (octet_length(material) > 0),
    -- Filled on first successful build+publish (NULL while pending).
    blob_id BYTEA CHECK (blob_id IS NULL OR octet_length(blob_id) = 32),
    detect_tag BYTEA CHECK (detect_tag IS NULL OR octet_length(detect_tag) = 32),
    -- Per-coin ephemeral x-only pubkey (SDR output_ref.epk / NIP-59 scan tag).
    epk BYTEA CHECK (epk IS NULL OR octet_length(epk) = 32),
    k_tx BYTEA CHECK (k_tx IS NULL OR octet_length(k_tx) = 32),
    ack_nonce BYTEA CHECK (ack_nonce IS NULL OR octet_length(ack_nonce) = 32),
    event_id BYTEA CHECK (event_id IS NULL OR octet_length(event_id) = 32),
    zbe_ciphertext BYTEA,
    out_ciphertext BYTEA,
    recipient_op_pk BYTEA CHECK (recipient_op_pk IS NULL OR octet_length(recipient_op_pk) = 32),
    -- Attempt counter: 0 before first publish; increments on each successful publish.
    attempt_n INTEGER NOT NULL DEFAULT 0 CHECK (attempt_n >= 0),
    last_published_at TIMESTAMPTZ,
    -- When the runtime may next publish / republish this row.
    next_attempt_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    ack_received_at TIMESTAMPTZ,
    fail_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT v1_delivery_outbox_subject_coin_kind_uq UNIQUE (subject, coin_id, kind)
);

-- Due-work index for the runtime republish / resume poll.
CREATE INDEX IF NOT EXISTS v1_delivery_outbox_due_idx
    ON v1_delivery_outbox (status, next_attempt_at)
    WHERE status IN ('pending', 'awaiting_ack');

CREATE INDEX IF NOT EXISTS v1_delivery_outbox_transition_idx
    ON v1_delivery_outbox (transition_pk)
    WHERE status NOT IN ('completed', 'failed');

CREATE INDEX IF NOT EXISTS v1_delivery_outbox_open_idx
    ON v1_delivery_outbox (status)
    WHERE status NOT IN ('completed', 'failed');
