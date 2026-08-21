-- §4.2 SelfDeliveryRecordV1 Phase A staging.
--
-- Phase A (at prove/persist/send time) stores everything known before the
-- transition's nullifier is a first-occurrence on Bitcoin. Phase B (scanner
-- hook after first-occurrence + §3.10 completed / size_final) fills
-- inclusion_block + occurred_at = MTP, seals serialize(SelfDeliveryRecordV1)
-- under ZBE, and inserts a self_delivery row into v1_delivery_outbox.
--
-- Keyed by transition nullifier Pk (transition_pk) so Phase B finds the
-- unique staged record. Never write a provisional SDR ciphertext here.

CREATE TABLE IF NOT EXISTS v1_sdr_phase_a (
    -- Transition nullifier Pkᵢ (on-chain first-occurrence key).
    transition_pk BYTEA PRIMARY KEY CHECK (octet_length(transition_pk) = 32),
    -- Account subject (owner address).
    subject BYTEA NOT NULL CHECK (octet_length(subject) = 32),
    -- Closed status: awaiting_first_occurrence → finalised | failed.
    status TEXT NOT NULL CHECK (status IN (
        'awaiting_first_occurrence',
        'finalised',
        'failed'
    )),
    -- Versioned JSON Phase-A material (SdrPhaseAMaterial). Never empty.
    material BYTEA NOT NULL CHECK (octet_length(material) > 0),
    -- Named permanent failure reason when status = failed.
    fail_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS v1_sdr_phase_a_open_idx
    ON v1_sdr_phase_a (status)
    WHERE status = 'awaiting_first_occurrence';

CREATE INDEX IF NOT EXISTS v1_sdr_phase_a_subject_idx
    ON v1_sdr_phase_a (subject)
    WHERE status = 'awaiting_first_occurrence';
