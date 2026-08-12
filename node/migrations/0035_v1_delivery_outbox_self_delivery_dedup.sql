-- Fix (§4.2 durable delivery outbox): self_delivery rows use a constant
-- zero coin_id sentinel (one SDR per transition, not one per coin — see
-- v1/delivery.rs::insert_sdr_outbox_pending), so the original
-- (subject, coin_id, kind) UNIQUE constraint from 0032 admits at most ONE
-- self_delivery row EVER per subject: every 2nd-and-later transition's
-- self-delivery insert fails a UNIQUE violation. The outbox_id PRIMARY KEY
-- already provides correct per-transition dedup via
-- ON CONFLICT (outbox_id) DO NOTHING
-- (outbox_id = SHA-256(kind ‖ subject ‖ coin_id ‖ transition_pk),
-- db_outbox::outbox_id). Widen the UNIQUE constraint to include
-- transition_pk so self_delivery rows are distinct per transition, while
-- external-delivery (subject, coin_id, kind) dedup is unaffected (an
-- external coin_id is already unique per transition, so adding
-- transition_pk to that arm changes no observable behaviour).

ALTER TABLE v1_delivery_outbox
    DROP CONSTRAINT v1_delivery_outbox_subject_coin_kind_uq;

ALTER TABLE v1_delivery_outbox
    ADD CONSTRAINT v1_delivery_outbox_subject_coin_kind_uq
    UNIQUE (subject, coin_id, kind, transition_pk);
