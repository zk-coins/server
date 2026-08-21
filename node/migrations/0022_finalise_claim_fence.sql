-- Monotonic fencing tokens for exclusive finalise claim acquisition.
--
-- Owner identity alone cannot fence durable writes: the same process can hold
-- an old claim and a new one after lease expiry + reclaim. Every claim win
-- therefore mints a fresh token from this sequence; durable host-edge writes
-- are conditional on the token that was current when the work began.
--
-- Unqualified so search_path-scoped test schemas (test_db) each get their own
-- sequence; production public schema gets one global counter.

CREATE SEQUENCE finalise_claim_fence_seq AS BIGINT;
