-- Persist block header timestamps for local BIP-113 median-time-past verification.

ALTER TABLE block_log ADD COLUMN block_time BIGINT;
