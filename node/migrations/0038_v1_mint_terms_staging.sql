-- Durable bridge from begin_v1_mint's raw MintRequest name to finalise-time
-- CoinProof.asset_terms construction.
--
-- Rows are never deleted: crash-resume may read the same one-time pk_create
-- more than once. See db_mint_terms_staging.rs for why DELETE-on-read is unsafe.

CREATE TABLE v1_mint_terms_staging (
    pk_create BYTEA PRIMARY KEY CHECK (octet_length(pk_create) = 32),
    issuance_terms BYTEA NOT NULL CHECK (octet_length(issuance_terms) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
