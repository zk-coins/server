-- Durable bridge from begin_v1_mint's raw MintRequest name to finalise-time
-- CoinProof.asset_terms construction.
--
-- Rows are keyed by the mint job's node-assigned, globally unique id, which is
-- never reused across attempts. A cancelled attempt therefore cannot shadow or
-- block a later attempt on the same account. Rows are never deleted because
-- crash-resume may read the same job's row more than once. See
-- db_mint_terms_staging.rs for why DELETE-on-read is unsafe.

CREATE TABLE v1_mint_terms_staging (
    job_id UUID PRIMARY KEY,
    pk_create BYTEA NOT NULL CHECK (octet_length(pk_create) = 32),
    issuance_terms BYTEA NOT NULL CHECK (octet_length(issuance_terms) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
