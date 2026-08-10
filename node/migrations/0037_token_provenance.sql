-- §4.6 Class B / §4.8 data permanence: issuer-originated token provenance.
--
-- A receiving node writes this table only after CoinProof verification has
-- accepted the bundle's self-authenticating asset_terms. The value is the
-- exact canonical §7.1 IssuanceTerms encoding used inside CoinProof; no
-- database-only codec exists.
--
-- This table is deliberately not state-epoch scoped. Provenance is a received
-- artefact, not rebuildable derived chain state, and must survive self-heal,
-- reorg handling, engine replacement, and every other canonical-view reset.
-- There is no delete path.

CREATE TABLE token_provenance (
    asset_id BYTEA PRIMARY KEY CHECK (octet_length(asset_id) = 32),
    issuance_terms BYTEA NOT NULL CHECK (octet_length(issuance_terms) > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
