-- v1.1 pending nullifier-publish recovery (Cutover G3 fix-round-2).
--
-- After a receive (or later mint/send) finalises, the account holds
-- last_proof + NullifierOpening (Pk, R, R') but not the Schnorr s, the
-- BatchMember, or the raw commit/reveal pair. Without those a crash mid-
-- publish leaves the node unable to rebroadcast or safely abandon.
--
-- This table stores everything a rebroadcast needs, walking each row
-- through the state machine:
--
--   members_ready  → intent durable (s + BatchMember); no txs yet
--   constructed    → raw commit_tx + reveal_tx persisted; nothing broadcast
--   commit_broadcast → commit on chain (or accepted by mempool); reveal pending
--   reveal_broadcast → both legs broadcast; scanner will fold on inclusion
--   complete       → optional terminal after scan-fold observed
--   failed         → operator abandoned (explicit; never silent)
--
-- Crash windows after this table exists:
--
-- | Window | Durable state | Recovery |
-- |--------|---------------|----------|
-- | After finalise, before members_ready insert | account only | clean retry of finalise path (or re-sign) |
-- | members_ready, no txs | s + member | re-construct txs, continue |
-- | constructed, neither broadcast | full pair | broadcast commit then reveal |
-- | commit_broadcast, no reveal | full pair + commit status | broadcast reveal only |
-- | reveal_broadcast | full pair | wait for scanner fold; no rebroadcast required |
--
-- Engine snapshot clears (v11_accounts/…) do NOT touch this table: a pending
-- publish outlives a concurrent NfLog rewrite.

CREATE TABLE v11_pending_publishes (
    -- Primary key is the transition's account-state nullifier Pk (one pending
    -- publish per account state key; a second transition must wait for scan).
    pk BYTEA PRIMARY KEY CHECK (octet_length(pk) = 32),
    owner BYTEA NOT NULL CHECK (octet_length(owner) = 32),
    -- NullifierSig components (BIP-340 R || s) plus S2C R'.
    r BYTEA NOT NULL CHECK (octet_length(r) = 32),
    s BYTEA NOT NULL CHECK (octet_length(s) = 32),
    r_prime BYTEA NOT NULL CHECK (octet_length(r_prime) = 32),
    -- BatchMember::build_tip
    build_tip_height BIGINT NOT NULL CHECK (build_tip_height >= 0 AND build_tip_height <= 4294967295),
    build_tip_hash BYTEA NOT NULL CHECK (octet_length(build_tip_hash) = 32),
    -- Consensus-serialised Transaction bytes; NULL until status ≥ constructed.
    commit_tx BYTEA,
    reveal_tx BYTEA,
    -- Derived txids (stable once constructed); NULL until constructed.
    commit_txid BYTEA CHECK (commit_txid IS NULL OR octet_length(commit_txid) = 32),
    reveal_txid BYTEA CHECK (reveal_txid IS NULL OR octet_length(reveal_txid) = 32),
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CHECK (status IN (
        'members_ready',
        'constructed',
        'commit_broadcast',
        'reveal_broadcast',
        'complete',
        'failed'
    )),
    -- Txs appear together. `members_ready` has none. `constructed` /
    -- `commit_broadcast` require both. Terminal statuses may keep or drop
    -- txs (`reveal_broadcast` without txs is the non-construct publisher path
    -- where only the signature was durable).
    CHECK (
        (status = 'members_ready'
         AND commit_tx IS NULL AND reveal_tx IS NULL
         AND commit_txid IS NULL AND reveal_txid IS NULL)
        OR
        (status IN ('constructed', 'commit_broadcast')
         AND commit_tx IS NOT NULL AND reveal_tx IS NOT NULL
         AND commit_txid IS NOT NULL AND reveal_txid IS NOT NULL)
        OR
        (status IN ('reveal_broadcast', 'complete', 'failed'))
    )
);

CREATE UNIQUE INDEX v11_pending_publishes_commit_txid_uidx
    ON v11_pending_publishes (commit_txid)
    WHERE commit_txid IS NOT NULL;

CREATE INDEX v11_pending_publishes_status_idx
    ON v11_pending_publishes (status)
    WHERE status NOT IN ('complete', 'failed');
