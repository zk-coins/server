-- Add op_secret (A/4') to the v1.1 operational bundle stored per account.
--
-- Spec §1.2 / §1.4: nav_rand = HKDF("zkCoins/v1/NavRand", op_secret ‖ u64-be(send_counter)).
-- Like nk, the secret is entrusted only to the account's own node. It is never
-- sent to a foreign node. Pre-0023 rows keep NULL; any transition that needs
-- nav_rand refuses rather than inventing a value (no silent default).

ALTER TABLE v11_accounts
    ADD COLUMN op_secret BYTEA
        CHECK (op_secret IS NULL OR octet_length(op_secret) = 32);
