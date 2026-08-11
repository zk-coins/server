-- Gap G6: admit `attest_balance` jobs for the §7.5 balance-attestation surface.
-- Additive: only widens the jobs.kind CHECK. Legacy mint/send rows unchanged.

ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_kind_check
    CHECK (kind IN ('mint', 'send', 'attest_balance'));
