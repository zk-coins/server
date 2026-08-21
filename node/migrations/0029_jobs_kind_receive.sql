-- §7.8 / §7.5: admit normative `receive` jobs (`kind == "receive"`).
-- Additive: only widens the jobs.kind CHECK. Existing mint/send/attest_balance
-- rows are unchanged.

ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_kind_check;
ALTER TABLE jobs
    ADD CONSTRAINT jobs_kind_check
    CHECK (kind IN ('mint', 'send', 'attest_balance', 'receive'));
