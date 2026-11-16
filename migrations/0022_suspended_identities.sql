-- 0022_suspended_identities: suspensions that outlive a deleted account
-- (Go only; see docs/auth.md).
--
-- Additive only: one new table and its index.
--
-- Deleting an account removes its identities, so without this table a
-- suspended user could delete the account and sign in again with the same
-- provider identity to get a fresh, active one. When an account is deleted
-- while its suspension is in effect, each of its identities leaves one row
-- here; a later first sign-in with that identity creates the new account
-- already suspended until the same time (and uses the row up), and linking
-- the identity to another account is refused while the row is live.
--
-- Nothing about the person is kept: no user id, no handle, no reason, and
-- not the subject itself, only an HMAC-SHA256 of (provider, subject) under a
-- key derived from the server secret (internal/auth/crypto.go). Rows whose
-- suspended_until has passed are ignored and deleted by housekeeping;
-- suspended_until NULL means the suspension had no end.

CREATE TABLE suspended_identities (
    provider        text NOT NULL CHECK (provider IN ('google', 'apple', 'github', 'x')),
    subject_hash    bytea NOT NULL CHECK (octet_length(subject_hash) = 32),
    suspended_until timestamptz,
    created_at      timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject_hash)
);
CREATE INDEX suspended_identities_until_idx ON suspended_identities (suspended_until)
    WHERE suspended_until IS NOT NULL;
