-- 0024_api_tokens: personal access tokens for the JSON data API and the
-- per-user salt of the private feed address (Go only; see docs/auth.md and
-- docs/api.md).
--
-- Additive only: two new tables and their indexes.
--
-- 1. api_tokens: a signed-in user creates up to 5 live tokens on the account
--    page. The secret ("nday_" + 32 random bytes, base64url) is shown once
--    and never stored: token_hash is its SHA-256. A revoked token keeps its
--    row (revoked_at set) and never works again. Part of the account: the
--    rows go when the user is deleted.
--
-- 2. feed_keys: one random salt per user. The private feed address carries
--    an HMAC of (user id, salt) under a key derived from the server secret,
--    so the address can be shown again at any time without storing it;
--    replacing the salt (rotation) invalidates the old address.

CREATE TABLE api_tokens (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    name         text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    token_hash   bytea NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz,
    revoked_at   timestamptz
);
CREATE INDEX api_tokens_user_idx ON api_tokens (user_id);

CREATE TABLE feed_keys (
    user_id    uuid PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    salt       bytea NOT NULL CHECK (octet_length(salt) = 16),
    created_at timestamptz NOT NULL DEFAULT now()
);
