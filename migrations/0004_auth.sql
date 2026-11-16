-- 0004_auth: accounts and sign-in (Go only; see docs/auth.md).
--
-- Identity is (provider, subject). No e-mail addresses, no provider tokens,
-- no avatars are stored. Other tables that reference a user must use
--   <col> uuid REFERENCES users (id) ON DELETE SET NULL
-- (authored content is anonymised, not deleted, when an account is deleted);
-- only the tables below, which ARE the account, use ON DELETE CASCADE.

CREATE TABLE users (
    -- Random (UUID v4), never sequential; the only id other tables use.
    id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Free text copied from the provider at first sign-in (sanitised by the
    -- application: no control or bidi-override characters, <= 64 characters).
    display_name      text CHECK (display_name IS NULL OR char_length(display_name) BETWEEN 1 AND 64),
    -- Public handle, chosen by the user (never derived from a provider):
    -- handle is the display casing, handle_key the canonical lower-case form
    -- that lives in the shared namespaces table (users and, later,
    -- organisations share one public namespace).
    handle            text,
    handle_key        text UNIQUE,
    handle_ns_kind    text NOT NULL DEFAULT 'user' CHECK (handle_ns_kind = 'user'),
    handle_changed_at timestamptz,
    locale            text CHECK (locale IS NULL OR (char_length(locale) <= 35
                                  AND locale ~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$')),
    -- Changed only by the CLI (nday auth-role).
    role              text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'moderator', 'admin')),
    status            text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
    suspended_until   timestamptz,
    status_reason     text CHECK (status_reason IS NULL OR char_length(status_reason) <= 500),
    terms_version     text CHECK (terms_version IS NULL OR char_length(terms_version) <= 64),
    terms_accepted_at timestamptz,
    -- WebAuthn user handle (user.id in passkey ceremonies): 32 random bytes,
    -- unrelated to id and to any personal data; created with the first passkey.
    webauthn_id       bytea UNIQUE CHECK (webauthn_id IS NULL OR octet_length(webauthn_id) = 32),
    created_at        timestamptz NOT NULL DEFAULT now(),
    last_seen_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT users_handle_pair CHECK ((handle IS NULL) = (handle_key IS NULL)),
    CONSTRAINT users_handle_canonical CHECK (handle_key = lower(handle)),
    CONSTRAINT users_terms_pair CHECK ((terms_version IS NULL) = (terms_accepted_at IS NULL)),
    CONSTRAINT users_status_fields CHECK (status = 'suspended' OR (suspended_until IS NULL AND status_reason IS NULL))
);

-- One public namespace for every root-level name (/<name>): today user
-- handles, later organisations (add 'org' to the kind CHECK and give the
-- organisations table the same (name_key, ns_kind) foreign key). A name is
-- unique here whatever owns it. 'held' rows are names released by a handle
-- change or an account deletion, blocked until held_until (housekeeping
-- deletes them afterwards); held_for lets the previous owner take a
-- just-released name back.
CREATE TABLE namespaces (
    name       text PRIMARY KEY CHECK (name ~ '^[a-z0-9][a-z0-9_-]{2,29}$'),
    kind       text NOT NULL CHECK (kind IN ('user', 'held')),
    created_at timestamptz NOT NULL DEFAULT now(),
    held_until timestamptz,
    held_for   uuid REFERENCES users (id) ON DELETE SET NULL,
    CONSTRAINT namespaces_name_kind UNIQUE (name, kind),
    CONSTRAINT namespaces_held CHECK ((kind = 'held') = (held_until IS NOT NULL))
);
CREATE INDEX namespaces_held_idx ON namespaces (held_until) WHERE kind = 'held';

-- A user's handle must be a 'user' namespace row (not held, not an org's).
ALTER TABLE users ADD CONSTRAINT users_handle_ns_fk
    FOREIGN KEY (handle_key, handle_ns_kind) REFERENCES namespaces (name, kind);

CREATE TABLE identities (
    provider     text NOT NULL CHECK (provider IN ('google', 'apple', 'github', 'x')),
    -- The provider's stable subject id (OIDC sub, GitHub numeric id, X id).
    subject      text NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 255),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Provider-side handle for display only (GitHub login, X username); may
    -- change or be reused upstream, so it is never used to identify anyone.
    handle       text CHECK (handle IS NULL OR char_length(handle) <= 100),
    linked_at    timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, subject),
    CONSTRAINT identities_one_per_provider UNIQUE (user_id, provider)
);

-- Only the SHA-256 of the session token is stored.
CREATE TABLE sessions (
    token_hash   bytea PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id      uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    created_at   timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    expires_at   timestamptz NOT NULL
);
CREATE INDEX sessions_user_idx ON sessions (user_id);
CREATE INDEX sessions_expires_idx ON sessions (expires_at);
CREATE INDEX sessions_last_seen_idx ON sessions (last_seen_at);

-- Passkeys (WebAuthn credentials, attestation "none").
CREATE TABLE passkeys (
    id                  uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id             uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- Unique across ALL users (WebAuthn L3 §7.1 step 26).
    credential_id       bytea NOT NULL UNIQUE CHECK (octet_length(credential_id) BETWEEN 1 AND 1023),
    -- SubjectPublicKeyInfo (DER) converted from the COSE key at registration.
    public_key          bytea NOT NULL CHECK (octet_length(public_key) <= 2048),
    algorithm           integer NOT NULL CHECK (algorithm IN (-7, -8, -257)),
    sign_count          bigint NOT NULL DEFAULT 0 CHECK (sign_count BETWEEN 0 AND 4294967295),
    -- Assertions refused because the counter did not increase (possible clone).
    counter_regressions integer NOT NULL DEFAULT 0,
    last_regression_at  timestamptz,
    aaguid              uuid,
    transports          text[] NOT NULL DEFAULT '{}' CHECK (cardinality(transports) <= 8),
    backup_eligible     boolean NOT NULL,
    backed_up           boolean NOT NULL,
    name                text NOT NULL CHECK (char_length(name) BETWEEN 1 AND 64),
    created_at          timestamptz NOT NULL DEFAULT now(),
    last_used_at        timestamptz
);
CREATE INDEX passkeys_user_idx ON passkeys (user_id);

-- Single-use marker for sign-in flows: SHA-256 of each OAuth `state` that
-- reached the callback and of each WebAuthn challenge that reached a finish
-- endpoint. The flow data itself lives in a sealed cookie.
CREATE TABLE auth_flow_used (
    state_hash bytea PRIMARY KEY CHECK (octet_length(state_hash) = 32),
    expires_at timestamptz NOT NULL
);
CREATE INDEX auth_flow_used_expires_idx ON auth_flow_used (expires_at);
