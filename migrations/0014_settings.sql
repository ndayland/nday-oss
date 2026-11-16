-- 0014_settings: configuration managed from the database (Go only;
-- internal/settings).
--
-- app_settings holds the settings an operator may change at run time
-- without editing the environment: one row per NDAY_* variable name.
-- Lookup is layered: a row here wins over the environment variable of the
-- same name; no row means "not set in the database" (the environment
-- variable, else the built-in default, applies as before). Only the keys
-- of internal/settings' registry are ever read from this table; everything
-- else (database URL, server secrets, origins, pool sizes, TLS, ...) is
-- read from the environment only.
--
-- A plain setting is stored in `value`; a secret (tokens, client secrets,
-- the Apple .p8 key) only as AES-256-GCM ciphertext in `secret`, sealed
-- with a key derived from the master key NDAY_SETTINGS_KEY, which never
-- leaves the environment. `hint` is the last few characters of a secret
-- (shown to staff to tell secrets apart), or NULL.

CREATE TABLE app_settings (
    key        text PRIMARY KEY
               CONSTRAINT app_settings_key CHECK (key ~ '^NDAY_[A-Z0-9_]{1,60}$'),
    value      text
               CONSTRAINT app_settings_value_len CHECK (char_length(value) <= 1024),
    secret     bytea
               CONSTRAINT app_settings_secret_len CHECK (octet_length(secret) <= 16384),
    hint       text
               CONSTRAINT app_settings_hint_len CHECK (char_length(hint) <= 8),
    updated_at timestamptz NOT NULL DEFAULT now(),
    -- exactly one of value / secret
    CONSTRAINT app_settings_one_kind CHECK ((value IS NULL) <> (secret IS NULL))
);

-- Changes are audited with target type 'setting' (target_id = the key);
-- widen the CHECK of 0012 (same name, superset).
ALTER TABLE admin_audit DROP CONSTRAINT admin_audit_target_type_check;
ALTER TABLE admin_audit ADD CONSTRAINT admin_audit_target_type_check
    CHECK (target_type IN ('comment', 'report', 'user', 'x_settings', 'x_account', 'x_draft', 'setting'));
