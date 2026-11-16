-- 0007_admin: the audit log of staff actions (Go only; see docs/admin.md).
--
-- Additive only: one new table, its indexes, and a trigger function.
--
-- Every staff action (comment hide/unhide, report resolve, user suspend /
-- unsuspend, role change, sign-out-everywhere) appends one row IN THE SAME
-- TRANSACTION as the change, on the web and in the CLI commands; a failed
-- insert fails the action. No code path updates or deletes rows, and the
-- trigger below refuses UPDATE, DELETE and TRUNCATE for every role that is
-- subject to triggers. It is a guard against mistakes, NOT against the
-- table's owner or a superuser: they can still DROP the trigger or the
-- table, ALTER TABLE ... DISABLE TRIGGER, or SET session_replication_role =
-- replica. In the current deployment the application connects as the role
-- that owns the tables (the same role runs migrations), so the trigger does
-- not stop a compromised application process; that would need a separate,
-- less privileged runtime role with only INSERT and SELECT on this table.
--
-- actor_id has NO foreign key: the row must outlive the account (deleting a
-- user must neither fail nor erase what that user did). actor_handle and
-- actor_role are snapshots taken in the same transaction. Commands run on
-- the server have actor_id NULL, actor_role 'cli' and source 'cli'.

CREATE TABLE admin_audit (
    id           bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    at           timestamptz NOT NULL DEFAULT now(),
    actor_id     uuid,
    actor_handle text CHECK (char_length(actor_handle) <= 64),
    actor_role   text NOT NULL CHECK (actor_role IN ('user', 'moderator', 'admin', 'cli')),
    -- short code, e.g. comment.hide, user.role, x.settings.update (list in docs/admin.md)
    action       text NOT NULL CHECK (action ~ '^[a-z]+(\.[a-z_]+)+$' AND char_length(action) <= 40),
    -- x_settings: the xposts collector's settings row (target_id '1');
    -- x_account: an allowlisted X account (target_id = numeric user id, or
    -- 'import' for a bulk import)
    target_type  text NOT NULL CHECK (target_type IN ('comment', 'report', 'user', 'x_settings', 'x_account')),
    target_id    text NOT NULL CHECK (char_length(target_id) BETWEEN 1 AND 64),
    -- human-readable snapshot as plain text: the handle, or a comment excerpt
    target_label text CHECK (char_length(target_label) <= 200),
    reason       text CHECK (char_length(reason) <= 500),
    details      jsonb NOT NULL DEFAULT '{}'::jsonb
                 CHECK (jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 2048),
    source       text NOT NULL CHECK (source IN ('web', 'cli')),
    -- web actions only: the client address as the rate limiter sees it and
    -- Cloudflare's request id
    client_addr  text CHECK (char_length(client_addr) <= 64),
    cf_ray       text CHECK (char_length(cf_ray) <= 64),
    CHECK ((source = 'cli') = (actor_id IS NULL)),
    CHECK ((source = 'cli') = (actor_role = 'cli')),
    CHECK (source = 'web' OR (client_addr IS NULL AND cf_ray IS NULL))
);

CREATE INDEX admin_audit_at_idx ON admin_audit (at DESC, id DESC);
CREATE INDEX admin_audit_target_idx ON admin_audit (target_type, target_id, at DESC);
CREATE INDEX admin_audit_actor_idx ON admin_audit (lower(actor_handle), at DESC);
CREATE INDEX admin_audit_action_idx ON admin_audit (action, at DESC);

CREATE FUNCTION admin_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'admin_audit is append-only: % refused', TG_OP
        USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE TRIGGER admin_audit_no_change BEFORE UPDATE OR DELETE ON admin_audit
    FOR EACH ROW EXECUTE FUNCTION admin_audit_append_only();
CREATE TRIGGER admin_audit_no_truncate BEFORE TRUNCATE ON admin_audit
    FOR EACH STATEMENT EXECUTE FUNCTION admin_audit_append_only();
