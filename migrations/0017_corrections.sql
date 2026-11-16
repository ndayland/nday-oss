-- 0017_corrections: readers' corrections of vulnerability pages (Go only;
-- see docs/corrections.md).
--
-- A signed-in reader reports that something on a vulnerability page is
-- wrong or missing (title, summary, affected products or versions, fix
-- information, a timeline event, source links, other). Staff accept or
-- reject it on /admin/corrections. An accepted correction becomes a public
-- revision note on the vulnerability page: the note an editor wrote
-- (public_note), its category, the time it was accepted and the
-- submitter's public handle. Accepting does NOT change the vulnerability
-- data (that comes from the collectors and would be overwritten by the
-- next run); the submitter's own text, the evidence link, pending and
-- rejected rows and the internal note are never public.
--
-- Additive only: one new table and its indexes; the CHECK on
-- admin_audit.target_type is widened (same name, superset of 0014's).
--
-- Foreign keys, following comments / comment_reports (0005):
--   - cve_id REFERENCES vuln with the default NO ACTION: vuln rows are never
--     deleted by the pipeline (docs/discuss.md §2.4); a future job that
--     deletes vuln rows fails loudly instead of silently dropping the public
--     revision log and must decide what happens to it first.
--   - submitter_id and decided_by REFERENCES users ON DELETE SET NULL
--     (docs/auth.md §2.1): deleting an account keeps its corrections, the
--     public note then shows no name ("deleted account"). Pending rows of a
--     deleted (or suspended) submitter stay in the queue but do not count
--     towards the per-vulnerability cap (internal/corrections). Who decided
--     stays in admin_audit (actor_id has no FK there).

-- Fail fast instead of queueing behind a long collector transaction (the
-- REFERENCES take SHARE ROW EXCLUSIVE on vuln and users, the ALTER takes
-- ACCESS EXCLUSIVE on admin_audit); see 0012. Each file runs in its own
-- transaction, so a timeout leaves nothing applied and a retry is safe.
SET LOCAL lock_timeout = '5s';

CREATE TABLE vuln_corrections (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id        text NOT NULL REFERENCES vuln (cve_id),
    submitter_id  uuid REFERENCES users (id) ON DELETE SET NULL,
    category      text NOT NULL CHECK (category IN ('title', 'summary', 'affected', 'fix', 'timeline', 'sources', 'other')),
    -- what the reader says is wrong or missing: plain text, normalised by
    -- the application (no control characters except tab/LF, no bidi
    -- embeddings, trimmed). Never public.
    body          text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 4000),
    -- optional evidence link: an absolute http(s) URL (the application
    -- validates it fully). Never public.
    evidence_url  text CHECK (evidence_url IS NULL OR (char_length(evidence_url) BETWEEN 8 AND 2048 AND evidence_url ~ '^https?://')),
    status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'accepted', 'rejected')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    decided_at    timestamptz,
    decided_by    uuid REFERENCES users (id) ON DELETE SET NULL,
    -- accepted: what the editor changed or confirmed, shown publicly
    public_note   text CHECK (public_note IS NULL OR char_length(public_note) BETWEEN 1 AND 1000),
    -- rejected: an optional note for staff only
    internal_note text CHECK (internal_note IS NULL OR char_length(internal_note) BETWEEN 1 AND 500),
    CONSTRAINT vuln_corrections_decided CHECK ((status = 'pending') = (decided_at IS NULL)),
    CONSTRAINT vuln_corrections_public_note CHECK ((status = 'accepted') = (public_note IS NOT NULL)),
    CONSTRAINT vuln_corrections_internal_note CHECK (status = 'rejected' OR internal_note IS NULL)
);
-- the public revision log of a vulnerability page
CREATE INDEX vuln_corrections_accepted_idx ON vuln_corrections (cve_id, decided_at DESC, id DESC) WHERE status = 'accepted';
-- open queue (oldest first) and the per-vulnerability cap of open ones
CREATE INDEX vuln_corrections_pending_idx ON vuln_corrections (created_at, id) WHERE status = 'pending';
CREATE INDEX vuln_corrections_pending_cve_idx ON vuln_corrections (cve_id) WHERE status = 'pending';
-- decided ones, most recently decided first (staff history)
CREATE INDEX vuln_corrections_decided_idx ON vuln_corrections (decided_at DESC, id DESC) WHERE status <> 'pending';
-- a submitter's own list and daily cap
CREATE INDEX vuln_corrections_submitter_idx ON vuln_corrections (submitter_id, created_at);

-- Decisions are audited with target type 'correction' (target_id = the
-- correction id).
ALTER TABLE admin_audit DROP CONSTRAINT admin_audit_target_type_check;
ALTER TABLE admin_audit ADD CONSTRAINT admin_audit_target_type_check
    CHECK (target_type IN ('comment', 'report', 'user', 'x_settings', 'x_account', 'x_draft', 'setting', 'correction'));
