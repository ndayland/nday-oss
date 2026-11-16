-- 0005_discuss: per-vulnerability discussions (Go only; see docs/discuss.md).
--
-- Additive only. One comment stream per vulnerability; a comment may have
-- replies one level deep. Authored rows reference users with
-- ON DELETE SET NULL (docs/auth.md §2.1): deleting an account keeps the
-- comments, without an author. Nothing here is ever deleted by the
-- application (author deletion and moderator hiding are status changes).
--
-- vuln rows are never deleted by the pipeline today (no DELETE FROM vuln in
-- Go or Python; a rejected CVE stays a vuln row with a cvelist "disclosed"
-- event whose detail.state is REJECTED). comments.cve_id therefore uses the
-- default NO ACTION: a future job that deletes vuln rows fails loudly
-- instead of silently dropping discussions, and must decide what happens to
-- them first.

CREATE TABLE comments (
    id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cve_id        text NOT NULL REFERENCES vuln (cve_id),
    -- Replies point at a top-level comment of the same vulnerability; this is
    -- enforced by the composite foreign key below (parent_id, cve_id,
    -- parent_is_reply=false) -> (id, cve_id, is_reply), so the database itself
    -- refuses a reply to a reply and a reply across vulnerabilities. The
    -- application additionally requires the parent to be visible (checked
    -- inside the INSERT, under a row lock).
    parent_id       uuid,
    is_reply        boolean NOT NULL,
    parent_is_reply boolean NOT NULL DEFAULT false CHECK (parent_is_reply = false),
    author_id     uuid REFERENCES users (id) ON DELETE SET NULL,
    -- Markdown source (internal/discuss/md), normalised by the application
    -- (LF line ends, no controls except tab/LF, no bidi embeddings, trimmed).
    body          text NOT NULL CHECK (char_length(body) BETWEEN 1 AND 10000),
    -- Locale tag of the page the comment was posted from (one stream for all
    -- site languages).
    lang          text NOT NULL CHECK (char_length(lang) <= 35 AND lang ~ '^[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*$'),
    -- false: written while the account was "new"; links render as text.
    -- Fixed at creation so rendering stays stable.
    links         boolean NOT NULL,
    status        text NOT NULL DEFAULT 'visible' CHECK (status IN ('visible', 'hidden', 'deleted')),
    created_at    timestamptz NOT NULL DEFAULT now(),
    edited_at     timestamptz,
    deleted_at    timestamptz,
    -- Time of the last change (create, edit, delete, hide, unhide).
    updated_at    timestamptz NOT NULL DEFAULT now(),
    -- Incremented by EVERY UPDATE of the row (no clock involved); with the
    -- status and the authors' public fields it makes the page cache key
    -- (discuss.Version), so every committed change changes the key.
    rev           bigint NOT NULL DEFAULT 1 CHECK (rev >= 1),
    hidden_at     timestamptz,
    hidden_by     uuid REFERENCES users (id) ON DELETE SET NULL,
    hidden_reason text CHECK (hidden_reason IS NULL OR char_length(hidden_reason) BETWEEN 1 AND 200),
    CONSTRAINT comments_reply_shape CHECK (is_reply = (parent_id IS NOT NULL)),
    CONSTRAINT comments_not_own_parent CHECK (parent_id IS NULL OR parent_id <> id),
    CONSTRAINT comments_hidden_fields CHECK (status <> 'hidden' OR (hidden_at IS NOT NULL AND hidden_reason IS NOT NULL)),
    CONSTRAINT comments_deleted_fields CHECK ((status = 'deleted') = (deleted_at IS NOT NULL)),
    CONSTRAINT comments_thread_key UNIQUE (id, cve_id, is_reply),
    CONSTRAINT comments_parent_fk FOREIGN KEY (parent_id, cve_id, parent_is_reply)
        REFERENCES comments (id, cve_id, is_reply)
);
-- top-level comments of a vulnerability, in order (page and cursor)
CREATE INDEX comments_cve_top_idx ON comments (cve_id, created_at, id) WHERE parent_id IS NULL;
-- replies of a thread, in order
CREATE INDEX comments_parent_idx ON comments (parent_id, created_at, id) WHERE parent_id IS NOT NULL;
-- a user's comments (daily limit, duplicate guard, "new account" count)
CREATE INDEX comments_author_idx ON comments (author_id, created_at);
-- site-wide patrol (GET /api/mod/recent)
CREATE INDEX comments_created_idx ON comments (created_at DESC, id DESC);

-- Previous bodies, one row per edit. Audit only: never exposed publicly.
CREATE TABLE comment_revisions (
    id          bigserial PRIMARY KEY,
    comment_id  uuid NOT NULL REFERENCES comments (id),
    body        text NOT NULL,
    replaced_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX comment_revisions_comment_idx ON comment_revisions (comment_id, replaced_at);

-- Reports by signed-in users. reporter_id is ON DELETE SET NULL (not
-- CASCADE): a report is moderation evidence and the open queue must not
-- shrink because the reporter deleted the account; the reporter is then
-- anonymous, like every other authored row (docs/auth.md §2.1).
CREATE TABLE comment_reports (
    id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    comment_id  uuid NOT NULL REFERENCES comments (id),
    reporter_id uuid REFERENCES users (id) ON DELETE SET NULL,
    reason      text NOT NULL CHECK (reason IN ('spam', 'abuse', 'off_topic', 'misinformation', 'malicious_link', 'illegal', 'other')),
    note        text CHECK (note IS NULL OR char_length(note) BETWEEN 1 AND 500),
    created_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz,
    resolved_by uuid REFERENCES users (id) ON DELETE SET NULL,
    -- hidden: the comment was hidden (automatic on hide); dismissed: no
    -- action needed; actioned: handled otherwise (e.g. the author suspended)
    resolution  text CHECK (resolution IN ('hidden', 'dismissed', 'actioned')),
    CONSTRAINT comment_reports_resolved CHECK ((resolved_at IS NULL) = (resolution IS NULL))
);
-- one OPEN report per (comment, reporter)
CREATE UNIQUE INDEX comment_reports_open_uniq ON comment_reports (comment_id, reporter_id) WHERE resolved_at IS NULL;
CREATE INDEX comment_reports_open_idx ON comment_reports (created_at, id) WHERE resolved_at IS NULL;
CREATE INDEX comment_reports_resolved_idx ON comment_reports (resolved_at DESC, id DESC) WHERE resolved_at IS NOT NULL;
CREATE INDEX comment_reports_reporter_idx ON comment_reports (reporter_id, created_at);
