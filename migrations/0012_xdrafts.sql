-- 0012_xdrafts: draft posts for the brand X account (Go only; see
-- docs/xposts.md section "Drafts" and docs/admin.md).
--
-- Additive: two new tables and one widened CHECK; no existing row changes.
--
-- x_draft: one draft post per (CVE, stage) EVER, written by `nday x-drafts`
-- and the pass after every collector run (internal/xdraft) when a live
-- (non-backfill) poc_published / exploited_in_wild / kev_added event is the
-- first of its type for the CVE. Staff review it on /admin/x/drafts, may
-- edit the text, open X's own web compose window with it (the server never
-- calls the X API for this and stores no X credentials) and then mark it
-- posted or discard it. Drafts are NOT public: no public page, feed, sitemap
-- or API reads this table (internal/site/public.go, TestPostsNotPublic).
--
-- body is stored WITHOUT the link to the detail page; the page appends
-- "\n" + the absolute detail URL when it builds the compose URL (the
-- collectors' environment has no public origin). The weighted length rule
-- (X's twitter-text v3 weights, a link = 23) is enforced by the Go code
-- (internal/xdraft.WeightedLength); the CHECK only bounds the raw size.
--
-- cve_id references vuln with ON DELETE CASCADE like every other per-CVE
-- table except comments: no code path deletes vuln rows today, and if one
-- ever does, a draft must not make it fail. event_id has NO foreign key: it
-- records which event triggered the draft, and the draft (and its audit
-- trail) must survive a re-import that replaces events. decided_by is ON
-- DELETE SET NULL: deleting an account never fails because of a draft, and
-- who acted stays in admin_audit (actor_id has no FK there).
--
-- version is bumped by every staff change; every staff UPDATE repeats the
-- business rule (status) and the version the page was rendered with in its
-- WHERE clause, so a stale page or a second admin never silently overwrites
-- a newer state.

-- Fail fast instead of queueing: CREATE TABLE … REFERENCES vuln, users
-- takes SHARE ROW EXCLUSIVE on vuln and users, and the ALTER below takes
-- ACCESS EXCLUSIVE on admin_audit. Behind a long collector transaction the
-- migration would wait, and every new writer of those tables would queue
-- behind it. With this setting it gives up after 5 s (SQLSTATE 55P03); the
-- runner applies each file in its own transaction (internal/db.Migrate), so
-- nothing is left applied and a retry is safe. SET LOCAL ends with that
-- transaction.
SET LOCAL lock_timeout = '5s';

CREATE TABLE x_draft (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    cve_id     text NOT NULL REFERENCES vuln (cve_id) ON DELETE CASCADE,
    -- the stage event type that triggered the draft
    stage      text NOT NULL
               CONSTRAINT x_draft_stage CHECK (stage IN ('poc_published', 'exploited_in_wild', 'kev_added')),
    -- event.id of the triggering event (no FK, see above)
    event_id   bigint NOT NULL,
    body       text NOT NULL
               CONSTRAINT x_draft_body_len CHECK (char_length(body) BETWEEN 1 AND 1000),
    status     text NOT NULL DEFAULT 'draft'
               CONSTRAINT x_draft_status CHECK (status IN ('draft', 'posted', 'discarded')),
    -- the post on X, normalised to https://x.com/<handle>/status/<id>
    post_url   text
               CONSTRAINT x_draft_post_url CHECK (post_url ~ '^https://x\.com/[A-Za-z0-9_]{1,15}/status/[0-9]{1,20}$'),
    version    int NOT NULL DEFAULT 1 CONSTRAINT x_draft_version CHECK (version >= 1),
    -- who marked it posted / discarded, and when (NULL while a draft)
    decided_by uuid REFERENCES users (id) ON DELETE SET NULL,
    decided_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT x_draft_once UNIQUE (cve_id, stage),
    CONSTRAINT x_draft_post_url_posted CHECK (post_url IS NULL OR status = 'posted'),
    CONSTRAINT x_draft_decided CHECK ((status = 'draft') = (decided_at IS NULL)),
    CONSTRAINT x_draft_decided_by CHECK (status <> 'draft' OR decided_by IS NULL)
);
-- the review page: pending drafts newest first; history by decision time
CREATE INDEX x_draft_status_created_idx ON x_draft (status, created_at DESC, id DESC);
CREATE INDEX x_draft_decided_idx ON x_draft (decided_at DESC, id DESC) WHERE status <> 'draft';

-- The generator's watermark: exactly one row. last_event_id is the highest
-- event.id already considered; NULL never stays (the first run stores the
-- current maximum and drafts nothing, so history never becomes drafts).
CREATE TABLE x_draft_state (
    id            int PRIMARY KEY DEFAULT 1 CONSTRAINT x_draft_state_one_row CHECK (id = 1),
    last_event_id bigint,
    last_run_at   timestamptz,
    -- what the last run did (counts, deferral), shown to staff
    last_run      jsonb NOT NULL DEFAULT '{}'::jsonb
                  CONSTRAINT x_draft_state_last_run CHECK (jsonb_typeof(last_run) = 'object'),
    updated_at    timestamptz NOT NULL DEFAULT now()
);

-- Staff actions on drafts are audited with target type 'x_draft'
-- (target_id = draft id); widen the CHECK of 0007 (same name, superset).
ALTER TABLE admin_audit DROP CONSTRAINT admin_audit_target_type_check;
ALTER TABLE admin_audit ADD CONSTRAINT admin_audit_target_type_check
    CHECK (target_type IN ('comment', 'report', 'user', 'x_settings', 'x_account', 'x_draft'));
