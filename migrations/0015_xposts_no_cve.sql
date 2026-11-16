-- 0015_xposts_no_cve: keep allowlisted X posts that name no CVE id yet
-- (Go only; see docs/xposts.md).
--
-- The xposts search query is "(from:... OR ...) CVE -is:retweet", so the API
-- also returns (and bills) posts of allowlisted researchers that talk about a
-- vulnerability before it has an id ("CVE pending", "CVE soon"), or that
-- write the id in a form ExtractCVEs does not accept. Until now they were
-- dropped before storage. They are now stored here, for a later "early
-- warning" feature that links such a post to the CVE once it is known.
-- Nothing reads these tables yet: no page and no API shows them.
--
-- Two changes, both additive:
--
-- 1. x_post_no_cve: one row per post (key = post id; written idempotently by
--    the pipeline, like event rows: observed_at and is_backfill are never
--    changed after the first insert, the other columns follow the latest raw
--    version). The raw payload is in raw_record (source 'xposts', key = post
--    id), exactly like posts that name a CVE id. These posts never become
--    event rows: event.cve_id is NOT NULL and references vuln.
--
-- 2. x_post_no_cve_link: the CVE ids a post is later linked to (zero, one or
--    several per post), with the time of the link. Nothing writes it yet.
--    Rows go away with the post or the vuln (ON DELETE CASCADE, like event).
--
-- Only checks the collector already guarantees (Normalize rejects anything
-- else), so a stored row can never fail a run; the handle is NOT checked
-- (event.detail.author_handle is not either): display code must validate it.

CREATE TABLE x_post_no_cve (
    -- X post id, decimal text (64-bit, may exceed JS integers)
    post_id       text PRIMARY KEY CHECK (post_id ~ '^[0-9]{1,19}$'),
    -- numeric author id; an allowlisted id when stored (x_accounts.user_id),
    -- deliberately not a foreign key: allowlist rows are never deleted
    author_id     text NOT NULL CHECK (author_id ~ '^[0-9]{1,19}$'),
    -- username from includes.users at fetch time; NULL when the API sent no
    -- author object
    author_handle text,
    text          text NOT NULL,
    -- the API's lang field; NULL when absent
    lang          text,
    -- post created_at (what X says)
    posted_at     timestamptz NOT NULL,
    -- https://x.com/<handle>/status/<id> or https://x.com/i/web/status/<id>
    url           text NOT NULL,
    -- when our collector first stored it (the pipeline's run time)
    observed_at   timestamptz NOT NULL,
    -- true = stored by the collector's first (bulk) run, as for event rows
    is_backfill   boolean NOT NULL DEFAULT false
);

CREATE TABLE x_post_no_cve_link (
    post_id   text NOT NULL REFERENCES x_post_no_cve (post_id) ON DELETE CASCADE,
    cve_id    text NOT NULL REFERENCES vuln (cve_id) ON DELETE CASCADE,
    linked_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (post_id, cve_id)
);
CREATE INDEX x_post_no_cve_link_cve_idx ON x_post_no_cve_link (cve_id);
