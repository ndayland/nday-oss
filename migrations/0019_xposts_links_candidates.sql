-- 0019_xposts_links_candidates: links in allowlisted X posts, and accounts
-- those posts quote, reply to or mention (Go only; see docs/xposts.md).
--
-- Three tables, all additive; written idempotently by the pipeline from the
-- xposts raw records (Normalize), except the resolver columns of
-- x_post_link, which `nday x-links-resolve` fills.
--
-- 1. x_post_link: one row per link of a stored post (posts with a CVE id,
--    stored as event rows, and posts without one, x_post_no_cve), key
--    (post id, position of the link in the post). No foreign key: the post
--    lives in event (several rows per post) or in x_post_no_cve.
--    Links come from the API's entities (origin 'api', status 'ok') or, for
--    raw records stored before the collector asked for entities, from the
--    t.co short links in the text (status 'pending'); the resolver then
--    reads the t.co redirect (origin 'resolver', status 'ok', or 'failed'
--    after 3 attempts). A row is never downgraded from 'ok' to 'pending'.
--
-- 2. x_account_candidate: X users that allowlisted researchers quote, reply
--    to or mention — candidates for the allowlist, decided by an admin
--    ('pending' or 'dismissed'; a dismissed candidate stays dismissed).
--    handle is the username the API sent (NULL when it was not a valid
--    handle); display code must still check it with xconfig.ValidHandle.
--
-- 3. x_account_candidate_ref: why: one row per (candidate, post, kind).

CREATE TABLE x_post_link (
    post_id      text NOT NULL CHECK (post_id ~ '^[0-9]{1,19}$'),
    -- order of the link in the post (0-based)
    pos          integer NOT NULL CHECK (pos >= 0),
    -- the t.co link as it appears in the text
    short_url    text NOT NULL,
    -- the API's expanded_url, or the resolver's Location header
    expanded_url text,
    -- unwound_url when the API sent one, else expanded_url
    final_url    text,
    -- lower-case host of final_url without a leading "www."
    host         text,
    -- internal/xlinks.Classify; 'other' while pending
    kind         text NOT NULL CHECK (kind IN ('media', 'quote', 'patch', 'code', 'poc', 'advisory', 'other')),
    -- the API's link title (card title); NULL when absent
    title        text,
    origin       text NOT NULL CHECK (origin IN ('api', 'resolver')),
    status       text NOT NULL CHECK (status IN ('ok', 'pending', 'failed')),
    -- resolver requests made for this row
    attempts     integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    -- when the resolver resolved it; NULL for links from the API
    resolved_at  timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (post_id, pos)
);
CREATE INDEX x_post_link_status_idx ON x_post_link (status);
CREATE INDEX x_post_link_host_idx ON x_post_link (host);

CREATE TABLE x_account_candidate (
    user_id       text PRIMARY KEY CHECK (user_id ~ '^[1-9][0-9]{0,18}$'),
    handle        text,
    -- posted_at of the oldest / newest post that referred to the user
    first_seen_at timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    status        text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'dismissed')),
    decided_at    timestamptz
);

CREATE TABLE x_account_candidate_ref (
    user_id     text NOT NULL REFERENCES x_account_candidate (user_id) ON DELETE CASCADE,
    -- the stored (allowlisted) post that refers to the user
    post_id     text NOT NULL CHECK (post_id ~ '^[0-9]{1,19}$'),
    -- the post's author: an allowlisted id when stored (no foreign key, as
    -- x_post_no_cve.author_id)
    referrer_id text NOT NULL CHECK (referrer_id ~ '^[0-9]{1,19}$'),
    kind        text NOT NULL CHECK (kind IN ('quoted', 'replied_to', 'mentioned')),
    posted_at   timestamptz NOT NULL,
    PRIMARY KEY (user_id, post_id, kind)
);
CREATE INDEX x_account_candidate_ref_referrer_idx ON x_account_candidate_ref (referrer_id);
