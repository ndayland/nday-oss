-- 0038_x_user: the X profile of the accounts whose posts we store (Go only;
-- collector xposts, internal/xavatar, docs/xposts.md "Author profiles and
-- avatars").
--
-- Additive. The search request asks for user.fields=name,profile_image_url
-- and the pipeline writes one row per post author from the raw record's
-- includes.users object: the display name (cleaned: no control or bidi
-- characters, whitespace collapsed, at most 64 characters) and the avatar
-- URL (kept only when it is https://pbs.twimg.com/profile_images/...).
-- Raw records stored before the request asked for those fields carry
-- neither and write nothing here; every author fills in on the next run.
--
-- The avatar bytes are fetched by `nday site-icons` (the same daily job and
-- guarded fetcher as site icons, internal/pagefetch) and served from our
-- own origin at /avatar/<hash>, so readers never contact X or twimg:
--   'ok'    an image is stored (also kept while later attempts fail);
--   'none'  the URL did not give a usable image: tried again after 30 days
--           or when the URL changes;
--   'error' transient failures without a stored image: tried again after
--           1 h, 4 h, 16 h, ... (avatar_failures), at most 30 days.
-- The image is third-party content: served only with the sniffed content
-- type, nosniff and a sandboxing CSP.

CREATE TABLE x_user (
    -- numeric X user id as decimal text (like x_accounts.user_id)
    user_id            text PRIMARY KEY CHECK (user_id ~ '^[1-9][0-9]{0,18}$'),
    -- display name, cleaned; NULL when absent or empty after cleaning.
    -- Untrusted upstream text: only ever rendered as text
    name               text CHECK (char_length(name) BETWEEN 1 AND 64),
    -- profile_image_url as validated (https://pbs.twimg.com/profile_images/...),
    -- NULL when absent or refused
    avatar_url         text CHECK (char_length(avatar_url) <= 2048),
    -- when the raw record the profile came with was fetched from X
    -- (raw_record.fetched_at): an older fetch (renormalize) never
    -- overwrites a newer profile
    seen_at            timestamptz NOT NULL,
    updated_at         timestamptz NOT NULL DEFAULT now(),
    -- avatar fetch state (internal/xavatar)
    avatar_status      text CHECK (avatar_status IN ('ok', 'none', 'error')),
    avatar_type        text CHECK (avatar_type IN ('image/png', 'image/jpeg', 'image/webp', 'image/gif')),
    avatar_image       bytea CHECK (octet_length(avatar_image) BETWEEN 1 AND 262144),
    -- first 16 hex digits of the image's SHA-256 (the path of /avatar/<hash>)
    avatar_hash        text CHECK (avatar_hash ~ '^[0-9a-f]{16}$'),
    -- the avatar_url the stored image came from
    avatar_src         text CHECK (char_length(avatar_src) <= 2048),
    -- the avatar_url of the last attempt (any outcome); a different
    -- avatar_url makes the row due at once
    avatar_tried       text CHECK (char_length(avatar_tried) <= 2048),
    avatar_fetched_at  timestamptz,
    avatar_next_try_at timestamptz,
    avatar_failures    integer NOT NULL DEFAULT 0 CHECK (avatar_failures >= 0),
    -- short reason of the last 'none' or failed attempt; for operators only
    avatar_error       text CHECK (char_length(avatar_error) <= 200),
    CHECK ((avatar_image IS NULL) = (avatar_type IS NULL) AND (avatar_image IS NULL) = (avatar_hash IS NULL)),
    CHECK ((avatar_status = 'ok') = (avatar_image IS NOT NULL))
);
CREATE INDEX x_user_avatar_hash_idx ON x_user (avatar_hash) WHERE avatar_hash IS NOT NULL;
