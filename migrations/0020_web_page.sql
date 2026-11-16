-- 0020_web_page: the queue of third-party web pages whose metadata (title,
-- site name) the site shows (Go only; internal/webpages, docs/webpages.md).
--
-- Additive. Producers enqueue URLs (webpages.Enqueue; today the X posts
-- links, internal/xlinks EnqueuePages); `nday pages-fetch` (also run after
-- every `nday collect xposts`) fetches pending rows through
-- internal/pagefetch (SSRF-guarded) and records the outcome:
--   'pending' not fetched yet, or a transient failure with attempts left;
--   'ok'      title found;
--   'none'    final: no usable title, not HTML, not 200, or refused;
--   'failed'  transient failures (transport error, 5xx, 429) 3 times; tried
--             again once a day (fetched_at older than 24 h) up to 6
--             attempts in all, then it stays 'failed'.
-- url_key is pagefetch.URLKey(url) (the site's resource key too): one row,
-- one fetch per distinct page. title and site_name are third-party text,
-- cleaned (pagefetch.CleanText) but untrusted: escape when displayed.

CREATE TABLE web_page (
    url_key      text PRIMARY KEY,
    -- the URL as first enqueued (absolute http/https, <= 2048 bytes)
    url          text NOT NULL CHECK (char_length(url) <= 2048),
    status       text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'ok', 'none', 'failed')),
    -- fetch attempts made
    attempts     integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    title        text CHECK (title IS NULL OR char_length(title) BETWEEN 1 AND 120),
    site_name    text CHECK (site_name IS NULL OR char_length(site_name) BETWEEN 1 AND 120),
    -- who enqueued it first (e.g. 'xposts')
    first_source text NOT NULL CHECK (first_source ~ '^[a-z][a-z0-9_]{0,31}$'),
    -- time of the last request (attempt); the slow retry of 'failed' rows
    -- waits 24 h after it
    fetched_at   timestamptz,
    created_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX web_page_status_idx ON web_page (status, created_at);

-- The X posts producer's sweep marker (internal/xlinks EnqueuePages): the
-- final_url last handed to the queue (queued, already queued under the
-- same key, or refused by the URL rules). A link is swept again only when
-- its final_url differs from this, so the sweep does not re-read the same
-- links on every run. Additive; NULL = not swept yet.
ALTER TABLE x_post_link ADD COLUMN page_queued_url text;
