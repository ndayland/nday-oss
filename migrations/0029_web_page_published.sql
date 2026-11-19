-- 0029_web_page_published: the publication time a fetched third-party page
-- states about itself (Go only; internal/pagefetch ExtractPublished,
-- internal/webpages, docs/webpages.md "Publication time").
--
-- Additive: four nullable columns without defaults (a catalog change, no
-- table rewrite); the CHECK constraints scan web_page once, a small table.
--   published_at        the stated publication time (UTC; for 'day'
--                       precision midnight UTC of the stated date); NULL =
--                       none found (or not looked at yet);
--   published_precision 'exact' (a time with a zone) or 'day';
--   published_source    where it was read: 'json-ld', 'meta:<name>',
--                       'meta:itemprop' or 'time' (for operators);
--   published_checked_at when nday last looked for it. Every fetch sets it;
--                       the backfill (webpages.Options.Backfill) re-fetches
--                       'ok' rows where it is NULL, oldest first, once each.

ALTER TABLE web_page
    ADD COLUMN published_at timestamptz,
    ADD COLUMN published_precision text CHECK (published_precision IN ('exact', 'day')),
    ADD COLUMN published_source text CHECK (published_source ~ '^[a-z0-9:._-]{1,64}$'),
    ADD COLUMN published_checked_at timestamptz,
    ADD CONSTRAINT web_page_published_whole CHECK ((published_at IS NULL) = (published_precision IS NULL)
        AND (published_at IS NULL) = (published_source IS NULL));

-- the backfill's pick: 'ok' rows not looked at yet, oldest first
CREATE INDEX web_page_published_todo_idx ON web_page (created_at) WHERE status = 'ok' AND published_checked_at IS NULL;
