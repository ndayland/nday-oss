-- 0016_comment_purpose: an optional purpose on top-level comments (Go only;
-- see docs/discuss.md).
--
-- The compose box lets the author say what a top-level comment is for, to
-- steer the discussion towards concrete contributions: a technical analysis,
-- a report of reproducing the issue, a report about a fix, a detection
-- method, or a question. It is optional (NULL = not given) and replies never
-- have one. The author may change it when editing; the previous value is
-- kept with the previous body in comment_revisions.
--
-- Two changes, both additive (existing rows get NULL and satisfy every
-- check):
--
-- 1. comments.purpose: NULL or one of the five codes; only on top-level
--    comments (parent_id IS NULL).
--
-- 2. comment_revisions.purpose: the purpose the comment had before the edit
--    the row records (NULL = none, or a reply). Older rows were written
--    before purposes existed and correctly hold NULL.

-- Fail fast instead of queueing: every ALTER TABLE below takes ACCESS
-- EXCLUSIVE on comments or comment_revisions. Behind a long transaction
-- reading those tables the migration would wait, and every new reader and
-- writer of them would queue behind it; see 0012. Each file runs in its own
-- transaction, so a timeout leaves nothing applied and a retry is safe.
SET LOCAL lock_timeout = '5s';

ALTER TABLE comments ADD COLUMN purpose text;
ALTER TABLE comments ADD CONSTRAINT comments_purpose_values
    CHECK (purpose IS NULL OR purpose IN ('analysis', 'reproduction', 'fix', 'detection', 'question'));
ALTER TABLE comments ADD CONSTRAINT comments_purpose_top_level
    CHECK (purpose IS NULL OR parent_id IS NULL);

ALTER TABLE comment_revisions ADD COLUMN purpose text;
ALTER TABLE comment_revisions ADD CONSTRAINT comment_revisions_purpose_values
    CHECK (purpose IS NULL OR purpose IN ('analysis', 'reproduction', 'fix', 'detection', 'question'));
