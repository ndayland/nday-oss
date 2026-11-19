-- 0034_xdraft_form: which form a draft was posted in (docs/xposts.md
-- "Forms"). Staff try whether X holds back posts that carry an outside
-- link, so /admin/x/drafts offers three ways to post a draft:
--   link         the text and the link in the compose window (as before);
--   image        the text only, the share card (with the page's address
--                printed on it) attached by hand;
--   image_reply  as image, then a reply to the post with the link.
-- Set when a draft is marked posted (default 'link'); NULL for drafts
-- that are pending, discarded, or were posted before this column existed.
-- The CHECK keeps it NULL unless the draft is posted.

-- Fail fast instead of queueing (see 0012): ADD COLUMN takes ACCESS
-- EXCLUSIVE on x_draft. A nullable column without a default rewrites
-- nothing, so the lock is held only for a moment.
SET LOCAL lock_timeout = '5s';

ALTER TABLE x_draft
    ADD COLUMN form text
        CONSTRAINT x_draft_form CHECK (form IN ('link', 'image', 'image_reply')),
    ADD CONSTRAINT x_draft_form_posted CHECK (form IS NULL OR status = 'posted');
