-- 0010_follows: vendors and products a user follows (Go only; see
-- docs/follows.md). Additive: one new table, nothing existing changes.
--
-- A follow is one free-text term. It matches a CVE when an affected row of
-- that CVE has lower(vendor) = term_key OR lower(product) = term_key (the
-- affected table has no normalised vendor/product key, so the match is an
-- exact, case-insensitive comparison of the whole name). label keeps the
-- spelling the user picked; term_key is lower(label) computed by the
-- database itself (internal/auth/store_follow.go), so the comparison and
-- the key use the same lower().
--
-- At most 50 follows per user: enforced by the application inside the
-- transaction that replaces a user's list. The rows are part of the
-- account and go with it (ON DELETE CASCADE).

CREATE TABLE user_follows (
    user_id    uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    term_key   text NOT NULL,
    label      text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, term_key),
    CONSTRAINT user_follows_key_lower CHECK (term_key = lower(term_key)),
    CONSTRAINT user_follows_key_len CHECK (char_length(term_key) BETWEEN 1 AND 200),
    CONSTRAINT user_follows_label_len CHECK (char_length(label) BETWEEN 1 AND 200),
    -- no C0/C1 control characters (U+0000 cannot occur in text at all)
    CONSTRAINT user_follows_no_control CHECK (
        term_key !~ '[\u0001-\u001f\u007f-\u009f]' AND label !~ '[\u0001-\u001f\u007f-\u009f]')
);
