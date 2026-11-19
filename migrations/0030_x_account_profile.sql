-- 0030_x_account_profile: the display name and the profile description
-- ("bio") of an allowlisted X account, as the X API user lookup returned
-- them (Go only; internal/xlookup, internal/admin xprofiles.go, docs/xposts.md).
--
-- Additive: three nullable columns without defaults (a catalog change, no
-- table rewrite).
--   name        the display name on X; NULL = not looked up yet or not found;
--   description the profile description; NULL as name ('' = an empty bio);
--   profile_at  when nday last looked the account up for them (every lookup
--               that adds or imports an account sets it, and the bounded
--               refresh of /admin/x picks rows where it is NULL first).
-- X allows 50 characters of name and 160 of description; the checks leave room.

ALTER TABLE x_accounts
    ADD COLUMN name text CHECK (char_length(name) <= 200),
    ADD COLUMN description text CHECK (char_length(description) <= 2000),
    ADD COLUMN profile_at timestamptz;
