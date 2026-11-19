-- 0036_github_trusted_owner: GitHub accounts whose repositories need no
-- review (Go only; internal/ghrepo owner.go, internal/admin, docs/github.md
-- "Trusted accounts").
--
-- Additive, plus a wider CHECK and a new github_poc_want:
--
-- 1. github_repo.owner_id: GitHub's numeric id of the repository's owner
--    (owner.id of the API response), written by every fetch from now on;
--    NULL for rows not fetched since. A login can be renamed and then
--    registered by someone else; the id can't, so matching prefers it.
--
-- 2. github_repo.status_by gets 'owner': trusted because the owner is on
--    the list below (matched by owner_id only). It is set only on an
--    identity nobody decided about (status 'unverified', status_by NULL)
--    that is not a fork or a collection, and taken back when the account
--    is disabled (to 'rule' when the post rule holds for it, else to NULL).
--    An admin's decision is never touched. When the post rule fires
--    (internal/ghrepo stampLinks) it replaces owner trust.
--
-- 3. github_trusted_owner: the list. login as GitHub spells it (or as
--    typed while the id is pending), unique case-insensitively; owner_id
--    from GET /users/{login} or the quick-added repository, NULL while
--    pending (then the account trusts nothing); login follows renames. enabled: disabled rows stay for history,
--    like x_accounts. x_user_id: an optional link to an allow-listed X
--    account of the same researcher (descriptive only, admin pages only:
--    it never changes trust and never reaches a public page).
--
-- 4. github_poc_want: 'owner' counts exactly like 'rule' (name /
--    description / topic basis for that vulnerability, not "old").
--
-- A binary of 0035 running after this: it writes status_by 'rule' and
-- 'admin' only (still allowed), never owner_id (left as it was), and never
-- grants or takes back 'owner'. The PoC triggers already fire on any
-- status_by change and their early exit only looks at status, so 'owner'
-- needs no trigger change.

SET LOCAL lock_timeout = '5s';

ALTER TABLE github_repo ADD COLUMN owner_id bigint CHECK (owner_id IS NULL OR owner_id > 0);
CREATE INDEX github_repo_owner_id_idx ON github_repo (owner_id) WHERE owner_id IS NOT NULL;
CREATE INDEX github_repo_owner_login_idx ON github_repo (lower(owner_login)) WHERE owner_login IS NOT NULL;

ALTER TABLE github_repo DROP CONSTRAINT github_repo_status_by_check;
ALTER TABLE github_repo ADD CONSTRAINT github_repo_status_by_check
    CHECK (status_by IS NULL OR status_by IN ('rule', 'admin', 'owner'));
ALTER TABLE github_repo ADD CONSTRAINT github_repo_status_owner CHECK (status_by IS DISTINCT FROM 'owner' OR status = 'trusted');

CREATE TABLE github_trusted_owner (
    id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login      text NOT NULL CHECK (login ~ '^[A-Za-z0-9][A-Za-z0-9-]{0,38}$'),
    owner_id   bigint UNIQUE CHECK (owner_id IS NULL OR owner_id > 0),
    note       text NOT NULL DEFAULT '' CHECK (char_length(note) <= 500),
    enabled    boolean NOT NULL DEFAULT true,
    x_user_id  text REFERENCES x_accounts (user_id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX github_trusted_owner_login_idx ON github_trusted_owner (lower(login));
CREATE INDEX github_trusted_owner_x_idx ON github_trusted_owner (x_user_id) WHERE x_user_id IS NOT NULL;

CREATE OR REPLACE FUNCTION github_poc_want(ids text[])
RETURNS TABLE (vid text, key text, at timestamptz, url text, repo text, live boolean)
LANGUAGE sql STABLE AS $$
    SELECT DISTINCT ON (x.vid, r.github_id) x.vid, r.github_id::text, t.at,
           'https://github.com/' || r.full_name, r.full_name,
           t.at IS NOT NULL AND t.at >= now() - interval '30 days'
    FROM github_repo_cve c
    JOIN github_repo r ON r.id = c.repo_id
    CROSS JOIN LATERAL (SELECT COALESCE((SELECT a.cve_id FROM vuln_alias a
                                         WHERE a.alias_type = 'ghsa' AND a.alias = c.cve_id), c.cve_id) AS vid) x
    JOIN vuln v ON v.cve_id = x.vid
    CROSS JOIN LATERAL (SELECT (SELECT min(COALESCE(d.occurred_at, CASE WHEN NOT d.is_backfill THEN d.observed_at END))
                                FROM event d WHERE d.cve_id = v.cve_id AND d.type = 'disclosed') AS first) f
    CROSS JOIN LATERAL (SELECT COALESCE(r.repo_created_at < LEAST(v.published_at, f.first) - interval '30 days', false) AS old) o
    CROSS JOIN LATERAL (SELECT CASE WHEN NOT o.old THEN GREATEST(r.repo_created_at, v.published_at, f.first) END AS at) t0
    CROSS JOIN LATERAL (SELECT CASE WHEN r.repo_created_at IS NOT NULL THEN t0.at END AS at) t
    WHERE c.cve_id IN (SELECT unnest(ids)
                       UNION SELECT a.alias FROM vuln_alias a WHERE a.cve_id = ANY(ids) AND a.alias_type = 'ghsa')
      AND x.vid = ANY(ids)
      AND r.github_id IS NOT NULL AND r.state = 'ok' AND r.full_name IS NOT NULL AND r.status = 'trusted'
      AND (r.status_by = 'admin'
           OR (r.status_by IN ('rule', 'owner') AND c.basis IN ('name', 'description', 'topic') AND NOT o.old))
    ORDER BY x.vid, r.github_id
$$;

-- Backfill: nothing is 'owner' yet, so this changes nothing today; it keeps
-- the events and the function in step all the same (history, as in 0033).
DO $$
DECLARE
    r record;
BEGIN
    SELECT * INTO r FROM github_poc_sync(ARRAY(
        SELECT DISTINCT COALESCE((SELECT a.cve_id FROM vuln_alias a WHERE a.alias_type = 'ghsa' AND a.alias = c.cve_id), c.cve_id)
        FROM github_repo_cve c), true);
    RAISE NOTICE 'github trusted owner backfill: % added, % removed, % updated', r.added, r.removed, r.updated;
END
$$;
