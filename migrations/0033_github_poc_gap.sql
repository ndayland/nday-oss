-- 0033_github_poc_gap: a repository created shortly before its CVE was
-- disclosed counts as a PoC (docs/github.md "PoC events"). Replaces only
-- github_poc_want of 0032 (same arguments and columns, so CREATE OR
-- REPLACE, and nothing that uses it changes), then one backfill.
--
-- 0032 left out every repository created before the disclosure (the
-- review page's "Predates" flag). In production most of those were made a
-- few hours or days before the record was published: coordinated
-- disclosure, a researcher preparing the repository under the reserved id
-- (sfewer-r7/CVE-2026-123007: 4 h 06 min before). Only a few were months
-- older (a reused or renamed repository).
--
-- disclosure = the earlier of vuln.published_at and the first disclosed
-- event (as in 0032); gap = disclosure - repository creation:
--   gap <= 0         unchanged: the creation time, precision day;
--   0 < gap <= 30 d  counts, rule-trusted (name / description / topic) and
--                    admin-trusted alike; the event time is the disclosure
--                    (the later of published_at and the first disclosed
--                    event, so days_disclosed_to_poc is 0, never negative),
--                    precision day; live is judged on that time;
--   gap > 30 d       as in 0032: rule-trusted does not count, admin-trusted
--                    counts with an unknown time and is always history.
-- The review page's "Predates" flag (internal/ghrepo predatesSQL, Go)
-- does not share this SQL and stays a hint for the reviewer.
--
-- No view change: the next refresh (every collector run, `nday
-- refresh-state` at the deploy) picks the new rows up.

-- Fail fast instead of queueing (see 0012): the backfill locks the vuln
-- rows it changes. Each file runs in its own transaction, so a timeout
-- leaves nothing applied and a retry is safe.
SET LOCAL lock_timeout = '5s';

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
    -- old: created more than 30 days before the disclosure (a NULL on
    -- either side is not old); at: the event time, NULL when unknown
    CROSS JOIN LATERAL (SELECT COALESCE(r.repo_created_at < LEAST(v.published_at, f.first) - interval '30 days', false) AS old) o
    CROSS JOIN LATERAL (SELECT CASE WHEN NOT o.old THEN GREATEST(r.repo_created_at, v.published_at, f.first) END AS at) t0
    CROSS JOIN LATERAL (SELECT CASE WHEN r.repo_created_at IS NOT NULL THEN t0.at END AS at) t
    WHERE c.cve_id IN (SELECT unnest(ids)
                       UNION SELECT a.alias FROM vuln_alias a WHERE a.cve_id = ANY(ids) AND a.alias_type = 'ghsa')
      AND x.vid = ANY(ids)
      AND r.github_id IS NOT NULL AND r.state = 'ok' AND r.full_name IS NOT NULL AND r.status = 'trusted'
      AND (r.status_by = 'admin' OR (r.status_by = 'rule' AND c.basis IN ('name', 'description', 'topic') AND NOT o.old))
    ORDER BY x.vid, r.github_id
$$;

-- Backfill: what now counts is history (is_backfill), as in 0032; events
-- that got a new time are updated.
DO $$
DECLARE
    r record;
BEGIN
    SELECT * INTO r FROM github_poc_sync(ARRAY(
        SELECT DISTINCT COALESCE((SELECT a.cve_id FROM vuln_alias a WHERE a.alias_type = 'ghsa' AND a.alias = c.cve_id), c.cve_id)
        FROM github_repo_cve c), true);
    RAISE NOTICE 'github poc gap backfill: % added, % removed, % updated', r.added, r.removed, r.updated;
END
$$;
