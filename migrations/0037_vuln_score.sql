-- 0037_vuln_score: the CVSS base score each vulnerability page shows, one
-- row per scored vulnerability, so lists can be filtered by it
-- (internal/site/cvss.go; ?cvss_min=&cvss_max= on /vuln, /api/vulns,
-- /api/search).
--
-- The rule is the page's (internal/site/vuln.go assemble and ghsaScore),
-- over the same events in the page's event order (effective time as in
-- event_effective, ascending, unknown last, then id). It reads the event
-- table itself, not the event_effective view, so that no later
-- DROP VIEW ... CASCADE of a view takes this one with it:
--
--   1. the last 'disclosed' event of source 'cvelist' whose detail has a
--      "cvss" object: its detail.cvss.base_score when that is a JSON
--      number. Such an event decides even without a usable score (then the
--      vulnerability has no score, as on the page, which then shows none);
--   2. otherwise the first 'patch_released' event whose detail.cvss gives a
--      score: cvss_v4, else cvss_v3, else the legacy {score, vector_string},
--      each only with a non-zero numeric score and a non-blank
--      vector_string.
--
-- A vulnerability without a score has no row. Scores outside 0..10 (none
-- today) are left out rather than breaking the refresh on numeric(3,1).
-- Scores are rounded to one decimal, as the page prints them.
--
-- Additive: a new materialized view and its indexes; nothing existing
-- changes. Creating it reads event once (ACCESS SHARE: writers are not
-- blocked); the indexes lock only the new view. It is refreshed with
-- REFRESH MATERIALIZED VIEW CONCURRENTLY right after vuln_state_mat, in the
-- same transaction (internal/state/refresh.go), so both lists' rows and
-- their scores are of the same moment. The unique index is what
-- CONCURRENTLY needs; (score, cve_id) serves a narrow score range.

CREATE MATERIALIZED VIEW vuln_score_mat AS
WITH cna AS (
    SELECT DISTINCT ON (e.cve_id) e.cve_id,
           CASE WHEN jsonb_typeof(e.detail->'cvss'->'base_score') = 'number'
                THEN (e.detail->'cvss'->>'base_score')::numeric END AS score
    FROM event e
    WHERE e.type = 'disclosed' AND e.source = 'cvelist'
      AND jsonb_typeof(e.detail->'cvss') = 'object'
    ORDER BY e.cve_id,
             COALESCE(e.occurred_at, CASE WHEN NOT e.is_backfill THEN e.observed_at END) DESC NULLS FIRST,
             e.id DESC
),
gh AS (
    SELECT DISTINCT ON (e.cve_id) e.cve_id, x.score
    FROM event e
    CROSS JOIN LATERAL (
        SELECT (c.o->>'score')::numeric AS score
        FROM (VALUES (1, e.detail->'cvss'->'cvss_v4'),
                     (2, e.detail->'cvss'->'cvss_v3'),
                     (3, e.detail->'cvss')) AS c(k, o)
        WHERE jsonb_typeof(c.o->'score') = 'number'
          AND (c.o->>'score')::numeric <> 0
          AND jsonb_typeof(c.o->'vector_string') = 'string'
          AND btrim(c.o->>'vector_string', E' \t\n\r\f\v') <> ''
        ORDER BY c.k
        LIMIT 1) x
    WHERE e.type = 'patch_released'
      AND e.source <> 'xposts' -- not public (site.NonPublicSources); none today
      AND jsonb_typeof(e.detail->'cvss') = 'object'
    ORDER BY e.cve_id,
             COALESCE(e.occurred_at, CASE WHEN NOT e.is_backfill THEN e.observed_at END) NULLS LAST,
             e.id
)
SELECT cve_id, round(score, 1)::numeric(3,1) AS score
FROM (SELECT cve_id, score FROM cna
      UNION ALL
      SELECT gh.cve_id, gh.score FROM gh
      WHERE NOT EXISTS (SELECT 1 FROM cna WHERE cna.cve_id = gh.cve_id)) s
WHERE round(score, 1) BETWEEN 0 AND 10;

CREATE UNIQUE INDEX vuln_score_mat_cve_idx ON vuln_score_mat (cve_id);

CREATE INDEX vuln_score_mat_score_idx ON vuln_score_mat (score, cve_id);
