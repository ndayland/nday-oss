-- 0039_osssec_no_transition: an oss-security post never counts as a
-- transition, so it never puts a vulnerability on the hot list (owner's
-- decision; docs/osssec.md).
--
-- osssec (since f0b8a2e) writes one analysis_published event per post and
-- id. Those events stay what they were everywhere else: in the event log,
-- in the stage (a post can still make the stage ANA), in has_analysis,
-- analysis_at and event_count. Only last_transition_at / _type / _event_id
-- skip them: the last transition is the newest first arrival of a type
-- among the other sources' events. So a vulnerability whose only recent
-- news is a post stays off the hot list, and one that got a patch
-- yesterday and a post today is listed with the patch. A vulnerability
-- with nothing but posts has no transition (NULL, as for one whose events
-- all have unknown times): off the hot list, in the catalogue's undated
-- tail.
--
-- The list of such sources is the function below, the one place in SQL;
-- internal/site.NoTransitionSources is the same list for the vulnerability
-- page (site/vuln.go assemble), checked by
-- internal/site/osssec_hot_db_test.go. Adding a mailing-list-like source
-- later: CREATE OR REPLACE the function, change the Go list, and refresh
-- (`nday refresh-state`); the view and the mat need no rebuild.
--
-- What changes:
--   1. counts_as_transition(source), new.
--   2. vuln_state (as in 0027): per_type also keeps first_tr_at, the
--      earliest time over the counting sources only, and last_tr orders by
--      it. Same columns, so CREATE OR REPLACE works with vuln_state_mat
--      depending on it.
--   3. vuln_state_mat (as in 0032): tr, which picks the event behind the
--      last transition, skips the same sources (else a post at exactly
--      the transition's time could be picked). Rebuilt as in 0032: built
--      under a new name, then swapped in. Same columns in the same order and
--      the same index names, so the running binary keeps working; the
--      rows are recomputed by the build itself, nothing to run afterwards.
--
-- Locks, in this order:
--   - the refresh's advisory lock (internal/state/refresh.go), held until
--     commit, so no refresh starts meanwhile: a refresh holds EXCLUSIVE on
--     vuln_state_mat and then reads vuln_state, the migration holds
--     vuln_state and then drops vuln_state_mat, which would deadlock. A
--     collector's refresh finds the lock taken and returns (its request
--     stays pending); once this commits the next refresh runs on the new
--     mat.
--     (LOCK TABLE does not work on a materialized view.) A refresh already
--     running when the migration starts makes it wait, at most 5 s.
--   - ACCESS EXCLUSIVE on the vuln_state view (CREATE OR REPLACE VIEW);
--     only the refresh reads it.
--   - the build reads event (ACCESS SHARE: collectors keep writing). What
--     they commit meanwhile shows with the next refresh (the next
--     collector run, or `nday refresh-state` right after the deploy).
--   - ACCESS EXCLUSIVE on vuln_state_mat for the DROP and renames at the
--     end: readers wait only for that moment, not for the build.
-- The build is the 0032 one plus a FILTER: on a local copy with 425k
-- vulns it took 5.3 s plus 0.9 s for the indexes, so expect about 7 s on
-- production, like 0032. Each file runs in its own transaction: a lock timeout leaves
-- nothing applied and a retry is safe.
SET LOCAL lock_timeout = '5s';

-- the same key as refreshLockClass | oid in internal/state/refresh.go
SELECT pg_advisory_xact_lock((x'6E647374'::bigint << 32) | 'vuln_state_mat'::regclass::oid::bigint);

-- Events of these sources never count as a transition. Today: osssec, the
-- oss-security mailing list. Add another mailing-list-like source here.
CREATE FUNCTION counts_as_transition(source text) RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT source <> ALL (ARRAY['osssec'])
$$;

CREATE OR REPLACE VIEW vuln_state AS
WITH per_type AS (
    -- first event of each STAGE type per vuln (MIN ignores unknown times);
    -- non-stage types (social_post) have stage_rank NULL and are skipped.
    -- first_tr_at: the same over the sources that count as a transition.
    SELECT cve_id, type, stage_rank,
           MIN(effective_at) AS first_at,
           MIN(effective_at) FILTER (WHERE counts_as_transition(source)) AS first_tr_at,
           count(*)          AS n
    FROM event_effective
    WHERE stage_rank IS NOT NULL
    GROUP BY cve_id, type, stage_rank
),
agg AS (
    SELECT cve_id,
           MAX(stage_rank)                                   AS stage_rank,
           SUM(n)::int                                       AS event_count,
           bool_or(type = 'patch_released')                  AS has_patch,
           bool_or(type = 'analysis_published')              AS has_analysis,
           bool_or(type = 'poc_published')                   AS has_poc,
           bool_or(type IN ('exploited_in_wild', 'kev_added')) AS exploited,
           bool_or(type = 'kev_added')                       AS in_kev,
           MIN(first_at) FILTER (WHERE type = 'disclosed')          AS disclosed_at,
           MIN(first_at) FILTER (WHERE type = 'patch_released')     AS patch_at,
           MIN(first_at) FILTER (WHERE type = 'analysis_published') AS analysis_at,
           MIN(first_at) FILTER (WHERE type = 'poc_published')      AS poc_at,
           -- earliest evidence of exploitation: in-the-wild report OR KEV listing
           MIN(first_at) FILTER (WHERE type IN ('exploited_in_wild', 'kev_added')) AS exploited_at,
           MIN(first_at) FILTER (WHERE type = 'kev_added')          AS kev_at
    FROM per_type
    GROUP BY cve_id
),
last_tr AS (
    -- most recent arrival of a NEW event type, counting sources only;
    -- ties -> higher stage rank wins
    SELECT DISTINCT ON (cve_id)
           cve_id, first_tr_at AS last_transition_at, type AS last_transition_type
    FROM per_type
    WHERE first_tr_at IS NOT NULL
    ORDER BY cve_id, first_tr_at DESC, stage_rank DESC
),
rej AS (
    -- the vuln's own record: the CVE record (cvelist) for a CVE id, the
    -- GitHub advisory (ghsa) for a GHSA id
    SELECT DISTINCT ON (cve_id)
           cve_id, (detail->>'state') = 'REJECTED' AS is_rejected
    FROM event_effective
    WHERE type = 'disclosed' AND detail ? 'state'
      AND (source = 'cvelist' OR (source = 'ghsa' AND cve_id LIKE 'GHSA-%'))
    ORDER BY cve_id, effective_at DESC NULLS LAST, observed_at DESC, id DESC
)
SELECT a.cve_id,
       t.type AS stage,
       a.stage_rank,
       a.has_patch, a.has_analysis, a.has_poc, a.exploited, a.in_kev,
       COALESCE(r.is_rejected, false) AS is_rejected,
       a.disclosed_at, a.patch_at, a.analysis_at, a.poc_at, a.exploited_at, a.kev_at,
       l.last_transition_at,
       l.last_transition_type,
       a.event_count,
       EXTRACT(EPOCH FROM (a.exploited_at - a.disclosed_at)) / 86400.0 AS days_disclosed_to_exploited,
       EXTRACT(EPOCH FROM (a.poc_at - a.disclosed_at)) / 86400.0       AS days_disclosed_to_poc
FROM agg a
JOIN (VALUES (1,'disclosed'),(2,'patch_released'),(3,'analysis_published'),
            (4,'poc_published'),(5,'exploited_in_wild'),(6,'kev_added')) AS t(stage_rank, type)
  ON t.stage_rank = a.stage_rank
LEFT JOIN last_tr l USING (cve_id)
LEFT JOIN rej r USING (cve_id);

CREATE MATERIALIZED VIEW vuln_state_mat_0039 AS
WITH s AS MATERIALIZED (
    SELECT * FROM vuln_state
),
x AS (
    SELECT cve_id,
           bool_or(type = 'disclosed')                                  AS has_disclosed,
           bool_or(type = 'exploited_in_wild')                          AS has_itw,
           MIN(effective_at) FILTER (WHERE type = 'exploited_in_wild')  AS itw_at,
           (count(DISTINCT source) FILTER (
               WHERE type = 'poc_published'
                 AND source IN ('exploitdb', 'metasploit', 'nuclei', 'github')))::int AS poc_sources
    FROM event_effective
    GROUP BY cve_id
),
tr AS (
    SELECT DISTINCT ON (e.cve_id) e.cve_id, e.id AS event_id
    FROM event_effective e
    JOIN s ON s.cve_id = e.cve_id
          AND e.type = s.last_transition_type
          AND e.effective_at = s.last_transition_at
    WHERE counts_as_transition(e.source)
    ORDER BY e.cve_id, (e.occurred_at IS NOT NULL) DESC, e.id
)
SELECT s.cve_id, s.stage, s.stage_rank,
       s.has_patch, s.has_analysis, s.has_poc, s.exploited, s.in_kev, s.is_rejected,
       s.disclosed_at, s.patch_at, s.analysis_at, s.poc_at, s.exploited_at, s.kev_at,
       s.last_transition_at, s.last_transition_type, s.event_count,
       s.days_disclosed_to_exploited, s.days_disclosed_to_poc,
       x.has_disclosed, x.has_itw, x.itw_at, x.poc_sources,
       tr.event_id AS last_transition_event_id
FROM s
JOIN x USING (cve_id)
LEFT JOIN tr USING (cve_id)
WITH DATA;

CREATE UNIQUE INDEX vuln_state_mat_0039_cve_idx ON vuln_state_mat_0039 (cve_id);
CREATE INDEX vuln_state_mat_0039_hot_idx ON vuln_state_mat_0039 (last_transition_at, stage_rank, cve_id);
CREATE INDEX vuln_state_mat_0039_stage_idx
    ON vuln_state_mat_0039 (stage_rank, last_transition_at, cve_id);
CREATE INDEX vuln_state_mat_0039_year_idx
    ON vuln_state_mat_0039 ((substr(cve_id, 5, 4)), last_transition_at, stage_rank, cve_id);
CREATE INDEX vuln_state_mat_0039_stage_year_idx
    ON vuln_state_mat_0039 (stage_rank, (substr(cve_id, 5, 4)), last_transition_at, cve_id);

DROP MATERIALIZED VIEW vuln_state_mat;
ALTER MATERIALIZED VIEW vuln_state_mat_0039 RENAME TO vuln_state_mat;
ALTER INDEX vuln_state_mat_0039_cve_idx RENAME TO vuln_state_mat_cve_idx;
ALTER INDEX vuln_state_mat_0039_hot_idx RENAME TO vuln_state_mat_hot_idx;
ALTER INDEX vuln_state_mat_0039_stage_idx RENAME TO vuln_state_mat_stage_idx;
ALTER INDEX vuln_state_mat_0039_year_idx RENAME TO vuln_state_mat_year_idx;
ALTER INDEX vuln_state_mat_0039_stage_year_idx RENAME TO vuln_state_mat_stage_year_idx;
