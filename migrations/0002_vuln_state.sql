-- 0002_vuln_state: derived lifecycle state. Nothing here is stored by hand;
-- the event table stays the single source of truth.
-- Plain views (~17k vulns is cheap). If it ever gets slow, vuln_state can be
-- turned into a MATERIALIZED VIEW with the same definition (+ REFRESH after collects).

-- The single definition of "when did this event happen for our purposes":
-- trust the source's time; else our observation time but only if the
-- observation was live (not a bulk import); else NULL = unknown.
CREATE VIEW event_effective AS
SELECT e.id,
       e.cve_id,
       e.type,
       CASE e.type
           WHEN 'disclosed'          THEN 1
           WHEN 'patch_released'     THEN 2
           WHEN 'analysis_published' THEN 3
           WHEN 'poc_published'      THEN 4
           WHEN 'exploited_in_wild'  THEN 5
           WHEN 'kev_added'          THEN 6
       END AS stage_rank,
       COALESCE(e.occurred_at,
                CASE WHEN NOT e.is_backfill THEN e.observed_at END) AS effective_at,
       e.occurred_at,
       e.observed_at,
       e.is_backfill,
       e.source,
       e.detail
FROM event e;

CREATE VIEW vuln_state AS
WITH per_type AS (
    -- first event of each type per vuln (MIN ignores unknown times)
    SELECT cve_id, type, stage_rank,
           MIN(effective_at) AS first_at,
           count(*)          AS n
    FROM event_effective
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
    -- most recent arrival of a NEW event type; ties -> higher stage rank wins
    SELECT DISTINCT ON (cve_id)
           cve_id, first_at AS last_transition_at, type AS last_transition_type
    FROM per_type
    WHERE first_at IS NOT NULL
    ORDER BY cve_id, first_at DESC, stage_rank DESC
),
rej AS (
    SELECT DISTINCT ON (cve_id)
           cve_id, (detail->>'state') = 'REJECTED' AS is_rejected
    FROM event_effective
    WHERE type = 'disclosed' AND source = 'cvelist' AND detail ? 'state'
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
