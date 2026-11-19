-- 0027_ghsa_vuln_classify: classification and rejection for vulnerabilities
-- keyed by a GHSA id (Go only; see docs/ghsa.md).
--
-- Since 0026 a GitHub advisory without a CVE is stored as a vuln keyed by
-- its GHSA id. Two derived layers still assumed a CVE id; both are widened
-- here, and nothing changes for CVE-keyed rows.
--
-- 1. classify_enqueue_raw(): a ghsa raw record used to queue only the CVE
--    its payload names (and the CVEs its rows fed before), so an advisory
--    without a CVE was never classified. It now also queues the advisory's
--    own GHSA id (raw_record.source_key). internal/classify derives such an
--    advisory under its GHSA id (DeriveGHSA), so vuln_cwe / vuln_cvss /
--    vuln_classify_input get rows for the GHSA-keyed vuln. The GHSA id is
--    queued for every ghsa record, with or without a CVE: when there is no
--    vuln row for it (the advisory has a CVE, or it was withdrawn before we
--    stored it) the classify run skips it like any CVE without a vuln row,
--    and the trigger does not have to guess whether the payload's cve_id is
--    usable (the derivation and normalize decide that). When the advisory
--    gains a CVE, its earlier rows under the GHSA id are found through
--    vuln_classify_input as before and moved with the vuln
--    (internal/pipeline mergeVuln).
--
-- 2. vuln_state.is_rejected: for a CVE it is the state on the CVE record's
--    disclosed event (source cvelist). A GHSA-keyed vuln has no CVE record;
--    the advisory is its record, and its disclosed event (source ghsa,
--    dedupe_key = the GHSA id) carries detail.state = 'PUBLISHED', or
--    'REJECTED' once the advisory is withdrawn. The rej CTE now reads that
--    event too, for GHSA-keyed rows only, so a withdrawn advisory shows as
--    rejected like a rejected CVE. A CVE-keyed row is unaffected: a ghsa
--    disclosed event that moved to a CVE during a merge is not read, and
--    the CVE record's own event removes it when it arrives. The view keeps
--    its columns, so CREATE OR REPLACE works with vuln_state_mat depending
--    on it; existing rows only change for GHSA-keyed vulns, of which there
--    are none before this release's re-normalize. vuln_state_mat picks it up
--    at its next refresh.
--
-- Additive in effect: no table changes, every existing row keeps its value.

-- Fail fast instead of queueing: replacing the view takes ACCESS EXCLUSIVE
-- on vuln_state; see 0012. Each file runs in its own transaction, so a
-- timeout leaves nothing applied and a retry is safe.
SET LOCAL lock_timeout = '5s';

CREATE OR REPLACE FUNCTION classify_enqueue_raw() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.source IN ('cvelist', 'nvd') THEN
        IF NEW.source_key ~ '^CVE-[0-9]{4}-[0-9]{4,}$' THEN
            INSERT INTO classify_queue (cve_id) VALUES (NEW.source_key);
        END IF;
    ELSIF NEW.source = 'ghsa' THEN
        -- the advisory's current CVE, its own GHSA id (the vuln's id while it
        -- has no CVE), and every id it fed before (its cve_id may have
        -- changed: the old id's ghsa rows must be removed)
        INSERT INTO classify_queue (cve_id)
        SELECT c FROM (
            SELECT NEW.payload->>'cve_id' AS c
            UNION
            SELECT NEW.source_key
            UNION
            SELECT cve_id FROM vuln_classify_input
            WHERE source = 'ghsa' AND source_key = NEW.source_key
        ) s
        WHERE c ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
           OR c ~ '^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$';
    END IF;
    RETURN NULL;
END
$$;

-- vuln_state as in 0008, except the rej CTE (see 2. above).
CREATE OR REPLACE VIEW vuln_state AS
WITH per_type AS (
    -- first event of each STAGE type per vuln (MIN ignores unknown times);
    -- non-stage types (social_post) have stage_rank NULL and are skipped
    SELECT cve_id, type, stage_rank,
           MIN(effective_at) AS first_at,
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
    -- most recent arrival of a NEW event type; ties -> higher stage rank wins
    SELECT DISTINCT ON (cve_id)
           cve_id, first_at AS last_transition_at, type AS last_transition_type
    FROM per_type
    WHERE first_at IS NOT NULL
    ORDER BY cve_id, first_at DESC, stage_rank DESC
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
