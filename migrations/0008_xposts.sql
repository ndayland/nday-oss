-- 0008_xposts: posts on X as "discussion" events (Go only; see docs/xposts.md).
--
-- Three changes, all additive for existing data:
--
-- 1. A new event type 'social_post' (source 'xposts'): one row per (post,
--    CVE id mentioned in the post). It is NOT a lifecycle stage: a post that
--    says "PoC out" or "exploited" proves nothing, so vuln_state below
--    ignores it (no stage, no transition, not counted in event_count).
--
-- 2. vuln_state is redefined with the same columns, only restricting
--    per_type to the six stage types (stage_rank IS NOT NULL). Before this
--    migration every event type had a rank, so the result for existing data
--    is identical. vuln_state_mat reads vuln_state and needs no change; it is
--    refreshed after the next collector run (or `nday refresh-state`).
--
-- 3. Configuration of the xposts collector that the admin backend will edit:
--    x_accounts (the allowlist, keyed by the numeric X user id because
--    handles change) and x_settings (one typed row; NULL = built-in
--    default). The bearer token is NOT stored here (env NDAY_X_BEARER_TOKEN).
--    The CHECKs are the same hard bounds the Go code clamps to on read
--    (internal/xconfig), so a bad value can never make a run spend without
--    limit.

ALTER TABLE event DROP CONSTRAINT event_type_check;
ALTER TABLE event ADD CONSTRAINT event_type_check CHECK (type IN (
    'disclosed', 'patch_released', 'analysis_published',
    'poc_published', 'exploited_in_wild', 'kev_added',
    'social_post'));

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

-- The allowlist. Only enabled rows are searched. Rows are never deleted by
-- the application (disable instead), so the history of who was followed
-- stays readable next to the events.
CREATE TABLE x_accounts (
    -- numeric X user id as decimal text (64-bit, may exceed JS integers)
    user_id    text PRIMARY KEY CHECK (user_id ~ '^[1-9][0-9]{0,18}$'),
    -- handle without '@' as last known; used in the search query
    handle     text NOT NULL CHECK (handle ~ '^[A-Za-z0-9_]{1,15}$'),
    note       text NOT NULL DEFAULT '' CHECK (char_length(note) <= 500),
    enabled    boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

-- Runtime knobs of the xposts collector: exactly one row; a NULL column
-- means "built-in default" (internal/xconfig.Defaults).
CREATE TABLE x_settings (
    id               int PRIMARY KEY DEFAULT 1 CONSTRAINT x_settings_one_row CHECK (id = 1),
    enabled          boolean,
    max_posts        int CHECK (max_posts BETWEEN 10 AND 5000),
    max_requests     int CHECK (max_requests BETWEEN 1 AND 100),
    bootstrap_days   int CHECK (bootstrap_days BETWEEN 1 AND 7),
    max_query_length int CHECK (max_query_length BETWEEN 64 AND 4096),
    updated_at       timestamptz NOT NULL DEFAULT now()
);
