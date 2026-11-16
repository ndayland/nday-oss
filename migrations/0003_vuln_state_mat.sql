-- 0003_vuln_state_mat: a materialized copy of vuln_state that is cheap to read.
--
-- vuln_state (0002) stays the single definition of the derived state; this
-- materialized view is vuln_state plus a few columns the website needs, and is
-- refreshed (CONCURRENTLY, so readers are never blocked) after every
-- successful collector run and by `nday refresh-state`. See internal/state
-- (Refresh) for the coordination protocol built on vuln_state_refresh below.
--
-- Extra columns (all derived from event_effective, nothing stored by hand):
--   has_disclosed            any 'disclosed' event
--   has_itw, itw_at          'exploited_in_wild' events only (vuln_state's
--                            exploited/exploited_at also count kev_added)
--   poc_sources              number of distinct curated PoC sources
--                            (exploitdb, metasploit, nuclei) with a poc event
--   last_transition_event_id the event that defines last_transition_at:
--                            type = last_transition_type and effective_at =
--                            last_transition_at; ties prefer an event with a
--                            source-given time, then the lowest id.

CREATE MATERIALIZED VIEW vuln_state_mat AS
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
                 AND source IN ('exploitdb', 'metasploit', 'nuclei')))::int AS poc_sources
    FROM event_effective
    GROUP BY cve_id
),
tr AS (
    SELECT DISTINCT ON (e.cve_id) e.cve_id, e.id AS event_id
    FROM event_effective e
    JOIN s ON s.cve_id = e.cve_id
          AND e.type = s.last_transition_type
          AND e.effective_at = s.last_transition_at
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

-- Required by REFRESH ... CONCURRENTLY; also the detail lookup.
CREATE UNIQUE INDEX vuln_state_mat_cve_idx ON vuln_state_mat (cve_id);
-- Hot list: walked backwards = last_transition_at DESC, stage_rank DESC,
-- cve_id DESC (the site's keyset order); stops after LIMIT rows.
CREATE INDEX vuln_state_mat_hot_idx ON vuln_state_mat (last_transition_at, stage_rank, cve_id);

-- Refresh bookkeeping (exactly one row). `requested` is bumped by every
-- writer after its data commit; a refresher records in `refreshed_seq` the
-- `requested` value it read BEFORE its refresh started, so every request
-- <= refreshed_seq is guaranteed to be visible in the materialized view.
CREATE TABLE vuln_state_refresh (
    id            int PRIMARY KEY CONSTRAINT vuln_state_refresh_one_row CHECK (id = 1),
    requested     bigint NOT NULL DEFAULT 0,
    refreshed_seq bigint NOT NULL DEFAULT 0,
    refreshed_at  timestamptz,
    duration_ms   int,
    last_error    text,
    last_error_at timestamptz
);
INSERT INTO vuln_state_refresh (id, refreshed_at) VALUES (1, now());

-- Search: CVE id prefix lookups compare bytewise (the database collation
-- en_US.utf8 is not prefix-consistent for LIKE/range scans).
CREATE INDEX vuln_cve_id_c_idx ON vuln (cve_id COLLATE "C");

-- Search: case-insensitive substring match (ILIKE '%term%') on title,
-- title_zh, vendor, product. Without an index that is a sequential scan of
-- vuln + affected (~45 ms at 46k vulns, growing linearly). pg_trgm is a
-- trusted extension (PG 13+), so the database owner can create it; if the
-- migrating role cannot, the search still works (sequential scan) and a
-- NOTICE is raised instead of failing the migration. The extension goes
-- into public (never into a per-test schema that gets dropped), or stays
-- wherever it is already installed.
DO $$
DECLARE
    sch text;
BEGIN
    BEGIN
        CREATE EXTENSION IF NOT EXISTS pg_trgm SCHEMA public;
    EXCEPTION
        WHEN unique_violation OR duplicate_object THEN
            NULL; -- created concurrently by another session (parallel test schemas)
        WHEN insufficient_privilege OR feature_not_supported OR undefined_file THEN
            RAISE NOTICE 'pg_trgm unavailable (%), search will use sequential scans', SQLERRM;
    END;
    SELECT n.nspname INTO sch
    FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
    WHERE e.extname = 'pg_trgm';
    IF sch IS NOT NULL THEN
        EXECUTE format('CREATE INDEX vuln_title_trgm_idx ON vuln USING gin (title %I.gin_trgm_ops)', sch);
        EXECUTE format('CREATE INDEX vuln_title_zh_trgm_idx ON vuln USING gin (title_zh %I.gin_trgm_ops)', sch);
        EXECUTE format('CREATE INDEX affected_vendor_trgm_idx ON affected USING gin (vendor %I.gin_trgm_ops)', sch);
        EXECUTE format('CREATE INDEX affected_product_trgm_idx ON affected USING gin (product %I.gin_trgm_ops)', sch);
    END IF;
END
$$;
