-- 0021_catalogue_indexes: indexes on vuln_state_mat for the catalogue of
-- every vulnerability (internal/site/catalogue.go; GET /api/vulns, /v1/vulns).
--
-- Additive: indexes only, no view change, no rebuild. The catalogue orders
-- by last_transition_at DESC, stage_rank DESC, cve_id DESC (the hot list's
-- order, vuln_state_mat_hot_idx walked backwards) and filters by the
-- CURRENT stage (stage_rank = n) and/or the CVE id year (substr(cve_id, 5, 4)
-- = 'YYYY'; vuln_cve_id_format guarantees 'CVE-YYYY-'). Each index puts the
-- equality columns first and the order columns after them, so a filtered
-- page is a backward index walk that stops after LIMIT+1 rows instead of a
-- walk of the time index that discards non-matching rows (a rare stage
-- such as patch_released, 316 of ~426k rows, would otherwise read most of
-- the view on its later pages). stage_rank is left out of the order columns
-- where it is an equality column (the planner drops it from the ORDER BY).
--
-- The year is compared by equality only, so the database collation
-- (en_US.utf8, not prefix-consistent for LIKE/range scans; see 0003) does
-- not matter here; cve_id keeps the default collation like hot_idx so the
-- keyset comparison and the ORDER BY match the index.
--
-- vuln_state_mat is only ever refreshed with REFRESH MATERIALIZED VIEW
-- CONCURRENTLY (internal/state/refresh.go), which keeps its indexes; no
-- migration drops and re-creates the view. If one ever does, these
-- statements must be repeated after it.

CREATE INDEX vuln_state_mat_stage_idx
    ON vuln_state_mat (stage_rank, last_transition_at, cve_id);

CREATE INDEX vuln_state_mat_year_idx
    ON vuln_state_mat ((substr(cve_id, 5, 4)), last_transition_at, stage_rank, cve_id);

CREATE INDEX vuln_state_mat_stage_year_idx
    ON vuln_state_mat (stage_rank, (substr(cve_id, 5, 4)), last_transition_at, cve_id);
