-- 0032_github_poc: a trusted GitHub repository counts as a fourth PoC
-- source next to exploitdb, metasploit and nuclei (Go only;
-- docs/github.md "PoC events", internal/ghrepo, internal/site).
--
-- The signal is stored the way the other three store theirs: a
-- poc_published event with source 'github', so the stage, the chart, the
-- lists, the feed, the API and the X drafts pick it up with no special
-- case. One event per (vulnerability, repository): dedupe_key is the
-- repository's GitHub id, occurred_at its creation time on GitHub with
-- detail.precision "day" (only the UTC day is shown), url and detail.title
-- its current https://github.com/<full name> and full name. Nothing about
-- a post, an author or the review (who decided, how) goes in the event:
-- events are public. observed_at and created_at are cut to the UTC day, so
-- the event never tells when a post link was checked or a decision made
-- (only the day a link was first mentioned is public).
--
-- Which repositories count (github_poc_want below, the only definition):
-- an 'ok' row whose status is 'trusted' and
--   - status_by 'admin': for every vulnerability it is associated with,
--     whatever the basis (a researcher's post alone is enough), or
--   - status_by 'rule': only for a vulnerability its own name, description
--     or topics name (github_repo_cve basis name / description / topic); a
--     'post' basis alone does not count.
-- Predates (the review page's flag, internal/ghrepo predatesSQL, taken per
-- vulnerability): the repository was created before the vulnerability's
-- vuln.published_at or before its first disclosed event (a renamed or
-- reused repository). Then a rule-trusted repository does not count for
-- that vulnerability, and an admin-trusted one counts with an unknown time
-- (occurred_at NULL, no precision, never live), so days_disclosed_to_poc
-- never goes negative because of a github event.
-- Association ids resolve to a vulnerability as everywhere else (a GHSA
-- id that is a 'ghsa' alias of a vulnerability means that vulnerability;
-- ghrepo.VulnOfSQL), and only vulnerabilities with a vuln row get events.
--
-- Kept in step by github_poc_sync(ids, backfill), which makes the github
-- events of the given vulnerabilities exactly the wanted set: missing ones
-- are inserted, ones that stopped counting (rejected, reset, gone,
-- association removed, now predates) are DELETED, so the stage is
-- recomputed as if they had never counted. It is called by the triggers
-- below in the same transaction as every change it depends on, whichever
-- code path makes it:
--   github_repo      status, status_by, state, full_name, repo_created_at
--   github_repo_cve  every insert, update and delete
--   vuln_alias       ghsa aliases (resolution of GHSA ids)
--   vuln             new rows (an id associated before its record arrived)
-- The first three are deferred constraint triggers: they fire at commit,
-- after everything the transaction did, so a fetch that rewrites the
-- associations of a repository (delete, then insert the same rows) leaves
-- the events alone instead of deleting and re-adding them. The vuln
-- trigger is a plain statement trigger (inserts never churn). A change of
-- vuln.published_at or of the disclosed events (the predates test) fires
-- nothing here: `nday github-discover` (hourly) ends with the repair
-- (ghrepo.SyncPoC), which converges that.
--
-- Locks: github_poc_sync first compares without locking (github_poc_diff);
-- only when something has to change does it lock the vuln rows FOR NO KEY
-- UPDATE (in id order), which serialises two syncs of one vulnerability
-- and waits for a collector's upsert of that row (SELECT ... FOR UPDATE,
-- internal/pipeline) as the tag pass already does; KEY SHARE readers
-- (foreign keys, the draft pass) are not blocked. No vuln row is written.
--
-- Live or history: an inserted event is live (is_backfill false) only when
-- the caller is not the backfill AND the repository's creation time is
-- known, within the last 30 days and does not predate the vulnerability;
-- otherwise it is history (is_backfill true). Who calls does not matter
-- otherwise, so a repository that drops out and comes back (a 404 then ok
-- again, a stamp cleared and set again, an admin reset and trust) or a
-- vuln row created for an old id never turns old code into a live event,
-- and the draft pass (internal/xdraft: first live event of its type)
-- drafts only a repository created recently. Times are the creation time
-- either way, so a backfilled CVE never shows as a change made today.
--
-- Order (table locks before any row lock, so a collector cannot deadlock
-- with the migration): functions, the index on event, the triggers, one
-- backfill, then vuln_state_mat. vuln_state_mat (0003) counts the new
-- source in poc_sources, so it is rebuilt: built under a new name (only
-- ACCESS SHARE on its inputs), then swapped in, so its readers are blocked
-- only for the swap at the end. Same columns and indexes as 0003 + 0021;
-- only poc_sources changes. Run `nday github-poc` after the deploy for
-- anything committed elsewhere meanwhile.

-- Fail fast instead of queueing (see 0012): CREATE INDEX takes SHARE on
-- event, CREATE TRIGGER SHARE ROW EXCLUSIVE on vuln, vuln_alias,
-- github_repo and github_repo_cve, DROP ACCESS EXCLUSIVE on vuln_state_mat
-- (a running REFRESH holds EXCLUSIVE), and the backfill locks a few vuln
-- rows. Each file runs in its own transaction, so a timeout leaves nothing
-- applied and a retry is safe.
SET LOCAL lock_timeout = '5s';

-- The wanted github events of the vulnerabilities ids (vuln rows only).
-- live: may be a live event (see "Live or history" above).
CREATE FUNCTION github_poc_want(ids text[])
RETURNS TABLE (vid text, key text, at timestamptz, url text, repo text, live boolean)
LANGUAGE sql STABLE AS $$
    SELECT DISTINCT ON (x.vid, r.github_id) x.vid, r.github_id::text,
           CASE WHEN NOT p.predates THEN r.repo_created_at END,
           'https://github.com/' || r.full_name, r.full_name,
           r.repo_created_at IS NOT NULL AND NOT p.predates AND r.repo_created_at >= now() - interval '30 days'
    FROM github_repo_cve c
    JOIN github_repo r ON r.id = c.repo_id
    CROSS JOIN LATERAL (SELECT COALESCE((SELECT a.cve_id FROM vuln_alias a
                                         WHERE a.alias_type = 'ghsa' AND a.alias = c.cve_id), c.cve_id) AS vid) x
    JOIN vuln v ON v.cve_id = x.vid
    CROSS JOIN LATERAL (SELECT COALESCE(r.repo_created_at < v.published_at, false)
                               OR COALESCE(r.repo_created_at < (
                                   SELECT min(COALESCE(d.occurred_at, CASE WHEN NOT d.is_backfill THEN d.observed_at END))
                                   FROM event d WHERE d.cve_id = v.cve_id AND d.type = 'disclosed'), false) AS predates) p
    WHERE c.cve_id IN (SELECT unnest(ids)
                       UNION SELECT a.alias FROM vuln_alias a WHERE a.cve_id = ANY(ids) AND a.alias_type = 'ghsa')
      AND x.vid = ANY(ids)
      AND r.github_id IS NOT NULL AND r.state = 'ok' AND r.full_name IS NOT NULL AND r.status = 'trusted'
      AND (r.status_by = 'admin' OR (r.status_by = 'rule' AND c.basis IN ('name', 'description', 'topic') AND NOT p.predates))
    ORDER BY x.vid, r.github_id
$$;

-- What github_poc_sync would change for ids, read-only (the dry run and
-- the sync's own first look).
CREATE FUNCTION github_poc_diff(ids text[], OUT added int, OUT removed int, OUT updated int)
LANGUAGE sql STABLE AS $$
    WITH w AS (SELECT * FROM github_poc_want(ids)),
    e AS (SELECT cve_id, dedupe_key, occurred_at, url FROM event
          WHERE cve_id = ANY(ids) AND type = 'poc_published' AND source = 'github')
    SELECT (SELECT count(*) FROM w WHERE NOT EXISTS (SELECT 1 FROM e WHERE e.cve_id = w.vid AND e.dedupe_key = w.key))::int,
           (SELECT count(*) FROM e WHERE NOT EXISTS (SELECT 1 FROM w WHERE w.vid = e.cve_id AND w.key = e.dedupe_key))::int,
           (SELECT count(*) FROM w JOIN e ON e.cve_id = w.vid AND e.dedupe_key = w.key
            WHERE (e.occurred_at, e.url) IS DISTINCT FROM (w.at, w.url))::int
$$;

-- Makes the github events of ids the wanted set; returns what it changed.
CREATE FUNCTION github_poc_sync(ids text[], backfill boolean,
                                OUT added int, OUT removed int, OUT updated int)
LANGUAGE plpgsql AS $$
DECLARE
    todo text[];
    d record;
    today timestamptz := date_trunc('day', now() AT TIME ZONE 'UTC') AT TIME ZONE 'UTC';
BEGIN
    added := 0; removed := 0; updated := 0;
    SELECT array_agg(DISTINCT i ORDER BY i) INTO todo FROM unnest(ids) i WHERE i IS NOT NULL;
    IF todo IS NULL THEN
        RETURN;
    END IF;
    -- compare first, without locks: most calls change nothing
    SELECT * INTO d FROM github_poc_diff(todo);
    IF d.added = 0 AND d.removed = 0 AND d.updated = 0 THEN
        RETURN;
    END IF;
    PERFORM 1 FROM vuln WHERE cve_id = ANY(todo) ORDER BY cve_id FOR NO KEY UPDATE;
    DELETE FROM event e
    WHERE e.cve_id = ANY(todo) AND e.type = 'poc_published' AND e.source = 'github'
      AND NOT EXISTS (SELECT 1 FROM github_poc_want(todo) w WHERE w.vid = e.cve_id AND w.key = e.dedupe_key);
    GET DIAGNOSTICS removed = ROW_COUNT;
    -- is_backfill of an existing event never changes (as in the pipeline)
    WITH up AS (
        INSERT INTO event AS e (cve_id, type, occurred_at, observed_at, source, url, detail, is_backfill, dedupe_key, created_at)
        SELECT w.vid, 'poc_published', w.at, today, 'github', w.url,
               jsonb_strip_nulls(jsonb_build_object('precision', CASE WHEN w.at IS NOT NULL THEN 'day' END,
                                                    'title', w.repo, 'url', w.url)),
               backfill OR NOT w.live, w.key, today
        FROM github_poc_want(todo) w
        ON CONFLICT ON CONSTRAINT event_uniq DO UPDATE
            SET occurred_at = EXCLUDED.occurred_at, url = EXCLUDED.url, detail = EXCLUDED.detail
            WHERE (e.occurred_at, e.url, e.detail) IS DISTINCT FROM (EXCLUDED.occurred_at, EXCLUDED.url, EXCLUDED.detail)
        RETURNING (xmax = 0) AS ins
    )
    SELECT count(*) FILTER (WHERE ins), count(*) FILTER (WHERE NOT ins) INTO added, updated FROM up;
END
$$;

-- A repository changed: its associated vulnerabilities. (An association
-- that went away is handled by github_poc_assoc with the old row.)
-- Discovery moves thousands of repositories nobody trusts: out at once
-- unless it is or was trusted or has a github event.
CREATE FUNCTION github_poc_repo() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.status <> 'trusted' AND (TG_OP = 'INSERT' OR OLD.status <> 'trusted')
       AND NOT EXISTS (SELECT 1 FROM event e WHERE e.source = 'github' AND e.dedupe_key = NEW.github_id::text) THEN
        RETURN NULL;
    END IF;
    PERFORM github_poc_sync(ARRAY(
        SELECT COALESCE((SELECT a.cve_id FROM vuln_alias a WHERE a.alias_type = 'ghsa' AND a.alias = c.cve_id), c.cve_id)
        FROM github_repo_cve c WHERE c.repo_id = NEW.id), false);
    RETURN NULL;
END
$$;

CREATE FUNCTION github_poc_assoc() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    ids text[] := '{}';
    repos bigint[] := '{}';
BEGIN
    IF TG_OP <> 'INSERT' THEN ids := ids || OLD.cve_id; repos := repos || OLD.repo_id; END IF;
    IF TG_OP <> 'DELETE' THEN ids := ids || NEW.cve_id; repos := repos || NEW.repo_id; END IF;
    ids := ARRAY(SELECT COALESCE((SELECT a.cve_id FROM vuln_alias a WHERE a.alias_type = 'ghsa' AND a.alias = i), i)
                 FROM unnest(ids) i
                 UNION SELECT unnest(ids));
    -- search stores many associations of repositories nobody trusts:
    -- nothing to do unless one is trusted or a github event is there
    IF NOT EXISTS (SELECT 1 FROM github_repo r WHERE r.id = ANY(repos) AND r.status = 'trusted')
       AND NOT EXISTS (SELECT 1 FROM event e WHERE e.cve_id = ANY(ids) AND e.type = 'poc_published' AND e.source = 'github') THEN
        RETURN NULL;
    END IF;
    PERFORM github_poc_sync(ids, false);
    RETURN NULL;
END
$$;

CREATE FUNCTION github_poc_alias() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    ids text[] := '{}';
    names text[] := '{}';
BEGIN
    IF TG_OP <> 'INSERT' THEN ids := ids || OLD.cve_id; names := names || OLD.alias; END IF;
    IF TG_OP <> 'DELETE' THEN ids := ids || NEW.cve_id; names := names || NEW.alias; END IF;
    -- most ghsa aliases name no repository: one index probe and out
    IF NOT EXISTS (SELECT 1 FROM github_repo_cve c WHERE c.cve_id = ANY(names)) THEN
        RETURN NULL;
    END IF;
    -- the alias itself too: without the alias it may be a GHSA-keyed vuln
    PERFORM github_poc_sync(ids || names, false);
    RETURN NULL;
END
$$;

CREATE FUNCTION github_poc_vuln_ins() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    PERFORM github_poc_sync(ARRAY(
        SELECT n.cve_id FROM new_rows n WHERE EXISTS (SELECT 1 FROM github_repo_cve c WHERE c.cve_id = n.cve_id)), false);
    RETURN NULL;
END
$$;

-- github events by repository (github_poc_repo) and their vulnerabilities
-- (the repair's stray events).
CREATE INDEX event_github_idx ON event (dedupe_key, cve_id) WHERE source = 'github';

CREATE CONSTRAINT TRIGGER github_poc_repo_upd AFTER UPDATE ON github_repo
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    WHEN ((OLD.status, OLD.status_by, OLD.state, OLD.full_name, OLD.repo_created_at)
          IS DISTINCT FROM (NEW.status, NEW.status_by, NEW.state, NEW.full_name, NEW.repo_created_at))
    EXECUTE FUNCTION github_poc_repo();
CREATE CONSTRAINT TRIGGER github_poc_repo_ins AFTER INSERT ON github_repo
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.status = 'trusted')
    EXECUTE FUNCTION github_poc_repo();
CREATE CONSTRAINT TRIGGER github_poc_assoc AFTER INSERT OR UPDATE OR DELETE ON github_repo_cve
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW
    EXECUTE FUNCTION github_poc_assoc();
CREATE CONSTRAINT TRIGGER github_poc_alias_ins AFTER INSERT ON vuln_alias
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (NEW.alias_type = 'ghsa')
    EXECUTE FUNCTION github_poc_alias();
CREATE CONSTRAINT TRIGGER github_poc_alias_upd AFTER UPDATE ON vuln_alias
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (OLD.alias_type = 'ghsa' OR NEW.alias_type = 'ghsa')
    EXECUTE FUNCTION github_poc_alias();
CREATE CONSTRAINT TRIGGER github_poc_alias_del AFTER DELETE ON vuln_alias
    DEFERRABLE INITIALLY DEFERRED FOR EACH ROW WHEN (OLD.alias_type = 'ghsa')
    EXECUTE FUNCTION github_poc_alias();
CREATE TRIGGER github_poc_vuln_ins AFTER INSERT ON vuln
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION github_poc_vuln_ins();

-- Backfill: repositories that qualify already are history (is_backfill).
DO $$
DECLARE
    r record;
BEGIN
    SELECT * INTO r FROM github_poc_sync(ARRAY(
        SELECT DISTINCT COALESCE((SELECT a.cve_id FROM vuln_alias a WHERE a.alias_type = 'ghsa' AND a.alias = c.cve_id), c.cve_id)
        FROM github_repo_cve c), true);
    RAISE NOTICE 'github poc backfill: % added, % removed, % updated', r.added, r.removed, r.updated;
END
$$;

CREATE MATERIALIZED VIEW vuln_state_mat_0032 AS
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

CREATE UNIQUE INDEX vuln_state_mat_0032_cve_idx ON vuln_state_mat_0032 (cve_id);
CREATE INDEX vuln_state_mat_0032_hot_idx ON vuln_state_mat_0032 (last_transition_at, stage_rank, cve_id);
CREATE INDEX vuln_state_mat_0032_stage_idx
    ON vuln_state_mat_0032 (stage_rank, last_transition_at, cve_id);
CREATE INDEX vuln_state_mat_0032_year_idx
    ON vuln_state_mat_0032 ((substr(cve_id, 5, 4)), last_transition_at, stage_rank, cve_id);
CREATE INDEX vuln_state_mat_0032_stage_year_idx
    ON vuln_state_mat_0032 (stage_rank, (substr(cve_id, 5, 4)), last_transition_at, cve_id);

DROP MATERIALIZED VIEW vuln_state_mat;
ALTER MATERIALIZED VIEW vuln_state_mat_0032 RENAME TO vuln_state_mat;
ALTER INDEX vuln_state_mat_0032_cve_idx RENAME TO vuln_state_mat_cve_idx;
ALTER INDEX vuln_state_mat_0032_hot_idx RENAME TO vuln_state_mat_hot_idx;
ALTER INDEX vuln_state_mat_0032_stage_idx RENAME TO vuln_state_mat_stage_idx;
ALTER INDEX vuln_state_mat_0032_year_idx RENAME TO vuln_state_mat_year_idx;
ALTER INDEX vuln_state_mat_0032_stage_year_idx RENAME TO vuln_state_mat_stage_year_idx;
