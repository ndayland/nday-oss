-- 0031_vuln_title: titles for vulnerabilities whose record has none (Go
-- only; see docs/titles.md, internal/titles and internal/tags/titles.go).
--
-- 57.7% of the vulnerabilities carry no title in their record (every
-- Oracle CVE, for one). nday composes one from structured data (a product,
-- a weakness tag, a component named in the description) by a fixed rule,
-- and staff may set a better one by hand. vuln.title is never written here:
-- it stays what the sources delivered. The effective title a page shows is
-- the staff title, else the record's title, else the composed one.
--
-- A 1:1 side table instead of columns on vuln: the backfill writes one row
-- per vulnerability (428k), and an UPDATE of vuln would rewrite each wide
-- vuln row (description and all), bloat it and take row locks that the
-- collectors' upserts (SELECT ... FOR UPDATE, internal/pipeline) wait for.
-- Writes here take only a KEY SHARE lock on the vuln row (the foreign key):
-- a collector's upsert of that row waits for the batch to commit, as it
-- already does for the tag pass, and nothing else is blocked. The pipeline's merge statements list
-- their vuln columns explicitly; the GHSA merge moves the staff title
-- (internal/pipeline/merge.go).
--
-- Composed part (written by the tag pass and `nday titles`; rebuilt from
-- the inputs at any time):
--   rule_version  internal/titles.RuleVersion the row was composed with;
--                 NULL = never considered (a row created by a staff edit)
--   form          full | weakness | component | excerpt; NULL = nothing
--                 composed (the record has a title, or no usable data)
--   product, weakness (a type tag slug), component, excerpt: the parts,
--                 plain text, cleaned and length-capped by the application;
--                 pages render them in the visitor's language
--   composed_en   the English rendering (API, feed, card, X drafts, search)
-- Staff part (/admin/titles; one audit row per change):
--   staff_title   1-160 characters, one line, NFC, no control or bidi
--                 characters (validated by the application)
--   staff_by, staff_at  who set it and when
--   staff_version optimistic concurrency of the staff edits (bumped by
--                 every set and clear)

-- Fail fast instead of queueing behind a long collector transaction (the
-- REFERENCES take SHARE ROW EXCLUSIVE on vuln and users, the triggers on
-- vuln take SHARE ROW EXCLUSIVE, the ALTERs ACCESS EXCLUSIVE on
-- admin_audit); see 0012. Each file runs in its own transaction, so a
-- timeout leaves nothing applied and a retry is safe.
SET LOCAL lock_timeout = '5s';

CREATE TABLE vuln_title (
    cve_id        text PRIMARY KEY REFERENCES vuln (cve_id) ON DELETE CASCADE,
    rule_version  int,
    form          text CONSTRAINT vuln_title_form CHECK (form IN ('full', 'weakness', 'component', 'excerpt')),
    product       text CONSTRAINT vuln_title_product CHECK (char_length(product) BETWEEN 1 AND 100),
    weakness      text CONSTRAINT vuln_title_weakness CHECK (weakness ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    component     text CONSTRAINT vuln_title_component CHECK (char_length(component) BETWEEN 1 AND 60),
    excerpt       text CONSTRAINT vuln_title_excerpt CHECK (char_length(excerpt) BETWEEN 1 AND 100),
    composed_en   text CONSTRAINT vuln_title_composed_en CHECK (char_length(composed_en) BETWEEN 1 AND 300),
    composed_at   timestamptz,
    staff_title   text CONSTRAINT vuln_title_staff CHECK (char_length(staff_title) BETWEEN 1 AND 160),
    staff_by      uuid REFERENCES users (id) ON DELETE SET NULL,
    staff_at      timestamptz,
    staff_version int NOT NULL DEFAULT 0,
    CONSTRAINT vuln_title_composed CHECK ((form IS NULL) = (composed_en IS NULL)),
    CONSTRAINT vuln_title_staff_at CHECK (staff_title IS NULL OR staff_at IS NOT NULL)
);
-- "rows lacking the current rule version" (the backfill) walks the
-- primary key; no further index is needed for it.

-- Search: a search by words of a composed or staff title finds it (ILIKE,
-- like vuln.title; internal/site/search.go). Trigram indexes as in 0003
-- when pg_trgm is installed. Size: measured locally at 19 MB for 145k
-- synthetic composed titles (so about 35 MB for production's ~250k; more
-- varied real text may need more), next to vuln_title_trgm_idx on
-- vuln.title; the staff index holds a few hundred rows (docs/titles.md).
DO $$
DECLARE
    sch text;
BEGIN
    SELECT n.nspname INTO sch
    FROM pg_extension e JOIN pg_namespace n ON n.oid = e.extnamespace
    WHERE e.extname = 'pg_trgm';
    IF sch IS NOT NULL THEN
        EXECUTE format('CREATE INDEX vuln_title_composed_trgm_idx ON vuln_title USING gin (composed_en %I.gin_trgm_ops)', sch);
        EXECUTE format('CREATE INDEX vuln_title_staff_trgm_idx ON vuln_title USING gin (staff_title %I.gin_trgm_ops)', sch);
    ELSE
        RAISE NOTICE 'pg_trgm unavailable, title search will use sequential scans';
    END IF;
END
$$;

-- Change detection: the composed parts are recomputed by the tag pass
-- (internal/tags processBatch, after the CVE's tags), so every input of the
-- rule queues the CVE in tag_queue in the same transaction as the write.
-- Already watched: affected (0013), the tag inputs (0011) and
-- vuln_tag_suppress (0011). Added here: the vuln row itself (a new
-- vulnerability; a changed title or description) and staff tag rows (the
-- tag pass writes only rule rows, so those are not watched, or every pass
-- would queue its own CVEs again).
CREATE FUNCTION title_enqueue_vuln_ins() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tag_queue (cve_id) SELECT cve_id FROM new_rows;
    RETURN NULL;
END
$$;

CREATE FUNCTION title_enqueue_vuln_upd() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tag_queue (cve_id)
    SELECT n.cve_id FROM new_rows n JOIN old_rows o USING (cve_id)
    WHERE n.title IS DISTINCT FROM o.title OR n.description IS DISTINCT FROM o.description;
    RETURN NULL;
END
$$;

CREATE FUNCTION title_enqueue_staff_new() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tag_queue (cve_id) SELECT DISTINCT cve_id FROM new_rows WHERE origin = 'staff';
    RETURN NULL;
END
$$;

CREATE FUNCTION title_enqueue_staff_old() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tag_queue (cve_id) SELECT DISTINCT cve_id FROM old_rows WHERE origin = 'staff';
    RETURN NULL;
END
$$;

CREATE FUNCTION title_enqueue_staff_both() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tag_queue (cve_id)
    SELECT cve_id FROM old_rows WHERE origin = 'staff'
    UNION
    SELECT cve_id FROM new_rows WHERE origin = 'staff';
    RETURN NULL;
END
$$;

CREATE TRIGGER vuln_title_ins AFTER INSERT ON vuln
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION title_enqueue_vuln_ins();
CREATE TRIGGER vuln_title_upd AFTER UPDATE ON vuln
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION title_enqueue_vuln_upd();

CREATE TRIGGER vuln_tag_staff_ins AFTER INSERT ON vuln_tag
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION title_enqueue_staff_new();
CREATE TRIGGER vuln_tag_staff_del AFTER DELETE ON vuln_tag
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION title_enqueue_staff_old();
CREATE TRIGGER vuln_tag_staff_upd AFTER UPDATE ON vuln_tag
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION title_enqueue_staff_both();

-- Staff title changes are audited with target type 'vuln' (target id = the
-- vulnerability id; actions vuln.title_set and vuln.title_clear).
ALTER TABLE admin_audit DROP CONSTRAINT admin_audit_target_type_check;
ALTER TABLE admin_audit ADD CONSTRAINT admin_audit_target_type_check
    CHECK (target_type IN ('comment', 'report', 'user', 'x_settings', 'x_account', 'x_draft', 'setting', 'correction', 'vuln'));
