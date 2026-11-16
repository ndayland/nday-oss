-- 0011_tags: CVE tags (Go only; see docs/tags.md and internal/tags).
--
-- A tag is nday's own derivation from data already in the database: the
-- classification layer (vuln_cwe, vuln_cvss, vuln_classify_input; migration
-- 0009), public lifecycle events (KEV, Exploit-DB, Metasploit, nuclei) and
-- GitHub advisories. The vocabulary is fixed in Go (internal/tags/vocab.go);
-- the database only stores assignments. Additive: no existing table, view or
-- row changes, and nothing here is read by vuln_state / vuln_state_mat.
--
-- origin = 'rule'  written by `nday tags` and the pass after every collector
--                  run; rebuilt from the inputs at any time (the rows can be
--                  dropped and recomputed);
-- origin = 'staff' reserved for the later admin phase (manual tags); nothing
--                  writes it yet.

CREATE TABLE vuln_tag (
    cve_id       text NOT NULL REFERENCES vuln (cve_id) ON DELETE CASCADE,
    -- a slug of the vocabulary (lower-case ASCII words joined by hyphens);
    -- validated by the Go code, the CHECK only keeps the shape
    tag          text NOT NULL CONSTRAINT vuln_tag_slug CHECK (tag ~ '^[a-z0-9]+(-[a-z0-9]+)*$'),
    origin       text NOT NULL CONSTRAINT vuln_tag_origin CHECK (origin IN ('rule', 'staff')),
    -- what the assignment rests on (rule: CWE ids / CVSS vector / events /
    -- advisories with their provenance; docs/tags.md §4)
    basis        jsonb NOT NULL DEFAULT '{}'::jsonb,
    -- internal/tags.RuleVersion that produced a rule row; NULL for staff rows
    rule_version int CONSTRAINT vuln_tag_rule_version CHECK (origin <> 'rule' OR rule_version IS NOT NULL),
    created_at   timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, tag, origin)
);
-- "CVEs with tag X": the list filters (EXISTS probes from the hot list walk
-- the primary key; tag-driven plans and the counts walk this index). origin
-- is included so that vuln_tag_visible's "staff or not suppressed" test is
-- answered by an index-only scan.
CREATE INDEX vuln_tag_tag_idx ON vuln_tag (tag, cve_id, origin);

-- Suppressed rule tags (written by the later admin phase; nothing writes it
-- yet). A suppressed (cve_id, tag) is not shown, not filterable and not
-- re-added by recomputation; staff rows are not affected.
CREATE TABLE vuln_tag_suppress (
    cve_id     text NOT NULL REFERENCES vuln (cve_id) ON DELETE CASCADE,
    tag        text NOT NULL,
    reason     text NOT NULL CONSTRAINT vuln_tag_suppress_reason CHECK (char_length(reason) BETWEEN 1 AND 500),
    created_at timestamptz NOT NULL DEFAULT now(),
    created_by uuid REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (cve_id, tag)
);

-- The single definition of "a tag the public sees" (like event_effective):
-- staff rows, and rule rows that are not suppressed. One CVE may have the
-- same tag from both origins; readers deduplicate.
CREATE VIEW vuln_tag_visible AS
SELECT t.cve_id, t.tag, t.origin, t.basis, t.rule_version, t.created_at
FROM vuln_tag t
WHERE t.origin = 'staff'
   OR NOT EXISTS (SELECT 1 FROM vuln_tag_suppress s WHERE s.cve_id = t.cve_id AND s.tag = t.tag);

-- Number of CVEs per tag (visible tags, each CVE once), rebuilt at the end
-- of every tag run that changed something and by `nday tags`. Pages read
-- this instead of counting vuln_tag per view; it can lag the rows by one
-- run (docs/tags.md §6).
CREATE TABLE vuln_tag_count (
    tag text PRIMARY KEY,
    n   bigint NOT NULL
);

-- Bookkeeping (exactly one row): when the counts were rebuilt, and which
-- rule version the last complete `nday tags --all` ran with (a run with an
-- older version means rows may be stale: the post-collector pass warns).
CREATE TABLE tag_run (
    id                 int PRIMARY KEY CONSTRAINT tag_run_one_row CHECK (id = 1),
    all_rule_version   int,
    all_completed_at   timestamptz,
    counts_refreshed_at timestamptz
);
INSERT INTO tag_run (id) VALUES (1);

-- Change log for the incremental pass, same discipline as classify_queue
-- (0009): every write that can change a CVE's tags appends the CVE id here
-- in the same transaction; a row is only deleted by the tag run that read
-- it, after reading the inputs in a later statement. Statement-level
-- triggers with transition tables: one INSERT per statement, not per row
-- (classify writes thousands of rows per COPY).
--
-- What is watched (internal/tags derives from exactly these):
--   vuln_cwe, vuln_cvss            type and access tags
--   vuln_classify_input            rejection flags; GHSA advisory versions
--                                  (ecosystem tags read the classified version)
--   event (kev_added, poc_published, disclosed)
--                                  exploit tags; CVE record rejection
--   vuln_tag_suppress              suppression added or lifted
CREATE TABLE tag_queue (
    id        bigserial PRIMARY KEY,
    cve_id    text NOT NULL,
    queued_at timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION tag_enqueue_new() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tag_queue (cve_id) SELECT DISTINCT cve_id FROM new_rows;
    RETURN NULL;
END
$$;

CREATE FUNCTION tag_enqueue_old() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tag_queue (cve_id) SELECT DISTINCT cve_id FROM old_rows;
    RETURN NULL;
END
$$;

CREATE FUNCTION tag_enqueue_both() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tag_queue (cve_id)
    SELECT cve_id FROM old_rows UNION SELECT cve_id FROM new_rows;
    RETURN NULL;
END
$$;

-- events: only the types the derivation reads (social_post never is)
CREATE FUNCTION tag_enqueue_event_new() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tag_queue (cve_id) SELECT DISTINCT cve_id FROM new_rows
    WHERE type IN ('kev_added', 'poc_published', 'disclosed');
    RETURN NULL;
END
$$;

CREATE FUNCTION tag_enqueue_event_old() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tag_queue (cve_id) SELECT DISTINCT cve_id FROM old_rows
    WHERE type IN ('kev_added', 'poc_published', 'disclosed');
    RETURN NULL;
END
$$;

CREATE FUNCTION tag_enqueue_event_both() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO tag_queue (cve_id)
    SELECT cve_id FROM old_rows WHERE type IN ('kev_added', 'poc_published', 'disclosed')
    UNION
    SELECT cve_id FROM new_rows WHERE type IN ('kev_added', 'poc_published', 'disclosed');
    RETURN NULL;
END
$$;

-- (PostgreSQL allows transition tables only on single-event triggers.)
CREATE TRIGGER vuln_cwe_tag_ins AFTER INSERT ON vuln_cwe
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_new();
CREATE TRIGGER vuln_cwe_tag_del AFTER DELETE ON vuln_cwe
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_old();
CREATE TRIGGER vuln_cwe_tag_upd AFTER UPDATE ON vuln_cwe
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_both();

CREATE TRIGGER vuln_cvss_tag_ins AFTER INSERT ON vuln_cvss
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_new();
CREATE TRIGGER vuln_cvss_tag_del AFTER DELETE ON vuln_cvss
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_old();
CREATE TRIGGER vuln_cvss_tag_upd AFTER UPDATE ON vuln_cvss
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_both();

CREATE TRIGGER vuln_classify_input_tag_ins AFTER INSERT ON vuln_classify_input
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_new();
CREATE TRIGGER vuln_classify_input_tag_del AFTER DELETE ON vuln_classify_input
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_old();
CREATE TRIGGER vuln_classify_input_tag_upd AFTER UPDATE ON vuln_classify_input
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_both();

CREATE TRIGGER event_tag_ins AFTER INSERT ON event
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_event_new();
CREATE TRIGGER event_tag_del AFTER DELETE ON event
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_event_old();
CREATE TRIGGER event_tag_upd AFTER UPDATE ON event
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_event_both();

CREATE TRIGGER vuln_tag_suppress_tag_ins AFTER INSERT ON vuln_tag_suppress
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_new();
CREATE TRIGGER vuln_tag_suppress_tag_del AFTER DELETE ON vuln_tag_suppress
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_old();
CREATE TRIGGER vuln_tag_suppress_tag_upd AFTER UPDATE ON vuln_tag_suppress
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_both();
