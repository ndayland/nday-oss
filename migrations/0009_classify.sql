-- 0009_classify: normalized classification data per CVE (CWE ids and CVSS
-- vectors with provenance), derived from the latest raw records of the
-- sources cvelist, nvd and ghsa by internal/classify (Go only; see
-- docs/nvd.md). Additive: no existing table, view or row changes; the event
-- tables and vuln_state are not read or written by anything here.
--
-- Nothing in these tables is entered by hand: `nday classify` and the
-- incremental pass after every collector run rebuild a CVE's rows from the
-- raw records, so the tables can always be dropped and recomputed.

-- source values (provenance of a row):
--   cve-cna        the CNA container of the CVE record (source_org = the
--                  CNA short name, cveMetadata.assignerShortName)
--   cve-adp        an ADP container of the CVE record (source_org = its
--                  providerMetadata.shortName, e.g. CISA-ADP)
--   nvd-primary    NVD's own analysts (NVD entry source = nvd@nist.gov)
--   nvd-secondary  what NVD republishes from a CNA/ADP (source_org = the
--                  NVD source identifier, an e-mail or UUID)
--   ghsa           a GitHub advisory (source_org = the GHSA id)

CREATE TABLE vuln_cwe (
    cve_id     text NOT NULL REFERENCES vuln (cve_id) ON DELETE CASCADE,
    cwe        text NOT NULL CONSTRAINT vuln_cwe_format CHECK (cwe ~ '^CWE-[0-9]+$'),
    source     text NOT NULL CONSTRAINT vuln_cwe_source CHECK (source IN (
                   'cve-cna', 'cve-adp', 'nvd-primary', 'nvd-secondary', 'ghsa')),
    source_org text NOT NULL DEFAULT '',
    PRIMARY KEY (cve_id, cwe, source, source_org)
);
-- "All CVEs with CWE X" (the primary key serves "classification of one CVE").
CREATE INDEX vuln_cwe_cwe_idx ON vuln_cwe (cwe, cve_id);

CREATE TABLE vuln_cvss (
    cve_id     text NOT NULL REFERENCES vuln (cve_id) ON DELETE CASCADE,
    version    text NOT NULL CONSTRAINT vuln_cvss_version CHECK (version IN ('2.0', '3.0', '3.1', '4.0')),
    -- validated per version by internal/classify (vector.go) before insert
    vector     text NOT NULL,
    -- as delivered by the source; NULL when absent or not a number in 0..10
    base_score numeric(3,1) CONSTRAINT vuln_cvss_score CHECK (base_score BETWEEN 0 AND 10),
    severity   text,
    source     text NOT NULL CONSTRAINT vuln_cvss_source CHECK (source IN (
                   'cve-cna', 'cve-adp', 'nvd-primary', 'nvd-secondary', 'ghsa')),
    source_org text NOT NULL DEFAULT '',
    PRIMARY KEY (cve_id, version, source, source_org)
);

-- Which raw record version each CVE's rows were derived from, one row per
-- (CVE, source, raw key) that was looked at, even when it produced no
-- classification row. rejected = that source marks the CVE rejected
-- (cvelist state REJECTED, NVD vulnStatus Rejected, GHSA withdrawn): such a
-- record contributes no vuln_cwe / vuln_cvss rows, and this flag is how the
-- tagging layer tells "rejected" from "never classified".
CREATE TABLE vuln_classify_input (
    cve_id         text NOT NULL REFERENCES vuln (cve_id) ON DELETE CASCADE,
    source         text NOT NULL CONSTRAINT vuln_classify_input_source CHECK (source IN ('cvelist', 'nvd', 'ghsa')),
    source_key     text NOT NULL,
    content_hash   text NOT NULL,
    rejected       boolean NOT NULL,
    -- counts of what the derivation skipped in this record
    cwe_skipped    int NOT NULL DEFAULT 0,
    cvss_skipped   int NOT NULL DEFAULT 0,
    classified_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (cve_id, source, source_key)
);
-- GHSA rows are keyed by advisory; find the CVEs an advisory fed.
CREATE INDEX vuln_classify_input_key_idx ON vuln_classify_input (source, source_key);

-- Change log for the incremental pass: every raw_record write of a
-- classified source (a new content version, or an older version made latest
-- again by bumping its fetched_at) and every new vuln row appends the
-- affected CVE id here, in the same transaction as the write. One row per
-- event (no ON CONFLICT): a row is only ever deleted by the classify run
-- that read it, after reading the raw records in a later snapshot, so a
-- write committed at any moment is either already visible to that run or
-- leaves its own row behind for the next one.
CREATE TABLE classify_queue (
    id        bigserial PRIMARY KEY,
    cve_id    text NOT NULL,
    queued_at timestamptz NOT NULL DEFAULT now()
);

CREATE FUNCTION classify_enqueue_raw() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF NEW.source IN ('cvelist', 'nvd') THEN
        IF NEW.source_key ~ '^CVE-[0-9]{4}-[0-9]{4,}$' THEN
            INSERT INTO classify_queue (cve_id) VALUES (NEW.source_key);
        END IF;
    ELSIF NEW.source = 'ghsa' THEN
        -- the advisory's current CVE, and every CVE it fed before (its cve_id
        -- may have changed: the old CVE's ghsa rows must be removed)
        INSERT INTO classify_queue (cve_id)
        SELECT c FROM (
            SELECT NEW.payload->>'cve_id' AS c
            UNION
            SELECT cve_id FROM vuln_classify_input
            WHERE source = 'ghsa' AND source_key = NEW.source_key
        ) s
        WHERE c ~ '^CVE-[0-9]{4}-[0-9]{4,}$';
    END IF;
    RETURN NULL;
END
$$;

CREATE TRIGGER raw_record_classify_enqueue
    AFTER INSERT OR UPDATE OF fetched_at ON raw_record
    FOR EACH ROW EXECUTE FUNCTION classify_enqueue_raw();

-- A vuln row that appears after its NVD (or GHSA) raw record: classify it
-- then (rows need the vuln row as their foreign-key target).
CREATE FUNCTION classify_enqueue_vuln() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    INSERT INTO classify_queue (cve_id) VALUES (NEW.cve_id);
    RETURN NULL;
END
$$;

CREATE TRIGGER vuln_classify_enqueue
    AFTER INSERT ON vuln
    FOR EACH ROW EXECUTE FUNCTION classify_enqueue_vuln();

-- GHSA advisories of one CVE (payload cve_id), for the derivation.
CREATE INDEX raw_record_ghsa_cve_idx ON raw_record ((payload->>'cve_id'))
    WHERE source = 'ghsa';
