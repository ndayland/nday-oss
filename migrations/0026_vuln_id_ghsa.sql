-- 0026_vuln_id_ghsa: a vulnerability's id may be a GHSA id.
--
-- The CVE id stays the main id. A GitHub advisory that has no CVE used to be
-- dropped at normalize time (only its raw record was kept); it now gets a
-- vuln row keyed by its GHSA id. When upstream later assigns a CVE, the row
-- and everything attached to it move to the CVE id and the GHSA id becomes
-- an ordinary alias (see docs/ghsa.md).
--
-- The column keeps its name: vuln.cve_id (and every cve_id that references
-- it) holds the vulnerability's id, a CVE id or a GHSA id. Only the format
-- check on vuln changes; the foreign keys carry it to the other tables.
--
-- GHSA ids are stored as "GHSA-" plus three groups of four characters from
-- GitHub's alphabet, lower case, the form vuln_alias already uses.
--
-- The check is re-added in one statement: it scans vuln once under an
-- exclusive lock (well under a second at the table's size). Every existing
-- row satisfies it, since the new rule only adds a second accepted form.

SET LOCAL lock_timeout = '5s';

ALTER TABLE vuln DROP CONSTRAINT vuln_cve_id_format;
ALTER TABLE vuln ADD CONSTRAINT vuln_cve_id_format CHECK (
    cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,}$'
    OR cve_id ~ '^GHSA(-[23456789cfghjmpqrvwx]{4}){3}$');
