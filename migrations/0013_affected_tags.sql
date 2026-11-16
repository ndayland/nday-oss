-- 0013_affected_tags: product and product-type tags read the affected table
-- (see docs/tags.md and internal/tags/products.go).
--
-- Rule version 2 of internal/tags derives product tags from two inputs:
-- the CVE's affected rows (vendor, product as the CVE record states them)
-- and the vulnerable CPE names of the classified NVD record. The NVD record
-- is already watched (vuln_classify_input triggers of 0011: a new NVD
-- version rewrites its input row with the new content hash); this migration
-- adds the same statement-level triggers on affected, so every insert,
-- update and delete of an affected row queues its CVE in tag_queue in the
-- same transaction. Additive: no table, row or existing trigger changes.
--
-- Write paths of affected today: internal/pipeline (INSERT ... ON CONFLICT
-- DO NOTHING, every collector and `nday import-cve`) and ON DELETE CASCADE
-- from vuln. Statement-level triggers fire for both (a cascaded delete is a
-- statement of its own); a statement that inserts nothing (conflict) queues
-- nothing.

CREATE TRIGGER affected_tag_ins AFTER INSERT ON affected
    REFERENCING NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_new();
CREATE TRIGGER affected_tag_del AFTER DELETE ON affected
    REFERENCING OLD TABLE AS old_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_old();
CREATE TRIGGER affected_tag_upd AFTER UPDATE ON affected
    REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows FOR EACH STATEMENT EXECUTE FUNCTION tag_enqueue_both();
