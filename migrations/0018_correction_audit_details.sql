-- 0018_correction_audit_details: room in admin_audit.details for the full
-- public note of an accepted correction (Go only; see docs/corrections.md
-- and docs/admin.md).
--
-- correction.accept records the editor's public note. reason holds at most
-- 500 characters (0007), the note up to 1000 (0017), so the audit row keeps
-- the whole note in details.public_note. A 1000-character note does not fit
-- the 2048 bytes 0007 allows for details (up to 4 bytes per character as
-- jsonb text, up to 6 as the JSON the application checks), so rows with
-- target_type 'correction' may hold up to 8192 bytes; every other row keeps
-- the 2048-byte limit (internal/audit: MaxDetails, MaxCorrectionDetails).
--
-- Only a CHECK is replaced (same name, a superset of 0007's): no existing
-- row changes, and every existing row satisfies it.

-- Fail fast instead of queueing: the ALTER takes ACCESS EXCLUSIVE on
-- admin_audit; see 0012. Each file runs in its own transaction, so a timeout
-- leaves nothing applied and a retry is safe.
SET LOCAL lock_timeout = '5s';

ALTER TABLE admin_audit DROP CONSTRAINT admin_audit_details_check;
ALTER TABLE admin_audit ADD CONSTRAINT admin_audit_details_check
    CHECK (jsonb_typeof(details) = 'object'
        AND octet_length(details::text) <= CASE WHEN target_type = 'correction' THEN 8192 ELSE 2048 END);
