from pathlib import Path

import psycopg
import pytest

from nday import db


def test_migration_applies_cleanly(conn):
    tables = {
        r[0]
        for r in conn.execute(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public'"
        )
    }
    assert {
        "schema_migrations",
        "raw_record",
        "vuln",
        "vuln_alias",
        "affected",
        "event",
        "collector_state",
    } <= tables
    versions = [
        r[0] for r in conn.execute("SELECT version FROM schema_migrations ORDER BY version")
    ]
    files = sorted(p.stem for p in (Path(__file__).parent.parent / "migrations").glob("*.sql"))
    assert versions[:2] == ["0001_init", "0002_vuln_state"]
    assert versions == files


def test_migrate_is_idempotent(conn):
    assert db.migrate(conn) == []


def test_event_type_check(conn):
    conn.execute("INSERT INTO vuln (cve_id) VALUES ('CVE-2024-1234')")
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute(
            """INSERT INTO event (cve_id, type, observed_at, source)
               VALUES ('CVE-2024-1234', 'bogus', now(), 't')"""
        )


def test_cve_id_format_allows_long_sequence(conn):
    conn.execute("INSERT INTO vuln (cve_id) VALUES ('CVE-2026-124194')")
    with pytest.raises(psycopg.errors.CheckViolation):
        conn.execute("INSERT INTO vuln (cve_id) VALUES ('CVE-2026-123')")
