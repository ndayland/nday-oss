"""Database connection and a tiny migration runner.

Migrations are plain SQL files named NNNN_description.sql, applied in
lexical order, each in its own transaction, and recorded in schema_migrations.
"""

from __future__ import annotations

import re
from pathlib import Path

import psycopg

from nday import config

MIGRATION_RE = re.compile(r"^(\d{4})_[\w-]+\.sql$")
# Arbitrary constant so concurrent `nday migrate` calls serialize.
MIGRATION_LOCK_ID = 0x6E646179


def connect(url: str | None = None) -> psycopg.Connection:
    """Autocommit connection; callers use `with conn.transaction():` explicitly."""
    return psycopg.connect(url or config.database_url(), autocommit=True)


def list_migrations(directory: Path) -> list[tuple[str, Path]]:
    found = []
    for p in sorted(directory.iterdir()):
        m = MIGRATION_RE.match(p.name)
        if m:
            found.append((p.stem, p))
    return found


def migrate(conn: psycopg.Connection, directory: Path | None = None) -> list[str]:
    """Apply pending migrations; return the versions applied this call."""
    directory = directory or config.migrations_dir()
    applied_now: list[str] = []
    conn.execute("SELECT pg_advisory_lock(%s)", (MIGRATION_LOCK_ID,))
    try:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS schema_migrations (
                   version    text PRIMARY KEY,
                   applied_at timestamptz NOT NULL DEFAULT now())"""
        )
        done = {r[0] for r in conn.execute("SELECT version FROM schema_migrations")}
        for version, path in list_migrations(directory):
            if version in done:
                continue
            sql = path.read_text(encoding="utf-8")
            with conn.transaction():
                conn.execute(sql)
                conn.execute(
                    "INSERT INTO schema_migrations (version) VALUES (%s)", (version,)
                )
            applied_now.append(version)
    finally:
        conn.execute("SELECT pg_advisory_unlock(%s)", (MIGRATION_LOCK_ID,))
    return applied_now
