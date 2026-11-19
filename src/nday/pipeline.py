"""Run a collector: fetch -> store raw -> normalize -> idempotent upserts -> state.

Idempotency rules (re-running on unchanged upstream data writes zero rows):
- raw_record: a record whose content hash equals the latest stored version for
  its (source, source_key) is skipped entirely (not even normalized).
- vuln: inserted if missing; otherwise updated only if the merged values differ.
- vuln_alias / affected: INSERT ... ON CONFLICT DO NOTHING.
- event: INSERT ... ON CONFLICT (cve_id, type, source, dedupe_key) DO UPDATE
  only when detail/url changed or occurred_at was unknown; observed_at and
  is_backfill of an existing event are never changed.

Backfill: an event is stored with is_backfill=true when the run is the
collector's first successful run (bulk import) OR its RawRecord.is_backfill is
set (fetched on demand, not observed live). For collectors with
`wants_missing_cves`, `state.wanted` is filled before fetch() (see
missing_cves()).
"""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime
from typing import Any

import psycopg
from psycopg.types.json import Jsonb

from nday.collectors.base import Collector, NormalizeError
from nday.models import CollectorState, Normalized, RawRecord, VulnUpsert, is_ghsa_id

log = logging.getLogger(__name__)


@dataclass
class RunStats:
    source: str
    is_backfill: bool = False
    fetched: int = 0
    raw_unchanged: int = 0
    raw_new: int = 0
    normalize_errors: int = 0
    vuln_inserted: int = 0
    vuln_updated: int = 0
    alias_inserted: int = 0
    affected_inserted: int = 0
    event_inserted: int = 0
    event_updated: int = 0

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


# --------------------------------------------------------------------------- state


def load_state(conn: psycopg.Connection, source: str) -> CollectorState:
    row = conn.execute(
        """SELECT cursor, last_run_at, last_status, last_error, last_success_at
           FROM collector_state WHERE source = %s""",
        (source,),
    ).fetchone()
    if row is None:
        return CollectorState(source=source)
    return CollectorState(source, *row)


def _save_state(
    conn: psycopg.Connection,
    source: str,
    *,
    run_at: datetime,
    status: str,
    error: str | None,
    cursor: dict[str, Any] | None = None,
    success: bool,
) -> None:
    # On failure keep the previous cursor and last_success_at.
    conn.execute(
        """INSERT INTO collector_state
               (source, cursor, last_run_at, last_status, last_error, last_success_at)
           VALUES (%(source)s, %(cursor)s, %(run_at)s, %(status)s, %(error)s,
                   CASE WHEN %(success)s THEN %(run_at)s END)
           ON CONFLICT (source) DO UPDATE SET
               cursor          = CASE WHEN %(success)s THEN EXCLUDED.cursor
                                      ELSE collector_state.cursor END,
               last_run_at     = EXCLUDED.last_run_at,
               last_status     = EXCLUDED.last_status,
               last_error      = EXCLUDED.last_error,
               last_success_at = CASE WHEN %(success)s THEN EXCLUDED.last_run_at
                                      ELSE collector_state.last_success_at END""",
        {
            "source": source,
            "cursor": Jsonb(cursor) if cursor is not None else None,
            "run_at": run_at,
            "status": status,
            "error": error,
            "success": success,
        },
    )


# Numeric-aware "newest CVE first": year, then sequence number (CVE-2026-100000
# sorts before CVE-2026-99999). vuln.cve_id is CHECKed to '^CVE-[0-9]{4}-[0-9]{4,}$',
# so the casts cannot fail; numeric (not bigint) because the sequence is unbounded.
# GHSA-keyed vulns (docs/ghsa.md) are not CVEs and are left out.
_MISSING_CVES_SQL = """
SELECT v.cve_id FROM vuln v
WHERE v.cve_id LIKE 'CVE-%%'
  AND NOT EXISTS (SELECT 1 FROM raw_record r
                  WHERE r.source = %(source)s AND r.source_key = v.cve_id)
ORDER BY split_part(v.cve_id, '-', 2)::int DESC,
         split_part(v.cve_id, '-', 3)::numeric DESC
LIMIT %(limit)s
"""


def missing_cves(conn: psycopg.Connection, source: str, limit: int) -> tuple[str, ...]:
    """CVE ids in `vuln` for which `source` has never stored a raw record (any
    content, including e.g. a RESERVED record that produced no event), newest
    first, at most `limit`."""
    if limit <= 0:
        return ()
    rows = conn.execute(_MISSING_CVES_SQL, {"source": source, "limit": limit})
    return tuple(r[0] for r in rows)


# --------------------------------------------------------------------------- raw


def _latest_hashes(conn: psycopg.Connection, source: str) -> dict[str, str]:
    rows = conn.execute(
        """SELECT DISTINCT ON (source_key) source_key, content_hash
           FROM raw_record WHERE source = %s
           ORDER BY source_key, fetched_at DESC, id DESC""",
        (source,),
    )
    return {k: h for k, h in rows}


def _store_raw(conn: psycopg.Connection, rec: RawRecord, h: str, run_at: datetime) -> bool:
    """Insert a new content version. If upstream reverted to an older version we
    already have, bump its fetched_at so it becomes "latest" again (no new row).
    Returns True if a new row was inserted."""
    row = conn.execute(
        """INSERT INTO raw_record (source, source_key, fetched_at, content_hash, payload)
           VALUES (%s, %s, %s, %s, %s)
           ON CONFLICT (source, source_key, content_hash)
               DO UPDATE SET fetched_at = EXCLUDED.fetched_at
           RETURNING (xmax = 0) AS inserted""",
        (rec.source, rec.source_key, run_at, h, Jsonb(rec.payload)),
    ).fetchone()
    return bool(row[0])


# --------------------------------------------------------------------------- vuln


def merge_vuln(existing: dict[str, Any], new: VulnUpsert) -> dict[str, Any]:
    """Pure merge of a VulnUpsert into the existing column values."""
    merged = dict(existing)
    for col in ("title", "description", "published_at", "modified_at"):
        value = getattr(new, col)
        if value is None or value == "":
            continue  # None never erases
        current = existing.get(col)
        if new.authoritative or current is None or current == "":
            merged[col] = value
    return merged


_VULN_COLS = ("title", "description", "published_at", "modified_at")


def _upsert_vuln(
    conn: psycopg.Connection, v: VulnUpsert, observed_at: datetime, stats: RunStats
) -> None:
    row = conn.execute(
        f"SELECT {', '.join(_VULN_COLS)} FROM vuln WHERE cve_id = %s FOR UPDATE",
        (v.cve_id,),
    ).fetchone()
    if row is None:
        cur = conn.execute(
            """INSERT INTO vuln (cve_id, title, description, published_at, modified_at,
                                 first_seen_at)
               VALUES (%s, %s, %s, %s, %s, %s)
               ON CONFLICT (cve_id) DO NOTHING""",
            (v.cve_id, v.title, v.description, v.published_at, v.modified_at, observed_at),
        )
        stats.vuln_inserted += cur.rowcount
        return
    existing = dict(zip(_VULN_COLS, row))
    merged = merge_vuln(existing, v)
    if merged != existing:
        conn.execute(
            """UPDATE vuln SET title = %(title)s, description = %(description)s,
                   published_at = %(published_at)s, modified_at = %(modified_at)s,
                   updated_at = now()
               WHERE cve_id = %(cve_id)s""",
            {**merged, "cve_id": v.cve_id},
        )
        stats.vuln_updated += 1


def _ensure_stub(conn: psycopg.Connection, cve_id: str, observed_at: datetime, stats: RunStats) -> None:
    cur = conn.execute(
        "INSERT INTO vuln (cve_id, first_seen_at) VALUES (%s, %s) ON CONFLICT (cve_id) DO NOTHING",
        (cve_id, observed_at),
    )
    stats.vuln_inserted += cur.rowcount


# --------------------------------------------------------------------------- apply


def apply_normalized(
    conn: psycopg.Connection,
    norm: Normalized,
    *,
    observed_at: datetime,
    is_backfill: bool,
    stats: RunStats,
) -> None:
    for v in norm.vulns:
        _upsert_vuln(conn, v, observed_at, stats)
    # Any CVE referenced by other rows gets at least a stub vuln (FK target).
    # A GHSA id never gets a stub: rows for a GHSA id without a vuln row are
    # skipped (a withdrawn advisory never stored stores nothing; docs/ghsa.md).
    known = {v.cve_id for v in norm.vulns}
    skip: set[str] = set()
    for cve_id in sorted(
        {r.cve_id for r in (*norm.aliases, *norm.affected, *norm.events)} - known
    ):
        if is_ghsa_id(cve_id):
            if conn.execute("SELECT 1 FROM vuln WHERE cve_id = %s", (cve_id,)).fetchone() is None:
                skip.add(cve_id)
            continue
        _ensure_stub(conn, cve_id, observed_at, stats)

    for a in norm.aliases:
        if a.cve_id in skip:
            continue
        cur = conn.execute(
            """INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES (%s, %s, %s)
               ON CONFLICT (alias_type, alias) DO NOTHING""",
            (a.cve_id, a.alias, a.alias_type),
        )
        stats.alias_inserted += cur.rowcount

    for af in norm.affected:
        if af.cve_id in skip:
            continue
        cur = conn.execute(
            """INSERT INTO affected (cve_id, vendor, product) VALUES (%s, %s, %s)
               ON CONFLICT (cve_id, vendor, product) DO NOTHING""",
            (af.cve_id, af.vendor, af.product),
        )
        stats.affected_inserted += cur.rowcount

    for e in norm.events:
        if e.cve_id in skip:
            continue
        row = conn.execute(
            """INSERT INTO event (cve_id, type, occurred_at, observed_at, source, url,
                                  detail, is_backfill, dedupe_key)
               VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
               ON CONFLICT (cve_id, type, source, dedupe_key) DO UPDATE SET
                   detail      = EXCLUDED.detail,
                   url         = EXCLUDED.url,
                   occurred_at = COALESCE(event.occurred_at, EXCLUDED.occurred_at)
               WHERE event.detail IS DISTINCT FROM EXCLUDED.detail
                  OR event.url IS DISTINCT FROM EXCLUDED.url
                  OR (event.occurred_at IS NULL AND EXCLUDED.occurred_at IS NOT NULL)
               RETURNING (xmax = 0) AS inserted""",
            (
                e.cve_id,
                e.type,
                e.occurred_at,
                observed_at,
                e.source,
                e.url,
                Jsonb(e.detail),
                is_backfill,
                e.dedupe_key,
            ),
        ).fetchone()
        if row is not None:
            if row[0]:
                stats.event_inserted += 1
            else:
                stats.event_updated += 1


# --------------------------------------------------------------------------- run


def run_collector(
    conn: psycopg.Connection,
    collector: Collector,
    *,
    renormalize: bool = False,
    now: datetime | None = None,
) -> RunStats:
    """Run one collector end to end. `conn` must be in autocommit mode."""
    run_at = now or datetime.now(UTC)
    state = load_state(conn, collector.name)
    # First successful run = bulk import: observed_at is not meaningful.
    stats = RunStats(source=collector.name, is_backfill=state.is_first_run)
    try:
        if collector.wants_missing_cves:
            state = replace(
                state, wanted=missing_cves(conn, collector.name, collector.wanted_limit)
            )
        result = collector.fetch(state)
        stats.fetched = len(result.records)
        errors: list[str] = []
        with conn.transaction():
            latest = _latest_hashes(conn, collector.name)
            for rec in result.records:
                h = rec.content_hash
                if latest.get(rec.source_key) == h:
                    stats.raw_unchanged += 1
                    if not renormalize:
                        continue
                else:
                    if _store_raw(conn, rec, h, run_at):
                        stats.raw_new += 1
                try:
                    norm = collector.normalize(rec)
                except NormalizeError as exc:
                    stats.normalize_errors += 1
                    errors.append(f"{rec.source_key}: {exc}")
                    log.warning("normalize failed for %s/%s: %s", rec.source, rec.source_key, exc)
                    continue
                apply_normalized(
                    conn,
                    norm,
                    observed_at=run_at,
                    is_backfill=stats.is_backfill or rec.is_backfill,
                    stats=stats,
                )
            _save_state(
                conn,
                collector.name,
                run_at=run_at,
                status="partial" if errors else "ok",
                error="; ".join(errors[:20]) or None,
                cursor=result.cursor,
                success=True,
            )
    except Exception as exc:
        try:
            _save_state(
                conn,
                collector.name,
                run_at=run_at,
                status="error",
                error=f"{type(exc).__name__}: {exc}"[:2000],
                success=False,
            )
        except Exception:  # e.g. connection lost; don't mask the original error
            log.exception("could not record failure in collector_state")
        raise
    return stats
