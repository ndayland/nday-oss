"""Query helpers over the derived vuln_state view."""

from __future__ import annotations

from datetime import timedelta

import psycopg
from psycopg.rows import dict_row

HOT_SQL = """
SELECT s.cve_id, v.title, s.stage, s.stage_rank, s.last_transition_at,
       s.last_transition_type, s.has_patch, s.has_analysis, s.has_poc,
       s.exploited, s.in_kev, s.is_rejected
FROM vuln_state s
JOIN vuln v USING (cve_id)
WHERE s.last_transition_at IS NOT NULL
  AND s.last_transition_at >= now() - %(since)s
  AND (%(inc)s OR NOT s.is_rejected)
  AND s.last_transition_type = ANY(%(types)s)
ORDER BY s.last_transition_at DESC, s.stage_rank DESC, s.cve_id
LIMIT %(limit)s
"""

# Lifecycle order; must match the ranking in migrations/0002_vuln_state.sql.
STAGES = ("disclosed", "patch_released", "analysis_published", "poc_published",
          "exploited_in_wild", "kev_added")


def hot(conn: psycopg.Connection, since: timedelta, limit: int,
        include_rejected: bool = False, min_stage: str = "disclosed") -> list[dict]:
    """Vulns whose most recent transition (reaching a NEW event type) falls in the
    window, newest first. `min_stage` keeps only transitions to that stage or a
    later one, e.g. "patch_released" hides the daily flood of plain disclosures."""
    types = list(STAGES[STAGES.index(min_stage):])
    cur = conn.cursor(row_factory=dict_row)
    cur.execute(HOT_SQL, {"since": since, "limit": limit, "inc": include_rejected,
                          "types": types})
    return cur.fetchall()


def stage_counts(conn: psycopg.Connection) -> list[tuple[str, int]]:
    """[(stage, n)] ordered by stage rank."""
    return conn.execute(
        "SELECT stage, count(*) FROM vuln_state GROUP BY stage, stage_rank ORDER BY stage_rank"
    ).fetchall()
