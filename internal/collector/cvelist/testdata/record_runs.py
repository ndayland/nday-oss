"""pytest plugin: records, for every run_collector() call made by the Python
cvelist tests, the returned stats (or the exception type) and the stored
cvelist cursor afterwards. The Go ports compare against this file
(testdata/python_runs.json), i.e. full cursor JSON + full stats per run.

Run from the repo root (own database, never the shared nday_test):

    NDAY_TEST_DATABASE_URL=postgresql://nday:nday@127.0.0.1:54329/nday_test_cvelist_py \
    PYTHONPATH=internal/collector/cvelist/testdata .venv/bin/python -m pytest -q -p record_runs \
        tests/test_cvelist.py tests/test_cvelist_backfill.py
"""
import dataclasses
import json
import os
from pathlib import Path

import pytest

import nday.pipeline as pipeline

OUT = Path(__file__).parent / "python_runs.json"
RUNS: dict[str, list] = {}
CURRENT = {"id": None}
_orig = pipeline.run_collector


def _recording(conn, collector, *a, **kw):
    entry = {"collector": collector.name}
    try:
        stats = _orig(conn, collector, *a, **kw)
        entry["stats"] = dataclasses.asdict(stats)
        return stats
    except Exception as exc:
        entry["error"] = type(exc).__name__
        raise
    finally:
        row = conn.execute("SELECT cursor, last_status FROM collector_state WHERE source='cvelist'").fetchone()
        entry["cvelist_cursor"] = row[0] if row else None
        entry["cvelist_status"] = row[1] if row else None
        RUNS.setdefault(CURRENT["id"], []).append(entry)


pipeline.run_collector = _recording


@pytest.hookimpl(tryfirst=True)
def pytest_runtest_setup(item):
    CURRENT["id"] = item.name


def pytest_sessionfinish(session, exitstatus):
    OUT.write_text(json.dumps(RUNS, indent=1, sort_keys=True, default=str) + "\n", encoding="utf-8")
