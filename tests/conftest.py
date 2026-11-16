from __future__ import annotations

import json
import os
from pathlib import Path

import httpx
import psycopg
import pytest
from psycopg import sql
from psycopg.conninfo import conninfo_to_dict, make_conninfo

from nday import config, db
from nday.collectors.kev import KEV_FEED_URL, KevCollector

FIXTURES = Path(__file__).parent / "fixtures"
DEFAULT_TEST_URL = "postgresql://nday:nday@127.0.0.1:54329/nday_test"


def _test_url() -> str:
    config.load_dotenv(config.PROJECT_ROOT / ".env")
    return os.environ.get("NDAY_TEST_DATABASE_URL", DEFAULT_TEST_URL)


@pytest.fixture(scope="session")
def test_db_url() -> str:
    url = _test_url()
    dbname = conninfo_to_dict(url)["dbname"]
    assert dbname and "test" in dbname, f"refusing to use non-test database {dbname!r}"
    admin = make_conninfo(url, dbname="postgres")
    with psycopg.connect(admin, autocommit=True) as c:
        exists = c.execute("SELECT 1 FROM pg_database WHERE datname = %s", (dbname,)).fetchone()
        if not exists:
            c.execute(sql.SQL("CREATE DATABASE {}").format(sql.Identifier(dbname)))
    return url


@pytest.fixture
def conn(test_db_url):
    """Fresh, fully migrated schema for every test."""
    with db.connect(test_db_url) as c:
        c.execute("DROP SCHEMA public CASCADE")
        c.execute("CREATE SCHEMA public")
        db.migrate(c)
        yield c


@pytest.fixture
def kev_feed() -> dict:
    return json.loads((FIXTURES / "kev_sample.json").read_text(encoding="utf-8"))


def make_kev_collector(feed: dict, seen_headers: list | None = None) -> KevCollector:
    """KevCollector whose HTTP layer serves `feed` (no network)."""

    def handler(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == KEV_FEED_URL
        if seen_headers is not None:
            seen_headers.append(dict(request.headers))
        return httpx.Response(200, json=feed)

    return KevCollector(client=httpx.Client(transport=httpx.MockTransport(handler)))
