"""Pipeline behaviour shared by the exploitdb / metasploit / nuclei collectors:
conditional requests, backfill flag, idempotency, size cap, retries, changed items."""

from datetime import UTC, datetime, timedelta

import httpx
import pytest

from nday import USER_AGENT
from nday.collectors._feed import FeedTooLarge
from nday.pipeline import run_collector
from poc_feed_helpers import ADAPTERS, FeedServer, collector

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
T1 = T0 + timedelta(days=1)
T2 = T1 + timedelta(days=1)

COUNTS = """SELECT (SELECT count(*) FROM raw_record), (SELECT count(*) FROM vuln),
                   (SELECT count(*) FROM vuln_alias), (SELECT count(*) FROM affected),
                   (SELECT count(*) FROM event)"""

SOURCES = sorted(ADAPTERS)


@pytest.fixture(params=SOURCES)
def feed(request):
    return ADAPTERS[request.param]


def _server(feed, data, etag='"v1"', **kw):
    return FeedServer(feed.url, feed.dump(data), etag, **kw)


def test_first_run_then_304_keeps_validators(conn, feed):
    server = _server(feed, feed.load(), etag='W/"abc"', gzip_body=True)
    s1 = run_collector(conn, collector(feed, server), now=T0)
    assert s1.is_backfill is True and s1.event_inserted > 0
    assert s1.vuln_updated == 0 and s1.alias_inserted == 0 and s1.affected_inserted == 0
    first = server.requests[0].headers
    assert first["user-agent"] == USER_AGENT
    assert first["accept-encoding"] == "gzip"
    assert "if-none-match" not in first
    cursor = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]
    assert cursor["etag"] == 'W/"abc"' and cursor["url"] == feed.url
    assert cursor["last_run"]["http_status"] == 200
    before = conn.execute(COUNTS).fetchone()

    s2 = run_collector(conn, collector(feed, server), now=T1)

    assert server.requests[1].headers["if-none-match"] == 'W/"abc"'
    assert (s2.fetched, s2.raw_new, s2.event_inserted, s2.event_updated) == (0, 0, 0, 0)
    assert conn.execute(COUNTS).fetchone() == before
    status, cur2 = conn.execute("SELECT last_status, cursor FROM collector_state").fetchone()
    assert status == "ok"
    assert cur2["etag"] == 'W/"abc"'
    assert cur2["last_run"] == {"http_status": 304, "attempts": 1}
    assert cur2["feed"] == cursor["feed"]  # counts of the last full download kept


def test_validators_not_sent_for_a_different_url(conn, feed):
    server = _server(feed, feed.load())
    run_collector(conn, collector(feed, server), now=T0)
    conn.execute("UPDATE collector_state SET cursor = jsonb_set(cursor, '{url}', '\"https://old.example/x\"')")
    run_collector(conn, collector(feed, server), now=T1)
    assert "if-none-match" not in server.requests[1].headers


def test_new_item_on_later_run_is_live(conn, feed):
    data = feed.load()
    server = _server(feed, feed.without(data, feed.new_key), etag='"v1"')
    s1 = run_collector(conn, collector(feed, server), now=T0)
    assert s1.is_backfill is True
    server.set(feed.dump(data), '"v2"')

    s2 = run_collector(conn, collector(feed, server), now=T1)

    assert s2.is_backfill is False
    assert s2.raw_new == 1 and s2.event_inserted >= 1 and s2.event_updated == 0
    rows = conn.execute(
        "SELECT dedupe_key, is_backfill, observed_at FROM event WHERE source = %s",
        (feed.cls.name,),
    ).fetchall()
    new = [r for r in rows if r[0] == feed.new_key]
    old = [r for r in rows if r[0] != feed.new_key]
    assert new and all(r[1:] == (False, T1) for r in new)
    assert old and all(r[1:] == (True, T0) for r in old)


def test_second_run_on_unchanged_200_is_idempotent(conn, feed):
    data = feed.load()
    run_collector(conn, collector(feed, _server(feed, data, '"a"')), now=T0)
    before = conn.execute(COUNTS).fetchone()
    snap = conn.execute("SELECT id, detail, observed_at, is_backfill FROM event ORDER BY id").fetchall()

    # different ETag (e.g. server ignored If-None-Match) but identical content
    s2 = run_collector(conn, collector(feed, _server(feed, data, '"b"')), now=T1)

    assert s2.raw_unchanged == s2.fetched > 0
    assert (s2.raw_new, s2.vuln_inserted, s2.event_inserted, s2.event_updated) == (0, 0, 0, 0)
    assert conn.execute(COUNTS).fetchone() == before
    assert conn.execute("SELECT id, detail, observed_at, is_backfill FROM event ORDER BY id").fetchall() == snap
    run_collector(conn, collector(feed, _server(feed, data, '"c"')), renormalize=True, now=T2)
    assert conn.execute(COUNTS).fetchone() == before


def test_changed_item_updates_detail_without_new_event(conn, feed):
    data = feed.load()
    server = _server(feed, data, '"v1"')
    run_collector(conn, collector(feed, server), now=T0)
    n_events = conn.execute("SELECT count(*) FROM event").fetchone()[0]
    server.set(feed.dump(feed.changed(data, feed.change_key)), '"v2"')

    s2 = run_collector(conn, collector(feed, server), now=T1)

    assert (s2.raw_new, s2.event_inserted, s2.event_updated) == (1, 0, 1)
    assert conn.execute("SELECT count(*) FROM event").fetchone()[0] == n_events
    title, observed, backfill = conn.execute(
        "SELECT detail->>'title', observed_at, is_backfill FROM event "
        "WHERE source = %s AND dedupe_key = %s AND cve_id = %s",
        (feed.cls.name, feed.change_key, feed.cve_of_change),
    ).fetchone()
    assert title.endswith("(updated)") and (observed, backfill) == (T0, True)
    assert conn.execute(
        "SELECT count(*) FROM raw_record WHERE source = %s AND source_key = %s",
        (feed.cls.name, feed.change_key),
    ).fetchone() == (2,)


@pytest.mark.parametrize("content_length", [True, False])
def test_size_cap_aborts_run_and_stores_nothing(conn, feed, content_length):
    body = feed.dump(feed.load())
    server = FeedServer(feed.url, body, content_length=content_length)
    with pytest.raises(FeedTooLarge):
        run_collector(conn, collector(feed, server, max_bytes=len(body) - 1), now=T0)
    assert conn.execute(COUNTS).fetchone() == (0, 0, 0, 0, 0)
    status, ok_at, err = conn.execute(
        "SELECT last_status, last_success_at, last_error FROM collector_state").fetchone()
    assert (status, ok_at) == ("error", None) and "FeedTooLarge" in err
    # exactly at the cap is fine
    s = run_collector(conn, collector(feed, FeedServer(feed.url, body), max_bytes=len(body)), now=T1)
    assert s.is_backfill is True and s.event_inserted > 0


def test_size_cap_applies_to_decoded_gzip_body(conn, feed):
    body = feed.dump(feed.load())
    server = FeedServer(feed.url, body, gzip_body=True)  # Content-Length = compressed size
    with pytest.raises(FeedTooLarge):
        run_collector(conn, collector(feed, server, max_bytes=len(body) - 1), now=T0)


def test_retries_429_and_5xx_then_succeeds(conn, feed):
    server = _server(feed, feed.load(), script=[429, 503])
    s = run_collector(conn, collector(feed, server), now=T0)
    assert len(server.requests) == 3 and s.event_inserted > 0
    cursor = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]
    assert cursor["last_run"]["attempts"] == 3


def test_persistent_5xx_fails_and_keeps_previous_cursor(conn, feed):
    server = _server(feed, feed.load(), '"v1"')
    run_collector(conn, collector(feed, server), now=T0)
    bad = _server(feed, feed.load(), script=[502, 502, 502, 502])
    with pytest.raises(httpx.HTTPStatusError):
        run_collector(conn, collector(feed, bad), now=T1)
    status, cursor = conn.execute("SELECT last_status, cursor FROM collector_state").fetchone()
    assert status == "error" and cursor["etag"] == '"v1"'
