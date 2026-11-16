"""On-demand backfill: the pipeline hands the cvelist collector the CVEs we know
(e.g. from KEV) but never fetched from cvelist; the collector fetches them in the
room left under max_files. No network: same fake upstream as test_cvelist."""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest
from conftest import make_kev_collector
from test_cvelist import (
    DELTA_LOG_URL,
    KEVREC,
    NA,
    NOW,
    REJECTED,
    TYPICAL,
    V4,
    FakeUpstream,
    change_set,
    rec,
    record_url,
    ts,
)

from nday.collectors import cvelist as cvelist_mod
from nday.collectors.base import Collector
from nday.collectors.cvelist import CveListCollector
from nday.models import CollectorState, FetchResult, Normalized, RawRecord
from nday.pipeline import missing_cves, run_collector

H = timedelta(hours=1)


def clone(base: str, cve: str, published: str | None = "2021-11-30T00:00:00.000Z") -> dict:
    """A real record re-labelled as another CVE (datePublished overridable)."""
    p = copy.deepcopy(rec(base))
    p["cveMetadata"]["cveId"] = cve
    if published is None:
        p["cveMetadata"].pop("datePublished", None)
    else:
        p["cveMetadata"]["datePublished"] = published
    return p


def add_stub(conn, *cves: str) -> None:
    for c in cves:
        conn.execute("INSERT INTO vuln (cve_id, first_seen_at) VALUES (%s, now())", (c,))


def fetched_files(up: FakeUpstream) -> set[str]:
    return {u for u in up.urls() if u != DELTA_LOG_URL}


def cursor(conn) -> dict:
    return conn.execute("SELECT cursor FROM collector_state WHERE source='cvelist'").fetchone()[0]


@pytest.fixture
def up() -> FakeUpstream:
    """Bootstrap from deltaLog only (no zips): today's ids are REJECTED, TYPICAL, KEVREC."""
    u = FakeUpstream()
    u.log = [
        change_set("2026-11-12T09:00:00.000Z", new=[KEVREC]),
        change_set("2026-11-12T08:00:00.000Z", updated=[REJECTED, TYPICAL]),
    ]
    return u


def run(conn, up: FakeUpstream, now, **kw):
    """One cvelist run whose collector clock equals the pipeline run time."""
    return run_collector(conn, up.collector(now=now, **kw), now=now)


def bootstrap(conn, up: FakeUpstream, **kw) -> None:
    kw.setdefault("bootstrap_days", 0)
    run(conn, up, NOW, **kw)
    up.requests.clear()


# ----------------------------------------------------------------- pipeline side


def test_missing_cves_query_excludes_stored_and_orders_numerically(conn):
    ids = ["CVE-2025-1234", "CVE-2026-99999", "CVE-2024-50000", "CVE-2026-100000",
           "CVE-2026-1000", "CVE-2023-0001"]
    add_stub(conn, *ids)
    # CVE-2023-0001 has a cvelist raw record that produced no event (RESERVED)
    reserved = clone(NA, "CVE-2023-0001")
    reserved["cveMetadata"]["state"] = "RESERVED"
    conn.execute(
        """INSERT INTO raw_record (source, source_key, fetched_at, content_hash, payload)
           VALUES ('cvelist', 'CVE-2023-0001', now(), 'h', %s::jsonb)""",
        (__import__("json").dumps(reserved),),
    )
    # a raw record from ANOTHER source does not count
    conn.execute(
        """INSERT INTO raw_record (source, source_key, fetched_at, content_hash, payload)
           VALUES ('kev', 'CVE-2025-1234', now(), 'h', '{}'::jsonb)"""
    )
    assert conn.execute("SELECT count(*) FROM event").fetchone() == (0,)

    assert missing_cves(conn, "cvelist", 100) == (
        "CVE-2026-100000", "CVE-2026-99999", "CVE-2026-1000", "CVE-2025-1234", "CVE-2024-50000",
    )
    assert missing_cves(conn, "cvelist", 2) == ("CVE-2026-100000", "CVE-2026-99999")
    assert missing_cves(conn, "cvelist", 0) == ()
    assert "CVE-2025-1234" not in missing_cves(conn, "kev", 100)


class Spy(Collector):
    name = "spy"

    def __init__(self):
        self.states: list[CollectorState] = []

    def fetch(self, state):
        self.states.append(state)
        return FetchResult(records=[], cursor={})

    def normalize(self, record):
        return Normalized()


class WantingSpy(Spy):
    name = "wspy"
    wants_missing_cves = True
    wanted_limit = 2


def test_pipeline_fills_wanted_only_for_opted_in(conn, kev_feed):
    add_stub(conn, "CVE-2026-5000", "CVE-2026-100001", "CVE-2020-0001")
    plain, wanting = Spy(), WantingSpy()
    run_collector(conn, plain, now=NOW)
    run_collector(conn, wanting, now=NOW)
    assert plain.states[0].wanted == ()
    assert wanting.states[0].wanted == ("CVE-2026-100001", "CVE-2026-5000")  # limit 2

    # kev: not opted in -> state.wanted empty, behaviour unchanged
    kev = make_kev_collector(kev_feed)
    seen: list[CollectorState] = []
    orig = kev.fetch
    kev.fetch = lambda st: (seen.append(st), orig(st))[1]
    stats = run_collector(conn, kev, now=NOW)
    assert seen[0].wanted == () and stats.is_backfill is True and stats.raw_new == 5
    assert conn.execute("SELECT bool_and(is_backfill) FROM event WHERE source='kev'").fetchone() == (True,)


def test_backfill_flag_does_not_touch_content_hash():
    p = rec(NA)
    a, b = RawRecord("cvelist", NA, p), RawRecord("cvelist", NA, p, is_backfill=True)
    assert a.content_hash == b.content_hash and a.is_backfill is False


# ----------------------------------------------------------------- collector side


def test_bootstrap_ignores_wanted(conn, up):
    add_stub(conn, "CVE-2021-43890")
    up.files["CVE-2021-43890"] = clone(TYPICAL, "CVE-2021-43890")
    bootstrap(conn, up)
    cur = cursor(conn)
    assert "backfill_missing" not in cur and "backfill_wanted" not in cur["last_run"]
    assert conn.execute(
        "SELECT count(*) FROM raw_record WHERE source_key='CVE-2021-43890'"
    ).fetchone() == (0,)


def test_queue_order_pending_then_changes_then_wanted_under_cap(conn, up):
    bootstrap(conn, up, max_files=2)  # REJECTED, TYPICAL fetched; KEVREC pending
    assert cursor(conn)["pending"] == [KEVREC]
    wanted = ["CVE-2026-90003", "CVE-2026-90002", "CVE-2026-90001"]
    add_stub(conn, *wanted)
    for w in wanted:
        up.files[w] = clone(TYPICAL, w)
    up.log.insert(0, change_set("2026-11-12T15:00:00.000Z", new=[NA]))

    c = up.collector(now=NOW + H, max_files=3)
    batches: list[list[str]] = []
    orig = c._fetch_records
    c._fetch_records = lambda ids: (batches.append(list(ids)), orig(ids))[1]
    stats = run_collector(conn, c, now=NOW + H)

    assert batches == [[KEVREC, NA, "CVE-2026-90003"]]  # pending -> change set -> newest wanted
    assert fetched_files(up) == {record_url(x) for x in (KEVREC, NA, "CVE-2026-90003")}
    cur = cursor(conn)
    assert cur["pending"] == []  # overflow wanted ids are NOT persisted
    lr = cur["last_run"]
    assert (lr["backfill_wanted"], lr["backfill_queued"], lr["backfill_fetched"],
            lr["backfill_dropped"], lr["files_fetched"], lr["ids_queued"]) == (3, 1, 1, 2, 3, 2)
    assert stats.fetched == 3

    # backfilled record -> is_backfill=true; live change-set record in the same run -> false
    rows = dict(conn.execute(
        "SELECT cve_id, is_backfill FROM event WHERE type='disclosed' AND cve_id = ANY(%s)",
        ([NA, KEVREC, "CVE-2026-90003"],),
    ).fetchall())
    assert rows == {NA: False, KEVREC: False, "CVE-2026-90003": True}

    # next run: no change sets -> the remaining wanted ids, newest first
    up.requests.clear()
    run(conn, up, NOW + 2 * H, max_files=3)
    assert fetched_files(up) == {record_url("CVE-2026-90002"), record_url("CVE-2026-90001")}
    up.requests.clear()
    run(conn, up, NOW + 3 * H, max_files=3)
    assert up.urls() == [DELTA_LOG_URL]  # settled
    assert cursor(conn)["last_run"]["backfill_wanted"] == 0


def test_wanted_id_already_in_change_set_is_not_backfill(conn, up):
    bootstrap(conn, up)
    add_stub(conn, NA)  # known (e.g. from KEV) AND changed upstream
    up.log.insert(0, change_set("2026-11-12T15:00:00.000Z", updated=[NA]))
    run(conn, up, NOW + H)
    assert [u for u in up.urls() if u == record_url(NA)] == [record_url(NA)]  # fetched once
    assert conn.execute(
        "SELECT is_backfill FROM event WHERE cve_id=%s", (NA,)
    ).fetchone() == (False,)
    assert cursor(conn)["last_run"]["backfill_queued"] == 0


def test_kev_only_vuln_gains_disclosure(conn, up, kev_feed):
    bootstrap(conn, up)
    run_collector(conn, make_kev_collector(kev_feed), now=NOW)  # stubs + kev_added
    kev_ids = [v["cveID"] for v in kev_feed["vulnerabilities"]]
    old = "CVE-2021-43890"
    up.files[old] = clone(TYPICAL, old, published="2021-12-14T18:00:00.000Z")
    rejected = "CVE-2026-59310"  # REJECTED without datePublished
    up.files[rejected] = clone(REJECTED, rejected, published=None)
    before = conn.execute("SELECT title FROM vuln WHERE cve_id=%s", (old,)).fetchone()[0]

    stats = run(conn, up, NOW + H)
    assert stats.is_backfill is False
    assert fetched_files(up) == {record_url(c) for c in kev_ids}
    cur = cursor(conn)
    assert cur["last_run"]["backfill_fetched"] == 2
    assert cur["last_run"]["backfill_missing"] == 3  # the other 3 KEV ids are 404 here
    assert cur["pending"] == []

    (title, desc, pub) = conn.execute(
        "SELECT title, description, published_at FROM vuln WHERE cve_id=%s", (old,)
    ).fetchone()
    p = up.files[old]["containers"]["cna"]
    assert title == p["title"] != before and desc == p["descriptions"][0]["value"]
    assert pub == ts("2021-12-14T18:00:00+00:00")
    assert conn.execute(
        "SELECT occurred_at, observed_at, is_backfill FROM event WHERE cve_id=%s AND type='disclosed'",
        (old,),
    ).fetchone() == (ts("2021-12-14T18:00:00+00:00"), NOW + H, True)
    st = conn.execute(
        "SELECT disclosed_at, round(days_disclosed_to_exploited, 2) FROM vuln_state WHERE cve_id=%s",
        (old,),
    ).fetchone()
    assert st[0] == ts("2021-12-14T18:00:00+00:00") and float(st[1]) == 0.25  # KEV 2021-12-15

    # REJECTED w/o date: unknown disclosure time, NOT our fetch time
    assert conn.execute(
        "SELECT occurred_at, is_backfill FROM event WHERE cve_id=%s AND type='disclosed'", (rejected,)
    ).fetchone() == (None, True)
    assert conn.execute(
        "SELECT disclosed_at, is_rejected FROM vuln_state WHERE cve_id=%s", (rejected,)
    ).fetchone() == (None, True)

    # second run: nothing fetched for them (404s are in the retry window)
    up.requests.clear()
    stats2 = run(conn, up, NOW + 2 * H)
    assert up.urls() == [DELTA_LOG_URL] and stats2.fetched == 0
    lr = cursor(conn)["last_run"]
    assert (lr["backfill_wanted"], lr["backfill_skipped_missing"], lr["backfill_queued"]) == (3, 3, 0)


def test_404_tracked_skipped_then_retried_and_bounded(conn, up, monkeypatch):
    bootstrap(conn, up)
    gone = ["CVE-2026-80003", "CVE-2026-80002", "CVE-2026-80001"]
    add_stub(conn, *gone)

    run(conn, up, NOW + H)
    assert fetched_files(up) == {record_url(c) for c in gone}
    cur = cursor(conn)
    assert cur["backfill_missing"] == {c: (NOW + H).isoformat() for c in gone}
    assert cur["last_run"]["backfill_missing"] == 3 and cur["pending"] == []

    up.requests.clear()  # within 7 days: skipped
    run(conn, up, NOW + 6 * 24 * H)
    assert up.urls() == [DELTA_LOG_URL]
    assert cursor(conn)["last_run"]["backfill_skipped_missing"] == 3

    # after the retry interval: retried; one now exists upstream
    up.files["CVE-2026-80002"] = clone(TYPICAL, "CVE-2026-80002")
    up.requests.clear()
    later = NOW + 8 * 24 * H
    run(conn, up, later)
    assert fetched_files(up) == {record_url(c) for c in gone}
    cur = cursor(conn)
    assert cur["backfill_missing"] == {
        "CVE-2026-80003": later.isoformat(), "CVE-2026-80001": later.isoformat()
    }
    assert cur["last_run"]["backfill_fetched"] == 1

    # custom retry interval (0 days = retry every run)
    up.requests.clear()
    run(conn, up, later + H, backfill_retry_days=0)
    assert len(fetched_files(up)) == 2

    # bounded map: keeps the most recent 404s
    monkeypatch.setattr(cvelist_mod, "MAX_BACKFILL_MISSING", 2)
    add_stub(conn, "CVE-2026-80000")
    run(conn, up, later + 30 * 24 * H)
    cur = cursor(conn)
    assert len(cur["backfill_missing"]) == 2
    assert cur["last_run"]["backfill_missing"] == 3
    assert cur["last_run"]["backfill_missing_tracked"] == 2


def test_missing_map_pruned_when_no_longer_wanted(conn, up):
    bootstrap(conn, up)
    add_stub(conn, "CVE-2026-80001")
    run(conn, up, NOW + H)
    assert list(cursor(conn)["backfill_missing"]) == ["CVE-2026-80001"]
    conn.execute("DELETE FROM vuln WHERE cve_id='CVE-2026-80001'")
    run(conn, up, NOW + 2 * H)
    assert cursor(conn)["backfill_missing"] == {}


def test_transient_failure_of_wanted_is_dropped_not_pending(conn, up):
    bootstrap(conn, up)
    w = "CVE-2026-70001"
    add_stub(conn, w)
    up.files[w] = clone(TYPICAL, w)
    up.fail[record_url(w)] = [500] * 4  # exhausts retries
    stats = run(conn, up, NOW + H)  # only wanted ids: must not raise
    row = conn.execute("SELECT cursor, last_status FROM collector_state").fetchone()
    assert row[1] == "ok" and stats.fetched == 0
    assert row[0]["pending"] == [] and row[0]["backfill_missing"] == {}
    assert row[0]["last_run"]["backfill_failed"] == 1

    # with a change set too: change id fetched, run ok, wanted failure still not pending
    up.fail[record_url(w)] = [500] * 4
    up.log.insert(0, change_set("2026-11-12T16:00:00.000Z", new=[V4]))
    run(conn, up, NOW + 2 * H)
    cur = cursor(conn)
    assert cur["pending"] == [] and cur["last_run"]["files_fetched"] == 1

    # next run it is wanted again and succeeds
    up.requests.clear()
    run(conn, up, NOW + 3 * H)
    assert fetched_files(up) == {record_url(w)}


def test_retry_days_from_env(monkeypatch):
    monkeypatch.setenv("NDAY_CVELIST_BACKFILL_RETRY_DAYS", "3")
    monkeypatch.setenv("NDAY_CVELIST_MAX_FILES", "50")
    c = CveListCollector(client=object())
    assert c.backfill_retry == timedelta(days=3)
    assert c.wanted_limit == 50 + cvelist_mod.MAX_BACKFILL_MISSING
    monkeypatch.setenv("NDAY_CVELIST_BACKFILL_RETRY_DAYS", "-1")
    with pytest.raises(ValueError):
        CveListCollector(client=object())
