"""cvelist collector tests. Records under tests/fixtures/cvelist/ are verbatim
live CVE JSON 5 records (fetched 2026-11-12); deltaLog/zips are served by an
in-process fake upstream (httpx.MockTransport), never the network."""

from __future__ import annotations

import copy
import io
import json
import logging
import zipfile
from datetime import UTC, date, datetime, timedelta
from pathlib import Path

import httpx
import pytest

from nday import USER_AGENT
from nday.collectors import COLLECTORS
from nday.collectors.base import NormalizeError
from nday.collectors.cvelist import (
    DELTA_LOG_URL,
    CveListCollector,
    eod_zip_url,
    extract_cvss,
    record_url,
)
from nday.models import Affected, Alias, RawRecord
from nday.pipeline import run_collector

FIX = Path(__file__).parent / "fixtures" / "cvelist"
NOW = datetime(2026, 11, 12, 14, 0, tzinfo=UTC)
TODAY = NOW.date()

TYPICAL = "CVE-2026-108262"  # GitHub_M: CNA title, CVSS 3.1, GHSA advisory, CISA-ADP SSVC
NO_TITLE = "CVE-2026-125344"  # Chrome: no CNA title, CVSS only in CISA-ADP
V4 = "CVE-2026-116081"  # CNA has CVSS 3.1 and 4.0
NA = "CVE-2026-117373"  # affected vendor/product "n/a", no metrics
REJECTED = "CVE-2026-107922"  # REJECTED, no datePublished
KEVREC = "CVE-2026-111793"  # CISA-ADP SSVC Exploitation=active + kev marker
ALL = [TYPICAL, NO_TITLE, V4, NA, REJECTED, KEVREC]

COUNT_SQL = """SELECT (SELECT count(*) FROM raw_record), (SELECT count(*) FROM vuln),
                      (SELECT count(*) FROM vuln_alias), (SELECT count(*) FROM affected),
                      (SELECT count(*) FROM event)"""


def rec(cve: str) -> dict:
    return json.loads((FIX / f"{cve}.json").read_text(encoding="utf-8"))


def norm(cve: str, payload: dict | None = None):
    return CveListCollector(client=object()).normalize(
        RawRecord("cvelist", cve, payload if payload is not None else rec(cve))
    )


def ts(s: str) -> datetime:
    return datetime.fromisoformat(s)


def change_set(fetch_time: str, new=(), updated=()) -> dict:
    """Same shape as a real deltaLog entry (see fixtures/cvelist/deltaLog_excerpt.json)."""

    def item(c):
        return {
            "cveId": c,
            "cveOrgLink": f"https://www.cve.org/CVERecord?id={c}",
            "githubLink": record_url(c),
            "dateUpdated": fetch_time,
        }

    return {
        "fetchTime": fetch_time,
        "numberOfChanges": len(new) + len(updated),
        "new": [item(c) for c in new],
        "updated": [item(c) for c in updated],
        "error": [],
    }


class FakeUpstream:
    """deltaLog (newest first, like upstream), end-of-day zips, record files."""

    def __init__(self):
        self.log: list[dict] = []
        self.zips: dict[date, dict[str, dict]] = {}
        self.files: dict[str, dict] = {c: rec(c) for c in ALL}
        self.fail: dict[str, list[int]] = {}  # url -> status codes to return first
        self.requests: list[httpx.Request] = []

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        url = str(request.url)
        if self.fail.get(url):
            return httpx.Response(self.fail[url].pop(0))
        if url == DELTA_LOG_URL:
            return httpx.Response(200, json=self.log)
        for day, recs in self.zips.items():
            if url == eod_zip_url(day):
                buf = io.BytesIO()
                with zipfile.ZipFile(buf, "w") as zf:
                    for c, p in recs.items():
                        zf.writestr(f"deltaCves/{c}.json", json.dumps(p))
                return httpx.Response(200, content=buf.getvalue())
        for c, p in self.files.items():
            if url == record_url(c):
                return httpx.Response(200, json=p)
        return httpx.Response(404)

    def urls(self) -> list[str]:
        return [str(r.url) for r in self.requests]

    def collector(self, now=NOW, **kw) -> CveListCollector:
        kw.setdefault("bootstrap_days", 2)
        kw.setdefault("max_files", 100)
        self.sleeps: list[float] = []
        return CveListCollector(
            client=httpx.Client(transport=httpx.MockTransport(self.handler)),
            clock=lambda: now,
            sleep=self.sleeps.append,
            **kw,
        )


@pytest.fixture
def up() -> FakeUpstream:
    u = FakeUpstream()
    d1, d2 = TODAY - timedelta(days=2), TODAY - timedelta(days=1)
    u.zips = {d1: {c: rec(c) for c in (TYPICAL, NO_TITLE)}, d2: {c: rec(c) for c in (V4, NA)}}
    # log: older days (covered by zips) + two change sets today
    u.log = [
        change_set("2026-11-12T09:00:00.000Z", new=[KEVREC]),
        change_set("2026-11-12T08:00:00.000Z", updated=[REJECTED, TYPICAL]),
        change_set("2026-11-11T10:00:00.000Z", new=[V4, NA]),
        change_set("2026-11-10T10:00:00.000Z", new=[TYPICAL, NO_TITLE]),
        change_set("2026-10-13T13:54:47.805Z", new=["CVE-2026-100000"]),
    ]
    return u


# ----------------------------------------------------------------- pure normalize


def test_registered():
    assert COLLECTORS["cvelist"] is CveListCollector


def test_deltalog_fixture_shape_matches_fake():
    real = json.loads((FIX / "deltaLog_excerpt.json").read_text())
    fake = change_set("2026-11-12T00:00:00.000Z", new=[TYPICAL])
    assert set(real[0]) == set(fake) == {"fetchTime", "numberOfChanges", "new", "updated", "error"}
    assert set(real[0]["new"][0]) == set(fake["new"][0])
    assert real[0]["new"][0]["githubLink"] == record_url(real[0]["new"][0]["cveId"])


def test_normalize_typical_published():
    p = rec(TYPICAL)
    n = norm(TYPICAL)
    (v,) = n.vulns
    assert v.authoritative is True
    assert v.title == p["containers"]["cna"]["title"]
    assert v.description == p["containers"]["cna"]["descriptions"][0]["value"]
    assert v.published_at == ts("2026-11-06T18:29:49.225+00:00")
    assert v.modified_at == ts(p["cveMetadata"]["dateUpdated"])
    advisory = p["containers"]["cna"]["source"]["advisory"]
    assert advisory.startswith("GHSA-")
    assert n.aliases == [Alias(TYPICAL, advisory, "ghsa")]
    assert n.affected == [
        Affected(TYPICAL, a["vendor"], a["product"]) for a in p["containers"]["cna"]["affected"]
    ]
    (e,) = n.events
    assert (e.type, e.source, e.dedupe_key) == ("disclosed", "cvelist", "")
    assert e.occurred_at == v.published_at
    assert e.url == f"https://www.cve.org/CVERecord?id={TYPICAL}"
    assert e.detail["state"] == "PUBLISHED"
    assert e.detail["assigner_short_name"] == "GitHub_M"
    assert e.detail["cvss"]["source"] == "cna"
    assert e.detail["cvss"]["version"] == "3.1"
    assert e.detail["ssvc"]["exploitation"] in ("none", "poc", "active")


def test_normalize_no_cna_title_uses_adp_cvss():
    p = rec(NO_TITLE)
    assert "title" not in p["containers"]["cna"]
    n = norm(NO_TITLE)
    assert n.vulns[0].title is None  # never invented
    assert n.vulns[0].description
    cvss = n.events[0].detail["cvss"]
    adp_metric = next(
        m["cvssV3_1"] for a in p["containers"]["adp"] for m in a.get("metrics", []) if "cvssV3_1" in m
    )
    assert cvss == {
        "version": "3.1",
        "base_score": adp_metric["baseScore"],
        "base_severity": adp_metric["baseSeverity"],
        "vector": adp_metric["vectorString"],
        "source": "adp:CISA-ADP",
    }
    assert n.aliases == []


def test_cvss_prefers_newest_version_in_cna():
    p = rec(V4)
    cvss = extract_cvss(p["containers"])
    v4 = next(m["cvssV4_0"] for m in p["containers"]["cna"]["metrics"] if "cvssV4_0" in m)
    assert cvss["version"] == "4.0" and cvss["source"] == "cna"
    assert (cvss["base_score"], cvss["vector"]) == (v4["baseScore"], v4["vectorString"])
    assert extract_cvss({"cna": {}}) is None
    assert "cvss" not in norm(NA).events[0].detail  # no metrics anywhere


def test_affected_skips_na():
    p = rec(NA)
    assert any("n/a" in (a.get("vendor"), a.get("product")) for a in p["containers"]["cna"]["affected"])
    assert norm(NA).affected == []


def test_normalize_rejected():
    n = norm(REJECTED)
    (v,) = n.vulns
    assert (v.title, v.description, v.published_at) == (None, None, None)
    assert v.modified_at == ts("2026-11-11T22:18:59.410+00:00")
    assert n.affected == [] and n.aliases == []
    (e,) = n.events
    assert e.occurred_at is None  # no datePublished -> not fabricated
    assert e.detail["state"] == "REJECTED"
    assert e.detail["date_rejected"] == "2026-11-11T22:18:59.410Z"
    assert e.detail["rejected_reasons"] and "cvss" not in e.detail


def test_normalize_reserved_emits_nothing():
    p = rec(NA)
    p["cveMetadata"]["state"] = "RESERVED"
    n = norm(NA, p)
    assert (n.vulns, n.events, n.affected, n.aliases) == ([], [], [], [])


def test_adp_kev_and_ssvc_go_to_detail_only():
    n = norm(KEVREC)
    assert [e.type for e in n.events] == ["disclosed"]  # no exploited_in_wild / kev_added
    d = n.events[0].detail
    assert d["ssvc"]["exploitation"] == "active"
    assert d["kev"]["date_added"] == "2026-11-10"


@pytest.mark.parametrize(
    "mutate",
    [
        lambda p: p.pop("cveMetadata"),
        lambda p: p.update(dataType="X"),
        lambda p: p["cveMetadata"].update(cveId="CVE-26-1"),
        lambda p: p["cveMetadata"].update(state="WEIRD"),
        lambda p: p["containers"].pop("cna"),
    ],
)
def test_normalize_malformed(mutate):
    p = rec(TYPICAL)
    mutate(p)
    with pytest.raises(NormalizeError):
        norm(TYPICAL, p)


def test_normalize_rejects_key_mismatch():
    with pytest.raises(NormalizeError):
        CveListCollector(client=object()).normalize(RawRecord("cvelist", NA, rec(TYPICAL)))


# ----------------------------------------------------------------- fetch + pipeline


def test_first_run_uses_zips_then_deltalog_for_today(conn, up):
    c = up.collector()
    stats = run_collector(conn, c, now=NOW)

    urls = up.urls()
    assert urls[0] == DELTA_LOG_URL
    assert eod_zip_url(TODAY - timedelta(days=2)) in urls
    assert eod_zip_url(TODAY - timedelta(days=1)) in urls
    # only today's change sets are fetched as files (TYPICAL newer than its zip copy)
    assert sorted(u for u in urls if "raw.githubusercontent.com" in u and u != DELTA_LOG_URL) == sorted(
        record_url(x) for x in (KEVREC, REJECTED, TYPICAL)
    )
    assert all(r.headers["user-agent"] == USER_AGENT for r in up.requests)
    assert stats.is_backfill is True
    assert stats.fetched == 6 and stats.raw_new == 6 and stats.normalize_errors == 0
    assert conn.execute(COUNT_SQL).fetchone()[0:2] == (6, 6)
    assert conn.execute(
        "SELECT count(*) FROM event WHERE type='disclosed' AND is_backfill"
    ).fetchone() == (6,)

    cur = conn.execute("SELECT cursor FROM collector_state WHERE source='cvelist'").fetchone()[0]
    assert cur["last_fetch_time"] == "2026-11-12T09:00:00.000Z"
    assert cur["pending"] == [] and cur["gaps"] == []
    assert cur["bootstrap"]["zip_days"] == ["2026-11-10", "2026-11-11"]
    assert cur["bootstrap"]["deltalog_from"] == "2026-11-12T00:00:00+00:00"
    assert cur["last_run"]["files_fetched"] == 3
    assert cur["last_run"]["http_requests"] == len(up.requests) == 6


def test_first_run_falls_back_to_deltalog_when_zip_missing(conn, up):
    del up.zips[TODAY - timedelta(days=1)]  # yesterday's release not published yet
    run_collector(conn, up.collector(), now=NOW)
    files = {u for u in up.urls() if u.endswith(".json") and u != DELTA_LOG_URL}
    assert files == {record_url(x) for x in (V4, NA, REJECTED, TYPICAL, KEVREC)}
    cur = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]
    assert cur["bootstrap"]["zip_days"] == ["2026-11-10"]
    assert cur["bootstrap"]["deltalog_from"] == "2026-11-11T00:00:00+00:00"


def test_second_run_is_idempotent(conn, up):
    run_collector(conn, up.collector(), now=NOW)
    before = conn.execute(COUNT_SQL).fetchone()
    up.requests.clear()

    stats = run_collector(conn, up.collector(now=NOW + timedelta(hours=1)), now=NOW + timedelta(hours=1))

    assert up.urls() == [DELTA_LOG_URL]  # nothing new -> no file fetches
    assert stats.fetched == 0 and stats.is_backfill is False
    assert conn.execute(COUNT_SQL).fetchone() == before

    # renormalize of unchanged data adds nothing either
    run_collector(conn, up.collector(), renormalize=True, now=NOW + timedelta(hours=2))
    assert conn.execute(COUNT_SQL).fetchone() == before


def test_incremental_fetches_only_new_change_sets(conn, up):
    run_collector(conn, up.collector(), now=NOW)
    later = NOW + timedelta(hours=1)
    changed = copy.deepcopy(rec(NA))
    changed["cveMetadata"]["dateUpdated"] = "2026-11-12T14:30:00.000Z"
    up.files[NA] = changed
    up.log.insert(0, change_set("2026-11-12T14:30:00.000Z", updated=[NA]))
    up.requests.clear()

    stats = run_collector(conn, up.collector(now=later), now=later)

    assert up.urls() == [DELTA_LOG_URL, record_url(NA)]
    assert (stats.fetched, stats.raw_new, stats.event_inserted, stats.event_updated) == (1, 1, 0, 0)
    assert stats.vuln_updated == 1
    assert conn.execute("SELECT modified_at FROM vuln WHERE cve_id=%s", (NA,)).fetchone() == (
        ts("2026-11-12T14:30:00+00:00"),
    )
    assert conn.execute(
        "SELECT count(*), bool_and(is_backfill) FROM event WHERE cve_id=%s", (NA,)
    ).fetchone() == (1, True)  # one disclosed event, still the bootstrap one
    cur = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]
    assert cur["last_fetch_time"] == "2026-11-12T14:30:00.000Z"
    assert cur["last_run"]["change_sets"] == 1

    # a genuinely new CVE after bootstrap is not backfill
    new = copy.deepcopy(rec(NA))
    new["cveMetadata"]["cveId"] = "CVE-2026-999999"
    up.files["CVE-2026-999999"] = new
    up.log.insert(0, change_set("2026-11-12T15:30:00.000Z", new=["CVE-2026-999999"]))
    run_collector(conn, up.collector(), now=later + timedelta(hours=1))
    assert conn.execute(
        "SELECT is_backfill, observed_at FROM event WHERE cve_id='CVE-2026-999999'"
    ).fetchone() == (False, later + timedelta(hours=1))


def test_falling_behind_warns_and_records_gap(conn, up, caplog):
    run_collector(conn, up.collector(), now=NOW)
    # 40 days later: the log no longer reaches back to our cursor
    much_later = NOW + timedelta(days=40)
    up.log = [
        change_set("2026-12-22T10:00:00.000Z", new=[NA]),
        change_set("2026-11-22T10:00:00.000Z", new=[V4]),
    ]
    with caplog.at_level(logging.WARNING, logger="nday.collectors.cvelist"):
        run_collector(conn, up.collector(now=much_later), now=much_later)
    assert any("fell behind" in r.message for r in caplog.records)
    cur = conn.execute("SELECT cursor, last_status FROM collector_state").fetchone()
    assert cur[1] == "ok"
    assert cur[0]["gaps"] == [
        {
            "missed_from": "2026-11-12T09:00:00.000Z",
            "log_starts": "2026-11-22T10:00:00.000Z",
            "detected_at": much_later.isoformat(),
        }
    ]
    assert cur[0]["last_fetch_time"] == "2026-12-22T10:00:00.000Z"

    # no false alarm when the log still covers the cursor
    caplog.clear()
    up.log.insert(0, change_set("2026-12-22T11:00:00.000Z", new=[NA]))
    with caplog.at_level(logging.WARNING, logger="nday.collectors.cvelist"):
        run_collector(conn, up.collector(), now=much_later + timedelta(hours=1))
    assert not any("fell behind" in r.message for r in caplog.records)
    assert len(conn.execute("SELECT cursor FROM collector_state").fetchone()[0]["gaps"]) == 1


def test_per_run_cap_keeps_backlog_pending(conn, up):
    up.zips = {}
    run_collector(conn, up.collector(bootstrap_days=0, max_files=2), now=NOW)
    # today's change sets: REJECTED, TYPICAL (08:00), KEVREC (09:00) -> 3 ids, cap 2
    files = {u for u in up.urls() if u != DELTA_LOG_URL}
    assert files == {record_url(REJECTED), record_url(TYPICAL)}  # oldest change sets first
    cur = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]
    assert cur["pending"] == [KEVREC]
    assert cur["last_fetch_time"] == "2026-11-12T09:00:00.000Z"

    up.log.insert(0, change_set("2026-11-12T15:00:00.000Z", new=[NA, V4]))
    up.requests.clear()
    run_collector(conn, up.collector(max_files=2), now=NOW + timedelta(hours=1))
    # backlog first, then the new change set, up to the cap
    assert {u for u in up.urls() if u != DELTA_LOG_URL} == {record_url(KEVREC), record_url(NA)}
    cur = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]
    assert cur["pending"] == [V4]
    assert cur["last_run"]["ids_queued"] == 3


def test_retry_with_backoff_then_failure_stays_pending(conn, up):
    up.zips = {}
    up.fail[record_url(TYPICAL)] = [503, 429]  # recovers on 3rd attempt
    up.fail[record_url(KEVREC)] = [500, 500, 500, 500]  # exhausts retries
    stats = run_collector(conn, up.collector(bootstrap_days=0), now=NOW)
    assert sorted(up.sleeps) == [1.0, 1.0, 2.0, 2.0, 4.0]
    assert stats.fetched == 2  # REJECTED + TYPICAL
    cur = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]
    assert cur["pending"] == [KEVREC]
    assert cur["last_run"]["files_failed"] == 1


def test_missing_record_file_is_dropped(conn, up):
    up.zips = {}
    del up.files[KEVREC]
    run_collector(conn, up.collector(bootstrap_days=0), now=NOW)
    cur = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]
    assert cur["pending"] == [] and cur["last_run"]["files_missing"] == [KEVREC]


def test_deltalog_failure_fails_run_and_keeps_cursor(conn, up):
    run_collector(conn, up.collector(), now=NOW)
    before = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]
    up.fail[DELTA_LOG_URL] = [502] * 4
    with pytest.raises(httpx.HTTPStatusError):
        run_collector(conn, up.collector(), now=NOW + timedelta(hours=1))
    row = conn.execute("SELECT cursor, last_status FROM collector_state").fetchone()
    assert row == (before, "error")


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("NDAY_CVELIST_BOOTSTRAP_DAYS", "3")
    monkeypatch.setenv("NDAY_CVELIST_MAX_FILES", "50")
    c = CveListCollector(client=object())
    assert (c.bootstrap_days, c.max_files) == (3, 50)
    monkeypatch.setenv("NDAY_CVELIST_BOOTSTRAP_DAYS", "31")
    with pytest.raises(ValueError):
        CveListCollector(client=object())
