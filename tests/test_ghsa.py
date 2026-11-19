"""ghsa collector tests. tests/fixtures/ghsa/advisories_sample.json holds verbatim
advisories from live GET /advisories responses (fetched 2026-11-12); the list
endpoint is served by an in-process fake (httpx.MockTransport) that implements
the same query semantics (updated>=, sort=updated asc, Link rel="next" with an
after= cursor), never the network."""

from __future__ import annotations

import base64
import copy
import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from nday import USER_AGENT
from nday.collectors import COLLECTORS
from nday.collectors.base import NormalizeError
from nday.collectors.ghsa import ADVISORIES_URL, GhsaCollector, fix_commit_urls, list_url, parse_ts
from nday.models import Alias, CollectorState, RawRecord
from nday.pipeline import run_collector

FIX = Path(__file__).parent / "fixtures" / "ghsa"
SAMPLE: list[dict] = json.loads((FIX / "advisories_sample.json").read_text(encoding="utf-8"))
RATE_LIMITED_BODY = json.loads((FIX / "rate_limited_403.json").read_text(encoding="utf-8"))
REAL_LINK = (FIX / "link_header.txt").read_text(encoding="utf-8").strip()

COUNT_SQL = """SELECT (SELECT count(*) FROM raw_record), (SELECT count(*) FROM vuln),
                      (SELECT count(*) FROM vuln_alias), (SELECT count(*) FROM affected),
                      (SELECT count(*) FROM event)"""


def _patched(a: dict) -> bool:
    return any((v.get("first_patched_version") or "").strip() for v in a.get("vulnerabilities") or [])


def pick(pred) -> dict:
    return copy.deepcopy(next(a for a in SAMPLE if pred(a)))


PATCHED = pick(lambda a: a["cve_id"] and not a["withdrawn_at"] and _patched(a) and fix_commit_urls(a["references"]))
UNPATCHED = pick(lambda a: a["cve_id"] and not a["withdrawn_at"] and not _patched(a))
NO_CVE = pick(lambda a: not a["cve_id"] and not a["withdrawn_at"])
WITHDRAWN_NO_CVE = pick(lambda a: a["withdrawn_at"])  # the live window had no withdrawn one with a CVE
WITHDRAWN = {**copy.deepcopy(PATCHED), "withdrawn_at": WITHDRAWN_NO_CVE["withdrawn_at"]}
NEWEST = max(parse_ts(a["updated_at"]) for a in SAMPLE)
NOW = NEWEST + timedelta(hours=1)


def norm(adv: dict):
    return GhsaCollector(client=object(), token="").normalize(RawRecord("ghsa", adv["ghsa_id"], adv))


def at(adv: dict, updated: str) -> dict:
    a = copy.deepcopy(adv)
    a["updated_at"] = updated
    return a


# ----------------------------------------------------------------- fake upstream


class FakeGitHub:
    """GET /advisories with GitHub's semantics as verified live: updated>=T filter,
    sort=updated&direction=asc, Link rel="next" carrying an opaque after= cursor."""

    def __init__(self, advisories: list[dict], page_size: int = 2):
        self.advisories = {a["ghsa_id"]: copy.deepcopy(a) for a in advisories}
        self.page_size = page_size
        self.remaining = 60
        self.fail: list[httpx.Response] = []  # responses served before normal ones
        self.requests: list[httpx.Request] = []
        self.reset = 1794495459

    def _rl(self) -> dict[str, str]:
        return {"x-ratelimit-limit": "60", "x-ratelimit-remaining": str(self.remaining),
                "x-ratelimit-used": str(60 - self.remaining), "x-ratelimit-reset": str(self.reset),
                "x-ratelimit-resource": "core"}

    def handler(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.fail:
            return self.fail.pop(0)
        if self.remaining <= 0:
            return httpx.Response(403, headers=self._rl(), json=RATE_LIMITED_BODY)
        self.remaining -= 1
        u = urlsplit(str(request.url))
        assert f"{u.scheme}://{u.netloc}{u.path}" == ADVISORIES_URL
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        assert (q["type"], q["sort"], q["direction"], q["per_page"]) == ("reviewed", "updated", "asc", "100")
        assert q["updated"].startswith(">=")
        since = parse_ts(q["updated"][2:])
        rows = sorted(
            (a for a in self.advisories.values() if parse_ts(a["updated_at"]) >= since),
            key=lambda a: (parse_ts(a["updated_at"]), a["ghsa_id"]),
        )
        if "after" in q:
            key = json.loads(base64.urlsafe_b64decode(q["after"]))
            if key == "bogus":
                return httpx.Response(422, json={"message": "Validation Failed"})
            rows = [a for a in rows if [a["updated_at"], a["ghsa_id"]] > key]
        page, more = rows[: self.page_size], len(rows) > self.page_size
        headers = self._rl()
        if more:
            token = base64.urlsafe_b64encode(json.dumps([page[-1]["updated_at"], page[-1]["ghsa_id"]]).encode()).decode()
            base = {k: v for k, v in q.items() if k not in ("after", "before")}
            nxt = httpx.URL(ADVISORIES_URL, params={**base, "after": token})
            headers["link"] = f'<{nxt}>; rel="next"'
        return httpx.Response(200, headers=headers, json=page)

    def collector(self, now=NOW, **kw) -> GhsaCollector:
        kw.setdefault("bootstrap_days", 7)
        kw.setdefault("max_requests", 10)
        kw.setdefault("overlap_minutes", 60)
        kw.setdefault("token", "")
        self.sleeps: list[float] = []
        return GhsaCollector(client=httpx.Client(transport=httpx.MockTransport(self.handler)),
                             clock=lambda: now, sleep=self.sleeps.append, **kw)

    def query(self, i: int = -1) -> dict[str, str]:
        return {k: v[0] for k, v in parse_qs(urlsplit(str(self.requests[i].url)).query).items()}


def cursor(conn) -> dict:
    return conn.execute("SELECT cursor FROM collector_state WHERE source='ghsa'").fetchone()[0]


# ----------------------------------------------------------------- fixtures sanity


def test_registered():
    assert COLLECTORS["ghsa"] is GhsaCollector


def test_fixture_is_real_shape():
    keys = {"ghsa_id", "cve_id", "url", "html_url", "summary", "description", "type", "severity",
            "source_code_location", "identifiers", "references", "published_at", "updated_at",
            "github_reviewed_at", "nvd_published_at", "withdrawn_at", "vulnerabilities", "cwes"}
    for a in SAMPLE:
        assert keys <= set(a), a["ghsa_id"]
        assert a["type"] == "reviewed"
    assert 'rel="next"' in REAL_LINK and "after=" in REAL_LINK


def test_next_url_parsed_from_real_link_header():
    resp = httpx.Response(200, headers={"link": REAL_LINK}, json=[])
    nxt = GhsaCollector._next_url(resp)
    q = parse_qs(urlsplit(nxt).query)
    assert nxt.startswith(ADVISORIES_URL + "?") and q["after"][0]
    bad = httpx.Response(200, headers={"link": '<https://evil.example/advisories?after=x>; rel="next"'})
    with pytest.raises(ValueError):
        GhsaCollector._next_url(bad)


# ----------------------------------------------------------------- pure normalize


def test_normalize_patched_advisory():
    a = PATCHED
    n = norm(a)
    cve, gid = a["cve_id"], a["ghsa_id"]
    assert n.aliases == [Alias(cve, gid, "ghsa")]
    (v,) = n.vulns
    assert (v.cve_id, v.title, v.description, v.authoritative) == (cve, a["summary"], a["description"].strip(), False)
    assert (v.published_at, v.modified_at) == (None, None)
    assert n.affected == []
    (e,) = n.events
    assert (e.type, e.source, e.dedupe_key, e.url) == ("patch_released", "ghsa", gid, a["html_url"])
    assert e.occurred_at is None  # GitHub does not say when the patch shipped
    d = e.detail
    assert d["ghsa_id"] == gid
    assert d["advisory_published_at"] == a["published_at"]
    assert d["advisory_updated_at"] == a["updated_at"]
    assert d["github_reviewed_at"] == a["github_reviewed_at"]
    assert d["severity"] == a["severity"]
    assert d["cvss"] == a["cvss_severities"]
    assert d["cwes"] == a["cwes"]
    assert d["packages"] == [
        {"ecosystem": x["package"]["ecosystem"], "name": x["package"]["name"],
         "vulnerable_version_range": x["vulnerable_version_range"],
         "first_patched_version": x["first_patched_version"]}
        for x in a["vulnerabilities"]
    ]
    assert d["fix_commit_urls"] and set(d["fix_commit_urls"]) <= set(a["references"])
    assert d["source_code_location"] == a["source_code_location"]
    assert d["references"] == a["references"]
    assert "epss" not in json.dumps(d)  # volatile scores stay in the raw record only


def test_normalize_unpatched_advisory_no_event():
    n = norm(UNPATCHED)
    assert n.events == []
    assert n.aliases == [Alias(UNPATCHED["cve_id"], UNPATCHED["ghsa_id"], "ghsa")]
    assert [v.title for v in n.vulns] == [UNPATCHED["summary"]]


def test_normalize_no_cve_keyed_by_ghsa():
    n = norm(NO_CVE)
    gid = NO_CVE["ghsa_id"]
    assert (n.aliases, n.affected) == ([], [])
    assert [(v.cve_id, v.title, v.authoritative, v.published_at, v.modified_at) for v in n.vulns] == [
        (gid, NO_CVE["summary"], True, parse_ts(NO_CVE["published_at"]), parse_ts(NO_CVE["updated_at"]))]
    disc, patch = n.events
    assert (disc.cve_id, disc.type, disc.source, disc.occurred_at, disc.dedupe_key, disc.url) == (
        gid, "disclosed", "ghsa", parse_ts(NO_CVE["published_at"]), gid, NO_CVE["html_url"])
    assert disc.detail == {"ghsa_id": gid, "state": "PUBLISHED", "withdrawn_at": None}
    assert (patch.cve_id, patch.type, patch.occurred_at, patch.dedupe_key) == (gid, "patch_released", None, gid)


def test_normalize_withdrawn():
    n0 = norm(WITHDRAWN_NO_CVE)
    assert (n0.vulns, n0.aliases) == ([], [])
    assert [(e.type, e.detail["state"]) for e in n0.events] == [("disclosed", "REJECTED")]
    n = norm(WITHDRAWN)
    assert n.aliases == [Alias(WITHDRAWN["cve_id"], WITHDRAWN["ghsa_id"], "ghsa")]
    assert (n.vulns, n.events, n.affected) == ([], [], [])


def test_patched_version_whitespace_or_null_is_unpatched():
    a = copy.deepcopy(PATCHED)
    for v in a["vulnerabilities"]:
        v["first_patched_version"] = "  "
    assert norm(a).events == []
    a["vulnerabilities"][0]["first_patched_version"] = {"identifier": "1.2.3"}  # legacy shape
    assert norm(a).events[0].detail["packages"][0]["first_patched_version"] == "1.2.3"


def test_fix_commit_url_extraction():
    refs = [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1",
        "https://github.com/acme/widget/commit/0123456789abcdef0123456789abcdef01234567",
        "https://github.com/acme/widget/commit/0123456789abcdef0123456789abcdef01234567",  # dup
        "https://github.com/acme/widget/pull/42",
        "https://github.com/acme/widget/pull/42/commits/abcdef1",
        "https://github.com/github/advisory-database/pull/10102",
        "https://github.com/acme/widget/security/advisories/GHSA-xxxx-xxxx-xxxx",
        "https://github.com/acme/widget/releases/tag/v1.2.3",
        "https://github.com/acme/widget/issues/7",
        "https://github.com/advisories/GHSA-2222-3333-4444",
        "https://github.com/acme/widget/commits/main",
        "https://gitlab.com/group/sub/proj/-/commit/89abcdef0123",
        "https://gitlab.example.org/team/proj/-/merge_requests/9",
        "https://gitlab.com/group/proj/-/issues/3",
        "https://bitbucket.org/o/r/commits/deadbeefcafe",
        "https://example.com/commit/0123456789abcdef",
        None,
        "",
    ]
    assert fix_commit_urls(refs) == [
        "https://github.com/acme/widget/commit/0123456789abcdef0123456789abcdef01234567",
        "https://github.com/acme/widget/pull/42",
        "https://github.com/acme/widget/pull/42/commits/abcdef1",
        "https://gitlab.com/group/sub/proj/-/commit/89abcdef0123",
        "https://gitlab.example.org/team/proj/-/merge_requests/9",
        "https://bitbucket.org/o/r/commits/deadbeefcafe",
    ]
    assert fix_commit_urls(None) == []


def test_fix_commit_urls_from_real_references():
    found = {u for a in SAMPLE for u in fix_commit_urls(a["references"])}
    assert found
    assert all(("/commit/" in u or "/pull/" in u or "/merge_requests/" in u) for u in found)
    assert not any("/advisories/" in u or "advisory-database" in u for u in found)
    a = next(x for x in SAMPLE if x["ghsa_id"] == "GHSA-7ph3-grqh-pv9v")
    assert norm(a).events[0].detail["fix_commit_urls"] == [
        "https://github.com/apache/gravitino/pull/8000",
        "https://github.com/apache/gravitino/commit/5355bd075d54cad1323606723e72cc32ca564f24",
    ]


@pytest.mark.parametrize(
    "mutate",
    [
        lambda a: a.update(ghsa_id="GHSA-nope"),
        lambda a: a.update(updated_at="yesterday"),
        lambda a: a.pop("published_at"),
        lambda a: a.update(cve_id="CVE-26-1"),
        lambda a: a.update(vulnerabilities="x"),
        lambda a: a.update(references={"a": 1}),
        lambda a: a["vulnerabilities"].append("junk"),
    ],
)
def test_normalize_malformed(mutate):
    a = copy.deepcopy(PATCHED)
    mutate(a)
    with pytest.raises(NormalizeError):
        norm(a)


def test_normalize_rejects_key_mismatch():
    with pytest.raises(NormalizeError):
        GhsaCollector(client=object(), token="").normalize(RawRecord("ghsa", UNPATCHED["ghsa_id"], PATCHED))


# ----------------------------------------------------------------- fetch + pipeline


def test_first_run_window_pagination_and_headers(conn):
    gh = FakeGitHub(SAMPLE, page_size=2)
    stats = run_collector(conn, gh.collector(), now=NOW)

    pages = -(-len(SAMPLE) // 2)
    assert len(gh.requests) == pages
    assert gh.query(0)["updated"] == ">=" + (NOW - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert "after" not in gh.query(0) and all("after" in gh.query(i) for i in range(1, pages))
    for r in gh.requests:
        assert r.headers["user-agent"] == USER_AGENT
        assert r.headers["accept"] == "application/vnd.github+json"
        assert "authorization" not in r.headers
    assert stats.is_backfill is True
    assert stats.fetched == stats.raw_new == len(SAMPLE) and stats.normalize_errors == 0
    with_cve = [a for a in SAMPLE if a["cve_id"]]
    patched_live = [a for a in SAMPLE if not a["withdrawn_at"] and _patched(a)]
    no_cve_live = [a for a in SAMPLE if not a["cve_id"] and not a["withdrawn_at"]]
    assert no_cve_live
    assert conn.execute("SELECT count(*) FROM raw_record WHERE source='ghsa'").fetchone() == (len(SAMPLE),)
    assert conn.execute("SELECT count(*) FROM vuln_alias").fetchone() == (len(with_cve),)
    # patch_released (no time) per live patched advisory; a disclosed event only
    # for the live ones without a CVE (keyed by the GHSA id); the withdrawn one
    # without a CVE stores nothing
    assert conn.execute(
        """SELECT count(*) FILTER (WHERE type = 'patch_released' AND occurred_at IS NULL),
                  count(*) FILTER (WHERE type = 'disclosed' AND cve_id LIKE 'GHSA-%'),
                  count(*), bool_and(is_backfill) FROM event"""
    ).fetchone() == (len(patched_live), len(no_cve_live), len(patched_live) + len(no_cve_live), True)
    assert conn.execute("SELECT count(*) FROM vuln WHERE cve_id LIKE 'GHSA-%'").fetchone() == (len(no_cve_live),)
    cur = cursor(conn)
    assert cur["since"] == NEWEST.strftime("%Y-%m-%dT%H:%M:%SZ")
    assert cur["pending"] is None and cur["gaps"] == []
    assert cur["bootstrap"]["days"] == 7
    assert cur["last_run"]["pages"] == pages and cur["last_run"]["advisories"] == len(SAMPLE)
    assert cur["last_run"]["rate_limit"]["remaining"] == 60 - pages


def test_first_run_window_excludes_older(conn):
    gh = FakeGitHub(SAMPLE + [at({**PATCHED, "ghsa_id": "GHSA-2222-3333-4444"}, "2020-01-01T00:00:00Z")])
    stats = run_collector(conn, gh.collector(), now=NOW)
    assert stats.fetched == len(SAMPLE)


def test_second_run_is_idempotent_and_overlaps(conn):
    gh = FakeGitHub(SAMPLE, page_size=100)
    run_collector(conn, gh.collector(), now=NOW)
    before = conn.execute(COUNT_SQL).fetchone()
    gh.requests.clear()
    later = NOW + timedelta(hours=1)
    stats = run_collector(conn, gh.collector(now=later), now=later)
    assert len(gh.requests) == 1  # a typical hourly run: one request
    assert gh.query()["updated"] == ">=" + (NEWEST - timedelta(minutes=60)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert stats.raw_new == 0 and stats.raw_unchanged == stats.fetched >= 1
    assert stats.is_backfill is False
    assert conn.execute(COUNT_SQL).fetchone() == before
    run_collector(conn, gh.collector(), renormalize=True, now=later + timedelta(hours=1))
    assert conn.execute(COUNT_SQL).fetchone() == before


def test_same_timestamp_overlap_is_safe(conn):
    """An advisory indexed late with the same updated_at as the high-water mark
    is still picked up (inclusive >= bound), even with zero overlap."""
    ts = "2026-11-12T10:00:00Z"
    a1 = at(PATCHED, ts)
    gh = FakeGitHub([a1], page_size=100)
    run_collector(conn, gh.collector(overlap_minutes=0), now=NOW)
    assert cursor(conn)["since"] == ts
    late = at(UNPATCHED, ts)  # same second, appears only now
    gh.advisories[late["ghsa_id"]] = late
    later = NOW + timedelta(hours=1)
    stats = run_collector(conn, gh.collector(now=later, overlap_minutes=0), now=later)
    assert gh.query()["updated"] == ">=" + ts
    assert stats.raw_new == 1 and stats.raw_unchanged == 1
    assert conn.execute("SELECT count(*) FROM raw_record WHERE source_key=%s", (late["ghsa_id"],)).fetchone() == (1,)


def test_request_cap_carries_pending_over(conn):
    gh = FakeGitHub(SAMPLE, page_size=2)
    run_collector(conn, gh.collector(), now=NOW)  # bootstrap complete
    # a burst of 5 advisories all with the same timestamp (bulk re-review)
    burst_ts = (NOW + timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
    burst = [at({**SAMPLE[i % len(SAMPLE)], "ghsa_id": gid}, burst_ts)
             for i, gid in enumerate(["GHSA-2222-2222-2222", "GHSA-3333-3333-3333", "GHSA-4444-4444-4444",
                                      "GHSA-5555-5555-5555", "GHSA-6666-6666-6666"])]
    for b in burst:
        gh.advisories[b["ghsa_id"]] = b
    later = NOW + timedelta(hours=1)
    gh.requests.clear()
    stats = run_collector(conn, gh.collector(now=later, max_requests=2, overlap_minutes=0), now=later)
    assert len(gh.requests) == 2
    cur = cursor(conn)
    assert cur["pending"]["reason"] == "request_cap" and "after=" in cur["pending"]["next_url"]
    assert cur["last_run"]["stopped"] == "request_cap"
    assert cur["since"] == burst_ts
    got_first = stats.raw_new
    # next run resumes the stored next URL (not the high-water mark, which would loop on the tie)
    gh.requests.clear()
    stats2 = run_collector(conn, gh.collector(now=later + timedelta(hours=1), max_requests=2,
                                              overlap_minutes=0), now=later + timedelta(hours=1))
    assert str(gh.requests[0].url) == cur["pending"]["next_url"]
    assert cursor(conn)["pending"] is None
    assert got_first + stats2.raw_new == len(burst)
    assert conn.execute(
        "SELECT count(*) FROM raw_record WHERE source_key = ANY(%s)", ([b["ghsa_id"] for b in burst],)
    ).fetchone() == (len(burst),)


def test_stale_pending_url_falls_back_to_since(conn):
    gh = FakeGitHub(SAMPLE, page_size=100)
    run_collector(conn, gh.collector(), now=NOW)
    conn.execute("""UPDATE collector_state SET cursor = jsonb_set(cursor, '{pending}', %s::jsonb)""",
                 (json.dumps({"next_url": list_url(NEWEST) + "&after=" + base64.urlsafe_b64encode(b'"bogus"').decode(),
                              "query_since": "2026-11-12T00:00:00Z", "reason": "request_cap"}),))
    gh.requests.clear()
    later = NOW + timedelta(hours=1)
    run_collector(conn, gh.collector(now=later), now=later)
    assert len(gh.requests) == 2 and "after" not in gh.query(1)
    assert cursor(conn)["pending"] is None


def test_rate_limit_mid_run_keeps_fetched_and_persists_progress(conn, caplog):
    gh = FakeGitHub(SAMPLE[:1], page_size=2)
    run_collector(conn, gh.collector(), now=NOW)
    for i, gid in enumerate(["GHSA-2222-2222-2222", "GHSA-3333-3333-3333", "GHSA-4444-4444-4444"]):
        gh.advisories[gid] = at({**UNPATCHED, "ghsa_id": gid}, (NOW + timedelta(minutes=i + 1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    gh.remaining = 1  # one more page, then 403 remaining=0
    later = NOW + timedelta(hours=1)
    gh.requests.clear()
    with caplog.at_level(logging.WARNING, logger="nday.collectors.ghsa"):
        stats = run_collector(conn, gh.collector(now=later, overlap_minutes=0), now=later)
    # header said remaining=0 after page 1, so no doomed second request is made
    assert len(gh.requests) == 1
    assert stats.raw_new == 1  # GHSA-2222 (+ the old one unchanged)
    row = conn.execute("SELECT last_status, cursor FROM collector_state").fetchone()
    assert row[0] == "ok"
    assert row[1]["pending"]["reason"] == "rate_limited"
    assert row[1]["last_run"]["rate_limit"]["reset_at"] == "2026-11-12T14:57:39Z"
    assert any("stopped early (rate_limited)" in r.message for r in caplog.records)

    # quota back: resumes and finishes
    gh.remaining = 60
    gh.requests.clear()
    stats = run_collector(conn, gh.collector(now=later + timedelta(hours=1)), now=later + timedelta(hours=1))
    assert stats.raw_new == 2
    assert cursor(conn)["pending"] is None


def test_rate_limited_403_on_first_request_of_incremental_run(conn):
    gh = FakeGitHub(SAMPLE, page_size=100)
    run_collector(conn, gh.collector(), now=NOW)
    before = cursor(conn)
    gh.remaining = 0
    later = NOW + timedelta(hours=1)
    stats = run_collector(conn, gh.collector(now=later), now=later)
    assert stats.fetched == 0 and len(gh.sleeps) == 0
    cur = cursor(conn)
    assert cur["since"] == before["since"]
    assert cur["pending"]["reason"] == "rate_limited"
    assert cur["pending"]["next_url"] == str(gh.requests[-1].url)


def test_rate_limited_first_run_fails_without_storing(conn):
    gh = FakeGitHub(SAMPLE, page_size=2)
    gh.remaining = 1
    with pytest.raises(RuntimeError, match="rate_limited"):
        run_collector(conn, gh.collector(), now=NOW)
    assert conn.execute(COUNT_SQL).fetchone() == (0, 0, 0, 0, 0)
    row = conn.execute("SELECT last_status, cursor, last_success_at FROM collector_state").fetchone()
    assert row == ("error", None, None)


def test_secondary_rate_limit_retry_after_then_success(conn):
    gh = FakeGitHub(SAMPLE, page_size=100)
    gh.fail = [httpx.Response(429, headers={"retry-after": "5", "x-ratelimit-remaining": "40"},
                              json={"message": "You have exceeded a secondary rate limit."}),
               httpx.Response(502)]
    stats = run_collector(conn, gh.collector(), now=NOW)
    assert gh.sleeps == [5.0, 2.0]
    assert stats.fetched == len(SAMPLE)


def test_other_4xx_fails_run(conn):
    gh = FakeGitHub(SAMPLE)
    gh.fail = [httpx.Response(403, headers={"x-ratelimit-remaining": "55"},
                              json={"message": "Resource not accessible"})]
    with pytest.raises(httpx.HTTPStatusError):
        run_collector(conn, gh.collector(), now=NOW)


def test_falling_behind_records_gap(conn, caplog):
    gh = FakeGitHub(SAMPLE[:1], page_size=1)
    run_collector(conn, gh.collector(), now=NOW)
    for i in range(3):
        gid = f"GHSA-{i + 2}{i + 2}{i + 2}{i + 2}-2222-2222"
        gh.advisories[gid] = at({**UNPATCHED, "ghsa_id": gid}, (NOW + timedelta(hours=i + 1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    much_later = NOW + timedelta(days=3)
    with caplog.at_level(logging.WARNING, logger="nday.collectors.ghsa"):
        run_collector(conn, gh.collector(now=much_later, max_requests=1, overlap_minutes=0), now=much_later)
    assert any("fell behind" in r.message for r in caplog.records)
    cur = cursor(conn)
    assert cur["gaps"] and cur["gaps"][0]["reason"] == "request_cap"
    assert cur["pending"] is not None


def test_unpatched_to_patched_creates_non_backfill_event(conn):
    """The reason this collector exists: GitHub adds a fixed version later."""
    adv = at(UNPATCHED, (NOW - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    gh = FakeGitHub([adv], page_size=100)
    run_collector(conn, gh.collector(), now=NOW)
    assert conn.execute("SELECT count(*) FROM event").fetchone() == (0,)
    assert conn.execute("SELECT alias FROM vuln_alias WHERE cve_id=%s", (adv["cve_id"],)).fetchone() == (adv["ghsa_id"],)

    fixed = at(adv, (NOW + timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ"))
    fixed["vulnerabilities"][0]["first_patched_version"] = "9.9.9"
    fixed["references"] = [*(fixed["references"] or []), "https://github.com/acme/widget/commit/0123456789abcdef"]
    gh.advisories[fixed["ghsa_id"]] = fixed
    later = NOW + timedelta(hours=1)
    stats = run_collector(conn, gh.collector(now=later), now=later)
    assert stats.event_inserted == 1 and stats.raw_new == 1
    row = conn.execute(
        "SELECT type, occurred_at, observed_at, is_backfill, dedupe_key, detail FROM event WHERE cve_id=%s",
        (adv["cve_id"],),
    ).fetchone()
    assert row[:5] == ("patch_released", None, later, False, adv["ghsa_id"])
    assert row[5]["packages"][0]["first_patched_version"] == "9.9.9"
    assert row[5]["fix_commit_urls"] == ["https://github.com/acme/widget/commit/0123456789abcdef"]


def test_stub_vuln_does_not_override_cvelist(conn):
    conn.execute("INSERT INTO vuln (cve_id, title, description, first_seen_at) VALUES (%s, 'CNA title', 'CNA desc', now())",
                 (PATCHED["cve_id"],))
    gh = FakeGitHub([PATCHED], page_size=100)
    run_collector(conn, gh.collector(), now=NOW)
    assert conn.execute("SELECT title, description FROM vuln WHERE cve_id=%s", (PATCHED["cve_id"],)).fetchone() == (
        "CNA title", "CNA desc")


def test_token_header_only_when_configured(conn, monkeypatch, caplog):
    secret = "ghp_testtoken_not_real_000000000000"
    gh = FakeGitHub(SAMPLE, page_size=100)
    monkeypatch.setenv("NDAY_GITHUB_TOKEN", secret)
    c = GhsaCollector(client=httpx.Client(transport=httpx.MockTransport(gh.handler)), clock=lambda: NOW,
                      sleep=lambda s: None)
    with caplog.at_level(logging.DEBUG):
        run_collector(conn, c, now=NOW)
    assert gh.requests[0].headers["authorization"] == f"Bearer {secret}"
    assert secret not in caplog.text
    assert secret not in json.dumps(cursor(conn))
    monkeypatch.delenv("NDAY_GITHUB_TOKEN")
    gh.requests.clear()
    c2 = GhsaCollector(client=httpx.Client(transport=httpx.MockTransport(gh.handler)), clock=lambda: NOW,
                       sleep=lambda s: None)
    c2.fetch(CollectorState(source="ghsa"))
    assert "authorization" not in gh.requests[0].headers


def test_settings_from_env(monkeypatch):
    monkeypatch.setenv("NDAY_GHSA_BOOTSTRAP_DAYS", "3")
    monkeypatch.setenv("NDAY_GHSA_MAX_REQUESTS", "4")
    monkeypatch.setenv("NDAY_GHSA_OVERLAP_MINUTES", "0")
    c = GhsaCollector(client=object())
    assert (c.bootstrap_days, c.max_requests, c.overlap) == (3, 4, timedelta(0))
    monkeypatch.setenv("NDAY_GHSA_BOOTSTRAP_DAYS", "91")
    with pytest.raises(ValueError):
        GhsaCollector(client=object())
    monkeypatch.setenv("NDAY_GHSA_BOOTSTRAP_DAYS", "7")
    monkeypatch.setenv("NDAY_GHSA_MAX_REQUESTS", "0")
    with pytest.raises(ValueError):
        GhsaCollector(client=object())
