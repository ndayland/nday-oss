from datetime import UTC, datetime, timedelta

import pytest

from conftest import make_kev_collector
from nday import USER_AGENT
from nday.collectors.base import NormalizeError
from nday.collectors.kev import KEV_CATALOG_URL, KevCollector
from nday.models import Affected, RawRecord, VulnUpsert, is_valid_cve_id
from nday.pipeline import merge_vuln, run_collector

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
T1 = T0 + timedelta(days=1)

COUNT_SQL = """SELECT (SELECT count(*) FROM raw_record), (SELECT count(*) FROM vuln),
                      (SELECT count(*) FROM vuln_alias), (SELECT count(*) FROM affected),
                      (SELECT count(*) FROM event)"""


def _entry(feed, cve):
    return next(e for e in feed["vulnerabilities"] if e["cveID"] == cve)


# ----------------------------------------------------------------- pure normalize


def test_cve_id_validation():
    assert is_valid_cve_id("CVE-2026-124194")
    assert is_valid_cve_id("CVE-2021-43890")
    assert not is_valid_cve_id("CVE-2021-123")
    assert not is_valid_cve_id("cve-2021-43890")


def test_kev_normalize_output(kev_feed):
    e = _entry(kev_feed, "CVE-2026-102895")
    norm = KevCollector(client=object()).normalize(RawRecord("kev", e["cveID"], e))

    assert norm.vulns == [
        VulnUpsert(
            cve_id="CVE-2026-102895",
            title=e["vulnerabilityName"],
            description=e["shortDescription"],
            authoritative=False,
        )
    ]
    assert norm.affected == [Affected("CVE-2026-102895", e["vendorProject"], e["product"])]
    assert norm.aliases == []
    assert len(norm.events) == 1
    ev = norm.events[0]
    assert ev.type == "kev_added"  # never exploited_in_wild
    assert ev.source == "kev"
    assert ev.url == KEV_CATALOG_URL
    assert ev.occurred_at == datetime(2026, 11, 9, tzinfo=UTC)
    assert ev.detail["precision"] == "day"
    assert ev.detail["known_ransomware_campaign_use"] == e["knownRansomwareCampaignUse"]
    assert ev.detail["required_action"] == e["requiredAction"]
    assert ev.detail["due_date"] == e["dueDate"]
    assert ev.detail["notes"] == e["notes"]
    assert ev.detail["cwes"] == ["CWE-287", "CWE-290", "CWE-346"]
    assert ev.detail["forensic_triage"] == e["forensicTriage"]


def test_kev_normalize_never_fabricates_occurred_at(kev_feed):
    e = dict(_entry(kev_feed, "CVE-2021-43890"), dateAdded="")
    ev = KevCollector(client=object()).normalize(RawRecord("kev", e["cveID"], e)).events[0]
    assert ev.occurred_at is None
    assert "precision" not in ev.detail


def test_kev_normalize_rejects_bad_cve(kev_feed):
    e = dict(_entry(kev_feed, "CVE-2021-43890"), cveID="CVE-21-1")
    with pytest.raises(NormalizeError):
        KevCollector(client=object()).normalize(RawRecord("kev", "CVE-21-1", e))


def test_merge_vuln_stub_vs_authoritative():
    existing = {"title": "Real title", "description": None, "published_at": None, "modified_at": None}
    stub = VulnUpsert("CVE-2024-1234", title="KEV title", description="KEV desc")
    assert merge_vuln(existing, stub) == {**existing, "description": "KEV desc"}
    auth = VulnUpsert("CVE-2024-1234", title="CVE title", authoritative=True)
    assert merge_vuln(existing, auth)["title"] == "CVE title"


# ----------------------------------------------------------------- pipeline + DB


def test_first_run_inserts_and_sends_generic_user_agent(conn, kev_feed):
    headers = []
    stats = run_collector(conn, make_kev_collector(kev_feed, headers), now=T0)
    n = len(kev_feed["vulnerabilities"])
    assert (stats.raw_new, stats.vuln_inserted, stats.affected_inserted, stats.event_inserted) == (n, n, n, n)
    assert conn.execute(COUNT_SQL).fetchone() == (n, n, 0, n, n)
    assert headers[0]["user-agent"] == USER_AGENT

    row = conn.execute(
        """SELECT v.title, v.first_seen_at, e.occurred_at, e.observed_at, e.detail->>'precision'
           FROM vuln v JOIN event e USING (cve_id) WHERE cve_id = 'CVE-2021-43890'"""
    ).fetchone()
    e = _entry(kev_feed, "CVE-2021-43890")
    assert row == (e["vulnerabilityName"], T0, datetime(2021, 12, 15, tzinfo=UTC), T0, "day")
    assert conn.execute("SELECT count(*) FROM event WHERE type <> 'kev_added'").fetchone() == (0,)

    state = conn.execute(
        "SELECT last_status, last_success_at, cursor->>'catalogVersion' FROM collector_state"
    ).fetchone()
    assert state == ("ok", T0, kev_feed["catalogVersion"])


def test_second_run_is_idempotent(conn, kev_feed):
    run_collector(conn, make_kev_collector(kev_feed), now=T0)
    before = conn.execute(COUNT_SQL).fetchone()
    snapshot = conn.execute(
        "SELECT cve_id, updated_at, observed_at, is_backfill FROM vuln JOIN event USING (cve_id) ORDER BY 1"
    ).fetchall()

    stats = run_collector(conn, make_kev_collector(kev_feed), now=T1)

    assert conn.execute(COUNT_SQL).fetchone() == before
    assert stats.raw_unchanged == len(kev_feed["vulnerabilities"])
    assert (stats.raw_new, stats.vuln_inserted, stats.vuln_updated, stats.event_inserted,
            stats.event_updated, stats.affected_inserted) == (0, 0, 0, 0, 0, 0)
    assert conn.execute(
        "SELECT cve_id, updated_at, observed_at, is_backfill FROM vuln JOIN event USING (cve_id) ORDER BY 1"
    ).fetchall() == snapshot

    # --renormalize on unchanged data must not add rows either.
    run_collector(conn, make_kev_collector(kev_feed), renormalize=True, now=T1)
    assert conn.execute(COUNT_SQL).fetchone() == before


def test_backfill_flag_first_vs_later_run(conn, kev_feed):
    newest = kev_feed["vulnerabilities"][-1]
    older = dict(kev_feed, vulnerabilities=kev_feed["vulnerabilities"][:-1])

    s1 = run_collector(conn, make_kev_collector(older), now=T0)
    assert s1.is_backfill is True
    s2 = run_collector(conn, make_kev_collector(kev_feed), now=T1)
    assert s2.is_backfill is False
    assert s2.event_inserted == 1

    rows = dict(conn.execute("SELECT cve_id, is_backfill FROM event").fetchall())
    assert rows.pop(newest["cveID"]) is False
    assert rows and all(rows.values())
    assert conn.execute(
        "SELECT observed_at FROM event WHERE cve_id = %s", (newest["cveID"],)
    ).fetchone() == (T1,)


def test_failed_first_run_keeps_backfill_for_next_run(conn, kev_feed):
    import httpx

    def boom(request):
        return httpx.Response(503)

    with pytest.raises(httpx.HTTPStatusError):
        run_collector(conn, KevCollector(client=httpx.Client(transport=httpx.MockTransport(boom))), now=T0)
    assert conn.execute("SELECT last_status, last_success_at FROM collector_state").fetchone() == ("error", None)

    stats = run_collector(conn, make_kev_collector(kev_feed), now=T1)
    assert stats.is_backfill is True


def test_stub_does_not_overwrite_existing_title(conn, kev_feed):
    cve = "CVE-2026-59310"
    conn.execute(
        "INSERT INTO vuln (cve_id, title, description) VALUES (%s, 'Existing title', '')", (cve,)
    )
    stats = run_collector(conn, make_kev_collector(kev_feed), now=T0)

    title, desc, first_seen = conn.execute(
        "SELECT title, description, first_seen_at FROM vuln WHERE cve_id = %s", (cve,)
    ).fetchone()
    assert title == "Existing title"
    # empty description is filled from KEV
    assert desc == _entry(kev_feed, cve)["shortDescription"]
    assert first_seen != T0  # pre-existing row keeps its first_seen_at
    assert stats.vuln_updated == 1
    assert stats.vuln_inserted == len(kev_feed["vulnerabilities"]) - 1


def test_changed_upstream_entry_updates_event_detail_without_new_event(conn, kev_feed):
    run_collector(conn, make_kev_collector(kev_feed), now=T0)
    changed = dict(kev_feed, vulnerabilities=[dict(e) for e in kev_feed["vulnerabilities"]])
    changed["vulnerabilities"][0]["dueDate"] = "2099-01-01"

    stats = run_collector(conn, make_kev_collector(changed), now=T1)

    assert (stats.raw_new, stats.event_inserted, stats.event_updated) == (1, 0, 1)
    cve = changed["vulnerabilities"][0]["cveID"]
    due, observed, backfill = conn.execute(
        "SELECT detail->>'due_date', observed_at, is_backfill FROM event WHERE cve_id = %s", (cve,)
    ).fetchone()
    assert (due, observed, backfill) == ("2099-01-01", T0, True)
    assert conn.execute(
        "SELECT count(*) FROM raw_record WHERE source_key = %s", (cve,)
    ).fetchone() == (2,)
