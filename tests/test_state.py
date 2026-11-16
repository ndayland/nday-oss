from datetime import UTC, datetime, timedelta

from nday import state

NOW = datetime.now(UTC)


def d(days_ago: float) -> datetime:
    return NOW - timedelta(days=days_ago)


def vuln(conn, cve, title="t"):
    conn.execute("INSERT INTO vuln (cve_id, title) VALUES (%s, %s)", (cve, title))


def ev(conn, cve, typ, occ=None, obs=None, backfill=False, source="x", detail="{}", key=""):
    conn.execute(
        """INSERT INTO event (cve_id, type, occurred_at, observed_at, is_backfill, source,
                              detail, dedupe_key)
           VALUES (%s,%s,%s,%s,%s,%s,%s::jsonb,%s)""",
        (cve, typ, occ, obs or NOW, backfill, source, detail, key),
    )


def row(conn, cve):
    cur = conn.execute("SELECT * FROM vuln_state WHERE cve_id = %s", (cve,))
    cols = [c.name for c in cur.description]
    r = cur.fetchone()
    return dict(zip(cols, r)) if r else None


def test_stage_ranking(conn):
    types = ["disclosed", "patch_released", "analysis_published",
             "poc_published", "exploited_in_wild", "kev_added"]
    for i, t in enumerate(types, 1):
        cve = f"CVE-2024-{1000 + i}"
        vuln(conn, cve)
        ev(conn, cve, t, occ=d(5))
        r = row(conn, cve)
        assert (r["stage"], r["stage_rank"]) == (t, i)
    # highest rank wins regardless of time order
    vuln(conn, "CVE-2024-2000")
    ev(conn, "CVE-2024-2000", "poc_published", occ=d(1))
    ev(conn, "CVE-2024-2000", "patch_released", occ=d(9))
    r = row(conn, "CVE-2024-2000")
    assert r["stage"] == "poc_published" and r["has_poc"] and r["has_patch"]
    assert not r["has_analysis"] and not r["exploited"] and not r["in_kev"]
    assert r["event_count"] == 2


def test_effective_at_rule(conn):
    for c in ("CVE-2024-3001", "CVE-2024-3002", "CVE-2024-3003"):
        vuln(conn, c)
    ev(conn, "CVE-2024-3001", "disclosed", occ=d(10), obs=d(1), backfill=True)
    ev(conn, "CVE-2024-3002", "disclosed", occ=None, obs=d(2), backfill=False)
    ev(conn, "CVE-2024-3003", "disclosed", occ=None, obs=d(3), backfill=True)
    assert row(conn, "CVE-2024-3001")["disclosed_at"] == d(10)
    assert row(conn, "CVE-2024-3002")["disclosed_at"] == d(2)
    r = row(conn, "CVE-2024-3003")
    assert r["disclosed_at"] is None and r["last_transition_at"] is None
    assert r["stage"] == "disclosed"  # stage still known even if time unknown


def test_exploited_via_kev_only(conn):
    vuln(conn, "CVE-2024-4001")
    ev(conn, "CVE-2024-4001", "kev_added", occ=d(2), source="kev")
    r = row(conn, "CVE-2024-4001")
    assert r["exploited"] and r["in_kev"] and r["stage"] == "kev_added"
    assert r["exploited_at"] == r["kev_at"] == d(2)


def test_is_rejected_uses_latest_cvelist_event(conn):
    vuln(conn, "CVE-2024-5001")
    vuln(conn, "CVE-2024-5002")
    vuln(conn, "CVE-2024-5003")
    ev(conn, "CVE-2024-5001", "disclosed", occ=d(3), source="cvelist",
       detail='{"state":"REJECTED"}')
    ev(conn, "CVE-2024-5002", "disclosed", occ=d(5), source="cvelist",
       detail='{"state":"REJECTED"}', key="a")
    ev(conn, "CVE-2024-5002", "disclosed", occ=d(1), source="cvelist",
       detail='{"state":"PUBLISHED"}', key="b")
    ev(conn, "CVE-2024-5003", "disclosed", occ=d(3), source="other")
    assert row(conn, "CVE-2024-5001")["is_rejected"] is True
    assert row(conn, "CVE-2024-5002")["is_rejected"] is False
    assert row(conn, "CVE-2024-5003")["is_rejected"] is False


def test_last_transition_ignores_repeat_same_type(conn):
    vuln(conn, "CVE-2024-6001")
    ev(conn, "CVE-2024-6001", "disclosed", occ=d(10))
    ev(conn, "CVE-2024-6001", "poc_published", occ=d(5), source="a")
    ev(conn, "CVE-2024-6001", "poc_published", occ=d(1), source="b")  # second PoC
    r = row(conn, "CVE-2024-6001")
    assert r["last_transition_type"] == "poc_published"
    assert r["last_transition_at"] == d(5)
    assert r["poc_at"] == d(5)


def test_last_transition_tie_breaks_by_rank(conn):
    vuln(conn, "CVE-2024-7001")
    t = d(2)
    ev(conn, "CVE-2024-7001", "poc_published", occ=t)
    ev(conn, "CVE-2024-7001", "patch_released", occ=t)
    ev(conn, "CVE-2024-7001", "analysis_published", occ=t)
    r = row(conn, "CVE-2024-7001")
    assert r["last_transition_at"] == t
    assert r["last_transition_type"] == "poc_published"


def test_days_between(conn):
    for c in ("CVE-2024-8001", "CVE-2024-8002", "CVE-2024-8003", "CVE-2024-8004"):
        vuln(conn, c)
    base = datetime(2024, 1, 10, tzinfo=UTC)
    ev(conn, "CVE-2024-8001", "disclosed", occ=base)
    ev(conn, "CVE-2024-8001", "exploited_in_wild", occ=base + timedelta(days=3))
    ev(conn, "CVE-2024-8001", "poc_published", occ=base + timedelta(days=1, hours=12))
    ev(conn, "CVE-2024-8002", "disclosed", occ=base)
    ev(conn, "CVE-2024-8002", "kev_added", occ=base - timedelta(days=4))  # negative
    ev(conn, "CVE-2024-8003", "disclosed", occ=None, obs=base, backfill=True)  # unknown
    ev(conn, "CVE-2024-8003", "kev_added", occ=base)
    ev(conn, "CVE-2024-8004", "disclosed", occ=base)  # no exploit/poc
    r = row(conn, "CVE-2024-8001")
    assert float(r["days_disclosed_to_exploited"]) == 3.0
    assert float(r["days_disclosed_to_poc"]) == 1.5
    assert float(row(conn, "CVE-2024-8002")["days_disclosed_to_exploited"]) == -4.0
    r = row(conn, "CVE-2024-8003")
    assert r["days_disclosed_to_exploited"] is None
    r = row(conn, "CVE-2024-8004")
    assert r["days_disclosed_to_exploited"] is None and r["days_disclosed_to_poc"] is None


def test_vuln_without_events_absent(conn):
    vuln(conn, "CVE-2024-9001")
    assert row(conn, "CVE-2024-9001") is None


def test_hot_window_order_and_rejected(conn):
    vuln(conn, "CVE-2024-1101", "old")
    ev(conn, "CVE-2024-1101", "disclosed", occ=d(30))
    vuln(conn, "CVE-2024-1102", "mid")
    ev(conn, "CVE-2024-1102", "disclosed", occ=d(3))
    vuln(conn, "CVE-2024-1103", "new")
    ev(conn, "CVE-2024-1103", "disclosed", occ=d(5))
    ev(conn, "CVE-2024-1103", "kev_added", occ=d(1))
    vuln(conn, "CVE-2024-1104", "rejected")
    ev(conn, "CVE-2024-1104", "disclosed", occ=d(0.5), source="cvelist",
       detail='{"state":"REJECTED"}')
    vuln(conn, "CVE-2024-1105", "unknown time")
    ev(conn, "CVE-2024-1105", "disclosed", occ=None, obs=d(1), backfill=True)

    ids = [r["cve_id"] for r in state.hot(conn, timedelta(days=7), 10)]
    assert ids == ["CVE-2024-1103", "CVE-2024-1102"]
    ids = [r["cve_id"] for r in state.hot(conn, timedelta(days=7), 10, include_rejected=True)]
    assert ids == ["CVE-2024-1104", "CVE-2024-1103", "CVE-2024-1102"]
    assert [r["cve_id"] for r in state.hot(conn, timedelta(days=7), 1)] == ["CVE-2024-1103"]
    top = state.hot(conn, timedelta(days=7), 10)[0]
    assert top["title"] == "new" and top["last_transition_type"] == "kev_added"
    # min_stage filters on the transition type, hiding plain disclosures.
    ids = [r["cve_id"] for r in state.hot(conn, timedelta(days=7), 10, min_stage="patch_released")]
    assert ids == ["CVE-2024-1103"]
    assert state.hot(conn, timedelta(days=7), 10, min_stage="kev_added")[0]["cve_id"] == "CVE-2024-1103"


def test_stage_counts(conn):
    vuln(conn, "CVE-2024-1201")
    vuln(conn, "CVE-2024-1202")
    ev(conn, "CVE-2024-1201", "disclosed", occ=d(1))
    ev(conn, "CVE-2024-1202", "disclosed", occ=d(1))
    ev(conn, "CVE-2024-1202", "kev_added", occ=d(1))
    assert state.stage_counts(conn) == [("disclosed", 1), ("kev_added", 1)]
