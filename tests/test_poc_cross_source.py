from datetime import UTC, datetime

from nday.pipeline import run_collector
from poc_feed_helpers import ADAPTERS, FeedServer, collector

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)
CVE = "CVE-2026-9198"  # real: EDB 52675, MSF langflow_unauth_rce_cve_2026_9198, nuclei template


def test_same_cve_from_three_sources(conn):
    for name in ("exploitdb", "metasploit", "nuclei"):
        a = ADAPTERS[name]
        run_collector(conn, collector(a, FeedServer(a.url, a.dump(a.load()))), now=T0)

    rows = conn.execute(
        "SELECT source, dedupe_key, occurred_at, detail->>'kind' FROM event "
        "WHERE cve_id = %s AND type = 'poc_published' ORDER BY source", (CVE,)
    ).fetchall()
    assert rows == [
        ("exploitdb", "52675", datetime(2026, 9, 2, tzinfo=UTC), "exploit"),
        ("metasploit", "exploit/multi/http/langflow_unauth_rce_cve_2026_9198", None, "msf_module"),
        ("nuclei", CVE, None, "detection_template"),
    ]
    # stub vuln created by the pipeline, no title from exploit metadata
    assert conn.execute("SELECT title FROM vuln WHERE cve_id = %s", (CVE,)).fetchone() == (None,)
    st = conn.execute(
        "SELECT has_poc, stage, poc_at, event_count FROM vuln_state WHERE cve_id = %s", (CVE,)
    ).fetchone()
    # poc_at = earliest known time: EDB's day (MSF/nuclei are backfill + unknown)
    assert st == (True, "poc_published", datetime(2026, 9, 2, tzinfo=UTC), 3)
