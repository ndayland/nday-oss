from datetime import UTC, datetime

import pytest

from nday.collectors.base import NormalizeError
from nday.collectors.metasploit import MetasploitCollector
from nday.models import RawRecord
from nday.pipeline import run_collector
from poc_feed_helpers import FeedServer, MsfFeed, collector

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def _mod(fullname):
    return next(v for v in MsfFeed.load().values() if v["fullname"] == fullname)


def _norm(p):
    return MetasploitCollector(client=object()).normalize(RawRecord("metasploit", p["fullname"], p))


def test_normalize_typical_module_occurred_at_none():
    p = _mod("exploit/multi/http/langflow_unauth_rce_cve_2026_9198")
    norm = _norm(p)
    assert norm.vulns == [] and norm.aliases == [] and norm.affected == []
    (ev,) = norm.events
    assert (ev.cve_id, ev.type, ev.source, ev.dedupe_key) == (
        "CVE-2026-9198", "poc_published", "metasploit", p["fullname"])
    # disclosure_date is the vuln's, mod_time is last modification: neither qualifies
    assert ev.occurred_at is None
    assert ev.url == ("https://github.com/rapid7/metasploit-framework/blob/master/"
                      "modules/exploits/multi/http/langflow_unauth_rce_cve_2026_9198.rb")
    d = ev.detail
    assert (d["kind"], d["confidence"], d["url"], d["title"]) == (
        "msf_module", "curated", ev.url, p["name"])
    assert (d["fullname"], d["module_type"], d["rank"], d["rank_name"]) == (
        p["fullname"], "exploit", 600, "excellent")
    assert d["vuln_disclosure_date"] == "2026-07-17"
    assert d["module_last_modified"] == "2026-08-21 14:02:04 +0000"
    assert d["path"] == p["path"]
    assert "precision" not in d and "disclosure_date" not in d and "mod_time" not in d


def test_multi_cve_module():
    evs = _norm(_mod("exploit/android/browser/webview_addjavascriptinterface")).events
    assert [e.cve_id for e in evs] == ["CVE-2012-6636", "CVE-2013-4710"]
    assert all(e.occurred_at is None for e in evs)


def test_trailing_space_reference_is_stripped():
    (ev,) = _norm(_mod("exploit/multi/http/uptime_file_upload_2")).events
    assert ev.cve_id == "CVE-2015-9263" and "dropped_cve_tokens" not in ev.detail


def test_invalid_cve_refs():
    p = _mod("auxiliary/admin/2wire/xslt_password_reset")
    mixed = dict(p, references=[*p["references"], "CVE-2007-43", "cve-2008-0001"])
    (a, b) = _norm(mixed).events
    assert (a.cve_id, b.cve_id) == ("CVE-2007-4387", "CVE-2008-0001")
    assert a.detail["dropped_cve_tokens"] == ["CVE-2007-43"]
    with pytest.raises(NormalizeError):
        _norm(dict(p, references=["CVE-n/a", "URL-https://x"]))
    with pytest.raises(NormalizeError):
        _norm(dict(p, references="CVE-2007-4387"))


def test_out_of_scope_type_rejected_by_normalize():
    with pytest.raises(NormalizeError):
        _norm(_mod("post/android/local/koffee"))


def test_parse_scope_and_counts():
    items, extra = MetasploitCollector(client=object()).parse_items(MsfFeed.dump(MsfFeed.load()))
    keys = [k for k, _ in items]
    assert "post/android/local/koffee" not in keys
    assert not any(k.startswith("payload/") for k in keys)
    assert extra == {"modules": 8, "out_of_scope_types": 2, "malformed_skipped": 0}


def test_run_skips_no_cve_and_out_of_scope(conn):
    server = FeedServer(MsfFeed.url, MsfFeed.dump(MsfFeed.load()))
    s = run_collector(conn, collector(MsfFeed, server), now=T0)
    assert (s.fetched, s.raw_new, s.normalize_errors, s.event_inserted) == (5, 5, 0, 6)
    keys = {k for (k,) in conn.execute("SELECT source_key FROM raw_record")}
    assert "exploit/android/adb/adb_server_exec" not in keys  # no CVE
    assert "post/android/local/koffee" not in keys  # out of scope
    cursor = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]
    lr = cursor["last_run"]
    assert (lr["items_in_scope"], lr["items_with_cve"], lr["items_without_cve"]) == (6, 5, 1)
    assert conn.execute(
        "SELECT count(*) FROM event WHERE occurred_at IS NOT NULL").fetchone() == (0,)
