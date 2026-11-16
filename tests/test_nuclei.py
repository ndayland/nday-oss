import json
from datetime import UTC, datetime

import pytest

from nday.collectors.base import NormalizeError
from nday.collectors.nuclei import NucleiCollector
from nday.models import RawRecord
from nday.pipeline import run_collector
from poc_feed_helpers import FeedServer, NucleiFeed, collector

T0 = datetime(2026, 11, 1, 12, 0, tzinfo=UTC)


def _obj(tid):
    return next(o for o in NucleiFeed.load() if o["ID"] == tid)


def _norm(p, key=None):
    return NucleiCollector(client=object()).normalize(RawRecord("nuclei", key or p["ID"], p))


def test_normalize_typical_template_occurred_at_none():
    p = _obj("CVE-2021-44228")
    norm = _norm(p)
    assert norm.vulns == [] and norm.aliases == [] and norm.affected == []
    (ev,) = norm.events
    assert (ev.cve_id, ev.type, ev.source, ev.dedupe_key) == (
        "CVE-2021-44228", "poc_published", "nuclei", "CVE-2021-44228")
    assert ev.occurred_at is None  # the index has no timestamps at all
    assert ev.url == ("https://github.com/projectdiscovery/nuclei-templates/blob/main/"
                      + p["file_path"])
    d = ev.detail
    assert (d["kind"], d["confidence"], d["url"]) == ("detection_template", "curated", ev.url)
    assert (d["title"], d["severity"], d["template_path"]) == (
        p["Info"]["Name"], "critical", p["file_path"])
    assert d["cvss_score"] == p["Info"]["Classification"]["CVSSScore"]


def test_one_cve_per_template():
    # The CVE index has exactly one ID per template, so there is no multi-CVE case.
    assert len(_norm(_obj("CVE-2026-9198")).events) == 1


def test_lowercase_id_normalised():
    p = dict(_obj("CVE-2026-9198"), ID="cve-2026-9198")
    assert _norm(p).events[0].cve_id == "CVE-2026-9198"


def test_invalid_or_malformed_template_is_normalize_error():
    p = _obj("CVE-2026-9198")
    with pytest.raises(NormalizeError):
        _norm(dict(p, ID="CVE-2026-91"))
    with pytest.raises(NormalizeError):
        _norm({k: v for k, v in p.items() if k != "file_path"})
    with pytest.raises(NormalizeError):
        _norm(p, key="CVE-2000-0114")


def test_run_skips_non_cve_template_and_counts_it(conn):
    objs = NucleiFeed.load()
    extra = dict(objs[0], ID="tech-detect-thing", file_path="http/technologies/x.yaml")
    server = FeedServer(NucleiFeed.url, NucleiFeed.dump([*objs, extra]))
    s = run_collector(conn, collector(NucleiFeed, server), now=T0)
    assert (s.fetched, s.raw_new, s.normalize_errors, s.event_inserted) == (4, 4, 0, 4)
    assert conn.execute(
        "SELECT count(*) FROM raw_record WHERE source_key = 'tech-detect-thing'").fetchone() == (0,)
    lr = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]["last_run"]
    assert (lr["lines"], lr["items_with_cve"], lr["items_without_cve"]) == (5, 4, 1)


def test_nul_character_is_stored_as_literal_escape(conn):
    # live: CVE-2021-32030's Description contains "\u0000" (PostgreSQL rejects NUL)
    objs = NucleiFeed.load()
    objs[0]["Info"]["Description"] = "value of '\x00' bypasses auth"
    server = FeedServer(NucleiFeed.url, NucleiFeed.dump(objs))
    s = run_collector(conn, collector(NucleiFeed, server), now=T0)
    assert s.raw_new == 4
    desc = conn.execute(
        "SELECT payload->'Info'->>'Description' FROM raw_record WHERE source_key = %s",
        (objs[0]["ID"],)).fetchone()[0]
    assert desc == "value of '\\u0000' bypasses auth"
    lr = conn.execute("SELECT cursor FROM collector_state").fetchone()[0]["last_run"]
    assert lr["items_nul_scrubbed"] == [objs[0]["ID"]]


def test_broken_line_fails_the_feed():
    with pytest.raises(json.JSONDecodeError):
        NucleiCollector(client=object()).parse_items(b'{"ID":"CVE-2020-1234"\n')
