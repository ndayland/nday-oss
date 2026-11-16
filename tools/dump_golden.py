"""Dump the PYTHON collectors' fetch()/normalize() output as golden files that
the Go tests compare against (normalize parity).

Run from the repository root with the project's virtualenv:

    .venv/bin/python tools/dump_golden.py            # all collectors in CASES
    .venv/bin/python tools/dump_golden.py kev        # just one

For every collector in CASES it writes
internal/collector/<name>/testdata/golden/<input-stem>.golden.json with:

  {"collector": name, "input": <path>, "kind": "fetch" | "records",
   "cursor": <FetchResult.cursor>                        (kind "fetch" only),
   "records": [{"source_key", "is_backfill", "content_hash",
                "normalized": {...}                      (normalize succeeded)
                | "error": {"type", "message", "fatal"}  (it raised)}]}

kind "fetch":   the collector's own fetch() runs against a mock HTTP transport
                that serves the input file as the body of EVERY GET (good for
                single-file feeds); records/cursor are what fetch() returned.
kind "records": the input is a JSON array of {"source_key", "payload"
                [, "is_backfill"]} objects, each normalized directly (use it
                for hand-written edge cases).

Datetimes are rendered as UTC "YYYY-MM-DDTHH:MM:SS.ffffffZ"; everything else
is the dataclass content (dataclasses.asdict). The file is written with
sort_keys and ensure_ascii=False; Go compares canonical JSON of both sides, so
number types (int vs float) and null-vs-absent must match exactly.

To add a collector: add an entry to CASES (a factory taking an httpx.Client
and the input files), run this script, commit the golden files, and write
the Go test with internal/testutil.CheckGolden (see docs/go.md).
"""

from __future__ import annotations

import dataclasses
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nday.collectors.base import NormalizeError  # noqa: E402
from nday.collectors.cvelist import CveListCollector  # noqa: E402
from nday.collectors.exploitdb import ExploitDbCollector  # noqa: E402
from nday.collectors.metasploit import MetasploitCollector  # noqa: E402
from nday.collectors.nuclei import NucleiCollector  # noqa: E402
from nday.collectors.kev import KevCollector  # noqa: E402
from nday.collectors.ghsa import GhsaCollector  # noqa: E402
from nday.models import CollectorState, RawRecord, content_hash  # noqa: E402

# name -> {"factory": callable(httpx.Client) -> Collector,
#          "fetch": [input files served by a mock transport],
#          "records": [JSON files: list of {"source_key", "payload"[, "is_backfill"]}]}
CASES = {
    "kev": {
        "factory": lambda client: KevCollector(client=client),
        "fetch": [
            "tests/fixtures/kev_sample.json",
            "internal/collector/kev/testdata/feed_edge.json",
        ],
        "records": ["internal/collector/kev/testdata/edge_records.json"],
    },
    "cvelist": {
        "factory": lambda client: CveListCollector(client=client),
        "records": [
            "internal/collector/cvelist/testdata/fixture_records.json",
            "internal/collector/cvelist/testdata/edge_records.json",
        ],
    },
    "exploitdb": {
        "factory": lambda client: ExploitDbCollector(client=client),
        "fetch": [
            "tests/fixtures/exploitdb/files_exploits.csv",
            "internal/collector/exploitdb/testdata/feed_edge.csv",
        ],
        "records": ["internal/collector/exploitdb/testdata/edge_records.json"],
    },
    "metasploit": {
        "factory": lambda client: MetasploitCollector(client=client),
        "fetch": [
            "tests/fixtures/metasploit/modules_metadata_base.json",
            "internal/collector/metasploit/testdata/feed_edge.json",
        ],
        "records": ["internal/collector/metasploit/testdata/edge_records.json"],
    },
    "nuclei": {
        "factory": lambda client: NucleiCollector(client=client),
        "fetch": [
            "tests/fixtures/nuclei/cves.json",
            "internal/collector/nuclei/testdata/feed_edge.jsonl",
        ],
        "records": ["internal/collector/nuclei/testdata/edge_records.json"],
    },
    "ghsa": {
        # records, not fetch: fetch's cursor is clock-dependent (fetch parity is
        # checked separately); sample_records.json = one record per advisory of
        # tests/fixtures/ghsa/advisories_sample.json, verbatim.
        "factory": lambda client: GhsaCollector(client=client, token=""),
        "records": [
            "internal/collector/ghsa/testdata/sample_records.json",
            "internal/collector/ghsa/testdata/edge_records.json",
        ],
    },
}


def _plain(value):
    if isinstance(value, datetime):
        return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def _normalize(collector, rec: RawRecord) -> dict:
    out = {"source_key": rec.source_key, "is_backfill": rec.is_backfill,
           "content_hash": content_hash(rec.payload)}
    try:
        norm = collector.normalize(rec)
    except Exception as exc:  # noqa: BLE001 - recorded, Go must fail the same way
        out["error"] = {"type": type(exc).__name__, "message": str(exc),
                        "fatal": not isinstance(exc, NormalizeError)}
        return out
    out["normalized"] = _plain(dataclasses.asdict(norm))
    return out


def _mock_client(body: bytes) -> httpx.Client:
    return httpx.Client(transport=httpx.MockTransport(lambda req: httpx.Response(200, content=body)))


def dump(name: str, case: dict) -> list[Path]:
    outdir = ROOT / "internal" / "collector" / name / "testdata" / "golden"
    outdir.mkdir(parents=True, exist_ok=True)
    written = []
    for rel in case.get("fetch", []):
        body = (ROOT / rel).read_bytes()
        collector = case["factory"](_mock_client(body))
        result = collector.fetch(CollectorState(source=name))
        doc = {"collector": name, "input": rel, "kind": "fetch", "cursor": _plain(result.cursor),
               "records": [_normalize(collector, r) for r in result.records]}
        written.append(_write(outdir, rel, doc))
    for rel in case.get("records", []):
        items = json.loads((ROOT / rel).read_text(encoding="utf-8"))
        collector = case["factory"](_mock_client(b""))
        recs = [RawRecord(name, it["source_key"], it["payload"], it.get("is_backfill", False))
                for it in items]
        doc = {"collector": name, "input": rel, "kind": "records",
               "records": [_normalize(collector, r) for r in recs]}
        written.append(_write(outdir, rel, doc))
    return written


def _write(outdir: Path, rel: str, doc: dict) -> Path:
    path = outdir / (Path(rel).stem + ".golden.json")
    path.write_text(json.dumps(doc, sort_keys=True, ensure_ascii=False, indent=1) + "\n",
                    encoding="utf-8")
    return path


def main(argv: list[str]) -> int:
    names = argv or sorted(CASES)
    for n in names:
        if n not in CASES:
            print(f"unknown collector {n!r}; known: {sorted(CASES)}", file=sys.stderr)
            return 2
        for p in dump(n, CASES[n]):
            print(f"wrote {p.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
