"""Fetch-logic parity harness, Python side. Runs the PYTHON cvelist fetch()
against recorded upstream files (no network) and writes what it did:

    .venv/bin/python internal/collector/cvelist/testdata/replay_py.py <scenario.json> <out.json>

scenario.json: {"data_dir", "clock" (ISO), "cursor" (object|null), "wanted" [ids],
                "bootstrap_days", "max_files", "backfill_retry_days", "concurrency",
                "fail": {url: [status, ...]}}       (statuses served first, then the file)
URL -> file: deltaLog.json -> <data_dir>/deltaLog.json; record -> <data_dir>/records/<id>.json;
end-of-day zip -> <data_dir>/zips/<YYYY-MM-DD>.zip; anything else / absent file -> 404.
out.json: {"urls": [requested URLs in order], "records": [[key, is_backfill, content_hash]],
           "cursor": {...}, "error": null|str, "missing_files": [urls answered 404]}
The Go side is replay_test.go (same scenario, compares against out.json).
"""
import json
import re
import sys
import threading
from datetime import datetime
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))
import nday.collectors.cvelist as cv  # noqa: E402
from nday.models import CollectorState, content_hash  # noqa: E402

ZIP_RE = re.compile(r"/cve_(\d{4}-\d{2}-\d{2})_at_end_of_day/")


def local_path(data: Path, url: str) -> Path | None:
    if url == cv.DELTA_LOG_URL:
        return data / "deltaLog.json"
    m = ZIP_RE.search(url)
    if m and url.startswith(cv.RELEASE_BASE):
        return data / "zips" / f"{m.group(1)}.zip"
    if url.startswith(cv.RAW_BASE + "/") and url.endswith(".json"):
        return data / "records" / url.rsplit("/", 1)[1]
    return None


def main(scenario_path: str, out_path: str) -> None:
    sc = json.loads(Path(scenario_path).read_text())
    data = Path(sc["data_dir"])
    fail = {k: list(v) for k, v in (sc.get("fail") or {}).items()}
    urls, missing = [], []
    lock = threading.Lock()

    def handler(req: httpx.Request) -> httpx.Response:
        url = str(req.url)
        with lock:
            urls.append(url)
            if fail.get(url):
                return httpx.Response(fail[url].pop(0))
        p = local_path(data, url)
        if p is None or not p.exists():
            with lock:
                missing.append(url)
            return httpx.Response(404)
        return httpx.Response(200, content=p.read_bytes())

    cv.CONCURRENCY = sc.get("concurrency", cv.CONCURRENCY)
    clock = datetime.fromisoformat(sc["clock"])
    c = cv.CveListCollector(
        client=httpx.Client(transport=httpx.MockTransport(handler)),
        bootstrap_days=sc["bootstrap_days"], max_files=sc["max_files"],
        backfill_retry_days=sc["backfill_retry_days"], clock=lambda: clock, sleep=lambda s: None)
    out = {"urls": urls, "missing_files": missing, "error": None, "records": [], "cursor": None}
    try:
        res = c.fetch(CollectorState(source="cvelist", cursor=sc.get("cursor"),
                                     wanted=tuple(sc.get("wanted") or ())))
        out["records"] = [[r.source_key, r.is_backfill, content_hash(r.payload)] for r in res.records]
        out["cursor"] = res.cursor
    except Exception as exc:  # noqa: BLE001
        out["error"] = f"{type(exc).__name__}: {exc}"
    Path(out_path).write_text(json.dumps(out, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"python: {len(urls)} requests ({len(missing)} 404), {len(out['records'])} records, error={out['error']}")


if __name__ == "__main__":
    main(*sys.argv[1:])
