"""Whole-dataset normalize parity, Python side (read-only on the given DB):
for the latest raw_record of every cvelist key, sha256 of the canonical JSON
of the Python normalize output (same rendering as tools/dump_golden.py), or
the error. Go side: TestNormalizeAllMatchesPython (CVELIST_NORM_PARITY).

    .venv/bin/python internal/collector/cvelist/testdata/normalize_all_py.py <db url> <out.json>
"""
import dataclasses
import hashlib
import json
import sys
from pathlib import Path

import psycopg

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "tools"))
from dump_golden import _plain  # noqa: E402

from nday.collectors.base import NormalizeError  # noqa: E402
from nday.collectors.cvelist import CveListCollector  # noqa: E402
from nday.models import RawRecord, canonical_json  # noqa: E402

url, out = sys.argv[1:]
c = CveListCollector(client=object())
res = {}
with psycopg.connect(url) as conn:
    conn.read_only = True
    rows = conn.execute("""SELECT DISTINCT ON (source_key) source_key, payload FROM raw_record
                           WHERE source = 'cvelist' ORDER BY source_key, fetched_at DESC, id DESC""").fetchall()
for key, payload in rows:
    try:
        n = c.normalize(RawRecord("cvelist", key, payload))
        res[key] = hashlib.sha256(canonical_json(_plain(dataclasses.asdict(n))).encode()).hexdigest()
    except NormalizeError as e:
        res[key] = f"NormalizeError: {e}"
    except Exception as e:  # noqa: BLE001
        res[key] = f"fatal {type(e).__name__}"
Path(out).write_text(json.dumps(res, indent=0) + "\n")
print(f"python: {len(res)} keys, {sum(1 for v in res.values() if ':' in v or v.startswith('fatal'))} errors")
