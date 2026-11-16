"""Dump PYTHON reference results for the primitives the Go port must match
exactly (canonical JSON / content hash, float repr, str.strip / isspace,
repr(), date.fromisoformat). Output: internal/pyjson/testdata/pyref.json,
consumed by internal/pyjson and internal/collector tests.

    .venv/bin/python tools/dump_pyref.py

Deterministic (fixed random seed), no network, no database.
"""

from __future__ import annotations

import json
import random
import struct
import sys
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from nday.models import canonical_json, content_hash  # noqa: E402

JSON_TEXTS = [
    '{"b":1,"a":2}', '{"a":1,"a":2,"b":{"a":3,"a":4}}', '[1.0, 0.0, -0.0, 6.30, 8.1, 100, -0, 1e2, 1E2, 1e-5, 1.5e-7]',
    '[1e16, 1e15, 123456789012345678, 123456789012345678.0, 9007199254740993, 9007199254740993.0]',
    '[1e400, -1e400, 1e-400, NaN, Infinity, -Infinity, 5e-324, 2.2250738585072014e-308, 1.7976931348623157e308]',
    '[0.1, 0.2, 0.30000000000000004, 1.1, 2.675, 1e22, 1e21, 1e-4, 1e-5, 0.000123, 12345.6789e-3]',
    '"\\u00e9\\u2028\\u2029\\u007f\\u0001\\u001f\\b\\f\\n\\r\\t\\"\\\\\\/<>&\'"',
    '"\\ud83d\\ude00 \\uD83D\\uDE00 café 中文 \U0001F600"',
    '{"é":1,"e":2,"E":3,"É":4,"\U0001F600":5,"￿":6,"":7,"a\\u0000b":8}',
    '{"nested":{"z":[{"y":null,"x":true}],"a":false},"arr":[[],{},[[]]]}',
    ' \t\n\r[1, 2 ]\r\n', '﻿{"bom":true}',
    '[1.]', '[01]', '[1e]', '[-]', '[.5]', '[+1]', '{"a" 1}', '{a:1}', '[1,]', "['x']",
    '"tab\there"', '"\\x41"', '[true false]', '[tru]', '[nan]', '[-Infinity, -NaN]', '1 2', '',
    '"\\ud800"', '"\\udc00x"', '[' + '9' * 4300 + ']', '[' + '9' * 4301 + ']',
    '{"k":"' + "é" * 3 + '"}',
]

STRIP_CHARS = [chr(c) for c in range(0, 0x3001) if chr(c).isspace()] + [
    "᠎", "​", "﻿", "\x00", "\x7f", "x"]

REPR_VALUES_JSON = [
    'null', 'true', '5', '-0', '2.5', '1e16', '"plain"', '"it\'s"', '"say \\"hi\\""',
    '"both \' and \\""', '"\\t\\n\\r\\u0007\\u007f\\u0080\\u00a0\\u00ad\\u00e9\\u200b\\u2028\\u3000\\ud83d\\ude00\\\\"',
    '[1, null, true, 2.5, "s"]', '{"a": [1, {"b": null}], "c": {}}', '"CVE-\\uff12\\uff10\\uff12\\uff14-1"',
]

DATES = [
    "2026-11-10", "20261110", "2026-W45", "2026-W45-2", "2026W452", "2026W45", "2026-1-1",
    "2026-11-10T00:00", "+2026-11-10", " 2026-11-10", "2026-02-30", "2024-02-29", "2023-02-29",
    "0000-01-01", "0001-01-01", "9999-12-31", "2026-11", "2026-311", "2026-W00", "2026-W00-1",
    "2026-W01-0", "2026-W01-8", "2026-W52-7", "2026-W53-1", "2020-W53-1", "2020-W53-7", "2015-W53-1",
    "2016-W53-1", "1992-W53-1", "2004-W53-1", "2026-W5-1", "2026W4521", "2026-W45-21", "2026-W452",
    "2026W45-2", "2026-1110", "202611-10", "2026-11-1x", "2026/11/10", "٢٠٢٦-11-10",
    "2026-13-01", "2026-00-10", "2026-11-00", "2026-11-31", "9999-W52-7", "0001-W01-1", "",
]


def main() -> int:
    rnd = random.Random(20261112)
    floats = []
    for _ in range(4000):
        f = struct.unpack("<d", struct.pack("<Q", rnd.getrandbits(64)))[0]
        if f == f:  # skip NaN payloads
            floats.append(f)
    for _ in range(2000):
        floats.append(round(rnd.uniform(-1e6, 1e6), rnd.randint(0, 8)))
        floats.append(rnd.uniform(0, 1) * 10 ** rnd.randint(-30, 30))
    floats += [0.0, -0.0, 1e16, 9999999999999998.0, 1e-4, 9.999999999999999e-05, 1e-5,
               float("inf"), float("-inf"), 5e-324, 1.7976931348623157e308]

    canon = []
    for t in JSON_TEXTS:
        try:
            v = json.loads(t.encode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            canon.append({"text": t, "error": type(exc).__name__})
            continue
        try:
            canon.append({"text": t, "canonical": canonical_json(v), "hash": content_hash(v)})
        except Exception as exc:  # noqa: BLE001 (lone surrogates fail at encode)
            canon.append({"text": t, "error": type(exc).__name__})

    doc = {
        "float_repr": [{"bits": struct.unpack("<Q", struct.pack("<d", f))[0], "repr": repr(f),
                        "json": json.dumps(f)} for f in floats],
        "canonical": canon,
        "strip": [{"s": f"{c}x{c}y{c}", "strip": f"{c}x{c}y{c}".strip(), "isspace": c.isspace()}
                  for c in STRIP_CHARS],
        "repr": [{"json": j, "repr": repr(json.loads(j))} for j in REPR_VALUES_JSON],
        "fromisoformat": [{"s": s, "ok": _iso(s) is not None, "date": _iso(s)} for s in DATES],
    }
    out = ROOT / "internal" / "pyjson" / "testdata" / "pyref.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, ensure_ascii=True, indent=0) + "\n", encoding="utf-8")
    print(f"wrote {out.relative_to(ROOT)}: {len(doc['float_repr'])} floats, {len(canon)} json texts")
    return 0


def _iso(s: str) -> str | None:
    try:
        return date.fromisoformat(s).isoformat()
    except ValueError:
        return None


if __name__ == "__main__":
    sys.exit(main())
