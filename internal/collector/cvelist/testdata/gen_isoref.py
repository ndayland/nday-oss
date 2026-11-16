"""Reference for the Go port of cvelist.parse_ts (datetime.fromisoformat, C
implementation). Run from the repo root:

    .venv/bin/python internal/collector/cvelist/testdata/gen_isoref.py

Writes testdata/fromisoformat_ref.json: [[input, isoformat-or-null, epoch-us-or-null], ...]
"""
import json
import random
import sys
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
sys.path.insert(0, str(ROOT / "src"))
from nday.collectors.cvelist import parse_ts  # noqa: E402

BASE = [
    "2026-11-12T13:43:18.605Z", "2026-11-06T18:29:49.225+00:00", "2021-11-30T00:00:00.000Z",
    "2026-11-12T14:00:00+00:00", "2026-11-12T14:00:00.123456+00:00", "2026-11-12", "20261112",
    "2026-11-12T13:43:18", "2026-11-12 13:43:18", "2026-11-12x13:43", "2026-11-12é13:43:18Z",
    "2026-11-12€13:43:18Z", "2026-11-12😀13:43:18Z", "2026-W01", "2026W01", "2026-W01-3", "2026W013",
    "2026-W53", "2020-W53-7", "2015-W53-1", "9999-W52-5", "9999-W52-6", "0001-W01-1", "2026-W00",
    "2026-W01-0", "2026-W01-8", "2026-W01T10", "2026W01T10", "2026W0110", "2026W01310:00",
    "2026-W01-310:00", "2026-W01-", "2026-W0", "2026-02-29", "2024-02-29", "2026-13-01", "0000-01-01",
    "2026-11-12T24:00:00", "2026-11-12T24:00", "2026-11-12T23:59:60", "2026-11-12T1", "2026-11-12T12",
    "2026-11-12T1230", "2026-11-12T123045", "2026-11-12T12:30", "2026-11-12T12:3045",
    "2026-11-12T1230:45", "2026-11-12T12:30:45.1", "2026-11-12T12:30:45,5", "2026-11-12T12:30:45.",
    "2026-11-12T12:30:45.+01:00", "2026-11-12T12:30:45.1234567", "2026-11-12T12:30:45.1234567890Z",
    "2026-11-12T12:30:45.12x", "2026-11-12T12:30:45.1234567x", "2026-11-12T12.5", "2026-11-12T12:30.5",
    "2026-11-12T12:30:45:00", "2026-11-12T12:30:45X", "2026-11-12T", "2026-11-12T+01:00",
    "2026-11-12T12:30:45+01", "2026-11-12T12:30:45+0130", "2026-11-12T12:30:45+01:30",
    "2026-11-12T12:30:45-01:30", "2026-11-12T12:30:45+01:30:15", "2026-11-12T12:30:45+013015",
    "2026-11-12T12:30:45+01:30:15.5", "2026-11-12T12:30:45+013015.123456", "2026-11-12T12:30:45+1",
    "2026-11-12T12:30:45+123", "2026-11-12T12:30:45+", "2026-11-12T12:30:45+23:59",
    "2026-11-12T12:30:45+24:00", "2026-11-12T12:30:45-23:59:59.999999", "2026-11-12T12:30:45+05:99",
    "2026-11-12T12:30:45+00:00:00.5", "2026-11-12T12:30:45-00:00", "2026-11-12T12:30:45Z ",
    "  2026-11-12T12:30:45Z  ", "2026-11-12T12:30:45ZZ", "2026-11-12T12:30:45Z+01:00",
    "2026-11-12T12:30:45+01:00Z", "2026-11-12T12:30Z", "2026-11-12T12Z", "2026-11-12T12:30:45.123Z",
    "2026-1-12", "2026-11-1", "2026-11-1T", "202611-12", "2026-1112", "２０２６-11-12", "2026-11-12T１2",
    "abcdefg", "", "2026", "2026-11", "1234567", "12345678", "2026-11-12T12:30:45-", "0001-01-01T00:00:00+01:00",
    "9999-12-31T23:59:59-01:00", "2026-11-12T12:30:45.000000+00:00", "2026-11-12T12:30:45.000001+00:00",
    "2026-11-12T12:30:45.5-05:00", "2026-11-12T00:00:00.000", "2026-11-12t12:30:45z", "2026-11-12T12:30:45z",
    "2026-11-12T12:30:45 +01:00", "2026-11-12T12 :30", "2026-11-12T12:30:45.123+01", "2026-11-12T12:30:45,123456789+01:00",
]

CHARS = "0123456789-:+.,ZTW W" + "Z+-"


def mutate(rng, s):
    s = list(s)
    for _ in range(rng.randint(1, 3)):
        op = rng.randint(0, 2)
        i = rng.randint(0, len(s)) if s else 0
        if op == 0 and s:
            del s[min(i, len(s) - 1)]
        elif op == 1:
            s.insert(i, rng.choice(CHARS))
        elif s:
            s[min(i, len(s) - 1)] = rng.choice(CHARS)
    return "".join(s)


def main():
    rng = random.Random(20261112)
    inputs = list(dict.fromkeys(BASE))
    seen = set(inputs)
    seeds = [b for b in BASE if len(b) >= 7]
    while len(inputs) < 6000:
        m = mutate(rng, rng.choice(seeds))
        if m not in seen:
            seen.add(m)
            inputs.append(m)
    out = []
    epoch = datetime(1970, 1, 1, tzinfo=UTC)
    for s in inputs:
        t = parse_ts(s)
        if t is None:
            out.append([s, None, None])
        else:
            d = t - epoch
            us = (d.days * 86400 + d.seconds) * 1_000_000 + d.microseconds
            out.append([s, t.isoformat(), us])
    path = Path(__file__).parent / "fromisoformat_ref.json"
    path.write_text(json.dumps(out, ensure_ascii=False, indent=0) + "\n", encoding="utf-8")
    ok = sum(1 for o in out if o[1] is not None)
    print(f"wrote {path.relative_to(ROOT)}: {len(out)} inputs, {ok} parse")


main()
