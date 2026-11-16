"""Reference data for the Go ghsa port, produced by the project's CPython.

Run from the repository root:

    .venv/bin/python internal/collector/ghsa/testdata/gen_pyref.py iso internal/collector/ghsa/testdata/fromisoformat.json 4000 1
    .venv/bin/python internal/collector/ghsa/testdata/gen_pyref.py classes internal/collector/ghsa/testdata/python_classes.json
    .venv/bin/python internal/collector/ghsa/testdata/gen_pyref.py fixurls internal/collector/ghsa/testdata/fix_urls.json 3000 1

(iso with a large N and another seed for an ad-hoc run: GHSA_ISO_VECTORS=<file> go test ...)
"""
import json, random, sys
from datetime import datetime, timedelta, UTC

sys.path.insert(0, "src")
from nday.collectors.ghsa import NOT_FIX_RE, fix_commit_urls, parse_ts  # noqa: E402
import re  # noqa: E402

EPOCH = datetime(1970, 1, 1)


def micros(dt):
    naive = dt.replace(tzinfo=None)
    off = dt.utcoffset() or timedelta(0)
    return (naive - EPOCH) // timedelta(microseconds=1) - off // timedelta(microseconds=1)


def ref(s):
    try:
        dt = datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None
    return micros(dt)


def ref_ts(s):
    dt = parse_ts(s)
    return None if dt is None else micros(dt)


HAND = [
    "2026-11-12T10:00:00Z", "2026-11-12T10:00:00+00:00", "2026-11-12T10:00:00", "2026-11-12",
    "20261112", "20261112T100000", "2026-11-12 10:00", "2026-11-12T10", "2026-11-12T1",
    "2026-11-12T10:00:00.1", "2026-11-12T10:00:00.1234567", "2026-11-12T10:00:00,5",
    "2026-11-12T10:00:00.", "2026-11-12T10:00:", "2026-11-12T10.5", "2026-11-12T10:30.5",
    "2026-11-12T101010123", "2026-11-12T10:10:10:10", "2026-11-12T10:00:00+05:30",
    "2026-11-12T10:00:00-05", "2026-11-12T10:00:00+0530", "2026-11-12T10:00:00+05:30:15",
    "2026-11-12T10:00:00+05:30:15.123", "2026-11-12T10:00:00+00:00:00.5", "2026-11-12T10:00:00+24:00",
    "2026-11-12T10:00:00+23:59:59.999999", "2026-11-12T10:00:00-23:59", "2026-11-12T10:00:00+99",
    "2026-11-12T10:00:00+", "2026-11-12T10:00:00+0", "2026-11-12T10:00:00+005", "2026-11-12T10:00:00Zx",
    "2026-11-12T10:00:00ZZ", "2026-11-12T24:00:00", "2026-02-29T00:00:00", "2024-02-29T00:00:00",
    "0001-01-01T00:00:00+01:00", "9999-12-31T23:59:59-01:00", "0000-01-01", "2026-13-01", "2026-W01",
    "2026W01", "2026W017", "2026-W01-7", "2026-W53", "2026-W53-1", "2020-W53", "2026W01T10",
    "2026-W01T10:00", "2026-W01-1T10:00", "2026-W0110:00", "2026W0110", "2026W01110", "2026W011100",
    "2026-W01-", "2026-W01-x", "2026-11-12x10:00", "2026-11-12é10:00", "2026-11-12é10",
    "2026-11-12\x0010:00", "2026-11-12T10:00\x00", "2026-11-12T10:00:00.12\x00", " 2026-11-12",
    "2026-11-12T10:00:00 ", "２０２６-11-12", "2026-1-12", "202611-12", "2026-1112", "2026-11-12T",
    "2026-11-12TT", "2026-11-12T10:00:00-00:00", "2026-11-12T10:00:00+00:00:00.000001",
    "2026-11-12T10:00:00-00:00:00.000001", "2026-11-12T10:00:00+00:01", "2026-11-12T1000", "2026-11-12T10:0000",
    "2026-11-12T1000:00", "2026-11-12T10:60", "2026-11-12T10:00:60", "2026-11-12T10:00:00.9999999",
    "2026-11-12T10:00:00.000000000000001", "2026-11-12T10-05", "2026-11-12T-05", "2026-11-12T+05:00",
    "2026-11-12T10:00:00+05:00Z", "2026-11-12T10:00:00+05:00+01", "1234567", "12345678", "2026-11",
    "2026-001", "2026001", "abcdefg", "", "2026-11-12T10:00:00.123+05:30", "2026-11-12T10:00:00,123-01",
]

ALPH = list("0123456789-:T+.,WZ ") + ["0"] * 10 + ["1", "2"] * 4 + ["é", "\x00", "x", "😀", "\x7f", "ı"]


def rnd(r):
    if r.random() < 0.6:
        base = r.choice(HAND)
        chars = list(base)
        for _ in range(r.randint(1, 3)):
            op = r.random()
            pos = r.randint(0, len(chars))
            if op < 0.4 and chars:
                chars[min(pos, len(chars) - 1)] = r.choice(ALPH)
            elif op < 0.7:
                chars.insert(pos, r.choice(ALPH))
            elif chars:
                del chars[min(pos, len(chars) - 1)]
        return "".join(chars)
    y = r.randint(0, 10000)
    s = f"{y:04d}" if y < 10000 else str(y)
    s += r.choice(["-", ""]) + f"{r.randint(0, 13):02d}" + r.choice(["-", ""]) + f"{r.randint(0, 32):02d}"
    if r.random() < 0.8:
        s += r.choice(["T", " ", "x"]) + f"{r.randint(0, 25):02d}"
        for _ in range(r.randint(0, 2)):
            s += r.choice([":", ""]) + f"{r.randint(0, 61):02d}"
        if r.random() < 0.4:
            s += r.choice([".", ","]) + "".join(r.choice("0123456789") for _ in range(r.randint(0, 9)))
        if r.random() < 0.6:
            s += r.choice(["Z", "+", "-", "+00:00"])
            if r.random() < 0.7:
                s += f"{r.randint(0, 25):02d}" + r.choice([":", ""]) + f"{r.randint(0, 61):02d}"
                if r.random() < 0.3:
                    s += r.choice([":", ""]) + f"{r.randint(0, 61):02d}"
    return s


def iso(out, n, seed):
    r = random.Random(seed)
    cases = list(dict.fromkeys(HAND + [rnd(r) for _ in range(n)]))
    vec = [{"s": s, "fromisoformat": ref(s), "parse_ts": ref_ts(s)} for s in cases]
    with open(out, "w", encoding="utf-8") as f:
        json.dump(vec, f, ensure_ascii=False, indent=0)
    ok = sum(v["fromisoformat"] is not None for v in vec)
    print(f"{len(vec)} vectors, {ok} valid fromisoformat, "
          f"{sum(v['parse_ts'] is not None for v in vec)} valid parse_ts")


def ranges(pred):
    out, start = [], None
    for cp in range(0x110000):
        ok = not 0xD800 <= cp <= 0xDFFF and pred(chr(cp))
        if ok and start is None:
            start = cp
        if not ok and start is not None:
            out.append([start, cp - 1])
            start = None
    if start is not None:
        out.append([start, 0x10FFFF])
    return out


def classes(out):
    d, s = re.compile(r"\d"), re.compile(r"\s")
    doc = {
        "re_d": ranges(lambda c: d.fullmatch(c) is not None),
        "isdecimal": ranges(str.isdecimal),
        "isdigit": ranges(str.isdigit),
        "re_s": ranges(lambda c: s.fullmatch(c) is not None),
        "isspace": ranges(str.isspace),
        "isprintable": ranges(str.isprintable),
        # every code point re.IGNORECASE matches for each letter of NOT_FIX_RE
        "ignorecase": {ch: [cp for cp in range(0x110000) if not 0xD800 <= cp <= 0xDFFF
                            and re.fullmatch(ch, chr(cp), re.I)]
                       for ch in sorted(set("httpsgithubcomadvisorydatabase"))},
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f)
    print("classes written")


PARTS = ["https://", "http://", "HTTPS://", "github.com", "GitHub.com", "gitlab.com", "my-gitlab.org",
         "bitbucket.org", "example.com", "/", "/", "/", "acme", "widget", "github", "advisory-database",
         "g\u0130thub", "advi\u017fory", "commit", "commits", "pull", "-", "-/commit", "-/merge_requests",
         "issues", "0123456789abcdef", "abcdef1", "ABCDEF0", "deadbeef", "42", "\uff14\uff12", "\u0669",
         "\U00010D40", "\U0001FBF5", "#", "?", "x=1", "\n", "\u2003", "\x0b", "\x1c", "\u00a0", "\u200b",
         " ", "\t", "\u2028", "files", "."]


def fixurls(out, n, seed):
    r = random.Random(seed)
    vec = []
    for _ in range(n):
        refs = []
        for _ in range(r.randint(0, 6)):
            if r.random() < 0.05:
                refs.append(r.choice([None, 7, "", ["x"]]))
                continue
            host = r.choice(["github.com", "GitHub.com", "gitlab.com", "my-gitlab.org", "gitlab.x.io",
                             "bitbucket.org", "example.com"])
            owner = r.choice(["acme", "github", "g\u0130thub", "Git\u0131hub", "a\u2003b", "a\x0bb", "a\u200bb"])
            repo = r.choice(["widget", "advisory-database", "Advisory-Database", "advi\u017fory-database", "x\x1cy"])
            mid = r.choice(["", "/sub", "/-", ""])
            kind = r.choice(["commit", "commits", "pull", "-/commit", "-/merge_requests", "issues", "releases/tag"])
            ident = r.choice(["0123456789abcdef0123456789abcdef01234567", "abcdef1", "abcdef", "ABCDEF0",
                              "42", "\uff14\uff12", "\u0669", "\U00010D40", "\U0001FBF5", "\U00016D70", "main"])
            tail = r.choice(["", "", "/files", "?diff=split", "#L1", "#x\ny", "#x\u2028y", "/commits/abcdef1"])
            u = (r.choice(["https://", "http://", "HTTPS://", "ftp://"]) + host + "/" + owner + mid + "/" + repo
                 + "/" + kind + "/" + ident + tail)
            for _ in range(r.choice([0, 0, 1, 2])):
                pos = r.randint(0, len(u))
                if r.random() < 0.5:
                    u = u[:pos] + r.choice(PARTS) + u[pos:]
                else:
                    u = u[:pos] + u[pos + 1:]
            if r.random() < 0.1:
                u = r.choice([" ", "\t", "\u3000", "\x1f"]) + u + r.choice([" ", "\n", ""])
            refs.append(u)
            if r.random() < 0.2:
                refs.append(u)
        vec.append({"refs": refs, "want": fix_commit_urls(refs),
                    "not_fix": [bool(NOT_FIX_RE.match(x)) if isinstance(x, str) else None for x in refs]})
    with open(out, "w", encoding="utf-8") as f:
        json.dump(vec, f, ensure_ascii=False, indent=0)
    print(f"{n} fix_commit_urls vectors, {sum(len(v['want']) for v in vec)} urls kept")


def main():
    cmd = sys.argv[1]
    if cmd == "iso":
        iso(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))
    elif cmd == "classes":
        classes(sys.argv[2])
    elif cmd == "fixurls":
        fixurls(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]))


main()
