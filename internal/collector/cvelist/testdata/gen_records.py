"""Builds the golden inputs for tools/dump_golden.py (kind "records"):

- fixture_records.json: every record under tests/fixtures/cvelist, verbatim.
- edge_records.json: hand-written edge cases derived from those records
  (malformed shapes, timestamp variants, CVSS/SSVC/affected/alias corner cases,
  inputs that make Python raise a non-NormalizeError).

Run from the repo root: .venv/bin/python internal/collector/cvelist/testdata/gen_records.py
then:                   .venv/bin/python tools/dump_golden.py cvelist
"""
import copy
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[4]
FIX = ROOT / "tests" / "fixtures" / "cvelist"
OUT = Path(__file__).parent

TYPICAL, NO_TITLE, V4, NA, REJECTED, KEVREC = (
    "CVE-2026-108262", "CVE-2026-125344", "CVE-2026-116081", "CVE-2026-117373",
    "CVE-2026-107922", "CVE-2026-111793")


def rec(c):
    return json.loads((FIX / f"{c}.json").read_text(encoding="utf-8"))


fixtures = [{"source_key": p.stem, "payload": json.loads(p.read_text(encoding="utf-8"))}
            for p in sorted(FIX.glob("CVE-*.json"))]
(OUT / "fixture_records.json").write_text(json.dumps(fixtures, ensure_ascii=False, indent=1) + "\n",
                                          encoding="utf-8")

edges = []


def add(name, base, mutate, key=None, backfill=False):
    p = copy.deepcopy(rec(base)) if base else None
    p = mutate(p) if mutate else p
    edges.append({"source_key": key or base, "payload": p, "is_backfill": backfill, "_case": name})


def m(fn):
    def w(p):
        fn(p)
        return p
    return w


cna = lambda p: p["containers"]["cna"]  # noqa: E731
meta = lambda p: p["cveMetadata"]  # noqa: E731

# --- NormalizeError cases (tests/test_cvelist.py::test_normalize_malformed + more)
add("no cveMetadata", TYPICAL, m(lambda p: p.pop("cveMetadata")))
add("dataType X", TYPICAL, m(lambda p: p.update(dataType="X")))
add("dataType missing", TYPICAL, m(lambda p: p.pop("dataType")))
add("bad cveId", TYPICAL, m(lambda p: meta(p).update(cveId="CVE-26-1")))
add("cveId int", TYPICAL, m(lambda p: meta(p).update(cveId=26)))
add("cveId quote", TYPICAL, m(lambda p: meta(p).update(cveId="it's \"x\"")))
add("state WEIRD", TYPICAL, m(lambda p: meta(p).update(state="WEIRD")))
add("state int", TYPICAL, m(lambda p: meta(p).update(state=5)))
add("state missing", TYPICAL, m(lambda p: meta(p).pop("state")))
add("no cna", TYPICAL, m(lambda p: p["containers"].pop("cna")))
add("containers list", TYPICAL, m(lambda p: p.update(containers=[])))
add("cna string", TYPICAL, m(lambda p: p["containers"].update(cna="x")))
add("key mismatch", TYPICAL, None, key=NA)
add("payload list", None, lambda p: [1, 2], key=TYPICAL)
add("cveMetadata list", TYPICAL, m(lambda p: p.update(cveMetadata=[])))
# --- cveId whitespace is stripped; RESERVED (even without containers)
add("cveId padded", NA, m(lambda p: meta(p).update(cveId="  CVE-2026-117373\t")))
add("reserved", NA, m(lambda p: meta(p).update(state="RESERVED")))
add("reserved no containers", NA, m(lambda p: (meta(p).update(state="RESERVED"), p.pop("containers"))))
# --- timestamps
add("ts naive", TYPICAL, m(lambda p: meta(p).update(datePublished="2026-11-06T18:29:49", dateUpdated="2026-11-07")))
add("ts offset", TYPICAL, m(lambda p: meta(p).update(datePublished="2026-11-06T18:29:49.1234567+05:30",
                                                     dateUpdated=" 2026-11-07T01:02:03-08:00 ")))
add("ts garbage", TYPICAL, m(lambda p: meta(p).update(datePublished="yesterday", dateUpdated="")))
add("ts number", TYPICAL, m(lambda p: meta(p).update(datePublished=20261106, dateUpdated=None)))
add("ts week", TYPICAL, m(lambda p: meta(p).update(datePublished="2026-W45-4T10:00Z")))
# --- REJECTED variants
add("rejected replacedBy", REJECTED, m(lambda p: cna(p).update(replacedBy=["CVE-2026-1000"],
                                                                rejectedReasons=[{"lang": "en", "value": "dup"}, "x", {"v": 1}])))
add("rejected falsy replacedBy", REJECTED, m(lambda p: cna(p).update(replacedBy=[])))
add("rejected reasons dict", REJECTED, m(lambda p: cna(p).update(rejectedReasons={"a": 1})))
add("rejected reasons string", REJECTED, m(lambda p: cna(p).update(rejectedReasons="abc")))
add("rejected reasons int (fatal)", REJECTED, m(lambda p: cna(p).update(rejectedReasons=3)))
add("rejected reasons missing", REJECTED, m(lambda p: cna(p).pop("rejectedReasons", None)))
add("rejected with datePublished", REJECTED, m(lambda p: meta(p).update(datePublished="2026-01-01T00:00:00Z")))
# --- descriptions
add("desc prefix", TYPICAL, m(lambda p: cna(p).update(descriptions=[
    {"lang": "es", "value": "hola"}, {"lang": "EN-us", "value": " english-us "}])))
add("desc exact wins", TYPICAL, m(lambda p: cna(p).update(descriptions=[
    {"lang": "en-US", "value": "us"}, {"lang": " en ", "value": "exact"}])))
add("desc empty values", TYPICAL, m(lambda p: cna(p).update(descriptions=[
    {"lang": "en", "value": "  "}, {"lang": "en", "value": 5}, "x", {"lang": "eng", "value": "eng"}])))
add("desc none", TYPICAL, m(lambda p: cna(p).update(descriptions=[{"lang": "fr", "value": "fr"}])))
add("desc string", TYPICAL, m(lambda p: cna(p).update(descriptions="english")))
add("desc int (fatal)", TYPICAL, m(lambda p: cna(p).update(descriptions=1)))
add("title whitespace", TYPICAL, m(lambda p: cna(p).update(title=" \x1c ")))
add("title non-str", TYPICAL, m(lambda p: cna(p).update(title=["t"])))
# --- affected
add("affected dupes and n/a", TYPICAL, m(lambda p: cna(p).update(affected=[
    {"vendor": "Acme", "product": "Rocket"}, {"vendor": " Acme ", "product": "Rocket "},
    {"vendor": "N/A", "product": "x"}, {"vendor": "x", "product": "n/A"}, {"vendor": "acme", "product": "Rocket"},
    {"vendor": "", "product": "y"}, {"vendor": "v"}, "str", 5, None, {"vendor": "n/a ", "product": "z"}])))
add("affected dict", TYPICAL, m(lambda p: cna(p).update(affected={"vendor": "x"})))
add("affected float (fatal)", TYPICAL, m(lambda p: cna(p).update(affected=1.5)))
add("affected false", TYPICAL, m(lambda p: cna(p).update(affected=False)))
# --- alias
add("ghsa padded", TYPICAL, m(lambda p: cna(p)["source"].update(advisory=" GHSA-2345-6789-cfgh\n")))
add("ghsa lowercase prefix", TYPICAL, m(lambda p: cna(p)["source"].update(advisory="ghsa-2345-6789-cfgh")))
add("ghsa bad charset", TYPICAL, m(lambda p: cna(p)["source"].update(advisory="GHSA-abcd-6789-cfgh")))
add("ghsa suffix", TYPICAL, m(lambda p: cna(p)["source"].update(advisory="GHSA-2345-6789-cfgh-x")))
add("source string", TYPICAL, m(lambda p: cna(p).update(source="GHSA-2345-6789-cfgh")))
add("advisory vendor id", TYPICAL, m(lambda p: cna(p)["source"].update(advisory="VENDOR-2026-1")))
# --- CVSS
add("cvss no version", V4, m(lambda p: [mm.get("cvssV4_0", {}).pop("version", None) for mm in cna(p)["metrics"]]))
add("cvss version empty", V4, m(lambda p: [mm["cvssV4_0"].update(version="") for mm in cna(p)["metrics"] if "cvssV4_0" in mm]))
add("cvss null score", V4, m(lambda p: [mm["cvssV4_0"].update(baseScore=None) for mm in cna(p)["metrics"] if "cvssV4_0" in mm]))
add("cvss v2 only int score", NA, m(lambda p: cna(p).update(metrics=[
    "junk", {"cvssV2_0": "notdict"}, {"cvssV2_0": {"baseScore": 7, "version": 2.0, "vectorString": "AV:N"}}])))
add("cvss metrics dict", NA, m(lambda p: cna(p).update(metrics={"cvssV3_1": {"baseScore": 1}})))
add("cvss adp no provider", NO_TITLE, m(lambda p: [a.pop("providerMetadata") for a in p["containers"]["adp"]]))
add("cvss adp provider str (fatal)", NO_TITLE, m(lambda p: [a.update(providerMetadata="CISA") for a in p["containers"]["adp"]]))
add("cvss adp provider empty str", NO_TITLE, m(lambda p: [a.update(providerMetadata="") for a in p["containers"]["adp"]]))
add("adp dict", NO_TITLE, m(lambda p: p["containers"].update(adp={"x": 1})))
add("adp int (fatal)", NO_TITLE, m(lambda p: p["containers"].update(adp=7)))
add("adp non-dict items", NO_TITLE, m(lambda p: p["containers"]["adp"].insert(0, "x")))
# --- SSVC / KEV
add("ssvc options merge", KEVREC, m(lambda p: [
    mm["other"]["content"].update(options=[{"Exploitation": "none"}, "x", {"Exploitation": "poc", "Automatable": "yes"}])
    for a in p["containers"]["adp"] for mm in a.get("metrics", []) if mm.get("other", {}).get("type") == "ssvc"]))
add("ssvc empty content", KEVREC, m(lambda p: [
    mm["other"].update(content=[]) for a in p["containers"]["adp"] for mm in a.get("metrics", [])
    if mm.get("other", {}).get("type") == "ssvc"]))
add("ssvc options int (fatal)", KEVREC, m(lambda p: [
    mm["other"]["content"].update(options=4) for a in p["containers"]["adp"] for mm in a.get("metrics", [])
    if mm.get("other", {}).get("type") == "ssvc"]))
add("kev content string", KEVREC, m(lambda p: [
    mm["other"].update(content="x") for a in p["containers"]["adp"] for mm in a.get("metrics", [])
    if mm.get("other", {}).get("type") == "kev"]))
add("adp metrics string", KEVREC, m(lambda p: [a.update(metrics="abc") for a in p["containers"]["adp"]]))
add("adp metrics int (fatal)", KEVREC, m(lambda p: [a.update(metrics=2) for a in p["containers"]["adp"]]))
add("two cisa adp", KEVREC, m(lambda p: p["containers"]["adp"].append(copy.deepcopy(p["containers"]["adp"][0]))))
add("backfill flag", TYPICAL, None, backfill=True)

for e in edges:  # keep the case name next to the record for humans
    e["payload"] = e["payload"]
(OUT / "edge_records.json").write_text(json.dumps(edges, ensure_ascii=False, indent=1) + "\n", encoding="utf-8")
print(f"{len(fixtures)} fixture records, {len(edges)} edge records")
