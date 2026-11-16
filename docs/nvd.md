# NVD data source and the classification layer

NVD (the US NIST National Vulnerability Database) is wired in as the 7th public data source, and only for "classification": each CVE's weakness type (CWE),
its CVSS vectors, and its CPE configuration (which lives only in the raw record). NVD **produces no lifecycle events** (its publish date isn't a stage), writes no
`vuln` or `event` rows, and doesn't change `vuln_state` / `vuln_state_mat`. The classification layer merges the CWE / CVSS from three sources (the CVE record's CNA/ADP containers, NVD and GHSA)
into two tables, with the origin on every row, for the tagging feature to read.

Code: `internal/collector/nvd` (download, verification, streaming parse, raw-record writes, incremental collection), `internal/classify` (derivation,
incremental queue, read API), `internal/cli/nvd.go` (commands), migration `migrations/0009_classify.sql`.

## 1. Data feeds only, no NVD API

The files are at `https://nvd.nist.gov/feeds/json/cve/2.0/`:

- `nvdcve-2.0-<year>.json.gz`, from 2002 through the current year (the 2002 file also holds CVE-1999…2001);
- `nvdcve-2.0-modified.json.gz` (records changed in roughly the last 8 days) and `nvdcve-2.0-recent.json.gz` (recently added);
- each file has a `.meta` next to it: `lastModifiedDate`, `size`, `zipSize`, `gzSize`, `sha256`.

These facts were checked with `curl` on 2026-11-14 (not copied from the docs):

| fact | how it was confirmed |
|---|---|
| `sha256` is the SHA-256 (uppercase hex) of the **decompressed** `.json`, `size` is the decompressed byte count, and `gzSize` is the byte count of the `.json.gz` | Downloaded the modified and recent files; `gunzip -c … \| shasum -a 256` and `wc -c` match `.meta` exactly (modified: `8D334DC8…`, 106,839,794 bytes; recent: `A1A21323…`, 26,585,340 bytes); the local 2010 and 2018 samples also match the current `.meta` `sha256` |
| The modified file covers about 8 days | The modified file generated at 2026-11-13T15:00:08Z has 15,623 entries, with `lastModified` from 2026-11-05T05:18:18 to 2026-11-13T14:59:29, a span of about 8.4 days |
| `lastModified` / `published` in records are UTC (no time zone), and the document's top-level `timestamp` is US Eastern time (also no time zone) | In the same file: `.meta` has `lastModifiedDate:2026-11-13T10:00:08-05:00` (= 15:00:08Z), the top-level `timestamp` is `2026-11-13T10:00:04.86`, and the newest record's `lastModified` is `14:59:29.850` |
| The yearly files aren't regenerated every day | The 25 yearly `.meta` files on 2026-11-14: 2003, 2004 and 2008 have `lastModifiedDate` 2026-10-21, and 2026, 2025 and 2024 have 2026-11-13 |
| `.meta` carries an `ETag` and the server supports conditional requests | `curl -I` shows `etag: W/"0b990c38173dd1:0"` and `last-modified` |
| The documentation pages (`/vuln/data-feeds`, `/developers/terms-of-use`) can't be read by script | They return a single-page-app shell that needs JavaScript, or a Cloudflare 403; there's no workaround |

**Unverified (the documentation pages couldn't be read)**: the officially stated update frequency, the official window of the modified file in days, and request etiquette. So the implementation relies only on the
facts measured above, and stays conservative: once an hour it fetches just the 165-byte `.meta` (with `If-None-Match`) and downloads only when it changed; the window is taken as **7 days**
(measured at a bit over 8, leaving a day of margin).

## 2. What gets stored

`raw_record`: `source = 'nvd'`, `source_key` = the CVE id, and `payload` = the feed entry's `cve` object verbatim (decoded with pyjson; the content hash and storage format are the same as for other sources,
and a record whose content hasn't changed isn't rewritten). `fetched_at` = the file's `.meta` `lastModifiedDate` (the snapshot time; for a `--dir` import with no `.meta` next to the file, the file's modification time).

Write rules (`writeRecords` in `internal/collector/nvd/store.go`), comparing each key with the newest stored version (`fetched_at DESC, id DESC`):

- Same content hash: do nothing.
- The newest stored version came from a **newer** snapshot: don't write (an old file never rolls newer data back).
- Otherwise `pipeline.StoreRaw`: insert a new version, or (when upstream reverts to an earlier version) set that version's `fetched_at` to this snapshot's time.

Writes within a batch are sorted by key, so a baseline import and an incremental collection running at the same time can't deadlock.

No events are produced: `Normalize` returns nothing, and `nday renormalize nvd` writes nothing. A CVE the CVE List hasn't delivered yet only gets its raw record stored,
and is classified once its `vuln` row appears (see §5).

## 3. Incremental collection: `nday collect nvd` (hourly)

1. Fetch `nvdcve-2.0-modified.meta` (with the previous `ETag`). On a 304, or when `sha256` equals the cursor's: record a successful run and finish without downloading.
2. If the cursor's `synced_through` (the `lastModifiedDate` of the last modified file applied successfully) is more than 7 days older than the new `.meta`: first re-read every
   yearly file whose `.meta` `lastModifiedDate` is later than `synced_through` (each file is written in batched transactions), then process modified.
3. Download modified and verify: byte count = `gzSize`, gzip complete, decompressed byte count = `size` (which is also the decompression cap, against compression bombs), SHA-256 =
   `sha256`. If `.meta` and the file don't agree (NVD regenerated it between the two requests), `.meta` and the file are each fetched once more.
4. The whole modified file and `collector_state` are written in **one transaction**. A failed download, truncation, failed verification or database error leaves everything unchanged, the cursor doesn't move,
   and `collector_state` records `error`.
5. The first run (no cursor) reads only modified; if the database has no NVD records yet, the output has a warning telling you to do a baseline import first.

HTTP (`internal/httpc`): the generic User-Agent `nday-collector/0.1.0`; 15 s to connect, 120 s read idle; a 60 s overall limit per attempt for `.meta` and 20 min for data files; up to 4 attempts on 429 / 5xx / network errors (1, 2, 4 s backoff, honoring `Retry-After` up to 60 s); body limits of 64 KiB for `.meta` and
512 MiB for `.json.gz`; a per-record limit of 16 MiB while parsing (the largest record in the 2010 and 2018 files is 347 KB, CVE-2018-12207).

Cursor example:

```json
{"modified": {"etag": "W/\"…\"", "sha256": "8d33…", "last_modified": "2026-11-13T10:00:08-05:00"},
 "synced_through": "2026-11-13T15:00:08Z", "last_fallback": {"from": "…", "files": ["2010"]}}
```

## 4. Baseline import: `nday import-nvd-baseline`

```
nday import-nvd-baseline (--dir DIR | --download) [--year YYYY ...] [--dry-run] [--limit N] [--batch-size N]
```

- `--download`: fetches the `.meta` and then the `.json.gz` for each year, and parses only after verification passes; only one yearly file's compressed bytes are in memory at a time (46 MB for 2026).
- `--dir`: reads `DIR/nvdcve-2.0-YYYY.json.gz` (or `YYYY.json.gz`); when a `nvdcve-2.0-YYYY.meta` is next to it, it verifies the same way; when there isn't one, it imports as usual and lists the file under `unverified` in the output.
- Decompression and parsing are both streaming (`json.Decoder` reads the `vulnerabilities` array token by token), so memory doesn't grow with file size; a test with a generated 120 MB
  file shows the parser has read at most 2 KB more bytes than the entries it has handed out (`TestParseBoundedMemory`).
- Bad entries (no `cve`, an invalid id, not an object) are counted and skipped; a `totalResults` that doesn't match the entry count is treated as truncation and reported as an error.
- Repeatable and interruptible: running it again only gives `raw_unchanged`; `--limit` stops after the batch in which N entries have been written (counted by batch).
- It doesn't touch `collector_state` and doesn't classify: after importing, run `nday classify --source nvd` (or `--all`).

## 5. The classification layer

### Tables (`migrations/0009_classify.sql`)

- `vuln_cwe(cve_id → vuln ON DELETE CASCADE, cwe CHECK '^CWE-[0-9]+$', source, source_org)`, primary key (cve_id, cwe, source, source_org);
  the index `vuln_cwe_cwe_idx (cwe, cve_id)` serves "all CVEs with CWE-X", and the primary key serves "one CVE's classification".
- `vuln_cvss(cve_id → vuln, version ∈ 2.0/3.0/3.1/4.0, vector, base_score numeric(3,1) NULL, severity NULL, source, source_org)`,
  primary key (cve_id, version, source, source_org).
- `vuln_classify_input(cve_id, source ∈ cvelist/nvd/ghsa, source_key, content_hash, rejected, cwe_skipped, cvss_skipped, classified_at)`:
  for each source of each CVE, which version of the raw record it was derived from, whether that version marks the CVE as rejected, and how many entries were skipped.
- `classify_queue(id, cve_id, queued_at)`: the incremental queue (below).

`source` values: `cve-cna`, `cve-adp`, `nvd-primary`, `nvd-secondary`, `ghsa`.

### Derivation rules (`internal/classify/derive.go`; each source's **latest** raw record version only)

| source | rule |
|---|---|
| CVE record (cvelist) | `state` = REJECTED: no rows, `rejected = true`; not PUBLISHED: no rows. The CNA container → `cve-cna`, `source_org` = its `providerMetadata.shortName` (falling back to `assignerShortName`); each ADP container → `cve-adp`, `source_org` = its shortName. CWE: the `cweId` of `problemTypes[].descriptions[]`, or `CWE-<n>` at the start of the description when there's none; `n/a`, free text and `CWE-noinfo` are skipped and counted. CVSS: `cvssV2_0` / `cvssV3_0` / `cvssV3_1` / `cvssV4_0` in `metrics[]` |
| NVD | `vulnStatus` = Rejected: no rows, `rejected = true`. An entry whose `source` is `nvd@nist.gov` → `nvd-primary`, everything else → `nvd-secondary`, with `source_org` = the entry's `source`. CWE: `weaknesses[].description[].value`; `NVD-CWE-noinfo`, `NVD-CWE-Other` and the like are skipped and counted. CVSS: `cvssData` of `metrics.cvssMetricV2/V30/V31/V40[]` (v2's severity is on the entry). `configurations` (CPE) and `references` stay only in the raw record |
| GHSA | `withdrawn_at` non-null: no rows, `rejected = true`. `cwes[].cwe_id`; CVSS takes the `vector_string` of `cvss_severities.cvss_v4` / `cvss_v3` and the legacy `cvss`, with the version read from the vector prefix; GitHub gives no per-vector severity, so it's stored as NULL; `source_org` = the GHSA id |

Why the NVD entry's `type` (Primary/Secondary) isn't used: in the samples it's relative to the record. In the recent file, 1,143 CNA weaknesses
and 665 CNA CVSS entries are marked `Primary` (before NVD has analyzed a CVE, the CNA's data is the "primary" data), and in the 2018 file, 100 of NVD's own
weaknesses are marked `Secondary`. So "supplied by an NVD analyst" can only be judged by `source = nvd@nist.gov`.

Validation and skipping:

- CVSS vectors are validated per version (`vector.go`): v2 is `AV:_/AC:_/Au:_/C:_/I:_/A:_` with no prefix and no parentheses, and v2 temporal/environmental metrics are allowed
  (VulDB's v2 vectors carry `E:POC/RL:OF/RC:C`, and rejecting them all would lose a large CNA's data); v3.x must be `CVSS:3.0/` or `CVSS:3.1/`, match the version of the place it appears in,
  and have all 8 base metrics; v4.0 is `CVSS:4.0/` plus the 11 base metrics. Metric order isn't checked; unknown metrics, invalid values and duplicate metrics are all invalid.
  Invalid vectors are skipped and counted (`vuln_classify_input.cvss_skipped`).
- Scores and severity are taken from the source as given (NULL when the score is outside 0–10 or not a number); **scores are never computed**.
- When one (CVE, version, source, source_org) source gives different vectors (a CNA that lists several v3.1 vectors per scenario), the first is kept and the rest count toward `cvss_skipped`
  (25 of the 18,015 local CVE records are like this).
- Non-CWE placeholder values aren't stored, only counted (`cwe_skipped`).

### Handling of rejected (REJECTED) CVEs

The source that marks a CVE as rejected/withdrawn has its classification rows **deleted**, and `vuln_classify_input` records `rejected = true`; other sources' rows stay
(for example when the CVE record is already REJECTED and NVD hasn't caught up, NVD's rows are still there). The reason: that's exactly what each source currently says. To decide whether a CVE
is rejected, the tagging layer looks at `vuln_state_mat.is_rejected` (consistent with the rest of the site) or `Classification.RejectedBy()`; both can tell "rejected" apart from
"never classified" (the latter has no input rows at all).

### Priority ("best CVSS")

`cve-cna` > `cve-adp` > `nvd-primary` > `nvd-secondary` > `ghsa`, with ties ordered by `source_org` byte order. One is taken per version.
(`ghsa` isn't among the four levels in the requirements; its vectors are stored too, and rank last.)

### Incremental updates: how nothing gets missed

Triggers in the migration append CVE ids to `classify_queue` in the **same transaction**:

- on `raw_record` INSERT (a new content version) and `UPDATE OF fetched_at` (when upstream reverts to an old version, the pipeline changes only `fetched_at`),
  the key is added for cvelist / nvd; for ghsa, `payload->>'cve_id'` is added together with the CVEs this advisory fed before (when the id changes the old rows must be deleted);
- on `vuln` INSERT (an NVD/GHSA raw record can arrive before its `vuln` row: classification rows can't be written without a `vuln` row, so it's classified when the `vuln` row appears).

`classify.Pending` (runs automatically after every successful `nday collect <any source>`, at most 200,000 queue rows; also `nday classify --pending`)
reads a batch of queue rows, **then** reads the raw records (the writes behind the queue rows it read have necessarily committed and are visible), writes the classification rows and deletes **exactly** the queue rows it read,
all in one transaction. Writes committed while the batch runs leave their own queue rows for the next batch. Queue rows aren't merged or upserted, so a write can't be swallowed by a row that is "being processed".
At the end of `--all`, it deletes the queue rows that existed before it started (those writes all committed before it began, and every batch can see them).

Every run that writes classification shares one session-level advisory lock (the oid of `classify_queue` distinguishes the database/schema). `nday classify` waits for the lock; the automatic run after
collection skips (the output says `deferred`) if it can't get it, and the run holding the lock, or the next one, handles the rest.

For each (CVE, source) it first compares the derived result with the stored rows and writes nothing if they match, so re-runs write nothing. When a raw record can't be derived (it isn't a JSON object), that source's
old rows are kept and the problem is listed in `errors`.

### Read API (Go, `internal/classify/read.go`)

- `classify.For(ctx, q, cveID)` and `classify.ForMany(ctx, q, ids)` (one SQL statement): `Classification{CWE, CVSS, Inputs}`;
- `(*Classification).BestCVSS()` and `classify.BestCVSSMany(ctx, q, ids)` (one SQL statement, `DISTINCT ON`): one per version, by the priority above;
- `(*Classification).RejectedBy()`: the source that marked the CVE as rejected.

Public JSON: `/api/vuln/{cve}` and `/v1/vuln/{cve}` have a `classification` object (`docs/api.md`).

## 6. Local measurements (dev machine, Docker PostgreSQL 16)

Local development database: 45,940 vulns, of which 18,069 have CVE record raw data (not the full set; most of the 2010 and 2018 vulns are empty records created by PoC sources).

| step | records | time | `raw_record` growth |
|---|---|---|---|
| `import-nvd-baseline --dir` 2010 (4.36 MB gz / 47.1 MB) | 5,250 new | 2.2 s | 18,685,952 B |
| same, 2018 (8.27 MB gz / 108.8 MB) | 17,819 new | 6.7 s | 53,936,128 B |
| same, the recent file (imported as 2026; 1.70 MB gz / 26.6 MB) | 5,991 new | 2.3 s | 14,794,752 B |
| run the three files again (with `.meta` verification) | 29,060 unchanged | 2.2 s | 0 |
| `classify --all` before importing NVD (cvelist + ghsa only) | 45,940 CVEs | 3.9 s | — |
| `classify --pending` (29,060 queue rows) | 7,965 with a vuln row, 21,095 without | 1.1 s | — |
| `classify --all` again | 0 changes | 2.0 s | — |

Table sizes after classification (with indexes): `vuln_cwe` 25,367 rows, 5,611,520 B; `vuln_cvss` 28,017 rows, 6,529,024 B; `vuln_classify_input` 26,210 rows,
7,512,064 B. The md5 fingerprints of `event`, `vuln` and `vuln_state_mat` are unchanged before and after import and classification.

Coverage (the 2010 and 2018 vulns in the local database):

| year | vulns | with CWE: CVE record only → plus NVD | with CVSS: CVE record only → plus NVD |
|---|---|---|---|
| 2010 | 1,432 | 18 (1.3%) → 1,311 (91.5%) | 24 (1.7%) → 1,428 (99.7%) |
| 2018 | 1,194 | 76 (6.4%) → 1,104 (92.5%) | 89 (7.5%) → 1,189 (99.6%) |

### Extrapolation to the full set (**an estimate, not a measurement**)

The 25 yearly `.meta` files (2026-11-14) total 2,941,757,422 B decompressed and 248,792,832 B compressed. The ratio of the three samples' stored size to decompressed size is 0.479,
and to compressed size 6.10. By the former, `raw_record` grows by about **1.4 GB**; by the latter, about **1.5 GB** (the 2026 file is 549 MB decompressed with very large configurations,
so it may deviate from the sample ratio). For the classification tables, extrapolating from the local rows per input (CVE record 0.95 CWE, 1.0 CVSS; NVD 1.0 / 1.24) and bytes per row,
with 425k CVE records + about 330k NVD, `vuln_cwe` is about 0.16 GB, `vuln_cvss` about 0.19 GB and `vuln_classify_input` about 0.22 GB, about 0.6 GB in total (on the high side:
real CVE records cover CWE/CVSS less often than the local sample). Time is extrapolated from local speed (about 2,700 records/s to import and about 4,700 inputs/s to classify): a baseline import of about 330k records takes about 2–3 minutes plus download (about 250 MB), and the first `classify --all` (about 750k inputs) takes about 3 minutes.

## 7. Attribution

The site's "about" page has one sentence (catalog key `about.nvd_notice`; `en` and `zh-Hans` are written, the other five languages currently show English, see `docs/i18n/README.md` §8):

> This product uses data from the NVD but is not endorsed or certified by the NVD.

**Verified (by opening https://nvd.nist.gov/developers/terms-of-use in a browser, 2026-11-14)**: the terms are about the NVD API, and the original text of the "Attribution" section is

> Services which utilize or access the NVD API are asked to display the following notice prominently within the application: "This product uses the NVD API but is not endorsed or certified by the NVD."

The same page also says: "If you modify the content accessed through the API, you may not attribute the source as the NVD."

This site doesn't call the API and only reads the data feeds, so it doesn't copy "uses the NVD API" but says "uses data from the NVD" instead, keeping "not endorsed or certified".
NVD's CWE and CVSS are shown as is with their source labeled, without rewriting the content; tags derived by this site's rules must never be labeled "from NVD".

Two more points were also checked with `curl` on 2026-11-14: requests for `nvdcve-2.0-modified.meta` and `nvdcve-2.0-recent.json.gz` with the collector's User-Agent (`nday-collector/0.1.0`) and with Go's default
`Go-http-client/2.0` both return 200 and aren't blocked.

## 8. Not yet run against the real NVD

Go programs on the development machine aren't allowed to reach the internet, so Go's download path has only been tested against an `httptest` server (a correct file, a wrong checksum, truncated gzip, a length mismatch,
an oversized body, 304 / unchanged sha256, 5xx retries that succeed and that fail, and yearly-file fallback). `collect nvd` and `import-nvd-baseline --download`
haven't been verified against the real NVD; locally, only `--dir` imports of files downloaded with `curl` have been run.
