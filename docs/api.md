# nday JSON API

A read-only JSON API, served by `nday serve [--listen 127.0.0.1:8080]` (or the `NDAY_LISTEN` environment variable).
The code is in `internal/web` (routes and middleware; the separate API host is in `internal/web/apihost.go`) and `internal/site`
(queries; the HTML pages use the same structs). No auth, no cookies, no write endpoints.

## Base URL

**Production base URL: `https://api.nday.land/v1`** (the website itself is at `https://www.nday.land`).

| Endpoint | API host (`NDAY_API_URL` set) | Single-host mode (unset; local development and tests) |
|---|---|---|
| Hot list | `GET /v1/hot` | `GET /api/hot` |
| Vulnerability catalog | `GET /v1/vulns` | `GET /api/vulns` |
| Discussed by researchers | `GET /v1/discussed` | `GET /api/discussed` |
| Single vulnerability | `GET /v1/vuln/{cve}` | `GET /api/vuln/{cve}` |
| Data sources | `GET /v1/sources` | `GET /api/sources` |
| Stats | `GET /v1/stats` | `GET /api/stats` |
| Search | `GET /v1/search` | `GET /api/search` |
| Vendor/product name suggestions | `GET /v1/affected/suggest` | `GET /api/affected/suggest` |
| Tag list | `GET /v1/tags` | `GET /api/tags` |
| Raw record | `GET /v1/raw/{source}/{key}.json` (alias: `GET /raw/{source}/{key}.json`) | `GET /raw/{source}/{key}.json` |
| Health check | `GET /healthz` | `GET /healthz` |
| Index | `GET /`, `GET /v1` | — |

In both modes the handlers, query parameters, response bodies, `ETag` and `Cache-Control` are identical. The sections below use the single-host paths.
On the API host, replace `/api` with `/v1` and put `/v1` in front of `/raw`.

- **Single-host mode**: if `NDAY_API_URL` isn't set, everything is served from the website host, same as it always was (local development: `http://127.0.0.1:8080/api/hot`).
- **API host** (`NDAY_API_URL=https://api.nday.land` set): requests whose `Host` is that host (case-insensitive, default port ignored)
  are handled by the API routes **only**: the `/v1/*` routes in the table above, `/raw/...` (an alias of `/v1/raw/...`), `/healthz`, the index (`{"name","docs","endpoints"}`, where `docs` points to the website's
  `/about#api`) and `/robots.txt` (`Disallow: /`). Everything else gets a JSON 404. Pages, static files, `/auth/*`, `/account/*` and
  `/api/me` don't exist on the API host (404).
- **Legacy path redirects**: when `NDAY_API_URL` is set, `/api/hot`, `/api/vulns`, `/api/discussed`, `/api/vuln/{cve}`, `/api/sources`, `/api/stats`, `/api/search` and
  `/raw/...` on the website host answer `308 Permanent Redirect`. `Location` is `NDAY_API_URL` + `/v1/...`, and the query string is kept as is
  (`Cache-Control: public, max-age=3600`). The target is built only from the configured origin and the escaped request path. The request's `Host` is never used.
  `/api/me`, `/auth/*` and `/account/*` aren't redirected. Other unknown `/api/*` paths are still a JSON 404. `/healthz` exists on both hosts.
  Exception: `/api/affected/suggest` is answered **directly** on the website host (same handler, same cache headers). The first-login page's script calls it,
  and the page CSP is `connect-src 'self'`, so the script can't follow a 308 to the API host. On the API host it's `/v1/affected/suggest`.
  A 308 keeps the method, but anything other than GET/HEAD is already a 405 on the website host.
- **CORS** (API host only, on every response including errors): `Access-Control-Allow-Origin: *`. It never sends
  `Access-Control-Allow-Credentials`. `Access-Control-Expose-Headers: ETag`. A preflight `OPTIONS` gets `204` with
  `Access-Control-Allow-Methods: GET, HEAD, OPTIONS`, `Access-Control-Allow-Headers: Accept, If-None-Match` and
  `Access-Control-Max-Age: 86400`. Responses also carry `Cross-Origin-Resource-Policy: cross-origin`, `X-Content-Type-Options: nosniff` and
  `Content-Security-Policy: default-src 'none'; frame-ancestors 'none'`. The API host never sends `Set-Cookie`
  (the middleware strips any `Set-Cookie`).
- **Login isn't part of the public API**: `/auth/*`, `/account/*` and `GET /api/me` exist only on the website host (see the appendix at the end), and cookies are never sent to the API host.

## General conventions

- Only `GET` / `HEAD` are accepted (the API host also accepts `OPTIONS` preflights). Other methods get a `405` (JSON, with `Allow: GET, HEAD`;
  on the API host, `Allow: GET, HEAD, OPTIONS`).
- Field names are snake_case. Times are always RFC 3339 UTC instants (`2026-11-09T00:00:00Z`). Unknown values are an explicit `null`,
  never a guess. Calendar dates (KEV `date_added` / `due_date`) are `YYYY-MM-DD` strings.
- Stages: each one has an event type name and a three-letter code:

  | type | code | `min_stage` shorthand |
  |---|---|---|
  | `disclosed` | `DIS` | `disclosed` |
  | `patch_released` | `PAT` | `patch` |
  | `analysis_published` | `ANA` | `analysis` |
  | `poc_published` | `POC` | `poc` |
  | `exploited_in_wild` | `ITW` | `exploited` |
  | `kev_added` | `KEV` | `kev` |

- **slot.state**: `none` (no event of this type), `known` (there's an event and its earliest effective time is known: `at`), `unknown`
  (there are events but none has a known time), `implied` (ITW only: there's no `exploited_in_wild` event but the CVE is in KEV;
  `not_after` is the KEV time, an upper bound, and `implied_by` is `"kev_added"`). `latest: true` marks the most recent change
  (at most one per row). `slots` always has 6 entries, in the order DIS PAT ANA POC ITW KEV.
- **precision** (events and transitions): `day` (`detail.precision` = "day"; only the UTC date means anything, and the time is 00:00Z),
  `exact` (the source gave a time), `observed` (the source gave no time, but we saw it live; the time is `observed_at`),
  `unknown` (the source gave no time and it came from a bulk import).
- **Effective time** `effective_at` is `occurred_at`, or else (for live observations) `observed_at`, or else `null`.
- `days_since_disclosure`: the difference in UTC calendar days from the disclosure date to the target date (can be negative: KEV earlier than the CVE publication). `null` if either is unknown.
- List data comes from the materialized state `vuln_state_mat`, which is refreshed after every successful collection (`state_refreshed_at`).
  `slots` / `transition` in `/api/vuln` are computed straight from the events, so they're always current.

### Errors

```json
{"error":{"status":400,"code":"bad_request","message":"since: bad duration \"5m\", use e.g. 24h, 7d or 30d","param":"since"}}
```

`code`: `bad_request` (400, `param` names the parameter), `not_found` (404), `method_not_allowed` (405),
`timeout` (503, database timeout), `internal` (500). Every parameter is validated. Unknown and repeated parameters are both a 400.

### Caching

| Endpoint | Cache-Control | Validator |
|---|---|---|
| `/api/*`, `/v1/*` (200 and 404) | `public, max-age=60` | weak `ETag` (hash of the body); `If-None-Match` is supported → 304 |
| `/raw/...`, `/v1/raw/...` | `public, max-age=3600` | strong `ETag` = the record's `content_hash`; `Last-Modified` = fetch time |
| `/healthz`, 400/405/5xx | `no-store` | — |

There's also a 30 s in-process TTL cache with request coalescing (concurrent requests with the same parameters hit the database once).
The `X-Nday-Cache: hit|miss` response header helps when debugging.

## Routes

### `GET /healthz`

A cheap liveness check: two single-row queries. Returns 200 when the database is reachable (`status` is `ok`, or `stale` if the last successful collection was more than 3 hours ago),
and 503 when it isn't (`status: "error"`).

```json
{
  "status": "stale",
  "db": "ok",
  "data_updated_at": "2026-11-12T15:19:46.457931Z",
  "data_age_seconds": 38821,
  "stale": true,
  "state_refreshed_at": "2026-11-13T02:06:36.567284Z",
  "checked_at": "2026-11-13T02:06:48.34523Z"
}
```

### `GET /api/hot`

Vulnerabilities that recently moved into a new stage, newest transition first (ties: higher stage first, then CVE ID descending; the order is stable).

| Parameter | Default | Values |
|---|---|---|
| `since` | `7d` | `<n>h` or `<n>d`, 1h–366d |
| `min_stage` | `patch_released` | type name, shorthand or code (see the table above) |
| `include_rejected` | `false` | `true/false/1/0` (empty = true) |
| `limit` | 50 | 1–200 |
| `offset` | 0 | 0–10000 (ignored when `cursor` is given) |
| `cursor` | — | the previous page's `next_cursor` |
| `tag` | — | tag slug (see `GET /api/tags`). **Repeatable**; results must match all of them (`?tag=remote-unauth&tag=xss`). Case-insensitive. An unknown slug, or more than 5 distinct slugs, is a 400 (`param: "tag"`) |

Each row has `researchers_7d` (added 2026-11-14; additive only): the number of **distinct** allowlisted researchers who posted about the CVE on X in the last 7 days (`[now-7d, now]`); only enabled accounts count
(rules in `internal/site/public.go` and `docs/xposts.md`, "Public visibility"). It doesn't affect ordering or `cursor`.

Each row has `pinned` (boolean; added 2026-11-14; additive only): CVEs researchers are **currently discussing** are pinned at the very top of the **first page** (no `cursor` and `offset=0`).
Those rows have `pinned: true`; all others have `false`. A CVE is pinned only if all of these hold (the rules live in `internal/site/pin.go`):

1. `researchers_7d` ≥ 2 (same definition as above: only enabled allowlisted accounts count);
2. the latest researcher post is at most 72 hours old;
3. the current "wave" of discussion started within the last 7 days. A wave is the CVE's most recent run of consecutive posts where each pair of neighbours is at most 7 days apart; it starts at the earliest post in that run.
   So a CVE that goes quiet for more than 7 days and then gets discussed again can be pinned again, while a CVE that's discussed continuously stops being pinned 7 days after its wave began;
4. it's already in this request's list (same `since`, `min_stage`, `include_rejected` and `tag`).

At most 10 rows (since 2026-11-16; it was 5 before), ordered by `researchers_7d` descending, then latest post time descending, then CVE ID ascending. The four numbers are the database settings
`NDAY_HOT_PIN_MAX` / `_RESEARCHERS` / `_RECENT_HOURS` / `_WAVE_DAYS` (`docs/settings.md`; `NDAY_HOT_PIN_MAX=0` turns pinning off, and top-up with it).

Top-up (2026-11-16): if the rules above select fewer than `NDAY_HOT_PIN_MAX` rows, the list is filled from the top of the `/api/discussed` ranking (`researchers_7d` descending,
latest post time descending, CVE ID ascending), skipping CVEs already pinned by the rules, until it's full or the ranking runs out. Topped-up rows only need to: have a lifecycle state
(CVEs that only appear in posts and have no stage event are skipped), and match `include_rejected` and `tag`. They do **not** need to be inside the `since` window or reach `min_stage`.
Rule-pinned rows come first, topped-up rows after. Every pinned row has a `pin_reason` (additive only): `"rule"` (pinned by the rules) or `"discussed"` (topped up). Normal rows don't have this field.
`pinned` is unchanged.

Paging: pinned CVEs are removed from the normal rows on **every page**, so a CVE never shows up twice. The first page is the pinned rows plus at most `limit` normal rows
(so at most `limit` + `NDAY_HOT_PIN_MAX` rows, `limit` + 10 by default). `limit`, `offset` and `next_cursor` apply to the normal rows only, exactly as when nothing is pinned.
Post times are used only for filtering and sorting and aren't returned. The Atom feed (`/feed.xml`) doesn't pin; it lists all rows in their original order.

The response has `tags` (added 2026-11-14; additive only): the normalized tag filter (in vocabulary order; `[]` when there's no filter). Each row has `tags` too: that CVE's tag slugs (vocabulary order).

Row fields: `products` has at most 2 entries (deduplicated case-insensitively, first reporter first) and `product_count` is the total.
`transition` is the most recent change (`type/code/at/precision/source/event_id`). `poc_sources` is how many of exploitdb,
metasploit and nuclei have a PoC event (n/3).

```sh
curl -s 'https://api.nday.land/v1/hot?since=30d&min_stage=patch' | jq .
# single-host mode: curl -s 'http://127.0.0.1:8080/api/hot?since=30d&min_stage=patch' | jq .
```

Example (`?since=30d&min_stage=patch&limit=1`, local database, 2026-11-13):

```json
{
  "since": "30d",
  "since_start": "2026-10-14T02:06:48.348007Z",
  "min_stage": "patch_released",
  "min_stage_code": "PAT",
  "include_rejected": false,
  "limit": 1,
  "offset": 0,
  "rows": [
    {
      "cve_id": "CVE-2026-59726",
      "title": "Ruflo: Unauthenticated RCE in MCP bridge default docker-compose deployment",
      "title_zh": null,
      "products": [
        {
          "vendor": "ruvnet",
          "product": "ruflo"
        }
      ],
      "product_count": 1,
      "stage": "poc_published",
      "stage_code": "POC",
      "is_rejected": false,
      "transition": {
        "type": "poc_published",
        "code": "POC",
        "at": "2026-11-11T00:00:00Z",
        "precision": "day",
        "source": "exploitdb",
        "event_id": 42212
      },
      "slots": [
        {
          "code": "DIS",
          "type": "disclosed",
          "state": "known",
          "at": "2026-07-09T17:31:20.627Z",
          "not_after": null,
          "implied_by": null,
          "latest": false
        },
        {
          "code": "PAT",
          "type": "patch_released",
          "state": "none",
          "at": null,
          "not_after": null,
          "implied_by": null,
          "latest": false
        },
        {
          "code": "ANA",
          "type": "analysis_published",
          "state": "none",
          "at": null,
          "not_after": null,
          "implied_by": null,
          "latest": false
        },
        {
          "code": "POC",
          "type": "poc_published",
          "state": "known",
          "at": "2026-11-11T00:00:00Z",
          "not_after": null,
          "implied_by": null,
          "latest": true
        },
        {
          "code": "ITW",
          "type": "exploited_in_wild",
          "state": "none",
          "at": null,
          "not_after": null,
          "implied_by": null,
          "latest": false
        },
        {
          "code": "KEV",
          "type": "kev_added",
          "state": "none",
          "at": null,
          "not_after": null,
          "implied_by": null,
          "latest": false
        }
      ],
      "disclosed_at": "2026-07-09T17:31:20.627Z",
      "days_since_disclosure": 125,
      "poc_sources": 2
    }
  ],
  "next_cursor": "MTc5NDM1NTIwMDAwMDAwMHw0fENWRS0yMDI2LTU5NzI2",
  "generated_at": "2026-11-13T02:06:48.348007Z"
}
```

### `GET /api/vulns`

Added 2026-11-15. The full vulnerability catalog: **every** vulnerability in the database (every row of `vuln_state_mat`, meaning every CVE with at least one lifecycle event,
including ones with only a disclosure event; placeholder CVEs with no events are left out). There's no time window, no minimum stage and **no pinning**.
It doesn't return a total (per-stage totals are in `GET /api/stats`).

Order: most recent change (`transition.at`) descending, ties broken by the **current** stage (higher first), then CVE ID descending (same as `/api/hot`).
A CVE whose stage event times are all unknown has no `transition.at`; it sorts after every row that has a time, by current stage (higher first) and then CVE ID descending.

| Parameter | Default | Values |
|---|---|---|
| `stage` | — (all) | The **current** stage, exact match. Values are the same as `min_stage` in `/api/hot`: `disclosed`, `patch`, `analysis`, `poc`, `exploited`, `kev`, or a code (`DIS` etc.), or the full type name. Case-insensitive. An empty or unknown value is a 400 (`param: "stage"`) |
| `year` | — (all) | The year in the CVE ID (`CVE-<year>-…`), from 1999 up to the current UTC year + 1. `0`, an empty value or a non-integer is a 400 (`param: "year"`) |
| `tag` | — | Same as `/api/hot`: repeatable, must match all, at most 5 distinct slugs (comma syntax isn't supported; `a,b` is treated as one unknown slug) |
| `include_rejected` | `false` | `true/false/1/0` (empty = true) |
| `limit` | 50 | 1–200 |
| `cursor` | — | the previous page's `next_cursor` (opaque; a `/api/hot` cursor doesn't work here and vice versa). An empty or invalid value is a 400 |

There's no `offset`; page with `cursor` only. Unknown parameters and repeated non-`tag` parameters are a 400, in the same error format as above.
`Cache-Control: public, max-age=60` with an `ETag` (`If-None-Match` → 304), same as `/api/hot`.

Response:

| Field | Description |
|---|---|
| `stage` / `stage_code` | The stage filter (full type name / code); `null` when there's no filter |
| `year` | The year filter; `null` when there's no filter |
| `tags` | The normalized tag filter (vocabulary order; `[]` when there's no filter) |
| `include_rejected`, `limit` | The values actually used |
| `rows` | Exactly the same structure as the `/api/hot` rows (including `tags` and `researchers_7d`); `pinned` is always `false` |
| `next_cursor` | A string when there's another page, otherwise `null` |
| `generated_at` | Generation time |

Rows with an unknown time: `transition` is `{"type":"","code":"","precision":"unknown","source":null,"event_id":null,"at":null}`,
`days_since_disclosure` is `null`, and no entry in `slots` has `latest: true`. These rows only appear on this endpoint (`/api/hot` rows always have a time).

Example (`?stage=kev&limit=1`, test data; the 6 `slots` entries are omitted, same structure as `/api/hot`):

```json
{
  "stage": "kev_added",
  "stage_code": "KEV",
  "year": null,
  "tags": [],
  "include_rejected": false,
  "limit": 1,
  "rows": [
    {
      "cve_id": "CVE-2026-1001",
      "title": null,
      "title_zh": null,
      "products": [
        {"vendor": "Barracuda Networks", "product": "Email Security Gateway (ESG)"},
        {"vendor": "Barracuda Networks", "product": "Load Balancer ADC"}
      ],
      "product_count": 3,
      "stage": "kev_added",
      "stage_code": "KEV",
      "is_rejected": false,
      "transition": {
        "type": "kev_added",
        "code": "KEV",
        "at": "2026-11-11T00:00:00Z",
        "precision": "day",
        "source": "kev",
        "event_id": 7
      },
      "slots": ["…"],
      "disclosed_at": null,
      "days_since_disclosure": null,
      "poc_sources": 0,
      "tags": [],
      "researchers_7d": 0,
      "pinned": false
    }
  ],
  "next_cursor": "dnwxNzk0MzU1MjAwMDAwMDAwfDZ8Q1ZFLTIwMjYtMTAwMQ",
  "generated_at": "2026-11-13T01:00:00Z"
}
```

### `GET /api/discussed`

Added 2026-11-14. "Discussed by researchers": CVEs that allowlisted researchers posted about on X in the last 7 days, ordered by `researchers_7d` (distinct authors) descending,
ties broken by the more recent latest post, then CVE ID ascending. **Only the count is public**; post content is for signed-in users only (`GET /api/posts/{cve}`, see the appendix at the end).
CVEs that are only mentioned in posts and have just a placeholder row in the database are listed too (`stage`, `stage_code` and `transition` are `null`, and `slots` are all `none`).

| Parameter | Default | Description |
|---|---|---|
| `limit` | 50 | 1–200 |
| `offset` | 0 | 0–10000 |

Row fields are the same as `/api/hot` rows (`stage`/`stage_code`/`transition` can be `null`), plus `researchers_7d` (≥1).
`next_offset` is the next page's `offset` when there's another page, otherwise `null`. Cache: `public, max-age=60`.

```sh
curl -s 'https://api.nday.land/v1/discussed?limit=20' | jq '.rows[] | {cve_id, researchers_7d}'
```

Example (test database, excerpt of the third row, a CVE that is only mentioned in posts):

```json
{"window":"7d","limit":50,"offset":0,"rows":[…,
  {"cve_id":"CVE-2026-8881","title":null,"title_zh":null,"products":[],"product_count":0,"stage":null,"stage_code":null,
   "is_rejected":false,"transition":null,"slots":[{"code":"DIS","type":"disclosed","state":"none","at":null,"not_after":null,"implied_by":null,"latest":false},…],
   "disclosed_at":null,"days_since_disclosure":null,"poc_sources":0,"tags":[],"researchers_7d":1},…],
 "next_offset":null,"generated_at":"2026-11-13T01:00:00Z"}
```

### `GET /api/vuln/{cve}`

The CVE ID is case-insensitive and is output in canonical uppercase. A malformed ID is a 400; one that doesn't exist is a 404.

- `events`: all events, ordered by effective time ascending, followed by the ones with unknown time (by stage, then id). `detail` is the source's original JSON.
- `slots`: the usual slot fields plus `precision`, `days_since_disclosure`, `event_ids` and `sources`.
- `state`: the materialized row (matches the lists; can be one refresh behind `events`; `null` when there are no events).
- Panels: `patches` (patch advisories such as GHSA: package, affected range, fixed version, fix commits), `poc` (always 3 entries),
  `kev`, `cvss` (the CVE record is preferred, with `source` as `cvelist:cna` / `cvelist:adp:<name>`; otherwise `ghsa`),
  `ssvc` (CISA-ADP), `cwes` (deduplicated across sources, names from GHSA), `raw_records` (raw records you can download) and
  `rejection` (the reason for a REJECTED record).
- `classification` (added 2026-11-14; additive only: none of the fields above or their values change): the CWEs and CVSS scores for this CVE from the classification layer (`vuln_cwe` / `vuln_cvss`,
  rules in `docs/nvd.md`), each with its provenance. Always an object; both arrays are empty when there's no classification data.
  - `cwe[]`: `id` (`CWE-<n>`, ascending by number) and `sources[]` (`source`, `source_org`; sorted by priority, then `source_org`).
  - `cvss[]`: `version` (`2.0` `3.0` `3.1` `4.0`, newer versions first), `vector`, `base_score` (the source's original value; `null` if missing or outside 0–10; nday doesn't compute scores),
    `severity` (the source's original text, can be `null`), `source` and `source_org`. When one version has several sources they're sorted by priority.
  - `source`: `cve-cna` (the CNA container of the CVE record; `source_org` is the CNA short name), `cve-adp` (an ADP container such as `CISA-ADP`),
    `nvd-primary` (NVD's own analysis; `source_org` is `nvd@nist.gov`), `nvd-secondary` (CNA/ADP data that NVD republishes;
    `source_org` is NVD's source identifier, an email or a UUID) and `ghsa` (`source_org` is the GHSA ID).
    Priority: `cve-cna` > `cve-adp` > `nvd-primary` > `nvd-secondary` > `ghsa`.
  - How it relates to `cvss` / `cwes`: those two older fields are still derived from the event details under the old rules (one "display" score, and CWEs with names).
    `classification` is the complete per-source list, and NVD data appears only here.
  - If a source marks the record rejected or withdrawn (CVE record REJECTED, NVD `Rejected`, GHSA withdrawn), that source contributes no entries. To tell whether a CVE is rejected, look at `is_rejected`.
- `tags` (added 2026-11-14; additive only; always an array): tags **nday derives itself by fixed rules** (`docs/tags.md`). They aren't given by NVD, CNAs or any other source,
  and a rejected CVE has no tags. Each entry has `slug`, `dimension` (`type` `access` `exploit` `product` `product-type` `ecosystem`;
  `product` and `product-type` since rule version 2), `origin` (`rule` = derived by rules;
  `staff` is reserved for manual tags later), `rule_version` and `basis` (the evidence):
  - type: `{"cwe": [{"id": "CWE-502", "sources": [{"source": "cve-cna", "source_org": "apache"}]}]}` (source values are the same as in `classification`);
  - access: `{"cvss": {"version": "3.1", "vector": "CVSS:3.1/…", "source": "cve-adp", "source_org": "CISA-ADP", "metrics": ["AV:N", "PR:N", "UI:N"]}}`;
  - exploit: `{"events": [{"source": "metasploit", "type": "poc_published", "keys": ["exploit/…"], "count": 5}]}`; for ransomware there's also
    `known_ransomware_campaign_use`;
  - ecosystem: `{"advisories": [{"id": "GHSA-…", "ecosystem": "maven", "packages": ["…"]}]}`;
  - product and product type (rule version 2): `affected` = the matched affected products (the `vendor` and `product` text from the CVE record, sorted and deduplicated, at most 10 entries)
    and `affected_count` (total matches); `cpe` = the matched CPE names (`part`/`vendor`/`product` that **NVD analysts** marked vulnerable,
    unescaped and lowercased, at most 10 entries) and `cpe_count`. A tag can have either kind of evidence or both. A product type also has `products` (the product slugs that give that type) and
    `type_rules` (the type rule ids that give it, such as `vendor:tenda`). Example:
    `{"affected": [{"vendor": "D-Link", "product": "DAP-1325"}], "affected_count": 1, "type_rules": ["d-link:router"]}`.
    nday derives these tags from its own product registry. CPE is just one of the facts NVD provides; the tags don't come from NVD.
  `source_org`, `keys`, `packages`, `vendor`, `product` and the CPE segments are upstream text, so escape them when you display them.
- `credits` (added 2026-11-14; additive only; always an array, `[]` when there are none): the people, organizations or tools the upstream record credits, **listed as the source wrote them**.
  nday doesn't verify them, merge different spellings or deduplicate across sources (the same name in two sources is two entries, each with its `source`). They're read from the latest raw record:
  `cvelist` = `credits[]` (`value`) in the CNA container of the CVE's latest CVE record; `ghsa` = `credits[]` of every GitHub advisory whose latest version still points at the CVE and isn't withdrawn,
  taking only `user.login` (no avatar, profile or other links). Order: `cvelist` first, then by GHSA ID, each keeping the source's order. Each entry has:
  - `role`: one of `finder` `reporter` `analyst` `coordinator` `remediation_developer` `remediation_reviewer`
    `remediation_verifier` `tool` `sponsor` `credit`. The source's types (`remediation developer` in CVE JSON 5, `remediation_developer` in GHSA, and so on) map to the value of the same name;
    a missing type, `other` or an unrecognized type becomes `credit`;
  - `type`: the source's original type (trimmed, at most 64 characters), or `null` if there isn't one;
  - `name`: the source's original text (trimmed, runs of whitespace and control characters collapsed into one space, truncated at 256 characters and ending in `…`);
  - `source`: `cvelist` / `ghsa`. `key`: which raw record it came from (a CVE ID or GHSA ID, `/raw/{source}/{key}.json`).

  Within one source, identical (`role`, `name`) pairs are kept once, and each source contributes at most 25 entries. `name` and `type` are free text from a third party (they may contain emails, URLs or markup),
  so escape them when you display them and don't treat them as links.

```sh
curl -s https://api.nday.land/v1/vuln/CVE-2026-102895 | jq .events
curl -s https://api.nday.land/v1/vuln/CVE-2018-0125 | jq .classification
curl -s https://api.nday.land/v1/vuln/CVE-2026-52760 | jq .credits
```

`classification` example (local development database, CVE-2018-0125: a sample of the CVE record + the NVD 2018 data feed):

```json
{
  "cwe": [
    {
      "id": "CWE-20",
      "sources": [
        {"source": "cve-cna", "source_org": "cisco"},
        {"source": "nvd-primary", "source_org": "nvd@nist.gov"},
        {"source": "nvd-secondary", "source_org": "psirt@cisco.com"}
      ]
    }
  ],
  "cvss": [
    {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "base_score": 9.8, "severity": "CRITICAL",
     "source": "cve-adp", "source_org": "CISA-ADP"},
    {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "base_score": 9.8, "severity": "CRITICAL",
     "source": "nvd-primary", "source_org": "nvd@nist.gov"},
    {"version": "3.1", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "base_score": 9.8, "severity": "CRITICAL",
     "source": "nvd-secondary", "source_org": "134c704f-9b21-4f2e-91b3-4a467353bcc0"},
    {"version": "2.0", "vector": "AV:N/AC:L/Au:N/C:C/I:C/A:C", "base_score": 10.0, "severity": "HIGH",
     "source": "nvd-primary", "source_org": "nvd@nist.gov"}
  ]
}
```

Example (long strings truncated with `…`; the `detail` of ghsa / kev keeps only some of its keys):

```json
{
  "cve_id": "CVE-2026-102895",
  "title": "GPUStack: Authentication bypass via trusted loopback source (reverse-proxy TCP peer or X-GPUStack-Real-IP header) grants…",
  "title_zh": null,
  "description": "GPUStack is an open-source GPU cluster manager for AI model serving and GPU instance provisioning. Prior to 2.2.0, get_c…",
  "summary_zh": null,
  "published_at": "2026-11-04T21:16:59.842Z",
  "modified_at": "2026-11-10T04:55:56.196Z",
  "first_seen_at": "2026-11-12T13:49:44.723449Z",
  "assigner": "GitHub_M",
  "is_rejected": false,
  "rejection": null,
  "aliases": [
    {
      "alias": "GHSA-gj9m-f8ph-pmhr",
      "type": "ghsa"
    }
  ],
  "products": [
    {
      "vendor": "GPUStack",
      "product": "GPUStack"
    }
  ],
  "stage": "kev_added",
  "stage_code": "KEV",
  "slots": [
    {
      "code": "DIS",
      "type": "disclosed",
      "state": "known",
      "at": "2026-11-04T21:16:59.842Z",
      "not_after": null,
      "implied_by": null,
      "latest": false,
      "precision": "exact",
      "days_since_disclosure": 0,
      "event_ids": [
        4012
      ],
      "sources": [
        "cvelist"
      ]
    },
    {
      "code": "PAT",
      "type": "patch_released",
      "state": "unknown",
      "at": null,
      "not_after": null,
      "implied_by": null,
      "latest": false,
      "precision": "unknown",
      "days_since_disclosure": null,
      "event_ids": [
        18977
      ],
      "sources": [
        "ghsa"
      ]
    },
    {
      "code": "ANA",
      "type": "analysis_published",
      "state": "none",
      "at": null,
      "not_after": null,
      "implied_by": null,
      "latest": false,
      "precision": null,
      "days_since_disclosure": null,
      "event_ids": [],
      "sources": []
    },
    {
      "code": "POC",
      "type": "poc_published",
      "state": "none",
      "at": null,
      "not_after": null,
      "implied_by": null,
      "latest": false,
      "precision": null,
      "days_since_disclosure": null,
      "event_ids": [],
      "sources": []
    },
    {
      "code": "ITW",
      "type": "exploited_in_wild",
      "state": "implied",
      "at": null,
      "not_after": "2026-11-09T00:00:00Z",
      "implied_by": "kev_added",
      "latest": false,
      "precision": null,
      "days_since_disclosure": null,
      "event_ids": [],
      "sources": []
    },
    {
      "code": "KEV",
      "type": "kev_added",
      "state": "known",
      "at": "2026-11-09T00:00:00Z",
      "not_after": null,
      "implied_by": null,
      "latest": true,
      "precision": "day",
      "days_since_disclosure": 5,
      "event_ids": [
        7
      ],
      "sources": [
        "kev"
      ]
    }
  ],
  "transition": {
    "type": "kev_added",
    "code": "KEV",
    "at": "2026-11-09T00:00:00Z",
    "precision": "day",
    "source": "kev",
    "event_id": 7
  },
  "disclosed_at": "2026-11-04T21:16:59.842Z",
  "days_since_disclosure": 5,
  "state": {
    "stage": "kev_added",
    "stage_code": "KEV",
    "stage_rank": 6,
    "has_patch": true,
    "has_analysis": false,
    "has_poc": false,
    "exploited": true,
    "in_kev": true,
    "is_rejected": false,
    "disclosed_at": "2026-11-04T21:16:59.842Z",
    "patch_at": null,
    "analysis_at": null,
    "poc_at": null,
    "exploited_at": "2026-11-09T00:00:00Z",
    "kev_at": "2026-11-09T00:00:00Z",
    "last_transition_at": "2026-11-09T00:00:00Z",
    "last_transition_type": "kev_added",
    "event_count": 3,
    "poc_sources": 0
  },
  "events": [
    {
      "id": 4012,
      "type": "disclosed",
      "code": "DIS",
      "source": "cvelist",
      "url": "https://www.cve.org/CVERecord?id=CVE-2026-102895",
      "occurred_at": "2026-11-04T21:16:59.842Z",
      "observed_at": "2026-11-12T13:59:01.599748Z",
      "effective_at": "2026-11-04T21:16:59.842Z",
      "is_backfill": true,
      "precision": "exact",
      "dedupe_key": "",
      "detail": {
        "kev": {
          "reference": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog?field_cve=CVE-2026-102895",
          "date_added": "2026-11-09"
        },
        "cvss": {
          "source": "cna",
          "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          "version": "3.1",
          "base_score": 9.8,
          "base_severity": "CRITICAL"
        },
        "ssvc": {
          "timestamp": "2026-11-05T00:00:00+00:00",
          "automatable": "yes",
          "exploitation": "active",
          "technical_impact": "total"
        },
        "state": "PUBLISHED",
        "date_published": "2026-11-04T21:16:59.842Z",
        "assigner_short_name": "GitHub_M"
      }
    },
    {
      "id": 7,
      "type": "kev_added",
      "code": "KEV",
      "source": "kev",
      "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      "occurred_at": "2026-11-09T00:00:00Z",
      "observed_at": "2026-11-12T13:49:44.723449Z",
      "effective_at": "2026-11-09T00:00:00Z",
      "is_backfill": true,
      "precision": "day",
      "dedupe_key": "",
      "detail": {
        "precision": "day",
        "date_added": "2026-11-09",
        "due_date": "2026-11-12",
        "forensic_triage": "Yes",
        "known_ransomware_campaign_use": "Unknown",
        "cwes": [
          "CWE-287",
          "CWE-290",
          "CWE-346"
        ],
        "…": "(more keys)"
      }
    },
    {
      "id": 18977,
      "type": "patch_released",
      "code": "PAT",
      "source": "ghsa",
      "url": "https://github.com/advisories/GHSA-gj9m-f8ph-pmhr",
      "occurred_at": null,
      "observed_at": "2026-11-12T15:00:15.227102Z",
      "effective_at": null,
      "is_backfill": true,
      "precision": "unknown",
      "dedupe_key": "GHSA-gj9m-f8ph-pmhr",
      "detail": {
        "ghsa_id": "GHSA-gj9m-f8ph-pmhr",
        "severity": "critical",
        "packages": [
          {
            "name": "gpustack",
            "ecosystem": "pip",
            "first_patched_version": "2.2.0",
            "vulnerable_version_range": "< 2.2.0"
          }
        ],
        "fix_commit_urls": [
          "https://github.com/gpustack/gpustack/pull/5346",
          "https://github.com/gpustack/gpustack/commit/53f42a6a553542974396d16a4ff6b12bcbedb48d"
        ],
        "advisory_published_at": "2026-11-09T22:15:27Z",
        "…": "(more keys)"
      }
    }
  ],
  "patches": [
    {
      "event_id": 18977,
      "source": "ghsa",
      "advisory_id": "GHSA-gj9m-f8ph-pmhr",
      "url": "https://github.com/advisories/GHSA-gj9m-f8ph-pmhr",
      "severity": "critical",
      "advisory_published_at": "2026-11-09T22:15:27Z",
      "packages": [
        {
          "ecosystem": "pip",
          "name": "gpustack",
          "affected_range": "< 2.2.0",
          "fixed_version": "2.2.0"
        }
      ],
      "fix_commit_urls": [
        "https://github.com/gpustack/gpustack/pull/5346",
        "https://github.com/gpustack/gpustack/commit/53f42a6a553542974396d16a4ff6b12bcbedb48d"
      ],
      "source_code_location": "https://github.com/gpustack/gpustack"
    }
  ],
  "poc": [
    {
      "source": "exploitdb",
      "present": false,
      "items": []
    },
    {
      "source": "metasploit",
      "present": false,
      "items": []
    },
    {
      "source": "nuclei",
      "present": false,
      "items": []
    }
  ],
  "poc_sources": 0,
  "kev": {
    "event_id": 7,
    "added_at": "2026-11-09T00:00:00Z",
    "precision": "day",
    "date_added": "2026-11-09",
    "due_date": "2026-11-12",
    "known_ransomware_campaign_use": "Unknown",
    "forensic_triage": "Yes",
    "required_action": "Apply mitigations in accordance with vendor instructions, ensuring compliance with CISA’s BOD 26-04 Prioritizing Securit…",
    "notes": "This vulnerability affects an open-source component, third-party library, protocol, or proprietary implementation that c…",
    "vulnerability_name": "GPUStack Improper Authentication Vulnerability",
    "vendor_project": "GPUStack",
    "product": "GPUStack",
    "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"
  },
  "cvss": {
    "score": 9.8,
    "severity": "CRITICAL",
    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "version": "3.1",
    "source": "cvelist:cna"
  },
  "ssvc": {
    "exploitation": "active",
    "automatable": "yes",
    "technical_impact": "total",
    "timestamp": "2026-11-05T00:00:00+00:00",
    "source": "cvelist:CISA-ADP"
  },
  "cwes": [
    {
      "id": "CWE-287",
      "name": "Improper Authentication",
      "sources": [
        "kev",
        "ghsa"
      ]
    },
    {
      "id": "CWE-290",
      "name": "Authentication Bypass by Spoofing",
      "sources": [
        "kev",
        "ghsa"
      ]
    },
    {
      "id": "CWE-346",
      "name": "Origin Validation Error",
      "sources": [
        "kev",
        "ghsa"
      ]
    }
  ],
  "raw_records": [
    {
      "source": "cvelist",
      "key": "CVE-2026-102895",
      "path": "/raw/cvelist/CVE-2026-102895.json",
      "fetched_at": "2026-11-12T13:59:01.599748Z"
    },
    {
      "source": "ghsa",
      "key": "GHSA-gj9m-f8ph-pmhr",
      "path": "/raw/ghsa/GHSA-gj9m-f8ph-pmhr.json",
      "fetched_at": "2026-11-12T15:00:15.227102Z"
    },
    {
      "source": "kev",
      "key": "CVE-2026-102895",
      "path": "/raw/kev/CVE-2026-102895.json",
      "fetched_at": "2026-11-12T13:49:44.723449Z"
    }
  ]
}
```

### `GET /api/sources`

Status of each collector (`last_error` is at most 300 characters), totals, the number of CVE-record backfills still pending, and the data update time (the latest successful collection).
Since 2026-11-14 `collectors` has 7 entries: the last is `nvd` (the NVD data feed; it provides classification data only and produces no events; the example below is from before it was added).

```json
{
  "collectors": [
    {
      "name": "cvelist",
      "status": "ok",
      "ok": true,
      "last_run_at": "2026-11-12T15:19:46.457931Z",
      "last_success_at": "2026-11-12T15:19:46.457931Z",
      "last_error": null
    },
    {
      "name": "kev",
      "status": "ok",
      "ok": true,
      "last_run_at": "2026-11-12T14:00:17.413747Z",
      "last_success_at": "2026-11-12T14:00:17.413747Z",
      "last_error": null
    },
    {
      "name": "ghsa",
      "status": "ok",
      "ok": true,
      "last_run_at": "2026-11-12T15:00:26.808909Z",
      "last_success_at": "2026-11-12T15:00:26.808909Z",
      "last_error": null
    },
    {
      "name": "exploitdb",
      "status": "ok",
      "ok": true,
      "last_run_at": "2026-11-12T15:18:49.171627Z",
      "last_success_at": "2026-11-12T15:18:49.171627Z",
      "last_error": null
    },
    {
      "name": "metasploit",
      "status": "ok",
      "ok": true,
      "last_run_at": "2026-11-12T15:18:54.765045Z",
      "last_success_at": "2026-11-12T15:18:54.765045Z",
      "last_error": null
    },
    {
      "name": "nuclei",
      "status": "ok",
      "ok": true,
      "last_run_at": "2026-11-12T15:19:38.620486Z",
      "last_success_at": "2026-11-12T15:19:38.620486Z",
      "last_error": null
    }
  ],
  "collectors_ok": 6,
  "collectors_total": 6,
  "vulns": 45940,
  "events": 58539,
  "cvelist_backfill_backlog": 27925,
  "data_updated_at": "2026-11-12T15:19:46.457931Z",
  "state_refreshed_at": "2026-11-13T02:06:36.567284Z",
  "state_error": null,
  "generated_at": "2026-11-13T02:06:48.352046Z"
}
```

### `GET /api/stats`

Counts by current stage (all 6 stages are listed, including zeros; rejected CVEs are included, see also `rejected`) plus counts for each feature.

```json
{
  "vulns": 45940,
  "with_events": 45939,
  "by_stage": [
    {
      "stage": "disclosed",
      "code": "DIS",
      "count": 15059
    },
    {
      "stage": "patch_released",
      "code": "PAT",
      "count": 221
    },
    {
      "stage": "analysis_published",
      "code": "ANA",
      "count": 0
    },
    {
      "stage": "poc_published",
      "code": "POC",
      "count": 28880
    },
    {
      "stage": "exploited_in_wild",
      "code": "ITW",
      "count": 0
    },
    {
      "stage": "kev_added",
      "code": "KEV",
      "count": 1779
    }
  ],
  "rejected": 279,
  "with_patch": 223,
  "with_analysis": 0,
  "with_poc": 29758,
  "exploited": 1779,
  "in_kev": 1779,
  "state_refreshed_at": "2026-11-13T02:06:36.567284Z",
  "generated_at": "2026-11-13T02:06:48.364069Z"
}
```

### `GET /api/search?q=&limit=`

`limit` defaults to 20, max 50. `q` is at most 100 characters.

- Input that looks like a CVE ID (`CVE-2026-1028`, `cve2026`, `2026-1028`) → exact/prefix match on the ID (`kind: "cve_id"`, exact matches first).
- A GHSA ID → exact match on aliases (`kind: "alias"`).
- Anything else → case-insensitive substring match on title, title_zh, vendor and product (`kind: "text"`; `%`, `_` and `\` are literal),
  most recently changed first. Fewer than 2 characters isn't queried (`kind: "too_short"`), and an empty string gives `kind: "empty"`.
- `truncated: true` means there are more matches.
- `tag` (repeatable, must match all; validated like `/api/hot`): limits any of the results above to CVEs that have all those tags. If `q` is empty but there's a `tag`, it lists every CVE with those tags,
  most recently changed first (`kind: "tags"`). The response has `tags` (the normalized filter), and each row has `tags` (added 2026-11-14; additive only).

### `GET /api/tags`

The tag vocabulary (`docs/tags.md`) and the number of CVEs per tag. No parameters. Counts are precomputed (rebuilt after every tagging run that changed tags, so they can be at most one collection behind);
`counts_at` is when they were computed (`null` if they never have been). `label` is the English name and `rule` is the English description of the rule. Product tags also have `product_types`
(the product type slugs that come with a match on that product; since 2026-11-14, additive only).

```json
{
  "note": "Tags are nday's own derivation from CWE ids, CVSS vectors, CISA KEV, Exploit-DB, Metasploit, nuclei and GitHub advisory data; …",
  "rule_version": 2,
  "dimensions": ["type", "access", "exploit", "product", "product-type", "ecosystem"],
  "tags": [
    {"slug": "command-injection", "dimension": "type", "label": "command injection",
     "rule": "One of CWE-77, CWE-78, CWE-88 is stated for the CVE by any source (CVE record CNA/ADP, NVD, GitHub advisory).", "count": 8196},
    {"slug": "remote-unauth", "dimension": "access", "label": "remote, unauthenticated", "rule": "The best CVSS v4.0/v3.x vector has AV:N, PR:N and UI:N (…)", "count": 69456},
    {"slug": "windows", "dimension": "product", "label": "Windows", "product_types": ["operating-system"],
     "rule": "An affected product of the CVE (CVE record) or a vulnerable CPE name given by NVD's analysts matches nday's registry entry for Windows.", "count": 8423}
  ],
  "counts_at": "2026-11-13T17:17:28.787063Z"
}
```

(Counts are from the full local development database, 2026-11-14.)

```json
{
  "query": "barracuda",
  "kind": "text",
  "rows": [
    {
      "cve_id": "CVE-2026-116606",
      "title": "Authentication Bypass Allows Global Configuration Restore in Barracuda Email Security Gateway",
      "title_zh": null,
      "products": [
        {
          "vendor": "Barracuda Networks",
          "product": "Barracuda Email Security Gateway (ESG)"
        }
      ],
      "product_count": 1,
      "stage": "kev_added",
      "stage_code": "KEV",
      "last_transition_at": "2026-11-10T00:00:00Z",
      "is_rejected": false
    },
    {
      "cve_id": "CVE-2026-111560",
      "title": "OS Command Injection in Barracuda Appliances",
      "title_zh": null,
      "products": [
        {
          "vendor": "Barracuda Networks",
          "product": "Multiple Products"
        },
        {
          "vendor": "Barracuda Networks",
          "product": "Barracuda Email Security Gateway (ESG)"
        }
      ],
      "product_count": 7,
      "stage": "kev_added",
      "stage_code": "KEV",
      "last_transition_at": "2026-11-10T00:00:00Z",
      "is_rejected": false
    }
  ],
  "truncated": true
}
```

### `GET /api/affected/suggest?q=&limit=`

Vendor and product name suggestions (used by the "follow" search box on the first-login page; see `docs/follows.md`). `limit` defaults to 8, max 20. `q` is normalized like search
(trimmed, runs of whitespace collapsed, at most 100 characters) and then lowercased. The returned `query` and the server's cache key are this form (`Forti` and ` forti ` are the same query).
`kind` uses the same vocabulary as search: `"text"` means a lookup was done; fewer than 3 characters gives `"too_short"` and an empty string gives `"empty"`. Neither of those queries the database, and `rows` is `[]` (200).

- It does a case-insensitive substring match on the vendor and product columns of `affected`, and groups the matched names by `lower()`:
  one name gives one row, regardless of case and regardless of whether it's a vendor or a product.
- `name`: the most common spelling in the group (ties go to the lowest byte order, so uppercase wins). `kind`: `"vendor"` if the name has ever appeared as a vendor, `"product"` if only as a product.
  `count`: the number of distinct vulnerabilities with that name among the matched rows. It equals the number of vulnerabilities with an `affected` row whose vendor or product is **exactly** that name (case-insensitive),
  which is the number of vulnerabilities that following this name would match (the name contains the query, so all of those rows pass the filter; verified in `internal/site/suggest_test.go`).
- The query runs ILIKE on the raw vendor/product columns first (the pg_trgm GIN index from migration 0003 can be used) and groups only the matched rows by `lower(name)`.
  `EXPLAIN ANALYZE` on a local copy of the data on 2026-11-14 (`q=for`): 12.9 ms execution (the earlier version picked names first and then joined the whole `affected` table on `lower()`: 246 ms).
- There's no per-client rate limit. None of the `/api/*` data endpoints has one right now (there's no rate limiter in `internal/web`). Like search, it relies on the in-process cache (the same query hits the database once per 30 seconds, and concurrent requests are coalesced).
- Ordered by `count` descending, then by name. All the data is public (`affected` is written only from public sources, and vulnerability pages and search already show it). Like search, it's publicly cached and doesn't read cookies.
- Errors: `400 bad_request` (`param` is `limit`, `q` or an unknown parameter name).

```json
{
  "query": "forti",
  "kind": "text",
  "rows": [
    {"name": "Fortinet", "kind": "vendor", "count": 169},
    {"name": "FortiManager", "kind": "product", "count": 47},
    {"name": "FortiAnalyzer", "kind": "product", "count": 38}
  ]
}
```

(The example numbers are from the local database on 2026-11-14, with `limit=3`.)

### `GET /raw/{source}/{key}.json`

The latest version of a record from one source, output as is (rendered from jsonb). `source` is one of cvelist, kev, ghsa, exploitdb,
metasploit, nuclei, nvd (the NVD key is the CVE ID and the content is that entry's `cve` object from the NVD data feed; `raw_records` doesn't list it,
so build `/raw/nvd/<CVE>.json` yourself). `key` is a CVE ID, GHSA ID, EDB ID, the full Metasploit module name (including `/`) or a Nuclei template id.
For links, just use `raw_records[].path` (`/raw/...`) from `/api/vuln` (`/v1/vuln`). On the API host, `GET /raw/{source}/{key}.json`
is an alias of `/v1/raw/...` (same handler, same response), so resolving it against the API origin works. Resolved against the website host, it gets a 308 to `/v1/raw/...`.

```
$ curl -sD- https://api.nday.land/v1/raw/ghsa/GHSA-gj9m-f8ph-pmhr.json
HTTP/1.1 200 OK
Cache-Control: public, max-age=3600
Content-Length: 6909
Content-Type: application/json; charset=utf-8
Etag: "c7eb19dd3ebcfa97ac3513f7c09865eda75ca67dcc6da207336ec2a11115a972"
Last-Modified: Thu, 12 Nov 2026 15:00:15 GMT

{"url": "https://api.github.com/advisories/GHSA-gj9m-f8ph-pmhr", "cvss": {"score": 9.8, ...
```

## Running

| Variable | Default | Description |
|---|---|---|
| `NDAY_DATABASE_URL` | — | Required |
| `NDAY_LISTEN` | `127.0.0.1:8080` | `--listen` takes precedence |
| `NDAY_DB_POOL_SIZE` | 8 | 1–64; every connection uses a read-only transaction and an 8 s `statement_timeout` |
| `NDAY_TLS_CERT` / `NDAY_TLS_KEY` | — | Same as `--tls-cert` / `--tls-key`: serve HTTPS directly (TLS 1.2 minimum). You must set both |
| `NDAY_TLS_CLIENT_CA` | — | Same as `--tls-client-ca`: require and verify client certificates issued by this CA (Cloudflare Authenticated Origin Pulls) |
| `NDAY_PUBLIC_URL` | — | The website origin (such as `https://www.nday.land`), used for page links and the `docs` field in the API index. An invalid value is ignored with a warning |
| `NDAY_API_URL` | — | The API host origin (such as `https://api.nday.land`). It must be an http(s) origin with no userinfo, path, query or fragment, or startup fails. Unset = single-host mode. If it's the same as `NDAY_PUBLIC_URL`, you get a warning and it runs in single-host mode. If it's set but `NDAY_PUBLIC_URL` isn't, you get a warning |

The same process also serves the HTML pages (`internal/webui`: `/`, `/vuln`, `/vuln/{cve}`, `/src`, `/stats`, `/about`, `/feed.xml`,
`/static/…`), on the website host only. Pages ignore unknown query parameters (so `utm_*` is fine), while this API still returns 400 for them. 404s under `/api/` and `/raw/` are still JSON.
The `curl` examples and "raw JSON" links on the pages point to `NDAY_API_URL/v1/...` when `NDAY_API_URL` is set, and to `NDAY_PUBLIC_URL/api/...` otherwise.

Access and error logs can be written to files (`NDAY_LOG_DIR`); see `docs/logging.md` for the format and fields.

Timeouts: ReadHeader 5 s, Read 10 s, Write 30 s, Idle 120 s, request context 10 s, max request header 32 KiB.
On SIGTERM/SIGINT it stops accepting connections and waits up to 20 s for in-flight requests. The log (slog, stderr) has one line per request: method, path,
query, status, bytes, dur_ms and cf_ip (`CF-Connecting-IP`, used only as a log field). No other request headers are logged.
It doesn't write to disk.

---

## Appendix: account and login endpoints (see also `docs/auth.md`)

When login is configured, the same process also serves `/auth/*`, `/account/*` and `GET /api/me` on the **website host**
(not on the API host, and not part of the public API at `https://api.nday.land/v1`).
These are the only routes in this API that read cookies and the only ones with POST. Every response has `Cache-Control: no-store`.
Everything above is unaffected: no cookies are read, no `Set-Cookie` is sent, and cache headers don't change. Query parameter values under `/auth/` are logged as
`REDACTED` in the access log, and rate limiting on the login endpoints uses `CF-Connecting-IP`. Every response also carries
`Permissions-Policy: publickey-credentials-create=(self), publickey-credentials-get=(self)`.
Endpoints, request/response examples and error codes are in `docs/auth.md` §3. When login isn't configured these routes don't exist (`/api/me` is the JSON 404 described above).

Contract changes that pages must follow:

- These routes only accept requests whose `Host` is the public origin host (otherwise `421 wrong_host`). GET routes no longer accept HEAD (405, `Allow: GET`).
- `GET /api/me` has a new `session` field when signed in: `{"created_at","recent_sign_in","recent_sign_in_until"}`. It also has `passkeys.max_per_user`.
- Follows (`docs/follows.md`): `user.follows` in `GET /api/me` (`[{"term","label"}]`), `POST /account/follows` (replaces the whole list) and
  `POST /account/follows/match` (which CVEs affect the followed vendors/products). The OAuth callback for a newly created account now does a 303 to the first-login page `/welcome` (`?next=` is the original return path).
- New ticket intent `"reauth"`: signing in to the same account from an already signed-in browser without a ticket no longer refreshes the session (it doesn't count as a recent sign-in). To satisfy `reauth_required` you must sign in again with a reauth ticket or a passkey. The same session token is also rate limited (`429 rate_limited`).
- Linking an identity no longer uses `?intent=link&csrf=…`. First `POST /auth/{provider}/ticket` (`{"intent":"link","return":"/path"}`, with `X-CSRF-Token`), then navigate to the returned `start_url` (single use, 2 minutes). To switch accounts while signed in, use `"intent":"switch"`.
- If an already signed-in browser starts a sign-in without a ticket and it would land on a different or new account, you get `?auth=signed_in_as_other` and the session is unchanged. There are also the callback results `reauth_required` and `suspended`.
- New error codes: `403 suspended` (a suspended user changing their handle, linking, or adding a passkey), `403 reauth_required` (adding a passkey, linking and deleting the account need a sign-in within the last 15 minutes), `409 last_usable_method`, `409 passkey_limit`, `400 display_name_reserved`, `429 signup_limit`, `403 ticket_required`/`ticket_invalid`, `503 busy`. `/api/me` and the signed-in endpoints are rate limited per address (`429 rate_limited`).

## Appendix: discussion endpoints (not part of the public data API)

When login is configured, the website host also serves per-vulnerability discussion endpoints `/api/discuss/*` and moderator endpoints `/api/mod/*` (`docs/discuss.md`), and the back office's `/api/admin/*` (staff only, POST with same origin + CSRF; among them the X allowlist and its candidates, `/api/admin/x/candidates/{id}/add|dismiss|restore`; documented in `docs/admin.md`, never on the API host and no data of it in `/v1`).
They read the session, they write, and responses vary by caller (`Cache-Control: no-store`). They are **not currently part of the public data API**:
they aren't on the API host (`https://api.nday.land/v1`), there's no `/v1/discuss`, and they aren't promised to stay stable for third parties. The endpoints above are unaffected.
Since 2026-11-15: `GET /api/discuss/{cve}` also returns comments to signed-out requests by default (the same public content a signed-in user with no role sees. The author's `display_name` has a value only for moderators and is always `null` for signed-out requests and ordinary signed-in users, who only get `handle` and `role`. All permission fields are false, and signed-out requests are also rate limited per address. With `NDAY_DISCUSS_GUEST_READ=off` it returns only the outline).
Top-level comments have an optional `purpose` (`analysis` / `reproduction` / `fix` / `detection` / `question`; can be set when posting and editing; new error code `400 bad_purpose`). See `docs/discuss.md` §3–§4.1.

## Appendix: researcher post endpoint (not part of the public data API)

Added 2026-11-14. When login is configured, the website host also serves `GET /api/posts/{cve}` (`internal/posts`), which the "Researcher discussion" section of the vulnerability page calls from a script.
It's the same kind as `/api/me` and `/api/discuss/*`: website host only (any other `Host` → `421 wrong_host`; it doesn't exist on the API host, which gives a JSON 404), GET only (anything else → 405 `Allow: GET`),
it reads the session cookie, and every response has `Cache-Control: private, no-store` + `Vary: Cookie`. It's rate limited per client address (burst of 120, then 1 request every 0.5 seconds, `429 rate_limited`).
Errors: `400 bad_cve`, `404 not_found` (`param: "cve"`, the vulnerability doesn't exist) and `503 busy` (the session lookup queue is full).

Signed out (or an invalid session): only the public count and an outline (at most 50 entries, newest first). Each entry has `author` (the @username stored in the post; `""` if it isn't valid),
`author_url` (`https://x.com/<author>`, or `null` when `author` is empty), a length bucket `size` (`s`/`m`/`l`) and a UTC date `day`.
There's no text, post id, post link, exact time, language or numeric author id:

```json
{"cve":"CVE-2026-102895","signed_in":false,"researchers_7d":3,"count":4,"posts":[],"outline":[
  {"author":"QzMarkerHandle","author_url":"https://x.com/QzMarkerHandle","size":"s","day":"2026-11-13"},
  {"author":"","author_url":null,"size":"s","day":"2026-11-12"},
  {"author":"QzSecondHandle","author_url":"https://x.com/QzSecondHandle","size":"l","day":"2026-11-11"},
  {"author":"QzMarkerHandle","author_url":"https://x.com/QzMarkerHandle","size":"s","day":"2026-11-05"}]}
```

Signed in: the posts themselves (also at most 50, newest first, only posts from currently enabled accounts; `author_url` is given only when the handle is valid, and `url` only accepts
`https://x.com/<handle|i/web>/status/<id>`, otherwise it's rebuilt from the post id in the `i/web` form). The text is untrusted; display it as plain text:

```json
{"cve":"CVE-2026-102895","signed_in":true,"researchers_7d":3,"count":4,"posts":[
  {"post_id":"1999000000000000001","author_handle":"QzMarkerHandle","author_url":"https://x.com/QzMarkerHandle",
   "text":"QZMARKER-TEXT-ONE PoC out for CVE-2026-102895","lang":"en","posted_at":"2026-11-13T00:00:00Z",
   "url":"https://x.com/QzMarkerHandle/status/1999000000000000001","links":[
     {"short_url":"https://t.co/QZSHORT01","final_url":"https://github.com/qzres/fix/commit/abc123/","host":"h.example","kind":"patch"},
     {"short_url":"https://t.co/QZSHORT02","final_url":"https://pbs.twimg.com/media/QZMEDIA.jpg","host":"h.example","kind":"media"},
     {"short_url":"https://t.co/QZSHORT03","final_url":"javascript:alert(5)","host":"h.example","kind":"other"}]},
  {"post_id":"1999000000000000099","author_handle":"\"><svg onload=QZEVILHANDLE>","author_url":null,
   "text":"QZMARKER-EVIL <script>alert(1)</script>\"><img src=x onerror=alert(2)> \u202eevil","lang":"en",
   "posted_at":"2026-11-12T22:00:00Z","url":"https://x.com/i/web/status/1999000000000000099","links":[]},…]}
```

`links` (added 2026-11-15; signed-in responses only): the post's resolved t.co links (rows in `x_post_link` with `status = 'ok'` and a `final_url`), in the order they appear in the post; `[]` if there are none.
Each entry has `short_url` (the t.co short link as it appears in the text), `final_url` (the final address, **untrusted**: clients should only make it a link if it's an http/https address), `host` and `kind`
(`media`/`quote`/`patch`/`code`/`poc`/`advisory`/`other`; see `docs/xposts.md`). Signed-out responses are unchanged (no `links`).
The public "related resources" section of the vulnerability page doesn't go through this endpoint. The server renders it directly (see `docs/xposts.md`, "Public visibility").

(Real output from the `TestPostsNotPublic` test, excerpted.) `GET /api/discuss/{cve}` has returned only the outline to signed-out requests since the same day. Since 2026-11-15 it returns the same public comment content as for signed-in users by default (with `NDAY_DISCUSS_GUEST_READ=off` it still returns only the outline); see `docs/discuss.md` §4.1. The rules for researcher posts (this section) are unchanged.


## Appendix: reader corrections endpoints (not part of the public data API)

Added 2026-11-15 (`internal/corrections`; details in `docs/corrections.md` §3). When login is configured, the website host also serves:

| Endpoint | Auth | Description |
|---|---|---|
| `POST /api/corrections/{cve}` | signed in, same origin + `X-CSRF-Token`, not suspended, has a handle, has accepted the current rules | Submit a correction: `{"category","body","evidence_url"?}`. Per-user token bucket + 24-hour cap + pending cap (`NDAY_CORRECTIONS_*`) |
| `GET /api/corrections/mine?cve=` | signed in (suspended users too) | The caller's own corrections and their status |
| `POST /api/corrections/item/{id}/accept` / `reject` | moderator or admin, same origin + CSRF | Accept (a public note is required) / reject (internal note optional); writes an audit log entry |

Same kind as `/api/discuss/*`: website host only (any other `Host` → `421 wrong_host`; it doesn't exist on the API host), reads the session cookie, every response has `Cache-Control: no-store` + `Vary: Cookie`, and it isn't promised to stay stable for third parties.
**The public data API (`/v1/*`) contains no correction data.** Accepted corrections appear only as a "revision history" in the vulnerability page's HTML (time, category, the public note the editor wrote, and the submitter's handle). Pending and rejected corrections, the submitter's original text, evidence links and internal notes never appear in any public response.
