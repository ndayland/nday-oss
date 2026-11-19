# Operational stats (access log rollup)

Implementation: `internal/stats` (classification in `classify.go`, line parsing in `parse.go`, daily aggregation in `aggregate.go`, the rollup transaction in `rollup.go`, the read API in `read.go`),
the command in `internal/cli/stats.go`, migration `migrations/0006_stats.sql`, and the scheduled job `deploy/systemd/nday-stats.{service,timer}`.
It uses only the standard library and pgx. The input is the access log written by `nday serve` (format in `docs/logging.md`).

## Command

```
nday stats-rollup [--dir DIR] [--day YYYY-MM-DD ...] [--all] [--dry-run]
```

| Flag | Description |
|---|---|
| `--dir` | The log directory; defaults to `NDAY_LOG_DIR`. If neither is set, it's a usage error (exit code 2) |
| (no `--day`/`--all`) | Processes every `access-*.log` whose (size, mtime) differs from what was recorded at the last successful rollup. The 10-minute scheduled job normally only recomputes "today" |
| `--day D` | Recomputes these dates (can be repeated), ignoring the recorded state |
| `--all` | Recomputes the date of every access log file in the directory (can't be combined with `--day`) |
| `--dry-run` | Reads files, computes, and writes to the database as usual, but rolls back every transaction: the database doesn't change (not even `stats_salt` is generated) |

For each day processed it prints one line: `<date> <recomputed|unchanged|no-file> files= lines= bad= partial= misfiled_in= misfiled_out= requests= pv= uv=`,
and a final line `days: N, visitor rows pruned: M`.

### How the rollup works

- **One transaction per day, recomputed from scratch**: `pg_advisory_xact_lock(0x6E647374)` → delete that day's rows from `stats_daily`, `stats_top`, and `stats_visitors`
  → write the new aggregates → record the file's size, mtime, and line count in `stats_files` → commit. There are no offsets, so you can interrupt and rerun at any time with the same result (idempotent).
- **Concurrency**: if two rollups run at the same time, they serialize per day on the same advisory lock. In automatic mode, whichever arrives second compares size/mtime again inside the lock, and if it sees the work is already done it skips it (`unchanged`).
- **Read-only log directory**: files are opened with `O_RDONLY`, and nothing in the directory is ever written, renamed, or deleted. The directory is also read-only in the systemd unit.
- A file is `fstat`ed first and read only up to that size: lines appended during the rollup are left for the next run (the recorded size matches what was actually read).
- **Fault tolerance**: lines that aren't a JSON object, whose `time` isn't RFC 3339, whose fields have the wrong types, that are empty, or that are longer than 64 KiB are counted as `bad`.
  A last line with no trailing newline that can't be parsed (it's being written) is counted as `partial`; a last line with no trailing newline that is complete is counted as usual. `\r\n` line endings are fine.
  If a file disappears after the directory was listed, it's skipped with a warning. Memory: lines are processed as a stream, apart from the day's aggregate tables (each top list holds at most 200,000 distinct keys) and the visitor set.
- **"Which day"**: a line belongs to the calendar date of its own `time` field in its own offset (`2026-11-12T20:30:00-05:00` belongs to 11-12).
  Normally that equals the date in the filename. When it doesn't, the line wins: it's counted as `misfiled_out` in its file and as `misfiled_in` on the day it belongs to.
  `stats_files.other_days` records the other dates that appear in a file, and when one of those days is recomputed this file is read too (only that day's lines are taken).
  When a file changes, the other dates it touches are also recomputed (at most twice per day per run).
- **After old logs are deleted**: stats already rolled up are kept (the data in the tables is kept permanently, and logs can be deleted as needed). If a day's own file is missing, that day is skipped (`no-file`)
  and isn't overwritten by stray misfiled lines from other files.
- **Retention of visitor rows**: at the end of each run, rows in `stats_visitors` older than "today (local timezone) − 90 days" are deleted, and visitor rows are no longer written when recomputing earlier dates.
  Unique visitor counts are kept permanently in `stats_daily`.

### Cost (measured)

A generated single-day file of 500,000 lines and 276.9 MB (about 554 bytes per line, all fields present), on a local machine (Apple Silicon, Docker PostgreSQL 16):

| Step | Time | Throughput |
|---|---|---|
| Parse + classify + aggregate | 1.39–1.61 s | ≈ 310–360k lines/s |
| Full recompute (including delete, COPY of 59k visitor rows, commit) | 1.57–1.71 s | ≈ 290–320k lines/s |

Peak resident memory of the whole test process (including generating the file) is about 32 MB (`/usr/bin/time -l`). To reproduce: `NDAY_STATS_BENCH=1 go test ./internal/stats/ -run TestThroughput -v`. A server CPU may be slower, so budget a few times that.
The scheduled job recomputes the whole of the current day's file every 10 minutes, so the cost of each run is proportional to the number of lines the day has so far (a few seconds per run at 500,000 lines a day).
The cost of `--all` is the sum of the lines in all the files.

## Tables (migration `0006_stats.sql`, only adds tables)

| Table | Contents | Retention |
|---|---|---|
| `stats_salt(id, salt bytea, created_at)` | A single row; a 32-byte random value generated at the first rollup, used for visitor hashes | Permanent; don't share it |
| `stats_files(file, day, size, mtime, lines, bad_lines, other_days, rolled_at)` | The state of each access log file at its last successful rollup | Permanent |
| `stats_daily(day, metric, dim, value)` | General daily counters, primary key (day, metric, dim) | Permanent |
| `stats_top(day, kind, key, value)` | At most 100 entries per kind per day, primary key (day, kind, key) | Permanent |
| `stats_visitors(day, visitor bytea(8), human)` | Hashes of visitors who viewed a page that day | 90 days |

## Classification rules (`classify.go`, all covered by table-driven tests)

**Host**: a `domain` starting with `api.` is the API host (the canonical host of `NDAY_API_URL`, i.e. `api.nday.land`). Everything else (`www.nday.land`, and `""` for anything that doesn't match a configured host, such as the bare domain's 308 or scans that hit the IP directly) is classified by the site host rules.

**Request kind** (`req_kind`, checked in order, each request gets exactly one):

| Kind | Rule |
|---|---|
| `health` | The path `/healthz` (any host) |
| `api` | Everything on the API host except `/robots.txt`; on the site host, `/api/*` (except the auth paths below) and `/raw/*` (in single-host mode, or before the 308 to the API host) |
| `static` | `/static/*`, `/robots.txt`, `/favicon.ico` |
| `auth` | `/auth/*`, `/account/*` (the JSON endpoints; the `/account` page itself is a page), `/api/me`, `/api/discuss/*`, `/api/posts/*` |
| `feed` | `[/<locale>]/feed.xml` |
| `page` | All other paths on the site host (including unknown paths that 404) |
| `redirect` | Any 3xx response (except 304), which overrides the kinds above |

`error` isn't a separate kind: a request with status ≥ 400 is counted in `req_error_kind` by its kind (and still counted in `req_kind`).
A 304 (the browser revalidating with `If-None-Match`; pages and static assets both have ETags) isn't a redirect and is counted under its original kind.

**Page view (pv)**: kind page, method GET, status 200 or 304. HEAD, 405, 404, and redirects aren't page views.

**Page type** (`pv_page`, after removing the language prefix): `/` and `/hot` → `home`; `/discussed` → `discussed`; `/vuln` (including `?q=` search) → `vuln_list`; `/vuln/{id}` → `vuln`;
`/stats`, `/src`, `/about`, `/login`, `/account`, `/welcome` → the same name; `/rules` and `/rules/*` → `rules`; `/admin` and `/admin/*` → `admin`; anything else → `other`.

**Language** (`pv_locale`): if the first path segment is one of `zh-hans`, `zh-hant`, `ja`, `ko`, `es`, `fr`, that's the language; otherwise `en`
(a test keeps this list in sync with `internal/webui/i18n/locales.json`).

**API endpoint** (`api_endpoint`; the API host has `/v1` removed, the site host has `/api` removed): `hot`, `vuln` (`/vuln/{id}`), `search`, `suggest` (`/affected/suggest`), `discussed`, `sources`, `stats`,
`raw` (`/v1/raw/*`, `/raw/*`), `index` (the API host's `/`, `/v1`, `/v1/`), `other`.

**Human / machine** (`IsBot`; the list is in one place, `botTokens` in `classify.go`): an empty UA; or a UA that contains (case-insensitive)
`bot crawl spider slurp monitor uptime preview fetch scan archiver facebookexternalhit embedly whatsapp telegram discord slack lighthouse pingdom validator`,
scanners `zgrab masscan nmap nuclei sqlmap nikto censys shodan expanse netcraft`,
HTTP libraries and command-line tools `curl wget python-requests python-urllib python-httpx aiohttp go-http-client okhttp libwww java/ apache-httpclient node-fetch axios undici httpie guzzlehttp ruby scrapy postman insomnia powershell winhttp reqwest`,
headless browsers `headlesschrome phantomjs selenium puppeteer playwright electron/`,
feed readers `feed rss newsblur inoreader tiny tiny netnewswire miniflux freshrss`;
or one that doesn't start with `Mozilla/` or `Opera`. All of those count as machines, and the rest count as humans. This is a heuristic: a script that fakes a browser UA is counted as human, and an unusual browser may be counted as a machine.
The UA family for machines (the `bot_ua` list): a known family name (Googlebot, bingbot, GPTBot, curl, ...; see `botFamilies`), otherwise a self-reported `…bot`/`…crawler`/`…spider` word in the UA,
`(empty)` for an empty UA, and `other` for the rest.

## Metric vocabulary (`stats_daily`)

`dim` format: scalar metrics use `all` or `human`; metrics with a breakdown use `all:<value>` or `human:<value>` (`all` = all traffic, `human` = humans only).
Rows with a value of 0 aren't stored (except `rt_*`), and a missing row reads as 0.

| metric | dim | Meaning |
|---|---|---|
| `req` | `all`, `human`, `bot` | Number of requests |
| `req_domain` | `all:<domain>`, `human:<domain>` | By `domain`; empty is `(none)` |
| `req_status` | `…:1xx` … `…:5xx`, `…:other` | By status class |
| `req_kind` | `…:page|api|feed|static|auth|health|redirect` | By request kind; the kinds sum to `req` |
| `req_error_kind` | `…:page|api|feed|static|auth|health` | Requests with status ≥ 400, by kind |
| `bytes` | `all`, `human` | Sum of response body bytes (`bytes_sent`) |
| `bytes_kind` | `…:<kind>` | By request kind |
| `pv` | `all`, `human` | Page views |
| `pv_page` | `…:home|vuln_list|vuln|stats|src|about|login|account|welcome|rules|admin|other` | By page type |
| `pv_locale` | `…:en|zh-hans|zh-hant|ja|ko|es|fr` | By language |
| `uv` | `all`, `human` | Distinct visitors who viewed a page that day |
| `api` | `all`, `human` | API requests (excluding redirects) |
| `api_endpoint` | `…:hot|vuln|search|suggest|sources|stats|raw|index|other` | By endpoint |
| `api_clients` | `all`, `human` | Distinct clients that called the API that day (same visitor hash) |
| `rt_page_ms` | `all:p50|p95|p99`, `human:…` | Percentiles of `request_time` for page views (milliseconds, nearest rank) |
| `rt_api_ms` | same as above | Percentiles of `request_time` for API requests |
| `rollup` | `lines`, `bad`, `partial`, `misfiled_out` | The day's **own file**: total lines, bad lines, an unfinished last line, lines that belong to other dates |
| `rollup` | `misfiled_in`, `top_overflow` | Lines for this day found in other files; the number of times something wasn't counted in a top list because of the 200,000-key cap |

## Top lists (`stats_top.kind`, at most 100 per day, ordered by count descending, ties by key)

| kind | Key | What's counted |
|---|---|---|
| `vuln_page` / `vuln_page_human` | CVE id (uppercase, must match `^CVE-\d{4}-\d{4,19}$`) | Vulnerability page views |
| `api_vuln` | CVE id | Successful queries (200/304) to the API `vuln` endpoint |
| `referrer_host` / `referrer_host_human` | Referrer host name | Page views |
| `country` / `country_human` | The two-letter `CF-IPCountry` code | Page views (empty values aren't counted) |
| `search` | Search term | Page views of `/vuln?q=` and successful API `search` requests |
| `not_found_human` | Path | 404 requests from humans |
| `bot_ua` | UA family | All requests from machines |

When `Top` reads a range of dates it adds up each day's top 100: only keys that are in the top 100 every day are exact, and the rest are lower bounds.

## Privacy rules

- **IPs and UAs aren't stored**: a visitor is the first 8 bytes of `SHA-256(salt ‖ date ‖ 0x00 ‖ client_ip ‖ 0x00 ‖ user_agent)`. The salt is a random value specific to each deployment (`stats_salt`),
  so without the database you can't work back from a hash to an IP. The date goes into the hash, so hashes from different dates can't be linked (you can't follow the same person across days, and you can't compute a deduplicated visitor count across days).
  The stats tables contain no IPs, UAs, cookies, or full URLs.
- **Visitor rows are kept for only 90 days** (`stats_visitors`); after that only that day's deduplicated count remains.
- **Search terms**: control and format characters are removed, leading and trailing whitespace trimmed, lowercased, at most 64 characters; **a term is stored only if at least 2 distinct visitors used it that day** (a term only one person searched never reaches the database; there's a test for it).
- **Referrers**: only the host name is stored (lowercased, port removed, ≤ 255 bytes), never the path or query string; this site's own hosts (`nday.land` and its subdomains, and the line's own `domain`) aren't counted.
- **404 paths**: only the path is stored (query string removed, ≤ 200 bytes), and only for human requests.
- The access log itself still contains IPs (`docs/logging.md`); the stats don't change how long logs are kept.

## Read API (`read.go`, for the admin back office; no HTTP)

`stats.NewReader(src)`, where `src` is a `*dbpool.Pool` or `stats.SingleConn(conn)`. Each method is a single read-only SELECT and can run concurrently. Dates use the year, month, and day of a `time.Time`; ranges include both ends and can be at most 3660 days (otherwise `ErrRange`).

| Method | Returns |
|---|---|
| `Series(ctx, metric, dim, from, to)` | One `Point{Day, Value}` per day; days with no data are 0 |
| `Top(ctx, kind, from, to, n)` | The top n `TopEntry{Key, Value}` after summing over the range (n ≤ 0 or > 1000 means 100) |
| `Days(ctx)` | The dates that have stats: the line count of their own file, bad lines, and the last rollup time |
| `Overview(ctx, day)` | The day's main numbers (requests, pv, uv, API, bytes, p50/p95) plus every `metric → dim → value` |

## Accuracy, and what isn't measured

- **Server logs only, no JavaScript**: there are no sessions, time on page, bounce rate, scrolling, or screen sizes. A "visitor" is "the same IP + the same UA on the same day",
  so one person on a different network counts as two, and several people behind the same NAT with the same browser version count as one.
- **Human / machine is a UA heuristic** (see above); a crawler that pretends to be a browser is counted as human.
- **Cloudflare edge cache**: requests served from the edge cache don't reach the origin and don't appear in the logs.
  - HTML pages respond with `Cache-Control: public, max-age=60` (`internal/webui/render.go:25`), but the live pages show `cf-cache-status: DYNAMIC` (an operational observation, not re-verified),
    meaning Cloudflare isn't caching HTML and every request goes to the origin, so **page views, searches, and vulnerability pages are complete**. This assumes no cache rule like "Cache Everything" has been added for HTML;
    if one is added later, pv will be far too low (only the first request per edge node per minute would get through). (Cloudflare by default doesn't cache HTML according to `Cache-Control` and only caches static files by extension. That's the default behaviour as remembered, not checked against the docs.)
  - Browser cache: back-navigation or reopening within `max-age=60` may not send a request, so pv is slightly low; a revisit after more than 60 seconds is a 304 and counts toward pv.
  - `/static/*` (`public, max-age=31536000, immutable`, `.css`/`.js`/fonts) and `/favicon.ico` can be cached at the edge by extension,
    so the request count and bytes for the `static` kind **only reflect what reached the origin** and are far below real download volume.
  - The JSON API (`private, max-age=60`), `/raw/*.json` (`private, max-age=3600`) and `feed.xml` (`private, no-store`) need an API token, a session or a private feed key, and must never be cached at the edge: a "Cache Everything"/Edge Cache TTL rule on `/api/*`, `/raw/*`, `/feed.xml`, `/<locale>/feed.xml` or the API host would hand gated responses to anyone (see `deploy/README.md`). Without such a rule every request reaches the origin, so these counts should be complete.
- **`request_time`** is origin processing time; it doesn't include Cloudflare or the visitor's network.
- **Timezone**: dates follow the offset carried by each line (the server's local timezone); a day is not a UTC day.
- **Recompute scope**: only changed files are recomputed, and dates whose logs have been deleted can't be recomputed.
