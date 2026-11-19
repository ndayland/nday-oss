# Web pages module: queueing and fetching third-party pages (`internal/webpages`, `internal/pagefetch`, migration `0020_web_page.sql`)

It exists to get page titles for the links in the "related resources" panel on a vulnerability page (see "Links and candidate accounts" in `docs/xposts.md`, the part about titles for linked pages).

## Who does what

- **Producers only enqueue**: `webpages.Enqueue(ctx, db, url, source)` is idempotent. The URL goes through `pagefetch.CheckURL` first, entries are deduplicated by `pagefetch.URLKey`, and `first_source` records the source that enqueued it first. The only producer right now is xposts (`xlinks.EnqueuePages`, `nday x-links-enqueue`).
- **The web pages module fetches**: `webpages.FetchPending` (command `nday pages-fetch [--limit N]`, default 100, with no overall time limit of its own). It also runs one pass after every successful `nday collect xposts`; in that case enqueueing and fetching share a 2-minute limit and at most 25 URLs. A single URL can take up to 25 seconds, so on slow sites a pass handles fewer URLs and the rest wait for next time. When the limit expires, the status and attempt count of rows that weren't processed stay as they were. It doesn't know where URLs come from. After it, the same collection runs the GitHub repository step, which has its own queue and limit and talks only to the GitHub API (`docs/github.md`).
- **The safe fetcher** `internal/pagefetch`: a standalone package. It doesn't depend on the database, the collectors, or the site code, has no global state, and doesn't read environment variables.

## The `web_page` table

| Column | Value |
|---|---|
| `url_key` | Primary key, `pagefetch.URLKey` (scheme and host lowercased, fragment and one trailing `/` on the path removed, query string kept). The site's `site.ResourceKey` is the same thing |
| `url` | The spelling that was enqueued first (≤ 2048 bytes) |
| `status` | `pending`: waiting to be fetched or retryable. `ok`: has a title. `none`: final, no title (not 200, not HTML, no usable title, or rejected). `failed`: 3 temporary errors (after that it's retried once every 24 hours, at most 6 attempts in total, and then it stays `failed`) |
| `attempts`, `fetched_at` | Number of requests, and the time of the latest request (updated on every request; the slow retry waits 24 hours from it) |
| `title`, `site_name` | The cleaned title (1–120 characters) and `og:site_name`. This is third-party text and must be escaped when displayed |
| `first_source`, `created_at` | The source that enqueued it first (for example `xposts`), and when it was enqueued |

## One fetch pass

It takes rows with `status = 'pending' AND attempts < 3`, or `status = 'failed' AND attempts < 6 AND fetched_at` more than 24 hours before the current time (the time comes from the caller's clock), earliest enqueued first, at most N. Each URL gets one GET, with a 1-second pause between requests, and if the context is cancelled it stops between rows.
A 200 with `Content-Type` `text/html` / `application/xhtml+xml` and a title → `ok`. A network error, 5xx, 408, or 429 → `attempts+1` (3 attempts → `failed`). Everything else (including rejected URLs, redirects, and connections) → `none`.
Stored URLs that no longer pass the rules go straight to `none` without a request.
**A redirect to another host gets no title**: the host name of the final URL (lowercased, trailing dot and one leading `www.` removed) must match the enqueued URL's (same host, http→https is fine). Otherwise the row is `none`. This stops a redirector from showing another site's title next to its own host name.
A panic while handling a page is caught: only the `url_key` and the panic value are logged (not the body), that page is recorded as `none`, and the pass continues. When the time limit expires or the pass is cancelled, rows that haven't been written yet keep their status and attempt count. The User-Agent is the same as the t.co resolver's (`nday-linkresolver/1`), with `Accept: text/html`.

## SSRF protection (`internal/pagefetch`)

- URL rules (`CheckURL`): absolute http/https only; must have a host; no userinfo; the port must be omitted or the default (http 80, https 443); if the host is an IP literal it must be a public address; ≤ 2048 bytes.
- Checks at connect time (`GuardControl`, a `net.Dialer.Control`): after DNS resolution and before every connect, the address actually being connected to is checked, so DNS rebinding doesn't get around it. The decision function `IsPublicAddr` rejects:
  0.0.0.0/8, 10/8, 100.64/10, 127/8, 169.254/16 (cloud metadata), 172.16/12, 192.0.0/24, 192.0.2/24, 192.88.99/24, 192.168/16, 198.18/15, 198.51.100/24, 203.0.113/24, 224/4, 240/4 (including broadcast);
  for IPv6 it only accepts 2000::/3, and rejects 2001::/23 within it (including Teredo), 2001:db8::/32, and 3fff::/20; IPv4-mapped (::ffff:0:0/96), NAT64 (64:ff9b::/96), and 6to4 (2002::/16) are judged by the embedded IPv4 address;
  IPv4-compatible addresses (::/96), local-use NAT64 (64:ff9b:1::/48), and addresses with a zone are always rejected. TCP only.
- Up to 3 redirects. Every hop goes through the URL rules again (the connect-time check applies to every hop), and every hop drops `Referer` and `Cookie` (so one site's address isn't leaked to another; there's no cookie jar). No proxy (`Proxy: nil`), TLS verification on, no connection reuse.
- Each URL has a 25-second total timeout (including redirects), 20 seconds for the response headers (some blogs take around 15 seconds to send the first byte), and 5 seconds each for connect and the TLS handshake. At most 512 KiB of the body is read (only for 200 HTML responses).
- Tests can only inject `DialControl` / `RewriteAddr` from code; there's no switch for them in the production path.

## Title extraction (`pagefetch.ExtractMeta`)

- It reads only `<head>` (up to `</head>` or `<body>`) and skips comments and the contents of script/style/noscript/template and similar. It takes the first `<title>`, or `og:title` if there's none or it's unusable. Tag name comparison case-folds ASCII letters only (so byte length doesn't change).
- Encoding: first the `Content-Type` charset, then `<meta charset>` in the first 1024 bytes, otherwise UTF-8. Decoding uses `golang.org/x/text` (already in go.mod, so no new dependency). UTF-16 and unknown encodings aren't handled, and titles containing invalid UTF-8 are discarded.
- Cleaning (`CleanText`): entities are decoded only once; control and format characters are removed (bidi controls, zero-width characters, tag characters, BOM, variation selectors), along with characters that render as blank (Hangul fillers U+115F/U+1160/U+3164/U+FFA0, U+034F, U+2800, U+180E, U+2060–U+2064); whitespace is collapsed and trimmed. A title with no letters or digits left after cleaning counts as no title.
- When `og:site_name` is present, a trailing "separator + site name" and a leading "site name + separator" are stripped from the title (separators ` - `, ` | `, ` – `, ` — `, ` · `, ` :: `, case-insensitive), never down to an empty string. Without `og:site_name` it doesn't guess.
- Generic titles (CAPTCHA pages, error pages, login pages; the list is `genericTitles` in `meta.go`) count as no title. Finally the title is cut to 120 characters (ending in `…` if it was longer).

## Publication time (`pagefetch.ExtractPublished`, migration `0029_web_page_published.sql`)

- Read from the HTML already fetched (no extra request), from the whole document (JSON-LD and `<time>` usually sit in the body), in this order of trust; the first value that parses and is plausible wins, a bad one falls through to the next source:
  1. JSON-LD (`<script type="application/ld+json">`): `datePublished` of the first object typed `Article`, `NewsArticle`, `BlogPosting`, `TechArticle`, `Report`, `ScholarlyArticle` or `AnalysisNewsArticle` (also inside arrays, `@graph` and `mainEntity`), else of the first object that has one;
  2. `<meta property="article:published_time">`;
  3. `<meta name>` `date`, `pubdate`, `publishdate`, `dc.date`, `dc.date.issued`, `citation_publication_date`, `parsely-pub-date`, `sailthru.date` (case-insensitive, in this order);
  4. `<meta itemprop="datePublished">`;
  5. `<time datetime>` with `pubdate` or `itemprop="datePublished"`.
- Never used: `Last-Modified`, `article:modified_time`, `dateModified`.
- Parsing is strict (`ParsePublished`): RFC 3339 and its common variants (offset without a colon, no seconds, a space instead of `T`) and RFC 1123 with a numeric offset or GMT/UTC give precision `exact` (stored in UTC); a date alone (`YYYY-MM-DD`, `YYYY/MM/DD`) or a date and time without a zone give precision `day` (the date as written). Anything else (a year alone, words, trailing text, zone names like `EST`) is not a time.
- Plausible: not before 1995-01-01 and not more than one day after the fetch.
- JSON-LD is bounded: at most 8 blocks of at most 64 KiB each, nesting at most 32 deep (deeper blocks are skipped), the walk goes at most 6 levels down; HTML comment and CDATA markers and a trailing `;` around the JSON are tolerated, anything else that doesn't parse is skipped.
- Stored with the page (`published_at`, `published_precision` `exact`/`day`, `published_source` such as `json-ld` or `meta:article:published_time`, for operators). Every fetch also sets `published_checked_at`.
- Backfill: pages fetched before this existed are `ok` without `published_checked_at`. `nday pages-fetch` and the pass after `nday collect xposts` re-fetch up to `webpages.DefaultBackfill` (20) of them per run after the pending pages, oldest first, one request each; whatever the outcome the page is marked and never re-fetched for this again, and only the publication time is written (status, attempts and title stay as they are). The pass after the collector stops the backfill early, without an error, when its 2-minute deadline is less than 30 seconds away. At the default rate (the hourly `nday-collect@xposts.timer`) that is up to 480 pages a day: a backfill of N pages takes about N / 480 days; `nday pages-fetch` run by hand adds 20 per run.
- GitHub repositories keep their creation day (`github_repo.repo_created_at`); nothing is invented for a link whose page states no time.

## Dots on the lifecycle chart (`internal/webui/chartdots.go`)

- The vulnerability page draws its external items at their time on the existing rows of the lifecycle chart (no new rows): analysis articles, advisories and other links on ANA, the links of the "PoC / exploit code" group on POC (only what counts as a PoC source: no dot for the unreviewed repositories, nor for code links; since 2026-11-19), patch links on PAT, researcher posts on the lower edge of the date-axis header. One colour per type (`--dot-post`, `--dot-art`, `--dot-poc`, `--dot-pat`, both themes), no legend.
- Time: the page's stated publication time (solid); else the day a researcher first posted the link (`site.Resource.FirstMentioned`, a ring: "not after"); a GitHub repository that counts at its creation day (one created before the disclosure is not drawn); a post at its UTC day. Items without a time are not drawn (they stay in the resources list). Items may start the axis at most 30 days before the earliest event; earlier ones are not drawn.
- A row with dots is taller (36 → 64 px): its label, stage marks and "time unknown" cell keep the upper 36 px, the dots get a lane under them. In a lane the items of one UTC day are one mark; then, while two neighbouring marks are closer at the 620 px reference plot than their hit boxes allow (at least 24 px, and 4 px between the marks), the closest pair merges. A single item is a 12 px dot; several are a bubble with the count inside (2–9: 18 px, 10–99: 22 px, 100+: 26 px). Posts on the header keep one triangle per UTC day (or closer than 8 px) with the count beside it.
- Each dot is a link to `#resources` (a mark holding a PoC link: the paged PoC list `#r-poc`; posts: `#research`) without script; `static/app.js` turns it into a button with a popover (hover, focus, tap; Escape, blur and a tap elsewhere close it; placed in the viewport, not clipped by the chart's scroller) listing at most 6 items — the kind's label, the title as a link (new tab, favicon) and the date (`≤` for a ring) — then one "show N more" link. A post's line is "@handle · day" linking to the profile; for a signed-in reader `static/discuss.js` adds a short excerpt and the post link from `GET /api/posts/{cve}`. The HTML is the same for every visitor.
- Public data only (`internal/site/public.go`): the dots show what the resources panel and the researcher outline already show, plus each link's first-mentioned day (owner's decision of 2026-11-17).

## Not handled

- `robots.txt` isn't read. Titles are third-party text: they're only cleaned and escaped, and their content isn't controlled.
- Rows aren't refreshed after `ok`/`none` (except the one-time publication-time backfill above). Only the title, site name and publication time are extracted (no author or summary).
- The https fetch path has no local test (the tests only use an http httptest server).
