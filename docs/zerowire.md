# zerowire: Cloudflare Radar's Zero Wire advisories (Go only)

This collector reads [Zero Wire](https://radar.cloudflare.com/zero-wire), the advisories Cloudforce One writes on Cloudflare Radar about
major vulnerabilities, and attaches each advisory, as a timeline event, to every CVE id and GHSA id it names. Code: `internal/collector/zerowire`.

There aren't many of them (about a dozen in four months), and the feed always carries all of them, so there's no backfill and no paging.

## What it fetches

One URL, `https://radar.cloudflare.com/zero-wire/feed` (RSS 2.0, about 130 KB), once per run, as a conditional GET (`If-None-Match` /
`If-Modified-Since` from the cursor; Cloudflare doesn't send an ETag or Last-Modified today, so for now it's a plain GET).

- Only `https://radar.cloudflare.com` is ever asked. A redirect to another host, or to plain http, is refused before the request goes out
  (same-host https redirects are followed).
- Through `internal/httpc` (generic `nday-collector` User-Agent): 3 tries on 429 / 5xx / network errors with backoff, 2 minutes per try,
  4 MB body cap.
- The XML is read with Go's `encoding/xml`, which never resolves external entities and skips elements it doesn't know.
- A failed request, or a body that isn't RSS, fails the run (status `error`); the next hourly run tries again.

From each `<item>` it reads:

- `<link>`: must be exactly `https://radar.cloudflare.com/zero-wire/<slug>` with the slug matching `^[a-z0-9][a-z0-9-]{0,199}$`
  (no query, no fragment, no other path). Anything else skips the item (counted in `skipped_bad_link`). A second item with the same slug is
  skipped too (`skipped_duplicate`).
- `<title>`: untrusted text. Entities decoded once, control, format and bidi characters dropped, whitespace collapsed, cut to 300 characters.
  It's only ever shown as text.
- `<pubDate>`: only the day (Zero Wire always says `00:00:00 GMT`).
- `<category>`s, cleaned the same way (at most 20, 100 characters each).
- Every CVE and GHSA id in the title, the description and `content:encoded` (the HTML as is, so ids in link targets count, and its text
  with tags stripped and entities decoded).

The `<guid>` is not used: it's `<slug>@<date>` and the date part changes when an advisory is updated.

## Cursor

`{"etag": …, "last_modified": …, "last_run": {"status", "items", "records", "without_ids", "skipped_bad_link", "skipped_duplicate"}}`.
On a 304 the validators are kept and nothing is returned.

## What is stored

Raw record, key = the slug: `slug`, `title`, `link`, `pub_date` (`YYYY-MM-DD`, or null), `cve_ids`, `ghsa_ids`, `categories`.

Deliberately **not** stored: the description and the article body, not even an excerpt (raw records are served by the API, and the
advisories belong to Cloudflare). An advisory that names no id still gets a raw record but gives no event (counted in `without_ids`).

Every run returns the whole feed, but the pipeline skips records whose content didn't change, so an unchanged feed writes nothing. A guid
that changes and nothing else doesn't change the record either.

## Events

One event per id in the advisory: CVE ids first, then GHSA ids, each in order of appearance, at most 50 per advisory.
CVE ids from before 1999 or more than a year after the advisory are ignored.

| column | value |
|---|---|
| `type` | `analysis_published` (stage ANA) |
| `source` | `zerowire` |
| `occurred_at` | 00:00 UTC of the advisory's day |
| `url` | the advisory on radar.cloudflare.com |
| `dedupe_key` | the slug |
| `detail` | `title`, `precision` (`day`; left out when the date is unknown) |

An unknown CVE id gets a stub vuln. A GHSA id goes through the usual redirect (`docs/ghsa.md`): onto its CVE when it's an alias, onto its own
GHSA-keyed vuln if there is one, otherwise nothing is written.

Updates: an event is identified by (CVE, type, source, slug), so when an advisory is updated its events are updated in place (new title),
not added again. `occurred_at` stays the first day we stored (the pipeline never moves a known time). An id the advisory gains adds one event,
dated by the advisory's current day. An id it drops keeps its event: the pipeline never deletes events (same as osssec).

Effect on the lifecycle: `vuln_state` takes the earliest event of each stage, so the ANA time is the first advisory that named the id.
Unlike an oss-security post, an advisory does count as a transition (it's not in `counts_as_transition` / `site.NoTransitionSources`),
so a new advisory can put a vulnerability on the hot list.

## Running it

```bash
sudo systemctl enable --now nday-collect@zerowire.timer
```

Hourly, like the other collectors. The feed says `max-age=300`, so an hour is well within what it allows.
