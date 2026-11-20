# osssec: posts on the oss-security mailing list (Go only)

This collector reads the [oss-security](https://seclists.org/oss-sec/) mailing list from the seclists.org archive and attaches each post,
as a timeline event, to every CVE id and GHSA id it names. Code: `internal/collector/osssec`.

## What it fetches

- The current quarter's thread index, `https://seclists.org/oss-sec/<year>/q<n>/`, as a conditional GET (`If-None-Match` /
  `If-Modified-Since` from the cursor). The message numbers are the `<a name="N" href="N">` anchors.
- Then each message page above the cursor, `https://seclists.org/oss-sec/<year>/q<n>/<N>`, oldest first.

From a message page it reads the subject, the author's display name (the address, which seclists shows as `user () host com`, is dropped),
the `Date` header (converted to UTC), whether it's a reply (subject starts with `Re:`, or the page lists references), and every CVE and GHSA id
in the subject and the body (tags stripped, entities decoded, first 512 KB of the body).

## Politeness

- At least 1 second between any two requests, and at most 40 message pages per run (the timer runs hourly, the list gets a few dozen posts a day).
- Retries: 3 tries on 429 / 5xx / network errors with backoff, through `internal/httpc` (generic `nday-collector` User-Agent).
- Size caps: 8 MB for an index, 2 MB for a message page.
- A failed request ends the run early. Whatever was fetched before it is kept and the cursor stops at the last message fully fetched.
  If nothing was fetched yet, the run fails (status `error`), so a stuck page shows up on `/admin` instead of hiding behind `ok`.
  A message page that is gone (404) is skipped.

## Cursor

`{"quarter": "2026/q4", "last_number": 801, "etag": …, "last_modified": …, "last_run": {…}}`.
`last_number` is -1 when nothing of the quarter was fetched yet. The index validators are kept only when every message the index listed
was handled, so a 304 really means "nothing new".

- First run (no cursor): only the newest 40 messages of the current quarter. It doesn't crawl the archive.
- Quarter rollover: when the clock is in a later quarter, the run first finishes the cursor's quarter, then moves on. A new quarter's index is 404
  until its first post; that's normal. A post filed into an old quarter after we moved on is not picked up.

## Backfill

To walk the whole current quarter from message 0 (cap 1500 pages, still 1 second apart, so about 15 minutes for a full quarter):

```bash
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) NDAY_OSSSEC_BACKFILL=1 /opt/nday/bin/nday collect osssec'
```

Set the variable only on that one command, never in `nday.env`: every timer run would then crawl the quarter. Posts already stored are fetched
again but write nothing new (same content hash).

## What is stored

Raw record, key `<year>/q<n>/<number>`: `url`, `year`, `quarter`, `number`, `subject`, `author`, `date` (UTC RFC 3339, or null),
`is_reply`, `cve_ids`, `ghsa_ids`, `subject_ids` (the ids in the subject).

Deliberately **not** stored: the message body or any excerpt of it (raw records are served by the API, and the posts belong to their authors),
and any e-mail address. A post that names no id still gets a raw record, so it isn't fetched again, but gives no event.

## Events

One event per id in the post: ids in the subject first, then the others in order of appearance, at most 50 per post (digests).
CVE ids from before 1999 or more than a year after the post are ignored.

| column | value |
|---|---|
| `type` | `analysis_published` (stage ANA) |
| `source` | `osssec` |
| `occurred_at` | the post's `Date` header |
| `url` | the post on seclists.org |
| `dedupe_key` | the raw record key |
| `detail` | `subject`, `author`, `is_reply`, `list` (`oss-security`) |

An unknown CVE id gets a stub vuln. A GHSA id goes through the usual redirect (`docs/ghsa.md`): onto its CVE when it's an alias, onto its own
GHSA-keyed vuln if there is one, otherwise nothing is written.

Effect on the lifecycle: `vuln_state` takes the earliest event of each stage, so the ANA time is the first post that named the id; a later reply adds
an event to the log but doesn't move the ANA time. A CVE whose only data is a post shows stage ANA with an unknown disclosure time.

A post is never a transition, though (migration 0039, owner's decision): it doesn't put a vulnerability on the hot list. `last_transition_*`
(and the page's `transition`) is the newest first arrival of a type among the other sources' events. A CVE that got a patch yesterday and a post
today is listed with the patch; one with nothing but posts has no transition (`null`), so it's not on the hot list and sorts into the
catalogue's undated tail. The post still shows in the event log, the stage, `has_analysis` and `analysis_at`. The list of such sources is the
SQL function `counts_as_transition` plus `site.NoTransitionSources` (a test keeps them equal); a later mailing-list-like source goes there.
