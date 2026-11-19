# GitHub repository module (`internal/ghrepo`, migration `0023_github_repo.sql`)

Phase 1 of GitHub PoC monitoring: GitHub repositories that allowlisted researchers link to in their X posts get their metadata from the GitHub REST API, are associated with CVEs, and the "Resources" panel on the vulnerability page shows them as repositories.
Phase 2 (migration `0025_github_discovery.sql`): active discovery through the search API, a review status per repository, and the public listing of found repositories (sections "Discovery", "Review", "Display"). The admin page on top of the review API is `/admin/github` (section "Admin review").
Not done yet: timeline events or stage changes (`poc_published` is phase 3). A repository with a CVE id in its name is **not** treated as a verified PoC.

## Who does what

- **Enqueue** (`ghrepo.Enqueue`, command `nday github-enqueue`): sweeps `x_post_link` rows with `status = 'ok'`, `host = 'github.com'`, `kind = 'code'` whose `final_url` differs from `repo_swept_url` (this release's marker; the phase-1 marker `repo_queued_url` is neither read for that nor written, see "Deploying"). Commits, pull requests and compares (`kind = 'patch'`) are patches, and advisory pages (`github.com/advisories/…`, `github.com/<owner>/<repo>/security/advisories/…`: `kind = 'advisory'`) are advisories: neither is a repository, neither is swept.
  A final URL that `ghrepo.ParseURL` accepts queues its name key (`owner/name` lower case) unless a row already holds the key; the vulnerability ids of the post (its `social_post` events: CVE ids, and the GHSA id of an advisory without a CVE) are recorded as `post` associations. The link's root key (`repo_root_key`, from `ghrepo.RootKeyOf` in Go; NULL for deep links) is written and `repo_swept_url = final_url`, whatever the outcome. The sweep reads no repository metadata and **decides no trust**. Idempotent, also the backfill; when nothing is new it is one indexed query. One transaction per link; a name another transaction creates at the same moment is used, not inserted twice (`ON CONFLICT`).
- **Fetch** (`ghrepo.FetchPending`, command `nday github-fetch [--limit N]`, default 50 requests): placeholders and link checks ask `GET https://api.github.com/repos/{owner}/{repo}`, known repositories are refreshed with `GET https://api.github.com/repositories/{github_id}`; 1 second apart.
- **After every successful `nday collect xposts`**, after the t.co and web page steps: enqueue, then one fetch pass, sharing their own 2-minute deadline, at most 25 requests (at most 5 of them refreshes). Log lines `github enqueue` and `github fetch pass`; a failure is only logged and never fails the collector run. With an injected Transport (tests, `tools/replay`) the fetch pass is skipped.

`ParseURL` accepts `http(s)://github.com/` or `www.github.com/` (default port, no user info) with at least two path segments: the owner (letters, digits, `-`, not starting with `-`, ≤ 39) and the repository (letters, digits, `.`, `_`, `-`, ≤ 100, not `.` or `..`; one trailing `.git` dropped), checked on the escaped path, so `%2F` and other escapes are refused. Site routes are refused as owners (`advisories`, `orgs`, `settings`, `topics`, `search`, `features`, `sponsors`, `marketplace`, `new`, … see `reserved` in `url.go`). `gist.github.com`, `api.github.com` and every other host are not repositories.

## Identity, names, links (the data model)

Three rules; everything else follows from them (`internal/ghrepo/identity.go`).

1. **A `github_repo` row with a `github_id` is that GitHub repository for good.** No statement changes a non-NULL `github_id` (the database refuses it: trigger `github_repo_keep_id`), such a row is never deleted and two of them are never merged. Its review status is about that repository and stays with it whatever its name becomes. A row with `github_id IS NULL` is only a **placeholder** for a queued name: it holds no status (CHECK `github_repo_status_identity`), is listed nowhere and cannot be decided about (`SetStatus` answers "not found").
2. **A name is not an identity.** `github_repo_name (name_key, repo_id)` maps a name key to at most one row: the identity that most recently answered for the key from the API — its current lower-cased `full_name` — or a placeholder. An identity holds no other key: no alias history is kept, for trust, for display or otherwise.
3. **Vouching is recorded on the link, by identity.** A root link (`x_post_link.repo_root_key`) is checked by a request for its key **by name**, made after the link exists; when a public repository created no later than the link was stored (`x_post_link.created_at`, which no sweep refreshes) answers, the link is stamped with that repository's id (`repo_github_id`). Rule trust is derived from stamps and from nothing else.

How an identity is refreshed: by id, `GET /repositories/{github_id}`. GitHub returns the same repository object as for `/repos/{owner}/{repo}`, under the repository's current name (it is the URL GitHub itself redirects a renamed repository's old name to: `GET /repos/twitter/bootstrap` answers `301` with `Location: https://api.github.com/repositories/2126244`, and that URL answers `200` with `"id": 2126244, "full_name": "twbs/bootstrap"`; checked 2026-11-16). A changed `full_name` is a rename of the **same** row.

### What each event changes

| Event | `github_repo` | `github_repo_name` | `x_post_link` | `github_rejected_name` |
|---|---|---|---|---|
| Sweep of a link (`Enqueue`) | a placeholder (`pending`) when no row holds the key; a `gone` row holding it becomes `pending` when the link was never swept before and is newer than the row's last request. When a stamp is cleared and it was the identity's last one, a `trusted` / `rule` identity goes back to `unverified` / NULL (`untrust`) | the key → the new placeholder | `repo_swept_url`, `repo_root_key`; the check and the stamp are kept when the root key is the same (another spelling of the URL) and cleared when it differs | — |
| By name, a placeholder's key answers with public repository G; no row has G | the placeholder **becomes** G (the one statement that writes a `github_id` into an existing row, `claim`: only into NULL); metadata; `ok` | G holds its current name; the asked key, if different (GitHub redirected an old name), is released | root links to the asked key: checked; stamped G when `G.created_at ≤ link.created_at` | — |
| By name, a key answers with G and a row has G | G's row: metadata, `ok`. The placeholder asked for is deleted, its `post` associations move to G's row | as above | as above | — |
| By name (a link check) or from search, a key held by identity A answers with another id G | A keeps its id, status and metadata. G's row (existing, or new) gets the metadata | the key → G's row; A holds no key until its own refresh by id — unconditional, no `If-None-Match` — tells its current name (the next pass) or that it is gone | by name only: as above (search stamps nothing) | — |
| From search, a result under a key a **placeholder** holds | a row of its own for the result (`first_source = 'search'`, no `post` association). The placeholder is not claimed and not deleted: only the answer for its own name may turn it into a repository | the key → the result's row; the placeholder stays queued without it, and its own request by name folds it into whoever answers | — | — |
| By id, 304 | `fetched_at` | if the identity holds no key: it takes the key of its stored name when that is free or a placeholder's; when another identity holds it, the key stays there and this row's ETag is dropped, so its next refresh is a 200 that decides (`holdName`) | — | — |
| By id, 200 | metadata; a changed `full_name` is a rename | the old key is released, the current name is taken (a placeholder there is folded in; another identity there loses the key) | — | an admin-rejected identity records the key it now holds |
| 404, 410, 451 or not public, by id (or search reports a known repository as not public) | `state = 'gone'`, status untouched | the identity's key is released (a later link to the name is queued and asked by name again) | — | — |
| 404, 410, 451 or not public, by name | the key's placeholder: `gone`. An identity that held the key keeps its id, status and state | an identity that held the key loses it (the next pass asks it by id) | root links to the key: checked, no stamp | — |
| Transient failure | `attempts + 1` | — | by name: `repo_check_attempts + 1` on the unchecked links to the key | — |
| A stamp is written | the stamped identity becomes `trusted` / `rule` if nobody decided about it (`status_by` NULL, or `owner`: the rule replaces owner trust) | — | — | — |
| An identity nobody (no admin) decided about ends up under a key recorded for **another** identity's rejection (new, or renamed into it) | `rejected` / `rule` | — | — | — |
| Admin: reject X (`SetStatus`) | `rejected` / `admin` | — | — | X's current key and the key of its stored `full_name` (X may hold no key at that moment) are recorded, with X as the row that recorded them |
| Admin: trust or reset X | `trusted` or `unverified` / `admin` | — | — | the keys recorded for X are removed, and only those |

No row above changes a non-NULL `github_id` or deletes a row that has one (the database refuses both: triggers `github_repo_keep_id`, `github_repo_keep_row`), and no automatic row changes an admin's decision.

Which answer wins a name: the most recent **200** for that name. A 200 by name or from search gives the key to the identity in the answer; a 200 by id gives the identity the key of its current `full_name`, taking it from whoever holds it (that one is then asked by id in turn, so two rows cannot keep one name: GitHub has one repository per name). A 304 only confirms what is stored and never takes a key from another identity.

## Tables

`github_repo` — one row per repository identity, or a placeholder. Our own `id` is the primary key; `github_id` (GitHub's numeric id) is `UNIQUE`, immutable once set, and `NULL` only for a placeholder. `queued_name` is the name key the row was created under.

| Column | Value |
|---|---|
| `full_name`, `owner_login`, `owner_type` | As GitHub returns them (`owner_type` only `User` / `Organization` / `Bot`) |
| `description`, `language`, `topics` | Cleaned (`pagefetch.CleanText`), cut to 500 / 64 characters; topics must match `^[a-z0-9][a-z0-9-]{0,49}$`, at most 20 |
| `stars`, `forks`, `is_fork`, `is_archived`, `repo_created_at`, `pushed_at` | From the response; counts clamped to `0 … 2^31-1` (`stars` NULL when the answer has no `stargazers_count`), times dropped when not RFC 3339 |
| `state` | `pending` (not fetched yet or transient failure with attempts left), `ok`, `gone` (404, 410, 451, or the repository is not public; earlier metadata kept but never shown; retried, see "One fetch pass"), `failed` (3 transient failures; retried once a day up to 6 attempts in all) |
| `attempts`, `etag`, `fetched_at` | Attempts since the last success; the ETag of the last 200; time of the last request |
| `status`, `status_by`, `status_at`, `seen_at` | Migration 0025, see "Review" |
| `first_source`, `created_at` | `xposts` or `search`; when the row was created |

`github_repo_name (name_key, repo_id)` — see rule 2 above.

`github_repo_cve (repo_id, cve_id, basis)` — `cve_id` is a vulnerability id as found: a CVE id or a GHSA id (see "GHSA ids"). `name`, `description`, `topic`: an id in that field of the last response (found with `xposts.ExtractCVEs` / `xposts.ExtractGHSAs` after turning `_` into spaces, so `CVE-2024-1234_poc` matches); replaced on every 200. `post`: the name was linked from a researcher post about the CVE; written by the enqueue sweep for the row that holds the name, never removed by a fetch. A `post` association is not trust and never moves a link into the PoC group.

`x_post_link` — `repo_queued_url`: the phase-1 sweep marker, no longer used. Migration 0025: `repo_swept_url` (the sweep marker, like `page_queued_url` for web pages), `repo_root_key` (the root key, NULL for deep links), `repo_checked_at` (a request by name for the key got a definite answer after the link existed), `repo_github_id` (the stamp; references `github_repo.github_id`; CHECK: only with a root key and a check), `repo_check_attempts` (transient failures of the check).

`github_rejected_name (name_key, repo_id, rejected_at)` — a name key recorded for the rejection of identity `repo_id`; primary key `(name_key, repo_id)`.

`github_search_cve (cve_id, searched_at, total_count, failures, failed_at)` — the targeted search of one id (CVE or GHSA). `github_search_scan (scan_key, created_after, window_end, next_page, window_total, window_incomplete, window_retries)` — one row per scan (`name:CVE-YYYY`, `name:GHSA`).

## One fetch pass

At most N requests (`--limit`, 25 after a collection), in this order:

1. rows to fetch, oldest first: `pending` with `attempts < 3` and `failed` with `attempts < 6` whose last attempt is over 24 hours old. A placeholder asks for its name, an identity for its id;
2. **link checks**: the root keys of links not checked yet (`repo_checked_at IS NULL`, `repo_check_attempts < 3`), oldest link first, one request **by name** per distinct key that step 1 does not already ask;
3. sharing one cap (at most 10 per pass, 5 after a collection; oldest fetch first): `ok` rows last fetched more than 7 days ago (not rows found by search that nobody decided about), `ok` identities that hold no name key (another repository answered for their name; at most 6 failures in a row), and `gone` rows created (our `created_at`) less than 7 days ago whose last attempt is over 24 hours old. After 7 days `gone` is final. An `ok` identity that holds its name sends `If-None-Match` with its ETag; one that holds no name is asked unconditionally (a 304 could not give it its name back).

A **new** link (an `x_post_link` row never swept before) to a name whose row is `gone` and was last asked before the link was stored makes that row `pending` again with `attempts = 0` during the enqueue sweep (`revived` in its counts), so a later post revives a repository made public since. A re-sweep of an old link does not.

| Response | Outcome |
|---|---|
| 200, valid public repository | see the table in "Identity, names, links"; `attempts = 0` |
| 200 by id carrying another id | a transient failure; nothing else changes |
| 304 (refresh) | unchanged, `fetched_at` updated |
| 404, 410, 451, or `private` not `false` / `visibility` not `public` | `gone` (metadata kept, not shown, status untouched); by name the links to the key are checked without a stamp |
| 429, or 403 with `x-ratelimit-remaining: 0` or `retry-after` | the pass **stops without an error**; this request and the rest change nothing (links stay unchecked) |
| other 403, 5xx, other status, malformed or oversized body, refused redirect, transport error | `attempts + 1`; `failed` at 3 (an `ok` row stays `ok`, a `gone` row stays `gone`); links stay unchecked |

A link is checked once. The one exception: when a key answers with a public repository while its placeholder is `gone` **and still inside the 7 days** (`GoneRetryWindow`, whatever made the pass ask the key), the links to that key that were checked without a stamp are looked at again, under the same condition (`repo_created_at ≤ link.created_at`), so a repository that became public shortly after the post is still vouched for, and one created after the post is not. After the 7 days a link checked with a 404 is never stamped.
A link whose check failed 3 times is no longer picked for its own sake; it is checked when its key is asked again (the placeholder's daily retry, or another link to the same key). An admin can always decide about the repository.

The pass also stops after any response that reports 5 or fewer requests left (`MinRemaining`), and before a request by name when fewer than 7 are left (GitHub answers a renamed repository's old name with a redirect: two requests), so a pass without a token never uses the last 5 requests of the shared hourly 60. `requests` in the pass's counts includes followed redirects. A panic while handling a request is recovered, logged (row id and panic value only) and counted as a transient failure. A cancelled or expired context stops the pass between requests; rows not yet written keep their state.

**Request cost.** A repository first seen through a post costs one request, as in phase 1: the fetch of its placeholder is also the check of the link. A new root link to a name we already hold costs one extra request (the check is always a fresh answer for the link's own key, never the stored row). A deep link to a known name costs none. A name GitHub redirects (renamed repository) costs two requests against the limit for one step of the pass, as before. Without a token (60 core requests an hour per address, the pass stopping at 5 left) a pass after a collection uses at most 25 steps, of which at most 5 are refreshes; link checks and new placeholders come first, so a burst of new links delays refreshes, never the other way round. With a token the limit is 5,000 an hour.

The steps after deploying are in "Deploying" at the end.

## Outbound requests (`client.go`)

- Only `https://api.github.com`, method GET. The dialer refuses any address other than `api.github.com:443`, and `pagefetch.GuardControl` refuses non-public addresses at connect time. No proxy (never from the environment), TLS verified, 5 s dial / TLS handshake, 15 s to response headers, 20 s per request, at most 256 KiB of body read.
- Redirects are followed by the client itself, at most 2, and only when the new URL is again `https://api.github.com/...` (default port, no user info); anything else is refused before a request is made.
- Headers: `User-Agent: nday-ghrepo/1`, `Accept: application/vnd.github+json`, `X-GitHub-Api-Version: 2022-11-28`, `If-None-Match` on refreshes, and `Authorization: Bearer <token>` only when a token is set and the request URL is `https://api.github.com`.
- Everything in a response is untrusted: decoded with typed fields (a wrong type in a required field makes the body malformed), text cleaned and cut, names re-validated.

## Token

Optional. The module uses the existing secret setting `NDAY_GITHUB_TOKEN` (the ghsa collector's): database settings (encrypted, set on `/admin/settings`, see `docs/settings.md`) layered over the environment, read when the step or command starts. Without it requests are anonymous (60 an hour per address); with it 5,000 an hour. The token is never logged or printed; the logs only say `authenticated=true|false`. Even with a token that can read private repositories, a private or internal repository is never stored (`gone`).

## Display

On the vulnerability page's "Resources" panel (`site.Store.Resources`, `site/repos.go`), a `code` link on github.com is decorated only when all of these hold:

- it is a link to the repository **root** (`/owner/name`, optional trailing `/`, optional `.git`, no query; `ghrepo.RootKeyOf`). Deep links (`/issues/3`, `/blob/…`, `/tree/…`, `/releases/…`, `/security/advisories/…`) keep their plain rendering and are never dropped or merged, also next to a decorated root link of the same repository;
- a link of a post about that CVE with that root key is **stamped** (`repo_github_id`): never a join on names;
- the stamped repository is `ok`. One that turned `gone` keeps its earlier metadata in the table, but its links render plain;
- the stamped repository still holds the link's key (`github_repo_name`) and the key equals its lower-cased `full_name`. A link to a name the repository was renamed away from, or that another repository answers for now, renders plain and keeps its group.

An unchecked link, and one checked without a stamp, render plain.

"About that CVE" above means the page's vulnerability, by either id (see "GHSA ids").

A decorated link shows `Owner/Name` as GitHub returned it, then `★ <stars>` (the locale's digit grouping) and the creation day `YYYY-MM-DD` (UTC) in the same small secondary style as the host. No description or other text. Only these three fields are public (`site/public.go`).
It moves under poc when the repository is associated with **that page's CVE** by `name`, `description` or `topic`, or when it counts as a PoC source of it (below); a `post` association alone keeps it where `xlinks.Classify` put it. Links are never folded: two spellings of the same root (e.g. `/o/r` and `/o/r.git`) are two entries.

**Counted or unreviewed** (since 2026-11-19, owner's request): the repositories under poc are split in two groups on the page. A repository **counts** when it has this vulnerability's `poc_published` event of source `github` (see "PoC events": exactly the `github_poc_want` set, the same thing the stage, `poc_sources` and the summary use; `ResourceRepo.Counted`). The "PoC / exploit code" group holds the non-GitHub PoC links and the counted repositories, with stars and no mark, whoever trusted them (admin, post rule, trusted account look the same). Every other repository under poc — unverified, or trusted but not counting here (rule/owner trust on a `post` basis only, or created more than 30 days before the disclosure) — goes to the collapsed group `rsch.res.unreviewed` ("Unreviewed repositories (N)", `<details>`, dim, own pager `?pocu=`, region `r-pocu`, open when `?pocu=` is in the URL; its pager links always carry `pocu`, page 1 too), without stars and without a per-row mark (the heading says it). The chart draws only the first group. An empty group renders nothing (no heading).

Review status on stamped post links (`ApplyRepos`): a `rejected` one (admin or rule) decorates nothing (its links render plain in their Classify group). One that is not under poc (a code link) and that an admin reset to `unverified` keeps the mark `rsch.res.unverified` ("unverified") and no star count; a trusted one there shows stars.

Found repositories (`site.AddSearchRepos`, query in `repoResources`): after the post links under poc, the other `ok`, not rejected repositories of the page's CVE, still holding their name key, and not shown through a decorated post link are listed as links to `https://github.com/<full_name>`:

- the counted ones first (read from the vulnerability's github events, whatever their association basis or `seen_at`), with stars, at most 200 read, by stars desc, then oldest; a counted fork or collection only when an admin trusted it;
- then up to **100** others (`site.MaxUnverifiedRepos`) associated by `name`, `description` or `topic` — unverified ones and trusted ones that do not count here — **without** a star count, by `min(stars, 50)` desc, then oldest creation, then id (buying more than 50 stars gains nothing);
- these others are filtered in SQL before the limit, unless an admin trusted them: no forks, no collections (more than 3 CVEs by name/description/topic, `ghrepo.CollectionMin`), and only rows search or a fetch returned in the last 14 days (`seen_at`); a known repository that search reports as not public becomes `gone` and is no longer listed;
- a repository is on the page once: not when the panel already has its URL, nor when the panel has a root link to its name (decorated or plain, whatever the spelling).

Before migration 0025 (no stamp and no status column) post links are decorated as in phase 1 and nothing else is listed.

Public: full name, creation day, which group (counts or not: the same fact the PoC events already publish), and stars only in the counted group or on trusted code links (`site/public.go`); never who trusted a repository or why. Pages stay `public, max-age=60`; nothing per user. The API has no repository list: the counted ones are its `github` PoC events, the others are on the page only.

## Discovery (`search.go`, command `nday github-discover [--max-requests N]`, timer `nday-github-discover.timer`)

One run: the new-repository scan, then the targeted search, at most N requests in all (default 40, at most 100), all `GET https://api.github.com/search/repositories` through the same pinned client, **without redirects** (any 3xx is a failed request; the Location is never requested), 15 s per request, body cap 2 MiB for a page of 100 (about 6 KiB per item, 582 KB measured for a full page). Results are stored from the response itself (`storeSearched` → `observe`: the row with the GitHub id — a changed `full_name` is its rename — else the placeholder queued under its name becomes it, else a new row with `first_source = 'search'`; metadata, `seen_at`, its name key, associations; forks stored with `is_fork`). A search result never grants trust, never stamps a link and never changes another row's id or status. Items with no CVE id in name, description or topics are skipped; a known repository that search reports as not public becomes `gone`. A fork with fewer than 10 stars that we have no row for isn't stored at all (see "Skipped forks" below; counted in `skipped_forks`).

| Part | Query (the only variable parts: year, window, CVE id) | Bound |
|---|---|---|
| Scan, CVE years | `CVE-2026 in:name fork:true created:2026-11-13T11:00:00Z..2026-11-16T11:00:00Z`, `sort=updated`, then the same for the previous year | 9 requests a run; the current year at most 6, the previous year the rest (at least 3; with a budget of 1 the years alternate by hour) |
| Scan, GHSA names | `GHSA in:name fork:true created:…..…`, `sort=updated` (scan key `name:GHSA`) | exactly 1 request a run, set aside before the year scans (with a scan budget under 3: every third hour instead) |
| Targeted | `CVE-2024-3094 in:name,description fork:true` or `GHSA-jfh8-c2jp-5v3q in:name,description fork:true`, `sort=stars`, page 1 | 30 ids a run |

- **Scan state** (`github_search_scan`, key `name:CVE-YYYY`: `created_after`, `window_end`, `next_page`, `window_total`, `window_incomplete`): GitHub cannot sort repositories by creation, so the scan reads creation-time windows `[created_after, window_end]`, up to now − 1 h (indexing time; a new key starts 3 days back).
  - Paging a search sorted by `updated` is not stable (a push moves a repository between pages), so **a window is narrowed until it fits one page**: a window wider than 1 minute whose first page reports more than 100 results, or comes back `incomplete_results`, is halved; the halved end is saved, so the next run continues with it (a backlog converges across runs). Only a 1-minute window is read page by page.
  - A window is read cleanly when every page its largest reported `total_count` asks for was parsed and none came back incomplete. Both are tracked over **all** pages of the window, also across runs (`window_total`, `window_incomplete`). Only then `created_after` moves to its end; the next window is at most twice as wide.
  - A run that stops inside a window (budget, rate limit, failure, run time) saves the page to read next and the next run resumes there. A 1-minute window is never skipped for lack of budget.
  - A 1-minute window with an incomplete page is read again from page 1 by the next run (a warning is logged); the cursor does not move. When that happens on 3 consecutive runs (`ScanIncompleteRetries`, counted in `window_retries`), the window is passed with a warning and counted in `scan_dropped` (the results beyond 1,000 if the total says so, else 1), so one window cannot stop a scan for good.
  - The one exception: a 1-minute window with more than 1,000 results moves on after its 10 retrievable pages when none was incomplete; the count passed over is logged and counted (`scan_dropped`).
- **Hot ids** (`HotCVEs`): for every hot vulnerability its own id and, when it is CVE-keyed, each of its GHSA alias ids (see "GHSA ids"). Hot vulnerabilities are the union of the first page of `/discussed` (distinct enabled allowlisted researchers in 7 days; the hot list's pins come from the same ranking) and the first page of `/hot` in its default view (a transition to `patch_released` or later in 7 days, not rejected), 50 each. An id is recorded as searched (`github_search_cve.searched_at`, one row per id) only when a page was parsed, and is then not searched again for 24 h. A failed request (bare 403, 422, 5xx, 3xx, oversized or malformed body, transport error) is not recorded as searched: it adds 1 to `failures`, and the CVE waits 2^(failures−1) hours (1, 2, 4, 8, 16, then 24) before its next try; a success resets it. A rate-limit refusal with headers (or the run time) records nothing. Order: all due CVE ids first, then the GHSA ids; inside each, never tried first, then least recently tried. README (`in:readme`) is not searched: README hits are mostly lists and scanners, and nday does not read READMEs, so such a hit would have no association to show.
- **Budget**: GitHub allows 10 search requests a minute without a token, 30 with one. Requests are 7 s apart without a token (any 60 s hold at most 9) and 2.5 s with one (at most 25). **Any 403 or 429 stops the run** (secondary limits may come without headers), as does a response reporting 0 left. A run stops itself after 15 minutes (`MaxRunTime`; the unit allows 20; the worst case without it would be 100 × (15 s + 7 s) ≈ 37 min). One log line per run: `github discover pass`.
- **One GitHub pass at a time**: `Discover` and the fetch pass (`FetchPending`) share one session advisory lock (try-lock; the one that cannot take it does nothing and reports `"locked": true`), released on every exit.
- Rows found by search that nobody decided about are not refreshed by the fetch pass; they are only updated when search returns them again, and they drop off the page 14 days after search or a fetch last returned them.

### Skipped forks

Rule: a GitHub repository flagged as a fork with fewer than `ghrepo.MinForkStars` (10) stars is not collected. "Skipped fork" = `is_fork` and `stars < 10`; an unknown star count (NULL, or no `stargazers_count` in the answer, now stored as NULL) never skips. An answer without the `fork` flag doesn't decode at all, so the flag is always known for a stored answer.

- **Search** (`storeSearched`, `Repo.SkippedFork`): a skipped fork with no `github_repo` row of its GitHub id writes nothing — no row, no name key, no association, and a placeholder queued under its name is left as it is — so nothing gets queued for it. The run counts it in `skipped_forks` (the JSON output, the log line and the `job_run` detail on `/admin/system`). A fork we already have a row for (a post link, a staff decision) is refreshed as before (`updated`). The queries are unchanged: they send `fork:true`, which makes GitHub return forks along with everything else (without it GitHub search leaves forks out); `fork:false` isn't sent because it would also drop forks with 10+ stars.
- **Everything else** (a fork first seen through a post link, anything asked by id or name): it has to be fetched once to learn it's a fork, and it's stored as usual (state `ok`, the normal refresh cadence). While nobody decided about it (`unverified` with `status_by` NULL) it is left out at read time (`skippedForkSQL`): not in the review queue (`ListReview` / `CountReview`), a post's root link stamped with it stays plain on public pages (and the found listing already leaves out forks an admin didn't trust). No status is written, no rejected name is recorded. When a refresh or a later search hit finds 10+ stars it shows up with no other change.
- Decided rows are never affected: admin-trusted, admin-rejected, an admin's reset, rule-trusted and owner-trusted forks are listed and shown exactly as before, whatever their stars. A skipped fork is never trusted, so it has no PoC event; forks are never trusted by owner, so the trusted-account refetch (`ownerRefetchSQL`) of one doesn't bring it into the queue either.

## Review (`review.go`, `identity.go`, migration 0025)

`github_repo.status`: `unverified` (default), `trusted`, `rejected`; `status_by`: `rule` / `admin` / `owner` (migration 0036, see "Trusted accounts") / NULL; `status_at`. A status belongs to a repository **identity** (a row with a GitHub id), never to a name or a placeholder.

| Who | When | Result |
|---|---|---|
| nobody | found by search, fetched, linked by a deep link, linked by a root link not checked yet or checked without a stamp | `unverified` / NULL |
| rule | a root link is stamped with the identity (`stampLinks`, the only place) and nobody decided about it | `trusted` / `rule` |
| rule | an identity no admin decided about turns up under a name key recorded for another identity's rejection (`observe`) | `rejected` / `rule`; a later stamp does not lift it; an admin can decide (it is a change, with its audit row) |
| rule | the last stamp of a `trusted` / `rule` identity is cleared (the link's root key changed; `untrust`) | back to `unverified` / NULL |
| admin | `SetStatus` | `trusted`, `rejected` or `unverified` / `admin`; no automatic path changes it |
| owner | its owner is an enabled trusted account and nobody decided about it (`syncOwners`: after a fetch or search stored it, and after an admin's change of the list) | `trusted` / `owner` |
| owner | the account is disabled, or the repository moved to an owner not on the list | back to `unverified` / NULL, or `trusted` / `rule` when a link is stamped with it |

So at all times: an identity is `trusted` / `rule` only while some link is stamped with it (a stamp alone does not make it so: an owner-trusted or seeded repository may carry one). When the rule fires (`stampLinks`, on a fetch by name) it replaces owner trust; when the stamp goes, owner trust comes back if the owner is listed. The rule's test (`ruleHoldsSQL`) is "a stamp exists"; stamps are written only for links of stored posts (allow-listed authors) and the test does not look at whether the author is still enabled.

Rejected names: when an admin rejects identity X, X's current name key — and the key of its stored `full_name`, for an X that holds no key at that moment — is recorded in `github_rejected_name` with X as the recorder; while X stays rejected by an admin, every key it comes to hold (a rename learned from its refresh or from search) is recorded too. So deleting the repository and registering its name again, or renaming it and registering the new name again, gives a repository that starts `rejected` / `rule`. Trusting or resetting X removes the keys X recorded, and only those; identities that were rejected by rule in the meantime stay so until an admin decides.

What was removed on purpose: trust through a name join (any name a row ever held), trust at sweep time, the "first id seen for a name" heuristic, the sweep-time `repo_swept_at`, merging rows, and resetting a row's status when its name answered with another id (the row is never rewritten, so there is nothing to reset).

Owner-level rejection (everything of one account) is not done; owner-level trust is (below). Go API for the admin page: `ListReview`, `CountReview` (identities in state `ok` only), `GetForUpdate`, `SetStatus` (status_by `admin`; `ErrRepoNotFound` for a placeholder); `ReviewItem` carries `Collection` (more than 3 CVEs by name/description/topic) and `Predates` (created before the earliest `vuln.published_at` of those CVEs).

## Admin review (`/admin/github`, `internal/admin/github.go`)

Admins only. The unverified repositories (open; without skipped forks nobody decided about, see "Skipped forks"), trusted and rejected (collapsed), 50 per list with the total; each row: the full name (linked to GitHub only when `ValidFullName`), description (escaped), stars, creation date, CVEs (linked to `/vuln/<CVE>`, at most 5 then `+N`), the flags fork / archived / collection / predates, and the source (search / X post). Actions trust, reject and reset (back to unverified) call `POST /api/admin/github/repos/{id}/trust|reject|reset` (no body): one transaction of `GetForUpdate`, `SetStatus` and an audit row `github.repo.trust|reject|reset`; `404 not_found` for an unknown id, `409 no_change` when an admin already set that status. A reset is an admin decision too: the post rule no longer trusts that repository. Details in `docs/admin.md` §2.3 and §4.3.

Locking: one order everywhere — the store lock (`lockStore`, a transaction advisory lock), then `github_repo` row locks. The fetch pass and discovery write in short transactions with no network request inside (`store`, `noAnswer`, the 304 update, `storeSearched`); each first takes the store lock, as do the per-link transactions of the enqueue sweep and an admin decision: `GetForUpdate` takes the store lock and then `FOR NO KEY UPDATE` on the one row. So the writers of `github_repo_name` and of statuses run one after another, `SetStatus` reads the row's names while no pass is moving them, and no two of them can wait for each other in a cycle (nobody holds a row lock while waiting for the store lock). An admin transaction holds the store lock until it commits (the status, the rejected names and the audit row): a pass waits for it for that long. Rows with a GitHub id are never deleted, so an admin's click always finds the row it was about.

## Trusted accounts (`owner.go`, `internal/admin/ghowners.go`, migration 0036)

A list of GitHub accounts (users or organisations) whose repositories need no review, kept by admins on `/admin/github` (section "trusted accounts"): `github_trusted_owner (login, owner_id, note, enabled, x_user_id)`. An identity nobody decided about whose owner is listed and enabled becomes `trusted` / `owner`, whatever links or stamps it has, unless it is a **fork** or a **collection** (more than 3 vulnerabilities by name/description/topic: the flags the public listing hides an untrusted repository by); those stay unverified for a person (staff can still trust them by hand). It never overrides a decision: admin-trusted stays `admin`, admin-rejected and rejected by rule stay rejected, rule-trusted stays `rule`. Taking owner trust back (account disabled, repository transferred, now a fork or collection) gives `rule` when the post rule holds for it now (`ruleHoldsSQL`), else `unverified` / NULL.

- Matching is **by id only**: `github_repo.owner_id` (the API's `owner.id`, stored by every 200 from 0036 on) equals the account's `owner_id`. A login is never enough: a stored row's login may be months old, and a login can be renamed away and registered by someone else (who has another id).
- The account's id: the quick add takes it from the review row's repository when that row has one; otherwise, and for an add by login, one `GET /users/{login}` to https://api.github.com (`ghrepo.LookupOwner`, 10 s, the server's GitHub token when configured) at the add. A 404 refuses the add (`422 github_not_found`). Any other failure (network, rate limit) saves the account **id pending** (shown in the list, "待确认" in zh-Hans): it trusts nothing, and every fetch pass (`FetchPending`, `resolveOwners`, at most 5 accounts a pass) tries again until it is pinned. Its displayed login then follows the owner's renames.
- Rows without `owner_id` (fetched before 0036) whose stored login names an enabled account are only candidates: the fetch pass's refresh picks them (`ownerRefetchSQL`: once after the account was added or enabled, then at most daily), including undecided rows found by search that are otherwise never refreshed, and asks them **without a validator** (no `If-None-Match`, so the answer is a 200 with `owner.id`, never a 304); the answer decides.
- Forks: a fork lives under the forker's account; it is never trusted by owner (above), only by a person.
- When: `observe` (every fetch and search result, so a newly found repository is trusted on arrival and a transferred one is re-checked), `untrust` (a rule-trusted repository whose stamp went), a pinned account, and every admin change of the list. All run under the store lock. An admin change runs in one transaction with `SET LOCAL statement_timeout = '120s'` (the auth pool's 5 s would otherwise cut the deferred PoC sync of a large account).
- X drafts: a new owner-trusted repository can give a PoC event that is **live** only when it was created within the last 30 days; the draft pass drafts such an event only when it is the CVE's first PoC event and was observed within 72 h, at most 10 drafts a run (up to 50 carried over to the next runs; more than 50 qualifying at once are dropped as a bulk change). So adding one account drafts at most one post per CVE named by its recent eligible repositories, and in practice at most 10 a run.
- Accounts are never deleted: disable instead (like the X allowlist). Disabling takes `owner` trust back from that account's repositories; admin decisions are untouched.
- PoC events: `owner` counts exactly like `rule` (below). A listed account's repository that does not name the CVE in its own name, description or topics (only a post links it) is trusted for display but gives no event.
- Public display: `owner` is shown like `rule` and `admin`: in the PoC group when the repository counts, in the unreviewed group (no stars) when it does not.
- **X link**: an account may name one allow-listed X account of the same researcher (`x_user_id`, `ON DELETE SET NULL`; one X account may have several GitHub accounts, e.g. a personal one and an organisation). It is descriptive only: it changes no trust in either direction (disabling the X account does not untrust the GitHub account, and vice versa). It is read only by admin pages (`/admin/github`, and a marker next to the handle on `/admin/x`); no public page, API response, feed or event carries it. The quick add of a review row links the X account when exactly one allow-listed account posted a link to the repository, and nothing when several did.
- Endpoints, audit actions (`github.owner.add|update|enable|disable|link|unlink`): `docs/admin.md` §2.3 and §4.3.

## PoC events (migration 0032, command `nday github-poc [--dry-run]`)

A trusted repository is the fourth PoC source next to exploitdb, metasploit and nuclei (owner's decision, 2026-11-19). It counts for a vulnerability when the row is `ok` and `trusted` and either an admin trusted it (any association, a post alone included) or the post rule or a trusted account (`owner`, migration 0036) trusted it and the association basis is `name`, `description` or `topic` (a `post` basis alone is not enough). GHSA ids resolve as on the pages (`VulnOfSQL`).

**Created before the disclosure** (migration 0033; disclosure = the earlier of `published_at` and the first disclosed event; gap = disclosure − creation): gap ≤ 0, the creation time; 0 < gap ≤ 30 days (coordinated disclosure: a repository prepared under the reserved id, e.g. sfewer-r7/CVE-2026-123007, 4 h before the record), it counts for rule and admin trust alike, at the disclosure time (precision day; live is judged on that time); gap > 30 days (a reused or renamed repository), rule trust does not count and admin trust counts with an unknown time (`occurred_at` NULL, always history). So a github event never makes `days_disclosed_to_poc` negative. The review page's "Predates" flag (`predatesSQL`, Go) is separate SQL and stays a hint for the reviewer.

Stored like the other three: one `poc_published` event per (vulnerability, repository), `source = 'github'`, `dedupe_key` the GitHub id, `occurred_at` the creation time with `detail.precision` `"day"` (pages show the UTC day; the exact time keeps a same-day PoC from sorting before the disclosure), `url`/`detail.url` `https://github.com/<full name>`, `detail.title` the full name. `observed_at` and `created_at` are cut to the UTC day, so neither the API nor the sitemap's `<lastmod>` tells when a post link was checked or a decision made. Nothing about posts or the review goes into the event: events are public.

One definition, in SQL: `github_poc_want(ids)` says which events should exist, `github_poc_diff(ids)` compares (read-only), `github_poc_sync(ids, backfill)` makes it so (inserts what is missing, **deletes** what stopped counting, updates a changed time or name). Triggers call it in the same transaction as every change it depends on, whatever code path makes it (admin decisions, the post rule, fetches, search, merges, an older binary): `github_repo` (status, status_by, state, full_name, repo_created_at; out at once for a repository that is not and was not trusted and has no event), `github_repo_cve`, ghsa rows of `vuln_alias` (deferred to commit, so a fetch that rewrites the associations leaves the event alone) and new `vuln` rows. Only a real change locks the vuln rows `FOR NO KEY UPDATE`.

Revocation: a rejection, a reset, `gone`, a lost association or a creation more than 30 days before the disclosure deletes the event, so stage, chart and lists read as if it had never counted (another source or repository keeps the stage).

**Live or history** does not depend on who calls: an inserted event is live (`is_backfill = false`) only outside the backfill and when the creation time is known, within the last 30 days (the event time: creation, or the disclosure for a repository prepared before it); otherwise it is history. The draft pass drafts a live event when it is the CVE's first PoC, so a recent trusted repository is drafted like a new Exploit-DB entry, while an old one that drops out and comes back (a 404 then ok, a stamp cleared and set, a reset and trust), or a vuln row created for an old id, never is.

Repair: `nday github-poc` runs the sync (history) over every associated vulnerability and every one with a github event (stray events go); `--dry-run` only compares. `nday github-discover` (hourly) ends with the same repair: it converges what no trigger sees, a changed `published_at` or disclosed event (the gap). Nothing else re-syncs on those.

Freshness: the vulnerability page reads events directly. Lists, feed and counts read `vuln_state_mat`: an admin decision that changed an event refreshes it in the background (the request does not wait); `github-fetch`, `github-discover` and the GitHub step after `collect xposts` refresh it when the github events changed (`ghrepo.PoCFingerprint` before and after); collector runs refresh it anyway.

Deploy: stop the collector and discovery timers, `nday migrate` (0032: functions, an index on event, triggers, backfill, rebuilt `vuln_state_mat`; fails after 5 s on a lock and can just be retried), (0033 on its own: replaces `github_poc_want` and runs one backfill, no view rebuild), then `nday github-poc` (prints `{"vulns":N,"added":0,"removed":0,"updated":0,"dry_run":false}` when nothing is out of step), `nday refresh-state`, start the timers.

0036 (trusted accounts): `nday migrate` (adds `owner_id`, widens the `status_by` CHECK, the new table, replaces `github_poc_want`, one backfill that changes nothing while the list is empty; fails after 5 s on a lock and can be retried), then swap the binary. The old binary keeps working in between: it writes only `rule` / `admin`, leaves `owner_id` alone and never grants `owner`; the triggers already fire on any `status_by` change.

## GHSA ids (the second id)

"CVE is the main id, GHSA the second id" (`docs/ghsa.md`): a vulnerability is keyed by its CVE id, or by its GHSA id while it has no CVE; a CVE-keyed one has its GHSA id as a `ghsa` alias (`vuln_alias`). For repositories:

- **Stored as found.** GHSA ids in a repository's name, description and topics are extracted like CVE ids (`xposts.ExtractGHSAs`, the helper the X collector uses: any case in, the canonical form `GHSA-` plus three lower-case groups from GitHub's alphabet out) and stored in `github_repo_cve.cve_id` with the same bases. Nothing is resolved at write time. `github_repo_cve.cve_id` and `github_search_cve.cve_id` accept exactly the two forms `vuln.cve_id` accepts (CHECKs, migration 0025).
- **Resolved when read.** A repository is associated with vulnerability V when it has an association whose id is V's id, or a GHSA id that is a `ghsa` alias of V. This is applied on the public page (the PoC grouping of a stamped post link and the found listing, on CVE-keyed and GHSA-keyed pages: `vulnMatch1/2` in `site/repos.go`), in the collection count (distinct vulnerabilities: a CVE and its own GHSA alias are **one**; a GHSA id we have no record of counts on its own; `ghrepo.VulnOfSQL`), and in the admin list (`ReviewItem.CVEs` shows the main id: the CVE when the GHSA id is its alias; the page links `/vuln/<id>` for both forms).
- **A GHSA-keyed vulnerability gets its CVE.** `pipeline.mergeVuln` moves the rows of the tables it lists and leaves the alias `(ghsa, G) → C`. `github_repo_cve` and `github_search_cve` have no foreign key to `vuln` and are not in that list: nothing in them moves, and nothing needs to — the alias makes the repositories of G show on C's page, and G keeps its `github_search_cve` row as C's second id.
- **Both ids are searched.** For a hot CVE-keyed vulnerability: its CVE id and each GHSA alias id (normally one); for a GHSA-keyed one: its GHSA id. `GHSAQuery` accepts only a canonical GHSA id as its variable part. GitHub matches the id in names: `GHSA-jfh8-c2jp-5v3q in:name,description` returned the one repository whose name contains that id, and `GHSA in:name` returned names like `rudSarkar/GHSA-673q-mjm6-r5xr` and `BlackHatExploitation/GHSA-xqc2-xf4c-x3h3-poc` (460 in all; checked 2026-11-17).
- **Budget.** A run makes at most 30 targeted searches, CVE ids first. The hot set is at most 100 vulnerabilities (50 discussed + 50 hot), so at most about 200 ids when each has a GHSA alias; an id is searched at most once in 24 hours. The hourly timer gives 24 × 30 = 720 searches a day, so both ids of every hot vulnerability fit (it takes 7 runs to go through 200 ids once, the CVE ids in the first 4). Without a token a run's 40 requests are 7 s apart (10 a minute allowed).
- **GHSA name scan.** One request a run for new repositories with `GHSA` in their name; results without a full GHSA or CVE id in name, description or topics are not stored.
- **Advisory links in posts.** `github.com/advisories/…` and `github.com/<owner>/<repo>/security/advisories/…` are `advisory` links (`xlinks.Classify`), not code: not swept, no placeholder, no check.

## Deploying (migration 0025 and this release)

In this order:

1. `nday migrate` — applies `0025_github_discovery` (after `0023`; it uses the id forms of `0026`).
2. Swap the binary and restart the services.
3. `nday github-enqueue` — the new sweep goes over every github.com code link once (it has its own marker) and writes the root keys.
4. `nday github-fetch` — repeat until its output shows `"link_checks": 0` (50 requests a run; without a token wait for the hourly limit between runs, or let the collector runs do it, 25 a run). Until a link is checked it renders **plain**: no name, date, stars or mark.
5. Advisory links stored before this release keep `kind = 'code'` until they are re-classified. `nday renormalize xposts` re-reads the stored posts and rewrites the links the API expanded; this statement does the same for every row, including links the resolver expanded:

   ```sql
   UPDATE x_post_link SET kind = 'advisory'
   WHERE host = 'github.com' AND kind = 'code'
     AND final_url ~* '^https?://(www\.)?github\.com/[^/?#]+/[^/?#]+/security/advisories(/|$|[?#])';
   ```
6. Install and enable `nday-github-discover.timer` (`deploy/README.md`).

Between step 1 and step 2 the old binary may still run (a collector timer). Its sweep only queues names and writes its own marker `repo_queued_url`, which the new sweep ignores, so no link is lost. Its fetch pass asks by name; where it would give a row another GitHub id or delete a row that has one (its rename merge), the triggers refuse, that pass ends with a logged error (`github fetch pass failed`) and changes nothing; it hits the same row again on its next run until the binary is swapped. Alias names it adds are dropped by the next answer the new code stores for that repository. No status and no stamp exists before the new binary runs, so there is no decision it could lose.

## Local preview

`go run ./tools/authdev -x-sample` adds two sample repository links with metadata (one with `CVE-2024-3094` in its name, listed under PoC on that page; one without), and four repositories "found by search" for `CVE-2024-3094` (unverified, trusted by an admin, rejected, an unverified fork), so the panel and the review list can be previewed without network.
