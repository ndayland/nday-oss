# xposts: vulnerability discussion on X (Go only)

This collector uses **only the official X API v2 recent search** (app-only Bearer token) to collect posts from allowlisted accounts that mention a CVE id or a GHSA id (the CVE id is the main id, the GHSA id the second one).
It doesn't scrape web pages and doesn't automate a browser. The only other API call is the **user lookup** used when you add an account to the allowlist (`GET /2/users/by`, see "Adding accounts by handle" below),
which runs only when an admin adds or imports accounts. Collection itself doesn't use it. Code: `internal/collector/xposts` (collector),
`internal/xconfig` (database config), `internal/xlookup` (user lookup), `internal/cli/xposts.go` (commands), `migrations/0008_xposts.sql`,
`migrations/0015_xposts_no_cve.sql` (posts without a CVE id, see below), and `internal/xlinks` with `migrations/0019_xposts_links_candidates.sql` (links in posts and candidate accounts, see below).

## Events

One `event` per (post, CVE id that appears in the post text), and one per (post, GHSA id that appears in it):

| column | value |
|---|---|
| `type` | `social_post`. This is **not a lifecycle stage**. `vuln_state` (redefined in 0008, columns unchanged) counts only the six stage types, so a post never changes the stage, `last_transition_*` or `has_poc`/`exploited`, and doesn't count toward `event_count`. A CVE mentioned only in posts gets a stub `vuln` row but no derived state |
| `source` | `xposts` |
| `occurred_at` | the post's `created_at` |
| `url` | `https://x.com/<handle>/status/<id>` (`https://x.com/i/web/status/<id>` when the author object is missing) |
| `dedupe_key` | the post id |
| `detail` | `post_id`, `author_id`, `author_handle`, `text`, `lang`, `cves` (all CVE ids in the post), `ghsas` (all GHSA ids; the key is there only when the post has one) |

CVE ids: `CVE-YYYY-NNNN…` in the text (case-insensitive, ASCII word boundaries), uppercased and de-duplicated. For long posts (note posts) it reads `note_tweet.text` (the full text), otherwise `text`.
GHSA ids: `GHSA-xxxx-xxxx-xxxx` in the same text (also inside a `github.com/advisories/...` URL), case-insensitive in, canonical out (`GHSA-` upper case, the groups lower case), only when the groups use GitHub's alphabet (`model.IsGHSAID`; anything else is not an id), de-duplicated.
There is no cap on the number of ids per post, for CVE or GHSA ids. The GHSA event is keyed by the GHSA id (`event.cve_id` is the vuln id); the pipeline (`docs/ghsa.md`) then handles it: a GHSA id that is an alias of a CVE
moves the event to that CVE, a GHSA id that has its own vuln row keeps the event on it (it moves to the CVE when the alias arrives), and for a GHSA id with no vuln row **nothing is written** (no event, no stub vuln; silently, not counted, the run does not fail).
A post that names both a CVE and its GHSA id gets two events with the same `detail` and the same `dedupe_key`; after the redirect they are the same `(cve_id, type, source, dedupe_key)` row, so it is stored once.
It does **not** read posts that are quoted or replied to. `detail.text` is still the original `text` field (for a long post, that's the truncated first half).
Posts whose author isn't in the enabled allowlist are dropped before raw is stored (counted in `cursor.last_run.dropped_author`).
**All** other posts by allowlisted authors are stored as raw, whether or not the text has a CVE id.
The raw payload = `{"post": <post object from the API>, "author": <author object from includes.users, or null>, "referenced": [{"type": "quoted"|"replied_to", "post": <post object from includes.tweets, or null>, "author": <its author object, or null>}, …]}`, keyed by post id.
When a post doesn't quote or reply to another post, there's no `referenced`. Older raw records have only `post` and `author` (and no `entities` either); they're normalized as usual.

### Posts without a CVE id (`x_post_no_cve`, migration `0015_xposts_no_cve.sql`)

The query itself requires the word "CVE" or "GHSA" in the text, so the API also returns (and bills for) allowlisted researchers' posts like "id not out yet", "CVE pending", or ones where the id is written as
`CVE-2026-XXXX`. These posts are stored as raw like any other (see above). Normalize produces no `event` and no stub `vuln`, and instead writes one `x_post_no_cve` row per post,
kept for a future "early warning" feature (researchers discuss first, the id comes later).
A post that names a GHSA id but no CVE id is also stored here, in addition to its GHSA-keyed event: Normalize cannot tell whether the GHSA id resolves (the pipeline skips an unknown one), and the table means "not attached to a vulnerability yet",
so the row is kept in every case and nothing is lost. If the GHSA id did resolve, the post is a normal linked post (it has its event) and also has this row; the row does no harm and the link table can say which vuln it belongs to.
**No page, admin list or API reads these two tables yet**; the admin page `/admin/x` shows only the per-run counts.

| column | value |
|---|---|
| `post_id` | the post id (primary key; writes are idempotent on it) |
| `author_id` | the author's numeric id (on the allowlist when stored; no foreign key, since allowlist rows are never deleted) |
| `author_handle` | `username` from `includes.users`; NULL when the author object is missing (not validated; use `xconfig.ValidHandle` before displaying) |
| `text` | the original text |
| `lang` | the API's `lang`; NULL when missing |
| `posted_at` | the post's `created_at` |
| `url` | the same `PostURL` rule as events |
| `observed_at`, `is_backfill` | the time of the run that first stored it, and whether that was the first (bulk) run; like `event`, never changed afterwards |

The write rule is the same as for events: `ON CONFLICT (post_id)` updates only when a column changed (for example the handle differs in a newer raw version of the same post). Repeated collection,
`--renormalize` and `nday renormalize xposts` produce no duplicate rows and don't change `observed_at`.

The link table `x_post_no_cve_link` (`post_id`, `cve_id`, `linked_at`, primary key `(post_id, cve_id)`): a post can later be linked to zero, one or several CVEs,
and the table records when. **Nothing writes it yet** (a future linking feature will). Link rows are deleted along with the post or the `vuln` (`ON DELETE CASCADE`, same as `event`).
After linking, the post stays in `x_post_no_cve` (the text really has no id) and doesn't automatically become a `social_post` event; whether to generate an event is left to a future feature.

Retention and deletion: the existing `social_post` posts have no retention period, cleanup job or compliance deletion (see "Not handled"), and neither does this table; posts deleted upstream aren't re-checked either.
Disabling an account doesn't affect rows already stored (same as events; events are filtered by whether the account is enabled only at display time).

Keeping these posts costs nothing extra: it only stores posts that the query already returns (and bills for).
Cost note: since GHSA ids were added the query is `(from:… OR …) (CVE OR GHSA) -is:retweet`, so it also matches (and bills) posts that mention only GHSA. The number of requests per run and the meaning of `max_posts`/`max_requests` are unchanged,
but the same cap now covers more posts. The longer query tail (28 characters, was 17) leaves fewer accounts per batch under `max_query_length` (default 512), so a large allowlist may need one more request per run. Whether the keyword `GHSA` also matches an id inside a URL
is unverified (X matches the text; what it does with expanded URLs is not documented here).

Existing rows: posts stored before GHSA support keep their raw record, so `nday renormalize xposts` re-reads them and writes the GHSA events (and updates `detail` of events whose post also names a GHSA id); nothing else is needed, and nothing writes `x_post_no_cve_link` yet.

## Configuration

| where | what |
|---|---|
| `NDAY_X_BEARER_TOKEN` (database setting or environment variable) | The only secret. You can store it in the database in `/admin/settings` (encrypted with AES-256-GCM, the database value wins; see `docs/settings.md`), and the environment variable still works as a fallback. It's never logged and never goes into the cursor. The collector uses it to search; the web process (`nday serve`, optional, see `deploy/README.md`) and `nday x-accounts-import` use it only to look up the numeric id for a handle |
| table `x_accounts` | The allowlist: `user_id` (numeric id as text, primary key), `handle`, `note`, `enabled`, `created_at`, `updated_at`. Only enabled rows are read. Rows are never deleted; disable instead |
| table `x_settings` | One row; NULL = default. The CHECK constraints match the hard limits in the code, and reads clamp again (with a warning) |

| setting | default | hard range |
|---|---|---|
| `enabled` | on | — |
| `max_posts` (posts returned per run, billed per post) | 500 | 10..5000 |
| `max_requests` (HTTP requests per run, retries included) | 20 | 1..100 |
| `bootstrap_days` (window for the first run) | 7 | 1..7 |
| `max_query_length` (characters per query) | 512 | 64..4096 |

With no token, no enabled accounts, or `enabled=off`, the run is skipped outright (no request, nothing stored, cursor unchanged,
`collector_state` is ok, and `cursor.last_run.skipped` gives the reason), so you can set up the schedule before configuring anything.

Commands:

```sh
nday x-accounts-import deploy/x-accounts.txt   # format in deploy/x-accounts.example.txt; upserts, never deletes, never changes enabled;
                                                 # lines with only an @handle get their id looked up before import (needs NDAY_X_BEARER_TOKEN in the environment)
nday x-accounts-list
nday x-accounts-disable <user id> / x-accounts-enable <user id>
nday x-settings                                  # show
nday x-settings --max-posts 200 --enabled off    # change; use the value default to restore the default
nday collect xposts
```

### The site's own account is never collected

The site's own X account, `@ndayland` (`xconfig.OwnHandle`, compared case-insensitively, no setting), is never collected. Every write of an allowlist handle (`InsertAccount`, `UpsertAccount`, `UpdateAccount`, import lines, the admin add / add by handle / update / enable / candidate add) fails with `xconfig.ErrOwnAccount` (`422 own_account` in the admin API, a line error in an import). Even if such a row gets into `x_accounts` directly, the collector leaves it out of the search query and drops any post by that account (one log line), a quoted, replied-to or mentioned `@ndayland` never becomes a candidate, and `ListCandidates` / `CountCandidates` hide an old candidate row with that handle.

### Admin UI

The admin page `/admin/x` (`docs/admin.md` §2.1) shows: the status of the last run (from `cursor.last_run`: billed post count `posts`, stored count `kept` (with a CVE id) and `kept_no_cve` (no CVE id, stored in `x_post_no_cve`; the run record also has `kept_ghsa_only`, the part of them that names a GHSA id, which the page does not show; older run records have `dropped_no_cve` instead, and the page no longer shows that field), dropped count `dropped_author`, request count, the reason it was skipped or stopped early, `since_id`),
cost at $0.005 per post (the actual cost of the last run, plus the worst case per run, per day and per 30 days at the current `max_posts`/`max_requests`), the settings form, the allowlist (add, edit, enable, disable, bulk import with a preview),
and a review list of collected posts. Reads and writes go only through functions in `internal/xconfig` (all of which take `*pgx.Conn` / `pgx.Tx`), and every change writes an audit record in the same transaction (`x.settings.update`, `x.account.*`, `x.accounts.import`).
The `x-accounts-import`, `x-accounts-enable|disable` and `x-settings` commands above also write audit records when they change something (the actor is the command line). The page never shows, returns or accepts the token (you enter the token in `/admin/settings`, which also shows only whether it's set and its last few characters; see `docs/settings.md`).
When the web process has a token, it uses it only for the user lookup below, and the page just shows "lookup on / off".

Linked GitHub accounts (migration 0036, `docs/github.md` "Trusted accounts"): a trusted GitHub account may be linked to one allowlisted X account of the same researcher (`github_trusted_owner.x_user_id`, `ON DELETE SET NULL`). The allowlist table shows the linked GitHub logins as small tags after the handle. The link is descriptive only: disabling (or removing) the X account does not untrust the GitHub account, and disabling the GitHub account does not touch the X account. It stays on admin pages; no public page, API response, feed or event carries it.

### Adding accounts by handle (user lookup, `internal/xlookup`)

An admin can add an account by entering just the handle (an `@` is fine): the server calls the official user lookup endpoint on the spot, gets the numeric id, and stores the handle with the capitalization X returns.
**The numeric id found at entry time becomes the account's key from then on** (the primary key of `x_accounts`); a later rename changes only the handle.

- The handle (and the note) is validated first with `xconfig.ValidHandle`; if it's invalid, no request is sent (`400 bad_handle`).
- The request: `GET https://api.x.com/2/users/by?usernames=h1,h2,…` with `Authorization: Bearer <token>`; at most 100 handles per request (bulk import batches by 100);
  one attempt, 10 s total timeout, no retries (not even on 429), and it honors the caller's context. The base URL is fixed to `https://api.x.com` and **only code** (tests, `tools/authdev`) can change it;
  no environment variable can point the token at another host. Error messages, logs, responses and audit records never contain the token.
- Results: a user in `data` → bound; an entry in `errors` whose type ends in `/2/problems/resource-not-found` → "no such account" (`422 x_not_found`);
  any other partial error that names the handle (such as `resource-unavailable`, a suspended account) → "suspended or unavailable" (`422 x_unavailable`); if the handle appears in neither → treated as not found.
  Failures of the whole request: no token → `503 x_lookup_off` (no request sent); 429 → `503 x_rate_limited`; 401/403 → `502 x_auth`; timeout, 5xx, any other status or an unparseable response → `502 x_upstream`.
- If the id is already on the allowlist: same handle → `409 exists` (the response includes `user_id` and `handle`); different handle (a rename, or just different capitalization) → the id's handle is updated to the spelling X returned,
  the note and enabled state stay as they are, the response has `"result":"renamed"` and `previous_handle`, and the audit action is `x.account.update`. An id only ever has one row.
- You can still enter the numeric id as well (no lookup); that's the only way to add accounts when the web process has no token.
- Bulk import (the page and `nday x-accounts-import`): lines with only `@handle  # note` are looked up first and then imported. The rules (two fields = id + handle; one field = handle;
  a one-field line that is all digits is ambiguous and rejected, so write `@digits` for an all-digit handle) are in `deploy/x-accounts.example.txt`. Lookups happen only if every line parses.
  If a handle isn't found, is suspended, or its id duplicates another line, nothing is written and every failing line is listed. A preview (`dry_run`) lists the id found for each line and writes nothing.
- Audit: `x.account.add` has `details` with `user_id`, `handle`, `note`, `lookup` (whether a lookup happened) and `entered` (the handle the admin typed);
  `x.accounts.import` also has `looked_up` (number of lines looked up) and `changed` (the accounts changed, as `"inserted <id> @<handle> lookup"`; ones that don't fit are counted in `changed_omitted`).
- Try it locally: `go run ./tools/authdev -x-sample -admin ada`; the page uses a fake in-process API (sample handles are in `tools/authdev/README.md`).

## Drafts: posts for the official nday X account (`internal/xdraft`, migration `0012_xdrafts.sql`)

This has nothing to do with the collector above: these are posts **we publish ourselves**. When a vulnerability newly reaches POC, ITW or KEV, the system writes an English draft. An admin reviews it at `/admin/x/drafts`
(`docs/admin.md` §2.2), can edit it, then clicks "open in X", which opens **X's own web compose window** (`https://x.com/intent/tweet?text=…`, prefilled with the text + a newline + the detail-page link).
The admin clicks Post on X themselves, then comes back to mark the draft published (optionally pasting the post link) or discard it.

**Posting is manual. The server never calls any X API to post and never stores any X credentials** (this has nothing to do with the collector's `NDAY_X_BEARER_TOKEN`, which isn't used here). The reason: posting a post with a link through the API costs $0.20 each,
while the web compose window is free and every post gets a human check. The compose-window format follows X's official docs https://docs.x.com/x-for-websites/post-button/guides/web-intent
("Base URL: https://x.com/intent/tweet"; `text`: "Pre-populated UTF-8 and URL-encoded Post text"; checked 2026-11-14; the old page on developer.x.com returned 402 to automated fetches and couldn't be read).

**Generation rules** (`xdraft.Generate`):

- A draft is written when a CVE's `poc_published` / `exploited_in_wild` / `kev_added` event is a **live observation** (`is_backfill = false`) and is the **first** event of that type for that CVE (smallest id; old bulk-imported events count as earlier).
- If the CVE already has `kev_added`, `exploited_in_wild` is skipped; a revoked CVE (REJECTED, the same rule as `vuln_state`) is skipped; other types such as `social_post` are ignored entirely.
- There is **at most one** draft per (CVE, stage), ever (unique constraint `x_draft_once`); re-runs and later duplicate events never generate another.
- An event id watermark (`x_draft_state.last_event_id`) means only new events are looked at; the **first run** only records the current max id and generates no drafts for history.
- At most `xdraft.MaxDraftsPerRun` = 10 per run. When there are more: if the run's qualifying events number no more than `xdraft.MaxBacklog` = 50 (for example CISA adding dozens of KEV entries at once), the extra ones are **carried over**: the watermark stops before the first event that didn't get a draft, and later runs continue (`carried`). More than 50 counts as a bulk change, and the excess is **skipped permanently** (`skipped_cap`). Events whose `observed_at` is more than 72 hours (`xdraft.MaxEventAge`) before the run are skipped permanently (`skipped_old`), so a carried-over backlog is bounded too. Bulk imports (backfill) generate no drafts and don't fill the queue.
- Concurrency safety: a run first locks the watermark row inside one transaction (`FOR UPDATE`), then does `LOCK TABLE event IN SHARE MODE` to make sure no transaction is still writing events (ids are assigned first and commits may come later; the SHARE lock waits for them to finish), and only then reads `max(id)`.
  The SHARE lock also conflicts with (auto)VACUUM/ANALYZE. The step after collection and `--dry-run` use `NOWAIT`: if the lock is busy they defer right away (`deferred: lock_busy`; if another run holds the watermark row it's `another_run`), and the writer's own later step or the next run picks it up, so nothing is missed.
  A manual (non-dry) run waits up to 3 seconds (`xdraft.WaitLock`; new collector writes queue behind it while it waits), then defers and tells you to retry later. A deferral caused by a busy event table is recorded in `x_draft_state.last_run` (`deferred`, `deferred_at`), leaves the watermark and the previous run's counts alone, and the admin page shows it. The lock is held only for this very short transaction.

**Text** (`xdraft.Build`; data only, no model):

```
CVE-2026-125350 +KEV T+0d
Google / Chromium, Chrome
Google Chromium Use-After-Free Vulnerability
Added to the CISA KEV catalog (known exploited).
```

Line 1: the CVE id, the site's stage-change notation (`+POC`/`+ITW`/`+KEV`), and `T+Nd` when the site's rule (`site.CalendarDays`: UTC calendar days from first disclosure to the first time of that stage) can give one.
Line 2: the affected vendors/products (de-duplicated the same way as the share card: "X / X" → "X", "X / X Foo" → "X / Foo", at most 3 pairs, the rest as "+N"; placeholders such as `n/a` are removed).
Line 3: the upstream English title (truncated). The last sentence says what happened (for a PoC it names the source: Exploit-DB entry / Metasploit module / nuclei template / GitHub repository).
Upstream text (title, vendor, product names; text an admin has edited isn't processed) is always treated as untrusted (`xdraft.Clean`): NFC; control and format characters (including bidi controls, zero-width joiners and tag characters) and emoji modifiers (U+FE0E/U+FE0F, skin tones U+1F3FB–1F3FF, U+20E3) are removed; whitespace is collapsed; links with a scheme (`…://…`) are removed; `@` and `＠` become `[at]`;
`#` and `＃` are removed when followed by a letter, digit, combining mark or `_` (`#1day` → `1day`); `$` and `＄` are removed when followed by a letter, combining mark or `_` (`$5` stays);
**every** dot (`.`, and `。` U+3002, `．` U+FF0E, `｡` U+FF61) whose previous character is a letter, digit or combining mark and whose next character is a letter or combining mark becomes `[.]`, whatever precedes the hostname (`中evil.com`, `x_y.evil.com`, `exämple.com` and `evil.рф` are all handled).
A dot followed by a digit is kept (`2.4.1`, `v1.2`): top-level domains start with a letter, so such a dot can't be the last dot of a domain and doesn't form a link. `ASP.NET` becomes `ASP[.]NET`; safety comes first. No hashtags, emoji or @ are added.
The text **contains no link** (the collector's environment has no `NDAY_PUBLIC_URL`); the page appends the newline and the detail-page URL only when it builds the compose link.

**Length**: it uses X's weighted length (twitter-text v3: limit 280; code points 0–4351, 8192–8205, 8208–8223 and 8242–8247 count 1, everything else counts 2, an emoji sequence counts 2, a link counts 23). `xdraft.WeightedLength` computes an **upper bound** and never undercounts:
text + newline + link (23) ≤ 280, that is, text ≤ 256. When generating, it first truncates the title, then drops the title, then truncates the product line. When an admin saves edited text, the server allows up to 280 (the whole post, for the image forms below; `400 too_long` above that); a text over 256 then has no link-form compose link, and marking it posted in the link form is refused (`400 link_too_long`). The generator still writes at most 256.
Each code point is counted on its own (emoji sequences aren't merged; © and ® count 2). Only a "definite link" counts 23: one at the start or after ASCII whitespace, with a lowercase `http(s)://` and an ASCII hostname whose top-level domain is on the list, a path limited to a conservative ASCII character set, and trailing punctuation removed (X will turn at least that part into a link).
Anything else X might recognize as a link is covered by a surcharge: each dot that could end a domain (letter/digit/combining mark before, letter/combining mark after) adds 19 (a link counts 23, and the shortest link, `a.co`, itself counts at least 4).
So emoji sequences, oddly placed links and things like `e.g` get overcounted, which only makes the limit stricter.

Command: `nday x-drafts [--dry-run]` (a manual run; `--dry-run` prints the JSON of the drafts it would generate and writes nothing, not even the watermark). The same step runs automatically after every successful `nday collect <source>` (one log line, `x draft pass`);
a failure is only logged and doesn't affect the collection result.

### Forms (migration `0034_xdraft_form.sql`)

To find out whether X holds back posts that carry an outside link, each pending draft on `/admin/x/drafts` offers three ways to post it (radio buttons on the row; `link` is the default):

| form | compose window | what the admin does by hand |
|---|---|---|
| `link` | text + newline + the English detail-page link (`xdraft.ComposeURL`, as before) | nothing |
| `image` | the text alone: no link in the text and no `url` parameter (`xdraft.ComposeTextURL`) | attaches the address card ("copy image" or "download image") |
| `image_reply` | as `image` | as `image`, then replies to their own post with the link ("copy link") |

The text-only post may use the whole 280 (`xdraft.FitsAlone`), and saving accepts up to 280. The budget with the link (`xdraft.BodyBudget` = 256) is unchanged: the generator and `xdraft.Share` still write at most 256; a saved text of 257–280 shows as over in the link form (no compose link there, server-rendered and in the script), and "mark posted" with form `link` refuses it (`400 link_too_long`), so the recorded form can't be wrong.
The link in a post names the stage: `…/vuln/CVE-…?s=poc` (`?s=itw`, `?s=kev`; `stageLink` in `internal/webui/share.go`, used by the drafts and by the page's share control; no stage, no parameter). X keeps the card of a URL it has already seen whatever the page shows later, so a post about a new stage needs a URL of its own; the page ignores the parameter and its canonical URL stays the plain one.
The chosen form is kept per draft in the browser (`localStorage`, key `nday.xdform.<id>`; it survives the reload after a save, is dropped when the draft is posted or discarded, shows up in the history, or is two weeks old; without storage the choice resets to `link` on reload).
The **address card** is the share card with the page's address printed in place of the brand at the top left (`nday.land/vuln/CVE-…`; `ogcard.Card.Address`, which changes the card's key, so caches never mix the two): `GET /og/vuln/{id}.png?addr=1`, the same route, caching and headers as the plain card (without `?v=` it's cached for 5 minutes).
Both cards carry the faint brand-mark watermark of the vulnerability's first tag with an icon (`ogcard.Card.Mark`, part of the key; docs/tagicons.md "On the share card"), or, when no tag has one, the product's name as a faint text watermark (`ogcard.Card.Wordmark`, also part of the key). Both also print the CVSS base score the page shows ("CVSS 9.1", `ogcard.Card.Score`, part of the key) right-aligned on the id row, red for a critical score (9.0 and up), the text colour otherwise; the id shrinks to leave room for it, and without a score the row is as before.
"copy image" fetches that same-origin PNG and puts it on the clipboard as an `image/png` `ClipboardItem`; it only shows where the browser supports that. The server still never posts and never calls X.

"mark posted" sends the form used (`{"form": "link" | "image" | "image_reply"}`; absent or `null` means `link`, anything else is `400 bad_form`). It's stored in `x_draft.form` (nullable; a CHECK allows only these three values and only on posted drafts; drafts posted before 0034 stay `NULL`), recorded in the audit row's details (`form`), and shown in the history's "form" column.

### Share control on public pages

Every vulnerability page has a small "share" menu next to the id's copy button: "post on X" (a plain link to the compose window, new tab) and "copy text" (script only; hidden without it, like the copy button).
The text is `xdraft.Share`: the draft body for the vulnerability's most advanced stage reached (KEV > ITW > POC, with the source of that stage's first event and its `T+Nd`, exactly as a draft would have it), or the same body without the stage when none was reached; English on every locale, upstream text through `xdraft.Clean`, at most 256 so that the link fits.
The link is the page's canonical URL in the page's language (`https://www.nday.land/zh-hans/vuln/CVE-…`; English has no prefix). It's built from public data only (the record and its events, never X posts), so the page stays the same for every visitor (`TestPostsNotPublic` compares it with posts stored and without).

## Fetch strategy

- Each request: `tweet.fields=author_id,created_at,lang,entities,note_tweet,referenced_tweets`,
  `expansions=author_id,referenced_tweets.id,referenced_tweets.id.author_id,entities.mentions.username`, `user.fields=username,name,profile_image_url` (`name` and `profile_image_url` since 2026-11-20, for the author cards; see "Author profiles and avatars")
  (a real request confirmed the API accepts these parameters, HTTP 200). `includes.tweets` holds the quoted/replied-to posts, and `includes.users` holds their authors and the mentioned users.
  **Billing is unverified**: X's docs don't say whether these extra fields and the expanded quoted posts (`includes.tweets`) are billed per post on top; go by actual usage in the developer console.

- Enabled accounts are sorted by numeric id and packed into as few queries as possible: `(from:h1 OR from:h2 …) (CVE OR GHSA) -is:retweet` (the two keywords are grouped so the implicit AND with the `from:` group and `-is:retweet` keeps its meaning),
  with length ≤ `max_query_length`. Each batch is one query, paged with `pagination_token`, with `max_results` ≤ 100 per page
  (and no more than the remaining `max_posts`; it stops when fewer than 10 remain, so the number of posts returned never exceeds `max_posts`).
- `from:` uses the handle: the official docs only show the `from:<username>` form and don't say whether a numeric id works.
  The numeric id is still the primary key: posts whose returned `author_id` isn't in the enabled allowlist are dropped. After an account is renamed, update the handle
  (re-importing does it), otherwise new posts from that account won't be found.
- The first run (or one where the cursor's `since_id` is outside the 7-day window) uses `start_time = now - bootstrap_days`
  (no earlier than now - 7 days + 1 hour); after that it uses `since_id` = the largest post id seen. The API accepts only one of the two.
- `since_id` advances only when **all batches complete**. Hitting the request limit or the post limit, an HTTP 429, or 3 consecutive 5xx/transport errors
  stops the run cleanly: the posts already fetched are stored as usual (they're already billed), `since_id` doesn't change, and the next run fetches them again;
  `cursor.last_run.stopped` / `stop_info` record the reason (handled the same way as ghsa's truncated runs). 429 isn't retried.
  Other 4xx errors (a bad query, an invalid token) fail the whole run; the error message contains only the URL (no token) and the API's title/detail.

## Author profiles and avatars (`x_user`, migration `0038_x_user.sql`)

The researcher section shows each author's X display name and avatar (added 2026-11-20).

**Data.** The search request asks for `user.fields=username,name,profile_image_url`. The raw payload keeps the whole `includes.users` object as `author`, and `Normalize` turns it into one `model.XUser` per post (`authorProfile` in `internal/collector/xposts/xposts.go`), which the pipeline upserts into `x_user` keyed by the numeric user id:

| column | value |
|---|---|
| `name` | `name`, cleaned by `xavatar.CleanName`: invalid UTF-8, control characters and invisible format characters (bidi overrides and isolates, zero-width marks; the zero-width joiner of emoji stays) dropped, whitespace collapsed to one space, trimmed, cut to 64 characters; NULL when nothing is left. Untrusted text: only ever rendered as text |
| `avatar_url` | `profile_image_url`, kept only when `xavatar.AvatarURL` accepts it: `https`, host exactly `pbs.twimg.com`, no user info, no port, a path under `/profile_images/` with no dot segments or escapes, no query or fragment, at most 2048 bytes; NULL otherwise ("no avatar") |
| `seen_at` | when the raw record was fetched from X (the run time in `nday collect xposts`, the stored `raw_record.fetched_at` in a renormalize): the newest fetch wins, so re-normalizing an older raw record never rolls a profile back, and a profile change shows on the next fetch of any of the author's posts |

A raw record whose author object has neither field (stored before the request asked for them), or whose author id is not a valid user id, gives no row and changes nothing; every allowlisted author fills in on their next collected post. A NULL `avatar_url` also drops a stored image; a changed one keeps the old image until the new one is fetched.

**Backfill** (`nday x-profiles [--dry-run] [--only-missing | --all]`, `internal/xprofiles`): so authors don't have to wait for their next collected post. The command looks the enabled allowlisted accounts up by id (`GET https://api.x.com/2/users?ids=<up to 100>&user.fields=username,name,profile_image_url`, `xlookup.ProfilesByID`: the same client, token and rules as the handle lookup: fixed host, one attempt, no retry, the token never logged), at most 10 requests a run, 1 s apart, 2 minutes in all; HTTP 429 stops the run cleanly (`rate_limited`; what was written stays). Each returned user goes through the collector's own `xavatar.Profile` (cleaned name, `AvatarURL`, `xconfig.ValidUserID`) and `pipeline.UpsertXUser` with `seen_at` = the time of the request, so "newest fetch wins" holds across both paths. Users X does not return (suspended, deleted: partial errors) are counted as `not_returned` and skipped. `--only-missing` (the default) asks only for accounts without a row or with one older than 30 days, so re-runs are cheap and continue after a cap or a 429; `--all` asks for every enabled account; `--dry-run` fetches and validates but writes nothing. Output: the counts as JSON (`considered`, `requested`, `returned`, `with_name`, `avatar_accepted`, `avatar_rejected`, `rejected_sample` (scheme, host and first path segment of up to 3 refused URLs), `not_returned`, `written`, `requests`, `rate_limited`, `timed_out`, `capped`, `dry_run`) and one "x profiles pass" log line. It never fetches images: the avatar pass below does, and only for authors a public outline shows. It needs the X token like `x-accounts-import` (database settings, or pass `/etc/nday/xposts.env` along with `nday.env`).

**Fetching the bytes** (`internal/xavatar`, `Run`): readers' browsers must never contact X or twimg (privacy, and the page CSP stays `img-src 'self' data:`), so the site stores the images and serves them itself. `nday site-icons` (the daily `deploy/systemd/nday-site-icons.timer`, whose unit already blocks private address ranges) runs an avatar pass after the site icons: at most 100 due avatars, 0.5 s apart, at most 3 minutes (with the icons' 15 it stays under the unit's 20-minute timeout). Due means an author the public outline shows (the same `researchsql.ListedAuthor` rule as serving: an author whose posts all lack a CVE, or are cut from every outline, is never fetched, so the avatar route cannot reveal allowlist membership the pages don't) whose `avatar_url` was never tried, changed since the last attempt (`avatar_tried`), or whose `avatar_next_try_at` passed. Each request goes through an `internal/pagefetch` client like the site icons': https only, the connect-time address guard (no private, loopback or link-local address, checked after DNS), redirects allowed only to another `pbs.twimg.com/profile_images/` URL (`pagefetch.Options.CheckRedirect`), 10 s timeout, 256 KiB body cap. The bytes must be PNG, JPEG, WebP or GIF by their magic bytes **and** a header decode (`siteicon.ValidateImage`, at most 1024 pixels a side; the `Content-Type` header is ignored; never SVG or ICO). Outcomes: `ok` (bytes, type, the first 16 hex digits of their SHA-256 and the time stored; refreshed after 30 days), `none` (no usable image: tried again after 30 days or when the URL changes), `error` (5xx, 408, 429 or a transport error: tried again after 1 h, 4 h, 16 h, ..., at most 30 days; a stored image is kept). Nothing is fetched while a page is served, so a visitor can never cause an outbound request. The command's JSON output has the avatar counts under `avatars`.

**Serving**: `GET /avatar/<hash>` (`internal/webui/xavatars.go`) serves the stored bytes of the image with that hash, only for an author the public outline shows (an enabled allowlisted account with at least one post among the newest 50 researcher posts of some CVE, `researchsql.ListedAuthor`, the outline query's own rule), with the stored (sniffed) `Content-Type`, `Cache-Control: public, max-age=604800, immutable` (the path is the content hash, so the bytes never change; a week, so a disabled account's picture ages out of caches), `ETag`, `X-Content-Type-Options: nosniff`, `Content-Security-Policy: default-src 'none'; sandbox` and `Cross-Origin-Resource-Policy: same-origin`. Anything else (unknown or malformed hash, a disabled account, a type other than the four) is a 404 cached for 5 minutes. The path is keyed by the image hash rather than the X user id because the outline is public and never names the numeric id. Without an avatar the card shows a square with the handle's first letter (CSS only).

## Links and candidate accounts (`x_post_link`, `x_account_candidate`, migration `0019_xposts_links_candidates.sql`)

`x_post_link` is read by the vulnerability page (see "Public visibility" below): the public "Resources" section, and the real links that signed-in users see in post text.
The two candidate-account tables are read by the candidates section of `/admin/x` (admin only, see below) and the commands below; no public page or API reads them.

**Links** (`x_post_link`, primary key `(post_id, pos)`; no foreign key, since a post lives in `event` or `x_post_no_cve`): one row per distinct t.co short link in each stored post (with or without a CVE id).
`pos` is the order within the post (for a long post, `note_tweet.entities.urls` first, then `entities.urls`, de-duplicated by short link).

| column | value |
|---|---|
| `short_url` | the `https://t.co/…` in the text |
| `expanded_url` / `final_url` | the API's `expanded_url`; `final_url` is `unwound_url` when there is one, otherwise the same as `expanded_url` |
| `host` | the lowercase hostname of `final_url`, without a leading `www.` |
| `kind` | `xlinks.Classify`: `media` (this post's own image/video), `quote` (another X post), `patch` (GitHub commit/pull/compare, the GitLab equivalents, chromium-review, crbug, issues.chromium.org), `code` (other GitHub/gist/GitLab repository links; you can't tell from the link whether it's a PoC, so it isn't called poc), `poc` (exploit-db, Packet Storm), `advisory` (a very short table of vendor/CERT hosts in `internal/xlinks/classify.go`, plus `github.com/advisories/`), and everything else, including unparseable links, is `other`; only http/https is recognized |
| `title` | the API's card title (sometimes present) |
| `origin` / `status` | `api` / `ok`: from the API's entities; `pending`: only the short link is known (see below); after the resolver resolves it, `resolver` / `ok`, and `failed` after 3 failures |
| `attempts`, `resolved_at` | the resolver's request count and resolution time (`resolved_at` is NULL for rows that came from the API) |

Older raw records (stored before entities were requested, so they have none): `https://t.co/<alphanumeric>` is taken from the text and stored as `pending` (`kind = other`, empty `host`; `origin = api` means the short link came from the post itself).
Writes are idempotent: `ON CONFLICT` updates only on change; an `ok` row is never downgraded to `pending`, and a `pending`/`failed` row's `attempts` is never reset by a rewrite (unless the same position gets a different short link).

**Resolver**: `nday x-links-resolve [--limit N]` (default 200). For rows with `status = pending` and `attempts < 3` (oldest first), and only when the short link is **exactly** `https://t.co/<alphanumeric>`, it sends **one** GET,
doesn't follow redirects, and reads only `Location` (which must be an absolute http/https address); it writes `expanded_url`/`final_url`/`host`/`kind`. No `Location`, any other status code or a network error gives `attempts+1`, and at 3 the row is marked `failed`.
A short link that isn't t.co sends no request and goes straight to `failed`. Each request has an 8 s timeout, there's a 250 ms pause between requests, and when the context is cancelled it stops between rows. The request host is fixed to `https://t.co`; only code (tests) can change it, and no environment variable can.
The same step runs automatically after every successful `nday collect xposts` (one log line, `x link pass`); a failure is only logged and doesn't affect the collection result. Other sources don't run it.

**Titles for linked pages (xposts only enqueues; the web page module fetches)**: xposts doesn't fetch third-party web pages. It only hands the links to the web page queue (`web_page`, `internal/webpages`, see `docs/webpages.md`).
`xlinks.EnqueuePages` is an idempotent scan: it takes rows in `x_post_link` with `status = 'ok'`, a `kind` that is publicly displayed (`poc`, `patch`, `advisory`, `code`, `other`), and a `final_url` that differs from the row's `page_queued_url` (a column added in migration 0020 that records the address last handed to the queue),
and calls `webpages.Enqueue(url, "xposts")` for each (de-duplicated by `pagefetch.URLKey`; addresses that don't meet the fetch rules, namely non-http/https, with user info, a non-default port, a non-public IP literal, or longer than 2048 bytes, aren't enqueued).
After handling each row, whether it was enqueued, was already in the queue (another spelling of the same key) or was rejected, it sets `page_queued_url` to the `final_url` at that moment, so later scans don't re-read these rows unless the final address changes.
It also backfills existing rows, via the manual command `nday x-links-enqueue`. After every successful `nday collect xposts` the steps run in order: t.co resolution → enqueue (log `x link enqueue`) → one round of page fetching (`webpages.FetchPending`, log `web page fetch pass`; enqueue and fetch share a 2-minute limit and at most 25 addresses),
and each step's failure is only logged and doesn't affect the collection result. When tests or `tools/replay` inject a Transport, the fetch step is skipped (so arbitrary hosts are never reached through an injected Transport). Manual fetch: `nday pages-fetch [--limit N]`.
Then the GitHub repository step (`docs/github.md`): repository links (`kind = 'code'` on github.com) are queued (log `github enqueue`) and one pass fetches their metadata from `https://api.github.com` (log `github fetch pass`; its own 2-minute limit, at most 25 repositories, stops quietly at the rate limit). Manual: `nday github-enqueue`, `nday github-fetch [--limit N]`.

**Candidate accounts** (`x_account_candidate`, `x_account_candidate_ref`): for each stored post, each user it quotes (`quoted`), replies to (`replied_to`) or @-mentions (`mentioned`, including in a long post's `note_tweet`) gets one ref
(primary key `(user_id, post_id, kind)`; `referrer_id` is the post's author, that is, an allowlisted account). The author themselves and items without a numeric id are skipped. A quoted post's author id comes from `author_id` in `includes.tweets`.
The handle is stored as the API gave it, or NULL if it's invalid (fails `xconfig.ValidHandle`); **still validate with `xconfig.ValidHandle` before displaying**.
Candidate rows are upserted: `first_seen_at`/`last_seen_at` take the minimum/maximum of the post times (re-running old records changes nothing), the handle follows the newest post, and **`status` is never changed** (once an admin dismisses a candidate, it stays dismissed).

The read/write functions are in `internal/xconfig/candidates.go` (they take `*pgx.Conn` / `pgx.Tx`): `ListCandidates` (lists only pending by default; excludes ids already in `x_accounts`, enabled or not;
sorted by the number of distinct **enabled** allowlist referrers descending, then ref count descending, then most recently seen descending; returns the handle, referrer count, ref count, kinds, first/last seen times and up to 3 post ids), `CountCandidates` (the same filter, no limit), `GetCandidateForUpdate`, `DismissCandidate` and `RestoreCandidate`.
The command `nday x-candidates [--limit N]` (default 50) lists pending candidates as text.

**On `/admin/x`** (section "candidates", `internal/admin/xcandidates.go`): the first 50 open candidates in `ListCandidates` order (a "first 50 of N" line when there are more), each with its `@handle` (a link to `https://x.com/<handle>` only when it passes `xconfig.ValidHandle`, otherwise a dash), user id, number of enabled referrers, kinds, last seen time, and the buttons **add to allowlist** (only with a valid handle) and **dismiss**; the dismissed ones (first 50) sit in a collapsed toggle with **restore**. Every button needs a second click to confirm.
Endpoints `POST /api/admin/x/candidates/{user id}/add | dismiss | restore` (no body; same checks as the other X actions; `docs/admin.md`). **Add** inserts the candidate's stored id and handle into `x_accounts` (enabled, empty note) with `xconfig.InsertAccount` in one transaction with the audit row `x.account.add` (`details` has `"candidate": true`, `"lookup": false`); no X API request. Refused with `422 no_handle` when the stored handle is missing or invalid (add such an account with the add form), `409 exists` when the id is already listed. The candidate row itself is **left as it is**: `ListCandidates`/`CountCandidates` exclude every id present in `x_accounts`, so it leaves the list at once. Dismiss/restore write `x.candidate.dismiss`/`x.candidate.restore` (target `x_account`/user id); a repeat is `409 no_change`.

## Official documentation references (checked 2026-11-13)

- Endpoint `GET https://api.x.com/2/tweets/search/recent`, covering the last 7 days, up to 100 per request:
  https://docs.x.com/x-api/posts/search/introduction , https://docs.x.com/x-api/posts/search-recent-posts
- At most one of `start_time` and `since_id`; `max_results` 10..100; `next_token` is in `meta`:
  https://docs.x.com/x-api/posts/search-recent-posts , https://docs.x.com/x-api/fundamentals/pagination
- Query length: recent search 512 characters (Enterprise 4096):
  https://docs.x.com/x-api/posts/search/introduction , https://docs.x.com/x-api/posts/search/integrate/build-a-query
- Rate limit headers `x-rate-limit-limit` / `-remaining` / `-reset`, 429 when exceeded; recent search is 450 requests per 15 minutes per app:
  https://docs.x.com/x-api/fundamentals/rate-limits
- Billing: reading posts is $0.005 per post: https://docs.x.com/x-api/getting-started/pricing

User lookup (checked 2026-11-14, quoted from the docs):

- Endpoint and limits: https://docs.x.com/x-api/users/user-lookup-by-usernames, the operation "Get Users by Usernames", `GET /2/users/by`, server "url: https://api.x.com";
  the `usernames` parameter is required, "minItems: 1", "maxItems: 100", each item with the pattern "^[A-Za-z0-9_]{1,15}$" (`style: form`, `explode: false`, that is, comma-separated);
  https://docs.x.com/x-api/users/lookup/introduction : "Retrieve up to 100 users per request".
- Authentication: the endpoint's security lists "BearerToken"; https://docs.x.com/resources/fundamentals/authentication : "App only Access Token allows a X developer app to access information publicly available on X."
- Partial errors: `errors` in a 200 response are Problem objects, with types "https://api.x.com/2/problems/resource-not-found" and "https://api.x.com/2/problems/resource-unavailable"
  (required `type`, `title`, `detail`, `resource_type`, optional `value` and others). The docs give **no** example and **don't** say which type a suspended account gets;
  the classification above (anything other than not-found counts as unavailable) is a conservative reading of those two type names and hasn't been verified against the real API.
- Rate limit: https://docs.x.com/x-api/fundamentals/rate-limits , `GET /2/users/by` "300/15min" per app, "900/15min" per user; a 429 example is
  `{"errors": [{"code": 88, "message": "Rate limit exceeded"}]}`; "Rate limits and billing are separate".
- Billing: https://docs.x.com/x-api/fundamentals/post-cap : "X API v2 uses **pay-per-usage** pricing."; that page's billing table lists only post endpoints, not user lookup;
  "Only successful responses that return data are billed." The docs don't say whether user lookup is billed separately (go by the developer console).

## Public visibility (signed-in users can read posts; the public sees only counts)

The rules live in `internal/site/public.go` (the comment at the top of the file is the authority) and are verified by `TestPostsNotPublic` and `TestResearcherCounts` in `internal/webui/nonpublic_test.go`.
**The only things about posts (`social_post`/`xposts`) that are public to a signed-out client** are:

| what's public | where |
|---|---|
| The number of **distinct** allowlisted authors who mentioned each CVE in the last 7 days (`researchers_7d`): post time `occurred_at` from 00:00 UTC six days ago up to now (today and the 6 UTC days before it; since 2026-11-21 calendar days instead of a rolling 168 hours, so no public number moves at the moment a post turns 7 days old, only at 00:00 UTC or when a post arrives; the hot list's pin rules measure "72 hours" and "7 days" from 00:00 UTC today for the same reason) | the `@N` badge on each `/hot` row (when N>0), a new field on each row of `GET /v1/hot`, next to the "Researcher discussion" heading on the vulnerability page, `/discussed` and `GET /v1/discussed` |
| Ranking CVEs by that number (ties go to the one with the newer latest post, then by CVE id ascending; the post time itself isn't returned) | `/discussed`, `GET /v1/discussed` |
| The `/discussed` **heat ranking** (owner's decision of 2026-11-21; the page only, not its JSON): per CVE the number of posts on each of the last 7 UTC days (today and the 6 before: exactly the researcher window, so the 7 counts add up to the CVE's posts in it), whether its **first researcher post ever** falls on today's or yesterday's UTC date (the "new" flag; it reveals that UTC day, like the sparkline, and can flip only at 00:00 UTC or when a post arrives, never at a post's own time), and the avatars of up to 4 window authors whom **that CVE's own outline** lists (newest post first; the same `/avatar/<hash>` paths, decorative: empty `alt`, no name, handle or link; an author cut from that CVE's outline only counts in "+N", which is the public count minus the avatars shown). Rules: `researcherHeatSQL` and `facesSQL` in `internal/site/public.go`, the flag in `discussedSQL` (`internal/site/discussed.go`); only the page asks for these (the JSON API runs the plain ranking); the trend label compares the posts of the last 3 days with the first 3 | each row of `/discussed` |
| **Pinning** on the first page of the hot list: CVEs with ≥ 2 researchers, a latest post from today or the 3 UTC days before (72 hours rounded up to whole UTC days), and a current wave of discussion that began today or in the 7 UTC days before (a wave: posts whose UTC dates are at most 7 days apart) are placed first and marked "Pinned". If fewer than 10 (the default `NDAY_HOT_PIN_MAX`) qualify, the top of the discussed ranking (the same counts as `/discussed`) fills the rest, and filled rows are also marked "Pinned", with `pin_reason: "discussed"` in the API. Rules: `internal/site/pin.go` and `pinned` under `/api/hot` in `docs/api.md`. All this reveals is "someone posted in the last few days", which doesn't go beyond the posting dates the outline already makes public; the post time itself isn't returned | the "Pinned" badge on each row of `/hot` (and tag pages), `pinned` on each row of `GET /v1/hot`, and `pin_reason` on pinned rows |
| The **outline** in the researcher section of the vulnerability page (author names are public): lists a few entries (at most 50, newest first), each with the **author @username** (the handle stored with the post, which must pass `xconfig.ValidHandle`; otherwise the neutral name "researcher" is shown, unlinked) and a link to their X profile, since 2026-11-20 the author's **X display name and avatar** (`author_name`, `author_avatar`; the avatar is a same-origin `/avatar/<hash>` path, see "Author profiles and avatars"), the UTC date of the post, and a rough length bucket (`s` ≤ 80 characters, `m` ≤ 200, `l` longer) | the page HTML (everyone sees the same thing), and `GET /api/posts/{cve}` when signed out |
| The **Resources** section of the vulnerability page: the links in that CVE's researcher posts (`x_post_link`, `status = 'ok'`, `kind` not `media`/`quote`, `final_url` an absolute http/https address with no user info and at most 2048 characters), de-duplicated by final address (scheme and host are case-insensitive, fragment and trailing `/` on the path are dropped, and the first spelling seen is kept), at most 30. Each entry has **only** the address, host, kind, the number of **distinct** researchers who posted it, and the link page's **title**: the link title the X API gave for that address (`x_post_link.title`) when non-empty, otherwise the title the web page module fetched (`web_page.title`, `status = 'ok'`, matched on `url_key`), both cleaned with `pagefetch.CleanTitle`. A title is third-party text and **appears only in this panel**. Sorted by kind (`poc`, `patch`, `advisory`, `code`, `other`), then researcher count descending, then earliest post first. **Who posted which link, post ids, post text and post times are not public.** The rules are in `site.Store.Resources` / `site.ResourcesFor`. A `code` link to a repository root on github.com, under the repository's current name, whose repository was fetched and is `ok` (`docs/github.md`) also shows only that repository's full name, star count and creation day, and is listed under `poc` when the repository's name, description or topics name the page's CVE | the page HTML (everyone sees the same thing; the "Resources" panel under "Raw records" in the sidebar, which doesn't appear when there are no links) |

So **which researcher posted on which day mentioning which CVE is public**, and therefore **anyone who has posted about a CVE in the database has their identity on nday's allowlist made public too**.
Author names appear only in the researcher section of the vulnerability page and in `/api/posts` when signed out (the Resources section carries no authors): `/hot`, `/discussed` and their JSON, the feed, the sitemap, share cards and `/v1/vuln` carry only counts, or nothing (the `/discussed` page also shows some of the outline's avatars, without names; see the heat ranking above).

Everything else (post text, post ids, post links ("view on X"), exact times, language, the author's numeric id, the links inside each post (including t.co short links), raw records and collector status) is **for signed-in users only**:
only `GET /api/posts/{cve}` (`internal/posts`, an auth-class endpoint, `docs/api.md` appendix) returns them, by calling
`site.Store.MemberPosts` when the request carries a valid session. The placeholder is scribble text: in the page each entry is just a `<span class="spk" data-size="s|m|l">`, and
`static/app.js` draws fine dot noise on a canvas from the length bucket and a random seed, **unrelated to the real content**; the author line is real text (public),
and without scripts the text is a CSS dot-matrix strip. Screen readers read each entry as one sentence, "Post by @author on <date>. Sign in to read it." ("Post by a researcher on <date>. Sign in to read it." when the author name is invalid). Clicking the noise goes to the sign-in page and comes back to this page with `?research` (a script scrolls to that section and clears the parameter).

**Disabled accounts**: posts are filtered by whether the author is **currently** an enabled allowlist account (`x_accounts.enabled`). Once an account is disabled, its posts aren't counted, and don't appear in the outline (so the name doesn't either), in Resources or in signed-in users' lists; re-enabling restores them.
Enabled state is judged by numeric id; the name shown is the handle stored in the post.

Posts (and their links) still do **not** change the stage, `event_count` or tags, and don't enter the feed, the sitemap (`lastmod` looks only at public events), share cards or `/raw/`; `xposts` isn't in the public `SourceNames`.

**Display (signed-in users, `static/discuss.js`)**: newest first, 10 entries a page (the same pager as the outline). Each entry is a card (`li.rp`; the signed-out outline uses the same card with the placeholder as its body and the day as its footer). Top row:
the avatar (`<img>` of `author_avatar`, accepted only as `/avatar/<16 hex>`) or a square with the handle's first letter, the display name (`author_name`, as text) followed by the `@handle` in a lighter color, or the `@handle` alone when there is no name (the name and handle together link to `https://x.com/<handle>` only if the handle passes `xconfig.ValidHandle`), and a small X mark. Body: the text (`textContent`,
`dir="auto"`, unchanged; CVE ids (`CVE-\d{4}-\d{4,}`, any case) are wrapped in a `span.rp-cve` for the mono green style, the text itself is not changed), cut to 5 lines with an "expand"/"collapse" button (`rsch.expand`, `rsch.collapse`) shown only when the text is longer. Bottom row: the post time in the local time zone and "view on X" (only `https://x.com/<handle|i/web>/status/<numeric id>` is accepted; otherwise it's rebuilt from the post id in the `i/web` form,
and if that fails there's no link); all external links get `target="_blank" rel="noopener noreferrer nofollow"`.
t.co short links in the text: each post from `/api/posts` carries `links` (the resolved links, in order); each complete occurrence of a `short_url` in the text
is replaced with a link whose text is the final address without the scheme (truncated with `…` past 48 characters), whose `href` is the final address and whose `title` is the full address. This happens only when the final address parses as an http/https address
with no user info; otherwise, and for short links with no resolved row, the original text stays. The rest of the text is unchanged, and everything is built with text nodes and `createElement`, never `innerHTML`
(this counts as "formatting for display" and doesn't rewrite the content). The `linkParts` and `cveParts` functions are tested by `internal/webui/resources_test.go`, which runs them with node (skipped when node isn't available).

**Display (Resources, everyone, `resources` in `templates/vuln.tmpl`)**: a panel in the sidebar under "Raw records", titled "Resources", grouped by kind (PoC / exploit code, Patches, Advisories, Code repositories, Articles and other links).
When there's a title, the link text is the page title followed by the hostname in a lighter color; with no title it's the host plus path (scheme removed, truncated past 48 characters); the link's `title` attribute is the full address;
when more than one researcher posted it, "N researchers" follows; `href` can only be http/https, `target="_blank" rel="noopener noreferrer nofollow ugc"`, and the title, text and address are all escaped by the template engine.
Signed-in users still see the address, not the title, in links inside post text. The result is cached in the page cache per CVE (like the researcher section).

### X developer terms (checked 2026-11-14)

- https://docs.x.com/developer-terms/policy : "You must maintain the integrity of all X Content that you display publicly or to people who use your service." This is why the text is shown verbatim and never rewritten.
- Same page: "If displayed content ceases to be available through the X API, then you must remove it from your service as soon as reasonably possible, or within 24 hours". **Not done** (see "Not handled" below).
- Same page: "You may only use and display the X name and logo to identify X as the source of X Content." The X name is used only in "view on X" to name the source; the X logo isn't used.
- https://docs.x.com/developer-terms/agreement : "Modify X Content only to format it for display on your Services". Only formatting is done (line breaks, direction isolation).
- The Display Requirements page on developer.x.com returned 402 to automated fetches, so its specific requirements for attribution, timestamps, avatars and the X logo couldn't be checked.

Known and accepted indirect traces:

- When a post mentions a CVE that isn't in the database, ingestion creates a placeholder `vuln` row (which now also shows up in `/discussed`).
- Every successful collection refreshes the public `state_refreshed_at`.
- The public `Sources()` doesn't include xposts; the admin system page and `/admin/x` show it through a separate, admin-only query and label it "not public".

Try it locally: `go run ./tools/authdev -x-sample` (`tools/authdev/README.md`).

## Not handled

- TODO: posts deleted upstream aren't re-checked or deleted (this applies to posts in `event` and to `x_post_no_cve`; the latter isn't shown anywhere at the moment). Signed-in users can read posts, and X's policy requires deleted or protected posts to come down within 24 hours (see above), so this needs to be implemented soon (the re-check endpoint is billed per post).
- CVE ids in long posts are read from `note_tweet.text`; but raw records stored before that don't have `note_tweet`, so ids in the second half of their long posts are still missed; `detail.text` is also still the truncated `text`.
- Whether the extra fields and expanded quoted posts are billed separately isn't stated in the docs and hasn't been verified.
- Web page fetching doesn't read `robots.txt`; a title is text from a third-party site (cleaned and escaped, but the content itself isn't controlled and could mislead). Each address is fetched at most 3 times, and after a success or a "no title" verdict it isn't refreshed again (a later title change isn't picked up).
- The link table only grows: when a newer raw version of the same post has fewer links, the extra old rows stay. Two resolvers running at the same time may each send a request for the same short link (there's no row lock).
- Links have no admin page yet (future work); candidates are reviewed on `/admin/x` and never added to the allowlist automatically.
- When truncated runs keep happening, the same batch of posts is fetched and billed again and again; raise the limits.
- An account newly added to the allowlist is collected only from the current `since_id` onward; there's no backfill.
