# nday admin area

Implementation: `internal/admin` (access rules, page queries, the `/api/admin/*` endpoints, error log reading), `internal/audit` (writing and reading the audit log),
`internal/webui/admin.go` + `templates/admin_*.tmpl` + `static/admin.js` (the server-rendered pages and the action scripts), `migrations/0007_admin.sql`.
`internal/auth/store_admin.go` provides the read-only user list/detail queries and the user actions on the web; hide/unhide/resolve-report in `internal/discuss` write their audit records inside the original transaction.
To try it locally, use `tools/authdev` (`-admin`, `-moderator`, `-stats-sample`; see `tools/authdev/README.md`).

The entry point is `https://www.nday.land/admin` (it's also under every language prefix: `/zh-hans/admin` …). It uses the site's existing sign-in and sessions, and there's no separate host.

---

## 1. Access rules

- **Staff** = a user whose role is moderator or admin, who isn't suspended (a suspension that has run out counts as not suspended), and whose request is on the public host. The role and status are re-read from the database on every request (the session lookup already joins `users`), so a role or suspension change from the CLI takes effect immediately.
- **Pages** (GET/HEAD): signed out → 302 to `/login?return=<this page's path and query>` in the same language. Signed in but not staff (including a suspended moderator/admin) → the site's ordinary 404 page. A moderator visiting `/admin` → 302 to `/admin/moderation`. A moderator visiting an admin-only page → 404. Another host (pointed here from another Cloudflare zone) → 404, and cookies aren't read. These routes don't exist at all on the API host.
- **Endpoints** `/api/admin/*`: admins only. They require POST, same-origin (`Origin`/`Sec-Fetch-Site`), `X-CSRF-Token`, a JSON request body, a per-user rate limit (burst 30, then 1 every 2 seconds), and a **recent sign-in** (the session was created within `NDAY_AUTH_SENSITIVE_WINDOW`, default 15 minutes, otherwise `403 reauth_required`, and the page pops up the same "re-authenticate" panel as the account page). Nobody can act on themselves, and an admin account can never be the target of a web action (only the CLI on the server can do that).
- **Accepting or rejecting reader corrections** (`/admin/corrections`) uses the corrections endpoints `POST /api/corrections/item/{id}/accept|reject` (moderator or admin, not suspended, same-origin + CSRF; see `docs/corrections.md`), and writes an audit record in the same transaction.
- **Moderation actions** use the discussion endpoints directly: `POST /api/discuss/comment/{id}/hide|unhide`, `POST /api/mod/reports/{id}/resolve` (moderator or admin, not suspended; see `docs/discuss.md`). They write an audit record in the same transaction.
- **All** `/admin*` pages and `/api/admin/*` responses (whatever the outcome, including 302/404/405) are forced, when the response headers are written, to `Cache-Control: no-store`, `X-Robots-Tag: noindex, nofollow` and `Vary: Cookie`, with `ETag`/`Last-Modified`/`Expires`/CDN cache headers removed. Conditional request headers are ignored (no 304). The pages don't go through the server's shared cache (`web.Cache`). Pages also have a per-user rate limit (burst 120, then 4 per second; beyond that you get a 429 error page).
- **Public pages are unchanged**: the account entry in the top bar gets a `data-admin="/admin"` attribute (the same for every visitor). When `/api/me` says the role is moderator/admin and the user isn't suspended, `app.js` adds an "Admin" link next to the handle. Server-side access control doesn't depend on this link.

### 1.1 Access matrix (output of `go test ./internal/admin -run TestAccessMatrix -v`; `{id}` is an ordinary user)

| Route | Signed out | Ordinary user | Suspended moderator | Suspended admin | Moderator | Admin |
|---|---|---|---|---|---|---|
| `GET /admin` | 302 → /login?return=%2Fadmin | 404 | 404 | 404 | 302 → /admin/moderation | 200 |
| `GET /admin/moderation` | 302 → /login?… | 404 | 404 | 404 | 200 | 200 |
| `GET /admin/corrections` (2026-11-15) | 302 → /login?… | 404 | 404 | 404 | 200 | 200 |
| `GET /admin/users` | 302 → /login?… | 404 | 404 | 404 | 404 | 200 |
| `GET /admin/users/{id}` | 302 → /login?… | 404 | 404 | 404 | 200 (limited view) | 200 |
| `GET /admin/system` | 302 → /login?… | 404 | 404 | 404 | 404 | 200 |
| `GET /admin/audit` | 302 → /login?… | 404 | 404 | 404 | 404 | 200 |
| `POST /api/admin/users/{id}/suspend` | 401 not_signed_in | 404 not_found | 404 not_found | 404 not_found | 403 forbidden | 200 |
| `POST /api/admin/users/{id}/unsuspend` | 401 | 404 | 404 | 404 | 403 forbidden | 200 |
| `POST /api/admin/users/{id}/role` | 401 | 404 | 404 | 404 | 403 forbidden | 200 |
| `POST /api/admin/users/{id}/signout-all` | 401 | 404 | 404 | 404 | 403 forbidden | 200 |
| `GET /admin/x` | 302 → /login?return=%2Fadmin%2Fx | 404 | 404 | 404 | 404 | 200 |
| `POST /api/admin/x/settings`, `/accounts`, `/accounts/{id}/update\|enable\|disable`, `/import`, `/candidates/{id}/add\|dismiss\|restore` | 401 not_signed_in | 404 not_found | 404 not_found | 404 not_found | 403 forbidden | 200 |
| `GET /admin/x/drafts` | 302 → /login?return=%2Fadmin%2Fx%2Fdrafts | 404 | 404 | 404 | 404 | 200 |
| `POST /api/admin/x/drafts/{id}/save\|posted\|discard\|restore` | 401 not_signed_in | 404 not_found | 404 not_found | 404 not_found | 403 forbidden | 200 |

The same test also covers: redirects under `/zh-hans/admin/…` keep the language prefix; the API host (POST → 405, GET → 404 JSON); other hosts (the whole site is stopped by `web.Server` before it reaches the admin area, see "Other hosts" in `docs/auth.md` Â§6: a page GET → `308` to the same path on the public host, an endpoint POST → `421 wrong_host` with `Cache-Control: no-store`; the test `checkForeignHost` asserts this, neither response has `X-Robots-Tag`, and the admin area's own 421 branch can't be reached on this path); an endpoint GET → 405; a missing, wrong or someone else's CSRF token → `403 csrf`; `Sec-Fetch-Site: cross-site`, a foreign `Origin`, or neither → `403 cross_site`; a form Content-Type → 415; an unknown field → 400; an expired session → `403 reauth_required` (pages are unaffected).

### 1.2 What moderators can see

| | Moderator | Admin |
|---|---|---|
| Content moderation (report queue, latest comments, hide/unhide/dismiss and close reports, earlier versions) | ✓ | ✓ |
| Reader corrections (pending and resolved lists, accept/reject; `docs/corrections.md`) | ✓ | ✓ |
| User page: handle, display name, account id, role, status (including when a suspension ends), sign-up time, comment count, recent comments, reports about their comments | ✓ | ✓ |
| User page: suspension reason, last activity, sign-in methods (provider, name at the provider, shortened subject, linked/last-used times), passkey count, active session count, reports submitted by this account, related audit records, the actions area | ✗ (not queried, not output) | ✓ |
| Operations statistics, user list/search, system status, the action log, the X collector, X drafts | ✗ (404) | ✓ |

No view shows tokens, full subjects, passkey names, or session information other than IP addresses. The client address in an audit record is visible to admins only. `TestModeratorView` asserts on the raw bytes that the moderator pages don't contain these fields.

---

## 2. Pages

All are server-rendered and `noindex`, show times in the visitor's time zone (`<time data-lt>`), and tables scroll horizontally inside their own container on narrow screens. User input (handles, display names, reasons, report notes, earlier versions, search terms, referrer hosts, 404 paths, log entries …) is always escaped as text, control characters become U+FFFD, and content that may contain bidi control characters goes in `<bdi>` or an element with `dir`. The only thing inserted as HTML is the output of the discussion renderer (`internal/discuss/md`), which is allow-listed.

| Page | Who | Content |
|---|---|---|
| `/admin?days=7\|30\|90` | Admin | Operations statistics: page views, unique visitors (summed per day over the range), API requests, new accounts, comments and currently open reports, for the range and for today; daily bar charts (page views and visitors: all/people; API; stacked status code classes; new accounts; comments and reports). Days without statistics are marked "no statistics for that day" (not 0). A world map of page views by people, by country and region (`country_human` in `stats_top`; the title says "people" to set it apart from the "countries" ranking below, which covers all traffic; 5 log-scaled color levels; hovering or tapping a country shows its code and count right away (`static/admin.js` reads `data-tip` and only uses `textContent`; without scripts it falls back to `<title>`); countries with no data show "no page views by people"; regions without an outline in 1:110m, such as SG, HK and MO, are drawn as same-colored dots; codes that can't be placed on the map, such as T1 (Tor) and XX, are listed under the map; the geometry is generated by `tools/worldmap`, see the header of `internal/webui/worldmap_data.go`). Rankings: most viewed vulnerabilities (linked), referrer hosts, countries, search terms, 404 paths from people, views by language, API by endpoint, machines by UA, and the share of machines. It also shows the time of the last rollup (`stats.Days`) and a note that the figures are estimated from server logs. Dates are calendar days in the server's time zone (consistent with the logs); community figures are bucketed at local midnight in the same time zone (`width_bucket`, exact across daylight saving too). Any other `days` value is treated as 7. |
| `/admin/moderation?status=&qc=&rc=` | Staff | Open reports grouped by comment (the rendered HTML body, the author, reasons and their counts, the number of reporters, notes, "edited N times" and the plain text of earlier versions). Actions: hide (with a reason), unhide, dismiss and close reports (confirmed with two clicks). A "latest comments" patrol list with a status filter (all/visible/hidden/deleted) and pagination. Every entry links to the comment on the vulnerability page (`?c=<id>#c-<id>`) and to the author's user page. Read-only when discussions are off. |
| `/admin/corrections?state=&c=` | Staff | Reader corrections (2026-11-15, `docs/corrections.md` §5.2): two lists, pending (oldest first) and resolved (`state=decided`, most recently resolved first), 30 per page. Each shows the submitted text, the source link (only clickable if it's an absolute http/https URL), the category and the submitter. A pending one can be accepted (a public resolution note is required and is shown, credited to the submitter, in the revision history on the vulnerability page; **it doesn't change the vulnerability data**) or rejected (an internal note is optional). Both need two clicks to confirm and call `POST /api/corrections/item/{id}/accept\|reject`. |
| `/admin/users?q=&after=` | Admin | Search by handle prefix, display name fragment (case-insensitive) or full account id. Columns: handle, display name, role, status, sign-up, last activity, comment count. 50 per page. |
| `/admin/users/{id}` | Staff (limited for moderators) | See 1.2. The actions area: suspend (a reason of 1–500 characters is required, duration 1 day/7 days/30 days/until lifted; for an already suspended account it reads "change suspension"), lift suspension, make moderator/revoke moderator, sign out of all devices. Each needs two clicks to confirm. No actions are shown for yourself or for admins. |
| `/admin/system` | Admin | Collectors (status, last run, last success, last error) and the refresh time of materialized state. The database size and the row counts of the main tables (exact for small tables, a planner estimate marked `~` for large ones) and their sizes. The statistics rollup status (files, rows, bad lines, last run). The newest 100 WARN/ERROR entries from today's and yesterday's `error-*.log`. Process start time, Go version, build info (module path, version, VCS revision), goroutine count, and the size and usage of each connection pool. It doesn't show environment variables or the database URL. |
| `/admin/settings` | Admin | Settings stored in the database (`app_settings`), in three groups: collectors, discussions and sign-in. For each key it shows the source (database / environment variable / default), the plain value in the database, and for secrets only whether they're set and their last few characters. You can save, and enter/replace/clear secrets. It never shows the value of an environment variable or of a secret. See `docs/settings.md` for details. |
| `/admin/x?q=&page=&author=&cve=&before=` | Admin | The X posts collector (see 2.1). `q` and `page` are an allow-listed search and page number; `author`, `cve` and `before` are the filter and paging position of the post list. |
| `/admin/x/drafts` | Admin | Draft posts for nday's official X account (see 2.2). |
| `/admin/audit?action=&actor=&target=&before=` | Admin | The audit log, newest first, 50 per page. Filter by action, the actor's handle (`cli` = the command line) and the target id. |

### 2.1 X posts collector (`/admin/x`)

Admins only (moderators don't see the navigation item, and visiting it directly gives a 404); the other rules are the same as for the other admin pages. Posts and the health of xposts are **not on any public page or public endpoint** (`internal/site/public.go`, `TestPostsNotPublic`). This page is the exception, for staff only.

- **Status**: the xposts state in `collector_state`, last run, last success, last error. From `cursor.last_run`: the number of billed posts (`posts`, the number of items the API returned), the number stored (`kept` for posts with a CVE id, and `kept_no_cve` for those without, which go into `x_post_no_cve` and aren't shown on any page, see `docs/xposts.md`), the number dropped (author not on the allow-list, `dropped_author`), the number of requests, batches, the time window and `since_id`. It also shows the skip reason (`no_token` / `no_accounts` / `disabled`) or the reason for stopping early, and `stop_info`. This page never shows, returns or accepts a token. When the web process has `NDAY_X_BEARER_TOKEN` configured (optional; `deploy/systemd/nday-web.service` reads `/etc/nday/xposts.env`), it's only used to look up the numeric id for a handle when you add or import accounts (`internal/xlookup`, "add by handle" in `docs/xposts.md`). The page only shows whether the lookup is on.
- **Cost**: the unit price comes from the constant `admin.XPricePerPostUSD = 0.005` (see "Admin UI" in `docs/xposts.md`). It shows the actual cost of the last run. For the worst case under the current settings, it's `min(max_posts, max_requests × 100)` posts per run, × 24 per day (`OnCalendar=hourly` in `deploy/systemd/nday-collect@.timer`, the constant `admin.XRunsPerDay`; the page says this assumes `nday-collect@xposts.timer` is enabled), and × 720 per 30 days. The form's script recalculates as you type (an invalid value shows —).
- **Settings**: `enabled`, `max_posts`, `max_requests`, `bootstrap_days`, `max_query_length`. Each shows its default and hard range, and you can choose "use default" (stored as NULL). Saving only goes through `xconfig.SaveSettings`.
- **Allow-list**: the numeric id, the handle (only handles that pass `xconfig.ValidHandle` link to `https://x.com/<handle>`, with `rel="noopener noreferrer nofollow"`), a note, the status, the post count, and added/updated times. It's sorted by numeric id, 10 per page (the constant `admin.XAccountsPage`), paginated on the server, with no script needed.
  `q` is a case-insensitive substring search on the handle (`xconfig.CountAccounts` / `SearchAccounts`, `strpos(lower(handle), lower($1)) > 0`, not `LIKE`, so `%`, `_` and `\` match literally and need no escaping);
  `q` first has control characters handled (`plain`), leading and trailing spaces and one leading `@` removed, and is at most 32 characters. `page` starts at 1; anything non-numeric, less than 1 or over 6 digits means page 1. Past the last page, the last page is shown (never an empty page). Counting, clamping and fetching the rows happen on one connection (`admin.Service.XAccounts`).
  Above the table is the search form (carrying the current `author` and `cve`) and a line saying where you are ("Showing 11–20 of 37 accounts."; when searching it also states the number of matches, with the search term escaped inside `<bdi>`); below the table are previous/next and "page N of M", hidden when there's only one page.
  In links, `page` is omitted when it's 1 and `q` when it's empty. The allow-list's paging and "show all accounts" links keep `author`, `cve` and `before` and end in `#accounts`; the post filter form and the post paging links keep `q` and `page` and end in `#posts`; a new search goes back to page 1.
  With no accounts at all, it says "none" and doesn't show search; a search with no matches shows a dedicated message and a link to clear the search. The "enabled / total" in the status area is always computed over all accounts, regardless of search and paging.
  Enable, disable, edit, add and import are done by the page script calling the endpoint and then `location.reload()`, so after an action you stay on the same search and page.
  You can add, edit the handle and note, enable and disable (there's no delete); bulk import (the format of `deploy/x-accounts.example.txt`, parsed by `xconfig.ParseAccounts`; same as the CLI: it never deletes and never changes the enabled state) first shows a preview (`dry_run`, computed in one transaction and rolled back), and if any line is invalid, nothing is written and every line's error is listed.
- **Add by handle**: the add form asks for the handle first (and an optional note), and the numeric id field is optional. Above the form it says whether lookup is on (`data-lookup="on|off"`). When only a handle is given, the server first validates the handle, then asks X for the id (`admin.Service.XAddByHandle`; the lookup runs outside the transaction, and the write and the audit record happen in one transaction). On success it shows "Added @handle as user id …" or "User id … was listed as @…; its handle is now @…", and refreshes after about 2.5 seconds. If the id found is already on the allow-list with the same handle, you get `409 exists`; if the handle differs, that id's handle is updated (no second row is created). In a bulk import, lines with only `@handle` are looked up the same way (at most 100 per request), and the preview lists the id found for each line. If any line can't be found or is suspended, nothing is written. With no token, giving only a handle gives `503 x_lookup_off`, while giving the numeric id works as usual.
- **Collected posts**: newest stored first, 30 per page, filterable by author handle and CVE id. They show time, author, body (escaped text, `dir="auto"`), CVE links, and the post link (only the form `https://x.com/<handle|i/web>/status/<id>` is accepted). There's also a small chart of posts stored per day over the last 30 days and the post count per account.

### 2.2 X post drafts (`/admin/x/drafts`)

Admins only (the navigation item "X drafts"; moderators don't see it, and visiting it directly gives a 404). Drafts are produced by `internal/xdraft` when a vulnerability **newly reaches** POC, ITW or KEV (the rules are in the "Drafts" section of `docs/xposts.md`),
and stored in `x_draft` (migration `0012_xdrafts.sql`). They're **not on any public page, feed, sitemap or public endpoint** (`TestPostsNotPublic` also stores drafts).

- **How publishing works**: the server never calls the X API and never stores any X credentials. The "open in X" next to each draft is an ordinary link (a new tab, `rel="noopener noreferrer"`),
  pointing to X's own compose window `https://x.com/intent/tweet?text=…`, where `text` is the draft body + a newline + the absolute URL of the vulnerability detail page (the English page, `NDAY_PUBLIC_URL` + `/vuln/<CVE>`),
  percent-encoded as a whole (`xdraft.ComposeURL`). The admin clicks Post on X themselves, then comes back here to "mark posted" (optionally pasting the post link). The reason: posting with a link through the X API costs $0.20 per post.
- **Pending**: newest first, at most 50 (when there are more, it says "Showing the newest 50 of N"). Each shows the phase code (`+POC`/`+ITW`/`+KEV`), the CVE id (linking to the public detail page in the current language),
  the time it was generated, an editable body (a text box, escaped), the weighted length including the link as `n/280` (the page script estimates it as you type; it's an upper bound, and with the link it may be higher than what the server computes; the server is authoritative), save, open in X, mark posted (with an optional post link), and discard (two clicks to confirm).
  "Open in X" opens the **saved** text (the link is generated by the server, not by script): when the text box has unsaved changes, the script hides this button and prompts you to save first; when the weighted length is over the limit (at server render time or in the script's estimate), the button isn't shown and "Too long" is shown instead.
  With no drafts it shows an empty state.
- **Recently handled**: all posted and discarded drafts, ordered by when they were handled, 20 per page (`admin.XHistoryPage`), with `?page=N` paging (server-side, no JS needed;
  a page number that's out of range or not a number goes to the nearest valid page; with only one page the paging row isn't shown). Pending drafts aren't affected by the page number. Columns: phase, CVE, outcome, time, actor (linked to their user page), post link (only the normalized `https://x.com/<handle>/status/<id>` is shown),
  and discarded ones can be "restored" to pending (two clicks to confirm).
- One line at the top of the page shows the generator's most recent run (`x_draft_state.last_run`): the number of new drafts, the number of qualifying events, the number left for later runs (`carried`), and the number **dropped permanently** (`skipped_cap`: the batch change exceeded the cap; `skipped_old`: older than 72 hours). If a later run was deferred because the event table was busy, another line notes the time.
- When the actor has no handle, it shows "no handle" and links to their user page (the same as the moderation page and the user list). When the account has been deleted, it shows "—".

---

## 3. Database connection pools

| Query | Pool |
|---|---|
| Reads for all pages (statistics, community counts, moderation lists, user list/detail, audit log, system status) | The site's read-only pool (`default_transaction_read_only=on`, `NDAY_DB_POOL_SIZE`) |
| User actions on the web (`/api/admin/*`) | The sign-in writable pool (`NDAY_AUTH_DB_POOL_SIZE`) |
| Hide/unhide/resolve report | The discussion writable pool (`NDAY_DISCUSS_DB_POOL_SIZE`), i.e. the existing discussion endpoints |
| Accept/reject reader corrections | The sign-in writable pool, i.e. the corrections endpoints `/api/corrections/item/{id}/accept\|reject` (`internal/corrections`) |
| `/api/admin/x/*` (allow-list, settings) | The sign-in writable pool; only through functions in `internal/xconfig` |
| `/api/admin/x/drafts/*` (drafts) | The sign-in writable pool (`admin.Service.XDraft*`); page reads use the read-only pool |
| CLI commands | The command's own single connection |

---

## 4. Endpoints

All responses are `no-store`. Error bodies are the same as for other endpoints: `{"error":{"status":403,"code":"reauth_required","message":"…"}}`. Order of checks (the site-wide check for other hosts comes before everything: 308/421, see above): host (421) → route (404) → method (405) → session and same-origin/CSRF (401, 403 `cross_site`/`csrf`) → staff (otherwise 404 `not_found`, so the admin area's existence isn't revealed) → admin (403 `forbidden`) → rate limit (429 `rate_limited` + `Retry-After`) → recent sign-in (403 `reauth_required`) → account id (404) → request body (415/413/400) → database conditional statement (404/403/409).

| Endpoint | Request body | Description |
|---|---|---|
| `POST /api/admin/users/{id}/suspend` | `{"reason":"1–500 characters","duration":"1d"\|"7d"\|"30d"\|"lifted"}` | The reason is counted after control/format characters are removed and whitespace is collapsed (`400 bad_reason`); `400 bad_duration`; it can overwrite an existing suspension (a new end time and reason) |
| `POST /api/admin/users/{id}/unsuspend` | none (or `{}`) | Not suspended → `409 no_change` |
| `POST /api/admin/users/{id}/role` | `{"role":"moderator"\|"user"}` | Only between user ↔ moderator; any other value (including `admin`) → `400 bad_role`; already that role → `409 no_change` |
| `POST /api/admin/users/{id}/signout-all` | none (or `{}`) | Deletes all of the account's sessions (they stop working immediately); no sessions → `409 no_change` |

On success: `200 {"ok":true,"user":{"id":"…","handle":"tom","role":"user","status":"suspended","suspended_until":"2026-11-20T12:00:00Z"}}`, and `signout-all` also has `"revoked_sessions":2`.

Errors: `403 self` (acting on yourself), `403 protected` (the target is an admin), `403 forbidden` (not an admin, or the actor was no longer an active admin when the action ran), `404 not_found` (the account doesn't exist or the id isn't a UUID), `409 no_change`, plus the common errors from section 1.

For the settings endpoints (`POST /api/admin/settings`, `/api/admin/settings/secret`, `/api/admin/settings/secret/clear`), see `docs/settings.md` §5 for requests, responses and error codes; the checks are the same as above.

### 4.1 X posts collector endpoints

The rules are the same as for the table above (admin, POST, same-origin, CSRF, rate limit, **recent sign-in**, because they decide what gets collected and how much it costs). A write is done in one transaction on the sign-in writable pool: first it re-confirms under a shared lock that the actor is still an active admin, then it calls `internal/xconfig`, then it writes the audit record.

| Endpoint | Request body | Success | Errors |
|---|---|---|---|
| `POST /api/admin/x/settings` | `{"enabled":true\|false\|null,"max_posts":N\|null,"max_requests":N\|null,"bootstrap_days":N\|null,"max_query_length":N\|null}`; all five keys are required, and `null` = default | `{"ok":true,"settings":{…},"worst_case_posts_per_run":200}` | `400 bad_setting` (`param` is the first field in error, `fields` gives the reason for each field: `range`/`type`/`missing`/`unknown`; nothing changes if invalid), `409 no_change` |
| `POST /api/admin/x/accounts` | `{"handle":"alice","note":"…"}` (handle only: the server asks X for the id) or `{"user_id":"1001","handle":"alice","note":"…"}` (no lookup); a leading `@` on the handle is removed; `user_id` can be omitted or empty | `{"ok":true,"user_id":"1001","handle":"Alice","result":"added"\|"renamed","looked_up":true}` (on `renamed` there's also `previous_handle`: the id was already on the allow-list, and the handle was changed to the spelling X returned) | `400 bad_user_id`/`bad_handle`/`bad_note` (before any outside request), `409 exists` (on lookup, with `user_id` and `handle`), `503 x_lookup_off` (the web process has no token), `422 x_not_found`, `422 x_unavailable` (suspended or unavailable), `503 x_rate_limited` (X returned 429, not retried), `502 x_auth` (X returned 401/403), `502 x_upstream` (timeout, 5xx or unparseable) |
| `POST /api/admin/x/accounts/{id}/update` | `{"handle":"…","note":"…"}` (the note can be cleared) | Same as above | `400 bad_handle`/`bad_note`, `404 not_found`, `409 no_change` |
| `POST /api/admin/x/accounts/{id}/enable`, `/disable` | none | `{"ok":true,"user_id":"…","enabled":true}` | `404`, `409 no_change` |
| `POST /api/admin/x/import` | `{"text":"…","dry_run":true\|false}` (≤ 256 KiB; lines with only `@handle` look up the id first) | `{"ok":true,"dry_run":…,"inserted":2,"updated":1,"unchanged":5,"lines":[{"line":3,"user_id":"…","handle":"…","result":"inserted","looked_up":true}]}` | `400 bad_import` (`lines`: `[{"line":4,"message":"…"}]`, including not found, suspended, and an id found that duplicates another line; nothing was written), `413 too_large`; if the lookup itself fails, the same `x_lookup_off`/`x_rate_limited`/`x_auth`/`x_upstream` as in the table above |
| `POST /api/admin/x/candidates/{id}/add` | none | `{"ok":true,"user_id":"…","handle":"…","result":"added"}`: the candidate's stored id and handle are added to the allow-list (enabled, empty note; no X request; `docs/xposts.md`) | `404 not_found` (no such candidate), `422 no_handle` (no valid stored handle), `409 exists` (already listed) |
| `POST /api/admin/x/candidates/{id}/dismiss`, `/restore` | none | `{"ok":true,"user_id":"…","status":"dismissed"\|"pending"}` | `404 not_found`, `409 no_change` |

A 404 if `{id}` isn't a valid numeric X user id.

### 4.2 X post draft endpoints

The rules are the same as for the table above (admin, POST, same-origin, CSRF, rate limit, **recent sign-in**). `{id}` is the draft id (decimal, otherwise 404); `version` is the version number from when the page was rendered, and it's required.
Each action is one transaction on the sign-in writable pool: re-confirm under a shared lock that the actor is an active admin → one conditional UPDATE (the WHERE clause repeats the rules: `id`, `version = $version`, the required `status`; saving also requires that the body actually changed),
with `version` incremented → the audit record. When no row was changed, the cause is diagnosed in the same transaction: doesn't exist → 404, a different version → 409 `stale_version` (another admin or another tab already changed it; nothing was written),
wrong status → 409 `wrong_status`, same body → 409 `no_change`.

| Endpoint | Request body | Success | Errors |
|---|---|---|---|
| `POST /api/admin/x/drafts/{id}/save` | `{"version":N,"body":"…"}` | `{"ok":true,"id":N,"version":N+1}` | `400 bad_body` (empty, over 1000 characters, or containing control characters other than newlines; CR LF becomes LF, and leading/trailing and end-of-line whitespace is removed), `400 too_long` (weighted length + newline + link 23 > 280; includes `weighted_length` and `max`=256), `409 stale_version`/`wrong_status`/`no_change`, `404` |
| `POST /api/admin/x/drafts/{id}/posted` | `{"version":N,"post_url":"…"}` (can be omitted or empty) | Same as above | `400 bad_post_url` (only `https://x.com/<handle>/status/<digits>` or the same form on twitter.com is accepted, optionally with `www.`/`mobile.`; a trailing slash, a query string (such as `?s=20`) and a fragment are **removed**; a status id can't start with 0, otherwise it's rejected; it's stored as `https://x.com/<handle>/status/<digits>`), `409`, `404` |
| `POST /api/admin/x/drafts/{id}/discard` | `{"version":N}` | Same as above | `409` (only from `draft`), `404` |
| `POST /api/admin/x/drafts/{id}/restore` | `{"version":N}` | Same as above | `409` (only from `discarded`), `404` |

The request body is at most 16 KiB. An unknown field, a missing `version`, or a `version` that isn't an integer in 1..2147483647 → `400 bad_request`; a field that isn't needed (such as `body` on discard) → `400 bad_request`.

**Atomicity**: each action is one transaction: lock the target row → one conditional UPDATE/DELETE whose WHERE repeats all the rules (the target isn't the actor, isn't an admin, the actor is an active admin, and the change is meaningful; the role statement also restricts to `role IN ('user','moderator')` and requires the new value to be in it too) → the audit record. Only when the statement changed no rows is the cause diagnosed, in the same transaction. If the CLI promotes the target to admin concurrently, the web statement either commits first (and the CLI then takes effect as usual), or re-evaluates the WHERE after the lock is released and no longer matches (`TestRoleChangeAtomic`, with `-race`).

---

## 5. Audit log (`admin_audit`, migration `0007_admin.sql`)

| Column | Description |
|---|---|
| `id bigint identity` | A sequence number; the paging cursor |
| `at timestamptz` | Write time (the database `now()`, i.e. the transaction start time) |
| `actor_id uuid` | The actor. **No foreign key** (deleting an account doesn't affect the record); NULL for the command line |
| `actor_handle`, `actor_role` | A snapshot taken from `users` in the same transaction; NULL / `cli` for the command line |
| `action` | The action code (see below) |
| `target_type`, `target_id`, `target_label` | `comment`/`report`/`user`/`x_settings`/`x_account`/`x_draft`/`setting`/`correction` (`0012_xdrafts.sql`, `0014_settings.sql` and `0017_corrections.sql` relaxed the CHECK), the target id, and a readable snapshot (a handle, a plain-text excerpt of a comment body of ≤200 characters, or `CVE-… +KEV` for a draft) |
| `reason` | The hide reason or suspension reason (≤500) |
| `details jsonb` | A small object (≤2 KiB; rows for the `correction` target ≤8 KiB, `0018_correction_audit_details.sql`): `cve`, `resolved_reports`, `comment_id`, `resolution`, `from`/`to`, `until`, `was`, `revoked_sessions` |
| `source` | `web` / `cli` |
| `client_addr`, `cf_ray` | Web actions only: the client address used for rate limiting (`CF-Connecting-IP`, /64 for IPv6) and `Cf-Ray` |

Action codes: `comment.hide`, `comment.unhide`, `report.resolve`, `user.suspend`, `user.unsuspend`, `user.role`, `user.signout_all`;
X collector: `x.settings.update` (target `x_settings`/`1`; `details` is `{"from":…,"to":…}` for each changed field, `null` = default), `x.account.add` (`details`: `user_id`, `handle`, `note`, `lookup`, plus `entered` = the handle the admin typed when a lookup was done; `"candidate": true` when added from the candidates list), `x.candidate.dismiss`, `x.candidate.restore` (target `x_account`/candidate user id, label `@handle` when valid), `x.account.update` (`user_id`, from/to for the changed fields; a manual edit also has `account` = the current `@handle`, and when add-by-handle discovers a rename it also has `lookup` and `entered`), `x.account.enable`, `x.account.disable` (target `x_account`/numeric id, label `@handle`), `x.accounts.import` (target `x_account`/`import`; `details` has `inserted`/`updated`/`unchanged`, `looked_up` (the number of lines whose id was looked up) and `changed` (the changed accounts as `"inserted <id> @<handle>"`, with ` lookup` added for looked-up ones; whatever exceeds `audit.MaxDetails` is counted in `changed_omitted`); nothing is written when nothing changed). Tokens never appear in audit records.
X drafts: `x.draft.save` (`details`: `cve`, the new `version`, `length` = the number of characters in the new body; the body itself isn't audited), `x.draft.posted` (also `post_url`, absent if not given), `x.draft.discard`, `x.draft.restore` (target `x_draft`/draft id, label `CVE-… +KEV`; the audit page links to `/admin/x/drafts#d-<id>`). Drafts newly created by the generator (the command line and the post-collection step) aren't audited.
Reader corrections (2026-11-15, `docs/corrections.md` §3.3): `correction.accept`, `correction.reject` (target `correction`/correction id, label = the CVE id plus an excerpt of the submission; `reason` is the public note or internal note (empty if none; cut to 500 characters); `details` has `cve` and `category`, and for an acceptance also the full public note `public_note` (up to 1000 characters); the audit page links to `/admin/corrections?state=decided#k-<id>`).
Database settings: `settings.update`, `settings.unset`, `settings.secret_set`, `settings.secret_clear` (target `setting`/the key name, or the group name or `settings` for a bulk save in the admin area; `details` only has key names and never values; the audit page links to `/admin/settings#s-<key>`; see `docs/settings.md` §7).

Where they're written (always in the same transaction as the change; if the audit insert fails, the whole action rolls back, and `TestAuditAtomic` verifies this by making the insert fail with a temporary trigger):

| Action | Web | CLI |
|---|---|---|
| Hide / unhide a comment | `discuss.Store.Hide` / `Unhide` (the discussion endpoints) | `nday discuss-hide` / `discuss-unhide` (the same function) |
| Resolve a report | `discuss.Store.ResolveReport` (now one transaction) | — |
| Suspend / lift / change role / sign out of all devices | `auth.Store.StaffSuspend` / `StaffUnsuspend` / `StaffSetRole` / `StaffSignOutAll` | `auth.Store.Suspend` / `Unsuspend` / `SetRole` (`nday auth-suspend` / `auth-unsuspend` / `auth-role`) |
| Accept / reject a reader correction | `corrections.Store.Accept` / `Reject` (`internal/corrections/store.go`) | — |
| Save / mark posted / discard / restore an X draft | `admin.Service.XDraftSave` / `XDraftPosted` / `XDraftDiscard` / `XDraftRestore` (`internal/admin/xdrafts.go`) | — |
| X settings / add, edit, enable, disable an account / import | `admin.Service.XSaveSettings` / `XAddAccount`, `XAddByHandle` / `XUpdateAccount` / `XSetAccountEnabled` / `XImport` (`internal/admin/xposts.go`) | `nday x-settings` (when something changed) / `x-accounts-enable`, `x-accounts-disable` (when the state changed) / `x-accounts-import` (when something was added or updated), sharing `admin.SetXAccountEnabled`, `admin.ResolveXImport` and `admin.ImportResolvedXAccounts` |

Reports that were closed automatically by a hide aren't recorded separately (the count is in `details.resolved_reports`).

**Append-only**: no code updates or deletes from this table. The trigger `admin_audit_no_change` (UPDATE/DELETE, per row) and `admin_audit_no_truncate` (TRUNCATE) raise `insufficient_privilege`. This protects against the program itself and against mistakes, but **not against the database owner or a superuser**: they can still `DROP TRIGGER`, `ALTER TABLE … DISABLE TRIGGER`, `SET session_replication_role = replica`, or drop the table.

---

## 6. Design decisions (where the requirements left room)

| Question | Decision |
|---|---|
| Which endpoints moderation actions use | Reuse `/api/discuss/comment/{id}/hide|unhide` and `/api/mod/reports/{id}/resolve`, with the audit written in the store functions in `internal/discuss`. "Dismiss and close reports" = calling resolve once for each open report on that comment (one audit row each) |
| A non-staff user calling `/api/admin/*` | 404 `not_found` (not revealed, same as the pages). A moderator calling it → 403 `forbidden` (moderators know the admin area exists anyway) |
| A moderator visiting an admin-only page | The ordinary 404 page; `/admin` itself redirects to the moderation page |
| Unique visitors over a range | Summed per day (the logs can't de-duplicate across days), and the card title says so |
| Suspension duration | Counted from the moment of the action, to the second; "until lifted" = no end time |
| Whether a web suspension revokes sessions | No (same as the CLI: a suspended user can still sign in, sign out and delete their account). If needed, click "sign out of all devices" separately |
| Client address in the audit | The same address key as rate limiting (/64 for IPv6); the UA isn't stored |
| Table row counts | `count(*)` for small tables, and the `pg_class.reltuples` estimate for large ones |

## 7. Known limitations

- In-process rate limits reset on restart and aren't shared between instances (same as sign-in and discussions).
- The audit time is the database transaction start time; the time of a change inside the same transaction (such as `suspended_until`) is taken from the application clock.
- The report queue shows 20 comments per page with at most 50 reports listed per comment; the latest comments are 50 per page, with at most 20 earlier versions per comment.
- The system page's error log is read from per-day files (in the server's time zone), only today's and yesterday's, reading at most the last 1 MiB of each file. Lines that are too long (>64 KiB) or can't be parsed are only counted.
