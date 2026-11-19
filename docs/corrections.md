# nday reader corrections (corrections to vulnerability records)

Implementation: `internal/corrections` (storage, HTTP endpoints, limits), `internal/site/corrections.go` (read-only queries for the public revision log),
`internal/admin/corrections.go` (the back office list queries), `internal/webui/corrview.go` + `templates/corrections.tmpl` + `static/corrections.js` (the vulnerability page),
`internal/webui/admin_corr.go` + `templates/admin_corr.tmpl` + `static/admin.js` (the back office `/admin/corrections`), `migrations/0017_corrections.sql`, and `migrations/0018_correction_audit_details.sql`.
Wiring: `internal/cli/auth.go` (mounted when sign-in is configured, using the sign-in writable pool) and `internal/cli/runtime.go` (settings stored in the database). It depends on the session, CSRF, role, suspension, and terms machinery in `internal/auth` (`docs/auth.md`), and is built the same way as the discussion report flow (`docs/discuss.md`).

---

## 1. Product rules

- When a reader finds something wrong or missing on a vulnerability page (title, summary, affected products or versions, fix information, timeline events, source links, other), they submit a correction from the "Report an error" section at the bottom of the page: a category, a description, and an optional evidence link.
- **Only signed-in users can submit** (a product rule). The account conditions are the same as for posting a comment: not suspended, has a public handle, and has accepted the current community rules (when `NDAY_TERMS_VERSION` is configured).
- Editors (moderators or admins) review corrections in the back office at `/admin/corrections`. **Accepting** requires writing a public note about how it was handled (what was changed or confirmed); **rejecting** can include an internal note. Both actions write an audit log entry.
- An accepted correction stays on that vulnerability page as a public revision log entry: the time it was handled, the category, the editor's public note, and the submitter's public handle (as credit).
- **Accepting doesn't change vulnerability data.** Titles, summaries, affected products, and so on come from upstream collection, so a manual edit to the database would be overwritten by the next collection run. A manual override mechanism is a separate piece of work and isn't built yet. So the only effect of "accept" is an extra public revision note on the page. The page and the back office both say so (`corr.lede`, `corr.log.note`, `admin.corr.lede`, `admin.corr.accept_note`).
- Not shown publicly: pending and rejected corrections, the text the submitter wrote, the evidence link, internal notes, and who handled it. Submitters can see their own corrections and their status (§3.2).
- There are no in-site notifications or emails: the repository has no existing notification mechanism (only the discussion section's own state), so none was added. Submitters see the status in the corrections section of the vulnerability page.

### 1.1 Decisions made where the requirements left room

| Question | Decision | Reason |
|---|---|---|
| Deleting a vulnerability row | `cve_id REFERENCES vuln` with the default `NO ACTION` | Same as `comments.cve_id` (`docs/discuss.md` §2.4): the pipeline never deletes vuln rows. If a job ever does, it fails outright when corrections exist, so someone has to decide what happens to the public revision log instead of it being dropped silently |
| Deleting the submitter's account | `submitter_id ON DELETE SET NULL` | Same as `comments.author_id` and `comment_reports.reporter_id` (`docs/auth.md` §2.1): the record is kept and the public credit becomes "reported by a deleted account". The deleted user's pending corrections stay in the queue for editors, but **no longer count** toward the pending total cap for that vulnerability (§4.1) |
| Deleting the handler's account | `decided_by ON DELETE SET NULL` | Same as `comments.hidden_by` and `comment_reports.resolved_by`; who handled it stays in `admin_audit` (`actor_id` has no foreign key) |
| Which name is used for credit | The submitter's **current** public handle (joined from `users` at query time) | Consistent with how comment authors are shown; the credit follows if the user renames; no snapshot is stored, and after the account is deleted no name is shown |
| Where the back office lives | A separate page `/admin/corrections` (nav item "corrections"), with the same permissions as `/admin/moderation` (moderators and admins) | The moderation page is organized around comments and reports (grouped by comment, hide/unhide); corrections are a different object with a different set of actions, and putting them on the same page would make both harder to use |
| Format of the public note | A single line of plain text (newlines and tabs become spaces), 1–1000 characters; the page shows it escaped as text, with `dir="auto"` | Markdown rendering isn't reused: the note is a short sentence written by an editor, and plain text is least error-prone |
| Format of the submission | Plain text, 1–4000 characters, normalized the same as comment bodies (`md.Clean`: control characters, bidi embedding/override/isolate characters, and non-rendering characters removed, CR LF → LF), with at least one visible character | Only editors see it, and it's shown as text |
| Evidence link | Optional; `md.SafeURL`: absolute `http`/`https`, printable ASCII, has a host name, no userinfo, ≤ 2048 bytes; the scheme is stored lowercase | Same rules as clickable links in comments; it's checked again through `ExtLink` when shown in the back office |
| Cap on unhandled corrections per vulnerability | Two caps: the total across everyone on one vulnerability (default 20), and per user on one vulnerability (default 3). The total cap doesn't count entries whose submitter's account was deleted or is currently suspended; a new account gets at most 1 on one vulnerability (§4.1) | With only a total cap, one person could fill a vulnerability's queue; and if several accounts fill it and then get suspended or deleted, the queue shouldn't stay full |
| Where submitters see their own corrections | Below the corrections section of the vulnerability page, under "Your reports on this vulnerability" (the script calls `GET /api/corrections/mine?cve=`); there's a clear message after a successful submission | The account page has no "my content" structure (only profile, follows, sign-in methods, and so on) and none was added here. The endpoint itself can list everything without `cve`, so the account page can use it later |
| Which connection pool is used for writes | The sign-in writable pool (`NDAY_AUTH_DB_POOL_SIZE`) | Corrections are rare and not worth another pool; the discussion pool doesn't exist when `NDAY_DISCUSS=off`, and corrections only depend on sign-in |
| Which settings group holds the limits | The "Discussion" group of settings stored in the database (`docs/settings.md`) | They're community content limits like the others; no new page group was opened |

---

## 2. Data model (`migrations/0017_corrections.sql`, additions only)

`vuln_corrections`:

| Column | Description |
|---|---|
| `id uuid` | Primary key, `gen_random_uuid()` |
| `cve_id text NOT NULL REFERENCES vuln` | The vulnerability it belongs to (canonical uppercase), `NO ACTION` |
| `submitter_id uuid REFERENCES users ON DELETE SET NULL` | The submitter |
| `category text` | `CHECK IN ('title','summary','affected','fix','timeline','sources','other')`: title, summary, affected products or versions, fix information, timeline event, source links, other |
| `body text` | The description the submitter wrote, 1–4000 characters (after normalization). **Not public** |
| `evidence_url text` | Optional evidence link, `^https?://`, 8–2048 characters (full validation happens in the application). **Not public** |
| `status text DEFAULT 'pending'` | `pending` / `accepted` / `rejected` |
| `created_at`, `decided_at` | `decided_at` is tied to the status: `CHECK ((status = 'pending') = (decided_at IS NULL))` |
| `decided_by uuid REFERENCES users ON DELETE SET NULL` | Who handled it |
| `public_note text` | The public note written on accept, 1–1000 characters; `CHECK ((status = 'accepted') = (public_note IS NOT NULL))`: it's required on accept and not allowed in other states |
| `internal_note text` | The internal note written on reject, 1–500 characters, nullable; `CHECK (status = 'rejected' OR internal_note IS NULL)`. **Only staff can see it** |

Indexes: public records `(cve_id, decided_at DESC, id DESC) WHERE status='accepted'`; the pending queue `(created_at, id) WHERE status='pending'`; the pending count per vulnerability `(cve_id) WHERE status='pending'`; the handled list `(decided_at DESC, id DESC) WHERE status<>'pending'`; and by submitter `(submitter_id, created_at)` (the daily cap and "my corrections").

The same migration relaxes the `admin_audit.target_type` CHECK to a superset of 0014's, adding `correction`. The migration starts with `SET LOCAL lock_timeout = '5s'` (same as 0012) and uses only plain SQL, so the Python runner can run it too.

---

## 3. HTTP endpoints

### 3.0 Common (same as `/api/discuss/*`)

- Site host only (any other `Host` → `421 wrong_host`; these routes don't exist on the API host). They're mounted only when sign-in is enabled (independent of the discussion switch).
- Every response has `Cache-Control: no-store` and `Vary: Cookie`, with no validators or CDN cache headers.
- Error body: `{"error":{"status":403,"code":"terms_required","message":"…","param":"2026-11-01"}}`.
- POST: same origin (`Origin` or `Sec-Fetch-Site: same-origin`) + `X-CSRF-Token` (the `csrf_token` from `GET /api/me`) + `Content-Type: application/json`, body ≤ 32 KiB, no unknown fields allowed.
- Every endpoint can return: `401 not_signed_in`, `403 cross_site`, `403 csrf`, `404 not_found` (unknown route, id not a UUID), `405 method_not_allowed`, `413 too_large`, `415 bad_request`, `400 bad_request`, `421 wrong_host`, `429 rate_limited` (with `Retry-After`), `503 busy`, `500 internal`.

### 3.1 `POST /api/corrections/{cve}` — submit

Auth: `auth.RequireActive` (signed in, same origin, CSRF, not suspended → otherwise `403 suspended`), then it requires a handle (`403 handle_required`) and acceptance of the current rules (`403 terms_required`, with `param` = the current version). The order and error codes are the same as for posting a comment (`internal/corrections/service.go` `submit`/`writeRefused`).

Request: `{"category":"fix","body":"The fixed version should be 2.4.1","evidence_url":"https://example.com/advisory"}` (`evidence_url` can be omitted or empty).

Processing order: `400 bad_cve` → account conditions → per-user token bucket (every outcome counts; default burst 3, then 1 per minute) → `429 rate_limited` → request body → `400 bad_category` (`param: "category"`) → `400 invalid_body` (`param: "body"`) → `400 bad_url` (`param: "evidence_url"`) → one transaction (advisory locks, first by submitter, then by vulnerability): the number of submissions in the rolling 24-hour window has reached `NDAY_CORRECTIONS_DAILY` (for a new account, the smaller of that and `NDAY_DISCUSS_NEW_POST_DAILY`, §4.1) → `429 daily_limit` (`Retry-After` = the seconds until the earliest one is 24 hours old); the user's pending count on this vulnerability has reached `NDAY_CORRECTIONS_OPEN_PER_USER` (1 for a new account) → `409 too_many_open`; the vulnerability's total pending count (not counting entries whose submitter's account was deleted or is currently suspended, §4.1) has reached `NDAY_CORRECTIONS_OPEN_PER_VULN` → `409 queue_full`; `INSERT … SELECT … FROM vuln` requires the vulnerability to exist → otherwise `404 not_found` (`param: "cve"`). `{cve}` is the vulnerability's id in any case: a CVE id, or the GHSA id of an advisory without a CVE (since 2026-11-16); a GHSA id that is only an alias of a CVE (e.g. after the advisory got a CVE and moved there) is that `404 not_found`, never a correction filed under the alias.

Success: `201`, `{"ok":true,"correction":{"id":"…","cve":"CVE-2026-0001","category":"fix","body":"…","evidence_url":"https://example.com/advisory","status":"pending","created_at":"2026-11-15T12:00:00Z","decided_at":null,"public_note":null}}`.

### 3.2 `GET /api/corrections/mine?cve=` — my corrections

Auth: `auth.RequireUser` (suspended users can also see their own). Per-user burst 120, then 1 per 0.5 seconds. `cve` is optional (a CVE or GHSA id; a bad format gives `400 bad_cve`). Returns the caller's own corrections, newest first, at most 100: `{"corrections":[…same correction objects as §3.1…],"limits":{"max_body_chars":4000,"max_url_bytes":2048}}`. Accepted ones have `public_note`; the internal note and the handler are **never** included.

### 3.3 `POST /api/corrections/item/{id}/accept` and `/reject` — staff

Auth: `auth.RequireRole(moderator)` (moderator or admin, not suspended; otherwise `403 forbidden` / `403 suspended`), same as `/api/discuss/comment/{id}/hide`. Per person burst 600, then 1 per 0.1 seconds (fixed).

- `accept`: `{"note":"public note"}`. If the note is empty or has no visible characters after normalization (`md.Clean`, newlines/tabs turned into spaces, leading and trailing whitespace removed) → `400 note_required`; over 1000 characters → `400 bad_note`.
- `reject`: `{"note":"internal note"}` or `{}`; over 500 characters → `400 bad_note`.
- Both: not found → `404 not_found`; already handled → `409 wrong_status`. One transaction: `SELECT … FOR UPDATE` → a conditional `UPDATE … WHERE status = 'pending'` → an audit record (`correction.accept` / `correction.reject`, object `correction`/id, summary is `CVE id + a digest of the submission`, `reason` is the public note or the internal note (truncated to 500 characters like every audit `reason`), `details` are `cve` and `category`, and on accept also the full public note as `public_note` (notes can be up to 1000 characters, which doesn't fit in `reason`; so the `details` limit for the `correction` object is 8 KiB while other objects stay at 2 KiB, `migrations/0018_correction_audit_details.sql`, `TestAcceptAuditFullNote`)). If the audit insert fails, the whole operation is rolled back (`TestDecideAuditAtomic`).
- Success: `200`, `{"ok":true,"correction":{…same as §3.1…}}` (without the internal note).

### 3.4 The public part

There's no public JSON endpoint. The vulnerability page (HTML, the same for every visitor, publicly cacheable, doesn't read cookies) renders the "revision log" on the server: `site.Store.Corrections` queries only rows with `status = 'accepted'` and takes only `decided_at`, `category`, `public_note`, the submitter's current `handle` (not taken when the submitter is **currently suspended**: the test is the same as `auth.User.EffectiveStatus`, `users.status = suspended` and `suspended_until` is empty or in the future, and a suspension that has expired but hasn't been cleaned up counts as lifted; the SQL is `site.SuspendedNowSQL`), and whether the submitter's account was deleted. The public data API (`/v1/*`), the feed, the sitemap, and search all exclude corrections (`TestCorrectionsOnVulnPage` checks those routes).

---

## 4. Limits and configuration

An in-process token bucket (`auth.RateLimiter`; it resets on restart and isn't shared across instances); the daily cap and the pending caps are counted in the database (safe under concurrency). An admin can also store the variables below in the database at `/admin/settings` (in the "Discussion" group; the database value wins and takes effect when saved: `corrections.Service.SetLimits`); see `docs/settings.md`. If a value is invalid: at startup it falls back to the environment variable, then to the default, with a warning (startup isn't blocked); when saving in the back office it's rejected.

| Variable | Default | Meaning |
|---|---|---|
| `NDAY_CORRECTIONS_DAILY` | 10 | The most submissions per user in 24 hours |
| `NDAY_CORRECTIONS_OPEN_PER_VULN` | 20 | The most pending corrections on one vulnerability at once (across everyone; not counting those whose submitter's account was deleted or is currently suspended, §4.1) |
| `NDAY_CORRECTIONS_OPEN_PER_USER` | 3 | The most pending corrections one user can have on the same vulnerability at once |
| `NDAY_CORRECTIONS_BURST` / `_EVERY` | 3 / 1m | The per-user token bucket for submission requests (every outcome counts) |

Counts are integers from 1 to 100000; durations are Go durations or days (`30s`, `2m`, `1d`), 1ms to 30d. Errors name only the variable and don't echo the value. Fixed limits: body 4000 characters, link 2048 bytes, public note 1000 characters, internal note 500 characters, request body 32 KiB.

### 4.1 New accounts, and suspended or deleted submitters

- **New accounts** reuse the discussion section's definition and configuration (`docs/discuss.md` §5: `NDAY_DISCUSS_NEW_ACCOUNT_AGE` defaults to 24h and `NDAY_DISCUSS_NEW_ACCOUNT_COMMENTS` defaults to 3; the values the discussion service currently has in effect are read at each submission, so a back office save takes effect immediately; when the discussion section is off, the discussion configuration from startup is used):
  an account is new if it's younger than `NEW_ACCOUNT_AGE`, **or** has fewer "contributions" than `NEW_ACCOUNT_COMMENTS`. One difference from the discussion section: contributions = visible comments **plus** accepted corrections (readers who only submit corrections and never comment can also "graduate").
  The limits on a new account: at most 1 pending on the same vulnerability (`corrections.NewAccountOpenPerUser`; going over → `409 too_many_open`), and a daily cap of the smaller of `NDAY_CORRECTIONS_DAILY` and `NDAY_DISCUSS_NEW_POST_DAILY` (→ `429 daily_limit`).
  Why it isn't copied as is: the discussion section's rules for new accounts don't refuse; they apply stricter limits (a lower daily cap, a slower token bucket) and make links non-clickable. A correction's evidence link is never public, and the token bucket is already stricter than for commenting (default burst 3, 1 per minute),
  so copying those items would do almost nothing against "using a batch of new accounts to fill one vulnerability's queue". What does work is limiting how many slots each new account can take on one vulnerability, so the equivalent is to lower that to 1 and copy the discussion section's new-account daily cap.
- **The total pending cap for one vulnerability** (`NDAY_CORRECTIONS_OPEN_PER_VULN`) counts only entries whose submitter still has an account and is **not currently suspended**: after the submitter deletes their account (`submitter_id` is `NULL`) or is suspended, their entries stay in the back office queue for editors, but they no longer block other people from submitting;
  once the suspension expires (`suspended_until` is not later than now, whether or not the background cleanup has set the status back) or is lifted, those entries count again. The suspension test is the same as `auth.User.EffectiveStatus` (`site.SuspendedNowSQL`).
  The "same user on the same vulnerability" cap still counts all of that user's pending entries. There's no bulk reject or expiry mechanism yet.
- Tests: `TestVulnQueueIgnoresSuspendedAndDeleted`, `TestNewAccountSubmit`.

---

## 5. Pages

### 5.1 The vulnerability page (`corrections.tmpl`, `corrview.go`)

- **Revision log** (`#revisions`): shown only when there are accepted corrections. Each entry has the time it was handled (`<time>`, converted to the visitor's timezone), the category, the editor's public note (escaped text, `dir="auto"`), and "reported by @handle" (or "reported by a deleted account" after the account is deleted; when the submitter is currently suspended or has no handle, the credit line is omitted rather than falsely saying "deleted"). The explanatory text says these entries don't change the data above. At most 100 entries, through the server's shared cache (30 seconds), so an accepted correction takes up to about 30 seconds plus the page's own 60-second cache to appear.
- **Correction entry point** (`#correction`, when sign-in is configured): explanatory text (stating that data isn't changed automatically). The HTML is the same for everyone; the sign-in prompt, "set a handle first", "accept the rules first", the suspension notice, and the form all carry `hidden`, and `static/corrections.js` shows one of them based on `/api/me`. Without the script, a `noscript` notice is shown. The sign-in link returns to `?correction`, and after coming back the script removes it and scrolls to that section.
- After a successful submission it shows "Sent. An editor will look at it; you can follow its status here." and refreshes the "Your reports on this vulnerability" list below (date, category, status, your own text, and for accepted ones the editor's note). The script uses only `textContent` and DOM methods, fixed paths, and keeps the CSRF token only in the request header (`TestCorrectionsScriptIsSafe`).

### 5.2 The back office `/admin/corrections` (`admin_corr.go`)

Staff (moderators and admins); the access rules are the same as `/admin/moderation` (signed-out users get a 302 to the sign-in page; non-staff and suspended staff get a 404; `no-store`/`noindex` are forced). Two lists: pending (oldest first) and handled (`?state=decided`, most recently handled first), 30 per page, cursor pagination. Each entry shows the submitter (linked to the user page), the time, a link to the vulnerability, the category, the status, the submitted text (`<pre>`, escaped text), and the evidence link (`ExtLink`: only an absolute http/https URL becomes a link, with `target="_blank" rel="noopener noreferrer"`); handled entries also show when it was handled, who handled it, and the public note or internal note. Pending entries have two forms, "accept" (a public note text box, required) and "reject" (an internal note, optional), both confirmed with two clicks; `static/admin.js` calls the endpoints in §3.3 and then reloads the page. In the audit page, `correction` objects link to `/admin/corrections?state=decided#k-<id>`.

---

## 6. Logging

Submit, accept, and reject each write one INFO line: `corrections: submitted|accepted|rejected`, with the internal user id, the correction id, and the CVE (plus the category on submit). **The submitted text, link, and notes are never logged** (test `checkLogs`). Rate limiting: a `corrections: rate limited` WARN.

---

## 7. Tests

`internal/corrections` (needs a local PostgreSQL): `TestSubmitAccess` (signed out, missing/wrong CSRF, cross-site, another host, no handle, rules not accepted, suspended and expired), `TestSubmitValidation` (category, empty/invisible/too-long body, `javascript:`/`data:`/`ftp:`/relative/protocol-relative/userinfo/quoted/too-long links, unknown fields, Content-Type, unknown CVE, the normalized result), `TestSubmitLimits` (the three caps, the token bucket, `SetLimits`), `TestDecide` (permissions, the public note being required and its length, handling twice, the audit row, the submitter's view not including the internal note, the public query returning only accepted ones, anonymity after account deletion, a vulnerability with corrections can't be deleted), `TestDecideAuditAtomic`, `TestLimitsFromEnv`, `TestVulnQueueIgnoresSuspendedAndDeleted` (after suspension or deletion others can submit again, entries count again after the suspension expires, and open-ended suspensions), `TestNewAccountSubmit` (a new account's slot and daily cap, deciding by age and by contributions, the rules changing with settings), `TestAcceptAuditFullNote` (a 1000-character note is kept whole in the audit `details.public_note`), and `TestPublicLogSuspendedSubmitter` (no credit while suspended, restored after expiry or lifting, the deleted-account marker).
`internal/webui`: `TestCorrectionsOnVulnPage` (lists only accepted ones, escaping, credit, the same HTML before and after sign-in, and pending/rejected entries, the original text, links, and internal notes not appearing in the page, feed, sitemap, search, `/v1/*`, `/api/discuss`, or `/api/posts`), `TestCorrectionsSuspendedSubmitter` (when the submitter is suspended the revision log shows no credit and doesn't say "deleted"), `TestCorrectionsWithoutAccounts`, and `TestCorrectionsScriptIsSafe`. `internal/admin`: `TestCorrectionsPage` (access, escaping, link checks, forms only on pending entries).

---

## 8. Known limitations

- Accepting doesn't change data (see §1). Manually overriding upstream fields is separate work.
- The in-process token bucket resets on restart and isn't shared across instances (same as discussions); the daily cap and the pending caps are in the database and aren't affected.
- The revision log shows at most 100 entries (older ones are still in the database).
- No notifications: submitters have to go back to the vulnerability page to see the status.
- The back office list can't be filtered by vulnerability or submitter.
