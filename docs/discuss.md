# nday discussions (backend contract)

Implementation: `internal/discuss` (store, service, HTTP), `internal/discuss/md` (Markdown subset renderer), `migrations/0005_discuss.sql`, `migrations/0016_comment_purpose.sql` (purpose), `internal/cli/discuss.go` (wiring and `discuss-hide`/`discuss-unhide`). It builds on the sessions, CSRF, roles, suspension and terms of `internal/auth` (`docs/auth.md`). This is the full contract for people writing pages and scripts; §9 is the checklist.

---

## 1. Product rules and design decisions

- Each vulnerability has one comment stream shared by all languages, and each comment records the locale (`lang`) of the page it was posted from. Replies are one level deep: a reply's parent must be a **visible** top-level comment on the **same vulnerability**.
- Post first, moderate later: comments show up immediately. The controls are rate limits, reports, moderator hiding and suspending accounts. Links written by new accounts aren't clickable.
- To post a comment you need to be signed in, not suspended, have a handle, and have accepted the current community rules (when `NDAY_TERMS_VERSION` is set).

Decisions where the requirements left room:

| Question | Decision | Why |
|---|---|---|
| Signed-out visitors (since 2026-11-15) | They **can read** by default. They get exactly the public content that a signed-in user with no role sees (body, the author's public name, time, replies, purpose), with every permission field false and no source text or moderation info. Posting, replying, reporting, editing and deleting still need sign-in (§4.1). Setting `NDAY_DISCUSS_GUEST_READ=off` goes back to the 2026-11-14 behaviour: only an outline (the total number of visible comments and the shape of the first page), with **no** body, author, language, id or time | Discussions are open for guests to read, while actions like posting still need sign-in. The switch is the way back. The page HTML is still the same for everyone and publicly cacheable, and a script fetches the comments (§4.1) |
| Purpose of a top-level comment (2026-11-15) | Optional: `analysis` technical analysis, `reproduction` reproduction report, `fix` fix report, `detection` detection method, `question` question. Replies have no purpose, and you can post without choosing one | Encourages specific contributions. With "reproduction report" or "fix report", the input's hint asks for version, environment, result and source. It's only a hint: there's no extra field and no validation. There's no "correct the information" purpose (that has its own entry point) and no filtering by purpose |
| Does changing the purpose count as an edit? | Yes. Changing only the purpose still writes a revision (old body + old purpose), sets `edited_at` and increments `rev`. If neither body nor purpose changed, nothing is written | It reuses the existing revision mechanism: a revision records "how it looked before the edit", and the purpose is part of the comment (it changes how readers understand it), so moderators should see the purpose from before the change |
| Hidden comments, for ordinary visitors | Only a placeholder: `id`, `parent_id`, `created_at`, `status:"hidden"`; `author:null`, `lang:""`, `body_html:""`, `links:false` | Hidden content is often harassment, ads or malicious links. Not even showing the author avoids singling people out and keeps the content from spreading |
| Hidden comments, for their author | They see the body, `body` and `moderation.hidden_reason`/`hidden_at` (but not which moderator) | So the author knows why it was hidden. The moderator's identity isn't exposed, so nobody gets targeted |
| Deleted comments (deleted by the author) | They appear as a placeholder only if they still have undeleted replies, otherwise they don't appear at all. Deleted **replies** never appear | Keeps the conversation's context |
| Can moderators see the body of a deleted comment? | Yes (top-level comments under a placeholder, and `/api/mod/recent`) | Stops people from "insulting and deleting" to dodge moderation. The body is kept anyway (soft delete) |
| Do edits also need acceptance of the current rules? | Yes (`403 terms_required`) | An edit is publishing new content |
| Links from new accounts | Decided **at posting time** and stored in `comments.links`; it doesn't change afterwards | Rendering stays stable: when an account "graduates", old comments don't suddenly grow clickable links |
| A reporter deletes their account | `comment_reports.reporter_id ON DELETE SET NULL` | Reports are moderation evidence, and the open queue shouldn't shrink because a reporter deleted their account. Consistent with `docs/auth.md` §2.1 |
| A vulnerability referenced by `comments.cve_id` is deleted | `REFERENCES vuln` defaults to `NO ACTION` (deleting the vuln row fails) | See §2.4 |
| Bidirectional control characters | **Remove** U+202A–U+202E and U+2066–U+2069 (embedding/override/isolate); keep U+200E/U+200F/U+061C | Scoped control characters can fail to close and "leak" into the rest of the page. With them removed, every body can safely go in an element with `dir="auto"`. The implicit direction marks have no scope, and Arabic/Hebrew text needs them |
| Which pool for writes | A small writable pool just for discussions (`NDAY_DISCUSS_DB_POOL_SIZE`, default 4) | The site pool is read-only (`default_transaction_read_only=on`), so writes can't use it. Half of the sign-in pool is kept for session lookups, so comment traffic shouldn't crowd out sign-in, and the other way round |
| Which pool for reads | Public reads that don't depend on the caller (a signed-out `GET`, `Outline`/`Version`, whether the vulnerability exists) use the **site's read-only pool** (`nday serve` passes in `Store.ReadDB`). Writes and signed-in reads (which need to see what the user just wrote) use the discussion write pool | A flood of reads can't use up the 4 write connections, and the other way round |
| Page cache key | `Version` is a digest of each comment's `(id, rev, status)` plus the author's handle, role, display name and whether the account was deleted, sorted by id. `rev` increases on every UPDATE | It doesn't depend on the clock: a write that took its timestamp first and then waited for a lock can no longer leave the key "unchanged" |
| Page size | The body HTML on one page (including any returned source text) is ≤ 512 KiB. A whole thread goes in if it fits, and there's always at least one thread. If a single thread is too big, it's cut at a reply boundary and a continuation cursor is returned | The size of public pages and JSON has an upper bound |
| REJECTED CVEs | Can be discussed as usual | Pages can add a notice themselves |
| Reply limit per thread | 200 (including deleted/hidden ones); beyond that, `409 thread_full`. Replies to the same thread are serialized with an advisory lock, so the limit is exact even under concurrency | Keeps the page size bounded |

---

## 2. Data model (`migrations/0005_discuss.sql`, additions only)

### 2.1 `comments`

| Column | Description |
|---|---|
| `id uuid` | Primary key, `gen_random_uuid()` (same as 0004) |
| `cve_id text NOT NULL REFERENCES vuln` | The vulnerability it belongs to (canonical uppercase form) |
| `parent_id uuid` / `is_reply bool` / `parent_is_reply bool DEFAULT false CHECK (=false)` | Composite foreign key `(parent_id, cve_id, parent_is_reply) → comments (id, cve_id, is_reply)`: **the database itself** rejects replies to replies and cross-vulnerability replies (the same approach as `handle_ns_kind` in 0004). `CHECK (is_reply = (parent_id IS NOT NULL))` |
| `author_id uuid REFERENCES users ON DELETE SET NULL` | After the account is deleted, the comment stays and the author is null |
| `body text` | Markdown source, 1–10000 characters (after normalization, see §3.2) |
| `lang text` | The locale tag of the page it was posted from (`zh-Hans` and so on, one of the enabled locales) |
| `links bool` | Whether links are clickable (the author wasn't a "new account" at posting time) |
| `status` | `visible` / `hidden` / `deleted` |
| `created_at`, `edited_at`, `deleted_at`, `updated_at` | `updated_at` is the time of the last change (taken after the row lock is acquired) |
| `rev bigint DEFAULT 1` | Incremented on every UPDATE (edit, delete, hide, unhide), independent of the clock; `Version` uses it |
| `hidden_at`, `hidden_by → users ON DELETE SET NULL`, `hidden_reason` (1–200 characters) | Required when hidden (`CHECK`); cleared on unhide; `hidden_by` is null when hidden from the CLI |
| `purpose text` (`0016`) | Nullable; a `CHECK` limits it to `analysis` / `reproduction` / `fix` / `detection` / `question`, and it may only be set on top-level comments (`purpose IS NULL OR parent_id IS NULL`) |

Indexes: `(cve_id, created_at, id) WHERE parent_id IS NULL` (pagination), `(parent_id, created_at, id) WHERE parent_id IS NOT NULL` (replies), `(author_id, created_at)` (daily limit, duplicate check, new-account check), `(created_at DESC, id DESC)` (moderator patrol).

### 2.2 `comment_revisions`

Every edit saves the **old** body and the **old** purpose: `comment_id`, `body`, `purpose` (added in `0016`, nullable, same values as above; rows from before 0016 have null), `replaced_at`. It's for auditing only, and only the moderator endpoint §3.9 returns it. An edit that changes neither body nor purpose writes nothing.

### 2.3 `comment_reports`

`id`, `comment_id`, `reporter_id → users ON DELETE SET NULL`, `reason` (`spam` `abuse` `off_topic` `misinformation` `malicious_link` `illegal` `other`), `note` (≤500 characters, nullable), `created_at`, `resolved_at`, `resolved_by → users ON DELETE SET NULL`, `resolution` (`hidden` automatically when the comment is hidden / `dismissed` / `actioned`). A partial unique index allows at most one **open** report per (comment, reporter).

### 2.4 When a vulnerability is deleted or rejected

Verified: neither the Go nor the Python code contains `DELETE FROM vuln` (the only occurrence is in a test, `internal/collector/cvelist/fetch_test.go:1018`). An entry rejected by CVE is still a `vuln` row, and only has `detail.state = 'REJECTED'` in the cvelist `disclosed` event (`rej` in `migrations/0002_vuln_state.sql`). So discussions don't disappear because of a "rejection". `comments.cve_id` uses the default `NO ACTION`: if some job ever deletes vuln rows, it fails outright when discussions exist, instead of silently dropping them. That job would have to decide first what to do with the discussions.

---

## 3. HTTP API

### 3.0 General

- **Only on the site host** (the host of `NDAY_PUBLIC_URL`, ignoring an explicit default port): any other `Host` → `421 wrong_host`. These routes don't exist at all on the API host (`NDAY_API_URL`; JSON 404/405). They only exist when sign-in is enabled (and `NDAY_DISCUSS` isn't `off`); otherwise you get 404.
- **Every response**: `Cache-Control: no-store`, `Vary: Cookie`, no `ETag`/`Last-Modified`/`Expires`/CDN cache headers, and conditional requests never get a 304 (also when a handler panics).
- **The error body** is the same as in the data API and the sign-in endpoints: `{"error":{"status":403,"code":"terms_required","message":"…","param":"2026-11-01"}}`; `param` may be omitted. `message` is in English and meant for developers; pages show localized text based on `code`.
- **Write requests** (all POSTs): same-origin (`Origin` equals the public origin, or `Sec-Fetch-Site: same-origin`, at least one of them) plus `X-CSRF-Token` (the `csrf_token` from `GET /api/me`). Requests with a body need `Content-Type: application/json`, ≤ 64 KiB, no unknown fields, and nothing after the value. Requests without a body (delete, unhide) don't need a `Content-Type`.
- Errors any endpoint may return: `401 not_signed_in` (endpoints that need sign-in), `403 cross_site`, `403 csrf` (`param: "X-CSRF-Token"`), `403 suspended` (write operations other than delete), `404 not_found` (unknown route, or an id in the path that isn't a UUID), `405 method_not_allowed` (with `Allow`), `413 too_large`, `415 bad_request` (Content-Type), `400 bad_request` (invalid JSON / unknown field), `421 wrong_host`, `429 rate_limited` (with `Retry-After` in seconds; also when the same session token is used too often), `503 busy` (the session lookup queue timed out, `Retry-After: 1`), `500 internal`.
- Times are all RFC 3339 UTC (`2026-11-13T12:00:00Z`). Ids are all lowercase UUID text.

### 3.1 `GET /api/discuss/{cve}?locale=&limit=&cursor=` (and `?thread=&cursor=`)

Anonymous requests are allowed. **When guest reading is allowed** (`NDAY_DISCUSS_GUEST_READ`, default `on`), a signed-out request goes through the same code as a signed-in user, as an "anonymous viewer", and gets the full content below (the fields of each comment are listed in §4.1: no `body` or `moderation`, every `can_*` and `reported` is `false`, `viewer.signed_in` is `false`), and all parameters are supported.
**When it's off**, only the outline is returned (§4.1: `comments` is `[]`, `next_cursor` is `null`, there's an extra `outline`, and all content parameters such as `cursor`/`thread`/`c`/`limit` are ignored).
After sign-in you get the full content plus fields that depend on the caller. It's rate-limited per client address (default burst 120, then 1 every 0.5 seconds). When the request is signed out and guest reading is allowed, each request also takes one token from a "guest read" bucket (per client address, default burst 60, then 1 every 2 seconds, `NDAY_DISCUSS_GUEST_READ_BURST` / `_EVERY`). Going over gives `429 rate_limited` (with `Retry-After`). Signed-out reads all use the site's read-only pool.

- `{cve}`: a CVE id in any case (`cve-2026-1234` works too). A bad format gives `400 bad_cve`; a vulnerability that doesn't exist gives `404 not_found` (`param: "cve"`).
- `locale`: the page's locale tag (such as `zh-Hans`). CVE links in the body get a prefix based on it (`/zh-hans/vuln/CVE-…`). If it's missing or not enabled, the primary language is used (`/vuln/CVE-…`).
- `limit`: top-level comments per page, 1–200, default 50 (otherwise `400 bad_request`, `param: "limit"`). A page also ends early once it has more than 500 comments (top-level plus replies), though it always includes at least one thread.
- `cursor`: the `next_cursor` of the previous page (invalid → `400 bad_cursor`).
- **Byte budget**: all `body_html` on a page (plus `body`, where returned) add up to ≤ `limits.max_page_bytes` (524288 = 512 KiB). A thread only goes in if it fits entirely, but the first thread always goes in. If the **first thread by itself** is over budget, it only carries its first few replies, with `replies_truncated: true` and `replies_next_cursor: "<cursor>"`, and `next_cursor` points at the thread after it.
- `c` (2026-11-14; for signed-out requests it only applies when guest reading is allowed): the id of a visible comment. It returns **the page that contains it**: if its thread is on the first page, you get the first page, otherwise a page starting with its thread.
  The response has an extra `cursor` (the cursor of the page used; `""` = the first page). Replies inside a truncated thread need `thread` to continue. If the id doesn't exist or isn't visible, you get the first page (`cursor: ""`).
- `thread`: continues a truncated thread, `GET /api/discuss/{cve}?thread=<top-level comment id>&cursor=<replies_next_cursor>`. The response has the same shape as this section, `comments` contains only this one thread (the top-level comment itself appears again), and `replies` are the replies after the cursor (also limited by the budget, at least one per call), possibly with `replies_truncated: true` again; `next_cursor` is always `null`. A thread that doesn't exist or doesn't belong to the vulnerability gives `404 not_found` (`param: "thread"` or none).

Top-level comments are in chronological order (ties broken by id), and each one carries all its undeleted replies (chronological). The response (for a signed-in user; when guest reading is allowed this is also what an anonymous visitor gets; excerpted from real test output; every visible comment now also has `body_nodes`, and every comment has `purpose`, see the table below):

```json
{"cve":"CVE-2026-0001","count":2,
 "comments":[{"id":"0b141010-ef0f-49ba-b9bd-2f476f8923bb","parent_id":null,
   "author":{"handle":"ada","display_name":"Ada","role":"user"},
   "lang":"zh-Hans","created_at":"2026-11-13T12:00:00Z","edited_at":null,"status":"visible",
   "body_html":"<p>升级到 <strong>2.4.1</strong>，见 <a href=\"/zh-hans/vuln/CVE-2026-0002\" rel=\"nofollow ugc noopener noreferrer\">CVE-2026-0002</a> 和 <a href=\"https://example.com/advisory\" rel=\"nofollow ugc noopener noreferrer\">https://example.com/advisory</a></p>\n",
   "links":true,"can_edit":false,"can_delete":false,"can_hide":false,"can_unhide":false,"can_report":false,"can_reply":false,"reported":false,
   "replies":[{"id":"44583087-828d-4c12-bfe1-cd9a01288cba","parent_id":"0b141010-ef0f-49ba-b9bd-2f476f8923bb",
     "author":{"handle":"bob","display_name":"Bob","role":"user"},"lang":"zh-Hans","created_at":"2026-11-13T12:00:00Z","edited_at":null,
     "status":"visible","body_html":"<p>谢谢！</p>\n","links":false,
     "can_edit":false,"can_delete":false,"can_hide":false,"can_unhide":false,"can_report":false,"can_reply":false,"reported":false,"replies":null}]}],
 "next_cursor":null,
 "viewer":{"signed_in":false,"handle":null,"role":null,"can_post":false,"post_refusal":"not_signed_in","terms_version":"2026-11-01","links":false,"moderator":false},
 "limits":{"max_body_chars":10000,"max_replies":200,"max_note_chars":500,"max_page_bytes":524288}}
```

Fields:

| Field | Description |
|---|---|
| `count` | The total number of **visible** comments on the vulnerability (including replies, across all pages) |
| `next_cursor` | Cursor for the next page; `null` means there's nothing more |
| `comments[].id` / `parent_id` | A `parent_id` of `null` means a top-level comment |
| `author` | `{handle, display_name, role}`; `null` = a placeholder (see §4) or the author deleted their account. Only moderators see a `display_name` with a value. For signed-out callers and ordinary signed-in users it's always `null` (it comes from the third-party sign-in profile, which is often a real name, and pages only show `handle`). When `role` is `moderator` or `admin`, the page should show a staff badge |
| `lang` | The locale of the page it was posted from; `""` for a placeholder |
| `status` | `visible` / `hidden` / `deleted` |
| `purpose` | Added 2026-11-15: the purpose declared on a top-level comment (`analysis` / `reproduction` / `fix` / `detection` / `question`); `null` if none was chosen, for replies and for placeholders |
| `body_html` | The rendered body, ready to insert as HTML (§6); `""` for a placeholder |
| `body_nodes` | Added 2026-11-14: the node tree of `body_html` (`md.Nodes`). Scripts build it with DOM methods only and don't parse HTML: a text node is a JSON string, an element is `{"e":"p","c":[…]}`, and links also have `"href"`. Only the elements in §6 can appear. Placeholders don't have this key. Example: `[{"e":"p","c":["Patch: ",{"e":"strong","c":["upgrade"]}]},"\n"]` |
| `body` | The Markdown source. This key is **only in responses to the author and moderators** (to pre-fill the edit box); nobody else gets it |
| `links` | Whether links in this comment are clickable (`false`: the author was a new account when posting, and links show as text; CVE links work as usual) |
| `edited_at` | Time of the last edit, or `null` |
| `can_edit` | The caller is the author, not suspended, has a handle, has accepted the current rules, and the comment is visible |
| `can_delete` | The caller is the author and the comment is visible or hidden (also while suspended) |
| `can_hide` / `can_unhide` | The caller is a moderator/admin who isn't suspended, and the comment is visible / hidden |
| `can_report` | The caller is signed in, not suspended, isn't the author, and the comment is visible |
| `can_reply` | The comment is top-level and visible, has fewer than 200 replies, and the caller can post |
| `reported` | The caller has an open report on this comment |
| `moderation` | For moderators: `{hidden_at, hidden_by?, hidden_reason, deleted_at?, open_reports, revisions}` (`hidden_by`/`deleted_at` are left out when empty; `revisions` = the number of saved old bodies, read them with §3.9). For the author of a hidden comment: `{hidden_at, hidden_reason}`. Nobody else gets this key |
| `replies` | For top-level comments: an array (possibly `[]`). For replies: `null` (a reply can't have replies) |
| `replies_truncated` / `replies_next_cursor` | Present on every comment: usually `false` / `null`. When `true`, this thread's replies weren't all returned; continue with `?thread=<id>&cursor=<replies_next_cursor>` |
| `viewer.signed_in` / `handle` / `role` / `moderator` | The caller; `moderator` = role ≥ moderator and not suspended |
| `viewer.can_post` / `post_refusal` | Whether they can post. When they can't, `post_refusal` is `not_signed_in` / `suspended` / `handle_required` / `terms_required` (checked in this order); when they can, it's `null` |
| `viewer.terms_version` | The current rules version (submit it when accepting); `null` if not configured |
| `viewer.links` | Whether links in a comment the caller posts **now** would be clickable (signed in and not a new account) |
| `limits` | Fixed upper bounds so pages can validate on the client, including `max_page_bytes` |

### 3.2 `POST /api/discuss/{cve}`: post a comment

Request: `{"body":"…","lang":"zh-Hans"}`; for a reply, also add `"parent_id":"<top-level comment id>"`. A top-level comment can add `"purpose":"reproduction"` (values in §3.1; `null` or `""` = no label).

Order of processing, and the errors:

1. Session, same-origin, CSRF, not suspended (§3.0).
2. `400 bad_cve`; `403 handle_required` (call `POST /account/handle` first); `403 terms_required` (`param` is the current rules version; call `POST /account/accept-terms {"version": param}` first).
3. Rate limit per client address (all users combined, default burst 10, then 1 every 10 seconds) → `429 rate_limited`.
4. The request body (the 413/415/400 of §3.0).
5. Body normalization (`md.Clean`, then trim leading and trailing whitespace): CR/CRLF → LF; remove control characters other than Tab/LF (including NUL, DEL, C1), U+FFFE/U+FFFF, and the bidi embedding/override/isolate characters; also remove invisible characters U+200B, U+2060, U+FEFF, U+00AD, U+3164, U+FFA0, U+115F, U+1160, U+180E and the tag characters U+E0000–U+E007F (ZWJ/ZWNJ are kept); keep at most 4 consecutive combining marks (Mn/Me) per base character; lines containing only spaces/Tab/ZWJ/ZWNJ become empty lines, and at most 2 consecutive empty lines are kept; invalid UTF-8 becomes U+FFFD. The result must be 1–10000 characters (Unicode code points) **and contain at least one visible character** (not whitespace, a combining mark or a format character), otherwise `400 invalid_body` (`param: "body"`). What gets stored is the normalized text.
6. `lang` must be an enabled locale tag (case-insensitive, stored in canonical form) → `400 bad_lang`. A `parent_id` that isn't a UUID → `400 bad_parent`. A `purpose` that isn't one of the five values, or a reply that carries a purpose → `400 bad_purpose` (`param: "purpose"`; a non-string → `400 bad_request`).
7. In one transaction (serialized per author): if the number of posts in the rolling 24-hour window has reached the limit → `429 daily_limit` (`Retry-After` = the seconds until the oldest post in the window is 24 hours old); the same author, the same vulnerability, an identical body, within 10 minutes and not deleted → `409 duplicate`; the per-user burst limit (different for new and old accounts) → `429 rate_limited`; the insert statement itself requires that the vulnerability exists (`404 not_found`, `param: "cve"`), that the parent comment is a visible top-level comment on the same vulnerability (taking a shared lock on it before commit; `400 bad_parent`, `param: "parent_id"`), and that the parent thread has fewer than 200 replies (`409 thread_full`).

On success: `201`, `{"ok":true,"comment":{…the comment as the caller sees it, same as §3.1…}}`.

### 3.3 `POST /api/discuss/comment/{id}/edit`: edit

Request `{"body":"…"}` or `{"body":"…","purpose":"fix"|null}`: no `purpose` key = the purpose stays; `null` or `""` = remove the purpose; a reply can only omit it or send `null`. Only the author can do this; they need to be not suspended, have a handle and have accepted the current rules, and the comment must be visible. The old body and old purpose are saved together in `comment_revisions`. If neither body nor purpose changed, nothing is written (`edited_at` stays); changing only the purpose still counts as an edit (a revision is written and `edited_at` updated). `links` keeps the value from posting time.

Errors: §3.0; `403 handle_required`, `403 terms_required`; `429 rate_limited` (per user, default burst 20, then 1 every 3 minutes, about 20 per hour); `400 invalid_body`; `400 bad_purpose` (unknown value, not a string, or setting a purpose on a reply); `404 not_found`; `403 not_author`; `409 wrong_status` (hidden/deleted). On success: `200`, `{"ok":true,"comment":{…}}`.

### 3.4 `POST /api/discuss/comment/{id}/delete`: delete

No request body. Only the author can do this, **also while suspended**, and visible or hidden comments can be deleted (soft delete). Per-user rate limit (every outcome counts, suspended users too): default burst 10, then 1 every 30 seconds → `429 rate_limited`. Errors: §3.0 (without `suspended`); `404 not_found`; `403 not_author` (including comments whose author deleted their account); `409 wrong_status` (already deleted). On success: `200`, `{"ok":true,"comment":{…placeholder…}}`.

### 3.5 `POST /api/discuss/comment/{id}/report`: report

Request `{"reason":"spam","note":"optional, ≤500 characters"}`. `reason` is one of `spam` `abuse` `off_topic` `misinformation` `malicious_link` `illegal` `other`. Any signed-in user who isn't suspended can report, except the author; only visible comments can be reported. Per-user rate limit (every outcome counts, including idempotent repeats and 404/409): default burst 5, then 1 per minute → `429 rate_limited`. There's also a daily limit (see below). If a hide happens concurrently, the report either commits first and is resolved along with the hide, or sees the comment already hidden and gets `409 wrong_status`. **Idempotent**: if you already have an open report on the comment, that one is returned (`already_reported: true`) and it doesn't count toward the daily limit.

```json
{"ok":true,"already_reported":false,
 "report":{"id":"3a03d7fc-79b9-4aa7-b6ce-902bf425b4a7","reason":"spam","note":"广告","created_at":"2026-11-13T12:00:00Z",
   "resolved_at":null,"resolution":null,"reporter":null,"resolved_by":null}}
```

(`reporter` is always `null` here: the reporter is the caller.) Errors: §3.0; `400 bad_reason`; `400 bad_note` (`note` is over 500 characters once newlines are turned into spaces); `404 not_found`; `403 own_comment`; `409 wrong_status`; `429 daily_limit` (by default 20 per user within 24 hours).

### 3.6 `POST /api/discuss/comment/{id}/hide` and `/unhide`: moderators

Requires the role moderator or admin, and not suspended (`403 forbidden` / `403 suspended`). Each moderator also has a generous rate limit (default burst 600, then 1 every 0.1 seconds).

- `hide`: request `{"reason":"1–200 characters"}` (→ `400 bad_reason`). Only visible comments can be hidden (`409 wrong_status`), and in the same transaction all open reports on that comment are marked `resolution:"hidden"`. On success: `{"ok":true,"comment":{…moderator view…},"resolved_reports":1}`.
- `unhide`: no request body; only for hidden comments (`409 wrong_status`); clears `hidden_*`. On success: `{"ok":true,"comment":{…}}`.

The moderator view of a comment has `body` and `moderation` on top of §3.1, and `moderation.cve` gives the vulnerability it belongs to (it only appears in the moderator endpoints and the hide/unhide responses).

### 3.7 `GET /api/mod/reports?state=open|resolved&limit=&cursor=` and `POST /api/mod/reports/{id}/resolve`: moderators

- List: `state` defaults to `open` (oldest first); `resolved` is most recently resolved first. `limit` is 1–100 (default 100), and `next_cursor` paginates. An invalid `state` → `400 bad_request`.

```json
{"state":"open","reports":[{"id":"3a03d7fc-…","reason":"spam","note":"广告","created_at":"2026-11-13T12:00:00Z",
  "resolved_at":null,"resolution":null,"reporter":{"handle":"bob","display_name":"Bob","role":"user"},"resolved_by":null,
  "comment":{…the comment in moderator view, with body and moderation.open_reports, moderation.cve…}}],"next_cursor":null}
```

  `reporter` / `resolved_by` being `null` means the account was deleted (or it was resolved from the CLI).
- Resolve: request `{"resolution":"dismissed"|"actioned"}` (`hidden` is only set by hide → `400 bad_resolution`); already resolved → `409 wrong_status`; doesn't exist → `404 not_found`. On success: `{"ok":true,"report":{…same as above…}}`.

### 3.8 `GET /api/mod/recent?limit=&cursor=`: moderator patrol

The newest comments site-wide (all statuses, including deleted), newest first, `limit` 1–100 (default 100): `{"comments":[…moderator view, replies is null…],"next_cursor":"…"|null}`.

---

### 3.9 `GET /api/mod/comment/{id}/revisions`: moderators read old bodies

Requires moderator/admin and not suspended (`401`/`403 forbidden`/`403 suspended`), with the moderator rate limit. It returns the saved old bodies (and the purpose at that time, added 2026-11-15; `null` = no purpose, or a revision from before 0016), **newest first**, at most 200, **source text only** (not rendered; pages must show it as text):

```json
{"comment_id":"0b141010-…","revisions":[{"body":"harmless","purpose":"fix","replaced_at":"2026-11-13T12:00:02Z"},
  {"body":"buy pills <b>now</b>","purpose":null,"replaced_at":"2026-11-13T12:00:01Z"}]}
```

A comment that doesn't exist → `404 not_found`. In each comment's moderator view, `moderation.revisions` is the count.

## 4. Visibility

| Status | Anonymous / other users | Author | Moderator (not suspended) |
|---|---|---|---|
| `visible` | Full (no `body`) | Full + `body` | Full + `body` + `moderation` |
| `hidden` | Placeholder | Full + `body` + `moderation.{hidden_at,hidden_reason}` | Full + `body` + `moderation` (including `hidden_by`) |
| `deleted` (only appears on top-level comments that have undeleted replies) | Placeholder | Placeholder | Full + `body` + `moderation.deleted_at` |

(This table is what **signed-in users** see. When guest reading is allowed, a signed-out visitor sees exactly the same as the "Anonymous / other users" column, see §4.1.)

A placeholder is `{"id","parent_id","created_at","status","author":null,"lang":"","edited_at":null,"purpose":null,"body_html":"","links":false,…can_*…,"replies":…}`. Replies to a hidden comment are shown as usual. `count` only counts visible comments. After the author deletes their account, the comment stays and `author` is `null`; nobody can edit or delete it any more (moderators can still hide it).

### 4.1 Signed-out visitors (2026-11-15: they can read by default)

**When guest reading is allowed** (`NDAY_DISCUSS_GUEST_READ` is `on`, the default; `discuss.Limits.GuestRead`, effective as soon as it's saved in the admin area):

- For a request with no valid session, `GET /api/discuss/{cve}` calls the same read code as for signed-in users, as an "anonymous viewer" (`read` in `internal/discuss/service.go`, `view(row, nil, …)`),
  so a guest sees what a signed-in user with no role sees, **and nothing more**. Field by field (`view` and `Comment` in `internal/discuss/view.go`):
  - Visible comments: `id`, `parent_id`, `author` (only the three keys `handle`, `display_name` and `role`, i.e. `Author` in `store.go`; **`display_name` is always `null`**. It's the name copied from the Google/GitHub profile at first third-party sign-in, there's no way to change it on the site, and pages don't show it, so `view` blanks it for the anonymous viewer; signed-in users see it unchanged. There's no user id, e-mail or sign-in method), `lang`, `created_at`, `edited_at`, `status`, `purpose`, `body_html`, `body_nodes`, `links`, `replies`, `replies_truncated`, `replies_next_cursor`;
  - Hidden / deleted comments (a deleted top-level comment that still has replies): a placeholder (§4), with no body, author, language or purpose. Deleted replies, and deleted top-level comments without replies, don't appear at all;
  - `can_edit` `can_delete` `can_hide` `can_unhide` `can_report` `can_reply` `reported` are always `false` (in `view`, each of them requires `v != nil`; the SQL for `reported` compares against a `NULL` caller, which is always false);
  - **No** `body` (the source text, only for the author and moderators) and no `moderation` (hide reason, who hid it, report count, revision count). Revision content and report content are only in the moderator endpoints;
  - `viewer`: `signed_in:false`, `handle:null`, `role:null`, `can_post:false`, `post_refusal:"not_signed_in"`, `terms_version`, `links:false`, `moderator:false`.
  Tests: `internal/discuss/guestread_test.go` (it uses hidden, deleted, a reply to a hidden comment, a deleted reply, an edited comment and a reported comment as fixtures and checks the guest response key by key. It also checks that the response is byte-for-byte identical to a signed-in reader's response once the caller-specific fields (including the author's `display_name`) are removed. `TestGuestReadNoDisplayName`: when an author has set a `display_name`, it doesn't appear in the guest response body for the default page or for the `c=`, `thread=` and `cursor=` queries, nor in an ordinary signed-in user's response, but it does in a moderator's. All write endpoints and moderator endpoints still return `401 not_signed_in` for guests),
  and `TestGuestCommentsPublic` in `internal/webui/nonpublic_test.go`.
- The page HTML is still **the same for everyone, doesn't read cookies** and stays publicly cacheable, and it still only has the outline (dotted squiggle noise). The only difference is that this HTML is determined by a site setting: the discussion area carries `data-guest="1"`,
  below the outline it says "loading N comments…" (without scripts: "Turn on JavaScript to read the comments."), and the dotted noise no longer links to the sign-in page. `static/discuss.js` requests `GET /api/discuss/{cve}` for **every** visitor and replaces the outline with the comments it gets back.
  When signed out, no action buttons are shown (every `can_*` from the server is false), and the post box is replaced with a note that discussions are open for everyone to read and that you can sign in to comment, reply and report ("Sign in to comment, reply or report."), plus a sign-in button (returning to `?discussion`).
  Visitors without JavaScript (including search engines) still can't read comment bodies (there's no server-side rendering).
- The endpoint is still `Cache-Control: no-store` and `Vary: Cookie`: the same URL returns different responses for signed-in users and guests (permission fields, `body`), and CDNs often don't key their cache on `Cookie`, so a public cache could serve one kind of response to the other kind of visitor. After a write, the script reloads with `?fresh=`, which also requires reading the latest content. The cost is bounded by rate limiting: besides the per-client-address read bucket, guests have their own "guest read" bucket (§5).

**When it's off** (`off`, falling back to the 2026-11-14 rules): for a request with no valid session, the page and `GET /api/discuss/{cve}` only give:

```json
{"cve":"CVE-2026-0001","count":2,"comments":[],"next_cursor":null,
 "outline":{"count":2,"threads":[{"status":"visible","size":"s","replies":[{"status":"visible","size":"s"}]}],"more":false},
 "viewer":{"signed_in":false,"handle":null,"role":null,"can_post":false,"post_refusal":"not_signed_in","terms_version":"2026-11-01","links":false,"moderator":false},
 "limits":{"max_body_chars":10000,"max_replies":200,"max_note_chars":500,"max_page_bytes":524288}}
```

- `outline` (`discuss.Service.Outline`, at most 50 threads on the first page): the `status` of each thread; for visible comments, a `size` (source text up to 120 characters is `s`, up to 600 is `m`, longer is `l`);
  the same for replies (at most 20 per thread are listed, the rest are counted in `more_replies`); `more` = there are more threads after these. There's **no** body, author, language, id, time or cursor.
- The discussion area of a vulnerability page (the HTML is the same for everyone) only draws this outline: visible comments are dotted squiggle noise (`static/app.js` draws it on a canvas by size class and a random seed,
  unrelated to the content; with no script it's a CSS dot pattern), and hidden/deleted placeholders still show their text. Below that is a line saying you can read the N comments after signing in, and a sign-in button (returning to `?discussion`).
- Signed-in users: `static/discuss.js` requests `GET /api/discuss/{cve}?locale=…[&c=…]`, replaces the outline with the comments it gets (building elements one by one from `body_nodes`),
  and then attaches the usual action buttons. The "more comments" and "more replies" buttons append inside the page (`cursor` / `thread`). Signed-in users without JavaScript can't see the comment content.
- Tests: the older tests in `internal/discuss` (the default in `harness_test.go` is guest reading off), `TestGuestReadSwitch`, and `TestPostsNotPublic` in `internal/webui` (it crawls the whole site with the switch off).

Unchanged in both modes: feeds, the sitemap, share cards, the public data API (the API host) and `/raw/` don't contain comments (`TestPostsNotPublic` crawls the whole site to verify this). The moderator endpoints and the admin area are unchanged. The visibility rules of the "researcher discussion" area (`internal/posts`) on the vulnerability page aren't affected by this switch.

---

## 5. Rate limits and configuration

In-process token buckets (the same `auth.RateLimiter` as sign-in: bounded LRU, IPv6 per /64, reset on restart, not shared between instances). Daily limits are counted in the database over a rolling 24-hour window (they survive a restart and are safe under concurrency). When rate-limited, you get `429` + `Retry-After`, and warning logs are limited to one per minute (with the number omitted).

A **new account** = an account created less than `NEW_ACCOUNT_AGE` ago **or** with fewer than `NEW_ACCOUNT_COMMENTS` visible comments. New accounts get stricter posting limits, and their comments have `links=false`.

| Variable | Default | Meaning |
|---|---|---|
| `NDAY_DISCUSS` | `on` | `off`: don't mount the discussion routes (sign-in works as usual) |
| `NDAY_DISCUSS_DB_POOL_SIZE` | 4 | Writable pool dedicated to discussions (1–32) |
| `NDAY_DISCUSS_POST_BURST` / `_POST_EVERY` / `_POST_DAILY` | 5 / 30s / 60 | Established accounts: per-user burst, the interval after that, and the 24-hour limit |
| `NDAY_DISCUSS_NEW_POST_BURST` / `_NEW_POST_EVERY` / `_NEW_POST_DAILY` | 2 / 2m / 10 | New accounts |
| `NDAY_DISCUSS_NEW_ACCOUNT_AGE` / `_NEW_ACCOUNT_COMMENTS` | 24h / 3 | What counts as a new account |
| `NDAY_DISCUSS_ADDR_BURST` / `_ADDR_EVERY` | 10 / 10s | Posting per client address (`CF-Connecting-IP`, all users combined) |
| `NDAY_DISCUSS_EDIT_BURST` / `_EDIT_EVERY` | 20 / 3m | Edits, per user (about 20 per hour) |
| `NDAY_DISCUSS_REPORT_DAILY` | 20 | Reports, per user per 24 hours |
| `NDAY_DISCUSS_REPORT_BURST` / `_REPORT_EVERY` | 5 / 1m | Report requests, per user (every outcome) |
| `NDAY_DISCUSS_DELETE_BURST` / `_DELETE_EVERY` | 10 / 30s | Delete requests, per user (suspended users count too) |
| `NDAY_DISCUSS_READ_BURST` / `_READ_EVERY` | 120 / 500ms | `GET /api/discuss/{cve}`, per client address |
| `NDAY_DISCUSS_GUEST_READ` | `on` | `off`: signed-out visitors only get the outline (§4.1); effective as soon as it's saved in the admin area, no restart needed |
| `NDAY_DISCUSS_GUEST_READ_BURST` / `_GUEST_READ_EVERY` | 60 / 2s | When guest reading is allowed, a signed-out `GET /api/discuss/{cve}` is also limited per client address (on top of the previous row) |
| `NDAY_DISCUSS_MOD_BURST` / `_MOD_EVERY` | 600 / 100ms | Moderator endpoints, per moderator |
| `NDAY_DISCUSS_DUPLICATE_WINDOW` | 10m | Window for the duplicate-content check |

Counts are integers from 1 to 100000; switches are `on` / `off` (case-insensitive); durations are Go durations or days (`30s`, `2m`, `24h`, `1d`), from 1ms to 30d. If a value is invalid, `nday serve` refuses to start, and the error names the variable without echoing the value.
Except for `NDAY_DISCUSS_DB_POOL_SIZE`, the variables in the table can also be stored in the database by an admin at `/admin/settings` (database values win, and saving takes effect on the running site; `NDAY_DISCUSS` needs a restart). See `docs/settings.md`. Also: at most 200 replies per thread, body ≤10000 characters, request body ≤64 KiB.

---

## 6. Markdown subset (`internal/discuss/md`)

The output consists **only** of these elements: `<p> <br> <pre><code> <code> <blockquote> <ul> <ol> <li> <em> <strong> <a>`. None of them have attributes except `<a>`, which has only `href` and a fixed `rel="nofollow ugc noopener noreferrer"`, and no `target`. Everything else is escaped text (`& < > " '` → `&amp; &lt; &gt; &#34; &#39;`). The output is always closed and properly nested.

Supported syntax:

| Syntax | Result |
|---|---|
| Paragraphs separated by blank lines | `<p>` |
| **Every newline** inside a paragraph, list item or quote | `<br>` (a hard break; leading and trailing whitespace on the line is removed) |
| A fenced code block that opens with ```` ``` ```` (3 or more backticks, indented at most 3 spaces) and ends at a line of at least as many backticks. An info string (such as `go`) is accepted and ignored; if it's never closed, it runs to the end | `<pre><code>…</code></pre>`, with the content escaped as is |
| `` `code` `` (a run of backticks of any length, paired with a run of the same length; text if it can't be paired) | `<code>` |
| Consecutive lines starting with `> ` | A single level of `<blockquote>` that contains only paragraphs; the second `>` of `>>` is text |
| Lines starting with `- ` or `* ` / lines starting with `1. ` (1–9 digits followed by a dot) | A single level of `<ul>` / `<ol>`. Following lines indented ≥2 spaces (or a Tab) belong to the same item; nested list markers are text; `<ol>` always numbers from 1. In the middle of a paragraph, only a line starting with `1.` can start a list (so a line after a newline within a paragraph like `2024. The year…` doesn't turn into a list; but a paragraph whose first line is `2024. The year…` does) |
| `*emphasis*` / `**bold**` (only `*` counts; `_` is an ordinary character, so `snake_case` is unaffected; three or more consecutive `*` are text; the opener can't be followed by whitespace and the closer can't be preceded by it; strictly nested, and anything that can't be paired is text) | `<em>` / `<strong>` |
| `[text](https://…)` | A link (the text may contain emphasis and code, but no other link; the URL ends at the first whitespace or `)`; titles and URLs with parentheses aren't supported) |
| A bare `http://…` / `https://…` (not directly preceded by a letter, digit or URL character) | An autolink. It ends at whitespace, `< > " \` ``, or any non-ASCII character (such as CJK punctuation); trailing `. , : ; ! ? ' *` and an unpaired `)` are stripped |
| `CVE-YYYY-NNNN…` (case-insensitive, a 4–19 digit sequence number, not directly preceded or followed by a letter or digit) | A link to this site's vulnerability page (`/zh-hans/vuln/CVE-…`, with the prefix following `locale`); the link text keeps the original spelling; **at most 30 per comment** (`md.MaxCVELinks`), and the rest are plain text |
| `\` + ASCII punctuation | The literal punctuation character |

**Link URLs** must start with `http://` or `https://`, be ≤2048 bytes, contain only printable ASCII (no spaces and no `" < > \ \``), be parseable by `net/url`, have a host, and have no user info (`https://user@host` isn't allowed). The scheme is lowercased in the output. Anything else (`javascript:`, `data:`, `vbscript:`, relative paths, `//host`, non-ASCII URLs) is shown as text. The path of a CVE link is generated by the server and must match `/[A-Za-z0-9._~/-]+` (not starting with `//`, no `.`/`..` segments, ≤128 bytes), otherwise it's shown as text.

**`links:false`** (comments written by new accounts): `[text](url)` and bare URLs are shown as text exactly as written (not parsed, so a `*` inside isn't treated as syntax either). CVE links work as usual.

**Not supported** (shown as text): `#` headings, images (`![x](u)` shows as `!` followed by an ordinary link), tables, HTML, footnotes, horizontal rules, Setext headings, indented code blocks, nested lists/quotes, link titles, reference-style links, `~~~` fences, strikethrough.

**Robustness**: it first applies the same character cleanup as §3.2 (control characters, bidi embedding/override/isolate characters, invisible characters, overlong runs of combining marks, too many empty lines, invalid UTF-8; `Clean` is idempotent), so none of those characters appear in the output, and it can go inside an element with `dir="auto"`. The output never contains 3 consecutive `<br>`. Running time is linear in the input length (a single pass; backtick-run pairing, URL end positions and the emphasis stack are all precomputed or amortized O(1)). Output length is ≤ `20 × input bytes + 64` (`md.MaxExpansion`), and there are at most 30 CVE links (each ≤ about 200 bytes), so the HTML of a 10000-character comment is at most about 200 KB (a flood of CVEs is now about 1 KB per 30 links plus text). A page also has a total budget of 512 KiB (§3.1). Tests: a table of syntax cases, an output allow-list validator (it parses each tag and attribute), linear-time checks on pathological input (100,000 backticks/`[`/`*`, unclosed fences, very long lines, NUL, bidi control characters, invalid UTF-8 …), three fuzz targets, and a 10 kB benchmark (about 125 µs on an M5 Max).

---

## 7. Logging

Every create, edit (when the body changed), delete, hide, unhide, report and report resolution writes one INFO line: `discuss: created|edited|deleted|hidden|unhidden|reported|report resolved`, with the internal user id, the comment id and the CVE (plus `reply`, `new_account`, `resolved_reports`, the report reason code, and so on). **The body, report note and hide reason are never logged.** Rate limiting: a `discuss: rate limited` WARN, at most one per minute, with a `suppressed` count. At startup: `discuss: discussions enabled terms_version=… pool=…`; if `NDAY_TERMS_VERSION` isn't set, there's an extra WARN.

---

## 8. Operations

- Migration `0005_discuss` (`nday migrate`) only adds tables. `0016_comment_purpose` adds a nullable `purpose` column and a `CHECK` to each of `comments` and `comment_revisions` (additions only; old rows are null).
- `nday discuss-hide <comment-id> --reason TEXT` / `nday discuss-unhide <comment-id>`: emergency handling when there's no web access. It first prints `comment: id=… cve=… author=<handle|-|(deleted account)> created=… status=… chars=… open_reports=…`, then runs. It only accepts a UUID (there's no "the handle changed owners" ambiguity, so `--yes` isn't needed). When hiding from the CLI, `hidden_by` is null.
- The moderator role: `nday auth-role <user-id|handle> moderator`.
- Hiding, unhiding (web and CLI) and resolving reports each write one audit record in the same transaction (`admin_audit`, see `docs/admin.md`). If the audit insert fails, the operation doesn't take effect. The admin moderation page `/admin/moderation` calls the endpoints in this document.
- To try it locally: `go run ./tools/authdev` (default terms version `dev-1`, and `-moderator ada` makes that user a moderator).

---

## 9. For people writing the pages

Everything the pages (`internal/webui`) and scripts need to do is here:

1. **Server-side rendering (the publicly cacheable vulnerability page)**: in `cmd/nday/main.go`, set `cli.DiscussHook = func(s *discuss.Service) { … }` the way `cli.AuthHook` is set, to get the service (it isn't called when discussions aren't enabled, and then the page shows no discussion area). The page uses **only** `s.Outline(ctx, cveID)` to draw the §4.1 outline (no body, author, id or time), `s.GuestRead()` to decide the text below the outline (the same for all visitors), and `s.Version(ctx, cveID)` as part of the cache key (any comment change, an author changing handle/display name/role, or an author deleting their account changes it; the format is `d2-…`, and you should treat it as an opaque string). The `Stream`/`StreamPage`/`StreamThread` functions that used to return bodies and authors have been removed: comment content only comes from `GET /api/discuss/{cve}` (for signed-in users, and for guests when guest reading is allowed). **Don't** put anything that depends on a cookie into a public page.
2. **The script fetches the content**: when signed in (`signed_in` from `GET /api/me`), or when the discussion area has `data-guest="1"` (signed in or not), request `GET /api/discuss/{cve}?locale=<page locale tag>` (`credentials: 'same-origin'`; if the address bar has `?c=<id>`, pass `c`), render the list from the returned comments (`body_nodes`, without parsing HTML), and attach buttons according to `can_*`, `reported`, `body` and `viewer` (guests get no buttons). If the response has an `outline` (guest reading was just turned off), keep the outline on the page. When a top-level comment has a `purpose`, show a purpose label after the author name (`disc.purpose`). The post box and the edit box (top-level comments only) have a purpose dropdown, and for "reproduction report" and "fix report" you set `disc.purpose_hint` as the input's placeholder.
3. **Write requests**:

   ```js
   async function post(path, body, csrf) {           // csrf = (await GET /api/me).csrf_token
     const r = await fetch(path, {method: 'POST', credentials: 'same-origin',
       headers: {'Content-Type': 'application/json', 'X-CSRF-Token': csrf},
       body: body === undefined ? undefined : JSON.stringify(body)});
     const j = await r.json();
     if (!r.ok) throw Object.assign(j.error, {retryAfter: r.headers.get('Retry-After')});
     return j;
   }
   post(`/api/discuss/${cve}`, {body, lang: pageLocale}, csrf)                 // post: 201 {ok, comment}
   post(`/api/discuss/${cve}`, {body, lang: pageLocale, parent_id: id}, csrf)  // reply
   post(`/api/discuss/comment/${id}/edit`, {body}, csrf)
   post(`/api/discuss/comment/${id}/delete`, undefined, csrf)
   post(`/api/discuss/comment/${id}/report`, {reason, note}, csrf)
   post(`/api/discuss/comment/${id}/hide`, {reason}, csrf)                     // moderator
   post(`/api/discuss/comment/${id}/unhide`, undefined, csrf)                  // moderator
   ```

   `lang` is the page's locale tag (the `tag` in the i18n registry, one of the enabled ones among `en`, `zh-Hans`, `zh-Hant`, `ja`, `ko`, `es`, `fr`). Scripts have to be external files (CSP forbids inline scripts); `connect-src 'self'` already covers these requests.
4. **State before posting** (`viewer.post_refusal`): `not_signed_in` → show the sign-in entry (the same as the account entry in the top bar); `handle_required` → send them to `/account` to set a handle; `terms_required` → show the rules and, once the user agrees, `POST /account/accept-terms {"version": viewer.terms_version}`, then retry; `suspended` → explain that the account is suspended (`/api/me` has `suspended_until`). The server's error code is still what counts: posting or editing may return `403 handle_required` or `403 terms_required` (`param` = the current version).
5. **Rendering rules**: insert `body_html` as HTML (`innerHTML`, or `template.HTML` in a template) inside a `dir="auto"` container. **Treat handles, display names, report notes, hide reasons and `body` as text, always** (`textContent`). When `role` is `moderator`/`admin`, show a staff badge. For comments with `links:false`, you can add a line like "links from new accounts aren't clickable". Show times in the visitor's time zone (like other times on the site). When `edited_at` isn't null, show "edited".
6. **Placeholders**: if `status` is `hidden` and there's no `body_html` → "Hidden by a moderator."; `deleted` → "Deleted by its author." Replies under a placeholder are shown as usual. When the author sees their own hidden comment, `moderation.hidden_reason` can be shown to them.
7. **Buttons**: show them only according to `can_edit`, `can_delete`, `can_report` (show "reported" when `reported` is true), `can_reply`, `can_hide`, `can_unhide`. Pre-fill the edit box from `body`. The list of report reasons: `spam` `abuse` `off_topic` `misinformation` `malicious_link` `illegal` `other`, with a note of ≤500 characters.
8. **Client-side validation**: the body, after trimming leading and trailing whitespace, is 1 to `limits.max_body_chars` (10000) characters (counted in code points; in JS use `[...s].length`). If it's over, the server returns `400 invalid_body`.
9. **Error code → text** (all of these need entries in the i18n catalog): `not_signed_in`, `cross_site`, `csrf` (fetch `/api/me` again and retry once), `suspended`, `handle_required`, `terms_required`, `forbidden`, `not_author`, `own_comment`, `wrong_status` (refresh the list), `not_found`, `bad_cve`, `bad_parent`, `thread_full`, `duplicate`, `invalid_body`, `bad_lang`, `bad_purpose`, `bad_reason`, `bad_note`, `bad_resolution`, `bad_cursor`, `bad_request`, `too_large`, `rate_limited` and `daily_limit` (use the `Retry-After` seconds to show "try again later"), `busy`, `wrong_host`, `internal`.
10. **Moderator pages** (if you build them): `GET /api/mod/reports?state=open`, `POST /api/mod/reports/{id}/resolve`, `GET /api/mod/recent`. These responses contain `body`; show it as text or via `body_html` as well.
11. **Don't** cache any `/api/discuss/*` or `/api/mod/*` response (the server already forces `no-store`), and don't put them in a Service Worker cache.

12. **Pagination, limits and rendering details the page has to handle**:
    - Every comment has `replies_truncated` (bool) and `replies_next_cursor` (string|null). When it's `true`, show "load more replies" at the end of that thread. On click, request `GET /api/discuss/{cve}?thread=<that thread's id>&cursor=<replies_next_cursor>&locale=…`, append the returned `comments[0].replies` to the thread, and update the button state from the returned `comments[0].replies_truncated`/`replies_next_cursor`. Don't use this response's `next_cursor` (it's always null). The same goes for server-rendered pages (without scripts, you can link to the API with `?thread=`, or just show "replies not fully shown").
    - A page may have fewer threads than the requested `limit` (because of the byte budget). Keep using whether `next_cursor` is null to decide if there's a next page.
    - `limits.max_page_bytes` (524288).
    - Body normalization is strict: a body with only invisible characters/combining marks gets `400 invalid_body` (an existing error code). The stored body may have fewer invisible characters, extra combining marks and extra blank lines than what the user typed (pre-fill the edit box with the returned `body`).
    - `delete` and `report` have per-user rate limits: `429 rate_limited` + `Retry-After` (an existing error code).
    - At most 30 CVE auto-links per comment.
    - Moderator pages: the endpoint `GET /api/mod/comment/{id}/revisions` (§3.9); `moderation.revisions` in the moderator view is the count; old bodies must be shown as text only.
    - The `Version` string has the format `d2-<count>-<md5>`; keep using it as an opaque cache key.

---

## 10. Known limitations

- In-process rate limits reset on restart and aren't shared between instances (same as sign-in). Daily limits are in the database and aren't affected.
- Replies to a hidden comment are still shown publicly. To hide them too, hide them one by one.
- Every call to `Version` does one index scan over all of a vulnerability's comments and computes a digest (using the read-only pool). For vulnerabilities with a huge number of comments, the page cache should use a TTL instead of computing it on every request.
- When a moderator resolves a report (`resolve`), `resolved_at` is still taken before the lock is acquired. It doesn't appear on public pages and doesn't affect `Version`.
- The Markdown subset is a simplified implementation and differs from CommonMark in corner cases (for example `*a **b c*` is all text), but the output always stays within the allow-list.
