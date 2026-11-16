# nday accounts and sign-in (backend)

Implementation: `internal/auth` (service, store, sessions, CSRF, rate limiting, handles, passkey endpoints), `internal/auth/jose` (ID token validation, JWKS cache, Apple ES256 client secret), `internal/auth/webauthn` (WebAuthn verification and a strict, minimal CBOR/COSE decoder), `internal/auth/fakeidp` and `internal/auth/webauthn/softauthn` (a fake identity provider and a software authenticator for tests), `migrations/0004_auth.sql`, `internal/cli/auth.go`. It uses only the standard library and pgx, which the repo already had.

The pages (`internal/webui`: the account entry in the top bar, `/login`, `/account`, the first-sign-in page `/welcome`; see `internal/webui/account.go` and `welcome.go`) don't read cookies and stay publicly cacheable. Browser scripts (the account entry in `static/app.js`, and `static/account.js`) learn the sign-in state from `GET /api/me`, then call the JSON endpoints below. To try it locally, use `tools/authdev`.

---

## 1. Design overview

- **Identity = (provider, subject).** That means the OIDC `sub` for Google/Apple, the numeric `id` for GitHub, `data.id` for X, and the credential id for passkeys. We never identify people by e-mail or username.
- **First sign-in** with an unknown identity creates a new nday user. **Linking** can only be started by a signed-in user (first `POST /auth/{p}/ticket` to get a one-time ticket, see §3.1). If the identity already belongs to another user, linking is refused (`?auth=conflict`). We never merge or take over accounts. Each user can have at most one identity per provider.
- **Signing in again while already signed in** (no ticket): you can only land on the **same account**, and the **original session stays exactly as it was** (same token, same `created_at`, result `?auth=ok`). Such a sign-in doesn't count as a "recent sign-in". If it would land on a different account, or create a new one, it's refused with `?auth=signed_in_as_other` and the session is untouched. To switch accounts, the page first gets a ticket with `intent=switch` (or signs out first). To refresh the session (recent sign-in), the page first gets a ticket with `intent=reauth`.
- **At least one usable sign-in method always remains.** After you unlink an identity or delete a passkey, at least one of the remaining methods must **work right now**: an identity from an enabled provider, or a passkey (when `NDAY_AUTH_PASSKEYS` is on). If nothing is left, you get `409 last_identity`. If all that's left is identities from disabled providers or passkeys while passkeys are turned off, you get `409 last_usable_method`.
- **Sessions.** A 256-bit random token lives in `__Host-nday_session` (`Secure; HttpOnly; SameSite=Lax; Path=/`). The cookie value is `base64url(token‖tag)`, where `tag` is the first 16 bytes of an HMAC with a derived key. A cookie with a wrong tag is treated as signed out without touching the database. A token hash that was looked up and found missing or expired goes into an in-process "dead token" cache (LRU, 50,000 entries, 10 minutes). After that, the same cookie takes no slot and causes no lookup. (A dead session never comes back: session rows are only inserted by `CreateSession` with a fresh random token, and `LoadSession` only updates `last_seen_at` after passing both expiry checks.) Each session token also has its own rate limit (burst 120, then 4 per second, independent of the client address, `429 rate_limited`), so replaying one cookie from many addresses only throttles that cookie. The database only stores SHA-256(token). Sessions expire after 14 days idle or 60 days absolute (configurable). Sign-in rotates the session (the old one is invalidated, so there's no session fixation). Sign-out, sign-out-everywhere and account deletion revoke sessions on the server. At most `max(1, NDAY_AUTH_DB_POOL_SIZE/2)` session lookups run at once (all database lookups for `/api/me` share one slot). If a lookup waits more than 2 seconds, you get `503 busy`. The remaining connections are kept for sign-in writes.
- **Recent sign-in (sensitive actions).** Registering a passkey, linking an identity and deleting the account require the session to have been created within `NDAY_AUTH_SENSITIVE_WINDOW` (default 15 minutes). Otherwise you get `403 reauth_required`. Only two things refresh a session: signing in with an `intent=reauth` ticket started from a page on this site (same account; the ticket request must be a same-origin POST with CSRF), or signing in with a passkey (same-origin POST with user verification). A sign-in without a ticket (including a top-level cross-site navigation from another site) that lands on the same account does not refresh the session. **This window proves that the user deliberately signed in again on a page of this site. It doesn't prove the identity provider asked for credentials again.** We don't send `prompt=login` or `max_age`, because neither the Google nor the Apple discovery document (checked 2026-11-13) lists `auth_time` in `claims_supported`, so we couldn't verify that the provider really re-authenticated. The window protects against someone who stole a cookie. It doesn't protect against scripts running in this site's origin (XSS, malicious extensions), which can fetch a reauth ticket themselves. Unlinking, deleting a passkey and signing out don't need a recent sign-in: they only reduce ways in, and the "at least one usable method" rule limits them. `session.recent_sign_in` / `recent_sign_in_until` in `/api/me` tell the page when to prompt for a fresh sign-in first.
- **Temporary sign-in flow data** (state, nonce, PKCE verifier, return path, link intent) is **sealed in a cookie**: AES-256-GCM (key derived from `NDAY_AUTH_SECRET` with HKDF-SHA256), stored in `__Host-nday_flow`, valid for 10 minutes. On callback, the state is compared first, then `SHA-256(state)` is inserted into `auth_flow_used` (a primary key conflict means replay, so it's refused). That makes it **single use**. The passkey challenge uses the same mechanism (`__Host-nday_webauthn`, 5 minutes, a single-use marker of `SHA-256("webauthn:"+challenge)`).
  - Why a cookie instead of plain database storage: `/start` is an anonymous endpoint, and a database-only design would let anyone write a row per request. The sealed-cookie design writes nothing at start. It's bound to the browser that started the flow (other browsers don't have the cookie), and the expiry is inside the ciphertext so it can't be tampered with. Single use is still enforced by the database marker, and writing that marker requires presenting a valid sealed cookie and a matching state. The cost: if you start two sign-in flows in the same browser, the second overwrites the first (the first one's callback gets `?auth=error`).
  - Key rotation: `NDAY_AUTH_SECRET` (current, used to encrypt and sign) plus `NDAY_AUTH_SECRET_PREVIOUS` (only used to decrypt and verify). The ciphertext carries an 8-byte key fingerprint.
- **CSRF.** Every state-changing endpoint is a POST and requires: (1) `Origin` equals the public origin (if sent) and `Sec-Fetch-Site` is `same-origin` (if sent), with at least one of the two present; (2) an `X-CSRF-Token` header equal to the session's CSRF token (`HMAC-SHA256(csrf key derived from the secret, "csrf:"‖session token hash)`, rotated with the session); (3) for endpoints with a body, `Content-Type: application/json` (cross-site forms can't send it, and cross-origin fetch triggers a preflight). OAuth callbacks are protected by state. The start endpoints for linking and switching accounts are GET navigations, so the page first calls the CSRF-protected `POST /auth/{p}/ticket` to get a **one-time ticket, valid for 2 minutes and bound to the session and provider**, then navigates to the returned `start_url`. A start with a ticket also rejects `Sec-Fetch-Site: cross-site/same-site`. The CSRF token itself never appears in a URL.
- **Open redirects.** The return path must match `^/[A-Za-z0-9._~\-/]*(\?([A-Za-z0-9._~\-=&+]|%[0-9A-Fa-f]{2})*)?$`, must not start with `//`, must have no `.`/`..` segments, must not be `/auth` or `/api`, and must not point under `/auth/`, `/account/` or `/api/`. (The account page `/account` itself is fine: it's where you land after linking or re-authenticating in the UI.) After decoding, the query string must contain no control characters or backslashes, and the whole path is at most 512 characters long. Anything that fails goes back to `/`.
- **Caching and privacy.** Only three route trees read cookies: `/auth/*`, `/account/*` and `/api/me`. The discussion endpoints `/api/discuss/*` and `/api/mod/*` also read them (public host only, also `no-store`, see `docs/discuss.md`), and so does the researcher post endpoint `GET /api/posts/{cve}` (public host only, response `private, no-store`, see the appendix of `docs/api.md`). All their responses get `Cache-Control: no-store`, forced when the response headers are written, together with `Vary: Cookie`. The three main route trees only accept requests whose `Host` equals the `NDAY_PUBLIC_URL` host (an explicit default port is ignored). Otherwise you get `421 wrong_host`. All other routes (HTML pages, data APIs such as `/api/hot`, `/raw/`, `/healthz`) never touch the session: they don't read cookies, send `Set-Cookie` or add `Vary: Cookie`, and the response is byte-for-byte the same with or without a cookie (there's a test for that). The server never writes user information into public pages.
- **Rate limiting.** Token buckets per client address. The address is `CF-Connecting-IP` (only if it parses as an IP), otherwise the socket address. IPv6 addresses share a bucket per /64. When the table is half full, bucketing switches to /48. It switches back only when the table is under 1/4 full **and** at least 10 minutes have passed (hysteresis, so flapping doesn't hand out a fresh burst each time). `CF-Connecting-IP` can only be trusted if the origin is reachable only through Cloudflare (zone-level Authenticated Origin Pulls plus a firewall, see `deploy/README.md`; at startup you get a warning if `NDAY_TLS_CLIENT_CA` isn't set). `/auth/{p}/start` and `/callback` each allow a burst of 10, then 1 every 6 seconds. The anonymous passkey endpoints allow a burst of 20, then 1 every 3 seconds. `/api/me` and all signed-in endpoints allow a burst of 300, then 5 per second. Passkey-only sign-up has an extra per-address limit of a burst of 3, then 1 per `NDAY_AUTH_PASSKEY_SIGNUP_INTERVAL` (default 1 hour), plus a site-wide cap of `NDAY_AUTH_PASSKEY_SIGNUP_DAILY` (default 200) per UTC day (`429 signup_limit`; only counted after the credential verifies). Going over the limit returns `429` with `Retry-After`. Each table holds at most 100,000 buckets. When it's full, the least recently used bucket is evicted (O(1), so a new client can always get a bucket). Expired buckets are cleaned up once a minute (only the tail of the LRU is scanned). Rate-limit warnings are logged at most once a minute, with the number of omitted warnings.
- **Logging.** In the access log, query values under `/auth/*` (`code`, `state`, `csrf` …) are always logged as `REDACTED` (only `return`, `intent` and `error` are kept). Auth logs only contain the provider, the result code, an internal reason code and the internal user id. They never contain client secrets, authorization codes, access/refresh/ID tokens, cookies, state, nonce, PKCE verifiers, challenges, or the error description text returned by the provider (a test scans the logs after a full flow).
- **HTTP to providers.** 10 s total timeout, no redirects followed, TLS 1.2+ with normal certificate verification, response body limit 1 MiB, JWKS limit 64 KiB, generic user agent `nday-auth/1.0`, no cookies, and only the parameters the protocol requires.

- **Display name is copied once.** A new user gets the provider's display name when the account is created at first sign-in. Later sign-ins don't update it (`Store.SignIn`, `internal/auth/store.go:190-191`; the existing-user branch only touches `handle`, `last_used_at` and `last_seen_at`).
- **Disabled providers.** If a provider is turned off, its `/auth/{p}/*` routes (including `unlink`) return 404 (`internal/auth/service.go:234-236`). A user whose only sign-in method is an identity from that provider can't sign in until it's enabled again.
- **Not implemented:** Apple server-to-server notifications, and calls to revoke GitHub or X tokens. Provider tokens are simply discarded after the sign-in.

### 1.1 Threat model

| Threat | What it protects | Mitigation |
|---|---|---|
| Login CSRF (an attacker hands the victim their own callback URL) | The victim's browser session | State is bound to a sealed cookie that only the browser that started the flow has. No cookie or no match → `?auth=error` (test: flow of another browser) |
| Authorization code interception / replay | The account | PKCE S256 (Google, GitHub, X); single-use state (`auth_flow_used`); codes expire at the provider (GitHub 10 minutes, X 30 seconds, Apple 5 minutes) |
| ID token forgery (`alg=none`, HS256 using the public key as the secret, swapped key, changed aud/iss, expired, replayed) | The account | Only RS256 is allowed (checked before fetching keys); the ≥2048-bit RSA public key is fetched from the JWKS by kid; `iss` must match exactly; `aud` must contain our client id; with multiple aud or an azp, azp must be our client; `exp`/`iat` allow 60 s of skew; `iat` must not be older than 10 minutes; `nonce` is compared in constant time |
| Provider confusion (mix-up) | The account | Each provider has its own callback URL; the provider inside the sealed data must match the callback path; if the callback carries an `iss` parameter (RFC 9207), it must be that provider's issuer |
| Account takeover (linking someone else's identity) | Other people's accounts | Linking can only be started from a signed-in session (plus CSRF). An identity that belongs to someone else → `conflict`. At callback time, the session must still be the one that started the link |
| Session fixation / stolen cookie | The session | Rotated at sign-in (except a same-account sign-in without a ticket from an already signed-in browser: the original session is unchanged and doesn't count as recent); `HttpOnly`, `Secure`, `__Host-` prefix (subdomains can't write it); sign-out, sign-out-everywhere and account deletion revoke on the server; only hashes are stored; an old stolen session can't add a passkey, link an identity or delete the account (recent sign-in requirement) |
| Cross-site navigation to start silently switching or creating an account | The user | A plain sign-in from an already signed-in browser can only land back on the same account, otherwise `?auth=signed_in_as_other`; switching needs a ticket |
| Flood of forged session cookies | The auth write pool | The cookie carries an HMAC tag, so forged ones never hit the database; session lookup concurrency is capped; `/api/me` is rate-limited per address |
| Another Cloudflare zone proxying this site | Rate limiting, login endpoints | Zone-level AOP (own certificate); auth routes check `Host` |
| CSRF on write operations | Account settings | Origin/Sec-Fetch-Site + session-bound CSRF token + JSON Content-Type |
| Open redirect | The user | Return path allow-list regex plus extra checks, falling back to `/` |
| Cache leaking personal data | The user | Auth responses are `no-store`; public pages don't read cookies or send Set-Cookie |
| Brute force / resource exhaustion | The service | Rate limits; all request bodies ≤ 4 KiB (passkey finish ≤ 64 KiB); CBOR input ≤ 16 KiB, depth ≤ 8, ≤ 512 items |
| Secrets in logs | Credentials | Query values redacted, only codes logged; log-scanning test |
| Cloned passkey | The account | A non-zero counter that doesn't increase → record `counter_regressions` and refuse |
| Passkey phishing / cross-site | The account | The browser scopes credentials to the RP ID; the server checks the `origin` allow-list, `rpIdHash`, `type`, `crossOrigin`, and that the challenge is single-use and bound to the browser |
| Impersonation after a username/handle is freed | Community identity | A released handle is held for 90 days (`namespaces.kind='held'`); only the previous owner can reclaim it during that time |

Out of scope: a compromised device or browser extension, theft of the provider account itself, and the network in front of Cloudflare (Cloudflare and Authenticated Origin Pulls are responsible for that. With Cloudflare's global shared certificate, AOP only proves "this came from the Cloudflare network", not "this came from nday's zone", so we recommend a zone-level certificate of your own, see `deploy/README.md`).

---

## 2. Stored data (migration `0004_auth.sql`; see that file for the exact schema)

| Table | Contents | Why |
|---|---|---|
| `users` | Random UUID `id`, `display_name` (≤64 characters, with control, bidi override and zero-width characters removed), `handle` + `handle_key` (public handle, chosen by the user), `handle_changed_at`, `locale`, `role`, `status`/`suspended_until`/`status_reason`, `terms_version`/`terms_accepted_at`, `webauthn_id` (32 random bytes, the WebAuthn user handle), `created_at`, `last_seen_at` | The account itself, plus the handle, role, suspension and terms the community features need |
| `namespaces` | Root-level name (lowercase), kind (`user`/`held`), hold period | Users and future organizations share one public namespace |
| `identities` | `provider`, `subject`, `user_id`, the provider-side handle (GitHub login / X username, display only), `linked_at`, `last_used_at` | Sign-in methods |
| `sessions` | `SHA-256(token)`, `user_id`, created / last active / absolute expiry times | Server-side, revocable sessions |
| `passkeys` | Internal id, `user_id`, `credential_id` (globally unique), SPKI public key, algorithm, signature counter, counter regression count, AAGUID, transports, BE/BS, user-chosen name, created / last used times | Passkeys |
| `auth_flow_used` | `SHA-256(state)` / `SHA-256("webauthn:"+challenge)` + expiry | Single-use markers |
| `suspended_identities` (migration `0022`) | `provider`, `HMAC-SHA256(provider, subject)` under a key derived from the server secret, `suspended_until`, `created_at` | Keeps a suspension in force after the suspended account is deleted (§2.1) |

**Not stored**: e-mail, avatar, access/refresh tokens, ID tokens, raw provider profiles, IP addresses, User-Agent. Even if GitHub's `/user` response includes an e-mail, it's discarded (test: no `@` appears in the database).

**Where the display name comes from**: for Google, the ID token's `name` (Google's docs say it "might (but is not guaranteed to)" appear with the profile scope; null if missing). For GitHub, `name`, falling back to `login` when it's null. For X, `data.name`. For Apple, null (see §5.2).

### 2.1 How other tables reference users (for future features)

- Type: `users.id uuid` (`auth.UserID` in Go, canonical text form).
- Foreign key convention: `author_id uuid REFERENCES users (id) ON DELETE SET NULL`. When an account is deleted, its content stays and the author becomes anonymous. Only `identities`, `sessions` and `passkeys`, which make up the account itself, use `ON DELETE CASCADE`. The test `TestDeleteAccount` creates such a table and checks that the content is still there after deletion, with `author_id` NULL.
- Account deletion: clear the handle and turn the name into `held` → `DELETE FROM users` (cascades to identities, sessions, passkeys).
- Deleting a suspended account: deletion is always allowed, but if the suspension is still in effect, each of the account's provider identities leaves one row in `suspended_identities` first, so deleting the account and signing in again isn't a way out of the suspension. The row holds only the provider, an HMAC-SHA256 of the provider and subject id under a key derived from the server secret (`"nday auth suspended identity v1"`, `internal/auth/crypto.go`), and when the suspension ends; no user id, handle, reason or raw subject is kept. It stays until that end (forever for an open-ended suspension) and housekeeping deletes it afterwards. While it is live, signing in with that identity creates a new account that is already suspended until the same time (the row is used up then, so lifting that suspension the usual way is enough), and linking the identity to another account is refused (`?auth=conflict`). This only covers the same provider identity: a suspended person can still make a new account with a different provider account or a passkey, and rows hashed under a server secret that has since been dropped from both `NDAY_AUTH_SECRET` and `NDAY_AUTH_SECRET_PREVIOUS` no longer match.

### 2.2 Public handles and namespaces (reserved for community/organizations)

- Rules: 3–30 ASCII letters, digits, `_` or `-`; the first character is a letter or digit. Unique case-insensitively; we store the display-case `handle` and the canonical lowercase `handle_key`. The reserved-name list is `ReservedNames` in `internal/auth/names.go` (the single source). Language-tag-style names shaped like `xx-yyyy` are also rejected (reserved for future locale prefixes such as `pt-br`). **When you add a top-level route, add its first path segment to `ReservedNames`** (`TestRoutesReservedAsHandles` in `internal/webui` builds the real server and fails for any registered first segment that is still free as a handle).
- Handles are never generated from the provider's username. You can set one at any time, and after that change it at most once every 30 days (changing only the case doesn't count).
- Mechanism: **a `namespaces` table plus a composite foreign key**. `namespaces(name PRIMARY KEY, kind)`, and `users(handle_key, handle_ns_kind='user')` references `namespaces(name, kind)`. Later, `organizations` can get the same `(name_key, ns_kind='org')` foreign key, with `'org'` added to the `kind` CHECK. No data has to move, a clash with existing user names is impossible (the same primary key guarantees uniqueness), and the database guarantees a user handle can only point at a `user`-kind name. The alternative (a unique index on each of users and organizations, with triggers cross-checking each other) risks races and gaps, so we don't use it.
- Release: after a rename or account deletion, the old name becomes `held` and is kept for `NDAY_AUTH_HANDLE_HOLD` (default 90 days). Nobody else can register it in that time, and the previous owner can reclaim it. The cleanup job deletes expired holds.

#### Reserved and look-alike handles (`internal/auth/names.go`)

Besides the exact entries in `ReservedNames` and the `xx-yyyy` locale-like shape, `IsReserved` also rejects handles that look like a reserved name or like the site or its staff. Comparisons use a **skeleton**: lowercase, `_` `-` `.` and spaces removed, `$`→`s` and `@`→`a`, and look-alike digits mapped to letters (`0→o 3→e 4→a 5→s 7→t 8→b`). A `1` is read both as `l` and as `i` (both skeletons are tried), and `rn` is also read as `m`. A handle is reserved when any of these holds:

1. Its skeleton (also after trimming leading and trailing separators) equals the skeleton of a `ReservedNames` entry (at least 2 characters). Examples: `adm1n`, `admin_`, `root_`.
2. After trimming leading and trailing digits and separators it is a protected word. This digit rule covers protected words only, so `kev1`, `me2`, `test123`, `apple1` and `es6` stay free.
3. Its skeleton is one protected word or a concatenation of protected words (`helpdesk`, `verified`, `support-team`, `nday-official`).
4. One of its parts, split on `_` `-` `.`, is a brand word or one of the role words in `tokenRoleWords` (`admin`, `admins`, `administrator`, `official`, `moderator`, `moderators`, `sysadmin`, `sysadm`, `helpdesk`, `verified`). `the_admin`, `real-admin` and `official-account` are refused. Everyday words (`team`, `root`, `security`, `system`, `support`, `staff`, `trust`, `safety`, `mod`) don't count as a part, so `red-team`, `root_cause`, `security-researcher`, `staff_engineer` and `monday_team` are fine.
5. Its skeleton starts with a brand word (`nday-news`), or ends with `admin`, `administrator`, `moderator` or `official` with at least two other characters before it (`iamadmin`, `webadmin`; `padmin` and `sadmin` stay free). There is no suffix rule for `staff`, `team`, `mod`, `root` or `trust` (`flagstaff`, `steam` and `mistrust` are fine).

Protected words (`brandWords` and `roleWords` in `names.go`): `nday`, `ndayland`, `admin`, `admins`, `administrator`, `official`, `support`, `security`, `moderator`, `moderators`, `mod`, `mods`, `staff`, `team`, `root`, `sysadmin`, `sysadm`, `system`, `abuse`, `verified`, `trust`, `safety`, `helpdesk`. Near-miss spellings like `admln` or `admiin` aren't covered. The lasting protection against impersonation is a staff badge the UI shows based on the role.

**Display names** are free text, and only impersonation of the site or its staff is refused (`DisplayNameImpersonates`). The name is NFKC-normalised first (full-width, mathematical and circled letters become ASCII). Then Cyrillic and Greek look-alike letters are mapped to Latin, in words that mix Latin with another script or that consist only of look-alikes (`Аdmin`, `nԁay`). Words written fully in Cyrillic or Greek (`Алексей`) are left alone. The name is refused when it:

- contains a CJK role word (`官方`, `管理员`, `管理員`, `站长`, `站長`, `客服`, `版主`, `运营`, `運營`, `工作人员`, `工作人員`, `公式`, `管理者`, `운영자`, `관리자`),
- has a word that starts with a brand word (`nday 官方`, `NDAY Support`, `ndaybot`), or
- has only protected words as its letters (`Admin`, `Support Team`).

`Team Rocket` and `Sunday Mod Fan` are allowed. When the provider supplies an impersonating display name, nday drops it and stores no display name (`SafeDisplayName`, used at `internal/auth/service.go:930` and `passkey.go:522`). A name typed in the passkey sign-up form gets `400 display_name_reserved` (`internal/auth/passkey.go:466-467`). The tests are `TestImpersonation` (`internal/auth/session_hardening_test.go:193`) and `TestImpersonationRules` (`internal/auth/hardening_test.go:637`).

### 2.3 Adding a separately verified contact e-mail later

The identity table has nothing to do with e-mail, so adding one doesn't touch identities. Create `user_contact_email(user_id uuid PRIMARY KEY REFERENCES users ON DELETE CASCADE, email text NOT NULL, verified_at timestamptz, verify_token_hash bytea, ...)`, and set `verified_at` after a verification mail. It would never take part in sign-in or account matching. This version stores no e-mail at all.

### 2.4 Roles, suspension, terms

- `role`: `user` < `moderator` < `admin`, default `user`. `nday auth-role <user-id|handle> <role>` can change any role. On the web, only admins can switch someone else between `user` and `moderator` (`POST /api/admin/users/{id}/role`, see `docs/admin.md`), and **no HTTP endpoint can create, change or revoke an admin**. Every role or suspension change (web and CLI) is written to the audit log `admin_audit` in the same transaction.
- `status`: `active`/`suspended` (`suspended_until` may be null, meaning indefinite; `status_reason`). Once it expires, the account counts as active, and the cleanup job sets it back. See `nday auth-suspend` / `nday auth-unsuspend`.
  - **Allowed while suspended**: signing in (any method), signing out, signing out everywhere, deleting the account, `GET /api/me`, accepting terms, setting the locale, renaming or deleting passkeys, and getting `switch` and `reauth` tickets (suspended users can sign in again).
  - **Refused while suspended (`403 suspended`)**: changing the handle, unlinking identities (a freed identity could sign up again as a new, active account), linking identities (getting a `link` ticket, a start with a ticket, and a re-check at callback time → `?auth=suspended`), and registering passkeys (both begin and finish). The rule is implemented in one place only, `need`/`guardFor`/`refusal` in `internal/auth/service.go`.
  - Future write features use `RequireActive` (also `403 suspended`).
- Terms: `NDAY_TERMS_VERSION` is the current version. First sign-in does **not** accept it automatically. `POST /account/accept-terms` only accepts the current version.

### 2.5 Go helpers for future features

```go
svc.Load(h)                       // auth.CurrentUser(r) may be nil
svc.RequireUser(h)                // 401 if signed out; for non-GET/HEAD/OPTIONS it also requires same-origin + X-CSRF-Token
svc.RequireActive(h)              // also rejects suspended users (use this for all write features)
svc.RequireRole("moderator")(h)   // RequireActive + minimum role
svc.PublicHost(r.Host)            // is Host the public origin host? (the same check the built-in routes use for 421 wrong_host)
```

When a request carries a session cookie (valid or not) or a user gets loaded, the final response is forced, at the moment the headers are written, to `Cache-Control: no-store` and `Vary: Cookie`, with `ETag`/`Last-Modified`/`Expires` and `CDN-Cache-Control`/`Cloudflare-CDN-Cache-Control`/`Surrogate-Control` removed. A handler that sets `public` itself gets overridden. The conditional request headers (`If-None-Match`/`If-Modified-Since`) are stripped, so a 304 is never returned. This also holds when a handler panics. Requests without a cookie default to `no-store`, and the handler can override that. Still, don't wrap these around a publicly cacheable page (signed-in visitors would lose caching). When `*auth.Service` is nil (the feature isn't enabled), these middlewares safely return 404 or treat the request as anonymous. `cli.AuthHook` receives the service instance when auth is enabled.

---

## 3. Endpoints

All responses carry `Cache-Control: no-store`. Error bodies look like the data API's: `{"error":{"status":403,"code":"csrf","message":"missing or invalid CSRF token","param":"X-CSRF-Token"}}`. Every route of a disabled provider returns 404. If there's no provider and passkeys are off, the whole feature registers no routes at all (`/api/me` is the data API's JSON 404, same as today).

### 3.1 Social sign-in

| Method and path | Description |
|---|---|
| `GET /auth/{google\|apple\|github\|x}/start?return=/path[&ticket=T]` | 302 to the provider; sets `__Host-nday_flow`. GET only (HEAD → 405) |
| `POST /auth/{provider}/ticket` | Session + CSRF; body `{"intent":"link"\|"switch"\|"reauth","return":"/path"}`; returns a one-time start URL (valid 2 minutes, bound to this session and provider) |
| `GET /auth/{provider}/callback` | 303 back to the return path with `auth=ok\|linked\|denied\|conflict\|error\|signed_in_as_other\|reauth_required\|suspended` appended; clears the flow cookie; on success sets the session cookie. **When a new account was created**, it's a 303 to the first-sign-in page instead (§3.4). GET only |

The `ticket` response: `{"ok":true,"signed_in":true,"intent":"link","start_url":"/auth/google/start?return=%2Faccount&ticket=…","expires_at":"2026-11-13T12:02:00Z"}`. The page calls `location.assign(start_url)` right away (it has to be a same-site top-level navigation). A `reauth` ticket: if the callback lands on the same account, a new session is issued (recent sign-in); if it lands on a different account, you get `?auth=signed_in_as_other`. It doesn't require a recent sign-in, and suspended users can use it. Errors: `link` needs the user not to be suspended (`403 suspended`) and to have signed in recently (`403 reauth_required`); `400 bad_request` (intent isn't link/switch/reauth). Ticket errors at start: `403 ticket_required` (`intent=link|switch|reauth` but no ticket), `403 ticket_invalid` (already used, expired, another session/browser, or another provider), `403 cross_site`. The old `intent=link&csrf=…` form no longer works.

```
GET /auth/github/start?return=/vuln/CVE-2026-1234
302 Location: https://github.com/login/oauth/authorize?client_id=…&code_challenge=…&code_challenge_method=S256&redirect_uri=https%3A%2F%2Fwww.nday.land%2Fauth%2Fgithub%2Fcallback&response_type=code&state=…
Set-Cookie: __Host-nday_flow=…; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Lax

GET /auth/github/callback?code=…&state=…
303 Location: /vuln/CVE-2026-1234?auth=ok
Set-Cookie: __Host-nday_flow=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax
Set-Cookie: __Host-nday_session=…; Path=/; Max-Age=5184000; HttpOnly; Secure; SameSite=Lax
```

Result codes: `ok` means sign-in succeeded. `linked` means linking succeeded (or the identity was already linked to you). `denied` means the user cancelled at the provider. `conflict` means the identity belongs to another account, or this account already has a different identity for that provider. `signed_in_as_other` means an already signed-in browser (without a switch ticket) went through the sign-in flow but the identity belongs to another account or has no account yet. Nothing was changed, and you're still on the original account (the page can say "You're signed in as X; sign out or choose switch account first to change"). `reauth_required` means the session was no longer inside the recent-sign-in window when linking finished. `suspended` means a suspended user tried to link. `error` covers everything else: no flow, state mismatch/replay/expiry, a missing `iss` when the provider declares RFC 9207 support (Google does: the discovery document fetched with curl on 2026-11-13 has `"authorization_response_iss_parameter_supported": true`; Apple has no such field, so it isn't enforced), token exchange failure, an invalid ID token, and so on. The reason is only in the server log.

### 3.2 Account JSON

`GET /api/me` (signed out):

```json
{"signed_in":false,"providers":["google","apple","github","x"],"passkeys":{"enabled":true,"signup":false,"max_per_user":20}}
```

(signed in):

```json
{"signed_in":true,
 "user":{"id":"0b8c6f0e-7f0e-4c1a-9a51-3c2f6f1d9e44","display_name":"Ada Lovelace","handle":"ada","handle_changeable_at":"2026-12-13T12:00:00Z",
   "locale":"zh-Hans","role":"user","status":"active","suspended_until":null,"status_reason":null,
   "terms":{"accepted_version":"2026-11-01","accepted_at":"2026-11-13T12:01:00Z","current_version":"2026-11-01","up_to_date":true},
   "identities":[{"provider":"github","handle":"ada","linked_at":"2026-11-13T12:00:00Z"}],
   "passkeys":[{"id":"5d1c…","name":"MacBook","created_at":"2026-11-13T12:05:00Z","last_used_at":null,"backed_up":true}],
   "follows":[{"term":"fortinet","label":"Fortinet"},{"term":"openssh","label":"OpenSSH"}],
   "created_at":"2026-11-13T12:00:00Z"},
 "session":{"created_at":"2026-11-13T12:00:00Z","recent_sign_in":true,"recent_sign_in_until":"2026-11-13T12:15:00Z"},
 "csrf_token":"q3J…43 characters…",
 "providers":["google","apple","github","x"],"passkeys":{"enabled":true,"signup":false,"max_per_user":20}}
```

When `session.recent_sign_in` is false (or the current time is past `recent_sign_in_until`), registering a passkey, linking and deleting the account return `403 reauth_required`. The page should first have the user sign in again, using an `intent=reauth` ticket for social sign-in (a plain start without a ticket doesn't refresh the session) or a passkey sign-in, and then retry.

POST endpoints (all require same-origin + `X-CSRF-Token`; those with a body require `Content-Type: application/json`):

| Endpoint | Request body | Success response | Main errors |
|---|---|---|---|
| `POST /auth/signout` | none | `{"ok":true,"signed_in":false}` | 403 `cross_site`/`csrf` |
| `POST /auth/signout-all` | none | `{"ok":true,"signed_in":false,"revoked_sessions":3}` | 401 |
| `POST /auth/{provider}/unlink` | none | `{"ok":true,"signed_in":true}` | 403 `suspended`, 404 `not_linked`, 409 `last_identity`/`last_usable_method` |
| `POST /auth/{provider}/ticket` | `{"intent":"link"\|"switch"\|"reauth","return":"/path"}` | see §3.1 | 403 `suspended`/`reauth_required` (link only), 400 |
| `POST /account/delete` | `{"confirm":true}` | `{"ok":true,"signed_in":false}` | 400, 403 `reauth_required` |
| `POST /account/locale` | `{"locale":"zh-Hans"}` or `{"locale":null}` | `{"ok":true,"signed_in":true}` | 400 |
| `POST /account/handle` | `{"handle":"Ada_1"}` | `{"ok":true,"signed_in":true,"handle":"Ada_1"}` | 400 `invalid_handle`, 403 `suspended`, 409 `handle_reserved`/`handle_taken`/`handle_change_too_soon` |
| `POST /account/accept-terms` | `{"version":"2026-11-01"}` | `{"ok":true,"signed_in":true}` | 409 `terms_version_mismatch`/`no_terms` |
| `POST /account/follows` | `{"terms":[{"label":"Fortinet"},{"label":"OpenSSH"}]}` (replaces the whole list; `[]` clears it; body ≤ 64 KiB, enough for 50 names of 200 four-byte characters) | `{"ok":true,"signed_in":true,"follows":[{"term":"fortinet","label":"Fortinet"},…]}` | 400 `invalid_follow`/`too_many_follows`/`bad_request` (missing `terms`), 403 `suspended` |
| `POST /account/follows/match` | `{"cve_ids":["CVE-2026-1001",…]}` (≤ 200, validated as CVE ids, lowercase accepted; body ≤ 16 KiB) | `{"matches":["CVE-2026-1001"]}` (canonical form, in request order, de-duplicated) | 400 `bad_request` (bad format or more than 200) |

`follows` (always present when signed in, possibly an empty array) is the list of vendor/product terms the user follows, in the order they were added. There's no separate `GET /account/follows`: everything under `/account/*` is POST, and the page reads `/api/me` every time anyway. The rules for following (matching, limits, validation) are in `docs/follows.md`. `follows/match` is read-only, but the list doesn't fit in a URL, so it's a POST with the same guards as the other endpoints (same-origin + CSRF; suspended users can use it). Changing `follows` requires the user not to be suspended.

Common errors: 401 `not_signed_in`, 403 `cross_site`, 403 `csrf`, 405, 415, 421 `wrong_host`, 429 `rate_limited` (per address, or a single session token used too often), 503 `busy` (session lookup queue timed out, with `Retry-After: 1`).

### 3.3 Passkeys (WebAuthn)

| Endpoint | Auth | Description |
|---|---|---|
| `POST /auth/passkey/register/begin` | Session + CSRF + not suspended + recent sign-in | Returns creation options; sets `__Host-nday_webauthn`; 409 `passkey_limit` when the user already has `max_per_user` |
| `POST /auth/passkey/register/finish` | Same | Body: `credential.toJSON()` + `"name"` |
| `POST /auth/passkey/login/begin` | Same-origin + rate limit | Username-less sign-in options (`allowCredentials: []`) |
| `POST /auth/passkey/login/finish` | Same-origin + rate limit | Body: `credential.toJSON()`, optionally `"switch": true`; on success sets a session (rotated). If the browser is signed in to **another** account, it's refused (409 `signed_in_as_other`; session and cookie unchanged, and nothing is written for the passkey's owner) unless the body has `"switch": true`. The same account → a new session (recent sign-in). No valid session → a normal sign-in |
| `POST /auth/passkey/signup/begin` | Same-origin + rate limit; exists only when `NDAY_AUTH_PASSKEY_SIGNUP=on` | Optional body `{"display_name":"…"}`; a display name that impersonates the site → 400 `display_name_reserved` |
| `POST /auth/passkey/signup/finish` | Same + the sign-up rate limit + the daily cap | Creates a passkey-only user and signs them in; 429 `rate_limited`/`signup_limit` |
| `POST /account/passkeys/{id}/rename` | Session + CSRF | `{"name":"YubiKey"}` |
| `POST /account/passkeys/{id}/delete` | Session + CSRF | 409 `last_identity` if it's the last sign-in method, 409 `last_usable_method` if none of the other methods work |

`register/begin` response:

```json
{"publicKey":{"rp":{"id":"nday.land","name":"nday"},
 "user":{"id":"<32 random bytes, base64url>","name":"ada","displayName":"Ada Lovelace"},
 "challenge":"<32 bytes, base64url>",
 "pubKeyCredParams":[{"type":"public-key","alg":-8},{"type":"public-key","alg":-7},{"type":"public-key","alg":-257}],
 "timeout":300000,"excludeCredentials":[{"type":"public-key","id":"…"}],
 "authenticatorSelection":{"residentKey":"required","requireResidentKey":true,"userVerification":"required"},
 "attestation":"none","hints":[]}}
```

`login/begin` response: `{"publicKey":{"challenge":"…","rpId":"nday.land","timeout":300000,"userVerification":"required","allowCredentials":[],"hints":[]}}`

`register/finish` response: `{"ok":true,"signed_in":true,"passkey":{"id":"5d1c…","name":"MacBook","backed_up":true}}`. `login/finish` and `signup/finish` return `{"ok":true,"signed_in":true}`.
Errors: 403 `suspended`, 403 `reauth_required`, 409 `passkey_limit` (registration), 400 `ceremony_invalid` (missing, expired, replayed or wrong-type challenge: start over), 400 `passkey_rejected` (`message` is a machine code: `origin`, `rp_id_hash`, `type`, `challenge`, `cross_origin`, `user_present`, `user_verified`, `backup_flags`, `signature`, `unknown_credential`, `user_handle`, `counter_regression`, `backup_eligibility_changed`, `attestation_format`, `unsupported_alg`, `cbor`, `cose_key_*`, `authdata_*`, `encoding` …), 409 `passkey_exists`, 409 `signed_in_as_other` (`login/finish`: signed in to another account and no `"switch": true`. The check runs after the assertion is verified but before the counter and `last_used_at` are updated, so a refusal only consumes the single-use challenge), 413 `too_large`.

#### What the page script has to send and receive (reference snippet)

This needs a browser that supports `PublicKeyCredential.parseCreationOptionsFromJSON` / `parseRequestOptionsFromJSON` / `toJSON()` (per MDN: Chrome/Edge 129, Firefox 119, Safari 18.4 and later; Baseline 2025-03-31). Older browsers need their own base64url ↔ ArrayBuffer conversion.

```js
// csrf comes from csrf_token in GET /api/me; all calls are same-origin fetches
async function post(path, body, csrf) {
  const r = await fetch(path, {method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json', ...(csrf ? {'X-CSRF-Token': csrf} : {})},
    body: body === undefined ? undefined : JSON.stringify(body)});
  const j = await r.json();
  if (!r.ok) throw j.error;            // {status, code, message}
  return j;
}
// add a passkey to the current account
async function addPasskey(csrf, name) {
  const {publicKey} = await post('/auth/passkey/register/begin', undefined, csrf);
  const cred = await navigator.credentials.create({publicKey: PublicKeyCredential.parseCreationOptionsFromJSON(publicKey)});
  return post('/auth/passkey/register/finish', {...cred.toJSON(), name}, csrf);
}
// link a social identity (intent "link"), switch to another account while signed in (intent "switch"),
// or sign in to the same account again for a sensitive action (intent "reauth")
async function startWithTicket(provider, intent, returnPath, csrf) {
  const {start_url} = await post(`/auth/${provider}/ticket`, {intent, return: returnPath}, csrf);
  location.assign(start_url);          // single use, valid for 2 minutes; look at ?auth=… when you come back
}
// check for a recent sign-in before a sensitive action (registering a passkey, linking, deleting the account)
async function needsReauth() {
  const me = await (await fetch('/api/me', {credentials: 'same-origin'})).json();
  return me.signed_in && (!me.session.recent_sign_in || Date.now() >= Date.parse(me.session.recent_sign_in_until));
  // true → have the user sign in again first: startWithTicket(provider, 'reauth', location.pathname, csrf)
  // or signInWithPasskey() (same account), then retry when you're back. A plain /auth/{p}/start doesn't refresh the session.
  // The server's own check, 403 reauth_required, is what counts
}
// username-less sign-in
// Using another account's passkey while signed in → 409 signed_in_as_other (no switch; to switch, add "switch": true to the finish body)
async function signInWithPasskey() {
  const {publicKey} = await post('/auth/passkey/login/begin');
  const cred = await navigator.credentials.get({publicKey: PublicKeyCredential.parseRequestOptionsFromJSON(publicKey)});
  await post('/auth/passkey/login/finish', cred.toJSON());   // then call GET /api/me again
}
```

The `finish` request body is the output of `toJSON()` (`id`, `rawId`, `type:"public-key"`, `response.clientDataJSON`, `response.attestationObject` or `authenticatorData`/`signature`/`userHandle`, `response.transports`; other members are ignored), and at registration you can add `"name"`. CSP: the existing `connect-src 'self'` already allows these fetches. No CSP directive governs WebAuthn (the spec only suggests, in §13.4.8, using CSP to restrict which scripts can run), so nothing needs loosening. The script has to be an external file (CSP forbids inline scripts). Every response carries `Permissions-Policy: publickey-credentials-create=(self), publickey-credentials-get=(self)`. That's the same as the spec's default allowlist `'self'`, written out explicitly so another policy can't override it later. Pages shouldn't call WebAuthn from inside an iframe: the server rejects `crossOrigin: true`/`topOrigin`.

### 3.4 First-sign-in page (`/welcome`)

- When `Store.SignIn` created a new account (`created`) during an OAuth callback, the callback doesn't go back to the return path. It sends a 303 to `auth.WelcomeReturn(return path)`:
  if the first segment of the return path is a language prefix (`auth.LocalePrefixes`; a test keeps it in sync with `internal/webui/i18n/locales.json`), the target is that language's
  `/<prefix>/welcome`, otherwise `/welcome`. If the return path isn't that language's home page, `?next=<escaped return path>` is appended. The result goes through the return-path rules again (§1), and
  `next` is left off if it would be too long. Any `auth=` parameter in the carried path is removed. If the return path is itself the welcome page (any language, with or without a trailing slash), it doesn't nest:
  it uses that page's own `next` instead (re-validated; if that's a welcome page again, no `next`). Examples: `/vuln/CVE-2026-1001` → `/welcome?next=%2Fvuln%2FCVE-2026-1001&auth=ok`,
  `/zh-hans/` → `/zh-hans/welcome?auth=ok`, `/welcome?next=%2Fvuln%2FX` → `/welcome?next=%2Fvuln%2FX&auth=ok`.
  Signing in to an existing account, linking and re-authenticating are unchanged.
- Passkey-only sign-up (`signup/finish` only returns JSON): the sign-in page's `data-welcome` is generated on the server with the same function, `auth.WelcomeReturn(the sign-in page's return path)`
  (with no return path, it uses the home page of the sign-in page's language), and `go()` in `account.js` navigates there, so both paths end up with the same language and `next`.
- The username field on the welcome page isn't pre-filled with the provider's username. If you leave it empty, no username is submitted (see `docs/follows.md` §3).
- The page is the same for every visitor (public cache, noindex). The server validates `next` against the return-path rules (it can't be the sign-in page or `/welcome` itself, in which case the language's home page is used),
  and both "Done" and "Skip all" go only to that address. The page script only calls `/api/me`, `POST /account/handle`, `POST /account/follows`,
  `POST /account/accept-terms` and the public `GET /api/affected/suggest`. Details are in `docs/follows.md` §3.
- `welcome` is in `ReservedNames`.

---

## 4. Passkey implementation notes

Based on W3C Web Authentication Level 3 (W3C Recommendation, 2026-08-25, https://www.w3.org/TR/webauthn-3/ , fetched 2026-11-13):

- Registration follows §7.1 steps 5–26 (`#sctn-registering-a-new-credential`): UTF-8 decode (strip the BOM) → JSON parse → "Verify that the value of C.type is webauthn.create." → challenge equals the base64url value → origin is in the `NDAY_AUTH_ORIGINS` allow-list → `crossOrigin` true or a `topOrigin` is always refused (nday isn't used in iframes) → CBOR-decode the attestationObject (only the three keys `fmt`/`attStmt`/`authData` are allowed) → "Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected by the Relying Party." → UP and UV must be set → "If the BE bit of the flags in authData is not set, verify that the BS bit is not set." → the algorithm must be in pubKeyCredParams → `fmt` must be `none` and `attStmt` an empty map (§8.7) → "Verify that the credentialId is ≤ 1023 bytes." → "Verify that the credentialId is not yet registered for any user." (`passkeys.credential_id` is globally UNIQUE).
- Assertion follows §7.2 (`#sctn-verifying-assertion`): the user isn't identified beforehand, so "verify that response.userHandle is present" applies, and it must equal the credential owner's `webauthn_id`. Then type `webauthn.get`, challenge, origin, crossOrigin, rpIdHash, UP, UV, BE/BS. In step 19, a BE that differs from registration → refuse. Step 21: the signature is "over the binary concatenation of authData and hash". Step 22, the counter: the spec says a value less than or equal to the stored one "is a signal, but not proof, that the authenticator may be cloned" and leaves it to the RP whether to fail. nday **records it (`counter_regressions`, `last_regression_at`) and refuses**. 0/0 (synced passkeys don't maintain a counter) is always accepted. Step 24 updates `sign_count`, `backed_up` and `last_used_at`.
- Signature formats (§6.5.5): ES256 "MUST be encoded as an ASN.1 DER Ecdsa-Sig-Value"; RS256 is RSASSA-PKCS1-v1_5 ("not ASN.1 wrapped"); EdDSA (Ed25519, `crypto/ed25519`) is a raw 64-byte signature (WebAuthn doesn't say so itself; this follows RFC 8032 and wasn't checked word for word). §5.8.5: "Keys with algorithm -7 (ES256) MUST specify 1 (P-256) as the crv parameter and MUST NOT use the compressed point form." EdDSA must use crv 6. RSA keys must be 2048–8192 bits.
- Options: `residentKey: "required"` (§5.4.6: if the client can't create a discoverable credential it "MUST return an error"), `userVerification: "required"` (the default is preferred, so we ask explicitly), `attestation: "none"`, `timeout` 300 s, and `excludeCredentials` lists existing credentials. `user.id` is 32 random bytes per user (§5.4.3: "The user handle MUST NOT contain personally identifying information", at most 64 bytes). `user.name` is the handle (else the display name, else "nday account"), and `displayName` is the display name.
- **How we get the public key: we parse the CBOR/COSE ourselves** (`internal/auth/webauthn/cbor.go`) instead of trusting the SPKI from the client's `getPublicKey()`. Reason: under the attestation "none" trust model, neither approach says anything about whether this is real hardware. But parsing the COSE public key out of authenticatorData guarantees that **the stored public key is the one carried by the same structure as the rpIdHash, flags and credentialId**, so a client can't attach an unrelated key in its JSON. It also relies only on the binary format the spec defines. The decoder supports only the types WebAuthn uses (integers, byte strings, UTF-8 text, arrays, maps with integer or text keys, true/false/null). It rejects indefinite lengths, tags, floats, extended simple values, non-shortest integer encodings (the CTAP2 canonical encoding in §2.4), duplicate keys, trailing bytes, input > 16 KiB, depth > 8 and more than 512 items. It does **not** enforce map key ordering (so slightly non-canonical clients still work; duplicate keys are rejected, so there's no ambiguity). The public key is stored as SPKI DER and read back with `x509.ParsePKIXPublicKey` at assertion time.
- Spec test vector: the L3 §16.2 "ES256 Credential with No Attestation" vector is used verbatim in `TestSpecVectorNoneES256`. That vector has the UV bit unset (flags 0x59/0x19), so the test checks that it passes with `RequireUV=false`, is refused under nday's policy (UV required), and fails if you flip one bit of the signature.

---

## 5. Providers (official docs fetched with curl on 2026-11-13)

### 5.1 Google (OpenID Connect)

- Endpoints (verbatim from the discovery document `https://accounts.google.com/.well-known/openid-configuration`): `"authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth"`, `"token_endpoint": "https://oauth2.googleapis.com/token"`, `"jwks_uri": "https://www.googleapis.com/oauth2/v3/certs"`, `"id_token_signing_alg_values_supported": ["RS256"]`, `"code_challenge_methods_supported": ["plain","S256"]`.
- Scope `openid profile`: "The scope parameter must begin with the openid value and then include the profile value, the email value, or both." (https://developers.google.com/identity/openid-connect/openid-connect ). We don't request `email`.
- `iss`: "Verify that the value of the iss claim in the ID token is equal to https://accounts.google.com or accounts.google.com." (same page). We accept both.
- Identifier: "Use sub within your application as the unique-identifier key for the user." (same page)
- Display name: the `name` claim has "Note that this claim is never guaranteed to be present." (same page). If it's missing, the display name is null (we don't make an extra userinfo call).
- nonce: the parameter table says "nonce (Required)"; nday always sends and verifies it.
- PKCE: discovery declares S256 support. The web-server docs don't mention PKCE for confidential clients (**not confirmed in the written docs**), but sending it is harmless, and the fake provider in the tests requires it.
- Key rotation: "These keys are regularly rotated; examine the Cache-Control header in the response to determine when you should retrieve them again." (https://developers.google.com/identity/gsi/web/guides/verify-google-id-token ). nday caches by max-age (clamped to 5 minutes–24 hours). An unknown kid triggers one immediate refetch (after that, no refetch for an unknown kid for 30 seconds). If a fetch fails, the cached old keys keep being used and there's no new fetch for 30 seconds (`RefetchInterval`). Fetching doesn't hold a lock, and concurrent calls share one fetch.
- Response mode: the default, query (GET callback).

### 5.2 Apple (Sign in with Apple, OpenID Connect)

- Endpoints (discovery `https://appleid.apple.com/.well-known/openid-configuration`): `"authorization_endpoint": "https://appleid.apple.com/auth/authorize"`, `"token_endpoint": "https://appleid.apple.com/auth/token"`, `"jwks_uri": "https://appleid.apple.com/auth/keys"`, `"id_token_signing_alg_values_supported": ["RS256"]`, `"token_endpoint_auth_methods_supported": ["client_secret_post"]`. There's no `code_challenge_methods_supported`.
- **We use response_mode `query` and request no scope.** The docs: "Valid values are `query`, `fragment`, and `form_post`. If you requested any scopes, the value must be `form_post`."; for scope, "You can request one, both, or none." (https://developer.apple.com/documentation/signinwithapplerestapi/request-an-authorization-to-the-sign-in-with-apple-server ). That makes the callback a top-level GET navigation, so the `SameSite=Lax` flow cookie is sent along and we don't need to accept a cross-site POST. (With form_post, the callback would be a cross-site POST started by appleid.apple.com, Lax cookies wouldn't be sent, and we'd have to loosen to `SameSite=None` and add separate CSRF protection.) The price: Apple doesn't give us the name: "the raw data is passed directly to your app from the browser and is not included in the user's identity token." (same page). The name only appears once, in the `user` parameter of the form_post on first authorization. So an Apple user's display name is null, and they can fill it in themselves once profile editing exists. We don't need the e-mail either (the ID token's email is ignored).
- PKCE: Apple's docs have no `code_challenge` parameter and discovery doesn't declare it, so we **don't send it** (support isn't confirmed). Protection comes from state + nonce + a client secret signed each time + a code valid for 5 minutes ("is valid for five minutes").
- nonce: "A unique, single-use string … This value is also used to prevent replay attacks"; nday always sends it and requires the same value in the ID token.
- Client secret (https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret ): `alg` ES256, `kid` is the 10-character Key ID, `iss` is the 10-character Team ID, `aud` "use `https://appleid.apple.com` as the audience.", `sub` "use the same App ID or Services ID that you use as the `client_id`", "It's an error to request an expiration time more than `15777000` seconds (six months) in the future". nday signs it in-process with the .p8 private key, valid for 1 hour and re-signed 5 minutes before it expires (JWS uses 64-byte r‖s).
- Validation: "Verify that the `iss` field contains `https://appleid.apple.com`", "Verify that the `aud` field is the developer's `client_id`" (https://developer.apple.com/documentation/signinwithapple/verifying-a-user ). That page also says "Verify the JWS E256 signature", which contradicts the RS256 in discovery/JWKS. nday follows discovery and the JWKS and only accepts RS256.
- Identifier: `sub` "serves as the primary identifier of the user"; it's stable within one Team (pairwise).
- Apple's `/auth/keys` response has the header `Cache-Control: no-store`. nday caches for 1 hour by default and relies on "refetch on an unknown kid" to handle rotation.

### 5.3 GitHub (OAuth 2.0, OAuth App)

- Endpoints: `GET https://github.com/login/oauth/authorize`, `POST https://github.com/login/oauth/access_token`. PKCE: "Must be `S256` - the `plain` code challenge method is not supported." (https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps ). The code "will expire after 10 minutes".
- Scope: not sent. "(no scope) | Grants read-only access to public information (including user profile info, repository info, and gists)" (https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/scopes-for-oauth-apps ).
- The token response needs `Accept: application/json` (same authorizing page: "For example, `Accept: application/json`"). Errors come back in a JSON `error` field (the docs don't describe the HTTP status code, so nday looks at the `error` field first).
- Who am I: `GET https://api.github.com/user`. `id` (int64) is the subject, `login` is the display handle, and `name` is the display name. "always use the `id` of the user. This value will never change for the user or be used to point to a different user" (https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/best-practices-for-creating-an-oauth-app ). After a rename, "your old username becomes available for anyone else to claim". A User-Agent is required: "Requests with no `User-Agent` header will be rejected."
- API version header: nday sends `X-GitHub-Api-Version: 2022-11-28` ("Requests without the `X-GitHub-Api-Version` header will default to use the `2022-11-28` version", supported until 2028-03-10; the newest is `2026-03-10`, so check for `/user` field changes before migrating).
- New OAuth Apps default to "Expire user access tokens" (8 hours + a refresh token). nday discards both the access and refresh tokens, so it isn't affected.
- GitHub recommends GitHub Apps ("In general, GitHub Apps are preferred over OAuth apps."). For "sign-in only", an OAuth App is simpler (no permissions or installation), and the endpoints are the same. This is an inference and is unverified.

### 5.4 X (OAuth 2.0 Authorization Code with PKCE)

- Endpoints: authorization is `https://x.com/i/oauth2/authorize`, and for the token "You can make a POST request to the following endpoint: https://api.x.com/2/oauth2/token" (https://docs.x.com/fundamentals/authentication/oauth-2-0/user-access-token ).
- PKCE: "We support authorization code with PKCE and refresh token as grant types for user authorization." (https://docs.x.com/fundamentals/authentication/oauth-2-0/authorization-code ). nday uses S256.
- Client authentication: "If you are working with confidential clients, you will need to use a basic authentication scheme …" (user-access-token page). nday uses HTTP Basic and doesn't put the client_id/secret in the form.
- Scope `users.read tweet.read` (the OpenAPI security requirement of GET /2/users/me, https://docs.x.com/x-api/users/get-my-user ).
- Who am I: `GET https://api.x.com/2/users/me` → `data.id` (a string, used as the subject), `data.username` (the display handle; "Usernames are unique but subject to change."), `data.name`.
- The authorization code "has a time limit of 30 seconds", so nday exchanges it as soon as the callback arrives.

### 5.5 Provider facts that may differ from older notes

- **X no longer has a free tier for new developers**: "The X API uses pay-per-usage pricing. No subscriptions—pay only for what you use.", "User: Read | $0.010 per resource" (https://docs.x.com/x-api/getting-started/pricing ). With no balance, "API requests will fail until you purchase more credits." Every X sign-in makes one `/2/users/me` call (we infer it's billed as User: Read, with the same resource de-duplicated within 24 hours UTC; the docs don't state this mapping, so it's unverified). The developer portal has moved to `console.x.com`.
- **A GitHub OAuth App can now have up to 10 callback URLs**, and callbacks created after 2026-08-03 default to exact matching (the older "only one callback, subdirectories match" no longer applies).
- Apple's docs about having to upload a domain verification file are out of date: "You don't need to upload a file on your server to complete the registration process for domains and subdomains." (https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/ ).
- WebAuthn Level 3 is a W3C Recommendation now (2026-08-25) and includes test vectors.

---

## 6. Configuration (environment variables)

The systemd unit additionally loads the optional file `/etc/nday/auth.env` (template `deploy/auth.env.example`). Everything is validated together at startup. Error messages name the variable and never echo its value, and any error makes `nday serve` exit (it never "half-enables").

In the table below, the provider IDs and secrets (including `NDAY_AUTH_APPLE_KEY`, but not `_FILE`), the passkey switches and limits, the session and sensitive-action durations, the handle hold period and `NDAY_TERMS_VERSION` can also be stored in the database by an admin at `/admin/settings` (database values win, secrets are stored encrypted, and saving takes effect on the running site). `NDAY_PUBLIC_URL`, `NDAY_AUTH_SECRET(_PREVIOUS)`, `NDAY_AUTH_RP_ID` and `NDAY_AUTH_ORIGINS` live only in the environment. If the database values make the sign-in configuration invalid, the site starts with the environment only and logs a warning. See `docs/settings.md`.

| Variable | Required | Description |
|---|---|---|
| `NDAY_PUBLIC_URL` | When enabled | The public origin, for example `https://www.nday.land` (origin only; https, with http://localhost allowed for development). An explicit default port (`:443`/`:80`) is stripped, and the same goes for `NDAY_AUTH_ORIGINS` |
| `NDAY_AUTH_SECRET` | When enabled | Base64 of ≥32 random bytes (`openssl rand -base64 48`; `openssl rand -hex 32` is accepted too). Obviously non-random values fail at startup: the placeholder from the docs, anything containing `changeme`/`change-me`, any exact repeating cycle with a period ≤ half the length, arithmetic sequences (checked on the text, on the base64 alphabet indexes, on the decoded bytes, and on the hex-decoded bytes), and fewer than 16 distinct decoded byte values. We checked for false positives with 200,000 random values per encoding (hex, base64, base64url, at 32 and 48 bytes): 0 were rejected |
| `NDAY_AUTH_SECRET_PREVIOUS` | No | The old secret during rotation (only used to decrypt in-flight cookies and verify CSRF) |
| `NDAY_AUTH_GOOGLE_CLIENT_ID` / `_CLIENT_SECRET` | As a pair | |
| `NDAY_AUTH_GITHUB_CLIENT_ID` / `_CLIENT_SECRET` | As a pair | |
| `NDAY_AUTH_X_CLIENT_ID` / `_CLIENT_SECRET` | As a pair | |
| `NDAY_AUTH_APPLE_SERVICES_ID`, `_TEAM_ID`, `_KEY_ID`, `_KEY_FILE` | All four together | `_KEY_FILE` is the path to the .p8 file (read at startup and validated as P-256 PKCS#8) |
| `NDAY_AUTH_PASSKEYS` | No | `on`/`off`; defaults to `on` when any provider is set. `on` with no provider means passkey-only |
| `NDAY_AUTH_PASSKEY_SIGNUP` | No | Default `off`: registering new accounts with only a passkey |
| `NDAY_AUTH_RP_ID` | No | Default: the public origin's hostname without `www.` (`www.nday.land` → `nday.land`). It must equal the origin host or a parent domain of it |
| `NDAY_AUTH_ORIGINS` | No | Comma-separated allowed WebAuthn origins; by default only `NDAY_PUBLIC_URL`. If the apex doesn't redirect to www, add `https://nday.land` |
| `NDAY_TERMS_VERSION` | No | The current terms version (`[A-Za-z0-9._-]{1,64}`) |
| `NDAY_AUTH_SESSION_IDLE` / `_MAX` | No | Default `14d` / `60d` (values like `12h` and `30d` are accepted) |
| `NDAY_AUTH_HANDLE_HOLD` | No | How long a released handle is held, default `90d` |
| `NDAY_AUTH_DB_POOL_SIZE` | No | Size of the writable pool dedicated to auth, default 4 (the site's read-only pool is unchanged); at most half of it is used for session lookups |
| `NDAY_AUTH_SENSITIVE_WINDOW` | No | The "recent sign-in" window required for sensitive actions, default `15m` (1m–24h) |
| `NDAY_AUTH_MAX_PASSKEYS` | No | Passkeys allowed per account, default 20 (1–100) |
| `NDAY_AUTH_PASSKEY_SIGNUP_DAILY` | No | Site-wide cap on passkey-only sign-ups per UTC day, default 200 (counted in-process, reset on restart) |
| `NDAY_AUTH_PASSKEY_SIGNUP_INTERVAL` | No | Per-address rate for passkey-only sign-ups: a burst of 3, then one per interval, default `1h` |

If only some variables of a provider are set, startup fails (for example: `auth: provider github is partly configured: NDAY_AUTH_GITHUB_CLIENT_ID set but NDAY_AUTH_GITHUB_CLIENT_SECRET missing (set all or none)`). If none are set, the feature stays dormant and the site behaves exactly as it does without it.

**Canonical host**: cookies carry the `__Host-` prefix and belong only to the host that issued them. The apex `nday.land` must 301 to `https://www.nday.land` on Cloudflare. Otherwise you won't see the sign-in state on the apex, and the Origin check on POST will reject the apex.

**Other hosts (the whole site, not just the sign-in routes)**: anyone can point their own domain through Cloudflare at this origin's IP and get a mirror of the whole site. So when `NDAY_PUBLIC_URL` is set (`internal/web/foreign.go`), requests whose `Host` (case-insensitive, default port ignored) isn't one of the following four are no longer passed to the site: the public host; its bare domain (when the public host is `www.X`, that's `X`, which still gets a 308 to the public host for GET/HEAD as described in the previous paragraph); the API host (API routes only); loopback names (`localhost`, `*.localhost`, loopback IP literals such as `127.0.0.1` and `[::1]`, on any port). For any other host, GET/HEAD gets a `308` to the same path and query on the public origin (built the same way as the apex redirect, but with `Cache-Control: no-store`, so it isn't cached anywhere), and other methods get `421 wrong_host` (JSON, `Cache-Control: no-store`). When `NDAY_PUBLIC_URL` isn't set (local development), this check is skipped. Loopback names keep working so that checks on the machine itself (`curl http://127.0.0.1:8080/healthz`) don't need a `Host` header. A limitation: if the other party's proxy rewrites the `Host` header to the public host, the application can't tell the difference. That's what the origin's client certificate (`NDAY_TLS_CLIENT_CA`, containing only your own zone's certificate) is for.

**Cloudflare**: don't set "Cache Everything" or an Edge TTL override on `/auth/*`, `/account/*` or `/api/me` (they're all `no-store`, and Cloudflare doesn't cache them under the default rules).

### 6.1 Operations commands

- `nday auth-gc`: deletes expired/idle sessions, expired single-use markers, expired handle holds and `suspended_identities` rows whose suspension has ended, and lifts suspensions that have run out (the server process also runs it automatically every 15 minutes). For the idle timeout `NDAY_AUTH_SESSION_IDLE`, the value in the database wins; if that value is invalid, it logs a warning and uses the environment only.
- `nday auth-role <user-id|handle> <user|moderator|admin> [--yes]`
- `nday auth-suspend <user-id|handle> [--until RFC3339 | --for 7d] [--reason TEXT] [--yes]`, `nday auth-unsuspend <user-id|handle> [--yes]`
- These three commands first print the resolved user (`user: id=… handle=… created=… last_seen=… role=… status=…`). When you specify the user by handle, you must add `--yes` (the handle may have changed owners), otherwise nothing is changed and the command exits with 1. A UUID doesn't need it.

---

## 7. Setting up the providers (for anyone self-hosting)

Every callback URL is `https://<public host>/auth/<provider>/callback`. The examples below use `https://www.nday.land`; substitute your own public host.

In general: generate `NDAY_AUTH_SECRET` (`openssl rand -base64 48`), put it in `/etc/nday/auth.env` (`root:nday`, mode 0640), set `NDAY_PUBLIC_URL=https://www.nday.land`, run `nday migrate`, and restart `nday-web`.

### 7.1 Google (free; cost: **the official docs have no explicit wording saying "free"**; with only non-sensitive scopes, no review is needed)

1. Open the Google Auth Platform in the Google Cloud console and follow the prompts to create a project and register the app: "click on the "GET STARTED" button on the overview page of the Google Auth Platform" (https://support.google.com/cloud/answer/15544987 ). Fill in the app name and user support e-mail, choose **External** for Audience, and add contact information.
2. On the Branding page, add the authorized domain `nday.land`: "Add your Authorized Domains before you add your redirect or origin URIs" (https://support.google.com/cloud/answer/10311615 ).
3. On the Data Access page, keep only `openid` and `.../auth/userinfo.profile` ("On the Data Access page, you can manage OAuth scopes."). With only non-sensitive scopes, "it is not mandatory for your app to complete the app verification process" (https://support.google.com/cloud/answer/13463073 ). Without brand verification, the consent screen only shows the domain. An app in Testing status that requests only name/profile/openid isn't subject to the 100 test-user limit (https://support.google.com/cloud/answer/15549945 ), but we recommend publishing it to Production.
4. Clients → Create Client → **Web application**: "Go to the Clients page. Click Create Client. Select the Web application application type." (https://developers.google.com/identity/protocols/oauth2/web-server#creatingcred ). Put `https://www.nday.land/auth/google/callback` in Authorized redirect URIs ("must exactly match … scheme, case, and trailing slash").
5. Copy the Client ID into `NDAY_AUTH_GOOGLE_CLIENT_ID` and the Client secret into `NDAY_AUTH_GOOGLE_CLIENT_SECRET`: "Your application's client secret will only be shown after you create the client … it will not be visible or accessible again." (https://support.google.com/cloud/answer/15549257 ). Changes take "5 minutes to a few hours" to apply.

### 7.2 Apple (needs the paid Apple Developer Program: "99 USD per membership year", https://developer.apple.com/programs/enroll/ )

1. Join the Apple Developer Program (a free account has no Certificates, Identifiers & Profiles). You need the Account Holder or Admin role.
2. Identifiers → App IDs: register a primary App ID with **Sign in with Apple** checked (https://developer.apple.com/help/account/identifiers/register-an-app-id/ ; "enable the App ID as a primary", https://developer.apple.com/help/account/capabilities/about-sign-in-with-apple/ ). Note: older docs say you need "an existing app in the App Store", while the help center only asks for a primary App ID with that capability enabled. **Unconfirmed**: whether a published app is really required.
3. Identifiers → **Services IDs** → create one (for example `land.nday.web`) → check Sign in with Apple → Configure: "Under Website URLs, provide your domains, subdomains, or return URLs … You must provide at least one domain or subdomain." (https://developer.apple.com/help/account/capabilities/configure-sign-in-with-apple-for-the-web/ ). Put `www.nday.land` under Domains and `https://www.nday.land/auth/apple/callback` under Return URLs (it must be https, and can't be an IP or localhost, so you can't test Apple locally). You don't need to upload a verification file. The Services ID goes into `NDAY_AUTH_APPLE_SERVICES_ID`.
4. Keys → create a private key with Sign in with Apple enabled, tied to the primary App ID above (https://developer.apple.com/help/account/capabilities/create-a-sign-in-with-apple-private-key/ ). Download the `.p8`: "you won't be able to download it again." (https://developer.apple.com/help/account/keys/create-a-private-key/ ). Put it at `/etc/nday/apple/AuthKey_XXXXXXXXXX.p8` (`root:nday` 0640), and put the path in `NDAY_AUTH_APPLE_KEY_FILE`.
5. The Key ID ("The key identifier appears below the key name.") goes into `NDAY_AUTH_APPLE_KEY_ID`. The Team ID (on the Membership page of the developer account, 10 characters; **no verbatim text found in an official help page**) goes into `NDAY_AUTH_APPLE_TEAM_ID`.
6. Optional: server-to-server notifications (consent-revoked, account-deleted). Not implemented in this version.

### 7.3 GitHub (free; no official sentence stating a price was found; up to 100 OAuth Apps per account)

1. Settings → Developer settings → OAuth apps → **New OAuth App** (https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app ).
2. Application name `nday`, Homepage URL `https://www.nday.land`, Authorization callback URL `https://www.nday.land/auth/github/callback` (don't turn on wildcard matching: "When wildcard matching is disabled, the redirect URL must exactly match the callback URL."). Leave Device Flow off. Leaving "Expire user access tokens" at its default is fine.
3. Register application → copy the Client ID into `NDAY_AUTH_GITHUB_CLIENT_ID`; generate a client secret and put it in `NDAY_AUTH_GITHUB_CLIENT_SECRET` (the button's name isn't confirmed in the docs).

### 7.4 X (pay per use; you need to buy credits)

1. Sign in at `console.x.com`: "Visit console.x.com and sign in with your X account.", accept the developer agreement, and create a New App (https://docs.x.com/x-api/getting-started/getting-access ).
2. Buy credits: "The X API uses pay-per-usage pricing."; "User: Read | $0.010 per resource" (https://docs.x.com/x-api/getting-started/pricing ). With no credits, "API requests will fail until you purchase more credits." (https://docs.x.com/x-api/fundamentals/post-cap ). For commercial use: "free tier is non-commercial only" (https://docs.x.com/developer-guidelines ).
3. User authentication settings: App permissions **Read**; Type of App **Web App** ("Web App and Automated App or bots are confidential clients."); Callback URI `https://www.nday.land/auth/x/callback` ("you will need to have exact match validation for your callback URL."); Website URL `https://www.nday.land`. (The console's exact field names only show up in the Ads/MCP guides, so they're **not confirmed in the core docs**.)
4. Copy the **OAuth 2.0** Client ID into `NDAY_AUTH_X_CLIENT_ID` and the Client Secret into `NDAY_AUTH_X_CLIENT_SECRET` ("Credentials are only displayed once."). Don't use the OAuth 1.0a API Key/Secret.

### 7.5 Passkeys (no third-party cost)

- Confirm `NDAY_AUTH_RP_ID=nday.land` (that's the default). **Once anyone has registered a passkey, you can't change the RP ID** (credentials are bound to it).
- If the apex also serves pages directly (no redirect), set `NDAY_AUTH_ORIGINS=https://www.nday.land,https://nday.land`.
- Decide on `NDAY_AUTH_PASSKEY_SIGNUP` (default off). When it's on, people can sign up without any third-party account. It costs nothing and is easy to mass-register through, so we suggest watching things for a while before turning it on.
