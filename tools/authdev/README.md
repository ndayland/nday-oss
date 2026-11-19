# authdev — try the sign-in UI locally

Development only. Runs the real site (`internal/web` + `internal/webui`) and the
real sign-in service (`internal/auth`) in one process on
`http://localhost:8090`, with the fake identity provider of
`internal/auth/fakeidp` standing in for Google, Apple, GitHub and X. Never
linked into `cmd/nday`; binds loopback only and refuses a non-loopback
`-listen`, an https or non-loopback `-public-url`, and a non-local database.

```sh
docker compose up -d db
export NDAY_DATABASE_URL=postgresql://nday:nday@127.0.0.1:54329/nday
go run ./cmd/nday migrate            # once: needs migrations/0004_auth.sql and 0005_discuss.sql
go run ./tools/authdev               # then open http://localhost:8090/login
```

- The fake providers approve every sign-in at once as the current **persona**
  (`ada`, `bob`, `mallory`; `deny` cancels at the provider). Start with
  `-persona bob`, or switch at `http://127.0.0.1:8091/?as=bob` (also accepted
  as `?as=` on the authorize page). Two personas = two accounts (conflict,
  "signed in as other").
- `-sensitive-window 30s` shortens the recent-sign-in window
  (`NDAY_AUTH_SENSITIVE_WINDOW`, default 15m) to try the "confirm it's you"
  panel without waiting.
- `-providers github,x` (empty = passkeys only), `-passkeys=false`,
  `-signup=false`, `-terms 2026-11-01` change the configuration. The terms
  version defaults to `dev-1` (posting a comment needs it accepted on the
  account page, which calls `POST /account/accept-terms`); `-terms ""`
  publishes none.
- Discussions (`docs/discuss.md`) are on: `GET/POST /api/discuss/{cve}` and
  the moderator endpoints. Run `go run ./cmd/nday migrate` once more for
  `migrations/0005_discuss.sql`. `-moderator ada` (comma-separated personas)
  makes those personas' accounts moderators as soon as they exist (checked
  every 2 s; passkey-only accounts are not covered — use
  `go run ./cmd/nday auth-role <handle> moderator --yes`). A new account's
  links render as plain text for its first 24 hours / 3 comments.
- Passkeys use RP ID `localhost`; they need a browser with an authenticator.
- The auth secret is random per start: restarting signs everyone out.
- Suspend an account to see that state:
  `go run ./cmd/nday auth-suspend <handle> --for 1d --yes`.
- Back office (`docs/admin.md`): `http://localhost:8090/admin`. `-admin ada`
  (comma-separated personas) makes those accounts administrators as soon as
  they exist, like `-moderator` (a direct, unaudited UPDATE: development
  only; on a server use `nday auth-role <handle> admin --yes`). Run
  `go run ./cmd/nday migrate` once more for `migrations/0007_admin.sql`.
- Database settings (`docs/settings.md`): `http://localhost:8090/admin/settings`
  saves for real through the runtime of `nday serve` (`cli.NewSettingsRuntime`),
  so a saved value is validated, stored in the local database, audited and
  applied (sign-in, discussion limits) at once. Its "environment" is the
  sign-in configuration built from the flags (shown as source "environment";
  `-sensitive-window` below 1m is written as 1m there), over the shell's
  environment for every other key. Settings already stored are applied at
  start-up when they are valid together with the flags (otherwise a warning,
  and the flags alone apply). Secrets are sealed with `NDAY_SETTINGS_KEY`
  when it is set, else with a random master key that lives only as long as
  the process (logged at start-up; such secrets cannot be read after a
  restart: the page then says "stored, cannot be decrypted" and they can be
  cleared). The X user lookup of `/admin/x` stays as `-x-lookup` set it:
  storing `NDAY_X_BEARER_TOKEN` here never makes authdev call the X API.
  Changing a provider's client id or secret makes that fake provider refuse
  sign-in until it is cleared again. Needs `migrations/0014_settings.sql`
  (`go run ./cmd/nday migrate`); without the table the page says the
  settings are unavailable.
- `-stats-sample /abs/scratch/dir` writes ten days of sample access logs
  (one day left out, so the charts show a gap; today partial) and an error
  log for today into that directory, rolls them up into the local database
  (`internal/stats`, like `nday stats-rollup --dir DIR --all`) and shows the
  directory's error log on `/admin/system`. Without it the system page reads
  `NDAY_LOG_DIR` when set. The sample countries are weighted into a heavy
  tail for the visitor map on `/admin` and include marker-only territories
  (SG, HK, MO) and codes the map cannot place (T1, XX).
- `-x-sample` inserts sample data for `/admin/x` into the local database:
  three allow-listed accounts (one disabled) and settings through
  `internal/xconfig`, a `collector_state` row for `xposts` whose cursor
  reports a run that stopped early, and six `social_post` events. It never
  calls the X API and needs no token. Run `go run ./cmd/nday migrate` once
  more for `migrations/0008_xposts.sql`.
  It also adds researcher posts for the vulnerability pages, the `@N`
  badges of `/hot` and `/discussed` (`docs/xposts.md`): five more accounts
  (`dana_vr`, `eve_poc`, `frank_dfir`, `grace_kev`; `heidi_old` disabled,
  so its posts neither count nor show) posting about the five CVEs with the
  most recent transitions in the local database and two stub CVEs
  (`CVE-2026-990001`, `CVE-2026-990002`), from 5 authors down to 1. Each run
  moves these posts back into the last ~15 hours, so the 7-day window does
  not empty. To compare the views: open `/discussed`, pick a CVE, and look
  at its "researcher discussion" and "discussion" sections signed out
  (speckle placeholders, a sign-in button; `GET /api/posts/CVE-…` returns
  only `outline`), then sign in (`/login`, any persona) and reload (the
  posts and comments appear; the same API call returns `posts`).
  Every other of these posts ends with a resolved `https://t.co/smpl…`
  link (`x_post_link`; a patch, an Exploit-DB, an advisory or a blog URL),
  so the "resources" section shows on those pages for everyone and the
  signed-in post text shows the real link (needs
  `migrations/0019_xposts_links_candidates.sql`; existing sample posts keep
  their old text, new databases get the link in the text too).
  Two GitHub repository links with fetched metadata are added too
  (`github_repo`, needs `migrations/0023_github_repo.sql`; `docs/github.md`):
  on `CVE-2024-3094` one repository with the CVE in its name, listed under
  PoC, and on `CVE-2025-1974` one without, listed under code repositories.
  Four repositories "found by search" for `CVE-2024-3094` (needs
  `migrations/0025_github_discovery.sql`): one unverified (listed under PoC
  with the "unverified" mark), one trusted by an admin, one rejected and one
  unverified fork (both not listed); a re-run keeps review decisions.
  Four allowlist candidates show in the candidates section of `/admin/x`
  (`ivan_re`, `judy_bugs`, one without a handle that cannot be added, and
  `mallory_x` already dismissed); existing candidate rows are left as they
  are, so adding or dismissing one survives a re-run.
- Adding an X account by handle on `/admin/x` (the server looks up the
  numeric user id) answers from an in-process fake of the X API user lookup
  (`internal/xlookup/xfake`): no token, no network; the requests never leave
  the process. It is on by default (`-x-lookup fake`); `-x-lookup off`
  shows the page as a server without `NDAY_X_BEARER_TOKEN` (the id field is
  then required). Only code can point the lookup elsewhere: `nday serve`
  always uses `https://api.x.com`. Trial handles (any case; with
  `-x-sample` the ids 1001–1003 are already listed):

  | handle | fake answer | what the page does |
  |---|---|---|
  | `nday_demo` | id `1700000000000000001`, spelled `Nday_Demo` | adds `@Nday_Demo` |
  | `cve_watcher` | id `1700000000000000002`, spelled `CVE_Watcher` | adds `@CVE_Watcher` |
  | `alice_sec` | id `1001`, spelled `Alice_Sec` | `-x-sample` lists 1001 as `alice_sec`: the handle is updated to the new spelling ("renamed") |
  | `carol_new` | id `1003` | `-x-sample` lists 1003 as `carol_ir`: renamed to `carol_new` |
  | `bob_sec` | id `1002` | already listed under that handle: "already listed" (409) |
  | `suspended_acct` | suspended | "suspended or unavailable", nothing added |
  | `ratelimited` | HTTP 429 | "rate limit reached", nothing added |
  | anything else | not found | "no X account has this handle" |

  Bulk import takes the same handles as `@handle  # note` lines; preview
  shows the id found for each.
- First-sign-in page and follows (`docs/follows.md`): run `go run ./cmd/nday migrate`
  once more for `migrations/0010_follows.sql`. A persona's first sign-in creates
  its account and lands on `http://localhost:8090/welcome` (the handle field
  stays empty; a button below it offers the persona name, e.g. `ada`). Every persona and provider
  pair is its own identity, so to land there again as a new user sign in with
  a pair not used yet (another provider button, or `?as=bob`), or delete the
  account on `/account` first. `/welcome` can also be opened directly while
  signed in (the page works for any account).
