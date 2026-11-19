# Deployment guide

Target environment: Ubuntu 24.04 and PostgreSQL 16 (the distro package). The backend is one statically linked Go binary with the schema migrations embedded, so the host doesn't need Go installed.

## Layout on the host

| Path | Contents |
|---|---|
| `/opt/nday/bin/nday` | The Go binary (owned by root, 0755) |
| `/etc/nday/nday.env` | Environment variables, `root:nday` 0640 (includes the master key `NDAY_SETTINGS_KEY` for database-stored settings, see "Settings stored in the database") |
| `/etc/nday/web.env` | Variables for `nday-web.service` only (listen address, TLS, `NDAY_PUBLIC_URL`, `NDAY_API_URL`, `NDAY_LOG_DIR`), `root:nday` 0640 |
| `/data/log/nday/` | The site's access and error logs (`NDAY_LOG_DIR`), `nday:nday` 0750, one file per day, never deleted automatically |
| `/etc/systemd/system/nday-collect@.service` / `.timer` | Copies of the two files in `systemd/` next to this README |

- The services run as the system user `nday` (no login shell).
- The database connection uses peer authentication over the local unix socket, so there's no password:
  `NDAY_DATABASE_URL=postgresql:///nday?host=/var/run/postgresql`
- The production database is `nday`, owned by the role `nday`. PostgreSQL listens on 127.0.0.1 only.

## Build

Run this from the project root on your dev machine:

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o nday-linux-amd64 ./cmd/nday
```

## Releasing a new version

Upload the binary:

```bash
scp nday-linux-amd64 <user>@<host>:nday-new
```

On the host, your login account can't read `/opt/nday` or `/etc/nday/nday.env`, and the `nday` system user can't read `/home/<user>`. So always run commands as `nday` in the form below (both the `cd` and the env-file read happen inside `sudo -u nday sh -c '…'`), and install the uploaded binary into `/opt/nday/bin/` before `nday` tries to run it:

```bash
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday <subcommand>'
```

Release steps. Do each one only after the previous one succeeded (use `set -e` if you put them in a script, otherwise a failure in the middle gets skipped):

```bash
# 1. Put the new binary next to the old one, so the running service isn't affected
sudo install -o root -g root -m 0755 /home/<user>/nday-new /opt/nday/bin/nday.new
sudo sha256sum /opt/nday/bin/nday.new                  # should match the checksum of your local build

# 2. Run the migrations with the new binary (they only add things, so the old binary keeps working);
#    you must see "applied: ..." and exit code 0
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday.new migrate'

# 3. Make sure no collector is running (the command should print nothing), keep the previous version, then swap
systemctl list-units 'nday-collect@*.service' --state=activating,active --no-legend
sudo cp -p /opt/nday/bin/nday /opt/nday/bin/nday.prev
sudo install -o root -g root -m 0755 /opt/nday/bin/nday.new /opt/nday/bin/nday
sudo rm /opt/nday/bin/nday.new

# 4. Restart the web service and check it
sudo systemctl restart nday-web.service
systemctl is-active nday-web.service
journalctl -u nday-web.service -n 20
```

To try the new binary before switching, start it after step 1 on another local port (plain HTTP, read-only connection pool), check it with `curl -H 'Host: www.nday.land' http://127.0.0.1:18080/`, then stop it. `curl http://127.0.0.1:18080/` without the `Host` header works too, because loopback addresses and `localhost` aren't restricted (see "Other hosts" in `docs/auth.md`).

```bash
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) NDAY_LISTEN=127.0.0.1:18080 NDAY_PUBLIC_URL=https://www.nday.land /opt/nday/bin/nday.new serve'
```

If `NDAY_LOG_DIR` is set, a trial run like this writes its requests to today's access log.

Rollback: install `/opt/nday/bin/nday.prev` as `/opt/nday/bin/nday` again and restart the service. You can leave the tables the migrations added.

Before releasing a change to the normalization logic, rehearse it on a copy of the production database. The result should contain only the changes you expect:

```bash
/opt/nday/bin/nday renormalize <source> --dry-run
```

## Adding a collector timer

```bash
sudo systemctl enable --now nday-collect@<source>.timer
```

It runs once an hour, with up to 5 minutes of random delay.

## Web service (nday-web)

`nday serve` serves the HTML pages and the JSON API (`docs/api.md`) from one process. Static assets are embedded in the binary, so it doesn't read or write the disk for them.
In production it sits behind Cloudflare, and the origin speaks HTTPS directly:

- Certificate: put a Cloudflare Origin Certificate at `/etc/nday/tls/origin.pem` and `origin.key` (`root:nday`, key 0640).
- Authenticated Origin Pulls (AOP): once `NDAY_TLS_CLIENT_CA` is set, connections without a client certificate signed by that CA are rejected during the TLS handshake.
  **We recommend zone-level AOP with your own client certificate.** Generate your own CA and client certificate, upload the client certificate to your Cloudflare zone,
  put your CA at `/etc/nday/tls/aop_ca.pem` and point `NDAY_TLS_CLIENT_CA` at it. Don't use Cloudflare's shared global certificate
  (`authenticated_origin_pull_ca.pem`). The difference is in Cloudflare's docs (https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/):
  the global certificate is shared by all Cloudflare accounts, so it only proves a request came from the Cloudflare network.
  That means **any** Cloudflare customer can point their own domain at your origin IP and still pass the handshake. A zone-level certificate is exclusive to your account,
  and zone-level certificates take precedence over the global one.
  The global certificate does prove the connection came from Cloudflare (direct connections to the origin and forged `CF-Connecting-IP` headers fail). It doesn't prove the request came from your own zone.
  The second layer of defense is in the application: `/auth/*`, `/account/*` and `/api/me` only accept requests whose `Host` equals the host of `NDAY_PUBLIC_URL` (otherwise 421).
  Also, when `NDAY_PUBLIC_URL` is set, the whole site refuses requests whose `Host` isn't the public host, its bare domain (`X` when the public host is `www.X`), the API host, or a loopback name (see "Other hosts" in `docs/auth.md` Â§6). So someone who points their own domain at your origin IP through Cloudflare doesn't get a mirror of your site.
  If sign-in is enabled and `NDAY_TLS_CLIENT_CA` isn't set, `nday serve` logs a warning at startup: in that case `CF-Connecting-IP` (used for sign-in rate limiting) is only as trustworthy as the firewall.
  For the exact dashboard steps to upload a zone certificate, follow the Cloudflare docs linked above.
- Minimum TLS version is 1.2.

Add this to `/etc/nday/web.env` (only `nday-web.service` reads it; see the comments in the service file):

```bash
NDAY_LISTEN=0.0.0.0:443
NDAY_TLS_CERT=/etc/nday/tls/origin.pem
NDAY_TLS_KEY=/etc/nday/tls/origin.key
NDAY_TLS_CLIENT_CA=/etc/nday/tls/aop_ca.pem   # your own CA for zone-level AOP (see above)
```

(The equivalent command-line flags are `--listen`, `--tls-cert`, `--tls-key` and `--tls-client-ca`. Giving a certificate without a key makes the process exit with an error.
Without these variables the server speaks plain HTTP and listens on `127.0.0.1:8080` by default.)

### Log files (/data/log/nday)

Without `NDAY_LOG_DIR` nothing changes: access logs and application logs both go to stderr (journald). With it set:

```bash
sudo install -d -o nday -g nday -m 0750 /data/log/nday
# /etc/nday/web.env
NDAY_LOG_DIR=/data/log/nday
```

- The directory gets two files per day: `access-YYYY-MM-DD.log` (one JSON line per request, for both the site host and the API host; access lines go **only** here, not to journald)
  and `error-YYYY-MM-DD.log` (every record at WARN and above, panics with stack traces, and one entry per 5xx; these also still go to journald).
- Files are split by the local date in the **server's local timezone** (`/etc/localtime`), and the `time` field in each line carries the same offset
  (for example `2026-11-13T15:30:00.123+02:00`), so a line always lands in the file for its own date. Restarting on the same day appends to the existing file.
- **nday never deletes or compresses anything in this directory.** Remove old files yourself (for example `find /data/log/nday -name '*-2026-0[1-6]-*.log' -delete`, but look at what it matches first).
- If the directory doesn't exist or today's file can't be opened, `nday serve` exits and says why. It doesn't create the directory for you.
- Access logs contain visitor IPs (`client_ip`, `remote_addr`, `http_x_forwarded_for`). That's personal data, so control access to it and decide how long to keep it.
- The service file has `ReadWritePaths=/data/log/nday` and `RequiresMountsFor=/data`: create the directory before starting the service, and make sure `/data` is mounted first.
- For the fields, the redaction rules and a few limitations (`request_length` is a reconstructed value; the `ssl_*` fields describe the Cloudflare-to-origin leg), see `docs/logging.md`.
- Size reference (measured per-line sizes, not a traffic forecast): 13 access-log lines from a local run came to 5558 bytes, about 430 bytes per line. Those requests had empty Cloudflare headers and a `curl/8.7.1` user agent. Production lines with `CF-Ray`, a country and a browser user agent will be longer (the user agent is capped at 300 bytes).

### Separate API host (api.nday.land)

The public data API lives at `https://api.nday.land/v1` and the site stays at `https://www.nday.land`. It's the same process and the same port, split by `Host`
(see the base URL section of `docs/api.md`). Add this to `/etc/nday/web.env` (only `nday-web.service` reads it):

```bash
NDAY_PUBLIC_URL=https://www.nday.land
NDAY_API_URL=https://api.nday.land
```

- The origin certificate must cover `api.nday.land` (it has to be in the hostname list of the Cloudflare Origin Certificate, or use `*.nday.land`).
  Otherwise TLS verification fails when Cloudflare connects to the origin as `api.nday.land` (a 526 under Full (strict)).
- The `api.nday.land` DNS record in Cloudflare must be **proxied** (orange cloud). The origin only accepts Cloudflare connections (AOP),
  so an unproxied record makes clients connect to the origin directly, fail the handshake, and expose your origin IP.
- The startup log should contain `api: separate host api_origin=https://api.nday.land`. If you see a warning like
  `NDAY_API_URL equals NDAY_PUBLIC_URL` or `NDAY_API_URL is set but NDAY_PUBLIC_URL is not`, check `web.env`.
  If `NDAY_API_URL` isn't valid, the service exits and names the variable.
- Once it's set, the old paths on the site host (`/api/hot` and so on, plus `/raw/...`) answer 308 and redirect to `https://api.nday.land/v1/...`. `/api/me`, `/auth/*` and
  `/account/*` don't change and stay on `www.nday.land` only. Without `NDAY_API_URL` the behavior is exactly as before.
- Checks:

  ```bash
  curl -sk --resolve api.nday.land:443:127.0.0.1 https://api.nday.land/v1/stats   # with a client CA set, the handshake fails here; that's expected
  curl -sI https://www.nday.land/api/stats    # 308, Location: https://api.nday.land/v1/stats
  curl -s https://api.nday.land/              # JSON index
  ```

Install and start:

```bash
sudo install -o root -g root -m 0644 nday-web.service /etc/systemd/system/nday-web.service
sudo systemctl daemon-reload
sudo systemctl enable --now nday-web.service
journalctl -u nday-web.service -n 30
curl -sk --resolve nday.land:443:127.0.0.1 https://nday.land/healthz   # with a client CA set, the handshake fails here; that's expected
```

The service runs as `nday` and binds port 443 through `AmbientCapabilities=CAP_NET_BIND_SERVICE`. `Restart=on-failure` brings it back after a crash.
After releasing a new version, run `sudo systemctl restart nday-web.service` (graceful shutdown: it waits up to 20 s for in-flight requests to finish).

## Sign-in and accounts (optional)

For the design and how to register with each provider, see `docs/auth.md`. Without any configuration the site behaves exactly as before.

1. Create an app at each provider as described in `docs/auth.md` §7. The callback URL is `https://www.nday.land/auth/<provider>/callback`.
2. Use `deploy/auth.env.example` as a template and write `/etc/nday/auth.env`:

   ```bash
   sudo install -o root -g nday -m 0640 auth.env.example /etc/nday/auth.env   # then edit in your values
   sudo install -d -o root -g nday -m 0750 /etc/nday/apple                     # Apple only: for the .p8 key
   sudo install -o root -g nday -m 0640 AuthKey_XXXXXXXXXX.p8 /etc/nday/apple/
   ```
3. Create the tables (`0004_auth`) and restart:

   ```bash
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday migrate'
   sudo install -o root -g root -m 0644 nday-web.service /etc/systemd/system/nday-web.service   # this version loads /etc/nday/auth.env
   sudo systemctl daemon-reload && sudo systemctl restart nday-web.service
   journalctl -u nday-web.service -n 30    # you should see "auth: sign-in enabled providers=[...]"; a config error makes it exit and name the variable
   ```
4. Cloudflare: make sure `nday.land` redirects with a 301 to `https://www.nday.land`, and never cache at the edge `/auth/*`, `/account/*`, `/api/me`, nor the gated data routes: `/api/*`, `/raw/*`, `/feed.xml`, `/<locale>/feed.xml` and everything on the API host (`api.nday.land`). A Cloudflare "Cache Everything" or Edge Cache TTL rule matching any of these would store a response that was only sent because the request carried an API token, a session cookie or a private feed key, and hand it to anyone who asks for the same URL without one (Cloudflare does not key its cache on `Authorization`). The origin sends `private`/`no-store` and `Vary: Authorization` on these; don't override that with a cache rule. Only the HTML pages, `/static/*`, the sitemap and the API index may use the default caching.

Most sign-in variables (each provider's ID and secret, the passkey switch, session lifetimes and so on) can also be changed in `/admin/settings` and stored in the database. See "Settings stored in the database" below and `docs/settings.md`.

The service process cleans up expired sessions and similar data every 15 minutes. You can also run `nday auth-gc` by hand (a session idle timeout stored in the database takes precedence). Admin commands: `nday auth-role`, `nday auth-suspend` and `nday auth-unsuspend` (they need the database URL from `nday.env`).

## Discussions (enabled together with accounts)

Every vulnerability page has a discussion section (design, endpoints and rate limits are in `docs/discuss.md`). It's mounted whenever sign-in is enabled. Set `NDAY_DISCUSS=off` to turn it off on its own (the routes return 404, nothing else changes).

1. **Publish your community rules first and set `NDAY_TERMS_VERSION`** (in `/etc/nday/auth.env`). Posting a comment requires having accepted the current version (`403 terms_required`). If it's not set, any account with a handle can comment, and the startup log warns `discuss: NDAY_TERMS_VERSION is not set`. After you change the version, everyone has to accept again before they can post.
2. Release as described in "Releasing a new version". The `nday.new migrate` in step 2 creates the tables of `0005_discuss` (it only adds tables, so the old binary isn't affected), and you must see `applied: 0005_discuss`. After the restart, check:

   ```bash
   journalctl -u nday-web.service -n 30    # you should see "discuss: discussions enabled terms_version=..."
   ```
3. Optional variables (defaults are at the end of `deploy/auth.env.example`; all of them go in `/etc/nday/auth.env`): `NDAY_DISCUSS`, `NDAY_DISCUSS_DB_POOL_SIZE` (a writable connection pool just for discussions, default 4; the database's `max_connections` has to cover site 8 + auth 4 + discussions 4 + the collector jobs), `NDAY_DISCUSS_POST_*`, `NDAY_DISCUSS_NEW_*`, `NDAY_DISCUSS_ADDR_*`, `NDAY_DISCUSS_EDIT_*`, `NDAY_DISCUSS_REPORT_DAILY`, `NDAY_DISCUSS_REPORT_*`, `NDAY_DISCUSS_DELETE_*`, `NDAY_DISCUSS_READ_*`, `NDAY_DISCUSS_MOD_*`, `NDAY_DISCUSS_DUPLICATE_WINDOW`, `NDAY_DISCUSS_GUEST_READ` (whether signed-out visitors can read comments, default on) and `NDAY_DISCUSS_GUEST_READ_*`. If a value is invalid the service refuses to start and names the variable. Except for `NDAY_DISCUSS_DB_POOL_SIZE`, these can also be stored in the database through `/admin/settings` (see "Settings stored in the database").
4. Moderators: `nday auth-role <user-id|handle> moderator`. For emergencies when the web UI isn't available: `nday discuss-hide <comment-id> --reason "…"` and `nday discuss-unhide <comment-id>` (they print the comment's id, vulnerability, author handle and state first, then act).
5. Cloudflare: don't set cache rules for `/api/discuss/*`, `/api/mod/*` or `/api/corrections/*` (the responses are all `no-store`), nor for any of the gated data routes listed under "Sign-in and accounts" (`/api/*`, `/raw/*`, `/feed.xml`, `/<locale>/feed.xml` and everything on the API host (`api.nday.land`)).
6. Public discussion reads (anonymous visitors, the discussion section on a vulnerability page) use the site's read-only connection pool and don't take extra connections.
7. **Local development databases only, not needed in production.** `0005_discuss` was changed after it was first written (`comments.rev` was added). If your local database created the tables with the older version, drop the three discussion tables and the migration record, then migrate again:

   ```bash
   psql "$NDAY_DATABASE_URL" -c "BEGIN; DROP TABLE comment_reports, comment_revisions, comments; DELETE FROM schema_migrations WHERE version = '0005_discuss'; COMMIT;"
   go run ./cmd/nday migrate
   ```

## Usage statistics (nday-stats)

`nday stats-rollup` aggregates `/data/log/nday/access-*.log` into the `stats_*` tables in the database (migration `0006_stats`; the tables, metrics and privacy rules are in `docs/stats.md`).
It only reads the log directory and never writes, renames or deletes anything there. It needs `nday.env` (database) and `web.env` (`NDAY_LOG_DIR`).

```bash
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday migrate'   # 0006_stats
sudo install -o root -g root -m 0644 nday-stats.service nday-stats.timer /etc/systemd/system/
sudo systemctl daemon-reload
# Run it by hand once first (the first run processes every access log in the directory); --dry-run computes without writing to the database
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday stats-rollup --dir /data/log/nday --dry-run'
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday stats-rollup --dir /data/log/nday'
sudo systemctl enable --now nday-stats.timer    # every 10 minutes; only recomputes files whose size or modification time changed (usually just today's)
journalctl -u nday-stats.service -n 20
```

- When running it by hand, pass the directory with `--dir` (`web.env` has comments, so it can't be expanded with `$(cat …)`). The timer reads `NDAY_LOG_DIR` from `web.env`.
- To recompute a day: `… nday stats-rollup --dir /data/log/nday --day 2026-11-13` (repeatable). To recompute everything: `--all`. Each day is deleted and rewritten in one transaction, so you can rerun or interrupt it at any time.
- Deleting old log files doesn't delete the statistics already rolled up. Don't use `--day` or `--all` on those dates afterwards (when the file is missing the day is skipped and its existing data is kept).

## Admin back office (/admin, enabled together with accounts)

The entry point is `https://www.nday.land/admin`. It uses the site's existing sign-in and sessions and is open only to moderators and admins. The access rules, pages, endpoints and audit log are described in `docs/admin.md`.

```bash
# Migration 0007_admin: the audit table admin_audit (add-only; has triggers that reject UPDATE/DELETE/TRUNCATE)
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday migrate'   # 0007_admin
sudo systemctl restart nday-web

# The first admin can only be granted on the server from the command line (the web UI can never create, change or revoke an admin).
# First have that account sign in on the site once and set a handle. When you use a handle, the command prints the account it resolved to first and needs --yes to confirm (an account id doesn't):
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday auth-role <handle> admin --yes'
# Revoke:
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday auth-role <handle> user --yes'
```

- These commands, plus `auth-suspend`, `auth-unsuspend`, `discuss-hide` and `discuss-unhide`, each write an audit record in the same transaction (the actor shows as "server CLI").
- Admins can grant and revoke the moderator role in the web UI (`/admin/users/<id>`). You can also keep using `nday auth-role <handle> moderator --yes`.
- The usage statistics page depends on `nday-stats.timer` above. Before the first rollup it says the statistics have never been rolled up, while the community numbers (accounts, comments, reports) are still read straight from the database.
- The system status page reads today's and yesterday's `error-*.log` from `NDAY_LOG_DIR` (in `/etc/nday/web.env`), read-only and at most the last 1 MiB of each file. If it isn't set, the page says so.
- The audit table's triggers protect against application bugs and mistakes, not against the database owner: the owner can still drop the triggers or the table.

## X post collection (xposts, optional)

Migration `0008_xposts` (the new event type `social_post`, the tables `x_accounts` and `x_settings`; add-only, and `vuln_state` stays the same for existing data; details in `docs/xposts.md`):

```bash
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday migrate'   # 0008_xposts
```

- **Keep the token in its own file.** Don't put `NDAY_X_BEARER_TOKEN` in `nday.env` (every collector job reads `nday.env`). Put it in
  `/etc/nday/xposts.env` and attach that file to the xposts collector unit. The `nday-web` unit file already reads the same file optionally
  with `EnvironmentFile=-/etc/nday/xposts.env` (the service starts fine if the file doesn't exist):

  ```bash
  sudo install -o root -g nday -m 0640 /dev/null /etc/nday/xposts.env    # contents: NDAY_X_BEARER_TOKEN=…
  sudo systemctl edit nday-collect@xposts.service                        # add two lines: [Service] and EnvironmentFile=/etc/nday/xposts.env
  sudo install -m 0644 deploy/systemd/nday-web.service /etc/systemd/system/ && sudo systemctl daemon-reload
  sudo systemctl restart nday-web                                        # so the web process picks up the token
  ```
  The web process uses this token for exactly one thing: when an admin adds or imports accounts by handle on `/admin/x`, it calls the official X API user lookup
  (`GET https://api.x.com/2/users/by?usernames=…`) to find the numeric user id and bind it. It never displays, logs, returns or accepts the token,
  and it only sends requests to `https://api.x.com` (no environment variable can change that address). If you don't want the web service to hold the token, don't give `nday-web` this file
  (put it at another path and attach it to the collector unit only). The admin page then says the lookup is off, and adding an account requires entering the numeric id as well.
  The startup log line `admin: back office enabled … x_lookup=true|false` tells you whether it's on.
- The timer uses the existing template, so one line enables it (once an hour with up to 5 minutes of random delay. The daily and 30-day worst-case costs on `/admin/x` assume 24 runs a day):

  ```bash
  sudo systemctl enable --now nday-collect@xposts.timer
  ```
  With no token, no enabled accounts, or collection switched off in settings, a run exits immediately: no requests, no cost.
- You can also store the token encrypted in the database through `/admin/settings` (this needs `NDAY_SETTINGS_KEY` first, see the next section). The database value wins and `xposts.env` still works as a fallback.
  Note that once it's in the database, every unit that loads `nday.env` can decrypt it, so the isolation of the separate file above no longer holds (`docs/settings.md` §9).
- Maintain the allowlist and settings on `/admin/x`, or with the commands `nday x-accounts-import`, `x-accounts-enable|disable` and `x-settings` (all of them write audit records).
  Lines in an import file that contain only `@handle` get their id looked up during the import. To import from the command line, the token has to be in the command's environment, for example:
  `sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env /etc/nday/xposts.env) /opt/nday/bin/nday x-accounts-import FILE'`
  (`xposts.env` is root:nday 0640, so the `nday` user can read it).
- Cost caps: a run returns at most `max_posts` posts (hard limit 5000) and makes at most `max_requests` requests (hard limit 100, each returning up to 100 posts). At $0.005 per post, the worst case for one run is $25, and for 24 runs a day it's $600.
- Link page titles (migration `0020_web_page`, which only adds the table `web_page`): when you release, `nday.new migrate` should print `applied: 0020_web_page` (and `0019` too if that one hasn't been applied yet).
  After that, every successful xposts collection queues the links found in posts and fetches the titles of third-party web pages in one pass (at most 25 pages, 2 minutes in total, 1 second between fetches, at most 25 seconds per page, and fewer pages per pass if many sites are slow, with the rest left for the next run. It only connects to ports 80 and 443 on public addresses; see `docs/webpages.md`).
  So the collector unit needs outbound access to ports 80 and 443 on any public host. To backfill existing links the first time, run `nday x-links-enqueue`, then `nday pages-fetch` (repeat as needed; it takes 100 pages per run by default). If the migration hasn't been applied, the automatic step after collection just logs a warning.
- GitHub repository metadata (migration `0023_github_repo`, additive: tables `github_repo`, `github_repo_name`, `github_repo_cve` and the column `x_post_link.repo_queued_url`): when you release, `nday.new migrate` should print `applied: 0023_github_repo`.
  After that, every successful xposts collection also queues the GitHub repository links of posts and fetches their metadata from `https://api.github.com` only (at most 25 repositories, 2 minutes, 1 second apart; it stops quietly at the rate limit; see `docs/github.md`). The repositories then show as `owner/name`, stars and creation date in the vulnerability page's Resources panel.
  The token is the existing `NDAY_GITHUB_TOKEN` (store it on `/admin/settings`, or put it in an env file the xposts collector unit loads); without it requests are anonymous, 60 an hour. Backfill: `nday github-enqueue`, then `nday github-fetch` (50 per run by default; repeat after the rate-limit window when anonymous). If the migration hasn't been applied, the automatic step logs a warning.

## GitHub PoC discovery (nday-github-discover)

Migration `0025_github_discovery` (additive: the columns `github_repo.status`, `status_by`, `status_at`, `seen_at`, `x_post_link.repo_swept_url`, `repo_root_key`, `repo_github_id`, `repo_checked_at`, `repo_check_attempts`, the tables `github_rejected_name`, `github_search_cve`, `github_search_scan`, two triggers that keep a repository row's GitHub id and the row itself, and CVE-or-GHSA ids in `github_repo_cve`). It does not depend on `0024`; either may be applied first. Details in `docs/github.md` ("Identity, names, links", "Discovery", "Review", "Deploying").

After the migration and the binary swap, repository links of earlier posts render plain (no name, stars or date) until the new code has checked them. Run, in this order:

```bash
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday github-enqueue'   # sweeps every github.com code link once
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday github-fetch'     # repeat until "link_checks": 0
```

`github-fetch` makes 50 requests a run; without a token wait for GitHub's hourly limit between runs (or leave it to the collector runs, 25 a run). A repository becomes trusted by rule only when a post links its root and that link was checked: the repository answering for the name was created before the link was stored. If the old binary runs between `migrate` and the swap (a collector timer), nothing is lost: the new sweep has its own marker, and an old fetch pass that would rewrite or delete a repository row is refused by the triggers and only logs `github fetch pass failed`. Advisory links (`github.com/<owner>/<repo>/security/advisories/…`) stored earlier as code: see step 5 of "Deploying" in `docs/github.md` for the one statement that re-classifies them.

```bash
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday.new migrate'   # applied: 0025_github_discovery
sudo install -o root -g root -m 0644 deploy/systemd/nday-github-discover.service deploy/systemd/nday-github-discover.timer /etc/systemd/system/
sudo systemctl daemon-reload
# Run it by hand once first (a few minutes without a token); it prints the counts as JSON
sudo systemctl start nday-github-discover.service && journalctl -u nday-github-discover.service -n 5    # one "github discover pass" line
sudo systemctl enable --now nday-github-discover.timer    # hourly, up to 5 minutes of random delay
```

- It only talks to `https://api.github.com/search/repositories`: at most 40 requests a run, 7 s apart without a token (2.5 s with one), so it never reaches GitHub's 10 (30 with a token) search requests a minute; it stops quietly on any 403 or 429 and after 15 minutes at most. It and the GitHub fetch step of the xposts collector never run at the same time: whichever comes second does nothing that time (`"locked": true`).
- Token: the same `NDAY_GITHUB_TOKEN` as above (database settings, or the environment of this unit); the unit loads `nday.env` only.
- Found repositories are **unverified**: the vulnerability page lists at most 5 per page under PoC with an "unverified" mark; they never change a stage. Repositories linked from researcher posts are trusted by rule, shown unmarked only on that post's page.
- Before stopping services for a restore, add `nday-github-discover.timer` to the stop/start lists in "Backup and restore".

## Site icons of outbound links (nday-site-icons)

Migration `0028_site_icon` (additive: the table `site_icon` only). On the vulnerability page every link that leaves the site shows the target site's small icon in front of its text, served from our own origin at `/icon/<host>?v=<hash>`; readers never contact the third party. A daily job fetches the icons; until it has run, the links show an empty box of the same size. Details in `docs/siteicons.md`.

```bash
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday.new migrate'   # applied: 0028_site_icon
sudo install -o root -g root -m 0644 deploy/systemd/nday-site-icons.service deploy/systemd/nday-site-icons.timer /etc/systemd/system/
sudo systemctl daemon-reload
# Run it by hand once first (up to 15 minutes); it prints the counts as JSON
sudo systemctl start nday-site-icons.service && journalctl -u nday-site-icons.service -n 5    # one "site icons pass" line
sudo systemctl enable --now nday-site-icons.timer    # daily at 05:15, up to 30 minutes of random delay
```

- The first runs take the 200 most linked hosts each (`nday site-icons --limit N` for more, at most 2000; repeat until `"candidates"` is below the limit). After that a run only sees new hosts, hosts whose icon is 30 days old, hosts without an icon after 30 days and failed hosts after 1 h, 4 h, 16 h, ... (at most 30 days).
- The unit needs outbound https (port 443) to any public host, like the collectors; plain http is never used and redirects to http or to a non-public address are refused.
- The web service only reads the table: if the binary is deployed before the migration, pages show the empty boxes and `/icon/...` answers 404.
- Before stopping services for a restore, add `nday-site-icons.timer` to the stop/start lists in "Backup and restore".

## Settings stored in the database (`app_settings`, optional)

Migration `0014_settings` adds the table `app_settings`. Admins can change 51 variables for the collectors, discussions and sign-in on `/admin/settings` (precedence: database, then environment variable, then default),
and secrets (the GitHub and X tokens, each sign-in method's secret, the Apple private key) are stored encrypted. The full description, the migration steps and the threat-model trade-offs are in `docs/settings.md`.

1. Release as described in "Releasing a new version". `nday.new migrate` should print `applied: 0014_settings`. If you don't store anything in the database, nothing changes.
2. To save secrets from the back office you need a master key. It lives only in the environment and is never stored in the database:

   ```bash
   echo "NDAY_SETTINGS_KEY=$(openssl rand -base64 32)" | sudo tee -a /etc/nday/nday.env >/dev/null   # root:nday 0640 stays as is
   sudo systemctl restart nday-web.service
   ```
   Keep a separate copy of this key somewhere safe and offline: **if you lose it, none of the secrets in the database can be read** (each process falls back to its environment variables), and you have to generate a new key and re-enter the secrets in the back office.
   There's no automatic re-encryption for key rotation yet: write the new key, restart the web service and re-enter the secrets one by one in the back office. `nday.env` is loaded by every unit, so every unit can decrypt the secrets in the database.
   If your backup puts `/etc/nday` and the database dump under the same backup root, the encryption doesn't help when the whole backup is stolen (`docs/settings.md` §9).
3. After entering a value in `/admin/settings`, confirm that its source badge says it comes from the database, then delete **only the lines you moved into the database** from the env file and restart the web service. The collectors read the database value on their next run.
   Don't delete the whole `auth.env`: `NDAY_AUTH_SECRET` and a few others can only live in the environment, and without it sign-in and the back office are disabled (`docs/settings.md` §10, step 5).
   For emergencies: `nday settings` (lists the sources), `nday settings-set KEY VALUE --yes` and `nday settings-unset KEY --yes` (secrets can't be written from the command line).
   The first two have to load the web service's whole environment (`nday.env`, `web.env`, `auth.env`, and `xposts.env` if you have it, using `set -a; . file`); see `docs/settings.md` §8 for the full commands. `settings-unset` only needs `nday.env`.
   After you change the database from the command line, the web service doesn't notice until the next save in the back office or a restart.

## NVD source and classification layer (nvd, classify)

The design, rules and measured numbers are in `docs/nvd.md`. NVD only provides classification data (CWE, CVSS, CPE). It doesn't produce events and doesn't change `vuln_state`.

1. Release as described in "Releasing a new version". The `nday.new migrate` in step 2 should print `applied: 0009_classify` (the new tables `vuln_cwe`, `vuln_cvss`,
   `vuln_classify_input` and `classify_queue`, a trigger on each of `raw_record` and `vuln` that only appends rows to the queue, and an expression index on `raw_record`
   that covers only ghsa rows. Building that index blocks writes to `raw_record` for a few seconds, so first make sure no collector is running).
   From this version on, every successful `nday collect <source>` also processes the classification queue (one `classification pass` line in the log).
2. One-time baseline import (about a 250 MB download, and `raw_record` grows by roughly 1.4 to 1.5 GB; that's an extrapolation, see `docs/nvd.md` §6):

   ```bash
   df -h /var/lib/postgresql          # check the free space first (leave at least 3 GB)
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday import-nvd-baseline --download --dry-run --year 2002'
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday import-nvd-baseline --download'
   ```
   For each yearly file it fetches the `.meta` first, then after the download checks `gzSize`, the uncompressed size and the SHA-256, and only then parses it and writes to the database. If it fails or gets interrupted, just rerun the same command:
   records already imported are skipped by content hash. You can also download `nvdcve-2.0-YYYY.json.gz` and the `.meta` files into a directory with `curl` and use
   `--dir <directory>` (the checks run the same way when the `.meta` sits next to the file).
3. First classification (reads all the CVE, NVD and GHSA raw records; safe to rerun, since identical results aren't written):

   ```bash
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday classify --all --dry-run'
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday classify --all'
   ```
   After that it's incremental. To process the queue by hand: `nday classify --pending`. To recompute only one source or some CVEs: `--source nvd|cvelist|ghsa`, `--cve CVE-… …`.
4. Enable the hourly incremental collection (existing template):

   ```bash
   sudo systemctl enable --now nday-collect@nvd.timer
   journalctl -u nday-collect@nvd.service -n 30    # "outcome": "unchanged" in the output means the .meta didn't change and nothing was downloaded
   ```
   Each run fetches only a `.meta` of about 165 bytes (with `If-None-Match`), and downloads the roughly 10 MB "modified" file only when it changed.
   After the timer has been off for more than 7 days, the first run re-reads the yearly files whose `.meta` changed first (possibly several hundred MB to download, taking a few minutes).
5. Check:

   ```bash
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday status'   # collector_state should list nvd
   curl -s https://api.nday.land/v1/vuln/CVE-2018-0125 | jq .classification
   ```
6. Before going live, check in the browser that the attribution text required by the NVD terms of use is right (`docs/nvd.md` §7; the About page text is the catalog key `about.nvd_notice`).

Rollback: the old binary doesn't know the new tables and triggers, but the triggers only append rows to `classify_queue`, so the old binary keeps running. The queue keeps growing until the new binary runs
`nday classify --pending` again (or you `TRUNCATE classify_queue` and run `classify --all` again).

## Following vendors and products, first sign-in page (enabled together with accounts)

Migration `0010_follows` (the new table `user_follows`, add-only; the rules are in `docs/follows.md`):

```bash
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday migrate'   # 0010_follows
sudo systemctl restart nday-web
```

- Migrate before you start the new binary: its `/api/me` reads `user_follows`, and without that table `/api/me` returns 500 for signed-in users.
- The OAuth callback for a newly created account goes to `/welcome` first (it can be skipped). Existing users aren't affected.
- Pinning followed items to the top of the home page happens in a script, only in browsers that are signed in and follow something. The HTML and caching don't change.
- In two-host mode, `/api/affected/suggest` on `www` doesn't redirect to the API host (the page script needs it). Cloudflare needs no rule change: like search, it's `public, max-age=60`.

## CVE tags (tags)

The design, vocabulary, rules and measured numbers are in `docs/tags.md`. Tags only read existing data (the classification layer, public events, GHSA raw records) and don't change events or `vuln_state`.

1. Release as described in "Releasing a new version". The `nday.new migrate` in step 2 should print `applied: 0011_tags` (the new tables `vuln_tag`, `vuln_tag_suppress`,
   `vuln_tag_count`, `tag_run` and `tag_queue`, the view `vuln_tag_visible`, and three statement-level triggers on each of `vuln_cwe`, `vuln_cvss`, `vuln_classify_input`, `event` and
   `vuln_tag_suppress` that only append rows to `tag_queue`. Creating them is quick and doesn't block collection). From this version on, every successful
   `nday collect <source>` processes the tag queue after classification (one `tag pass` line in the log). Until step 3 is done, every run also logs the warning
   `tags: rows may be stale: run nday tags --all`. That's expected.
2. Finish the NVD baseline and `nday classify --all` first (steps 2 and 3 of the previous section). The order isn't strictly required, but classifying first means you only need one full tagging run: every CVE changed by `classify --all`
   goes into `tag_queue` (several hundred thousand rows, which is normal), and the `--all` in the next step clears them all.
3. One-time full tagging (safe to rerun; identical results aren't written):

   ```bash
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday tags --all --dry-run'
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday tags --all'
   ```
   On a full local copy (424,972 CVEs, with only three NVD sample files) it took 19.5 s, wrote 884,886 rows, and `vuln_tag` with its indexes was 298 MB. For production after the full NVD baseline,
   our **extrapolation** is about 1.2 to 1.6 M rows, 0.45 to 0.6 GB and 30 to 40 s (an extrapolation, not a measurement; see `docs/tags.md` §8). After that it's incremental. To process the queue by hand:
   `nday tags --pending`. To recompute only some CVEs: `nday tags --cve CVE-… …`. After you release a version that changes the rules (`internal/tags.RuleVersion` goes up by one),
   run `nday tags --all` once more.
4. Check:

   ```bash
   curl -s https://api.nday.land/v1/tags | jq '.counts_at, (.tags | map(select(.slug == "ransomware")))'
   curl -s https://api.nday.land/v1/vuln/CVE-2021-44228 | jq '.tags[] | {slug, basis}'
   curl -s 'https://api.nday.land/v1/hot?since=30d&tag=remote-unauth' | jq '.rows | length'
   ```
   On the site, look at `/tags`, `/tag/remote-unauth`, and the "why these tags" section on any vulnerability page.

Rollback: the old binary doesn't know the new tables, view and triggers. The triggers only append rows to `tag_queue`, so the old binary keeps running, and the queue keeps growing until the new binary runs
`nday tags --pending` again (or you `TRUNCATE tag_queue` and run `tags --all` again).

### Product and product-type tags (rule version 2, migration `0013_affected_tags`)

This adds two dimensions: `product` (about 200 well-known product families, such as Windows, Chrome and FortiOS) and `product-type` (23 categories, such as operating system, router and
database). The sources are the `affected` table (the vendor and product given in the CVE record) and the **vulnerable** CPE names in the NVD record version the classification layer read. The vocabulary and rules are in
`docs/tags.md` §1 and §2.

1. Release as described in "Releasing a new version". `nday.new migrate` should print `applied: 0013_affected_tags` (it only adds three statement-level triggers on `affected`
   that append rows to `tag_queue`. It doesn't change any table or data and finishes instantly).
2. `internal/tags.RuleVersion` goes from 1 to 2, so after the release you **must** run a full pass (until you do, every post-collection incremental run warns
   `tags: rows may be stale: run nday tags --all`; that's expected):

   ```bash
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday tags --all --dry-run'
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday tags --all'
   ```
   Measured on a full local copy (424,972 CVEs; NVD had only the 2010, 2018 and recent sample files): the first `--all` took 51.9 s, rewrote 303,966 CVEs and
   inserted 1,101,127 rows (105,798 product rows and 110,452 product-type rows). A second run changed nothing and took 23 s. `vuln_tag` with its indexes was 384 MB after VACUUM FULL
   (695 MB right after the first full run without cleanup, because all the old rows were deleted and reinserted; run `VACUUM (ANALYZE) vuln_tag` afterwards).
3. **CPE coverage depends on the full NVD baseline.** In the local sample only 21,246 CVEs had a vulnerable CPE from NVD. In production, CPEs only cover most CVEs after the NVD baseline import
   (`nday import-nvd-baseline`, see the NVD section) and `classify --all`. It's fine if you import the baseline after this release: when `classify`
   writes `vuln_classify_input`, the trigger puts the CVE into `tag_queue`, and the incremental run after collection or `nday tags --pending` catches up.
4. Check:

   ```bash
   curl -s https://api.nday.land/v1/tags | jq '.rule_version, .dimensions, (.tags | map(select(.slug == "windows" or .slug == "operating-system")))'
   curl -s https://api.nday.land/v1/vuln/CVE-2018-8174 | jq '.tags[] | select(.dimension == "product" or .dimension == "product-type") | {slug, basis}'
   ```
   On the site, look at the product and product type groups on `/tags`, `/tag/fortios`, and the "affected products in the CVE record" and
   "CPE names NVD's analysts give as vulnerable" lines in a vulnerability page's basis.

Rollback: the old binary (rule version 1) doesn't know the product slugs, and the read path skips them (`tags.Lookup` doesn't show slugs it doesn't know). If the old binary runs `tags --all`,
it deletes the product rows. The `0013` triggers only append queue rows, so the old binary handles them as usual.

## X post drafts (for the official account, part of the back office)

The design is in the "Drafts" section of `docs/xposts.md` and in `docs/admin.md` §2.2. **There's nothing to configure**: no X API, no token and no new environment variable. An admin posts by hand in X's own web composer.

1. Release as described in "Releasing a new version". The `nday.new migrate` in step 2 should print `applied: 0012_xdrafts` (the new tables `x_draft` and `x_draft_state`, and `x_draft` added to the `target_type` CHECK on `admin_audit`; add-only).
   **Run the migration while no collector is running** (run the check command from step 3 first; it should print nothing): creating the tables briefly locks `vuln`, `users` and `admin_audit`. The migration file has `SET LOCAL lock_timeout = '5s'`.
   If a long transaction is in the way, after about 5 seconds it fails with `canceling statement due to lock timeout (SQLSTATE 55P03)` and exit code 1, and **nothing is applied** (each migration is one transaction). Just rerun it after the collection finishes. It's safe to retry.
2. After that, every successful `nday collect <source>` also runs the draft step (one `x draft pass` line in the log; if another collector is writing at the time, it logs `x draft pass deferred`, which is normal). The first run only records the current highest event id (`baseline=true`) and doesn't generate drafts for history.
3. Running it by hand (optional):

   ```bash
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday x-drafts --dry-run'
   sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday x-drafts'
   ```

4. Admins review drafts at `https://www.nday.land/admin/x/drafts`.

Rollback: the old binary doesn't know the two tables and keeps running as before. No new drafts are generated, and existing ones stay in the tables.

## Researcher discussion, comments for signed-in users only, and the "Researchers are discussing" list

What changed (design in the "Public visibility" section of `docs/xposts.md`, `docs/discuss.md` §4.1 and `docs/api.md`):

- Vulnerability pages have a "researcher discussion" section. For posts on X from allowlisted accounts that mention the CVE, **only signed-in users can read the text** (`GET /api/posts/{cve}`, enabled together with accounts). Signed-out visitors see the **author's @username (linked to their X profile) and the date**. The text is a dotted placeholder, plus a sign-in button. This means that a researcher who posted about a CVE in the database is publicly identifiable as being on the allowlist.
- Comments are signed-in only too: the page no longer contains comment text or authors, and a signed-out `GET /api/discuss/{cve}` returns only an outline (counts and shapes). **Signed-in users without JavaScript can't see comment content.**
- Only counts are public: `@N` on each `/hot` row, `researchers_7d` on each `GET /v1/hot` row (added only, nothing changed), the new `/discussed` page (in the navigation and the sitemap) and `GET /v1/discussed`.
- Posts from allowlisted accounts that have been disabled are no longer counted or shown (the name doesn't appear either).
- Fix: the sitemap `lastmod` used to include the ingest time of every event, posts included, so ingesting a post changed it publicly. It now only looks at public events. After the release, the `lastmod` of some sitemap shards can move backwards; that's expected.

Release:

1. **There's no migration** (no new index is needed: the new queries use the existing `event_type_occurred_idx` and `event_uniq`, and EXPLAIN ANALYZE on a local database with 600,000 events shows all of them under 4 ms). `nday.new migrate` should print no new `applied:` line.
2. **There are no new environment variables.** `GET /api/posts/{cve}` is mounted automatically when sign-in is configured. Without sign-in it doesn't exist (the researcher section still shows the count and the placeholder, but no sign-in button).
3. Cloudflare: like `/api/discuss/*`, **don't cache** `/api/posts/*` (the response itself is `private, no-store` and carries `Vary: Cookie`), nor `/api/*`, `/raw/*`, `/feed.xml`, `/<locale>/feed.xml` and everything on the API host (`api.nday.land`) (they need an API token, a session or a feed key; see "Sign-in and accounts"). If you have path-based cache rules, add them all to the exclusion list. In two-host mode, `/api/discussed` answers 308 and redirects to `https://api.nday.land/v1/discussed`.
4. Check after the release:
   ```bash
   curl -sD- https://www.nday.land/api/posts/CVE-2024-3094 | head -20      # signed out: outline, no text; Cache-Control: private, no-store
   curl -s -H "Authorization: Bearer $NDAY_TOKEN" 'https://api.nday.land/v1/discussed?limit=5' | jq '.rows[] | {cve_id, researchers_7d}'
   curl -s -H "Authorization: Bearer $NDAY_TOKEN" 'https://api.nday.land/v1/hot?limit=3' | jq '.rows[0].researchers_7d'
   ```
   Sign in with a browser and open a vulnerability page that has posts: the researcher section should show them. After you sign out, only the dotted placeholder should remain.

Rollback: the old binary runs as before (there's no schema change). Comments go back to being rendered on the server for everyone, and `/discussed` and `/api/posts` disappear.

**Known gap:** X's policy requires posts that were deleted or made protected to be taken down within 24 hours. There's no recheck job yet (see the "Not handled" section of `docs/xposts.md`).

## Backup and restore

Every day at 04:30 (server time), `nday-backup.timer` runs `/opt/nday/bin/nday-backup` (`deploy/backup/nday-backup.sh` in the repo):

| Path | Contents | Kept |
|---|---|---|
| `/data/backup/daily/nday-YYYYMMDD.dump` | A full `pg_dump -Fc` backup | The latest 14 |
| `/data/backup/weekly/nday-GGGG-Www.dump` | Each Sunday's dump (a hard link, so it takes no extra space) | The latest 8 |
| `/data/backup/config/nday-etc-YYYYMMDD.tar.gz` | `/etc/nday` and nday's systemd unit files (**includes the sign-in secrets and the TLS private key**, mode 0600) | The latest 14 |
| `/data/backup/last-success` | Time, file and byte count of the most recent successful backup | n/a |

- Each backup is written to a temporary file first and only renamed once it passes the checks (`pg_restore -l` can read it, it has data for `vuln`, `event`, `raw_record` and `schema_migrations`, and it's at least 100 MiB).
  Old files are only cleaned up after a new backup succeeds, and only regular files in those three directories whose names match the formats above are deleted. Hand-made
  `nday-pre-*.dump` files in the root of `/data/backup/` are left alone.
- Before starting, it requires at least 5 GiB free on the disk that holds `/data/backup`, and fails otherwise.
- Optional `/etc/nday/backup.env`: `NDAY_BACKUP_KEEP_DAILY`, `NDAY_BACKUP_KEEP_WEEKLY`, `NDAY_BACKUP_DIR`.
- **The backups are on the same data disk of the same host as the database.** That protects against mistakes and failed migrations, but if the host or the data disk is lost, the backups go with it. Off-site backup isn't implemented yet.

One-time install:

```bash
sudo install -d -o nday -g nday -m 0750 /data/backup
sudo install -o root -g root -m 0755 nday-backup.sh /opt/nday/bin/nday-backup
sudo install -o root -g root -m 0644 nday-backup.service nday-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload && sudo systemctl enable --now nday-backup.timer
sudo systemctl start nday-backup.service && journalctl -u nday-backup.service -n 10   # take one right away
```

Checks:

```bash
systemctl list-timers nday-backup.timer
sudo cat /data/backup/last-success
systemctl --failed          # if a backup fails, nday-backup.service shows up here (there's no active alerting yet)
```

Restore drill (doesn't touch the production database; in one test, restoring a 4.7 GB database took about 2 min 20 s):

```bash
sudo -u postgres createdb -O nday nday_restore_test
sudo -u nday pg_restore -j 2 --no-owner -d 'postgresql:///nday_restore_test?host=/var/run/postgresql' /data/backup/daily/nday-YYYYMMDD.dump
# compare row counts, migration versions and so on, then:
sudo -u postgres dropdb nday_restore_test
```

Restoring into the production database for real (this loses everything written after the backup, so stop the services first):

```bash
sudo systemctl stop nday-web.service 'nday-collect@*.timer' nday-stats.timer nday-backup.timer
sudo -u postgres psql -c 'ALTER DATABASE nday RENAME TO nday_broken'          # rename it and keep it; drop it once you've confirmed the restore is good
sudo -u postgres createdb -O nday nday
sudo -u nday pg_restore -j 2 --no-owner -d 'postgresql:///nday?host=/var/run/postgresql' /data/backup/daily/nday-YYYYMMDD.dump
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday migrate'     # catches up on migrations when the binary is newer than the backup
sudo systemctl start nday-web.service nday-stats.timer nday-backup.timer
sudo systemctl start 'nday-collect@cvelist.timer' 'nday-collect@kev.timer' 'nday-collect@ghsa.timer' \
  'nday-collect@exploitdb.timer' 'nday-collect@metasploit.timer' 'nday-collect@nuclei.timer' 'nday-collect@nvd.timer'
```

After the restore, the collectors catch up on everything since the backup from their own cursors. If NVD hasn't been updated for more than 7 days, the first run re-reads the yearly files.
Data created on the site itself (users, comments and so on) after the backup can't be recovered.

## Firewall: Cloudflare IP ranges

On the origin, ufw denies inbound traffic by default. Port 22 is open to all addresses, and ports 80 and 443 are open only to the ranges Cloudflare publishes (one rule per range per port, with the comment `cloudflare`).
Cloudflare's lists are at https://www.cloudflare.com/ips-v4 and https://www.cloudflare.com/ips-v6 and change now and then.
`nday-cloudflare-ufw.timer` runs `/opt/nday/bin/nday-cloudflare-ufw` as root every 6 hours (starting at 00:15, 06:15, 12:15 and 18:15, plus up to 30 minutes of random delay).
The script is `deploy/firewall/nday-cloudflare-ufw.py` in the repo and uses only the Python standard library:

- **New ranges are allowed automatically.** **Ranges Cloudflare has removed are not deleted automatically.** They're only written to the log, and the run exits with status 3,
  so `nday-cloudflare-ufw.service` shows up in `systemctl --failed` until someone has looked at them and run `--prune` by hand (see below).
- It only manages rules in `ufw show added` that look like `ufw allow from <range> to any port <80|443> proto tcp comment 'cloudflare'`.
  The port 22 rule and any other rule are never added, changed or deleted, and after each change it checks that those rules are byte-for-byte the same as before. It never deletes rules by number.
- The fetched lists are validated before use: they must come over HTTPS (certificate verified, redirects not followed), every line must be a valid public range of the right address family, the prefix length must be in a sane range
  (IPv4 /12 to /32, IPv6 /24 to /64), and there must be at least half as many entries as are currently allowed and no more than the limit (IPv4 64, IPv6 32). If any check fails,
  nothing is changed and it exits with status 1 (which also shows up in `systemctl --failed`). It also refuses to run when ufw isn't enabled.
- When something changed, it writes the additions and deletions to the journal and writes the latest published list to `/etc/nday/cloudflare-ips.txt`. When nothing changed, it prints nothing.
- There's no active alerting yet: you need to look at `systemctl --failed` yourself (same as for backups).

**Your cloud provider's network firewall is a separate layer that this script can't manage.** If that layer also allows ports 80 and 443 only from Cloudflare's ranges,
then when Cloudflare adds a range you have to add it by hand in the provider's console, or origin pulls from the new range still won't reach the host. If that layer allows ports 80 and 443 from all addresses
(and the host's ufw does the restricting), you don't need to do anything. When `added:` shows up in the journal, check the console once.

Install (run from this directory):

```bash
sudo install -o root -g root -m 0755 firewall/nday-cloudflare-ufw.py /opt/nday/bin/nday-cloudflare-ufw
sudo install -o root -g root -m 0644 systemd/nday-cloudflare-ufw.service systemd/nday-cloudflare-ufw.timer /etc/systemd/system/
sudo /opt/nday/bin/nday-cloudflare-ufw --dry-run     # see what it plans to do first; changes nothing
sudo systemctl daemon-reload && sudo systemctl enable --now nday-cloudflare-ufw.timer
sudo systemctl start nday-cloudflare-ufw.service && systemctl status nday-cloudflare-ufw.service --no-pager | head -5
```

Day to day:

```bash
systemctl list-timers nday-cloudflare-ufw.timer
journalctl -u nday-cloudflare-ufw.service -n 30      # added: / deleted: / the reason a validation failed
sudo /opt/nday/bin/nday-cloudflare-ufw --dry-run     # the difference from Cloudflare's current lists
```

When the service fails, look at the journal first. If it says "no longer published by Cloudflare, still allowed", make sure those ranges really are gone from
https://www.cloudflare.com/ips/ before you delete them:

```bash
sudo /opt/nday/bin/nday-cloudflare-ufw --prune --dry-run   # lists the rules that would be deleted
sudo /opt/nday/bin/nday-cloudflare-ufw --prune
sudo systemctl reset-failed nday-cloudflare-ufw.service
```

After changing the script, run the tests first (a fake ufw, so the real firewall isn't touched): `python3 deploy/firewall/nday_cloudflare_ufw_test.py`.

## Everyday checks

```bash
systemctl list-timers 'nday-*'
journalctl -u nday-collect@kev.service -n 30
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday status'
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday hot --since 7d'
```

## Known gaps

- Off-site backup (encrypt the daily backup and ship it to object storage or another machine; the local daily backup already exists, see "Backup and restore").
- Active alerting for failed backups.
- Alerting for failed collection.
