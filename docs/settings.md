# nday database settings (`app_settings`)

Some `NDAY_*` settings can be stored in the database (table `app_settings`, migration `0014_settings.sql`). An admin changes them in the admin UI at `/admin/settings`,
with no need to edit `/etc/nday/*.env` and restart. Code: `internal/settings` (registry, storage, encryption, snapshot), `internal/cli/runtime.go` (validation and apply inside the web process),
`internal/cli/settings.go` (command line and collector jobs), `internal/admin/settings.go` and `api_settings.go` (admin endpoints), `internal/webui/admin_settings.go` (the page).

## 1. Precedence

**database > environment variable > built-in default**, decided key by key:

- For a key in the registry (`settings.Defs()`), if the database has a usable row, its value is used.
- With no row (or an unusable row, see section 6), the environment variable of the same name is used; if that's empty, the built-in default applies.
- Keys outside the registry are **never read from the database**, even if the table has a row of the same name (it's ignored, with a warning).

The admin page shows, for each key, where the value in effect comes from (database / environment / default). **The page and the endpoints never show an environment variable's value**, only its source. A plain value stored in the database is shown; a secret shows only "set · ends in xxxx" or "not set".

## 2. Which keys can go into the database

63 in total, in four groups (page order: collectors / discussions / sign-in / hot list). Keys marked "secret" are stored encrypted and can only be entered in the admin UI, and keys marked "restart" take effect only after the website restarts.

| group | keys |
|---|---|
| collectors (8) | `NDAY_CVELIST_BOOTSTRAP_DAYS`, `NDAY_CVELIST_MAX_FILES`, `NDAY_CVELIST_BACKFILL_RETRY_DAYS`, `NDAY_GHSA_BOOTSTRAP_DAYS`, `NDAY_GHSA_MAX_REQUESTS`, `NDAY_GHSA_OVERLAP_MINUTES`, `NDAY_GITHUB_TOKEN` (secret), `NDAY_X_BEARER_TOKEN` (secret) |
| discussions (31) | `NDAY_DISCUSS` (restart), `NDAY_DISCUSS_POST_BURST` / `_POST_EVERY` / `_POST_DAILY`, `NDAY_DISCUSS_NEW_POST_BURST` / `_NEW_POST_EVERY` / `_NEW_POST_DAILY`, `NDAY_DISCUSS_NEW_ACCOUNT_AGE` / `_NEW_ACCOUNT_COMMENTS`, `NDAY_DISCUSS_ADDR_BURST` / `_ADDR_EVERY`, `NDAY_DISCUSS_EDIT_BURST` / `_EDIT_EVERY`, `NDAY_DISCUSS_REPORT_DAILY` / `_REPORT_BURST` / `_REPORT_EVERY`, `NDAY_DISCUSS_DELETE_BURST` / `_DELETE_EVERY`, `NDAY_DISCUSS_READ_BURST` / `_READ_EVERY`, `NDAY_DISCUSS_MOD_BURST` / `_MOD_EVERY`, `NDAY_DISCUSS_DUPLICATE_WINDOW`, `NDAY_DISCUSS_GUEST_READ` (whether signed-out visitors can read comments, on/off, default on; when off they only get an outline; applies on save), `NDAY_DISCUSS_GUEST_READ_BURST` / `_GUEST_READ_EVERY` (per-address rate limit for signed-out comment reads, default 60 / 2s). Also the reader-correction limits (shown in the same group as the discussion limits, applies on save, see `docs/corrections.md` §4): `NDAY_CORRECTIONS_DAILY`, `NDAY_CORRECTIONS_OPEN_PER_VULN`, `NDAY_CORRECTIONS_OPEN_PER_USER`, `NDAY_CORRECTIONS_BURST` / `_EVERY` |
| sign-in (20) | `NDAY_AUTH_GITHUB_CLIENT_ID`, `NDAY_AUTH_GOOGLE_CLIENT_ID`, `NDAY_AUTH_X_CLIENT_ID`, `NDAY_AUTH_APPLE_SERVICES_ID`, `NDAY_AUTH_APPLE_TEAM_ID`, `NDAY_AUTH_APPLE_KEY_ID`, `NDAY_AUTH_PASSKEYS`, `NDAY_AUTH_PASSKEY_SIGNUP`, `NDAY_AUTH_PASSKEY_SIGNUP_DAILY`, `NDAY_AUTH_PASSKEY_SIGNUP_INTERVAL`, `NDAY_AUTH_MAX_PASSKEYS`, `NDAY_AUTH_SESSION_IDLE`, `NDAY_AUTH_SESSION_MAX`, `NDAY_AUTH_SENSITIVE_WINDOW`, `NDAY_AUTH_HANDLE_HOLD`, `NDAY_TERMS_VERSION`, `NDAY_AUTH_GITHUB_CLIENT_SECRET` (secret), `NDAY_AUTH_GOOGLE_CLIENT_SECRET` (secret), `NDAY_AUTH_X_CLIENT_SECRET` (secret), `NDAY_AUTH_APPLE_KEY` (secret) |
| hot list (4) | `NDAY_HOT_PIN_MAX` (the most rows to pin, 0–20, default 10; when the rule selects fewer than this, the rest are filled from the top of the "Researchers are discussing" ranking (`/discussed`); 0 = pinning off, and the fill is off too), `NDAY_HOT_PIN_RESEARCHERS` (the minimum `researchers_7d`, 1–100, default 2), `NDAY_HOT_PIN_RECENT_HOURS` (the latest researcher post is at most this many hours old, 1–168, default 72), `NDAY_HOT_PIN_WAVE_DAYS` (the largest gap between neighboring posts within one wave of discussion, and also the most days ago the wave may have started, 1–30, default 7). The rules are in `internal/site/pin.go` and `pinned` under `/api/hot` in `docs/api.md` |

Each key's meaning, range and default are in the description under that key on the admin page (consistent with `docs/discuss.md` §5, `docs/auth.md` §6 and `.env.example`). Validation uses the original validation functions (`auth.FromEnv`, `discuss.Enabled` / `LimitsFromEnv`, the constructors of the cvelist / ghsa / xposts collectors, `site.PinConfigFromEnv`, `corrections.LimitsFromEnv`).

### Environment-only keys

| key | why |
|---|---|
| `NDAY_DATABASE_URL` | Needed before the database can be reached |
| `NDAY_SETTINGS_KEY` | The master key can't live in the database it protects |
| `NDAY_AUTH_SECRET`, `NDAY_AUTH_SECRET_PREVIOUS` | The server secret for session cookies and CSRF. It's fixed for the life of the process, and changing it signs everyone out, so it has to be a deliberate deploy operation |
| `NDAY_PUBLIC_URL`, `NDAY_API_URL`, `NDAY_AUTH_RP_ID`, `NDAY_AUTH_ORIGINS` | Host routing, cookie scope and the WebAuthn RP are fixed at startup and can't change while running (`auth.Service.CheckReconfigure` refuses) |
| `NDAY_AUTH_APPLE_KEY_FILE` | Points at a file on disk; to keep the PEM text in the database, use `NDAY_AUTH_APPLE_KEY` |
| `NDAY_LISTEN`, `NDAY_TLS_*`, `NDAY_LOG_DIR` | The listener, certificates and log directory are opened at startup |
| `NDAY_DB_POOL_SIZE`, `NDAY_DISCUSS_DB_POOL_SIZE` | The connection pools are built at startup |
| `NDAY_I18N_DEBUG`, backup settings (`NDAY_BACKUP_*`) | Development/operations switches, unrelated to application configuration |

## 3. The master key `NDAY_SETTINGS_KEY`

Secrets are stored only as ciphertext, and the key comes from the environment variable `NDAY_SETTINGS_KEY` (only in the environment; never stored in the database or logged).

- **Generate**: `openssl rand -base64 32` (base64, standard or URL alphabet, with or without padding; after decoding it must be at least 32 bytes with at least 16 distinct byte values, and obviously non-random values such as all zeros are rejected).
- **Where to put it**: `/etc/nday/nday.env` (`root:nday` 0640). Every unit (the website, each collector job, stats, backup) loads this file, so they can all decrypt the secrets in the database (see section 8 for the trade-off).
- **Not set**: plain settings work as usual; the admin UI can't save secrets (`409 no_master_key`, and the page disables the secret inputs and says why); secrets already in the database can't be read and are treated as "not in the database" (the environment variable is used), though stored ones can still be cleared.
- **Lost**: **none** of the secrets in the database can be read, and each process falls back to environment variables (there's a warning in the logs and at the top of the admin page, naming only the keys). You need to generate a new master key and **re-enter** each secret in the admin UI (entering one overwrites the old ciphertext). When the website starts, if a sign-in method is left with only half of its configuration because of this (for example the Client ID is still in the database but the Secret can't be decrypted), only **that sign-in method's** database rows are ignored (see section 6); other sign-in methods, passkeys and the remaining database settings keep working.
- **Rotation**: there's no automatic re-encryption. The steps: generate a new key and put it in `nday.env` → restart the website (`systemctl restart nday-web`) → re-enter each secret in `/admin/settings` (after the key change the old ciphertext can't be read, and the page shows "stored, cannot be decrypted") → confirm the source is back to "database". Until a secret is re-entered it falls back to the environment variable; where the environment has none, the feature pauses (for example X collection is skipped, and that sign-in method is unavailable; note that a "partial configuration" of a sign-in method is rejected, see section 6).

### Encryption format

- A 256-bit key is derived from the master key with HKDF-SHA256 (info `nday settings seal v1`), and the cipher is AES-256-GCM.
- Stored as `version (1 byte, =1) | nonce (12 bytes, random) | ciphertext+tag`. The additional data (AAD) is the key name, so one ciphertext can't be moved to another key.
- The `hint` column: for a secret of at least 24 characters that isn't a PEM it stores the last 4 characters, to help tell secrets apart; otherwise it's empty.
- When decryption fails (wrong key, corrupted data) it reports only "cannot be decrypted" and reveals nothing else.

## 4. When changes take effect

| who | when it reads the database |
|---|---|
| Collector jobs (`nday collect …`) | At the **start of every run** (database values are layered over the environment); a change takes effect from the next run |
| The website (`nday serve`) | Once at startup; after that, **saving in the admin UI takes effect right away**: the save endpoint validates and writes to the database in one transaction, and after the commit the runtime **re-reads the database** and applies the configuration now in it to the running process (sign-in `auth.Service.Reconfigure`, discussion limits and the guest-read switch `discuss.Service.SetLimits`, the `/admin/x` user-lookup token, hot-list pinning `site.Store.SetPinConfig`, reader-correction limits `corrections.Service.SetLimits`). Reading the database and applying happen serially under one lock, so when two admins save at the same time, whichever "apply" runs first, the process ends up in the state of the last commit in the database |
| Commands such as `nday auth-gc` and `nday x-accounts-import` | Read the database on every run |

Exceptions:

- `NDAY_DISCUSS` decides at startup whether the discussion routes are mounted, so it **needs a restart** of the website (the page says "applies after a restart").
- Sign-in going **from fully off to on** needs a restart (the sign-in routes are mounted at startup; while it's fully off you can't even reach the admin UI). Conversely, the admin UI **can't turn sign-in off entirely** (`422 sign_in_off`); if you need that, change the environment variables and restart.
- The HTML of public pages has a 60-second shared cache, so page content that depends on settings (for example the discussion state) can be up to 60 seconds late.
- After you change the database from the command line (`nday settings-set` / `settings-unset`), the website process **doesn't notice automatically**. It picks the change up the next time someone saves in the admin UI (a save re-reads the database and applies everything, so command-line changes take effect too; even a save that changes nothing re-applies) or when the website restarts.

## 5. Admin page and endpoints

`/admin/settings` (admins only, nav item "settings"): three groups, collectors / discussions / sign-in, each with a form and a "save this group" button. There are jump links to each group at the top of the page. Each plain setting is one row: its name (`admin.set.name`, the main label) with the key name beside it in small monospace (the name used on the command line and in environment variables), a description, an input (the database value; empty = not set in the database), a source badge, and when it takes effect (per section 4: for the collectors group "applies from the next collector run", `NDAY_X_BEARER_TOKEN` is "collector: from its next run; /admin/x lookups: at once", `NDAY_DISCUSS` is "applies after a restart", and everything else is "applies at once"; see `settingEffect` in `internal/webui/admin_settings.go`). When a key is added to the registry, its name and description must be added to `keys.json` and the en / zh-Hans catalogs (`TestSettingNames`). `NDAY_DISCUSS`, `NDAY_DISCUSS_GUEST_READ`, `NDAY_AUTH_PASSKEYS` and `NDAY_AUTH_PASSKEY_SIGNUP` use a dropdown (not set in the database / on / off). Secrets get their own rows: only the state and source are shown, with a password input (a text box for the Apple private key) and "save / replace" and "clear" buttons. A stored secret also has a checkbox "clear it with this group's save" in the group form (for example to remove a sign-in method's Client ID and Secret together; removing either one alone is rejected as a "partial configuration"). No secret value, and no environment variable value, is ever in the page HTML. After a save the sources and states update in place without reloading the page; if you've been signed in too long, the existing re-sign-in panel pops up.

Endpoints (the same checks as the other `/api/admin/*`: admin, POST, same origin, CSRF, rate limit, recent sign-in → `403 reauth_required`):

| endpoint | request body | notes |
|---|---|---|
| `POST /api/admin/settings` | `{"set":{"NDAY_…":"value",…},"unset":["NDAY_…",…]}` (≤64 KiB) | `set` takes only plain settings; `unset` takes any registry key (clearing a secret needs no value) |
| `POST /api/admin/settings/secret` | `{"key":"NDAY_…","value":"…"}` (≤16 KiB) | Save/replace one secret |
| `POST /api/admin/settings/secret/clear` | `{"key":"NDAY_…"}` | Clear one secret |

Success: `200 {"ok":true,"changed":[keys],"restart":[the keys among them that need a restart],"settings":{key:{"source":"db|env|default","stored":…,"restart":…,"value":"the plain value in the database"|"set":…,"hint":"…"}}}`.
Errors: `503 settings_off` (the process isn't wired to the settings runtime), `400 unknown_setting`, `400 secret_setting` (a secret sent to the plain endpoint), `400 not_secret` (a plain key sent to the secret endpoint), `400 bad_setting` (`fields`: key → `value`|`conflict`), `400 bad_secret`, `409 no_master_key`, `422 invalid_config` (`keys`: the keys involved), `422 sign_in_off`, `500 not_applied` (written to the database and committed, but the running website couldn't apply it; it takes effect after a restart; the ERROR log records only key names).

Every write: in one transaction, `LOCK TABLE app_settings` → read the current rows → build the candidate configuration → validate it as a whole in the runtime (on failure nothing is written, and the error names only keys) → write the rows and the audit record → commit → apply (the runtime re-reads the database and applies the state now in it). A plain setting whose value equals the database's, or clearing a row that doesn't exist, counts as "no change": nothing is written to the database or the audit log, but the state in the database is **still applied once**, so after a `500 not_applied`, clicking save again (without changing any value) is the retry. The `500 not_applied` response body also carries `settings` (the committed state in the database), and the page uses it to update the source badges and clear the secret inputs while showing the "saved but not applied" error.

**Secrets aren't compared for equality**: when you save/replace a secret, whether or not the submitted value equals the one in the database, it's always re-encrypted and written, a `settings.secret_set` audit record is written, and the response always has `changed:[key]`. Otherwise someone holding an admin session could use a "no change" response to quietly verify guesses at a secret. **A secret's value never appears** in responses, errors, logs or audit records; and the request body doesn't go into the access log either (the access log records only method, path, status, byte count and so on, and for the request body only its length: `AccessLog` in `internal/web/middleware.go`, `AccessLogFile` / `countingBody` in `internal/web/logfiles.go`).

## 6. Bad values and secrets that can't be decrypted

- A database value fails validation (for example someone wrote a bad value with SQL): a collector job warns (naming only the key) and builds that collector from **the environment only**; at startup the website likewise falls back to the environment by part (sign-in / discussions / X lookup) and warns; `nday auth-gc` falls back to the environment and warns.
- At website startup the sign-in part **degrades step by step**: when the layered sign-in configuration is rejected, it first finds the sign-in method the rejection names (GitHub / Google / X / Apple) and ignores **all of that method's database rows** together (Client ID, Secret; for Apple the Services ID / Team ID / Key ID / private key), so that method uses the environment (or is off if the environment has nothing), logs one WARN per ignored method (key names only), and retries; only if it still fails (for example `NDAY_AUTH_SESSION_IDLE` is a bad value) does it fall back to the environment only as a whole. If the final result is "sign-in fully off" while the database actually has sign-in-related rows, it logs one more **ERROR**-level message saying the admin UI can't be reached right now, and that the way to recover is to inspect with `nday settings`, delete the bad row with `nday settings-unset KEY --yes` (or fill in the environment variables) and restart (section 8). A save at runtime (`Apply`) doesn't degrade like this: it was validated as a whole before saving.
- When the environment **alone** isn't a valid configuration (for example `auth.env` has only the Client ID left because the Secret was moved into the database and removed from the env file; or Apple's `NDAY_AUTH_APPLE_KEY_FILE` was removed and the private key is in the database; or an environment variable for some discussion limit is bad but the database has a valid value), the website **reads the database first** at startup: if the whole configuration with the database layered over the environment is valid it starts with it (with a WARN saying "the environment alone is invalid, completed by database settings"); only if the database has no usable row, can't be read, or the layered result is still invalid does it refuse to start with the original environment error (the message is the same as before). `NDAY_DISCUSS_DB_POOL_SIZE` is environment-only, and when it's invalid startup is always refused.
- A secret that can't be decrypted (no master key, a changed master key, corrupted data), a plain key stored as ciphertext, a secret stored as plaintext, or a key not in the registry: that row has no effect and is treated as the environment variable; a warning (key name and reason only) goes to the log and also shows at the top of the admin page.
- Validation is whole-configuration: the database values and the environment variables together must form a valid configuration (for example a sign-in method's Client ID and Secret are either both present or both absent, wherever each comes from). One sign-in method's ID and Secret **can come separately from the database and the environment** (for example the ID stays in `auth.env` and the Secret is only in the database), and both on save and at startup (the previous point) the judgment is made on the layered whole.

## 7. Audit

Target type `setting`; `details` has key names only and never values:

| action | source | object id | `details` |
|---|---|---|---|
| `settings.update` | the admin UI saving plain settings | the key when it's one key, the group name (`collectors`/`discuss`/`auth`/`hot`) when several keys of one group, `settings` across groups | `{"set":[…],"unset":[…]}` |
| `settings.update` | `nday settings-set` | the key | `{"keys":[key]}` |
| `settings.unset` | `nday settings-unset` | the key | `{"keys":[key]}` |
| `settings.secret_set` | the admin UI saving/replacing a secret | the key | `{"keys":[key]}` |
| `settings.secret_clear` | the admin UI clearing a secret (on its own or with a group save) | the key | `{"keys":[key]}` |

On the audit page these records link to `/admin/settings#s-<key>`.

## 8. Emergency commands (on the server)

`nday settings` and `settings-set` need to see **the website's whole environment** (the same files `nday-web.service` loads): whole-configuration validation needs `NDAY_PUBLIC_URL` from `web.env` and `NDAY_AUTH_SECRET` from `auth.env` (with only `nday.env` loaded, once sign-in is in the database, changing any key is rejected, and `settings-set` tells you to load these two files after the error), and the source column is also judged by this process's environment (when a file is missing, those keys show up as `default`). `web.env` has comments, so you can't expand it with `env $(cat …)`; load it with `set -a; . file` instead (all inside the subshell of `sudo -u nday sh -c '…'`, so your current shell is unaffected):

```bash
sudo -u nday sh -c 'cd /opt/nday && set -a; . /etc/nday/nday.env; . /etc/nday/web.env; . /etc/nday/auth.env; [ -f /etc/nday/xposts.env ] && . /etc/nday/xposts.env; set +a; /opt/nday/bin/nday settings'                    # each key's source and plain value in the database; secrets show only set and the last characters
sudo -u nday sh -c 'cd /opt/nday && set -a; . /etc/nday/nday.env; . /etc/nday/web.env; . /etc/nday/auth.env; [ -f /etc/nday/xposts.env ] && . /etc/nday/xposts.env; set +a; /opt/nday/bin/nday settings-set KEY VALUE --yes'  # validates the whole configuration, then writes a plain setting (audited)
sudo -u nday sh -c 'cd /opt/nday && env $(cat /etc/nday/nday.env) /opt/nday/bin/nday settings-unset KEY --yes'          # deletes the row in the database, back to the environment variable/default (audited; this also clears a secret)
```

`settings-unset` doesn't validate the whole configuration; it needs only `NDAY_DATABASE_URL` (`nday.env`).

Secrets **can't** be written from the command line (the value would show up in the process list and shell history); enter them only in the admin UI. After a command-line change, the website notices only at the next admin save or restart (section 4).
When you can't get into the admin UI (for example the sign-in settings in the database are broken), delete the rows involved with `settings-unset` to go back to the environment's configuration, then restart the website.

## 9. Threat-model trade-offs

- **Isolation is weaker**: if `NDAY_X_BEARER_TOKEN` stays in a separate `/etc/nday/xposts.env`, only the xposts collector unit and the website get it. Once it's in the database, the master key is in `nday.env`, which **every unit can read**, so any collector job (if compromised) can decrypt the X token and the other secrets from the database. The isolation of "other collector jobs can't get the X token" no longer holds; secrets that need that isolation should stay only in their own env file and not go into the database.
- **Backups**: `nday-backup` puts a tar of `/etc/nday` (including the master key) and the database dump in the same backup root (`$NDAY_BACKUP_DIR/config/` and `daily/`, `weekly/`). If the whole backup is taken, the encryption gives no protection. Encryption guards against "getting only the database or only the dump".
- Someone who can act as an admin through the admin UI (recent sign-in) can replace a secret but can't see the old value; someone who can read both the database and `nday.env` can decrypt all the secrets.
- Pages, endpoints, logs, audit records and error messages contain no secret values; the formatted output of `settings.Snapshot` and `settings.Key` is redacted.
- Secrets are saved without an equality comparison (section 5), so the admin endpoint can't be used as an oracle for "guessing right or not".
- The ciphertext is bound only to the key name (AAD), not to the `hint` column, the version or a time: someone with database write access can write back an older ciphertext for the same key (rolling back to an old secret), or rewrite `hint` so the page shows different last characters. Database write access can already change any setting (including breaking a plain setting outright or deleting a secret), so this is outside what the encryption protects against.
- A decoded master key with fewer than 16 distinct byte values (for example all zeros, a repeated short pattern, an ASCII word) is rejected as "not randomly generated" (treated as no master key, with a warning); generate it with `openssl rand -base64 32`.

## 10. Moving settings out of `/etc/nday/*.env`

1. Deploy the new binary and migrate: `… nday migrate` (`0014_settings`).
2. Generate the master key and put it in `/etc/nday/nday.env`: `echo "NDAY_SETTINGS_KEY=$(openssl rand -base64 32)" | sudo tee -a /etc/nday/nday.env`, then `sudo systemctl restart nday-web`. Keep another copy of the master key somewhere safe offline (see section 3 for what losing it means).
3. An admin signs in to `/admin/settings` and enters the values to move into the database (plain settings are saved by group; secrets are "save / replace"d one by one).
4. Confirm those keys' source badges now say "database" (or check `db` in `nday settings`).
5. From the matching env files (`auth.env`, `xposts.env`, `nday.env`), **remove only the lines that are now in the database**, then restart the website (`systemctl restart nday-web`); collector jobs see the new state on their next run.
   **Don't delete or rename the whole `auth.env`**: `NDAY_AUTH_SECRET` in it (and `NDAY_AUTH_SECRET_PREVIOUS`, `NDAY_PUBLIC_URL`, `NDAY_AUTH_RP_ID`, `NDAY_AUTH_ORIGINS`, `NDAY_AUTH_APPLE_KEY_FILE`, `NDAY_AUTH_DB_POOL_SIZE`) can only come from the environment, and `NDAY_TERMS_VERSION` is still here when it hasn't been moved into the database. Without `NDAY_AUTH_SECRET`, the startup log reports `NDAY_AUTH_SECRET is required` and an ERROR saying `sign-in is OFF`, and the sign-in entry point and the admin UI both disappear; put that line back into `auth.env` and restart to recover, and the settings in the database are unaffected. `xposts.env` has only the token line, so it can be deleted entirely once the token is in the database, as long as no unit references it with `EnvironmentFile=/etc/nday/xposts.env` without a leading `-` (also delete the drop-in for `nday-collect@xposts`, or change it to use `-`).
6. Verify: those keys are still `db` in `nday settings`; the website's startup log has no `settings:` warnings; sign-in, discussions, `/admin/x` lookups and the next xposts / ghsa collection all work.

Keys you don't want in the database can stay in the environment; you can mix the two.
