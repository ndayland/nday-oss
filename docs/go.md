# The Go implementation

The Python implementation (`src/nday`) is the behavioural reference. The Go binary runs against the same PostgreSQL database in place,
with no data changes. This file covers how the Go code is laid out, how parity with Python is checked, and the steps for porting a
collector from the Python reference.

## Layout

| Path | What it does |
|---|---|
| `cmd/nday` | Executable entry point; only calls `internal/cli` |
| `internal/cli` | The command line: `migrate` / `collect` / `renormalize` / `status` / `hot`, with the same output and exit codes as Python; Go also adds `refresh-state` and `serve` |
| `internal/config` | `.env` loading (same rules as Python `load_dotenv`), `NDAY_DATABASE_URL`, `NDAY_MIGRATIONS_DIR` |
| `internal/db` | pgx connections; the migration runner (shares the `schema_migrations` bookkeeping table and the advisory lock id with Python) |
| `migrations/embed.go` | Embeds `migrations/*.sql` in the binary (the SQL files stay the single source of truth) |
| `internal/model` | RawRecord / VulnUpsert / Alias / Affected / Event / Normalized / CollectorState / FetchResult |
| `internal/pyjson` | Parsing/serialization that's byte-for-byte identical to Python `json`, plus `canonical_json`, `content_hash`, `repr()` |
| `internal/pystr` | Python `str.strip()` / `isspace()` / `splitlines()` semantics |
| `internal/collector` | The collector interface (the package doc is the porting guide), `NormalizeError`, `Text`, `ParseISODate` |
| `internal/collector/kev` | CISA KEV collector |
| `internal/collector/xposts` | X (Twitter) post collector (Go only): official API v2 recent search plus an allowlist; event type `social_post` (not a lifecycle stage). See `docs/xposts.md` |
| `internal/xconfig` | All the SQL for xposts' database configuration (the `x_accounts` allowlist and the `x_settings` run parameters); shared by the CLI and the admin back office |
| `internal/settings` | Settings stored in the database (`app_settings`): a registry of `NDAY_*` variables that can be stored, read/write, secret encryption (master key `NDAY_SETTINGS_KEY`), and snapshots (database > environment variable > default). Commands `nday settings` / `settings-set` / `settings-unset`; back office page `/admin/settings`. See `docs/settings.md` |
| `internal/httpc` | HTTP shared by collectors: common UA, timeouts, retry with backoff on 429/5xx/transport errors, Retry-After, size limit, injectable RoundTripper/sleep |
| `internal/pipeline` | fetch → store raw → normalize → idempotent upsert → collector_state; `Renormalize` (the offline parity check) |
| `internal/state` | Derived state: reading the `vuln_state_mat` materialized view (CLI hot, stage counts) and coordinating refreshes (`Refresh`) |
| `internal/site` | The website's query layer (hot, vulnerability detail, sources, stats, search, raw records); returns plain structs with json tags. The package doc is written for HTML authors |
| `internal/web` | HTTP server: JSON API routes, middleware (logging, panic recovery, timeout, cache headers), TTL + coalescing cache. See `docs/api.md` |
| `internal/webui` | The HTML site: server-side rendered (`html/template`), with templates, CSS, JS, fonts, and icons embedded in the binary. The view models (time formatting, lifecycle bar, chart coordinates, status sentence) are kept separate from the templates and have unit tests. Registered through `cli.ServeHook` |
| `internal/dbpool` | A fixed-size pool of `*pgx.Conn` (pgxpool isn't available as a dependency) |
| `internal/registry` | The table of collectors the CLI can run |
| `internal/testutil` | A separate schema per test, a fake RoundTripper, golden comparison |
| `tools/dump_golden.py` | Generates normalize goldens with the **Python** collectors |
| `tools/dump_pyref.py` | Generates basic-semantics references with **Python** (float repr, canonical JSON, strip, repr, fromisoformat) |
| `tools/hashparity` | Recomputes the hash of every `raw_record` row in the database from `payload::text` in Go and compares it with the stored value (read-only) |
| `tools/replay`, `tools/replay_py.py` | Run the full pipeline in Go / Python respectively, with the same local file standing in for the network |
| `tools/worldmap` | Generates the geometry for the back office visitor map, `internal/webui/worldmap_data.go`, from the Natural Earth admin-0 country GeoJSON (pinned release tag, downloaded by hand to a temp directory). The download and regeneration commands are in the package comment of `tools/worldmap/main.go` |

## Common commands

```sh
go test ./...                                   # needs a local container; each test uses its own schema, so tests can run concurrently
gofmt -l . && go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o nday ./cmd/nday   # production linux/amd64

.venv/bin/python tools/dump_golden.py [name]    # regenerate goldens (Python behaviour wins)
.venv/bin/python tools/dump_pyref.py            # regenerate the basic-semantics references
go run ./tools/worldmap -tag v5.1.2 -shapes DIR/ne_110m_admin_0_countries.geojson \
  -points DIR/ne_50m_admin_0_countries.geojson -out internal/webui/worldmap_data.go   # back office map geometry (see tools/worldmap/main.go for downloading DIR)

# Parity check (always on a snapshot database; don't touch nday)
docker compose exec -T db sh -c 'createdb -U nday nday_parity && pg_dump -U nday nday | psql -q -U nday nday_parity'
export NDAY_DATABASE_URL=postgresql://nday:nday@127.0.0.1:54329/nday_parity
go run ./cmd/nday migrate                       # must print "applied: (none, up to date)"
go run ./tools/hashparity                       # matched/mismatched for each source
go run ./cmd/nday renormalize <source> --dry-run   # must be 0 insert / 0 update
```

Test database: `NDAY_TEST_DATABASE_URL` (default `postgresql://nday:nday@127.0.0.1:54329/nday_test`;
the database name must contain `test`, and it's created automatically if missing). Each test creates a
`go_test_<pid>_<nanoseconds>_<random>` schema, the connection's `search_path` points only at it, and it's dropped with
`DROP SCHEMA ... CASCADE` at the end. Tests never touch `public` (which the Python tests use) or anyone else's schemas.
Set `NDAY_TEST_SKIP_DB=1` to skip the database tests.

## Derived state and the website (Go only)

- `migrations/0003_vuln_state_mat.sql`: `vuln_state_mat` is `vuln_state` plus a few columns the website needs
  (`has_disclosed`, `has_itw`/`itw_at`, `poc_sources` — exploitdb, metasploit, nuclei and, since 0032, github —, `last_transition_event_id`). Its unique index supports
  `REFRESH ... CONCURRENTLY`, so readers are never blocked. The single-row table `vuln_state_refresh` records request/completion sequence numbers.
  Search uses a `vuln (cve_id COLLATE "C")` index and a pg_trgm GIN index (skipped if you lack permission to create the extension, in which case search falls back to a sequential scan).
  `vuln_state` is still the definition.
- After every successful collection (after the data transaction commits), `pipeline` calls `state.Refresh` in no-wait mode. When several collectors finish at the same time,
  only one session refreshes; the others register a request and return right away, and the lock holder checks again when it's done and refreshes once more if needed.
  Requests aren't lost and don't queue up.
  A failed refresh is only logged (`collector_state` stays ok). `nday refresh-state` refreshes by hand (wait mode).
- `nday serve [--listen addr] [--tls-cert f --tls-key f [--tls-client-ca f]]`: the read-only JSON API (`docs/api.md`) and the HTML pages (`internal/webui`, registered by `cmd/nday` through `cli.ServeHook`). HTML routes are registered with `web.Server.Handle`
  and reuse the same middleware (see the `internal/web` package doc).

## Checklist for porting a collector

1. Read the Python collector and its tests all the way through. The `name` must be exactly the same as in Python.
2. Create `internal/collector/<name>/` and implement `collector.Collector` (see the `internal/collector`
   package doc):
   - `Fetch(ctx, state)`: do all HTTP through `httpc.New(httpc.Options{Transport: deps.Transport, ...})`, and
     copy the retry/timeout/limit values from the Python constants (`_feed.py`: 4 attempts, 1/2/4 s, Retry-After capped at 60 s,
     64 MiB). Always parse upstream JSON with `pyjson.Decode`, **never** `encoding/json`
     (otherwise the content hash won't match what's in the database, and taking over would re-store every raw record).
     For non-JSON sources (CSV, etc.), build the same payload Python builds: strings, `pyjson.Int`
     (Python int), `float64` (Python float), `*pyjson.Object` (keeps insertion order).
   - The cursor uses pyjson values (`*pyjson.Object` or `map[string]any`), with the same keys and value types as Python.
   - `Normalize(rec)`: a pure function. Use `collector.Text` for string values (Python `_text`, with the strip semantics where
     `\x1c-\x1f` also count as whitespace); use `collector.ParseISODate` for dates
     (= `date.fromisoformat`); for other time formats, write the parser the way Python's does and add a reference
     the way `dump_pyref.py` does. `Event.Detail` values pass straight through as the upstream pyjson values.
     In Python, `p.get(k)` on a missing key gives None, so in Go it must be `nil`
     (jsonb distinguishes null from a missing key).
   - Return `collector.NormalizeErrorf(...)` for a bad record, with the same message text as Python
     (Python's `{x!r}` becomes `pyjson.Repr`). Where Python would raise a non-NormalizeError exception,
     Go returns a plain error (the whole run fails).
   - If it needs on-demand backfill, implement `collector.WantsMissingCVEs` and set
     `RawRecord.IsBackfill = true` only on records fetched because they were wanted.
   - Read the configuration once in the Factory from `deps.LookupEnv` (like Python, it doesn't read `.env`; see below).
3. Register it in `internal/registry/registry.go` and remove its name from `PythonOnly`.
4. Golden: add a fixture to `CASES` in `tools/dump_golden.py` (use `"fetch"` for a single-file feed and `"records"` for
   hand-written edge cases; the format is in the script's docs), run `.venv/bin/python tools/dump_golden.py <name>`,
   and write the Go test: `testutil.CheckGolden(t, "internal/collector/<name>/testdata/golden/<x>.golden.json", newC)`.
   If a golden fails, fix the Go code to match Python; don't change the golden.
5. Port Python's pipeline + DB tests (see `internal/collector/kev/kev_test.go`). Use `testutil.FakeTransport`
   for all network access and `testutil.NewMigratedDB(t)` for the database; `t.Parallel()` is fine.
6. Quality gates: `go test ./...`, an empty `gofmt -l .`, `go vet ./...`, and a linux/amd64 build.
7. Parity: on a fresh snapshot, `go run ./tools/hashparity -source <name>` (must show 0 mismatches,
   otherwise explain each kind) and `go run ./cmd/nday renormalize <name> --dry-run` (must be 0/0).
   Note that renormalize only finds differences that would trigger a write: stub vulns (only empty fields get filled) and events that already
   have an occurred_at won't expose a difference. So the golden tests and "run the same download through Go and Python into two fresh databases, then
   compare with SQL" (`tools/replay` + `tools/replay_py.py`) are still needed.

## `nday renormalize <source> [--dry-run]` (Go only)

Re-normalizes the latest raw_record for each key of the source (`fetched_at DESC, id DESC`),
going through exactly the same apply path as collect and printing the same stats JSON. It doesn't touch the network or change collector_state.
With `--dry-run` the whole transaction is rolled back. It differs from `collect --renormalize` in that it processes records in source_key order,
and in that `RawRecord.is_backfill` isn't stored in the database, so events this command creates are always `is_backfill=true`
(they come from existing data, not live observation), and `is_backfill` in the stats is also true.

## Intentional differences from Python / Python quirks kept

- The text of `collector_state.last_error` when a run fails: Python's is `f"{type(exc).__name__}: {exc}"`,
  Go's is `<Go error type name>: <Go error text>` (also truncated to 2000 characters), so the wording differs.
- On failure Python prints a traceback and Go prints `error: ...`; the exit code is 1 in both cases, and usage errors are 2 in both.
- `nday collect <a source not yet ported>` exits with 2 and says "not ported to Go yet".
- The KEV download: like Python, no retries and a 60 s timeout; Go also adds a 64 MiB size limit.
- The log formats differ (Go uses slog text format, all to stderr); stdout is the same.
- When `NDAY_MIGRATIONS_DIR` is set to an empty string, Python uses the current directory and Go treats it as unset (it uses the embedded migrations).
- The migration filename regex is ASCII in Go (Python's `\w` supports Unicode); don't use non-ASCII filenames.
- GHSA-keyed vulnerabilities ([ghsa.md](ghsa.md)): both sides normalize an advisory without a CVE the same way (the goldens check it),
  and neither makes a stub vuln for a GHSA id. Only Go redirects rows written under a GHSA id that's already an alias, merges a GHSA-keyed
  vuln into its CVE when the alias appears (`internal/pipeline/merge.go`), drops the advisory's `disclosed` event when the CVE record's
  arrives, and leaves GHSA ids out of `missing_cves` (Python leaves them out too, but only so the casts don't fail). On a database where
  an advisory gained a CVE, the Python pipeline leaves both the GHSA-keyed row and the alias in place.
- Python behaviours kept as they are (not fixed):
  - `is_valid_cve_id`'s `\d` matches any Unicode digit (for example the full-width `CVE-２０２４-1234` counts as valid),
    and the database CHECK constraint then rejects it on write, so the whole run fails. Go uses `\p{Nd}` to stay consistent.
  - `cmd_collect` builds the collector first and loads `.env` afterwards, so collector settings that exist only in `.env`
    (such as `NDAY_CVELIST_*`) have no effect. Go keeps the same order.
  - For unchanged records, `collect --renormalize` sets `is_backfill = whether this is the first run` on the newly produced events,
    so on an incremental run they're marked false with observed_at set to the time of this run, which makes them look like live observations.
