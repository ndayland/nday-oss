# nday

Vulnerability intelligence collection and storage for nday.land. The core idea is to record each vulnerability's lifecycle as a timeline of events
(disclosure → patch release → technical analysis → public PoC → exploited in the wild → added to CISA KEV).
A vulnerability's "current stage" is derived from its events, never maintained by hand.

Every event stores two timestamps: `occurred_at` (the time the source claims; can be empty, and we never make one up)
and `observed_at` (when our collector first saw it). Events from a collector's first bulk import are marked
`is_backfill = true`, and their `observed_at` doesn't reflect when they actually became visible.

## Local development

You need Go (see `go.mod`; the module is `nday.land/nday`) and Docker.

```sh
docker compose up -d                 # PostgreSQL 16, host port 54329
cp .env.example .env
go run ./cmd/nday migrate
go run ./cmd/nday collect kev
go run ./cmd/nday status
go run ./cmd/nday serve --listen 127.0.0.1:8080   # website + JSON API
go test ./...                        # each test gets its own schema in the nday_test database; no network
```

A production build is `CGO_ENABLED=0 go build -o nday ./cmd/nday`. For deploying it, see `deploy/README.md`. For the other subcommands, run `nday -h`.

## Layout

- `cmd/nday/`: the entry point. It only calls `internal/cli`.
- `internal/cli/`: the command line (`migrate`, `collect`, `serve`, and so on).
- `internal/collector/`: the collector interface (read its package doc before writing a new one) and one package per source. `internal/registry/` lists them.
- `internal/pipeline/`: fetch, store raw data, normalize, idempotent write, update collection state.
- `internal/web/`, `internal/webui/`, `internal/site/`: the JSON API, the HTML site and the query layer behind them.
- `migrations/`: SQL migrations, run in numeric order and embedded in the binary.
- `docs/`: design notes per area. Start with `docs/go.md`.
- `deploy/`: server setup and operations.

## Python reference

`src/nday/` is the original Python implementation. It's kept as the behavioural reference: the Go collectors are checked against goldens generated from it (`tools/dump_golden.py`, see `docs/go.md`). It has its own `pytest` suite (`python3.13 -m venv .venv && .venv/bin/pip install -e '.[dev]' && .venv/bin/pytest`). Production runs the Go binary.

## License

nday is free software under the GNU Affero General Public License v3.0 (AGPL-3.0-only); see `LICENSE`. If you run a modified version as a network service, you have to offer its source to the people using it.

The nday name and the logos under `assets/brand/` aren't covered by that license. Please don't use them for your own deployment.
