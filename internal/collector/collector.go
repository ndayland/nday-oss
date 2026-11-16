// Package collector defines the contract every nday source implements, plus
// the small pure helpers most collectors need. It is the Go port of
// src/nday/collectors/base.py; read this before porting a collector.
//
// # The contract
//
// A collector has a unique Name (it becomes raw_record.source, event.source
// and collector_state.source — it MUST equal the Python collector's name so
// the Go binary continues the same rows) and two methods:
//
// Fetch(ctx, state) (*model.FetchResult, error) — side effects allowed.
//   - state is the stored collector_state (Cursor from the last successful
//     run; state.IsFirstRun() when there has never been one).
//   - Return ALL upstream records you want considered, each with a stable
//     SourceKey and the verbatim upstream JSON as Payload, decoded with
//     pyjson.Decode (NOT encoding/json: the content hash must be byte-for-byte
//     Python's). Do not filter unchanged records yourself; the pipeline hashes
//     each payload and skips versions it already stored.
//   - Return the new cursor in FetchResult.Cursor (a pyjson value). It is
//     persisted only if the whole run succeeds.
//   - Do HTTP through httpc.Client (generic "nday-collector/0.1" User-Agent,
//     timeouts, retry/backoff honouring Retry-After, size cap; injectable
//     http.RoundTripper and sleep for tests). Never put personal names, emails
//     or hostnames in requests.
//   - Honour ctx (cancellation, deadlines).
//
// Normalize(rec) (*model.Normalized, error) — MUST be pure and deterministic.
//   - No I/O, no clock reads, no randomness, no map-iteration-order effects:
//     the pipeline sets observed_at and is_backfill itself.
//   - Event.OccurredAt is what the source claims; nil if unknown, never
//     fabricated. Put precision ({"precision": "day"}) and source facts in
//     Event.Detail using pyjson values (strings, pyjson.Int, float64, nil,
//     []any, *pyjson.Object, map[string]any) — usually upstream values passed
//     through untouched, so jsonb compares equal to what Python stored.
//   - VulnUpsert{Authoritative:false} for stub/secondary info (only fills
//     empty fields); Authoritative:true only for the canonical CVE source.
//   - Return a *NormalizeError (use NormalizeErrorf) for a malformed record:
//     the pipeline counts it, keeps the raw record, records
//     "<source_key>: <message>" in collector_state.last_error (status
//     "partial") and continues. ANY OTHER error aborts the whole run, exactly
//     like a non-NormalizeError exception in Python. Python messages often use
//     repr(); use pyjson.Repr / pyjson.StrRepr to keep last_error identical.
//   - Because raw payloads are kept, Normalize can be re-run later
//     ("nday collect <name> --renormalize" or, offline, "nday renormalize").
//
// Optional interfaces:
//   - WantsMissingCVEs (Python's wants_missing_cves/wanted_limit): the pipeline
//     fills state.Wanted before Fetch with CVE ids that are in vuln but for
//     which this source has never stored a raw record, newest first, at most
//     WantedLimit(). Mark records fetched only because they were wanted with
//     RawRecord.IsBackfill=true.
//   - io.Closer: called once after the run (Python's close()).
//   - Preparer (Go only): the pipeline calls Prepare with its connection
//     before Fetch, for collectors whose run configuration lives in the
//     database (xposts: allowlist and settings). Not called by renormalize.
//
// Pipeline guarantees (internal/pipeline): fetch -> store raw (skip unchanged
// by content hash) -> normalize changed records -> idempotent upserts ->
// update collector_state, all data writes in one transaction. Running a
// collector twice on unchanged upstream data creates zero new rows.
//
// Register the collector in internal/registry to expose it to the CLI.
package collector

import (
	"context"
	"fmt"
	"net/http"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/model"
)

// Collector is one upstream source. See the package documentation.
type Collector interface {
	// Name is the source name; equal to the Python collector's `name`.
	Name() string
	// Fetch fetches upstream records and the new cursor. May do network I/O.
	Fetch(ctx context.Context, state model.CollectorState) (*model.FetchResult, error)
	// Normalize is a pure transformation of one raw record.
	Normalize(rec model.RawRecord) (*model.Normalized, error)
}

// WantsMissingCVEs is implemented by collectors that opt in to on-demand
// backfill (Python: wants_missing_cves = True). WantedLimit bounds
// state.Wanted (Python: wanted_limit, default 1000); <= 0 means none.
type WantsMissingCVEs interface {
	WantedLimit() int
}

// Preparer is implemented by collectors that read their run configuration
// from the database (Go only). RunCollector calls Prepare once, outside the
// data transaction, before Fetch; an error fails the run like a Fetch error.
type Preparer interface {
	Prepare(ctx context.Context, conn *pgx.Conn) error
}

// DefaultWantedLimit is Python's Collector.wanted_limit default.
const DefaultWantedLimit = 1000

// NormalizeError marks a malformed upstream record (Python NormalizeError).
type NormalizeError struct{ Msg string }

func (e *NormalizeError) Error() string { return e.Msg }

// NormalizeErrorf builds a *NormalizeError.
func NormalizeErrorf(format string, args ...any) error {
	return &NormalizeError{Msg: fmt.Sprintf(format, args...)}
}

// Env looks up configuration (os.LookupEnv in production, a map in tests).
type Env func(key string) (string, bool)

// Deps are the injectable dependencies of a collector.
type Deps struct {
	// Env: configuration lookup. In the CLI it is os.LookupEnv evaluated
	// BEFORE the .env file is loaded, like Python's cmd_collect constructs the
	// collector before db.connect() loads .env (see docs/go.md).
	Env Env
	// Transport: nil in production (real network); tests and tools/replay
	// inject a fake http.RoundTripper. Pass it to httpc.Options.Transport.
	Transport http.RoundTripper
}

// LookupEnv returns d.Env(key), tolerating a nil Env.
func (d Deps) LookupEnv(key string) (string, bool) {
	if d.Env == nil {
		return "", false
	}
	return d.Env(key)
}

// Factory builds a collector.
type Factory func(d Deps) (Collector, error)
