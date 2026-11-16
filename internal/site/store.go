// Package site is the read-only query layer of the nday website: typed Go
// functions returning plain structs, used by the JSON API (internal/web) and
// by the HTML pages. Nothing here knows about HTTP or HTML.
//
// # Using it
//
//	pool := dbpool.New(cfg, dbpool.Options{Size: 8})
//	store := site.New(pool)               // or site.New(site.SingleConn(conn))
//	page, err := store.Hot(ctx, site.HotParams{Since: 30 * 24 * time.Hour, MinStage: "patch_released"})
//	v, found, err := store.Vuln(ctx, "cve-2026-102895")
//	src, err := store.Sources(ctx)
//	st, err := store.Stats(ctx)
//	res, err := store.Search(ctx, "barracuda", 20)
//	raw, found, err := store.Raw(ctx, "kev", "CVE-2026-102895")
//
// Every exported struct carries the json tags the API uses, so a page can
// also be rendered from the same values the API returns.
//
// # Conventions
//
//   - All times are UTC instants (time.Time in UTC). Formatting, time zones
//     and "T+5d"-style labels are the caller's job. A nil *time.Time means
//     "unknown" — never a guess. Calendar dates that are not instants
//     (KEV due_date, date_added) are "YYYY-MM-DD" strings.
//   - Lifecycle stages are event types (disclosed, patch_released,
//     analysis_published, poc_published, exploited_in_wild, kev_added) with
//     three-letter codes DIS PAT ANA POC ITW KEV (StageInfos, StageCode).
//   - Slot rules (ComputeSlots): a type with no event is "none"; with events
//     and a known earliest effective time "known"; with events whose times
//     are all unknown "unknown"; ITW without an exploited_in_wild event but
//     with a kev_added event is "implied" (NotAfter = KEV time, an upper
//     bound: being in KEV means exploitation was already happening).
//   - Precision rules (EventPrecision): "day" (detail.precision = "day";
//     show only the date), "exact" (source time), "observed" (no source time,
//     nday saw it live; the time is our observation time), "unknown".
//   - Effective time of an event = occurred_at, else observed_at if observed
//     live, else unknown (SQL view event_effective, the single definition).
//   - Titles: Title is the upstream English title and may be nil (vulns only
//     referenced by other sources, not yet backfilled from the CVE list);
//     TitleZh is not populated yet. Fall back TitleZh -> Title -> CVE id.
//   - Lists come from vuln_state_mat (materialized; refreshed after every
//     collector run, so at most one run behind the event table). Vuln
//     detail computes slots/transition from its events directly, so it is
//     always current; its State field is the materialized row.
//   - Invalid caller input yields *InputError (map to HTTP 400). A CVE that
//     does not exist is (nil, false, nil), not an error.
package site

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// ConnSource hands out a connection for the duration of fn.
// *dbpool.Pool implements it; SingleConn adapts one *pgx.Conn.
type ConnSource interface {
	WithConn(ctx context.Context, fn func(*pgx.Conn) error) error
}

// SingleConn adapts a single connection (serialised by a mutex) to
// ConnSource — for the CLI and tests.
func SingleConn(c *pgx.Conn) ConnSource { return &single{c: c} }

type single struct {
	mu sync.Mutex
	c  *pgx.Conn
}

func (s *single) WithConn(_ context.Context, fn func(*pgx.Conn) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return fn(s.c)
}

// Store runs the site's queries. Safe for concurrent use when its
// ConnSource is.
type Store struct {
	db   ConnSource
	now  func() time.Time
	pins *pinBox // hot list pinning numbers (pin.go); shared by WithClock copies
}

// New returns a Store reading through db.
func New(db ConnSource) *Store { return &Store{db: db, now: time.Now, pins: new(pinBox)} }

// WithClock returns a copy of s using now as the clock (tests).
func (s *Store) WithClock(now func() time.Time) *Store {
	c := *s
	c.now = now
	return &c
}

func (s *Store) clock() time.Time { return s.now().UTC() }
