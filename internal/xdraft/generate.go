package xdraft

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/site"
)

// The generation rule (docs/xposts.md):
//
//   - a draft is made for (CVE, stage) when a live (is_backfill = false)
//     event of type poc_published, exploited_in_wild or kev_added is the
//     FIRST event of that type for the CVE (lowest id; backfilled events
//     count as earlier events, so history never becomes a draft);
//   - exploited_in_wild is skipped when the CVE already has kev_added;
//   - rejected CVEs (the latest cvelist record says REJECTED, the same rule
//     as vuln_state) are skipped; social_post and every other type are
//     ignored;
//   - at most one draft per (CVE, stage) ever (UNIQUE x_draft_once; ON
//     CONFLICT DO NOTHING), so re-runs and later events never add a second.
//
// Which events are looked at: an event-id watermark (x_draft_state). The
// very first run stores the current maximum and drafts nothing. Each run
// considers events with watermark < id <= max(id), then moves the
// watermark to that max, also past the events it skipped (except a small
// backlog over the cap, see below).
//
// Why a watermark is safe: ids are taken when a collector inserts, but rows
// become visible when its transaction commits, so a lower id can commit
// after a higher one. The run therefore takes LOCK TABLE event IN SHARE
// MODE before reading max(id): SHARE conflicts with the ROW EXCLUSIVE lock
// every writing transaction holds until it commits, so once granted no
// insert is in flight and every id up to max(id) is committed or gone. The
// lock is held only for the run's short transaction. SHARE also conflicts
// with (auto)vacuum and analyze of event. After a collector run
// (Options.NoWait) and in a dry run the run never waits: if the lock is busy
// it defers (Result.Deferred "lock_busy") and leaves the watermark alone;
// the writer's own pass, or the next run, covers the events. A manual run
// waits at most WaitLock (while it waits, new collector inserts queue
// behind it). Overlapping runs are serialised by the watermark row (SELECT …
// FOR UPDATE, same waiting rule; "another_run" when busy). A deferral of the
// table lock is recorded in x_draft_state.last_run (deferred, deferred_at)
// without touching the watermark or the last run's counts. So is
// "vuln_busy": the vuln rows of the drafts to create are locked NOWAIT
// while the run holds the event table, because a merge (docs/ghsa.md)
// holds vuln rows and then needs the event table.
//
// Bounds: at most MaxDraftsPerRun drafts per run, and events observed more
// than MaxEventAge before the run are skipped for good (skipped_old). When
// more drafts qualify than the cap: if at most MaxBacklog qualify, the rest
// are carried over (the watermark stops just before the first one not
// drafted, so the next runs draft them, still bounded by the age limit;
// Result.Carried); if more qualify, it is a bulk change and the rest are
// skipped for good (skipped_cap). So a CISA batch of a few dozen KEV entries
// is drafted over a few runs, and a bulk import never floods the queue.

// MaxDraftsPerRun caps the drafts one run creates.
const MaxDraftsPerRun = 10

// MaxBacklog: when at most this many drafts qualify in a run, those over
// MaxDraftsPerRun are carried over to the next runs; when more qualify, they
// are skipped for good.
const MaxBacklog = 50

// MaxEventAge skips events observed longer ago than this (by observed_at,
// the collector's run time of a live event).
const MaxEventAge = 72 * time.Hour

// WaitLock is how long a manual, non-dry run waits for the locks before it
// gives up (deferred); collector inserts queue behind it meanwhile.
const WaitLock = 3 * time.Second

// Options of Generate.
type Options struct {
	// DryRun computes everything and rolls back; Result.Drafts holds what
	// would be created.
	DryRun bool
	// NoWait: never wait for a lock (the pass after a collector run).
	NoWait bool
	// Now is the run clock (default time.Now).
	Now func() time.Time
	// Max overrides MaxDraftsPerRun (tests); 0 = the constant.
	Max int
}

// Draft is one created (or, in a dry run, would-be) draft.
type Draft struct {
	ID      int64  `json:"id,omitempty"`
	CVE     string `json:"cve_id"`
	Stage   string `json:"stage"`
	EventID int64  `json:"event_id"`
	Body    string `json:"body"`
	Weight  int    `json:"weighted_length"`
}

// Result is what a run did.
type Result struct {
	Baseline   bool    `json:"baseline"` // first run: watermark set, nothing drafted
	Deferred   string  `json:"deferred,omitempty"`
	From       int64   `json:"from_event_id"`
	To         int64   `json:"to_event_id"`
	Candidates int     `json:"candidates"`
	Created    int     `json:"created"`
	SkippedCap int     `json:"skipped_cap"`
	SkippedOld int     `json:"skipped_old"`
	Existing   int     `json:"existing"` // a draft for (CVE, stage) already existed
	Carried    int     `json:"carried"`  // over the cap, left for the next runs
	DryRun     bool    `json:"dry_run"`
	Drafts     []Draft `json:"drafts"`
}

var errRollback = errors.New("dry run")

// lockBusy: SQLSTATE 55P03 lock_not_available (NOWAIT, lock_timeout).
func lockBusy(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "55P03"
}

// Generate runs the rule once on conn (which must not be inside a
// transaction). A busy lock is not an error: Result.Deferred says why.
func Generate(ctx context.Context, conn *pgx.Conn, o Options) (*Result, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	limit := o.Max
	if limit <= 0 {
		limit = MaxDraftsPerRun
	}
	now := o.Now().UTC()
	res := &Result{DryRun: o.DryRun, Drafts: []Draft{}}
	err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		// NoWait: the row and table locks below are NOWAIT; the timeout only
		// bounds the first run's insert of the state row
		wait, nowait := "2000ms", " NOWAIT"
		if !o.NoWait && !o.DryRun {
			wait, nowait = fmt.Sprintf("%dms", WaitLock.Milliseconds()), ""
		}
		if _, err := tx.Exec(ctx, `SELECT set_config('lock_timeout', $1, true)`, wait); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO x_draft_state (id) VALUES (1) ON CONFLICT (id) DO NOTHING`); err != nil {
			return err
		}
		var last *int64
		if err := tx.QueryRow(ctx, `SELECT last_event_id FROM x_draft_state WHERE id = 1 FOR UPDATE`+nowait).Scan(&last); err != nil {
			if lockBusy(err) {
				res.Deferred = "another_run"
				return errRollback
			}
			return err
		}
		// a savepoint, so a busy lock can still be recorded
		sp, err := tx.Begin(ctx)
		if err != nil {
			return err
		}
		if _, err := sp.Exec(ctx, `LOCK TABLE event IN SHARE MODE`+nowait); err != nil {
			_ = sp.Rollback(ctx)
			if !lockBusy(err) {
				return err
			}
			res.Deferred = "lock_busy"
			if o.DryRun {
				return errRollback
			}
			_, err := tx.Exec(ctx, `UPDATE x_draft_state SET last_run = last_run || jsonb_build_object('deferred', 'lock_busy',
				'deferred_at', $1::timestamptz), updated_at = $1 WHERE id = 1`, now)
			return err
		}
		var hi int64
		if err := tx.QueryRow(ctx, `SELECT coalesce(max(id), 0) FROM event`).Scan(&hi); err != nil {
			return err
		}
		res.To = hi
		if last == nil {
			res.Baseline = true
			return saveState(ctx, tx, hi, now, res)
		}
		res.From = *last
		if hi <= *last {
			return saveState(ctx, tx, *last, now, res)
		}
		cands, err := candidates(ctx, tx, *last, hi)
		if err != nil {
			return err
		}
		res.Candidates = len(cands)
		qualifying := 0
		var cves []string
		for _, c := range cands {
			if !c.existing && now.Sub(c.observed) <= MaxEventAge {
				qualifying++
				cves = append(cves, c.cve)
			}
		}
		// The vuln rows of the drafts this run may create (their foreign
		// key), FOR KEY SHARE NOWAIT: this run holds the event table, and a
		// merge of a GHSA-keyed vuln into its CVE (docs/ghsa.md) holds both
		// vuln rows FOR UPDATE before it moves the events. Waiting for such
		// a row here would deadlock with it; the run defers instead
		// ("vuln_busy", recorded like "lock_busy", watermark unchanged).
		if len(cves) > 0 {
			sp2, err := tx.Begin(ctx)
			if err != nil {
				return err
			}
			if _, err := sp2.Exec(ctx, `SELECT 1 FROM vuln WHERE cve_id = ANY($1) ORDER BY cve_id FOR KEY SHARE NOWAIT`, cves); err != nil {
				_ = sp2.Rollback(ctx)
				if !lockBusy(err) {
					return err
				}
				res.Deferred = "vuln_busy"
				if o.DryRun {
					return errRollback
				}
				_, err := tx.Exec(ctx, `UPDATE x_draft_state SET last_run = last_run || jsonb_build_object('deferred', 'vuln_busy',
					'deferred_at', $1::timestamptz), updated_at = $1 WHERE id = 1`, now)
				return err
			}
			if err := sp2.Commit(ctx); err != nil { // RELEASE SAVEPOINT: the locks stay
				return err
			}
		}
		to := hi
		for _, c := range cands {
			switch {
			case c.existing:
				res.Existing++
				continue
			case now.Sub(c.observed) > MaxEventAge:
				res.SkippedOld++
				continue
			case res.Created >= limit && qualifying <= MaxBacklog:
				if res.Carried == 0 {
					to = c.id - 1 // the next run starts at this event
				}
				res.Carried++
				continue
			case res.Created >= limit:
				res.SkippedCap++
				continue
			}
			in, err := loadInput(ctx, tx, c)
			if err != nil {
				return err
			}
			d := Draft{CVE: c.cve, Stage: c.stage, EventID: c.id, Body: Build(in)}
			d.Weight = WeightedLength(d.Body)
			err = tx.QueryRow(ctx, `INSERT INTO x_draft (cve_id, stage, event_id, body, created_at, updated_at)
				VALUES ($1, $2, $3, $4, $5, $5) ON CONFLICT ON CONSTRAINT x_draft_once DO NOTHING RETURNING id`,
				d.CVE, d.Stage, d.EventID, d.Body, now).Scan(&d.ID)
			if errors.Is(err, pgx.ErrNoRows) {
				res.Existing++
				continue
			}
			if err != nil {
				return err
			}
			res.Created++
			if o.DryRun {
				d.ID = 0
			}
			res.Drafts = append(res.Drafts, d)
		}
		return saveState(ctx, tx, to, now, res)
	})
	if errors.Is(err, errRollback) {
		err = nil
	}
	if err != nil {
		return nil, err
	}
	return res, nil
}

// saveState moves the watermark (or, in a dry run, rolls everything back).
func saveState(ctx context.Context, tx pgx.Tx, to int64, now time.Time, res *Result) error {
	if res.DryRun {
		return errRollback
	}
	summary, _ := json.Marshal(map[string]any{"baseline": res.Baseline, "from_event_id": res.From, "to_event_id": res.To,
		"candidates": res.Candidates, "created": res.Created, "skipped_cap": res.SkippedCap, "skipped_old": res.SkippedOld,
		"existing": res.Existing, "carried": res.Carried})
	_, err := tx.Exec(ctx, `UPDATE x_draft_state SET last_event_id = greatest(coalesce(last_event_id, 0), $1),
		last_run_at = $2, last_run = $3::jsonb, updated_at = $2 WHERE id = 1`, to, now, string(summary))
	return err
}

type candidate struct {
	id       int64
	cve      string
	stage    string
	source   string
	observed time.Time
	existing bool // a draft for (cve, stage) exists already
}

// CandidatesSQL selects the events in (from, to] that are the first of
// their stage type for their CVE (lowest id), live, not ITW after KEV and
// not on a rejected CVE, in id order. Exported for EXPLAIN in the docs.
const CandidatesSQL = `SELECT e.id, e.cve_id, e.type, e.source, e.observed_at,
       EXISTS (SELECT 1 FROM x_draft d WHERE d.cve_id = e.cve_id AND d.stage = e.type) AS existing
FROM event e
WHERE e.id > $1 AND e.id <= $2
  AND e.type IN ('poc_published', 'exploited_in_wild', 'kev_added')
  AND NOT e.is_backfill
  AND NOT EXISTS (SELECT 1 FROM event p WHERE p.cve_id = e.cve_id AND p.type = e.type AND p.id < e.id)
  AND NOT (e.type = 'exploited_in_wild'
           AND EXISTS (SELECT 1 FROM event k WHERE k.cve_id = e.cve_id AND k.type = 'kev_added'))
  AND NOT coalesce((SELECT (r.detail->>'state') = 'REJECTED' FROM event r
                    WHERE r.cve_id = e.cve_id AND r.type = 'disclosed' AND r.source = 'cvelist' AND r.detail ? 'state'
                    ORDER BY coalesce(r.occurred_at, CASE WHEN NOT r.is_backfill THEN r.observed_at END) DESC NULLS LAST,
                             r.observed_at DESC, r.id DESC
                    LIMIT 1), false)
ORDER BY e.id`

func candidates(ctx context.Context, tx pgx.Tx, from, to int64) ([]candidate, error) {
	rows, err := tx.Query(ctx, CandidatesSQL, from, to)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (candidate, error) {
		var c candidate
		err := r.Scan(&c.id, &c.cve, &c.stage, &c.source, &c.observed, &c.existing)
		return c, err
	})
}

// loadInput reads what the text needs: the effective title in English
// (the staff title, else the record's, else the composed one; site.TitleInfo,
// docs/titles.md), the affected pairs in the order first reported, and the
// T+ figure by the site's rule (site.CalendarDays from the first effective
// disclosure to the first effective time of this stage; effective =
// event_effective).
func loadInput(ctx context.Context, tx pgx.Tx, c candidate) (Input, error) {
	in := Input{CVE: c.cve, Stage: c.stage, Source: c.source}
	var title *string
	var disc, at *time.Time
	err := tx.QueryRow(ctx, `SELECT COALESCE(t.staff_title, NULLIF(btrim(v.title), ''), t.composed_en),
			(SELECT min(effective_at) FROM event_effective WHERE cve_id = v.cve_id AND type = 'disclosed'),
			(SELECT min(effective_at) FROM event_effective WHERE cve_id = v.cve_id AND type = $2)
		FROM vuln v LEFT JOIN vuln_title t ON t.cve_id = v.cve_id WHERE v.cve_id = $1`, c.cve, c.stage).Scan(&title, &disc, &at)
	if err != nil {
		return in, err
	}
	if title != nil {
		in.Title = *title
	}
	in.Days = site.CalendarDays(disc, at)
	rows, err := tx.Query(ctx, `SELECT vendor, product FROM affected WHERE cve_id = $1 ORDER BY id LIMIT 50`, c.cve)
	if err != nil {
		return in, err
	}
	in.Products, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (Product, error) {
		var p Product
		return p, r.Scan(&p.Vendor, &p.Product)
	})
	return in, err
}
