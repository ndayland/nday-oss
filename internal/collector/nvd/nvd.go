// Package nvd is the NIST National Vulnerability Database collector (JSON
// 2.0 data feeds, https://nvd.nist.gov/feeds/json/cve/2.0/; never the NVD
// API). See docs/nvd.md.
//
// What it stores: one raw_record per CVE (source "nvd", key = the CVE id,
// payload = the feed entry's "cve" object as delivered, content-hashed like
// every source, so an unchanged record is never rewritten). NVD produces NO
// lifecycle events (its publish date is not a stage): Normalize returns
// nothing, so vuln, event and vuln_state are never touched by this source,
// and no vuln row is created for a CVE the CVE List has not delivered yet.
// Its data feeds the classification layer (internal/classify: CWE and CVSS
// with provenance); CPE configurations stay in the raw record.
//
// Two ways in, sharing the download/verify (fetch.go), the streaming parser
// (feed.go) and the raw writer (store.go):
//   - `nday import-nvd-baseline`: the yearly files (baseline.go), once;
//   - `nday collect nvd` (Run, hourly): the "modified" feed. Its .meta is
//     fetched first (If-None-Match with the stored ETag); a 304 or an
//     unchanged sha256 ends the run without downloading. Otherwise the feed
//     is downloaded, verified against the .meta (gzSize, complete gzip,
//     size, SHA-256) and written in ONE transaction together with
//     collector_state, so a failed or truncated download, a bad checksum or
//     a database error changes nothing and keeps the cursor.
//
// Cursor: {"modified": {"last_modified", "sha256", "etag"}, "synced_through":
// the .meta lastModifiedDate of the last applied modified feed}. The
// modified feed only holds records changed in the last ~8 days (measured
// on 2026-11-14: lastModified from 2026-11-05T05:18 to 2026-11-13T14:59 in a
// feed generated at 2026-11-13T15:00Z; docs/nvd.md). When synced_through is
// older than CoverageWindow before the new feed, records changed in the gap
// may be missing from it, so the run first re-reads every yearly file whose
// .meta lastModifiedDate is after synced_through (one transaction per batch
// of each file; the cursor only moves when everything succeeded).
// On the very first run (no cursor) only the modified feed is read and a
// warning says to run the baseline import if no NVD record is stored yet.
package nvd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
)

// Name is the source name (raw_record.source, collector_state.source).
const Name = "nvd"

// CoverageWindow is how far back the modified feed is trusted to reach.
// The observed span is ~8 days; one day of margin.
const CoverageWindow = 7 * 24 * time.Hour

// ModifiedFeed is the name of the incremental feed.
const ModifiedFeed = "modified"

// Collector implements collector.Collector (registry, Name, a Normalize
// that yields nothing) and Run (the actual collection, streamed).
type Collector struct {
	Fetcher *Fetcher
	Logger  *slog.Logger
	// Years: the yearly files the fallback may read (default
	// FirstYear..current year).
	Years func(now time.Time) []int
}

// Options configures New.
type Options struct {
	Transport http.RoundTripper
	Base      string
	Sleep     func(ctx context.Context, d time.Duration) error
	Logger    *slog.Logger
}

// New builds the collector.
func New(o Options) *Collector {
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	return &Collector{
		Fetcher: NewFetcher(FetcherOptions{Base: o.Base, Transport: o.Transport, Sleep: o.Sleep, Logger: o.Logger}),
		Logger:  o.Logger,
		Years:   DefaultYears,
	}
}

// Factory is the registry entry.
func Factory(d collector.Deps) (collector.Collector, error) {
	return New(Options{Transport: d.Transport}), nil
}

// Name implements collector.Collector.
func (c *Collector) Name() string { return Name }

// ErrStreamed: the feed is too large for a FetchResult; use Run.
var ErrStreamed = errors.New("nvd: this collector streams its feeds; run it with `nday collect nvd` (nvd.Collector.Run)")

// Fetch implements collector.Collector; NVD is collected by Run.
func (c *Collector) Fetch(context.Context, model.CollectorState) (*model.FetchResult, error) {
	return nil, ErrStreamed
}

// Normalize implements collector.Collector: NVD yields no vuln, alias,
// affected or event rows (renormalize nvd is therefore a no-op).
func (c *Collector) Normalize(model.RawRecord) (*model.Normalized, error) {
	return &model.Normalized{}, nil
}

// RunStats is printed by `nday collect nvd`.
type RunStats struct {
	Source string `json:"source"`
	// Outcome: unchanged (304 / same sha256), modified, fallback+modified.
	Outcome  string       `json:"outcome"`
	Feeds    []*FileStats `json:"feeds"`
	Total    WriteStats   `json:"total"`
	Warnings []string     `json:"warnings,omitempty"`
}

// cursor is the parsed collector_state.cursor.
type cursor struct {
	lastModified, sha, etag string
	synced                  *time.Time
}

func readCursor(v any) cursor {
	var c cursor
	o, _ := v.(*pyjson.Object)
	if o == nil {
		return c
	}
	if m, ok := o.Get("modified").(*pyjson.Object); ok {
		c.lastModified, _ = m.Get("last_modified").(string)
		c.sha, _ = m.Get("sha256").(string)
		c.etag, _ = m.Get("etag").(string)
	}
	if s, ok := o.Get("synced_through").(string); ok {
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			t = t.UTC()
			c.synced = &t
		}
	}
	return c
}

func (c cursor) value(fallback *pyjson.Object) *pyjson.Object {
	m := pyjson.NewObject()
	m.Set("last_modified", c.lastModified)
	m.Set("sha256", c.sha)
	m.Set("etag", c.etag)
	o := pyjson.NewObject()
	o.Set("modified", m)
	if c.synced != nil {
		o.Set("synced_through", c.synced.Format(time.RFC3339))
	} else {
		o.Set("synced_through", nil)
	}
	if fallback != nil {
		o.Set("last_fallback", fallback)
	}
	return o
}

// RunOptions for Run.
type RunOptions struct {
	Now func() time.Time
	// BatchSize for the yearly fallback (default DefaultBatchSize).
	BatchSize int
}

// Run performs one incremental collection (see the package doc). conn must
// not be inside a transaction. On failure collector_state records the error
// and keeps the previous cursor; the error is returned.
func (c *Collector) Run(ctx context.Context, conn *pgx.Conn, o RunOptions) (*RunStats, error) {
	now := time.Now
	if o.Now != nil {
		now = o.Now
	}
	runAt := now().UTC().Truncate(time.Microsecond)
	log := c.Logger
	st := &RunStats{Source: Name, Feeds: []*FileStats{}}
	state, err := pipeline.LoadState(ctx, conn, Name)
	if err != nil {
		return nil, err
	}
	cur := readCursor(state.Cursor)
	runErr := func() error {
		mr, err := c.Fetcher.Meta(ctx, ModifiedFeed, cur.etag)
		if err != nil {
			return err
		}
		if mr.NotModified || (cur.sha != "" && mr.Meta.SHA256 == cur.sha) {
			st.Outcome = "unchanged"
			log.Info("nvd: modified feed unchanged since the last run", "not_modified", mr.NotModified,
				"last_modified", cur.lastModified)
			if mr.ETag != "" {
				cur.etag = mr.ETag
			}
			return pipeline.SaveState(ctx, conn, Name, runAt, "ok", nil, cur.value(nil), true)
		}
		meta := mr.Meta
		var fallback *pyjson.Object
		if cur.synced == nil {
			var n int64
			if err := conn.QueryRow(ctx, `SELECT count(*) FROM (SELECT 1 FROM raw_record WHERE source = $1 LIMIT 1) s`, Name).Scan(&n); err != nil {
				return err
			}
			if n == 0 {
				w := "no NVD record stored yet: this run reads only the modified feed (~8 days); run `nday import-nvd-baseline --download` once for the full history"
				st.Warnings = append(st.Warnings, w)
				log.Warn("nvd: " + w)
			}
		} else if gap := meta.LastModified.Sub(*cur.synced); gap > CoverageWindow {
			st.Outcome = "fallback+modified"
			log.Warn("nvd: last sync is older than the modified feed's window; re-reading changed yearly files",
				"synced_through", cur.synced.Format(time.RFC3339), "feed_last_modified", meta.Raw, "gap", gap.Round(time.Minute).String())
			fallback, err = c.fallback(ctx, conn, *cur.synced, o, st)
			if err != nil {
				return err
			}
		}
		if st.Outcome == "" {
			st.Outcome = "modified"
		}
		body, err := c.Fetcher.Feed(ctx, ModifiedFeed, meta)
		if err != nil {
			var ce *ChecksumError
			if !errors.As(err, &ce) {
				return err
			}
			// regenerated between .meta and feed: fetch the pair again
			log.Warn("nvd: modified feed does not match its .meta, fetching both again", "err", err)
			if meta, body, err = c.Fetcher.MetaAndFeed(ctx, ModifiedFeed); err != nil {
				return err
			}
		}
		next := cursor{lastModified: meta.Raw, sha: meta.SHA256, etag: mr.ETag, synced: &meta.LastModified}
		return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			r, err := Unpack(bytes.NewReader(body), meta.Size)
			if err != nil {
				return err
			}
			fs, err := ImportFeed(ctx, conn, r, ImportOptions{Snapshot: meta.LastModified, OneTx: tx, Logger: log, Label: ModifiedFeed})
			if err != nil {
				return err
			}
			fs.Verified = true
			st.Feeds = append(st.Feeds, fs)
			st.Total.add(fs.WriteStats)
			status, errText := "ok", (*string)(nil)
			if st.Total.BadEntries > 0 {
				status = "partial"
				s := fmt.Sprintf("%d unusable entries: %s", st.Total.BadEntries, strings.Join(st.Total.Errors, "; "))
				errText = &s
			}
			return pipeline.SaveState(ctx, tx, Name, runAt, status, errText, next.value(fallback), true)
		})
	}()
	if runErr != nil {
		msg := runErr.Error()
		if len([]rune(msg)) > 2000 {
			msg = string([]rune(msg)[:2000])
		}
		if err := pipeline.SaveState(context.WithoutCancel(ctx), conn, Name, runAt, "error", &msg, nil, false); err != nil {
			log.Error("could not record failure in collector_state", "err", err)
		}
		return nil, runErr
	}
	return st, nil
}

// fallback re-reads every yearly file whose .meta changed after synced.
func (c *Collector) fallback(ctx context.Context, conn *pgx.Conn, synced time.Time, o RunOptions, st *RunStats) (*pyjson.Object, error) {
	years := DefaultYears
	if c.Years != nil {
		years = c.Years
	}
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	var read []any
	for _, y := range years(now) {
		name := yearName(y)
		mr, err := c.Fetcher.Meta(ctx, name, "")
		if err != nil {
			return nil, fmt.Errorf("nvd %s: %w", name, err)
		}
		if !mr.Meta.LastModified.After(synced) {
			continue
		}
		meta, body, err := func() (Meta, []byte, error) {
			b, err := c.Fetcher.Feed(ctx, name, mr.Meta)
			var ce *ChecksumError
			if errors.As(err, &ce) {
				return c.Fetcher.MetaAndFeed(ctx, name)
			}
			return mr.Meta, b, err
		}()
		if err != nil {
			return nil, fmt.Errorf("nvd %s: %w", name, err)
		}
		r, err := Unpack(bytes.NewReader(body), meta.Size)
		if err != nil {
			return nil, err
		}
		fs, err := ImportFeed(ctx, conn, r, ImportOptions{Snapshot: meta.LastModified, BatchSize: o.BatchSize,
			Logger: c.Logger, Label: name})
		if fs != nil {
			fs.Verified = true
			st.Feeds = append(st.Feeds, fs)
			st.Total.add(fs.WriteStats)
		}
		if err != nil {
			return nil, fmt.Errorf("nvd %s: %w", name, err)
		}
		read = append(read, name)
	}
	fb := pyjson.NewObject()
	fb.Set("from", synced.Format(time.RFC3339))
	fb.Set("files", read)
	return fb, nil
}
