package cveimport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/cvelist"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
)

// Defaults.
const (
	DefaultBatchSize     = 2000
	DefaultProgressEvery = 20000
	DefaultBatchAttempts = 5
	// lockTimeout bounds the wait for the raw_record table lock behind a
	// long-running writer; the batch is then retried.
	lockTimeout = "5min"
)

// Options for Import.
type Options struct {
	// BatchSize is the number of records written per transaction.
	BatchSize int
	// Limit stops after this many records were taken for import (records
	// already in the database do not count); 0 = no limit.
	Limit int
	// Year imports only CVE-<Year>-* (0 = all years).
	Year int
	// DryRun reads, decodes, hashes and normalizes every selected record
	// (including those that would be skipped) and counts; writes nothing
	// and takes no locks.
	DryRun bool
	// SnapshotAt is the fetched_at of the imported raw_record rows: the time
	// of the baseline snapshot (midnight UTC of its day). See Import.
	SnapshotAt time.Time
	// Now is the clock for observed_at / first_seen_at (default time.Now).
	Now func() time.Time
	// Workers decoding/normalizing in parallel (default min(GOMAXPROCS, 8)).
	Workers int
	// ProgressEvery logs progress each time this many more records were processed.
	ProgressEvery int
	// Stop, when closed, makes Import finish the batch in flight and return
	// (Stats.Interrupted). Cancelling ctx instead aborts the current batch
	// (rolled back).
	Stop <-chan struct{}
	// BatchAttempts bounds the retries of a batch that hit a deadlock, a
	// serialization failure or the lock timeout (default 5).
	BatchAttempts int
	Logger        *slog.Logger

	// beforeCommit is a test hook run inside each write transaction, after
	// all rows of the batch are written and before COMMIT.
	beforeCommit func(ctx context.Context, tx pgx.Tx) error
}

// Stats of an Import.
type Stats struct {
	Members  int `json:"members"`  // CVE record files in the archive
	Selected int `json:"selected"` // after the --year filter
	// Processed counts selected records examined so far (imported, skipped
	// or failed).
	Processed int `json:"processed"`
	// SkippedExisting: a cvelist raw_record already existed when the run
	// started (never touched). SkippedRace: none existed at start but one
	// was committed by a concurrent writer (the cvelist collector) before
	// this batch took its lock: also skipped.
	SkippedExisting int `json:"skipped_existing"`
	SkippedRace     int `json:"skipped_race"`
	// Imported: raw_record rows written (one per imported CVE).
	Imported int `json:"imported"`
	// By cveMetadata.state over the decoded records (imported ones; in a
	// dry run every selected record).
	Published    int `json:"published"`
	Rejected     int `json:"rejected"`
	Reserved     int `json:"reserved"`
	OtherState   int `json:"other_state"`
	DryRunSkips  int `json:"dry_run_would_skip"`
	DryRunImport int `json:"dry_run_would_import"`
	// NormalizeErrors: collector.NormalizeError (raw stored, nothing applied,
	// exactly like the collector). FatalErrors: other Normalize/Validate
	// failures (the collector would abort its whole run; here the record is
	// NOT stored so a later run retries it). DecodeErrors: invalid JSON or
	// unreadable member (not stored). NotObject: JSON that is not an object
	// (the collector ignores those). Oversized: members over
	// cvelist.MaxMemberBytes (the collector skips those).
	NormalizeErrors int      `json:"normalize_errors"`
	FatalErrors     int      `json:"fatal_errors"`
	DecodeErrors    int      `json:"decode_errors"`
	NotObject       int      `json:"not_object"`
	Oversized       int      `json:"oversized"`
	Duplicates      int      `json:"duplicates"`
	Errors          []string `json:"errors,omitempty"` // "<id>: <kind>: <message>", at most maxErrorList
	Batches         int      `json:"batches"`
	BatchRetries    int      `json:"batch_retries"`
	Interrupted     bool     `json:"interrupted"`
	// Rows written, as counted by the pipeline's apply code.
	VulnInserted     int     `json:"vuln_inserted"`
	VulnUpdated      int     `json:"vuln_updated"`
	AliasInserted    int     `json:"alias_inserted"`
	AffectedInserted int     `json:"affected_inserted"`
	EventInserted    int     `json:"event_inserted"`
	EventUpdated     int     `json:"event_updated"`
	ElapsedSec       float64 `json:"elapsed_sec"`
}

const maxErrorList = 1000

func (s *Stats) addError(id, kind, msg string) {
	if len(s.Errors) < maxErrorList {
		s.Errors = append(s.Errors, id+": "+kind+": "+msg)
	}
}

type item struct {
	m     Member
	skip  bool // already in the database (decoded only in a dry run)
	rec   model.RawRecord
	hash  string
	norm  *model.Normalized
	nerr  *collector.NormalizeError
	fatal error
	// bad is set for records that cannot be stored (decode error, not an
	// object, oversized): badKind names the counter.
	bad, badKind string
	state        string
}

type batch struct {
	items     []item
	processed int // selected records this batch accounts for (incl. pre-skipped)
	preSkip   int
}

// LoadExisting returns every CVE id that has at least one cvelist
// raw_record (any content version).
func LoadExisting(ctx context.Context, q interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
}) (map[string]bool, error) {
	rows, err := q.Query(ctx, `SELECT DISTINCT source_key FROM raw_record WHERE source = $1`, cvelist.Name)
	if err != nil {
		return nil, err
	}
	keys, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(keys))
	for _, k := range keys {
		out[k] = true
	}
	return out, nil
}

// Import writes every selected baseline record whose CVE has no cvelist
// raw_record yet. Rules (each one is what RunCollector does for a cvelist
// record, unless stated):
//
//   - Never regress: a CVE that already has ANY cvelist raw_record is
//     skipped entirely (those came from the incremental collector and are
//     at least as new as the baseline). Checked once up front (fast path)
//     and again inside every batch transaction under a table lock (below).
//   - raw_record: pipeline.StoreRaw with the content hash of the payload
//     (same hashing and compact sorted JSON as the collector). fetched_at =
//     Options.SnapshotAt (the baseline's midnight), not the import time: a
//     collector run that commits a newer version after a batch therefore
//     still sorts as the latest version (its fetched_at is its run time).
//   - Normalize: the cvelist collector's own Normalize through
//     pipeline.NormalizeOne (RESERVED -> raw only; REJECTED -> dates +
//     rejection facts; PUBLISHED -> vuln/affected/alias/disclosed event).
//   - Apply: pipeline.ApplyNormalized with isBackfill = true and observed_at
//     = the batch's time (events is_backfill=true, vuln first_seen_at = now).
//   - collector_state (cursor, backfill_missing, last_run/success) is never
//     touched, and no derived-state refresh happens here (the caller
//     refreshes once at the end).
//
// Transactions: one per batch. Each starts with
// LOCK TABLE raw_record IN SHARE ROW EXCLUSIVE MODE, which waits for every
// open transaction that already wrote raw_record (a running collector) to
// finish and makes concurrent raw_record writers wait for this batch
// (readers, the website and REFRESH are not blocked: the lock does not
// conflict with ACCESS SHARE). Under the lock the batch re-reads which of
// its ids now have a cvelist raw_record and skips those, so a concurrent
// cvelist run can never be overwritten by an older baseline version; the
// opposite order (collector commits after the batch) is ordinary collector
// behaviour: its newer version overwrites ours. Deadlocks (40P01),
// serialization failures (40001) and lock timeouts (55P03) roll the batch
// back and retry it. A crash or a cancelled ctx loses at most the batch in
// flight; re-running continues where it stopped because imported ids are
// skipped.
func Import(ctx context.Context, conn *pgx.Conn, arc *Archive, c *cvelist.Collector, o Options) (*Stats, error) {
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultBatchSize
	}
	if o.ProgressEvery <= 0 {
		o.ProgressEvery = DefaultProgressEvery
	}
	if o.Workers <= 0 {
		o.Workers = min(runtime.GOMAXPROCS(0), 8)
	}
	if o.BatchAttempts <= 0 {
		o.BatchAttempts = DefaultBatchAttempts
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.SnapshotAt.IsZero() {
		return nil, errors.New("cveimport: SnapshotAt is required")
	}
	o.SnapshotAt = o.SnapshotAt.UTC().Truncate(time.Microsecond)
	log := o.Logger
	start := time.Now()
	st := &Stats{Members: len(arc.Members)}

	existing, err := LoadExisting(ctx, conn)
	if err != nil {
		return nil, fmt.Errorf("load existing cvelist ids: %w", err)
	}
	var selected []Member
	toImport := 0
	for _, m := range arc.Members {
		if o.Year != 0 && m.Year != o.Year {
			continue
		}
		selected = append(selected, m)
		if !existing[m.CVE] {
			toImport++
		}
	}
	st.Selected = len(selected)
	if o.Limit > 0 && toImport > o.Limit {
		toImport = o.Limit
	}
	log.Info("baseline import starting", "members", st.Members, "selected", st.Selected,
		"existing_cvelist_ids", len(existing), "to_import", toImport, "batch_size", o.BatchSize,
		"dry_run", o.DryRun, "snapshot_at", o.SnapshotAt.Format(time.RFC3339))

	// Producer: builds batches (pre-skipping known ids) and decodes them in
	// parallel; at most one decoded batch waits while the previous is written.
	pctx, cancelProducer := context.WithCancel(ctx)
	defer cancelProducer()
	batches := make(chan *batch, 1)
	var prodErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(batches)
		prodErr = produce(pctx, selected, existing, c, o, batches)
	}()

	nextProgress := o.ProgressEvery
	importedOrFailed := 0
	progress := func(final bool) {
		el := time.Since(start).Seconds()
		rate := float64(st.Processed) / max(el, 1e-9)
		irate := float64(importedOrFailed) / max(el, 1e-9)
		eta := "n/a"
		if irate > 0 && toImport > importedOrFailed {
			eta = (time.Duration(float64(toImport-importedOrFailed)/irate) * time.Second).Round(time.Second).String()
		}
		msg := "baseline import progress"
		if final {
			msg = "baseline import finished"
		}
		log.Info(msg, "processed", st.Processed, "of", st.Selected, "imported", st.Imported,
			"skipped_existing", st.SkippedExisting, "skipped_race", st.SkippedRace,
			"published", st.Published, "rejected", st.Rejected, "reserved", st.Reserved,
			"errors", st.NormalizeErrors+st.FatalErrors+st.DecodeErrors+st.NotObject+st.Oversized,
			"rate_per_s", fmt.Sprintf("%.0f", rate), "import_rate_per_s", fmt.Sprintf("%.0f", irate), "eta", eta)
	}
	var runErr error
loop:
	for {
		select {
		case <-stopCh(o.Stop):
			st.Interrupted = true
			log.Warn("stop requested: finished the last batch, exiting", "processed", st.Processed, "imported", st.Imported)
			break loop
		default:
		}
		var b *batch
		var ok bool
		select {
		case b, ok = <-batches:
		case <-stopCh(o.Stop):
			st.Interrupted = true
			log.Warn("stop requested: finished the last batch, exiting", "processed", st.Processed, "imported", st.Imported)
			break loop
		}
		if !ok {
			break
		}
		if o.DryRun {
			countDry(st, b, log)
		} else {
			bs, err := writeBatch(ctx, conn, b, o, log)
			if err != nil {
				runErr = err
				break
			}
			merge(st, bs)
		}
		st.Batches++
		st.Processed += b.processed
		st.SkippedExisting += b.preSkip
		importedOrFailed += len(b.items) - b.preSkipDecoded()
		if st.Processed >= nextProgress {
			progress(false)
			for nextProgress <= st.Processed {
				nextProgress += o.ProgressEvery
			}
		}
	}
	cancelProducer()
	for range batches { // unblock and drain the producer
	}
	wg.Wait()
	st.ElapsedSec = time.Since(start).Seconds()
	if runErr != nil {
		return st, runErr
	}
	if prodErr != nil && !errors.Is(prodErr, context.Canceled) {
		return st, prodErr
	}
	if ctx.Err() != nil {
		return st, ctx.Err()
	}
	progress(true)
	return st, nil
}

// preSkipDecoded is the number of items carried only for dry-run counting.
func (b *batch) preSkipDecoded() int {
	n := 0
	for _, it := range b.items {
		if it.skip {
			n++
		}
	}
	return n
}

func stopCh(c <-chan struct{}) <-chan struct{} {
	if c == nil {
		return nil // never ready
	}
	return c
}

func produce(ctx context.Context, selected []Member, existing map[string]bool, c *cvelist.Collector,
	o Options, out chan<- *batch) error {
	taken := 0
	i := 0
	for i < len(selected) {
		b := &batch{}
		take := 0
		for i < len(selected) && take < o.BatchSize {
			if o.Limit > 0 && taken >= o.Limit {
				break
			}
			m := selected[i]
			i++
			b.processed++
			if existing[m.CVE] {
				b.preSkip++
				if o.DryRun {
					b.items = append(b.items, item{m: m, skip: true})
				}
				continue
			}
			existing[m.CVE] = true // a duplicate member later in the archive is skipped
			b.items = append(b.items, item{m: m})
			take++
			taken++
		}
		if b.processed == 0 {
			break
		}
		decode(ctx, b.items, c, o.Workers)
		select {
		case out <- b:
		case <-ctx.Done():
			return ctx.Err()
		}
		if o.Limit > 0 && taken >= o.Limit {
			break
		}
	}
	return nil
}

// decode reads, decodes, hashes and normalizes items in parallel. Pure CPU
// work on bounded data (one batch).
func decode(ctx context.Context, items []item, c *cvelist.Collector, workers int) {
	next := make(chan int)
	var wg sync.WaitGroup
	for w := 0; w < min(workers, max(len(items), 1)); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				decodeOne(&items[i], c)
			}
		}()
	}
	for i := range items {
		if ctx.Err() != nil {
			break
		}
		next <- i
	}
	close(next)
	wg.Wait()
}

func decodeOne(it *item, c *cvelist.Collector) {
	id := it.m.CVE
	if it.m.Size() > cvelist.MaxMemberBytes {
		it.bad, it.badKind = fmt.Sprintf("member is %d bytes > %d (the collector skips it)", it.m.Size(), cvelist.MaxMemberBytes), "oversized"
		return
	}
	data, err := it.m.Read(cvelist.MaxMemberBytes)
	if err != nil {
		it.bad, it.badKind = err.Error(), "decode"
		return
	}
	v, err := pyjson.Decode(data)
	if err != nil {
		it.bad, it.badKind = err.Error(), "decode"
		return
	}
	obj, ok := v.(*pyjson.Object)
	if !ok {
		it.bad, it.badKind = "record is not a JSON object (the collector ignores it)", "not_object"
		return
	}
	if meta, ok := obj.Get("cveMetadata").(*pyjson.Object); ok {
		if s, ok := meta.Get("state").(string); ok {
			it.state = s
		}
	}
	it.rec = model.RawRecord{Source: cvelist.Name, SourceKey: id, Payload: obj, IsBackfill: true}
	if it.hash, err = it.rec.ContentHash(); err != nil {
		it.bad, it.badKind = "content hash: "+err.Error(), "decode"
		return
	}
	it.norm, it.nerr, it.fatal = pipeline.NormalizeOne(c, it.rec)
}

func countState(st *Stats, state string) {
	switch state {
	case "PUBLISHED":
		st.Published++
	case "REJECTED":
		st.Rejected++
	case "RESERVED":
		st.Reserved++
	default:
		st.OtherState++
	}
}

func countBad(st *Stats, it *item) bool {
	if it.bad == "" {
		return false
	}
	switch it.badKind {
	case "oversized":
		st.Oversized++
	case "not_object":
		st.NotObject++
	default:
		st.DecodeErrors++
	}
	st.addError(it.m.CVE, it.badKind, it.bad)
	return true
}

func countDry(st *Stats, b *batch, log *slog.Logger) {
	for i := range b.items {
		it := &b.items[i]
		if it.skip {
			st.DryRunSkips++
		} else {
			st.DryRunImport++
		}
		if countBad(st, it) {
			log.Warn("baseline record unusable", "cve", it.m.CVE, "kind", it.badKind, "err", it.bad)
			continue
		}
		countState(st, it.state)
		switch {
		case it.fatal != nil:
			st.FatalErrors++
			st.addError(it.m.CVE, "fatal", it.fatal.Error())
			log.Warn("normalize failed (fatal kind)", "cve", it.m.CVE, "err", it.fatal)
		case it.nerr != nil:
			st.NormalizeErrors++
			st.addError(it.m.CVE, "normalize", it.nerr.Msg)
			log.Warn("normalize failed", "cve", it.m.CVE, "err", it.nerr.Msg)
		}
	}
}

func merge(st *Stats, b *Stats) {
	st.SkippedRace += b.SkippedRace
	st.Imported += b.Imported
	st.Published += b.Published
	st.Rejected += b.Rejected
	st.Reserved += b.Reserved
	st.OtherState += b.OtherState
	st.NormalizeErrors += b.NormalizeErrors
	st.FatalErrors += b.FatalErrors
	st.DecodeErrors += b.DecodeErrors
	st.NotObject += b.NotObject
	st.Oversized += b.Oversized
	st.Duplicates += b.Duplicates
	st.BatchRetries += b.BatchRetries
	for _, e := range b.Errors {
		if len(st.Errors) < maxErrorList {
			st.Errors = append(st.Errors, e)
		}
	}
	st.VulnInserted += b.VulnInserted
	st.VulnUpdated += b.VulnUpdated
	st.AliasInserted += b.AliasInserted
	st.AffectedInserted += b.AffectedInserted
	st.EventInserted += b.EventInserted
	st.EventUpdated += b.EventUpdated
}

func retryable(err error) bool {
	var pe *pgconn.PgError
	if errors.As(err, &pe) {
		switch pe.Code {
		case "40P01", "40001", "55P03":
			return true
		}
	}
	return false
}

// writeBatch writes one batch in one transaction (retried on deadlock,
// serialization failure or lock timeout). The returned Stats are this
// batch's counts, valid only after the commit succeeded.
func writeBatch(ctx context.Context, conn *pgx.Conn, b *batch, o Options, log *slog.Logger) (*Stats, error) {
	var lastErr error
	for attempt := 1; attempt <= o.BatchAttempts; attempt++ {
		bs, err := tryBatch(ctx, conn, b, o)
		if err == nil {
			bs.BatchRetries = attempt - 1
			for _, e := range bs.Errors {
				log.Warn("baseline record not applied", "detail", e)
			}
			return bs, nil
		}
		if !retryable(err) || ctx.Err() != nil {
			return nil, err
		}
		lastErr = err
		log.Warn("batch rolled back, retrying", "attempt", attempt, "err", err)
		t := time.NewTimer(time.Duration(attempt) * time.Second)
		select {
		case <-ctx.Done():
			t.Stop()
			return nil, ctx.Err()
		case <-t.C:
		}
	}
	return nil, fmt.Errorf("batch failed after %d attempts: %w", o.BatchAttempts, lastErr)
}

func tryBatch(ctx context.Context, conn *pgx.Conn, b *batch, o Options) (*Stats, error) {
	bs := &Stats{}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx)) //nolint:errcheck // no-op after Commit
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = '`+lockTimeout+`'`); err != nil {
		return nil, err
	}
	// Serialise with every raw_record writer (see Import).
	if _, err := tx.Exec(ctx, `LOCK TABLE raw_record IN SHARE ROW EXCLUSIVE MODE`); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SET LOCAL lock_timeout = 0`); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(b.items))
	for _, it := range b.items {
		ids = append(ids, it.m.CVE)
	}
	rows, err := tx.Query(ctx, `SELECT DISTINCT source_key FROM raw_record WHERE source = $1 AND source_key = ANY($2)`,
		cvelist.Name, ids)
	if err != nil {
		return nil, err
	}
	present, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, err
	}
	now := map[string]bool{}
	for _, k := range present {
		now[k] = true
	}
	observedAt := o.Now().UTC().Truncate(time.Microsecond)
	pst := &pipeline.Stats{}
	for i := range b.items {
		it := &b.items[i]
		if now[it.m.CVE] {
			bs.SkippedRace++
			continue
		}
		if countBad(bs, it) {
			continue
		}
		if it.fatal != nil {
			bs.FatalErrors++
			bs.addError(it.m.CVE, "fatal", it.fatal.Error())
			continue
		}
		ins, err := pipeline.StoreRaw(ctx, tx, it.rec, it.hash, o.SnapshotAt)
		if err != nil {
			return nil, fmt.Errorf("store raw %s: %w", it.m.CVE, err)
		}
		if !ins { // impossible under the lock unless the archive repeats an id
			bs.Duplicates++
			continue
		}
		now[it.m.CVE] = true
		bs.Imported++
		countState(bs, it.state)
		if it.nerr != nil {
			bs.NormalizeErrors++
			bs.addError(it.m.CVE, "normalize", it.nerr.Msg)
			continue
		}
		if err := pipeline.ApplyNormalized(ctx, tx, it.norm, observedAt, true, pst); err != nil {
			return nil, fmt.Errorf("apply %s: %w", it.m.CVE, err)
		}
	}
	if o.beforeCommit != nil {
		if err := o.beforeCommit(ctx, tx); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	bs.VulnInserted, bs.VulnUpdated = pst.VulnInserted, pst.VulnUpdated
	bs.AliasInserted, bs.AffectedInserted = pst.AliasInserted, pst.AffectedInserted
	bs.EventInserted, bs.EventUpdated = pst.EventInserted, pst.EventUpdated
	return bs, nil
}
