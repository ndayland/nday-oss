// Package tags derives CVE tags: a fixed vocabulary (vocab.go) assigned
// automatically from data already in the database, each assignment with the
// basis it rests on (derive.go). Schema: migrations/0011_tags.sql. Design,
// vocabulary and rules: docs/tags.md.
//
// A tag is nday's own derivation. Its basis names the facts and their
// provenance (a CWE id stated by the CNA and by NVD's analysts, a CVSS
// vector from the CNA, a KEV entry, a GitHub advisory); a tag is never
// presented as coming from one of those sources.
//
// Inputs, per CVE (load.go): vuln_cwe and vuln_cvss (type and access
// tags), vuln_classify_input (rejection flags; the classified version of
// each GitHub advisory, whose packages give ecosystem tags), the public
// lifecycle events kev_added and poc_published (exploit tags) and the CVE
// record's disclosed events (rejection), vuln_tag_suppress.
//
// Change detection ("never missed"): statement-level triggers of migration
// 0011 append the affected CVE ids to tag_queue in the same transaction as
// every INSERT, UPDATE and DELETE of vuln_cwe, vuln_cvss,
// vuln_classify_input, vuln_tag_suppress and of event rows of the types read
// here. Pending reads a batch of queue rows, derives those CVEs from inputs
// read by LATER statements (so every write whose queue row was read is
// visible), replaces the rule rows that differ and deletes exactly the queue
// rows it read, in one transaction. A bumped RuleVersion is not a database
// write: `nday tags --all` recomputes everything (All), and the post-collector
// pass warns until it has run with the current version.
//
// Concurrency: one session advisory lock serialises every writing run
// (Pending, All, ByCVE). Pending without Wait skips when another run holds
// the lock (the post-collector pass); that run, or the next one, drains
// what is left.
//
// Writes are minimal and atomic per CVE: a CVE whose derived (tag, basis,
// rule_version) set equals its stored rule rows is not touched; otherwise
// all its rule rows are replaced in the batch transaction. Staff rows are
// never read or written here. Nothing outside vuln_tag, vuln_tag_count,
// tag_run and tag_queue is written.
package tags

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
)

// Defaults.
const (
	DefaultBatchSize = 2000
	// lockClass is the high half of the advisory lock key ("ndtg"); the low
	// half is the oid of tag_queue, so each database/schema has its own.
	lockClass int64 = 0x6E647467 << 32
)

const lockKeySQL = `($1::bigint | 'tag_queue'::regclass::oid::bigint)`

// Options for a tag run.
type Options struct {
	// DryRun derives and compares, counts what would change, writes nothing
	// (each batch transaction is rolled back) and leaves the queue.
	DryRun bool
	// BatchSize: CVEs per transaction (default 2000).
	BatchSize int
	// Wait for the lock instead of returning Stats.Deferred.
	Wait bool
	// MaxQueue bounds the queue rows one Pending call takes (0 = all).
	MaxQueue int
	Logger   *slog.Logger
	// ProgressEvery logs progress every this many CVEs (0 = 50000).
	ProgressEvery int
	// ruleVersion overrides RuleVersion (tests: a version bump).
	ruleVersion int
	// afterRead is a test hook run inside each batch transaction after the
	// inputs were read and before anything is written.
	afterRead func(ctx context.Context, tx pgx.Tx) error
}

func (o *Options) defaults() {
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultBatchSize
	}
	if o.Logger == nil {
		o.Logger = slog.Default()
	}
	if o.ProgressEvery <= 0 {
		o.ProgressEvery = 50000
	}
	if o.ruleVersion == 0 {
		o.ruleVersion = RuleVersion
	}
}

// Stats of a run.
type Stats struct {
	Mode        string `json:"mode"`
	RuleVersion int    `json:"rule_version"`
	// Deferred: another run held the lock; nothing was done.
	Deferred bool `json:"deferred"`
	DryRun   bool `json:"dry_run"`
	// QueueRows: tag_queue rows consumed (Pending; All deletes the rows
	// queued before it started).
	QueueRows int `json:"queue_rows"`
	// CVEs examined; NoVuln: of those, without a vuln row (nothing to tag).
	CVEs   int `json:"cves"`
	NoVuln int `json:"no_vuln"`
	// Rejected: CVEs that are rejected (they get no tags).
	Rejected int `json:"rejected"`
	// Changed / Unchanged: CVEs whose rule rows were replaced / already equal.
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
	// Rows deleted and inserted (would be, in a dry run).
	Deleted  int `json:"deleted"`
	Inserted int `json:"inserted"`
	// Tagged: CVEs with at least one rule tag after the run (of those examined).
	Tagged int `json:"tagged"`
	// CountsRefreshed: vuln_tag_count was rebuilt.
	CountsRefreshed bool    `json:"counts_refreshed"`
	Batches         int     `json:"batches"`
	ElapsedSec      float64 `json:"elapsed_sec"`
}

func (s *Stats) merge(b *Stats) {
	s.Batches++
	s.CVEs += b.CVEs
	s.NoVuln += b.NoVuln
	s.Rejected += b.Rejected
	s.Changed += b.Changed
	s.Unchanged += b.Unchanged
	s.Deleted += b.Deleted
	s.Inserted += b.Inserted
	s.Tagged += b.Tagged
}

var errLocked = errors.New("tags: another run holds the lock")

func lock(ctx context.Context, conn *pgx.Conn, wait bool) (func(), error) {
	if wait {
		if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock`+lockKeySQL, lockClass); err != nil {
			return nil, fmt.Errorf("tags lock: %w", err)
		}
	} else {
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock`+lockKeySQL, lockClass).Scan(&got); err != nil {
			return nil, fmt.Errorf("tags lock: %w", err)
		}
		if !got {
			return nil, errLocked
		}
	}
	return func() {
		_, _ = conn.Exec(context.WithoutCancel(ctx), `SELECT pg_advisory_unlock`+lockKeySQL, lockClass)
	}, nil
}

func run(ctx context.Context, conn *pgx.Conn, mode string, o Options, body func(*Stats) error) (*Stats, error) {
	o.defaults()
	st := &Stats{Mode: mode, DryRun: o.DryRun, RuleVersion: o.ruleVersion}
	start := time.Now()
	unlock, err := lock(ctx, conn, o.Wait)
	if errors.Is(err, errLocked) {
		st.Deferred = true
		o.Logger.Info("tags: another run holds the lock; it or the next run drains the queue", "mode", mode)
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	defer unlock()
	err = body(st)
	if err == nil && !o.DryRun && (st.Changed > 0 || mode == "all") {
		if err = RefreshCounts(ctx, conn); err == nil {
			st.CountsRefreshed = true
		}
	}
	st.ElapsedSec = time.Since(start).Seconds()
	return st, err
}

// Pending drains tag_queue (the incremental pass).
func Pending(ctx context.Context, conn *pgx.Conn, o Options) (*Stats, error) {
	o.defaults()
	return run(ctx, conn, "pending", o, func(st *Stats) error {
		lastID := int64(0) // dry run: walk the queue without deleting
		for o.MaxQueue <= 0 || st.QueueRows < o.MaxQueue {
			n := o.BatchSize
			if o.MaxQueue > 0 {
				n = min(n, o.MaxQueue-st.QueueRows)
			}
			rows, err := conn.Query(ctx, `SELECT id, cve_id FROM tag_queue WHERE id > $1 ORDER BY id LIMIT $2`, lastID, n)
			if err != nil {
				return err
			}
			var ids []int64
			var cves []string
			seen := map[string]bool{}
			for rows.Next() {
				var id int64
				var cve string
				if err := rows.Scan(&id, &cve); err != nil {
					rows.Close()
					return err
				}
				ids = append(ids, id)
				if !seen[cve] {
					seen[cve] = true
					cves = append(cves, cve)
				}
			}
			rows.Close()
			if err := rows.Err(); err != nil {
				return err
			}
			if len(ids) == 0 {
				return nil
			}
			lastID = ids[len(ids)-1]
			sort.Strings(cves)
			if err := processBatch(ctx, conn, cves, ids, o, st); err != nil {
				return err
			}
			st.QueueRows += len(ids)
		}
		return nil
	})
}

// All recomputes every CVE that has a vuln row (the initial backfill, and
// after a RuleVersion bump). The queue rows that existed when it started are
// deleted at the end (every write they stand for committed before the run
// started, so each batch read it), and tag_run records the rule version.
func All(ctx context.Context, conn *pgx.Conn, o Options) (*Stats, error) {
	o.defaults()
	return run(ctx, conn, "all", o, func(st *Stats) error {
		var maxID int64
		if err := conn.QueryRow(ctx, `SELECT COALESCE(max(id), 0) FROM tag_queue`).Scan(&maxID); err != nil {
			return err
		}
		after := ""
		next := o.ProgressEvery
		for {
			rows, err := conn.Query(ctx, `SELECT cve_id FROM vuln WHERE cve_id > $1 ORDER BY cve_id LIMIT $2`, after, o.BatchSize)
			if err != nil {
				return err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				break
			}
			after = ids[len(ids)-1]
			if err := processBatch(ctx, conn, ids, nil, o, st); err != nil {
				return err
			}
			if st.CVEs >= next {
				o.Logger.Info("tags progress", "cves", st.CVEs, "changed", st.Changed, "inserted", st.Inserted)
				next += o.ProgressEvery
			}
		}
		// (Rule rows of a slug retired by a rule change need no extra step:
		// every CVE was just compared with the current rules and rewritten.)
		if o.DryRun {
			return nil
		}
		if maxID > 0 {
			tag, err := conn.Exec(ctx, `DELETE FROM tag_queue WHERE id <= $1`, maxID)
			if err != nil {
				return err
			}
			st.QueueRows = int(tag.RowsAffected())
		}
		_, err := conn.Exec(ctx, `UPDATE tag_run SET all_rule_version = $1, all_completed_at = now() WHERE id = 1`, o.ruleVersion)
		return err
	})
}

// ByCVE recomputes the given CVEs.
func ByCVE(ctx context.Context, conn *pgx.Conn, ids []string, o Options) (*Stats, error) {
	o.defaults()
	ids = append([]string(nil), ids...)
	sort.Strings(ids)
	return run(ctx, conn, "cve", o, func(st *Stats) error {
		for i := 0; i < len(ids); i += o.BatchSize {
			if err := processBatch(ctx, conn, ids[i:min(i+o.BatchSize, len(ids))], nil, o, st); err != nil {
				return err
			}
		}
		return nil
	})
}

// RefreshCounts rebuilds vuln_tag_count (visible tags, each CVE counted
// once per tag) and stamps tag_run.counts_refreshed_at, in one transaction
// (readers see the old or the new counts, never a mix).
func RefreshCounts(ctx context.Context, conn *pgx.Conn) error {
	return pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM vuln_tag_count`); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO vuln_tag_count (tag, n)
            SELECT tag, count(DISTINCT cve_id) FROM vuln_tag_visible GROUP BY tag`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `UPDATE tag_run SET counts_refreshed_at = now() WHERE id = 1`)
		return err
	})
}

// RuleVersionState reports the rule version of the last complete --all run
// (0 when it never ran).
func RuleVersionState(ctx context.Context, conn *pgx.Conn) (int, error) {
	var v *int
	if err := conn.QueryRow(ctx, `SELECT all_rule_version FROM tag_run WHERE id = 1`).Scan(&v); err != nil {
		return 0, err
	}
	if v == nil {
		return 0, nil
	}
	return *v, nil
}

// storedRow is one stored rule row.
type storedRow struct {
	tag, basis string // basis: canonical JSON
	version    int
}

func rowKey(tag, basis string, version int) string {
	return fmt.Sprintf("%s\x00%d\x00%s", tag, version, basis)
}

var errDryRun = errors.New("dry run: rolled back")

// processBatch derives cves (sorted, distinct) and replaces the rule rows
// of every CVE whose result differs, in one transaction that also deletes
// queueIDs.
func processBatch(ctx context.Context, conn *pgx.Conn, cves []string, queueIDs []int64, o Options, st *Stats) error {
	bst := Stats{}
	err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		bst = Stats{CVEs: len(cves)}
		inputs, err := loadInputs(ctx, tx, cves)
		if err != nil {
			return err
		}
		bst.NoVuln = len(cves) - len(inputs)
		ids := make([]string, 0, len(inputs))
		for _, c := range cves {
			if inputs[c] != nil {
				ids = append(ids, c)
			}
		}
		stored, err := loadStored(ctx, tx, ids)
		if err != nil {
			return err
		}
		if o.afterRead != nil {
			if err := o.afterRead(ctx, tx); err != nil {
				return err
			}
		}
		type newRow struct {
			cve, tag, basis string
		}
		var changed []string
		var rows []newRow
		for _, cve := range ids {
			in := inputs[cve]
			if in.Rejected {
				bst.Rejected++
			}
			got := Derive(*in)
			if len(got) > 0 {
				bst.Tagged++
			}
			want := make([]string, 0, len(got))
			var add []newRow
			for _, a := range got {
				b := a.Basis.Canonical()
				want = append(want, rowKey(a.Slug, b, o.ruleVersion))
				add = append(add, newRow{cve, a.Slug, b})
			}
			sort.Strings(want)
			have := make([]string, 0, len(stored[cve]))
			for _, r := range stored[cve] {
				have = append(have, rowKey(r.tag, r.basis, r.version))
			}
			sort.Strings(have)
			if equalStrings(want, have) {
				if len(want) > 0 {
					bst.Unchanged++
				}
				continue
			}
			bst.Changed++
			bst.Deleted += len(have)
			bst.Inserted += len(add)
			changed = append(changed, cve)
			rows = append(rows, add...)
		}
		if len(changed) > 0 {
			if _, err := tx.Exec(ctx, `DELETE FROM vuln_tag WHERE cve_id = ANY($1) AND origin = 'rule'`, changed); err != nil {
				return err
			}
			if len(rows) > 0 {
				now := time.Now().UTC()
				if _, err := tx.CopyFrom(ctx, pgx.Identifier{"vuln_tag"},
					[]string{"cve_id", "tag", "origin", "basis", "rule_version", "created_at"},
					pgx.CopyFromSlice(len(rows), func(i int) ([]any, error) {
						r := rows[i]
						return []any{r.cve, r.tag, "rule", r.basis, o.ruleVersion, now}, nil
					})); err != nil {
					return fmt.Errorf("insert vuln_tag: %w", err)
				}
			}
		}
		if len(queueIDs) > 0 && !o.DryRun {
			if _, err := tx.Exec(ctx, `DELETE FROM tag_queue WHERE id = ANY($1)`, queueIDs); err != nil {
				return err
			}
		}
		if o.DryRun {
			return errDryRun
		}
		return nil
	})
	if err != nil && !errors.Is(err, errDryRun) {
		return err
	}
	st.merge(&bst)
	return nil
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// loadStored reads the stored rule rows of ids.
func loadStored(ctx context.Context, tx pgx.Tx, ids []string) (map[string][]storedRow, error) {
	out := map[string][]storedRow{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := tx.Query(ctx, `SELECT cve_id, tag, basis::text, rule_version FROM vuln_tag
        WHERE cve_id = ANY($1) AND origin = 'rule'`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var cve, tag, basis string
		var v int
		if err := rows.Scan(&cve, &tag, &basis, &v); err != nil {
			return nil, err
		}
		c, err := CanonicalJSON([]byte(basis))
		if err != nil {
			c = basis // cannot happen for jsonb; compares unequal and is rewritten
		}
		out[cve] = append(out[cve], storedRow{tag: tag, basis: c, version: v})
	}
	return out, rows.Err()
}
