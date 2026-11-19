// Package classify maintains the classification layer: per CVE, the CWE ids
// (vuln_cwe) and CVSS vectors (vuln_cvss) that the CVE record (CNA and ADP
// containers), NVD and GitHub advisories deliver, each row with its
// provenance, plus vuln_classify_input (which raw record version each
// CVE's rows came from, and whether that source marks the CVE rejected).
// Schema: migrations/0009_classify.sql. Rules: derive.go and docs/nvd.md.
//
// Everything is derived from the LATEST raw_record of each source (the
// pipeline's order: fetched_at DESC, id DESC); this package never writes
// raw_record, vuln, event or anything vuln_state reads, and never changes
// what the collectors' Normalize produce.
//
// Change detection ("never missed"): triggers of migration 0009 append the
// CVE id to classify_queue in the same transaction as
//   - every raw_record INSERT of cvelist / nvd / ghsa (a new content
//     version),
//   - every raw_record UPDATE OF fetched_at (an older version that became
//     the latest again: the pipeline bumps fetched_at instead of inserting),
//   - every vuln INSERT (a CVE whose NVD or GHSA raw record arrived before
//     its vuln row: rows need the vuln row, so it is classified now).
//
// Pending drains the queue: it reads a batch of queue rows, derives those
// CVEs from raw records read by LATER statements (so every write whose
// queue row was read is visible), writes the rows and deletes exactly the
// queue rows it read, all in one transaction. A write that commits while a
// batch runs leaves its own queue row for the next batch or run. Queue
// rows are never merged or upserted, so no write can be absorbed by a row
// that is being processed.
//
// Concurrency: one session advisory lock serialises every writing run
// (Pending, All, BySource, ByCVE). Pending without Wait skips when another
// run holds the lock (the post-collector pass); that run, or the next one,
// drains what is left.
//
// Writes are minimal: a (CVE, raw source) whose derived rows equal the
// stored ones is not touched, so re-running writes nothing.
package classify

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Defaults.
const (
	DefaultBatchSize = 2000
	// lockClass is the high half of the advisory lock key ("ndcl"); the low
	// half is the oid of classify_queue, so each database/schema has its own.
	lockClass int64 = 0x6E64636C << 32
)

const lockKeySQL = `($1::bigint | 'classify_queue'::regclass::oid::bigint)`

// Options for a classify run.
type Options struct {
	// DryRun derives and compares, counts what would change, writes nothing
	// (the transaction of each batch is rolled back) and leaves the queue.
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
	// afterRead is a test hook run inside each batch transaction after the
	// raw records were read and before anything is written.
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
}

// Stats of a run.
type Stats struct {
	Mode string `json:"mode"`
	// Deferred: another run held the lock; nothing was done.
	Deferred bool `json:"deferred"`
	DryRun   bool `json:"dry_run"`
	// QueueRows: classify_queue rows consumed (Pending; All deletes the
	// rows queued before it started).
	QueueRows int `json:"queue_rows"`
	// CVEs examined; NoVuln: of those, without a vuln row (skipped; a later
	// vuln insert queues them again).
	CVEs   int `json:"cves"`
	NoVuln int `json:"no_vuln"`
	// Busy: of those, whose vuln row another transaction held (a collector
	// run, a merge); skipped and left queued for the next run.
	Busy int `json:"busy"`
	// Inputs: raw records derived (one per CVE and source, one per advisory
	// for ghsa). Rejected: of those, marking the CVE rejected.
	Inputs   int `json:"inputs"`
	Rejected int `json:"rejected"`
	// Changed / Unchanged: (CVE, raw source) pairs whose rows were replaced /
	// already equal.
	Changed   int `json:"changed"`
	Unchanged int `json:"unchanged"`
	// Rows deleted and inserted (would be, in a dry run).
	CWEDeleted   int `json:"cwe_deleted"`
	CWEInserted  int `json:"cwe_inserted"`
	CVSSDeleted  int `json:"cvss_deleted"`
	CVSSInserted int `json:"cvss_inserted"`
	// Skipped facts (see Derived): not stored.
	CWESkipped  int `json:"cwe_skipped"`
	CVSSSkipped int `json:"cvss_skipped"`
	// DeriveErrors: raw records whose payload could not be decoded (their
	// CVE keeps its previous rows of that source; listed in Errors).
	DeriveErrors int      `json:"derive_errors"`
	Errors       []string `json:"errors,omitempty"`
	Batches      int      `json:"batches"`
	ElapsedSec   float64  `json:"elapsed_sec"`
}

func (s *Stats) addError(msg string) {
	s.DeriveErrors++
	if len(s.Errors) < 100 {
		s.Errors = append(s.Errors, msg)
	}
}

// ---------------------------------------------------------------- locking

// ErrLocked is returned by tryLock when another run holds the lock.
var errLocked = errors.New("classify: another run holds the lock")

func lock(ctx context.Context, conn *pgx.Conn, wait bool) (func(), error) {
	if wait {
		if _, err := conn.Exec(ctx, `SELECT pg_advisory_lock`+lockKeySQL, lockClass); err != nil {
			return nil, fmt.Errorf("classify lock: %w", err)
		}
	} else {
		var got bool
		if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock`+lockKeySQL, lockClass).Scan(&got); err != nil {
			return nil, fmt.Errorf("classify lock: %w", err)
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
	st := &Stats{Mode: mode, DryRun: o.DryRun}
	start := time.Now()
	unlock, err := lock(ctx, conn, o.Wait)
	if errors.Is(err, errLocked) {
		st.Deferred = true
		o.Logger.Info("classify: another run holds the lock; it or the next run drains the queue", "mode", mode)
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	defer unlock()
	err = body(st)
	st.ElapsedSec = time.Since(start).Seconds()
	return st, err
}

// ------------------------------------------------------------------- modes

// Pending drains classify_queue (the incremental pass).
func Pending(ctx context.Context, conn *pgx.Conn, o Options) (*Stats, error) {
	o.defaults()
	return run(ctx, conn, "pending", o, func(st *Stats) error {
		lastID := int64(0) // dry run: walk the queue without deleting
		for o.MaxQueue <= 0 || st.QueueRows < o.MaxQueue {
			n := o.BatchSize
			if o.MaxQueue > 0 {
				n = min(n, o.MaxQueue-st.QueueRows)
			}
			rows, err := conn.Query(ctx, `SELECT id, cve_id FROM classify_queue WHERE id > $1 ORDER BY id LIMIT $2`, lastID, n)
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
			if err := processBatch(ctx, conn, cves, Families, ids, o, st); err != nil {
				return err
			}
			st.QueueRows += len(ids)
		}
		return nil
	})
}

// All re-derives every CVE that has a vuln row, from all three sources (the
// initial backfill). The queue rows that existed when it started are
// deleted at the end: every write they stand for committed before the run
// started, so each batch read it.
func All(ctx context.Context, conn *pgx.Conn, o Options) (*Stats, error) {
	o.defaults()
	return run(ctx, conn, "all", o, func(st *Stats) error {
		var maxID int64
		if err := conn.QueryRow(ctx, `SELECT COALESCE(max(id), 0) FROM classify_queue`).Scan(&maxID); err != nil {
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
			if err := processBatch(ctx, conn, ids, Families, nil, o, st); err != nil {
				return err
			}
			if st.CVEs >= next {
				o.Logger.Info("classify progress", "cves", st.CVEs, "changed", st.Changed, "cwe_inserted", st.CWEInserted,
					"cvss_inserted", st.CVSSInserted)
				next += o.ProgressEvery
			}
		}
		if !o.DryRun && maxID > 0 {
			tag, err := conn.Exec(ctx, `DELETE FROM classify_queue WHERE id <= $1`, maxID)
			if err != nil {
				return err
			}
			st.QueueRows = int(tag.RowsAffected())
		}
		return nil
	})
}

// BySource re-derives, from one raw source only, every CVE that source has
// a raw record for (and, for ghsa, every CVE that has ghsa rows).
func BySource(ctx context.Context, conn *pgx.Conn, source string, o Options) (*Stats, error) {
	o.defaults()
	if _, ok := familySources[source]; !ok {
		return nil, fmt.Errorf("classify: unknown source %q (choose from %s)", source, strings.Join(Families, ", "))
	}
	return run(ctx, conn, "source:"+source, o, func(st *Stats) error {
		if source == FamGHSA {
			// every advisory's CVE, its GHSA id (the vuln's id while it has
			// no CVE; skipped when there is no such vuln row), and every id
			// that has ghsa rows
			rows, err := conn.Query(ctx, `SELECT c FROM (
                SELECT payload->>'cve_id' AS c FROM raw_record WHERE source = 'ghsa'
                UNION SELECT source_key FROM raw_record WHERE source = 'ghsa'
                UNION SELECT cve_id FROM vuln_classify_input WHERE source = 'ghsa') s
                WHERE c IS NOT NULL ORDER BY c`)
			if err != nil {
				return err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			for i := 0; i < len(ids); i += o.BatchSize {
				if err := processBatch(ctx, conn, ids[i:min(i+o.BatchSize, len(ids))], []string{source}, nil, o, st); err != nil {
					return err
				}
			}
			return nil
		}
		after := ""
		next := o.ProgressEvery
		for {
			rows, err := conn.Query(ctx, `SELECT DISTINCT source_key FROM raw_record
                WHERE source = $1 AND source_key > $2 ORDER BY source_key LIMIT $3`, source, after, o.BatchSize)
			if err != nil {
				return err
			}
			ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				return nil
			}
			after = ids[len(ids)-1]
			if err := processBatch(ctx, conn, ids, []string{source}, nil, o, st); err != nil {
				return err
			}
			if st.CVEs >= next {
				o.Logger.Info("classify progress", "source", source, "cves", st.CVEs, "changed", st.Changed)
				next += o.ProgressEvery
			}
		}
	})
}

// ByCVE re-derives the given CVEs from all sources.
func ByCVE(ctx context.Context, conn *pgx.Conn, ids []string, o Options) (*Stats, error) {
	o.defaults()
	ids = append([]string(nil), ids...)
	sort.Strings(ids)
	return run(ctx, conn, "cve", o, func(st *Stats) error {
		for i := 0; i < len(ids); i += o.BatchSize {
			if err := processBatch(ctx, conn, ids[i:min(i+o.BatchSize, len(ids))], Families, nil, o, st); err != nil {
				return err
			}
		}
		return nil
	})
}

// ------------------------------------------------------------------- batch

// Projections keep only what the derivation reads (the CVE record's
// affected/references and NVD's configurations are most of the bytes), in
// the same shape as the full payload, so Derive* see the same values.
const (
	cvelistProjection = `jsonb_build_object(
        'cveMetadata', jsonb_build_object('state', payload->'cveMetadata'->'state',
                                          'assignerShortName', payload->'cveMetadata'->'assignerShortName'),
        'containers', jsonb_build_object(
            'cna', jsonb_build_object('providerMetadata', payload->'containers'->'cna'->'providerMetadata',
                                      'problemTypes', payload->'containers'->'cna'->'problemTypes',
                                      'metrics', payload->'containers'->'cna'->'metrics'),
            'adp', CASE WHEN jsonb_typeof(payload->'containers'->'adp') = 'array' THEN
                     (SELECT jsonb_agg(CASE WHEN jsonb_typeof(a) = 'object' THEN
                                 jsonb_build_object('providerMetadata', a->'providerMetadata',
                                                    'problemTypes', a->'problemTypes', 'metrics', a->'metrics')
                             END ORDER BY o)
                      FROM jsonb_array_elements(payload->'containers'->'adp') WITH ORDINALITY AS x(a, o))
                   END))`
	nvdProjection = `jsonb_build_object('vulnStatus', payload->'vulnStatus',
        'weaknesses', payload->'weaknesses', 'metrics', payload->'metrics')`
	ghsaProjection = `jsonb_build_object('cve_id', payload->'cve_id', 'ghsa_id', payload->'ghsa_id',
        'withdrawn_at', payload->'withdrawn_at', 'cwes', payload->'cwes', 'cvss', payload->'cvss',
        'cvss_severities', payload->'cvss_severities')`
)

func latestSQL(projection string) string {
	return `SELECT DISTINCT ON (source_key) source_key, content_hash, jsonb_typeof(payload), ` + projection + `::text
FROM raw_record WHERE source = $1 AND source_key = ANY($2)
ORDER BY source_key, fetched_at DESC, id DESC`
}

// The latest version of every advisory that names one of the ids in any
// version, that is one of the ids (a GHSA-keyed vuln is its own advisory),
// or that fed one of them before.
var ghsaLatestSQL = `SELECT DISTINCT ON (r.source_key) r.source_key, r.content_hash, jsonb_typeof(r.payload), ` +
	strings.ReplaceAll(ghsaProjection, "payload", "r.payload") + `::text
FROM raw_record r
WHERE r.source = 'ghsa' AND r.source_key IN (
    SELECT source_key FROM raw_record WHERE source = 'ghsa' AND payload->>'cve_id' = ANY($1)
    UNION SELECT source_key FROM raw_record WHERE source = 'ghsa' AND source_key = ANY($1)
    UNION SELECT source_key FROM vuln_classify_input WHERE source = 'ghsa' AND cve_id = ANY($1))
ORDER BY r.source_key, r.fetched_at DESC, r.id DESC`

// input is one derived raw record.
type input struct {
	family, key, hash string
	d                 *Derived
}

func (in input) inputKey() string {
	return fmt.Sprintf("%s\x00%s\x00%t\x00%d\x00%d", in.key, in.hash, in.d.Rejected, in.d.CWESkipped, in.d.CVSSSkipped)
}

// pairKey is (CVE, raw source).
type pairKey struct{ cve, family string }

// state is the rows of one pair, as canonical keys.
type pairState struct {
	cwe, cvss, inputs []string
}

func (a pairState) equal(b pairState) bool {
	eq := func(x, y []string) bool {
		if len(x) != len(y) {
			return false
		}
		for i := range x {
			if x[i] != y[i] {
				return false
			}
		}
		return true
	}
	return eq(a.cwe, b.cwe) && eq(a.cvss, b.cvss) && eq(a.inputs, b.inputs)
}

// processBatch derives cves (sorted, distinct) from the given raw sources
// and replaces the stored rows of every (CVE, source) that differs, in one
// transaction that also deletes queueIDs.
func processBatch(ctx context.Context, conn *pgx.Conn, cves []string, families []string, queueIDs []int64,
	o Options, st *Stats) error {
	bst := Stats{}
	err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
		bst = Stats{}
		bst.CVEs = len(cves)
		// 1. which CVEs have a vuln row (the FK target), locked until
		// commit; busy rows are skipped (LockVulns)
		have, busy, err := LockVulns(ctx, tx, cves)
		if err != nil {
			return err
		}
		bst.Busy = len(busy)
		if err := keepBusy(ctx, tx, "classify_queue", busy, queueIDs, o.DryRun); err != nil {
			return err
		}
		inVuln := make(map[string]bool, len(have))
		for _, c := range have {
			inVuln[c] = true
		}
		ids := make([]string, 0, len(have))
		for _, c := range cves {
			if inVuln[c] {
				ids = append(ids, c)
			}
		}
		bst.NoVuln = len(cves) - len(ids) - len(busy)
		// 2. derive from the latest raw records
		derived := map[pairKey][]input{}
		failed := map[pairKey]bool{}
		for _, fam := range families {
			var q string
			var args []any
			if fam == FamGHSA {
				q, args = ghsaLatestSQL, []any{ids}
			} else {
				proj := cvelistProjection
				if fam == FamNVD {
					proj = nvdProjection
				}
				q, args = latestSQL(proj), []any{fam, ids}
			}
			rows, err := tx.Query(ctx, q, args...)
			if err != nil {
				return fmt.Errorf("read %s raw records: %w", fam, err)
			}
			type rr struct{ key, hash, typ, payload string }
			recs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (rr, error) {
				var x rr
				return x, r.Scan(&x.key, &x.hash, &x.typ, &x.payload)
			})
			if err != nil {
				return fmt.Errorf("read %s raw records: %w", fam, err)
			}
			for _, r := range recs {
				var d *Derived
				cve := r.key
				if r.typ != "object" {
					// the projection would turn it into an empty object;
					// keep the previous rows instead
					bst.addError(fmt.Sprintf("%s/%s: payload is a JSON %s, not an object", fam, r.key, r.typ))
					if fam != FamGHSA {
						failed[pairKey{cve, fam}] = true
					}
					continue
				}
				switch fam {
				case FamCVEList:
					d, err = DeriveCVE5(cve, []byte(r.payload))
				case FamNVD:
					d, err = DeriveNVD(cve, []byte(r.payload))
				case FamGHSA:
					cve, d, err = DeriveGHSA([]byte(r.payload))
				}
				if err != nil {
					bst.addError(fmt.Sprintf("%s/%s: %v", fam, r.key, err))
					if fam != FamGHSA {
						failed[pairKey{cve, fam}] = true
					}
					continue
				}
				if !inVuln[cve] {
					continue // ghsa advisory now naming a CVE outside this batch / without vuln
				}
				derived[pairKey{cve, fam}] = append(derived[pairKey{cve, fam}], input{family: fam, key: r.key, hash: r.hash, d: d})
			}
		}
		if o.afterRead != nil {
			if err := o.afterRead(ctx, tx); err != nil {
				return err
			}
		}
		// 3. stored rows
		stored, err := loadStored(ctx, tx, ids, families)
		if err != nil {
			return err
		}
		// 4. compare and collect replacements per family
		type repl struct {
			cves []string
			cwe  []CWERow
			cvss []CVSSRow
			ins  []input
		}
		byFam := map[string]*repl{}
		for _, fam := range families {
			byFam[fam] = &repl{}
		}
		for _, cve := range ids {
			for _, fam := range families {
				pk := pairKey{cve, fam}
				if failed[pk] {
					continue
				}
				ins := derived[pk]
				var want pairState
				var cw []CWERow
				var cv []CVSSRow
				seenCWE, seenCVSS := map[string]bool{}, map[string]bool{}
				for _, in := range ins {
					bst.Inputs++
					if in.d.Rejected {
						bst.Rejected++
					}
					bst.CWESkipped += in.d.CWESkipped
					bst.CVSSSkipped += in.d.CVSSSkipped
					want.inputs = append(want.inputs, in.inputKey())
					for _, r := range in.d.CWEs {
						if k := r.key(); !seenCWE[k] {
							seenCWE[k] = true
							cw = append(cw, r)
							want.cwe = append(want.cwe, k)
						}
					}
					for _, r := range in.d.CVSS {
						pkk := r.Version + "\x00" + r.Source + "\x00" + r.SourceOrg
						if !seenCVSS[pkk] {
							seenCVSS[pkk] = true
							cv = append(cv, r)
							want.cvss = append(want.cvss, r.key())
						}
					}
				}
				sort.Strings(want.cwe)
				sort.Strings(want.cvss)
				sort.Strings(want.inputs)
				have := stored[pk]
				if have.equal(want) {
					if len(ins) > 0 || len(have.cwe)+len(have.cvss)+len(have.inputs) > 0 {
						bst.Unchanged++
					}
					continue
				}
				bst.Changed++
				bst.CWEDeleted += len(have.cwe)
				bst.CVSSDeleted += len(have.cvss)
				bst.CWEInserted += len(cw)
				bst.CVSSInserted += len(cv)
				r := byFam[fam]
				r.cves = append(r.cves, cve)
				r.cwe = append(r.cwe, cw...)
				r.cvss = append(r.cvss, cv...)
				r.ins = append(r.ins, ins...)
			}
		}
		// 5. write
		now := time.Now().UTC()
		for _, fam := range families {
			r := byFam[fam]
			if len(r.cves) == 0 {
				continue
			}
			srcs := familySources[fam]
			if _, err := tx.Exec(ctx, `DELETE FROM vuln_cwe WHERE cve_id = ANY($1) AND source = ANY($2)`, r.cves, srcs); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM vuln_cvss WHERE cve_id = ANY($1) AND source = ANY($2)`, r.cves, srcs); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM vuln_classify_input WHERE cve_id = ANY($1) AND source = $2`, r.cves, fam); err != nil {
				return err
			}
			if len(r.cwe) > 0 {
				if _, err := tx.CopyFrom(ctx, pgx.Identifier{"vuln_cwe"}, []string{"cve_id", "cwe", "source", "source_org"},
					pgx.CopyFromSlice(len(r.cwe), func(i int) ([]any, error) {
						x := r.cwe[i]
						return []any{x.CVEID, x.CWE, x.Source, x.SourceOrg}, nil
					})); err != nil {
					return fmt.Errorf("insert vuln_cwe: %w", err)
				}
			}
			if len(r.cvss) > 0 {
				if _, err := tx.CopyFrom(ctx, pgx.Identifier{"vuln_cvss"},
					[]string{"cve_id", "version", "vector", "base_score", "severity", "source", "source_org"},
					pgx.CopyFromSlice(len(r.cvss), func(i int) ([]any, error) {
						x := r.cvss[i]
						return []any{x.CVEID, x.Version, x.Vector, x.BaseScore, x.Severity, x.Source, x.SourceOrg}, nil
					})); err != nil {
					return fmt.Errorf("insert vuln_cvss: %w", err)
				}
			}
			if len(r.ins) > 0 {
				if _, err := tx.CopyFrom(ctx, pgx.Identifier{"vuln_classify_input"},
					[]string{"cve_id", "source", "source_key", "content_hash", "rejected", "cwe_skipped", "cvss_skipped", "classified_at"},
					pgx.CopyFromSlice(len(r.ins), func(i int) ([]any, error) {
						x := r.ins[i]
						return []any{x.d.CVEID, x.family, x.key, x.hash, x.d.Rejected, x.d.CWESkipped, x.d.CVSSSkipped, now}, nil
					})); err != nil {
					return fmt.Errorf("insert vuln_classify_input: %w", err)
				}
			}
		}
		if len(queueIDs) > 0 && !o.DryRun {
			// (a busy id's rows stay; the condition is checked on the
			// version this statement sees, so it never waits for them)
			if _, err := tx.Exec(ctx, `DELETE FROM classify_queue WHERE id = ANY($1) AND cve_id <> ALL(COALESCE($2::text[], '{}'))`, queueIDs, busy); err != nil {
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

var errDryRun = errors.New("dry run: rolled back")

// LockVulns locks the vuln rows of ids (sorted, distinct) FOR KEY SHARE
// until the transaction ends and returns the ids that have one (have) and
// those whose row another transaction holds (busy). The lock keeps a merge
// of a GHSA-keyed vuln into its CVE (docs/ghsa.md), which deletes the
// GHSA-keyed row, from running between the batch's read and its writes
// (the writes' foreign keys need the row). A row another transaction holds
// in a conflicting mode (a collector run's upsert FOR UPDATE, a merge, a
// delete) is skipped, not waited for: waiting while holding the rows
// already locked, and the rows the batch then rewrites, could close a cycle
// with that transaction (deadlock_detected). The caller leaves the busy
// ids queued for the next run. Used by internal/tags as well.
func LockVulns(ctx context.Context, tx pgx.Tx, ids []string) (have, busy []string, err error) {
	rows, err := tx.Query(ctx, `SELECT cve_id FROM vuln WHERE cve_id = ANY($1) ORDER BY cve_id FOR KEY SHARE SKIP LOCKED`, ids)
	if err != nil {
		return nil, nil, err
	}
	if have, err = pgx.CollectRows(rows, pgx.RowTo[string]); err != nil {
		return nil, nil, err
	}
	got := make(map[string]bool, len(have))
	for _, id := range have {
		got[id] = true
	}
	var rest []string
	for _, id := range ids {
		if !got[id] {
			rest = append(rest, id)
		}
	}
	if len(rest) == 0 {
		return have, nil, nil
	}
	// skipped: busy if the row is still there (or being deleted), else gone
	rows, err = tx.Query(ctx, `SELECT cve_id FROM vuln WHERE cve_id = ANY($1) ORDER BY cve_id`, rest)
	if err != nil {
		return nil, nil, err
	}
	busy, err = pgx.CollectRows(rows, pgx.RowTo[string])
	return have, busy, err
}

// keepBusy makes sure busy ids are recomputed later: a pass over the queue
// (queueIDs != nil) keeps their rows; any other pass queues them in table
// (classify_queue has no foreign key, so this takes no lock on vuln).
func keepBusy(ctx context.Context, tx pgx.Tx, table string, busy []string, queueIDs []int64, dryRun bool) error {
	if len(busy) == 0 || queueIDs != nil || dryRun {
		return nil
	}
	_, err := tx.Exec(ctx, `INSERT INTO `+table+` (cve_id) SELECT unnest($1::text[])`, busy)
	return err
}

func (s *Stats) merge(b *Stats) {
	s.Batches++
	s.CVEs += b.CVEs
	s.NoVuln += b.NoVuln
	s.Busy += b.Busy
	s.Inputs += b.Inputs
	s.Rejected += b.Rejected
	s.Changed += b.Changed
	s.Unchanged += b.Unchanged
	s.CWEDeleted += b.CWEDeleted
	s.CWEInserted += b.CWEInserted
	s.CVSSDeleted += b.CVSSDeleted
	s.CVSSInserted += b.CVSSInserted
	s.CWESkipped += b.CWESkipped
	s.CVSSSkipped += b.CVSSSkipped
	s.DeriveErrors += b.DeriveErrors
	for _, e := range b.Errors {
		if len(s.Errors) < 100 {
			s.Errors = append(s.Errors, e)
		}
	}
}

// loadStored reads the stored rows of ids for the given raw sources.
func loadStored(ctx context.Context, tx pgx.Tx, ids []string, families []string) (map[pairKey]pairState, error) {
	famOf := map[string]string{}
	var srcs []string
	for _, f := range families {
		for _, s := range familySources[f] {
			famOf[s] = f
			srcs = append(srcs, s)
		}
	}
	out := map[pairKey]pairState{}
	rows, err := tx.Query(ctx, `SELECT cve_id, cwe, source, source_org FROM vuln_cwe WHERE cve_id = ANY($1) AND source = ANY($2)`, ids, srcs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r CWERow
		if err := rows.Scan(&r.CVEID, &r.CWE, &r.Source, &r.SourceOrg); err != nil {
			rows.Close()
			return nil, err
		}
		pk := pairKey{r.CVEID, famOf[r.Source]}
		s := out[pk]
		s.cwe = append(s.cwe, r.key())
		out[pk] = s
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT cve_id, version, vector, base_score::float8, severity, source, source_org
        FROM vuln_cvss WHERE cve_id = ANY($1) AND source = ANY($2)`, ids, srcs)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var r CVSSRow
		if err := rows.Scan(&r.CVEID, &r.Version, &r.Vector, &r.BaseScore, &r.Severity, &r.Source, &r.SourceOrg); err != nil {
			rows.Close()
			return nil, err
		}
		pk := pairKey{r.CVEID, famOf[r.Source]}
		s := out[pk]
		s.cvss = append(s.cvss, r.key())
		out[pk] = s
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows, err = tx.Query(ctx, `SELECT cve_id, source, source_key, content_hash, rejected, cwe_skipped, cvss_skipped
        FROM vuln_classify_input WHERE cve_id = ANY($1) AND source = ANY($2)`, ids, families)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var cve, fam string
		in := input{d: &Derived{}}
		if err := rows.Scan(&cve, &fam, &in.key, &in.hash, &in.d.Rejected, &in.d.CWESkipped, &in.d.CVSSSkipped); err != nil {
			rows.Close()
			return nil, err
		}
		pk := pairKey{cve, fam}
		s := out[pk]
		s.inputs = append(s.inputs, in.inputKey())
		out[pk] = s
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for k, s := range out {
		sort.Strings(s.cwe)
		sort.Strings(s.cvss)
		sort.Strings(s.inputs)
		out[k] = s
	}
	return out, nil
}
