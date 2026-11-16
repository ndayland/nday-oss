package stats

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// LockID is the advisory lock that serialises the per-day recomputes of
// concurrent rollups ("ndst"; db.MigrationLockID is "nday").
const LockID int64 = 0x6E647374

// DefaultVisitorRetention is how long stats_visitors rows are kept.
const DefaultVisitorRetention = 90

// Options configure Rollup.
type Options struct {
	// Dir is the log directory (NDAY_LOG_DIR). It is only ever read.
	Dir string
	// Days, if set, are recomputed whatever their recorded state; All
	// recomputes the day of every access file. Neither: every file whose
	// (size, mtime) differs from its last successful rollup.
	Days []string
	All  bool
	// DryRun computes everything and rolls every transaction back.
	DryRun bool
	// Now (default time.Now) and Location (default time.Local) give "today"
	// for the visitor-row retention.
	Now      func() time.Time
	Location *time.Location
	// VisitorRetention in days (default 90): stats_visitors rows of days
	// before today minus this many days are deleted (and not written).
	VisitorRetention int
	// OwnHosts are excluded from the referrer list, with their subdomains
	// (default nday.land); the line's own domain is always excluded.
	OwnHosts []string
	// Log receives warnings (default slog.Default()).
	Log *slog.Logger
}

// DayResult describes one day of a rollup.
type DayResult struct {
	Day string
	// Status: "recomputed", "unchanged" (another rollup already did it) or
	// "no-file" (nothing to read: existing rows kept).
	Status string
	Files  []string // files read, own file first
	// Lines, Bad, Partial, MisfiledOut describe the day's own file;
	// MisfiledIn counts lines of this day found in other days' files.
	Lines, Bad, Partial, MisfiledIn, MisfiledOut int64
	Requests, PageViews, Visitors                int64
}

// Result is what Rollup did.
type Result struct {
	Days           []DayResult
	PrunedVisitors int64
	DryRun         bool
}

var fileRe = regexp.MustCompile(`^access-([0-9]{4}-[0-9]{2}-[0-9]{2})\.log$`)

// ParseDay validates a YYYY-MM-DD date.
func ParseDay(s string) (time.Time, error) {
	t, err := time.Parse("2006-01-02", s)
	if err != nil || t.Format("2006-01-02") != s {
		return time.Time{}, fmt.Errorf("invalid day %q (want YYYY-MM-DD)", s)
	}
	return t, nil
}

func fileName(day string) string { return "access-" + day + ".log" }

type fileRow struct {
	size      int64
	mtime     time.Time
	otherDays []string
}

// Rollup recomputes the statistics of the selected days from the access
// files in o.Dir. Each day is one transaction: advisory lock, delete the
// day's rows, insert the new aggregates, record the file's size and mtime.
// conn must not be inside a transaction.
func Rollup(ctx context.Context, conn *pgx.Conn, o Options) (*Result, error) {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Location == nil {
		o.Location = time.Local
	}
	if o.VisitorRetention <= 0 {
		o.VisitorRetention = DefaultVisitorRetention
	}
	if o.OwnHosts == nil {
		o.OwnHosts = []string{"nday.land"}
	}
	if o.Log == nil {
		o.Log = slog.Default()
	}
	st, err := os.Stat(o.Dir)
	if err != nil {
		return nil, fmt.Errorf("log directory: %w", err)
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("log directory: %s is not a directory", o.Dir)
	}
	today := o.Now().In(o.Location).Format("2006-01-02")
	t, _ := ParseDay(today)
	cutoff := t.AddDate(0, 0, -o.VisitorRetention).Format("2006-01-02")

	r := &rollup{conn: conn, o: o, cutoff: cutoff, dryOther: map[string][]string{}}
	pending := map[string]bool{} // day -> forced
	switch {
	case len(o.Days) > 0:
		for _, d := range o.Days {
			if _, err := ParseDay(d); err != nil {
				return nil, err
			}
			pending[d] = true
		}
	default:
		files, err := r.listFiles()
		if err != nil {
			return nil, err
		}
		var known map[string]fileRow
		if !o.All {
			if known, err = r.knownFiles(ctx); err != nil {
				return nil, err
			}
		}
		for day, fi := range files {
			if o.All {
				pending[day] = true
			} else if k, ok := known[fileName(day)]; !ok || !sameFile(fi, k) {
				pending[day] = false // re-checked under the lock
			}
		}
	}
	res := &Result{DryRun: o.DryRun}
	// A day linked by a later recompute (its misfiled lines in another file
	// changed) is recomputed again; at most twice in all per run, which also
	// bounds a dry run (whose rolled-back records never settle).
	runs := map[string]int{}
	for len(pending) > 0 {
		days := make([]string, 0, len(pending))
		for d := range pending {
			days = append(days, d)
		}
		sort.Strings(days)
		day := days[0]
		force := pending[day]
		delete(pending, day)
		runs[day]++
		dr, linked, err := r.day(ctx, day, force)
		if err != nil {
			return res, fmt.Errorf("day %s: %w", day, err)
		}
		res.Days = append(res.Days, dr)
		for _, d := range linked {
			if runs[d] < 2 {
				pending[d] = true
			}
		}
	}
	if res.PrunedVisitors, err = r.prune(ctx); err != nil {
		return res, err
	}
	return res, nil
}

type rollup struct {
	conn     *pgx.Conn
	o        Options
	cutoff   string              // stats_visitors keeps days >= cutoff
	dryOther map[string][]string // dry run: other_days written by this run (rolled back in the DB)
}

func (r *rollup) own(h string) bool {
	for _, o := range r.o.OwnHosts {
		o = strings.ToLower(o)
		if h == o || strings.HasSuffix(h, "."+o) {
			return true
		}
	}
	return false
}

type diskFile struct {
	size  int64
	mtime time.Time
}

func (r *rollup) listFiles() (map[string]diskFile, error) {
	entries, err := os.ReadDir(r.o.Dir)
	if err != nil {
		return nil, fmt.Errorf("log directory: %w", err)
	}
	out := map[string]diskFile{}
	for _, e := range entries {
		m := fileRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		if _, err := ParseDay(m[1]); err != nil {
			continue
		}
		info, err := e.Info()
		if errors.Is(err, fs.ErrNotExist) {
			r.o.Log.Warn("stats: log file vanished, skipped", "file", e.Name())
			continue
		}
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			r.o.Log.Warn("stats: not a regular file, skipped", "file", e.Name())
			continue
		}
		out[m[1]] = diskFile{info.Size(), info.ModTime()}
	}
	return out, nil
}

func sameFile(f diskFile, k fileRow) bool {
	return f.size == k.size && f.mtime.Truncate(time.Microsecond).Equal(k.mtime)
}

func (r *rollup) knownFiles(ctx context.Context) (map[string]fileRow, error) {
	rows, err := r.conn.Query(ctx, "SELECT file, size, mtime FROM stats_files")
	if err != nil {
		return nil, err
	}
	out := map[string]fileRow{}
	for rows.Next() {
		var name string
		var k fileRow
		if err := rows.Scan(&name, &k.size, &k.mtime); err != nil {
			rows.Close()
			return nil, err
		}
		out[name] = k
	}
	return out, rows.Err()
}

func ensureSalt(ctx context.Context, tx pgx.Tx) ([]byte, error) {
	var salt []byte
	err := tx.QueryRow(ctx, "SELECT salt FROM stats_salt").Scan(&salt)
	if err == nil {
		return salt, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	fresh := make([]byte, 32)
	if _, err := rand.Read(fresh); err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, "INSERT INTO stats_salt (salt) VALUES ($1) ON CONFLICT DO NOTHING", fresh); err != nil {
		return nil, err
	}
	err = tx.QueryRow(ctx, "SELECT salt FROM stats_salt").Scan(&salt)
	return salt, err
}

func dayStrings(ts []time.Time) []string {
	out := make([]string, len(ts))
	for i, t := range ts {
		out[i] = t.Format("2006-01-02")
	}
	return out
}

// openRead opens a log file read-only and returns it with its size and
// mtime at open time; reads stop at that size, so a line appended during
// the rollup is left for the next run. ok=false: the file does not exist.
func (r *rollup) openRead(name string) (f *os.File, size int64, mtime time.Time, ok bool, err error) {
	f, err = os.Open(filepath.Join(r.o.Dir, name)) // O_RDONLY
	if errors.Is(err, fs.ErrNotExist) {
		return nil, 0, time.Time{}, false, nil
	}
	if err != nil {
		return nil, 0, time.Time{}, false, err
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, 0, time.Time{}, false, err
	}
	return f, info.Size(), info.ModTime().Truncate(time.Microsecond), true, nil
}

// day recomputes one day in one transaction and returns the days linked to
// it through misfiled lines (to recompute as well).
func (r *rollup) day(ctx context.Context, day string, force bool) (dr DayResult, linked []string, err error) {
	dr.Day = day
	dayTime, _ := ParseDay(day)
	tx, err := r.conn.Begin(ctx)
	if err != nil {
		return dr, nil, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	// Serialise with any concurrent rollup; released at commit/rollback.
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", LockID); err != nil {
		return dr, nil, err
	}
	own := fileName(day)
	var old fileRow
	hadOld := true
	var oldOther []time.Time
	err = tx.QueryRow(ctx, "SELECT size, mtime, other_days FROM stats_files WHERE file = $1", own).
		Scan(&old.size, &old.mtime, &oldOther)
	if errors.Is(err, pgx.ErrNoRows) {
		hadOld, err = false, nil
	}
	if err != nil {
		return dr, nil, err
	}
	old.otherDays = dayStrings(oldOther)
	if !force && hadOld {
		if info, serr := os.Stat(filepath.Join(r.o.Dir, own)); serr == nil &&
			sameFile(diskFile{info.Size(), info.ModTime()}, old) {
			dr.Status = "unchanged"
			return dr, nil, nil
		}
	}
	// Other files holding lines of this day.
	var secondary []string
	rows, err := tx.Query(ctx, "SELECT file FROM stats_files WHERE $1::date = ANY (other_days) AND file <> $2 ORDER BY file", dayTime, own)
	if err != nil {
		return dr, nil, err
	}
	secondary, err = pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return dr, nil, err
	}
	for f, ds := range r.dryOther {
		for _, d := range ds {
			if d == day && f != own && !contains(secondary, f) {
				secondary = append(secondary, f)
			}
		}
	}
	sort.Strings(secondary)

	salt, err := ensureSalt(ctx, tx)
	if err != nil {
		return dr, nil, err
	}
	agg := newDayAgg(day, salt, r.own)
	var scan scanResult
	otherOut := map[string]int64{}
	f, size, mtime, ownOK, err := r.openRead(own)
	if err != nil {
		return dr, nil, err
	}
	if ownOK {
		scan, err = scanLines(io.LimitReader(f, size), func(l Line) {
			if l.Day == day {
				agg.add(&l)
			} else {
				otherOut[l.Day]++
			}
		})
		f.Close()
		if err != nil {
			return dr, nil, fmt.Errorf("%s: %w", own, err)
		}
		dr.Files = append(dr.Files, own)
	} else {
		// The day's own file is gone (deleted after an earlier rollup): if
		// its rows came from that file, other files' misfiled lines alone
		// must not replace them.
		var fromOwn bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM stats_daily
			WHERE day = $1 AND metric = 'rollup' AND dim = 'lines')`, dayTime).Scan(&fromOwn); err != nil {
			return dr, nil, err
		}
		if hadOld || fromOwn || len(secondary) == 0 {
			r.o.Log.Warn("stats: log file missing, day skipped (existing rows kept)", "file", own)
			dr.Status = "no-file"
			return dr, nil, nil
		}
	}
	for _, name := range secondary {
		sf, ssize, _, ok, err := r.openRead(name)
		if err != nil {
			return dr, nil, err
		}
		if !ok {
			r.o.Log.Warn("stats: log file vanished, skipped", "file", name, "day", day)
			continue
		}
		_, err = scanLines(io.LimitReader(sf, ssize), func(l Line) {
			if l.Day == day {
				agg.add(&l)
				dr.MisfiledIn++
			}
		})
		sf.Close()
		if err != nil {
			return dr, nil, fmt.Errorf("%s: %w", name, err)
		}
		dr.Files = append(dr.Files, name)
	}
	if len(dr.Files) == 0 {
		// Nothing to read: keep whatever rows the day has (its log file may
		// have been deleted after an earlier rollup).
		dr.Status = "no-file"
		return dr, nil, nil
	}
	var misOut int64
	newOther := make([]string, 0, len(otherOut))
	for d, n := range otherOut {
		misOut += n
		newOther = append(newOther, d)
	}
	sort.Strings(newOther)
	agg.inc("rollup", "misfiled_out", misOut)
	daily, tops := agg.rows(scan, dr.MisfiledIn)

	for _, t := range []string{"stats_daily", "stats_top", "stats_visitors"} {
		if _, err := tx.Exec(ctx, "DELETE FROM "+t+" WHERE day = $1", dayTime); err != nil {
			return dr, nil, err
		}
	}
	dailyRows := make([][]any, len(daily))
	for i, d := range daily {
		dailyRows[i] = []any{dayTime, d.Metric, d.Dim, d.Value}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"stats_daily"}, []string{"day", "metric", "dim", "value"},
		pgx.CopyFromRows(dailyRows)); err != nil {
		return dr, nil, err
	}
	topRows := make([][]any, len(tops))
	for i, t := range tops {
		topRows[i] = []any{dayTime, t.Kind, t.Key, t.Value}
	}
	if _, err := tx.CopyFrom(ctx, pgx.Identifier{"stats_top"}, []string{"day", "kind", "key", "value"},
		pgx.CopyFromRows(topRows)); err != nil {
		return dr, nil, err
	}
	if day >= r.cutoff {
		if _, err := tx.CopyFrom(ctx, pgx.Identifier{"stats_visitors"}, []string{"day", "visitor", "human"},
			pgx.CopyFromRows(agg.visitorRows(dayTime))); err != nil {
			return dr, nil, err
		}
	}
	if ownOK {
		otherTimes := make([]time.Time, len(newOther))
		for i, d := range newOther {
			otherTimes[i], _ = ParseDay(d)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO stats_files (file, day, size, mtime, lines, bad_lines, other_days, rolled_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, now())
			ON CONFLICT (file) DO UPDATE SET day = EXCLUDED.day, size = EXCLUDED.size, mtime = EXCLUDED.mtime,
			  lines = EXCLUDED.lines, bad_lines = EXCLUDED.bad_lines, other_days = EXCLUDED.other_days,
			  rolled_at = EXCLUDED.rolled_at`,
			own, dayTime, size, mtime, scan.Lines, scan.Bad, otherTimes); err != nil {
			return dr, nil, err
		}
	}
	if r.o.DryRun {
		r.dryOther[own] = newOther
	} else if err := tx.Commit(ctx); err != nil {
		return dr, nil, err
	}
	dr.Status = "recomputed"
	dr.Lines, dr.Bad, dr.Partial, dr.MisfiledOut = scan.Lines, scan.Bad, scan.Partial, misOut
	dr.Requests = agg.daily[metricKey{"req", "all"}]
	dr.PageViews = agg.daily[metricKey{"pv", "all"}]
	dr.Visitors = agg.daily[metricKey{"uv", "all"}]
	// Days whose misfiled lines in this file may have changed. Only a file
	// that changed since its last rollup links days, so linking terminates.
	if !ownOK || hadOld && old.size == size && old.mtime.Equal(mtime) &&
		strings.Join(old.otherDays, ",") == strings.Join(newOther, ",") {
		return dr, nil, nil
	}
	linkedSet := map[string]bool{}
	for _, d := range append(old.otherDays, newOther...) {
		if d != day {
			linkedSet[d] = true
		}
	}
	for d := range linkedSet {
		linked = append(linked, d)
	}
	sort.Strings(linked)
	return dr, linked, nil
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// prune deletes visitor rows older than the retention (a dry run counts them).
func (r *rollup) prune(ctx context.Context) (int64, error) {
	cut, _ := ParseDay(r.cutoff)
	tx, err := r.conn.Begin(ctx)
	if err != nil {
		return 0, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	tag, err := tx.Exec(ctx, "DELETE FROM stats_visitors WHERE day < $1", cut)
	if err != nil {
		return 0, err
	}
	if !r.o.DryRun {
		if err := tx.Commit(ctx); err != nil {
			return 0, err
		}
	}
	return tag.RowsAffected(), nil
}
