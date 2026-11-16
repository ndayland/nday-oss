package stats

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// ConnSource hands out a connection for the duration of fn (*dbpool.Pool
// implements it; SingleConn adapts one connection). Same contract as
// site.ConnSource.
type ConnSource interface {
	WithConn(ctx context.Context, fn func(*pgx.Conn) error) error
}

// SingleConn adapts one connection (serialised by a mutex) to ConnSource.
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

// Reader runs the read-only queries of the admin UI. Every method uses one
// connection for one statement, so it is safe for concurrent use when its
// ConnSource is. Days are dates (time.Time at UTC midnight; only the
// year/month/day of from/to are used); ranges are inclusive.
type Reader struct{ db ConnSource }

// NewReader returns a Reader over db.
func NewReader(db ConnSource) *Reader { return &Reader{db: db} }

// MaxRangeDays bounds a Series/Top range.
const MaxRangeDays = 3660

// ErrRange: to before from, or a range longer than MaxRangeDays.
var ErrRange = errors.New("stats: invalid day range")

// Point is one day of a series.
type Point struct {
	Day   time.Time
	Value int64
}

// TopEntry is one key of a top list.
type TopEntry struct {
	Key   string
	Value int64
}

// DayInfo describes a day that has statistics.
type DayInfo struct {
	Day      time.Time
	Files    int        // log files recorded for the day's own date (0 or 1)
	Lines    int64      // lines of the day's own file
	BadLines int64      // malformed lines of the day's own file
	RolledAt *time.Time // last successful rollup of the day's own file (nil: none recorded)
}

// Overview is the headline numbers of one day plus every counter.
type Overview struct {
	Day                       time.Time
	Requests, HumanRequests   int64
	PageViews, HumanPageViews int64
	Visitors, HumanVisitors   int64
	APIRequests, APIClients   int64
	BytesSent                 int64
	PageP50, PageP95          int64 // ms, all traffic
	APIP50, APIP95            int64
	// Metrics is every stats_daily row of the day: metric -> dim -> value.
	Metrics map[string]map[string]int64
}

func dateOnly(t time.Time) time.Time {
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func checkRange(from, to time.Time) (time.Time, time.Time, error) {
	from, to = dateOnly(from), dateOnly(to)
	if to.Before(from) || to.Sub(from) > MaxRangeDays*24*time.Hour {
		return from, to, ErrRange
	}
	return from, to, nil
}

// Series returns metric/dim for every day of [from, to], days without a
// row (no traffic, or not rolled up) being 0.
func (r *Reader) Series(ctx context.Context, metric, dim string, from, to time.Time) ([]Point, error) {
	from, to, err := checkRange(from, to)
	if err != nil {
		return nil, err
	}
	var out []Point
	err = r.db.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT d::date, COALESCE(s.value, 0)
			FROM generate_series($1::date, $2::date, interval '1 day') AS d
			LEFT JOIN stats_daily s ON s.day = d::date AND s.metric = $3 AND s.dim = $4
			ORDER BY 1`, from, to, metric, dim)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (Point, error) {
			var p Point
			err := row.Scan(&p.Day, &p.Value)
			return p, err
		})
		return err
	})
	return out, err
}

// Top sums a top list over [from, to] and returns the n largest keys
// (ties by key). Each day stores only its own top 100, so for a range the
// result is exact only for keys that were in every day's top 100.
func (r *Reader) Top(ctx context.Context, kind string, from, to time.Time, n int) ([]TopEntry, error) {
	from, to, err := checkRange(from, to)
	if err != nil {
		return nil, err
	}
	if n <= 0 || n > 1000 {
		n = TopN
	}
	var out []TopEntry
	err = r.db.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT key, sum(value)::bigint AS v FROM stats_top
			WHERE kind = $1 AND day BETWEEN $2 AND $3
			GROUP BY key ORDER BY v DESC, key LIMIT $4`, kind, from, to, n)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (TopEntry, error) {
			var e TopEntry
			err := row.Scan(&e.Key, &e.Value)
			return e, err
		})
		return err
	})
	return out, err
}

// Days lists the days that have statistics, oldest first.
func (r *Reader) Days(ctx context.Context) ([]DayInfo, error) {
	var out []DayInfo
	err := r.db.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT d.day, count(f.file)::int, COALESCE(sum(f.lines), 0)::bigint,
			  COALESCE(sum(f.bad_lines), 0)::bigint, max(f.rolled_at)
			FROM (SELECT DISTINCT day FROM stats_daily) d
			LEFT JOIN stats_files f ON f.day = d.day
			GROUP BY d.day ORDER BY d.day`)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(row pgx.CollectableRow) (DayInfo, error) {
			var d DayInfo
			err := row.Scan(&d.Day, &d.Files, &d.Lines, &d.BadLines, &d.RolledAt)
			return d, err
		})
		return err
	})
	return out, err
}

// Overview returns one day's counters (all zero for a day without data).
func (r *Reader) Overview(ctx context.Context, day time.Time) (*Overview, error) {
	o := &Overview{Day: dateOnly(day), Metrics: map[string]map[string]int64{}}
	err := r.db.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT metric, dim, value FROM stats_daily WHERE day = $1`, o.Day)
		if err != nil {
			return err
		}
		var metric, dim string
		var v int64
		_, err = pgx.ForEachRow(rows, []any{&metric, &dim, &v}, func() error {
			m := o.Metrics[metric]
			if m == nil {
				m = map[string]int64{}
				o.Metrics[metric] = m
			}
			m[dim] = v
			return nil
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	g := func(metric, dim string) int64 { return o.Metrics[metric][dim] }
	o.Requests, o.HumanRequests = g("req", "all"), g("req", "human")
	o.PageViews, o.HumanPageViews = g("pv", "all"), g("pv", "human")
	o.Visitors, o.HumanVisitors = g("uv", "all"), g("uv", "human")
	o.APIRequests, o.APIClients = g("api", "all"), g("api_clients", "all")
	o.BytesSent = g("bytes", "all")
	o.PageP50, o.PageP95 = g("rt_page_ms", "all:p50"), g("rt_page_ms", "all:p95")
	o.APIP50, o.APIP95 = g("rt_api_ms", "all:p50"), g("rt_api_ms", "all:p95")
	return o, nil
}
