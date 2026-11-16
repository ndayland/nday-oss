package admin

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/stats"
)

// Operations statistics (/admin): the access-log rollup of internal/stats
// (docs/stats.md) plus community numbers read from the database. Days are
// the server's local calendar days, as in the log files. All queries run on
// ReadDB.

// Ranges a dashboard may cover (days, the query parameter "days").
var Ranges = []int{7, 30, 90}

// DayValue is one day of a series. Gap: the statistics of that day were
// never rolled up (no log file, or the roll-up has not run), so 0 means
// "unknown", not "none". Community series never have gaps.
type DayValue struct {
	Day time.Time // midnight UTC carrying the local calendar date
	V   int64
	Gap bool
}

// Cards are the headline numbers of a period.
type Cards struct {
	PageViews, HumanPageViews int64
	// Visitors: unique per day; over a range the sum of the daily counts
	// (visitor-days: the logs cannot dedupe across days, docs/stats.md).
	Visitors, HumanVisitors int64
	APIRequests             int64
	NewAccounts, Comments   int64
	Reports                 int64
}

// Dashboard is everything the statistics page shows.
type Dashboard struct {
	Days        int
	From, To    time.Time // first and last day (To = today)
	HasStats    bool      // the roll-up has run at least once
	LastRollup  *time.Time
	RolledDays  int // days of the range with statistics
	Range       Cards
	Today       Cards
	OpenReports int64

	PageViews, HumanPageViews []DayValue
	Visitors, HumanVisitors   []DayValue
	APIRequests               []DayValue
	Status                    map[string][]DayValue // 2xx, 3xx, 4xx, 5xx (all traffic)
	NewAccounts, Comments     []DayValue
	Reports                   []DayValue

	TopVulns, Referrers, Countries, Searches, NotFound, BotUA []stats.TopEntry
	Locales, Endpoints                                        []stats.TopEntry
	Requests, BotRequests                                     int64 // over the range

	// CountriesHuman: page views by people per country (stats_top kind
	// country_human), up to MapN codes, for the world map.
	CountriesHuman []stats.TopEntry
}

// StatusClasses are the status-class series in display order.
var StatusClasses = []string{"2xx", "3xx", "4xx", "5xx"}

// TopN is the length of the dashboard's top lists.
const TopN = 15

// MapN is how many country codes the world map loads: the reader's cap,
// well above the number of codes, so the map is never cut.
const MapN = 1000

// localDate is t's calendar date in loc, as midnight UTC (the form the
// stats tables use).
func localDate(t time.Time, loc *time.Location) time.Time {
	y, m, d := t.In(loc).Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

// Dashboard loads the statistics of the last days (one of Ranges) ending
// today (local).
func (s *Service) Dashboard(ctx context.Context, days int) (*Dashboard, error) {
	ok := false
	for _, r := range Ranges {
		ok = ok || r == days
	}
	if !ok {
		days = Ranges[0]
	}
	to := localDate(s.now(), s.loc)
	from := to.AddDate(0, 0, -(days - 1))
	d := &Dashboard{Days: days, From: from, To: to, Status: map[string][]DayValue{}}

	info, err := s.stats.Days(ctx)
	if err != nil {
		return nil, err
	}
	have := map[time.Time]bool{}
	for _, di := range info {
		day := time.Date(di.Day.Year(), di.Day.Month(), di.Day.Day(), 0, 0, 0, 0, time.UTC)
		have[day] = true
		if di.RolledAt != nil && (d.LastRollup == nil || di.RolledAt.After(*d.LastRollup)) {
			t := di.RolledAt.UTC()
			d.LastRollup = &t
		}
	}
	d.HasStats = len(info) > 0
	for t := from; !t.After(to); t = t.AddDate(0, 0, 1) {
		if have[t] {
			d.RolledDays++
		}
	}

	// every daily counter of the range in one query
	metrics := []string{"pv", "uv", "api", "req_status", "req"}
	vals := map[string]map[time.Time]int64{} // metric|dim -> day -> value
	err = s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT day, metric, dim, value FROM stats_daily
			WHERE day BETWEEN $1 AND $2 AND metric = ANY($3)`, from, to, metrics)
		if err != nil {
			return err
		}
		var day time.Time
		var metric, dim string
		var v int64
		_, err = pgx.ForEachRow(rows, []any{&day, &metric, &dim, &v}, func() error {
			k := metric + "|" + dim
			if vals[k] == nil {
				vals[k] = map[time.Time]int64{}
			}
			vals[k][time.Date(day.Year(), day.Month(), day.Day(), 0, 0, 0, 0, time.UTC)] = v
			return nil
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	series := func(metric, dim string) []DayValue {
		var out []DayValue
		for t := from; !t.After(to); t = t.AddDate(0, 0, 1) {
			out = append(out, DayValue{Day: t, V: vals[metric+"|"+dim][t], Gap: !have[t]})
		}
		return out
	}
	d.PageViews, d.HumanPageViews = series("pv", "all"), series("pv", "human")
	d.Visitors, d.HumanVisitors = series("uv", "all"), series("uv", "human")
	d.APIRequests = series("api", "all")
	for _, c := range StatusClasses {
		d.Status[c] = series("req_status", "all:"+c)
	}
	for _, p := range series("req", "all") {
		d.Requests += p.V
	}
	for _, p := range series("req", "bot") {
		d.BotRequests += p.V
	}

	// community numbers, bucketed by local day
	if d.NewAccounts, err = s.perDay(ctx, "users", from, to); err != nil {
		return nil, err
	}
	if d.Comments, err = s.perDay(ctx, "comments", from, to); err != nil {
		return nil, err
	}
	if d.Reports, err = s.perDay(ctx, "comment_reports", from, to); err != nil {
		return nil, err
	}
	err = s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, `SELECT count(*) FROM comment_reports WHERE resolved_at IS NULL`).Scan(&d.OpenReports)
	})
	if err != nil {
		return nil, err
	}

	sum := func(v []DayValue) (all, last int64) {
		for _, p := range v {
			all += p.V
		}
		if len(v) > 0 {
			last = v[len(v)-1].V
		}
		return
	}
	d.Range.PageViews, d.Today.PageViews = sum(d.PageViews)
	d.Range.HumanPageViews, d.Today.HumanPageViews = sum(d.HumanPageViews)
	d.Range.Visitors, d.Today.Visitors = sum(d.Visitors)
	d.Range.HumanVisitors, d.Today.HumanVisitors = sum(d.HumanVisitors)
	d.Range.APIRequests, d.Today.APIRequests = sum(d.APIRequests)
	d.Range.NewAccounts, d.Today.NewAccounts = sum(d.NewAccounts)
	d.Range.Comments, d.Today.Comments = sum(d.Comments)
	d.Range.Reports, d.Today.Reports = sum(d.Reports)

	tops := []struct {
		kind string
		dst  *[]stats.TopEntry
	}{{"vuln_page", &d.TopVulns}, {"referrer_host", &d.Referrers}, {"country", &d.Countries},
		{"search", &d.Searches}, {"not_found_human", &d.NotFound}, {"bot_ua", &d.BotUA}}
	for _, t := range tops {
		if *t.dst, err = s.stats.Top(ctx, t.kind, from, to, TopN); err != nil {
			return nil, err
		}
	}
	if d.CountriesHuman, err = s.stats.Top(ctx, stats.TopCountryHuman, from, to, MapN); err != nil {
		return nil, err
	}
	if d.Locales, err = s.dims(ctx, "pv_locale", from, to); err != nil {
		return nil, err
	}
	if d.Endpoints, err = s.dims(ctx, "api_endpoint", from, to); err != nil {
		return nil, err
	}
	return d, nil
}

// dims sums the "all:<value>" dims of a metric over the range.
func (s *Service) dims(ctx context.Context, metric string, from, to time.Time) ([]stats.TopEntry, error) {
	var out []stats.TopEntry
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT substr(dim, 5), sum(value)::bigint FROM stats_daily
			WHERE metric = $1 AND day BETWEEN $2 AND $3 AND dim LIKE 'all:%' GROUP BY dim`, metric, from, to)
		if err != nil {
			return err
		}
		out, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (stats.TopEntry, error) {
			var e stats.TopEntry
			return e, r.Scan(&e.Key, &e.Value)
		})
		return err
	})
	sort.Slice(out, func(i, j int) bool {
		if out[i].Value != out[j].Value {
			return out[i].Value > out[j].Value
		}
		return out[i].Key < out[j].Key
	})
	return out, err
}

// perDay counts rows of table by local day of created_at over [from, to]:
// the bucket bounds are the local midnights, so a day is exact in any zone
// (daylight saving included). table is one of a fixed set.
func (s *Service) perDay(ctx context.Context, table string, from, to time.Time) ([]DayValue, error) {
	switch table {
	case "users", "comments", "comment_reports":
	default:
		panic("admin: perDay: unknown table " + table)
	}
	var starts []time.Time
	for t := from; !t.After(to); t = t.AddDate(0, 0, 1) {
		starts = append(starts, time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, s.loc))
	}
	end := time.Date(to.Year(), to.Month(), to.Day()+1, 0, 0, 0, 0, s.loc)
	counts := make([]int64, len(starts))
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT width_bucket(created_at, $1::timestamptz[]), count(*) FROM `+table+`
			WHERE created_at >= $2 AND created_at < $3 GROUP BY 1`, starts, starts[0], end)
		if err != nil {
			return err
		}
		var b int
		var n int64
		_, err = pgx.ForEachRow(rows, []any{&b, &n}, func() error {
			if b >= 1 && b <= len(counts) {
				counts[b-1] += n
			}
			return nil
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	out := make([]DayValue, len(starts))
	for i, st := range starts {
		out[i] = DayValue{Day: time.Date(st.Year(), st.Month(), st.Day(), 0, 0, 0, 0, time.UTC), V: counts[i]}
	}
	return out, nil
}

// knownLocales maps the pv_locale dims to locale tags (docs/stats.md).
var knownLocales = map[string]string{"en": "en", "zh-hans": "zh-Hans", "zh-hant": "zh-Hant", "ja": "ja", "ko": "ko", "es": "es", "fr": "fr"}

// LocaleTag returns the locale tag of a pv_locale dim ("" when unknown).
func LocaleTag(dim string) string { return knownLocales[strings.ToLower(dim)] }
