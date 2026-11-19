package admin

import (
	"context"
	"errors"
	"runtime"
	"runtime/debug"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/jobrun"
	"nday.land/nday/internal/site"
)

// The system page (/admin/system). Nothing here prints environment
// variables, the database URL or any other secret: the build information
// is the module path, version and VCS stamp only.

// TableSize is one table of the system page.
type TableSize struct {
	Name  string
	Rows  int64 // exact for Exact tables, else the planner's estimate (-1 unknown)
	Exact bool
	Bytes int64 // table + indexes + TOAST
}

// tables shown on the system page, and the small ones counted exactly.
var (
	systemTables = []string{"vuln", "vuln_alias", "affected", "event", "raw_record", "collector_state", "vuln_state_mat",
		"users", "identities", "sessions", "passkeys", "namespaces", "comments", "comment_revisions", "comment_reports",
		"stats_files", "stats_daily", "stats_top", "stats_visitors", "admin_audit", "x_accounts", "x_settings"}
	exactTables = []string{"users", "identities", "sessions", "passkeys", "comments", "comment_reports", "admin_audit", "collector_state"}
)

// StatsStatus is the state of the statistics roll-up.
type StatsStatus struct {
	Files      int
	Lines      int64
	BadLines   int64
	LastRollup *time.Time
	LastFile   string
}

// BuildInfo is what the binary says about itself.
type BuildInfo struct {
	GoVersion string
	Path      string
	Version   string
	Revision  string
	Time      string
	Modified  bool
}

// PoolInfo is a pool's size and use.
type PoolInfo struct {
	Name        string
	Size        int
	InUse, Idle int
	Known       bool // InUse/Idle known
}

// CollectorRow is one collector_state row for the system page, public or
// not (the public site.Sources hides the non-public ones on purpose).
type CollectorRow struct {
	Name          string
	Status        *string
	LastRunAt     *time.Time
	LastSuccessAt *time.Time
	LastError     *string
	Public        bool
}

// Collectors lists every collector — the public ones in site.SourceNames
// order, then the non-public ones (site.NonPublicSources, e.g. xposts),
// then any other row of collector_state. Admin-only: it ignores the public
// filter of internal/site deliberately.
func (s *Service) Collectors(ctx context.Context) ([]CollectorRow, error) {
	byName := map[string]CollectorRow{}
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		rows, err := c.Query(ctx, `SELECT source, last_status, last_run_at, last_success_at, last_error FROM collector_state ORDER BY source`)
		if err != nil {
			return err
		}
		_, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (struct{}, error) {
			var x CollectorRow
			if err := r.Scan(&x.Name, &x.Status, &x.LastRunAt, &x.LastSuccessAt, &x.LastError); err != nil {
				return struct{}{}, err
			}
			byName[x.Name] = x
			return struct{}{}, nil
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	var out []CollectorRow
	seen := map[string]bool{}
	add := func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		x, ok := byName[name]
		if !ok {
			x = CollectorRow{Name: name}
		}
		x.Public = site.IsPublicSource(name)
		out = append(out, x)
	}
	for _, n := range site.SourceNames {
		add(n)
	}
	for _, n := range site.NonPublicSources {
		add(n)
	}
	names := make([]string, 0, len(byName))
	for n := range byName {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		add(n)
	}
	return out, nil
}

// JobRow is one background job for the system page (job_run, migration
// 0035), with a backlog count when there is a cheap one.
type JobRow struct {
	Name          string // jobrun.Names
	Recorded      bool   // a job_run row exists
	StartedAt     *time.Time
	FinishedAt    *time.Time
	OK            *bool
	Error         *string
	LastSuccessAt *time.Time
	// Limited: the last run's stored counters say the remote told it to
	// stop (detail.rate_limited true: github-discover and github-fetch)
	Limited     bool
	Status      string // JobStatus
	BacklogKind string // "pending", "due" or "" (none shown)
	Backlog     int64
}

// jobEvery is how often each job is meant to run: the hourly ones ride
// nday-github-discover.timer or nday-collect@xposts.timer, site icons
// nday-site-icons.timer (daily).
var jobEvery = map[string]time.Duration{
	jobrun.GitHubDiscover: time.Hour,
	jobrun.GitHubPoC:      time.Hour,
	jobrun.GitHubFetch:    time.Hour,
	jobrun.PagesFetch:     time.Hour,
	jobrun.SiteIcons:      24 * time.Hour,
}

// runningFor is how long an unfinished run counts as running: the
// units' TimeoutStartSec (20 min) plus slack. Older means it died.
const runningFor = 30 * time.Minute

// JobStatus is the state of a job's last run at now:
//
//	none        no record yet (neutral: fresh deploy, timer not fired)
//	running     started less than runningFor ago, no end yet
//	unfinished  started earlier, no end recorded (killed, crashed)
//	error       the last run ended with an error
//	stale       the last run was ok but is older than 2.5 periods
//	            (two missed runs plus the timers' random delay)
//	limited     the last run was ok but was rate limited (Limited): it
//	            ended cleanly, often after doing nothing
//	ok          otherwise
func JobStatus(j JobRow, now time.Time) string {
	switch {
	case !j.Recorded || j.StartedAt == nil:
		return "none"
	case j.FinishedAt == nil || j.OK == nil:
		if now.Sub(*j.StartedAt) < runningFor {
			return "running"
		}
		return "unfinished"
	case !*j.OK:
		return "error"
	}
	if every, ok := jobEvery[j.Name]; ok && now.Sub(*j.StartedAt) > every*5/2 {
		return "stale"
	}
	if j.Limited {
		return "limited"
	}
	return "ok"
}

// jobBacklog: one count per job where it is cheap — each an index range
// on a table of a few thousand rows (github_repo_state_idx,
// web_page_status_idx, site_icon_next_try_idx). Discovery and the PoC
// repair have no queue. Site icons count only known hosts due again: new
// hosts come from the linked-hosts query, far too heavy for a page view.
var jobBacklog = map[string]struct{ kind, sql string }{
	jobrun.GitHubFetch: {"pending", `SELECT count(*) FROM github_repo WHERE state = 'pending'`},
	jobrun.PagesFetch:  {"pending", `SELECT count(*) FROM web_page WHERE status = 'pending'`},
	jobrun.SiteIcons:   {"due", `SELECT count(*) FROM site_icon WHERE next_try_at <= now()`},
}

// Jobs lists every job of jobrun.Names with its last run and backlog. A
// database without job_run (0035 not applied) shows every job with no
// record; a backlog query that fails just leaves that count out.
func (s *Service) Jobs(ctx context.Context) ([]JobRow, error) {
	byName := map[string]JobRow{}
	err := s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		// rate_limited is read as jsonb true only: a missing, null or
		// malformed detail is not limited (and never fails the page)
		rows, err := c.Query(ctx, `SELECT name, started_at, finished_at, ok, error, last_success_at,
            COALESCE(jsonb_typeof(detail) = 'object' AND detail->'rate_limited' = 'true'::jsonb, false) FROM job_run`)
		if err != nil {
			if isUndefinedTable(err) {
				return nil
			}
			return err
		}
		_, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (struct{}, error) {
			x := JobRow{Recorded: true}
			if err := r.Scan(&x.Name, &x.StartedAt, &x.FinishedAt, &x.OK, &x.Error, &x.LastSuccessAt, &x.Limited); err != nil {
				return struct{}{}, err
			}
			byName[x.Name] = x
			return struct{}{}, nil
		})
		return err
	})
	if err != nil {
		return nil, err
	}
	now := s.now()
	out := make([]JobRow, 0, len(jobrun.Names))
	for _, n := range jobrun.Names {
		x, ok := byName[n]
		if !ok {
			x = JobRow{Name: n}
		}
		for _, t := range []**time.Time{&x.StartedAt, &x.FinishedAt, &x.LastSuccessAt} {
			if *t != nil {
				u := (*t).UTC()
				*t = &u
			}
		}
		x.Status = JobStatus(x, now)
		out = append(out, x)
	}
	err = s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		for i := range out {
			b, ok := jobBacklog[out[i].Name]
			if !ok {
				continue
			}
			var n int64
			if err := c.QueryRow(ctx, b.sql).Scan(&n); err != nil {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				continue
			}
			out[i].BacklogKind, out[i].Backlog = b.kind, n
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// isUndefinedTable: Postgres' undefined_table (a migration not applied).
func isUndefinedTable(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "42P01"
}

// System is the system page.
type System struct {
	Collectors []CollectorRow
	Jobs       []JobRow
	Sources    *site.SourcesReport
	Tables     []TableSize
	DBSize     int64
	Stats      StatsStatus
	Logs       LogTail
	Started    time.Time
	Build      BuildInfo
	Pools      []PoolInfo
	Goroutine  int
}

// System loads the system page.
func (s *Service) System(ctx context.Context) (*System, error) {
	sys := &System{Started: s.o.Started.UTC(), Goroutine: runtime.NumGoroutine()}
	if s.o.Site != nil {
		src, err := s.o.Site.Sources(ctx)
		if err != nil {
			return nil, err
		}
		sys.Sources = src
	}
	cs, err := s.Collectors(ctx)
	if err != nil {
		return nil, err
	}
	sys.Collectors = cs
	if sys.Jobs, err = s.Jobs(ctx); err != nil {
		return nil, err
	}
	exact := map[string]bool{}
	for _, t := range exactTables {
		exact[t] = true
	}
	err = s.o.ReadDB.WithConn(ctx, func(c *pgx.Conn) error {
		if err := c.QueryRow(ctx, `SELECT pg_database_size(current_database())`).Scan(&sys.DBSize); err != nil {
			return err
		}
		rows, err := c.Query(ctx, `SELECT cl.relname, cl.reltuples::bigint, pg_total_relation_size(cl.oid)
			FROM pg_class cl JOIN pg_namespace n ON n.oid = cl.relnamespace
			WHERE n.nspname = current_schema() AND cl.relkind IN ('r', 'm', 'p') AND cl.relname = ANY($1)
			ORDER BY cl.relname`, systemTables)
		if err != nil {
			return err
		}
		sys.Tables, err = pgx.CollectRows(rows, func(r pgx.CollectableRow) (TableSize, error) {
			var t TableSize
			return t, r.Scan(&t.Name, &t.Rows, &t.Bytes)
		})
		if err != nil {
			return err
		}
		for i := range sys.Tables {
			t := &sys.Tables[i]
			if !exact[t.Name] {
				continue
			}
			// the name comes from systemTables via pg_class, never from input
			if err := c.QueryRow(ctx, `SELECT count(*) FROM `+pgx.Identifier{t.Name}.Sanitize()).Scan(&t.Rows); err != nil {
				return err
			}
			t.Exact = true
		}
		return c.QueryRow(ctx, `SELECT count(*)::int, coalesce(sum(lines), 0)::bigint, coalesce(sum(bad_lines), 0)::bigint,
				max(rolled_at), coalesce((SELECT file FROM stats_files ORDER BY rolled_at DESC, file DESC LIMIT 1), '')
			FROM stats_files`).Scan(&sys.Stats.Files, &sys.Stats.Lines, &sys.Stats.BadLines, &sys.Stats.LastRollup, &sys.Stats.LastFile)
	})
	if err != nil {
		return nil, err
	}
	if sys.Stats.LastRollup != nil {
		t := sys.Stats.LastRollup.UTC()
		sys.Stats.LastRollup = &t
	}
	now := s.now().In(s.loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, s.loc)
	sys.Logs = ReadErrorLogs(s.o.LogDir, []time.Time{today, today.AddDate(0, 0, -1)}, MaxRecords)
	sys.Build = buildInfo()
	for _, p := range s.o.Pools {
		pi := PoolInfo{Name: p.Name, Size: p.Size}
		if p.Stats != nil {
			st := p.Stats()
			pi.InUse, pi.Idle, pi.Known = st.InUse, st.Idle, true
		}
		sys.Pools = append(sys.Pools, pi)
	}
	return sys, nil
}

func buildInfo() BuildInfo {
	b := BuildInfo{GoVersion: runtime.Version()}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return b
	}
	b.Path, b.Version = bi.Main.Path, bi.Main.Version
	for _, st := range bi.Settings {
		switch st.Key {
		case "vcs.revision":
			b.Revision = st.Value
		case "vcs.time":
			b.Time = st.Value
		case "vcs.modified":
			b.Modified = st.Value == "true"
		}
	}
	return b
}
