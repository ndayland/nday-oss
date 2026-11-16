package admin

import (
	"context"
	"runtime"
	"runtime/debug"
	"sort"
	"time"

	"github.com/jackc/pgx/v5"

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

// System is the system page.
type System struct {
	Collectors []CollectorRow
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
