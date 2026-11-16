// Package cli implements the nday command line (port of src/nday/cli.py):
//
//	nday [-v] migrate
//	nday [-v] collect <source> [--renormalize]
//	nday [-v] renormalize <source> [--dry-run]      (Go only: offline parity oracle)
//	nday [-v] status
//	nday [-v] hot [--since 24h|7d] [--limit N] [--min-stage S] [--include-rejected]
//	nday [-v] refresh-state                         (Go only: refresh vuln_state_mat now)
//	nday [-v] serve [--listen 127.0.0.1:8080] [--tls-cert F --tls-key F [--tls-client-ca F]]
//	                                                (Go only: website + JSON API; NDAY_LISTEN,
//	                                                NDAY_TLS_CERT, NDAY_TLS_KEY, NDAY_TLS_CLIENT_CA)
//	nday [-v] auth-gc                               (Go only: expired sessions/sign-in markers/held names)
//	nday [-v] auth-role <user-id|handle> <user|moderator|admin>
//	nday [-v] auth-suspend <user-id|handle> [--until RFC3339 | --for 7d] [--reason TEXT]
//	nday [-v] auth-unsuspend <user-id|handle>       (accounts: see docs/auth.md)
//	nday [-v] stats-rollup [--dir DIR] [--day YYYY-MM-DD ...] [--all] [--dry-run]
//	                                                (access logs -> stats_*; docs/stats.md)
//	nday [-v] discuss-hide <comment-id> --reason TEXT
//	nday [-v] discuss-unhide <comment-id>           (discussions: see docs/discuss.md)
//	nday [-v] import-nvd-baseline (--dir DIR | --download) [--year YYYY ...] [--dry-run] [--limit N] [--batch-size N]
//	nday [-v] classify (--all | --source S | --cve ID [ID ...] | --pending) [--dry-run] [--batch-size N]
//	                                                (NVD and the classification layer: docs/nvd.md)
//	nday [-v] tags (--all | --cve ID [ID ...] | --pending) [--dry-run] [--batch-size N]
//	                                                (CVE tags: docs/tags.md)
//	nday [-v] x-drafts [--dry-run]                  (draft posts for the brand X account: docs/xposts.md)
//	nday [-v] x-links-resolve [--limit N]           (expand pending t.co links of X posts: docs/xposts.md)
//	nday [-v] x-links-enqueue                       (queue X post links for their page titles: docs/xposts.md)
//	nday [-v] pages-fetch [--limit N]               (fetch queued third-party pages' titles: docs/webpages.md)
//	nday [-v] x-candidates [--limit N]              (allowlist candidates from X posts: docs/xposts.md)
//	nday [-v] settings                              (database settings; secrets only on the admin pages)
//	nday [-v] settings-set KEY VALUE --yes
//	nday [-v] settings-unset KEY --yes
//
// Output on stdout and exit codes match Python: 0 success, 2 usage error,
// 1 runtime failure (Python: uncaught exception). NDAY_DATABASE_URL is read
// from the environment, seeded from ./.env without overriding real variables.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata" // render timestamps in any session TimeZone, even without system zoneinfo

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/nvd"
	"nday.land/nday/internal/collector/xposts"
	"nday.land/nday/internal/config"
	"nday.land/nday/internal/db"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/pystr"
	"nday.land/nday/internal/registry"
	"nday.land/nday/internal/state"
	"nday.land/nday/internal/web"
)

// Tables are counted by `status` (Python TABLES).
var Tables = []string{"raw_record", "vuln", "vuln_alias", "affected", "event", "collector_state"}

// Env bundles the process environment so tests can run the CLI in-process.
type Env struct {
	Stdout, Stderr io.Writer
	// Factories overrides registry.Collectors.
	Factories map[string]collector.Factory
	// Transport, if set, is handed to collector factories (tests, tools/replay)
	// and to the X user lookup of x-accounts-import (tests).
	Transport http.RoundTripper
	// Now overrides the run clock of collect/renormalize.
	Now func() time.Time
}

const usage = `usage: nday [-h] [-v] {migrate,collect,renormalize,hot,status,refresh-state,serve,auth-gc,auth-role,auth-suspend,auth-unsuspend,discuss-hide,discuss-unhide,x-accounts-import,x-accounts-list,x-accounts-enable,x-accounts-disable,x-settings,x-drafts,x-links-resolve,x-links-enqueue,pages-fetch,x-candidates,settings,settings-set,settings-unset} ...`

// Main runs the CLI and returns the exit code.
func Main(ctx context.Context, args []string, env Env) int {
	if env.Stdout == nil {
		env.Stdout = os.Stdout
	}
	if env.Stderr == nil {
		env.Stderr = os.Stderr
	}
	if env.Factories == nil {
		env.Factories = registry.Collectors
	}
	err := run(ctx, args, env)
	var ue *usageError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &ue):
		fmt.Fprintln(env.Stderr, usage)
		fmt.Fprintln(env.Stderr, ue.Error())
		return 2
	case errors.Is(err, errHelp):
		return 0
	default:
		fmt.Fprintf(env.Stderr, "error: %v\n", err)
		return 1
	}
}

var errHelp = errors.New("help")

func run(ctx context.Context, args []string, env Env) error {
	verbose := false
	for len(args) > 0 && strings.HasPrefix(args[0], "-") {
		switch args[0] {
		case "-v", "--verbose", "--verb", "--verbo", "--verbos", "--ver", "--ve", "--v":
			verbose = true
		case "-h", "--help", "--h", "--he", "--hel":
			fmt.Fprintln(env.Stdout, usage)
			return errHelp
		default:
			return &usageError{"nday", "unrecognized arguments: " + args[0]}
		}
		args = args[1:]
	}
	level := slog.LevelInfo
	if verbose {
		level = slog.LevelDebug
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(env.Stderr, &slog.HandlerOptions{Level: level})))
	if len(args) == 0 {
		return &usageError{"nday", "the following arguments are required: command"}
	}
	cmd, rest := args[0], args[1:]
	prog := "nday " + cmd
	for _, a := range rest {
		if a == "-h" || a == "--help" {
			fmt.Fprintln(env.Stdout, "usage: "+prog+" ...")
			return errHelp
		}
	}
	switch cmd {
	case "migrate":
		if _, err := parseArgs(prog, nil, rest, 0); err != nil {
			return err
		}
		return cmdMigrate(ctx, env)
	case "collect", "renormalize":
		flag := "--renormalize"
		if cmd == "renormalize" {
			flag = "--dry-run"
		}
		p, err := parseArgs(prog, []optSpec{{name: flag}}, rest, 1)
		if err != nil {
			return err
		}
		if len(p.pos) == 0 {
			return &usageError{prog, "the following arguments are required: source"}
		}
		source := p.pos[0]
		factory, ok := env.Factories[source]
		if !ok {
			for _, py := range registry.PythonOnly {
				if py == source {
					return &usageError{prog, fmt.Sprintf("argument source: %q is not ported to Go yet (Python implementation only)", source)}
				}
			}
			names := make([]string, 0, len(env.Factories))
			for n := range env.Factories {
				names = append(names, n)
			}
			return &usageError{prog, fmt.Sprintf("argument source: invalid choice: '%s' (choose from %s)", source, quoteChoices(sortedCopy(names)))}
		}
		_, flagSet := p.flags[flag]
		if cmd == "collect" {
			return cmdCollect(ctx, env, source, factory, flagSet)
		}
		return cmdRenormalize(ctx, env, factory, flagSet)
	case "hot":
		p, err := parseArgs(prog, []optSpec{
			{name: "--since", hasValue: true}, {name: "--limit", hasValue: true},
			{name: "--include-rejected"}, {name: "--min-stage", hasValue: true},
		}, rest, 0)
		if err != nil {
			return err
		}
		since := 24 * time.Hour
		if v, ok := p.flags["--since"]; ok {
			if since, err = ParseSince(v); err != nil {
				return &usageError{prog, "argument --since: " + err.Error()}
			}
		}
		limit := 20
		if v, ok := p.flags["--limit"]; ok {
			if limit, err = strconv.Atoi(pystr.Strip(v)); err != nil {
				return &usageError{prog, fmt.Sprintf("argument --limit: invalid int value: '%s'", v)}
			}
		}
		minStage := model.EventPatchReleased
		if v, ok := p.flags["--min-stage"]; ok {
			if !model.IsEventType(v) {
				return &usageError{prog, fmt.Sprintf("argument --min-stage: invalid choice: '%s' (choose from %s)", v, quoteChoices(model.Stages))}
			}
			minStage = v
		}
		_, inc := p.flags["--include-rejected"]
		return cmdHot(ctx, env, since, limit, inc, minStage)
	case "status":
		if _, err := parseArgs(prog, nil, rest, 0); err != nil {
			return err
		}
		return cmdStatus(ctx, env)
	case "refresh-state":
		if _, err := parseArgs(prog, nil, rest, 0); err != nil {
			return err
		}
		return cmdRefreshState(ctx, env)
	case "import-cve-baseline": // one-off full CVE history import (importcve.go)
		return runImportCVEBaseline(ctx, env, prog, rest)
	case "import-nvd-baseline": // NVD yearly feeds -> raw_record (nvd.go, docs/nvd.md)
		return runImportNVDBaseline(ctx, env, prog, rest)
	case "classify": // raw records -> vuln_cwe / vuln_cvss (nvd.go, docs/nvd.md)
		return runClassify(ctx, env, prog, rest)
	case "tags": // classification + public events -> vuln_tag (tags.go, docs/tags.md)
		return runTags(ctx, env, prog, rest)
	case "x-drafts": // stage events -> x_draft (xdrafts.go, docs/xposts.md)
		return runXDrafts(ctx, env, prog, rest)
	case "x-links-resolve": // pending t.co links -> x_post_link (xlinks.go, docs/xposts.md)
		return runXLinksResolve(ctx, env, prog, rest)
	case "x-links-enqueue": // x_post_link -> web_page queue (xlinks.go, docs/xposts.md)
		return runXLinksEnqueue(ctx, env, prog, rest)
	case "pages-fetch": // web_page queue -> titles (xlinks.go, docs/webpages.md)
		return runPagesFetch(ctx, env, prog, rest)
	case "x-candidates": // x_account_candidate list (xlinks.go, docs/xposts.md)
		return runXCandidates(ctx, env, prog, rest)
	case "stats-rollup": // access logs -> stats_* tables (stats.go, docs/stats.md)
		return runStatsRollup(ctx, env, prog, rest)
	case "auth-gc", "auth-role", "auth-suspend", "auth-unsuspend":
		return runAuthCommand(ctx, env, cmd, rest)
	case "discuss-hide", "discuss-unhide":
		return runDiscussCommand(ctx, env, cmd, rest)
	case "settings", "settings-set", "settings-unset": // database settings (settings.go)
		return runSettingsCommand(ctx, env, cmd, rest)
	case "x-accounts-import", "x-accounts-list", "x-accounts-enable", "x-accounts-disable", "x-settings":
		return runXCommand(ctx, env, cmd, rest) // xposts configuration (xposts.go, docs/xposts.md)
	case "serve":
		p, err := parseArgs(prog, []optSpec{{name: "--listen", hasValue: true}, {name: "--tls-cert", hasValue: true},
			{name: "--tls-key", hasValue: true}, {name: "--tls-client-ca", hasValue: true}}, rest, 0)
		if err != nil {
			return err
		}
		flagOrEnv := func(flag, env string) string {
			if v, ok := p.flags[flag]; ok {
				return v
			}
			return os.Getenv(env)
		}
		listen := flagOrEnv("--listen", "NDAY_LISTEN")
		if listen == "" {
			listen = "127.0.0.1:8080"
		}
		tlsOpts := web.TLSOptions{CertFile: flagOrEnv("--tls-cert", "NDAY_TLS_CERT"),
			KeyFile: flagOrEnv("--tls-key", "NDAY_TLS_KEY"), ClientCAFile: flagOrEnv("--tls-client-ca", "NDAY_TLS_CLIENT_CA")}
		if err := tlsOpts.Validate(); err != nil {
			return &usageError{prog, err.Error()}
		}
		return cmdServe(ctx, env, listen, tlsOpts)
	}
	return &usageError{"nday", fmt.Sprintf("argument command: invalid choice: '%s' (choose from 'migrate', 'collect', 'renormalize', 'hot', 'status', 'refresh-state', 'serve', 'auth-gc', 'auth-role', 'auth-suspend', 'auth-unsuspend', 'discuss-hide', 'discuss-unhide', 'x-accounts-import', 'x-accounts-list', 'x-accounts-enable', 'x-accounts-disable', 'x-settings', 'x-drafts', 'x-links-resolve', 'x-links-enqueue', 'pages-fetch', 'x-candidates', 'settings', 'settings-set', 'settings-unset')", cmd)}
}

func sortedCopy(s []string) []string {
	c := append([]string(nil), s...)
	sort.Strings(c)
	return c
}

func connect(ctx context.Context) (*pgx.Conn, error) {
	url, err := config.DatabaseURL()
	if err != nil {
		return nil, err
	}
	return db.Connect(ctx, url)
}

func cmdMigrate(ctx context.Context, env Env) error {
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	applied, err := db.Migrate(ctx, conn, db.MigrationsFS())
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		fmt.Fprintln(env.Stdout, "applied: (none, up to date)")
	} else {
		fmt.Fprintln(env.Stdout, "applied: "+strings.Join(applied, ", "))
	}
	return nil
}

// StatsJSON renders stats exactly like Python's json.dumps(stats.as_dict(), indent=2).
func StatsJSON(s *pipeline.Stats) string {
	o := pyjson.NewObject()
	o.Set("source", s.Source)
	o.Set("is_backfill", s.IsBackfill)
	for _, kv := range []struct {
		k string
		v int
	}{
		{"fetched", s.Fetched}, {"raw_unchanged", s.RawUnchanged}, {"raw_new", s.RawNew},
		{"normalize_errors", s.NormalizeErrors}, {"vuln_inserted", s.VulnInserted},
		{"vuln_updated", s.VulnUpdated}, {"alias_inserted", s.AliasInserted},
		{"affected_inserted", s.AffectedInserted}, {"event_inserted", s.EventInserted},
		{"event_updated", s.EventUpdated},
	} {
		o.Set(kv.k, kv.v)
	}
	out, _ := pyjson.Encode(o, pyjson.Options{Indent: 2, EnsureASCII: true})
	return out
}

func newCollector(env Env, factory collector.Factory) (collector.Collector, error) {
	// Like Python's cmd_collect, the collector is constructed BEFORE .env is
	// loaded by the connect step (so collector settings come from the real
	// environment only).
	return factory(collector.Deps{Env: os.LookupEnv, Transport: env.Transport})
}

func closeCollector(c collector.Collector) {
	if cl, ok := c.(io.Closer); ok {
		_ = cl.Close()
	}
}

// cmdCollect runs one collector. Its configuration is the database
// settings (internal/settings) layered over the environment as it was
// BEFORE connect loads ./.env (like Python's cmd_collect, collector
// settings never come from .env; docs/go.md). Without usable database
// settings (none stored, table missing, rejected values) it is exactly the
// environment, as before.
func cmdCollect(ctx context.Context, env Env, source string, factory collector.Factory, renormalize bool) error {
	envSnap := environSnapshot()
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	c, err := buildCollector(ctx, conn, env, source, factory, envSnap)
	if err != nil {
		return err
	}
	defer closeCollector(c)
	if nc, ok := c.(*nvd.Collector); ok {
		// NVD streams its feeds (too large for a FetchResult) and yields no
		// events; --renormalize has nothing to redo for it.
		st, err := nc.Run(ctx, conn, nvd.RunOptions{Now: env.Now})
		if err != nil {
			return err
		}
		printJSON(env, st)
	} else {
		st, err := pipeline.RunCollector(ctx, conn, c, pipeline.Options{Renormalize: renormalize, Now: env.Now})
		if err != nil {
			return err
		}
		fmt.Fprintln(env.Stdout, StatsJSON(st))
	}
	postRunClassify(ctx, conn)
	postRunTags(ctx, conn)
	postRunXDrafts(ctx, conn, env)
	if source == xposts.Name {
		postRunXLinks(ctx, conn, env)
	}
	return nil
}

func cmdRenormalize(ctx context.Context, env Env, factory collector.Factory, dryRun bool) error {
	c, err := newCollector(env, factory)
	if err != nil {
		return err
	}
	defer closeCollector(c)
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	st, err := pipeline.Renormalize(ctx, conn, c, pipeline.RenormalizeOptions{DryRun: dryRun, Now: env.Now})
	if err != nil {
		return err
	}
	fmt.Fprintln(env.Stdout, StatsJSON(st))
	if dryRun {
		slog.Info("dry run: transaction rolled back, nothing written")
	}
	return nil
}

var sinceRe = regexp.MustCompile(`^([0-9]+)([hd])$`)

// ParseSince is Python's parse_since: "<n>h" or "<n>d" (surrounding
// whitespace allowed).
func ParseSince(text string) (time.Duration, error) {
	m := sinceRe.FindStringSubmatch(pystr.Strip(text))
	if m == nil {
		return 0, fmt.Errorf("bad duration %s, use e.g. 24h or 7d", pyjson.StrRepr(text))
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	unit := time.Hour
	if m[2] == "d" {
		unit = 24 * time.Hour
	}
	if err != nil || n > int64((1<<63-1)/unit) {
		return 0, fmt.Errorf("duration %s out of range", pyjson.StrRepr(text))
	}
	return time.Duration(n) * unit, nil
}

// sessionLocation is the connection's TimeZone: psycopg returns timestamptz
// values in it, and Python prints them with str() / strftime.
func sessionLocation(ctx context.Context, conn *pgx.Conn) *time.Location {
	var name string
	if err := conn.QueryRow(ctx, "SELECT current_setting('TimeZone')").Scan(&name); err == nil {
		if loc, err := time.LoadLocation(name); err == nil {
			return loc
		}
	}
	return time.UTC
}

// pyDatetime is str(datetime) of an aware datetime: "YYYY-MM-DD HH:MM:SS[.ffffff]+HH:MM".
func pyDatetime(t *time.Time, loc *time.Location) string {
	if t == nil {
		return "None"
	}
	lt := t.In(loc)
	s := lt.Format("2006-01-02 15:04:05")
	if us := lt.Nanosecond() / 1000; us != 0 {
		s += fmt.Sprintf(".%06d", us)
	}
	_, off := lt.Zone()
	sign := '+'
	if off < 0 {
		sign, off = '-', -off
	}
	s += fmt.Sprintf("%c%02d:%02d", sign, off/3600, off/60%60)
	if off%60 != 0 {
		s += fmt.Sprintf(":%02d", off%60)
	}
	return s
}

func pyBool(b bool) string {
	if b {
		return "True"
	}
	return "False"
}

func cmdStatus(ctx context.Context, env Env) error {
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	loc := sessionLocation(ctx, conn)
	w := env.Stdout
	fmt.Fprintln(w, "table counts:")
	for _, t := range Tables {
		var n int64
		if err := conn.QueryRow(ctx, "SELECT count(*) FROM "+t).Scan(&n); err != nil {
			return err
		}
		fmt.Fprintf(w, "  %-16s %d\n", t, n)
	}
	fmt.Fprintln(w, "events by type / is_backfill:")
	rows, err := conn.Query(ctx, "SELECT type, is_backfill, count(*) FROM event GROUP BY 1, 2 ORDER BY 1, 2")
	if err != nil {
		return err
	}
	type tb struct {
		typ string
		bf  bool
		n   int64
	}
	evs, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (tb, error) {
		var x tb
		return x, r.Scan(&x.typ, &x.bf, &x.n)
	})
	if err != nil {
		return err
	}
	for _, e := range evs {
		fmt.Fprintf(w, "  %-20s backfill=%-5s %d\n", e.typ, pyBool(e.bf), e.n)
	}
	fmt.Fprintln(w, "collector_state:")
	rows, err = conn.Query(ctx, `SELECT source, last_status, last_run_at, last_success_at, cursor::text, last_error
               FROM collector_state ORDER BY source`)
	if err != nil {
		return err
	}
	type cs struct {
		source        string
		status        *string
		runAt, okAt   *time.Time
		cursor, error *string
	}
	states, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (cs, error) {
		var x cs
		return x, r.Scan(&x.source, &x.status, &x.runAt, &x.okAt, &x.cursor, &x.error)
	})
	if err != nil {
		return err
	}
	if len(states) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	for _, s := range states {
		status := "None"
		if s.status != nil {
			status = *s.status
		}
		fmt.Fprintf(w, "  %s: status=%s last_run_at=%s last_success_at=%s\n", s.source, status,
			pyDatetime(s.runAt, loc), pyDatetime(s.okAt, loc))
		cursor := "null"
		if s.cursor != nil {
			// psycopg json.loads the jsonb text (keeping its key order), then
			// Python prints json.dumps(cursor, ensure_ascii=False).
			v, err := pyjson.DecodeString(*s.cursor)
			if err != nil {
				return err
			}
			if cursor, err = pyjson.Encode(v, pyjson.Options{}); err != nil {
				return err
			}
		}
		fmt.Fprintf(w, "    cursor=%s\n", cursor)
		if s.error != nil && *s.error != "" {
			fmt.Fprintf(w, "    last_error=%s\n", *s.error)
		}
	}
	fmt.Fprintln(w, "stage counts:")
	counts, err := state.StageCounts(ctx, conn)
	if err != nil {
		return err
	}
	for _, c := range counts {
		fmt.Fprintf(w, "  %-20s %d\n", c.Stage, c.N)
	}
	return nil
}

func cmdHot(ctx context.Context, env Env, since time.Duration, limit int, includeRejected bool, minStage string) error {
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	loc := sessionLocation(ctx, conn)
	rows, err := state.Hot(ctx, conn, since, limit, includeRejected, minStage)
	if err != nil {
		return err
	}
	if len(rows) == 0 {
		fmt.Fprintln(env.Stdout, "(none)")
		return nil
	}
	for _, r := range rows {
		flags := ""
		for _, f := range []struct {
			c  string
			on bool
		}{{"P", r.HasPatch}, {"A", r.HasAnalysis}, {"O", r.HasPoc}, {"X", r.Exploited}, {"K", r.InKev}, {"R", r.IsRejected}} {
			if f.on {
				flags += f.c
			} else {
				flags += "-"
			}
		}
		title := ""
		if r.Title != nil {
			title = strings.ReplaceAll(*r.Title, "\n", " ")
		}
		if rs := []rune(title); len(rs) > 50 {
			title = string(rs[:49]) + "…"
		}
		when := r.LastTransitionAt.In(loc).Format("2006-01-02 15:04")
		fmt.Fprintf(env.Stdout, "%s %s %s %s %s %s\n", padRight(r.CVEID, 16), padRight(r.Stage, 18),
			padRight(r.LastTransitionType, 18), when, flags, title)
	}
	return nil
}

// padRight is Python's f"{s:<n}" (pads by code points).
func padRight(s string, n int) string {
	if k := len([]rune(s)); k < n {
		return s + strings.Repeat(" ", n-k)
	}
	return s
}
