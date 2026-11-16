package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/web"
)

// DiscussHook, if set, receives the discussion service when discussions are
// enabled (the page renderer uses its Stream and Version).
var DiscussHook func(*discuss.Service)

// discussConfig is NDAY_DISCUSS* read and validated before serve starts.
type discussConfig struct {
	enabled bool
	limits  discuss.Limits
	pool    int
	// readDB is the site's read-only pool: public, caller-independent reads
	// (anonymous stream, Stream/StreamPage/Version) use it, so a read flood
	// cannot take the discussion write pool (nil: the write pool).
	readDB auth.ConnSource
	// svc is the running service (set by setupDiscuss; nil when off).
	svc *discuss.Service
}

func discussFromEnv() (*discussConfig, error) {
	on, err := discuss.Enabled(os.Getenv)
	if err != nil {
		return nil, err
	}
	l, err := discuss.LimitsFromEnv(os.Getenv)
	if err != nil {
		return nil, err
	}
	n, err := discuss.PoolSize(os.Getenv)
	if err != nil {
		return nil, err
	}
	return &discussConfig{enabled: on, limits: l, pool: n}, nil
}

// setupDiscuss mounts the discussion endpoints when accounts are enabled
// (svc != nil) and NDAY_DISCUSS is not "off". Discussions get their own
// small WRITABLE pool (NDAY_DISCUSS_DB_POOL_SIZE, default 4): the site pool
// is read-only, and the auth pool is kept for sign-in and session lookups
// (half of it is reserved for those), so a burst of comment traffic cannot
// starve sign-in and vice versa. The returned function closes the pool
// (returned too, for the back office's system page; nil when off).
func setupDiscuss(srv *web.Server, svc *auth.Service, cfg *discussConfig, dbURL string, log *slog.Logger) (func(), *dbpool.Pool, error) {
	if svc == nil || cfg == nil || !cfg.enabled {
		if cfg != nil && !cfg.enabled {
			log.Info("discuss: discussions are disabled (" + discuss.EnvEnabled + "=off)")
		}
		return func() {}, nil, nil
	}
	pc, err := pgx.ParseConfig(dbURL)
	if err != nil {
		return nil, nil, err
	}
	pc.RuntimeParams["application_name"] = "nday-discuss"
	pc.RuntimeParams["statement_timeout"] = "5000"
	pool := dbpool.New(pc, dbpool.Options{Size: cfg.pool})
	ds, err := discuss.New(discuss.Options{Store: &discuss.Store{DB: pool, ReadDB: cfg.readDB}, Auth: svc, Logger: log, Limits: &cfg.limits})
	if err != nil {
		pool.Close()
		return nil, nil, err
	}
	ds.Register(srv)
	cfg.svc = ds
	if DiscussHook != nil {
		DiscussHook(ds)
	}
	terms := svc.Config().TermsVersion
	log.Info("discuss: discussions enabled", "terms_version", terms, "pool", cfg.pool)
	if terms == "" {
		log.Warn("discuss: NDAY_TERMS_VERSION is not set, so anyone with a handle can post without accepting " +
			"community rules (see docs/discuss.md)")
	}
	return pool.Close, pool, nil
}

// runDiscussCommand handles discuss-hide and discuss-unhide: moderation
// without the web. Like auth-role it first prints what the id resolves to.
func runDiscussCommand(ctx context.Context, env Env, cmd string, rest []string) error {
	prog := "nday " + cmd
	var p *parsed
	var err error
	switch cmd {
	case "discuss-hide":
		p, err = parseArgs(prog, []optSpec{{name: "--reason", hasValue: true}}, rest, 1)
		if err == nil && len(p.pos) != 1 {
			err = &usageError{prog, "usage: nday discuss-hide <comment-id> --reason TEXT"}
		}
		if err == nil {
			r := strings.TrimSpace(p.flags["--reason"])
			if n := utf8.RuneCountInString(r); n < 1 || n > discuss.MaxReasonChars {
				err = &usageError{prog, fmt.Sprintf("argument --reason: required, 1 to %d characters", discuss.MaxReasonChars)}
			}
		}
	case "discuss-unhide":
		p, err = parseArgs(prog, nil, rest, 1)
		if err == nil && len(p.pos) != 1 {
			err = &usageError{prog, "usage: nday discuss-unhide <comment-id>"}
		}
	}
	if err == nil && !discuss.ValidID(p.pos[0]) {
		err = &usageError{prog, "argument comment-id: not a comment id (UUID)"}
	}
	if err != nil {
		return err
	}
	id := strings.ToLower(p.pos[0])
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	st := &discuss.Store{DB: auth.SingleConn(conn)}
	c, err := st.Get(ctx, nil, id)
	if errors.Is(err, discuss.ErrNotFound) {
		return fmt.Errorf("no comment with id %s", id)
	}
	if err != nil {
		return err
	}
	author := "-"
	if c.Author != nil && c.Author.Handle != nil {
		author = *c.Author.Handle
	} else if c.AuthorID == nil {
		author = "(deleted account)"
	}
	fmt.Fprintf(env.Stdout, "comment: id=%s cve=%s author=%s created=%s status=%s chars=%d open_reports=%d\n", c.ID, c.CVE, author,
		c.CreatedAt.UTC().Format(time.RFC3339), c.Status, utf8.RuneCountInString(c.Body), c.OpenReports)
	switch cmd {
	case "discuss-hide":
		var n int64
		_, n, err = st.Hide(ctx, id, nil, strings.TrimSpace(p.flags["--reason"]))
		if err == nil {
			fmt.Fprintf(env.Stdout, "discuss-hide: %s hidden (resolved_reports=%d)\n", id, n)
		}
	case "discuss-unhide":
		_, err = st.Unhide(ctx, id, nil)
		if err == nil {
			fmt.Fprintf(env.Stdout, "discuss-unhide: %s visible\n", id)
		}
	}
	if errors.Is(err, discuss.ErrWrongStatus) {
		return fmt.Errorf("comment %s is %s; nothing changed", id, c.Status)
	}
	return err
}
