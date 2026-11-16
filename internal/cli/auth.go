package cli

import (
	"context"
	"fmt"
	"log/slog"
	"nday.land/nday/internal/posts"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/corrections"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/web"
)

// AuthHook, if set, receives the auth service when sign-in is enabled
// (future features use it for RequireUser / RequireActive / RequireRole).
var AuthHook func(*auth.Service)

// AuthHousekeepingEvery is the interval of the in-process auth GC.
var AuthHousekeepingEvery = 15 * time.Minute

// setupAuth mounts sign-in on srv when cfg enables it, and with it the
// discussions (setupDiscuss; they need accounts) and the staff back office
// (setupAdmin). Auth gets its own
// small WRITABLE pool (the site pool stays read-only). The returned stop
// function ends housekeeping and closes the pool.
//
// clientCA reports whether the origin requires Cloudflare's client
// certificate (NDAY_TLS_CLIENT_CA); without it, CF-Connecting-IP (used for
// the sign-in rate limits) is only as trustworthy as the firewall.
func setupAuth(ctx context.Context, srv *web.Server, cfg *auth.Config, dcfg *discussConfig, ad *adminDeps, dbURL string, log *slog.Logger, clientCA bool) (func(), error) {
	if !cfg.Enabled() {
		log.Info("auth: no sign-in provider configured; accounts are disabled")
		return func() {}, nil
	}
	pc, err := pgx.ParseConfig(dbURL)
	if err != nil {
		return nil, err
	}
	pc.RuntimeParams["application_name"] = "nday-auth"
	pc.RuntimeParams["statement_timeout"] = "5000"
	size := 4
	if v := os.Getenv("NDAY_AUTH_DB_POOL_SIZE"); v != "" {
		if size, err = strconv.Atoi(v); err != nil || size < 1 || size > 32 {
			return nil, fmt.Errorf("NDAY_AUTH_DB_POOL_SIZE must be 1..32, got %q", v)
		}
	}
	pool := dbpool.New(pc, dbpool.Options{Size: size})
	// at most half of the pool serves session lookups (/api/me floods), the
	// rest stays free for sign-in writes
	svc, err := auth.New(cfg, auth.Options{Store: &auth.Store{DB: pool}, Logger: log, SessionLookups: max(1, size/2)})
	if err != nil {
		pool.Close()
		return nil, err
	}
	svc.Register(srv)
	if ad != nil && ad.site != nil {
		// researcher posts on vulnerability pages: content for signed-in
		// users only (internal/posts, docs/xposts.md)
		posts.New(posts.Options{Auth: svc, Store: ad.site, Logger: log}).Register(srv)
	}
	// readers' corrections of vulnerability pages (docs/corrections.md):
	// with sign-in, on the sign-in pool (small, rare writes)
	var snap *settings.Snapshot
	if ad != nil {
		snap = ad.snap
	}
	// the discussion's new-account rule applies to submissions too; read at
	// each submission, so /admin/settings changes take effect at once
	newAccount := func() discuss.Limits {
		switch {
		case dcfg != nil && dcfg.svc != nil:
			return dcfg.svc.Limits()
		case dcfg != nil:
			return dcfg.limits
		}
		return discuss.DefaultLimits()
	}
	corr, err := corrections.New(corrections.Options{Store: &corrections.Store{DB: pool}, Auth: svc, Logger: log,
		Limits: ptrTo(correctionsServe(snap, os.LookupEnv, log)), NewAccount: newAccount})
	if err != nil {
		pool.Close()
		return nil, err
	}
	corr.Register(srv)
	if ad != nil {
		ad.corrections = corr
	}
	stopDiscuss, discussPool, err := setupDiscuss(srv, svc, dcfg, dbURL, log)
	if err != nil {
		pool.Close()
		return nil, err
	}
	if err := setupAdmin(srv, svc, pool, discussPool, ad, log); err != nil {
		stopDiscuss()
		pool.Close()
		return nil, err
	}
	if AuthHook != nil {
		AuthHook(svc)
	}
	hctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() { defer close(done); svc.RunHousekeeping(hctx, AuthHousekeepingEvery) }()
	log.Info("auth: sign-in enabled", "providers", svc.Enabled(), "origin", cfg.PublicOrigin)
	if !clientCA {
		log.Warn("auth: NDAY_TLS_CLIENT_CA is not set, so the origin accepts connections that do not come through " +
			"Cloudflare; the CF-Connecting-IP header used for sign-in rate limits is then only as trustworthy as the " +
			"firewall in front of the origin (see docs/auth.md, Authenticated Origin Pulls)")
	}
	return func() { cancel(); <-done; stopDiscuss(); pool.Close() }, nil
}

// runAuthCommand handles auth-gc, auth-role, auth-suspend, auth-unsuspend.
func runAuthCommand(ctx context.Context, env Env, cmd string, rest []string) error {
	prog := "nday " + cmd
	var p *parsed
	var err error
	switch cmd {
	case "auth-gc":
		p, err = parseArgs(prog, nil, rest, 0)
	case "auth-role":
		p, err = parseArgs(prog, []optSpec{{name: "--yes"}}, rest, 2)
		if err == nil && len(p.pos) != 2 {
			err = &usageError{prog, "usage: nday auth-role <user-id|handle> <user|moderator|admin> [--yes]"}
		}
		if err == nil && !auth.ValidRole(p.pos[1]) {
			err = &usageError{prog, fmt.Sprintf("argument role: invalid choice: '%s' (choose from 'user', 'moderator', 'admin')", p.pos[1])}
		}
	case "auth-suspend":
		p, err = parseArgs(prog, []optSpec{{name: "--until", hasValue: true}, {name: "--for", hasValue: true},
			{name: "--reason", hasValue: true}, {name: "--yes"}}, rest, 1)
		if err == nil && len(p.pos) != 1 {
			err = &usageError{prog, "usage: nday auth-suspend <user-id|handle> [--until RFC3339 | --for 7d] [--reason TEXT] [--yes]"}
		}
	case "auth-unsuspend":
		p, err = parseArgs(prog, []optSpec{{name: "--yes"}}, rest, 1)
		if err == nil && len(p.pos) != 1 {
			err = &usageError{prog, "usage: nday auth-unsuspend <user-id|handle> [--yes]"}
		}
	}
	if err != nil {
		return err
	}
	var until *time.Time
	if cmd == "auth-suspend" {
		_, hasUntil := p.flags["--until"]
		_, hasFor := p.flags["--for"]
		switch {
		case hasUntil && hasFor:
			return &usageError{prog, "use either --until or --for"}
		case hasUntil:
			t, err := time.Parse(time.RFC3339, p.flags["--until"])
			if err != nil {
				return &usageError{prog, "argument --until: want RFC 3339, e.g. 2026-12-31T00:00:00Z"}
			}
			until = &t
		case hasFor:
			d, err := ParseSince(p.flags["--for"])
			if err != nil {
				return &usageError{prog, "argument --for: " + err.Error()}
			}
			t := time.Now().Add(d)
			until = &t
		}
		if r := p.flags["--reason"]; len([]rune(r)) > 500 {
			return &usageError{prog, "argument --reason: at most 500 characters"}
		}
	}
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	st := &auth.Store{DB: auth.SingleConn(conn)}
	if cmd == "auth-gc" {
		idle, err := gcSessionIdle(ctx, conn) // database settings first (settings.go)
		if err != nil {
			return err
		}
		r, err := st.GC(ctx, idle)
		if err != nil {
			return err
		}
		fmt.Fprintf(env.Stdout, "auth-gc: sessions=%d flows=%d names=%d unsuspended=%d\n", r.Sessions, r.Flows, r.Names, r.Unsuspended)
		return nil
	}
	u, err := st.FindUser(ctx, p.pos[0])
	if err == auth.ErrNotFound {
		return fmt.Errorf("no user with id or handle %q", p.pos[0])
	}
	if err != nil {
		return err
	}
	// A handle may have changed hands since it
	// was noted down, so show who it resolves to, and act on a handle only
	// with --yes (a user id needs no confirmation).
	handle := "-"
	if u.Handle != nil {
		handle = *u.Handle
	}
	fmt.Fprintf(env.Stdout, "user: id=%s handle=%s created=%s last_seen=%s role=%s status=%s\n", u.ID, handle,
		u.CreatedAt.UTC().Format(time.RFC3339), u.LastSeenAt.UTC().Format(time.RFC3339), u.Role, u.Status)
	if _, yes := p.flags["--yes"]; !yes && !strings.EqualFold(p.pos[0], u.ID) {
		return fmt.Errorf("%q is a handle, which may now belong to someone else: check the user above, then repeat with --yes (or pass the user id)", p.pos[0])
	}
	switch cmd {
	case "auth-role":
		err = st.SetRole(ctx, u.ID, p.pos[1])
		if err == nil {
			fmt.Fprintf(env.Stdout, "auth-role: %s %s -> %s\n", u.ID, u.Role, p.pos[1])
		}
	case "auth-suspend":
		err = st.Suspend(ctx, u.ID, until, p.flags["--reason"])
		if err == nil {
			when := "indefinitely"
			if until != nil {
				when = "until " + until.UTC().Format(time.RFC3339)
			}
			fmt.Fprintf(env.Stdout, "auth-suspend: %s suspended %s\n", u.ID, when)
		}
	case "auth-unsuspend":
		err = st.Unsuspend(ctx, u.ID)
		if err == nil {
			fmt.Fprintf(env.Stdout, "auth-unsuspend: %s active\n", u.ID)
		}
	}
	return err
}
