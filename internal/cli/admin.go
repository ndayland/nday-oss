package cli

import (
	"context"
	"log/slog"
	"os"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/collector/ghsa"
	"nday.land/nday/internal/corrections"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/pystr"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/web"
)

// AdminHook, if set, receives the staff back office when sign-in is enabled
// (the page renderer mounts /admin with it; docs/admin.md).
var AdminHook func(*admin.Service)

// adminDeps are the serve-time pieces the back office reads with: the
// site's read-only pool (every page query) and its query layer.
type adminDeps struct {
	sitePool *dbpool.Pool
	site     *site.Store
	// database settings read at start-up (nil: none or unreadable), the
	// master key, and the discussion configuration (its running service),
	// for the X lookup and the settings runtime (runtime.go)
	snap    *settings.Snapshot
	key     *settings.Key
	discuss *discussConfig
	// corrections is the readers' corrections service (set by setupAuth)
	corrections *corrections.Service
}

func ptrTo[T any](v T) *T { return &v }

// setupAdmin mounts /api/admin/ and hands the back office to AdminHook.
// Pools: page reads on the read-only site pool, user actions on the auth
// pool, moderation actions are the discussion endpoints (discussion pool;
// nil when discussions are off: the moderation module is then read-only).
func setupAdmin(srv *web.Server, svc *auth.Service, authPool, discussPool *dbpool.Pool, d *adminDeps, log *slog.Logger) error {
	if d == nil || d.sitePool == nil {
		return nil
	}
	pools := []admin.Pool{{Name: "site", Size: d.sitePool.Size(), Stats: d.sitePool.Stats},
		{Name: "auth", Size: authPool.Size(), Stats: authPool.Stats}}
	if discussPool != nil {
		pools = append(pools, admin.Pool{Name: "discuss", Size: discussPool.Size(), Stats: discussPool.Stats})
	}
	rt := &serveRuntime{env: os.LookupEnv, key: d.key, load: loadVia(d.sitePool, d.key), auth: svc, site: d.site, log: log}
	if d.discuss != nil {
		rt.discuss = d.discuss.svc
	}
	rt.corrections = d.corrections
	a, err := admin.New(admin.Options{Auth: svc, AuthDB: authPool, ReadDB: d.sitePool, Site: d.site,
		Discussions: discussPool != nil, LogDir: os.Getenv(web.EnvLogDir), Pools: pools, Logger: log,
		XLookup: xLookupServe(d.snap, os.LookupEnv, log), Settings: rt, GitHubLookup: githubLookupServe(d.snap, rt.load)})
	if err != nil {
		return err
	}
	rt.admin = a
	a.Register(srv)
	if AdminHook != nil {
		AdminHook(a)
	}
	log.Info("admin: back office enabled", "discussions", discussPool != nil, "x_lookup", a.XLookupAvailable())
	return nil
}

// githubLookupServe resolves a trusted GitHub account's login when an admin
// adds it (ghrepo.LookupOwner: one request to https://api.github.com),
// with the GitHub token in force (database settings over the environment,
// read at each call; unauthenticated when none).
func githubLookupServe(snap *settings.Snapshot, load func(context.Context) (*settings.Snapshot, error)) func(context.Context, string) (int64, string, error) {
	return func(ctx context.Context, login string) (int64, string, error) {
		cur := snap
		if s, err := load(ctx); err == nil && s != nil {
			cur = s
		}
		tok := ""
		if cur != nil {
			tok, _ = cur.Lookup(os.LookupEnv)(ghsa.TokenEnv)
		}
		return ghrepo.LookupOwner(ctx, ghrepo.NewClient(ghrepo.ClientOptions{Token: pystr.Strip(tok)}), login)
	}
}
