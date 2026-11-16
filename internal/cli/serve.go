package cli

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/config"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/state"
	"nday.land/nday/internal/web"
)

// cmdRefreshState refreshes vuln_state_mat, waiting for a concurrent
// refresh instead of handing the request over to it.
func cmdRefreshState(ctx context.Context, env Env) error {
	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	start := time.Now()
	res, err := state.Refresh(ctx, conn, state.RefreshOptions{Wait: true})
	if err != nil {
		return err
	}
	fmt.Fprintf(env.Stdout, "refresh-state: refreshes=%d covered=%t pending=%t refresh_ms=%d total_ms=%d\n",
		res.Refreshes, res.Covered, res.Pending, res.Elapsed.Milliseconds(), time.Since(start).Milliseconds())
	return nil
}

// ServeHook, if set, receives the server before Handler() is built (tests,
// and the place the HTML routes get registered).
var ServeHook func(*web.Server)

// ServeReady, if set, is called with the bound address (tests).
var ServeReady func(net.Addr)

// cmdServe runs the website API until SIGINT/SIGTERM (or ctx cancellation).
// Pool size: NDAY_DB_POOL_SIZE (default 8). Every connection is read-only
// with an 8 s statement_timeout.
//
// NDAY_PUBLIC_URL (site origin, used in page links; an invalid value is
// ignored with a warning, as before) and NDAY_API_URL (optional API host
// origin; an invalid value is an error) are read here, once, and handed to
// internal/web through web.Config (internal/webui takes them from the server).
// NDAY_API_URL equal to the site origin is ignored with a warning: the site
// would otherwise be served by the API mux.
//
// NDAY_LOG_DIR (optional, absolute, must exist): access lines go to
// access-YYYY-MM-DD.log there instead of stderr, and WARN+ records also to
// error-YYYY-MM-DD.log (local dates; see web.LogFiles). Unset: stderr only.
//
// With tlsOpts set it serves HTTPS directly (TLS 1.2+); with a client CA it
// requires verified client certificates. The TLS files are loaded before
// anything else so a bad file fails fast.
func cmdServe(ctx context.Context, env Env, listen string, tlsOpts web.TLSOptions) error {
	tlsCfg, err := tlsOpts.Config()
	if err != nil {
		return err
	}
	logs, err := openLogFiles()
	if err != nil {
		return err
	}
	if logs != nil {
		defer logs.Close()
		// One wrap for the whole process: stderr exactly as before, plus
		// WARN+ (incl. panics and the 5xx records) in the error file.
		prev := slog.Default()
		slog.SetDefault(slog.New(web.TeeHandler(prev.Handler(), logs.ErrorHandler())))
		defer slog.SetDefault(prev)
	}
	url, err := config.DatabaseURL()
	if err != nil {
		return err
	}
	log := slog.Default()
	// Sign-in and the discussion limits are validated before anything
	// starts. When the environment alone is invalid, the database settings
	// may complete it (e.g. a client secret moved into the database): they
	// are read now, and the environment's error stands unless the layered
	// configuration is valid (runtime.go).
	skey := settingsKey()
	authCfg, authErr := auth.FromEnv(nil)
	discussCfg, discussErr := discussFromEnv()
	var snap *settings.Snapshot
	layered := false
	if authErr != nil || discussErr != nil {
		if dbCfg, err := pgx.ParseConfig(url); err == nil { // (else: the pool below reports it)
			pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
			snap = startupSnapshot(pctx, dbCfg, skey, log)
			cancel()
		}
		if authCfg, err = layerAuth(snap, os.LookupEnv, authCfg, authErr, log); err != nil {
			return err
		}
		if discussCfg, err = layerDiscuss(snap, os.LookupEnv, discussCfg, discussErr, log); err != nil {
			return err
		}
		layered = true
	}
	if logs != nil {
		log.Info("log files", "dir", os.Getenv(web.EnvLogDir), "access", logs.Access.Name(), "error", logs.Error.Name())
	}
	publicURL, apiURL, err := originsFromEnv(log)
	if err != nil {
		return err
	}
	cfg, err := pgx.ParseConfig(url)
	if err != nil {
		return err
	}
	cfg.RuntimeParams["application_name"] = "nday-serve"
	cfg.RuntimeParams["statement_timeout"] = "8000"
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	size := 8
	if v := os.Getenv("NDAY_DB_POOL_SIZE"); v != "" {
		if size, err = strconv.Atoi(v); err != nil || size < 1 || size > 64 {
			return fmt.Errorf("NDAY_DB_POOL_SIZE must be 1..64, got %q", v)
		}
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: size})
	defer pool.Close()
	discussCfg.readDB = pool // public discussion reads use the read-only site pool
	store := site.New(pool)
	pctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	if h, err := store.Health(pctx); err != nil {
		log.Warn("database not reachable at startup; serving anyway (healthz reports it)", "err", err)
	} else {
		log.Info("database ok", "data_updated_at", h.DataUpdatedAt, "state_refreshed_at", h.StateRefreshedAt)
	}
	cancel()
	// Database settings (runtime.go): layered over the environment that was
	// validated above; values the validators refuse fall back to it. (Done
	// already when the environment alone was refused.)
	if !layered {
		pctx, cancel = context.WithTimeout(ctx, 5*time.Second)
		snap = serveSnapshot(pctx, pool, skey, log)
		cancel()
		if authCfg, err = layerAuth(snap, os.LookupEnv, authCfg, nil, log); err != nil {
			return err
		}
		if discussCfg, err = layerDiscuss(snap, os.LookupEnv, discussCfg, nil, log); err != nil {
			return err
		}
	}
	store.SetPinConfig(pinsServe(snap, os.LookupEnv, log))
	srv := web.New(web.Config{Store: store, Logger: log, PublicURL: publicURL, APIURL: apiURL, Logs: logs})
	ad := &adminDeps{sitePool: pool, site: store, snap: snap, key: skey, discuss: discussCfg}
	stopAuth, err := setupAuth(ctx, srv, authCfg, discussCfg, ad, url, log, tlsOpts.ClientCAFile != "")
	if err != nil {
		return err
	}
	defer stopAuth()
	if ServeHook != nil {
		ServeHook(srv)
	}
	sctx, stop := signal.NotifyContext(ctx, syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return web.ServeTLS(sctx, listen, srv.Handler(), log, ServeReady, tlsCfg)
}

// originsFromEnv reads NDAY_PUBLIC_URL and NDAY_API_URL (web.ParseOrigin
// rules for both) and logs the resulting API location.
func originsFromEnv(log *slog.Logger) (publicURL, apiURL string, err error) {
	publicURL, perr := web.ParseOrigin(os.Getenv(web.EnvPublicURL))
	if perr != nil {
		log.Warn("ignoring "+web.EnvPublicURL, "err", perr)
		publicURL = ""
	}
	apiURL, err = web.ParseOrigin(os.Getenv(web.EnvAPIURL))
	if err != nil {
		return "", "", fmt.Errorf("%s: %w", web.EnvAPIURL, err)
	}
	switch {
	case apiURL == "":
		log.Info("api: single-host mode", "api_base", originOr(publicURL)+"/api/")
	case publicURL != "" && web.SameOrigin(apiURL, publicURL):
		log.Warn(web.EnvAPIURL+" equals "+web.EnvPublicURL+"; ignoring it (single-host mode)", "api_url", apiURL)
		apiURL = ""
	default:
		if publicURL == "" {
			log.Warn(web.EnvAPIURL+" is set but "+web.EnvPublicURL+" is not: pages and the API index link to "+web.DefaultPublicURL,
				"api_url", apiURL)
		}
		log.Info("api: separate host", "api_origin", apiURL, "api_base", apiURL+"/v1/", "public_url", originOr(publicURL))
	}
	return publicURL, apiURL, nil
}

func originOr(o string) string {
	if o == "" {
		return web.DefaultPublicURL
	}
	return o
}

// openLogFiles opens the NDAY_LOG_DIR files (nil, nil when unset). Problems
// of the sink itself are reported on the current (stderr) logger.
func openLogFiles() (*web.LogFiles, error) {
	dir := os.Getenv(web.EnvLogDir)
	if dir == "" {
		return nil, nil
	}
	return web.OpenLogFiles(web.LogOptions{Dir: dir, Stderr: slog.Default()})
}
