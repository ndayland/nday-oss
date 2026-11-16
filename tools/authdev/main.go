// Command authdev runs the nday website with sign-in on http://localhost so
// the sign-in and account pages can be tried by hand. It is a development
// tool only: it is never linked into cmd/nday, binds loopback only and
// refuses anything else (see README.md in this directory).
//
// One process serves the real site (internal/web + internal/webui) and the
// real sign-in service (internal/auth) on -listen, with the fake identity
// provider of internal/auth/fakeidp on other loopback ports standing in for
// Google, Apple, GitHub and X. The fake approves every sign-in as the
// current test persona (-persona; switch at http://127.0.0.1:<idp>/ or with
// ?as=<persona> on its authorize page). Passkeys are on (RP ID localhost),
// the auth secret is random per start, and the sensitive-action window can
// be shortened with -sensitive-window to try re-verification. Discussions
// (internal/discuss) are mounted too, with terms version "dev-1" by default;
// -moderator makes the named personas moderators, -admin administrators.
// The staff back office (internal/admin, /admin) is mounted as well;
// -stats-sample DIR writes a few days of sample access logs and an error
// log into DIR and rolls them up into the local database, so the
// statistics and system pages have something to show; -x-sample inserts
// sample data for the X posts collector page (/admin/x). The X user lookup
// of that page (adding an account by handle) answers from the in-process
// fake of internal/xlookup/xfake (-x-lookup fake, the default; -x-lookup
// off shows the page without a token): no token, no network.
//
//	NDAY_DATABASE_URL=postgresql://nday:nday@127.0.0.1:54329/nday go run ./tools/authdev
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"html"
	"log/slog"
	"nday.land/nday/internal/posts"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/auth/fakeidp"
	"nday.land/nday/internal/corrections"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui"
	"nday.land/nday/internal/xlookup"
	"nday.land/nday/internal/xlookup/xfake"
)

// personas are the test users the fake provider signs in as. "deny"
// plays a user who cancels at the provider.
var personas = map[string]string{"ada": "Ada Lovelace", "bob": "Bob Example", "mallory": "Mallory", "deny": ""}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "authdev:", err)
		os.Exit(1)
	}
}

func run() error {
	listen := flag.String("listen", "127.0.0.1:8090", "loopback address of the site")
	idpListen := flag.String("idp-listen", "127.0.0.1:8091", "loopback address of the fake providers' authorize pages")
	publicURL := flag.String("public-url", "", "public origin (default http://localhost:<port of -listen>); must be http and loopback")
	persona := flag.String("persona", "ada", "test persona the fake providers sign in as: ada, bob, mallory or deny")
	providers := flag.String("providers", "google,apple,github,x", "providers to enable (comma-separated; empty = passkeys only)")
	passkeys := flag.Bool("passkeys", true, "enable passkeys")
	signup := flag.Bool("signup", true, "enable passkey-only sign-up")
	window := flag.Duration("sensitive-window", 15*time.Minute, "recent sign-in window for sensitive actions (NDAY_AUTH_SENSITIVE_WINDOW); e.g. 30s to try re-verification")
	terms := flag.String("terms", "dev-1", "terms version to publish (NDAY_TERMS_VERSION; empty = none); posting a comment needs it accepted")
	moderators := flag.String("moderator", "", "comma-separated personas made moderators as soon as they have an account (e.g. ada)")
	admins := flag.String("admin", "", "comma-separated personas made administrators as soon as they have an account (e.g. ada)")
	xsample := flag.Bool("x-sample", false, "insert sample X collector data (accounts, settings, cursor, posts) into the local database for /admin/x; never calls the X API")
	xlookupMode := flag.String("x-lookup", "fake", "X user lookup on /admin/x: fake (in-process fake API with the trial handles of README.md; never the network) or off (as without a token)")
	sample := flag.String("stats-sample", "", "absolute scratch directory: write sample access/error logs there, roll them up into the local database, and show them in /admin")
	flag.Parse()

	if _, ok := personas[*persona]; !ok {
		return fmt.Errorf("-persona: unknown persona %q", *persona)
	}
	var modPersonas []string
	for _, m := range strings.Split(*moderators, ",") {
		if m = strings.TrimSpace(m); m == "" {
			continue
		}
		if _, ok := personas[m]; !ok || m == "deny" {
			return fmt.Errorf("-moderator: unknown persona %q", m)
		}
		modPersonas = append(modPersonas, m)
	}
	var adminPersonas []string
	for _, m := range strings.Split(*admins, ",") {
		if m = strings.TrimSpace(m); m == "" {
			continue
		}
		if _, ok := personas[m]; !ok || m == "deny" {
			return fmt.Errorf("-admin: unknown persona %q", m)
		}
		adminPersonas = append(adminPersonas, m)
	}
	if *xlookupMode != "fake" && *xlookupMode != "off" {
		return fmt.Errorf("-x-lookup: want fake or off, got %q", *xlookupMode)
	}
	if *window < 10*time.Second {
		return errors.New("-sensitive-window: at least 10s")
	}
	if err := loopbackAddr(*listen); err != nil {
		return fmt.Errorf("-listen: %w", err)
	}
	if err := loopbackAddr(*idpListen); err != nil {
		return fmt.Errorf("-idp-listen: %w", err)
	}
	_, port, _ := net.SplitHostPort(*listen)
	if *publicURL == "" {
		*publicURL = "http://localhost:" + port
	}
	origin, err := devOrigin(*publicURL)
	if err != nil {
		return fmt.Errorf("-public-url: %w", err)
	}
	dbURL := os.Getenv("NDAY_DATABASE_URL")
	if dbURL == "" {
		return errors.New("NDAY_DATABASE_URL is not set (local database, e.g. postgresql://nday:nday@127.0.0.1:54329/nday)")
	}
	pc, err := pgx.ParseConfig(dbURL)
	if err != nil {
		return fmt.Errorf("NDAY_DATABASE_URL: %w", err)
	}
	if !loopbackHost(pc.Host) && !strings.HasPrefix(pc.Host, "/") {
		return errors.New("NDAY_DATABASE_URL must point to a local database (loopback host or unix socket)")
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// databases: the site's read-only pool and auth's writable pool
	sitePC := pc.Copy()
	sitePC.RuntimeParams["application_name"] = "nday-authdev-site"
	sitePC.RuntimeParams["default_transaction_read_only"] = "on"
	sitePool := dbpool.New(sitePC, dbpool.Options{Size: 4})
	defer sitePool.Close()
	authPC := pc.Copy()
	authPC.RuntimeParams["application_name"] = "nday-authdev-auth"
	authPool := dbpool.New(authPC, dbpool.Options{Size: 4})
	defer authPool.Close()
	discussPC := pc.Copy()
	discussPC.RuntimeParams["application_name"] = "nday-authdev-discuss"
	discussPool := dbpool.New(discussPC, dbpool.Options{Size: 4})
	defer discussPool.Close()
	if err := checkSchema(ctx, authPool); err != nil {
		return err
	}
	if *xsample {
		if err := xSample(ctx, dbURL, log); err != nil {
			return fmt.Errorf("-x-sample: %w", err)
		}
	}
	logDir := os.Getenv("NDAY_LOG_DIR")
	if *sample != "" {
		if err := sampleStats(ctx, dbURL, *sample, log); err != nil {
			return err
		}
		logDir = *sample
	}

	// fake providers
	idp := fakeidp.New()
	defer idp.Server.Close()
	appleKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	secret := make([]byte, 48) // (also NDAY_AUTH_SECRET of the settings runtime: openssl rand -base64 48)
	if _, err := rand.Read(secret); err != nil {
		return err
	}
	cfg := &auth.Config{PublicOrigin: origin, Secrets: [][]byte{secret}, Providers: map[string]auth.ProviderCredentials{},
		TermsVersion: *terms, SessionIdle: auth.DefaultSessionIdle, SessionMax: auth.DefaultSessionMax,
		HandleHold: auth.DefaultHandleHold, Passkeys: *passkeys, PasskeySignup: *passkeys && *signup,
		RPID: "localhost", Origins: []string{origin}, SensitiveWindow: *window}
	idpLn, err := net.Listen("tcp", *idpListen)
	if err != nil {
		return err
	}
	idpBase := "http://" + idpLn.Addr().String()
	eps := idp.Endpoints()
	var enabled []string
	for _, p := range strings.Split(*providers, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		ep, ok := eps[p]
		if !ok {
			return fmt.Errorf("-providers: unknown provider %q", p)
		}
		ep.AuthURL = idpBase + "/" + p + "/authorize" // the fake has no browser-facing page; ours approves
		eps[p] = ep
		creds := auth.ProviderCredentials{ClientID: "dev-" + p, ClientSecret: "dev-secret-" + p}
		fc := fakeidp.Client{ID: creds.ClientID, Secret: creds.ClientSecret, RedirectURI: cfg.RedirectURI(p)}
		if p == auth.Apple {
			creds = auth.ProviderCredentials{ClientID: "land.nday.dev", TeamID: "DEVTEAM123", KeyID: "DEVKEY1234", AppleKey: appleKey}
			fc = fakeidp.Client{ID: creds.ClientID, RedirectURI: cfg.RedirectURI(p), ApplePub: &appleKey.PublicKey,
				AppleTeamID: creds.TeamID, AppleKeyID: creds.KeyID}
		}
		cfg.Providers[p] = creds
		idp.Register(p, fc)
		enabled = append(enabled, p)
	}
	if !cfg.Enabled() {
		return errors.New("nothing to sign in with: enable a provider or passkeys")
	}
	svc, err := auth.New(cfg, auth.Options{Store: &auth.Store{DB: authPool}, Logger: log, Client: idp.Server.Client(),
		Endpoints: eps, SessionLookups: 2})
	if err != nil {
		return err
	}

	srv := web.New(web.Config{Store: site.New(sitePool), Logger: log, PublicURL: origin})
	svc.Register(srv)
	ds, err := discuss.New(discuss.Options{Store: &discuss.Store{DB: discussPool, ReadDB: sitePool}, Auth: svc, Logger: log})
	if err != nil {
		return err
	}
	ds.Register(srv)
	posts.New(posts.Options{Auth: svc, Store: site.New(sitePool), Logger: log}).Register(srv)
	corr, err := corrections.New(corrections.Options{Store: &corrections.Store{DB: authPool}, Auth: svc, Logger: log,
		NewAccount: ds.Limits})
	if err != nil {
		return err
	}
	corr.Register(srv) // readers' corrections (docs/corrections.md)
	if len(modPersonas) > 0 {
		go promote(ctx, authPool, modPersonas, auth.RoleModerator, log)
	}
	if len(adminPersonas) > 0 {
		go promote(ctx, authPool, adminPersonas, auth.RoleAdmin, log)
	}
	// database settings (/admin/settings): settings.go
	rt, err := devSettings(ctx, authPool, cfg, secret, appleKey, *window, svc, ds, log)
	if err != nil {
		return fmt.Errorf("settings: %w", err)
	}
	var xlk *xlookup.Client
	if *xlookupMode == "fake" {
		// the fake answers in-process (its Transport): the requests never
		// leave this process, whatever the URL says
		fake := xfake.Trial()
		if xlk, err = xlookup.New(xlookup.Options{Token: xfake.TrialToken, BaseURL: "http://x-api.fake.invalid",
			Transport: fake.Transport(), Logger: log}); err != nil {
			return err
		}
	}
	adm, err := admin.New(admin.Options{Auth: svc, AuthDB: authPool, ReadDB: sitePool, Site: site.New(sitePool), Discussions: true,
		XLookup: xlk, Settings: rt, LogDir: logDir, Logger: log, Pools: []admin.Pool{{Name: "site", Size: sitePool.Size(), Stats: sitePool.Stats},
			{Name: "auth", Size: authPool.Size(), Stats: authPool.Stats}, {Name: "discuss", Size: discussPool.Size(), Stats: discussPool.Stats}}})
	if err != nil {
		return err
	}
	adm.Register(srv)
	if _, err := webui.New(srv, webui.Options{BaseURL: origin, Accounts: webui.AccountsOf(svc), Discussions: ds, Admin: adm}); err != nil {
		return err
	}
	go svc.RunHousekeeping(ctx, 15*time.Minute)

	fp := &fakePages{idp: idp, persona: *persona, providers: enabled, site: origin}
	idpSrv := &http.Server{Handler: fp, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = idpSrv.Serve(idpLn) }()
	defer idpSrv.Close()

	fmt.Fprintf(os.Stderr, "\nauthdev (development only; random auth secret, fake providers)\n"+
		"  site:      %s/   sign in: %s/login   account: %s/account\n"+
		"  personas:  %s/  (now: %s; also ?as=<persona> on the authorize page)\n"+
		"  providers: %s; passkeys %v (sign-up %v); sensitive window %s; terms %q\n"+
		"  discussions: %s/api/discuss/CVE-…  moderators: %s\n"+
		"  back office: %s/admin  administrators: %s  logs: %s\n"+
		"  X user lookup on /admin/x: %s\n\n",
		origin, origin, origin, idpBase, *persona, strings.Join(enabled, ", "), cfg.Passkeys, cfg.PasskeySignup, *window, *terms,
		origin, strings.Join(modPersonas, ", "), origin, strings.Join(adminPersonas, ", "), logDir,
		map[string]string{"fake": "fake, in-process (trial handles in tools/authdev/README.md)", "off": "off"}[*xlookupMode])
	return web.Serve(ctx, *listen, srv.Handler(), log, nil)
}

// personaSubjects are the provider subjects the fake providers use for a
// persona (see fakePages.ServeHTTP).
func personaSubjects(who string) [][2]string {
	n := map[string]string{"ada": "1", "bob": "2", "mallory": "3"}[who]
	return [][2]string{{auth.Google, who + "-" + auth.Google}, {auth.Apple, who + "-" + auth.Apple},
		{auth.GitHub, n + "001"}, {auth.X, n + "002"}}
}

// promote gives the accounts of the given personas role (moderator or
// admin) as soon as they exist (checked every two seconds; development
// only: a direct UPDATE, not audited — on a server use `nday auth-role`).
func promote(ctx context.Context, db *dbpool.Pool, who []string, role string, log *slog.Logger) {
	var provs, subs []string
	for _, w := range who {
		for _, ps := range personaSubjects(w) {
			provs, subs = append(provs, ps[0]), append(subs, ps[1])
		}
	}
	t := time.NewTicker(2 * time.Second)
	defer t.Stop()
	for {
		err := db.WithConn(ctx, func(c *pgx.Conn) error {
			tag, err := c.Exec(ctx, `UPDATE users SET role = $3 WHERE role = 'user' AND id IN (
				SELECT i.user_id FROM identities i JOIN unnest($1::text[], $2::text[]) AS p(provider, subject)
				ON i.provider = p.provider AND i.subject = p.subject)`, provs, subs, role)
			if err == nil && tag.RowsAffected() > 0 {
				log.Info("authdev: persona account promoted", "role", role, "personas", strings.Join(who, ","), "accounts", tag.RowsAffected())
			}
			return err
		})
		if err != nil && ctx.Err() == nil {
			log.Warn("authdev: promoting moderators failed", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// loopbackAddr accepts host:port with a loopback IP or "localhost".
func loopbackAddr(addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil || port == "" {
		return errors.New("want host:port")
	}
	if !loopbackHost(host) {
		return fmt.Errorf("%s is not a loopback address; authdev never listens on the network", host)
	}
	return nil
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

// devOrigin validates the public origin: http only, loopback host.
func devOrigin(v string) (string, error) {
	o, err := auth.ParsePublicOrigin(v)
	if err != nil {
		return "", err
	}
	u, _ := url.Parse(o)
	if u.Scheme != "http" {
		return "", errors.New("authdev serves plain http on loopback only; https public URLs are refused")
	}
	if !loopbackHost(u.Hostname()) {
		return "", errors.New("the public URL must be a loopback host (localhost)")
	}
	return o, nil
}

func checkSchema(ctx context.Context, db *dbpool.Pool) error {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var ok bool
	err := db.WithConn(c, func(conn *pgx.Conn) error {
		return conn.QueryRow(c, "SELECT to_regclass('public.identities') IS NOT NULL AND to_regclass('public.admin_audit') IS NOT NULL").Scan(&ok)
	})
	if err != nil {
		return fmt.Errorf("database: %w", err)
	}
	if !ok {
		return errors.New("the auth or audit tables are missing: run `go run ./cmd/nday migrate` against this database first")
	}
	return nil
}

// fakePages are the browser-facing pages of the fake providers: the
// authorize endpoint approves at once as the current persona (or denies
// for "deny"), and / switches the persona.
type fakePages struct {
	idp       *fakeidp.IDP
	providers []string
	site      string

	mu      sync.Mutex
	persona string
}

func (f *fakePages) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if r.Method != http.MethodGet {
		http.Error(w, "GET only", http.StatusMethodNotAllowed)
		return
	}
	if as := r.URL.Query().Get("as"); as != "" {
		if _, ok := personas[as]; !ok {
			http.Error(w, "unknown persona", http.StatusBadRequest)
			return
		}
		f.mu.Lock()
		f.persona = as
		f.mu.Unlock()
	}
	f.mu.Lock()
	who := f.persona
	f.mu.Unlock()
	seg := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(seg) == 2 && seg[1] == "authorize" {
		p := seg[0]
		full := "http://" + r.Host + r.URL.RequestURI()
		if who == "deny" {
			http.Redirect(w, r, f.idp.Deny(p, full), http.StatusFound)
			return
		}
		sub := who + "-" + p
		if p == auth.GitHub || p == auth.X { // their user ids are numbers
			sub = map[string]string{"ada": "1", "bob": "2", "mallory": "3"}[who] + map[string]string{auth.GitHub: "001", auth.X: "002"}[p]
		}
		cb, err := f.idp.Approve(p, full, fakeidp.Account{Subject: sub, Name: personas[who], Username: who})
		if err != nil {
			http.Error(w, "fake provider refused the request: "+err.Error(), http.StatusBadRequest)
			return
		}
		http.Redirect(w, r, cb, http.StatusFound)
		return
	}
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	names := make([]string, 0, len(personas))
	for n := range personas {
		names = append(names, n)
	}
	sort.Strings(names)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", "default-src 'none'")
	fmt.Fprintf(w, "<!doctype html><title>authdev personas</title><p>fake providers (%s) sign in as <b>%s</b>.</p><ul>",
		html.EscapeString(strings.Join(f.providers, ", ")), html.EscapeString(who))
	for _, n := range names {
		fmt.Fprintf(w, `<li><a href="/?as=%s">%s</a> %s</li>`, n, n, html.EscapeString(personas[n]))
	}
	fmt.Fprintf(w, `</ul><p><a href="%s/account">back to the site</a></p>`, html.EscapeString(f.site))
}
