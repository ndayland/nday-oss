package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/corrections"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/xlookup"
)

// Database settings in the website process (internal/settings):
//
//   - at start-up, cmdServe validates the environment alone first. When it
//     is valid, it then reads app_settings through the read-only site pool
//     and resolves sign-in, the discussion switch and limits, and the X
//     lookup token from the database settings layered over the
//     environment. A part the database values break falls back, with a
//     warning naming keys only: sign-in first drops the stored keys of each
//     provider the database leaves incomplete or invalid (layerAuth), then
//     the database altogether; a database that would switch sign-in off
//     although the environment turns it on is ignored. An unreadable table
//     (migration 0014 not applied) means the environment alone.
//   - when the environment alone is invalid for sign-in or discussions
//     (e.g. a client ID in auth.env whose secret was moved into the
//     database), cmdServe reads app_settings before failing and starts with
//     the layered configuration if that is valid; otherwise (no usable row,
//     an unreadable table, or still invalid) it stops with the
//     environment's error, exactly as before.
//   - while it runs, serveRuntime (settings.Runtime, handed to the back
//     office) validates a candidate snapshot and, after a save, re-reads
//     app_settings and applies what is stored: auth.Service.Reconfigure,
//     discuss.Service.SetLimits, admin.Service.SetXLookup and
//     site.Store.SetPinConfig.

// logSnapshotWarnings logs the warnings of snap (key names and reasons only).
func logSnapshotWarnings(snap *settings.Snapshot, log *slog.Logger) {
	for _, w := range snap.Warnings() {
		log.Warn("settings: " + w)
	}
}

// serveSnapshot reads app_settings through pool; on failure it warns and
// returns a nil snapshot (the environment alone applies, as before). The
// snapshot's warnings are logged. key is the master key (settingsKey).
func serveSnapshot(ctx context.Context, pool *dbpool.Pool, key *settings.Key, log *slog.Logger) *settings.Snapshot {
	snap, err := loadVia(pool, key)(ctx)
	if err != nil {
		log.Warn("settings: cannot read the database settings; using the environment only", "err", err)
		return nil
	}
	logSnapshotWarnings(snap, log)
	return snap
}

// startupSnapshot is serveSnapshot over one read-only connection opened
// from cfg (before the site pool exists: the environment alone was refused
// and the database settings may complete it).
func startupSnapshot(ctx context.Context, cfg *pgx.ConnConfig, key *settings.Key, log *slog.Logger) *settings.Snapshot {
	cfg = cfg.Copy()
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	cfg.RuntimeParams["statement_timeout"] = "8000"
	c, err := pgx.ConnectConfig(ctx, cfg)
	if err != nil {
		log.Warn("settings: cannot read the database settings; using the environment only", "err", err)
		return nil
	}
	defer c.Close(context.WithoutCancel(ctx))
	snap, err := settings.LoadSnapshot(ctx, c, key)
	if err != nil {
		log.Warn("settings: cannot read the database settings; using the environment only", "err", err)
		return nil
	}
	logSnapshotWarnings(snap, log)
	return snap
}

// loadVia returns a loader of the stored settings through pool (secrets
// opened with key).
func loadVia(pool *dbpool.Pool, key *settings.Key) func(context.Context) (*settings.Snapshot, error) {
	return func(ctx context.Context) (*settings.Snapshot, error) {
		var snap *settings.Snapshot
		err := pool.WithConn(ctx, func(c *pgx.Conn) error {
			var err error
			snap, err = settings.LoadSnapshot(ctx, c, key)
			return err
		})
		return snap, err
	}
}

// servesAny reports whether snap serves at least one registered setting
// (no row, or none usable: the environment alone, exactly as before).
func servesAny(snap *settings.Snapshot) bool {
	for _, d := range settings.Defs() {
		if snap.Source(d.Key, nil) == settings.SourceDB {
			return true
		}
	}
	return false
}

// authProviders are the managed settings of each sign-in provider: what
// layerAuth drops together when the database leaves the provider
// incomplete or invalid (NDAY_AUTH_APPLE_KEY_FILE is environment-only).
var authProviders = []struct {
	name string
	keys []string
}{
	{auth.Google, []string{auth.EnvGoogleClientID, auth.EnvGoogleClientSecret}},
	{auth.Apple, []string{auth.EnvAppleServicesID, auth.EnvAppleTeamID, auth.EnvAppleKeyID, auth.EnvAppleKey}},
	{auth.GitHub, []string{auth.EnvGitHubClientID, auth.EnvGitHubClientSecret}},
	{auth.X, []string{auth.EnvXClientID, auth.EnvXClientSecret}},
}

// storedKeys returns the keys of keys that have a row in snap (usable or
// not).
func storedKeys(snap *settings.Snapshot, keys []string) []string {
	var out []string
	for _, k := range keys {
		if snap.Has(k) {
			out = append(out, k)
		}
	}
	return out
}

// signInRows returns the stored settings of snap (usable or not) that are
// meant to turn sign-in on: provider credentials, and NDAY_AUTH_PASSKEYS
// unless it is stored as off. (Terms, session lengths and the like do not
// count: they are stored whether sign-in is on or not.)
func signInRows(snap *settings.Snapshot) []string {
	var keys []string
	for _, p := range authProviders {
		keys = append(keys, storedKeys(snap, p.keys)...)
	}
	if snap.Has(auth.EnvPasskeys) {
		switch v, _ := snap.Value(auth.EnvPasskeys); strings.ToLower(v) {
		case "off", "0", "false", "no":
		default:
			keys = append(keys, auth.EnvPasskeys)
		}
	}
	return keys
}

// layerAuth returns the sign-in configuration to start with. envCfg and
// envErr are auth.FromEnv of the environment alone.
//
// With nothing served by snap it is the environment's (envErr returned as
// it is). Otherwise snap over env is tried; when that is refused, the
// stored keys of every provider the refusal names are dropped together
// (that provider uses the environment, or is off; a WARN names the keys)
// and it is tried again. Still refused, or with no provider to drop: the
// environment alone (envErr when that is invalid too). A layered
// configuration that would switch sign-in off although the environment
// turns it on is ignored as well. Sign-in that only the database turns on
// is enabled. When sign-in ends up off although sign-in rows are stored,
// an ERROR says how to recover. Nothing logged holds a value.
func layerAuth(snap *settings.Snapshot, env func(string) (string, bool), envCfg *auth.Config, envErr error,
	log *slog.Logger) (*auth.Config, error) {
	cfg, err := layeredAuth(snap, env, envCfg, envErr, log)
	if err == nil && cfg == nil {
		if rows := signInRows(snap); len(rows) > 0 {
			log.Error("settings: sign-in is OFF although sign-in settings are stored in the database (they are unusable "+
				"or incomplete, see the warnings above); the back office is unreachable until this is fixed: inspect them "+
				"with `nday settings`, remove the broken ones with `nday settings-unset KEY --yes` (or set the missing "+
				"values in the environment), then restart (docs/settings.md section 8)", "keys", rows)
		}
	}
	return cfg, err
}

func layeredAuth(snap *settings.Snapshot, env func(string) (string, bool), envCfg *auth.Config, envErr error,
	log *slog.Logger) (*auth.Config, error) {
	if !servesAny(snap) {
		return envCfg, envErr
	}
	cur := snap
	var cfg *auth.Config
	var err error
	for {
		if cfg, err = auth.FromEnv(cur.Lookup(env)); err == nil {
			break
		}
		named := map[string]bool{}
		for _, k := range namedKeys(err) {
			named[k] = true
		}
		dropped := false
		for _, p := range authProviders {
			mentioned := false
			for _, k := range p.keys {
				mentioned = mentioned || named[k]
			}
			stored := storedKeys(cur, p.keys)
			if !mentioned || len(stored) == 0 {
				continue
			}
			log.Warn("settings: sign-in ignores the database settings of provider "+p.name+
				" (incomplete or invalid with them); it uses the environment for this provider", "keys", stored)
			for _, k := range stored {
				cur = cur.Without(k)
			}
			dropped = true
		}
		if !dropped {
			break
		}
	}
	switch {
	case err != nil && envErr != nil:
		log.Warn("settings: the database settings do not make the sign-in configuration valid", "err", err.Error())
		return nil, envErr
	case err != nil:
		log.Warn("settings: sign-in rejects the database settings; using the environment only", "err", err.Error())
		return envCfg, nil
	case cfg == nil && envCfg != nil:
		log.Warn("settings: the database settings would turn sign-in off entirely; using the environment only",
			"err", errSignInOff.Error())
		return envCfg, nil
	case envErr != nil:
		log.Warn("settings: the environment alone is not a valid sign-in configuration; the database settings complete it",
			"err", envErr.Error())
	}
	return cfg, nil
}

// namedKeys returns the distinct NDAY_* names an error mentions.
func namedKeys(err error) []string {
	if err == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, k := range keyNameRe.FindAllString(err.Error(), -1) {
		if !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

var keyNameRe = regexp.MustCompile(`\bNDAY_[A-Z0-9_]*[A-Z0-9]`)

// layerDiscuss returns the discussion configuration to start with: dcfg
// and envErr are discussFromEnv of the environment alone. The switch and
// the limits come from snap over env unless snap serves nothing or its
// values are refused (a warning; the environment's configuration, or
// envErr when that is invalid too). The pool size stays environment-only:
// when it is invalid, envErr is returned whatever the database holds.
func layerDiscuss(snap *settings.Snapshot, env func(string) (string, bool), dcfg *discussConfig, envErr error,
	log *slog.Logger) (*discussConfig, error) {
	if !servesAny(snap) {
		return dcfg, envErr
	}
	get := getenv(snap.Lookup(env))
	on, err := discuss.Enabled(get)
	l, lerr := discuss.LimitsFromEnv(get)
	if err = errors.Join(err, lerr); err != nil {
		if envErr != nil {
			log.Warn("settings: the database settings do not make the discussion configuration valid", "err", err.Error())
			return nil, envErr
		}
		log.Warn("settings: discussions reject the database settings; using the environment only", "err", err.Error())
		return dcfg, nil
	}
	if envErr != nil {
		n, perr := discuss.PoolSize(getenv(env))
		if perr != nil {
			return nil, envErr
		}
		log.Warn("settings: the environment alone is not a valid discussion configuration; the database settings complete it",
			"err", envErr.Error())
		return &discussConfig{enabled: on, limits: l, pool: n}, nil
	}
	dcfg.enabled, dcfg.limits = on, l
	return dcfg, nil
}

// pinsServe is the start-up pinning of the hot list (site/pin.go): from
// snap over env; values it refuses fall back to the environment alone,
// then to the defaults, with a warning naming keys only. It never stops
// the site.
func pinsServe(snap *settings.Snapshot, env func(string) (string, bool), log *slog.Logger) site.PinConfig {
	c, err := site.PinConfigFromEnv(getenv(snap.Lookup(env)))
	if err == nil {
		return c
	}
	log.Warn("settings: the hot list pinning rejects the database settings; using the environment only", "err", err.Error())
	if c, err = site.PinConfigFromEnv(getenv(env)); err == nil {
		return c
	}
	log.Warn("settings: the hot list pinning rejects the environment; using the defaults", "err", err.Error())
	return site.DefaultPinConfig
}

// correctionsServe is the start-up limits of readers' corrections
// (internal/corrections): from snap over env; values it refuses fall back
// to the environment alone, then to the defaults, with a warning naming
// keys only. It never stops the site.
func correctionsServe(snap *settings.Snapshot, env func(string) (string, bool), log *slog.Logger) corrections.Limits {
	l, err := corrections.LimitsFromEnv(getenv(snap.Lookup(env)))
	if err == nil {
		return l
	}
	log.Warn("settings: the correction limits reject the database settings; using the environment only", "err", err.Error())
	if l, err = corrections.LimitsFromEnv(getenv(env)); err == nil {
		return l
	}
	log.Warn("settings: the correction limits reject the environment; using the defaults", "err", err.Error())
	return corrections.DefaultLimits()
}

// xLookupFrom builds the X user lookup of /admin/x from NDAY_X_BEARER_TOKEN
// as lookup gives it (nil, nil when unset). The base URL is always the X
// API's: no setting can change it. Errors never contain the token.
func xLookupFrom(lookup func(string) (string, bool), log *slog.Logger) (*xlookup.Client, error) {
	tok, _ := lookup(xlookup.TokenEnv)
	if tok == "" {
		return nil, nil
	}
	return xlookup.New(xlookup.Options{Token: tok, Logger: log})
}

// xLookupServe is the start-up X lookup: from snap over env; a database
// token that cannot be used falls back to the environment's; a token that
// cannot go in a header turns the lookup off with a warning instead of
// stopping the site. The token itself is never logged.
func xLookupServe(snap *settings.Snapshot, env func(string) (string, bool), log *slog.Logger) *xlookup.Client {
	c, err := xLookupFrom(snap.Lookup(env), log)
	if err != nil && snap.Source(xlookup.TokenEnv, nil) == settings.SourceDB {
		log.Warn("settings: the X user lookup rejects the database settings; using the environment only",
			"err", xlookup.TokenEnv+": invalid value")
		c, err = xLookupFrom(env, log)
	}
	if err != nil {
		log.Warn("admin: X user lookup disabled", "err", err)
		return nil
	}
	return c
}

// serveRuntime is settings.Runtime of `nday serve`.
type serveRuntime struct {
	mu      sync.Mutex // serialises Apply (each one loads and applies under it)
	env     func(string) (string, bool)
	key     *settings.Key
	load    func(context.Context) (*settings.Snapshot, error) // reads app_settings now
	auth    *auth.Service
	discuss *discuss.Service // nil: discussions are off
	admin   *admin.Service   // set once the back office exists
	site    *site.Store      // nil: no hot list in this process
	// corrections is the readers' corrections service (nil: none)
	corrections *corrections.Service
	log         *slog.Logger
}

var _ settings.Runtime = (*serveRuntime)(nil)

// NewSettingsRuntime returns the settings.Runtime of `nday serve` for a
// process that builds its services itself (tools/authdev): env is that
// process's environment lookup (what its configuration was built from),
// key the master key (nil: secrets cannot be stored), db a pool Apply
// reads app_settings through (read-only is enough), authSvc the sign-in
// service (nil: none), discussSvc the discussion service (nil: off).
// Unlike in `nday serve` it never changes the X user lookup of a back
// office.
func NewSettingsRuntime(env func(string) (string, bool), key *settings.Key, db *dbpool.Pool, authSvc *auth.Service,
	discussSvc *discuss.Service, log *slog.Logger) settings.Runtime {
	if log == nil {
		log = slog.Default()
	}
	return &serveRuntime{env: env, key: key, load: loadVia(db, key), auth: authSvc, discuss: discussSvc, log: log}
}

// Env is the process environment.
func (rt *serveRuntime) Env() func(string) (string, bool) { return rt.env }

// Key is the master key (nil: not configured).
func (rt *serveRuntime) Key() *settings.Key { return rt.key }

// resolved is what a snapshot configures in the running process.
type resolved struct {
	auth   *auth.Config
	limits discuss.Limits
	x      *xlookup.Client
	pins   site.PinConfig
	corr   corrections.Limits
}

// resolve parses everything Apply changes from snap over the environment;
// the errors name keys only.
func (rt *serveRuntime) resolve(snap *settings.Snapshot) (*resolved, error) {
	lookup := snap.Lookup(rt.env)
	var res resolved
	var errs []error
	var err error
	if res.auth, err = auth.FromEnv(lookup); err != nil {
		errs = append(errs, err)
	}
	if res.limits, err = discuss.LimitsFromEnv(getenv(lookup)); err != nil {
		errs = append(errs, err)
	}
	if res.x, err = xLookupFrom(lookup, rt.log); err != nil {
		errs = append(errs, errors.New(xlookup.TokenEnv+": invalid value (it cannot go in an HTTP header)"))
	}
	if res.pins, err = site.PinConfigFromEnv(getenv(lookup)); err != nil {
		errs = append(errs, err)
	}
	if res.corr, err = corrections.LimitsFromEnv(getenv(lookup)); err != nil {
		errs = append(errs, err)
	}
	if err := errors.Join(errs...); err != nil {
		return nil, err
	}
	return &res, nil
}

// Validate is validateCandidate (every validator of the managed settings,
// and sign-in may not be switched off when the environment turns it on)
// plus what Apply checks: the parsed configuration and, with sign-in
// running, auth.Service.CheckReconfigure (sign-in stays on; the public
// origin, secrets and WebAuthn RP stay as they are).
func (rt *serveRuntime) Validate(candidate *settings.Snapshot) error {
	if err := validateCandidate(candidate.Lookup(rt.env), rt.env); err != nil {
		return err
	}
	res, err := rt.resolve(candidate)
	if err != nil {
		return err
	}
	if rt.auth != nil {
		return rt.auth.CheckReconfigure(res.auth)
	}
	return nil
}

// Apply reads app_settings again and puts the configuration it gives
// into the running process: sign-in (Reconfigure), the discussion limits
// (SetLimits), the X user lookup (SetXLookup) and the hot list pinning
// (SetPinConfig). Loading and applying
// happen under one lock, so whatever order concurrent saves call it in,
// the last call leaves the process at the last committed state; applying
// an unchanged state again is harmless. NDAY_DISCUSS and the other Restart
// settings wait for the next start. Nothing changes when it fails.
func (rt *serveRuntime) Apply(ctx context.Context) error {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	snap, err := rt.load(ctx)
	if err != nil {
		return fmt.Errorf("settings: cannot read the stored settings: %w", err)
	}
	logSnapshotWarnings(snap, rt.log)
	res, err := rt.resolve(snap)
	if err != nil {
		return err
	}
	if rt.auth != nil {
		if err := rt.auth.Reconfigure(res.auth); err != nil {
			return err
		}
	}
	if rt.discuss != nil {
		rt.discuss.SetLimits(res.limits)
	}
	if rt.admin != nil {
		rt.admin.SetXLookup(res.x)
	}
	if rt.site != nil {
		rt.site.SetPinConfig(res.pins)
	}
	if rt.corrections != nil {
		rt.corrections.SetLimits(res.corr)
	}
	attrs := []any{"x_lookup", res.x.Configured(), "hot_pin_max", res.pins.Max}
	if rt.auth != nil {
		cfg := rt.auth.Config()
		attrs = append(attrs, "providers", rt.auth.Enabled(), "passkeys", cfg.Passkeys, "terms_version", cfg.TermsVersion)
	}
	rt.log.Info("settings: applied to the running site", attrs...)
	return nil
}
