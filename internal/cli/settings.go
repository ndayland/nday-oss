package cli

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/cvelist"
	"nday.land/nday/internal/collector/ghsa"
	"nday.land/nday/internal/collector/xposts"
	"nday.land/nday/internal/corrections"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/site"
)

// Commands for the database-backed settings (internal/settings, table
// app_settings). These are the emergency tools on the server; secrets are
// written only from the admin pages (a value on the command line would be
// visible in the process list and the shell history):
//
//	nday settings                       every managed setting: source (db/env/default), the stored
//	                                    value of plain settings, "set" and the hint of secrets
//	nday settings-set KEY VALUE --yes   store a plain setting after validating the resulting
//	                                    configuration (audited)
//	nday settings-unset KEY --yes       delete the stored row: the environment or the default
//	                                    applies again (audited)
const settingsUsage = "usage: nday settings | nday settings-set KEY VALUE --yes | nday settings-unset KEY --yes " +
	"(secrets are set on the admin pages, never on the command line)"

// ------------------------------------------------------------------ validation

// collectorChecks are the collectors whose constructors validate managed
// settings (they read only their configuration; nothing touches the
// network).
var collectorChecks = []struct {
	name    string
	factory collector.Factory
}{
	{cvelist.Name, cvelist.Factory},
	{ghsa.Name, ghsa.Factory},
	{xposts.Name, xposts.Factory},
}

// managedCollectorKeys are the collector settings of the registry.
func managedCollectorKeys() []string {
	var keys []string
	for _, d := range settings.GroupDefs(settings.GroupCollectors) {
		keys = append(keys, d.Key)
	}
	return keys
}

// only restricts lookup to one key (everything else unset).
func only(lookup func(string) (string, bool), key string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		if k != key {
			return "", false
		}
		return lookup(k)
	}
}

// collectorError builds the collector from lookup and, when that fails,
// returns an error that names the offending keys and never a value (the
// constructors' own messages may quote what they read). Each managed
// collector key is tried alone to find the culprits.
func collectorError(name string, factory collector.Factory, lookup func(string) (string, bool)) error {
	c, err := factory(collector.Deps{Env: lookup})
	if err == nil {
		closeCollector(c)
		return nil
	}
	var bad []string
	for _, k := range managedCollectorKeys() {
		c, err := factory(collector.Deps{Env: only(lookup, k)})
		if err != nil {
			bad = append(bad, k)
			continue
		}
		closeCollector(c)
	}
	if len(bad) == 0 {
		return fmt.Errorf("collector %s: the configuration is invalid", name)
	}
	var errs []error
	for _, k := range bad {
		errs = append(errs, fmt.Errorf("%s: invalid value (rejected by the %s collector)", k, name))
	}
	return errors.Join(errs...)
}

// getenv adapts a lookup to the func(string) string of internal/discuss.
func getenv(lookup func(string) (string, bool)) func(string) string {
	return func(k string) string {
		v, _ := lookup(k)
		return v
	}
}

// validateSettings runs every existing validator of the managed settings
// on a candidate configuration (lookup: as the processes would see it):
// sign-in (auth.FromEnv), discussions (discuss.Enabled, LimitsFromEnv),
// the cvelist, ghsa and xposts collectors and the hot list's pinning
// (site.PinConfigFromEnv). The errors name keys, never values.
func validateSettings(lookup func(string) (string, bool)) error {
	var errs []error
	if _, err := auth.FromEnv(lookup); err != nil {
		errs = append(errs, err)
	}
	if _, err := discuss.Enabled(getenv(lookup)); err != nil {
		errs = append(errs, err)
	}
	if _, err := discuss.LimitsFromEnv(getenv(lookup)); err != nil {
		errs = append(errs, err)
	}
	for _, c := range collectorChecks {
		if err := collectorError(c.name, c.factory, lookup); err != nil {
			errs = append(errs, err)
		}
	}
	if _, err := site.PinConfigFromEnv(getenv(lookup)); err != nil {
		errs = append(errs, err)
	}
	if _, err := corrections.LimitsFromEnv(getenv(lookup)); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// errSignInOff: a change would switch sign-in off entirely.
var errSignInOff = errors.New("auth: the change would turn sign-in off entirely (every provider and passkeys); " +
	"change the environment instead if that is intended")

// validateCandidate is validateSettings(candidate) plus: when sign-in is
// enabled by the environment alone (env), the candidate must not disable it
// as a whole.
func validateCandidate(candidate, env func(string) (string, bool)) error {
	err := validateSettings(candidate)
	if base, berr := auth.FromEnv(env); berr == nil && base != nil {
		if cfg, cerr := auth.FromEnv(candidate); cerr == nil && cfg == nil {
			err = errors.Join(err, errSignInOff)
		}
	}
	return err
}

// ------------------------------------------------------------------ layered lookup

// environSnapshot copies the process environment now (the collector
// configuration is taken before connect loads ./.env, see docs/go.md).
func environSnapshot() func(string) (string, bool) {
	m := map[string]string{}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			if _, dup := m[k]; !dup { // the first occurrence wins, like os.LookupEnv
				m[k] = v
			}
		}
	}
	return func(k string) (string, bool) {
		v, ok := m[k]
		return v, ok
	}
}

// settingsKey reads the master key from the process environment (after
// connect, so ./.env may provide it like NDAY_DATABASE_URL). A bad key is
// logged and treated as absent.
func settingsKey() *settings.Key {
	k, err := settings.KeyFromEnv(os.LookupEnv)
	if err != nil {
		slog.Warn("settings: ignoring the master key", "err", err)
		return nil
	}
	return k
}

// loadSnapshot reads app_settings; on failure (e.g. migration 0014 not
// applied yet) it logs a warning and returns nil, an empty snapshot: the
// environment alone applies, as before. Snapshot warnings are logged too.
func loadSnapshot(ctx context.Context, conn *pgx.Conn) *settings.Snapshot {
	snap, err := settings.LoadSnapshot(ctx, conn, settingsKey())
	if err != nil {
		slog.Warn("settings: cannot read the database settings; using the environment only", "err", err)
		return nil
	}
	for _, w := range snap.Warnings() {
		slog.Warn("settings: " + w)
	}
	return snap
}

// buildCollector constructs the named collector from the database
// settings layered over envSnap (the environment snapshot taken before
// connect). If the database values make the constructor fail, it warns
// (keys only, never values) and builds from envSnap alone, whose error, if
// any, is returned exactly as before.
func buildCollector(ctx context.Context, conn *pgx.Conn, env Env, name string, factory collector.Factory,
	envSnap func(string) (string, bool)) (collector.Collector, error) {
	if snap := loadSnapshot(ctx, conn); snap != nil {
		lookup := snap.Lookup(envSnap)
		c, err := factory(collector.Deps{Env: lookup, Transport: env.Transport})
		if err == nil {
			return c, nil
		}
		slog.Warn("settings: the collector rejects its configuration with the database settings; using the environment only",
			"source", name, "err", collectorError(name, factory, lookup).Error())
	}
	return factory(collector.Deps{Env: envSnap, Transport: env.Transport})
}

// gcSessionIdle is the session idle time `nday auth-gc` expires sessions
// with: NDAY_AUTH_SESSION_IDLE of the sign-in configuration from the
// database settings layered over the environment. When the database values
// are refused it warns (keys only) and uses the environment alone, whose
// error, if any, is returned as before; sign-in off means the default.
func gcSessionIdle(ctx context.Context, conn *pgx.Conn) (time.Duration, error) {
	cfg, err := auth.FromEnv(nil)
	if snap := loadSnapshot(ctx, conn); servesAny(snap) {
		dcfg, derr := auth.FromEnv(snap.Lookup(os.LookupEnv))
		if derr == nil {
			cfg, err = dcfg, nil
		} else {
			slog.Warn("settings: sign-in rejects the database settings; auth-gc uses the environment only", "err", derr.Error())
		}
	}
	if err != nil {
		return 0, err
	}
	if cfg.Enabled() {
		return cfg.SessionIdle, nil
	}
	return auth.DefaultSessionIdle, nil
}

// ------------------------------------------------------------------ commands

func runSettingsCommand(ctx context.Context, env Env, cmd string, rest []string) error {
	prog := "nday " + cmd
	maxPos := map[string]int{"settings": 0, "settings-set": 2, "settings-unset": 1}[cmd]
	var specs []optSpec
	if cmd != "settings" {
		specs = []optSpec{{name: "--yes"}}
	}
	p, err := parseArgs(prog, specs, rest, maxPos)
	if err != nil {
		return err
	}
	var key, value string
	if cmd != "settings" {
		if len(p.pos) != maxPos {
			return &usageError{prog, settingsUsage}
		}
		key = p.pos[0]
		d, ok := settings.Lookup(key)
		if !ok {
			// (not echoed: a value pasted in the wrong place must not be printed)
			return &usageError{prog, "argument KEY: not a setting managed in the database (nday settings lists them)"}
		}
		if cmd == "settings-set" {
			if d.Secret {
				return &usageError{prog, key + " is a secret: set it on the admin pages, never on the command line"}
			}
			if value, err = settings.CheckValue(key, p.pos[1]); err != nil {
				return &usageError{prog, "argument VALUE: " + err.Error()}
			}
		}
		if _, ok := p.flags["--yes"]; !ok {
			return &usageError{prog, "the following arguments are required: --yes (this changes the live configuration)"}
		}
	}

	conn, err := connect(ctx)
	if err != nil {
		return err
	}
	defer conn.Close(context.WithoutCancel(ctx))
	switch cmd {
	case "settings-unset":
		var removed bool
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if err := settings.Lock(ctx, tx); err != nil {
				return err
			}
			var err error
			if removed, err = settings.Unset(ctx, tx, key); err != nil || !removed {
				return err
			}
			return audit.Write(ctx, tx, audit.Entry{Action: audit.SettingsUnset, TargetType: audit.TargetSetting,
				TargetID: key, Details: map[string]any{"keys": []string{key}}})
		})
		if err != nil {
			return err
		}
		if !removed {
			fmt.Fprintf(env.Stdout, "settings-unset: %s was not set in the database\n", key)
			return nil
		}
		fmt.Fprintf(env.Stdout, "settings-unset: %s removed from the database%s\n", key, restartNote(key))
		return nil
	case "settings-set":
		k := settingsKey()
		changed := false
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			if err := settings.Lock(ctx, tx); err != nil {
				return err
			}
			snap, err := settings.LoadSnapshot(ctx, tx, k)
			if err != nil {
				return err
			}
			if cur, ok := snap.Value(key); ok && cur == value {
				return nil // nothing changes: no write, no audit row
			}
			candidate := snap.With(key, value).Lookup(os.LookupEnv)
			if err := validateCandidate(candidate, os.LookupEnv); err != nil {
				return fmt.Errorf("%s: refused, the resulting configuration is invalid:\n%w%s", key, err, envFilesHint(err))
			}
			if changed, err = settings.Set(ctx, tx, key, value); err != nil || !changed {
				return err
			}
			return audit.Write(ctx, tx, audit.Entry{Action: audit.SettingsUpdate, TargetType: audit.TargetSetting,
				TargetID: key, Details: map[string]any{"keys": []string{key}}})
		})
		if err != nil {
			return err
		}
		if !changed {
			fmt.Fprintf(env.Stdout, "settings-set: %s unchanged\n", key)
			return nil
		}
		fmt.Fprintf(env.Stdout, "settings-set: %s stored in the database%s\n", key, restartNote(key))
		return nil
	}
	return listSettings(ctx, env, conn)
}

// envFilesHint is a note added to a refusal that names a variable only
// the website's environment files provide (NDAY_PUBLIC_URL in web.env,
// NDAY_AUTH_SECRET in auth.env): the command was probably run with
// nday.env alone. It names files, never values.
func envFilesHint(err error) string {
	for _, k := range namedKeys(err) {
		if k == auth.EnvPublicURL || k == auth.EnvSecret {
			return "\nhint: the check needs the website's whole environment; load /etc/nday/web.env and " +
				"/etc/nday/auth.env as well as nday.env (docs/settings.md section 8)"
		}
	}
	return ""
}

func restartNote(key string) string {
	if d, ok := settings.Lookup(key); ok && d.Restart {
		return " (the website applies it after a restart)"
	}
	return ""
}

// listSettings prints every managed setting; secrets show only "set" and
// their hint. The env source is this process's environment (with ./.env).
func listSettings(ctx context.Context, env Env, conn *pgx.Conn) error {
	snap, err := settings.LoadSnapshot(ctx, conn, settingsKey())
	if err != nil {
		return err
	}
	w := env.Stdout
	for _, g := range settings.Groups {
		fmt.Fprintf(w, "[%s]\n", g)
		for _, d := range settings.GroupDefs(g) {
			stored := "-"
			switch {
			case !snap.Has(d.Key):
			case d.Secret:
				stored = "secret set"
				if h := snap.Hint(d.Key); h != "" {
					stored += ", ends " + strconv.Quote(h)
				}
				if snap.Source(d.Key, nil) != settings.SourceDB {
					stored += " (cannot be read)"
				}
			default:
				if v, ok := snap.Value(d.Key); ok {
					stored = strconv.Quote(v)
				} else {
					stored = "(cannot be read)"
				}
			}
			if at, ok := snap.UpdatedAt(d.Key); ok {
				stored += " at " + at.UTC().Format("2006-01-02T15:04:05Z")
			}
			if d.Restart {
				stored += " [restart]"
			}
			fmt.Fprintf(w, "  %-36s %-7s %s\n", d.Key, snap.Source(d.Key, os.LookupEnv), stored)
		}
	}
	for _, m := range snap.Warnings() {
		fmt.Fprintln(env.Stderr, "warning: "+m)
	}
	return nil
}
