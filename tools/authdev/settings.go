package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/cli"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/settings"
)

// The database settings of /admin/settings (docs/settings.md) in authdev:
// the runtime of `nday serve` (cli.NewSettingsRuntime), so saving on the
// page really validates, stores and applies. Its "environment" is the
// sign-in configuration authdev builds from its flags, written out as the
// NDAY_* variables `nday serve` would read (devEnv), over the process
// environment for every other key. The master key comes from
// NDAY_SETTINGS_KEY, else a random one that lives only as long as this
// process (secrets stored with it cannot be read after a restart).

// devEnv is cfg (built by run from the flags) as environment variables;
// window is the sensitive-action window (the variable's range starts at 1m).
func devEnv(cfg *auth.Config, secret []byte, appleKey *ecdsa.PrivateKey, window time.Duration) (map[string]string, error) {
	onOff := map[bool]string{true: "on", false: "off"}
	if window < time.Minute {
		window = time.Minute
	}
	m := map[string]string{
		auth.EnvPublicURL:       cfg.PublicOrigin,
		auth.EnvSecret:          base64.StdEncoding.EncodeToString(secret),
		auth.EnvPasskeys:        onOff[cfg.Passkeys],
		auth.EnvPasskeySignup:   onOff[cfg.PasskeySignup],
		auth.EnvSensitiveWindow: window.String(),
	}
	if cfg.TermsVersion != "" {
		m[auth.EnvTermsVersion] = cfg.TermsVersion
	}
	ids := map[string][2]string{auth.Google: {auth.EnvGoogleClientID, auth.EnvGoogleClientSecret},
		auth.GitHub: {auth.EnvGitHubClientID, auth.EnvGitHubClientSecret}, auth.X: {auth.EnvXClientID, auth.EnvXClientSecret}}
	for p, c := range cfg.Providers {
		if p != auth.Apple {
			m[ids[p][0]], m[ids[p][1]] = c.ClientID, c.ClientSecret
			continue
		}
		der, err := x509.MarshalPKCS8PrivateKey(appleKey)
		if err != nil {
			return nil, err
		}
		m[auth.EnvAppleServicesID], m[auth.EnvAppleTeamID], m[auth.EnvAppleKeyID] = c.ClientID, c.TeamID, c.KeyID
		m[auth.EnvAppleKey] = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	}
	return m, nil
}

// devLookup serves the sign-in variables from dev only (a variable of the
// shell must not change what authdev runs with) and everything else from
// the process environment.
func devLookup(dev map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		if v, ok := dev[k]; ok {
			return v, true
		}
		if strings.HasPrefix(k, "NDAY_AUTH_") || k == auth.EnvPublicURL || k == auth.EnvTermsVersion {
			return "", false
		}
		return os.LookupEnv(k)
	}
}

// devSettingsKey is NDAY_SETTINGS_KEY, else a random key for this process.
func devSettingsKey(log *slog.Logger) (*settings.Key, error) {
	k, err := settings.KeyFromEnv(os.LookupEnv)
	if err != nil || k != nil {
		return k, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	log.Info("authdev: " + settings.EnvKey + " is not set; using a random master key for this process only " +
		"(secrets saved on /admin/settings cannot be read after a restart)")
	return settings.ParseKey(base64.StdEncoding.EncodeToString(b))
}

// devSettings builds the settings runtime and applies the settings stored
// in the database (if the configuration they give is accepted; otherwise
// the flags alone apply). nil when the database has no app_settings table
// (migrations/0014_settings.sql not applied): /admin/settings then says
// the settings are unavailable.
func devSettings(ctx context.Context, db *dbpool.Pool, cfg *auth.Config, secret []byte, appleKey *ecdsa.PrivateKey,
	window time.Duration, svc *auth.Service, ds *discuss.Service, log *slog.Logger) (settings.Runtime, error) {
	var ok bool
	if err := db.WithConn(ctx, func(c *pgx.Conn) error {
		return c.QueryRow(ctx, "SELECT to_regclass('public.app_settings') IS NOT NULL").Scan(&ok)
	}); err != nil {
		return nil, err
	}
	if !ok {
		log.Warn("authdev: no app_settings table (run `go run ./cmd/nday migrate`); /admin/settings is unavailable")
		return nil, nil
	}
	dev, err := devEnv(cfg, secret, appleKey, window)
	if err != nil {
		return nil, err
	}
	key, err := devSettingsKey(log)
	if err != nil {
		return nil, err
	}
	rt := cli.NewSettingsRuntime(devLookup(dev), key, db, svc, ds, log)
	var snap *settings.Snapshot
	if err := db.WithConn(ctx, func(c *pgx.Conn) error {
		var err error
		snap, err = settings.LoadSnapshot(ctx, c, key)
		return err
	}); err != nil {
		return nil, err
	}
	for _, w := range snap.Warnings() {
		log.Warn("authdev: settings: " + w)
	}
	stored := false
	for _, d := range settings.Defs() {
		stored = stored || snap.Source(d.Key, nil) == settings.SourceDB
	}
	switch err := rt.Validate(snap); {
	case !stored: // nothing stored: the flags apply as they are
	case err != nil:
		// (the runtime's errors name keys, never values)
		log.Warn("authdev: the database settings are refused; the flags alone apply", "err", err.Error())
	default:
		if err := rt.Apply(ctx); err != nil {
			log.Warn("authdev: the database settings could not be applied; the flags alone apply", "err", err.Error())
		}
	}
	return rt, nil
}
