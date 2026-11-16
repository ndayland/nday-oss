package settings_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/testutil"
)

func key(t *testing.T) *settings.Key {
	t.Helper()
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	k, err := settings.ParseKey(base64.StdEncoding.EncodeToString(b))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestStoreRoundTrip(t *testing.T) {
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	k := key(t)
	const tok = "ghp_SECRET_db_round_trip_9876"

	if rows, err := settings.Load(ctx, d.Conn); err != nil || len(rows) != 0 {
		t.Fatalf("empty: %v %v", rows, err)
	}
	err := pgx.BeginFunc(ctx, d.Conn, func(tx pgx.Tx) error {
		if err := settings.Lock(ctx, tx); err != nil {
			return err
		}
		if ch, err := settings.Set(ctx, tx, "NDAY_DISCUSS_POST_BURST", " 9 "); err != nil || !ch {
			t.Errorf("set: %v %v", ch, err)
		}
		if ch, err := settings.Set(ctx, tx, "NDAY_DISCUSS_POST_BURST", "9"); err != nil || ch {
			t.Errorf("set same: %v %v", ch, err)
		}
		return settings.SetSecret(ctx, tx, "NDAY_GITHUB_TOKEN", "  "+tok+"\n", k)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := settings.SetSecret(ctx, d.Conn, "NDAY_AUTH_APPLE_KEY", "-----BEGIN PRIVATE KEY-----\nMIGTAgEAMBMG\n-----END PRIVATE KEY-----", k); err != nil {
		t.Fatal(err)
	}
	if err := settings.SetSecret(ctx, d.Conn, "NDAY_X_BEARER_TOKEN", "x", nil); !errors.Is(err, settings.ErrNoKey) {
		t.Errorf("no key: %v", err)
	}
	for _, c := range []struct {
		name string
		err  error
	}{
		{"set secret key", func() error { _, err := settings.Set(ctx, d.Conn, "NDAY_GITHUB_TOKEN", "v"); return err }()},
		{"seal plain key", settings.SetSecret(ctx, d.Conn, "NDAY_DISCUSS", "v", k)},
		{"unknown", func() error { _, err := settings.Set(ctx, d.Conn, "NDAY_DATABASE_URL", "v"); return err }()},
		{"empty", func() error { _, err := settings.Set(ctx, d.Conn, "NDAY_DISCUSS", " "); return err }()},
		{"empty secret", settings.SetSecret(ctx, d.Conn, "NDAY_GITHUB_TOKEN", " ", k)},
	} {
		if c.err == nil {
			t.Errorf("%s accepted", c.name)
		}
	}

	rows, err := settings.Load(ctx, d.Conn)
	if err != nil || len(rows) != 3 {
		t.Fatalf("load: %d %v", len(rows), err)
	}
	var raw []byte
	var hint *string
	if err := d.Conn.QueryRow(ctx, `SELECT secret, hint FROM app_settings WHERE key = 'NDAY_GITHUB_TOKEN'`).Scan(&raw, &hint); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), tok) || hint == nil || *hint != "9876" {
		t.Errorf("stored secret: hint %v", hint)
	}
	if err := d.Conn.QueryRow(ctx, `SELECT hint FROM app_settings WHERE key = 'NDAY_AUTH_APPLE_KEY'`).Scan(&hint); err != nil || hint != nil {
		t.Errorf("PEM hint: %v %v", hint, err)
	}

	snap, err := settings.LoadSnapshot(ctx, d.Conn, k)
	if err != nil {
		t.Fatal(err)
	}
	get := snap.Lookup(func(string) (string, bool) { return "env", true })
	if v, _ := get("NDAY_GITHUB_TOKEN"); v != tok {
		t.Error("secret did not round-trip")
	}
	if v, _ := get("NDAY_DISCUSS_POST_BURST"); v != "9" {
		t.Errorf("plain: %q", v)
	}
	if v, _ := get("NDAY_DISCUSS_POST_DAILY"); v != "env" {
		t.Errorf("unset: %q", v)
	}
	if len(snap.Warnings()) != 0 {
		t.Errorf("warnings: %v", snap.Warnings())
	}
	// a wrong master key falls back to the environment with a warning
	snap2, _ := settings.LoadSnapshot(ctx, d.Conn, key(t))
	if v, _ := snap2.Lookup(func(string) (string, bool) { return "env", true })("NDAY_GITHUB_TOKEN"); v != "env" {
		t.Error("wrong key served the secret")
	}
	if w := strings.Join(snap2.Warnings(), ";"); !strings.Contains(w, "NDAY_GITHUB_TOKEN") || strings.Contains(w, tok) {
		t.Errorf("wrong-key warnings: %s", w)
	}

	// Unset removes the row (the environment applies again)
	if removed, err := settings.Unset(ctx, d.Conn, "NDAY_GITHUB_TOKEN"); err != nil || !removed {
		t.Errorf("unset: %v %v", removed, err)
	}
	if removed, err := settings.Unset(ctx, d.Conn, "NDAY_GITHUB_TOKEN"); err != nil || removed {
		t.Errorf("unset again: %v %v", removed, err)
	}
	if _, err := settings.Unset(ctx, d.Conn, "NDAY_DATABASE_URL"); !errors.Is(err, settings.ErrUnknownKey) {
		t.Errorf("unset unknown: %v", err)
	}
}

func TestChecks(t *testing.T) {
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	for _, q := range []string{
		`INSERT INTO app_settings (key, value) VALUES ('nday_lower', 'x')`,
		`INSERT INTO app_settings (key, value) VALUES ('OTHER_KEY', 'x')`,
		`INSERT INTO app_settings (key, value) VALUES ('NDAY_', 'x')`,
		`INSERT INTO app_settings (key, value) VALUES ('NDAY_` + strings.Repeat("A", 61) + `', 'x')`,
		`INSERT INTO app_settings (key) VALUES ('NDAY_NEITHER')`,
		`INSERT INTO app_settings (key, value, secret) VALUES ('NDAY_BOTH', 'x', '\x01')`,
		`INSERT INTO app_settings (key, value) VALUES ('NDAY_LONG', repeat('x', 1025))`,
		`INSERT INTO app_settings (key, secret) VALUES ('NDAY_BIG', decode(repeat('00', 16385), 'hex'))`,
		`INSERT INTO app_settings (key, secret, hint) VALUES ('NDAY_HINT', '\x01', '123456789')`,
		`INSERT INTO admin_audit (actor_role, action, target_type, target_id, source) VALUES ('cli', 'settings.update', 'nope', 'x', 'cli')`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err == nil {
			t.Errorf("accepted: %.80s", q)
		}
	}
	for _, q := range []string{
		`INSERT INTO app_settings (key, value) VALUES ('NDAY_` + strings.Repeat("A", 60) + `', repeat('é', 1024))`,
		`INSERT INTO app_settings (key, secret, hint) VALUES ('NDAY_OK_SECRET', decode(repeat('00', 16384), 'hex'), '12345678')`,
		`INSERT INTO admin_audit (actor_role, action, target_type, target_id, source) VALUES ('cli', 'settings.update', 'setting', 'NDAY_DISCUSS', 'cli')`,
		`INSERT INTO admin_audit (actor_role, action, target_type, target_id, source) VALUES ('cli', 'x.draft.save', 'x_draft', '1', 'cli')`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Errorf("refused %.80s: %v", q, err)
		}
	}
}
