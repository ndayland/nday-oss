package settings

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"
)

func newKey(t *testing.T) (*Key, string) {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	s := base64.StdEncoding.EncodeToString(b)
	k, err := ParseKey(s)
	if err != nil || k == nil {
		t.Fatalf("ParseKey: %v", err)
	}
	return k, s
}

func TestRegistry(t *testing.T) {
	all := Defs()
	if len(all) != 63 {
		t.Fatalf("%d settings, want 63", len(all))
	}
	n := map[string]int{}
	secrets := 0
	gi := 0
	for _, d := range all {
		n[d.Group]++
		if d.Secret {
			secrets++
		}
		for gi < len(Groups) && Groups[gi] != d.Group {
			gi++
		}
		if gi == len(Groups) {
			t.Fatalf("%s: groups out of order", d.Key)
		}
		if got, ok := Lookup(d.Key); !ok || got != d {
			t.Errorf("Lookup(%s) = %v %v", d.Key, got, ok)
		}
		if d.Restart != (d.Key == "NDAY_DISCUSS") {
			t.Errorf("%s: Restart=%v", d.Key, d.Restart)
		}
	}
	if n[GroupDiscuss] != 31 || n[GroupCollectors] != 8 || n[GroupAuth] != 20 || n[GroupHot] != 4 || secrets != 6 {
		t.Errorf("groups %v, secrets %d", n, secrets)
	}
	for _, k := range []string{"NDAY_DATABASE_URL", "NDAY_AUTH_SECRET", "NDAY_AUTH_SECRET_PREVIOUS", "NDAY_PUBLIC_URL",
		"NDAY_AUTH_RP_ID", "NDAY_AUTH_ORIGINS", "NDAY_DISCUSS_DB_POOL_SIZE", "NDAY_AUTH_APPLE_KEY_FILE", EnvKey} {
		if _, ok := Lookup(k); ok {
			t.Errorf("%s must stay environment-only", k)
		}
	}
	if len(GroupDefs(GroupCollectors)) != 8 {
		t.Error("GroupDefs")
	}
}

func TestParseKey(t *testing.T) {
	if k, err := ParseKey("  "); k != nil || err != nil {
		t.Fatalf("empty: %v %v", k, err)
	}
	b := make([]byte, 40)
	_, _ = rand.Read(b)
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if k, err := ParseKey(" " + enc.EncodeToString(b) + "\n"); err != nil || k == nil {
			t.Errorf("encoding: %v", err)
		}
	}
	short := base64.StdEncoding.EncodeToString(b[:31])
	if _, err := ParseKey(short); err == nil || strings.Contains(err.Error(), short) || !strings.Contains(err.Error(), EnvKey) {
		t.Errorf("short key: %v", err)
	}
	if _, err := ParseKey("not*base64!"); err == nil || strings.Contains(err.Error(), "not*base64") {
		t.Errorf("bad key: %v", err)
	}
	// low entropy: all zeros, a repeated short pattern, an ASCII word (fewer
	// than 16 distinct byte values) are refused without echoing the value
	for _, raw := range [][]byte{make([]byte, 32), []byte(strings.Repeat("abcdefgh", 4)),
		[]byte("passwordpasswordpasswordpassword"), append(make([]byte, 40), 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14)} {
		in := base64.StdEncoding.EncodeToString(raw)
		k, err := ParseKey(in)
		if err == nil || k != nil || strings.Contains(err.Error(), in) || !strings.Contains(err.Error(), "openssl rand -base64 32") ||
			!strings.Contains(err.Error(), "does not look random") {
			t.Errorf("low-entropy key accepted or bad error: %v", err)
		}
	}
	// 16 distinct values is enough
	sixteen := make([]byte, 32)
	for i := range sixteen {
		sixteen[i] = byte(i % 16)
	}
	if k, err := ParseKey(base64.StdEncoding.EncodeToString(sixteen)); err != nil || k == nil {
		t.Errorf("16 distinct bytes refused: %v", err)
	}
	// the same material gives the same key (HKDF is deterministic)
	s := base64.StdEncoding.EncodeToString(b)
	k1, _ := ParseKey(s)
	k2, _ := ParseKey(base64.RawURLEncoding.EncodeToString(b))
	ct, err := k1.seal("NDAY_GITHUB_TOKEN", []byte("hello"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := k2.open("NDAY_GITHUB_TOKEN", ct); err != nil || string(pt) != "hello" {
		t.Errorf("same material: %q %v", pt, err)
	}
	if k, err := KeyFromEnv(func(string) (string, bool) { return "", false }); k != nil || err != nil {
		t.Error("KeyFromEnv unset")
	}
}

func TestSealOpen(t *testing.T) {
	k, _ := newKey(t)
	other, _ := newKey(t)
	const secret = "ghp_THIS-IS-THE-SECRET-1234"
	ct, err := k.seal("NDAY_GITHUB_TOKEN", []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	if ct[0] != 1 || len(ct) != 1+12+len(secret)+16 || bytes.Contains(ct, []byte(secret)) {
		t.Fatalf("format: %d bytes", len(ct))
	}
	ct2, _ := k.seal("NDAY_GITHUB_TOKEN", []byte(secret))
	if bytes.Equal(ct, ct2) {
		t.Error("nonce reused")
	}
	if pt, err := k.open("NDAY_GITHUB_TOKEN", ct); err != nil || string(pt) != secret {
		t.Fatalf("round trip: %v", err)
	}
	// AAD: the ciphertext of one key does not open as another key
	if _, err := k.open("NDAY_X_BEARER_TOKEN", ct); err == nil {
		t.Error("moved ciphertext opened")
	}
	if _, err := other.open("NDAY_GITHUB_TOKEN", ct); err == nil {
		t.Error("wrong master key opened")
	}
	bad := append([]byte(nil), ct...)
	bad[len(bad)-1] ^= 1
	if _, err := k.open("NDAY_GITHUB_TOKEN", bad); err == nil {
		t.Error("tampered ciphertext opened")
	}
	bad = append([]byte(nil), ct...)
	bad[0] = 2
	if _, err := k.open("NDAY_GITHUB_TOKEN", bad); err == nil {
		t.Error("unknown version opened")
	}
	if _, err := k.open("NDAY_GITHUB_TOKEN", ct[:10]); err == nil {
		t.Error("short opened")
	}
	var nk *Key
	if _, err := nk.seal("NDAY_GITHUB_TOKEN", []byte("x")); !errors.Is(err, ErrNoKey) {
		t.Error("nil key sealed")
	}
}

func TestHint(t *testing.T) {
	for in, want := range map[string]string{
		"ghp_abcdefgh1234abcdefgh1234": "1234",
		"ghp_abcdefgh1234":             "", // 16 characters: too short for a hint
		"short-12345-12345-12345":      "", // 23 characters
		"exactly-24-characters-xy":     "s-xy",
		"-----BEGIN PRIVATE KEY-----\nMIGT\n-----END PRIVATE KEY-----": "",
		"ééééééééééééééééééééàbcd":                                     "àbcd",
	} {
		if got := Hint(in); got != want {
			t.Errorf("Hint(%q) = %q want %q", in, got, want)
		}
	}
}

func str(s string) *string { return &s }

func TestSnapshotLayers(t *testing.T) {
	k, _ := newKey(t)
	wrong, _ := newKey(t)
	const tok = "SECRET-github-token-value"
	ct, _ := k.seal("NDAY_GITHUB_TOKEN", []byte(tok))
	moved, _ := k.seal("NDAY_X_BEARER_TOKEN", []byte("SECRET-moved-x-token"))
	at := time.Date(2026, 11, 14, 1, 2, 3, 0, time.UTC)
	rows := []Row{
		{Key: "NDAY_DISCUSS_POST_BURST", Value: str(" 9 "), UpdatedAt: at},
		{Key: "NDAY_GITHUB_TOKEN", Sealed: ct, Hint: "alue", UpdatedAt: at},
		{Key: "NDAY_AUTH_GOOGLE_CLIENT_SECRET", Sealed: moved, UpdatedAt: at}, // sealed for another key
		{Key: "NDAY_DATABASE_URL", Value: str("postgres://evil")},             // not registered
		{Key: "NDAY_AUTH_SECRET", Value: str("db-auth-secret")},               // not registered
		{Key: "NDAY_X_BEARER_TOKEN", Value: str("plain-secret")},              // wrong kind
	}
	env := map[string]string{
		"NDAY_DISCUSS_POST_BURST":        "5",
		"NDAY_GITHUB_TOKEN":              "env-token",
		"NDAY_AUTH_GOOGLE_CLIENT_SECRET": "env-google",
		"NDAY_DATABASE_URL":              "postgres://env",
		"NDAY_AUTH_SECRET":               "env-auth-secret",
		"NDAY_DISCUSS_POST_DAILY":        "70",
		"NDAY_GHSA_MAX_REQUESTS":         "  ",
	}
	envf := func(key string) (string, bool) { v, ok := env[key]; return v, ok }
	s := NewSnapshot(rows, k)
	get := s.Lookup(envf)
	for key, want := range map[string]string{
		"NDAY_DISCUSS_POST_BURST":        "9",
		"NDAY_GITHUB_TOKEN":              tok,
		"NDAY_AUTH_GOOGLE_CLIENT_SECRET": "env-google",
		"NDAY_DATABASE_URL":              "postgres://env",
		"NDAY_AUTH_SECRET":               "env-auth-secret",
		"NDAY_DISCUSS_POST_DAILY":        "70",
	} {
		if v, ok := get(key); !ok || v != want {
			t.Errorf("%s = %q %v, want %q", key, v, ok, want)
		}
	}
	if _, ok := get("NDAY_X_BEARER_TOKEN"); ok {
		t.Error("wrong-kind row served")
	}
	for key, want := range map[string]string{
		"NDAY_DISCUSS_POST_BURST": SourceDB, "NDAY_GITHUB_TOKEN": SourceDB,
		"NDAY_AUTH_GOOGLE_CLIENT_SECRET": SourceEnv, "NDAY_DISCUSS_POST_DAILY": SourceEnv,
		"NDAY_GHSA_MAX_REQUESTS": SourceDefault, "NDAY_X_BEARER_TOKEN": SourceDefault,
	} {
		if got := s.Source(key, envf); got != want {
			t.Errorf("Source(%s) = %s want %s", key, got, want)
		}
	}
	if !s.Has("NDAY_X_BEARER_TOKEN") || !s.Has("NDAY_GITHUB_TOKEN") || s.Has("NDAY_DATABASE_URL") || s.Has("NDAY_GHSA_MAX_REQUESTS") {
		t.Error("Has")
	}
	if v, ok := s.Value("NDAY_DISCUSS_POST_BURST"); !ok || v != "9" {
		t.Error("Value plain")
	}
	if _, ok := s.Value("NDAY_GITHUB_TOKEN"); ok {
		t.Error("Value returned a secret")
	}
	if s.Hint("NDAY_GITHUB_TOKEN") != "alue" {
		t.Error("Hint")
	}
	if u, ok := s.UpdatedAt("NDAY_GITHUB_TOKEN"); !ok || !u.Equal(at) {
		t.Error("UpdatedAt")
	}
	w := strings.Join(s.Warnings(), "\n")
	for _, want := range []string{"NDAY_AUTH_GOOGLE_CLIENT_SECRET: stored secret cannot be decrypted",
		"NDAY_DATABASE_URL: stored in app_settings but not a registered setting", "NDAY_X_BEARER_TOKEN: stored as plain text"} {
		if !strings.Contains(w, want) {
			t.Errorf("warnings lack %q:\n%s", want, w)
		}
	}
	if strings.Contains(w, "evil") || strings.Contains(w, "plain-secret") || strings.Contains(w, "SECRET-") {
		t.Errorf("warnings leak a value:\n%s", w)
	}

	// wrong master key, and no master key: the secret falls back to env
	for name, kk := range map[string]*Key{"wrong": wrong, "none": nil} {
		s2 := NewSnapshot(rows, kk)
		if v, _ := s2.Lookup(envf)("NDAY_GITHUB_TOKEN"); v != "env-token" {
			t.Errorf("%s key: %q", name, v)
		}
		if s2.Source("NDAY_GITHUB_TOKEN", envf) != SourceEnv {
			t.Errorf("%s key: source", name)
		}
		if !strings.Contains(strings.Join(s2.Warnings(), "\n"), "NDAY_GITHUB_TOKEN: stored ") {
			t.Errorf("%s key: no warning", name)
		}
		if v, ok := s2.Lookup(envf)("NDAY_DISCUSS_POST_BURST"); !ok || v != "9" {
			t.Errorf("%s key: plain value lost", name)
		}
	}

	// nil snapshot and nil env
	var ns *Snapshot
	if v, ok := ns.Lookup(envf)("NDAY_DISCUSS_POST_BURST"); !ok || v != "5" {
		t.Error("nil snapshot")
	}
	if _, ok := s.Lookup(nil)("NDAY_DATABASE_URL"); ok {
		t.Error("nil env")
	}

	// With / Without
	c := s.With("NDAY_DISCUSS_POST_DAILY", "3").Without("NDAY_DISCUSS_POST_BURST")
	if v, _ := c.Lookup(envf)("NDAY_DISCUSS_POST_DAILY"); v != "3" {
		t.Error("With")
	}
	if v, _ := c.Lookup(envf)("NDAY_DISCUSS_POST_BURST"); v != "5" {
		t.Error("Without")
	}
	if v, _ := s.Lookup(envf)("NDAY_DISCUSS_POST_DAILY"); v != "70" {
		t.Error("With changed the original")
	}
}

func TestNoLeak(t *testing.T) {
	k, keyText := newKey(t)
	const tok = "SECRET-never-printed-0123456789"
	ct, _ := k.seal("NDAY_GITHUB_TOKEN", []byte(tok))
	s := NewSnapshot([]Row{{Key: "NDAY_GITHUB_TOKEN", Sealed: ct}}, k)
	var logs bytes.Buffer
	lg := slog.New(slog.NewTextHandler(&logs, nil))
	lg.Info("x", "snap", s, "key", k, "snapv", *s)
	lg.Info("y", slog.Any("snap", s))
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("z", "snap", s, "key", k)
	out := fmt.Sprintf("%v %+v %#v %s %q %x | %v %+v %#v %s %x | %v %+v %#v | %v",
		s, s, s, s, s, s, k, k, k, k, k, *s, *s, *s, []any{s, k}) + logs.String()
	for _, leak := range []string{tok, "never-printed", keyText} {
		if strings.Contains(out, leak) {
			t.Fatalf("formatting leaked %q:\n%s", leak, out)
		}
	}
	if !strings.Contains(out, "settings.Snapshot(1 rows, 0 warnings)") || !strings.Contains(out, "settings.Key(redacted)") {
		t.Errorf("unexpected format:\n%s", out)
	}
	e := s.entries["NDAY_GITHUB_TOKEN"]
	if got := fmt.Sprintf("%v %+v %#v", e, e, e.sec); strings.Contains(got, tok) {
		t.Errorf("entry leaked: %s", got)
	}
}

func TestCheckValue(t *testing.T) {
	if v, err := CheckValue("NDAY_DISCUSS_POST_BURST", "  7 \n"); err != nil || v != "7" {
		t.Errorf("trim: %q %v", v, err)
	}
	for _, c := range []struct {
		key, val string
		err      error
	}{
		{"NDAY_DATABASE_URL", "x", ErrUnknownKey},
		{"NDAY_GITHUB_TOKEN", "x", ErrSecretKey},
		{"NDAY_DISCUSS", "   ", ErrEmpty},
	} {
		if _, err := CheckValue(c.key, c.val); !errors.Is(err, c.err) {
			t.Errorf("%s: %v", c.key, err)
		}
	}
	if _, err := CheckValue("NDAY_DISCUSS", "a\nb"); err == nil || strings.Contains(err.Error(), "a\nb") {
		t.Errorf("control: %v", err)
	}
	if _, err := CheckValue("NDAY_DISCUSS", strings.Repeat("x", MaxValueLen+1)); err == nil {
		t.Error("too long accepted")
	}
	if _, err := CheckValue("ghp_secretvalue", "x"); err == nil || strings.Contains(err.Error(), "ghp_") {
		t.Errorf("unknown key echoed: %v", err)
	}
}
