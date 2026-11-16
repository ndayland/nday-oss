package settings

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Sources reported by Snapshot.Source.
const (
	SourceDB      = "db"
	SourceEnv     = "env"
	SourceDefault = "default"
)

// secretText holds a decrypted secret behind a pointer: fmt prints a
// nested pointer as an address, and the type itself never formats its
// content.
type secretText struct{ s string }

func newSecret(s string) *secretText { return &secretText{s} }

func (*secretText) String() string             { return "(secret)" }
func (*secretText) GoString() string           { return "(secret)" }
func (*secretText) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte("(secret)")) }
func (*secretText) LogValue() slog.Value       { return slog.StringValue("(secret)") }
func (t *secretText) reveal() string {
	if t == nil {
		return ""
	}
	return t.s
}

type entry struct {
	secret    bool
	usable    bool // value can be served (plain, or a secret that opened)
	value     string
	sec       *secretText
	hint      string
	updatedAt time.Time
}

// Snapshot is an immutable view of app_settings, secrets opened with the
// master key. Its zero value (or nil) is an empty snapshot: every lookup
// goes to the environment. It never formats or logs a secret.
type Snapshot struct {
	entries  map[string]entry
	warnings []string
}

// NewSnapshot builds a snapshot from rows (Load) and the master key (nil:
// none configured). Rows of unregistered keys, of the wrong kind, or
// secrets that cannot be opened are not served; each such row adds a
// warning that names only the key and the reason.
func NewSnapshot(rows []Row, k *Key) *Snapshot {
	s := &Snapshot{entries: map[string]entry{}}
	warn := func(key, why string) { s.warnings = append(s.warnings, key+": "+why) }
	for _, r := range rows {
		d, ok := Lookup(r.Key)
		if !ok {
			warn(safeKey(r.Key), "stored in app_settings but not a registered setting; ignored")
			continue
		}
		e := entry{secret: d.Secret, hint: r.Hint, updatedAt: r.UpdatedAt}
		switch {
		case d.Secret && r.Value != nil:
			warn(r.Key, "stored as plain text but it is a secret; ignored (using the environment)")
		case !d.Secret && r.Value == nil:
			warn(r.Key, "stored encrypted but it is not a secret; ignored (using the environment)")
		case !d.Secret:
			e.value, e.usable = strings.TrimSpace(*r.Value), true
		case k == nil:
			warn(r.Key, "stored encrypted but "+EnvKey+" is not set; using the environment")
		default:
			pt, err := k.open(r.Key, r.Sealed)
			if err != nil {
				warn(r.Key, "stored secret "+err.Error()+"; using the environment")
				break
			}
			e.sec, e.usable = newSecret(strings.TrimSpace(string(pt))), true
			clear(pt)
		}
		s.entries[r.Key] = e
	}
	return s
}

// LoadSnapshot is Load + NewSnapshot.
func LoadSnapshot(ctx context.Context, db DB, k *Key) (*Snapshot, error) {
	rows, err := Load(ctx, db)
	if err != nil {
		return nil, err
	}
	return NewSnapshot(rows, k), nil
}

// Warnings lists the rows that are not served (key and reason only).
func (s *Snapshot) Warnings() []string {
	if s == nil {
		return nil
	}
	return append([]string(nil), s.warnings...)
}

func (s *Snapshot) get(key string) (entry, bool) {
	if s == nil {
		return entry{}, false
	}
	e, ok := s.entries[key]
	return e, ok
}

// served returns the value the database provides for key, if any.
func (s *Snapshot) served(key string) (string, bool) {
	if _, reg := Lookup(key); !reg {
		return "", false
	}
	e, ok := s.get(key)
	if !ok || !e.usable {
		return "", false
	}
	if e.secret {
		return e.sec.reveal(), true
	}
	return e.value, true
}

// Lookup returns the layered lookup: a registered key the snapshot serves
// comes from the database, everything else from env (nil env: no
// environment). The result is safe for concurrent use.
func (s *Snapshot) Lookup(env func(string) (string, bool)) func(string) (string, bool) {
	return func(key string) (string, bool) {
		if v, ok := s.served(key); ok {
			return v, true
		}
		if env == nil {
			return "", false
		}
		return env(key)
	}
}

// With returns a copy of s in which key (registered, plain) is served with
// value, for validating a candidate configuration before it is written.
func (s *Snapshot) With(key, value string) *Snapshot {
	c := s.clone()
	if d, ok := Lookup(key); ok {
		e := entry{secret: d.Secret, usable: true, updatedAt: time.Now().UTC()}
		if d.Secret {
			e.sec, e.hint = newSecret(value), Hint(value)
		} else {
			e.value = value
		}
		c.entries[key] = e
	}
	return c
}

func (s *Snapshot) clone() *Snapshot {
	c := &Snapshot{entries: map[string]entry{}}
	if s != nil {
		for k, e := range s.entries {
			c.entries[k] = e
		}
		c.warnings = append(c.warnings, s.warnings...)
	}
	return c
}

// Without returns a copy of s in which key is not served (as after Unset).
func (s *Snapshot) Without(key string) *Snapshot {
	c := s.clone()
	delete(c.entries, key)
	return c
}

// Has reports whether a row for key is stored (even one that cannot be
// served; Source tells whether it is).
func (s *Snapshot) Has(key string) bool {
	_, ok := s.get(key)
	return ok
}

// Source says where the effective value of key comes from: "db" when the
// snapshot serves it, "env" when env has a non-blank value, else
// "default".
func (s *Snapshot) Source(key string, env func(string) (string, bool)) string {
	if _, ok := s.served(key); ok {
		return SourceDB
	}
	if env != nil {
		if v, ok := env(key); ok && strings.TrimSpace(v) != "" {
			return SourceEnv
		}
	}
	return SourceDefault
}

// Value returns the stored value of a plain (non-secret) setting; never a
// secret.
func (s *Snapshot) Value(key string) (string, bool) {
	e, ok := s.get(key)
	if !ok || e.secret || !e.usable {
		return "", false
	}
	return e.value, true
}

// Hint returns the stored hint of a secret ("" if none).
func (s *Snapshot) Hint(key string) string {
	e, _ := s.get(key)
	return e.hint
}

// UpdatedAt returns when the row of key was last written.
func (s *Snapshot) UpdatedAt(key string) (time.Time, bool) {
	e, ok := s.get(key)
	return e.updatedAt, ok
}

func (s Snapshot) summary() string {
	return fmt.Sprintf("settings.Snapshot(%d rows, %d warnings)", len(s.entries), len(s.warnings))
}

// The formatting methods have value receivers so that a Snapshot value is
// redacted as well as a *Snapshot (a nil *Snapshot prints as <nil>).

// String shows only counts.
func (s Snapshot) String() string { return s.summary() }

// GoString shows only counts.
func (s Snapshot) GoString() string { return s.summary() }

// Format shows only counts, for every verb.
func (s Snapshot) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(s.summary())) }

// LogValue shows only counts.
func (s Snapshot) LogValue() slog.Value { return slog.StringValue(s.summary()) }
