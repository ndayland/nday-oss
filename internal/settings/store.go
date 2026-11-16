package settings

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is the database handle (*pgx.Conn, pgx.Tx).
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Limits, as in the app_settings CHECKs.
const (
	MaxValueLen  = 1024  // characters of a plain value
	MaxSealedLen = 16384 // bytes of a sealed secret
	// MaxSecretLen is the longest secret (bytes) that still fits sealed.
	MaxSecretLen = MaxSealedLen - 1 - nonceLen - 16
	MaxHintLen   = 8
	// hintChars is how many trailing characters of a secret make its hint.
	hintChars = 4
	// minHintSecret: shorter secrets get no hint (it would reveal too much).
	minHintSecret = 24
)

// Errors of the write functions (they never contain the value).
var (
	ErrUnknownKey = errors.New("settings: not a registered setting")
	ErrSecretKey  = errors.New("settings: this setting is a secret (use SetSecret)")
	ErrPlainKey   = errors.New("settings: this setting is not a secret (use Set)")
	ErrEmpty      = errors.New("settings: empty value (use Unset to clear a setting)")
)

// Row is one app_settings row as stored. Exactly one of Value and Sealed
// is set; Sealed is ciphertext (never the secret itself).
type Row struct {
	Key       string
	Value     *string
	Sealed    []byte
	Hint      string
	UpdatedAt time.Time
}

// IsSecret reports whether the row holds a sealed secret.
func (r Row) IsSecret() bool { return r.Value == nil }

// Lock serialises read-modify-write of app_settings until the end of the
// caller's transaction (db must be a pgx.Tx): Load after it sees the latest
// committed rows.
func Lock(ctx context.Context, db DB) error {
	_, err := db.Exec(ctx, `LOCK TABLE app_settings IN SHARE ROW EXCLUSIVE MODE`)
	return err
}

// Load reads every stored row, by key (rows of unregistered keys included;
// Snapshot ignores them).
func Load(ctx context.Context, db DB) ([]Row, error) {
	rows, err := db.Query(ctx, `SELECT key, value, secret, coalesce(hint, ''), updated_at FROM app_settings ORDER BY key`)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, func(r pgx.CollectableRow) (Row, error) {
		var x Row
		err := r.Scan(&x.Key, &x.Value, &x.Sealed, &x.Hint, &x.UpdatedAt)
		x.UpdatedAt = x.UpdatedAt.UTC()
		return x, err
	})
}

func def(key string, secret bool) error {
	d, ok := Lookup(key)
	switch {
	case !ok:
		return fmt.Errorf("%w: %s", ErrUnknownKey, safeKey(key))
	case d.Secret && !secret:
		return fmt.Errorf("%w: %s", ErrSecretKey, key)
	case !d.Secret && secret:
		return fmt.Errorf("%w: %s", ErrPlainKey, key)
	}
	return nil
}

// safeKey is key for an error message when it is a plausible key name, else
// a placeholder (an unknown "key" might be a value pasted in the wrong
// place).
func safeKey(key string) string {
	if len(key) <= 70 && strings.HasPrefix(key, "NDAY_") && strings.Trim(key[5:], "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_") == "" {
		return key
	}
	return "(invalid key name)"
}

// CheckValue validates a plain value as Set stores it (after trimming):
// registered non-secret key, non-empty, at most MaxValueLen characters,
// valid UTF-8 without control characters. It returns the trimmed value.
func CheckValue(key, value string) (string, error) {
	if err := def(key, false); err != nil {
		return "", err
	}
	v := strings.TrimSpace(value)
	if v == "" {
		return "", fmt.Errorf("%w: %s", ErrEmpty, key)
	}
	if !utf8.ValidString(v) || utf8.RuneCountInString(v) > MaxValueLen || strings.IndexFunc(v, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("settings: %s must be one line of at most %d characters", key, MaxValueLen)
	}
	return v, nil
}

// Set stores a plain setting (trimmed; see CheckValue). changed is false
// when the stored value was already the same (the row is left untouched).
func Set(ctx context.Context, db DB, key, value string) (changed bool, err error) {
	v, err := CheckValue(key, value)
	if err != nil {
		return false, err
	}
	tag, err := db.Exec(ctx, `INSERT INTO app_settings (key, value) VALUES ($1, $2)
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, secret = NULL, hint = NULL, updated_at = now()
        WHERE app_settings.value IS DISTINCT FROM EXCLUDED.value`, key, v)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// Hint is the hint stored with a secret: its last 4 characters when it is
// at least 24 characters long and not a PEM block, else "".
func Hint(plaintext string) string {
	if strings.Contains(plaintext, "-----BEGIN") || utf8.RuneCountInString(plaintext) < minHintSecret {
		return ""
	}
	r := []rune(plaintext)
	h := string(r[len(r)-hintChars:])
	if strings.IndexFunc(h, func(c rune) bool { return unicode.IsControl(c) || unicode.IsSpace(c) }) >= 0 {
		return ""
	}
	return h
}

// SetSecret seals plaintext (trimmed) with k and stores it with its Hint.
// It needs a master key (ErrNoKey otherwise). Errors never contain the
// secret.
func SetSecret(ctx context.Context, db DB, key, plaintext string, k *Key) error {
	if err := def(key, true); err != nil {
		return err
	}
	v := strings.TrimSpace(plaintext)
	if v == "" {
		return fmt.Errorf("%w: %s", ErrEmpty, key)
	}
	if !utf8.ValidString(v) || len(v) > MaxSecretLen || strings.ContainsRune(v, 0) {
		return fmt.Errorf("settings: %s must be valid text of at most %d bytes", key, MaxSecretLen)
	}
	sealed, err := k.seal(key, []byte(v))
	if err != nil {
		return fmt.Errorf("settings: %s: %w", key, err)
	}
	var hint *string
	if h := Hint(v); h != "" {
		hint = &h
	}
	_, err = db.Exec(ctx, `INSERT INTO app_settings (key, secret, hint) VALUES ($1, $2, $3)
        ON CONFLICT (key) DO UPDATE SET value = NULL, secret = EXCLUDED.secret, hint = EXCLUDED.hint, updated_at = now()`,
		key, sealed, hint)
	if err != nil {
		// (a PgError's text never carries parameters; only ciphertext was sent)
		return fmt.Errorf("settings: storing %s: %w", key, err)
	}
	return nil
}

// Unset deletes the row of a registered key (the environment or the
// default applies again). removed is false when there was no row.
func Unset(ctx context.Context, db DB, key string) (removed bool, err error) {
	if _, ok := Lookup(key); !ok {
		return false, fmt.Errorf("%w: %s", ErrUnknownKey, safeKey(key))
	}
	tag, err := db.Exec(ctx, `DELETE FROM app_settings WHERE key = $1`, key)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}
