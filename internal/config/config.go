// Package config reads configuration from environment variables, optionally
// seeded from a .env file in the working directory (port of config.py).
package config

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"unicode/utf8"

	"nday.land/nday/internal/pystr"
)

// LoadDotenv is Python's load_dotenv: KEY=VALUE lines; blank lines, lines
// starting with '#' and lines without '=' are skipped; key and value are
// stripped, then the value is stripped of double-quote and then of
// single-quote characters (Python: .strip('"').strip("'"));
// an existing environment variable (even empty) is never overridden.
// A missing file is not an error. path "" means ./.env.
func LoadDotenv(path string) error {
	if path == "" {
		path = ".env"
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return nil // Python: `if not path.is_file(): return`
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !utf8.Valid(data) {
		return fmt.Errorf("%s: not valid UTF-8", path)
	}
	// Python read_text("utf-8") keeps a BOM as U+FEFF (not whitespace), so a
	// BOM-prefixed first line yields a key starting with U+FEFF; same here.
	for _, line := range pystr.Splitlines(string(data)) {
		line = pystr.Strip(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		key, value, _ := strings.Cut(line, "=")
		key = pystr.Strip(key)
		value = pystr.StripChars(pystr.StripChars(pystr.Strip(value), `"`), `'`)
		if _, ok := os.LookupEnv(key); !ok {
			if err := os.Setenv(key, value); err != nil {
				return err
			}
		}
	}
	return nil
}

// ErrNoDatabaseURL mirrors Python's RuntimeError message.
var ErrNoDatabaseURL = errors.New("NDAY_DATABASE_URL is not set (see .env.example)")

// DatabaseURL is Python's database_url(): loads ./.env, then reads NDAY_DATABASE_URL.
func DatabaseURL() (string, error) {
	if err := LoadDotenv(""); err != nil {
		return "", err
	}
	url := os.Getenv("NDAY_DATABASE_URL")
	if url == "" {
		return "", ErrNoDatabaseURL
	}
	return url, nil
}

// MigrationsDir returns NDAY_MIGRATIONS_DIR when set. Python defaults to the
// repository's migrations/ directory; the Go binary embeds that directory
// instead and only reads from disk when this override is set.
func MigrationsDir() (string, bool) {
	d, ok := os.LookupEnv("NDAY_MIGRATIONS_DIR")
	return d, ok && d != ""
}
