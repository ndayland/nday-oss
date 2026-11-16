// Package testutil provides isolated PostgreSQL schemas, fake HTTP
// transports and golden-file comparison for the Go tests.
//
// Database isolation: every NewDB call creates a brand-new schema with a
// unique name (go_test_<pid>_<nanos>_<random>) in the test database and
// returns a connection (and URL) whose search_path is that schema only, then
// drops it with CASCADE in t.Cleanup. Tests can therefore run in parallel,
// from several machines/people against the same server, and alongside the
// Python test suite (which uses the public schema).
//
// The server comes from NDAY_TEST_DATABASE_URL (default
// postgresql://nday:nday@127.0.0.1:54329/nday_test, the docker-compose
// container); the database name must contain "test" (same guard as the Python
// conftest) and is created if missing. If the server is unreachable the DB
// tests fail (they are not skipped), unless NDAY_TEST_SKIP_DB=1.
package testutil

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/db"
	"nday.land/nday/migrations"
)

// DefaultTestURL is used when NDAY_TEST_DATABASE_URL is not set.
const DefaultTestURL = "postgresql://nday:nday@127.0.0.1:54329/nday_test"

// RepoRoot returns the repository root (directory containing go.mod).
func RepoRoot() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

// TestURL returns the configured test database URL.
func TestURL() string {
	if u := os.Getenv("NDAY_TEST_DATABASE_URL"); u != "" {
		return u
	}
	return DefaultTestURL
}

var ensureOnce sync.Once
var ensureErr error

func ensureDatabase(ctx context.Context, base string) error {
	ensureOnce.Do(func() {
		cfg, err := pgx.ParseConfig(base)
		if err != nil {
			ensureErr = err
			return
		}
		name := cfg.Database
		if !strings.Contains(name, "test") {
			ensureErr = fmt.Errorf("refusing to use non-test database %q", name)
			return
		}
		// (retrying like Connect: the result is cached for the whole process,
		// so one "too many clients" here would fail every database test)
		conn, err := retryTooManyClients(ctx, func() (*pgx.Conn, error) { return pgx.ConnectConfig(ctx, cfg) })
		if err == nil {
			conn.Close(ctx)
			return
		}
		var pgErr *pgconn.PgError
		if !errors.As(err, &pgErr) || pgErr.Code != "3D000" { // invalid_catalog_name
			ensureErr = err
			return
		}
		admin := cfg.Copy()
		admin.Database = "postgres"
		ac, err := retryTooManyClients(ctx, func() (*pgx.Conn, error) { return pgx.ConnectConfig(ctx, admin) })
		if err != nil {
			ensureErr = err
			return
		}
		defer ac.Close(ctx)
		_, err = ac.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{name}.Sanitize())
		if errors.As(err, &pgErr) && pgErr.Code == "42P04" { // created concurrently
			err = nil
		}
		ensureErr = err
	})
	return ensureErr
}

// TestDB is an isolated schema.
type TestDB struct {
	Conn   *pgx.Conn
	URL    string // libpq URL selecting the schema via search_path
	Schema string
}

// NewDB creates an isolated, EMPTY schema (not migrated).
func NewDB(t testing.TB) *TestDB {
	t.Helper()
	if os.Getenv("NDAY_TEST_SKIP_DB") == "1" {
		t.Skip("NDAY_TEST_SKIP_DB=1")
	}
	ctx := context.Background()
	base := TestURL()
	if err := ensureDatabase(ctx, base); err != nil {
		t.Fatalf("test database: %v", err)
	}
	var rnd [4]byte
	_, _ = rand.Read(rnd[:])
	schema := fmt.Sprintf("go_test_%d_%d_%s", os.Getpid(), time.Now().UnixNano(), hex.EncodeToString(rnd[:]))
	// The admin connection is not held for the test's duration (many
	// packages run DB tests in parallel against max_connections=100).
	admin, err := Connect(ctx, base)
	if err != nil {
		t.Fatalf("connect %s: %v", redact(base), err)
	}
	_, err = admin.Exec(ctx, "CREATE SCHEMA "+schema)
	admin.Close(ctx)
	if err != nil {
		t.Fatalf("create schema: %v", err)
	}
	u := WithSearchPath(base, schema)
	conn, err := Connect(ctx, u)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() {
		conn.Close(ctx)
		admin, err := Connect(ctx, base)
		if err != nil {
			t.Errorf("drop schema %s: %v", schema, err)
			return
		}
		defer admin.Close(ctx)
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Errorf("drop schema %s: %v", schema, err)
		}
	})
	return &TestDB{Conn: conn, URL: u, Schema: schema}
}

// Connect is pgx.Connect, retrying for up to two minutes while the server
// answers "too many clients" (SQLSTATE 53300): parallel test packages can
// briefly exhaust max_connections.
func Connect(ctx context.Context, url string) (*pgx.Conn, error) {
	return retryTooManyClients(ctx, func() (*pgx.Conn, error) { return pgx.Connect(ctx, url) })
}

// Dial returns a dbpool.Options.Dial function that opens connections like
// the pool's default but retries, as Connect does, while the server
// answers "too many clients" (SQLSTATE 53300).
func Dial(cfg *pgx.ConnConfig) func(ctx context.Context) (*pgx.Conn, error) {
	return func(ctx context.Context) (*pgx.Conn, error) {
		return retryTooManyClients(ctx, func() (*pgx.Conn, error) { return pgx.ConnectConfig(ctx, cfg.Copy()) })
	}
}

// retryTooManyClients calls connect until it succeeds, fails with an error
// other than 53300, the two minute deadline passes or ctx is done.
func retryTooManyClients(ctx context.Context, connect func() (*pgx.Conn, error)) (*pgx.Conn, error) {
	deadline := time.Now().Add(2 * time.Minute)
	delay := 20 * time.Millisecond
	for {
		c, err := connect()
		var pgErr *pgconn.PgError
		if err == nil || !errors.As(err, &pgErr) || pgErr.Code != "53300" || time.Now().After(deadline) {
			return c, err
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, err
		case <-timer.C:
		}
		if delay < 500*time.Millisecond {
			delay *= 2
		}
	}
}

// NewMigratedDB creates an isolated schema with all migrations applied.
func NewMigratedDB(t testing.TB) *TestDB {
	t.Helper()
	d := NewDB(t)
	if _, err := db.Migrate(context.Background(), d.Conn, migrations.FS); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}

// WithSearchPath adds search_path=<schema> to a URL or keyword/value DSN
// (pgx sends unknown parameters as run-time parameters).
func WithSearchPath(base, schema string) string {
	if strings.HasPrefix(base, "postgres://") || strings.HasPrefix(base, "postgresql://") {
		u, err := url.Parse(base)
		if err == nil {
			q := u.Query()
			q.Set("search_path", schema)
			u.RawQuery = q.Encode()
			return u.String()
		}
	}
	return base + " search_path=" + schema
}

func redact(u string) string {
	if p, err := url.Parse(u); err == nil && p.User != nil {
		p.User = url.User(p.User.Username())
		return p.String()
	}
	return "(dsn)"
}

// Request is what a FakeTransport saw.
type Request struct {
	URL    string
	Header http.Header
}

// FakeTransport serves canned responses; it never touches the network.
type FakeTransport struct {
	mu       sync.Mutex
	Requests []Request
	// Handler returns status, headers and body for a request.
	Handler func(r *http.Request) (int, http.Header, []byte, error)
}

// RoundTrip implements http.RoundTripper.
func (f *FakeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.Requests = append(f.Requests, Request{URL: r.URL.String(), Header: r.Header.Clone()})
	f.mu.Unlock()
	status, hdr, body, err := f.Handler(r)
	if err != nil {
		return nil, err
	}
	if hdr == nil {
		hdr = http.Header{}
	}
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:        hdr,
		Body:          ioNopCloser(body),
		ContentLength: int64(len(body)),
		Request:       r,
		Proto:         "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
	}, nil
}

// Serve returns a FakeTransport answering every request with 200 and body.
func Serve(body []byte) *FakeTransport {
	return &FakeTransport{Handler: func(*http.Request) (int, http.Header, []byte, error) {
		return 200, http.Header{"Content-Type": {"application/json"}}, body, nil
	}}
}

// ReadFile reads a file relative to the repository root.
func ReadFile(t testing.TB, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(RepoRoot(), rel))
	if err != nil {
		t.Fatal(err)
	}
	return b
}
