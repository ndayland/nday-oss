// Package db opens connections and runs the SQL migrations (port of db.py).
//
// Migrations are the files migrations/NNNN_description.sql, embedded into the
// binary (package nday.land/nday/migrations), applied in lexical order, each in
// its own transaction, and recorded in schema_migrations(version text PRIMARY
// KEY, applied_at timestamptz) with version = file name without ".sql" — the
// exact bookkeeping of the Python runner, so a database migrated by Python is
// recognised as up to date and vice versa. Concurrent runs serialise on the
// same session advisory lock id as Python (0x6E646179).
package db

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/config"
	"nday.land/nday/migrations"
)

// MigrationLockID is Python's MIGRATION_LOCK_ID.
const MigrationLockID int64 = 0x6E646179

// migrationRe is Python's MIGRATION_RE = r"^(\d{4})_[\w-]+\.sql$". Python's \w
// and \d are Unicode-aware; the shipped file names are ASCII, so the ASCII
// classes are used here (a non-ASCII migration name would be skipped by Go
// but applied by Python — do not create one).
var migrationRe = regexp.MustCompile(`^([0-9]{4})_[A-Za-z0-9_-]+\.sql$`)

// Connect opens a single connection (Python: psycopg autocommit connection;
// a pgx.Conn outside an explicit transaction is autocommit too). Any libpq
// URL/keyword string works, including postgresql:///nday?host=/var/run/postgresql.
func Connect(ctx context.Context, url string) (*pgx.Conn, error) {
	return pgx.Connect(ctx, url)
}

// Migration is one migration file.
type Migration struct {
	Version string // file name without .sql, e.g. "0001_init"
	SQL     string
}

// MigrationsFS returns the migration source: NDAY_MIGRATIONS_DIR if set (as
// Python honours it), otherwise the embedded copy.
func MigrationsFS() fs.FS {
	if dir, ok := config.MigrationsDir(); ok {
		return os.DirFS(dir)
	}
	return migrations.FS
}

// ListMigrations returns the migrations in fsys, sorted by file name.
func ListMigrations(fsys fs.FS) ([]Migration, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		if migrationRe.MatchString(e.Name()) {
			names = append(names, e.Name())
		}
	}
	sort.Strings(names)
	out := make([]Migration, 0, len(names))
	for _, n := range names {
		b, err := fs.ReadFile(fsys, n)
		if err != nil {
			return nil, err
		}
		out = append(out, Migration{Version: strings.TrimSuffix(n, ".sql"), SQL: string(b)})
	}
	return out, nil
}

// Migrate applies pending migrations from fsys and returns the versions
// applied by this call (empty when up to date). conn must not be inside a
// transaction.
func Migrate(ctx context.Context, conn *pgx.Conn, fsys fs.FS) (applied []string, err error) {
	list, err := ListMigrations(fsys)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", MigrationLockID); err != nil {
		return nil, err
	}
	defer func() {
		// Like Python's finally; a failed unlock must not mask the original error.
		if _, uerr := conn.Exec(context.WithoutCancel(ctx), "SELECT pg_advisory_unlock($1)", MigrationLockID); uerr != nil && err == nil {
			err = uerr
		}
	}()
	if _, err := conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
                   version    text PRIMARY KEY,
                   applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		return nil, err
	}
	done := map[string]bool{}
	rows, err := conn.Query(ctx, "SELECT version FROM schema_migrations")
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return nil, err
		}
		done[v] = true
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	applied = []string{}
	for _, m := range list {
		if done[m.Version] {
			continue
		}
		err := pgx.BeginFunc(ctx, conn, func(tx pgx.Tx) error {
			// No arguments: pgx uses the simple query protocol, so a file with
			// several statements runs as one batch, like psycopg's execute(sql).
			if _, err := tx.Exec(ctx, m.SQL); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", m.Version)
			return err
		})
		if err != nil {
			return applied, fmt.Errorf("migration %s: %w", m.Version, err)
		}
		applied = append(applied, m.Version)
	}
	return applied, nil
}
