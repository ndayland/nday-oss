package db_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"

	"nday.land/nday/internal/db"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/migrations"
)

func TestMigrationAppliesCleanly(t *testing.T) {
	t.Parallel()
	d := testutil.NewDB(t)
	ctx := context.Background()
	applied, err := db.Migrate(ctx, d.Conn, migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(applied, ",") != "0001_init,0002_vuln_state,0003_vuln_state_mat,0004_auth,0005_discuss,0006_stats,0007_admin,0008_xposts,0009_classify,0010_follows,0011_tags,0012_xdrafts,0013_affected_tags,0014_settings,0015_xposts_no_cve,0016_comment_purpose,0017_corrections,0018_correction_audit_details,0019_xposts_links_candidates,0020_web_page,0021_catalogue_indexes,0022_suspended_identities" {
		t.Errorf("applied %v", applied)
	}
	rows, _ := d.Conn.Query(ctx, "SELECT tablename FROM pg_tables WHERE schemaname = current_schema()")
	have := map[string]bool{}
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		have[n] = true
	}
	for _, n := range []string{"schema_migrations", "raw_record", "vuln", "vuln_alias", "affected", "event", "collector_state", "vuln_cwe", "vuln_cvss", "vuln_classify_input", "classify_queue",
		"vuln_tag", "vuln_tag_suppress", "vuln_tag_count", "tag_run", "tag_queue"} {
		if !have[n] {
			t.Errorf("missing table %s", n)
		}
	}
	rows, _ = d.Conn.Query(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	var vs []string
	for rows.Next() {
		var v string
		_ = rows.Scan(&v)
		vs = append(vs, v)
	}
	if strings.Join(vs, ",") != "0001_init,0002_vuln_state,0003_vuln_state_mat,0004_auth,0005_discuss,0006_stats,0007_admin,0008_xposts,0009_classify,0010_follows,0011_tags,0012_xdrafts,0013_affected_tags,0014_settings,0015_xposts_no_cve,0016_comment_purpose,0017_corrections,0018_correction_audit_details,0019_xposts_links_candidates,0020_web_page,0021_catalogue_indexes,0022_suspended_identities" {
		t.Errorf("versions %v", vs)
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	applied, err := db.Migrate(context.Background(), d.Conn, migrations.FS)
	if err != nil || len(applied) != 0 {
		t.Fatalf("%v %v", applied, err)
	}
}

// A database migrated by the PYTHON runner: same schema, schema_migrations
// rows written by Python (versions = file stems, applied_at default now()).
// The Go runner must see it as up to date and touch nothing.
func TestPythonBookkeepingIsRecognised(t *testing.T) {
	t.Parallel()
	d := testutil.NewDB(t)
	ctx := context.Background()
	list, err := db.ListMigrations(migrations.FS)
	if err != nil {
		t.Fatal(err)
	}
	// Exactly what nday.db.migrate executes, statement for statement.
	if _, err := d.Conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (
                   version    text PRIMARY KEY,
                   applied_at timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	for _, m := range list {
		if _, err := d.Conn.Exec(ctx, m.SQL); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Conn.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES ($1)", m.Version); err != nil {
			t.Fatal(err)
		}
	}
	applied, err := db.Migrate(ctx, d.Conn, migrations.FS)
	if err != nil || len(applied) != 0 {
		t.Fatalf("Go wants to apply %v (%v) on a Python-migrated schema", applied, err)
	}
}

func TestEventTypeCheck(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	if _, err := d.Conn.Exec(ctx, "INSERT INTO vuln (cve_id) VALUES ('CVE-2024-1234')"); err != nil {
		t.Fatal(err)
	}
	_, err := d.Conn.Exec(ctx, `INSERT INTO event (cve_id, type, observed_at, source)
               VALUES ('CVE-2024-1234', 'bogus', now(), 't')`)
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" {
		t.Fatalf("want check_violation, got %v", err)
	}
}

func TestCVEIDFormatAllowsLongSequence(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	if _, err := d.Conn.Exec(ctx, "INSERT INTO vuln (cve_id) VALUES ('CVE-2026-124194')"); err != nil {
		t.Fatal(err)
	}
	_, err := d.Conn.Exec(ctx, "INSERT INTO vuln (cve_id) VALUES ('CVE-2026-123')")
	var pe *pgconn.PgError
	if !errors.As(err, &pe) || pe.Code != "23514" {
		t.Fatalf("want check_violation, got %v", err)
	}
}

func TestEmbeddedMigrationsMatchDirectory(t *testing.T) {
	list, err := db.ListMigrations(migrations.FS)
	if err != nil || len(list) < 2 || list[0].Version != "0001_init" {
		t.Fatalf("%v %v", list, err)
	}
	for _, m := range list {
		if string(testutil.ReadFile(t, "migrations/"+m.Version+".sql")) != m.SQL {
			t.Errorf("%s differs from migrations/ on disk", m.Version)
		}
	}
}
