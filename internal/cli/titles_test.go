package cli_test

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"nday.land/nday/internal/testutil"
)

// `nday titles`: the backfill's JSON summary, idempotence, --all and the
// usage errors (docs/titles.md).
func TestTitlesCommand(t *testing.T) {
	d := testutil.NewMigratedDB(t)
	t.Setenv("NDAY_DATABASE_URL", d.URL)
	env := kevEnv(t, time.Now().UTC())
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO vuln (cve_id, description) VALUES ('CVE-2026-0101', 'Acme Widget allows remote attackers to read files.'),
		 ('CVE-2026-0102', NULL)`,
		`INSERT INTO vuln (cve_id, title) VALUES ('CVE-2026-0103', 'Own title')`,
		`DELETE FROM tag_queue`,
	} {
		if _, err := d.Conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	var st struct {
		Considered  int            `json:"considered"`
		Composed    map[string]int `json:"composed"`
		RecordTitle int            `json:"record_title"`
		Untitled    int            `json:"untitled"`
		Written     int            `json:"written"`
		Done        bool           `json:"done"`
		RuleVersion int            `json:"rule_version"`
		Duration    *float64       `json:"duration_sec"`
	}
	for i, c := range []struct {
		args              []string
		considered, wrote int
	}{
		{[]string{"titles", "--limit", "2", "--batch-size", "1"}, 2, 2},
		{[]string{"titles"}, 1, 1},
		{[]string{"titles"}, 0, 0},
		{[]string{"titles", "--all"}, 3, 0},
	} {
		code, out, errb := runCLI(t, env, c.args...)
		if code != 0 {
			t.Fatalf("%v: %d %s", c.args, code, errb)
		}
		st.Composed = nil
		if err := json.Unmarshal([]byte(out), &st); err != nil {
			t.Fatalf("%v: %v %s", c.args, err, out)
		}
		if st.Considered != c.considered || st.Written != c.wrote || st.Duration == nil || st.RuleVersion != 1 || st.Done != (i > 0) {
			t.Errorf("%v: %s", c.args, out)
		}
		if i == 3 && (st.Composed["excerpt"] != 1 || st.RecordTitle != 1 || st.Untitled != 1) {
			t.Errorf("--all summary: %s", out)
		}
	}
	var en string
	if err := d.Conn.QueryRow(ctx, `SELECT composed_en FROM vuln_title WHERE cve_id = 'CVE-2026-0101'`).Scan(&en); err != nil ||
		en != "Acme Widget allows remote attackers to read files" {
		t.Errorf("composed %q %v", en, err)
	}
	for _, bad := range [][]string{{"titles", "CVE-2026-1"}, {"titles", "--limit", "-1"}, {"titles", "--batch-size", "0"}, {"titles", "--pending"}} {
		if code, _, _ := runCLI(t, env, bad...); code != 2 {
			t.Errorf("%v: exit %d, want 2", bad, code)
		}
	}
}
