package ghrepo_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/db"
	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/state"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xdraft"
	"nday.land/nday/migrations"
)

// pocDB is a database for the github PoC events (migration 0032).
type pocDB struct {
	t    *testing.T
	conn *pgx.Conn
}

func (p pocDB) exec(q string, args ...any) {
	p.t.Helper()
	if _, err := p.conn.Exec(context.Background(), q, args...); err != nil {
		p.t.Fatalf("%v\n%s", err, q)
	}
}

func (p pocDB) str(q string, args ...any) string {
	p.t.Helper()
	var s *string
	if err := p.conn.QueryRow(context.Background(), q, args...).Scan(&s); err != nil {
		p.t.Fatalf("%v\n%s", err, q)
	}
	if s == nil {
		return "<nil>"
	}
	return *s
}

// vuln adds a vulnerability disclosed on 2026-01-10.
func (p pocDB) vuln(cve string) {
	p.t.Helper()
	p.exec(`INSERT INTO vuln (cve_id) VALUES ($1)`, cve)
	p.exec(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, is_backfill, dedupe_key)
        VALUES ($1, 'disclosed', '2026-01-10T08:00:00Z', '2026-01-10T09:00:00Z', 'cvelist', true, $1)`, cve)
}

// repo adds a fetched repository: status/by ("" = nobody decided), created
// at that time, associated with cve on basis. Each statement commits on
// its own, so the deferred triggers run after each.
func (p pocDB) repo(gh int, status, by, created, cve, basis string) {
	p.t.Helper()
	var byArg, atArg any
	if by != "" {
		byArg, atArg = by, time.Now()
	}
	name := "o/r" + strings.Repeat("x", gh%5) + string(rune('a'+gh%26))
	p.exec(`INSERT INTO github_repo (github_id, queued_name, full_name, state, first_source, repo_created_at, status, status_by, status_at)
        VALUES ($1, lower($2), $2, 'ok', 'search', $3, $4, $5, $6)`, gh, name, created, status, byArg, atArg)
	p.exec(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) SELECT id, $2, $3 FROM github_repo WHERE github_id = $1`, gh, cve, basis)
}

func (p pocDB) id(gh int) int64 {
	p.t.Helper()
	var id int64
	if err := p.conn.QueryRow(context.Background(), `SELECT id FROM github_repo WHERE github_id = $1`, gh).Scan(&id); err != nil {
		p.t.Fatal(err)
	}
	return id
}

// events lists the github events: "cve key day backfill".
func (p pocDB) events() string {
	p.t.Helper()
	return p.str(`SELECT COALESCE(string_agg(concat_ws(' ', cve_id, dedupe_key, to_char(occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI'), is_backfill::text), ', '
                  ORDER BY cve_id, dedupe_key), '') FROM event WHERE source = 'github'`)
}

// stage refreshes vuln_state_mat and returns "stage poc_sources poc_day".
func (p pocDB) stage(cve string) string {
	p.t.Helper()
	if _, err := state.Refresh(context.Background(), p.conn, state.RefreshOptions{Wait: true}); err != nil {
		p.t.Fatal(err)
	}
	return p.str(`SELECT concat_ws(' ', stage, poc_sources, COALESCE(to_char(poc_at AT TIME ZONE 'UTC', 'YYYY-MM-DD'), '-'))
        FROM vuln_state_mat WHERE cve_id = $1`, cve)
}

func newPoCDB(t *testing.T) pocDB {
	return pocDB{t: t, conn: testutil.NewMigratedDB(t).Conn}
}

// Which repositories count: trusted by an admin (any basis, a post alone
// included), or trusted by the post rule AND named for the CVE by its name,
// description or topics; never post-only rule trust, a rejection, nobody's
// decision or a repository that is gone. A GHSA id resolves to the CVE it
// is an alias of.
func TestPoCQualifyMatrix(t *testing.T) {
	t.Parallel()
	p := newPoCDB(t)
	for i := 1; i <= 9; i++ {
		p.vuln("CVE-2026-010" + string(rune('0'+i)))
	}
	p.repo(1, "trusted", "admin", "2026-02-01T13:14:15Z", "CVE-2026-0101", "post")
	p.repo(2, "trusted", "rule", "2026-02-02T00:00:00Z", "CVE-2026-0102", "name")
	p.repo(3, "trusted", "rule", "2026-02-03T23:59:59Z", "CVE-2026-0103", "description")
	p.repo(4, "trusted", "rule", "2026-02-04T00:00:00Z", "CVE-2026-0104", "topic")
	p.repo(5, "trusted", "rule", "2026-02-05T00:00:00Z", "CVE-2026-0105", "post")
	p.repo(6, "rejected", "admin", "2026-02-06T00:00:00Z", "CVE-2026-0106", "name")
	p.repo(7, "unverified", "", "2026-02-07T00:00:00Z", "CVE-2026-0107", "name")
	p.repo(8, "trusted", "admin", "2026-02-08T00:00:00Z", "CVE-2026-0108", "name")
	p.exec(`UPDATE github_repo SET state = 'gone' WHERE github_id = 8`)
	// a GHSA id of CVE-2026-0109 in the name of a rule-trusted repository
	p.exec(`INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ('CVE-2026-0109', 'GHSA-2345-6789-cfgh', 'ghsa')`)
	p.repo(9, "trusted", "rule", "2026-02-09T00:00:00Z", "GHSA-2345-6789-cfgh", "name")
	// created long ago: history (is_backfill), at the creation time
	want := "CVE-2026-0101 1 2026-02-01 13:14 true, CVE-2026-0102 2 2026-02-02 00:00 true, CVE-2026-0103 3 2026-02-03 23:59 true, " +
		"CVE-2026-0104 4 2026-02-04 00:00 true, CVE-2026-0109 9 2026-02-09 00:00 true"
	if got := p.events(); got != want {
		t.Errorf("events:\n got %s\nwant %s", got, want)
	}
	// what the event says: the repository and its day, nothing else; the
	// times nday adds are days only (no time a link was checked)
	today := time.Now().UTC().Format("2006-01-02")
	if got := p.str(`SELECT concat_ws(' ', url, detail::text, to_char(observed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS'),
            to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')) FROM event WHERE source = 'github' AND cve_id = 'CVE-2026-0101'`); got !=
		`https://github.com/o/rxb {"url": "https://github.com/o/rxb", "title": "o/rxb", "precision": "day"} `+today+` 00:00:00 `+today+` 00:00:00` {
		t.Errorf("event 1: %s", got)
	}
	if got := p.stage("CVE-2026-0102"); got != "poc_published 1 2026-02-02" {
		t.Errorf("stage 0102: %s", got)
	}
	for _, c := range []string{"CVE-2026-0105", "CVE-2026-0106", "CVE-2026-0107", "CVE-2026-0108"} {
		if got := p.stage(c); got != "disclosed 0 -" {
			t.Errorf("stage %s: %s", c, got)
		}
	}
	// the post-only repository gains a name basis: it counts from then on
	p.exec(`INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, 'CVE-2026-0105', 'name')`, p.id(5))
	if got := p.stage("CVE-2026-0105"); got != "poc_published 1 2026-02-05" {
		t.Errorf("stage 0105 with a name basis: %s", got)
	}
	// an association id with no vulnerability yet: the event comes with the vuln row
	p.repo(10, "trusted", "admin", "2026-02-10T00:00:00Z", "CVE-2026-0110", "name")
	if strings.Contains(p.events(), "CVE-2026-0110") {
		t.Fatal("event without a vuln row")
	}
	p.vuln("CVE-2026-0110")
	if got := p.stage("CVE-2026-0110"); got != "poc_published 1 2026-02-10" {
		t.Errorf("stage 0110 after its vuln row: %s", got)
	}
}

// Revocation: a rejection, a reset, a repository that is gone or an
// association that goes away deletes the event, and the stage is computed
// as if it had never counted; another qualifying repository keeps it.
func TestPoCRevocation(t *testing.T) {
	t.Parallel()
	p := newPoCDB(t)
	ctx := context.Background()
	p.vuln("CVE-2026-0201")
	p.repo(21, "trusted", "admin", "2026-03-01T10:00:00Z", "CVE-2026-0201", "name")
	if got := p.stage("CVE-2026-0201"); got != "poc_published 1 2026-03-01" {
		t.Fatalf("trusted: %s", got)
	}
	if _, err := ghrepo.SetStatus(ctx, p.conn, p.id(21), ghrepo.StatusRejected); err != nil {
		t.Fatal(err)
	}
	if got, ev := p.stage("CVE-2026-0201"), p.events(); got != "disclosed 0 -" || ev != "" {
		t.Errorf("rejected: %s / %s", got, ev)
	}
	if _, err := ghrepo.SetStatus(ctx, p.conn, p.id(21), ghrepo.StatusTrusted); err != nil {
		t.Fatal(err)
	}
	if got := p.stage("CVE-2026-0201"); got != "poc_published 1 2026-03-01" {
		t.Errorf("trusted again: %s", got)
	}
	if _, err := ghrepo.SetStatus(ctx, p.conn, p.id(21), ghrepo.StatusUnverified); err != nil {
		t.Fatal(err)
	}
	if got := p.stage("CVE-2026-0201"); got != "disclosed 0 -" {
		t.Errorf("reset: %s", got)
	}

	// earliest creation day wins; revoking it falls back to the next one
	p.repo(22, "trusted", "admin", "2026-03-05T10:00:00Z", "CVE-2026-0201", "name")
	p.repo(23, "trusted", "rule", "2026-02-20T23:00:00Z", "CVE-2026-0201", "topic")
	if got := p.stage("CVE-2026-0201"); got != "poc_published 1 2026-02-20" {
		t.Errorf("two repositories: %s", got)
	}
	p.exec(`UPDATE github_repo SET state = 'gone' WHERE github_id = 23`)
	if got := p.stage("CVE-2026-0201"); got != "poc_published 1 2026-03-05" {
		t.Errorf("earliest gone: %s", got)
	}
	// the association goes away (a fetch no longer finds the id)
	p.exec(`DELETE FROM github_repo_cve WHERE repo_id = $1`, p.id(22))
	if got, ev := p.stage("CVE-2026-0201"), p.events(); got != "disclosed 0 -" || ev != "" {
		t.Errorf("association gone: %s / %s", got, ev)
	}

	// another PoC source stays when the repository stops counting
	p.vuln("CVE-2026-0202")
	p.exec(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, detail, is_backfill, dedupe_key)
        VALUES ('CVE-2026-0202', 'poc_published', '2026-04-01', '2026-04-01', 'exploitdb', '{"precision": "day"}', true, '1')`)
	p.repo(24, "trusted", "admin", "2026-03-01T00:00:00Z", "CVE-2026-0202", "name")
	if got := p.stage("CVE-2026-0202"); got != "poc_published 2 2026-03-01" {
		t.Errorf("two sources: %s", got)
	}
	if _, err := ghrepo.SetStatus(ctx, p.conn, p.id(24), ghrepo.StatusRejected); err != nil {
		t.Fatal(err)
	}
	if got := p.stage("CVE-2026-0202"); got != "poc_published 1 2026-04-01" {
		t.Errorf("exploitdb left: %s", got)
	}

	// a fetch rewrites the associations (delete, then the same rows again)
	// in one transaction: the event is left alone, same id
	p.vuln("CVE-2026-0203")
	p.repo(25, "trusted", "rule", "2026-03-01T00:00:00Z", "CVE-2026-0203", "name")
	before := p.str(`SELECT id::text FROM event WHERE source = 'github' AND cve_id = 'CVE-2026-0203'`)
	err := pgx.BeginFunc(ctx, p.conn, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `DELETE FROM github_repo_cve WHERE repo_id = $1 AND basis <> 'post'`, p.id(25)); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO github_repo_cve (repo_id, cve_id, basis) VALUES ($1, 'CVE-2026-0203', 'name')`, p.id(25))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if after := p.str(`SELECT id::text FROM event WHERE source = 'github' AND cve_id = 'CVE-2026-0203'`); after != before {
		t.Errorf("event churned: %s -> %s", before, after)
	}
}

// The backfill: repositories that qualify when 0032 is applied get their
// events as history (is_backfill, the creation day as time): no X draft,
// not a change of today in the hot list. `nday github-poc` (SyncPoC) finds
// nothing more to do, as often as it runs.
func TestPoCBackfill(t *testing.T) {
	t.Parallel()
	d := testutil.NewDB(t)
	ctx := context.Background()
	p := pocDB{t: t, conn: d.Conn}
	sub, err := fs.Sub(migrations.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	before := fstest.MapFS{}
	entries, _ := fs.ReadDir(sub, ".")
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".sql") && e.Name() < "0032" {
			b, _ := fs.ReadFile(sub, e.Name())
			before[e.Name()] = &fstest.MapFile{Data: b}
		}
	}
	if _, err := db.Migrate(ctx, d.Conn, before); err != nil {
		t.Fatal(err)
	}
	created := time.Now().Add(-40 * 24 * time.Hour).UTC().Format(time.RFC3339)
	for i, c := range []string{"CVE-2026-0301", "CVE-2026-0302"} {
		p.vuln(c)
		p.repo(31+i, "trusted", []string{"admin", "rule"}[i], created, c, "name")
	}
	p.repo(33, "trusted", "rule", created, "CVE-2026-0301", "post") // post only: no event of its own
	// the draft pass ran before (its watermark exists)
	if r, err := xdraft.Generate(ctx, d.Conn, xdraft.Options{}); err != nil || !r.Baseline {
		t.Fatalf("%+v %v", r, err)
	}
	applied, err := db.Migrate(ctx, d.Conn, migrations.FS)
	if err != nil || strings.Join(applied, ",") != "0032_github_poc,0033_github_poc_gap,0034_xdraft_form,0035_job_run,0036_github_trusted_owner,0037_vuln_score,0038_x_user,0039_osssec_no_transition" {
		t.Fatalf("%v %v", applied, err)
	}
	day, at := created[:10], created[:10]+" "+created[11:16]
	if got := p.events(); got != "CVE-2026-0301 31 "+at+" true, CVE-2026-0302 32 "+at+" true" {
		t.Errorf("backfill: %s", got)
	}
	if got := p.stage("CVE-2026-0301"); got != "poc_published 1 "+day {
		t.Errorf("stage: %s", got)
	}
	r, err := xdraft.Generate(ctx, d.Conn, xdraft.Options{})
	if err != nil || r.Created != 0 || r.Candidates != 0 {
		t.Errorf("drafts after the backfill: %+v %v", r, err)
	}
	hot, err := state.Hot(ctx, d.Conn, 7*24*time.Hour, 50, true, "disclosed")
	if err != nil || len(hot) != 0 {
		t.Errorf("hot list of the last 7 days: %+v %v", hot, err)
	}
	for range 2 {
		res, err := ghrepo.SyncPoC(ctx, d.Conn, false)
		if err != nil || res != (ghrepo.PoCSyncResult{Vulns: 2}) {
			t.Errorf("sync again: %+v %v", res, err)
		}
	}
	// SyncPoC repairs what is out of step, as history
	p.exec(`DELETE FROM event WHERE source = 'github' AND cve_id = 'CVE-2026-0302'`)
	if res, err := ghrepo.SyncPoC(ctx, d.Conn, true); err != nil || res.Added != 1 || !res.DryRun {
		t.Errorf("dry run: %+v %v", res, err)
	}
	if res, err := ghrepo.SyncPoC(ctx, d.Conn, false); err != nil || res.Added != 1 {
		t.Errorf("repair: %+v %v", res, err)
	}
	if got := p.events(); !strings.HasSuffix(got, "CVE-2026-0302 32 "+at+" true") {
		t.Errorf("repaired: %s", got)
	}
}

// Going forward a repository that starts to count is a new PoC like an
// entry of the other three sources: a live event, and the draft pass drafts
// it when it is the CVE's first PoC (and not when another source was first).
func TestPoCGoingForward(t *testing.T) {
	t.Parallel()
	p := newPoCDB(t)
	ctx := context.Background()
	p.vuln("CVE-2026-0401")
	p.vuln("CVE-2026-0402")
	p.exec(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, detail, is_backfill, dedupe_key)
        VALUES ('CVE-2026-0402', 'poc_published', '2026-04-01', '2026-04-01', 'nuclei', '{}', true, 't')`)
	if r, err := xdraft.Generate(ctx, p.conn, xdraft.Options{}); err != nil || !r.Baseline {
		t.Fatalf("%+v %v", r, err)
	}
	recent := time.Now().Add(-5 * 24 * time.Hour).UTC().Truncate(time.Minute)
	p.repo(41, "unverified", "", recent.Format(time.RFC3339), "CVE-2026-0401", "name")
	p.repo(42, "unverified", "", recent.Format(time.RFC3339), "CVE-2026-0402", "name")
	for _, gh := range []int{41, 42} {
		if _, err := ghrepo.SetStatus(ctx, p.conn, p.id(gh), ghrepo.StatusTrusted); err != nil {
			t.Fatal(err)
		}
	}
	at := recent.Format("2006-01-02 15:04")
	if got := p.events(); got != "CVE-2026-0401 41 "+at+" false, CVE-2026-0402 42 "+at+" false" {
		t.Errorf("events: %s", got)
	}
	r, err := xdraft.Generate(ctx, p.conn, xdraft.Options{})
	if err != nil || r.Created != 1 || len(r.Drafts) != 1 || r.Drafts[0].CVE != "CVE-2026-0401" || r.Drafts[0].Stage != "poc_published" ||
		!strings.Contains(r.Drafts[0].Body, "Public PoC available: GitHub repository.") || r.Drafts[0].Weight > 280 {
		t.Errorf("drafts: %+v %v", r, err)
	}
}

// Live or history does not depend on who calls the sync: a repository
// created within the last 30 days gives a live event, an older one
// history, also when it drops out and comes back (a 404 then ok again, an
// admin reset and trust), so no draft is made for old code.
func TestPoCLiveWindow(t *testing.T) {
	t.Parallel()
	p := newPoCDB(t)
	ctx := context.Background()
	ago := func(days int) string {
		return time.Now().Add(-time.Duration(days) * 24 * time.Hour).UTC().Format(time.RFC3339)
	}
	for _, c := range []string{"CVE-2026-0501", "CVE-2026-0502", "CVE-2026-0503"} {
		p.vuln(c)
	}
	p.repo(51, "unverified", "", ago(5), "CVE-2026-0501", "name")
	p.repo(52, "unverified", "", ago(90), "CVE-2026-0502", "name")
	p.repo(53, "trusted", "rule", ago(60), "CVE-2026-0503", "name")
	if r, err := xdraft.Generate(ctx, p.conn, xdraft.Options{}); err != nil || !r.Baseline {
		t.Fatalf("%+v %v", r, err)
	}
	for _, gh := range []int{51, 52} {
		if _, err := ghrepo.SetStatus(ctx, p.conn, p.id(gh), ghrepo.StatusTrusted); err != nil {
			t.Fatal(err)
		}
	}
	flags := func() string {
		return p.str(`SELECT string_agg(cve_id || '=' || is_backfill::text, ' ' ORDER BY cve_id) FROM event WHERE source = 'github'`)
	}
	if got := flags(); got != "CVE-2026-0501=false CVE-2026-0502=true CVE-2026-0503=true" {
		t.Errorf("trusted now: %s", got)
	}
	// flaps of the old ones: gone and back, reset and trusted again
	p.exec(`UPDATE github_repo SET state = 'gone' WHERE github_id = 53`)
	p.exec(`UPDATE github_repo SET state = 'ok' WHERE github_id = 53`)
	for _, st := range []string{ghrepo.StatusUnverified, ghrepo.StatusTrusted} {
		if _, err := ghrepo.SetStatus(ctx, p.conn, p.id(52), st); err != nil {
			t.Fatal(err)
		}
	}
	if got := flags(); got != "CVE-2026-0501=false CVE-2026-0502=true CVE-2026-0503=true" {
		t.Errorf("after the flaps: %s", got)
	}
	r, err := xdraft.Generate(ctx, p.conn, xdraft.Options{})
	if err != nil || r.Candidates != 1 || r.Created != 1 || r.Drafts[0].CVE != "CVE-2026-0501" {
		t.Errorf("drafts: %+v %v", r, err)
	}
}

// The gap between the disclosure (published_at, or the first disclosed
// event) and the repository's creation (migration 0033): created after it,
// the creation time; up to 30 days before (coordinated disclosure, a
// repository prepared under the reserved id), it counts for rule and admin
// trust alike, at the disclosure time; more than 30 days before (a reused
// name), rule trust does not count and admin trust counts with an unknown
// time. A github event never makes days_disclosed_to_poc negative, and a
// publication date that changes later is converged by the repair.
func TestPoCPredates(t *testing.T) {
	t.Parallel()
	p := newPoCDB(t)
	ctx := context.Background()
	pub := func(cve, at string) {
		p.exec(`INSERT INTO vuln (cve_id, published_at) VALUES ($1, $2)`, cve, at)
		p.exec(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, is_backfill, dedupe_key)
            VALUES ($1, 'disclosed', $2, $2, 'cvelist', true, $1)`, cve, at)
	}
	const disc = "2026-06-01T08:00:00Z"
	for i := 1; i <= 6; i++ {
		pub("CVE-2026-060"+string(rune('0'+i)), disc)
	}
	p.repo(61, "trusted", "rule", "2026-06-01T03:54:00Z", "CVE-2026-0601", "name")  // 4 h 06 min before: counts at the disclosure
	p.repo(62, "trusted", "rule", "2026-05-22T08:00:00Z", "CVE-2026-0602", "topic") // 10 days before: counts
	p.repo(63, "trusted", "rule", "2026-05-01T08:00:00Z", "CVE-2026-0603", "name")  // 31 days before, rule: no
	p.repo(64, "trusted", "admin", "2026-05-01T08:00:00Z", "CVE-2026-0604", "name") // 31 days before, admin: time unknown
	p.repo(65, "trusted", "rule", "2026-06-01T12:00:00Z", "CVE-2026-0605", "name")  // after: the creation time
	p.repo(66, "trusted", "admin", "2026-05-25T00:00:00Z", "CVE-2026-0606", "post") // 7 days before, admin, post only: counts
	want := "CVE-2026-0601 2026-06-01 08:00:00+00 true true, CVE-2026-0602 2026-06-01 08:00:00+00 true true, " +
		"CVE-2026-0604 - false true, CVE-2026-0605 2026-06-01 12:00:00+00 true true, CVE-2026-0606 2026-06-01 08:00:00+00 true true"
	if got := p.str(`SELECT string_agg(concat_ws(' ', cve_id, COALESCE(occurred_at::text, '-'), (detail ? 'precision')::text, is_backfill::text), ', ' ORDER BY cve_id)
        FROM event WHERE source = 'github'`); got != want {
		t.Errorf("events:\n got %s\nwant %s", got, want)
	}
	for cve, w := range map[string]string{"CVE-2026-0601": "poc_published 1 2026-06-01", "CVE-2026-0602": "poc_published 1 2026-06-01",
		"CVE-2026-0603": "disclosed 0 -", "CVE-2026-0604": "poc_published 1 -", "CVE-2026-0605": "poc_published 1 2026-06-01"} {
		if got := p.stage(cve); got != w {
			t.Errorf("%s: %s, want %s", cve, got, w)
		}
	}
	if got := p.str(`SELECT concat_ws(' ', count(*) FILTER (WHERE days_disclosed_to_poc < 0), min(days_disclosed_to_poc)::numeric(6,2),
            count(*) FILTER (WHERE days_disclosed_to_poc = 0)) FROM vuln_state_mat`); got != "0 0.00 3" {
		t.Errorf("days to PoC (negative, min, zero): %s", got)
	}
	// the record of CVE-2026-0605 now says it was published 40 days
	// later: the repository is old for it. No trigger sees that; the
	// repair (hourly, after discovery) does
	p.exec(`UPDATE vuln SET published_at = '2026-07-11T13:00:00Z' WHERE cve_id = 'CVE-2026-0605'`)
	p.exec(`UPDATE event SET occurred_at = '2026-07-11T13:00:00Z' WHERE cve_id = 'CVE-2026-0605' AND type = 'disclosed'`)
	if res, err := ghrepo.SyncPoC(ctx, p.conn, false); err != nil || res.Removed != 1 || res.Added != 0 || res.Updated != 0 {
		t.Errorf("repair: %+v %v", res, err)
	}
	if got := p.stage("CVE-2026-0605"); got != "disclosed 0 -" {
		t.Errorf("after the repair: %s", got)
	}
}

// The dry run only compares: no locks, no writes, no event ids used. The
// repair also visits vulnerabilities whose github event lost its
// association (a stray event).
func TestPoCRepairDryRunAndStray(t *testing.T) {
	t.Parallel()
	p := newPoCDB(t)
	ctx := context.Background()
	p.vuln("CVE-2026-0701")
	p.vuln("CVE-2026-0702")
	p.repo(71, "trusted", "admin", "2026-03-01T00:00:00Z", "CVE-2026-0701", "name")
	p.exec(`DELETE FROM event WHERE source = 'github'`)
	p.exec(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, is_backfill, dedupe_key)
        VALUES ('CVE-2026-0702', 'poc_published', NULL, now(), 'github', true, '999')`)
	seq := func() string {
		return p.str(`SELECT concat_ws(' ', last_value, is_called, (SELECT count(*) FROM event)) FROM event_id_seq`)
	}
	before := seq()
	// (github_poc_diff is a STABLE function: it cannot lock or write)
	res, err := ghrepo.SyncPoC(ctx, p.conn, true)
	if err != nil || res != (ghrepo.PoCSyncResult{Vulns: 2, Added: 1, Removed: 1, DryRun: true}) {
		t.Errorf("dry run: %+v %v", res, err)
	}
	if after := seq(); after != before {
		t.Errorf("dry run used ids or wrote: %s -> %s", before, after)
	}
	if res, err := ghrepo.SyncPoC(ctx, p.conn, false); err != nil || res.Added != 1 || res.Removed != 1 || res.Vulns != 2 {
		t.Errorf("repair: %+v %v", res, err)
	}
	if got := p.events(); got != "CVE-2026-0701 71 2026-03-01 00:00 true" {
		t.Errorf("after the repair: %s", got)
	}
}
