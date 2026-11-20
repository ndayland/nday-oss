package xposts_test

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/collector/xposts"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pipeline"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xconfig"
)

// End to end through the pipeline: configuration from the database,
// social_post events stored, lifecycle stage untouched, cursor handling.
func TestPipeline(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := d.Conn.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	// CVE-2026-1111 is disclosed; the posts say "PoC" and "exploited".
	exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-1111')`)
	exec(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source) VALUES
          ('CVE-2026-1111', 'disclosed', '2026-11-01T00:00:00Z', '2026-11-01T00:00:00Z', 'cvelist')`)
	exec(`REFRESH MATERIALIZED VIEW vuln_state_mat`)

	run := func(tok string, steps ...step) (*testutil.FakeTransport, *pipeline.Stats) {
		t.Helper()
		ft := script(t, steps...)
		c, err := xposts.New(xposts.Options{Transport: ft, Env: env(map[string]string{xposts.TokenEnv: tok}),
			Clock: func() time.Time { return NOW }, Logger: slog.New(slog.NewTextHandler(&logBuf{}, nil))})
		if err != nil {
			t.Fatal(err)
		}
		st, err := pipeline.RunCollector(ctx, d.Conn, c, pipeline.Options{Now: func() time.Time { return NOW }, Logger: slog.New(slog.NewTextHandler(&logBuf{}, nil))})
		if err != nil {
			t.Fatal(err)
		}
		return ft, st
	}
	cursor := func() (*pyjson.Object, string) {
		t.Helper()
		st, err := pipeline.LoadState(ctx, d.Conn, xposts.Name)
		if err != nil {
			t.Fatal(err)
		}
		return st.Cursor.(*pyjson.Object), *st.LastStatus
	}

	// 1. token set but no accounts: skipped cleanly, nothing requested
	ft, st := run(token)
	if len(ft.Requests) != 0 || st.Fetched != 0 {
		t.Fatalf("%d requests, %+v", len(ft.Requests), st)
	}
	if cur, status := cursor(); status != "ok" || lastRun(t, cur).Get("skipped") != "no_accounts" || cur.Get("since_id") != nil {
		t.Fatalf("%s %s", status, pyjson.Repr(cur))
	}

	// 2. accounts in the table, settings defaults: posts stored
	for _, a := range accounts {
		if _, err := xconfig.UpsertAccount(ctx, d.Conn, a.UserID, a.Handle, ""); err != nil {
			t.Fatal(err)
		}
	}
	_, st = run(token, step{status: 200, file: "search_page1.json"}, step{status: 200, file: "search_page2.json"})
	// 3 records: two posts with CVE ids (3 events, unchanged by 0015) and
	// one without (x_post_no_cve)
	if st.Fetched != 3 || st.RawNew != 3 || st.EventInserted != 3 || st.EventUpdated != 0 || st.VulnInserted != 1 {
		t.Fatalf("%+v", st)
	}
	if cur, status := cursor(); status != "ok" || cur.Get("since_id") != newest {
		t.Fatalf("%s %s", status, pyjson.Repr(cur))
	}
	var n int
	if err := d.Conn.QueryRow(ctx, `SELECT count(*) FROM event WHERE type = 'social_post' AND source = 'xposts'`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("%d %v", n, err)
	}
	var url, detail string
	if err := d.Conn.QueryRow(ctx, `SELECT url, detail->>'author_handle' FROM event WHERE cve_id = 'CVE-2026-22222'`).Scan(&url, &detail); err != nil ||
		url != "https://x.com/alice_sec/status/2120833985541046272" || detail != "alice_sec" {
		t.Fatalf("%s %s %v", url, detail, err)
	}
	// the stage is unchanged: still "disclosed", no transition, social posts not counted
	for _, view := range []string{"vuln_state", "vuln_state_mat"} {
		var stage, lastType string
		var hasPoc, exploited bool
		var count int
		if err := d.Conn.QueryRow(ctx, `SELECT stage, last_transition_type, has_poc, exploited, event_count FROM `+view+
			` WHERE cve_id = 'CVE-2026-1111'`).Scan(&stage, &lastType, &hasPoc, &exploited, &count); err != nil {
			t.Fatal(view, err)
		}
		if stage != "disclosed" || lastType != "disclosed" || hasPoc || exploited || count != 1 {
			t.Errorf("%s: %s %s %v %v %d", view, stage, lastType, hasPoc, exploited, count)
		}
		// a CVE known only from posts has no derived state at all
		if err := d.Conn.QueryRow(ctx, `SELECT count(*) FROM `+view+` WHERE cve_id = 'CVE-2026-22222'`).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s: %d %v", view, n, err)
		}
	}

	// 3. 429 mid-run: stored what came, cursor not advanced
	ft, st = run(token, step{status: 200, file: "search_page1.json"}, step{status: 429, file: "error_429.json"})
	if len(ft.Requests) != 2 || st.RawUnchanged != 2 || st.EventInserted != 0 {
		t.Fatalf("%+v", st)
	}
	if q := query(t, ft.Requests[0].URL); q.Get("since_id") != newest {
		t.Errorf("%v", q)
	}
	if cur, status := cursor(); status != "ok" || cur.Get("since_id") != newest || lastRun(t, cur).Get("stopped") != "rate_limited" {
		t.Fatalf("%s %s", status, pyjson.Repr(cur))
	}

	// 4. settings from the table: max_requests=1; disabled account dropped from the query
	if err := xconfig.SaveSettings(ctx, d.Conn, xconfig.Stored{MaxRequests: ptrInt(1)}); err != nil {
		t.Fatal(err)
	}
	if err := xconfig.SetAccountEnabled(ctx, d.Conn, "1002", false); err != nil {
		t.Fatal(err)
	}
	ft, _ = run(token, step{status: 200, file: "search_page1.json"})
	if len(ft.Requests) != 1 || query(t, ft.Requests[0].URL).Get("query") != "(from:alice_sec) (CVE OR GHSA) -is:retweet" {
		t.Fatalf("%v", ft.Requests)
	}
	if cur, _ := cursor(); lastRun(t, cur).Get("stopped") != "request_cap" || lastRun(t, cur).Get("dropped_author") != pyjson.Int("1") {
		t.Fatalf("%s", pyjson.Repr(cur))
	}

	// 5. collector switched off in the table: skipped, no request
	if err := xconfig.SaveSettings(ctx, d.Conn, xconfig.Stored{Enabled: ptrBool(false)}); err != nil {
		t.Fatal(err)
	}
	ft, _ = run(token)
	if cur, status := cursor(); len(ft.Requests) != 0 || status != "ok" || lastRun(t, cur).Get("skipped") != "disabled" || cur.Get("since_id") != newest {
		t.Fatalf("%s %s", status, pyjson.Repr(cur))
	}
}

func ptrInt(v int) *int    { return &v }
func ptrBool(v bool) *bool { return &v }

// eventRows is every xposts event, one line each, in a fixed order.
func eventRows(t *testing.T, ctx context.Context, d *testutil.TestDB) []string {
	t.Helper()
	rows, err := d.Conn.Query(ctx, `SELECT concat_ws(' | ', cve_id, type, (occurred_at AT TIME ZONE 'UTC')::text, (observed_at AT TIME ZONE 'UTC')::text, url,
		detail::text, is_backfill::text, dedupe_key) FROM event WHERE source = 'xposts' ORDER BY cve_id, dedupe_key`)
	if err != nil {
		t.Fatal(err)
	}
	out, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Posts without a CVE id (migration 0015): stored once in x_post_no_cve and
// as raw records, never as events; posts with a CVE id give exactly the
// events they gave before; other authors are still dropped.
func TestPipelineNoCVE(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	for _, a := range accounts {
		if _, err := xconfig.UpsertAccount(ctx, d.Conn, a.UserID, a.Handle, ""); err != nil {
			t.Fatal(err)
		}
	}
	at := NOW
	run := func(opt pipeline.Options, steps ...step) *pipeline.Stats {
		t.Helper()
		ft := script(t, steps...)
		c, err := xposts.New(xposts.Options{Transport: ft, Env: env(map[string]string{xposts.TokenEnv: token}),
			Clock: func() time.Time { return at }, Logger: slog.New(slog.NewTextHandler(&logBuf{}, nil))})
		if err != nil {
			t.Fatal(err)
		}
		opt.Now = func() time.Time { return at }
		opt.Logger = slog.New(slog.NewTextHandler(&logBuf{}, nil))
		st, err := pipeline.RunCollector(ctx, d.Conn, c, opt)
		if err != nil {
			t.Fatal(err)
		}
		if len(ft.Requests) != len(steps) {
			t.Fatalf("%d requests for %d responses", len(ft.Requests), len(steps))
		}
		return st
	}
	count := func(sql string) int {
		t.Helper()
		var n int
		if err := d.Conn.QueryRow(ctx, sql).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	type row struct {
		id, author, text, url string
		handle, lang          *string
		posted, observed      time.Time
		backfill              bool
	}
	posts := func() []row {
		t.Helper()
		rows, err := d.Conn.Query(ctx, `SELECT post_id, author_id, author_handle, text, lang, posted_at, url, observed_at, is_backfill
			FROM x_post_no_cve ORDER BY post_id`)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pgx.CollectRows(rows, func(r pgx.CollectableRow) (row, error) {
			var x row
			return x, r.Scan(&x.id, &x.author, &x.handle, &x.text, &x.lang, &x.posted, &x.url, &x.observed, &x.backfill)
		})
		if err != nil {
			t.Fatal(err)
		}
		return out
	}

	// 1. first (bulk) run over the original fixtures
	st := run(pipeline.Options{}, step{status: 200, file: "search_page1.json"}, step{status: 200, file: "search_page2.json"})
	if st.Fetched != 3 || st.RawNew != 3 || st.EventInserted != 3 || st.VulnInserted != 2 {
		t.Fatalf("%+v", st)
	}
	// the events are exactly what posts with CVE ids gave before 0015
	ts := "2026-11-13 12:00:00"
	wantEvents := []string{
		`CVE-2026-1111 | social_post | 2026-11-12 08:00:00 | ` + ts + ` | https://x.com/bob_sec/status/2120788687057846272 | ` +
			`{"cves": ["CVE-2026-1111"], "lang": "zh", "text": "在野利用 CVE-2026-1111，详见公告", "post_id": "2120788687057846272", "author_id": "1002", "author_handle": "bob_sec"} | true | 2120788687057846272`,
		`CVE-2026-1111 | social_post | 2026-11-12 11:00:00 | ` + ts + ` | https://x.com/alice_sec/status/2120833985541046272 | ` +
			`{"cves": ["CVE-2026-1111", "CVE-2026-22222"], "lang": "en", "text": "Patch now: cve-2026-1111 and CVE-2026-1111 again; a PoC exists for CVE-2026-22222.", "post_id": "2120833985541046272", "author_id": "1001", "author_handle": "alice_sec"} | true | 2120833985541046272`,
		`CVE-2026-22222 | social_post | 2026-11-12 11:00:00 | ` + ts + ` | https://x.com/alice_sec/status/2120833985541046272 | ` +
			`{"cves": ["CVE-2026-1111", "CVE-2026-22222"], "lang": "en", "text": "Patch now: cve-2026-1111 and CVE-2026-1111 again; a PoC exists for CVE-2026-22222.", "post_id": "2120833985541046272", "author_id": "1001", "author_handle": "alice_sec"} | true | 2120833985541046272`,
	}
	if got := eventRows(t, ctx, d); !slices.Equal(got, wantEvents) {
		t.Fatalf("events:\n%s", strings.Join(got, "\n"))
	}
	if n := count(`SELECT count(*) FROM vuln`); n != 2 {
		t.Errorf("%d vulns", n)
	}
	p := posts()
	if len(p) != 1 || p[0].id != "2120818886046646272" || p[0].author != "1002" || p[0].handle == nil || *p[0].handle != "bob_sec" ||
		p[0].lang == nil || *p[0].lang != "en" || p[0].text != "No id in this one, just CVE talk (CVE-20261111 is not an id)." ||
		p[0].url != "https://x.com/bob_sec/status/2120818886046646272" || !p[0].posted.Equal(time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)) ||
		!p[0].observed.Equal(NOW) || !p[0].backfill {
		t.Fatalf("%+v", p)
	}
	if n := count(`SELECT count(*) FROM raw_record WHERE source = 'xposts' AND source_key = '2120818886046646272'
		AND payload ? 'post' AND payload ? 'author'`); n != 1 {
		t.Errorf("raw record of the no-CVE post: %d", n)
	}
	// the author not on the allowlist is still dropped (no raw record, no row)
	if n := count(`SELECT count(*) FROM raw_record WHERE source_key = '2120811336299446272'`); n != 0 {
		t.Errorf("non-allowlisted post stored")
	}
	st0, err := pipeline.LoadState(ctx, d.Conn, xposts.Name)
	if err != nil {
		t.Fatal(err)
	}
	lr := lastRun(t, st0.Cursor)
	if lr.Get("kept") != pyjson.Int("2") || lr.Get("kept_no_cve") != pyjson.Int("1") || lr.Get("dropped_author") != pyjson.Int("1") ||
		lr.Get("dropped_no_cve") != nil {
		t.Errorf("last_run %s", pyjson.Repr(lr))
	}

	// 2. the same posts again later (e.g. after a truncated run), then with
	// --renormalize: no new row, observed_at / is_backfill unchanged
	at = NOW.Add(time.Hour)
	st = run(pipeline.Options{}, step{status: 200, file: "search_page1.json"}, step{status: 200, file: "search_page2.json"})
	if st.RawNew != 0 || st.RawUnchanged != 3 || st.EventInserted != 0 || st.EventUpdated != 0 {
		t.Fatalf("%+v", st)
	}
	st = run(pipeline.Options{Renormalize: true}, step{status: 200, file: "search_page1.json"}, step{status: 200, file: "search_page2.json"})
	if st.RawNew != 0 || st.EventInserted != 0 || st.EventUpdated != 0 {
		t.Fatalf("%+v", st)
	}
	if got := posts(); len(got) != 1 || !got[0].observed.Equal(NOW) || !got[0].backfill {
		t.Fatalf("%+v", got)
	}
	if got := eventRows(t, ctx, d); !slices.Equal(got, wantEvents) {
		t.Fatalf("events changed:\n%s", strings.Join(got, "\n"))
	}

	// 3. a live run with new posts: two more no-CVE rows (one without lang,
	// one with), one more event; 9999 dropped
	st = run(pipeline.Options{}, step{status: 200, file: "search_nocve.json"})
	if st.RawNew != 3 || st.EventInserted != 1 || st.VulnInserted != 1 {
		t.Fatalf("%+v", st)
	}
	p = posts()
	if len(p) != 3 || p[0].id != "2120818886046646272" || p[1].id != "2120900000000000000" || p[2].id != "2120930000000000000" {
		t.Fatalf("%+v", p)
	}
	if p[1].lang != nil || p[1].handle == nil || *p[1].handle != "alice_sec" || p[1].backfill || !p[1].observed.Equal(at) ||
		p[2].text != "Heads up: pre-auth RCE in FooGateway, CVE pending, writeup after the patch." {
		t.Errorf("%+v %+v", p[1], p[2])
	}
	if n := count(`SELECT count(*) FROM raw_record WHERE source_key = '2120920000000000000'`); n != 0 {
		t.Errorf("non-allowlisted post stored")
	}
	// the no-CVE posts never create events or vulns
	if n := count(`SELECT count(*) FROM event WHERE dedupe_key IN (SELECT post_id FROM x_post_no_cve)`); n != 0 {
		t.Errorf("%d events for no-CVE posts", n)
	}
	// a CVE id named only by the post without a handle gets an i/web link
	var u string
	if err := d.Conn.QueryRow(ctx, `SELECT url FROM event WHERE cve_id = 'CVE-2026-4444'`).Scan(&u); err != nil ||
		u != "https://x.com/i/web/status/2120910000000000000" {
		t.Errorf("%s %v", u, err)
	}

	// 4. the link table accepts several CVEs per post and cascades
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_post_no_cve_link (post_id, cve_id) VALUES
		('2120930000000000000', 'CVE-2026-1111'), ('2120930000000000000', 'CVE-2026-4444')`); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_post_no_cve_link (post_id, cve_id) VALUES ('2120930000000000000', 'CVE-2026-1111')`); err == nil {
		t.Error("duplicate link accepted")
	}
	if n := count(`SELECT count(*) FROM x_post_no_cve_link WHERE linked_at IS NOT NULL`); n != 2 {
		t.Errorf("%d links", n)
	}
	if _, err := d.Conn.Exec(ctx, `DELETE FROM x_post_no_cve WHERE post_id = '2120930000000000000'`); err != nil {
		t.Fatal(err)
	}
	if n := count(`SELECT count(*) FROM x_post_no_cve_link`); n != 0 {
		t.Errorf("%d links after deleting the post", n)
	}
}

// Links and referred accounts (migration 0019): stored for every kept post,
// written idempotently (a rerun or --renormalize rewrites no row), an 'ok'
// link is never downgraded to 'pending', a dismissed candidate stays
// dismissed.
func TestPipelineLinksCandidates(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	for _, a := range accounts {
		if _, err := xconfig.UpsertAccount(ctx, d.Conn, a.UserID, a.Handle, ""); err != nil {
			t.Fatal(err)
		}
	}
	run := func(opt pipeline.Options, steps ...step) *pipeline.Stats {
		t.Helper()
		ft := script(t, steps...)
		c, err := xposts.New(xposts.Options{Transport: ft, Env: env(map[string]string{xposts.TokenEnv: token}),
			Clock: func() time.Time { return NOW }, Logger: slog.New(slog.NewTextHandler(&logBuf{}, nil))})
		if err != nil {
			t.Fatal(err)
		}
		opt.Now = func() time.Time { return NOW }
		opt.Logger = slog.New(slog.NewTextHandler(&logBuf{}, nil))
		st, err := pipeline.RunCollector(ctx, d.Conn, c, opt)
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	dump := func(sql string) []string {
		t.Helper()
		rows, err := d.Conn.Query(ctx, sql)
		if err != nil {
			t.Fatal(err)
		}
		out, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return out
	}
	// xmin changes on every rewrite of a row: equal dumps = nothing written
	linkSQL := `SELECT concat_ws(' | ', post_id, pos, short_url, coalesce(expanded_url, '-'), coalesce(final_url, '-'),
		coalesce(host, '-'), kind, coalesce(title, '-'), origin, status, attempts, coalesce(resolved_at::text, '-'), xmin::text)
		FROM x_post_link ORDER BY post_id, pos`
	candSQL := `SELECT concat_ws(' | ', user_id, coalesce(handle, '-'), (first_seen_at AT TIME ZONE 'UTC')::text,
		(last_seen_at AT TIME ZONE 'UTC')::text, status, coalesce(decided_at::text, '-'), xmin::text)
		FROM x_account_candidate ORDER BY user_id`
	refSQL := `SELECT concat_ws(' | ', user_id, post_id, referrer_id, kind, (posted_at AT TIME ZONE 'UTC')::text, xmin::text)
		FROM x_account_candidate_ref ORDER BY user_id, post_id, kind`
	strip := func(rows []string) []string { // without xmin
		out := make([]string, len(rows))
		for i, r := range rows {
			out[i] = r[:strings.LastIndex(r, " | ")]
		}
		return out
	}

	st := run(pipeline.Options{}, step{status: 200, file: "search_entities.json"})
	if st.RawNew != 2 || st.EventInserted != 1 {
		t.Fatalf("%+v", st)
	}
	links, cands, refs := dump(linkSQL), dump(candSQL), dump(refSQL)
	if want := []string{
		"2121000000000000001 | 0 | https://t.co/Note1 | https://github.com/acme/foogw/commit/0123abcd | https://github.com/acme/foogw/commit/0123abcd | github.com | patch | - | api | ok | 0 | -",
		"2121000000000000001 | 1 | https://t.co/Adv1 | https://fortiguard.fortinet.com/psirt/FG-IR-26-001 | https://www.fortiguard.fortinet.com/psirt/FG-IR-26-001 | fortiguard.fortinet.com | advisory | PSIRT advisory FG-IR-26-001 | api | ok | 0 | -",
		"2121000000000000002 | 0 | https://t.co/Media2 | https://x.com/bob_sec/status/2121000000000000002/photo/1 | https://x.com/bob_sec/status/2121000000000000002/photo/1 | x.com | media | - | api | ok | 0 | -",
		"2121000000000000002 | 1 | https://t.co/Quote2 | https://twitter.com/carol_re/status/2120999000000000001 | https://twitter.com/carol_re/status/2120999000000000001 | twitter.com | quote | - | api | ok | 0 | -",
	}; !slices.Equal(strip(links), want) {
		t.Fatalf("links:\n%s", strings.Join(links, "\n"))
	}
	if want := []string{
		"1001 | alice_sec | 2026-11-12 18:00:00 | 2026-11-12 18:00:00 | pending | -",
		"3001 | carol_re | 2026-11-12 17:00:00 | 2026-11-12 18:00:00 | pending | -",
		"3002 | dave_vr | 2026-11-12 17:00:00 | 2026-11-12 17:00:00 | pending | -",
		"3003 | - | 2026-11-12 18:00:00 | 2026-11-12 18:00:00 | pending | -",
	}; !slices.Equal(strip(cands), want) {
		t.Fatalf("candidates:\n%s", strings.Join(cands, "\n"))
	}
	if want := []string{
		"1001 | 2121000000000000002 | 1002 | replied_to | 2026-11-12 18:00:00",
		"3001 | 2121000000000000001 | 1001 | quoted | 2026-11-12 17:00:00",
		"3001 | 2121000000000000002 | 1002 | quoted | 2026-11-12 18:00:00",
		"3002 | 2121000000000000001 | 1001 | mentioned | 2026-11-12 17:00:00",
		"3003 | 2121000000000000002 | 1002 | mentioned | 2026-11-12 18:00:00",
	}; !slices.Equal(strip(refs), want) {
		t.Fatalf("refs:\n%s", strings.Join(refs, "\n"))
	}

	// rerun and --renormalize: no row rewritten (same xmin), no new row
	run(pipeline.Options{}, step{status: 200, file: "search_entities.json"})
	run(pipeline.Options{Renormalize: true}, step{status: 200, file: "search_entities.json"})
	if got := dump(linkSQL); !slices.Equal(got, links) {
		t.Errorf("links rewritten:\n%s", strings.Join(got, "\n"))
	}
	if got := dump(candSQL); !slices.Equal(got, cands) {
		t.Errorf("candidates rewritten:\n%s", strings.Join(got, "\n"))
	}
	if got := dump(refSQL); !slices.Equal(got, refs) {
		t.Errorf("refs rewritten:\n%s", strings.Join(got, "\n"))
	}

	// a dismissed candidate stays dismissed when the posts come again
	if _, err := xconfig.DismissCandidate(ctx, d.Conn, "3001"); err != nil {
		t.Fatal(err)
	}
	run(pipeline.Options{Renormalize: true}, step{status: 200, file: "search_entities.json"})
	var status string
	if err := d.Conn.QueryRow(ctx, `SELECT status FROM x_account_candidate WHERE user_id = '3001'`).Scan(&status); err != nil || status != "dismissed" {
		t.Errorf("%s %v", status, err)
	}

	// an old-shape version of a post (t.co links from the text, pending)
	// never downgrades its 'ok' links; a new pending link is added, and a
	// pending one keeps the resolver's attempts
	old, _ := pyjson.DecodeString(`{"post": {"id": "2121000000000000002", "author_id": "1002", "created_at": "2026-11-12T18:00:00Z",
		"text": "CVE soon https://t.co/Media2 https://t.co/Quote2 https://t.co/New3"}, "author": null}`)
	c, err := xposts.New(xposts.Options{Env: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	apply := func() {
		t.Helper()
		n, err := c.Normalize(model.RawRecord{Source: xposts.Name, SourceKey: "2121000000000000002", Payload: old})
		if err != nil {
			t.Fatal(err)
		}
		if err := pipeline.ApplyNormalized(ctx, d.Conn, n, NOW, false, &pipeline.Stats{}); err != nil {
			t.Fatal(err)
		}
	}
	apply()
	if _, err := d.Conn.Exec(ctx, `UPDATE x_post_link SET attempts = 2 WHERE post_id = '2121000000000000002' AND pos = 2`); err != nil {
		t.Fatal(err)
	}
	apply()
	got := strip(dump(`SELECT concat_ws(' | ', pos, short_url, coalesce(host, '-'), kind, status, attempts, xmin::text)
		FROM x_post_link WHERE post_id = '2121000000000000002' ORDER BY pos`))
	if want := []string{"0 | https://t.co/Media2 | x.com | media | ok | 0", "1 | https://t.co/Quote2 | twitter.com | quote | ok | 0",
		"2 | https://t.co/New3 | - | other | pending | 2"}; !slices.Equal(got, want) {
		t.Errorf("after old-shape apply:\n%s", strings.Join(got, "\n"))
	}
}

// GHSA ids in posts (docs/ghsa.md): an alias of a CVE goes to that CVE (one
// event even when the post also names the CVE), a GHSA id with its own vuln
// row keeps its GHSA-keyed event, an unknown GHSA id writes no event, no stub
// vuln and no error; the x_post_no_cve row is there for a post without a CVE
// id in every case.
func TestPipelineGHSA(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	c, err := xposts.New(xposts.Options{Env: env(map[string]string{xposts.TokenEnv: token}),
		Logger: slog.New(slog.NewTextHandler(&logBuf{}, nil))})
	if err != nil {
		t.Fatal(err)
	}
	exec := func(sql string, args ...any) {
		t.Helper()
		if _, err := d.Conn.Exec(ctx, sql, args...); err != nil {
			t.Fatal(err)
		}
	}
	count := func(sql string, args ...any) int {
		t.Helper()
		var n int
		if err := d.Conn.QueryRow(ctx, sql, args...).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	const (
		gAlias = "GHSA-2cm2-m3w5-gp2f" // alias of CVE-2026-5555
		gOwn   = "GHSA-jmqv-2mx7-544h" // has its own vuln row
		gNone  = "GHSA-cfgh-jmpq-rvwx" // unknown
	)
	exec(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-5555'), ('CVE-2026-6666'), ($1)`, gOwn)
	exec(`INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ('CVE-2026-5555', $1, 'ghsa'), ('CVE-2026-6666', $2, 'ghsa')`,
		gAlias, "GHSA-2222-3333-4444")
	apply := func(id, text string) *pipeline.Stats {
		t.Helper()
		v, err := pyjson.DecodeString(`{"post": {"id": "` + id + `", "author_id": "1001", "created_at": "2026-11-12T00:00:00Z", "text": ` +
			jsonStr(text) + `}, "author": {"id": "1001", "username": "alice_sec"}}`)
		if err != nil {
			t.Fatal(err)
		}
		n, err := c.Normalize(model.RawRecord{Source: xposts.Name, SourceKey: id, Payload: v})
		if err != nil {
			t.Fatal(err)
		}
		st := &pipeline.Stats{}
		if err := pipeline.ApplyNormalized(ctx, d.Conn, n, NOW, false, st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	events := func(id string) string {
		t.Helper()
		rows, err := d.Conn.Query(ctx, `SELECT cve_id FROM event WHERE dedupe_key = $1 ORDER BY cve_id`, id)
		if err != nil {
			t.Fatal(err)
		}
		got, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(got, ",")
	}

	// CVE + its GHSA alias in one post: one event, a rerun changes nothing
	for i := 0; i < 2; i++ {
		st := apply("101", "CVE-2026-5555 = "+strings.ToUpper(gAlias[:5])+gAlias[5:])
		if st.EventInserted != 1-i || st.EventUpdated != 0 {
			t.Fatalf("run %d: %+v", i, st)
		}
	}
	if got := events("101"); got != "CVE-2026-5555" {
		t.Errorf("events %q", got)
	}
	if n := count(`SELECT count(*) FROM x_post_no_cve WHERE post_id = '101'`); n != 0 {
		t.Error("post with a CVE id in x_post_no_cve")
	}
	// alias only: the event lands on the CVE; the post is also kept in the no-CVE table
	apply("102", "see https://github.com/advisories/"+gAlias)
	if got := events("102"); got != "CVE-2026-5555" || count(`SELECT count(*) FROM x_post_no_cve WHERE post_id = '102'`) != 1 {
		t.Errorf("events %q", got)
	}
	// a GHSA id with its own vuln row keeps a GHSA-keyed event
	apply("103", gOwn)
	if got := events("103"); got != gOwn {
		t.Errorf("events %q", got)
	}
	// unknown GHSA id: no event, no stub, no error, post kept for later
	before := count(`SELECT count(*) FROM vuln`)
	st := apply("104", "new advisory "+gNone)
	if got := events("104"); got != "" || count(`SELECT count(*) FROM vuln`) != before || st.EventInserted != 0 ||
		count(`SELECT count(*) FROM x_post_no_cve WHERE post_id = '104'`) != 1 {
		t.Errorf("events %q", got)
	}
	// CVE + unknown GHSA id: the CVE event only
	apply("105", "CVE-2026-6666 "+gNone)
	if got := events("105"); got != "CVE-2026-6666" {
		t.Errorf("events %q", got)
	}
	// the raw GHSA key never appears as an alias row of its own
	if n := count(`SELECT count(*) FROM vuln_alias WHERE alias = $1`, gNone); n != 0 {
		t.Errorf("%d alias rows", n)
	}
}

// TestPipelineXUser: the author object's name and profile_image_url fill
// x_user (cleaned and validated), dated by when the record was fetched; a
// record without them (stored before the request asked for them) still
// gives its event and leaves the profile alone; a later fetch with another
// picture moves avatar_url and keeps the stored image until internal/xavatar
// fetches the new one; a renormalize never rolls a profile back to an
// older fetch.
func TestPipelineXUser(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	ctx := context.Background()
	for _, a := range accounts {
		if _, err := xconfig.UpsertAccount(ctx, d.Conn, a.UserID, a.Handle, ""); err != nil {
			t.Fatal(err)
		}
	}
	quiet := func() *slog.Logger { return slog.New(slog.NewTextHandler(&logBuf{}, nil)) }
	run := func(at time.Time, steps ...step) *pipeline.Stats {
		t.Helper()
		c, err := xposts.New(xposts.Options{Transport: script(t, steps...), Env: env(map[string]string{xposts.TokenEnv: token}),
			Clock: func() time.Time { return at }, Logger: quiet()})
		if err != nil {
			t.Fatal(err)
		}
		st, err := pipeline.RunCollector(ctx, d.Conn, c, pipeline.Options{Now: func() time.Time { return at }, Logger: quiet()})
		if err != nil {
			t.Fatal(err)
		}
		return st
	}
	type urow struct {
		name, avatar *string
		seen         time.Time
		hash         *string
	}
	get := func(id string) *urow {
		t.Helper()
		var r urow
		err := d.Conn.QueryRow(ctx, `SELECT name, avatar_url, seen_at, avatar_hash FROM x_user WHERE user_id = $1`, id).Scan(&r.name, &r.avatar, &r.seen, &r.hash)
		if err == pgx.ErrNoRows {
			return nil
		}
		if err != nil {
			t.Fatal(err)
		}
		return &r
	}
	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	oldURL := "https://pbs.twimg.com/profile_images/1790000000000000001/aBc_normal.jpg"
	newURL := "https://pbs.twimg.com/profile_images/1790000000000000002/new_normal.png"

	run(NOW, step{status: 200, file: "search_page1.json"}, step{status: 200, file: "search_page2.json"})
	alice, bob := get("1001"), get("1002")
	if alice == nil || str(alice.name) != "Alice" || str(alice.avatar) != oldURL || !alice.seen.Equal(NOW) {
		t.Fatalf("alice: %+v", alice)
	}
	// Bob: both responses of the run are one fetch; the later record (by
	// key) has the cleaned name, the other an empty one; neither avatar URL
	// is acceptable (http, another host)
	if bob == nil || str(bob.name) != "Bob the builder" || bob.avatar != nil || !bob.seen.Equal(NOW) {
		t.Fatalf("bob: %+v", bob)
	}
	if get("9999") != nil {
		t.Fatal("a dropped (not allow-listed) author got a profile")
	}
	// pretend the avatar was fetched
	if _, err := d.Conn.Exec(ctx, `UPDATE x_user SET avatar_status = 'ok', avatar_type = 'image/png', avatar_image = '\x89'::bytea,
        avatar_hash = '0123456789abcdef', avatar_src = avatar_url, avatar_tried = avatar_url WHERE user_id = '1001'`); err != nil {
		t.Fatal(err)
	}

	// an old-style record: stored and normalized, profile untouched
	if st := run(NOW.Add(time.Hour), step{status: 200, file: "search_oldprofile.json"}); st.RawNew != 1 || st.EventInserted != 1 {
		t.Fatalf("old record: %+v", st)
	}
	if a := get("1001"); str(a.name) != "Alice" || str(a.avatar) != oldURL || str(a.hash) != "0123456789abcdef" || !a.seen.Equal(NOW) {
		t.Fatalf("alice after an old-style record: %+v", a)
	}

	// a later fetch with a new picture: name cleaned, avatar_url moves, the
	// stored image stays (served until the new one is fetched)
	later := NOW.Add(2 * time.Hour)
	run(later, step{status: 200, file: "search_newavatar.json"})
	a := get("1001")
	if str(a.name) != "Alice R" || str(a.avatar) != newURL || str(a.hash) != "0123456789abcdef" || !a.seen.Equal(later) {
		t.Fatalf("alice after a new picture: %+v name=%q", a, str(a.name))
	}

	// renormalize: every record again, each dated by its stored fetch time,
	// so page1's older profile of Alice does not win over the newer one
	if _, err := pipeline.Renormalize(ctx, d.Conn, mustNew(t), pipeline.RenormalizeOptions{Now: func() time.Time { return later.Add(time.Hour) },
		Logger: quiet(), SkipStateRefresh: true}); err != nil {
		t.Fatal(err)
	}
	if a := get("1001"); str(a.avatar) != newURL || !a.seen.Equal(later) {
		t.Fatalf("alice after renormalize: %+v", a)
	}
}

// mustNew is a collector for Renormalize (no network).
func mustNew(t *testing.T) *xposts.Collector {
	t.Helper()
	c, err := xposts.New(xposts.Options{Env: env(map[string]string{xposts.TokenEnv: token}), Clock: func() time.Time { return NOW },
		Logger: slog.New(slog.NewTextHandler(&logBuf{}, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return c
}
