package site_test

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
)

// catSeed adds, on top of sitetest.Seed (+ SeedTags):
//
//	CVE-2014-1000  disclosed exact 2014-04-07 (dated, old year)
//	CVE-2014-0160  disclosed, unknown time  -> undated tail, rank 1
//	CVE-2014-9999  disclosed, unknown time  -> undated tail, rank 1
//	CVE-2014-0161  PoC, unknown time        -> undated tail, rank 4
//	CVE-2015-0001  KEV, unknown time        -> undated tail, rank 6
//	CVE-2025-0001..0006  one event each at the same instant 2025-06-01:
//	               ranks PAT, POC, DIS, PAT, POC, DIS (ties on time)
func catSeed(t *testing.T, d *testutil.TestDB) {
	t.Helper()
	sitetest.SeedTags(t, d.Conn)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	s.Vuln("CVE-2014-1000", sitetest.P("old dated"))
	s.Event(sitetest.Ev{CVE: "CVE-2014-1000", Type: "disclosed", Source: "cvelist", Occurred: sitetest.P(sitetest.Day(2014, 4, 7)),
		Backfill: true, Detail: `{"state": "PUBLISHED"}`})
	for _, u := range []struct{ cve, typ, src string }{
		{"CVE-2014-0160", "disclosed", "nvd"}, {"CVE-2014-9999", "disclosed", "nvd"},
		{"CVE-2014-0161", "poc_published", "exploitdb"}, {"CVE-2015-0001", "kev_added", "kev"},
	} {
		s.Vuln(u.cve, nil)
		s.Event(sitetest.Ev{CVE: u.cve, Type: u.typ, Source: u.src, Backfill: true, Key: u.cve})
	}
	tie := sitetest.Day(2025, 6, 1)
	for i, typ := range []string{"patch_released", "poc_published", "disclosed", "patch_released", "poc_published", "disclosed"} {
		c := "CVE-2025-000" + string(rune('1'+i))
		s.Vuln(c, sitetest.P("tie "+c))
		s.Event(sitetest.Ev{CVE: c, Type: typ, Source: "ghsa", Occurred: &tie, Key: c})
	}
	s.Refresh()
}

func catSeeded(t *testing.T) (*site.Store, *testutil.TestDB) {
	st, d, _ := seeded(t)
	catSeed(t, d)
	return st, d
}

// cids is ids() without shortening (several years are mixed).
func cids(rows []site.HotRow) string {
	s := make([]string, len(rows))
	for i, r := range rows {
		s[i] = r.CVEID
	}
	return strings.Join(s, ",")
}

// refOrder is the catalogue order computed independently in SQL.
func refOrder(t *testing.T, d *testutil.TestDB, where string) string {
	t.Helper()
	rows, err := d.Conn.Query(ctx, `SELECT m.cve_id FROM vuln_state_mat m WHERE `+where+`
        ORDER BY m.last_transition_at DESC NULLS LAST, m.stage_rank DESC, m.cve_id DESC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		out = append(out, id)
	}
	return strings.Join(out, ",")
}

func TestCatalogueOrderAndFilters(t *testing.T) {
	st, d := catSeeded(t)
	page, err := st.Catalogue(ctx, site.CatalogueParams{})
	if err != nil {
		t.Fatal(err)
	}
	// every non-rejected CVE with an event, newest change first, undated tail
	// last (rank desc, id desc); CVE-2026-1010 (no events) is not a row
	want := "CVE-2026-1004,CVE-2026-1001,CVE-2026-1002,CVE-2026-1003,CVE-2026-102895,CVE-2026-1008,CVE-2026-1007,CVE-2026-1009,CVE-2026-1006," +
		"CVE-2025-0005,CVE-2025-0002,CVE-2025-0004,CVE-2025-0001,CVE-2025-0006,CVE-2025-0003,CVE-2014-1000," +
		"CVE-2015-0001,CVE-2014-0161,CVE-2014-9999,CVE-2014-0160"
	if got := cids(page.Rows); got != want {
		t.Errorf("order\n got %s\nwant %s", got, want)
	}
	if ref := refOrder(t, d, "NOT m.is_rejected"); ref != want {
		t.Errorf("reference order %s", ref)
	}
	if page.Stage != nil || page.StageCode != nil || page.Year != nil || page.Limit != 50 || page.NextCursor != nil ||
		page.IncludeRejected || len(page.Tags) != 0 || !page.GeneratedAt.Equal(sitetest.Now) {
		t.Errorf("page %+v", page)
	}
	// rows are hot rows: same content for a CVE the hot list also has
	hot, _ := st.Hot(ctx, site.HotParams{Since: 30 * 24 * time.Hour, MinStage: "patch", NoPins: true})
	hb, cb := map[string]string{}, map[string]string{}
	for _, r := range hot.Rows {
		b, _ := json.Marshal(r)
		hb[r.CVEID] = string(b)
	}
	for _, r := range page.Rows {
		b, _ := json.Marshal(r)
		cb[r.CVEID] = string(b)
	}
	for id, b := range hb {
		if cb[id] != b {
			t.Errorf("%s differs from the hot row:\n%s\n%s", id, cb[id], b)
		}
	}
	// undated row: no transition time, type, latest slot or T+
	for _, r := range page.Rows {
		if r.CVEID != "CVE-2014-0161" {
			continue
		}
		if !r.Transition.At.IsZero() || r.Transition.Type != "" || r.Transition.Code != "" || r.Transition.Precision != "unknown" ||
			r.Stage != "poc_published" || r.StageCode != "POC" || r.DaysSinceDisclosure != nil || slotCodes(r.Slots) != "---U--" {
			t.Errorf("undated row %+v %s", r, slotCodes(r.Slots))
		}
		b, _ := json.Marshal(r.Transition)
		if string(b) != `{"type":"","code":"","precision":"unknown","source":null,"event_id":null,"at":null}` {
			t.Errorf("undated transition json %s", b)
		}
	}
	for _, c := range []struct {
		p     site.CatalogueParams
		where string
		want  string
	}{
		{site.CatalogueParams{Stage: "patch"}, "m.stage = 'patch_released' AND NOT m.is_rejected",
			"CVE-2026-1003,CVE-2026-1006,CVE-2025-0004,CVE-2025-0001"},
		{site.CatalogueParams{Stage: "disclosed"}, "m.stage = 'disclosed' AND NOT m.is_rejected",
			"CVE-2026-1004,CVE-2025-0006,CVE-2025-0003,CVE-2014-1000,CVE-2014-9999,CVE-2014-0160"},
		{site.CatalogueParams{Stage: "KEV"}, "m.stage = 'kev_added' AND NOT m.is_rejected",
			"CVE-2026-1001,CVE-2026-102895,CVE-2026-1008,CVE-2026-1007,CVE-2026-1009,CVE-2015-0001"},
		{site.CatalogueParams{Stage: "analysis"}, "m.stage = 'analysis_published'", ""},
		{site.CatalogueParams{Year: 2014}, "m.cve_id LIKE 'CVE-2014-%'",
			"CVE-2014-1000,CVE-2014-0161,CVE-2014-9999,CVE-2014-0160"},
		{site.CatalogueParams{Year: 2025, Stage: "poc_published"}, "m.cve_id LIKE 'CVE-2025-%' AND m.stage = 'poc_published'",
			"CVE-2025-0005,CVE-2025-0002"},
		{site.CatalogueParams{Year: 2014, Stage: "disclosed"}, "m.cve_id LIKE 'CVE-2014-%' AND m.stage = 'disclosed'",
			"CVE-2014-1000,CVE-2014-9999,CVE-2014-0160"},
		{site.CatalogueParams{Year: 2003}, "m.cve_id LIKE 'CVE-2003-%'", ""},
		// rejected: excluded by default, included on request
		{site.CatalogueParams{Stage: "patch", IncludeRejected: true}, "m.stage = 'patch_released'",
			"CVE-2026-1005,CVE-2026-1003,CVE-2026-1006,CVE-2025-0004,CVE-2025-0001"},
		// tags (SeedTags): network = GPU, 1002; + stage
		{site.CatalogueParams{Tags: []string{"network"}}, "m.cve_id IN ('CVE-2026-102895', 'CVE-2026-1002')",
			"CVE-2026-1002,CVE-2026-102895"},
		{site.CatalogueParams{Tags: []string{"network"}, Stage: "kev"}, "m.cve_id = 'CVE-2026-102895'", "CVE-2026-102895"},
		{site.CatalogueParams{Tags: []string{"network", "no-interaction"}}, "m.cve_id = 'CVE-2026-102895'", "CVE-2026-102895"},
		{site.CatalogueParams{Tags: []string{"crlf-injection"}, Year: 2025}, "false", ""},
	} {
		pg, err := st.Catalogue(ctx, c.p)
		if err != nil {
			t.Fatalf("%+v: %v", c.p, err)
		}
		if got := cids(pg.Rows); got != c.want {
			t.Errorf("%+v: got %s want %s", c.p, got, c.want)
		}
		if ref := refOrder(t, d, c.where); ref != c.want {
			t.Errorf("%+v: reference %s want %s", c.p, ref, c.want)
		}
	}
	pg, _ := st.Catalogue(ctx, site.CatalogueParams{Stage: "Patch", Year: 2025, Tags: []string{" Network "}})
	if pg.Stage == nil || *pg.Stage != "patch_released" || *pg.StageCode != "PAT" || pg.Year == nil || *pg.Year != 2025 ||
		strings.Join(pg.Tags, ",") != "network" {
		t.Errorf("echo %+v", pg)
	}
	// tags are filled in
	for _, r := range page.Rows {
		if r.CVEID == sitetest.GPU && !strings.Contains(strings.Join(r.Tags, ","), "network") {
			t.Errorf("GPU tags %v", r.Tags)
		}
	}
}

// Paging with every limit 1..5, filtered and not: the concatenated pages
// equal the single page (no duplicates, no gaps), across ties on time and
// across the boundary into the undated tail.
func TestCataloguePaging(t *testing.T) {
	st, _ := catSeeded(t)
	for _, base := range []site.CatalogueParams{
		{IncludeRejected: true}, {}, {Stage: "disclosed"}, {Stage: "kev"}, {Stage: "poc"}, {Stage: "patch"},
		{Year: 2014}, {Year: 2025}, {Year: 2025, Stage: "patch"}, {Year: 2014, Stage: "disclosed"}, {Tags: []string{"network"}},
	} {
		full, err := st.Catalogue(ctx, base)
		if err != nil || full.NextCursor != nil {
			t.Fatalf("%+v: %v", base, err)
		}
		for limit := 1; limit <= 5; limit++ {
			p := base
			p.Limit = limit
			var got []string
			seen := map[string]bool{}
			for n := 0; ; n++ {
				if n > 40 {
					t.Fatalf("%+v: no end", p)
				}
				page, err := st.Catalogue(ctx, p)
				if err != nil {
					t.Fatalf("%+v: %v", p, err)
				}
				if len(page.Rows) > limit || (page.NextCursor != nil && len(page.Rows) != limit) {
					t.Errorf("%+v: %d rows", p, len(page.Rows))
				}
				for _, r := range page.Rows {
					if seen[r.CVEID] {
						t.Errorf("%+v: duplicate %s", p, r.CVEID)
					}
					seen[r.CVEID] = true
					got = append(got, r.CVEID)
				}
				if page.NextCursor == nil {
					break
				}
				p.Cursor = *page.NextCursor
			}
			if strings.Join(got, ",") != cids(full.Rows) {
				t.Errorf("%+v limit %d:\n got %s\nwant %s", base, limit, strings.Join(got, ","), cids(full.Rows))
			}
		}
	}
	// a cursor from another filter still continues in order (a stage filter
	// with a cursor of another stage rank, dated and undated)
	all, _ := st.Catalogue(ctx, site.CatalogueParams{})
	idx := func(id string) int {
		for i, r := range all.Rows {
			if r.CVEID == id {
				return i
			}
		}
		return -1
	}
	for _, at := range []int{0, 4, 9, 12, 16, 17, 18} {
		pg, _ := st.Catalogue(ctx, site.CatalogueParams{Limit: at + 1})
		if pg.NextCursor == nil {
			t.Fatalf("no cursor at %d", at)
		}
		for _, stage := range []string{"disclosed", "patch", "poc", "kev"} {
			rest, err := st.Catalogue(ctx, site.CatalogueParams{Stage: stage, Cursor: *pg.NextCursor})
			if err != nil {
				t.Fatal(err)
			}
			whole, _ := st.Catalogue(ctx, site.CatalogueParams{Stage: stage})
			var want []string
			for _, r := range whole.Rows {
				if idx(r.CVEID) > at {
					want = append(want, r.CVEID)
				}
			}
			if cids(rest.Rows) != strings.Join(want, ",") {
				t.Errorf("after %d (%s), stage %s: got %s want %s", at, all.Rows[at].CVEID, stage, cids(rest.Rows), strings.Join(want, ","))
			}
		}
	}
}

func TestCatalogueInputErrors(t *testing.T) {
	st, _ := catSeeded(t)
	next := time.Now().UTC().Year() + 1
	for _, c := range []struct {
		p     site.CatalogueParams
		param string
	}{
		{site.CatalogueParams{Stage: "x"}, "stage"},
		{site.CatalogueParams{Stage: "social_post"}, "stage"},
		{site.CatalogueParams{Year: 1998}, "year"},
		{site.CatalogueParams{Year: next + 1}, "year"},
		{site.CatalogueParams{Year: -1}, "year"},
		{site.CatalogueParams{Limit: 201}, "limit"},
		{site.CatalogueParams{Limit: -1}, "limit"},
		{site.CatalogueParams{Cursor: "zz"}, "cursor"},
		{site.CatalogueParams{Cursor: "djF8MXwxfENWRS0yMDI2LTE"}, "cursor"},
		{site.CatalogueParams{Cursor: strings.Repeat("A", 101)}, "cursor"},
		{site.CatalogueParams{Tags: []string{"nope"}}, "tag"},
		{site.CatalogueParams{Tags: []string{"remote-unauth", "network", "adjacent", "local", "physical", "no-auth"}}, "tag"},
	} {
		var ie *site.InputError
		if _, err := st.Catalogue(ctx, c.p); !errors.As(err, &ie) || ie.Param != c.param {
			t.Errorf("%+v: %v", c.p, err)
		}
	}
	// a hot cursor is not a catalogue cursor
	hot, _ := st.Hot(ctx, site.HotParams{Since: 30 * 24 * time.Hour, Limit: 1})
	if _, err := st.Catalogue(ctx, site.CatalogueParams{Cursor: *hot.NextCursor}); err == nil {
		t.Error("hot cursor accepted")
	}
	for _, ok := range []site.CatalogueParams{{Year: 1999}, {Year: next}, {Limit: 200}, {Limit: 1}} {
		if _, err := st.Catalogue(ctx, ok); err != nil {
			t.Errorf("%+v: %v", ok, err)
		}
	}
}

func TestCatalogueCacheKey(t *testing.T) {
	a, err := site.CatalogueParams{Stage: "PAT", Year: 2025, Tags: []string{"nuclei", "Network", "network"}}.Normalize()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := site.CatalogueParams{Stage: "patch_released", Year: 2025, Tags: []string{"network", "nuclei"}, Limit: 50}.Normalize()
	if a.CacheKey() != b.CacheKey() {
		t.Errorf("%q != %q", a.CacheKey(), b.CacheKey())
	}
	z, _ := site.CatalogueParams{}.Normalize()
	if z.CacheKey() != "vulns||0|false|50||" {
		t.Errorf("zero key %q", z.CacheKey())
	}
	for _, other := range []site.CatalogueParams{{Stage: "poc"}, {Year: 2024}, {IncludeRejected: true}, {Limit: 49}, {Tags: []string{"nuclei"}}} {
		o, _ := other.Normalize()
		if o.CacheKey() == z.CacheKey() || o.CacheKey() == a.CacheKey() {
			t.Errorf("%+v collides: %q", other, o.CacheKey())
		}
	}
}

// Pinning never applies: a CVE pinned on the hot list stays a plain row in
// its ordinary position, and the researcher count is still filled.
func TestCatalogueNoPins(t *testing.T) {
	st, d := catSeeded(t)
	post := pinSeeder(t, d)
	post("CVE-2026-1003", "a1", 1*h)
	post("CVE-2026-1003", "a2", 2*h)
	hot, err := st.Hot(ctx, site.HotParams{})
	if err != nil {
		t.Fatal(err)
	}
	if pinnedOf(t, hot) != "1003" {
		t.Fatalf("precondition: hot pins %q", pinnedOf(t, hot))
	}
	page, err := st.Catalogue(ctx, site.CatalogueParams{Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if cids(page.Rows) != "CVE-2026-1004,CVE-2026-1001,CVE-2026-1002" {
		t.Errorf("first page %s", cids(page.Rows))
	}
	page, _ = st.Catalogue(ctx, site.CatalogueParams{})
	for i, r := range page.Rows {
		if r.Pinned {
			t.Errorf("pinned %s", r.CVEID)
		}
		if r.CVEID == "CVE-2026-1003" && (i != 3 || r.Researchers != 2) {
			t.Errorf("1003 at %d researchers %d", i, r.Researchers)
		}
	}
}

// The catalogue exposes what hot rows expose: the researcher count, never
// a post's text, id, URL, author id or handle.
func TestCatalogueHasNoPostData(t *testing.T) {
	st, d := catSeeded(t)
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('7123456789', 'qzcatauthor', true)`); err != nil {
		t.Fatal(err)
	}
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	at := sitetest.Now.Add(-time.Hour)
	const postID, text = "1987654321987654321", "QZCATMARK secret post text"
	s.Event(sitetest.Ev{CVE: sitetest.GPU, Type: "social_post", Source: "xposts", Occurred: &at, Observed: at, Key: postID,
		URL: sitetest.P("https://x.com/qzcatauthor/status/" + postID),
		Detail: `{"post_id": "` + postID + `", "author_id": "7123456789", "author_handle": "qzcatauthor", "text": "` + text +
			`", "lang": "en", "cves": ["` + sitetest.GPU + `"]}`})
	s.Raw("xposts", postID, "h-qzcat", `{"post": {"id": "`+postID+`", "text": "`+text+`"}}`, at)
	s.Refresh()
	for _, p := range []site.CatalogueParams{{}, {Stage: "kev"}, {Year: 2026}, {Tags: []string{"network"}}, {IncludeRejected: true, Limit: 200}} {
		page, err := st.Catalogue(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := json.Marshal(page)
		body := string(b)
		for _, bad := range []string{"QZCATMARK", postID, "7123456789", "qzcatauthor", "x.com", "social_post", "xposts"} {
			if strings.Contains(strings.ToLower(body), strings.ToLower(bad)) {
				t.Errorf("%+v: response contains %q", p, bad)
			}
		}
		if !strings.Contains(body, `"cve_id":"`+sitetest.GPU+`"`) {
			t.Errorf("%+v: GPU missing", p)
			continue
		}
		for _, r := range page.Rows {
			if r.CVEID == sitetest.GPU && r.Researchers != 1 {
				t.Errorf("GPU researchers_7d %d", r.Researchers)
			}
		}
	}
}
