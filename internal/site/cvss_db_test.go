package site_test

import (
	"errors"
	"math"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
)

// cvssSeed adds, on top of catSeeded, vulnerabilities CVE-2023-00NN (title
// "cvsstest NN") whose scores exercise every branch of the page's rule
// (site/vuln.go assemble, ghsaScore); want is the score the page shows
// ("" = none).
var cvssCases = []struct {
	n    string
	want string
	evs  []sitetest.Ev // CVE filled in
}{
	{"01", "9.8", []sitetest.Ev{{Type: "disclosed", Source: "cvelist", Detail: `{"cvss": {"source": "cna", "base_score": 9.8}}`}}},
	// a CVE record with a cvss object but no score decides: no GHSA fallback
	{"02", "", []sitetest.Ev{
		{Type: "disclosed", Source: "cvelist", Detail: `{"cvss": {"vector": "CVSS:3.1/AV:N"}}`},
		{Type: "patch_released", Source: "ghsa", Detail: `{"cvss": {"cvss_v3": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N"}}}`}}},
	{"03", "9.3", []sitetest.Ev{{Type: "patch_released", Source: "ghsa",
		Detail: `{"cvss": {"cvss_v4": {"score": 9.3, "vector_string": "CVSS:4.0/AV:N"}, "cvss_v3": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N"}}}`}}},
	{"04", "7.5", []sitetest.Ev{{Type: "patch_released", Source: "ghsa",
		Detail: `{"cvss": {"cvss_v4": {"score": 0.0, "vector_string": null}, "cvss_v3": {"score": 7.5, "vector_string": "CVSS:3.1/AV:N"}}}`}}},
	{"05", "5.3", []sitetest.Ev{{Type: "patch_released", Source: "ghsa", Detail: `{"cvss": {"score": 5.3, "vector_string": "CVSS:3.1/AV:N"}}`}}},
	// the first patch event (by effective time, unknown last) with a score
	{"06", "6.1", []sitetest.Ev{
		{Type: "patch_released", Source: "ghsa", Backfill: true, Key: "u", Detail: `{"cvss": {"score": 9.9, "vector_string": "CVSS:3.1/AV:N"}}`},
		{Type: "patch_released", Source: "ghsa", Key: "a", Detail: `{}`},
		{Type: "patch_released", Source: "ghsa", Key: "b", Detail: `{"cvss": {"cvss_v3": {"score": 6.1, "vector_string": "CVSS:3.1/AV:N"}}}`},
		{Type: "patch_released", Source: "ghsa", Key: "c", Detail: `{"cvss": {"cvss_v3": {"score": 8.8, "vector_string": "CVSS:3.1/AV:N"}}}`}}},
	{"07", "", []sitetest.Ev{{Type: "disclosed", Source: "cvelist", Detail: `{"cvss": {"base_score": "9.8"}}`}}},
	{"08", "", []sitetest.Ev{{Type: "disclosed", Source: "nvd"}}},
	{"09", "0", []sitetest.Ev{{Type: "disclosed", Source: "cvelist", Detail: `{"cvss": {"base_score": 0, "base_severity": "NONE"}}`}}},
	{"10", "4", []sitetest.Ev{
		{Type: "disclosed", Source: "cvelist", Detail: `{"cvss": {"base_score": 4.0}}`},
		{Type: "patch_released", Source: "ghsa", Detail: `{"cvss": {"cvss_v3": {"score": 9.0, "vector_string": "CVSS:3.1/AV:N"}}}`}}},
	{"11", "10", []sitetest.Ev{{Type: "disclosed", Source: "cvelist", Detail: `{"cvss": {"base_score": 10}}`}}},
	{"12", "3.1", []sitetest.Ev{{Type: "patch_released", Source: "ghsa",
		Detail: `{"cvss": {"cvss_v4": {"score": 9.1, "vector_string": "   "}, "cvss_v3": {"score": 3.1, "vector_string": "CVSS:3.1/AV:N"}}}`}}},
	{"13", "7", []sitetest.Ev{{Type: "disclosed", Source: "cvelist", Detail: `{"state": "REJECTED", "cvss": {"base_score": 7.0}}`}}},
}

func cvssSeeded(t *testing.T) (*site.Store, *testutil.TestDB) {
	st, d := catSeeded(t)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	for i, c := range cvssCases {
		id := "CVE-2023-00" + c.n
		s.Vuln(id, sitetest.P("cvsstest "+c.n))
		for j, e := range c.evs {
			e.CVE = id
			if e.Key == "" {
				e.Key = e.Source
			}
			if !e.Backfill {
				at := sitetest.Day(2023, 1, 1).Add(time.Duration(i*24+j) * time.Hour)
				e.Occurred = &at
			}
			s.Event(e)
		}
	}
	s.Refresh()
	return st, d
}

// in2023 is the ids of rows from CVE-2023-, shortened and sorted.
func in2023(ids []string) string {
	var out []string
	for _, id := range ids {
		if strings.HasPrefix(id, "CVE-2023-00") {
			out = append(out, strings.TrimPrefix(id, "CVE-2023-00"))
		}
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func rowIDs(rows []site.HotRow) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.CVEID
	}
	return out
}

// vuln_score_mat holds exactly the score each vulnerability page shows, for
// the cases above and every vulnerability of the shared fixture.
func TestVulnScoreMatchesPage(t *testing.T) {
	st, d := cvssSeeded(t)
	rows, err := d.Conn.Query(ctx, `SELECT m.cve_id, sc.score::float8 FROM vuln_state_mat m
        LEFT JOIN vuln_score_mat sc USING (cve_id) ORDER BY m.cve_id`)
	if err != nil {
		t.Fatal(err)
	}
	mat := map[string]*float64{}
	for rows.Next() {
		var id string
		var sc *float64
		if err := rows.Scan(&id, &sc); err != nil {
			t.Fatal(err)
		}
		mat[id] = sc
	}
	rows.Close()
	if len(mat) < 30 {
		t.Fatalf("only %d vulnerabilities", len(mat))
	}
	scored := 0
	for id, sc := range mat {
		v, found, err := st.Vuln(ctx, id)
		if err != nil || !found {
			t.Fatalf("%s: %v %v", id, found, err)
		}
		var page *float64
		if v.CVSS != nil && v.CVSS.Score != nil && *v.CVSS.Score >= 0 && *v.CVSS.Score <= 10 {
			r := math.Round(*v.CVSS.Score*10) / 10
			page = &r
		}
		switch {
		case (page == nil) != (sc == nil):
			t.Errorf("%s: page %v, vuln_score_mat %v", id, fp(page), fp(sc))
		case page != nil && *page != *sc:
			t.Errorf("%s: page %v, vuln_score_mat %v", id, *page, *sc)
		case sc != nil:
			scored++
		}
	}
	for _, c := range cvssCases {
		sc := mat["CVE-2023-00"+c.n]
		got := ""
		if sc != nil {
			got = strconv.FormatFloat(*sc, 'f', -1, 64)
		}
		if got != c.want {
			t.Errorf("CVE-2023-00%s: score %q, want %q", c.n, got, c.want)
		}
	}
	if scored < 10 {
		t.Errorf("only %d scored", scored)
	}
}

func fp(f *float64) any {
	if f == nil {
		return "none"
	}
	return *f
}

func asInput(err error, ie **site.InputError) bool { return errors.As(err, ie) }

func TestCatalogueCVSSFilter(t *testing.T) {
	st, d := cvssSeeded(t)
	for _, c := range []struct {
		p    site.CatalogueParams
		want string
	}{
		{site.CatalogueParams{CVSSMin: "9"}, "01,03,11"},
		{site.CatalogueParams{CVSSMin: "7", CVSSMax: "8.9"}, "04"},
		{site.CatalogueParams{CVSSMin: "7", CVSSMax: "8.9", IncludeRejected: true}, "04,13"},
		{site.CatalogueParams{CVSSMin: "9.8", CVSSMax: "9.8"}, "01"}, // exact
		{site.CatalogueParams{CVSSMin: "9.7", CVSSMax: "9.7"}, ""},
		{site.CatalogueParams{CVSSMin: "0", CVSSMax: "0"}, "09"},
		{site.CatalogueParams{CVSSMax: "3.9"}, "09,12"},
		{site.CatalogueParams{CVSSMin: "0.1", CVSSMax: "3.9"}, "12"}, // the low band
		// no bound left out: every scored one, never 02, 07, 08 (no score)
		{site.CatalogueParams{CVSSMin: "0", CVSSMax: "10"}, "01,03,04,05,06,09,10,11,12"},
		{site.CatalogueParams{CVSSMin: "0", IncludeRejected: true}, "01,03,04,05,06,09,10,11,12,13"},
		{site.CatalogueParams{}, "01,02,03,04,05,06,07,08,09,10,11,12"},
		// with the other filters
		{site.CatalogueParams{CVSSMin: "5", Stage: "patch"}, "03,04,05,06"},
		{site.CatalogueParams{CVSSMin: "4", CVSSMax: "4", Stage: "patch", Year: 2023}, "10"},
		{site.CatalogueParams{CVSSMin: "9", Year: 2014}, ""},
		{site.CatalogueParams{CVSSMin: "9", Stage: "kev"}, ""},
	} {
		page, err := st.Catalogue(ctx, c.p)
		if err != nil {
			t.Fatalf("%+v: %v", c.p, err)
		}
		if got := in2023(rowIDs(page.Rows)); got != c.want {
			t.Errorf("%+v: got %s want %s", c.p, got, c.want)
		}
		// the whole page in catalogue order, against SQL written independently
		where := refWhere(c.p)
		if got, want := cids(page.Rows), refOrder(t, d, where); got != want {
			t.Errorf("%+v:\n got %s\nwant %s", c.p, got, want)
		}
		n, ok, err := st.CatalogueCount(ctx, c.p)
		if err != nil || !ok || n != int64(len(page.Rows)) {
			t.Errorf("%+v: count %d %v %v, rows %d", c.p, n, ok, err, len(page.Rows))
		}
		p, _ := c.p.Normalize()
		if (p.CVSSMin == "") != (page.CVSSMin == nil) || (p.CVSSMax == "") != (page.CVSSMax == nil) {
			t.Errorf("%+v: page bounds %v %v", c.p, fp(page.CVSSMin), fp(page.CVSSMax))
		}
	}
	// with a tag filter (fixture tags): same as the independent SQL
	for _, tg := range []string{"network", "remote-unauth", "nuclei"} {
		p := site.CatalogueParams{CVSSMin: "7", Tags: []string{tg}, IncludeRejected: true}
		page, err := st.Catalogue(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		want := refOrder(t, d, refWhere(p)+` AND EXISTS (SELECT 1 FROM vuln_tag_visible t WHERE t.cve_id = m.cve_id AND t.tag = '`+tg+`')`)
		if cids(page.Rows) != want {
			t.Errorf("tag %s: got %s want %s", tg, cids(page.Rows), want)
		}
		all, _ := st.Catalogue(ctx, site.CatalogueParams{Tags: []string{tg}, IncludeRejected: true})
		if len(all.Rows) == len(page.Rows) && tg == "network" {
			t.Errorf("tag %s: the score filter removed nothing (%d rows); the case proves nothing", tg, len(all.Rows))
		}
	}
	v, _ := st.Catalogue(ctx, site.CatalogueParams{CVSSMin: "9.0", CVSSMax: "10.0"})
	if v.CVSSMin == nil || *v.CVSSMin != 9 || v.CVSSMax == nil || *v.CVSSMax != 10 {
		t.Errorf("bounds %v %v", fp(v.CVSSMin), fp(v.CVSSMax))
	}
}

// refWhere is the catalogue's WHERE for p written out by hand (stage, year,
// rejected, score; no tags).
func refWhere(p site.CatalogueParams) string {
	w := []string{"true"}
	if !p.IncludeRejected {
		w = append(w, "NOT m.is_rejected")
	}
	if p.Stage != "" {
		st, _ := site.ParseStage(p.Stage)
		w = append(w, "m.stage = '"+st+"'")
	}
	if p.Year != 0 {
		w = append(w, "m.cve_id LIKE 'CVE-"+strconv.Itoa(p.Year)+"-%'")
	}
	if p.CVSSMin != "" || p.CVSSMax != "" {
		lo, hi := p.CVSSMin, p.CVSSMax
		if lo == "" {
			lo = "0"
		}
		if hi == "" {
			hi = "10"
		}
		w = append(w, "m.cve_id IN (SELECT cve_id FROM vuln_score_mat WHERE score BETWEEN "+lo+" AND "+hi+")")
	}
	return strings.Join(w, " AND ")
}

func TestCatalogueCVSSPaging(t *testing.T) {
	st, _ := cvssSeeded(t)
	for _, base := range []site.CatalogueParams{
		{CVSSMin: "0"}, {CVSSMin: "7", IncludeRejected: true}, {CVSSMin: "5", Stage: "patch"}, {CVSSMax: "9.8"},
		{CVSSMin: "0", Year: 2023}, {CVSSMin: "0", Tags: []string{"network"}},
	} {
		full, err := st.Catalogue(ctx, base)
		if err != nil || full.NextCursor != nil {
			t.Fatalf("%+v: %v", base, err)
		}
		for limit := 1; limit <= 4; limit++ {
			p := base
			p.Limit = limit
			var got []string
			var pages []*site.CataloguePage
			for n := 0; ; n++ {
				if n > 60 {
					t.Fatalf("%+v: no end", p)
				}
				page, err := st.Catalogue(ctx, p)
				if err != nil {
					t.Fatalf("%+v: %v", p, err)
				}
				pages = append(pages, page)
				got = append(got, rowIDs(page.Rows)...)
				if page.NextCursor == nil {
					break
				}
				p.Cursor = *page.NextCursor
			}
			if strings.Join(got, ",") != cids(full.Rows) {
				t.Errorf("%+v limit %d:\n got %s\nwant %s", base, limit, strings.Join(got, ","), cids(full.Rows))
			}
			// paging back from every later page gives the page before it
			for i := 1; i < len(pages); i++ {
				if pages[i].PrevCursor == nil {
					t.Fatalf("%+v limit %d: page %d has no prev cursor", base, limit, i)
				}
				q := base
				q.Limit, q.Before = limit, *pages[i].PrevCursor
				back, err := st.Catalogue(ctx, q)
				if err != nil {
					t.Fatal(err)
				}
				if cids(back.Rows) != cids(pages[i-1].Rows) {
					t.Errorf("%+v limit %d: back from page %d: %s, want %s", base, limit, i, cids(back.Rows), cids(pages[i-1].Rows))
				}
			}
		}
	}
	// the score filter is part of the cache keys
	a, _ := site.CatalogueParams{CVSSMin: "9"}.Normalize()
	b, _ := site.CatalogueParams{CVSSMin: "9", CVSSMax: "10"}.Normalize()
	z, _ := site.CatalogueParams{}.Normalize()
	c, _ := site.CatalogueParams{CVSSMin: "9.0"}.Normalize()
	if a.CacheKey() == z.CacheKey() || a.CacheKey() == b.CacheKey() || a.CountKey() == z.CountKey() || a.CountKey() == b.CountKey() ||
		a.CacheKey() != c.CacheKey() {
		t.Errorf("keys %q %q %q %q", a.CacheKey(), b.CacheKey(), z.CacheKey(), c.CacheKey())
	}
}

func TestCatalogueCVSSInputErrors(t *testing.T) {
	st, _ := catSeeded(t)
	for _, c := range []struct {
		p     site.CatalogueParams
		param string
	}{
		{site.CatalogueParams{CVSSMin: "-1"}, "cvss_min"},
		{site.CatalogueParams{CVSSMin: "11"}, "cvss_min"},
		{site.CatalogueParams{CVSSMax: "NaN"}, "cvss_max"},
		{site.CatalogueParams{CVSSMax: "1e1"}, "cvss_max"},
		{site.CatalogueParams{CVSSMin: "9,8"}, "cvss_min"},
		{site.CatalogueParams{CVSSMin: "9", CVSSMax: "8"}, "cvss_max"},
		{site.CatalogueParams{CVSSMin: "1); DROP TABLE vuln; --"}, "cvss_min"},
	} {
		var ie *site.InputError
		if _, err := st.Catalogue(ctx, c.p); !asInput(err, &ie) || ie.Param != c.param {
			t.Errorf("%+v: %v", c.p, err)
		}
		if _, _, err := st.CatalogueCount(ctx, c.p); !asInput(err, &ie) || ie.Param != c.param {
			t.Errorf("count %+v: %v", c.p, err)
		}
	}
}

func TestSearchCVSSFilter(t *testing.T) {
	st, _ := cvssSeeded(t)
	for _, c := range []struct {
		q    string
		f    site.SearchFilter
		kind string
		want string
	}{
		{"cvsstest", site.SearchFilter{}, site.SearchText, "01,02,03,04,05,06,07,08,09,10,11,12,13"},
		{"cvsstest", site.SearchFilter{CVSSMin: "9"}, site.SearchText, "01,03,11"},
		{"cvsstest", site.SearchFilter{CVSSMin: "7", CVSSMax: "8.9"}, site.SearchText, "04,13"}, // search lists rejected ones
		{"cvsstest", site.SearchFilter{CVSSMin: "9.3", CVSSMax: "9.3"}, site.SearchText, "03"},
		{"CVE-2023-00", site.SearchFilter{CVSSMax: "3.9"}, site.SearchCVE, "09,12"},
		{"CVE-2023-0001", site.SearchFilter{CVSSMin: "9.9"}, site.SearchCVE, ""},
		// a blank query with only a score filter searches nothing
		{"", site.SearchFilter{CVSSMin: "9"}, site.SearchEmpty, ""},
	} {
		res, err := st.SearchFiltered(ctx, c.q, c.f, 50)
		if err != nil {
			t.Fatalf("%q %+v: %v", c.q, c.f, err)
		}
		ids := make([]string, len(res.Rows))
		for i, r := range res.Rows {
			ids[i] = r.CVEID
		}
		if res.Kind != c.kind || in2023(ids) != c.want {
			t.Errorf("%q %+v: %s %s, want %s %s", c.q, c.f, res.Kind, in2023(ids), c.kind, c.want)
		}
	}
	// with a tag: the tags listing narrowed by score, every row scored in range
	all, _ := st.SearchFiltered(ctx, "", site.SearchFilter{Tags: []string{"network"}}, 50)
	hi, err := st.SearchFiltered(ctx, "", site.SearchFilter{Tags: []string{"network"}, CVSSMin: "9"}, 50)
	if err != nil || hi.Kind != site.SearchTags || hi.CVSSMin == nil || *hi.CVSSMin != 9 || hi.CVSSMax != nil {
		t.Fatalf("%+v %v", hi, err)
	}
	if len(hi.Rows) == 0 || len(hi.Rows) >= len(all.Rows) {
		t.Errorf("network: %d rows with score >= 9 of %d", len(hi.Rows), len(all.Rows))
	}
	for _, r := range hi.Rows {
		v, _, _ := st.Vuln(ctx, r.CVEID)
		if v.CVSS == nil || v.CVSS.Score == nil || *v.CVSS.Score < 9 {
			t.Errorf("%s: score %+v", r.CVEID, v.CVSS)
		}
	}
	var ie *site.InputError
	if _, err := st.SearchFiltered(ctx, "cvsstest", site.SearchFilter{CVSSMin: "10.5"}, 10); !asInput(err, &ie) || ie.Param != "cvss_min" {
		t.Errorf("bad bound: %v", err)
	}
}
