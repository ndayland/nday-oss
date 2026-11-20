package webui_test

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/tags"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/web/webtest"
	"nday.land/nday/internal/webui"
)

// Vulnerabilities of the title tests (docs/titles.md):
const (
	tComposed = "CVE-2026-7001" // no record title: composed "Java SE: buffer overflow / out-of-bounds write in Compiler"
	tStaff    = "CVE-2026-7002" // record title and a hostile staff title
	tUntitled = "CVE-2026-7003" // nothing to compose from: stays untitled
	tHostile  = "CVE-2026-7004" // no record title; hostile product and component
	tRecord   = "CVE-2026-7005" // the record's own title only
	staffEvil = `Staff <img src=x onerror=alert(9)> & "co"`
)

func newTitlesEnv(t *testing.T) *tenv {
	t.Helper()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	ctx := context.Background()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := d.Conn.Exec(ctx, q, args...); err != nil {
			t.Fatalf("%v\n%s", err, q)
		}
	}
	for i, id := range []string{tComposed, tStaff, tUntitled, tHostile, tRecord} {
		var title *string
		if id == tStaff || id == tRecord {
			title = sitetest.P("Record title of " + id)
		}
		s.Vuln(id, title)
		s.Event(sitetest.Ev{CVE: id, Type: "disclosed", Source: "cvelist", Occurred: sitetest.P(sitetest.Ago(5)),
			Detail: `{"state": "PUBLISHED"}`})
		s.Event(sitetest.Ev{CVE: id, Type: "poc_published", Source: "exploitdb", Occurred: sitetest.P(sitetest.Ago(1 + float64(i)/10)),
			Key: "70" + id[len(id)-2:], Detail: `{"kind": "exploit", "confidence": "curated", "title": "x", "url": "https://www.exploit-db.com/exploits/1"}`})
	}
	exec(`UPDATE vuln SET description = $2 WHERE cve_id = $1`, tComposed,
		"Vulnerability in the Oracle Java SE product of Oracle Java SE (component: Compiler). Supported versions that are affected are 8u471.")
	s.Affected(tComposed, "Oracle Corporation", "Java SE")
	exec(`INSERT INTO vuln_cwe (cve_id, cwe, source) VALUES ($1, 'CWE-787', 'cve-cna')`, tComposed)
	exec(`UPDATE vuln SET description = $2 WHERE cve_id = $1`, tHostile,
		"Vulnerability in Evil (component: <b>Core</b> & \"Kit\u202e\").")
	s.Affected(tHostile, "Acme", `Evil <svg onload=alert(3)>`)
	if _, err := tags.All(ctx, d.Conn, tags.Options{Wait: true}); err != nil {
		t.Fatal(err)
	}
	exec(`UPDATE vuln_title SET staff_title = $2, staff_at = now(), staff_version = 1 WHERE cve_id = $1`, tStaff, staffEvil)
	// researchers discuss the composed one (the /discussed ranking)
	exec(`INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('7007', 'res_one', true)`)
	s.Event(sitetest.Ev{CVE: tComposed, Type: "social_post", Source: "xposts", Occurred: sitetest.P(sitetest.Ago(1)), Key: "7001001",
		Detail: `{"author_id": "7007", "author_handle": "res_one", "post_id": "7001001", "text": "t", "cves": ["` + tComposed + `"]}`})
	s.Refresh()
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 3, Dial: testutil.Dial(cfg)})
	t.Cleanup(pool.Close)
	now := func() time.Time { return sitetest.Now }
	srv := web.New(web.Config{Store: site.New(pool).WithClock(now), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	srv.SetAPIAuth(webtest.BearerAuth{})
	ui, err := webui.New(srv, webui.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	return &tenv{ts: ts, ui: ui}
}

const composedEN = "Java SE: buffer overflow / out-of-bounds write in Compiler"

// jsonRows decodes the rows (or the object) of an API answer by CVE id.
func jsonTitles(t *testing.T, body string) map[string][3]any {
	t.Helper()
	var v any
	if err := json.Unmarshal([]byte(body), &v); err != nil {
		t.Fatalf("%v: %s", err, body)
	}
	out := map[string][3]any{}
	var walk func(any)
	walk = func(x any) {
		switch y := x.(type) {
		case map[string]any:
			if id, ok := y["cve_id"].(string); ok {
				if _, has := y["effective_title"]; has {
					out[id] = [3]any{y["title"], y["effective_title"], y["title_origin"]}
				}
			}
			for _, z := range y {
				walk(z)
			}
		case []any:
			for _, z := range y {
				walk(z)
			}
		}
	}
	walk(v)
	return out
}

// The JSON API: title unchanged (the record's title or null), the new
// effective_title and title_origin on every surface; search matches the
// composed and the staff title; an untitled vulnerability stays untitled.
func TestTitlesAPI(t *testing.T) {
	e := newTitlesEnv(t)
	want := map[string][3]any{
		tComposed: {nil, composedEN, "composed"},
		tStaff:    {"Record title of " + tStaff, staffEvil, "staff"},
		tUntitled: {nil, nil, nil},
		tRecord:   {"Record title of " + tRecord, "Record title of " + tRecord, "record"},
	}
	for _, path := range []string{"/api/hot?since=30d&min_stage=poc_published", "/api/vulns", "/api/vuln/" + tComposed,
		"/api/vuln/" + tStaff, "/api/vuln/" + tUntitled, "/api/vuln/" + tRecord, "/api/discussed", "/api/search?q=CVE-2026-700"} {
		resp, body := e.get(t, path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		got := jsonTitles(t, body)
		if len(got) == 0 {
			t.Errorf("%s: no rows with effective_title", path)
		}
		for id, g := range got {
			if w, ok := want[id]; ok && g != w {
				t.Errorf("%s %s: got %v, want %v", path, id, g, w)
			}
		}
		if path == "/api/discussed" && got[tComposed] != want[tComposed] {
			t.Errorf("discussed: %v", got)
		}
	}
	// search by words of the composed title and of the staff title
	for q, id := range map[string]string{"out-of-bounds write in Compiler": tComposed, "onerror=alert(9)": tStaff} {
		_, body := e.get(t, "/api/search?q="+strings.ReplaceAll(strings.ReplaceAll(q, " ", "+"), "=", "%3D"))
		if _, ok := jsonTitles(t, body)[id]; !ok {
			t.Errorf("search %q does not find %s: %s", q, id, body)
		}
	}
	// hostile record text: the composed title is plain text (markup and
	// bidi controls removed), JSON-escaped like every string
	_, body := e.get(t, "/api/vuln/"+tHostile)
	if got := jsonTitles(t, body)[tHostile]; got != [3]any{nil, `Acme Evil: vulnerability in Core & "Kit"`, "composed"} ||
		!strings.Contains(body, `"effective_title":"Acme Evil: vulnerability in Core & \"Kit\""`) {
		t.Errorf("hostile JSON: %v", got)
	}
	_, body = e.get(t, "/api/vuln/"+tStaff)
	if !strings.Contains(body, `"effective_title":"Staff <img src=x onerror=alert(9)> & \"co\""`) {
		t.Errorf("staff JSON: %s", grep(body, "effective_title"))
	}
}

var markRe = regexp.MustCompile(`<span class="tmark" title="([^"]*)" data-origin="(composed|staff)"><span aria-hidden="true">\x{2060}\*</span><span class="sr">([^<]*)</span></span>`)

// Pages: a composed or staff title is shown as a title with one marker; the
// record's own has none; untitled keeps its wording; hostile text is
// escaped in HTML and the feed; the page title and meta carry the title.
func TestTitlesPages(t *testing.T) {
	e := newTitlesEnv(t)
	_, page := e.get(t, "/vuln/"+tComposed)
	if !strings.Contains(page, `<h1 class="vt">`+composedEN+`<span class="tmark"`) {
		t.Errorf("composed h1: %s", grep(page, "<h1"))
	}
	m := markRe.FindAllStringSubmatch(page, -1)
	if len(m) != 1 || m[0][2] != "composed" || m[0][1] != "Title composed by nday; the CVE record has none." || m[0][3] != m[0][1] {
		t.Errorf("composed marker: %v", m)
	}
	if !strings.Contains(page, "<title>") || !strings.Contains(grep(page, "<title>"), "Java SE: buffer overflow") ||
		!strings.Contains(grep(page, `name="description"`), "Java SE: buffer overflow") {
		t.Errorf("title/meta: %s %s", grep(page, "<title>"), grep(page, `name="description"`))
	}
	_, zh := e.get(t, "/zh-hans/vuln/"+tComposed)
	if !strings.Contains(zh, `<h1 class="vt">Java SE：Compiler 中的 buffer overflow / out-of-bounds write<span class="tmark" title="标题由 nday 生成；CVE 记录未提供标题。" data-origin="composed">`) {
		t.Errorf("zh h1: %s", grep(zh, "<h1"))
	}
	_, page = e.get(t, "/vuln/"+tStaff)
	if m := markRe.FindAllStringSubmatch(page, -1); len(m) != 1 || m[0][2] != "staff" || m[0][1] != "Title set by nday staff." {
		t.Errorf("staff marker: %v", m)
	}
	if strings.Contains(page, "<img src=x") || !strings.Contains(page, `Staff &lt;img src=x onerror=alert(9)&gt; &amp; &#34;co&#34;`) {
		t.Errorf("staff title not escaped: %s", grep(page, "<h1"))
	}
	_, page = e.get(t, "/vuln/"+tRecord)
	if strings.Contains(page, `class="tmark"`) || !strings.Contains(page, `>Record title of `+tRecord+`</h1>`) {
		t.Errorf("record title page: %s", grep(page, "<h1"))
	}
	_, page = e.get(t, "/vuln/"+tUntitled)
	if strings.Contains(page, `class="tmark"`) || !strings.Contains(page, `<h1 class="vt missing">(the CVE record has no title)</h1>`) {
		t.Errorf("untitled page: %s", grep(page, "<h1"))
	}
	_, page = e.get(t, "/vuln/"+tHostile)
	if strings.Contains(page, "<b>Core") || strings.Contains(grep(page, "<h1"), "\u202e") ||
		!strings.Contains(page, `<h1 class="vt">Acme Evil: vulnerability in Core &amp; &#34;Kit&#34;<span class="tmark"`) {
		t.Errorf("hostile page: %s", grep(page, "<h1"))
	}
	// the hot list: the marker after the composed and staff titles only
	_, page = e.get(t, "/?since=30d&min_stage=poc_published")
	for id, origin := range map[string]string{tComposed: "composed", tStaff: "staff", tRecord: "", tUntitled: ""} {
		row := rowOf(page, id)
		if row == "" {
			t.Fatalf("hot list: no row %s", id)
		}
		has := markRe.FindStringSubmatch(row)
		if (origin == "") != (has == nil) || (has != nil && has[2] != origin) {
			t.Errorf("hot row %s: marker %v, want %q", id, has, origin)
		}
		if origin != "" && !strings.Contains(row, `class="ttl tm"`) {
			t.Errorf("hot row %s: no tm class", id)
		}
	}
	if !strings.Contains(rowOf(page, tUntitled), `class="ttl missing"`) {
		t.Errorf("untitled hot row: %s", rowOf(page, tUntitled))
	}
	// search page and /discussed
	_, page = e.get(t, "/vuln?q=Compiler")
	if !strings.Contains(page, `<span class="ttx">`+composedEN+`</span><span class="tmark"`) {
		t.Errorf("search page: %s", grep(page, tComposed))
	}
	_, page = e.get(t, "/discussed")
	if row := rowOf(page, tComposed); markRe.FindString(row) == "" {
		t.Errorf("discussed row: %s", row)
	}
	// the feed: the effective title, escaped
	_, feed := e.get(t, "/feed.xml?min_stage=poc_published")
	if strings.Contains(feed, "<img src=x") || !strings.Contains(feed, "Staff &lt;img src=x onerror=alert(9)&gt; &amp;") {
		t.Errorf("feed: staff title not escaped: %s", grep(feed, tStaff))
	}
	if !strings.Contains(feed, "<title>+POC "+tComposed+" "+composedEN+"</title>") {
		t.Errorf("feed lacks the composed title: %s", grep(feed, tComposed))
	}
}

// grep returns the lines of s containing sub.
func grep(s, sub string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// rowOf is the list row of id (from its element to the next row).
func rowOf(page, id string) string {
	i := strings.Index(page, `data-id="`+id+`"`)
	if i < 0 {
		return ""
	}
	rest := page[i:]
	// up to the next row: a table row, or a /discussed list row
	for _, next := range []string{`role="row"`, `<li class="dzr"`} {
		if j := strings.Index(rest[1:], next); j > 0 {
			rest = rest[:j+1]
		}
	}
	return rest
}
