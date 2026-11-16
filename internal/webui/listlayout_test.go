package webui_test

import (
	"context"
	"io"
	"log/slog"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui"
)

// A hot list row's vulnerability cell: the title first, on its own line
// (aria-hidden, out of the tab order), then one line with the ID link, its
// badges, the tags and the products.
func TestHotRowTitleOwnLine(t *testing.T) {
	e := newEnv(t)
	for _, p := range []string{"/", "/tag/auth-bypass", "/zh-hans/"} {
		_, body := e.get(t, p)
		i := strings.Index(body, `<div class="tr" role="row" data-row=""`)
		if i < 0 {
			t.Fatalf("%s: no row", p)
		}
		row := body[i:]
		row = row[:strings.Index(row, `<div class="stc" role="cell">`)]
		ttl := strings.Index(row, `<a class="ttl`)
		l1 := strings.Index(row, `<div class="l1"><a class="id" href=`)
		vend := strings.Index(row, `<span class="vend">`)
		vn := strings.Index(row, `<span class="vn">`)
		if ttl < 0 || l1 < 0 || vend < 0 || vn < 0 || !(ttl < l1 && l1 < vend && vend < vn) {
			t.Errorf("%s: cell order ttl=%d l1=%d vend=%d vn=%d\n%s", p, ttl, l1, vend, vn, row)
		}
		if !regexp.MustCompile(`<a class="ttl[^"]*" href="[^"]+" tabindex="-1" aria-hidden="true"`).MatchString(row) {
			t.Errorf("%s: title link not hidden from the tab order and assistive technology\n%s", p, row)
		}
		// the title closes before the second line opens: never on the ID's line
		if strings.Contains(row[l1:], `class="ttl`) {
			t.Errorf("%s: title on the ID line", p)
		}
	}
}

// The hot list and tag pages fold their filters into a disclosure (open in
// the HTML; app.js closes it on phones) whose summary names the selection.
func TestHotFilterDisclosure(t *testing.T) {
	e := newEnv(t)
	_, body := e.get(t, "/")
	for _, want := range []string{
		`<details class="flt" open="">` + "\n" + `<summary><span class="k">Filters</span> <span class="sep" aria-hidden="true">·</span> 7d <span class="sep" aria-hidden="true">·</span> patch</summary>` + "\n" + `<div class="flags">`,
		`<p class="lede hot-lede">`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("/ missing %q", want)
		}
	}
	_, body = e.get(t, "/?since=30d&include_rejected=1")
	if !strings.Contains(body, `<details class="flt" open="" data-keep="">`) || !strings.Contains(body, `·</span> 30d `) ||
		!strings.Contains(body, `·</span> Include rejected IDs</summary>`) {
		t.Error("a selection other than the defaults: no data-keep or no summary of it")
	}
	_, body = e.get(t, "/tag/auth-bypass")
	if !strings.Contains(body, `<details class="flt" open="">`) {
		t.Error("tag page: no filter disclosure")
	}
	b, err := os.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `flt.open = !mq.matches || flt.hasAttribute('data-keep')`) {
		t.Error("app.js does not fold the filters on phones")
	}
}

var bareCmd = regexp.MustCompile(`(?s)(.{0,40})<div class="cmd">`)

// Public pages show their API command only inside a closed disclosure.
func TestAPICommandsFolded(t *testing.T) {
	e := newEnv(t)
	for p, summary := range map[string]string{
		"/tags":                 "Get this list from the API",
		"/src":                  "Get this list from the API",
		"/stats":                "Get these figures from the API",
		"/vuln/" + sitetest.GPU: "Get this record from the API",
		"/":                     "Get this list from the API",
		"/discussed":            "Get this list from the API",
	} {
		_, body := e.get(t, p)
		want := `<details class="apid">` + "\n<summary>" + summary + "</summary>\n" + `<div class="cmd">`
		if !strings.Contains(body, want) {
			t.Errorf("%s: no folded API command %q", p, summary)
		}
		for _, m := range bareCmd.FindAllStringSubmatch(body, -1) {
			if !strings.HasSuffix(m[1], "</summary>\n") {
				t.Errorf("%s: an open command box after %q", p, m[1])
			}
		}
	}
}

// The formatting help of the discussion is hidden in the HTML; discuss.js
// shows it with the compose box only (signed in and allowed to write).
func TestFormattingHelpOnlyForWriters(t *testing.T) {
	f := &fakeDisc{version: "v1", outline: outlineFixture()}
	e := newDiscEnv(t, webui.Options{Accounts: discAccounts, Discussions: f})
	_, body := e.get(t, "/vuln/"+sitetest.GPU)
	if !strings.Contains(body, `<details class="disc-md" id="disc-md" hidden="">`) {
		t.Error("formatting help not hidden for a signed-out visitor")
	}
	b, err := os.ReadFile("static/discuss.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `if (md) md.hidden = id !== 'disc-new';`) {
		t.Error("discuss.js does not tie the formatting help to the compose box")
	}
}

// The vulnerability page says once that the text is upstream's: the note under
// the title goes when the summary carries its source line, and stays for an
// upstream title without one.
func TestSingleUpstreamNote(t *testing.T) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	if _, err := d.Conn.Exec(context.Background(), `UPDATE vuln SET description = 'Upstream text.' WHERE cve_id = $1`, sitetest.GPU); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 2})
	t.Cleanup(pool.Close)
	now := func() time.Time { return sitetest.Now }
	srv := web.New(web.Config{Store: site.New(pool).WithClock(now), Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	if _, err := webui.New(srv, webui.Options{Now: now}); err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	e := &tenv{ts: ts}
	const top = "标题与描述为上游英文原文。"
	_, body := e.get(t, "/zh-hans/vuln/"+sitetest.GPU)
	if !strings.Contains(body, "未经改写") || strings.Contains(body, top) {
		t.Errorf("%s: want the summary source line only (src %v, top %v)", sitetest.GPU, strings.Contains(body, "未经改写"), strings.Contains(body, top))
	}
	checked := 0
	for _, id := range []string{"CVE-2026-1001", "CVE-2026-1002", "CVE-2026-1004", "CVE-2026-1005", "CVE-2026-1006"} {
		resp, body := e.get(t, "/zh-hans/vuln/"+id)
		if resp.StatusCode != 200 || !strings.Contains(body, `<h1 class="vt" lang="en">`) {
			continue
		}
		checked++
		if strings.Contains(body, "未经改写") || strings.Count(body, top) != 1 {
			t.Errorf("%s: an upstream title without a summary keeps its one note", id)
		}
	}
	if checked == 0 {
		t.Error("no page with an upstream title and no summary checked")
	}
}
