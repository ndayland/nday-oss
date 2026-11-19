package webui_test

import (
	"html"
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
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/web/webtest"
	"nday.land/nday/internal/webui"
)

// newDeadStoreEnv is a seeded site whose database pool is closed before the
// first request: any page that reads the store fails (500). A page that
// answers 200 here ran no query at all.
func newDeadStoreEnv(t *testing.T) *tenv {
	t.Helper()
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	sitetest.Seed(t, d.Conn)
	cfg, err := pgx.ParseConfig(d.URL)
	if err != nil {
		t.Fatal(err)
	}
	pool := dbpool.New(cfg, dbpool.Options{Size: 1})
	t.Cleanup(pool.Close)
	now := func() time.Time { return sitetest.Now }
	store := site.New(pool).WithClock(now)
	srv := web.New(web.Config{Store: store, Logger: slog.New(slog.NewTextHandler(io.Discard, nil))})
	srv.SetAPIAuth(webtest.BearerAuth{})
	ui, err := webui.New(srv, webui.Options{Now: now})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(srv.Handler())
	t.Cleanup(ts.Close)
	pool.Close()
	return &tenv{ts: ts, ui: ui, store: store}
}

// The bare /vuln is the landing: the search box, its examples and one
// "browse all" link; no tabs, filters, list or pager, and no store access.
func TestCatalogueLanding(t *testing.T) {
	e := newDeadStoreEnv(t)
	// the dead pool is real: the full list needs the store
	if resp, _ := e.get(t, "/vuln?browse=1"); resp.StatusCode == 200 {
		t.Fatal("the store is not dead: the list rendered")
	}
	words := map[string]string{"en": "browse all", "zh-Hans": "浏览全部", "zh-Hant": "瀏覽全部", "ja": "すべて見る",
		"ko": "전체 보기", "es": "ver todo", "fr": "tout parcourir"}
	if n := len(e.ui.Locales().Enabled); n != len(words) {
		t.Fatalf("%d locales, want %d", n, len(words))
	}
	// unknown parameters and empty known ones do not leave the landing
	for _, l := range e.ui.Locales().Enabled {
		for _, q := range []string{"", "?q=", "?q=+", "?utm_source=x", "?year=&stage=&p=3"} {
			path := l.Path("/vuln") + q
			resp, body := e.get(t, path)
			if resp.StatusCode != 200 {
				t.Fatalf("%s: %d", path, resp.StatusCode)
			}
			want := `<p class="note cex cbrowse"><a href="` + l.Path("/vuln?browse=1") + `">` + words[l.Tag] + `</a></p>`
			if !strings.Contains(body, want) {
				t.Errorf("%s: no browse link %s", path, want)
			}
			for _, bad := range []string{`class="cstages"`, `data-page-region`, `class="tbl`, `class="pager"`, `class="flt"`, `class="legend"`,
				`data-row`, `class="pgr"`, `<div class="empty"`} {
				if strings.Contains(body, bad) {
					t.Errorf("%s: landing contains %s", path, bad)
				}
			}
			for _, need := range []string{`<div class="chero">`, `class="cbg"`, `<input id="cat-q" type="search" name="q"`,
				`GHSA-gj9m-f8ph-pmhr</a>`, `<link rel="canonical" href="https://nday.land` + l.Path("/vuln") + `"/>`} {
				if !strings.Contains(body, need) {
					t.Errorf("%s: landing misses %s", path, need)
				}
			}
			if resp.Header.Get("X-Robots-Tag") != "" || strings.Contains(body, `name="robots"`) {
				t.Errorf("%s: landing is not indexable", path)
			}
			if strings.Count(body, `href="`+l.Path("/vuln?browse=1")+`"`) != 1 {
				t.Errorf("%s: browse link count", path)
			}
		}
	}
}

var catHrefRe = regexp.MustCompile(`href="((?:/[a-z-]+)?/vuln(?:\?[^"]*)?)"`)

// ?browse=1 is the full list the bare URL used to be, and every link on the
// list pages that means "everything" leads to a list (the landing only by
// the header's nav item and the search forms).
func TestCatalogueBrowse(t *testing.T) {
	e := newCatEnv(t, catSeedPage)
	want := storeIDs(t, e.store, site.CatalogueParams{})
	resp, body := e.get(t, "/vuln?browse=1")
	if resp.StatusCode != 200 || joinIDs(rowIDs(body)) != joinIDs(want[:50]) {
		t.Fatalf("browse: %d, rows %v", resp.StatusCode, rowIDs(body))
	}
	for _, need := range []string{`class="cstages"`, `data-page-region="r-cat"`, `class="flt"`, `class="pager"`, `<div class="chero">`,
		`<link rel="canonical" href="https://nday.land/vuln?browse=1"/>`, `<link rel="alternate" hreflang="ja" href="https://nday.land/ja/vuln?browse=1"/>`} {
		if !strings.Contains(body, need) {
			t.Errorf("browse misses %s", need)
		}
	}
	if resp.Header.Get("X-Robots-Tag") != "" || strings.Contains(body, `name="robots"`) || strings.Contains(body, "cbrowse") {
		t.Error("browse: robots or landing link")
	}
	// the landing is not its duplicate
	_, land := e.get(t, "/vuln")
	if strings.Contains(land, `href="https://nday.land/vuln?browse=1"`) && strings.Contains(land, `rel="canonical" href="https://nday.land/vuln?browse=1"`) {
		t.Error("the landing names the list as canonical")
	}
	// every catalogue link of the list pages lands on a list
	pages := []string{"/vuln?browse=1", "/vuln?stage=kev", "/vuln?year=2026&tag=network", "/vuln?include_rejected=1", "/zh-hans/vuln?browse=1"}
	_, first := e.get(t, "/vuln?browse=1")
	pages = append(pages, html.UnescapeString(catNextRe.FindStringSubmatch(first)[1]))
	for _, p := range pages {
		_, b := e.get(t, p)
		bare := 0
		for _, m := range catHrefRe.FindAllStringSubmatch(b, -1) {
			h := html.UnescapeString(m[1])
			if strings.HasSuffix(h, "/vuln") {
				bare++ // the nav item: the landing
				continue
			}
			if strings.Contains(h, "?q=") {
				continue // a search
			}
			resp, lb := e.get(t, h)
			if resp.StatusCode != 200 || !strings.Contains(lb, `data-page-region="r-cat"`) {
				t.Errorf("%s: link %s is not a list (%d)", p, h, resp.StatusCode)
			}
		}
		if bare != 1 {
			t.Errorf("%s: %d bare /vuln links, want 1 (the nav item)", p, bare)
		}
	}
	// the filtered views keep their own canonical and noindex
	resp, b := e.get(t, "/vuln?stage=kev")
	if resp.Header.Get("X-Robots-Tag") != "noindex" || !strings.Contains(b, `href="https://nday.land/vuln?stage=kev"`) {
		t.Error("filtered view changed")
	}
}
