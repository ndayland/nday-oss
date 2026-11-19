package webui_test

import (
	"encoding/json"
	"encoding/xml"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"nday.land/nday/internal/site/sitetest"
)

type sitemapDoc struct {
	XMLName  xml.Name
	Sitemaps []struct {
		Loc string `xml:"loc"`
	} `xml:"sitemap"`
	URLs []struct {
		Loc     string `xml:"loc"`
		LastMod string `xml:"lastmod"`
	} `xml:"url"`
}

func (e *tenv) sitemap(t *testing.T, path string) sitemapDoc {
	t.Helper()
	resp, body := e.get(t, path)
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "application/xml; charset=utf-8" ||
		resp.Header.Get("Cache-Control") != "public, max-age=3600" {
		t.Fatalf("%s: %d %v", path, resp.StatusCode, resp.Header)
	}
	if !strings.HasPrefix(body, `<?xml version="1.0" encoding="UTF-8"?>`) {
		t.Errorf("%s: no XML declaration", path)
	}
	var d sitemapDoc
	if err := xml.Unmarshal([]byte(body), &d); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	if d.XMLName.Space != "http://www.sitemaps.org/schemas/sitemap/0.9" {
		t.Errorf("%s: namespace %q", path, d.XMLName.Space)
	}
	return d
}

var w3cTimeRe = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)

func TestSitemap(t *testing.T) {
	e := newEnv(t)
	const base = "https://nday.land"
	enabled := e.ui.Locales().Enabled

	idx := e.sitemap(t, "/sitemap.xml")
	var shards []string
	for _, s := range idx.Sitemaps {
		shards = append(shards, s.Loc)
	}
	// Fixture: CVE-2026-1001..1010 (bucket 0), CVE-2026-6666 (bucket 1), GPU = CVE-2026-102895 (bucket 20),
	// GHSA-gpwc-27cw-rh9r (the GHSA shard "g", after every CVE shard).
	if got := strings.Join(shards, " "); idx.XMLName.Local != "sitemapindex" || got != base+"/sitemap/pages.xml "+
		base+"/sitemap/vuln-2026-0.xml "+base+"/sitemap/vuln-2026-1.xml "+base+"/sitemap/vuln-2026-20.xml "+
		base+"/sitemap/ghsa-g.xml" {
		t.Errorf("index %s %s", idx.XMLName.Local, got)
	}

	// Every listed URL is the canonical URL its page declares.
	checkCanonical := func(loc string) {
		t.Helper()
		path := strings.TrimPrefix(loc, base)
		resp, body := e.get(t, path)
		m := canonicalRe.FindStringSubmatch(body)
		if resp.StatusCode != 200 || m == nil || m[1] != loc || strings.Contains(body, `name="robots"`) {
			t.Errorf("%s: %d canonical %v", loc, resp.StatusCode, m)
		}
	}

	pages := e.sitemap(t, "/sitemap/pages.xml")
	if pages.XMLName.Local != "urlset" || len(pages.URLs) != 6*len(enabled) {
		t.Errorf("pages: %s %d urls", pages.XMLName.Local, len(pages.URLs))
	}
	seen := map[string]bool{}
	for _, u := range pages.URLs {
		seen[u.Loc] = true
		if u.LastMod != "" {
			t.Errorf("%s: lastmod %q", u.Loc, u.LastMod)
		}
		checkCanonical(u.Loc)
	}
	for _, l := range enabled {
		for _, p := range []string{"/", "/discussed", "/about", "/src", "/stats", "/rules"} {
			if !seen[base+l.Path(p)] {
				t.Errorf("pages: missing %s", base+l.Path(p))
			}
		}
		for _, p := range []string{"/hot", "/vuln", "/login", "/account", "/welcome", "/feed.xml"} {
			if seen[base+l.Path(p)] {
				t.Errorf("pages: lists %s", base+l.Path(p))
			}
		}
	}

	gpu := e.sitemap(t, "/sitemap/vuln-2026-20.xml")
	if len(gpu.URLs) != len(enabled) {
		t.Errorf("vuln-2026-20: %d urls", len(gpu.URLs))
	}
	for i, l := range enabled {
		if i >= len(gpu.URLs) {
			break
		}
		u := gpu.URLs[i]
		if u.Loc != base+l.Path("/vuln/"+sitetest.GPU) || !w3cTimeRe.MatchString(u.LastMod) {
			t.Errorf("vuln-2026-20[%d]: %+v", i, u)
		}
		checkCanonical(u.Loc)
	}

	gh := e.sitemap(t, "/sitemap/ghsa-g.xml")
	if len(gh.URLs) != len(enabled) {
		t.Errorf("ghsa-g: %d urls", len(gh.URLs))
	}
	for i, l := range enabled {
		if i < len(gh.URLs) {
			if u := gh.URLs[i]; u.Loc != base+l.Path("/vuln/"+sitetest.GHSA) || !w3cTimeRe.MatchString(u.LastMod) {
				t.Errorf("ghsa-g[%d]: %+v", i, u)
			}
			checkCanonical(gh.URLs[i].Loc)
		}
	}

	b0 := e.sitemap(t, "/sitemap/vuln-2026-0.xml")
	ids := map[string]int{}
	for _, u := range b0.URLs {
		ids[u.Loc[strings.LastIndex(u.Loc, "/")+1:]]++
	}
	for _, id := range []string{"CVE-2026-1001", "CVE-2026-1004", "CVE-2026-1010"} {
		if ids[id] != len(enabled) {
			t.Errorf("vuln-2026-0: %s listed %d times", id, ids[id])
		}
	}
	if ids["CVE-2026-1005"] != 0 || len(ids) != 9 {
		t.Errorf("vuln-2026-0: rejected listed or wrong set %v", ids)
	}

	// Unknown, empty and non-canonical shard names are real 404s; the
	// sitemap is not under any locale prefix.
	for _, p := range []string{"/sitemap/vuln-2026-3.xml", "/sitemap/vuln-2026-020.xml", "/sitemap/vuln-2026-0", "/sitemap/vuln-26-0.xml",
		"/sitemap/vuln-2026--1.xml", "/sitemap/nope.xml", "/sitemap/", "/sitemap", "/zh-hans/sitemap.xml",
		"/zh-hans/sitemap/pages.xml", "/sitemap/vuln-2026-99999999999999999999.xml",
		"/sitemap/ghsa-2.xml", "/sitemap/ghsa-a.xml", "/sitemap/ghsa-G.xml", "/sitemap/ghsa-gp.xml", "/sitemap/ghsa-.xml"} {
		if resp, _ := e.get(t, p); resp.StatusCode != 404 {
			t.Errorf("%s: %d", p, resp.StatusCode)
		}
	}

	_, body := e.get(t, "/robots.txt")
	if !strings.HasSuffix(body, "\nSitemap: "+base+"/sitemap.xml\n") {
		t.Errorf("robots.txt: %q", body)
	}
}

// TestHotFilterNoIndex: a filtered home page is noindex (meta and header);
// the plain home page and its pagination stay indexable.
func TestHotFilterNoIndex(t *testing.T) {
	e := newEnv(t)
	_, raw := e.get(t, "/api/hot?limit=1")
	var api struct {
		NextCursor *string `json:"next_cursor"`
	}
	if err := json.Unmarshal([]byte(raw), &api); err != nil || api.NextCursor == nil {
		t.Fatalf("cursor: %v %s", err, raw)
	}
	const meta = `<meta name="robots" content="noindex"/>`
	check := func(p string, noindex bool) {
		t.Helper()
		resp, body := e.get(t, p)
		if resp.StatusCode != 200 || strings.Contains(body, meta) != noindex || (resp.Header.Get("X-Robots-Tag") == "noindex") != noindex {
			t.Errorf("%s: %d meta %v header %q, want noindex=%v", p, resp.StatusCode, strings.Contains(body, meta),
				resp.Header.Get("X-Robots-Tag"), noindex)
		}
	}
	for _, p := range []string{"/?since=24h", "/?since=30d", "/?min_stage=poc", "/?include_rejected=1",
		"/zh-hans/?since=24h", "/hot?min_stage=exploited", "/?since=24h&cursor=" + url.QueryEscape(*api.NextCursor)} {
		check(p, true)
	}
	for _, p := range []string{"/", "/zh-hans/", "/?cursor=" + url.QueryEscape(*api.NextCursor), "/?since=7d&min_stage=patch",
		"/?utm_source=x"} {
		check(p, false)
	}
}
