package webui_test

import (
	"bytes"
	"image/png"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui"
)

var ogImageRe = regexp.MustCompile(`<meta property="og:image" content="([^"]*)"/>`)

func ogImage(t *testing.T, e *tenv, path string) string {
	t.Helper()
	_, body := e.get(t, path)
	m := ogImageRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("%s: no og:image", path)
	}
	return htmlUnescape(m[1])
}

// TestShareCard: the detail page (every locale, the same URL) links its own
// card; the card is a 1200x630 PNG; the card answers 404 exactly where the
// detail page does; other pages keep the static card.
func TestShareCard(t *testing.T) {
	const base = "https://www.nday.land"
	e := newEnvFull(t, web.Config{PublicURL: base}, webui.Options{})
	cardRe := regexp.MustCompile(`^` + regexp.QuoteMeta(base) + `/og/vuln/(CVE-\d{4}-\d+)\.png\?v=([0-9a-f]{10})$`)

	keys := map[string]string{}
	for _, id := range []string{sitetest.GPU, "CVE-2026-1004", "CVE-2026-1005", "CVE-2026-1009", "CVE-2026-1010"} {
		var first string
		for _, l := range e.ui.Locales().Enabled {
			u := ogImage(t, e, l.Path("/vuln/"+id))
			if first == "" {
				first = u
			} else if u != first {
				t.Errorf("%s: og:image differs by locale: %q vs %q", l.Path("/vuln/"+id), u, first)
			}
		}
		m := cardRe.FindStringSubmatch(first)
		if m == nil || m[1] != id {
			t.Errorf("%s: og:image %q", id, first)
			continue
		}
		keys[id] = m[2]
		path := strings.TrimPrefix(first, base)
		resp, body := e.get(t, path)
		if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "image/png" ||
			resp.Header.Get("Cache-Control") != "public, max-age=86400" {
			t.Errorf("%s: %d %q %q", path, resp.StatusCode, resp.Header.Get("Content-Type"), resp.Header.Get("Cache-Control"))
			continue
		}
		img, err := png.Decode(strings.NewReader(body))
		if err != nil {
			t.Errorf("%s: %v", path, err)
			continue
		}
		if b := img.Bounds(); b.Dx() != 1200 || b.Dy() != 630 {
			t.Errorf("%s: %v", path, b)
		}
		// Without (or with a stale) version: same picture, short cache.
		r2, b2 := e.get(t, "/og/vuln/"+id+".png?v=0000000000")
		if r2.StatusCode != 200 || b2 != body || r2.Header.Get("Cache-Control") != "public, max-age=300" {
			t.Errorf("%s stale v: %d same=%v %q", id, r2.StatusCode, b2 == body, r2.Header.Get("Cache-Control"))
		}
		// Validators.
		r3, _ := e.get(t, path, "If-None-Match", resp.Header.Get("ETag"))
		if resp.Header.Get("ETag") == "" || r3.StatusCode != http.StatusNotModified {
			t.Errorf("%s: etag %q -> %d", path, resp.Header.Get("ETag"), r3.StatusCode)
		}
	}
	seen := map[string]string{}
	for id, k := range keys {
		if o, dup := seen[k]; dup {
			t.Errorf("%s and %s share card version %s", id, o, k)
		}
		seen[k] = id
	}

	// Other pages, and the detail page's own 404/400, keep the static card.
	for _, p := range []string{"/", "/about", "/vuln", "/zh-hans/stats", "/vuln/CVE-2099-99999", "/vuln/not-a-cve", "/no/such/page"} {
		if u := ogImage(t, e, p); !strings.HasPrefix(u, base+"/static/og.") || !strings.HasSuffix(u, ".png") {
			t.Errorf("%s: og:image %q", p, u)
		}
	}

	// 404 where the detail page is 404 (unknown CVE), and for names that are
	// not "<CVE id>.png" or not on the locale-independent path.
	for _, p := range []string{"/og/vuln/CVE-2099-99999.png", "/og/vuln/not-a-cve.png", "/og/vuln/" + sitetest.GPU,
		"/og/vuln/" + sitetest.GPU + ".jpg", "/og/vuln/" + sitetest.GPU + ".png.png", "/og/vuln/",
		"/zh-hans/og/vuln/" + sitetest.GPU + ".png", "/og/" + sitetest.GPU + ".png"} {
		if r, _ := e.get(t, p); r.StatusCode != 404 {
			t.Errorf("%s: %d", p, r.StatusCode)
		}
	}
	if r, _ := e.get(t, "/vuln/CVE-2099-99999"); r.StatusCode != 404 {
		t.Errorf("detail page of the unknown CVE: %d", r.StatusCode)
	}
	// A non-canonical id redirects to the canonical card, like the page.
	if r := e.noRedirect(t, "/og/vuln/cve-2026-102895.png?v=1"); r.StatusCode != 301 ||
		r.Header.Get("Location") != "/og/vuln/"+sitetest.GPU+".png?v=1" {
		t.Errorf("lower-case id: %d %q", r.StatusCode, r.Header.Get("Location"))
	}
	// Only GET and HEAD.
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/og/vuln/"+sitetest.GPU+".png", bytes.NewReader(nil))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %d", resp.StatusCode)
	}
}
