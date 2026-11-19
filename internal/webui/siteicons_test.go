package webui_test

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/siteicon"
	"nday.land/nday/internal/webui"
)

func iconPNG(t *testing.T) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := png.Encode(&b, image.NewRGBA(image.Rect(0, 0, 16, 16))); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// putIcon stores an 'ok' icon for host (or a 'none' row when img is nil).
func putIcon(t *testing.T, c *pgx.Conn, host string, img []byte) string {
	t.Helper()
	now := sitetest.Now
	if img == nil {
		if _, err := c.Exec(context.Background(), `INSERT INTO site_icon (host, status, fetched_at, next_try_at) VALUES ($1, 'none', $2, $2)`,
			host, now); err != nil {
			t.Fatal(err)
		}
		return ""
	}
	h := siteicon.Hash(img)
	if _, err := c.Exec(context.Background(), `INSERT INTO site_icon (host, status, content_type, image, hash, fetched_at, next_try_at)
VALUES ($1, 'ok', 'image/png', $2, $3, $4, $4)`, host, img, h, now); err != nil {
		t.Fatal(err)
	}
	return h
}

// TestSiteIconRoute: /icon/{host} serves exactly the stored bytes with the
// stored type and the locking-down headers; anything else is a short-cached
// 404, and nothing is ever fetched or redirected (not a proxy).
func TestSiteIconRoute(t *testing.T) {
	e, conn := newMemberEnv(t, false)
	img := iconPNG(t)
	hash := putIcon(t, conn, "ico.example", img)
	putIcon(t, conn, "none.example", nil)

	get := func(path string, hdr ...string) (*http.Response, []byte) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, e.ts.URL+path, nil)
		req.Host = wwwHost
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		c := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err := c.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var b bytes.Buffer
		b.ReadFrom(resp.Body)
		return resp, b.Bytes()
	}
	common := func(path string, resp *http.Response) {
		t.Helper()
		h := resp.Header
		if h.Get("X-Content-Type-Options") != "nosniff" || h.Get("Content-Security-Policy") != "default-src 'none'; sandbox" ||
			h.Get("Cross-Origin-Resource-Policy") != "same-origin" || h.Get("Set-Cookie") != "" {
			t.Errorf("%s: headers %v", path, h)
		}
	}
	resp, body := get("/icon/ico.example?v=" + hash)
	common("current", resp)
	if resp.StatusCode != 200 || !bytes.Equal(body, img) || resp.Header.Get("Content-Type") != "image/png" ||
		resp.Header.Get("Cache-Control") != "public, max-age=86400, immutable" || resp.Header.Get("ETag") != `"`+hash+`"` {
		t.Errorf("current: %d %v %d bytes", resp.StatusCode, resp.Header, len(body))
	}
	resp, body = get("/icon/ico.example")
	if resp.StatusCode != 200 || !bytes.Equal(body, img) || resp.Header.Get("Cache-Control") != "public, max-age=86400" {
		t.Errorf("no v: %d %v", resp.StatusCode, resp.Header)
	}
	// a ?v= that is not the stored hash (old or made up): short cache
	for _, v := range []string{"0123456789abcdef", ""} {
		resp, body = get("/icon/ico.example?v=" + v)
		if resp.StatusCode != 200 || !bytes.Equal(body, img) || resp.Header.Get("Cache-Control") != "public, max-age=300" {
			t.Errorf("stale v %q: %d %v", v, resp.StatusCode, resp.Header)
		}
	}
	// read from the store on every request, not kept in the page cache:
	// a row added after a 404 is served at once
	if resp, _ := get("/icon/late.example"); resp.StatusCode != 404 {
		t.Errorf("late before: %d", resp.StatusCode)
	}
	lateHash := putIcon(t, conn, "late.example", img)
	if resp, body := get("/icon/late.example?v=" + lateHash); resp.StatusCode != 200 || !bytes.Equal(body, img) {
		t.Errorf("late after: %d", resp.StatusCode)
	}
	resp, body = get("/icon/ico.example?v=0123456789abcdef", "If-None-Match", `"`+hash+`"`)
	if resp.StatusCode != http.StatusNotModified || len(body) != 0 {
		t.Errorf("conditional: %d", resp.StatusCode)
	}
	for _, p := range []string{"/icon/none.example", "/icon/missing.example", "/icon/ICO.example", "/icon/ico.example.",
		"/icon/ico.example:443", "/icon/127.0.0.1", "/icon/localhost", "/icon/..", "/icon/ico.example%2F..%2F",
		"/icon/" + url.PathEscape("https://ico.example/favicon.ico"), "/icon/%69co.example%00", "/icon/xn--bcher-kva.example"} {
		resp, body := get(p)
		if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound || resp.StatusCode == http.StatusTemporaryRedirect {
			continue // the mux cleaning a path ("..") is not the icon route
		}
		common(p, resp)
		if resp.StatusCode != 404 || bytes.Equal(body, img) || resp.Header.Get("Cache-Control") != "public, max-age=300" ||
			strings.HasPrefix(resp.Header.Get("Content-Type"), "image/") {
			t.Errorf("%s: %d %v", p, resp.StatusCode, resp.Header)
		}
	}
	req, _ := http.NewRequest(http.MethodPost, e.ts.URL+"/icon/ico.example", nil)
	req.Host = wwwHost
	if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST: %v %v", resp, err)
	}
}

var (
	favImgRe    = regexp.MustCompile(`<img class="fav" src="/icon/([a-z0-9.-]+)\?v=([0-9a-f]{16})" alt="" width="16" height="16" loading="lazy" decoding="async"/>`)
	anchorFavRe = regexp.MustCompile(`<a\s[^>]*>(<img class="fav"[^>]*/>|<span class="fav" aria-hidden="true"></span>)?`)
)

// TestVulnPageSiteIcons: on the vulnerability page every link that leaves
// the site starts with the stored icon of its host or the placeholder;
// internal links get nothing; the page is the same for every visitor and
// still polyglot without inline styles.
func TestVulnPageSiteIcons(t *testing.T) {
	e, conn := newMemberEnv(t, true)
	img := iconPNG(t)
	hash := putIcon(t, conn, "github.com", img)
	putIcon(t, conn, "cwe.mitre.org", nil)
	resp, body := e.fetch(t, wwwHost, "/vuln/"+sitetest.GPU, nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if _, p := CheckHTML(body); len(p) != 0 {
		t.Errorf("page problems: %v", p)
	}
	main := body[strings.Index(body, "<main"):strings.LastIndex(body, "</main>")]
	icons, placeholders := 0, 0
	for _, m := range anchorFavRe.FindAllStringSubmatch(main, -1) {
		tag, fav := m[0][:len(m[0])-len(m[1])], m[1]
		external := strings.Contains(tag, ` target="_blank"`)
		switch {
		case !external && (fav != "" || strings.Contains(tag, "data-fav")):
			t.Errorf("internal link decorated: %s", m[0])
		case external && (fav == "" || !strings.Contains(tag, ` data-fav=""`)):
			t.Errorf("external link without icon or placeholder: %s", m[0])
		case external && strings.HasPrefix(fav, "<img"):
			icons++
			im := favImgRe.FindStringSubmatch(fav)
			if im == nil || im[1] != "github.com" || im[2] != hash || !strings.Contains(tag, `href="https://github.com/`) {
				t.Errorf("icon: %s", m[0])
			}
		case external:
			placeholders++
			if strings.Contains(tag, `href="https://github.com/`) {
				t.Errorf("github link without its icon: %s", m[0])
			}
		}
	}
	if icons == 0 || placeholders == 0 {
		t.Errorf("icons %d, placeholders %d", icons, placeholders)
	}
	before, after := body[:strings.Index(body, "<main")], body[strings.LastIndex(body, "</main>"):]
	if strings.Contains(before+after, `class="fav"`) || strings.Contains(before+after, "data-fav") {
		t.Error("decoration outside <main>")
	}
	// the icon URL it references is served
	if resp, b := e.fetch(t, wwwHost, "/icon/github.com?v="+hash, nil); resp.StatusCode != 200 || b != string(img) {
		t.Errorf("icon fetch: %d", resp.StatusCode)
	}
	// the same bytes for a signed-in reader (publicly cacheable page)
	cookies, _ := e.signIn(t, "9301", "iconreader")
	if _, in := e.fetch(t, wwwHost, "/vuln/"+sitetest.GPU, cookies); in != body {
		t.Error("the page differs for a signed-in reader")
	}
	// no icons on other pages
	for _, p := range []string{"/", "/src", "/about"} {
		if _, b := e.fetch(t, wwwHost, p, nil); strings.Contains(b, `class="fav"`) {
			t.Errorf("%s has site icons", p)
		}
	}
}

// TestSiteIconHostsCovered: every outbound link host of every seeded
// vulnerability page (posts, resources, hostile data included) is a host
// the background job picks (siteicon.Due), so no page link is left without
// a chance of an icon.
func TestSiteIconHostsCovered(t *testing.T) {
	e, conn := newMemberEnv(t, true)
	rows, err := conn.Query(context.Background(), `SELECT cve_id FROM vuln ORDER BY cve_id`)
	if err != nil {
		t.Fatal(err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		t.Fatal(err)
	}
	due, err := siteicon.Due(context.Background(), conn, time.Now(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	picked := map[string]bool{}
	for _, c := range due {
		picked[c.Host] = true
	}
	seen := map[string]bool{}
	pages := 0
	for _, id := range ids {
		resp, body := e.fetch(t, wwwHost, "/vuln/"+id, nil)
		if resp.StatusCode != 200 {
			continue
		}
		pages++
		for _, u := range webui.OutboundLinks([]byte(body)) {
			h, ok := siteicon.HostOf(u)
			if !ok {
				continue
			}
			seen[h] = true
			if !picked[h] {
				t.Errorf("/vuln/%s links %s, whose host the job never picks", id, u)
			}
		}
	}
	hosts := make([]string, 0, len(seen))
	for h := range seen {
		hosts = append(hosts, h)
	}
	sort.Strings(hosts)
	if pages < 5 || len(hosts) < 4 {
		t.Errorf("%d pages, hosts %v: the fixture lost its links?", pages, hosts)
	}
	t.Logf("%d pages, outbound hosts: %s", pages, strings.Join(hosts, " "))
}
