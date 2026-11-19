package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestTitlesAccess: /admin/titles and /api/admin/titles/{id}/set|clear for
// every kind of visitor (access matrix rows of docs/admin.md).
func TestTitlesAccess(t *testing.T) {
	h := newHarness(t, hopt{})
	anon := h.browser()
	user := h.user("pat", "user")
	smod := h.user("sam", "moderator")
	h.suspend(smod.id)
	sadm := h.user("sue", "admin")
	h.suspend(sadm.id)
	mod := h.user("mia", "moderator")
	adm := h.user("boss", "admin")
	for _, c := range []struct {
		name string
		b    *browser
		st   int
		loc  string
	}{{"signed out", anon, 302, "/login?return=" + url.QueryEscape("/admin/titles")}, {"user", user, 404, ""},
		{"suspended moderator", smod, 404, ""}, {"suspended admin", sadm, 404, ""}, {"moderator", mod, 404, ""}, {"admin", adm, 200, ""}} {
		resp, body := c.b.do("GET", "/admin/titles", "")
		if resp.StatusCode != c.st || (c.loc != "" && resp.Header.Get("Location") != c.loc) {
			t.Errorf("page as %s: %d %s\n%s", c.name, resp.StatusCode, resp.Header.Get("Location"), h.logs.String())
		}
		if c.st == 200 {
			checkPersonalHeaders(t, "titles page", resp)
			if !strings.Contains(string(body), `href="/admin/titles" aria-current="page"`) {
				t.Errorf("menu item not current")
			}
		}
	}
	for _, c := range []struct {
		name   string
		b      *browser
		status int
		code   string
	}{{"signed out", anon, 401, "not_signed_in"}, {"user", user, 404, "not_found"}, {"suspended moderator", smod, 404, "not_found"},
		{"suspended admin", sadm, 404, "not_found"}, {"moderator", mod, 403, "forbidden"}} {
		resp, body := c.b.post("/api/admin/titles/"+cveA+"/set", `{"version":0,"title":"Foo"}`)
		expect(t, "set as "+c.name, resp, body, c.status, c.code)
		resp, body = c.b.post("/api/admin/titles/"+cveA+"/clear", `{"version":0}`)
		expect(t, "clear as "+c.name, resp, body, c.status, c.code)
	}
	check(t, "set as admin", 200, "")(adm.post("/api/admin/titles/"+cveA+"/set", `{"version":0,"title":"Foo"}`))
	check(t, "clear as admin", 200, "")(adm.post("/api/admin/titles/"+cveA+"/clear", `{"version":1}`))
	check(t, "GET endpoint", 405, "method_not_allowed")(adm.do("GET", "/api/admin/titles/"+cveA+"/set", ""))
	check(t, "no CSRF", 403, "csrf")(adm.post("/api/admin/titles/"+cveA+"/set", `{"version":2,"title":"x"}`, "X-CSRF-Token", ""))
	check(t, "cross-site", 403, "cross_site")(adm.post("/api/admin/titles/"+cveA+"/set", `{"version":2,"title":"x"}`, "Sec-Fetch-Site", "cross-site"))
	h.clock.Advance(16 * time.Minute)
	check(t, "stale sign-in", 403, "reauth_required")(adm.post("/api/admin/titles/"+cveA+"/set", `{"version":2,"title":"x"}`))
	if n := h.count(`SELECT count(*) FROM admin_audit WHERE target_type = 'vuln'`); n != 2 {
		t.Errorf("audit rows %d, want 2", n)
	}
}

// TestTitlesActions: validation, optimistic concurrency, one audit row per
// action with the old and new title, a cleared title falls back.
func TestTitlesActions(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("boss", "admin")
	h.sql(`UPDATE vuln SET description = 'Acme Widget lets attackers in.' WHERE cve_id = $1`, cveA)
	h.sql(`INSERT INTO vuln_title (cve_id, rule_version, form, excerpt, composed_en) VALUES ($1, 1, 'excerpt', 'Acme Widget lets attackers in', 'Acme Widget lets attackers in')`, cveA)
	p := "/api/admin/titles/" + cveA
	for _, c := range []struct{ body, code string }{
		{`{"version":0,"title":""}`, "bad_title"}, {`{"version":0,"title":"   "}`, "bad_title"},
		{`{"version":0,"title":"a\nb"}`, "bad_title"}, {`{"version":0,"title":"a\u202eb"}`, "bad_title"},
		{`{"version":0,"title":"a\u200bb"}`, "bad_title"}, {`{"version":0,"title":"a\tb"}`, "bad_title"},
		{`{"version":0,"title":"` + strings.Repeat("x", 161) + `"}`, "bad_title"}, {`{"version":0}`, "bad_title"},
		{`{"title":"x"}`, "bad_request"}, {`{"version":-1,"title":"x"}`, "bad_request"},
		{`{"version":0,"title":"x","extra":1}`, "bad_request"},
	} {
		check(t, "set "+c.body, 400, c.code)(adm.post(p+"/set", c.body))
	}
	check(t, "clear with a title", 400, "bad_request")(adm.post(p+"/clear", `{"version":0,"title":"x"}`))
	check(t, "unknown vulnerability", 404, "not_found")(adm.post("/api/admin/titles/CVE-2026-99999/set", `{"version":0,"title":"x"}`))
	check(t, "not an id", 404, "not_found")(adm.post("/api/admin/titles/nope/set", `{"version":0,"title":"x"}`))
	check(t, "nothing to clear", 409, "no_change")(adm.post(p+"/clear", `{"version":0}`))
	if n := h.count(`SELECT count(*) FROM admin_audit`); n != 0 {
		t.Fatalf("refused requests wrote %d audit rows", n)
	}
	// set (lower-case id, NFC, trimmed), then a stale version, the same title, a new one, clear
	resp, body := adm.post("/api/admin/titles/"+strings.ToLower(cveA)+"/set", `{"version":0,"title":"  Acme Widget: login bypass via Cafe\u0301 header "}`)
	expect(t, "set", resp, body, 200, "")
	var out struct {
		OK      bool   `json:"ok"`
		CVE     string `json:"cve_id"`
		Version int    `json:"version"`
	}
	if err := json.Unmarshal(body, &out); err != nil || !out.OK || out.CVE != cveA || out.Version != 1 {
		t.Fatalf("set answer %s", body)
	}
	if n := h.count(`SELECT count(*) FROM vuln_title WHERE cve_id = $1 AND staff_title = 'Acme Widget: login bypass via Café header'
		AND staff_by = (SELECT id FROM users WHERE handle = 'boss') AND staff_version = 1 AND composed_en IS NOT NULL`, cveA); n != 1 {
		t.Errorf("stored title")
	}
	check(t, "stale version", 409, "stale_version")(adm.post(p+"/set", `{"version":0,"title":"Other"}`))
	check(t, "same title", 409, "no_change")(adm.post(p+"/set", `{"version":1,"title":"Acme Widget: login bypass via Café header"}`))
	check(t, "new title", 200, "")(adm.post(p+"/set", `{"version":1,"title":"Acme Widget: auth bypass"}`))
	check(t, "stale clear", 409, "stale_version")(adm.post(p+"/clear", `{"version":1}`))
	// the public answer while the staff title is set
	resp, body = adm.do("GET", "/api/vuln/"+cveA, "")
	if resp.StatusCode == 200 && !strings.Contains(string(body), `"effective_title":"Acme Widget: auth bypass","title_origin":"staff"`) {
		t.Errorf("public answer with the staff title: %s", body)
	}
	check(t, "clear", 200, "")(adm.post(p+"/clear", `{"version":2}`))
	if n := h.count(`SELECT count(*) FROM vuln_title WHERE cve_id = $1 AND staff_title IS NULL AND staff_by IS NULL AND staff_at IS NULL AND staff_version = 3`, cveA); n != 1 {
		t.Errorf("cleared row")
	}
	// one audit row per action, with the old and the new title
	rows, err := h.db.Conn.Query(context.Background(), `SELECT action, target_type, target_id, target_label, details::text FROM admin_audit ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var a, tt, id, label, d string
		if err := rows.Scan(&a, &tt, &id, &label, &d); err != nil {
			t.Fatal(err)
		}
		got = append(got, a+" "+tt+" "+id+" "+label+" "+d)
	}
	rows.Close()
	want := []string{
		`vuln.title_set vuln ` + cveA + ` ` + cveA + ` {"cve": "` + cveA + `", "new": "Acme Widget: login bypass via Café header", "old": null, "version": 1}`,
		`vuln.title_set vuln ` + cveA + ` ` + cveA + ` {"cve": "` + cveA + `", "new": "Acme Widget: auth bypass", "old": "Acme Widget: login bypass via Café header", "version": 2}`,
		`vuln.title_clear vuln ` + cveA + ` ` + cveA + ` {"cve": "` + cveA + `", "old": "Acme Widget: auth bypass", "version": 3}`,
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("audit rows:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// the audit page links the vulnerability's entry on /admin/titles
	if _, body := adm.do("GET", "/admin/audit", ""); !strings.Contains(string(body), `href="/admin/titles?cve=`+cveA+`"`) {
		t.Errorf("audit page: no link to the titles page")
	}
}

// TestTitlesQueue: most researchers first, then most posts; the filter
// (no record title, all); 10 per page with the shared pager in its region;
// the lookup box.
func TestTitlesQueue(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("boss", "admin")
	for i := 1; i <= 4; i++ {
		h.sql(`INSERT INTO x_accounts (user_id, handle, enabled) VALUES ($1, $2, true)`, fmt.Sprint(9000+i), fmt.Sprintf("res%d", i))
	}
	h.sql(`INSERT INTO x_accounts (user_id, handle, enabled) VALUES ('9099', 'gone', false)`)
	post := func(cve string, author, n int) {
		for k := 0; k < n; k++ {
			id := fmt.Sprintf("%d%02d%s", author, k, cve[len(cve)-4:])
			h.sql(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, detail, dedupe_key)
				VALUES ($1, 'social_post', $2, $2, 'xposts', $3, $4)`, cve, h.clock.Now().Add(-time.Hour*time.Duration(k+1)),
				fmt.Sprintf(`{"author_id": "%d", "post_id": "%s"}`, author, id), id)
		}
	}
	// 14 untitled + 1 titled vulnerability discussed; one old post only
	for i := 1; i <= 15; i++ {
		cve := fmt.Sprintf("CVE-2026-%04d", 5000+i)
		title := any(nil)
		if i == 2 {
			title = "Record title"
		}
		h.sql(`INSERT INTO vuln (cve_id, title, description) VALUES ($1, $2, $3)`, cve, title, "Desc "+strings.Repeat("y", 400))
		post(cve, 9001, 1)
	}
	post("CVE-2026-5003", 9002, 3) // 2 researchers, 4 posts
	post("CVE-2026-5004", 9002, 1) // 2 researchers, 2 posts
	post("CVE-2026-5002", 9002, 1) // titled: 2 researchers
	post("CVE-2026-5002", 9003, 1) // 3 researchers
	post("CVE-2026-5005", 9099, 5) // a disabled account does not count
	h.sql(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-5099')`)
	h.sql(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, detail, dedupe_key)
		VALUES ('CVE-2026-5099', 'social_post', $1, $1, 'xposts', '{"author_id": "9001"}', 'old')`, h.clock.Now().Add(-8*24*time.Hour))
	ctx := context.Background()
	order := func(all bool, page int) (string, int) {
		rows, w, err := h.adm.TitleQueue(ctx, all, page)
		if err != nil {
			t.Fatal(err)
		}
		var ids []string
		for _, r := range rows {
			ids = append(ids, fmt.Sprintf("%s:%d/%d", r.CVEID[len(r.CVEID)-2:], r.Researchers, r.Posts))
		}
		return strings.Join(ids, " "), w.Total
	}
	if got, total := order(false, 1); total != 14 || !strings.HasPrefix(got, "03:2/4 04:2/2 01:1/1 05:1/1 06:1/1") {
		t.Errorf("untitled page 1 (%d): %s", total, got)
	}
	if got, total := order(true, 1); total != 15 || !strings.HasPrefix(got, "02:3/3 03:2/4 04:2/2 01:1/1") {
		t.Errorf("all page 1 (%d): %s", total, got)
	}
	if got, _ := order(false, 2); got != "12:1/1 13:1/1 14:1/1 15:1/1" {
		t.Errorf("untitled page 2: %s", got)
	}
	if got, _ := order(false, 9); got != "12:1/1 13:1/1 14:1/1 15:1/1" {
		t.Errorf("past the end: %s", got)
	}
	// the page: region, pager, rows and the edit form
	resp, body := adm.do("GET", "/admin/titles?p=2", "")
	s := string(body)
	if resp.StatusCode != 200 || !strings.Contains(s, `id="r-titles" data-page-region="r-titles"`) || strings.Count(s, `<tr data-cve=`) != 4 ||
		!strings.Contains(s, `<nav class="pager"`) || !strings.Contains(s, `aria-current="true">no record title</a>`) {
		t.Errorf("page 2: %d\n%s", resp.StatusCode, s)
	}
	if !strings.Contains(s, `<form class="acct-form adm-title" data-cve="CVE-2026-5012" data-v="0" novalidate="">`) ||
		!strings.Contains(s, `aria-controls="dt-q-CVE-2026-5012"`) || strings.Contains(s, `data-act="ticlear"`) {
		t.Errorf("row edit form")
	}
	if !strings.Contains(s, "Desc "+strings.Repeat("y", 294)+"…") {
		t.Errorf("description reference not cut to 300 characters")
	}
	_, body = adm.do("GET", "/admin/titles?f=all", "")
	if s := string(body); !strings.Contains(s, `aria-current="true">all</a>`) || !strings.Contains(s, "Record title") {
		t.Errorf("filter all")
	}
	// a staff title: the clear button and the marker
	h.sql(`INSERT INTO vuln_title (cve_id, staff_title, staff_at, staff_version) VALUES ('CVE-2026-5003', 'Hand <b>made</b>', now(), 4)`)
	_, body = adm.do("GET", "/admin/titles", "")
	if s := string(body); !strings.Contains(s, `data-act="ticlear" data-cve="CVE-2026-5003" data-v="4"`) ||
		!strings.Contains(s, `value="Hand &lt;b&gt;made&lt;/b&gt;"`) || !strings.Contains(s, `data-origin="staff"`) {
		t.Errorf("staff row:\n%s", s)
	}
	// lookup: any vulnerability, also one nobody discusses; unknown ids
	_, body = adm.do("GET", "/admin/titles?cve=cve-2026-0001", "")
	if s := string(body); !strings.Contains(s, `id="t-lookup"`) || !strings.Contains(s, `data-cve="`+cveA+`"`) {
		t.Errorf("lookup")
	}
	_, body = adm.do("GET", "/admin/titles?cve=CVE-2026-424242", "")
	if s := string(body); !strings.Contains(s, "No vulnerability CVE-2026-424242.") {
		t.Errorf("lookup unknown")
	}
	_, body = adm.do("GET", "/admin/titles?cve=%3Cscript%3E", "")
	if s := string(body); !strings.Contains(s, "No vulnerability &lt;script&gt;.") {
		t.Errorf("lookup hostile")
	}
}
