package admin_test

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/xdraft"
)

// draft inserts a pending draft and returns its id.
func (h *harness) draft(cve, stage, body string) string {
	h.t.Helper()
	h.sql(`INSERT INTO vuln (cve_id) VALUES ($1) ON CONFLICT DO NOTHING`, cve)
	var id int64
	if err := h.db.Conn.QueryRow(context.Background(), `INSERT INTO x_draft (cve_id, stage, event_id, body, created_at, updated_at)
		VALUES ($1, $2, 1, $3, $4, $4) RETURNING id`, cve, stage, body, h.clock.Now()).Scan(&id); err != nil {
		h.t.Fatal(err)
	}
	return strconv.FormatInt(id, 10)
}

func (h *harness) draftRow(id string) (status string, version int, body string, url *string) {
	h.t.Helper()
	if err := h.db.Conn.QueryRow(context.Background(), `SELECT status, version, body, post_url FROM x_draft WHERE id = $1`, id).
		Scan(&status, &version, &body, &url); err != nil {
		h.t.Fatal(err)
	}
	return
}

func jbody(v map[string]any) string { b, _ := json.Marshal(v); return string(b) }

// TestXDraftAccess: the page and every endpoint for every kind of visitor,
// CSRF, cross-site, a stale sign-in, ids and hosts.
func TestXDraftAccess(t *testing.T) {
	h := newHarness(t, hopt{})
	anon := h.browser()
	user := h.user("pat", "user")
	smod := h.user("sam", "moderator")
	h.suspend(smod.id)
	sadm := h.user("sue", "admin")
	h.suspend(sadm.id)
	mod := h.user("mia", "moderator")
	adm := h.user("kim", "admin")
	who := []struct {
		name string
		b    *browser
	}{{"signed out", anon}, {"user", user}, {"suspended moderator", smod}, {"suspended admin", sadm}, {"moderator", mod}, {"admin", adm}}
	for _, w := range who {
		resp, _ := w.b.do("GET", "/admin/x/drafts", "")
		want := map[string]int{"signed out": 302, "admin": 200}[w.name]
		if want == 0 {
			want = 404
		}
		if resp.StatusCode != want {
			t.Errorf("/admin/x/drafts as %s: %d, want %d", w.name, resp.StatusCode, want)
		}
	}
	if resp, _ := anon.do("GET", "/zh-hans/admin/x/drafts", ""); resp.Header.Get("Location") != "/zh-hans/login?return=%2Fzh-hans%2Fadmin%2Fx%2Fdrafts" {
		t.Errorf("zh-hans signed out: %s", resp.Header.Get("Location"))
	}
	if _, body := mod.do("GET", "/admin/moderation", ""); strings.Contains(string(body), `href="/admin/x/drafts"`) {
		t.Error("moderator sees the drafts nav item")
	}
	if _, body := adm.do("GET", "/admin/moderation", ""); !strings.Contains(string(body), `href="/admin/x/drafts"`) {
		t.Error("admin lacks the drafts nav item")
	}
	want := map[string]string{"signed out": "401 not_signed_in", "user": "404 not_found", "suspended moderator": "404 not_found",
		"suspended admin": "404 not_found", "moderator": "403 forbidden", "admin": "200 "}
	// one draft per action so that every admin call succeeds (restore: a
	// discarded draft)
	for i, ep := range []struct{ verb, body string }{{"save", `"body":"edited text"`}, {"posted", `"post_url":""`}, {"discard", ``},
		{"restore", ``}} {
		id := h.draft(fmt.Sprintf("CVE-2026-01%02d", i), "kev_added", "CVE +KEV")
		if ep.verb == "restore" {
			h.sql(`UPDATE x_draft SET status = 'discarded', decided_at = now() WHERE id = $1`, id)
		}
		b := `{"version":1` + map[bool]string{true: "," + ep.body, false: ""}[ep.body != ""] + `}`
		for _, w := range who {
			resp, body := w.b.post("/api/admin/x/drafts/"+id+"/"+ep.verb, b)
			if got := fmt.Sprintf("%d %s", resp.StatusCode, errCode(body)); got != want[w.name] {
				t.Errorf("%s as %s: %s %s, want %s", ep.verb, w.name, got, body, want[w.name])
			}
		}
	}
	id := h.draft("CVE-2026-0200", "kev_added", "x")
	p := "/api/admin/x/drafts/" + id + "/discard"
	check(t, "discard as admin", 200, "")(adm.post("/api/admin/x/drafts/"+h.draft("CVE-2026-0201", "kev_added", "y")+"/discard", `{"version":1}`))
	// the version must be a positive 32-bit integer, on every action
	vid := h.draft("CVE-2026-0202", "kev_added", "z")
	for _, verb := range []string{"save", "posted", "discard", "restore"} {
		extra := map[string]string{"save": `,"body":"new"`}[verb]
		for _, v := range []string{"0", "-1", "3000000000", "2147483648", "99999999999999999999", "1.5", `"1"`} {
			check(t, verb+" version "+v, 400, "bad_request")(adm.post("/api/admin/x/drafts/"+vid+"/"+verb, `{"version":`+v+extra+`}`))
		}
	}
	check(t, "largest version", 409, "stale_version")(adm.post("/api/admin/x/drafts/"+vid+"/discard", `{"version":2147483647}`))
	check(t, "GET endpoint", 405, "method_not_allowed")(adm.do("GET", p, ""))
	check(t, "no CSRF", 403, "csrf")(adm.post(p, `{"version":1}`, "X-CSRF-Token", ""))
	check(t, "bad CSRF", 403, "csrf")(adm.post(p, `{"version":1}`, "X-CSRF-Token", flip(adm.csrf)))
	check(t, "cross-site", 403, "cross_site")(adm.post(p, `{"version":1}`, "Sec-Fetch-Site", "cross-site"))
	resp, body := adm.do("POST", p, `{"version":1}`, "Host", "evil.example", "Origin", origin, "X-CSRF-Token", adm.csrf)
	checkForeignHost(t, "wrong host", "POST", p, resp, body)
	check(t, "API host", 405, "method_not_allowed")(adm.do("POST", p, `{"version":1}`, "Host", apiHost, "Origin", origin, "X-CSRF-Token", adm.csrf))
	check(t, "bad id", 404, "not_found")(adm.post("/api/admin/x/drafts/01/discard", `{"version":1}`))
	check(t, "id not a number", 404, "not_found")(adm.post("/api/admin/x/drafts/abc/discard", `{"version":1}`))
	check(t, "unknown verb", 404, "not_found")(adm.post("/api/admin/x/drafts/"+id+"/publish", `{"version":1}`))
	check(t, "no such draft", 404, "not_found")(adm.post("/api/admin/x/drafts/999999/discard", `{"version":1}`))
	check(t, "form body", 415, "bad_request")(adm.post(p, `version=1`, "Content-Type", "application/x-www-form-urlencoded"))
	check(t, "no version", 400, "bad_request")(adm.post(p, `{}`))
	check(t, "unknown field", 400, "bad_request")(adm.post(p, `{"version":1,"x":1}`))
	before := h.count(`SELECT count(*) FROM admin_audit`)
	h.clock.Advance(16 * time.Minute)
	check(t, "stale session", 403, "reauth_required")(adm.post(p, `{"version":1}`))
	if st, _, _, _ := h.draftRow(id); st != "draft" {
		t.Error("a refused request changed the draft")
	}
	if n := h.count(`SELECT count(*) FROM admin_audit`); n != before {
		t.Error("refused requests wrote audit rows")
	}
}

// TestXDraftActions: save (over-length, bad text, no change, stale
// version), posted (URL normalised or refused), discard, restore, wrong
// states, and one audit row per change.
func TestXDraftActions(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	adm2 := h.user("lee", "admin")
	id := h.draft("CVE-2026-0300", "poc_published", "CVE-2026-0300 +POC\nPublic PoC available: Exploit-DB entry.")
	u := "/api/admin/x/drafts/" + id + "/"
	audits := func() int { return h.count(`SELECT count(*) FROM admin_audit WHERE action LIKE 'x.draft.%'`) }

	resp, body := adm.post(u+"save", jbody(map[string]any{"version": 1, "body": "  New text\r\nline two  \n"}))
	expect(t, "save", resp, body, 200, "")
	if st, v, b, _ := h.draftRow(id); st != "draft" || v != 2 || b != "New text\nline two" {
		t.Errorf("after save: %s %d %q", st, v, b)
	}
	if !strings.Contains(string(body), `"version":2`) {
		t.Errorf("save answer %s", body)
	}
	check(t, "same text", 409, "no_change")(adm.post(u+"save", jbody(map[string]any{"version": 2, "body": "New text\nline two"})))
	check(t, "stale version (second admin)", 409, "stale_version")(adm2.post(u+"save", jbody(map[string]any{"version": 1, "body": "older page"})))
	over := strings.Repeat("a", xdraft.BodyBudget+1)
	resp, body = adm.post(u+"save", jbody(map[string]any{"version": 2, "body": over}))
	expect(t, "over-length", resp, body, 400, "too_long")
	if !strings.Contains(string(body), `"weighted_length":257`) || !strings.Contains(string(body), `"max":256`) {
		t.Errorf("too_long body %s", body)
	}
	check(t, "CJK over-length", 400, "too_long")(adm.post(u+"save", jbody(map[string]any{"version": 2, "body": strings.Repeat("漏", 129)})))
	// emoji modifiers count on their own (an emoji-grouping count saw 21 here)
	check(t, "emoji with 250 selectors", 400, "too_long")(adm.post(u+"save",
		jbody(map[string]any{"version": 2, "body": "CVE-2026-0900 +KEV 😀" + strings.Repeat("\uFE0F", 250)})))
	check(t, "CJK fits", 200, "")(adm.post(u+"save", jbody(map[string]any{"version": 2, "body": strings.Repeat("漏", 128)})))
	check(t, "exactly the budget", 200, "")(adm.post(u+"save", jbody(map[string]any{"version": 3, "body": strings.Repeat("b", xdraft.BodyBudget)})))
	for _, bad := range []string{"", "   ", "tab\there", "nul\x00", "bell\a", strings.Repeat("x", 1001)} {
		check(t, "bad body "+strconv.Quote(bad), 400, "bad_body")(adm.post(u+"save", jbody(map[string]any{"version": 4, "body": bad})))
	}
	check(t, "save without body", 400, "bad_body")(adm.post(u+"save", `{"version":4}`))
	check(t, "discard with body", 400, "bad_request")(adm.post(u+"discard", `{"version":4,"body":"x"}`))
	if n := audits(); n != 3 {
		t.Errorf("audit rows after saves: %d", n)
	}

	for _, bad := range []string{"https://evil.example/a/status/1", "x.com/a/status/1", "https://x.com/a", "javascript:alert(1)"} {
		check(t, "bad post URL "+bad, 400, "bad_post_url")(adm.post(u+"posted", jbody(map[string]any{"version": 4, "post_url": bad})))
	}
	check(t, "posted", 200, "")(adm.post(u+"posted", jbody(map[string]any{"version": 4, "post_url": "https://twitter.com/ndayland/status/1857000000000000001?s=20"})))
	if st, v, _, pu := h.draftRow(id); st != "posted" || v != 5 || pu == nil || *pu != "https://x.com/ndayland/status/1857000000000000001" {
		t.Errorf("after posted: %s %d %v", st, v, pu)
	}
	check(t, "save a posted draft", 409, "wrong_status")(adm.post(u+"save", jbody(map[string]any{"version": 5, "body": "late"})))
	check(t, "posted twice", 409, "wrong_status")(adm.post(u+"posted", jbody(map[string]any{"version": 5, "post_url": ""})))
	check(t, "discard a posted draft", 409, "wrong_status")(adm.post(u+"discard", `{"version":5}`))
	check(t, "restore a posted draft", 409, "wrong_status")(adm.post(u+"restore", `{"version":5}`))

	id2 := h.draft("CVE-2026-0301", "kev_added", "CVE-2026-0301 +KEV")
	u2 := "/api/admin/x/drafts/" + id2 + "/"
	check(t, "restore a pending draft", 409, "wrong_status")(adm.post(u2+"restore", `{"version":1}`))
	check(t, "discard", 200, "")(adm.post(u2+"discard", `{"version":1}`))
	check(t, "discard stale", 409, "stale_version")(adm.post(u2+"discard", `{"version":1}`))
	check(t, "restore", 200, "")(adm.post(u2+"restore", `{"version":2}`))
	if st, v, _, _ := h.draftRow(id2); st != "draft" || v != 3 {
		t.Errorf("after restore: %s %d", st, v)
	}
	check(t, "posted without URL", 200, "")(adm.post(u2+"posted", `{"version":3}`))
	var by *string
	_ = h.db.Conn.QueryRow(context.Background(), `SELECT decided_by::text FROM x_draft WHERE id = $1`, id2).Scan(&by)
	if by == nil || *by != adm.id {
		t.Errorf("decided_by %v", by)
	}
	// the audit trail
	rows, err := h.db.Conn.Query(context.Background(), `SELECT action, target_type, target_id, target_label, details::text, actor_handle
		FROM admin_audit WHERE action LIKE 'x.draft.%' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for rows.Next() {
		var a, tt, tid, label, det, actor string
		if err := rows.Scan(&a, &tt, &tid, &label, &det, &actor); err != nil {
			t.Fatal(err)
		}
		got = append(got, a+" "+tt+"/"+tid+" "+label+" "+det+" "+actor)
	}
	wantAudit := []string{
		"x.draft.save x_draft/" + id + ` CVE-2026-0300 +POC {"cve": "CVE-2026-0300", "length": 17, "version": 2} kim`,
		"x.draft.save x_draft/" + id + ` CVE-2026-0300 +POC {"cve": "CVE-2026-0300", "length": 128, "version": 3} kim`,
		"x.draft.save x_draft/" + id + ` CVE-2026-0300 +POC {"cve": "CVE-2026-0300", "length": 256, "version": 4} kim`,
		"x.draft.posted x_draft/" + id + ` CVE-2026-0300 +POC {"cve": "CVE-2026-0300", "version": 5, "post_url": "https://x.com/ndayland/status/1857000000000000001"} kim`,
		"x.draft.discard x_draft/" + id2 + ` CVE-2026-0301 +KEV {"cve": "CVE-2026-0301", "version": 2} kim`,
		"x.draft.restore x_draft/" + id2 + ` CVE-2026-0301 +KEV {"cve": "CVE-2026-0301", "version": 3} kim`,
		"x.draft.posted x_draft/" + id2 + ` CVE-2026-0301 +KEV {"cve": "CVE-2026-0301", "version": 4} kim`,
	}
	if strings.Join(got, "\n") != strings.Join(wantAudit, "\n") {
		t.Errorf("audit:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(wantAudit, "\n"))
	}
	// the audit page links the draft
	if _, body := adm.do("GET", "/admin/audit", ""); !strings.Contains(string(body), `href="/admin/x/drafts#d-`+id2+`"`) {
		t.Error("audit page lacks the draft link")
	}
}

// TestXDraftAuditRollback: a failing audit insert rolls the action back.
func TestXDraftAuditRollback(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	id := h.draft("CVE-2026-0400", "kev_added", "text")
	h.sql(`CREATE FUNCTION fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'audit down'; END $$`)
	h.sql(`CREATE TRIGGER fail_audit BEFORE INSERT ON admin_audit FOR EACH ROW EXECUTE FUNCTION fail_audit()`)
	check(t, "discard with the audit failing", 500, "internal")(adm.post("/api/admin/x/drafts/"+id+"/discard", `{"version":1}`))
	if st, v, _, _ := h.draftRow(id); st != "draft" || v != 1 {
		t.Errorf("rolled back? %s %d", st, v)
	}
}

var composeRe = regexp.MustCompile(`<a class="btn sm adm-lnk" data-compose="" href="([^"]*)" target="_blank" rel="noopener noreferrer">`)

// TestXDraftPage: pending drafts with the compose link (X's host only,
// fully encoded, the absolute English detail URL), escaped text, the
// weighted length, the history with post links and restore, the empty
// state, and well-formed markup.
func TestXDraftPage(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	_, body := adm.do("GET", "/admin/x/drafts", "")
	if !strings.Contains(string(body), "No pending drafts.") || !strings.Contains(string(body), "Nothing posted or discarded yet.") {
		t.Error("empty state missing")
	}
	hostile := "CVE-2026-0500 +KEV T+3d\n<script>alert(1)</script> & \"q\" 'a' #x\n漏洞 😀"
	id := h.draft("CVE-2026-0500", "kev_added", hostile)
	posted := h.draft("CVE-2026-0501", "poc_published", "old one")
	h.sql(`UPDATE x_draft SET status = 'posted', post_url = 'https://x.com/ndayland/status/42', decided_by = $1, decided_at = now() WHERE id = $2`, adm.id, posted)
	gone := h.draft("CVE-2026-0502", "exploited_in_wild", "dropped")
	h.sql(`UPDATE x_draft SET status = 'discarded', decided_by = $1, decided_at = now(), version = 2 WHERE id = $2`, adm.id, gone)
	resp, b := adm.do("GET", "/admin/x/drafts", "")
	s := string(b)
	if resp.StatusCode != 200 {
		t.Fatalf("page: %d", resp.StatusCode)
	}
	if p := checkHTML(s, adminElems); len(p) > 0 {
		t.Errorf("markup: %v", p)
	}
	if strings.Contains(s, "<script>alert") || !strings.Contains(s, "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("draft text not escaped")
	}
	m := composeRe.FindAllStringSubmatch(s, -1)
	if len(m) != 1 {
		t.Fatalf("compose links: %v", m)
	}
	href := html.UnescapeString(m[0][1])
	cu, err := url.Parse(href)
	if err != nil || cu.Scheme != "https" || cu.Host != "x.com" || cu.Path != "/intent/tweet" || len(cu.Query()) != 1 {
		t.Fatalf("compose URL %q", href)
	}
	if got := cu.Query().Get("text"); got != hostile+"\n"+origin+"/vuln/CVE-2026-0500" {
		t.Errorf("compose text %q", got)
	}
	if strings.ContainsAny(strings.TrimPrefix(href, "https://x.com/intent/tweet?text="), " \n<>\"'#&+") {
		t.Errorf("compose URL not fully encoded: %s", href)
	}
	if href != xdraft.ComposeURL(hostile, origin+"/vuln/CVE-2026-0500") {
		t.Errorf("compose URL %s", href)
	}
	n := xdraft.WeightedLength(hostile) + xdraft.LinkCost
	for _, w := range []string{fmt.Sprintf("%d/280 with the link", n), `data-d="` + id + `" data-v="1"`, `href="/vuln/CVE-2026-0500"`,
		`href="https://x.com/ndayland/status/42" rel="noopener noreferrer nofollow"`, `data-act="xdrestore" data-d="` + gone + `" data-v="2"`,
		`id="d-` + posted + `"`, `href="/admin/users/` + adm.id + `"`, `+KEV`, `+POC`, `+ITW`} {
		if !strings.Contains(s, w) {
			t.Errorf("page lacks %s", w)
		}
	}
	// the zh-hans page links the Chinese detail page but still posts the English one
	_, zb := adm.do("GET", "/zh-hans/admin/x/drafts", "")
	if !strings.Contains(string(zb), `href="/zh-hans/vuln/CVE-2026-0500"`) || !strings.Contains(string(zb), url.QueryEscape(origin+"/vuln/CVE-2026-0500")) {
		t.Error("zh-hans page links")
	}
	// an over-length draft (e.g. stored before a rule change) has no compose
	// link, and says why
	long := h.draft("CVE-2026-0503", "kev_added", strings.Repeat("x", 300))
	_, b = adm.do("GET", "/admin/x/drafts", "")
	art := string(b)[strings.Index(string(b), `id="d-`+long+`"`):]
	art = art[:strings.Index(art, "</article>")]
	if strings.Contains(art, "data-compose") || !strings.Contains(art, `<span class="bad" data-over="">Too long`) {
		t.Errorf("over-length draft: %s", art)
	}
	if len(composeRe.FindAllString(string(b), -1)) != 1 || strings.Count(string(b), `data-over="" hidden=""`) != 1 {
		t.Error("compose links / over hints")
	}
	// a decider without a handle is shown like elsewhere in the back office
	h.sql(`UPDATE users SET handle = NULL, handle_key = NULL WHERE id = $1`, adm.id)
	_, b = adm.do("GET", "/admin/x/drafts", "")
	if !strings.Contains(string(b), `<a href="/admin/users/`+adm.id+`">no handle</a>`) {
		t.Error("no-handle decider")
	}
	h.sql(`UPDATE users SET handle = 'kim', handle_key = 'kim' WHERE id = $1`, adm.id)
	// the generator's last run, with what it dropped, and a later deferral
	h.sql(`INSERT INTO x_draft_state (id, last_event_id, last_run_at, last_run) VALUES (1, 9, now(),
		'{"created": 10, "candidates": 75, "carried": 0, "skipped_cap": 64, "skipped_old": 1, "deferred": "lock_busy", "deferred_at": "2026-11-13T12:30:00+00:00"}')`)
	_, b = adm.do("GET", "/admin/x/drafts", "")
	for _, w := range []string{"10 new drafts from 75 qualifying events; 0 left for the next runs, 64 dropped over the cap, 1 dropped as too old.",
		"A later pass at ", "2026-11-13T12:30Z"} {
		if !strings.Contains(string(b), w) {
			t.Errorf("run line lacks %q", w)
		}
	}
	h.sql(`DELETE FROM x_draft WHERE id = $1`, long)
	// over the cap: only the newest are listed
	for i := 0; i < 52; i++ {
		h.draft(fmt.Sprintf("CVE-2026-1%03d", i), "kev_added", "t")
		h.clock.Advance(time.Second)
	}
	_, b = adm.do("GET", "/admin/x/drafts", "")
	if c := strings.Count(string(b), `class="acct-form adm-xd"`); c != 50 || !strings.Contains(string(b), "Showing the newest 50 of 53.") {
		t.Errorf("capped list: %d forms", c)
	}
}

// The decided drafts are paged XHistoryPage at a time, newest decision
// first; ?page past the end or not a number is clamped.
func TestXDraftHistoryPaging(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	rowRe := regexp.MustCompile(`<tr id="d-(\d+)">`)
	hist := func(path string) (ids []string, body string) {
		t.Helper()
		resp, b := adm.do("GET", path, "")
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		for _, m := range rowRe.FindAllStringSubmatch(string(b), -1) {
			ids = append(ids, m[1])
		}
		return ids, string(b)
	}
	// exactly one page: no pager
	n := admin.XHistoryPage
	var want []string // newest decision first
	for i := 0; i < n; i++ {
		id := h.draft(fmt.Sprintf("CVE-2026-1%03d", i), "kev_added", "t")
		h.sql(`UPDATE x_draft SET status = 'discarded', decided_by = $1, decided_at = now() - make_interval(mins => $3) WHERE id = $2`, adm.id, id, i)
		want = append(want, id)
	}
	ids, body := hist("/admin/x/drafts")
	if len(ids) != n || strings.Contains(body, `class="pager"`) {
		t.Fatalf("one page: %d rows, pager %v", len(ids), strings.Contains(body, `class="pager"`))
	}
	// 45 decided: pages of 20, 20, 5
	for i := n; i < 45; i++ {
		id := h.draft(fmt.Sprintf("CVE-2026-1%03d", i), "kev_added", "t")
		h.sql(`UPDATE x_draft SET status = 'posted', decided_by = $1, decided_at = now() - make_interval(mins => $3) WHERE id = $2`, adm.id, id, i)
		want = append(want, id)
	}
	pending := h.draft("CVE-2026-1999", "kev_added", "still pending")
	for _, c := range []struct {
		path       string
		from, to   int
		page       string
		prev, next string
	}{
		{"/admin/x/drafts", 0, 20, "page 1 of 3", "", `href="/admin/x/drafts?page=2#history" rel="next"`},
		{"/admin/x/drafts?page=2", 20, 40, "page 2 of 3", `href="/admin/x/drafts#history" rel="prev"`, `href="/admin/x/drafts?page=3#history" rel="next"`},
		{"/admin/x/drafts?page=3", 40, 45, "page 3 of 3", `href="/admin/x/drafts?page=2#history" rel="prev"`, ""},
		{"/admin/x/drafts?page=99", 40, 45, "page 3 of 3", `href="/admin/x/drafts?page=2#history" rel="prev"`, ""},
		{"/admin/x/drafts?page=0", 0, 20, "page 1 of 3", "", `rel="next"`},
		{"/admin/x/drafts?page=-4", 0, 20, "page 1 of 3", "", `rel="next"`},
		{"/admin/x/drafts?page=abc", 0, 20, "page 1 of 3", "", `rel="next"`},
	} {
		ids, body := hist(c.path)
		if strings.Join(ids, ",") != strings.Join(want[c.from:c.to], ",") {
			t.Errorf("%s rows: %v, want %v", c.path, ids, want[c.from:c.to])
		}
		if !strings.Contains(body, c.page) {
			t.Errorf("%s lacks %q", c.path, c.page)
		}
		if (c.prev == "") == strings.Contains(body, `rel="prev"`) || !strings.Contains(body, c.prev) {
			t.Errorf("%s prev link, want %q", c.path, c.prev)
		}
		if (c.next == "") == strings.Contains(body, `rel="next"`) || !strings.Contains(body, c.next) {
			t.Errorf("%s next link, want %q", c.path, c.next)
		}
		// the pending drafts do not depend on the history page
		if !strings.Contains(body, `data-d="`+pending+`"`) {
			t.Errorf("%s lacks the pending draft", c.path)
		}
		if p := checkHTML(body, adminElems); len(p) > 0 {
			t.Errorf("%s markup: %v", c.path, p)
		}
	}
	// the localized page keeps its prefix in the pager
	if _, zb := hist("/zh-hans/admin/x/drafts?page=2"); !strings.Contains(zb, `href="/zh-hans/admin/x/drafts?page=3#history"`) {
		t.Error("zh-hans pager link")
	}
}
