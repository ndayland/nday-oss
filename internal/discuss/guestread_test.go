package discuss_test

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/discuss"
)

// guestLimits are generous limits with signed-out reading on.
func guestLimits() *discuss.Limits {
	l := discuss.DefaultLimits()
	l.PostBurst, l.NewPostBurst, l.AddrBurst, l.EditBurst, l.ReadBurst, l.GuestReadBurst = 1000, 1000, 1000, 1000, 1000, 1000
	l.PostDaily, l.NewPostDaily, l.ReportDaily = 1000, 1000, 1000
	return &l
}

// guestFixture stores, on cveA, comments in every state a page can meet,
// each with a distinctive body: PUBLIC-* may be shown to anyone, SECRET-*
// must never reach a signed-out caller. It returns the members and the
// ids by name.
func guestFixture(t *testing.T, h *harness) (ada, bob, mod *browser, ids map[string]string) {
	t.Helper()
	ada, bob, mod = h.member("ada"), h.member("bob"), h.member("carol")
	h.establish(ada.id)
	h.establish(bob.id)
	h.setRole(mod.id, "moderator")
	mod.refresh()
	ids = map[string]string{}
	post := func(b *browser, name, body string, parent *string, purpose string) {
		req := map[string]any{"body": body, "lang": "en"}
		if parent != nil {
			req["parent_id"] = *parent
		}
		if purpose != "" {
			req["purpose"] = purpose
		}
		j, _ := json.Marshal(req)
		resp, raw := b.post("/api/discuss/"+cveA, string(j))
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, resp.StatusCode, raw)
		}
		var r struct {
			Comment struct {
				ID string `json:"id"`
			} `json:"comment"`
		}
		_ = json.Unmarshal(raw, &r)
		ids[name] = r.Comment.ID
		h.clock.Advance(time.Second)
	}
	ok := func(what string, resp *http.Response, raw []byte) {
		t.Helper()
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", what, resp.StatusCode, raw)
		}
	}
	// T1: visible, edited (its old text is a revision), reported, purpose
	post(ada, "T1", "SECRET-OLD-T1 before the edit", nil, "reproduction")
	resp, raw := ada.post("/api/discuss/comment/"+ids["T1"]+"/edit", `{"body":"PUBLIC-T1 reproduced on 2.3.1","purpose":"analysis"}`)
	ok("edit T1", resp, raw)
	post(bob, "R1", "PUBLIC-R1 same here", ptr(ids["T1"]), "")
	resp, raw = bob.post("/api/discuss/comment/"+ids["T1"]+"/report", `{"reason":"other","note":"SECRET-NOTE of the reporter"}`)
	ok("report T1", resp, raw)
	// R5: a hidden reply; R6: a deleted reply
	post(bob, "R5", "SECRET-HIDDEN-R5 spam", ptr(ids["T1"]), "")
	resp, raw = mod.post("/api/discuss/comment/"+ids["R5"]+"/hide", `{"reason":"SECRET-REASON-R5"}`)
	ok("hide R5", resp, raw)
	post(bob, "R6", "SECRET-DELETED-R6 oops", ptr(ids["T1"]), "")
	resp, raw = bob.post("/api/discuss/comment/"+ids["R6"]+"/delete", "")
	ok("delete R6", resp, raw)
	// T2: hidden, with a visible reply
	post(ada, "T2", "SECRET-HIDDEN-T2 abuse", nil, "question")
	post(bob, "R2", "PUBLIC-R2 under a hidden comment", ptr(ids["T2"]), "")
	resp, raw = mod.post("/api/discuss/comment/"+ids["T2"]+"/hide", `{"reason":"SECRET-REASON-T2"}`)
	ok("hide T2", resp, raw)
	// T3: deleted, with a visible reply (a placeholder)
	post(ada, "T3", "SECRET-DELETED-T3 gone", nil, "fix")
	post(bob, "R3", "PUBLIC-R3 under a deleted comment", ptr(ids["T3"]), "")
	resp, raw = ada.post("/api/discuss/comment/"+ids["T3"]+"/delete", "")
	ok("delete T3", resp, raw)
	// T4: deleted without replies (absent)
	post(ada, "T4", "SECRET-DELETED-T4 alone", nil, "")
	resp, raw = ada.post("/api/discuss/comment/"+ids["T4"]+"/delete", "")
	ok("delete T4", resp, raw)
	return ada, bob, mod, ids
}

// commentKeys are the only keys a comment of a signed-out response may
// have (docs/discuss.md §4.1); authorKeys those of its author, where
// display_name is always null for a signed-out caller.
var (
	commentKeys = []string{"id", "parent_id", "author", "lang", "created_at", "edited_at", "status", "purpose", "body_html",
		"body_nodes", "links", "can_edit", "can_delete", "can_hide", "can_unhide", "can_report", "can_reply", "reported",
		"replies", "replies_truncated", "replies_next_cursor"}
	authorKeys = []string{"handle", "display_name", "role"}
	topKeys    = []string{"cve", "count", "comments", "next_cursor", "cursor", "viewer", "limits"}
)

// checkGuestJSON checks a signed-out response field by field: only the
// allowed keys, every permission false, no source, no moderation data,
// no SECRET-* text and no user id.
func checkGuestJSON(t *testing.T, what string, raw []byte, userIDs ...string) map[string]any {
	t.Helper()
	text := string(raw)
	for _, bad := range append([]string{"SECRET-", `"body":`, "moderation", "hidden_reason", "hidden_by", "open_reports",
		"revisions", "reporter", "email", "github", "outline", "terms_accepted", "suspended"}, userIDs...) {
		if strings.Contains(text, bad) {
			t.Errorf("%s: signed-out JSON holds %q: %s", what, bad, text)
		}
	}
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	for k := range top {
		if !slices.Contains(topKeys, k) {
			t.Errorf("%s: unexpected top-level key %q", what, k)
		}
	}
	var walk func(c map[string]any)
	walk = func(c map[string]any) {
		for k, v := range c {
			if !slices.Contains(commentKeys, k) {
				t.Errorf("%s: comment %v has key %q", what, c["id"], k)
			}
			if strings.HasPrefix(k, "can_") || k == "reported" {
				if v != false {
					t.Errorf("%s: comment %v: %s = %v for a signed-out caller", what, c["id"], k, v)
				}
			}
		}
		if a, ok := c["author"].(map[string]any); ok {
			for k := range a {
				if !slices.Contains(authorKeys, k) {
					t.Errorf("%s: author has key %q", what, k)
				}
			}
			if a["display_name"] != nil {
				t.Errorf("%s: comment %v: author display_name %v for a signed-out caller", what, c["id"], a["display_name"])
			}
		}
		if c["status"] != "visible" { // a placeholder: nothing but its place
			if c["author"] != nil || c["body_html"] != "" || c["lang"] != "" || c["purpose"] != nil || c["body_nodes"] != nil ||
				c["edited_at"] != nil || c["links"] != false {
				t.Errorf("%s: placeholder %v shows content: %v", what, c["id"], c)
			}
		}
		if reps, ok := c["replies"].([]any); ok {
			for _, r := range reps {
				walk(r.(map[string]any))
			}
		}
	}
	comments, _ := top["comments"].([]any)
	for _, c := range comments {
		walk(c.(map[string]any))
	}
	v, _ := top["viewer"].(map[string]any)
	if v["signed_in"] != false || v["can_post"] != false || v["post_refusal"] != "not_signed_in" || v["handle"] != nil ||
		v["role"] != nil || v["moderator"] != false || v["links"] != false {
		t.Errorf("%s: viewer %v", what, v)
	}
	return top
}

// withoutCaller drops the fields that depend on who asks (permissions,
// reported, viewer, the authors' display names) so a signed-out and a
// signed-in response compare.
func withoutCaller(t *testing.T, raw []byte) string {
	t.Helper()
	var top map[string]any
	if err := json.Unmarshal(raw, &top); err != nil {
		t.Fatal(err)
	}
	delete(top, "viewer")
	var strip func(c map[string]any)
	strip = func(c map[string]any) {
		for k := range c {
			if strings.HasPrefix(k, "can_") || k == "reported" {
				delete(c, k)
			}
		}
		if a, ok := c["author"].(map[string]any); ok {
			delete(a, "display_name")
		}
		if reps, ok := c["replies"].([]any); ok {
			for _, r := range reps {
				strip(r.(map[string]any))
			}
		}
	}
	comments, _ := top["comments"].([]any)
	for _, c := range comments {
		strip(c.(map[string]any))
	}
	b, _ := json.Marshal(top)
	return string(b)
}

// TestGuestRead: with signed-out reading on, a signed-out caller gets what
// a signed-in member without any role sees of the comments (bodies,
// authors' public names, times, replies, purposes) and nothing more: no
// hidden, deleted or reply-deleted text, no source, no hide reason, no
// report, no revision, no user id, no permission; every query form
// (c=, thread=, cursor=, limit=) obeys the same rule.
func TestGuestRead(t *testing.T) {
	h := newHarness(t, hopt{terms: terms, limits: guestLimits()})
	ada, bob, mod, ids := guestFixture(t, h)
	anon := h.browser()
	anon.ip = "203.0.113.50"

	resp, raw := anon.do("GET", "/api/discuss/"+cveA+"?locale=en", "")
	if resp.StatusCode != 200 || !strings.Contains(strings.Join(resp.Header.Values("Vary"), ","), "Cookie") {
		t.Fatalf("guest read: %d %v %s", resp.StatusCode, resp.Header, raw)
	}
	t.Logf("signed-out GET /api/discuss/%s: %s", cveA, raw)
	top := checkGuestJSON(t, "first page", raw, ada.id, bob.id, mod.id)
	for _, want := range []string{"PUBLIC-T1", "PUBLIC-R1", "PUBLIC-R2", "PUBLIC-R3", `"handle":"ada"`, `"handle":"bob"`,
		`"purpose":"analysis"`, `"created_at":"2026-11-13T12:00:00Z"`, `"edited_at":"2026-11-13T12:00:01Z"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("guest read lacks %q", want)
		}
	}
	// threads: T1 (visible, R1; R5 hidden placeholder; R6 deleted: absent),
	// T2 (hidden placeholder, R2), T3 (deleted placeholder, R3); T4 absent
	var s stream
	_ = json.Unmarshal(raw, &s)
	shape := []string{}
	for _, c := range s.Comments {
		x := c.Status
		for _, r := range c.Replies {
			x += "+" + r.Status
		}
		shape = append(shape, x)
	}
	if strings.Join(shape, ",") != "visible+visible+hidden,hidden+visible,deleted+visible" || s.Count != 4 || top["next_cursor"] != nil {
		t.Errorf("shape %v count %d", shape, s.Count)
	}
	if strings.Contains(string(raw), ids["T4"]) || strings.Contains(string(raw), ids["R6"]) {
		t.Error("a deleted comment without replies, or a deleted reply, is listed")
	}

	// the same as a signed-in member without any role sees, but for the
	// caller's own fields
	rd := h.reader()
	_, mine := rd.do("GET", "/api/discuss/"+cveA+"?locale=en", "")
	if a, b := withoutCaller(t, raw), withoutCaller(t, mine); a != b {
		t.Errorf("guest and member views differ:\n%s\n%s", a, b)
	}

	// every query form
	cur := ""
	if len(s.Comments) > 0 {
		var one stream
		_, r1 := anon.do("GET", "/api/discuss/"+cveA+"?limit=1", "")
		_ = json.Unmarshal(r1, &one)
		checkGuestJSON(t, "limit=1", r1, ada.id, bob.id, mod.id)
		if one.NextCursor == nil || len(one.Comments) != 1 {
			t.Fatalf("limit=1: %s", r1)
		}
		cur = *one.NextCursor
	}
	for _, q := range []string{"?cursor=" + cur, "?c=" + ids["R1"], "?c=" + ids["R5"], "?c=" + ids["T2"], "?c=" + ids["T4"],
		"?thread=" + ids["T1"], "?thread=" + ids["T2"], "?thread=" + ids["T3"], "?locale=ja&limit=200"} {
		resp, raw := anon.do("GET", "/api/discuss/"+cveA+q, "")
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d %s", q, resp.StatusCode, raw)
			continue
		}
		checkGuestJSON(t, q, raw, ada.id, bob.id, mod.id)
		_, mine := rd.do("GET", "/api/discuss/"+cveA+q, "")
		if a, b := withoutCaller(t, raw), withoutCaller(t, mine); a != b {
			t.Errorf("%s: guest and member views differ:\n%s\n%s", q, a, b)
		}
	}
	if resp, raw := anon.do("GET", "/api/discuss/"+cveA+"?thread="+ids["T4"], ""); resp.StatusCode != 404 {
		t.Errorf("thread of a deleted comment without replies: %d %s", resp.StatusCode, raw)
	}

	// signed-in members still get their own fields
	s = ada.stream(cveA, "")
	if c := s.Comments[0]; c.Body == nil || !c.CanEdit {
		t.Errorf("author's view: %+v", c)
	}
	s = mod.stream(cveA, "")
	if c := s.Comments[1]; c.Moderation == nil || c.Body == nil || *c.Body != "SECRET-HIDDEN-T2 abuse" {
		t.Errorf("moderator's view of the hidden comment: %+v", c)
	}
}

// TestGuestReadNoDisplayName: an author's display name (copied from the
// sign-in provider's profile) never reaches a signed-out caller, whatever
// the query form (first page, c=, thread=, cursor=), nor a signed-in
// member; only a moderator gets it.
func TestGuestReadNoDisplayName(t *testing.T) {
	h := newHarness(t, hopt{terms: terms, limits: guestLimits()})
	ada, bob, mod, ids := guestFixture(t, h)
	names := map[string]string{ada.id: "Ada Byron-King", bob.id: "Robert Q. Private"}
	for id, n := range names {
		if _, err := h.db.Conn.Exec(context.Background(), `UPDATE users SET display_name = $2 WHERE id = $1`, id, n); err != nil {
			t.Fatal(err)
		}
	}
	anon := h.browser()
	anon.ip = "203.0.113.51"
	_, r1 := anon.do("GET", "/api/discuss/"+cveA+"?limit=1", "")
	var one stream
	if err := json.Unmarshal(r1, &one); err != nil || one.NextCursor == nil {
		t.Fatalf("limit=1: %s", r1)
	}
	queries := []string{"", "?limit=1", "?cursor=" + *one.NextCursor}
	for _, k := range []string{"T1", "R1", "R2", "R3", "T2", "R5"} {
		queries = append(queries, "?c="+ids[k])
	}
	for _, k := range []string{"T1", "T2", "T3"} {
		queries = append(queries, "?thread="+ids[k])
	}
	for _, q := range queries {
		resp, raw := anon.do("GET", "/api/discuss/"+cveA+q, "")
		if resp.StatusCode != 200 {
			t.Errorf("%q: %d %s", q, resp.StatusCode, raw)
			continue
		}
		if !strings.Contains(string(raw), `"handle":"`) {
			t.Errorf("%q: no author in %s", q, raw)
		}
		for _, n := range names {
			if strings.Contains(string(raw), n) {
				t.Errorf("%q: signed-out response holds the display name %q: %s", q, n, raw)
			}
		}
		checkGuestJSON(t, q, raw, ada.id, bob.id)
	}
	// a signed-in member does not get it either; a moderator does
	_, mine := h.reader().do("GET", "/api/discuss/"+cveA, "")
	for _, n := range names {
		if strings.Contains(string(mine), n) {
			t.Errorf("member's response holds the display name %q: %s", n, mine)
		}
	}
	_, staff := mod.do("GET", "/api/discuss/"+cveA, "")
	if !strings.Contains(string(staff), `"display_name":"Ada Byron-King"`) {
		t.Errorf("moderator's view lost the display name: %s", staff)
	}
}

// TestGuestWritesRefused: signed out, every write and moderator endpoint
// is refused exactly as before signed-out reading existed (401
// not_signed_in), with or without a forged CSRF header, and nothing is
// written.
func TestGuestWritesRefused(t *testing.T) {
	h := newHarness(t, hopt{terms: terms, limits: guestLimits()})
	_, _, _, ids := guestFixture(t, h)
	anon := h.browser()
	before := h.count(`SELECT count(*) FROM comments`) + h.count(`SELECT count(*) FROM comment_reports`) +
		h.count(`SELECT count(*) FROM comment_revisions`)
	id := ids["T1"]
	for _, c := range []struct{ path, body string }{
		{"/api/discuss/" + cveA, `{"body":"guest post","lang":"en"}`},
		{"/api/discuss/" + cveA, `{"body":"guest reply","lang":"en","parent_id":"` + id + `"}`},
		{"/api/discuss/comment/" + id + "/edit", `{"body":"guest edit","purpose":"fix"}`},
		{"/api/discuss/comment/" + id + "/delete", ""},
		{"/api/discuss/comment/" + id + "/report", `{"reason":"spam"}`},
		{"/api/discuss/comment/" + id + "/hide", `{"reason":"x"}`},
		{"/api/discuss/comment/" + ids["T2"] + "/unhide", ""},
		{"/api/mod/reports/00000000-0000-4000-8000-000000000000/resolve", `{"resolution":"dismissed"}`},
	} {
		for _, hdr := range [][]string{
			{"Origin", origin, "Sec-Fetch-Site", "same-origin", "Content-Type", "application/json"},
			{"Origin", origin, "Sec-Fetch-Site", "same-origin", "Content-Type", "application/json", "X-CSRF-Token", "forged"},
		} {
			resp, body := anon.do("POST", c.path, c.body, hdr...)
			expect(t, "signed out POST "+c.path, resp, body, 401, "not_signed_in")
		}
	}
	for _, p := range []string{"/api/mod/reports", "/api/mod/recent", "/api/mod/comment/" + id + "/revisions"} {
		resp, body := anon.do("GET", p, "")
		expect(t, "signed out GET "+p, resp, body, 401, "not_signed_in")
	}
	after := h.count(`SELECT count(*) FROM comments`) + h.count(`SELECT count(*) FROM comment_reports`) +
		h.count(`SELECT count(*) FROM comment_revisions`)
	if after != before {
		t.Errorf("signed-out requests wrote rows: %d -> %d", before, after)
	}
}

// TestGuestReadSwitch: turning signed-out reading off at run time
// (SetLimits, as /admin/settings does) restores the outline for signed-out
// callers at once (members unaffected); the guest bucket limits signed-out
// reads per address and does not touch members.
func TestGuestReadSwitch(t *testing.T) {
	h := newHarness(t, hopt{terms: terms, limits: guestLimits()})
	ada, bob, mod, _ := guestFixture(t, h)
	anon := h.browser()
	if !h.dsvc.GuestRead() {
		t.Fatal("GuestRead off with GuestRead limits")
	}
	off := *guestLimits()
	off.GuestRead = false
	h.dsvc.SetLimits(off)
	if h.dsvc.GuestRead() {
		t.Fatal("GuestRead still on")
	}
	resp, raw := anon.do("GET", "/api/discuss/"+cveA, "")
	if resp.StatusCode != 200 || strings.Contains(string(raw), "PUBLIC-") || strings.Contains(string(raw), "SECRET-") ||
		!strings.Contains(string(raw), `"outline":{"count":4`) || !strings.Contains(string(raw), `"comments":[]`) ||
		strings.Contains(string(raw), ada.id) || strings.Contains(string(raw), `"handle":"ada"`) {
		t.Errorf("guest reading off: %d %s", resp.StatusCode, raw)
	}
	if s := bob.stream(cveA, ""); len(s.Comments) != 3 || s.Outline != nil {
		t.Errorf("member with guest reading off: %+v", s)
	}

	// the guest bucket: 2 signed-out reads, then 429; members go on
	on := *guestLimits()
	on.GuestReadBurst, on.GuestReadEvery = 2, time.Hour
	h.dsvc.SetLimits(on)
	for i := 0; i < 2; i++ {
		if resp, raw := anon.do("GET", "/api/discuss/"+cveA, ""); resp.StatusCode != 200 || !strings.Contains(string(raw), "PUBLIC-T1") {
			t.Fatalf("guest read %d: %d %s", i, resp.StatusCode, raw)
		}
	}
	resp, raw = anon.do("GET", "/api/discuss/"+cveA, "")
	expect(t, "third guest read", resp, raw, 429, "rate_limited")
	if resp.Header.Get("Retry-After") == "" {
		t.Error("429 without Retry-After")
	}
	mod.ip = anon.ip
	if s := mod.stream(cveA, ""); len(s.Comments) != 3 {
		t.Errorf("a member from the same address: %+v", s)
	}
	other := h.browser()
	other.ip = "203.0.113.99"
	if resp, _ := other.do("GET", "/api/discuss/"+cveA, ""); resp.StatusCode != 200 {
		t.Errorf("another address: %d", resp.StatusCode)
	}
}

// TestGuestReadEnv: NDAY_DISCUSS_GUEST_READ and its bucket.
func TestGuestReadEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	l, err := discuss.LimitsFromEnv(env(nil))
	if err != nil || !l.GuestRead || l.GuestReadBurst != 60 || l.GuestReadEvery != 2*time.Second {
		t.Errorf("defaults: %+v %v", l, err)
	}
	l, err = discuss.LimitsFromEnv(env(map[string]string{"NDAY_DISCUSS_GUEST_READ": " OFF ",
		"NDAY_DISCUSS_GUEST_READ_BURST": "5", "NDAY_DISCUSS_GUEST_READ_EVERY": "1m"}))
	if err != nil || l.GuestRead || l.GuestReadBurst != 5 || l.GuestReadEvery != time.Minute {
		t.Errorf("set: %+v %v", l, err)
	}
	for k, v := range map[string]string{"NDAY_DISCUSS_GUEST_READ": "yes-secret", "NDAY_DISCUSS_GUEST_READ_BURST": "-7",
		"NDAY_DISCUSS_GUEST_READ_EVERY": "forever"} {
		_, err := discuss.LimitsFromEnv(env(map[string]string{k: v}))
		if err == nil || !strings.Contains(err.Error(), k) || strings.Contains(err.Error(), v) {
			t.Errorf("%s=%s: %v", k, v, err)
		}
	}
}

// TestPurpose: the optional purpose of top-level comments — set when
// posting, shown to everyone, changed by the author's edit (the old one
// kept with the old body in a revision), refused on replies and for
// unknown values; the database enforces the same.
func TestPurpose(t *testing.T) {
	h := newHarness(t, hopt{terms: terms, limits: guestLimits()})
	ada, bob, mod := h.member("ada"), h.member("bob"), h.member("carol")
	h.setRole(mod.id, "moderator")
	mod.refresh()
	create := func(b *browser, body string) (*http.Response, []byte) {
		return b.post("/api/discuss/"+cveA, body)
	}
	resp, raw := create(ada, `{"body":"repro on 2.3.1, Debian 12","lang":"en","purpose":"reproduction"}`)
	expect(t, "with purpose", resp, raw, 201, "")
	var cr struct {
		Comment struct {
			ID      string  `json:"id"`
			Purpose *string `json:"purpose"`
		} `json:"comment"`
	}
	_ = json.Unmarshal(raw, &cr)
	id := cr.Comment.ID
	if cr.Comment.Purpose == nil || *cr.Comment.Purpose != "reproduction" {
		t.Errorf("purpose: %s", raw)
	}
	for _, body := range []string{`{"body":"no purpose","lang":"en"}`, `{"body":"null purpose","lang":"en","purpose":null}`,
		`{"body":"empty purpose","lang":"en","purpose":""}`} {
		resp, raw := create(ada, body)
		if resp.StatusCode != 201 || !strings.Contains(string(raw), `"purpose":null`) {
			t.Errorf("%s: %d %s", body, resp.StatusCode, raw)
		}
	}
	for what, body := range map[string]string{
		"unknown purpose":    `{"body":"x1","lang":"en","purpose":"correction"}`,
		"purpose on a reply": `{"body":"x2","lang":"en","purpose":"fix","parent_id":"` + id + `"}`,
		"not a string":       `{"body":"x3","lang":"en","purpose":5}`,
	} {
		resp, raw := create(bob, body)
		want, code := 400, "bad_purpose"
		if what == "not a string" {
			code = "bad_request"
		}
		expect(t, what, resp, raw, want, code)
		if code == "bad_purpose" && errParam(raw) != "purpose" {
			t.Errorf("%s: param %q", what, errParam(raw))
		}
	}
	resp, raw = create(bob, `{"body":"a reply","lang":"en","parent_id":"`+id+`","purpose":null}`)
	expect(t, "reply, null purpose", resp, raw, 201, "")
	var rr struct {
		Comment struct {
			ID string `json:"id"`
		} `json:"comment"`
	}
	_ = json.Unmarshal(raw, &rr)

	// shown to a signed-out reader
	if s, raw := h.browser().do("GET", "/api/discuss/"+cveA, ""); s.StatusCode != 200 ||
		!strings.Contains(string(raw), `"purpose":"reproduction"`) {
		t.Errorf("guest view: %s", raw)
	}

	edit := func(body string) (*http.Response, []byte) {
		return ada.post("/api/discuss/comment/"+id+"/edit", body)
	}
	revs := func() int { return h.count(`SELECT count(*) FROM comment_revisions WHERE comment_id = $1`, id) }
	purpose := func() string {
		var p *string
		if err := h.db.Conn.QueryRow(context.Background(), `SELECT purpose FROM comments WHERE id = $1`, id).Scan(&p); err != nil {
			t.Fatal(err)
		}
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	// purpose only: an edit (revision with the old body and purpose)
	resp, raw = edit(`{"body":"repro on 2.3.1, Debian 12","purpose":"fix"}`)
	if resp.StatusCode != 200 || !strings.Contains(string(raw), `"purpose":"fix"`) || strings.Contains(string(raw), `"edited_at":null`) ||
		revs() != 1 || purpose() != "fix" {
		t.Errorf("purpose edit: %d %s revs %d", resp.StatusCode, raw, revs())
	}
	// no purpose key: kept; body unchanged: nothing written
	h.clock.Advance(time.Second)
	resp, raw = edit(`{"body":"repro on 2.3.1, Debian 12"}`)
	if resp.StatusCode != 200 || revs() != 1 || purpose() != "fix" {
		t.Errorf("unchanged edit: %d %s revs %d", resp.StatusCode, raw, revs())
	}
	// body changed, purpose kept
	resp, raw = edit(`{"body":"fixed in 2.3.2"}`)
	if resp.StatusCode != 200 || revs() != 2 || purpose() != "fix" {
		t.Errorf("body edit: %d %s", resp.StatusCode, raw)
	}
	// null clears
	h.clock.Advance(time.Second)
	resp, raw = edit(`{"body":"fixed in 2.3.2","purpose":null}`)
	if resp.StatusCode != 200 || revs() != 3 || purpose() != "<nil>" || !strings.Contains(string(raw), `"purpose":null`) {
		t.Errorf("clear: %d %s", resp.StatusCode, raw)
	}
	for what, body := range map[string]string{"unknown": `{"body":"x","purpose":"correction"}`, "number": `{"body":"x","purpose":5}`} {
		resp, raw := edit(body)
		expect(t, "edit "+what, resp, raw, 400, "bad_purpose")
	}
	// replies: a purpose is refused; null is fine
	resp, raw = bob.post("/api/discuss/comment/"+rr.Comment.ID+"/edit", `{"body":"a reply","purpose":"fix"}`)
	expect(t, "reply edit with purpose", resp, raw, 400, "bad_purpose")
	resp, raw = bob.post("/api/discuss/comment/"+rr.Comment.ID+"/edit", `{"body":"a reply, edited","purpose":null}`)
	expect(t, "reply edit, null purpose", resp, raw, 200, "")

	// moderators read each earlier purpose with its body, newest first
	resp, raw = mod.do("GET", "/api/mod/comment/"+id+"/revisions", "")
	var rv struct {
		Revisions []struct {
			Body    string  `json:"body"`
			Purpose *string `json:"purpose"`
		} `json:"revisions"`
	}
	if err := json.Unmarshal(raw, &rv); err != nil || resp.StatusCode != 200 || len(rv.Revisions) != 3 {
		t.Fatalf("revisions: %d %s", resp.StatusCode, raw)
	}
	got := []string{}
	for _, r := range rv.Revisions {
		p := "<nil>"
		if r.Purpose != nil {
			p = *r.Purpose
		}
		got = append(got, r.Body+"|"+p)
	}
	if want := "fixed in 2.3.2|fix,repro on 2.3.1, Debian 12|fix,repro on 2.3.1, Debian 12|reproduction"; strings.Join(got, ",") != want {
		t.Errorf("revisions %v, want %s", got, want)
	}

	// the database itself
	ctx := context.Background()
	for what, q := range map[string]string{
		"unknown value": `UPDATE comments SET purpose = 'correction' WHERE id = '` + id + `'`,
		"on a reply":    `UPDATE comments SET purpose = 'fix' WHERE id = '` + rr.Comment.ID + `'`,
		"revision":      `UPDATE comment_revisions SET purpose = 'correction' WHERE comment_id = '` + id + `'`,
	} {
		if _, err := h.db.Conn.Exec(ctx, q); err == nil || !strings.Contains(err.Error(), "check constraint") {
			t.Errorf("%s: %v", what, err)
		}
	}
}
