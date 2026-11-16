package discuss_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/discuss"
)

func TestCreateReadAndVisibility(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ada, bob, mod := h.member("ada"), h.member("bob"), h.member("carol")
	h.establish(ada.id)
	h.setRole(mod.id, "moderator")
	mod.refresh()
	anon := h.browser()

	top := ada.create(cveA, "Patch: **upgrade** to 2.0, see CVE-2026-0002 and https://example.com/a?x=1&y=2\n<script>SECRET-BODY</script>", nil)
	if top.Status != "visible" || top.Lang != "zh-Hans" || !top.Links || top.Body == nil || !top.CanEdit || !top.CanDelete || top.CanReport {
		t.Errorf("created comment as seen by its author: %+v", top)
	}
	if !strings.Contains(top.BodyHTML, `<strong>upgrade</strong>`) || !strings.Contains(top.BodyHTML, `href="/zh-hans/vuln/CVE-2026-0002"`) ||
		!strings.Contains(top.BodyHTML, `href="https://example.com/a?x=1&amp;y=2"`) || strings.Contains(top.BodyHTML, "<script") {
		t.Errorf("body_html: %s", top.BodyHTML)
	}
	reply := bob.create(cveA, "thanks", &top.ID)
	if reply.ParentID == nil || *reply.ParentID != top.ID || reply.Replies != nil {
		t.Errorf("reply: %+v", reply)
	}
	if reply.Links { // bob is a new account: his links are not clickable
		t.Errorf("a new account's reply has links=true")
	}

	// signed out: the outline only (docs/discuss.md §4.1): count and
	// shape, no body, author, id, language or time
	s := anon.stream(cveA, "?locale=ja")
	if s.CVE != cveA || s.Count != 2 || len(s.Comments) != 0 || s.NextCursor != nil || s.Outline == nil ||
		len(s.Outline.Threads) != 1 || s.Outline.Threads[0].Status != "visible" || s.Outline.Threads[0].Size != "s" ||
		len(s.Outline.Threads[0].Replies) != 1 || s.Outline.More {
		t.Fatalf("signed-out stream: %+v", s)
	}
	if s.Viewer.SignedIn || s.Viewer.CanPost || s.Viewer.PostRefusal == nil || *s.Viewer.PostRefusal != "not_signed_in" ||
		s.Viewer.TermsVersion == nil || *s.Viewer.TermsVersion != terms {
		t.Errorf("signed-out viewer: %+v", s.Viewer)
	}
	// raw JSON, whatever the query asks: nothing of the comments but their shape
	for _, q := range []string{"", "?locale=ja", "?thread=" + top.ID, "?c=" + top.ID, "?limit=1&cursor=" + "MTc2MzAzNTIwMDAwMDAwMC45MTUxNmVhMi01ZjYwLTQxODItOGQzNC00ZTVmNjA3MTgyOTM"} {
		resp, raw := anon.do("GET", "/api/discuss/"+cveA+q, "")
		if resp.StatusCode != 200 {
			t.Errorf("signed out %s: %d %s", q, resp.StatusCode, raw)
		}
		for _, bad := range []string{`"body`, ada.id, bob.id, "ada", "bob", "SECRET-BODY", "upgrade", "thanks", top.ID, reply.ID,
			"created_at", "zh-Hans", "author"} {
			if strings.Contains(string(raw), bad) {
				t.Errorf("signed-out JSON %s holds %q: %s", q, bad, raw)
			}
		}
	}
	// a signed-in reader without a handle: the public fields of every comment
	rd := h.reader()
	s = rd.stream(cveA, "?locale=ja")
	if s.CVE != cveA || s.Count != 2 || len(s.Comments) != 1 || len(s.Comments[0].Replies) != 1 || s.NextCursor != nil || s.Outline != nil {
		t.Fatalf("reader stream: %+v", s)
	}
	c := s.Comments[0]
	if c.Body != nil || c.CanEdit || c.CanDelete || !c.CanReport || c.CanReply || c.CanHide || c.Moderation != nil ||
		c.Author == nil || *c.Author.Handle != "ada" || !strings.Contains(c.BodyHTML, `href="/ja/vuln/CVE-2026-0002"`) {
		t.Errorf("reader's view of a comment: %+v", c)
	}
	if c.Replies[0].Replies != nil {
		t.Errorf("a reply has replies: %+v", c.Replies[0])
	}
	_, raw := rd.do("GET", "/api/discuss/"+cveA, "")
	// (body_nodes carries the text "<script>…" as a JSON string: text, never markup)
	if strings.Contains(string(raw), `"body":`) || strings.Contains(string(raw), ada.id) || strings.Contains(c.BodyHTML, "<script") ||
		!strings.Contains(string(raw), `"body_nodes":[{"e":"p","c":["Patch: ",{"e":"strong","c":["upgrade"]}`) {
		t.Errorf("reader JSON leaks source or user ids, or lacks body_nodes: %s", raw)
	}

	// another member: may report and reply
	s = bob.stream(cveA, "")
	c = s.Comments[0]
	if c.Body != nil || c.CanEdit || c.CanDelete || !c.CanReport || !c.CanReply || !s.Viewer.CanPost || s.Viewer.Links {
		t.Errorf("bob's view: %+v viewer %+v", c, s.Viewer)
	}
	if r := c.Replies[0]; r.Body == nil || !r.CanEdit || !r.CanDelete || r.CanReport || r.CanReply {
		t.Errorf("bob's view of his reply: %+v", r)
	}
	// the author
	s = ada.stream(cveA, "")
	if c = s.Comments[0]; c.Body == nil || !c.CanEdit || !c.CanDelete || c.CanReport || !s.Viewer.Links {
		t.Errorf("author's view: %+v %+v", c, s.Viewer)
	}
	// a moderator
	s = mod.stream(cveA, "")
	if c = s.Comments[0]; c.Body == nil || !c.CanHide || c.CanUnhide || c.Moderation == nil || c.Moderation.OpenReports == nil || !s.Viewer.Moderator {
		t.Errorf("moderator's view: %+v", c)
	}

	// replies need a visible top-level parent of the same vulnerability
	resp, body := bob.tryCreate(cveA, "reply to reply", &reply.ID)
	expect(t, "reply to a reply", resp, body, 400, "bad_parent")
	resp, body = bob.tryCreate(cveB, "cross-cve", &top.ID)
	expect(t, "reply across vulnerabilities", resp, body, 400, "bad_parent")
	resp, body = bob.tryCreate(cveA, "unknown parent", ptr("0b8c6f0e-7f0e-4c1a-9a51-3c2f6f1d9e44"))
	expect(t, "unknown parent", resp, body, 400, "bad_parent")
	resp, body = bob.tryCreate(cveA, "bad parent id", ptr("x'; DROP TABLE comments"))
	expect(t, "malformed parent", resp, body, 400, "bad_parent")
	if n := h.count(`SELECT count(*) FROM comments WHERE cve_id = $1`, cveA); n != 2 {
		t.Errorf("%d comments on %s, want 2", n, cveA)
	}
}

func TestCreateRefusals(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ada := h.member("ada")
	ok := `{"body":"hello","lang":"en"}`
	path := "/api/discuss/" + cveA

	anon := h.browser()
	resp, body := anon.do("POST", path, ok, "Origin", origin, "Sec-Fetch-Site", "same-origin", "Content-Type", "application/json")
	expect(t, "signed out", resp, body, 401, "not_signed_in")

	resp, body = ada.do("POST", path, ok, "Origin", "https://evil.example", "Content-Type", "application/json", "X-CSRF-Token", ada.csrf)
	expect(t, "wrong origin", resp, body, 403, "cross_site")
	resp, body = ada.do("POST", path, ok, "Sec-Fetch-Site", "cross-site", "Content-Type", "application/json", "X-CSRF-Token", ada.csrf)
	expect(t, "cross-site fetch", resp, body, 403, "cross_site")
	resp, body = ada.do("POST", path, ok, "Content-Type", "application/json", "X-CSRF-Token", ada.csrf)
	expect(t, "no origin evidence", resp, body, 403, "cross_site")
	resp, body = ada.do("POST", path, ok, "Origin", origin, "Content-Type", "application/json")
	expect(t, "missing CSRF", resp, body, 403, "csrf")
	resp, body = ada.do("POST", path, ok, "Origin", origin, "Content-Type", "application/json", "X-CSRF-Token", "AAAA"+ada.csrf[4:])
	expect(t, "invalid CSRF", resp, body, 403, "csrf")
	resp, body = ada.do("POST", path, ok, "Origin", origin, "Content-Type", "text/plain", "X-CSRF-Token", ada.csrf)
	expect(t, "text/plain", resp, body, 415, "bad_request")
	resp, body = ada.do("POST", path, ok, "Host", "evil.example", "Origin", origin, "Content-Type", "application/json", "X-CSRF-Token", ada.csrf)
	expect(t, "other host", resp, body, 421, "wrong_host")
	resp, body = ada.do("POST", path, ok, "Host", apiHost, "Origin", origin, "Content-Type", "application/json", "X-CSRF-Token", ada.csrf)
	expect(t, "API host", resp, body, 405, "method_not_allowed")
	resp, body = ada.do("GET", path, "", "Host", apiHost)
	expect(t, "API host GET", resp, body, 404, "not_found")
	resp, body = ada.do("PUT", path, ok)
	expect(t, "PUT", resp, body, 405, "method_not_allowed")

	resp, body = ada.post("/api/discuss/CVE-2026-9999", ok)
	expect(t, "unknown cve", resp, body, 404, "not_found")
	resp, body = ada.post("/api/discuss/not-a-cve", ok)
	expect(t, "malformed cve", resp, body, 400, "bad_cve")
	resp, body = ada.post(path, `{"body":"   \u0000‮  ","lang":"en"}`)
	expect(t, "empty after normalisation", resp, body, 400, "invalid_body")
	resp, body = ada.post(path, fmt.Sprintf(`{"body":%q,"lang":"en"}`, strings.Repeat("字", discuss.MaxBodyChars+1)))
	expect(t, "over 10000 characters", resp, body, 400, "invalid_body")
	resp, body = ada.post(path, fmt.Sprintf(`{"body":%q,"lang":"en"}`, strings.Repeat("a", 70000)))
	expect(t, "over 64 KiB", resp, body, 413, "too_large")
	resp, body = ada.post(path, `{"body":"x","lang":"xx"}`)
	expect(t, "disabled lang", resp, body, 400, "bad_lang")
	resp, body = ada.post(path, `{"body":"x","lang":"en","admin":true}`)
	expect(t, "unknown field", resp, body, 400, "bad_request")
	resp, body = ada.post(path, `{"body":"x","lang":"en"} {}`)
	expect(t, "trailing JSON", resp, body, 400, "bad_request")
	// exactly 10000 characters after trimming is fine; CR/LF normalised
	c := ada.create(cveA, "  "+strings.Repeat("字", discuss.MaxBodyChars)+"\r\n ", nil)
	if c.Body == nil || len([]rune(*c.Body)) != discuss.MaxBodyChars {
		t.Errorf("10000-character body not stored as such")
	}

	// no handle
	nohandle := h.browser()
	nohandle.signIn("dave")
	resp, body = nohandle.post(path, ok)
	expect(t, "no handle", resp, body, 403, "handle_required")
	// terms not accepted
	noterms := h.browser()
	id := noterms.signIn("erin")
	key := "erin"
	if _, err := h.as.SetHandle(context.Background(), id, "erin", key, 0); err != nil {
		t.Fatal(err)
	}
	resp, body = noterms.post(path, ok)
	expect(t, "terms not accepted", resp, body, 403, "terms_required")
	if errParam(body) != terms {
		t.Errorf("terms_required param %q, want %q", errParam(body), terms)
	}
	if err := h.as.AcceptTerms(context.Background(), id, "2025-01-01"); err != nil {
		t.Fatal(err)
	}
	resp, body = noterms.post(path, ok)
	expect(t, "old terms version", resp, body, 403, "terms_required")
	s := noterms.stream(cveA, "")
	if s.Viewer.CanPost || s.Viewer.PostRefusal == nil || *s.Viewer.PostRefusal != "terms_required" {
		t.Errorf("viewer with old terms: %+v", s.Viewer)
	}
	// suspended
	if err := h.as.Suspend(context.Background(), ada.id, nil, "test"); err != nil {
		t.Fatal(err)
	}
	resp, body = ada.post(path, ok)
	expect(t, "suspended", resp, body, 403, "suspended")
	s = ada.stream(cveA, "")
	if s.Viewer.CanPost || *s.Viewer.PostRefusal != "suspended" || s.Comments[0].CanEdit || !s.Comments[0].CanDelete {
		t.Errorf("suspended viewer: %+v %+v", s.Viewer, s.Comments[0])
	}
	if n := h.count(`SELECT count(*) FROM comments`); n != 1 {
		t.Errorf("%d comments stored, want 1", n)
	}
}

func TestNoTermsConfigured(t *testing.T) {
	h := newHarness(t, hopt{})
	ada := h.member("ada")
	ada.create(cveA, "no rules published yet", nil)
	if s := ada.stream(cveA, ""); !s.Viewer.CanPost || s.Viewer.TermsVersion != nil {
		t.Errorf("viewer without terms: %+v", s.Viewer)
	}
}

func TestEditAndDelete(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ada, bob := h.member("ada"), h.member("bob")
	c := ada.create(cveA, "first SECRET-BODY", nil)
	edit := func(b *browser, id, text string) (*http.Response, []byte) {
		j, _ := json.Marshal(map[string]string{"body": text})
		return b.post("/api/discuss/comment/"+id+"/edit", string(j))
	}
	h.clock.Advance(time.Minute)
	resp, body := edit(ada, c.ID, "second *version*")
	expect(t, "edit", resp, body, 200, "")
	var r struct {
		Comment comment `json:"comment"`
	}
	_ = json.Unmarshal(body, &r)
	if r.Comment.EditedAt == nil || *r.Comment.Body != "second *version*" || !strings.Contains(r.Comment.BodyHTML, "<em>version</em>") {
		t.Errorf("edited: %+v", r.Comment)
	}
	if n := h.count(`SELECT count(*) FROM comment_revisions WHERE comment_id = $1 AND body = 'first SECRET-BODY'`, c.ID); n != 1 {
		t.Errorf("%d revisions with the old body", n)
	}
	resp, body = edit(ada, c.ID, "second *version*") // unchanged: no revision
	expect(t, "unchanged edit", resp, body, 200, "")
	if n := h.count(`SELECT count(*) FROM comment_revisions`); n != 1 {
		t.Errorf("%d revisions after a no-op edit", n)
	}
	resp, body = edit(bob, c.ID, "hijack")
	expect(t, "edit by another user", resp, body, 403, "not_author")
	resp, body = edit(ada, "0b8c6f0e-7f0e-4c1a-9a51-3c2f6f1d9e44", "x")
	expect(t, "edit unknown", resp, body, 404, "not_found")
	resp, body = edit(ada, "nope", "x")
	expect(t, "edit malformed id", resp, body, 404, "not_found")
	resp, body = edit(ada, c.ID, " ")
	expect(t, "edit to empty", resp, body, 400, "invalid_body")
	resp, body = ada.do("POST", "/api/discuss/comment/"+c.ID+"/edit", `{"body":"x"}`, "Origin", origin, "Content-Type", "application/json")
	expect(t, "edit without CSRF", resp, body, 403, "csrf")
	// revisions are never exposed
	_, raw := ada.do("GET", "/api/discuss/"+cveA, "")
	if strings.Contains(string(raw), "SECRET-BODY") {
		t.Errorf("an old revision is visible: %s", raw)
	}

	// delete: other users cannot; the author can; twice is a conflict
	del := func(b *browser, id string) (*http.Response, []byte) {
		return b.post("/api/discuss/comment/"+id+"/delete", "")
	}
	resp, body = del(bob, c.ID)
	expect(t, "delete by another user", resp, body, 403, "not_author")
	reply := bob.create(cveA, "a reply", &c.ID)
	resp, body = del(ada, c.ID)
	expect(t, "delete", resp, body, 200, "")
	resp, body = del(ada, c.ID)
	expect(t, "delete twice", resp, body, 409, "wrong_status")
	resp, body = edit(ada, c.ID, "edit deleted")
	expect(t, "edit deleted", resp, body, 409, "wrong_status")
	// a deleted comment with replies stays as a placeholder
	s := h.reader().stream(cveA, "")
	if len(s.Comments) != 1 || s.Comments[0].Status != "deleted" || s.Comments[0].Author != nil || s.Comments[0].BodyHTML != "" ||
		len(s.Comments[0].Replies) != 1 || s.Count != 1 {
		t.Fatalf("deleted placeholder: %+v", s)
	}
	// once its last reply is deleted it disappears
	resp, body = del(bob, reply.ID)
	expect(t, "delete reply", resp, body, 200, "")
	if s := h.reader().stream(cveA, ""); len(s.Comments) != 0 || s.Count != 0 {
		t.Errorf("deleted thread still shown: %+v", s)
	}
	resp, body = bob.tryCreate(cveA, "reply to deleted", &c.ID)
	expect(t, "reply to a deleted comment", resp, body, 400, "bad_parent")

	// suspended: no edit, no create, but delete own
	d := ada.create(cveA, "another", nil)
	if err := h.as.Suspend(context.Background(), ada.id, nil, "test"); err != nil {
		t.Fatal(err)
	}
	resp, body = edit(ada, d.ID, "while suspended")
	expect(t, "edit while suspended", resp, body, 403, "suspended")
	resp, body = del(ada, d.ID)
	expect(t, "delete while suspended", resp, body, 200, "")

	// deleting needs a session, same origin and CSRF too
	e := bob.create(cveA, "keep", nil)
	resp, body = h.browser().do("POST", "/api/discuss/comment/"+e.ID+"/delete", "", "Origin", origin)
	expect(t, "delete signed out", resp, body, 401, "not_signed_in")
	resp, body = bob.do("POST", "/api/discuss/comment/"+e.ID+"/delete", "", "Origin", "https://evil.example", "X-CSRF-Token", bob.csrf)
	expect(t, "delete cross-site", resp, body, 403, "cross_site")
}

func TestReports(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ada, bob, carol := h.member("ada"), h.member("bob"), h.member("carol")
	c := ada.create(cveA, "spam spam", nil)
	report := func(b *browser, id, body string) (*http.Response, []byte) {
		return b.post("/api/discuss/comment/"+id+"/report", body)
	}
	resp, body := report(ada, c.ID, `{"reason":"spam"}`)
	expect(t, "report own", resp, body, 403, "own_comment")
	resp, body = report(bob, c.ID, `{"reason":"rude"}`)
	expect(t, "unknown reason", resp, body, 400, "bad_reason")
	resp, body = report(bob, c.ID, fmt.Sprintf(`{"reason":"other","note":%q}`, strings.Repeat("n", 501)))
	expect(t, "long note", resp, body, 400, "bad_note")
	resp, body = report(bob, c.ID, `{"reason":"spam","note":"  buy\nnow  "}`)
	expect(t, "report", resp, body, 200, "")
	var r struct {
		Already bool `json:"already_reported"`
		Report  struct {
			ID   string  `json:"id"`
			Note *string `json:"note"`
		} `json:"report"`
	}
	_ = json.Unmarshal(body, &r)
	if r.Already || r.Report.Note == nil || *r.Report.Note != "buy now" {
		t.Errorf("report: %s", body)
	}
	first := r.Report.ID
	resp, body = report(bob, c.ID, `{"reason":"abuse"}`)
	expect(t, "report again", resp, body, 200, "")
	_ = json.Unmarshal(body, &r)
	if !r.Already || r.Report.ID != first {
		t.Errorf("second report is not idempotent: %s", body)
	}
	if n := h.count(`SELECT count(*) FROM comment_reports`); n != 1 {
		t.Errorf("%d reports, want 1", n)
	}
	if s := bob.stream(cveA, ""); !s.Comments[0].Reported {
		t.Errorf("reported flag not set for the reporter")
	}
	if s := carol.stream(cveA, ""); s.Comments[0].Reported {
		t.Errorf("reported flag set for another user")
	}
	resp, body = h.browser().do("POST", "/api/discuss/comment/"+c.ID+"/report", `{"reason":"spam"}`, "Origin", origin, "Content-Type", "application/json")
	expect(t, "report signed out", resp, body, 401, "not_signed_in")
	if err := h.as.Suspend(context.Background(), carol.id, nil, "x"); err != nil {
		t.Fatal(err)
	}
	resp, body = report(carol, c.ID, `{"reason":"spam"}`)
	expect(t, "report while suspended", resp, body, 403, "suspended")
	resp, body = report(bob, "0b8c6f0e-7f0e-4c1a-9a51-3c2f6f1d9e44", `{"reason":"spam"}`)
	expect(t, "report unknown", resp, body, 404, "not_found")
}

func TestModeration(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ada, bob, mod, admin := h.member("ada"), h.member("bob"), h.member("carol"), h.member("dave")
	h.setRole(mod.id, "moderator")
	h.setRole(admin.id, "admin")
	c := ada.create(cveA, "bad SECRET-BODY", nil)
	bob.post("/api/discuss/comment/"+c.ID+"/report", `{"reason":"abuse"}`)
	hide := func(b *browser, id string) (*http.Response, []byte) {
		return b.post("/api/discuss/comment/"+id+"/hide", `{"reason":"abusive language"}`)
	}
	resp, body := hide(bob, c.ID)
	expect(t, "hide by a user", resp, body, 403, "forbidden")
	resp, body = h.browser().do("POST", "/api/discuss/comment/"+c.ID+"/hide", `{"reason":"x"}`, "Origin", origin, "Content-Type", "application/json")
	expect(t, "hide signed out", resp, body, 401, "not_signed_in")
	resp, body = mod.do("POST", "/api/discuss/comment/"+c.ID+"/hide", `{"reason":"x"}`, "Origin", origin, "Content-Type", "application/json")
	expect(t, "hide without CSRF", resp, body, 403, "csrf")
	resp, body = mod.post("/api/discuss/comment/"+c.ID+"/hide", `{"reason":"  "}`)
	expect(t, "hide without reason", resp, body, 400, "bad_reason")

	// open reports are visible to moderators only
	resp, body = bob.do("GET", "/api/mod/reports", "")
	expect(t, "reports as a user", resp, body, 403, "forbidden")
	resp, body = h.browser().do("GET", "/api/mod/reports", "")
	expect(t, "reports signed out", resp, body, 401, "not_signed_in")
	resp, body = mod.do("GET", "/api/mod/reports", "")
	expect(t, "reports", resp, body, 200, "")
	var reps struct {
		Reports []struct {
			ID       string  `json:"id"`
			Reason   string  `json:"reason"`
			Comment  comment `json:"comment"`
			Reporter *struct{ Handle *string }
		} `json:"reports"`
	}
	_ = json.Unmarshal(body, &reps)
	if len(reps.Reports) != 1 || reps.Reports[0].Comment.ID != c.ID || reps.Reports[0].Comment.Body == nil ||
		reps.Reports[0].Reporter == nil || *reps.Reports[0].Reporter.Handle != "bob" {
		t.Fatalf("open reports: %s", body)
	}

	resp, body = hide(mod, c.ID)
	expect(t, "hide", resp, body, 200, "")
	var hr struct {
		Resolved int `json:"resolved_reports"`
	}
	_ = json.Unmarshal(body, &hr)
	if hr.Resolved != 1 {
		t.Errorf("hide resolved %d reports: %s", hr.Resolved, body)
	}
	resp, body = hide(mod, c.ID)
	expect(t, "hide twice", resp, body, 409, "wrong_status")
	resp, body = bob.post("/api/discuss/comment/"+c.ID+"/report", `{"reason":"abuse"}`)
	expect(t, "report hidden", resp, body, 409, "wrong_status")
	resp, body = ada.post("/api/discuss/comment/"+c.ID+"/edit", `{"body":"sorry"}`)
	expect(t, "edit hidden", resp, body, 409, "wrong_status")
	resp, body = bob.tryCreate(cveA, "reply to hidden", &c.ID)
	expect(t, "reply to hidden", resp, body, 400, "bad_parent")

	// visibility of a hidden comment
	for name, b := range map[string]*browser{"signed-in reader": h.reader(), "other": bob} {
		s := b.stream(cveA, "")
		if len(s.Comments) != 1 {
			t.Fatalf("%s: %+v", name, s)
		}
		x := s.Comments[0]
		if x.Status != "hidden" || x.Author != nil || x.BodyHTML != "" || x.Body != nil || x.Lang != "" || x.Moderation != nil || x.CanReport {
			t.Errorf("%s sees a hidden comment as %+v", name, x)
		}
		_, raw := b.do("GET", "/api/discuss/"+cveA, "")
		if strings.Contains(string(raw), "SECRET-BODY") || strings.Contains(string(raw), "abusive") {
			t.Errorf("%s: hidden content in JSON: %s", name, raw)
		}
	}
	s := ada.stream(cveA, "")
	if x := s.Comments[0]; x.Body == nil || x.BodyHTML == "" || x.Moderation == nil || x.Moderation.HiddenReason == nil ||
		*x.Moderation.HiddenReason != "abusive language" || x.Moderation.HiddenBy != nil || !x.CanDelete || x.CanEdit {
		t.Errorf("author's view of the hidden comment: %+v", x)
	}
	s = mod.stream(cveA, "")
	if x := s.Comments[0]; x.Body == nil || x.Moderation == nil || x.Moderation.HiddenBy == nil || *x.Moderation.HiddenBy.Handle != "carol" ||
		!x.CanUnhide || x.CanHide || x.Author == nil {
		t.Errorf("moderator's view of the hidden comment: %+v", x)
	}
	if s.Count != 0 {
		t.Errorf("count includes hidden comments: %d", s.Count)
	}

	// resolved reports, resolve, recent
	resp, body = admin.do("GET", "/api/mod/reports?state=resolved", "")
	expect(t, "resolved reports", resp, body, 200, "")
	_ = json.Unmarshal(body, &reps)
	if len(reps.Reports) != 1 {
		t.Errorf("resolved: %s", body)
	}
	resp, body = admin.do("GET", "/api/mod/reports?state=all", "")
	expect(t, "bad state", resp, body, 400, "bad_request")
	resp, body = admin.post("/api/mod/reports/"+reps.Reports[0].ID+"/resolve", `{"resolution":"dismissed"}`)
	expect(t, "resolve resolved", resp, body, 409, "wrong_status")
	h.clock.Advance(time.Second)
	d := ada.create(cveB, "meh", nil)
	resp, body = bob.post("/api/discuss/comment/"+d.ID+"/report", `{"reason":"off_topic"}`)
	_ = json.Unmarshal(body, &struct{}{})
	var rr struct {
		Report struct{ ID string } `json:"report"`
	}
	_ = json.Unmarshal(body, &rr)
	resp, body = bob.post("/api/mod/reports/"+rr.Report.ID+"/resolve", `{"resolution":"dismissed"}`)
	expect(t, "resolve as a user", resp, body, 403, "forbidden")
	resp, body = admin.post("/api/mod/reports/"+rr.Report.ID+"/resolve", `{"resolution":"hidden"}`)
	expect(t, "resolve as hidden", resp, body, 400, "bad_resolution")
	resp, body = admin.post("/api/mod/reports/"+rr.Report.ID+"/resolve", `{"resolution":"dismissed"}`)
	expect(t, "resolve", resp, body, 200, "")
	resp, body = mod.do("GET", "/api/mod/recent?limit=1", "")
	expect(t, "recent", resp, body, 200, "")
	var rec struct {
		Comments   []comment `json:"comments"`
		NextCursor *string   `json:"next_cursor"`
	}
	_ = json.Unmarshal(body, &rec)
	if len(rec.Comments) != 1 || rec.Comments[0].ID != d.ID || rec.NextCursor == nil {
		t.Fatalf("recent: %s", body)
	}
	resp, body = mod.do("GET", "/api/mod/recent?cursor="+*rec.NextCursor, "")
	_ = json.Unmarshal(body, &rec)
	if len(rec.Comments) != 1 || rec.Comments[0].ID != c.ID || rec.Comments[0].Status != "hidden" {
		t.Errorf("recent page 2: %s", body)
	}
	resp, body = bob.do("GET", "/api/mod/recent", "")
	expect(t, "recent as a user", resp, body, 403, "forbidden")

	// unhide
	resp, body = bob.post("/api/discuss/comment/"+c.ID+"/unhide", "")
	expect(t, "unhide as a user", resp, body, 403, "forbidden")
	resp, body = mod.post("/api/discuss/comment/"+c.ID+"/unhide", "")
	expect(t, "unhide", resp, body, 200, "")
	resp, body = mod.post("/api/discuss/comment/"+c.ID+"/unhide", "")
	expect(t, "unhide visible", resp, body, 409, "wrong_status")
	if s := h.reader().stream(cveA, ""); s.Comments[0].Status != "visible" || s.Comments[0].BodyHTML == "" {
		t.Errorf("after unhide: %+v", s.Comments[0])
	}
	if n := h.count(`SELECT count(*) FROM comments WHERE hidden_at IS NOT NULL OR hidden_reason IS NOT NULL`); n != 0 {
		t.Errorf("hide fields not cleared on unhide")
	}

	// a suspended moderator is just suspended
	if err := h.as.Suspend(context.Background(), mod.id, nil, "x"); err != nil {
		t.Fatal(err)
	}
	resp, body = hide(mod, c.ID)
	expect(t, "hide by a suspended moderator", resp, body, 403, "suspended")
	if s := mod.stream(cveA, ""); s.Comments[0].CanHide || s.Viewer.Moderator {
		t.Errorf("suspended moderator gets moderator controls")
	}
}

func TestNewAccountsAndLinks(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	newbie, old := h.member("ada"), h.member("bob")
	h.establish(old.id)
	text := "see [this](https://evil.example/x) and https://evil.example/y about CVE-2026-0002"
	n := newbie.create(cveA, text, nil)
	o := old.create(cveA, text, nil)
	if n.Links || strings.Contains(n.BodyHTML, "https://evil.example") && strings.Contains(n.BodyHTML, `href="https://evil`) ||
		!strings.Contains(n.BodyHTML, `href="/zh-hans/vuln/CVE-2026-0002"`) {
		t.Errorf("new account's comment: links=%v %s", n.Links, n.BodyHTML)
	}
	if !o.Links || !strings.Contains(o.BodyHTML, `href="https://evil.example/x"`) {
		t.Errorf("established account's comment: %s", o.BodyHTML)
	}
	// rendering stays as written: the newbie becoming established later does
	// not make the old comment's links clickable
	h.establish(newbie.id)
	s := h.reader().stream(cveA, "")
	for _, c := range s.Comments {
		if c.ID == n.ID && strings.Contains(c.BodyHTML, `href="https://evil`) {
			t.Errorf("old comment of a now-established account became clickable")
		}
	}
	if s := newbie.stream(cveA, ""); !s.Viewer.Links {
		t.Errorf("established viewer: links=false")
	}
}

func TestPagination(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ada := h.member("ada")
	var ids []string
	for i := 0; i < 7; i++ {
		h.clock.Advance(time.Second)
		ids = append(ids, ada.create(cveA, fmt.Sprintf("comment %d", i), nil).ID)
	}
	anon := h.reader()
	var got []string
	q := "?limit=3"
	for pages := 0; ; pages++ {
		s := anon.stream(cveA, q)
		for _, c := range s.Comments {
			got = append(got, c.ID)
		}
		if s.NextCursor == nil {
			break
		}
		if pages > 5 {
			t.Fatal("no end")
		}
		q = "?limit=3&cursor=" + *s.NextCursor
	}
	if strings.Join(got, ",") != strings.Join(ids, ",") {
		t.Errorf("pages: %v, want %v", got, ids)
	}
	for _, q := range []string{"?cursor=!!", "?cursor=bm9wZQ", "?limit=0", "?limit=201", "?limit=x"} {
		resp, body := anon.do("GET", "/api/discuss/"+cveA+q, "")
		if resp.StatusCode != 400 {
			t.Errorf("%s: %d %s", q, resp.StatusCode, body)
		}
	}
	resp, body := anon.do("GET", "/api/discuss/CVE-2026-9999", "")
	expect(t, "GET unknown cve", resp, body, 404, "not_found")
	resp, body = anon.do("GET", "/api/discuss/x", "")
	expect(t, "GET malformed cve", resp, body, 400, "bad_cve")
	resp, body = anon.do("GET", "/api/discuss/cve-2026-0001", "")
	expect(t, "GET lower-case cve", resp, body, 200, "")
	resp, body = anon.do("GET", "/api/discuss/comment/"+ids[0]+"/edit", "")
	expect(t, "GET on a POST route", resp, body, 405, "method_not_allowed")
	resp, body = anon.do("GET", "/api/mod/nope", "")
	expect(t, "unknown route", resp, body, 404, "not_found")
}

func TestPageSizeCap(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ctx := context.Background()
	ada := h.member("ada")
	// 3 threads of 200 replies each (inserted directly): a page stops before
	// it exceeds PageMaxComments, but always holds one thread
	for i := 0; i < 3; i++ {
		var top string
		if err := h.db.Conn.QueryRow(ctx, `INSERT INTO comments (cve_id, is_reply, author_id, body, lang, links, created_at, updated_at)
			VALUES ($1, false, $2, 't', 'en', true, $3, $3) RETURNING id::text`, cveA, ada.id, h.clock.Now().Add(time.Duration(i)*time.Second)).Scan(&top); err != nil {
			t.Fatal(err)
		}
		if _, err := h.db.Conn.Exec(ctx, `INSERT INTO comments (cve_id, parent_id, is_reply, author_id, body, lang, links, created_at, updated_at)
			SELECT $1, $2::uuid, true, $3, 'r' || g, 'en', true, $4, $4 FROM generate_series(1, 200) g`, cveA, top, ada.id,
			h.clock.Now().Add(time.Duration(i)*time.Second+time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	s := h.reader().stream(cveA, "?limit=200")
	if len(s.Comments) != 2 || s.NextCursor == nil {
		t.Fatalf("page holds %d threads (next %v), want 2 and a cursor", len(s.Comments), s.NextCursor)
	}
	s = h.reader().stream(cveA, "?cursor="+*s.NextCursor)
	if len(s.Comments) != 1 || len(s.Comments[0].Replies) != 200 || s.NextCursor != nil || s.Comments[0].CanReply {
		t.Errorf("last page: %d threads", len(s.Comments))
	}
	resp, body := ada.tryCreate(cveA, "one more", &s.Comments[0].ID)
	expect(t, "reply to a full thread", resp, body, 409, "thread_full")
}

// TestPermalinkPage: ?c=<id> (signed in) returns the page that holds the
// comment and says which cursor it is ("" = first page); an unknown or
// hidden id gives the first page; signed out it changes nothing.
func TestPermalinkPage(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ada := h.member("ada")
	var ids []string
	for i := 0; i < 3; i++ {
		h.clock.Advance(time.Second)
		ids = append(ids, ada.create(cveA, fmt.Sprintf("comment %d", i), nil).ID)
	}
	rd := h.reader()
	s := rd.stream(cveA, "?limit=1&c="+ids[2])
	if len(s.Comments) != 1 || s.Comments[0].ID != ids[2] || s.Cursor == nil || *s.Cursor == "" {
		t.Errorf("?c= of the third: %+v", s)
	}
	s = rd.stream(cveA, "?limit=1&c="+ids[0])
	if len(s.Comments) != 1 || s.Comments[0].ID != ids[0] || s.Cursor == nil || *s.Cursor != "" || s.NextCursor == nil {
		t.Errorf("?c= of the first: %+v", s)
	}
	s = rd.stream(cveA, "?limit=1&c=00000000-0000-4000-8000-000000000000")
	if len(s.Comments) != 1 || s.Comments[0].ID != ids[0] || s.Cursor == nil || *s.Cursor != "" {
		t.Errorf("?c= of an unknown id: %+v", s)
	}
	if s := h.browser().stream(cveA, "?c="+ids[2]); len(s.Comments) != 0 || s.Cursor != nil || s.Outline == nil || len(s.Outline.Threads) != 3 {
		t.Errorf("signed out ?c=: %+v", s)
	}
}
