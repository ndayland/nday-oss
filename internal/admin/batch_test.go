package admin_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

type batchAnswer struct {
	OK      bool `json:"ok"`
	Done    int  `json:"done"`
	Changed int  `json:"changed"`
	Failed  int  `json:"failed"`
	Results []struct {
		ID     string `json:"id"`
		Result string `json:"result"`
	} `json:"results"`
}

func batchOf(t *testing.T, b []byte) batchAnswer {
	t.Helper()
	var a batchAnswer
	if err := json.Unmarshal(b, &a); err != nil {
		t.Fatalf("answer %s: %v", b, err)
	}
	return a
}

func (a batchAnswer) results() string {
	var s []string
	for _, r := range a.Results {
		s = append(s, r.ID+"="+r.Result)
	}
	return strings.Join(s, " ")
}

// TestBatchRefused: every batch endpoint refuses, writing nothing, for the
// wrong visitor, a missing or bad CSRF token, a cross-site request, a stale
// sign-in, a body that is not the batch JSON, an unknown action, no items,
// more than a page of items and an id listed twice.
func TestBatchRefused(t *testing.T) {
	h := newHarness(t, hopt{})
	h.xCandFixture()
	r := h.ghFixture()
	d := h.draft("CVE-2026-0101", "kev_added", "draft one")
	anon, user, mod := h.browser(), h.user("pat", "user"), h.user("lee", "moderator")
	adm := h.user("kim", "admin")
	audits := func() int { return h.count(`SELECT count(*) FROM admin_audit`) }
	before := audits()
	eps := []struct{ path, body string }{
		{"/api/admin/x/candidates/batch", `{"action":"dismiss","items":[{"id":"3001","state":"pending"}]}`},
		{"/api/admin/github/repos/batch", `{"action":"trust","items":[{"id":"` + idStr(r.poc) + `","state":"unverified"}]}`},
		{"/api/admin/x/drafts/batch", `{"action":"discard","items":[{"id":"` + d + `","version":1}]}`},
	}
	for _, e := range eps {
		check(t, e.path+" signed out", 401, "not_signed_in")(anon.post(e.path, e.body))
		check(t, e.path+" user", 404, "not_found")(user.post(e.path, e.body))
		check(t, e.path+" moderator", 403, "forbidden")(mod.post(e.path, e.body))
		check(t, e.path+" GET", 405, "method_not_allowed")(adm.do("GET", e.path, ""))
		check(t, e.path+" no CSRF", 403, "csrf")(adm.post(e.path, e.body, "X-CSRF-Token", ""))
		check(t, e.path+" bad CSRF", 403, "csrf")(adm.post(e.path, e.body, "X-CSRF-Token", flip(adm.csrf)))
		check(t, e.path+" cross-site", 403, "cross_site")(adm.post(e.path, e.body, "Sec-Fetch-Site", "cross-site"))
		check(t, e.path+" not JSON", 400, "bad_request")(adm.post(e.path, `items`))
		check(t, e.path+" unknown field", 400, "bad_request")(adm.post(e.path, `{"action":"x","items":[],"all":true}`))
		check(t, e.path+" unknown action", 400, "bad_request")(adm.post(e.path, strings.Replace(e.body, `"action":"`, `"action":"z`, 1)))
		check(t, e.path+" no items", 400, "bad_request")(adm.post(e.path, e.body[:strings.Index(e.body, `"items"`)]+`"items":[]}`))
		item := e.body[strings.Index(e.body, `[`)+1 : strings.LastIndex(e.body, `]`)]
		check(t, e.path+" duplicate", 400, "duplicate")(adm.post(e.path, strings.Replace(e.body, item, item+","+item, 1)))
		var many []string
		for i := 0; i < 11; i++ {
			many = append(many, strings.Replace(item, `"id":"`, fmt.Sprintf(`"id":"9%d`, i), 1))
		}
		check(t, e.path+" 11 items", 400, "too_many")(adm.post(e.path, strings.Replace(e.body, item, strings.Join(many, ","), 1)))
	}
	if n := audits(); n != before {
		t.Errorf("refused requests wrote %d audit rows", n-before)
	}
	if h.count(`SELECT count(*) FROM x_account_candidate WHERE status = 'dismissed'`) != 1 ||
		h.count(`SELECT count(*) FROM github_repo WHERE status = 'trusted'`) != 1 ||
		h.count(`SELECT count(*) FROM x_draft WHERE status = 'draft'`) != 1 {
		t.Error("a refused request changed something")
	}
	// a stale sign-in: re-verification first, nothing applied
	h.clock.Advance(16 * time.Minute)
	for _, e := range eps {
		check(t, e.path+" stale session", 403, "reauth_required")(adm.post(e.path, e.body))
	}
	if n := audits(); n != before {
		t.Errorf("stale-session requests wrote %d audit rows", n-before)
	}
}

// TestBatchCandidates: each item is applied as its single action would be
// (same rules, one audit row each with the single action's name) when it
// is still in the state the page showed; the others are reported, not
// applied.
func TestBatchCandidates(t *testing.T) {
	h := newHarness(t, hopt{})
	h.xCandFixture()
	adm := h.user("kim", "admin")
	p := "/api/admin/x/candidates/batch"
	// 3001 and 3005 pending: dismissed; 3004 already dismissed (the page
	// showed it pending): stale; 9999 absent; "x1" malformed
	resp, b := adm.post(p, `{"action":"dismiss","items":[{"id":"3001","state":"pending"},{"id":"3004","state":"pending"},`+
		`{"id":"9999","state":"pending"},{"id":"3005","state":"pending"},{"id":"x1","state":"pending"}]}`)
	if resp.StatusCode != 200 {
		t.Fatalf("dismiss: %d %s", resp.StatusCode, b)
	}
	a := batchOf(t, b)
	if got := a.results(); got != "3001=ok 3004=stale 9999=not_found 3005=ok x1=invalid" || a.Done != 2 || a.Changed != 2 || a.Failed != 1 {
		t.Errorf("dismiss: %s (%+v)", got, a)
	}
	if n := h.count(`SELECT count(*) FROM admin_audit WHERE action = 'x.candidate.dismiss'`); n != 2 {
		t.Errorf("%d x.candidate.dismiss rows, want 2 (one per applied item)", n)
	}
	if n := h.count(`SELECT count(*) FROM x_account_candidate WHERE status = 'dismissed' AND user_id IN ('3001', '3004', '3005')`); n != 3 {
		t.Errorf("%d dismissed", n)
	}
	// restore from the dismissed list; add from the open list (no handle: refused per item)
	_, b = adm.post(p, `{"action":"restore","items":[{"id":"3001","state":"dismissed"},{"id":"3004","state":"dismissed"}]}`)
	if a := batchOf(t, b); a.results() != "3001=ok 3004=ok" {
		t.Errorf("restore: %s", a.results())
	}
	_, b = adm.post(p, `{"action":"add","items":[{"id":"3001","state":"pending"},{"id":"3002","state":"pending"},{"id":"1001","state":"pending"}]}`)
	if a := batchOf(t, b); a.results() != "3001=ok 3002=no_handle 1001=exists" || a.Done != 1 || a.Changed != 1 || a.Failed != 1 {
		t.Errorf("add: %s %+v", a.results(), a)
	}
	if n := h.count(`SELECT count(*) FROM admin_audit WHERE action = 'x.account.add' AND target_id = '3001'`); n != 1 {
		t.Errorf("%d x.account.add rows for 3001", n)
	}
	if n := h.count(`SELECT count(*) FROM x_accounts WHERE user_id = '3001' AND handle = 'carol'`); n != 1 {
		t.Error("3001 not listed")
	}
	// a state that is not a candidate state, a version on a candidate: invalid
	_, b = adm.post(p, `{"action":"dismiss","items":[{"id":"3005","state":"open"},{"id":"3005x","state":"pending","version":2}]}`)
	if a := batchOf(t, b); a.results() != "3005=invalid 3005x=invalid" {
		t.Errorf("invalid: %s", a.results())
	}
}

// TestBatchGitHub: trust and reject per item with the state the page
// showed; a repository decided meanwhile is stale and keeps its status.
func TestBatchGitHub(t *testing.T) {
	h := newHarness(t, hopt{})
	r := h.ghFixture()
	adm := h.user("kim", "admin")
	p := "/api/admin/github/repos/batch"
	body := fmt.Sprintf(`{"action":"reject","items":[{"id":"%d","state":"unverified"},{"id":"%d","state":"unverified"},`+
		`{"id":"%d","state":"unverified"},{"id":"999999","state":"unverified"}]}`, r.poc, r.lab, r.coll)
	resp, b := adm.post(p, body)
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	a := batchOf(t, b)
	want := fmt.Sprintf("%d=ok %d=stale %d=ok 999999=not_found", r.poc, r.lab, r.coll)
	if a.results() != want || a.Done != 2 || a.Changed != 2 || a.Failed != 0 {
		t.Errorf("reject: %s (%+v), want %s", a.results(), a, want)
	}
	if n := h.count(`SELECT count(*) FROM admin_audit WHERE action = 'github.repo.reject'`); n != 2 {
		t.Errorf("%d github.repo.reject rows, want 2", n)
	}
	if n := h.count(`SELECT count(*) FROM github_repo WHERE id = $1 AND status = 'trusted'`, r.lab); n != 1 {
		t.Error("the stale item changed")
	}
	// trusted list: reset; the same status by an admin already: no_change
	_, b = adm.post(p, fmt.Sprintf(`{"action":"reset","items":[{"id":"%d","state":"trusted"}]}`, r.lab))
	if a := batchOf(t, b); a.results() != fmt.Sprintf("%d=ok", r.lab) {
		t.Errorf("reset: %s", a.results())
	}
	_, b = adm.post(p, fmt.Sprintf(`{"action":"reject","items":[{"id":"%d","state":"rejected"}]}`, r.bad))
	if a := batchOf(t, b); a.results() != fmt.Sprintf("%d=no_change", r.bad) || a.Changed != 1 {
		t.Errorf("no change: %s", a.results())
	}
}

// TestBatchDrafts: discard per item with the version the page was rendered
// with; a newer version is stale, a decided draft wrong_status.
func TestBatchDrafts(t *testing.T) {
	h := newHarness(t, hopt{})
	d1 := h.draft("CVE-2026-0101", "kev_added", "one")
	d2 := h.draft("CVE-2026-0102", "kev_added", "two")
	d3 := h.draft("CVE-2026-0103", "kev_added", "three")
	h.sql(`UPDATE x_draft SET version = 2 WHERE id = $1`, d2)
	h.sql(`UPDATE x_draft SET status = 'posted', decided_at = now() WHERE id = $1`, d3)
	adm := h.user("kim", "admin")
	resp, b := adm.post("/api/admin/x/drafts/batch", fmt.Sprintf(`{"action":"discard","items":[{"id":"%s","version":1},`+
		`{"id":"%s","version":1},{"id":"%s","version":1},{"id":"%s"}]}`, d1, d2, d3, "77"))
	if resp.StatusCode != 200 {
		t.Fatalf("%d %s", resp.StatusCode, b)
	}
	a := batchOf(t, b)
	want := d1 + "=ok " + d2 + "=stale " + d3 + "=wrong_status 77=invalid"
	if a.results() != want || a.Done != 1 || a.Changed != 2 || a.Failed != 1 {
		t.Errorf("discard: %s (%+v), want %s", a.results(), a, want)
	}
	if st, v, _, _ := h.draftRow(d1); st != "discarded" || v != 2 {
		t.Errorf("d1: %s v%d", st, v)
	}
	if st, _, _, _ := h.draftRow(d2); st != "draft" {
		t.Errorf("d2: %s", st)
	}
	if n := h.count(`SELECT count(*) FROM admin_audit WHERE action = 'x.draft.discard'`); n != 1 {
		t.Errorf("%d x.draft.discard rows, want 1", n)
	}
	check(t, "mark posted has no batch", 400, "bad_request")(adm.post("/api/admin/x/drafts/batch",
		fmt.Sprintf(`{"action":"posted","items":[{"id":"%s","version":2}]}`, d2)))
}
