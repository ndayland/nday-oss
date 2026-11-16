package discuss_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/discuss"
)

func testLimits() *discuss.Limits {
	l := discuss.DefaultLimits()
	l.PostDaily, l.NewPostDaily = 7, 3
	l.AddrBurst = 1000
	l.EditBurst = 2
	l.ReportDaily = 2
	l.ReadBurst = 1000
	l.GuestRead = false // the outline fallback (guestread_test.go covers guest reading)
	return &l
}

func retryAfterAtLeast(t *testing.T, what string, resp *http.Response, min int) {
	t.Helper()
	n, err := strconv.Atoi(resp.Header.Get("Retry-After"))
	if err != nil || n < min {
		t.Errorf("%s: Retry-After %q, want >= %d", what, resp.Header.Get("Retry-After"), min)
	}
}

func TestRateLimitEstablished(t *testing.T) {
	h := newHarness(t, hopt{terms: terms, limits: testLimits()})
	ada := h.member("ada")
	h.establish(ada.id)
	for i := 0; i < 5; i++ {
		ada.create(cveA, fmt.Sprintf("burst %d", i), nil)
	}
	resp, body := ada.tryCreate(cveA, "sixth", nil)
	expect(t, "sixth at once", resp, body, 429, "rate_limited")
	retryAfterAtLeast(t, "rate_limited", resp, 1)
	h.clock.Advance(30 * time.Second)
	ada.create(cveA, "after 30s", nil)
	h.clock.Advance(30 * time.Second)
	ada.create(cveA, "after 60s", nil) // 7 in 24 h
	h.clock.Advance(30 * time.Second)
	resp, body = ada.tryCreate(cveA, "eighth", nil)
	expect(t, "daily cap", resp, body, 429, "daily_limit")
	retryAfterAtLeast(t, "daily_limit", resp, 23*3600)
	h.clock.Advance(24 * time.Hour)
	ada.create(cveA, "next day", nil)
	if !strings.Contains(h.logs.String(), "discuss: rate limited") {
		t.Error("no rate-limit warning logged")
	}
}

func TestRateLimitNewAccount(t *testing.T) {
	h := newHarness(t, hopt{terms: terms, limits: testLimits()})
	bob := h.member("bob")
	bob.create(cveA, "one", nil)
	bob.create(cveA, "two", nil)
	resp, body := bob.tryCreate(cveA, "three", nil)
	expect(t, "new account burst", resp, body, 429, "rate_limited")
	retryAfterAtLeast(t, "new account", resp, 100)
	h.clock.Advance(2 * time.Minute)
	bob.create(cveA, "three", nil)
	h.clock.Advance(2 * time.Minute)
	resp, body = bob.tryCreate(cveA, "four", nil)
	expect(t, "new account daily cap", resp, body, 429, "daily_limit")
	// nothing refused was stored
	if n := h.count(`SELECT count(*) FROM comments WHERE author_id = $1`, bob.id); n != 3 {
		t.Errorf("%d comments stored, want 3", n)
	}
}

func TestRateLimitAddress(t *testing.T) {
	l := testLimits()
	l.AddrBurst, l.AddrEvery = 3, 10*time.Second
	h := newHarness(t, hopt{terms: terms, limits: l})
	users := []*browser{h.member("ada"), h.member("bob"), h.member("carol"), h.member("dave")}
	for i, u := range users[:3] {
		u.create(cveA, fmt.Sprintf("from one address %d", i), nil)
	}
	resp, body := users[3].tryCreate(cveA, "fourth user, same address", nil)
	expect(t, "per-address limit across users", resp, body, 429, "rate_limited")
	users[3].ip = "203.0.113.9"
	users[3].create(cveA, "other address", nil)
	h.clock.Advance(10 * time.Second)
	users[0].create(cveA, "after 10 s", nil)
}

func TestDuplicate(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ada, bob := h.member("ada"), h.member("bob")
	c := ada.create(cveA, "same text", nil)
	h.clock.Advance(9 * time.Minute)
	resp, body := ada.tryCreate(cveA, "  same text\r\n", nil)
	expect(t, "duplicate", resp, body, 409, "duplicate")
	bob.create(cveA, "same text", nil)                       // another user
	ada.create(cveB, "same text", nil)                       // another vulnerability
	resp, body = ada.tryCreate(cveA, "same text", ptr(c.ID)) // a reply with the same body on the same cve
	expect(t, "duplicate as a reply", resp, body, 409, "duplicate")
	h.clock.Advance(2 * time.Minute)
	ada.create(cveA, "same text", nil) // window over
	d := ada.create(cveA, "deleted then reposted", nil)
	ada.post("/api/discuss/comment/"+d.ID+"/delete", "")
	ada.create(cveA, "deleted then reposted", nil)
}

func TestEditAndReportLimits(t *testing.T) {
	h := newHarness(t, hopt{terms: terms, limits: testLimits()})
	ada, bob := h.member("ada"), h.member("bob")
	h.establish(ada.id)
	c := ada.create(cveA, "v0", nil)
	for i := 1; i <= 2; i++ {
		resp, body := ada.post("/api/discuss/comment/"+c.ID+"/edit", fmt.Sprintf(`{"body":"v%d"}`, i))
		expect(t, "edit", resp, body, 200, "")
	}
	resp, body := ada.post("/api/discuss/comment/"+c.ID+"/edit", `{"body":"v3"}`)
	expect(t, "third edit at once", resp, body, 429, "rate_limited")
	h.clock.Advance(3 * time.Minute)
	resp, body = ada.post("/api/discuss/comment/"+c.ID+"/edit", `{"body":"v3"}`)
	expect(t, "edit after 3 min", resp, body, 200, "")

	var ids []string
	for i := 0; i < 3; i++ {
		h.clock.Advance(time.Hour) // ada's own post limits are not under test
		ids = append(ids, ada.create(cveA, fmt.Sprintf("r%d", i), nil).ID)
	}
	for _, id := range ids[:2] {
		resp, body := bob.post("/api/discuss/comment/"+id+"/report", `{"reason":"spam"}`)
		expect(t, "report", resp, body, 200, "")
	}
	resp, body = bob.post("/api/discuss/comment/"+ids[0]+"/report", `{"reason":"spam"}`)
	expect(t, "repeat report (idempotent, not counted)", resp, body, 200, "")
	resp, body = bob.post("/api/discuss/comment/"+ids[2]+"/report", `{"reason":"spam"}`)
	expect(t, "report daily cap", resp, body, 429, "daily_limit")
	h.clock.Advance(24 * time.Hour)
	resp, body = bob.post("/api/discuss/comment/"+ids[2]+"/report", `{"reason":"spam"}`)
	expect(t, "report next day", resp, body, 200, "")
}

func TestReadLimit(t *testing.T) {
	l := testLimits()
	l.ReadBurst, l.ReadEvery = 3, time.Second
	h := newHarness(t, hopt{terms: terms, limits: l})
	anon := h.browser()
	for i := 0; i < 3; i++ {
		anon.stream(cveA, "")
	}
	resp, body := anon.do("GET", "/api/discuss/"+cveA, "")
	expect(t, "read limit", resp, body, 429, "rate_limited")
	h.clock.Advance(time.Second)
	anon.stream(cveA, "")
}

func TestLimitsFromEnv(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }
	l, err := discuss.LimitsFromEnv(get)
	if err != nil || l != discuss.DefaultLimits() {
		t.Fatalf("defaults: %+v %v", l, err)
	}
	env["NDAY_DISCUSS_POST_BURST"] = "9"
	env["NDAY_DISCUSS_NEW_ACCOUNT_AGE"] = "2d"
	env["NDAY_DISCUSS_EDIT_EVERY"] = "90s"
	l, err = discuss.LimitsFromEnv(get)
	if err != nil || l.PostBurst != 9 || l.NewAccountAge != 48*time.Hour || l.EditEvery != 90*time.Second {
		t.Errorf("overrides: %+v %v", l, err)
	}
	for k, v := range map[string]string{"NDAY_DISCUSS_POST_DAILY": "-7", "NDAY_DISCUSS_READ_BURST": "x",
		"NDAY_DISCUSS_ADDR_EVERY": "-1s", "NDAY_DISCUSS_DUPLICATE_WINDOW": "31d"} {
		e := map[string]string{k: v}
		_, err := discuss.LimitsFromEnv(func(n string) string { return e[n] })
		if err == nil || !strings.Contains(err.Error(), k) || strings.Contains(err.Error(), v) {
			t.Errorf("%s=%s: %v", k, v, err)
		}
	}
	for v, want := range map[string]bool{"": true, "on": true, "OFF": false} {
		got, err := discuss.Enabled(func(string) string { return v })
		if err != nil || got != want {
			t.Errorf("Enabled(%q) = %v %v", v, got, err)
		}
	}
	if _, err := discuss.Enabled(func(string) string { return "maybe" }); err == nil {
		t.Error("Enabled(maybe) accepted")
	}
	if n, err := discuss.PoolSize(func(string) string { return "" }); n != 4 || err != nil {
		t.Errorf("PoolSize default %d %v", n, err)
	}
	if _, err := discuss.PoolSize(func(string) string { return "33" }); err == nil {
		t.Error("PoolSize 33 accepted")
	}
}

// Nothing personal is cacheable: every discussion response is no-store with
// Vary: Cookie and no validators, conditional requests never get 304, and
// the data API host knows nothing of discussions.
func TestNothingPersonalCacheable(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ada := h.member("ada")
	ada.create(cveA, "x", nil)
	for _, b := range []*browser{h.browser(), ada} {
		resp, _ := b.do("GET", "/api/discuss/"+cveA, "", "If-None-Match", "*", "If-Modified-Since", "Mon, 01 Jan 2024 00:00:00 GMT")
		if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" ||
			!strings.Contains(strings.ToLower(strings.Join(resp.Header.Values("Vary"), ",")), "cookie") || resp.Header.Get("Set-Cookie") != "" {
			t.Errorf("GET stream: %d %v", resp.StatusCode, resp.Header)
		}
	}
	for _, p := range []string{"/api/discuss/" + cveA, "/v1/discuss/" + cveA, "/api/mod/reports", "/v1/mod/recent"} {
		resp, body := ada.do("GET", p, "", "Host", apiHost)
		if resp.StatusCode != 404 || strings.Contains(string(body), `"comments"`) {
			t.Errorf("API host %s: %d %s", p, resp.StatusCode, body)
		}
	}
	// the site's data routes are unchanged (two-host mode: 308 to the API host)
	resp, _ := ada.do("GET", "/api/hot", "")
	if resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("/api/hot on the site host: %d", resp.StatusCode)
	}
}

func TestAccountDeletionKeepsComments(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ada, bob := h.member("ada"), h.member("bob")
	c := ada.create(cveA, "by ada", nil)
	bob.create(cveA, "reply by bob", ptr(c.ID))
	bob.post("/api/discuss/comment/"+c.ID+"/report", `{"reason":"other"}`)
	before, _ := h.dsvc.Version(context.Background(), cveA)
	ctx := context.Background()
	if err := h.as.DeleteUser(ctx, ada.id, 0, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.as.DeleteUser(ctx, bob.id, 0, nil); err != nil {
		t.Fatal(err)
	}
	s := h.reader().stream(cveA, "")
	if len(s.Comments) != 1 || s.Comments[0].Author != nil || !strings.Contains(s.Comments[0].BodyHTML, "by ada") ||
		len(s.Comments[0].Replies) != 1 || s.Comments[0].Replies[0].Author != nil {
		t.Errorf("after account deletion: %+v", s)
	}
	if n := h.count(`SELECT count(*) FROM comments WHERE author_id IS NULL`); n != 2 {
		t.Errorf("%d authorless comments, want 2", n)
	}
	if n := h.count(`SELECT count(*) FROM comment_reports WHERE reporter_id IS NULL AND resolved_at IS NULL`); n != 1 {
		t.Errorf("the deleted reporter's open report is gone (%d)", n)
	}
	after, _ := h.dsvc.Version(ctx, cveA)
	if before == after {
		t.Error("Version unchanged after the authors' accounts were deleted")
	}
	// nobody can edit or delete an authorless comment
	carol := h.member("carol")
	resp, body := carol.post("/api/discuss/comment/"+c.ID+"/delete", "")
	expect(t, "delete authorless", resp, body, 403, "not_author")
}

func TestStreamAndVersion(t *testing.T) {
	h := newHarness(t, hopt{terms: terms})
	ctx := context.Background()
	ada, mod := h.member("ada"), h.member("carol")
	h.setRole(mod.id, "moderator")
	link := func(cve string) string { return "/fr/vuln/" + cve }
	v0, err := h.dsvc.Version(ctx, cveA)
	if err != nil {
		t.Fatal(err)
	}
	c := ada.create(cveA, "about CVE-2026-0002", nil)
	ada.post("/api/discuss/comment/"+c.ID+"/report", `{"reason":"spam"}`) // own: refused, no change
	v1, _ := h.dsvc.Version(ctx, cveA)
	if v1 == v0 {
		t.Error("Version unchanged after a create")
	}
	if again, _ := h.dsvc.Version(ctx, cveA); again != v1 {
		t.Error("Version not stable")
	}
	// the signed-out outline is all that is public (docs/discuss.md §4.1)
	o, err := h.dsvc.Outline(ctx, cveA)
	if err != nil || o.Count != 1 || len(o.Threads) != 1 || o.Threads[0].Status != "visible" || o.Threads[0].Size != "s" {
		t.Fatalf("Outline: %+v %v", o, err)
	}
	j, _ := json.Marshal(o)
	if strings.Contains(string(j), ada.id) || strings.Contains(string(j), c.ID) || strings.Contains(string(j), "ada") ||
		strings.Contains(string(j), "CVE-2026-0002") {
		t.Errorf("Outline JSON: %s", j)
	}
	_ = link
	steps := []func(){
		func() {
			h.clock.Advance(time.Second)
			ada.post("/api/discuss/comment/"+c.ID+"/edit", `{"body":"edited"}`)
		},
		func() { h.clock.Advance(time.Second); mod.post("/api/discuss/comment/"+c.ID+"/hide", `{"reason":"x"}`) },
		func() {
			h.clock.Advance(time.Second)
			if _, err := h.as.SetHandle(ctx, ada.id, "Ada", "ada", 0); err != nil { // case-only change
				t.Fatal(err)
			}
		},
		func() { h.setRole(ada.id, "moderator") },
	}
	prev := v1
	for i, step := range steps {
		step()
		v, _ := h.dsvc.Version(ctx, cveA)
		if v == prev {
			t.Errorf("step %d: Version unchanged", i)
		}
		prev = v
	}
	if o, _ := h.dsvc.Outline(ctx, cveA); len(o.Threads) != 1 || o.Threads[0].Status != "hidden" || o.Threads[0].Size != "" || o.Count != 0 {
		t.Errorf("Outline of a hidden comment: %+v", o)
	}
	if o, _ := h.dsvc.Outline(ctx, "CVE-2026-9999"); len(o.Threads) != 0 {
		t.Errorf("Outline of an unknown CVE: %+v", o)
	}
}
