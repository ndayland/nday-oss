package auth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"testing"

	"nday.land/nday/internal/auth"
)

type followsResp struct {
	OK      bool          `json:"ok"`
	Follows []auth.Follow `json:"follows"`
}

func followsBody(labels ...string) string {
	type t struct {
		Label string `json:"label"`
	}
	ts := []t{}
	for _, l := range labels {
		ts = append(ts, t{l})
	}
	b, _ := json.Marshal(map[string]any{"terms": ts})
	return string(b)
}

func (b *browser) setFollows(labels ...string) (int, string, []auth.Follow) {
	b.h.t.Helper()
	resp, body := b.post("/account/follows", followsBody(labels...))
	var r followsResp
	_ = json.Unmarshal(body, &r)
	return resp.StatusCode, errCode(b.h.t, body), r.Follows
}

func (b *browser) myFollows() []auth.Follow {
	b.h.t.Helper()
	_, body := b.do("GET", "/api/me", "")
	var m struct {
		User struct {
			Follows []auth.Follow `json:"follows"`
		} `json:"user"`
	}
	if err := json.Unmarshal(body, &m); err != nil {
		b.h.t.Fatal(err)
	}
	return m.User.Follows
}

func terms(fs []auth.Follow) string {
	var s []string
	for _, f := range fs {
		s = append(s, f.Term+"="+f.Label)
	}
	return strings.Join(s, ",")
}

// TestFollowsReplaceAndValidate: POST /account/follows replaces the whole
// list (normalised, de-duplicated case-insensitively, order kept), /api/me
// shows it, and bad input is refused without changing anything.
func TestFollowsReplaceAndValidate(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	b.login(auth.GitHub, acct("f1"), "")
	if fs := b.myFollows(); fs == nil || len(fs) != 0 {
		t.Fatalf("new account follows %v (want [])", fs)
	}
	st, code, fs := b.setFollows("  Fortinet ", "Palo   Alto\tNetworks", "fortinet", "OpenSSH")
	if st != 200 || code != "" || terms(fs) != "fortinet=Fortinet,palo alto networks=Palo Alto Networks,openssh=OpenSSH" {
		t.Fatalf("set: %d %s %s", st, code, terms(fs))
	}
	if got := terms(b.myFollows()); got != terms(fs) {
		t.Errorf("/api/me follows %s", got)
	}
	// replace: openssh goes, Fortinet stays first (re-spelt), Ivanti is added
	if st, _, fs := b.setFollows("Ivanti", "FORTINET"); st != 200 || terms(fs) != "fortinet=FORTINET,ivanti=Ivanti" {
		t.Errorf("replace: %d %s", st, terms(fs))
	}
	before := terms(b.myFollows())
	long := strings.Repeat("a", auth.MaxFollowRunes+1)
	for _, c := range []struct {
		labels []string
		code   string
	}{
		{[]string{""}, "invalid_follow"},
		{[]string{"  \t "}, "invalid_follow"},
		{[]string{long}, "invalid_follow"},
		{[]string{"ok", "bell\x07"}, "invalid_follow"},
		{[]string{"c1\u0090control"}, "invalid_follow"},
		{[]string{"rtl‮override"}, "invalid_follow"},
		{[]string{"zero​width"}, "invalid_follow"},
	} {
		if st, code, _ := b.setFollows(c.labels...); st != 400 || code != c.code {
			t.Errorf("%q: %d %s", c.labels, st, code)
		}
	}
	// the cap: 50 distinct terms are fine (duplicates do not count), 51 are not
	many := make([]string, 0, 52)
	for i := 0; i < auth.MaxFollows; i++ {
		many = append(many, fmt.Sprintf("Vendor %02d", i))
	}
	if st, code, _ := b.setFollows(append(many, "vendor 00", "VENDOR 01")...); st != 200 || code != "" {
		t.Errorf("50 + duplicates: %d %s", st, code)
	}
	if n := h.count(`SELECT count(*) FROM user_follows`); n != auth.MaxFollows {
		t.Errorf("rows %d", n)
	}
	if st, code, _ := b.setFollows(append(many, "one more")...); st != 400 || code != "too_many_follows" {
		t.Errorf("51: %d %s", st, code)
	}
	if n := h.count(`SELECT count(*) FROM user_follows`); n != auth.MaxFollows {
		t.Errorf("refused request changed the list: %d rows", n)
	}
	if _, _, fs := b.setFollows("FORTINET", "Ivanti"); terms(fs) != before {
		t.Errorf("restore %s, want %s", terms(fs), before)
	}
	// body shape: terms required, unknown fields refused, too large refused
	for _, body := range []string{`{}`, `{"terms":null}`, `{"terms":[{"label":"a","x":1}]}`, `{"labels":[]}`,
		`{"terms":[{"label":"` + strings.Repeat("a", 70<<10) + `"}]}`} {
		if resp, out := b.post("/account/follows", body); resp.StatusCode != 400 || errCode(t, out) != "bad_request" {
			t.Errorf("%.40s: %d %s", body, resp.StatusCode, out)
		}
	}
	// the largest valid body: 50 labels of 200 four-byte characters
	big := make([]string, auth.MaxFollows)
	for i := range big {
		big[i] = strings.Repeat("\U0001D538", auth.MaxFollowRunes-1) + string(rune(0x1F600+i))
	}
	if n := len(followsBody(big...)); n <= 40000 || n > 64<<10 {
		t.Fatalf("maximal body is %d bytes", n)
	}
	if st, code, fs := b.setFollows(big...); st != 200 || len(fs) != auth.MaxFollows {
		t.Errorf("maximal valid body: %d %s %d", st, code, len(fs))
	}
	// [] removes everything
	if st, _, fs := b.setFollows(); st != 200 || len(fs) != 0 || h.count(`SELECT count(*) FROM user_follows`) != 0 {
		t.Errorf("clear: %d %v", st, fs)
	}
	// the database refuses what the code refuses
	ctx := context.Background()
	id := b.me().User.ID
	for _, bad := range []string{
		`INSERT INTO user_follows (user_id, term_key, label) VALUES ($1, 'Upper', 'Upper')`,
		`INSERT INTO user_follows (user_id, term_key, label) VALUES ($1, '', '')`,
		`INSERT INTO user_follows (user_id, term_key, label) VALUES ($1, E'a\x07', E'a\x07')`,
	} {
		if _, err := h.db.Conn.Exec(ctx, bad, id); err == nil {
			t.Errorf("schema accepted: %s", bad)
		}
	}
}

// TestFollowsAccess: the endpoints need a session, same-origin and the CSRF
// token; a suspended user may not change the list but may still match;
// deleting the account deletes the follows.
func TestFollowsAccess(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	anon := h.browser()
	for _, p := range []string{"/account/follows", "/account/follows/match"} {
		resp, out := anon.do("POST", p, `{"terms":[]}`, "Origin", origin, "Content-Type", "application/json")
		if resp.StatusCode != 401 || errCode(t, out) != "not_signed_in" {
			t.Errorf("anon %s: %d %s", p, resp.StatusCode, out)
		}
		if resp, _ := anon.do("GET", p, ""); resp.StatusCode != 405 || resp.Header.Get("Allow") != "POST" {
			t.Errorf("GET %s: %d", p, resp.StatusCode)
		}
	}
	b := h.browser()
	b.login(auth.GitHub, acct("f2"), "")
	tok := b.me().CSRFToken
	if resp, out := b.do("POST", "/account/follows", followsBody("x1"), "Origin", origin, "Content-Type", "application/json"); resp.StatusCode != 403 || errCode(t, out) != "csrf" {
		t.Errorf("no CSRF: %d %s", resp.StatusCode, out)
	}
	if resp, out := b.do("POST", "/account/follows", followsBody("x1"), "Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site",
		"Content-Type", "application/json", "X-CSRF-Token", tok); resp.StatusCode != 403 || errCode(t, out) != "cross_site" {
		t.Errorf("cross-site: %d %s", resp.StatusCode, out)
	}
	if resp, _ := b.do("POST", "/account/follows", followsBody("x1"), "Origin", origin, "Content-Type", "text/plain", "X-CSRF-Token", tok); resp.StatusCode != 415 {
		t.Errorf("text/plain: %d", resp.StatusCode)
	}
	if st, _, _ := b.setFollows("Fortinet"); st != 200 {
		t.Fatal("set")
	}
	ctx := context.Background()
	id := b.me().User.ID
	if err := h.store.Suspend(ctx, id, nil, "x"); err != nil {
		t.Fatal(err)
	}
	if st, code, _ := b.setFollows("Ivanti"); st != 403 || code != "suspended" {
		t.Errorf("suspended set: %d %s", st, code)
	}
	if resp, out := b.post("/account/follows/match", `{"cve_ids":[]}`); resp.StatusCode != 200 || strings.TrimSpace(string(out)) != `{"matches":[]}` {
		t.Errorf("suspended match: %d %s", resp.StatusCode, out)
	}
	if err := h.store.Unsuspend(ctx, id); err != nil {
		t.Fatal(err)
	}
	b.reauth(auth.GitHub, "f2")
	if resp, _ := b.post("/account/delete", `{"confirm":true}`); resp.StatusCode != 200 {
		t.Fatal("delete")
	}
	if n := h.count(`SELECT count(*) FROM user_follows`); n != 0 {
		t.Errorf("follows left after account deletion: %d", n)
	}
}

// TestFollowsMatch: a CVE matches when an affected vendor OR product equals a
// followed term case-insensitively (whole name only); ids come back in the
// request's order, once; bad ids and too many ids are refused; a list of 200
// long ids (more than 4 KiB) is accepted.
func TestFollowsMatch(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	ctx := context.Background()
	for _, r := range [][3]string{
		{"CVE-2026-0001", "Fortinet", "FortiOS"},       // vendor
		{"CVE-2026-0002", "OpenBSD", "OpenSSH"},        // product, other case than followed
		{"CVE-2026-0003", "Fortinetx", "Fortinet-ish"}, // substring only: no
		{"CVE-2026-0004", "Acme", "Widget"},            // unrelated
		{"CVE-2026-0005", "PALO ALTO NETWORKS", "PAN-OS"},
		{"GHSA-gpwc-27cw-rh9r", "fortinet", "fortisdk"}, // an advisory without a CVE: keyed by its GHSA id
	} {
		if _, err := h.db.Conn.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ($1) ON CONFLICT DO NOTHING`, r[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := h.db.Conn.Exec(ctx, `INSERT INTO affected (cve_id, vendor, product) VALUES ($1, $2, $3)`, r[0], r[1], r[2]); err != nil {
			t.Fatal(err)
		}
	}
	a, other := h.browser(), h.browser()
	a.login(auth.GitHub, acct("m1"), "")
	other.login(auth.GitHub, acct("m2"), "")
	if st, _, _ := a.setFollows("fortinet", "openssh", "Palo Alto Networks"); st != 200 {
		t.Fatal("set")
	}
	if st, _, _ := other.setFollows("Acme"); st != 200 {
		t.Fatal("set other")
	}
	match := func(br *browser, ids ...string) (int, string, string) {
		b, _ := json.Marshal(map[string]any{"cve_ids": ids})
		resp, out := br.post("/account/follows/match", string(b))
		return resp.StatusCode, errCode(t, out), strings.TrimSpace(string(out))
	}
	if st, _, out := match(a, "CVE-2026-0005", "CVE-2026-0004", "cve-2026-0002", "CVE-2026-0003", "CVE-2026-0001", "CVE-2026-0002", "CVE-2026-9999"); st != 200 ||
		out != `{"matches":["CVE-2026-0005","CVE-2026-0002","CVE-2026-0001"]}` {
		t.Errorf("match: %d %s", st, out)
	}
	if st, _, out := match(other, "CVE-2026-0001", "CVE-2026-0004"); st != 200 || out != `{"matches":["CVE-2026-0004"]}` {
		t.Errorf("other user's follows: %d %s", st, out)
	}
	if st, _, out := match(a, "ghsa-GPWC-27cw-rh9r", "CVE-2026-0001"); st != 200 || out != `{"matches":["GHSA-gpwc-27cw-rh9r","CVE-2026-0001"]}` {
		t.Errorf("GHSA id: %d %s", st, out)
	}
	for _, bad := range []string{"not-a-cve", "GHSA-aaaa-27cw-rh9r"} {
		if st, code, _ := match(a, "CVE-2026-0001", bad); st != 400 || code != "bad_request" {
			t.Errorf("bad id %s: %d %s", bad, st, code)
		}
	}
	ids := make([]string, auth.MaxMatchCVEs)
	for i := range ids {
		ids[i] = fmt.Sprintf("CVE-2026-%013d", i+1)
	}
	ids[150] = "CVE-2026-0001"
	if b, _ := json.Marshal(map[string]any{"cve_ids": ids}); len(b) <= 4096 {
		t.Fatalf("test body only %d bytes", len(b))
	}
	if st, _, out := match(a, ids...); st != 200 || out != `{"matches":["CVE-2026-0001"]}` {
		t.Errorf("200 ids: %d %s", st, out)
	}
	if st, code, _ := match(a, append(ids, "CVE-2026-0002")...); st != 400 || code != "bad_request" {
		t.Errorf("201 ids: %d %s", st, code)
	}
	// no follows: nothing matches
	if st, _, _ := a.setFollows(); st != 200 {
		t.Fatal("clear")
	}
	if st, _, out := match(a, "CVE-2026-0001"); st != 200 || out != `{"matches":[]}` {
		t.Errorf("no follows: %d %s", st, out)
	}
}

// TestWelcomeRedirect: a sign-in that creates the account goes to the
// welcome page of the return path's locale with the return path as next; a
// returning user goes straight back; hostile return paths end at /welcome.
func TestWelcomeRedirect(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	for i, c := range []struct{ ret, first string }{
		{"/vuln/CVE-2026-0001", "/welcome?next=%2Fvuln%2FCVE-2026-0001&auth=ok"},
		{"/zh-hans/vuln?q=a+b&auth=x", "/zh-hans/welcome?next=%2Fzh-hans%2Fvuln%3Fq%3Da%2Bb&auth=ok"},
		{"/welcome?next=%2Fvuln%2FCVE-2026-0002", "/welcome?next=%2Fvuln%2FCVE-2026-0002&auth=ok"},
		{"/", "/welcome?auth=ok"},
		{"/zh-hans/", "/zh-hans/welcome?auth=ok"},
		{"/ja", "/ja/welcome?auth=ok"},
		{"//evil.example", "/welcome?auth=ok"},
		{"/xx-yy/vuln", "/welcome?next=%2Fxx-yy%2Fvuln&auth=ok"},
	} {
		sub := fmt.Sprintf("w%d", i)
		b := h.browser()
		if loc := b.login(auth.GitHub, acct(sub), "return="+url.QueryEscape(c.ret)); loc != c.first {
			t.Errorf("new account, return %q -> %q, want %q", c.ret, loc, c.first)
		}
		// returning user: straight back to the return path (no welcome page
		// unless that is where they came from)
		b2 := h.browser()
		want := auth.SafeReturnPath(c.ret)
		if loc := b2.login(auth.GitHub, acct(sub), "return="+url.QueryEscape(c.ret)); !strings.HasPrefix(loc, strings.Split(want, "?")[0]+"?") ||
			strings.Contains(loc, "welcome") != strings.Contains(want, "welcome") {
			t.Errorf("returning user, return %q -> %q", c.ret, loc)
		}
	}
}

func TestWelcomeReturn(t *testing.T) {
	for in, want := range map[string]string{
		"/":                     "/welcome",
		"/hot":                  "/welcome?next=%2Fhot",
		"/fr/":                  "/fr/welcome",
		"/fr/src":               "/fr/welcome?next=%2Ffr%2Fsrc",
		"/zh-hant/vuln/CVE-1-2": "/zh-hant/welcome?next=%2Fzh-hant%2Fvuln%2FCVE-1-2",
		"/account":              "/welcome?next=%2Faccount",
		// a welcome page as the return path: its own next, not nested
		"/welcome?next=%2Fvuln%2FX":                      "/welcome?next=%2Fvuln%2FX",
		"/zh-hans/welcome?next=%2Fzh-hans%2Fsrc&auth=ok": "/zh-hans/welcome?next=%2Fzh-hans%2Fsrc",
		"/welcome/?next=%2Fhot":                          "/welcome?next=%2Fhot",
		"/welcome?next=%2Fwelcome%3Fnext%3D%252Fx":       "/welcome",
		"/welcome?next=%2Fja%2Fwelcome%2F":               "/welcome",
		"/welcome":                                       "/welcome",
		"/fr/welcome":                                    "/fr/welcome",
		"/welcome?next=%2F%2Fevil.example":               "/welcome",
		"/welcome?next=%2Faccount%2Fdelete":              "/welcome",
		"/fr/welcome?next=%2Fvuln%3Fauth%3Dx%26q%3D1":    "/fr/welcome?next=%2Fvuln%3Fq%3D1",
		// auth= never travels in next
		"/vuln?auth=ok":                 "/welcome?next=%2Fvuln",
		"/vuln?q=1&auth=ok":             "/welcome?next=%2Fvuln%3Fq%3D1",
		"https://evil.example":          "/welcome",
		"/" + strings.Repeat("a/", 200): "/welcome", // next would be too long
	} {
		got := auth.WelcomeReturn(in)
		if got != want {
			t.Errorf("WelcomeReturn(%q) = %q, want %q", in, got, want)
		}
		if auth.SafeReturnPath(got) != got {
			t.Errorf("WelcomeReturn(%q) = %q is not a safe return path", in, got)
		}
	}
}
