package auth_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui"
)

const apiHostName = "api.nday.land"

// acctGet is a same-origin GET of an account endpoint with the CSRF token.
func (b *browser) acctGet(path string) (*http.Response, []byte) {
	b.h.t.Helper()
	tok := b.me().CSRFToken
	return b.do("GET", path, "", "Origin", origin, "Sec-Fetch-Site", "same-origin", "X-CSRF-Token", tok)
}

type tokenList struct {
	OK     bool `json:"ok"`
	Tokens []struct {
		ID         string  `json:"id"`
		Name       string  `json:"name"`
		CreatedAt  string  `json:"created_at"`
		LastUsedAt *string `json:"last_used_at"`
	} `json:"tokens"`
	Max int `json:"max"`
}

func (b *browser) tokens() tokenList {
	b.h.t.Helper()
	resp, body := b.acctGet("/account/tokens")
	var l tokenList
	if resp.StatusCode != 200 || json.Unmarshal(body, &l) != nil || !l.OK {
		b.h.t.Fatalf("list tokens: %d %s", resp.StatusCode, body)
	}
	return l
}

// newToken creates an API token and returns its secret and id.
func (b *browser) newToken(name string) (string, string) {
	b.h.t.Helper()
	resp, body := b.post("/account/tokens", `{"name":"`+name+`"}`)
	var r struct {
		OK     bool   `json:"ok"`
		Secret string `json:"secret"`
		Token  struct {
			ID         string  `json:"id"`
			Name       string  `json:"name"`
			LastUsedAt *string `json:"last_used_at"`
		} `json:"token"`
	}
	if resp.StatusCode != 200 || json.Unmarshal(body, &r) != nil || !r.OK || r.Token.ID == "" {
		b.h.t.Fatalf("create token: %d %s", resp.StatusCode, body)
	}
	b.h.secret(r.Secret)
	if !strings.HasPrefix(r.Secret, auth.APITokenPrefix) || len(r.Secret) != auth.APITokenLen || r.Token.Name != name || r.Token.LastUsedAt != nil {
		b.h.t.Fatalf("create token: %s", body)
	}
	return r.Secret, r.Token.ID
}

// api requests path on host without cookies; tok "" sends no Authorization.
func (h *harness) api(host, path, tok string, hdr ...string) (*http.Response, []byte) {
	h.t.Helper()
	c := h.browser()
	if tok != "" {
		hdr = append(hdr, "Authorization", "Bearer "+tok)
	}
	return c.do("GET", path, "", append([]string{"Host", host}, hdr...)...)
}

// checkGated401 checks a refusal: status, code, no-store, the challenge.
func checkRefusal(t *testing.T, what string, resp *http.Response, body []byte, status int, code string) {
	t.Helper()
	cc := resp.Header.Get("Cache-Control")
	if resp.StatusCode != status || errCode(t, body) != code || (cc != "no-store" && cc != "private, no-store") ||
		(status == 401) != (resp.Header.Get("WWW-Authenticate") == `Bearer realm="nday"`) {
		t.Errorf("%s: %d %v %s (want %d %s)", what, resp.StatusCode, resp.Header, body, status, code)
	}
	if strings.Contains(string(body), `"rows"`) || strings.Contains(string(body), "CVE-2026-102895") && code != "not_found" {
		t.Errorf("%s: data in a refusal: %s", what, body)
	}
}

func vary(resp *http.Response) string { return strings.Join(resp.Header.Values("Vary"), ", ") }

// checkPrivate checks a successful gated response.
func checkPrivate(t *testing.T, what string, resp *http.Response, body []byte) {
	t.Helper()
	cc := resp.Header.Get("Cache-Control")
	if resp.StatusCode != 200 || strings.Contains(cc, "public") || !strings.Contains(cc, "private") ||
		!strings.Contains(vary(resp), "Authorization") || !json.Valid(body) {
		t.Errorf("%s: %d %q %v %.200s", what, resp.StatusCode, cc, resp.Header, body)
	}
}

func TestAPITokenAccountEndpoints(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, seed: true})
	b := h.browser()
	b.login(auth.GitHub, acct("tok-a"), "")

	// same-origin and CSRF like every account endpoint
	if resp, body := b.do("GET", "/account/tokens", ""); resp.StatusCode != 403 || errCode(t, body) != "cross_site" {
		t.Errorf("no same-origin evidence: %d %s", resp.StatusCode, body)
	}
	if resp, body := b.do("GET", "/account/tokens", "", "Sec-Fetch-Site", "same-origin"); resp.StatusCode != 403 || errCode(t, body) != "csrf" {
		t.Errorf("no CSRF: %d %s", resp.StatusCode, body)
	}
	if resp, body := h.browser().do("GET", "/account/tokens", "", "Sec-Fetch-Site", "same-origin"); resp.StatusCode != 401 || errCode(t, body) != "not_signed_in" {
		t.Errorf("signed out: %d %s", resp.StatusCode, body)
	}
	if l := b.tokens(); len(l.Tokens) != 0 || l.Max != 5 {
		t.Errorf("fresh list %+v", l)
	}
	// names
	for _, n := range []string{`""`, `"   "`, `"` + strings.Repeat("x", 65) + `"`} {
		if resp, body := b.post("/account/tokens", `{"name":`+n+`}`); resp.StatusCode != 400 || errCode(t, body) != "bad_request" {
			t.Errorf("name %s: %d %s", n, resp.StatusCode, body)
		}
	}
	if resp, body := b.post("/account/tokens", `{"name":"x","extra":1}`); resp.StatusCode != 400 {
		t.Errorf("unknown field: %d %s", resp.StatusCode, body)
	}
	sec, id := b.newToken("ci " + strings.Repeat("y", 61)) // 64 characters
	l := b.tokens()
	raw, _ := json.Marshal(l)
	if len(l.Tokens) != 1 || l.Tokens[0].ID != id || strings.Contains(string(raw), sec) || strings.Contains(string(raw), "hash") {
		t.Errorf("list %s", raw)
	}
	if n := h.count(`SELECT count(*) FROM api_tokens WHERE position($1::bytea IN token_hash) > 0 OR name = $2`, []byte(sec), sec); n != 0 {
		t.Error("the secret is stored")
	}
	// limit of 5 live tokens
	ids := []string{id}
	for i := 0; i < 4; i++ {
		_, id := b.newToken("t")
		ids = append(ids, id)
	}
	if resp, body := b.post("/account/tokens", `{"name":"sixth"}`); resp.StatusCode != 409 || errCode(t, body) != "token_limit" {
		t.Errorf("sixth: %d %s", resp.StatusCode, body)
	}
	// revoke: idempotent, frees a slot, the token stops working at once
	if resp, _ := h.api(publicHost, "/api/stats", sec); resp.StatusCode != 200 {
		t.Fatalf("token before revoke: %d", resp.StatusCode)
	}
	for i := 0; i < 2; i++ {
		if resp, body := b.post("/account/tokens/"+id+"/revoke", ""); resp.StatusCode != 200 {
			t.Errorf("revoke %d: %d %s", i, resp.StatusCode, body)
		}
	}
	resp, body := h.api(publicHost, "/api/stats", sec)
	checkRefusal(t, "revoked", resp, body, 401, "invalid_token")
	if l := b.tokens(); len(l.Tokens) != 4 {
		t.Errorf("after revoke: %d tokens", len(l.Tokens))
	}
	b.newToken("again")
	for _, bad := range []string{"nope", "00000000-0000-0000-0000-000000000000", ids[1] + "x"} {
		if resp, body := b.post("/account/tokens/"+bad+"/revoke", ""); resp.StatusCode != 404 || errCode(t, body) != "not_found" {
			t.Errorf("revoke %s: %d %s", bad, resp.StatusCode, body)
		}
	}

	// another user can neither see nor revoke these tokens
	o := h.browser()
	o.ip = "198.51.100.8"
	o.login(auth.GitHub, acct("tok-b"), "")
	if l := o.tokens(); len(l.Tokens) != 0 {
		t.Errorf("other user sees %d tokens", len(l.Tokens))
	}
	if resp, body := o.post("/account/tokens/"+ids[1]+"/revoke", ""); resp.StatusCode != 404 || errCode(t, body) != "not_found" {
		t.Errorf("other user's revoke: %d %s", resp.StatusCode, body)
	}
	if n := h.count(`SELECT count(*) FROM api_tokens WHERE id = $1 AND revoked_at IS NULL`, ids[1]); n != 1 {
		t.Error("another user revoked the token")
	}

	// creating needs a recent sign-in (like adding a passkey); revoking not
	h.clock.Advance(16 * time.Minute)
	if resp, body := o.post("/account/tokens", `{"name":"late"}`); resp.StatusCode != 403 || errCode(t, body) != "reauth_required" {
		t.Errorf("old session: %d %s", resp.StatusCode, body)
	}
	o.reauth(auth.GitHub, "tok-b")
	osec, _ := o.newToken("fresh")
	if resp, body := b.post("/account/tokens/"+ids[2]+"/revoke", ""); resp.StatusCode != 200 {
		t.Errorf("revoke on an old session: %d %s", resp.StatusCode, body)
	}

	// suspended: no new token, and the existing ones stop working
	uid := o.me().User.ID
	if err := h.store.Suspend(context.Background(), uid, nil, "test"); err != nil {
		t.Fatal(err)
	}
	if resp, body := o.post("/account/tokens", `{"name":"x"}`); resp.StatusCode != 403 || errCode(t, body) != "suspended" {
		t.Errorf("suspended create: %d %s", resp.StatusCode, body)
	}
	resp, body = h.api(publicHost, "/api/stats", osec)
	checkRefusal(t, "suspended user's token", resp, body, 403, "suspended")
	if err := h.store.Unsuspend(context.Background(), uid); err != nil {
		t.Fatal(err)
	}
	if resp, _ := h.api(publicHost, "/api/stats", osec); resp.StatusCode != 200 {
		t.Errorf("after unsuspend: %d", resp.StatusCode)
	}

	// deleting the account removes its tokens
	o.reauth(auth.GitHub, "tok-b")
	o.deleteAccount()
	resp, body = h.api(publicHost, "/api/stats", osec)
	checkRefusal(t, "deleted account's token", resp, body, 401, "invalid_token")
	if n := h.count(`SELECT count(*) FROM api_tokens WHERE user_id = $1`, uid); n != 0 {
		t.Errorf("%d tokens left after deleting the account", n)
	}
}

// The gate matrix on the site host (single-host mode, /api and /raw) and on
// the API host (two-host mode, /v1 and the /raw alias).
func TestAPIGateMatrix(t *testing.T) {
	for _, mode := range []string{"single", "two"} {
		t.Run(mode, func(t *testing.T) {
			o := harnessOpt{providers: []string{auth.GitHub}, seed: true}
			host, prefix := publicHost, "/api"
			if mode == "two" {
				o.apiURL, host, prefix = "https://"+apiHostName, apiHostName, "/v1"
			}
			h := newHarness(t, o)
			b := h.browser()
			b.login(auth.GitHub, acct("matrix"), "")
			valid, _ := b.newToken("valid")
			revoked, rid := b.newToken("revoked")
			b.post("/account/tokens/"+rid+"/revoke", "")
			s := h.browser()
			s.ip = "198.51.100.20"
			s.login(auth.GitHub, acct("matrix-suspended"), "")
			susp, _ := s.newToken("s")
			if err := h.store.Suspend(context.Background(), s.me().User.ID, nil, ""); err != nil {
				t.Fatal(err)
			}
			unknown := h.svc.MintAPITokenForTest() // tagged by this server, never stored
			h.secret(unknown)
			rawPath := "/raw/kev/CVE-2026-102895.json"
			if mode == "two" {
				rawPath = "/v1" + rawPath
			}
			paths := []string{prefix + "/hot?since=30d", prefix + "/vuln/CVE-2026-102895", prefix + "/search?q=barracuda", rawPath,
				prefix + "/affected/suggest?q=barra", prefix + "/stats"}
			if mode == "two" {
				paths = append(paths, "/raw/kev/CVE-2026-102895.json") // alias on the API host
			}
			for _, p := range paths {
				// the valid token first: its body is then in the response cache
				resp, body := h.api(host, p, valid)
				checkPrivate(t, p+" valid", resp, body)
				for name, hdr := range map[string][]string{
					"none":      nil,
					"basic":     {"Authorization", "Basic " + valid},
					"no token":  {"Authorization", "Bearer"},
					"bearer sp": {"Authorization", "Bearer   "},
					"query":     {"X-Nothing", "1"},
				} {
					q := p
					if name == "query" {
						q += map[bool]string{true: "&", false: "?"}[strings.Contains(p, "?")] + "access_token=" + valid
					}
					resp, body := h.api(host, q, "", hdr...)
					checkRefusal(t, p+" "+name, resp, body, 401, "token_required")
					if resp.Header.Get("X-Nday-Cache") != "" {
						t.Errorf("%s %s: answered from the cache", p, name)
					}
				}
				for name, tok := range map[string]string{"unknown": unknown, "garbage": "x.y.z", "revoked": revoked, "wrong case": strings.ToUpper(valid)} {
					resp, body := h.api(host, p, tok)
					checkRefusal(t, p+" "+name, resp, body, 401, "invalid_token")
				}
				resp, body = h.api(host, p, susp)
				checkRefusal(t, p+" suspended", resp, body, 403, "suspended")
				// a session cookie is not an API credential here
				resp, body = b.do("GET", p, "", "Host", host)
				if p == prefix+"/affected/suggest?q=barra" && mode == "single" || p == rawPath && mode == "single" {
					// ... except for the page routes on the site host
					if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(vary(resp), "Cookie") {
						t.Errorf("%s with the session: %d %v", p, resp.StatusCode, resp.Header)
					}
				} else {
					checkRefusal(t, p+" cookie only", resp, body, 401, "token_required")
				}
			}
			// two Authorization headers are malformed
			req, _ := http.NewRequest("GET", h.ts.URL+prefix+"/stats", nil)
			req.Host = host
			req.Header.Add("Authorization", "Bearer "+valid)
			req.Header.Add("Authorization", "Bearer "+valid)
			if resp, err := http.DefaultClient.Do(req); err != nil || resp.StatusCode != 401 {
				t.Errorf("two headers: %v %v", resp, err)
			}
			// public without a token
			public := []string{"/healthz"}
			if mode == "two" {
				public = append(public, "/", "/v1", "/robots.txt")
			} else {
				public = append(public, "/")
			}
			for _, p := range public {
				if resp, body := h.api(host, p, ""); resp.StatusCode != 200 {
					t.Errorf("public %s: %d %s", p, resp.StatusCode, body)
				}
			}
			if mode == "two" {
				// the site host: redirects stay public; suggest and raw are
				// served there, with the token or the session
				for _, p := range []string{"/api/hot", "/api/vuln/CVE-2026-102895", "/api/search?q=x"} {
					if resp, _ := h.api(publicHost, p, ""); resp.StatusCode != http.StatusPermanentRedirect {
						t.Errorf("www %s: %d", p, resp.StatusCode)
					}
				}
				for _, p := range []string{"/api/affected/suggest?q=barra", "/raw/kev/CVE-2026-102895.json"} {
					resp, body := h.api(publicHost, p, "")
					checkRefusal(t, "www "+p+" signed out", resp, body, 401, "token_required")
					resp, body = h.api(publicHost, p, valid)
					checkPrivate(t, "www "+p+" token", resp, body)
					resp, body = b.do("GET", p, "")
					if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "no-store" || !strings.Contains(vary(resp), "Cookie") ||
						resp.Header.Get("ETag") != "" {
						t.Errorf("www %s session: %d %v", p, resp.StatusCode, resp.Header)
					}
					resp, body = s.do("GET", p, "")
					checkRefusal(t, "www "+p+" suspended session", resp, body, 403, "suspended")
					// a session cookie sent to the API host counts for nothing
					resp, body = b.do("GET", "/v1"+strings.TrimPrefix(p, "/api"), "", "Host", apiHostName)
					checkRefusal(t, "api host "+p+" cookie", resp, body, 401, "token_required")
				}
			}
		})
	}
}

func TestAPITokenLastUsedAndLimits(t *testing.T) {
	ck := &clock{t: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)}
	tokRL := auth.NewRateLimiter(3, time.Hour)
	tokRL.Now = ck.Now
	clRL := auth.NewRateLimiter(30, time.Hour)
	clRL.Now = ck.Now
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, seed: true, apiToken: tokRL, apiClient: clRL})
	b := h.browser()
	b.login(auth.GitHub, acct("lim"), "")
	sec, id := b.newToken("lim")
	lastUsed := func() *time.Time {
		var v *time.Time
		if err := h.db.Conn.QueryRow(context.Background(), `SELECT last_used_at FROM api_tokens WHERE id = $1`, id).Scan(&v); err != nil {
			t.Fatal(err)
		}
		return v
	}
	if lastUsed() != nil {
		t.Fatal("fresh token has last_used_at")
	}
	t0 := h.clock.Now()
	h.api(publicHost, "/api/stats", sec)
	if v := lastUsed(); v == nil || !v.Equal(t0) {
		t.Errorf("first use: %v", v)
	}
	h.clock.Advance(30 * time.Second)
	h.api(publicHost, "/api/stats", sec)
	if v := lastUsed(); v == nil || !v.Equal(t0) {
		t.Errorf("within a minute: %v (want %v)", v, t0)
	}
	// third request: the per-token limit (burst 3 here) answers 429
	h.api(publicHost, "/api/stats", sec)
	resp, body := h.api(publicHost, "/api/stats", sec)
	if resp.StatusCode != 429 || errCode(t, body) != "rate_limited" || resp.Header.Get("Retry-After") == "" {
		t.Errorf("per token: %d %s", resp.StatusCode, body)
	}
	h.clock.Advance(31 * time.Second)
	if v := lastUsed(); v == nil || !v.Equal(t0) {
		t.Errorf("a refused request touched last_used_at: %v", v)
	}
	// list shows last_used_at
	if l := b.tokens(); len(l.Tokens) != 1 || l.Tokens[0].LastUsedAt == nil {
		t.Errorf("list: %+v", l)
	}

	// A replayed invalid token costs one lookup, then none.
	bad := h.svc.MintAPITokenForTest()
	before := h.dbc.calls.Load()
	for i := 0; i < 5; i++ {
		resp, body := h.api(publicHost, "/api/stats", bad, "CF-Connecting-IP", "203.0.113.50")
		checkRefusal(t, "replayed", resp, body, 401, "invalid_token")
	}
	if n := h.dbc.calls.Load() - before; n != 1 {
		t.Errorf("replayed invalid token: %d lookups, want 1", n)
	}
	// Made-up tokens from one client: the per-client limit stops the lookups.
	before = h.dbc.calls.Load()
	limited := 0
	for i := 0; i < 40; i++ {
		tok := h.svc.MintAPITokenForTest()
		h.secret(tok)
		resp, _ := h.api(publicHost, "/api/stats", tok, "CF-Connecting-IP", "203.0.113.60")
		if resp.StatusCode == 429 {
			limited++
		}
	}
	if limited != 10 || h.dbc.calls.Load()-before > 30 {
		t.Errorf("flood: %d refused with 429, %d lookups", limited, h.dbc.calls.Load()-before)
	}
	// Malformed tokens never reach the database.
	before = h.dbc.calls.Load()
	for _, tok := range []string{"short", auth.APITokenPrefix + strings.Repeat("!", 64), "xxxx_" + sec[5:], sec[:len(sec)-1] + "\t"} {
		resp, body := h.api(publicHost, "/api/stats", tok, "CF-Connecting-IP", "203.0.113.70")
		checkRefusal(t, "malformed "+tok, resp, body, 401, "invalid_token")
	}
	if n := h.dbc.calls.Load() - before; n != 0 {
		t.Errorf("malformed tokens: %d lookups", n)
	}
	// Well-shaped tokens with a wrong tag (forged without the server
	// secret): no lookup, and they don't even use up the client's limit
	// (burst 30 here), whatever CF-Connecting-IP claims.
	before = h.dbc.calls.Load()
	for i := 0; i < 100; i++ {
		raw := make([]byte, 48)
		_, _ = rand.Read(raw)
		forged := auth.APITokenPrefix + base64.RawURLEncoding.EncodeToString(raw)
		resp, body := h.api(publicHost, "/api/stats", forged, "CF-Connecting-IP", "203.0.113.80")
		checkRefusal(t, "forged", resp, body, 401, "invalid_token")
	}
	if n := h.dbc.calls.Load() - before; n != 0 {
		t.Errorf("forged tokens: %d lookups", n)
	}
}

// A saturated API lookup semaphore answers token requests 503 quickly and
// never delays or fails a session check.
func TestAPISlotsDoNotStarveSessions(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, seed: true})
	b := h.browser()
	b.login(auth.GitHub, acct("slots"), "")
	tok, _ := b.newToken("slots")
	release := h.svc.HoldAPISlotsForTest()
	start := time.Now()
	resp, body := h.api(publicHost, "/api/stats", tok)
	if resp.StatusCode != 503 || errCode(t, body) != "busy" || resp.Header.Get("Retry-After") != "1" || time.Since(start) > time.Second {
		t.Errorf("token while saturated: %d %s after %v", resp.StatusCode, body, time.Since(start))
	}
	for i := 0; i < 20; i++ {
		start = time.Now()
		if m := b.me(); !m.SignedIn {
			t.Fatal("session check failed")
		}
		resp, _ := b.do("GET", "/api/affected/suggest?q=barra", "")
		if resp.StatusCode != 200 || time.Since(start) > 500*time.Millisecond {
			t.Errorf("session while API slots are full: %d after %v", resp.StatusCode, time.Since(start))
		}
	}
	release()
	if resp, _ := h.api(publicHost, "/api/stats", tok); resp.StatusCode != 200 {
		t.Errorf("after release: %d", resp.StatusCode)
	}
}

// Creating and revoking in a loop keeps at most RevokedTokenHistory
// revoked rows per user.
func TestRevokedTokensBounded(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}})
	b := h.browser()
	b.login(auth.GitHub, acct("loop"), "")
	uid := b.me().User.ID
	ctx := context.Background()
	var first string
	for i := 0; i < auth.RevokedTokenHistory+10; i++ {
		sec, err := h.svc.IssueAPIToken(ctx, uid, "loop") // the same store path as POST /account/tokens
		if err != nil {
			t.Fatal(err)
		}
		h.secret(sec)
		if i == 0 {
			first = sec
		}
		var id string
		if err := h.db.Conn.QueryRow(ctx, `SELECT id::text FROM api_tokens WHERE revoked_at IS NULL`).Scan(&id); err != nil {
			t.Fatal(err)
		}
		h.clock.Advance(time.Second)
		if err := h.store.RevokeAPIToken(ctx, uid, id); err != nil {
			t.Fatal(err)
		}
	}
	b.newToken("last")
	if n := h.count(`SELECT count(*) FROM api_tokens WHERE revoked_at IS NOT NULL`); n != auth.RevokedTokenHistory {
		t.Errorf("%d revoked rows, want %d", n, auth.RevokedTokenHistory)
	}
	if n := h.count(`SELECT count(*) FROM api_tokens WHERE revoked_at IS NULL`); n != 1 {
		t.Errorf("%d live rows", n)
	}
	resp, body := h.api(publicHost, "/api/stats", first)
	checkRefusal(t, "pruned revoked token", resp, body, 401, "invalid_token")
}

// ---- private feed ----

type feedAddr struct {
	Key string `json:"key"`
	URL string `json:"url"`
}

func (b *browser) feedAddr(path, method string) feedAddr {
	b.h.t.Helper()
	var resp *http.Response
	var body []byte
	if method == "POST" {
		resp, body = b.post(path, "")
	} else {
		resp, body = b.acctGet(path)
	}
	var f feedAddr
	if resp.StatusCode != 200 || json.Unmarshal(body, &f) != nil || f.Key == "" {
		b.h.t.Fatalf("%s %s: %d %s", method, path, resp.StatusCode, body)
	}
	b.h.secret(f.Key)
	if f.URL != origin+"/feed.xml?key="+f.Key {
		b.h.t.Errorf("feed url %q", f.URL)
	}
	return f
}

func withWebUI(h *harness, srv *web.Server) {
	if _, err := webui.New(srv, webui.Options{Now: func() time.Time { return h.clock.Now() }}); err != nil {
		h.t.Fatal(err)
	}
}

func checkFeedOK(t *testing.T, what string, resp *http.Response, body []byte, cc string) {
	t.Helper()
	if resp.StatusCode != 200 || !strings.HasPrefix(resp.Header.Get("Content-Type"), "application/atom+xml") ||
		resp.Header.Get("Cache-Control") != cc || !bytes.Contains(body, []byte("<feed")) ||
		!strings.Contains(vary(resp), "Authorization") {
		t.Errorf("%s: %d %v %.200s", what, resp.StatusCode, resp.Header, body)
	}
}

func TestPrivateFeed(t *testing.T) {
	h := newHarness(t, harnessOpt{providers: []string{auth.GitHub}, seed: true, apiURL: "https://" + apiHostName, register: withWebUI})
	b := h.browser()
	b.login(auth.GitHub, acct("feed"), "")
	f := b.feedAddr("/account/feed", "GET")
	if again := b.feedAddr("/account/feed", "GET"); again != f {
		t.Errorf("the address changed: %v %v", f, again)
	}
	uid := b.me().User.ID
	if !strings.HasPrefix(f.Key, uid+".") || len(f.Key) != 36+1+22+1+22 {
		t.Errorf("key %q", f.Key)
	}

	// key: 200, private, no referrer; also with ?tag= and per locale
	for _, p := range []string{"/feed.xml?key=" + f.Key, "/feed.xml?tag=kev&key=" + f.Key, "/zh-hans/feed.xml?key=" + f.Key} {
		resp, body := h.api(publicHost, p, "")
		checkFeedOK(t, p, resp, body, "private, no-store")
		if resp.Header.Get("Referrer-Policy") != "no-referrer" || bytes.Contains(body, []byte(f.Key)) {
			t.Errorf("%s: referrer policy %q, key in body %v", p, resp.Header.Get("Referrer-Policy"), bytes.Contains(body, []byte(f.Key)))
		}
	}
	// the session and an API token work too
	resp, body := b.do("GET", "/feed.xml", "")
	checkFeedOK(t, "session", resp, body, "no-store")
	if !strings.Contains(vary(resp), "Cookie") {
		t.Errorf("session feed Vary %q", vary(resp))
	}
	tok, _ := b.newToken("feed")
	resp, body = h.api(publicHost, "/feed.xml", tok)
	checkFeedOK(t, "token", resp, body, "private, no-store")

	// refusals: all the same 401 as no credential
	other := h.browser()
	other.ip = "198.51.100.30"
	other.login(auth.GitHub, acct("feed-other"), "")
	of := other.feedAddr("/account/feed", "GET")
	mac := f.Key[len(uid)+1:]
	omac := of.Key[strings.IndexByte(of.Key, '.')+1:]
	flip := func(s string) string {
		c := byte('A')
		if s[0] == 'A' {
			c = 'B'
		}
		return string(c) + s[1:]
	}
	var first []byte
	for name, key := range map[string]string{
		"wrong mac":            uid + "." + flip(mac),
		"other user's mac":     uid + "." + omac,
		"unknown user":         "0f0f0f0f-0000-4000-8000-000000000000." + mac,
		"issued, unknown user": h.svc.MintFeedKeyForTest("0f0f0f0f-0000-4000-8000-000000000000", make([]byte, 16)),
		"issued, wrong salt":   h.svc.MintFeedKeyForTest(uid, make([]byte, 16)),
		"upper-case id":        strings.ToUpper(uid) + "." + mac,
		"no dot":               uid + mac,
		"short":                uid + "." + mac[:10],
		"empty":                "",
		"api token as key":     tok,
		"padded":               f.Key + "=",
		"two keys (second)":    f.Key + "&key=" + f.Key,
	} {
		resp, body := h.api(publicHost, "/feed.xml?key="+key, "")
		checkRefusal(t, "feed "+name, resp, body, 401, "token_required")
		if first == nil {
			first = body
		} else if !bytes.Equal(first, body) {
			t.Errorf("feed %s: body differs: %s vs %s", name, body, first)
		}
	}
	resp, body = h.api(publicHost, "/feed.xml", "")
	checkRefusal(t, "feed without credentials", resp, body, 401, "token_required")
	if !bytes.Equal(body, first) {
		t.Errorf("a wrong key and no credential differ: %s vs %s", first, body)
	}
	if resp.Header.Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("refusal Referrer-Policy %q", resp.Header.Get("Referrer-Policy"))
	}

	// forged keys (right shape, wrong tag, a real user id) never reach the
	// database
	before := h.dbc.calls.Load()
	for i := 0; i < 50; i++ {
		raw := make([]byte, 32)
		_, _ = rand.Read(raw)
		k := uid + "." + base64.RawURLEncoding.EncodeToString(raw[:16]) + "." + base64.RawURLEncoding.EncodeToString(raw[16:])
		resp, body := h.api(publicHost, "/feed.xml?key="+k, "", "CF-Connecting-IP", "203.0.113.90")
		checkRefusal(t, "forged feed key", resp, body, 401, "token_required")
	}
	if n := h.dbc.calls.Load() - before; n != 0 {
		t.Errorf("forged feed keys: %d lookups", n)
	}

	// the key is for the feed only
	for _, p := range []string{"/v1/hot?key=" + f.Key, "/v1/raw/kev/CVE-2026-102895.json?key=" + f.Key, "/raw/kev/CVE-2026-102895.json?key=" + f.Key} {
		resp, body := h.api(apiHostName, p, "")
		if resp.StatusCode != 401 {
			t.Errorf("api host %s: %d %s", p, resp.StatusCode, body)
		}
	}
	for _, p := range []string{"/raw/kev/CVE-2026-102895.json?key=" + f.Key, "/api/affected/suggest?q=barra&key=" + f.Key} {
		if resp, body := h.api(publicHost, p, ""); resp.StatusCode != 401 {
			t.Errorf("www %s: %d %s", p, resp.StatusCode, body)
		}
	}

	// rotation: the old address stops at once, the new one works; no
	// recent sign-in needed
	h.clock.Advance(time.Hour)
	nf := b.feedAddr("/account/feed/rotate", "POST")
	if nf.Key == f.Key || b.feedAddr("/account/feed", "GET") != nf {
		t.Errorf("rotate: %v -> %v", f, nf)
	}
	resp, body = h.api(publicHost, "/feed.xml?key="+f.Key, "")
	checkRefusal(t, "rotated key", resp, body, 401, "token_required")
	resp, body = h.api(publicHost, "/feed.xml?key="+nf.Key, "")
	checkFeedOK(t, "new key", resp, body, "private, no-store")

	// suspended: the key is refused, the user cannot rotate
	if err := h.store.Suspend(context.Background(), uid, nil, ""); err != nil {
		t.Fatal(err)
	}
	resp, body = h.api(publicHost, "/feed.xml?key="+nf.Key, "")
	checkRefusal(t, "suspended key", resp, body, 403, "suspended")
	if resp, body := b.post("/account/feed/rotate", ""); resp.StatusCode != 403 || errCode(t, body) != "suspended" {
		t.Errorf("suspended rotate: %d %s", resp.StatusCode, body)
	}
	resp, body = b.do("GET", "/feed.xml", "")
	checkRefusal(t, "suspended session", resp, body, 403, "suspended")
	if err := h.store.Unsuspend(context.Background(), uid); err != nil {
		t.Fatal(err)
	}

	// deleted: the key is refused
	other.reauth(auth.GitHub, "feed-other")
	other.deleteAccount()
	resp, body = h.api(publicHost, "/feed.xml?key="+of.Key, "")
	checkRefusal(t, "deleted user's key", resp, body, 401, "token_required")

	// the access log never shows the key
	if logs := h.logs.String(); strings.Contains(logs, nf.Key) || strings.Contains(logs, mac) || !strings.Contains(logs, "key=REDACTED") {
		t.Errorf("feed key in the log (or no redacted line):\n%s", logs)
	}

	// Two secrets: a service whose current secret is new and whose
	// previous one is the harness's still accepts the address made with the
	// previous secret, and signs new addresses with the current one (which
	// the harness, knowing only the old secret, refuses).
	cfg2 := *h.cfg
	cfg2.Secrets = [][]byte{bytes.Repeat([]byte{9}, 32), h.cfg.Secrets[0]}
	log2 := slog.New(slog.NewTextHandler(h.logs, nil))
	svc2, err := auth.New(&cfg2, auth.Options{Store: h.store, Logger: log2, Now: h.clock.Now})
	if err != nil {
		t.Fatal(err)
	}
	srv2 := web.New(web.Config{Store: site.New(h.dbc).WithClock(func() time.Time { return sitetest.Now }), Logger: log2})
	svc2.Register(srv2)
	withWebUI(h, srv2)
	ts2 := httptest.NewServer(srv2.Handler())
	t.Cleanup(ts2.Close)
	send := func(ts *httptest.Server, path string, hdr ...string) (*http.Response, []byte) {
		req, _ := http.NewRequest("GET", ts.URL+path, nil)
		req.Host = publicHost
		for i := 0; i+1 < len(hdr); i += 2 {
			req.Header.Set(hdr[i], hdr[i+1])
		}
		for _, c := range b.jar {
			req.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value})
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		return resp, body
	}
	resp, body = send(ts2, "/feed.xml?key="+nf.Key)
	checkFeedOK(t, "previous-secret key on the new service", resp, body, "private, no-store")
	resp, body = send(ts2, "/account/feed", "Origin", origin, "Sec-Fetch-Site", "same-origin", "X-CSRF-Token", b.me().CSRFToken)
	var f2 feedAddr
	if resp.StatusCode != 200 || json.Unmarshal(body, &f2) != nil || f2.Key == "" || f2.Key == nf.Key {
		t.Fatalf("new service's address: %d %s", resp.StatusCode, body)
	}
	h.secret(f2.Key)
	resp, body = send(ts2, "/feed.xml?key="+f2.Key)
	checkFeedOK(t, "current-secret key", resp, body, "private, no-store")
	if resp, _ := h.api(publicHost, "/feed.xml?key="+f2.Key, ""); resp.StatusCode != 401 {
		t.Errorf("a key of an unknown secret: %d", resp.StatusCode)
	}
}
