package web_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type suggestBody struct {
	Query string `json:"query"`
	Kind  string `json:"kind"`
	Rows  []struct {
		Name  string `json:"name"`
		Kind  string `json:"kind"`
		Count int    `json:"count"`
	} `json:"rows"`
}

func (b suggestBody) String() string {
	var s []string
	for _, r := range b.Rows {
		s = append(s, r.Name+"/"+r.Kind+"/"+string(rune('0'+r.Count)))
	}
	return strings.Join(s, ",")
}

// TestSuggest: GET /api/affected/suggest lists vendor and product names that
// contain q (case-insensitive), grouped case-insensitively (a name that is
// both a vendor and a product is one "vendor" row), with the number of
// vulnerabilities, publicly cached; parameters are validated like search.
func TestSuggest(t *testing.T) {
	e := newEnv(t, nil)
	for q, want := range map[string]string{
		"barra":     "Barracuda Networks/vendor/1",
		"BALANC":    "Load Balancer ADC/product/1",
		"gpu":       "GPUStack/vendor/1", // GPUStack and gpustack, vendor and product: one row
		"a":         "",                  // too short: no rows
		"ab":        "",                  // too short: 3 characters at least
		"%25%25%25": "",                  // a literal %, not a wildcard
		"zzzzz":     "",
	} {
		resp, b := e.get(t, "/api/affected/suggest?q="+q)
		var got suggestBody
		if resp.StatusCode != 200 || json.Unmarshal(b, &got) != nil || got.Rows == nil {
			t.Fatalf("q=%s: %d %s", q, resp.StatusCode, b)
		}
		if got.String() != want {
			t.Errorf("q=%s: %s, want %s (%s)", q, got, want, b)
		}
		if resp.Header.Get("Cache-Control") != "private, max-age=60" || resp.Header.Get("ETag") == "" {
			t.Errorf("q=%s: headers %v", q, resp.Header)
		}
	}
	resp, b := e.get(t, "/api/affected/suggest?q=%20%20Barracuda%20%20Networks%20&limit=20")
	var got suggestBody
	if resp.StatusCode != 200 || json.Unmarshal(b, &got) != nil || got.Query != "barracuda networks" || got.Kind != "text" || len(got.Rows) != 1 {
		t.Errorf("normalised query: %d %s", resp.StatusCode, b)
	}
	// the cache key is the normalised query: another spelling hits the cache
	before := e.src.n.Load()
	if resp, _ := e.get(t, "/api/affected/suggest?q=BARRACUDA+NETWORKS&limit=20"); resp.Header.Get("X-Nday-Cache") != "hit" || e.src.n.Load() != before {
		t.Errorf("other spelling: cache %q, db calls %d", resp.Header.Get("X-Nday-Cache"), e.src.n.Load()-before)
	}
	// too short and empty: the search shape (kind), no database query
	for q, kind := range map[string]string{"zq": "too_short", "%20": "empty", "": "empty", "%C3%A9x": "too_short"} {
		before := e.src.n.Load()
		_, b := e.get(t, "/api/affected/suggest?q="+q)
		if json.Unmarshal(b, &got) != nil || got.Kind != kind || got.Rows == nil || len(got.Rows) != 0 || e.src.n.Load() != before {
			t.Errorf("q=%q: %s (db calls %d)", q, b, e.src.n.Load()-before)
		}
	}
	// "ati" matches several names (Web Application Firewall, ...): limit
	// cuts to one row.
	if _, b := e.get(t, "/api/affected/suggest?q=ati&limit=1"); json.Unmarshal(b, &got) != nil || len(got.Rows) != 1 {
		t.Errorf("limit=1: %s", b)
	}
	for path, param := range map[string]string{
		"/api/affected/suggest?q=abc&limit=0":                 "limit",
		"/api/affected/suggest?q=abc&limit=21":                "limit",
		"/api/affected/suggest?q=abc&limit=x":                 "limit",
		"/api/affected/suggest?q=abc&x=1":                     "x",
		"/api/affected/suggest?q=abc&q=cd":                    "q",
		"/api/affected/suggest?q=" + strings.Repeat("a", 101): "q",
	} {
		resp, b := e.get(t, path)
		var er struct {
			Error struct {
				Code  string `json:"code"`
				Param string `json:"param"`
			} `json:"error"`
		}
		if resp.StatusCode != 400 || json.Unmarshal(b, &er) != nil || er.Error.Code != "bad_request" || er.Error.Param != param {
			t.Errorf("%s: %d %s", path, resp.StatusCode, b)
		}
	}
	if resp, _ := e.get(t, "/api/affected/suggest?q=abc", "Cookie", "__Host-nday_session=x"); resp.Header.Get("Set-Cookie") != "" ||
		strings.Contains(resp.Header.Get("Vary"), "Cookie") {
		t.Error("suggest touched the session")
	}
}

// TestSuggestTwoHost: in two-host mode the site host keeps answering
// /api/affected/suggest itself (the welcome page script calls it under CSP
// connect-src 'self'); the API host serves it under /v1 with CORS; the
// other data routes still redirect.
func TestSuggestTwoHost(t *testing.T) {
	e := newTwoEnv(t)
	resp, b := do(t, e.two, "GET", "www.nday.land", "/api/affected/suggest?q=barra")
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"Barracuda Networks"`) {
		t.Errorf("site host: %d %s", resp.StatusCode, b)
	}
	resp, b = do(t, e.two, "GET", apiHost, "/v1/affected/suggest?q=barra")
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"Barracuda Networks"`) || resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("API host: %d %v %s", resp.StatusCode, resp.Header, b)
	}
	if resp, _ := do(t, e.two, "GET", "www.nday.land", "/api/search?q=barra"); resp.StatusCode != http.StatusPermanentRedirect {
		t.Errorf("/api/search on the site host: %d", resp.StatusCode)
	}
	if resp, _ := do(t, e.two, "GET", apiHost, "/api/affected/suggest?q=barra"); resp.StatusCode != 404 {
		t.Errorf("/api/ path on the API host: %d", resp.StatusCode)
	}
}
