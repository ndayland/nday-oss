package web_test

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestVulnsEndpointAndCaching(t *testing.T) {
	e := newEnv(t, nil)
	resp, b := e.get(t, "/api/vulns?limit=2")
	if resp.StatusCode != 200 || resp.Header.Get("Cache-Control") != "public, max-age=60" ||
		resp.Header.Get("Content-Type") != "application/json; charset=utf-8" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("%d %v %s", resp.StatusCode, resp.Header, b)
	}
	m := decode(t, b)
	rows := m["rows"].([]any)
	if len(rows) != 2 || m["next_cursor"] == nil || m["stage"] != nil || m["stage_code"] != nil || m["year"] != nil ||
		m["limit"].(float64) != 2 || m["include_rejected"] != false || len(m["tags"].([]any)) != 0 || m["generated_at"] == nil {
		t.Errorf("%s", b)
	}
	for _, k := range []string{"since", "since_start", "min_stage", "offset"} {
		if _, ok := m[k]; ok {
			t.Errorf("hot-only field %s present", k)
		}
	}
	r0 := rows[0].(map[string]any)
	if r0["cve_id"] != "CVE-2026-1004" || r0["pinned"] != false || r0["stage"] != "disclosed" {
		t.Errorf("row %v", r0)
	}
	etag := resp.Header.Get("ETag")
	if etag == "" || resp.Header.Get("X-Nday-Cache") != "miss" {
		t.Errorf("etag %q cache %q", etag, resp.Header.Get("X-Nday-Cache"))
	}
	before := e.src.n.Load()
	resp, b = e.get(t, "/api/vulns?limit=2", "If-None-Match", etag)
	if resp.StatusCode != http.StatusNotModified || len(b) != 0 || resp.Header.Get("X-Nday-Cache") != "hit" || e.src.n.Load() != before {
		t.Errorf("conditional: %d %q", resp.StatusCode, resp.Header.Get("X-Nday-Cache"))
	}
	// paging to the end
	var got []string
	cur := ""
	for i := 0; i < 20; i++ {
		resp, b = e.get(t, "/api/vulns?limit=2&include_rejected=1"+cur)
		if resp.StatusCode != 200 {
			t.Fatalf("%d %s", resp.StatusCode, b)
		}
		m := decode(t, b)
		for _, r := range m["rows"].([]any) {
			got = append(got, strings.TrimPrefix(r.(map[string]any)["cve_id"].(string), "CVE-2026-"))
		}
		if m["next_cursor"] == nil {
			break
		}
		cur = "&cursor=" + url.QueryEscape(m["next_cursor"].(string))
	}
	if strings.Join(got, ",") != "1005,1004,1001,1002,1003,102895,1008,1007,1009,1006" {
		t.Errorf("pages %v", got)
	}
	// filters, echoed canonically; tag repeatable
	resp, b = e.get(t, "/api/vulns?stage=KEV&year=2026&tag=ransomware&tag=ransomware")
	m = decode(t, b)
	if resp.StatusCode != 200 || m["stage"] != "kev_added" || m["stage_code"] != "KEV" || m["year"].(float64) != 2026 ||
		len(m["tags"].([]any)) != 1 || len(m["rows"].([]any)) != 0 {
		t.Errorf("%d %s", resp.StatusCode, b)
	}
	resp, b = e.get(t, "/api/vulns?stage=patch&include_rejected=true")
	m = decode(t, b)
	if len(m["rows"].([]any)) != 3 || m["rows"].([]any)[0].(map[string]any)["cve_id"] != "CVE-2026-1005" {
		t.Errorf("%d %s", resp.StatusCode, b)
	}
}

func TestVulnsBadRequests(t *testing.T) {
	e := newEnv(t, nil)
	next := strconv.Itoa(time.Now().UTC().Year() + 2)
	for path, param := range map[string]string{
		"/api/vulns?stage=zzz":                             "stage",
		"/api/vulns?stage=":                                "stage",
		"/api/vulns?stage=kev&stage=poc":                   "stage",
		"/api/vulns?year=1998":                             "year",
		"/api/vulns?year=" + next:                          "year",
		"/api/vulns?year=0":                                "year",
		"/api/vulns?year=":                                 "year",
		"/api/vulns?year=2026x":                            "year",
		"/api/vulns?limit=0":                               "limit",
		"/api/vulns?limit=201":                             "limit",
		"/api/vulns?limit=x":                               "limit",
		"/api/vulns?cursor=bogus":                          "cursor",
		"/api/vulns?cursor=":                               "cursor",
		"/api/vulns?include_rejected=maybe":                "include_rejected",
		"/api/vulns?tag=nope":                              "tag",
		"/api/vulns?offset=0":                              "offset",
		"/api/vulns?since=7d":                              "since",
		"/api/vulns?min_stage=patch":                       "min_stage",
		"/api/vulns?foo=1":                                 "foo",
		"/api/vulns?limit=2&limit=3":                       "limit",
		"/api/vulns?year=2026&year=2025":                   "year",
		"/api/vulns?include_rejected=1&include_rejected=0": "include_rejected",
	} {
		resp, b := e.get(t, path)
		if resp.StatusCode != 400 || resp.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("%s: %d %s", path, resp.StatusCode, b)
			continue
		}
		er := decode(t, b)["error"].(map[string]any)
		if er["param"] != param || er["code"] != "bad_request" || er["status"].(float64) != 400 {
			t.Errorf("%s: %s", path, b)
		}
	}
	// a hot cursor is not a catalogue cursor
	_, b := e.get(t, "/api/hot?since=30d&limit=1")
	if resp, _ := e.get(t, "/api/vulns?cursor="+url.QueryEscape(decode(t, b)["next_cursor"].(string))); resp.StatusCode != 400 {
		t.Errorf("hot cursor: %d", resp.StatusCode)
	}
}

func TestVulnsTwoHosts(t *testing.T) {
	e := newTwoEnv(t)
	for old, v1 := range map[string]string{
		"/api/vulns":                        "/v1/vulns",
		"/api/vulns?stage=kev&limit=2":      "/v1/vulns?stage=kev&limit=2",
		"/api/vulns?year=2026&tag=network":  "/v1/vulns?year=2026&tag=network",
		"/api/vulns?stage=nope":             "/v1/vulns?stage=nope",
		"/api/vulns?include_rejected=1&x=1": "/v1/vulns?include_rejected=1&x=1",
	} {
		r1, b1 := do(t, e.single, "GET", "", old)
		r2, b2 := do(t, e.two, "GET", apiHost, v1)
		if r1.StatusCode != r2.StatusCode || string(b1) != string(b2) || r1.Header.Get("ETag") != r2.Header.Get("ETag") ||
			r1.Header.Get("Cache-Control") != r2.Header.Get("Cache-Control") {
			t.Errorf("%s vs %s: %d %s\n  vs %d %s", old, v1, r1.StatusCode, b1, r2.StatusCode, b2)
		}
		checkCORS(t, v1, r2)
		if r1.Header.Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("single-host %s has CORS", old)
		}
		// site host in two-host mode: 308 to the API host, query kept
		resp, _ := do(t, e.two, "GET", "www.nday.land", old)
		if resp.StatusCode != http.StatusPermanentRedirect || resp.Header.Get("Location") != testAPI+v1 ||
			resp.Header.Get("Cache-Control") != "public, max-age=3600" {
			t.Errorf("redirect %s: %d %q", old, resp.StatusCode, resp.Header.Get("Location"))
		}
	}
	if r, b := do(t, e.two, "GET", apiHost, "/v1/vulns"); r.StatusCode != 200 || r.Header.Get("Cache-Control") != "public, max-age=60" ||
		r.Header.Get("ETag") == "" || !strings.Contains(string(b), `"rows":[`) {
		t.Errorf("v1: %d %v", r.StatusCode, r.Header)
	}
	// single-host mode has no /v1
	if resp, _ := do(t, e.single, "GET", apiHost, "/v1/vulns"); resp.StatusCode != 404 {
		t.Errorf("single /v1/vulns %d", resp.StatusCode)
	}
	// neighbours unaffected: /api/vuln/{cve} and /v1/vuln/{cve} still the detail
	if r, b := do(t, e.two, "GET", apiHost, "/v1/vuln/CVE-2026-1003"); r.StatusCode != 200 || !strings.Contains(string(b), `"cve_id":"CVE-2026-1003"`) {
		t.Errorf("v1 vuln: %d", r.StatusCode)
	}
	if r, _ := do(t, e.two, "GET", apiHost, "/v1/vulns/x"); r.StatusCode != 404 {
		t.Errorf("/v1/vulns/x: %d", r.StatusCode)
	}
	if r, _ := do(t, e.two, "POST", apiHost, "/v1/vulns"); r.StatusCode != 405 {
		t.Errorf("POST: %d", r.StatusCode)
	}
}
