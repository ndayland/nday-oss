package web_test

import (
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site/sitetest"
)

// cvssEnv is newEnv plus CVE-2023-00NN with these displayed scores ("" =
// none), titled "cvsstest NN".
func cvssEnv(t *testing.T) *env {
	e := newEnv(t, nil)
	s := sitetest.Seeder{T: t, Conn: e.db.Conn}
	for i, c := range []struct{ n, detail, typ, src string }{
		{"01", `{"cvss": {"base_score": 9.8}}`, "disclosed", "cvelist"},
		{"02", `{"cvss": {"base_score": 7.2}}`, "disclosed", "cvelist"},
		{"03", `{"cvss": {"cvss_v3": {"score": 5.0, "vector_string": "CVSS:3.1/AV:N"}}}`, "patch_released", "ghsa"},
		{"04", `{}`, "disclosed", "cvelist"},
		{"05", `{"cvss": {"base_score": 0.5}}`, "disclosed", "cvelist"},
	} {
		id := "CVE-2023-00" + c.n
		s.Vuln(id, sitetest.P("cvsstest "+c.n))
		at := sitetest.Day(2023, 1, 1).Add(time.Duration(i) * time.Hour)
		s.Event(sitetest.Ev{CVE: id, Type: c.typ, Source: c.src, Occurred: &at, Detail: c.detail, Key: id})
	}
	s.Refresh()
	return e
}

// pageScore is the score /api/vuln shows for id (nil = none).
func pageScore(t *testing.T, e *env, id string) *float64 {
	t.Helper()
	_, b := e.get(t, "/api/vuln/"+id)
	c, _ := decode(t, b)["cvss"].(map[string]any)
	if c == nil {
		return nil
	}
	f, ok := c["score"].(float64)
	if !ok {
		return nil
	}
	return &f
}

func listIDs(t *testing.T, e *env, path string) []string {
	t.Helper()
	var out []string
	cur := ""
	for i := 0; i < 50; i++ {
		resp, b := e.get(t, path+cur)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, b)
		}
		m := decode(t, b)
		for _, r := range m["rows"].([]any) {
			out = append(out, r.(map[string]any)["cve_id"].(string))
		}
		if m["next_cursor"] == nil {
			return out
		}
		cur = "&cursor=" + url.QueryEscape(m["next_cursor"].(string))
	}
	t.Fatalf("%s: no end", path)
	return nil
}

// /api/vulns with cvss_min / cvss_max: exactly the rows whose /api/vuln
// score is in range, in catalogue order, through every page.
func TestVulnsCVSS(t *testing.T) {
	e := cvssEnv(t)
	all := listIDs(t, e, "/api/vulns?include_rejected=true&limit=200")
	scores := map[string]*float64{}
	for _, id := range all {
		scores[id] = pageScore(t, e, id)
	}
	n := 0
	for _, s := range scores {
		if s != nil {
			n++
		}
	}
	if n < 5 {
		t.Fatalf("only %d scored rows", n)
	}
	for _, c := range []struct {
		q      string
		lo, hi float64
	}{
		{"cvss_min=9", 9, 10},
		{"cvss_min=7&cvss_max=8.9", 7, 8.9},
		{"cvss_min=9.8&cvss_max=9.8", 9.8, 9.8},
		{"cvss_max=3.9", 0, 3.9},
		{"cvss_min=0", 0, 10},
		{"cvss_min=5.0&cvss_max=10.0", 5, 10},
	} {
		var want []string
		for _, id := range all {
			if s := scores[id]; s != nil && *s >= c.lo-1e-9 && *s <= c.hi+1e-9 {
				want = append(want, id)
			}
		}
		if len(want) == 0 {
			t.Fatalf("%s: no expected row; the case proves nothing", c.q)
		}
		got := listIDs(t, e, "/api/vulns?include_rejected=true&limit=1&"+c.q)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("%s:\n got %v\nwant %v", c.q, got, want)
		}
	}
	// the bounds are echoed as numbers (null without a bound), canonically
	_, b := e.get(t, "/api/vulns?cvss_min=9.0&year=2023")
	m := decode(t, b)
	if m["cvss_min"] != 9.0 || m["cvss_max"] != nil || m["year"].(float64) != 2023 || len(m["rows"].([]any)) != 1 {
		t.Errorf("%s", b)
	}
	_, b = e.get(t, "/api/vulns")
	if m := decode(t, b); m["cvss_min"] != nil || m["cvss_max"] != nil {
		t.Errorf("unfiltered bounds: %s", b)
	}
	if _, ok := decode(t, b)["cvss_min"]; !ok {
		t.Error("cvss_min missing (null expected)")
	}
}

func TestVulnsCVSSBadRequests(t *testing.T) {
	e := newEnv(t, nil)
	for path, param := range map[string]string{
		"/api/vulns?cvss_min=":                            "cvss_min",
		"/api/vulns?cvss_max=":                            "cvss_max",
		"/api/vulns?cvss_min=-1":                          "cvss_min",
		"/api/vulns?cvss_min=10.1":                        "cvss_min",
		"/api/vulns?cvss_max=11":                          "cvss_max",
		"/api/vulns?cvss_min=NaN":                         "cvss_min",
		"/api/vulns?cvss_min=1e1":                         "cvss_min",
		"/api/vulns?cvss_min=9,8":                         "cvss_min",
		"/api/vulns?cvss_min=9.85":                        "cvss_min",
		"/api/vulns?cvss_min=+9":                          "cvss_min",
		"/api/vulns?cvss_min=%209":                        "cvss_min",
		"/api/vulns?cvss_min=" + strings.Repeat("9", 300): "cvss_min",
		"/api/vulns?cvss_min=9&cvss_max=7":                "cvss_max",
		"/api/vulns?cvss_min=7&cvss_min=8":                "cvss_min",
		"/api/vulns?cvss=9":                               "cvss",
		"/api/search?q=abc&cvss_min=x":                    "cvss_min",
		"/api/search?q=abc&cvss_max=":                     "cvss_max",
		"/api/search?q=abc&cvss_min=8&cvss_max=2":         "cvss_max",
		"/api/search?q=abc&cvss_max=1&cvss_max=2":         "cvss_max",
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
}

func TestSearchCVSS(t *testing.T) {
	e := cvssEnv(t)
	ids := func(path string) (string, map[string]any) {
		resp, b := e.get(t, path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d %s", path, resp.StatusCode, b)
		}
		m := decode(t, b)
		var out []string
		for _, r := range m["rows"].([]any) {
			out = append(out, strings.TrimPrefix(r.(map[string]any)["cve_id"].(string), "CVE-2023-00"))
		}
		sort.Strings(out)
		return strings.Join(out, ","), m
	}
	for path, want := range map[string]string{
		"/api/search?q=cvsstest":                              "01,02,03,04,05",
		"/api/search?q=cvsstest&cvss_min=7":                   "01,02",
		"/api/search?q=cvsstest&cvss_min=5&cvss_max=5":        "03",
		"/api/search?q=cvsstest&cvss_max=3.9":                 "05",
		"/api/search?q=CVE-2023-00&cvss_min=0.1&cvss_max=6.9": "03,05",
	} {
		if got, _ := ids(path); got != want {
			t.Errorf("%s: %s, want %s", path, got, want)
		}
	}
	got, m := ids("/api/search?q=cvsstest&cvss_min=7")
	if m["cvss_min"] != 7.0 || m["cvss_max"] != nil || m["kind"] != "text" || got == "" {
		t.Errorf("%v", m)
	}
	// a blank query with only a score filter searches nothing
	if _, m := ids("/api/search?q=&cvss_min=9"); m["kind"] != "empty" {
		t.Errorf("blank: %v", m)
	}
	// the filter is part of the cache key
	a, _ := ids("/api/search?q=cvsstest&cvss_min=9")
	b, _ := ids("/api/search?q=cvsstest&cvss_min=" + strconv.Itoa(0))
	if a == b {
		t.Errorf("cache: %s %s", a, b)
	}
}
