package web_test

import (
	"net/url"
	"strings"
	"testing"
)

// before / prev_cursor (additive): walking back through /api/hot and
// /api/vulns returns the pages walked forwards, the first page last, with
// prev_cursor null on it; a bad or combined before is a 400.
func TestBeforeAndPrevCursor(t *testing.T) {
	e := newEnv(t, nil)
	for _, base := range []string{"/api/hot?since=30d&limit=2", "/api/vulns?limit=2&include_rejected=1"} {
		var pages []string
		var prevs []any
		cur := ""
		for i := 0; i < 20; i++ {
			resp, b := e.get(t, base+cur)
			if resp.StatusCode != 200 {
				t.Fatalf("%s: %d %s", base+cur, resp.StatusCode, b)
			}
			m := decode(t, b)
			if _, ok := m["prev_cursor"]; !ok {
				t.Fatalf("%s: no prev_cursor field", base)
			}
			pages = append(pages, apiIDs(m))
			prevs = append(prevs, m["prev_cursor"])
			if m["next_cursor"] == nil {
				break
			}
			cur = "&cursor=" + url.QueryEscape(m["next_cursor"].(string))
		}
		if len(pages) < 3 || prevs[0] != nil {
			t.Fatalf("%s: precondition: %d pages, first prev %v", base, len(pages), prevs[0])
		}
		prev := prevs[len(prevs)-1]
		for i := len(pages) - 2; i >= 0; i-- {
			if prev == nil {
				t.Fatalf("%s: page %d has no prev_cursor", base, i+2)
			}
			resp, b := e.get(t, base+"&before="+url.QueryEscape(prev.(string)))
			if resp.StatusCode != 200 {
				t.Fatalf("%d %s", resp.StatusCode, b)
			}
			m := decode(t, b)
			if got := apiIDs(m); got != pages[i] {
				t.Errorf("%s back to page %d: %s, want %s", base, i+1, got, pages[i])
			}
			prev = m["prev_cursor"]
			if (i == 0) != (prev == nil) {
				t.Errorf("%s page %d: prev_cursor %v", base, i+1, prev)
			}
		}
	}
	_, b := e.get(t, "/api/hot?since=30d&limit=1")
	c := url.QueryEscape(decode(t, b)["next_cursor"].(string))
	_, b = e.get(t, "/api/vulns?limit=1")
	vc := url.QueryEscape(decode(t, b)["next_cursor"].(string))
	for _, p := range []string{"/api/hot?before=bogus", "/api/hot?cursor=" + c + "&before=" + c, "/api/vulns?before=bogus",
		"/api/vulns?before=", "/api/vulns?cursor=" + vc + "&before=" + vc} {
		resp, b := e.get(t, p)
		if resp.StatusCode != 400 || decode(t, b)["error"].(map[string]any)["param"] != "before" {
			t.Errorf("%s: %d %s", p, resp.StatusCode, b)
		}
	}
}

func apiIDs(m map[string]any) string {
	var ids []string
	for _, r := range m["rows"].([]any) {
		ids = append(ids, r.(map[string]any)["cve_id"].(string))
	}
	return strings.Join(ids, ",")
}
