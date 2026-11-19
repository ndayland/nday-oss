package ghrepo

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The scan query: only the year and the window vary.
func TestScanQuery(t *testing.T) {
	lo := time.Date(2026, 11, 13, 11, 0, 0, 0, time.UTC)
	hi := time.Date(2026, 11, 16, 11, 0, 0, 0, time.FixedZone("x", 3600)) // printed in UTC
	q, err := ScanQuery(2026, lo, hi)
	if err != nil || q != "CVE-2026 in:name fork:true created:2026-11-13T11:00:00Z..2026-11-16T10:00:00Z" {
		t.Errorf("%q %v", q, err)
	}
	for _, y := range []int{0, 1998, 10000, -2026} {
		if _, err := ScanQuery(y, lo, hi); err == nil {
			t.Errorf("year %d accepted", y)
		}
	}
}

// The targeted query: the CVE id is the only variable part and nothing but
// a well-formed id is accepted, so no qualifier, quote, operator or space
// can be injected.
func TestCVEQuery(t *testing.T) {
	q, err := CVEQuery("CVE-2024-3094")
	if err != nil || q != "CVE-2024-3094 in:name,description fork:true" {
		t.Errorf("%q %v", q, err)
	}
	for _, bad := range []string{"", "cve-2024-3094", "CVE-2024-309", "CVE-24-3094", "CVE-2024-3094 user:evil", "CVE-2024-3094 in:readme",
		`CVE-2024-3094"`, "CVE-2024-3094\n", "CVE-2024-3094 OR x", "CVE-2024-3094&sort=x", "CVE-2024-3094+repo:x",
		"CVE-2024-12345678901234567890", " CVE-2024-3094", "CVE-2024-3094 fork:only", "CVE-２０２４-3094"} {
		if q, err := CVEQuery(bad); err == nil {
			t.Errorf("%q accepted: %q", bad, q)
		}
	}
}

// The targeted query for a GHSA id: the canonical id is the only variable
// part; nothing else — another case, another alphabet, a qualifier, a quote,
// an operator, a space — is accepted. IDQuery picks the query by the id's form.
func TestGHSAQuery(t *testing.T) {
	q, err := GHSAQuery("GHSA-gpwc-27cw-rh9r")
	if err != nil || q != "GHSA-gpwc-27cw-rh9r in:name,description fork:true" {
		t.Errorf("%q %v", q, err)
	}
	for _, bad := range []string{"", "ghsa-gpwc-27cw-rh9r", "GHSA-GPWC-27CW-RH9R", "GHSA-gpwc-27cw", "GHSA-gpwc-27cw-rh9r-x", "GHSA-aaaa-bbbb-cccc",
		"GHSA-gpwc-27cw-rh9r user:evil", "GHSA-gpwc-27cw-rh9r in:readme", `GHSA-gpwc-27cw-rh9r"`, "GHSA-gpwc-27cw-rh9r\n", "GHSA-gpwc-27cw-rh9r OR x",
		"GHSA-gpwc-27cw-rh9r&sort=x", "GHSA-gpwc-27cw-rh9r+repo:x", " GHSA-gpwc-27cw-rh9r", "GHSA-gpwc-27cw-rh9r fork:only", "GHSA-gpwc 27cw-rh9r",
		"GHSA-gpwc-27cw-rh9\u0440", "CVE-2024-3094", "GHSA"} {
		if q, err := GHSAQuery(bad); err == nil {
			t.Errorf("%q accepted: %q", bad, q)
		}
	}
	for id, want := range map[string]string{"GHSA-gpwc-27cw-rh9r": "GHSA-gpwc-27cw-rh9r in:name,description fork:true",
		"CVE-2024-3094": "CVE-2024-3094 in:name,description fork:true"} {
		if q, err := IDQuery(id); err != nil || q != want {
			t.Errorf("IDQuery(%q) = %q %v", id, q, err)
		}
	}
	for _, bad := range []string{"GHSA-gpwc-27cw-rh9r user:evil", "CVE-2024-3094 user:evil", "GHSA-CVE-2024-3094", "x"} {
		if q, err := IDQuery(bad); err == nil {
			t.Errorf("IDQuery(%q) accepted: %q", bad, q)
		}
	}
	lo := time.Date(2026, 11, 13, 11, 0, 0, 0, time.UTC)
	if q := GHSAScanQuery(lo, lo.Add(time.Hour)); q != "GHSA in:name fork:true created:2026-11-13T11:00:00Z..2026-11-13T12:00:00Z" {
		t.Errorf("%q", q)
	}
	if p := SearchPath(q, "stars", 1); p != "/search/repositories?order=desc&page=1&per_page=100&q=GHSA-gpwc-27cw-rh9r+in%3Aname%2Cdescription+fork%3Atrue&sort=stars" {
		t.Errorf("%s", p)
	}
}

// SearchPath encodes q as one parameter: whatever q holds cannot add or
// change another parameter.
func TestSearchPath(t *testing.T) {
	q, _ := CVEQuery("CVE-2024-3094")
	if p := SearchPath(q, "stars", 1); p != "/search/repositories?order=desc&page=1&per_page=100&q=CVE-2024-3094+in%3Aname%2Cdescription+fork%3Atrue&sort=stars" {
		t.Errorf("%s", p)
	}
	sq, _ := ScanQuery(2025, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), time.Date(2026, 1, 2, 0, 0, 0, 0, time.UTC))
	if p := SearchPath(sq, "updated", 3); p != "/search/repositories?order=desc&page=3&per_page=100&q=CVE-2025+in%3Aname+fork%3Atrue+created%3A2026-01-01T00%3A00%3A00Z..2026-01-02T00%3A00%3A00Z&sort=updated" {
		t.Errorf("%s", p)
	}
	p := SearchPath("x&sort=evil&per_page=1000#frag", "", 2)
	u, err := url.Parse(APIBase + p)
	if err != nil {
		t.Fatal(err)
	}
	v := u.Query()
	if len(v) != 3 || v.Get("q") != "x&sort=evil&per_page=1000#frag" || v.Get("per_page") != "100" || v.Get("page") != "2" || u.Fragment != "" {
		t.Errorf("%s -> %v", p, v)
	}
}

func searchItem(id int, full, desc string, fork bool) string {
	return fmt.Sprintf(`{"id": %d, "full_name": %q, "private": false, "visibility": "public", "owner": {"login": %q, "type": "User"},
        "description": %q, "stargazers_count": 3, "forks_count": 0, "language": null, "topics": [], "fork": %t, "archived": false,
        "created_at": "2026-11-15T12:00:00Z", "pushed_at": "2026-11-15T13:00:00Z", "score": 1.0}`, id, full, strings.Split(full, "/")[0], desc, fork)
}

func TestDecodeSearch(t *testing.T) {
	body := `{"total_count": 108, "incomplete_results": false, "items": [` + searchItem(1, "a/CVE-2026-1111-poc", "x", false) + `,
        {"id": "nope"}, null, 7, ` + searchItem(2, "b/../x", "", false) + `, ` + searchItem(3, "c/tool", "PoC for CVE-2025-2222", true) + `]}`
	p, err := DecodeSearch([]byte(body))
	if err != nil || p.Total != 108 || p.Incomplete || len(p.Repos) != 2 || p.Bad != 4 {
		t.Fatalf("%+v %v", p, err)
	}
	if p.Repos[0].FullName != "a/CVE-2026-1111-poc" || !p.Repos[0].Public || p.Repos[1].Fork != true ||
		fmt.Sprint(p.Repos[1].Associations()) != "map[description:[CVE-2025-2222]]" {
		t.Errorf("%+v %+v", p.Repos[0], p.Repos[1])
	}
	// clamps
	if p, err := DecodeSearch([]byte(`{"total_count": -5, "incomplete_results": true, "items": []}`)); err != nil || p.Total != 0 || !p.Incomplete {
		t.Errorf("%+v %v", p, err)
	}
	if p, err := DecodeSearch([]byte(`{"total_count": 99999999999999, "incomplete_results": false, "items": []}`)); err != nil || p.Total != 1<<31-1 {
		t.Errorf("%+v %v", p, err)
	}
	many := make([]string, SearchPerPage+1)
	for i := range many {
		many[i] = searchItem(i+1, fmt.Sprintf("o/CVE-2026-%d", 1000+i), "", false)
	}
	for name, b := range map[string]string{
		"not json":         `<html>`,
		"array":            `[]`,
		"no total":         `{"incomplete_results": false, "items": []}`,
		"no incomplete":    `{"total_count": 1, "items": []}`,
		"no items":         `{"total_count": 1, "incomplete_results": false}`,
		"items null":       `{"total_count": 1, "incomplete_results": false, "items": null}`,
		"items object":     `{"total_count": 1, "incomplete_results": false, "items": {}}`,
		"total string":     `{"total_count": "1", "incomplete_results": false, "items": []}`,
		"total float":      `{"total_count": 1.5, "incomplete_results": false, "items": []}`,
		"incomplete str":   `{"total_count": 1, "incomplete_results": "no", "items": []}`,
		"too many items":   `{"total_count": 101, "incomplete_results": false, "items": [` + strings.Join(many, ",") + `]}`,
		"truncated":        `{"total_count": 1, "incomplete_results": false, "items": [` + searchItem(1, "a/b", "", false),
		"deeply nested":    `{"total_count": 1, "incomplete_results": false, "items": [` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `]}`,
		"trailing garbage": `{"total_count": 1, "incomplete_results": false, "items": []} x`,
	} {
		if p, err := DecodeSearch([]byte(b)); err == nil {
			t.Errorf("%s: accepted %+v", name, p)
		}
	}
}

// Search reads up to MaxSearchBody (a page larger than MaxBody is fine;
// a larger one is TooBig); the rate-limit headers are read.
func TestSearchBodyCap(t *testing.T) {
	big := strings.Repeat("x", MaxBody+10)
	huge := strings.Repeat("x", MaxSearchBody+1)
	a := newAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Remaining", "7")
		w.Header().Set("X-RateLimit-Resource", "search")
		if r.URL.Query().Get("page") == "2" {
			w.Write([]byte(huge))
			return
		}
		w.Write([]byte(big))
	})
	c := a.client("")
	ctx := context.Background()
	r, err := c.Search(ctx, SearchPath("x", "", 1))
	if err != nil || r.TooBig || len(r.Body) != len(big) || r.Remaining != 7 || r.Resource != "search" {
		t.Fatalf("%v %v", r, err)
	}
	if r, err := c.Search(ctx, SearchPath("x", "", 2)); err != nil || !r.TooBig || r.Body != nil {
		t.Errorf("huge: %v", err)
	}
	if r, err := c.Get(ctx, "/search/repositories?q=x", ""); err != nil || !r.TooBig {
		t.Errorf("Get keeps MaxBody: %v", err)
	}
	req := a.requests()[0]
	if req.Method != http.MethodGet || req.URL.Path != "/search/repositories" || req.Header.Get("Authorization") != "" {
		t.Errorf("%s %s %v", req.Method, req.URL, req.Header)
	}
}

// The spacing keeps every 60 seconds under GitHub's search limits (10 a
// minute without a token, 30 with one), and a run's cap at the default
// fits in the hourly timer with room to spare.
func TestSearchBudget(t *testing.T) {
	if n := int(time.Minute/SearchSpacingAnon) + 1; n > 10 {
		t.Errorf("anonymous: %d requests a minute", n)
	}
	if n := int(time.Minute/SearchSpacingAuth) + 1; n > 30 {
		t.Errorf("authenticated: %d requests a minute", n)
	}
	if d := time.Duration(MaxMaxRequests-1) * SearchSpacingAnon; d > 15*time.Minute {
		t.Errorf("a run of %d requests takes %v", MaxMaxRequests, d)
	}
	if DefaultScanPages+DefaultHotCVEs > DefaultMaxRequests {
		t.Error("default shares exceed the default cap")
	}
}

// skippedForkSQL spells MinForkStars as a literal (a const string can't
// call strconv): they must agree.
func TestSkippedForkSQLMatchesConst(t *testing.T) {
	if !strings.Contains(skippedForkSQL, fmt.Sprintf("r.stars < %d,", MinForkStars)) || SkippedForkSQL != skippedForkSQL {
		t.Errorf("skippedForkSQL %q, MinForkStars %d", skippedForkSQL, MinForkStars)
	}
}
