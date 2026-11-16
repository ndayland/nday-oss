package xposts_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/collector"
	"nday.land/nday/internal/collector/xposts"
	"nday.land/nday/internal/model"
	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/registry"
	"nday.land/nday/internal/testutil"
	"nday.land/nday/internal/xconfig"
)

// NOW is the test clock; the fixture posts are from the day before.
var NOW = time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC)

const (
	tdir   = "internal/collector/xposts/testdata/"
	token  = "test-token-not-real"
	newest = "2120833985541046272" // highest id in the fixtures
)

var accounts = []xconfig.Account{
	{UserID: "1002", Handle: "bob_sec", Enabled: true},
	{UserID: "1001", Handle: "alice_sec", Enabled: true},
}

func env(m map[string]string) collector.Env {
	return func(k string) (string, bool) { v, ok := m[k]; return v, ok }
}

type logBuf struct{ strings.Builder }

func (l *logBuf) Write(p []byte) (int, error) { return l.Builder.Write(p) }

// step is one canned response.
type step struct {
	status int
	file   string
	hdr    http.Header
	err    error
}

func script(t *testing.T, steps ...step) *testutil.FakeTransport {
	t.Helper()
	i := 0
	return &testutil.FakeTransport{Handler: func(*http.Request) (int, http.Header, []byte, error) {
		if i >= len(steps) {
			t.Errorf("unexpected request %d", i+1)
			return 500, nil, nil, nil
		}
		s := steps[i]
		i++
		if s.err != nil {
			return 0, nil, nil, s.err
		}
		var body []byte
		if s.file != "" {
			body = testutil.ReadFile(t, tdir+s.file)
		}
		return s.status, s.hdr, body, nil
	}}
}

func newC(t *testing.T, ft *testutil.FakeTransport, s *xconfig.Settings, accts []xconfig.Account, tok string, log *logBuf) *xposts.Collector {
	t.Helper()
	if log == nil {
		log = &logBuf{}
	}
	c, err := xposts.New(xposts.Options{Transport: ft, Env: env(map[string]string{xposts.TokenEnv: tok}),
		Clock: func() time.Time { return NOW }, Sleep: func(context.Context, time.Duration) error { return nil },
		Logger: slog.New(slog.NewTextHandler(log, nil)), Accounts: accts, Settings: s})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func query(t *testing.T, raw string) url.Values {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme+"://"+u.Host+u.Path != xposts.SearchURL {
		t.Fatalf("endpoint %s", raw)
	}
	return u.Query()
}

func lastRun(t *testing.T, cur any) *pyjson.Object {
	t.Helper()
	return cur.(*pyjson.Object).Get("last_run").(*pyjson.Object)
}

func sinceID(cur any) any { return cur.(*pyjson.Object).Get("since_id") }

func TestRegistered(t *testing.T) {
	f, ok := registry.Collectors[xposts.Name]
	if !ok {
		t.Fatal("xposts not registered")
	}
	c, err := f(collector.Deps{Env: env(nil)})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.(collector.Preparer); !ok || c.Name() != "xposts" {
		t.Fatalf("%T %s", c, c.Name())
	}
}

func TestExtractCVEs(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want []string
	}{
		{"cve-2026-1111 and CVE-2026-1111, CVE-2025-123456", []string{"CVE-2026-1111", "CVE-2025-123456"}},
		{"Cve-2024-0001.", []string{"CVE-2024-0001"}},
		{"在野利用CVE-2026-1111，见公告", []string{"CVE-2026-1111"}},
		{"#CVE-2026-1234 (CVE-2026-5678)", []string{"CVE-2026-1234", "CVE-2026-5678"}},
		{"CVE-2026-123 CVE-20261111 XCVE-2026-1111 CVE-2026-1111abc CVE_2026_1111", nil},
		{"no ids", nil},
	} {
		if got := xposts.ExtractCVEs(tc.in); !slices.Equal(got, tc.want) {
			t.Errorf("%q: %v want %v", tc.in, got, tc.want)
		}
	}
}

func TestBuildQueries(t *testing.T) {
	q, err := xposts.BuildQueries(accounts, 512)
	if err != nil || len(q) != 1 || q[0] != "(from:bob_sec OR from:alice_sec) CVE -is:retweet" {
		t.Fatalf("%q %v", q, err)
	}
	var many []xconfig.Account
	for i := 0; i < 60; i++ {
		many = append(many, xconfig.Account{UserID: "1", Handle: strings.Repeat("a", 14) + string(rune('a'+i%26))})
	}
	for _, maxLen := range []int{64, 100, 512, 4096} {
		qs, err := xposts.BuildQueries(many, maxLen)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for i, q := range qs {
			if len(q) > maxLen {
				t.Errorf("max %d: query %d has %d chars", maxLen, i, len(q))
			}
			n += strings.Count(q, "from:")
			// the next account would not have fit
			if i+1 < len(qs) && len(q)+len(" OR from:")+15 <= maxLen {
				t.Errorf("max %d: query %d not packed (%d chars)", maxLen, i, len(q))
			}
		}
		if n != len(many) {
			t.Errorf("max %d: %d accounts in queries", maxLen, n)
		}
	}
	if _, err := xposts.BuildQueries(accounts[:1], 20); err == nil {
		t.Error("too short max length accepted")
	}
}

// First run: start_time, pagination, author filtering (posts without a CVE
// id are kept since migration 0015), cursor.
func TestFetchFirstRun(t *testing.T) {
	ft := script(t, step{status: 200, file: "search_page1.json",
		hdr: http.Header{"X-Rate-Limit-Limit": {"450"}, "X-Rate-Limit-Remaining": {"449"}, "X-Rate-Limit-Reset": {"1794573600"}}},
		step{status: 200, file: "search_page2.json"})
	c := newC(t, ft, nil, accounts, token, nil)
	res, err := c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name})
	if err != nil {
		t.Fatal(err)
	}
	if len(ft.Requests) != 2 {
		t.Fatalf("%d requests", len(ft.Requests))
	}
	q1, q2 := query(t, ft.Requests[0].URL), query(t, ft.Requests[1].URL)
	if q1.Get("query") != "(from:alice_sec OR from:bob_sec) CVE -is:retweet" || q1.Get("start_time") != "2026-11-06T13:00:00Z" ||
		q1.Has("since_id") || q1.Get("max_results") != "100" ||
		q1.Get("expansions") != "author_id,referenced_tweets.id,referenced_tweets.id.author_id,entities.mentions.username" ||
		q1.Get("tweet.fields") != "author_id,created_at,lang,entities,note_tweet,referenced_tweets" || q1.Get("user.fields") != "username" || q1.Has("pagination_token") {
		t.Errorf("request 1: %v", q1)
	}
	if q2.Get("pagination_token") != "b26v89c19zqg8o3fpzbkk7bmjckcbfhy9cmhn8ofhdpml" || q2.Get("query") != q1.Get("query") ||
		q2.Get("start_time") != q1.Get("start_time") {
		t.Errorf("request 2: %v", q2)
	}
	for _, r := range ft.Requests {
		if r.Header.Get("Authorization") != "Bearer "+token || !strings.HasPrefix(r.Header.Get("User-Agent"), "nday-collector/") {
			t.Errorf("headers %v", r.Header)
		}
	}
	var keys []string
	for _, r := range res.Records {
		keys = append(keys, r.SourceKey)
	}
	if !slices.Equal(keys, []string{"2120788687057846272", "2120818886046646272", "2120833985541046272"}) {
		t.Errorf("records %v", keys)
	}
	if sinceID(res.Cursor) != newest {
		t.Errorf("since_id %v", sinceID(res.Cursor))
	}
	lr := lastRun(t, res.Cursor)
	for k, want := range map[string]any{"mode": "start_time", "posts": 4, "kept": 2, "kept_no_cve": 1,
		"dropped_author": 1, "dropped_no_cve": nil, "batches": 1, "batches_done": 1, "http_requests": 2, "stopped": nil} {
		if got := lr.Get(k); pyjson.Repr(got) != pyjson.Repr(want) {
			t.Errorf("last_run.%s = %s want %s", k, pyjson.Repr(got), pyjson.Repr(want))
		}
	}
	if rl := lr.Get("rate_limit").(*pyjson.Object); rl.Get("remaining") != pyjson.Int("449") {
		t.Errorf("rate_limit %s", pyjson.Repr(rl))
	}
}

// Incremental run: since_id instead of start_time; nothing new keeps it.
func TestFetchIncremental(t *testing.T) {
	ft := script(t, step{status: 200, file: "search_empty.json"})
	c := newC(t, ft, nil, accounts, token, nil)
	cur := pyjson.NewObject()
	cur.Set("since_id", newest)
	ok := NOW.Add(-time.Hour)
	res, err := c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name, Cursor: cur, LastSuccessAt: &ok})
	if err != nil {
		t.Fatal(err)
	}
	q := query(t, ft.Requests[0].URL)
	if q.Get("since_id") != newest || q.Has("start_time") {
		t.Errorf("%v", q)
	}
	if sinceID(res.Cursor) != newest || len(res.Records) != 0 {
		t.Errorf("cursor %s", pyjson.Repr(res.Cursor))
	}

	// a since_id older than the 7-day window falls back to start_time
	ft = script(t, step{status: 200, file: "search_empty.json"})
	c = newC(t, ft, &xconfig.Settings{Enabled: true, MaxPosts: 500, MaxRequests: 20, BootstrapDays: 2, MaxQueryLength: 512}, accounts, token, nil)
	cur.Set("since_id", "2116681624581046272") // 2026-11-01
	res, err = c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name, Cursor: cur, LastSuccessAt: &ok})
	if err != nil {
		t.Fatal(err)
	}
	q = query(t, ft.Requests[0].URL)
	if q.Has("since_id") || q.Get("start_time") != "2026-11-11T12:00:00Z" {
		t.Errorf("%v", q)
	}
	if sinceID(res.Cursor) != "2116681624581046272" {
		t.Errorf("cursor %s", pyjson.Repr(res.Cursor))
	}
}

// Several batches: one query per batch, each paginated separately.
func TestFetchBatches(t *testing.T) {
	ft := script(t, step{status: 200, file: "search_page1.json"}, step{status: 200, file: "search_page2.json"},
		step{status: 200, file: "search_empty.json"})
	s := xconfig.Defaults
	s.MaxQueryLength = 40
	c := newC(t, ft, &s, accounts, token, nil)
	res, err := c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name})
	if err != nil {
		t.Fatal(err)
	}
	if len(ft.Requests) != 3 {
		t.Fatalf("%d requests", len(ft.Requests))
	}
	got := []string{query(t, ft.Requests[0].URL).Get("query"), query(t, ft.Requests[1].URL).Get("query"), query(t, ft.Requests[2].URL).Get("query")}
	want := []string{"(from:alice_sec) CVE -is:retweet", "(from:alice_sec) CVE -is:retweet", "(from:bob_sec) CVE -is:retweet"}
	if !slices.Equal(got, want) {
		t.Errorf("%q", got)
	}
	if lr := lastRun(t, res.Cursor); lr.Get("batches") != 2 || lr.Get("batches_done") != 2 || sinceID(res.Cursor) != newest {
		t.Errorf("%s", pyjson.Repr(res.Cursor))
	}
}

// Caps and 429 stop cleanly, keep the posts, and do not advance the cursor.
func TestFetchStops(t *testing.T) {
	old := pyjson.NewObject()
	old.Set("since_id", "2120700000000000000")
	ok := NOW.Add(-time.Hour)
	st := model.CollectorState{Source: xposts.Name, Cursor: old, LastSuccessAt: &ok}
	for _, tc := range []struct {
		name     string
		settings xconfig.Settings
		steps    []step
		reason   string
		requests int
		records  int
	}{
		{"request cap", xconfig.Settings{Enabled: true, MaxPosts: 500, MaxRequests: 1, BootstrapDays: 7, MaxQueryLength: 512},
			[]step{{status: 200, file: "search_page1.json"}}, "request_cap", 1, 2},
		{"post cap", xconfig.Settings{Enabled: true, MaxPosts: 11, MaxRequests: 20, BootstrapDays: 7, MaxQueryLength: 512},
			[]step{{status: 200, file: "search_page1.json"}}, "post_cap", 1, 2},
		{"429", xconfig.Defaults, []step{{status: 200, file: "search_page1.json"},
			{status: 429, file: "error_429.json", hdr: http.Header{"X-Rate-Limit-Remaining": {"0"}, "X-Rate-Limit-Reset": {"1794573600"}}}},
			"rate_limited", 2, 2},
		{"5xx", xconfig.Defaults, []step{{status: 503}, {status: 503}, {status: 503}}, "server_error", 3, 0},
		{"transport", xconfig.Defaults, []step{{err: errors.New("connection reset")}, {err: errors.New("connection reset")},
			{err: errors.New("connection reset")}}, "transport_error", 3, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ft := script(t, tc.steps...)
			log := &logBuf{}
			s := tc.settings
			c := newC(t, ft, &s, accounts, token, log)
			res, err := c.Fetch(context.Background(), st)
			if err != nil {
				t.Fatal(err)
			}
			if len(ft.Requests) != tc.requests || len(res.Records) != tc.records {
				t.Errorf("requests %d records %d", len(ft.Requests), len(res.Records))
			}
			if sinceID(res.Cursor) != "2120700000000000000" {
				t.Errorf("cursor advanced: %s", pyjson.Repr(res.Cursor))
			}
			if lr := lastRun(t, res.Cursor); lr.Get("stopped") != tc.reason {
				t.Errorf("stopped %v", lr.Get("stopped"))
			}
			if tc.name == "post cap" {
				if q := query(t, ft.Requests[0].URL); q.Get("max_results") != "11" {
					t.Errorf("max_results %s", q.Get("max_results"))
				}
			}
			if !strings.Contains(log.String(), "stopped early") || strings.Contains(log.String(), token) {
				t.Errorf("log %q", log.String())
			}
		})
	}
}

// Other 4xx (bad query, bad token) fail the run without leaking the token.
func TestFetch4xxFails(t *testing.T) {
	ft := script(t, step{status: 400, file: "error_400.json"})
	log := &logBuf{}
	c := newC(t, ft, nil, accounts, token, log)
	_, err := c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name})
	if err == nil || !strings.Contains(err.Error(), "HTTP 400 (Invalid Request: One or more parameters") || strings.Contains(err.Error(), token) {
		t.Fatalf("%v", err)
	}
	if strings.Contains(log.String(), token) {
		t.Error("token logged")
	}
}

// Missing configuration: no request, no records, cursor kept, reason recorded.
func TestFetchSkipped(t *testing.T) {
	off := xconfig.Defaults
	off.Enabled = false
	old := pyjson.NewObject()
	old.Set("since_id", newest)
	for _, tc := range []struct {
		name, tok, reason string
		accts             []xconfig.Account
		s                 *xconfig.Settings
	}{
		{"no token", "  ", "no_token", accounts, nil},
		{"no accounts", token, "no_accounts", nil, nil},
		{"disabled", token, "disabled", accounts, &off},
	} {
		ft := script(t)
		c := newC(t, ft, tc.s, tc.accts, tc.tok, nil)
		res, err := c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name, Cursor: old})
		if err != nil {
			t.Fatal(err)
		}
		if len(ft.Requests) != 0 || len(res.Records) != 0 || sinceID(res.Cursor) != newest || lastRun(t, res.Cursor).Get("skipped") != tc.reason {
			t.Errorf("%s: %s", tc.name, pyjson.Repr(res.Cursor))
		}
	}
	if _, err := xposts.New(xposts.Options{Env: env(map[string]string{xposts.TokenEnv: "tok\nen"})}); err == nil ||
		strings.Contains(err.Error(), "tok") && !strings.Contains(err.Error(), xposts.TokenEnv) {
		t.Errorf("bad token accepted: %v", err)
	}
}

// Normalize golden: one social_post event per (post, CVE).
// NDAY_UPDATE_GOLDEN=1 rewrites testdata/golden/normalize.golden.json.
func TestNormalizeGolden(t *testing.T) {
	ft := script(t, step{status: 200, file: "search_page1.json"}, step{status: 200, file: "search_page2.json"})
	c := newC(t, ft, nil, accounts, token, nil)
	res, err := c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name})
	if err != nil {
		t.Fatal(err)
	}
	out := pyjson.NewObject()
	for _, r := range res.Records {
		n, err := c.Normalize(r)
		if err != nil {
			t.Fatal(err)
		}
		if err := n.Validate(); err != nil {
			t.Fatal(err)
		}
		out.Set(r.SourceKey, testutil.NormalizedValue(n))
	}
	got, err := pyjson.Encode(out, pyjson.Options{Indent: 2, SortKeys: true})
	if err != nil {
		t.Fatal(err)
	}
	got += "\n"
	path := filepath.Join(testutil.RepoRoot(), tdir, "golden/normalize.golden.json")
	if os.Getenv("NDAY_UPDATE_GOLDEN") == "1" {
		if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%v (NDAY_UPDATE_GOLDEN=1 writes it)", err)
	}
	if string(want) != got {
		t.Errorf("normalize output differs from %s (NDAY_UPDATE_GOLDEN=1 rewrites it):\n%s", path, got)
	}
}

func TestNormalizeErrors(t *testing.T) {
	c := newC(t, script(t), nil, nil, "", nil)
	mk := func(s string) model.RawRecord {
		v, err := pyjson.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return model.RawRecord{Source: xposts.Name, SourceKey: "5", Payload: v}
	}
	for _, s := range []string{
		`[]`,
		`{"post": 1}`,
		`{"post": {"id": "6", "author_id": "1", "created_at": "2026-11-12T00:00:00Z", "text": "CVE-2026-1111"}}`,
		`{"post": {"id": "5", "author_id": "x", "created_at": "2026-11-12T00:00:00Z", "text": "CVE-2026-1111"}}`,
		`{"post": {"id": "5", "author_id": "1", "created_at": "yesterday", "text": "CVE-2026-1111"}}`,
		`{"post": {"id": "5", "author_id": "1", "created_at": "2026-11-12T00:00:00Z", "text": null}}`,
	} {
		_, err := c.Normalize(mk(s))
		var ne *collector.NormalizeError
		if !errors.As(err, &ne) {
			t.Errorf("%s: %v", s, err)
		}
	}
	// no author object: i/web link, null handle
	n, err := c.Normalize(mk(`{"post": {"id": "5", "author_id": "1", "created_at": "2026-11-12T00:00:00Z", "text": "CVE-2026-1111"}, "author": null}`))
	if err != nil || len(n.Events) != 1 || *n.Events[0].URL != "https://x.com/i/web/status/5" || n.Events[0].Detail["author_handle"] != nil {
		t.Errorf("%v %+v", err, n)
	}
	// no CVE: no event, no vuln, one PostNoCVE (null handle and lang here)
	n, err = c.Normalize(mk(`{"post": {"id": "5", "author_id": "1", "created_at": "2026-11-12T00:00:00Z", "text": "nothing"}, "author": null}`))
	if err != nil || len(n.Events) != 0 || len(n.Vulns) != 0 || len(n.PostsNoCVE) != 1 {
		t.Fatalf("%v %+v", err, n)
	}
	if p := n.PostsNoCVE[0]; p.PostID != "5" || p.AuthorID != "1" || p.AuthorHandle != nil || p.Lang != nil || p.Text != "nothing" ||
		!p.PostedAt.Equal(time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)) || p.URL != "https://x.com/i/web/status/5" {
		t.Errorf("%+v", p)
	}
	if err := n.Validate(); err != nil {
		t.Error(err)
	}
	// a post with a CVE id never also gives a PostNoCVE
	n, err = c.Normalize(mk(`{"post": {"id": "5", "author_id": "1", "created_at": "2026-11-12T00:00:00Z", "text": "CVE-2026-1111"}, "author": null}`))
	if err != nil || len(n.PostsNoCVE) != 0 {
		t.Errorf("%v %+v", err, n)
	}
}

// Posts without a CVE id: kept (raw record) when the author is allowlisted,
// dropped otherwise; counted as kept_no_cve; same requests and query.
func TestFetchKeepsNoCVE(t *testing.T) {
	ft := script(t, step{status: 200, file: "search_nocve.json"})
	c := newC(t, ft, nil, accounts, token, nil)
	res, err := c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name})
	if err != nil {
		t.Fatal(err)
	}
	if len(ft.Requests) != 1 || query(t, ft.Requests[0].URL).Get("query") != "(from:alice_sec OR from:bob_sec) CVE -is:retweet" {
		t.Fatalf("%d requests", len(ft.Requests))
	}
	var keys []string
	for _, r := range res.Records {
		keys = append(keys, r.SourceKey)
	}
	// 2120920000000000000 (author 9999, no CVE id) is dropped
	if !slices.Equal(keys, []string{"2120900000000000000", "2120910000000000000", "2120930000000000000"}) {
		t.Errorf("records %v", keys)
	}
	lr := lastRun(t, res.Cursor)
	for k, want := range map[string]any{"posts": 4, "kept": 1, "kept_no_cve": 2, "dropped_author": 1, "http_requests": 1} {
		if got := lr.Get(k); pyjson.Repr(got) != pyjson.Repr(want) {
			t.Errorf("last_run.%s = %s want %s", k, pyjson.Repr(got), pyjson.Repr(want))
		}
	}
	if sinceID(res.Cursor) != "2120930000000000000" {
		t.Errorf("since_id %v", sinceID(res.Cursor))
	}
	// the raw payload has the same shape as for posts with a CVE id
	for _, r := range res.Records {
		p := r.Payload.(*pyjson.Object)
		if !slices.Equal(p.Keys(), []string{"post", "author"}) {
			t.Errorf("%s: payload keys %v", r.SourceKey, p.Keys())
		}
	}
}

// New-shape responses (entities, note_tweet, referenced posts): the raw
// payload carries the referenced posts and their authors; Normalize reads CVE
// ids from note_tweet.text only (never from referenced posts) and emits the
// links and the referred accounts of every stored post.
func TestNormalizeLinksCandidates(t *testing.T) {
	ft := script(t, step{status: 200, file: "search_entities.json"})
	c := newC(t, ft, nil, accounts, token, nil)
	res, err := c.Fetch(context.Background(), model.CollectorState{Source: xposts.Name})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || res.Records[0].SourceKey != "2121000000000000001" || res.Records[1].SourceKey != "2121000000000000002" {
		t.Fatalf("%+v", res.Records)
	}
	if lr := lastRun(t, res.Cursor); lr.Get("kept") != 1 || lr.Get("kept_no_cve") != 1 || lr.Get("dropped_author") != 1 {
		t.Errorf("last_run %s", pyjson.Repr(lr))
	}
	p1 := res.Records[0].Payload.(*pyjson.Object)
	if !slices.Equal(p1.Keys(), []string{"post", "author", "referenced"}) {
		t.Fatalf("payload keys %v", p1.Keys())
	}
	ref := p1.Get("referenced").([]any)
	if len(ref) != 1 {
		t.Fatalf("referenced %s", pyjson.Repr(ref))
	}
	r0 := ref[0].(*pyjson.Object)
	if !slices.Equal(r0.Keys(), []string{"type", "post", "author"}) || r0.Get("type") != "quoted" ||
		r0.Get("post").(*pyjson.Object).Get("id") != "2120999000000000001" ||
		r0.Get("author").(*pyjson.Object).Get("username") != "carol_re" {
		t.Errorf("referenced %s", pyjson.Repr(r0))
	}

	str := func(p *string) string {
		if p == nil {
			return "<nil>"
		}
		return *p
	}
	links := func(n *model.Normalized) []string {
		var out []string
		for _, l := range n.PostLinks {
			out = append(out, strings.Join([]string{l.PostID, fmt.Sprint(l.Pos), l.ShortURL, str(l.ExpandedURL), str(l.FinalURL),
				str(l.Host), l.Kind, str(l.Title), l.Origin, l.Status}, " | "))
		}
		return out
	}
	refs := func(n *model.Normalized) []string {
		var out []string
		for _, r := range n.CandidateRefs {
			out = append(out, strings.Join([]string{r.UserID, str(r.Handle), r.PostID, r.ReferrerID, r.Kind,
				r.PostedAt.Format(time.RFC3339)}, " | "))
		}
		return out
	}

	// post 1: long post; the CVE id is only in note_tweet.text, the quoted
	// post's CVE-2026-8888 is ignored
	n, err := c.Normalize(res.Records[0])
	if err != nil {
		t.Fatal(err)
	}
	if err := n.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(n.Events) != 1 || n.Events[0].CVEID != "CVE-2026-7777" || len(n.PostsNoCVE) != 0 ||
		!strings.HasSuffix(n.Events[0].Detail["text"].(string), "https://t.co/Note1") {
		t.Fatalf("%+v", n)
	}
	if got, want := links(n), []string{
		"2121000000000000001 | 0 | https://t.co/Note1 | https://github.com/acme/foogw/commit/0123abcd | https://github.com/acme/foogw/commit/0123abcd | github.com | patch | <nil> | api | ok",
		"2121000000000000001 | 1 | https://t.co/Adv1 | https://fortiguard.fortinet.com/psirt/FG-IR-26-001 | https://www.fortiguard.fortinet.com/psirt/FG-IR-26-001 | fortiguard.fortinet.com | advisory | PSIRT advisory FG-IR-26-001 | api | ok",
	}; !slices.Equal(got, want) {
		t.Errorf("links:\n%s", strings.Join(got, "\n"))
	}
	if got, want := refs(n), []string{
		"3001 | carol_re | 2121000000000000001 | 1001 | quoted | 2026-11-12T17:00:00Z",
		"3002 | dave_vr | 2121000000000000001 | 1001 | mentioned | 2026-11-12T17:00:00Z",
	}; !slices.Equal(got, want) {
		t.Errorf("refs:\n%s", strings.Join(got, "\n"))
	}

	// post 2: no CVE id; own photo = media, quoted post = quote; the
	// author's own mention and the id that is not a number are skipped, an
	// invalid handle is dropped
	n, err = c.Normalize(res.Records[1])
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Events) != 0 || len(n.PostsNoCVE) != 1 {
		t.Fatalf("%+v", n)
	}
	if got, want := links(n), []string{
		"2121000000000000002 | 0 | https://t.co/Media2 | https://x.com/bob_sec/status/2121000000000000002/photo/1 | https://x.com/bob_sec/status/2121000000000000002/photo/1 | x.com | media | <nil> | api | ok",
		"2121000000000000002 | 1 | https://t.co/Quote2 | https://twitter.com/carol_re/status/2120999000000000001 | https://twitter.com/carol_re/status/2120999000000000001 | twitter.com | quote | <nil> | api | ok",
	}; !slices.Equal(got, want) {
		t.Errorf("links:\n%s", strings.Join(got, "\n"))
	}
	if got, want := refs(n), []string{
		"3001 | carol_re | 2121000000000000002 | 1002 | quoted | 2026-11-12T18:00:00Z",
		"1001 | alice_sec | 2121000000000000002 | 1002 | replied_to | 2026-11-12T18:00:00Z",
		"3003 | <nil> | 2121000000000000002 | 1002 | mentioned | 2026-11-12T18:00:00Z",
	}; !slices.Equal(got, want) {
		t.Errorf("refs:\n%s", strings.Join(got, "\n"))
	}
}

// Raw records stored before the collector asked for entities (only post and
// author): still normalize; their t.co links are pending, in text order,
// de-duplicated; no referred accounts.
func TestNormalizeOldShapeLinks(t *testing.T) {
	c := newC(t, script(t), nil, nil, "", nil)
	v, err := pyjson.DecodeString(`{"post": {"id": "2120000000000000009", "author_id": "1001", "created_at": "2026-11-12T00:00:00Z",
		"text": "CVE-2026-1111 PoC https://t.co/Old1A and https://t.co/Old2B, again https://t.co/Old1A; http://t.co/Plain https://t.co/"},
		"author": {"id": "1001", "username": "alice_sec"}}`)
	if err != nil {
		t.Fatal(err)
	}
	n, err := c.Normalize(model.RawRecord{Source: xposts.Name, SourceKey: "2120000000000000009", Payload: v})
	if err != nil {
		t.Fatal(err)
	}
	if len(n.Events) != 1 || len(n.CandidateRefs) != 0 || len(n.PostLinks) != 2 {
		t.Fatalf("%+v", n)
	}
	for i, short := range []string{"https://t.co/Old1A", "https://t.co/Old2B"} {
		l := n.PostLinks[i]
		if l.PostID != "2120000000000000009" || l.Pos != i || l.ShortURL != short || l.Status != "pending" || l.Origin != "api" ||
			l.Kind != "other" || l.ExpandedURL != nil || l.FinalURL != nil || l.Host != nil || l.Title != nil {
			t.Errorf("%d: %+v", i, l)
		}
	}
}
