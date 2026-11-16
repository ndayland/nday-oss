package discuss_test

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/discuss"
	"nday.land/nday/internal/testutil"
)

// A client following next_cursor and replies_next_cursor sees every
// comment exactly once, and no response exceeds the byte budget.
func TestPageBudgetFollow(t *testing.T) {
	h := newHarness(t, hopt{})
	ctx := context.Background()
	ada := h.member("ada")
	big := strings.Repeat("y&", 3000) // ~6 kB source, ~30 kB HTML
	want := map[string]bool{}
	for i := 0; i < 2; i++ {
		var top string
		if err := h.db.Conn.QueryRow(ctx, `INSERT INTO comments (cve_id, is_reply, author_id, body, lang, links, created_at, updated_at)
			VALUES ($1, false, $2, $3, 'en', true, $4, $4) RETURNING id::text`, cveA, ada.id, big, h.clock.Now().Add(time.Duration(i)*time.Second)).Scan(&top); err != nil {
			t.Fatal(err)
		}
		want[top] = true
		rows, err := h.db.Conn.Query(ctx, `INSERT INTO comments (cve_id, parent_id, is_reply, author_id, body, lang, links, created_at, updated_at)
			SELECT $1, $2::uuid, true, $3, $4 || g, 'en', true, $5::timestamptz + g * interval '1 ms', $5::timestamptz FROM generate_series(1, 60) g RETURNING id::text`,
			cveA, top, ada.id, big, h.clock.Now().Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			want[id] = true
		}
	}
	anon := h.reader()
	seen := map[string]int{}
	type page struct {
		Comments []struct {
			ID      string  `json:"id"`
			Body    string  `json:"body_html"`
			Trunc   bool    `json:"replies_truncated"`
			Next    *string `json:"replies_next_cursor"`
			Replies []struct {
				ID   string `json:"id"`
				Body string `json:"body_html"`
			} `json:"replies"`
		} `json:"comments"`
		NextCursor *string `json:"next_cursor"`
		Limits     struct {
			MaxPageBytes int `json:"max_page_bytes"`
		} `json:"limits"`
	}
	get := func(q string) page {
		resp, body := anon.do("GET", "/api/discuss/"+cveA+q, "")
		if resp.StatusCode != 200 {
			t.Fatalf("GET %s: %d %s", q, resp.StatusCode, body)
		}
		var p page
		if err := json.Unmarshal(body, &p); err != nil {
			t.Fatal(err)
		}
		size := 0
		for _, c := range p.Comments {
			size += len(c.Body)
			for _, r := range c.Replies {
				size += len(r.Body)
			}
		}
		if size > discuss.PageMaxHTMLBytes || p.Limits.MaxPageBytes != discuss.PageMaxHTMLBytes {
			t.Errorf("GET %s: %d bytes of HTML (budget %d, limits %d)", q, size, discuss.PageMaxHTMLBytes, p.Limits.MaxPageBytes)
		}
		return p
	}
	truncated := 0
	q := "?limit=200"
	for pages := 0; pages < 50; pages++ {
		p := get(q)
		for _, c := range p.Comments {
			if !strings.Contains(q, "thread=") {
				seen[c.ID]++
			}
			for _, r := range c.Replies {
				seen[r.ID]++
			}
		}
		switch {
		case len(p.Comments) == 1 && p.Comments[0].Trunc:
			truncated++
			th := p.Comments[0]
			// finish this thread first, then the page cursor
			for k := 0; th.Trunc; k++ {
				if k > 50 {
					t.Fatal("thread never ends")
				}
				tp := get("?thread=" + th.ID + "&cursor=" + *th.Next)
				th = tp.Comments[0]
				for _, r := range th.Replies {
					seen[r.ID]++
				}
				if tp.NextCursor != nil {
					t.Errorf("thread continuation has a next_cursor")
				}
			}
		}
		if p.NextCursor == nil {
			break
		}
		q = "?limit=200&cursor=" + *p.NextCursor
	}
	if truncated == 0 {
		t.Error("no thread was cut by the budget")
	}
	for id := range want {
		if seen[id] != 1 {
			t.Errorf("comment %s seen %d times", id, seen[id])
		}
	}
	if len(seen) != len(want) {
		t.Errorf("saw %d comments, want %d", len(seen), len(want))
	}
	// a page of 200 threads cuts the same way, and the thread continues
	r := anon.stream(cveA, "?limit=200")
	if len(r.Comments) != 1 || !r.Comments[0].RepliesTruncated || r.NextCursor == nil {
		t.Fatalf("page: %+v", r)
	}
	tr := anon.stream(cveA, "?thread="+r.Comments[0].ID+"&cursor="+*r.Comments[0].RepliesNextCursor)
	if len(tr.Comments) != 1 || len(tr.Comments[0].Replies) == 0 {
		t.Fatalf("thread: %+v", tr)
	}
	resp, body := anon.do("GET", "/api/discuss/"+cveA+"?thread=0b8c6f0e-7f0e-4c1a-9a51-3c2f6f1d9e44", "")
	expect(t, "unknown thread", resp, body, 404, "not_found")
}

// Delete and report are rate limited per user, whatever the outcome.
func TestDeleteReportLimits(t *testing.T) {
	l := discuss.DefaultLimits()
	l.PostBurst, l.NewPostBurst, l.AddrBurst, l.ReadBurst = 1000, 1000, 1000, 1000
	l.PostDaily, l.NewPostDaily, l.ReportDaily = 1000, 1000, 1000
	l.DeleteBurst, l.DeleteEvery = 2, time.Minute
	l.ReportBurst, l.ReportEvery = 2, time.Minute
	h := newHarness(t, hopt{limits: &l})
	ada, bob := h.member("ada"), h.member("bob")
	unknown := "0b8c6f0e-7f0e-4c1a-9a51-3c2f6f1d9e44"
	c := ada.create(cveA, "x", nil)
	for i := 0; i < 2; i++ {
		resp, body := bob.post("/api/discuss/comment/"+unknown+"/delete", "")
		expect(t, "delete unknown", resp, body, 404, "not_found")
	}
	resp, body := bob.post("/api/discuss/comment/"+unknown+"/delete", "")
	expect(t, "third delete", resp, body, 429, "rate_limited")
	retryAfterAtLeast(t, "delete", resp, 1)
	for i := 0; i < 2; i++ {
		resp, body := bob.post("/api/discuss/comment/"+c.ID+"/report", `{"reason":"spam"}`) // second is idempotent
		expect(t, "report", resp, body, 200, "")
	}
	resp, body = bob.post("/api/discuss/comment/"+c.ID+"/report", `{"reason":"spam"}`)
	expect(t, "third report", resp, body, 429, "rate_limited")
	// suspended users may delete, but are limited too
	if err := h.as.Suspend(context.Background(), ada.id, nil, "x"); err != nil {
		t.Fatal(err)
	}
	resp, body = ada.post("/api/discuss/comment/"+c.ID+"/delete", "")
	expect(t, "suspended delete", resp, body, 200, "")
	for i := 0; i < 2; i++ {
		ada.post("/api/discuss/comment/"+unknown+"/delete", "")
	}
	resp, body = ada.post("/api/discuss/comment/"+unknown+"/delete", "")
	expect(t, "suspended delete limit", resp, body, 429, "rate_limited")
	h.clock.Advance(time.Minute)
	resp, body = ada.post("/api/discuss/comment/"+unknown+"/delete", "")
	expect(t, "delete after a minute", resp, body, 404, "not_found")
}

// Invisible-only bodies are refused; invisible characters and zalgo
// are cleaned before storing.
func TestInvisibleBodies(t *testing.T) {
	h := newHarness(t, hopt{})
	ada := h.member("ada")
	for _, b := range []string{"\u200b\u200b", "\u200d \u200c\n\u3164", "\u0301\u0302", "\ufeff\u2060\u00ad", "\U000E0041\U000E0042"} {
		j, _ := json.Marshal(map[string]string{"body": b, "lang": "en"})
		resp, body := ada.post("/api/discuss/"+cveA, string(j))
		expect(t, fmt.Sprintf("invisible %q", b), resp, body, 400, "invalid_body")
	}
	c := ada.create(cveA, "a\u200bb e\u0301\u0302\u0303\u0304\u0305\u0306\n\n\n\n\nz", nil)
	if *c.Body != "ab e\u0301\u0302\u0303\u0304\n\n\nz" {
		t.Errorf("stored %q", *c.Body)
	}
}

// Moderators can read earlier bodies; nobody else can.
func TestModRevisions(t *testing.T) {
	h := newHarness(t, hopt{})
	ada, bob, mod := h.member("ada"), h.member("bob"), h.member("carol")
	h.setRole(mod.id, "moderator")
	c := ada.create(cveA, "buy pills <b>now</b>", nil)
	bob.post("/api/discuss/comment/"+c.ID+"/report", `{"reason":"spam"}`)
	h.clock.Advance(time.Second)
	ada.post("/api/discuss/comment/"+c.ID+"/edit", `{"body":"harmless"}`)
	h.clock.Advance(time.Second)
	ada.post("/api/discuss/comment/"+c.ID+"/edit", `{"body":"harmless 2"}`)
	path := "/api/mod/comment/" + c.ID + "/revisions"
	resp, body := mod.do("GET", path, "")
	expect(t, "revisions", resp, body, 200, "")
	var r struct {
		CommentID string `json:"comment_id"`
		Revisions []struct {
			Body       string `json:"body"`
			ReplacedAt string `json:"replaced_at"`
		} `json:"revisions"`
	}
	if err := json.Unmarshal(body, &r); err != nil {
		t.Fatal(err)
	}
	if r.CommentID != c.ID || len(r.Revisions) != 2 || r.Revisions[0].Body != "harmless" || r.Revisions[1].Body != "buy pills <b>now</b>" {
		t.Errorf("revisions: %s", body)
	}
	if strings.Contains(string(body), "<p>") || strings.Contains(string(body), "&lt;") {
		t.Errorf("revisions are rendered/escaped HTML: %s", body)
	}
	s := mod.stream(cveA, "")
	if s.Comments[0].Moderation == nil {
		t.Fatal("no moderation block")
	}
	_, raw := mod.do("GET", "/api/discuss/"+cveA, "")
	if !strings.Contains(string(raw), `"revisions":2`) {
		t.Errorf("moderator view lacks revisions count: %s", raw)
	}
	_, raw = bob.do("GET", "/api/discuss/"+cveA, "")
	if strings.Contains(string(raw), `"revisions"`) {
		t.Errorf("non-moderator sees revisions count")
	}
	resp, body = bob.do("GET", path, "")
	expect(t, "revisions as a user", resp, body, 403, "forbidden")
	resp, body = h.browser().do("GET", path, "")
	expect(t, "revisions signed out", resp, body, 401, "not_signed_in")
	resp, body = mod.do("GET", "/api/mod/comment/0b8c6f0e-7f0e-4c1a-9a51-3c2f6f1d9e44/revisions", "")
	expect(t, "revisions unknown", resp, body, 404, "not_found")
	resp, body = mod.do("POST", path, "")
	expect(t, "POST revisions", resp, body, 405, "method_not_allowed")
}

type countingSource struct {
	inner auth.ConnSource
	n     atomic.Int64
}

func (c *countingSource) WithConn(ctx context.Context, fn func(*pgx.Conn) error) error {
	c.n.Add(1)
	return c.inner.WithConn(ctx, fn)
}

// Public reads use the read-only pool; writes and signed-in reads the
// write pool.
func TestReadPool(t *testing.T) {
	h := newHarness(t, hopt{})
	ctx := context.Background()
	pc, err := pgx.ParseConfig(h.db.URL)
	if err != nil {
		t.Fatal(err)
	}
	pc.RuntimeParams["default_transaction_read_only"] = "on"
	ro := dbpool.New(pc, dbpool.Options{Size: 2, Dial: testutil.Dial(pc)})
	t.Cleanup(ro.Close)
	rc := &countingSource{inner: ro}
	h.ds.ReadDB = rc
	ada := h.member("ada")
	c := ada.create(cveA, "on the write pool", nil) // would fail on a read-only connection
	ada.post("/api/discuss/comment/"+c.ID+"/edit", `{"body":"edited"}`)
	if n := rc.n.Load(); n != 0 {
		t.Errorf("writes used the read pool %d times", n)
	}
	before := rc.n.Load()
	ada.stream(cveA, "")
	signedIn := rc.n.Load() - before
	before = rc.n.Load()
	if s := h.browser().stream(cveA, ""); s.Outline == nil || len(s.Outline.Threads) != 1 {
		t.Fatalf("anonymous stream: %+v", s)
	}
	if _, err := h.dsvc.Outline(ctx, cveA); err != nil {
		t.Fatal(err)
	}
	if _, err := h.dsvc.Version(ctx, cveA); err != nil {
		t.Fatal(err)
	}
	anon := rc.n.Load() - before
	// signed in: only the vulnerability check is a public read
	if signedIn > 1 || anon < 4 {
		t.Errorf("read pool used %d times for a signed-in GET, %d for anonymous GET+Stream+Version", signedIn, anon)
	}
}
