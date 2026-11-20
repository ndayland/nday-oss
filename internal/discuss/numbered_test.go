package discuss_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// numberedFixture stores on cveA 26 top-level comments by ada, oldest
// first: #5 is deleted without replies (absent), #7 deleted with a reply (a
// placeholder), #3 hidden (a placeholder), #12 has two replies, #0 one; so 25
// threads are shown: 10 / 10 / 5 pages.
func numberedFixture(t *testing.T) (h *harness, ada, mod *browser, tops []string, replies map[string][]string) {
	t.Helper()
	l := guestLimits()
	l.GuestRead = true
	h = newHarness(t, hopt{limits: l})
	ada, mod = h.member("ada"), h.member("carol")
	h.setRole(mod.id, "moderator")
	mod.refresh()
	replies = map[string][]string{}
	for i := 0; i < 26; i++ {
		h.clock.Advance(time.Second)
		tops = append(tops, ada.create(cveA, fmt.Sprintf("top %02d", i), nil).ID)
	}
	rep := func(i int) {
		h.clock.Advance(time.Second)
		replies[tops[i]] = append(replies[tops[i]], ada.create(cveA, fmt.Sprintf("reply %d to %02d", len(replies[tops[i]]), i), &tops[i]).ID)
	}
	rep(0)
	rep(12)
	rep(12)
	rep(7)
	for _, d := range []int{5, 7} {
		if resp, body := ada.post("/api/discuss/comment/"+tops[d]+"/delete", ""); resp.StatusCode != 200 {
			t.Fatalf("delete: %d %s", resp.StatusCode, body)
		}
	}
	if resp, body := mod.post("/api/discuss/comment/"+tops[3]+"/hide", `{"reason":"test"}`); resp.StatusCode != 200 {
		t.Fatalf("hide: %d %s", resp.StatusCode, body)
	}
	return
}

type numbered struct {
	stream
	Page    *int `json:"page"`
	Pages   *int `json:"pages"`
	Threads *int `json:"threads"`
}

func (b *browser) numbered(cve, query string) numbered {
	b.h.t.Helper()
	resp, body := b.do("GET", "/api/discuss/"+cve+query, "")
	if resp.StatusCode != 200 {
		b.h.t.Fatalf("GET %s: %d %s", query, resp.StatusCode, body)
	}
	var n numbered
	if err := json.Unmarshal(body, &n); err != nil {
		b.h.t.Fatal(err)
	}
	return n
}

func TestNumberedPages(t *testing.T) {
	h, ada, mod, tops, replies := numberedFixture(t)
	guest := h.browser() // signed out; guest reading is on
	var shown []string   // the thread order of the stream: creation order without #5
	for i, id := range tops {
		if i != 5 {
			shown = append(shown, id)
		}
	}
	ids := func(cs []comment) []string {
		var out []string
		for _, c := range cs {
			out = append(out, c.ID)
		}
		return out
	}
	for _, who := range []struct {
		name string
		b    *browser
	}{{"guest", guest}, {"member", ada}, {"moderator", mod}} {
		for p, want := range [][]string{shown[:10], shown[10:20], shown[20:]} {
			n := who.b.numbered(cveA, fmt.Sprintf("?page=%d&limit=10", p+1))
			if got := ids(n.Comments); strings.Join(got, " ") != strings.Join(want, " ") {
				t.Errorf("%s page %d: %v, want %v", who.name, p+1, got, want)
			}
			// the same totals for every viewer: the placeholders (hidden #3, deleted-with-reply #7)
			// are counted, the deleted comment without replies (#5) is not
			if n.Page == nil || *n.Page != p+1 || n.Pages == nil || *n.Pages != 3 || n.Threads == nil || *n.Threads != 25 {
				t.Errorf("%s page %d: page/pages/threads %v %v %v", who.name, p+1, n.Page, n.Pages, n.Threads)
			}
			if n.NextCursor != nil {
				t.Errorf("%s page %d: a cursor in a numbered page", who.name, p+1)
			}
			for _, c := range n.Comments { // a thread keeps its replies
				if len(c.Replies) != len(replies[c.ID]) && c.ID != tops[7] {
					t.Errorf("%s: thread %s has %d replies, want %d", who.name, c.ID, len(c.Replies), len(replies[c.ID]))
				}
			}
		}
	}
	// statuses on page 1: the hidden placeholder at its place; a guest sees no body of it
	if n := guest.numbered(cveA, "?page=1&limit=10"); n.Comments[3].ID != tops[3] || n.Comments[3].Status != "hidden" || n.Comments[3].Body != nil {
		t.Errorf("page 1, hidden thread: %+v", n.Comments[3])
	}
	// out of range is the last page; invalid values are refused; no mixing with a cursor
	if n := guest.numbered(cveA, "?page=99&limit=10"); n.Page == nil || *n.Page != 3 || len(n.Comments) != 5 {
		t.Errorf("page 99: %v, %d comments", n.Page, len(n.Comments))
	}
	cur := *guest.numbered(cveA, "?limit=10").NextCursor
	for _, q := range []string{"?page=0", "?page=-1", "?page=x", "?page=2&cursor=" + cur, "?page=2&thread=" + tops[0]} {
		resp, body := guest.do("GET", "/api/discuss/"+cveA+q, "")
		expect(t, q, resp, body, http.StatusBadRequest, "bad_request")
	}
	// without ?page= nothing changed: the cursor path, no page fields
	if n := guest.numbered(cveA, "?limit=10"); len(n.Comments) != 10 || n.NextCursor == nil || n.Page != nil || n.Pages != nil || n.Threads != nil {
		t.Errorf("cursor path: %d comments, next %v, page fields %v %v %v", len(n.Comments), n.NextCursor, n.Page, n.Pages, n.Threads)
	}
	// Locate: the index of a thread (and of a reply's thread) names its page
	for i, id := range shown {
		pos, err := h.dsvc.Locate(context.Background(), cveA, id)
		if err != nil {
			if id == tops[3] || id == tops[7] { // hidden / deleted: not located
				continue
			}
			t.Fatalf("locate %d: %v", i, err)
		}
		if pos.Index != i {
			t.Errorf("thread %d: Index %d", i, pos.Index)
		}
	}
	for _, i := range []int{0, 12} {
		for _, r := range replies[tops[i]] {
			pos, err := h.dsvc.Locate(context.Background(), cveA, r)
			if err != nil || !pos.Reply || pos.ThreadID != tops[i] || pos.Index != indexOf(shown, tops[i]) {
				t.Errorf("reply of %d: %+v %v", i, pos, err)
			}
			n := guest.numbered(cveA, fmt.Sprintf("?page=%d&limit=10", pos.Index/10+1))
			found := false
			for _, c := range n.Comments {
				found = found || c.ID == tops[i]
			}
			if !found {
				t.Errorf("reply of %d: its thread is not on page %d", i, pos.Index/10+1)
			}
		}
	}
	// a new top-level comment is the last thread: Locate puts it on the last page
	h.clock.Advance(time.Second)
	fresh := ada.create(cveA, "newest", nil)
	pos, err := h.dsvc.Locate(context.Background(), cveA, fresh.ID)
	if err != nil || pos.Index != 25 {
		t.Fatalf("new comment: %+v %v", pos, err)
	}
	n := guest.numbered(cveA, fmt.Sprintf("?page=%d&limit=10", pos.Index/10+1))
	if len(n.Comments) != 6 || n.Comments[5].ID != fresh.ID {
		t.Errorf("last page after a post: %d comments", len(n.Comments))
	}
	// the signed-out outline of a page (what the public HTML draws)
	o, err := h.dsvc.OutlinePage(context.Background(), cveA, 2, 10)
	if err != nil || o.Page != 2 || o.Pages != 3 || o.Total != 26 || len(o.Threads) != 10 || !o.More {
		t.Errorf("outline page 2: %+v %v", o, err)
	}
	if o, _ = h.dsvc.OutlinePage(context.Background(), cveA, 50, 10); o.Page != 3 || len(o.Threads) != 6 || o.More {
		t.Errorf("outline page 50: page %d, %d threads", o.Page, len(o.Threads))
	}
}

func indexOf(s []string, id string) int {
	for i, x := range s {
		if x == id {
			return i
		}
	}
	return -1
}
