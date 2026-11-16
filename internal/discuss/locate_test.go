package discuss_test

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"nday.land/nday/internal/discuss"
)

// TestLocate: Locate's cursors open exactly the page (StreamPage) and the
// thread continuation (StreamThread) that begin with the comment's thread or
// reply; hidden, deleted, foreign, unknown and malformed ids are not found.
func TestLocate(t *testing.T) {
	h := newHarness(t, hopt{})
	ctx := context.Background()
	ada := h.member("ada")
	var tops []comment
	replies := map[string][]comment{}
	for i := 0; i < 3; i++ {
		h.clock.Advance(time.Second) // distinct times: creation order is stream order
		c := ada.create(cveA, "top "+strconv.Itoa(i), nil)
		tops = append(tops, c)
		for k := 0; k < 3; k++ {
			h.clock.Advance(time.Second)
			replies[c.ID] = append(replies[c.ID], ada.create(cveA, "reply "+strconv.Itoa(i)+"."+strconv.Itoa(k), &c.ID))
		}
	}
	other := ada.create(cveB, "elsewhere", nil)
	hidden := ada.create(cveA, "to hide", nil)
	if _, _, err := h.ds.Hide(ctx, hidden.ID, nil, "test"); err != nil {
		t.Fatal(err)
	}
	gone := replies[tops[2].ID][2]
	if resp, body := ada.post("/api/discuss/comment/"+gone.ID+"/delete", ""); resp.StatusCode != 200 {
		t.Fatalf("delete: %d %s", resp.StatusCode, body)
	}

	rd := h.reader()
	for i, top := range tops {
		p, err := h.dsvc.Locate(ctx, cveA, top.ID)
		if err != nil {
			t.Fatalf("top %d: %v", i, err)
		}
		if p.ThreadID != top.ID || p.Reply || p.ReplyCursor != "" || (i == 0) != (p.PageCursor == "") {
			t.Errorf("top %d: %+v", i, p)
		}
		r := rd.stream(cveA, "?limit=1&cursor="+p.PageCursor)
		if len(r.Comments) == 0 || r.Comments[0].ID != top.ID {
			t.Errorf("top %d: page at its cursor does not start with it", i)
		}
		for k, rep := range replies[top.ID] {
			if rep.ID == gone.ID {
				continue
			}
			p, err := h.dsvc.Locate(ctx, cveA, rep.ID)
			if err != nil {
				t.Fatalf("reply %d.%d: %v", i, k, err)
			}
			if p.ThreadID != top.ID || !p.Reply || (k == 0) != (p.ReplyCursor == "") {
				t.Errorf("reply %d.%d: %+v", i, k, p)
			}
			th := rd.stream(cveA, "?thread="+p.ThreadID+"&cursor="+p.ReplyCursor)
			if len(th.Comments) != 1 || len(th.Comments[0].Replies) == 0 || th.Comments[0].Replies[0].ID != rep.ID {
				t.Errorf("reply %d.%d: continuation at its cursor does not start with it", i, k)
			}
		}
	}
	for name, id := range map[string]string{"hidden": hidden.ID, "deleted": gone.ID, "other cve": other.ID,
		"unknown": "00000000-0000-4000-8000-000000000000", "malformed": "x' OR 1=1"} {
		if p, err := h.dsvc.Locate(ctx, cveA, id); !errors.Is(err, discuss.ErrNotFound) {
			t.Errorf("%s: %+v %v, want ErrNotFound", name, p, err)
		}
	}
	// a blank id is not a comment
	if p, err := h.dsvc.Locate(ctx, cveA, "  "); err == nil || p != nil {
		t.Error("blank id located")
	}
}
