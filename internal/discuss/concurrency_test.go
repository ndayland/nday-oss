package discuss_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
	"time"

	"nday.land/nday/internal/discuss"
)

func (h *harness) newComment(author, cve, body string, parent *string) *discuss.Row {
	h.t.Helper()
	l := discuss.DefaultLimits()
	l.PostDaily, l.NewPostDaily = 100000, 100000
	r, _, err := h.ds.Create(context.Background(), discuss.NewComment{CVE: cve, Parent: parent, Author: author, Body: body, Lang: "en"}, l, nil)
	if err != nil {
		h.t.Fatal(err)
	}
	return r
}

func both(f, g func()) {
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(2)
	go func() { defer wg.Done(); <-start; f() }()
	go func() { defer wg.Done(); <-start; g() }()
	close(start)
	wg.Wait()
}

func TestConcurrentEdits(t *testing.T) {
	h := newHarness(t, hopt{})
	ada := h.member("ada")
	ctx := context.Background()
	for i := 0; i < 20; i++ {
		c := h.newComment(ada.id, cveA, fmt.Sprintf("orig %d", i), nil)
		var e1, e2 error
		both(func() { _, _, e1 = h.ds.Edit(ctx, c.ID, ada.id, "one") },
			func() { _, _, e2 = h.ds.Edit(ctx, c.ID, ada.id, "two") })
		if e1 != nil || e2 != nil {
			t.Fatalf("edits: %v %v", e1, e2)
		}
		r, _ := h.ds.Get(ctx, nil, c.ID)
		// serialised: the second edit saw the first's body, so the revisions
		// are the original and the first edit's body (or only the original
		// when both wrote the same text, which they do not here)
		revs := h.count(`SELECT count(*) FROM comment_revisions WHERE comment_id = $1`, c.ID)
		orig := h.count(`SELECT count(*) FROM comment_revisions WHERE comment_id = $1 AND body = $2`, c.ID, fmt.Sprintf("orig %d", i))
		other := map[string]string{"one": "two", "two": "one"}[r.Body]
		lost := h.count(`SELECT count(*) FROM comment_revisions WHERE comment_id = $1 AND body = $2`, c.ID, other)
		if revs != 2 || orig != 1 || lost != 1 {
			t.Fatalf("round %d: final %q, %d revisions (orig %d, other %d)", i, r.Body, revs, orig, lost)
		}
	}
}

func TestConcurrentEditAndHide(t *testing.T) {
	h := newHarness(t, hopt{})
	ada, mod := h.member("ada"), h.member("carol")
	ctx := context.Background()
	edited, refused := 0, 0
	for i := 0; i < 30; i++ {
		c := h.newComment(ada.id, cveA, fmt.Sprintf("before %d", i), nil)
		var ee, he error
		both(func() { _, _, ee = h.ds.Edit(ctx, c.ID, ada.id, "after") },
			func() { _, _, he = h.ds.Hide(ctx, c.ID, &mod.id, "r") })
		if he != nil {
			t.Fatalf("hide failed: %v", he)
		}
		r, _ := h.ds.Get(ctx, nil, c.ID)
		revs := h.count(`SELECT count(*) FROM comment_revisions WHERE comment_id = $1`, c.ID)
		switch {
		case ee == nil:
			edited++
			if r.Body != "after" || revs != 1 || r.Status != "hidden" {
				t.Fatalf("edit won: %+v revisions %d", r, revs)
			}
		case errors.Is(ee, discuss.ErrWrongStatus):
			refused++
			if r.Body != fmt.Sprintf("before %d", i) || revs != 0 || r.Status != "hidden" {
				t.Fatalf("hide won but the edit left traces: %+v revisions %d", r, revs)
			}
		default:
			t.Fatalf("edit: %v", ee)
		}
	}
	t.Logf("edit first %d times, hide first %d times", edited, refused)
}

func TestConcurrentDeleteAndReply(t *testing.T) {
	h := newHarness(t, hopt{})
	ada, bob := h.member("ada"), h.member("bob")
	ctx := context.Background()
	l := discuss.DefaultLimits()
	l.PostDaily, l.NewPostDaily = 100000, 100000
	replied, refused := 0, 0
	for i := 0; i < 30; i++ {
		c := h.newComment(ada.id, cveA, fmt.Sprintf("parent %d", i), nil)
		var de, ce error
		var reply *discuss.Row
		both(func() {
			// stagger the delete in odd rounds so both orders occur
			if i%2 == 1 {
				time.Sleep(time.Duration(rand.IntN(4000)) * time.Microsecond)
			}
			_, de = h.ds.Delete(ctx, c.ID, ada.id)
		},
			func() {
				reply, _, ce = h.ds.Create(ctx, discuss.NewComment{CVE: cveA, Parent: &c.ID, Author: bob.id,
					Body: fmt.Sprintf("reply %d", i), Lang: "en"}, l, nil)
			})
		if de != nil {
			t.Fatalf("delete: %v", de)
		}
		switch {
		case ce == nil:
			replied++
			// the reply was committed before the delete: the parent is a
			// placeholder that still shows the reply
			p, err := h.ds.Page(ctx, nil, cveA, nil, 200)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, top := range p.Top {
				if top.ID == c.ID {
					found = top.Status == "deleted" && len(p.Replies[c.ID]) == 1 && p.Replies[c.ID][0].ID == reply.ID
				}
			}
			if !found {
				t.Fatalf("round %d: reply to a deleted parent is not shown under its placeholder", i)
			}
		case errors.Is(ce, discuss.ErrBadParent):
			refused++
			if n := h.count(`SELECT count(*) FROM comments WHERE parent_id = $1`, c.ID); n != 0 {
				t.Fatalf("refused reply was stored")
			}
		default:
			t.Fatalf("create: %v", ce)
		}
	}
	t.Logf("reply first %d times, delete first %d times", replied, refused)
}

// The daily cap holds under concurrent posting by one user.
func TestConcurrentDailyCap(t *testing.T) {
	h := newHarness(t, hopt{})
	ada := h.member("ada")
	h.establish(ada.id)
	ctx := context.Background()
	l := discuss.DefaultLimits()
	l.PostDaily = 5
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok, capped := 0, 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := h.ds.Create(ctx, discuss.NewComment{CVE: cveA, Author: ada.id, Body: fmt.Sprintf("c%d", i), Lang: "en"}, l, nil)
			mu.Lock()
			defer mu.Unlock()
			var le *discuss.LimitError
			switch {
			case err == nil:
				ok++
			case errors.As(err, &le) && le.Code == "daily_limit":
				capped++
			default:
				t.Errorf("create: %v", err)
			}
		}()
	}
	wg.Wait()
	if ok != 5 || capped != 15 {
		t.Errorf("%d created, %d capped; want 5 and 15", ok, capped)
	}
}

// Concurrent reports by one user on one comment leave one open report.
func TestConcurrentReports(t *testing.T) {
	h := newHarness(t, hopt{})
	ada, bob := h.member("ada"), h.member("bob")
	c := h.newComment(ada.id, cveA, "x", nil)
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, _, err := h.ds.AddReport(context.Background(), c.ID, bob.id, "spam", nil, 100); err != nil {
				t.Errorf("report: %v", err)
			}
		}()
	}
	wg.Wait()
	if n := h.count(`SELECT count(*) FROM comment_reports`); n != 1 {
		t.Errorf("%d reports, want 1", n)
	}
}

// The database itself refuses replies to replies and across
// vulnerabilities (composite foreign key), whatever the application does.
func TestSchemaRefusesBadThreads(t *testing.T) {
	h := newHarness(t, hopt{})
	ada := h.member("ada")
	top := h.newComment(ada.id, cveA, "top", nil)
	reply := h.newComment(ada.id, cveA, "reply", &top.ID)
	ctx := context.Background()
	for name, args := range map[string][]any{
		"reply to reply":  {cveA, reply.ID},
		"cross-cve reply": {cveB, top.ID},
	} {
		_, err := h.db.Conn.Exec(ctx, `INSERT INTO comments (cve_id, parent_id, is_reply, author_id, body, lang, links)
			VALUES ($1, $2::uuid, true, $3, 'x', 'en', true)`, args[0], args[1], ada.id)
		if err == nil {
			t.Errorf("%s: accepted by the database", name)
		}
	}
	if _, err := h.db.Conn.Exec(ctx, `INSERT INTO comments (cve_id, parent_id, is_reply, author_id, body, lang, links)
		VALUES ($1, NULL, true, $2, 'x', 'en', true)`, cveA, ada.id); err == nil {
		t.Error("is_reply without parent accepted")
	}
	if _, err := h.db.Conn.Exec(ctx, `UPDATE comments SET status = 'hidden' WHERE id = $1::uuid`, top.ID); err == nil {
		t.Error("hidden without reason accepted")
	}
}
