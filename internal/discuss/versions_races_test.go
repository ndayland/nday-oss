package discuss_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/discuss"
)

// waitForLockWait polls until some backend of this database waits on a lock.
func (h *harness) waitForLockWait() {
	h.t.Helper()
	for i := 0; i < 500; i++ {
		if h.count(`SELECT count(*) FROM pg_stat_activity WHERE datname = current_database() AND wait_event_type = 'Lock'`) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("nothing ever waited on a lock")
}

// Interleaving: Hide(X) waits on a row lock while Edit(Y)
// commits with a later clock; a page cached under v1 must not survive the
// hide: v1 != v2.
func TestVersionInterleavedHide(t *testing.T) {
	h := newHarness(t, hopt{})
	ctx := context.Background()
	ada, mod := h.member("ada"), h.member("carol")
	h.setRole(mod.id, "moderator")
	x := h.newComment(ada.id, cveA, "X: abusive SECRET-BODY", nil)
	y := h.newComment(ada.id, cveA, "Y: harmless", nil)
	holder, err := pgx.Connect(ctx, h.db.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close(ctx)
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `SELECT 1 FROM comments WHERE id = $1::uuid FOR UPDATE`, x.ID); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, _, err := h.ds.Hide(ctx, x.ID, &mod.id, "abuse"); done <- err }()
	h.waitForLockWait()
	h.clock.Advance(time.Minute)
	if _, _, err := h.ds.Edit(ctx, y.ID, ada.id, "Y: harmless, edited"); err != nil {
		t.Fatal(err)
	}
	v1, _ := h.dsvc.Version(ctx, cveA)
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	v2, _ := h.dsvc.Version(ctx, cveA)
	if v1 == v2 {
		t.Errorf("Version unchanged across a hide that committed after a later edit: %s", v1)
	}
	for _, c := range h.reader().stream(cveA, "").Comments {
		if c.ID == x.ID && (c.Status != "hidden" || strings.Contains(c.BodyHTML, "SECRET")) {
			t.Errorf("fresh stream still shows X: %+v", c)
		}
	}
}

// Every change a page renders changes the version (clock not advanced,
// so only content can make the difference); another CVE's version does not.
func TestVersionChangesWithoutClock(t *testing.T) {
	h := newHarness(t, hopt{})
	ctx := context.Background()
	ada, bob, mod := h.member("ada"), h.member("bob"), h.member("carol")
	h.setRole(mod.id, "moderator")
	c := h.newComment(ada.id, cveA, "one", nil)
	d := h.newComment(bob.id, cveA, "two", nil)
	other, _ := h.dsvc.Version(ctx, cveB)
	prev, _ := h.dsvc.Version(ctx, cveA)
	step := func(name string, f func() error) {
		t.Helper()
		if err := f(); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		v, _ := h.dsvc.Version(ctx, cveA)
		if v == prev {
			t.Errorf("%s: Version unchanged", name)
		}
		prev = v
	}
	step("hide", func() error { _, _, err := h.ds.Hide(ctx, c.ID, &mod.id, "r"); return err })
	step("unhide", func() error { _, err := h.ds.Unhide(ctx, c.ID, &mod.id); return err })
	step("edit", func() error { _, _, err := h.ds.Edit(ctx, c.ID, ada.id, "one!"); return err })
	step("delete", func() error { _, err := h.ds.Delete(ctx, d.ID, bob.id); return err })
	step("role change", func() error { return h.as.SetRole(ctx, ada.id, "moderator") })
	step("handle change", func() error { _, err := h.as.SetHandle(ctx, ada.id, "Ada", "ada", 0); return err })
	step("account deletion", func() error { return h.as.DeleteUser(ctx, ada.id, 0, nil) })
	if v, _ := h.dsvc.Version(ctx, cveB); v != other {
		t.Errorf("unrelated CVE's Version changed: %s -> %s", other, v)
	}
}

// insertUsers creates n users with handles directly (fast).
func (h *harness) insertUsers(n int) []string {
	h.t.Helper()
	var ids []string
	for i := 0; i < n; i++ {
		var id string
		if err := h.db.Conn.QueryRow(context.Background(), `INSERT INTO users (display_name, created_at) VALUES ($1, now() - interval '30 days')
			RETURNING id::text`, fmt.Sprintf("u%d", i)).Scan(&id); err != nil {
			h.t.Fatal(err)
		}
		ids = append(ids, id)
	}
	return ids
}

// The reply cap is exact under concurrency.
func TestThreadCapConcurrent(t *testing.T) {
	h := newHarness(t, hopt{})
	ctx := context.Background()
	ada := h.member("ada")
	top := h.newComment(ada.id, cveA, "top", nil)
	if _, err := h.db.Conn.Exec(ctx, `INSERT INTO comments (cve_id, parent_id, is_reply, author_id, body, lang, links)
		SELECT $1, $2::uuid, true, $3, 'r' || g, 'en', true FROM generate_series(1, $4::int) g`, cveA, top.ID, ada.id, discuss.MaxReplies-1); err != nil {
		t.Fatal(err)
	}
	users := h.insertUsers(6)
	l := discuss.DefaultLimits()
	l.PostDaily, l.NewPostDaily = 1000, 1000
	for round := 0; round < 5; round++ {
		if round > 0 { // back to 199
			if _, err := h.db.Conn.Exec(ctx, `DELETE FROM comments WHERE parent_id = $1::uuid AND body LIKE 'race%'`, top.ID); err != nil {
				t.Fatal(err)
			}
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		ok, full := 0, 0
		start := make(chan struct{})
		for i, u := range users {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, _, err := h.ds.Create(ctx, discuss.NewComment{CVE: cveA, Parent: &top.ID, Author: u, Body: fmt.Sprintf("race %d %d", round, i), Lang: "en"}, l, nil)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					ok++
				case errors.Is(err, discuss.ErrThreadFull):
					full++
				default:
					t.Errorf("create: %v", err)
				}
			}()
		}
		close(start)
		wg.Wait()
		if n := h.count(`SELECT count(*) FROM comments WHERE parent_id = $1::uuid`, top.ID); n != discuss.MaxReplies || ok != 1 {
			t.Fatalf("round %d: %d replies (cap %d), %d created, %d refused", round, n, discuss.MaxReplies, ok, full)
		}
	}
}

// A report racing with a hide never stays open on a hidden comment.
func TestReportHideRace(t *testing.T) {
	h := newHarness(t, hopt{})
	ctx := context.Background()
	ada, bob, mod := h.member("ada"), h.member("bob"), h.member("carol")
	h.setRole(mod.id, "moderator")
	for i := 0; i < 40; i++ {
		c := h.newComment(ada.id, cveA, fmt.Sprintf("c%d", i), nil)
		var re error
		both(func() {
			if i%2 == 1 {
				time.Sleep(time.Duration(rand.IntN(3000)) * time.Microsecond)
			}
			_, _, re = h.ds.AddReport(ctx, c.ID, bob.id, "spam", nil, 1000)
		}, func() {
			if _, _, err := h.ds.Hide(ctx, c.ID, &mod.id, "r"); err != nil {
				t.Errorf("hide: %v", err)
			}
		})
		if re != nil && !errors.Is(re, discuss.ErrWrongStatus) {
			t.Fatalf("report: %v", re)
		}
		if n := h.count(`SELECT count(*) FROM comment_reports r JOIN comments c ON c.id = r.comment_id
			WHERE r.resolved_at IS NULL AND c.status = 'hidden'`); n != 0 {
			t.Fatalf("round %d: %d open reports on hidden comments", i, n)
		}
	}
}

// One page of GET (and StreamPage) stays within the byte budget even
// with huge threads; threads are never silently lost.
func TestPageByteBudget(t *testing.T) {
	h := newHarness(t, hopt{})
	ctx := context.Background()
	ada := h.member("ada")
	big := strings.Repeat("x&", 2500) // 5000 bytes -> ~12.5 kB of HTML
	var tops []string
	for i := 0; i < 3; i++ {
		var top string
		if err := h.db.Conn.QueryRow(ctx, `INSERT INTO comments (cve_id, is_reply, author_id, body, lang, links, created_at, updated_at)
			VALUES ($1, false, $2, $3, 'en', true, $4, $4) RETURNING id::text`, cveA, ada.id, big, h.clock.Now().Add(time.Duration(i)*time.Second)).Scan(&top); err != nil {
			t.Fatal(err)
		}
		tops = append(tops, top)
		if _, err := h.db.Conn.Exec(ctx, `INSERT INTO comments (cve_id, parent_id, is_reply, author_id, body, lang, links, created_at, updated_at)
			SELECT $1, $2::uuid, true, $3, $4 || g, 'en', true, $5, $5 FROM generate_series(1, 120) g`, cveA, top, ada.id, big,
			h.clock.Now().Add(time.Duration(i)*time.Second+time.Millisecond)); err != nil {
			t.Fatal(err)
		}
	}
	const budget = 512 << 10
	r := h.reader().stream(cveA, "?limit=200")
	size := 0
	for _, c := range r.Comments {
		size += len(c.BodyHTML)
		for _, x := range c.Replies {
			size += len(x.BodyHTML)
		}
	}
	if size > budget {
		t.Errorf("one page holds %d bytes of HTML (budget %d)", size, budget)
	}
	if len(r.Comments) == 0 || r.Comments[0].ID != tops[0] {
		t.Fatalf("first page does not start with the first thread")
	}
}
