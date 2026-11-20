package admin_test

import (
	"context"
	"crypto/md5"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/admin"
	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/testutil"
)

// walk pages a newest-first keyset list to its end and returns its length.
func walk[T, C any](t *testing.T, name string, page func(admin.Keyset[C]) ([]T, *C, *C, error)) int {
	t.Helper()
	n := 0
	var pos admin.Keyset[C]
	for i := 0; ; i++ {
		if i > 100 {
			t.Fatalf("%s: no end", name)
		}
		rows, _, next, err := page(pos)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		n += len(rows)
		if next == nil {
			return n
		}
		pos = admin.Keyset[C]{Older: next}
	}
}

// TestKeysetListTotals: the length of each keyset list (users, audit log,
// patrol list, X posts) agrees with walking it, for each filter; the pages
// say "page X of Y", and a page number past the count is clamped.
func TestKeysetListTotals(t *testing.T) {
	h := newHarness(t, hopt{})
	ctx := context.Background()
	adm := h.user("kim", "admin")
	tom := h.user("tom", "user")
	for i := 0; i < 23; i++ {
		b := h.user(fmt.Sprintf("u%02d", i), "user")
		team := "Team Red"
		if i%3 == 0 {
			team = "Team Blue"
		}
		h.sql(`UPDATE users SET display_name = $2 WHERE id = $1`, b.id, team)
		h.clock.Advance(time.Second)
	}
	for _, q := range []string{"", "red", "BLUE", "team", "nobody", tom.id, "u1", "%", "_"} {
		n, err := h.adm.UsersCount(ctx, q)
		w := walk(t, "users "+q, func(p admin.Keyset[auth.UserCursor]) ([]admin.UserListRow, *auth.UserCursor, *auth.UserCursor, error) {
			return h.adm.Users(ctx, q, p)
		})
		if err != nil || n != w {
			t.Errorf("users %q: counted %d (%v), walked %d", q, n, err, w)
		}
	}

	for i := 0; i < 27; i++ {
		action, actor, role := "user.role", "kim", "admin"
		switch i % 3 {
		case 1:
			action = "comment.hide"
		case 2:
			actor, role = "", "cli"
		}
		h.sql(`INSERT INTO admin_audit (actor_id, actor_handle, actor_role, action, target_type, target_id, source)
			VALUES (CASE WHEN $3 = 'cli' THEN NULL ELSE $1::uuid END, NULLIF($2, ''), $3, $4, 'user', $5,
			        CASE WHEN $3 = 'cli' THEN 'cli' ELSE 'web' END)`,
			adm.id, actor, role, action, []string{adm.id, tom.id}[i%2])
	}
	for _, f := range []audit.Filter{{}, {Action: "user.role"}, {Action: "comment.hide"}, {ActorHandle: "KIM"}, {ActorHandle: "cli"},
		{TargetID: tom.id}, {Action: "user.role", ActorHandle: "kim", TargetID: adm.id}, {Action: "user.suspend"}} {
		n, err := h.adm.AuditCount(ctx, f)
		w := walk(t, fmt.Sprintf("audit %+v", f), func(p admin.Keyset[int64]) ([]audit.Row, *int64, *int64, error) {
			return h.adm.AuditLog(ctx, f, p)
		})
		if err != nil || n != w {
			t.Errorf("audit %+v: counted %d (%v), walked %d", f, n, err, w)
		}
	}

	for i := 0; i < 24; i++ {
		c := h.comment(tom.id, fmt.Sprintf("comment %02d", i))
		switch i % 4 {
		case 1:
			h.sql(`UPDATE comments SET status = 'hidden', hidden_at = now(), hidden_reason = 'spam' WHERE id = $1`, c)
		case 2:
			h.sql(`UPDATE comments SET status = 'deleted', deleted_at = now() WHERE id = $1`, c)
		}
		h.clock.Advance(time.Minute)
	}
	for _, s := range append([]string{""}, admin.CommentStatuses...) {
		n, err := h.adm.RecentCommentsCount(ctx, s)
		w := walk(t, "comments "+s, func(p admin.Keyset[admin.Cursor]) ([]*admin.Comment, *admin.Cursor, *admin.Cursor, error) {
			return h.adm.RecentComments(ctx, s, p)
		})
		if err != nil || n != w || (s == "" && n != 24) {
			t.Errorf("comments %q: counted %d (%v), walked %d", s, n, err, w)
		}
	}

	// posts: one event per CVE of a post (a post on two CVEs is one row)
	h.sql(`INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0002') ON CONFLICT DO NOTHING`)
	for i := 0; i < 25; i++ {
		postID := fmt.Sprintf("1870000000000000%03d", i)
		handle, cves := "alice_sec", []string{cveA}
		if i%2 == 1 {
			handle = "bob_sec"
		}
		if i%5 == 0 {
			cves = append(cves, "CVE-2026-0002")
		}
		detail, _ := json.Marshal(map[string]any{"post_id": postID, "author_id": "1001", "author_handle": handle, "text": "t",
			"lang": "en", "cves": cves})
		for _, c := range cves {
			h.sql(`INSERT INTO event (cve_id, type, occurred_at, observed_at, source, url, detail, dedupe_key)
				VALUES ($1, 'social_post', $2, $2, 'xposts', $3, $4, $5)`, c, h.clock.Now().Add(-time.Duration(i)*time.Minute),
				"https://x.com/"+handle+"/status/"+postID, string(detail), postID)
		}
	}
	for _, f := range [][2]string{{"", ""}, {"alice_sec", ""}, {"BOB_SEC", ""}, {"", "CVE-2026-0002"}, {"bob_sec", "CVE-2026-0002"},
		{"", cveA}, {"nobody", ""}} {
		n, err := h.adm.XPostsCount(ctx, f[0], f[1])
		w := walk(t, "posts "+f[0]+f[1], func(p admin.Keyset[admin.Cursor]) ([]admin.XPost, *admin.Cursor, *admin.Cursor, error) {
			return h.adm.XPosts(ctx, f[0], f[1], p)
		})
		if err != nil || n != w || (f == [2]string{} && n != 25) {
			t.Errorf("posts %v: counted %d (%v), walked %d", f, n, err, w)
		}
	}

	// the pages: 26 accounts (kim, tom and 24 more) on 3 pages
	h.user("zed", "user")
	r := region(t, page(t, adm, "/admin/users"), "r-users")
	if !strings.Contains(r, `<span class="sr">page 1 of 3</span>`) {
		t.Errorf("users page 1:\n%s", r)
	}
	next := link(r, "next")
	if r = region(t, page(t, adm, next), "r-users"); !strings.Contains(r, `<span class="sr">page 2 of 3</span>`) {
		t.Errorf("users page 2:\n%s", r)
	}
	// ?p= only labels the page: past the count it is the last page that
	// still has a next one (page 2 of 3 here), and the links go on from it
	r = region(t, page(t, adm, strings.Replace(next, "p=2", "p=99", 1)), "r-users")
	if !strings.Contains(r, `<span class="sr">page 2 of 3</span>`) || !strings.Contains(link(r, "next"), "p=3") {
		t.Errorf("users page 2 labelled 99:\n%s", r)
	}
	if r = region(t, page(t, adm, link(r, "next")), "r-users"); !strings.Contains(r, `<span class="sr">page 3 of 3</span>`) || link(r, "next") != "" {
		t.Errorf("users page 3:\n%s", r)
	}
	// a filter changes the count: 8 blue accounts fit on one page
	if r = region(t, page(t, adm, "/admin/users?q=blue"), "r-users"); strings.Contains(r, `class="pager"`) {
		t.Errorf("one page of blue accounts has a pager:\n%s", r)
	}
	// the audit log (27 rows: 3 pages), the patrol list (24: 3), posts (25 + the fixture's: 3)
	if r = region(t, page(t, adm, "/admin/audit"), "r-audit"); !strings.Contains(r, `<span class="sr">page 1 of 3</span>`) {
		t.Errorf("audit page 1:\n%s", r)
	}
	if r = region(t, page(t, adm, "/admin/audit?action=comment_hide"), "r-audit"); strings.Contains(r, `class="pager"`) {
		t.Errorf("9 comment.hide rows have a pager:\n%s", r)
	}
	if r = region(t, page(t, adm, "/admin/moderation"), "r-recent"); !strings.Contains(r, `<span class="sr">page 1 of 3</span>`) {
		t.Errorf("patrol page 1:\n%s", r)
	}
	if r = region(t, page(t, adm, "/admin/moderation?status=visible"), "r-recent"); !strings.Contains(r, `<span class="sr">page 1 of 2</span>`) {
		t.Errorf("patrol visible page 1 (12 comments):\n%s", r)
	}
}

// TestAuditCountPlans: the audit log's counts by action and by actor walk
// their indexes; the whole log and a target alone are one pass (logged).
// 20,000 synthetic rows; production timings still have to be taken there.
func TestAuditCountPlans(t *testing.T) {
	if testing.Short() {
		t.Skip("short")
	}
	t.Parallel()
	ctx := context.Background()
	d := testutil.NewMigratedDB(t)
	if _, err := d.Conn.Exec(ctx, `INSERT INTO admin_audit (actor_handle, actor_role, action, target_type, target_id, source, at)
		SELECT 'staff' || (i % 12), 'cli', (ARRAY['user.role','comment.hide','comment.unhide','x.draft.save','report.resolve'])[1 + i % 5],
		       'user', md5(i::text), 'cli', timestamptz '2026-11-01' - i * interval '1 minute'
		FROM generate_series(1, 20000) i;
		ANALYZE admin_audit`); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		f    audit.Filter
		idx  string // "" = logged only
	}{
		{"action", audit.Filter{Action: "comment.hide"}, "admin_audit_action_idx"},
		{"actor", audit.Filter{ActorHandle: "Staff3"}, "admin_audit_actor_idx"},
		{"action + actor", audit.Filter{Action: "comment.hide", ActorHandle: "staff3"}, "admin_audit_"},
		{"whole log", audit.Filter{}, ""},
		{"target", audit.Filter{TargetID: md5hex("7")}, ""},
	} {
		sql, args := audit.CountSQL(c.f)
		rows, err := d.Conn.Query(ctx, "EXPLAIN "+sql, args...)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		var lines []string
		for rows.Next() {
			var l string
			if err := rows.Scan(&l); err != nil {
				t.Fatal(err)
			}
			lines = append(lines, l)
		}
		rows.Close()
		plan := strings.Join(lines, "\n")
		if c.idx != "" && (strings.Contains(plan, "Seq Scan on admin_audit") || !strings.Contains(plan, c.idx)) {
			t.Errorf("%s: want a walk of %s:\n%s", c.name, c.idx, plan)
		} else {
			t.Logf("%s:\n%s", c.name, plan)
		}
	}
}

func md5hex(s string) string { return fmt.Sprintf("%x", md5.Sum([]byte(s))) }
