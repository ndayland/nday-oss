package corrections_test

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/corrections"
	"nday.land/nday/internal/discuss"
)

// TestVulnQueueIgnoresSuspendedAndDeleted: the per-vulnerability cap of
// open corrections does not count those whose submitter is suspended now
// (with or without an end) or deleted the account, so a few accounts that
// filled the queue and were then suspended or deleted do not keep others
// out; when a suspension ends, its corrections count again (the same rule
// as auth.User.EffectiveStatus, without the housekeeping having run).
func TestVulnQueueIgnoresSuspendedAndDeleted(t *testing.T) {
	lim := corrections.Limits{Daily: 100, OpenPerVuln: 3, OpenPerUser: 3, Burst: 1000, Every: time.Millisecond}
	h := newHarness(t, "", &lim)
	ctx := context.Background()
	s1, s2 := h.member("spam1"), h.member("spam2")
	o1, o2, o3, o4 := h.member("ola"), h.member("oli"), h.member("oma"), h.member("ove")
	path := "/api/corrections/" + cveA
	req := jsonOf(map[string]any{"category": "title", "body": "x"})
	full := func(what string, b *browser) {
		t.Helper()
		resp, body := b.post(path, req)
		expect(t, what, resp, body, 409, "queue_full")
	}

	s1.submit(cveA, "title", "spam a", nil)
	s1.submit(cveA, "title", "spam b", nil)
	s2.submit(cveA, "title", "spam c", nil)
	full("queue filled by two accounts", o1)

	// s1 suspended for a day: its two no longer count
	until := h.clock.Now().Add(24 * time.Hour)
	if err := h.as.Suspend(ctx, s1.id, &until, "spam"); err != nil {
		t.Fatal(err)
	}
	o1.submit(cveA, "title", "real 1", nil)
	o2.submit(cveA, "title", "real 2", nil)
	full("full again (s2 + two others)", o3)

	// s2's account deleted (submitter_id NULL): its one no longer counts
	if _, err := h.db.Conn.Exec(ctx, `DELETE FROM users WHERE id = $1`, s2.id); err != nil {
		t.Fatal(err)
	}
	if n := h.count(`SELECT count(*) FROM vuln_corrections WHERE submitter_id IS NULL AND status = 'pending'`); n != 1 {
		t.Fatalf("%d pending corrections without submitter, want 1", n)
	}
	o3.submit(cveA, "title", "real 3", nil)
	full("full with three counted", o4)

	// the suspension ends (users.status still 'suspended': no housekeeping):
	// s1's two count again
	h.clock.Advance(25 * time.Hour)
	if n := h.count(`SELECT count(*) FROM users WHERE id = $1 AND status = 'suspended'`, s1.id); n != 1 {
		t.Fatal("the suspension was lifted in the table; the test needs it elapsed only")
	}
	full("elapsed suspension counts again", o4)

	// suspended without an end: s1 and o1 out, two counted, room for one
	if err := h.as.Suspend(ctx, s1.id, nil, "spam"); err != nil {
		t.Fatal(err)
	}
	if err := h.as.Suspend(ctx, o1.id, nil, "test"); err != nil {
		t.Fatal(err)
	}
	o4.submit(cveA, "title", "real 4", nil)
	full("full again", o2)

	// the cap of another vulnerability is separate; nothing was lost
	if n := h.count(`SELECT count(*) FROM vuln_corrections WHERE cve_id = $1 AND status = 'pending'`, cveA); n != 7 {
		t.Errorf("%d pending corrections on A, want 7", n)
	}
}

// TestNewAccountSubmit: the discussion's new-account rule (younger than
// NewAccountAge, or fewer than NewAccountComments contributions: visible
// comments plus accepted corrections) applies to submissions: a new
// account may have one open correction per vulnerability and at most
// NewPostDaily submissions a day; the rule is read at each submission.
func TestNewAccountSubmit(t *testing.T) {
	lim := corrections.Limits{Daily: 100, OpenPerVuln: 100, OpenPerUser: 3, Burst: 1000, Every: time.Millisecond}
	h := newHarness(t, "", &lim)
	ctx := context.Background()
	if _, err := h.db.Conn.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ('CVE-2026-0003')`); err != nil {
		t.Fatal(err)
	}
	nl := discuss.DefaultLimits() // 24h, 3 contributions, 10 a day
	nl.NewPostDaily = 2
	h.newAcct.Store(&nl)
	req := jsonOf(map[string]any{"category": "title", "body": "x"})

	fresh := h.member("neo")
	fresh.submit(cveA, "title", "one", nil)
	resp, b := fresh.post("/api/corrections/"+cveA, req)
	expect(t, "new account, second open on one vuln", resp, b, 409, "too_many_open")
	fresh.submit(cveB, "title", "two", nil)
	resp, b = fresh.post("/api/corrections/CVE-2026-0003", req)
	expect(t, "new account, daily cap", resp, b, 429, "daily_limit")

	// old, but without contributions: still new
	old := h.member("old")
	if _, err := h.db.Conn.Exec(ctx, `UPDATE users SET created_at = $2 WHERE id = $1`, old.id, h.clock.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	old.submit(cveA, "title", "old one", nil)
	resp, b = old.post("/api/corrections/"+cveA, req)
	expect(t, "old account without contributions", resp, b, 409, "too_many_open")
	// three visible comments: no longer new
	for i := 0; i < 3; i++ {
		if _, err := h.db.Conn.Exec(ctx, `INSERT INTO comments (cve_id, is_reply, author_id, body, lang, links, created_at, updated_at)
			VALUES ($1, false, $2, $3, 'en', true, $4, $4)`, cveB, old.id, "seed "+string(rune('a'+i)), h.clock.Now().Add(-47*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	old.submit(cveA, "title", "old two", nil)
	old.submit(cveA, "title", "old three", nil)
	old.submit(cveB, "title", "old four", nil) // past NewPostDaily: the normal cap applies

	// accepted corrections count as contributions too
	acc := h.member("acc")
	if _, err := h.db.Conn.Exec(ctx, `UPDATE users SET created_at = $2 WHERE id = $1`, acc.id, h.clock.Now().Add(-48*time.Hour)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if _, err := h.db.Conn.Exec(ctx, `INSERT INTO vuln_corrections (cve_id, submitter_id, category, body, status, created_at, decided_at, public_note)
			VALUES ($1, $2, 'title', 'x', 'accepted', $3, $3, 'ok')`, cveB, acc.id, h.clock.Now().Add(-47*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	acc.submit(cveA, "title", "acc one", nil)
	acc.submit(cveA, "title", "acc two", nil)

	// young account with contributions: new by age
	young := h.member("yun")
	for i := 0; i < 3; i++ {
		if _, err := h.db.Conn.Exec(ctx, `INSERT INTO comments (cve_id, is_reply, author_id, body, lang, links, created_at, updated_at)
			VALUES ($1, false, $2, $3, 'en', true, $4, $4)`, cveB, young.id, "seed "+string(rune('a'+i)), h.clock.Now()); err != nil {
			t.Fatal(err)
		}
	}
	young.submit(cveA, "title", "young one", nil)
	resp, b = young.post("/api/corrections/"+cveA, req)
	expect(t, "young account with comments", resp, b, 409, "too_many_open")

	// the rule as configured now (e.g. /admin/settings): off
	off := nl
	off.NewAccountAge, off.NewAccountComments = 0, 0
	h.newAcct.Store(&off)
	young.submit(cveA, "title", "young two", nil)
	fresh.submit(cveA, "title", "fresh again", nil)
}

// TestAcceptAuditFullNote: the audit row of an accept holds the whole
// public note (details.public_note) even at MaxPublicNote characters of
// the widest kinds (4-byte characters, characters JSON escapes), which is
// more than reason (MaxReason) and the general details limit allow.
func TestAcceptAuditFullNote(t *testing.T) {
	h := newHarness(t, "", nil)
	sub, mod := h.member("ada"), h.moderator("mia")
	c := sub.submit(cveA, "fix", "x", nil)
	note := strings.Repeat("<长😀&", corrections.MaxPublicNote/4)
	if utf8.RuneCountInString(note) != corrections.MaxPublicNote {
		t.Fatalf("note has %d characters", utf8.RuneCountInString(note))
	}
	resp, b := mod.post("/api/corrections/item/"+c.ID+"/accept", jsonOf(map[string]string{"note": note}))
	expect(t, "accept", resp, b, 200, "")
	var got, reason string
	var size int
	if err := h.db.Conn.QueryRow(context.Background(), `SELECT details->>'public_note', reason, octet_length(details::text)
		FROM admin_audit WHERE action = $1 AND target_id = $2`, audit.CorrectionAccept, c.ID).Scan(&got, &reason, &size); err != nil {
		t.Fatal(err)
	}
	if got != note {
		t.Errorf("details.public_note has %d characters, want the whole note (%d)", utf8.RuneCountInString(got), utf8.RuneCountInString(note))
	}
	if size <= audit.MaxDetails {
		t.Errorf("details are %d bytes; the test means to exceed the general limit %d", size, audit.MaxDetails)
	}
	if utf8.RuneCountInString(reason) != audit.MaxReason || !strings.HasPrefix(note, reason) {
		t.Errorf("reason: %d characters, a prefix of the note: %v", utf8.RuneCountInString(reason), strings.HasPrefix(note, reason))
	}
	// the general limit still holds for other targets
	if _, err := h.db.Conn.Exec(context.Background(), `INSERT INTO admin_audit (actor_role, action, target_type, target_id, details, source)
		VALUES ('cli', 'user.role', 'user', 'x', jsonb_build_object('n', $1::text), 'cli')`, strings.Repeat("x", 3000)); err == nil {
		t.Error("a 3000-byte details object was stored for a user target")
	}
}

// TestPublicLogSuspendedSubmitter: the public revision log shows no handle
// while the submitter is suspended (with or without an end), the handle
// again when the suspension has elapsed (EffectiveStatus, without the
// housekeeping) or is lifted, and marks only a deleted account as deleted.
func TestPublicLogSuspendedSubmitter(t *testing.T) {
	h := newHarness(t, "", nil)
	ctx := context.Background()
	sub, mod := h.member("ada"), h.moderator("mia")
	c := sub.submit(cveA, "fix", "x", nil)
	resp, b := mod.post("/api/corrections/item/"+c.ID+"/accept", `{"note":"confirmed"}`)
	expect(t, "accept", resp, b, 200, "")
	st := h.site.WithClock(h.clock.Now)
	check := func(what string, handle string, deleted bool) {
		t.Helper()
		pub, err := st.Corrections(ctx, cveA)
		if err != nil {
			t.Fatal(err)
		}
		if len(pub) != 1 {
			t.Fatalf("%s: %+v", what, pub)
		}
		got := ""
		if pub[0].Handle != nil {
			got = *pub[0].Handle
		}
		if got != handle || pub[0].Deleted != deleted || pub[0].Note != "confirmed" {
			t.Errorf("%s: handle %q deleted %v, want %q %v", what, got, pub[0].Deleted, handle, deleted)
		}
	}
	check("active", "ada", false)
	until := h.clock.Now().Add(24 * time.Hour)
	if err := h.as.Suspend(ctx, sub.id, &until, "spam"); err != nil {
		t.Fatal(err)
	}
	check("suspended for a day", "", false)
	h.clock.Advance(24 * time.Hour) // the end itself: active again
	check("suspension elapsed", "ada", false)
	if err := h.as.Suspend(ctx, sub.id, nil, "spam"); err != nil {
		t.Fatal(err)
	}
	check("suspended without an end", "", false)
	if err := h.as.Unsuspend(ctx, sub.id); err != nil {
		t.Fatal(err)
	}
	check("unsuspended", "ada", false)
	if _, err := h.db.Conn.Exec(ctx, `DELETE FROM users WHERE id = $1`, sub.id); err != nil {
		t.Fatal(err)
	}
	check("deleted", "", true)
}
