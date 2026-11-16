package admin_test

import (
	"strings"
	"testing"

	"nday.land/nday/internal/auth"
)

// TestCorrectionsPage: /admin/corrections is for staff (moderators and
// admins), lists the open queue and the decided corrections, shows every
// user-entered text escaped, the evidence link only when it is an
// absolute http(s) URL, and the decision forms only for open ones.
func TestCorrectionsPage(t *testing.T) {
	h := newHarness(t, hopt{})
	sub := h.user("ada", auth.RoleUser)
	mod := h.user("mia", auth.RoleModerator)
	adm := h.user("boss", auth.RoleAdmin)
	plain := h.user("bob", auth.RoleUser)
	h.sql(`INSERT INTO vuln_corrections (id, cve_id, submitter_id, category, body, evidence_url, created_at)
		VALUES ('11111111-1111-4111-8111-111111111111', $1, $2, 'fix', '<script>alert("body")</script> QZPENDING', 'https://example.com/"><b>x</b>', $3)`,
		cveA, sub.id, h.clock.Now())
	h.sql(`INSERT INTO vuln_corrections (id, cve_id, submitter_id, category, body, evidence_url, status, created_at, decided_at, decided_by, internal_note)
		VALUES ('22222222-2222-4222-8222-222222222222', $1, $2, 'title', 'QZREJECTED body', 'https://bad host/<u>QZLINK</u>', 'rejected', $3, $3, $4, '<i>QZINTERNAL</i>')`,
		cveA, sub.id, h.clock.Now(), mod.id)
	h.sql(`INSERT INTO vuln_corrections (id, cve_id, submitter_id, category, body, status, created_at, decided_at, decided_by, public_note)
		VALUES ('33333333-3333-4333-8333-333333333333', $1, $2, 'summary', 'QZACCEPTED body', 'accepted', $3, $3, $4, '<b>QZPUBLIC</b>')`,
		cveA, sub.id, h.clock.Now(), mod.id)

	// access: like the moderation page
	if resp, _ := h.browser().do("GET", "/admin/corrections", ""); resp.StatusCode != 302 ||
		!strings.HasPrefix(resp.Header.Get("Location"), "/login?return=") {
		t.Errorf("signed out: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	if resp, _ := plain.do("GET", "/admin/corrections", ""); resp.StatusCode != 404 {
		t.Errorf("plain user: %d", resp.StatusCode)
	}
	h.suspend(adm.id)
	if resp, _ := adm.do("GET", "/admin/corrections", ""); resp.StatusCode != 404 {
		t.Errorf("suspended admin: %d", resp.StatusCode)
	}
	h.suspend(mod.id)
	if resp, _ := mod.do("GET", "/admin/corrections", ""); resp.StatusCode != 404 {
		t.Errorf("suspended moderator: %d", resp.StatusCode)
	}
	h.sql(`UPDATE users SET status = 'active', suspended_until = NULL, status_reason = NULL WHERE id IN ($1, $2)`, adm.id, mod.id)

	resp, b := mod.do("GET", "/admin/corrections", "")
	page := string(b)
	if resp.StatusCode != 200 {
		t.Fatalf("moderator: %d", resp.StatusCode)
	}
	for _, want := range []string{
		`&lt;script&gt;alert(&#34;body&#34;)&lt;/script&gt; QZPENDING`,
		`data-act="accept" data-id="11111111-1111-4111-8111-111111111111"`,
		`data-act="reject" data-id="11111111-1111-4111-8111-111111111111"`,
		`href="https://example.com/%22%3E%3Cb%3Ex%3C/b%3E"`, // the evidence link, escaped
		`href="/vuln/` + cveA + `"`,
		`href="/admin/corrections"`, // the nav tab
		`waiting (1)`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("pending list lacks %q", want)
		}
	}
	for _, bad := range []string{"<script>alert", "QZREJECTED", "QZACCEPTED", "<b>x</b>"} {
		if strings.Contains(page, bad) {
			t.Errorf("pending list contains %q", bad)
		}
	}

	_, b = adm.do("GET", "/admin/corrections?state=decided", "")
	page = string(b)
	for _, want := range []string{"QZREJECTED body", "QZACCEPTED body", "&lt;i&gt;QZINTERNAL&lt;/i&gt;", "&lt;b&gt;QZPUBLIC&lt;/b&gt;", "https://bad host/&lt;u&gt;QZLINK&lt;/u&gt;",
		`id="k-22222222-2222-4222-8222-222222222222"`, "@mia"} {
		if !strings.Contains(page, want) {
			t.Errorf("decided list lacks %q", want)
		}
	}
	for _, bad := range []string{`href="https://bad`, "<u>QZLINK", "<i>QZINTERNAL", "<b>QZPUBLIC", "QZPENDING", `data-act="accept"`} {
		if strings.Contains(page, bad) {
			t.Errorf("decided list contains %q", bad)
		}
	}
}
