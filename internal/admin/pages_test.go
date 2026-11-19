package admin_test

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// adminElems are the elements the admin pages (and the shared chrome) may
// contain; an injected element fails checkHTML.
var adminElems = map[string]bool{}

func init() {
	for _, e := range strings.Fields(`html head meta title link script body header div a nav form span input kbd details summary ul li
		main p h1 h2 h3 section dl dt dd table thead tbody tr th td code bdi br article pre button label select option textarea
		figure figcaption svg rect footer b template time strong em blockquote ol dialog`) {
		adminElems[e] = true
	}
}

// TestModeratorView: the moderator's user page carries none of the
// admin-only data (asserted on the raw bytes), the admin's does.
func TestModeratorView(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	mod := h.user("mia", "moderator")
	target := h.user("tom", "user")
	h.sql(`UPDATE users SET status = 'suspended', suspended_until = $2, status_reason = 'REASON-SECRET-7' WHERE id = $1`,
		target.id, h.clock.Now().Add(48*time.Hour))
	h.sql(`INSERT INTO passkeys (user_id, credential_id, public_key, algorithm, backup_eligible, backed_up, name) VALUES ($1, '\x0102', '\x03', -7, false, false, 'PASSKEY-NAME-1')`, target.id)
	c := h.comment(target.id, "a comment by tom")
	h.report(c, adm.id, "spam", nil) // filed by the admin, about tom
	tc := h.comment(adm.id, "the admin's comment")
	h.report(tc, target.id, "other", ptr("FILED-NOTE-9")) // filed by tom
	h.sql(`INSERT INTO admin_audit (actor_id, actor_handle, actor_role, action, target_type, target_id, source, client_addr, cf_ray)
		VALUES ($1, 'kim', 'admin', 'user.role', 'user', $2, 'web', '203.0.113.99', 'RAY-SECRET-1')`, adm.id, target.id)
	resp, body := mod.do("GET", "/admin/users/"+target.id, "")
	if resp.StatusCode != 200 {
		t.Fatalf("moderator view: %d", resp.StatusCode)
	}
	s := string(body)
	for _, secret := range []string{"tom-gh", // name at the provider
		"REASON-SECRET-7", "PASSKEY-NAME-1", "FILED-NOTE-9", "203.0.113.99", "RAY-SECRET-1", // reason, passkey, filed report, audit
		`id="h-methods"`, `id="h-actions"`, `id="h-rfiled"`, `id="h-audit"`, `id="reauth"`, "data-reauth", "/api/admin/",
		"9001", "9002", "9003", // provider subjects of the personas
	} {
		if strings.Contains(s, secret) {
			t.Errorf("moderator view contains %q", secret)
		}
	}
	for _, want := range []string{"@tom", "a comment by tom", `id="h-rabout"`} {
		if !strings.Contains(s, want) {
			t.Errorf("moderator view lacks %q", want)
		}
	}
	// the moderator cannot reach the full view any other way
	if resp, _ := mod.do("GET", "/admin/users?q=tom", ""); resp.StatusCode != 404 {
		t.Errorf("moderator user list: %d", resp.StatusCode)
	}
	_, body = adm.do("GET", "/admin/users/"+target.id, "")
	s = string(body)
	for _, want := range []string{"tom-gh", "REASON-SECRET-7", "FILED-NOTE-9", "203.0.113.99", `id="h-actions"`, `id="reauth"`,
		`<dialog class="dlg" id="reauth" aria-labelledby="reauth-h">`} {
		if !strings.Contains(s, want) {
			t.Errorf("admin view lacks %q", want)
		}
	}
	if strings.Contains(s, "PASSKEY-NAME-1") {
		t.Error("admin view shows a passkey name (only the count is shown)")
	}
}

func ptr(s string) *string { return &s }

// TestHostileData: attacker-controlled strings everywhere they can reach the
// admin pages (display names, reasons, notes, earlier comment versions,
// comment bodies, audit labels and details, statistics keys, log records)
// come out as text: the pages stay well-formed, no element or attribute is
// injected, and bidi controls stay inside isolating elements.
func TestHostileData(t *testing.T) {
	dir := t.TempDir()
	h := newHarness(t, hopt{logDir: dir})
	adm := h.user("kim", "admin")
	mod := h.user("mia", "moderator")
	evil := h.user("eve", "user")
	payloads := []string{
		`<script>alert(1)</script>`, `"><img src=x onerror=alert(2)>`, `'><svg onload=alert(3)>`, `</textarea><b>x</b>`,
		"‮RTL override‬ and ⁦isolate", `javascript:alert(4)`, `{{.}} ${x} {name}`, `&amp;&lt;`,
		strings.Repeat("W", 3000), "]]><!--", "ctl\x01\x1b[31m\u0085",
	}
	p := func(i int) string { return payloads[i%len(payloads)] }
	h.sql(`UPDATE users SET display_name = $2, status = 'suspended', status_reason = $3 WHERE id = $1`, evil.id, trunc(p(1)+p(4), 60), trunc(p(0)+p(4)+p(8), 500))
	h.sql(`UPDATE identities SET handle = $2 WHERE user_id = $1`, evil.id, p(2))
	var cids []string
	for i := range payloads {
		cid := h.comment(evil.id, "body "+p(i)+"\n\n"+p(i+4)+" CVE-2026-0001 https://evil.example/\""+p(i))
		cids = append(cids, cid)
		h.sql(`INSERT INTO comment_revisions (comment_id, body, replaced_at) VALUES ($1, $2, now())`, cid, "old "+p(i)+p(4))
		h.sql(`UPDATE comments SET edited_at = now() WHERE id = $1`, cid)
		note := trunc(p(i)+p(4), 400)
		h.report(cid, mod.id, "other", &note)
		h.sql(`INSERT INTO admin_audit (actor_id, actor_handle, actor_role, action, target_type, target_id, target_label, reason, details, source, client_addr, cf_ray)
			VALUES ($1, 'kim', 'admin', 'comment.hide', 'comment', $2, $3, $4, jsonb_build_object('cve', $5::text, 'x', $6::text), 'web', $7, $8)`,
			adm.id, cid, trunc(p(i), 200), trunc(p(i)+p(4), 500), trunc(p(i), 300), trunc(p(i), 300), trunc(p(i), 64), trunc(p(i+1), 64))
	}
	h.sql(`UPDATE comments SET status = 'hidden', hidden_reason = $2, hidden_at = now(), hidden_by = $3 WHERE id = $1`, cids[0], trunc(p(0)+p(4), 200), mod.id)
	today := time.Now().UTC().Format("2006-01-02")
	day := h.clock.Now().Format("2006-01-02")
	for i, k := range payloads {
		for _, kind := range []string{"search", "referrer_host", "not_found_human", "bot_ua", "country", "vuln_page"} {
			h.sql(`INSERT INTO stats_top (day, kind, key, value) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, day, kind, trunc(k, 2000), 10+i)
		}
		h.sql(`INSERT INTO stats_daily (day, metric, dim, value) VALUES ($1, 'pv_locale', $2, 3), ($1, 'api_endpoint', $2, 4) ON CONFLICT DO NOTHING`,
			day, "all:"+trunc(k, 200))
	}
	h.sql(`INSERT INTO stats_files (file, day, size, mtime, lines, bad_lines) VALUES ($1, $2, 10, now(), 10, 1)`, "access-"+day+".log", day)
	h.sql(`INSERT INTO collector_state (source, last_status, last_error, last_run_at) VALUES ('kev', 'error', $1, now())`, p(0)+p(4))
	var log strings.Builder
	for _, k := range payloads {
		log.WriteString(`{"time":"` + strings.ReplaceAll(trunc(k, 30), `"`, `\"`) + `","level":"ERROR","msg":` + jsonString(k) + `,"path":` + jsonString(k) + "}\n")
	}
	log.WriteString("garbage \xff\xfe not json\n")
	for _, name := range []string{"error-" + today + ".log", "error-" + day + ".log"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(log.String()), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pages := []string{"/admin", "/admin?days=90", "/admin/moderation", "/admin/moderation?status=hidden", "/admin/users",
		"/admin/users?q=" + "%3Cscript%3E", "/admin/users/" + evil.id, "/admin/system", "/admin/audit", "/admin/audit?actor=%22%3E%3Cb%3E&target=x",
		"/zh-hans/admin/moderation", "/zh-hans/admin/users/" + evil.id}
	for _, pg := range pages {
		resp, body := adm.do("GET", pg, "")
		if resp.StatusCode != 200 {
			t.Errorf("%s: %d", pg, resp.StatusCode)
			continue
		}
		s := string(body)
		for _, pr := range checkHTML(s, adminElems) {
			t.Errorf("%s: %s", pg, pr)
		}
		// (injected attributes and elements are caught by checkHTML; these
		// are the raw forms of the payloads)
		if strings.Contains(s, "<script>alert") || strings.Contains(s, "<img") || strings.Contains(s, "<svg onload") ||
			strings.Contains(s, "<b>x</b>") || strings.Contains(s, `href="javascript`) || strings.Contains(s, "]]><!--") {
			t.Errorf("%s: markup injected", pg)
		}
		if n := strings.Count(s, "<script"); n != 3 { // theme.js, app.js and admin.js
			t.Errorf("%s: %d script elements", pg, n)
		}
	}
	// the moderator's pages too
	for _, pg := range []string{"/admin/moderation", "/admin/users/" + evil.id} {
		_, body := mod.do("GET", pg, "")
		for _, pr := range checkHTML(string(body), adminElems) {
			t.Errorf("moderator %s: %s", pg, pr)
		}
	}
	// the hostile values did reach the pages (as text)
	_, body := adm.do("GET", "/admin/system", "")
	if !strings.Contains(string(body), "&lt;script&gt;alert(1)&lt;/script&gt;") {
		t.Error("system page: escaped payload not found (log records or collector error not shown?)")
	}
	_ = context.Background()
}

func jsonString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20:
			b.WriteString(`\u00`)
			b.WriteByte("0123456789abcdef"[r>>4])
			b.WriteByte("0123456789abcdef"[r&15])
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// TestModerationPage: open reports grouped by comment (reasons, reporters,
// notes, earlier versions as text), the patrol list with its filter and
// paging, the permalinks, and the controls the script uses.
func TestModerationPage(t *testing.T) {
	h := newHarness(t, hopt{})
	mod := h.user("mia", "moderator")
	r1 := h.user("rex", "user")
	r2 := h.user("roy", "user")
	author := h.user("tom", "user")
	c := h.comment(author.id, "current *text*")
	h.sql(`INSERT INTO comment_revisions (comment_id, body, replaced_at) VALUES ($1, 'first <b>version</b>', now() - interval '2 hours'),
		($1, 'second version', now() - interval '1 hour')`, c)
	h.sql(`UPDATE comments SET edited_at = now() WHERE id = $1`, c)
	a := h.report(c, r1.id, "spam", ptr("ad for pills"))
	h.clock.Advance(time.Second)
	b := h.report(c, r2.id, "spam", nil)
	other := h.comment(author.id, "hidden one")
	h.sql(`UPDATE comments SET status = 'hidden', hidden_reason = 'rude', hidden_at = now(), hidden_by = $2 WHERE id = $1`, other, mod.id)
	for i := 0; i < 55; i++ {
		h.clock.Advance(time.Second)
		h.comment(r1.id, "filler")
	}
	_, body := mod.do("GET", "/admin/moderation", "")
	s := string(body)
	for _, want := range []string{
		`data-act="dismiss" data-reports="` + a + ` ` + b + `"`, `data-act="hide" data-id="` + c + `"`,
		"<em>text</em>", "edited 2 times", "2 earlier versions", "first &lt;b&gt;version&lt;/b&gt;", "2 reports", "from 2 accounts",
		"ad for pills", `href="/vuln/CVE-2026-0001?c=` + c + `#c-` + c + `"`, `href="/admin/users/` + author.id + `"`,
		`?rc=`, "spam or advertising",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("moderation page lacks %q", want)
		}
	}
	_, body = mod.do("GET", "/admin/moderation?status=hidden", "")
	if s := string(body); !strings.Contains(s, "hidden one") || strings.Contains(s, "filler") ||
		!strings.Contains(s, `data-act="unhide" data-id="`+other+`"`) || !strings.Contains(s, "Hidden: <bdi>rude</bdi> (by @<bdi>mia</bdi>)") {
		t.Error("status filter / hidden comment")
	}
	_, body = mod.do("GET", "/admin/moderation?status=bogus&rc=garbage&qc=%00", "")
	if !strings.Contains(string(body), "filler") {
		t.Error("bad filter/cursor values fall back to the first page")
	}
	// public pages are the same for everyone and only carry the slot hook
	anon := h.browser()
	_, pa := anon.do("GET", "/src", "")
	_, pm := mod.do("GET", "/src", "")
	if string(pa) != string(pm) || !strings.Contains(string(pa), `data-admin="/admin"`) {
		t.Error("public page differs for staff, or lacks data-admin")
	}
}
