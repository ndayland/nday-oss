package webui_test

import (
	"context"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site/sitetest"
)

// TestCorrectionsOnVulnPage: the revision log of a vulnerability page lists
// the ACCEPTED corrections only (time, category, the editor's note escaped,
// the submitter's handle), is absent without any, and the page is the same
// bytes signed in and out. Pending and rejected corrections, submitters'
// texts, evidence links and internal notes are on no public response.
func TestCorrectionsOnVulnPage(t *testing.T) {
	e, conn := newMemberEnv(t, false)
	_, uid := e.signIn(t, "7001", "corrector")
	cookies, _ := e.signIn(t, "7002", "reader")
	ctx := context.Background()
	at := sitetest.Now.Add(-3 * time.Hour)
	ins := func(status, body string, note, internal *string) {
		t.Helper()
		var decided any
		if status != "pending" {
			decided = at
		}
		if _, err := conn.Exec(ctx, `INSERT INTO vuln_corrections (cve_id, submitter_id, category, body, evidence_url, status,
				created_at, decided_at, public_note, internal_note) VALUES ($1, $2, 'fix', $3, 'https://example.com/QZLINK', $4, $5, $6, $7, $8)`,
			sitetest.GPU, uid, body, status, at, decided, note, internal); err != nil {
			t.Fatal(err)
		}
	}
	note := `Fixed version is 2.4.1 <script>alert("QZ")</script> & "quoted"`
	ins("accepted", "QZBODY-ACCEPTED", &note, nil)
	ins("pending", "QZBODY-PENDING", nil, nil)
	ins("rejected", "QZBODY-REJECTED", nil, sitetestP("QZINTERNAL"))

	_, out := e.fetch(t, wwwHost, "/vuln/"+sitetest.GPU, nil)
	_, in := e.fetch(t, wwwHost, "/vuln/"+sitetest.GPU, cookies)
	if out != in {
		t.Error("the vulnerability page differs for a signed-in visitor")
	}
	log := between(t, out, `<section class="sec corr-log" id="revisions"`, "</section>")
	for _, want := range []string{"Revision log", "1 accepted correction", "fix information",
		`Fixed version is 2.4.1 &lt;script&gt;alert(&#34;QZ&#34;)&lt;/script&gt; &amp; &#34;quoted&#34;`, "reported by @corrector",
		`<time datetime="` + at.UTC().Format("2006-01-02T15:04:05Z07:00") + `"`, "do not change the data above"} {
		if !strings.Contains(log, want) {
			t.Errorf("revision log lacks %q:\n%s", want, log)
		}
	}
	entry := between(t, out, `<section class="sec corr" id="correction"`, "</section>")
	for _, want := range []string{`data-cve="` + sitetest.GPU + `"`, `id="corr-form" hidden=""`, `id="corr-out" hidden=""`,
		`href="/login?return=` + url.QueryEscape("/vuln/"+sitetest.GPU+"?correction") + `"`, "Upstream data is not changed", `<details class="corr-d" id="corr-d">`,
		`<option value="affected">affected products or versions</option>`} {
		if !strings.Contains(entry, want) {
			t.Errorf("entry lacks %q:\n%s", want, entry)
		}
	}
	if !strings.Contains(out, "/static/corrections.") {
		t.Error("the page does not load corrections.js")
	}

	// localized
	_, zh := e.fetch(t, wwwHost, "/zh-hans/vuln/"+sitetest.GPU, nil)
	if !strings.Contains(zh, "修订记录") || !strings.Contains(zh, "由 @corrector 报告") || !strings.Contains(zh, "上游数据不会被改动") {
		t.Error("zh-Hans page lacks the corrections words")
	}

	// nothing but the accepted note leaks, anywhere public
	markers := []string{"QZBODY", "QZLINK", "QZINTERNAL", "<script>alert(\"QZ\")"}
	paths := []struct{ host, path string }{
		{wwwHost, "/vuln/" + sitetest.GPU}, {wwwHost, "/ja/vuln/" + sitetest.GPU}, {wwwHost, "/feed.xml"},
		{wwwHost, "/vuln?q=BODY-PENDING"}, {wwwHost, "/sitemap.xml"}, {wwwHost, "/"},
		{apiHost, "/v1/vuln/" + sitetest.GPU}, {apiHost, "/v1/search?q=BODY-REJECTED"}, {apiHost, "/v1/hot"},
		{wwwHost, "/api/discuss/" + sitetest.GPU}, {wwwHost, "/api/posts/" + sitetest.GPU},
	}
	for _, p := range paths {
		_, body := e.fetch(t, p.host, p.path, nil)
		_, body2 := e.fetch(t, p.host, p.path, cookies)
		for _, m := range markers {
			if strings.Contains(body, m) || strings.Contains(body2, m) {
				t.Errorf("%s%s contains %q", p.host, p.path, m)
			}
		}
	}

	// a vulnerability without accepted corrections has no log, but the entry
	_, other := e.fetch(t, wwwHost, "/vuln/"+postCVE, nil)
	if strings.Contains(other, `id="revisions"`) || !strings.Contains(other, `id="correction"`) {
		t.Error("log/entry on a vulnerability without accepted corrections")
	}
}

// TestCorrectionsSuspendedSubmitter: while the submitter is suspended the
// revision log names nobody for their correction: no handle and no
// "deleted account" line (that is only for a deleted account).
func TestCorrectionsSuspendedSubmitter(t *testing.T) {
	e, conn := newMemberEnv(t, false)
	_, uid := e.signIn(t, "7101", "qzsuspended")
	ctx := context.Background()
	at := sitetest.Now.Add(-3 * time.Hour)
	for i, sub := range []any{uid, nil} {
		if _, err := conn.Exec(ctx, `INSERT INTO vuln_corrections (cve_id, submitter_id, category, body, status, created_at, decided_at,
				public_note) VALUES ($1, $2, 'fix', 'x', 'accepted', $3, $3, $4)`, sitetest.GPU, sub, at.Add(time.Duration(i)*time.Minute),
			"QZNOTE-"+string(rune('A'+i))); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := conn.Exec(ctx, `UPDATE users SET status = 'suspended', status_reason = 'spam' WHERE id = $1`, uid); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"/vuln/" + sitetest.GPU, "/zh-hans/vuln/" + sitetest.GPU} {
		_, out := e.fetch(t, wwwHost, p, nil)
		log := between(t, out, `<section class="sec corr-log" id="revisions"`, "</section>")
		if strings.Contains(log, "qzsuspended") || !strings.Contains(log, "QZNOTE-A") || !strings.Contains(log, "QZNOTE-B") {
			t.Errorf("%s: revision log:\n%s", p, log)
		}
		deleted := "reported by a deleted account"
		if strings.HasPrefix(p, "/zh-hans/") {
			deleted = "报告者账号已删除"
		}
		if n := strings.Count(log, deleted); n != 1 {
			t.Errorf("%s: %d deleted-account lines, want 1 (the deleted one only):\n%s", p, n, log)
		}
		if n := strings.Count(log, `class="weak"`); n != 1 {
			t.Errorf("%s: %d name lines, want 1:\n%s", p, n, log)
		}
	}
}

// TestCorrectionsWithoutAccounts: without sign-in there is no entry and no
// script, only the (public) revision log.
func TestCorrectionsWithoutAccounts(t *testing.T) {
	e := newEnv(t)
	_, body := e.get(t, "/vuln/"+sitetest.GPU)
	if strings.Contains(body, `id="correction"`) || strings.Contains(body, "/static/corrections.") {
		t.Error("the entry is shown without accounts")
	}
}

// TestCorrectionsScriptIsSafe: corrections.js follows the rules of the
// other page scripts (no HTML sinks, fixed same-origin paths, the CSRF
// token only as a header, words from the page).
func TestCorrectionsScriptIsSafe(t *testing.T) {
	b, err := os.ReadFile("static/corrections.js")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, bad := range []string{"innerHTML", "insertAdjacentHTML", "outerHTML", "document.write", "eval(", "new Function",
		"DOMParser", "createContextualFragment", "setHTML", "javascript:", "localStorage", "sessionStorage", "document.cookie",
		"postMessage", "http://", "https://", "XMLHttpRequest", "location.href", "location.assign", "location.replace", "window.open"} {
		if strings.Contains(src, bad) {
			t.Errorf("corrections.js contains %q", bad)
		}
	}
	calls := regexp.MustCompile(`fetch\(([^,]+),`).FindAllStringSubmatch(src, -1)
	if len(calls) != 1 || strings.TrimSpace(calls[0][1]) != "path" || !strings.Contains(src, "credentials: 'same-origin'") {
		t.Errorf("fetch calls: %v", calls)
	}
	for _, p := range regexp.MustCompile(`'(/(?:auth|account|api)/[^']*)'`).FindAllStringSubmatch(src, -1) {
		if p[1] != "/api/corrections/" && p[1] != "/api/corrections/mine?cve=" {
			t.Errorf("corrections.js uses path %s", p[1])
		}
	}
	for _, want := range []string{"if (!CVE.test(cve)) return;", "if (csrf) headers['X-CSRF-Token'] = csrf;",
		"'/api/corrections/' + cve", "'/api/corrections/mine?cve=' + encodeURIComponent(cve)"} {
		if !strings.Contains(src, want) {
			t.Errorf("corrections.js: missing %q", want)
		}
	}
	rest := src
	for _, ok := range []string{"let csrf = '';", "if (csrf) headers['X-CSRF-Token'] = csrf;", "e.code === 'csrf'",
		"csrf = (me && me.signed_in && me.csrf_token) || '';", "csrf = me.csrf_token || '';", "'csrf'"} {
		rest = strings.ReplaceAll(rest, ok, "")
	}
	if m := regexp.MustCompile(`.*\bcsrf\b.*`).FindString(rest); m != "" {
		t.Errorf("corrections.js: the CSRF token is used for something else than the header: %s", m)
	}
	phrase := regexp.MustCompile(`[A-Za-z]{2,}[ \x{00a0}]+[A-Za-z]{2,}`)
	for _, m := range regexp.MustCompile(`'[^'\n]*'`).FindAllString(src, -1) {
		if m == "'use strict'" || strings.HasPrefix(m, "'corr-") {
			continue // the directive and class names
		}
		if phrase.MatchString(m) || strings.ContainsAny(m, "<>") {
			t.Errorf("corrections.js: literal %s; words come from the page", m)
		}
	}
}

func sitetestP(s string) *string { return &s }
