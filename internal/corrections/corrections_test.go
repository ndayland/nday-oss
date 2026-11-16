package corrections_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/corrections"
)

// TestSubmitAccess: who may submit, and the request guards (the same as
// posting a comment: session, same origin, CSRF, active account, handle,
// current rules; only on the public host).
func TestSubmitAccess(t *testing.T) {
	h := newHarness(t, terms, nil)
	path := "/api/corrections/" + cveA
	body := jsonOf(map[string]any{"category": "title", "body": "SECRET-BODY wrong title"})

	anon := h.browser()
	resp, b := anon.do("POST", path, body, "Origin", origin, "Sec-Fetch-Site", "same-origin", "Content-Type", "application/json")
	expect(t, "signed out", resp, b, 401, "not_signed_in")
	resp, b = anon.do("GET", "/api/corrections/mine", "")
	expect(t, "signed out mine", resp, b, 401, "not_signed_in")

	m := h.member("ada")
	resp, b = m.do("POST", path, body, "Origin", origin, "Sec-Fetch-Site", "same-origin", "Content-Type", "application/json")
	expect(t, "no CSRF", resp, b, 403, "csrf")
	resp, b = m.do("POST", path, body, "Origin", origin, "Sec-Fetch-Site", "same-origin", "Content-Type", "application/json",
		"X-CSRF-Token", "not-the-token")
	expect(t, "wrong CSRF", resp, b, 403, "csrf")
	resp, b = m.do("POST", path, body, "Origin", "https://evil.example", "Sec-Fetch-Site", "cross-site",
		"Content-Type", "application/json", "X-CSRF-Token", m.csrf)
	expect(t, "cross site", resp, b, 403, "cross_site")
	resp, b = m.do("POST", path, body, "Host", "evil.example", "Origin", origin, "Sec-Fetch-Site", "same-origin",
		"Content-Type", "application/json", "X-CSRF-Token", m.csrf)
	expect(t, "other host", resp, b, http.StatusMisdirectedRequest, "wrong_host")
	if resp, _ := m.do("POST", path, body, "Host", apiHost, "Content-Type", "application/json", "X-CSRF-Token", m.csrf); resp.StatusCode == 201 {
		t.Error("API host accepted a submission")
	}
	resp, b = m.do("GET", path, "")
	expect(t, "GET on submit", resp, b, 405, "method_not_allowed")
	if h.count(`SELECT count(*) FROM vuln_corrections`) != 0 {
		t.Fatal("a refused request stored a correction")
	}

	// no handle; then rules not accepted
	nh := h.browser()
	nh.signIn("nohandle")
	resp, b = nh.post(path, body)
	expect(t, "no handle", resp, b, 403, "handle_required")
	key, _ := auth.CanonicalHandle("bob")
	if _, err := h.as.SetHandle(context.Background(), nh.id, "bob", key, 0); err != nil {
		t.Fatal(err)
	}
	resp, b = nh.post(path, body)
	expect(t, "rules not accepted", resp, b, 403, "terms_required")

	// suspended: refused, but may still read their own list
	m.submit(cveA, "title", "SECRET-BODY first", nil)
	until := h.clock.Now().Add(24 * time.Hour)
	if err := h.as.Suspend(context.Background(), m.id, &until, "spam"); err != nil {
		t.Fatal(err)
	}
	resp, b = m.post(path, body)
	expect(t, "suspended", resp, b, 403, "suspended")
	if got := m.mine(""); len(got) != 1 {
		t.Errorf("suspended user's own list: %+v", got)
	}
	// lifted by time
	h.clock.Advance(25 * time.Hour)
	m.submit(cveA, "summary", "SECRET-BODY second", nil)
	if n := h.count(`SELECT count(*) FROM vuln_corrections`); n != 2 {
		t.Errorf("%d corrections stored, want 2", n)
	}
}

// TestSubmitValidation: category, text, link, CVE and body checks.
func TestSubmitValidation(t *testing.T) {
	h := newHarness(t, "", nil)
	m := h.member("ada")
	path := "/api/corrections/" + cveA
	for _, tc := range []struct {
		name string
		req  any
		code string
	}{
		{"unknown category", map[string]any{"category": "headline", "body": "x"}, "bad_category"},
		{"empty category", map[string]any{"category": "", "body": "x"}, "bad_category"},
		{"empty body", map[string]any{"category": "title", "body": "   \n\t "}, "invalid_body"},
		{"invisible body", map[string]any{"category": "title", "body": "​⁦‮"}, "invalid_body"},
		{"too long", map[string]any{"category": "title", "body": strings.Repeat("长", corrections.MaxBodyChars+1)}, "invalid_body"},
		{"javascript link", map[string]any{"category": "fix", "body": "x", "evidence_url": "javascript:alert(1)"}, "bad_url"},
		{"data link", map[string]any{"category": "fix", "body": "x", "evidence_url": "data:text/html,<b>x</b>"}, "bad_url"},
		{"ftp link", map[string]any{"category": "fix", "body": "x", "evidence_url": "ftp://example.com/a"}, "bad_url"},
		{"relative link", map[string]any{"category": "fix", "body": "x", "evidence_url": "/vuln/CVE-2026-0001"}, "bad_url"},
		{"scheme-relative link", map[string]any{"category": "fix", "body": "x", "evidence_url": "//evil.example/x"}, "bad_url"},
		{"credentials in link", map[string]any{"category": "fix", "body": "x", "evidence_url": "https://user:pw@example.com/"}, "bad_url"},
		{"link with quote", map[string]any{"category": "fix", "body": "x", "evidence_url": "https://example.com/\"onmouseover=x"}, "bad_url"},
		{"link too long", map[string]any{"category": "fix", "body": "x", "evidence_url": "https://example.com/" + strings.Repeat("a", 2048)}, "bad_url"},
		{"unknown field", map[string]any{"category": "fix", "body": "x", "status": "accepted"}, "bad_request"},
	} {
		resp, b := m.post(path, jsonOf(tc.req))
		expect(t, tc.name, resp, b, 400, tc.code)
	}
	resp, b := m.post("/api/corrections/not-a-cve", jsonOf(map[string]any{"category": "title", "body": "x"}))
	expect(t, "bad CVE", resp, b, 400, "bad_cve")
	resp, b = m.post("/api/corrections/CVE-2099-99999", jsonOf(map[string]any{"category": "title", "body": "x"}))
	expect(t, "unknown CVE", resp, b, 404, "not_found")
	resp, b = m.do("POST", path, `{"category":"title","body":"x"}`, "Origin", origin, "Sec-Fetch-Site", "same-origin",
		"Content-Type", "text/plain", "X-CSRF-Token", m.csrf)
	expect(t, "content type", resp, b, 415, "bad_request")
	if n := h.count(`SELECT count(*) FROM vuln_corrections`); n != 0 {
		t.Fatalf("%d invalid submissions stored", n)
	}

	// valid: the text is cleaned (bidi controls, CR LF), the link's scheme
	// lower-cased; the maximum length passes
	c := m.submit(strings.ToLower(cveA), "affected", "  versions ‮<b>wrong</b>\r\nfixed in 2.4.1  ", ptr(" HTTPS://example.com/advisory?id=1 "))
	if c.CVE != cveA || c.Category != "affected" || c.Body != "versions <b>wrong</b>\nfixed in 2.4.1" || c.Status != "pending" ||
		c.EvidenceURL == nil || *c.EvidenceURL != "https://example.com/advisory?id=1" || c.PublicNote != nil || c.DecidedAt != nil {
		t.Errorf("stored: %+v", c)
	}
	h.clock.Advance(time.Second)
	m.submit(cveA, "other", strings.Repeat("长", corrections.MaxBodyChars), ptr(""))
	if got := m.mine("?cve=" + cveA); len(got) != 2 || got[0].Category != "other" || got[0].EvidenceURL != nil {
		t.Errorf("mine: %d rows, first %s", len(got), got[0].Category)
	}
	resp, b = m.do("GET", "/api/corrections/mine?cve=x", "")
	expect(t, "mine bad CVE", resp, b, 400, "bad_cve")
}

// TestSubmitLimits: the daily cap, the open caps per user and vulnerability,
// the per-user token bucket, and SetLimits on the running service.
func TestSubmitLimits(t *testing.T) {
	lim := corrections.Limits{Daily: 3, OpenPerVuln: 3, OpenPerUser: 2, Burst: 100, Every: time.Millisecond}
	h := newHarness(t, "", &lim)
	a, b2, c := h.member("ada"), h.member("bob"), h.member("cyd")
	req := jsonOf(map[string]any{"category": "title", "body": "x"})

	a.submit(cveA, "title", "one", nil)
	a.submit(cveA, "title", "two", nil)
	resp, b := a.post("/api/corrections/"+cveA, req)
	expect(t, "third open on one vuln", resp, b, 409, "too_many_open")
	b2.submit(cveA, "title", "bob one", nil)
	resp, b = c.post("/api/corrections/"+cveA, req)
	expect(t, "vuln queue full", resp, b, 409, "queue_full")
	c.submit(cveB, "title", "cyd on B", nil)

	a.submit(cveB, "title", "three", nil)
	resp, b = a.post("/api/corrections/"+cveB, req)
	expect(t, "daily cap", resp, b, 429, "daily_limit")
	if ra := resp.Header.Get("Retry-After"); ra == "" || ra == "0" {
		t.Errorf("daily cap: Retry-After %q", ra)
	}
	h.clock.Advance(24*time.Hour + time.Second)
	a.submit(cveB, "title", "next day", nil)

	// the token bucket counts every request, whatever its outcome
	h.cs.SetLimits(corrections.Limits{Daily: 100, OpenPerVuln: 100, OpenPerUser: 100, Burst: 2, Every: time.Hour})
	d := h.member("dee")
	resp, b = d.post("/api/corrections/"+cveA, jsonOf(map[string]any{"category": "nope", "body": "x"}))
	expect(t, "bucket 1 (invalid)", resp, b, 400, "bad_category")
	d.submit(cveA, "title", "ok", nil)
	resp, b = d.post("/api/corrections/"+cveA, req)
	expect(t, "bucket empty", resp, b, 429, "rate_limited")
	if resp.Header.Get("Retry-After") == "" {
		t.Error("rate_limited without Retry-After")
	}
	if h.cs.Limits().Burst != 2 {
		t.Error("SetLimits not in force")
	}
	if !strings.Contains(h.logs.String(), "corrections: rate limited") {
		t.Error("no rate-limit warning logged")
	}
}

// TestDecide: staff accept (public note required) and reject (optional
// internal note); every decision writes an audit row in its transaction;
// the submitter sees the status and the public note, never the internal one.
func TestDecide(t *testing.T) {
	h := newHarness(t, terms, nil)
	sub, other := h.member("ada"), h.member("bob")
	mod := h.moderator("mia")
	c1 := sub.submit(cveA, "fix", "SECRET-BODY fixed version is wrong", ptr("https://example.com/secret-link"))
	h.clock.Advance(time.Second)
	c2 := sub.submit(cveA, "title", "SECRET-BODY title typo", nil)
	acc := "/api/corrections/item/" + c1.ID + "/accept"
	rej := "/api/corrections/item/" + c2.ID + "/reject"

	resp, b := other.post(acc, `{"note":"x"}`)
	expect(t, "user accepts", resp, b, 403, "forbidden")
	resp, b = h.browser().do("POST", acc, `{"note":"x"}`, "Origin", origin, "Sec-Fetch-Site", "same-origin", "Content-Type", "application/json")
	expect(t, "signed out accepts", resp, b, 401, "not_signed_in")
	resp, b = mod.do("POST", acc, `{"note":"x"}`, "Origin", origin, "Sec-Fetch-Site", "same-origin", "Content-Type", "application/json")
	expect(t, "mod without CSRF", resp, b, 403, "csrf")
	resp, b = mod.post(acc, `{}`)
	expect(t, "accept without note", resp, b, 400, "note_required")
	resp, b = mod.post(acc, `{"note":"  ​ \n "}`)
	expect(t, "accept with blank note", resp, b, 400, "note_required")
	resp, b = mod.post(acc, jsonOf(map[string]string{"note": strings.Repeat("n", corrections.MaxPublicNote+1)}))
	expect(t, "note too long", resp, b, 400, "bad_note")
	resp, b = mod.post("/api/corrections/item/00000000-0000-4000-8000-000000000000/accept", `{"note":"x"}`)
	expect(t, "unknown id", resp, b, 404, "not_found")
	resp, b = mod.post("/api/corrections/item/nope/accept", `{"note":"x"}`)
	expect(t, "bad id", resp, b, 404, "not_found")
	if h.count(`SELECT count(*) FROM vuln_corrections WHERE status <> 'pending'`) != 0 || h.count(`SELECT count(*) FROM admin_audit WHERE target_type = 'correction'`) != 0 {
		t.Fatal("a refused decision changed something")
	}

	resp, b = mod.post(acc, jsonOf(map[string]string{"note": "Fixed version confirmed as 2.4.1 <script>alert(1)</script>\nper vendor"}))
	expect(t, "accept", resp, b, 200, "")
	var r struct {
		Correction correction `json:"correction"`
	}
	_ = json.Unmarshal(b, &r)
	if r.Correction.Status != "accepted" || r.Correction.PublicNote == nil ||
		*r.Correction.PublicNote != "Fixed version confirmed as 2.4.1 <script>alert(1)</script> per vendor" {
		t.Errorf("accepted: %+v", r.Correction)
	}
	resp, b = mod.post(acc, `{"note":"again"}`)
	expect(t, "accept twice", resp, b, 409, "wrong_status")
	resp, b = mod.post("/api/corrections/item/"+c1.ID+"/reject", `{}`)
	expect(t, "reject accepted", resp, b, 409, "wrong_status")

	resp, b = mod.post(rej, jsonOf(map[string]string{"note": strings.Repeat("n", corrections.MaxInternalNote+1)}))
	expect(t, "internal note too long", resp, b, 400, "bad_note")
	resp, b = mod.post(rej, jsonOf(map[string]string{"note": "SECRET-NOTE duplicate of upstream"}))
	expect(t, "reject", resp, b, 200, "")
	if strings.Contains(string(b), "SECRET-NOTE") {
		t.Error("the reject response carries the internal note")
	}
	c3 := sub.submit(cveB, "other", "third", nil)
	resp, b = mod.post("/api/corrections/item/"+c3.ID+"/reject", "")
	expect(t, "reject with an empty body", resp, b, 400, "bad_request")
	resp, b = mod.post("/api/corrections/item/"+c3.ID+"/reject", `{}`)
	expect(t, "reject without note", resp, b, 200, "")

	// audit rows: one per decision, actor, target, reason
	type row struct{ action, actor, target, reason, cve string }
	rows, err := h.db.Conn.Query(context.Background(), `SELECT action, coalesce(actor_handle, ''), target_type || ':' || target_id,
		coalesce(reason, ''), coalesce(details->>'cve', '') FROM admin_audit WHERE target_type = 'correction' ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	var got []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.action, &x.actor, &x.target, &x.reason, &x.cve); err != nil {
			t.Fatal(err)
		}
		got = append(got, x)
	}
	rows.Close()
	want := []row{
		{"correction.accept", "mia", "correction:" + c1.ID, "Fixed version confirmed as 2.4.1 <script>alert(1)</script> per vendor", cveA},
		{"correction.reject", "mia", "correction:" + c2.ID, "SECRET-NOTE duplicate of upstream", cveA},
		{"correction.reject", "mia", "correction:" + c3.ID, "", cveB},
	}
	if len(got) != len(want) {
		t.Fatalf("audit rows: %+v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("audit row %d: %+v, want %+v", i, got[i], want[i])
		}
	}

	// the submitter's view: statuses, the public note, never the internal note
	resp, b = sub.do("GET", "/api/corrections/mine", "")
	if resp.StatusCode != 200 || strings.Contains(string(b), "SECRET-NOTE") || strings.Contains(string(b), "internal") {
		t.Errorf("mine: %d %s", resp.StatusCode, b)
	}
	mine := sub.mine("?cve=" + cveA)
	if len(mine) != 2 || mine[0].ID != c2.ID || mine[0].Status != "rejected" || mine[0].PublicNote != nil ||
		mine[1].Status != "accepted" || mine[1].PublicNote == nil {
		t.Errorf("mine after decisions: %+v", mine)
	}
	if len(other.mine("")) != 0 {
		t.Error("another user sees someone's corrections")
	}

	// public: the accepted one only, with the handle; nothing else
	pub, err := h.site.Corrections(context.Background(), cveA)
	if err != nil {
		t.Fatal(err)
	}
	if len(pub) != 1 || pub[0].Category != "fix" || pub[0].Handle == nil || *pub[0].Handle != "ada" ||
		pub[0].Note != "Fixed version confirmed as 2.4.1 <script>alert(1)</script> per vendor" {
		t.Errorf("public corrections: %+v", pub)
	}
	if pub, _ := h.site.Corrections(context.Background(), cveB); len(pub) != 0 {
		t.Errorf("public corrections of B: %+v", pub)
	}
	// account deleted: the record stays, without a name
	if _, err := h.db.Conn.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, sub.id); err != nil {
		t.Fatal(err)
	}
	if pub, _ := h.site.Corrections(context.Background(), cveA); len(pub) != 1 || pub[0].Handle != nil {
		t.Errorf("after account deletion: %+v", pub)
	}
	if n := h.count(`SELECT count(*) FROM vuln_corrections WHERE submitter_id IS NULL`); n != 3 {
		t.Errorf("%d corrections without submitter after deletion, want 3", n)
	}
	// a vuln with corrections cannot be deleted silently (NO ACTION)
	if _, err := h.db.Conn.Exec(context.Background(), `DELETE FROM vuln WHERE cve_id = $1`, cveA); err == nil {
		t.Error("deleting a vulnerability with corrections succeeded")
	}
}

// TestDecideAuditAtomic: when the audit row cannot be written, the
// decision is rolled back.
func TestDecideAuditAtomic(t *testing.T) {
	h := newHarness(t, "", nil)
	sub, mod := h.member("ada"), h.moderator("mia")
	c := sub.submit(cveA, "title", "x", nil)
	ctx := context.Background()
	if _, err := h.db.Conn.Exec(ctx, `CREATE FUNCTION fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'audit refused'; END $$;
		CREATE TRIGGER fail_audit BEFORE INSERT ON admin_audit FOR EACH ROW EXECUTE FUNCTION fail_audit();`); err != nil {
		t.Fatal(err)
	}
	resp, b := mod.post("/api/corrections/item/"+c.ID+"/accept", `{"note":"ok"}`)
	expect(t, "accept with failing audit", resp, b, 500, "internal")
	if n := h.count(`SELECT count(*) FROM vuln_corrections WHERE status = 'pending'`); n != 1 {
		t.Error("the decision was kept without its audit row")
	}
	if _, err := h.db.Conn.Exec(ctx, `DROP TRIGGER fail_audit ON admin_audit`); err != nil {
		t.Fatal(err)
	}
	resp, b = mod.post("/api/corrections/item/"+c.ID+"/accept", `{"note":"ok"}`)
	expect(t, "accept", resp, b, 200, "")
}

// TestLimitsFromEnv: defaults, overrides, and errors that name the
// variable without echoing its value.
func TestLimitsFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	l, err := corrections.LimitsFromEnv(env(nil))
	if err != nil || l != corrections.DefaultLimits() {
		t.Fatalf("defaults: %+v %v", l, err)
	}
	l, err = corrections.LimitsFromEnv(env(map[string]string{"NDAY_CORRECTIONS_DAILY": "5", "NDAY_CORRECTIONS_EVERY": "2d",
		"NDAY_CORRECTIONS_OPEN_PER_VULN": " 7 ", "NDAY_CORRECTIONS_OPEN_PER_USER": "1", "NDAY_CORRECTIONS_BURST": "9"}))
	if err != nil || l.Daily != 5 || l.Every != 48*time.Hour || l.OpenPerVuln != 7 || l.OpenPerUser != 1 || l.Burst != 9 {
		t.Errorf("overrides: %+v %v", l, err)
	}
	for k, v := range map[string]string{"NDAY_CORRECTIONS_DAILY": "0000000", "NDAY_CORRECTIONS_OPEN_PER_VULN": "LEAKVALUE",
		"NDAY_CORRECTIONS_BURST": "100001", "NDAY_CORRECTIONS_EVERY": "31d", "NDAY_CORRECTIONS_OPEN_PER_USER": "-1"} {
		_, err := corrections.LimitsFromEnv(env(map[string]string{k: v}))
		if err == nil || !strings.Contains(err.Error(), k) || strings.Contains(err.Error(), v) {
			t.Errorf("%s=%s: %v", k, v, err)
		}
	}
}
