package discuss_test

import (
	"context"
	"strings"
	"testing"
)

// A vulnerability keyed by a GHSA id (an advisory without a CVE) has a
// discussion like any other; a GHSA id with no vulnerability of its own (an
// alias, e.g. after the ingest side moved the vulnerability under its new
// CVE) is the not-found error, for reading and for posting, so a page left
// open from before the move gets a clean answer.
func TestGHSAKeyedDiscussion(t *testing.T) {
	const ghsa, alias = "GHSA-gpwc-27cw-rh9r", "GHSA-2222-3333-4444"
	h := newHarness(t, hopt{terms: terms})
	ctx := context.Background()
	if _, err := h.db.Conn.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ($1)`, ghsa); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Conn.Exec(ctx, `INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ($1, $2, 'ghsa')`, cveA, alias); err != nil {
		t.Fatal(err)
	}
	ada := h.member("ada")
	h.establish(ada.id)
	ada.refresh()
	anon := h.browser()

	top := ada.create(ghsa, "Same bug as ghsa-GPWC-27cw-rh9r and CVE-2026-0002", nil)
	if !strings.Contains(top.BodyHTML, `href="/zh-hans/vuln/`+ghsa+`"`) || !strings.Contains(top.BodyHTML, `href="/zh-hans/vuln/CVE-2026-0002"`) {
		t.Errorf("body_html: %s", top.BodyHTML)
	}
	reply := ada.create("ghsa-GPWC-27CW-RH9R", "and a reply", &top.ID) // any letter case
	if reply.ParentID == nil || *reply.ParentID != top.ID {
		t.Errorf("reply: %+v", reply)
	}
	if s := ada.stream(ghsa, ""); s.CVE != ghsa || s.Count != 2 || len(s.Comments) != 1 {
		t.Errorf("signed-in stream: %+v", s)
	}
	if s := anon.stream(ghsa, ""); s.CVE != ghsa || s.Count != 2 || s.Outline == nil {
		t.Errorf("signed-out stream: %+v", s)
	}

	resp, body := ada.tryCreate(alias, "x", nil)
	expect(t, "post on an alias", resp, body, 404, "not_found")
	resp, body = anon.do("GET", "/api/discuss/"+alias, "")
	expect(t, "read an alias", resp, body, 404, "not_found")
	resp, body = ada.tryCreate("GHSA-aaaa-27cw-rh9r", "x", nil)
	expect(t, "malformed GHSA id", resp, body, 400, "bad_cve")
}
