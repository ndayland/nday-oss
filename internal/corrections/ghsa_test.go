package corrections_test

import (
	"context"
	"testing"
)

// A vulnerability keyed by a GHSA id takes corrections like a CVE; a GHSA id
// that is only an alias (e.g. after the ingest side moved the vulnerability
// under its new CVE) is the not-found error, and a malformed one bad_cve.
func TestGHSAKeyedCorrections(t *testing.T) {
	const ghsa, alias = "GHSA-gpwc-27cw-rh9r", "GHSA-2222-3333-4444"
	h := newHarness(t, "", nil)
	ctx := context.Background()
	if _, err := h.db.Conn.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ($1)`, ghsa); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Conn.Exec(ctx, `INSERT INTO vuln_alias (cve_id, alias, alias_type) VALUES ($1, $2, 'ghsa')`, cveA, alias); err != nil {
		t.Fatal(err)
	}
	m := h.member("ada")
	c := m.submit("ghsa-GPWC-27cw-rh9r", "title", "the package is qzmerge", nil)
	if c.CVE != ghsa || c.Status != "pending" {
		t.Errorf("submitted: %+v", c)
	}
	if mine := m.mine("?cve=" + ghsa); len(mine) != 1 || mine[0].ID != c.ID {
		t.Errorf("mine: %+v", mine)
	}
	if mine := m.mine("?cve=" + alias); len(mine) != 0 {
		t.Errorf("mine for the alias: %+v", mine)
	}
	body := jsonOf(map[string]any{"category": "title", "body": "x"})
	resp, b := m.post("/api/corrections/"+alias, body)
	expect(t, "alias", resp, b, 404, "not_found")
	resp, b = m.post("/api/corrections/GHSA-aaaa-27cw-rh9r", body)
	expect(t, "malformed", resp, b, 400, "bad_cve")
}
