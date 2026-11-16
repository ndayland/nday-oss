package site_test

import (
	"strings"
	"testing"

	"nday.land/nday/internal/site"
)

// TestSuggestCountIsFollowMatch: for every suggested name, count equals the
// number of vulnerabilities a follow of that exact name matches
// (lower(vendor) = name OR lower(product) = name), whatever the spelling of
// the rows; queries are normalised (lower case) and short ones never reach
// the database.
func TestSuggestCountIsFollowMatch(t *testing.T) {
	st, d, _ := seeded(t)
	for _, r := range [][3]string{
		{"CVE-2026-2001", "Fortinet", "FortiOS"},
		{"CVE-2026-2002", "FORTINET", "FortiProxy"},
		{"CVE-2026-2003", "Acme", "fortinet"},         // the name as a product only
		{"CVE-2026-2004", "fortinet", "Fortinet"},     // both columns, one CVE
		{"CVE-2026-2005", "Fortinet Inc.", "FortiOS"}, // another name containing the query
		{"CVE-2026-2006", "Other", "FortiOS 7.4"},
	} {
		if _, err := d.Conn.Exec(ctx, `INSERT INTO vuln (cve_id) VALUES ($1) ON CONFLICT DO NOTHING`, r[0]); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Conn.Exec(ctx, `INSERT INTO affected (cve_id, vendor, product) VALUES ($1, $2, $3)`, r[0], r[1], r[2]); err != nil {
			t.Fatal(err)
		}
	}
	for _, q := range []string{"forti", "  FORTI  ", "tinet", "acm", "rtios"} {
		res, err := st.Suggest(ctx, q, site.MaxSuggestLimit)
		if err != nil {
			t.Fatal(err)
		}
		if res.Kind != site.SearchText || res.Query != strings.ToLower(strings.TrimSpace(q)) || len(res.Rows) == 0 {
			t.Fatalf("%q: %+v", q, res)
		}
		for _, row := range res.Rows {
			var want int
			if err := d.Conn.QueryRow(ctx, `SELECT count(DISTINCT cve_id) FROM affected
				WHERE lower(vendor) = lower($1) OR lower(product) = lower($1)`, row.Name).Scan(&want); err != nil {
				t.Fatal(err)
			}
			if row.Count != want {
				t.Errorf("%q: %s count %d, a follow matches %d", q, row.Name, row.Count, want)
			}
		}
	}
	res, _ := st.Suggest(ctx, "forti", 1)
	if len(res.Rows) != 1 || res.Rows[0].Name != "Fortinet" || res.Rows[0].Kind != site.SuggestVendor || res.Rows[0].Count != 4 {
		t.Errorf("top row %+v", res.Rows)
	}
	for q, kind := range map[string]string{"": site.SearchEmpty, "  ": site.SearchEmpty, "fo": site.SearchTooShort, "f ": site.SearchTooShort} {
		res, err := st.Suggest(ctx, q, 0)
		if err != nil || res.Kind != kind || res.Rows == nil || len(res.Rows) != 0 {
			t.Errorf("%q: %+v %v", q, res, err)
		}
	}
}
