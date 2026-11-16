package site_test

import (
	"testing"

	"nday.land/nday/internal/site/sitetest"
)

// The description source is the latest record of a source whose text equals
// vuln.description; older versions, other CVEs' advisories and withdrawn
// advisories do not count.
func TestVulnDescriptionSource(t *testing.T) {
	st, d, _ := seeded(t)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	s.Raw("cvelist", sitetest.GPU, "h-desc-old", `{"containers": {"cna": {"descriptions": [{"lang": "en", "value": "Old CNA text."}]}}}`, sitetest.Ago(30))
	s.Raw("cvelist", sitetest.GPU, "h-desc-new", `{"containers": {"cna": {"descriptions": [
	  {"lang": "de", "value": "Deutscher Text."}, {"lang": "en", "value": "New CNA text."}, "junk"]}}}`, sitetest.Ago(0.5))
	s.Raw("ghsa", "GHSA-desc-0001", "h-desc-g1", `{"ghsa_id": "GHSA-desc-0001", "cve_id": "`+sitetest.GPU+`", "description": "Advisory text."}`, sitetest.Ago(1))
	s.Raw("ghsa", "GHSA-desc-0002", "h-desc-g2", `{"ghsa_id": "GHSA-desc-0002", "cve_id": "`+sitetest.GPU+`",
	  "withdrawn_at": "2026-11-01T00:00:00Z", "description": "Withdrawn text."}`, sitetest.Ago(1))
	s.Raw("kev", sitetest.GPU, "h-desc-k", `{"cveID": "`+sitetest.GPU+`", "shortDescription": "KEV text."}`, sitetest.Ago(1))

	for _, c := range []struct{ desc, want string }{
		{"New CNA text.", "cvelist/" + sitetest.GPU},
		{"Advisory text.\n", "ghsa/GHSA-desc-0001"},
		{"KEV text.", "kev/" + sitetest.GPU},
		{"Old CNA text.", ""},
		{"Withdrawn text.", ""},
	} {
		if _, err := d.Conn.Exec(ctx, `UPDATE vuln SET description = $2 WHERE cve_id = $1`, sitetest.GPU, c.desc); err != nil {
			t.Fatal(err)
		}
		v, found, err := st.Vuln(ctx, sitetest.GPU)
		if err != nil || !found {
			t.Fatal(found, err)
		}
		got := ""
		if v.DescriptionSource != nil {
			got = v.DescriptionSource.Source + "/" + v.DescriptionSource.Key
		}
		if got != c.want {
			t.Errorf("description %q: source %q, want %q", c.desc, got, c.want)
		}
	}
}
