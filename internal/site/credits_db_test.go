package site_test

import (
	"encoding/json"
	"strings"
	"testing"

	"nday.land/nday/internal/site/sitetest"
)

// Credits come from the latest CVE record and the latest version of each
// GHSA advisory that still names the CVE and is not withdrawn.
func TestVulnCredits(t *testing.T) {
	st, d, _ := seeded(t)
	sitetest.SeedCredits(t, d.Conn)
	v, found, err := st.Vuln(ctx, sitetest.GPU)
	if err != nil || !found {
		t.Fatal(found, err)
	}
	var got []string
	for _, c := range v.Credits {
		typ := "-"
		if c.Type != nil {
			typ = *c.Type
		}
		got = append(got, c.Source+"|"+c.Key+"|"+c.Role+"|"+typ+"|"+c.Name)
	}
	want := []string{
		"cvelist|" + sitetest.GPU + "|finder|finder|Zhang Wei of Example Lab",
		"cvelist|" + sitetest.GPU + "|reporter|reporter|Example PSIRT",
		"cvelist|" + sitetest.GPU + "|credit|-|Anonymous researcher",
		"cvelist|" + sitetest.GPU + "|finder|finder|" + sitetest.CreditHostile,
		"ghsa|GHSA-cred-0001|reporter|reporter|zq-credit-login",
		"ghsa|GHSA-cred-0001|remediation_developer|remediation_developer|fixer-dev",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("credits:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	b, _ := json.Marshal(v.Credits)
	if strings.Contains(string(b), "api.github.com") || strings.Contains(string(b), "github.com/") {
		t.Errorf("profile URLs leaked: %s", b)
	}

	// Without credits: an empty array, never null.
	v, _, err = st.Vuln(ctx, "CVE-2026-1010")
	if err != nil || v.Credits == nil || len(v.Credits) != 0 {
		t.Errorf("CVE-2026-1010: %#v %v", v.Credits, err)
	}
	// GHSA-cred-0002's latest version names CVE-2026-1003.
	v, _, err = st.Vuln(ctx, "CVE-2026-1003")
	if err != nil || len(v.Credits) != 1 || v.Credits[0].Name != "moved-away" || v.Credits[0].Role != "finder" {
		t.Errorf("CVE-2026-1003: %+v %v", v.Credits, err)
	}
}
