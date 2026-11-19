package site_test

import (
	"errors"
	"testing"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
)

// TestVulnsByGHSA: a GHSA id in any letter case resolves to the CVE it is an
// alias of; an unknown one gives none; a malformed one is an InputError.
// (vuln_alias is unique on (alias_type, alias), so one id never names two.)
func TestVulnsByGHSA(t *testing.T) {
	st, _, _ := seeded(t)
	for _, in := range []string{"GHSA-gj9m-f8ph-pmhr", "ghsa-GJ9M-F8PH-PMHR", " Ghsa-gj9m-f8ph-pmhr "} {
		got, err := st.VulnsByGHSA(ctx, in)
		if err != nil || len(got) != 1 || got[0] != sitetest.GPU {
			t.Errorf("%q: %v %v", in, got, err)
		}
	}
	got, err := st.VulnsByGHSA(ctx, "GHSA-2222-3333-4444")
	if err != nil || got == nil || len(got) != 0 {
		t.Errorf("unknown: %#v %v", got, err)
	}
	// GitHub's alphabet only: "a", "b" and "0" never appear in a GHSA id
	for _, in := range []string{"", "CVE-2026-1", "GHSA-gj9m-f8ph", "GHSA-gj9m-f8ph-pmhr-x", "GHSA-aaaa-bbbb-cccc", "GHSA-0j9m-f8ph-pmhr"} {
		var ie *site.InputError
		if _, err := st.VulnsByGHSA(ctx, in); !errors.As(err, &ie) {
			t.Errorf("%q: %v", in, err)
		}
	}
	if g, ok := site.ParseGHSAID("GHSA-GJ9M-f8ph-PMHR"); !ok || g != "GHSA-gj9m-f8ph-pmhr" {
		t.Errorf("ParseGHSAID: %q %v", g, ok)
	}
}
