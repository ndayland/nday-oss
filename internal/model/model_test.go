package model

import "testing"

func TestVulnIDs(t *testing.T) {
	for _, c := range []struct {
		id        string
		cve, ghsa bool
	}{
		{"CVE-2026-1234", true, false},
		{"CVE-2026-1234567", true, false},
		{"GHSA-2cm2-m3w5-gp2f", false, true},
		{"GHSA-jmqv-2mx7-544h", false, true},
		{"GHSA-2CM2-M3W5-GP2F", false, false}, // upper case groups: not canonical
		{"ghsa-2cm2-m3w5-gp2f", false, false}, // lower case prefix
		{"GHSA-aaaa-bbbb-cccc", false, false}, // 'a', 'b' are not in GitHub's alphabet
		{"GHSA-2cm2-m3w5-gp2", false, false},
		{"GHSA-2cm2-m3w5-gp2f-2222", false, false},
		{" GHSA-2cm2-m3w5-gp2f", false, false},
		{"CVE-26-1", false, false},
		{"", false, false},
	} {
		if IsValidCVEID(c.id) != c.cve || IsGHSAID(c.id) != c.ghsa || IsValidVulnID(c.id) != (c.cve || c.ghsa) {
			t.Errorf("%q: cve %v ghsa %v vuln %v", c.id, IsValidCVEID(c.id), IsGHSAID(c.id), IsValidVulnID(c.id))
		}
	}
}

func TestValidateVulnIDs(t *testing.T) {
	ok := &Normalized{
		Vulns:   []VulnUpsert{{CVEID: "GHSA-2cm2-m3w5-gp2f"}},
		Aliases: []Alias{{CVEID: "CVE-2026-1234", Alias: "GHSA-2cm2-m3w5-gp2f", AliasType: "ghsa"}},
		Events:  []Event{{CVEID: "GHSA-2cm2-m3w5-gp2f", Type: EventDisclosed, Source: "ghsa"}},
	}
	if err := ok.Validate(); err != nil {
		t.Error(err)
	}
	for _, n := range []*Normalized{
		{Vulns: []VulnUpsert{{CVEID: "GHSA-2CM2-M3W5-GP2F"}}},
		{Affected: []Affected{{CVEID: "PYSEC-2026-1"}}},
		{Events: []Event{{CVEID: "GHSA-aaaa-bbbb-cccc", Type: EventDisclosed}}},
	} {
		if err := n.Validate(); err == nil {
			t.Errorf("accepted %+v", n)
		}
	}
}
