package classify

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestValidVector(t *testing.T) {
	ok := [][2]string{
		{V2, "AV:N/AC:L/Au:N/C:P/I:P/A:P"},
		{V2, "AV:N/AC:H/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:C"}, // VulDB style temporal
		{V30, "CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
		{V31, "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C"},
		{V31, "CVSS:3.1/S:U/AV:N/AC:L/PR:N/UI:N/C:H/I:H/A:H"}, // order not enforced
		{V40, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N"},
		{V40, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X"},
		{V40, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/MSI:S/U:Amber"},
	}
	bad := [][2]string{
		{V2, "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"},           // prefixed v2
		{V2, "(AV:N/AC:L/Au:N/C:P/I:P/A:P)"},                  // parenthesised
		{V2, "AV:N/AC:L/Au:N/C:P/I:P"},                        // missing A
		{V2, "AV:N/AC:L/Au:N/C:P/I:P/A:Z"},                    // bad value
		{V31, "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, // version mismatch
		{V31, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:Q"},
		{V31, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H"},
		{V31, "CVSS:3.1/AV:N/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, // duplicate
		{V31, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/"},     // empty part
		{V40, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N"},
		{V40, "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/U:Blue"},
		{"1.0", "AV:N"},
		{V31, ""},
	}
	for _, c := range ok {
		if !ValidVector(c[0], c[1]) {
			t.Errorf("rejected %s %s", c[0], c[1])
		}
	}
	for _, c := range bad {
		if ValidVector(c[0], c[1]) {
			t.Errorf("accepted %s %s", c[0], c[1])
		}
	}
}

func TestNormalizeCWE(t *testing.T) {
	for in, want := range map[string]string{
		"CWE-79": "CWE-79", " cwe-079 ": "CWE-79", "CWE-0": "CWE-0", "NVD-CWE-noinfo": "", "NVD-CWE-Other": "",
		"n/a": "", "CWE-": "", "CWE-79a": "", "CWE-noinfo": "", "Improper input": "", "CWE-99999999999": "",
	} {
		if got := NormalizeCWE(in); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
	}
}

func repoPath(parts ...string) string {
	return filepath.Join(append([]string{"..", ".."}, parts...)...)
}

type fixtureRec struct {
	Key     string          `json:"key"`
	Payload json.RawMessage `json:"payload"`
}

func loadCVE5(t *testing.T) []fixtureRec {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "cve5.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recs []fixtureRec
	if err := json.Unmarshal(b, &recs); err != nil {
		t.Fatal(err)
	}
	return recs
}

func loadNVD(t *testing.T) map[string]json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(repoPath("internal", "collector", "nvd", "testdata", "fixture.json"))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vulnerabilities []struct {
			CVE json.RawMessage `json:"cve"`
		} `json:"vulnerabilities"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	out := map[string]json.RawMessage{}
	for _, v := range doc.Vulnerabilities {
		var id struct{ ID string }
		_ = json.Unmarshal(v.CVE, &id)
		out[id.ID] = v.CVE
	}
	return out
}

func loadGHSA(t *testing.T) []json.RawMessage {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "ghsa.json"))
	if err != nil {
		t.Fatal(err)
	}
	var recs []json.RawMessage
	if err := json.Unmarshal(b, &recs); err != nil {
		t.Fatal(err)
	}
	return recs
}

// render gives a compact, comparable view of a derivation.
func render(d *Derived) []string {
	var out []string
	if d.Rejected {
		out = append(out, "REJECTED")
	}
	for _, r := range d.CWEs {
		out = append(out, fmt.Sprintf("cwe %s %s/%s", r.CWE, r.Source, r.SourceOrg))
	}
	for _, r := range d.CVSS {
		s, sev := "-", "-"
		if r.BaseScore != nil {
			s = fmt.Sprintf("%.1f", *r.BaseScore)
		}
		if r.Severity != nil {
			sev = *r.Severity
		}
		out = append(out, fmt.Sprintf("cvss %s %s/%s %s %s %s", r.Version, r.Source, r.SourceOrg, s, sev, r.Vector))
	}
	out = append(out, fmt.Sprintf("skipped cwe=%d cvss=%d", d.CWESkipped, d.CVSSSkipped))
	sort.Strings(out)
	return out
}

func check(t *testing.T, name string, d *Derived, want []string) {
	t.Helper()
	sort.Strings(want)
	if got := render(d); !reflect.DeepEqual(got, want) {
		t.Errorf("%s:\n got %s\nwant %s", name, strings.Join(got, "\n     "), strings.Join(want, "\n     "))
	}
}

func TestDeriveCVE5(t *testing.T) {
	want := map[string][]string{
		// CNA v4.0 + v3.1, CWE via cweId; ADP CISA-ADP without metrics
		"CVE-2010-20125": {"cwe CWE-98 cve-cna/VulnCheck",
			"cvss 3.1 cve-cna/VulnCheck 7.5 HIGH CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
			"cvss 4.0 cve-cna/VulnCheck 8.7 HIGH CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
			"skipped cwe=0 cvss=0"},
		// all four versions (v2 with temporal metrics, no severity)
		"CVE-2026-105137": {"cwe CWE-494 cve-cna/VulDB",
			"cvss 2.0 cve-cna/VulDB 5.1 - AV:N/AC:H/Au:N/C:P/I:P/A:P/E:POC/RL:OF/RC:C",
			"cvss 3.0 cve-cna/VulDB 5.0 MEDIUM CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C",
			"cvss 3.1 cve-cna/VulDB 5.0 MEDIUM CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:L/E:P/RL:O/RC:C",
			"cvss 4.0 cve-cna/VulDB 2.3 LOW CVSS:4.0/AV:N/AC:H/AT:N/PR:N/UI:P/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N/E:P",
			"skipped cwe=0 cvss=0"},
		// CNA and ADP state the same CWE and vector: one row each, provenance kept
		"CVE-2023-3758": {"cwe CWE-362 cve-adp/CISA-ADP", "cwe CWE-362 cve-cna/redhat",
			"cvss 3.1 cve-adp/CISA-ADP 7.1 HIGH CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
			"cvss 3.1 cve-cna/redhat 7.1 HIGH CVSS:3.1/AV:A/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
			"skipped cwe=0 cvss=0"},
		"CVE-2026-111221": {"REJECTED", "skipped cwe=0 cvss=0"},
		// CNA "n/a" skipped; ADP CWE from the description text
		"CVE-2026-117068": {"cwe CWE-191 cve-adp/CISA-ADP",
			"cvss 3.1 cve-adp/CISA-ADP 7.5 HIGH CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			"skipped cwe=1 cvss=0"},
		// "CWE-noinfo Not enough information" is not a CWE id
		"CVE-2010-0188": {"cvss 3.1 cve-adp/CISA-ADP 7.8 HIGH CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			"skipped cwe=2 cvss=0"},
		// hand-made: malformed v3.1 vector skipped, v4.0 kept
		"CVE-2010-99999": {"cwe CWE-98 cve-cna/VulnCheck",
			"cvss 4.0 cve-cna/VulnCheck 8.7 HIGH CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
			"skipped cwe=0 cvss=1"},
	}
	seen := 0
	for _, r := range loadCVE5(t) {
		d, err := DeriveCVE5(r.Key, r.Payload)
		if err != nil {
			t.Fatal(r.Key, err)
		}
		if w, ok := want[r.Key]; ok {
			check(t, r.Key, d, w)
			seen++
		}
	}
	if seen != len(want) {
		t.Errorf("checked %d of %d", seen, len(want))
	}
	// RESERVED and other states: nothing
	d, _ := DeriveCVE5("CVE-2026-1", []byte(`{"cveMetadata":{"state":"RESERVED"},"containers":{"cna":{"problemTypes":[{"descriptions":[{"cweId":"CWE-79"}]}]}}}`))
	check(t, "reserved", d, []string{"skipped cwe=0 cvss=0"})
}

func TestDeriveNVD(t *testing.T) {
	recs := loadNVD(t)
	cna := "134c704f-9b21-4f2e-91b3-4a467353bcc0" // CISA-ADP's NVD source id
	want := map[string][]string{
		// v2 only, NVD's own analysis
		"CVE-2010-0157": {"cwe CWE-22 nvd-primary/nvd@nist.gov",
			"cvss 2.0 nvd-primary/nvd@nist.gov 7.5 HIGH AV:N/AC:L/Au:N/C:P/I:P/A:P", "skipped cwe=0 cvss=0"},
		// v3.0 + v2 primary
		"CVE-2018-3810": {"cwe CWE-287 nvd-primary/nvd@nist.gov",
			"cvss 2.0 nvd-primary/nvd@nist.gov 7.5 HIGH AV:N/AC:L/Au:N/C:P/I:P/A:P",
			"cvss 3.0 nvd-primary/nvd@nist.gov 9.8 CRITICAL CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "skipped cwe=0 cvss=0"},
		// same CWE from NVD (Primary) and the CNA (Secondary): two rows
		"CVE-2018-0125": {"cwe CWE-20 nvd-primary/nvd@nist.gov", "cwe CWE-20 nvd-secondary/psirt@cisco.com",
			"cvss 2.0 nvd-primary/nvd@nist.gov 10.0 HIGH AV:N/AC:L/Au:N/C:C/I:C/A:C",
			"cvss 3.1 nvd-primary/nvd@nist.gov 9.8 CRITICAL CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"cvss 3.1 nvd-secondary/" + cna + " 9.8 CRITICAL CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			"skipped cwe=0 cvss=0"},
		// v4.0 from a CNA
		"CVE-2010-10012": {"cwe CWE-22 nvd-secondary/disclosure@vulncheck.com",
			"cvss 4.0 nvd-secondary/disclosure@vulncheck.com 8.7 HIGH CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:X/CR:X/IR:X/AR:X/MAV:X/MAC:X/MAT:X/MPR:X/MUI:X/MVC:X/MVI:X/MVA:X/MSC:X/MSI:X/MSA:X/S:X/AU:X/R:X/V:X/RE:X/U:X",
			"skipped cwe=0 cvss=0"},
		"CVE-2018-0741": {"cvss 2.0 nvd-primary/nvd@nist.gov 2.6 LOW AV:N/AC:H/Au:N/C:P/I:N/A:N",
			"cvss 3.0 nvd-primary/nvd@nist.gov 5.3 MEDIUM CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
			"skipped cwe=1 cvss=0"}, // NVD-CWE-noinfo
		"CVE-2010-0278": {"cvss 2.0 nvd-primary/nvd@nist.gov 4.3 MEDIUM AV:N/AC:M/Au:N/C:N/I:N/A:P", "skipped cwe=1 cvss=0"}, // NVD-CWE-Other
		"CVE-2010-0735": {"REJECTED", "skipped cwe=0 cvss=0"},
		// no metrics; a CNA weakness typed "Primary" is still nvd-secondary
		"CVE-2026-83494": {"cwe CWE-693 nvd-secondary/secalert@redhat.com", "skipped cwe=0 cvss=0"},
		"CVE-2026-100365": {"cwe CWE-89 nvd-secondary/security-advisories@github.com", "cwe CWE-943 nvd-secondary/security-advisories@github.com",
			"cvss 3.1 nvd-secondary/security-advisories@github.com 8.8 HIGH CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", "skipped cwe=0 cvss=0"},
		// very large configurations: ignored
		"CVE-2010-3015": {"cwe CWE-189 nvd-primary/nvd@nist.gov",
			"cvss 2.0 nvd-primary/nvd@nist.gov 4.7 MEDIUM AV:L/AC:M/Au:N/C:N/I:N/A:C", "skipped cwe=0 cvss=0"},
		// hand-made: bad v2 value, v3.0 vector in the v3.1 slot
		"CVE-2010-99998": {"cwe CWE-22 nvd-primary/nvd@nist.gov", "skipped cwe=0 cvss=2"},
	}
	for id, w := range want {
		raw, ok := recs[id]
		if !ok {
			t.Fatalf("%s not in the fixture", id)
		}
		d, err := DeriveNVD(id, raw)
		if err != nil {
			t.Fatal(err)
		}
		check(t, id, d, w)
	}
}

func TestDeriveGHSA(t *testing.T) {
	recs := loadGHSA(t)
	want := [][]string{
		{"cwe CWE-613 ghsa/GHSA-2586-8ghr-69fj", "cvss 3.0 ghsa/GHSA-2586-8ghr-69fj 4.2 - CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:L/A:N", "skipped cwe=0 cvss=0"},
		{"REJECTED", "skipped cwe=0 cvss=0"}, // withdrawn
		{"cwe CWE-200 ghsa/GHSA-llll-llll-llll", "cvss 3.1 ghsa/GHSA-llll-llll-llll 5.3 - CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", "skipped cwe=1 cvss=0"},
	}
	for i, r := range recs {
		cve, d, err := DeriveGHSA(r)
		if err != nil || cve != "CVE-2026-126076" {
			t.Fatal(cve, err)
		}
		check(t, fmt.Sprint("ghsa ", i), d, want[i])
	}
}

func TestDeriveGHSAWithoutCVE(t *testing.T) {
	for _, cve := range []string{`null`, `""`, `"  "`} {
		id, d, err := DeriveGHSA([]byte(`{"ghsa_id":"GHSA-2cm2-m3w5-gp2f","cve_id":` + cve + `,"cwes":[{"cwe_id":"CWE-94"}]}`))
		if err != nil || id != "GHSA-2cm2-m3w5-gp2f" || d.CVEID != id || len(d.CWEs) != 1 {
			t.Errorf("%s: %q %+v %v", cve, id, d, err)
		}
	}
	// a malformed GHSA id keys nothing
	if id, _, _ := DeriveGHSA([]byte(`{"ghsa_id":"GHSA-xxxx","cve_id":null}`)); id != "" {
		t.Errorf("%q", id)
	}
}

func TestBestCVSSPrecedence(t *testing.T) {
	f := func(v float64) *float64 { return &v }
	c := &Classification{CVSS: []CVSSEntry{
		{Version: V31, Vector: "g", BaseScore: f(1), Source: SrcGHSA, SourceOrg: "GHSA-x"},
		{Version: V31, Vector: "s", BaseScore: f(2), Source: SrcNVDSecondary, SourceOrg: "a@b"},
		{Version: V31, Vector: "p", BaseScore: f(3), Source: SrcNVDPrimary, SourceOrg: NVDOwnSource},
		{Version: V31, Vector: "a2", Source: SrcADP, SourceOrg: "Z-ADP"},
		{Version: V31, Vector: "a1", Source: SrcADP, SourceOrg: "CISA-ADP"},
		{Version: V2, Vector: "p2", Source: SrcNVDPrimary, SourceOrg: NVDOwnSource},
		{Version: V2, Vector: "s2", Source: SrcNVDSecondary, SourceOrg: "x"},
		{Version: V40, Vector: "c4", Source: SrcCNA, SourceOrg: "VulDB"},
		{Version: V40, Vector: "g4", Source: SrcGHSA, SourceOrg: "GHSA-y"},
	}}
	got := map[string]string{}
	for v, e := range c.BestCVSS() {
		got[v] = e.Vector
	}
	want := map[string]string{V31: "a1", V2: "p2", V40: "c4"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%v != %v", got, want)
	}
	c.CVSS = append(c.CVSS, CVSSEntry{Version: V31, Vector: "cna", Source: SrcCNA, SourceOrg: "x"})
	if c.BestCVSS()[V31].Vector != "cna" {
		t.Error("cve-cna must win")
	}
}
