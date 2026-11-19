package webui

import (
	"strings"
	"testing"

	"nday.land/nday/internal/site"
)

// cvssConditions picks the exploitability metrics of each version, in
// display order, and marks values the version does not define.
func TestCVSSConditions(t *testing.T) {
	str := func(cs []cvssCond) string {
		var parts []string
		for _, c := range cs {
			k := c.Key
			if k == "" {
				k = "?"
			}
			parts = append(parts, c.Metric+":"+c.Value+"="+k)
		}
		return strings.Join(parts, " ")
	}
	for _, c := range []struct {
		name, vector, version, want string
	}{
		{"2.0", "AV:N/AC:M/Au:S/C:P/I:P/A:N", "2.0",
			"AV:N=vuln.cvss.av2 AC:M=vuln.cvss.ac2 Au:S=vuln.cvss.au"},
		{"2.0 with temporal metrics", "AV:L/AC:H/Au:M/C:C/I:C/A:C/E:POC/RL:OF/RC:C", "2.0",
			"AV:L=vuln.cvss.av2 AC:H=vuln.cvss.ac2 Au:M=vuln.cvss.au"},
		{"2.0 has no physical AV", "AV:P/AC:L/Au:N/C:N/I:N/A:P", "2.0",
			"AV:P=? AC:L=vuln.cvss.ac2 Au:N=vuln.cvss.au"},
		{"3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H", "3.1",
			"AV:N=vuln.cvss.av AC:L=vuln.cvss.ac PR:N=vuln.cvss.pr UI:R=vuln.cvss.ui"},
		{"3.0, any order", "CVSS:3.0/UI:N/PR:H/AC:H/AV:P/S:U/C:L/I:N/A:N", "3.0",
			"AV:P=vuln.cvss.av AC:H=vuln.cvss.ac PR:H=vuln.cvss.pr UI:N=vuln.cvss.ui"},
		{"4.0", "CVSS:4.0/AV:A/AC:H/AT:P/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "4.0",
			"AV:A=vuln.cvss.av AC:H=vuln.cvss.ac4 AT:P=vuln.cvss.at PR:L=vuln.cvss.pr UI:A=vuln.cvss.ui4"},
		{"4.0 passive UI", "CVSS:4.0/AV:L/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:A", "4.0",
			"AV:L=vuln.cvss.av AC:L=vuln.cvss.ac4 AT:N=vuln.cvss.at PR:N=vuln.cvss.pr UI:P=vuln.cvss.ui4"},
		{"unknown values", "CVSS:3.1/AV:Q/AC:L/PR:XX/UI:P/S:U/C:H/I:H/A:H", "3.1",
			"AV:Q=? AC:L=vuln.cvss.ac PR:XX=? UI:P=?"},
		{"4.0 UI:R is a 3.x value", "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:R/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "4.0",
			"AV:N=vuln.cvss.av AC:L=vuln.cvss.ac4 AT:N=vuln.cvss.at PR:N=vuln.cvss.pr UI:R=?"},
		{"missing metrics left out", "CVSS:3.1/AV:N/C:H", "3.1", "AV:N=vuln.cvss.av"},
		{"first of a repeated metric", "CVSS:3.1/AV:N/AV:L/AC:L/PR:N/UI:N", "3.1",
			"AV:N=vuln.cvss.av AC:L=vuln.cvss.ac PR:N=vuln.cvss.pr UI:N=vuln.cvss.ui"},
		{"unknown version", "CVSS:3.2/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "", ""},
		{"garbage", "not a vector", "", ""},
	} {
		ver, got := cvssConditions(c.vector)
		if ver != c.version || str(got) != c.want {
			t.Errorf("%s: %q %q, want %q %q", c.name, ver, str(got), c.version, c.want)
		}
	}
}

// The block in a locale: every defined value has its text, an undefined
// one only its code; the source line names version and provenance; no
// vector, no block.
func TestBuildCVSSView(t *testing.T) {
	en, zh := loc(t, "en"), loc(t, "zh-Hans")
	s := func(v string) *string { return &v }
	u := s("https://www.cve.org/CVERecord?id=CVE-2026-1")
	v := &site.VulnDetail{CVEID: "CVE-2026-1", Assigner: s("GitHub_M"),
		Events: []site.Event{{ID: 7, Type: "disclosed", Source: "cvelist", URL: u}},
		CVSS:   &site.CVSS{Vector: s("CVSS:3.1/AV:N/AC:L/PR:N/UI:Q/S:U/C:H/I:H/A:H"), Version: s("3.1"), Source: "cvelist:cna", EventID: 7}}
	cv := BuildCVSSView(en, v)
	if cv == nil || cv.Version != "3.1" || cv.Vector != *v.CVSS.Vector || len(cv.Items) != 4 {
		t.Fatalf("%+v", cv)
	}
	want := []CVSSItem{
		{Code: "AV:N", Label: "Attack vector", Text: "Network: the attacker only needs to reach it over the network"},
		{Code: "AC:L", Label: "Attack complexity", Text: "Low: no special conditions; the attacker can expect repeatable success"},
		{Code: "PR:N", Label: "Privileges required", Text: "None: no account or authorization needed"},
		{Code: "UI:Q", Label: "User interaction", Text: ""},
	}
	for i, w := range want {
		if cv.Items[i] != w {
			t.Errorf("item %d: %+v, want %+v", i, cv.Items[i], w)
		}
	}
	if got := string(cv.Source); got != `CVSS 3.1 vector from the CVE record, scored by the CNA <a href="https://www.cve.org/CVERecord?id=CVE-2026-1" target="_blank" rel="noopener noreferrer">GitHub_M</a>.` {
		t.Errorf("source: %s", got)
	}
	if cz := BuildCVSSView(zh, v); cz.Items[0].Label != "攻击途径" || !strings.HasPrefix(cz.Items[0].Text, "网络：") {
		t.Errorf("zh: %+v", cz.Items[0])
	}

	// 2.0 from an ADP; 4.0 from a GitHub advisory (its GHSA id, linked).
	v.CVSS = &site.CVSS{Vector: s("AV:A/AC:H/Au:N/C:P/I:N/A:N"), Version: s("2.0"), Source: "cvelist:adp:CISA-ADP", EventID: 7}
	cv = BuildCVSSView(en, v)
	if len(cv.Items) != 3 || cv.Items[2].Label != "Authentication" || cv.Items[2].Text != "None: no authentication" ||
		!strings.Contains(string(cv.Source), "CVSS 2.0 vector from the CVE record, added by the ADP <a") ||
		!strings.Contains(string(cv.Source), ">CISA-ADP</a>") {
		t.Errorf("2.0: %+v %s", cv.Items, cv.Source)
	}
	v.Events = append(v.Events, site.Event{ID: 9, Type: "patch_released", Source: "ghsa", DedupeKey: "GHSA-aaaa-bbbb-cccc",
		URL: s("https://github.com/advisories/GHSA-aaaa-bbbb-cccc")})
	v.CVSS = &site.CVSS{Vector: s("CVSS:4.0/AV:P/AC:L/AT:N/PR:H/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), Version: s("4.0"), Source: "ghsa", EventID: 9}
	cv = BuildCVSSView(zh, v)
	if len(cv.Items) != 5 || cv.Items[2].Label != "攻击前提" || cv.Items[2].Code != "AT:N" ||
		string(cv.Source) != `CVSS 4.0 向量，来自 GitHub 安全公告 <a href="https://github.com/advisories/GHSA-aaaa-bbbb-cccc" target="_blank" rel="noopener noreferrer">GHSA-aaaa-bbbb-cccc</a>。` {
		t.Errorf("4.0: %+v %s", cv.Items, cv.Source)
	}

	// An unknown version: the vector, no items; the source's version is named.
	v.CVSS = &site.CVSS{Vector: s("CVSS:5.0/AV:N"), Version: s("5.0"), Source: "ghsa", EventID: 404}
	cv = BuildCVSSView(en, v)
	if cv.Version != "" || len(cv.Items) != 0 || string(cv.Source) != `CVSS 5.0 vector, source <span>ghsa</span>.` {
		t.Errorf("unknown version: %+v %s", cv, cv.Source)
	}

	// No vector: no block.
	for _, c := range []*site.CVSS{nil, {Score: new(float64)}, {Vector: s("  ")}} {
		v.CVSS = c
		if BuildCVSSView(en, v) != nil {
			t.Errorf("block without a vector: %+v", c)
		}
	}
}
