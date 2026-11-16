package tags

import (
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"nday.land/nday/internal/classify"
)

func slugsOf(a []Assigned) string {
	var s []string
	for _, x := range a {
		s = append(s, x.Slug)
	}
	return strings.Join(s, " ")
}

func cwe(id string, src ...string) classify.CWEEntry {
	e := classify.CWEEntry{ID: id}
	for i := 0; i+1 < len(src); i += 2 {
		e.Sources = append(e.Sources, classify.Provenance{Source: src[i], SourceOrg: src[i+1]})
	}
	return e
}

func cvss(version, vector, source, org string) classify.CVSSEntry {
	return classify.CVSSEntry{Version: version, Vector: vector, Source: source, SourceOrg: org}
}

const (
	v31net  = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	v31ui   = "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H"
	v31loc  = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H"
	v31phys = "CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	v40net  = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	v40adj  = "CVSS:4.0/AV:A/AC:L/AT:N/PR:L/UI:A/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	v2net   = "AV:N/AC:L/Au:N/C:P/I:P/A:P"
	v2adj   = "AV:A/AC:L/Au:S/C:P/I:P/A:P"
)

func TestDerive(t *testing.T) {
	cna := func(id string) classify.CWEEntry { return cwe(id, classify.SrcCNA, "mitre") }
	for _, c := range []struct {
		name string
		in   Input
		want string
	}{
		{"empty", Input{}, ""},
		{"type from any source, several tags, vocabulary order",
			Input{CWE: []classify.CWEEntry{cwe("CWE-79", classify.SrcNVDPrimary, "nvd@nist.gov"), cna("CWE-89"), cwe("CWE-787", classify.SrcGHSA, "GHSA-x")}},
			"sql-injection buffer-overflow xss"},
		{"relatives map to one tag", Input{CWE: []classify.CWEEntry{cna("CWE-121"), cna("CWE-122"), cna("CWE-787")}}, "buffer-overflow"},
		{"one id, two tags", Input{CWE: []classify.CWEEntry{cna("CWE-680")}}, "buffer-overflow integer-overflow"},
		{"catch-alls get nothing", Input{CWE: []classify.CWEEntry{cna("CWE-20"), cna("CWE-74"), cna("CWE-264"), cna("CWE-693")}}, ""},
		{"v3.1 remote unauthenticated", Input{CVSS: []classify.CVSSEntry{cvss("3.1", v31net, classify.SrcCNA, "mitre")}},
			"remote-unauth network no-auth no-interaction"},
		{"v3.1 with user interaction: no composite", Input{CVSS: []classify.CVSSEntry{cvss("3.1", v31ui, classify.SrcCNA, "mitre")}},
			"network no-auth"},
		{"local", Input{CVSS: []classify.CVSSEntry{cvss("3.1", v31loc, classify.SrcCNA, "mitre")}}, "local no-interaction"},
		{"physical", Input{CVSS: []classify.CVSSEntry{cvss("3.1", v31phys, classify.SrcCNA, "mitre")}}, "physical no-auth no-interaction"},
		{"v4.0 adjacent", Input{CVSS: []classify.CVSSEntry{cvss("4.0", v40adj, classify.SrcCNA, "x")}}, "adjacent"},
		{"v2 only: never no-interaction or remote-unauth", Input{CVSS: []classify.CVSSEntry{cvss("2.0", v2net, classify.SrcNVDPrimary, "nvd@nist.gov")}},
			"network no-auth"},
		{"v2 adjacent with auth", Input{CVSS: []classify.CVSSEntry{cvss("2.0", v2adj, classify.SrcNVDPrimary, "nvd@nist.gov")}}, "adjacent"},
		{"v3 preferred over v2 even from a lower source",
			Input{CVSS: []classify.CVSSEntry{cvss("2.0", v2adj, classify.SrcCNA, "mitre"), cvss("3.1", v31net, classify.SrcGHSA, "GHSA-x")}},
			"remote-unauth network no-auth no-interaction"},
		{"among v3/v4 the higher source wins",
			Input{CVSS: []classify.CVSSEntry{cvss("4.0", v40adj, classify.SrcNVDSecondary, "x"), cvss("3.1", v31loc, classify.SrcCNA, "mitre")}},
			"local no-interaction"},
		{"same source: newest version",
			Input{CVSS: []classify.CVSSEntry{cvss("3.1", v31loc, classify.SrcCNA, "mitre"), cvss("4.0", v40net, classify.SrcCNA, "mitre")}},
			"remote-unauth network no-auth no-interaction"},
		{"invalid vector ignored", Input{CVSS: []classify.CVSSEntry{cvss("3.1", "CVSS:3.1/AV:N", classify.SrcCNA, "mitre")}}, ""},
		{"ransomware only when Known",
			Input{Events: []EventFact{{Type: "kev_added", Source: "kev", Ransomware: "Known"}}}, "ransomware"},
		{"ransomware Unknown / absent", Input{Events: []EventFact{{Type: "kev_added", Source: "kev", Ransomware: "Unknown"},
			{Type: "kev_added", Source: "kev"}}}, ""},
		{"ransomware from another source is ignored", Input{Events: []EventFact{{Type: "kev_added", Source: "xposts", Ransomware: "Known"}}}, ""},
		{"poc sources", Input{Events: []EventFact{{Type: "poc_published", Source: "metasploit", Key: "exploit/x"},
			{Type: "poc_published", Source: "exploitdb", Key: "1"}, {Type: "poc_published", Source: "nuclei", Key: "CVE-1"}}},
			"metasploit exploit-db nuclei"},
		{"non-public or other events never tag", Input{Events: []EventFact{{Type: "poc_published", Source: "xposts", Key: "1"},
			{Type: "social_post", Source: "xposts"}, {Type: "poc_published", Source: "github", Key: "x"}}}, ""},
		{"ecosystems", Input{Advisories: []Advisory{{ID: "GHSA-a", Packages: []Package{{"pip", "a"}, {"npm", "b"}, {"other", "c"}}},
			{ID: "GHSA-b", Packages: []Package{{"Rust", "d"}, {"actions", "e"}}}}}, "npm pypi crates-io github-actions"},
		{"rejected: nothing", Input{Rejected: true, CWE: []classify.CWEEntry{cna("CWE-79")},
			Events: []EventFact{{Type: "kev_added", Source: "kev", Ransomware: "Known"}}}, ""},
		{"suppressed rule tag left out", Input{CWE: []classify.CWEEntry{cna("CWE-79"), cna("CWE-89")}, Suppressed: []string{"xss"}},
			"sql-injection"},
	} {
		if got := slugsOf(Derive(c.in)); got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
}

func TestDeriveBasis(t *testing.T) {
	in := Input{
		CWE: []classify.CWEEntry{
			cwe("CWE-79", classify.SrcNVDPrimary, "nvd@nist.gov", classify.SrcCNA, "mitre"),
			cwe("CWE-80", classify.SrcGHSA, "GHSA-x"),
		},
		CVSS: []classify.CVSSEntry{cvss("2.0", v2net, classify.SrcNVDPrimary, "nvd@nist.gov")},
		Events: []EventFact{{Type: "kev_added", Source: "kev", Ransomware: "Known"},
			{Type: "poc_published", Source: "metasploit", Key: "b"}, {Type: "poc_published", Source: "metasploit", Key: "a"},
			{Type: "poc_published", Source: "metasploit", Key: "a"}},
		Advisories: []Advisory{{ID: "GHSA-z", Packages: []Package{{"npm", "y"}, {"npm", "x"}}}},
	}
	got := map[string]string{}
	for _, a := range Derive(in) {
		got[a.Slug] = a.Basis.Canonical()
	}
	want := map[string]string{
		// sources by precedence (CNA before NVD), CWE ids numerically
		"xss":        `{"cwe":[{"id":"CWE-79","sources":[{"source":"cve-cna","source_org":"mitre"},{"source":"nvd-primary","source_org":"nvd@nist.gov"}]},{"id":"CWE-80","sources":[{"source":"ghsa","source_org":"GHSA-x"}]}]}`,
		"network":    `{"cvss":{"metrics":["AV:N"],"source":"nvd-primary","source_org":"nvd@nist.gov","vector":"AV:N/AC:L/Au:N/C:P/I:P/A:P","version":"2.0"}}`,
		"no-auth":    `{"cvss":{"metrics":["Au:N"],"source":"nvd-primary","source_org":"nvd@nist.gov","vector":"AV:N/AC:L/Au:N/C:P/I:P/A:P","version":"2.0"}}`,
		"ransomware": `{"events":[{"count":1,"known_ransomware_campaign_use":"Known","source":"kev","type":"kev_added"}]}`,
		"metasploit": `{"events":[{"count":3,"keys":["a","b"],"source":"metasploit","type":"poc_published"}]}`,
		"npm":        `{"advisories":[{"ecosystem":"npm","id":"GHSA-z","packages":["x","y"]}]}`,
	}
	if len(got) != len(want) {
		t.Errorf("tags %v", got)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s basis\n got %s\nwant %s", k, got[k], w)
		}
	}
	// the canonical form of a jsonb rendering of the same value is equal
	var v any
	_ = json.Unmarshal([]byte(want["xss"]), &v)
	b, _ := json.MarshalIndent(v, "", "   ")
	if c, _ := CanonicalJSON(b); c != want["xss"] {
		t.Errorf("canonical %s", c)
	}
}

// The vocabulary: stable slug shape, unique, every type tag maps CWE ids,
// coverage of the 50 CWE ids most used in production (2026-11-14) except
// the deliberately unmapped catch-alls, and no unmapped id is also mapped.
func TestVocabulary(t *testing.T) {
	slugRe := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	dims := map[string]int{}
	for _, tg := range Vocabulary {
		if !slugRe.MatchString(tg.Slug) || tg.Label == "" || tg.Rule == "" {
			t.Errorf("bad entry %+v", tg)
		}
		dims[tg.Dim]++
		if (tg.Dim == DimType) != (len(tg.CWEs) > 0) {
			t.Errorf("%s: CWE list and dimension disagree", tg.Slug)
		}
	}
	if len(dims) != len(Dimensions) || dims[DimType] < 30 || dims[DimType] > 40 {
		t.Errorf("dimensions %v", dims)
	}
	unmapped := map[string]bool{}
	for _, u := range UnmappedCWEs {
		for _, id := range u.IDs {
			k := "CWE-" + strconv.Itoa(id)
			unmapped[k] = true
			if len(TagsForCWE(k)) > 0 {
				t.Errorf("%s is listed as unmapped but assigns %v", k, TagsForCWE(k))
			}
		}
	}
	// top 50 by CVE count in production (task brief, 2026-11-14: the first
	// 25) and on the local full import (the next 25)
	top := []int{79, 89, 862, 284, 22, 416, 352, 125, 20, 787, 200, 74, 78, 94, 121, 122, 863, 918, 119, 400, 434, 639,
		120, 306, 502, 287, 77, 269, 476, 190, 770, 285, 362, 601, 98, 266, 295, 732, 798, 59, 276, 532, 693, 427, 522,
		611, 843, 367, 347, 73}
	for _, id := range top {
		k := "CWE-" + strconv.Itoa(id)
		if len(TagsForCWE(k)) == 0 && !unmapped[k] {
			t.Errorf("%s (top 50) is neither mapped nor listed as unmapped", k)
		}
	}
	if !Valid("xss") || Valid("XSS") || Valid("nope") {
		t.Error("Valid")
	}
}

func TestParseFilterAndRowPicks(t *testing.T) {
	got, bad := ParseFilter([]string{" XSS ", "remote-unauth", "nope", "xss", "", "ransomware"})
	if strings.Join(got, ",") != "xss,remote-unauth,ransomware" || strings.Join(bad, ",") != "nope" {
		t.Errorf("ParseFilter %v %v", got, bad)
	}
	many, _ := ParseFilter([]string{"xss", "csrf", "ssrf", "xxe", "npm", "go", "pub"})
	if len(many) != MaxFilterTags {
		t.Errorf("cap %v", many)
	}
	all := []string{"network", "metasploit", "xss", "sql-injection", "ransomware", "remote-unauth", "npm"}
	Sort(all)
	if p := strings.Join(RowPicks(all), ","); p != "remote-unauth,ransomware,sql-injection" {
		t.Errorf("RowPicks %s", p)
	}
	if p := RowPicks([]string{"network", "npm"}); len(p) != 0 {
		t.Errorf("RowPicks without signal %v", p)
	}
	s := []string{"npm", "xss", "network"}
	Sort(s)
	if !sort.SliceIsSorted(s, func(i, j int) bool { return Order(s[i]) < Order(s[j]) }) || s[0] != "xss" {
		t.Errorf("Sort %v", s)
	}
}
