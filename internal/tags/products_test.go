package tags

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// The registry's shape: valid unique slugs, every product has known product
// types, no product rule matches on product text alone or on a vendor alone
// (high precision; only type rules may), type rules name a known type.
func TestProductRegistry(t *testing.T) {
	slugRe := regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	types := map[string]bool{}
	for _, pt := range productTypeTags {
		types[pt.Slug] = true
		if pt.Dim != DimProductType {
			t.Errorf("%s: dimension %s", pt.Slug, pt.Dim)
		}
	}
	if len(types) != 23 {
		t.Errorf("%d product types, want 23", len(types))
	}
	for _, p := range Products {
		if !slugRe.MatchString(p.Slug) || p.Label == "" {
			t.Errorf("product %q: bad slug or label", p.Slug)
		}
		if tg, ok := Lookup(p.Slug); !ok || tg.Dim != DimProduct {
			t.Errorf("product %s not in the vocabulary as a product tag", p.Slug)
		}
		if len(p.Types) == 0 {
			t.Errorf("product %s has no type", p.Slug)
		}
		for _, ty := range p.Types {
			if !types[ty] {
				t.Errorf("product %s: unknown type %s", p.Slug, ty)
			}
		}
		if len(p.Aff) == 0 {
			t.Errorf("product %s has no affected rule", p.Slug)
		}
		for _, m := range p.Aff {
			if len(m.Vendors) == 0 {
				t.Errorf("product %s: a rule without vendors (product text alone)", p.Slug)
			}
			if len(m.Exact)+len(m.Prefix)+len(m.Words) == 0 {
				t.Errorf("product %s: a vendor-only rule", p.Slug)
			}
			for _, v := range m.Vendors {
				if Normalize(v) != v {
					t.Errorf("product %s: vendor %q not normalized", p.Slug, v)
				}
			}
			for _, x := range append(append(append([]string(nil), m.Exact...), m.Prefix...), m.Words...) {
				if Normalize(x) != x || x == "" {
					t.Errorf("product %s: pattern %q not normalized", p.Slug, x)
				}
			}
		}
		for _, c := range p.CPE {
			if len(c.Vendors) == 0 || len(c.Exact)+len(c.Prefix) == 0 {
				t.Errorf("product %s: empty CPE rule", p.Slug)
			}
		}
	}
	ids := map[string]bool{}
	for _, r := range TypeRules {
		if ids[r.ID] || !types[r.Type] || r.Why == "" {
			t.Errorf("type rule %s: duplicate, unknown type %q or no reason", r.ID, r.Type)
		}
		ids[r.ID] = true
		if r.Match.Vendors == nil && len(r.Match.Exact)+len(r.Match.Prefix)+len(r.Match.Words) == 0 {
			t.Errorf("type rule %s matches everything", r.ID)
		}
	}
	// no product or product-type slug collides with another dimension's
	// (init panics on duplicates; this names the dimensions)
	seen := map[string]string{}
	for _, tg := range Vocabulary {
		if d, dup := seen[tg.Slug]; dup {
			t.Errorf("slug %s in %s and %s", tg.Slug, d, tg.Dim)
		}
		seen[tg.Slug] = tg.Dim
	}
}

func TestParseCPE(t *testing.T) {
	for in, want := range map[string]string{
		"cpe:2.3:o:microsoft:windows_10_1809:-:*:*:*:*:*:x64:*": "o|microsoft|windows_10_1809",
		`cpe:2.3:a:joomla:joomla\!:1.5.0:*:*:*:*:*:*:*`:         "a|joomla|joomla!",
		`cpe:2.3:a:acme:foo\:bar:1.0:*:*:*:*:*:*:*`:             "a|acme|foo:bar",
		"cpe:2.3:H:Cisco:ASA_5505:-:*:*:*:*:*:*:*":              "h|cisco|asa_5505",
		"cpe:2.3:a:acme:widget":                                 "a|acme|widget",
		"cpe:2.3:x:acme:widget:1":                               "",
		"cpe:2.3:a:*:widget:1":                                  "",
		"cpe:/a:acme:widget:1":                                  "",
		"":                                                      "",
	} {
		c, ok := ParseCPE(in)
		got := ""
		if ok {
			got = c.Part + "|" + c.Vendor + "|" + c.Product
		}
		if got != want {
			t.Errorf("ParseCPE(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchWords(t *testing.T) {
	for _, c := range []struct {
		s, p string
		want bool
	}{
		{"cisco ios xe software", "ios xe", true},
		{"cisco ios xe software", "ios", true},
		{"windows 10 version 1809", "windows", true},
		{"windowsfoo", "windows", false},
		{"d-link dir-605l", "dir-", true},
		{"undir-605", "dir-", false},
		{"for joomla", "for joomla", true},
		{"vue-router", "router", true}, // why the router type rule never uses bare "router"
		{"routers", "router", false},
	} {
		if got := containsWord(c.s, c.p); got != c.want {
			t.Errorf("containsWord(%q, %q) = %t", c.s, c.p, got)
		}
	}
	if !hasWordPrefix("junos os evolved", "junos os") || hasWordPrefix("junosx", "junos") || !hasWordPrefix("big-ip (ltm)", "big-ip") {
		t.Error("hasWordPrefix")
	}
	if Normalize("  Microsoft \t Windows  10 ") != "microsoft windows 10" {
		t.Error("Normalize")
	}
}

func rowsOf(rows ...string) []AffectedRow {
	var out []AffectedRow
	for _, r := range rows {
		v, p, _ := strings.Cut(r, "|")
		out = append(out, AffectedRow{Vendor: v, Product: p})
	}
	return out
}

func cpes(names ...string) []CPE {
	var out []CPE
	for _, n := range names {
		c, ok := ParseCPE(n)
		if !ok {
			panic(n)
		}
		out = append(out, c)
	}
	return out
}

// Spellings and versions of a family collapse into one tag; products bring
// their types; precision guards (other vendors, excluded wordings) hold.
func TestDeriveProducts(t *testing.T) {
	for _, c := range []struct {
		name string
		in   Input
		want string
	}{
		{"windows spellings collapse", Input{Affected: rowsOf("Microsoft|Windows 10 Version 1809", "Microsoft Corporation|Windows Kernel",
			"microsoft|Windows 11 version 24H2")}, "windows operating-system"},
		{"windows server is its own family", Input{Affected: rowsOf("Microsoft|Windows Server 2019 (Server Core installation)")},
			"windows-server operating-system"},
		{"edge on windows is not windows", Input{Affected: rowsOf("Microsoft|Microsoft Edge (EdgeHTML-based) on Windows 10 Version 1809")},
			"edge browser"},
		{"chrome", Input{Affected: rowsOf("Google|Chrome")}, "chrome browser"},
		{"chrome extension of another vendor", Input{Affected: rowsOf("Securly|Securly Chrome Extension")}, ""},
		{"apple vs appleple", Input{Affected: rowsOf("appleple inc.|a-blog cms")}, ""},
		{"android spellings", Input{Affected: rowsOf("Google Inc.|Android", "google|Android")}, "android operating-system"},
		{"linux kernel", Input{Affected: rowsOf("Linux|Linux")}, "linux-kernel operating-system"},
		{"two types", Input{Affected: rowsOf("Citrix|NetScaler ADC and NetScaler Gateway")}, "netscaler network-device firewall-vpn"},
		{"vendor type rule", Input{Affected: rowsOf("Tenda|AC15")}, "network-device"},
		{"words type rule", Input{Affected: rowsOf("Some Dev|Contact Form for WordPress")}, "cms"},
		{"router word not bare", Input{Affected: rowsOf("vuejs|vue-router")}, ""},
		{"simatic mfp is not a printer", Input{Affected: rowsOf("Siemens|SIMATIC S7-1500 CPU 1518-4 PN/DP MFP")}, "simatic ics"},
		{"cpe only", Input{CPEs: cpes("cpe:2.3:o:fortinet:fortios:7.2.0:*:*:*:*:*:*:*")}, "fortios firewall-vpn"},
		{"cpe windows server not windows", Input{CPEs: cpes("cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*")}, "windows-server operating-system"},
		{"cpe vendor type rule", Input{CPEs: cpes("cpe:2.3:o:netgear:r7000_firmware:-:*:*:*:*:*:*:*")}, "network-device"},
		{"rejected", Input{Rejected: true, Affected: rowsOf("Google|Chrome")}, ""},
		{"suppressed product", Input{Affected: rowsOf("Google|Chrome"), Suppressed: []string{"chrome"}}, "browser"},
		{"suppressed type", Input{Affected: rowsOf("Google|Chrome"), Suppressed: []string{"browser"}}, "chrome"},
	} {
		if got := slugsOf(Derive(c.in)); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

// The basis lists the matched affected rows as stored (sorted, deduplicated,
// capped) and the CPE triples separately; a product-type basis names the
// products and type rules that gave it.
func TestDeriveProductBasis(t *testing.T) {
	var rows []string
	for i := 0; i < 13; i++ {
		rows = append(rows, fmt.Sprintf("Microsoft|Windows 10 Version 1%03d", 999-i))
	}
	rows = append(rows, "Microsoft|Windows 10 Version 1999") // duplicate row
	got := map[string]Basis{}
	for _, a := range Derive(Input{Affected: rowsOf(append(rows, "Tenda|AC15")...),
		CPEs: cpes("cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_10:1809:*:*:*:*:*:*:*")}) {
		got[a.Slug] = a.Basis
	}
	w := got["windows"]
	if w.AffectedCount != 13 || len(w.Affected) != maxBasisItems || w.Affected[0].Product != "Windows 10 Version 1987" ||
		w.Affected[0].Vendor != "Microsoft" || w.CPECount != 1 || len(w.CPE) != 1 || w.CPE[0] != (BasisCPE{"o", "microsoft", "windows_10"}) ||
		len(w.Products) != 0 || len(w.TypeRules) != 0 {
		t.Errorf("windows basis %s", w.Canonical())
	}
	os := got["operating-system"]
	if strings.Join(os.Products, " ") != "windows" || len(os.TypeRules) != 0 || os.AffectedCount != 13 {
		t.Errorf("operating-system basis %s", os.Canonical())
	}
	nd := got["network-device"]
	if strings.Join(nd.TypeRules, " ") != "vendor:tenda" || len(nd.Products) != 0 || len(nd.Affected) != 1 || nd.Affected[0].Product != "AC15" {
		t.Errorf("network-device basis %s", nd.Canonical())
	}
	if c := w.Canonical(); !strings.Contains(c, `"affected_count":13`) || !strings.Contains(c, `"cpe":[{"part":"o","product":"windows_10","vendor":"microsoft"}]`) {
		t.Errorf("canonical %s", c)
	}
}
