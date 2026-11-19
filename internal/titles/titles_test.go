package titles

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// English labels of the type tags the cases use (internal/tags vocabulary;
// TestEnglishLabels in internal/tags checks the real ones render the same).
var labels = map[string]string{
	"buffer-overflow": "buffer overflow / out-of-bounds write", "sql-injection": "SQL injection", "xss": "XSS",
	"path-traversal": "path traversal", "command-injection": "command injection", "use-after-free": "use-after-free",
	"info-disclosure": "information disclosure", "csrf": "CSRF", "auth-bypass": "authentication bypass",
	"resource-exhaustion": "resource exhaustion", "null-dereference": "NULL pointer dereference",
	"broken-access-control": "broken access control", "deserialization": "deserialization of untrusted data",
	"ssrf": "SSRF", "file-upload": "unrestricted file upload", "out-of-bounds-read": "out-of-bounds read",
}

func label(s string) string { return labels[s] }

const oracleJava = "Vulnerability in the Oracle Java SE, Oracle GraalVM for JDK, Oracle GraalVM Enterprise Edition product of Oracle Java SE (component: Compiler). Supported versions that are affected are Oracle Java SE: 8u471, 11.0.29; Oracle GraalVM for JDK: 17.0.17. Easily exploitable vulnerability allows unauthenticated attacker with network access via multiple protocols to compromise Oracle Java SE."

const oracleMySQL = "Vulnerability in the MySQL Server product of Oracle MySQL (component: Server: Optimizer). Supported versions that are affected are 8.0.43 and prior. Easily exploitable vulnerability allows high privileged attacker with network access via multiple protocols to compromise MySQL Server."

const vuldb = "A vulnerability was found in itsourcecode Online Hotel Management System 1.0. It has been classified as critical. This affects an unknown part of the file /admin/edit_room.php of the component Room Handler. The manipulation of the argument id leads to sql injection. It is possible to initiate the attack remotely."

const vuldbNoComponent = "A vulnerability classified as problematic has been found in code-projects Simple Blog 1.0. Affected is an unknown function of the file /search.php. The manipulation of the argument q leads to cross site scripting."

const kernel = "In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: fix use-after-free in nft_set_catchall_destroy(). Free the element after removing it from the list."

const wordfence = "The Essential Addons for Elementor plugin for WordPress is vulnerable to Stored Cross-Site Scripting via the 'title' parameter in all versions up to, and including, 6.0.3 due to insufficient input sanitization and output escaping."

const github = "Next.js is a React framework for building full-stack web applications. In versions 15.0.0 through 15.2.2, an attacker can bypass authorization checks in middleware by sending a crafted x-middleware-subrequest header."

const mitre = "An issue was discovered in the Netfilter component of the Linux kernel before 6.1.2. A crafted packet leads to a NULL pointer dereference."

const apache = "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') vulnerability in Apache Tomcat. This issue affects Apache Tomcat: from 11.0.0-M1 through 11.0.2."

const hpe = "The XML Parser component of HPE Integrated Lights-Out 5 before 3.05 allows a remote attacker to read arbitrary files."

const talos = "A heap-based buffer overflow vulnerability exists in the PDF parsing functionality of Foxit PDF Reader 2024.2.3.25184. A specially crafted PDF document can lead to memory corruption."

const zdi = "Ivanti Endpoint Manager Path Traversal Information Disclosure Vulnerability. This vulnerability allows remote attackers to disclose sensitive information on affected installations of Ivanti Endpoint Manager."

const msrc = "Windows Kernel Elevation of Privilege Vulnerability"

const cisco = "A vulnerability in the web-based management interface of Cisco IOS XE Software could allow an unauthenticated, remote attacker to conduct a cross-site request forgery (CSRF) attack on an affected system."

const sap = "SAP NetWeaver Visual Composer Metadata Uploader is not protected with a proper authorization, allowing unauthenticated agent to upload potentially malicious executable binaries."

const siemens = "A vulnerability has been identified in SIMATIC S7-1500 CPU family (All versions < V3.1.5). Affected devices do not properly handle specially crafted packets."

func TestCompose(t *testing.T) {
	aff := func(vp ...string) []Affected {
		var out []Affected
		for i := 0; i+1 < len(vp); i += 2 {
			out = append(out, Affected{vp[i], vp[i+1]})
		}
		return out
	}
	cases := []struct {
		name string
		in   Input
		want string // English rendering ("" = untitled)
		form string
	}{
		// --- the live Oracle example: one product tag, a type tag, Oracle's component
		{"oracle java (live example)", Input{Description: oracleJava, ProductLabels: []string{"Java SE"},
			Affected: aff("Oracle Corporation", "Oracle Java SE", "Oracle Corporation", "Oracle GraalVM for JDK", "Oracle Corporation", "Oracle GraalVM Enterprise Edition"),
			Weakness: "buffer-overflow"}, "Java SE: buffer overflow / out-of-bounds write in Compiler", FormFull},
		{"oracle java, no type tag", Input{Description: oracleJava, ProductLabels: []string{"Java SE"}},
			"Java SE: vulnerability in Compiler", FormComponent},
		{"oracle mysql, no product tag: affected row, vendor dropped", Input{Description: oracleMySQL,
			Affected: aff("Oracle Corporation", "MySQL Server")}, "Oracle MySQL Server: vulnerability in Server: Optimizer", FormComponent},
		{"oracle product names the vendor", Input{Description: oracleJava, Affected: aff("Oracle Corporation", "Oracle Java SE")},
			"Oracle Java SE: vulnerability in Compiler", FormComponent},
		{"oracle, two product tags: affected row", Input{Description: oracleJava, ProductLabels: []string{"Java SE", "GraalVM"},
			Affected: aff("Oracle Corporation", "Oracle GraalVM for JDK", "Oracle Corporation", "Oracle Java SE")},
			"Oracle GraalVM for JDK: vulnerability in Compiler", FormComponent},
		{"oracle duplicate product tag label", Input{Description: oracleJava, ProductLabels: []string{"Java SE", "Java SE"}},
			"Java SE: vulnerability in Compiler", FormComponent},
		{"oracle with weakness, mysql", Input{Description: oracleMySQL, Affected: aff("Oracle Corporation", "MySQL Server"),
			Weakness: "resource-exhaustion"}, "Oracle MySQL Server: resource exhaustion in Server: Optimizer", FormFull},
		// --- VulDB
		{"vuldb component + sqli", Input{Description: vuldb, Affected: aff("itsourcecode", "Online Hotel Management System"),
			Weakness: "sql-injection"}, "itsourcecode Online Hotel Management System: SQL injection in Room Handler", FormFull},
		{"vuldb without component", Input{Description: vuldbNoComponent, Affected: aff("code-projects", "Simple Blog"),
			Weakness: "xss"}, "code-projects Simple Blog: XSS", FormWeakness},
		{"vuldb no tags no component: excerpt", Input{Description: vuldbNoComponent, Affected: aff("code-projects", "Simple Blog")},
			"A vulnerability classified as problematic has been found in code-projects Simple Blog 1.0", FormExcerpt},
		// --- kernel.org
		{"kernel: product tag + type tag", Input{Description: kernel, ProductLabels: []string{"Linux kernel"},
			Affected: aff("Linux", "Linux"), Weakness: "use-after-free"}, "Linux kernel: use-after-free", FormWeakness},
		{"kernel: vendor = product", Input{Description: kernel, Affected: aff("Linux", "Linux"), Weakness: "use-after-free"},
			"Linux: use-after-free", FormWeakness},
		{"kernel: no tags: excerpt cut", Input{Description: kernel, Affected: aff("Linux", "Linux")},
			"Linux: vulnerability in …", ""}, // replaced below: no component, so excerpt
		// --- MITRE "in the X component"
		{"mitre component phrase", Input{Description: mitre, Affected: aff("n/a", "n/a"), ProductLabels: []string{"Linux kernel"},
			Weakness: "null-dereference"}, "Linux kernel: NULL pointer dereference in Netfilter", FormFull},
		{"mitre placeholders only: excerpt", Input{Description: mitre, Affected: aff("n/a", "n/a"), Weakness: "null-dereference"},
			"An issue was discovered in the Netfilter component of the Linux kernel before 6.1.2", FormExcerpt},
		// --- Wordfence
		{"wordfence plugin vendor handle", Input{Description: wordfence, Affected: aff("wpdevteam", "Essential Addons for Elementor"),
			Weakness: "xss"}, "wpdevteam Essential Addons for Elementor: XSS", FormWeakness},
		// --- GitHub advisory-style
		{"github vendor = org", Input{Description: github, Affected: aff("vercel", "next.js"), Weakness: "auth-bypass"},
			"vercel next.js: authentication bypass", FormWeakness},
		// --- Apache
		{"apache foundation + product with first word", Input{Description: apache, Affected: aff("Apache Software Foundation", "Apache Tomcat"),
			Weakness: "path-traversal"}, "Apache Tomcat: path traversal", FormWeakness},
		{"apache with leading The", Input{Description: apache, Affected: aff("The Apache Software Foundation", "Apache Tomcat"),
			Weakness: "path-traversal"}, "Apache Tomcat: path traversal", FormWeakness},
		// --- HPE "The X component of"
		{"hpe sentence-start component", Input{Description: hpe, Affected: aff("Hewlett Packard Enterprise (HPE)", "HPE Integrated Lights-Out 5 (iLO 5)")},
			"HPE Integrated Lights-Out 5 (iLO 5): vulnerability in XML Parser", FormComponent},
		// --- Talos, ZDI, MSRC, Cisco, SAP, Siemens
		{"talos", Input{Description: talos, Affected: aff("Foxit", "PDF Reader"), Weakness: "buffer-overflow"},
			"Foxit PDF Reader: buffer overflow / out-of-bounds write", FormWeakness},
		{"zdi", Input{Description: zdi, Affected: aff("Ivanti", "Endpoint Manager"), Weakness: "path-traversal"},
			"Ivanti Endpoint Manager: path traversal", FormWeakness},
		{"msrc no tags: excerpt", Input{Description: msrc, Affected: aff("Microsoft", "Windows 10 Version 22H2")},
			"Windows Kernel Elevation of Privilege Vulnerability", FormExcerpt},
		{"msrc with tag", Input{Description: msrc, Affected: aff("Microsoft", "Windows 10 Version 22H2", "Microsoft", "Windows 11 Version 24H2"),
			Weakness: "use-after-free"}, "Microsoft Windows 10 Version 22H2: use-after-free", FormWeakness},
		{"cisco", Input{Description: cisco, Affected: aff("Cisco", "Cisco IOS XE Software"), Weakness: "csrf"},
			"Cisco IOS XE Software: CSRF", FormWeakness},
		{"sap", Input{Description: sap, Affected: aff("SAP_SE", "SAP NetWeaver (Visual Composer development server)"), Weakness: "file-upload"},
			"SAP NetWeaver (Visual Composer development server): unrestricted file upload", FormWeakness},
		{"siemens: product tag none, many rows: first", Input{Description: siemens,
			Affected: aff("Siemens", "SIMATIC S7-1500 CPU 1511-1 PN", "Siemens", "SIMATIC S7-1500 CPU 1513-1 PN")},
			"Siemens SIMATIC S7-1500 CPU 1511-1 PN", ""}, // replaced below
		// --- vendor suffixes
		{"inc suffix", Input{Affected: aff("Google Inc.", "Chrome"), Weakness: "use-after-free"}, "Google Chrome: use-after-free", FormWeakness},
		{"llc suffix", Input{Affected: aff("Google LLC", "Android"), Weakness: "out-of-bounds-read"}, "Google Android: out-of-bounds read", FormWeakness},
		{"co ltd suffix", Input{Affected: aff("Shenzhen Tenda Technology Co.,Ltd.", "AC15"), Weakness: "buffer-overflow"},
			"Shenzhen Tenda Technology AC15: buffer overflow / out-of-bounds write", FormWeakness},
		{"gmbh suffix", Input{Affected: aff("Pilz GmbH & Co. KG", "PASvisu"), Weakness: "info-disclosure"},
			"Pilz GmbH & Co. KG PASvisu: information disclosure", FormWeakness},
		{"corp. suffix", Input{Affected: aff("Zyxel Corp.", "NAS326 firmware"), Weakness: "command-injection"},
			"Zyxel NAS326 firmware: command injection", FormWeakness},
		{"vendor placeholder", Input{Affected: aff("n/a", "libxml2"), Weakness: "use-after-free"}, "libxml2: use-after-free", FormWeakness},
		{"vendor and product placeholders, rows skipped", Input{Affected: aff("unspecified", "unspecified", "Acme", "Widget"), Weakness: "ssrf"},
			"Acme Widget: SSRF", FormWeakness},
		// --- excerpt rules
		{"record title present: nothing", Input{RecordTitle: "Foo: bar", Description: vuldb, Affected: aff("a", "b"), Weakness: "xss"}, "", ""},
		{"record title blank: composed", Input{RecordTitle: "  ", Description: msrc}, "Windows Kernel Elevation of Privilege Vulnerability", FormExcerpt},
		{"no data at all", Input{}, "", ""},
		{"rejected notice", Input{Description: "** REJECT ** DO NOT USE THIS CANDIDATE NUMBER. Reason: duplicate."}, "", ""},
		{"rejected reason", Input{Description: "Rejected reason: This CVE ID has been rejected or withdrawn by its CVE Numbering Authority."}, "", ""},
		{"disputed marker dropped", Input{Description: "** DISPUTED ** Foo Bar 2.1 allows remote attackers to cause a denial of service via a crafted request. NOTE: the vendor disputes this."},
			"Foo Bar 2.1 allows remote attackers to cause a denial of service via a crafted request", FormExcerpt},
		{"versions, e.g. and initials are not sentence ends", Input{Description: "Acme Server before 2.4.1 allows attackers (e.g. remote ones) to read files via J. Doe's plugin. More text."},
			"Acme Server before 2.4.1 allows attackers (e.g. remote ones) to read files via J. Doe's plugin", FormExcerpt},
		{"a version number ends a sentence", Input{Description: "Acme Server is affected up to version 2. The fix is in 3.0."},
			"Acme Server is affected up to version 2", FormExcerpt},
		{"long first sentence cut at a word", Input{Description: "The quick brown fox component handler in the Example Product Suite for Enterprise Deployments allows unauthenticated remote attackers to execute arbitrary code via a crafted request to the management endpoint."},
			"The quick brown fox component handler in the Example Product Suite for Enterprise Deployments…", FormExcerpt},
		{"too short description", Input{Description: "TBD."}, "", ""},
		{"html markup removed", Input{Description: "<p>Stored <b>XSS</b> in Foo&amp;Bar admin panel.</p><p>More.</p>"},
			"Stored XSS in Foo&Bar admin panel", FormExcerpt},
		{"script tag and entities are text-free", Input{Description: "&lt;script&gt;alert(1)&lt;/script&gt; Reflected input in search page of Shop 1.0."},
			"alert(1) Reflected input in search page of Shop 1.0", FormExcerpt},
		{"bidi and zero-width removed", Input{Description: "Acme\u202e Gateway\u200b allows\u2066 spoofing of logs.\u2069"},
			"Acme Gateway allows spoofing of logs", FormExcerpt},
		{"control characters become spaces", Input{Description: "Acme\tGateway\r\nallows\x00spoofing\x1b[31m of logs."},
			"Acme Gateway allows spoofing [31m of logs", FormExcerpt},
		{"backticks removed", Input{Description: "The `parse()` function of libfoo mishandles input."}, "The parse() function of libfoo mishandles input", FormExcerpt},
		// --- component guards
		{"affected component is no component", Input{Description: "A flaw in the affected component of Foo allows bypass.", Affected: aff("Foo", "Foo")},
			"A flaw in the affected component of Foo allows bypass", FormExcerpt},
		{"component equal to product dropped", Input{Description: "An issue in the Foo component of Foo.", Affected: aff("Acme", "Foo"), Weakness: "xss"},
			"Acme Foo: XSS", FormWeakness},
		{"overlong component ignored", Input{Description: "Bug (component: " + strings.Repeat("x", 61) + ").", Affected: aff("Acme", "Foo"), Weakness: "xss"},
			"Acme Foo: XSS", FormWeakness},
		{"hostile component text", Input{Description: "Vulnerability in Foo (component: <img src=x onerror=alert(1)> Core).", Affected: aff("Acme", "Foo")},
			"Acme Foo: vulnerability in Core", FormComponent},
		{"long product cut", Input{Affected: aff("Acme", strings.Repeat("Enterprise ", 10)+"Suite"), Weakness: "xss"},
			"Acme Enterprise Enterprise Enterprise Enterprise…: XSS", FormWeakness},
	}
	cases[12].want, cases[12].form = "In the Linux kernel, the following vulnerability has been resolved: netfilter: nf_tables: fix…", FormExcerpt
	cases[26].want, cases[26].form = "A vulnerability has been identified in SIMATIC S7-1500 CPU family (All versions < V3.1.5)", FormExcerpt
	for _, c := range cases {
		p := Compose(c.in)
		got := English(p, label)
		if got != c.want || p.Form != c.form {
			t.Errorf("%s:\n got %q (%s)\nwant %q (%s)", c.name, got, p.Form, c.want, c.form)
		}
		if p.Excerpt != "" && utf8.RuneCountInString(p.Excerpt) > MaxExcerpt {
			t.Errorf("%s: excerpt too long", c.name)
		}
		if utf8.RuneCountInString(p.Product) > MaxProduct || utf8.RuneCountInString(p.Component) > MaxComponent {
			t.Errorf("%s: part too long %+v", c.name, p)
		}
		for _, s := range []string{p.Product, p.Component, p.Excerpt} {
			if strings.ContainsAny(s, "\u202e\u200b\u2066\u2069\x00\t\n") || strings.Contains(s, "<img") {
				t.Errorf("%s: unclean part %q", c.name, s)
			}
		}
	}
	if len(cases) < 40 {
		t.Fatalf("only %d cases", len(cases))
	}
}

func TestCut(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"short", 10, "short"},
		{"exactly ten", 11, "exactly ten"},
		{"one two three four", 10, "one two…"},
		{"averyveryverylongword", 10, "averyvery…"},
		{"one two, three", 10, "one two…"},
	} {
		if got := cut(c.in, c.n); got != c.want {
			t.Errorf("cut(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
}

func TestNormalizeVendor(t *testing.T) {
	for in, want := range map[string]string{
		"Oracle Corporation": "Oracle", "Microsoft Corporation": "Microsoft", "Google LLC": "Google", "Apple Inc.": "Apple",
		"Foo Co., Ltd.": "Foo", "The Apache Software Foundation": "Apache Software Foundation", "Siemens AG": "Siemens",
		"Acme, Inc.": "Acme", "Inc.": "Inc.", "SAP SE": "SAP", "SAP_SE": "SAP", "n/a": "n/a",
		"Hewlett Packard Enterprise (HPE)": "Hewlett Packard Enterprise",
	} {
		if got := NormalizeVendor(in); got != want {
			t.Errorf("NormalizeVendor(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCleanStaff(t *testing.T) {
	ok := map[string]string{
		"  Java SE: JIT compiler memory corruption  ": "Java SE: JIT compiler memory corruption",
		"a  b":                   "a b",
		"Cafe\u0301":             "Café", // NFC
		strings.Repeat("x", 160): strings.Repeat("x", 160),
		"中文标题：远程代码执行":            "中文标题：远程代码执行",
	}
	for in, want := range ok {
		got, err := CleanStaff(in)
		if err != nil || got != want {
			t.Errorf("CleanStaff(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "   ", "a\nb", "a\rb", "a\tb", "a\u202eb", "a\u200bb", "a\u2028b", "a\x00b",
		strings.Repeat("x", 161), "bad\xffutf8"} {
		if got, err := CleanStaff(in); err == nil {
			t.Errorf("CleanStaff(%q) = %q, want an error", in, got)
		}
	}
}

func TestRenderPatterns(t *testing.T) {
	p := Parts{Form: FormFull, Product: "Java SE", Weakness: "buffer-overflow", Component: "Compiler"}
	if got := Render("{product}：{component} 中的 {weakness}", p, "buffer overflow / out-of-bounds write"); got != "Java SE：Compiler 中的 buffer overflow / out-of-bounds write" {
		t.Errorf("zh %q", got)
	}
	if got := English(Parts{}, label); got != "" {
		t.Errorf("empty %q", got)
	}
	if got := English(Parts{Form: FormExcerpt, Excerpt: "x y"}, label); got != "x y" {
		t.Errorf("excerpt %q", got)
	}
	// a placeholder inside a part is not expanded again
	if got := Render(EnglishPattern(FormFull), Parts{Form: FormFull, Product: "{component}", Weakness: "xss", Component: "C"}, "XSS"); got != "{component}: XSS in C" {
		t.Errorf("nested %q", got)
	}
}

// Findings of the review: a suffix cut must not split a character, a
// version range is not markup, and a VulDB component stops at the verb.
func TestReviewCases(t *testing.T) {
	for _, v := range []string{"Foo İNC", "ACME TEKNOLOJİ LİMİTED", "İİİ, ltd", "X İ inc"} {
		if got := NormalizeVendor(v); !utf8.ValidString(got) {
			t.Errorf("NormalizeVendor(%q) = %q: invalid UTF-8", v, got)
		}
		p := Compose(Input{Description: "x", Affected: []Affected{{Vendor: v, Product: "Widget"}}, Weakness: "xss"})
		if !utf8.ValidString(p.Product) {
			t.Errorf("Compose with vendor %q: product %q invalid UTF-8", v, p.Product)
		}
	}
	if got := NormalizeVendor("X İ inc"); got != "X İ" {
		t.Errorf("NormalizeVendor = %q", got)
	}
	if got := Excerpt(Clean("Foo versions <2.3 and >1.0 allow remote attackers to execute code. More.")); got != "Foo versions <2.3 and >1.0 allow remote attackers to execute code" {
		t.Errorf("excerpt = %q", got)
	}
	if got := Clean("a <b>bold</b> &lt;script&gt;x&lt;/script&gt; move"); got != "a bold x move" {
		t.Errorf("clean = %q", got)
	}
	for in, want := range map[string]string{
		"A flaw of the component Login leads to XSS. The attack is remote.":     "Login",
		"affects some code of the component Room Handler. The manipulation":     "Room Handler",
		"an issue of the component HTTP POST Request Handler allows injection.": "HTTP POST Request Handler",
	} {
		if got := ComponentOf(in); got != want {
			t.Errorf("ComponentOf(%q) = %q, want %q", in, got, want)
		}
	}
}
