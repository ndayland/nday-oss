package tags

import (
	"sort"
	"strconv"
	"strings"
)

// RuleVersion identifies the derivation rules in this package (vocabulary,
// CWE map, CVSS/event/advisory rules). Every rule row stores it. Bump it
// whenever a rule changes what is assigned or how the basis looks, then run
// `nday tags --all` (docs/tags.md §5); the pass after each collector run
// warns while the last complete --all ran with another version.
//
// Version 2 added the product and product-type dimensions (products.go).
const RuleVersion = 2

// Dimensions of the vocabulary, in display order.
const (
	DimType    = "type"    // weakness type, from CWE ids
	DimAccess  = "access"  // attack vector and requirements, from the best CVSS vector
	DimExploit = "exploit" // public exploitation evidence and tooling, from lifecycle events
	// DimProduct: well-known product families, from affected rows and NVD CPE names
	DimProduct = "product"
	// DimProductType: what kind of product, from the matched products and type rules
	DimProductType = "product-type"
	DimEcosystem   = "ecosystem" // package ecosystems, from GitHub advisories
)

// Dimensions lists the dimensions in display order.
var Dimensions = []string{DimType, DimAccess, DimExploit, DimProduct, DimProductType, DimEcosystem}

// i18n keys (select messages: tag.name and tag.desc select on the slug,
// tag.dim and tag.dim_desc on the dimension). Every slug of Vocabulary is a
// select value of tag.name / tag.desc in internal/webui/i18n/keys.json, and
// the English catalog's tag.name equals Tag.Label (checked by tests).
//
// Product tags are the exception: their names are the Go labels (English in
// every locale, like all product names) and their description is the one
// parameterised message KeyProductDesc, so their slugs are not select values.
const (
	KeyName        = "tag.name"
	KeyDesc        = "tag.desc"
	KeyProductDesc = "tag.desc_product"
	KeyDim         = "tag.dim"
	KeyDimDesc     = "tag.dim_desc"
	SelectTag      = "tag" // select variable of KeyName / KeyDesc
	SelectDim      = "dim" // select variable of KeyDim / KeyDimDesc
	MaxFilterTags  = 5     // tag filters per list request
)

// Tag is one entry of the fixed vocabulary.
type Tag struct {
	// Slug: lower-case ASCII words joined by hyphens; stable forever (URLs,
	// API, stored rows). Never rename: add a new slug and retire the old.
	Slug string
	Dim  string
	// Label: the English label (API, docs, the en catalog). Product names
	// and technical terms are kept in English in every locale.
	Label string
	// Strong tags are drawn with more weight on pages (high triage signal).
	Strong bool
	// Rule says in one English sentence what assigns the tag (API, docs).
	Rule string
	// CWEs (type tags): the CWE ids that assign it, from any source.
	CWEs []int
	// Ecosystems (ecosystem tags): the GitHub advisory ecosystem values.
	Ecosystems []string
	// ProductTypes (product tags): the product-type slugs a match assigns.
	ProductTypes []string
}

// cweRule renders the rule of a type tag from its CWE list.
func cweRule(ids []int) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = "CWE-" + strconv.Itoa(id)
	}
	return "One of " + strings.Join(s, ", ") + " is stated for the CVE by any source (CVE record CNA/ADP, NVD, GitHub advisory)."
}

func typeTag(slug, label string, cwes ...int) Tag {
	return Tag{Slug: slug, Dim: DimType, Label: label, CWEs: cwes, Rule: cweRule(cwes)}
}

func ecoTag(slug, label string, ecos ...string) Tag {
	return Tag{Slug: slug, Dim: DimEcosystem, Label: label, Ecosystems: ecos,
		Rule: "A GitHub advisory of the CVE (the version the classification layer read, not withdrawn) lists a package in the " +
			strings.Join(ecos, "/") + " ecosystem."}
}

// Vocabulary is the complete, ordered vocabulary: dimension by dimension,
// and within a dimension in display order (the first type tag of a CVE in
// this order is the one a list row shows). The order of type tags puts the
// classes practitioners triage by first (injection, memory corruption,
// access control) and broad or low-impact classes last.
var Vocabulary = buildVocabulary()

func buildVocabulary() []Tag {
	out := append([]Tag(nil), coreVocabulary...)
	for _, p := range Products {
		out = append(out, Tag{Slug: p.Slug, Dim: DimProduct, Label: p.Label, ProductTypes: p.Types,
			Rule: "An affected product of the CVE (CVE record) or a vulnerable CPE name given by NVD's analysts matches nday's registry entry for " +
				p.Label + "."})
	}
	out = append(out, productTypeTags...)
	return append(out, ecosystemVocabulary...)
}

// coreVocabulary: the type, access and exploit dimensions.
var coreVocabulary = []Tag{
	// ---- type: weakness type from CWE ids (any source in vuln_cwe) ----
	typeTag("command-injection", "command injection", 77, 78, 88),
	typeTag("code-injection", "code injection", 94, 95, 96, 97, 917),
	typeTag("sql-injection", "SQL injection", 89, 564),
	typeTag("deserialization", "deserialization of untrusted data", 502),
	typeTag("template-injection", "template injection", 1336),
	typeTag("file-upload", "unrestricted file upload", 434),
	typeTag("file-inclusion", "file inclusion", 98),
	typeTag("path-traversal", "path traversal", 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 73),
	typeTag("ssrf", "SSRF", 918),
	typeTag("xxe", "XXE", 611, 827),
	typeTag("auth-bypass", "authentication bypass", 287, 288, 289, 290, 291, 294, 302, 303, 304, 305, 306, 603, 620, 640, 1390),
	typeTag("broken-access-control", "broken access control", 280, 281, 282, 283, 284, 285, 276, 425, 566, 639, 732, 862, 863, 1220),
	typeTag("privilege-management", "improper privilege management", 250, 266, 267, 268, 269, 270, 271, 272, 273, 274, 648),
	typeTag("hardcoded-credentials", "hard-coded credentials", 259, 321, 798, 1392),
	typeTag("buffer-overflow", "buffer overflow / out-of-bounds write", 119, 120, 121, 122, 123, 124, 131, 680, 787, 788, 805, 806),
	typeTag("use-after-free", "use-after-free", 416, 825),
	typeTag("double-free", "double free", 415, 1341),
	typeTag("out-of-bounds-read", "out-of-bounds read", 125, 126, 127),
	typeTag("type-confusion", "type confusion", 843),
	typeTag("integer-overflow", "integer overflow", 128, 190, 191, 680),
	typeTag("format-string", "format string", 134),
	typeTag("uninitialized-memory", "use of uninitialized memory", 457, 824, 908, 909),
	typeTag("null-dereference", "NULL pointer dereference", 476, 690),
	typeTag("race-condition", "race condition", 362, 364, 366, 367, 368, 662, 667, 820, 821, 1223),
	typeTag("xss", "XSS", 79, 80, 81, 83, 84, 85, 86, 87),
	typeTag("csrf", "CSRF", 352),
	typeTag("prototype-pollution", "prototype pollution", 1321),
	typeTag("request-smuggling", "HTTP request smuggling", 444),
	typeTag("crlf-injection", "CRLF injection", 93, 113, 117),
	typeTag("open-redirect", "open redirect", 601),
	typeTag("ui-spoofing", "UI spoofing / clickjacking", 451, 1007, 1021),
	typeTag("search-path", "uncontrolled search path", 426, 427, 428),
	typeTag("link-following", "link following", 59, 61, 62, 64, 65, 1386),
	typeTag("session-management", "session management flaw", 384, 613),
	typeTag("crypto-failure", "cryptographic failure", 256, 257, 260, 261, 295, 296, 297, 298, 299, 310, 311, 312, 319,
		322, 323, 324, 325, 326, 327, 328, 329, 330, 331, 335, 336, 337, 338, 340, 347, 522, 523, 757, 759, 760, 780, 916),
	typeTag("info-disclosure", "information disclosure", 200, 201, 203, 204, 208, 209, 210, 211, 213, 215, 359, 497, 532,
		538, 548, 552, 922),
	typeTag("resource-exhaustion", "resource exhaustion", 400, 401, 404, 405, 407, 409, 674, 770, 771, 772, 773, 775, 776,
		789, 834, 835, 920, 1333),

	// ---- access: best CVSS vector (v4.0/v3.x preferred over v2.0) ----
	{Slug: "remote-unauth", Dim: DimAccess, Label: "remote, unauthenticated", Strong: true,
		Rule: "The best CVSS v4.0/v3.x vector has AV:N, PR:N and UI:N (never assigned from CVSS 2.0, which has no user-interaction metric)."},
	{Slug: "network", Dim: DimAccess, Label: "network", Rule: "The best CVSS vector has AV:N."},
	{Slug: "adjacent", Dim: DimAccess, Label: "adjacent network", Rule: "The best CVSS vector has AV:A."},
	{Slug: "local", Dim: DimAccess, Label: "local", Rule: "The best CVSS vector has AV:L."},
	{Slug: "physical", Dim: DimAccess, Label: "physical", Rule: "The best CVSS v4.0/v3.x vector has AV:P (CVSS 2.0 has no physical vector)."},
	{Slug: "no-auth", Dim: DimAccess, Label: "no authentication required", Rule: "The best CVSS vector has PR:N (CVSS 2.0: Au:N)."},
	{Slug: "no-interaction", Dim: DimAccess, Label: "no user interaction",
		Rule: "The best CVSS v4.0/v3.x vector has UI:N (never assigned from CVSS 2.0, which has no user-interaction metric)."},

	// ---- exploit: public lifecycle events (never non-public sources) ----
	{Slug: "ransomware", Dim: DimExploit, Label: "ransomware use", Strong: true,
		Rule: "The CVE's CISA KEV entry says its use in ransomware campaigns is known (knownRansomwareCampaignUse = Known)."},
	{Slug: "metasploit", Dim: DimExploit, Label: "Metasploit", Rule: "A Metasploit Framework module references the CVE."},
	{Slug: "exploit-db", Dim: DimExploit, Label: "Exploit-DB", Rule: "An Exploit-DB entry references the CVE."},
	{Slug: "nuclei", Dim: DimExploit, Label: "nuclei", Rule: "A nuclei template references the CVE."},
}

// (product and product-type: products.go)

// ecosystemVocabulary: GitHub advisory package ecosystems.
var ecosystemVocabulary = []Tag{
	ecoTag("npm", "npm", "npm"),
	ecoTag("pypi", "PyPI", "pip"),
	ecoTag("maven", "Maven", "maven"),
	ecoTag("go", "Go", "go"),
	ecoTag("nuget", "NuGet", "nuget"),
	ecoTag("rubygems", "RubyGems", "rubygems"),
	ecoTag("composer", "Composer", "composer"),
	ecoTag("crates-io", "crates.io", "rust"),
	ecoTag("hex", "Hex", "erlang"),
	ecoTag("pub", "pub", "pub"),
	ecoTag("swift", "Swift", "swift"),
	ecoTag("github-actions", "GitHub Actions", "actions"),
}

// UnmappedCWEs are CWE ids in common use that deliberately get no type tag,
// with the reason (docs/tags.md lists them; the derivation ignores them like
// any id not in the map).
var UnmappedCWEs = []struct {
	IDs    []int
	Reason string
}{
	{[]int{20}, "Improper Input Validation: a catch-all that names no weakness class"},
	{[]int{74, 707, 116}, "generic injection / neutralization classes: the specific child (79, 89, 78, ...) is tagged when stated"},
	{[]int{664, 682, 691, 693, 697, 703, 710, 435}, "CWE pillars and very broad classes (resource control, calculation, protection mechanism failure, ...)"},
	{[]int{16, 17, 18, 19, 189, 254, 255, 264, 275, 399, 840}, "CWE categories used by older NVD records (Permissions, Privileges and Access Controls; Resource Management Errors; Numeric Errors; ...): too broad to name a class"},
	{[]int{668, 669, 610, 441}, "exposure / transfer of a resource between spheres: abstract parents of several tagged classes"},
	{[]int{345, 346}, "insufficient verification of data authenticity / origin: too broad (signature checks, CORS, postMessage, ...)"},
	{[]int{129, 193, 822, 1284, 1285}, "index and quantity validation, off-by-one, untrusted pointer: cannot tell whether memory is read or written"},
	{[]int{248, 369, 617, 754, 755}, "uncaught exceptions, divide by zero, reachable assertions, exception handling: a crash whose class is not stated"},
	{[]int{665, 602}, "improper initialization (abstract parent of 908/909), client-side enforcement of server-side security: too broad"},
	{[]int{184, 829, 494, 749, 1188, 915, 1236, 307, 521, 90, 91, 643, 943}, "specific but rare or ambiguous ids, left for a later rule version (see docs/tags.md §3)"},
}

// bySlug and cweTags index the vocabulary.
var (
	bySlug  = map[string]*Tag{}
	cweTags = map[string][]string{} // "CWE-79" -> slugs in vocabulary order
	ecoTags = map[string]string{}   // GHSA ecosystem value -> slug
	order   = map[string]int{}
)

func init() {
	for i := range Vocabulary {
		t := &Vocabulary[i]
		if _, dup := bySlug[t.Slug]; dup {
			panic("tags: duplicate slug " + t.Slug)
		}
		bySlug[t.Slug] = t
		order[t.Slug] = i
		for _, id := range t.CWEs {
			k := "CWE-" + strconv.Itoa(id)
			cweTags[k] = append(cweTags[k], t.Slug)
		}
		for _, e := range t.Ecosystems {
			ecoTags[e] = t.Slug
		}
	}
}

// Lookup returns the vocabulary entry of slug.
func Lookup(slug string) (Tag, bool) {
	t, ok := bySlug[slug]
	if !ok {
		return Tag{}, false
	}
	return *t, true
}

// Valid reports whether slug is in the vocabulary.
func Valid(slug string) bool { _, ok := bySlug[slug]; return ok }

// Order is the position of slug in the vocabulary (unknown slugs last).
func Order(slug string) int {
	if i, ok := order[slug]; ok {
		return i
	}
	return len(Vocabulary)
}

// Sort orders slugs by vocabulary order (unknown last, then by name).
func Sort(slugs []string) {
	sort.SliceStable(slugs, func(i, j int) bool {
		oi, oj := Order(slugs[i]), Order(slugs[j])
		if oi != oj {
			return oi < oj
		}
		return slugs[i] < slugs[j]
	})
}

// InDim returns the vocabulary entries of one dimension, in order.
func InDim(dim string) []Tag {
	var out []Tag
	for _, t := range Vocabulary {
		if t.Dim == dim {
			out = append(out, t)
		}
	}
	return out
}

// TagsForCWE returns the type tags a CWE id ("CWE-79") assigns.
func TagsForCWE(id string) []string { return cweTags[id] }

// ParseFilter validates list-filter slugs: lower-cased and trimmed, unknown
// slugs and duplicates dropped, at most MaxFilterTags kept, the result in
// vocabulary order (canonical: equal selections give equal lists). bad lists
// what was dropped as unknown.
func ParseFilter(raw []string) (slugs, bad []string) {
	seen := map[string]bool{}
	for _, r := range raw {
		s := strings.ToLower(strings.TrimSpace(r))
		if s == "" {
			continue
		}
		if !Valid(s) {
			bad = append(bad, r)
			continue
		}
		if !seen[s] {
			seen[s] = true
			slugs = append(slugs, s)
		}
	}
	Sort(slugs)
	if len(slugs) > MaxFilterTags {
		slugs = slugs[:MaxFilterTags]
	}
	return slugs, bad
}

// RowPicks chooses the at most three tags a list row shows, from the CVE's
// visible slugs: remote-unauth (the strongest reachability signal), then
// ransomware (the strongest consequence signal that the lifecycle strip does
// not already show), then the first type tag (what the bug is). Access tags
// other than remote-unauth, Metasploit / nuclei / Exploit-DB (the row's POC
// n/3 column says that) and ecosystems are left to the vulnerability page.
func RowPicks(slugs []string) []string {
	var out []string
	has := map[string]bool{}
	for _, s := range slugs {
		has[s] = true
	}
	for _, s := range []string{"remote-unauth", "ransomware"} {
		if has[s] {
			out = append(out, s)
		}
	}
	best := ""
	for _, s := range slugs {
		if t, ok := bySlug[s]; ok && t.Dim == DimType && (best == "" || Order(s) < Order(best)) {
			best = s
		}
	}
	if best != "" {
		out = append(out, best)
	}
	return out
}
