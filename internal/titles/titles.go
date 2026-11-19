// Package titles composes a title for a vulnerability whose record has
// none (docs/titles.md). The rule is deterministic and uses only data
// already in the database: the product (the vulnerability's product tag,
// else its affected rows), the weakness (its first type tag) and a
// component named explicitly in the description. No external service and
// no language model are involved.
//
// The package is pure: the caller passes the inputs (internal/tags reads
// them and stores the result in vuln_title, migration 0031) and renders the
// parts (internal/webui in the visitor's language, English everywhere
// else). Every input text is untrusted (a CNA's description): it is
// cleaned of control, format and bidi characters and of markup, its white
// space collapsed and its length capped; the result is plain text that
// every sink escapes.
package titles

import (
	"errors"
	"html"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// RuleVersion identifies the composition rule. Every composed row stores
// it; bump it whenever Compose changes what it produces for some input,
// then run `nday titles` (it recomputes every row of an older version).
const RuleVersion = 1

// Origins of an effective title (the field title_origin of the API).
const (
	OriginStaff    = "staff"    // set by nday staff (/admin/titles)
	OriginRecord   = "record"   // the record's own title
	OriginComposed = "composed" // composed by this rule
)

// Forms of a composed title.
const (
	FormFull      = "full"      // {product}: {weakness} in {component}
	FormWeakness  = "weakness"  // {product}: {weakness}
	FormComponent = "component" // {product}: vulnerability in {component}
	FormExcerpt   = "excerpt"   // the description's first sentence, cut
)

// Forms lists the forms (summaries, docs).
var Forms = []string{FormFull, FormWeakness, FormComponent, FormExcerpt}

// Length caps (runes).
const (
	MaxProduct   = 60
	MaxComponent = 40
	MaxExcerpt   = 100
	MaxStaff     = 160
	// MaxComposed bounds the English rendering (product + the longest
	// weakness label + component + the pattern).
	MaxComposed = 300
)

// English joining patterns (the en catalog's title.composed has the same
// text; internal/webui checks it).
var englishPattern = map[string]string{
	FormFull:      "{product}: {weakness} in {component}",
	FormWeakness:  "{product}: {weakness}",
	FormComponent: "{product}: vulnerability in {component}",
}

// Affected is one affected row of the record (vendor, product as stated).
type Affected struct{ Vendor, Product string }

// Input is what the rule reads for one vulnerability.
type Input struct {
	// RecordTitle: the record's own title; when it is not blank nothing
	// is composed (the record's title is the effective one).
	RecordTitle string
	Description string
	// ProductLabels: the labels of the vulnerability's visible product
	// tags (one per tag).
	ProductLabels []string
	// Affected: the affected rows, first reported first.
	Affected []Affected
	// Weakness: the slug of the first visible type tag in vocabulary
	// order ("" = none).
	Weakness string
}

// Parts is a composed title. Form "" means nothing was composed.
type Parts struct {
	Form      string `json:"form"`
	Product   string `json:"product,omitempty"`
	Weakness  string `json:"weakness,omitempty"` // a type tag slug
	Component string `json:"component,omitempty"`
	Excerpt   string `json:"excerpt,omitempty"`
}

// Empty reports whether nothing was composed.
func (p Parts) Empty() bool { return p.Form == "" }

// Compose applies the rule (docs/titles.md §2).
func Compose(in Input) Parts {
	p := compose(in)
	// Never hand the database invalid UTF-8: one bad row would fail its
	// whole batch on every run.
	p.Product = strings.ToValidUTF8(p.Product, "")
	p.Component = strings.ToValidUTF8(p.Component, "")
	p.Excerpt = strings.ToValidUTF8(p.Excerpt, "")
	return p
}

func compose(in Input) Parts {
	if strings.TrimSpace(in.RecordTitle) != "" {
		return Parts{}
	}
	desc := Clean(in.Description)
	product := productOf(in.ProductLabels, in.Affected)
	if product != "" {
		component := ComponentOf(desc)
		if component != "" && hasWord(product, component) {
			component = ""
		}
		switch {
		case in.Weakness != "" && component != "":
			return Parts{Form: FormFull, Product: product, Weakness: in.Weakness, Component: component}
		case in.Weakness != "":
			return Parts{Form: FormWeakness, Product: product, Weakness: in.Weakness}
		case component != "":
			return Parts{Form: FormComponent, Product: product, Component: component}
		}
	}
	if ex := Excerpt(desc); ex != "" {
		return Parts{Form: FormExcerpt, Excerpt: ex}
	}
	return Parts{}
}

// Render fills a joining pattern ("{product}: {weakness} in {component}")
// with the parts; weakness is the label to show for p.Weakness. The
// excerpt form is the excerpt itself.
func Render(pattern string, p Parts, weakness string) string {
	if p.Form == FormExcerpt {
		return p.Excerpt
	}
	return strings.NewReplacer("{product}", p.Product, "{weakness}", weakness, "{component}", p.Component).Replace(pattern)
}

// English is the English rendering of p ("" when nothing was composed);
// label gives the English label of a type tag slug.
func English(p Parts, label func(slug string) string) string {
	if p.Empty() {
		return ""
	}
	w := ""
	if p.Weakness != "" {
		w = label(p.Weakness)
	}
	return Render(englishPattern[p.Form], p, w)
}

// EnglishPattern is the English joining pattern of a form ("" for the
// excerpt).
func EnglishPattern(form string) string { return englishPattern[form] }

// ---------------------------------------------------------------- cleaning

var (
	// A tag starts with a letter ("<b>", "</code>", "<a href=…>"); "<2.3 and
	// >1.0" is a version range and stays.
	tagRe  = regexp.MustCompile(`</?[A-Za-z][^<>]{0,500}>`)
	markRe = regexp.MustCompile("`+")
)

// Clean makes untrusted text one line of plain text: invalid UTF-8
// replaced, HTML tags removed and entities decoded (then tags removed once
// more), Markdown code marks (backticks) removed, control characters and
// line or paragraph separators turned into spaces, format characters (bidi
// embeddings, overrides and isolates, zero-width characters, soft hyphens)
// dropped, white space runs collapsed, trimmed, NFC.
func Clean(s string) string {
	s = strings.ToValidUTF8(s, "�")
	if strings.ContainsAny(s, "<&") {
		s = tagRe.ReplaceAllString(s, " ")
		s = html.UnescapeString(s)
		s = tagRe.ReplaceAllString(s, " ")
	}
	s = markRe.ReplaceAllString(s, "")
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r) || unicode.IsControl(r) || r == ' ' || r == ' ':
			space = b.Len() > 0
			continue
		case unicode.Is(unicode.Cf, r) || r == '￼':
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return norm.NFC.String(b.String())
}

// cut shortens s to at most n runes at a word boundary, with an ellipsis
// when cut (the ellipsis counts).
func cut(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)[:n-1]
	i := len(r)
	for i > 0 && r[i-1] != ' ' {
		i--
	}
	if i > len(r)/2 { // a word boundary not too far back
		r = r[:i]
	}
	out := strings.TrimRightFunc(string(r), func(c rune) bool {
		return unicode.IsSpace(c) || strings.ContainsRune(",;:-–—(/", c)
	})
	return out + "…"
}

// ---------------------------------------------------------------- product

// placeholders are affected values that name nothing.
var placeholders = map[string]bool{
	"": true, "n/a": true, "na": true, "-": true, "--": true, "*": true, "?": true, "unknown": true, "unspecified": true,
	"not applicable": true, "none": true, "all": true, "various": true, "multiple": true, "generic": true, "other": true,
	"n/a n/a": true, "not specified": true, "undefined": true, "null": true,
	"[unknown]": true, "[n/a]": true, "(unknown)": true, "tbd": true, "[tbd]": true,
}

func isPlaceholder(s string) bool { return placeholders[strings.ToLower(strings.TrimSpace(s))] }

// legalSuffixes are company-form words dropped from the end of a vendor
// name (case-insensitive, with any comma or period before them).
var legalSuffixes = []string{
	"co., ltd.", "co.,ltd.", "co., ltd", "co.,ltd", "co. ltd.", "co. ltd", "co ltd", "pty ltd", "pty. ltd.",
	"corporation", "incorporated", "inc.", "inc", "corp.", "corp", "co.", "ltd.", "ltd", "limited", "l.l.c.", "llc",
	"gmbh", "ag", "se", "s.a.", "s.p.a.", "spa", "b.v.", "bv", "n.v.", "nv", "plc", "oy", "ab", "a/s", "as", "sas", "sarl",
	"s.r.l.", "srl", "s.r.o.", "k.k.", "kk", "pte. ltd.", "pte ltd", "sdn bhd", "sdn. bhd.",
}

// NormalizeVendor is a vendor name without company-form suffixes ("Oracle
// Corporation" → "Oracle", "Foo Co., Ltd." → "Foo"), a leading "The" or a
// trailing parenthesised short name ("Hewlett Packard Enterprise (HPE)");
// underscores are spaces ("SAP_SE").
func NormalizeVendor(v string) string {
	v, _ = splitShort(Clean(strings.ReplaceAll(v, "_", " ")))
	if len(v) > 4 && strings.EqualFold(v[:4], "the ") {
		v = v[4:]
	}
	for changed := true; changed; {
		changed = false
		for _, s := range legalSuffixes {
			// Compared on v's own bytes: lowercasing can change a name's
			// byte length ("İ"), so an offset into a lowered copy may land
			// inside a character.
			k := len(v) - len(s)
			if k > 0 && (v[k-1] == ' ' || v[k-1] == ',') && strings.EqualFold(v[k:], s) {
				v = strings.TrimRight(strings.TrimSpace(v[:k]), " ,")
				changed = v != ""
				break
			}
		}
	}
	return strings.TrimSpace(v)
}

// splitShort splits "Name (NM)" into "Name" and "NM".
func splitShort(v string) (string, string) {
	if m := shortRe.FindStringSubmatch(v); m != nil {
		return strings.TrimSpace(m[1]), m[2]
	}
	return v, ""
}

var shortRe = regexp.MustCompile(`^(.+?)\s*\(([^()]{1,20})\)$`)

// hasWord reports whether phrase occurs in s as whole words (ASCII case
// folded).
func hasWord(s, phrase string) bool {
	if phrase == "" {
		return false
	}
	ls, lp := strings.ToLower(s), strings.ToLower(phrase)
	for i := 0; ; {
		j := strings.Index(ls[i:], lp)
		if j < 0 {
			return false
		}
		a, b := i+j, i+j+len(lp)
		if (a == 0 || !isWordByte(ls, a-1, true)) && (b == len(ls) || !isWordByte(ls, b, false)) {
			return true
		}
		i = a + 1
	}
}

func isWordByte(s string, i int, before bool) bool {
	var r rune
	if before {
		r, _ = utf8.DecodeLastRuneInString(s[:i+1])
	} else {
		r, _ = utf8.DecodeRuneInString(s[i:])
	}
	return unicode.IsLetter(r) || unicode.IsDigit(r)
}

// usable reports whether a cleaned name names something: not a
// placeholder, at least two runes, a letter or digit.
func usable(s string) bool {
	if isPlaceholder(s) || utf8.RuneCountInString(s) < 2 {
		return false
	}
	return strings.IndexFunc(s, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) >= 0
}

// ProductName is the product of one affected row as a title shows it: the
// product alone when it already names the vendor ("Oracle Java SE"; vendor
// "Apache Software Foundation", product "Apache Tomcat") or the vendor is
// missing, else "vendor product" ("Google Chrome"). "" when the product is
// missing.
func ProductName(vendor, product string) string {
	p := Clean(product)
	if !usable(p) {
		return ""
	}
	v := NormalizeVendor(vendor)
	if !usable(v) {
		return p
	}
	if _, short := splitShort(Clean(strings.ReplaceAll(vendor, "_", " "))); short != "" && hasWord(p, short) {
		return p
	}
	first := v
	if i := strings.IndexByte(v, ' '); i > 0 {
		first = v[:i]
	}
	if strings.EqualFold(v, p) || hasWord(p, v) || (utf8.RuneCountInString(first) >= 3 && hasWord(p, first) &&
		strings.HasPrefix(strings.ToLower(p), strings.ToLower(first))) {
		return p
	}
	return v + " " + p
}

// productOf: the label of the product tag when there is exactly one, else
// the first affected row that names a product (first reported first).
func productOf(labels []string, aff []Affected) string {
	distinct := map[string]bool{}
	var one string
	for _, l := range labels {
		if l = Clean(l); l != "" && !distinct[l] {
			distinct[l] = true
			one = l
		}
	}
	if len(distinct) == 1 {
		return cut(one, MaxProduct)
	}
	for _, a := range aff {
		if p := ProductName(a.Vendor, a.Product); p != "" {
			return cut(p, MaxProduct)
		}
	}
	return ""
}

// ---------------------------------------------------------------- component

// Conservative, anchored patterns that name a component explicitly; the
// first that matches wins. Never a guess: a description that does not say
// "component" yields none.
var componentRes = []*regexp.Regexp{
	// Oracle: "... product of Oracle Java SE (component: Compiler)."
	regexp.MustCompile(`\(component: ([^()]{1,60})\)`),
	// VulDB: "... of the file /admin/login.php of the component Login Page. The manipulation ..."
	regexp.MustCompile(`\bof the component ([^,;:()"<>{}\[\]]{1,60}?)(?:\.\s|\.$|,\s|$|\s(?:leads?|allows?|results?|causes?|has|have|is|are|was|were|could|can|may|might|will|which|that|when|via|by|and|or|to|due)\b)`),
	// "... in the Netfilter component of the Linux kernel ..." (a capitalised name)
	regexp.MustCompile(`\bin the ([A-Z0-9][A-Za-z0-9_\-./+#]*(?: [A-Za-z0-9_\-./+#]+){0,4}) component\b`),
	// "The XML Parser component of Foo before 1.2 allows ..." (a sentence's start)
	regexp.MustCompile(`(?:^|[.!?]\s)The ([A-Z0-9][A-Za-z0-9_\-./+#]*(?: [A-Za-z0-9_\-./+#]+){0,4}) component (?:of|in)\b`),
}

// notComponent are words a "component" phrase starts with that name none.
var notComponent = map[string]bool{"affected": true, "vulnerable": true, "same": true, "following": true, "this": true,
	"that": true, "above": true, "below": true, "said": true, "specific": true, "unknown": true, "a": true, "an": true,
	"the": true, "any": true, "another": true, "other": true, "each": true, "every": true, "some": true, "certain": true}

// ComponentOf is the component the cleaned description names explicitly
// ("" when none): at most MaxComponent runes and six words, never cut.
func ComponentOf(desc string) string {
	for _, re := range componentRes {
		m := re.FindStringSubmatch(desc)
		if m == nil {
			continue
		}
		c := strings.TrimSpace(strings.TrimRight(strings.TrimSpace(m[1]), "."))
		words := strings.Fields(c)
		if len(words) == 0 || len(words) > 6 || utf8.RuneCountInString(c) > MaxComponent ||
			notComponent[strings.ToLower(words[0])] || !usable(c) {
			continue
		}
		return c
	}
	return ""
}

// ---------------------------------------------------------------- excerpt

// abbreviations end with a period inside a sentence.
var abbreviations = map[string]bool{"e.g": true, "i.e": true, "etc": true, "vs": true, "v": true, "inc": true,
	"corp": true, "ltd": true, "co": true, "no": true, "mr": true, "ms": true, "dr": true, "approx": true, "ver": true,
	"cf": true, "al": true, "st": true, "jr": true, "sr": true, "fig": true, "u.s": true}

// rejectedRe: descriptions that are a rejection notice, not a description.
var rejectedRe = regexp.MustCompile(`(?i)^(\*\* ?reject ?\*\*|rejected reason:|do not use this candidate number)`)

// markerRe: leading status markers of old records ("** DISPUTED ** ").
var markerRe = regexp.MustCompile(`^(\*\* ?[A-Z][A-Z ]{2,40} ?\*\* ?)+`)

// Excerpt is the first sentence of the cleaned description, without its
// final period, cut at a word boundary to at most MaxExcerpt runes (with an
// ellipsis when cut); "" when there is no usable description.
func Excerpt(desc string) string {
	if rejectedRe.MatchString(desc) {
		return ""
	}
	desc = strings.TrimSpace(strings.ReplaceAll(markerRe.ReplaceAllString(desc, ""), "**", ""))
	s := firstSentence(desc)
	s = strings.TrimRight(s, ". ")
	if !usable(s) || utf8.RuneCountInString(s) < 8 {
		return ""
	}
	return cut(s, MaxExcerpt)
}

func firstSentence(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '.' && c != '!' && c != '?' {
			continue
		}
		if i+1 < len(s) && s[i+1] != ' ' {
			continue // "1.2.3", "file.php", "..."
		}
		if c == '.' {
			j := strings.LastIndexByte(s[:i], ' ')
			w := strings.ToLower(strings.Trim(s[j+1:i], "(\"'"))
			if r, n := utf8.DecodeRuneInString(w); abbreviations[w] || (n > 0 && n == len(w) && unicode.IsLetter(r)) {
				continue
			}
		}
		return s[:i+1]
	}
	return s
}

// ---------------------------------------------------------------- staff titles

// ErrStaffTitle: a staff title that breaks the rules.
var ErrStaffTitle = errors.New("a title of 1 to 160 characters on one line, without control or bidi characters")

// CleanStaff validates a staff title and returns it as stored: NFC, white
// space at the ends trimmed, runs of spaces collapsed. It must be valid
// UTF-8, one line, without control, format (bidi, zero-width) or
// line-separator characters, 1 to MaxStaff runes.
func CleanStaff(s string) (string, error) {
	if !utf8.ValidString(s) {
		return "", ErrStaffTitle
	}
	s = norm.NFC.String(strings.TrimFunc(s, unicode.IsSpace))
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), r == ' ', r == ' ', r == '�':
			return "", ErrStaffTitle
		case unicode.IsSpace(r):
			space = true
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	out := b.String()
	if n := utf8.RuneCountInString(out); n < 1 || n > MaxStaff {
		return "", ErrStaffTitle
	}
	return out, nil
}
