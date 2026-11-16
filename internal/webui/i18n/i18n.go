// Package i18n holds the website's locales: a small registry of locale
// conventions (locales.json), one message catalog per locale
// (catalogs/<tag>.json) and the key reference that says what every message
// is for (keys.json). It formats messages, numbers and lists and validates
// catalogs against the key reference.
//
// The rule this package exists to enforce: every user-visible sentence,
// label and phrase is ONE message authored whole for its locale. Go code and
// templates choose WHICH message applies and supply values; word order,
// particles, spacing and punctuation belong to the catalog. See
// docs/i18n/README.md.
//
// A locale is enabled when its catalog file exists and passes Validate.
package i18n

import (
	"embed"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"sync"
)

//go:embed locales.json keys.json pending.json catalogs/*.json
var embedded embed.FS

// Primary is the tag of the primary locale (served at the site root, used
// for x-default).
const Primary = "en"

// MissingOpen / MissingClose surround the key of a message that could not be
// rendered (tests look for them in page output).
const (
	MissingOpen  = "⟦"
	MissingClose = "⟧"
)

// NumberFormat is how a locale writes integers.
type NumberFormat struct {
	Group string `json:"group"` // thousands separator
	// MinGroupDigits is CLDR's minimumGroupingDigits: with 2, 4-digit
	// numbers are not grouped (Spanish "1000" but "45.965").
	MinGroupDigits int `json:"min_group_digits"`
}

// Typography are machine-checked conventions of a locale (Validate).
type Typography struct {
	// SentenceFinal lists the characters a message marked "sentence" may
	// end with.
	SentenceFinal []string `json:"sentence_final"`
	// FullwidthPunct: ASCII , ; : ! ? ( ) next to a Han/Kana character is an
	// error (use the full-width forms).
	FullwidthPunct bool `json:"fullwidth_punct"`
	// NarrowSpaceBefore: these characters must be preceded by a no-break
	// space (U+00A0 or U+202F), never by an ordinary space or directly by a
	// letter (French ; : ! ? »).
	NarrowSpaceBefore string `json:"nbsp_before"`
	// NarrowSpaceAfter: these characters must be followed by a no-break
	// space (French «).
	NarrowSpaceAfter string `json:"nbsp_after"`
}

// Locale is one registry entry plus, once loaded, its catalog.
type Locale struct {
	Tag        string       `json:"tag"`         // BCP 47: en, zh-Hans, ...
	Prefix     string       `json:"prefix"`      // URL prefix without slashes ("" for the primary locale)
	NativeName string       `json:"native_name"` // shown in the language switcher
	Match      []string     `json:"match"`       // lower-case browser language tags that prefer this locale
	Plural     string       `json:"plural"`      // plural rule id: one_other | zero_one_other_fr | none
	Number     NumberFormat `json:"number"`
	FontsCJK   []string     `json:"fonts_cjk"` // Han/Kana/Hangul font families, in order
	Typography Typography   `json:"typography"`

	cat      *Catalog
	ref      *Reference
	enabled  bool
	problems []string
	once     sync.Map // key -> []segment cache
	// pending are the key prefixes and keys this locale may leave out of its
	// catalog for now (pending.json); such keys render the primary locale's
	// text.
	pending  []PendingEntry
	fallback *Locale // the primary locale (nil for the primary itself)
}

// Enabled reports whether the catalog exists and passed validation.
func (l *Locale) Enabled() bool { return l.enabled }

// Problems are the validation problems of the catalog (nil when valid; one
// entry "no catalog file" when the file is missing).
func (l *Locale) Problems() []string { return l.problems }

// IsPrimary reports whether this is the primary (English) locale.
func (l *Locale) IsPrimary() bool { return l.Tag == Primary }

// Path prefixes an absolute site path with the locale prefix:
// "/vuln/X" -> "/zh-hans/vuln/X"; "/" -> "/zh-hans/"; "/?a=b" -> "/zh-hans/?a=b".
func (l *Locale) Path(p string) string {
	if l.Prefix == "" {
		return p
	}
	if p == "" {
		p = "/"
	}
	return "/" + l.Prefix + p
}

// Home is the locale's home path.
func (l *Locale) Home() string { return l.Path("/") }

// Catalog is a locale's messages as stored in catalogs/<tag>.json.
type Catalog struct {
	Locale   string                     `json:"locale"`
	Messages map[string]json.RawMessage `json:"messages"`

	strs map[string]string            // plain messages
	vars map[string]map[string]string // plural / select variants
}

// Set is the loaded registry with catalogs.
type Set struct {
	All       []*Locale // registry order
	Enabled   []*Locale // registry order, enabled only
	Reference *Reference
	Pending   []PendingEntry // pending.json
	byTag     map[string]*Locale
	byPrefix  map[string]*Locale
}

// ByTag returns the locale with the given tag (any state) or nil.
func (s *Set) ByTag(tag string) *Locale { return s.byTag[strings.ToLower(tag)] }

// ByPrefix returns the ENABLED locale served under prefix ("" = primary) or nil.
func (s *Set) ByPrefix(prefix string) *Locale {
	l := s.byPrefix[prefix]
	if l == nil || !l.enabled {
		return nil
	}
	return l
}

// Primary returns the primary locale.
func (s *Set) Primary() *Locale { return s.byTag[strings.ToLower(Primary)] }

var (
	defaultOnce sync.Once
	defaultSet  *Set
	defaultErr  error
)

// Default loads the embedded registry, reference and catalogs (once).
func Default() (*Set, error) {
	defaultOnce.Do(func() { defaultSet, defaultErr = Load(embedded) })
	return defaultSet, defaultErr
}

// Embedded is the embedded file system (locales.json, keys.json, catalogs/).
func Embedded() fs.FS { return embedded }

// Load reads locales.json, keys.json and catalogs/<tag>.json from fsys. A
// structural error in the registry or reference is an error; a missing or
// invalid catalog only leaves that locale disabled (see Problems). The
// primary locale must be enabled.
func Load(fsys fs.FS) (*Set, error) {
	ref, err := LoadReference(fsys)
	if err != nil {
		return nil, err
	}
	b, err := fs.ReadFile(fsys, "locales.json")
	if err != nil {
		return nil, err
	}
	var reg struct {
		Locales []*Locale `json:"locales"`
	}
	if err := strictUnmarshal(b, &reg); err != nil {
		return nil, fmt.Errorf("locales.json: %w", err)
	}
	s := &Set{Reference: ref, byTag: map[string]*Locale{}, byPrefix: map[string]*Locale{}}
	for _, l := range reg.Locales {
		if err := checkRegistryEntry(l); err != nil {
			return nil, fmt.Errorf("locales.json: %s: %w", l.Tag, err)
		}
		if s.byTag[strings.ToLower(l.Tag)] != nil || s.byPrefix[l.Prefix] != nil {
			return nil, fmt.Errorf("locales.json: duplicate tag or prefix %q", l.Tag)
		}
		l.ref = ref
		s.byTag[strings.ToLower(l.Tag)] = l
		s.byPrefix[l.Prefix] = l
		s.All = append(s.All, l)
	}
	pend, err := LoadPending(fsys, s)
	if err != nil {
		return nil, err
	}
	s.Pending = pend
	for _, l := range s.All {
		if !l.IsPrimary() {
			l.fallback = s.Primary()
		}
		cb, err := fs.ReadFile(fsys, "catalogs/"+l.Tag+".json")
		if err != nil {
			l.problems = []string{"no catalog file catalogs/" + l.Tag + ".json"}
			continue
		}
		cat, probs := ParseCatalog(cb)
		if cat != nil {
			l.cat = cat
			probs = append(probs, Validate(l, cat, ref)...)
		}
		l.problems = probs
		l.enabled = cat != nil && len(probs) == 0
		if l.enabled {
			s.Enabled = append(s.Enabled, l)
		}
	}
	// Catalog files without a registry entry are a mistake worth failing on.
	ents, _ := fs.ReadDir(fsys, "catalogs")
	for _, e := range ents {
		tag := strings.TrimSuffix(e.Name(), ".json")
		if s.byTag[strings.ToLower(tag)] == nil {
			return nil, fmt.Errorf("catalogs/%s has no entry in locales.json", e.Name())
		}
	}
	p := s.Primary()
	if p == nil || p.Prefix != "" {
		return nil, fmt.Errorf("locales.json: primary locale %q missing or prefixed", Primary)
	}
	if !p.enabled {
		return nil, fmt.Errorf("primary catalog %s is invalid: %s", Primary, strings.Join(p.problems, "; "))
	}
	return s, nil
}

func checkRegistryEntry(l *Locale) error {
	if l.Tag == "" || l.NativeName == "" {
		return fmt.Errorf("tag and native_name are required")
	}
	if l.Tag != Primary && (l.Prefix == "" || l.Prefix != strings.ToLower(l.Prefix) || strings.Contains(l.Prefix, "/")) {
		return fmt.Errorf("prefix must be a lower-case path segment")
	}
	if _, ok := pluralRules[l.Plural]; !ok {
		return fmt.Errorf("unknown plural rule %q", l.Plural)
	}
	if l.Number.Group == "" {
		return fmt.Errorf("number.group is required")
	}
	if len(l.Typography.SentenceFinal) == 0 {
		return fmt.Errorf("typography.sentence_final is required")
	}
	return nil
}

func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// ParseCatalog decodes a catalog file. Problems are returned for values that
// are neither a string nor an object of strings.
func ParseCatalog(b []byte) (*Catalog, []string) {
	var c Catalog
	if err := strictUnmarshal(b, &c); err != nil {
		return nil, []string{"catalog is not valid JSON of the expected shape: " + err.Error()}
	}
	c.strs = map[string]string{}
	c.vars = map[string]map[string]string{}
	var probs []string
	for k, raw := range c.Messages {
		var s string
		if json.Unmarshal(raw, &s) == nil {
			c.strs[k] = s
			continue
		}
		var m map[string]string
		if json.Unmarshal(raw, &m) == nil {
			c.vars[k] = m
			continue
		}
		probs = append(probs, k+": value must be a string or an object of strings")
	}
	sort.Strings(probs)
	return &c, probs
}

// Keys returns the catalog's keys, sorted.
func (c *Catalog) Keys() []string {
	var ks []string
	for k := range c.Messages {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// ---------------------------------------------------------------- plurals

// pluralRules maps a rule id to its category function and the categories a
// catalog must provide. Only integer operands are used on this site.
var pluralRules = map[string]struct {
	cats []string
	fn   func(n int64) string
}{
	// English, Spanish: 1 is "one".
	"one_other": {[]string{"one", "other"}, func(n int64) string {
		if n == 1 {
			return "one"
		}
		return "other"
	}},
	// French: 0 and 1 are "one" (CLDR i = 0,1).
	"zero_one_other_fr": {[]string{"one", "other"}, func(n int64) string {
		if n == 0 || n == 1 {
			return "one"
		}
		return "other"
	}},
	// Chinese, Japanese, Korean: no plural forms.
	"none": {[]string{"other"}, func(int64) string { return "other" }},
}

// PluralCategory is the CLDR category of n in this locale.
func (l *Locale) PluralCategory(n int64) string {
	if n < 0 {
		n = -n
	}
	return pluralRules[l.Plural].fn(n)
}

// PluralCategories are the categories a plural message must provide.
func (l *Locale) PluralCategories() []string { return pluralRules[l.Plural].cats }

// ---------------------------------------------------------------- numbers

// Int formats an integer with the locale's grouping.
func (l *Locale) Int(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	min := l.Number.MinGroupDigits
	if min < 1 {
		min = 1
	}
	if len(s) < 3+min {
		if neg {
			return "-" + s
		}
		return s
	}
	var b strings.Builder
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			b.WriteString(l.Number.Group)
		}
		b.WriteRune(c)
	}
	if neg {
		return "-" + b.String()
	}
	return b.String()
}

// ---------------------------------------------------------------- values

// Upstream marks text that comes from upstream records in its original
// language (English). In other locales it renders as <span lang="en">.
type Upstream string

// Raw is a plain-text value that is not a number even if it looks like one.
type Raw string

// ---------------------------------------------------------------- messages

type segment struct {
	lit string
	ph  string // placeholder name when lit == ""
}

// parseMessage splits "a {x} b" into segments. Unbalanced braces are an error.
func parseMessage(s string) ([]segment, error) {
	var out []segment
	for len(s) > 0 {
		i := strings.IndexAny(s, "{}")
		if i < 0 {
			out = append(out, segment{lit: s})
			break
		}
		if s[i] == '}' {
			return nil, fmt.Errorf("unexpected '}'")
		}
		if i > 0 {
			out = append(out, segment{lit: s[:i]})
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return nil, fmt.Errorf("unclosed '{'")
		}
		name := s[i+1 : i+j]
		if !validName(name) {
			return nil, fmt.Errorf("bad placeholder {%s}", name)
		}
		out = append(out, segment{ph: name})
		s = s[i+j+1:]
	}
	return out, nil
}

func validName(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_') {
			return false
		}
	}
	return true
}

// args turns name/value pairs into a map.
func args(kv []any) map[string]any {
	m := make(map[string]any, len(kv)/2)
	for i := 0; i+1 < len(kv); i += 2 {
		if k, ok := kv[i].(string); ok {
			m[k] = kv[i+1]
		}
	}
	return m
}

func asInt(v any) (int64, bool) {
	switch x := v.(type) {
	case int:
		return int64(x), true
	case int64:
		return x, true
	case int32:
		return int64(x), true
	}
	return 0, false
}

// variant picks the message text for key given the arguments: plural
// messages by the category of their count, select messages by their value.
func (l *Locale) variant(key string, a map[string]any) (string, bool) {
	if l.cat == nil {
		return "", false
	}
	if l.FallsBack(key) {
		return l.fallback.variant(key, a)
	}
	if s, ok := l.cat.strs[key]; ok {
		return s, true
	}
	vs, ok := l.cat.vars[key]
	if !ok {
		return "", false
	}
	def := l.ref.byKey[key]
	if def == nil {
		return "", false
	}
	switch {
	case def.Plural != "":
		n, _ := asInt(a[def.Plural])
		if s, ok := vs[l.PluralCategory(n)]; ok {
			return s, true
		}
		s, ok := vs["other"]
		return s, ok
	case def.Select != nil:
		v := fmt.Sprint(a[def.Select.Var])
		if s, ok := vs[v]; ok {
			return s, true
		}
		s, ok := vs["other"]
		return s, ok
	}
	return "", false
}

// plural messages may also be plain strings in locales without plural forms.
func (l *Locale) segments(key string, a map[string]any) ([]segment, bool) {
	text, ok := l.variant(key, a)
	if !ok {
		return nil, false
	}
	type cached struct {
		segs []segment
		err  error
	}
	if c, ok := l.once.Load(text); ok {
		cc := c.(cached)
		return cc.segs, cc.err == nil
	}
	segs, err := parseMessage(text)
	l.once.Store(text, cached{segs, err})
	return segs, err == nil
}

func missing(key string) string { return MissingOpen + key + MissingClose }

// Text renders a message as plain text (for attributes, <title>, the feed
// and Go-side composition). kv are name/value pairs; values are strings,
// integers (formatted with the locale's grouping), Upstream or Raw.
// template.HTML values are not allowed in plain text and render as a
// missing marker.
func (l *Locale) Text(key string, kv ...any) string {
	a := args(kv)
	segs, ok := l.segments(key, a)
	if !ok {
		return missing(key)
	}
	var b strings.Builder
	for _, s := range segs {
		if s.ph == "" {
			b.WriteString(s.lit)
			continue
		}
		v, ok := a[s.ph]
		if !ok {
			b.WriteString(missing(key + "{" + s.ph + "}"))
			continue
		}
		switch x := v.(type) {
		case template.HTML:
			b.WriteString(missing(key + "{" + s.ph + "}:html"))
		case Upstream:
			b.WriteString(string(x))
		default:
			b.WriteString(l.plain(x))
		}
	}
	return b.String()
}

func (l *Locale) plain(v any) string {
	if n, ok := asInt(v); ok {
		return l.Int(n)
	}
	switch x := v.(type) {
	case string:
		return x
	case Raw:
		return string(x)
	case fmt.Stringer:
		return x.String()
	}
	return fmt.Sprint(v)
}

// HTML renders a message as HTML: the message text and plain values are
// escaped; template.HTML values (inline elements built by Go code) are
// inserted as is; Upstream values become <span lang="en"> outside English.
//
// A pending message that falls back to the primary locale (FallsBack) is
// wrapped in <span lang="en">.
func (l *Locale) HTML(key string, kv ...any) template.HTML {
	h := l.html(key, args(kv), nil)
	if l.FallsBack(key) {
		return template.HTML(`<span lang="`+Primary+`">`) + h + template.HTML("</span>")
	}
	return h
}

// html renders with an optional wrapper around every substituted value (the
// debug page highlights values).
func (l *Locale) html(key string, a map[string]any, wrap func(string) string) template.HTML {
	segs, ok := l.segments(key, a)
	if !ok {
		return template.HTML(html.EscapeString(missing(key)))
	}
	var b strings.Builder
	for _, s := range segs {
		if s.ph == "" {
			b.WriteString(html.EscapeString(s.lit))
			continue
		}
		v, ok := a[s.ph]
		var out string
		switch x := v.(type) {
		case nil:
			out = html.EscapeString(missing(key + "{" + s.ph + "}"))
		case template.HTML:
			out = string(x)
		case Upstream:
			out = l.UpstreamHTML(string(x))
		default:
			out = html.EscapeString(l.plain(x))
		}
		if !ok {
			out = html.EscapeString(missing(key + "{" + s.ph + "}"))
		}
		if wrap != nil {
			out = wrap(out)
		}
		b.WriteString(out)
	}
	return template.HTML(b.String())
}

// Highlight renders like HTML but wraps every substituted value in <mark>
// (catalog preview).
func (l *Locale) Highlight(key string, kv ...any) template.HTML {
	return l.html(key, args(kv), func(s string) string { return "<mark>" + s + "</mark>" })
}

// UpstreamHTML escapes upstream text and, outside English, marks it lang="en".
func (l *Locale) UpstreamHTML(s string) string {
	if l.IsPrimary() {
		return html.EscapeString(s)
	}
	return `<span lang="en">` + html.EscapeString(s) + `</span>`
}

// FallsBack reports whether key is pending for this locale (pending.json)
// and missing from its catalog, so it renders the primary locale's text.
func (l *Locale) FallsBack(key string) bool {
	if l.fallback == nil || l.cat == nil || !l.isPending(key) {
		return false
	}
	_, a := l.cat.strs[key]
	_, b := l.cat.vars[key]
	return !a && !b
}

func (l *Locale) isPending(key string) bool {
	for _, p := range l.pending {
		if p.Matches(key) {
			return true
		}
	}
	return false
}

// Has reports whether the catalog has key.
func (l *Locale) Has(key string) bool {
	if l.cat == nil {
		return false
	}
	_, a := l.cat.strs[key]
	_, b := l.cat.vars[key]
	return a || b
}

// ---------------------------------------------------------------- lists

// List kinds: "and" (a list in running prose: "a, b and c") and "seq"
// (a compact enumeration in UI: "a, b, c" / "a、b、c").
const (
	ListAnd = "and"
	ListSeq = "seq"
)

// List joins plain-text items with the locale's list patterns.
func (l *Locale) List(kind string, items []string) string {
	hs := make([]template.HTML, len(items))
	for i, s := range items {
		hs[i] = template.HTML(s) // plain: patterns are applied textually below
	}
	return string(l.list(kind, hs, func(k string, a, b template.HTML) template.HTML {
		return template.HTML(l.Text(k, "a", Raw(a), "b", Raw(b)))
	}))
}

// ListHTML joins HTML items (already escaped / built by Go code).
func (l *Locale) ListHTML(kind string, items []template.HTML) template.HTML {
	return l.list(kind, items, func(k string, a, b template.HTML) template.HTML {
		return l.HTML(k, "a", a, "b", b)
	})
}

// list applies CLDR-style patterns: two items use "<kind>.two"; longer lists
// use "<kind>.start" for the first pair, "<kind>.middle" inside and
// "<kind>.end" for the last pair (built from the end, as CLDR does).
func (l *Locale) list(kind string, items []template.HTML, pat func(k string, a, b template.HTML) template.HTML) template.HTML {
	p := "list." + kind + "."
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	case 2:
		return pat(p+"two", items[0], items[1])
	}
	n := len(items)
	acc := pat(p+"end", items[n-2], items[n-1])
	for i := n - 3; i >= 1; i-- {
		acc = pat(p+"middle", items[i], acc)
	}
	return pat(p+"start", items[0], acc)
}

// Join concatenates consecutive sentences with the locale's joiner
// ("sentence.joiner": a space in English, nothing in Chinese).
func (l *Locale) Join(sentences []string) string {
	return strings.Join(sentences, l.Text("sentence.joiner"))
}

// JoinHTML is Join for HTML sentences.
func (l *Locale) JoinHTML(sentences []template.HTML) template.HTML {
	j := html.EscapeString(l.Text("sentence.joiner"))
	var b strings.Builder
	for i, s := range sentences {
		if i > 0 {
			b.WriteString(j)
		}
		b.WriteString(string(s))
	}
	return template.HTML(b.String())
}
