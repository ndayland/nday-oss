package i18n

import (
	"fmt"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Reference is keys.json: every message key with what it is for.
type Reference struct {
	Groups []*Group `json:"groups"`
	byKey  map[string]*KeyDef
	order  []string
}

// Group is a page or component.
type Group struct {
	ID    string    `json:"id"`
	Title string    `json:"title"`
	Where string    `json:"where"`
	Keys  []*KeyDef `json:"keys"`
}

// KeyDef describes one message for the people who author it.
type KeyDef struct {
	Key    string `json:"key"`
	Where  string `json:"where"`  // where it appears
	Intent string `json:"intent"` // what the reader must understand
	// Kind: label | sentence | phrase | title | pattern | joiner.
	// "sentence" messages must end with one of the locale's sentence-final
	// characters.
	Kind         string                  `json:"kind"`
	Placeholders map[string]*Placeholder `json:"placeholders,omitempty"`
	Plural       string                  `json:"plural,omitempty"` // name of the count placeholder that selects the plural form
	Select       *Select                 `json:"select,omitempty"`
	Constraints  []string                `json:"constraints,omitempty"` // human-readable
	MaxCols      int                     `json:"max_cols,omitempty"`    // display columns (CJK = 2) excluding placeholders
	Neighbors    string                  `json:"neighbors,omitempty"`   // untranslated tokens it sits next to
	AllowEmpty   bool                    `json:"allow_empty,omitempty"`
	AllowSpace   bool                    `json:"allow_edge_space,omitempty"` // leading/trailing spaces are meaningful
	Group        string                  `json:"-"`
}

// Placeholder describes a {name} in a message.
type Placeholder struct {
	// Kind: text | number | token (language-neutral: code, flag, path, time,
	// version) | upstream (record text in its original language) | html (an
	// inline element built by the page: link, <kbd>, <code>, stage code).
	Kind     string `json:"kind"`
	Meaning  string `json:"meaning"`
	Example  string `json:"example"`
	Optional bool   `json:"optional,omitempty"` // may be left out of the message
}

// Select is a select-style message: one variant per value of Var.
type Select struct {
	Var     string            `json:"var"`
	Values  []string          `json:"values"`
	Meaning map[string]string `json:"meaning,omitempty"` // value -> what it means
}

// LoadReference reads keys.json.
func LoadReference(fsys fs.FS) (*Reference, error) {
	b, err := fs.ReadFile(fsys, "keys.json")
	if err != nil {
		return nil, err
	}
	var r Reference
	if err := strictUnmarshal(b, &r); err != nil {
		return nil, fmt.Errorf("keys.json: %w", err)
	}
	r.byKey = map[string]*KeyDef{}
	for _, g := range r.Groups {
		for _, k := range g.Keys {
			if r.byKey[k.Key] != nil {
				return nil, fmt.Errorf("keys.json: duplicate key %s", k.Key)
			}
			if k.Intent == "" || k.Where == "" || k.Kind == "" {
				return nil, fmt.Errorf("keys.json: %s needs where, intent and kind", k.Key)
			}
			switch k.Kind {
			case "label", "sentence", "phrase", "title", "pattern", "joiner":
			default:
				return nil, fmt.Errorf("keys.json: %s: unknown kind %q", k.Key, k.Kind)
			}
			for n, p := range k.Placeholders {
				if !validName(n) {
					return nil, fmt.Errorf("keys.json: %s: bad placeholder name %q", k.Key, n)
				}
				switch p.Kind {
				case "text", "number", "token", "upstream", "html":
				default:
					return nil, fmt.Errorf("keys.json: %s: placeholder %s: unknown kind %q", k.Key, n, p.Kind)
				}
				if p.Example == "" || p.Meaning == "" {
					return nil, fmt.Errorf("keys.json: %s: placeholder %s needs meaning and example", k.Key, n)
				}
			}
			if k.Plural != "" {
				if p := k.Placeholders[k.Plural]; p == nil || p.Kind != "number" {
					return nil, fmt.Errorf("keys.json: %s: plural %q must be a number placeholder", k.Key, k.Plural)
				}
			}
			if k.Plural != "" && k.Select != nil {
				return nil, fmt.Errorf("keys.json: %s: plural and select cannot be combined; split the key", k.Key)
			}
			if k.Select != nil && (k.Select.Var == "" || len(k.Select.Values) == 0) {
				return nil, fmt.Errorf("keys.json: %s: select needs var and values", k.Key)
			}
			k.Group = g.ID
			r.byKey[k.Key] = k
			r.order = append(r.order, k.Key)
		}
	}
	return &r, nil
}

// Key returns the definition of key or nil.
func (r *Reference) Key(key string) *KeyDef { return r.byKey[key] }

// Keys returns all keys in reference order.
func (r *Reference) Keys() []string { return append([]string(nil), r.order...) }

// ExampleArgs are the example values of a key's placeholders (numbers as
// ints, upstream text as Upstream, html as <code>example</code>), plus the
// select value or plural count given.
func (k *KeyDef) ExampleArgs() []any {
	var kv []any
	names := make([]string, 0, len(k.Placeholders))
	for n := range k.Placeholders {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := k.Placeholders[n]
		kv = append(kv, n, ExampleValue(p))
	}
	return kv
}

// ExampleValue converts a placeholder example into a render value.
func ExampleValue(p *Placeholder) any {
	switch p.Kind {
	case "number":
		var n int64
		if _, err := fmt.Sscan(p.Example, &n); err == nil {
			return n
		}
	case "upstream":
		return Upstream(p.Example)
	case "html":
		return htmlExample(p.Example)
	}
	return p.Example
}

// ---------------------------------------------------------------- validate

var (
	tagRe    = regexp.MustCompile(`<\s*/?\s*[A-Za-z!][^>]*>`)
	entityRe = regexp.MustCompile(`&(#[0-9]+|#x[0-9A-Fa-f]+|[A-Za-z]+);`)
)

// Validate checks a catalog against the reference and the locale's
// conventions. It returns human-readable problems (none = valid).
func Validate(l *Locale, c *Catalog, ref *Reference) []string {
	var probs []string
	add := func(format string, a ...any) { probs = append(probs, fmt.Sprintf(format, a...)) }
	if c.Locale != l.Tag {
		add("catalog \"locale\" is %q, want %q", c.Locale, l.Tag)
	}
	for _, k := range c.Keys() {
		if ref.byKey[k] == nil {
			add("%s: unknown key (not in keys.json)", k)
		}
	}
	for _, key := range ref.order {
		def := ref.byKey[key]
		s, isStr := c.strs[key]
		vs, isVar := c.vars[key]
		if !isStr && !isVar {
			if _, bad := c.Messages[key]; !bad && !l.isPending(key) {
				add("%s: missing", key)
			}
			continue
		}
		variants := map[string]string{}
		switch {
		case def.Plural != "":
			cats := l.PluralCategories()
			if isStr {
				if len(cats) != 1 {
					add("%s: plural message needs an object with %s", key, strings.Join(cats, ", "))
					continue
				}
				variants["other"] = s
				break
			}
			for _, cat := range cats {
				if _, ok := vs[cat]; !ok {
					add("%s: plural variant %q missing (this locale needs %s)", key, cat, strings.Join(cats, ", "))
				}
			}
			for cat := range vs {
				if !contains(cats, cat) {
					add("%s: plural variant %q is not used by this locale (needs %s)", key, cat, strings.Join(cats, ", "))
				}
			}
			variants = vs
		case def.Select != nil:
			if isStr {
				add("%s: select message needs an object with %s", key, strings.Join(def.Select.Values, ", "))
				continue
			}
			for _, v := range def.Select.Values {
				if _, ok := vs[v]; !ok {
					add("%s: select variant %q missing", key, v)
				}
			}
			for v := range vs {
				if !contains(def.Select.Values, v) {
					add("%s: unknown select variant %q (allowed: %s)", key, v, strings.Join(def.Select.Values, ", "))
				}
			}
			variants = vs
		default:
			if isVar {
				add("%s: must be a plain string", key)
				continue
			}
			variants[""] = s
		}
		names := make([]string, 0, len(variants))
		for n := range variants {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, vn := range names {
			for _, p := range checkText(l, def, vn, variants[vn]) {
				if vn != "" {
					add("%s[%s]: %s", key, vn, p)
				} else {
					add("%s: %s", key, p)
				}
			}
		}
	}
	return probs
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

// checkText validates one variant.
func checkText(l *Locale, def *KeyDef, variant, s string) []string {
	var probs []string
	add := func(format string, a ...any) { probs = append(probs, fmt.Sprintf(format, a...)) }
	if strings.TrimSpace(s) == "" && !def.AllowEmpty {
		return []string{"empty"}
	}
	if !def.AllowSpace && s != strings.TrimSpace(s) {
		add("leading or trailing whitespace")
	}
	if tagRe.MatchString(s) {
		add("contains an HTML tag (catalogs are plain text; inline elements come in through placeholders)")
	}
	if entityRe.MatchString(s) {
		add("contains an HTML entity (write the character itself)")
	}
	if strings.ContainsAny(s, "\n\t\r") {
		add("contains a line break or tab")
	}
	segs, err := parseMessage(s)
	if err != nil {
		return append(probs, err.Error())
	}
	used := map[string]bool{}
	var lits strings.Builder
	for _, sg := range segs {
		if sg.ph != "" {
			if def.Placeholders[sg.ph] == nil {
				add("unknown placeholder {%s} (declared: %s)", sg.ph, declared(def))
			}
			used[sg.ph] = true
			lits.WriteString("\x00") // placeholder boundary for typography checks
			continue
		}
		lits.WriteString(sg.lit)
	}
	for n, p := range def.Placeholders {
		if used[n] || p.Optional {
			continue
		}
		if n == def.Plural && variant != "other" {
			continue // "one" may spell the number out ("a day")
		}
		if def.Select != nil && n == def.Select.Var {
			continue
		}
		add("placeholder {%s} is not used", n)
	}
	if def.MaxCols > 0 {
		if w := Cols(strings.ReplaceAll(lits.String(), "\x00", "")); w > def.MaxCols {
			add("too long: %d columns, at most %d (CJK characters count 2)", w, def.MaxCols)
		}
	}
	text := lits.String()
	if def.Kind == "sentence" {
		ok := false
		trimmed := strings.TrimRight(text, "   ")
		for _, f := range l.Typography.SentenceFinal {
			if strings.HasSuffix(trimmed, f) {
				ok = true
			}
		}
		if !ok {
			add("a sentence must end with one of %q", strings.Join(l.Typography.SentenceFinal, " "))
		}
	}
	if l.Typography.FullwidthPunct {
		rs := []rune(text)
		for i, r := range rs {
			if !strings.ContainsRune(",;:!?()", r) {
				continue
			}
			prev, next := rune(0), rune(0)
			if i > 0 {
				prev = rs[i-1]
			}
			if i+1 < len(rs) {
				next = rs[i+1]
			}
			if IsWide(prev) || IsWide(next) {
				add("ASCII %q next to a CJK character; use the full-width form", string(r))
				break
			}
		}
		if strings.HasSuffix(strings.TrimSpace(text), ".") && len(rs) > 1 {
			if last := []rune(strings.TrimSuffix(strings.TrimSpace(text), ".")); len(last) > 0 && IsWide(last[len(last)-1]) {
				add("sentence ends with ASCII '.' after a CJK character; use 。")
			}
		}
	}
	if b := l.Typography.NarrowSpaceBefore; b != "" {
		rs := []rune(text)
		for i, r := range rs {
			if !strings.ContainsRune(b, r) || i == 0 {
				continue
			}
			if p := rs[i-1]; p != ' ' && p != ' ' {
				add("%q must be preceded by a no-break space (U+202F or U+00A0)", string(r))
				break
			}
		}
	}
	if a := l.Typography.NarrowSpaceAfter; a != "" {
		rs := []rune(text)
		for i, r := range rs {
			if !strings.ContainsRune(a, r) || i+1 >= len(rs) {
				continue
			}
			if n := rs[i+1]; n != ' ' && n != ' ' {
				add("%q must be followed by a no-break space (U+202F or U+00A0)", string(r))
				break
			}
		}
	}
	return probs
}

func declared(def *KeyDef) string {
	var ns []string
	for n := range def.Placeholders {
		ns = append(ns, "{"+n+"}")
	}
	sort.Strings(ns)
	if len(ns) == 0 {
		return "none"
	}
	return strings.Join(ns, " ")
}

// IsWide reports whether r is a Han, Kana or Hangul character or CJK
// punctuation (two columns in a monospace font).
func IsWide(r rune) bool {
	return unicode.In(r, unicode.Han, unicode.Hiragana, unicode.Katakana, unicode.Hangul) ||
		(r >= 0x3000 && r <= 0x303f) || (r >= 0xff00 && r <= 0xff60) || (r >= 0xffe0 && r <= 0xffe6)
}

// Cols is the display width of s in a monospace font (wide characters 2).
func Cols(s string) int {
	n := 0
	for _, r := range s {
		if IsWide(r) {
			n += 2
		} else if r != utf8.RuneError {
			n++
		}
	}
	return n
}
