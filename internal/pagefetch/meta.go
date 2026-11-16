package pagefetch

import (
	"html"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/encoding/htmlindex"
	"golang.org/x/text/transform"
)

// MaxTitle is the length of a cleaned title in runes (an ellipsis included
// when cut).
const MaxTitle = 120

// Meta is what ExtractMeta reads from a page. All of it is untrusted
// third-party text, already cleaned (CleanText); display code must still
// escape it.
type Meta struct {
	// Title is the page title: the first <title> of the head, else meta
	// og:title; with a leading or trailing site name (og:site_name) cut off,
	// cut to MaxTitle runes; "" when there is none or it is a generic
	// bot-wall / error title (IsGenericTitle).
	Title string
	// SiteName is meta og:site_name, cleaned and cut to MaxTitle runes.
	SiteName string
}

// genericTitles are titles of bot walls, error and sign-in pages: a title
// that is essentially one of these (IsGenericTitle) is not a title. The one
// place this list lives.
var genericTitles = []string{
	"just a moment", "attention required", "access denied", "403 forbidden", "forbidden",
	"404 not found", "not found", "page not found", "are you a robot", "captcha",
	"error", "sign in", "log in", "login", "security check", "too many requests",
}

// titleSep matches a separator between a title and a site name (" - ",
// " | ", " – ", " — ", " · ", " :: ", flexible whitespace; "-" needs
// whitespace on both sides).
const titleSep = `(?:\s*(?:\||–|—|·|::)\s*|\s+-\s+)`

var genericSepRe = regexp.MustCompile(titleSep)

// IsGenericTitle reports whether t (cleaned) is essentially a generic
// title: one of genericTitles, alone or next to a site name ("Sign in -
// Example", "Example | 404 Not Found"), ignoring case and surrounding
// punctuation.
func IsGenericTitle(t string) bool {
	norm := func(s string) string {
		return strings.TrimFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) })
	}
	parts := genericSepRe.Split(t, -1)
	cands := []string{t}
	if len(parts) > 1 {
		cands = append(cands, parts[0], parts[len(parts)-1])
	}
	for _, c := range cands {
		n := norm(c)
		for _, g := range genericTitles {
			if n == g {
				return true
			}
		}
	}
	return false
}

// invisible are characters that render as nothing (or blank) without being
// control, format or space characters: Hangul fillers, the combining
// grapheme joiner, the braille blank, the Mongolian vowel separator, word
// joiner and invisible operators, the BOM.
var invisible = map[rune]bool{
	0x115F: true, 0x1160: true, 0x3164: true, 0xFFA0: true, // Hangul fillers
	0x034F: true, // combining grapheme joiner
	0x2800: true, // braille pattern blank
	0x180E: true, // Mongolian vowel separator
	0x2060: true, 0x2061: true, 0x2062: true, 0x2063: true, 0x2064: true,
	0xFEFF: true,
}

// CleanText cleans untrusted text once: HTML entities decoded once; control
// and format characters (bidi controls, zero-width characters, tag
// characters, BOM, ...) dropped; every run of whitespace made one space;
// trimmed. Text with an invalid UTF-8 sequence or U+FFFD (a decoding
// failure) gives "".
func CleanText(s string) string {
	s = html.UnescapeString(s)
	if !utf8.ValidString(s) || strings.ContainsRune(s, utf8.RuneError) {
		return ""
	}
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = true
			continue
		case unicode.IsControl(r), unicode.Is(unicode.Cf, r), unicode.Is(unicode.Co, r), unicode.Is(unicode.Cs, r),
			r >= 0xFE00 && r <= 0xFE0F, r >= 0xE0100 && r <= 0xE01EF, // variation selectors
			invisible[r]:
			continue
		}
		if space && b.Len() > 0 {
			b.WriteByte(' ')
		}
		space = false
		b.WriteRune(r)
	}
	return b.String()
}

// Cut cuts s to max runes, the last one an ellipsis when cut.
func Cut(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	r := []rune(s)
	return strings.TrimRight(string(r[:max-1]), " ") + "…"
}

// StripSiteName removes a trailing "<sep> site" or leading "site <sep>"
// from title (case-insensitive; separators as titleSep). The result is
// never empty: when stripping would leave nothing, title is returned
// unchanged. Both arguments are cleaned text.
func StripSiteName(title, site string) string {
	if site == "" || strings.EqualFold(title, site) {
		return title
	}
	q := regexp.QuoteMeta(site)
	if m := regexp.MustCompile(`(?is)^(.*?\S)` + titleSep + q + `$`).FindStringSubmatch(title); m != nil && strings.TrimSpace(m[1]) != "" {
		title = strings.TrimSpace(m[1])
	}
	if m := regexp.MustCompile(`(?is)^` + q + titleSep + `(\S.*)$`).FindStringSubmatch(title); m != nil && strings.TrimSpace(m[1]) != "" {
		title = strings.TrimSpace(m[1])
	}
	return title
}

// hasLetterOrDigit reports whether s has at least one letter or digit.
func hasLetterOrDigit(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// CleanTitle is the title rule for text from any source (a page or an
// API): CleanText, StripSiteName with site (cleaned), "" when generic or
// without any letter or digit, cut to MaxTitle.
func CleanTitle(title, site string) string {
	t := StripSiteName(CleanText(title), CleanText(site))
	if t == "" || IsGenericTitle(t) || !hasLetterOrDigit(t) {
		return ""
	}
	return Cut(t, MaxTitle)
}

// ExtractMeta reads the title and site name of an HTML page (IsHTML; other
// pages give an empty Meta). The body is decoded from the charset of the
// Content-Type header, else of a <meta charset> / http-equiv declaration in
// the first 1024 bytes, else as UTF-8; an unknown or non-ASCII-compatible
// charset (UTF-16) gives an empty Meta. Only the head is read (up to
// </head> or <body>); comments, script, style, noscript and template
// contents are skipped.
func ExtractMeta(p *Page) Meta {
	if p == nil || !p.IsHTML() || len(p.Body) == 0 {
		return Meta{}
	}
	doc, ok := decode(p.Body, p.Charset)
	if !ok {
		return Meta{}
	}
	title, og, site := scanHead(doc)
	m := Meta{SiteName: Cut(CleanText(site), MaxTitle)}
	for _, t := range []string{title, og} {
		if c := CleanTitle(t, site); c != "" {
			m.Title = c
			break
		}
	}
	return m
}

var metaCharsetRe = regexp.MustCompile(`(?i)<meta[^>]+charset\s*=\s*["']?\s*([A-Za-z0-9._:-]+)`)

// decode returns body as UTF-8.
func decode(body []byte, charset string) (string, bool) {
	if charset == "" {
		head := body
		if len(head) > 1024 {
			head = head[:1024]
		}
		if m := metaCharsetRe.FindSubmatch(head); m != nil {
			charset = strings.ToLower(string(m[1]))
		}
	}
	if charset == "" || charset == "utf-8" || charset == "utf8" {
		return string(body), true
	}
	enc, err := htmlindex.Get(charset)
	if err != nil {
		return "", false
	}
	name, _ := htmlindex.Name(enc)
	switch name {
	case "utf-8":
		return string(body), true
	case "utf-16be", "utf-16le", "replacement":
		return "", false
	}
	out, _, err := transform.Bytes(enc.NewDecoder(), body)
	if err != nil {
		return "", false
	}
	return string(out), true
}

// scanHead returns the raw text of the first <title>, and the content of
// meta og:title and og:site_name, from the head of doc.
func scanHead(doc string) (title, ogTitle, siteName string) {
	low := asciiLower(doc) // same byte length as doc: indexes are shared
	gotTitle := false
	i := 0
	for i < len(doc) {
		j := strings.IndexByte(low[i:], '<')
		if j < 0 {
			break
		}
		i += j
		if strings.HasPrefix(low[i:], "<!--") {
			k := strings.Index(low[i+4:], "-->")
			if k < 0 {
				break
			}
			i += 4 + k + 3
			continue
		}
		name, end := tagName(low, i+1)
		if name == "" {
			i++
			continue
		}
		gt := tagEnd(doc, end)
		if gt < 0 {
			break
		}
		switch name {
		case "/head", "body":
			return
		case "script", "style", "noscript", "template", "textarea", "xmp", "iframe", "noembed", "noframes":
			k := strings.Index(low[gt:], "</"+name)
			if k < 0 {
				return
			}
			i = gt + k + 2
			continue
		case "title":
			k := strings.Index(low[gt:], "</title")
			if k < 0 {
				return
			}
			if !gotTitle {
				title, gotTitle = doc[gt:gt+k], true
			}
			i = gt + k + 2
			continue
		case "meta":
			attrs := parseAttrs(doc[end : gt-1])
			prop := strings.ToLower(attrs["property"])
			if prop == "" {
				prop = strings.ToLower(attrs["name"])
			}
			switch prop {
			case "og:title":
				if ogTitle == "" {
					ogTitle = attrs["content"]
				}
			case "og:site_name":
				if siteName == "" {
					siteName = attrs["content"]
				}
			}
		}
		i = gt
	}
	return
}

// asciiLower lower-cases ASCII letters only, so the result has exactly
// the byte length of s and every index into it is an index into s
// (strings.ToLower changes lengths: U+212A, U+0130, invalid bytes).
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

// tagName reads a tag name (with a leading "/" for end tags) of the lower
// case document at i; "" when there is none.
func tagName(low string, i int) (string, int) {
	j := i
	if j < len(low) && low[j] == '/' {
		j++
	}
	k := j
	for k < len(low) && (low[k] >= 'a' && low[k] <= 'z' || low[k] >= '0' && low[k] <= '9' || low[k] == '-') {
		k++
	}
	if k == j || (low[j] < 'a' || low[j] > 'z') {
		return "", i
	}
	return low[i:k], k
}

// tagEnd returns the index just after the ">" closing the tag whose
// attributes start at i (quoted values may contain ">"); -1 when none.
func tagEnd(doc string, i int) int {
	var q byte
	for ; i < len(doc); i++ {
		c := doc[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '>':
			return i + 1
		}
	}
	return -1
}

// parseAttrs parses the attributes of a tag (names lower case, first
// occurrence wins; values raw: CleanText decodes entities).
func parseAttrs(s string) map[string]string {
	out := map[string]string{}
	i := 0
	for i < len(s) {
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == '\f' || s[i] == '/') {
			i++
		}
		j := i
		for j < len(s) && s[j] != '=' && s[j] != ' ' && s[j] != '\t' && s[j] != '\n' && s[j] != '\r' && s[j] != '\f' && s[j] != '/' {
			j++
		}
		if j == i {
			i++
			continue
		}
		name := strings.ToLower(s[i:j])
		i = j
		for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == '\f') {
			i++
		}
		val := ""
		if i < len(s) && s[i] == '=' {
			i++
			for i < len(s) && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r' || s[i] == '\f') {
				i++
			}
			if i < len(s) && (s[i] == '"' || s[i] == '\'') {
				q := s[i]
				k := strings.IndexByte(s[i+1:], q)
				if k < 0 {
					val, i = s[i+1:], len(s)
				} else {
					val, i = s[i+1:i+1+k], i+1+k+1
				}
			} else {
				k := i
				for k < len(s) && s[k] != ' ' && s[k] != '\t' && s[k] != '\n' && s[k] != '\r' && s[k] != '\f' {
					k++
				}
				val, i = s[i:k], k
			}
		}
		if _, dup := out[name]; !dup {
			out[name] = val
		}
	}
	return out
}
