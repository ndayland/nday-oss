package xdraft

import (
	"regexp"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"

	"nday.land/nday/internal/model"
	"nday.land/nday/internal/site"
)

// Stages that get a draft, in lifecycle order.
var Stages = []string{model.EventPocPublished, model.EventExploitedInWild, model.EventKevAdded}

// IsStage reports whether t is one of Stages.
func IsStage(t string) bool {
	for _, s := range Stages {
		if s == t {
			return true
		}
	}
	return false
}

// Product is one affected vendor/product pair, in the order first reported.
type Product struct{ Vendor, Product string }

// Input is everything a draft says. Every string from upstream (title,
// vendor, product, source) is untrusted text.
type Input struct {
	CVE   string // CVE-2026-12345
	Stage string // poc_published | exploited_in_wild | kev_added
	// Days is site.CalendarDays(disclosure, first time of this stage): the
	// site's T+Nd figure; nil when either time is unknown.
	Days     *int
	Title    string    // upstream English title ("" = none)
	Products []Product // affected pairs, first reported first
	Source   string    // source of the triggering event (exploitdb, kev …)
}

// Limits of the parts (weighted).
const (
	maxProductLine = 64
	maxTitle       = 140
	minTitle       = 12 // a title cut shorter than this is left out
	maxPairs       = 3
)

// sourceNames: how the sentence names a source.
var pocWhat = map[string]string{
	"exploitdb":  "Exploit-DB entry",
	"metasploit": "Metasploit module",
	"nuclei":     "nuclei template",
}

var tokenRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

// sourceToken is a source name safe to print (registry names are lower-case
// tokens; anything else becomes "unknown").
func sourceToken(s string) string {
	if tokenRe.MatchString(s) {
		return s
	}
	return "unknown"
}

// Sentence is the plain sentence saying what happened.
func Sentence(stage, source string) string {
	switch stage {
	case model.EventKevAdded:
		return "Added to the CISA KEV catalog (known exploited)."
	case model.EventPocPublished:
		if w, ok := pocWhat[source]; ok {
			return "Public PoC available: " + w + "."
		}
		return "Public PoC available (source: " + sourceToken(source) + ")."
	case model.EventExploitedInWild:
		return "Exploitation in the wild reported (source: " + sourceToken(source) + ")."
	}
	return ""
}

// TPlus is the site's notation of days since disclosure ("T+5d", "T-20d");
// "" when unknown (the draft then leaves the figure out).
func TPlus(days *int) string {
	if days == nil {
		return ""
	}
	if *days < 0 {
		return "T-" + strconv.Itoa(-*days) + "d"
	}
	return "T+" + strconv.Itoa(*days) + "d"
}

// Clean makes untrusted UPSTREAM text (titles, vendor and product names)
// safe for a post. It is not applied to text an admin edits.
//
//   - NFC; one line: control and format characters (bidi controls, zero-
//     width joiners, tag characters) removed, white space collapsed;
//   - emoji modifiers removed: variation selectors U+FE0E/U+FE0F, skin
//     tones U+1F3FB..U+1F3FF, the keycap U+20E3;
//   - anything with a scheme ("https://…", "ftp://…") dropped;
//   - mentions: "@" and "＠" become "[at]";
//   - hashtags: "#" and "＃" dropped when a letter, digit, mark or "_"
//     follows; cashtags: "$" and "＄" dropped when a letter, mark or "_"
//     follows ("$5" stays);
//   - links: every dot (".", and the look-alikes "。" U+3002, "．" U+FF0E,
//     "｡" U+FF61) between a letter, digit or mark and a following letter or
//     mark becomes "[.]", whatever precedes the host ("中evil.com",
//     "x_y.evil.com", "exämple.com", "evil.рф"). A dot followed by a digit
//     stays ("2.4.1", "v1.2"): a TLD starts with a letter, so such a dot
//     never ends a domain name. "ASP.NET" becomes "ASP[.]NET".
func Clean(s string) string {
	s = norm.NFC.String(strings.ToValidUTF8(s, ""))
	var b strings.Builder
	space := false
	for _, r := range s {
		switch {
		case unicode.IsSpace(r):
			space = b.Len() > 0
			continue
		case unicode.IsControl(r) || unicode.Is(unicode.Cf, r) || r == '\uFFFD' || emojiModifier(r):
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	s = schemeURLRe.ReplaceAllString(b.String(), "")
	// mentions, hashtags, cashtags (ASCII and full-width forms)
	r := []rune(s)
	b.Reset()
	for i, c := range r {
		next := rune(0)
		if i+1 < len(r) {
			next = r[i+1]
		}
		switch c {
		case '@', '\uFF20':
			b.WriteString("[at]")
			continue
		case '#', '\uFF03':
			if lnm(next) || next == '_' {
				continue
			}
		case '$', '\uFF04':
			if unicode.IsLetter(next) || unicode.IsMark(next) || next == '_' {
				continue
			}
		}
		b.WriteRune(c)
	}
	// dots that may end a domain name (after the pass above, so a dropped
	// "#" cannot join two parts)
	r = []rune(b.String())
	b.Reset()
	for i, c := range r {
		if isDot(c) && i > 0 && i+1 < len(r) && linkDot(r[i-1], r[i+1]) {
			b.WriteString("[.]")
			continue
		}
		b.WriteRune(c)
	}
	return strings.Join(strings.Fields(b.String()), " ")
}

// emojiModifier: variation selectors, skin tones and the keycap mark.
func emojiModifier(r rune) bool {
	return r == 0xFE0E || r == 0xFE0F || r >= 0x1F3FB && r <= 0x1F3FF || r == 0x20E3
}

// Linkable reports whether text still holds something X may turn into a
// link: a sure link (WeightedLength rule 2) or a dot that may end a domain
// name. Clean's output never is.
func Linkable(text string) bool {
	s := norm.NFC.String(text)
	prev := rune(-1)
	for i := 0; i < len(s); {
		if sureURL(s, i) > i {
			return true
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if isDot(r) && prev >= 0 && i < len(s) {
			if next, _ := utf8.DecodeRuneInString(s[i:]); linkDot(prev, next) {
				return true
			}
		}
		prev = r
	}
	return false
}

var schemeURLRe = regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://[^\s]*`)

// ProductLine renders affected pairs like the share card (internal/ogcard
// productLine): consecutive pairs of one vendor merged ("Vendor / A, B"),
// vendors joined with " · ", a product that only repeats its vendor adds
// nothing ("X / X" -> "X", "X / X Foo" -> "X / Foo"), at most maxPairs
// pairs and " +N" for the rest. Every name goes through Clean.
func ProductLine(ps []Product) string {
	var groups []string
	var cur []string
	vendor, shown, open := "", 0, false
	flush := func() {
		if !open {
			return
		}
		g := strings.Join(cur, ", ")
		switch {
		case vendor != "" && g != "":
			g = vendor + " / " + g
		case vendor != "":
			g = vendor
		}
		if g != "" {
			groups = append(groups, g)
		}
	}
	total := 0
	for _, p := range ps {
		v, pr := Clean(p.Vendor), Clean(p.Product)
		if !meaningful(v) {
			v = ""
		}
		if !meaningful(pr) || pr == "*" {
			pr = ""
		}
		if v == "" && pr == "" {
			continue
		}
		total++
		if shown >= maxPairs {
			continue
		}
		shown++
		if !open || !strings.EqualFold(v, vendor) {
			flush()
			vendor, cur, open = v, nil, true
		}
		if v != "" {
			if strings.EqualFold(pr, v) {
				pr = ""
			} else if len(pr) > len(v) && pr[len(v)] == ' ' && strings.EqualFold(pr[:len(v)], v) {
				pr = strings.TrimSpace(pr[len(v):])
			}
		}
		dup := false
		for _, have := range cur {
			if strings.EqualFold(have, pr) {
				dup = true
			}
		}
		if pr != "" && !dup {
			cur = append(cur, pr)
		}
	}
	flush()
	line := strings.Join(groups, " · ")
	if n := total - shown; n > 0 && line != "" {
		line += " +" + strconv.Itoa(n)
	}
	return line
}

// meaningful: a name with a letter or digit that is not a placeholder of
// the CVE record ("n/a", "unknown", …).
func meaningful(s string) bool {
	switch strings.ToLower(s) {
	case "n/a", "na", "unknown", "unspecified", "not applicable", "none":
		return false
	}
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// cut shortens s to at most w weighted, ending in "…" when cut (at a word
// boundary when one is near).
func cut(s string, w int) string {
	if WeightedLength(s) <= w {
		return s
	}
	r := []rune(s)
	if len(r) > 2*w+2 { // every rune weighs at least 1 (no scheme URL is left after Clean)
		r = r[:2*w+2]
	}
	for n := len(r); n > 0; n-- {
		t := strings.TrimRight(string(r[:n]), " ,;:-–—/·")
		if sp := strings.LastIndexByte(t, ' '); sp > 0 && len(t)-sp < 16 && n < len(r) {
			t = strings.TrimRight(t[:sp], " ,;:-–—/·")
		}
		if t != "" && WeightedLength(t+"…") <= w {
			return t + "…"
		}
	}
	return ""
}

// Build is the draft body (without the link, which the page appends):
//
//	CVE-2026-12345 +KEV T+12d
//	Vendor / Product
//	Upstream title, cut to fit
//	Added to the CISA KEV catalog (known exploited).
//
// The result always weighs at most BodyBudget (the title is cut first,
// then left out, then the product line is cut). No hashtags, emoji or
// mentions; upstream text goes through Clean.
func Build(in Input) string {
	head := in.CVE + " +" + site.StageCode(in.Stage)
	if tp := TPlus(in.Days); tp != "" {
		head += " " + tp
	}
	sent := Sentence(in.Stage, in.Source)
	prod := cut(ProductLine(in.Products), maxProductLine)
	title := cut(Clean(in.Title), maxTitle)
	join := func(title, prod string) string {
		parts := []string{head}
		for _, p := range []string{prod, title} {
			if p != "" {
				parts = append(parts, p)
			}
		}
		return strings.Join(append(parts, sent), "\n")
	}
	body := join(title, prod)
	if WeightedLength(body) <= BodyBudget {
		return body
	}
	if title != "" {
		room := BodyBudget - WeightedLength(join("", prod)) - 1 // the title's newline
		if t := cut(title, room); WeightedLength(t) >= minTitle {
			if b := join(t, prod); WeightedLength(b) <= BodyBudget {
				return b
			}
		}
	}
	body = join("", prod)
	if WeightedLength(body) <= BodyBudget {
		return body
	}
	room := BodyBudget - WeightedLength(join("", "")) - 1
	if p := cut(prod, room); p != "" {
		if b := join("", p); WeightedLength(b) <= BodyBudget {
			return b
		}
	}
	return join("", "")
}
