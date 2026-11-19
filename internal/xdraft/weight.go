// Package xdraft writes draft posts for the brand X account (docs/xposts.md,
// migrations/0012_xdrafts.sql): when a vulnerability newly reaches POC, ITW
// or KEV, Generate stores a short English draft built from data only; staff
// review it on /admin/x/drafts and publish it themselves through X's web
// compose window (ComposeURL). Nothing here calls X or any other service.
//
// The package also holds the rules shared by the generator, the admin
// endpoints and the page: X's weighted length (WeightedLength), the post URL
// validator (NormalizePostURL) and the compose URL (ComposeURL).
package xdraft

import (
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// X's length rule (twitter-text v3 configuration): maxWeightedTweetLength
// 280, scale 100, defaultWeight 200, weight 100 for the code point ranges
// below, every URL counts transformedURLLength 23. Weights here are in
// units of scale (1 = 100, 2 = 200).
const (
	MaxWeighted = 280
	URLWeight   = 23
	// LinkCost is what the page appends to a body: "\n" + the detail URL.
	LinkCost = 1 + URLWeight
	// BodyBudget is the most a body may weigh so that body + "\n" + link
	// fits: what the generator and Share write. A saved body may weigh up
	// to MaxWeighted (the image forms post it alone); one over BodyBudget
	// cannot be posted in the link form.
	BodyBudget = MaxWeighted - LinkCost
	// MaxBodyRunes bounds a body before weighting (the table's CHECK).
	MaxBodyRunes = 1000
)

// weight of one code point: 1 for the light ranges of the v3 config
// (0-4351, 8192-8205, 8208-8223, 8242-8247), else 2. The two emoji inside
// the light ranges (© and ®) count 2, as twitter-text counts an emoji.
func weight(r rune) int {
	switch {
	case r == 0x00A9 || r == 0x00AE:
		return 2
	case r <= 4351, r >= 8192 && r <= 8205, r >= 8208 && r <= 8223, r >= 8242 && r <= 8247:
		return 1
	}
	return 2
}

// The counting rule is an UPPER BOUND of twitter-text v3, never below it:
//
//  1. Every code point counts its own weight (no emoji grouping: X counts a
//     whole emoji sequence as 2, here each pictograph, modifier, variation
//     selector, tag character and joiner counts on its own, which is never
//     less).
//  2. A "sure" link counts URLWeight: it starts at the beginning of the text
//     or after an ASCII space, tab or newline; is "http://" or "https://"
//     (lower case) followed by an ASCII host name with a TLD from the list
//     below, ending at the end of the text, white space, "/" or one of
//     .,;:!?)'" ; and takes a path only from the conservative ASCII set
//     [A-Za-z0-9/_=+%~.-], trimmed back to a character in [A-Za-z0-9/_=+-].
//     twitter-text links at least that much (its path and ending sets
//     contain these), so the link X makes covers the span and the rest is
//     counted by rule 1 and 3, which is never less than X counts it.
//  3. Anything else X might turn into a link is covered by a surcharge:
//     every link X makes contains a dot ending its domain name, preceded by
//     a letter, digit or mark and followed by the first letter of the TLD;
//     the shortest link ("a.co") weighs at least 4 by rule 1, so X saves at
//     most URLWeight-4 = 19 per link over rule 1 — this package adds 19 for
//     every such dot (ASCII ".", and the look-alikes U+3002, U+FF0E, U+FF61
//     for good measure) outside a sure link. A dot followed by a digit never
//     ends a domain name (TLDs start with a letter), so "2.4.1" costs
//     nothing extra.
//
// The result over-counts text with links in odd places, emoji sequences and
// abbreviations ("e.g"), which only makes the limit stricter.
const dotSurcharge = URLWeight - 4

// maxSureURL: twitter-text does not link URLs longer than this.
const maxSureURL = 4000

// tlds for a sure link (rule 2): a subset of twitter-text's list (common
// generic ones, popular new ones and country codes). A host with another
// TLD is never "sure"; it is covered by rule 3.
var tlds = "com|net|org|edu|gov|mil|int|info|biz|name|pro|mobi|asia|tel|travel|jobs|cat|coop|aero|museum|xxx|" +
	"app|dev|page|blog|cloud|online|site|tech|xyz|land|link|live|news|shop|store|top|club|space|website|wiki|" +
	"art|design|digital|email|global|group|host|life|media|network|one|run|social|software|solutions|systems|today|" +
	"tools|world|zone|codes|security|services|support|team|works|io|co|me|tv|ai|ly|gg|sh|to|so|fm|ws|cc|im|is|it|us|" +
	"uk|de|cn|ru|jp|fr|nl|eu|ca|au|in|br|kr|tw|hk|sg|ch|se|no|fi|dk|pl|cz|es|pt|be|at|ie|nz|mx|ar|cl|za|il|ir|tr|ua|" +
	"vn|th|id|my|ph|py|pw|cx|gl|ms|nu|tk|ml|ga|cf|gq|la|li|lu|md|mn|rs|si|sk|st|su|tf|vc|ac"

var sureHostRe = regexp.MustCompile(`^https?://(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+(?:` + tlds + `)`)

// isDot: the ASCII dot and its full-width / ideographic look-alikes.
func isDot(r rune) bool { return r == '.' || r == 0x3002 || r == 0xFF0E || r == 0xFF61 }

func lnm(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.IsMark(r) }

// linkDot reports whether a dot between prev and next may end a domain name
// that X links (rule 3; also what Clean neutralises in upstream text).
func linkDot(prev, next rune) bool {
	return lnm(prev) && (unicode.IsLetter(next) || unicode.IsMark(next))
}

// sureURL returns the end of a sure link starting at s[i:] (rule 2), or i.
func sureURL(s string, i int) int {
	if i > 0 {
		if p := s[i-1]; p != ' ' && p != '\t' && p != '\n' {
			return i
		}
	}
	m := sureHostRe.FindStringIndex(s[i:])
	if m == nil {
		return i
	}
	end := i + m[1]
	if end < len(s) && !strings.ContainsRune(" \t\n/.,;:!?)'\"", rune(s[end])) {
		return i // the host goes on (another label, a port, "@", a non-ASCII letter …)
	}
	if end < len(s) && s[end] == '/' {
		j := end
		for j < len(s) && strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_=+%~.-", s[j]) >= 0 {
			j++
		}
		for j > end && strings.IndexByte("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789/_=+-", s[j-1]) < 0 {
			j--
		}
		end = j
	}
	if end-i > maxSureURL {
		return i
	}
	return end
}

// WeightedLength is an upper bound of X's weighted length of text (NFC
// first, as twitter-text does), by the rules above. Invalid UTF-8 counts 2
// per bad byte.
func WeightedLength(text string) int {
	s := norm.NFC.String(text)
	n := 0
	prev := rune(-1)
	for i := 0; i < len(s); {
		if end := sureURL(s, i); end > i {
			n += URLWeight
			i = end
			prev = '/'
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == utf8.RuneError && size == 1 {
			n += 2
			prev = r
			continue
		}
		n += weight(r)
		if isDot(r) && prev >= 0 {
			if next, _ := utf8.DecodeRuneInString(s[i:]); i < len(s) && linkDot(prev, next) {
				n += dotSurcharge
			}
		}
		prev = r
	}
	return n
}

// FitsWithLink reports whether body + "\n" + a link fits in one post.
func FitsWithLink(body string) bool { return WeightedLength(body) <= BodyBudget }

// FitsAlone reports whether body fits one post on its own, with no link
// (the whole MaxWeighted budget; the image forms of the drafts page).
func FitsAlone(body string) bool { return WeightedLength(body) <= MaxWeighted }
