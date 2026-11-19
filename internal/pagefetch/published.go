package pagefetch

import (
	"encoding/json"
	"html"
	"strings"
	"time"
)

// Publication time of a fetched article (docs/webpages.md, "Publication
// time"). ExtractPublished reads it from the HTML already fetched (no
// request of its own), from the sources a page states it in, in this order
// of trust:
//
//  1. JSON-LD (<script type="application/ld+json">): datePublished of the
//     first object typed Article, NewsArticle, BlogPosting, TechArticle,
//     Report, ScholarlyArticle or AnalysisNewsArticle, else of the first
//     object that has one at all (top-level objects, arrays, @graph and
//     mainEntity);
//  2. <meta property="article:published_time">;
//  3. <meta name=...> date, pubdate, publishdate, dc.date, dc.date.issued,
//     citation_publication_date, parsely-pub-date, sailthru.date (names
//     compared case-insensitively; in this order);
//  4. <meta itemprop="datePublished">;
//  5. <time datetime> with a pubdate attribute or itemprop="datePublished".
//
// A source whose value does not parse (ParsePublished) or is implausible
// (before PublishedMin, or after the fetch time plus PublishedSlack) is
// skipped and the next one is tried. Modification times (Last-Modified,
// article:modified_time, dateModified) are never used.

// Precision of a publication time.
const (
	PublishedExact = "exact" // a time of day with a zone or offset
	PublishedDay   = "day"   // a calendar date (also a time without a zone)
)

// Bounds of the extraction.
const (
	// maxLDBlocks JSON-LD blocks are read per page, each at most maxLDBytes.
	maxLDBlocks = 8
	maxLDBytes  = 64 << 10
	// maxLDDepth bounds the nesting of a JSON-LD block (deeper: skipped) and
	// of the walk over it.
	maxLDDepth = 32
	maxLDWalk  = 6
	// PublishedSlack: a time up to this much after the fetch is accepted
	// (zones, clocks); later ones are not a publication time.
	PublishedSlack = 24 * time.Hour
)

// PublishedMin: earlier dates are not a publication time of a web article.
var PublishedMin = time.Date(1995, 1, 1, 0, 0, 0, 0, time.UTC)

// Published is a page's stated publication time.
type Published struct {
	At        time.Time // UTC; for PublishedDay midnight UTC of the date
	Precision string    // PublishedExact | PublishedDay
	// Source names where it was read: "json-ld", "meta:<property or
	// name, lower case>", "meta:itemprop" or "time".
	Source string
}

// ldArticleTypes are the JSON-LD types whose datePublished is preferred.
var ldArticleTypes = map[string]bool{"article": true, "newsarticle": true, "blogposting": true, "techarticle": true,
	"report": true, "scholarlyarticle": true, "analysisnewsarticle": true}

// metaDateNames are the <meta name> keys read, in order of trust.
var metaDateNames = []string{"date", "pubdate", "publishdate", "dc.date", "dc.date.issued", "citation_publication_date",
	"parsely-pub-date", "sailthru.date"}

// ExtractPublished returns the publication time p states (see above), judged
// against fetchedAt; ok is false when there is none, p is not an HTML page or
// its body cannot be decoded (the same rules as ExtractMeta).
func ExtractPublished(p *Page, fetchedAt time.Time) (Published, bool) {
	if p == nil || !p.IsHTML() || len(p.Body) == 0 {
		return Published{}, false
	}
	doc, ok := decode(p.Body, p.Charset)
	if !ok {
		return Published{}, false
	}
	return publishedFrom(scanDates(doc), fetchedAt)
}

// dateCands are the raw values scanDates found, per source, in page order.
type dateCands struct {
	ld       []string // JSON-LD blocks
	article  []string // meta article:published_time
	names    map[string][]string
	itemprop []string
	times    []string
}

// publishedFrom picks the first plausible value by the order of trust.
func publishedFrom(c dateCands, fetchedAt time.Time) (Published, bool) {
	try := func(v, source string) (Published, bool) {
		at, prec, ok := ParsePublished(v)
		if !ok || !Plausible(at, fetchedAt) {
			return Published{}, false
		}
		return Published{At: at, Precision: prec, Source: source}, true
	}
	var ldAny []string
	for _, b := range c.ld {
		art, other := ldDates(b)
		for _, v := range art {
			if p, ok := try(v, "json-ld"); ok {
				return p, true
			}
		}
		ldAny = append(ldAny, other...)
	}
	for _, v := range ldAny {
		if p, ok := try(v, "json-ld"); ok {
			return p, true
		}
	}
	for _, v := range c.article {
		if p, ok := try(v, "meta:article:published_time"); ok {
			return p, true
		}
	}
	for _, n := range metaDateNames {
		for _, v := range c.names[n] {
			if p, ok := try(v, "meta:"+n); ok {
				return p, true
			}
		}
	}
	for _, v := range c.itemprop {
		if p, ok := try(v, "meta:itemprop"); ok {
			return p, true
		}
	}
	for _, v := range c.times {
		if p, ok := try(v, "time"); ok {
			return p, true
		}
	}
	return Published{}, false
}

// Plausible reports whether at can be the publication time of a page
// fetched at fetchedAt: not before PublishedMin, not after fetchedAt plus
// PublishedSlack.
func Plausible(at, fetchedAt time.Time) bool {
	return !at.Before(PublishedMin) && !at.After(fetchedAt.Add(PublishedSlack))
}

// publishedLayouts: with a zone or offset (exact), and without (day).
var (
	exactLayouts = []string{
		time.RFC3339Nano, "2006-01-02T15:04Z07:00", "2006-01-02T15:04:05.999999999Z0700", "2006-01-02T15:04Z0700",
		"2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05.999999999 Z07:00", "2006-01-02 15:04:05.999999999 -0700",
		"2006-01-02 15:04:05.999999999-0700",
		"Mon, 02 Jan 2006 15:04:05 -0700", "Mon, 2 Jan 2006 15:04:05 -0700",
	}
	// RFC 1123 with a zone name: only GMT and UTC (Go would make up a
	// zero offset for an unknown abbreviation).
	gmtLayouts = []string{"Mon, 02 Jan 2006 15:04:05", "Mon, 2 Jan 2006 15:04:05"}
	dayLayouts = []string{
		"2006-01-02T15:04:05.999999999", "2006-01-02T15:04", "2006-01-02 15:04:05.999999999", "2006-01-02 15:04",
		"2006-01-02", "2006/01/02", "2006/1/2",
	}
)

// ParsePublished parses a stated publication time strictly: RFC 3339 and
// its common variants (offset without a colon, no seconds, a space for T),
// RFC 1123 (numeric offset, or GMT / UTC) give PublishedExact (in UTC); a
// date only (YYYY-MM-DD, YYYY/MM/DD) or a date and time without a zone give
// PublishedDay (the date as written, midnight UTC). Anything else (a year
// alone, words, trailing text) is not a time.
func ParsePublished(s string) (time.Time, string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > 64 {
		return time.Time{}, "", false
	}
	for _, l := range exactLayouts {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), PublishedExact, true
		}
	}
	for _, z := range []string{" GMT", " UTC"} {
		if rest, ok := strings.CutSuffix(s, z); ok {
			for _, l := range gmtLayouts {
				if t, err := time.Parse(l, rest); err == nil {
					return t.UTC(), PublishedExact, true
				}
			}
		}
	}
	for _, l := range dayLayouts {
		if t, err := time.Parse(l, s); err == nil {
			y, m, d := t.Date()
			return time.Date(y, m, d, 0, 0, 0, 0, time.UTC), PublishedDay, true
		}
	}
	return time.Time{}, "", false
}

// scanDates collects the raw date values of the whole document (JSON-LD
// is often in the body, <time> always), skipping comments and the contents
// of other scripts, styles and raw-text elements.
func scanDates(doc string) dateCands {
	c := dateCands{names: map[string][]string{}}
	low := asciiLower(doc)
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
		case "script", "style", "noscript", "template", "textarea", "xmp", "iframe", "noembed", "noframes":
			k := strings.Index(low[gt:], "</"+name)
			if k < 0 {
				return c
			}
			if name == "script" && len(c.ld) < maxLDBlocks && k <= maxLDBytes {
				attrs := parseAttrs(doc[end : gt-1])
				if strings.EqualFold(strings.TrimSpace(attrs["type"]), "application/ld+json") {
					c.ld = append(c.ld, doc[gt:gt+k])
				}
			}
			i = gt + k + 2
			continue
		case "meta":
			attrs := parseAttrs(doc[end : gt-1])
			v := html.UnescapeString(attrs["content"])
			switch {
			case strings.EqualFold(attrs["property"], "article:published_time"):
				c.article = append(c.article, v)
			case strings.EqualFold(attrs["itemprop"], "datepublished"):
				c.itemprop = append(c.itemprop, v)
			case attrs["name"] != "":
				n := strings.ToLower(strings.TrimSpace(attrs["name"]))
				if n == "article:published_time" {
					c.article = append(c.article, v)
				} else {
					c.names[n] = append(c.names[n], v)
				}
			}
		case "time":
			attrs := parseAttrs(doc[end : gt-1])
			_, pub := attrs["pubdate"]
			if dt, ok := attrs["datetime"]; ok && (pub || strings.EqualFold(attrs["itemprop"], "datepublished")) {
				c.times = append(c.times, html.UnescapeString(dt))
			}
		}
		i = gt
	}
	return c
}

// ldDates reads one JSON-LD block: the datePublished values of article
// objects and of other objects, in document order. Junk around the JSON
// (HTML comment or CDATA markers, a trailing semicolon) is tolerated; a block
// that still does not parse, or nests deeper than maxLDDepth, gives nothing.
func ldDates(block string) (articles, others []string) {
	s := strings.TrimSpace(block)
	for _, w := range [][2]string{{"<!--", "-->"}, {"<![CDATA[", "]]>"}, {"//<![CDATA[", "//]]>"}} {
		s = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(s, w[0]), w[1]))
	}
	s = strings.TrimSpace(strings.TrimSuffix(s, ";"))
	if s == "" || !shallow(s, maxLDDepth) {
		return nil, nil
	}
	var v any
	if err := json.Unmarshal([]byte(s), &v); err != nil {
		return nil, nil
	}
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if depth > maxLDWalk {
			return
		}
		switch x := v.(type) {
		case []any:
			for _, e := range x {
				walk(e, depth+1)
			}
		case map[string]any:
			if d, ok := x["datePublished"].(string); ok {
				if ldIsArticle(x["@type"]) {
					articles = append(articles, d)
				} else {
					others = append(others, d)
				}
			}
			for _, k := range []string{"@graph", "mainEntity"} {
				if c, ok := x[k]; ok {
					walk(c, depth+1)
				}
			}
		}
	}
	walk(v, 0)
	return articles, others
}

// ldIsArticle reports whether a JSON-LD @type (a string or an array of
// strings, possibly with a schema.org prefix) names an article type.
func ldIsArticle(t any) bool {
	one := func(s string) bool {
		s = strings.ToLower(strings.TrimSpace(s))
		if i := strings.LastIndexAny(s, "/:#"); i >= 0 {
			s = s[i+1:]
		}
		return ldArticleTypes[s]
	}
	switch x := t.(type) {
	case string:
		return one(x)
	case []any:
		for _, e := range x {
			if s, ok := e.(string); ok && one(s) {
				return true
			}
		}
	}
	return false
}

// shallow reports whether the JSON text s nests arrays and objects at most
// max deep (strings are skipped; a malformed text may pass and then fail to
// parse).
func shallow(s string, max int) bool {
	depth := 0
	in := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case in:
			if c == '\\' {
				i++
			} else if c == '"' {
				in = false
			}
		case c == '"':
			in = true
		case c == '{' || c == '[':
			depth++
			if depth > max {
				return false
			}
		case c == '}' || c == ']':
			depth--
		}
	}
	return true
}
