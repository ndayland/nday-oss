package zerowire

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"nday.land/nday/internal/collector/xposts"
	"nday.land/nday/internal/pagefetch"
)

// Limits on what we keep from one item.
const (
	MaxTitleRunes    = 300
	MaxCategories    = 20
	MaxCategoryRunes = 100
	MaxItems         = 500 // the feed has about a dozen; anything past this is ignored
)

// Article is what we keep from one feed item. The description and the
// article body are only read for ids; they never leave the parser.
type Article struct {
	Slug       string
	Title      string // cleaned, at most MaxTitleRunes; may be ""
	Link       string // always ArticleURL(Slug)
	PubDate    string // "YYYY-MM-DD" (the feed only gives a date), "" when missing or unreadable
	CVEs       []string
	GHSAs      []string
	Categories []string
}

// FeedStats counts what ParseFeed left out.
type FeedStats struct {
	Items     int // items in the feed (up to MaxItems)
	BadLink   int // link isn't https://radar.cloudflare.com/zero-wire/<slug>
	Duplicate int // a second item with a slug we already had
}

// rss is the bit of RSS 2.0 we read. Unknown elements are ignored by
// encoding/xml, and it never resolves external entities.
type rss struct {
	XMLName xml.Name `xml:"rss"`
	Items   []item   `xml:"channel>item"`
}

type item struct {
	Title       string   `xml:"title"`
	Link        string   `xml:"link"`
	PubDate     string   `xml:"pubDate"`
	Description string   `xml:"description"`
	Content     string   `xml:"http://purl.org/rss/1.0/modules/content/ encoded"`
	Categories  []string `xml:"category"`
}

// slugRe is what we accept as an article slug.
var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,199}$`)

// ValidSlug reports whether s is an acceptable slug.
func ValidSlug(s string) bool { return slugRe.MatchString(s) }

// ArticleURL is the public address of one advisory.
func ArticleURL(slug string) string { return ArticleBaseURL + slug }

// SlugOf returns the slug of an advisory link, or false when the link is
// anything other than exactly https://radar.cloudflare.com/zero-wire/<slug>
// (no query, no fragment, no trailing slash, no other host).
func SlugOf(link string) (string, bool) {
	link = strings.TrimSpace(link)
	slug, ok := strings.CutPrefix(link, ArticleBaseURL)
	if !ok || !ValidSlug(slug) {
		return "", false
	}
	return slug, true
}

var tagRe = regexp.MustCompile(`(?s)<[^>]*>`)

// cleanTitle makes the (hostile) title safe to keep: entities decoded once,
// control / format / bidi characters dropped, whitespace collapsed, cut.
func cleanTitle(s string) string {
	return pagefetch.Cut(pagefetch.CleanText(s), MaxTitleRunes)
}

// pubDay reads an RSS pubDate and returns its calendar day as written
// (Zero Wire always says 00:00:00 GMT, so the day is all there is).
func pubDay(s string) string {
	t, err := mail.ParseDate(strings.TrimSpace(s))
	if err != nil {
		return ""
	}
	return t.Format(time.DateOnly)
}

// ParseFeed reads the RSS document. An item whose link isn't a Zero Wire
// advisory is skipped; a repeated slug keeps the first item.
func ParseFeed(body []byte) ([]Article, FeedStats, error) {
	var doc rss
	d := xml.NewDecoder(bytes.NewReader(body))
	if err := d.Decode(&doc); err != nil {
		return nil, FeedStats{}, fmt.Errorf("not an RSS feed: %w", err)
	}
	items := doc.Items
	if len(items) > MaxItems {
		items = items[:MaxItems]
	}
	st := FeedStats{Items: len(items)}
	seen := map[string]bool{}
	var out []Article
	for _, it := range items {
		slug, ok := SlugOf(it.Link)
		if !ok {
			st.BadLink++
			continue
		}
		if seen[slug] {
			st.Duplicate++
			continue
		}
		seen[slug] = true
		// ids can sit in link targets as well as in the text, so look at the
		// raw HTML and at its decoded text
		text := strings.Join([]string{it.Title, it.Description, it.Content,
			html.UnescapeString(tagRe.ReplaceAllString(it.Content, " "))}, "\n")
		a := Article{Slug: slug, Title: cleanTitle(it.Title), Link: ArticleURL(slug), PubDate: pubDay(it.PubDate),
			CVEs: xposts.ExtractCVEs(text), GHSAs: xposts.ExtractGHSAs(text)}
		for _, c := range it.Categories {
			if len(a.Categories) == MaxCategories {
				break
			}
			if c = pagefetch.Cut(pagefetch.CleanText(c), MaxCategoryRunes); c != "" {
				a.Categories = append(a.Categories, c)
			}
		}
		out = append(out, a)
	}
	return out, st, nil
}
