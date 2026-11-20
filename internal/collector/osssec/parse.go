package osssec

import (
	"errors"
	"html"
	"net/mail"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/collector/xposts"
)

// BodyScanBytes is how much of a message body we look at for ids. Real posts
// are a few KB; a huge one (a pasted log, a full patch) still has its ids up
// top, and this keeps the regex work bounded.
const BodyScanBytes = 512 << 10

// MHonArc comment markers on seclists.org message pages.
const (
	mSubjectBegin = "<!--X-Subject-Header-Begin-->"
	mSubjectEnd   = "<!--X-Subject-Header-End-->"
	mHeadBegin    = "<!--X-Head-of-Message-->"
	mHeadEnd      = "<!--X-Head-of-Message-End-->"
	mBodyBegin    = "<!--X-Body-of-Message-->"
	mBodyEnd      = "<!--X-Body-of-Message-End-->"
	mRefsBegin    = "<!--X-References-->"
	mRefsEnd      = "<!--X-References-End-->"
)

// Message is what we keep from one message page. No body text and no e-mail
// address ever leave the parser.
type Message struct {
	Subject    string
	Author     string     // display name only; "" when the post shows just an address
	Date       *time.Time // UTC; nil when the Date header is missing or unreadable
	IsReply    bool
	CVEs       []string // every CVE id in subject + body, first appearance first
	GHSAs      []string // every GHSA id in subject + body, canonical form
	SubjectIDs []string // the CVE and GHSA ids that appear in the subject
}

// ErrNotMessage means the page doesn't look like an archived message (the
// MHonArc markers are missing), e.g. the site layout changed.
var ErrNotMessage = errors.New("not a message page (MHonArc markers missing)")

var (
	tagRe      = regexp.MustCompile(`(?s)<[^>]*>`)
	spaceRe    = regexp.MustCompile(`\s+`)
	headLineRe = regexp.MustCompile(`(?is)<em>\s*([A-Za-z-]+)\s*</em>\s*:\s*(.*?)<br\s*/?>`)
	metaSubjRe = regexp.MustCompile(`(?i)<meta\s+name="Subject"\s+content="([^"]*)"`)
	// an obfuscated address the way seclists shows it: "user () host com"
	obfuscRe = regexp.MustCompile(`\S+\s+\(\)\s+\S+`)
	replyRe  = regexp.MustCompile(`(?i)^re\s*:`)
	// index anchors: <a name="797" href="797">
	indexRe = regexp.MustCompile(`<a name="([0-9]{1,6})" href="([0-9]{1,6})"`)
)

// section returns the text between two markers, and whether both were found.
func section(page, begin, end string) (string, bool) {
	i := strings.Index(page, begin)
	if i < 0 {
		return "", false
	}
	rest := page[i+len(begin):]
	j := strings.Index(rest, end)
	if j < 0 {
		return "", false
	}
	return rest[:j], true
}

// plainText strips tags (each becomes a space so ids in neighbouring elements
// don't run together) and then decodes entities.
func plainText(s string) string {
	return html.UnescapeString(tagRe.ReplaceAllString(s, " "))
}

// oneLine collapses whitespace and trims.
func oneLine(s string) string {
	return strings.TrimSpace(spaceRe.ReplaceAllString(s, " "))
}

// ParseMessage reads one seclists.org message page.
func ParseMessage(page []byte) (*Message, error) {
	s := string(page)
	head, ok := section(s, mHeadBegin, mHeadEnd)
	if !ok {
		return nil, ErrNotMessage
	}
	body, ok := section(s, mBodyBegin, mBodyEnd)
	if !ok {
		return nil, ErrNotMessage
	}
	m := &Message{}
	if subj, ok := section(s, mSubjectBegin, mSubjectEnd); ok {
		// the subject header holds <h1>subject</h1><hr>
		m.Subject = oneLine(plainText(subj))
	}
	if m.Subject == "" {
		if mm := metaSubjRe.FindStringSubmatch(s); mm != nil {
			m.Subject = oneLine(html.UnescapeString(mm[1]))
		}
	}
	for _, f := range headLineRe.FindAllStringSubmatch(head, -1) {
		val := oneLine(plainText(f[2]))
		switch strings.ToLower(f[1]) {
		case "from":
			m.Author = displayName(val)
		case "date":
			if t, err := mail.ParseDate(val); err == nil {
				u := t.UTC()
				m.Date = &u
			}
		}
	}
	refs, _ := section(s, mRefsBegin, mRefsEnd)
	m.IsReply = replyRe.MatchString(m.Subject) || strings.TrimSpace(plainText(refs)) != ""

	if len(body) > BodyScanBytes {
		body = body[:BodyScanBytes]
	}
	text := m.Subject + "\n" + plainText(body)
	m.CVEs = xposts.ExtractCVEs(text)
	m.GHSAs = xposts.ExtractGHSAs(text)
	m.SubjectIDs = append(xposts.ExtractCVEs(m.Subject), xposts.ExtractGHSAs(m.Subject)...)
	return m, nil
}

// displayName turns a From value like `Jane Doe <jane () example org>` into
// "Jane Doe". Anything that still looks like an address is dropped: we never
// keep e-mail addresses, obfuscated or not.
func displayName(from string) string {
	name := from
	if i := strings.Index(name, "<"); i >= 0 {
		name = name[:i]
	}
	name = strings.TrimSpace(name)
	name = strings.Trim(name, `"' `)
	name = strings.TrimSpace(name)
	if name == "" || strings.Contains(name, "@") || obfuscRe.MatchString(name) {
		return ""
	}
	if len([]rune(name)) > 200 {
		name = string([]rune(name)[:200])
	}
	return name
}

// ParseIndex returns the message numbers linked from a quarter index page,
// ascending and deduplicated. The thread index lists them in thread order,
// so the order on the page means nothing.
func ParseIndex(page []byte) []int {
	seen := map[int]bool{}
	var out []int
	for _, m := range indexRe.FindAllStringSubmatch(string(page), -1) {
		if m[1] != m[2] {
			continue
		}
		n, err := strconv.Atoi(m[1])
		if err != nil || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}
