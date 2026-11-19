package webui

import (
	"bytes"
	"context"
	"encoding/xml"
	"net/http"
	"strconv"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/tags"
	"nday.land/nday/internal/webui/i18n"
)

// Atom structures (RFC 4287). encoding/xml escapes all text and replaces
// characters that are invalid in XML.
type atomFeed struct {
	XMLName xml.Name    `xml:"http://www.w3.org/2005/Atom feed"`
	Lang    string      `xml:"http://www.w3.org/XML/1998/namespace lang,attr"`
	ID      string      `xml:"id"`
	Title   string      `xml:"title"`
	Sub     string      `xml:"subtitle"`
	Updated string      `xml:"updated"`
	Links   []atomLink  `xml:"link"`
	Author  atomAuthor  `xml:"author"`
	Entries []atomEntry `xml:"entry"`
}

type atomLink struct {
	Rel  string `xml:"rel,attr,omitempty"`
	Type string `xml:"type,attr,omitempty"`
	Href string `xml:"href,attr"`
}

type atomAuthor struct {
	Name string `xml:"name"`
}

type atomText struct {
	Type string `xml:"type,attr"`
	Body string `xml:",chardata"`
}

type atomEntry struct {
	ID       string    `xml:"id"`
	Title    string    `xml:"title"`
	Updated  string    `xml:"updated"`
	Link     atomLink  `xml:"link"`
	Category []atomCat `xml:"category"`
	Summary  atomText  `xml:"summary"`
}

type atomCat struct {
	Term string `xml:"term,attr"`
}

// FeedEntryID is the stable id of a transition entry: the same CVE entering
// the same stage at the same instant always has the same id.
func FeedEntryID(r site.HotRow) string {
	return "tag:nday.land,2026:transition/" + r.CVEID + "/" + r.Transition.Code + "/" +
		strconv.FormatInt(r.Transition.At.UTC().Unix(), 10)
}

// BuildFeed renders the Atom document of a hot page in locale l.
func BuildFeed(l *i18n.Locale, page *site.HotPage, baseURL string, now time.Time) ([]byte, error) {
	self := baseURL + l.Path("/feed.xml")
	title, home := l.Text("feed.title"), baseURL+l.Home()
	if len(page.Tags) > 0 {
		// a tag-filtered feed (?tag=): its own id, title and list page
		self += "?" + tagQuery(page.Tags)
		title = l.Text("tag.feed.title", "tags", tagLabels(l, page.Tags))
		f := HotFilters{Since: defaultSince, MinStage: defaultMinStage, Fixed: page.Tags[0], Tags: page.Tags[1:]}
		home = baseURL + l.Path(f.Href(false))
	}
	f := atomFeed{Lang: l.Tag, ID: self, Title: title, Sub: l.Text("feed.subtitle"),
		Links:  []atomLink{{Rel: "self", Type: "application/atom+xml", Href: self}, {Rel: "alternate", Type: "text/html", Href: home}},
		Author: atomAuthor{Name: "nday.land"}}
	updated := time.Time{}
	for _, r := range page.Rows {
		at := r.Transition.At.UTC()
		if at.After(updated) {
			updated = at
		}
		title, _, _, _ := rowTitle(l, r.TitleZh, r.Title, r.TitleInfo, slotsRecord(r.Slots))
		vendor, _ := ProductLine(l, r.Products, r.ProductCount, 2)
		stage := r.Transition.Code
		if !knownStage(stage) {
			stage = "other"
		}
		sum := []string{l.Text("feed.summary.change", "stage", stage, "change", "+"+r.Transition.Code,
			"time", FormatAt(l, &at, r.Transition.Precision), "precision", PrecisionNote(l, r.Transition.Precision))}
		if vendor != "" {
			sum = append(sum, l.Text("feed.summary.products", "products", vendor))
		}
		sum = append(sum, l.Text("feed.summary.tplus", "tplus", FormatTPlus(r.DaysSinceDisclosure),
			"poc", strconv.Itoa(r.PocSources)+"/"+strconv.Itoa(len(site.PocSourceNames))))
		f.Entries = append(f.Entries, atomEntry{
			ID:       FeedEntryID(r),
			Title:    "+" + r.Transition.Code + " " + r.CVEID + " " + truncRunes(title, 140),
			Updated:  at.Format(time.RFC3339),
			Link:     atomLink{Rel: "alternate", Type: "text/html", Href: baseURL + l.Path("/vuln/"+r.CVEID)},
			Category: []atomCat{{Term: r.Transition.Code}},
			Summary:  atomText{Type: "text", Body: l.Join(sum)},
		})
	}
	if updated.IsZero() {
		updated = now.UTC().Truncate(time.Hour)
	}
	f.Updated = updated.Format(time.RFC3339)
	var buf bytes.Buffer
	buf.WriteString(xml.Header)
	enc := xml.NewEncoder(&buf)
	enc.Indent("", "  ")
	if err := enc.Encode(f); err != nil {
		return nil, err
	}
	buf.WriteByte('\n')
	return buf.Bytes(), nil
}

func (u *UI) feed(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	ts, _ := tags.ParseFilter(r.URL.Query()["tag"]) // ?tag= (repeatable); unknown slugs are ignored
	p, err := site.HotParams{Since: defaultSince, MinStage: defaultMinStage, Limit: 50, Tags: ts, NoPins: true}.Normalize()
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	v, err := u.cached(r.Context(), "feed|"+loc.Tag+"|"+u.srv.Store.HotCacheKey(p), func(ctx context.Context) (any, error) {
		page, err := u.srv.Store.Hot(ctx, p)
		if err != nil {
			return nil, err
		}
		return BuildFeed(loc, page, u.opts.BaseURL, u.opts.Now())
	})
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	body := v.([]byte)
	h := w.Header()
	h.Set("Content-Type", "application/atom+xml; charset=utf-8")
	// personal: reached only through web.Gate (session, API token or the
	// private feed key), so no shared cache may keep it. The body itself is
	// the same for everyone (the in-process cache key has no credential).
	h.Set("Cache-Control", "private, no-store")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
