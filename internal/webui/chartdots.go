package webui

import (
	"sort"
	"strconv"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
	"nday.land/nday/internal/xlinks"
)

// Dots on the lifecycle chart (docs/webpages.md "Dots on the lifecycle
// chart"): the external items of the page — the resources' links
// (resources.go) and the researcher posts' public outline (discussion.go)
// — drawn at their time on the existing rows, without new rows:
// analysis articles, advisories and other links on ANA, the PoC links that
// count on POC (ChartItems), patch links on PAT, researcher posts on the
// lower edge of the date-axis header. A solid dot is a stated time (a page's
// publication time, a post's day, a repository's creation day), a ring an
// upper bound ("not after": the day a researcher first posted the link, or
// the creation day of an unverified repository). A row with dots gets a
// lane of its own under its stage marks (ChartRow.Lane); there the items of
// one UTC day are one mark, and neighbouring marks merge until no two hit
// boxes overlap at the narrowest plot width (rowGroups). A mark of several
// items is a bubble with the count inside, sized in steps by the count
// (bubblePx). Researcher posts on the header keep their own rule (same UTC
// day, or closer than postMergePx: one triangle with a count beside it). The
// page is the same for every visitor: only data that is public anyway is
// drawn (site/public.go).

// Dot types (CSS classes d-<type>, one colour each).
const (
	dotPost = "post"
	dotArt  = "art"
	dotPoC  = "poc"
	dotPat  = "pat"
)

const (
	// postMergePx: researcher posts on the header closer than this at
	// PlotMinPx merge into one triangle.
	postMergePx = 8.0
	// dotGapPx is the least gap between two marks of a lane, dotHitPx the
	// least side of a mark's hit box (desktop; app.css: 32px on phones), at
	// PlotMinPx.
	dotGapPx = 4.0
	dotHitPx = 24.0
	// laneFY is the y of a lane mark's box in its row (app.css "lane").
	laneFY = "34"
	// MaxDotLines caps the lines of a dot's popover; the rest is one link
	// to the section that lists everything.
	MaxDotLines = 6
	// MaxDotLead: external items may start the axis at most this much
	// before the earliest event; earlier ones are not drawn.
	MaxDotLead = 30 * 24 * time.Hour
)

// dotRowOf is the stage row of a resource kind's dots.
var dotRowOf = map[string]string{dotArt: "ANA", dotPoC: "POC", dotPat: "PAT"}

// dotTypeOf is the dot type of a resource kind.
func dotTypeOf(kind string) string {
	switch kind {
	case xlinks.KindPoC, xlinks.KindCode:
		return dotPoC
	case xlinks.KindPatch:
		return dotPat
	}
	return dotArt
}

// ChartItem is one external item the chart may draw.
type ChartItem struct {
	Type      string    // dotPost | dotArt | dotPoC | dotPat
	Kind      string    // site.ResourceKinds ("" for a post)
	At        time.Time // zero = no usable time: not drawn
	Precision string    // exact | day
	NotAfter  bool      // an upper bound: drawn as a ring
	Repo      bool      // a GitHub repository (At = its creation day)
	Text      string    // shown text: the link's title (or repository name, or host+path); a post's @handle without "@" ("" = neutral name)
	URL       string    // the link; a post's author profile ("" = none)
	RI        int       // a post's index in the researcher outline (discuss.js)
}

// ChartItems lists the dots' items of a page: every resource link with a
// time, and every post of the outline (at its UTC day). The POC row holds
// only what counts: the PoC group's links. The unreviewed repositories and
// the code links (a URL alone does not make a PoC) get no dot.
func ChartItems(rv *ResourcesView, research *ResearchView) []ChartItem {
	var out []ChartItem
	if rv != nil {
		for _, g := range rv.Groups {
			if g.Unreviewed || g.Kind == xlinks.KindCode {
				continue
			}
			for _, r := range g.Links {
				if r.When.IsZero() {
					continue
				}
				text := r.Text
				switch {
				case r.Repo != "":
					text = r.Repo
				case r.Title != "":
					text = r.Title
				}
				out = append(out, ChartItem{Type: dotTypeOf(g.Kind), Kind: g.Kind, At: r.When, Precision: r.Precision,
					NotAfter: r.NotAfter, Repo: r.Repo != "", Text: text, URL: r.URL})
			}
		}
	}
	if research != nil {
		for i, e := range research.Entries {
			d, err := time.Parse(time.DateOnly, e.Day)
			if err != nil {
				continue
			}
			out = append(out, ChartItem{Type: dotPost, At: d, Precision: site.PrecisionDay, Text: e.Author, URL: e.AuthorURL, RI: i})
		}
	}
	return out
}

// ChartDot is one drawn dot (several merged items) and its popover.
type ChartDot struct {
	ID    string // id of the popover element
	X     string // SVG attribute (percentage)
	FY    string // y of the hit box (rows "0"; the header lifts it to its lower edge)
	Type  string // dot type (CSS class d-<Type>): the most frequent type of its items
	Ring  bool   // every item is an upper bound
	N     int    // items merged
	Size  string // lane marks: the bubble class by N (bubbleClass; "" = a plain dot)
	Label string // accessible name: type, count, date
	Href  string // #resources, #<PoCRegion> (holds a PoC link) or #research: the link without script, and the popover's "more"
	Lines []DotLine
	More  int // items beyond the lines
}

// DotLine is one line of a popover.
type DotLine struct {
	Kind string // the kind's label (resources); "" for a post
	Text string // title, repository or host+path; a post's handle (without "@"), or the neutral name
	URL  string // the link; a post's author profile; "" = no link
	Date string // YYYY-MM-DD, or "≤ YYYY-MM-DD" for an upper bound
	Post bool
	At   bool   // Text is a handle (shown with "@")
	RI   int    // a post's index in the outline
	Day  string // a post's day (discuss.js matches the signed-in post by it)
}

// itemX is the position of an item: a day at its middle, never right of
// "now" (today's middle may still be ahead).
func itemX(s Scale, it ChartItem) float64 {
	x := s.Pct(it.At)
	if it.Precision == site.PrecisionDay {
		x = s.Pct(dayFloor(it.At.UTC()).Add(12 * time.Hour))
	}
	return min(x, s.NowPct)
}

// dotItems keeps the drawable items: a time, not more than MaxDotLead
// before earliest, a repository not created before the disclosure day
// (disclosed nil = unknown: kept).
func dotItems(items []ChartItem, earliest time.Time, disclosed *time.Time) []ChartItem {
	var out []ChartItem
	min := earliest.Add(-MaxDotLead)
	for _, it := range items {
		at := it.At
		if at.IsZero() || at.Before(min) {
			continue
		}
		if it.Repo && disclosed != nil && at.Before(dayFloor(disclosed.UTC())) {
			continue
		}
		out = append(out, it)
	}
	return out
}

// dotDate is an item's date in a popover.
func dotDate(l *i18n.Locale, it ChartItem) string {
	if it.NotAfter {
		at := it.At
		return FormatNotAfter(l, &at)
	}
	return it.At.UTC().Format(layoutDate)
}

// bubblePx is the diameter of a lane mark of n items at every plot width
// (app.css "lane"): a plain dot, or a bubble with the count inside.
func bubblePx(n int) float64 {
	switch {
	case n <= 1:
		return 12
	case n < 10:
		return 18
	case n < 100:
		return 22
	}
	return 26
}

// bubbleClass is the CSS class of a lane mark of n items ("" = a plain dot).
func bubbleClass(n int) string {
	switch {
	case n <= 1:
		return ""
	case n < 10:
		return "b2"
	case n < 100:
		return "b3"
	}
	return "b4"
}

// hitPx is the side of a lane mark's hit box on desktop (app.css): at
// least dotHitPx, and dotGapPx/2 around the mark on each side.
func hitPx(n int) float64 { return max(dotHitPx, bubblePx(n)+dotGapPx) }

// needPx is the least distance at PlotMinPx between the centres of two
// neighbouring lane marks of a and b items: their hit boxes do not overlap,
// which also keeps at least dotGapPx between the marks themselves.
func needPx(a, b int) float64 {
	return max((hitPx(a)+hitPx(b))/2, (bubblePx(a)+bubblePx(b))/2+dotGapPx)
}

// laneGroup is a lane mark being formed: its items in time order and the
// span of their positions (pixels at PlotMinPx).
type laneGroup struct {
	items  []ChartItem
	x0, x1 float64
}

func (g laneGroup) centre() float64 { return (g.x0 + g.x1) / 2 }

// rowGroups groups one lane's items (sorted by time): one group per UTC day,
// then, while two neighbours are closer than needPx, the closest pair (the
// least slack) merges, so no two marks of the lane overlap at PlotMinPx (or
// at any wider plot).
func rowGroups(s Scale, items []ChartItem) []laneGroup {
	var gs []laneGroup
	for _, it := range items {
		x := Px(itemX(s, it))
		if n := len(gs); n > 0 && dayFloor(gs[n-1].items[0].At.UTC()).Equal(dayFloor(it.At.UTC())) {
			gs[n-1].items = append(gs[n-1].items, it)
			gs[n-1].x1 = max(gs[n-1].x1, x)
			continue
		}
		gs = append(gs, laneGroup{items: []ChartItem{it}, x0: x, x1: x})
	}
	for {
		best, slack := -1, 0.0
		for i := 0; i+1 < len(gs); i++ {
			d := gs[i+1].centre() - gs[i].centre() - needPx(len(gs[i].items), len(gs[i+1].items))
			if d < -1e-9 && (best < 0 || d < slack) {
				best, slack = i, d
			}
		}
		if best < 0 {
			return gs
		}
		a, b := gs[best], gs[best+1]
		gs[best] = laneGroup{items: append(append([]ChartItem{}, a.items...), b.items...), x0: min(a.x0, b.x0), x1: max(a.x1, b.x1)}
		gs = append(gs[:best+1], gs[best+2:]...)
	}
}

// postGroups groups the header's posts (sorted by time): the same UTC day,
// or closer than postMergePx to the previous one.
func postGroups(s Scale, items []ChartItem) []laneGroup {
	var gs []laneGroup
	var lastX float64
	for _, it := range items {
		x := Px(itemX(s, it))
		if n := len(gs); n > 0 {
			g := &gs[n-1]
			prev := g.items[len(g.items)-1]
			if dayFloor(prev.At.UTC()).Equal(dayFloor(it.At.UTC())) || x-lastX < postMergePx {
				g.items = append(g.items, it)
				g.x1 = x
				lastX = x
				continue
			}
		}
		gs = append(gs, laneGroup{items: []ChartItem{it}, x0: x, x1: x})
		lastX = x
	}
	return gs
}

// dominantType is the most frequent dot type of g (the first to reach
// that count on a tie).
func dominantType(g []ChartItem) string {
	n := map[string]int{}
	best := ""
	for _, it := range g {
		n[it.Type]++
		if best == "" || n[it.Type] > n[best] {
			best = it.Type
		}
	}
	return best
}

// clusterDots merges one row's items (any order) into dots, in time order:
// the header's posts (fy "-7") by postGroups, a lane's items by rowGroups.
func clusterDots(l *i18n.Locale, s Scale, items []ChartItem, seq *int, fy string) []ChartDot {
	sort.SliceStable(items, func(a, b int) bool { return items[a].At.Before(items[b].At) })
	lane := fy == laneFY
	var groups []laneGroup
	if lane {
		groups = rowGroups(s, items)
	} else {
		groups = postGroups(s, items)
	}
	var out []ChartDot
	for _, lg := range groups {
		g := lg.items
		*seq++
		d := ChartDot{ID: "cd-" + strconv.Itoa(*seq), X: pctAttr(lg.centre() / PlotMinPx * 100), FY: fy, Type: dominantType(g), Ring: true, N: len(g),
			Href: "#resources"}
		if lane {
			d.Size = bubbleClass(d.N)
		}
		switch d.Type {
		case dotPost:
			d.Href = "#research"
		case dotPoC:
			for _, it := range g {
				if it.Kind == xlinks.KindPoC {
					d.Href = "#" + PoCRegion // the paged PoC list (resources.go)
					break
				}
			}
		}
		var kinds []string
		seen := map[string]bool{}
		for i, it := range g {
			if !it.NotAfter {
				d.Ring = false
			}
			label := ""
			if it.Kind != "" {
				label = l.Text(resourceKindKeys[it.Kind])
			}
			if d.Type == dotPost {
				label = l.Text("rsch.h2")
			}
			if !seen[label] {
				seen[label] = true
				kinds = append(kinds, label)
			}
			if i >= MaxDotLines {
				d.More++
				continue
			}
			ln := DotLine{Date: dotDate(l, it), Text: it.Text, URL: it.URL}
			if it.Type == dotPost {
				ln.Post, ln.RI, ln.Day = true, it.RI, it.At.UTC().Format(time.DateOnly)
				ln.At = it.Text != ""
				if !ln.At {
					ln.Text, ln.URL = l.Text("rsch.unknown_author"), ""
				}
			} else {
				ln.Kind = label
			}
			d.Lines = append(d.Lines, ln)
		}
		date := dotDate(l, g[0])
		if last := dotDate(l, g[len(g)-1]); last != date {
			date += "–" + last
		}
		parts := kinds
		if d.N > 1 {
			parts = append(parts, l.Int(int64(d.N)))
		}
		d.Label = l.List(i18n.ListSeq, append(parts, date))
		out = append(out, d)
	}
	return out
}

// placeDots lays the drawable items out on c's rows and header.
func placeDots(l *i18n.Locale, c *Chart, items []ChartItem) {
	byType := map[string][]ChartItem{}
	for _, it := range items {
		byType[it.Type] = append(byType[it.Type], it)
	}
	seq := 0
	c.PostDots = clusterDots(l, c.Scale, byType[dotPost], &seq, "-7")
	c.Dots = append(c.Dots, c.PostDots...)
	for i := range c.Rows {
		for _, t := range []string{dotPat, dotArt, dotPoC} {
			if dotRowOf[t] != c.Rows[i].Code || len(byType[t]) == 0 {
				continue
			}
			c.Rows[i].Dots = clusterDots(l, c.Scale, byType[t], &seq, laneFY)
			c.Rows[i].Lane = len(c.Rows[i].Dots) > 0
			c.Dots = append(c.Dots, c.Rows[i].Dots...)
		}
	}
}
