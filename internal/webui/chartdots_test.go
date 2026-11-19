package webui

import (
	"math/rand"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
)

func dayT(s string) time.Time {
	t, _ := time.Parse(time.DateOnly, s)
	return t
}

// TestResourceWhen: a repository's creation day (a ring when unverified),
// else the page's stated publication time, else the first-mentioned day as
// a ring; nothing without any of them.
func TestResourceWhen(t *testing.T) {
	pub := time.Date(2026, 11, 6, 10, 0, 0, 0, time.FixedZone("x", 3600))
	cases := []struct {
		r        site.Resource
		at, prec string
		ring     bool
	}{
		{site.Resource{Repo: &site.ResourceRepo{Created: "2026-11-05"}, FirstMentioned: "2026-11-07"}, "2026-11-05T00:00:00Z", "day", false},
		{site.Resource{Repo: &site.ResourceRepo{Created: "2026-11-05", Unverified: true}}, "2026-11-05T00:00:00Z", "day", true},
		{site.Resource{Repo: &site.ResourceRepo{}, FirstMentioned: "2026-11-07"}, "2026-11-07T00:00:00Z", "day", true},
		{site.Resource{Published: &pub, PublishedPrecision: "exact", FirstMentioned: "2026-11-07"}, "2026-11-06T09:00:00Z", "exact", false},
		{site.Resource{Published: &pub, PublishedPrecision: "day"}, "2026-11-06T09:00:00Z", "day", false},
		{site.Resource{Published: &pub, PublishedPrecision: "bogus", FirstMentioned: "2026-11-07"}, "2026-11-07T00:00:00Z", "day", true},
		{site.Resource{FirstMentioned: "2026-11-07"}, "2026-11-07T00:00:00Z", "day", true},
		{site.Resource{}, "", "", false},
	}
	for i, c := range cases {
		at, prec, ring := resourceWhen(c.r)
		got := ""
		if !at.IsZero() {
			got = at.Format(time.RFC3339)
		}
		if got != c.at || prec != c.prec || ring != c.ring {
			t.Errorf("%d: %s %s %v, want %s %s %v", i, got, prec, ring, c.at, c.prec, c.ring)
		}
	}
}

func dotsFixture() (*ResourcesView, *ResearchView) {
	rv := &ResourcesView{Groups: []ResourceGroup{
		{Kind: "poc", Links: []ResourceLink{
			{URL: "https://github.com/o/early", Text: "github.com/o/early", Repo: "o/early", When: dayT("2026-11-01"), Precision: "day"}, // before disclosure
			{URL: "https://github.com/o/poc", Text: "github.com/o/poc", Repo: "o/poc", When: dayT("2026-11-08"), Precision: "day", NotAfter: true, Unverified: true},
			{URL: "https://poc.example/x", Text: "poc.example/x", When: dayT("2026-11-10"), Precision: "day", NotAfter: true},
		}},
		{Kind: "patch", Links: []ResourceLink{
			{URL: "https://github.com/o/r/commit/abc", Text: "github.com/o/r/commit/abc", Title: "Fix <it>", When: time.Date(2026, 11, 6, 10, 0, 0, 0, time.UTC), Precision: "exact"},
			{URL: "https://no.example/time", Text: "no.example/time"}, // no time: not drawn
		}},
		{Kind: "advisory", Links: []ResourceLink{
			{URL: "https://adv.example/1", Text: "adv.example/1", Title: "Advisory one", When: dayT("2026-11-07"), Precision: "day"},
		}},
		{Kind: "other", Links: []ResourceLink{
			{URL: "https://blog.example/a", Text: "blog.example/a", Title: "Write-up", When: dayT("2026-11-07"), Precision: "day", NotAfter: true},
		}},
	}}
	rsch := &ResearchView{Entries: []ResearchShape{
		{Author: "alice", AuthorURL: "https://x.com/alice", Day: "2026-11-12"},
		{Day: "2026-11-12"},
		{Author: "bob", AuthorURL: "https://x.com/bob", Day: "2026-11-05"},
		{Author: "bad", Day: "not a day"},
	}}
	return rv, rsch
}

// TestChartDots: placement by type on the existing rows, rings and solid
// dots, merging of one day, pre-disclosure repositories and items without
// a time left out, the popover lines and the accessible names.
func TestChartDots(t *testing.T) {
	now := time.Date(2026, 11, 13, 2, 30, 0, 0, time.UTC)
	l := loc(t, "en")
	rv, rsch := dotsFixture()
	items := ChartItems(rv, rsch)
	if len(items) != 9 { // 6 links with a time, 3 posts with a day
		t.Fatalf("%d items: %+v", len(items), items)
	}
	plain := BuildChart(l, gpuDetail(), now)
	c := BuildChart(l, gpuDetail(), now, items...)
	if !c.Scale.Start.Equal(plain.Scale.Start) || len(c.Rows) != 6 {
		t.Errorf("scale moved by items after the earliest event: %v vs %v", c.Scale.Start, plain.Scale.Start)
	}
	for i := range c.Rows {
		if c.Rows[i].Aria != plain.Rows[i].Aria || len(c.Rows[i].Marks) != len(plain.Rows[i].Marks) {
			t.Errorf("row %s changed: %q", c.Rows[i].Code, c.Rows[i].Aria)
		}
	}
	byCode := map[string][]ChartDot{}
	for _, r := range c.Rows {
		byCode[r.Code] = r.Dots
	}
	if d := byCode["PAT"]; len(d) != 1 || d[0].Type != "pat" || d[0].Ring || d[0].N != 1 || d[0].Href != "#resources" ||
		d[0].Lines[0].Text != "Fix <it>" || d[0].Lines[0].Kind != "Patches" || d[0].Lines[0].Date != "2026-11-06" ||
		d[0].Label != "Patches, 2026-11-06" {
		t.Errorf("PAT dots %+v", d)
	}
	// advisory (solid) and article (ring) of one day: one solid dot
	if d := byCode["ANA"]; len(d) != 1 || d[0].Type != "art" || d[0].Ring || d[0].N != 2 || len(d[0].Lines) != 2 ||
		d[0].Lines[1].Date != "≤ 2026-11-07" || d[0].Lines[1].Kind != "Articles and other links" ||
		d[0].Label != "Advisories, Articles and other links, 2, 2026-11-07–≤ 2026-11-07" {
		t.Errorf("ANA dots %+v", d)
	}
	// the repository created before the disclosure is left out; the
	// unverified one and the first-mentioned link are rings
	if d := byCode["POC"]; len(d) != 2 || !d[0].Ring || !d[1].Ring || d[0].Lines[0].Text != "o/poc" || d[1].Lines[0].Text != "poc.example/x" ||
		pctOf(d[0].X) >= pctOf(d[1].X) {
		t.Errorf("POC dots %+v", d)
	}
	for _, code := range []string{"DIS", "ITW", "KEV"} {
		if len(byCode[code]) != 0 {
			t.Errorf("%s has dots", code)
		}
	}
	// posts: one dot per UTC day, on the header
	p := c.PostDots
	if len(p) != 2 || p[0].N != 1 || p[1].N != 2 || p[1].Ring || p[0].FY != "-7" || p[1].Href != "#research" ||
		p[1].Lines[0].Text != "alice" || !p[1].Lines[0].At || p[1].Lines[0].URL != "https://x.com/alice" || p[1].Lines[0].RI != 0 ||
		p[1].Lines[1].Text != "researcher" || p[1].Lines[1].At || p[1].Lines[1].URL != "" || p[1].Lines[1].RI != 1 || p[1].Lines[1].Day != "2026-11-12" ||
		p[0].Lines[0].RI != 2 || p[1].Label != "Researcher discussion, 2, 2026-11-12" {
		t.Errorf("post dots %+v", p)
	}
	// every dot once in Dots, unique ids
	ids := map[string]bool{}
	for _, d := range c.Dots {
		ids[d.ID] = true
	}
	if len(c.Dots) != 6 || len(ids) != 6 {
		t.Errorf("%d dots, %d ids", len(c.Dots), len(ids))
	}
	if got := BuildChart(l, gpuDetail(), now, ChartItems(nil, nil)...); len(got.Dots) != 0 || len(got.PostDots) != 0 {
		t.Errorf("dots without items: %+v", got.Dots)
	}
}

// TestChartDotsScaleCap: items may move the start of the axis back by at
// most MaxDotLead; earlier ones are not drawn.
func TestChartDotsScaleCap(t *testing.T) {
	now := time.Date(2026, 11, 13, 2, 30, 0, 0, time.UTC)
	l := loc(t, "en")
	dis := *gpuDetail().Slots[0].At
	in := ChartItem{Type: dotArt, Kind: "other", At: dis.Add(-20 * 24 * time.Hour), Precision: "day", NotAfter: true, Text: "t", URL: "https://a.example/"}
	out := ChartItem{Type: dotPat, Kind: "patch", At: dis.Add(-MaxDotLead - time.Hour), Precision: "exact", Text: "t", URL: "https://b.example/"}
	c := BuildChart(l, gpuDetail(), now, in, out)
	if c.Scale.Start.After(in.At) || len(c.Rows[2].Dots) != 1 || len(c.Rows[1].Dots) != 0 {
		t.Errorf("start %v, ANA %+v, PAT %+v", c.Scale.Start, c.Rows[2].Dots, c.Rows[1].Dots)
	}
	plain := BuildChart(l, gpuDetail(), now)
	if c2 := BuildChart(l, gpuDetail(), now, out); !c2.Scale.Start.Equal(plain.Scale.Start) || len(c2.Dots) != 0 {
		t.Errorf("an item beyond the cap moved the axis: %v", c2.Scale.Start)
	}
	// the stage marks are still where the scale puts them
	if c.Rows[0].Marks[0].X != pctAttr(c.Scale.Pct(dis)) {
		t.Errorf("DIS mark %s", c.Rows[0].Marks[0].X)
	}
}

// TestChartDotsCluster: marks of one lane closer than needPx at the
// narrowest plot merge (on a long axis, days apart); farther ones do not; a popover
// lists at most MaxDotLines items and counts the rest.
func TestChartDotsCluster(t *testing.T) {
	now := time.Date(2026, 11, 13, 2, 30, 0, 0, time.UTC)
	l := loc(t, "en")
	old := gpuDetail()
	at := time.Date(2014, 3, 2, 14, 0, 0, 0, time.UTC)
	old.Events[0].EffectiveAt, old.Events[0].OccurredAt = &at, &at
	old.Slots[0].At = &at
	var items []ChartItem
	for i := 0; i < 3; i++ { // 2016-01-01, -03, -05: < 1px apart on a 12-year axis
		items = append(items, ChartItem{Type: dotPoC, Kind: "poc", At: time.Date(2016, 1, 1+2*i, 0, 0, 0, 0, time.UTC), Precision: "day",
			Text: "p" + strconv.Itoa(i), URL: "https://p.example/" + strconv.Itoa(i)})
	}
	items = append(items, ChartItem{Type: dotPoC, Kind: "poc", At: time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC), Precision: "day", Text: "far", URL: "https://f.example/"})
	c := BuildChart(l, old, now, items...)
	d := c.Rows[3].Dots
	if len(d) != 2 || d[0].N != 3 || d[1].N != 1 || Px(pctOf(d[1].X)-pctOf(d[0].X)) < needPx(3, 1) {
		t.Errorf("long axis: %+v", d)
	}
	// short axis: two days apart is wider than a dot: not merged
	c = BuildChart(l, gpuDetail(), now,
		ChartItem{Type: dotPoC, Kind: "poc", At: dayT("2026-11-06"), Precision: "day", Text: "a", URL: "https://a.example/"},
		ChartItem{Type: dotPoC, Kind: "poc", At: dayT("2026-11-08"), Precision: "day", Text: "b", URL: "https://b.example/"})
	if d := c.Rows[3].Dots; len(d) != 2 {
		t.Errorf("short axis: %+v", d)
	}
	// one day, 8 items: 6 lines and 2 more
	items = nil
	for i := 0; i < 8; i++ {
		items = append(items, ChartItem{Type: dotArt, Kind: "other", At: time.Date(2026, 11, 7, i, 0, 0, 0, time.UTC), Precision: "exact",
			Text: "t" + strconv.Itoa(i), URL: "https://t.example/" + strconv.Itoa(i)})
	}
	c = BuildChart(l, gpuDetail(), now, items...)
	if d := c.Rows[2].Dots; len(d) != 1 || d[0].N != 8 || len(d[0].Lines) != MaxDotLines || d[0].More != 2 ||
		d[0].Lines[0].Text != "t0" || !strings.HasSuffix(d[0].Label, ", 8, 2026-11-07") {
		t.Errorf("cap: %+v", d)
	}
}

// TestBubbleSizes: a single item is a plain 12px dot; a bubble grows in
// steps by its count; its hit box is at least dotHitPx and leaves dotGapPx
// around the mark.
func TestBubbleSizes(t *testing.T) {
	for _, c := range []struct {
		n    int
		px   float64
		cls  string
		hitP float64
	}{{1, 12, "", 24}, {2, 18, "b2", 24}, {9, 18, "b2", 24}, {10, 22, "b3", 26}, {99, 22, "b3", 26}, {100, 26, "b4", 30}, {5000, 26, "b4", 30}} {
		if bubblePx(c.n) != c.px || bubbleClass(c.n) != c.cls || hitPx(c.n) != c.hitP {
			t.Errorf("%d: %v %q %v, want %v %q %v", c.n, bubblePx(c.n), bubbleClass(c.n), hitPx(c.n), c.px, c.cls, c.hitP)
		}
	}
}

// liveDetail is gpuDetail disclosed 28 days before now: a day is about as
// wide as on the live page that asked for lanes (30px at a 910px plot).
func liveDetail(now time.Time) *site.VulnDetail {
	v := gpuDetail()
	at := now.Add(-28 * 24 * time.Hour)
	v.Events[0].EffectiveAt, v.Events[0].OccurredAt = &at, &at
	v.Slots[0].At = &at
	return v
}

// pocItems are n PoC links on day (kind poc), named from i.
func pocItems(day time.Time, n, i int) []ChartItem {
	var out []ChartItem
	for k := 0; k < n; k++ {
		out = append(out, ChartItem{Type: dotPoC, Kind: "poc", At: day, Precision: "day", Repo: true,
			Text: "o/r" + strconv.Itoa(i+k), URL: "https://github.com/o/r" + strconv.Itoa(i+k)})
	}
	return out
}

// TestChartDotsLane: only rows with dots get a lane; lane marks sit at
// laneFY, bubbles carry their size class; a PoC mark links to the paged PoC
// list, a mark of code links only to the resources; the shape of the live
// page (47, 16, 4, 1, 2, 1 items on consecutive days, then 2 and 1 days
// later: eight marks of one UTC day each, about 19px apart at PlotMinPx)
// becomes five marks that do not overlap — the closest neighbours merge
// first (47+16, 4+1, 2+1) — a merged one named by its date range.
func TestChartDotsLane(t *testing.T) {
	now := time.Date(2026, 11, 13, 2, 30, 0, 0, time.UTC)
	l := loc(t, "en")
	v := liveDetail(now)
	d0 := dayFloor(now.Add(-20 * 24 * time.Hour))
	var items []ChartItem
	i := 0
	for k, n := range []int{47, 16, 4, 1, 2, 1} {
		items = append(items, pocItems(d0.AddDate(0, 0, k), n, i)...)
		i += n
	}
	items = append(items, pocItems(d0.AddDate(0, 0, 10), 2, i)...)
	items = append(items, pocItems(d0.AddDate(0, 0, 17), 1, i+2)...)
	c := BuildChart(l, v, now, items...)
	var poc ChartRow
	for _, r := range c.Rows {
		if r.Lane != (len(r.Dots) > 0) {
			t.Errorf("%s: lane %v with %d dots", r.Code, r.Lane, len(r.Dots))
		}
		if r.Code == "POC" {
			poc = r
		}
	}
	if !poc.Lane {
		t.Fatal("POC row without a lane")
	}
	// before: one mark per UTC day (8); now five
	if px := Px(c.Scale.Pct(d0.AddDate(0, 0, 1)) - c.Scale.Pct(d0)); px < 15 || px > 25 {
		t.Errorf("a day is %.1fpx at %vpx, not like the live page", px, PlotMinPx)
	}
	d := poc.Dots
	if len(d) != 5 || d[0].N != 63 || d[1].N != 5 || d[2].N != 3 || d[3].N != 2 || d[4].N != 1 ||
		d[0].Size != "b3" || d[1].Size != "b2" || d[2].Size != "b2" || d[3].Size != "b2" || d[4].Size != "" {
		for _, x := range d {
			t.Logf("%s n=%d %s", x.X, x.N, x.Size)
		}
		t.Fatalf("%d marks", len(d))
	}
	for _, x := range d {
		if x.FY != laneFY || x.Href != "#"+PoCRegion || x.Type != dotPoC {
			t.Errorf("mark %+v", x)
		}
	}
	from, to := d0.Format(time.DateOnly), d0.AddDate(0, 0, 1).Format(time.DateOnly)
	if d[0].Label != "PoC / exploit code, 63, "+from+"–"+to || len(d[0].Lines) != MaxDotLines || d[0].More != 63-MaxDotLines {
		t.Errorf("merged mark %q, %d lines, %d more", d[0].Label, len(d[0].Lines), d[0].More)
	}
	if d[4].Label != "PoC / exploit code, "+d0.AddDate(0, 0, 17).Format(time.DateOnly) {
		t.Errorf("single mark %q", d[4].Label)
	}
	// code links only: the mark links to the resources
	code := BuildChart(l, v, now, ChartItem{Type: dotPoC, Kind: "code", At: d0, Precision: "day", Text: "c", URL: "https://c.example/"})
	if dd := code.Rows[3].Dots; len(dd) != 1 || dd[0].Href != "#resources" || dd[0].Size != "" {
		t.Errorf("code mark %+v", dd)
	}
	// the header's posts keep their rule and no size
	for _, p := range c.PostDots {
		if p.Size != "" || p.FY != "-7" {
			t.Errorf("post %+v", p)
		}
	}
}

// TestChartDotsNoOverlap: for random item sets on random axes, no two marks
// of a lane come closer at PlotMinPx than needPx (so neither their hit boxes
// nor the marks themselves, with dotGapPx between, overlap), and every
// drawable item is in exactly one mark.
func TestChartDotsNoOverlap(t *testing.T) {
	l := loc(t, "en")
	rng := rand.New(rand.NewSource(1))
	kinds := []string{"poc", "code", "patch", "advisory", "other"}
	for round := 0; round < 300; round++ {
		now := time.Date(2026, 11, 13, rng.Intn(24), 0, 0, 0, time.UTC)
		span := []int{3, 10, 28, 90, 400, 3000}[rng.Intn(6)]
		v := liveDetail(now)
		at := now.Add(-time.Duration(span) * 24 * time.Hour)
		v.Events[0].EffectiveAt, v.Events[0].OccurredAt = &at, &at
		v.Slots[0].At = &at
		var items []ChartItem
		n := 1 + rng.Intn(200)
		for k := 0; k < n; k++ {
			kind := kinds[rng.Intn(len(kinds))]
			when := at.Add(time.Duration(rng.Int63n(int64(now.Sub(at)) + 1)))
			prec := "day"
			if rng.Intn(3) == 0 {
				prec = "exact"
			}
			items = append(items, ChartItem{Type: dotTypeOf(kind), Kind: kind, At: when, Precision: prec, NotAfter: rng.Intn(2) == 0,
				Text: "t" + strconv.Itoa(k), URL: "https://e.example/" + strconv.Itoa(k)})
		}
		c := BuildChart(l, v, now, items...)
		total := 0
		for _, r := range c.Rows {
			for j, d := range r.Dots {
				total += d.N
				if d.Size != bubbleClass(d.N) || d.FY != laneFY {
					t.Fatalf("round %d %s: mark %+v", round, r.Code, d)
				}
				if j == 0 {
					continue
				}
				p := r.Dots[j-1]
				dist := Px(pctOf(d.X) - pctOf(p.X))
				// pctAttr rounds to 0.001%: allow that much
				if slack := dist - needPx(p.N, d.N); slack < -2*PlotMinPx/100*0.0005 {
					t.Fatalf("round %d %s: marks %d (%d items) and %d (%d items) %.3fpx apart, need %.1f", round, r.Code, j-1, p.N, j, d.N, dist, needPx(p.N, d.N))
				}
				if gap := dist - (bubblePx(p.N)+bubblePx(d.N))/2; gap < dotGapPx-0.01 {
					t.Fatalf("round %d %s: gap %.2fpx", round, r.Code, gap)
				}
			}
		}
		if total != n {
			t.Fatalf("round %d: %d items in marks, %d drawn", round, total, n)
		}
	}
}

// TestPoCPaging: the PoC group is ordered by stars (most first; links
// without a shown star count after, in their order), cut to PoCPageSize per
// page with the page clamped; the other groups are untouched.
func TestPoCPaging(t *testing.T) {
	l := loc(t, "en")
	mk := func() *ResourcesView {
		var ls []ResourceLink
		ls = append(ls, ResourceLink{URL: "https://p.example/plain1", Text: "plain1"})
		for i := 0; i < 20; i++ {
			ls = append(ls, ResourceLink{URL: "https://github.com/o/s" + strconv.Itoa(i), Repo: "o/s" + strconv.Itoa(i), Stars: (i % 7) * 10})
		}
		ls = append(ls, ResourceLink{URL: "https://github.com/o/u1", Repo: "o/u1", Unverified: true},
			ResourceLink{URL: "https://p.example/plain2", Text: "plain2"},
			ResourceLink{URL: "https://github.com/o/u2", Repo: "o/u2", Unverified: true})
		return &ResourcesView{Groups: []ResourceGroup{{Kind: "poc", Links: ls},
			{Kind: "patch", Links: []ResourceLink{{URL: "https://x.example/", Text: "x"}}}}}
	}
	href := func(n int) string { return "/p" + strconv.Itoa(n) }
	var all []string
	for page := 1; page <= 3; page++ {
		v := mk()
		v.PagePoC(l, page, href)
		g := v.Groups[0]
		want := PoCPageSize
		if page == 3 {
			want = 4
		}
		if len(g.Links) != want || g.Region != PoCRegion || g.Pager == nil || v.Groups[1].Region != "" || v.Groups[1].Pager != nil || len(v.Groups[1].Links) != 1 {
			t.Fatalf("page %d: %d links, region %q, pager %+v", page, len(g.Links), g.Region, g.Pager)
		}
		if g.Pager.Page != "page "+strconv.Itoa(page)+" of 3" {
			t.Errorf("page %d: position %q", page, g.Pager.Page)
		}
		for _, x := range g.Links {
			all = append(all, x.URL)
		}
	}
	// stars desc, ties in their order (i%7: 60 for 6, 13; 50 for 5, 12, 19; …)
	want := []string{"s6", "s13", "s5", "s12", "s19", "s4", "s11", "s18", "s3", "s10", "s17", "s2", "s9", "s16", "s1", "s8", "s15", "s0", "s7", "s14"}
	for i, w := range want {
		if !strings.HasSuffix(all[i], "/"+w) {
			t.Fatalf("order at %d: %s, want %s (%v)", i, all[i], w, all)
		}
	}
	if tail := all[20:]; len(tail) != 4 || !strings.HasSuffix(tail[0], "plain1") || !strings.HasSuffix(tail[1], "/u1") ||
		!strings.HasSuffix(tail[2], "plain2") || !strings.HasSuffix(tail[3], "/u2") {
		t.Errorf("unstarred tail %v", tail)
	}
	// clamped: past the end is the last page, below 1 the first
	for _, c := range []struct{ in, first string }{{"99", "https://p.example/plain1"}, {"0", "https://github.com/o/s6"}, {"x", "https://github.com/o/s6"}, {"-3", "https://github.com/o/s6"}, {"", "https://github.com/o/s6"}} {
		v := mk()
		v.PagePoC(l, pocPage(c.in), href)
		if v.Groups[0].Links[0].URL != c.first {
			t.Errorf("pocp=%q: first %s", c.in, v.Groups[0].Links[0].URL)
		}
	}
	// one page: a region, no pager
	v := &ResourcesView{Groups: []ResourceGroup{{Kind: "poc", Links: []ResourceLink{{URL: "https://a.example/"}}}}}
	v.PagePoC(l, 1, href)
	if v.Groups[0].Region != PoCRegion || v.Groups[0].Pager != nil {
		t.Errorf("one page: %+v", v.Groups[0])
	}
	var nilView *ResourcesView
	nilView.PagePoC(l, 2, href) // no resources: nothing to do
}

// TestPoCHref: page links keep the page's other query parameters (not the
// throw-away fresh=), carry pocp from page 2 and end in the region's id.
func TestPoCHref(t *testing.T) {
	q := url.Values{"c": {"12"}, "thread": {"t1"}, "cursor": {"a b"}, "pocp": {"4"}, "fresh": {"9"}}
	h := pocHref(loc(t, "en"), "CVE-2026-1", q)
	if got := h(1); got != "/vuln/CVE-2026-1?c=12&cursor=a+b&thread=t1#r-poc" {
		t.Errorf("page 1: %s", got)
	}
	if got := h(3); got != "/vuln/CVE-2026-1?c=12&cursor=a+b&pocp=3&thread=t1#r-poc" {
		t.Errorf("page 3: %s", got)
	}
	if got := pocHref(loc(t, "ja"), "CVE-2026-1", nil)(2); got != "/ja/vuln/CVE-2026-1?pocp=2#r-poc" {
		t.Errorf("ja: %s", got)
	}
}
