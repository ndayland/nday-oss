package site_test

import (
	"errors"
	"strings"
	"testing"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
)

// Backward paging (Before / PrevCursor) on the hot list and the catalogue:
// walking back from the last page visits exactly the pages walked forwards,
// in reverse, and ends on the first page as a fresh visit shows it; next
// after previous returns the same rows; ties on the sort keys are neither
// skipped nor repeated; the filters stay applied.

// pageSig is a page's rows (with the pinned mark) and whether it links on.
func pageSig(rows []site.HotRow, next, prev *string) string {
	var b strings.Builder
	for _, r := range rows {
		b.WriteString(r.CVEID)
		if r.Pinned {
			b.WriteString("*" + r.PinReason)
		}
		b.WriteByte(',')
	}
	if next != nil {
		b.WriteString(" next=" + *next)
	}
	if prev != nil {
		b.WriteString(" prev=" + *prev)
	}
	return b.String()
}

func TestHotBackwardPaging(t *testing.T) {
	st, d, _ := seeded(t)
	fillPosts(t, pinSeeder(t, d))
	// ties: three CVEs share one transition time (see TestHotCursorCurrentStageTies)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	at, old := sitetest.Ago(1.5), sitetest.Ago(20)
	for _, c := range []string{"CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2003"} {
		s.Vuln(c, sitetest.P("tie "+c))
	}
	s.Event(sitetest.Ev{CVE: "CVE-2026-2001", Type: "kev_added", Source: "kev", Occurred: &old, Key: "k2001"})
	s.Event(sitetest.Ev{CVE: "CVE-2026-2001", Type: "patch_released", Source: "ghsa", Occurred: &at, Key: "GHSA-2001"})
	s.Event(sitetest.Ev{CVE: "CVE-2026-2002", Type: "analysis_published", Source: "x", Occurred: &at, Key: "a2002"})
	s.Event(sitetest.Ev{CVE: "CVE-2026-2003", Type: "patch_released", Source: "ghsa", Occurred: &at, Key: "GHSA-2003"})
	s.Refresh()

	for _, base := range []site.HotParams{
		{Since: 30 * day, MinStage: "disclosed"},
		{Since: 30 * day, MinStage: "patch"},
		{Since: 30 * day, MinStage: "disclosed", IncludeRejected: true},
		{Since: 30 * day, MinStage: "disclosed", NoPins: true},
	} {
		for _, limit := range []int{1, 2, 3, 5} {
			p := base
			p.Limit = limit
			fresh, err := st.Hot(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			if fresh.PrevCursor != nil {
				t.Errorf("%+v: first page has a previous page", p)
			}
			// forwards
			var fwd []*site.HotPage
			q := p
			for n := 0; ; n++ {
				if n > 60 {
					t.Fatalf("%+v: no end", p)
				}
				page, err := st.Hot(ctx, q)
				if err != nil {
					t.Fatal(err)
				}
				if n > 0 && page.PrevCursor == nil {
					t.Errorf("%+v page %d: no previous page", p, n+1)
				}
				fwd = append(fwd, page)
				if page.NextCursor == nil {
					break
				}
				q.Cursor = *page.NextCursor
			}
			if len(fwd) < 2 {
				t.Fatalf("%+v: fixture too small (%d pages)", p, len(fwd))
			}
			// backwards from the last page: the same pages, in reverse
			cur := fwd[len(fwd)-1]
			for i := len(fwd) - 2; i >= 0; i-- {
				if cur.PrevCursor == nil {
					t.Fatalf("%+v: page %d has no previous page", p, i+2)
				}
				b := p
				b.Before = *cur.PrevCursor
				back, err := st.Hot(ctx, b)
				if err != nil {
					t.Fatal(err)
				}
				want := fwd[i]
				if i > 0 {
					// a middle page: the same rows; it links on to the page it came from
					if got, w := pageSig(back.Rows, nil, nil), pageSig(want.Rows, nil, nil); got != w {
						t.Errorf("%+v back to page %d:\n got %s\nwant %s", p, i+1, got, w)
					}
					for _, r := range back.Rows {
						if r.Pinned {
							t.Errorf("%+v back to page %d: pinned %s", p, i+1, r.CVEID)
						}
					}
					if back.NextCursor == nil {
						t.Errorf("%+v back to page %d: no next", p, i+1)
					} else {
						n := p
						n.Cursor = *back.NextCursor
						again, err := st.Hot(ctx, n)
						if err != nil {
							t.Fatal(err)
						}
						if got, w := pageSig(again.Rows, nil, nil), pageSig(fwd[i+1].Rows, nil, nil); got != w {
							t.Errorf("%+v next after previous (page %d):\n got %s\nwant %s", p, i+2, got, w)
						}
					}
				} else {
					// the first page, exactly as a fresh visit (pinned rows included)
					if got, w := pageSig(back.Rows, back.NextCursor, back.PrevCursor), pageSig(fresh.Rows, fresh.NextCursor, fresh.PrevCursor); got != w {
						t.Errorf("%+v back to the first page:\n got %s\nwant %s", p, got, w)
					}
					if back.Offset != 0 || back.Pins != fresh.Pins {
						t.Errorf("%+v back to the first page: offset %d pins %d/%d", p, back.Offset, back.Pins, fresh.Pins)
					}
				}
				cur = back
			}
		}
	}
	// the tie: paged one row at a time backwards, nothing skipped or repeated
	p := site.HotParams{Since: 30 * day, MinStage: "patch", NoPins: true, Limit: 200}
	all, _ := st.Hot(ctx, p)
	if !strings.Contains(ids(all.Rows), "2001,2002,2003") {
		t.Fatalf("precondition: %s", ids(all.Rows))
	}
	p.Limit = 1
	last := p
	for {
		page, _ := st.Hot(ctx, last)
		if page.NextCursor == nil {
			break
		}
		last.Cursor = *page.NextCursor
	}
	page, _ := st.Hot(ctx, last)
	got := []string{ids(page.Rows)}
	for n := 0; page.PrevCursor != nil && n < 60; n++ {
		b := p
		b.Before = *page.PrevCursor
		page, _ = st.Hot(ctx, b)
		got = append([]string{ids(page.Rows)}, got...)
	}
	if strings.Join(got, ",") != ids(all.Rows) {
		t.Errorf("backwards one by one %q\nwant %q", strings.Join(got, ","), ids(all.Rows))
	}
}

func TestHotBeforeInput(t *testing.T) {
	st, _, _ := seeded(t)
	first, err := st.Hot(ctx, site.HotParams{Since: 30 * day, Limit: 1})
	if err != nil || first.NextCursor == nil {
		t.Fatalf("precondition: %v", err)
	}
	var ie *site.InputError
	for _, p := range []site.HotParams{
		{Before: "garbage"},
		{Before: strings.Repeat("A", 200)},
		{Before: *first.NextCursor, Cursor: *first.NextCursor},
	} {
		if _, err := st.Hot(ctx, p); !errors.As(err, &ie) || ie.Param != "before" {
			t.Errorf("%+v: %v", p, err)
		}
	}
	// a cache key per position
	a, _ := site.HotParams{Before: *first.NextCursor}.Normalize()
	b, _ := site.HotParams{Cursor: *first.NextCursor}.Normalize()
	z, _ := site.HotParams{}.Normalize()
	if a.CacheKey() == b.CacheKey() || a.CacheKey() == z.CacheKey() {
		t.Errorf("cache keys %q %q %q", a.CacheKey(), b.CacheKey(), z.CacheKey())
	}
}

func TestCatalogueBackwardPaging(t *testing.T) {
	st, _ := catSeeded(t)
	for _, base := range []site.CatalogueParams{
		{IncludeRejected: true}, {}, {Stage: "disclosed"}, {Stage: "kev"}, {Stage: "poc"}, {Stage: "patch"},
		{Year: 2014}, {Year: 2025}, {Year: 2025, Stage: "patch"}, {Year: 2014, Stage: "disclosed"}, {Tags: []string{"network"}},
	} {
		for limit := 1; limit <= 5; limit++ {
			p := base
			p.Limit = limit
			fresh, err := st.Catalogue(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			if fresh.PrevCursor != nil {
				t.Errorf("%+v: first page has a previous page", p)
			}
			var fwd []*site.CataloguePage
			q := p
			for n := 0; ; n++ {
				if n > 40 {
					t.Fatalf("%+v: no end", p)
				}
				page, err := st.Catalogue(ctx, q)
				if err != nil {
					t.Fatal(err)
				}
				if n > 0 && page.PrevCursor == nil {
					t.Errorf("%+v page %d: no previous page", p, n+1)
				}
				fwd = append(fwd, page)
				if page.NextCursor == nil {
					break
				}
				q.Cursor = *page.NextCursor
			}
			cur := fwd[len(fwd)-1]
			for i := len(fwd) - 2; i >= 0; i-- {
				if cur.PrevCursor == nil {
					t.Fatalf("%+v: page %d has no previous page", p, i+2)
				}
				b := p
				b.Before = *cur.PrevCursor
				back, err := st.Catalogue(ctx, b)
				if err != nil {
					t.Fatal(err)
				}
				if i == 0 {
					if got, w := pageSig(back.Rows, back.NextCursor, back.PrevCursor), pageSig(fresh.Rows, fresh.NextCursor, fresh.PrevCursor); got != w {
						t.Errorf("%+v back to the first page:\n got %s\nwant %s", p, got, w)
					}
				} else {
					if got, w := cids(back.Rows), cids(fwd[i].Rows); got != w {
						t.Errorf("%+v back to page %d:\n got %s\nwant %s", p, i+1, got, w)
					}
					if back.NextCursor == nil {
						t.Errorf("%+v back to page %d: no next", p, i+1)
					} else {
						n := p
						n.Cursor = *back.NextCursor
						again, _ := st.Catalogue(ctx, n)
						if got, w := cids(again.Rows), cids(fwd[i+1].Rows); got != w {
							t.Errorf("%+v next after previous (page %d):\n got %s\nwant %s", p, i+2, got, w)
						}
					}
				}
				cur = back
			}
		}
	}
	// a position from another filter (dated rows, ties and the undated tail):
	// a stage page before it holds that stage's rows before the position
	all, _ := st.Catalogue(ctx, site.CatalogueParams{})
	const limit = 2
	for at := 1; at < len(all.Rows); at++ {
		pg, _ := st.Catalogue(ctx, site.CatalogueParams{Cursor: mustNext(t, st, at)})
		if len(pg.Rows) == 0 || pg.Rows[0].CVEID != all.Rows[at].CVEID || pg.PrevCursor == nil {
			t.Fatalf("precondition at %d", at)
		}
		for _, stage := range []string{"disclosed", "patch", "poc", "kev"} {
			whole, _ := st.Catalogue(ctx, site.CatalogueParams{Stage: stage})
			var before []string
			for _, r := range whole.Rows {
				for i := 0; i < at; i++ {
					if all.Rows[i].CVEID == r.CVEID {
						before = append(before, r.CVEID)
					}
				}
			}
			got, err := st.Catalogue(ctx, site.CatalogueParams{Stage: stage, Limit: limit, Before: *pg.PrevCursor})
			if err != nil {
				t.Fatal(err)
			}
			want := before
			if len(before) <= limit {
				// nothing before those rows: the stage's first page
				first, _ := st.Catalogue(ctx, site.CatalogueParams{Stage: stage, Limit: limit})
				want = strings.Split(cids(first.Rows), ",")
			} else {
				want = before[len(before)-limit:]
			}
			if cids(got.Rows) != strings.Join(want, ",") {
				t.Errorf("before %d (%s), stage %s: got %s want %s", at, all.Rows[at].CVEID, stage, cids(got.Rows), strings.Join(want, ","))
			}
		}
	}
	// input
	var ie *site.InputError
	for _, p := range []site.CatalogueParams{{Before: "garbage"}, {Before: mustNext(t, st, 1), Cursor: mustNext(t, st, 1)}} {
		if _, err := st.Catalogue(ctx, p); !errors.As(err, &ie) || ie.Param != "before" {
			t.Errorf("%+v: %v", p, err)
		}
	}
}

// mustNext is the catalogue cursor after the first n rows (unfiltered).
func mustNext(t *testing.T, st *site.Store, n int) string {
	t.Helper()
	pg, err := st.Catalogue(ctx, site.CatalogueParams{Limit: n})
	if err != nil || pg.NextCursor == nil {
		t.Fatalf("no cursor after %d: %v", n, err)
	}
	return *pg.NextCursor
}

// The discussed ranking reports its length (for the pager's "of N").
func TestDiscussedTotal(t *testing.T) {
	st, d, _ := seeded(t)
	fillPosts(t, pinSeeder(t, d))
	all, err := st.Discussed(ctx, site.DiscussedParams{Limit: 200})
	if err != nil || len(all.Rows) < 3 {
		t.Fatalf("precondition: %v %d", err, len(all.Rows))
	}
	if all.Total != len(all.Rows) {
		t.Errorf("total %d, rows %d", all.Total, len(all.Rows))
	}
	for off := 0; off < len(all.Rows); off++ {
		pg, _ := st.Discussed(ctx, site.DiscussedParams{Limit: 1, Offset: off})
		if pg.Total != len(all.Rows) || len(pg.Rows) != 1 || pg.Rows[0].CVEID != all.Rows[off].CVEID {
			t.Errorf("offset %d: total %d rows %d", off, pg.Total, len(pg.Rows))
		}
	}
	if pg, _ := st.Discussed(ctx, site.DiscussedParams{Limit: 1, Offset: len(all.Rows)}); pg.Total != 0 || len(pg.Rows) != 0 {
		t.Errorf("past the end: total %d", pg.Total)
	}
}

// Stats.ByStageLive is ByStage without rejected CVEs.
func TestStatsByStageLive(t *testing.T) {
	st, _ := catSeeded(t)
	stats, err := st.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var live int64
	for i, c := range stats.ByStage {
		pg, _ := st.Catalogue(ctx, site.CatalogueParams{Stage: c.Stage, Limit: 200})
		if int64(len(pg.Rows)) != stats.ByStageLive[i] {
			t.Errorf("%s: catalogue %d rows, live count %d", c.Code, len(pg.Rows), stats.ByStageLive[i])
		}
		live += stats.ByStageLive[i]
	}
	if live != stats.WithEvents-stats.Rejected {
		t.Errorf("live %d, with events %d, rejected %d", live, stats.WithEvents, stats.Rejected)
	}
}
