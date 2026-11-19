package site_test

import (
	"testing"
	"time"

	"nday.land/nday/internal/site"
)

// The lists' lengths (listcount.go) agree with walking every page of the
// list by keyset, for each filter combination; the hot list's count leaves
// out the pinned CVEs exactly as its pages do.

func TestHotCount(t *testing.T) {
	st, d, _ := seeded(t)
	catSeed(t, d)
	post := pinSeeder(t, d)
	for i, a := range []string{"a1", "a2", "a3"} {
		post("CVE-2026-1001", a, time.Duration(i+1)*h)
	}
	post("CVE-2026-1004", "a1", 2*h)
	post("CVE-2026-1004", "a2", 3*h)
	post("CVE-2026-1007", "a5", 1*h) // one researcher: no pin, a fill row of the discussed ranking
	st.SetPinConfig(site.PinConfig{Max: 2, MinResearchers: 2, Recent: 72 * h, Wave: 7 * day})
	for _, base := range []site.HotParams{
		{Since: 30 * day, MinStage: "disclosed", IncludeRejected: true},
		{Since: 30 * day, MinStage: "disclosed"},
		{Since: 7 * day, MinStage: "disclosed"},
		{Since: 60 * h, MinStage: "disclosed"},
		{Since: 30 * day}, // patch and later
		{Since: 30 * day, MinStage: "kev"},
		{Since: 366 * day, MinStage: "disclosed", Tags: []string{"network"}},
		{Since: 30 * day, MinStage: "disclosed", Tags: []string{"network", "no-auth"}},
		{Since: 30 * day, MinStage: "disclosed", NoPins: true},
		{Since: 30 * day, MinStage: "disclosed", Tags: []string{"xss"}},
	} {
		tot, ok, err := st.HotCount(ctx, base)
		if err != nil || !ok {
			t.Fatalf("%+v: %v %v", base, ok, err)
		}
		for _, limit := range []int{1, 2, 3, 50} {
			p := base
			p.Limit = limit
			pins, rows, pages := 0, 0, 0
			seen := map[string]bool{}
			for {
				pages++
				if pages > 60 {
					t.Fatalf("%+v: no end", p)
				}
				page, err := st.Hot(ctx, p)
				if err != nil {
					t.Fatal(err)
				}
				for _, r := range page.Rows {
					if seen[r.CVEID] {
						t.Errorf("%+v: %s twice", p, r.CVEID)
					}
					seen[r.CVEID] = true
					if r.Pinned {
						pins++
					} else {
						rows++
					}
				}
				if pages == 1 && page.Pins != tot.Pins {
					t.Errorf("%+v: page pins %d, count %d", p, page.Pins, tot.Pins)
				}
				if page.NextCursor == nil {
					break
				}
				p.Cursor = *page.NextCursor
			}
			if int64(rows) != tot.Rows || pins != tot.Pins || pages != tot.Pages(limit) {
				t.Errorf("%+v limit %d: walked %d rows + %d pinned on %d pages, counted %+v (%d pages)", base, limit, rows, pins, pages,
					tot, tot.Pages(limit))
			}
		}
	}
	// the pins really are left out of the count (the case above with pins)
	with, _, _ := st.HotCount(ctx, site.HotParams{Since: 30 * day, MinStage: "disclosed"})
	without, _, _ := st.HotCount(ctx, site.HotParams{Since: 30 * day, MinStage: "disclosed", NoPins: true})
	if with.Pins == 0 || with.Rows+int64(with.Pins) != without.Rows || without.Pins != 0 {
		t.Errorf("pins %+v, no pins %+v", with, without)
	}
	// a broad tag (more CVEs than TagCountMax, from the precomputed counts)
	// is not counted, as on the catalogue; with a narrow one beside it, it is
	if _, err := d.Conn.Exec(ctx, `UPDATE vuln_tag_count SET n = $1 WHERE tag = 'network'`, site.TagCountMax+1); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		tags []string
		ok   bool
	}{{[]string{"network"}, false}, {[]string{"network", "no-auth"}, true}, {nil, true}} {
		tot, ok, err := st.HotCount(ctx, site.HotParams{Since: 366 * day, MinStage: "disclosed", Tags: c.tags})
		if err != nil || ok != c.ok || (!ok && tot != (site.HotTotal{})) {
			t.Errorf("tags %v: %+v %v %v", c.tags, tot, ok, err)
		}
	}
	// the key: every filter, not the position or the page size
	p, _ := site.HotParams{Since: 30 * day, MinStage: "disclosed"}.Normalize()
	q, _ := site.HotParams{Since: 30 * day, MinStage: "disclosed", Limit: 7, Cursor: mustHotCursor(t, st)}.Normalize()
	if st.HotCountKey(p) != st.HotCountKey(q) {
		t.Error("the count key depends on the position")
	}
	keys := map[string]bool{}
	for _, f := range []site.HotParams{
		{Since: 30 * day, MinStage: "disclosed"}, {Since: 7 * day, MinStage: "disclosed"}, {Since: 30 * day},
		{Since: 30 * day, MinStage: "disclosed", IncludeRejected: true}, {Since: 30 * day, MinStage: "disclosed", NoPins: true},
		{Since: 30 * day, MinStage: "disclosed", Tags: []string{"xss"}},
	} {
		n, _ := f.Normalize()
		keys[st.HotCountKey(n)] = true
	}
	if len(keys) != 6 {
		t.Errorf("%d distinct keys for 6 filters", len(keys))
	}
	k := st.HotCountKey(p)
	st.SetPinConfig(site.PinConfig{Max: 3, MinResearchers: 2, Recent: 72 * h, Wave: 7 * day})
	if st.HotCountKey(p) == k {
		t.Error("the count key ignores the pinning numbers")
	}
}

func mustHotCursor(t *testing.T, st *site.Store) string {
	t.Helper()
	page, err := st.Hot(ctx, site.HotParams{Since: 30 * day, MinStage: "disclosed", Limit: 1, NoPins: true})
	if err != nil || page.NextCursor == nil {
		t.Fatalf("no cursor: %v", err)
	}
	return *page.NextCursor
}

func TestCatalogueCount(t *testing.T) {
	st, d := catSeeded(t)
	for _, base := range []site.CatalogueParams{
		{}, {IncludeRejected: true}, {Stage: "disclosed"}, {Stage: "kev", IncludeRejected: true},
		{Year: 2014}, {Year: 2025}, {Year: 2026, IncludeRejected: true}, {Year: 2025, Stage: "patch"}, {Year: 2014, Stage: "disclosed"},
		{Tags: []string{"network"}}, {Tags: []string{"network"}, IncludeRejected: true}, {Tags: []string{"network", "no-auth"}},
		{Tags: []string{"network"}, Year: 2026}, {Tags: []string{"network"}, Stage: "kev"}, {Tags: []string{"xss"}},
		{Year: 1999},
	} {
		n, ok, err := st.CatalogueCount(ctx, base)
		if err != nil || !ok {
			t.Fatalf("%+v: %v %v", base, ok, err)
		}
		p := base
		p.Limit = 2
		walked := 0
		for i := 0; ; i++ {
			if i > 60 {
				t.Fatalf("%+v: no end", p)
			}
			page, err := st.Catalogue(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			walked += len(page.Rows)
			if page.NextCursor == nil {
				break
			}
			p.Cursor = *page.NextCursor
		}
		if int64(walked) != n {
			t.Errorf("%+v: walked %d, counted %d", base, walked, n)
		}
	}
	// a broad tag (more CVEs than TagCountMax, from the
	// precomputed counts) is not counted; with a narrow one beside it, it is
	if _, err := d.Conn.Exec(ctx, `UPDATE vuln_tag_count SET n = $1 WHERE tag = 'network'`, site.TagCountMax+1); err != nil {
		t.Fatal(err)
	}
	if n, ok, err := st.CatalogueCount(ctx, site.CatalogueParams{Tags: []string{"network"}}); err != nil || ok || n != 0 {
		t.Errorf("broad tag: %d %v %v", n, ok, err)
	}
	if _, ok, err := st.CatalogueCount(ctx, site.CatalogueParams{Tags: []string{"network", "no-auth"}}); err != nil || !ok {
		t.Errorf("broad and narrow tag: %v %v", ok, err)
	}
	// the key: every filter, not the position or the page size
	a, _ := site.CatalogueParams{Year: 2025}.Normalize()
	b, _ := site.CatalogueParams{Year: 2025, Limit: 3, Cursor: mustNext(t, st, 1)}.Normalize()
	if a.CountKey() != b.CountKey() {
		t.Error("the count key depends on the position")
	}
	keys := map[string]bool{}
	for _, f := range []site.CatalogueParams{{}, {Year: 2025}, {Year: 2025, Stage: "patch"}, {Stage: "patch"}, {IncludeRejected: true},
		{Tags: []string{"network"}}, {Tags: []string{"network", "no-auth"}}} {
		n, _ := f.Normalize()
		keys[n.CountKey()] = true
	}
	if len(keys) != 7 {
		t.Errorf("%d distinct keys for 7 filters", len(keys))
	}
}
