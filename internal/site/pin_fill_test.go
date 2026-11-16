package site_test

import (
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
)

// fillPosts seeds a mix for the fill (pin.go): one CVE the rule pins and
// discussed CVEs the rule does not pin.
//
//	1001  a1, a2 at 1h, 2h                 rule (KEV 2 days ago)
//	1006  a1, a2, a3 at 4 days             3 researchers, last post too old for
//	                                        the rule; PAT 40 days ago (outside
//	                                        every window below)
//	1004  a1 at 1h                         1; disclosed only (below min stage PAT)
//	1002  a2 at 5h, "off" (disabled) x3    1 (the disabled account does not count)
//	1003  a3 at 4 days                     1
//	1005  a1, a2 at 73h                    2; REJECTED (too old for the rule)
//	1010  a1..a4 at 1h                     4; no lifecycle row (stub): never shown
func fillPosts(t *testing.T, post func(cve, author string, ago time.Duration)) {
	t.Helper()
	post("CVE-2026-1001", "a1", 1*h)
	post("CVE-2026-1001", "a2", 2*h)
	for _, a := range []string{"a1", "a2", "a3"} {
		post("CVE-2026-1006", a, 4*day)
	}
	post("CVE-2026-1004", "a1", 1*h)
	post("CVE-2026-1002", "a2", 5*h)
	for i := 0; i < 3; i++ {
		post("CVE-2026-1002", "off", time.Duration(i+1)*h)
	}
	post("CVE-2026-1003", "a3", 4*day)
	post("CVE-2026-1005", "a1", 3*day+h)
	post("CVE-2026-1005", "a2", 3*day+h)
	for _, a := range []string{"a1", "a2", "a3", "a4"} {
		post("CVE-2026-1010", a, 1*h)
	}
}

// Fewer pins by the rule than Max: filled from the discussed ranking in its
// order; the fill ignores the window and the minimum stage but keeps the
// rejected switch and the tags; stubs are skipped; Max bounds it; Max 0
// pins nothing.
func TestHotPinFill(t *testing.T) {
	st, d, _ := seeded(t)
	fillPosts(t, pinSeeder(t, d))
	base := site.HotParams{Since: 7 * day, MinStage: "patch"}

	page, err := st.Hot(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	if got := pinnedOf(t, page); got != "1001,1006,1004,1002,1003" {
		t.Errorf("pinned %q", got)
	}
	if r, f := pinnedBy(page, site.PinRule), pinnedBy(page, site.PinDiscussed); r != "1001" || f != "1006,1004,1002,1003" {
		t.Errorf("rule %q fill %q", r, f)
	}
	if got := ordinaryOf(page); got != "102895,1008,1007,1009" {
		t.Errorf("ordinary %q", got)
	}
	for _, r := range page.Rows {
		if r.Pinned != (r.PinReason != "") {
			t.Errorf("%s pinned %t reason %q", r.CVEID, r.Pinned, r.PinReason)
		}
		want := map[string]int{"CVE-2026-1001": 2, "CVE-2026-1006": 3, "CVE-2026-1004": 1, "CVE-2026-1002": 1, "CVE-2026-1003": 1}[r.CVEID]
		if r.Researchers != want {
			t.Errorf("%s researchers %d want %d", r.CVEID, r.Researchers, want)
		}
	}

	// The fill is the discussed ranking itself, minus the rule's pins,
	// rejected CVEs and stubs.
	disc, err := st.Discussed(ctx, site.DiscussedParams{})
	if err != nil {
		t.Fatal(err)
	}
	var rank []string
	for _, r := range disc.Rows {
		if _, ok := r.HotRow(); ok && !r.IsRejected && r.CVEID != "CVE-2026-1001" {
			rank = append(rank, strings.TrimPrefix(r.CVEID, "CVE-2026-"))
		}
	}
	if got := strings.Join(rank, ","); got != pinnedBy(page, site.PinDiscussed) {
		t.Errorf("discussed ranking %q != fill %q", got, pinnedBy(page, site.PinDiscussed))
	}

	// Rejected CVEs fill only with the switch (2 researchers: after 1006).
	p := base
	p.IncludeRejected = true
	page, _ = st.Hot(ctx, p)
	if got := pinnedBy(page, site.PinDiscussed); got != "1006,1005,1004,1002,1003" {
		t.Errorf("fill with rejected %q", got)
	}

	// Tags: only the tag's CVEs fill (network: 1002 and GPU; GPU has no
	// researcher posts, so it stays an ordinary row).
	sitetest.SeedTags(t, d.Conn)
	p = base
	p.Tags = []string{"network"}
	page, _ = st.Hot(ctx, p)
	if got, all := pinnedOf(t, page), ids(page.Rows); got != "1002" || all != "1002,102895" || pinnedBy(page, site.PinDiscussed) != "1002" {
		t.Errorf("tag network: pinned %q rows %q", got, all)
	}

	// Max bounds rule + fill.
	st.SetPinConfig(site.PinConfig{Max: 3, MinResearchers: 2, Recent: 72 * h, Wave: 7 * day})
	page, _ = st.Hot(ctx, base)
	if got := pinnedOf(t, page); got != "1001,1006,1004" {
		t.Errorf("max 3: %q", got)
	}
	// Exactly Max by the rule: no fill.
	st.SetPinConfig(site.PinConfig{Max: 1, MinResearchers: 2, Recent: 72 * h, Wave: 7 * day})
	page, _ = st.Hot(ctx, base)
	if got := pinnedOf(t, page); got != "1001" || pinnedBy(page, site.PinRule) != "1001" {
		t.Errorf("max 1: %q", got)
	}
	if got := ordinaryOf(page); got != "1002,1003,102895,1008,1007,1009" {
		t.Errorf("max 1 ordinary %q", got)
	}
	// Max 0: no pins at all, fill included.
	st.SetPinConfig(site.PinConfig{Max: 0, MinResearchers: 2, Recent: 72 * h, Wave: 7 * day})
	page, _ = st.Hot(ctx, base)
	if pinnedOf(t, page) != "" || ids(page.Rows) != "1001,1002,1003,102895,1008,1007,1009" {
		t.Errorf("max 0: %q", ids(page.Rows))
	}
	// NoPins (the feed) likewise.
	st.SetPinConfig(site.DefaultPinConfig)
	p = base
	p.NoPins = true
	page, _ = st.Hot(ctx, p)
	if pinnedOf(t, page) != "" || ids(page.Rows) != "1001,1002,1003,102895,1008,1007,1009" {
		t.Errorf("no pins: %q", ids(page.Rows))
	}

	// Cache key: the pin config is part of it, the request too.
	k := st.HotCacheKey(base)
	st.SetPinConfig(site.PinConfig{Max: 9, MinResearchers: 2, Recent: 72 * h, Wave: 7 * day})
	if st.HotCacheKey(base) == k {
		t.Error("cache key ignores Max")
	}
	st.SetPinConfig(site.DefaultPinConfig)
	if st.HotCacheKey(base) != k {
		t.Error("cache key not stable")
	}
}

// Every CVE appears exactly once over pages 1..n, with rule pins, fill pins
// that the window would also list (1002, 1003) and ordinary rows; the
// pinned set is excluded identically on every page (cursor and offset).
func TestHotPinNoDuplicatesAcrossPages(t *testing.T) {
	st, d, _ := seeded(t)
	fillPosts(t, pinSeeder(t, d))
	full, err := st.Hot(ctx, site.HotParams{Since: 30 * day, MinStage: "disclosed", NoPins: true, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	for _, limit := range []int{1, 2, 3} {
		p := site.HotParams{Since: 30 * day, MinStage: "disclosed", Limit: limit}
		count := map[string]int{}
		var pinned []string
		var order []string
		for n := 1; ; n++ {
			page, err := st.Hot(ctx, p)
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range page.Rows {
				count[r.CVEID]++
				order = append(order, strings.TrimPrefix(r.CVEID, "CVE-2026-"))
				if r.Pinned {
					if n != 1 {
						t.Errorf("limit %d page %d: pinned %s", limit, n, r.CVEID)
					}
					pinned = append(pinned, r.CVEID)
				}
			}
			if page.NextCursor == nil {
				break
			}
			p.Cursor = *page.NextCursor
			if n > 50 {
				t.Fatal("no end")
			}
		}
		// 1001 by the rule, then the fill: 1006 (transition 40 days ago,
		// outside the window), 1004, 1002, 1003 (both also in the window).
		if got := strings.Join(order[:5], ","); got != "1001,1006,1004,1002,1003" {
			t.Errorf("limit %d: first rows %q", limit, got)
		}
		for id, c := range count {
			if c != 1 {
				t.Errorf("limit %d: %s appears %d times (%v)", limit, id, c, order)
			}
		}
		// Everything the unpinned list holds, plus the fill row outside the
		// window (1006), and nothing else.
		want := map[string]bool{"CVE-2026-1006": true}
		for _, r := range full.Rows {
			want[r.CVEID] = true
		}
		if len(count) != len(want) {
			t.Errorf("limit %d: %d ids, want %d (%v)", limit, len(count), len(want), order)
		}
		for id := range want {
			if count[id] != 1 {
				t.Errorf("limit %d: %s missing", limit, id)
			}
		}
		if len(pinned) != 5 {
			t.Errorf("limit %d: pinned %v", limit, pinned)
		}

		// Offset paging: same ordinary rows, never a pinned one.
		seen := map[string]int{}
		for _, id := range pinned {
			seen[id]++
		}
		for off := 0; off <= len(full.Rows); off += limit {
			page, err := st.Hot(ctx, site.HotParams{Since: 30 * day, MinStage: "disclosed", Limit: limit, Offset: off})
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range page.Rows {
				if !r.Pinned {
					seen[r.CVEID]++
				}
			}
		}
		for id, c := range seen {
			if c != 1 {
				t.Errorf("offset limit %d: %s seen %d times", limit, id, c)
			}
		}
		if len(seen) != len(want) {
			t.Errorf("offset limit %d: %d ids want %d", limit, len(seen), len(want))
		}
	}
}

// The keyset of the hot list is (last_transition_at, stage_rank, cve_id)
// where stage_rank is the CURRENT stage's rank. Three CVEs share one
// transition time: 2001 is KEV (rank 6) but its last transition is a later
// patch (rank 2), 2002's last transition is an analysis (rank 3), 2003's a
// patch (rank 2). Paged one row at a time, none may be skipped.
func TestHotCursorCurrentStageTies(t *testing.T) {
	st, d, _ := seeded(t)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	at := sitetest.Ago(1.5)
	old := sitetest.Ago(20)
	for _, c := range []string{"CVE-2026-2001", "CVE-2026-2002", "CVE-2026-2003"} {
		s.Vuln(c, sitetest.P("tie "+c))
	}
	s.Event(sitetest.Ev{CVE: "CVE-2026-2001", Type: "kev_added", Source: "kev", Occurred: &old, Key: "k2001"})
	s.Event(sitetest.Ev{CVE: "CVE-2026-2001", Type: "patch_released", Source: "ghsa", Occurred: &at, Key: "GHSA-2001"})
	s.Event(sitetest.Ev{CVE: "CVE-2026-2002", Type: "analysis_published", Source: "x", Occurred: &at, Key: "a2002"})
	s.Event(sitetest.Ev{CVE: "CVE-2026-2003", Type: "patch_released", Source: "ghsa", Occurred: &at, Key: "GHSA-2003"})
	s.Refresh()

	p := site.HotParams{Since: 30 * day, MinStage: "patch", NoPins: true, Limit: 200}
	all, err := st.Hot(ctx, p)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(all.Rows); !strings.Contains(got, "2001,2002,2003") {
		t.Fatalf("precondition: one page %q", got)
	}
	for _, r := range all.Rows {
		if r.CVEID == "CVE-2026-2001" && (r.Stage != "kev_added" || r.Transition.Type != "patch_released") {
			t.Fatalf("precondition: 2001 stage %s transition %s", r.Stage, r.Transition.Type)
		}
	}
	p.Limit = 1
	var got []string
	for n := 0; n < 50; n++ {
		page, err := st.Hot(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, ids(page.Rows))
		if page.NextCursor == nil {
			break
		}
		p.Cursor = *page.NextCursor
	}
	if strings.Join(got, ",") != ids(all.Rows) {
		t.Errorf("paged %q\nwant  %q", strings.Join(got, ","), ids(all.Rows))
	}
}
