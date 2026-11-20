package site_test

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/ghrepo"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
)

// The heat ranking's extras (site/discussed.go, public.go): posts per UTC
// day, the "new" flag (first post ever today or yesterday, UTC), the ranking's top count and the listed
// authors' avatars, without moving the ranking.
func TestDiscussedHeat(t *testing.T) {
	st, d, _ := seeded(t)
	post := pinSeeder(t, d)
	// sitetest.Now is 2026-11-13 01:00 UTC: day 6 is the 13th, day 0 the 7th
	post("CVE-2026-1001", "a1", 30*time.Minute) // day 6
	post("CVE-2026-1001", "a2", 2*h)            // day 5 (the 12th, 23:00)
	post("CVE-2026-1001", "a2", 3*h)            // day 5 again: posts, not researchers
	post("CVE-2026-1001", "a3", 6*day+30*time.Minute)
	post("CVE-2026-1001", "a4", 6*day+2*h) // 2026-11-06 23:00: before the window's first day, not counted
	post("CVE-2026-1001", "off", 1*h)      // disabled: nothing
	post("CVE-2026-1002", "a5", 20*h)      // yesterday (UTC): new
	// CVE-2026-1003: a6's post is the 51st newest, so the outline doesn't
	// list a6 for this CVE (it still counts)
	post("CVE-2026-1003", "a6", 4*day)
	for i := 0; i < 50; i++ {
		post("CVE-2026-1003", "a1", h+time.Duration(i)*time.Minute)
	}
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_user (user_id, seen_at, avatar_status, avatar_type, avatar_image, avatar_hash) VALUES
		('7001', now(), 'ok', 'image/png', '\x01', '00000000000000a1'), ('7006', now(), 'ok', 'image/png', '\x06', '00000000000000a6')`); err != nil {
		t.Fatal(err)
	}
	page, err := st.Discussed(ctx, site.DiscussedParams{Heat: true})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]site.DiscussedRow{}
	var order []string
	for _, r := range page.Rows {
		got[r.CVEID] = r
		order = append(order, strings.TrimPrefix(r.CVEID, "CVE-2026-"))
	}
	if strings.Join(order, ",") != "1001,1003,1002" || page.Top != 3 || page.Total != 3 {
		t.Fatalf("ranking %v top %d total %d", order, page.Top, page.Total)
	}
	a := got["CVE-2026-1001"]
	if a.Researchers != 3 || a.Days != [site.HeatDays]int{1, 0, 0, 0, 0, 2, 1} || a.Fresh ||
		strings.Join(a.Faces, "|") != "/avatar/00000000000000a1||" {
		t.Errorf("1001: %d %v %v %q", a.Researchers, a.Days, a.Fresh, a.Faces)
	}
	b := got["CVE-2026-1002"]
	if b.Researchers != 1 || !b.Fresh || b.Days != [site.HeatDays]int{0, 0, 0, 0, 0, 1, 0} || len(b.Faces) != 1 || b.Faces[0] != "" {
		t.Errorf("1002: %+v", b)
	}
	c := got["CVE-2026-1003"]
	if c.Researchers != 2 || c.Fresh || strings.Join(c.Faces, " ") != "/avatar/00000000000000a1" {
		t.Errorf("1003: researchers %d faces %q (a6 is not in this CVE's outline)", c.Researchers, c.Faces)
	}
	// the page on later offsets keeps the whole ranking's top
	if p2, err := st.Discussed(ctx, site.DiscussedParams{Limit: 1, Offset: 2, Heat: true}); err != nil || p2.Top != 3 || len(p2.Rows) != 1 {
		t.Errorf("offset 2: top %d rows %d %v", p2.Top, len(p2.Rows), err)
	}
}

// Without Heat (the JSON API) none of the extras is computed.
func TestDiscussedPlain(t *testing.T) {
	st, d, _ := seeded(t)
	post := pinSeeder(t, d)
	post("CVE-2026-1001", "a1", 30*time.Minute)
	post("CVE-2026-1001", "a2", 20*h)
	page, err := st.Discussed(ctx, site.DiscussedParams{})
	if err != nil || len(page.Rows) != 1 {
		t.Fatalf("%v %d", err, len(page.Rows))
	}
	r := page.Rows[0]
	if r.Researchers != 2 || page.Total != 1 || page.Top != 0 || r.Fresh || r.Faces != nil || r.Days != [site.HeatDays]int{} {
		t.Errorf("plain row carries heat extras: top %d %+v", page.Top, r)
	}
	heat, _ := st.Discussed(ctx, site.DiscussedParams{Heat: true})
	if (site.DiscussedParams{}).CacheKey() == (site.DiscussedParams{Heat: true}).CacheKey() || heat.Rows[0].CVEID != r.CVEID {
		t.Error("the plain and heat pages share a cache key or rank differently")
	}
}

// Everything public about researcher posts depends on the request time
// by UTC day only (researcherWindow, freshSince, the pin cutoffs): with
// the same posts, the ranking (plain and heat: order, counts, top, flags,
// sparkline, faces), the hot list's counts and pins and the vulnerability
// page's count are identical at any two times of one UTC day, and change
// only across 00:00 UTC.
func TestDiscussedDayGranular(t *testing.T) {
	base, d, _ := seeded(t)
	post := pinSeeder(t, d)
	// relative to sitetest.Now (2026-11-13 01:00 UTC)
	post("CVE-2026-1001", "a1", 37*h+30*time.Minute) // 2026-11-11 11:30
	post("CVE-2026-1001", "a2", 25*h+30*time.Minute) // 2026-11-11 23:30
	post("CVE-2026-1001", "a5", 49*h)                // 2026-11-11 00:00
	post("CVE-2026-1002", "a3", 7*day+13*h)          // 2026-11-05 12:00: in the window until 2026-11-12 00:00
	post("CVE-2026-1002", "a4", 36*h)                // 2026-11-11 13:00
	post("CVE-2026-1003", "a6", 4*day)               // 2026-11-09 01:00
	type snap struct {
		heat, plain   *site.DiscussedPage
		hot           *site.HotPage
		outline, rows string
	}
	at := func(s string) snap {
		t.Helper()
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatal(err)
		}
		st := base.WithClock(func() time.Time { return ts })
		var sn snap
		if sn.heat, err = st.Discussed(ctx, site.DiscussedParams{Heat: true}); err != nil {
			t.Fatal(err)
		}
		if sn.plain, err = st.Discussed(ctx, site.DiscussedParams{}); err != nil {
			t.Fatal(err)
		}
		if sn.hot, err = st.Hot(ctx, site.HotParams{Since: 30 * day, MinStage: "disclosed"}); err != nil {
			t.Fatal(err)
		}
		o, err := st.ResearcherOutline(ctx, "CVE-2026-1002")
		if err != nil {
			t.Fatal(err)
		}
		sn.outline = fmt.Sprint(o.Researchers)
		for _, p := range []*site.DiscussedPage{sn.heat, sn.plain} {
			p.GeneratedAt = time.Time{}
		}
		// the hot list's own since= filter is over public events and
		// slides with the request (not about posts): left out here
		sn.hot.GeneratedAt, sn.hot.SinceStart = time.Time{}, time.Time{}
		var rs []string
		for _, r := range sn.heat.Rows {
			rs = append(rs, fmt.Sprintf("%s:%d:%v:%v:%q", r.CVEID, r.Researchers, r.Days, r.Fresh, r.Faces))
		}
		sn.rows = strings.Join(rs, " ") + fmt.Sprintf(" top=%d", sn.heat.Top)
		return sn
	}
	same := func(a, b snap) bool {
		return reflect.DeepEqual(a.heat, b.heat) && reflect.DeepEqual(a.plain, b.plain) && reflect.DeepEqual(a.hot, b.hot) && a.outline == b.outline
	}
	prev, morning, evening, next := at("2026-11-11T23:59:59Z"), at("2026-11-12T00:00:00Z"), at("2026-11-12T23:59:59Z"), at("2026-11-13T00:00:00Z")
	if !same(morning, evening) {
		t.Errorf("one UTC day, two answers:\n%s\n%s\nheat %v plain %v hot %v outline %v", morning.rows, evening.rows,
			reflect.DeepEqual(morning.heat, evening.heat), reflect.DeepEqual(morning.plain, evening.plain),
			reflect.DeepEqual(morning.hot, evening.hot), morning.outline == evening.outline)
	}
	if same(prev, morning) || same(evening, next) {
		t.Error("nothing changed across 00:00 UTC")
	}
	for name, c := range map[string]struct {
		s    snap
		want string
	}{
		// 1002: 2026-11-05 counts up to 2026-11-11 (window from 11-05), not after;
		// 1001: first post 11-11, "new" on 11-11 and 11-12, not on 11-13
		"prev":    {prev, `CVE-2026-1001:3:[0 0 0 0 0 0 3]:true:["" "" ""] CVE-2026-1002:2:[1 0 0 0 0 0 1]:false:["" ""] CVE-2026-1003:1:[0 0 0 0 1 0 0]:false:[""] top=3`},
		"morning": {morning, `CVE-2026-1001:3:[0 0 0 0 0 3 0]:true:["" "" ""] CVE-2026-1002:1:[0 0 0 0 0 1 0]:false:[""] CVE-2026-1003:1:[0 0 0 1 0 0 0]:false:[""] top=3`},
		"next":    {next, `CVE-2026-1001:3:[0 0 0 0 3 0 0]:false:["" "" ""] CVE-2026-1002:1:[0 0 0 0 1 0 0]:false:[""] CVE-2026-1003:1:[0 0 1 0 0 0 0]:false:[""] top=3`},
	} {
		if c.s.rows != c.want {
			t.Errorf("%s:\n got %s\nwant %s", name, c.s.rows, c.want)
		}
	}
	// the 7 per-day counts add up to the posts in the window
	for _, r := range morning.heat.Rows {
		n := 0
		for _, c := range r.Days {
			n += c
		}
		if want := map[string]int{"CVE-2026-1001": 3, "CVE-2026-1002": 1, "CVE-2026-1003": 1}[r.CVEID]; n != want {
			t.Errorf("%s: days add up to %d, want %d", r.CVEID, n, want)
		}
	}
	if prev.outline != "2" || morning.outline != "1" {
		t.Errorf("vulnerability page count %s then %s, want 2 then 1", prev.outline, morning.outline)
	}
}

// The pin rule on whole UTC days: Recent 36h is 2 days (cutoff 00:00 UTC
// two days ago, never 12:00), and the wave gap compares UTC dates, so posts
// 7 days apart at 09:00 or at 11:00 are one wave either way.
func TestPinDayCutoffs(t *testing.T) {
	st, d, _ := seeded(t)
	post := pinSeeder(t, d)
	// sitetest.Now is 2026-11-13 01:00 UTC
	post("CVE-2026-1001", "a1", 49*h)             // 2026-11-11 00:00: on the cutoff
	post("CVE-2026-1001", "a2", 61*h)             // 2026-11-10 12:00
	post("CVE-2026-1009", "a1", 49*h+time.Minute) // 2026-11-10 23:59: a minute before
	post("CVE-2026-1009", "a2", 50*h)
	// one wave from 2026-11-03 10:00 (outside the 7-day wave cap) whether
	// the later posts are at 09:00 or 11:00 on 2026-11-10
	for cve, hourOfDay := range map[string]int{"CVE-2026-1008": 9, "CVE-2026-1007": 11} {
		post(cve, "a1", 9*day+15*h) // 2026-11-03 10:00
		later := time.Duration(24+1-hourOfDay)*h + 2*day
		post(cve, "a2", later)
		post(cve, "a3", later)
	}
	st.SetPinConfig(site.PinConfig{Max: 10, MinResearchers: 2, Recent: 36 * h, Wave: 7 * day})
	var first string
	for _, clock := range []string{"2026-11-13T01:00:00Z", "2026-11-13T12:00:00Z", "2026-11-13T23:59:59Z"} {
		ts, _ := time.Parse(time.RFC3339, clock)
		page, err := st.WithClock(func() time.Time { return ts }).Hot(ctx, site.HotParams{Since: 30 * day, MinStage: "disclosed"})
		if err != nil {
			t.Fatal(err)
		}
		got := pinnedBy(page, site.PinRule)
		if got != "1001" {
			t.Errorf("%s: rule-pinned %q, want 1001 (latest post on the 00:00 UTC cutoff; 1009 a minute before; 1007/1008 one old wave)", clock, got)
		}
		if first == "" {
			first = pinnedOf(t, page)
		} else if pinnedOf(t, page) != first {
			t.Errorf("%s: pins %q, earlier %q", clock, pinnedOf(t, page), first)
		}
	}
	// with Recent 4 days the wave decides for 1007/1008: one wave from
	// 2026-11-03 (gap 7 UTC days, not more), too old; 1001 and 1009 pin
	st.SetPinConfig(site.PinConfig{Max: 10, MinResearchers: 2, Recent: 96 * h, Wave: 7 * day})
	page, err := st.Hot(ctx, site.HotParams{Since: 30 * day, MinStage: "disclosed"})
	if err != nil {
		t.Fatal(err)
	}
	if got := pinnedBy(page, site.PinRule); got != "1001,1009" {
		t.Errorf("rule-pinned %q, want 1001,1009 (1007 at 11:00 and 1008 at 09:00 are the same old wave)", got)
	}
}

// The public pins, counts and ranking are the same at 01:00, 12:00 and
// 23:59 UTC of one day (the fixture clock is 01:00).
func TestPublicStableThroughTheDay(t *testing.T) {
	base, d, _ := seeded(t)
	post := pinSeeder(t, d)
	post("CVE-2026-1001", "a1", 20*h) // 2026-11-12 05:00
	post("CVE-2026-1001", "a2", 22*h)
	post("CVE-2026-1009", "a1", 3*day+20*h) // 2026-11-09 05:00
	post("CVE-2026-1009", "a3", 4*day)
	post("CVE-2026-1003", "a4", 6*day+30*time.Minute) // 2026-11-07 00:30, the window's first day
	post("CVE-2026-1004", "a5", 6*day+2*h)            // 2026-11-06 23:00, before it
	snap := func(clock string) string {
		t.Helper()
		ts, _ := time.Parse(time.RFC3339, clock)
		st := base.WithClock(func() time.Time { return ts })
		hot, err := st.Hot(ctx, site.HotParams{Since: 30 * day, MinStage: "disclosed"})
		if err != nil {
			t.Fatal(err)
		}
		var b strings.Builder
		for _, r := range hot.Rows {
			fmt.Fprintf(&b, "%s:%d:%v:%s ", r.CVEID, r.Researchers, r.Pinned, r.PinReason)
		}
		for _, heat := range []bool{false, true} {
			p, err := st.Discussed(ctx, site.DiscussedParams{Heat: heat})
			if err != nil {
				t.Fatal(err)
			}
			for _, r := range p.Rows {
				fmt.Fprintf(&b, "|%s:%d:%v:%v:%q", r.CVEID, r.Researchers, r.Days, r.Fresh, r.Faces)
			}
			fmt.Fprintf(&b, "|top=%d total=%d", p.Top, p.Total)
		}
		o, err := st.ResearcherOutline(ctx, "CVE-2026-1003")
		if err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "|outline=%d", o.Researchers)
		return b.String()
	}
	a, b, c := snap("2026-11-13T01:00:00Z"), snap("2026-11-13T12:00:00Z"), snap("2026-11-13T23:59:59Z")
	if a != b || a != c {
		t.Errorf("not stable through the day:\n%s\n%s\n%s", a, b, c)
	}
	if !strings.Contains(a, "CVE-2026-1001:2:true:rule") || strings.Contains(a, "CVE-2026-1004:1") || !strings.Contains(a, "outline=1") {
		t.Errorf("unexpected day: %s", a)
	}
	if next := snap("2026-11-14T00:00:00Z"); next == a {
		t.Error("nothing changed at 00:00 UTC")
	}
}

// The GitHub search's "discussed" source (internal/ghrepo hotSQL) uses the
// same day-aligned window as /discussed: a post at the window's first
// instant is in, one a second earlier (inside a rolling 168 h) is not.
func TestGitHubHotUsesResearcherWindow(t *testing.T) {
	st, d, _ := seeded(t)
	post := pinSeeder(t, d)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	s.Vuln("CVE-2026-8101", nil)
	s.Vuln("CVE-2026-8102", nil)
	post("CVE-2026-8101", "a1", 6*day+h)             // 2026-11-07 00:00
	post("CVE-2026-8102", "a2", 6*day+h+time.Second) // a second earlier
	ids, err := ghrepo.HotCVEs(ctx, d.Conn, sitetest.Now, 1000)
	if err != nil {
		t.Fatal(err)
	}
	got := "," + strings.Join(ids, ",") + ","
	page, err := st.Discussed(ctx, site.DiscussedParams{})
	if err != nil {
		t.Fatal(err)
	}
	var disc []string
	for _, r := range page.Rows {
		disc = append(disc, r.CVEID)
	}
	if !strings.Contains(got, ",CVE-2026-8101,") || strings.Contains(got, ",CVE-2026-8102,") ||
		strings.Join(disc, ",") != "CVE-2026-8101" {
		t.Errorf("github hot ids %s; discussed %v", got, disc)
	}
}
