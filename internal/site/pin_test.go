package site_test

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
)

// pinSeeder adds the X allowlist (authors a1..a6 enabled, "off" disabled)
// and returns a function storing one researcher post (what the xposts
// collector stores: a social_post event of source xposts).
func pinSeeder(t *testing.T, d *testutil.TestDB) func(cve, author string, ago time.Duration) {
	t.Helper()
	if _, err := d.Conn.Exec(ctx, `INSERT INTO x_accounts (user_id, handle, enabled) VALUES
		('7001', 'r_one', true), ('7002', 'r_two', true), ('7003', 'r_three', true), ('7004', 'r_four', true),
		('7005', 'r_five', true), ('7006', 'r_six', true), ('7099', 'r_off', false)`); err != nil {
		t.Fatal(err)
	}
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	n := 0
	return func(cve, author string, ago time.Duration) {
		t.Helper()
		n++
		at := sitetest.Now.Add(-ago)
		author = map[string]string{"a1": "7001", "a2": "7002", "a3": "7003", "a4": "7004", "a5": "7005", "a6": "7006",
			"off": "7099"}[author]
		id := fmt.Sprintf("19%017d", n)
		s.Event(sitetest.Ev{CVE: cve, Type: "social_post", Source: "xposts", Occurred: &at, Observed: at, Key: id,
			Detail: `{"post_id": "` + id + `", "author_id": "` + author + `", "author_handle": "h", "text": "t", "cves": ["` + cve + `"]}`})
	}
}

// pinnedOf lists the pinned rows of a page ("" = none) and checks that
// they come first.
func pinnedOf(t *testing.T, page *site.HotPage) string {
	t.Helper()
	var p []site.HotRow
	for i, r := range page.Rows {
		if r.Pinned {
			if i != len(p) {
				t.Errorf("pinned row %s after an ordinary row", r.CVEID)
			}
			p = append(p, r)
		}
	}
	return ids(p)
}

// pinnedBy lists the pinned rows of a page with the given PinReason.
func pinnedBy(page *site.HotPage, reason string) string {
	var p []site.HotRow
	for _, r := range page.Rows {
		if r.Pinned && r.PinReason == reason {
			p = append(p, r)
		}
	}
	return ids(p)
}

func ordinaryOf(page *site.HotPage) string {
	var o []site.HotRow
	for _, r := range page.Rows {
		if !r.Pinned {
			o = append(o, r)
		}
	}
	return ids(o)
}

const (
	h   = time.Hour
	day = 24 * time.Hour
)

// The rule: threshold, 72h expiry, the 7-day wave cap, re-pinning after a
// gap of more than 7 days, disabled authors, order, and the filters.
func TestHotPinRule(t *testing.T) {
	st, d, _ := seeded(t)
	post := pinSeeder(t, d)
	// pinned: two researchers in the last hours
	post("CVE-2026-1001", "a1", 1*h)
	post("CVE-2026-1001", "a2", 2*h)
	// not pinned: one researcher (a disabled account does not count)
	post("CVE-2026-1002", "a1", 1*h)
	post("CVE-2026-1002", "off", 1*h)
	post("CVE-2026-1002", "off", 2*h)
	// not pinned: two researchers, but the latest post is 73h old
	post("CVE-2026-1003", "a1", 4*day)
	post("CVE-2026-1003", "a2", 73*h)
	// not pinned: discussed without a break longer than 7 days since 9 days
	// ago (gaps of 6 days and about 3 days): the wave is too old
	post("CVE-2026-1007", "a1", 9*day)
	post("CVE-2026-1007", "a1", 3*day)
	post("CVE-2026-1007", "a2", 1*h)
	// pinned again: an old wave 20 days ago, silence, a new wave 2 days ago
	post("CVE-2026-1008", "a1", 20*day)
	post("CVE-2026-1008", "a2", 19*day)
	post("CVE-2026-1008", "a1", 2*day)
	post("CVE-2026-1008", "a2", 1*day)
	// pinned first: three researchers
	post("CVE-2026-1009", "a1", 5*h)
	post("CVE-2026-1009", "a2", 6*h)
	post("CVE-2026-1009", "a3", 7*h)
	// rejected: pinned only with --include-rejected
	post("CVE-2026-1005", "a1", 30*time.Minute)
	post("CVE-2026-1005", "a2", 40*time.Minute)

	month := 30 * day
	page, err := st.Hot(ctx, site.HotParams{Since: month, MinStage: "disclosed"})
	if err != nil {
		t.Fatal(err)
	}
	// The rule pins 1009, 1001, 1008; the rest of the 10 comes from the
	// discussed ranking (1007: 2 researchers, 1h; 1003: 2, 73h; 1002: 1).
	if got, rule := pinnedOf(t, page), pinnedBy(page, site.PinRule); rule != "1009,1001,1008" || got != "1009,1001,1008,1007,1003,1002" {
		t.Errorf("pinned %q rule %q", got, rule)
	}
	if got := ordinaryOf(page); got != "1004,102895" {
		t.Errorf("ordinary %q", got)
	}
	r := map[string]int{}
	for _, row := range page.Rows {
		r[row.CVEID] = row.Researchers
	}
	if r["CVE-2026-1009"] != 3 || r["CVE-2026-1001"] != 2 || r["CVE-2026-1008"] != 2 || r["CVE-2026-1002"] != 1 ||
		r["CVE-2026-1003"] != 2 || r["CVE-2026-1007"] != 2 {
		t.Errorf("researchers %v", r)
	}

	// --include-rejected: the rejected CVE is pinned too (2 researchers,
	// latest post 30 minutes ago: before 1001's hour).
	page, _ = st.Hot(ctx, site.HotParams{Since: month, MinStage: "disclosed", IncludeRejected: true})
	if got := pinnedBy(page, site.PinRule); got != "1009,1005,1001,1008" {
		t.Errorf("pinned with rejected %q", got)
	}
	// Window: 60 hours keeps only 1001 among the pinned (1008's transition
	// is 5 days old, 1009's 6) — a pinned CVE is always one the list holds
	// anyway.
	page, _ = st.Hot(ctx, site.HotParams{Since: 60 * h, MinStage: "disclosed"})
	if got := pinnedBy(page, site.PinRule); got != "1001" {
		t.Errorf("pinned 60h %q", got)
	}
	// ...but the fill ignores the window: the ranking's order.
	if got := pinnedBy(page, site.PinDiscussed); got != "1009,1007,1008,1003,1002" {
		t.Errorf("fill 60h %q", got)
	}
	if got := ordinaryOf(page); got != "1004" {
		t.Errorf("ordinary 60h %q", got)
	}
	// Minimum stage: 1009 (KEV) stays, 1004 (disclosed only) is not listed.
	page, _ = st.Hot(ctx, site.HotParams{Since: month, MinStage: "kev"})
	if got := pinnedBy(page, site.PinRule); got != "1009,1001,1008" {
		t.Errorf("pinned kev %q", got)
	}
	page, _ = st.Hot(ctx, site.HotParams{Since: month, MinStage: "patch"})
	if got := ordinaryOf(page); got != "102895" {
		t.Errorf("ordinary patch %q", got)
	}
	// Tags: only the tagged CVE (crlf-injection is 1003's; not pinned).
	sitetest.SeedTags(t, d.Conn)
	page, _ = st.Hot(ctx, site.HotParams{Since: month, MinStage: "disclosed", Tags: []string{"crlf-injection"}})
	if got, all := pinnedBy(page, site.PinRule), ids(page.Rows); got != "" || all != "1003" || pinnedOf(t, page) != "1003" {
		t.Errorf("tag: rule-pinned %q rows %q", got, all) // 1003 fills: it is discussed
	}
	page, _ = st.Hot(ctx, site.HotParams{Since: month, MinStage: "disclosed", Tags: []string{"ransomware"}})
	if got, all := pinnedOf(t, page), ids(page.Rows); got != "1008" || all != "1008" {
		t.Errorf("tag ransomware: pinned %q rows %q", got, all)
	}

	// The 72h edge: a post 71h old keeps 1003 pinned.
	post("CVE-2026-1003", "a3", 71*h)
	page, _ = st.Hot(ctx, site.HotParams{Since: month, MinStage: "disclosed"})
	if got := pinnedBy(page, site.PinRule); got != "1009,1003,1001,1008" {
		t.Errorf("pinned after 71h post %q", got) // 1003 has 3 researchers now
	}

	// JSON carries the flag on every row, the reason on pinned rows only.
	b, _ := json.Marshal(page.Rows)
	body := string(b)
	if c := strings.Count(body, `"pinned":true`); c != 6 || strings.Count(body, `"pinned":false`) != len(page.Rows)-6 {
		t.Errorf("json pinned flags: %d true in %s", c, b)
	}
	if strings.Count(body, `"pin_reason":"rule"`) != 4 || strings.Count(body, `"pin_reason":"discussed"`) != 2 ||
		strings.Count(body, `"pin_reason"`) != 6 {
		t.Errorf("json pin_reason: %s", b)
	}
}

// At most Max pinned rows in the stated order; they show only on the first
// page and never again on later pages (cursor or offset); the settings.
func TestHotPinMaxAndPaging(t *testing.T) {
	st, d, _ := seeded(t)
	post := pinSeeder(t, d)
	for i, a := range []string{"a1", "a2", "a3", "a4"} {
		post("CVE-2026-1005", a, time.Duration(i+1)*h)
	}
	for i, a := range []string{"a1", "a2", "a3"} {
		post("CVE-2026-1004", a, time.Duration(i+1)*h)
	}
	two := func(cve string, last time.Duration) {
		post(cve, "a5", last)
		post(cve, "a6", last+h)
	}
	two("CVE-2026-1001", 1*h)
	two("CVE-2026-1003", 2*h) // ties with 1002 on the latest post: CVE id asc
	two("CVE-2026-1002", 2*h)
	two(sitetest.GPU, 5*h)
	two("CVE-2026-1008", 6*h)

	// The rule alone yields 7 here: Max 5 truncates them (no fill).
	if c := st.PinConfig(); c != site.DefaultPinConfig || c.Max != 10 {
		t.Errorf("default config %+v", c)
	}
	st.SetPinConfig(site.PinConfig{Max: 5, MinResearchers: 2, Recent: 72 * h, Wave: 7 * day})
	base := site.HotParams{Since: 30 * day, MinStage: "disclosed", IncludeRejected: true}
	full := base
	full.NoPins = true
	all, err := st.Hot(ctx, full)
	if err != nil {
		t.Fatal(err)
	}
	if got := ids(all.Rows); got != "1005,1004,1001,1002,1003,102895,1008,1007,1009" || pinnedOf(t, all) != "" {
		t.Fatalf("NoPins %q", got)
	}

	p := base
	p.Limit = 2
	var seen []string
	pages := 0
	for {
		page, err := st.Hot(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		got := pinnedOf(t, page)
		if pages == 1 {
			if got != "1005,1004,1001,1002,1003" || pinnedBy(page, site.PinRule) != got {
				t.Errorf("first page pinned %q", got)
			}
			if ordinaryOf(page) != "102895,1008" || len(page.Rows) != 7 {
				t.Errorf("first page ordinary %q (%d rows)", ordinaryOf(page), len(page.Rows))
			}
		} else if got != "" {
			t.Errorf("page %d pinned %q", pages, got)
		}
		for _, r := range page.Rows {
			seen = append(seen, strings.TrimPrefix(r.CVEID, "CVE-2026-"))
		}
		if page.NextCursor == nil {
			break
		}
		p.Cursor = *page.NextCursor
	}
	if pages != 2 || strings.Join(seen, ",") != "1005,1004,1001,1002,1003,102895,1008,1007,1009" {
		t.Errorf("pages %d rows %v", pages, seen)
	}
	// Offset paging: the ordinary rows without the pinned ones.
	off := base
	off.Limit, off.Offset = 2, 2
	page, _ := st.Hot(ctx, off)
	if ids(page.Rows) != "1007,1009" || pinnedOf(t, page) != "" || page.NextCursor != nil {
		t.Errorf("offset 2: %q", ids(page.Rows))
	}
	off.Offset = 1
	page, _ = st.Hot(ctx, off)
	if ids(page.Rows) != "1008,1007" {
		t.Errorf("offset 1: %q", ids(page.Rows))
	}

	// Settings: fewer rows, a higher threshold, pinning off.
	k0 := st.HotCacheKey(base)
	st.SetPinConfig(site.PinConfig{Max: 2, MinResearchers: 2, Recent: 72 * h, Wave: 7 * day})
	if st.HotCacheKey(base) == k0 {
		t.Error("cache key ignores the pinning settings")
	}
	page, _ = st.Hot(ctx, base)
	if got := pinnedOf(t, page); got != "1005,1004" {
		t.Errorf("max 2: %q", got)
	}
	st.SetPinConfig(site.PinConfig{Max: 5, MinResearchers: 3, Recent: 72 * h, Wave: 7 * day})
	page, _ = st.Hot(ctx, base)
	if got := pinnedBy(page, site.PinRule); got != "1005,1004" {
		t.Errorf("3 researchers: %q", got)
	}
	// filled up to 5 from the ranking (2 researchers each; 1h, 2h, 2h: id asc)
	if got := pinnedBy(page, site.PinDiscussed); got != "1001,1002,1003" {
		t.Errorf("3 researchers, fill: %q", got)
	}
	st.SetPinConfig(site.PinConfig{Max: 0, MinResearchers: 2, Recent: 72 * h, Wave: 7 * day})
	page, _ = st.Hot(ctx, base)
	if pinnedOf(t, page) != "" || ids(page.Rows) != ids(all.Rows) {
		t.Errorf("pinning off: %q", ids(page.Rows))
	}
}

func TestPinConfigFromEnv(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	c, err := site.PinConfigFromEnv(env(nil))
	if err != nil || c != site.DefaultPinConfig || c.Max != 10 || c.MinResearchers != 2 || c.Recent != 72*h || c.Wave != 7*day {
		t.Fatalf("defaults %+v %v", c, err)
	}
	c, err = site.PinConfigFromEnv(env(map[string]string{site.EnvPinMax: "0", site.EnvPinResearchers: " 3 ",
		site.EnvPinRecentHours: "24", site.EnvPinWaveDays: "14"}))
	if err != nil || c != (site.PinConfig{Max: 0, MinResearchers: 3, Recent: 24 * h, Wave: 14 * day}) {
		t.Errorf("set %+v %v", c, err)
	}
	for k, v := range map[string]string{site.EnvPinMax: "21", site.EnvPinResearchers: "0", site.EnvPinRecentHours: "169",
		site.EnvPinWaveDays: "x"} {
		if _, err := site.PinConfigFromEnv(env(map[string]string{k: v})); err == nil || !strings.HasPrefix(err.Error(), k+" ") {
			t.Errorf("%s=%s: %v", k, v, err)
		}
	}
}
