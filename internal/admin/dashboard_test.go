package admin_test

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestDashboardEmpty: no statistics at all (the roll-up never ran) and no
// community data: the page says so and still renders every section.
func TestDashboardEmpty(t *testing.T) {
	h := newHarness(t, hopt{})
	adm := h.user("kim", "admin")
	d, err := h.adm.Dashboard(context.Background(), 30)
	if err != nil {
		t.Fatal(err)
	}
	if d.HasStats || d.LastRollup != nil || d.RolledDays != 0 || len(d.PageViews) != 30 || d.Range.PageViews != 0 {
		t.Errorf("empty dashboard: %+v", d)
	}
	for _, p := range d.PageViews {
		if !p.Gap {
			t.Errorf("%s: no statistics but not a gap", p.Day)
		}
	}
	if d.Range.NewAccounts != 1 || d.Today.NewAccounts != 1 { // kim signed up today
		t.Errorf("accounts: %+v", d.Range)
	}
	_, body := adm.do("GET", "/admin?days=30", "")
	s := string(body)
	if strings.Contains(s, "adm-map-svg") || !strings.Contains(s, `id="h-map"`) {
		t.Error("empty map: no SVG, the section with its empty note")
	}
	for _, want := range []string{"never been rolled up", `id="ch-pv"`, `id="t-vuln"`, "nothing yet", `aria-current="true">last 30 days`} {
		if !strings.Contains(s, want) {
			t.Errorf("empty page lacks %q", want)
		}
	}
	for _, q := range []string{"?days=8", "?days=-1", "?days=x", "?days=99999"} { // anything else is the default range
		if resp, body := adm.do("GET", "/admin"+q, ""); resp.StatusCode != 200 || !strings.Contains(string(body), `aria-current="true">last 7 days`) {
			t.Errorf("%s: %d", q, resp.StatusCode)
		}
	}
}

// TestDashboardPartialDaysAndGaps: days with statistics, days without (a
// gap, not a zero), today partial; community numbers bucketed by the
// server's local day.
func TestDashboardPartialDaysAndGaps(t *testing.T) {
	sg, err := time.LoadLocation("Asia/Singapore")
	if err != nil {
		t.Skip("no tz database:", err)
	}
	h := newHarness(t, hopt{loc: sg})
	adm := h.user("kim", "admin")
	// the clock is 2026-11-13 12:00 UTC = 20:00 in Singapore: today is 11-13
	for _, d := range []string{"2026-11-13", "2026-11-11", "2026-11-10"} { // 11-12 is missing
		h.sql(`INSERT INTO stats_daily (day, metric, dim, value) VALUES ($1, 'pv', 'all', 100), ($1, 'pv', 'human', 60),
			($1, 'uv', 'all', 40), ($1, 'uv', 'human', 30), ($1, 'api', 'all', 7), ($1, 'req', 'all', 200), ($1, 'req', 'bot', 50),
			($1, 'req_status', 'all:2xx', 180), ($1, 'req_status', 'all:4xx', 20), ($1, 'pv_locale', 'all:zh-hans', 70),
			($1, 'pv_locale', 'all:en', 30), ($1, 'api_endpoint', 'all:hot', 7)`, d)
		h.sql(`INSERT INTO stats_files (file, day, size, mtime, lines, bad_lines, rolled_at) VALUES ($1, $2, 1, now(), 200, 0, $3)`,
			"access-"+d+".log", d, h.clock.Now())
		h.sql(`INSERT INTO stats_top (day, kind, key, value) VALUES ($1, 'vuln_page', 'CVE-2026-0001', 9), ($1, 'search', 'openssl', 3)`, d)
		// the map reads country_human (more codes than a top list holds); the list reads country
		h.sql(`INSERT INTO stats_top (day, kind, key, value) VALUES ($1, 'country', 'US', 99), ($1, 'country_human', 'SG', 5),
			($1, 'country_human', 'T1', 2)`, d)
		for _, cc := range strings.Fields("AR AT AU BE BR CA CH CN DE ES FI FR GB IN IT JP KR NL NO SE") {
			h.sql(`INSERT INTO stats_top (day, kind, key, value) VALUES ($1, 'country_human', $2, 1)`, d, cc)
		}
	}
	// accounts: 15:59 UTC is 23:59 in Singapore (11-12), 16:01 UTC is 00:01 (11-13)
	h.sql(`INSERT INTO users (created_at, last_seen_at) VALUES ('2026-11-12T15:59:00Z', now()), ('2026-11-12T16:01:00Z', now())`)
	d, err := h.adm.Dashboard(context.Background(), 7)
	if err != nil {
		t.Fatal(err)
	}
	if d.To.Format("2006-01-02") != "2026-11-13" || d.From.Format("2006-01-02") != "2026-11-07" || d.RolledDays != 3 || !d.HasStats {
		t.Fatalf("range %s..%s rolled %d", d.From, d.To, d.RolledDays)
	}
	gaps := ""
	for _, p := range d.PageViews {
		if p.Gap {
			gaps += p.Day.Format("01-02") + " "
		}
	}
	if gaps != "11-07 11-08 11-09 11-12 " {
		t.Errorf("gaps: %s", gaps)
	}
	if d.Range.PageViews != 300 || d.Today.PageViews != 100 || d.Range.HumanVisitors != 90 || d.Requests != 600 || d.BotRequests != 150 {
		t.Errorf("sums: %+v %d %d", d.Range, d.Requests, d.BotRequests)
	}
	acc := map[string]int64{}
	for _, p := range d.NewAccounts {
		acc[p.Day.Format("01-02")] = p.V
	}
	if acc["11-12"] != 1 || acc["11-13"] != 2 { // the 16:01 one and kim (12:00 UTC = 20:00 local)
		t.Errorf("accounts by local day: %v", acc)
	}
	if len(d.TopVulns) != 1 || d.TopVulns[0].Value != 27 || len(d.Locales) != 2 || d.Locales[0].Key != "zh-hans" {
		t.Errorf("tops: %+v %+v", d.TopVulns, d.Locales)
	}
	if len(d.Countries) != 1 || d.Countries[0].Key != "US" || len(d.CountriesHuman) != 22 || d.CountriesHuman[0].Key != "SG" ||
		d.CountriesHuman[0].Value != 15 {
		t.Errorf("countries: %+v human %+v", d.Countries, d.CountriesHuman)
	}
	_, body := adm.do("GET", "/admin?days=7", "")
	s := string(body)
	for _, want := range []string{`id="h-map"`, "page views by people, by country, last 7 days", "<title>SG: 15</title>",
		"<title>SE: 3</title>", `data-cc="US" data-n="0" data-tip="US: no page views by people"`,
		`class="adm-map-tip"`, "<bdi>T1</bdi>: 6"} {
		if !strings.Contains(s, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, want := range []string{"3 of the 7 days have statistics", "Asia/Singapore", `href="/vuln/CVE-2026-0001"`, "25.0%", "简体中文",
		`class="gap"`, "2026-11-12: no statistics"} {
		if !strings.Contains(s, want) {
			t.Errorf("page lacks %q", want)
		}
	}
}
