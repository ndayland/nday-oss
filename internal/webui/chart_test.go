package webui

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
)

func pctOf(s string) float64 {
	v, _ := strconv.ParseFloat(strings.TrimSuffix(s, "%"), 64)
	return v
}

func checkScale(t *testing.T, name string, s Scale, now time.Time) {
	t.Helper()
	if len(s.Ticks) == 0 || len(s.Ticks) > MaxTicks {
		t.Errorf("%s: %d ticks", name, len(s.Ticks))
	}
	if s.NowPct < 90 || s.NowPct > 99.5 {
		t.Errorf("%s: now at %.2f%%", name, s.NowPct)
	}
	if !s.Start.Before(now) || !s.End.After(now) {
		t.Errorf("%s: range %v..%v", name, s.Start, s.End)
	}
	// Visible labels never overlap each other or the "now" label (judged at
	// the narrowest plot width).
	prevRight := -1.0
	for _, tk := range s.Ticks {
		if tk.Pct < 0 || tk.Pct > 100 {
			t.Errorf("%s: tick at %.2f", name, tk.Pct)
		}
		if tk.Label == "" {
			continue
		}
		left := Px(tk.Pct) + tickLabelDX
		if left < prevRight+4 {
			t.Errorf("%s: label %q collides", name, tk.Label)
		}
		prevRight = left + float64(len(tk.Label))*charPx
		if prevRight > Px(s.NowPct)-nowLabelPx {
			t.Errorf("%s: label %q collides with now", name, tk.Label)
		}
	}
}

func TestComputeScale(t *testing.T) {
	now := time.Date(2026, 11, 13, 2, 30, 0, 0, time.UTC)
	cases := []struct {
		name     string
		earliest time.Time
		unit     string
	}{
		{"5 days ago", time.Date(2026, 11, 8, 21, 16, 0, 0, time.UTC), "day"},
		{"9 days (mockup)", time.Date(2026, 11, 4, 21, 16, 0, 0, time.UTC), "day"},
		{"same day", now.Add(-time.Hour), "day"},
		{"future (clock skew)", now.Add(48 * time.Hour), "day"},
		{"6 weeks", now.AddDate(0, 0, -42), "week"},
		{"5 months", now.AddDate(0, -5, 0), "month"},
		{"2 years", now.AddDate(-2, 0, 0), "quarter"},
		{"2014", time.Date(2014, 3, 2, 0, 0, 0, 0, time.UTC), "2year"},
		{"2003", time.Date(2003, 4, 2, 5, 0, 0, 0, time.UTC), "5year"},
		{"1988", time.Date(1988, 1, 1, 0, 0, 0, 0, time.UTC), "5year"},
	}
	for _, c := range cases {
		s := ComputeScale(c.earliest, now)
		if s.Unit != c.unit {
			t.Errorf("%s: unit %s want %s (%d ticks)", c.name, s.Unit, c.unit, len(s.Ticks))
		}
		checkScale(t, c.name, s, now)
		e := c.earliest
		if e.After(now) {
			e = now
		}
		if p := s.Pct(e); p < 0 || p > 100 {
			t.Errorf("%s: earliest at %.2f", c.name, p)
		}
	}
	// A week minimum: a vuln disclosed an hour ago still gets 7+ day columns.
	s := ComputeScale(now.Add(-time.Hour), now)
	if len(s.Ticks) < 7 {
		t.Errorf("short span: %d ticks", len(s.Ticks))
	}
	// Labels by unit.
	if s.Ticks[1].Label == "" || len(s.Ticks[1].Label) != 5 {
		t.Errorf("day label %q", s.Ticks[1].Label)
	}
	y := ComputeScale(time.Date(2014, 3, 2, 0, 0, 0, 0, time.UTC), now)
	if y.Ticks[0].Label != "2014" || y.Ticks[1].Label != "2016" {
		t.Errorf("year labels %q %q", y.Ticks[0].Label, y.Ticks[1].Label)
	}
	if s.Pct(s.Start.Add(-time.Hour)) != 0 || s.Pct(s.End.Add(time.Hour)) != 100 {
		t.Error("Pct does not clamp")
	}
}

func TestChartMarksMinimumSize(t *testing.T) {
	now := time.Date(2026, 11, 13, 2, 30, 0, 0, time.UTC)
	// Short span: a day is wide -> percentage bar.
	s := ComputeScale(time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC), now)
	m, l, r := placeMark(s, markSpec{at: time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC), precision: "day"})
	if m.Kind != "bar" || pctOf(m.W) < 8 || r.at()-l.at() < minBarPx {
		t.Errorf("short day bar %+v", m)
	}
	// Twelve years: a day is ~0.14px -> fixed-width pin.
	s = ComputeScale(time.Date(2014, 1, 1, 0, 0, 0, 0, time.UTC), now)
	m, l, r = placeMark(s, markSpec{at: time.Date(2020, 5, 1, 0, 0, 0, 0, time.UTC), precision: "day"})
	if m.Kind != "pin" || r.at()-l.at() != minBarPx {
		t.Errorf("long day bar %+v", m)
	}
	// Exact time is a 12px point regardless of scale.
	m, l, r = placeMark(s, markSpec{at: time.Date(2020, 5, 1, 13, 0, 0, 0, time.UTC), precision: "exact"})
	if m.Kind != "point" || r.at()-l.at() != 12 {
		t.Errorf("point %+v", m)
	}
	// Label placement: near "now" it flips to the left of the mark.
	row := buildRow(loc(t, "zh-Hans"), s, ChartRow{}, []markSpec{{at: now.Add(-24 * time.Hour), precision: "day", text: "11-12 日精度"}})
	if row.Label == nil || row.Label.Anchor != "end" {
		t.Errorf("label near now %+v", row.Label)
	}
	row = buildRow(loc(t, "zh-Hans"), s, ChartRow{}, []markSpec{{at: time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC), precision: "exact", text: "x"},
		{at: time.Date(2016, 1, 1, 0, 0, 0, 0, time.UTC), precision: "exact"}})
	if row.Label == nil || row.Label.Anchor != "start" || row.Label.Text != "x 等 2 条" || row.Label.DX != "14" {
		t.Errorf("label %+v", row.Label)
	}
}

func TestBuildChart(t *testing.T) {
	now := time.Date(2026, 11, 13, 2, 30, 0, 0, time.UTC)
	v := gpuDetail()
	c := BuildChart(loc(t, "zh-Hans"), v, now)
	if len(c.Rows) != 6 {
		t.Fatalf("rows %d", len(c.Rows))
	}
	dis, pat, ana, itw, kev := c.Rows[0], c.Rows[1], c.Rows[2], c.Rows[4], c.Rows[5]
	if len(dis.Marks) != 1 || dis.Marks[0].Kind != "point" || dis.Label == nil || dis.Label.Text != "11-04T21:16Z" {
		t.Errorf("DIS %+v %+v", dis, dis.Label)
	}
	if len(pat.Marks) != 0 || strings.Join(pat.Unknown, ",") != "gpustack 2.2.0" || !pat.UnknownHollow {
		t.Errorf("PAT %+v", pat)
	}
	if !ana.Empty {
		t.Errorf("ANA %+v", ana)
	}
	if len(itw.Marks) != 1 || !itw.Marks[0].Hollow || itw.Label.Text != "≤ 11-09，由 KEV 推定" {
		t.Errorf("ITW %+v %+v", itw, itw.Label)
	}
	if len(kev.Marks) != 1 || kev.Marks[0].Kind != "bar" || !kev.Marks[0].Latest || kev.Label.Text != "11-09 日精度" {
		t.Errorf("KEV %+v %+v", kev, kev.Label)
	}
	// Old vulnerability: labels carry the year.
	old := gpuDetail()
	at := time.Date(2014, 3, 2, 14, 0, 0, 0, time.UTC)
	old.Events[0].EffectiveAt, old.Events[0].OccurredAt = &at, &at
	c = BuildChart(loc(t, "zh-Hans"), old, now)
	if c.Rows[0].Label.Text != "2014-03-02T14:00Z" || c.Scale.Unit != "2year" {
		t.Errorf("old: %+v %s", c.Rows[0].Label, c.Scale.Unit)
	}
	if c.Rows[5].Marks[0].Kind != "pin" {
		t.Errorf("old KEV should be a pin: %+v", c.Rows[5].Marks[0])
	}
}

// gpuDetail is CVE-2026-102895 as the store returns it (trimmed).
func gpuDetail() *site.VulnDetail {
	dis := tp("2026-11-04T21:16:59Z")
	kev := tp("2026-11-09T00:00:00Z")
	exact, day := site.PrecisionExact, site.PrecisionDay
	unknown := site.PrecisionUnknown
	return &site.VulnDetail{
		CVEID: "CVE-2026-102895", Title: sp("GPUStack: Authentication bypass"),
		Slots: []site.DetailSlot{
			{Slot: site.Slot{Code: "DIS", State: "known", At: dis}, Precision: &exact, DaysSinceDisclosure: ip(0)},
			{Slot: site.Slot{Code: "PAT", State: "unknown"}, Precision: &unknown},
			{Slot: site.Slot{Code: "ANA", State: "none"}},
			{Slot: site.Slot{Code: "POC", State: "none"}},
			{Slot: site.Slot{Code: "ITW", State: "implied", NotAfter: kev, ImpliedBy: sp("kev_added")}},
			{Slot: site.Slot{Code: "KEV", State: "known", At: kev, Latest: true}, Precision: &day, DaysSinceDisclosure: ip(5)},
		},
		Transition:          &site.Transition{Type: "kev_added", Code: "KEV", At: *kev, Precision: day},
		DaysSinceDisclosure: ip(5),
		Events: []site.Event{
			{ID: 4012, Type: "disclosed", Code: "DIS", Source: "cvelist", OccurredAt: dis, EffectiveAt: dis, Precision: exact, IsBackfill: true},
			{ID: 7, Type: "kev_added", Code: "KEV", Source: "kev", OccurredAt: kev, EffectiveAt: kev, Precision: day, IsBackfill: true},
			{ID: 18977, Type: "patch_released", Code: "PAT", Source: "ghsa", Precision: unknown, IsBackfill: true, DedupeKey: "GHSA-gj9m-f8ph-pmhr"},
		},
		Patches: []site.Patch{{EventID: 18977, Source: "ghsa", Packages: []site.Package{{Ecosystem: sp("pip"), Name: sp("gpustack"),
			AffectedRange: sp("< 2.2.0"), FixedVersion: sp("2.2.0")}}}},
		Poc: []site.PocSource{{Source: "exploitdb"}, {Source: "metasploit"}, {Source: "nuclei"}},
		KEV: &site.KEVFacts{EventID: 7, DueDate: sp("2026-11-12")},
	}
}
