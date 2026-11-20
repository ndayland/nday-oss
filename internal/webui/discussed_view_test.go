package webui

import (
	"testing"

	"nday.land/nday/internal/site"
)

func TestHeatBar(t *testing.T) {
	for _, c := range []struct{ n, top, want int }{
		{5, 5, 100}, {3, 5, 60}, {1, 3, 33}, {2, 3, 67}, {1, 200, 2}, {0, 5, 0}, {1, 0, 0}, {7, 5, 100},
	} {
		if got := heatBar(c.n, c.top); got != c.want {
			t.Errorf("heatBar(%d, %d) = %d, want %d", c.n, c.top, got, c.want)
		}
	}
}

func TestBuildSpark(t *testing.T) {
	en := loc(t, "en")
	for _, c := range []struct {
		days         [site.HeatDays]int
		trend, label string
		points       string
	}{
		// a week without posts: flat along the bottom
		{[7]int{}, "flat", "7-day trend: steady", "2.0,18.0 11.3,18.0 20.7,18.0 30.0,18.0 39.3,18.0 48.7,18.0 58.0,18.0"},
		// zero days in between; scaled to the row's busiest day
		{[7]int{4, 0, 2, 0, 0, 0, 1}, "down", "7-day trend: falling", "2.0,2.0 11.3,18.0 20.7,10.0 30.0,18.0 39.3,18.0 48.7,18.0 58.0,14.0"},
		{[7]int{0, 0, 1, 9, 0, 1, 0}, "flat", "7-day trend: steady", "2.0,18.0 11.3,18.0 20.7,16.2 30.0,2.0 39.3,18.0 48.7,16.2 58.0,18.0"},
		{[7]int{0, 1, 0, 0, 2, 0, 0}, "up", "7-day trend: rising", "2.0,18.0 11.3,10.0 20.7,18.0 30.0,18.0 39.3,2.0 48.7,18.0 58.0,18.0"},
	} {
		s := BuildSpark(en, c.days)
		if s.Trend != c.trend || s.Label != c.label || s.Points != c.points {
			t.Errorf("%v: %+v, want %s %q %s", c.days, s, c.trend, c.label, c.points)
		}
	}
	zh := loc(t, "zh-Hans")
	if s := BuildSpark(zh, [7]int{1}); s.Label != "7 天趋势：下降" {
		t.Errorf("zh label %q", s.Label)
	}
}

func TestBuildHeatRowFlagsAndFaces(t *testing.T) {
	en := loc(t, "en")
	kev, kevCode := "kev_added", "KEV"
	slots := func(codes ...string) []site.Slot {
		var out []site.Slot
		for _, st := range site.StageInfos {
			s := site.Slot{Code: st.Code, Type: st.Type, State: site.SlotNone}
			for _, c := range codes {
				if c == st.Code {
					s.State = site.SlotKnown
				}
			}
			out = append(out, s)
		}
		return out
	}
	for _, c := range []struct {
		name  string
		row   site.DiscussedRow
		class string
	}{
		{"new wins over bare", site.DiscussedRow{CVEID: "CVE-2026-1", Researchers: 1, Fresh: true}, "dz-new"},
		{"bare: no PoC, no patch", site.DiscussedRow{CVEID: "CVE-2026-1", Researchers: 1, Slots: slots("DIS", "ITW")}, "dz-bare"},
		{"a PoC: none", site.DiscussedRow{CVEID: "CVE-2026-1", Researchers: 1, Slots: slots("DIS", "POC")}, ""},
		{"a patch: none", site.DiscussedRow{CVEID: "CVE-2026-1", Researchers: 1, Slots: slots("DIS", "PAT")}, ""},
		{"rejected: never bare", site.DiscussedRow{CVEID: "CVE-2026-1", Researchers: 1, IsRejected: true, Slots: slots("DIS")}, ""},
		{"rejected stub: never bare", site.DiscussedRow{CVEID: "CVE-2026-1", Researchers: 1, IsRejected: true}, ""},
		{"new with a PoC", site.DiscussedRow{CVEID: "CVE-2026-1", Researchers: 1, Fresh: true, Slots: slots("POC")}, "dz-new"},
	} {
		if v := BuildHeatRow(en, c.row, 1, 1); v.FlagClass != c.class || (c.class == "") != (v.Flag == "") {
			t.Errorf("%s: flag %q %q, want %q", c.name, v.FlagClass, v.Flag, c.class)
		}
	}
	// faces: at most MaxFaces, never more than the count; "+N" is the rest
	f := []string{"/avatar/0000000000000001", "", "/avatar/0000000000000003", "", "/avatar/0000000000000005"}
	v := BuildHeatRow(en, site.DiscussedRow{CVEID: "CVE-2026-1", Researchers: 13, Faces: f, Stage: &kev, StageCode: &kevCode}, 51, 26)
	if len(v.Faces) != site.MaxFaces || v.More != "+9" || v.Rank != "51" || v.Bar != 50 || v.Stage != "KEV" || v.StageClass != "st-kev" ||
		v.Unit != "researchers" || v.Heat != "13" {
		t.Errorf("row %+v", v)
	}
	v = BuildHeatRow(en, site.DiscussedRow{CVEID: "CVE-2026-1", Researchers: 2, Faces: f[:3]}, 1, 2)
	if len(v.Faces) != 2 || v.More != "" {
		t.Errorf("faces beyond the count: %+v", v)
	}
	v = BuildHeatRow(en, site.DiscussedRow{CVEID: "CVE-2026-1", Researchers: 1234}, 1, 1234)
	if v.More != "+1,234" || v.Heat != "1,234" || v.Bar != 100 || v.Stage != "" {
		t.Errorf("no faces: %+v", v)
	}
}
