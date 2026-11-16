package webui

import (
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
)

// Unknown states are told apart: no CVE
// record yet vs a record without a title or description; no score vs a
// score of 0; no fix record vs "no patch"; a rejected ID without the risk
// and fix boilerplate.

func TestRowTitleStates(t *testing.T) {
	zh := loc(t, "zh-Hans")
	none := site.Slot{Code: "DIS", State: site.SlotNone}
	known := site.Slot{Code: "DIS", State: site.SlotKnown}
	for _, c := range []struct {
		name  string
		rec   int
		title string
	}{
		{"no slots", slotsRecord(nil), "等待官方记录回填"},
		{"DIS none", slotsRecord([]site.Slot{none}), "等待官方记录回填"},
		{"DIS known", slotsRecord([]site.Slot{known}), "上游未提供标题"},
		{"search row", recordUnknown, "无标题"},
	} {
		title, missing, _ := rowTitle(zh, nil, sp(" "), c.rec)
		if title != c.title || !missing {
			t.Errorf("%s: %q %v, want %q", c.name, title, missing, c.title)
		}
	}
	if title, missing, _ := rowTitle(zh, nil, sp("x"), recordMissing); title != "x" || missing {
		t.Errorf("a title is shown whatever the record state: %q %v", title, missing)
	}
	en := loc(t, "en")
	if title, _, _ := rowTitle(en, nil, nil, recordPresent); strings.Contains(title, "not fetched") {
		t.Errorf("record present but untitled says the record is missing: %q", title)
	}
}

func TestVulnUnknownStates(t *testing.T) {
	zh := loc(t, "zh-Hans")
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	exact := site.PrecisionExact
	base := func(record bool) *site.VulnDetail {
		ns := func(c string) site.DetailSlot { return site.DetailSlot{Slot: site.Slot{Code: c, State: site.SlotNone}} }
		v := &site.VulnDetail{CVEID: "CVE-2026-9",
			Slots: []site.DetailSlot{ns("DIS"), ns("PAT"), ns("ANA"), ns("POC"), ns("ITW"), ns("KEV")},
			Poc:   []site.PocSource{{Source: "exploitdb"}, {Source: "metasploit"}, {Source: "nuclei"}}}
		if record {
			v.Slots[iDIS] = site.DetailSlot{Slot: site.Slot{Code: "DIS", State: site.SlotKnown, At: tp("2026-11-04T21:16:59Z")},
				Precision: &exact, DaysSinceDisclosure: ip(0)}
		}
		return v
	}
	build := func(v *site.VulnDetail) VulnView { return BuildVulnView(zh, v, now, NewAPI("https://nday.land", "")) }
	cvss := func(vv VulnView) (Fact, bool) {
		for _, f := range vv.Facts {
			if f.Label == zh.Text("fact.cvss") {
				return f, true
			}
		}
		return Fact{}, false
	}

	// no record yet: waiting for it
	vv := build(base(false))
	if vv.HasRecord || vv.Title != "（等待官方 CVE 记录回填）" {
		t.Errorf("no record: %v %q", vv.HasRecord, vv.Title)
	}
	// a record without title or description
	vv = build(base(true))
	if !vv.HasRecord || vv.Title != "（上游 CVE 记录未提供标题）" || vv.Summary != "" {
		t.Errorf("record without title: %v %q", vv.HasRecord, vv.Title)
	}
	// no score: "暂无评分", never "0"
	if f, ok := cvss(vv); !ok || f.Value != "暂无评分" || f.Class != "weak" {
		t.Errorf("no score: %+v %v", f, ok)
	}
	// a score of 0 is a score
	v := base(true)
	v.CVSS = &site.CVSS{Score: new(float64), Severity: sp("NONE")}
	if f, ok := cvss(build(v)); !ok || f.Value != "0.0 NONE" {
		t.Errorf("score 0: %+v %v", f, ok)
	}
	// no fix record: says it does not mean there is no patch
	if s := build(base(true)).Sentence; !strings.Contains(s, "本站尚未获取修复依据，不能据此认为没有补丁。") {
		t.Errorf("no fix record: %s", s)
	}
	// rejected: no CVSS row, no risk/fix boilerplate in the sentence
	v = base(true)
	v.IsRejected = true
	vv = build(v)
	if _, ok := cvss(vv); ok || vv.Rejected == nil {
		t.Errorf("rejected: CVSS fact %v, banner %v", ok, vv.Rejected != nil)
	}
	for _, s := range []string{"补丁", "PoC", "KEV"} {
		if strings.Contains(vv.Sentence, s) {
			t.Errorf("rejected sentence says %q: %s", s, vv.Sentence)
		}
	}
	// en: none of the texts concludes "no patch" / "safe" from missing records
	en := loc(t, "en")
	for _, k := range []string{"status.patch.none", "vuln.fix.none", "vuln.fix.unfixed", "rsch.empty", "fact.cvss_none"} {
		txt := strings.ToLower(en.Text(k))
		for _, bad := range []string{"unfixed", "not exploited", "safe"} {
			if strings.Contains(txt, bad) {
				t.Errorf("%s: %q", k, txt)
			}
		}
	}
}
