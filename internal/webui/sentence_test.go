package webui

import (
	"testing"

	"nday.land/nday/internal/site"
)

func TestStatusSentence(t *testing.T) {
	exact, day := site.PrecisionExact, site.PrecisionDay
	none := func(code string) site.DetailSlot { return site.DetailSlot{Slot: site.Slot{Code: code, State: "none"}} }
	base := func() *site.VulnDetail {
		return &site.VulnDetail{
			Slots: []site.DetailSlot{none("DIS"), none("PAT"), none("ANA"), none("POC"), none("ITW"), none("KEV")},
			Poc:   []site.PocSource{{Source: "exploitdb"}, {Source: "metasploit"}, {Source: "nuclei"}},
		}
	}
	disclosed := func(v *site.VulnDetail) {
		v.Slots[iDIS] = site.DetailSlot{Slot: site.Slot{Code: "DIS", State: "known", At: tp("2026-11-04T21:16:59Z")}, Precision: &exact, DaysSinceDisclosure: ip(0)}
	}
	inKEV := func(v *site.VulnDetail, days *int) {
		v.Slots[iKEV] = site.DetailSlot{Slot: site.Slot{Code: "KEV", State: "known", At: tp("2026-11-09T00:00:00Z")}, Precision: &day, DaysSinceDisclosure: days}
		v.Slots[iITW] = site.DetailSlot{Slot: site.Slot{Code: "ITW", State: "implied", NotAfter: tp("2026-11-09T00:00:00Z")}}
	}
	patched := func(v *site.VulnDetail, fixed ...string) {
		v.Slots[iPAT] = site.DetailSlot{Slot: site.Slot{Code: "PAT", State: "unknown"}}
		p := site.Patch{}
		for i := 0; i+1 < len(fixed); i += 2 {
			p.Packages = append(p.Packages, site.Package{Name: sp(fixed[i]), FixedVersion: sp(fixed[i+1])})
		}
		v.Patches = append(v.Patches, p)
	}

	cases := []struct {
		name  string
		setup func(v *site.VulnDetail)
		want  string
	}{
		{"mockup: KEV T+5, patch, 0/3", func(v *site.VulnDetail) { disclosed(v); inKEV(v, ip(5)); patched(v, "gpustack", "2.2.0") },
			"披露后第 5 天进入 KEV。已有补丁记录，修复版本是 gpustack 2.2.0。三个 PoC 库都还没有收录。"},
		{"stub: no record, KEV, no patch", func(v *site.VulnDetail) { inKEV(v, nil) },
			"本站还没有取到这个编号的官方 CVE 记录，披露时间未知。2026-11-09 进入 CISA KEV。本站尚未获取修复依据，不能据此认为没有补丁。三个 PoC 库都还没有收录。"},
		{"disclosed only", func(v *site.VulnDetail) { disclosed(v) },
			"披露于 2026-11-04T21:16Z。本站尚未获取修复依据，不能据此认为没有补丁。三个 PoC 库都还没有收录。尚未列入 CISA KEV。"},
		{"KEV same day", func(v *site.VulnDetail) { disclosed(v); inKEV(v, ip(0)) },
			"披露当天进入 KEV。本站尚未获取修复依据，不能据此认为没有补丁。三个 PoC 库都还没有收录。"},
		{"KEV before CVE record", func(v *site.VulnDetail) { disclosed(v); inKEV(v, ip(-20)) },
			"进入 KEV 早于 CVE 记录发布 20 天。本站尚未获取修复依据，不能据此认为没有补丁。三个 PoC 库都还没有收录。"},
		{"PoC 2/3 with day count", func(v *site.VulnDetail) {
			disclosed(v)
			v.Slots[iPOC] = site.DetailSlot{Slot: site.Slot{Code: "POC", State: "known", At: tp("2026-11-11T00:00:00Z")}, Precision: &day, DaysSinceDisclosure: ip(7)}
			v.Poc[0].Present, v.Poc[2].Present = true, true
		}, "披露后第 7 天出现公开 PoC。本站尚未获取修复依据，不能据此认为没有补丁。PoC 库中 exploitdb、nuclei 已收录（2/3）。尚未列入 CISA KEV。"},
		{"PoC 3/3, time unknown", func(v *site.VulnDetail) {
			disclosed(v)
			v.Slots[iPOC] = site.DetailSlot{Slot: site.Slot{Code: "POC", State: "unknown"}}
			v.Poc[0].Present, v.Poc[1].Present, v.Poc[2].Present = true, true, true
		}, "披露于 2026-11-04T21:16Z。本站尚未获取修复依据，不能据此认为没有补丁。三个 PoC 库都已收录。尚未列入 CISA KEV。"},
		{"patch without fixed version", func(v *site.VulnDetail) { disclosed(v); patched(v) },
			"披露于 2026-11-04T21:16Z。已有补丁记录，但来源没有给出修复版本。三个 PoC 库都还没有收录。尚未列入 CISA KEV。"},
		{"many fixed versions", func(v *site.VulnDetail) { disclosed(v); patched(v, "a", "1", "b", "2", "c", "3", "a", "1") },
			"披露于 2026-11-04T21:16Z。已有补丁记录，修复版本有 a 1、b 2 等 3 个。三个 PoC 库都还没有收录。尚未列入 CISA KEV。"},
		{"disclosure time unknown, KEV time unknown", func(v *site.VulnDetail) {
			v.Slots[iDIS] = site.DetailSlot{Slot: site.Slot{Code: "DIS", State: "unknown"}}
			v.Slots[iKEV] = site.DetailSlot{Slot: site.Slot{Code: "KEV", State: "unknown"}}
		}, "披露时间未知。已列入 CISA KEV，列入时间未知。本站尚未获取修复依据，不能据此认为没有补丁。三个 PoC 库都还没有收录。"},
		// a rejected ID: no "nothing on record" boilerplate about patch, PoC or KEV
		{"rejected", func(v *site.VulnDetail) { v.IsRejected = true; disclosed(v) },
			"该编号已被 CVE 拒绝（REJECTED），不是有效漏洞。披露于 2026-11-04T21:16Z。"},
		// ... but records that exist are still said
		{"rejected with patch, PoC and KEV", func(v *site.VulnDetail) {
			v.IsRejected = true
			disclosed(v)
			inKEV(v, ip(5))
			patched(v, "a", "1")
			v.Poc[0].Present = true
		}, "该编号已被 CVE 拒绝（REJECTED），不是有效漏洞。披露后第 5 天进入 KEV。已有补丁记录，修复版本是 a 1。PoC 库中 exploitdb 已收录（1/3）。"},
	}
	for _, c := range cases {
		v := base()
		c.setup(v)
		if got := StatusSentence(loc(t, "zh-Hans"), v); got != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, got, c.want)
		}
	}
	if StatusSentence(loc(t, "zh-Hans"), nil) != "" {
		t.Error("nil")
	}
}
