package webui

import (
	"encoding/json"
	"time"

	"nday.land/nday/internal/site"
)

// Fixed data scenarios for the rule-generated text: the golden tests render
// them in every enabled locale, and the catalog preview page (/__i18n/<tag>)
// shows them so a catalog writer reads every sentence in context.

// StatusScenario is one vulnerability state for StatusSentence.
type StatusScenario struct {
	Name string
	V    *site.VulnDetail
}

// EventScenario is one event for EventText.
type EventScenario struct {
	Name string
	E    site.Event
}

func scTime(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

func scInt(n int) *int       { return &n }
func scStr(s string) *string { return &s }

// StatusScenarios covers every branch of StatusMessages.
func StatusScenarios() []StatusScenario {
	exact, day := site.PrecisionExact, site.PrecisionDay
	none := func(code string) site.DetailSlot { return site.DetailSlot{Slot: site.Slot{Code: code, State: "none"}} }
	base := func() *site.VulnDetail {
		return &site.VulnDetail{
			Slots: []site.DetailSlot{none("DIS"), none("PAT"), none("ANA"), none("POC"), none("ITW"), none("KEV")},
			Poc:   []site.PocSource{{Source: "exploitdb"}, {Source: "metasploit"}, {Source: "nuclei"}},
		}
	}
	disclosed := func(v *site.VulnDetail) {
		v.Slots[iDIS] = site.DetailSlot{Slot: site.Slot{Code: "DIS", State: "known", At: scTime("2026-11-04T21:16:59Z")}, Precision: &exact, DaysSinceDisclosure: scInt(0)}
	}
	inKEV := func(v *site.VulnDetail, days *int) {
		v.Slots[iKEV] = site.DetailSlot{Slot: site.Slot{Code: "KEV", State: "known", At: scTime("2026-11-09T00:00:00Z")}, Precision: &day, DaysSinceDisclosure: days}
		v.Slots[iITW] = site.DetailSlot{Slot: site.Slot{Code: "ITW", State: "implied", NotAfter: scTime("2026-11-09T00:00:00Z")}}
	}
	patched := func(v *site.VulnDetail, fixed ...string) {
		v.Slots[iPAT] = site.DetailSlot{Slot: site.Slot{Code: "PAT", State: "unknown"}}
		p := site.Patch{}
		for i := 0; i+1 < len(fixed); i += 2 {
			p.Packages = append(p.Packages, site.Package{Name: scStr(fixed[i]), FixedVersion: scStr(fixed[i+1])})
		}
		v.Patches = append(v.Patches, p)
	}
	known := func(v *site.VulnDetail, i int, code string, days int) {
		v.Slots[i] = site.DetailSlot{Slot: site.Slot{Code: code, State: "known", At: scTime("2026-11-11T00:00:00Z")}, Precision: &day, DaysSinceDisclosure: scInt(days)}
	}
	sc := []struct {
		name  string
		setup func(v *site.VulnDetail)
	}{
		{"kev_t5_patch_0of3 (CVE-2026-102895 shape)", func(v *site.VulnDetail) { disclosed(v); inKEV(v, scInt(5)); patched(v, "gpustack", "2.2.0") }},
		{"stub_no_record_kev_no_patch", func(v *site.VulnDetail) { inKEV(v, nil) }},
		{"disclosed_only", func(v *site.VulnDetail) { disclosed(v) }},
		{"kev_same_day", func(v *site.VulnDetail) { disclosed(v); inKEV(v, scInt(0)) }},
		{"kev_1_day_after", func(v *site.VulnDetail) { disclosed(v); inKEV(v, scInt(1)) }},
		{"kev_before_record_20d", func(v *site.VulnDetail) { disclosed(v); inKEV(v, scInt(-20)) }},
		{"kev_before_record_1d", func(v *site.VulnDetail) { disclosed(v); inKEV(v, scInt(-1)) }},
		{"poc_t7_2of3", func(v *site.VulnDetail) {
			disclosed(v)
			known(v, iPOC, "POC", 7)
			v.Poc[0].Present, v.Poc[2].Present = true, true
		}},
		{"poc_t1_1of3", func(v *site.VulnDetail) {
			disclosed(v)
			known(v, iPOC, "POC", 1)
			v.Poc[1].Present = true
		}},
		{"poc_time_unknown_3of3", func(v *site.VulnDetail) {
			disclosed(v)
			v.Slots[iPOC] = site.DetailSlot{Slot: site.Slot{Code: "POC", State: "unknown"}}
			v.Poc[0].Present, v.Poc[1].Present, v.Poc[2].Present = true, true, true
		}},
		{"patch_t3_known", func(v *site.VulnDetail) { disclosed(v); patched(v, "a", "1.0.1", "b", "2.0"); known(v, iPAT, "PAT", 3) }},
		{"patch_same_day", func(v *site.VulnDetail) { disclosed(v); known(v, iPAT, "PAT", 0) }},
		{"patch_before_record_2d", func(v *site.VulnDetail) { disclosed(v); known(v, iPAT, "PAT", -2) }},
		{"analysis_t2", func(v *site.VulnDetail) { disclosed(v); known(v, iANA, "ANA", 2) }},
		{"itw_t12", func(v *site.VulnDetail) { disclosed(v); known(v, iITW, "ITW", 12) }},
		{"itw_before_record_3d", func(v *site.VulnDetail) { disclosed(v); known(v, iITW, "ITW", -3) }},
		{"patch_without_fixed_version", func(v *site.VulnDetail) { disclosed(v); patched(v) }},
		{"two_fixed_versions", func(v *site.VulnDetail) { disclosed(v); patched(v, "a", "1", "b", "2") }},
		{"many_fixed_versions", func(v *site.VulnDetail) { disclosed(v); patched(v, "a", "1", "b", "2", "c", "3", "a", "1") }},
		{"disclosure_unknown_kev_time_unknown", func(v *site.VulnDetail) {
			v.Slots[iDIS] = site.DetailSlot{Slot: site.Slot{Code: "DIS", State: "unknown"}}
			v.Slots[iKEV] = site.DetailSlot{Slot: site.Slot{Code: "KEV", State: "unknown"}}
		}},
		{"rejected", func(v *site.VulnDetail) { v.IsRejected = true; disclosed(v) }},
	}
	out := make([]StatusScenario, 0, len(sc))
	for _, s := range sc {
		v := base()
		s.setup(v)
		out = append(out, StatusScenario{Name: s.name, V: v})
	}
	return out
}

// EventScenarios covers every event type/source and detail variant.
func EventScenarios() []EventScenario {
	ev := func(source, typ, code, detail string) site.Event {
		return site.Event{Source: source, Type: typ, Code: code, Detail: json.RawMessage(detail)}
	}
	return []EventScenario{
		{"cvelist_full", ev("cvelist", "disclosed", "DIS", `{"assigner_short_name":"GitHub_M","cvss":{"base_score":9.8,"base_severity":"CRITICAL"},"ssvc":{"exploitation":"active"}}`)},
		{"cvelist_high_ssvc_poc", ev("cvelist", "disclosed", "DIS", `{"assigner_short_name":"mitre","cvss":{"base_score":7.5,"base_severity":"HIGH"},"ssvc":{"exploitation":"poc"}}`)},
		{"cvelist_medium", ev("cvelist", "disclosed", "DIS", `{"cvss":{"base_score":5.3,"base_severity":"MEDIUM"}}`)},
		{"cvelist_low", ev("cvelist", "disclosed", "DIS", `{"cvss":{"base_score":3.1,"base_severity":"LOW"}}`)},
		{"cvelist_none", ev("cvelist", "disclosed", "DIS", `{"cvss":{"base_score":0,"base_severity":"NONE"}}`)},
		{"cvelist_score_no_severity", ev("cvelist", "disclosed", "DIS", `{"assigner_short_name":"VulDB","cvss":{"base_score":6.1}}`)},
		{"cvelist_bare", ev("cvelist", "disclosed", "DIS", `{}`)},
		{"cvelist_rejected_at", ev("cvelist", "disclosed", "DIS", `{"state":"REJECTED","date_rejected":"2026-11-05T15:22:30.387Z"}`)},
		{"cvelist_rejected", ev("cvelist", "disclosed", "DIS", `{"state":"REJECTED"}`)},
		{"kev_due_forensic_ransom_unknown", ev("kev", "kev_added", "KEV", `{"due_date":"2026-11-12","forensic_triage":"Yes","known_ransomware_campaign_use":"Unknown"}`)},
		{"kev_due_ransom_known", ev("kev", "kev_added", "KEV", `{"due_date":"2026-11-30","known_ransomware_campaign_use":"Known"}`)},
		{"kev_forensic_only", ev("kev", "kev_added", "KEV", `{"forensic_triage":"Yes"}`)},
		{"kev_plain", ev("kev", "kev_added", "KEV", `{}`)},
		{"ghsa_one_fix_commit_published", ev("ghsa", "patch_released", "PAT", `{"packages":[{"name":"gpustack","first_patched_version":"2.2.0"}],"fix_commit_urls":["u"],"advisory_published_at":"2026-11-09T22:15:27Z"}`)},
		{"ghsa_two_fixes", ev("ghsa", "patch_released", "PAT", `{"packages":[{"name":"a","first_patched_version":"1.2"},{"name":"b","first_patched_version":"3.4"}]}`)},
		{"ghsa_five_fixes", ev("ghsa", "patch_released", "PAT", `{"packages":[{"name":"a","first_patched_version":"1"},{"name":"b","first_patched_version":"2"},{"name":"c","first_patched_version":"3"},{"name":"d","first_patched_version":"4"},{"name":"e","first_patched_version":"5"}]}`)},
		{"ghsa_four_fixes", ev("ghsa", "patch_released", "PAT", `{"packages":[{"name":"a","first_patched_version":"1"},{"name":"b","first_patched_version":"2"},{"name":"c","first_patched_version":"3"},{"name":"d","first_patched_version":"4"}]}`)},
		{"ghsa_no_fix", ev("ghsa", "patch_released", "PAT", `{"packages":[{"name":"gpustack-ui"}],"advisory_published_at":"2026-11-09T22:15:27Z"}`)},
		{"exploitdb_full_verified", ev("exploitdb", "poc_published", "POC", `{"title":"X 1.0 - RCE","edb_id":52001,"verified":true}`)},
		{"exploitdb_title_only", ev("exploitdb", "poc_published", "POC", `{"title":"X 1.0 - RCE"}`)},
		{"exploitdb_id_only", ev("exploitdb", "poc_published", "POC", `{"edb_id":52002}`)},
		{"exploitdb_bare", ev("exploitdb", "poc_published", "POC", `{}`)},
		{"metasploit_full", ev("metasploit", "poc_published", "POC", `{"fullname":"exploit/linux/http/x_rce","title":"X Unauthenticated RCE"}`)},
		{"metasploit_name", ev("metasploit", "poc_published", "POC", `{"fullname":"exploit/linux/http/x_rce"}`)},
		{"metasploit_title", ev("metasploit", "poc_published", "POC", `{"title":"X Unauthenticated RCE"}`)},
		{"metasploit_bare", ev("metasploit", "poc_published", "POC", `{}`)},
		{"nuclei_full", ev("nuclei", "poc_published", "POC", `{"template_id":"CVE-2026-1","title":"X - Auth Bypass"}`)},
		{"nuclei_id", ev("nuclei", "poc_published", "POC", `{"template_id":"CVE-2026-1"}`)},
		{"nuclei_title", ev("nuclei", "poc_published", "POC", `{"title":"X - Auth Bypass"}`)},
		{"nuclei_bare", ev("nuclei", "poc_published", "POC", `{}`)},
		{"generic_itw", ev("x", "exploited_in_wild", "ITW", `not json`)},
		{"generic_ana", ev("blog", "analysis_published", "ANA", `{}`)},
		{"generic_dis", ev("osv", "disclosed", "DIS", `{}`)},
		{"generic_pat", ev("vendor", "patch_released", "PAT", `{}`)},
		{"generic_poc", ev("github", "poc_published", "POC", `{}`)},
		{"generic_kev", ev("mirror", "kev_added", "KEV", `{}`)},
		{"generic_unknown_stage", ev("y", "weird", "XYZ", `{}`)},
	}
}
