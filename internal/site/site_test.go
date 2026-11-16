package site_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/testutil"
)

var ctx = context.Background()

func seeded(t *testing.T) (*site.Store, *testutil.TestDB, sitetest.Fixture) {
	t.Parallel()
	d := testutil.NewMigratedDB(t)
	f := sitetest.Seed(t, d.Conn)
	return site.New(site.SingleConn(d.Conn)).WithClock(func() time.Time { return sitetest.Now }), d, f
}

func ids(rows []site.HotRow) string {
	s := make([]string, len(rows))
	for i, r := range rows {
		s[i] = strings.TrimPrefix(r.CVEID, "CVE-2026-")
	}
	return strings.Join(s, ",")
}

func slotCodes(s []site.Slot) string {
	out := ""
	for _, x := range s {
		c := map[string]string{"none": "-", "known": "K", "unknown": "U", "implied": "I"}[x.State]
		if x.Latest {
			c = strings.ToLower(c)
		}
		out += c
	}
	return out
}

func TestHotOrderFiltersAndRows(t *testing.T) {
	st, _, _ := seeded(t)
	month := 30 * 24 * time.Hour
	page, err := st.Hot(ctx, site.HotParams{Since: month, MinStage: "patch"})
	if err != nil {
		t.Fatal(err)
	}
	// Newest transition first; 1007/1008 tie (same time, same rank) -> cve_id desc.
	if got := ids(page.Rows); got != "1001,1002,1003,102895,1008,1007,1009" {
		t.Errorf("order %s", got)
	}
	if page.Since != "30d" || page.MinStage != "patch_released" || page.MinStageCode != "PAT" || page.NextCursor != nil ||
		!page.SinceStart.Equal(sitetest.Now.Add(-month)) {
		t.Errorf("page %+v", page)
	}
	byID := map[string]site.HotRow{}
	for _, r := range page.Rows {
		byID[r.CVEID] = r
	}
	g := byID[sitetest.GPU]
	if slotCodes(g.Slots) != "KU-KIk" || g.Stage != "kev_added" || g.StageCode != "KEV" || g.PocSources != 3 {
		t.Errorf("GPU row %s %+v", slotCodes(g.Slots), g)
	}
	if g.Transition.Type != "kev_added" || g.Transition.Code != "KEV" || g.Transition.Precision != "day" ||
		*g.Transition.Source != "kev" || !g.Transition.At.Equal(sitetest.Day(2026, 11, 9)) {
		t.Errorf("GPU transition %+v", g.Transition)
	}
	if g.DaysSinceDisclosure == nil || *g.DaysSinceDisclosure != 5 || g.DisclosedAt == nil {
		t.Errorf("T+ %v", g.DaysSinceDisclosure)
	}
	if !g.Slots[4].NotAfter.Equal(sitetest.Day(2026, 11, 9)) {
		t.Errorf("ITW bound %+v", g.Slots[4])
	}
	if g.ProductCount != 1 || len(g.Products) != 1 || g.Products[0] != (site.Product{Vendor: "GPUStack", Product: "GPUStack"}) {
		t.Errorf("products %+v %d", g.Products, g.ProductCount)
	}
	b := byID["CVE-2026-1001"] // three products, no title, no disclosure
	if b.ProductCount != 3 || len(b.Products) != 2 || b.Products[1].Product != "Load Balancer ADC" || b.Title != nil ||
		b.DisclosedAt != nil || b.DaysSinceDisclosure != nil || slotCodes(b.Slots) != "----Ik" {
		t.Errorf("1001 %+v %s", b, slotCodes(b.Slots))
	}
	if r := byID["CVE-2026-1003"]; r.Transition.Precision != "exact" || *r.TitleZh != "cowlib 响应拆分" || slotCodes(r.Slots) != "-k----" {
		t.Errorf("1003 %+v", r)
	}
	if r := byID["CVE-2026-1009"]; slotCodes(r.Slots) != "----Uk" {
		t.Errorf("1009 real ITW with unknown time must be unknown, not implied: %s", slotCodes(r.Slots))
	}

	// Observed-live transition; min_stage filter; rejected; window.
	p2, _ := st.Hot(ctx, site.HotParams{Since: month, MinStage: "poc"})
	if got := ids(p2.Rows); got != "1001,1002,102895,1008,1007,1009" {
		t.Errorf("poc+ %s", got)
	}
	for _, r := range p2.Rows {
		if r.CVEID == "CVE-2026-1002" && (r.Transition.Precision != "observed" || *r.Transition.Source != "metasploit" ||
			*r.DaysSinceDisclosure != 7) {
			t.Errorf("observed %+v", r.Transition)
		}
	}
	p3, _ := st.Hot(ctx, site.HotParams{Since: month, MinStage: "disclosed", IncludeRejected: true})
	if got := ids(p3.Rows); got != "1005,1004,1001,1002,1003,102895,1008,1007,1009" {
		t.Errorf("all %s", got)
	}
	p4, _ := st.Hot(ctx, site.HotParams{Since: 366 * 24 * time.Hour, MinStage: "patch"})
	if !strings.HasSuffix(ids(p4.Rows), ",1006") {
		t.Errorf("year %s", ids(p4.Rows))
	}
	p5, _ := st.Hot(ctx, site.HotParams{Since: 24 * time.Hour, MinStage: "kev"})
	if ids(p5.Rows) != "" {
		t.Errorf("24h kev %s", ids(p5.Rows))
	}
}

func TestHotPaging(t *testing.T) {
	st, _, _ := seeded(t)
	p := site.HotParams{Since: 30 * 24 * time.Hour, MinStage: "disclosed", IncludeRejected: true, Limit: 2}
	full, _ := st.Hot(ctx, site.HotParams{Since: p.Since, MinStage: p.MinStage, IncludeRejected: true})
	var got []string
	pages := 0
	for {
		page, err := st.Hot(ctx, p)
		if err != nil {
			t.Fatal(err)
		}
		pages++
		got = append(got, ids(page.Rows))
		if page.NextCursor == nil {
			break
		}
		p.Cursor = *page.NextCursor
	}
	if strings.Join(got, ",") != ids(full.Rows) || pages != 5 {
		t.Errorf("cursor pages %v vs %s", got, ids(full.Rows))
	}
	off, _ := st.Hot(ctx, site.HotParams{Since: p.Since, MinStage: "disclosed", IncludeRejected: true, Limit: 3, Offset: 3})
	if ids(off.Rows) != strings.Join(strings.Split(ids(full.Rows), ",")[3:6], ",") {
		t.Errorf("offset %s", ids(off.Rows))
	}
	for _, bad := range []site.HotParams{{Limit: 201}, {Limit: -1}, {Offset: -1}, {Offset: 10001}, {Cursor: "zz"}, {MinStage: "x"}, {Since: time.Minute}} {
		var ie *site.InputError
		if _, err := st.Hot(ctx, bad); !errors.As(err, &ie) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
}

func TestVulnDetailAllSources(t *testing.T) {
	st, _, f := seeded(t)
	v, found, err := st.Vuln(ctx, "cve-2026-102895")
	if err != nil || !found {
		t.Fatal(found, err)
	}
	if v.CVEID != sitetest.GPU || *v.Assigner != "GitHub_M" || v.IsRejected || v.Rejection != nil {
		t.Errorf("%+v", v)
	}
	// Events: known time ascending, then unknown (by stage, then id).
	var order []string
	for _, e := range v.Events {
		order = append(order, e.Source+":"+e.Precision)
	}
	if strings.Join(order, " ") != "cvelist:exact exploitdb:day kev:day ghsa:unknown metasploit:unknown nuclei:unknown" {
		t.Errorf("events %v", order)
	}
	e0 := v.Events[0]
	if e0.ID != f.GPUEvents["cvelist"] || e0.Code != "DIS" || !e0.IsBackfill || e0.DedupeKey != "" || e0.EffectiveAt == nil ||
		*e0.URL != "https://www.cve.org/CVERecord?id="+sitetest.GPU || !json.Valid(e0.Detail) {
		t.Errorf("event %+v", e0)
	}
	var codes []string
	for _, s := range v.Slots {
		codes = append(codes, s.Code+"="+s.State)
	}
	if strings.Join(codes, " ") != "DIS=known PAT=unknown ANA=none POC=known ITW=implied KEV=known" {
		t.Errorf("slots %v", codes)
	}
	if !v.Slots[5].Latest || *v.Slots[5].Precision != "day" || *v.Slots[5].DaysSinceDisclosure != 5 ||
		*v.Slots[3].Precision != "day" || *v.Slots[3].DaysSinceDisclosure != 4 || len(v.Slots[3].EventIDs) != 3 ||
		*v.Slots[1].Precision != "unknown" || v.Slots[4].Precision != nil || !v.Slots[4].NotAfter.Equal(sitetest.Day(2026, 11, 9)) {
		t.Errorf("slot details %+v", v.Slots)
	}
	if v.Transition == nil || v.Transition.Type != "kev_added" || *v.Transition.EventID != f.GPUEvents["kev"] || *v.DaysSinceDisclosure != 5 {
		t.Errorf("transition %+v", v.Transition)
	}
	if v.State == nil || v.State.Stage != "kev_added" || v.State.PocSources != 3 || v.State.EventCount != 6 || *v.Stage != "kev_added" {
		t.Errorf("state %+v", v.State)
	}
	if len(v.Aliases) != 1 || v.Aliases[0] != (site.Alias{Alias: "GHSA-gj9m-f8ph-pmhr", Type: "ghsa"}) || len(v.Products) != 1 {
		t.Errorf("aliases/products %+v %+v", v.Aliases, v.Products)
	}
	// Patch panel.
	if len(v.Patches) != 1 {
		t.Fatalf("patches %+v", v.Patches)
	}
	p := v.Patches[0]
	if *p.AdvisoryID != "GHSA-gj9m-f8ph-pmhr" || len(p.Packages) != 2 || *p.Packages[0].FixedVersion != "2.2.0" ||
		*p.Packages[0].AffectedRange != "< 2.2.0" || *p.Packages[0].Ecosystem != "pip" || p.Packages[1].FixedVersion != nil ||
		len(p.FixCommitURLs) != 2 || !p.AdvisoryPublishedAt.Equal(time.Date(2026, 11, 9, 22, 15, 27, 0, time.UTC)) {
		t.Errorf("patch %+v", p)
	}
	// PoC panel.
	if v.PocSources != 3 || len(v.Poc) != 3 || v.Poc[0].Source != "exploitdb" || v.Poc[1].Items[0].Key != "exploit/linux/http/gpustack_rce" ||
		*v.Poc[1].Items[0].Kind != "msf_module" || *v.Poc[0].Items[0].Title != "GPUStack 2.1 - Auth Bypass" || v.Poc[0].Items[0].Precision != "day" ||
		*v.Poc[2].Items[0].Kind != "detection_template" {
		t.Errorf("poc %+v", v.Poc)
	}
	// KEV, CVSS, SSVC, CWE.
	k := v.KEV
	if k == nil || *k.DateAdded != "2026-11-09" || *k.DueDate != "2026-11-12" || *k.ForensicTriage != "Yes" ||
		*k.KnownRansomwareCampaignUse != "Unknown" || *k.RequiredAction != "Apply mitigations" || k.Precision != "day" {
		t.Errorf("kev %+v", k)
	}
	if c := v.CVSS; c == nil || *c.Score != 9.8 || *c.Severity != "CRITICAL" || *c.Version != "3.1" || c.Source != "cvelist:cna" {
		t.Errorf("cvss %+v", c)
	}
	if s := v.SSVC; s == nil || *s.Exploitation != "active" || *s.Automatable != "yes" {
		t.Errorf("ssvc %+v", s)
	}
	var cw []string
	for _, c := range v.CWEs {
		name := ""
		if c.Name != nil {
			name = *c.Name
		}
		cw = append(cw, c.ID+"|"+name+"|"+strings.Join(c.Sources, "+"))
	}
	if strings.Join(cw, " ; ") != "CWE-20|Improper Input Validation|ghsa ; CWE-287|Improper Authentication|kev+ghsa ; "+
		"CWE-290|Authentication Bypass by Spoofing|kev+ghsa ; CWE-346|Origin Validation Error|kev+ghsa" {
		t.Errorf("cwes %v", cw)
	}
	var raws []string
	for _, r := range v.RawRecords {
		raws = append(raws, r.Path)
	}
	if strings.Join(raws, " ") != "/raw/cvelist/CVE-2026-102895.json /raw/exploitdb/52001.json /raw/ghsa/GHSA-gj9m-f8ph-pmhr.json "+
		"/raw/kev/CVE-2026-102895.json /raw/metasploit/exploit/linux/http/gpustack_rce.json /raw/nuclei/CVE-2026-102895.json" {
		t.Errorf("raw %v", raws)
	}
	// JSON: explicit nulls and RFC 3339 UTC.
	b, _ := json.Marshal(v)
	for _, want := range []string{`"title_zh":null`, `"published_at":null`, `"occurred_at":null`, `"at":"2026-11-09T00:00:00Z"`, `"code":"ITW"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("json lacks %s", want)
		}
	}
}

func TestVulnDetailEdgeCases(t *testing.T) {
	st, _, _ := seeded(t)
	if v, found, err := st.Vuln(ctx, "CVE-1999-0001"); v != nil || found || err != nil {
		t.Errorf("not found: %v %v %v", v, found, err)
	}
	var ie *site.InputError
	if _, _, err := st.Vuln(ctx, "CVE-1999-1' OR 1=1"); !errors.As(err, &ie) {
		t.Errorf("bad id: %v", err)
	}
	v, found, err := st.Vuln(ctx, "CVE-2026-1010") // no events
	if err != nil || !found || v.State != nil || v.Stage != nil || v.Transition != nil || len(v.Events) != 0 ||
		len(v.Slots) != 6 || v.Slots[0].State != "none" || v.CVSS != nil || len(v.Poc) != 3 {
		t.Errorf("no events %+v %v", v, err)
	}
	v, _, _ = st.Vuln(ctx, "CVE-2026-1005")
	if !v.IsRejected || v.Rejection == nil || v.Rejection.Reasons[0] != "dup" || v.Rejection.ReplacedBy[0] != "CVE-2026-1003" {
		t.Errorf("rejection %+v", v.Rejection)
	}
	v, _, _ = st.Vuln(ctx, "CVE-2026-1002")
	if v.Transition.Precision != "observed" || v.Events[1].Precision != "observed" || v.Events[1].EffectiveAt == nil {
		t.Errorf("observed %+v", v.Events)
	}
}

// The Go slot/transition computation from events (detail) agrees with the
// SQL one (vuln_state -> vuln_state_mat, hot list) for every fixture vuln.
func TestDetailAgreesWithMaterializedState(t *testing.T) {
	st, _, _ := seeded(t)
	page, err := st.Hot(ctx, site.HotParams{Since: 366 * 24 * time.Hour, MinStage: "disclosed", IncludeRejected: true, Limit: 200})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Rows) != 10 {
		t.Fatalf("rows %d", len(page.Rows))
	}
	for _, h := range page.Rows {
		v, _, err := st.Vuln(ctx, h.CVEID)
		if err != nil {
			t.Fatal(err)
		}
		var vs []site.Slot
		for _, s := range v.Slots {
			vs = append(vs, s.Slot)
		}
		if !reflect.DeepEqual(vs, h.Slots) {
			t.Errorf("%s slots differ:\nhot    %+v\ndetail %+v", h.CVEID, h.Slots, vs)
		}
		if !reflect.DeepEqual(*v.Transition, h.Transition) {
			t.Errorf("%s transition: hot %+v detail %+v", h.CVEID, h.Transition, *v.Transition)
		}
		if *v.Stage != h.Stage || v.IsRejected != h.IsRejected || v.PocSources != h.PocSources ||
			!reflect.DeepEqual(v.DaysSinceDisclosure, h.DaysSinceDisclosure) {
			t.Errorf("%s: stage %s/%s rejected %v/%v poc %d/%d", h.CVEID, *v.Stage, h.Stage, v.IsRejected, h.IsRejected, v.PocSources, h.PocSources)
		}
	}
}

func searchIDs(t *testing.T, st *site.Store, q string, limit int) (string, *site.SearchResult) {
	t.Helper()
	r, err := st.Search(ctx, q, limit)
	if err != nil {
		t.Fatalf("%q: %v", q, err)
	}
	s := make([]string, len(r.Rows))
	for i, x := range r.Rows {
		s[i] = strings.TrimPrefix(x.CVEID, "CVE-2026-")
	}
	return strings.Join(s, ","), r
}

func TestSearch(t *testing.T) {
	st, d, _ := seeded(t)
	s := sitetest.Seeder{T: t, Conn: d.Conn}
	for i, title := range []string{"100% safe parser", "1000 safe parser", "a_b overflow", "axb overflow", `back\slash bug`} {
		s.Vuln(fmt.Sprintf("CVE-2025-%04d", 2001+i), sitetest.P(title))
	}
	s.Vuln("CVE-2026-10281", sitetest.P("prefix one"))
	s.Vuln("CVE-2026-102800", sitetest.P("prefix two"))
	s.Refresh()

	if got, r := searchIDs(t, st, "cve-2026-102895", 0); got != "102895" || r.Kind != "cve_id" || r.Query != "CVE-2026-102895" {
		t.Errorf("exact %s %+v", got, r)
	}
	if got, _ := searchIDs(t, st, "2026-1028", 0); got != "10281,102800,102895" {
		t.Errorf("prefix %s", got)
	}
	if got, r := searchIDs(t, st, "CVE-2026-10", 2); got != "1001,1002" || !r.Truncated {
		t.Errorf("prefix limit %s %v", got, r.Truncated)
	}
	// Text: vendor match, most recently active first (nulls last).
	if got, r := searchIDs(t, st, "BARRACUDA", 0); got != "1001" || r.Kind != "text" || r.Rows[0].ProductCount != 3 || r.Rows[0].StageCode == nil {
		t.Errorf("vendor %s", got)
	}
	if got, _ := searchIDs(t, st, "响应", 0); got != "1003" {
		t.Errorf("title_zh %s", got)
	}
	if got, _ := searchIDs(t, st, "tie", 0); got != "1008,1007" {
		t.Errorf("title %s", got)
	}
	if got, _ := searchIDs(t, st, "gpustack", 0); got != "102895" { // title + both affected spellings: one row
		t.Errorf("dedupe %s", got)
	}
	// LIKE metacharacters are literal.
	for q, want := range map[string]string{"100%": "2025-2001", "a_b": "2025-2003", `k\s`: "2025-2005", "0%": "2025-2001", "%%": "", "__": ""} {
		got, _ := searchIDs(t, st, q, 0)
		if got != strings.ReplaceAll(want, "2025-", "CVE-2025-") {
			t.Errorf("escape %q: %q", q, got)
		}
	}
	if got, r := searchIDs(t, st, "GHSA-GJ9M-F8PH-PMHR", 0); got != "102895" || r.Kind != "alias" {
		t.Errorf("ghsa %s %+v", got, r)
	}
	if _, r := searchIDs(t, st, "x", 0); r.Kind != "too_short" || len(r.Rows) != 0 {
		t.Errorf("short %+v", r)
	}
	if _, r := searchIDs(t, st, "   ", 0); r.Kind != "empty" {
		t.Errorf("empty %+v", r)
	}
	if got, _ := searchIDs(t, st, "'; DROP TABLE vuln; --", 0); got != "" {
		t.Errorf("injection %s", got)
	}
	var ie *site.InputError
	if _, err := st.Search(ctx, strings.Repeat("a", 101), 0); !errors.As(err, &ie) {
		t.Errorf("long: %v", err)
	}
	if _, err := st.Search(ctx, "abc", 51); !errors.As(err, &ie) {
		t.Errorf("limit: %v", err)
	}
}

func TestRaw(t *testing.T) {
	st, _, _ := seeded(t)
	r, found, err := st.Raw(ctx, "kev", sitetest.GPU)
	if err != nil || !found || r.ContentHash != "h-kev-new" || !strings.Contains(string(r.Payload), `"v": 2`) || !json.Valid(r.Payload) {
		t.Errorf("latest %+v %v", r, err)
	}
	if r, found, _ := st.Raw(ctx, "metasploit", "exploit/linux/http/gpustack_rce"); !found || r.ContentHash != "h-msf" {
		t.Error("slash key")
	}
	if r, found, err := st.Raw(ctx, "kev", "CVE-1999-0001"); r != nil || found || err != nil {
		t.Error("missing")
	}
	var ie *site.InputError
	if _, _, err := st.Raw(ctx, "nosuch", "x"); !errors.As(err, &ie) {
		t.Error(err)
	}
}

func TestSourcesStatsHealth(t *testing.T) {
	st, _, _ := seeded(t)
	src, err := st.Sources(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range src.Collectors {
		names = append(names, c.Name)
	}
	if strings.Join(names, ",") != "cvelist,kev,ghsa,exploitdb,metasploit,nuclei,nvd" || src.CollectorsTotal != 7 || src.CollectorsOK != 1 {
		t.Errorf("collectors %v ok=%d", names, src.CollectorsOK)
	}
	kev := src.Collectors[1]
	if *kev.Status != "error" || kev.OK || len([]rune(*kev.LastError)) != 301 || src.Collectors[2].Status != nil || src.Collectors[2].LastRunAt != nil {
		t.Errorf("kev %+v", kev)
	}
	// data_updated_at = latest successful run (cvelist Ago(0.1), not kev's failed Ago(0.05)).
	if !src.DataUpdatedAt.Equal(sitetest.Ago(0.1)) || src.Vulns != 11 || src.Events != 18 || src.StateRefreshedAt == nil {
		t.Errorf("totals %+v", src)
	}
	// Every vuln except GPU lacks a cvelist raw record.
	if src.CvelistBackfillBacklog != 10 {
		t.Errorf("backlog %d", src.CvelistBackfillBacklog)
	}
	stats, err := st.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var by []string
	for _, b := range stats.ByStage {
		by = append(by, fmt.Sprintf("%s=%d", b.Code, b.Count))
	}
	if strings.Join(by, " ") != "DIS=1 PAT=3 ANA=0 POC=1 ITW=0 KEV=5" || stats.Vulns != 11 || stats.WithEvents != 10 ||
		stats.Rejected != 1 || stats.WithPatch != 4 || stats.WithPoc != 2 || stats.InKEV != 5 || stats.Exploited != 5 {
		t.Errorf("stats %v %+v", by, stats)
	}
	h, err := st.Health(ctx)
	if err != nil || h.DB != "ok" || h.Stale || *h.DataAgeSeconds != int64(0.1*86400) {
		t.Errorf("health %+v %v", h, err)
	}
	late := st.WithClock(func() time.Time { return sitetest.Now.Add(4 * time.Hour) })
	if h, _ := late.Health(ctx); !h.Stale {
		t.Error("stale")
	}
}
