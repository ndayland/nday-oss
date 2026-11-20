package webui

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
)

func tp(s string) *time.Time {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return &t
}

func ip(n int) *int { return &n }

func sp(s string) *string { return &s }

func TestFormatByPrecision(t *testing.T) {
	zh := loc(t, "zh-Hans")
	at := tp("2026-11-09T22:15:27Z")
	cases := []struct {
		t          *time.Time
		prec, want string
		short      string
	}{
		{at, site.PrecisionExact, "2026-11-09T22:15Z", "11-09T22:15Z"},
		{at, site.PrecisionObserved, "2026-11-09T22:15Z", "11-09T22:15Z"},
		{tp("2026-11-09T00:00:00Z"), site.PrecisionDay, "2026-11-09", "11-09"},
		{nil, site.PrecisionExact, "时间未知", "时间未知"},
		{at, site.PrecisionUnknown, "时间未知", "时间未知"},
	}
	for _, c := range cases {
		if got := FormatAt(zh, c.t, c.prec); got != c.want {
			t.Errorf("FormatAt(%v,%s)=%q want %q", c.t, c.prec, got, c.want)
		}
		if got := FormatAtShort(zh, c.t, c.prec); got != c.short {
			t.Errorf("FormatAtShort(%v,%s)=%q want %q", c.t, c.prec, got, c.short)
		}
	}
	// Non-UTC input is shown in UTC.
	loc := time.FixedZone("x", 8*3600)
	l := time.Date(2026, 11, 13, 1, 5, 0, 0, loc)
	if got := FormatAt(zh, &l, site.PrecisionExact); got != "2026-11-12T17:05Z" {
		t.Errorf("tz: %q", got)
	}
	if got := FormatNotAfter(zh, tp("2026-11-09T00:00:00Z")); got != "≤ 2026-11-09" {
		t.Errorf("not after %q", got)
	}
	if PrecisionShort(zh, "day") != "日精度" || PrecisionShort(zh, "observed") != "实时" || PrecisionShort(zh, "exact") != "精确" {
		t.Error("PrecisionShort")
	}
	if PrecisionNote(zh, "day") != "日精度，来源给出" || PrecisionNote(zh, "unknown") != "来源未给出时间" {
		t.Error("PrecisionNote")
	}
	if got := DateGroupLabel(zh, *tp("2026-11-12T23:59:00Z")); got != "2026-11-12 周四" {
		t.Errorf("group %q", got)
	}
}

func TestTPlus(t *testing.T) {
	zh := loc(t, "zh-Hans")
	for _, c := range []struct {
		d    *int
		want string
	}{{nil, "T+?"}, {ip(0), "T+0d"}, {ip(157), "T+157d"}, {ip(-20), "T-20d"}} {
		if got := FormatTPlus(c.d); got != c.want {
			t.Errorf("FormatTPlus(%v)=%q want %q", c.d, got, c.want)
		}
	}
	if !strings.Contains(TPlusTitle(zh, ip(-3)), "早 3 天") || !strings.Contains(TPlusTitle(zh, nil), "未知") {
		t.Error("TPlusTitle")
	}
}

func TestFormatInt(t *testing.T) {
	for n, want := range map[int64]string{0: "0", 999: "999", 1000: "1,000", 45965: "45,965", 1234567: "1,234,567", -1234: "-1,234"} {
		if got := loc(t, "en").Int(n); got != want {
			t.Errorf("Int(%d)=%q", n, got)
		}
	}
}

func TestSlotClass(t *testing.T) {
	cases := []struct {
		s      site.Slot
		state  string
		latest bool
	}{
		{site.Slot{Code: "DIS", State: site.SlotKnown}, "mk mk-known", false},
		{site.Slot{Code: "KEV", State: site.SlotKnown, Latest: true}, "mk mk-known", true},
		{site.Slot{Code: "PAT", State: site.SlotUnknown}, "mk mk-hollow", false},
		{site.Slot{Code: "ITW", State: site.SlotImplied}, "mk mk-hollow", false},
		{site.Slot{Code: "ANA", State: site.SlotNone}, "mk mk-none", false},
		{site.Slot{Code: "ANA", State: site.SlotNone, Latest: true}, "mk mk-none", false},
	}
	for _, c := range cases {
		st, l := SlotClass(c.s)
		if st != c.state || l != c.latest {
			t.Errorf("SlotClass(%+v)=%q,%v", c.s, st, l)
		}
	}
	strip := BuildStrip(loc(t, "zh-Hans"), []site.Slot{{Code: "DIS", State: "known"}, {Code: "PAT", State: "none"}, {Code: "ANA", State: "none"},
		{Code: "POC", State: "unknown"}, {Code: "ITW", State: "implied"}, {Code: "KEV", State: "known", Latest: true}})
	// per slot: the marker shape (k known, o hollow, n none; slot index = stage, coloured by the stylesheet)
	// and the halo only on the latest change
	var refs, halos []string
	for _, s := range strip.Slots {
		refs, halos = append(refs, s.Ref), append(halos, s.Halo)
	}
	if got := strings.Join(refs, " "); got != "k0 n1 n2 o3 o4 k5" || strings.Join(halos, ",") != ",,,,,h5" || !strip.Slots[5].Latest {
		t.Errorf("strip %+v", strip.Slots)
	}
	if strip.Label != "生命周期：披露已发生，公开 PoC已发生但时间未知，在野利用由 KEV 推定，进入 KEV是最近一次变化" {
		t.Errorf("label %q", strip.Label)
	}
	if StageClass("KEV") != "st-kev" || StageClass("XYZ") != "st-unk" {
		t.Error("StageClass")
	}
}

func TestProductLine(t *testing.T) {
	zh := loc(t, "zh-Hans")
	ps := []site.Product{{Vendor: "Barracuda Networks", Product: "Email Security Gateway (ESG)"}, {Vendor: "barracuda networks", Product: "Load Balancer ADC"}}
	if got, _ := ProductLine(zh, ps, 7, 2); got != "Barracuda Networks / Email Security Gateway (ESG)、Load Balancer ADC +5" {
		t.Errorf("same vendor: %q", got)
	}
	ps2 := []site.Product{{Vendor: "Cisco", Product: "BroadWorks"}, {Vendor: "IBM", Product: "Aspera"}}
	if got, _ := ProductLine(zh, ps2, 2, 2); got != "Cisco / BroadWorks · IBM / Aspera" {
		t.Errorf("two vendors: %q", got)
	}
	if got, _ := ProductLine(zh, nil, 0, 2); got != "" {
		t.Errorf("none: %q", got)
	}
	if got, _ := ProductLine(zh, nil, 3, 2); got != "3 个产品" {
		t.Errorf("only count: %q", got)
	}
	if got, _ := ProductLine(zh, ps2, 2, 1); got != "Cisco / BroadWorks +1" {
		t.Errorf("max: %q", got)
	}
}

func TestShellQuoteAndCurl(t *testing.T) {
	for in, want := range map[string]string{
		"https://nday.land/api/vuln/CVE-2026-1":      "https://nday.land/api/vuln/CVE-2026-1",
		"https://x/api/hot?since=7d&min_stage=patch": "'https://x/api/hot?since=7d&min_stage=patch'",
		"it's":         `'it'\''s'`,
		"":             "''",
		"a b":          "'a b'",
		"$(rm -rf /)":  "'$(rm -rf /)'",
		"gpustack>=2":  "'gpustack>=2'",
		".events":      ".events",
		"x`id`":        "'x`id`'",
		"semi;colon":   "'semi;colon'",
		"new\nline":    "'new\nline'",
		"@nuxt/c@3.1":  "@nuxt/c@3.1",
		"q=%E4%B8%AD+": "q=%E4%B8%AD+",
	} {
		if got := ShellQuote(in); got != want {
			t.Errorf("ShellQuote(%q)=%q want %q", in, got, want)
		}
	}
	c := CurlCmd("https://nday.land/api/hot?since=30d&min_stage=patch", ".")
	if c.Cmd != `curl -s -H "Authorization: Bearer $NDAY_TOKEN" 'https://nday.land/api/hot?since=30d&min_stage=patch'` || c.Pipe != "| jq ." ||
		c.Copy != `curl -s -H "Authorization: Bearer $NDAY_TOKEN" 'https://nday.land/api/hot?since=30d&min_stage=patch' | jq .` {
		t.Errorf("curl %+v", c)
	}
}

func TestUpgradeCmd(t *testing.T) {
	cases := []struct{ eco, name, ver, want string }{
		{"pip", "gpustack", "2.2.0", "pip install -U 'gpustack>=2.2.0'"},
		{"npm", "@nuxt/content", "3.15.2", "npm install @nuxt/content@3.15.2"},
		{"rubygems", "rails", "7.1.3.1", "gem install rails -v 7.1.3.1"},
		{"nuget", "Newtonsoft.Json", "13.0.1", "dotnet add package Newtonsoft.Json --version 13.0.1"},
		{"go", "github.com/x/y", "1.2.3", ""},
		{"maven", "org.x:y", "1.0", ""},
		{"composer", "a/b", "1.0", ""},
		{"pip", "evil;rm", "1.0", ""},
		{"pip", "ok", "1.0; rm -rf /", ""},
		{"npm", "a@b", "1.0", ""},
		{"pip", "x", "", ""},
	}
	for _, c := range cases {
		if got := UpgradeCmd(c.eco, c.name, c.ver); got != c.want {
			t.Errorf("UpgradeCmd(%q,%q,%q)=%q want %q", c.eco, c.name, c.ver, got, c.want)
		}
	}
}

func TestSafeURL(t *testing.T) {
	good := map[string]string{
		"https://github.com/advisories/GHSA-x": "https://github.com/advisories/GHSA-x",
		"HTTP://Example.com/a?b=1":             "http://Example.com/a?b=1",
	}
	for in, want := range good {
		if got, ok := SafeURL(in); !ok || got != want {
			t.Errorf("SafeURL(%q)=%q,%v", in, got, ok)
		}
	}
	for _, in := range []string{"javascript:alert(1)", "JavaScript:alert(1)", " javascript:alert(1)", "data:text/html,<script>",
		"vbscript:x", "//evil.example/x", "/relative", "https://", "https://user:pw@host/", "https://a b", "https://a\nb",
		"https://evil\\@good", "ftp://x/y", "", "mailto:a@b", "https:evil"} {
		if got, ok := SafeURL(in); ok {
			t.Errorf("SafeURL(%q) accepted as %q", in, got)
		}
	}
	if l := ExtLink("x", "javascript:alert(1)"); l.Href != "" || l.Text != "x" {
		t.Errorf("ExtLink %+v", l)
	}
	if l := ExtLink("", "https://a.example/"); l.Href != "https://a.example/" || !l.External {
		t.Errorf("ExtLink %+v", l)
	}
	if l := CommitLink("https://github.com/gpustack/gpustack/pull/5346"); l.Text != "gpustack/gpustack#5346" {
		t.Errorf("pull %+v", l)
	}
	if l := CommitLink("https://github.com/gpustack/gpustack/commit/53F42A6a553542974396d16a4ff6b12bcbedb48d"); l.Text != "gpustack/gpustack@53f42a6" {
		t.Errorf("commit %+v", l)
	}
	if l := CommitLink("javascript:alert(1)"); l.Href != "" {
		t.Errorf("bad commit %+v", l)
	}
	if l := AliasLink("GHSA-gj9m-f8ph-pmhr", "ghsa"); l.Href != "https://github.com/advisories/GHSA-gj9m-f8ph-pmhr" {
		t.Errorf("alias %+v", l)
	}
	if l := AliasLink("GHSA-<x>", "ghsa"); l.Href != "" {
		t.Errorf("bad alias %+v", l)
	}
	if l := CWELink("CWE-287"); l.Href != "https://cwe.mitre.org/data/definitions/287.html" {
		t.Errorf("cwe %+v", l)
	}
	if l := CWELink("CWE-28\"7"); l.Href != "" {
		t.Errorf("bad cwe %+v", l)
	}
}

func TestHotFiltersLinks(t *testing.T) {
	def := HotFilters{Since: defaultSince, MinStage: defaultMinStage}
	if def.Href(false) != "/" {
		t.Errorf("default href %q", def.Href(false))
	}
	f := HotFilters{Since: 30 * 24 * time.Hour, MinStage: "poc_published", IncludeRejected: true, Cursor: "abc+/="}
	if got := f.Href(true); got != "/?since=30d&min_stage=poc&include_rejected=1&cursor=abc%2B%2F%3D" {
		t.Errorf("href %q", got)
	}
	if got := NewAPI("https://nday.land", "").URL(f.APIPath()); got != "https://nday.land/api/hot?since=30d&min_stage=poc&include_rejected=true" {
		t.Errorf("api %q", got)
	}
	if got := NewAPI("https://www.nday.land", "https://api.nday.land").URL(f.APIPath()); got != "https://api.nday.land/v1/hot?since=30d&min_stage=poc&include_rejected=true" {
		t.Errorf("api two-host %q", got)
	}
	next, prev := "NEXT", "PREV"
	page := &site.HotPage{NextCursor: &next, PrevCursor: &prev, Limit: 50}
	hv := BuildHotView(loc(t, "en"), f, page, nil, NewAPI("https://nday.land", ""))
	if hv.Pager == nil || hv.Pager.Next != "/?since=30d&min_stage=poc&include_rejected=1&cursor=NEXT" {
		t.Errorf("next %+v", hv.Pager)
	}
	if len(hv.Pager.Items) == 0 || hv.Pager.Items[0].Href != "/?since=30d&min_stage=poc&include_rejected=1" ||
		hv.Pager.Prev != "/?since=30d&min_stage=poc&include_rejected=1&before=PREV" {
		t.Errorf("first/prev %+v", hv.Pager)
	}
	// Filter links keep the other filters and drop the cursor.
	if hv.Since[0].Href != "/?since=24h&min_stage=poc&include_rejected=1" || !hv.Since[2].Active || hv.Since[0].Active {
		t.Errorf("since %+v", hv.Since)
	}
	if hv.Stage[0].Href != "/?since=30d&include_rejected=1" || !hv.Stage[1].Active {
		t.Errorf("stage %+v", hv.Stage)
	}
	if hv.Rejected.Href != "/?since=30d&min_stage=poc" || !hv.Rejected.Active {
		t.Errorf("rejected %+v", hv.Rejected)
	}
	// the data API command (account page): the token header from $NDAY_TOKEN
	if c := CurlCmd(NewAPI("https://nday.land", "").URL(f.APIPath()), "."); c.Copy != `curl -s -H "Authorization: Bearer $NDAY_TOKEN" 'https://nday.land/api/hot?since=30d&min_stage=poc&include_rejected=true' | jq .` {
		t.Errorf("curl %q", c.Copy)
	}
	// Unknown parameters are ignored; bad known ones are errors.
	if _, err := parseHotFilters(map[string][]string{"utm_source": {"x"}, "since": {"30d"}}); err != nil {
		t.Error(err)
	}
	if _, err := parseHotFilters(map[string][]string{"since": {"5m"}}); err == nil {
		t.Error("bad since accepted")
	}
}

func TestHotRowGrouping(t *testing.T) {
	d1 := *tp("2026-11-12T17:04:00Z")
	d2 := *tp("2026-11-12T00:00:00Z")
	d3 := *tp("2026-11-11T00:00:00Z")
	mk := func(at time.Time, prec string) site.HotRow {
		return site.HotRow{CVEID: "CVE-2026-1", Transition: site.Transition{Code: "KEV", At: at, Precision: prec}}
	}
	last := ""
	zh := loc(t, "zh-Hans")
	r1 := BuildHotRow(zh, mk(d1, "observed"), &last)
	r2 := BuildHotRow(zh, mk(d2, "day"), &last)
	r3 := BuildHotRow(zh, mk(d3, "day"), &last)
	if r1.DateHeader != "2026-11-12 周四" || r2.DateHeader != "" || r3.DateHeader != "2026-11-11 周三" {
		t.Errorf("groups %q %q %q", r1.DateHeader, r2.DateHeader, r3.DateHeader)
	}
	if r1.Time.Text != "11-12T17:04Z" || r1.Prec != "实时" || r2.Time.Text != "11-12" || r2.Prec != "日精度" {
		t.Errorf("times %+v %+v", r1, r2)
	}
	// observed has a time of day: convertible; day precision is a calendar date: never.
	if r1.Time.At != "2026-11-12T17:04:00Z" || r1.Time.Style != "short" || r2.Time.At != "" || r3.Time.At != "" {
		t.Errorf("stamps %+v %+v %+v", r1.Time, r2.Time, r3.Time)
	}
	if got := string(r1.Time.HTML()); got != `<time datetime="2026-11-12T17:04:00Z" data-lt="short">11-12T17:04Z</time>` {
		t.Errorf("html %s", got)
	}
	if got := string(r2.Time.HTML()); got != "11-12" {
		t.Errorf("day html %s", got)
	}
	if r1.Title != "等待官方记录回填" || !r1.TitleMissing || r1.TPlus != "T+?" || r1.Poc != "0/4" || !r1.PocZero {
		t.Errorf("row %+v", r1)
	}
	// The change in words, with the code kept as a secondary token.
	if r1.Change != "+KEV" || r1.ChangeText != "进入 KEV" || r1.ChangeClass != "st-kev" {
		t.Errorf("change %q %q %q", r1.Change, r1.ChangeText, r1.ChangeClass)
	}
	en := loc(t, "en")
	for code, want := range map[string]string{"DIS": "disclosed", "PAT": "patch released", "ANA": "analysis published",
		"POC": "PoC published", "ITW": "exploited in the wild", "KEV": "added to KEV", "XYZ": "XYZ"} {
		if got := ChangeText(en, code); got != want {
			t.Errorf("ChangeText(%s) = %q, want %q", code, got, want)
		}
	}
}

// Pinned rows (site/pin.go) carry the marker, have no date header and do
// not start a date group: the first ordinary row still gets its header.
func TestHotPinnedRows(t *testing.T) {
	d := *tp("2026-11-12T00:00:00Z")
	row := func(id string, pinned bool) site.HotRow {
		return site.HotRow{CVEID: id, Pinned: pinned, Transition: site.Transition{Code: "KEV", At: d, Precision: "day"}}
	}
	page := &site.HotPage{Rows: []site.HotRow{row("CVE-2026-1", true), row("CVE-2026-2", false), row("CVE-2026-3", false)}}
	hv := BuildHotView(loc(t, "zh-Hans"), HotFilters{Since: 7 * 24 * time.Hour, MinStage: "patch_released"}, page,
		nil, NewAPI("https://nday.land", ""))
	if len(hv.Rows) != 3 || !hv.Rows[0].Pinned || hv.Rows[1].Pinned || hv.Rows[0].DateHeader != "" ||
		hv.Rows[1].DateHeader != "2026-11-12 周四" || hv.Rows[2].DateHeader != "" {
		t.Errorf("rows %+v", hv.Rows)
	}
	// A rule pin, a fill pin (site.PinDiscussed; it may lack a known
	// transition time) and ordinary rows: each row once, the same badge for
	// both kinds, no date header on either.
	fill := site.HotRow{CVEID: "CVE-2026-4", Pinned: true, PinReason: site.PinDiscussed,
		Transition: site.Transition{Precision: site.PrecisionUnknown}}
	rule := row("CVE-2026-1", true)
	rule.PinReason = site.PinRule
	page = &site.HotPage{Rows: []site.HotRow{rule, fill, row("CVE-2026-2", false), row("CVE-2026-3", false)}}
	hv = BuildHotView(loc(t, "en"), HotFilters{Since: 7 * 24 * time.Hour, MinStage: "patch_released"}, page,
		nil, NewAPI("https://nday.land", ""))
	seen := map[string]int{}
	for _, r := range hv.Rows {
		seen[r.CVE]++
	}
	if len(hv.Rows) != 4 || len(seen) != 4 || !hv.Rows[0].Pinned || !hv.Rows[1].Pinned || hv.Rows[2].Pinned ||
		hv.Rows[0].DateHeader != "" || hv.Rows[1].DateHeader != "" || hv.Rows[2].DateHeader == "" || hv.Rows[3].DateHeader != "" {
		t.Errorf("rule + fill rows %+v", hv.Rows)
	}
	if got := loc(t, "zh-Hans").Text("hot.pinned"); got != "置顶" {
		t.Errorf("zh-Hans marker %q", got)
	}
	if got := loc(t, "en").Text("hot.pinned"); got != "Pinned" {
		t.Errorf("en marker %q", got)
	}
}

func TestTokenizeJSON(t *testing.T) {
	toks := TokenizeJSON([]byte(`{"a": "b:\"c", "k\"q": [1, "x"], "d": {"e": null}}`))
	var keys []string
	var all strings.Builder
	for _, tk := range toks {
		all.WriteString(tk.Text)
		if tk.Key {
			keys = append(keys, tk.Text)
		}
	}
	if all.String() != `{"a": "b:\"c", "k\"q": [1, "x"], "d": {"e": null}}` {
		t.Errorf("lossy: %s", all.String())
	}
	if strings.Join(keys, ",") != `"a","k\"q","d","e"` {
		t.Errorf("keys %v", keys)
	}
	raw := RawEventJSON(site.Event{ID: 1, Type: "kev_added", Detail: json.RawMessage(`{"x":"</pre><script>"}`)})
	var s strings.Builder
	for _, tk := range raw {
		s.WriteString(tk.Text)
	}
	if !strings.Contains(s.String(), `"x": "</pre><script>"`) {
		t.Errorf("raw %s", s.String())
	}
}

func TestEventText(t *testing.T) {
	cases := []struct {
		e    site.Event
		want string
	}{
		{site.Event{Source: "cvelist", Type: "disclosed", Detail: json.RawMessage(`{"assigner_short_name":"GitHub_M","cvss":{"base_score":9.8,"base_severity":"CRITICAL"},"ssvc":{"exploitation":"active"}}`)},
			"CVE 记录发布，编号分配方是 GitHub_M。CVSS 9.8，严重。CISA 的 SSVC 评估中利用状态为 active。"},
		{site.Event{Source: "cvelist", Type: "disclosed", Detail: json.RawMessage(`{"state":"REJECTED","date_rejected":"2026-11-05T15:22:30.387Z"}`)},
			`CVE 记录被拒绝（REJECTED），拒绝时间 <time datetime="2026-11-05T15:22:30Z" data-lt="long">2026-11-05T15:22Z</time>。`},
		{site.Event{Source: "kev", Type: "kev_added", Detail: json.RawMessage(`{"due_date":"2026-11-12","forensic_triage":"Yes","known_ransomware_campaign_use":"Unknown"}`)},
			"CISA 将其列入已知被利用漏洞目录，要求在 2026-11-12 前修复，并要求做取证排查。是否被勒索软件使用：未知。"},
		{site.Event{Source: "ghsa", Type: "patch_released", Detail: json.RawMessage(`{"packages":[{"name":"gpustack","first_patched_version":"2.2.0"}],"fix_commit_urls":["u"],"advisory_published_at":"2026-11-09T22:15:27Z"}`)},
			`公告给出修复版本 gpustack 2.2.0。公告附有修复提交。公告本身发布于 <time datetime="2026-11-09T22:15:27Z" data-lt="long">2026-11-09T22:15Z</time>，补丁实际发布时间没有记录。`},
		{site.Event{Source: "exploitdb", Type: "poc_published", Detail: json.RawMessage(`{"title":"X 1.0 - RCE","edb_id":52001,"verified":true}`)},
			`Exploit-DB 收录公开利用代码《<span lang="en">X 1.0 - RCE</span>》（EDB-52001）。已由 Exploit-DB 验证。`},
		{site.Event{Source: "nuclei", Type: "poc_published", Detail: json.RawMessage(`{"template_id":"CVE-1","title":"T"}`)},
			`Nuclei 收录检测模板 CVE-1（<span lang="en">T</span>）。来源没有给出模板的发布时间。`},
		{site.Event{Source: "x", Type: "exploited_in_wild", Code: "ITW", Detail: json.RawMessage(`not json`)},
			"x 报告了在野利用事件。"},
	}
	for _, c := range cases {
		if got := string(EventText(loc(t, "zh-Hans"), c.e)); got != c.want {
			t.Errorf("EventText(%s)=%q\nwant %q", c.e.Source, got, c.want)
		}
	}
}
