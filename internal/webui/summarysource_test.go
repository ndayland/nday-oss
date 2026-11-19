package webui

import (
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
)

// An upstream summary names its record and links it: the upstream page an
// event of that record points to, else the stored raw record; an unknown
// source is said to be upstream text without a link. A model-written
// summary keeps its own note and gets no source line.
func TestSummarySource(t *testing.T) {
	en, zh := loc(t, "en"), loc(t, "zh-Hans")
	now := time.Date(2026, 11, 15, 0, 0, 0, 0, time.UTC)
	s := func(v string) *string { return &v }
	v := &site.VulnDetail{CVEID: "CVE-2026-1", Description: s("Upstream text."),
		Events: []site.Event{
			{ID: 1, Source: "cvelist", URL: s("https://www.cve.org/CVERecord?id=CVE-2026-1")},
			{ID: 2, Source: "ghsa", DedupeKey: "GHSA-aaaa", URL: s("https://github.com/advisories/GHSA-aaaa")},
			{ID: 3, Source: "kev", URL: s("javascript:alert(1)")},
		},
		RawRecords: []site.RawLink{{Source: "kev", Key: "CVE-2026-1", Path: site.RawPath("kev", "CVE-2026-1")}}}
	for _, c := range []struct {
		src  *site.DescSource
		want string
	}{
		{&site.DescSource{Source: "cvelist", Key: "CVE-2026-1"},
			`Original text of the CVE record (<a href="https://www.cve.org/CVERecord?id=CVE-2026-1" target="_blank" rel="noopener noreferrer">cvelist</a>), shown as published.`},
		{&site.DescSource{Source: "ghsa", Key: "GHSA-aaaa"},
			`Original text of GitHub advisory <a href="https://github.com/advisories/GHSA-aaaa" target="_blank" rel="noopener noreferrer">GHSA-aaaa</a>, shown as published.`},
		{&site.DescSource{Source: "ghsa", Key: "GHSA-zzzz"}, // no event, no raw record: plain text
			`Original text of GitHub advisory <span>GHSA-zzzz</span>, shown as published.`},
		{&site.DescSource{Source: "kev", Key: "CVE-2026-1"}, // unsafe upstream URL: the raw record
			`Original text of the CISA KEV entry (<a href="/raw/kev/CVE-2026-1.json">kev</a>), shown as published.`},
		{nil, en.Text("vuln.summary.upstream", "from", "unknown")},
	} {
		v.DescriptionSource = c.src
		vv := BuildVulnView(en, v, now, NewAPI("https://nday.land", ""))
		if string(vv.SummarySrc) != c.want {
			t.Errorf("%+v:\n got %s\nwant %s", c.src, vv.SummarySrc, c.want)
		}
	}
	v.DescriptionSource = &site.DescSource{Source: "cvelist", Key: "CVE-2026-1"}
	if vv := BuildVulnView(zh, v, now, API{}); !strings.HasPrefix(string(vv.SummarySrc), "以上是 CVE 记录（<a ") {
		t.Errorf("zh: %s", vv.SummarySrc)
	}
	v.SummaryZh = s("模型写的摘要。")
	if vv := BuildVulnView(zh, v, now, API{}); !vv.SummaryIsZh || vv.SummarySrc != "" {
		t.Errorf("model summary got a source line: %s", vv.SummarySrc)
	}
}
