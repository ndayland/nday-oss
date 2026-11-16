package webui

import (
	"html/template"
	"net/url"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// StatusLine is the top status line. Full (the sources page) is the whole
// strip ("● collectors 6/6 ok │ vulns … │ …"); the short form (list pages)
// says only when the data was last updated, plus the collector count, linked
// to the sources page, while a collector is failing.
type StatusLine struct {
	Full      bool
	AllOK     bool
	Collector string
	Vulns     string
	Events    string
	Backlog   string
	Updated   template.HTML
}

// BuildStatusLine summarises collector health and totals.
func BuildStatusLine(l *i18n.Locale, s *site.SourcesReport) *StatusLine {
	if s == nil {
		return nil
	}
	sl := &StatusLine{AllOK: s.CollectorsOK == s.CollectorsTotal && s.CollectorsTotal > 0,
		Collector: l.Text("statusline.collectors", "ok", s.CollectorsOK, "total", s.CollectorsTotal),
		Vulns:     l.Text("statusline.vulns", "n", s.Vulns), Events: l.Text("statusline.events", "n", s.Events),
		Backlog: l.Text("statusline.backlog", "n", s.CvelistBackfillBacklog), Updated: l.HTML("statusline.updated_unknown")}
	if s.DataUpdatedAt != nil {
		sl.Updated = l.HTML("statusline.updated", "time", instant(*s.DataUpdatedAt, stampLong).HTML())
	}
	return sl
}

// Bar is one row of a horizontal bar chart (SVG width in percent).
type Bar struct {
	Code  string
	Name  string
	Class string
	Count string
	W     string // percentage of the largest count, at least 1% when > 0
}

// StageBars builds bars from stage counts; skipZero drops empty stages.
func StageBars(l *i18n.Locale, counts []site.StageCount, skipZero bool) []Bar {
	var max int64
	for _, c := range counts {
		if c.Count > max {
			max = c.Count
		}
	}
	var out []Bar
	for _, c := range counts {
		if skipZero && c.Count == 0 {
			continue
		}
		w := 0.0
		if max > 0 && c.Count > 0 {
			w = float64(c.Count) / float64(max) * 100
			if w < 1 {
				w = 1
			}
		}
		st := stageByCode(c.Code)
		out = append(out, Bar{Code: c.Code, Name: StageName(l, c.Code), Class: st.Class, Count: l.Int(c.Count), W: pctAttr(w)})
	}
	return out
}

// CollectorView is one collector line.
type CollectorView struct {
	Name        string
	Status      string // ok | partial | error (upstream status tokens) | the locale's "never ran"
	StatusClass string
	LastSuccess Stamp
	LastRun     Stamp
	Error       string
	Info        SourceInfo
}

// SourceInfo describes a collector for readers.
type SourceInfo struct {
	What     template.HTML
	Produces template.HTML
	Upstream Link
}

// sourceInfos: what each collector is and what it produces (catalog keys)
// and where its data comes from.
var sourceInfos = map[string]struct {
	what, produces string
	up             Link
}{
	"cvelist": {"src.cvelist.what", "src.cvelist.produces",
		Link{Text: "github.com/CVEProject/cvelistV5", Href: "https://github.com/CVEProject/cvelistV5", External: true}},
	"kev": {"src.kev.what", "src.kev.produces",
		Link{Text: "cisa.gov/known-exploited-vulnerabilities-catalog", Href: "https://www.cisa.gov/known-exploited-vulnerabilities-catalog", External: true}},
	"ghsa": {"src.ghsa.what", "src.ghsa.produces",
		Link{Text: "github.com/advisories", Href: "https://github.com/advisories", External: true}},
	"exploitdb": {"src.exploitdb.what", "src.exploitdb.produces",
		Link{Text: "exploit-db.com", Href: "https://www.exploit-db.com/", External: true}},
	"metasploit": {"src.metasploit.what", "src.metasploit.produces",
		Link{Text: "github.com/rapid7/metasploit-framework", Href: "https://github.com/rapid7/metasploit-framework", External: true}},
	"nuclei": {"src.nuclei.what", "src.nuclei.produces",
		Link{Text: "github.com/projectdiscovery/nuclei-templates", Href: "https://github.com/projectdiscovery/nuclei-templates", External: true}},
	"nvd": {"src.nvd.what", "src.nvd.produces",
		Link{Text: "nvd.nist.gov/vuln/data-feeds", Href: "https://nvd.nist.gov/vuln/data-feeds", External: true}},
}

// BuildCollectors lists collectors in display order.
func BuildCollectors(l *i18n.Locale, s *site.SourcesReport) []CollectorView {
	if s == nil {
		return nil
	}
	var out []CollectorView
	for _, c := range s.Collectors {
		cv := CollectorView{Name: c.Name, Status: l.Text("collector.never_run"), StatusClass: "weak", LastSuccess: Stamp{Text: "—"},
			LastRun: Stamp{Text: "—"}}
		if si, ok := sourceInfos[c.Name]; ok {
			cv.Info = SourceInfo{What: l.HTML(si.what), Upstream: si.up,
				Produces: l.HTML(si.produces, "dis", stageCodeHTML("DIS"), "pat", stageCodeHTML("PAT"),
					"poc", stageCodeHTML("POC"), "itw", stageCodeHTML("ITW"), "kev", stageCodeHTML("KEV"))}
		}
		if c.Status != nil {
			cv.Status = *c.Status
			switch *c.Status {
			case "ok":
				cv.StatusClass = "ok"
			case "error":
				cv.StatusClass = "bad"
			default:
				cv.StatusClass = "warn"
			}
		}
		if c.LastSuccessAt != nil {
			cv.LastSuccess = shortStamp(*c.LastSuccessAt)
		}
		if c.LastRunAt != nil {
			cv.LastRun = shortStamp(*c.LastRunAt)
		}
		if c.LastError != nil {
			cv.Error = *c.LastError
		}
		out = append(out, cv)
	}
	return out
}

// shortStamp is "11-12T15:19Z" (convertible).
func shortStamp(t time.Time) Stamp { return instant(t, stampShort) }

// SearchRowView is one search hit.
type SearchRowView struct {
	CVE          string
	Href         string
	Title        string
	TitleMissing bool
	TitleLang    string
	Vendor       string
	Stage        string
	StageClass   string
	Last         string
	Rejected     bool
	Tags         []TagChip // at most three (tags.RowPicks), each adds itself as a filter
}

// SearchView is the search page.
type SearchView struct {
	Query     string
	Kind      string
	Rows      []SearchRowView
	Truncated bool
	Curl      CmdLine
	Limit     int
	// Tag filter (tagview.go addSearchTags): active chips (removable) and the
	// link to the vocabulary.
	Chips    []TagChip
	TagsHref string
}

// BuildSearchView converts a search result.
func BuildSearchView(l *i18n.Locale, q string, res *site.SearchResult, limit int, api API) SearchView {
	sv := SearchView{Query: q, Limit: limit}
	if res == nil {
		return sv
	}
	sv.Kind, sv.Truncated = res.Kind, res.Truncated
	sv.Curl = CurlCmd(api.URL("/search?q="+queryEscape(res.Query)), ".rows")
	for _, r := range res.Rows {
		rv := SearchRowView{CVE: r.CVEID, Href: l.Path("/vuln/" + r.CVEID), Rejected: r.IsRejected, Stage: "—", StageClass: "weak",
			Last: "—"}
		// a search row has no slots, and a missing stage may only mean the
		// lists are not refreshed yet: the reason for a missing title is unknown
		rv.Title, rv.TitleMissing, rv.TitleLang = rowTitle(l, r.TitleZh, r.Title, recordUnknown)
		rv.Vendor, _ = ProductLine(l, r.Products, r.ProductCount, 2)
		if r.StageCode != nil {
			rv.Stage, rv.StageClass = *r.StageCode, StageClass(*r.StageCode)
		}
		if r.LastTransitionAt != nil {
			rv.Last = r.LastTransitionAt.UTC().Format(layoutDate)
		}
		sv.Rows = append(sv.Rows, rv)
	}
	return sv
}

func queryEscape(s string) string { return url.QueryEscape(s) }

// StatsView is the stats page.
type StatsView struct {
	Bars    []Bar
	Totals  []Fact
	AsOf    template.HTML // convertible <time>, "" when unknown
	Curl    CmdLine
	Visible bool
}

// BuildStatsView converts site.Stats.
func BuildStatsView(l *i18n.Locale, s *site.Stats, api API) StatsView {
	sv := StatsView{Curl: CurlCmd(api.URL("/stats"), ".")}
	if s == nil {
		return sv
	}
	sv.Visible = true
	sv.Bars = StageBars(l, s.ByStage, false)
	sv.Totals = []Fact{
		{Label: l.Text("stats.total.vulns"), Value: l.Int(s.Vulns)},
		{Label: l.Text("stats.total.with_events"), Value: l.Int(s.WithEvents)},
		{Label: l.Text("stats.total.with_patch"), Value: l.Int(s.WithPatch), Class: "st-pat"},
		{Label: l.Text("stats.total.with_poc"), Value: l.Int(s.WithPoc), Class: "st-poc"},
		{Label: l.Text("stats.total.exploited"), Value: l.Int(s.Exploited), Class: "st-itw"},
		{Label: l.Text("stats.total.in_kev"), Value: l.Int(s.InKEV), Class: "st-kev"},
		{Label: l.Text("stats.total.rejected"), Value: l.Int(s.Rejected), Class: "weak"},
	}
	if s.StateRefreshedAt != nil {
		sv.AsOf = minuteHTML(s.StateRefreshedAt)
	}
	return sv
}
