package webui

import (
	"html/template"
	"sort"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// Fact is one item of the key-facts row.
type Fact struct {
	Label string
	Value string
	Class string // colour class of the value
	Note  string // dimmed suffix
	// ValueHTML replaces Value when set (a convertible <time>).
	ValueHTML template.HTML
}

// EventItem is one entry of the event log.
type EventItem struct {
	Anchor    string
	Time      Stamp
	TimeNote  string // where the time comes from; "" when the source gave it exactly
	Sign      string // "+" (event) or "~" (implied)
	Code      string
	Class     string
	Name      string
	Text      template.HTML
	Src       Link          // "src <link>"; empty for implied entries
	SrcKey    string        // e.g. the GHSA id, shown after the source name
	Obs       template.HTML // how nday got it (with a convertible <time>)
	Basis     []Link        // implied entries: what the inference rests on
	BasisHTML template.HTML
	Raw       []JSONTok
	Implied   bool
	Upstream  string // href for the "o" key (safe URL or "")
}

// PkgRow is one affected package.
type PkgRow struct {
	Ecosystem, Name, Affected, Fixed string
	Upgrade                          *CmdLine
}

// PocRow is one curated PoC source.
type PocRow struct {
	Source  string
	Present bool
	Items   []Link
}

// CWERow is a weakness.
type CWERow struct {
	ID   Link
	Name string
	Lang string // "en" when Name is upstream English on a non-English page
}

// CreditRow is one credited person, organisation or tool. Name is
// upstream text, rendered escaped only, never as a link.
type CreditRow struct {
	Role   string // role key (site.CreditRoles), shown via credit.role
	Name   string
	Source string // cvelist | ghsa, as on the event log
}

// RejectView describes a REJECTED record.
type RejectView struct {
	Date       template.HTML // convertible <time>, "" when not given
	Reasons    []string
	ReplacedBy []Link
	Lang       string // lang of the upstream reasons
}

// VulnView is the vulnerability page.
type VulnView struct {
	ID            string
	Aliases       []Link
	Title         string
	TitleMissing  bool
	TitleLang     string
	HasRecord     bool          // the CVE record is collected (DIS event; only cvelist emits one)
	Original      string        // English title when a Chinese one is shown
	Sentence      string        // plain text (meta description)
	SentenceHTML  template.HTML // the same with convertible <time> elements
	Curl          CmdLine
	Facts         []Fact
	Rejected      *RejectView
	Chart         Chart
	Summary       string
	SummaryIsZh   bool
	SummaryLang   string
	Description   string        // English original when SummaryIsZh
	SummaryText   []TextBlock   // Summary split into paragraphs and code (prose.go)
	OrigText      []TextBlock   // Description split the same way
	SummarySrc    template.HTML // under an upstream summary: its record (summarySource)
	CVSS          *CVSSView     // exploit conditions (cvssview.go); nil = no vector
	Events        []EventItem
	EventCount    int
	Packages      []PkgRow
	HasPatch      bool
	FixCommits    []Link
	Advisories    []Link
	Poc           []PocRow
	PocCount      string
	PocCountHTML  template.HTML
	CWEs          []CWERow
	RawRecords    []Link
	Products      string
	ProductsTotal int
	Discussion    *DiscView     // nil = discussions off (discussion.go)
	Research      *ResearchView // researcher posts on X (discussion.go)
	Corrections   *CorrView     // readers' corrections: revision log and entry (corrview.go)
	Tags          *VulnTags     // nil = no tags (tagview.go)
	Credits       []CreditRow   // empty = the panel is left out

	// Resources: the public links of the researcher posts (resources.go);
	// nil = none or unavailable (the section is left out).
	Resources *ResourcesView
}

// BuildVulnView turns a site.VulnDetail into the page view model.
func BuildVulnView(l *i18n.Locale, v *site.VulnDetail, now time.Time, api API) VulnView {
	vv := VulnView{ID: v.CVEID, Sentence: StatusSentence(l, v), SentenceHTML: StatusSentenceHTML(l, v),
		Curl:       CurlCmd(api.URL("/vuln/"+v.CVEID), ".events"),
		EventCount: len(v.Events)}
	for _, a := range v.Aliases {
		vv.Aliases = append(vv.Aliases, AliasLink(a.Alias, a.Type))
	}
	vv.HasRecord = hasSlot(v, iDIS)
	zh := l.Tag == "zh-Hans" // title_zh / summary_zh exist for Simplified Chinese only
	switch {
	case zh && v.TitleZh != nil && strings.TrimSpace(*v.TitleZh) != "":
		vv.Title = *v.TitleZh
		if v.Title != nil {
			vv.Original = *v.Title
		}
	case v.Title != nil && strings.TrimSpace(*v.Title) != "":
		vv.Title = *v.Title
		vv.TitleLang = upstreamLang(l)
	default:
		vv.TitleMissing = true
		if vv.HasRecord {
			vv.Title = l.Text("title.missing_no_title")
		} else {
			vv.Title = l.Text("title.missing_no_record")
		}
	}
	vv.Products, vv.ProductsTotal = ProductLine(l, v.Products, len(v.Products), 6)

	// Summary.
	switch {
	case zh && v.SummaryZh != nil && strings.TrimSpace(*v.SummaryZh) != "":
		vv.Summary, vv.SummaryIsZh = *v.SummaryZh, true
		vv.Description = deref(v.Description)
	case v.Description != nil && strings.TrimSpace(*v.Description) != "":
		vv.Summary = *v.Description
		vv.SummaryLang = upstreamLang(l)
		vv.SummarySrc = summarySource(l, v, api)
	}
	if vv.Summary != "" {
		// product and vendor names are never shown as code ("WS_FTP Server")
		names := make([]string, 0, 2*len(v.Products))
		for _, p := range v.Products {
			names = append(names, p.Vendor, p.Product)
		}
		vv.SummaryText = FormatText(vv.Summary, names...)
		vv.OrigText = FormatText(vv.Description, names...)
	}

	if v.IsRejected {
		r := &RejectView{Lang: upstreamLang(l)}
		if v.Rejection != nil {
			if v.Rejection.DateRejected != nil {
				r.Date = isoStamp(*v.Rejection.DateRejected).HTML()
			}
			r.Reasons = v.Rejection.Reasons
			for _, id := range v.Rejection.ReplacedBy {
				if c, ok := site.ParseCVEID(id); ok {
					r.ReplacedBy = append(r.ReplacedBy, Link{Text: c, Href: l.Path("/vuln/" + c)})
				} else {
					r.ReplacedBy = append(r.ReplacedBy, Link{Text: id})
				}
			}
		}
		vv.Rejected = r
	}

	vv.Tags = BuildVulnTags(l, v.Tags)
	vv.Facts = buildFacts(l, v)
	vv.CVSS = BuildCVSSView(l, v)
	vv.Chart = BuildChart(l, v, now)
	vv.Events = buildEvents(l, v)
	vv.EventCount = len(vv.Events)
	buildAside(l, v, &vv, api)
	return vv
}

// summarySource says which upstream record an upstream summary is the
// text of (site.VulnDetail.DescriptionSource), linked to that record: the
// upstream page an event of that record points to, else the stored raw
// record. Unknown source: the text is only said to be upstream text.
func summarySource(l *i18n.Locale, v *site.VulnDetail, api API) template.HTML {
	ds := v.DescriptionSource
	if ds == nil {
		return l.HTML("vuln.summary.upstream", "from", "unknown")
	}
	lk := Link{Text: ds.Source}
	if ds.Source == "ghsa" {
		lk.Text = ds.Key
	}
	for _, e := range v.Events {
		if e.Source != ds.Source || e.URL == nil || (ds.Source == "ghsa" && e.DedupeKey != ds.Key) {
			continue
		}
		if u, ok := SafeURL(*e.URL); ok {
			lk.Href, lk.External = u, true
			break
		}
	}
	if lk.Href == "" {
		for _, r := range v.RawRecords {
			if r.Source == ds.Source && r.Key == ds.Key {
				lk.Href = api.Href(r.Path)
				break
			}
		}
	}
	return l.HTML("vuln.summary.upstream", "from", ds.Source, "link", linkHTML(lk))
}

// tplusFact is the "T+ of the last change" figure: the stage code of the
// last transition and FormatTPlus of its days since disclosure; ok=false
// when there is no transition or it is the disclosure itself. The detail
// page's fact list and the share card (ogcard.go) both use it.
func tplusFact(v *site.VulnDetail) (code, val string, ok bool) {
	if v.Transition == nil || v.Transition.Code == "DIS" || !knownStage(v.Transition.Code) {
		return "", "", false
	}
	return v.Transition.Code, FormatTPlus(v.DaysSinceDisclosure), true
}

func hasSlot(v *site.VulnDetail, i int) bool {
	return i < len(v.Slots) && v.Slots[i].State != site.SlotNone
}

func buildFacts(l *i18n.Locale, v *site.VulnDetail) []Fact {
	var f []Fact
	if v.StageCode != nil {
		f = append(f, Fact{Label: l.Text("fact.stage"), Value: *v.StageCode, Class: StageClass(*v.StageCode) + " b"})
	} else {
		f = append(f, Fact{Label: l.Text("fact.stage"), Value: l.Text("value.no_record"), Class: "weak"})
	}
	disc := Fact{Label: l.Text("fact.disclosed"), Value: l.Text("time.unknown"), Class: "weak"}
	if len(v.Slots) > iDIS && v.Slots[iDIS].State == site.SlotKnown {
		st := StampAt(l, v.Slots[iDIS].At, deref(v.Slots[iDIS].Precision), stampLong)
		disc = Fact{Label: l.Text("fact.disclosed"), Value: st.Text, ValueHTML: st.HTML()}
	}
	f = append(f, disc)
	if code, val, ok := tplusFact(v); ok {
		fact := Fact{Label: l.Text("fact.tplus", "stage", code), Value: val}
		if v.DaysSinceDisclosure == nil {
			fact.Class = "weak"
			fact.Note = l.Text("fact.tplus_note_unknown")
		} else if v.Transition.Precision == site.PrecisionDay {
			fact.Note = l.Text("fact.tplus_note_day", "code", code)
		}
		f = append(f, fact)
	}
	if v.CVSS != nil && v.CVSS.Score != nil {
		val := strconv.FormatFloat(*v.CVSS.Score, 'f', 1, 64)
		if v.CVSS.Severity != nil {
			val += " " + strings.ToUpper(*v.CVSS.Severity)
		}
		note := ""
		if v.CVSS.Version != nil {
			note = "v" + *v.CVSS.Version
		}
		f = append(f, Fact{Label: l.Text("fact.cvss"), Value: val, Note: note})
	} else if !v.IsRejected {
		// no score is not a score of 0 (shown above as "0.0 NONE"); a
		// rejected ID has no risk to score, so the row is left out
		f = append(f, Fact{Label: l.Text("fact.cvss"), Value: l.Text("fact.cvss_none"), Class: "weak"})
	}
	if v.KEV != nil {
		due := Fact{Label: l.Text("fact.kev_due"), Value: l.Text("value.not_given"), Class: "weak"}
		if v.KEV.DueDate != nil {
			due = Fact{Label: l.Text("fact.kev_due"), Value: *v.KEV.DueDate}
		}
		f = append(f, due)
	}
	return f
}

// BuildChart lays out the lifecycle chart: rows are the six stages, x is
// time from the earliest known event to now.
func BuildChart(l *i18n.Locale, v *site.VulnDetail, now time.Time) Chart {
	byCode := map[string][]site.Event{}
	earliest := now
	for _, e := range v.Events {
		byCode[e.Code] = append(byCode[e.Code], e)
		if e.EffectiveAt != nil && e.EffectiveAt.Before(earliest) {
			earliest = *e.EffectiveAt
		}
	}
	for _, s := range v.Slots {
		if s.NotAfter != nil && s.NotAfter.Before(earliest) {
			earliest = *s.NotAfter
		}
	}
	sc := ComputeScale(earliest, now)
	longSpan := sc.Start.Year() != now.UTC().Year()
	c := Chart{Scale: sc, Ticks: sc.Ticks, NowX: pctAttr(sc.NowPct)}
	for _, t := range sc.Ticks {
		c.Grid = append(c.Grid, pctAttr(t.Pct))
	}
	latestCode := ""
	if v.Transition != nil {
		latestCode = v.Transition.Code
	}
	for i, st := range stages {
		row := ChartRow{Code: st.Code, Short: StageShort(l, st.Code), Class: st.Class}
		var marks []markSpec
		unknownSeen := map[string]bool{}
		for _, e := range byCode[st.Code] {
			if e.EffectiveAt == nil {
				label := unknownLabel(l, v, e)
				if !unknownSeen[label] {
					unknownSeen[label] = true
					row.Unknown = append(row.Unknown, label)
				}
				continue
			}
			prec := e.Precision
			if prec != site.PrecisionDay {
				prec = "exact"
			}
			marks = append(marks, markSpec{at: *e.EffectiveAt, precision: prec,
				text: chartTimeLabel(l, e.EffectiveAt, e.Precision, longSpan)})
		}
		sort.SliceStable(marks, func(a, b int) bool { return marks[a].at.Before(marks[b].at) })
		if len(marks) > 0 && st.Code == latestCode {
			marks[0].latest = true
		}
		if i < len(v.Slots) && v.Slots[i].State == site.SlotImplied {
			s := v.Slots[i]
			if s.NotAfter != nil {
				lbl := shortOrLong(*s.NotAfter, longSpan)
				marks = append(marks, markSpec{at: *s.NotAfter, precision: site.PrecisionDay, hollow: true,
					text: l.Text("chart.mark.implied", "date", lbl)})
			} else {
				row.Unknown = append(row.Unknown, l.Text("chart.unknown.implied"))
			}
		}
		row.UnknownHollow = len(row.Unknown) > 0
		if len(marks) == 0 && len(row.Unknown) == 0 {
			row.Empty = true
		}
		row.UnknownText = l.List(i18n.ListSeq, row.Unknown)
		row = buildRow(l, sc, row, marks)
		switch {
		case row.Empty:
			row.Aria = l.Text("chart.row_label", "code", st.Code, "text", l.Text("value.no_record"))
		case row.Label != nil:
			row.Aria = l.Text("chart.row_label", "code", st.Code, "text", i18n.Raw(row.Label.Text))
		default:
			row.Aria = l.Text("chart.row_label", "code", st.Code, "text", l.Text("time.unknown"))
		}
		c.Rows = append(c.Rows, row)
	}
	return c
}

func shortOrLong(t time.Time, long bool) string {
	if long {
		return t.UTC().Format(layoutDate)
	}
	return t.UTC().Format(layoutShortDate)
}

func chartTimeLabel(l *i18n.Locale, t *time.Time, precision string, long bool) string {
	u := t.UTC()
	switch {
	case precision == site.PrecisionDay:
		return l.Text("chart.mark.day", "date", shortOrLong(u, long))
	case long:
		return u.Format(layoutMinute)
	}
	return u.Format(layoutShortMinute)
}

// unknownLabel is what an event without a time shows in the "time
// unknown" column: fixed versions for a patch advisory, else the source name.
func unknownLabel(l *i18n.Locale, v *site.VulnDetail, e site.Event) string {
	if e.Type == "patch_released" {
		for _, p := range v.Patches {
			if p.EventID != e.ID {
				continue
			}
			var fixed []string
			for _, pk := range p.Packages {
				if pk.Name != nil && pk.FixedVersion != nil {
					fixed = append(fixed, l.Text("pkg.version", "name", *pk.Name, "version", *pk.FixedVersion))
				}
			}
			if len(fixed) > 0 {
				if len(fixed) > 2 {
					return l.Text("chart.unknown.fixed_many", "first", i18n.Raw(fixed[0]), "total", len(fixed),
						"more", len(fixed)-1)
				}
				return l.List(i18n.ListSeq, fixed)
			}
		}
	}
	return e.Source
}

// buildEvents is the event log: events in the store's order (known times
// ascending, unknown last) with the implied ITW entry inserted after the
// last event at or before its upper bound.
func buildEvents(l *i18n.Locale, v *site.VulnDetail) []EventItem {
	var out []EventItem
	for _, e := range v.Events {
		st := stageByCode(e.Code)
		it := EventItem{Anchor: "ev-" + strconv.FormatInt(e.ID, 10), Sign: "+", Code: e.Code, Class: st.Class,
			Name: StageName(l, e.Code), Text: EventText(l, e), Raw: RawEventJSON(e)}
		if e.EffectiveAt == nil {
			it.Time, it.TimeNote = Stamp{Text: l.Text("time.unknown")}, PrecisionNote(l, site.PrecisionUnknown)
		} else {
			it.Time = StampAt(l, e.EffectiveAt, e.Precision, stampLong)
			if e.Precision != site.PrecisionExact { // an exact time from the source needs no note
				it.TimeNote = PrecisionNote(l, e.Precision)
			}
		}
		it.Src = Link{Text: e.Source}
		if e.URL != nil {
			if u, ok := SafeURL(*e.URL); ok {
				it.Src = Link{Text: e.Source, Href: u, External: true}
				it.Upstream = u
			}
		}
		if e.DedupeKey != "" && e.DedupeKey != v.CVEID {
			it.SrcKey = e.DedupeKey
		}
		obs := e.ObservedAt
		if e.IsBackfill {
			it.Obs = l.HTML("ev.obs.backfill", "time", minuteHTML(&obs))
		} else {
			it.Obs = l.HTML("ev.obs.live", "time", minuteHTML(&obs))
		}
		out = append(out, it)
	}
	if len(v.Slots) > iITW && v.Slots[iITW].State == site.SlotImplied {
		s := v.Slots[iITW]
		it := EventItem{Anchor: "ev-itw-implied", Sign: "~", Code: "ITW", Class: stageByCode("ITW").Class,
			Name: StageName(l, "ITW"), Implied: true, TimeNote: l.Text("ev.implied.note")}
		ms := []Msg{msg("ev.implied.bound")}
		if s.NotAfter == nil {
			it.Time = Stamp{Text: l.Text("time.unknown")}
			ms = []Msg{msg("ev.implied.kev_time_unknown")}
		} else {
			it.Time = Stamp{Text: FormatNotAfter(l, s.NotAfter)} // an upper bound on a date: never converted
		}
		it.Basis = []Link{{Text: "kev", Href: l.Path("/src#kev")}}
		if v.SSVC != nil && v.SSVC.Exploitation != nil && *v.SSVC.Exploitation == "active" {
			ms = append(ms, msg("ev.implied.ssvc"))
			it.Basis = append(it.Basis, Link{Text: l.Text("ev.implied.basis_ssvc"), Href: l.Path("/src#cvelist")})
		}
		hs := make([]template.HTML, len(ms))
		for i, m := range ms {
			hs[i] = m.HTML(l)
		}
		it.Text = l.JoinHTML(hs)
		it.BasisHTML = l.HTML("ev.implied.basis", "links", linkList(l, i18n.ListAnd, it.Basis))
		pos := len(out)
		if s.NotAfter != nil {
			pos = 0
			for i, e := range v.Events {
				if e.EffectiveAt != nil && !e.EffectiveAt.After(*s.NotAfter) {
					pos = i + 1
				}
			}
		} else {
			// before the first event with unknown time
			for i, e := range v.Events {
				if e.EffectiveAt == nil {
					pos = i
					break
				}
			}
		}
		out = append(out[:pos], append([]EventItem{it}, out[pos:]...)...)
	}
	return out
}

func buildAside(l *i18n.Locale, v *site.VulnDetail, vv *VulnView, api API) {
	seenCommit := map[string]bool{}
	for _, p := range v.Patches {
		vv.HasPatch = true
		label := deref(p.AdvisoryID)
		if label == "" {
			label = p.Source
		}
		if p.URL != nil {
			vv.Advisories = append(vv.Advisories, ExtLink(label, *p.URL))
		} else {
			vv.Advisories = append(vv.Advisories, Link{Text: label})
		}
		for _, pk := range p.Packages {
			row := PkgRow{Ecosystem: deref(pk.Ecosystem), Name: deref(pk.Name), Affected: deref(pk.AffectedRange),
				Fixed: deref(pk.FixedVersion)}
			if row.Fixed != "" {
				if cmd := UpgradeCmd(row.Ecosystem, row.Name, row.Fixed); cmd != "" {
					c := newCmd(cmd, "")
					row.Upgrade = &c
				}
			}
			vv.Packages = append(vv.Packages, row)
		}
		for _, u := range p.FixCommitURLs {
			if !seenCommit[u] {
				seenCommit[u] = true
				vv.FixCommits = append(vv.FixCommits, CommitLink(u))
			}
		}
	}
	for _, ps := range v.Poc {
		row := PocRow{Source: ps.Source, Present: ps.Present}
		for _, it := range ps.Items {
			text := it.Key
			if it.Title != nil && *it.Title != "" {
				text = *it.Title
			}
			if ps.Source == "exploitdb" {
				text = "EDB-" + it.Key + " " + text
			}
			text = truncRunes(text, 80)
			var lk Link
			if it.URL != nil {
				lk = ExtLink(text, *it.URL)
			} else {
				lk = Link{Text: text}
			}
			lk.Lang = upstreamLang(l)
			row.Items = append(row.Items, lk)
		}
		vv.Poc = append(vv.Poc, row)
	}
	vv.PocCount = strconv.Itoa(v.PocSources) + "/" + strconv.Itoa(len(site.PocSourceNames))
	vv.PocCountHTML = template.HTML(`<span class="weak">` + vv.PocCount + `</span>`)
	for _, c := range v.CWEs {
		row := CWERow{ID: CWELink(c.ID), Name: deref(c.Name)}
		if row.Name != "" {
			row.Lang = upstreamLang(l)
		}
		vv.CWEs = append(vv.CWEs, row)
	}
	for _, c := range v.Credits {
		vv.Credits = append(vv.Credits, CreditRow{Role: c.Role, Name: c.Name, Source: c.Source})
	}
	for _, r := range v.RawRecords {
		vv.RawRecords = append(vv.RawRecords, Link{Text: r.Source + "/" + r.Key + ".json", Href: api.Href(r.Path)})
	}
}
