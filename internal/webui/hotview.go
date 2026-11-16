package webui

import (
	"net/url"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// SlotView is one marker of a lifecycle strip (216x22 SVG, 36px per slot).
// The strip draws shared shapes (parts.tmpl stripdefs) by reference: Ref
// names the marker (k known, o hollow, n none; then the slot index), Halo the
// halo of the slot ("h" and the index) when it is the latest change. The
// stylesheet colours each by its slot, so slot i must be stage i.
type SlotView struct {
	State  string // marker classes: "mk mk-known" | "mk mk-hollow" | "mk mk-none"
	Latest bool   // draw the halo
	Ref    string // marker shape: k0..k5, o0..o5, n0..n5
	Halo   string // halo shape h0..h5, "" when not latest
}

var slotRefs = map[string]string{"mk mk-known": "k", "mk mk-hollow": "o", "mk mk-none": "n"}

// Strip is the six-slot lifecycle strip of a list row.
type Strip struct {
	Slots []SlotView
	Label string // accessible description
}

// SlotClass maps a slot to its marker: filled (known), hollow (unknown or
// implied), empty (none); latest marks the most recent change (halo).
func SlotClass(s site.Slot) (state string, latest bool) {
	state = "mk mk-none"
	switch s.State {
	case site.SlotKnown:
		state = "mk mk-known"
	case site.SlotUnknown, site.SlotImplied:
		state = "mk mk-hollow"
	}
	return state, s.Latest && s.State != site.SlotNone
}

var slotStates = map[string]string{site.SlotKnown: "known", site.SlotUnknown: "unknown", site.SlotImplied: "implied"}

// BuildStrip renders slots as a strip (36px per slot, centres at 18+36i;
// slots in StageInfos order, DIS..KEV).
// Its accessible label lists each slot that has happened with the locale's
// "strip.slot" phrase (by state), joined with "strip.sep".
func BuildStrip(l *i18n.Locale, slots []site.Slot) Strip {
	var st Strip
	var parts []string
	for i, s := range slots {
		state, latest := SlotClass(s)
		v := SlotView{State: state, Latest: latest, Ref: slotRefs[state] + strconv.Itoa(i)}
		if latest {
			v.Halo = "h" + strconv.Itoa(i)
		}
		st.Slots = append(st.Slots, v)
		if s.State == site.SlotNone {
			continue
		}
		k := slotStates[s.State]
		if latest {
			k = "latest"
		}
		if k == "" {
			continue
		}
		parts = append(parts, l.Text("strip.slot", "state", k, "stage", StageName(l, s.Code)))
	}
	if len(parts) == 0 {
		st.Label = l.Text("strip.label_empty")
	} else {
		st.Label = l.Text("strip.label", "slots", i18n.Raw(strings.Join(parts, l.Text("strip.sep"))))
	}
	return st
}

// ProductLine renders affected products: pairs of the same vendor are merged
// ("Barracuda Networks / ESG, Load Balancer ADC"), different vendors joined
// with " · ", and "+N" appended when total exceeds what is shown. max limits
// how many of the given pairs are used. Vendor and product names are
// upstream text; separators inside a vendor come from the locale.
func ProductLine(l *i18n.Locale, ps []site.Product, total, max int) (string, int) {
	if len(ps) > max {
		ps = ps[:max]
	}
	var groups []string
	var cur []string
	vendor := ""
	flush := func() {
		if len(cur) > 0 {
			groups = append(groups, vendor+" / "+l.List(i18n.ListSeq, cur))
		}
	}
	for i, p := range ps {
		if i == 0 || !strings.EqualFold(p.Vendor, vendor) {
			flush()
			vendor, cur = p.Vendor, nil
		}
		cur = append(cur, p.Product)
	}
	flush()
	s := strings.Join(groups, " · ")
	if more := total - len(ps); more > 0 {
		if s == "" {
			s = l.Text("products.count", "n", more)
		} else {
			s += " +" + strconv.Itoa(more)
		}
	}
	return s, total
}

// What a list row knows about the official CVE record, to say why it has no
// title ("not collected yet" and "the record gives no title" are different
// states).
const (
	recordUnknown = iota // the row data cannot tell (search rows)
	recordMissing        // no CVE record collected yet (no DIS event)
	recordPresent        // a CVE record is collected (it has a DIS event)
)

// slotsRecord tells from a row's lifecycle slots whether the CVE record is
// collected: the DIS slot comes only from the cvelist record
// (site/vuln.go; model.EventDisclosed is emitted by cvelist alone). No
// slots means no event at all, so no record either.
func slotsRecord(slots []site.Slot) int {
	if len(slots) > iDIS && slots[iDIS].State != site.SlotNone {
		return recordPresent
	}
	return recordMissing
}

// rowTitle picks title_zh (Simplified Chinese pages only), then the upstream
// title; missing reports the placeholder, chosen by what the row knows about
// the CVE record (recordUnknown/Missing/Present). lang is "en" when the
// title is upstream English shown on a non-English page.
func rowTitle(l *i18n.Locale, zh, en *string, record int) (title string, missing bool, lang string) {
	if l.Tag == "zh-Hans" && zh != nil && strings.TrimSpace(*zh) != "" {
		return *zh, false, ""
	}
	if en != nil && strings.TrimSpace(*en) != "" {
		return *en, false, upstreamLang(l)
	}
	switch record {
	case recordMissing:
		return l.Text("title.missing_row"), true, ""
	case recordPresent:
		return l.Text("title.missing_row_no_title"), true, ""
	}
	return l.Text("title.missing_row_unknown"), true, ""
}

// upstreamLang is the lang attribute of upstream (English) record text.
func upstreamLang(l *i18n.Locale) string {
	if l.IsPrimary() {
		return ""
	}
	return "en"
}

// HotRowView is one hot-list row.
type HotRowView struct {
	DateHeader   string // non-empty on the first row of a UTC date
	Change       string // +KEV
	ChangeText   string // what changed, in words (hot.change); "" = no change
	ChangeClass  string
	Time         Stamp
	Prec         string
	CVE          string
	Href         string
	Title        string
	TitleMissing bool
	TitleLang    string
	Vendor       string
	Rejected     bool
	Strip        Strip
	TPlus        string
	TPlusTitle   string
	Poc          string
	PocZero      bool
	Tags         []TagChip  // at most three (tags.RowPicks), each adds itself as a filter
	Rsch         *RschBadge // researchers on X in the last 7 days (nil = none)
	// Pinned: shown first because researchers are discussing it now
	// (site/pin.go: by the rule or filled from the discussed ranking; one
	// badge for both); it has no date header and does not start a date
	// group.
	Pinned bool
}

// RschBadge is the researcher count of a list row (a public aggregate;
// site/public.go).
type RschBadge struct {
	N     string // the count, formatted
	Title string // "N researchers mentioned this in the last 7 days"
}

// rschBadge is the badge for n researchers (nil when n is 0).
func rschBadge(l *i18n.Locale, n int) *RschBadge {
	if n <= 0 {
		return nil
	}
	return &RschBadge{N: l.Int(int64(n)), Title: l.Text("rsch.count", "n", n)}
}

// FilterOpt is one filter value link. Its label is the locale's words
// (hot.filter.*); the query parameter it sets stays the API's.
type FilterOpt struct {
	Label  string
	Href   string
	Active bool
}

// HotFilters is the canonical hot-list selection as the page sees it.
type HotFilters struct {
	Since           time.Duration
	MinStage        string // event type
	IncludeRejected bool
	Cursor          string
	// Tags: ?tag= filters (vocabulary slugs, canonical order; unknown slugs
	// were dropped by parseHotFilters).
	Tags []string
	// Fixed: the tag of a /tag/<slug> page ("" on the home page); it is part
	// of the path, not of the query.
	Fixed string
}

// AllTags is the tag filter of the list: Fixed plus Tags, canonical.
func (f HotFilters) AllTags() []string {
	if f.Fixed == "" {
		return f.Tags
	}
	return withTag(f.Tags, f.Fixed)
}

// base is the locale-neutral path of the list.
func (f HotFilters) base() string {
	if f.Fixed != "" {
		return tagPath(f.Fixed)
	}
	return "/"
}

// Page defaults (the API's defaults).
const (
	defaultSince    = 7 * 24 * time.Hour
	defaultMinStage = "patch_released"
	hotPageSize     = 50
)

var (
	sinceChoices = []string{"24h", "7d", "30d"}
	stageChoices = []string{"patch", "poc", "exploited"}
)

// Query renders f as page query parameters, defaults omitted.
func (f HotFilters) Query(withCursor bool) string {
	q := url.Values{}
	if f.Since != defaultSince {
		q.Set("since", formatSince(f.Since))
	}
	if f.MinStage != defaultMinStage {
		q.Set("min_stage", stageAlias(f.MinStage))
	}
	if f.IncludeRejected {
		q.Set("include_rejected", "1")
	}
	if withCursor && f.Cursor != "" {
		q.Set("cursor", f.Cursor)
	}
	s := encodeOrdered(q, "since", "min_stage", "include_rejected")
	if len(f.Tags) > 0 {
		if s != "" {
			s += "&"
		}
		s += tagQuery(f.Tags)
	}
	if c := encodeOrdered(q, "cursor"); c != "" {
		if s != "" {
			s += "&"
		}
		s += c
	}
	return s
}

// encodeOrdered encodes q in the given key order.
func encodeOrdered(q url.Values, keys ...string) string {
	var parts []string
	for _, k := range keys {
		if v, ok := q[k]; ok {
			parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(v[0]))
		}
	}
	return strings.Join(parts, "&")
}

// Href is the locale-neutral page URL for f.
func (f HotFilters) Href(withCursor bool) string {
	if q := f.Query(withCursor); q != "" {
		return f.base() + "?" + q
	}
	return f.base()
}

// formatSince is site.FormatSince, except that one day stays "24h" like the
// filter button says.
func formatSince(d time.Duration) string {
	if d == 24*time.Hour {
		return "24h"
	}
	return site.FormatSince(d)
}

func stageAlias(t string) string {
	for _, s := range site.StageInfos {
		if s.Type == t {
			return s.Alias
		}
	}
	return t
}

// APIPath is the equivalent JSON API endpoint path for API (filters only,
// always explicit): "/hot?since=...".
func (f HotFilters) APIPath() string {
	q := "since=" + url.QueryEscape(formatSince(f.Since)) + "&min_stage=" + url.QueryEscape(stageAlias(f.MinStage))
	if f.IncludeRejected {
		q += "&include_rejected=true"
	}
	if t := f.AllTags(); len(t) > 0 {
		q += "&" + tagQuery(t)
	}
	return "/hot?" + q
}

// HotView is the home page.
type HotView struct {
	Since     []FilterOpt
	Stage     []FilterOpt
	Rejected  FilterOpt
	Curl      CmdLine
	APIPath   string
	Rows      []HotRowView
	NextHref  string
	FirstHref string
	OnCursor  bool
	Window    string
	MinCode   string
	// Tag filters: the active ?tag= chips (each removable), the link to the
	// vocabulary, and on a tag page its heading.
	Chips    []TagChip
	TagsHref string
	Tag      *TagHead
	// Custom: a selection other than the defaults (the filters start open on
	// phones; hot.tmpl, app.js).
	Custom bool
}

// BuildHotView builds the home page view.
func BuildHotView(l *i18n.Locale, f HotFilters, page *site.HotPage, api API) HotView {
	hv := HotView{Curl: CurlCmd(api.URL(f.APIPath()), "."), APIPath: api.Href(f.APIPath()),
		Window: formatSince(f.Since), MinCode: site.StageCode(f.MinStage),
		Custom: f.Since != defaultSince || f.MinStage != defaultMinStage || f.IncludeRejected || len(f.Tags) > 0}
	for _, s := range sinceChoices {
		d, _ := site.ParseSince(s)
		g := f
		g.Since, g.Cursor = d, ""
		hv.Since = append(hv.Since, FilterOpt{Label: l.Text("hot.filter.since_opt", "window", s), Href: l.Path(g.Href(false)), Active: d == f.Since})
	}
	for _, s := range stageChoices {
		t, _ := site.ParseStage(s)
		g := f
		g.MinStage, g.Cursor = t, ""
		hv.Stage = append(hv.Stage, FilterOpt{Label: l.Text("hot.filter.stage_opt", "stage", s), Href: l.Path(g.Href(false)), Active: t == f.MinStage})
	}
	g := f
	g.IncludeRejected, g.Cursor = !f.IncludeRejected, ""
	hv.Rejected = FilterOpt{Label: l.Text("hot.filter.rejected"), Href: l.Path(g.Href(false)), Active: f.IncludeRejected}
	hv.TagsHref = l.Path("/tags")
	for _, s := range f.Tags {
		g := f
		g.Tags, g.Cursor = withoutTag(f.Tags, s), ""
		c := chip(s, l.Path(tagPath(s)))
		c.Remove = l.Path(g.Href(false))
		hv.Chips = append(hv.Chips, c)
	}
	addTag := func(s string) string {
		g := f
		g.Cursor = ""
		if s != f.Fixed {
			g.Tags = withTag(f.Tags, s)
		}
		return l.Path(g.Href(false))
	}
	if page != nil {
		lastDate := ""
		for _, r := range page.Rows {
			var row HotRowView
			if r.Pinned {
				none := ""
				row = BuildHotRow(l, r, &none)
				row.DateHeader = ""
			} else {
				row = BuildHotRow(l, r, &lastDate)
			}
			row.Tags = RowChips(r.Tags, addTag)
			hv.Rows = append(hv.Rows, row)
		}
		if page.NextCursor != nil {
			n := f
			n.Cursor = *page.NextCursor
			hv.NextHref = l.Path(n.Href(true))
		}
	}
	if f.Cursor != "" {
		hv.OnCursor = true
		hv.FirstHref = l.Path(f.Href(false))
	}
	return hv
}

// ChangeText says in words what a row's transition to code was (the code
// itself for an unknown code).
func ChangeText(l *i18n.Locale, code string) string {
	if !knownStage(code) {
		return code
	}
	return l.Text("hot.change", "stage", code)
}

// BuildHotRow converts one row; lastDate tracks date grouping across rows.
func BuildHotRow(l *i18n.Locale, r site.HotRow, lastDate *string) HotRowView {
	at := r.Transition.At
	v := HotRowView{CVE: r.CVEID, Href: l.Path("/vuln/" + r.CVEID), Rejected: r.IsRejected,
		Change: "+" + r.Transition.Code, ChangeText: ChangeText(l, r.Transition.Code), ChangeClass: StageClass(r.Transition.Code),
		Time: StampAt(l, &at, r.Transition.Precision, stampShort), Prec: PrecisionShort(l, r.Transition.Precision),
		Strip: BuildStrip(l, r.Slots), TPlus: FormatTPlus(r.DaysSinceDisclosure), TPlusTitle: TPlusTitle(l, r.DaysSinceDisclosure),
		Poc: strconv.Itoa(r.PocSources) + "/" + strconv.Itoa(len(site.PocSourceNames)), PocZero: r.PocSources == 0}
	v.Title, v.TitleMissing, v.TitleLang = rowTitle(l, r.TitleZh, r.Title, slotsRecord(r.Slots))
	v.Vendor, _ = ProductLine(l, r.Products, r.ProductCount, 2)
	v.Rsch = rschBadge(l, r.Researchers)
	v.Pinned = r.Pinned
	if d := DateGroupLabel(l, at); d != *lastDate {
		v.DateHeader = d
		*lastDate = d
	}
	return v
}
