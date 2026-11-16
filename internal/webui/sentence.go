package webui

import (
	"html/template"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// Slot indexes (site.StageInfos order).
const (
	iDIS = iota
	iPAT
	iANA
	iPOC
	iITW
	iKEV
)

// Msg is a chosen catalog message with its values: rule code decides WHICH
// messages apply, the catalog owns the words.
type Msg struct {
	Key  string
	Args []any // name/value pairs
}

func msg(key string, kv ...any) Msg { return Msg{Key: key, Args: kv} }

// Text renders m in l as plain text.
func (m Msg) Text(l *i18n.Locale) string { return l.Text(m.Key, m.resolve(l)...) }

// HTML renders m in l as HTML (upstream values marked lang="en"; times
// with a time of day as convertible <time> elements).
func (m Msg) HTML(l *i18n.Locale) template.HTML { return l.HTML(m.Key, m.resolveHTML(l)...) }

// localValue is a value whose text depends on the locale (a time that may
// be "unknown", a list joined with the locale's list pattern).
type localValue interface{ value(l *i18n.Locale) any }

// htmlValue is a localValue with its own HTML form (a convertible time).
type htmlValue interface {
	html(l *i18n.Locale) template.HTML
}

func (m Msg) resolveHTML(l *i18n.Locale) []any {
	out := make([]any, len(m.Args))
	for i, a := range m.Args {
		switch v := a.(type) {
		case htmlValue:
			a = v.html(l)
		case localValue:
			a = v.value(l)
		}
		out[i] = a
	}
	return out
}

func (m Msg) resolve(l *i18n.Locale) []any {
	out := make([]any, len(m.Args))
	for i, a := range m.Args {
		if lv, ok := a.(localValue); ok {
			a = lv.value(l)
		}
		out[i] = a
	}
	return out
}

// renderMsgs renders sentence messages and joins them with the locale's
// sentence joiner.
func renderMsgs(l *i18n.Locale, ms []Msg) string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Text(l)
	}
	return l.Join(out)
}

// Lead-sentence keys per stage: "N days after disclosure" and "N days
// before the CVE record". One key per stage so every locale can phrase each
// stage's event naturally (verb, gender, word order) instead of slotting a
// stage name into a shared frame.
var (
	leadAfterKeys = map[string]string{
		"PAT": "status.lead.after.pat", "ANA": "status.lead.after.ana", "POC": "status.lead.after.poc",
		"ITW": "status.lead.after.itw", "KEV": "status.lead.after.kev",
	}
	leadBeforeKeys = map[string]string{
		"PAT": "status.lead.before.pat", "ANA": "status.lead.before.ana", "POC": "status.lead.before.poc",
		"ITW": "status.lead.before.itw", "KEV": "status.lead.before.kev",
	}
)

// renderMsgsHTML is renderMsgs as HTML.
func renderMsgsHTML(l *i18n.Locale, ms []Msg) template.HTML {
	out := make([]template.HTML, len(ms))
	for i, m := range ms {
		out[i] = m.HTML(l)
	}
	return l.JoinHTML(out)
}

// StatusSentenceHTML is StatusSentence as HTML, with convertible times.
func StatusSentenceHTML(l *i18n.Locale, v *site.VulnDetail) template.HTML {
	if v == nil {
		return ""
	}
	return renderMsgsHTML(l, StatusMessages(v))
}

// StatusSentence is the one-paragraph, plain-language state of a
// vulnerability, generated only from facts in v (never guessing).
func StatusSentence(l *i18n.Locale, v *site.VulnDetail) string {
	if v == nil {
		return ""
	}
	return renderMsgs(l, StatusMessages(v))
}

// StatusMessages chooses the sentences of the status paragraph, in order:
//
//  1. Rejected CVE: say so first (status.rejected).
//  2. Lead: no disclosure event -> the official record is missing
//     (status.no_record); disclosure time unknown (status.disclosure_unknown);
//     otherwise the highest later stage with a known time and day count
//     (status.lead.same_day / status.lead.after.<stage> /
//     status.lead.before.<stage> for negative counts), else
//     status.disclosed_at.
//  3. KEV listing date when in KEV and not already the lead
//     (status.kev.at / status.kev.time_unknown).
//  4. Patch: fixed versions from advisories (status.patch.fixed with up to
//     two, status.patch.fixed_many beyond), an advisory without a fixed
//     version (status.patch.no_version), or none (status.patch.none).
//  5. PoC: which of the three curated sources have it (status.poc.*).
//  6. Not in KEV: status.kev.not_listed (true as of the last KEV fetch).
//
// For a rejected ID the "nothing on record" sentences of 4-6
// (status.patch.none, status.poc.none, status.kev.not_listed) are left out:
// they are risk and fix boilerplate that does not apply to an ID that names
// no vulnerability. Records that do exist (a patch, a PoC, a KEV listing)
// are still said.
//
// Values are language-neutral (dates, versions, source names) or numbers;
// lists of them are built with the locale's list patterns at render time.
func StatusMessages(v *site.VulnDetail) []Msg {
	if v == nil {
		return nil
	}
	var out []Msg
	if v.IsRejected {
		out = append(out, msg("status.rejected"))
	}
	slot := func(i int) *site.DetailSlot {
		if i < len(v.Slots) {
			return &v.Slots[i]
		}
		return &site.DetailSlot{Slot: site.Slot{State: site.SlotNone}}
	}
	dis := slot(iDIS)
	kev := slot(iKEV)
	leadIsKEV := false
	switch dis.State {
	case site.SlotNone:
		out = append(out, msg("status.no_record"))
	case site.SlotUnknown, site.SlotImplied:
		out = append(out, msg("status.disclosure_unknown"))
	default:
		var lead *Msg
		for i := iKEV; i > iDIS; i-- {
			s := slot(i)
			if s.State != site.SlotKnown || s.DaysSinceDisclosure == nil {
				continue
			}
			d := *s.DaysSinceDisclosure
			code := stages[i].Code
			var m Msg
			switch {
			case d == 0:
				m = msg("status.lead.same_day", "stage", code)
			case d > 0:
				m = msg(leadAfterKeys[code], "days", d)
			default:
				m = msg(leadBeforeKeys[code], "days", -d)
			}
			lead = &m
			leadIsKEV = i == iKEV
			break
		}
		if lead == nil {
			out = append(out, msg("status.disclosed_at", "time", timeValue{dis.At, deref(dis.Precision)}))
		} else {
			out = append(out, *lead)
		}
	}
	if kev.State != site.SlotNone && !leadIsKEV {
		if kev.State == site.SlotKnown {
			out = append(out, msg("status.kev.at", "date", timeValue{kev.At, deref(kev.Precision)}))
		} else {
			out = append(out, msg("status.kev.time_unknown"))
		}
	}
	for _, m := range []Msg{patchMessage(v, slot(iPAT)), pocMessage(v)} {
		if v.IsRejected && (m.Key == "status.patch.none" || m.Key == "status.poc.none") {
			continue
		}
		out = append(out, m)
	}
	if kev.State == site.SlotNone && !v.IsRejected {
		out = append(out, msg("status.kev.not_listed"))
	}
	return out
}

// timeValue is an instant rendered by precision (FormatAt) when the message
// is rendered; it is a language-neutral ISO 8601 token unless unknown.
type timeValue struct {
	t    *time.Time
	prec string
}

func (v timeValue) value(l *i18n.Locale) any { return i18n.Raw(FormatAt(l, v.t, v.prec)) }

func (v timeValue) html(l *i18n.Locale) template.HTML {
	return StampAt(l, v.t, v.prec, stampLong).HTML()
}

// isoValue is an RFC 3339 instant from an event's detail, shown to the
// minute (isoMinute); convertible in HTML when it parses.
type isoValue string

func (v isoValue) value(*i18n.Locale) any { return i18n.Raw(isoMinute(string(v))) }

func (v isoValue) html(*i18n.Locale) template.HTML { return isoStamp(string(v)).HTML() }

// pkgList is a list of "name version" pairs rendered with a list pattern.
type pkgList struct {
	kind  string
	items [][2]string
}

func (v pkgList) value(l *i18n.Locale) any {
	items := make([]string, len(v.items))
	for i, p := range v.items {
		items[i] = l.Text("pkg.version", "name", p[0], "version", p[1])
	}
	return i18n.Raw(l.List(v.kind, items))
}

// listValue is a list of language-neutral tokens rendered with a list pattern.
type listValue struct {
	kind  string
	items []string
}

func (v listValue) value(l *i18n.Locale) any { return i18n.Raw(l.List(v.kind, v.items)) }

func patchMessage(v *site.VulnDetail, pat *site.DetailSlot) Msg {
	if pat.State == site.SlotNone {
		return msg("status.patch.none")
	}
	var fixed [][2]string
	seen := map[[2]string]bool{}
	for _, p := range v.Patches {
		for _, pk := range p.Packages {
			if pk.FixedVersion == nil || pk.Name == nil {
				continue
			}
			s := [2]string{*pk.Name, *pk.FixedVersion}
			if !seen[s] {
				seen[s] = true
				fixed = append(fixed, s)
			}
		}
	}
	switch {
	case len(fixed) == 0:
		return msg("status.patch.no_version")
	case len(fixed) <= 2:
		return msg("status.patch.fixed", "versions", pkgList{i18n.ListAnd, fixed}, "count", len(fixed))
	}
	return msg("status.patch.fixed_many", "shown", pkgList{i18n.ListSeq, fixed[:2]}, "total", len(fixed),
		"more", len(fixed)-2)
}

func pocMessage(v *site.VulnDetail) Msg {
	var have []string
	for _, p := range v.Poc {
		if p.Present {
			have = append(have, p.Source)
		}
	}
	total := len(site.PocSourceNames)
	switch len(have) {
	case 0:
		return msg("status.poc.none")
	case total:
		return msg("status.poc.all")
	}
	return msg("status.poc.some", "sources", listValue{i18n.ListAnd, have}, "n", len(have), "total", total)
}
