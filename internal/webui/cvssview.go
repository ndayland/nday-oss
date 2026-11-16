package webui

import (
	"html/template"
	"strings"

	"nday.land/nday/internal/classify"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// Exploit conditions of the vulnerability page: the CVSS vector behind the
// score on the facts row (site.VulnDetail.CVSS), shown as delivered, with
// its exploitability metrics explained one by one:
//
//	2.0        AV AC Au
//	3.0 / 3.1  AV AC PR UI
//	4.0        AV AC AT PR UI
//
// Impact metrics (C/I/A, S, VC…SA) are not explained. A value the
// specification of that version does not define is shown as its code only;
// a vector of a version not listed above is shown without explanations.
// No vector: no block.

// CVSSView is the exploit-conditions block (nil = no vector).
type CVSSView struct {
	Vector  string        // as delivered
	Version string        // declared by the vector ("" = none we know)
	Source  template.HTML // version and provenance (vuln.cvss.source)
	Items   []CVSSItem    // empty for an unknown version
}

// CVSSItem is one explained metric.
type CVSSItem struct {
	Code  string // "AV:N", as in the vector
	Label string // the metric's name
	Text  string // the value explained; "" when the value is not defined
}

// cvssCond is one exploitability metric of a vector: its name, its value
// and the message that explains the value (Key "" = undefined value).
type cvssCond struct {
	Metric, Value string
	Key           string // select message, keyed by Value
}

// cvssMetricKeys: per version, the exploitability metrics in display order,
// the select message explaining each, and the values that message defines
// (the specification's values for that version).
var cvssMetricKeys = map[string][]struct {
	metric, key string
	values      string // single-letter values
}{
	classify.V2: {
		{"AV", "vuln.cvss.av2", "LAN"},
		{"AC", "vuln.cvss.ac2", "HML"},
		{"Au", "vuln.cvss.au", "MSN"},
	},
	classify.V30: v3Conds,
	classify.V31: v3Conds,
	classify.V40: {
		{"AV", "vuln.cvss.av", "NALP"},
		{"AC", "vuln.cvss.ac4", "LH"},
		{"AT", "vuln.cvss.at", "NP"},
		{"PR", "vuln.cvss.pr", "NLH"},
		{"UI", "vuln.cvss.ui4", "NPA"},
	},
}

var v3Conds = []struct {
	metric, key string
	values      string
}{
	{"AV", "vuln.cvss.av", "NALP"},
	{"AC", "vuln.cvss.ac", "LH"},
	{"PR", "vuln.cvss.pr", "NLH"},
	{"UI", "vuln.cvss.ui", "NR"},
}

// cvssConditions parses vector and returns its version and exploitability
// metrics. Metrics missing from the vector are left out; a value that is
// not one letter of the version's defined values gets Key "". An unknown
// version returns no metrics.
func cvssConditions(vector string) (version string, out []cvssCond) {
	vector = strings.TrimSpace(vector)
	version = classify.VersionOfVector(vector)
	defs, ok := cvssMetricKeys[version]
	if !ok {
		return "", nil
	}
	body := vector
	if version != classify.V2 {
		_, body, _ = strings.Cut(vector, "/")
	}
	got := map[string]string{}
	for _, part := range strings.Split(body, "/") {
		if k, v, ok := strings.Cut(part, ":"); ok {
			if _, dup := got[k]; !dup {
				got[k] = v
			}
		}
	}
	for _, d := range defs {
		v, ok := got[d.metric]
		if !ok {
			continue
		}
		c := cvssCond{Metric: d.metric, Value: v}
		if len(v) == 1 && strings.Contains(d.values, v) {
			c.Key = d.key
		}
		out = append(out, c)
	}
	return version, out
}

// cvssItem renders one condition in l (the value message is selected by
// the value; an undefined value gets no text).
func cvssItem(l *i18n.Locale, c cvssCond) CVSSItem {
	it := CVSSItem{Code: c.Metric + ":" + c.Value, Label: l.Text("vuln.cvss.metric", "metric", c.Metric)}
	if c.Key != "" {
		it.Text = l.Text(c.Key, "v", c.Value)
	}
	return it
}

// BuildCVSSView builds the block for v (nil without a vector).
func BuildCVSSView(l *i18n.Locale, v *site.VulnDetail) *CVSSView {
	if v.CVSS == nil || v.CVSS.Vector == nil || strings.TrimSpace(*v.CVSS.Vector) == "" {
		return nil
	}
	cv := &CVSSView{Vector: strings.TrimSpace(*v.CVSS.Vector)}
	var conds []cvssCond
	cv.Version, conds = cvssConditions(cv.Vector)
	for _, c := range conds {
		cv.Items = append(cv.Items, cvssItem(l, c))
	}
	ver := cv.Version
	if ver == "" && v.CVSS.Version != nil {
		ver = *v.CVSS.Version // what the source says; the vector declares none we know
	}
	cv.Source = cvssSource(l, v, ver)
	return cv
}

// cvssSource is the version-and-provenance line: who delivered the vector
// (site.CVSS.Source), linked to that record where an event of the page
// gives its URL.
func cvssSource(l *i18n.Locale, v *site.VulnDetail, ver string) template.HTML {
	var ev *site.Event
	for i := range v.Events {
		if v.Events[i].ID == v.CVSS.EventID {
			ev = &v.Events[i]
			break
		}
	}
	link := func(text string) template.HTML {
		lk := Link{Text: text}
		if ev != nil && ev.URL != nil {
			if u, ok := SafeURL(*ev.URL); ok {
				lk.Href, lk.External = u, true
			}
		}
		return linkHTML(lk)
	}
	verTok := ver
	if verTok == "" {
		verTok = "?"
	}
	src := v.CVSS.Source
	switch {
	case src == "cvelist:cna" && v.Assigner != nil && strings.TrimSpace(*v.Assigner) != "":
		return l.HTML("vuln.cvss.source", "src", "cna", "version", verTok, "org", link(strings.TrimSpace(*v.Assigner)))
	case strings.HasPrefix(src, "cvelist:adp:") && strings.TrimPrefix(src, "cvelist:adp:") != "":
		return l.HTML("vuln.cvss.source", "src", "adp", "version", verTok, "org", link(strings.TrimPrefix(src, "cvelist:adp:")))
	case src == "ghsa" && ev != nil && ev.DedupeKey != "":
		return l.HTML("vuln.cvss.source", "src", "ghsa", "version", verTok, "org", link(ev.DedupeKey))
	}
	return l.HTML("vuln.cvss.source", "src", "other", "version", verTok, "org", link(src))
}
