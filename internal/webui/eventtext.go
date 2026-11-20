package webui

import (
	"encoding/json"
	"html/template"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// detailMap decodes an event's detail JSON (nil on anything but an object).
func detailMap(raw json.RawMessage) map[string]any {
	var m map[string]any
	if len(raw) == 0 || json.Unmarshal(raw, &m) != nil {
		return nil
	}
	return m
}

// str returns m[k] as a trimmed, length-capped string ("" if absent or not a
// string/number).
func str(m map[string]any, k string) string {
	switch v := m[k].(type) {
	case string:
		return truncRunes(strings.TrimSpace(v), 200)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	}
	return ""
}

func obj(m map[string]any, k string) map[string]any {
	o, _ := m[k].(map[string]any)
	return o
}

func list(m map[string]any, k string) []any {
	l, _ := m[k].([]any)
	return l
}

// EventText is the rule-generated one-paragraph text of an event, built only
// from its type, source and detail (see EventMessages), as HTML: titles of
// upstream records are marked as English outside the English locale.
func EventText(l *i18n.Locale, e site.Event) template.HTML {
	ms := EventMessages(e)
	out := make([]template.HTML, len(ms))
	for i, m := range ms {
		out[i] = m.HTML(l)
	}
	return l.JoinHTML(out)
}

// EventMessages chooses the sentences describing an event. Unknown shapes
// fall back to ev.generic, which claims nothing beyond "source X reported
// an event of this stage".
func EventMessages(e site.Event) []Msg {
	d := detailMap(e.Detail)
	switch {
	case e.Source == "cvelist" && e.Type == "disclosed":
		return cvelistMessages(d)
	case e.Source == "kev" && e.Type == "kev_added":
		return kevMessages(d)
	case e.Source == "ghsa" && e.Type == "patch_released":
		return ghsaMessages(d)
	case e.Source == "exploitdb" && e.Type == "poc_published":
		title, id := str(d, "title"), str(d, "edb_id")
		var ms []Msg
		switch {
		case title != "" && id != "":
			ms = append(ms, msg("ev.edb.added", "known", "title_id", "title", i18n.Upstream(title), "edb", "EDB-"+id))
		case title != "":
			ms = append(ms, msg("ev.edb.added", "known", "title", "title", i18n.Upstream(title)))
		case id != "":
			ms = append(ms, msg("ev.edb.added", "known", "id", "edb", "EDB-"+id))
		default:
			ms = append(ms, msg("ev.edb.added", "known", "none"))
		}
		if v, ok := d["verified"].(bool); ok && v {
			ms = append(ms, msg("ev.edb.verified"))
		}
		return ms
	case e.Source == "metasploit" && e.Type == "poc_published":
		return []Msg{namedItem("ev.msf.added", "module", str(d, "fullname"), str(d, "title")), msg("ev.msf.no_time")}
	case e.Source == "nuclei" && e.Type == "poc_published":
		return []Msg{namedItem("ev.nuclei.added", "template", str(d, "template_id"), str(d, "title")), msg("ev.nuclei.no_time")}
	case e.Source == "github" && e.Type == "poc_published" && str(d, "title") != "":
		// a trusted repository (migration 0032): its name and why the date is a day
		return []Msg{msg("ev.github.repo", "repo", str(d, "title")), msg("ev.github.created")}
	case e.Source == "osssec" && e.Type == "analysis_published":
		// a post on the oss-security list; the post itself is the source link
		kind := "post"
		if r, ok := d["is_reply"].(bool); ok && r {
			kind = "reply"
		}
		if s := str(d, "subject"); s != "" {
			return []Msg{msg("ev.osssec.post", "kind", kind, "subject", i18n.Upstream(s))}
		}
		return []Msg{msg("ev.osssec.post", "kind", "none")}
	case e.Source == "zerowire" && e.Type == "analysis_published":
		// a Cloudflare Zero Wire advisory; the advisory itself is the source link
		if s := str(d, "title"); s != "" {
			return []Msg{msg("ev.zerowire.advisory", "kind", "advisory", "title", i18n.Upstream(s))}
		}
		return []Msg{msg("ev.zerowire.advisory", "kind", "none")}
	}
	stage := e.Code
	if !knownStage(stage) {
		stage = "other"
	}
	return []Msg{msg("ev.generic", "stage", stage, "source", e.Source)}
}

// namedItem picks the variant of a "source added <name> (<title>)" message
// by which of name and title are known.
func namedItem(key, nameVar, name, title string) Msg {
	switch {
	case name != "" && title != "":
		return msg(key, "known", "name_title", nameVar, name, "title", i18n.Upstream(title))
	case name != "":
		return msg(key, "known", "name", nameVar, name)
	case title != "":
		return msg(key, "known", "title", "title", i18n.Upstream(title))
	}
	return msg(key, "known", "none")
}

func cvelistMessages(d map[string]any) []Msg {
	if strings.EqualFold(str(d, "state"), "REJECTED") {
		if dr := str(d, "date_rejected"); dr != "" {
			return []Msg{msg("ev.cve.rejected_at", "time", isoValue(dr))}
		}
		return []Msg{msg("ev.cve.rejected")}
	}
	var ms []Msg
	if a := str(d, "assigner_short_name"); a != "" {
		ms = append(ms, msg("ev.cve.published_by", "assigner", a))
	} else {
		ms = append(ms, msg("ev.cve.published"))
	}
	if c := obj(d, "cvss"); c != nil {
		if score := str(c, "base_score"); score != "" {
			ms = append(ms, msg("ev.cve.cvss", "severity", severityValue(str(c, "base_severity")), "score", score))
		}
	}
	if ss := obj(d, "ssvc"); ss != nil {
		switch str(ss, "exploitation") {
		case "active":
			ms = append(ms, msg("ev.cve.ssvc_active"))
		case "poc":
			ms = append(ms, msg("ev.cve.ssvc_poc"))
		}
	}
	return ms
}

func kevMessages(d map[string]any) []Msg {
	due := str(d, "due_date")
	forensic := strings.EqualFold(str(d, "forensic_triage"), "Yes")
	terms := "plain"
	switch {
	case due != "" && forensic:
		terms = "due_forensic"
	case due != "":
		terms = "due"
	case forensic:
		terms = "forensic"
	}
	ms := []Msg{msg("ev.kev.added", "terms", terms, "due", due)}
	switch strings.ToLower(str(d, "known_ransomware_campaign_use")) {
	case "known":
		ms = append(ms, msg("ev.kev.ransomware_known"))
	case "unknown":
		ms = append(ms, msg("ev.kev.ransomware_unknown"))
	}
	return ms
}

func ghsaMessages(d map[string]any) []Msg {
	var fixed [][2]string
	for _, p := range list(d, "packages") {
		pm, _ := p.(map[string]any)
		name := str(pm, "name")
		if name == "" {
			continue
		}
		if v := str(pm, "first_patched_version"); v != "" {
			fixed = append(fixed, [2]string{name, v})
		}
	}
	var ms []Msg
	switch {
	case len(fixed) > 3:
		ms = append(ms, msg("ev.ghsa.fixed_many", "shown", pkgList{i18n.ListSeq, fixed[:3]}, "total", len(fixed),
			"more", len(fixed)-3))
	case len(fixed) > 0:
		ms = append(ms, msg("ev.ghsa.fixed", "versions", pkgList{i18n.ListAnd, fixed}, "count", len(fixed)))
	default:
		ms = append(ms, msg("ev.ghsa.no_fix"))
	}
	if len(list(d, "fix_commit_urls")) > 0 {
		ms = append(ms, msg("ev.ghsa.commits"))
	}
	if pub := str(d, "advisory_published_at"); pub != "" {
		ms = append(ms, msg("ev.ghsa.published", "time", isoValue(pub)))
	} else {
		ms = append(ms, msg("ev.ghsa.no_patch_time"))
	}
	return ms
}

// isoStamp is isoMinute as a Stamp (convertible when s parses).
func isoStamp(s string) Stamp {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return Stamp{Text: s}
	}
	return instant(t, stampLong)
}

// isoMinute reformats an RFC 3339 string to "2026-11-09T22:15Z" (as is if
// it does not parse).
func isoMinute(s string) string {
	t, err := time.Parse(time.RFC3339Nano, s)
	if err != nil {
		return s
	}
	return t.UTC().Format(layoutMinute)
}
