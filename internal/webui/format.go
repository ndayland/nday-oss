package webui

import (
	"html/template"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// Time formats. Every time the server renders is UTC (stated once in the
// status bar); app.js converts the ones marked by Stamp to the visitor's
// time zone.
const (
	layoutMinute      = "2006-01-02T15:04Z"
	layoutDate        = "2006-01-02"
	layoutShortMinute = "01-02T15:04Z"
	layoutShortDate   = "01-02"
)

// Stamp is a rendered time. Text is what the page shows without JavaScript
// (UTC). At is set only when Text shows a time of day: it is the instant in
// RFC 3339 UTC and HTML wraps Text in <time datetime=… data-lt=Style>, which
// app.js rewrites to the visitor's time zone. Calendar dates (day
// precision), upper bounds and unknown times leave At empty: a date given
// by a source must never move across midnight.
type Stamp struct {
	Text  string
	At    string // RFC 3339 UTC, "" = not an instant with a time of day
	Style string // stampLong (2026-11-13T08:25Z) | stampShort (11-13T08:25Z)
}

// Stamp styles: the fields app.js keeps when it converts (nday.formatTime).
const (
	stampLong  = "long"
	stampShort = "short"
)

// HTML is Text, wrapped in a convertible <time> element when At is set.
func (s Stamp) HTML() template.HTML {
	text := template.HTMLEscapeString(s.Text)
	if s.At == "" {
		return template.HTML(text)
	}
	return template.HTML(`<time datetime="` + template.HTMLEscapeString(s.At) + `" data-lt="` +
		template.HTMLEscapeString(s.Style) + `">` + text + `</time>`)
}

// String is Text (plain-text contexts).
func (s Stamp) String() string { return s.Text }

// instant is a Stamp of t shown to the minute in UTC.
func instant(t time.Time, style string) Stamp {
	u := t.UTC()
	layout := layoutMinute
	if style == stampShort {
		layout = layoutShortMinute
	}
	return Stamp{Text: u.Format(layout), At: u.Format(time.RFC3339), Style: style}
}

// StampAt is FormatAt (long) or FormatAtShort (short) as a Stamp: only
// values that show a time of day are convertible.
func StampAt(l *i18n.Locale, t *time.Time, precision string, style string) Stamp {
	if t == nil || precision == site.PrecisionUnknown {
		return Stamp{Text: l.Text("time.unknown")}
	}
	if precision == site.PrecisionDay {
		if style == stampShort {
			return Stamp{Text: t.UTC().Format(layoutShortDate)}
		}
		return Stamp{Text: t.UTC().Format(layoutDate)}
	}
	return instant(*t, style)
}

// FormatAt renders an instant by precision: day precision shows only the UTC
// date, exact/observed show minutes, a nil time is the locale's "time
// unknown".
func FormatAt(l *i18n.Locale, t *time.Time, precision string) string {
	if t == nil || precision == site.PrecisionUnknown {
		return l.Text("time.unknown")
	}
	u := t.UTC()
	if precision == site.PrecisionDay {
		return u.Format(layoutDate)
	}
	return u.Format(layoutMinute)
}

// FormatAtShort is FormatAt without the year (list rows, where the date
// group header carries it).
func FormatAtShort(l *i18n.Locale, t *time.Time, precision string) string {
	if t == nil || precision == site.PrecisionUnknown {
		return l.Text("time.unknown")
	}
	u := t.UTC()
	if precision == site.PrecisionDay {
		return u.Format(layoutShortDate)
	}
	return u.Format(layoutShortMinute)
}

// FormatNotAfter renders an implied upper bound: "≤ 2026-11-09" (a
// language-neutral token).
func FormatNotAfter(l *i18n.Locale, t *time.Time) string {
	if t == nil {
		return l.Text("time.unknown")
	}
	return "≤ " + t.UTC().Format(layoutDate)
}

// minuteHTML renders an instant to the minute as a convertible <time>
// element ("2026-11-09T22:15Z" without JavaScript), "" for nil.
func minuteHTML(t *time.Time) template.HTML {
	if t == nil {
		return ""
	}
	return instant(*t, stampLong).HTML()
}

// PrecisionShort is the short precision label of a list row ("" when the
// time is unknown: the time column already says so).
func PrecisionShort(l *i18n.Locale, precision string) string {
	switch precision {
	case site.PrecisionDay, site.PrecisionObserved, site.PrecisionExact:
		return l.Text("precision.short", "precision", precision)
	}
	return ""
}

// PrecisionNote explains where an event time comes from (event log).
func PrecisionNote(l *i18n.Locale, precision string) string {
	switch precision {
	case site.PrecisionDay, site.PrecisionExact, site.PrecisionObserved:
	default:
		precision = site.PrecisionUnknown
	}
	return l.Text("precision.note", "precision", precision)
}

// FormatTPlus renders days since disclosure: "T+5d", "T-20d" (event before
// the CVE record was published), "T+?" when unknown. Language-neutral.
func FormatTPlus(days *int) string {
	if days == nil {
		return "T+?"
	}
	if *days < 0 {
		return "T-" + strconv.Itoa(-*days) + "d"
	}
	return "T+" + strconv.Itoa(*days) + "d"
}

// TPlusTitle is the tooltip of a T+ value.
func TPlusTitle(l *i18n.Locale, days *int) string {
	switch {
	case days == nil:
		return l.Text("tplus.title.unknown")
	case *days < 0:
		return l.Text("tplus.title.before", "days", -*days)
	}
	return l.Text("tplus.title.after", "days", *days)
}

var weekdays = [...]string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}

// DateGroupLabel is a hot-list group header: "2026-11-12 Thu" (UTC date;
// the locale owns the format and the weekday names).
func DateGroupLabel(l *i18n.Locale, t time.Time) string {
	u := t.UTC()
	return l.Text("hot.date_group", "date", u.Format(layoutDate),
		"weekday", l.Text("weekday.short", "day", weekdays[u.Weekday()]))
}

// Stage presentation: the code and its colour class are language-neutral;
// names come from the catalog ("stage.name", "stage.short").
type stageMeta struct {
	Code  string // DIS
	Class string // st-dis (colour)
}

var stages = []stageMeta{
	{"DIS", "st-dis"}, {"PAT", "st-pat"}, {"ANA", "st-ana"}, {"POC", "st-poc"}, {"ITW", "st-itw"}, {"KEV", "st-kev"},
}

// stageByCode returns the presentation of a stage code.
func stageByCode(code string) stageMeta {
	for _, s := range stages {
		if s.Code == code {
			return s
		}
	}
	return stageMeta{Code: code, Class: "st-unk"}
}

func knownStage(code string) bool { return stageByCode(code).Class != "st-unk" }

// StageName is the stage's name in the locale (the code itself for an
// unknown code).
func StageName(l *i18n.Locale, code string) string {
	if !knownStage(code) {
		return code
	}
	return l.Text("stage.name", "stage", code)
}

// StageShort is the short stage label of chart rows.
func StageShort(l *i18n.Locale, code string) string {
	if !knownStage(code) {
		return code
	}
	return l.Text("stage.short", "stage", code)
}

// StageClass maps a stage code to its colour class.
func StageClass(code string) string { return stageByCode(code).Class }

// severityValue normalises a CVSS severity for the "severity" select
// ("other" when unknown).
func severityValue(s string) string {
	switch u := strings.ToUpper(s); u {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE":
		return u
	}
	return "other"
}

// truncRunes shortens s to at most n runes, adding "…".
func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
