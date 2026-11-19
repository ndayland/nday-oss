package webui

import (
	"strconv"
	"time"
	"unicode/utf8"

	"nday.land/nday/internal/webui/i18n"
)

// Chart geometry assumptions, in CSS pixels. The chart box has min-width
// 924px (it scrolls horizontally below that) minus the 136px label and 168px
// "time unknown" columns: the plot is at least PlotMinPx wide. Collision and
// minimum-size decisions are made for that narrowest case, so they hold at
// every wider size too.
const (
	PlotMinPx   = 620.0
	MaxTicks    = 12
	charPx      = 6.7 // advance of an 11px JetBrains Mono glyph
	tickLabelDX = 4.0 // tick labels start this far right of their grid line
	nowLabelPx  = 3*charPx + 6
	minBarPx    = 8.0 // a day bar narrower than this is drawn at this width
	minSpan     = 7 * 24 * time.Hour
)

// Tick is one vertical grid line with its label (Label "" = line only).
type Tick struct {
	At    time.Time
	Pct   float64
	X     string // Pct as an SVG attribute
	Label string
}

// Scale maps instants to horizontal percentages of the plot.
type Scale struct {
	Start, End time.Time
	Unit       string // day | week | month | quarter | year | 2year | 5year | 10year
	Ticks      []Tick
	NowPct     float64
}

// Pct is the position of t in [0, 100], clamped.
func (s Scale) Pct(t time.Time) float64 {
	span := s.End.Sub(s.Start)
	if span <= 0 {
		return 0
	}
	p := float64(t.Sub(s.Start)) / float64(span) * 100
	switch {
	case p < 0:
		return 0
	case p > 100:
		return 100
	}
	return p
}

// Px converts a percentage to pixels at the narrowest plot width.
func Px(pct float64) float64 { return pct / 100 * PlotMinPx }

type unit struct {
	name  string
	floor func(time.Time) time.Time
	next  func(time.Time) time.Time
	label func(time.Time) string
}

func dayFloor(t time.Time) time.Time {
	y, m, d := t.Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func monthsFloor(n int) func(time.Time) time.Time {
	return func(t time.Time) time.Time {
		m := (int(t.Month())-1)/n*n + 1
		return time.Date(t.Year(), time.Month(m), 1, 0, 0, 0, 0, time.UTC)
	}
}

func yearsFloor(n int) func(time.Time) time.Time {
	return func(t time.Time) time.Time {
		y := t.Year() / n * n
		return time.Date(y, 1, 1, 0, 0, 0, 0, time.UTC)
	}
}

var units = []unit{
	{"day", dayFloor, func(t time.Time) time.Time { return t.AddDate(0, 0, 1) },
		func(t time.Time) string { return t.Format("01-02") }},
	{"week", func(t time.Time) time.Time { // weeks start on Monday
		d := dayFloor(t)
		return d.AddDate(0, 0, -((int(d.Weekday()) + 6) % 7))
	}, func(t time.Time) time.Time { return t.AddDate(0, 0, 7) },
		func(t time.Time) string { return t.Format("01-02") }},
	{"month", monthsFloor(1), func(t time.Time) time.Time { return t.AddDate(0, 1, 0) },
		func(t time.Time) string { return t.Format("2006-01") }},
	{"quarter", monthsFloor(3), func(t time.Time) time.Time { return t.AddDate(0, 3, 0) },
		func(t time.Time) string { return t.Format("2006-01") }},
	{"year", yearsFloor(1), func(t time.Time) time.Time { return t.AddDate(1, 0, 0) },
		func(t time.Time) string { return t.Format("2006") }},
	{"2year", yearsFloor(2), func(t time.Time) time.Time { return t.AddDate(2, 0, 0) },
		func(t time.Time) string { return t.Format("2006") }},
	{"5year", yearsFloor(5), func(t time.Time) time.Time { return t.AddDate(5, 0, 0) },
		func(t time.Time) string { return t.Format("2006") }},
	{"10year", yearsFloor(10), func(t time.Time) time.Time { return t.AddDate(10, 0, 0) },
		func(t time.Time) string { return t.Format("2006") }},
}

// ComputeScale picks the time axis for a lifecycle chart: from the start of
// the tick unit containing the earliest known event to "now" plus a small
// margin (so "now" sits near the right edge), with the smallest tick unit
// (day, week, month, quarter, 1/2/5/10 years) that keeps at most MaxTicks
// grid lines. Spans shorter than a week are widened to a week. Tick labels
// that would overlap the "now" label are dropped (the grid line stays).
func ComputeScale(earliest, now time.Time) Scale {
	now = now.UTC()
	earliest = earliest.UTC()
	if earliest.After(now) {
		earliest = now
	}
	if now.Sub(earliest) < minSpan {
		earliest = now.Add(-minSpan)
	}
	var s Scale
	for i, u := range units {
		start := u.floor(earliest)
		span := now.Sub(start)
		pad := span / 30
		if pad < 2*time.Hour {
			pad = 2 * time.Hour
		}
		end := now.Add(pad)
		var ticks []Tick
		for t := start; t.Before(end); t = u.next(t) {
			ticks = append(ticks, Tick{At: t})
		}
		if len(ticks) > MaxTicks && i < len(units)-1 {
			continue
		}
		s = Scale{Start: start, End: end, Unit: u.name, Ticks: ticks}
		for j := range s.Ticks {
			s.Ticks[j].Pct = s.Pct(s.Ticks[j].At)
			s.Ticks[j].X = pctAttr(s.Ticks[j].Pct)
			s.Ticks[j].Label = u.label(s.Ticks[j].At)
		}
		break
	}
	s.NowPct = s.Pct(now)
	nowLeft := Px(s.NowPct) - nowLabelPx
	for j := range s.Ticks {
		t := &s.Ticks[j]
		left := Px(t.Pct) + tickLabelDX
		right := left + float64(utf8.RuneCountInString(t.Label))*charPx
		if right+4 > nowLeft || right > PlotMinPx {
			t.Label = ""
		}
	}
	return s
}

// pctAttr renders a percentage for an SVG attribute ("55.556%").
func pctAttr(p float64) string { return strconv.FormatFloat(p, 'f', 3, 64) + "%" }

// ChartMark is one drawn event. Kinds: "point" (exact/observed time, a 12px
// square centred on X), "bar" (a UTC day, from X with width W), "pin" (a day
// too narrow to see at this scale, drawn as a minBarPx-wide bar centred on X).
type ChartMark struct {
	Kind   string
	X, W   string // SVG attribute values (percentages)
	Hollow bool   // implied / upper bound
	Latest bool   // the vulnerability's last transition (halo)
}

// ChartLabel is the text next to a row's first mark.
type ChartLabel struct {
	X      string // anchor position (percentage)
	DX     string // pixel offset from X
	Anchor string // start | end
	Text   string
}

// ChartRow is one stage of the lifecycle chart.
type ChartRow struct {
	Code, Short, Class string
	Marks              []ChartMark
	Label              *ChartLabel
	Empty              bool       // no event of this stage at all: "no record yet"
	Unknown            []string   // events without a time (right-hand column)
	UnknownHollow      bool       // draw the hollow marker in the unknown column
	UnknownText        string     // Unknown as a list in the locale
	Aria               string     // accessible label of the row
	Dots               []ChartDot // external items on this row (chartdots.go)
	// Lane: the row has dots, drawn in a lane of their own under the stage
	// marks; the row is taller (app.css "lane"), its label, marks and
	// "time unknown" cell stay in the upper part.
	Lane bool
}

// Chart is the lifecycle chart view model.
type Chart struct {
	Scale Scale
	Ticks []Tick
	NowX  string
	Grid  []string // x of grid lines
	Rows  []ChartRow
	// PostDots: researcher posts on the header's lower edge; Dots: every
	// dot (header and rows), for the popovers (chartdots.go).
	PostDots []ChartDot
	Dots     []ChartDot
}

// markSpec is an input mark for buildRow.
type markSpec struct {
	at        time.Time
	precision string // exact | observed | day
	hollow    bool
	latest    bool
	text      string // label text
}

// edge is a mark side: a percentage plus a pixel offset.
type edge struct {
	pct float64
	px  float64
}

// at is the edge position in pixels at the narrowest plot width.
func (e edge) at() float64 { return Px(e.pct) + e.px }

// placeMark positions one mark on the scale and returns its left and right
// edges.
func placeMark(s Scale, m markSpec) (ChartMark, edge, edge) {
	if m.precision == "day" {
		d := dayFloor(m.at.UTC())
		x0, x1 := s.Pct(d), s.Pct(d.Add(24*time.Hour))
		if Px(x1-x0) < minBarPx {
			c := (x0 + x1) / 2
			return ChartMark{Kind: "pin", X: pctAttr(c), Hollow: m.hollow, Latest: m.latest},
				edge{c, -minBarPx / 2}, edge{c, minBarPx / 2}
		}
		return ChartMark{Kind: "bar", X: pctAttr(x0), W: pctAttr(x1 - x0), Hollow: m.hollow, Latest: m.latest},
			edge{x0, 0}, edge{x1, 0}
	}
	x := s.Pct(m.at)
	return ChartMark{Kind: "point", X: pctAttr(x), Hollow: m.hollow, Latest: m.latest}, edge{x, -6}, edge{x, 6}
}

// buildRow lays out a row's marks; the first mark gets the label, placed to
// its right, or to its left when it would cross the "now" line (judged at the
// narrowest plot width, so it holds when the plot is wider).
func buildRow(l *i18n.Locale, s Scale, row ChartRow, marks []markSpec) ChartRow {
	for i, m := range marks {
		cm, left, right := placeMark(s, m)
		row.Marks = append(row.Marks, cm)
		if i != 0 || m.text == "" {
			continue
		}
		text := m.text
		if len(marks) > 1 {
			text = l.Text("chart.mark.more", "label", i18n.Raw(m.text), "n", len(marks), "more", len(marks)-1)
		}
		w := float64(i18n.Cols(text))*charPx + 8 // wide (CJK) characters count two columns
		if right.at()+8+w < Px(s.NowPct)-4 {
			row.Label = &ChartLabel{X: pctAttr(right.pct), DX: fmtPx(right.px + 8), Anchor: "start", Text: text}
		} else {
			row.Label = &ChartLabel{X: pctAttr(left.pct), DX: fmtPx(left.px - 8), Anchor: "end", Text: text}
		}
	}
	return row
}

func fmtPx(v float64) string { return strconv.FormatFloat(v, 'f', -1, 64) }
