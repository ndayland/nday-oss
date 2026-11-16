package webui

import (
	"html/template"
	"math"
	"sort"
	"strconv"
	"strings"

	"nday.land/nday/internal/stats"
	"nday.land/nday/internal/webui/i18n"
)

// The visitor map of the back office statistics page (docs/admin.md): page
// views per country (stats_top kind country_human) on a world map built from
// the generated outlines of worldmap_data.go (tools/worldmap). Countries are
// coloured by a stepped logarithmic scale (classes m1..m5, m0 = none; the
// colours are CSS, .adm-map in app.css); territories without an outline at
// this scale (Singapore, Hong Kong, island states) are circle markers in the
// same scale, drawn only when they have data; codes that cannot be placed at
// all (T1 = Tor, XX = unknown, anything else) are listed under the map.
//
// Every country path and marker carries data-cc, data-n (the count in the
// locale's format) and data-tip (the tooltip text); static/admin.js shows
// data-tip as an instant tooltip on hover and tap (and removes the
// <title>s, the fallback without script, so there is no second tooltip).
//
// Keys come from request headers (via the access logs). The SVG is built
// here as text, so every value written into it is escaped here; only map
// codes from worldmap_data.go and numbers reach attributes.

// MapSteps is the largest number of colour steps.
const MapSteps = 5

// mapMarkerR is the marker radius in viewBox units.
const mapMarkerR = 8

// MapStep is one legend entry.
type MapStep struct {
	Class string // m1..m5
	Label string // the step's counts ("1–10"), plain text
}

// WorldMap is the visitor map view model.
type WorldMap struct {
	SVG      template.HTML // the map (empty when Empty)
	Legend   []MapStep
	Unplaced template.HTML // "T1: 12, XX: 3" (codes escaped, in <bdi>); "" when every code was placed
	Empty    bool          // no positive count at all
}

// mapBounds returns the inclusive upper bound of every step for counts up to
// max: max^(i/MapSteps) rounded up to 1, 2 or 5 times a power of ten, the
// last one max itself, strictly increasing (small maxima get fewer steps).
func mapBounds(max int64) []int64 {
	if max <= 0 {
		return nil
	}
	var out []int64
	for i := 1; i < MapSteps; i++ {
		b := niceUp(math.Pow(float64(max), float64(i)/MapSteps))
		if b >= max || len(out) > 0 && b <= out[len(out)-1] {
			continue
		}
		out = append(out, b)
	}
	return append(out, max)
}

// niceUp is the smallest of 1, 2, 5 times a power of ten that is >= x.
func niceUp(x float64) int64 {
	n := int64(math.Ceil(x - 1e-9))
	if n < 1 {
		return 1
	}
	for p := int64(1); ; p *= 10 {
		for _, m := range []int64{1, 2, 5} {
			if m*p >= n {
				return m * p
			}
		}
	}
}

// mapClass is the class of count v: "m0" for none, else the step's class;
// the top step is always m5, so fewer steps use the darker end.
func mapClass(bounds []int64, v int64) string {
	if v <= 0 {
		return "m0"
	}
	off := MapSteps - len(bounds) + 1
	for i, b := range bounds {
		if v <= b {
			return "m" + strconv.Itoa(off+i)
		}
	}
	return "m" + strconv.Itoa(MapSteps)
}

// BuildWorldMap lays out the map of es (summed per key; counts <= 0 are
// ignored).
func BuildWorldMap(l *i18n.Locale, es []stats.TopEntry) WorldMap {
	counts := map[string]int64{}
	for _, e := range es {
		if e.Value > 0 {
			counts[e.Key] += e.Value
		}
	}
	var max int64
	for _, v := range counts {
		if v > max {
			max = v
		}
	}
	if max == 0 {
		return WorldMap{Empty: true}
	}
	bounds := mapBounds(max)
	m := WorldMap{}
	lo := int64(1)
	for _, b := range bounds {
		label := l.Int(b)
		if lo != b {
			label = l.Text("admin.stats.map_range", "lo", lo, "hi", b)
		}
		m.Legend = append(m.Legend, MapStep{Class: mapClass(bounds, b), Label: label})
		lo = b + 1
	}

	type un struct {
		key string
		v   int64
	}
	var unplaced []un
	placed := 0
	for k, v := range counts {
		_, shape := mapShapes[k]
		_, point := mapPoints[k]
		if shape || point {
			placed++
		} else {
			unplaced = append(unplaced, un{k, v})
		}
	}

	// tip: the data attributes static/admin.js reads for its tooltip (code,
	// formatted count, full text) and the <title> fallback without script
	tip := func(code string, v int64) (attrs, title string) {
		text := l.Text("admin.stats.map_item", "code", code, "n", v)
		if v <= 0 {
			text = l.Text("admin.stats.map_nodata", "code", code)
		}
		e := template.HTMLEscapeString
		return ` data-cc="` + e(code) + `" data-n="` + e(l.Int(v)) + `" data-tip="` + e(text) + `"`, "<title>" + e(text) + "</title>"
	}
	var b strings.Builder
	b.WriteString(`<svg class="adm-map-svg" viewBox="0 0 ` + strconv.Itoa(mapW) + " " + strconv.Itoa(mapH) +
		`" role="img" aria-label="` + template.HTMLEscapeString(l.Text("admin.stats.map_aria", "n", placed, "max", max)) + `">`)
	for _, d := range mapUncoded {
		b.WriteString(`<path class="m0" d="` + d + `"/>`)
	}
	for _, code := range mapShapeCodes {
		v := counts[code]
		attrs, title := tip(code, v)
		b.WriteString(`<path class="` + mapClass(bounds, v) + `"` + attrs + ` d="` + mapShapes[code] + `">` + title + `</path>`)
	}
	for _, code := range mapPointCodes {
		v := counts[code]
		if v <= 0 {
			continue
		}
		p := mapPoints[code]
		attrs, title := tip(code, v)
		b.WriteString(`<circle class="mk ` + mapClass(bounds, v) + `"` + attrs + ` cx="` + strconv.Itoa(p[0]) + `" cy="` + strconv.Itoa(p[1]) +
			`" r="` + strconv.Itoa(mapMarkerR) + `">` + title + `</circle>`)
	}
	b.WriteString(`</svg>`)
	m.SVG = template.HTML(b.String())

	if len(unplaced) > 0 {
		sort.Slice(unplaced, func(i, j int) bool {
			if unplaced[i].v != unplaced[j].v {
				return unplaced[i].v > unplaced[j].v
			}
			return unplaced[i].key < unplaced[j].key
		})
		items := make([]template.HTML, len(unplaced))
		for i, u := range unplaced {
			items[i] = l.HTML("admin.stats.map_item", "code", isolate(u.key), "n", u.v)
		}
		m.Unplaced = l.ListHTML(i18n.ListSeq, items)
	}
	return m
}

// mapShapeCodes and mapPointCodes are the codes of the map in drawing order.
var mapShapeCodes, mapPointCodes = sortedKeys(mapShapes), sortedKeys(mapPoints)

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
