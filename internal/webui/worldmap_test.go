package webui

import (
	"bytes"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"nday.land/nday/internal/stats"
	"nday.land/nday/internal/webui/i18n"
)

func TestMapBounds(t *testing.T) {
	cases := []struct {
		max  int64
		want string
	}{
		{0, ""},
		{1, "1"},
		{2, "2"},
		{3, "2 3"},
		{10, "2 5 10"},
		{100, "5 10 20 50 100"},
		{12345, "10 50 500 2000 12345"},
		{100000, "10 100 1000 10000 100000"},
	}
	for _, c := range cases {
		var got []string
		for _, b := range mapBounds(c.max) {
			got = append(got, strconv.FormatInt(b, 10))
		}
		if g := strings.Join(got, " "); g != c.want {
			t.Errorf("mapBounds(%d) = %q, want %q", c.max, g, c.want)
		}
	}
}

func TestMapClass(t *testing.T) {
	five := mapBounds(12345) // 10 50 500 2000 12345
	two := mapBounds(3)      // 2 3
	cases := []struct {
		bounds []int64
		v      int64
		want   string
	}{
		{five, 0, "m0"}, {five, -4, "m0"},
		{five, 1, "m1"}, {five, 10, "m1"}, {five, 11, "m2"}, {five, 50, "m2"},
		{five, 51, "m3"}, {five, 500, "m3"}, {five, 2000, "m4"}, {five, 2001, "m5"}, {five, 12345, "m5"},
		{five, 99999, "m5"},                            // above max (not produced by BuildWorldMap) stays in the top step
		{two, 1, "m4"}, {two, 2, "m4"}, {two, 3, "m5"}, // fewer steps use the darker end
	}
	for _, c := range cases {
		if got := mapClass(c.bounds, c.v); got != c.want {
			t.Errorf("mapClass(%v, %d) = %s, want %s", c.bounds, c.v, got, c.want)
		}
	}
}

// pathOf extracts the element drawn for code (path or circle) from the SVG.
func pathOf(svg, code string) string {
	re := regexp.MustCompile(`<(path|circle) class="([^"]*)"[^>]*><title>` + regexp.QuoteMeta(code) + `: [^<]*</title>`)
	m := re.FindStringSubmatch(svg)
	if m == nil {
		return ""
	}
	return m[1] + " " + m[2]
}

func TestBuildWorldMap(t *testing.T) {
	l := loc(t, "en")
	cases := []struct {
		name     string
		in       []stats.TopEntry
		empty    bool
		drawn    map[string]string // code -> "path m3" / "circle mk m2"
		absent   []string          // marker territories without data: no circle
		legend   string
		unplaced string
	}{
		{name: "nil", in: nil, empty: true},
		{name: "only zero and negative", in: []stats.TopEntry{{Key: "US", Value: 0}, {Key: "T1", Value: -3}}, empty: true},
		{
			name: "heavy tail with markers and specials",
			in: []stats.TopEntry{{Key: "US", Value: 12345}, {Key: "CN", Value: 2001}, {Key: "FR", Value: 400}, {Key: "NO", Value: 11},
				{Key: "SG", Value: 60}, {Key: "HK", Value: 3}, {Key: "T1", Value: 12}, {Key: "XX", Value: 3}, {Key: "ZZ", Value: 12}},
			drawn: map[string]string{"US": "path m5", "CN": "path m5", "FR": "path m3", "NO": "path m2", "DE": "path m0",
				"SG": "circle mk m3", "HK": "circle mk m1"},
			absent:   []string{"MO", "MT"},
			legend:   "m1 1–10|m2 11–50|m3 51–500|m4 501–2,000|m5 2,001–12,345",
			unplaced: "T1: 12, ZZ: 12, XX: 3",
		},
		{
			name:   "duplicate keys are summed; a small maximum gets fewer steps",
			in:     []stats.TopEntry{{Key: "JP", Value: 1}, {Key: "JP", Value: 1}},
			drawn:  map[string]string{"JP": "path m5", "US": "path m0"},
			legend: "m5 1–2",
		},
		{
			name:     "only unplaced codes: the map is drawn, all neutral",
			in:       []stats.TopEntry{{Key: "T1", Value: 5}},
			drawn:    map[string]string{"US": "path m0"},
			legend:   "m4 1–2|m5 3–5",
			unplaced: "T1: 5",
		},
	}
	for _, c := range cases {
		m := BuildWorldMap(l, c.in)
		if m.Empty != c.empty {
			t.Errorf("%s: Empty = %v", c.name, m.Empty)
		}
		if c.empty {
			if m.SVG != "" || m.Legend != nil || m.Unplaced != "" {
				t.Errorf("%s: empty map has content %+v", c.name, m)
			}
			continue
		}
		svg := string(m.SVG)
		if !strings.HasPrefix(svg, `<svg class="adm-map-svg" viewBox="0 0 2000 `) || !strings.HasSuffix(svg, "</svg>") {
			t.Errorf("%s: svg frame %.80q", c.name, svg)
		}
		for code, want := range c.drawn {
			if got := pathOf(svg, code); got != want {
				t.Errorf("%s: %s drawn as %q, want %q", c.name, code, got, want)
			}
		}
		for _, code := range c.absent {
			if strings.Contains(svg, "<title>"+code+":") {
				t.Errorf("%s: marker %s without data is drawn", c.name, code)
			}
		}
		var lg []string
		for _, s := range m.Legend {
			lg = append(lg, s.Class+" "+s.Label)
		}
		if g := strings.Join(lg, "|"); g != c.legend {
			t.Errorf("%s: legend %q, want %q", c.name, g, c.legend)
		}
		if g := textOf(string(m.Unplaced)); g != c.unplaced {
			t.Errorf("%s: unplaced %q, want %q", c.name, g, c.unplaced)
		}
		for _, code := range []string{"T1", "XX", "ZZ"} {
			if strings.Contains(svg, ">"+code+":") {
				t.Errorf("%s: %s is in the SVG", c.name, code)
			}
		}
	}
	// the title carries code and count in the locale's number format
	m := BuildWorldMap(l, []stats.TopEntry{{Key: "US", Value: 12345}})
	if !strings.Contains(string(m.SVG), "<title>US: 12,345</title>") {
		t.Error("titles")
	}
	// data attributes for the script's tooltip: code, formatted count, text (no data: its own label)
	for _, want := range []string{`<path class="m5" data-cc="US" data-n="12,345" data-tip="US: 12,345" d="m`,
		`<path class="m0" data-cc="BR" data-n="0" data-tip="BR: no page views by people" d="m`,
		"<title>BR: no page views by people</title>"} {
		if !strings.Contains(string(m.SVG), want) {
			t.Errorf("SVG lacks %q", want)
		}
	}
	mk := BuildWorldMap(l, []stats.TopEntry{{Key: "SG", Value: 1500}, {Key: "US", Value: 2}})
	if !strings.Contains(string(mk.SVG), `<circle class="mk m5" data-cc="SG" data-n="1,500" data-tip="SG: 1,500" cx=`) {
		t.Errorf("marker attributes: %.200s", mk.SVG[strings.Index(string(mk.SVG), "<circle"):])
	}
	// every element with a tooltip has all three attributes, with escaped values
	attrs := regexp.MustCompile(`<(path|circle) class="[a-z0-9 ]+" data-cc="[A-Z]{2}" data-n="[0-9,]+" data-tip="[^"<>]+" (d|cx)=`)
	if n := len(attrs.FindAllString(string(m.SVG), -1)); n != len(mapShapes) || strings.Count(string(m.SVG), "data-tip=") != n {
		t.Errorf("%d elements with tooltip attributes, want %d (one per outline; no marker has data)", n, len(mapShapes))
	}
	zh := BuildWorldMap(loc(t, "zh-Hans"), []stats.TopEntry{{Key: "US", Value: 12345}})
	if !strings.Contains(string(zh.SVG), `data-tip="BR：没有人的页面浏览"`) || !strings.Contains(string(zh.SVG), `data-tip="US：12,345"`) {
		t.Error("zh-Hans tooltip text")
	}
	if !strings.Contains(string(m.SVG), `aria-label="world map: 1 country or territory with page views by people, highest 12,345"`) {
		t.Errorf("aria: %.300s", m.SVG)
	}
}

var tagStrip = regexp.MustCompile(`<[^>]*>`)

func textOf(h string) string { return tagStrip.ReplaceAllString(h, "") }

func TestBuildWorldMapDeterministic(t *testing.T) {
	l := loc(t, "zh-Hans")
	in := []stats.TopEntry{{Key: "US", Value: 9}, {Key: "SG", Value: 7}, {Key: "T1", Value: 2}, {Key: "XX", Value: 2},
		{Key: "CN", Value: 120}, {Key: "Q9", Value: 2}, {Key: "MO", Value: 1}}
	first := BuildWorldMap(l, in)
	for i := 0; i < 20; i++ {
		rev := make([]stats.TopEntry, len(in))
		for j := range in {
			rev[j] = in[(j+i)%len(in)]
		}
		m := BuildWorldMap(l, rev)
		if m.SVG != first.SVG || m.Unplaced != first.Unplaced || len(m.Legend) != len(first.Legend) {
			t.Fatalf("output depends on input order (rotation %d)", i)
		}
	}
	// equal counts in code order, joined with the locale's "seq" list pattern
	if got, want := textOf(string(first.Unplaced)), l.List(i18n.ListSeq, []string{"Q9：2", "T1：2", "XX：2"}); got != want {
		t.Errorf("unplaced %q, want %q", got, want)
	}
}

// A hostile key (it comes from a request header through the logs) never
// reaches the page unescaped: not in the SVG, not in the list under it, and
// not through the real template.
func TestBuildWorldMapEscapes(t *testing.T) {
	l := loc(t, "en")
	evil := `"><script>alert(1)</script><svg onload=x>` + "‮\x01"
	in := []stats.TopEntry{{Key: evil, Value: 5}, {Key: "US", Value: 3}, {Key: "<title>", Value: 1}}
	m := BuildWorldMap(l, in)
	for _, s := range []string{string(m.SVG), string(m.Unplaced)} {
		if strings.Contains(s, "<script") || strings.Contains(s, "onload") && !strings.Contains(s, "&lt;svg onload") || strings.Contains(s, "\x01") {
			t.Errorf("unescaped key: %q", s)
		}
	}
	if strings.Contains(string(m.SVG), "script") {
		t.Errorf("unplaced key in the SVG: %q", m.SVG)
	}
	if !strings.Contains(string(m.Unplaced), "<bdi>&#34;&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;svg onload=x&gt;‮�</bdi>: 5") {
		t.Errorf("unplaced: %q", m.Unplaced)
	}
	if strings.Count(string(m.Unplaced), "<bdi>") != 2 || !strings.Contains(string(m.Unplaced), "&lt;title&gt;") {
		t.Errorf("unplaced: %q", m.Unplaced)
	}

	// through the page template
	set, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	assets, err := loadAssets("")
	if err != nil {
		t.Fatal(err)
	}
	r, err := newRenderer(assets, set)
	if err != nil {
		t.Fatal(err)
	}
	v := AdminView{Title: "x", Tab: "stats", Role: "admin", IsAdmin: true,
		Body: AdminStatsView{Days: 7, Map: m, Tables: []TopTable{{ID: "t-cc", Key: "countries", Col: "country",
			Rows: []TopRow{{Key: plain(evil), Value: "5"}}}}}}
	out, err := r.render(l, "admin_stats", &Page{Title: "t", Data: v, L: l, Lang: "en", Personal: true, NoIndex: true})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("<script>alert")) || bytes.Contains(out, []byte("<svg onload")) {
		t.Errorf("hostile key unescaped in the page")
	}
	for _, want := range []string{`id="h-map"`, "page views by people, by country, last 7 days", `<svg class="adm-map-svg"`,
		"Not on the map (Tor, unknown or unrecognised codes): <bdi>", `<span class="sw m0" aria-hidden="true"></span>none`} {
		if !bytes.Contains(out, []byte(want)) {
			t.Errorf("page lacks %q", want)
		}
	}
	// empty state
	v.Body = AdminStatsView{Days: 30, Map: BuildWorldMap(l, nil)}
	out, err = r.render(l, "admin_stats", &Page{Title: "t", Data: v, L: l, Lang: "en", Personal: true, NoIndex: true})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("adm-map-svg")) || !bytes.Contains(out, []byte("Nothing in this period.")) {
		t.Error("empty map state")
	}
}

// The generated data parses as SVG path data, sits inside the viewBox and
// has the expected codes.
func TestWorldMapData(t *testing.T) {
	if mapW != 2000 || mapH < 900 || mapH > 1100 {
		t.Fatalf("viewBox %d x %d", mapW, mapH)
	}
	for _, c := range []string{"US", "CN", "FR", "NO", "RU", "BR", "AU", "IN", "JP", "DE", "GB", "TW", "XK"} {
		if mapShapes[c] == "" {
			t.Errorf("no outline for %s", c)
		}
	}
	for _, c := range []string{"SG", "HK", "MO", "MT", "BH"} {
		if _, ok := mapPoints[c]; !ok {
			t.Errorf("no marker for %s", c)
		}
	}
	if _, ok := mapShapes["AQ"]; ok {
		t.Error("Antarctica is drawn")
	}
	if len(mapShapes) < 170 || len(mapPoints) < 40 {
		t.Errorf("%d outlines, %d markers", len(mapShapes), len(mapPoints))
	}
	code := regexp.MustCompile(`^[A-Z]{2}$`)
	sub := regexp.MustCompile(`m(-?\d+ -?\d+(?: -?\d+ -?\d+){2,})z`)
	check := func(name, d string) {
		if rest := sub.ReplaceAllString(d, ""); rest != "" || d == "" {
			t.Errorf("%s: path data does not parse: %.60q", name, rest)
			return
		}
		// absolute positions of every point stay in the viewBox
		var cx, cy int
		for _, m := range sub.FindAllStringSubmatch(d, -1) {
			nums := strings.Fields(m[1])
			x, y := cx, cy
			for i := 0; i < len(nums); i += 2 {
				x += atoi(t, nums[i])
				y += atoi(t, nums[i+1])
				if i == 0 {
					cx, cy = x, y
				}
				if x < -1 || x > mapW+1 || y < -1 || y > mapH+1 {
					t.Errorf("%s: point %d,%d outside the viewBox", name, x, y)
					return
				}
			}
		}
	}
	for c, d := range mapShapes {
		if !code.MatchString(c) {
			t.Errorf("bad code %q", c)
		}
		check(c, d)
	}
	for i, d := range mapUncoded {
		check("uncoded "+strconv.Itoa(i), d)
	}
	for c, p := range mapPoints {
		if !code.MatchString(c) || mapShapes[c] != "" {
			t.Errorf("marker %q: bad code or also an outline", c)
		}
		if p[0] < 0 || p[0] > mapW || p[1] < 0 || p[1] > mapH {
			t.Errorf("marker %s at %v outside the viewBox", c, p)
		}
	}
}

func atoi(t *testing.T, s string) int {
	n, err := strconv.Atoi(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}
