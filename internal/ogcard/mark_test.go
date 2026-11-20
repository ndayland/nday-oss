package ogcard

import (
	"bytes"
	"image"
	"image/color"
	"math"
	"testing"
)

// circle is a disc of radius 10 around (12,12), drawn with two arcs.
const circle = "M12 2a10 10 0 1 0 0 20a10 10 0 1 0 0-20z"

func coverage(m *image.Alpha) float64 {
	sum := 0.0
	for _, a := range m.Pix {
		sum += float64(a) / 255
	}
	return sum
}

func TestParsePath(t *testing.T) {
	for _, tc := range []struct {
		d    string
		ops  string
		last pt // where the pen ends (the last segment's end point)
	}{
		{"M1 2L3 4", "ML", pt{3, 4}},
		{"M1,2 3,4 5,6", "MLL", pt{5, 6}},                      // pairs after a moveto are linetos
		{"m1 1 2 2", "ML", pt{3, 3}},                           // ... relative ones for m
		{"M.5.5l.186.186", "ML", pt{.686, .686}},               // compact numbers
		{"M1-2l1-2", "ML", pt{2, -4}},                          // a sign starts a number
		{"M1e1 2E-1h1e+1", "ML", pt{20, .2}},                   // exponents
		{"M0 0H5V6h1v1", "MLLLL", pt{6, 7}},                    // H V h v
		{"M0 0C1 1 2 2 3 3S5 5 6 6", "MCC", pt{6, 6}},          // C S
		{"M0 0c1 1 2 2 3 3s2 2 3 3", "MCC", pt{6, 6}},          // c s
		{"M0 0Q1 1 2 0T4 0", "MCC", pt{4, 0}},                  // Q T as cubics
		{"M0 0q1 1 2 0t2 0", "MCC", pt{4, 0}},                  // q t
		{"M0 0a.186.186 0 00.186-.185", "MC", pt{.186, -.185}}, // glued arc flags
		{"M0 0A1 1 0 1 1 2 0", "MCC", pt{2, 0}},                // a half circle: two quarters
		{"M0 0a5 5 0 0 1 0 0", "M", pt{0, 0}},                  // zero-length arc: nothing
		{"M0 0a0 5 0 0 1 3 4", "ML", pt{3, 4}},                 // zero radius: a line
		{"M0 0h2v2zm1 1h1z", "MLLZMLZ", pt{}},                  // z, then m relative to the start
	} {
		segs, err := parsePath(tc.d)
		if err != nil {
			t.Errorf("%q: %v", tc.d, err)
			continue
		}
		var ops []byte
		for _, s := range segs {
			ops = append(ops, s.op)
		}
		if string(ops) != tc.ops {
			t.Errorf("%q: ops %s, want %s", tc.d, ops, tc.ops)
			continue
		}
		var end pt
		switch s := segs[len(segs)-1]; s.op {
		case 'C':
			end = s.p[2]
		case 'Z':
		default:
			end = s.p[0]
		}
		if math.Abs(end.x-tc.last.x) > 1e-9 || math.Abs(end.y-tc.last.y) > 1e-9 {
			t.Errorf("%q: ends at %v, want %v", tc.d, end, tc.last)
		}
	}
	// the m after z above starts at (0,0)+(1,1)
	if segs, _ := parsePath("M0 0h2v2zm1 1h1z"); segs[4].p[0] != (pt{1, 1}) {
		t.Errorf("m after z: %v", segs[4].p[0])
	}
	for _, d := range []string{"", "   ", "L1 1", "M1", "M1 2 3", "M1 2X3 4", "M1 2a1 1 0 2 0 3 3",
		"M1 2a1 1 0 0", "M1e 2", "M. 1", "M1 2z3 4", "M--1 2", "M1 2C1 2 3", "M1e999 2"} {
		if _, err := parsePath(d); err == nil {
			t.Errorf("%q parsed", d)
		}
		if _, err := MarkMask(d); err == nil {
			t.Errorf("%q: MarkMask without an error", d)
		}
	}
}

// The arcs come out round and in the right place: the disc's coverage is
// about pi r^2 and its centre pixel is solid, a corner empty.
func TestMarkMaskDisc(t *testing.T) {
	m, err := MarkMask(circle)
	if err != nil {
		t.Fatal(err)
	}
	r := 10.0 * markScale
	if got, want := coverage(m), math.Pi*r*r; math.Abs(got-want)/want > 0.005 {
		t.Errorf("coverage %.0f, want about %.0f", got, want)
	}
	if m.AlphaAt(markSide/2, markSide/2).A != 0xFF || m.AlphaAt(5, 5).A != 0 {
		t.Error("disc is not where it should be")
	}
	// non-zero fill: a second disc wound the same way doesn't punch a hole
	// (only the anti-aliased rim gets denser), one wound the other way does
	same, _ := MarkMask(circle + circle)
	if d := coverage(same) - coverage(m); same.AlphaAt(markSide/2, markSide/2).A != 0xFF || d < 0 || d > 2*math.Pi*r {
		t.Errorf("same-direction overlap: centre %d, coverage +%.0f", same.AlphaAt(markSide/2, markSide/2).A, d)
	}
	hole, _ := MarkMask(circle + "M12 7a5 5 0 1 1 0 10a5 5 0 1 1 0-10z")
	if hole.AlphaAt(markSide/2, markSide/2).A != 0 {
		t.Error("counter-wound inner disc left no hole")
	}
}

// The watermark only touches its box, under the text; the header's brand
// stays as it was. A mark that doesn't parse, or a slug without a path, is
// no watermark at all.
func TestWatermark(t *testing.T) {
	plain := sample()
	marked := sample()
	marked.Mark, marked.MarkPath = "disc", circle
	p, m := decode(t, render(t, plain)), decode(t, render(t, marked))
	box := image.Rect(markX, markY, markX+markSide, markY+markSide)
	inside, outside := 0, 0
	for y := 0; y < Height; y++ {
		for x := 0; x < Width; x++ {
			if p.At(x, y) != m.At(x, y) {
				if image.Pt(x, y).In(box) {
					inside++
				} else {
					outside++
				}
			}
		}
	}
	if inside < 10000 || outside != 0 {
		t.Errorf("differing pixels: %d in the mark's box, %d outside", inside, outside)
	}
	// the brand ("nday" in green at the top left) is untouched, and the
	// middle of the disc is the faint mark colour, not the background
	if p.At(marginX+4, headBase-10) != m.At(marginX+4, headBase-10) {
		t.Error("brand area changed")
	}
	cx, cy := markX+markSide/2, markY+markSide/2
	if r, _, _, _ := m.At(cx, cy).RGBA(); r>>8 <= uint32(cBg.R) || r>>8 > uint32(cBg.R)+20 {
		t.Errorf("mark colour %v at the disc's centre", m.At(cx, cy))
	}
	for _, c := range []Card{
		func() Card { c := sample(); c.Mark, c.MarkPath = "broken", "M1 2X"; return c }(),
		func() Card { c := sample(); c.Mark = "nopath"; return c }(),
		func() Card { c := sample(); c.MarkPath = circle; return c }(),
	} {
		if !bytes.Equal(render(t, c), render(t, plain)) {
			t.Errorf("mark %q %q: picture differs from the plain card", c.Mark, c.MarkPath)
		}
	}
}

// The slug is in the key, the path data is not.
func TestMarkKey(t *testing.T) {
	a, b, c := sample(), sample(), sample()
	b.Mark, b.MarkPath = "docker", circle
	c.Mark, c.MarkPath = "linux", circle
	if a.Key() == b.Key() || b.Key() == c.Key() {
		t.Error("the mark slug didn't change the key")
	}
	d := b
	d.MarkPath = "M0 0h1v1z"
	if d.Key() != b.Key() {
		t.Error("the path data changed the key")
	}
}

// The CVSS score: drawn only on the id row, in the key, and the id shrinks
// to keep clear of it.
func TestScore(t *testing.T) {
	plain, scored, other := sample(), sample(), sample()
	scored.Score, other.Score = "9.1", "7.5"
	if plain.Key() == scored.Key() || scored.Key() == other.Key() {
		t.Error("the score didn't change the key")
	}
	p, s := decode(t, render(t, plain)), decode(t, render(t, scored))
	diff := 0
	for y := 0; y < Height; y++ {
		for x := 0; x < Width; x++ {
			if p.At(x, y) != s.At(x, y) {
				diff++
			}
		}
	}
	if diff == 0 {
		t.Error("the score drew nothing")
	}
	// junk is no score: the plain picture
	junk := sample()
	junk.Score = " · "
	if !bytes.Equal(render(t, junk), render(t, plain)) {
		t.Error("a score without digits drew something")
	}
	f, _ := loadFonts()
	cv := &canvas{f: f}
	for _, id := range []string{"CVE-2026-102895", "CVE-2026-1234567", "GHSA-xxxx-xxxx-xxxx", "CVE-2026-123456789012"} {
		for _, score := range []string{"9.1", "10.0", ""} {
			sw := cv.scoreWidth(score)
			idW := width(cv.face(true, idSizeFor(id, idRoom(sw))), id)
			if sw > 0 && idW+idGap+sw > contentW || idW > contentW {
				t.Errorf("%s with %q: id %dpx + gap + score %dpx > %d", id, score, idW, sw, contentW)
			}
		}
	}
}

func TestScoreColor(t *testing.T) {
	for score, want := range map[string]color.RGBA{
		"9.0": cCritical, "9.8": cCritical, "10.0": cCritical,
		"8.9": cFg, "0.0": cFg, "": cFg, "n/a": cFg, "11.0": cFg,
	} {
		if got := scoreColor(score); got != want {
			t.Errorf("scoreColor(%q) = %v, want %v", score, got, want)
		}
	}
}
