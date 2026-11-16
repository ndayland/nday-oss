// Package ogcard draws the share card (Open Graph / X summary_large_image)
// of one vulnerability: a 1200x630 PNG with the CVE id, the affected
// products, the English title, the six-slot lifecycle strip and the brand.
//
// It is a pure function of Card: no database, no HTTP, no i18n. The text is
// drawn with the embedded JetBrains Mono TrueType faces (fonts/NOTICE),
// which cover Latin only; Clean drops every rune the card cannot draw, so
// no missing-glyph box is ever rendered. The same Card always yields the
// same bytes.
package ogcard

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"strconv"
	"strings"
	"sync"
	"unicode"

	"golang.org/x/image/font"
	"golang.org/x/image/font/opentype"
	"golang.org/x/image/font/sfnt"
	"golang.org/x/image/math/fixed"
)

// Width and Height of the card in pixels.
const (
	Width  = 1200
	Height = 630
)

// Version names the drawing; it is part of Key, so changing the layout
// changes every card URL.
const Version = "1"

// SlotState is how a lifecycle slot is drawn.
type SlotState uint8

const (
	SlotNone   SlotState = iota // empty outline: the stage has not happened
	SlotKnown                   // filled: happened, time known
	SlotHollow                  // hollow: happened, time unknown or implied
)

// Slot is one of the six lifecycle markers.
type Slot struct {
	Code   string    // DIS PAT ANA POC ITW KEV
	State  SlotState //
	Latest bool      // the most recent change: drawn with a halo
}

// Product is one affected vendor/product pair (upstream text).
type Product struct {
	Vendor  string
	Product string
}

// Card is everything the card shows.
type Card struct {
	CVE   string // CVE-2026-102895
	Title string // upstream English title; "" when there is none
	// Products: affected pairs in display order; ProductTotal counts all of
	// them (pairs not passed or not drawable show as "+N").
	Products     []Product
	ProductTotal int
	Slots        []Slot // six, in stage order
	// Change is the stage code of the most recent stage change and TPlus
	// its "T+Nd" figure; both "" to leave the figure out.
	Change   string
	TPlus    string
	Rejected bool
}

// Key is a short digest of everything that changes the picture (Card and
// Version): equal keys, equal PNGs.
func (c Card) Key() string {
	b, _ := json.Marshal(struct {
		V string
		C Card
	}{Version, c})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:5])
}

// Palette (internal/webui/static/app.css).
var (
	cBg      = rgb(0x0D1117)
	cLine2   = rgb(0x1D2531)
	cLine    = rgb(0x263040)
	cStrip   = rgb(0x232D3B)
	cNone    = rgb(0x2B3646)
	cSep     = rgb(0x3A475A)
	cGreen   = rgb(0x7EE787)
	cFg      = rgb(0xE7ECF2)
	cFg2     = rgb(0xA3AFBD)
	cFg3     = rgb(0x8592A2)
	stageRGB = map[string]color.RGBA{
		"DIS": rgb(0x9FB0C3), "PAT": rgb(0x5EB1FF), "ANA": rgb(0xB79CFF),
		"POC": rgb(0xF5B83D), "ITW": rgb(0xFF8A4C), "KEV": rgb(0xFF5C6C),
	}
)

func rgb(v uint32) color.RGBA {
	return color.RGBA{R: uint8(v >> 16), G: uint8(v >> 8), B: uint8(v), A: 0xFF}
}

func stageColor(code string) color.RGBA {
	if c, ok := stageRGB[code]; ok {
		return c
	}
	return cFg2
}

// over is c at opacity a (0..1000) over the background.
func over(c color.RGBA, a int) color.RGBA {
	mix := func(f, b uint8) uint8 { return uint8((int(f)*a + int(b)*(1000-a) + 500) / 1000) }
	return color.RGBA{R: mix(c.R, cBg.R), G: mix(c.G, cBg.G), B: mix(c.B, cBg.B), A: 0xFF}
}

//go:embed fonts/JetBrainsMono-Regular.ttf
var regularTTF []byte

//go:embed fonts/JetBrainsMono-Bold.ttf
var boldTTF []byte

type fonts struct{ regular, bold *opentype.Font }

var loadFonts = sync.OnceValues(func() (fonts, error) {
	r, err := opentype.Parse(regularTTF)
	if err != nil {
		return fonts{}, err
	}
	b, err := opentype.Parse(boldTTF)
	if err != nil {
		return fonts{}, err
	}
	return fonts{r, b}, nil
})

// latin reports whether r is in the scripts the card draws: Latin letters,
// digits, punctuation and symbols of the Latin blocks. Everything else
// (Han, Cyrillic, combining marks ...) is dropped even when the font has it.
func latin(r rune) bool {
	switch {
	case r < 0x20 || r == 0x7F || (r >= 0x80 && r < 0xA0):
		return false
	case r < 0x250: // Basic Latin .. Latin Extended-B
		return true
	case unicode.Is(unicode.Latin, r):
		return true
	case r >= 0x2000 && r <= 0x206F: // General Punctuation
		return !unicode.Is(unicode.Cf, r)
	}
	return false
}

// Clean returns s reduced to what the card can draw: runes outside latin or
// missing from either face are dropped, whitespace runs become one space,
// and the result is trimmed.
func Clean(s string) string {
	f, err := loadFonts()
	if err != nil {
		return ""
	}
	var buf sfnt.Buffer
	var b strings.Builder
	space := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			space = b.Len() > 0
			continue
		}
		if !latin(r) || !has(f.regular, &buf, r) || !has(f.bold, &buf, r) {
			continue
		}
		if space {
			b.WriteByte(' ')
			space = false
		}
		b.WriteRune(r)
	}
	return b.String()
}

func has(f *opentype.Font, buf *sfnt.Buffer, r rune) bool {
	g, err := f.GlyphIndex(buf, r)
	return err == nil && g != 0
}

// meaningful: s has a letter or digit (not just separators left over after
// Clean dropped a name).
func meaningful(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return true
		}
	}
	return false
}

// Layout (pixels). Baselines are y of the text baseline.
const (
	marginX    = 72
	contentW   = Width - 2*marginX
	headBase   = 92
	headSize   = 32
	ruleY      = 128
	idSizeMax  = 88
	textSize   = 30
	lineH      = 42
	stripY     = 466 // centre line of the strip
	slotPitch  = contentW / 6
	markerSide = 52
	markerLine = 7
	haloSide   = 88
	codeBase   = 566
	codeSize   = 30
)

type canvas struct {
	img *image.RGBA
	f   fonts
}

func (c *canvas) face(bold bool, size float64) font.Face {
	f := c.f.regular
	if bold {
		f = c.f.bold
	}
	face, err := opentype.NewFace(f, &opentype.FaceOptions{Size: size, DPI: 72, Hinting: font.HintingNone})
	if err != nil {
		panic(err) // only for invalid options
	}
	return face
}

func width(face font.Face, s string) int { return font.MeasureString(face, s).Ceil() }

func (c *canvas) text(face font.Face, col color.Color, x, y int, s string) int {
	d := font.Drawer{Dst: c.img, Src: image.NewUniform(col), Face: face, Dot: fixed.P(x, y)}
	d.DrawString(s)
	return d.Dot.X.Ceil()
}

func (c *canvas) rect(x0, y0, x1, y1 int, col color.Color) {
	draw.Draw(c.img, image.Rect(x0, y0, x1, y1), image.NewUniform(col), image.Point{}, draw.Src)
}

// box draws a square of side s centred on (cx, cy): filled with fill, with
// an inner border of width line in stroke (line 0: no border).
func (c *canvas) box(cx, cy, s, line int, fill, stroke color.Color) {
	x0, y0 := cx-s/2, cy-s/2
	if line > 0 {
		c.rect(x0, y0, x0+s, y0+s, stroke)
		c.rect(x0+line, y0+line, x0+s-line, y0+s-line, fill)
		return
	}
	c.rect(x0, y0, x0+s, y0+s, fill)
}

// ellipsis is "…" when the faces have it.
func ellipsis() string {
	if Clean("…") == "…" {
		return "…"
	}
	return "..."
}

// fit shortens s rune by rune until s+tail fits in max pixels, ending s with
// an ellipsis when it was cut.
func fit(face font.Face, s, tail string, max int) string {
	if width(face, s+tail) <= max {
		return s + tail
	}
	e := ellipsis()
	r := []rune(s)
	for k := len(r) - 1; k > 0; k-- {
		if width(face, string(r[:k])+e+tail) > max {
			continue
		}
		// prefer a word boundary when it keeps most of the line
		if sp := strings.LastIndexByte(string(r[:k]), ' '); sp >= 0 && len([]rune(string(r[:k])[:sp])) >= k*2/3 {
			k = len([]rune(string(r[:k])[:sp]))
		}
		return strings.TrimRight(string(r[:k]), " ,·/") + e + tail
	}
	return strings.TrimSpace(tail)
}

// wrap breaks s into at most n lines of max pixels; the last line is
// ellipsised when text remains.
func wrap(face font.Face, s string, n, max int) []string {
	words := strings.Fields(s)
	var lines []string
	for len(words) > 0 && len(lines) < n {
		if len(lines) == n-1 {
			lines = append(lines, fit(face, strings.Join(words, " "), "", max))
			break
		}
		line := words[0]
		if width(face, line) > max { // one word longer than a line: break it
			r := []rune(line)
			k := len(r)
			for k > 1 && width(face, string(r[:k])) > max {
				k--
			}
			lines = append(lines, string(r[:k]))
			words[0] = string(r[k:])
			continue
		}
		i := 1
		for ; i < len(words); i++ {
			if width(face, line+" "+words[i]) > max {
				break
			}
			line += " " + words[i]
		}
		lines = append(lines, line)
		words = words[i:]
	}
	return lines
}

// productLine renders the affected products like the site's product line:
// consecutive pairs of one vendor merged ("Vendor / A, B"), vendors joined
// with " · ", and " +N" for the pairs not shown.
func productLine(ps []Product, total int) (line, more string) {
	var groups []string
	var cur []string
	vendor, shown := "", 0
	open := false
	flush := func() {
		if !open {
			return
		}
		g := strings.Join(cur, ", ")
		switch {
		case vendor != "" && g != "":
			g = vendor + " / " + g
		case vendor != "":
			g = vendor
		}
		groups = append(groups, g)
	}
	for _, p := range ps {
		v, pr := Clean(p.Vendor), Clean(p.Product)
		if !meaningful(v) {
			v = ""
		}
		if !meaningful(pr) {
			pr = ""
		}
		if v == "" && pr == "" {
			continue
		}
		shown++
		if !open || !strings.EqualFold(v, vendor) {
			flush()
			vendor, cur, open = v, nil, true
		}
		// A product that only repeats its vendor adds nothing: "X / X" is
		// shown as "X", "X / X Foo" as "X / Foo", and a product is listed
		// once per vendor.
		if v != "" {
			if strings.EqualFold(pr, v) {
				pr = ""
			} else if len(pr) > len(v) && pr[len(v)] == ' ' && strings.EqualFold(pr[:len(v)], v) {
				pr = strings.TrimSpace(pr[len(v):])
			}
		}
		dup := false
		for _, have := range cur {
			if strings.EqualFold(have, pr) {
				dup = true
				break
			}
		}
		if pr != "" && !dup {
			cur = append(cur, pr)
		}
	}
	flush()
	if total < len(ps) {
		total = len(ps)
	}
	if n := total - shown; n > 0 {
		more = " +" + strconv.Itoa(n)
	}
	return strings.Join(groups, " · "), more
}

// Render draws c as a PNG.
func Render(c Card) ([]byte, error) {
	f, err := loadFonts()
	if err != nil {
		return nil, err
	}
	cv := &canvas{img: image.NewRGBA(image.Rect(0, 0, Width, Height)), f: f}
	cv.rect(0, 0, Width, Height, cBg)

	// Header: brand left; REJECTED and the latest change right.
	head := cv.face(true, headSize)
	x := cv.text(head, cGreen, marginX, headBase, "nday")
	cv.text(head, cFg2, x, headBase, ".land")
	right := Width - marginX
	small := cv.face(false, headSize)
	if tp, code := Clean(c.TPlus), Clean(c.Change); tp != "" && code != "" {
		w := width(small, tp)
		cv.text(small, cFg, right-w, headBase, tp)
		right -= w + width(small, " ")
		ch := "+" + code
		w = width(head, ch)
		cv.text(head, stageColor(code), right-w, headBase, ch)
		right -= w + 28
	}
	if c.Rejected {
		tag := cv.face(false, 24)
		const label = "REJECTED"
		w := width(tag, label)
		x0 := right - w - 24
		cv.rect(x0, headBase-30, right, headBase+10, cLine)
		cv.rect(x0+2, headBase-28, right-2, headBase+8, cBg)
		cv.text(tag, cFg3, x0+12, headBase-1, label)
	}
	cv.rect(marginX, ruleY, Width-marginX, ruleY+2, cLine2)

	// CVE id, products, title. Without a title the block moves down to
	// keep the space above the strip balanced.
	title := Clean(c.Title)
	if !meaningful(title) {
		title = ""
	}
	tf := cv.face(false, textSize)
	var lines []string
	if title != "" {
		lines = wrap(tf, title, 2, contentW)
	}
	id := Clean(c.CVE)
	idSize := float64(idSizeMax)
	if n := len([]rune(id)); n > 0 {
		// JetBrains Mono advances are 0.6em
		if s := float64(contentW) / (0.6 * float64(n)); s < idSize {
			idSize = s
		}
	}
	y := 228
	switch len(lines) {
	case 0:
		y += 62
	case 1:
		y += 22
	}
	cv.text(cv.face(true, idSize), cFg, marginX, y, id)
	y += 58
	if pl, more := productLine(c.Products, c.ProductTotal); pl != "" || more != "" {
		cv.text(tf, cFg2, marginX, y, fit(tf, pl, more, contentW))
		y += lineH + 8
	}
	for _, l := range lines {
		cv.text(tf, cFg, marginX, y, l)
		y += lineH
	}

	// Lifecycle strip.
	first := marginX + slotPitch/2
	last := first + 5*slotPitch
	cv.rect(first, stripY-1, last, stripY+2, cStrip)
	code := cv.face(true, codeSize)
	for i := 0; i < 6; i++ {
		s := Slot{State: SlotNone}
		if i < len(c.Slots) {
			s = c.Slots[i]
		}
		cx := first + i*slotPitch
		col := stageColor(s.Code)
		if s.Latest && s.State != SlotNone {
			a := 300
			if s.Code == "KEV" {
				a = 320
			}
			cv.box(cx, stripY, haloSide, 0, over(col, a), nil)
		}
		switch s.State {
		case SlotKnown:
			cv.box(cx, stripY, markerSide, 0, col, nil)
		case SlotHollow:
			cv.box(cx, stripY, markerSide, markerLine, cBg, col)
		default:
			cv.box(cx, stripY, markerSide, markerLine, cBg, cNone)
		}
		label := Clean(s.Code)
		lc := col
		if s.State == SlotNone {
			lc = cSep
		}
		cv.text(code, lc, cx-width(code, label)/2, codeBase, label)
	}

	var out bytes.Buffer
	if err := (&png.Encoder{CompressionLevel: png.BestCompression}).Encode(&out, cv.img); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
