package ogcard

import (
	"errors"
	"image"
	"image/color"
	"sync"

	"golang.org/x/image/vector"
)

// The watermark: the brand mark of the affected product (a Simple Icons
// 24x24 path, docs/tagicons.md), drawn big and faint behind everything
// else, hanging off the right and bottom edges. Tune these.
const (
	markScale    = 26      // viewBox units to pixels: the 24x24 mark becomes a 624px box
	markX, markY = 640, 60 // top-left corner of that box on the card
	markOpacity  = 0.07    // cFg over cBg at this much, where the mark is solid
)

var markOrigin = image.Point{X: markX, Y: markY}

const markSide = 24 * markScale

// MarkMask rasterises SVG path data in the 24x24 viewBox at the card's
// watermark size: a markSide-square alpha mask, non-zero fill. Bad path
// data is an error, never a panic.
func MarkMask(d string) (*image.Alpha, error) {
	segs, err := parsePath(d)
	if err != nil {
		return nil, err
	}
	z := vector.NewRasterizer(markSide, markSide)
	f := func(p pt) (float32, float32) { return float32(p.x * markScale), float32(p.y * markScale) }
	open := false
	for _, s := range segs {
		switch s.op {
		case 'M':
			if open {
				z.ClosePath()
			}
			z.MoveTo(f(s.p[0]))
			open = true
		case 'L':
			z.LineTo(f(s.p[0]))
		case 'C':
			ax, ay := f(s.p[0])
			bx, by := f(s.p[1])
			cx, cy := f(s.p[2])
			z.CubeTo(ax, ay, bx, by, cx, cy)
		case 'Z':
			z.ClosePath() // the pen goes back to the subpath's start, as in SVG
		}
	}
	if open {
		z.ClosePath()
	}
	m := image.NewAlpha(image.Rect(0, 0, markSide, markSide))
	z.Draw(m, m.Bounds(), image.Opaque, image.Point{})
	return m, nil
}

// markCache keeps the rasterised mask of each slug (a hundred or so at
// most), so a card render doesn't rasterise again. A failed parse is kept
// too, as a nil mask.
var markCache = struct {
	sync.Mutex
	m map[string]markEntry
}{m: map[string]markEntry{}}

type markEntry struct {
	d    string
	mask *image.Alpha
	err  error
}

const markCacheMax = 256

// markFor is the cached mask of slug drawn from path data d.
func markFor(slug, d string) (*image.Alpha, error) {
	if slug == "" || d == "" {
		return nil, errors.New("no mark")
	}
	markCache.Lock()
	e, ok := markCache.m[slug]
	markCache.Unlock()
	if ok && e.d == d {
		return e.mask, e.err
	}
	mask, err := MarkMask(d)
	markCache.Lock()
	if _, have := markCache.m[slug]; have || len(markCache.m) < markCacheMax {
		markCache.m[slug] = markEntry{d, mask, err}
	}
	markCache.Unlock()
	return mask, err
}

// drawMark paints the mask onto the background at markOrigin, clipped to
// the canvas. It expects the canvas to hold only cBg there.
func (c *canvas) drawMark(m *image.Alpha) {
	var lut [256]color.RGBA
	for a := range lut {
		k := float64(a) / 255 * markOpacity
		mix := func(f, b uint8) uint8 { return uint8(float64(f)*k + float64(b)*(1-k) + 0.5) }
		lut[a] = color.RGBA{R: mix(cFg.R, cBg.R), G: mix(cFg.G, cBg.G), B: mix(cFg.B, cBg.B), A: 0xFF}
	}
	r := m.Bounds().Add(markOrigin).Intersect(c.img.Bounds())
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			if a := m.AlphaAt(x-markOrigin.X, y-markOrigin.Y).A; a != 0 {
				c.img.SetRGBA(x, y, lut[a])
			}
		}
	}
}
