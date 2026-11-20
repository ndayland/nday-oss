package ogcard

import (
	"image"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/math/fixed"
)

// The name watermark: when there's no brand mark, the product's name is
// drawn big and faint in bold in the bottom right corner, behind the
// lifecycle strip and clear of the id, the product line and the title. One
// line, at most the first two words of the name. Tune these.
const (
	wordSizeMax = 280  // font size of a short name
	wordSizeMin = 96   // never smaller; a longer name is cut down or clipped instead
	wordOpacity = 0.07 // cFg over cBg, like the mark
	wordTop     = 400  // nothing is drawn above this: the title's last line ends higher up
	wordBase    = Height - 14
	wordRight   = Width - marginX/2 // the ink ends here, a bit past the margin
	wordAreaW   = wordRight - marginX
	wordWords   = 2 // words of the name kept
)

// wordLine is what's drawn of name and its font size: the first two words
// as big as fits the width, or just the first word when two don't fit even
// at the smallest size.
func wordLine(name string) (string, float64) {
	words := strings.Fields(name)
	if len(words) == 0 {
		return "", 0
	}
	// JetBrains Mono advances are 0.6em
	size := func(s string) float64 { return float64(wordAreaW) / (0.6 * float64(len([]rune(s)))) }
	line := strings.Join(words[:min(len(words), wordWords)], " ")
	if size(line) < wordSizeMin {
		line = words[0]
	}
	return line, min(wordSizeMax, max(size(line), wordSizeMin))
}

// drawWordmark paints name as the watermark, clipped to the rows from
// wordTop down. It expects the canvas to hold only cBg there, and reports
// whether it drew anything.
func (c *canvas) drawWordmark(name string) bool {
	name = Clean(name)
	if !meaningful(name) {
		return false
	}
	line, size := wordLine(name)
	face := c.face(true, size)
	k := wordOpacity
	mix := func(f, b uint8) uint8 { return uint8(float64(f)*k + float64(b)*(1-k) + 0.5) }
	col := cBg
	col.R, col.G, col.B = mix(cFg.R, cBg.R), mix(cFg.G, cBg.G), mix(cFg.B, cBg.B)
	// The ink, not the pen, ends at wordRight; a word too long even at the
	// smallest size starts at the margin instead and runs off the right.
	b, _ := font.BoundString(face, line)
	x := fixed.I(wordRight) - b.Max.X
	if left := fixed.I(marginX) - b.Min.X; x < left {
		x = left
	}
	dst := c.img.SubImage(image.Rect(0, wordTop, Width, Height)).(*image.RGBA)
	d := font.Drawer{Dst: dst, Src: image.NewUniform(col), Face: face, Dot: fixed.Point26_6{X: x, Y: fixed.I(wordBase)}}
	d.DrawString(line)
	return true
}
