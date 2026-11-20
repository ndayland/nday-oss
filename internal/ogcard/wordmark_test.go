package ogcard

import (
	"bytes"
	"image/color"
	"strings"
	"testing"
)

// The name watermark only touches the card under the header rule, stays
// faint, and never changes a pixel of the text, the strip or anything else
// drawn on top.
func TestWordmark(t *testing.T) {
	plain := sample()
	plain.Slots = sixSlots("kk-kkk", 5) // no hollow marker: those show the watermark through
	word := plain
	word.Wordmark = "Redis"
	p, w := decode(t, render(t, plain)), decode(t, render(t, word))
	near := func(a, b uint8) bool { return int(a) <= int(b)+25 && int(b) <= int(a)+25 }
	nearTint := func(a, b uint8) bool { return int(a) <= int(b)+16 && int(b) <= int(a)+16 }
	// colours of fully covered text and shapes: never touched
	solid := map[color.RGBA]bool{cFg: true, cFg2: true, cFg3: true, cGreen: true, cLine2: true, cStrip: true, cNone: true, cSep: true}
	for _, c := range stageRGB {
		solid[c] = true
	}
	head, body := 0, 0
	for y := 0; y < Height; y++ {
		for x := 0; x < Width; x++ {
			pc, wc := p.At(x, y).(color.RGBA), w.At(x, y).(color.RGBA)
			if pc == wc {
				continue
			}
			if y < wordTop {
				head++
				continue
			}
			body++
			switch {
			case pc == cBg:
				if !near(wc.R, cBg.R) || !near(wc.G, cBg.G) || !near(wc.B, cBg.B) || wc.A != 0xFF {
					t.Fatalf("(%d,%d): %v is not faint", x, y, wc)
				}
			case solid[pc]:
				t.Fatalf("(%d,%d): solid %v changed to %v", x, y, pc, wc)
			default:
				// the anti-aliased rim of text drawn over the watermark: off
				// by no more than the watermark's tint
				if !nearTint(pc.R, wc.R) || !nearTint(pc.G, wc.G) || !nearTint(pc.B, wc.B) || wc.A != 0xFF {
					t.Fatalf("(%d,%d): rim %v changed to %v", x, y, pc, wc)
				}
			}
		}
	}
	if head != 0 || body < 10000 {
		t.Errorf("differing pixels: %d in the header, %d below it", head, body)
	}

	// the mark wins over the name
	marked := sample()
	marked.Mark, marked.MarkPath = "disc", circle
	both := marked
	both.Wordmark = "Redis"
	if !bytes.Equal(render(t, both), render(t, marked)) {
		t.Error("a wordmark changed a card that has a mark")
	}
	// a name with nothing the card can draw is no watermark
	for _, s := range []string{"漏洞管理平台", "   ", "--"} {
		c := sample()
		c.Wordmark = s
		if !bytes.Equal(render(t, c), render(t, sample())) {
			t.Errorf("wordmark %q drew something", s)
		}
	}
	// long, very long and short names all draw
	for _, s := range []string{"Ivanti Connect Secure and Policy Secure Gateways", strings.Repeat("x", 60), "Redis"} {
		c := sample()
		c.Wordmark = s
		if bytes.Equal(render(t, c), render(t, sample())) {
			t.Errorf("wordmark %q drew nothing", s)
		}
	}
}

// No name leaves the key as it was; a name changes it.
func TestWordmarkKey(t *testing.T) {
	c := sample()
	c.Wordmark = ""
	if c.Key() != sample().Key() || c.Key() != "02d71a9bb3" {
		t.Errorf("empty wordmark changed the key: %s", c.Key())
	}
	c.Wordmark = "Redis"
	if c.Key() == sample().Key() {
		t.Error("the wordmark didn't change the key")
	}
}

// The first two words, one word when two don't fit, and a size inside the
// limits.
func TestWordLine(t *testing.T) {
	for _, tc := range []struct{ name, line string }{
		{"Redis", "Redis"},
		{"SolarWinds", "SolarWinds"},
		{"Windows Server", "Windows Server"},
		{"Ivanti Connect Secure and Policy Secure Gateways", "Ivanti Connect"},
		{"Internationalization Framework", "Internationalization"},
		{strings.Repeat("x", 60), strings.Repeat("x", 60)},
	} {
		line, size := wordLine(tc.name)
		if line != tc.line {
			t.Errorf("%q: %q, want %q", tc.name, line, tc.line)
		}
		if size < wordSizeMin || size > wordSizeMax {
			t.Errorf("%q: size %.1f", tc.name, size)
		}
	}
	if _, size := wordLine("Redis"); size != wordSizeMax {
		t.Errorf("a short name is %.1f, not the biggest size", size)
	}
}
