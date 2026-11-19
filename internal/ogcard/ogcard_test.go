package ogcard

import (
	"bytes"
	"image"
	"image/png"
	"strings"
	"testing"

	"golang.org/x/image/font/sfnt"
)

func sixSlots(states string, latest int) []Slot {
	codes := []string{"DIS", "PAT", "ANA", "POC", "ITW", "KEV"}
	var s []Slot
	for i, c := range codes {
		st := SlotNone
		switch states[i] {
		case 'k':
			st = SlotKnown
		case 'h':
			st = SlotHollow
		}
		s = append(s, Slot{Code: c, State: st, Latest: i == latest})
	}
	return s
}

func sample() Card {
	return Card{CVE: "CVE-2026-102895", Title: "NVIDIA GPU Display Driver out-of-bounds write",
		Products: []Product{{"NVIDIA", "GPU Display Driver"}, {"NVIDIA", "vGPU"}}, ProductTotal: 3,
		Slots: sixSlots("kkhkkk", 5), Change: "KEV", TPlus: "T+12d"}
}

func render(t *testing.T, c Card) []byte {
	t.Helper()
	b, err := Render(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestRenderPNG(t *testing.T) {
	for _, c := range []Card{sample(), {}, {CVE: "CVE-2026-1", Rejected: true, Slots: sixSlots("k-----", 0)}} {
		img, err := png.Decode(bytes.NewReader(render(t, c)))
		if err != nil {
			t.Fatal(err)
		}
		if b := img.Bounds(); b.Dx() != Width || b.Dy() != Height || Width != 1200 || Height != 630 {
			t.Errorf("%+v: bounds %v", c, b)
		}
	}
}

func TestDeterministic(t *testing.T) {
	a, b := render(t, sample()), render(t, sample())
	if !bytes.Equal(a, b) {
		t.Fatal("same card, different bytes")
	}
	if sample().Key() != sample().Key() || len(sample().Key()) != 10 {
		t.Errorf("key %q", sample().Key())
	}
	// A stage change changes the key and the picture.
	c := sample()
	c.Slots = sixSlots("kkhkk-", 4)
	if c.Key() == sample().Key() || bytes.Equal(render(t, c), a) {
		t.Error("stage change kept the key or the picture")
	}
}

// Text the font cannot draw is dropped: a card with Han/Cyrillic/emoji text
// renders exactly like the card holding only what Clean keeps, so no
// missing-glyph box is drawn for the dropped runes.
func TestNonLatinDropped(t *testing.T) {
	hostile := Card{CVE: "CVE-2026-1003", Title: "华为路由器远程代码执行漏洞",
		Products:     []Product{{"华为", "鸿蒙 HarmonyOS"}, {"Яндекс", "Браузер"}, {"Ünïcode GmbH", "Zürich​ 🔥Tooĺ"}},
		ProductTotal: 3, Slots: sixSlots("kkk---", 2), Change: "ANA", TPlus: "T+3d"}
	clean := hostile
	clean.Title = ""
	clean.Products = []Product{{"", "HarmonyOS"}, {"", ""}, {"Ünïcode GmbH", "Zürich Tool"}}
	got, want := render(t, hostile), render(t, clean)
	if !bytes.Equal(got, want) {
		t.Error("non-Latin text changed the picture: something was drawn for dropped runes")
	}
	if s := Clean("华为 / 鸿蒙"); s != "/" {
		t.Errorf("Clean = %q", s)
	}
	if s := Clean("  Zürich\t​ 🔥Tool  "); s != "Zürich Tool" {
		t.Errorf("Clean = %q", s)
	}
	// Every rune Clean keeps has a glyph in both faces.
	f, err := loadFonts()
	if err != nil {
		t.Fatal(err)
	}
	var buf sfnt.Buffer
	var all strings.Builder
	for r := rune(0); r < 0x3000; r++ {
		all.WriteRune(r)
	}
	for _, r := range Clean(all.String()) {
		if r != ' ' && (!has(f.regular, &buf, r) || !has(f.bold, &buf, r)) {
			t.Errorf("Clean kept %U without a glyph", r)
		}
	}
}

func TestProductLine(t *testing.T) {
	line, more := productLine([]Product{{"Barracuda Networks", "ESG"}, {"barracuda networks", "Load Balancer ADC"},
		{"Fortinet", "FortiOS"}, {"华为", "路由器"}}, 6)
	if line != "Barracuda Networks / ESG, Load Balancer ADC · Fortinet / FortiOS" || more != " +3" {
		t.Errorf("%q %q", line, more)
	}
	for _, tc := range []struct {
		ps   []Product
		want string
	}{
		{[]Product{{"GPUStack", "GPUStack"}}, "GPUStack"},
		{[]Product{{"Cisco", "BroadWorks"}, {"Cisco", "Cisco BroadWorks"}}, "Cisco / BroadWorks"},
		{[]Product{{"Cisco", "cisco IOS XE"}, {"Cisco", "IOS XE"}, {"Cisco", "Ciscoworks"}}, "Cisco / IOS XE, Ciscoworks"},
		{[]Product{{"", "curl"}, {"", "curl"}}, "curl"},
	} {
		if line, more := productLine(tc.ps, len(tc.ps)); line != tc.want || more != "" {
			t.Errorf("%v: %q %q, want %q", tc.ps, line, more, tc.want)
		}
	}
}

func TestTextFits(t *testing.T) {
	f, _ := loadFonts()
	cv := &canvas{f: f}
	face := cv.face(false, textSize)
	long := strings.Repeat("Supercalifragilistic ", 20) + strings.Repeat("x", 200)
	lines := wrap(face, long, 2, contentW)
	if len(lines) != 2 || !strings.HasSuffix(lines[1], "…") {
		t.Errorf("wrap: %q", lines)
	}
	for _, l := range lines {
		if w := width(face, l); w > contentW {
			t.Errorf("line %q is %dpx", l, w)
		}
	}
	if s := fit(face, long, " +99", contentW); width(face, s) > contentW || !strings.HasSuffix(s, "… +99") {
		t.Errorf("fit: %q", s)
	}
	if s := fit(face, "", strings.Repeat("9", 300), 100); s == "" {
		t.Error("fit of an over-long tail returned nothing")
	}
}

// TestAddressCard: the address card prints the address in place of the
// brand, only in the header band; it has its own key; a card without an
// address keeps the key it had before the field existed (the plain cards'
// URLs do not change).
func TestAddressCard(t *testing.T) {
	plain := sample()
	if plain.Key() != "8cec58c08e" { // sample().Key() at b705e83, before Address
		t.Errorf("plain key changed: %s", plain.Key())
	}
	addr := sample()
	addr.Address = "nday.land/vuln/CVE-2026-102895"
	if addr.Key() == plain.Key() {
		t.Error("the address card has the plain card's key")
	}
	a, p := decode(t, render(t, addr)), decode(t, render(t, plain))
	head, body := 0, 0
	for y := 0; y < Height; y++ {
		for x := 0; x < Width; x++ {
			if a.At(x, y) != p.At(x, y) {
				if y < ruleY {
					head++
				} else {
					body++
				}
			}
		}
	}
	if head == 0 || body != 0 {
		t.Errorf("differing pixels: %d in the header, %d below it", head, body)
	}
	// the host alone is the brand: the same picture as the plain card
	brand := sample()
	brand.Address = "nday.land"
	if !bytes.Equal(render(t, brand), render(t, plain)) {
		t.Error("host-only address differs from the brand")
	}
	// the longest address with everything on the right still renders
	long := Card{CVE: "GHSA-aaaa-bbbb-cccc", Rejected: true, Change: "KEV", TPlus: "T+12345d",
		Address: "nday.land/vuln/GHSA-aaaa-bbbb-cccc"}
	if _, err := Render(long); err != nil {
		t.Fatal(err)
	}
}

func decode(t *testing.T, b []byte) image.Image {
	t.Helper()
	img, err := png.Decode(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	return img
}
