package webui

import (
	"os"
	"path/filepath"
	"testing"

	"nday.land/nday/internal/ogcard"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/tags"
)

// Every mark of the sprite parses and rasterises to something visible at
// the share card's watermark size, so no tag silently loses its watermark.
func TestTagIconPathsRasterise(t *testing.T) {
	if len(tagIconPaths) != len(tagIconSymbols) || len(tagIconPaths) == 0 {
		t.Fatalf("%d paths for %d symbols: a symbol isn't in the shape tagIconPaths reads", len(tagIconPaths), len(tagIconSymbols))
	}
	for id, d := range tagIconPaths {
		m, err := ogcard.MarkMask(d)
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		lit := 0
		for _, a := range m.Pix {
			if a != 0 {
				lit++
			}
		}
		if lit == 0 {
			t.Errorf("%s: empty mask", id)
		}
	}
}

// The watermark is the mark of the first tag, in the page's order, that has
// an icon; none, no mark.
func TestCardMark(t *testing.T) {
	view := func(slugs ...string) []tags.View {
		var vs []tags.View
		for _, s := range slugs {
			vs = append(vs, tags.View{Slug: s})
		}
		return vs
	}
	for _, tc := range []struct {
		tags []tags.View
		want string
	}{
		{nil, ""},
		{view("windows", "no-such-tag"), ""},
		{view("windows", "tomcat", "docker"), "apachetomcat"},
		{view("linux-kernel", "docker"), "linux"},
	} {
		c := cardFor(&site.VulnDetail{CVEID: "CVE-2026-7010", Tags: tc.tags})
		if c.Mark != tc.want || (c.MarkPath != "") != (tc.want != "") || c.MarkPath != tagIconPaths[tc.want] {
			t.Errorf("%v: mark %q (path %d bytes), want %q", tc.tags, c.Mark, len(c.MarkPath), tc.want)
		}
	}
	plain := cardFor(&site.VulnDetail{CVEID: "CVE-2026-7010"})
	marked := cardFor(&site.VulnDetail{CVEID: "CVE-2026-7010", Tags: view("docker")})
	if plain.Key() == marked.Key() || cardPath(plain) == cardPath(marked) {
		t.Error("the watermark didn't change the card's URL")
	}
}

// NDAY_OGCARD_SAMPLES=<dir> writes sample cards there for a look by eye:
// docker.png, linux.png, apachetomcat.png, none.png (no mark) and
// noscore.png, one card with different watermarks and scores; and word-*.png,
// the name watermark of cards without a mark.
func TestCardMarkSamples(t *testing.T) {
	dir := os.Getenv("NDAY_OGCARD_SAMPLES")
	if dir == "" {
		t.Skip("NDAY_OGCARD_SAMPLES not set")
	}
	slots := []ogcard.Slot{
		{Code: "DIS", State: ogcard.SlotKnown}, {Code: "PAT", State: ogcard.SlotKnown},
		{Code: "ANA", State: ogcard.SlotHollow}, {Code: "POC", State: ogcard.SlotKnown, Latest: true},
		{Code: "ITW"}, {Code: "KEV"},
	}
	for _, smp := range []struct{ name, mark, score string }{
		{"docker", "docker", "9.1"}, {"linux", "linux", "7.5"}, {"apachetomcat", "apachetomcat", "4.3"},
		{"none", "", "9.8"}, {"noscore", "docker", ""},
	} {
		mark := smp.mark
		c := ogcard.Card{CVE: "CVE-2026-31415",
			Title:        "Remote code execution via crafted multipart upload in the management endpoint when partial PUT is enabled",
			Products:     []ogcard.Product{{Vendor: "Apache Software Foundation", Product: "Apache Tomcat"}, {Vendor: "Docker", Product: "Docker Engine"}},
			ProductTotal: 3, Slots: slots, Change: "POC", TPlus: "T+9d",
			Mark: mark, MarkPath: tagIconPaths[mark], Score: smp.score}
		b, err := ogcard.Render(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, smp.name+".png"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// the name watermark, no mark: word-*.png
	base := func() ogcard.Card {
		return ogcard.Card{CVE: "CVE-2026-31415",
			Title:        "Remote code execution via crafted multipart upload in the management endpoint when partial PUT is enabled",
			Products:     []ogcard.Product{{Vendor: "Apache Software Foundation", Product: "Apache Tomcat"}, {Vendor: "Docker", Product: "Docker Engine"}},
			ProductTotal: 3, Slots: slots, Change: "POC", TPlus: "T+9d", Score: "9.1"}
	}
	hollow := []ogcard.Slot{
		{Code: "DIS", State: ogcard.SlotHollow}, {Code: "PAT", State: ogcard.SlotHollow},
		{Code: "ANA", State: ogcard.SlotHollow, Latest: true}, {Code: "POC"}, {Code: "ITW"}, {Code: "KEV"},
	}
	for name, edit := range map[string]func(*ogcard.Card){
		"word-short":    func(c *ogcard.Card) { c.Wordmark = "Redis" },
		"word-long":     func(c *ogcard.Card) { c.Wordmark = "Ivanti Connect Secure and Policy Secure Gateways" },
		"word-tagshort": func(c *ogcard.Card) { c.Wordmark = tags.ShortName("solarwinds-platform") },
		"word-two":      func(c *ogcard.Card) { c.Wordmark = "Windows Server" },
		"word-oneword":  func(c *ogcard.Card) { c.Wordmark = "SolarWinds" },
		"word-ghsa": func(c *ogcard.Card) {
			c.CVE, c.Wordmark = "GHSA-9wx4-h78v-vm56", "widget-go"
			c.Products, c.ProductTotal = []ogcard.Product{{Vendor: "acme", Product: "github.com/acme/widget-go"}}, 1
		},
		"word-multi": func(c *ogcard.Card) {
			c.Products = []ogcard.Product{{Vendor: "Cisco", Product: "IOS XE"}, {Vendor: "Cisco", Product: "IOS XR"}, {Vendor: "Juniper", Product: "Junos"}}
			c.ProductTotal, c.Wordmark = 3, "IOS XE"
		},
		"word-hollow": func(c *ogcard.Card) { c.Slots, c.Change, c.Wordmark = hollow, "ANA", "Windows Server" },
	} {
		c := base()
		edit(&c)
		b, err := ogcard.Render(c)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name+".png"), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// Without an icon the watermark is a name: the first product tag's label,
// else the first usable affected product (or its vendor); one name only.
func TestCardWordmark(t *testing.T) {
	// a product tag without an icon
	var bare tags.Tag
	for _, tg := range tags.InDim(tags.DimProduct) {
		if tags.Icons[tg.Slug] == "" && ogcard.Clean(tg.Label) != "" {
			bare = tg
			break
		}
	}
	if bare.Slug == "" {
		t.Fatal("no product tag without an icon")
	}
	t.Logf("product tag without an icon: %s (%q)", bare.Slug, bare.Label)
	pt := func(slugs ...string) []tags.View {
		var vs []tags.View
		for _, s := range slugs {
			tg, _ := tags.Lookup(s)
			vs = append(vs, tags.View{Slug: s, Dimension: tg.Dim})
		}
		return vs
	}
	pp := func(vp ...string) []site.Product {
		var ps []site.Product
		for i := 0; i+1 < len(vp); i += 2 {
			ps = append(ps, site.Product{Vendor: vp[i], Product: vp[i+1]})
		}
		return ps
	}
	for _, tc := range []struct {
		name     string
		tags     []tags.View
		products []site.Product
		mark     string
		want     string
	}{
		{"icon", pt("docker"), pp("Acme", "Widget"), "docker", ""},
		{"bare product tag", pt(bare.Slug), pp("Acme", "Widget"), "", tags.ShortName(bare.Slug)},
		{"long label: the short name", pt("magento"), pp("Adobe", "Commerce"), "", "Magento"},
		{"first usable product", nil, pp("n/a", "n/a", "Acme Corp", "Widget Server"), "", "Widget Server"},
		{"placeholder product, real vendor", nil, pp("Acme Corp", "unknown", "Other", "Thing"), "", "Acme Corp"},
		{"CJK only", nil, pp("华为", "鸿蒙"), "", ""},
		{"several products: the first", nil, pp("Cisco", "IOS XE", "Cisco", "IOS XR", "Juniper", "Junos"), "", "IOS XE"},
		{"long package path: the last segment", nil, pp("acme", "github.com/acme/widget-go"), "", "widget-go"},
		{"short scoped package: whole", nil, pp("", "@angular/core"), "", "@angular/core"},
		{"nothing", nil, nil, "", ""},
	} {
		c := cardFor(&site.VulnDetail{CVEID: "CVE-2026-7010", Tags: tc.tags, Products: tc.products})
		if c.Wordmark != tc.want || c.Mark != tc.mark {
			t.Errorf("%s: wordmark %q mark %q, want %q %q", tc.name, c.Wordmark, c.Mark, tc.want, tc.mark)
		}
	}
	plain := cardFor(&site.VulnDetail{CVEID: "CVE-2026-7010"})
	if plain.Key() != (ogcard.Card{CVE: plain.CVE, ProductTotal: plain.ProductTotal, Slots: plain.Slots,
		Change: plain.Change, TPlus: plain.TPlus, Score: plain.Score}).Key() {
		t.Error("no name changed the key")
	}
	named := cardFor(&site.VulnDetail{CVEID: "CVE-2026-7010", Products: pp("Acme Corp", "Widget Server")})
	unnamed := named
	unnamed.Wordmark = ""
	if cardPath(named) == cardPath(unnamed) {
		t.Error("the name didn't change the card's URL")
	}
}
