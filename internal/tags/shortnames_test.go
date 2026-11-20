package tags

import (
	"strings"
	"testing"
)

// Every product tag has a name short enough for the share card's one-line
// watermark: two words and 18 characters at most, plain ASCII. A ShortNames
// entry is for a product tag and actually changes its label.
func TestShortNames(t *testing.T) {
	for slug, s := range ShortNames {
		tg, ok := Lookup(slug)
		if !ok || tg.Dim != DimProduct {
			t.Errorf("%s: not a product tag", slug)
		}
		if s == tg.Label {
			t.Errorf("%s: %q is just the label", slug, s)
		}
	}
	for _, tg := range InDim(DimProduct) {
		s := ShortName(tg.Slug)
		if s == "" || len(s) > 18 || len(strings.Fields(s)) > 2 || strings.TrimSpace(s) != s {
			t.Errorf("%s: short name %q (label %q)", tg.Slug, s, tg.Label)
		}
		for _, r := range s {
			if r < 0x20 || r > 0x7E {
				t.Errorf("%s: %q isn't plain ASCII", tg.Slug, s)
				break
			}
		}
	}
	if ShortName("no-such-tag") != "" || ShortName("magento") != "Magento" || ShortName("redis") != "Redis" {
		t.Error("ShortName lookups")
	}
}
