package tags

import (
	"regexp"
	"testing"
)

// Icons: every key is a product or ecosystem tag, every target a plain
// Simple Icons slug; IconFor gives nothing to other dimensions or unknown
// slugs. (That every target is a symbol of the generated sprite is checked
// in internal/webui.)
func TestIconMapping(t *testing.T) {
	idRe := regexp.MustCompile(`^[a-z0-9]+$`)
	for slug, id := range Icons {
		tg, ok := Lookup(slug)
		switch {
		case !ok:
			t.Errorf("%s: not a tag", slug)
		case tg.Dim != DimProduct && tg.Dim != DimEcosystem:
			t.Errorf("%s: dimension %s cannot have an icon", slug, tg.Dim)
		}
		if !idRe.MatchString(id) {
			t.Errorf("%s: icon id %q", slug, id)
		}
		if IconFor(slug) != id {
			t.Errorf("%s: IconFor %q", slug, IconFor(slug))
		}
	}
	for _, tg := range Vocabulary {
		if tg.Dim != DimProduct && tg.Dim != DimEcosystem && IconFor(tg.Slug) != "" {
			t.Errorf("%s (%s) has an icon", tg.Slug, tg.Dim)
		}
	}
	if IconFor("nope") != "" || IconFor("") != "" {
		t.Error("unknown slug has an icon")
	}
}
