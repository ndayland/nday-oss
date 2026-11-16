package webui

import (
	"testing"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/tags"
)

// /tags shows the 20 tags with the most CVEs of a large dimension and folds
// the rest; a dimension of at most 20 tags keeps the vocabulary order.
func TestTagsPageTop(t *testing.T) {
	rep := &site.TagsReport{}
	for i, tg := range tags.Vocabulary {
		n := int64(0)
		switch tg.Slug {
		case "csrf":
			n = 9
		case "xss":
			n = 7
		default:
			if tg.Dim == tags.DimAccess {
				n = int64(i)
			}
		}
		rep.Tags = append(rep.Tags, site.TagInfo{Slug: tg.Slug, Dimension: tg.Dim, Count: n})
	}
	p := BuildTagsPage(loc(t, "en"), rep, API{})
	for _, g := range p.Groups {
		all := len(tags.InDim(g.Dim))
		switch {
		case all <= TagsPageTop:
			if len(g.More) != 0 || len(g.Rows) != all {
				t.Errorf("%s: %d shown, %d folded of %d", g.Dim, len(g.Rows), len(g.More), all)
			}
			for i, tg := range tags.InDim(g.Dim) {
				if g.Rows[i].Chip.Slug != tg.Slug {
					t.Errorf("%s: row %d is %s, vocabulary order has %s", g.Dim, i, g.Rows[i].Chip.Slug, tg.Slug)
					break
				}
			}
		default:
			if len(g.Rows) != TagsPageTop || len(g.More) != all-TagsPageTop {
				t.Errorf("%s: %d shown, %d folded of %d", g.Dim, len(g.Rows), len(g.More), all)
			}
		}
		if g.Dim == tags.DimType {
			// by count, then vocabulary order among equals
			first := tags.InDim(tags.DimType)[0].Slug
			if g.Rows[0].Chip.Slug != "csrf" || g.Rows[1].Chip.Slug != "xss" || g.Rows[2].Chip.Slug != first {
				t.Errorf("type order: %s %s %s", g.Rows[0].Chip.Slug, g.Rows[1].Chip.Slug, g.Rows[2].Chip.Slug)
			}
		}
	}
}
