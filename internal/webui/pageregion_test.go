package webui_test

import (
	"html"
	"regexp"
	"strings"
	"testing"
)

// Paging in place (docs/pagination.md; static/app.js "paging"): each public
// paged list sits with its pager in one region (data-page-region="<id>",
// the element's own id), and a later page differs from the first OUTSIDE
// the region only where app.js outside() takes the loaded page's version:
// the language links, the robots meta, the catalogue's search area
// (compact, no backdrop) and the status bar's row count (#pos, recounted by
// rowsIn). Anything else that starts to depend on the page fails here and
// must be handled there.

// regionOf is the region element id in body, from its start tag to its
// matching </div> ("" = none).
func regionOf(body, id string) string {
	start := strings.Index(body, `<div class="pgr" id="`+id+`" data-page-region="`+id+`">`)
	if start < 0 {
		return ""
	}
	depth := 0
	for i := start; i < len(body); {
		switch {
		case strings.HasPrefix(body[i:], "<div"):
			depth++
			i += 4
		case strings.HasPrefix(body[i:], "</div>"):
			depth--
			i += 6
			if depth == 0 {
				return body[start:i]
			}
		default:
			i++
		}
	}
	return ""
}

var (
	regionAttrRe = regexp.MustCompile(`data-page-region="`)
	langHrefRe   = regexp.MustCompile(`(<li><a href=")[^"]*(" hreflang=)`)
	posRe        = regexp.MustCompile(`<span id="pos">[^<]*</span>`)
)

// outsideRegion is body without the region id and with the parts outside()
// updates normalised.
func outsideRegion(body, id string) string {
	s := strings.Replace(body, regionOf(body, id), "REGION", 1)
	s = langHrefRe.ReplaceAllString(s, "${1}${2}")
	s = posRe.ReplaceAllString(s, `<span id="pos"></span>`)
	s = strings.Replace(s, "<meta name=\"robots\" content=\"noindex\"/>\n", "", 1)
	s = strings.Replace(s, `<div class="chero compact">`, `<div class="chero">`, 1)
	return strings.Replace(s, "<div class=\"cbg\" aria-hidden=\"true\"></div>\n", "", 1)
}

func TestPublicPageRegions(t *testing.T) {
	e := newCatEnv(t, catSeedPage, hotSeedPage)
	next := func(body string) string {
		if m := catNextRe.FindStringSubmatch(pagerOf(body)); m != nil {
			return html.UnescapeString(m[1])
		}
		return ""
	}
	for _, c := range []struct{ id, first, second string }{
		{"r-hot", "/", ""},
		{"r-cat", "/vuln?browse=1", ""},
		{"r-cat", "/vuln?include_rejected=1", ""},
		{"r-discussed", "/discussed", "/discussed?offset=50"},
	} {
		_, one := e.get(t, c.first)
		second := c.second
		if second == "" {
			second = next(one)
		}
		if second == "" {
			t.Fatalf("%s: no second page", c.first)
		}
		resp, two := e.get(t, second)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", second, resp.StatusCode)
		}
		for _, p := range []struct{ path, body string }{{c.first, one}, {second, two}} {
			if n := len(regionAttrRe.FindAllString(p.body, -1)); n != 1 {
				t.Errorf("%s: %d regions, want 1", p.path, n)
			}
			r := regionOf(p.body, c.id)
			if r == "" {
				t.Fatalf("%s: no region %s", p.path, c.id)
			}
			// the list and its pager (if any) are inside the region
			// the list: the table of the hot list and the catalogue, the
			// ranked list of /discussed (its box, which holds the empty
			// note on a page past the end)
			if !strings.Contains(r, `<div class="tbl-in" role="table"`) && !strings.Contains(r, `<div class="dzw">`) {
				t.Errorf("%s: the list is outside region %s", p.path, c.id)
			}
			if pg := pagerOf(p.body); pg != "" && !strings.Contains(r, pg) {
				t.Errorf("%s: the pager is outside region %s", p.path, c.id)
			}
			ids := rowIDs(p.body)
			if c.id == "r-discussed" {
				ids, _ = heatRows(p.body)
			}
			for _, id := range ids {
				if !strings.Contains(r, `data-id="`+id+`"`) {
					t.Errorf("%s: row %s outside region %s", p.path, id, c.id)
				}
			}
		}
		if regionOf(one, c.id) == regionOf(two, c.id) {
			t.Errorf("%s: page 2 shows the same region as page 1", c.first)
		}
		if a, b := outsideRegion(one, c.id), outsideRegion(two, c.id); a != b {
			t.Errorf("%s vs %s: the page differs outside region %s beyond what app.js updates:\n%s", c.first, second, c.id, firstDiff(a, b))
		}
	}
	// the known differences are real (so the normalisation above is not idle)
	_, cat1 := e.get(t, "/vuln?browse=1")
	_, cat2 := e.get(t, next(cat1))
	if !strings.Contains(cat1, `<div class="chero">`) || !strings.Contains(cat1, `class="cbg"`) ||
		!strings.Contains(cat2, `<div class="chero compact">`) || strings.Contains(cat2, `class="cbg"`) {
		t.Error("catalogue: the search area is not compact on page 2")
	}
	if !strings.Contains(cat2, `hreflang="ja"`) || !strings.Contains(cat2, `<li><a href="/ja/vuln?cursor=`) {
		t.Error("catalogue page 2: language links without the position")
	}
	_, d2 := e.get(t, "/discussed?offset=50")
	if !strings.Contains(d2, `<meta name="robots" content="noindex"/>`) {
		t.Error("discussed page 2: no robots noindex")
	}
}

// firstDiff shows where two strings start to differ.
func firstDiff(a, b string) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	from := max(0, i-120)
	return "page 1: …" + a[from:min(len(a), i+200)] + "\npage 2: …" + b[from:min(len(b), i+200)]
}
