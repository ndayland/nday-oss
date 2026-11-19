package webui

import (
	"testing"

	"nday.land/nday/internal/site"
	"nday.land/nday/internal/webui/i18n"
)

// A vulnerability shard holds at most SitemapSpan ids, each once per
// locale; with every known locale enabled that stays well under the
// protocol's 50,000 URLs (and, at ~150 bytes a URL, under 50 MB).
func TestSitemapShardLimit(t *testing.T) {
	set, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	if n := len(set.All) * site.SitemapSpan; n > 45000 {
		t.Errorf("a shard may hold %d URLs (%d locales x %d)", n, len(set.All), site.SitemapSpan)
	}
	if n := len(sitemapPages) * len(set.All); n > 45000 {
		t.Errorf("pages shard: %d URLs", n)
	}
}

func TestParseSitemapShard(t *testing.T) {
	for in, want := range map[string]site.SitemapBucket{"vuln-2026-0.xml": {Year: 2026, Bucket: 0}, "vuln-1999-20.xml": {Year: 1999, Bucket: 20},
		"ghsa-g.xml": {GHSA: "g"}, "ghsa-2.xml": {GHSA: "2"}} {
		b, ok := parseSitemapShard(in)
		if !ok || b != want || sitemapShardPath(b) != "/sitemap/"+in {
			t.Errorf("%s: %v %v", in, b, ok)
		}
	}
	for _, in := range []string{"", "pages.xml", "vuln-2026-0", "vuln-2026-00.xml", "vuln-02026-0.xml", "vuln-2026--1.xml",
		"vuln-2026-+1.xml", "vuln-999-0.xml", "vuln-10000-0.xml", "vuln-2026.xml", "vuln-2026-1-2.xml", "Vuln-2026-0.xml",
		"ghsa-.xml", "ghsa-a.xml", "ghsa-0.xml", "ghsa-G.xml", "ghsa-gg.xml", "ghsa-g", "GHSA-g.xml", "vuln-g.xml"} {
		if b, ok := parseSitemapShard(in); ok {
			t.Errorf("%s: accepted as %v", in, b)
		}
	}
}
