package webui

import (
	"bufio"
	"context"
	"encoding/xml"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/site"
)

// Sitemaps (sitemaps.org protocol). /sitemap.xml is an index of the shards
// under /sitemap/ (both outside every locale prefix; "sitemap" is a reserved
// name in internal/auth/names.go, so no locale or community route can take
// it):
//
//	/sitemap/pages.xml           the indexable static pages
//	/sitemap/vuln-YYYY-B.xml     CVE-YYYY-N with N / site.SitemapSpan == B
//	/sitemap/ghsa-C.xml          vulnerabilities keyed by a GHSA id GHSA-Cxxx-…
//
// Every page appears once per enabled locale, at exactly the canonical URL
// the page itself declares (BaseURL + locale.Path(path)). A vulnerability's
// shard depends on its id alone (stable), and a shard holds at most
// site.SitemapSpan × locales URLs (35,000 with 7 locales; the protocol's
// limit is 50,000).

// sitemapPages are the locale-neutral paths of the indexable static pages
// (not /hot, an alias of /; not the /vuln search page; not the sign-in,
// account, welcome or admin pages, which are noindex).
var sitemapPages = []string{"/", "/discussed", "/about", "/src", "/stats", "/rules"}

const (
	sitemapNS        = "http://www.sitemaps.org/schemas/sitemap/0.9"
	sitemapCache     = "public, max-age=3600"
	sitemapType      = "application/xml; charset=utf-8"
	sitemapPagesFile = "pages.xml"
	sitemapVulnPre   = "vuln-"
	sitemapGHSAPre   = "ghsa-"
	sitemapExt       = ".xml"
)

// sitemapShardPath is the path of a vulnerability shard.
func sitemapShardPath(b site.SitemapBucket) string {
	if b.GHSA != "" {
		return "/sitemap/" + sitemapGHSAPre + b.GHSA + sitemapExt
	}
	return "/sitemap/" + sitemapVulnPre + strconv.Itoa(b.Year) + "-" + strconv.Itoa(b.Bucket) + sitemapExt
}

// parseSitemapShard parses "vuln-YYYY-B.xml" (canonical numbers only, so
// every shard has exactly one URL) or "ghsa-C.xml" (C one character of
// site.GHSAAlphabet, lower case).
func parseSitemapShard(file string) (site.SitemapBucket, bool) {
	if rest, ok := strings.CutPrefix(file, sitemapGHSAPre); ok {
		c, ok := strings.CutSuffix(rest, sitemapExt)
		if !ok || len(c) != 1 || !strings.Contains(site.GHSAAlphabet, c) {
			return site.SitemapBucket{}, false
		}
		return site.SitemapBucket{GHSA: c}, true
	}
	rest, ok := strings.CutPrefix(file, sitemapVulnPre)
	if !ok {
		return site.SitemapBucket{}, false
	}
	if rest, ok = strings.CutSuffix(rest, sitemapExt); !ok {
		return site.SitemapBucket{}, false
	}
	ys, bs, ok := strings.Cut(rest, "-")
	if !ok {
		return site.SitemapBucket{}, false
	}
	y, err1 := strconv.Atoi(ys)
	b, err2 := strconv.Atoi(bs)
	if err1 != nil || err2 != nil || strconv.Itoa(y) != ys || strconv.Itoa(b) != bs || y < 1000 || y > 9999 || b < 0 {
		return site.SitemapBucket{}, false
	}
	return site.SitemapBucket{Year: y, Bucket: b}, true
}

func (u *UI) sitemapBuckets(ctx context.Context) ([]site.SitemapBucket, error) {
	v, err := u.cached(ctx, "sitemap|index", func(ctx context.Context) (any, error) { return u.srv.Store.SitemapBuckets(ctx) })
	if err != nil {
		return nil, err
	}
	return v.([]site.SitemapBucket), nil
}

func (u *UI) sitemapVulns(ctx context.Context, b site.SitemapBucket) ([]site.SitemapEntry, error) {
	key := "sitemap|vuln|" + strconv.Itoa(b.Year) + "|" + strconv.Itoa(b.Bucket) + "|" + b.GHSA
	v, err := u.cached(ctx, key, func(ctx context.Context) (any, error) { return u.srv.Store.SitemapVulns(ctx, b) })
	if err != nil {
		return nil, err
	}
	return v.([]site.SitemapEntry), nil
}

// sitemapIndex serves /sitemap.xml.
func (u *UI) sitemapIndex(w http.ResponseWriter, r *http.Request) {
	buckets, err := u.sitemapBuckets(r.Context())
	if err != nil {
		u.fail(w, r, u.locales.Primary(), err)
		return
	}
	bw := startSitemap(w, `<sitemapindex xmlns="`+sitemapNS+`">`)
	loc := func(p string) {
		_, _ = bw.WriteString("<sitemap><loc>")
		_ = xml.EscapeText(bw, []byte(u.opts.BaseURL+p))
		_, _ = bw.WriteString("</loc></sitemap>\n")
	}
	loc("/sitemap/" + sitemapPagesFile)
	for _, b := range buckets {
		loc(sitemapShardPath(b))
	}
	_, _ = bw.WriteString("</sitemapindex>\n")
	_ = bw.Flush()
}

// sitemapShard serves /sitemap/{file}; unknown and empty shards are 404.
func (u *UI) sitemapShard(w http.ResponseWriter, r *http.Request) {
	file := r.PathValue("file")
	if file == sitemapPagesFile {
		bw := startSitemap(w, `<urlset xmlns="`+sitemapNS+`">`)
		for _, p := range sitemapPages {
			for _, l := range u.locales.Enabled {
				writeSitemapURL(bw, u.opts.BaseURL+l.Path(p), time.Time{})
			}
		}
		_, _ = bw.WriteString("</urlset>\n")
		_ = bw.Flush()
		return
	}
	b, ok := parseSitemapShard(file)
	if !ok {
		u.notFound(w, r, u.locales.Primary())
		return
	}
	entries, err := u.sitemapVulns(r.Context(), b)
	if err != nil {
		u.fail(w, r, u.locales.Primary(), err)
		return
	}
	if len(entries) == 0 {
		u.notFound(w, r, u.locales.Primary())
		return
	}
	bw := startSitemap(w, `<urlset xmlns="`+sitemapNS+`">`)
	for _, e := range entries {
		for _, l := range u.locales.Enabled {
			writeSitemapURL(bw, u.opts.BaseURL+l.Path("/vuln/"+e.CVEID), e.LastMod)
		}
	}
	_, _ = bw.WriteString("</urlset>\n")
	_ = bw.Flush()
}

// startSitemap writes the headers, the XML declaration and the root element
// and returns the buffered body writer (the caller flushes it).
func startSitemap(w http.ResponseWriter, root string) *bufio.Writer {
	h := w.Header()
	h.Set("Content-Type", sitemapType)
	h.Set("Cache-Control", sitemapCache)
	w.WriteHeader(http.StatusOK)
	bw := bufio.NewWriterSize(w, 32<<10)
	_, _ = io.WriteString(bw, xml.Header)
	_, _ = bw.WriteString(root + "\n")
	return bw
}

// writeSitemapURL writes one <url>; a zero lastmod is omitted.
func writeSitemapURL(bw *bufio.Writer, href string, lastmod time.Time) {
	_, _ = bw.WriteString("<url><loc>")
	_ = xml.EscapeText(bw, []byte(href))
	_, _ = bw.WriteString("</loc>")
	if !lastmod.IsZero() {
		_, _ = bw.WriteString("<lastmod>" + lastmod.UTC().Format(time.RFC3339) + "</lastmod>")
	}
	_, _ = bw.WriteString("</url>\n")
}
