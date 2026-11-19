package webui

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"html"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"nday.land/nday/internal/siteicon"
)

// Site icons (docs/siteicons.md): on the vulnerability page every link that
// leaves the site shows the target site's icon in front of its text. The
// icons are fetched by `nday site-icons` (internal/siteicon) in the
// background and served from our own origin at /icon/<host>?v=<hash>; a page
// view only looks the hosts up, in one query.
//
// Which links: exactly the anchors the page marks as leaving the site,
// target="_blank" (commit "Open links that leave the site in a new tab";
// TestExternalLinksOpenInNewTab keeps every external link and no internal
// one marked), inside <main>. They are found in the rendered page rather
// than in the view model because many are built as HTML fragments in Go
// (summary source, CVSS source, tag reasons, implied-event basis) next to
// the template's own; OutboundLinks is the one enumeration, used for the
// lookup and for the decoration alike.

const (
	iconPrefix = "/icon/"
	// Cache-Control of the icon route: by its current ?v= the bytes never
	// change; without ?v= a day; a ?v= that is not the stored hash (an old
	// or made-up URL) and a missing icon only briefly.
	iconCacheCurrent = "public, max-age=86400, immutable"
	iconCacheNoV     = "public, max-age=86400"
	iconCacheShort   = "public, max-age=300"
	// iconCSP: an image needs nothing, and a document (should a browser
	// ever render one) gets no script, no origin.
	iconCSP = "default-src 'none'; sandbox"
	// favPlaceholder takes the icon's place when there is none: the same
	// 16x16 box drawn in CSS, so nothing shifts and nothing is broken.
	favPlaceholder = `<span class="fav" aria-hidden="true"></span>`
	// favAttr marks a decorated anchor for the stylesheet (it reserves the
	// icon's room at the start of the link, so the icon cannot wrap away
	// from the text).
	favAttr = ` data-fav=""`
)

var (
	startTagRe = regexp.MustCompile(`<a\s[^>]*>`)
	hrefAttrRe = regexp.MustCompile(`\shref="([^"]*)"`)
)

// outboundTag is one anchor start tag of a rendered page that leaves the
// site: [start, end) of the tag in the page and its icon host ("" = none).
type outboundTag struct {
	start, end int
	host       string
}

// mainBounds returns the byte range of the page's <main> element contents
// (-1, -1 when there is none).
func mainBounds(page []byte) (int, int) {
	i := bytes.Index(page, []byte("<main"))
	j := bytes.LastIndex(page, []byte("</main>"))
	if i < 0 || j < i {
		return -1, -1
	}
	return i, j
}

// outboundTags finds the anchors of page's <main> that leave the site
// (target="_blank"; the page's own escaping guarantees no ">" inside an
// attribute value).
func outboundTags(page []byte) []outboundTag {
	lo, hi := mainBounds(page)
	if lo < 0 {
		return nil
	}
	var out []outboundTag
	for _, m := range startTagRe.FindAllIndex(page[lo:hi], -1) {
		tag := page[lo+m[0] : lo+m[1]]
		if !bytes.Contains(tag, []byte(` target="_blank"`)) {
			continue
		}
		t := outboundTag{start: lo + m[0], end: lo + m[1]}
		if h := hrefAttrRe.FindSubmatch(tag); h != nil {
			t.host, _ = siteicon.HostOf(html.UnescapeString(string(h[1])))
		}
		out = append(out, t)
	}
	return out
}

// OutboundLinks returns the href of every link of a rendered page's <main>
// that leaves the site, in page order: what gets a site icon.
func OutboundLinks(page []byte) []string {
	var out []string
	for _, t := range outboundTags(page) {
		if h := hrefAttrRe.FindSubmatch(page[t.start:t.end]); h != nil {
			out = append(out, html.UnescapeString(string(h[1])))
		}
	}
	return out
}

// decorateOutbound puts the site icon (icons: host -> hash) or the
// placeholder at the start of every outbound link of page's <main>.
func decorateOutbound(page []byte, tags []outboundTag, icons map[string]string) []byte {
	if len(tags) == 0 {
		return page
	}
	var b bytes.Buffer
	b.Grow(len(page) + len(tags)*160)
	prev := 0
	for _, t := range tags {
		b.Write(page[prev : t.end-1]) // the start tag without its ">"
		b.WriteString(favAttr + ">")
		if hash, ok := icons[t.host]; ok && t.host != "" {
			b.WriteString(`<img class="fav" src="` + iconPrefix + t.host + `?v=` + html.EscapeString(hash) +
				`" alt="" width="16" height="16" loading="lazy" decoding="async"/>`)
		} else {
			b.WriteString(favPlaceholder)
		}
		prev = t.end
	}
	b.Write(page[prev:])
	return b.Bytes()
}

// withSiteIcons decorates a rendered page's outbound links, looking their
// hosts up in one query through the shared cache. A failed lookup is
// logged and gives placeholders: the page is still served.
func (u *UI) withSiteIcons(ctx context.Context, page []byte) []byte {
	tags := outboundTags(page)
	if len(tags) == 0 {
		return page
	}
	set := map[string]bool{}
	var hosts []string
	for _, t := range tags {
		if t.host != "" && !set[t.host] {
			set[t.host] = true
			hosts = append(hosts, t.host)
		}
	}
	icons := map[string]string{}
	if len(hosts) > 0 {
		sort.Strings(hosts)
		sum := sha256.Sum256([]byte(strings.Join(hosts, " ")))
		got, err := u.cached(ctx, "icons|"+hex.EncodeToString(sum[:16]), func(ctx context.Context) (any, error) {
			return u.srv.Store.SiteIcons(ctx, hosts)
		})
		if err != nil {
			u.srv.Log.Warn("site icon lookup failed", "err", err)
		} else if m, ok := got.(map[string]string); ok && m != nil {
			icons = m
		}
	}
	return decorateOutbound(page, tags, icons)
}

// siteIcon serves GET /icon/{host}: the stored icon of host, as stored,
// never anything else (no fetch, no redirect: not a proxy). host must
// already be a normalised icon host (siteicon.ValidHost), else 404. The row
// is read straight from the store (one primary-key read), not through the
// shared page cache: arbitrary names must not evict pages or pin bytes.
func (u *UI) siteIcon(w http.ResponseWriter, r *http.Request) {
	host := r.PathValue("host")
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", iconCSP)
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	var ic *siteicon.Icon
	if siteicon.ValidHost(host) {
		var err error
		ic, err = u.srv.Store.SiteIcon(r.Context(), host)
		if err != nil {
			u.srv.Log.Warn("site icon load failed", "host", host, "err", err)
			h.Set("Cache-Control", "no-store")
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if ic == nil {
		h.Set("Cache-Control", iconCacheShort)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	h.Set("Content-Type", ic.ContentType)
	switch q := r.URL.Query(); {
	case !q.Has("v"):
		h.Set("Cache-Control", iconCacheNoV)
	case q.Get("v") == ic.Hash:
		h.Set("Cache-Control", iconCacheCurrent)
	default:
		h.Set("Cache-Control", iconCacheShort)
	}
	etag := `"` + ic.Hash + `"`
	h.Set("ETag", etag)
	if etagMatch(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(ic.Image)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(ic.Image)
	}
}
