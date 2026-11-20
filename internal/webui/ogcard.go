package webui

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"

	"nday.land/nday/internal/ogcard"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/tags"
	"nday.land/nday/internal/titles"
)

// Share cards: GET /og/vuln/{id}.png is the vulnerability's 1200x630 Open
// Graph image (internal/ogcard), one per vulnerability (CVE id, or the GHSA
// id of an advisory without a CVE) for every locale. The detail
// page links it as og:image with ?v=<ogcard.Card.Key>, so a change of what
// the card shows yields a new URL and social caches fetch it again.
//
// ?addr=1 is the address card: the same card with the page's address
// printed in place of the brand (ogcard.Card.Address; a different Key),
// for a post that carries no link (the image forms of /admin/x/drafts,
// docs/xposts.md "Forms"). Same route, caching and headers.

const (
	cardPrefix   = "/og/vuln/"
	cardExt      = ".png"
	cardCacheTTL = 10 * time.Minute // rendered PNGs, keyed by content
	cardProducts = 6                // pairs passed to the card (as the detail page's product line)
	cardWordPath = 18               // a package path longer than this is cut to its last segment for the watermark
)

// cardFor is the card input of a vulnerability: the effective title in
// English (staff, record or composed; never title_zh), the affected products, the strip slots as BuildStrip
// classifies them, the detail page's T+ figure and CVSS score, and the watermark: the mark
// of the first tag (in the page's tag order) that has an icon, or, when none
// has, the product's name (cardWordmark).
func cardFor(v *site.VulnDetail) ogcard.Card {
	c := ogcard.Card{CVE: v.CVEID, ProductTotal: len(v.Products), Rejected: v.IsRejected}
	if v.EffectiveTitle != nil {
		c.Title = strings.TrimSpace(*v.EffectiveTitle)
	}
	for i, p := range v.Products {
		if i == cardProducts {
			break
		}
		c.Products = append(c.Products, ogcard.Product{Vendor: p.Vendor, Product: p.Product})
	}
	for _, s := range v.Slots {
		class, latest := SlotClass(s.Slot)
		st := ogcard.SlotNone
		switch class {
		case "mk mk-known":
			st = ogcard.SlotKnown
		case "mk mk-hollow":
			st = ogcard.SlotHollow
		}
		c.Slots = append(c.Slots, ogcard.Slot{Code: s.Code, State: st, Latest: latest})
	}
	if code, val, ok := tplusFact(v); ok {
		c.Change, c.TPlus = code, val
	}
	c.Score, _ = cvssScore(v)
	c.Mark, c.MarkPath = cardMark(v)
	if c.Mark == "" {
		c.Wordmark = cardWordmark(v)
	}
	return c
}

// cardWordmark is the name drawn as v's watermark when no tag has an icon:
// the short name of the first product tag (tags.ShortName), else the first affected product with
// a usable name (or its vendor when the product names nothing). A name the
// card can't draw (no Latin letter or digit left after ogcard.Clean) is
// skipped; "" for none.
func cardWordmark(v *site.VulnDetail) string {
	usable := func(s string) bool {
		if titles.IsPlaceholder(s) {
			return false
		}
		for _, r := range ogcard.Clean(s) {
			if unicode.IsLetter(r) || unicode.IsDigit(r) {
				return true
			}
		}
		return false
	}
	for _, t := range v.Tags {
		if t.Dimension != tags.DimProduct {
			continue
		}
		if name := tags.ShortName(t.Slug); usable(name) {
			return name
		}
	}
	for _, p := range v.Products {
		switch {
		case usable(p.Product):
			// A long package path ("github.com/acme/widget-go") would run
			// off the card: its last segment is the name people know.
			if i := strings.LastIndexByte(p.Product, '/'); i >= 0 && len(p.Product) > cardWordPath &&
				!strings.ContainsRune(p.Product, ' ') && usable(p.Product[i+1:]) {
				return p.Product[i+1:]
			}
			return p.Product
		case usable(p.Vendor):
			return p.Vendor
		}
	}
	return ""
}

// cardMark is the slug and path data of v's watermark, "" "" for none.
func cardMark(v *site.VulnDetail) (slug, path string) {
	for _, t := range v.Tags {
		if id := tagIcon(t.Slug); id != "" && tagIconPaths[id] != "" {
			return id, tagIconPaths[id]
		}
	}
	return "", ""
}

// cardPath is the site-relative URL of c's card.
func cardPath(c ogcard.Card) string {
	return cardPrefix + c.CVE + cardExt + "?v=" + c.Key()
}

// cardAddrParam asks the card route for the address card.
const cardAddrParam = "addr"

// addrCardPath is the site-relative URL of id's address card, without ?v=
// (the drafts page does not load the card's data; such a URL is cached
// briefly).
func addrCardPath(id string) string {
	return cardPrefix + id + cardExt + "?" + cardAddrParam + "=1"
}

// ogVuln serves a share card. It answers 404 exactly when the detail page
// does for a canonical id (vulnDetail found=false) or the file name is not
// "<vulnerability id>.png" (a GHSA id that is only an alias of a CVE is a
// 404: the card is the CVE's); a non-canonical id redirects like the page does.
func (u *UI) ogVuln(w http.ResponseWriter, r *http.Request) {
	raw, isPNG := strings.CutSuffix(r.PathValue("file"), cardExt)
	id, ok := site.ParseVulnID(raw)
	if !isPNG || !ok {
		u.notFound(w, r, u.locales.Primary())
		return
	}
	if raw != id {
		to := cardPrefix + id + cardExt
		if r.URL.RawQuery != "" {
			to += "?" + r.URL.RawQuery
		}
		http.Redirect(w, r, to, http.StatusMovedPermanently)
		return
	}
	v, found, err := u.vulnDetail(r.Context(), id)
	if err != nil {
		u.fail(w, r, u.locales.Primary(), err)
		return
	}
	if !found {
		u.notFound(w, r, u.locales.Primary())
		return
	}
	c := cardFor(v)
	if r.URL.Query().Get(cardAddrParam) == "1" {
		c.Address = u.cardAddress(id)
	}
	key := c.Key()
	ttl := cardCacheTTL
	if u.opts.CacheTTL < 0 { // caching disabled
		ttl = u.opts.CacheTTL
	}
	got, _, err := u.srv.Cache.Get(r.Context(), "ogcard|"+id+"|"+key, ttl, func(context.Context) (any, error) {
		return ogcard.Render(c)
	})
	if err != nil {
		u.fail(w, r, u.locales.Primary(), err)
		return
	}
	body := got.([]byte)
	h := w.Header()
	h.Set("Content-Type", "image/png")
	h.Set("X-Content-Type-Options", "nosniff")
	// The URL the page links (?v= the current key) changes whenever the
	// picture does, so it may be kept for a day; any other URL briefly.
	if r.URL.Query().Get("v") == key {
		h.Set("Cache-Control", "public, max-age=86400")
	} else {
		h.Set("Cache-Control", "public, max-age=300")
	}
	etag := `"` + key + `"`
	h.Set("ETag", etag)
	if etagMatch(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}
