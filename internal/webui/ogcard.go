package webui

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/ogcard"
	"nday.land/nday/internal/site"
)

// Share cards: GET /og/vuln/{CVE}.png is the vulnerability's 1200x630 Open
// Graph image (internal/ogcard), one per CVE for every locale. The detail
// page links it as og:image with ?v=<ogcard.Card.Key>, so a change of what
// the card shows yields a new URL and social caches fetch it again.

const (
	cardPrefix   = "/og/vuln/"
	cardExt      = ".png"
	cardCacheTTL = 10 * time.Minute // rendered PNGs, keyed by content
	cardProducts = 6                // pairs passed to the card (as the detail page's product line)
)

// cardFor is the card input of a vulnerability: the upstream English title
// (never title_zh), the affected products, the strip slots as BuildStrip
// classifies them and the detail page's T+ figure.
func cardFor(v *site.VulnDetail) ogcard.Card {
	c := ogcard.Card{CVE: v.CVEID, ProductTotal: len(v.Products), Rejected: v.IsRejected}
	if v.Title != nil {
		c.Title = strings.TrimSpace(*v.Title)
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
	return c
}

// cardPath is the site-relative URL of c's card.
func cardPath(c ogcard.Card) string {
	return cardPrefix + c.CVE + cardExt + "?v=" + c.Key()
}

// ogVuln serves a share card. It answers 404 exactly when the detail page
// does for a canonical id (vulnDetail found=false) or the file name is not
// "<CVE id>.png"; a non-canonical id redirects like the page does.
func (u *UI) ogVuln(w http.ResponseWriter, r *http.Request) {
	raw, isPNG := strings.CutSuffix(r.PathValue("file"), cardExt)
	id, ok := site.ParseCVEID(raw)
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
