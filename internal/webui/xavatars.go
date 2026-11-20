package webui

import (
	"net/http"
	"strconv"

	"nday.land/nday/internal/xavatar"
)

// X avatars (docs/xposts.md "Author profiles and avatars"): the researcher
// section shows each author's X picture. The bytes are fetched by `nday
// site-icons` (internal/xavatar) in the background and served from our own
// origin at /avatar/<hash>, so a reader's browser never contacts X or
// twimg and the page CSP (img-src 'self' data:) stays as it is. The path
// is the image's content hash, not the X user id: the outline is public
// and never names the numeric id.

const (
	avatarPrefix = "/avatar/"
	// avatarCache: the path is the content hash, so the bytes behind it
	// never change; a week rather than a year so a disabled account's
	// picture ages out of caches.
	avatarCache = "public, max-age=604800, immutable"
	// avatarCSP: an image needs nothing (like iconCSP).
	avatarCSP = "default-src 'none'; sandbox"
)

// xAvatar serves GET /avatar/{hash}: the stored avatar with that content
// hash, as stored (no fetch, no redirect: not a proxy), with the content
// type sniffed when it was stored (never SVG: xavatar.Validate accepts
// PNG, JPEG, WebP and GIF only), and only of an author the public outline
// shows (a post of theirs in some vulnerability page's outline), so the
// route tells nothing about the allowlist the pages do not. Anything else,
// a disabled account's picture included, is a 404. The row is read straight from the store
// (indexed), not through the shared page cache.
func (u *UI) xAvatar(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("hash")
	h := w.Header()
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", avatarCSP)
	h.Set("Cross-Origin-Resource-Policy", "same-origin")
	var a *xavatar.Avatar
	if xavatar.HashRe.MatchString(key) {
		var err error
		a, err = u.srv.Store.XAvatar(r.Context(), key)
		if err != nil {
			u.srv.Log.Warn("x avatar load failed", "err", err)
			h.Set("Cache-Control", "no-store")
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
	}
	if a == nil || a.Hash != key || !avatarType(a.ContentType) {
		h.Set("Cache-Control", iconCacheShort)
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	h.Set("Content-Type", a.ContentType)
	h.Set("Cache-Control", avatarCache)
	etag := `"` + a.Hash + `"`
	h.Set("ETag", etag)
	if etagMatch(r.Header.Get("If-None-Match"), etag) {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	h.Set("Content-Length", strconv.Itoa(len(a.Image)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		_, _ = w.Write(a.Image)
	}
}

// avatarType: the raster types xavatar stores; anything else (a row
// written by hand, say) is never served.
func avatarType(ct string) bool {
	switch ct {
	case "image/png", "image/jpeg", "image/webp", "image/gif":
		return true
	}
	return false
}
