package siteicon

import (
	"context"
	"errors"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"nday.land/nday/internal/pagefetch"
	"nday.land/nday/internal/webpages"
)

// Fetch limits.
const (
	// RequestTimeout bounds one request, redirects included.
	RequestTimeout = 10 * time.Second
	// HostTimeout bounds all requests for one host (three requests of a
	// responsive site take well under it; a slow one is cut off).
	HostTimeout = 15 * time.Second
	// MaxLinkTries is the number of <link rel=icon> candidates of a home
	// page that are requested at most.
	MaxLinkTries = 3
	// UserAgent of every request: the one of the other third-party
	// fetchers (internal/webpages).
	UserAgent = webpages.UserAgent
)

// Outcome statuses (site_icon.status).
const (
	StatusOK    = "ok"
	StatusNone  = "none"
	StatusError = "error"
)

// Fetched is the result of fetching one host's icon.
type Fetched struct {
	Status      string // StatusOK, StatusNone or StatusError
	ContentType string // StatusOK: the validated type
	Image       []byte // StatusOK: the validated bytes
	SourceURL   string // StatusOK: the URL the bytes came from (after redirects)
	Why         string // StatusNone / StatusError: a short reason, for logs and site_icon.last_error
	Requests    int
	Refused     int // requests refused by the URL rules or the address guard
}

// Fetcher fetches icons. Both clients are pagefetch clients (URL rules,
// connect-time address guard on every connection, redirects re-checked)
// with HTTPSOnly set, so a redirect to http or to a non-public address is
// refused without a connection.
type Fetcher struct {
	icon *pagefetch.Client // image requests: any 200 body read, capped at MaxBytes
	page *pagefetch.Client // home pages: HTML bodies, capped at pagefetch.MaxBody
}

// NewFetcher returns the production Fetcher. base carries the test hooks
// of pagefetch.Options (DialControl, RewriteAddr, RootCAs); its other
// fields are ignored.
func NewFetcher(base pagefetch.Options) *Fetcher {
	o := pagefetch.Options{UserAgent: UserAgent, HTTPSOnly: true, Timeout: RequestTimeout,
		DialControl: base.DialControl, RewriteAddr: base.RewriteAddr, RootCAs: base.RootCAs}
	ic := o
	ic.Accept = "image/webp,image/png,image/x-icon,image/*;q=0.8"
	ic.AnyBody, ic.MaxBody = true, MaxBytes
	po := o
	po.Accept = "text/html"
	return &Fetcher{icon: pagefetch.New(ic), page: pagefetch.New(po)}
}

// Fetch finds host's icon: https://<host>/favicon.ico when that is a valid
// icon (Validate), else the first candidate of the home page
// (https://<host>/) whose <link rel="icon" | "shortcut icon" |
// "apple-touch-icon"> is a valid icon (relative URLs resolved against the
// page's final URL; another host is fine, every request goes through the
// same guarded https-only client), at most MaxLinkTries candidates. A
// transport error, 5xx, 408 or 429 on the first request or the home page is
// StatusError (retried with back-off); no valid icon otherwise is
// StatusNone. The context should carry a deadline (Run gives HostTimeout).
func (f *Fetcher) Fetch(ctx context.Context, host string) Fetched {
	var out Fetched
	if !ValidHost(host) {
		out.Status, out.Why = StatusNone, "invalid host"
		return out
	}
	base := "https://" + host + "/"
	ok, transient, why := f.tryIcon(ctx, &out, base+"favicon.ico")
	if ok {
		return out
	}
	if ctx.Err() != nil {
		out.Status, out.Why = StatusError, "time budget"
		return out
	}
	if transient {
		out.Status, out.Why = StatusError, "favicon.ico: "+why
		return out
	}
	out.Requests++
	p, err := f.page.Get(ctx, base)
	switch {
	case err != nil && errors.Is(err, pagefetch.ErrRefused):
		out.Refused++
		out.Status, out.Why = StatusNone, "home page refused"
		return out
	case err != nil:
		out.Status, out.Why = StatusError, "home page: transport error"
		return out
	case transientStatus(p.Status):
		out.Status, out.Why = StatusError, "home page: HTTP "+http.StatusText(p.Status)
		return out
	case !p.IsHTML():
		out.Status, out.Why = StatusNone, "favicon.ico: "+why+"; no HTML home page"
		return out
	}
	cands := IconLinks(p.Body, p.URL)
	for i, c := range cands {
		if i == MaxLinkTries || ctx.Err() != nil {
			break
		}
		if ok, _, _ := f.tryIcon(ctx, &out, c); ok {
			return out
		}
	}
	out.Status, out.Why = StatusNone, "favicon.ico: "+why+"; no usable link rel=icon"
	return out
}

// tryIcon requests one icon URL; ok when it is a valid icon (out filled
// in), transient when the request failed in a way worth retrying later.
func (f *Fetcher) tryIcon(ctx context.Context, out *Fetched, u string) (ok, transient bool, why string) {
	out.Requests++
	p, err := f.icon.Get(ctx, u)
	switch {
	case err != nil && errors.Is(err, pagefetch.ErrRefused):
		out.Refused++
		return false, false, "refused"
	case err != nil:
		return false, true, "transport error"
	case transientStatus(p.Status):
		return false, true, "HTTP " + http.StatusText(p.Status)
	case p.Status != http.StatusOK:
		return false, false, "HTTP " + http.StatusText(p.Status)
	case p.Truncated:
		return false, false, "too large"
	}
	ct, err := Validate(p.Body)
	if err != nil {
		return false, false, "not a usable image"
	}
	out.Status, out.ContentType, out.Image, out.SourceURL = StatusOK, ct, p.Body, p.URL
	return true, false, ""
}

func transientStatus(s int) bool {
	return s >= 500 || s == http.StatusTooManyRequests || s == http.StatusRequestTimeout
}

var (
	linkTagRe = regexp.MustCompile(`(?is)<link\b[^>]*>`)
	attrRe    = regexp.MustCompile(`(?s)([a-zA-Z_:][-a-zA-Z0-9_:.]*)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s"'=<>` + "`" + `]+))`)
)

// IconLinks returns the icon candidates of an HTML document fetched from
// pageURL, in document order: the href of every <link> whose rel has the
// token "icon" ("icon", "shortcut icon") or is "apple-touch-icon" /
// "apple-touch-icon-precomposed", resolved against pageURL, https only,
// without SVG (type image/svg+xml or a .svg path), duplicates dropped.
func IconLinks(doc []byte, pageURL string) []string {
	base, err := url.Parse(pageURL)
	if err != nil {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	for _, tag := range linkTagRe.FindAll(doc, -1) {
		attrs := map[string]string{}
		for _, m := range attrRe.FindAllSubmatch(tag[5:], -1) {
			k := strings.ToLower(string(m[1]))
			if _, dup := attrs[k]; dup {
				continue
			}
			attrs[k] = html.UnescapeString(string(m[2]) + string(m[3]) + string(m[4]))
		}
		if !iconRel(attrs["rel"]) || strings.Contains(strings.ToLower(attrs["type"]), "svg") {
			continue
		}
		href := strings.TrimSpace(attrs["href"])
		if href == "" {
			continue
		}
		ref, err := url.Parse(href)
		if err != nil {
			continue
		}
		abs := base.ResolveReference(ref)
		abs.Fragment = ""
		if abs.Scheme != "https" || strings.HasSuffix(strings.ToLower(abs.Path), ".svg") {
			continue
		}
		s := abs.String()
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func iconRel(rel string) bool {
	for _, t := range strings.Fields(strings.ToLower(rel)) {
		switch t {
		case "icon", "apple-touch-icon", "apple-touch-icon-precomposed":
			return true
		}
	}
	return false
}
