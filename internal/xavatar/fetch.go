package xavatar

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"nday.land/nday/internal/pagefetch"
	"nday.land/nday/internal/siteicon"
)

// Fetch limits.
const (
	// RequestTimeout bounds one avatar request, redirects included.
	RequestTimeout = 10 * time.Second
	// MaxBytes is the largest avatar stored (and the body cap of a request;
	// the x_user.avatar_image CHECK).
	MaxBytes = 256 << 10
	// MaxDim is the largest width or height accepted, in pixels (X's
	// "_400x400" variant is the biggest one it links).
	MaxDim = 1024
)

// limits are the image rules: PNG, JPEG, WebP or GIF by magic bytes and
// header decode (siteicon.ValidateImage), never ICO, never SVG.
var limits = siteicon.Limits{MaxBytes: MaxBytes, MaxDim: MaxDim}

// Validate decides whether b may be stored and served as an avatar and
// returns its content type, from the bytes alone.
func Validate(b []byte) (string, error) { return siteicon.ValidateImage(b, limits) }

// Outcome statuses (x_user.avatar_status): the ones of site icons.
const (
	StatusOK    = siteicon.StatusOK
	StatusNone  = siteicon.StatusNone
	StatusError = siteicon.StatusError
)

// Fetched is the result of fetching one avatar.
type Fetched struct {
	Status      string // StatusOK, StatusNone or StatusError
	ContentType string // StatusOK: the sniffed type
	Image       []byte // StatusOK: the validated bytes
	Why         string // StatusNone / StatusError: a short reason
	Refused     bool   // the URL rules, the redirect rule or the address guard refused a request
}

// Fetcher fetches avatars through a pagefetch client: https only, the
// connect-time address guard on every connection (no private, loopback or
// link-local address, checked after DNS), at most pagefetch.MaxRedirects
// redirects and each one only to AvatarHost (SameHost), a short timeout and
// a MaxBytes body cap.
type Fetcher struct {
	c *pagefetch.Client
}

// NewFetcher returns the production Fetcher. base carries the test hooks
// of pagefetch.Options (DialControl, RewriteAddr, RootCAs); its other
// fields are ignored.
func NewFetcher(base pagefetch.Options) *Fetcher {
	o := pagefetch.Options{UserAgent: siteicon.UserAgent, HTTPSOnly: true, Timeout: RequestTimeout,
		Accept: "image/webp,image/png,image/jpeg,image/gif;q=0.9", AnyBody: true, MaxBody: MaxBytes,
		CheckRedirect: func(u *url.URL) error {
			if !SameHost(u) {
				return fmt.Errorf("%w: redirect off %s", pagefetch.ErrRefused, AvatarHost)
			}
			return nil
		},
		DialControl: base.DialControl, RewriteAddr: base.RewriteAddr, RootCAs: base.RootCAs}
	return &Fetcher{c: pagefetch.New(o)}
}

// Fetch gets the avatar at raw, which must pass AvatarURL (else StatusNone
// without a request). A transport error, 5xx, 408 or 429 is StatusError
// (retried with back-off); a refusal, another status, a body over
// MaxBytes or bytes that are not a usable image (whatever the
// Content-Type header says) is StatusNone.
func (f *Fetcher) Fetch(ctx context.Context, raw string) Fetched {
	u, ok := AvatarURL(raw)
	if !ok {
		return Fetched{Status: StatusNone, Why: "not an avatar URL"}
	}
	p, err := f.c.Get(ctx, u)
	switch {
	case err != nil && errors.Is(err, pagefetch.ErrRefused):
		return Fetched{Status: StatusNone, Why: "refused", Refused: true}
	case err != nil:
		return Fetched{Status: StatusError, Why: "transport error"}
	case p.Status >= 500 || p.Status == http.StatusTooManyRequests || p.Status == http.StatusRequestTimeout:
		return Fetched{Status: StatusError, Why: "HTTP " + http.StatusText(p.Status)}
	case p.Status != http.StatusOK:
		return Fetched{Status: StatusNone, Why: "HTTP " + http.StatusText(p.Status)}
	case p.Truncated:
		return Fetched{Status: StatusNone, Why: "too large"}
	}
	ct, err := Validate(p.Body)
	if err != nil {
		return Fetched{Status: StatusNone, Why: "not a usable image"}
	}
	return Fetched{Status: StatusOK, ContentType: ct, Image: p.Body}
}
