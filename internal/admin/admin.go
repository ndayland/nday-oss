// Package admin is the staff back office of nday (docs/admin.md): the
// access rules, the read-only queries behind the /admin pages (rendered by
// internal/webui) and the JSON action endpoints under /api/admin/.
//
// Access (enforced on the server for every page and endpoint; role and
// status are re-read from the database on every request through the
// session lookup of internal/auth):
//
//   - staff = role moderator or admin, active (not suspended), on the public
//     host. The API host never routes here (web.Server.Handle routes).
//   - pages: signed out -> 302 to the localized sign-in page; signed in but
//     not staff (and any request on another host) -> the site's ordinary
//     404 page; moderators see the moderation module and a limited user
//     view only.
//   - /api/admin/*: admin only; POST, same origin, X-CSRF-Token, JSON
//     bodies, per-user rate limit, and a recent sign-in (403
//     reauth_required). Nobody acts on their own account, and an admin is
//     never the target of a web action.
//
// Every response of a page or endpoint is Cache-Control: no-store with
// X-Robots-Tag: noindex, nofollow (forced when the header is written), and
// nothing here goes through the server's shared cache.
//
// Pools: page reads use ReadDB (the site's read-only pool); the user
// actions write through AuthDB (the auth pool); moderation actions are the
// discussion endpoints (/api/discuss/comment/{id}/hide|unhide,
// /api/mod/reports/{id}/resolve) on the discussion pool. Every action writes
// its audit row (internal/audit) in its own transaction.
package admin

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/dbpool"
	"nday.land/nday/internal/settings"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/stats"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/xlookup"
)

// Pool describes a database pool for the system page.
type Pool struct {
	Name  string
	Size  int
	Stats func() dbpool.Stats // nil: size only
}

// Options for New.
type Options struct {
	// Auth is the sign-in service (required): sessions, CSRF, roles.
	Auth *auth.Service
	// AuthDB is the auth service's writable pool: the user actions.
	AuthDB auth.ConnSource
	// ReadDB is a read-only pool for every page query (`nday serve` passes
	// the site pool, default_transaction_read_only=on).
	ReadDB auth.ConnSource
	// Site reads the collectors and state for the system page (same pool).
	Site *site.Store
	// Discussions: the discussion endpoints are mounted, so the moderation
	// module can act (without them it is read-only).
	Discussions bool
	// LogDir is NDAY_LOG_DIR ("" = not configured): the system page reads
	// today's and yesterday's error-YYYY-MM-DD.log from it.
	LogDir string
	// Pools are shown on the system page.
	Pools []Pool
	// XLookup resolves X handles to user ids when an account is added or
	// imported on /admin/x (nil or without a token: lookup unavailable;
	// `nday serve` builds it from NDAY_X_BEARER_TOKEN, never with another
	// base URL).
	XLookup *xlookup.Client
	// Settings applies database settings to the running process (the
	// settings pages; nil: not available). `nday serve` passes its
	// implementation (internal/cli).
	Settings settings.Runtime
	// Location is the server's local zone: statistics days and log files
	// are local calendar days (default time.Local).
	Location *time.Location
	Logger   *slog.Logger
	Now      func() time.Time
	// Started is the process start time (default: New's call time).
	Started time.Time
	// ActionLimit limits /api/admin/* per user (default burst 30, then 1
	// per 2 s); PageLimit limits page views per user (default burst 120,
	// then 4 per second).
	ActionLimit, PageLimit *auth.RateLimiter
}

// Service is the back office.
type Service struct {
	o     Options
	auth  *auth.Service
	read  *auth.Store // users etc. through ReadDB
	write *auth.Store // user actions through AuthDB
	stats *stats.Reader
	log   *slog.Logger
	now   func() time.Time
	loc   *time.Location
	// xl is the X user lookup in force (Options.XLookup, then SetXLookup).
	xl atomic.Pointer[xlookup.Client]
}

// New builds the service.
func New(o Options) (*Service, error) {
	if o.Auth == nil || o.AuthDB == nil || o.ReadDB == nil {
		return nil, errors.New("admin: auth service and both pools are required")
	}
	s := &Service{o: o, auth: o.Auth, log: o.Logger, now: o.Now, loc: o.Location}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.loc == nil {
		s.loc = time.Local
	}
	if s.o.Started.IsZero() {
		s.o.Started = s.now()
	}
	if s.o.ActionLimit == nil {
		s.o.ActionLimit = auth.NewRateLimiter(30, 2*time.Second)
	}
	if s.o.PageLimit == nil {
		s.o.PageLimit = auth.NewRateLimiter(120, 250*time.Millisecond)
	}
	s.read = &auth.Store{DB: o.ReadDB, Now: s.now}
	s.write = &auth.Store{DB: o.AuthDB, Now: s.now}
	s.stats = stats.NewReader(o.ReadDB)
	s.xl.Store(o.XLookup)
	return s, nil
}

// xLookup is the X user lookup in force (nil: none).
func (s *Service) xLookup() *xlookup.Client { return s.xl.Load() }

// SetXLookup replaces the X user lookup (nil turns it off), e.g. after
// NDAY_X_BEARER_TOKEN was set, changed or cleared in the database settings.
// Requests already looking up finish with the previous client.
func (s *Service) SetXLookup(c *xlookup.Client) { s.xl.Store(c) }

// Settings is Options.Settings (nil: database settings cannot be applied
// by this process).
func (s *Service) Settings() settings.Runtime { return s.o.Settings }

// Discussions reports whether moderation actions are available.
func (s *Service) Discussions() bool { return s.o.Discussions }

// Location is the zone of statistics days.
func (s *Service) Location() *time.Location { return s.loc }

// Now is the clock.
func (s *Service) Now() time.Time { return s.now() }

// ---- access ----

// Level is what a page or endpoint requires.
type Level int

const (
	// Staff: moderators and admins (the moderation module, the limited
	// user view).
	Staff Level = iota
	// AdminOnly: admins.
	AdminOnly
)

// Decision is the outcome of the access check of a page.
type Decision int

const (
	Allow  Decision = iota // render
	SignIn                 // 302 to the sign-in page
	Hidden                 // the ordinary 404 page
)

// IsStaff: role moderator or admin and not suspended.
func (s *Service) IsStaff(u *auth.User) bool {
	return u != nil && u.HasRole(auth.RoleModerator) && u.EffectiveStatus(s.auth.Now()) == auth.StatusActive
}

// IsAdmin: an active admin.
func (s *Service) IsAdmin(u *auth.User) bool { return s.IsStaff(u) && u.Role == auth.RoleAdmin }

// Decide is the access check of a page request that went through Page.
func (s *Service) Decide(r *http.Request, lvl Level) (Decision, *auth.User) {
	if !s.auth.PublicHost(r.Host) {
		return Hidden, nil
	}
	u := auth.CurrentUser(r)
	switch {
	case u == nil:
		return SignIn, nil
	case !s.IsStaff(u), lvl == AdminOnly && u.Role != auth.RoleAdmin:
		return Hidden, u
	}
	return Allow, u
}

// PageAllowed takes a page-view token for u (false: 429).
func (s *Service) PageAllowed(u *auth.User) bool {
	ok, _ := s.o.PageLimit.Allow(u.ID)
	return ok
}

// Page wraps a page handler: every response is forced to no-store and
// noindex (whatever the handler sets), conditional request headers are
// dropped (no 304), and the session is loaded through auth.Load — only on
// the public host (any other host gets nothing from the cookie; Decide
// answers Hidden there).
func (s *Service) Page(next http.Handler) http.Handler {
	loaded := s.auth.Load(next)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pw := &personal{ResponseWriter: w}
		defer pw.onPanic()
		r = dropConditional(r)
		if !s.auth.PublicHost(r.Host) {
			next.ServeHTTP(pw, r)
			return
		}
		loaded.ServeHTTP(pw, r)
	})
}

// personal forces the headers of every back-office response when the
// header is written: Cache-Control no-store, X-Robots-Tag noindex,
// nofollow, Vary: Cookie, and no validators or CDN cache directives.
type personal struct {
	http.ResponseWriter
	done bool
}

func (w *personal) apply() {
	h := w.Header()
	h.Set("Cache-Control", web.CacheNever)
	h.Set("X-Robots-Tag", "noindex, nofollow")
	for _, k := range []string{"ETag", "Last-Modified", "Expires", "CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Surrogate-Control"} {
		h.Del(k)
	}
	for _, v := range h.Values("Vary") {
		for _, t := range strings.Split(v, ",") {
			if t = strings.TrimSpace(t); strings.EqualFold(t, "Cookie") || t == "*" {
				return
			}
		}
	}
	h.Add("Vary", "Cookie")
}

func (w *personal) WriteHeader(code int) {
	if !w.done {
		w.apply()
		w.done = code >= 200
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *personal) Write(b []byte) (int, error) {
	if !w.done {
		w.apply()
		w.done = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *personal) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w *personal) onPanic() {
	if p := recover(); p != nil {
		if !w.done {
			w.apply()
		}
		panic(p)
	}
}

func dropConditional(r *http.Request) *http.Request {
	if r.Header.Get("If-None-Match") == "" && r.Header.Get("If-Modified-Since") == "" {
		return r
	}
	r = r.Clone(r.Context())
	r.Header.Del("If-None-Match")
	r.Header.Del("If-Modified-Since")
	return r
}
