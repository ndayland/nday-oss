package discuss

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"nday.land/nday/internal/audit"
	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/webui/i18n"
)

// Options for New.
type Options struct {
	Store *Store
	// Auth is the sign-in service (required): sessions, CSRF, roles, terms.
	Auth   *auth.Service
	Logger *slog.Logger
	// Now is the clock of the rate limiters and permission checks (tests);
	// the Store has its own.
	Now    func() time.Time
	Limits *Limits // nil: DefaultLimits
	// Locales are the enabled locale tags a comment may be posted from
	// (nil: the enabled locales of internal/webui/i18n).
	Locales []string
	// CVEPath builds the vulnerability page path for a locale tag and a
	// canonical CVE id (nil: the i18n locale prefix + "/vuln/" + id).
	CVEPath func(locale, cve string) string
}

// Service is the discussion HTTP surface and the page-facing read API.
type Service struct {
	store   *Store
	auth    *auth.Service
	log     *slog.Logger
	now     func() time.Time
	locales map[string]string // lower-case tag -> tag
	primary string
	cvePath func(locale, cve string) string

	lims  atomic.Pointer[limState] // limits and limiters in force (limits.go)
	limMu sync.Mutex               // serialises SetLimits

	hRead, hCreate, hEdit, hDelete, hReport, hHide, hUnhide, hReports, hResolve, hRecent, hRevisions http.Handler

	rlWarn warnAggregate
}

// New builds the service.
func New(opt Options) (*Service, error) {
	if opt.Store == nil || opt.Auth == nil {
		return nil, errors.New("discuss: store and auth service are required")
	}
	s := &Service{store: opt.Store, auth: opt.Auth, log: opt.Logger, now: opt.Now, cvePath: opt.CVEPath,
		locales: map[string]string{}}
	if s.log == nil {
		s.log = slog.Default()
	}
	if s.now == nil {
		s.now = time.Now
	}
	lim := DefaultLimits()
	if opt.Limits != nil {
		lim = *opt.Limits
	}
	tags := opt.Locales
	if tags == nil || s.cvePath == nil {
		set, err := i18n.Default()
		if err != nil {
			return nil, fmt.Errorf("discuss: locales: %w", err)
		}
		if tags == nil {
			for _, l := range set.Enabled {
				tags = append(tags, l.Tag)
			}
		}
		if s.cvePath == nil {
			s.cvePath = func(locale, cve string) string {
				l := set.ByTag(locale)
				if l == nil || !l.Enabled() {
					l = set.Primary()
				}
				return l.Path("/vuln/" + cve)
			}
		}
	}
	if len(tags) == 0 {
		return nil, errors.New("discuss: no locale enabled")
	}
	for _, t := range tags {
		s.locales[strings.ToLower(t)] = t
	}
	s.primary = tags[0]
	s.lims.Store(s.newLimState(lim, nil))

	a := s.auth
	mod := a.RequireRole(auth.RoleModerator)
	s.hRead = a.Load(http.HandlerFunc(s.read))
	s.hCreate = a.RequireActive(http.HandlerFunc(s.create))
	s.hEdit = a.RequireActive(http.HandlerFunc(s.edit))
	s.hDelete = a.RequireUser(http.HandlerFunc(s.delete)) // suspended users may delete their own comments
	s.hReport = a.RequireActive(http.HandlerFunc(s.report))
	s.hHide = mod(http.HandlerFunc(s.hide))
	s.hUnhide = mod(http.HandlerFunc(s.unhide))
	s.hReports = mod(http.HandlerFunc(s.reports))
	s.hResolve = mod(http.HandlerFunc(s.resolve))
	s.hRecent = mod(http.HandlerFunc(s.recent))
	s.hRevisions = mod(http.HandlerFunc(s.revisions))
	return s, nil
}

// Register mounts /api/discuss/ and /api/mod/ on the site host (Handle
// routes are never reachable on the API host).
func (s *Service) Register(srv *web.Server) {
	srv.Handle("/api/discuss/", s)
	srv.Handle("/api/mod/", s)
}

// Limits returns the limits in force.
func (s *Service) Limits() Limits { return s.cur().lim }

// ---- page-facing read API ----

// Version changes whenever what a page shows of cve's discussion (the
// signed-out Outline, or any comment a member may see) may change (see
// Store.Version); use it as the page cache key.
func (s *Service) Version(ctx context.Context, cve string) (string, error) {
	return s.store.Version(ctx, cve)
}

// GuestRead reports whether signed-out visitors may read the comments
// (Limits.GuestRead, NDAY_DISCUSS_GUEST_READ); when false they get only
// the Outline. Pages use it to choose what to say to signed-out visitors.
func (s *Service) GuestRead() bool { return s.cur().lim.GuestRead }

// cost is what a comment adds to a page's byte budget.
func cost(c *Comment) int {
	n := len(c.BodyHTML)
	if c.Body != nil {
		n += len(*c.Body)
	}
	return n
}

var startCursor = &Cursor{ID: nilUUID} // before any reply

// cutReplies adds rendered replies to top until the budget (used so far
// included) is exhausted, at least min of them; when some are left out it
// marks the thread truncated with the cursor to continue from.
func cutReplies(top *Comment, rows []*Row, rendered []Comment, used, min int) {
	for k, rc := range rendered {
		if k >= min && used+cost(&rc) > PageMaxHTMLBytes {
			cur := startCursor
			if k > 0 {
				cur = &Cursor{At: rows[k-1].CreatedAt, ID: rows[k-1].ID}
			}
			c := encodeCursor(cur)
			top.RepliesTruncated, top.RepliesNextCursor = true, &c
			return
		}
		used += cost(&rc)
		top.Replies = append(top.Replies, rc)
	}
}

func buildThread(top *Row, reps []*Row, v *Viewer, link LinkFunc) Comment {
	c := view(top, v, link, false)
	rendered := make([]Comment, len(reps))
	for k, r := range reps {
		rendered[k] = view(r, v, link, false)
	}
	cutReplies(&c, reps, rendered, cost(&c), 1) // at least one reply per call: progress
	return c
}

// buildPage renders a page within PageMaxHTMLBytes of body HTML (plus
// source bodies when present): whole threads while they fit, always at
// least the first one; a first thread that alone exceeds the budget is cut
// at a reply boundary (RepliesTruncated, RepliesNextCursor). It returns the
// comments and the cursor of the next page (nil = none).
func buildPage(p *Page, v *Viewer, link LinkFunc) ([]Comment, *Cursor) {
	out := make([]Comment, 0, len(p.Top))
	used := 0
	for i, t := range p.Top {
		c := view(t, v, link, false)
		reps := p.Replies[t.ID]
		rendered := make([]Comment, len(reps))
		size := cost(&c)
		for k, r := range reps {
			rendered[k] = view(r, v, link, false)
			size += cost(&rendered[k])
		}
		switch {
		case used+size <= PageMaxHTMLBytes:
			c.Replies = append(c.Replies, rendered...)
			out = append(out, c)
			used += size
		case i > 0:
			return out, &Cursor{At: p.Top[i-1].CreatedAt, ID: p.Top[i-1].ID}
		default:
			cutReplies(&c, reps, rendered, cost(&c), 0)
			out = append(out, c)
			if len(p.Top) > 1 || p.Next != nil {
				return out, &Cursor{At: t.CreatedAt, ID: t.ID}
			}
			return out, nil
		}
	}
	return out, p.Next
}

// ---- cursors ----

func encodeCursor(c *Cursor) string {
	if c == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(c.At.UnixMicro(), 10) + "." + c.ID))
}

var uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// ValidID reports whether s is a UUID in canonical text form (any case).
func ValidID(s string) bool { return uuidRe.MatchString(s) }

// ValidCursor reports whether s is a well-formed stream cursor (a
// next_cursor/NextCursor value): StreamPage accepts exactly these (and "").
// Read-only helper for pages that take a cursor from a URL.
func ValidCursor(s string) bool {
	_, ok := decodeCursor(s)
	return ok
}

func decodeCursor(s string) (*Cursor, bool) {
	if len(s) > 100 {
		return nil, false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, false
	}
	at, id, ok := strings.Cut(string(b), ".")
	us, err := strconv.ParseInt(at, 10, 64)
	if !ok || err != nil || !ValidID(id) {
		return nil, false
	}
	return &Cursor{At: time.UnixMicro(us).UTC(), ID: strings.ToLower(id)}, true
}

// ---- HTTP ----

// noStore forces Cache-Control: no-store (and drops validators and CDN
// cache headers) on every discussion response, whatever a handler sets,
// with Vary: Cookie: the responses depend on the caller.
type noStore struct {
	http.ResponseWriter
	done bool
}

func (w *noStore) apply() {
	if w.done {
		return
	}
	w.done = true
	h := w.Header()
	h.Set("Cache-Control", web.CacheNever)
	for _, k := range []string{"ETag", "Last-Modified", "Expires", "CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Surrogate-Control"} {
		h.Del(k)
	}
	if !slices.ContainsFunc(h.Values("Vary"), func(v string) bool { return strings.Contains(strings.ToLower(v), "cookie") }) {
		h.Add("Vary", "Cookie")
	}
}

func (w *noStore) WriteHeader(code int) {
	if code >= 200 {
		w.apply()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *noStore) Write(b []byte) (int, error) {
	w.apply()
	return w.ResponseWriter.Write(b)
}

func (w *noStore) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ServeHTTP routes /api/discuss/* and /api/mod/*.
//
//	GET  /api/discuss/{cve}                      public stream (+ per-caller fields)
//	POST /api/discuss/{cve}                      create
//	POST /api/discuss/comment/{id}/edit|delete|report|hide|unhide
//	GET  /api/mod/reports?state=open|resolved
//	POST /api/mod/reports/{id}/resolve
//	GET  /api/mod/recent
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	nw := &noStore{ResponseWriter: w}
	w = nw
	w.Header().Set("Cache-Control", web.CacheNever)
	defer func() {
		if p := recover(); p != nil {
			nw.apply()
			panic(p)
		}
	}()
	// Only the public host (another zone pointed at
	// the origin cannot use these routes).
	if !s.auth.PublicHost(r.Host) {
		web.WriteError(w, http.StatusMisdirectedRequest, "wrong_host", "this host does not serve discussions", "")
		return
	}
	// moderation actions record the client in their audit row (docs/admin.md)
	r = r.WithContext(audit.WithClient(r.Context(), auth.ClientAddr(r), r.Header.Get("Cf-Ray")))
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	var h http.Handler
	method := http.MethodPost
	switch {
	case len(segs) == 3 && segs[1] == "discuss" && segs[2] != "comment":
		switch r.Method {
		case http.MethodGet:
			method, h = http.MethodGet, s.hRead
		default:
			h = s.hCreate
		}
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			w.Header().Set("Allow", "GET, POST")
			web.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET or POST", "")
			return
		}
	case len(segs) == 5 && segs[1] == "discuss" && segs[2] == "comment":
		h = map[string]http.Handler{"edit": s.hEdit, "delete": s.hDelete, "report": s.hReport, "hide": s.hHide,
			"unhide": s.hUnhide}[segs[4]]
	case len(segs) == 3 && segs[1] == "mod" && segs[2] == "reports":
		method, h = http.MethodGet, s.hReports
	case len(segs) == 5 && segs[1] == "mod" && segs[2] == "reports" && segs[4] == "resolve":
		h = s.hResolve
	case len(segs) == 3 && segs[1] == "mod" && segs[2] == "recent":
		method, h = http.MethodGet, s.hRecent
	case len(segs) == 5 && segs[1] == "mod" && segs[2] == "comment" && segs[4] == "revisions":
		method, h = http.MethodGet, s.hRevisions
	}
	if h == nil {
		web.WriteError(w, http.StatusNotFound, "not_found", "no such endpoint", "")
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		web.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use "+method, "")
		return
	}
	if method == http.MethodGet && segs[1] == "discuss" && s.limited(w, s.cur().readRL, auth.ClientAddr(r), "read") {
		return
	}
	h.ServeHTTP(w, r)
}

func (s *Service) viewer(u *auth.User) *Viewer {
	if u == nil {
		return nil
	}
	active := u.EffectiveStatus(s.now()) == auth.StatusActive
	return &Viewer{ID: u.ID, Active: active, HasHandle: u.Handle != nil, TermsOK: s.termsOK(u),
		Moderator: active && u.HasRole(auth.RoleModerator)}
}

func (s *Service) termsVersion() string { return s.auth.Config().TermsVersion }

func (s *Service) termsOK(u *auth.User) bool {
	v := s.termsVersion()
	return v == "" || (u.TermsVersion != nil && *u.TermsVersion == v)
}

// postRefused answers 403 handle_required / terms_required when the user
// may not write content (beyond what RequireActive checks).
func (s *Service) postRefused(w http.ResponseWriter, u *auth.User) bool {
	if u.Handle == nil {
		web.WriteError(w, http.StatusForbidden, "handle_required", "choose a public handle first (POST /account/handle)", "")
		return true
	}
	if !s.termsOK(u) {
		web.WriteError(w, http.StatusForbidden, "terms_required", "accept the current community rules first (POST /account/accept-terms)", s.termsVersion())
		return true
	}
	return false
}

func (s *Service) link(locale string) LinkFunc {
	return func(cve string) string { return s.cvePath(locale, cve) }
}

// locale canonicalises an enabled locale tag ("" when not enabled).
func (s *Service) locale(tag string) string { return s.locales[strings.ToLower(tag)] }

func pathCVE(w http.ResponseWriter, r *http.Request) (string, bool) {
	seg := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[2]
	cve, ok := site.ParseVulnID(seg)
	if !ok {
		web.WriteError(w, http.StatusBadRequest, "bad_cve", "not a vulnerability id", "cve")
	}
	return cve, ok
}

func pathID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[3]
	if !ValidID(id) {
		web.WriteError(w, http.StatusNotFound, "not_found", "no such comment", "")
		return "", false
	}
	return strings.ToLower(id), true
}

// readJSON decodes a JSON body (Content-Type application/json, at most
// MaxRequestBytes, no unknown fields, nothing after the value).
func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	mt, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if mt != "application/json" {
		web.WriteError(w, http.StatusUnsupportedMediaType, "bad_request", "Content-Type must be application/json", "")
		return false
	}
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, MaxRequestBytes))
	dec.DisallowUnknownFields()
	err := dec.Decode(v)
	if err == nil {
		if _, e := dec.Token(); e != io.EOF {
			err = errors.New("trailing data")
		}
	}
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			web.WriteError(w, http.StatusRequestEntityTooLarge, "too_large", fmt.Sprintf("request body over %d bytes", MaxRequestBytes), "")
		} else {
			web.WriteError(w, http.StatusBadRequest, "bad_request", "invalid JSON body", "")
		}
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := web.EncodeJSON(v)
	if err != nil {
		web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

func retryAfter(w http.ResponseWriter, d time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(d/time.Second)+1))
}

// limited takes a token for key from l; on refusal it answers 429.
func (s *Service) limited(w http.ResponseWriter, l *auth.RateLimiter, key, what string) bool {
	ok, wait := l.Allow(key)
	if ok {
		return false
	}
	retryAfter(w, wait)
	s.rlWarn.note(s.log, what)
	web.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests; try again later", "")
	return true
}

// fail maps a store error to the error response.
func (s *Service) fail(w http.ResponseWriter, op string, err error) {
	var le *LimitError
	switch {
	case errors.As(err, &le):
		retryAfter(w, le.RetryAfter)
		s.rlWarn.note(s.log, op+"_"+le.Code)
		msg := "too many requests; try again later"
		if le.Code == "daily_limit" {
			msg = "daily limit reached; try again later"
		}
		web.WriteError(w, http.StatusTooManyRequests, le.Code, msg, "")
	case errors.Is(err, ErrNotFound):
		web.WriteError(w, http.StatusNotFound, "not_found", err.Error(), "")
	case errors.Is(err, ErrNoVuln):
		web.WriteError(w, http.StatusNotFound, "not_found", err.Error(), "cve")
	case errors.Is(err, ErrNotAuthor):
		web.WriteError(w, http.StatusForbidden, "not_author", err.Error(), "")
	case errors.Is(err, ErrOwnComment):
		web.WriteError(w, http.StatusForbidden, "own_comment", err.Error(), "")
	case errors.Is(err, ErrWrongStatus), errors.Is(err, ErrReportClosed):
		web.WriteError(w, http.StatusConflict, "wrong_status", err.Error(), "")
	case errors.Is(err, ErrBadParent):
		web.WriteError(w, http.StatusBadRequest, "bad_parent", err.Error(), "parent_id")
	case errors.Is(err, ErrThreadFull):
		web.WriteError(w, http.StatusConflict, "thread_full", err.Error(), "parent_id")
	case errors.Is(err, ErrDuplicate):
		web.WriteError(w, http.StatusConflict, "duplicate", err.Error(), "body")
	case errors.Is(err, ErrBadPurpose):
		web.WriteError(w, http.StatusBadRequest, "bad_purpose", err.Error(), "purpose")
	default:
		s.log.Error("discuss: internal error", "op", op, "err", err)
		web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
	}
}

// ---- handlers ----

type viewerInfo struct {
	SignedIn     bool    `json:"signed_in"`
	Handle       *string `json:"handle"`
	Role         *string `json:"role"`
	CanPost      bool    `json:"can_post"`
	PostRefusal  *string `json:"post_refusal"`
	TermsVersion *string `json:"terms_version"`
	Links        bool    `json:"links"`
	Moderator    bool    `json:"moderator"`
}

type limitsInfo struct {
	MaxBodyChars int `json:"max_body_chars"`
	MaxReplies   int `json:"max_replies"`
	MaxNoteChars int `json:"max_note_chars"`
	MaxPageBytes int `json:"max_page_bytes"`
}

type streamResponse struct {
	CVE        string    `json:"cve"`
	Count      int       `json:"count"`
	Comments   []Comment `json:"comments"`
	NextCursor *string   `json:"next_cursor"`
	// Cursor: with ?c=, the page cursor of the page returned ("" = the
	// first page); absent otherwise.
	Cursor *string `json:"cursor,omitempty"`
	// Outline: with guest reading off (Limits.GuestRead), signed-out
	// callers get only the shape of the first page (Comments is then
	// empty; docs/discuss.md §4.1).
	Outline *Outline   `json:"outline,omitempty"`
	Viewer  viewerInfo `json:"viewer"`
	Limits  limitsInfo `json:"limits"`
}

// read: GET /api/discuss/{cve}?cursor=&limit=&locale=
func (s *Service) read(w http.ResponseWriter, r *http.Request) {
	cve, ok := pathCVE(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	var after *Cursor
	if c := q.Get("cursor"); c != "" {
		if after, ok = decodeCursor(c); !ok {
			web.WriteError(w, http.StatusBadRequest, "bad_cursor", "invalid cursor", "cursor")
			return
		}
	}
	limit := PageDefault
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > PageMax {
			web.WriteError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("limit must be 1..%d", PageMax), "limit")
			return
		}
		limit = n
	}
	loc := s.locale(q.Get("locale"))
	if loc == "" {
		loc = s.primary
	}
	u := auth.CurrentUser(r)
	cur := s.cur()
	// A signed-out reader of the comments takes a token from the guest
	// bucket too (the comment HTML costs more than the outline did).
	if u == nil && cur.lim.GuestRead && s.limited(w, cur.guestRL, auth.ClientAddr(r), "guest_read") {
		return
	}
	exists, err := s.store.VulnExists(r.Context(), cve)
	if err != nil {
		s.fail(w, "read", err)
		return
	}
	if !exists {
		web.WriteError(w, http.StatusNotFound, "not_found", "no such vulnerability", "cve")
		return
	}
	v := s.viewer(u)
	resp := streamResponse{CVE: cve,
		Limits: limitsInfo{MaxBodyChars: MaxBodyChars, MaxReplies: MaxReplies, MaxNoteChars: MaxNoteChars,
			MaxPageBytes: PageMaxHTMLBytes}}
	var next *Cursor
	if u == nil && !cur.lim.GuestRead {
		// Signed out with guest reading off: no bodies, no authors, no ids,
		// no times — the outline of the first page only, whatever the query
		// asked for. (With guest reading on, a signed-out caller is an
		// anonymous viewer below: v is nil, so view gives exactly what
		// every member sees — never body, moderation, can_* or reported —
		// and every read goes to the read-only pool.)
		p, err := s.store.Page(r.Context(), nil, cve, nil, PageDefault)
		if err != nil {
			s.fail(w, "read", err)
			return
		}
		resp.Outline = buildOutline(p)
		resp.Count, resp.Comments = p.Visible, []Comment{}
		if tv := s.termsVersion(); tv != "" {
			resp.Viewer.TermsVersion = &tv
		}
		refusal := "not_signed_in"
		resp.Viewer.PostRefusal = &refusal
		writeJSON(w, http.StatusOK, resp)
		return
	}
	if c := strings.ToLower(q.Get("c")); c != "" && q.Get("thread") == "" && q.Get("cursor") == "" && ValidID(c) {
		// the page that holds visible comment c: the first page when its
		// thread is there, else the page that begins with its thread (a reply
		// cut off a long thread: the script follows replies_next_cursor)
		used := ""
		if pos, err := s.Locate(r.Context(), cve, c); err == nil {
			first, err := s.store.Page(r.Context(), v.idPtr(), cve, nil, limit)
			if err != nil {
				s.fail(w, "read", err)
				return
			}
			comments, n := buildPage(first, v, s.link(loc))
			shown := false
			for _, t := range comments {
				shown = shown || t.ID == pos.ThreadID
			}
			if shown || pos.PageCursor == "" {
				resp.Count, resp.Comments, next = first.Visible, comments, n
				used = "-"
			} else {
				after, _ = decodeCursor(pos.PageCursor)
				used = pos.PageCursor
			}
		} else if !errors.Is(err, ErrNotFound) {
			s.fail(w, "read", err)
			return
		}
		if used == "-" {
			used = ""
		} else {
			p, err := s.store.Page(r.Context(), v.idPtr(), cve, after, limit)
			if err != nil {
				s.fail(w, "read", err)
				return
			}
			resp.Count = p.Visible
			resp.Comments, next = buildPage(p, v, s.link(loc))
		}
		resp.Cursor = &used
	} else if th := q.Get("thread"); th != "" {
		// continuation of a thread cut by the byte budget
		if !ValidID(th) {
			web.WriteError(w, http.StatusNotFound, "not_found", "no such thread", "thread")
			return
		}
		top, reps, err := s.store.Thread(r.Context(), v.idPtr(), cve, strings.ToLower(th), after)
		if err != nil {
			s.fail(w, "read", err)
			return
		}
		resp.Comments = []Comment{buildThread(top, reps, v, s.link(loc))}
		if resp.Count, err = s.store.Visible(r.Context(), v.idPtr(), cve); err != nil {
			s.fail(w, "read", err)
			return
		}
	} else {
		p, err := s.store.Page(r.Context(), v.idPtr(), cve, after, limit)
		if err != nil {
			s.fail(w, "read", err)
			return
		}
		resp.Count = p.Visible
		resp.Comments, next = buildPage(p, v, s.link(loc))
	}
	if c := encodeCursor(next); c != "" {
		resp.NextCursor = &c
	}
	if tv := s.termsVersion(); tv != "" {
		resp.Viewer.TermsVersion = &tv
	}
	refusal := "not_signed_in"
	if u != nil {
		role := u.Role
		resp.Viewer.SignedIn, resp.Viewer.Handle, resp.Viewer.Role, resp.Viewer.Moderator = true, u.Handle, &role, v.Moderator
		switch {
		case !v.Active:
			refusal = "suspended"
		case !v.HasHandle:
			refusal = "handle_required"
		case !v.TermsOK:
			refusal = "terms_required"
		default:
			refusal = ""
		}
		newAcct, err := s.store.NewAccount(r.Context(), u.ID, cur.lim)
		if err != nil {
			s.fail(w, "read", err)
			return
		}
		resp.Viewer.Links = !newAcct
	}
	if refusal == "" {
		resp.Viewer.CanPost = true
	} else {
		resp.Viewer.PostRefusal = &refusal
	}
	writeJSON(w, http.StatusOK, resp)
}

type commentResponse struct {
	OK              bool    `json:"ok"`
	Comment         Comment `json:"comment"`
	ResolvedReports *int64  `json:"resolved_reports,omitempty"`
}

// create: POST /api/discuss/{cve} with {"body", "parent_id"?, "lang"}
func (s *Service) create(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	cve, ok := pathCVE(w, r)
	if !ok || s.postRefused(w, u) {
		return
	}
	cur := s.cur() // one set of limits for the whole request
	if s.limited(w, cur.addrRL, auth.ClientAddr(r), "create_addr") {
		return
	}
	var body struct {
		Body     string  `json:"body"`
		ParentID *string `json:"parent_id"`
		Lang     string  `json:"lang"`
		Purpose  *string `json:"purpose"` // top-level only; null or "" = none
	}
	if !readJSON(w, r, &body) {
		return
	}
	text, ok := NormalizeBody(body.Body)
	if !ok {
		web.WriteError(w, http.StatusBadRequest, "invalid_body",
			fmt.Sprintf("the comment must have 1 to %d characters", MaxBodyChars), "body")
		return
	}
	lang := s.locale(body.Lang)
	if lang == "" {
		web.WriteError(w, http.StatusBadRequest, "bad_lang", "lang must be an enabled locale tag", "lang")
		return
	}
	var parent *string
	if body.ParentID != nil {
		if !ValidID(*body.ParentID) {
			web.WriteError(w, http.StatusBadRequest, "bad_parent", ErrBadParent.Error(), "parent_id")
			return
		}
		p := strings.ToLower(*body.ParentID)
		parent = &p
	}
	var purpose *string
	if body.Purpose != nil && *body.Purpose != "" {
		if !ValidPurpose(*body.Purpose) || parent != nil {
			web.WriteError(w, http.StatusBadRequest, "bad_purpose", ErrBadPurpose.Error(), "purpose")
			return
		}
		purpose = body.Purpose
	}
	gate := func(newAcct bool) error {
		l := cur.postRL
		if newAcct {
			l = cur.newPostRL
		}
		if ok, wait := l.Allow(u.ID); !ok {
			return &LimitError{Code: "rate_limited", RetryAfter: wait}
		}
		return nil
	}
	row, newAcct, err := s.store.Create(r.Context(), NewComment{CVE: cve, Parent: parent, Author: u.ID, Body: text, Lang: lang,
		Purpose: purpose}, cur.lim, gate)
	if err != nil {
		s.fail(w, "create", err)
		return
	}
	s.log.Info("discuss: created", "user", u.ID, "comment", row.ID, "cve", cve, "reply", parent != nil, "new_account", newAcct,
		"purpose", deref(purpose))
	writeJSON(w, http.StatusCreated, commentResponse{OK: true, Comment: view(row, s.viewer(u), s.link(lang), false)})
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// editPurpose reads the "purpose" of an edit: absent -> keep (set false);
// null or "" -> none; else one of Purposes (ok false: not a string or
// unknown).
func editPurpose(raw json.RawMessage) (set bool, p *string, ok bool) {
	if len(raw) == 0 {
		return false, nil, true
	}
	if string(raw) == "null" {
		return true, nil, true
	}
	var v string
	if err := json.Unmarshal(raw, &v); err != nil {
		return false, nil, false
	}
	if v == "" {
		return true, nil, true
	}
	if !ValidPurpose(v) {
		return false, nil, false
	}
	return true, &v, true
}

// edit: POST /api/discuss/comment/{id}/edit with {"body", "purpose"?}
func (s *Service) edit(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	id, ok := pathID(w, r)
	if !ok || s.postRefused(w, u) {
		return
	}
	if s.limited(w, s.cur().editRL, u.ID, "edit") {
		return
	}
	var body struct {
		Body    string          `json:"body"`
		Purpose json.RawMessage `json:"purpose"` // absent: keep; null or "": none
	}
	if !readJSON(w, r, &body) {
		return
	}
	text, ok := NormalizeBody(body.Body)
	if !ok {
		web.WriteError(w, http.StatusBadRequest, "invalid_body",
			fmt.Sprintf("the comment must have 1 to %d characters", MaxBodyChars), "body")
		return
	}
	setPurpose, purpose, ok := editPurpose(body.Purpose)
	if !ok {
		web.WriteError(w, http.StatusBadRequest, "bad_purpose", ErrBadPurpose.Error(), "purpose")
		return
	}
	row, changed, err := s.store.EditComment(r.Context(), id, u.ID, EditInput{Body: text, SetPurpose: setPurpose, Purpose: purpose})
	if err != nil {
		s.fail(w, "edit", err)
		return
	}
	if changed {
		s.log.Info("discuss: edited", "user", u.ID, "comment", row.ID, "cve", row.CVE)
	}
	writeJSON(w, http.StatusOK, commentResponse{OK: true, Comment: view(row, s.viewer(u), s.link(row.Lang), false)})
}

// delete: POST /api/discuss/comment/{id}/delete
func (s *Service) delete(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if s.limited(w, s.cur().deleteRL, u.ID, "delete") {
		return
	}
	row, err := s.store.Delete(r.Context(), id, u.ID)
	if err != nil {
		s.fail(w, "delete", err)
		return
	}
	s.log.Info("discuss: deleted", "user", u.ID, "comment", row.ID, "cve", row.CVE)
	writeJSON(w, http.StatusOK, commentResponse{OK: true, Comment: view(row, s.viewer(u), s.link(row.Lang), false)})
}

type reportResponse struct {
	OK              bool    `json:"ok"`
	AlreadyReported bool    `json:"already_reported"`
	Report          *Report `json:"report"`
}

// report: POST /api/discuss/comment/{id}/report with {"reason", "note"?}
func (s *Service) report(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	id, ok := pathID(w, r)
	if !ok {
		return
	}
	if s.limited(w, s.cur().reportRL, u.ID, "report") {
		return
	}
	var body struct {
		Reason string  `json:"reason"`
		Note   *string `json:"note"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !slices.Contains(ReportReasons, body.Reason) {
		web.WriteError(w, http.StatusBadRequest, "bad_reason", "reason must be one of "+strings.Join(ReportReasons, ", "), "reason")
		return
	}
	var note *string
	if body.Note != nil {
		n := normalizeLine(*body.Note)
		if utf8.RuneCountInString(n) > MaxNoteChars {
			web.WriteError(w, http.StatusBadRequest, "bad_note", fmt.Sprintf("note: at most %d characters", MaxNoteChars), "note")
			return
		}
		if n != "" {
			note = &n
		}
	}
	rep, already, err := s.store.AddReport(r.Context(), id, u.ID, body.Reason, note, s.cur().lim.ReportDaily)
	if err != nil {
		s.fail(w, "report", err)
		return
	}
	if !already {
		s.log.Info("discuss: reported", "user", u.ID, "comment", id, "report", rep.ID, "reason", rep.Reason)
	}
	writeJSON(w, http.StatusOK, reportResponse{OK: true, AlreadyReported: already, Report: rep})
}

// hide: POST /api/discuss/comment/{id}/hide with {"reason"} (moderators)
func (s *Service) hide(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	id, ok := pathID(w, r)
	if !ok || s.limited(w, s.cur().modRL, u.ID, "mod") {
		return
	}
	var body struct {
		Reason string `json:"reason"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	reason := normalizeLine(body.Reason)
	if n := utf8.RuneCountInString(reason); n < 1 || n > MaxReasonChars {
		web.WriteError(w, http.StatusBadRequest, "bad_reason", fmt.Sprintf("reason: 1 to %d characters", MaxReasonChars), "reason")
		return
	}
	row, n, err := s.store.Hide(r.Context(), id, &u.ID, reason)
	if err != nil {
		s.fail(w, "hide", err)
		return
	}
	s.log.Info("discuss: hidden", "user", u.ID, "comment", row.ID, "cve", row.CVE, "resolved_reports", n)
	writeJSON(w, http.StatusOK, commentResponse{OK: true, Comment: view(row, s.viewer(u), s.link(row.Lang), true), ResolvedReports: &n})
}

// unhide: POST /api/discuss/comment/{id}/unhide (moderators)
func (s *Service) unhide(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	id, ok := pathID(w, r)
	if !ok || s.limited(w, s.cur().modRL, u.ID, "mod") {
		return
	}
	row, err := s.store.Unhide(r.Context(), id, &u.ID)
	if err != nil {
		s.fail(w, "unhide", err)
		return
	}
	s.log.Info("discuss: unhidden", "user", u.ID, "comment", row.ID, "cve", row.CVE)
	writeJSON(w, http.StatusOK, commentResponse{OK: true, Comment: view(row, s.viewer(u), s.link(row.Lang), true)})
}

func modPaging(w http.ResponseWriter, r *http.Request) (*Cursor, int, bool) {
	q := r.URL.Query()
	var after *Cursor
	if c := q.Get("cursor"); c != "" {
		var ok bool
		if after, ok = decodeCursor(c); !ok {
			web.WriteError(w, http.StatusBadRequest, "bad_cursor", "invalid cursor", "cursor")
			return nil, 0, false
		}
	}
	limit := ModPageMax
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > ModPageMax {
			web.WriteError(w, http.StatusBadRequest, "bad_request", fmt.Sprintf("limit must be 1..%d", ModPageMax), "limit")
			return nil, 0, false
		}
		limit = n
	}
	return after, limit, true
}

type modReport struct {
	*Report
	Comment Comment `json:"comment"`
}

type reportsResponse struct {
	State      string      `json:"state"`
	Reports    []modReport `json:"reports"`
	NextCursor *string     `json:"next_cursor"`
}

// reports: GET /api/mod/reports?state=open|resolved&cursor=&limit= (moderators)
func (s *Service) reports(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	if s.limited(w, s.cur().modRL, u.ID, "mod") {
		return
	}
	state := r.URL.Query().Get("state")
	if state == "" {
		state = "open"
	}
	if state != "open" && state != "resolved" {
		web.WriteError(w, http.StatusBadRequest, "bad_request", "state must be open or resolved", "state")
		return
	}
	after, limit, ok := modPaging(w, r)
	if !ok {
		return
	}
	reps, next, err := s.store.Reports(r.Context(), &u.ID, state == "open", after, limit)
	if err != nil {
		s.fail(w, "reports", err)
		return
	}
	v := s.viewer(u)
	resp := reportsResponse{State: state, Reports: []modReport{}}
	for _, rep := range reps {
		resp.Reports = append(resp.Reports, modReport{Report: rep, Comment: view(rep.Comment, v, s.link(rep.Comment.Lang), true)})
	}
	if c := encodeCursor(next); c != "" {
		resp.NextCursor = &c
	}
	writeJSON(w, http.StatusOK, resp)
}

// resolve: POST /api/mod/reports/{id}/resolve with {"resolution"} (moderators)
func (s *Service) resolve(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	id, ok := pathID(w, r)
	if !ok || s.limited(w, s.cur().modRL, u.ID, "mod") {
		return
	}
	var body struct {
		Resolution string `json:"resolution"`
	}
	if !readJSON(w, r, &body) {
		return
	}
	if !slices.Contains(Resolutions, body.Resolution) {
		web.WriteError(w, http.StatusBadRequest, "bad_resolution", "resolution must be dismissed or actioned", "resolution")
		return
	}
	rep, err := s.store.ResolveReport(r.Context(), id, &u.ID, body.Resolution)
	if err != nil {
		s.fail(w, "resolve", err)
		return
	}
	s.log.Info("discuss: report resolved", "user", u.ID, "report", rep.ID, "comment", rep.Comment.ID, "resolution", body.Resolution)
	writeJSON(w, http.StatusOK, struct {
		OK     bool      `json:"ok"`
		Report modReport `json:"report"`
	}{true, modReport{Report: rep, Comment: view(rep.Comment, s.viewer(u), s.link(rep.Comment.Lang), true)}})
}

// recent: GET /api/mod/recent?cursor=&limit= (moderators)
func (s *Service) recent(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	if s.limited(w, s.cur().modRL, u.ID, "mod") {
		return
	}
	after, limit, ok := modPaging(w, r)
	if !ok {
		return
	}
	rows, next, err := s.store.Recent(r.Context(), &u.ID, after, limit)
	if err != nil {
		s.fail(w, "recent", err)
		return
	}
	v := s.viewer(u)
	resp := struct {
		Comments   []Comment `json:"comments"`
		NextCursor *string   `json:"next_cursor"`
	}{Comments: []Comment{}}
	for _, row := range rows {
		c := view(row, v, s.link(row.Lang), true)
		c.Replies = nil
		resp.Comments = append(resp.Comments, c)
	}
	if c := encodeCursor(next); c != "" {
		resp.NextCursor = &c
	}
	writeJSON(w, http.StatusOK, resp)
}

// revisions: GET /api/mod/comment/{id}/revisions (moderators): the stored
// earlier bodies, newest first, as source text only.
func (s *Service) revisions(w http.ResponseWriter, r *http.Request) {
	u := auth.CurrentUser(r)
	id, ok := pathID(w, r)
	if !ok || s.limited(w, s.cur().modRL, u.ID, "mod") {
		return
	}
	revs, err := s.store.Revisions(r.Context(), id)
	if err != nil {
		s.fail(w, "revisions", err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		CommentID string     `json:"comment_id"`
		Revisions []Revision `json:"revisions"`
	}{id, revs})
}

// warnAggregate logs rate limiting at most once per minute, with how many
// refusals per kind were not logged since the previous line (like auth).
type warnAggregate struct {
	mu   sync.Mutex
	last time.Time
	n    map[string]int
}

func (a *warnAggregate) note(log *slog.Logger, what string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := time.Now()
	if !a.last.IsZero() && now.Sub(a.last) < time.Minute {
		if a.n == nil {
			a.n = map[string]int{}
		}
		a.n[what]++
		return
	}
	attrs := []any{"limit", what}
	if len(a.n) > 0 {
		keys := make([]string, 0, len(a.n))
		total := 0
		for k, v := range a.n {
			keys = append(keys, k)
			total += v
		}
		slices.Sort(keys)
		var b strings.Builder
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(' ')
			}
			fmt.Fprintf(&b, "%s=%d", k, a.n[k])
		}
		attrs = append(attrs, "suppressed", total, "suppressed_by_limit", b.String(), "since", a.last.UTC().Format(time.RFC3339))
	}
	log.Warn("discuss: rate limited", attrs...)
	a.last, a.n = now, nil
}
