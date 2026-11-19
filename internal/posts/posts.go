// Package posts serves the researcher section of vulnerability pages:
// GET /api/posts/{cve} (docs/xposts.md "Public visibility", docs/api.md).
//
// Researcher posts are posts on X by allow-listed accounts that mention a
// CVE id (the xposts collector). Their content is for signed-in users
// only. Like /api/me and /api/discuss this is an auth-class endpoint: only
// on the public host (other Host: 421 wrong_host; never on the API host),
// GET only, it reads the session cookie, and every response is
// Cache-Control: private, no-store with Vary: Cookie.
//
//   - signed in: the posts (text, author handle and profile link, time, link
//     to the post, the post's resolved t.co links), newest first, at most
//     site.MaxMemberPosts;
//   - signed out: only what site/public.go declares public — the researcher
//     count and the outline (per post: the author's @username and profile
//     link when the handle is valid, the UTC date, a size class). No text,
//     post id, post URL, exact time, language or author id is ever read
//     for such a request.
package posts

import (
	"context"
	"log/slog"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/web"
	"nday.land/nday/internal/xconfig"
)

// CacheControl of every response.
const CacheControl = "private, no-store"

// Store is what the endpoint reads (site.Store).
type Store interface {
	VulnExists(ctx context.Context, cve string) (bool, error)
	ResearcherOutline(ctx context.Context, cve string) (*site.ResearcherOutline, error)
	MemberPosts(ctx context.Context, cve string) ([]site.MemberPost, error)
}

// Options configure the service.
type Options struct {
	Auth   *auth.Service
	Store  Store
	Logger *slog.Logger
	// ReadBurst / ReadEvery: per client address (default 120 / 500ms, like
	// GET /api/discuss).
	ReadBurst int
	ReadEvery time.Duration
	Now       func() time.Time
}

// Service is the endpoint.
type Service struct {
	auth  *auth.Service
	store Store
	log   *slog.Logger
	rl    *auth.RateLimiter
	h     http.Handler
}

// New builds the service.
func New(o Options) *Service {
	s := &Service{auth: o.Auth, store: o.Store, log: o.Logger}
	if s.log == nil {
		s.log = slog.Default()
	}
	if o.ReadBurst == 0 {
		o.ReadBurst = 120
	}
	if o.ReadEvery == 0 {
		o.ReadEvery = 500 * time.Millisecond
	}
	s.rl = auth.NewRateLimiter(o.ReadBurst, o.ReadEvery)
	if o.Now != nil {
		s.rl.Now = o.Now
	}
	s.h = o.Auth.Load(http.HandlerFunc(s.read))
	return s
}

// Register mounts GET /api/posts/{cve} on the site host.
func (s *Service) Register(srv *web.Server) { srv.Handle("/api/posts/", s) }

// privateWriter forces the cache headers on every response, whatever an
// inner handler (auth.Load) set.
type privateWriter struct {
	http.ResponseWriter
	done bool
}

func (w *privateWriter) apply() {
	if w.done {
		return
	}
	w.done = true
	h := w.Header()
	h.Set("Cache-Control", CacheControl)
	for _, k := range []string{"ETag", "Last-Modified", "Expires", "CDN-Cache-Control", "Cloudflare-CDN-Cache-Control", "Surrogate-Control"} {
		h.Del(k)
	}
	if !slices.ContainsFunc(h.Values("Vary"), func(v string) bool { return strings.Contains(strings.ToLower(v), "cookie") }) {
		h.Add("Vary", "Cookie")
	}
}

func (w *privateWriter) WriteHeader(code int) {
	if code >= 200 {
		w.apply()
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *privateWriter) Write(b []byte) (int, error) {
	w.apply()
	return w.ResponseWriter.Write(b)
}

func (w *privateWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

// ServeHTTP answers /api/posts/{cve}.
func (s *Service) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pw := &privateWriter{ResponseWriter: w}
	defer func() {
		if p := recover(); p != nil {
			pw.apply()
			panic(p)
		}
	}()
	w = pw
	w.Header().Set("Cache-Control", CacheControl)
	if !s.auth.PublicHost(r.Host) {
		web.WriteError(w, http.StatusMisdirectedRequest, "wrong_host", "this host does not serve posts", "")
		return
	}
	segs := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")
	if len(segs) != 3 || segs[2] == "" {
		web.WriteError(w, http.StatusNotFound, "not_found", "no such endpoint", "")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		web.WriteError(w, http.StatusMethodNotAllowed, "method_not_allowed", "use GET", "")
		return
	}
	if ok, wait := s.rl.Allow(auth.ClientAddr(r)); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
		web.WriteError(w, http.StatusTooManyRequests, "rate_limited", "too many requests; try again later", "")
		return
	}
	s.h.ServeHTTP(w, r)
}

// Post is one post in a signed-in response.
type Post struct {
	PostID       string    `json:"post_id"`
	AuthorHandle string    `json:"author_handle"`
	AuthorURL    *string   `json:"author_url"` // https://x.com/<handle>, only for a valid handle
	Text         string    `json:"text"`       // untrusted: render as text
	Lang         string    `json:"lang"`       // BCP 47-like tag or ""
	PostedAt     time.Time `json:"posted_at"`
	URL          *string   `json:"url"` // https://x.com/<handle|i/web>/status/<id>
	// Links: the post's resolved t.co links in order ([] when none); the
	// page shows each short link of the text as its final URL.
	Links []Link `json:"links"`
}

// Link is one resolved link of a post (signed in only). Untrusted: a
// client links FinalURL only when it is an http/https URL.
type Link struct {
	ShortURL string `json:"short_url"` // the t.co link as it appears in Text
	FinalURL string `json:"final_url"`
	Host     string `json:"host"`
	Kind     string `json:"kind"` // xlinks kind: media, quote, patch, code, poc, advisory, other
}

// Response is the body of a 200.
type Response struct {
	CVE         string `json:"cve"`
	SignedIn    bool   `json:"signed_in"`
	Researchers int    `json:"researchers_7d"`
	// Count is how many posts the section lists (len(Posts) or len(Outline)).
	Count int `json:"count"`
	// Posts: signed in only ([] when signed out).
	Posts []Post `json:"posts"`
	// Outline: signed out only (absent when signed in).
	Outline []site.OutlineEntry `json:"outline,omitempty"`
}

var (
	postURLRe = regexp.MustCompile(`^https://x\.com/(?:[A-Za-z0-9_]{1,15}|i/web)/status/[0-9]{1,20}$`)
	postIDRe  = regexp.MustCompile(`^[0-9]{1,20}$`)
	langRe    = regexp.MustCompile(`^[a-zA-Z]{2,3}(-[a-zA-Z0-9]{2,8})?$`)
)

// PostURL is u when it is a post link of the accepted forms, else the
// i/web link of a numeric post id, else nil.
func PostURL(u, id string) *string {
	if postURLRe.MatchString(u) {
		return &u
	}
	if postIDRe.MatchString(id) {
		s := "https://x.com/i/web/status/" + id
		return &s
	}
	return nil
}

// ProfileURL is https://x.com/<handle> for a handle that passes
// xconfig.ValidHandle, else nil.
func ProfileURL(handle string) *string {
	if !xconfig.ValidHandle(handle) {
		return nil
	}
	s := "https://x.com/" + handle
	return &s
}

func (s *Service) read(w http.ResponseWriter, r *http.Request) {
	seg := strings.Split(strings.TrimPrefix(r.URL.Path, "/"), "/")[2]
	cve, ok := site.ParseVulnID(seg)
	if !ok {
		web.WriteError(w, http.StatusBadRequest, "bad_cve", "not a vulnerability id", "cve")
		return
	}
	ctx := r.Context()
	exists, err := s.store.VulnExists(ctx, cve)
	if err != nil {
		s.internal(w, err)
		return
	}
	if !exists {
		web.WriteError(w, http.StatusNotFound, "not_found", "no such vulnerability", "cve")
		return
	}
	o, err := s.store.ResearcherOutline(ctx, cve)
	if err != nil {
		s.internal(w, err)
		return
	}
	resp := Response{CVE: cve, Researchers: o.Researchers, Posts: []Post{}}
	if auth.CurrentUser(r) == nil {
		resp.Outline, resp.Count = o.Entries, len(o.Entries)
		s.write(w, resp)
		return
	}
	ps, err := s.store.MemberPosts(ctx, cve)
	if err != nil {
		s.internal(w, err)
		return
	}
	resp.SignedIn = true
	for _, p := range ps {
		lang := p.Lang
		if !langRe.MatchString(lang) {
			lang = ""
		}
		links := []Link{}
		for _, l := range p.Links {
			links = append(links, Link{ShortURL: l.ShortURL, FinalURL: l.FinalURL, Host: l.Host, Kind: l.Kind})
		}
		resp.Posts = append(resp.Posts, Post{PostID: p.PostID, AuthorHandle: p.AuthorHandle, AuthorURL: ProfileURL(p.AuthorHandle),
			Text: p.Text, Lang: lang, PostedAt: p.PostedAt.UTC(), URL: PostURL(p.URL, p.PostID), Links: links})
	}
	resp.Count = len(resp.Posts)
	s.write(w, resp)
}

func (s *Service) internal(w http.ResponseWriter, err error) {
	s.log.Error("posts: internal error", "err", err)
	web.WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
}

func (s *Service) write(w http.ResponseWriter, v any) {
	b, err := web.EncodeJSON(v)
	if err != nil {
		s.internal(w, err)
		return
	}
	h := w.Header()
	h.Set("Content-Type", "application/json; charset=utf-8")
	h.Set("Content-Length", strconv.Itoa(len(b)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(b)
}
