package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"nday.land/nday/internal/site"
)

// cached is a cache entry: an encoded body plus its status.
type cached struct {
	status   int
	body     Body
	location string // set: a redirect to this URL (status 3xx, no body)
}

// repeatable parameters may be given more than once (?tag=a&tag=b).
var repeatable = map[string]bool{"tag": true}

// queryParams validates that q only has allowed parameters, each given once
// unless it is repeatable.
func queryParams(r *http.Request, allowed ...string) (url.Values, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return nil, &site.InputError{Param: "query", Msg: "malformed query string"}
	}
	for k, vs := range q {
		ok := false
		for _, a := range allowed {
			if k == a {
				ok = true
			}
		}
		if !ok {
			return nil, &site.InputError{Param: k, Msg: "unknown parameter"}
		}
		if len(vs) > 1 && !repeatable[k] {
			return nil, &site.InputError{Param: k, Msg: "given more than once"}
		}
	}
	return q, nil
}

func intParam(q url.Values, name string, def int) (int, error) {
	v, ok := q[name]
	if !ok {
		return def, nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(v[0]))
	if err != nil {
		return 0, &site.InputError{Param: name, Msg: "not an integer"}
	}
	return n, nil
}

func boolParam(q url.Values, name string) (bool, error) {
	v, ok := q[name]
	if !ok {
		return false, nil
	}
	switch strings.ToLower(strings.TrimSpace(v[0])) {
	case "", "1", "true", "yes", "on":
		return true, nil
	case "0", "false", "no", "off":
		return false, nil
	}
	return false, &site.InputError{Param: name, Msg: "expected true or false"}
}

// fail writes the error response for err.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ie *site.InputError
	switch {
	case errors.As(err, &ie):
		WriteError(w, http.StatusBadRequest, "bad_request", ie.Error(), ie.Param)
	case isTimeout(err) || errors.Is(err, context.Canceled):
		s.Log.Warn("request timed out", "path", trunc(r.URL.Path, 300), "err", err)
		WriteError(w, http.StatusServiceUnavailable, "timeout", "the database did not answer in time", "")
	default:
		s.Log.Error("request failed", "path", trunc(r.URL.Path, 300), "err", err)
		WriteError(w, http.StatusInternalServerError, "internal", "internal error", "")
	}
}

// serveCached answers from the in-process cache (key) or computes the body.
func (s *Server) serveCached(w http.ResponseWriter, r *http.Request, key, cacheControl string,
	fn func(ctx context.Context) (cached, error)) {
	v, hit, err := s.Cache.Get(r.Context(), key, s.cfg.CacheTTL, func(ctx context.Context) (any, error) {
		return fn(ctx)
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	c := v.(cached)
	if hit {
		w.Header().Set("X-Nday-Cache", "hit")
	} else {
		w.Header().Set("X-Nday-Cache", "miss")
	}
	cc := cacheControl
	if c.location != "" {
		w.Header().Set("Location", c.location)
		w.Header().Set("Cache-Control", CacheList)
		w.WriteHeader(c.status)
		return
	}
	if c.status != http.StatusOK {
		cc = CacheList // short public caching of a 404 is fine
	}
	WriteBody(w, r, c.status, c.body, cc)
}

func ok(v any) (cached, error) {
	b, err := NewBody(v)
	return cached{status: http.StatusOK, body: b}, err
}

func (s *Server) hot(w http.ResponseWriter, r *http.Request) {
	q, err := queryParams(r, "since", "min_stage", "include_rejected", "limit", "offset", "cursor", "before", "tag")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := site.HotParams{Cursor: q.Get("cursor"), Before: q.Get("before"), Tags: q["tag"]}
	if v, ok := q["since"]; ok {
		if p.Since, err = site.ParseSince(v[0]); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if v, ok := q["min_stage"]; ok {
		if p.MinStage, err = site.ParseStage(v[0]); err != nil {
			s.fail(w, r, err)
			return
		}
	}
	if p.IncludeRejected, err = boolParam(q, "include_rejected"); err == nil {
		if p.Limit, err = intParam(q, "limit", 0); err == nil {
			p.Offset, err = intParam(q, "offset", 0)
		}
	}
	if err == nil {
		if _, ok := q["limit"]; ok && p.Limit == 0 {
			err = &site.InputError{Param: "limit", Msg: fmt.Sprintf("must be 1..%d", site.MaxHotLimit)}
		}
	}
	if err == nil {
		p, err = p.Normalize()
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.serveCached(w, r, s.Store.HotCacheKey(p), CacheList, func(ctx context.Context) (cached, error) {
		page, err := s.Store.Hot(ctx, p)
		if err != nil {
			return cached{}, err
		}
		return ok(page)
	})
}

// discussed: CVEs ranked by how many allow-listed researchers posted about
// them on X in the last 7 days (counts only; site/public.go).
func (s *Server) discussed(w http.ResponseWriter, r *http.Request) {
	q, err := queryParams(r, "limit", "offset")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	var p site.DiscussedParams
	if p.Limit, err = intParam(q, "limit", 0); err == nil {
		p.Offset, err = intParam(q, "offset", 0)
	}
	if err == nil {
		if _, ok := q["limit"]; ok && p.Limit == 0 {
			err = &site.InputError{Param: "limit", Msg: fmt.Sprintf("must be 1..%d", site.MaxHotLimit)}
		}
	}
	if err == nil {
		p, err = p.Normalize()
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.serveCached(w, r, p.CacheKey(), CacheList, func(ctx context.Context) (cached, error) {
		page, err := s.Store.Discussed(ctx, p)
		if err != nil {
			return cached{}, err
		}
		return ok(page)
	})
}

func (s *Server) vuln(w http.ResponseWriter, r *http.Request) {
	if _, err := queryParams(r); err != nil {
		s.fail(w, r, err)
		return
	}
	id, valid := site.ParseVulnID(r.PathValue("cve"))
	if !valid {
		s.fail(w, r, &site.InputError{Param: "cve", Msg: site.BadVulnIDMsg})
		return
	}
	key, prefix := "vuln|"+id, ""
	if site.IsGHSAID(id) {
		// A GHSA id that is only an alias answers with a redirect into the
		// same route family, so the family is part of the key.
		prefix = r.URL.Path[:strings.LastIndex(r.URL.Path, "/")+1]
		key = "vuln|" + prefix + "|" + id
	}
	s.serveCached(w, r, key, CacheList, func(ctx context.Context) (cached, error) {
		v, found, err := s.Store.Vuln(ctx, id)
		if err != nil {
			return cached{}, err
		}
		if found {
			return ok(v)
		}
		if prefix != "" {
			return s.ghsaAlias(ctx, prefix, id)
		}
		return vulnNotFound(id + " is not in the database")
	})
}

// vulnNotFound is a cached 404 not_found about the vulnerability id.
func vulnNotFound(msg string) (cached, error) {
	b, err := NewBody(struct {
		Error APIError `json:"error"`
	}{APIError{Status: 404, Code: "not_found", Message: msg, Param: "cve"}})
	return cached{status: http.StatusNotFound, body: Body{JSON: b.JSON}}, err
}

// ghsaAlias answers /v1/vuln/{GHSA id} (or /api/vuln/...) for a GHSA id that
// is not a vulnerability of its own: an alias of one CVE -> 307 to the same
// route family's CVE URL (the alias comes from upstream and can change, so it
// is cached no longer than a detail response); none -> 404 not_found;
// several -> 409 ambiguous naming the search endpoint.
func (s *Server) ghsaAlias(ctx context.Context, prefix, ghsa string) (cached, error) {
	cves, err := s.Store.VulnsByGHSA(ctx, ghsa)
	if err != nil {
		return cached{}, err
	}
	switch len(cves) {
	case 1:
		return cached{status: http.StatusTemporaryRedirect, location: prefix + cves[0]}, nil
	case 0:
		return vulnNotFound(ghsa + " is not in the database")
	}
	b, err := NewBody(struct {
		Error APIError `json:"error"`
	}{APIError{Status: 409, Code: "ambiguous", Message: ghsa + " is an alias of more than one CVE; use /search?q=" + ghsa, Param: "cve"}})
	return cached{status: http.StatusConflict, body: Body{JSON: b.JSON}}, err
}

func (s *Server) sources(w http.ResponseWriter, r *http.Request) {
	if _, err := queryParams(r); err != nil {
		s.fail(w, r, err)
		return
	}
	s.serveCached(w, r, "sources", CacheList, func(ctx context.Context) (cached, error) {
		v, err := s.Store.Sources(ctx)
		if err != nil {
			return cached{}, err
		}
		return ok(v)
	})
}

func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	if _, err := queryParams(r); err != nil {
		s.fail(w, r, err)
		return
	}
	s.serveCached(w, r, "stats", CacheList, func(ctx context.Context) (cached, error) {
		v, err := s.Store.Stats(ctx)
		if err != nil {
			return cached{}, err
		}
		return ok(v)
	})
}

func (s *Server) search(w http.ResponseWriter, r *http.Request) {
	q, err := queryParams(r, "q", "limit", "tag")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	tagSlugs, err := site.NormalizeTags(q["tag"])
	if err != nil {
		s.fail(w, r, err)
		return
	}
	limit, err := intParam(q, "limit", site.DefaultSearchLimit)
	if err == nil && (limit < 1 || limit > site.MaxSearchLimit) {
		err = &site.InputError{Param: "limit", Msg: fmt.Sprintf("must be 1..%d", site.MaxSearchLimit)}
	}
	var text string
	if err == nil {
		text, err = site.NormalizeQuery(q.Get("q"))
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.serveCached(w, r, "search|"+strconv.Itoa(limit)+"|"+strings.Join(tagSlugs, ",")+"|"+text, CacheList, func(ctx context.Context) (cached, error) {
		v, err := s.Store.SearchTagged(ctx, text, tagSlugs, limit)
		if err != nil {
			return cached{}, err
		}
		return ok(v)
	})
}

// tags is GET /api/tags: the tag vocabulary with precomputed counts.
func (s *Server) tags(w http.ResponseWriter, r *http.Request) {
	if _, err := queryParams(r); err != nil {
		s.fail(w, r, err)
		return
	}
	s.serveCached(w, r, "tags", CacheList, func(ctx context.Context) (cached, error) {
		v, err := s.Store.Tags(ctx)
		if err != nil {
			return cached{}, err
		}
		return ok(v)
	})
}

// suggest: GET /api/affected/suggest?q=&limit= — vendor and product names
// for the follow picker of the welcome page (docs/api.md).
func (s *Server) suggest(w http.ResponseWriter, r *http.Request) {
	q, err := queryParams(r, "q", "limit")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	limit, err := intParam(q, "limit", site.DefaultSuggestLimit)
	if err == nil && (limit < 1 || limit > site.MaxSuggestLimit) {
		err = &site.InputError{Param: "limit", Msg: fmt.Sprintf("must be 1..%d", site.MaxSuggestLimit)}
	}
	var text string
	if err == nil {
		text, err = site.NormalizeSuggestQuery(q.Get("q")) // the cache key is the normalised query
	}
	if err != nil {
		s.fail(w, r, err)
		return
	}
	s.serveCached(w, r, "suggest|"+strconv.Itoa(limit)+"|"+text, CacheList, func(ctx context.Context) (cached, error) {
		v, err := s.Store.Suggest(ctx, text, limit)
		if err != nil {
			return cached{}, err
		}
		return ok(v)
	})
}

func (s *Server) raw(w http.ResponseWriter, r *http.Request) {
	if _, err := queryParams(r); err != nil {
		s.fail(w, r, err)
		return
	}
	source, key := r.PathValue("source"), r.PathValue("key")
	if !strings.HasSuffix(key, ".json") {
		WriteError(w, http.StatusNotFound, "not_found", "raw records are served as /raw/{source}/{key}.json", "")
		return
	}
	key = strings.TrimSuffix(key, ".json")
	if err := site.ValidateRawKey(source, key); err != nil {
		s.fail(w, r, err)
		return
	}
	rec, found, err := s.Store.Raw(r.Context(), source, key)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	if !found {
		w.Header().Set("Cache-Control", CacheList)
		WriteError(w, http.StatusNotFound, "not_found", "no raw record for "+source+"/"+key, "")
		return
	}
	h := w.Header()
	h.Set("Last-Modified", rec.FetchedAt.UTC().Format(http.TimeFormat))
	WriteBody(w, r, http.StatusOK, Body{JSON: rec.Payload, ETag: `"` + rec.ContentHash + `"`}, CacheRaw)
}

// healthResponse is the /healthz body.
type healthResponse struct {
	Status string `json:"status"` // ok | stale | error
	site.Health
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()
	h, err := s.Store.Health(ctx)
	resp := healthResponse{Status: "ok", Health: h}
	status := http.StatusOK
	switch {
	case err != nil:
		s.Log.Warn("healthz: database unreachable", "err", err)
		resp.Status, status = "error", http.StatusServiceUnavailable
	case h.Stale:
		resp.Status = "stale"
	}
	b, err := NewBody(resp)
	if err != nil {
		s.fail(w, r, err)
		return
	}
	WriteBody(w, r, status, Body{JSON: b.JSON}, CacheNever)
}
