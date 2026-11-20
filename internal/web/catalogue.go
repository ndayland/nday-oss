package web

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"nday.land/nday/internal/site"
)

// vulns is GET /api/vulns (/v1/vulns on the API host): the catalogue of
// every vulnerability, most recent change first (site.Store.Catalogue).
// ?stage=&year=&tag=&cvss_min=&cvss_max=&include_rejected=&limit=&cursor=&before=
func (s *Server) vulns(w http.ResponseWriter, r *http.Request) {
	q, err := queryParams(r, "stage", "year", "tag", "cvss_min", "cvss_max", "include_rejected", "limit", "cursor", "before")
	if err != nil {
		s.fail(w, r, err)
		return
	}
	p := site.CatalogueParams{Stage: q.Get("stage"), Cursor: q.Get("cursor"), Before: q.Get("before"), Tags: q["tag"],
		CVSSMin: q.Get("cvss_min"), CVSSMax: q.Get("cvss_max")}
	if v, ok := q["stage"]; ok && v[0] == "" {
		err = &site.InputError{Param: "stage", Msg: "empty (leave the parameter out for every stage)"}
	}
	if err == nil {
		err = emptyCVSSParam(q)
	}
	if err == nil {
		if p.Year, err = intParam(q, "year", 0); err == nil {
			if _, ok := q["year"]; ok && p.Year == 0 {
				err = &site.InputError{Param: "year", Msg: fmt.Sprintf("must be %d..%d", site.MinCatalogueYear, site.MaxCatalogueYear())}
			}
		}
	}
	if err == nil {
		p.IncludeRejected, err = boolParam(q, "include_rejected")
	}
	if err == nil {
		if p.Limit, err = intParam(q, "limit", 0); err == nil {
			if _, ok := q["limit"]; ok && p.Limit == 0 {
				err = &site.InputError{Param: "limit", Msg: fmt.Sprintf("must be 1..%d", site.MaxCatalogueLimit)}
			}
		}
	}
	if err == nil {
		if v, ok := q["cursor"]; ok && v[0] == "" {
			err = &site.InputError{Param: "cursor", Msg: "invalid cursor"}
		} else if v, ok := q["before"]; ok && v[0] == "" {
			err = &site.InputError{Param: "before", Msg: "invalid cursor"}
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
		page, err := s.Store.Catalogue(ctx, p)
		if err != nil {
			return cached{}, err
		}
		return ok(page)
	})
}

// emptyCVSSParam rejects an empty cvss_min / cvss_max, as an empty stage or
// year (leave the parameter out for no bound).
func emptyCVSSParam(q url.Values) error {
	for _, k := range []string{"cvss_min", "cvss_max"} {
		if v, ok := q[k]; ok && v[0] == "" {
			return &site.InputError{Param: k, Msg: "empty (leave the parameter out for no bound)"}
		}
	}
	return nil
}
