package webui

import "strings"

// API builds every URL of the public data API that a page shows: curl
// lines, "raw JSON" links and endpoint names. No page builds API URLs by
// hand.
//
// Endpoint paths passed in carry no prefix: "/hot?since=7d",
// "/vuln/CVE-2026-1", "/search?q=x", "/sources", "/stats",
// "/raw/kev/CVE-2026-1.json" (as site.RawPath returns them), "/healthz".
//
// Single-host mode (no API origin): "/api/hot", "/raw/...", "/healthz" on
// the site origin; links stay relative. Two-host mode: "/v1/hot",
// "/v1/raw/...", "/healthz" on the API origin; links are absolute.
type API struct {
	site string // public site origin
	api  string // API host origin; "" = single-host mode
}

// NewAPI returns the builder for a site origin and an optional API origin
// (both already validated, see web.ParseOrigin).
func NewAPI(siteURL, apiURL string) API {
	return API{site: strings.TrimRight(siteURL, "/"), api: strings.TrimRight(apiURL, "/")}
}

// Path is the endpoint's path (and query) on the host that serves it.
func (a API) Path(p string) string {
	switch {
	case p == "/healthz" || strings.HasPrefix(p, "/healthz?"):
		return p
	case a.api != "":
		return "/v1" + p
	case strings.HasPrefix(p, "/raw/"):
		return p
	}
	return "/api" + p
}

// URL is the absolute URL of the endpoint (curl lines).
func (a API) URL(p string) string {
	if a.api != "" {
		return a.api + a.Path(p)
	}
	return a.site + a.Path(p)
}

// Href is the link target for a page: relative on the site host in
// single-host mode, absolute on the API host otherwise.
func (a API) Href(p string) string {
	if a.api == "" {
		return a.Path(p)
	}
	return a.URL(p)
}
