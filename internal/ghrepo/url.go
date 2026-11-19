// Package ghrepo is the GitHub repository module (docs/github.md): it
// queues the GitHub repositories that allowlisted researchers link to from
// their X posts (Enqueue, from x_post_link), fetches their metadata from the
// GitHub REST API (FetchPending: GET https://api.github.com/repos/{owner}/{repo}
// only; never github.com pages) and associates them with CVEs (tables
// github_repo, github_repo_name, github_repo_cve; migrations/0023_github_repo.sql).
// Everything the API returns is untrusted text: cleaned with the
// internal/pagefetch helpers, cut, type-checked.
package ghrepo

import (
	"net/url"
	"regexp"
	"strings"
)

var (
	// GitHub user / organisation names: letters, digits and hyphens, not
	// starting with a hyphen, at most 39 characters.
	ownerRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`)
	// repository names: letters, digits, '.', '_' and '-', at most 100.
	repoRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)
)

// reserved are first path segments of github.com that are site routes,
// never a user or organisation.
var reserved = map[string]bool{
	"about": true, "account": true, "advisories": true, "apps": true, "articles": true, "blog": true, "business": true,
	"codespaces": true, "collections": true, "contact": true, "copilot": true, "customer-stories": true, "dashboard": true,
	"discussions": true, "downloads": true, "education": true, "enterprise": true, "events": true, "explore": true,
	"features": true, "git-guides": true, "github-copilot": true, "issues": true, "join": true, "login": true, "logout": true,
	"marketplace": true, "mobile": true, "models": true, "new": true, "nonprofit": true, "notifications": true,
	"organizations": true, "orgs": true, "password_reset": true, "premium-support": true, "pricing": true, "pulls": true,
	"readme": true, "resources": true, "search": true, "security": true, "sessions": true, "settings": true,
	"showcases": true, "signup": true, "site": true, "sitemap": true, "solutions": true, "sponsors": true, "stars": true,
	"team": true, "teams": true, "topics": true, "trending": true, "users": true, "watching": true,
}

// ParseURL returns the owner and repository name of a github.com URL that
// points at a repository or anything inside it (http or https, host
// github.com or www.github.com, no user info, default port only). The
// owner and name are the path's first two segments as written (one
// trailing ".git" of the name dropped); ok is false for other hosts
// (gist.github.com included), site routes (reserved first segments) and
// segments that are not valid GitHub names (escapes included).
func ParseURL(raw string) (owner, name string, ok bool) {
	if len(raw) > 2048 {
		return "", "", false
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.User != nil || u.Opaque != "" {
		return "", "", false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host != "github.com" && host != "www.github.com" {
		return "", "", false
	}
	if p := u.Port(); p != "" && !(u.Scheme == "https" && p == "443") && !(u.Scheme == "http" && p == "80") {
		return "", "", false
	}
	segs := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	if len(segs) < 2 {
		return "", "", false
	}
	owner, name = segs[0], strings.TrimSuffix(segs[1], ".git")
	if !ownerRe.MatchString(owner) || reserved[strings.ToLower(owner)] || !ValidName(name) {
		return "", "", false
	}
	return owner, name, true
}

// ValidName reports whether s is a valid repository name.
func ValidName(s string) bool { return repoRe.MatchString(s) && s != "." && s != ".." }

// ValidFullName reports whether s is "owner/name" with a valid owner and name.
func ValidFullName(s string) bool {
	o, n, ok := strings.Cut(s, "/")
	return ok && ownerRe.MatchString(o) && ValidName(n)
}

// Key is the name key of a repository (github_repo_name.name_key): "owner/name"
// lower case (GitHub names are case-insensitive).
func Key(owner, name string) string { return strings.ToLower(owner + "/" + name) }

// KeyOf is Key of the repository raw points into; ok as ParseURL.
func KeyOf(raw string) (string, bool) {
	o, n, ok := ParseURL(raw)
	if !ok {
		return "", false
	}
	return Key(o, n), true
}

// RootKeyOf is KeyOf for a link to the repository root only:
// /owner/name with an optional trailing "/" and an optional ".git", no
// query (a fragment is ignored). Deep links (/owner/name/issues/3,
// /blob/..., /tree/..., /releases/...) give ok false.
func RootKeyOf(raw string) (string, bool) {
	k, ok := KeyOf(raw)
	if !ok {
		return "", false
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.RawQuery != "" || u.ForceQuery {
		return "", false
	}
	segs := strings.Split(strings.TrimPrefix(u.EscapedPath(), "/"), "/")
	if len(segs) == 3 && segs[2] == "" {
		segs = segs[:2]
	}
	if len(segs) != 2 {
		return "", false
	}
	return k, true
}
