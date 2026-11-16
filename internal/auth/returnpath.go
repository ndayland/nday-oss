package auth

import (
	"net/url"
	"regexp"
	"strings"
)

// returnPathRe is the allow-pattern for post-sign-in return targets: an
// absolute path of unreserved characters and '/', optionally followed by a
// query of unreserved characters, '=', '&', '+' and %XX escapes. No
// scheme, no authority, no backslash, no fragment, no whitespace or control
// characters can match.
var returnPathRe = regexp.MustCompile(`^/[A-Za-z0-9._~\-/]*(\?([A-Za-z0-9._~\-=&+]|%[0-9A-Fa-f]{2})*)?$`)

// MaxReturnPath bounds the return target length.
const MaxReturnPath = 512

// SafeReturnPath returns p if it is an acceptable same-site return target,
// otherwise "/". Rejected: "//host" and "/\host" (protocol-relative),
// absolute URLs, any backslash or control character (also percent-encoded),
// dot segments, /auth, /api and paths into /auth/, /account/ or /api/ (no
// loops back into the sign-in machinery; the page /account itself is
// allowed), and anything longer than MaxReturnPath.
func SafeReturnPath(p string) string {
	if ok := validReturnPath(p); ok {
		return p
	}
	return "/"
}

func validReturnPath(p string) bool {
	if p == "" || len(p) > MaxReturnPath || !returnPathRe.MatchString(p) {
		return false
	}
	path, query, _ := strings.Cut(p, "?")
	if strings.HasPrefix(path, "//") {
		return false
	}
	for _, seg := range strings.Split(path, "/")[1:] {
		if seg == "." || seg == ".." {
			return false
		}
	}
	// No loops back into the sign-in machinery: /auth, /api and everything
	// below them, and everything below /account/ (the JSON endpoints). The
	// account PAGE /account itself is a valid target (the UI returns there
	// after linking or re-verifying).
	if path == "/auth" || path == "/api" {
		return false
	}
	for _, pre := range []string{"/auth/", "/account/", "/api/"} {
		if strings.HasPrefix(path, pre) {
			return false
		}
	}
	// The query may carry %XX escapes (search terms); after decoding they
	// must not contain control characters or backslashes.
	dec, err := url.QueryUnescape(query)
	if err != nil {
		return false
	}
	for _, r := range dec {
		if r < 0x20 || r == 0x7f || r == '\\' || (r >= 0x80 && r < 0xa0) {
			return false
		}
	}
	return true
}

// withOutcome appends auth=<code> to a validated return path, replacing an
// existing auth parameter.
func withOutcome(p, code string) string {
	path, query, _ := strings.Cut(p, "?")
	var keep []string
	if query != "" {
		for _, kv := range strings.Split(query, "&") {
			if k, _, _ := strings.Cut(kv, "="); k == "auth" || kv == "" {
				continue
			}
			keep = append(keep, kv)
		}
	}
	keep = append(keep, "auth="+code)
	return path + "?" + strings.Join(keep, "&")
}

// WelcomePath is the first-sign-in page (internal/webui, every enabled
// locale under its prefix). The OAuth callback sends a newly created account
// there instead of to its return path, which becomes ?next=.
const WelcomePath = "/welcome"

// LocalePrefixes are the URL prefixes of the site's non-primary locales
// (internal/webui/i18n/locales.json; a webui test keeps the two in step).
// WelcomeReturn keeps the locale of the return path with them.
var LocalePrefixes = []string{"ja", "ko", "es", "fr", "zh-hans", "zh-hant"}

// WelcomeReturn maps a validated return path to the welcome page in the
// same locale, carrying the return path as ?next= unless it is that
// locale's home: "/vuln/X" -> "/welcome?next=%2Fvuln%2FX",
// "/zh-hans/" -> "/zh-hans/welcome". A return path that is itself a welcome
// page (any locale, with or without a trailing slash) is not nested: its own
// next (validated again) is carried instead. Any auth= parameter is dropped
// from the carried path. The result passes SafeReturnPath; when the escaped
// return path would make it too long, next is left out.
func WelcomeReturn(ret string) string {
	ret = SafeReturnPath(ret)
	prefix := localePrefixOf(ret)
	w := prefix + WelcomePath
	if path, query, _ := strings.Cut(ret, "?"); path == w || path == w+"/" {
		q, _ := url.ParseQuery(query)
		ret = SafeReturnPath(q.Get("next"))
		if p, _, _ := strings.Cut(ret, "?"); strings.TrimSuffix(p, "/") == localePrefixOf(ret)+WelcomePath {
			ret = "/" // a welcome page again: no deeper
		}
	}
	ret = withoutAuth(ret)
	if ret == "/" || ret == prefix || ret == prefix+"/" {
		return w
	}
	if next := w + "?next=" + url.QueryEscape(ret); validReturnPath(next) {
		return next
	}
	return w
}

// localePrefixOf returns "/<prefix>" when the first segment of p is one of
// LocalePrefixes, else "".
func localePrefixOf(p string) string {
	seg, _, _ := strings.Cut(strings.TrimPrefix(p, "/"), "/")
	seg, _, _ = strings.Cut(seg, "?")
	for _, l := range LocalePrefixes {
		if seg == l {
			return "/" + l
		}
	}
	return ""
}

// withoutAuth drops every auth=<result> parameter from a validated path.
func withoutAuth(p string) string {
	path, query, ok := strings.Cut(p, "?")
	if !ok {
		return p
	}
	var keep []string
	for _, kv := range strings.Split(query, "&") {
		if k, _, _ := strings.Cut(kv, "="); k == "auth" || kv == "" {
			continue
		}
		keep = append(keep, kv)
	}
	if len(keep) == 0 {
		return path
	}
	return path + "?" + strings.Join(keep, "&")
}
