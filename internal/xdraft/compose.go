package xdraft

import (
	"net/url"
	"regexp"
	"strings"
)

// ComposeBase is X's web intent for composing a post, as documented at
// https://docs.x.com/x-for-websites/post-button/guides/web-intent ("Base
// URL: https://x.com/intent/tweet"; parameter text: "Pre-populated UTF-8
// and URL-encoded Post text"). The admin opens it in a new tab and presses
// Post on X; nothing is sent from the server.
const ComposeBase = "https://x.com/intent/tweet"

// ComposeText is what the post says: the body, a newline and the absolute
// URL of the vulnerability's detail page.
func ComposeText(body, link string) string { return body + "\n" + link }

// ComposeURL is the compose intent pre-filled with ComposeText, every byte
// outside [A-Za-z0-9-_.~] percent-encoded (spaces as %20, newlines as %0A).
func ComposeURL(body, link string) string {
	return ComposeBase + "?text=" + strings.ReplaceAll(url.QueryEscape(ComposeText(body, link)), "+", "%20")
}

var postURLRe = regexp.MustCompile(`^https://(?:www\.|mobile\.)?(?:x|twitter)\.com/([A-Za-z0-9_]{1,15})/status/([1-9][0-9]{0,19})/?(?:[?#][^\s]*)?$`)

// NormalizePostURL accepts the URL of a post on X — https://x.com/<handle>/
// status/<digits> or the same on twitter.com (www. and mobile. too) — and
// returns it as https://x.com/<handle>/status/<digits>. A trailing slash,
// a query ("?s=20", what X's share button adds) and a fragment are accepted
// and STRIPPED (never stored); a status id with a leading zero, an "i"
// handle, white space inside, another scheme, host or path: ok false.
func NormalizePostURL(s string) (string, bool) {
	m := postURLRe.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil || m[1] == "i" {
		return "", false
	}
	return "https://x.com/" + m[1] + "/status/" + m[2], true
}
