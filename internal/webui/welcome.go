package webui

import (
	"net/http"
	"net/url"
	"path"
	"strings"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/webui/i18n"
)

// The first-sign-in page /welcome (docs/auth.md §3.4, docs/follows.md).
//
// The OAuth callback sends a newly created account here (auth.WelcomeReturn,
// with the original return path as ?next=), and account.js does the same
// after a passkey sign-up. Like /login and /account the HTML is the same for
// every visitor (publicly cacheable, noindex); account.js fills it from
// /api/me and saves what the user chose. Everything on it is optional.

// FollowPreset is one ready-made follow button: Label is what is shown and
// saved, Term its key (lower-case Label), the exact lower-cased vendor or
// product name in the affected table (see docs/follows.md for which were
// checked against data).
type FollowPreset struct{ Label, Term string }

// followPresets is the one list of preset follows: brand names, never
// translated, each exactly a vendor or product name of the affected table
// ("Linux": the kernel CNA records vendor and product "Linux"). The term is
// the label in lower case, like a follow saved through POST /account/follows.
var followPresets = presets("Linux", "Windows", "Chrome", "iOS and iPadOS", "macOS", "Android", "OpenSSH",
	"Fortinet", "Ivanti", "Cisco", "Palo Alto Networks", "Citrix", "VMware", "Atlassian", "GitLab", "Kubernetes",
	"WordPress")

func presets(labels ...string) []FollowPreset {
	out := make([]FollowPreset, len(labels))
	for i, l := range labels {
		out[i] = FollowPreset{Label: l, Term: strings.ToLower(l)}
	}
	return out
}

// FollowPresets returns a copy of the preset list (tests, docs).
func FollowPresets() []FollowPreset { return append([]FollowPreset(nil), followPresets...) }

// scribbleWords are the lengths of the meaningless filler words of the
// signed-out sample (their glyphs are invisible; CSS draws a wavy stroke).
var scribbleWords = []int{3, 6, 2, 8, 4, 5, 9, 3, 7, 2, 6, 4, 8, 5, 3, 7, 4}

// WelcomeData is the welcome page's data (no personal data).
type WelcomeData struct {
	Presets   []FollowPreset
	Next      string // validated ?next= ("" = none)
	Dest      string // where "done" and "skip" go: Next or the locale's home
	LoginHref string
	Rules     bool     // a terms version is configured: show the rules section
	Scribble  []string // filler words of the signed-out sample
	// DiscussDemo shows the side block comparing a practitioner post as a
	// signed-out and a signed-in visitor see it. Off until posts are shown to
	// signed-in users at all (docs/xposts.md): the block would promise a
	// feature that does not exist yet.
	DiscussDemo bool
	Providers   []ProviderLink
}

// welcomeNext validates ?next= like a sign-in return path (cleanReturn) and
// also refuses a path that is not in canonical form (empty or dot segments,
// "//"; one trailing slash is fine) and every spelling of the welcome page
// itself: "done" must never come back here. "" = none.
func (u *UI) welcomeNext(raw string) string {
	next := u.cleanReturn(raw)
	if next == "" {
		return ""
	}
	p, _, _ := strings.Cut(next, "?")
	clean := path.Clean(p)
	if p != "/" && clean != strings.TrimSuffix(p, "/") {
		return ""
	}
	if u.isPage(clean, auth.WelcomePath) {
		return ""
	}
	return next
}

func (u *UI) welcome(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	a := u.opts.Accounts.Current()
	next := u.welcomeNext(r.URL.Query().Get("next"))
	d := WelcomeData{Presets: followPresets, Next: next, Dest: next, Rules: a.TermsVersion != ""}
	if d.Dest == "" {
		d.Dest = loc.Home()
	}
	ret := loc.Path(auth.WelcomePath)
	if next != "" {
		ret += "?next=" + url.QueryEscape(next)
	}
	d.LoginHref = loc.Path("/login") + "?return=" + url.QueryEscape(ret)
	for _, p := range a.Providers {
		d.Providers = append(d.Providers, ProviderLink{ID: p, Name: providerNames[p]})
	}
	for _, n := range scribbleWords {
		d.Scribble = append(d.Scribble, strings.Repeat("x", n))
	}
	w.Header().Set("X-Robots-Tag", "noindex")
	u.page(w, r, loc, http.StatusOK, "welcome", &Page{Title: loc.Text("acct.welcome.title"),
		Description: loc.Text("acct.welcome.description"), Path: "~/welcome", Hints: helpHints(loc), NoIndex: true,
		AcctScript: true, Canonical: auth.WelcomePath, Data: d})
}
