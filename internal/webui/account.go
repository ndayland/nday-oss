package webui

import (
	"net/http"
	"net/url"
	"sort"
	"strings"

	"nday.land/nday/internal/auth"
	"nday.land/nday/internal/webui/i18n"
)

// Sign-in pages and the top-bar account slot.
//
// The signed-in state never reaches the HTML: every page (including /login
// and /account) is the same for every visitor and stays publicly cacheable;
// nothing here reads the session cookie or goes through auth.Load. The page
// script asks GET /api/me (same origin) once per page view and fills the
// slot (static/app.js) or the account page (static/account.js). What the
// server knows at render time — which providers are enabled, whether
// passkeys and passkey sign-up are on — decides which controls exist.
//
// Words the scripts need are rendered into an inert
// <template id="acct-msgs"> as <span data-k="key">text</span> (select
// messages as key#value; placeholders stay as literal {name} for the script
// to fill with textContent). A message that falls back to English
// (i18n/pending.json) carries lang="en".

// Accounts is what the pages know about sign-in at render time. nil means
// accounts are disabled: no slot, no /login, no /account.
type Accounts struct {
	// Providers are the enabled providers in display order (auth.AllProviders).
	Providers []string
	// Passkeys: WebAuthn sign-in and passkey management are on.
	Passkeys bool
	// PasskeySignup: new passkey-only accounts may be created.
	PasskeySignup bool
	// MaxPasskeys per account (0 = unknown).
	MaxPasskeys int
	// TermsVersion is the configured community rules version
	// (NDAY_TERMS_VERSION; "" = none), shown on /rules.
	TermsVersion string
	// live, when set (AccountsOf), returns the values in force now: the
	// sign-in configuration can change while the site runs.
	live func() *Accounts
}

// Current returns the values to render with now (a, when it is fixed; nil
// for nil).
func (a *Accounts) Current() *Accounts {
	if a == nil || a.live == nil {
		return a
	}
	return a.live()
}

// AccountsOf describes an auth service for the pages (nil service: nil),
// following its configuration (auth.Service.Reconfigure): Current gives
// the values in force at render time.
func AccountsOf(svc *auth.Service) *Accounts {
	if svc == nil {
		return nil
	}
	now := func() *Accounts {
		cfg := svc.Config()
		return &Accounts{Providers: svc.Enabled(), Passkeys: cfg.Passkeys, PasskeySignup: cfg.Passkeys && cfg.PasskeySignup,
			MaxPasskeys: cfg.MaxPasskeys, TermsVersion: cfg.TermsVersion}
	}
	a := now()
	a.live = now
	return a
}

// providerNames are the brand names shown on the buttons (never translated).
var providerNames = map[string]string{auth.Google: "Google", auth.Apple: "Apple", auth.GitHub: "GitHub", auth.X: "X"}

// ProviderLink is one provider on the sign-in and account pages.
type ProviderLink struct {
	ID   string // google | apple | github | x
	Name string // brand name
	Href string // /auth/{id}/start?return=… (sign-in page only)
}

// ScriptMsg is one message for the page scripts.
type ScriptMsg struct{ Key, Text, Lang string }

// AcctView is the account part of every page when accounts are enabled.
type AcctView struct {
	LoginPath   string // localized /login
	LoginHref   string // localized /login?return=<this page> (the no-JS link)
	AccountPath string // localized /account
	Msgs        []ScriptMsg
	Script      bool // the page loads account.js
	Disc        bool // the page loads discuss.js
	Admin       bool // the page loads admin.js
	// AdminPath is the localized /admin when the back office exists: the
	// slot script adds a link there for staff accounts (the HTML is the
	// same for everyone).
	AdminPath string
}

// slotKeys are the messages app.js needs on every page.
var slotKeys = []string{"acct.slot.signin", "acct.slot.account", "acct.role.badge", "admin.slot",
	"acct.banner.ok", "acct.banner.linked", "acct.banner.denied", "acct.banner.conflict", "acct.banner.error",
	"acct.banner.signed_in_as_other", "acct.banner.reauth_required", "acct.banner.suspended", "acct.banner.dismiss"}

// pageKeys are the messages account.js needs on /login, /account and
// /welcome.
var pageKeys = []string{"acct.busy", "acct.save", "acct.cancel", "acct.yes", "acct.no",
	"acct.login.signed_in", "acct.page.unknown", "acct.role.name", "acct.profile.not_set",
	"acct.suspended.until", "acct.suspended.open", "acct.suspended.reason",
	"acct.handle.next", "acct.handle.saved",
	"acct.methods.linked", "acct.methods.linked_as", "acct.methods.not_linked", "acct.methods.unlinked",
	"acct.passkeys.never", "acct.passkeys.added", "acct.passkeys.rename", "acct.passkeys.rename_label",
	"acct.passkeys.renamed", "acct.passkeys.delete", "acct.passkeys.delete_confirm", "acct.passkeys.deleted",
	"acct.passkeys.unsupported",
	"acct.sessions.current", "acct.sessions.recent", "acct.sessions.not_recent", "acct.sessions.signed_out",
	"acct.sessions.signed_out_all",
	"acct.terms.accepted", "acct.terms.pending", "acct.terms.accept", "acct.terms.saved",
	"acct.delete.confirm_label", "acct.delete.done",
	"acct.reauth.provider", "acct.reauth.done", "acct.reauth.none",
	"acct.err.suspended", "acct.err.reauth_required", "acct.err.last_identity", "acct.err.last_usable_method",
	"acct.err.passkey_limit", "acct.err.passkey_exists", "acct.err.display_name_reserved", "acct.err.invalid_handle",
	"acct.err.handle_reserved", "acct.err.handle_taken", "acct.err.handle_change_too_soon", "acct.err.signup_limit",
	"acct.err.rate_limited", "acct.err.busy", "acct.err.csrf", "acct.err.ticket_invalid", "acct.err.cross_site",
	"acct.err.not_signed_in", "acct.err.webauthn_cancelled", "acct.err.ceremony_invalid", "acct.err.passkey_rejected",
	"acct.err.not_linked", "acct.err.not_found", "acct.err.terms_version_mismatch", "acct.err.network",
	"acct.err.generic",
	// follows (account page, welcome page)
	"acct.follows.remove", "acct.follows.remove_label", "acct.follows.saved",
	"acct.err.invalid_follow", "acct.err.too_many_follows",
	// welcome page
	"acct.welcome.handle_use", "acct.welcome.handle_ok", "acct.welcome.handle_empty",
	"acct.welcome.handle_current", "acct.welcome.follows_count", "acct.welcome.search_none",
	"acct.welcome.search_count", "acct.welcome.search_failed", "acct.welcome.rules_done", "acct.welcome.partial"}

// scriptMsgs renders keys for the scripts: placeholders stay "{name}",
// select messages become one entry per value ("key#value").
func scriptMsgs(set *i18n.Set, l *i18n.Locale, keys []string) []ScriptMsg {
	var out []ScriptMsg
	for _, k := range keys {
		def := set.Reference.Key(k)
		if def == nil {
			continue // TestKeyUsage reports it
		}
		var kv []any
		names := make([]string, 0, len(def.Placeholders))
		for n := range def.Placeholders {
			names = append(names, n)
		}
		sort.Strings(names)
		for _, n := range names {
			kv = append(kv, n, "{"+n+"}")
		}
		lang := ""
		if l.FallsBack(k) {
			lang = i18n.Primary
		}
		if def.Select != nil {
			for _, v := range def.Select.Values {
				out = append(out, ScriptMsg{Key: k + "#" + v, Text: l.Text(k, append(kv, def.Select.Var, v)...), Lang: lang})
			}
			continue
		}
		out = append(out, ScriptMsg{Key: k, Text: l.Text(k, kv...), Lang: lang})
	}
	return out
}

// acctView builds the account part of a page (nil when accounts are off).
func (u *UI) acctView(r *http.Request, loc *i18n.Locale, script, disc, adm bool) *AcctView {
	if u.opts.Accounts == nil {
		return nil
	}
	v := &AcctView{LoginPath: loc.Path("/login"), AccountPath: loc.Path("/account"), Script: script, Disc: disc, Admin: adm}
	if u.opts.Admin != nil {
		v.AdminPath = loc.Path("/admin")
	}
	v.LoginHref = v.LoginPath
	if ret := u.pageReturn(r); ret != "" {
		v.LoginHref += "?return=" + url.QueryEscape(ret)
	}
	keys := slotKeys
	if script {
		keys = append(append([]string(nil), slotKeys...), pageKeys...)
	}
	if disc {
		keys = append(append(append(append([]string(nil), keys...), discKeys...), rschKeys...), corrKeys...)
	}
	if adm {
		keys = append(append([]string(nil), keys...), adminKeys...)
	}
	v.Msgs = scriptMsgs(u.locales, loc, keys)
	return v
}

// pageReturn is the return target for the sign-in link of the current page:
// its path and query without the auth result parameter, if acceptable.
func (u *UI) pageReturn(r *http.Request) string {
	q := r.URL.Query()
	q.Del("auth")
	p := r.URL.Path
	if len(q) > 0 {
		p += "?" + q.Encode()
	}
	if ret := u.cleanReturn(p); ret != "" {
		return ret
	}
	return u.cleanReturn(r.URL.Path)
}

// cleanReturn accepts a return target that auth.SafeReturnPath (the
// server's own rule for post-sign-in targets) accepts, except a sign-in
// page. "" when not acceptable.
func (u *UI) cleanReturn(ret string) string {
	if ret == "" || u.isPage(ret, "/login") || auth.SafeReturnPath(ret) != ret {
		return ""
	}
	return ret
}

// isPage reports whether p (path[?query]) is page in some enabled locale.
func (u *UI) isPage(p, page string) bool {
	path, _, _ := strings.Cut(p, "?")
	for _, l := range u.locales.Enabled {
		if path == l.Path(page) {
			return true
		}
	}
	return false
}

// LoginData is the sign-in page's data.
type LoginData struct {
	Providers   []ProviderLink
	Passkeys    bool
	Signup      bool
	Return      string // where to continue ("" = home)
	ReturnText  string // Return as shown
	AccountPath string
	// Welcome is where a passkey sign-up continues: auth.WelcomeReturn of
	// Return, exactly where the OAuth callback sends a new account
	// (account.js navigates there).
	Welcome string
}

func (u *UI) login(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	a := u.opts.Accounts.Current()
	ret := u.cleanReturn(r.URL.Query().Get("return"))
	dest := ret
	if dest == "" {
		dest = loc.Home()
	}
	d := LoginData{Passkeys: a.Passkeys, Signup: a.PasskeySignup, Return: dest, ReturnText: dest,
		AccountPath: loc.Path("/account"), Welcome: auth.WelcomeReturn(dest)} // what the OAuth callback does
	for _, p := range a.Providers {
		d.Providers = append(d.Providers, ProviderLink{ID: p, Name: providerNames[p],
			Href: "/auth/" + p + "/start?" + url.Values{"return": {dest}}.Encode()})
	}
	p := &Page{Title: loc.Text("acct.login.title"), Description: loc.Text("acct.login.description"),
		Path: "~/login", Hints: helpHints(loc), NoIndex: true, AcctScript: true, Canonical: "/login", Data: d}
	w.Header().Set("X-Robots-Tag", "noindex")
	u.page(w, r, loc, http.StatusOK, "login", p)
}

// AccountData is the account page's data (no personal data: the script
// fills it from /api/me).
type AccountData struct {
	Providers   []ProviderLink
	Passkeys    bool
	MaxPasskeys int
	LoginHref   string
	Home        string
	WelcomeHref string // the welcome page (where follows are picked), back to here
}

func (u *UI) account(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	a := u.opts.Accounts.Current()
	d := AccountData{Passkeys: a.Passkeys, MaxPasskeys: a.MaxPasskeys, Home: loc.Home(),
		LoginHref:   loc.Path("/login") + "?return=" + url.QueryEscape(loc.Path("/account")),
		WelcomeHref: loc.Path(auth.WelcomePath) + "?next=" + url.QueryEscape(loc.Path("/account"))}
	for _, p := range a.Providers {
		d.Providers = append(d.Providers, ProviderLink{ID: p, Name: providerNames[p]})
	}
	w.Header().Set("X-Robots-Tag", "noindex")
	u.page(w, r, loc, http.StatusOK, "account", &Page{Title: loc.Text("acct.page.title"),
		Description: loc.Text("acct.page.description"), Path: "~/account", Hints: helpHints(loc), NoIndex: true,
		AcctScript: true, Canonical: "/account", Data: d})
}

// robotsAccounts are the robots.txt lines for the sign-in pages.
func (u *UI) robotsAccounts() string {
	if u.opts.Accounts == nil {
		return ""
	}
	var b strings.Builder
	b.WriteString("Disallow: /auth/\n")
	for _, l := range u.locales.Enabled {
		b.WriteString("Disallow: " + l.Path("/login") + "\n")
		b.WriteString("Disallow: " + l.Path("/account") + "\n")
		b.WriteString("Disallow: " + l.Path(auth.WelcomePath) + "\n")
	}
	return b.String()
}
