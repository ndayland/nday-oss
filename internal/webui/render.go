package webui

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"net/http"
	"strconv"
	"strings"

	"nday.land/nday/internal/webui/i18n"
)

// CSP is sent with every HTML response. Nothing inline is allowed: no style
// attributes, no <style>, no inline scripts or handlers (enforced by tests).
const CSP = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self' data:; font-src 'self'; " +
	"connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// Cache-Control values of HTML responses.
const (
	cachePage  = "public, max-age=60"
	cacheError = "no-store"
)

// Hint is a key hint of the bottom status bar.
type Hint struct{ Key, Text string }

// Alternate is one hreflang alternate of a page.
type Alternate struct{ Tag, Href string }

// LangLink is one entry of the language switcher: the same page (path and
// query) in another locale. Hint and Dismiss are that locale's own words
// for the optional "read this page in ..." line (app.js), Match the
// browser language tags that prefer it.
type LangLink struct {
	Tag, Name, Href string
	Current         bool
	Hint, Dismiss   string
	Match           string
}

// Page is what every template receives.
type Page struct {
	Title       string // <title>
	Description string // meta description
	Nav         string // hot | vuln | stats | src | about | ""
	Path        string // status bar path, "~/hot"
	Pos         string // status bar position, "1/50"
	PosID       bool   // Pos is updated by the cursor script
	Hints       []Hint
	Status      *StatusLine
	Query       string // search box value
	AutoSelect  bool   // select the first row on load (list pages)
	CopyID      string // what "y" copies when no row is selected
	Up          string // where "u" goes when there is no same-site history
	// Canonical: set by handlers as the locale-neutral path+query; page()
	// replaces it with the absolute URL of the page's own locale.
	Canonical  string
	OGImage    string // absolute URL of the share card; page() sets the static one unless the handler set one (vuln)
	Data       any
	L          *i18n.Locale
	Lang       string // BCP 47 tag for <html lang>
	Alternates []Alternate
	XDefault   string
	Switch     []LangLink
	// Accounts (set by page() when accounts are enabled; see account.go).
	NoIndex    bool // robots noindex (sign-in pages)
	AcctScript bool // load account.js and its messages
	DiscScript bool // load discuss.js and its messages (vulnerability pages with accounts: researcher posts, discussions)
	// Admin pages (admin.go): Personal makes the page no-store without
	// validators, canonical link or hreflang alternates; AdminScript loads
	// admin.js and its messages.
	Personal    bool
	AdminScript bool
	Acct        *AcctView
	// Tag filters (tagview.go): SearchTags keep the search page's tag filter
	// in the search box form.
	SearchTags []string
	// siteIcons: put the site icon in front of every link that leaves the
	// site (the vulnerability page; siteicons.go).
	siteIcons bool
	// Landing: the search-only state of /vuln (catalogue.go isCatLanding).
	// The body gets class "landing" (full-screen search, no status bar,
	// app.css), the header menus sit in a disclosure (details.topm) that
	// folds on phones, and the header search box is left out (the page's
	// own box is the search). Every other page renders as before.
	Landing bool
}

// renderer holds the parsed page templates, one set per locale (the
// message functions are bound to the locale).
type renderer struct {
	pages map[string]map[string]*template.Template // tag -> page -> template
	debug *template.Template
}

var pageNames = []string{"hot", "discussed", "vuln", "search", "catalogue", "src", "stats", "about", "error", "login", "account", "welcome", "rules", "tags",
	"admin_stats", "admin_mod", "admin_users", "admin_user", "admin_system", "admin_audit", "admin_x", "admin_xdrafts",
	"admin_settings", "admin_corr", "admin_github", "admin_titles"}

// localeFuncs are the template functions bound to a locale:
//
//	t "key" "name" value ...   message as HTML (values escaped; template.HTML values inserted)
//	ts "key" ...               message as plain text (attributes, <title>)
//	href "/src"                locale-prefixed site path
//	num 45965                  number with the locale's grouping
//	links "and" .Links         links joined with the locale's list pattern
//	upstream .Text             upstream (English) text, marked lang="en" outside English
//	tagname / tagnames .Slug   a tag's name as HTML / text (product tags: the English product name)
//	tagdesc / tagdescs .Slug   a tag's one-sentence description as HTML / text
//	fallbacklang "key"         the primary locale's tag when key falls back to it (pending), else ""
func localeFuncs(l *i18n.Locale) template.FuncMap {
	return template.FuncMap{
		"t":        l.HTML,
		"ts":       l.Text,
		"href":     l.Path,
		"num":      func(n int) string { return l.Int(int64(n)) },
		"links":    func(kind string, ls []Link) template.HTML { return linkList(l, kind, ls) },
		"upstream": func(s string) template.HTML { return template.HTML(l.UpstreamHTML(s)) },
		"tagname":  func(slug string) template.HTML { return tagNameHTML(l, slug) },
		"tagnames": func(slug string) string { return tagNameText(l, slug) },
		"tagdesc":  func(slug string) template.HTML { return tagDescHTML(l, slug) },
		"tagdescs": func(slug string) string { return tagDescText(l, slug) },
		"fallbacklang": func(key string) string {
			if l.FallsBack(key) {
				return i18n.Primary
			}
			return ""
		},
	}
}

func newRenderer(assets *Assets, set *i18n.Set) (*renderer, error) {
	return newRendererIcons(assets, set, TagIconMode)
}

// newRendererIcons is newRenderer with a tag icon rendering (TagIconUse or
// TagIconMask; tests render both).
func newRendererIcons(assets *Assets, set *i18n.Set, iconMode string) (*renderer, error) {
	funcs := template.FuncMap{
		"asset":   assets.URL,
		"list3":   func(a, b, c string) []string { return []string{a, b, c} },
		"join":    strings.Join,
		"kbd":     func(s string) template.HTML { return template.HTML("<kbd>" + template.HTMLEscapeString(s) + "</kbd>") },
		"code":    codeHTML,
		"stage":   stageCodeHTML,
		"a":       anchorHTML,
		"contact": contactHTML,
		"path":    pathHTML,
	}
	// tagicon .Slug: the icon's symbol id, "" for none; tagiconmask: the mask
	// rendering is on (parts.tmpl "tagicon", base.tmpl; tagicons.go)
	funcs["tagicon"] = tagIcon
	funcs["tagiconmask"] = func() bool { return iconMode == TagIconMask }
	for k, v := range localeFuncs(set.Primary()) { // parse-time stand-ins
		funcs[k] = v
	}
	base, err := template.New("base").Funcs(funcs).ParseFS(templateFS, "templates/base.tmpl", "templates/parts.tmpl",
		"templates/corrections.tmpl")
	if err != nil {
		return nil, err
	}
	parsed := map[string]*template.Template{}
	for _, name := range pageNames {
		t, err := base.Clone()
		if err != nil {
			return nil, err
		}
		b, err := fs.ReadFile(templateFS, "templates/"+name+".tmpl")
		if err != nil {
			return nil, err
		}
		if _, err := t.Parse(string(b)); err != nil {
			return nil, fmt.Errorf("%s: %w", name, err)
		}
		parsed[name] = t
	}
	r := &renderer{pages: map[string]map[string]*template.Template{}}
	for _, l := range set.Enabled {
		m := map[string]*template.Template{}
		for name, t := range parsed {
			c, err := t.Clone()
			if err != nil {
				return nil, err
			}
			m[name] = c.Funcs(localeFuncs(l))
		}
		r.pages[l.Tag] = m
	}
	dt, err := template.New("i18n").Funcs(funcs).ParseFS(templateFS, "templates/debug/i18n.tmpl")
	if err != nil {
		return nil, err
	}
	r.debug = dt
	return r, nil
}

// render executes a page into bytes.
func (r *renderer) render(l *i18n.Locale, name string, p *Page) ([]byte, error) {
	t, ok := r.pages[l.Tag][name]
	if !ok {
		return nil, fmt.Errorf("webui: no page %q for %s", name, l.Tag)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, "base.tmpl", p); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// codeHTML is <code>s</code> (escaped), for placeholders.
func codeHTML(s string) template.HTML {
	return template.HTML("<code>" + template.HTMLEscapeString(s) + "</code>")
}

// stageCodeHTML is a coloured stage code (DIS, +KEV, ~ITW) for placeholders.
func stageCodeHTML(code string) template.HTML {
	c := strings.TrimLeft(code, "+~")
	return template.HTML(`<span class="b ` + StageClass(c) + `">` + template.HTMLEscapeString(code) + `</span>`)
}

// anchorHTML is an internal link for placeholders (href must be a site path).
func anchorHTML(href, text string) template.HTML {
	return template.HTML(`<a href="` + template.HTMLEscapeString(href) + `">` + template.HTMLEscapeString(text) + `</a>`)
}

// pathHTML is a site path token for placeholders ("~/hot"): the "~/" prefix
// is decoration, hidden from assistive technology, so a link reads as its
// word alone.
func pathHTML(p string) template.HTML {
	if rest, ok := strings.CutPrefix(p, "~/"); ok {
		return template.HTML(`<span aria-hidden="true">~/</span>` + template.HTMLEscapeString(rest))
	}
	return template.HTML(template.HTMLEscapeString(p))
}

// ContactEmail is the site's public contact address (about and rules pages).
const ContactEmail = "connect@nday.land"

// contactHTML is ContactEmail as a mailto link, for placeholders.
func contactHTML() template.HTML {
	return template.HTML(`<a href="mailto:` + ContactEmail + `">` + ContactEmail + `</a>`)
}

// linkHTML renders a Link like the "link" template.
func linkHTML(l Link) template.HTML {
	lang := ""
	if l.Lang != "" {
		lang = ` lang="` + template.HTMLEscapeString(l.Lang) + `"`
	}
	if l.Href == "" {
		return template.HTML("<span" + lang + ">" + template.HTMLEscapeString(l.Text) + "</span>")
	}
	rel := ""
	if l.External {
		rel = ` target="_blank" rel="noopener noreferrer"`
	}
	return template.HTML(`<a href="` + template.HTMLEscapeString(l.Href) + `"` + rel + lang + `>` + template.HTMLEscapeString(l.Text) + `</a>`)
}

// linkList joins links with a list pattern of the locale.
func linkList(l *i18n.Locale, kind string, ls []Link) template.HTML {
	hs := make([]template.HTML, len(ls))
	for i, x := range ls {
		hs[i] = linkHTML(x)
	}
	return l.ListHTML(kind, hs)
}

func htmlUnescape(s string) string { return html.UnescapeString(s) }

// setHTMLHeaders sets the headers every HTML response carries.
func setHTMLHeaders(h http.Header) {
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Content-Security-Policy", CSP)
	h.Set("X-Frame-Options", "DENY")
	h.Set("Cross-Origin-Opener-Policy", "same-origin")
}

// writeHTML writes an HTML body with a weak ETag; 200 answers
// If-None-Match with 304. Non-200 responses are never cached.
func writeHTML(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	h := w.Header()
	setHTMLHeaders(h)
	if status != http.StatusOK {
		h.Set("Cache-Control", cacheError)
		h.Del("ETag")
	} else {
		h.Set("Cache-Control", cachePage)
		sum := sha256.Sum256(body)
		etag := `W/"` + hex.EncodeToString(sum[:12]) + `"`
		h.Set("ETag", etag)
		if etagMatch(r.Header.Get("If-None-Match"), etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
	}
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// writePersonal writes a page that belongs to the signed-in visitor (the
// admin pages): never cacheable, no validators, never a 304.
func writePersonal(w http.ResponseWriter, r *http.Request, status int, body []byte) {
	h := w.Header()
	setHTMLHeaders(h)
	h.Set("Cache-Control", cacheError)
	h.Del("ETag")
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(body)
	}
}

// etagMatch is the weak comparison of If-None-Match.
func etagMatch(header, etag string) bool {
	if header == "" {
		return false
	}
	norm := func(s string) string { return strings.TrimPrefix(strings.TrimSpace(s), "W/") }
	for _, t := range strings.Split(header, ",") {
		if strings.TrimSpace(t) == "*" || norm(t) == norm(etag) {
			return true
		}
	}
	return false
}
