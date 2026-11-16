package webui

import (
	"context"
	"html/template"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"nday.land/nday/internal/classify"
	"nday.land/nday/internal/site"
	"nday.land/nday/internal/tags"
	"nday.land/nday/internal/webui/i18n"
)

// Tags on pages (docs/tags.md §7). Slugs and labels come from the fixed
// vocabulary (internal/tags) and the catalogs (tag.name, tag.desc, tag.dim);
// a basis holds CWE ids, CVSS vectors and source names validated upstream,
// and upstream strings (CNA names, module names, package names) that are
// rendered as inert text (escaped, bidi controls neutralised, isolated in
// <bdi>). Every tag is presented as nday's derivation, never as a source's.

// TagChip is one tag shown as a link.
type TagChip struct {
	Slug   string
	Class  string // "tg", plus "tg-s" (strong), "tg-rw" (ransomware) and tg-c-<category> (typeCategory)
	Href   string // tag page or "add this filter" link
	Strong bool   // drawn with more weight (remote-unauth, ransomware)
	Remove string // active filter chips: the same list without this tag
}

func chip(slug, href string) TagChip {
	t, _ := tags.Lookup(slug)
	c := TagChip{Slug: slug, Href: href, Strong: t.Strong, Class: "tg"}
	if t.Strong {
		c.Class += " tg-s"
	}
	if t.Dim == tags.DimExploit && slug == "ransomware" {
		c.Class += " tg-rw"
	}
	if cat, ok := typeCategory[slug]; ok && t.Dim == tags.DimType {
		c.Class += " tg-c-" + cat
	}
	return c
}

// typeCategory groups weakness-type tags for colour only (class tg-c-<cat>,
// app.css): exec leads to running the attacker's code, mem is memory
// corruption, authz authentication and privileges, web injection and
// request-side web flaws. Presentation only: the label still names the tag.
// Type tags not listed here, and every other dimension, stay neutral.
var typeCategory = map[string]string{
	"command-injection": "exec", "code-injection": "exec", "deserialization": "exec",
	"template-injection": "exec", "file-upload": "exec", "file-inclusion": "exec",

	"buffer-overflow": "mem", "use-after-free": "mem", "double-free": "mem", "out-of-bounds-read": "mem",
	"type-confusion": "mem", "integer-overflow": "mem", "format-string": "mem", "uninitialized-memory": "mem",

	"auth-bypass": "authz", "broken-access-control": "authz", "privilege-management": "authz",
	"hardcoded-credentials": "authz", "session-management": "authz",

	"sql-injection": "web", "xss": "web", "csrf": "web", "ssrf": "web", "xxe": "web", "path-traversal": "web",
	"prototype-pollution": "web", "request-smuggling": "web", "crlf-injection": "web", "open-redirect": "web",
}

// Tag names and descriptions. Product tags (dimension product) are the
// exception to the catalog: their name is the English product name (the Go
// label, the same in every locale) and their description is the one
// parameterised message tags.KeyProductDesc; every other tag reads the
// tag.name / tag.desc select messages.

// (The keys are written out, not tags.KeyName / KeyDesc / KeyProductDesc,
// so that TestKeyUsage sees them; TestTagVocabularyMatchesCatalogs checks
// the constants have these values.)

// tagNameText is the display name of slug as plain text.
func tagNameText(l *i18n.Locale, slug string) string {
	if t, ok := tags.Lookup(slug); ok && t.Dim == tags.DimProduct {
		return t.Label
	}
	return l.Text("tag.name", tags.SelectTag, slug)
}

// tagNameHTML is the display name of slug as HTML.
func tagNameHTML(l *i18n.Locale, slug string) template.HTML {
	if t, ok := tags.Lookup(slug); ok && t.Dim == tags.DimProduct {
		return template.HTML(template.HTMLEscapeString(t.Label))
	}
	return l.HTML("tag.name", tags.SelectTag, slug)
}

// tagDescText is the one-sentence description of slug as plain text.
func tagDescText(l *i18n.Locale, slug string) string {
	if t, ok := tags.Lookup(slug); ok && t.Dim == tags.DimProduct {
		return l.Text("tag.desc_product", "name", t.Label)
	}
	return l.Text("tag.desc", tags.SelectTag, slug)
}

// tagDescHTML is the one-sentence description of slug as HTML.
func tagDescHTML(l *i18n.Locale, slug string) template.HTML {
	if t, ok := tags.Lookup(slug); ok && t.Dim == tags.DimProduct {
		return l.HTML("tag.desc_product", "name", t.Label)
	}
	return l.HTML("tag.desc", tags.SelectTag, slug)
}

// tagPath is the locale-neutral path of a tag page.
func tagPath(slug string) string { return "/tag/" + slug }

// bidiControls are neutralised in upstream text shown inside a basis.
var bidiControls = strings.NewReplacer(
	"‪", "�", "‫", "�", "‬", "�", "‭", "�", "‮", "�",
	"⁦", "�", "⁧", "�", "⁨", "�", "⁩", "�",
	"‎", "�", "‏", "�", "؜", "�")

// inertHTML renders upstream text as inert, isolated text.
func inertHTML(s string) template.HTML {
	return template.HTML("<bdi>" + template.HTMLEscapeString(bidiControls.Replace(truncRunes(s, 120))) + "</bdi>")
}

// inertCode is inertHTML in a <code> (keys, vectors).
func inertCode(s string) template.HTML {
	return template.HTML("<code>" + string(inertHTML(s)) + "</code>")
}

// TagGroup is the tags of one dimension.
type TagGroup struct {
	Dim  string
	Tags []TagChip
}

// TagWhy is one line of "why these tags": the tag and what it rests on.
type TagWhy struct {
	Chip  TagChip
	Basis []template.HTML
}

// VulnTags is the tags block of a vulnerability page.
type VulnTags struct {
	Groups []TagGroup
	Why    []TagWhy
	// V2: an access tag rests on a CVSS 2.0 vector (show the caveat).
	V2 bool
}

// BuildVulnTags builds the tags block (nil when the CVE has no tags).
func BuildVulnTags(l *i18n.Locale, vs []tags.View) *VulnTags {
	if len(vs) == 0 {
		return nil
	}
	vt := &VulnTags{}
	seen := map[string]int{} // slug -> index in Why
	for _, v := range vs {
		c := chip(v.Slug, l.Path(tagPath(v.Slug)))
		i, ok := seen[v.Slug]
		if !ok {
			i = len(vt.Why)
			seen[v.Slug] = i
			vt.Why = append(vt.Why, TagWhy{Chip: c})
			if n := len(vt.Groups); n == 0 || vt.Groups[n-1].Dim != v.Dimension {
				vt.Groups = append(vt.Groups, TagGroup{Dim: v.Dimension})
			}
			g := &vt.Groups[len(vt.Groups)-1]
			g.Tags = append(g.Tags, c)
		}
		b := v.Decoded()
		lines := basisLines(l, v.Origin, b)
		if b.CVSS != nil && b.CVSS.Version == classify.V2 {
			vt.V2 = true
		}
		vt.Why[i].Basis = append(vt.Why[i].Basis, lines...)
	}
	return vt
}

// provenanceHTML names where a fact came from ("the CNA (mitre)", "NVD's
// analysts"), from the catalog.
func provenanceHTML(l *i18n.Locale, p classify.Provenance) template.HTML {
	src := p.Source
	switch src {
	case classify.SrcCNA, classify.SrcADP, classify.SrcNVDPrimary, classify.SrcNVDSecondary, classify.SrcGHSA:
	default:
		src = "other"
	}
	return l.HTML("tag.source", "source", src, "org", inertHTML(p.SourceOrg))
}

// basisLines renders a basis as one line per fact.
func basisLines(l *i18n.Locale, origin string, b tags.Basis) []template.HTML {
	var out []template.HTML
	for _, c := range b.CWE {
		ps := make([]template.HTML, len(c.Sources))
		for i, p := range c.Sources {
			ps[i] = provenanceHTML(l, p)
		}
		out = append(out, l.HTML("tag.basis.cwe", "cwe", linkHTML(CWELink(c.ID)), "sources", l.ListHTML(i18n.ListAnd, ps)))
	}
	if v := b.CVSS; v != nil {
		ms := make([]template.HTML, len(v.Metrics))
		for i, m := range v.Metrics {
			ms[i] = inertCode(m)
		}
		out = append(out, l.HTML("tag.basis.cvss", "metrics", l.ListHTML(i18n.ListSeq, ms), "vector", inertCode(v.Vector),
			"version", v.Version, "source", provenanceHTML(l, classify.Provenance{Source: v.Source, SourceOrg: v.SourceOrg})))
	}
	for _, e := range b.Events {
		switch {
		case e.Source == tags.SrcKEV:
			out = append(out, l.HTML("tag.basis.kev", "value", inertCode(e.KnownRansomwareCampaignUse)))
		default:
			src := e.Source
			if src != tags.SrcExploitDB && src != tags.SrcMetasploit && src != tags.SrcNuclei {
				continue
			}
			ks := make([]template.HTML, len(e.Keys))
			for i, k := range e.Keys {
				ks[i] = inertCode(k)
			}
			if more := e.Count - len(e.Keys); more > 0 {
				out = append(out, l.HTML("tag.basis.poc_more", "source", src, "keys", l.ListHTML(i18n.ListSeq, ks), "more", more))
				continue
			}
			out = append(out, l.HTML("tag.basis.poc", "source", src, "keys", l.ListHTML(i18n.ListSeq, ks)))
		}
	}
	for _, a := range b.Advisories {
		ps := make([]template.HTML, len(a.Packages))
		for i, p := range a.Packages {
			ps[i] = inertCode(p)
		}
		adv := linkHTML(AliasLink(a.ID, "ghsa"))
		if len(ps) == 0 {
			out = append(out, l.HTML("tag.basis.ghsa_nopkg", "advisory", adv, "ecosystem", inertCode(a.Ecosystem)))
			continue
		}
		out = append(out, l.HTML("tag.basis.ghsa", "advisory", adv, "ecosystem", inertCode(a.Ecosystem),
			"packages", l.ListHTML(i18n.ListSeq, ps)))
	}
	out = append(out, productBasisLines(l, b)...)
	if len(out) == 0 {
		out = append(out, l.HTML("tag.basis.none", "origin", origin))
	}
	return out
}

// productBasisLines renders the evidence of a product or product-type tag:
// the affected rows (as the CVE record states them), the vulnerable CPE
// names (attributed to NVD's analysts, who give them; the tag is nday's),
// and for a product-type tag the products and type rules that gave it.
func productBasisLines(l *i18n.Locale, b tags.Basis) []template.HTML {
	var out []template.HTML
	more := func(line template.HTML, total, shown int) template.HTML {
		if n := total - shown; n > 0 {
			return l.HTML("tag.basis.more", "list", line, "more", n)
		}
		return line
	}
	if len(b.Affected) > 0 {
		rows := make([]template.HTML, len(b.Affected))
		for i, a := range b.Affected {
			rows[i] = inertHTML(a.Vendor) + " · " + inertHTML(a.Product)
		}
		out = append(out, more(l.HTML("tag.basis.affected", "rows", l.ListHTML(i18n.ListSeq, rows)), b.AffectedCount, len(b.Affected)))
	}
	if len(b.CPE) > 0 {
		cs := make([]template.HTML, len(b.CPE))
		for i, c := range b.CPE {
			cs[i] = inertCode(c.Part + ":" + c.Vendor + ":" + c.Product)
		}
		out = append(out, more(l.HTML("tag.basis.cpe", "cpes", l.ListHTML(i18n.ListSeq, cs)), b.CPECount, len(b.CPE)))
	}
	if len(b.Products) > 0 {
		ps := make([]template.HTML, 0, len(b.Products))
		for _, s := range b.Products {
			if !tags.Valid(s) {
				continue
			}
			ps = append(ps, template.HTML(`<a href="`+template.HTMLEscapeString(l.Path(tagPath(s)))+`">`)+tagNameHTML(l, s)+"</a>")
		}
		if len(ps) > 0 {
			out = append(out, l.HTML("tag.basis.products", "products", l.ListHTML(i18n.ListAnd, ps)))
		}
	}
	if len(b.TypeRules) > 0 {
		rs := make([]template.HTML, len(b.TypeRules))
		for i, r := range b.TypeRules {
			rs[i] = inertCode(r)
		}
		out = append(out, l.HTML("tag.basis.type_rule", "rules", l.ListHTML(i18n.ListSeq, rs)))
	}
	return out
}

// RowChips are the at most three tags a list row shows (tags.RowPicks),
// each linking to href(slug) (the list filtered by it).
func RowChips(slugs []string, href func(string) string) []TagChip {
	var out []TagChip
	for _, s := range tags.RowPicks(slugs) {
		out = append(out, chip(s, href(s)))
	}
	return out
}

// withTag returns slugs plus s, canonical (vocabulary order, deduplicated).
func withTag(slugs []string, s string) []string {
	out, _ := tags.ParseFilter(append(append([]string(nil), slugs...), s))
	return out
}

// withoutTag returns slugs without s.
func withoutTag(slugs []string, s string) []string {
	var out []string
	for _, x := range slugs {
		if x != s {
			out = append(out, x)
		}
	}
	return out
}

// tagQuery renders "tag=a&tag=b".
func tagQuery(slugs []string) string {
	parts := make([]string, len(slugs))
	for i, s := range slugs {
		parts[i] = "tag=" + url.QueryEscape(s)
	}
	return strings.Join(parts, "&")
}

// ---------------------------------------------------------------- /tags

// TagsPageRow is one vocabulary entry on /tags.
type TagsPageRow struct {
	Chip  TagChip
	Count string
	Zero  bool
}

// TagsPageTop is how many tags of a dimension /tags shows before folding
// the rest away.
const TagsPageTop = 20

// TagsPageGroup is one dimension on /tags. A dimension with more than
// TagsPageTop tags is ordered by count (most CVEs first, ties in vocabulary
// order): Rows holds the first TagsPageTop and More the rest, which the
// page folds into a <details>. Smaller dimensions keep the vocabulary order
// and have no More.
type TagsPageGroup struct {
	Dim  string
	Rows []TagsPageRow
	More []TagsPageRow
}

// TagsPage is the /tags page.
type TagsPage struct {
	Groups   []TagsPageGroup
	CountsAt template.HTML // convertible <time>, "" when never computed
	Curl     CmdLine
}

func (u *UI) tagsReport(ctx context.Context) (*site.TagsReport, error) {
	v, err := u.cached(ctx, "tags", func(ctx context.Context) (any, error) { return u.srv.Store.Tags(ctx) })
	if err != nil {
		return nil, err
	}
	return v.(*site.TagsReport), nil
}

// BuildTagsPage builds /tags from the vocabulary and the counts.
func BuildTagsPage(l *i18n.Locale, rep *site.TagsReport, api API) TagsPage {
	p := TagsPage{Curl: CurlCmd(api.URL("/tags"), ".tags")}
	if rep.CountsAt != nil {
		p.CountsAt = minuteHTML(rep.CountsAt)
	}
	for _, d := range tags.Dimensions {
		g := TagsPageGroup{Dim: d}
		var counts []int64
		for _, ti := range rep.Tags {
			if ti.Dimension != d {
				continue
			}
			g.Rows = append(g.Rows, TagsPageRow{Chip: chip(ti.Slug, l.Path(tagPath(ti.Slug))), Count: l.Int(ti.Count), Zero: ti.Count == 0})
			counts = append(counts, ti.Count)
		}
		if len(g.Rows) > TagsPageTop {
			idx := make([]int, len(g.Rows))
			for i := range idx {
				idx[i] = i
			}
			sort.SliceStable(idx, func(a, b int) bool { return counts[idx[a]] > counts[idx[b]] })
			rows := make([]TagsPageRow, len(idx))
			for i, j := range idx {
				rows[i] = g.Rows[j]
			}
			g.Rows, g.More = rows[:TagsPageTop], rows[TagsPageTop:]
		}
		p.Groups = append(p.Groups, g)
	}
	return p
}

func (u *UI) tagsPage(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	rep, err := u.tagsReport(r.Context())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	d := BuildTagsPage(loc, rep, u.api)
	u.page(w, r, loc, http.StatusOK, "tags", &Page{Title: loc.Text("tag.page.title"),
		Description: loc.Text("tag.page.description"),
		Nav:         "", Path: "~/tags", Pos: loc.Text("tag.sbar", "n", len(tags.Vocabulary)), Hints: helpHints(loc),
		RawHref: u.api.Href("/tags"), Canonical: "/tags", Data: d})
}

// ---------------------------------------------------------- /tag/{slug}

// TagHead heads the hot list on a tag page.
type TagHead struct {
	Slug     string
	Dim      string
	Count    int64
	CountsAt template.HTML
	CWEs     template.HTML // type tags: the CWE ids that assign it (links)
	All      string        // /tags
	Feed     string        // the feed of this list
}

func (u *UI) tagPage(w http.ResponseWriter, r *http.Request, loc *i18n.Locale) {
	slug := r.PathValue("slug")
	t, ok := tags.Lookup(slug)
	if !ok {
		if low := strings.ToLower(slug); low != slug && tags.Valid(low) {
			to := loc.Path(tagPath(low))
			if r.URL.RawQuery != "" {
				to += "?" + r.URL.RawQuery
			}
			http.Redirect(w, r, to, http.StatusMovedPermanently)
			return
		}
		u.notFound(w, r, loc)
		return
	}
	f, err := parseHotFilters(r.URL.Query())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	f.Fixed = t.Slug
	f.Tags = withoutTag(f.Tags, t.Slug)
	rep, err := u.tagsReport(r.Context())
	if err != nil {
		u.fail(w, r, loc, err)
		return
	}
	head := &TagHead{Slug: t.Slug, Dim: t.Dim, Count: rep.CountsOf(t.Slug), All: loc.Path("/tags"),
		Feed: loc.Path("/feed.xml") + "?" + tagQuery(f.AllTags())}
	if rep.CountsAt != nil {
		head.CountsAt = minuteHTML(rep.CountsAt)
	}
	if len(t.CWEs) > 0 {
		ls := make([]Link, len(t.CWEs))
		for i, id := range t.CWEs {
			ls[i] = CWELink("CWE-" + strconv.Itoa(id))
		}
		head.CWEs = linkList(loc, i18n.ListSeq, ls)
	}
	u.hotList(w, r, loc, f, head)
}

// ------------------------------------------------------------- /vuln

// searchHref is the locale-neutral search URL for q and tag filters.
func searchHref(q string, ts []string) string {
	var parts []string
	if q != "" {
		parts = append(parts, "q="+url.QueryEscape(q))
	}
	if len(ts) > 0 {
		parts = append(parts, tagQuery(ts))
	}
	if len(parts) == 0 {
		return "/vuln"
	}
	return "/vuln?" + strings.Join(parts, "&")
}

// searchAPIPath is the API path of a search.
func searchAPIPath(q string, ts []string) string {
	parts := []string{"q=" + url.QueryEscape(q)}
	if len(ts) > 0 {
		parts = append(parts, tagQuery(ts))
	}
	return "/search?" + strings.Join(parts, "&")
}

// addSearchTags adds the tag filter to the search page: active chips, row
// chips (each adds its tag to the filter, keeping the query) and the API
// command with the tags.
func addSearchTags(l *i18n.Locale, sv *SearchView, q string, ts []string, res *site.SearchResult, api API) {
	sv.TagsHref = l.Path("/tags")
	for _, s := range ts {
		c := chip(s, l.Path(tagPath(s)))
		c.Remove = l.Path(searchHref(q, withoutTag(ts, s)))
		sv.Chips = append(sv.Chips, c)
	}
	if res == nil {
		return
	}
	if len(ts) > 0 {
		sv.Curl = CurlCmd(api.URL(searchAPIPath(res.Query, ts)), ".rows")
	}
	for i := range sv.Rows {
		if i < len(res.Rows) {
			sv.Rows[i].Tags = RowChips(res.Rows[i].Tags, func(s string) string { return l.Path(searchHref(q, withTag(ts, s))) })
		}
	}
}
