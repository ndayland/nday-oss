package webui_test

import (
	"regexp"
	"strings"
	"testing"

	"nday.land/nday/internal/site/sitetest"
	"nday.land/nday/internal/tags"
	"nday.land/nday/internal/webui/i18n"
)

// The vocabulary is defined once, in Go: the catalog reference's select
// values are exactly its slugs and dimensions, and the English catalog's
// names are its English labels. Product tags (dimension product) are the one
// exception: their names are the Go labels in every locale and they share
// the parameterised description tags.KeyProductDesc, so they are not select
// values (and must not be: a stale per-product entry would be dead text).
func TestTagVocabularyMatchesCatalogs(t *testing.T) {
	set, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	var slugs []string
	nProducts := 0
	for _, tg := range tags.Vocabulary {
		if tg.Dim == tags.DimProduct {
			nProducts++
			if tg.Label == "" || strings.TrimSpace(tg.Label) != tg.Label {
				t.Errorf("product %s: bad label %q", tg.Slug, tg.Label)
			}
			continue
		}
		slugs = append(slugs, tg.Slug)
		if got := set.Primary().Text(tags.KeyName, tags.SelectTag, tg.Slug); got != tg.Label {
			t.Errorf("en %s: %q, Go label %q", tg.Slug, got, tg.Label)
		}
	}
	for _, k := range []string{tags.KeyName, tags.KeyDesc} {
		if def := set.Reference.Key(k); def == nil || def.Select == nil || def.Select.Var != tags.SelectTag ||
			strings.Join(def.Select.Values, " ") != strings.Join(slugs, " ") {
			t.Errorf("%s select values differ from the vocabulary", k)
		}
	}
	for _, k := range []string{tags.KeyDim, tags.KeyDimDesc} {
		if def := set.Reference.Key(k); def == nil || def.Select == nil || def.Select.Var != tags.SelectDim ||
			strings.Join(def.Select.Values, " ") != strings.Join(tags.Dimensions, " ") {
			t.Errorf("%s select values differ from the dimensions", k)
		}
	}
	if nProducts == 0 {
		t.Error("no product tags in the vocabulary")
	}
	// tagview.go writes these keys out literally (TestKeyUsage)
	if tags.KeyName != "tag.name" || tags.KeyDesc != "tag.desc" || tags.KeyProductDesc != "tag.desc_product" {
		t.Error("tag message keys changed: update tagview.go")
	}
	// the shared product description: one placeholder, the product name
	if def := set.Reference.Key(tags.KeyProductDesc); def == nil || def.Select != nil {
		t.Errorf("%s missing or a select message", tags.KeyProductDesc)
	}
	if got := set.Primary().Text(tags.KeyProductDesc, "name", "Windows"); !strings.Contains(got, "Windows") {
		t.Errorf("%s does not name the product: %q", tags.KeyProductDesc, got)
	}
}

// section returns the part of body between the first start and the next end.
func section(body, start, end string) string {
	i := strings.Index(body, start)
	if i < 0 {
		return ""
	}
	j := strings.Index(body[i:], end)
	if j < 0 {
		return body[i:]
	}
	return body[i : i+j]
}

func TestVulnTagsBlock(t *testing.T) {
	e := newEnv(t)
	_, body := e.get(t, "/vuln/"+sitetest.GPU)
	block := section(body, `<div class="vtags">`, `<div class="cmd">`)
	for _, want := range []string{
		`<a class="tg tg-c-authz" href="/tag/auth-bypass"`, `>authentication bypass</a>`,
		`<a class="tg tg-s" href="/tag/remote-unauth"`, `>remote, unauthenticated</a>`,
		`<span class="dim">weakness type</span>`, `<span class="dim">exploitation</span>`,
		`<details class="why">`, "NVD, the CNA and other sources do not assign them",
		`<a href="https://cwe.mitre.org/data/definitions/287.html" rel="noopener noreferrer">CWE-287</a>, stated by the CNA <bdi>GitHub_M</bdi> and NVD&#39;s analysts`,
		"<code><bdi>AV:N</bdi></code>, <code><bdi>PR:N</bdi></code>, <code><bdi>UI:N</bdi></code> in <code><bdi>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</bdi></code> (CVSS 3.1) from the CNA <bdi>GitHub_M</bdi>",
		"Metasploit modules <code><bdi>exploit/linux/http/gpustack_rce</bdi></code>",
	} {
		if !strings.Contains(block, want) {
			t.Errorf("GPU tags block missing %q\n%s", want, block)
		}
	}
	if strings.Contains(block, "CVSS 2.0 has no user-interaction metric") {
		t.Error("v2 note without a v2 basis")
	}
	// the block sits right under the status sentence, before the facts
	if i, j, k := strings.Index(body, `<p class="sentence">`), strings.Index(body, `<div class="vtags">`), strings.Index(body, `<dl class="facts">`); !(i < j && j < k) {
		t.Errorf("block position %d %d %d", i, j, k)
	}
	// CVSS 2.0 basis: the caveat; never no-interaction / remote-unauth
	_, body = e.get(t, "/vuln/CVE-2026-1002")
	block = section(body, `<div class="vtags">`, `<div class="cmd">`)
	if !strings.Contains(block, "CVSS 2.0 has no user-interaction metric") || strings.Contains(block, "/tag/no-interaction") ||
		!strings.Contains(block, "/tag/command-injection") || !strings.Contains(block, "(CVSS 2.0) from NVD&#39;s analysts") {
		t.Errorf("v2 block\n%s", block)
	}
	// no tags (REJECTED): no block
	_, body = e.get(t, "/vuln/CVE-2026-1005")
	if strings.Contains(body, `<div class="vtags">`) {
		t.Error("rejected CVE shows tags")
	}
	// zh-Hans: localised descriptive labels, English technical terms
	_, body = e.get(t, "/zh-hans/vuln/"+sitetest.GPU)
	block = section(body, `<div class="vtags">`, `<div class="cmd">`)
	for _, want := range []string{`href="/zh-hans/tag/remote-unauth"`, ">远程未授权</a>", ">authentication bypass</a>", "这些标签的依据",
		"不是 NVD、编号分配方或其他来源给出的", "（来源：编号分配方 <bdi>GitHub_M</bdi>、NVD 分析人员）"} {
		if !strings.Contains(block, want) {
			t.Errorf("zh block missing %q\n%s", want, block)
		}
	}
	// a pending locale shows the English text marked lang="en"
	_, body = e.get(t, "/ja/vuln/"+sitetest.GPU)
	if !strings.Contains(section(body, `<div class="vtags">`, `<div class="cmd">`), `<span lang="en">remote, unauthenticated</span>`) {
		t.Error("ja fallback not marked")
	}
}

// Hostile upstream strings in a basis (a CNA name and a Metasploit module
// name with markup and bidi controls) render as inert, isolated text.
func TestVulnTagsHostileBasis(t *testing.T) {
	e := newEnv(t)
	for _, l := range e.ui.Locales().Enabled {
		_, body := e.get(t, l.Path("/vuln/"+evilCVE))
		block := section(body, `<div class="vtags">`, `<div class="cmd">`)
		if block == "" {
			t.Fatalf("%s: no tags block", l.Tag)
		}
		for _, bad := range []string{"<img src=x", "<script>alert(6)", "<script>alert(7)", "‮", "⁦"} {
			if strings.Contains(block, bad) {
				t.Errorf("%s: %q in the tags block", l.Tag, bad)
			}
		}
		for _, want := range []string{"<bdi>&lt;img src=x onerror=alert(5)&gt;�gnp.exe�</bdi>",
			"<bdi>exploit/&lt;script&gt;alert(6)&lt;/script&gt;�</bdi>",
			"<bdi>Tenda</bdi> · <bdi>AC15 &lt;script&gt;alert(7)&lt;/script&gt;�</bdi>"} {
			if !strings.Contains(block, want) {
				t.Errorf("%s: missing inert %q\n%s", l.Tag, want, block)
			}
		}
		if _, problems := CheckHTML(body); len(problems) > 0 {
			t.Errorf("%s: %v", l.Tag, problems)
		}
	}
}

func TestHotTagFilters(t *testing.T) {
	e := newEnv(t)
	rowRe := regexp.MustCompile(`data-id="(CVE-[0-9-]+)"`)
	rows := func(body string) string {
		var s []string
		for _, m := range rowRe.FindAllStringSubmatch(body, -1) {
			s = append(s, m[1])
		}
		return strings.Join(s, " ")
	}
	_, body := e.get(t, "/?tag=remote-unauth")
	if got := rows(body); got != sitetest.GPU {
		t.Errorf("one tag: %s", got)
	}
	// the active chip removes itself; the canonical link keeps the filter
	for _, want := range []string{`<span class="k">Tags</span>`, `<a class="tx" href="/" aria-label="Remove the remote, unauthenticated filter"`,
		`<link rel="canonical" href="https://nday.land/?tag=remote-unauth"/>`,
		`href="/feed.xml?tag=remote-unauth"`, `curl -s &#39;https://nday.land/api/hot?since=7d&amp;min_stage=patch&amp;tag=remote-unauth&#39;`} {
		if !strings.Contains(body, want) {
			t.Errorf("one tag page missing %q", want)
		}
	}
	// row chips: at most three, remote-unauth then the first type tag; each
	// adds itself to the filter
	chips := section(body, `<span class="rtags">`, `</span>`)
	if strings.Count(chips, `class="tg`) != 2 || !strings.Contains(chips, `href="/?tag=auth-bypass&amp;tag=remote-unauth"`) {
		t.Errorf("row chips %s", chips)
	}
	// two tags (AND), unknown slugs dropped from links
	_, body = e.get(t, "/?tag=nope&tag=auth-bypass&tag=remote-unauth")
	if got := rows(body); got != sitetest.GPU ||
		!strings.Contains(body, `<link rel="canonical" href="https://nday.land/?tag=auth-bypass&amp;tag=remote-unauth"/>`) ||
		strings.Contains(section(body, `<div class="flags">`, `<div class="tbl">`), "nope") {
		t.Errorf("two tags: %s", got)
	}
	_, body = e.get(t, "/?tag=remote-unauth&tag=ransomware&since=30d")
	if got := rows(body); got != "" || !strings.Contains(body, "Tag filters narrow the list further") {
		t.Errorf("no match: %s", got)
	}
	_, body = e.get(t, "/?tag=ransomware&since=30d")
	if got := rows(body); got != "CVE-2026-1008" || !strings.Contains(body, `class="tg tg-s tg-rw"`) {
		t.Errorf("ransomware: %s", got)
	}
	// the unfiltered list links the vocabulary
	_, body = e.get(t, "/")
	if !strings.Contains(body, `<a class="tall" href="/tags">browse tags</a>`) || rows(body) == sitetest.GPU {
		t.Error("unfiltered list")
	}
}

func TestTagPages(t *testing.T) {
	e := newEnv(t)
	resp, body := e.get(t, "/tags")
	if resp.StatusCode != 200 {
		t.Fatalf("/tags %d", resp.StatusCode)
	}
	for _, want := range []string{`<a class="tg tg-c-authz" href="/tag/auth-bypass"`, `<code class="slug">auth-bypass</code>`,
		`<link rel="canonical" href="https://nday.land/tags"/>`, `hreflang="zh-Hans" href="https://nday.land/zh-hans/tags"`,
		"Counts as of <time", "Tags are nday&#39;s, not NVD&#39;s or the CNA&#39;s"} {
		if !strings.Contains(body, want) {
			t.Errorf("/tags missing %q", want)
		}
	}
	// the catalogue prints each description beside its chip, so the chip has no tooltip repeating it
	if strings.Contains(body, `<a class="tg tg-c-authz" href="/tag/auth-bypass" title=`) || !strings.Contains(body, `<dd class="d">`) {
		t.Error("/tags: a chip repeats its visible description as a title")
	}
	// count of network: GPU and CVE-2026-1002
	if !regexp.MustCompile(`href="/tag/network"[^>]*>network</a><code class="slug">network</code></dt><dd class="n">2</dd>`).MatchString(body) {
		t.Error("/tags network count")
	}
	_, body = e.get(t, "/zh-hans/tag/auth-bypass")
	for _, want := range []string{`<title>authentication bypass · 标签 · nday</title>`, "共有 1 个 CVE 带有这个标签。",
		`href="/zh-hans/feed.xml?tag=auth-bypass"`, `<link rel="canonical" href="https://nday.land/zh-hans/tag/auth-bypass"/>`,
		`data-id="` + sitetest.GPU + `"`, `CWE-287</a>`} {
		if !strings.Contains(body, want) {
			t.Errorf("tag page missing %q", want)
		}
	}
	// filter links on a tag page stay on it
	if !strings.Contains(body, `href="/zh-hans/tag/auth-bypass?since=30d"`) {
		t.Error("since links leave the tag page")
	}
	if resp, _ := e.get(t, "/tag/nope"); resp.StatusCode != 404 {
		t.Errorf("unknown tag %d", resp.StatusCode)
	}
	if resp := e.noRedirect(t, "/tag/XSS"); resp.StatusCode != 301 || resp.Header.Get("Location") != "/tag/xss" {
		t.Errorf("upper-case slug %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
	// feed with a tag: title says so, entries are filtered
	_, body = e.get(t, "/feed.xml?tag=ransomware&tag=nope")
	if !strings.Contains(body, "<title>nday · hot · ransomware use</title>") || !strings.Contains(body, "CVE-2026-1008") ||
		strings.Contains(body, sitetest.GPU) || !strings.Contains(body, `href="https://nday.land/feed.xml?tag=ransomware"`) {
		t.Errorf("tag feed\n%s", body)
	}
	_, plain := e.get(t, "/feed.xml")
	if !strings.Contains(plain, sitetest.GPU) {
		t.Error("plain feed lost rows")
	}
	// /vuln: tags alone filter the catalogue (catalogue_test.go); query plus tags, chips keep the query
	_, body = e.get(t, "/vuln?tag=network")
	if !strings.Contains(body, `data-id="`+sitetest.GPU+`"`) || !strings.Contains(body, `data-id="CVE-2026-1002"`) ||
		!strings.Contains(body, `<input type="hidden" name="tag" value="network"/>`) {
		t.Error("search by tag")
	}
	_, body = e.get(t, "/vuln?q=gpu&tag=remote-unauth")
	if !strings.Contains(body, `data-id="`+sitetest.GPU+`"`) || !strings.Contains(body, `<a class="tx" href="/vuln?q=gpu"`) {
		t.Error("search q+tag")
	}
	_, body = e.get(t, "/vuln?tag=xss&tag=csrf")
	if !strings.Contains(body, "No vulnerability matches these filters.") {
		t.Error("catalogue by tags: none")
	}
}

// Product and product-type tags (rule version 2): from an affected row (a
// type rule) and from the classified NVD record's vulnerable CPE names; the
// platform CPE (vulnerable = false) gives nothing. Product names stay in
// English in every locale; CPE evidence is attributed to NVD's analysts.
func TestVulnProductTags(t *testing.T) {
	e := newEnv(t)
	_, body := e.get(t, "/vuln/CVE-2026-1002")
	block := section(body, `<div class="vtags">`, `<div class="cmd">`)
	for _, want := range []string{
		`<span class="dim">product</span>`, `<span class="dim">product type</span>`,
		`<a class="tg" href="/tag/fortios" title="CVEs whose affected products include FortiOS`, `>FortiOS</a>`,
		`href="/tag/firewall-vpn"`, `>firewall / VPN / security gateway</a>`, `>router / switch</a>`,
		"CPE names NVD&#39;s analysts give as vulnerable: <code><bdi>o:fortinet:fortios</bdi></code>",
		"affected products in the CVE record: <bdi>D-Link</bdi> · <bdi>DIR-605L</bdi>",
		"nday&#39;s type rule <code><bdi>d-link:router</bdi></code>",
		`the product type of <a href="/tag/fortios">FortiOS</a> in nday&#39;s product registry`,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("product block missing %q\n%s", want, block)
		}
	}
	if strings.Contains(block, "/tag/windows") || strings.Contains(block, "windows_10") {
		t.Error("a platform CPE (vulnerable = false) gave a tag")
	}
	// dimension order: exploit, product, product type
	if i, j, k := strings.Index(block, ">exploitation<"), strings.Index(block, ">product<"), strings.Index(block, ">product type<"); !(i < j && j < k) {
		t.Errorf("dimension order %d %d %d", i, j, k)
	}
	_, body = e.get(t, "/zh-hans/vuln/CVE-2026-1002")
	block = section(body, `<div class="vtags">`, `<div class="cmd">`)
	for _, want := range []string{`href="/zh-hans/tag/fortios"`, ">FortiOS</a>", ">防火墙/VPN/安全网关</a>", "NVD 分析人员标为易受攻击的 CPE 名称"} {
		if !strings.Contains(block, want) {
			t.Errorf("zh product block missing %q\n%s", want, block)
		}
	}
	// tag page, list filter, /tags, feed
	resp, body := e.get(t, "/tag/fortios")
	if resp.StatusCode != 200 || !strings.Contains(body, "<title>FortiOS · ") || !strings.Contains(body, `data-id="CVE-2026-1002"`) ||
		!strings.Contains(body, "CVEs whose affected products include FortiOS") {
		t.Errorf("/tag/fortios %d", resp.StatusCode)
	}
	if _, body = e.get(t, "/vuln?tag=firewall-vpn"); !strings.Contains(body, `data-id="CVE-2026-1002"`) {
		t.Error("filter by product type")
	}
	_, body = e.get(t, "/tags")
	if !regexp.MustCompile(`href="/tag/fortios"[^>]*>FortiOS</a><code class="slug">fortios</code></dt><dd class="n">1</dd>`).MatchString(body) ||
		!strings.Contains(body, `id="dim-product-type"`) {
		t.Error("/tags product rows")
	}
	if _, body = e.get(t, "/feed.xml?tag=fortios"); !strings.Contains(body, "<title>nday · hot · FortiOS</title>") {
		t.Error("product feed title")
	}
	// a pending locale: the product name is English, unmarked like other product names
	if _, body = e.get(t, "/ja/vuln/CVE-2026-1002"); !strings.Contains(section(body, `<div class="vtags">`, `<div class="cmd">`), ">FortiOS</a>") {
		t.Error("ja product name")
	}
}
