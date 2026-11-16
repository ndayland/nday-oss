package webui_test

import (
	"context"
	"encoding/json"
	"html"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/site/sitetest"
)

const (
	codeCVE  = "CVE-2026-7771" // a description with a diagram, inline code and hostile text
	plainCVE = "CVE-2026-7772" // the same record with a plain description
)

// bidi is RLO + "gnp.exe" + LRI (written as escapes; NUL is left out, the
// database cannot store it: TestProseHostileInput covers it).
var bidi = string(rune(0x202E)) + "gnp.exe" + string(rune(0x2066))

// codeDesc mixes what upstream descriptions contain with markup that must
// stay inert: </pre> and </code> inside a code block and inside prose,
// attribute-breaking quotes, entities, bidi controls, control characters,
// CRLF and tabs.
var codeDesc = "In the Linux kernel, the following vulnerability has been resolved:\r\n\r\n" +
	"exec: fix <script>alert(1)</script> in de_thread() & \"q\" 'a' &amp; " + bidi + " x\x01y\x7fz\r\n\r\n" +
	"In short:\n\n      thread B           the parent\n\n  timer_create()\n    arm_timer()   // </pre></code><script>alert(2)</script>\n" +
	"  execve()\n\tde_thread(B) \"><img src=x onerror=alert(3)>\n\n" +
	"Fixes: `</code><b>x</b>` and CONFIG_FOO_BAR in bprm->point_of_no_return.\n\n[ tglx: Move the cleanup ]"

func TestDescriptionRendering(t *testing.T) {
	e := newEnvSeeded(t, seedDescriptions)
	set := e.ui.Locales()
	for _, l := range []string{"en", "zh-Hans"} {
		loc := set.ByTag(l)
		p := loc.Path("/vuln/" + codeCVE)
		resp, body := e.get(t, p)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		if _, problems := CheckHTML(body); len(problems) > 0 {
			t.Errorf("%s: %v", p, problems)
		}
		for _, bad := range []string{"<script>alert", "</pre></code><script>", "<img src=x", "<b>x</b>", "\x01", "\x7f", "\r"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: unescaped %q", p, bad)
			}
		}
		// the diagram is one <pre>, with its columns and escaped markup
		// numbered (six lines), one element per line with its line break inside
		pre := regexp.MustCompile(`(?s)<pre class="tx-code tx-num g2" dir="ltr"><code>(.*?)</code></pre>`).FindAllStringSubmatch(body, -1)
		if len(pre) != 1 {
			t.Fatalf("%s: %d code blocks", p, len(pre))
		}
		// (no common indentation to remove: the last line is tab-indented)
		want := "      thread B           the parent\n\n  timer_create()\n    arm_timer()   // &lt;/pre&gt;&lt;/code&gt;&lt;script&gt;alert(2)&lt;/script&gt;\n  execve()\n\tde_thread(B) &#34;&gt;&lt;img src=x onerror=alert(3)&gt;"
		if n := strings.Count(pre[0][1], `<span class="l">`); n != 6 || n != strings.Count(pre[0][1], "\n</span>") {
			t.Errorf("%s: %d line elements in %q", p, n, pre[0][1])
		}
		got := strings.TrimSuffix(regexp.MustCompile(`<span class="[a-z]+">|</span>`).ReplaceAllString(pre[0][1], ""), "\n")
		if got != want {
			t.Errorf("%s: code block\n%q\nwant\n%q", p, got, want)
		}
		// highlighted (hilite.go): calls and the comment are tokens, the
		// comment's markup stays escaped inside its token
		for _, tok := range []string{
			`<span class="l">  <span class="hf">timer_create</span>()` + "\n</span>",
			`<span class="hf">arm_timer</span>()   <span class="hc">// &lt;/pre&gt;&lt;/code&gt;&lt;script&gt;alert(2)&lt;/script&gt;</span>` + "\n</span>",
			`<span class="l">      thread B           the parent` + "\n</span>", // plain text gets no span
		} {
			if !strings.Contains(pre[0][1], tok) {
				t.Errorf("%s: missing %q in %q", p, tok, pre[0][1])
			}
		}
		for _, want := range []string{
			`<code dir="ltr">de_thread()</code>`, `<code dir="ltr">CONFIG_FOO_BAR</code>`,
			`<code dir="ltr">bprm<span class="nw">-&gt;</span>point_of_no_return</code>`, // "->" never wraps
			`<code dir="ltr">&lt;/code&gt;&lt;b&gt;x&lt;/b&gt;</code>`,
			"<p>[ tglx: Move the cleanup ]</p>",
			bidi + " x" + string(rune(0xFFFD)) + "y" + string(rune(0xFFFD)) + "z</p>", // controls replaced, bidi kept (isolated by CSS)
		} {
			if !strings.Contains(body, want) {
				t.Errorf("%s: missing %q", p, want)
			}
		}
		if l == "zh-Hans" {
			// summary_zh is shown, the English original is split the same way
			if !strings.Contains(body, `<div class="summary"><p>在 <code dir="ltr">de_thread()</code> 中修复。</p></div>`) ||
				!strings.Contains(body, `<div class="orig-t" lang="en"><p>In the Linux kernel`) {
				t.Errorf("zh: summary_zh or original missing")
			}
		} else if !strings.Contains(body, `<div class="summary"><p>In the Linux kernel`) {
			t.Errorf("en: summary missing")
		}
	}

	// Plain-text outputs do not depend on the description: the two records
	// differ only there and give the same head (description, Open Graph,
	// share card key), search row and API fields other than description;
	// the API returns the stored description byte for byte.
	for _, l := range set.Enabled {
		_, a := e.get(t, l.Path("/vuln/"+codeCVE))
		_, b := e.get(t, l.Path("/vuln/"+plainCVE))
		// the share card key hashes the CVE id; that the card ignores the
		// description is TestShareCardIgnoresDescription
		key := regexp.MustCompile(`\.png\?v=[0-9a-f]+`)
		ha, hb := key.ReplaceAllString(headMeta(a), ".png"), key.ReplaceAllString(headMeta(b), ".png")
		if strings.ReplaceAll(ha, codeCVE, "X") != strings.ReplaceAll(hb, plainCVE, "X") || ha == "" {
			t.Errorf("%s: head differs:\n%s\n%s", l.Tag, ha, hb)
		}
		if strings.Contains(ha, "de_thread") || strings.Contains(ha, "tx-code") {
			t.Errorf("%s: description leaked into the head: %s", l.Tag, ha)
		}
		_, s := e.get(t, l.Path("/vuln?q=CVE-2026-777"))
		if strings.Contains(s, "tx-code") || strings.Contains(s, "de_thread") {
			t.Errorf("%s: search rows show the description", l.Tag)
		}
	}
	for cve, want := range map[string]string{codeCVE: codeDesc, plainCVE: "plain words"} {
		_, body := e.get(t, "/api/vuln/"+cve)
		var v struct {
			Description *string `json:"description"`
		}
		if err := json.Unmarshal([]byte(body), &v); err != nil {
			t.Fatal(err)
		}
		if v.Description == nil || *v.Description != want {
			t.Errorf("api %s: description %q", cve, deref(v.Description))
		}
	}
	_, feed := e.get(t, "/feed.xml")
	if strings.Contains(feed, "de_thread") {
		t.Error("feed shows the description")
	}
}

func deref(s *string) string {
	if s == nil {
		return "<nil>"
	}
	return *s
}

// headMeta is the page's <title> and <meta> tags.
func headMeta(body string) string {
	head, _, _ := strings.Cut(body, "</head>")
	var out []string
	for _, m := range regexp.MustCompile(`<title>[^<]*</title>|<meta [^>]*>`).FindAllString(head, -1) {
		out = append(out, html.UnescapeString(m))
	}
	return strings.Join(out, "\n")
}

// seedDescriptions adds the two records.
func seedDescriptions(t *testing.T, conn *pgx.Conn) {
	s := sitetest.Seeder{T: t, Conn: conn}
	title := "exec timer use-after-free"
	for _, c := range []struct{ cve, desc string }{{codeCVE, codeDesc}, {plainCVE, "plain words"}} {
		s.Vuln(c.cve, &title)
		if _, err := conn.Exec(context.Background(), `UPDATE vuln SET description = $2 WHERE cve_id = $1`, c.cve, c.desc); err != nil {
			t.Fatal(err)
		}
		s.Event(sitetest.Ev{CVE: c.cve, Type: "disclosed", Source: "cvelist", Occurred: sitetest.P(sitetest.Day(2026, 11, 10)),
			Detail: `{"state": "PUBLISHED"}`})
	}
	if _, err := conn.Exec(context.Background(), `UPDATE vuln SET summary_zh = $2 WHERE cve_id = $1`, codeCVE, "在 de_thread() 中修复。"); err != nil {
		t.Fatal(err)
	}
	s.Refresh()
}
