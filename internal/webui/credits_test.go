package webui_test

import (
	"regexp"
	"strings"
	"testing"

	"nday.land/nday/internal/site/sitetest"
)

var credPanelRe = regexp.MustCompile(`(?s)<section class="panel">\s*<h2><span class="h" aria-hidden="true"># </span>[^<]*(?:<span lang="en">[^<]*</span>)?</h2>\s*<dl class="cred">.*?</dl>\s*</section>`)

// The credits panel: present with the seeded credits (sitetest.SeedCredits),
// names as escaped text and never links, profile URLs never shown; absent
// entirely for a vulnerability without credits.
func TestCreditsPanel(t *testing.T) {
	e := newEnv(t)
	for _, l := range e.ui.Locales().Enabled {
		p := l.Path("/vuln/" + sitetest.GPU)
		resp, body := e.get(t, p)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", p, resp.StatusCode)
		}
		panel := credPanelRe.FindString(body)
		if panel == "" {
			t.Fatalf("%s: no credits panel", p)
		}
		if strings.Count(panel, "<dt>") != 6 || strings.Contains(panel, "<a ") || strings.Contains(panel, "href=") {
			t.Errorf("%s: panel %s", p, panel)
		}
		for _, want := range []string{
			`<bdi dir="auto">Zhang Wei of Example Lab</bdi><span class="weak">cvelist</span>`,
			`<bdi dir="auto">&lt;img src=x onerror=alert(1)&gt;Eve</bdi>`,
			`<bdi dir="auto">zq-credit-login</bdi><span class="weak">ghsa</span>`,
			`<bdi dir="auto">fixer-dev</bdi>`,
			`<dt>` + string(l.HTML("credit.role", "role", "remediation_developer")) + `</dt>`,
			`<dt>` + string(l.HTML("credit.role", "role", "credit")) + `</dt><dd><bdi dir="auto">Anonymous researcher</bdi>`,
		} {
			if !strings.Contains(panel, want) {
				t.Errorf("%s: panel lacks %q:\n%s", p, want, panel)
			}
		}
		for _, bad := range []string{sitetest.CreditHostile, "api.github.com", "received_events", "Old Version Person",
			"moved-away", "withdrawn-one"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s: %q in page", p, bad)
			}
		}
		if _, problems := CheckHTML(body); len(problems) > 0 {
			t.Errorf("%s: %v", p, problems)
		}
		for _, id := range []string{"CVE-2026-1010", "CVE-2026-1002"} {
			_, body := e.get(t, l.Path("/vuln/"+id))
			if strings.Contains(body, `class="cred"`) || strings.Contains(body, string(l.HTML("credit.h2"))+"</h2>") {
				t.Errorf("%s %s: credits panel without credits", l.Tag, id)
			}
		}
	}
	set := e.ui.Locales()
	_, body := e.get(t, "/vuln/"+sitetest.GPU)
	if !strings.Contains(body, "># </span>Credits</h2>") || !strings.Contains(body, "<dt>remediation developer</dt>") {
		t.Error("en panel wording")
	}
	_, body = e.get(t, "/zh-hans/vuln/"+sitetest.GPU)
	if !strings.Contains(body, "># </span>致谢</h2>") || !strings.Contains(body, "<dt>发现者</dt>") {
		t.Error("zh-Hans panel wording")
	}
	// A locale that has not written the keys yet shows the English, marked.
	if ja := set.ByTag("ja"); ja.Enabled() && ja.FallsBack("credit.h2") {
		_, body = e.get(t, ja.Path("/vuln/"+sitetest.GPU))
		if !strings.Contains(body, `<span lang="en">Credits</span></h2>`) {
			t.Error("ja fallback heading not marked lang=en")
		}
	}
}
