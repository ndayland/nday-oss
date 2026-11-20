package webui_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/site/sitetest"
)

// A CVE whose only data is a Zero Wire advisory (docs/zerowire.md): the vuln
// page has the advisory's sentence with its title (as text) and a link to
// the advisory, and the sources page has the zerowire row.
func TestZerowireEventOnVulnPage(t *testing.T) {
	const cve = "CVE-2026-132825"
	const adv = "https://radar.cloudflare.com/zero-wire/ruby2shell"
	e := newEnvSeeded(t, func(t *testing.T, conn *pgx.Conn) {
		s := sitetest.Seeder{T: t, Conn: conn}
		s.Vuln(cve, nil)
		u := adv
		s.Event(sitetest.Ev{CVE: cve, Type: "analysis_published", Source: "zerowire", Occurred: sitetest.P(sitetest.Day(2026, 11, 19)),
			URL: &u, Key: "ruby2shell",
			Detail: `{"title": "ruby2shell: heap overflow in <b>Ruby</b>", "precision": "day"}`})
		s.Refresh()
	})
	resp, body := e.get(t, "/vuln/"+cve)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	ev := regionOf(body, "r-events")
	for _, want := range []string{
		"Cloudflare Zero Wire advisory: “ruby2shell: heap overflow in &lt;b&gt;Ruby&lt;/b&gt;”.",
		`href="` + adv + `"`,
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("event log lacks %s:\n%s", want, ev)
		}
	}
	if strings.Contains(ev, "<b>Ruby") {
		t.Error("the title was rendered as markup")
	}
	_, zh := e.get(t, "/zh-hans/vuln/"+cve)
	if !strings.Contains(zh, `Cloudflare Zero Wire 通告：“<span lang="en">ruby2shell: heap overflow in &lt;b&gt;Ruby&lt;/b&gt;</span>”。`) {
		t.Errorf("zh-Hans sentence missing:\n%s", regionOf(zh, "r-events"))
	}

	_, src := e.get(t, "/src")
	if !strings.Contains(src, `href="https://radar.cloudflare.com/zero-wire"`) || !strings.Contains(src, "Zero Wire advisories by Cloudforce One") {
		t.Error("sources page has no zerowire row")
	}
}
