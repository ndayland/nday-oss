package webui_test

import (
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"nday.land/nday/internal/site/sitetest"
)

// A CVE whose only data is an oss-security post (docs/osssec.md): the vuln
// page has the post's sentence with its subject and a link to the post, and
// the sources page has the osssec row.
func TestOsssecEventOnVulnPage(t *testing.T) {
	const cve = "CVE-2026-124749"
	const post = "https://seclists.org/oss-sec/2026/q4/788"
	e := newEnvSeeded(t, func(t *testing.T, conn *pgx.Conn) {
		s := sitetest.Seeder{T: t, Conn: conn}
		s.Vuln(cve, nil)
		u := post
		s.Event(sitetest.Ev{CVE: cve, Type: "analysis_published", Source: "osssec", Occurred: sitetest.P(sitetest.Day(2026, 11, 19)),
			URL: &u, Key: "2026/q4/788",
			Detail: `{"subject": "CVE-2026-124749: pam-mysql: pre-auth <bypass>", "author": "Andrey Vasilevsky", "is_reply": false, "list": "oss-security"}`})
		s.Refresh()
	})
	resp, body := e.get(t, "/vuln/"+cve)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	ev := regionOf(body, "r-events")
	for _, want := range []string{
		"Posted to the oss-security mailing list: “CVE-2026-124749: pam-mysql: pre-auth &lt;bypass&gt;”.",
		`href="` + post + `"`,
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("event log lacks %s:\n%s", want, ev)
		}
	}
	_, zh := e.get(t, "/zh-hans/vuln/"+cve)
	if !strings.Contains(zh, `oss-security 邮件列表发帖：“<span lang="en">CVE-2026-124749: pam-mysql: pre-auth &lt;bypass&gt;</span>”。`) {
		t.Errorf("zh-Hans sentence missing:\n%s", regionOf(zh, "r-events"))
	}

	_, src := e.get(t, "/src")
	if !strings.Contains(src, `href="https://seclists.org/oss-sec/"`) || !strings.Contains(src, "oss-security mailing list") {
		t.Error("sources page has no osssec row")
	}
}
