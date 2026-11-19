package webui_test

import (
	"html"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"nday.land/nday/internal/site/sitetest"
)

var (
	anchorRe = regexp.MustCompile(`<a\s[^>]*>`)
	attrOfRe = regexp.MustCompile(`\s([a-z-]+)="([^"]*)"`)
)

// TestExternalLinksOpenInNewTab: on the public pages every link to another
// host opens in a new tab with rel noopener noreferrer, and links to the
// site's own hosts (and site paths) do not.
func TestExternalLinksOpenInNewTab(t *testing.T) {
	e, _ := newMemberEnv(t, true)
	own := map[string]bool{wwwHost: true, apiHost: true, "nday.land": true}
	external := 0
	for _, p := range []string{"/", "/about", "/src", "/vuln/" + sitetest.GPU, "/vuln/" + evilCVE} {
		resp, body := e.fetch(t, wwwHost, p, nil)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: status %d", p, resp.StatusCode)
		}
		for _, tag := range anchorRe.FindAllString(body, -1) {
			attrs := map[string]string{}
			for _, m := range attrOfRe.FindAllStringSubmatch(tag, -1) {
				attrs[m[1]] = html.UnescapeString(m[2])
			}
			href, target, rel := attrs["href"], attrs["target"], " "+attrs["rel"]+" "
			u, err := url.Parse(href)
			off := err == nil && (u.Scheme == "http" || u.Scheme == "https") && !own[strings.ToLower(u.Hostname())]
			switch {
			case off:
				external++
				if target != "_blank" || !strings.Contains(rel, " noopener ") || !strings.Contains(rel, " noreferrer ") {
					t.Errorf("%s: external link without a new tab or noopener: %s", p, tag)
				}
			case target != "":
				t.Errorf("%s: internal link with a target: %s", p, tag)
			}
		}
	}
	if external < 10 {
		t.Errorf("only %d external links checked; the pages lost their links?", external)
	}
}
