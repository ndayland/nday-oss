package webui_test

import (
	"strings"
	"testing"
)

// The NVD source is registered as public: its health row and description
// appear on the sources page, and the about page carries NVD's notice. The
// pending locales show the English text marked lang="en".
func TestNVDSourceRowAndNotice(t *testing.T) {
	e := newEnv(t)
	for path, wants := range map[string][]string{
		"/src": {"nvd", "NIST&#39;s National Vulnerability Database", "none: NVD supplies classification data (CWE, CVSS, CPE), not lifecycle events",
			`href="https://nvd.nist.gov/vuln/data-feeds"`},
		"/zh-hans/src":   {"美国 NIST 国家漏洞数据库", "不产生生命周期事件"},
		"/about":         {"This product uses data from the NVD but is not endorsed or certified by the NVD."},
		"/zh-hans/about": {"本站使用了 NVD（美国国家漏洞数据库）的数据，但未经 NVD 认可或认证"},
		"/ja/about":      {`lang="en">This product uses data from the NVD but is not endorsed or certified by the NVD.`},
	} {
		resp, body := e.get(t, path)
		if resp.StatusCode != 200 {
			t.Fatalf("%s: %d", path, resp.StatusCode)
		}
		for _, w := range wants {
			if !strings.Contains(body, w) {
				t.Errorf("%s lacks %q", path, w)
			}
		}
	}
}
