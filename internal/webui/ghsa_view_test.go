package webui

import (
	"strings"
	"testing"
	"time"

	"nday.land/nday/internal/site"
)

// A withdrawn advisory keyed by its GHSA id says GitHub withdrew it (banner
// and status sentence), not that CVE rejected it; a rejected CVE keeps its
// own words.
func TestWithdrawnAdvisoryWords(t *testing.T) {
	now := time.Date(2026, 11, 13, 0, 0, 0, 0, time.UTC)
	at := "2026-11-05T15:22:30Z"
	for _, tag := range []string{"en", "zh-Hans"} {
		l := loc(t, tag)
		w := &site.VulnDetail{CVEID: "GHSA-gpwc-27cw-rh9r", IsRejected: true,
			Rejection: &site.Rejection{DateRejected: &at, Reasons: []string{}, ReplacedBy: []string{}}}
		vv := BuildVulnView(l, w, now, API{})
		if vv.Rejected == nil || !vv.Rejected.Withdrawn {
			t.Fatalf("%s: %+v", tag, vv.Rejected)
		}
		if s := StatusSentence(l, w); !strings.HasPrefix(s, l.Text("status.withdrawn")) || strings.Contains(s, l.Text("status.rejected")) {
			t.Errorf("%s withdrawn: %q", tag, s)
		}
		c := &site.VulnDetail{CVEID: "CVE-2026-1005", IsRejected: true}
		if vv := BuildVulnView(l, c, now, API{}); vv.Rejected == nil || vv.Rejected.Withdrawn {
			t.Errorf("%s: a rejected CVE reads as withdrawn", tag)
		}
		if s := StatusSentence(l, c); !strings.HasPrefix(s, l.Text("status.rejected")) {
			t.Errorf("%s rejected: %q", tag, s)
		}
	}
}
