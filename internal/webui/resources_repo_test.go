package webui

import (
	"testing"

	"nday.land/nday/internal/site"
)

// A fetched repository replaces the title / text and host with its full
// name, stars and creation day; other links are unchanged.
func TestBuildResourcesViewRepo(t *testing.T) {
	v := BuildResourcesView([]site.Resource{
		{URL: "https://github.com/o/r", Kind: "poc", Title: "GitHub - o/r", Researchers: 1,
			Repo: &site.ResourceRepo{FullName: "O/R", Stars: 12, Created: "2026-01-02"}},
		{URL: "https://github.com/u/v", Kind: "poc", Host: "github.com",
			Repo: &site.ResourceRepo{FullName: "u/v", Stars: 1, Created: "2026-01-03", Unverified: true}},
		{URL: "https://github.com/g/one", Kind: "code", Title: "T", Researchers: 1},
	})
	if v == nil || len(v.Groups) != 2 {
		t.Fatalf("%+v", v)
	}
	if l := v.Groups[0].Links[0]; l.Repo != "O/R" || l.Stars != 12 || l.Created != "2026-01-02" || l.Unverified {
		t.Errorf("repo link %+v", l)
	}
	if l := v.Groups[0].Links[1]; l.Repo != "u/v" || !l.Unverified {
		t.Errorf("unverified link %+v", l)
	}
	if l := v.Groups[1].Links[0]; l.Repo != "" || l.Title != "T" || l.Host != "github.com" {
		t.Errorf("plain link %+v", l)
	}
}
