package site

import "testing"

func TestMatchDescSource(t *testing.T) {
	s := func(v string) *string { return &v }
	texts := []descText{
		{"kev", "CVE-2026-1", "Same text."},
		{"ghsa", "GHSA-bbbb", "Same text."},
		{"ghsa", "GHSA-aaaa", " Same text.\n"},
		{"cvelist", "CVE-2026-1", "Other text."},
		{"nvd", "CVE-2026-1", "Nvd text."}, // not a description source
	}
	for _, c := range []struct {
		name string
		desc *string
		want string
	}{
		{"nil", nil, ""},
		{"blank", s("  "), ""},
		{"ghsa before kev, lowest id, trimmed", s("Same text."), "ghsa/GHSA-aaaa"},
		{"cvelist", s("Other text.  "), "cvelist/CVE-2026-1"},
		{"unknown source ignored", s("Nvd text."), ""},
		{"no match", s("Changed since."), ""},
	} {
		got := ""
		if d := matchDescSource(c.desc, texts); d != nil {
			got = d.Source + "/" + d.Key
		}
		if got != c.want {
			t.Errorf("%s: got %q, want %q", c.name, got, c.want)
		}
	}
	both := append([]descText{{"cvelist", "CVE-2026-1", "Same text."}}, texts...)
	if d := matchDescSource(s("Same text."), both); d == nil || d.Source != "cvelist" {
		t.Errorf("cvelist first: %+v", d)
	}
}
