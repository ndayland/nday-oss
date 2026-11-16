package site

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCreditRole(t *testing.T) {
	cases := map[string]string{
		"finder": "finder", "reporter": "reporter", "analyst": "analyst", "coordinator": "coordinator",
		"remediation developer": "remediation_developer", "remediation_developer": "remediation_developer",
		"Remediation  Reviewer": "remediation_reviewer", "remediation-verifier": "remediation_verifier",
		"tool": "tool", "sponsor": "sponsor", "other": "credit", "user": "credit", "credit": "credit",
		"": "credit", "<b>finder</b>": "credit", "FINDER": "finder",
	}
	for in, want := range cases {
		in := in
		if got := CreditRole(&in); got != want {
			t.Errorf("CreditRole(%q) = %q, want %q", in, got, want)
		}
	}
	if got := CreditRole(nil); got != CreditRoleCredit {
		t.Errorf("CreditRole(nil) = %q", got)
	}
}

func TestBuildCredits(t *testing.T) {
	long := strings.Repeat("é", 400)
	many := `[`
	for i := 0; i < 40; i++ {
		if i > 0 {
			many += ","
		}
		many += `{"type": "finder", "value": "person ` + string(rune('A'+i%26)) + string(rune('a'+i/26)) + `"}`
	}
	many += `]`
	recs := []creditRecord{
		// GHSA rows first on purpose: cvelist must still come first.
		{Source: "ghsa", Key: "GHSA-zzzz-zzzz-zzzz", JSON: []byte(`[{"type": "reporter", "login": "alice"}]`)},
		{Source: "ghsa", Key: "GHSA-aaaa-aaaa-aaaa", JSON: []byte(`[
			{"type": "remediation_developer", "login": "bob"},
			{"type": "reporter", "login": "alice"},
			{"type": "analyst", "login": null},
			{"type": "analyst"},
			"scalar", 7, null]`)},
		{Source: "cvelist", Key: "CVE-2026-1", JSON: []byte(`[
			{"lang": "en", "type": "finder", "value": "  Kostya\n\tKortchinsky | OpenAI  "},
			{"lang": "en", "type": "finder", "value": "Kostya Kortchinsky | OpenAI"},
			{"lang": "en", "type": "reporter", "value": "Kostya Kortchinsky | OpenAI"},
			{"lang": "en", "value": "<script>alert(1)</script>"},
			{"lang": "en", "type": "made up", "value": "Mallory"},
			{"lang": "en", "type": "other", "value": "Trent"},
			{"lang": "en", "type": "finder", "value": "   "},
			{"lang": "en", "type": "finder", "value": ""},
			{"lang": "en", "type": "finder", "value": 42},
			{"lang": "en", "type": "tool", "value": "` + long + `"},
			{"lang": "en", "type": "remediation developer", "value": "alice"}]`)},
		{Source: "xposts", Key: "1", JSON: []byte(`[{"type": "finder", "value": "never"}]`)},
		{Source: "cvelist", Key: "CVE-2026-2", JSON: []byte(`null`)},
		{Source: "cvelist", Key: "CVE-2026-3", JSON: []byte(`{"type": "finder"}`)},
	}
	got := buildCredits(recs)
	type row struct{ role, name, source, key string }
	want := []row{
		{"finder", "Kostya Kortchinsky | OpenAI", "cvelist", "CVE-2026-1"},
		{"reporter", "Kostya Kortchinsky | OpenAI", "cvelist", "CVE-2026-1"},
		{"credit", "<script>alert(1)</script>", "cvelist", "CVE-2026-1"},
		{"credit", "Mallory", "cvelist", "CVE-2026-1"},
		{"credit", "Trent", "cvelist", "CVE-2026-1"},
		{"tool", "", "cvelist", "CVE-2026-1"}, // long: checked below
		{"remediation_developer", "alice", "cvelist", "CVE-2026-1"},
		{"remediation_developer", "bob", "ghsa", "GHSA-aaaa-aaaa-aaaa"},
		{"reporter", "alice", "ghsa", "GHSA-aaaa-aaaa-aaaa"}, // the same in GHSA-zzzz is a duplicate
	}
	if len(got) != len(want) {
		t.Fatalf("got %d credits, want %d: %+v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if g.Role != w.role || g.Source != w.source || g.Key != w.key || (w.name != "" && g.Name != w.name) {
			t.Errorf("credit %d = %+v, want %+v", i, g, w)
		}
	}
	if n := got[5].Name; utf8.RuneCountInString(n) != MaxCreditRunes || !strings.HasSuffix(n, "…") || !strings.HasPrefix(n, "éé") {
		t.Errorf("long value not cut to %d runes: %d %q", MaxCreditRunes, utf8.RuneCountInString(n), n[:10])
	}
	if got[2].Type != nil || got[3].Type == nil || *got[3].Type != "made up" || got[0].Type == nil || *got[0].Type != "finder" {
		t.Errorf("types: %v %v %v", got[2].Type, got[3].Type, got[0].Type)
	}

	// Cap per source; another source still gets its own entries.
	got = buildCredits([]creditRecord{{Source: "cvelist", Key: "CVE-2026-1", JSON: []byte(many)},
		{Source: "ghsa", Key: "GHSA-a", JSON: []byte(`[{"type": "finder", "login": "x"}]`)}})
	if len(got) != MaxCreditsPerSource+1 || got[MaxCreditsPerSource].Source != "ghsa" {
		t.Errorf("cap: %d credits, last %+v", len(got), got[len(got)-1])
	}

	if got := buildCredits(nil); got == nil || len(got) != 0 {
		t.Errorf("no records: %#v", got)
	}
}

func TestCleanCreditText(t *testing.T) {
	cases := map[string]string{
		"  a  b ":       "a b",
		"a\u0000b c":    "a b c",
		"\n\t":          "",
		"罗鑫 <x@y>":      "罗鑫 <x@y>",
		"a\xffb":        "ab",
		"x" + "‍" + "y": "x‍y", // format characters are kept (scripts need ZWJ)
	}
	for in, want := range cases {
		if got := cleanCreditText(in, 100); got != want {
			t.Errorf("cleanCreditText(%q) = %q, want %q", in, got, want)
		}
	}
	if got := cleanCreditText("abcdef", 4); got != "abc…" {
		t.Errorf("cut: %q", got)
	}
	if got := cleanCreditText("ab   cdef", 4); got != "ab…" {
		t.Errorf("cut before space: %q", got)
	}
}
