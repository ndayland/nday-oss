package webui

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The audit page's filters are cut by runes on valid UTF-8: a byte cut
// through a multi-byte character made PostgreSQL reject the query (500).
func TestCutRunes(t *testing.T) {
	for _, in := range []string{
		strings.Repeat("a", 63) + "é",
		strings.Repeat("a", 63) + "é" + "tail",
		strings.Repeat("漏", 200),
		"ok\xc3",
		"\xff\xfe",
		"",
	} {
		got := cutRunes(in, 64)
		if !utf8.ValidString(got) {
			t.Errorf("cutRunes(%q) = %q: not valid UTF-8", in, got)
		}
		if n := utf8.RuneCountInString(got); n > 64 {
			t.Errorf("cutRunes(%q): %d runes", in, n)
		}
	}
	if got := cutRunes(strings.Repeat("a", 63)+"é", 64); got != strings.Repeat("a", 63)+"é" {
		t.Errorf("a 64-rune value was changed: %q", got)
	}
}
