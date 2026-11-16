package webui

import (
	"testing"

	"nday.land/nday/internal/webui/i18n"
)

// loc returns an enabled locale of the embedded set.
func loc(t testing.TB, tag string) *i18n.Locale {
	t.Helper()
	set, err := i18n.Default()
	if err != nil {
		t.Fatal(err)
	}
	l := set.ByTag(tag)
	if l == nil || !l.Enabled() {
		t.Fatalf("locale %s not enabled: %v", tag, l.Problems())
	}
	return l
}
