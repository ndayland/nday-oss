package discuss

import (
	"testing"
	"time"
)

// TestValidCursor: ValidCursor accepts exactly what decodeCursor (and so
// StreamPage) accepts.
func TestValidCursor(t *testing.T) {
	good := encodeCursor(&Cursor{At: time.Date(2026, 11, 13, 12, 0, 0, 0, time.UTC), ID: "0b141010-ef0f-49ba-b9bd-2f476f8923bb"})
	if !ValidCursor(good) {
		t.Errorf("ValidCursor(%q) = false", good)
	}
	for _, bad := range []string{"", "x", "!!!", good + "=", "MTIz", encodeCursor(&Cursor{ID: "not-a-uuid"}),
		string(make([]byte, 101))} {
		if ValidCursor(bad) {
			t.Errorf("ValidCursor(%q) = true", bad)
		}
		if _, ok := decodeCursor(bad); ok {
			t.Errorf("decodeCursor(%q) ok", bad)
		}
	}
}
