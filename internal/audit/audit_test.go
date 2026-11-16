package audit

import (
	"context"
	"strings"
	"testing"
)

func TestExcerpt(t *testing.T) {
	for _, c := range []struct {
		in   string
		n    int
		want string
	}{
		{"  buy\n\npills\tnow  ", 200, "buy pills now"},
		{"a\u202eb\u200bc\x00d", 200, "abcd"},
		{"abcdef", 4, "abc…"},
		{"ab cdef", 4, "ab…"},
		{"abcd", 4, "abcd"},
		{"", 4, ""},
		{"x", 0, ""},
		{"\xff\xfe", 10, "\uFFFD"}, // a run of invalid bytes is one replacement
	} {
		if got := Excerpt(c.in, c.n); got != c.want {
			t.Errorf("Excerpt(%q, %d) = %q, want %q", c.in, c.n, got, c.want)
		}
	}
	if got := Excerpt(strings.Repeat("字", 500), MaxLabel); len([]rune(got)) != MaxLabel {
		t.Errorf("long excerpt: %d runes", len([]rune(got)))
	}
}

func TestWriteRefusesInvalid(t *testing.T) {
	for _, e := range []Entry{{}, {Action: UserRole, TargetType: TargetUser}, {Action: UserRole, TargetID: "x"},
		{Action: UserRole, TargetType: TargetUser, TargetID: "x", Details: map[string]any{"big": strings.Repeat("x", MaxDetails)}}} {
		if err := Write(context.Background(), nil, e); err != ErrInvalid {
			t.Errorf("%+v: %v", e, err)
		}
	}
}
