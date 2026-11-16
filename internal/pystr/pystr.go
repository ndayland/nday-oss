// Package pystr reproduces the few Python str methods whose exact semantics
// leak into stored data: str.strip() / str.isspace() and str.splitlines().
//
// Go's strings.TrimSpace is NOT equivalent: Python also treats U+001C..U+001F
// (file/group/record/unit separators) as whitespace. A KEV field consisting
// of "\x1f" is None in Python; with TrimSpace it would be a non-empty string.
package pystr

import (
	"strings"
	"unicode"
)

// IsSpace reports whether r is whitespace for Python's str.isspace()
// (CPython 3.12/3.13: bidi class WS, B or S, or category Zs).
func IsSpace(r rune) bool {
	if r >= 0x1C && r <= 0x1F {
		return true
	}
	return unicode.IsSpace(r)
}

// Strip is Python's s.strip() without arguments.
func Strip(s string) string { return strings.TrimFunc(s, IsSpace) }

// StripChars is Python's s.strip(chars).
func StripChars(s, chars string) string { return strings.Trim(s, chars) }

// Splitlines is Python's s.splitlines() (no keepends).
func Splitlines(s string) []string {
	var out []string
	start := 0
	rs := []rune(s)
	for i := 0; i < len(rs); i++ {
		switch rs[i] {
		case '\n', '\r', '\v', '\f', 0x1C, 0x1D, 0x1E, 0x85, 0x2028, 0x2029:
			out = append(out, string(rs[start:i]))
			if rs[i] == '\r' && i+1 < len(rs) && rs[i+1] == '\n' {
				i++
			}
			start = i + 1
		}
	}
	if start < len(rs) {
		out = append(out, string(rs[start:]))
	}
	return out
}
