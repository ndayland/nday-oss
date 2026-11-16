package pyjson

import (
	"fmt"
	"strings"
	"unicode"
)

// Repr is Python's repr() for a decoded JSON value (None, True, 'str',
// [1, 2], {'k': 'v'} in insertion order, floats via FloatRepr). Collectors use
// it so NormalizeError messages (stored in collector_state.last_error) match
// the Python implementation's f"...{value!r}".
func Repr(v any) string {
	var b strings.Builder
	repr(&b, v)
	return b.String()
}

func repr(b *strings.Builder, v any) {
	switch x := v.(type) {
	case nil:
		b.WriteString("None")
	case bool:
		if x {
			b.WriteString("True")
		} else {
			b.WriteString("False")
		}
	case string:
		b.WriteString(StrRepr(x))
	case Int:
		b.WriteString(string(x))
	case int:
		b.WriteString(formatInt(int64(x)))
	case int64:
		b.WriteString(formatInt(x))
	case float64:
		b.WriteString(FloatRepr(x))
	case []any:
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(", ")
			}
			repr(b, e)
		}
		b.WriteByte(']')
	case *Object:
		b.WriteByte('{')
		for i, k := range x.Keys() {
			if i > 0 {
				b.WriteString(", ")
			}
			b.WriteString(StrRepr(k))
			b.WriteString(": ")
			repr(b, x.Get(k))
		}
		b.WriteByte('}')
	default:
		fmt.Fprintf(b, "%v", v)
	}
}

// StrRepr is Python's repr(str): single quotes unless the text contains ' and
// no "; escapes \\, the quote, \t \n \r; non-printable runes as \xNN, \uNNNN or
// \UNNNNNNNN (Python's str.isprintable: everything except categories Cc, Cf,
// Cs, Co, Cn, Zl, Zp and Zs other than ' ', which is what Go's unicode.IsPrint
// computes, modulo the Unicode version).
func StrRepr(s string) string {
	quote := byte('\'')
	if strings.ContainsRune(s, '\'') && !strings.ContainsRune(s, '"') {
		quote = '"'
	}
	var b strings.Builder
	b.WriteByte(quote)
	for _, r := range s {
		switch {
		case r == rune(quote) || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r == '\t':
			b.WriteString(`\t`)
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r < 0x20 || r == 0x7F:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r < 0x7F:
			b.WriteRune(r)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		case r <= 0xFF:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xFFFF:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
	}
	b.WriteByte(quote)
	return b.String()
}
