package pyjson

import (
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Options selects the json.dumps flavour.
type Options struct {
	SortKeys bool // sort_keys=True (code point order)
	// Compact: separators=(",", ":"); otherwise Python's default (", ", ": ").
	Compact bool
	// EnsureASCII: ensure_ascii=True (escape everything outside 0x20..0x7E).
	EnsureASCII bool
	// Indent > 0: indent=N (item separator "," + newline, key separator ": ").
	Indent int
}

// Encode renders v like json.dumps(v, ...) with the given options.
func Encode(v any, opt Options) (string, error) {
	var b strings.Builder
	if err := encodeValue(&b, v, opt, 0); err != nil {
		return "", err
	}
	return b.String(), nil
}

// FloatRepr is Python's repr(float) (also what json.dumps writes for finite floats).
func FloatRepr(f float64) string {
	switch {
	case math.IsNaN(f):
		return "nan"
	case math.IsInf(f, 1):
		return "inf"
	case math.IsInf(f, -1):
		return "-inf"
	}
	e := strconv.FormatFloat(f, 'e', -1, 64) // shortest round-trip digits: d[.ddd]e±XX
	p := strings.LastIndexByte(e, 'e')
	exp, _ := strconv.Atoi(e[p+1:])
	// CPython float_repr_style 'r': exponent form iff decpt <= -4 or decpt > 16,
	// where decpt = exp + 1.
	if exp < -4 || exp >= 16 {
		return e // Go and CPython both write at least two exponent digits with a sign
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	if !strings.ContainsAny(s, ".") {
		s += ".0"
	}
	return s
}

func jsonFloat(f float64) string {
	switch {
	case math.IsNaN(f):
		return "NaN"
	case math.IsInf(f, 1):
		return "Infinity"
	case math.IsInf(f, -1):
		return "-Infinity"
	}
	return FloatRepr(f)
}

func newline(b *strings.Builder, opt Options, level int) {
	if opt.Indent > 0 {
		b.WriteByte('\n')
		b.WriteString(strings.Repeat(" ", opt.Indent*level))
	}
}

func itemSep(opt Options) string {
	switch {
	case opt.Indent > 0 || opt.Compact:
		return ","
	default:
		return ", "
	}
}

func keySep(opt Options) string {
	if opt.Compact {
		return ":"
	}
	return ": "
}

func encodeValue(b *strings.Builder, v any, opt Options, level int) error {
	switch x := v.(type) {
	case nil:
		b.WriteString("null")
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case string:
		return encodeString(b, x, opt.EnsureASCII)
	case Int:
		b.WriteString(string(x))
	case int:
		b.WriteString(formatInt(int64(x)))
	case int64:
		b.WriteString(formatInt(x))
	case float64:
		b.WriteString(jsonFloat(x))
	case []any:
		if len(x) == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteByte('[')
		for i, e := range x {
			if i > 0 {
				b.WriteString(itemSep(opt))
			}
			newline(b, opt, level+1)
			if err := encodeValue(b, e, opt, level+1); err != nil {
				return err
			}
		}
		newline(b, opt, level)
		b.WriteByte(']')
	case []string:
		arr := make([]any, len(x))
		for i, s := range x {
			arr[i] = s
		}
		return encodeValue(b, arr, opt, level)
	case *Object:
		if x == nil {
			b.WriteString("null")
			return nil
		}
		return encodeObject(b, x.keys, func(k string) any { return x.vals[k] }, opt, level)
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		sort.Strings(keys) // a Go map has no order; sorted is the only deterministic choice
		return encodeObject(b, keys, func(k string) any { return x[k] }, opt, level)
	default:
		return fmt.Errorf("pyjson: cannot encode %T", v)
	}
	return nil
}

func encodeObject(b *strings.Builder, keys []string, get func(string) any, opt Options, level int) error {
	if len(keys) == 0 {
		b.WriteString("{}")
		return nil
	}
	if opt.SortKeys {
		keys = append([]string(nil), keys...)
		// Byte order of valid UTF-8 equals code point order (Python str order).
		sort.Strings(keys)
	}
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteString(itemSep(opt))
		}
		newline(b, opt, level+1)
		if err := encodeString(b, k, opt.EnsureASCII); err != nil {
			return err
		}
		b.WriteString(keySep(opt))
		if err := encodeValue(b, get(k), opt, level+1); err != nil {
			return err
		}
	}
	newline(b, opt, level)
	b.WriteByte('}')
	return nil
}

const lowerHex = "0123456789abcdef"

func writeU(b *strings.Builder, r rune) {
	b.WriteString(`\u`)
	b.WriteByte(lowerHex[r>>12&0xF])
	b.WriteByte(lowerHex[r>>8&0xF])
	b.WriteByte(lowerHex[r>>4&0xF])
	b.WriteByte(lowerHex[r&0xF])
}

func encodeString(b *strings.Builder, s string, ensureASCII bool) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("pyjson: string is not valid UTF-8: %q", s)
	}
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		case '\n':
			b.WriteString(`\n`)
		case '\r':
			b.WriteString(`\r`)
		case '\t':
			b.WriteString(`\t`)
		case '\b':
			b.WriteString(`\b`)
		case '\f':
			b.WriteString(`\f`)
		default:
			switch {
			case r < 0x20:
				writeU(b, r)
			case !ensureASCII || r <= 0x7E:
				b.WriteRune(r)
			case r <= 0xFFFF:
				writeU(b, r)
			default:
				r -= 0x10000
				writeU(b, 0xD800|(r>>10)&0x3FF)
				writeU(b, 0xDC00|r&0x3FF)
			}
		}
	}
	b.WriteByte('"')
	return nil
}
