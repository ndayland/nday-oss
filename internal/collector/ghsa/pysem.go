package ghsa

// Python semantics the GHSA collector depends on that the foundation packages
// do not provide: str.isdigit()/str.isdecimal() with CPython 3.13's Unicode
// 15.1 tables (Go 1.27's unicode package is Unicode 17, so \p{Nd} is NOT the
// same set), int(str), str(value), truthiness and the regex classes \d / \s
// of Python's `re` for str patterns.
//
// The tables were generated with the project's interpreter (.venv, CPython
// 3.13.14, unicodedata 15.1.0):
//
//	re.compile(r"\d").fullmatch(c)  == str.isdecimal(c)   -> pyDecimal
//	str.isdigit(c)                                        -> pyDigit
//	re.compile(r"\s").fullmatch(c)  == str.isspace(c)     -> pystr.IsSpace
//
// pysem_test.go checks them against testdata/python_classes.json, written by
// the same interpreter.

import (
	"fmt"
	"math/big"
	"strings"
	"unicode"
	"unicode/utf8"

	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/pystr"
)

type cpRange struct{ lo, hi rune }

// pyDecimal: Python str.isdecimal() / re `\d` (Unicode 15.1, category Nd).
// Every range is a run of whole 0..9 blocks, so a digit's value is
// (cp - lo) % 10.
var pyDecimal = []cpRange{
	{0x30, 0x39}, {0x660, 0x669}, {0x6F0, 0x6F9}, {0x7C0, 0x7C9}, {0x966, 0x96F}, {0x9E6, 0x9EF},
	{0xA66, 0xA6F}, {0xAE6, 0xAEF}, {0xB66, 0xB6F}, {0xBE6, 0xBEF}, {0xC66, 0xC6F}, {0xCE6, 0xCEF},
	{0xD66, 0xD6F}, {0xDE6, 0xDEF}, {0xE50, 0xE59}, {0xED0, 0xED9}, {0xF20, 0xF29}, {0x1040, 0x1049},
	{0x1090, 0x1099}, {0x17E0, 0x17E9}, {0x1810, 0x1819}, {0x1946, 0x194F}, {0x19D0, 0x19D9},
	{0x1A80, 0x1A89}, {0x1A90, 0x1A99}, {0x1B50, 0x1B59}, {0x1BB0, 0x1BB9}, {0x1C40, 0x1C49},
	{0x1C50, 0x1C59}, {0xA620, 0xA629}, {0xA8D0, 0xA8D9}, {0xA900, 0xA909}, {0xA9D0, 0xA9D9},
	{0xA9F0, 0xA9F9}, {0xAA50, 0xAA59}, {0xABF0, 0xABF9}, {0xFF10, 0xFF19}, {0x104A0, 0x104A9},
	{0x10D30, 0x10D39}, {0x11066, 0x1106F}, {0x110F0, 0x110F9}, {0x11136, 0x1113F}, {0x111D0, 0x111D9},
	{0x112F0, 0x112F9}, {0x11450, 0x11459}, {0x114D0, 0x114D9}, {0x11650, 0x11659}, {0x116C0, 0x116C9},
	{0x11730, 0x11739}, {0x118E0, 0x118E9}, {0x11950, 0x11959}, {0x11C50, 0x11C59}, {0x11D50, 0x11D59},
	{0x11DA0, 0x11DA9}, {0x11F50, 0x11F59}, {0x16A60, 0x16A69}, {0x16AC0, 0x16AC9}, {0x16B50, 0x16B59},
	{0x1D7CE, 0x1D7FF}, {0x1E140, 0x1E149}, {0x1E2F0, 0x1E2F9}, {0x1E4F0, 0x1E4F9}, {0x1E950, 0x1E959},
	{0x1FBF0, 0x1FBF9},
}

// pyDigit: Python str.isdigit() (Numeric_Type Decimal or Digit): pyDecimal
// plus superscripts, circled digits, etc. int()/float() reject the extra ones.
var pyDigit = []cpRange{
	{0x30, 0x39}, {0xB2, 0xB3}, {0xB9, 0xB9}, {0x660, 0x669}, {0x6F0, 0x6F9}, {0x7C0, 0x7C9},
	{0x966, 0x96F}, {0x9E6, 0x9EF}, {0xA66, 0xA6F}, {0xAE6, 0xAEF}, {0xB66, 0xB6F}, {0xBE6, 0xBEF},
	{0xC66, 0xC6F}, {0xCE6, 0xCEF}, {0xD66, 0xD6F}, {0xDE6, 0xDEF}, {0xE50, 0xE59}, {0xED0, 0xED9},
	{0xF20, 0xF29}, {0x1040, 0x1049}, {0x1090, 0x1099}, {0x1369, 0x1371}, {0x17E0, 0x17E9},
	{0x1810, 0x1819}, {0x1946, 0x194F}, {0x19D0, 0x19DA}, {0x1A80, 0x1A89}, {0x1A90, 0x1A99},
	{0x1B50, 0x1B59}, {0x1BB0, 0x1BB9}, {0x1C40, 0x1C49}, {0x1C50, 0x1C59}, {0x2070, 0x2070},
	{0x2074, 0x2079}, {0x2080, 0x2089}, {0x2460, 0x2468}, {0x2474, 0x247C}, {0x2488, 0x2490},
	{0x24EA, 0x24EA}, {0x24F5, 0x24FD}, {0x24FF, 0x24FF}, {0x2776, 0x277E}, {0x2780, 0x2788},
	{0x278A, 0x2792}, {0xA620, 0xA629}, {0xA8D0, 0xA8D9}, {0xA900, 0xA909}, {0xA9D0, 0xA9D9},
	{0xA9F0, 0xA9F9}, {0xAA50, 0xAA59}, {0xABF0, 0xABF9}, {0xFF10, 0xFF19}, {0x104A0, 0x104A9},
	{0x10A40, 0x10A43}, {0x10D30, 0x10D39}, {0x10E60, 0x10E68}, {0x11052, 0x1105A}, {0x11066, 0x1106F},
	{0x110F0, 0x110F9}, {0x11136, 0x1113F}, {0x111D0, 0x111D9}, {0x112F0, 0x112F9}, {0x11450, 0x11459},
	{0x114D0, 0x114D9}, {0x11650, 0x11659}, {0x116C0, 0x116C9}, {0x11730, 0x11739}, {0x118E0, 0x118E9},
	{0x11950, 0x11959}, {0x11C50, 0x11C59}, {0x11D50, 0x11D59}, {0x11DA0, 0x11DA9}, {0x11F50, 0x11F59},
	{0x16A60, 0x16A69}, {0x16AC0, 0x16AC9}, {0x16B50, 0x16B59}, {0x1D7CE, 0x1D7FF}, {0x1E140, 0x1E149},
	{0x1E2F0, 0x1E2F9}, {0x1E4F0, 0x1E4F9}, {0x1E950, 0x1E959}, {0x1F100, 0x1F10A}, {0x1FBF0, 0x1FBF9},
}

func inRanges(r rune, rs []cpRange) (cpRange, bool) {
	for _, x := range rs {
		if r < x.lo {
			return cpRange{}, false
		}
		if r <= x.hi {
			return x, true
		}
	}
	return cpRange{}, false
}

// decimalValue returns the digit value of a Python decimal character.
func decimalValue(r rune) (int, bool) {
	x, ok := inRanges(r, pyDecimal)
	if !ok {
		return 0, false
	}
	return int(r-x.lo) % 10, true
}

// isDigitStr is Python's s.isdigit() (False for "").
func isDigitStr(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if _, ok := inRanges(r, pyDigit); !ok {
			return false
		}
	}
	return true
}

// pyIntError mirrors Python's ValueError from int(str).
type pyIntError struct{ s string }

func (e *pyIntError) Error() string {
	return "invalid literal for int() with base 10: " + pyStrRepr(e.s)
}

// pyInt is Python's int(s) for base 10: surrounding Unicode whitespace,
// optional sign, decimal digits (any Unicode Nd) with single underscores
// between digits.
func pyInt(s string) (*big.Int, error) {
	t := pystr.Strip(s)
	neg := false
	if t != "" && (t[0] == '+' || t[0] == '-') {
		neg = t[0] == '-'
		t = t[1:]
	}
	if t == "" {
		return nil, &pyIntError{s}
	}
	var b strings.Builder
	prevUnderscore := true // a leading underscore is invalid
	for _, r := range t {
		if r == '_' {
			if prevUnderscore {
				return nil, &pyIntError{s}
			}
			prevUnderscore = true
			continue
		}
		v, ok := decimalValue(r)
		if !ok {
			return nil, &pyIntError{s}
		}
		b.WriteByte(byte('0' + v))
		prevUnderscore = false
	}
	if prevUnderscore { // trailing underscore
		return nil, &pyIntError{s}
	}
	if b.Len() > 4300 { // sys.int_info.default_max_str_digits (ValueError)
		return nil, fmt.Errorf("Exceeds the limit (4300 digits) for integer string conversion: value has %d digits; use sys.set_int_max_str_digits() to increase the limit", b.Len())
	}
	n, _ := new(big.Int).SetString(b.String(), 10)
	if neg {
		n.Neg(n)
	}
	return n, nil
}

// pyFloatDigits is float(s) for a string that passed s.isdigit() (Python
// only calls float() after that check): decimal digits convert, other isdigit
// characters (superscripts...) make float() raise ValueError.
func pyFloatDigits(s string) (float64, error) {
	n, err := pyInt(s)
	if err != nil {
		return 0, fmt.Errorf("could not convert string to float: %s", pyStrRepr(s))
	}
	f, _ := new(big.Float).SetInt(n).Float64()
	return f, nil
}

// truthy is Python's bool(value) for pyjson values.
func truthy(v any) bool {
	switch x := v.(type) {
	case nil:
		return false
	case bool:
		return x
	case string:
		return x != ""
	case pyjson.Int:
		return x != "0"
	case int:
		return x != 0
	case int64:
		return x != 0
	case float64:
		return x != 0 // NaN is truthy, like Python
	case []any:
		return len(x) > 0
	case *pyjson.Object:
		return x.Len() > 0
	case map[string]any:
		return len(x) > 0
	}
	return true
}

// pyStr is Python's str(value) for pyjson values (repr except for str).
func pyStr(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return pyRepr(v)
}

// truncRunes is Python's s[:n].
func truncRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	i := 0
	for j := range s {
		if i == n {
			return s[:j]
		}
		i++
	}
	return s
}

// reSpace is the body of a regexp character class equal to Python's `\s`
// for str patterns (== str.isspace(), which pystr.IsSpace implements). Go's
// `\s` is only [\t\n\f\r ] (not even \v).
const reSpace = `\t-\r\x{1C}-\x{20}\x{85}\x{A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}`

// reDecimal is the body of a character class equal to Python's `\d`.
var reDecimal = func() string {
	var b strings.Builder
	for _, r := range pyDecimal {
		fmt.Fprintf(&b, `\x{%X}-\x{%X}`, r.lo, r.hi)
	}
	return b.String()
}()

// goOnlyPrintable: code points Go 1.27's unicode.IsPrint (Unicode 17) treats
// as printable but CPython 3.13's str.isprintable() (Unicode 15.1) does not
// (characters assigned in Unicode 16/17). Python's repr() escapes them.
var goOnlyPrintable = []cpRange{
	{0x88F, 0x88F}, {0x897, 0x897}, {0xC5C, 0xC5C}, {0xCDC, 0xCDC}, {0x1ACF, 0x1ADD}, {0x1AE0, 0x1AEB},
	{0x1B4E, 0x1B4F}, {0x1B7F, 0x1B7F}, {0x1C89, 0x1C8A}, {0x20C1, 0x20C1}, {0x2427, 0x2429}, {0x2B96, 0x2B96},
	{0x31E4, 0x31E5}, {0xA7CB, 0xA7CF}, {0xA7D2, 0xA7D2}, {0xA7D4, 0xA7D4}, {0xA7DA, 0xA7DC}, {0xA7F1, 0xA7F1},
	{0xFBC3, 0xFBD2}, {0xFD90, 0xFD91}, {0xFDC8, 0xFDCE}, {0x105C0, 0x105F3}, {0x10940, 0x10959}, {0x10D40, 0x10D65},
	{0x10D69, 0x10D85}, {0x10D8E, 0x10D8F}, {0x10EC2, 0x10EC7}, {0x10ED0, 0x10ED8}, {0x10EFA, 0x10EFC}, {0x11380, 0x11389},
	{0x1138B, 0x1138B}, {0x1138E, 0x1138E}, {0x11390, 0x113B5}, {0x113B7, 0x113C0}, {0x113C2, 0x113C2}, {0x113C5, 0x113C5},
	{0x113C7, 0x113CA}, {0x113CC, 0x113D5}, {0x113D7, 0x113D8}, {0x113E1, 0x113E2}, {0x116D0, 0x116E3}, {0x11B60, 0x11B67},
	{0x11BC0, 0x11BE1}, {0x11BF0, 0x11BF9}, {0x11DB0, 0x11DDB}, {0x11DE0, 0x11DE9}, {0x11F5A, 0x11F5A}, {0x13460, 0x143FA},
	{0x16100, 0x16139}, {0x16D40, 0x16D79}, {0x16EA0, 0x16EB8}, {0x16EBB, 0x16ED3}, {0x16FF2, 0x16FF6}, {0x187F8, 0x187FF},
	{0x18CFF, 0x18CFF}, {0x18D09, 0x18D1E}, {0x18D80, 0x18DF2}, {0x1CC00, 0x1CCFC}, {0x1CD00, 0x1CEB3}, {0x1CEBA, 0x1CED0},
	{0x1CEE0, 0x1CEF0}, {0x1E5D0, 0x1E5FA}, {0x1E5FF, 0x1E5FF}, {0x1E6C0, 0x1E6DE}, {0x1E6E0, 0x1E6F5}, {0x1E6FE, 0x1E6FF},
	{0x1F6D8, 0x1F6D8}, {0x1F777, 0x1F77A}, {0x1F8B2, 0x1F8BB}, {0x1F8C0, 0x1F8C1}, {0x1F8D0, 0x1F8D8}, {0x1FA54, 0x1FA57},
	{0x1FA89, 0x1FA8A}, {0x1FA8E, 0x1FA8F}, {0x1FABE, 0x1FABE}, {0x1FAC6, 0x1FAC6}, {0x1FAC8, 0x1FAC8}, {0x1FACD, 0x1FACD},
	{0x1FADC, 0x1FADC}, {0x1FADF, 0x1FADF}, {0x1FAE9, 0x1FAEA}, {0x1FAEF, 0x1FAEF}, {0x1FBCB, 0x1FBEF}, {0x1FBFA, 0x1FBFA},
	{0x2B73A, 0x2B73F}, {0x2CEA2, 0x2CEAD}, {0x323B0, 0x33479},
}

func pyPrintable(r rune) bool {
	if _, ok := inRanges(r, goOnlyPrintable); ok {
		return false
	}
	return unicode.IsPrint(r)
}

// pyStrRepr is Python 3.13's repr(str). Same algorithm as pyjson.StrRepr,
// but with the Unicode 15.1 printable set (pyjson.StrRepr uses Go's tables,
// a foundation gap reported with this port).
func pyStrRepr(s string) string {
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
		case pyPrintable(r):
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

// pyRepr is Python's repr() of a pyjson value, using pyStrRepr for strings
// (pyjson.Repr otherwise).
func pyRepr(v any) string {
	var b strings.Builder
	var rec func(v any)
	rec = func(v any) {
		switch x := v.(type) {
		case string:
			b.WriteString(pyStrRepr(x))
		case []any:
			b.WriteByte('[')
			for i, e := range x {
				if i > 0 {
					b.WriteString(", ")
				}
				rec(e)
			}
			b.WriteByte(']')
		case *pyjson.Object:
			b.WriteByte('{')
			for i, k := range x.Keys() {
				if i > 0 {
					b.WriteString(", ")
				}
				b.WriteString(pyStrRepr(k))
				b.WriteString(": ")
				rec(x.Get(k))
			}
			b.WriteByte('}')
		default:
			b.WriteString(pyjson.Repr(v))
		}
	}
	rec(v)
	return b.String()
}
