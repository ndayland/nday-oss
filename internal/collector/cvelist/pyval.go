package cvelist

import (
	"fmt"
	"math/big"
	"strings"
	"unicode"

	"nday.land/nday/internal/pyjson"
	"nday.land/nday/internal/pystr"
)

// Python value semantics needed to port cvelist.py faithfully on arbitrary
// (possibly malformed) upstream JSON. A Python TypeError/AttributeError is a
// plain Go error here (fatal for the run), never a NormalizeError.

// truthy is Python's bool(v) for a decoded JSON value.
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
	case float64:
		return x != 0 // NaN is truthy, like Python
	case []any:
		return len(x) > 0
	case *pyjson.Object:
		return x.Len() > 0
	case map[string]any:
		return len(x) > 0
	default:
		return true
	}
}

// pyTypeName is type(v).__name__ for a decoded JSON value.
func pyTypeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case string:
		return "str"
	case pyjson.Int:
		return "int"
	case float64:
		return "float"
	case []any:
		return "list"
	case *pyjson.Object, map[string]any:
		return "dict"
	default:
		return fmt.Sprintf("%T", v)
	}
}

// TypeError mirrors a Python TypeError / AttributeError raised on malformed
// input (fatal for the run in Python, so fatal here).
type TypeError struct{ Msg string }

func (e *TypeError) Error() string { return e.Msg }

// iterOr is `for x in (v or [])`: falsy -> nothing; list -> items; dict ->
// keys; str -> its characters; any other truthy value -> TypeError.
func iterOr(v any) ([]any, error) {
	if !truthy(v) {
		return nil, nil
	}
	switch x := v.(type) {
	case []any:
		return x, nil
	case *pyjson.Object:
		out := make([]any, 0, x.Len())
		for _, k := range x.Keys() {
			out = append(out, k)
		}
		return out, nil
	case string:
		out := []any{}
		for _, r := range x {
			out = append(out, string(r))
		}
		return out, nil
	default:
		return nil, &TypeError{fmt.Sprintf("'%s' object is not iterable", pyTypeName(v))}
	}
}

// getOrEmpty is `(v or {}).get(key)`: falsy -> None; dict -> get; any other
// truthy value -> AttributeError.
func getOrEmpty(v any, key string) (any, error) {
	if !truthy(v) {
		return nil, nil
	}
	if o, ok := v.(*pyjson.Object); ok {
		return o.Get(key), nil
	}
	return nil, &TypeError{fmt.Sprintf("'%s' object has no attribute 'get'", pyTypeName(v))}
}

// asObject returns v as a dict, or nil (isinstance(v, dict) is false).
func asObject(v any) *pyjson.Object {
	o, _ := v.(*pyjson.Object)
	return o
}

// pyStrEq is `v == s` for a JSON value and a str.
func pyStrEq(v any, s string) bool {
	x, ok := v.(string)
	return ok && x == s
}

// parsePyInt is Python's int(str) in base 10: surrounding whitespace, an
// optional sign, Unicode decimal digits, single underscores between digits.
func parsePyInt(raw string) (*big.Int, bool) {
	s := pystr.Strip(raw)
	neg := false
	if s != "" && (s[0] == '+' || s[0] == '-') {
		neg = s[0] == '-'
		s = s[1:]
	}
	if s == "" {
		return nil, false
	}
	var digits strings.Builder
	prevUnderscore, first := false, true
	for _, r := range s {
		switch {
		case r == '_':
			if first || prevUnderscore {
				return nil, false
			}
			prevUnderscore = true
			continue
		case unicode.Is(unicode.Nd, r):
			d, ok := digitValue(r)
			if !ok {
				return nil, false
			}
			digits.WriteByte(byte('0' + d))
		default:
			return nil, false
		}
		prevUnderscore, first = false, false
	}
	if prevUnderscore {
		return nil, false
	}
	n, ok := new(big.Int).SetString(digits.String(), 10)
	if !ok {
		return nil, false
	}
	if neg {
		n.Neg(n)
	}
	return n, true
}

// digitValue is the decimal value of a Unicode Nd rune: Nd digits are
// encoded in contiguous ascending runs whose length is a multiple of ten,
// each starting at a zero.
func digitValue(r rune) (int, bool) {
	if !unicode.Is(unicode.Nd, r) {
		return 0, false
	}
	z := r
	for z > 0 && unicode.Is(unicode.Nd, z-1) {
		z--
	}
	return int(r-z) % 10, true
}

// maxSetting saturates huge integer settings (Python ints are unbounded).
const maxSetting = 1 << 40

// clampInt converts a big.Int to int, saturating at +-maxSetting.
func clampInt(n *big.Int) int {
	if n.Cmp(big.NewInt(maxSetting)) > 0 {
		return maxSetting
	}
	if n.Cmp(big.NewInt(-maxSetting)) < 0 {
		return -maxSetting
	}
	return int(n.Int64())
}
