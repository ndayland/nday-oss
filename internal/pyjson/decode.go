package pyjson

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

// maxIntDigits mirrors CPython's default sys.int_info.default_max_str_digits:
// json.loads raises ValueError for longer integer literals.
const maxIntDigits = 4300

// maxDepth bounds nesting (CPython raises RecursionError at roughly 1000).
const maxDepth = 10000

// SyntaxError is a decode failure at a byte offset.
type SyntaxError struct {
	Msg    string
	Offset int
}

func (e *SyntaxError) Error() string { return fmt.Sprintf("%s (byte %d)", e.Msg, e.Offset) }

// Decode parses data like Python's json.loads(bytes) (UTF-8 input).
// See the package documentation for the value model.
func Decode(data []byte) (any, error) {
	if len(data) >= 3 && data[0] == 0xEF && data[1] == 0xBB && data[2] == 0xBF {
		data = data[3:] // json.loads(bytes) decodes with utf-8-sig
	}
	if !utf8.Valid(data) {
		return nil, errors.New("pyjson: input is not valid UTF-8")
	}
	d := &decoder{s: data}
	d.ws()
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	d.ws()
	if d.i != len(d.s) {
		return nil, d.err("Extra data")
	}
	return v, nil
}

// DecodeString is Decode for a string (e.g. PostgreSQL jsonb::text output).
func DecodeString(s string) (any, error) { return Decode([]byte(s)) }

type decoder struct {
	s []byte
	i int
}

func (d *decoder) err(msg string) error { return &SyntaxError{Msg: msg, Offset: d.i} }

func (d *decoder) ws() {
	for d.i < len(d.s) {
		switch d.s[d.i] {
		case ' ', '\t', '\n', '\r':
			d.i++
		default:
			return
		}
	}
}

func (d *decoder) lit(word string) bool {
	if len(d.s)-d.i >= len(word) && string(d.s[d.i:d.i+len(word)]) == word {
		d.i += len(word)
		return true
	}
	return false
}

func (d *decoder) value(depth int) (any, error) {
	if depth > maxDepth {
		return nil, d.err("nesting too deep")
	}
	if d.i >= len(d.s) {
		return nil, d.err("Expecting value")
	}
	switch c := d.s[d.i]; {
	case c == '"':
		return d.str()
	case c == '{':
		return d.object(depth)
	case c == '[':
		return d.array(depth)
	case c == 'n' && d.lit("null"):
		return nil, nil
	case c == 't' && d.lit("true"):
		return true, nil
	case c == 'f' && d.lit("false"):
		return false, nil
	case c == 'N' && d.lit("NaN"):
		return math.NaN(), nil
	case c == 'I' && d.lit("Infinity"):
		return math.Inf(1), nil
	case c == '-' && d.lit("-Infinity"):
		return math.Inf(-1), nil
	case c == '-' || (c >= '0' && c <= '9'):
		return d.number()
	}
	return nil, d.err("Expecting value")
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

// number matches CPython's NUMBER_RE: (-?(?:0|[1-9]\d*))(\.\d+)?([eE][-+]?\d+)?
func (d *decoder) number() (any, error) {
	start := d.i
	if d.s[d.i] == '-' {
		d.i++
	}
	if d.i >= len(d.s) || !isDigit(d.s[d.i]) {
		d.i = start
		return nil, d.err("Expecting value")
	}
	if d.s[d.i] == '0' {
		d.i++
	} else {
		for d.i < len(d.s) && isDigit(d.s[d.i]) {
			d.i++
		}
	}
	isFloat := false
	if d.i+1 < len(d.s) && d.s[d.i] == '.' && isDigit(d.s[d.i+1]) {
		isFloat = true
		d.i += 2
		for d.i < len(d.s) && isDigit(d.s[d.i]) {
			d.i++
		}
	}
	if d.i < len(d.s) && (d.s[d.i] == 'e' || d.s[d.i] == 'E') {
		j := d.i + 1
		if j < len(d.s) && (d.s[j] == '+' || d.s[j] == '-') {
			j++
		}
		if j < len(d.s) && isDigit(d.s[j]) {
			for j < len(d.s) && isDigit(d.s[j]) {
				j++
			}
			isFloat = true
			d.i = j
		}
	}
	lit := string(d.s[start:d.i])
	if !isFloat {
		n := len(lit)
		if lit[0] == '-' {
			n--
		}
		if n > maxIntDigits {
			return nil, d.err("integer literal exceeds 4300 digits")
		}
		return Int(canonicalIntText(lit)), nil
	}
	f, err := strconv.ParseFloat(lit, 64)
	if err != nil {
		var ne *strconv.NumError
		if !errors.As(err, &ne) || ne.Err != strconv.ErrRange {
			return nil, d.err("bad number " + lit)
		}
		// ErrRange: f is ±Inf (overflow) or the correctly rounded tiny value,
		// exactly what Python's float() returns.
	}
	return f, nil
}

func hexVal(c byte) (rune, bool) {
	switch {
	case c >= '0' && c <= '9':
		return rune(c - '0'), true
	case c >= 'a' && c <= 'f':
		return rune(c-'a') + 10, true
	case c >= 'A' && c <= 'F':
		return rune(c-'A') + 10, true
	}
	return 0, false
}

func (d *decoder) hex4(at int) (rune, bool) {
	if at+4 > len(d.s) {
		return 0, false
	}
	var r rune
	for k := 0; k < 4; k++ {
		v, ok := hexVal(d.s[at+k])
		if !ok {
			return 0, false
		}
		r = r<<4 | v
	}
	return r, true
}

func (d *decoder) str() (string, error) {
	d.i++ // opening quote
	// Fast path: no escapes.
	start := d.i
	for d.i < len(d.s) {
		c := d.s[d.i]
		if c == '"' {
			s := string(d.s[start:d.i])
			d.i++
			return s, nil
		}
		if c == '\\' {
			break
		}
		if c < 0x20 {
			return "", d.err("Invalid control character")
		}
		d.i++
	}
	buf := append([]byte(nil), d.s[start:d.i]...)
	for {
		if d.i >= len(d.s) {
			return "", d.err("Unterminated string")
		}
		c := d.s[d.i]
		switch {
		case c == '"':
			d.i++
			return string(buf), nil
		case c < 0x20:
			return "", d.err("Invalid control character")
		case c != '\\':
			buf = append(buf, c)
			d.i++
			continue
		}
		// escape
		if d.i+1 >= len(d.s) {
			return "", d.err("Unterminated string")
		}
		e := d.s[d.i+1]
		d.i += 2
		switch e {
		case '"', '\\', '/':
			buf = append(buf, e)
		case 'b':
			buf = append(buf, '\b')
		case 'f':
			buf = append(buf, '\f')
		case 'n':
			buf = append(buf, '\n')
		case 'r':
			buf = append(buf, '\r')
		case 't':
			buf = append(buf, '\t')
		case 'u':
			r, ok := d.hex4(d.i)
			if !ok {
				return "", d.err("Invalid \\uXXXX escape")
			}
			d.i += 4
			if r >= 0xD800 && r <= 0xDBFF {
				// Python combines a following low surrogate escape.
				if d.i+1 < len(d.s) && d.s[d.i] == '\\' && d.s[d.i+1] == 'u' {
					if r2, ok := d.hex4(d.i + 2); ok && r2 >= 0xDC00 && r2 <= 0xDFFF {
						d.i += 6
						r = 0x10000 + (r-0xD800)<<10 + (r2 - 0xDC00)
						buf = utf8.AppendRune(buf, r)
						continue
					}
				}
				return "", d.err("lone surrogate escape (not representable; Python fails later when hashing/storing it)")
			}
			if r >= 0xDC00 && r <= 0xDFFF {
				return "", d.err("lone surrogate escape (not representable; Python fails later when hashing/storing it)")
			}
			buf = utf8.AppendRune(buf, r)
		default:
			d.i -= 2
			return "", d.err("Invalid \\escape")
		}
	}
}

func (d *decoder) array(depth int) ([]any, error) {
	d.i++
	out := []any{}
	d.ws()
	if d.i < len(d.s) && d.s[d.i] == ']' {
		d.i++
		return out, nil
	}
	for {
		d.ws()
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
		d.ws()
		if d.i >= len(d.s) {
			return nil, d.err("Expecting ',' delimiter")
		}
		switch d.s[d.i] {
		case ',':
			d.i++
		case ']':
			d.i++
			return out, nil
		default:
			return nil, d.err("Expecting ',' delimiter")
		}
	}
}

func (d *decoder) object(depth int) (*Object, error) {
	d.i++
	o := NewObject()
	d.ws()
	if d.i < len(d.s) && d.s[d.i] == '}' {
		d.i++
		return o, nil
	}
	for {
		d.ws()
		if d.i >= len(d.s) || d.s[d.i] != '"' {
			return nil, d.err("Expecting property name enclosed in double quotes")
		}
		k, err := d.str()
		if err != nil {
			return nil, err
		}
		d.ws()
		if d.i >= len(d.s) || d.s[d.i] != ':' {
			return nil, d.err("Expecting ':' delimiter")
		}
		d.i++
		d.ws()
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		o.Set(k, v)
		d.ws()
		if d.i >= len(d.s) {
			return nil, d.err("Expecting ',' delimiter")
		}
		switch d.s[d.i] {
		case ',':
			d.i++
		case '}':
			d.i++
			return o, nil
		default:
			return nil, d.err("Expecting ',' delimiter")
		}
	}
}
