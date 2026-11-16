// Package webauthn verifies WebAuthn (passkey) registrations and
// assertions for the "none" attestation case, following W3C Web
// Authentication Level 3 (Recommendation, 25 August 2026) §7.1 and §7.2.
// It contains a deliberately small CBOR decoder: only what attestation
// objects, authenticator data and COSE keys need, and strict about it.
package webauthn

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"unicode/utf8"
)

// CBOR limits. Inputs are tiny in practice (a COSE key is < 300 bytes for
// RSA-2048 and ~77 bytes for P-256); anything larger is refused.
const (
	MaxCBORBytes = 16 << 10
	maxDepth     = 8
	maxItems     = 512
)

// ErrCBOR is wrapped by every decoding failure.
var ErrCBOR = errors.New("cbor")

// cborMap is a decoded map. Keys are int64 or string (the only key types
// WebAuthn uses); duplicate keys are rejected.
type cborMap map[any]any

type decoder struct {
	b     []byte
	pos   int
	items int
}

func cborErr(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{ErrCBOR}, a...)...)
}

// decodeCBOR decodes exactly one data item that must span all of b.
func decodeCBOR(b []byte) (any, error) {
	v, n, err := decodeCBORPrefix(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, cborErr("%d trailing bytes", len(b)-n)
	}
	return v, nil
}

// decodeCBORPrefix decodes one data item at the start of b and returns how
// many bytes it used (authenticator data embeds a COSE key followed by
// optional extension data, with no length prefix).
func decodeCBORPrefix(b []byte) (any, int, error) {
	if len(b) > MaxCBORBytes {
		return nil, 0, cborErr("input too large")
	}
	d := &decoder{b: b}
	v, err := d.item(0)
	if err != nil {
		return nil, 0, err
	}
	return v, d.pos, nil
}

// head reads the initial byte and argument. Only definite lengths in their
// shortest form (CTAP2 canonical CBOR, WebAuthn §2.4) are accepted.
func (d *decoder) head() (major byte, arg uint64, err error) {
	if d.pos >= len(d.b) {
		return 0, 0, cborErr("unexpected end")
	}
	ib := d.b[d.pos]
	d.pos++
	major, ai := ib>>5, ib&0x1f
	need := 0
	switch {
	case ai < 24:
		return major, uint64(ai), nil
	case ai == 24:
		need = 1
	case ai == 25:
		need = 2
	case ai == 26:
		need = 4
	case ai == 27:
		need = 8
	case ai == 31:
		return 0, 0, cborErr("indefinite length not allowed")
	default:
		return 0, 0, cborErr("reserved additional information %d", ai)
	}
	if len(d.b)-d.pos < need {
		return 0, 0, cborErr("unexpected end")
	}
	p := d.b[d.pos : d.pos+need]
	d.pos += need
	switch need {
	case 1:
		arg = uint64(p[0])
	case 2:
		arg = uint64(binary.BigEndian.Uint16(p))
	case 4:
		arg = uint64(binary.BigEndian.Uint32(p))
	case 8:
		arg = binary.BigEndian.Uint64(p)
	}
	if major == 7 {
		// 1-byte simple values (32..255) and floats are never used by WebAuthn.
		return 0, 0, cborErr("floats and extended simple values not allowed")
	}
	minimal := (need == 1 && arg >= 24) || (need == 2 && arg > 0xff) || (need == 4 && arg > 0xffff) || (need == 8 && arg > 0xffffffff)
	if !minimal {
		return 0, 0, cborErr("non-canonical integer encoding")
	}
	return major, arg, nil
}

func (d *decoder) item(depth int) (any, error) {
	if depth > maxDepth {
		return nil, cborErr("nesting too deep")
	}
	d.items++
	if d.items > maxItems {
		return nil, cborErr("too many items")
	}
	major, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		if arg > math.MaxInt64 {
			return nil, cborErr("integer overflow")
		}
		return int64(arg), nil
	case 1:
		if arg > math.MaxInt64 {
			return nil, cborErr("integer overflow")
		}
		return -1 - int64(arg), nil
	case 2, 3:
		if arg > uint64(len(d.b)-d.pos) {
			return nil, cborErr("string longer than input")
		}
		s := d.b[d.pos : d.pos+int(arg)]
		d.pos += int(arg)
		if major == 3 {
			if !utf8.Valid(s) {
				return nil, cborErr("invalid UTF-8 in text string")
			}
			return string(s), nil
		}
		return append([]byte(nil), s...), nil
	case 4:
		if arg > uint64(len(d.b)-d.pos) { // each item takes at least one byte
			return nil, cborErr("array longer than input")
		}
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if arg > uint64(len(d.b)-d.pos)/2 {
			return nil, cborErr("map longer than input")
		}
		out := make(cborMap, arg)
		for i := uint64(0); i < arg; i++ {
			k, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case int64, string:
			default:
				return nil, cborErr("map key of unsupported type %T", k)
			}
			if _, dup := out[k]; dup {
				return nil, cborErr("duplicate map key %v", k)
			}
			v, err := d.item(depth + 1)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case 6:
		return nil, cborErr("tags not allowed")
	default: // 7
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
		return nil, cborErr("unsupported simple value or float")
	}
}
