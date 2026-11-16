package pyjson

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Int is a JSON integer kept as its canonical decimal text (Python int has
// arbitrary precision). Canonical: optional '-', no leading zeros, never "-0".
type Int string

// IntOf returns the Int for a Go integer.
func IntOf(n int64) Int {
	return Int(formatInt(n))
}

// Object is an insertion-ordered JSON object with Python dict semantics.
type Object struct {
	keys []string
	vals map[string]any
}

// NewObject returns an empty object.
func NewObject() *Object { return &Object{vals: map[string]any{}} }

// Set stores v under k. A new key is appended; an existing key keeps its
// position and gets the new value (like assigning to a Python dict).
func (o *Object) Set(k string, v any) {
	if o.vals == nil {
		o.vals = map[string]any{}
	}
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
}

// Get returns the value for k, or nil if absent (like dict.get).
func (o *Object) Get(k string) any {
	if o == nil {
		return nil
	}
	return o.vals[k]
}

// Lookup returns the value for k and whether it is present.
func (o *Object) Lookup(k string) (any, bool) {
	if o == nil {
		return nil, false
	}
	v, ok := o.vals[k]
	return v, ok
}

// Keys returns the keys in insertion order (do not modify).
func (o *Object) Keys() []string {
	if o == nil {
		return nil
	}
	return o.keys
}

// Len is the number of keys.
func (o *Object) Len() int {
	if o == nil {
		return 0
	}
	return len(o.keys)
}

// Clone returns a shallow copy (values are shared).
func (o *Object) Clone() *Object {
	c := &Object{keys: append([]string(nil), o.Keys()...), vals: make(map[string]any, o.Len())}
	for _, k := range c.keys {
		c.vals[k] = o.vals[k]
	}
	return c
}

// Canonical is Python's canonical_json(v):
// json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).
func Canonical(v any) (string, error) {
	return Encode(v, Options{SortKeys: true, Compact: true})
}

// ContentHash is Python's content_hash(v): sha256 hex of canonical_json(v) in UTF-8.
func ContentHash(v any) (string, error) {
	s, err := Canonical(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:]), nil
}

func formatInt(n int64) string {
	neg := n < 0
	u := uint64(n)
	if neg {
		u = -u
	}
	var b [24]byte
	i := len(b)
	for {
		i--
		b[i] = byte('0' + u%10)
		u /= 10
		if u == 0 {
			break
		}
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// canonicalIntText turns a JSON integer literal into Python's int repr.
func canonicalIntText(lit string) string {
	neg := strings.HasPrefix(lit, "-")
	digits := strings.TrimLeft(strings.TrimPrefix(lit, "-"), "0")
	if digits == "" {
		return "0"
	}
	if neg {
		return "-" + digits
	}
	return digits
}
