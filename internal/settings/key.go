package settings

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strings"
)

// EnvKey is the master key's environment variable (never in the database).
const EnvKey = "NDAY_SETTINGS_KEY"

// MinKeyBytes is the minimum decoded length of the master key.
const MinKeyBytes = 32

// minKeyDistinct is the minimum number of distinct byte values of the
// decoded master key: a cheap check that refuses obviously non-random keys
// (all zeros, a repeated pattern, an ASCII word). 32 random bytes have
// about 30 distinct values; fewer than 16 is practically impossible.
const minKeyDistinct = 16

const (
	sealVersion = 1
	nonceLen    = 12
	hkdfInfo    = "nday settings seal v1"
)

// Key seals and opens secrets. The zero value is unusable; build it with
// ParseKey. It never prints its material.
type Key struct {
	aead cipher.AEAD
}

// ParseKey decodes the master key (base64: standard or URL alphabet, with
// or without padding; surrounding white space ignored) of at least
// MinKeyBytes bytes and derives the sealing key from it (HKDF-SHA256, info
// "nday settings seal v1"). A key with fewer than 16 distinct byte values
// (e.g. all zeros) is refused as not random. An empty string returns (nil, nil): no master
// key configured. Errors never contain the value.
func ParseKey(s string) (*Key, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var raw []byte
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			raw = b
			break
		}
	}
	if raw == nil {
		return nil, fmt.Errorf("%s must be base64 of at least %d random bytes (openssl rand -base64 32)", EnvKey, MinKeyBytes)
	}
	if len(raw) < MinKeyBytes {
		return nil, fmt.Errorf("%s decodes to %d bytes; at least %d random bytes are required (openssl rand -base64 32)", EnvKey, len(raw), MinKeyBytes)
	}
	if distinctBytes(raw) < minKeyDistinct {
		clear(raw)
		return nil, fmt.Errorf("%s does not look random (too few distinct bytes); generate one with openssl rand -base64 32", EnvKey)
	}
	k, err := hkdf.Key(sha256.New, raw, nil, hkdfInfo, 32)
	clear(raw)
	if err != nil {
		return nil, fmt.Errorf("%s: key derivation failed", EnvKey)
	}
	block, err := aes.NewCipher(k)
	clear(k)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", EnvKey, err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("%s: %v", EnvKey, err)
	}
	return &Key{aead: aead}, nil
}

// distinctBytes counts the distinct byte values of b.
func distinctBytes(b []byte) int {
	var seen [256]bool
	n := 0
	for _, c := range b {
		if !seen[c] {
			seen[c] = true
			n++
		}
	}
	return n
}

// KeyFromEnv is ParseKey of lookup(EnvKey) (nil lookup: not configured).
func KeyFromEnv(lookup func(string) (string, bool)) (*Key, error) {
	if lookup == nil {
		return nil, nil
	}
	v, _ := lookup(EnvKey)
	return ParseKey(v)
}

// ErrNoKey: a secret was to be sealed or opened without a master key.
var ErrNoKey = errors.New(EnvKey + " is not set")

// errOpen is the only error of open: it says nothing about the data.
var errOpen = errors.New("cannot be decrypted (wrong " + EnvKey + " or damaged value)")

// seal returns version(1) | nonce(12) | ciphertext+tag, bound to the key
// name (AAD) so the ciphertext of one setting cannot be moved to another.
func (k *Key) seal(name string, plaintext []byte) ([]byte, error) {
	if k == nil || k.aead == nil {
		return nil, ErrNoKey
	}
	out := make([]byte, 1+nonceLen, 1+nonceLen+len(plaintext)+k.aead.Overhead())
	out[0] = sealVersion
	if _, err := rand.Read(out[1 : 1+nonceLen]); err != nil {
		return nil, err
	}
	return k.aead.Seal(out, out[1:1+nonceLen], plaintext, []byte(name)), nil
}

// open reverses seal for the same name.
func (k *Key) open(name string, sealed []byte) ([]byte, error) {
	if k == nil || k.aead == nil {
		return nil, ErrNoKey
	}
	if len(sealed) < 1+nonceLen+k.aead.Overhead() || sealed[0] != sealVersion {
		return nil, errOpen
	}
	pt, err := k.aead.Open(nil, sealed[1:1+nonceLen], sealed[1+nonceLen:], []byte(name))
	if err != nil {
		return nil, errOpen
	}
	return pt, nil
}

const redactedKey = "settings.Key(redacted)"

// String never shows key material.
func (k *Key) String() string { return redactedKey }

// GoString never shows key material.
func (k *Key) GoString() string { return redactedKey }

// Format prints the redacted form for every verb (%v %+v %#v %s %x ...).
func (k *Key) Format(f fmt.State, _ rune) { _, _ = f.Write([]byte(redactedKey)) }

// LogValue never shows key material.
func (k *Key) LogValue() slog.Value { return slog.StringValue(redactedKey) }
