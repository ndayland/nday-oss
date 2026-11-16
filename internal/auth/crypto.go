package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var b64 = base64.RawURLEncoding

// keyset holds the keys derived from each configured server secret
// (index 0 = current). Separate HKDF "info" labels give independent keys
// for sealing, CSRF tokens, session tags and the identities of deleted
// suspended accounts.
type keyset struct {
	seal []cipher.AEAD
	ids  [][]byte // 8-byte key fingerprints, prefixed to sealed blobs
	csrf [][]byte
	stag [][]byte // session cookie tag keys
	susp [][]byte // suspended identity hash keys
}

func newKeyset(secrets [][]byte) (*keyset, error) {
	if len(secrets) == 0 {
		return nil, errors.New("auth: no server secret")
	}
	ks := &keyset{}
	for _, s := range secrets {
		sk, err := hkdf.Key(sha256.New, s, nil, "nday auth seal v1", 32)
		if err != nil {
			return nil, err
		}
		ck, err := hkdf.Key(sha256.New, s, nil, "nday auth csrf v1", 32)
		if err != nil {
			return nil, err
		}
		tk, err := hkdf.Key(sha256.New, s, nil, "nday auth session tag v1", 32)
		if err != nil {
			return nil, err
		}
		uk, err := hkdf.Key(sha256.New, s, nil, "nday auth suspended identity v1", 32)
		if err != nil {
			return nil, err
		}
		blk, err := aes.NewCipher(sk)
		if err != nil {
			return nil, err
		}
		aead, err := cipher.NewGCM(blk)
		if err != nil {
			return nil, err
		}
		id := sha256.Sum256(append([]byte("nday auth key id v1:"), sk...))
		ks.seal = append(ks.seal, aead)
		ks.ids = append(ks.ids, id[:8])
		ks.csrf = append(ks.csrf, ck)
		ks.stag = append(ks.stag, tk)
		ks.susp = append(ks.susp, uk)
	}
	return ks, nil
}

const sealVersion = 1

// sealB64 encrypts and authenticates plaintext with the current key:
// version(1) | keyid(8) | nonce(12) | ciphertext+tag, base64url.
// purpose is bound as associated data so a blob sealed for one use cannot
// be replayed as another.
func (k *keyset) sealB64(purpose string, plaintext []byte) string {
	aead := k.seal[0]
	out := make([]byte, 0, 1+8+aead.NonceSize()+len(plaintext)+aead.Overhead())
	out = append(out, sealVersion)
	out = append(out, k.ids[0]...)
	nonce := make([]byte, aead.NonceSize())
	_, _ = rand.Read(nonce)
	out = append(out, nonce...)
	out = aead.Seal(out, nonce, plaintext, []byte(purpose))
	return b64.EncodeToString(out)
}

var errUnseal = errors.New("auth: sealed value invalid")

// openB64 reverses sealB64 with whichever configured key produced it.
func (k *keyset) openB64(purpose, s string) ([]byte, error) {
	if len(s) > 4096 {
		return nil, errUnseal
	}
	b, err := b64.DecodeString(s)
	if err != nil || len(b) < 1+8+12+16 || b[0] != sealVersion {
		return nil, errUnseal
	}
	for i, id := range k.ids {
		if !hmac.Equal(b[1:9], id) {
			continue
		}
		aead := k.seal[i]
		ns := aead.NonceSize()
		pt, err := aead.Open(nil, b[9:9+ns], b[9+ns:], []byte(purpose))
		if err != nil {
			return nil, errUnseal
		}
		return pt, nil
	}
	return nil, errUnseal
}

// csrfToken derives the CSRF token of a session from its token hash.
func (k *keyset) csrfToken(sessionHash []byte) string {
	return b64.EncodeToString(csrfMAC(k.csrf[0], sessionHash))
}

// checkCSRF accepts a token made with any configured key.
func (k *keyset) checkCSRF(sessionHash []byte, token string) bool {
	got, err := b64.DecodeString(token)
	if err != nil || len(got) != sha256.Size {
		return false
	}
	ok := false
	for _, key := range k.csrf {
		if hmac.Equal(got, csrfMAC(key, sessionHash)) {
			ok = true
		}
	}
	return ok
}

// sessionTag authenticates a session token (16-byte HMAC), so forged
// cookies are refused without a database lookup.
func (k *keyset) sessionTag(token []byte) []byte { return sessionMAC(k.stag[0], token) }

// checkSessionTag accepts a tag made with any configured key.
func (k *keyset) checkSessionTag(token, tag []byte) bool {
	ok := false
	for _, key := range k.stag {
		if hmac.Equal(tag, sessionMAC(key, token)) {
			ok = true
		}
	}
	return ok
}

// suspendedIdentity hashes a provider identity under every configured key
// (index 0 = current key). Deleting a suspended account keeps only this
// hash, so the raw subject id is gone while a later sign-in with the same
// identity can still be recognised. Without the server secret the hash
// can't be matched against a known subject.
func (k *keyset) suspendedIdentity(provider, subject string) [][]byte {
	out := make([][]byte, len(k.susp))
	for i, key := range k.susp {
		m := hmac.New(sha256.New, key)
		m.Write([]byte("suspended identity:"))
		m.Write([]byte(provider))
		m.Write([]byte{0})
		m.Write([]byte(subject))
		out[i] = m.Sum(nil)
	}
	return out
}

func sessionMAC(key, token []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("session:"))
	m.Write(token)
	return m.Sum(nil)[:16]
}

func csrfMAC(key, sessionHash []byte) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte("csrf:"))
	m.Write(sessionHash)
	return m.Sum(nil)
}

// randomToken returns n random bytes, base64url without padding.
func randomToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b) // crypto/rand.Read never fails (Go >= 1.24)
	return b64.EncodeToString(b)
}

func sha256Bytes(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// pkceChallenge is the S256 code challenge of verifier (RFC 7636 4.2).
func pkceChallenge(verifier string) string {
	h := sha256.Sum256([]byte(verifier))
	return b64.EncodeToString(h[:])
}

func sha256Raw(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}

// randRead is crypto/rand.Read.
var randRead = rand.Read
