// Package softauthn is a software WebAuthn authenticator + client for
// tests: it generates credential keys, builds clientDataJSON, authenticator
// data and "none" attestation objects, and signs assertions, with knobs to
// produce every kind of malformed or hostile response.
package softauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sort"

	"nday.land/nday/internal/auth/webauthn"
)

var b64 = base64.RawURLEncoding

// ---- minimal CBOR encoder (canonical: shortest heads, sorted map keys) ----

// Map is an encodable map; keys int or string.
type Map map[any]any

// Raw is pre-encoded CBOR inserted verbatim.
type Raw []byte

func head(buf *bytes.Buffer, major byte, n uint64) {
	switch {
	case n < 24:
		buf.WriteByte(major<<5 | byte(n))
	case n <= 0xff:
		buf.Write([]byte{major<<5 | 24, byte(n)})
	case n <= 0xffff:
		buf.WriteByte(major<<5 | 25)
		_ = binary.Write(buf, binary.BigEndian, uint16(n))
	case n <= 0xffffffff:
		buf.WriteByte(major<<5 | 26)
		_ = binary.Write(buf, binary.BigEndian, uint32(n))
	default:
		buf.WriteByte(major<<5 | 27)
		_ = binary.Write(buf, binary.BigEndian, n)
	}
}

// CBOR encodes v (int, int64, []byte, string, bool, nil, []any, Map, Raw).
func CBOR(v any) []byte {
	var buf bytes.Buffer
	enc(&buf, v)
	return buf.Bytes()
}

func enc(buf *bytes.Buffer, v any) {
	switch x := v.(type) {
	case Raw:
		buf.Write(x)
	case int:
		enc(buf, int64(x))
	case int64:
		if x >= 0 {
			head(buf, 0, uint64(x))
		} else {
			head(buf, 1, uint64(-1-x))
		}
	case []byte:
		head(buf, 2, uint64(len(x)))
		buf.Write(x)
	case string:
		head(buf, 3, uint64(len(x)))
		buf.WriteString(x)
	case bool:
		if x {
			buf.WriteByte(0xf5)
		} else {
			buf.WriteByte(0xf4)
		}
	case nil:
		buf.WriteByte(0xf6)
	case []any:
		head(buf, 4, uint64(len(x)))
		for _, e := range x {
			enc(buf, e)
		}
	case Map:
		type kv struct{ k, v []byte }
		var kvs []kv
		for k, val := range x {
			kvs = append(kvs, kv{CBOR(k), CBOR(val)})
		}
		sort.Slice(kvs, func(i, j int) bool {
			if len(kvs[i].k) != len(kvs[j].k) {
				return len(kvs[i].k) < len(kvs[j].k)
			}
			return bytes.Compare(kvs[i].k, kvs[j].k) < 0
		})
		head(buf, 5, uint64(len(kvs)))
		for _, e := range kvs {
			buf.Write(e.k)
			buf.Write(e.v)
		}
	default:
		panic(fmt.Sprintf("softauthn: cannot encode %T", v))
	}
}

// ---- authenticator ----

// Credential is a credential held by the software authenticator.
type Credential struct {
	ID         []byte
	Alg        int
	Key        crypto.Signer
	UserHandle []byte
	SignCount  uint32
	RPID       string
}

// NewCredential generates a key for alg (-7, -8 or -257).
func NewCredential(alg int, rpID string, userHandle []byte) *Credential {
	c := &Credential{ID: make([]byte, 32), Alg: alg, UserHandle: userHandle, RPID: rpID}
	_, _ = rand.Read(c.ID)
	switch alg {
	case webauthn.AlgES256:
		c.Key, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case webauthn.AlgRS256:
		c.Key, _ = rsa.GenerateKey(rand.Reader, 2048)
	case webauthn.AlgEdDSA:
		_, k, _ := ed25519.GenerateKey(rand.Reader)
		c.Key = k
	default:
		panic("alg")
	}
	return c
}

// COSEKey is the credential public key as a COSE_Key map.
func (c *Credential) COSEKey() Map {
	switch k := c.Key.Public().(type) {
	case *ecdsa.PublicKey:
		b, _ := k.Bytes()
		return Map{1: 2, 3: -7, -1: 1, -2: b[1:33], -3: b[33:]}
	case *rsa.PublicKey:
		return Map{1: 3, 3: -257, -1: k.N.Bytes(), -2: bigEndian(k.E)}
	case ed25519.PublicKey:
		return Map{1: 1, 3: -8, -1: 6, -2: []byte(k)}
	}
	panic("key")
}

func bigEndian(e int) []byte {
	var out []byte
	for e > 0 {
		out = append([]byte{byte(e)}, out...)
		e >>= 8
	}
	return out
}

// Sign signs msg as WebAuthn requires for the credential's algorithm.
func (c *Credential) Sign(msg []byte) []byte {
	switch k := c.Key.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(k, msg)
	default:
		h := sha256.Sum256(msg)
		sig, err := c.Key.Sign(rand.Reader, h[:], crypto.SHA256)
		if err != nil {
			panic(err)
		}
		return sig // ECDSA: ASN.1 DER; RSA: PKCS#1 v1.5
	}
}

// Opts tweak what the client/authenticator produce (zero value = valid).
type Opts struct {
	Origin       string // default "https://www.nday.land"
	Type         string // default webauthn.create / webauthn.get
	Challenge    string // override the challenge (base64url)
	CrossOrigin  bool
	Flags        *byte  // override authenticator data flags
	RPID         string // override the RP ID hashed into authData
	ExtraClient  string // appended raw into clientDataJSON before the closing brace
	Fmt          string // attestation fmt (default "none")
	AttStmt      Map    // attestation statement (default {})
	COSEKey      any    // override the COSE key (Map or Raw)
	SignCount    *uint32
	TamperCD     bool // flip a byte of clientDataJSON after signing
	TamperAD     bool // flip a byte of authenticatorData after signing
	BadSig       bool
	UserHandle   []byte // override userHandle in assertions
	NoUserHandle bool
}

// DefaultFlags: UP | UV | BE | BS (a synced passkey).
const DefaultFlags = webauthn.FlagUP | webauthn.FlagUV | webauthn.FlagBE | webauthn.FlagBS

func clientDataJSON(typ, challenge string, o Opts) []byte {
	origin := o.Origin
	if origin == "" {
		origin = "https://www.nday.land"
	}
	if o.Type != "" {
		typ = o.Type
	}
	if o.Challenge != "" {
		challenge = o.Challenge
	}
	s := fmt.Sprintf(`{"type":%q,"challenge":%q,"origin":%q,"crossOrigin":%t%s}`, typ, challenge, origin, o.CrossOrigin, o.ExtraClient)
	return []byte(s)
}

func (c *Credential) authData(o Opts, attested bool) []byte {
	rp := c.RPID
	if o.RPID != "" {
		rp = o.RPID
	}
	h := sha256.Sum256([]byte(rp))
	flags := byte(DefaultFlags)
	if o.Flags != nil {
		flags = *o.Flags
	}
	if attested {
		flags |= webauthn.FlagAT
	}
	var buf bytes.Buffer
	buf.Write(h[:])
	buf.WriteByte(flags)
	cnt := c.SignCount
	if o.SignCount != nil {
		cnt = *o.SignCount
	}
	_ = binary.Write(&buf, binary.BigEndian, cnt)
	if attested {
		buf.Write(make([]byte, 16)) // AAGUID: zero for "none"
		_ = binary.Write(&buf, binary.BigEndian, uint16(len(c.ID)))
		buf.Write(c.ID)
		var key any = c.COSEKey()
		if o.COSEKey != nil {
			key = o.COSEKey
		}
		enc(&buf, key)
	}
	return buf.Bytes()
}

// RegistrationJSON is PublicKeyCredential.toJSON() of a registration.
type RegistrationJSON struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string   `json:"clientDataJSON"`
		AttestationObject string   `json:"attestationObject"`
		Transports        []string `json:"transports"`
	} `json:"response"`
	ClientExtensionResults map[string]any `json:"clientExtensionResults"`
	Name                   string         `json:"name,omitempty"`
}

// Register answers navigator.credentials.create() for challenge (base64url).
func (c *Credential) Register(challenge string, o Opts) RegistrationJSON {
	cd := clientDataJSON("webauthn.create", challenge, o)
	f := o.Fmt
	if f == "" {
		f = "none"
	}
	st := o.AttStmt
	if st == nil {
		st = Map{}
	}
	ao := CBOR(Map{"fmt": f, "attStmt": st, "authData": c.authData(o, true)})
	if o.TamperCD {
		cd[len(cd)-2] ^= 1
	}
	var r RegistrationJSON
	r.ID, r.RawID, r.Type = b64.EncodeToString(c.ID), b64.EncodeToString(c.ID), "public-key"
	r.Response.ClientDataJSON = b64.EncodeToString(cd)
	r.Response.AttestationObject = b64.EncodeToString(ao)
	r.Response.Transports = []string{"internal", "hybrid"}
	r.ClientExtensionResults = map[string]any{}
	return r
}

// AssertionJSON is PublicKeyCredential.toJSON() of an assertion.
type AssertionJSON struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle,omitempty"`
	} `json:"response"`
	ClientExtensionResults map[string]any `json:"clientExtensionResults"`
}

// Assert answers navigator.credentials.get() for challenge (base64url).
// The signature counter is incremented unless o.SignCount is set.
func (c *Credential) Assert(challenge string, o Opts) AssertionJSON {
	cd := clientDataJSON("webauthn.get", challenge, o)
	if o.SignCount == nil && c.SignCount != 0 {
		c.SignCount++
	}
	ad := c.authData(o, false)
	h := sha256.Sum256(cd)
	sig := c.Sign(append(append([]byte(nil), ad...), h[:]...))
	if o.BadSig {
		sig = c.Sign([]byte("something else"))
	}
	if o.TamperCD {
		cd[len(cd)-2] ^= 1
	}
	if o.TamperAD {
		ad[32] ^= webauthn.FlagBS | webauthn.FlagBE
	}
	var r AssertionJSON
	r.ID, r.RawID, r.Type = b64.EncodeToString(c.ID), b64.EncodeToString(c.ID), "public-key"
	r.Response.ClientDataJSON = b64.EncodeToString(cd)
	r.Response.AuthenticatorData = b64.EncodeToString(ad)
	r.Response.Signature = b64.EncodeToString(sig)
	uh := c.UserHandle
	if o.UserHandle != nil {
		uh = o.UserHandle
	}
	if !o.NoUserHandle {
		r.Response.UserHandle = b64.EncodeToString(uh)
	}
	r.ClientExtensionResults = map[string]any{}
	return r
}

// JSON marshals v.
func JSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
