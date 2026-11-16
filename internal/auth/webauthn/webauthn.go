package webauthn

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"unicode/utf8"
)

// COSE algorithm identifiers (WebAuthn L3 §5.8.5; IANA COSE registry).
const (
	AlgES256 = -7
	AlgEdDSA = -8
	AlgRS256 = -257
)

// SupportedAlgs in the order offered in pubKeyCredParams.
var SupportedAlgs = []int{AlgEdDSA, AlgES256, AlgRS256}

// Flags of authenticator data (WebAuthn L3 §6.1).
const (
	FlagUP = 0x01
	FlagUV = 0x04
	FlagBE = 0x08
	FlagBS = 0x10
	FlagAT = 0x40
	FlagED = 0x80
)

// MaxCredentialIDLen is the limit of L3 §7.1 step 25.
const MaxCredentialIDLen = 1023

// Error is a verification failure with a stable machine code.
type Error struct{ Code string }

func (e *Error) Error() string { return "webauthn: " + e.Code }

func fail(code string) error { return &Error{Code: code} }

// Code returns the machine code of a verification error ("invalid" for
// anything else).
func Code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	if errors.Is(err, ErrCBOR) {
		return "cbor"
	}
	return "invalid"
}

// RP is the relying party's policy.
type RP struct {
	ID        string   // RP ID, e.g. "nday.land"
	Origins   []string // allowed clientDataJSON.origin values, exact match
	RequireUV bool     // nday: always true (a passkey is the only factor)
}

// ---- COSE keys ----

// parseCOSEKey converts a COSE_Key (RFC 9052 §7, WebAuthn L3 §5.8.5) to a
// Go public key. Only the three supported algorithms are accepted, with the
// exact key types and curves the specification requires.
func parseCOSEKey(m cborMap) (alg int, pub crypto.PublicKey, err error) {
	geti := func(k int64) (int64, bool) { v, ok := m[k].(int64); return v, ok }
	getb := func(k int64) ([]byte, bool) { v, ok := m[k].([]byte); return v, ok }
	kty, ok1 := geti(1)
	a, ok2 := geti(3)
	if !ok1 || !ok2 {
		return 0, nil, fail("cose_key_fields")
	}
	switch {
	case a == AlgES256 && kty == 2: // EC2
		crv, ok := geti(-1)
		x, okx := getb(-2)
		y, oky := getb(-3)
		if !ok || crv != 1 || !okx || !oky || len(x) != 32 || len(y) != 32 {
			return 0, nil, fail("cose_key_ec2") // P-256, uncompressed only (§5.8.5)
		}
		pk, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return 0, nil, fail("cose_key_point")
		}
		return AlgES256, pk, nil
	case a == AlgEdDSA && kty == 1: // OKP
		crv, ok := geti(-1)
		x, okx := getb(-2)
		if !ok || crv != 6 || !okx || len(x) != ed25519.PublicKeySize {
			return 0, nil, fail("cose_key_okp")
		}
		return AlgEdDSA, ed25519.PublicKey(append([]byte(nil), x...)), nil
	case a == AlgRS256 && kty == 3: // RSA
		n, okn := getb(-1)
		e, oke := getb(-2)
		if !okn || !oke || len(e) == 0 || len(e) > 4 || len(n) == 0 || n[0] == 0 {
			return 0, nil, fail("cose_key_rsa")
		}
		ev := 0
		for _, b := range e {
			ev = ev<<8 | int(b)
		}
		nb := new(big.Int).SetBytes(n)
		if nb.BitLen() < 2048 || nb.BitLen() > 8192 || ev < 3 || ev%2 == 0 {
			return 0, nil, fail("cose_key_rsa_size")
		}
		return AlgRS256, &rsa.PublicKey{N: nb, E: ev}, nil
	}
	return 0, nil, fail("unsupported_alg")
}

// verifySig checks sig over msg (L3 §6.5.5: ES256 is ASN.1 DER, RS256 is
// PKCS#1 v1.5, EdDSA is the raw 64-byte Ed25519 signature).
func verifySig(alg int, pub crypto.PublicKey, msg, sig []byte) bool {
	switch alg {
	case AlgES256:
		k, ok := pub.(*ecdsa.PublicKey)
		h := sha256.Sum256(msg)
		return ok && ecdsa.VerifyASN1(k, h[:], sig)
	case AlgRS256:
		k, ok := pub.(*rsa.PublicKey)
		h := sha256.Sum256(msg)
		return ok && rsa.VerifyPKCS1v15(k, crypto.SHA256, h[:], sig) == nil
	case AlgEdDSA:
		k, ok := pub.(ed25519.PublicKey)
		return ok && len(sig) == ed25519.SignatureSize && ed25519.Verify(k, msg, sig)
	}
	return false
}

// ---- authenticator data ----

// AuthData is parsed authenticator data (L3 §6.1, §6.5.1).
type AuthData struct {
	RPIDHash  []byte
	Flags     byte
	SignCount uint32
	// attested credential data (AT flag)
	AAGUID       []byte
	CredentialID []byte
	COSEKey      cborMap
}

// ParseAuthData parses authenticator data. withCred says whether attested
// credential data must be present (registration) or absent (assertion).
// Extension data (ED) must be one CBOR map that ends exactly at the end.
func ParseAuthData(b []byte, withCred bool) (*AuthData, error) {
	if len(b) < 37 || len(b) > MaxCBORBytes {
		return nil, fail("authdata_length")
	}
	ad := &AuthData{RPIDHash: b[:32], Flags: b[32], SignCount: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if (ad.Flags&FlagAT != 0) != withCred {
		return nil, fail("authdata_at_flag")
	}
	if withCred {
		if len(rest) < 18 {
			return nil, fail("authdata_length")
		}
		ad.AAGUID = rest[:16]
		l := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if l == 0 || l > MaxCredentialIDLen || l > len(rest) {
			return nil, fail("credential_id_length")
		}
		ad.CredentialID, rest = rest[:l], rest[l:]
		v, n, err := decodeCBORPrefix(rest)
		if err != nil {
			return nil, err
		}
		m, ok := v.(cborMap)
		if !ok {
			return nil, fail("cose_key_not_map")
		}
		ad.COSEKey, rest = m, rest[n:]
	}
	if ad.Flags&FlagED != 0 {
		v, err := decodeCBOR(rest)
		if err != nil {
			return nil, err
		}
		if _, ok := v.(cborMap); !ok {
			return nil, fail("extensions_not_map")
		}
	} else if len(rest) != 0 {
		return nil, fail("authdata_trailing_bytes")
	}
	return ad, nil
}

// ---- client data ----

type clientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin *bool  `json:"crossOrigin"`
	TopOrigin   string `json:"topOrigin"`
}

// checkClientData runs L3 §7.1 steps 5-11 / §7.2 steps 8-14.
func (rp *RP) checkClientData(raw []byte, typ string, challenge []byte) error {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")) // "UTF-8 decode" strips a BOM
	if len(raw) == 0 || len(raw) > 8192 || !utf8.Valid(raw) {
		return fail("client_data")
	}
	var c clientData
	if err := json.Unmarshal(raw, &c); err != nil {
		return fail("client_data")
	}
	if c.Type != typ {
		return fail("type")
	}
	want := base64.RawURLEncoding.EncodeToString(challenge)
	if len(challenge) < 16 || subtle.ConstantTimeCompare([]byte(c.Challenge), []byte(want)) != 1 {
		return fail("challenge")
	}
	if !slices.Contains(rp.Origins, c.Origin) {
		return fail("origin")
	}
	// nday never runs WebAuthn inside an iframe.
	if (c.CrossOrigin != nil && *c.CrossOrigin) || c.TopOrigin != "" {
		return fail("cross_origin")
	}
	return nil
}

func (rp *RP) checkFlagsAndRP(ad *AuthData) error {
	want := sha256.Sum256([]byte(rp.ID))
	if subtle.ConstantTimeCompare(ad.RPIDHash, want[:]) != 1 {
		return fail("rp_id_hash")
	}
	if ad.Flags&FlagUP == 0 {
		return fail("user_present")
	}
	if rp.RequireUV && ad.Flags&FlagUV == 0 {
		return fail("user_verified")
	}
	if ad.Flags&FlagBE == 0 && ad.Flags&FlagBS != 0 {
		return fail("backup_flags")
	}
	return nil
}

// Credential is a verified new credential (the "credential record" of L3
// §7.1 step 27, minus what nday does not keep).
type Credential struct {
	ID        []byte
	Alg       int
	PublicKey []byte // SubjectPublicKeyInfo DER (x509.MarshalPKIXPublicKey)
	SignCount uint32
	AAGUID    []byte
	BE, BS    bool
	UV        bool
}

// VerifyRegistration implements L3 §7.1 steps 5-25 for attestation "none".
// The caller checks step 26 (credential id not registered to anyone) when
// storing, and that challenge was issued to this browser and not used.
func (rp *RP) VerifyRegistration(challenge, clientDataJSON, attestationObject []byte, algs []int) (*Credential, error) {
	if err := rp.checkClientData(clientDataJSON, "webauthn.create", challenge); err != nil {
		return nil, err
	}
	v, err := decodeCBOR(attestationObject)
	if err != nil {
		return nil, err
	}
	ao, ok := v.(cborMap)
	if !ok || len(ao) != 3 {
		return nil, fail("attestation_object")
	}
	f, ok1 := ao["fmt"].(string)
	stmt, ok2 := ao["attStmt"].(cborMap)
	raw, ok3 := ao["authData"].([]byte)
	if !ok1 || !ok2 || !ok3 {
		return nil, fail("attestation_object")
	}
	// We request attestation "none" (L3 §8.7): fmt "none", attStmt = {}.
	if f != "none" || len(stmt) != 0 {
		return nil, fail("attestation_format")
	}
	ad, err := ParseAuthData(raw, true)
	if err != nil {
		return nil, err
	}
	if err := rp.checkFlagsAndRP(ad); err != nil {
		return nil, err
	}
	alg, pub, err := parseCOSEKey(ad.COSEKey)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(algs, alg) {
		return nil, fail("unsupported_alg")
	}
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fail("public_key")
	}
	return &Credential{ID: append([]byte(nil), ad.CredentialID...), Alg: alg, PublicKey: spki, SignCount: ad.SignCount,
		AAGUID: append([]byte(nil), ad.AAGUID...), BE: ad.Flags&FlagBE != 0, BS: ad.Flags&FlagBS != 0, UV: ad.Flags&FlagUV != 0}, nil
}

// Assertion is the verified result of an authentication ceremony.
type Assertion struct {
	SignCount uint32
	BE, BS    bool
	UV        bool
}

// VerifyAssertion implements L3 §7.2 steps 8-21 against a stored public
// key (SPKI DER) and algorithm. Counter and backup-state policy (steps 19,
// 22, 24) are applied by the caller with the returned values.
func (rp *RP) VerifyAssertion(challenge, clientDataJSON, authData, sig []byte, alg int, spki []byte) (*Assertion, error) {
	if err := rp.checkClientData(clientDataJSON, "webauthn.get", challenge); err != nil {
		return nil, err
	}
	ad, err := ParseAuthData(authData, false)
	if err != nil {
		return nil, err
	}
	if err := rp.checkFlagsAndRP(ad); err != nil {
		return nil, err
	}
	pub, err := x509.ParsePKIXPublicKey(spki)
	if err != nil {
		return nil, fail("stored_key")
	}
	h := sha256.Sum256(clientDataJSON)
	msg := append(append([]byte(nil), authData...), h[:]...)
	if len(sig) == 0 || len(sig) > 1024 || !verifySig(alg, pub, msg, sig) {
		return nil, fail("signature")
	}
	return &Assertion{SignCount: ad.SignCount, BE: ad.Flags&FlagBE != 0, BS: ad.Flags&FlagBS != 0, UV: ad.Flags&FlagUV != 0}, nil
}

// ValidRPID checks that rpID may be used by origin host (L3 §4 "RP ID":
// equal to the host or a registrable domain suffix of it). Without the
// public suffix list, nday requires the RP ID to contain a dot (or be
// localhost) — the owner sets it explicitly.
func ValidRPID(rpID, host string) error {
	if rpID == "" || strings.ToLower(rpID) != rpID || strings.HasPrefix(rpID, ".") || strings.HasSuffix(rpID, ".") {
		return fmt.Errorf("RP ID %q must be a lower-case domain", rpID)
	}
	if rpID != "localhost" && !strings.Contains(rpID, ".") {
		return fmt.Errorf("RP ID %q must be a registrable domain such as nday.land", rpID)
	}
	if host != rpID && !strings.HasSuffix(host, "."+rpID) {
		return fmt.Errorf("origin host %q is not %q or a subdomain of it", host, rpID)
	}
	return nil
}
