package webauthn_test

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"nday.land/nday/internal/auth/webauthn"
	"nday.land/nday/internal/auth/webauthn/softauthn"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

// TestSpecVectorNoneES256 replays W3C Web Authentication Level 3 (REC
// 2026-08-25) §16.2 "ES256 Credential with No Attestation",
// https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256.
// The vectors have UV clear (flags 0x59 / 0x19), so they verify only with
// RequireUV=false — and nday, which requires UV, must refuse them.
func TestSpecVectorNoneES256(t *testing.T) {
	regChallenge := unhex("00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130")
	regCD := unhex("7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d")
	attObj := unhex("a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220")
	authChallenge := unhex("39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408")
	authAD := unhex("bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000")
	authCD := unhex("7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d")
	sig := unhex("3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87")

	rp := &webauthn.RP{ID: "example.org", Origins: []string{"https://example.org"}}
	cred, err := rp.VerifyRegistration(regChallenge, regCD, attObj, webauthn.SupportedAlgs)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(cred.ID) != "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" ||
		hex.EncodeToString(cred.AAGUID) != "8446ccb9ab1db374750b2367ff6f3a1f" || cred.Alg != webauthn.AlgES256 ||
		!cred.BE || !cred.BS || cred.UV || cred.SignCount != 0 {
		t.Fatalf("%+v", cred)
	}
	as, err := rp.VerifyAssertion(authChallenge, authCD, authAD, sig, cred.Alg, cred.PublicKey)
	if err != nil || as.SignCount != 0 || !as.BS {
		t.Fatalf("assertion: %v %+v", err, as)
	}
	strict := &webauthn.RP{ID: "example.org", Origins: []string{"https://example.org"}, RequireUV: true}
	if _, err := strict.VerifyRegistration(regChallenge, regCD, attObj, webauthn.SupportedAlgs); webauthn.Code(err) != "user_verified" {
		t.Errorf("UV not required: %v", err)
	}
	if _, err := strict.VerifyAssertion(authChallenge, authCD, authAD, sig, cred.Alg, cred.PublicKey); webauthn.Code(err) != "user_verified" {
		t.Errorf("UV not required: %v", err)
	}
	// flipping one signature byte must fail
	bad := append([]byte(nil), sig...)
	bad[10] ^= 1
	if _, err := rp.VerifyAssertion(authChallenge, authCD, authAD, bad, cred.Alg, cred.PublicKey); webauthn.Code(err) != "signature" {
		t.Errorf("tampered vector signature: %v", err)
	}
}

var rp = &webauthn.RP{ID: "nday.land", Origins: []string{"https://www.nday.land", "https://nday.land"}, RequireUV: true}

func challenge() ([]byte, string) {
	c := make([]byte, 32)
	_, _ = rand.Read(c)
	return c, base64.RawURLEncoding.EncodeToString(c)
}

func dec(s string) []byte {
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func register(t *testing.T, c *softauthn.Credential, o softauthn.Opts) (*webauthn.Credential, error) {
	ch, chs := challenge()
	r := c.Register(chs, o)
	return rp.VerifyRegistration(ch, dec(r.Response.ClientDataJSON), dec(r.Response.AttestationObject), webauthn.SupportedAlgs)
}

func flags(f byte) *byte { return &f }

func TestCeremoniesPerAlgorithm(t *testing.T) {
	for _, alg := range webauthn.SupportedAlgs {
		c := softauthn.NewCredential(alg, "nday.land", []byte("handle-123"))
		cred, err := register(t, c, softauthn.Opts{})
		if err != nil || cred.Alg != alg {
			t.Fatalf("alg %d: %v", alg, err)
		}
		ch, chs := challenge()
		a := c.Assert(chs, softauthn.Opts{Origin: "https://nday.land"})
		as, err := rp.VerifyAssertion(ch, dec(a.Response.ClientDataJSON), dec(a.Response.AuthenticatorData), dec(a.Response.Signature), cred.Alg, cred.PublicKey)
		if err != nil || !as.UV {
			t.Fatalf("alg %d assertion: %v", alg, err)
		}
		// alg not offered
		ch2, chs2 := challenge()
		r := c.Register(chs2, softauthn.Opts{})
		if _, err := rp.VerifyRegistration(ch2, dec(r.Response.ClientDataJSON), dec(r.Response.AttestationObject), []int{99}); webauthn.Code(err) != "unsupported_alg" {
			t.Errorf("alg %d not in pubKeyCredParams: %v", alg, err)
		}
	}
}

func TestRegistrationNegatives(t *testing.T) {
	c := softauthn.NewCredential(webauthn.AlgES256, "nday.land", nil)
	es := c.COSEKey()
	cases := []struct {
		name string
		o    softauthn.Opts
		code string
	}{
		{"wrong challenge", softauthn.Opts{Challenge: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}, "challenge"},
		{"wrong origin", softauthn.Opts{Origin: "https://evil.example"}, "origin"},
		{"http origin", softauthn.Opts{Origin: "http://www.nday.land"}, "origin"},
		{"wrong type", softauthn.Opts{Type: "webauthn.get"}, "type"},
		{"cross origin", softauthn.Opts{CrossOrigin: true}, "cross_origin"},
		{"top origin", softauthn.Opts{ExtraClient: `,"topOrigin":"https://evil.example"`}, "cross_origin"},
		{"wrong rp id hash", softauthn.Opts{RPID: "evil.example"}, "rp_id_hash"},
		{"rp id of subdomain", softauthn.Opts{RPID: "www.nday.land"}, "rp_id_hash"},
		{"no UP", softauthn.Opts{Flags: flags(webauthn.FlagUV)}, "user_present"},
		{"no UV", softauthn.Opts{Flags: flags(webauthn.FlagUP)}, "user_verified"},
		{"BS without BE", softauthn.Opts{Flags: flags(webauthn.FlagUP | webauthn.FlagUV | webauthn.FlagBS)}, "backup_flags"},
		{"packed attestation", softauthn.Opts{Fmt: "packed", AttStmt: softauthn.Map{"alg": -7}}, "attestation_format"},
		{"none with statement", softauthn.Opts{AttStmt: softauthn.Map{"x": 1}}, "attestation_format"},
		{"tampered client data", softauthn.Opts{TamperCD: true}, "client_data"},
		{"ES256 key on P-384 crv", softauthn.Opts{COSEKey: softauthn.Map{1: 2, 3: -7, -1: 2, -2: es[-2], -3: es[-3]}}, "cose_key_ec2"},
		{"point not on curve", softauthn.Opts{COSEKey: softauthn.Map{1: 2, 3: -7, -1: 1, -2: make([]byte, 32), -3: make([]byte, 32)}}, "cose_key_point"},
		{"compressed point", softauthn.Opts{COSEKey: softauthn.Map{1: 2, 3: -7, -1: 1, -2: es[-2]}}, "cose_key_ec2"},
		{"alg/kty mismatch", softauthn.Opts{COSEKey: softauthn.Map{1: 3, 3: -7, -1: 1, -2: es[-2], -3: es[-3]}}, "unsupported_alg"},
		{"ES384", softauthn.Opts{COSEKey: softauthn.Map{1: 2, 3: -35, -1: 2, -2: es[-2], -3: es[-3]}}, "unsupported_alg"},
		{"RSA 1024", softauthn.Opts{COSEKey: softauthn.Map{1: 3, 3: -257, -1: make([]byte, 128), -2: []byte{1, 0, 1}}}, "cose_key_rsa"},
		{"key not a map", softauthn.Opts{COSEKey: softauthn.Raw{0x80}}, "cose_key_not_map"},
		{"duplicate COSE key", softauthn.Opts{COSEKey: softauthn.Raw(append([]byte{0xa6}, append(softauthn.CBOR(es)[1:], 0x01, 0x02)...))}, "cbor"},
		{"indefinite map", softauthn.Opts{COSEKey: softauthn.Raw{0xbf, 0x01, 0x02, 0xff}}, "cbor"},
		{"tagged value", softauthn.Opts{COSEKey: softauthn.Raw{0xa1, 0x01, 0xc2, 0x41, 0x00}}, "cbor"},
		{"float", softauthn.Opts{COSEKey: softauthn.Raw{0xa1, 0x01, 0xf9, 0x00, 0x14}}, "cbor"},
		{"non-canonical int", softauthn.Opts{COSEKey: softauthn.Raw{0xa1, 0x18, 0x01, 0x02}}, "cbor"},
		{"byte string past end", softauthn.Opts{COSEKey: softauthn.Raw{0xa1, 0x01, 0x5a, 0xff, 0xff, 0xff, 0xff}}, "cbor"},
		{"trailing bytes after key", softauthn.Opts{COSEKey: softauthn.Raw(append(softauthn.CBOR(es), 0x00))}, "authdata_trailing_bytes"},
	}
	for _, tc := range cases {
		_, err := register(t, c, tc.o)
		if webauthn.Code(err) != tc.code {
			t.Errorf("%s: got %v (%s), want %s", tc.name, err, webauthn.Code(err), tc.code)
		}
	}
	// hostile attestation objects
	ch, chs := challenge()
	good := c.Register(chs, softauthn.Opts{})
	cd := dec(good.Response.ClientDataJSON)
	ao := dec(good.Response.AttestationObject)
	for name, bad := range map[string][]byte{
		"empty":              {},
		"truncated":          ao[:len(ao)-5],
		"trailing":           append(append([]byte(nil), ao...), 0),
		"array":              {0x80},
		"deep nesting":       []byte(strings.Repeat("\x81", 20) + "\x00"),
		"huge":               append([]byte{0x5a, 0x00, 0x01, 0x00, 0x00}, make([]byte, 65536)...),
		"extra key":          softauthn.CBOR(softauthn.Map{"fmt": "none", "attStmt": softauthn.Map{}, "authData": []byte{1}, "x": 1}),
		"authData too short": softauthn.CBOR(softauthn.Map{"fmt": "none", "attStmt": softauthn.Map{}, "authData": make([]byte, 36)}),
		"huge array count":   {0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		"invalid utf8":       softauthn.CBOR(softauthn.Map{"fmt": softauthn.Raw{0x62, 0xff, 0xfe}, "attStmt": softauthn.Map{}, "authData": []byte{1}}),
	} {
		if _, err := rp.VerifyRegistration(ch, cd, bad, webauthn.SupportedAlgs); err == nil {
			t.Errorf("hostile attestation object %q accepted", name)
		}
	}
	// credential id length limits
	long := softauthn.NewCredential(webauthn.AlgES256, "nday.land", nil)
	long.ID = make([]byte, 1024)
	if _, err := register(t, long, softauthn.Opts{}); webauthn.Code(err) != "credential_id_length" {
		t.Errorf("1024-byte credential id: %v", err)
	}
	long.ID = make([]byte, 1023)
	if _, err := register(t, long, softauthn.Opts{}); err != nil {
		t.Errorf("1023-byte credential id: %v", err)
	}
	// extension data must be a single map ending the buffer
	ext := softauthn.NewCredential(webauthn.AlgES256, "nday.land", nil)
	f := byte(softauthn.DefaultFlags | webauthn.FlagED)
	ch, chs = challenge()
	r := ext.Register(chs, softauthn.Opts{Flags: &f, COSEKey: softauthn.Raw(append(softauthn.CBOR(ext.COSEKey()), softauthn.CBOR(softauthn.Map{"credProtect": 2})...))})
	if _, err := rp.VerifyRegistration(ch, dec(r.Response.ClientDataJSON), dec(r.Response.AttestationObject), webauthn.SupportedAlgs); err != nil {
		t.Errorf("extensions: %v", err)
	}
}

func TestAssertionNegatives(t *testing.T) {
	c := softauthn.NewCredential(webauthn.AlgRS256, "nday.land", []byte("u"))
	cred, err := register(t, c, softauthn.Opts{})
	if err != nil {
		t.Fatal(err)
	}
	other := softauthn.NewCredential(webauthn.AlgRS256, "nday.land", []byte("u"))
	otherCred, _ := register(t, other, softauthn.Opts{})
	run := func(o softauthn.Opts, key []byte) error {
		ch, chs := challenge()
		a := c.Assert(chs, o)
		_, err := rp.VerifyAssertion(ch, dec(a.Response.ClientDataJSON), dec(a.Response.AuthenticatorData), dec(a.Response.Signature), cred.Alg, key)
		return err
	}
	for _, tc := range []struct {
		name string
		o    softauthn.Opts
		code string
	}{
		{"wrong type", softauthn.Opts{Type: "webauthn.create"}, "type"},
		{"wrong origin", softauthn.Opts{Origin: "https://www.nday.land.evil.example"}, "origin"},
		{"wrong challenge", softauthn.Opts{Challenge: "x"}, "challenge"},
		{"cross origin", softauthn.Opts{CrossOrigin: true}, "cross_origin"},
		{"rp id hash", softauthn.Opts{RPID: "evil.example"}, "rp_id_hash"},
		{"no UP", softauthn.Opts{Flags: flags(webauthn.FlagUV)}, "user_present"},
		{"no UV", softauthn.Opts{Flags: flags(webauthn.FlagUP)}, "user_verified"},
		{"AT in assertion", softauthn.Opts{Flags: flags(softauthn.DefaultFlags | webauthn.FlagAT)}, "authdata_at_flag"},
		{"tampered client data", softauthn.Opts{TamperCD: true}, "client_data"},
		{"tampered authenticator data", softauthn.Opts{TamperAD: true}, "signature"},
		{"bad signature", softauthn.Opts{BadSig: true}, "signature"},
	} {
		if err := run(tc.o, cred.PublicKey); webauthn.Code(err) != tc.code {
			t.Errorf("%s: %v, want %s", tc.name, err, tc.code)
		}
	}
	if err := run(softauthn.Opts{}, otherCred.PublicKey); webauthn.Code(err) != "signature" {
		t.Errorf("other credential's key: %v", err)
	}
	if err := run(softauthn.Opts{}, []byte("not spki")); webauthn.Code(err) != "stored_key" {
		t.Errorf("garbage stored key: %v", err)
	}
	if err := run(softauthn.Opts{}, cred.PublicKey); err != nil {
		t.Fatal(err)
	}
}

func TestValidRPID(t *testing.T) {
	for _, c := range [][2]string{{"nday.land", "www.nday.land"}, {"nday.land", "nday.land"}, {"localhost", "localhost"}} {
		if err := webauthn.ValidRPID(c[0], c[1]); err != nil {
			t.Error(c, err)
		}
	}
	for _, c := range [][2]string{{"land", "www.nday.land"}, {"evil.example", "www.nday.land"}, {"ay.land", "www.nday.land"},
		{"www.nday.land", "nday.land"}, {"Nday.land", "nday.land"}, {".nday.land", "www.nday.land"}} {
		if err := webauthn.ValidRPID(c[0], c[1]); err == nil {
			t.Error("accepted", c)
		}
	}
}
