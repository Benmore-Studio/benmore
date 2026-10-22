//go:build !cli

package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"sort"
	"testing"
)

// ---- a software authenticator for tests ----

// cborEnc encodes the handful of types WebAuthn needs (test-only).
func cborEnc(v any) []byte {
	var b bytes.Buffer
	var enc func(any)
	head := func(major byte, n uint64) {
		switch {
		case n < 24:
			b.WriteByte(major<<5 | byte(n))
		case n < 1<<8:
			b.WriteByte(major<<5 | 24)
			b.WriteByte(byte(n))
		case n < 1<<16:
			b.WriteByte(major<<5 | 25)
			binary.Write(&b, binary.BigEndian, uint16(n))
		default:
			b.WriteByte(major<<5 | 26)
			binary.Write(&b, binary.BigEndian, uint32(n))
		}
	}
	enc = func(v any) {
		switch x := v.(type) {
		case int:
			if x >= 0 {
				head(0, uint64(x))
			} else {
				head(1, uint64(-1-x))
			}
		case []byte:
			head(2, uint64(len(x)))
			b.Write(x)
		case string:
			head(3, uint64(len(x)))
			b.WriteString(x)
		case map[any]any:
			head(5, uint64(len(x)))
			keys := make([]any, 0, len(x))
			for k := range x {
				keys = append(keys, k)
			}
			sort.Slice(keys, func(i, j int) bool { return cborKeyLess(keys[i], keys[j]) })
			for _, k := range keys {
				enc(k)
				enc(x[k])
			}
		default:
			panic("cborEnc: unsupported type")
		}
	}
	enc(v)
	return b.Bytes()
}

func cborKeyLess(a, b any) bool {
	ai, aok := a.(int)
	bi, bok := b.(int)
	if aok && bok {
		return ai < bi
	}
	return aok
}

type testAuthenticator struct {
	credID []byte
	cose   []byte
	signer func([]byte) []byte
	count  uint32
}

func newTestAuthenticator(t *testing.T, ed bool) *testAuthenticator {
	t.Helper()
	a := &testAuthenticator{credID: make([]byte, 16)}
	rand.Read(a.credID)
	if ed {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		a.cose = cborEnc(map[any]any{1: 1, 3: coseAlgEdDSA, -1: 6, -2: []byte(pub)})
		a.signer = func(m []byte) []byte { return ed25519.Sign(priv, m) }
		return a
	}
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pad := func(b []byte) []byte { return append(make([]byte, 32-len(b)), b...) }
	a.cose = cborEnc(map[any]any{1: 2, 3: coseAlgES256, -1: 1, -2: pad(priv.X.Bytes()), -3: pad(priv.Y.Bytes())})
	a.signer = func(m []byte) []byte {
		sum := sha256.Sum256(m)
		sig, _ := ecdsa.SignASN1(rand.Reader, priv, sum[:])
		return sig
	}
	return a
}

func testClientData(typ string, challenge []byte, origin string) []byte {
	b, _ := json.Marshal(map[string]any{"type": typ, "challenge": b64urlEncode(challenge), "origin": origin})
	return b
}

func testAuthData(rpID string, flags byte, count uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	b := append([]byte(nil), h[:]...)
	b = append(b, flags)
	b = binary.BigEndian.AppendUint32(b, count)
	return append(b, attested...)
}

// create returns clientDataJSON and attestationObject for a registration.
func (a *testAuthenticator) create(rpID, origin string, challenge []byte, flags byte) ([]byte, []byte) {
	attested := make([]byte, 16) // AAGUID
	attested = binary.BigEndian.AppendUint16(attested, uint16(len(a.credID)))
	attested = append(attested, a.credID...)
	attested = append(attested, a.cose...)
	att := cborEnc(map[any]any{"fmt": "none", "attStmt": map[any]any{}, "authData": testAuthData(rpID, flags, a.count, attested)})
	return testClientData("webauthn.create", challenge, origin), att
}

// get returns clientDataJSON, authenticatorData and signature for a sign-in.
func (a *testAuthenticator) get(rpID, origin string, challenge []byte, flags byte) ([]byte, []byte, []byte) {
	cd := testClientData("webauthn.get", challenge, origin)
	ad := testAuthData(rpID, flags, a.count, nil)
	sum := sha256.Sum256(cd)
	return cd, ad, a.signer(append(append([]byte(nil), ad...), sum[:]...))
}

const testRP, testOrigin = "app.example.com", "https://app.example.com"

func TestWebAuthnRegistrationAndAssertion(t *testing.T) {
	for _, ed := range []bool{false, true} {
		a := newTestAuthenticator(t, ed)
		challenge := make([]byte, 32)
		rand.Read(challenge)
		cd, att := a.create(testRP, testOrigin, challenge, webauthnFlagUP|webauthnFlagUV|webauthnFlagAT)
		reg, err := verifyWebAuthnRegistration(cd, att, challenge, testRP, testOrigin)
		if err != nil {
			t.Fatalf("ed=%v registration: %v", ed, err)
		}
		if !bytes.Equal(reg.CredentialID, a.credID) {
			t.Fatal("credential id not extracted")
		}

		a.count = 0 // synced passkeys report 0 throughout
		cd, ad, sig := a.get(testRP, testOrigin, challenge, webauthnFlagUP|webauthnFlagUV)
		if _, err := verifyWebAuthnAssertion(cd, ad, sig, reg.PublicKey, challenge, testRP, testOrigin, 0); err != nil {
			t.Fatalf("ed=%v assertion: %v", ed, err)
		}
		bad := append([]byte(nil), sig...)
		bad[len(bad)-1] ^= 0xff
		if _, err := verifyWebAuthnAssertion(cd, ad, bad, reg.PublicKey, challenge, testRP, testOrigin, 0); err == nil {
			t.Fatalf("ed=%v tampered signature verified", ed)
		}
		a.count = 5
		cd, ad, sig = a.get(testRP, testOrigin, challenge, webauthnFlagUP|webauthnFlagUV)
		if n, err := verifyWebAuthnAssertion(cd, ad, sig, reg.PublicKey, challenge, testRP, testOrigin, 4); err != nil || n != 5 {
			t.Fatalf("ed=%v advancing counter: n=%d err=%v", ed, n, err)
		}
		if _, err := verifyWebAuthnAssertion(cd, ad, sig, reg.PublicKey, challenge, testRP, testOrigin, 5); err == nil {
			t.Fatalf("ed=%v replayed counter verified", ed)
		}
	}
}

func TestWebAuthnRejections(t *testing.T) {
	a := newTestAuthenticator(t, false)
	challenge := make([]byte, 32)
	rand.Read(challenge)
	other := make([]byte, 32)
	rand.Read(other)
	full := byte(webauthnFlagUP | webauthnFlagUV | webauthnFlagAT)
	cases := map[string]func() ([]byte, []byte){
		"wrong challenge": func() ([]byte, []byte) { return a.create(testRP, testOrigin, other, full) },
		"wrong origin":    func() ([]byte, []byte) { return a.create(testRP, "https://evil.example", challenge, full) },
		"wrong rp id":     func() ([]byte, []byte) { return a.create("evil.example", testOrigin, challenge, full) },
		"no user verify":  func() ([]byte, []byte) { return a.create(testRP, testOrigin, challenge, webauthnFlagUP|webauthnFlagAT) },
		"no presence":     func() ([]byte, []byte) { return a.create(testRP, testOrigin, challenge, webauthnFlagUV|webauthnFlagAT) },
		"get as create": func() ([]byte, []byte) {
			_, att := a.create(testRP, testOrigin, challenge, full)
			return testClientData("webauthn.get", challenge, testOrigin), att
		},
	}
	for name, build := range cases {
		cd, att := build()
		if _, err := verifyWebAuthnRegistration(cd, att, challenge, testRP, testOrigin); !errors.Is(err, errWebAuthn) {
			t.Errorf("%s: err=%v, want a verification failure", name, err)
		}
	}
}

func TestCBORDecoderBounds(t *testing.T) {
	deep := bytes.Repeat([]byte{0x81}, 50) // 50 nested one-element arrays
	deep = append(deep, 0x00)
	if _, _, err := cborDecodeFirst(deep); err == nil {
		t.Fatal("deep nesting accepted")
	}
	if _, _, err := cborDecodeFirst([]byte{0x5a, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("byte string longer than the input accepted")
	}
	if _, _, err := cborDecodeFirst([]byte{0x9b, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}); err == nil {
		t.Fatal("huge array length accepted")
	}
	if _, _, err := cborDecodeFirst([]byte{0x5f, 0xff}); err == nil {
		t.Fatal("indefinite-length CBOR accepted")
	}
	if _, err := parseCOSEKey(cborEnc(map[any]any{1: 3, 3: coseAlgRS256, -1: append([]byte{0xfe}, make([]byte, 255)...), -2: []byte{4}})); err == nil {
		t.Fatal("RSA key with an even exponent accepted")
	}
	if _, err := parseCOSEKey(cborEnc(map[any]any{1: 2, 3: coseAlgES256, -1: 1, -2: make([]byte, 32), -3: make([]byte, 32)})); err == nil {
		t.Fatal("a point not on P-256 was accepted")
	}
}
