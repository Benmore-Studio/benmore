//go:build !cli

package main

// In-tree WebAuthn (passkey) verification - the subset a relying party needs
// for passkeys, kept dependency-free like TOTP and the OAuth provider:
//
//   - registration: clientDataJSON (type, challenge, origin) and the
//     attestationObject's authenticator data (RP ID hash, user present +
//     verified, attested credential). Attestation statements are not
//     verified: registration asks for attestation "none", the passkey norm,
//     so the server trusts the signed-in user, not the device's maker.
//   - sign-in: clientDataJSON, authenticator data (RP ID hash, user present +
//     verified, sign counter) and the signature over authData ||
//     SHA-256(clientDataJSON) with the stored key: ES256 (P-256), EdDSA
//     (Ed25519) or RS256.
//
// Every length and nesting depth from the client is bounded.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
)

const (
	coseAlgES256 = -7
	coseAlgEdDSA = -8
	coseAlgRS256 = -257

	webauthnFlagUP = 0x01 // user present
	webauthnFlagUV = 0x04 // user verified (biometric / PIN)
	webauthnFlagAT = 0x40 // attested credential data included

	webauthnMaxCBOR  = 64 << 10
	webauthnMaxDepth = 8
)

var errWebAuthn = errors.New("passkey verification failed")

func webauthnFail(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errWebAuthn, fmt.Sprintf(format, args...))
}

// b64url decodes the unpadded base64url the WebAuthn JSON forms use; padded
// input is accepted too.
func b64url(s string) ([]byte, error) {
	if b, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return b, nil
	}
	return base64.URLEncoding.DecodeString(s)
}

func b64urlEncode(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// ---- minimal CBOR (RFC 8949) decoder: the types WebAuthn uses ----

type cborDecoder struct {
	b     []byte
	depth int
}

func (d *cborDecoder) head() (major byte, arg uint64, err error) {
	if len(d.b) == 0 {
		return 0, 0, webauthnFail("truncated CBOR")
	}
	ib := d.b[0]
	d.b = d.b[1:]
	major, info := ib>>5, ib&0x1f
	switch {
	case info < 24:
		return major, uint64(info), nil
	case info == 24, info == 25, info == 26, info == 27:
		n := 1 << (info - 24)
		if len(d.b) < n {
			return 0, 0, webauthnFail("truncated CBOR")
		}
		var v uint64
		for _, c := range d.b[:n] {
			v = v<<8 | uint64(c)
		}
		d.b = d.b[n:]
		return major, v, nil
	}
	return 0, 0, webauthnFail("unsupported CBOR encoding")
}

// value decodes one item: uint64, int64 (negative), []byte, string, []any,
// map[any]any (keys int64/uint64/string), bool or nil.
func (d *cborDecoder) value() (any, error) {
	d.depth++
	defer func() { d.depth-- }()
	if d.depth > webauthnMaxDepth {
		return nil, webauthnFail("CBOR nested too deeply")
	}
	major, arg, err := d.head()
	if err != nil {
		return nil, err
	}
	switch major {
	case 0:
		return arg, nil
	case 1:
		if arg > 1<<62 {
			return nil, webauthnFail("CBOR integer out of range")
		}
		return -1 - int64(arg), nil
	case 2, 3:
		if arg > uint64(len(d.b)) {
			return nil, webauthnFail("truncated CBOR")
		}
		v := d.b[:arg]
		d.b = d.b[arg:]
		if major == 3 {
			return string(v), nil
		}
		return append([]byte(nil), v...), nil
	case 4:
		if arg > uint64(len(d.b)) {
			return nil, webauthnFail("CBOR array too long")
		}
		out := make([]any, 0, arg)
		for i := uint64(0); i < arg; i++ {
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil
	case 5:
		if arg > uint64(len(d.b)) {
			return nil, webauthnFail("CBOR map too long")
		}
		out := make(map[any]any, arg)
		for i := uint64(0); i < arg; i++ {
			k, err := d.value()
			if err != nil {
				return nil, err
			}
			switch k.(type) {
			case uint64, int64, string:
			default:
				return nil, webauthnFail("unsupported CBOR map key")
			}
			v, err := d.value()
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case 7:
		switch arg {
		case 20:
			return false, nil
		case 21:
			return true, nil
		case 22:
			return nil, nil
		}
	}
	return nil, webauthnFail("unsupported CBOR type %d", major)
}

// cborDecodeFirst decodes the first item and returns the remaining bytes (the
// credential public key is followed by optional extensions in authData).
func cborDecodeFirst(b []byte) (any, []byte, error) {
	if len(b) > webauthnMaxCBOR {
		return nil, nil, webauthnFail("CBOR too large")
	}
	d := &cborDecoder{b: b}
	v, err := d.value()
	return v, d.b, err
}

// cborInt reads an integer map key/value as int64.
func cborInt(v any) (int64, bool) {
	switch n := v.(type) {
	case uint64:
		if n > 1<<62 {
			return 0, false
		}
		return int64(n), true
	case int64:
		return n, true
	}
	return 0, false
}

func coseField(m map[any]any, key int64) any {
	if key >= 0 {
		if v, ok := m[uint64(key)]; ok {
			return v
		}
	}
	return m[key]
}

// webauthnPublicKey is a parsed COSE credential key.
type webauthnPublicKey struct {
	alg int64
	key crypto.PublicKey
}

func parseCOSEKey(raw []byte) (*webauthnPublicKey, error) {
	v, rest, err := cborDecodeFirst(raw)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, webauthnFail("trailing bytes after public key")
	}
	m, ok := v.(map[any]any)
	if !ok {
		return nil, webauthnFail("public key is not a COSE map")
	}
	kty, _ := cborInt(coseField(m, 1))
	alg, ok := cborInt(coseField(m, 3))
	if !ok {
		return nil, webauthnFail("public key has no algorithm")
	}
	bytesField := func(k int64) []byte { b, _ := coseField(m, k).([]byte); return b }
	switch {
	case kty == 2 && alg == coseAlgES256: // EC2, P-256
		if crv, _ := cborInt(coseField(m, -1)); crv != 1 {
			return nil, webauthnFail("ES256 key is not on P-256")
		}
		x, y := bytesField(-2), bytesField(-3)
		if len(x) != 32 || len(y) != 32 {
			return nil, webauthnFail("malformed P-256 key")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return nil, webauthnFail("P-256 point is not on the curve")
		}
		return &webauthnPublicKey{alg: alg, key: pub}, nil
	case kty == 1 && alg == coseAlgEdDSA: // OKP, Ed25519
		if crv, _ := cborInt(coseField(m, -1)); crv != 6 {
			return nil, webauthnFail("EdDSA key is not Ed25519")
		}
		x := bytesField(-2)
		if len(x) != ed25519.PublicKeySize {
			return nil, webauthnFail("malformed Ed25519 key")
		}
		return &webauthnPublicKey{alg: alg, key: ed25519.PublicKey(x)}, nil
	case kty == 3 && alg == coseAlgRS256: // RSA
		n, e := bytesField(-1), bytesField(-2)
		modulus := new(big.Int).SetBytes(n)
		if modulus.BitLen() < 2048 || modulus.BitLen() > 4096 || modulus.Bit(0) == 0 || len(e) == 0 || len(e) > 4 {
			return nil, webauthnFail("unsupported RSA key size")
		}
		exp := 0
		for _, c := range e {
			exp = exp<<8 | int(c)
		}
		if exp < 3 || exp%2 == 0 {
			return nil, webauthnFail("invalid RSA exponent")
		}
		return &webauthnPublicKey{alg: alg, key: &rsa.PublicKey{N: modulus, E: exp}}, nil
	}
	return nil, webauthnFail("unsupported key type %d / algorithm %d", kty, alg)
}

func (k *webauthnPublicKey) verify(data, sig []byte) bool {
	switch pub := k.key.(type) {
	case *ecdsa.PublicKey:
		sum := sha256.Sum256(data)
		return ecdsa.VerifyASN1(pub, sum[:], sig)
	case ed25519.PublicKey:
		return ed25519.Verify(pub, data, sig)
	case *rsa.PublicKey:
		sum := sha256.Sum256(data)
		return rsa.VerifyPKCS1v15(pub, crypto.SHA256, sum[:], sig) == nil
	}
	return false
}

// ---- client data and authenticator data ----

type webauthnClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
}

func checkClientData(raw []byte, wantType string, challenge []byte, origin string) error {
	if len(raw) == 0 || len(raw) > 4096 {
		return webauthnFail("missing or oversized clientDataJSON")
	}
	var cd webauthnClientData
	if err := json.Unmarshal(raw, &cd); err != nil {
		return webauthnFail("unreadable clientDataJSON")
	}
	if cd.Type != wantType {
		return webauthnFail("clientData type %q, want %q", cd.Type, wantType)
	}
	got, err := b64url(cd.Challenge)
	if err != nil || subtle.ConstantTimeCompare(got, challenge) != 1 {
		return webauthnFail("challenge mismatch")
	}
	if cd.Origin != origin {
		return webauthnFail("origin %q, want %q", cd.Origin, origin)
	}
	if cd.CrossOrigin {
		return webauthnFail("cross-origin ceremony")
	}
	return nil
}

type webauthnAuthData struct {
	flags        byte
	signCount    uint32
	credentialID []byte
	publicKey    []byte // raw COSE key (registration only)
}

func parseAuthData(b []byte, rpID string, needCredential bool) (*webauthnAuthData, error) {
	if len(b) < 37 {
		return nil, webauthnFail("authenticator data too short")
	}
	want := sha256.Sum256([]byte(rpID))
	if subtle.ConstantTimeCompare(b[:32], want[:]) != 1 {
		return nil, webauthnFail("credential belongs to another site")
	}
	ad := &webauthnAuthData{flags: b[32], signCount: binary.BigEndian.Uint32(b[33:37])}
	if ad.flags&webauthnFlagUP == 0 {
		return nil, webauthnFail("user presence not asserted")
	}
	if ad.flags&webauthnFlagUV == 0 {
		return nil, webauthnFail("user verification (biometric or PIN) not performed")
	}
	if !needCredential {
		return ad, nil
	}
	if ad.flags&webauthnFlagAT == 0 {
		return nil, webauthnFail("no credential in authenticator data")
	}
	rest := b[37:]
	if len(rest) < 18 {
		return nil, webauthnFail("truncated attested credential")
	}
	idLen := int(binary.BigEndian.Uint16(rest[16:18]))
	rest = rest[18:]
	if idLen == 0 || idLen > 1023 || len(rest) < idLen {
		return nil, webauthnFail("invalid credential id")
	}
	ad.credentialID = append([]byte(nil), rest[:idLen]...)
	rest = rest[idLen:]
	if _, after, err := cborDecodeFirst(rest); err != nil {
		return nil, err
	} else {
		ad.publicKey = append([]byte(nil), rest[:len(rest)-len(after)]...)
	}
	return ad, nil
}

// webauthnRegistration is a verified new credential.
type webauthnRegistration struct {
	CredentialID []byte
	PublicKey    []byte // COSE
	Alg          int64
	SignCount    uint32
}

// verifyWebAuthnRegistration checks a navigator.credentials.create() result.
func verifyWebAuthnRegistration(clientDataJSON, attestationObject, challenge []byte, rpID, origin string) (*webauthnRegistration, error) {
	if err := checkClientData(clientDataJSON, "webauthn.create", challenge, origin); err != nil {
		return nil, err
	}
	v, rest, err := cborDecodeFirst(attestationObject)
	if err != nil {
		return nil, err
	}
	m, ok := v.(map[any]any)
	if !ok || len(rest) != 0 {
		return nil, webauthnFail("malformed attestation object")
	}
	authData, _ := m["authData"].([]byte)
	ad, err := parseAuthData(authData, rpID, true)
	if err != nil {
		return nil, err
	}
	key, err := parseCOSEKey(ad.publicKey)
	if err != nil {
		return nil, err
	}
	return &webauthnRegistration{CredentialID: ad.credentialID, PublicKey: ad.publicKey, Alg: key.alg, SignCount: ad.signCount}, nil
}

// verifyWebAuthnAssertion checks a navigator.credentials.get() result against
// the stored COSE key and returns the authenticator's new sign counter.
func verifyWebAuthnAssertion(clientDataJSON, authenticatorData, signature, storedKey, challenge []byte, rpID, origin string, storedCount uint32) (uint32, error) {
	if err := checkClientData(clientDataJSON, "webauthn.get", challenge, origin); err != nil {
		return 0, err
	}
	ad, err := parseAuthData(authenticatorData, rpID, false)
	if err != nil {
		return 0, err
	}
	key, err := parseCOSEKey(storedKey)
	if err != nil {
		return 0, err
	}
	sum := sha256.Sum256(clientDataJSON)
	if !key.verify(append(append([]byte(nil), authenticatorData...), sum[:]...), signature) {
		return 0, webauthnFail("signature does not match the registered passkey")
	}
	// A counter that fails to advance means a cloned authenticator. Synced
	// passkeys report 0 throughout, which is allowed.
	if (ad.signCount != 0 || storedCount != 0) && ad.signCount <= storedCount {
		return 0, webauthnFail("sign counter did not advance (possible cloned authenticator)")
	}
	return ad.signCount, nil
}

// webauthnEqualID compares credential ids without a timing signal.
func webauthnEqualID(a, b []byte) bool { return len(a) == len(b) && bytes.Equal(a, b) }
