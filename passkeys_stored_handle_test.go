//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// A passkey moved into this app's store from another one keeps the user
// handle its authenticator was given there (user_handle): sign-in accepts
// exactly that handle for it, and the handle this app would derive is
// refused for that passkey. A passkey without one is checked against the
// derived handle, as before.
func TestPasskeyStoredUserHandle(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	if err := EnsurePasskeysTable(app.DB); err != nil {
		t.Fatal(err)
	}
	// The column is added to a table created before it existed, too.
	if err := EnsurePasskeysTable(app.DB); err != nil {
		t.Fatalf("second ensure: %v", err)
	}
	cookies, sid, uid := loginTestUser(app, "mover@example.com", "user")
	signedIn := &passkeyTestClient{t: t, app: app, cookies: map[string]*http.Cookie{}}
	for _, ck := range cookies {
		signedIn.cookies[ck.Name] = ck
	}
	csrf := authMintCSRFToken(sid)
	auth := newTestAuthenticator(t, false)
	code, opts := signedIn.do(passkeyRegisterOptions(app), "POST", "/api/_auth/passkeys/register/options", map[string]any{"password": "testpass123"}, csrf)
	if code != http.StatusOK {
		t.Fatalf("register options: %d %v", code, opts)
	}
	challenge, _ := b64url(opts["challenge"].(string))
	cd, att := auth.create(testRP, testOrigin, challenge, webauthnFlagUP|webauthnFlagUV|webauthnFlagAT)
	cred := map[string]any{"id": b64urlEncode(auth.credID), "rawId": b64urlEncode(auth.credID), "type": "public-key", "name": "Laptop",
		"response": map[string]any{"clientDataJSON": b64urlEncode(cd), "attestationObject": b64urlEncode(att)}}
	if code, out := signedIn.do(passkeyRegister(app), "POST", "/api/_auth/passkeys/register", cred, csrf); code != http.StatusOK {
		t.Fatalf("register: %d %v", code, out)
	}

	anon := &passkeyTestClient{t: t, app: app, cookies: map[string]*http.Cookie{}}
	anonCSRF := authMintCSRFToken("")
	signIn := func(handle []byte) int {
		code, o := anon.do(passkeyLoginOptions(app), "POST", "/api/_auth/passkeys/login/options", map[string]any{}, anonCSRF)
		if code != http.StatusOK {
			t.Fatalf("login options: %d %v", code, o)
		}
		ch, _ := b64url(o["challenge"].(string))
		cd, ad, sig := auth.get(testRP, testOrigin, ch, webauthnFlagUP|webauthnFlagUV)
		body := map[string]any{"id": b64urlEncode(auth.credID), "rawId": b64urlEncode(auth.credID), "type": "public-key",
			"response": map[string]any{"clientDataJSON": b64urlEncode(cd), "authenticatorData": b64urlEncode(ad), "signature": b64urlEncode(sig), "userHandle": b64urlEncode(handle)}}
		code, _ = anon.do(passkeyLogin(app), "POST", "/api/_auth/passkeys/login", body, anonCSRF)
		return code
	}
	derived := passkeyUserHandle(app, uid)
	if code := signIn(derived); code != http.StatusOK {
		t.Fatalf("derived handle on a passkey registered here: %d", code)
	}
	moved := []byte(strings.Repeat("9", 32))
	if _, err := app.DB.Exec(`UPDATE _benmore_passkeys SET user_handle = ? WHERE user_id = ?`, string(moved), uid); err != nil {
		t.Fatal(err)
	}
	if code := signIn(moved); code != http.StatusOK {
		t.Fatalf("stored handle on a moved passkey: %d", code)
	}
	if code := signIn(derived); code != http.StatusUnauthorized {
		t.Fatalf("derived handle on a moved passkey: %d, want 401", code)
	}
	if code := signIn([]byte(strings.Repeat("8", 32))); code != http.StatusUnauthorized {
		t.Fatalf("another handle on a moved passkey: %d, want 401", code)
	}
}
