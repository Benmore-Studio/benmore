//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

type passkeyTestClient struct {
	t       *testing.T
	app     *App
	cookies map[string]*http.Cookie
}

func (c *passkeyTestClient) do(h http.HandlerFunc, method, path string, body any, csrf string) (int, map[string]any) {
	c.t.Helper()
	var buf bytes.Buffer
	if body != nil {
		json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Host = testRP
	req.Header.Set("X-Forwarded-Proto", "https")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	for _, ck := range c.cookies {
		req.AddCookie(ck)
	}
	if id := req.PathValue("id"); id == "" && len(path) > len("/api/_auth/passkeys/") && method == http.MethodDelete {
		req.SetPathValue("id", path[len("/api/_auth/passkeys/"):])
	}
	rec := httptest.NewRecorder()
	h(rec, req)
	for _, ck := range rec.Result().Cookies() {
		if ck.MaxAge < 0 {
			delete(c.cookies, ck.Name)
		} else {
			c.cookies[ck.Name] = ck
		}
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// A signed-in user adds a passkey; signed out, the passkey signs them in with
// a fresh session; the same challenge cannot be replayed; removing the passkey
// ends its use.
func TestPasskeyRegisterAndSignIn(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	if err := EnsurePasskeysTable(app.DB); err != nil {
		t.Fatal(err)
	}
	cookies, sid, uid := loginTestUser(app, "ada@example.com", "user")
	signedIn := &passkeyTestClient{t: t, app: app, cookies: map[string]*http.Cookie{}}
	for _, ck := range cookies {
		signedIn.cookies[ck.Name] = ck
	}
	csrf := authMintCSRFToken(sid)
	auth := newTestAuthenticator(t, false)
	if code, _ := signedIn.do(passkeyRegisterOptions(app), "POST", "/api/_auth/passkeys/register/options", map[string]any{}, ""); code != http.StatusForbidden {
		t.Fatalf("options without CSRF: %d", code)
	}
	// Adding a passkey re-confirms the account, as MFA enrollment does.
	if code, _ := signedIn.do(passkeyRegisterOptions(app), "POST", "/api/_auth/passkeys/register/options", map[string]any{}, csrf); code != http.StatusBadRequest {
		t.Fatalf("options without a password: %d", code)
	}
	code, opts := signedIn.do(passkeyRegisterOptions(app), "POST", "/api/_auth/passkeys/register/options", map[string]any{"password": "testpass123"}, csrf)
	if code != http.StatusOK || opts["rp"].(map[string]any)["id"] != testRP {
		t.Fatalf("register options: %d %v", code, opts)
	}
	challenge, _ := b64url(opts["challenge"].(string))
	registerCookie := *signedIn.cookies[flowCookieName(flowCookiePasskey, !app.DevMode)]
	cd, att := auth.create(testRP, testOrigin, challenge, webauthnFlagUP|webauthnFlagUV|webauthnFlagAT)
	cred := map[string]any{"id": b64urlEncode(auth.credID), "rawId": b64urlEncode(auth.credID), "type": "public-key", "name": "Laptop",
		"response": map[string]any{"clientDataJSON": b64urlEncode(cd), "attestationObject": b64urlEncode(att)}}
	if code, out := signedIn.do(passkeyRegister(app), "POST", "/api/_auth/passkeys/register", cred, csrf); code != http.StatusOK {
		t.Fatalf("register: %d %v", code, out)
	}
	backup := filepath.Join(app.Dir, "before-passkey-removal.db")
	if err := sqliteVacuumInto(filepath.Join(app.Dir, "data.db"), backup); err != nil {
		t.Fatal(err)
	}
	signedIn.cookies[flowCookieName(flowCookiePasskey, !app.DevMode)] = &registerCookie
	if code, _ := signedIn.do(passkeyRegister(app), "POST", "/api/_auth/passkeys/register", cred, csrf); code == http.StatusOK {
		t.Fatal("the saved registration challenge cookie was accepted twice")
	}

	anon := &passkeyTestClient{t: t, app: app, cookies: map[string]*http.Cookie{}}
	anonCSRF := authMintCSRFToken("")
	var savedLoginCookie *http.Cookie
	var savedLoginBody map[string]any
	signIn := func() (int, map[string]any) {
		code, o := anon.do(passkeyLoginOptions(app), "POST", "/api/_auth/passkeys/login/options", map[string]any{}, anonCSRF)
		if code != http.StatusOK {
			t.Fatalf("login options: %d %v", code, o)
		}
		challengeCookie := *anon.cookies[flowCookieName(flowCookiePasskey, !app.DevMode)]
		ch, _ := b64url(o["challenge"].(string))
		cd, ad, sig := auth.get(testRP, testOrigin, ch, webauthnFlagUP|webauthnFlagUV)
		body := map[string]any{"id": b64urlEncode(auth.credID), "rawId": b64urlEncode(auth.credID), "type": "public-key",
			"response": map[string]any{"clientDataJSON": b64urlEncode(cd), "authenticatorData": b64urlEncode(ad), "signature": b64urlEncode(sig), "userHandle": b64urlEncode(passkeyUserHandle(app, uid))}}
		savedLoginCookie, savedLoginBody = &challengeCookie, body
		return anon.do(passkeyLogin(app), "POST", "/api/_auth/passkeys/login", body, anonCSRF)
	}
	code, out := signIn()
	if code != http.StatusOK || out["ok"] != true {
		t.Fatalf("passkey sign-in: %d %v", code, out)
	}
	var session *http.Cookie
	for _, ck := range anon.cookies {
		if ck.Name == sessionCookie("x", app.DevMode, app.SessionDuration).Name {
			session = ck
		}
	}
	if session == nil {
		t.Fatal("passkey sign-in set no session cookie")
	}
	// A fresh passkey sign-in is itself the proof for adding another passkey.
	fresh := &passkeyTestClient{t: t, app: app, cookies: map[string]*http.Cookie{session.Name: session}}
	if code, out := fresh.do(passkeyRegisterOptions(app), "POST", "/api/_auth/passkeys/register/options", map[string]any{}, authMintCSRFToken(session.Value)); code != http.StatusOK {
		t.Fatalf("fresh passkey sign-in could not add a passkey without a password: %d %v", code, out)
	}
	anon.cookies[flowCookieName(flowCookiePasskey, !app.DevMode)] = savedLoginCookie
	if code, _ := anon.do(passkeyLogin(app), "POST", "/api/_auth/passkeys/login", savedLoginBody, anonCSRF); code != http.StatusBadRequest {
		t.Fatalf("saved login challenge cookie replay status = %d, want 400", code)
	}

	// Two concurrent requests with the same signed cookie and assertion have
	// exactly one winner, even for a synced authenticator whose counter stays 0.
	loginOptionsCode, concurrentOptions := anon.do(passkeyLoginOptions(app), "POST", "/api/_auth/passkeys/login/options", map[string]any{}, anonCSRF)
	if loginOptionsCode != http.StatusOK {
		t.Fatalf("concurrent login options: %d %v", loginOptionsCode, concurrentOptions)
	}
	concurrentCookie := *anon.cookies[flowCookieName(flowCookiePasskey, !app.DevMode)]
	concurrentChallenge, _ := b64url(concurrentOptions["challenge"].(string))
	cd, ad, sig := auth.get(testRP, testOrigin, concurrentChallenge, webauthnFlagUP|webauthnFlagUV)
	concurrentBody, _ := json.Marshal(map[string]any{"id": b64urlEncode(auth.credID), "rawId": b64urlEncode(auth.credID), "type": "public-key",
		"response": map[string]any{"clientDataJSON": b64urlEncode(cd), "authenticatorData": b64urlEncode(ad), "signature": b64urlEncode(sig), "userHandle": b64urlEncode(passkeyUserHandle(app, uid))}})
	statuses := make(chan int, 2)
	for i := 0; i < 2; i++ {
		go func() {
			req := httptest.NewRequest("POST", "/api/_auth/passkeys/login", bytes.NewReader(concurrentBody))
			req.Host = testRP
			req.Header.Set("X-Forwarded-Proto", "https")
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			req.Header.Set("X-CSRF-Token", anonCSRF)
			req.AddCookie(&concurrentCookie)
			rec := httptest.NewRecorder()
			passkeyLogin(app)(rec, req)
			statuses <- rec.Code
		}()
	}
	first, second := <-statuses, <-statuses
	if !(first == http.StatusOK && second == http.StatusBadRequest || first == http.StatusBadRequest && second == http.StatusOK) {
		t.Fatalf("concurrent replay statuses = %d, %d; want exactly one 200 and one 400", first, second)
	}
	if app.Design == nil {
		app.Design = &DesignConfig{}
	}
	if app.Design.Auth == nil {
		app.Design.Auth = map[string]string{}
	}
	if app.Paths == nil {
		app.Paths = DiscoverAuthPaths(nil)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET password_change_required=1 WHERE id=?`, uid); err != nil {
		t.Fatal(err)
	}
	if code, out := signIn(); code != http.StatusForbidden || out["error"] != "password_change_required" {
		t.Fatalf("temporary-password account passkey sign-in = %d %v", code, out)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET password_change_required=0 WHERE id=?`, uid); err != nil {
		t.Fatal(err)
	}
	app.Design.Auth["require_verified"] = "true"
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET verified=0 WHERE id=?`, uid); err != nil {
		t.Fatal(err)
	}
	if code, out := signIn(); code != http.StatusForbidden || out["error"] != "email_verification_required" {
		t.Fatalf("unverified passkey account sign-in = %d %v", code, out)
	}
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET verified=1 WHERE id=?`, uid); err != nil {
		t.Fatal(err)
	}
	app.Design.Auth["otp"] = "true"
	delete(anon.cookies, sessionCookie("x", app.DevMode, app.SessionDuration).Name)
	if code, out := signIn(); code != http.StatusOK || out["otp_required"] != true {
		t.Fatalf("auth.otp passkey sign-in did not continue to email proof: %d %v", code, out)
	}
	if _, present := anon.cookies[sessionCookie("x", app.DevMode, app.SessionDuration).Name]; present {
		t.Fatal("auth.otp passkey sign-in issued a session before email proof")
	}
	app.Design.Auth["otp"] = "false"
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(session)
	if s := getSession(app, req); s == nil || s.UserID != uid {
		t.Fatalf("the new session does not belong to the passkey's user: %+v", s)
	}

	_, list := signedIn.do(passkeyList(app), "GET", "/api/_auth/passkeys", nil, "")
	items, _ := list["passkeys"].([]any)
	if len(items) != 1 {
		t.Fatalf("list: %v", list)
	}
	id := items[0].(map[string]any)["id"]
	if code, out := signedIn.do(passkeyDelete(app), "DELETE", "/api/_auth/passkeys/"+jsonNumberString(id), nil, csrf); code != http.StatusOK {
		t.Fatalf("delete: %d %v", code, out)
	}
	if code, _ := signIn(); code != http.StatusUnauthorized {
		t.Fatalf("a removed passkey still signed in: %d", code)
	}
	// Restoring the snapshot must not revive the passkey deleted after it was made.
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	if err := restoreDatabase(app.Dir, backup); err != nil {
		t.Fatal(err)
	}
	db, err := openDBWithEnv(app.Dir, app.environment)
	if err != nil {
		t.Fatal(err)
	}
	app.DB = db
	var restoredPasskeys int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_passkeys WHERE user_id=? AND credential_id=?`, uid, b64urlEncode(auth.credID)).Scan(&restoredPasskeys); err != nil || restoredPasskeys != 0 {
		t.Fatalf("restore revived a removed passkey: count=%d err=%v", restoredPasskeys, err)
	}
}

func TestPasskeysCanBeTurnedOff(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	if app.Design == nil {
		app.Design = &DesignConfig{}
	}
	if app.Design.Auth == nil {
		app.Design.Auth = map[string]string{}
	}
	app.Design.Auth["passkeys"] = "false"
	c := &passkeyTestClient{t: t, app: app, cookies: map[string]*http.Cookie{}}
	if code, _ := c.do(passkeyLoginOptions(app), "POST", "/api/_auth/passkeys/login/options", map[string]any{}, authMintCSRFToken("")); code != http.StatusNotFound {
		t.Fatalf("auth.passkeys: false still served passkey sign-in: %d", code)
	}
}

func jsonNumberString(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}
