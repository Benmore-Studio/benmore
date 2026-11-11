//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// mfaGateFixture is an app whose notes are private to their owner, with one
// signed-in member who holds a cookie session, a Bearer session and an API
// token, and owns one note.
func mfaGateFixture(t *testing.T) (app *App, mux *http.ServeMux, uid int64, sid, bearer, tok string) {
	t.Helper()
	app, mux = auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	EnsureLoginAttemptsTable(app.DB)
	EnsureUserRolesTable(app.DB)
	hash, err := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('mgr', 'mgr@example.com', ?, 'user', 1)", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ = res.LastInsertId()
	sid = CreateSession(app.DB, uid, "mgr@example.com", "", time.Hour)
	bearer = CreateSession(app.DB, uid, "mgr@example.com", "", time.Hour)
	tok = auditToken(t, app, sid, "*")
	passwordChangeExec(t, app.DB, "INSERT INTO notes(user_id,title) VALUES (?,?)", uid, "private-note")
	app.Design = &DesignConfig{Auth: map[string]string{"require_mfa_for_roles": "manager"}}
	return app, mux, uid, sid, bearer, tok
}

type mfaGateCall struct {
	method, path, cookie, bearer, body string
	html                               bool
}

func (c mfaGateCall) serve(h http.Handler) *httptest.ResponseRecorder {
	r := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
	if c.body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if c.html {
		r.Header.Set("Accept", "text/html")
	}
	if c.cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: c.cookie})
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(c.cookie))
	}
	if c.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+c.bearer)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func mfaGateTokenCount(t *testing.T, app *App, uid int64) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id=?", uid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// F2 (round 1105): auth.require_mfa_for_roles was checked only when a sign-in
// issued a credential. A member granted a listed role while signed in, or one
// whose role became listed, kept using the cookie, Bearer sessions and API
// tokens they already held, and could mint a year-long API token with the
// role's scopes without ever enrolling. Every credential of such an account is
// now held to MFA enrollment until the account enrolls a TOTP factor.
func TestRequiredMFAEnrollmentHoldsExistingCredentials(t *testing.T) {
	app, mux, uid, sid, bearer, tok := mfaGateFixture(t)
	gated := requestSessionCacheMiddleware(mfaEnrollmentMiddleware(mux, app))
	notes := func(h http.Handler, cookie, bearerCred string) *httptest.ResponseRecorder {
		return mfaGateCall{method: "GET", path: "/api/notes", cookie: cookie, bearer: bearerCred}.serve(h)
	}

	// Control: the member holds no listed role, so every credential reads.
	for name, w := range map[string]*httptest.ResponseRecorder{
		"cookie": notes(gated, sid, ""), "bearer session": notes(gated, "", bearer), "api token": notes(gated, "", tok),
	} {
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "private-note") {
			t.Fatalf("control %s read: %d %s", name, w.Code, w.Body.String())
		}
	}

	// An admin grants the listed role while the member is signed in. It takes
	// effect on the member's next request, for every credential.
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (?, 'manager')", uid)
	for name, w := range map[string]*httptest.ResponseRecorder{
		"cookie": notes(gated, sid, ""), "bearer session": notes(gated, "", bearer), "api token": notes(gated, "", tok),
	} {
		var body map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if w.Code != http.StatusForbidden || body["error"] != "mfa_enrollment_required" || body["redirect"] != "/mfa-setup" ||
			!strings.Contains(w.Body.String(), "/api/_auth/mfa/setup") || strings.Contains(w.Body.String(), "private-note") {
			t.Fatalf("%s of an unenrolled manager: %d %s", name, w.Code, w.Body.String())
		}
	}
	// The session itself does not resolve, so no handler grants it anything
	// even without the navigation gate in front (benmore host).
	for name, w := range map[string]*httptest.ResponseRecorder{
		"cookie": notes(mux, sid, ""), "bearer session": notes(mux, "", bearer), "api token": notes(mux, "", tok),
	} {
		if w.Code != http.StatusUnauthorized || strings.Contains(w.Body.String(), "private-note") {
			t.Fatalf("ungated %s of an unenrolled manager: %d %s", name, w.Code, w.Body.String())
		}
	}
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	if s := getSession(app, r); s != nil {
		t.Fatalf("getSession resolved an unenrolled manager: %+v", s)
	}

	// No new credential while enrollment is pending.
	before := mfaGateTokenCount(t, app, uid)
	mint := `{"name":"nomfa","scopes":"notes:read","expires_in":"1y"}`
	for _, h := range []http.Handler{gated, mux} {
		w := mfaGateCall{method: "POST", path: "/api/_auth/api-tokens", cookie: sid, body: mint}.serve(h)
		if w.Code == http.StatusOK || strings.Contains(w.Body.String(), "bmr_") {
			t.Fatalf("an unenrolled manager minted an API token: %d %s", w.Code, w.Body.String())
		}
	}
	if after := mfaGateTokenCount(t, app, uid); after != before {
		t.Fatalf("API tokens %d -> %d while enrollment was required", before, after)
	}

	// Pages send the browser to the setup page; the setup page, the CSRF token
	// and the enrollment endpoints stay reachable.
	if w := (mfaGateCall{method: "GET", path: "/dashboard", cookie: sid, html: true}).serve(gated); w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/mfa-setup" {
		t.Fatalf("page navigation: %d %q", w.Code, w.Header().Get("Location"))
	}
	if w := (mfaGateCall{method: "GET", path: "/mfa-setup", cookie: sid, html: true}).serve(gated); w.Code == http.StatusSeeOther || strings.Contains(w.Body.String(), "mfa_enrollment_required") {
		t.Fatalf("setup page withheld: %d %s", w.Code, w.Body.String())
	}

	// Enrollment from the existing session needs the current password, as any
	// signed-in enrollment does; then the same credentials work again.
	if w := (mfaGateCall{method: "POST", path: "/api/_auth/mfa/setup", cookie: sid, body: `{}`}).serve(gated); w.Code != http.StatusBadRequest {
		t.Fatalf("setup without a password: %d %s", w.Code, w.Body.String())
	}
	w := mfaGateCall{method: "POST", path: "/api/_auth/mfa/setup", cookie: sid, body: `{"password":"` + fixturePassword + `"}`}.serve(gated)
	var setup struct{ Secret string }
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &setup) != nil || setup.Secret == "" {
		t.Fatalf("setup from the held session: %d %s", w.Code, w.Body.String())
	}
	if w := (mfaGateCall{method: "POST", path: "/api/_auth/mfa/verify", cookie: sid, body: `{"code":"` + GenerateTOTP(setup.Secret) + `"}`}).serve(gated); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "mfa_enabled") {
		t.Fatalf("verify from the held session: %d %s", w.Code, w.Body.String())
	}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"cookie": notes(gated, sid, ""), "bearer session": notes(gated, "", bearer), "api token": notes(gated, "", tok),
	} {
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "private-note") {
			t.Fatalf("enrolled manager %s read: %d %s", name, w.Code, w.Body.String())
		}
	}
	if w := (mfaGateCall{method: "POST", path: "/api/_auth/api-tokens", cookie: sid, body: mint}).serve(gated); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "bmr_") {
		t.Fatalf("enrolled manager could not mint an API token: %d %s", w.Code, w.Body.String())
	}
}

// Listing a role that existing accounts already hold applies on their next
// request; enrolled holders, unlisted roles and a session platform tooling
// drives as the user (probe_route as) are unaffected.
func TestRequiredMFAEnrollmentAppliesWhenRoleBecomesListed(t *testing.T) {
	app, mux, uid, sid, _, _ := mfaGateFixture(t)
	gated := requestSessionCacheMiddleware(mfaEnrollmentMiddleware(mux, app))
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET role='manager' WHERE id=?", uid)
	enrolledHash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified, totp_secret) VALUES ('mgr2', 'mgr2@example.com', ?, 'manager', 1, 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP')", string(enrolledHash))
	if err != nil {
		t.Fatal(err)
	}
	enrolled, _ := res.LastInsertId()
	enrolledSID := CreateSession(app.DB, enrolled, "mgr2@example.com", "", time.Hour)
	passwordChangeExec(t, app.DB, "INSERT INTO notes(user_id,title) VALUES (?,?)", enrolled, "enrolled-note")
	delegated := createDelegatedSession(app.DB, uid, "mgr@example.com", "", time.Hour)

	app.Design = &DesignConfig{Auth: map[string]string{"require_mfa_for_roles": "auditor"}}
	if w := (mfaGateCall{method: "GET", path: "/api/notes", cookie: sid}).serve(gated); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "private-note") {
		t.Fatalf("unlisted role was held: %d %s", w.Code, w.Body.String())
	}
	app.Design = &DesignConfig{Auth: map[string]string{"require_mfa_for_roles": "auditor, Manager"}}
	if w := (mfaGateCall{method: "GET", path: "/api/notes", cookie: sid}).serve(gated); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "private-note") {
		t.Fatalf("existing session after the role was listed: %d %s", w.Code, w.Body.String())
	}
	if w := (mfaGateCall{method: "GET", path: "/api/notes", cookie: enrolledSID}).serve(gated); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "enrolled-note") {
		t.Fatalf("enrolled manager was held: %d %s", w.Code, w.Body.String())
	}
	if w := (mfaGateCall{method: "GET", path: "/api/notes", cookie: delegated}).serve(gated); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "private-note") {
		t.Fatalf("platform tooling's delegated session was held: %d %s", w.Code, w.Body.String())
	}
	// A factor that is only pending (setup started, never verified) is not one.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret='pending:JBSWY3DPEHPK3PXP' WHERE id=?", uid)
	if w := (mfaGateCall{method: "GET", path: "/api/notes", cookie: sid}).serve(gated); w.Code != http.StatusForbidden {
		t.Fatalf("pending enrollment counted as a factor: %d %s", w.Code, w.Body.String())
	}
}

// A passkey sign-in stands in for the TOTP step of an enrolled account (user
// verification is required), but it is not an enrollment: an account whose
// role auth.require_mfa_for_roles lists and that has no factor gets the
// setup grant a password or social sign-in gets, never a session.
func TestPasskeySignInHonorsRequiredMFAEnrollment(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	app.SessionDuration = time.Hour
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureMFAColumns(app.DB)
	if err := EnsurePasskeysTable(app.DB); err != nil {
		t.Fatal(err)
	}
	cookies, sid, uid := loginTestUser(app, "ada@example.com", "manager")
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

	app.Design = &DesignConfig{Auth: map[string]string{"require_mfa_for_roles": "manager"}}
	app.Paths = DiscoverAuthPaths(nil)
	held := httptest.NewRequest("GET", "/", nil)
	held.AddCookie(cookies[0])
	if s := getSession(app, held); s != nil {
		t.Fatal("the manager's existing session still resolved after the role was listed")
	}

	sessionName := sessionCookie("x", app.DevMode, app.SessionDuration).Name
	setupName := flowCookieName(flowCookieMFASetup, !app.DevMode)
	signIn := func() (*passkeyTestClient, int, map[string]any) {
		anon := &passkeyTestClient{t: t, app: app, cookies: map[string]*http.Cookie{}}
		anonCSRF := authMintCSRFToken("")
		code, o := anon.do(passkeyLoginOptions(app), "POST", "/api/_auth/passkeys/login/options", map[string]any{}, anonCSRF)
		if code != http.StatusOK {
			t.Fatalf("login options: %d %v", code, o)
		}
		ch, _ := b64url(o["challenge"].(string))
		cd, ad, sig := auth.get(testRP, testOrigin, ch, webauthnFlagUP|webauthnFlagUV)
		body := map[string]any{"id": b64urlEncode(auth.credID), "rawId": b64urlEncode(auth.credID), "type": "public-key",
			"response": map[string]any{"clientDataJSON": b64urlEncode(cd), "authenticatorData": b64urlEncode(ad), "signature": b64urlEncode(sig), "userHandle": b64urlEncode(passkeyUserHandle(app, uid))}}
		code, out := anon.do(passkeyLogin(app), "POST", "/api/_auth/passkeys/login", body, anonCSRF)
		return anon, code, out
	}

	anon, code, out := signIn()
	if code != http.StatusOK || out["mfa_setup_required"] != true || out["redirect"] != "/mfa-setup" || out["user"] != nil {
		t.Fatalf("unenrolled manager passkey sign-in: %d %v", code, out)
	}
	if _, ok := anon.cookies[sessionName]; ok {
		t.Fatal("unenrolled manager got a session from a passkey")
	}
	grant := anon.cookies[setupName]
	if grant == nil {
		t.Fatal("passkey sign-in issued no enrollment grant")
	}
	r := httptest.NewRequest("POST", "/api/_auth/mfa/setup", nil)
	r.AddCookie(grant)
	if got, _, err := mfaSetupTokenIdentity(app, app.DB, r); err != nil || got != uid {
		t.Fatalf("enrollment grant does not name the manager: %d %v", got, err)
	}

	// Enrolled: the passkey signs in without a TOTP step, and the sessions
	// the account already held work again.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET totp_secret='JBSWY3DPEHPK3PXP' WHERE id=?", uid)
	anon, code, out = signIn()
	if code != http.StatusOK || out["ok"] != true || anon.cookies[sessionName] == nil {
		t.Fatalf("enrolled manager passkey sign-in: %d %v", code, out)
	}
	if s := getSession(app, held); s == nil || s.UserID != uid {
		t.Fatalf("the enrolled manager's earlier session stayed held: %+v", s)
	}
}

// The YAML runner's users stand for signed-in users: one holding a listed role
// is enrolled, so `as_role: manager` tests keep their session.
func TestTestRunnerUserWithRequiredRoleIsEnrolled(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureMFAColumns(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{"require_mfa_for_roles": "manager"}}
	cookies, _, uid := loginTestUser(app, "runner@example.com", "manager")
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(cookies[0])
	if s := getSession(app, r); s == nil || s.UserID != uid {
		t.Fatalf("runner session of a listed role was held: %+v", s)
	}
	_, _, plain := loginTestUser(app, "plain@example.com", "user")
	if CheckMFA(app.DB, plain) {
		t.Fatal("a runner user with no listed role was given a factor")
	}
}
