//go:build !cli

package main

import (
	"encoding/base32"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func accountSettingsMuxFixture(t *testing.T, enabled *bool) (*App, *appRouteMux, int64, string) {
	t.Helper()
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	app.DevMode = true
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{"identifier": "email", "allow_emails": "owner@example.com,allowed@example.com,mfa@example.com"}, SEO: map[string]string{"url": "https://pilot.example"}}
	if enabled != nil {
		app.Design.Features = &FeaturesConfig{AccountSettings: enabled}
	}
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsureUserRolesTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	EnsureAPITokensTable(app.DB)
	EnsureAuditLogTable(app.DB)
	EnsureMFAColumns(app.DB)
	hash, err := bcrypt.GenerateFromPassword([]byte("Correct-Horse-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, verified) VALUES ('owner', 'owner@example.com', ?, 1)", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	sid := CreateSession(app.DB, uid, "owner@example.com", "", time.Hour)
	mux := buildAppRouteMux(app, false, "https://pilot.example", false, nil)
	return app, mux, uid, sid
}

func accountSettingsRequest(mux http.Handler, method, path, body, sid string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	if strings.Contains(body, "=") {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if sid != "" {
		r.AddCookie(sessionCookie(sid, true, time.Hour))
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

func TestAccountSettingsFeatureOptOutKeepsCoreIdentityAndLogin(t *testing.T) {
	off := false
	app, mux, uid, sid := accountSettingsMuxFixture(t, &off)
	sent := fakeEmailGateway(t)
	for _, c := range []struct{ method, path, body string }{
		{"GET", "/api/_auth/users", ""}, {"GET", "/api/_auth/users/1", ""},
		{"PATCH", "/api/_auth/profile", `{"first_name":"Changed"}`},
		{"POST", "/settings/password", "current_password=Correct-Horse-1&new_password=New-Horse-2&confirm_password=New-Horse-2"},
		{"POST", "/settings/profile", "email=outside%40example.net&current_password=Correct-Horse-1"},
		{"POST", "/settings/delete-account", "confirm=DELETE"},
		{"GET", "/settings/confirm-email?token=anything", ""}, {"POST", "/settings/confirm-email", "token=anything"},
		{"GET", "/api/_auth/sessions", ""}, {"DELETE", "/api/_auth/sessions/not-real", ""},
		{"POST", "/api/_auth/mfa/setup", `{"password":"Correct-Horse-1"}`},
		{"POST", "/api/_auth/mfa/verify", `{"code":"000000"}`}, {"POST", "/api/_auth/mfa/disable", `{"code":"000000"}`},
		{"POST", "/api/_auth/passkeys/register/options", `{}`}, {"POST", "/api/_auth/passkeys/register", `{}`},
		{"GET", "/api/_auth/passkeys", ""}, {"DELETE", "/api/_auth/passkeys/not-real", ""}, {"DELETE", "/api/_auth/passkeys", ""},
	} {
		if got := accountSettingsRequest(mux, c.method, c.path, c.body, sid).Code; got != http.StatusNotFound {
			t.Errorf("%s %s = %d, want 404", c.method, c.path, got)
		}
	}
	// An ordinary session wins over any attached setup token, even with valid CSRF.
	for _, setupToken := range []string{"bogus-setup-token", mintMFASetupToken(app, uid, "owner@example.com")} {
		setupReq := httptest.NewRequest("POST", "/api/_auth/mfa/setup", strings.NewReader(`{"password":"Correct-Horse-1"}`))
		setupReq.Header.Set("Content-Type", "application/json")
		setupReq.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
		setupReq.Header.Set("X-MFA-Setup-Token", setupToken)
		setupReq.AddCookie(sessionCookie(sid, true, time.Hour))
		setupRec := httptest.NewRecorder()
		mux.ServeHTTP(setupRec, setupReq)
		if setupRec.Code != http.StatusNotFound {
			t.Errorf("session plus setup-token header = %d, want 404", setupRec.Code)
		}
	}
	cookieSetupReq := httptest.NewRequest("POST", "/api/_auth/mfa/setup", strings.NewReader(`{"password":"Correct-Horse-1"}`))
	cookieSetupReq.Header.Set("Content-Type", "application/json")
	cookieSetupReq.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
	cookieSetupReq.AddCookie(sessionCookie(sid, true, time.Hour))
	cookieSetupReq.AddCookie(&http.Cookie{Name: flowCookieName(flowCookieMFASetup, !app.DevMode), Value: mintMFASetupToken(app, uid, "owner@example.com")})
	cookieSetupRec := httptest.NewRecorder()
	mux.ServeHTTP(cookieSetupRec, cookieSetupReq)
	if cookieSetupRec.Code != http.StatusNotFound {
		t.Errorf("session plus valid setup-token cookie = %d, want 404", cookieSetupRec.Code)
	}
	invalidAnonymous := httptest.NewRequest("POST", "/api/_auth/mfa/setup", strings.NewReader(`{"password":"Correct-Horse-1"}`))
	invalidAnonymous.Header.Set("X-MFA-Setup-Token", "bogus-setup-token")
	invalidAnonymousRec := httptest.NewRecorder()
	mux.ServeHTTP(invalidAnonymousRec, invalidAnonymous)
	if invalidAnonymousRec.Code != http.StatusNotFound {
		t.Errorf("anonymous invalid setup-token header = %d, want 404", invalidAnonymousRec.Code)
	}
	if got := accountSettingsRequest(mux, "GET", "/api/_auth/profile", "", sid).Code; got != http.StatusOK {
		t.Fatalf("current-user identity endpoint = %d, want 200", got)
	}
	var first, email, secret string
	var sessions, pending int
	if err := app.DB.QueryRow("SELECT first_name, email, COALESCE(totp_secret,'') FROM _benmore_users WHERE id = ?", uid).Scan(&first, &email, &secret); err != nil {
		t.Fatal(err)
	}
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?", uid).Scan(&sessions)
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_email_changes WHERE user_id = ?", uid).Scan(&pending)
	if first != "" || email != "owner@example.com" || secret != "" || sessions != 1 || pending != 0 {
		t.Fatalf("disabled routes mutated account: first=%q email=%q mfa=%q sessions=%d pending=%d", first, email, secret, sessions, pending)
	}
	if len(sent()) != 0 {
		t.Fatal("disabled email-change route sent mail")
	}
	setupToken := mintMFASetupToken(app, uid, "owner@example.com")
	setupReq := httptest.NewRequest("POST", "/api/_auth/mfa/setup", strings.NewReader(`{}`))
	setupReq.AddCookie(&http.Cookie{Name: flowCookieName(flowCookieMFASetup, !app.DevMode), Value: setupToken})
	setupRec := httptest.NewRecorder()
	mux.ServeHTTP(setupRec, setupReq)
	if setupRec.Code != http.StatusOK {
		t.Fatalf("login-issued MFA enrollment with settings disabled = %d: %s", setupRec.Code, setupRec.Body.String())
	}

	// Login uses the normal CSRF bootstrap and remains available while settings are off.
	csrf := httptest.NewRecorder()
	mux.ServeHTTP(csrf, httptest.NewRequest("GET", "/api/_csrf", nil))
	var csrfBody struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(csrf.Body.Bytes(), &csrfBody); err != nil {
		t.Fatal(err)
	}
	form := url.Values{"email": {"owner@example.com"}, "password": {"Correct-Horse-1"}, "_csrf": {csrfBody.Token}}
	login := httptest.NewRecorder()
	loginReq := httptest.NewRequest("POST", "/login", strings.NewReader(form.Encode()))
	loginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mux.ServeHTTP(login, loginReq)
	if login.Code != http.StatusSeeOther {
		t.Fatalf("login with settings disabled = %d: %s", login.Code, login.Body.String())
	}
	var loginCookie *http.Cookie
	for _, c := range login.Result().Cookies() {
		if strings.Contains(c.Name, "benmore_session") {
			loginCookie = c
		}
	}
	if loginCookie == nil {
		t.Fatalf("password login did not issue its session cookie: status=%d body=%s csrf=%q", login.Code, login.Body.String(), csrf.Body.String())
	}
	logoutReq := httptest.NewRequest("POST", "/logout", nil)
	logoutReq.AddCookie(loginCookie)
	logoutReq.Header.Set("X-CSRF-Token", authMintCSRFToken(loginCookie.Value))
	logout := httptest.NewRecorder()
	mux.ServeHTTP(logout, logoutReq)
	if logout.Code != http.StatusSeeOther {
		t.Fatalf("logout with settings disabled = %d", logout.Code)
	}
	if GetSessionFromDB(app.DB, loginCookie.Value) != nil {
		t.Fatal("logout with settings disabled retained session")
	}

	// A real login-time TOTP proof remains available even though optional factor management is off.
	mfaHash, err := bcrypt.GenerateFromPassword([]byte("Correct-Horse-1"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	mfaSecret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("synthetic-mfa-seed!"))
	if _, err := app.DB.Exec("INSERT INTO _benmore_users (username,email,password_hash,verified,totp_secret) VALUES ('mfa','mfa@example.com',?,1,?)", string(mfaHash), mfaSecret); err != nil {
		t.Fatal(err)
	}
	mfaForm := url.Values{"email": {"mfa@example.com"}, "password": {"Correct-Horse-1"}, "_csrf": {authMintCSRFToken("")}}
	mfaLoginReq := httptest.NewRequest("POST", "/login", strings.NewReader(mfaForm.Encode()))
	mfaLoginReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	mfaLogin := httptest.NewRecorder()
	mux.ServeHTTP(mfaLogin, mfaLoginReq)
	if mfaLogin.Code != http.StatusSeeOther || mfaLogin.Header().Get("Location") != app.Paths.VerifyMFA {
		t.Fatalf("MFA login step: status=%d location=%q", mfaLogin.Code, mfaLogin.Header().Get("Location"))
	}
	var stepCookie *http.Cookie
	for _, c := range mfaLogin.Result().Cookies() {
		if c.Name == flowCookieName(flowCookieMFA, !app.DevMode) {
			stepCookie = c
		}
	}
	if stepCookie == nil {
		t.Fatal("MFA login did not issue the verification cookie")
	}
	verifyReq := httptest.NewRequest("POST", app.Paths.VerifyMFA, strings.NewReader(url.Values{"mfa_code": {GenerateTOTP(mfaSecret)}}.Encode()))
	verifyReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	verifyReq.AddCookie(stepCookie)
	verify := httptest.NewRecorder()
	mux.ServeHTTP(verify, verifyReq)
	if verify.Code != http.StatusSeeOther {
		t.Fatalf("login MFA verification with settings disabled = %d: %s", verify.Code, verify.Body.String())
	}
	var verifiedSession *http.Cookie
	for _, c := range verify.Result().Cookies() {
		if c.Name == sessionCookieNameFor(!app.DevMode) {
			verifiedSession = c
		}
	}
	if verifiedSession == nil || GetSessionFromDB(app.DB, verifiedSession.Value) == nil {
		t.Fatal("login MFA verification did not issue a session")
	}

	// Login-time MFA and required-password replacement are independent routes.
	for _, path := range []string{"/verify-mfa", "/api/_auth/change-password", "/api/_auth/passkeys/login/options"} {
		route := path
		method := "POST"
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(method, route, strings.NewReader("code=000000")))
		if w.Code == http.StatusNotFound {
			t.Errorf("core authentication route %s was hidden", path)
		}
	}
}

func TestAccountSettingsDefaultsEnabledAndEmailAllowlistRechecked(t *testing.T) {
	app, mux, uid, sid := accountSettingsMuxFixture(t, nil)
	sent := fakeEmailGateway(t)
	for _, c := range []struct{ method, path string }{{"GET", "/api/_auth/profile"}, {"GET", "/api/_auth/users"}, {"GET", "/api/_auth/sessions"}} {
		if got := accountSettingsRequest(mux, c.method, c.path, "", sid).Code; got != http.StatusOK {
			t.Errorf("default %s %s = %d, want 200", c.method, c.path, got)
		}
	}
	allowedForm := url.Values{"email": {"allowed@example.com"}, "current_password": {"Correct-Horse-1"}, "_csrf": {authMintCSRFToken(sid)}}
	allowedReq := httptest.NewRequest("POST", "http://pilot.example/settings/profile", strings.NewReader(allowedForm.Encode()))
	allowedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	allowedReq.AddCookie(sessionCookie(sid, true, time.Hour))
	allowedRec := httptest.NewRecorder()
	mux.ServeHTTP(allowedRec, allowedReq)
	if allowedRec.Code != http.StatusSeeOther || len(sent()) != 1 {
		t.Fatalf("default allowed email change: status=%d sends=%d body=%s", allowedRec.Code, len(sent()), allowedRec.Body.String())
	}
	ensureEmailChangesTable(app.DB)
	var pendingBefore int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_email_changes WHERE user_id = ?", uid).Scan(&pendingBefore)
	blockedForm := url.Values{"email": {"blocked@example.net"}, "current_password": {"Correct-Horse-1"}, "_csrf": {authMintCSRFToken(sid)}}
	blockedReq := httptest.NewRequest("POST", "http://pilot.example/settings/profile", strings.NewReader(blockedForm.Encode()))
	blockedReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	blockedReq.AddCookie(sessionCookie(sid, true, time.Hour))
	blockedRec := httptest.NewRecorder()
	mux.ServeHTTP(blockedRec, blockedReq)
	if len(sent()) != 1 {
		t.Fatalf("disallowed email change sent mail; sends=%d status=%d", len(sent()), blockedRec.Code)
	}
	var pending int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_email_changes WHERE user_id = ?", uid).Scan(&pending)
	if pending != pendingBefore {
		t.Fatalf("disallowed request changed pending rows from %d to %d", pendingBefore, pending)
	}
	token := "old-policy-token"
	if _, err := app.DB.Exec("INSERT INTO _benmore_email_changes (user_id,new_email,token_hash,expires_at) VALUES (?,?,?,?)", uid, "blocked@example.net", hashResetToken(token), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := confirmEmailChange(app, token); err == nil {
		t.Fatal("confirmation outside the current allowlist was accepted")
	}
	if got := currentEmail(t, app, uid); got != "owner@example.com" {
		t.Fatalf("disallowed confirmation changed account email to %q", got)
	}
}
