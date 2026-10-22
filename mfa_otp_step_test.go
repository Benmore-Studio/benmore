//go:build !cli

package main

import (
	"encoding/base32"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// With auth.otp on, the emailed code must be proven before any session,
// including when the TOTP step is completed on the separate MFA page.
func TestAuditMFAWebStepKeepsEmailOTP(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{"otp": "true"}}
	EnsureLoginAttemptsTable(app.DB)
	EnsureMFAColumns(app.DB)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("synthetic-totp-seed!"))
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (username, email, password_hash, role, verified, totp_secret) VALUES ('mfa', 'mfa@example.com', ?, 'user', 1, ?)", string(hash), secret)
	mux := http.NewServeMux()
	RegisterMFALoginRoute(mux, app)

	cookie := func(w *httptest.ResponseRecorder, name string) string {
		for _, c := range w.Result().Cookies() {
			if c.Name == name && c.MaxAge >= 0 {
				return c.Value
			}
		}
		return ""
	}
	form := url.Values{"email": {"mfa@example.com"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	handleLogin(w, r, app)
	mfaCookie := cookie(w, flowCookieName("_benmore_mfa_uid", true))
	if mfaCookie == "" {
		t.Fatalf("login did not route to the MFA step: %d %v", w.Code, w.Header())
	}

	r = httptest.NewRequest(http.MethodPost, app.Paths.VerifyMFA, strings.NewReader(url.Values{"mfa_code": {GenerateTOTP(secret)}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: flowCookieName("_benmore_mfa_uid", true), Value: mfaCookie})
	vw := httptest.NewRecorder()
	mux.ServeHTTP(vw, r)
	var sessions int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions").Scan(&sessions)
	if cookie(vw, sessionCookieName) != "" || sessions != 0 {
		t.Fatalf("auth.otp app issued a session after password + TOTP without the emailed code (sessions=%d, location=%q)", sessions, vw.Header().Get("Location"))
	}
}
