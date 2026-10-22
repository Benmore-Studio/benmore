//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// With auth.otp on, a role that must enroll MFA used to get the enrollment
// token straight after the password - and enrollment verify issues a full
// session, so a password alone was enough to sign in (binding the caller's
// own authenticator on the way). The emailed code must come first.
func TestOTPRequiredBeforeMFAEnrollment(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	EnsureLoginAttemptsTable(app.DB)
	EnsureMFAColumns(app.DB)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('ops', 'ops@example.com', ?, 'manager', 1)", string(hash))

	cookie := func(w *httptest.ResponseRecorder, name string) string {
		for _, c := range w.Result().Cookies() {
			if c.Name == name && c.MaxAge >= 0 {
				return c.Value
			}
		}
		return ""
	}
	login := func() *httptest.ResponseRecorder {
		form := url.Values{"email": {"ops@example.com"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
		r := httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleLogin(w, r, app)
		return w
	}

	// Control: without OTP the enrollment token follows the password.
	app.Design = &DesignConfig{Auth: map[string]string{"require_mfa_for_roles": "manager"}}
	if w := login(); cookie(w, flowCookieName("_benmore_mfa_setup", true)) == "" {
		t.Fatalf("non-OTP app lost the enrollment redirect: %d %v", w.Code, w.Header())
	}

	app.Design = &DesignConfig{Auth: map[string]string{"require_mfa_for_roles": "manager", "otp": "true"}}
	w := login()
	if cookie(w, flowCookieName("_benmore_mfa_setup", true)) != "" || cookie(w, sessionCookieName) != "" {
		t.Fatal("password alone produced an enrollment token or session with auth.otp on")
	}
	otpCookie := cookie(w, flowCookieName("_benmore_otp_uid", true))
	if otpCookie == "" || !strings.HasPrefix(w.Header().Get("Location"), app.Paths.VerifyOTP) {
		t.Fatalf("login did not route to the OTP step: %d %q", w.Code, w.Header().Get("Location"))
	}
	var code string
	if err := app.DB.QueryRow("SELECT code FROM _benmore_otp WHERE email = 'ops@example.com'").Scan(&code); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, app.Paths.VerifyOTP, strings.NewReader(url.Values{"code": {code}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.AddCookie(&http.Cookie{Name: flowCookieName("_benmore_otp_uid", true), Value: otpCookie})
	vw := httptest.NewRecorder()
	handleVerifyOTP(vw, r, app)
	if cookie(vw, sessionCookieName) != "" {
		t.Fatal("OTP step issued a session to an account that must enroll MFA")
	}
	if cookie(vw, flowCookieName("_benmore_mfa_setup", true)) == "" || vw.Header().Get("Location") != "/mfa-setup" {
		t.Fatalf("OTP step did not continue to enrollment: %d %q", vw.Code, vw.Header().Get("Location"))
	}
	var sessions int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions").Scan(&sessions)
	if sessions != 0 {
		t.Fatalf("sessions issued before enrollment: %d", sessions)
	}
}
