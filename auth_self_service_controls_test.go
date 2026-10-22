//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestAuthSelfServiceOptOutClosesProductionHandlers(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Paths = &AuthPaths{Login: "/signin", Signup: "/join", Logout: "/signout", ForgotPassword: "/recover", ResetPassword: "/choose-password", VerifyEmail: "/verify", VerifyOTP: "/verify-otp"}
	app.Design = &DesignConfig{Auth: map[string]string{"signup": "false", "password_reset": "false", "api_tokens": "false"}, SEO: map[string]string{}}
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)

	for _, path := range []string{"/join", "/recover", "/choose-password", "/api/_auth/token", "/api/_auth/api-tokens"} {
		r := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"email":"new@example.com","password":"Whatever!123","name":"test","scopes":"*"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusNotFound {
			t.Errorf("POST %s = %d, want 404: %s", path, w.Code, w.Body.String())
		}
	}
	for name, query := range map[string]string{
		"users":    "SELECT COUNT(*) FROM _benmore_users",
		"resets":   "SELECT COUNT(*) FROM _benmore_password_resets",
		"tokens":   "SELECT COUNT(*) FROM _benmore_api_tokens",
		"sessions": "SELECT COUNT(*) FROM _benmore_sessions",
	} {
		var n int
		if err := app.DB.QueryRow(query).Scan(&n); err != nil || n != 0 {
			t.Errorf("%s side effects: count=%d err=%v", name, n, err)
		}
	}
	if id, err := oauthFindOrCreateUser(app, "oauth-new@example.com", "New OAuth", true); id != 0 || err != errAuthSignupDisabled {
		t.Errorf("closed signup allowed OAuth account creation: id=%d err=%v", id, err)
	}
}

func TestAuthSelfServiceOptOutDefaultsKeepSignupAndPasswordLogin(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)

	form := url.Values{"email": {"person@example.com"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Signup, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK && w.Code != http.StatusCreated && w.Code != http.StatusSeeOther {
		t.Fatalf("default signup refused: %d %s", w.Code, w.Body.String())
	}
	var email string
	if err := app.DB.QueryRow("SELECT email FROM _benmore_users LIMIT 1").Scan(&email); err != nil || email != "person@example.com" {
		t.Fatalf("default signup did not create account: email=%q err=%v", email, err)
	}

	recoveryUser(t, app, "login@example.com", fixturePassword, 1)
	login := url.Values{"email": {"login@example.com"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	r = httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(login.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Accept", "application/json")
	w = httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusOK && w.Code != http.StatusSeeOther {
		t.Fatalf("default password login refused: %d %s", w.Code, w.Body.String())
	}
	if id, err := oauthFindOrCreateUser(app, "oauth-new@example.com", "New OAuth", true); err != nil || id == 0 {
		t.Fatalf("default OAuth account creation refused: id=%d err=%v", id, err)
	}
}
