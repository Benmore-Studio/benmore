//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The mail senders treat a To value as a comma-list, and the auth.domain gate
// only checked that the address ENDS with the allowed domain. Registering
// "me@evil.example,x@corp.example" therefore passed a corp.example gate while
// the OTP / verification mail was delivered to me@evil.example as well - the
// one proof an OTP-protected, domain-locked app relies on.
func TestSignupRefusesMultiRecipientAddress(t *testing.T) {
	t.Setenv("BENMORE_PUBLIC_URL", "https://app.real")
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{"domain": "corp.example", "otp": "true"}, SEO: map[string]string{}}

	for _, email := range []string{
		"me@evil.example,x@corp.example",
		"me@evil.example;x@corp.example",
		"me@evil.example x@corp.example",
		"me@evil.example@corp.example",
		"<me@evil.example>x@corp.example",
		"nobody",
	} {
		form := url.Values{"email": {email}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
		r := httptest.NewRequest(http.MethodPost, app.Paths.Signup, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		handleSignup(httptest.NewRecorder(), r, app)
		var n int
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_users").Scan(&n)
		if n != 0 {
			t.Fatalf("signup accepted %q", email)
		}
	}

	// Control: a plain in-domain address still registers.
	form := url.Values{"email": {"Person@Corp.example"}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	r := httptest.NewRequest(http.MethodPost, app.Paths.Signup, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleSignup(httptest.NewRecorder(), r, app)
	var stored string
	if err := app.DB.QueryRow("SELECT email FROM _benmore_users").Scan(&stored); err != nil || stored != "person@corp.example" {
		t.Fatalf("control signup: %q %v", stored, err)
	}
}

func TestEmailChangeRefusesMultiRecipientAddress(t *testing.T) {
	t.Setenv("BENMORE_PUBLIC_URL", "https://app.real")
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureUsersTable(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{"url": "https://app.real"}}
	r := httptest.NewRequest(http.MethodPatch, "/api/_auth/profile", nil)
	if err := requestEmailChange(app, r, 1, "me@evil.example,x@corp.example"); err == nil {
		t.Fatal("email change accepted a multi-recipient address")
	}
	var pending int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_email_changes").Scan(&pending)
	if pending != 0 {
		t.Fatalf("a pending change was recorded: %d", pending)
	}
	if err := requestEmailChange(app, r, 1, "ok@corp.example"); err != nil && !strings.Contains(err.Error(), "confirmation email") {
		t.Fatalf("control change refused: %v", err)
	}
}
