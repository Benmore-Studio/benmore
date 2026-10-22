//go:build !cli

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// A grandfathered, unverified account in an app that keys grants by email
// must verify its address at its next password sign-in; everyone else signs
// in as before, and a failed send never locks the member out.
func TestGrandfatheredAccountsVerifyOnNextSignIn(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{"url": "https://app.example.test"}}
	EnsureLoginAttemptsTable(app.DB)
	EnsureMFAColumns(app.DB)
	EnsurePasswordResetsTable(app.DB)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	for _, u := range []struct {
		email                   string
		verified, grandfathered int
	}{{"old@corp.example", 0, 1}, {"done@corp.example", 1, 1}, {"new@corp.example", 0, 0}} {
		passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (username, email, password_hash, verified, email_grandfathered) VALUES (?, ?, ?, ?, ?)",
			u.email, u.email, string(hash), u.verified, u.grandfathered)
	}
	var sent []string
	var sendErr error
	orig := sendVerificationEmail
	sendVerificationEmail = func(_ *App, to, _, body string) error { sent = append(sent, to+"|"+body); return sendErr }
	t.Cleanup(func() { sendVerificationEmail = orig })

	login := func(email string) *httptest.ResponseRecorder {
		form := url.Values{"email": {email}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
		r := httptest.NewRequest(http.MethodPost, app.Paths.Login, strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		handleLogin(w, r, app)
		return w
	}
	session := func(w *httptest.ResponseRecorder) string {
		for _, c := range w.Result().Cookies() {
			if c.Name == sessionCookieName && c.MaxAge >= 0 {
				return c.Value
			}
		}
		return ""
	}

	w := login("old@corp.example")
	if session(w) != "" || len(sent) != 1 || !strings.HasPrefix(sent[0], "old@corp.example|") {
		t.Fatalf("grandfathered unverified sign-in: session=%v sent=%v", session(w) != "", sent)
	}
	// A retry within minutes doesn't send a second link.
	if w := login("old@corp.example"); session(w) != "" || len(sent) != 1 {
		t.Fatalf("retry: session=%v sends=%d", session(w) != "", len(sent))
	}
	// The token exchange stops the same way.
	tr := httptest.NewRequest(http.MethodPost, "/api/_auth/token", strings.NewReader(`{"email":"old@corp.example","password":"`+fixturePassword+`"}`))
	tw := httptest.NewRecorder()
	handleTokenAuth(tw, tr, app)
	var tok map[string]any
	json.Unmarshal(tw.Body.Bytes(), &tok)
	if tw.Code != http.StatusForbidden || tok["error"] != "email_verification_required" {
		t.Fatalf("token exchange for a grandfathered account = %d %s", tw.Code, tw.Body.String())
	}

	// Opening the link verifies the account; the next sign-in completes.
	link := regexp.MustCompile(`token=([0-9a-f]+)`).FindStringSubmatch(sent[0])
	if link == nil {
		t.Fatalf("no verification link in %q", sent[0])
	}
	// The link opens outside any session (the sign-in stopped before one was
	// issued), so it asks for the account's password before verifying.
	vw := httptest.NewRecorder()
	handleVerifyEmail(vw, httptest.NewRequest(http.MethodGet, app.Paths.VerifyEmail+"?token="+link[1], nil), app)
	if vw.Code != http.StatusOK {
		t.Fatalf("expected the password prompt, got %d", vw.Code)
	}
	confirm := url.Values{"token": {link[1]}, "password": {fixturePassword}, "_csrf": {authMintCSRFToken("")}}
	cr := httptest.NewRequest(http.MethodPost, app.Paths.VerifyEmail, strings.NewReader(confirm.Encode()))
	cr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	handleVerifyEmailConfirm(httptest.NewRecorder(), cr, app)
	if w := login("old@corp.example"); session(w) == "" {
		t.Fatalf("verified account could not sign in: %d %v", w.Code, w.Header())
	}

	// Verified and non-grandfathered accounts are not interrupted.
	for _, email := range []string{"done@corp.example", "new@corp.example"} {
		if w := login(email); session(w) == "" {
			t.Fatalf("%s was stopped by the grandfather gate", email)
		}
	}

	// If the link can't be sent, the member keeps signing in.
	passwordChangeExec(t, app.DB, "UPDATE _benmore_users SET verified = 0, email_grandfathered = 1 WHERE email = 'done@corp.example'")
	sendErr = errors.New("mail down")
	if w := login("done@corp.example"); session(w) == "" {
		t.Fatal("a failed send locked a grandfathered member out")
	}

	// An app that keys nothing by email never asks.
	sendErr = nil
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"}
	app.Access = &AccessConfig{rules: map[string]map[AccessOp]string{"notes": {"all": "self"}}}
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (username, email, password_hash, verified, email_grandfathered) VALUES ('plain', 'plain@corp.example', ?, 0, 1)", string(hash))
	before := len(sent)
	if w := login("plain@corp.example"); session(w) == "" || len(sent) != before {
		t.Fatalf("app without email-keyed grants gated sign-in: session=%v sends=%d", session(w) != "", len(sent)-before)
	}
}
