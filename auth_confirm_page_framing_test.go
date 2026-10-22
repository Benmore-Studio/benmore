//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// framingDenied reports whether a response forbids every framer, given the
// app-wide headers already applied to it.
func framingDenied(h http.Header) bool {
	denied := false
	for _, csp := range h.Values("Content-Security-Policy") {
		for _, d := range strings.Split(csp, ";") {
			if f := strings.Fields(d); len(f) == 2 && strings.EqualFold(f[0], "frame-ancestors") && f[1] == "'none'" {
				denied = true
			}
		}
	}
	return denied && h.Get("X-Frame-Options") == "DENY"
}

// An app may let other sites frame it (csp.frame_ancestors, for embed pages),
// and every app can be framed by the platform workspace. The framework's own
// confirmation pages inherited that policy, so a page whose button confirms
// an email change, verifies an address or replaces a password could be shown
// inside someone else's frame.
func TestConfirmationPagesRefuseFraming(t *testing.T) {
	app, mux, uid, _ := newEmailChangeTestApp(t)
	EnsurePasswordResetsTable(app.DB)
	ensureEmailChangesTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}, CSP: map[string]string{"frame_ancestors": "*"}}
	serve := func(h http.HandlerFunc, r *http.Request) http.Header {
		w := httptest.NewRecorder()
		applySecurityHeaders(w, false, app) // what the app-wide middleware sets first
		h(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status %d", r.URL.Path, w.Code)
		}
		return w.Header()
	}

	if _, err := app.DB.Exec("INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, 'next@example.com', ?, ?)",
		uid, hashResetToken("change"), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if h := serve(mux.ServeHTTP, httptest.NewRequest(http.MethodGet, "/settings/confirm-email?token=change", nil)); !framingDenied(h) {
		t.Errorf("the email-change confirmation page can be framed: %q / %q", h.Values("Content-Security-Policy"), h.Get("X-Frame-Options"))
	}

	mustExec(t, app.DB, "UPDATE _benmore_users SET verified = 0")
	if _, err := app.DB.Exec("INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES (?, 'amy@example.com', ?, 'verify')",
		hashResetToken("verify"), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	verify := func(w http.ResponseWriter, r *http.Request) { handleVerifyEmail(w, r, app) }
	if h := serve(verify, httptest.NewRequest(http.MethodGet, "/verify-email?token=verify", nil)); !framingDenied(h) {
		t.Errorf("the verify-email confirmation page can be framed: %q / %q", h.Values("Content-Security-Policy"), h.Get("X-Frame-Options"))
	}

	change := func(w http.ResponseWriter, r *http.Request) { renderPasswordChange(w, r, app, "", http.StatusOK) }
	if h := serve(change, httptest.NewRequest(http.MethodGet, passwordChangePagePath, nil)); !framingDenied(h) {
		t.Errorf("the required-password-change page can be framed: %q / %q", h.Values("Content-Security-Policy"), h.Get("X-Frame-Options"))
	}

	// Control: an ordinary response of the same app keeps the app's policy.
	w := httptest.NewRecorder()
	applySecurityHeaders(w, false, app)
	if framingDenied(w.Header()) {
		t.Fatal("control: the app-wide policy already denies framing, so this test proves nothing")
	}
}
