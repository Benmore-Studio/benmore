//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// Mail security scanners and link previewers fetch every link in an incoming
// message. The confirmation link applied the change on that GET, so anyone
// could ask to move their own account onto an address they don't control
// (one with pending invites, shares or email-keyed memberships) and let the
// recipient's mail scanner confirm it. Opening the link now only shows a
// confirm button; the change applies on its POST.
func TestEmailChangeLinkFetchDoesNotApply(t *testing.T) {
	app, mux, uid, _ := newEmailChangeTestApp(t)
	ensureEmailChangesTable(app.DB)
	token := "scanner-fetched-token"
	if _, err := app.DB.Exec("INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, 'invited@corp.example', ?, ?)",
		uid, hashResetToken(token), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // a scanner, then the person opening the mail
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/settings/confirm-email?token="+token, nil))
		if got := currentEmail(t, app, uid); got != "amy@example.com" {
			t.Fatalf("fetching the link changed the email to %q", got)
		}
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `method="post"`) || !strings.Contains(rec.Body.String(), "invited@corp.example") {
			t.Fatalf("link page: %d %s", rec.Code, rec.Body.String())
		}
	}

	post := func(form url.Values) {
		r := httptest.NewRequest(http.MethodPost, "/settings/confirm-email", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		mux.ServeHTTP(httptest.NewRecorder(), r)
	}
	post(url.Values{"token": {token}}) // no CSRF token
	if got := currentEmail(t, app, uid); got != "amy@example.com" {
		t.Fatalf("a POST without the form's CSRF token applied the change: %q", got)
	}
	// The requester, outside the account's signed-in browser, also proves the
	// account with its password (settings_email_change_proof_test.go).
	EnsureLoginAttemptsTable(app.DB)
	post(url.Values{"token": {token}, "_csrf": {authMintCSRFToken("")}, "password": {"Correct-Horse-1"}})
	if got := currentEmail(t, app, uid); got != "invited@corp.example" {
		t.Fatalf("confirming from the page did not apply the change: %q", got)
	}
}
