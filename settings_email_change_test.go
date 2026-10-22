//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func newEmailChangeTestApp(t *testing.T) (*App, *http.ServeMux, int64, string) {
	t.Helper()
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	hash, _ := bcrypt.GenerateFromPassword([]byte("Correct-Horse-1"), bcrypt.MinCost)
	res, err := app.DB.Exec(`INSERT INTO _benmore_users (username, email, password_hash, verified) VALUES ('amy', 'amy@example.com', ?, 1)`, string(hash))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	sid := CreateSession(app.DB, uid, "amy@example.com", "", time.Hour)
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, app)
	return app, mux, uid, sid
}

func currentEmail(t *testing.T, app *App, uid int64) string {
	var e string
	app.DB.QueryRow("SELECT email FROM _benmore_users WHERE id = ?", uid).Scan(&e)
	return e
}

// Changing the email must never take effect without the new inbox proving
// control: email is an authorization input (tenant membership, shares,
// invites resolve by it).
func TestProfileEmailChangeDoesNotApplyImmediately(t *testing.T) {
	app, mux, uid, sid := newEmailChangeTestApp(t)
	req := httptest.NewRequest("PATCH", "/api/_auth/profile", strings.NewReader(`{"email":"invited-ceo@corp.example","current_password":"Correct-Horse-1"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sid)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if got := currentEmail(t, app, uid); got != "amy@example.com" {
		t.Fatalf("email changed without confirmation: %q (status %d)", got, rec.Code)
	}
	// No mail provider in tests: the request fails closed and leaves no
	// pending change behind.
	var pending int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_email_changes").Scan(&pending)
	if rec.Code == http.StatusAccepted || pending != 0 {
		t.Fatalf("unsent confirmation left a pending change: status=%d pending=%d", rec.Code, pending)
	}
}

func TestConfirmEmailChangeAppliesOnceAndRevokesSessions(t *testing.T) {
	app, mux, uid, _ := newEmailChangeTestApp(t)
	ensureEmailChangesTable(app.DB)
	EnsureLoginAttemptsTable(app.DB)
	mustExec(t, app.DB, "UPDATE _benmore_users SET verified = 0 WHERE id = "+strconv.FormatInt(uid, 10))
	token := "known-token-for-test"
	if _, err := app.DB.Exec("INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, 'amy.new@example.com', ?, ?)",
		uid, hashResetToken(token), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	// Open the link, then press its confirm button.
	get := func(tok string) {
		mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/settings/confirm-email?token="+tok, nil))
		// Outside the account's own browser the confirm form also takes the
		// account's password.
		form := url.Values{"token": {tok}, "_csrf": {authMintCSRFToken("")}, "password": {"Correct-Horse-1"}}
		r := httptest.NewRequest("POST", "/settings/confirm-email", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		mux.ServeHTTP(httptest.NewRecorder(), r)
	}
	get(token)
	if got := currentEmail(t, app, uid); got != "amy.new@example.com" {
		t.Fatalf("confirmed change not applied: %q", got)
	}
	var verified, sessions int
	app.DB.QueryRow("SELECT verified FROM _benmore_users WHERE id = ?", uid).Scan(&verified)
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ?", uid).Scan(&sessions)
	if verified != 1 || sessions != 0 {
		t.Fatalf("after confirm verified=%d sessions=%d, want 1 and 0", verified, sessions)
	}
	// Single use.
	mustExec(t, app.DB, "UPDATE _benmore_users SET email = 'amy@example.com' WHERE id = "+strconv.FormatInt(uid, 10))
	get(token)
	if got := currentEmail(t, app, uid); got != "amy@example.com" {
		t.Fatalf("token reused: %q", got)
	}
	// Expired links do nothing.
	expired := "expired-token"
	app.DB.Exec("INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, 'late@example.com', ?, ?)",
		uid, hashResetToken(expired), time.Now().Add(-time.Minute).UTC().Format(time.RFC3339))
	get(expired)
	if got := currentEmail(t, app, uid); got != "amy@example.com" {
		t.Fatalf("expired token applied: %q", got)
	}
}
