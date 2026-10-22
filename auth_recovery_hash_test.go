//go:build !cli

package main

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// The reset table stores only token hashes. The stored hash itself must not
// work as a reset token (the old IN(hash, raw) fallback made it one).
func TestResetTokenHashIsNotAToken(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Paths = &AuthPaths{Login: "/login", ResetPassword: "/reset-password", ForgotPassword: "/forgot-password"}
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsurePasswordResetsTable(app.DB)
	EnsureAPITokensTable(app.DB)
	EnsureAuditLogTable(app.DB)
	appOAuthEnsureTables(app)
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (5, 'vic', 'vic@example.com', 'old-hash')`)
	raw := "real-reset-token-value"
	stored := hashResetToken(raw)
	mustExec(t, app.DB, `INSERT INTO _benmore_password_resets (token, email, expires_at, type) VALUES ('`+stored+`', 'vic@example.com', '`+time.Now().Add(time.Hour).UTC().Format(time.RFC3339)+`', 'reset')`)
	post := func(tok string) {
		form := url.Values{"token": {tok}, "password": {"N3w-Passw0rd!x"}, "confirm": {"N3w-Passw0rd!x"}}
		req := httptest.NewRequest("POST", "/reset-password", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		handleResetPassword(rec, req, app)
	}
	hashNow := func() string {
		var h string
		app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = 5").Scan(&h)
		return h
	}
	post(stored)
	if hashNow() != "old-hash" {
		t.Fatal("the stored token hash reset the password")
	}
	post(raw)
	if hashNow() == "old-hash" {
		t.Fatal("the genuine token no longer resets the password")
	}
}
