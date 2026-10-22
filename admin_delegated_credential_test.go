//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// An admin's delegated credential (here a session scoped to docs:read) must
// not keep admin authority on admin-only management endpoints that never
// consult the credential's scopes; the admin's own login session still does.
func TestAdminOnlyEndpointsIgnoreDelegatedScopes(t *testing.T) {
	app, mux, cleanup := signedURLApp(t)
	defer cleanup()
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('boss', 'boss@example.com', 'admin', 1)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	scoped := CreateSession(app.DB, uid, "boss@example.com", "", time.Hour, "docs:read")

	// 1. Subscribe to every row change in the app.
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/_webhooks", scoped, map[string]any{"url": "https://hooks.example.com/x", "secret": "s"})
	// (Any answer but 403 means the admin gate passed; the URL check that
	// follows fails only because the test host doesn't resolve.)
	if rec.Code != http.StatusForbidden {
		t.Errorf("docs:read token passed the webhook-subscription admin gate: %d %s", rec.Code, rec.Body.String())
	}
	// 2. Read the whole user table through the admin panel.
	rec = crudScopeRequest(t, mux, http.MethodGet, "/_admin/_benmore_users", scoped, nil)
	if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "boss@example.com") {
		t.Errorf("docs:read token read _benmore_users via /_admin: %d", rec.Code)
	}
	// 3. Read the audit trail.
	rec = crudScopeRequest(t, mux, http.MethodGet, "/api/_audit", scoped, nil)
	if rec.Code == http.StatusOK {
		t.Errorf("docs:read token read the audit log: %d", rec.Code)
	}
	// The same admin's unscoped login session keeps every one of them.
	full := CreateSession(app.DB, uid, "boss@example.com", "", time.Hour)
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_audit", full, nil); rec.Code != http.StatusOK {
		t.Errorf("admin login session lost the audit log: %d %s", rec.Code, rec.Body.String())
	}
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/_admin/_benmore_users", full, nil); rec.Code == http.StatusForbidden {
		t.Errorf("admin login session lost the admin panel: %d", rec.Code)
	}
}
