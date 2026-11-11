//go:build !cli

package main

import (
	"net/http"
	"testing"
	"time"
)

// An admin's scoped API token is delegated access: it may share only what
// the owner and admin-grant checks allow, not every row (security.md 15b).
func TestScopedAdminTokenCannotShareOthersRows(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	_ = createCrudScopeSession(t, app, "owner@example.com", "user", "", "") // user 1 owns note 1
	full := createCrudScopeSession(t, app, "boss@example.com", "admin", "", "")
	adminID := GetSessionFromDB(app.DB, full).UserID
	scoped := CreateSession(app.DB, adminID, "boss@example.com", "", time.Hour, "notes:write,notes:read")

	body := map[string]any{"email": "friend@example.com", "permission": "edit"}
	if rec := crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/share", scoped, body); rec.Code != http.StatusForbidden {
		t.Fatalf("scoped admin token sharing another user's row = %d %s, want 403", rec.Code, rec.Body.String())
	}
	if rec := crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/share", full, body); rec.Code != http.StatusOK {
		t.Fatalf("full admin sign-in sharing = %d %s, want 200", rec.Code, rec.Body.String())
	}
}
