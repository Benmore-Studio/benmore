//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// Lock status names the user holding the lock. It must follow the same
// read gate as the row itself: a caller in another tenant (or without the
// table's read mode) learns neither that the row is being edited nor who
// is editing it.
func TestLockStatusRequiresRowReadAccess(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	EnsureLocksTable(app.DB)
	groupA := createCrudScopeSession(t, app, "group-a@example.com", "user", "org-a", "")
	groupB := createCrudScopeSession(t, app, "group-b@example.com", "user", "org-b", "")

	// Tenant B's editor holds a lock on tenant B's record 2.
	if _, err := app.DB.Exec(`INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at)
		VALUES ('records', '2', 2, 'editor-b@example.com', datetime('now', '+1 hour'))`); err != nil {
		t.Fatal(err)
	}

	// The owning tenant still sees who holds it.
	own := crudScopeRequest(t, mux, http.MethodGet, "/api/records/2/lock", groupB, nil)
	if own.Code != http.StatusOK || !strings.Contains(own.Body.String(), "editor-b@example.com") {
		t.Fatalf("same-tenant lock status = %d %s, want 200 naming the holder", own.Code, own.Body.String())
	}

	// Another tenant gets nothing about the row.
	cross := crudScopeRequest(t, mux, http.MethodGet, "/api/records/2/lock", groupA, nil)
	if cross.Code == http.StatusOK || strings.Contains(cross.Body.String(), "editor-b@example.com") {
		t.Fatalf("cross-tenant lock status = %d %s, want no lock details", cross.Code, cross.Body.String())
	}

	// notes has no access: rule, so it is owner-scoped: user A cannot see
	// the lock on user B's note.
	if _, err := app.DB.Exec(`INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at)
		VALUES ('notes', '2', 2, 'owner-b@example.com', datetime('now', '+1 hour'))`); err != nil {
		t.Fatal(err)
	}
	other := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/2/lock", groupA, nil)
	if other.Code == http.StatusOK || strings.Contains(other.Body.String(), "owner-b@example.com") {
		t.Fatalf("non-owner lock status = %d %s, want no lock details", other.Code, other.Body.String())
	}
}
