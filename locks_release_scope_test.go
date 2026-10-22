//go:build !cli

package main

import (
	"net/http"
	"testing"
)

// Lock release answered 404 for an unlocked row and 403 for a row locked by
// someone else, on ANY id - so a caller in another tenant could tell which
// of that tenant's rows were being edited. Every lock endpoint now answers
// 404 for a row the caller cannot read, locked or not.
func TestLockEndpointsAnswer404ForUnreadableRows(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	EnsureLocksTable(app.DB)
	crudScopeMustExec(t, app.DB, `INSERT INTO records (org_id, user_id, title) VALUES ('org-b', 2, 'b-unlocked')`) // id 3
	groupA := createCrudScopeSession(t, app, "group-a@example.com", "user", "org-a", "")
	groupB := createCrudScopeSession(t, app, "group-b@example.com", "user", "org-b", "")

	// Tenant B's editor holds a lock on record 2; record 3 is unlocked.
	crudScopeMustExec(t, app.DB, `INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at)
		VALUES ('records', '2', 99, 'editor-b@example.com', datetime('now', '+1 hour'))`)

	for _, path := range []string{"/api/records/2/lock", "/api/records/3/lock", "/api/records/404/lock"} {
		for _, method := range []string{http.MethodDelete, http.MethodPost, http.MethodGet} {
			assertStatus(t, mux, method, path, groupA, nil, http.StatusNotFound)
		}
	}
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_locks WHERE table_name='records' AND row_id='2'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("cross-tenant release touched the lock: count=%d err=%v", n, err)
	}

	// Inside the tenant the specific answers are unchanged.
	assertStatus(t, mux, http.MethodDelete, "/api/records/2/lock", groupB, nil, http.StatusForbidden)
	assertStatus(t, mux, http.MethodDelete, "/api/records/3/lock", groupB, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPost, "/api/records/3/lock", groupB, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodDelete, "/api/records/3/lock", groupB, nil, http.StatusOK)
}
