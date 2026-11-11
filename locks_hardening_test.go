//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// Lock status on a `read: anon` table used to name the editor holding the
// lock to any anonymous visitor. It now needs a session, and only a caller
// who may edit the row is told who holds it.
func TestLockStatusHidesHolderFromAnonAndReadOnlyCallers(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	EnsureLocksTable(app.DB)
	app.Access.rules["notes"] = map[AccessOp]string{"read": "anon", "update": "admin"}
	reader := createCrudScopeSession(t, app, "reader@example.com", "user", "", "")
	if _, err := app.DB.Exec(`INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at)
		VALUES ('notes', '1', 99, 'editor@example.com', datetime('now', '+1 hour'))`); err != nil {
		t.Fatal(err)
	}

	anon := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1/lock", "", nil)
	if anon.Code != http.StatusUnauthorized || strings.Contains(anon.Body.String(), "editor@example.com") {
		t.Fatalf("anonymous lock status = %d %s, want 401 without the holder", anon.Code, anon.Body.String())
	}

	ro := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1/lock", reader, nil)
	if ro.Code != http.StatusOK || !strings.Contains(ro.Body.String(), `"locked":true`) || strings.Contains(ro.Body.String(), "editor@example.com") {
		t.Fatalf("read-only lock status = %d %s, want locked without the holder", ro.Code, ro.Body.String())
	}
}

// A table the caller may not read answers the lock routes exactly like an
// unmatched /api path (security.md 14f), not a distinct {"error":"not found"}.
func TestLockRoutesUnreadableTableAnswersUnmatched(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	EnsureLocksTable(app.DB)
	app.Access.rules["notes"] = map[AccessOp]string{"all": "admin"}
	user := createCrudScopeSession(t, app, "plain@example.com", "user", "", "")
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		rec := crudScopeRequest(t, mux, method, "/api/notes/1/lock", user, nil)
		if rec.Code != http.StatusNotFound || strings.TrimSpace(rec.Body.String()) != unmatchedAPINotFoundBody {
			t.Fatalf("%s lock on unreadable table = %d %s, want the unmatched-route 404", method, rec.Code, rec.Body.String())
		}
	}
}

// CheckLock only reads: an expired lock is ignored (never a stale 409) and
// left for the cleanup worker instead of deleted on every write's check.
func TestCheckLockIgnoresExpiredWithoutWriting(t *testing.T) {
	app, _ := newCrudScopeTestApp(t)
	EnsureLocksTable(app.DB)
	if _, err := app.DB.Exec(`INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at)
		VALUES ('notes', '1', 99, 'old@example.com', datetime('now', '-1 hour')),
		       ('notes', '2', 99, 'live@example.com', datetime('now', '+1 hour'))`); err != nil {
		t.Fatal(err)
	}
	if locked, _ := CheckLock(app.DB, "notes", "1", 1); locked {
		t.Fatal("expired lock reported as held")
	}
	if locked, by := CheckLock(app.DB, "notes", "2", 1); !locked || by != "live@example.com" {
		t.Fatalf("live lock = %v %q, want held by live@example.com", locked, by)
	}
	var n int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_locks WHERE row_id = '1'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("expired lock rows = %d (%v), want CheckLock to leave it to the sweeper", n, err)
	}
}

// An anonymous PATCH on an `update: anon` table holds no lock, so any lock
// blocks it, as DELETE and batch already did.
func TestAnonymousPatchHonoursRecordLock(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	EnsureLocksTable(app.DB)
	app.Access.rules["notes"] = map[AccessOp]string{"read": "anon", "update": "anon"}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at)
		VALUES ('notes', '1', 99, 'editor@example.com', datetime('now', '+1 hour'))`); err != nil {
		t.Fatal(err)
	}
	// A Bearer value that names no session: anonymous, and a native client
	// (no cookie), so CSRF does not apply.
	req := crudScopeRequest(t, mux, http.MethodPatch, "/api/notes/1", "no-such-session", map[string]any{"title": "changed"})
	if req.Code != http.StatusConflict {
		t.Fatalf("anonymous PATCH on a locked row = %d %s, want 409", req.Code, req.Body.String())
	}
	var title string
	if err := app.DB.QueryRow(`SELECT title FROM notes WHERE id = 1`).Scan(&title); err != nil || title != "owner-a" {
		t.Fatalf("title = %q (%v), want unchanged", title, err)
	}
}
