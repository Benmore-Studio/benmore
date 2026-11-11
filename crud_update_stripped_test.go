//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// strippedUpdateApp is a bookings table whose status column belongs to a
// workflow, owner-scoped, with the CRUD routes registered.
func strippedUpdateApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open(sqliteHistoryTestDriver, filepath.Join(dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	mustExec(t, db, `CREATE TABLE bookings (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, status TEXT DEFAULT 'requested', notes TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAuditLogTable(db)
	EnsureIdempotencyTable(db)
	EnsureWebhooksTable(db)
	EnsurePermissionsTable(db)
	cols, err := GetTableColumns(db, "bookings")
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour,
		Tables: []Table{{Name: "bookings", Columns: cols}},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{"bookings": {"all": "self"}}},
		Workflows: &WorkflowConfig{Workflows: map[string]*Workflow{"booking": {
			Name: "booking", Table: "bookings", Field: "status", Initial: "requested",
			States:      []string{"requested", "confirmed"},
			Transitions: map[string]map[string]Transition{"requested": {"confirmed": {}}},
		}}},
	}
	t.Cleanup(app.Shutdown)
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	return app, mux
}

// Round 2 B8: a PATCH that names the workflow state column (or another column
// no update writes) used to answer 200 {"status":"updated"} with the state
// unchanged and no sign of it, and a state-only PATCH a bare 400 "No fields
// to update". The dropped columns are now named in X-Stripped-Fields and the
// body, with a pointer to the transition route.
func TestPatchNamesStrippedWorkflowAndProtectedFields(t *testing.T) {
	app, mux := strippedUpdateApp(t)
	sid := createCrudScopeSession(t, app, "booker@example.com", "user", "", "")
	session := GetSessionFromDB(app.DB, sid)
	if session == nil {
		t.Fatal("missing session")
	}
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/bookings", sid, map[string]any{"notes": "first"})
	if w.Code != http.StatusOK {
		t.Fatalf("create %d %s", w.Code, w.Body.String())
	}
	var created map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &created); err != nil {
		t.Fatal(err)
	}
	id := fmt.Sprint(created["id"])

	// Mixed PATCH: notes saves, status is dropped and named.
	w = crudScopeRequest(t, mux, http.MethodPatch, "/api/bookings/"+id, sid, map[string]any{"status": "confirmed", "notes": "x"})
	if w.Code != http.StatusOK {
		t.Fatalf("mixed patch %d %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Stripped-Fields"); got != "status" {
		t.Fatalf("mixed patch X-Stripped-Fields = %q, want status", got)
	}
	var body map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "updated" {
		t.Fatalf("mixed patch body %v", body)
	}
	hint, _ := body["hint"].(string)
	if !strings.Contains(hint, "POST /api/bookings/"+id+"/transition") {
		t.Fatalf("mixed patch hint does not point at the transition route: %q", hint)
	}
	var status, notes string
	if err := app.DB.QueryRow("SELECT status, notes FROM bookings WHERE id = ?", id).Scan(&status, &notes); err != nil {
		t.Fatal(err)
	}
	if status != "requested" || notes != "x" {
		t.Fatalf("row after mixed patch: status=%q notes=%q", status, notes)
	}

	// State-only PATCH: still 400, now naming the column and the route.
	w = crudScopeRequest(t, mux, http.MethodPatch, "/api/bookings/"+id, sid, map[string]any{"status": "confirmed"})
	if w.Code != http.StatusBadRequest {
		t.Fatalf("status-only patch %d %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Stripped-Fields"); got != "status" {
		t.Fatalf("status-only patch X-Stripped-Fields = %q", got)
	}
	body = map[string]any{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("status-only patch body is not JSON: %v %s", err, w.Body.String())
	}
	if body["error"] != "No fields to update" {
		t.Fatalf("status-only patch error = %v", body["error"])
	}
	if fields, _ := body["stripped_fields"].([]any); len(fields) != 1 || fields[0] != "status" {
		t.Fatalf("status-only patch stripped_fields = %v", body["stripped_fields"])
	}
	if hint, _ := body["hint"].(string); !strings.Contains(hint, "/api/bookings/"+id+"/transition") || !strings.Contains(hint, `"booking" workflow`) {
		t.Fatalf("status-only patch hint = %q", hint)
	}

	// Another user's id is dropped and named; the caller's own id, the path
	// id and a clean PATCH are not.
	w = crudScopeRequest(t, mux, http.MethodPatch, "/api/bookings/"+id, sid, map[string]any{"user_id": session.UserID + 7, "created_at": "2020-01-01"})
	if w.Code != http.StatusBadRequest || w.Header().Get("X-Stripped-Fields") != "created_at,user_id" {
		t.Fatalf("protected-only patch %d stripped=%q %s", w.Code, w.Header().Get("X-Stripped-Fields"), w.Body.String())
	}
	if hint := w.Body.String(); !strings.Contains(hint, "managed by the framework") {
		t.Fatalf("protected-only patch hint = %s", hint)
	}
	w = crudScopeRequest(t, mux, http.MethodPatch, "/api/bookings/"+id, sid, map[string]any{"id": created["id"], "user_id": session.UserID, "notes": "y"})
	if w.Code != http.StatusOK {
		t.Fatalf("echo patch %d %s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("X-Stripped-Fields"); got != "" {
		t.Fatalf("echo of own id named as stripped: %q", got)
	}
	if strings.Contains(w.Body.String(), "stripped_fields") {
		t.Fatalf("clean patch body names stripped fields: %s", w.Body.String())
	}
	var owner int64
	if err := app.DB.QueryRow("SELECT user_id FROM bookings WHERE id = ?", id).Scan(&owner); err != nil || owner != session.UserID {
		t.Fatalf("owner changed: %d %v", owner, err)
	}
}
