//go:build !cli && !windows

package main

import (
	"database/sql"
	"errors"
	"net/http"
	"strings"
	"testing"
)

// The unchanged-echo allowance must not become an equality oracle: when the
// caller cannot read the owned column, a right and a wrong guess both get 403.

func ownedWithExtraColumn(t *testing.T, column, stored string) *ownedFieldFixture {
	t.Helper()
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	if _, err := f.app.DB.Exec("ALTER TABLE tasks ADD COLUMN " + column + " TEXT"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("UPDATE tasks SET "+column+" = ? WHERE id = 1", stored); err != nil {
		t.Fatal(err)
	}
	f.app.mu.Lock()
	f.app.Flows = append(append([]Flow(nil), f.app.Flows...), Flow{Name: "review_command", Trigger: FlowTrigger{Type: "command"},
		Command: &FlowCommand{Writes: []string{"tasks"}, Owns: []FlowCommandOwn{{Table: "tasks", Column: column}}}})
	f.app.mu.Unlock()
	return f
}

func TestCommandOwnedFieldsHiddenColumnEchoIsNotAnOracle(t *testing.T) {
	f := ownedWithExtraColumn(t, "review_token", "s3cret")
	if !apiHiddenColumn(f.app, "tasks", "review_token") {
		t.Skip("fixture column is not hidden by name; precondition of the test")
	}
	for _, who := range []string{f.user, f.admin} {
		for _, guess := range []string{"nope", "s3cret"} {
			rec := crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", who, map[string]any{"title": "probe", "review_token": guess})
			if rec.Code != http.StatusForbidden {
				t.Fatalf("guess %q: status %d, want 403 for both guesses: %s", guess, rec.Code, rec.Body.String())
			}
			if title, _, _ := f.task(t); title != "Source-backed task" {
				t.Fatalf("a refused probe wrote the title: %q", title)
			}
		}
	}
}

func TestCommandOwnedFieldsEchoRefusedWhenReadModeDeniesCaller(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	// Editors may edit but not read tasks: status is not readable for them, so
	// even the right value is refused (and nothing is learned from the answer).
	f.app.Access.rules["tasks"] = map[AccessOp]string{"all": "group", OpRead: "admin"}
	for _, guess := range []string{"nope", "open"} {
		rec := crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"title": "probe", "status": guess})
		f.ownedBody(t, rec, "tasks.status")
	}
	// An admin who can read the column still gets the echo.
	rec := crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.admin, map[string]any{"title": "ok", "status": "open"})
	if rec.Code != http.StatusOK {
		t.Fatalf("readable echo: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCommandOwnedFieldsEchoRefusedForEncryptedColumn(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	f.app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"tasks": {{Column: "status"}}}}
	for _, guess := range []string{"nope", "open"} {
		rec := crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"title": "probe", "status": guess})
		f.ownedBody(t, rec, "tasks.status")
	}
}

func TestCommandOwnedFieldsReadableEchoStillSucceedsAndOnlyEchoIsNoop(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	rec := crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"title": "kept", "status": "open"})
	if rec.Code != http.StatusOK {
		t.Fatalf("readable echo with another change: %d %s", rec.Code, rec.Body.String())
	}
	// Only echoed owned keys: 200 no-op rather than 400 "No fields to update".
	rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"status": "open"})
	if rec.Code != http.StatusOK || rec.Body.String() == "" {
		t.Fatalf("echo-only update: %d %s", rec.Code, rec.Body.String())
	}
	if title, status, _ := f.task(t); title != "kept" || status != "open" {
		t.Fatalf("echo-only update changed the row: %q %q", title, status)
	}
	// An empty body is still a client error.
	rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"project_id_unknown": 1})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("a request with no writable field: %d %s", rec.Code, rec.Body.String())
	}
}

// failingCompare passes everything through except the comparison query, which fails.
type failingCompare struct{ mutationQuerier }

func (f failingCompare) QueryRow(q string, args ...any) *sql.Row {
	if strings.Contains(q, "EXISTS(SELECT 1 FROM main.") {
		// Same connection (the test pool holds one): a row that carries a query error.
		return f.mutationQuerier.QueryRow("SELECT * FROM no_such_table_for_test")
	}
	return f.mutationQuerier.QueryRow(q, args...)
}

func TestOwnedUpdateDropComparisonFailureIsInternalNotAnOwnershipRefusal(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	session := GetSessionFromDB(f.app.DB, f.user)
	if session == nil {
		t.Fatal("no session")
	}
	tx, err := f.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	_, err = ownedUpdateDrop(failingCompare{tx}, f.app, session, "tasks", "1", map[string]any{"status": "open"})
	var request *updateRequestError
	if err == nil || !errors.As(err, &request) || request.status != http.StatusInternalServerError {
		t.Fatalf("a failed comparison must be an internal error, got %v", err)
	}
	if _, isOwned := err.(*ownedFieldError); isOwned {
		t.Fatalf("a failed comparison was reported as an ownership refusal: %v", err)
	}
}
