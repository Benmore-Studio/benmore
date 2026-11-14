//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

func assertUnmatchedAPI(t *testing.T, label string, code int, body string) {
	t.Helper()
	if code != http.StatusNotFound || strings.TrimSpace(body) != unmatchedAPINotFoundBody {
		t.Fatalf("%s = %d %s, want exactly the unmatched-route 404", label, code, body)
	}
}

// Side routes answer an unknown table, and a table the caller may not read,
// with exactly the unmatched-route 404 (security.md 14f).
func TestSideRoutesAnswerUnreadableTablesLikeUnmatchedPaths(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	EnsureLocksTable(app.DB)
	sid := createCrudScopeSession(t, app, "plain@example.com", "user", "", "")

	// /api/_transaction: an unknown table used to answer 400 "unknown table".
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", sid, map[string]any{
		"operations": []map[string]any{{"table": "no_such_table", "action": "insert", "data": map[string]any{"x": 1}}},
	})
	assertUnmatchedAPI(t, "transaction on unknown table", rec.Code, rec.Body.String())

	// /api/_query: an unknown table used to answer "unknown table: x".
	rec = crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sid, map[string]any{"table": "no_such_table"})
	assertUnmatchedAPI(t, "query on unknown table", rec.Code, rec.Body.String())

	// Share/permissions on an admin-only table answered 403 to a caller who
	// cannot even list it.
	mux = rebuildTestMux(t, app, true, "http://localhost", func() {
		app.Access.rules["notes"] = map[AccessOp]string{"all": "admin"}
	})
	rec = crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/share", sid, map[string]any{"email": "x@example.com", "permission": "view"})
	assertUnmatchedAPI(t, "share on unreadable table", rec.Code, rec.Body.String())
	rec = crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1/permissions", sid, nil)
	assertUnmatchedAPI(t, "permissions on unreadable table", rec.Code, rec.Body.String())
	rec = crudScopeRequest(t, mux, http.MethodDelete, "/api/notes/1/share/1", sid, nil)
	assertUnmatchedAPI(t, "revoke on unreadable table", rec.Code, rec.Body.String())

	// A readable table keeps its 403 for a row the caller may not share.
	mux = rebuildTestMux(t, app, true, "http://localhost", func() {
		app.Access.rules["notes"] = map[AccessOp]string{"read": "everyone"}
	})
	rec = crudScopeRequest(t, mux, http.MethodPost, "/api/notes/2/share", sid, map[string]any{"email": "x@example.com", "permission": "view"})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("share of another user's row on a readable table = %d %s, want 403", rec.Code, rec.Body.String())
	}
}

// Revert ran no table gate: on an admin-only table it answered
// {"error":"not found"} for a missing row instead of the unmatched 404.
func TestRevertOnUnreadableTableAnswersUnmatched(t *testing.T) {
	app, mux, sid, _ := changedByFixture(t)
	app.Access.rules["notes"] = map[AccessOp]string{"all": "admin"}
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/notes/999/revert/1", sid, nil)
	assertUnmatchedAPI(t, "revert on unreadable table", rec.Code, rec.Body.String())
}
