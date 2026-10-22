//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// A table that exists in the database but not in the loaded schema (a model
// removed from schema.prisma, or a table a migration created) still gets
// auto-CRUD routes. The framework knows none of its columns, so a mode that
// scopes rows by them (self, group, member-of, owner_or_role) has nothing to
// scope with and must not read as "every row".
func TestScopedModeOnSchemaUnknownTableFailsClosed(t *testing.T) {
	for _, mode := range []string{"self", "group"} {
		t.Run(mode, func(t *testing.T) {
			app, mux := newAccessScopeFixture(t,
				map[string]map[AccessOp]string{"default": {"all": mode}},
				`CREATE TABLE legacy_notes (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, user_id INTEGER, body TEXT)`,
				`INSERT INTO legacy_notes (org_id, user_id, body) VALUES ('org-a', 1, 'alice-private'), ('org-b', 2, 'bob-own')`,
			)
			_ = createCrudScopeSession(t, app, "alice@example.com", "user", "org-a", "")
			bob := createCrudScopeSession(t, app, "bob@example.com", "user", "org-b", "")
			mux = buildAppMux(app, true, "http://localhost")

			rec := crudScopeRequest(t, mux, http.MethodGet, "/api/legacy_notes", bob, nil)
			if rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "alice-private") {
				t.Fatalf("%s mode on a schema-unknown table read another tenant's/owner's row: %s", mode, rec.Body.String())
			}
			rec = crudScopeRequest(t, mux, http.MethodPatch, "/api/legacy_notes/1", bob, map[string]any{"body": "overwritten"})
			var body string
			if err := app.DB.QueryRow("SELECT body FROM legacy_notes WHERE id = 1").Scan(&body); err != nil || body != "alice-private" {
				t.Fatalf("%s mode on a schema-unknown table let another user update the row (status %d): body=%q", mode, rec.Code, body)
			}
		})
	}
}
