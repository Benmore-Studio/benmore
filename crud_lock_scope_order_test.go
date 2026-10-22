//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"testing"
)

// A record lock on a row the caller cannot see answered 409 on DELETE, PATCH,
// batch and /api/_transaction, before the row scope said 404 - so the status
// told the caller the row existed (and who held it, in dev mode). Scope is
// checked first now: an invisible row is 404 whether or not it is locked, and
// a lock still blocks a row the caller can see.
func TestRecordLockDoesNotLeakRowsOutsideScope(t *testing.T) {
	app, mux := newAccessScopeFixture(t,
		map[string]map[AccessOp]string{"records": {"all": "self"}},
		`INSERT INTO records (id, org_id, user_id, title) VALUES
			(1, 'org-a', 1, 'alice-own'),
			(2, 'org-a', 2, 'bob-own')`,
	)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "org-a", "")
	_ = createCrudScopeSession(t, app, "bob@example.com", "user", "org-a", "")
	// Bob holds a lock on his own row 2 and on alice's row 1.
	for _, id := range []int{1, 2} {
		crudScopeMustExec(t, app.DB, fmt.Sprintf(`INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at)
			VALUES ('records', '%d', 2, 'bob@example.com', datetime('now', '+1 hour'))`, id))
	}

	assertStatus(t, mux, http.MethodDelete, "/api/records/2", alice, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPatch, "/api/records/2", alice, map[string]any{"title": "x"}, http.StatusNotFound)
	for _, c := range []struct {
		method string
		body   map[string]any
	}{
		{http.MethodPatch, map[string]any{"ids": []any{2}, "fields": map[string]any{"title": "x"}}},
		{http.MethodDelete, map[string]any{"ids": []any{2}}},
	} {
		if rec := crudScopeRequest(t, mux, c.method, "/api/records/batch", alice, c.body); rec.Code == http.StatusConflict {
			t.Errorf("%s batch on an invisible locked row = 409 (leaks it): %s", c.method, rec.Body.String())
		}
	}
	for _, action := range []string{"update", "delete"} {
		rec := crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", alice, map[string]any{
			"operations": []any{map[string]any{"table": "records", "action": action, "id": 2, "data": map[string]any{"title": "x"}}},
		})
		if rec.Code == http.StatusConflict {
			t.Errorf("transaction %s on an invisible locked row = 409 (leaks it): %s", action, rec.Body.String())
		}
	}
	assertRecordTitle(t, app.DB, 2, "bob-own")
	assertRowExists(t, app.DB, "records", 2, true)

	// A lock still binds a row the caller can see.
	assertStatus(t, mux, http.MethodDelete, "/api/records/1", alice, nil, http.StatusConflict)
	assertStatus(t, mux, http.MethodPatch, "/api/records/1", alice, map[string]any{"title": "x"}, http.StatusConflict)
	assertStatus(t, mux, http.MethodPatch, "/api/records/batch", alice, map[string]any{"ids": []any{1}, "fields": map[string]any{"title": "x"}}, http.StatusConflict)
	assertStatus(t, mux, http.MethodDelete, "/api/records/batch", alice, map[string]any{"ids": []any{1}}, http.StatusConflict)
	assertStatus(t, mux, http.MethodPost, "/api/_transaction", alice, map[string]any{
		"operations": []any{map[string]any{"table": "records", "action": "delete", "id": 1}},
	}, http.StatusConflict)
	assertRecordTitle(t, app.DB, 1, "alice-own")
}
