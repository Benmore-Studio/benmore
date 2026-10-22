//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A record lock answers 409 only to a caller who may edit the row, on every
// write route (PATCH, DELETE, batch, /api/_transaction). The workflow
// transition route checked the lock before the row scope, so a 409 instead of
// a 404 told any signed-in user that another owner's (or tenant's) row exists
// and is being edited right now.
func TestWorkflowTransitionLockDoesNotConfirmInvisibleRow(t *testing.T) {
	app, _ := newAccessScopeFixture(t,
		map[string]map[AccessOp]string{"records": {"all": "self"}},
		`INSERT INTO records (org_id, user_id, title) VALUES (NULL, 1, 'draft')`,
	)
	EnsureLocksTable(app.DB)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	crudScopeMustExec(t, app.DB, `INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at) VALUES ('records', '1', 1, 'alice@example.com', datetime('now', '+1 hour'))`)
	wf := &Workflow{Table: "records", Field: "title", Initial: "draft", Transitions: map[string]map[string]Transition{"draft": {"final": {}}}}

	transition := func(sid string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		r := authzReq("POST", "/api/records/1/transition", sid, `{"to":"final"}`)
		r.SetPathValue("id", "1")
		handleTransition(w, r, app, wf)
		return w
	}
	if w := transition(bob); w.Code != http.StatusNotFound {
		t.Fatalf("a row the caller can't edit must be 404 whether or not it is locked, got %d %s", w.Code, w.Body.String())
	}
	// The lock holder transitions; another editor would still see the 409.
	if w := transition(alice); w.Code != http.StatusOK {
		t.Fatalf("lock holder transition: %d %s", w.Code, w.Body.String())
	}
}
