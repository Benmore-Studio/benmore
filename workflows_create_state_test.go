//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A new row may start only in its workflow's initial state. Updates already
// can't set the state column; without the create-side rule a caller could
// create an order directly in `approved`, a state only an approver can
// transition to.
func TestWorkflowStateOnCreateIsInitialOnly(t *testing.T) {
	app, _, cleanup := newWorkflowTenantApp(t)
	defer cleanup()
	uid := workflowTestUser(t, app, "creator@example.com")
	addMember(t, app, "A", uid, "member")
	sid := CreateSession(app.DB, uid, "creator@example.com", "A", 0)

	send := func(handler func(http.ResponseWriter, *http.Request, *App, string), method, ct, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "https://app.example.com/api/orders", strings.NewReader(body))
		r.Header.Set("Content-Type", ct)
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		handler(w, r, app, "orders")
		return w
	}
	statuses := func() map[string]int {
		out := map[string]int{}
		rows, err := app.DB.Query("SELECT COALESCE(status, '') FROM orders")
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		for rows.Next() {
			var s string
			rows.Scan(&s)
			out[s]++
		}
		return out
	}

	send(handleCreate, "POST", "application/x-www-form-urlencoded", url.Values{"status": {"approved"}}.Encode())
	send(handleCreate, "POST", "application/x-www-form-urlencoded", url.Values{"status": {"pending"}}.Encode())
	send(handleBatchCreate, "POST", "application/json", `[{"status":"approved"},{"status":"pending"}]`)
	send(handleStreamingIngest, "POST", "application/x-ndjson", "{\"status\":\"approved\"}\n")
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	session := GetSessionFromDB(app.DB, sid)
	if _, err := txInsert(tx, app, "orders", map[string]any{"status": "approved"}, session); err != nil {
		t.Fatal(err)
	}
	if _, err := txInsert(tx, app, "orders", map[string]any{"status": "pending"}, session); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	got := statuses()
	if got["approved"] != 0 {
		t.Fatalf("a create placed rows directly in a guarded state: %v", got)
	}
	if got["pending"] != 3 {
		t.Fatalf("the declared initial state must still be accepted on create (single, batch, tx): %v", got)
	}
}
