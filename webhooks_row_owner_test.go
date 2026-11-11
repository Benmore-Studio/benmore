//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// newWebhookOwnerApp serves an app with an owned `tickets` table (user_id and
// user_email are its own columns), a `notes` table with neither column, and
// an active admin subscription to both. admin is user 1, alice user 2; alice
// owns tickets 1-4.
func newWebhookOwnerApp(t *testing.T) (app *App, mux *http.ServeMux, admin string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, user_email TEXT, title TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`)
	app = &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Tables: []Table{
			{Name: "tickets", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "user_email"}, {Name: "title"}}},
			{Name: "notes", Columns: []Column{{Name: "id"}, {Name: "title"}}},
		},
	}
	admin = createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	EnsureWebhooksTable(db)
	EnsureJobsTable(db)
	EnsureAuditLogTable(db)
	crudScopeMustExec(t, db, `INSERT INTO tickets (id, user_id, user_email, title) VALUES
		(1, 2, 'alice@example.com', 'one'), (2, 2, 'alice@example.com', 'two'),
		(3, 2, 'alice@example.com', 'three'), (4, 2, 'alice@example.com', 'four')`)
	crudScopeMustExec(t, db, `INSERT INTO notes (id, title) VALUES (1, 'note')`)
	crudScopeMustExec(t, db, `INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (1, 'https://hooks.example.invalid/x', 'whsec-signing-secret', 'tickets,notes', '')`)
	t.Cleanup(app.Shutdown)
	return app, buildAppMux(app, true, "http://localhost"), admin
}

// webhookJobsAfter returns the subscription delivery jobs queued after id.
func webhookJobsAfter(t *testing.T, app *App, after int64) (rows []map[string]any, last int64) {
	t.Helper()
	jobs, err := app.DB.Query("SELECT id, payload FROM _benmore_jobs WHERE job_type = 'webhook_subscription' AND id > ? ORDER BY id", after)
	if err != nil {
		t.Fatal(err)
	}
	defer jobs.Close()
	last = after
	for jobs.Next() {
		var raw string
		if err := jobs.Scan(&last, &raw); err != nil {
			t.Fatal(err)
		}
		data := map[string]any{}
		if err := json.Unmarshal([]byte(raw), &data); err != nil {
			t.Fatal(err)
		}
		row, err := openJobPayloadRow(app, data, valueText(data["_webhook_subscription"].(map[string]any)["table"]))
		if err != nil {
			t.Fatal(err)
		}
		row["_meta_user_id"] = data["_webhook_subscription"].(map[string]any)["user_id"]
		rows = append(rows, row)
	}
	return rows, last
}

// A subscription's `data` is the changed row: an admin editing or deleting
// alice's ticket must not make the delivery say the admin owns it. Before,
// injectSessionContext overwrote user_id/user_email with the actor's for hook
// SQL and the same map was delivered, so a receiver saw `"user_id":1,
// "old_user_id":2` while the database still said 2. A table without those
// columns keeps the actor fields, as documented.
func TestWebhookSubscriptionDataKeepsRowOwnColumns(t *testing.T) {
	app, mux, admin := newWebhookOwnerApp(t)
	var last int64
	expect := func(name string, want map[string]any) {
		t.Helper()
		var rows []map[string]any
		rows, last = webhookJobsAfter(t, app, last)
		if len(rows) != 1 {
			t.Fatalf("%s: %d delivery jobs queued, want 1", name, len(rows))
		}
		for k, v := range want {
			if valueText(rows[0][k]) != valueText(v) {
				t.Fatalf("%s: data.%s = %v, want %v (row %v)", name, k, rows[0][k], v, rows[0])
			}
		}
		if valueText(rows[0]["_meta_user_id"]) != "1" {
			t.Fatalf("%s: queued actor id = %v, want the admin (1)", name, rows[0]["_meta_user_id"])
		}
	}

	assertStatus(t, mux, http.MethodPatch, "/api/tickets/1", admin, map[string]any{"title": "edited"}, http.StatusOK)
	expect("PATCH", map[string]any{"user_id": 2, "old_user_id": 2, "user_email": "alice@example.com", "title": "edited"})

	assertStatus(t, mux, http.MethodDelete, "/api/tickets/2", admin, nil, http.StatusOK)
	expect("DELETE", map[string]any{"user_id": 2, "user_email": "alice@example.com"})

	assertStatus(t, mux, http.MethodPost, "/api/tickets", admin, map[string]any{"title": "new", "user_email": "carol@example.com"}, http.StatusOK)
	expect("POST", map[string]any{"user_id": 1, "user_email": "carol@example.com"})

	assertStatus(t, mux, http.MethodPost, "/api/tickets/batch", admin, []map[string]any{{"title": "batched", "user_email": "dave@example.com"}}, http.StatusOK)
	expect("batch create", map[string]any{"user_email": "dave@example.com"})

	assertStatus(t, mux, http.MethodPatch, "/api/tickets/batch", admin, map[string]any{"ids": []any{3}, "fields": map[string]any{"title": "batch-edited"}}, http.StatusOK)
	expect("batch update", map[string]any{"user_id": 2, "user_email": "alice@example.com", "title": "batch-edited"})

	assertStatus(t, mux, http.MethodDelete, "/api/tickets/batch", admin, map[string]any{"ids": []any{3}}, http.StatusOK)
	expect("batch delete", map[string]any{"user_id": 2, "user_email": "alice@example.com"})

	assertStatus(t, mux, http.MethodPost, "/api/_transaction", admin, map[string]any{"operations": []any{
		map[string]any{"table": "tickets", "action": "delete", "id": 4},
	}}, http.StatusOK)
	expect("transaction delete", map[string]any{"user_id": 2, "user_email": "alice@example.com"})

	// No user_id/user_email columns: the actor fields stay in data.
	assertStatus(t, mux, http.MethodPatch, "/api/notes/1", admin, map[string]any{"title": "edited"}, http.StatusOK)
	expect("PATCH notes", map[string]any{"user_id": 1, "user_email": "admin@example.com", "user_role": "admin", "title": "edited"})
}

// A workflow transition queues its delivery inside the transition
// transaction; the row's owner survives there too.
func TestWebhookSubscriptionTransitionKeepsRowOwner(t *testing.T) {
	app, wf, cleanup := newWorkflowTenantApp(t)
	defer cleanup()
	owner := workflowTestUser(t, app, "owner@example.test")
	mustExec(t, app.DB, "UPDATE _benmore_users SET role = 'admin' WHERE id = 1")
	operator := workflowTestUser(t, app, "operator@example.test")
	addMember(t, app, "A", operator, "approver")
	mustExecArgs(t, app.DB, "INSERT INTO orders (id, org_id, user_id, status) VALUES (1, 'A', ?, 'pending')", owner)
	mustExecArgs(t, app.DB, "INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (?, 'https://hooks.example.invalid/x', 'whsec-signing-secret', 'orders', '')", owner)
	sid := CreateSession(app.DB, operator, "operator@example.test", "A", time.Hour)
	if res := transitionAs(app, wf, sid, "1", "approved"); res.Code != http.StatusOK {
		t.Fatalf("transition = %d %s", res.Code, res.Body.String())
	}
	rows, _ := webhookJobsAfter(t, app, 0)
	if len(rows) != 1 {
		t.Fatalf("%d delivery jobs, want 1", len(rows))
	}
	if valueText(rows[0]["user_id"]) != valueText(owner) || valueText(rows[0]["old_user_id"]) != valueText(owner) {
		t.Fatalf("transition delivery user_id = %v (old %v), want the owner %d", rows[0]["user_id"], rows[0]["old_user_id"], owner)
	}
	if valueText(rows[0]["_meta_user_id"]) != valueText(operator) {
		t.Fatalf("queued actor id = %v, want the operator %d", rows[0]["_meta_user_id"], operator)
	}
}

// The actor is on the envelope: triggered_by (email) and
// triggered_by_user_id, read from the queued job like the delivery does.
func TestWebhookSubscriptionEnvelopeNamesActor(t *testing.T) {
	app, mux, admin := newWebhookOwnerApp(t)
	assertStatus(t, mux, http.MethodPatch, "/api/tickets/1", admin, map[string]any{"title": "edited"}, http.StatusOK)
	data := webhookTestJobPayload(t, app)
	row, err := openJobPayloadRow(app, data, "tickets")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(webhookSubscriptionBody(data["_webhook_subscription"].(map[string]any), "update", "tickets", row, time.Now()))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		TriggeredBy       string         `json:"triggered_by"`
		TriggeredByUserID json.Number    `json:"triggered_by_user_id"`
		Data              map[string]any `json:"data"`
	}
	if err := json.Unmarshal(encoded, &body); err != nil {
		t.Fatal(err)
	}
	if body.TriggeredBy != "admin@example.com" || body.TriggeredByUserID.String() != "1" {
		t.Fatalf("envelope actor = %q / %q, want admin@example.com / 1 (%s)", body.TriggeredBy, body.TriggeredByUserID, encoded)
	}
	if valueText(body.Data["user_id"]) != "2" || valueText(body.Data["old_user_id"]) != "2" {
		t.Fatalf("envelope data user_id = %v (old %v), want the owner 2 (%s)", body.Data["user_id"], body.Data["old_user_id"], encoded)
	}

	// A sessionless change names no actor.
	sessionless := webhookSubscriptionBody(map[string]any{"webhook_id": "1"}, "insert", "notes", map[string]any{"id": 1}, time.Now())
	if _, ok := sessionless["triggered_by"]; ok {
		t.Fatalf("sessionless envelope = %v; want no triggered_by", sessionless)
	}
	if _, ok := sessionless["triggered_by_user_id"]; ok {
		t.Fatalf("sessionless envelope = %v; want no triggered_by_user_id", sessionless)
	}
}
