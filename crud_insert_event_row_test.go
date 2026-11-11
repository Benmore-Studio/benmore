//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newInsertEventApp serves an `orders` table with defaulted columns, a hidden
// credential column, an after-insert hook posting the default body and an
// admin's webhook subscription. It returns the admin's bearer token.
func newInsertEventApp(t *testing.T) (*App, *http.ServeMux, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT,
		amount_cents INTEGER, status TEXT NOT NULL DEFAULT 'new', api_key TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Tables: []Table{{Name: "orders", Columns: []Column{
			{Name: "id", Type: "INTEGER"}, {Name: "user_id", Type: "INTEGER"}, {Name: "title", Type: "TEXT"},
			{Name: "amount_cents", Type: "INTEGER"}, {Name: "status", Type: "TEXT"}, {Name: "api_key", Type: "TEXT"},
			{Name: "created_at", Type: "DATETIME"}, {Name: "updated_at", Type: "DATETIME"},
		}}},
		Hooks: &HookConfig{OnInsert: map[string][]Hook{"orders": {{Webhook: "https://hooks.example.invalid/orders"}}}},
	}
	admin := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	EnsureWebhooksTable(db)
	EnsureJobsTable(db)
	EnsureAuditLogTable(db)
	EnsureIdempotencyTable(db)
	crudScopeMustExec(t, db, `INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (1, 'https://hooks.example.invalid/x', 'whsec-signing-secret', 'orders', '')`)
	t.Cleanup(app.Shutdown)
	return app, buildAppMux(app, true, "http://localhost"), admin
}

// lastJobRow is the row of the newest job of a type, as delivery reads it.
func lastJobRow(t *testing.T, app *App, jobType string) (map[string]any, string) {
	t.Helper()
	var raw string
	if err := app.DB.QueryRow("SELECT payload FROM _benmore_jobs WHERE job_type = ? ORDER BY id DESC LIMIT 1", jobType).Scan(&raw); err != nil {
		t.Fatalf("no %s job queued: %v", jobType, err)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		t.Fatal(err)
	}
	row, err := openJobPayloadRow(app, data, "orders")
	if err != nil {
		t.Fatal(err)
	}
	return row, raw
}

// A create's insert event is the row as stored, like an update event: typed
// values, the columns the database filled in, and none of the internal
// session flags. It used to be the submitted fields as text
// ("amount_cents":"2500"), without status/created_at/updated_at, plus
// "user_admin_bypass" and "user_act_as_group_id", sent to third parties.
func TestCreateInsertEventCarriesStoredRow(t *testing.T) {
	app, mux, admin := newInsertEventApp(t)
	assertStatus(t, mux, http.MethodPost, "/api/orders", admin, map[string]any{"title": "first", "amount_cents": 2500, "api_key": "live-credential"}, http.StatusOK)

	for _, jobType := range []string{"webhook_subscription", "hook"} {
		row, raw := lastJobRow(t, app, jobType)
		if strings.Contains(raw, `"amount_cents":"2500"`) {
			t.Fatalf("%s payload carries amount_cents as text: %s", jobType, raw)
		}
		if _, isText := row["amount_cents"].(string); isText || valueText(row["amount_cents"]) != "2500" {
			t.Fatalf("%s amount_cents = %#v, want the number 2500", jobType, row["amount_cents"])
		}
		if row["status"] != "new" || valueText(row["created_at"]) == "" || valueText(row["updated_at"]) == "" {
			t.Fatalf("%s row lacks the defaulted columns: %v", jobType, row)
		}
	}

	// What leaves the app: the subscription's data and the hook's default body.
	subscription, _ := lastJobRow(t, app, "webhook_subscription")
	sent := webhookSubscriptionBody(map[string]any{"webhook_id": "1"}, "insert", "orders", subscription, time.Now())
	hookRow, _ := lastJobRow(t, app, "hook")
	var hookBody map[string]any
	if err := json.Unmarshal([]byte(hookDefaultBody(app, "orders", hookRow)), &hookBody); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]map[string]any{"subscription data": sent["data"].(map[string]any), "hook default body": hookBody} {
		for _, internal := range []string{"user_admin_bypass", "user_act_as_group_id", "api_key"} {
			if _, ok := data[internal]; ok {
				t.Fatalf("%s carries %s: %v", name, internal, data)
			}
		}
		if data["status"] != "new" || data["title"] != "first" {
			t.Fatalf("%s = %v, want the stored row", name, data)
		}
	}
	// The hook keeps the actor's session keys and the flags for its own SQL.
	if hookRow["user_email"] != "admin@example.com" || hookRow["user_admin_bypass"] != true {
		t.Fatalf("hook row lost its session context: %v", hookRow)
	}

	// An update's subscription data drops the flags too.
	assertStatus(t, mux, http.MethodPatch, "/api/orders/1", admin, map[string]any{"title": "edited"}, http.StatusOK)
	updated := webhookSubscriptionBody(map[string]any{"webhook_id": "1"}, "update", "orders", func() map[string]any { r, _ := lastJobRow(t, app, "webhook_subscription"); return r }(), time.Now())
	if data := updated["data"].(map[string]any); data["title"] != "edited" || data["user_admin_bypass"] != nil || data["user_act_as_group_id"] != nil {
		t.Fatalf("update data = %v", data)
	}
}

func idempotentBatch(t *testing.T, mux *http.ServeMux, token, key string, body any) *httptest.ResponseRecorder {
	t.Helper()
	data, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/orders/batch", bytes.NewReader(data))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	if key != "" {
		req.Header.Set("X-Idempotency-Key", key)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// X-Idempotency-Key on a batch create works like on a single create: the
// retry answers the first response and inserts nothing; a different body
// with the same key is refused. It used to be ignored, so two identical
// batches inserted every row twice.
func TestBatchCreateHonoursIdempotencyKey(t *testing.T) {
	app, mux, admin := newInsertEventApp(t)
	count := func() int {
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM orders").Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	batch := []map[string]any{{"title": "a"}, {"title": "b"}}
	first := idempotentBatch(t, mux, admin, "batch-key-1", batch)
	if first.Code != http.StatusOK || count() != 2 {
		t.Fatalf("first batch = %d %s (rows %d)", first.Code, first.Body.String(), count())
	}
	retry := idempotentBatch(t, mux, admin, "batch-key-1", batch)
	if retry.Code != http.StatusOK || retry.Body.String() != first.Body.String() {
		t.Fatalf("retry = %d %q, want the first answer %q", retry.Code, retry.Body.String(), first.Body.String())
	}
	if n := count(); n != 2 {
		t.Fatalf("a retried batch inserted again: %d rows, want 2", n)
	}
	changed := idempotentBatch(t, mux, admin, "batch-key-1", []map[string]any{{"title": "c"}})
	if changed.Code != http.StatusConflict || count() != 2 {
		t.Fatalf("same key, different body = %d %s (rows %d), want 409", changed.Code, changed.Body.String(), count())
	}
	// No key: every batch inserts.
	if rec := idempotentBatch(t, mux, admin, "", batch); rec.Code != http.StatusOK || count() != 4 {
		t.Fatalf("keyless batch = %d (rows %d)", rec.Code, count())
	}
	// A key longer than a single create accepts is refused.
	if rec := idempotentBatch(t, mux, admin, strings.Repeat("k", 257), batch); rec.Code != http.StatusBadRequest || count() != 4 {
		t.Fatalf("over-long key = %d (rows %d)", rec.Code, count())
	}
}
