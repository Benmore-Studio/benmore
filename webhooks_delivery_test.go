//go:build !cli

package main

import (
	"encoding/json"
	"testing"
)

func webhookTestJobPayload(t *testing.T, app *App) map[string]any {
	t.Helper()
	var raw string
	if err := app.DB.QueryRow("SELECT payload FROM _benmore_jobs WHERE job_type = 'webhook_subscription' ORDER BY id DESC LIMIT 1").Scan(&raw); err != nil {
		t.Fatalf("no delivery job queued: %v", err)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(raw), &data); err != nil {
		t.Fatal(err)
	}
	return data
}

// A delivery job re-checks its subscription every time it runs: a
// subscription removed, deactivated or re-pointed after the row change was
// queued (or whose owner lost admin) receives nothing, including retries.
// The job carries neither the signing secret nor hidden columns.
func TestWebhookDeliveryRechecksSubscriptionAndStripsSecrets(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	EnsureJobsTable(app.DB)
	_, _, adminID := loginTestUser(app, "owner@example.com", "admin")
	app.Tables = []Table{{Name: "notes", Columns: []Column{
		{Name: "id", Type: "INTEGER"}, {Name: "title", Type: "TEXT"}, {Name: "api_key", Type: "TEXT"},
	}}}
	const hookURL = "https://hooks.example.invalid/notes"
	res, err := app.DB.Exec("INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (?, ?, 'whsec-signing-secret', 'notes', '')", adminID, hookURL)
	if err != nil {
		t.Fatal(err)
	}
	subID, _ := res.LastInsertId()

	FireWebhookSubscriptions(app, "insert", "notes", map[string]any{"id": 1, "title": "hello", "api_key": "live-credential"}, nil)
	data := webhookTestJobPayload(t, app)
	sub := data["_webhook_subscription"].(map[string]any)
	if _, ok := sub["secret"]; ok {
		t.Fatal("delivery job payload carries the subscription's signing secret")
	}
	row := data["_row"].(map[string]any)
	if _, ok := row["api_key"]; ok || row["title"] != "hello" {
		t.Fatalf("delivery row = %v; want title kept and the hidden api_key column stripped", row)
	}

	// Subscription deleted while the delivery was queued: dropped, no send.
	mustExec(t, app.DB, "DELETE FROM _benmore_webhooks")
	if err := executeWebhookSubscriptionJob(data, app); err != nil {
		t.Fatalf("delivery for a deleted subscription = %v; want a no-op", err)
	}

	restore := func(active int, url string) {
		mustExec(t, app.DB, "DELETE FROM _benmore_webhooks")
		if _, err := app.DB.Exec("INSERT INTO _benmore_webhooks (id, user_id, url, secret, tables, events, active) VALUES (?, ?, ?, 'whsec-signing-secret', 'notes', '', ?)", subID, adminID, url, active); err != nil {
			t.Fatal(err)
		}
	}
	restore(0, hookURL)
	if err := executeWebhookSubscriptionJob(data, app); err != nil {
		t.Fatalf("delivery for an inactive subscription = %v; want a no-op", err)
	}
	restore(1, "https://other.example.invalid/hook")
	if err := executeWebhookSubscriptionJob(data, app); err != nil {
		t.Fatalf("delivery after the subscription URL changed = %v; want a no-op", err)
	}
	restore(1, hookURL)
	mustExec(t, app.DB, "UPDATE _benmore_users SET role = 'user' WHERE email = 'owner@example.com'")
	if err := executeWebhookSubscriptionJob(data, app); err != nil {
		t.Fatalf("delivery for a demoted owner = %v; want a no-op", err)
	}

	// A live subscription still attempts delivery (it fails here only
	// because the .invalid host can't be reached).
	mustExec(t, app.DB, "UPDATE _benmore_users SET role = 'admin' WHERE email = 'owner@example.com'")
	if err := executeWebhookSubscriptionJob(data, app); err == nil {
		t.Fatal("live subscription was dropped instead of attempting delivery")
	}
}

// The transactional update path queues its delivery and audit row inside the
// mutation. It follows the same rules as the post-commit path: no signing
// secret in the job, no hidden columns (or their old_* deltas) in the
// delivery row, and hidden columns recorded in the audit log as changed only.
func TestTransactionalUpdateStripsSecretsFromDeliveryAndAudit(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	EnsureJobsTable(app.DB)
	EnsureAuditLogTable(app.DB)
	_, _, adminID := loginTestUser(app, "owner@example.com", "admin")
	app.Tables = []Table{{Name: "notes", Columns: []Column{
		{Name: "id", Type: "INTEGER"}, {Name: "title", Type: "TEXT"}, {Name: "api_key", Type: "TEXT"},
	}}}
	if _, err := app.DB.Exec("INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (?, 'https://hooks.example.invalid/notes', 'whsec-signing-secret', 'notes', 'update')", adminID); err != nil {
		t.Fatal(err)
	}
	before := map[string]any{"id": 1, "title": "hello", "api_key": "old-credential"}
	after := map[string]any{"id": 1, "title": "hello again", "api_key": "live-credential"}
	event := map[string]any{"id": 1, "title": "hello again", "api_key": "live-credential", "old_title": "hello", "old_api_key": "old-credential"}

	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := enqueueWebhookSubscriptionsTx(tx, app, "update", "notes", event, nil); err != nil {
		t.Fatal(err)
	}
	if err := LogAuditTx(tx, app, "update", "notes", "1", &Session{UserID: adminID, Email: "owner@example.com"}, before, after); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	data := webhookTestJobPayload(t, app)
	if _, ok := data["_webhook_subscription"].(map[string]any)["secret"]; ok {
		t.Fatal("transactional delivery job carries the subscription's signing secret")
	}
	row := data["_row"].(map[string]any)
	_, key := row["api_key"]
	_, oldKey := row["old_api_key"]
	if key || oldKey || row["title"] != "hello again" || row["old_title"] != "hello" {
		t.Fatalf("delivery row = %v; want titles kept and the hidden api_key columns stripped", row)
	}
	if event["api_key"] != "live-credential" || after["api_key"] != "live-credential" {
		t.Fatal("the caller's rows were modified")
	}

	var oldValues, newValues string
	if err := app.DB.QueryRow("SELECT old_values, new_values FROM _benmore_audit_log WHERE table_name = 'notes'").Scan(&oldValues, &newValues); err != nil {
		t.Fatal(err)
	}
	for _, values := range []string{oldValues, newValues} {
		var recorded map[string]any
		if err := json.Unmarshal([]byte(values), &recorded); err != nil {
			t.Fatal(err)
		}
		if recorded["api_key"] != auditHiddenValue {
			t.Fatalf("audit values = %s; want api_key recorded as %q", values, auditHiddenValue)
		}
	}
}
