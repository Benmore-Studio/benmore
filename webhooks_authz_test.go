//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A non-admin end user must not be able to subscribe to the app's row
// changes: a subscription receives every tenant's data.
func TestWebhookCreateRequiresAdmin(t *testing.T) {
	oldKey := appEncryptionKey
	appEncryptionKey = make([]byte, 32) // secrets are encrypted at rest; fail-closed without a key
	t.Cleanup(func() { appEncryptionKey = oldKey })
	app, done := newTestApp(t)
	defer done()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	mux := http.NewServeMux()
	RegisterWebhookRoutes(mux, app)
	_, userToken, _ := loginTestUser(app, "member@example.com", "user")
	_, adminToken, _ := loginTestUser(app, "owner@example.com", "admin")
	post := func(token string) int {
		req := httptest.NewRequest("POST", "/api/_webhooks", strings.NewReader(`{"url":"https://example.com/hook","secret":"s3cret"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := post(userToken); code != http.StatusForbidden {
		t.Fatalf("non-admin webhook create = %d, want 403", code)
	}
	if code := post(adminToken); code != http.StatusCreated {
		t.Fatalf("admin webhook create = %d, want 201", code)
	}
}

// Subscriptions whose owner is not (or no longer) an active admin never
// receive deliveries, including ones created before the create-time check.
func TestWebhookDeliveryRequiresActiveAdminOwner(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	_, _, memberID := loginTestUser(app, "member@example.com", "user")
	_, _, adminID := loginTestUser(app, "owner@example.com", "admin")
	_, _, exAdminID := loginTestUser(app, "former@example.com", "admin")
	mustExec(t, app.DB, "UPDATE _benmore_users SET deactivated_at = '2026-09-01' WHERE email = 'former@example.com'")
	if webhookOwnerIsActiveAdmin(app, memberID) {
		t.Fatal("member must not qualify as a webhook owner")
	}
	if !webhookOwnerIsActiveAdmin(app, adminID) {
		t.Fatal("active admin must qualify")
	}
	if webhookOwnerIsActiveAdmin(app, exAdminID) {
		t.Fatal("deactivated admin must not keep receiving data")
	}
	if webhookOwnerIsActiveAdmin(app, int64(999999)) || webhookOwnerIsActiveAdmin(app, nil) {
		t.Fatal("unknown owner must not qualify")
	}
}

// A subscription delivery is a response leaving the app. It shipped every
// column of the changed row, including the hidden ones no API read returns
// (`*_secret`, `*_token`) and their old_* deltas, to the subscriber's URL,
// and parked them in the job queue on the way.
func TestWebhookPayloadOmitsHiddenColumns(t *testing.T) {
	app, done := newTestApp(t)
	defer done()
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	EnsureJobsTable(app.DB)
	_, _, adminID := loginTestUser(app, "owner@example.com", "admin")
	app.Tables = []Table{{Name: "integrations", Columns: []Column{
		{Name: "id"}, {Name: "user_id"}, {Name: "name", Type: "TEXT"}, {Name: "api_secret", Type: "TEXT"}, {Name: "refresh_token", Type: "TEXT"},
	}}}
	if _, err := app.DB.Exec("INSERT INTO _benmore_webhooks (user_id, url, secret) VALUES (?, 'https://hooks.example.com/x', 's')", adminID); err != nil {
		t.Fatal(err)
	}
	row := map[string]any{"id": 1, "name": "stripe2", "api_secret": "sk-new-secret", "refresh_token": "rt-new",
		"old_api_secret": "sk-old-secret", "old_name": "stripe"}
	FireWebhookSubscriptions(app, "update", "integrations", row, &Session{UserID: adminID, Email: "owner@example.com"})

	var payload string
	if err := app.DB.QueryRow("SELECT payload FROM _benmore_jobs WHERE job_type = 'webhook_subscription'").Scan(&payload); err != nil {
		t.Fatalf("no delivery queued: %v", err)
	}
	for _, secret := range []string{"sk-new-secret", "sk-old-secret", "rt-new", "api_secret", "refresh_token"} {
		if strings.Contains(payload, secret) {
			t.Errorf("webhook payload carries hidden %q: %s", secret, payload)
		}
	}
	for _, want := range []string{`"name":"stripe2"`, `"old_name":"stripe"`} {
		if !strings.Contains(payload, want) {
			t.Errorf("webhook payload lost %s: %s", want, payload)
		}
	}
	if row["api_secret"] != "sk-new-secret" {
		t.Fatal("caller's row was modified")
	}
}
