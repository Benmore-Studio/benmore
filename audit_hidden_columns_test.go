//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// Audit old/new values carried hidden columns (`*_secret`, `*_token`, their
// `old_*` change deltas) in plaintext, and /api/_audit, get_audit_log and the
// audit shipper hand those values out. They are recorded as changed, never by
// value.
func TestAuditLogRedactsHiddenColumns(t *testing.T) {
	app, mux, admin, cleanup := adminPanelApp(t)
	defer cleanup()
	EnsureAuditLogTable(app.DB)
	app.Tables = append(app.Tables, Table{Name: "integrations", Columns: []Column{
		{Name: "id"}, {Name: "user_id"}, {Name: "name", Type: "TEXT"}, {Name: "api_secret", Type: "TEXT"}, {Name: "refresh_token", Type: "TEXT"},
	}})
	oldRow := map[string]any{"id": 1, "name": "stripe", "api_secret": "sk-old-secret", "refresh_token": "rt-old"}
	newRow := map[string]any{"id": 1, "name": "stripe2", "api_secret": "sk-new-secret", "refresh_token": "rt-new",
		"old_api_secret": "sk-old-secret", "old_name": "stripe"}
	LogAudit(app, "update", "integrations", "1", &Session{UserID: 1, Email: "boss@example.com"}, oldRow, newRow)
	LogAudit(app, "update", "_benmore_users", "2", &Session{UserID: 1, Email: "boss@example.com"},
		map[string]any{"password_hash": "$2a$12$hashvalue", "email": "victim@example.com"}, nil)

	if newRow["api_secret"] != "sk-new-secret" || oldRow["refresh_token"] != "rt-old" {
		t.Fatalf("LogAudit modified the caller's rows: %v %v", oldRow, newRow)
	}
	rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_audit", admin, nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/_audit: %d %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, secret := range []string{"sk-old-secret", "sk-new-secret", "rt-old", "rt-new", "hashvalue"} {
		if strings.Contains(body, secret) {
			t.Errorf("audit log serves hidden value %q: %s", secret, body)
		}
	}
	for _, want := range []string{"stripe2", `\"old_name\":\"stripe\"`, `\"api_secret\":\"[hidden]\"`, `\"old_api_secret\":\"[hidden]\"`, "victim@example.com"} {
		if !strings.Contains(body, want) {
			t.Errorf("audit log lost %s: %s", want, body)
		}
	}
}
