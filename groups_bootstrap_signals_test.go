//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// bootstrapHookRows returns the rows of the on_insert hook jobs queued for
// table, decoded from their durable payloads.
func bootstrapHookRows(t *testing.T, app *App, table string) []map[string]any {
	t.Helper()
	rows, err := app.DB.Query("SELECT payload FROM _benmore_jobs WHERE job_type = 'hook' ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var payload struct {
			Hook map[string]any `json:"_hook"`
			Row  map[string]any `json:"_row"`
		}
		if err := json.Unmarshal([]byte(raw), &payload); err != nil {
			t.Fatalf("hook payload %q: %v", raw, err)
		}
		if payload.Hook["table"] == table {
			out = append(out, payload.Row)
		}
	}
	return out
}

// The founding membership POST /api/_groups/create writes is a row insert
// like any other: it fired no hooks.yaml on_insert hook, no on_insert event
// flow, no webhook subscription and no realtime event (only the org insert
// did), so an app that provisions per-member state from those signals never
// did it for the founder. Its audit row had an empty row_id and left out the
// granted role.
func TestGroupBootstrapMembershipEmitsInsertSignals(t *testing.T) {
	app, uid, cleanup := newBootstrapTestApp(t, "email")
	defer cleanup()
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE member_log (member_id INTEGER, company_id INTEGER, role TEXT)")
	for _, name := range []string{"companies", "company_members"} {
		cols, err := GetTableColumns(app.DB, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	app.Hooks = &HookConfig{OnInsert: map[string][]Hook{
		"companies":       {{SQL: "SELECT 1"}},
		"company_members": {{SQL: "SELECT 1"}},
	}}
	app.Flows = []Flow{{
		Name:    "provision-member",
		Trigger: FlowTrigger{Type: "on_insert", Table: "company_members"},
		Steps:   []FlowStep{{Type: "sql", SQL: "INSERT INTO member_log (member_id, company_id, role) VALUES (:id, :company_id, :member_role)"}},
	}}
	admin := createCrudScopeSession(t, app, "boss@example.com", "admin", "", "")
	var adminID int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = 'boss@example.com'").Scan(&adminID); err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, "INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES ("+itoaInt(adminID)+", 'https://hooks.example.com/in', 'whsec', 'companies,company_members', 'insert')")
	watcher := subscribeFlowRealtime(t, app, admin)

	sid := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour)
	w := bootstrapAs(app, sid, `{"name":"Acme"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	var orgID, memberID int64
	if err := app.DB.QueryRow("SELECT id FROM companies").Scan(&orgID); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT id FROM company_members").Scan(&memberID); err != nil {
		t.Fatal(err)
	}

	// Audit: one row per insert, each naming its row and every value written.
	auditRow := func(table string) (string, map[string]any) {
		t.Helper()
		var rowID, newValues string
		if err := app.DB.QueryRow("SELECT row_id, new_values FROM _benmore_audit_log WHERE action = 'insert' AND table_name = ?", table).Scan(&rowID, &newValues); err != nil {
			t.Fatalf("audit row for %s: %v", table, err)
		}
		var values map[string]any
		if err := json.Unmarshal([]byte(newValues), &values); err != nil {
			t.Fatalf("audit values for %s: %v", table, err)
		}
		return rowID, values
	}
	if rowID, values := auditRow("companies"); rowID != itoaInt(orgID) || values["name"] != "Acme" {
		t.Fatalf("org audit row_id=%q values=%v", rowID, values)
	}
	rowID, values := auditRow("company_members")
	if rowID != itoaInt(memberID) {
		t.Fatalf("membership audit row_id = %q, want the membership id %d", rowID, memberID)
	}
	for k, want := range map[string]any{"id": float64(memberID), "company_id": float64(orgID), "email": "founder@example.com", "member_role": "company_admin", "user_id": float64(uid)} {
		if values[k] != want {
			t.Fatalf("membership audit %s = %v, want %v (values %v)", k, values[k], want, values)
		}
	}

	// hooks.yaml on_insert: queued for both tables, the membership hook with
	// the row and the session context in the new tenant.
	if n := len(bootstrapHookRows(t, app, "companies")); n != 1 {
		t.Fatalf("org on_insert hooks queued: %d, want 1", n)
	}
	hooks := bootstrapHookRows(t, app, "company_members")
	if len(hooks) != 1 {
		t.Fatalf("membership on_insert hooks queued: %d, want 1", len(hooks))
	}
	for k, want := range map[string]any{"id": float64(memberID), "member_role": "company_admin", "user_group_id": itoaInt(orgID), "user_email": "founder@example.com"} {
		if hooks[0][k] != want {
			t.Fatalf("membership hook row %s = %v, want %v (row %v)", k, hooks[0][k], want, hooks[0])
		}
	}

	// Webhook subscriptions: one delivery per table.
	for _, table := range []string{"companies", "company_members"} {
		var n int
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE job_type = 'webhook_subscription' AND payload LIKE ?", `%"table":"`+table+`"%`).Scan(&n)
		if n != 1 {
			t.Fatalf("webhook subscription deliveries for %s: %d, want 1", table, n)
		}
	}

	// Realtime: an admin watching both tables hears of both inserts.
	sse, _ := watcher.drain()
	got := strings.Join(sse, " ")
	for _, table := range []string{"companies", "company_members"} {
		if !strings.Contains(got, `{"table":"`+table+`","action":"insert"}`) {
			t.Fatalf("realtime events %q lack the %s insert", got, table)
		}
	}

	// on_insert event flow on the membership table ran with its row.
	deadline := time.Now().Add(5 * time.Second)
	for {
		var gotID, gotOrg int64
		var role string
		err := app.DB.QueryRow("SELECT member_id, company_id, role FROM member_log").Scan(&gotID, &gotOrg, &role)
		if err == nil {
			if gotID != memberID || gotOrg != orgID || role != "company_admin" {
				t.Fatalf("event flow saw member %d org %d role %q", gotID, gotOrg, role)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("on_insert flow on the membership table never ran: %v", err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// Both audit rows are written inside the bootstrap transaction: when the
// membership's audit row cannot be stored, neither row commits (before, the
// audit rows were written after commit and a failure left an unaudited
// tenant behind).
func TestGroupBootstrapAuditCommitsWithTheRows(t *testing.T) {
	app, uid, cleanup := newBootstrapTestApp(t, "user_id")
	defer cleanup()
	mustExec(t, app.DB, "CREATE TRIGGER membership_audit_fails BEFORE INSERT ON _benmore_audit_log WHEN NEW.table_name = 'company_members' BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END")

	sid := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour)
	w := bootstrapAs(app, sid, `{"name":"Acme"}`)
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "audit write failed") {
		t.Fatalf("bootstrap with an unwritable audit row: %d %s", w.Code, w.Body.String())
	}
	if n := countRows(t, app, "companies") + countRows(t, app, "company_members") + countRows(t, app, "_benmore_audit_log"); n != 0 {
		t.Fatalf("a bootstrap whose audit failed left %d rows", n)
	}
	var group string
	app.DB.QueryRow("SELECT COALESCE(group_id, '') FROM _benmore_sessions").Scan(&group)
	if group != "" {
		t.Fatalf("session attached to a tenant that was rolled back: %q", group)
	}

	// Once the audit log accepts the row, the same request succeeds and the
	// one-group check inside the transaction still refuses a second tenant.
	mustExec(t, app.DB, "DROP TRIGGER membership_audit_fails")
	if w := bootstrapAs(app, sid, `{"name":"Acme"}`); w.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	mustExec(t, app.DB, "UPDATE _benmore_sessions SET group_id = NULL")
	if w := bootstrapAs(app, sid, `{"name":"Second"}`); w.Code != http.StatusConflict {
		t.Fatalf("second bootstrap must be 409, got %d: %s", w.Code, w.Body.String())
	}
	if n := countRows(t, app, "_benmore_audit_log"); n != 2 {
		t.Fatalf("audit rows after one bootstrap: %d, want 2", n)
	}
}

// A membership table keyed by a TEXT uuid reports that id, as text, in the
// audit row.
func TestGroupBootstrapAuditsUUIDMembershipID(t *testing.T) {
	app, uid, cleanup := newBootstrapTestApp(t, "user_id")
	defer cleanup()
	mustExec(t, app.DB, "DROP TABLE company_members")
	mustExec(t, app.DB, "CREATE TABLE company_members (id TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(16)))), company_id INTEGER NOT NULL, user_id INTEGER, member_role TEXT)")

	sid := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour)
	if w := bootstrapAs(app, sid, `{"name":"Acme"}`); w.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	var memberID, rowID string
	if err := app.DB.QueryRow("SELECT id FROM company_members").Scan(&memberID); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow("SELECT row_id FROM _benmore_audit_log WHERE table_name = 'company_members'").Scan(&rowID); err != nil {
		t.Fatal(err)
	}
	if len(memberID) != 32 || rowID != memberID {
		t.Fatalf("membership audit row_id = %q, want the uuid %q", rowID, memberID)
	}
}
