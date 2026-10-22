//go:build !cli && !windows

package main

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// Review follow-ups: group bootstrap, admin-panel routes, unchanged echo on
// update, scope-before-disclosure ordering and columns generic DELETE writes.

func TestCommandOwnedFieldsGroupBootstrapRefusesOwnedOrgColumn(t *testing.T) {
	app, uid, cleanup := newBootstrapTestApp(t, "email")
	defer cleanup()
	mustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN approved INTEGER NOT NULL DEFAULT 0")
	app.Flows = []Flow{{Name: "approve_company", Trigger: FlowTrigger{Type: "command"},
		Command: &FlowCommand{Writes: []string{"companies"}, Owns: []FlowCommandOwn{{Table: "companies", Column: "approved"}}}}}
	sid := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour)

	w := bootstrapAs(app, sid, `{"name":"Acme","approved":1}`)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "field_owned_by_command") || !strings.Contains(w.Body.String(), "companies.approved") {
		t.Fatalf("owned org column: %d %s", w.Code, w.Body.String())
	}
	if n := countRows(t, app, "companies") + countRows(t, app, "company_members"); n != 0 {
		t.Fatalf("a refused bootstrap wrote %d rows", n)
	}
	// Without the owned key the bootstrap works and the column keeps its default.
	w = bootstrapAs(app, sid, `{"name":"Acme"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap without the owned column: %d %s", w.Code, w.Body.String())
	}
	var approved int
	if err := app.DB.QueryRow("SELECT approved FROM companies").Scan(&approved); err != nil || approved != 0 {
		t.Fatalf("approved = %d err %v", approved, err)
	}
}

func TestCommandOwnedFieldsAdminPanelRoutes(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	rec := rawOwnedRequest(f.mux, http.MethodPost, "/_admin/api/tasks/update/1", f.admin, "application/x-www-form-urlencoded", "status=done")
	f.ownedBody(t, rec, "tasks.status")
	rec = rawOwnedRequest(f.mux, http.MethodPost, "/_admin/api/tasks/create", f.admin, "application/x-www-form-urlencoded", "project_id=7&title=n&status=done")
	f.ownedBody(t, rec, "tasks.status")
	if _, status, _ := f.task(t); status != "open" {
		t.Fatalf("admin panel changed the owned column: %q", status)
	}
	// An admin-panel edit of an unowned column still works.
	rec = rawOwnedRequest(f.mux, http.MethodPost, "/_admin/api/tasks/update/1", f.admin, "application/x-www-form-urlencoded", "title=via-admin")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin panel unowned edit: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCommandOwnedFieldsUnchangedEchoAllowedOnUpdate(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	for _, who := range []string{f.user, f.admin} {
		// Full-row echo: the owned value is the stored one, another field changes.
		rec := crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", who, map[string]any{"title": "echoed", "status": "open"})
		if rec.Code != http.StatusOK {
			t.Fatalf("echo of an unchanged owned value: %d %s", rec.Code, rec.Body.String())
		}
		if title, status, _ := f.task(t); title != "echoed" || status != "open" {
			t.Fatalf("after echo: %q %q", title, status)
		}
		// A changed value is still refused and nothing else is written.
		rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", who, map[string]any{"title": "again", "status": "done"})
		f.ownedBody(t, rec, "tasks.status")
		if title, status, _ := f.task(t); title != "echoed" || status != "open" {
			t.Fatalf("a refused update wrote: %q %q", title, status)
		}
	}
	// Admin-panel form echo (strings), then a changed value.
	rec := rawOwnedRequest(f.mux, http.MethodPost, "/_admin/api/tasks/update/1", f.admin, "application/x-www-form-urlencoded", "title=form-echo&status=open")
	if rec.Code != http.StatusOK {
		t.Fatalf("admin form echo: %d %s", rec.Code, rec.Body.String())
	}
	rec = rawOwnedRequest(f.mux, http.MethodPost, "/_admin/api/tasks/update/1", f.admin, "application/x-www-form-urlencoded", "title=x&status=closed")
	f.ownedBody(t, rec, "tasks.status")

	// NULL echoed as an empty string is a change and stays refused.
	rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"title": "n", "completed_by": ""})
	f.ownedBody(t, rec, "tasks.completed_by")

	// Transactions echo the same way.
	rec = crudScopeRequest(t, f.mux, http.MethodPost, "/api/_transaction", f.user, map[string]any{"operations": []map[string]any{
		{"table": "tasks", "action": "update", "id": 1, "data": map[string]any{"title": "tx", "status": "open"}}}})
	if rec.Code != http.StatusOK {
		t.Fatalf("transaction echo: %d %s", rec.Code, rec.Body.String())
	}
	// Create and batch update keep refusing any value for an owned column.
	rec = crudScopeRequest(t, f.mux, http.MethodPost, "/api/tasks", f.user, map[string]any{"project_id": 7, "title": "c", "status": "open"})
	f.ownedBody(t, rec, "tasks.status")
	rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/batch", f.user, map[string]any{"ids": []int{1}, "fields": map[string]string{"status": "open"}})
	f.ownedBody(t, rec, "tasks.status")
}

func TestCommandOwnedFieldsScopeCheckPrecedesOwnershipDisclosure(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	f.app.Roles.Roles["reader"] = RoleDef{Scopes: "tasks:read"}
	reader := createCrudScopeSession(t, f.app, "reader@example.com", "reader", "17", "")
	if _, err := f.app.DB.Exec(`INSERT INTO members(org_id,email,user_id) SELECT '17',email,id FROM _benmore_users WHERE email='reader@example.com'`); err != nil {
		t.Fatal(err)
	}
	rec := crudScopeRequest(t, f.mux, http.MethodPost, "/api/tasks", reader, map[string]any{"project_id": 7, "title": "x", "status": "done"})
	if rec.Code != http.StatusForbidden || strings.Contains(rec.Body.String(), "complete_item") || strings.Contains(rec.Body.String(), "field_owned_by_command") {
		t.Fatalf("a scope-less token learned the owning command: %d %s", rec.Code, rec.Body.String())
	}
}

func TestCommandOwnsRejectsColumnsGenericDeleteAndUpdateWrite(t *testing.T) {
	columns := map[string]map[string]string{"work_items": {"id": "id", "status": "status", "deleted_at": "deleted_at", "updated_at": "updated_at"}}
	for col, want := range map[string]string{"deleted_at": "written by generic DELETE", "Deleted_At": "written by generic DELETE", "updated_at": "written by every generic UPDATE"} {
		_, err := ownedParse(t, "  owns: [work_items."+col+"]\n", columns)
		if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "cannot be owned") {
			t.Errorf("owns %s: err = %v, want %q", col, err, want)
		}
	}
	if _, err := ownedParse(t, "  owns: [work_items.status]\n", columns); err != nil {
		t.Fatal(err)
	}
}

func TestOwnedFieldCheckerResolvesOnceAndIsNoopWithoutOwnership(t *testing.T) {
	app := &App{}
	check := ownedFieldChecker(app, "tasks")
	if check("status", "title") != nil {
		t.Fatal("no command owns anything yet")
	}
	app.Flows = []Flow{{Name: "c", Command: &FlowCommand{Owns: []FlowCommandOwn{{Table: "tasks", Column: "status"}}}}}
	if check("status") != nil {
		t.Fatal("the checker is resolved once per request, not re-read per call")
	}
	if v := ownedFieldChecker(app, "TASKS")("Title", "STATUS"); v == nil || v.Command != "c" {
		t.Fatalf("checker = %#v", v)
	}
}
