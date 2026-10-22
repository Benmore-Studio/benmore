//go:build !cli

package main

import (
	"reflect"
	"testing"
	"time"
)

// A timeout transition is a sessionless write: it is announced to the
// row's tenant (and admins), not to every tenant's readers.
func TestWorkflowTimeoutBroadcastStaysInRowTenant(t *testing.T) {
	app := flowRealtimeApp(t)
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, "ALTER TABLE orgdocs ADD COLUMN status TEXT")
	mustExec(t, app.DB, "ALTER TABLE orgdocs ADD COLUMN updated_at DATETIME")
	mustExec(t, app.DB, "UPDATE orgdocs SET status = 'draft', updated_at = datetime('now', '-2 hours') WHERE id = 1")
	mustExec(t, app.DB, "UPDATE orgdocs SET status = 'published', updated_at = datetime('now') WHERE id = 2")
	for i := range app.Tables {
		if app.Tables[i].Name == "orgdocs" {
			cols, err := GetTableColumns(app.DB, "orgdocs")
			if err != nil {
				t.Fatal(err)
			}
			app.Tables[i].Columns = cols
		}
	}
	mustExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-a', 'a@example.com'), ('tenant-b', 'b@example.com')")
	subA := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "a@example.com", "user", "tenant-a", ""))
	subB := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "b@example.com", "user", "tenant-b", ""))

	wf := &Workflow{Name: "docs", Table: "orgdocs", Field: "status",
		Transitions: map[string]map[string]Transition{"draft": {"archived": {}}},
		Timeouts:    map[string]WorkflowTimeout{"draft": {After: time.Hour, To: "archived"}}}
	checkWorkflowTimeouts(app, wf)

	event := []string{`{"table":"orgdocs","action":"update"}`}
	if sse, _ := subA.drain(); !reflect.DeepEqual(sse, event) {
		t.Fatalf("row's tenant got %q, want the update event", sse)
	}
	if sse, _ := subB.drain(); len(sse) != 0 {
		t.Fatalf("another tenant heard about the timeout: %q", sse)
	}
}
