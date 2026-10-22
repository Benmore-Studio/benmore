//go:build !cli

package main

import (
	"testing"
	"time"
)

func newWorkflowTimeoutApp(t *testing.T) (*App, *Workflow) {
	t.Helper()
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	app.Stop = make(chan struct{})
	EnsureJobsTable(app.DB)
	EnsureAuditLogTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT, updated_at DATETIME)")
	app.Tables = []Table{{Name: "orders", Columns: []Column{{Name: "id"}, {Name: "status"}, {Name: "updated_at"}}}}
	wf := &Workflow{
		Name: "orders", Table: "orders", Field: "status", Initial: "shipped",
		States:       []string{"shipped", "delivered"},
		Transitions:  map[string]map[string]Transition{"shipped": {"delivered": {}}},
		OnTransition: map[string][]Hook{"delivered": {{SQL: "SELECT 1"}}},
		Timeouts:     map[string]WorkflowTimeout{"shipped": {After: time.Second, To: "delivered"}},
	}
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"orders": wf}}
	return app, wf
}

// A hot reload closes the current stop generation. The checker started for
// the previous workflows.yaml must exit with it: before, it looped forever,
// so a removed timeout kept moving rows and every push added one more
// checker firing on_transition hooks.
func TestWorkflowTimeoutCheckerStopsWithReloadGeneration(t *testing.T) {
	old := workflowTimeoutInterval
	workflowTimeoutInterval = 10 * time.Millisecond
	t.Cleanup(func() { workflowTimeoutInterval = old })

	app, wf := newWorkflowTimeoutApp(t)
	done := startWorkflowTimeoutChecker(app, wf)

	// Reload: retire this generation (the new config has no timeout).
	app.mu.Lock()
	close(app.Stop)
	app.Stop = make(chan struct{})
	app.mu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout checker kept running after its stop generation closed")
	}

	mustExec(t, app.DB, "INSERT INTO orders (status, updated_at) VALUES ('shipped', datetime('now', '-1 hour'))")
	time.Sleep(100 * time.Millisecond)
	var status string
	if err := app.DB.QueryRow("SELECT status FROM orders").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "shipped" {
		t.Fatalf("retired checker moved the row to %q", status)
	}
}

// The checker's UPDATE applies only while the row is still in the timed-out
// state, so a second checker (or a user transition in between) can't apply
// the same timeout twice and fire its hooks again.
func TestWorkflowTimeoutAppliesOnlyFromTimedOutState(t *testing.T) {
	app, wf := newWorkflowTimeoutApp(t)
	mustExec(t, app.DB, "INSERT INTO orders (status, updated_at) VALUES ('shipped', datetime('now', '-1 hour'))")

	applied, err := applyWorkflowTimeout(app, wf, "1", "shipped", "delivered")
	if err != nil || !applied {
		t.Fatalf("first apply = %v, %v; want applied", applied, err)
	}
	applied, err = applyWorkflowTimeout(app, wf, "1", "shipped", "delivered")
	if err != nil || applied {
		t.Fatalf("second apply from a stale state = %v, %v; want not applied", applied, err)
	}

	// A user moved the row on; a stale timeout must not pull it back.
	mustExec(t, app.DB, "UPDATE orders SET status = 'returned' WHERE id = 1")
	if applied, _ := applyWorkflowTimeout(app, wf, "1", "shipped", "delivered"); applied {
		t.Fatal("timeout overwrote a state the row reached through another transition")
	}
	var status string
	app.DB.QueryRow("SELECT status FROM orders WHERE id = 1").Scan(&status)
	if status != "returned" {
		t.Fatalf("status = %q, want returned", status)
	}
}

func TestCheckWorkflowTimeoutsFiresHooksOnce(t *testing.T) {
	app, wf := newWorkflowTimeoutApp(t)
	mustExec(t, app.DB, "INSERT INTO orders (status, updated_at) VALUES ('shipped', datetime('now', '-1 hour'))")
	checkWorkflowTimeouts(app, wf)
	checkWorkflowTimeouts(app, wf)
	var hooks int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE job_type = 'hook'").Scan(&hooks)
	if hooks != 1 {
		t.Fatalf("on_transition hook enqueued %d times, want 1", hooks)
	}
}
