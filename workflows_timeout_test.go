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
	EnsureWebhooksTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, status TEXT, updated_at DATETIME)")
	app.Tables = []Table{{Name: "orders", Columns: []Column{{Name: "id"}, {Name: "status"}, {Name: "updated_at"}}}}
	wf := &Workflow{
		Name: "orders", Table: "orders", Field: "status", Initial: "shipped",
		States:       []string{"shipped", "delivered"},
		Transitions:  map[string]map[string]Transition{"shipped": {"delivered": {}}},
		OnTransition: map[string][]Hook{"delivered": {{Webhook: "https://example.com/hook"}}},
		Timeouts:     map[string]WorkflowTimeout{"shipped": {After: time.Second, To: "delivered"}},
	}
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"orders": wf}}
	// The failure waits and resume positions are kept per process, and the
	// waits are capped: once tests of earlier runs in this process have filled
	// the map, each new failure evicts another row's wait and that row is
	// tried again in the same test. Each app takes its own entries with it.
	t.Cleanup(func() {
		workflowTimeoutBackoff.mu.Lock()
		for k := range workflowTimeoutBackoff.m {
			if k.dir == app.Dir {
				delete(workflowTimeoutBackoff.m, k)
			}
		}
		workflowTimeoutBackoff.mu.Unlock()
		workflowTimeoutResume.mu.Lock()
		for k := range workflowTimeoutResume.m {
			if k.dir == app.Dir {
				delete(workflowTimeoutResume.m, k)
			}
		}
		workflowTimeoutResume.mu.Unlock()
	})
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

// A row edited after the sweep selected it has a fresh updated_at: the
// timeout's own transaction re-checks the deadline and leaves it alone.
func TestWorkflowTimeoutRechecksDeadlineInTransaction(t *testing.T) {
	app, wf := newWorkflowTimeoutApp(t)
	mustExec(t, app.DB, "INSERT INTO orders (status, updated_at) VALUES ('shipped', datetime('now'))")
	applied, err := applyWorkflowTimeoutDue(app, wf, "1", "shipped", "delivered", 3600)
	if err != nil || applied {
		t.Fatalf("apply on a row edited within the deadline = %v, %v; want not applied", applied, err)
	}
	mustExec(t, app.DB, "UPDATE orders SET updated_at = datetime('now', '-2 hours') WHERE id = 1")
	applied, err = applyWorkflowTimeoutDue(app, wf, "1", "shipped", "delivered", 3600)
	if err != nil || !applied {
		t.Fatalf("apply past the deadline = %v, %v; want applied", applied, err)
	}
}

// A failing timeout is retried with a doubling wait (capped), not every sweep.
func TestWorkflowTimeoutFailureBacksOff(t *testing.T) {
	b := &workflowTimeoutBackoffMap{m: map[workflowTimeoutKey]workflowTimeoutRetry{}}
	k := workflowTimeoutKey{dir: "d", workflow: "w", id: "1"}
	now := time.Unix(1_000_000, 0)
	if b.skip(k, now) {
		t.Fatal("an unknown row was skipped")
	}
	if w := b.fail(k, now); w != time.Minute {
		t.Fatalf("first wait = %s, want 1m", w)
	}
	if !b.skip(k, now.Add(30*time.Second)) || b.skip(k, now.Add(61*time.Second)) {
		t.Fatal("the row was not skipped for exactly its wait")
	}
	var w time.Duration
	for i := 0; i < 10; i++ {
		w = b.fail(k, now)
	}
	if w != workflowTimeoutMaxBackoff {
		t.Fatalf("wait after many failures = %s, want the cap", w)
	}
	b.clear(k)
	if b.skip(k, now) {
		t.Fatal("a cleared row is still skipped")
	}
	b.fail(k, now)
	b.prune(now.Add(4 * time.Hour))
	if len(b.m) != 0 {
		t.Fatal("prune kept a long-stale entry")
	}
}
