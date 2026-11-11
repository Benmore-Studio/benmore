//go:build !cli

package main

import (
	"testing"
	"time"
)

// on_transition hooks see the caller's session context like every hooks.yaml
// hook: `{{user_id}}` is the user who made the transition. The row's own
// user_id (its owner) is `{{old_user_id}}`, which a transition never changes.
// The workflows topic's example notified `{{user_id}}` with "Your order
// shipped", so staff confirming a client's booking notified themselves; the
// example now uses `{{old_user_id}}`. A timeout transition has no caller and
// set only old_<state>, so `{{old_user_id}}` did not resolve there and the
// owner got nothing; it now carries old_<col> for every column too.
func TestWorkflowTransitionNotifyTargets(t *testing.T) {
	app, wf, cleanup := newWorkflowTenantApp(t)
	defer cleanup()
	EnsureNotificationsTable(app.DB)
	mustExec(t, app.DB, "ALTER TABLE orders ADD COLUMN updated_at DATETIME")
	app.Tables[1].Columns = append(app.Tables[1].Columns, Column{Name: "updated_at"})
	owner := workflowTestUser(t, app, "client@example.test")
	staff := workflowTestUser(t, app, "staff@example.test")
	addMember(t, app, "A", owner, "client")
	addMember(t, app, "A", staff, "approver")
	wf.States = append(wf.States, "expired")
	wf.Transitions["approved"] = map[string]Transition{"expired": {}}
	wf.Timeouts = map[string]WorkflowTimeout{"approved": {After: time.Hour, To: "expired"}}
	wf.OnTransition = map[string][]Hook{
		"approved": {
			{Notify: &NotifyHook{UserID: "{{old_user_id}}", Title: "owner: approved"}},
			{Notify: &NotifyHook{UserID: "{{user_id}}", Title: "actor: approved"}},
		},
		"expired": {
			{Notify: &NotifyHook{UserID: "{{old_user_id}}", Title: "owner: expired"}},
		},
	}
	if _, err := app.DB.Exec("INSERT INTO orders (id, org_id, user_id, status) VALUES (1, 'A', ?, 'pending')", owner); err != nil {
		t.Fatal(err)
	}

	sid := CreateSession(app.DB, staff, "staff@example.test", "A", time.Hour)
	if w := transitionAs(app, wf, sid, "1", "approved"); w.Code != 200 {
		t.Fatalf("transition: %d %s", w.Code, w.Body.String())
	}
	runQueuedJobs(t, app)

	// The timeout: no caller at all.
	mustExec(t, app.DB, "UPDATE orders SET updated_at = datetime('now', '-2 hours') WHERE id = 1")
	checkWorkflowTimeouts(app, wf)
	runQueuedJobs(t, app)

	want := map[string]int64{"owner: approved": owner, "actor: approved": staff, "owner: expired": owner}
	rows, err := app.DB.Query("SELECT title, user_id FROM _benmore_notifications")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]int64{}
	for rows.Next() {
		var title string
		var uid int64
		if err := rows.Scan(&title, &uid); err != nil {
			t.Fatal(err)
		}
		got[title] = uid
	}
	for title, uid := range want {
		if got[title] != uid {
			t.Errorf("%q went to user %d, want %d (all: %v)", title, got[title], uid, got)
		}
	}
	if len(got) != len(want) {
		t.Errorf("notifications=%v, want %v", got, want)
	}
}

// runQueuedJobs runs every due job until the queue is empty.
func runQueuedJobs(t *testing.T, app *App) {
	t.Helper()
	for i := 0; i < 50 && processNextJob(app); i++ {
	}
	var failed int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE status <> 'completed'").Scan(&failed); err != nil {
		t.Fatal(err)
	}
	if failed != 0 {
		var errText string
		_ = app.DB.QueryRow("SELECT COALESCE(error, status) FROM _benmore_jobs WHERE status <> 'completed' LIMIT 1").Scan(&errText)
		t.Fatalf("%d job(s) did not complete: %s", failed, errText)
	}
}
