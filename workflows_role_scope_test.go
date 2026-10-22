//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newWorkflowTenantApp builds a two-tenant app whose `orders` table carries a
// role-gated workflow. The membership table has a `role` column, which is what
// transition role checks and SSR role sections read for the in-app role.
func newWorkflowTenantApp(t *testing.T) (*App, *Workflow, func()) {
	t.Helper()
	app, cleanup := newTestApp(t)
	EnsureSessionsTable(app.DB)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatalf("EnsureUsersTable: %v", err)
	}
	EnsureAuditLogTable(app.DB)
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	EnsureLocksTable(app.DB)
	mustExec(t, app.DB, "CREATE TABLE members (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT NOT NULL, user_id INTEGER NOT NULL, role TEXT)")
	mustExec(t, app.DB, "CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id TEXT, user_id INTEGER, status TEXT)")
	app.Tables = []Table{
		{Name: "members", Columns: []Column{{Name: "id"}, {Name: "org_id"}, {Name: "user_id"}, {Name: "role"}}},
		{Name: "orders", Columns: []Column{{Name: "id"}, {Name: "org_id"}, {Name: "user_id"}, {Name: "status"}}},
	}
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"}
	wf := &Workflow{
		Name: "orders", Table: "orders", Field: "status", Initial: "pending",
		States: []string{"pending", "approved"},
		Transitions: map[string]map[string]Transition{
			"pending": {"approved": {Role: "approver"}},
		},
	}
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"orders": wf}}
	return app, wf, cleanup
}

func workflowTestUser(t *testing.T, app *App, email string) int64 {
	t.Helper()
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, 'user', 1)", email, email)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func addMember(t *testing.T, app *App, org string, uid int64, role string) {
	t.Helper()
	if _, err := app.DB.Exec("INSERT INTO members (org_id, user_id, role) VALUES (?, ?, ?)", org, uid, role); err != nil {
		t.Fatalf("insert member: %v", err)
	}
}

func transitionAs(app *App, wf *Workflow, sid, id, to string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://app.example.com/api/orders/"+id+"/transition", strings.NewReader(`{"to":"`+to+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+sid)
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	handleTransition(w, r, app, wf)
	return w
}

// A member's in-app role belongs to the tenant it was granted in. A user who
// is an approver in one tenant and a plain member in another must not approve
// the second tenant's orders: the role lookup has to follow the session's
// effective tenant, not whichever membership row the database returns first.
func TestWorkflowTransitionRoleIsTenantScoped(t *testing.T) {
	app, wf, cleanup := newWorkflowTenantApp(t)
	defer cleanup()

	uid := workflowTestUser(t, app, "multi@example.com")
	// Approver in org A (the older row), plain member in org B.
	addMember(t, app, "A", uid, "approver")
	addMember(t, app, "B", uid, "member")
	mustExec(t, app.DB, "INSERT INTO orders (id, org_id, user_id, status) VALUES (1, 'A', 999, 'pending')")
	mustExec(t, app.DB, "INSERT INTO orders (id, org_id, user_id, status) VALUES (2, 'B', 999, 'pending')")

	inB := CreateSession(app.DB, uid, "multi@example.com", "B", time.Hour)
	if w := transitionAs(app, wf, inB, "2", "approved"); w.Code != http.StatusForbidden {
		t.Fatalf("member of B approved B's order with A's approver role: %d %s", w.Code, w.Body.String())
	}
	var status string
	app.DB.QueryRow("SELECT status FROM orders WHERE id = 2").Scan(&status)
	if status != "pending" {
		t.Fatalf("order 2 status = %q, want pending", status)
	}

	// The same user acting in org A still holds approver there.
	inA := CreateSession(app.DB, uid, "multi@example.com", "A", time.Hour)
	if w := transitionAs(app, wf, inA, "1", "approved"); w.Code != http.StatusOK {
		t.Fatalf("approver of A must approve A's order: %d %s", w.Code, w.Body.String())
	}
}

// SSR role sections read the same in-app role; it must be the effective
// tenant's role too.
func TestResolveAppRoleFollowsEffectiveTenant(t *testing.T) {
	app, _, cleanup := newWorkflowTenantApp(t)
	defer cleanup()

	uid := workflowTestUser(t, app, "multi@example.com")
	addMember(t, app, "A", uid, "approver")
	addMember(t, app, "B", uid, "member")

	if got := resolveAppRole(app, &Session{UserID: uid, GroupID: "B"}); got != "member" {
		t.Fatalf("role in B = %q, want member", got)
	}
	if got := resolveAppRole(app, &Session{UserID: uid, GroupID: "A"}); got != "approver" {
		t.Fatalf("role in A = %q, want approver", got)
	}
	// No effective tenant: no tenant role.
	if got := resolveAppRole(app, &Session{UserID: uid}); got != "" {
		t.Fatalf("role without a tenant = %q, want empty", got)
	}
	// A stepped-in admin sees the acted-as tenant's role (none here).
	if got := resolveAppRole(app, &Session{UserID: uid, Role: "admin", ActingAsGroup: "C"}); got != "" {
		t.Fatalf("role while acting as C = %q, want empty", got)
	}
}

// A transition is an update of the state column, so it honours the same
// mutation gates as PATCH: another user's record lock refuses it, and webhook
// subscribers hear about it.
func TestWorkflowTransitionHonorsUpdatePipeline(t *testing.T) {
	app, wf, cleanup := newWorkflowTenantApp(t)
	defer cleanup()
	EnsureWebhooksTable(app.DB)
	EnsureJobsTable(app.DB)
	wf.Transitions["pending"]["cancelled"] = Transition{}
	wf.States = append(wf.States, "cancelled")

	alice := workflowTestUser(t, app, "alice@example.com")
	bob := workflowTestUser(t, app, "bob@example.com")
	addMember(t, app, "B", alice, "member")
	addMember(t, app, "B", bob, "member")
	mustExec(t, app.DB, "INSERT INTO orders (id, org_id, user_id, status) VALUES (2, 'B', 999, 'pending')")
	sid := CreateSession(app.DB, alice, "alice@example.com", "B", time.Hour)

	// Bob holds the edit lock: Alice's transition must wait like a PATCH would.
	if _, err := app.DB.Exec(`INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at)
		VALUES ('orders', '2', ?, 'bob@example.com', datetime('now', '+5 minutes'))`, bob); err != nil {
		t.Fatalf("insert lock: %v", err)
	}
	if w := transitionAs(app, wf, sid, "2", "cancelled"); w.Code != http.StatusConflict {
		t.Fatalf("transition of a row locked by another user: %d %s", w.Code, w.Body.String())
	}
	var status string
	app.DB.QueryRow("SELECT status FROM orders WHERE id = 2").Scan(&status)
	if status != "pending" {
		t.Fatalf("locked order status = %q, want pending", status)
	}
	mustExec(t, app.DB, "DELETE FROM _benmore_locks")

	// A webhook subscriber (an active admin) receives the transition.
	admin := workflowTestUser(t, app, "admin@example.com")
	mustExec(t, app.DB, "UPDATE _benmore_users SET role = 'admin' WHERE email = 'admin@example.com'")
	if _, err := app.DB.Exec(`INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (?, 'https://hooks.example.com/x', 'unused', 'orders', 'update')`, admin); err != nil {
		t.Fatalf("insert webhook: %v", err)
	}
	if w := transitionAs(app, wf, sid, "2", "cancelled"); w.Code != http.StatusOK {
		t.Fatalf("unlocked transition: %d %s", w.Code, w.Body.String())
	}
	var jobs int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE job_type = 'webhook_subscription'").Scan(&jobs)
	if jobs != 1 {
		t.Fatalf("webhook subscription deliveries queued = %d, want 1", jobs)
	}
}

// The SSR <transitions> tag reads a row's state to pick its buttons. It must
// read through the row scope: another tenant's record renders nothing, the
// same as GET /api/<table>/<id>/transitions answers 404.
func TestTransitionTagUsesRowScope(t *testing.T) {
	app, wf, cleanup := newWorkflowTenantApp(t)
	defer cleanup()
	wf.Transitions["pending"]["cancelled"] = Transition{}

	alice := workflowTestUser(t, app, "alice@example.com")
	addMember(t, app, "B", alice, "member")
	mustExec(t, app.DB, "INSERT INTO orders (id, org_id, user_id, status) VALUES (1, 'A', 999, 'pending')")
	mustExec(t, app.DB, "INSERT INTO orders (id, org_id, user_id, status) VALUES (2, 'B', 999, 'pending')")
	ctx := &RenderContext{Data: map[string]any{}, App: app,
		User: &Session{UserID: alice, Email: "alice@example.com", GroupID: "B", Role: "user", Verified: true}}

	if out := expandTransitionTags(`<transitions table="orders" id="1">`, app, ctx); strings.Contains(out, "transition") && strings.Contains(out, "hx-post") {
		t.Fatalf("another tenant's order rendered transition buttons: %s", out)
	}
	if out := expandTransitionTags(`<transitions table="orders" id="2">`, app, ctx); !strings.Contains(out, `hx-post="/api/orders/2/transition"`) {
		t.Fatalf("own tenant's order should render its transitions: %s", out)
	}
}

// The UPDATE is conditioned on the state the transition was validated
// against, so two racing transitions from the same state cannot both apply.
func TestWorkflowTransitionRefusesStaleState(t *testing.T) {
	app, wf, cleanup := newWorkflowTenantApp(t)
	defer cleanup()
	wf.Transitions["pending"]["cancelled"] = Transition{}

	alice := workflowTestUser(t, app, "alice@example.com")
	addMember(t, app, "B", alice, "member")
	mustExec(t, app.DB, "INSERT INTO orders (id, org_id, user_id, status) VALUES (2, 'B', 999, 'pending')")
	// A before-hook moves the row after validation. The conditional write
	// must refuse the stale state and roll back the hook with the transition.
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{
		"orders": {{SQL: "UPDATE orders SET status = 'approved' WHERE id = 2"}},
	}}
	sid := CreateSession(app.DB, alice, "alice@example.com", "B", time.Hour)
	if w := transitionAs(app, wf, sid, "2", "cancelled"); w.Code != http.StatusConflict {
		t.Fatalf("transition from a state that changed underneath: %d %s", w.Code, w.Body.String())
	}
	var status string
	app.DB.QueryRow("SELECT status FROM orders WHERE id = 2").Scan(&status)
	if status != "pending" {
		t.Fatalf("status = %q, want the original pending state after hook rollback", status)
	}
}
