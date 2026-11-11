//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A transition's `when:` is judged over the row with the caller's session keys
// and old_<column> for every column, so "decided by someone other than the
// requester" can be written as a condition. It used to get the plain stored
// row: user_id was the row's own column and every old_<column> NULL, so
// `old_user_id != user_id` always held and a requester approved their own
// request.

// newTransitionCallerApp is the two-tenant orders app with two approvers of
// tenant A, each owning one pending order.
func newTransitionCallerApp(t *testing.T) (app *App, wf *Workflow, ann, bob int64, annSID, bobSID string) {
	t.Helper()
	app, wf, cleanup := newWorkflowTenantApp(t)
	t.Cleanup(cleanup)
	wf.States = []string{"pending", "approved", "returned", "draft"}
	wf.Transitions = map[string]map[string]Transition{
		"pending":  {"approved": {Role: "approver", When: "old_user_id != user_id"}},
		"returned": {"draft": {When: "old_user_id = user_id"}},
	}
	ann = workflowTestUser(t, app, "ann@example.com")
	bob = workflowTestUser(t, app, "bob@example.com")
	addMember(t, app, "A", ann, "approver")
	addMember(t, app, "A", bob, "approver")
	mustExecArgs(t, app.DB, "INSERT INTO orders (id, org_id, user_id, status) VALUES (1, 'A', ?, 'pending'), (2, 'A', ?, 'pending'), (3, 'A', ?, 'returned')", ann, bob, ann)
	annSID = CreateSession(app.DB, ann, "ann@example.com", "A", time.Hour)
	bobSID = CreateSession(app.DB, bob, "bob@example.com", "A", time.Hour)
	return app, wf, ann, bob, annSID, bobSID
}

func orderStatus(t *testing.T, app *App, id string) string {
	t.Helper()
	var s string
	if err := app.DB.QueryRow("SELECT status FROM orders WHERE id = ?", id).Scan(&s); err != nil {
		t.Fatal(err)
	}
	return s
}

func availableTargets(t *testing.T, app *App, wf *Workflow, sid, id string) (current string, targets []string) {
	t.Helper()
	r := httptest.NewRequest("GET", "https://app.example.com/api/orders/"+id+"/transitions", nil)
	r.Header.Set("Authorization", "Bearer "+sid)
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	handleAvailableTransitions(w, r, app, wf)
	var body struct {
		Current     string              `json:"current"`
		Transitions []map[string]string `json:"transitions"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil {
		t.Fatalf("transitions of %s: %d %s", id, w.Code, w.Body.String())
	}
	if body.Transitions == nil {
		t.Fatalf("transitions of %s is not a list: %s", id, w.Body.String())
	}
	for _, entry := range body.Transitions {
		targets = append(targets, entry["to"])
	}
	return body.Current, targets
}

func TestTransitionWhenSeesTheCallerAndThePreviousValues(t *testing.T) {
	app, wf, _, _, annSID, bobSID := newTransitionCallerApp(t)

	// The requester cannot approve their own request; another approver can.
	w := transitionAs(app, wf, annSID, "1", "approved")
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "condition not met") {
		t.Fatalf("the requester approved their own order: %d %s", w.Code, w.Body.String())
	}
	if got := orderStatus(t, app, "1"); got != "pending" {
		t.Fatalf("order 1 is %q after the refused approval, want pending", got)
	}
	if w := transitionAs(app, wf, annSID, "2", "approved"); w.Code != http.StatusOK {
		t.Fatalf("another approver could not approve: %d %s", w.Code, w.Body.String())
	}
	if got := orderStatus(t, app, "2"); got != "approved" {
		t.Fatalf("order 2 is %q, want approved", got)
	}

	// Only the requester returns their order to draft.
	if w := transitionAs(app, wf, bobSID, "3", "draft"); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("someone else returned the order to draft: %d %s", w.Code, w.Body.String())
	}
	if got := orderStatus(t, app, "3"); got != "returned" {
		t.Fatalf("order 3 is %q after the refused move, want returned", got)
	}
	if w := transitionAs(app, wf, annSID, "3", "draft"); w.Code != http.StatusOK {
		t.Fatalf("the requester could not return their own order to draft: %d %s", w.Code, w.Body.String())
	}

	// The other caller keys, and the row before the change: the state column
	// still holds the current state, and old_<column> the same stored values.
	wf.Transitions["draft"] = map[string]Transition{"pending": {
		When: "user_email = 'ann@example.com' AND user_role = 'user' AND user_group_id = org_id AND status = 'draft' AND old_status = 'draft' AND old_org_id = 'A'",
	}}
	if w := transitionAs(app, wf, bobSID, "3", "pending"); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a condition on user_email passed for another caller: %d %s", w.Code, w.Body.String())
	}
	if w := transitionAs(app, wf, annSID, "3", "pending"); w.Code != http.StatusOK {
		t.Fatalf("a condition on the caller's keys and old_<column> did not hold: %d %s", w.Code, w.Body.String())
	}
}

// The row's own user_id stays reachable: old_user_id, or the stored table.
func TestTransitionWhenReachesTheRowOwner(t *testing.T) {
	app, wf, _, bob, annSID, _ := newTransitionCallerApp(t)
	for _, when := range []string{
		"old_user_id = " + valueText(bob),
		"(SELECT o.user_id FROM main.orders o WHERE o.id = orders.id) = " + valueText(bob),
	} {
		mustExec(t, app.DB, "UPDATE orders SET status = 'pending' WHERE id IN (1, 2)")
		wf.Transitions["pending"]["approved"] = Transition{Role: "approver", When: when}
		if w := transitionAs(app, wf, annSID, "1", "approved"); w.Code != http.StatusUnprocessableEntity {
			t.Fatalf("when %q held for ann's own order: %d %s", when, w.Code, w.Body.String())
		}
		if w := transitionAs(app, wf, annSID, "2", "approved"); w.Code != http.StatusOK {
			t.Fatalf("when %q did not hold for bob's order: %d %s", when, w.Code, w.Body.String())
		}
	}
}

// The before_update hooks a transition fires see the same previous values and
// caller, with the state column already holding the target state.
func TestTransitionBeforeHookSeesThePreviousValues(t *testing.T) {
	app, wf, ann, bob, annSID, _ := newTransitionCallerApp(t)
	wf.Transitions["pending"]["approved"] = Transition{Role: "approver"}
	mustExec(t, app.DB, "CREATE TABLE decisions (id INTEGER PRIMARY KEY, note TEXT)")
	app.Hooks = &HookConfig{
		BeforeUpdate: map[string][]Hook{"orders": {{
			SQL:  "SELECT 'you cannot decide your own request' AS error",
			When: "status = 'approved' AND old_status = 'pending' AND old_user_id = user_id",
		}}},
	}
	wf.OnTransition = map[string][]Hook{"approved": {{
		SQL:  "INSERT INTO decisions (note) VALUES ({{old_status}} || '>' || {{status}} || ' owner ' || {{old_user_id}} || ' by ' || {{user_id}})",
		When: "old_status = 'pending' AND old_user_id != user_id",
	}}}

	w := transitionAs(app, wf, annSID, "1", "approved")
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "you cannot decide your own request") {
		t.Fatalf("the before_update guard did not refuse the requester: %d %s", w.Code, w.Body.String())
	}
	if got := orderStatus(t, app, "1"); got != "pending" {
		t.Fatalf("order 1 is %q after the refused approval, want pending", got)
	}
	if w := transitionAs(app, wf, annSID, "2", "approved"); w.Code != http.StatusOK {
		t.Fatalf("the guard refused another approver: %d %s", w.Code, w.Body.String())
	}
	var note string
	if err := app.DB.QueryRow("SELECT note FROM decisions").Scan(&note); err != nil {
		t.Fatalf("the on_transition hook did not run: %v", err)
	}
	if want := "pending>approved owner " + valueText(bob) + " by " + valueText(ann); note != want {
		t.Fatalf("on_transition row: %q, want %q", note, want)
	}
}

// GET .../transitions and the <transitions> tag list only the moves the
// caller may make: not one whose `when:` is unmet or cannot be evaluated, and
// none when the state column is owned by a command.
func TestAvailableTransitionsHonourWhen(t *testing.T) {
	app, wf, ann, _, annSID, bobSID := newTransitionCallerApp(t)
	wf.Transitions["pending"]["cancelled"] = Transition{}
	wf.Transitions["pending"]["lost"] = Transition{When: "no_such_column = 1"}

	if current, got := availableTargets(t, app, wf, annSID, "1"); current != "pending" || strings.Join(got, ",") != "cancelled" {
		t.Fatalf("ann's own order lists %q in %q, want cancelled in pending", got, current)
	}
	if _, got := availableTargets(t, app, wf, bobSID, "1"); strings.Join(got, ",") != "approved,cancelled" {
		t.Fatalf("bob lists %q for ann's order, want approved,cancelled", got)
	}
	// What is listed is what the transition route accepts.
	if w := transitionAs(app, wf, annSID, "1", "lost"); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("a transition whose condition cannot be evaluated: %d %s", w.Code, w.Body.String())
	}

	ctx := &RenderContext{Data: map[string]any{}, App: app,
		User: &Session{UserID: ann, Email: "ann@example.com", GroupID: "A", Role: "user", Verified: true}}
	own := expandTransitionTags(`<transitions table="orders" id="1">`, app, ctx)
	if strings.Contains(own, `"to":"approved"`) || strings.Contains(own, `"to":"lost"`) || !strings.Contains(own, `"to":"cancelled"`) {
		t.Fatalf("the tag on ann's own order: %s", own)
	}
	if other := expandTransitionTags(`<transitions table="orders" id="2">`, app, ctx); !strings.Contains(other, `"to":"approved"`) {
		t.Fatalf("the tag on bob's order does not offer approved: %s", other)
	}

	// A command-owned state column moves only through its command: the route
	// answers 403 field_owned_by_command for every target, so none is listed.
	app.Flows = []Flow{{Name: "decide_order", Command: &FlowCommand{Owns: []FlowCommandOwn{{Table: "orders", Column: "status"}}}}}
	if w := transitionAs(app, wf, bobSID, "1", "cancelled"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "field_owned_by_command") {
		t.Fatalf("a transition of a command-owned state: %d %s", w.Code, w.Body.String())
	}
	if current, got := availableTargets(t, app, wf, bobSID, "1"); current != "pending" || len(got) != 0 {
		t.Fatalf("a command-owned state lists %q in %q, want none in pending", got, current)
	}
	if owned := expandTransitionTags(`<transitions table="orders" id="2">`, app, ctx); strings.Contains(owned, "hx-post") {
		t.Fatalf("the tag offers moves of a command-owned state: %s", owned)
	}
}
