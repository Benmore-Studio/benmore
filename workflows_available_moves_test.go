//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// GET /api/<table>/{id}/transitions and the <transitions> tag list a move only
// when POST .../transition would accept it from this caller for this row: the
// table's update rule, the caller's write scope and the edit row scope count,
// not only the transition's role and `when:`. A caller who may read the row
// but not change it used to be shown moves the route then refused.

// tagOffers reports whether the <transitions> tag offers session the move to.
func tagOffers(app *App, session *Session, id, to string) bool {
	ctx := &RenderContext{Data: map[string]any{}, App: app, User: session}
	return strings.Contains(expandTransitionTags(`<transitions table="orders" id="`+id+`">`, app, ctx), `"to":"`+to+`"`)
}

func TestAvailableTransitionsFollowTheUpdateRule(t *testing.T) {
	app, wf, _, bob, _, bobSID := newTransitionCallerApp(t)
	wf.Transitions["pending"]["cancelled"] = Transition{}
	bobView := &Session{UserID: bob, Email: "bob@example.com", GroupID: "A", Role: "user", Verified: true}

	// Without a rule a member of the tenant may update its rows: both moves
	// are offered for ann's order.
	if _, got := availableTargets(t, app, wf, bobSID, "1"); strings.Join(got, ",") != "approved,cancelled" {
		t.Fatalf("bob lists %q for ann's order, want approved,cancelled", got)
	}

	// update: admin. The route refuses every transition by a member.
	app.Access = accessFromYAML(t, "access:\n  orders:\n    read: group\n    update: admin\n")
	if w := transitionAs(app, wf, bobSID, "1", "cancelled"); w.Code == http.StatusOK {
		t.Fatalf("a member moved a row whose update rule is admin: %d %s", w.Code, w.Body.String())
	}
	if current, got := availableTargets(t, app, wf, bobSID, "1"); current != "pending" || len(got) != 0 {
		t.Fatalf("update: admin lists %q in %q for a member, want none in pending", got, current)
	}
	if tagOffers(app, bobView, "1", "cancelled") {
		t.Fatal("the tag offers a member a move of a row whose update rule is admin")
	}
}

func TestAvailableTransitionsFollowTheWriteScope(t *testing.T) {
	app, wf, _, bob, _, bobSID := newTransitionCallerApp(t)
	wf.Transitions["pending"]["cancelled"] = Transition{}
	// The account's role may read orders but not write them.
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"user": {Scopes: "orders:read members:read"}}}

	if w := transitionAs(app, wf, bobSID, "1", "cancelled"); w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "scope denied") {
		t.Fatalf("a read-only caller's transition: %d %s", w.Code, w.Body.String())
	}
	if current, got := availableTargets(t, app, wf, bobSID, "1"); current != "pending" || len(got) != 0 {
		t.Fatalf("a read-only caller lists %q in %q, want none in pending", got, current)
	}
	readOnly := &Session{UserID: bob, Email: "bob@example.com", GroupID: "A", Role: "user", Scopes: "orders:read members:read", Verified: true}
	if tagOffers(app, readOnly, "1", "cancelled") {
		t.Fatal("the tag offers a read-only caller a move")
	}
}

func TestAvailableTransitionsFollowTheEditRowScope(t *testing.T) {
	app, wf, _, bob, _, bobSID := newTransitionCallerApp(t)
	wf.Transitions["pending"]["cancelled"] = Transition{}
	EnsurePermissionsTable(app.DB) // update: self reads record grants
	// Every member reads the tenant's orders; each changes only their own.
	app.Access = accessFromYAML(t, "access:\n  orders:\n    read: group\n    update: self\n")
	bobView := &Session{UserID: bob, Email: "bob@example.com", GroupID: "A", Role: "user", Verified: true}

	// Ann's order: bob reads it, the route answers 404 to his transition.
	if w := transitionAs(app, wf, bobSID, "1", "cancelled"); w.Code != http.StatusNotFound {
		t.Fatalf("bob moved ann's order under update: self: %d %s", w.Code, w.Body.String())
	}
	if current, got := availableTargets(t, app, wf, bobSID, "1"); current != "pending" || len(got) != 0 {
		t.Fatalf("bob lists %q in %q for a row he may not edit, want none in pending", got, current)
	}
	if tagOffers(app, bobView, "1", "cancelled") {
		t.Fatal("the tag offers bob a move of a row he may not edit")
	}

	// His own order: the moves the route accepts (approving your own is
	// refused by the transition's `when:`).
	if _, got := availableTargets(t, app, wf, bobSID, "2"); strings.Join(got, ",") != "cancelled" {
		t.Fatalf("bob lists %q for his own order, want cancelled", got)
	}
	if !tagOffers(app, bobView, "2", "cancelled") {
		t.Fatal("the tag does not offer bob the move of his own order")
	}
	if w := transitionAs(app, wf, bobSID, "2", "cancelled"); w.Code != http.StatusOK {
		t.Fatalf("bob could not move his own order: %d %s", w.Code, w.Body.String())
	}
}
