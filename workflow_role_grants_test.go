//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A transition guarded by `role: reviewer` admits a user who holds reviewer
// through a role grant (_benmore_user_roles), as a `role:reviewer` access mode
// does. It used to read only the users.role column and the membership role,
// so a granted reviewer got 403 on the transition while every other gate
// accepted the role.
func TestWorkflowTransitionHonorsGlobalRoleGrant(t *testing.T) {
	app := authzApp(t)
	EnsureAuditLogTable(app.DB)
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	authzTable(t, app, "docs", "CREATE TABLE docs (id INTEGER PRIMARY KEY, user_id INTEGER, status TEXT)")
	uid := authzUser(t, app, "rev@example.com", "user")
	mustExecArgs(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (?, 'reviewer')", uid)
	other := authzUser(t, app, "plain@example.com", "user")
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO docs (id, user_id, status) VALUES (1, %d, 'draft'), (2, %d, 'draft')", uid, other))
	wf := &Workflow{Table: "docs", Field: "status", Transitions: map[string]map[string]Transition{
		"draft": {"approved": {Role: "reviewer"}},
	}}
	transition := func(sid, id string) int {
		w := httptest.NewRecorder()
		r := authzReq("POST", "/api/docs/"+id+"/transition", sid, `{"to":"approved"}`)
		r.SetPathValue("id", id)
		handleTransition(w, r, app, wf)
		return w.Code
	}
	if code := transition(authzSession(t, app, uid, "rev@example.com"), "1"); code != http.StatusOK {
		t.Fatalf("granted reviewer: transition status %d, want 200", code)
	}
	if code := transition(authzSession(t, app, other, "plain@example.com"), "2"); code != http.StatusForbidden {
		t.Fatalf("user without the role: transition status %d, want 403", code)
	}
}

// In an app with groups, a grant scoped to the caller's tenant counts on a
// table the tenant key bounds and not on one without it (only a global grant
// does there), exactly as tableModeAllowed counts a `role:` gate.
func TestWorkflowRoleGrantFollowsTheTenantBound(t *testing.T) {
	app := authzApp(t)
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"}
	authzTable(t, app, "members", "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, user_id INTEGER)")
	authzTable(t, app, "tickets", "CREATE TABLE tickets (id INTEGER PRIMARY KEY, org_id TEXT, status TEXT)")
	authzTable(t, app, "catalog", "CREATE TABLE catalog (id INTEGER PRIMARY KEY, status TEXT)")
	tenantGrant := authzUser(t, app, "tenant@example.com", "user")
	globalGrant := authzUser(t, app, "global@example.com", "user")
	mustExecArgs(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (?, 'reviewer', 'g1')", tenantGrant)
	mustExecArgs(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (?, 'reviewer')", globalGrant)
	session := func(uid int64) *Session {
		return &Session{UserID: uid, Role: "user", Roles: []string{"user", "reviewer"}, GroupID: "g1"}
	}
	for _, tc := range []struct {
		who   string
		uid   int64
		table string
		want  bool
	}{
		{"tenant grant, tenant-bound table", tenantGrant, "tickets", true},
		{"tenant grant, table without the tenant key", tenantGrant, "catalog", false},
		{"global grant, tenant-bound table", globalGrant, "tickets", true},
		{"global grant, table without the tenant key", globalGrant, "catalog", true},
	} {
		if got := hasWorkflowRole(app, session(tc.uid), tc.table, "reviewer"); got != tc.want {
			t.Errorf("%s: hasWorkflowRole = %t, want %t", tc.who, got, tc.want)
		}
		if got := tableModeAllowed(app, tc.table, OpWrite, "role:reviewer", session(tc.uid), 0); got != tc.want {
			t.Errorf("%s: the role: access mode says %t; the test expects them to agree", tc.who, got)
		}
	}
	if hasWorkflowRole(app, &Session{UserID: tenantGrant, Role: "user", Roles: []string{"user"}, GroupID: "g1"}, "tickets", "reviewer") {
		t.Error("a session without the role passed")
	}
}
