//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func generatedWorkflowRoleFixture(t *testing.T) (*App, *httptest.Server) {
	t.Helper()
	app, _ := auditApp(t)
	app.Group = nil
	app.Tables = nil
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{}}
	for _, table := range []string{"orders", "reviews"} {
		mustExec(t, app.DB, "CREATE TABLE "+quoteIdent(table)+" (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, status TEXT DEFAULT 'pending')")
		cols, err := GetTableColumns(app.DB, table)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: table, Columns: cols})
		app.Access.rules[table] = map[AccessOp]string{"all": "self"}
		role := "staff"
		if table == "reviews" {
			role = "editor"
		}
		app.Workflows.Workflows[table] = &Workflow{
			Name: table, Table: table, Field: "status", Initial: "pending",
			States:      []string{"pending", "approved", "cancelled", "blocked"},
			Transitions: map[string]map[string]Transition{"pending": {"approved": {Role: role}}},
		}
	}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	registerWorkflows(mux, app)
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	return app, server
}

func TestGeneratedWorkflowAuthorizedRoleDoesNotChangeOrdinaryIdentity(t *testing.T) {
	app, server := generatedWorkflowRoleFixture(t)
	// Other generated tests already use this identity. A requested AsRole on
	// that same email cannot grant a new role, and must not change its authority.
	loginTestUser(app, frameworkTestUser, "user")
	generated := generateWorkflowTests(app)
	identities := map[string]bool{}
	for _, table := range []string{"reviews", "orders"} {
		name := "wf_" + table + "_valid_transition"
		journey := generated.Tests[name]
		result := runSingleTest(app, server.URL, generated.Name, name, journey)
		if !result.Pass {
			t.Fatalf("authorized %s transition failed: %+v", table, result)
		}
		if journey.AsUser == frameworkTestUser || identities[journey.AsUser] {
			t.Fatalf("different workflow roles reused a shared identity: %q", journey.AsUser)
		}
		identities[journey.AsUser] = true
		var state, role string
		if err := app.DB.QueryRow("SELECT o.status, u.role FROM "+quoteIdent(table)+" o JOIN _benmore_users u ON o.user_id = u.id").Scan(&state, &role); err != nil {
			t.Fatal(err)
		}
		if state != "approved" || role != app.Workflows.Workflows[table].Transitions["pending"]["approved"].Role {
			t.Fatalf("wrong persisted transition or actor: state=%q role=%q", state, role)
		}
		// A real unprivileged request must still fail and leave its own row pending.
		journey.AsUser, journey.AsRole = frameworkTestUser, ""
		journey.Steps[1].Expect = AppTestExpect{Status: http.StatusForbidden}
		result = runSingleTest(app, server.URL, generated.Name, name+"_role_denied", journey)
		if !result.Pass {
			t.Fatalf("ordinary role guard changed: %+v", result)
		}
		var pending int
		if err := app.DB.QueryRow("SELECT count(*) FROM "+quoteIdent(table)+" o JOIN _benmore_users u ON o.user_id = u.id WHERE u.email = ? AND o.status = 'pending'", frameworkTestUser).Scan(&pending); err != nil || pending != 1 {
			t.Fatalf("denial changed persisted state: pending=%d err=%v", pending, err)
		}
	}
	var role string
	if err := app.DB.QueryRow("SELECT role FROM _benmore_users WHERE email = ?", frameworkTestUser).Scan(&role); err != nil || role != "user" {
		t.Fatalf("ordinary generated-test identity changed: role=%q err=%v", role, err)
	}
}

func TestGeneratedWorkflowMixedTargetsAreDeterministicAndAvoidConditions(t *testing.T) {
	app, server := generatedWorkflowRoleFixture(t)
	wf := app.Workflows.Workflows["orders"]
	wf.Transitions["pending"] = map[string]Transition{
		"a_blocked": {Role: "admin", When: "1 = 0"},
		"approved":  {Role: "staff"},
		"cancelled": {},
	}
	wf.States = append(wf.States, "a_blocked")
	first := generateWorkflowTests(app).Tests["wf_orders_valid_transition"]
	if got := first.Steps[1].JSON["to"]; got != "approved" || first.AsRole != "staff" {
		t.Fatalf("wrong eligible transition/role: to=%v role=%q", got, first.AsRole)
	}
	for i := 0; i < 100; i++ {
		if got := generateWorkflowTests(app).Tests["wf_orders_valid_transition"]; !reflect.DeepEqual(first, got) {
			t.Fatal("workflow generation depends on map iteration")
		}
	}
	result := runSingleTest(app, server.URL, "_framework_workflows", "wf_orders_valid_transition", first)
	if !result.Pass {
		t.Fatalf("mixed-role generated transition failed: %+v", result)
	}
	wf.Transitions["pending"] = map[string]Transition{"a_blocked": {When: "1 = 0"}}
	generated := generateWorkflowTests(app)
	if _, ok := generated.Tests["wf_orders_valid_transition"]; ok {
		t.Fatal("invented a successful transition without its required fixture condition")
	}
	for _, suffix := range []string{"invalid_transition", "available_transitions", "unauth_rejected"} {
		journey, ok := generated.Tests["wf_orders_"+suffix]
		if !ok {
			t.Fatalf("conditional workflow lost independent %s coverage", suffix)
		}
		if result := runSingleTest(app, server.URL, generated.Name, "wf_orders_"+suffix, journey); !result.Pass {
			t.Fatalf("conditional workflow %s failed: %+v", suffix, result)
		}
	}
	for _, role := range []string{"", "user", "USER"} {
		wf.Transitions["pending"] = map[string]Transition{"cancelled": {Role: role}}
		journey := generateWorkflowTests(app).Tests["wf_orders_valid_transition"]
		if journey.AsUser != frameworkTestUser || journey.AsRole != "" {
			t.Fatalf("ordinary role %q changed the shared identity: user=%q role=%q", role, journey.AsUser, journey.AsRole)
		}
	}
}
