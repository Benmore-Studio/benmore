//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A transition's `role: "owner,manager"` is an any-of list, as an access
// `role:owner,manager` mode is. It used to be compared as one exact string,
// so the transition was locked for every non-admin (403 `role 'owner,manager'
// required`) and GET /transitions hid it.
func TestWorkflowTransitionRoleListIsAnyOf(t *testing.T) {
	app, wf, cleanup := newWorkflowTenantApp(t)
	defer cleanup()
	wf.Transitions["pending"]["approved"] = Transition{Role: "owner, manager"}

	owner := workflowTestUser(t, app, "owner@example.com")
	manager := workflowTestUser(t, app, "manager@example.com")
	member := workflowTestUser(t, app, "member@example.com")
	addMember(t, app, "A", owner, "owner")
	addMember(t, app, "A", manager, "manager")
	addMember(t, app, "A", member, "member")
	mustExec(t, app.DB, "INSERT INTO orders (id, org_id, user_id, status) VALUES (1, 'A', 999, 'pending'), (2, 'A', 999, 'pending'), (3, 'A', 999, 'pending')")

	available := func(sid, id string) []map[string]string {
		t.Helper()
		r := httptest.NewRequest("GET", "https://app.example.com/api/orders/"+id+"/transitions", nil)
		r.Header.Set("Authorization", "Bearer "+sid)
		r.SetPathValue("id", id)
		w := httptest.NewRecorder()
		handleAvailableTransitions(w, r, app, wf)
		var body struct {
			Transitions []map[string]string `json:"transitions"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &body) != nil {
			t.Fatalf("transitions: %d %s", w.Code, w.Body.String())
		}
		return body.Transitions
	}
	status := func(id string) string {
		var s string
		if err := app.DB.QueryRow("SELECT status FROM orders WHERE id = ?", id).Scan(&s); err != nil {
			t.Fatal(err)
		}
		return s
	}

	for _, tc := range []struct {
		who string
		uid int64
		id  string
	}{{"owner", owner, "1"}, {"manager", manager, "2"}} {
		sid := CreateSession(app.DB, tc.uid, tc.who+"@example.com", "A", time.Hour)
		if got := available(sid, tc.id); len(got) != 1 || got[0]["to"] != "approved" || got[0]["role"] != "owner,manager" {
			t.Fatalf("%s: /transitions = %v, want the approved transition listed", tc.who, got)
		}
		if w := transitionAs(app, wf, sid, tc.id, "approved"); w.Code != http.StatusOK {
			t.Fatalf("%s: transition %d %s", tc.who, w.Code, w.Body.String())
		}
		if got := status(tc.id); got != "approved" {
			t.Fatalf("%s: status %q after a 200 transition", tc.who, got)
		}
	}

	sid := CreateSession(app.DB, member, "member@example.com", "A", time.Hour)
	if got := available(sid, "3"); len(got) != 0 {
		t.Fatalf("member: /transitions = %v, want none", got)
	}
	w := transitionAs(app, wf, sid, "3", "approved")
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "one of the roles 'owner', 'manager' required") {
		t.Fatalf("member: transition %d %s", w.Code, w.Body.String())
	}
	if got := status("3"); got != "pending" {
		t.Fatalf("member: status %q after a refused transition", got)
	}
}

// Each listed role passes through every source a single role passes through,
// and no other: a role grant counts exactly where the access mode
// `role:<list>` counts it (the tenant bound), and the users.role column passes
// any listed role.
func TestWorkflowRoleListMatchesAccessRoleMode(t *testing.T) {
	app := authzApp(t)
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"}
	authzTable(t, app, "members", "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, user_id INTEGER)")
	authzTable(t, app, "tickets", "CREATE TABLE tickets (id INTEGER PRIMARY KEY, org_id TEXT, status TEXT)")
	authzTable(t, app, "catalog", "CREATE TABLE catalog (id INTEGER PRIMARY KEY, status TEXT)")
	tenantGrant := authzUser(t, app, "tenant@example.com", "user")
	globalGrant := authzUser(t, app, "global@example.com", "user")
	columnRole := authzUser(t, app, "column@example.com", "auditor")
	mustExecArgs(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role, group_id) VALUES (?, 'reviewer', 'g1')", tenantGrant)
	mustExecArgs(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (?, 'reviewer')", globalGrant)
	session := func(uid int64, role string, roles ...string) *Session {
		return &Session{UserID: uid, Role: role, Roles: append([]string{role}, roles...), GroupID: "g1"}
	}
	for _, tc := range []struct {
		who     string
		session *Session
		table   string
		want    bool
	}{
		{"tenant grant, tenant-bound table", session(tenantGrant, "user", "reviewer"), "tickets", true},
		{"tenant grant, table without the tenant key", session(tenantGrant, "user", "reviewer"), "catalog", false},
		{"global grant, tenant-bound table", session(globalGrant, "user", "reviewer"), "tickets", true},
		{"global grant, table without the tenant key", session(globalGrant, "user", "reviewer"), "catalog", true},
		{"users.role names a listed role", session(columnRole, "auditor"), "catalog", true},
		{"no listed role", session(tenantGrant, "user"), "tickets", false},
	} {
		if got := hasWorkflowRole(app, tc.session, tc.table, "approver, reviewer, auditor"); got != tc.want {
			t.Errorf("%s: hasWorkflowRole = %t, want %t", tc.who, got, tc.want)
		}
		if got := tableModeAllowed(app, tc.table, OpWrite, "role:approver,reviewer,auditor", tc.session, 0); got != tc.want {
			t.Errorf("%s: the role: access mode says %t; the test expects them to agree", tc.who, got)
		}
	}
	// A role: that names no role admits only a platform admin.
	if hasWorkflowRole(app, session(globalGrant, "user", "reviewer"), "tickets", " , ") {
		t.Error("a role list naming no role admitted a non-admin")
	}
	if !hasWorkflowRole(app, &Session{UserID: 1, Role: "admin"}, "tickets", " , ") {
		t.Error("a platform admin passes every transition role")
	}
}

// workflows.yaml takes a transition role as one name, a comma-separated
// string or a YAML list (flow or block style); all store the same any-of list.
func TestWorkflowRoleYAMLForms(t *testing.T) {
	for name, role := range map[string]string{
		"plain":       `role: owner,manager`,
		"quoted":      `role: "owner, manager"`,
		"flow list":   `role: [owner, manager]`,
		"block list":  "role:\n          - owner\n          - manager",
		"single item": `role: [ "owner,manager" ]`,
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := parseWorkflowsYAML([]byte("orders:\n  table: orders\n  field: status\n  initial: pending\n  transitions:\n    pending:\n      approved:\n        " + role + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			if got := cfg.Workflows["orders"].Transitions["pending"]["approved"].Role; got != "owner,manager" {
				t.Fatalf("role = %q, want owner,manager", got)
			}
		})
	}
	if cfg, err := parseWorkflowsYAML([]byte("orders:\n  table: orders\n  field: status\n  transitions:\n    pending:\n      approved: { role: admin }\n")); err != nil || cfg.Workflows["orders"].Transitions["pending"]["approved"].Role != "admin" {
		t.Fatalf("single role: %v %+v", err, cfg)
	}
	for name, role := range map[string]string{
		"empty list": `role: []`,
		"map":        `role: { any: owner }`,
		"nested":     `role: [[owner]]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseWorkflowsYAML([]byte("orders:\n  table: orders\n  field: status\n  transitions:\n    pending:\n      approved: { " + role + " }\n"))
			if err == nil || !strings.Contains(err.Error(), "role") {
				t.Fatalf("%s accepted: %v", role, err)
			}
		})
	}
}

// The write gate refuses a role: that names no role, and the write gate and
// `benmore check` warn about a role name no other part of the app names.
func TestWorkflowRoleValidation(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("schema.prisma", "model orders {\n  id Int @id @default(autoincrement())\n  status String @default(\"pending\")\n}\n")
	write("app.yaml", "name: shop\ngroups:\n  table: members\n  key: org_id\n  user_field: user_id\n  role_field: role\n  bootstrap:\n    org_table: orgs\n    founding_role: owner\naccess:\n  orders:\n    read: role:manager,clerk\n")

	empty := "orders:\n  table: orders\n  field: status\n  transitions:\n    pending:\n      approved: { role: \",\" }\n"
	if msg := ValidateOnWriteIn(dir, "workflows.yaml", empty); !strings.Contains(msg, "names no role") {
		t.Fatalf("a role: naming no role passed the write gate: %q", msg)
	}

	typo := "orders:\n  table: orders\n  field: status\n  transitions:\n    pending:\n      approved: { role: \"owner, manger\" }\n      cancelled: { role: [clerk, admin] }\n"
	if msg := ValidateOnWriteIn(dir, "workflows.yaml", typo); msg != "" {
		t.Fatalf("an unknown role name is a warning, not a refusal: %s", msg)
	}
	write("workflows.yaml", typo)
	for name, report := range map[string]CheckReport{
		"write":         RunSourceCheck(dir, "workflows.yaml"),
		"app.yaml edit": RunSourceCheck(dir, "app.yaml"),
		"check":         runCheck(dir, "", false),
	} {
		var warned []string
		for _, f := range report.Findings {
			if strings.Contains(f.Message, "role") && strings.Contains(f.Message, "workflows.yaml") && f.Severity == "warning" {
				warned = append(warned, f.Message)
			}
		}
		if len(warned) != 1 || !strings.Contains(warned[0], `"manger"`) || strings.Contains(warned[0], `"owner"`) || strings.Contains(warned[0], `"clerk"`) {
			t.Fatalf("%s: role warnings %q, want one naming only manger (findings %+v)", name, warned, report.Findings)
		}
	}

	write("workflows.yaml", "orders:\n  table: orders\n  field: status\n  transitions:\n    pending:\n      approved: { role: [owner, manager, editor] }\n")
	for _, f := range runCheck(dir, "", false).Findings {
		if strings.Contains(f.Message, "is not a role") {
			t.Fatalf("declared and built-in roles warned: %s", f.Message)
		}
	}
}
