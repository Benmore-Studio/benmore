//go:build !cli

package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// A flow's `role:` names one role or several, and any of them admits the
// caller. Each name means what it means alone: `admin` is the global admin,
// in a list too, and any other name is matched against every role the caller
// holds, the tenant role included.
func TestFlowRoleListAdmitsAnyOfItsRoles(t *testing.T) {
	warehouse := &Session{UserID: 3, Role: "warehouse", Roles: []string{"warehouse"}}
	managerByGrant := &Session{UserID: 4, Role: "user", Roles: []string{"user", "manager"}}
	clerk := &Session{UserID: 5, Role: "clerk", Roles: []string{"clerk"}}
	tenantAdmin := &Session{UserID: 7, Role: "user", Roles: []string{"user", "admin"}, GroupID: "3"}
	tenantFinance := &Session{UserID: 8, Role: "user", Roles: []string{"user", "finance"}, GroupID: "3"}
	globalAdmin := &Session{UserID: 1, Role: "admin", Roles: []string{"admin"}}
	cases := []struct {
		name    string
		session *Session
		role    string
		want    bool
	}{
		{"the first listed role", warehouse, "warehouse,manager", true},
		{"the second listed role, held by a grant", managerByGrant, "warehouse,manager", true},
		{"neither role", clerk, "warehouse,manager", false},
		{"a global admin", globalAdmin, "warehouse,manager", true},
		{"spaces around the names", managerByGrant, " warehouse , manager ", true},
		{"one name is still one name", warehouse, "warehouse", true},
		{"one name, another role", clerk, "warehouse", false},
		{"letter case is part of the name", warehouse, "Warehouse,Manager", false},
		{"a tenant role in a list", tenantFinance, "admin,finance", true},
		{"admin in a list is the global admin: tenant admin", tenantAdmin, "admin,finance", false},
		{"admin in a list is the global admin: global admin", globalAdmin, "admin,finance", true},
		{"an admin-only list, tenant admin", tenantAdmin, "admin,Admin", false},
		{"Admin in a list, tenant admin", tenantAdmin, "finance, Admin", false},
		{"a space does not separate names", warehouse, "warehouse manager", false},
		{"an empty name: a listed role", warehouse, "warehouse,,manager", false},
		{"an empty name: a global admin", globalAdmin, "warehouse,,manager", true},
		{"a trailing comma", warehouse, "warehouse,", false},
		{"only a comma", clerk, ",", false},
		{"signed out", nil, "warehouse,manager", false},
	}
	for _, c := range cases {
		if got := flowRoleAllowed(c.session, c.role); got != c.want {
			t.Errorf("%s: flowRoleAllowed(%q) = %v, want %v", c.name, c.role, got, c.want)
		}
	}
}

// roleListFlow is a request flow that writes one activity row named after
// itself, gated by the `role:` line as written.
func roleListFlow(name, roleLine string) string {
	return `on:
  request:
    method: POST
    path: /api/` + name + `
    ` + roleLine + `
jobs:
  run:
    steps:
      - run: sql
        with: { query: "INSERT INTO activity (company_id, note) VALUES (0, '` + name + `')" }
      - run: respond
        with: { status: 200, json: { logged: true } }
`
}

// End to end, the string form and the YAML list form on every door the gate
// guards: the request, the flows.json listing, scheduling, the queued run of
// an async flow and the connector tool.
func TestFlowRoleListFormsOnEveryDoor(t *testing.T) {
	app := authzApp(t)
	authzTable(t, app, "companies", "CREATE TABLE companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)")
	authzTable(t, app, "company_members", "CREATE TABLE company_members (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, email TEXT, user_id INTEGER, member_role TEXT)")
	authzTable(t, app, "activity", "CREATE TABLE activity (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, note TEXT)")
	app.Group = &GroupConfig{Table: "company_members", Key: "company_id", UserField: "email", RoleField: "member_role",
		Bootstrap: &GroupBootstrapConfig{OrgTable: "companies", FoundingRole: "admin"}}

	forms := map[string]string{
		"string-form":  `role: "warehouse, manager"`,
		"plain-form":   `role: warehouse,manager`,
		"list-form":    `role: [warehouse, manager]`,
		"block-form":   "role:\n      - warehouse\n      - manager",
		"admin-list":   `role: [admin, finance]`,
		"only-admin":   `role: [admin]`,
		"one-in-a-row": `role: [warehouse]`,
	}
	for name, roleLine := range forms {
		flow := roleListFlow(name, roleLine)
		if msg := ValidateOnWriteIn(app.Dir, "flows/"+name+".yaml", flow); msg != "" {
			t.Fatalf("%s: the write gate refuses %s: %s", name, roleLine, msg)
		}
		writeTestFile(t, app.Dir, "flows/"+name+".yaml", flow)
	}
	// A read flow behind a connector tool, gated by a list.
	writeTestFile(t, app.Dir, "flows/activity-export.yaml", `on:
  request:
    method: GET
    path: /api/activity-export
    role: [warehouse, manager]
    permissions: [activity:read]
jobs:
  run:
    steps:
      - id: rows
        run: sql
        with: { query: "SELECT COUNT(*) AS n FROM activity" }
      - run: respond
        with: { status: 200, json: { n: "${{ steps.rows.outputs.n }}" } }
`)
	flows, err := loadFlowsChecked(app.Dir, true)
	if err != nil || len(flows) != len(forms)+1 {
		t.Fatalf("load flows: %d %v", len(flows), err)
	}
	app.Flows = flows
	mux := http.NewServeMux()
	RegisterFlows(mux, app, flows)
	flowNamed := func(name string) Flow {
		for _, f := range flows {
			if f.Name == name {
				return f
			}
		}
		t.Fatalf("no flow %s", name)
		return Flow{}
	}
	// Every form loads as the names joined with a comma.
	for name, want := range map[string]string{"string-form": "warehouse,manager", "plain-form": "warehouse,manager", "list-form": "warehouse,manager",
		"block-form": "warehouse,manager", "admin-list": "admin,finance", "only-admin": "admin", "one-in-a-row": "warehouse"} {
		if got := flowNamed(name).Role; got != want {
			t.Errorf("%s loads with role %q, want %q", name, got, want)
		}
	}

	session := func(email, role string) (string, *Session) {
		t.Helper()
		uid := authzUser(t, app, email, role)
		sid := authzSession(t, app, uid, email)
		s := getSession(app, authzReq("GET", "/", sid, ""))
		if s == nil {
			t.Fatalf("no session for %s", email)
		}
		return sid, s
	}
	warehouseSID, warehouse := session("wendy@example.com", "warehouse")
	managerSID, manager := session("mona@example.com", "manager")
	clerkSID, clerk := session("carl@example.com", "clerk")
	rootSID, root := session("root@example.com", "admin")

	// A founder holds the tenant role admin; a member holds the tenant role finance.
	founderUID := authzUser(t, app, "founder@example.com", "user")
	founderSID := authzSession(t, app, founderUID, "founder@example.com")
	w := httptest.NewRecorder()
	handleGroupBootstrap(w, authzReq("POST", "/api/_groups/create", founderSID, `{"name":"Acme"}`), app)
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	founder := getSession(app, authzReq("GET", "/", founderSID, ""))
	if founder == nil || !HasAnyRole(founder, []string{"admin"}) || founder.IsAdmin() {
		t.Fatalf("the founder should hold the tenant role admin and no global admin: %+v", founder)
	}
	financeUID := authzUser(t, app, "fin@example.com", "user")
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO company_members (company_id, email, user_id, member_role) VALUES (%s, 'fin@example.com', %d, 'finance')", founder.GroupID, financeUID))
	financeSID := authzSession(t, app, financeUID, "fin@example.com")
	finance := getSession(app, authzReq("GET", "/", financeSID, ""))
	if finance == nil || !HasAnyRole(finance, []string{"finance"}) {
		t.Fatalf("the finance member should hold the tenant role finance: %+v", finance)
	}

	logged := func(note string) int {
		t.Helper()
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM activity WHERE note = ?", note).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	// passes checks one caller against one flow on each door.
	passes := func(flowName, who, sid string, s *Session, want bool) {
		t.Helper()
		before := logged(flowName)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authzReq("POST", "/api/"+flowName, sid, `{}`))
		wantCode, wantRows := http.StatusForbidden, before
		if want {
			wantCode, wantRows = http.StatusOK, before+1
		}
		if rec.Code != wantCode || logged(flowName) != wantRows {
			t.Errorf("%s calls %s: %d %s (%d rows, want %d and %d rows)", who, flowName, rec.Code, strings.TrimSpace(rec.Body.String()), logged(flowName), wantCode, wantRows)
		}
		flow := flowNamed(flowName)
		if got := flowListedFor(flow, s); got != want {
			t.Errorf("flows.json lists %s for %s: %v, want %v", flowName, who, got, want)
		}
		if _, err := schedulableFlow(app, flowName, s); (err == nil) != want || (!want && !errors.Is(err, errScheduledFlowRole)) {
			t.Errorf("%s schedules %s: %v, want allowed %v", who, flowName, err, want)
		}
		if _, err := flowJobActorCheck(app, &flow, roundTripFlowJobActor(t, s), map[string]any{"user_group_id": s.GroupID}); (err == nil) != want {
			t.Errorf("a job of %s queued for %s: %v, want allowed %v", flowName, who, err, want)
		}
	}
	for _, name := range []string{"string-form", "plain-form", "list-form", "block-form"} {
		passes(name, "a warehouse account", warehouseSID, warehouse, true)
		passes(name, "a manager account", managerSID, manager, true)
		passes(name, "an account with neither role", clerkSID, clerk, false)
		passes(name, "a tenant admin", founderSID, founder, false)
		passes(name, "the global admin", rootSID, root, true)
	}
	// `admin` in a list is the global admin; the tenant role beside it is matched by name.
	passes("admin-list", "a tenant admin", founderSID, founder, false)
	passes("admin-list", "a tenant finance member", financeSID, finance, true)
	passes("admin-list", "the global admin", rootSID, root, true)
	passes("admin-list", "a warehouse account", warehouseSID, warehouse, false)
	passes("only-admin", "a tenant admin", founderSID, founder, false)
	passes("only-admin", "a tenant finance member", financeSID, finance, false)
	passes("only-admin", "the global admin", rootSID, root, true)
	passes("one-in-a-row", "a warehouse account", warehouseSID, warehouse, true)
	passes("one-in-a-row", "a manager account", managerSID, manager, false)

	// A connector read tool that calls a flow gated by a list.
	tool := &AppMCPTool{Name: "activity_export", Effect: "read", Handler: AppMCPHandler{Kind: "native", Operation: "flow.call", Flow: "activity-export"}}
	for who, c := range map[string]struct {
		s    *Session
		want bool
	}{"a warehouse account": {warehouse, true}, "a manager account": {manager, true}, "an account with neither role": {clerk, false}, "a tenant admin": {founder, false}, "the global admin": {root, true}} {
		if got := appMCPToolAllowed(app, tool, c.s); got != c.want {
			t.Errorf("the connector tool for %s: %v, want %v", who, got, c.want)
		}
	}

	// The served listing, as each caller's browser gets it.
	RegisterBMTypesRoute(mux, app)
	listing := func(sid string) string {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authzReq("GET", "/_internal/flows.json", sid, ""))
		return rec.Body.String()
	}
	for who, sid := range map[string]string{"warehouse": warehouseSID, "manager": managerSID} {
		if got := listing(sid); !strings.Contains(got, "/api/list-form") || !strings.Contains(got, "/api/string-form") || strings.Contains(got, "/api/admin-list") {
			t.Errorf("flows.json for the %s account: %s", who, got)
		}
	}
	if got := listing(clerkSID); strings.Contains(got, "/api/list-form") || strings.Contains(got, "/api/string-form") {
		t.Errorf("flows.json shows a role-gated flow to an account without the role: %s", got)
	}
}

// A role value that names no role, or holds an empty name, is refused when
// the file is written, in words that name the key.
func TestFlowRoleBadFormsAreRefusedAtWrite(t *testing.T) {
	for name, roleLine := range map[string]string{
		"empty list":                 `role: []`,
		"empty name in a list":       `role: [warehouse, ""]`,
		"null in a list":             `role: [warehouse, ~]`,
		"blank name in a list":       `role: [warehouse, "  "]`,
		"list in a list":             `role: [[warehouse, manager]]`,
		"map":                        `role: { any: [warehouse, manager] }`,
		"map in a list":              `role: [{ name: warehouse }]`,
		"empty name in a string":     `role: "warehouse,,manager"`,
		"trailing comma":             `role: "warehouse,"`,
		"leading comma":              `role: ",manager"`,
		"only a comma":               `role: ","`,
		"only spaces":                `role: "  "`,
		"empty name, block list":     "role:\n      - warehouse\n      - \"\"",
		"comma name inside the list": `role: [warehouse, "manager,"]`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "app.yaml", "site_name: roles\n")
			writeTestFile(t, dir, "schema.prisma", roleGateSchema)
			msg := ValidateOnWriteIn(dir, "flows/receive-stock.yaml", roleGateFlow(roleLine))
			if msg == "" {
				t.Fatalf("%s is accepted", roleLine)
			}
			if strings.Contains(msg, "unmarshal") || strings.Contains(msg, "!!") {
				t.Errorf("the refusal quotes the YAML decoder: %s", msg)
			}
			for _, want := range []string{"on.request.role", "role: [warehouse, manager]", `docs: api(at:"flows.role_gate")`} {
				if !strings.Contains(msg, want) {
					t.Errorf("the refusal lacks %q: %s", want, msg)
				}
			}
		})
	}
}

// A deployed file that carries an empty role name is not refused at load: it
// keeps admitting only a global admin, and the load log says so.
func TestDeployedFlowRoleWithAnEmptyNameAdmitsOnlyAGlobalAdmin(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: r\n")
	writeTestFile(t, dir, "schema.prisma", roleGateSchema)
	writeTestFile(t, dir, "flows/receive-stock.yaml", roleGateFlow(`role: "warehouse,"`))

	var buf bytes.Buffer
	log.SetOutput(&buf)
	defer log.SetOutput(os.Stderr)
	flows, err := loadFlowsCheckedFromSourcesSkipping(dir, true, nil, false, log.Printf) // as the serving load, which logs
	log.SetOutput(os.Stderr)
	if err != nil || len(flows) != 1 {
		t.Fatalf("loaded %d flows, err %v: a deployed file must keep loading", len(flows), err)
	}
	if flows[0].Role == "" {
		t.Fatal("the flow lost its role gate")
	}
	if flowRoleAllowed(&Session{UserID: 3, Role: "warehouse", Roles: []string{"warehouse"}}, flows[0].Role) {
		t.Error("a role value with an empty name admits the role beside it")
	}
	if !flowRoleAllowed(&Session{UserID: 1, Role: "admin", Roles: []string{"admin"}}, flows[0].Role) {
		t.Error("a global admin is refused")
	}
	if logged := buf.String(); !strings.Contains(logged, "WARNING: flows/receive-stock.yaml: ") || !strings.Contains(logged, "empty role name") || !strings.Contains(logged, "only a global admin") {
		t.Errorf("the load log does not say what the gate does:\n%s", logged)
	}
}
