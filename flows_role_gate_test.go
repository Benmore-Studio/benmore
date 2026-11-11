//go:build !cli

package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A flow's `role: admin` gate names the app's global admin. A tenant role
// that happens to be called admin (the membership role, which anyone gets by
// founding a tenant when founding_role is admin, or a group-scoped grant)
// sits in the same session role list and used to pass it.
func TestFlowRoleAdminNeedsGlobalAdmin(t *testing.T) {
	tenantAdmin := &Session{UserID: 7, Role: "user", Roles: []string{"user", "admin"}, GroupID: "3"}
	tenantFinance := &Session{UserID: 8, Role: "user", Roles: []string{"user", "finance"}, GroupID: "3"}
	columnAdmin := &Session{UserID: 1, Role: "admin", Roles: []string{"admin"}}
	grantAdmin := &Session{UserID: 2, Role: "user", Roles: []string{"user", "admin"}, GlobalAdmin: true}
	cases := []struct {
		name    string
		session *Session
		role    string
		want    bool
	}{
		{"tenant admin, role: admin", tenantAdmin, "admin", false},
		{"tenant admin, role: Admin", tenantAdmin, "Admin", false},
		{"tenant admin, padded role", tenantAdmin, " admin ", false},
		{"tenant admin, another role", tenantAdmin, "finance", false},
		{"tenant finance, role: finance", tenantFinance, "finance", true},
		{"tenant finance, role: admin", tenantFinance, "admin", false},
		{"admin by users.role, role: admin", columnAdmin, "admin", true},
		{"admin by users.role, any role", columnAdmin, "finance", true},
		{"admin by global grant, role: admin", grantAdmin, "admin", true},
		{"admin by global grant, any role", grantAdmin, "finance", true},
		{"signed out", nil, "admin", false},
	}
	for _, c := range cases {
		if got := flowRoleAllowed(c.session, c.role); got != c.want {
			t.Errorf("%s: flowRoleAllowed = %v, want %v", c.name, got, c.want)
		}
	}
}

// End to end, on every door a flow's role gate guards: the request, the
// flows.json listing, scheduling, the queued run of an async flow and the
// connector tool. A user who signs up and founds a tenant (founding_role
// admin) must pass none of them for a `role: admin` flow, the global admin
// passes all, and a tenant role with another name keeps passing its own gate.
func TestTenantAdminDoesNotPassRoleAdminFlow(t *testing.T) {
	app := authzApp(t)
	authzTable(t, app, "companies", "CREATE TABLE companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)")
	authzTable(t, app, "company_members", "CREATE TABLE company_members (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, email TEXT, user_id INTEGER, member_role TEXT)")
	authzTable(t, app, "activity", "CREATE TABLE activity (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, note TEXT)")
	app.Group = &GroupConfig{Table: "company_members", Key: "company_id", UserField: "email", RoleField: "member_role",
		Bootstrap: &GroupBootstrapConfig{OrgTable: "companies", FoundingRole: "admin"}}
	mustExec(t, app.DB, "INSERT INTO companies (id, name) VALUES (50, 'Someone else')")

	worker := func(name, role, extra string) {
		writeTestFile(t, app.Dir, "flows/"+name+".yaml", `on:
  request:
    method: POST
    path: /api/`+name+`
    role: `+role+"\n"+extra+`jobs:
  run:
    steps:
      - run: sql
        with: { query: "INSERT INTO activity (company_id, note) VALUES (:company, '`+name+`')" }
      - run: respond
        with: { status: 200, json: { logged: true } }
`)
	}
	worker("log-activity", "admin", "")
	worker("spend-report", "finance", "")
	writeTestFile(t, app.Dir, "flows/admin-export.yaml", `on:
  request:
    method: GET
    path: /api/admin-export
    role: admin
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
	if err != nil || len(flows) != 3 {
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

	// The founder signs up and founds a tenant: tenant role admin, no global role.
	founder := authzUser(t, app, "founder@example.com", "user")
	founderSID := authzSession(t, app, founder, "founder@example.com")
	w := httptest.NewRecorder()
	handleGroupBootstrap(w, authzReq("POST", "/api/_groups/create", founderSID, `{"name":"Acme"}`), app)
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	founderSession := getSession(app, authzReq("GET", "/", founderSID, ""))
	if founderSession == nil || !HasAnyRole(founderSession, []string{"admin"}) || founderSession.IsAdmin() {
		t.Fatalf("the founder should hold the tenant role admin and no global admin: %+v", founderSession)
	}
	tenant := founderSession.GroupID

	finance := authzUser(t, app, "fin@example.com", "user")
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO company_members (company_id, email, user_id, member_role) VALUES (%s, 'fin@example.com', %d, 'finance')", tenant, finance))
	financeSID := authzSession(t, app, finance, "fin@example.com")
	financeSession := getSession(app, authzReq("GET", "/", financeSID, ""))
	if financeSession == nil || !HasAnyRole(financeSession, []string{"finance"}) {
		t.Fatalf("the finance member should hold the tenant role finance: %+v", financeSession)
	}

	root := authzUser(t, app, "root@example.com", "admin")
	rootSID := authzSession(t, app, root, "root@example.com")
	rootSession := getSession(app, authzReq("GET", "/", rootSID, ""))

	call := func(sid, method, path, body string) (int, string) {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authzReq(method, path, sid, body))
		return rec.Code, rec.Body.String()
	}
	logged := func(note string) int {
		t.Helper()
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM activity WHERE note = ?", note).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	// The request. The payload names another tenant: exactly what the gate is for.
	if code, body := call(founderSID, "POST", "/api/log-activity", `{"company":50}`); code != http.StatusForbidden || logged("log-activity") != 0 {
		t.Errorf("a tenant admin called a role: admin flow: %d %s (%d rows written)", code, body, logged("log-activity"))
	}
	if code, body := call(financeSID, "POST", "/api/log-activity", `{"company":50}`); code != http.StatusForbidden {
		t.Errorf("a tenant finance user called a role: admin flow: %d %s", code, body)
	}
	if code, body := call(rootSID, "POST", "/api/log-activity", `{"company":50}`); code != http.StatusOK || logged("log-activity") != 1 {
		t.Errorf("the global admin was refused its own flow: %d %s", code, body)
	}
	if code, body := call(financeSID, "POST", "/api/spend-report", `{"company":`+tenant+`}`); code != http.StatusOK || logged("spend-report") != 1 {
		t.Errorf("a tenant finance user was refused a role: finance flow: %d %s", code, body)
	}
	if code, body := call(founderSID, "POST", "/api/spend-report", `{"company":`+tenant+`}`); code != http.StatusForbidden {
		t.Errorf("a tenant admin passed role: finance: %d %s", code, body)
	}

	// The flows.json listing follows the request gate.
	if flowListedFor(flowNamed("log-activity"), founderSession) {
		t.Error("flows.json lists a role: admin flow for a tenant admin")
	}
	if !flowListedFor(flowNamed("log-activity"), rootSession) || !flowListedFor(flowNamed("spend-report"), financeSession) {
		t.Error("flows.json hides a flow its caller may run")
	}

	// Scheduling a flow needs the role it is gated on.
	if _, err := schedulableFlow(app, "log-activity", founderSession); !errors.Is(err, errScheduledFlowRole) {
		t.Errorf("a tenant admin may schedule a role: admin flow: %v", err)
	}
	if _, err := schedulableFlow(app, "log-activity", rootSession); err != nil {
		t.Errorf("the global admin cannot schedule its own flow: %v", err)
	}
	if _, err := schedulableFlow(app, "spend-report", financeSession); err != nil {
		t.Errorf("a tenant finance user cannot schedule a role: finance flow: %v", err)
	}

	// A queued async run re-checks the role when it starts.
	logFlow, reportFlow := flowNamed("log-activity"), flowNamed("spend-report")
	if _, err := flowJobActorCheck(app, &logFlow, roundTripFlowJobActor(t, founderSession), map[string]any{"user_group_id": tenant}); err == nil {
		t.Error("a job queued for a tenant admin ran a role: admin flow")
	}
	if _, err := flowJobActorCheck(app, &logFlow, roundTripFlowJobActor(t, rootSession), nil); err != nil {
		t.Errorf("a job queued for the global admin was refused: %v", err)
	}
	if _, err := flowJobActorCheck(app, &reportFlow, roundTripFlowJobActor(t, financeSession), map[string]any{"user_group_id": tenant}); err != nil {
		t.Errorf("a job queued for a tenant finance user was refused: %v", err)
	}

	// A connector read tool that calls the flow.
	tool := &AppMCPTool{Name: "admin_export", Effect: "read", Handler: AppMCPHandler{Kind: "native", Operation: "flow.call", Flow: "admin-export"}}
	if appMCPToolAllowed(app, tool, founderSession) {
		t.Error("a tenant admin may call a connector tool backed by a role: admin flow")
	}
	if !appMCPToolAllowed(app, tool, rootSession) {
		t.Error("the global admin may not call its own connector tool")
	}
}
