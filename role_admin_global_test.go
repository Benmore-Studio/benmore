//go:build !cli

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// roleAdminApp is a tenant app whose membership table carries the in-tenant
// role, with one member of each kind in tenant 1: a tenant admin and a tenant
// approver (both plain accounts), plus an admin by column and an admin by a
// global grant. orders carries the tenant key; catalog does not.
type roleAdminApp struct {
	app                                                          *App
	tenantAdmin, tenantApprover, columnAdmin, grantAdmin         string // session ids
	tenantAdminID, tenantApproverID, columnAdminID, grantAdminID int64
}

func newRoleAdminApp(t *testing.T) *roleAdminApp {
	t.Helper()
	app := authzApp(t)
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	EnsureLocksTable(app.DB)
	authzTable(t, app, "companies", "CREATE TABLE companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)")
	authzTable(t, app, "company_members", "CREATE TABLE company_members (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, user_id INTEGER, member_role TEXT)")
	authzTable(t, app, "orders", "CREATE TABLE orders (id INTEGER PRIMARY KEY, company_id INTEGER, status TEXT)")
	authzTable(t, app, "catalog", "CREATE TABLE catalog (id INTEGER PRIMARY KEY, status TEXT)")
	app.Group = &GroupConfig{Table: "company_members", Key: "company_id", UserField: "user_id", RoleField: "member_role",
		Bootstrap: &GroupBootstrapConfig{OrgTable: "companies", FoundingRole: "admin"}}
	mustExec(t, app.DB, "INSERT INTO companies (id, name) VALUES (1, 'Acme')")
	f := &roleAdminApp{app: app}
	member := func(email, column, tenantRole string) (int64, string) {
		uid := authzUser(t, app, email, column)
		if tenantRole != "" {
			mustExecArgs(t, app.DB, "INSERT INTO company_members (company_id, user_id, member_role) VALUES (1, ?, ?)", uid, tenantRole)
		}
		sid := CreateSession(app.DB, uid, email, "1", time.Hour)
		if sid == "" {
			t.Fatal("CreateSession failed")
		}
		return uid, sid
	}
	f.tenantAdminID, f.tenantAdmin = member("tenant-admin@example.com", "user", "admin")
	f.tenantApproverID, f.tenantApprover = member("tenant-approver@example.com", "user", "approver")
	f.columnAdminID, f.columnAdmin = member("column-admin@example.com", "admin", "")
	f.grantAdminID, f.grantAdmin = member("grant-admin@example.com", "user", "viewer")
	mustExecArgs(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (?, 'admin')", f.grantAdminID)

	founder := f.session(t, f.tenantAdmin)
	if founder.IsAdmin() || !HasAnyRole(founder, []string{"admin"}) {
		t.Fatalf("the tenant admin should hold the tenant role admin and no global admin: %+v", founder)
	}
	if !f.session(t, f.grantAdmin).IsAdmin() || !f.session(t, f.columnAdmin).IsAdmin() {
		t.Fatal("the column admin and the grant admin should both be global admins")
	}
	return f
}

func (f *roleAdminApp) session(t *testing.T, sid string) *Session {
	t.Helper()
	s := getSession(f.app, authzReq("GET", "/", sid, ""))
	if s == nil {
		t.Fatal("no session")
	}
	return s
}

// A transition `role: admin` on a table without the tenant key is the app's
// global admin, as a `role:admin` access rule there is. A tenant membership
// role named admin used to pass it: the table has no tenant column to bound
// the role, so every tenant's admin (with groups.bootstrap.founding_role
// "admin", every account that founds a tenant) could make the transition.
func TestWorkflowRoleAdminOnUngroupedTableNeedsGlobalAdmin(t *testing.T) {
	f := newRoleAdminApp(t)
	app := f.app
	catalog := &Workflow{Name: "catalog", Table: "catalog", Field: "status", Initial: "draft",
		States: []string{"draft", "published", "reviewed", "archived"},
		Transitions: map[string]map[string]Transition{"draft": {
			"published": {Role: "admin"},
			"reviewed":  {Role: "approver"},
			"archived":  {Role: "approver,admin"},
		}}}
	orders := &Workflow{Name: "orders", Table: "orders", Field: "status", Initial: "pending",
		States:      []string{"pending", "approved"},
		Transitions: map[string]map[string]Transition{"pending": {"approved": {Role: "admin"}}}}
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"catalog": catalog, "orders": orders}}
	// Every signed-in user may edit a catalog row; the transition role is the
	// only gate on who moves its state.
	app.Access = accessFromYAML(t, "access:\n  catalog: {all: everyone}\n")

	nextID := 0
	transition := func(wf *Workflow, sid, to string) (int, string) {
		t.Helper()
		nextID++
		id := fmt.Sprint(nextID)
		if wf.Table == "orders" {
			mustExec(t, app.DB, "INSERT INTO orders (id, company_id, status) VALUES ("+id+", 1, 'pending')")
		} else {
			mustExec(t, app.DB, "INSERT INTO catalog (id, status) VALUES ("+id+", 'draft')")
		}
		w := httptest.NewRecorder()
		r := authzReq("POST", "/api/"+wf.Table+"/"+id+"/transition", sid, `{"to":"`+to+`"}`)
		r.SetPathValue("id", id)
		handleTransition(w, r, app, wf)
		var state string
		if err := app.DB.QueryRow("SELECT status FROM "+wf.Table+" WHERE id = ?", id).Scan(&state); err != nil {
			t.Fatal(err)
		}
		return w.Code, state
	}
	for _, tc := range []struct {
		name     string
		wf       *Workflow
		sid, to  string
		wantCode int
	}{
		{"tenant admin, role: admin, table without the tenant key", catalog, f.tenantAdmin, "published", http.StatusForbidden},
		{"tenant admin, role: [approver, admin], table without the tenant key", catalog, f.tenantAdmin, "archived", http.StatusForbidden},
		{"tenant approver, role: [approver, admin], table without the tenant key", catalog, f.tenantApprover, "archived", http.StatusOK},
		{"tenant approver, role: approver, table without the tenant key", catalog, f.tenantApprover, "reviewed", http.StatusOK},
		{"tenant approver, role: admin", catalog, f.tenantApprover, "published", http.StatusForbidden},
		{"admin by column, role: admin, table without the tenant key", catalog, f.columnAdmin, "published", http.StatusOK},
		{"admin by global grant, role: admin, table without the tenant key", catalog, f.grantAdmin, "published", http.StatusOK},
		{"tenant admin, role: admin, tenant-keyed table", orders, f.tenantAdmin, "approved", http.StatusOK},
		{"tenant approver, role: admin, tenant-keyed table", orders, f.tenantApprover, "approved", http.StatusForbidden},
	} {
		code, state := transition(tc.wf, tc.sid, tc.to)
		want := tc.wf.Initial
		if tc.wantCode == http.StatusOK {
			want = tc.to
		}
		if code != tc.wantCode || state != want {
			t.Errorf("%s: transition status %d, stored state %q; want %d and %q", tc.name, code, state, tc.wantCode, want)
		}
	}

	// The listing a page or client builds its buttons from agrees.
	tenantAdmin := f.session(t, f.tenantAdmin)
	for _, move := range availableWorkflowMoves(app, catalog, tenantAdmin, map[string]any{"id": int64(1), "status": "draft"}) {
		t.Errorf("the tenant admin is offered catalog transition %q", move.To)
	}

	// An approved command checks the same guard inside its transaction.
	command := func(s *Session, table, role string) bool {
		t.Helper()
		tx, err := app.DB.BeginTx(context.Background(), nil)
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		cap := &appMCPCommandCapability{actor: *s, generation: &appMCPRuntimeGeneration{view: app}}
		return appMCPCommandHasWorkflowRole(cap, appMCPContextTx{tx: tx, ctx: context.Background()}, table, role)
	}
	tenantApprover := f.session(t, f.tenantApprover)
	for _, tc := range []struct {
		name        string
		s           *Session
		table, role string
		want        bool
	}{
		{"tenant admin, catalog, admin", tenantAdmin, "catalog", "admin", false},
		{"tenant admin, catalog, approver,admin", tenantAdmin, "catalog", "approver,admin", false},
		{"tenant approver, catalog, approver,admin", tenantApprover, "catalog", "approver,admin", true},
		{"tenant admin, orders, admin", tenantAdmin, "orders", "admin", true},
		{"admin by grant, catalog, admin", f.session(t, f.grantAdmin), "catalog", "admin", true},
	} {
		if got := command(tc.s, tc.table, tc.role); got != tc.want {
			t.Errorf("command guard, %s: %t, want %t", tc.name, got, tc.want)
		}
		if got := hasWorkflowRole(app, tc.s, tc.table, tc.role); got != tc.want {
			t.Errorf("transition guard, %s: %t, want %t", tc.name, got, tc.want)
		}
	}

	// A table the app lists in groups.shared keeps counting tenant roles, as
	// its `role:` access rule does.
	app.Group.Shared = []string{"catalog"}
	if !hasWorkflowRole(app, tenantAdmin, "catalog", "admin") || !tableModeAllowed(app, "catalog", OpUpdate, "role:admin", tenantAdmin, 0) {
		t.Error("on a groups.shared table the tenant admin should pass role: admin, on the transition and the access rule alike")
	}
	if !command(tenantAdmin, "catalog", "admin") {
		t.Error("on a groups.shared table the command guard should pass the tenant admin")
	}
}

// `{{#role "admin"}}` opens for the app's global admin only, and a tenant
// role named admin opens no other role's section. A held "admin" from any
// source (the membership role included) used to open every role section.
func TestRoleSectionAdminIsTheGlobalAdmin(t *testing.T) {
	f := newRoleAdminApp(t)
	page := &Page{Route: "/roles", RawHTML: `<p>{{user.app_role}}</p>` +
		`{{#role "admin"}}ADMIN_SECTION{{/role}}` +
		`{{#role "approver"}}APPROVER_SECTION{{/role}}` +
		`{{#role "billing,admin"}}BILLING_OR_ADMIN_SECTION{{/role}}` +
		`{{#role "approver,billing"}}APPROVER_OR_BILLING_SECTION{{/role}}`}
	render := func(sid string) string {
		t.Helper()
		w := httptest.NewRecorder()
		servePage(w, authzReq("GET", "/roles", sid, ""), f.app, page, false)
		if w.Code != http.StatusOK {
			t.Fatalf("page=%d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	sections := []string{"ADMIN_SECTION", "APPROVER_SECTION", "BILLING_OR_ADMIN_SECTION", "APPROVER_OR_BILLING_SECTION"}
	for _, tc := range []struct {
		name, sid string
		open      []string
	}{
		{"tenant admin", f.tenantAdmin, nil},
		{"tenant approver", f.tenantApprover, []string{"APPROVER_SECTION", "APPROVER_OR_BILLING_SECTION"}},
		{"admin by column", f.columnAdmin, sections},
		{"admin by global grant", f.grantAdmin, sections},
	} {
		html := render(tc.sid)
		for _, section := range sections {
			want := false
			for _, o := range tc.open {
				want = want || o == section
			}
			if got := strings.Contains(html, section); got != want {
				t.Errorf("%s: section %s rendered=%t, want %t", tc.name, section, got, want)
			}
		}
	}
	if html := render(f.tenantAdmin); !strings.Contains(html, "<p>admin</p>") {
		t.Errorf("the tenant admin's user.app_role should still read admin: %s", html)
	}
}

// The docs page list names a role-gated page for exactly the callers the page
// route admits. It used to match the role against every role in the session
// (tenant roles included, no hierarchy), so it listed a page the route
// refused and left out one the route served.
func TestDocsPageListFollowsThePageRoleGate(t *testing.T) {
	f := newRoleAdminApp(t)
	app := f.app
	managerID := authzUser(t, app, "manager@example.com", "manager")
	manager := CreateSession(app.DB, managerID, "manager@example.com", "", time.Hour)
	grantedID := authzUser(t, app, "granted-approver@example.com", "user")
	mustExecArgs(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (?, 'approver')", grantedID)
	granted := CreateSession(app.DB, grantedID, "granted-approver@example.com", "", time.Hour)
	app.Pages = map[string]*Page{
		"/admin-only": {Route: "/admin-only", File: "admin-only.html", Role: "admin", RawHTML: "ok"},
		"/approvals":  {Route: "/approvals", File: "approvals.html", Role: "approver", RawHTML: "ok"},
		"/editors":    {Route: "/editors", File: "editors.html", Role: "editor", RawHTML: "ok"},
		"/open":       {Route: "/open", File: "open.html", RawHTML: "ok"},
	}
	listed := func(sid, route string) bool {
		t.Helper()
		docs := generateAPIDocs(app, docsViewerFor(f.session(t, sid)))
		pages, ok := docs["pages"].([]map[string]string)
		if !ok {
			t.Fatalf("docs pages: %T", docs["pages"])
		}
		inJSON := false
		for _, p := range pages {
			inJSON = inJSON || p["route"] == route
		}
		if inMarkdown := strings.Contains(renderDocsMarkdownFor(app, docsViewerFor(f.session(t, sid))), "`"+route+"`"); inMarkdown != inJSON {
			t.Errorf("%s: the JSON docs list it=%t, the Markdown docs=%t", route, inJSON, inMarkdown)
		}
		return inJSON
	}
	served := func(sid, route string) bool {
		t.Helper()
		w := httptest.NewRecorder()
		RoleMiddleware(app, app.Pages[route], func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })(w, authzReq("GET", route, sid, ""))
		return w.Code == http.StatusOK
	}
	for _, tc := range []struct {
		name, sid, route string
		want             bool
	}{
		{"tenant admin, role=admin page", f.tenantAdmin, "/admin-only", false},
		{"tenant approver, role=approver page", f.tenantApprover, "/approvals", false},
		{"manager, role=editor page", manager, "/editors", true},
		{"manager, role=admin page", manager, "/admin-only", false},
		{"approver by global grant, role=approver page", granted, "/approvals", true},
		{"tenant approver, ungated page", f.tenantApprover, "/open", true},
	} {
		if tc.route != "/open" {
			if got := served(tc.sid, tc.route); got != tc.want {
				t.Fatalf("%s: the page route serves it=%t; the test expects %t", tc.name, got, tc.want)
			}
		}
		if got := listed(tc.sid, tc.route); got != tc.want {
			t.Errorf("%s: docs list the page=%t, the route serves it=%t", tc.name, got, tc.want)
		}
	}
}

// `benmore check` and the post-write check say, for each gate that reads
// `admin` as the global admin, that the app's tenant admins do not pass it.
// Only a flow's gate was reported.
func TestCheckWarnsWhereTenantAdminsDoNotPassAnAdminGate(t *testing.T) {
	write := func(dir, foundingRole string) {
		writeTestFile(t, dir, "app.yaml", `groups:
  table: company_members
  key: company_id
  user_field: user_id
  role_field: member_role
  bootstrap:
    org_table: companies
    founding_role: `+foundingRole+`
`)
		writeTestFile(t, dir, "schema.prisma", `model Company {
  id   Int    @id @default(autoincrement())
  name String
  @@map("companies")
}

model CompanyMember {
  id         Int    @id @default(autoincrement())
  companyId  Int    @map("company_id")
  userId     Int    @map("user_id")
  memberRole String @default("member") @map("member_role")
  @@map("company_members")
}

model Order {
  id        Int    @id @default(autoincrement())
  companyId Int    @map("company_id")
  status    String @default("pending")
  @@map("orders")
}

model CatalogItem {
  id     Int    @id @default(autoincrement())
  status String @default("draft")
  @@map("catalog")
}
`)
		writeTestFile(t, dir, "workflows.yaml", `catalog:
  table: catalog
  field: status
  initial: draft
  transitions:
    draft:
      published: { role: admin }
      archived: { role: [member, Admin] }
orders:
  table: orders
  field: status
  initial: pending
  transitions:
    pending:
      approved: { role: admin }
`)
		writeTestFile(t, dir, "team.html", `<page title="Team" role="member, admin">
<h1>Team</h1>
{{#role "admin"}}<a href="/invite">Invite</a>{{/role}}
{{#role "member"}}<p>Member</p>{{/role}}
</page>
`)
		writeTestFile(t, dir, "partials/nav.html", `<nav>{{#role 'billing,admin'}}<a href="/billing">Billing</a>{{/role}}</nav>
`)
	}
	warnings := func(report CheckReport) []string {
		var out []string
		for _, f := range report.Findings {
			if f.Severity == "warning" && strings.Contains(f.Message, "tenant admin does NOT pass") && f.Source != "flows" {
				out = append(out, f.File+": "+f.Message)
			}
		}
		return out
	}
	has := func(list []string, parts ...string) bool {
		for _, msg := range list {
			all := true
			for _, part := range parts {
				all = all && strings.Contains(msg, part)
			}
			if all {
				return true
			}
		}
		return false
	}

	dir := t.TempDir()
	write(dir, "admin")
	all := warnings(RunSourceCheck(dir, ""))
	for _, want := range [][]string{
		{"workflows.yaml: ", "catalog.transitions.draft -> published", "transition_roles"},
		{"workflows.yaml: ", "catalog.transitions.draft -> archived"},
		{"team.html: ", `role="member, admin"`, "ssr_page_gates"},
		{"team.html: ", `{{#role "admin"}}`, "user.app_role"},
		{"partials/nav.html: ", `{{#role "billing,admin"}}`},
	} {
		if !has(all, want...) {
			t.Errorf("no warning with %q in:\n%s", want, strings.Join(all, "\n"))
		}
	}
	if has(all, "orders.transitions") {
		t.Errorf("a transition on a table that carries the tenant key is reported:\n%s", strings.Join(all, "\n"))
	}
	if len(all) != 5 {
		t.Errorf("%d warnings, want 5:\n%s", len(all), strings.Join(all, "\n"))
	}
	// A write of one file reports that file's gates.
	if got := warnings(RunSourceCheck(dir, "team.html")); len(got) != 2 || !has(got, "team.html: ") {
		t.Errorf("after a write of team.html: %q", got)
	}
	if got := warnings(RunSourceCheck(dir, "workflows.yaml")); len(got) != 2 || !has(got, "workflows.yaml: ") {
		t.Errorf("after a write of workflows.yaml: %q", got)
	}
	if got := warnings(RunSourceCheck(dir, "static/app.css")); len(got) != 0 {
		t.Errorf("after a write of an unrelated file: %q", got)
	}

	// A table the app lists in groups.shared counts tenant roles: no warning.
	appYAML, err := os.ReadFile(filepath.Join(dir, "app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "app.yaml", strings.Replace(string(appYAML), "  role_field: member_role\n", "  role_field: member_role\n  shared: [catalog]\n", 1))
	if got := warnings(RunSourceCheck(dir, "")); has(got, "workflows.yaml: ") || len(got) != 3 {
		t.Errorf("with catalog in groups.shared: %q", got)
	}

	// No tenant member can hold a role named admin: nothing to say.
	quiet := t.TempDir()
	write(quiet, "org_admin")
	if got := warnings(RunSourceCheck(quiet, "")); len(got) != 0 {
		t.Errorf("an app whose tenant roles are not named admin is warned: %q", got)
	}
}
