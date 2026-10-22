//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// authzApp is a test app with the auth tables and a helper that creates a
// table and registers its columns on app.Tables.
func authzApp(t *testing.T) *App {
	t.Helper()
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	EnsureSessionsTable(app.DB)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatalf("EnsureUsersTable: %v", err)
	}
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatalf("EnsureUserRolesTable: %v", err)
	}
	mustExec(t, app.DB, `CREATE TABLE IF NOT EXISTS _benmore_permissions (resource_type TEXT, resource_id INTEGER, grant_type TEXT, grantee_id TEXT, permission TEXT, expires_at TEXT)`)
	return app
}

func authzTable(t *testing.T, app *App, name, ddl string) {
	t.Helper()
	mustExec(t, app.DB, ddl)
	cols, err := GetTableColumns(app.DB, name)
	if err != nil {
		t.Fatalf("columns %s: %v", name, err)
	}
	app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
}

func authzUser(t *testing.T, app *App, email, role string) int64 {
	t.Helper()
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, ?, 1)", email, email, role)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	id, _ := res.LastInsertId()
	return id
}

func authzSession(t *testing.T, app *App, uid int64, email string, scopes ...string) string {
	t.Helper()
	sid := CreateSession(app.DB, uid, email, "", time.Hour, scopes...)
	if sid == "" {
		t.Fatal("CreateSession failed")
	}
	return sid
}

func authzReq(method, target, sid, body string) *http.Request {
	r := httptest.NewRequest(method, "https://app.example.com"+target, strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/json")
	}
	if sid != "" {
		r.Header.Set("Authorization", "Bearer "+sid)
	}
	return r
}

func accessFromYAML(t *testing.T, y string) *AccessConfig {
	t.Helper()
	a, err := parseAccessConfig([]byte(y))
	if err != nil || a == nil {
		t.Fatalf("parse access: %v", err)
	}
	return a
}

// ---- Finding 1: tenant "admin" is not a global admin ----

func TestHasAnyRole_TenantAdminDoesNotPassOtherRoleGates(t *testing.T) {
	tenantAdmin := &Session{Role: "user", Roles: []string{"user", "admin"}}
	if HasAnyRole(tenantAdmin, []string{"staff"}) {
		t.Error("a tenant (membership) admin role must not satisfy role:staff")
	}
	if !HasAnyRole(tenantAdmin, []string{"admin"}) {
		t.Error("a tenant admin role still matches a literal role:admin gate")
	}
	if !HasAnyRole(&Session{Role: "admin"}, []string{"staff"}) {
		t.Error("a users.role admin is a global admin and passes every role gate")
	}
	if !HasAnyRole(&Session{Role: "user", GlobalAdmin: true}, []string{"staff"}) {
		t.Error("a global admin grant passes every role gate")
	}
}

// End to end: a signup bootstraps a tenant with founding_role "admin", then
// must not pass role:staff, must not bypass row scoping, and on an
// un-grouped owner_or_role:admin table must see only its own rows.
func TestFoundingAdminCannotEscalateAcrossTenants(t *testing.T) {
	app := authzApp(t)
	authzTable(t, app, "companies", "CREATE TABLE companies (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL)")
	authzTable(t, app, "company_members", "CREATE TABLE company_members (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, email TEXT, user_id INTEGER, member_role TEXT)")
	authzTable(t, app, "notes", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT)")
	app.Group = &GroupConfig{Table: "company_members", Key: "company_id", UserField: "email", RoleField: "member_role",
		Bootstrap: &GroupBootstrapConfig{OrgTable: "companies", FoundingRole: "admin"}}
	app.Access = accessFromYAML(t, "access:\n  notes:\n    read: owner_or_role:admin\n  reports: role:staff\n")

	victim := authzUser(t, app, "victim@example.com", "user")
	attacker := authzUser(t, app, "mallory@example.com", "user")
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO notes (id, user_id, title) VALUES (1, %d, 'victim'), (2, %d, 'mine')", victim, attacker))

	sid := authzSession(t, app, attacker, "mallory@example.com")
	w := httptest.NewRecorder()
	handleGroupBootstrap(w, authzReq("POST", "/api/_groups/create", sid, `{"name":"Evil"}`), app)
	if w.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	s := getSession(app, authzReq("GET", "/", sid, ""))
	if s == nil || !HasAnyRole(s, []string{"admin"}) {
		t.Fatalf("founder should hold the tenant role admin, got %+v", s)
	}
	if s.IsAdmin() || s.IsAdminBypass() {
		t.Fatal("tenant admin must not be a global admin")
	}
	if app.Access.Allowed("role:staff", s, 0) {
		t.Fatal("tenant admin must not pass role:staff")
	}
	if got := visibleIDs(t, app, "notes", s); got != "2" {
		t.Fatalf("tenant admin on an un-grouped owner_or_role:admin table must see only own rows, got %q", got)
	}

	// A GLOBAL grant of the role still widens to every row.
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO _benmore_user_roles (user_id, role) VALUES (%d, 'admin')", attacker))
	if got := visibleIDs(t, app, "notes", s); got != "1,2" {
		t.Fatalf("a global role grant should see every row, got %q", got)
	}
	// And a global admin bypasses outright.
	if _, _, bypass := rowScopeClause(app, "notes", &Session{UserID: 99, Role: "admin"}, "view"); !bypass {
		t.Fatal("global admin must bypass row scoping")
	}
}

func visibleIDs(t *testing.T, app *App, table string, s *Session) string {
	t.Helper()
	q := "SELECT id FROM " + table
	pred, args, bypass := rowScopeClause(app, table, s, "view")
	if !bypass && pred != "" {
		q += " WHERE " + pred
	}
	rows, err := app.DB.Query(q+" ORDER BY id", args...)
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	defer func() { _ = rows.Close() }()
	var ids []string
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	return strings.Join(ids, ",")
}

// ---- Finding 2: perm: fails closed ----

func TestPermModeFailsClosedWithoutRoles(t *testing.T) {
	noRoles := accessFromYAML(t, "access:\n  posts:\n    write: perm:posts.publish\n")
	if noRoles.Allowed("perm:posts.publish", &Session{UserID: 1}, 0) {
		t.Error("cookie session in an app without roles: must not pass perm:")
	}
	if noRoles.Allowed("perm:posts.publish", &Session{UserID: 1, Scopes: "posts:publish"}, 0) {
		t.Error("a self-minted token scope must not pass perm: in an app without roles:")
	}
	withRoles := accessFromYAML(t, "roles:\n  editor:\n    scopes: \"posts:publish\"\naccess:\n  posts:\n    write: perm:posts.publish\n")
	if !withRoles.Allowed("perm:posts.publish", &Session{UserID: 1, Scopes: "posts:publish"}, 0) {
		t.Error("a role-granted permission should pass perm:")
	}
	if withRoles.Allowed("perm:posts.publish", &Session{UserID: 1, Scopes: "posts:read"}, 0) {
		t.Error("a role without the permission must not pass")
	}
	if HasPermission(&Session{UserID: 1}, "posts:publish") {
		t.Error("an empty permission set grants nothing")
	}
	if msg := validateAuthzAppYAML("access:\n  posts:\n    write: perm:posts.publish\n"); msg == "" {
		t.Error("perm: without roles: should be a write-time error")
	}
	if msg := validateAuthzAppYAML("roles:\n  editor:\n    scopes: \"posts:publish\"\naccess:\n  posts:\n    write: perm:posts.publish\n"); msg != "" {
		t.Errorf("perm: with roles: is valid, got %q", msg)
	}
}

// ---- Finding 3: admin console endpoints refuse delegated credentials ----

func TestAdminEndpointsRequireAdminConsole(t *testing.T) {
	app := authzApp(t)
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"admin": {Scopes: "*"}}}
	mux := http.NewServeMux()
	RegisterRoleRoutes(mux, app)
	admin := authzUser(t, app, "admin@example.com", "admin")
	other := authzUser(t, app, "u@example.com", "user")

	full := authzSession(t, app, admin, "admin@example.com")
	scoped := authzSession(t, app, admin, "admin@example.com", "notes:read")
	for _, c := range []struct {
		path, sid string
		want      int
	}{
		{"/api/_auth/roles", full, http.StatusOK},
		{"/api/_auth/roles", scoped, http.StatusForbidden},
		{fmt.Sprintf("/api/_auth/users/%d/roles", other), full, http.StatusOK},
		{fmt.Sprintf("/api/_auth/users/%d/roles", other), scoped, http.StatusForbidden},
		{fmt.Sprintf("/api/_auth/users/%d/roles", admin), scoped, http.StatusOK},
	} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, authzReq("GET", c.path, c.sid, ""))
		if w.Code != c.want {
			t.Errorf("GET %s (%s): %d want %d: %s", c.path, map[bool]string{true: "full", false: "scoped"}[c.sid == full], w.Code, c.want, w.Body.String())
		}
	}
}

func TestNotificationsHonorCredentialScopes(t *testing.T) {
	app := authzApp(t)
	mux := http.NewServeMux()
	RegisterNotificationRoutes(mux, app)
	admin := authzUser(t, app, "admin@example.com", "admin")
	other := authzUser(t, app, "u@example.com", "user")
	nid, err := CreateNotification(app.DB, other, "hi", "body", "info", "")
	if err != nil {
		t.Fatal(err)
	}

	do := func(method, path, sid string) int {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, authzReq(method, path, sid, ""))
		return w.Code
	}
	if c := do("GET", "/api/_notifications", authzSession(t, app, other, "u@example.com", "notes:read")); c != http.StatusForbidden {
		t.Errorf("notes:read token listing notifications: %d want 403", c)
	}
	if c := do("GET", "/api/_notifications/count", authzSession(t, app, other, "u@example.com", "notes:read")); c != http.StatusForbidden {
		t.Errorf("notes:read token reading the count: %d want 403", c)
	}
	if c := do("GET", "/api/_notifications", authzSession(t, app, other, "u@example.com", "_notifications:read")); c != http.StatusOK {
		t.Errorf("_notifications:read token: %d want 200", c)
	}
	if c := do("GET", "/api/_notifications", authzSession(t, app, other, "u@example.com")); c != http.StatusOK {
		t.Errorf("full session: %d want 200", c)
	}
	// A scoped admin token may not delete another user's notification.
	path := fmt.Sprintf("/api/_notifications/%d", nid)
	if c := do("DELETE", path, authzSession(t, app, admin, "admin@example.com", "_notifications:write")); c != http.StatusNotFound {
		t.Errorf("scoped admin deleting another user's notification: %d want 404", c)
	}
	if c := do("DELETE", path, authzSession(t, app, admin, "admin@example.com")); c != http.StatusOK {
		t.Errorf("admin console deleting: %d want 200", c)
	}
}

// ---- Finding 4: workflow before-hooks see the target state ----

func TestWorkflowTransitionBeforeHookSeesTargetState(t *testing.T) {
	app := authzApp(t)
	EnsureAuditLogTable(app.DB)
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	authzTable(t, app, "docs", "CREATE TABLE docs (id INTEGER PRIMARY KEY, user_id INTEGER, status TEXT)")
	uid := authzUser(t, app, "a@example.com", "user")
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO docs (id, user_id, status) VALUES (1, %d, 'draft')", uid))
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{
		"docs": {{SQL: "SELECT 'approval needs a reviewer' AS error WHERE {{status}} = 'approved'"}},
	}}
	wf := &Workflow{Table: "docs", Field: "status", Transitions: map[string]map[string]Transition{
		"draft": {"approved": {}, "review": {}},
	}}
	sid := authzSession(t, app, uid, "a@example.com")

	w := httptest.NewRecorder()
	r := authzReq("POST", "/api/docs/1/transition", sid, `{"to":"approved"}`)
	r.SetPathValue("id", "1")
	handleTransition(w, r, app, wf)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("guard on the new state must fire: %d %s", w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	r = authzReq("POST", "/api/docs/1/transition", sid, `{"to":"review"}`)
	r.SetPathValue("id", "1")
	handleTransition(w, r, app, wf)
	if w.Code != http.StatusOK {
		t.Fatalf("other transition: %d %s", w.Code, w.Body.String())
	}

	// Available transitions need read scope on the table.
	w = httptest.NewRecorder()
	r = authzReq("GET", "/api/docs/1/transitions", authzSession(t, app, uid, "a@example.com", "other:read"), "")
	r.SetPathValue("id", "1")
	handleAvailableTransitions(w, r, app, wf)
	if w.Code != http.StatusForbidden {
		t.Fatalf("token without docs:read: %d want 403", w.Code)
	}
}

// ---- Findings 5 + 7: include audit and per-parent cap ----

func TestIncludeChildrenCappedAndAudited(t *testing.T) {
	app := authzApp(t)
	authzTable(t, app, "projects", "CREATE TABLE projects (id INTEGER PRIMARY KEY, title TEXT)")
	authzTable(t, app, "tasks", "CREATE TABLE tasks (id INTEGER PRIMARY KEY, project_id INTEGER, title TEXT)")
	app.JoinMap = JoinMap{"tasks": {"project_id": {Table: "projects", Column: "id"}}}
	app.Access = accessFromYAML(t, "access:\n  projects: everyone\n  tasks: everyone\n")
	app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "tasks"}}
	EnsureReadAuditTable(app.DB)
	app.readAudit = &readAuditBuffer{db: app.DB, sync: true}
	mustExec(t, app.DB, "INSERT INTO projects (id, title) VALUES (1, 'big'), (2, 'small')")
	for i := 1; i <= maxIncludeChildrenPerParent+50; i++ {
		mustExec(t, app.DB, fmt.Sprintf("INSERT INTO tasks (id, project_id, title) VALUES (%d, 1, 't')", i))
	}
	mustExec(t, app.DB, "INSERT INTO tasks (id, project_id, title) VALUES (1000, 2, 'a'), (1001, 2, 'b')")

	rows := []map[string]any{{"id": int64(1)}, {"id": int64(2)}}
	session := &Session{UserID: 7, Email: "v@example.com"}
	ResolveIncludes(app, "projects", rows, "tasks", session)

	big, _ := rows[0]["tasks"].([]map[string]any)
	if len(big) != maxIncludeChildrenPerParent {
		t.Fatalf("big project children = %d, want cap %d", len(big), maxIncludeChildrenPerParent)
	}
	if fmt.Sprint(big[0]["id"]) != "1" || fmt.Sprint(big[len(big)-1]["id"]) != fmt.Sprint(maxIncludeChildrenPerParent) {
		t.Fatalf("cap should keep the lowest ids, got %v..%v", big[0]["id"], big[len(big)-1]["id"])
	}
	if _, leaked := big[0][includeRankColumn]; leaked {
		t.Fatal("rank column must be stripped")
	}
	if m, _ := rows[0][includeTruncatedKey].([]string); len(m) != 1 || m[0] != "tasks" {
		t.Fatalf("big project should be marked truncated, got %v", rows[0][includeTruncatedKey])
	}
	small, _ := rows[1]["tasks"].([]map[string]any)
	if len(small) != 2 || rows[1][includeTruncatedKey] != nil {
		t.Fatalf("small project: %d children, marker %v", len(small), rows[1][includeTruncatedKey])
	}
	var n int
	_ = app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_read_audit WHERE table_name='tasks' AND query_type='include' AND user_id=7").Scan(&n)
	if n != 1 {
		t.Fatalf("include of an audited table should log one read-audit entry, got %d", n)
	}
}

func TestAsOfAndVersionReadsAreAudited(t *testing.T) {
	app := authzApp(t)
	authzTable(t, app, "notes", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, created_at DATETIME DEFAULT '2020-01-01 00:00:00')")
	uid := authzUser(t, app, "a@example.com", "user")
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO notes (id, user_id, title) VALUES (1, %d, 'x')", uid))
	app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "*"}}
	EnsureReadAuditTable(app.DB)
	app.readAudit = &readAuditBuffer{db: app.DB, sync: true}
	sid := authzSession(t, app, uid, "a@example.com")

	w := httptest.NewRecorder()
	handleRead(w, authzReq("GET", "/api/notes/1?as_of=2030-01-01T00:00:00Z", sid, ""), app, "notes")
	if w.Code != http.StatusOK {
		t.Fatalf("as_of read: %d %s", w.Code, w.Body.String())
	}
	var n int
	_ = app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_read_audit WHERE query_type='as_of' AND row_id='1'").Scan(&n)
	if n != 1 {
		t.Fatalf("as_of read should be audited, got %d entries", n)
	}
}

// ---- Finding 6: docs never list hidden columns ----

func TestDocsOmitHiddenColumns(t *testing.T) {
	app := authzApp(t)
	authzTable(t, app, "integrations", "CREATE TABLE integrations (id INTEGER PRIMARY KEY, name TEXT, api_key TEXT, public_key TEXT)")
	app.Access = accessFromYAML(t, "access:\n  integrations: everyone\n")
	docs, _ := json.Marshal(generateAPIDocs(app, fullDocs))
	schema, _ := json.Marshal(generateRichSchema(app, &Session{UserID: 1, Role: "admin"}))
	openapi := openAPISchemaForTable(app, app.Tables[len(app.Tables)-1])
	for name, out := range map[string]string{"docs": string(docs), "schema": string(schema)} {
		if strings.Contains(out, `"api_key"`) {
			t.Errorf("%s lists the hidden column api_key", name)
		}
		if !strings.Contains(out, `"public_key"`) {
			t.Errorf("%s should still list public_key", name)
		}
	}
	if props, _ := openapi["properties"].(map[string]any); props["api_key"] != nil || props["name"] == nil {
		t.Errorf("OpenAPI read schema: %v", props)
	}
	if md := renderDocsMarkdownFor(app, fullDocs); strings.Contains(md, "api_key") {
		t.Error("markdown docs list api_key")
	}
}

// ---- Finding 8: deterministic tenant resolution ----

func TestResolveGroupIDIsDeterministic(t *testing.T) {
	app := authzApp(t)
	mustExec(t, app.DB, "CREATE TABLE members (email TEXT, org_id TEXT)")
	// The index would make the planner return the smallest org_id first.
	mustExec(t, app.DB, "CREATE INDEX members_email_org ON members(email, org_id)")
	mustExec(t, app.DB, "INSERT INTO members (email, org_id) VALUES ('a@example.com', 'z-first'), ('a@example.com', 'a-second')")
	authzUser(t, app, "a@example.com", "user")
	g := &GroupConfig{Table: "members", Key: "org_id", UserField: "email"}
	if got := ResolveGroupID(app.DB, g, "a@example.com"); got != "z-first" {
		t.Fatalf("ResolveGroupID = %q, want the oldest membership z-first", got)
	}
}

// ---- Finding 9: bootstrap honors the org table's declared write mode ----

func TestBootstrapHonorsOrgWriteMode(t *testing.T) {
	for _, c := range []struct {
		yaml string
		want int
	}{
		{"access:\n  companies:\n    write: admin\n", http.StatusForbidden},
		{"access:\n  companies:\n    write: role:sales\n", http.StatusForbidden},
		{"access:\n  companies:\n    read: group\n    write: off\n", http.StatusOK},
		{"access:\n  companies: group\n", http.StatusOK},
		{"access:\n  default:\n    write: admin\n", http.StatusOK},
	} {
		app, uid, cleanup := newBootstrapTestApp(t, "email")
		app.Access = accessFromYAML(t, c.yaml)
		sid := CreateSession(app.DB, uid, "founder@example.com", "", time.Hour)
		w := bootstrapAs(app, sid, `{"name":"Acme"}`)
		if w.Code != c.want {
			t.Errorf("%q: %d want %d: %s", c.yaml, w.Code, c.want, w.Body.String())
		}
		cleanup()
	}
}

// ---- Finding 11: single-row read matches the list's broad read ----

func TestHandleReadHonorsEveryoneMode(t *testing.T) {
	app := authzApp(t)
	authzTable(t, app, "posts", "CREATE TABLE posts (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT)")
	app.Access = accessFromYAML(t, "access:\n  posts:\n    read: everyone\n")
	author := authzUser(t, app, "a@example.com", "user")
	reader := authzUser(t, app, "b@example.com", "user")
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO posts (id, user_id, title) VALUES (1, %d, 'hello')", author))
	w := httptest.NewRecorder()
	handleRead(w, authzReq("GET", "/api/posts/1", authzSession(t, app, reader, "b@example.com"), ""), app, "posts")
	if w.Code != http.StatusOK {
		t.Fatalf("everyone-readable row by id: %d %s", w.Code, w.Body.String())
	}
	// Default (self) mode still hides another user's row.
	app.Access = nil
	w = httptest.NewRecorder()
	handleRead(w, authzReq("GET", "/api/posts/1", authzSession(t, app, reader, "b@example.com"), ""), app, "posts")
	if w.Code != http.StatusNotFound {
		t.Fatalf("owner-scoped row read by another user: %d want 404", w.Code)
	}
}

// ---- Finding 10: authorization warnings ----

func TestAuthzWarnings(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.yaml", `groups:
  table: org_members
  key: org_id
  user_field: user_id
  role_field: member_role
  bootstrap:
    org_table: orgs
    founding_role: admin
access:
  rooms: member-of:room_members(room_id, user_id)
  invoices:
    read: everyone
  settings: role:admin
`)
	write("schema.prisma", `model RoomMember {
  id      Int @id @default(autoincrement())
  roomId  Int
  userId  Int
}
model Invoice {
  id     Int    @id @default(autoincrement())
  orgId  String
  total  Int
}
`)
	write("static/app.tsx", "const r = bm.room(`chat:${id}`);\n")
	var msgs []string
	for _, f := range authzWarnings(dir) {
		msgs = append(msgs, f.Message)
	}
	all := strings.Join(msgs, "\n")
	for _, want := range []string{"founding_role is \"admin\"", "access.settings.all", "room_members is a member-of membership table", "invoices carries the tenant key", "static/app.tsx"} {
		if !strings.Contains(all, want) {
			t.Errorf("missing warning %q in:\n%s", want, all)
		}
	}
}
