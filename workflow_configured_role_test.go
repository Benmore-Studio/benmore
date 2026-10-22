//go:build !cli && !windows

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"
)

// The configured membership column is authoritative even while an older role
// column remains in the schema. Global user roles stay ordinary in every case.
func TestWorkflowConfiguredMembershipRole(t *testing.T) {
	for _, tc := range []struct {
		name, current, legacy string
		active                int
		want                  int
	}{
		{"configured_approver", "approver", "viewer", 1, http.StatusOK},
		{"configured_without_legacy", "approver", "viewer", 1, http.StatusOK},
		{"stale_legacy_approver", "viewer", "approver", 1, http.StatusForbidden},
		{"foreign_approver_only", "viewer", "viewer", 1, http.StatusForbidden},
		{"exact_case", "APPROVER", "viewer", 1, http.StatusForbidden},
		{"inactive_approver", "approver", "approver", 0, http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, wf, cleanup := newWorkflowTenantApp(t)
			defer cleanup()
			mustExec(t, app.DB, "ALTER TABLE members ADD COLUMN member_role TEXT")
			mustExec(t, app.DB, "ALTER TABLE members ADD COLUMN active INTEGER DEFAULT 1")
			app.Tables[0].Columns = append(app.Tables[0].Columns, Column{Name: "member_role"}, Column{Name: "active"})
			app.Group.RoleField, app.Group.ActiveField = "member_role", "active"
			uid := workflowTestUser(t, app, "configured@example.com")
			addMember(t, app, "A", uid, "approver")
			addMember(t, app, "B", uid, tc.legacy)
			if _, err := app.DB.Exec("UPDATE members SET member_role='approver' WHERE org_id='A'"); err != nil {
				t.Fatal(err)
			}
			if _, err := app.DB.Exec("UPDATE members SET member_role=?,active=? WHERE org_id='B'", tc.current, tc.active); err != nil {
				t.Fatal(err)
			}
			mustExec(t, app.DB, "INSERT INTO orders(id,org_id,user_id,status) VALUES(1,'B',999,'pending')")
			if tc.name == "configured_without_legacy" {
				mustExec(t, app.DB, "ALTER TABLE members DROP COLUMN role")
				var columns []Column
				for _, col := range app.Tables[0].Columns {
					if col.Name != "role" {
						columns = append(columns, col)
					}
				}
				app.Tables[0].Columns = columns
			}
			sid := CreateSession(app.DB, uid, "configured@example.com", "B", time.Hour)
			w := transitionAs(app, wf, sid, "1", "approved")
			if w.Code != tc.want {
				t.Errorf("transition=%d %s; want %d", w.Code, w.Body.String(), tc.want)
			}
			var state string
			if err := app.DB.QueryRow("SELECT status FROM orders WHERE id=1").Scan(&state); err != nil {
				t.Fatal(err)
			}
			want := "pending"
			if tc.want == http.StatusOK {
				want = "approved"
			}
			if state != want {
				t.Errorf("persisted status=%q; want %q", state, want)
			}
		})
	}
}

func TestCommandWorkflowConfiguredMembershipRole(t *testing.T) {
	for _, tc := range []struct {
		name, current, legacy string
		beforeCommit          string
		allow                 bool
	}{
		{"configured_approver", "approver", "viewer", "", true},
		{"stale_legacy_approver", "viewer", "approver", "", false},
		{"foreign_approver_only", "viewer", "viewer", "", false},
		{"exact_case", "APPROVER", "viewer", "", false},
		{"role_removed_after_approval", "approver", "approver", "UPDATE members SET member_role='viewer' WHERE org_id='17'", false},
		{"membership_removed_after_approval", "approver", "approver", "DELETE FROM members WHERE org_id='17'", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, sid, uid := newUnenrolledCommandProviderTaskFixtureWithManifest(t, hookTaskFlow, "", func(_ *AppMCPManifest, dir string) {
				writeTestFile(t, dir, "schema.sql", `CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL, user_id INTEGER NOT NULL, member_role TEXT, role TEXT);
CREATE TABLE projects (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL);
CREATE TABLE tasks (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, org_id TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, completed_by INTEGER, completed_at TEXT);
CREATE TABLE activities (id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, actor_user_id INTEGER NOT NULL, actor_email TEXT NOT NULL, event TEXT NOT NULL);`)
				writeTestFile(t, dir, "app.yaml", `groups: {table: members, key: org_id, user_field: email, role_field: member_role}
roles:
  editor: {scopes: [tasks:read, tasks:write]}
  user: {scopes: [tasks:read, tasks:write]}
access:
  projects: {all: group}
  tasks: {all: group}
  activities: {all: group}
`)
			})
			if _, err := app.DB.Exec("UPDATE _benmore_users SET role='user' WHERE id=?", uid); err != nil {
				t.Fatal(err)
			}
			actor, err := loadStoredSessionChecked(app.DB, true, sid)
			if err != nil || actor == nil || actor.Role != "user" {
				t.Fatalf("expected ordinary actor: %+v %v", actor, err)
			}
			if _, err := app.DB.Exec("UPDATE members SET member_role=?,role=?", tc.current, tc.legacy); err != nil {
				t.Fatal(err)
			}
			if _, err := app.DB.Exec("INSERT INTO members(org_id,email,user_id,member_role,role) VALUES('99','task-actor@example.com',?,'approver','approver')", uid); err != nil {
				t.Fatal(err)
			}
			if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
				t.Fatal(err)
			}
			g := snapshotAppMCPGeneration(app)
			if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, g); err != nil {
				t.Fatal(err)
			}
			if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, g); err != nil {
				t.Fatal(err)
			}
			commandParityGeneration(app, func(g *appMCPRuntimeGeneration) {
				g.workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"tasks": {Name: "tasks", Table: "tasks", Field: "status", Initial: "open", States: []string{"open", "done"}, Transitions: map[string]map[string]Transition{"open": {"done": {Role: "approver"}}}}}}
				g.view.Workflows = g.workflows
			})
			ensureCommandAuditFixture(t, app)
			EnsureJobsTable(app.DB)
			g = snapshotAppMCPGeneration(app)
			pair, err := createAppMCPNativeGrantFor(context.Background(), app, uid, "17", "configured-role-client", grantFixtureResource, "complete_item", time.Now().UTC())
			if err != nil {
				t.Fatal(err)
			}
			grant, err := readAppMCPGrant(app.DB, pair.GrantID)
			if err != nil {
				t.Fatal(err)
			}
			origin, err := appMCPConnectorOrigin(app, g, grant, &g.manifest.Tools[0], pair.AccessToken, grantFixtureResource)
			if err != nil {
				t.Fatal(err)
			}
			request := appMCPCommandRequest{app: app, generation: g, toolName: "complete_item", origin: origin, now: time.Now().UTC()}
			prepared, err := appMCPPrepareOperation(context.Background(), request, map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
			if err != nil {
				t.Fatal(err)
			}
			approve := request
			approve.origin = appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sid}
			if _, err := appMCPReviewOperation(context.Background(), approve, prepared.ID, "configured-role-review"); err != nil {
				t.Fatal(err)
			}
			if tc.beforeCommit != "" {
				mustExec(t, app.DB, tc.beforeCommit)
			}
			beforeTasks, err := QueryRows(app.DB, "SELECT * FROM tasks ORDER BY id")
			if err != nil {
				t.Fatal(err)
			}
			beforeAudit := hookCount(t, app, "SELECT count(*) FROM _benmore_audit_log WHERE table_name IN ('tasks','activities')")
			beforeJobs := hookCount(t, app, "SELECT count(*) FROM _benmore_jobs")
			committed, err := appMCPCommitOperation(context.Background(), request, prepared.ID)
			if (err == nil) != tc.allow {
				t.Errorf("command error=%v; want allowed=%t", err, tc.allow)
			}
			if !tc.allow && tc.beforeCommit == "" && (err == nil || !strings.Contains(err.Error(), "role 'approver' required")) {
				t.Errorf("wrong refusal: %v", err)
			}
			if !tc.allow {
				assertCommandTaskUnchanged(t, app)
				afterTasks, err := QueryRows(app.DB, "SELECT * FROM tasks ORDER BY id")
				if err != nil || !reflect.DeepEqual(beforeTasks, afterTasks) || hookCount(t, app, "SELECT count(*) FROM _benmore_audit_log WHERE table_name IN ('tasks','activities')") != beforeAudit || hookCount(t, app, "SELECT count(*) FROM _benmore_jobs") != beforeJobs {
					t.Fatalf("refused command changed business rows, audit or jobs: %v", err)
				}
				if hookCount(t, app, "SELECT count(*) FROM activities") != 0 {
					t.Fatal("refused command left an activity")
				}
			} else if committed == nil || committed.Outcome != "applied" || hookCount(t, app, "SELECT count(*) FROM tasks WHERE status='done'") != 1 || hookCount(t, app, "SELECT count(*) FROM activities") != 1 {
				t.Fatalf("approved command did not persist exactly one task and activity: %+v", committed)
			}
		})
	}
}

func TestWorkflowConfiguredRoleResolutionAndPage(t *testing.T) {
	app, _, cleanup := newWorkflowTenantApp(t)
	defer cleanup()
	mustExec(t, app.DB, "ALTER TABLE members ADD COLUMN member_role TEXT")
	mustExec(t, app.DB, "ALTER TABLE members ADD COLUMN deleted_at TEXT")
	app.Tables[0].Columns = append(app.Tables[0].Columns, Column{Name: "member_role"}, Column{Name: "deleted_at"})
	app.Group.RoleField = "member_role"
	uid := workflowTestUser(t, app, "page-role@example.com")
	addMember(t, app, "A", uid, "approver")
	mustExec(t, app.DB, "UPDATE members SET member_role='viewer'")
	sid := CreateSession(app.DB, uid, "page-role@example.com", "A", time.Hour)
	page := &Page{Route: "/role-check", RawHTML: `<p>{{user.app_role}}</p>{{#role "approver"}}PRIVATE_APPROVAL_MARKER{{/role}}`}
	render := func() string {
		r := httptest.NewRequest("GET", "https://app.example.com/role-check", nil)
		r.Header.Set("Authorization", "Bearer "+sid)
		w := httptest.NewRecorder()
		servePage(w, r, app, page, false)
		if w.Code != http.StatusOK {
			t.Fatalf("page=%d %s", w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	if html := render(); strings.Contains(html, "PRIVATE_APPROVAL_MARKER") || !strings.Contains(html, "<p>viewer</p>") {
		t.Fatalf("stale legacy role affected rendered page: %s", html)
	}
	mustExec(t, app.DB, "UPDATE members SET member_role='approver',role='viewer'")
	if html := render(); !strings.Contains(html, "PRIVATE_APPROVAL_MARKER") || !strings.Contains(html, "<p>approver</p>") {
		t.Fatalf("configured role missing from page: %s", html)
	}
	actor := &Session{UserID: uid, Role: "user", GroupID: "A"}
	for _, sql := range []string{"UPDATE members SET member_role=NULL,role='approver'", "UPDATE members SET member_role='',role='approver'", "UPDATE members SET member_role='approver',deleted_at='2026-01-01'"} {
		mustExec(t, app.DB, sql)
		if got := resolveAppRole(app, actor); got != "" {
			t.Fatalf("invalid configured membership resolved %q", got)
		}
	}
	mustExec(t, app.DB, "UPDATE members SET member_role='approver',deleted_at=NULL,role='approver'")
	for _, actor := range []*Session{{UserID: uid, Role: "user"}, {UserID: uid, Role: "admin", GroupID: "A", ActingAsGroup: "B"}} {
		if got := resolveAppRole(app, actor); got != "" {
			t.Fatalf("wrong effective tenant resolved %q", got)
		}
	}
	app.Group.RoleField = "missing_configured_column"
	if got := resolveAppRole(app, actor); got != "" {
		t.Fatalf("missing configured field fell back to legacy role: %q", got)
	}
}
