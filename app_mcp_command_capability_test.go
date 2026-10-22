//go:build !cli && !windows

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func capabilityRoles() *RolesConfig {
	return &RolesConfig{Roles: map[string]RoleDef{
		"base":   {Scopes: "tasks:read"},
		"editor": {Scopes: "billing:write org:manage", Inherits: []string{"base"}},
		"super":  {Scopes: "*"},
		"deputy": {Inherits: []string{"editor"}},
	}}
}

func TestAppMCPCommandCapabilityPermissionsNeedARoleThatGrantsThem(t *testing.T) {
	command, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(commandFixtureForManifest), map[string]bool{"work_items": true})
	if err != nil {
		t.Fatal(err)
	}
	tables := map[string]bool{"work_items": true}
	check := func(roles *RolesConfig, permissions ...string) error {
		manifest := commandManifest()
		manifest.Tools[0].Permissions = permissions
		return validateAppMCPBindingsForTables(manifest, []Flow{command}, tables, roles)
	}
	for _, permissions := range [][]string{
		{"billing:write"},
		{"org:manage", "billing:write"},
		{"work_items:read", "billing:write"},
		{"work_items:write", "org:manage"},
	} {
		if err := check(capabilityRoles(), permissions...); err != nil {
			t.Fatalf("%v rejected: %v", permissions, err)
		}
	}
	if err := check(&RolesConfig{Roles: map[string]RoleDef{"viewer": {Scopes: "tasks:read"}}}, "billing:write"); err == nil {
		t.Fatal("capability no role grants was accepted")
	}
	if err := check(nil, "billing:write"); err == nil {
		t.Fatal("capability accepted with no roles declared")
	}
	for _, permissions := range [][]string{
		{"evilage:write"},                   // typo
		{"org:manage"},                      // capability, but no write action covers a write
		{"org:manage", "work_items:read"},   // still no write coverage
		{"work_items:manage"},               // tables keep read/write only
		{"work_items:write", "super:write"}, // "*" role names no resource
		{"work_items:write", "tasks:write"}, // tasks is only granted read-wise; it is a scope resource, so allowed here
	} {
		err := check(capabilityRoles(), permissions...)
		if permissions[len(permissions)-1] == "tasks:write" {
			if err != nil {
				t.Fatalf("scope resource named by a role rejected: %v", err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("permissions accepted: %v", permissions)
		}
	}
	if err := check(capabilityRoles(), "billing:wr!te", "work_items:write"); err == nil {
		t.Fatal("non-identifier capability action accepted")
	}
}

const commandCapabilityAppYAML = `groups: {table: members, key: org_id, user_field: email}
roles:
  viewer: {scopes: [tasks:read]}
  editor: {scopes: [tasks:read, billing:write]}
  admin: {scopes: '*'}
access:
  projects: {all: group}
  tasks: {all: group}
  activities: {all: group}
`

// The flow records who it saw: prepare shows role:is_admin in the preview and
// apply writes the same pair into the activity row.
func commandCapabilityFlow() string {
	source := commandTaskFlowFixture
	source = strings.Replace(source, "SELECT id, status FROM tasks WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'\n          params: {id: '${{ params.arguments.id }}', project_id: '${{ params.arguments.project_id }}', tenant: '${{ user.group_id }}'}",
		"SELECT id, :role || ':' || :is_admin AS who FROM tasks WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'\n          params: {id: '${{ params.arguments.id }}', project_id: '${{ params.arguments.project_id }}', tenant: '${{ user.group_id }}', role: '${{ user.role }}', is_admin: '${{ user.is_admin }}'}", 1)
	source = strings.Replace(source, "preview: {status: '${{ steps.selected_task.outputs.first.status }}'}", "preview: {status: '${{ steps.selected_task.outputs.first.who }}'}", 1)
	source = strings.Replace(source, "SELECT t.id,:actor,:email,'completed' FROM", "SELECT t.id,:actor,:email,:role || ':' || :is_admin FROM", 1)
	source = strings.Replace(source, "tenant: '${{ user.group_id }}', email: '${{ user.email }}'}", "tenant: '${{ user.group_id }}', email: '${{ user.email }}', role: '${{ user.role }}', is_admin: '${{ user.is_admin }}'}", 1)
	return source
}

func newCommandCapabilityFixture(t *testing.T) (*App, map[string]string) {
	t.Helper()
	app, editorSession, _ := newUnenrolledCommandProviderTaskFixtureWithManifest(t, commandCapabilityFlow(), "", func(manifest *AppMCPManifest, dir string) {
		writeTestFile(t, dir, "app.yaml", commandCapabilityAppYAML)
		manifest.Tools[0].Permissions = []string{"billing:write"}
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	sessions := map[string]string{"editor": editorSession}
	for _, role := range []string{"viewer", "admin"} {
		email := role + "-actor@example.com"
		sid := createCrudScopeSession(t, app, email, role, "17", "")
		actor := GetSessionFromDB(app.DB, sid)
		if actor == nil {
			t.Fatalf("%s session missing", role)
		}
		if _, err := app.DB.Exec(`INSERT INTO members(org_id,email,user_id) VALUES('17',?,?)`, email, actor.UserID); err != nil {
			t.Fatal(err)
		}
		sessions[role] = actor.ID // the stored key; sid is the raw token
	}
	return app, sessions
}

func TestAppMCPCommandCapabilityScopeGatesRuntimeAndRoleBindingsAreLive(t *testing.T) {
	app, sessions := newCommandCapabilityFixture(t)
	tool, _, err := appMCPFindCommandDeclaration(snapshotAppMCPGeneration(app), "complete_item")
	if err != nil || len(tool.Permissions) != 1 || tool.Permissions[0] != "billing:write" {
		t.Fatalf("capability command was not admitted: %v", err)
	}
	if scopes := appMCPLiveScopes(app, appMCPManifestSnapshot(app), snapshotAppMCPGeneration(app)); !strings.Contains(scopes, "billing:write") {
		t.Fatalf("capability scope not advertised: %q", scopes)
	}
	origin := func(role string) appMCPCommandOrigin {
		return appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessions[role]}
	}
	// An actor whose roles do not grant the capability is refused.
	if _, err := prepareCommandTask(t, app, origin("viewer")); err == nil {
		t.Fatal("actor without the capability scope could prepare")
	}
	for _, tc := range []struct{ role, who string }{{"editor", "editor:0"}, {"admin", "admin:1"}} {
		prepared, err := prepareCommandTask(t, app, origin(tc.role))
		if err != nil {
			t.Fatalf("%s prepare: %v", tc.role, err)
		}
		if prepared.Preview["status"] != tc.who {
			t.Fatalf("%s prepare bound %v, want %q", tc.role, prepared.Preview["status"], tc.who)
		}
		if _, err := applyCommandTask(t, app, origin(tc.role), prepared); err != nil {
			t.Fatalf("%s apply: %v", tc.role, err)
		}
		var event string
		if err := app.DB.QueryRow(`SELECT event FROM activities WHERE task_id=1`).Scan(&event); err != nil || event != tc.who {
			t.Fatalf("%s apply bound %q (%v), want %q", tc.role, event, err, tc.who)
		}
		// Reset for the next actor.
		if _, err := app.DB.Exec(`DELETE FROM activities; UPDATE tasks SET status='open', completed_by=NULL, completed_at=NULL`); err != nil {
			t.Fatal(err)
		}
	}
	// A tenant membership role never reads as the global role or admin.
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET role='editor' WHERE email='admin-actor@example.com'`); err != nil {
		t.Fatal(err)
	}
	prepared, err := prepareCommandTask(t, app, origin("admin"))
	if err != nil || prepared.Preview["status"] != "editor:0" {
		t.Fatalf("demoted actor still bound as admin: %v %v", prepared, err)
	}
	// Deactivated actors never reach a binding.
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET deactivated_at=? WHERE email='editor-actor@example.com' OR email='task-actor@example.com'`, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareCommandTask(t, app, origin("editor")); err == nil {
		t.Fatal("deactivated actor could prepare")
	}
}

func TestCommandActorIdentityBindingsStayInSQLBindings(t *testing.T) {
	for _, ref := range []string{"${{ user.role }}", "${{user.is_admin}}"} {
		if got := commandActorIdentityKind(ref); got == "" {
			t.Fatalf("%q not recognized", ref)
		}
		if err := commandCompileLexicalRef(ref, "apply", nil, nil, false); err == nil {
			t.Fatalf("%q accepted outside a SQL binding", ref)
		}
	}
	if _, err := compileCommandPhaseSQLRef("${{ user.is_admin }}", "prepare", nil, nil); err != nil {
		t.Fatalf("prepare binding rejected: %v", err)
	}
	for _, bad := range []string{"${{ user.deactivated }}", "${{ user.roles }}", "x ${{ user.role }}", "${{ user.admin }}"} {
		if _, err := compileCommandPhaseSQLRef(bad, "apply", nil, nil); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
	// Dependency params keep the old closed set.
	if commandActorIdentityRef.MatchString("${{ user.id }}") || commandParam.MatchString("${{ user.role }}") {
		t.Fatal("identity grammar leaked into the dependency/param grammar")
	}
}
