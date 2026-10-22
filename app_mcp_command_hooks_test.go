//go:build !cli && !windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const hookFiredOnUpdate = `on_update:
  tasks:
    - sql: INSERT INTO activities(task_id,actor_user_id,actor_email,event) VALUES({{id}},{{user_id}},'{{user_email}}','hook_fired')
`

// hookTaskFlow is the provider fixture with a readback that tolerates the
// extra activity row a hook writes (`first` needs exactly one row).
var hookTaskFlow = strings.Replace(commandTaskFlowFixture, "JOIN activities AS a ON a.task_id=t.id WHERE", "JOIN activities AS a ON a.task_id=t.id AND a.event='completed' WHERE", 1)

func hookFixtureOrigin(sessionID string) appMCPCommandOrigin {
	return appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
}

// runHookedCommand prepares and applies the fixture command in one native
// capability and commits when it succeeds.
func runHookedCommand(t *testing.T, app *App, sessionID string) (map[string]any, error) {
	t.Helper()
	var readback map[string]any
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: snapshotAppMCPGeneration(app), toolName: "complete_item", origin: hookFixtureOrigin(sessionID), now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		if err != nil {
			return false, err
		}
		_, readback, err = cap.apply(prepared)
		return err == nil, err
	})
	return readback, err
}

func hookCount(t *testing.T, app *App, query string, args ...any) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestAppMCPCommandHookOnUpdateFiresOnceInCommandTransaction(t *testing.T) {
	app, sessionID, actorID := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hookFiredOnUpdate)
	readback, err := runHookedCommand(t, app, sessionID)
	if err != nil {
		t.Fatalf("command with an on_update SQL hook: %v", err)
	}
	if readback["status"] != "done" {
		t.Fatalf("readback: %#v", readback)
	}
	var who int64
	var email string
	if err := app.DB.QueryRow(`SELECT actor_user_id, actor_email FROM activities WHERE event='hook_fired' AND task_id=1`).Scan(&who, &email); err != nil || who != actorID || email != "task-actor@example.com" {
		t.Fatalf("hook row missing or not bound to the trusted actor: %d %q %v", who, email, err)
	}
	if n := hookCount(t, app, `SELECT count(*) FROM activities WHERE event='hook_fired'`); n != 1 {
		t.Fatalf("hook fired %d times, want exactly once", n)
	}
	if n := hookCount(t, app, `SELECT count(*) FROM activities WHERE event='completed'`); n != 1 {
		t.Fatalf("the command's own activity write was lost: %d", n)
	}
}

func TestAppMCPCommandHookWhenGatesFiring(t *testing.T) {
	for _, tc := range []struct {
		when string
		want int
	}{{"status = 'done'", 1}, {"status = 'open'", 0}, {"old_status = 'open' AND status != old_status", 1}} {
		hooks := strings.Replace(hookFiredOnUpdate, "  tasks:\n    - sql:", "  tasks:\n    - when: \""+tc.when+"\"\n      sql:", 1)
		app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hooks)
		if _, err := runHookedCommand(t, app, sessionID); err != nil {
			t.Fatalf("when %q: %v", tc.when, err)
		}
		if n := hookCount(t, app, `SELECT count(*) FROM activities WHERE event='hook_fired'`); n != tc.want {
			t.Fatalf("when %q fired %d hooks, want %d", tc.when, n, tc.want)
		}
	}
}

func TestAppMCPCommandBeforeHookRefusalAbortsEverything(t *testing.T) {
	hooks := `before_update:
  tasks:
    - sql: SELECT 'blocked by policy' AS error WHERE '{{status}}' = 'done'
` + hookFiredOnUpdate
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hooks)
	_, err := runHookedCommand(t, app, sessionID)
	if err == nil || !strings.Contains(err.Error(), "blocked by policy") {
		t.Fatalf("before-hook refusal did not abort the command: %v", err)
	}
	assertCommandTaskUnchanged(t, app)
	if n := hookCount(t, app, `SELECT count(*) FROM activities`); n != 0 {
		t.Fatalf("a refused command left %d activity rows", n)
	}
	// A before-hook that does not fire lets the same command through.
	passing := strings.Replace(hooks, "= 'done'", "= 'never'", 1)
	app, sessionID, _ = newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, passing)
	if _, err := runHookedCommand(t, app, sessionID); err != nil {
		t.Fatalf("non-matching before-hook refused the command: %v", err)
	}
}

func TestAppMCPCommandBeforeHookSeesPreWriteState(t *testing.T) {
	// Refuses only if the row is already done when the hook runs, which is
	// the state after the write; pre-write parity must let the command pass.
	hooks := `before_update:
  tasks:
    - sql: SELECT 'already done' AS error WHERE EXISTS (SELECT 1 FROM tasks WHERE id = {{id}} AND status = 'done')
`
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hooks)
	if _, err := runHookedCommand(t, app, sessionID); err != nil {
		t.Fatalf("before-hook observed post-write state: %v", err)
	}
}

func TestAppMCPCommandApplyFailureAfterHookRollsBackHookEffects(t *testing.T) {
	flowSource := strings.Replace(hookTaskFlow, "expect_rows: '=1'", "expect_rows: '=2'", 1)
	if flowSource == hookTaskFlow {
		t.Fatal("fixture did not change")
	}
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, flowSource, hookFiredOnUpdate)
	if _, err := runHookedCommand(t, app, sessionID); err == nil {
		t.Fatal("cardinality mismatch was accepted")
	}
	assertCommandTaskUnchanged(t, app)
	if n := hookCount(t, app, `SELECT count(*) FROM activities`); n != 0 {
		t.Fatalf("hook effects survived a failed command: %d", n)
	}
}

func TestAppMCPCommandHookMayWriteNotificationsButCommandSQLMayNot(t *testing.T) {
	hooks := `on_update:
  tasks:
    - sql: INSERT INTO _benmore_notifications(user_id,title,body,type,link,read) VALUES({{user_id}}, 'Task done', '{{title}}', 'info', '/task?id=' || CAST({{id}} AS INTEGER), 0)
`
	app, sessionID, actorID := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hooks)
	EnsureNotificationsTable(app.DB)
	if _, err := runHookedCommand(t, app, sessionID); err != nil {
		t.Fatalf("hook inbox write: %v", err)
	}
	var body string
	var userID int64
	if err := app.DB.QueryRow(`SELECT user_id, body FROM _benmore_notifications WHERE link='/task?id=1'`).Scan(&userID, &body); err != nil || userID != actorID || body != "Source-backed task" {
		t.Fatalf("hook notification row: %d %q %v", userID, body, err)
	}
	// The command's own authored SQL still cannot reach the inbox.
	if err := validateCommandApplySQL("INSERT INTO _benmore_notifications(user_id,title) VALUES(1,'x')", []string{"tasks", "_benmore_notifications"}); err == nil {
		t.Fatal("command apply SQL was allowed to write _benmore_notifications")
	}
	// ... and the connection guard enforces the same split at the engine.
	app2, sessionID2, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hooks)
	EnsureNotificationsTable(app2.DB)
	if _, err := app2.DB.Exec(`CREATE TABLE unrelated (v INTEGER)`); err != nil {
		t.Fatal(err)
	}
	const insert = `INSERT INTO _benmore_notifications(user_id,title) VALUES(1,'x')`
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app2, generation: snapshotAppMCPGeneration(app2), toolName: "complete_item", origin: hookFixtureOrigin(sessionID2), now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		if err := cap.enterPhase("apply", []string{"tasks"}, cap.effectTables(), false); err != nil {
			return false, err
		}
		_, applyErr := cap.tx.ExecContext(cap.ctx, insert)
		cap.leavePhase()
		if !isCommandSQLiteAuthRefusal(applyErr) {
			t.Errorf("apply-phase notification write was not refused by the authorizer: %v", applyErr)
		}
		readErr := cap.withNativeMetadata(appMCPCommandMetadataHookRead, func() error {
			_, err := cap.tx.ExecContext(cap.ctx, insert)
			return err
		})
		if readErr == nil {
			t.Error("read-only hook scope accepted a write")
		}
		for _, denied := range []string{`INSERT INTO _benmore_mcp_operations(id) VALUES('x')`, `INSERT INTO unrelated(v) VALUES(1)`, `DELETE FROM _benmore_mcp_command_approvals`} {
			deniedErr := cap.withNativeMetadata(appMCPCommandMetadataHookWrite, func() error {
				_, err := cap.tx.ExecContext(cap.ctx, denied)
				return err
			})
			if deniedErr == nil {
				t.Errorf("hook scope accepted %q", denied)
			}
		}
		return false, cap.withNativeMetadata(appMCPCommandMetadataHookWrite, func() error {
			_, err := cap.tx.ExecContext(cap.ctx, insert)
			return err
		})
	})
	if err != nil {
		t.Fatalf("hook scope refused the inbox write: %v", err)
	}
}

func TestAppMCPCommandLiveHooksEditNeverRunsAndStaleOperationRefuses(t *testing.T) {
	installCanonicalHotHandler(t)
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hookFiredOnUpdate)
	prepared, err := prepareCommandTask(t, app, hookFixtureOrigin(sessionID))
	if err != nil {
		t.Fatal(err)
	}
	live := strings.Replace(hookFiredOnUpdate, "hook_fired", "live_hook", 1)
	if err := os.WriteFile(filepath.Join(app.Dir, "hooks.yaml"), []byte(live), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := applyCommandTask(t, app, hookFixtureOrigin(sessionID), prepared); err == nil {
		t.Fatal("command ran after the live hooks.yaml diverged from the captured generation")
	}
	// Even after the live source is reloaded, an operation prepared under the
	// old generation is stale (its execution digest changed).
	reviewAppMCPFixture(t, app.Dir)
	if err := hotReloadApp(app, false); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, err := applyCommandTask(t, app, hookFixtureOrigin(sessionID), prepared); err == nil {
		t.Fatal("stale prepared operation ran under a different hook set")
	}
	assertCommandTaskUnchanged(t, app)
	if n := hookCount(t, app, `SELECT count(*) FROM activities WHERE event IN ('hook_fired','live_hook')`); n != 0 {
		t.Fatalf("a hook ran for a refused operation: %d", n)
	}
}

func TestAppMCPCommandUnsupportedHookKindsStayRefused(t *testing.T) {
	for name, hooks := range map[string]string{
		"email in a before-hook": `before_update:
  tasks:
    - email:
        to: "a@example.com"
        subject: "x"
        template: "x"
`,
		"mixed sql and ws hook": `on_update:
  tasks:
    - sql: SELECT 1
      ws:
        room: "task-{{id}}"
        payload: '{"s":"{{status}}"}'
`,
		"writing before-hook": `before_update:
  tasks:
    - sql: INSERT INTO activities(task_id,actor_user_id,actor_email,event) VALUES({{id}},1,'x','y')
`,
	} {
		app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hooks)
		_, err := runHookedCommand(t, app, sessionID)
		if err == nil || !strings.Contains(err.Error(), "unsupported canonical hooks") {
			t.Fatalf("%s was not refused: %v", name, err)
		}
		assertCommandTaskUnchanged(t, app)
	}
}

func TestAppMCPCommandHookCannotAuthorFullTextIndexWrites(t *testing.T) {
	for _, table := range []string{"tasks_fts", "tasks_fts_data", "tasks_fts_idx", "tasks_fts_docsize", "tasks_fts_config"} {
		for _, test := range []struct{ name, sql string }{
			{name: "write", sql: "INSERT INTO " + table + "(id) VALUES(1)"},
			{name: "read", sql: "SELECT * FROM " + table},
		} {
			t.Run(table+"/"+test.name, func(t *testing.T) {
				cap := &appMCPCommandCapability{
					generation: &appMCPRuntimeGeneration{
						sourceFiles: map[string][]byte{"schema.prisma": []byte(`model Task {
  id Int @id
  name String
  @@fulltext([name])
  @@map("tasks")
}`)},
						hooks: &HookConfig{OnUpdate: map[string][]Hook{
							"tasks": {{SQL: test.sql}},
						}},
					},
					enrollment: &appMCPVerifiedRevisionEnrollment{record: &appMCPRevisionEnrollment{TableNames: []string{"tasks"}}},
				}
				err := appMCPCommandHookEffectsSupported(cap, "tasks", "update")
				if err == nil || !strings.Contains(err.Error(), `command SQL cannot reference generated full-text storage table "`+table+`"`) {
					t.Fatalf("direct hook %s to generated full-text storage was not refused: %v", test.name, err)
				}
			})
		}
	}
}

func TestAppMCPCommandHookWriteToUnenrolledTableFailsClosed(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hookFiredOnUpdate)
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: snapshotAppMCPGeneration(app), toolName: "complete_item", origin: hookFixtureOrigin(sessionID), now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		if !commandTableSet(cap.effectTables())["activities"] {
			t.Error("a table written only by a hook was not enrolled")
		}
		kept := cap.enrollment.record.TableNames
		var without []string
		for _, name := range kept {
			if name != "activities" {
				without = append(without, name)
			}
		}
		cap.enrollment.record.TableNames = without
		defer func() { cap.enrollment.record.TableNames = kept }()
		return false, appMCPCommandHookEffectsSupported(cap, "tasks", "update")
	})
	if err == nil || !strings.Contains(err.Error(), "not revision-enrolled") {
		t.Fatalf("unenrolled hook write was not refused clearly: %v", err)
	}
}

func TestAppMCPExposureBeforeHookRefusalLeavesOperationUnconsumed(t *testing.T) {
	h := newExposureHarnessWithHooks(t, `before_update:
  tasks:
    - sql: SELECT 'blocked by policy' AS error WHERE '{{status}}' = 'done'
`+hookFiredOnUpdate)
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code == "" {
		t.Fatal("commit succeeded through a refusing before-hook")
	}
	if h.taskDone() || h.count("SELECT count(*) FROM activities") != 0 {
		t.Fatal("refused commit left business or hook rows")
	}
	state := h.status(id)
	// The refused attempt is recorded as failed; the operation stays unconsumed and retryable.
	attempt, _ := state["attempt"].(map[string]any)
	if state["state"] != "failed" || attempt["error_class"] != "hook_refused" || state["receipt"] != nil || state["business"] != "not_committed" {
		t.Fatalf("operation was consumed or received a receipt: %#v", state)
	}
}

const taskHookSchema = `CREATE TABLE org_memberships (id INTEGER PRIMARY KEY, group_id TEXT NOT NULL, member_email TEXT NOT NULL, member_user_id INTEGER NOT NULL, status TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'member', user_id INTEGER NOT NULL DEFAULT 0);
CREATE TABLE projects (id INTEGER PRIMARY KEY, group_id TEXT NOT NULL);
CREATE TABLE tasks (id INTEGER PRIMARY KEY, group_id TEXT NOT NULL, project_id INTEGER NOT NULL, name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open', assignee TEXT NOT NULL DEFAULT '', assignee_id INTEGER, user_id INTEGER NOT NULL DEFAULT 0, completed_at TEXT);
CREATE TABLE activities (id INTEGER PRIMARY KEY, group_id TEXT NOT NULL, project_id INTEGER, actor_user_id INTEGER, actor_email TEXT, kind TEXT NOT NULL, target_type TEXT, target_id INTEGER, target_label TEXT, description TEXT, user_id INTEGER);
`

const taskHookFlow = `command:
  version: 1
  prepared_schema:
    type: object
    additionalProperties: false
    required: [id]
    properties:
      id: {type: integer, minimum: 1, maximum: 9007199254740991}
  preview_schema:
    type: object
    additionalProperties: false
    required: [status]
    properties:
      status: {type: string, minLength: 1, maxLength: 32}
  writes: [tasks]
  dependencies:
    - name: selected_task
      table: tasks
      query: SELECT id FROM tasks WHERE id = :id AND group_id = :tenant AND status <> 'done'
      params: {id: '${{ params.arguments.id }}', tenant: '${{ user.group_id }}'}
      max_rows: 1
jobs:
  prepare:
    steps:
      - id: selected_task
        run: sql
        with:
          query: SELECT id, status FROM tasks WHERE id = :id AND group_id = :tenant AND status <> 'done'
          params: {id: '${{ params.arguments.id }}', tenant: '${{ user.group_id }}'}
      - run: respond
        with:
          status: 200
          json:
            arguments: {id: '${{ steps.selected_task.outputs.first.id }}'}
            preview: {status: '${{ steps.selected_task.outputs.first.status }}'}
  apply:
    steps:
      - id: complete_task
        run: sql
        expect_rows: '=1'
        with:
          query: UPDATE tasks SET status = 'done', completed_at = datetime('now') WHERE id = :id AND group_id = :tenant AND status <> 'done'
          params: {id: '${{ params.id }}', tenant: '${{ user.group_id }}'}
      - run: respond
        with: {status: 200, json: {ok: true}}
  readback:
    steps:
      - id: completed_task
        run: sql
        with:
          query: SELECT id, status FROM tasks WHERE id = :id AND group_id = :tenant
          params: {id: '${{ params.id }}', tenant: '${{ user.group_id }}'}
      - run: respond
        with:
          status: 200
          json:
            id: '${{ steps.completed_task.outputs.first.id }}'
            status: '${{ steps.completed_task.outputs.first.status }}'
`

// newTaskHookFixture mirrors a production app's tasks/activities/org_memberships
// shape with the production tasks on_update hooks copied verbatim.
func newTaskHookFixture(t *testing.T) (*App, string, int64) {
	t.Helper()
	epochFixture(t)
	t.Setenv("BENMORE_TEST_BOOT", "1")
	hookBytes, err := os.ReadFile("testdata/tasks_on_update_hooks.yaml")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", taskHookSchema)
	writeTestFile(t, dir, "app.yaml", `groups: {table: org_memberships, key: group_id, user_field: member_email, role_field: role}
roles:
  editor: {scopes: [tasks:read, tasks:write]}
access:
  projects: {all: group}
  tasks: {all: group}
  activities: {all: group}
`)
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: provider-fixture-key-with-sufficient-length\n")
	writeTestFile(t, dir, "flows/complete_item.yaml", taskHookFlow)
	writeTestFile(t, dir, "hooks.yaml", "on_update:\n"+string(hookBytes))
	manifest := commandManifest()
	manifest.Tools[0].InputSchema.Properties["arguments"].Properties = map[string]*AppMCPSchema{
		"id": {Type: "integer", Minimum: floatPointer(1), Maximum: floatPointer(float64(appMCPCommandSafeIntegerMax))},
	}
	manifest.Tools[0].InputSchema.Properties["arguments"].Required = []string{"id"}
	manifest.Tools[0].OutputSchema = &AppMCPSchema{Type: "object", AdditionalProperties: commandBoolPtr(false), Required: []string{"id", "status"}, Properties: map[string]*AppMCPSchema{
		"id":     {Type: "integer", Minimum: floatPointer(1), Maximum: floatPointer(float64(appMCPCommandSafeIntegerMax))},
		"status": {Type: "string", MinLength: intPointer(1), MaxLength: intPointer(32)},
	}}
	manifest.Tools[0].Permissions = []string{"tasks:write"}
	manifest.Tools[0].Output.Include = []string{"id", "status"}
	manifest.Resources = []AppMCPResource{{Name: "command", URI: grantFixtureResource, MIMEType: "application/json", Component: "none"}}
	manifestBytes, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "mcp.yaml", string(manifestBytes))
	reviewAppMCPFixture(t, dir)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load production-shaped app: %v", err)
	}
	app.DB.SetMaxOpenConns(1)
	t.Cleanup(app.Shutdown)
	ensureEmptyCommandWebhookFixture(t, app)
	EnsureNotificationsTable(app.DB)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	sid := createCrudScopeSession(t, app, "task-actor@example.com", "editor", "17", "")
	actor := GetSessionFromDB(app.DB, sid)
	if actor == nil {
		t.Fatal("actor session was not created")
	}
	for _, stmt := range []string{
		`INSERT INTO org_memberships(group_id,member_email,member_user_id,status) VALUES('17','task-actor@example.com',` + strconv.FormatInt(actor.UserID, 10) + `,'active')`,
		`INSERT INTO projects(id,group_id) VALUES(7,'17')`,
		`INSERT INTO tasks(id,group_id,project_id,name,status) VALUES(1,'17',7,'File the interconnection application','open')`,
	} {
		if _, err := app.DB.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatalf("task hook enrollment: %v", err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	return app, actor.ID, actor.UserID
}

func TestAppMCPCommandOnInsertHookRunsForInsertSQL(t *testing.T) {
	// The fixture command's own activities INSERT is the hooked statement; its
	// on_insert hook writes tasks, which must be enrolled and writable.
	hooks := `on_insert:
  activities:
    - sql: UPDATE tasks SET title = title || '+hooked' WHERE id = {{task_id}}
`
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hooks)
	if _, err := runHookedCommand(t, app, sessionID); err != nil {
		t.Fatalf("command with an on_insert hook: %v", err)
	}
	var title string
	if err := app.DB.QueryRow(`SELECT title FROM tasks WHERE id=1`).Scan(&title); err != nil || title != "Source-backed task+hooked" {
		t.Fatalf("on_insert hook did not run exactly once: %q %v", title, err)
	}
}

func TestAppMCPCommandTaskCompleteRunsRealHooksEndToEnd(t *testing.T) {
	app, sessionID, actorID := newTaskHookFixture(t)
	var readback map[string]any
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: snapshotAppMCPGeneration(app), toolName: "complete_item", origin: hookFixtureOrigin(sessionID), now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		for _, table := range []string{"tasks", "activities"} {
			if !commandTableSet(cap.effectTables())[table] {
				t.Errorf("hook-written table %q is not enrolled: %v", table, cap.effectTables())
			}
		}
		prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1}})
		if err != nil {
			return false, err
		}
		_, readback, err = cap.apply(prepared)
		return err == nil, err
	})
	if err != nil {
		t.Fatalf("task-complete command: %v", err)
	}
	if readback["status"] != "done" {
		t.Fatalf("receipt readback: %#v", readback)
	}
	var kind, label, email string
	var actor, target int64
	if err := app.DB.QueryRow(`SELECT kind, target_label, actor_email, actor_user_id, target_id FROM activities WHERE kind='task_completed'`).Scan(&kind, &label, &email, &actor, &target); err != nil ||
		label != "File the interconnection application" || email != "task-actor@example.com" || actor != actorID || target != 1 {
		t.Fatalf("task_completed activity: %q %q %d %d %v", label, email, actor, target, err)
	}
	if n := hookCount(t, app, `SELECT count(*) FROM activities WHERE kind='task_completed'`); n != 1 {
		t.Fatalf("task_completed activities: %d, want exactly 1", n)
	}
	if n := hookCount(t, app, `SELECT count(*) FROM activities`); n != 1 {
		t.Fatalf("unexpected extra hook rows: %d", n)
	}
	if n := hookCount(t, app, `SELECT count(*) FROM tasks WHERE id=1 AND status='done'`); n != 1 {
		t.Fatal("task is not done")
	}
}
