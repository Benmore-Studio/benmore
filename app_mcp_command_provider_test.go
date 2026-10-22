//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func newCommandProviderTaskFixture(t *testing.T) (*App, string, int64) {
	return newCommandProviderTaskFixtureWithSource(t, commandTaskFlowFixture)
}

func newCommandProviderTaskFixtureWithSource(t *testing.T, flowSource string) (*App, string, int64) {
	return newCommandProviderTaskFixtureWithPolicies(t, flowSource, "")
}

func ensureEmptyCommandWebhookFixture(t *testing.T, app *App) {
	t.Helper()
	EnsureWebhooksTable(app.DB)
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM main._benmore_webhooks`).Scan(&count); err != nil {
		t.Fatalf("initialize native command webhook table: %v", err)
	}
	if count != 0 {
		t.Fatalf("native command webhook fixture must start empty, found %d subscriptions", count)
	}
}

func newCommandProviderTaskFixtureWithPolicies(t *testing.T, flowSource, hookSource string) (*App, string, int64) {
	t.Helper()
	app, sessionID, userID := newUnenrolledCommandProviderTaskFixture(t, flowSource, hookSource)
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatalf("establish explicit task fixture owner: %v", err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatalf("explicit command fixture enrollment: %v", err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatalf("enable explicitly enrolled command fixture: %v", err)
	}
	return app, sessionID, userID
}

// newUnenrolledCommandProviderTaskFixture loads the reviewed command app with
// no owner state and no revision enrollment, as a first owner enable finds it.
func newUnenrolledCommandProviderTaskFixture(t *testing.T, flowSource, hookSource string) (*App, string, int64) {
	return newUnenrolledCommandProviderTaskFixtureWithManifest(t, flowSource, hookSource, nil)
}

func newUnenrolledCommandProviderTaskFixtureWithManifest(t *testing.T, flowSource, hookSource string, configure func(*AppMCPManifest, string)) (*App, string, int64) {
	t.Helper()
	epochFixture(t)
	t.Setenv("BENMORE_TEST_BOOT", "1")
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", `CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL, user_id INTEGER NOT NULL);
CREATE TABLE projects (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL);
CREATE TABLE tasks (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, org_id TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, completed_by INTEGER, completed_at TEXT);
CREATE TABLE activities (id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, actor_user_id INTEGER NOT NULL, actor_email TEXT NOT NULL, event TEXT NOT NULL);
`)
	writeTestFile(t, dir, "app.yaml", `groups: {table: members, key: org_id, user_field: email}
roles:
  editor: {scopes: [tasks:read, tasks:write]}
access:
  projects: {all: group}
  tasks: {all: group}
  activities: {all: group}
`)
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: provider-fixture-key-with-sufficient-length\n")
	writeTestFile(t, dir, "flows/complete_item.yaml", flowSource)
	if hookSource != "" {
		writeTestFile(t, dir, "hooks.yaml", hookSource)
	}
	manifest := commandManifest()
	manifest.Tools[0].InputSchema.Properties["arguments"].Properties = map[string]*AppMCPSchema{
		"id":         {Type: "integer", Minimum: floatPointer(1), Maximum: floatPointer(float64(appMCPCommandSafeIntegerMax))},
		"project_id": {Type: "integer", Minimum: floatPointer(1), Maximum: floatPointer(float64(appMCPCommandSafeIntegerMax))},
	}
	manifest.Tools[0].InputSchema.Properties["arguments"].Required = []string{"id", "project_id"}
	manifest.Tools[0].OutputSchema = &AppMCPSchema{Type: "object", AdditionalProperties: commandBoolPtr(false), Required: []string{"id", "status", "completed_by", "completed_at", "actor_email"}, Properties: map[string]*AppMCPSchema{
		"id":           {Type: "integer", Minimum: floatPointer(1), Maximum: floatPointer(float64(appMCPCommandSafeIntegerMax))},
		"status":       {Type: "string", MinLength: intPointer(1), MaxLength: intPointer(32)},
		"completed_by": {Type: "integer", Minimum: floatPointer(1), Maximum: floatPointer(float64(appMCPCommandSafeIntegerMax))},
		"completed_at": {Type: "string", MinLength: intPointer(1), MaxLength: intPointer(32)},
		"actor_email":  {Type: "string", MinLength: intPointer(1), MaxLength: intPointer(254)},
	}}
	manifest.Tools[0].Permissions = []string{"tasks:write"}
	manifest.Tools[0].Output.Include = []string{"id", "status", "completed_by", "completed_at", "actor_email"}
	manifest.Resources = []AppMCPResource{{Name: "command", URI: grantFixtureResource, MIMEType: "application/json", Component: "none"}}
	if configure != nil {
		configure(manifest, dir)
	}
	manifestBytes, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "mcp.yaml", string(manifestBytes))
	reviewAppMCPFixture(t, dir)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load source-backed command app: %v", err)
	}
	app.DB.SetMaxOpenConns(1)
	t.Cleanup(app.Shutdown)
	ensureEmptyCommandWebhookFixture(t, app)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	sid := createCrudScopeSession(t, app, "task-actor@example.com", "editor", "17", "")
	actor := GetSessionFromDB(app.DB, sid)
	if actor == nil {
		t.Fatal("native task actor session was not created")
	}
	if _, err := app.DB.Exec(`INSERT INTO members(org_id,email,user_id) VALUES('17',?,?)`, actor.Email, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO projects(id,org_id) VALUES(7,'17')`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO tasks(id,project_id,org_id,title,status) VALUES(1,7,'17','Source-backed task','open')`); err != nil {
		t.Fatal(err)
	}
	return app, actor.ID, actor.UserID
}

func TestAppMCPCommandProviderNonSQLHookNeedsConnectorGrantAndRollsBack(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, commandTaskFlowFixture, `on_update:
  tasks:
    - ws:
        room: "task-{{id}}"
        payload: '{"s":"{{status}}"}'
`)
	generation := snapshotAppMCPGeneration(app)
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		if err != nil {
			return false, err
		}
		_, _, err = cap.apply(prepared)
		return false, err
	})
	// A session-origin capability has no grant to stamp on a queued effect, so
	// the enqueue fails and the whole command rolls back.
	if err == nil || !strings.Contains(err.Error(), "need the connector grant") {
		t.Fatalf("delivery hook without a connector grant was not refused: %v", err)
	}
	assertCommandTaskUnchanged(t, app)
}

const commandTaskFlowFixture = `command:
  version: 1
  prepared_schema:
    type: object
    additionalProperties: false
    required: [id, project_id]
    properties:
      id: {type: integer, minimum: 1, maximum: 9007199254740991}
      project_id: {type: integer, minimum: 1, maximum: 9007199254740991}
  preview_schema:
    type: object
    additionalProperties: false
    required: [status]
    properties:
      status: {type: string, minLength: 1, maxLength: 32}
  writes: [tasks, activities]
  dependencies:
    - name: selected_task
      table: tasks
      query: SELECT id FROM tasks WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'
      params: {id: '${{ params.arguments.id }}', project_id: '${{ params.arguments.project_id }}', tenant: '${{ user.group_id }}'}
      max_rows: 1
jobs:
  prepare:
    steps:
      - id: selected_task
        run: sql
        with:
          query: SELECT id, status FROM tasks WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'
          params: {id: '${{ params.arguments.id }}', project_id: '${{ params.arguments.project_id }}', tenant: '${{ user.group_id }}'}
      - run: respond
        with:
          status: 200
          json:
            arguments: {id: '${{ steps.selected_task.outputs.first.id }}', project_id: '${{ params.arguments.project_id }}'}
            preview: {status: '${{ steps.selected_task.outputs.first.status }}'}
  apply:
    steps:
      - id: complete_task
        run: sql
        expect_rows: '>0'
        with:
          query: UPDATE tasks SET status = 'done', completed_by = :actor, completed_at = datetime('now') WHERE id = :id AND project_id = :project_id AND org_id = :tenant AND status <> 'done'
          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', actor: '${{ user.id }}', tenant: '${{ user.group_id }}'}
      - id: add_activity
        run: sql
        expect_rows: '=1'
        with:
          query: INSERT INTO activities(task_id,actor_user_id,actor_email,event) SELECT t.id,:actor,:email,'completed' FROM tasks AS t JOIN members AS m ON m.org_id=t.org_id WHERE t.id=:id AND t.project_id=:project_id AND t.org_id=:tenant AND m.user_id=:actor
          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', actor: '${{ user.id }}', tenant: '${{ user.group_id }}', email: '${{ user.email }}'}
      - run: respond
        with: {status: 200, json: {ok: true}}
  readback:
    steps:
      - id: completed_task
        run: sql
        with:
          query: SELECT t.id,t.status,t.completed_by,t.completed_at,a.actor_email FROM tasks AS t JOIN activities AS a ON a.task_id=t.id WHERE t.id=:id AND t.project_id=:project_id AND t.org_id=:tenant
          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', tenant: '${{ user.group_id }}'}
      - run: respond
        with:
          status: 200
          json:
            id: '${{ steps.completed_task.outputs.first.id }}'
            status: '${{ steps.completed_task.outputs.first.status }}'
            completed_by: '${{ steps.completed_task.outputs.first.completed_by }}'
            completed_at: '${{ steps.completed_task.outputs.first.completed_at }}'
            actor_email: '${{ steps.completed_task.outputs.first.actor_email }}'
`

func TestAppMCPCommandProviderNativeTaskSessionPrepareApplyReadback(t *testing.T) {
	app, sessionID, actorID := newCommandProviderTaskFixture(t)
	generation := snapshotAppMCPGeneration(app)
	tool, flow, err := appMCPFindCommandDeclaration(generation, "complete_item")
	if err != nil || tool == nil || flow == nil || flow.Command == nil {
		t.Fatalf("real loaded command binding missing: %v", err)
	}
	if len(flow.Command.Apply.Steps[1].CommandSQLParams) != 5 || flow.Command.Apply.Steps[1].CommandSQLParams["email"] != (FlowCommandParamRef{Kind: "actor_email"}) {
		t.Fatal("captured apply command did not preserve the exact trusted-email reference")
	}
	var readback map[string]any
	intent := map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}}
	err = appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		prepared, err := cap.prepare(intent)
		if err != nil {
			return false, err
		}
		if prepared.ActorUserID != actorID || prepared.ActorEmail != "task-actor@example.com" {
			return false, errors.New("prepared trusted actor binding was not captured")
		}
		_, result, err := cap.apply(prepared)
		if err != nil {
			return false, err
		}
		readback = result
		return true, nil
	})
	if err != nil {
		t.Fatalf("source-backed native session command: %v", err)
	}
	if readback["status"] != "done" || readback["actor_email"] != "task-actor@example.com" {
		t.Fatalf("authoritative task readback mismatch: %#v", readback)
	}
	if completedAt, ok := readback["completed_at"].(string); !ok || completedAt == "" {
		t.Fatalf("server-owned completion timestamp is missing from readback: %#v", readback["completed_at"])
	} else if _, err := time.ParseInLocation("2006-01-02 15:04:05", completedAt, time.UTC); err != nil {
		t.Fatalf("server-owned completion timestamp is malformed: %q %v", completedAt, err)
	}
	completedBy, ok := readback["completed_by"].(json.Number)
	if parsed, parseErr := completedBy.Int64(); !ok || parseErr != nil || parsed != actorID {
		t.Fatalf("authoritative readback did not preserve the task actor id: %#v", readback["completed_by"])
	}
	var activityActor int64
	var activityEmail string
	var activityCount int
	var activityEvent string
	if err := app.DB.QueryRow(`SELECT count(*),max(actor_user_id),max(actor_email),max(event) FROM activities WHERE task_id=1`).Scan(&activityCount, &activityActor, &activityEmail, &activityEvent); err != nil || activityCount != 1 || activityActor != actorID || activityEmail != "task-actor@example.com" || activityEvent != "completed" {
		t.Fatalf("task completion effect did not persist exactly one trusted completion activity: count=%d actor=%d email=%q event=%q err=%v", activityCount, activityActor, activityEmail, activityEvent, err)
	}
	var status string
	if err := app.DB.QueryRow(`SELECT status FROM tasks WHERE id=1`).Scan(&status); err != nil || status != "done" {
		t.Fatalf("task completion was not committed: status=%q err=%v", status, err)
	}
	if _, err := prepareCommandTask(t, app, appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}); err == nil {
		t.Fatal("already-completed task remained eligible for a duplicate completion activity")
	}
	if err := app.DB.QueryRow(`SELECT count(*) FROM activities WHERE task_id=1`).Scan(&activityCount); err != nil || activityCount != 1 {
		t.Fatalf("rejected repeat completion created another activity: %d %v", activityCount, err)
	}
}

func TestAppMCPCommandProviderSourceChangeDuringApplyRollsBack(t *testing.T) {
	app, _, actorID := newCommandProviderTaskFixture(t)
	generation := snapshotAppMCPGeneration(app)
	now := time.Now().UTC()
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := createAppMCPNativeGrantFor(context.Background(), app, actorID, "17", "source-change-fixture", grantFixtureResource, "complete_item", now)
	if err != nil {
		t.Fatalf("create connector command grant: %v", err)
	}
	pin := appMCPWriteAuthorityPin{
		Origin: app, Generation: generation, CredentialHash: mustAppMCPCredentialHash(t, pair.AccessToken, "access"), GrantID: pair.GrantID,
		AppID: state.App, Epoch: state.Epoch, WriteEpoch: state.ApprovedWriteEpoch,
		Resource: grantFixtureResource, Client: "source-change-fixture", Tenant: "17", UserID: actorID,
		UserCreated: readUserCreatedForTest(t, app, actorID), Permissions: strings.Fields(pair.Scopes),
	}
	var capability *appMCPCommandCapability
	var applyResult map[string]any
	err = appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandConnectorOrigin, connector: &pin}, now: now,
	}, func(cap *appMCPCommandCapability) (bool, error) {
		capability = cap
		prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		if err != nil {
			return false, err
		}
		if prepared == nil {
			return false, errors.New("command preparation returned no prepared intent")
		}
		phaseErr := cap.withFullSourceVerificationPhase(func() error {
			if err := os.WriteFile(filepath.Join(app.Dir, "app.yaml"), []byte("groups: {table: members, key: org_id, user_field: email}\n# source changed during apply\n"), 0600); err != nil {
				return err
			}
			var err error
			applyResult, err = appMCPRunCommandPhase(cap, "apply", prepared.Arguments)
			return err
		})
		if applyResult == nil || applyResult["ok"] != true {
			return false, fmt.Errorf("apply phase did not complete before source verification: result=%#v", applyResult)
		}
		return true, phaseErr
	})
	var authorityErr *appMCPWriteAuthorityError
	if err == nil || !errors.As(err, &authorityErr) || authorityErr.cause == nil || !strings.Contains(authorityErr.cause.Error(), "digest mismatch") {
		var authorityErr *appMCPWriteAuthorityError
		if errors.As(err, &authorityErr) && authorityErr.cause != nil {
			t.Logf("connector authority failure cause: %v", authorityErr.cause)
		}
		t.Fatalf("source mutation during apply was not rejected before commit: %v", err)
	}
	if capability == nil || capability.sourceVerificationScope {
		t.Fatalf("source-verification scope was not reset after phase failure: %#v", capability)
	}
	assertCommandTaskUnchanged(t, app)
}

func TestAppMCPCommandProviderMissingWebhookTableFailsClosedAfterEmptyBaseline(t *testing.T) {
	// Demonstrate that an initialized empty table supports the native command
	// before exercising the missing-table case in its own isolated fixture.
	baselineApp, baselineSession, _ := newCommandProviderTaskFixture(t)
	baselineOrigin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: baselineSession}
	baselinePrepared, err := prepareCommandTask(t, baselineApp, baselineOrigin)
	if err != nil {
		t.Fatalf("prepare command with empty webhook table: %v", err)
	}
	baselineReadback, err := applyCommandTask(t, baselineApp, baselineOrigin, baselinePrepared)
	if err != nil || baselineReadback["status"] != "done" {
		t.Fatalf("empty webhook table did not permit the valid task command: readback=%#v err=%v", baselineReadback, err)
	}

	app, sessionID, _ := newCommandProviderTaskFixture(t)
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil {
		t.Fatalf("prepare isolated command before removing webhook table: %v", err)
	}
	if _, err := app.DB.Exec(`DROP TABLE main._benmore_webhooks`); err != nil {
		t.Fatal(err)
	}
	if _, err := applyCommandTask(t, app, origin, prepared); err == nil || !strings.Contains(err.Error(), "check command webhook effects") || !strings.Contains(err.Error(), "no such table") {
		t.Fatalf("missing webhook table was treated like an empty table: %v", err)
	}
	assertCommandTaskUnchanged(t, app)
}

func TestAppMCPCommandAuthorityTrustedActorEmailPrepareApplyComparison(t *testing.T) {
	app, _, actorID := newCommandProviderTaskFixture(t)
	now := time.Now().UTC()
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := createAppMCPNativeGrantFor(context.Background(), app, actorID, "17", "command-fixture", grantFixtureResource, "complete_item", now)
	if err != nil {
		t.Fatalf("create private native command grant: %v", err)
	}
	pin := appMCPWriteAuthorityPin{
		Origin: app, Generation: snapshotAppMCPGeneration(app),
		CredentialHash: mustAppMCPCredentialHash(t, pair.AccessToken, "access"), GrantID: pair.GrantID,
		AppID: state.App, Epoch: state.Epoch, WriteEpoch: state.ApprovedWriteEpoch,
		Resource: grantFixtureResource, Client: "command-fixture", Tenant: "17", UserID: actorID,
		UserCreated: readUserCreatedForTest(t, app, actorID), Permissions: strings.Fields(pair.Scopes),
	}
	origin := appMCPCommandOrigin{kind: appMCPCommandConnectorOrigin, connector: &pin}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil || prepared.ActorEmail != "task-actor@example.com" {
		t.Fatalf("connector preparation did not capture the current trusted email: %+v %v", prepared, err)
	}
	if _, err := app.DB.Exec(`UPDATE main._benmore_users SET email='changed-actor@example.com' WHERE id=?`, actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`UPDATE members SET email='changed-actor@example.com' WHERE org_id='17' AND user_id=?`, actorID); err != nil {
		t.Fatal(err)
	}
	if _, err := applyCommandTask(t, app, origin, prepared); err == nil {
		t.Fatal("prepared command accepted a changed trusted actor email")
	}
	assertCommandTaskUnchanged(t, app)
	prepared, err = prepareCommandTask(t, app, origin)
	if err != nil || prepared.ActorEmail != "changed-actor@example.com" {
		t.Fatalf("fresh connector preparation rejected its current trusted email: %+v %v", prepared, err)
	}
	readback, err := applyCommandTask(t, app, origin, prepared)
	if err != nil {
		t.Fatalf("fresh connector command did not apply: %v", err)
	}
	if readback["status"] != "done" || readback["actor_email"] != "changed-actor@example.com" {
		t.Fatalf("connector task readback did not use the fresh verified actor email: %#v", readback)
	}
}

func TestAppMCPCommandProviderReadbackFailureRollsBackTaskEffects(t *testing.T) {
	oldQuery := "WHERE t.id=:id AND t.project_id=:project_id AND t.org_id=:tenant\n          params:"
	flowSource := strings.Replace(commandTaskFlowFixture, oldQuery,
		"WHERE t.id=:id AND t.project_id=:project_id AND t.org_id=:tenant AND t.id=999\n          params:", 1)
	if flowSource == commandTaskFlowFixture {
		t.Fatal("readback failure fixture did not change the source query")
	}
	if strings.Count(commandTaskFlowFixture, oldQuery) != 1 {
		t.Fatal("readback failure fixture did not target exactly one authoritative query")
	}
	app, sessionID, _ := newCommandProviderTaskFixtureWithSource(t, flowSource)
	generation := snapshotAppMCPGeneration(app)
	writesObservedBeforeRollback := false
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		if err != nil {
			return false, err
		}
		_, _, err = cap.apply(prepared)
		if err != nil {
			writesObservedBeforeRollback = cap.withInternalRead(func() error {
				var status string
				var activities int
				if queryErr := cap.tx.QueryRowContext(cap.ctx, `SELECT status FROM tasks WHERE id=1`).Scan(&status); queryErr != nil {
					return queryErr
				}
				if queryErr := cap.tx.QueryRowContext(cap.ctx, `SELECT count(*) FROM activities WHERE task_id=1`).Scan(&activities); queryErr != nil {
					return queryErr
				}
				if status != "done" || activities != 1 {
					return errors.New("apply effects were not present before readback refusal")
				}
				return nil
			}) == nil
		}
		return false, err
	})
	if err == nil {
		t.Fatal("missing authoritative readback was accepted")
	}
	if !strings.Contains(err.Error(), "command response reference is missing") {
		t.Fatalf("provider failed before authoritative readback: %v", err)
	}
	if !writesObservedBeforeRollback {
		t.Fatal("readback refusal did not occur after task and activity writes in the doomed transaction")
	}
	assertCommandTaskUnchanged(t, app)
}

func TestAppMCPCommandProviderChangedDependencyAfterPrepareRefuses(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil || prepared == nil {
		t.Fatalf("prepare source-backed task before dependency edit: %+v %v", prepared, err)
	}
	if _, err := app.DB.Exec(`UPDATE tasks SET title='changed after prepare' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	if _, err := applyCommandTask(t, app, origin, prepared); err == nil {
		t.Fatal("command accepted a selected task changed after prepare")
	}
	assertCommandTaskUnchanged(t, app)
	var title string
	if err := app.DB.QueryRow(`SELECT title FROM tasks WHERE id=1`).Scan(&title); err != nil || title != "changed after prepare" {
		t.Fatalf("test fixture edit was unexpectedly rolled back: %q %v", title, err)
	}
}

func prepareCommandTask(t *testing.T, app *App, origin appMCPCommandOrigin) (*appMCPCommandPrepared, error) {
	t.Helper()
	generation := snapshotAppMCPGeneration(app)
	var prepared *appMCPCommandPrepared
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item", origin: origin, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		var err error
		prepared, err = cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		return false, err
	})
	return prepared, err
}

func applyCommandTask(t *testing.T, app *App, origin appMCPCommandOrigin, prepared *appMCPCommandPrepared) (map[string]any, error) {
	t.Helper()
	generation := snapshotAppMCPGeneration(app)
	var readback map[string]any
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item", origin: origin, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		_, result, err := cap.apply(prepared)
		if err != nil {
			return false, err
		}
		readback = result
		return true, nil
	})
	return readback, err
}

func assertCommandTaskUnchanged(t *testing.T, app *App) {
	t.Helper()
	var status string
	var activityCount int
	if err := app.DB.QueryRow(`SELECT status FROM tasks WHERE id=1`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT count(*) FROM activities WHERE task_id=1`).Scan(&activityCount); err != nil {
		t.Fatal(err)
	}
	if status != "open" || activityCount != 0 {
		t.Fatalf("rejected prepared email changed task or activity state: status=%q activities=%d", status, activityCount)
	}
}

func floatPointer(value float64) *float64 { return &value }

func newCommandProviderRoadmapFixture(t *testing.T) (*App, string, int64) {
	t.Helper()
	epochFixture(t)
	t.Setenv("BENMORE_TEST_BOOT", "1")
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", `CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL, user_id INTEGER NOT NULL);
CREATE TABLE projects (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL);
CREATE TABLE roadmap_stages (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, org_id TEXT NOT NULL, start_date TEXT, due_date TEXT);
CREATE TABLE roadmap_slots (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, stage_id INTEGER NOT NULL, org_id TEXT NOT NULL, start_date TEXT NOT NULL, due_date TEXT NOT NULL);
CREATE TABLE roadmap_edges (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, org_id TEXT NOT NULL, predecessor_slot_id INTEGER NOT NULL, successor_slot_id INTEGER NOT NULL, lag_days INTEGER NOT NULL, UNIQUE(project_id, predecessor_slot_id, successor_slot_id));
`)
	writeTestFile(t, dir, "app.yaml", `groups: {table: members, key: org_id, user_field: email}
roles:
  editor: {scopes: [roadmap:read, roadmap_slots:write]}
access:
  projects: {all: group}
  roadmap_stages: {all: group}
  roadmap_slots: {all: group}
  roadmap_edges: {all: group}
`)
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: provider-fixture-key-with-sufficient-length\n")
	writeTestFile(t, dir, "flows/update_roadmap.yaml", commandRoadmapFlowFixture)
	writeTestFile(t, dir, "static/roadmap/prepare.ts", `export function prepareRoadmap(args: any) {
	  const intent = args.intent;
	  const slots = args.slots as Array<{id:number,start_date:string,due_date:string}>;
	  const byId = new Map(slots.map((slot) => [slot.id, slot]));
	  const predecessor = byId.get(intent.predecessor_slot_id);
	  const successor = byId.get(intent.successor_slot_id);
	  if (!predecessor || !successor || predecessor.id === successor.id) throw new Error("roadmap endpoints are not in the captured project stage");
	  const addDays = (value: string, days: number) => {
	    const date = new Date(value + "T00:00:00.000Z");
	    if (!Number.isFinite(date.getTime())) throw new Error("invalid captured roadmap date");
	    date.setUTCDate(date.getUTCDate() + days);
	    return date.toISOString().slice(0, 10);
	  };
	  const duration = Math.max(0, Math.round((Date.parse(successor.due_date + "T00:00:00Z") - Date.parse(successor.start_date + "T00:00:00Z")) / 86400000));
	  const movedStart = addDays(predecessor.due_date, intent.lag_days);
	  const changes = [
	    {slot_id: predecessor.id, new_start_date: predecessor.start_date, new_due_date: predecessor.due_date},
	    {slot_id: successor.id, new_start_date: movedStart, new_due_date: addDays(movedStart, duration)},
	  ];
	  const seen = new Set<number>();

	  for (const change of changes) {
    if (seen.has(change.slot_id)) throw new Error("duplicate roadmap target");
    seen.add(change.slot_id);
  }
  return { changes, count: changes.length };
}
`)
	manifest := commandManifest()
	closed := false
	maxID := float64(appMCPCommandSafeIntegerMax)
	minID := float64(1)
	manifest.Tools[0].Name = "update_roadmap"
	manifest.Tools[0].Handler.Flow = "update_roadmap"
	manifest.Tools[0].Description = "Update a bounded roadmap plan"
	manifest.Tools[0].Permissions = []string{"roadmap_slots:write"}
	manifest.Tools[0].InputSchema.Properties["arguments"].Properties = map[string]*AppMCPSchema{
		"project_id":          {Type: "integer", Minimum: &minID, Maximum: &maxID},
		"stage_id":            {Type: "integer", Minimum: &minID, Maximum: &maxID},
		"predecessor_slot_id": {Type: "integer", Minimum: &minID, Maximum: &maxID},
		"successor_slot_id":   {Type: "integer", Minimum: &minID, Maximum: &maxID},
		"lag_days":            {Type: "integer", Minimum: floatPointer(0), Maximum: floatPointer(365)},
	}
	manifest.Tools[0].InputSchema.Properties["arguments"].Required = []string{"project_id", "stage_id", "predecessor_slot_id", "successor_slot_id", "lag_days"}
	manifest.Tools[0].OutputSchema = &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Required: []string{"stage_start", "stage_due", "edge_lag_days", "slots"}, Properties: map[string]*AppMCPSchema{
		"stage_start":   {Type: "string", MaxLength: intPointer(32)},
		"stage_due":     {Type: "string", MaxLength: intPointer(32)},
		"edge_lag_days": {Type: "integer", Minimum: floatPointer(0), Maximum: floatPointer(365)},
		"slots": {Type: "array", MinItems: intPointer(1), MaxItems: intPointer(256), Items: &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Required: []string{"id", "start_date", "due_date"}, Properties: map[string]*AppMCPSchema{
			"id":         {Type: "integer", Minimum: &minID, Maximum: &maxID},
			"start_date": {Type: "string", MaxLength: intPointer(32)},
			"due_date":   {Type: "string", MaxLength: intPointer(32)},
		}}},
	}}
	manifest.Tools[0].Output.Include = []string{"stage_start", "stage_due", "edge_lag_days", "slots"}
	manifest.Resources = []AppMCPResource{{Name: "command", URI: grantFixtureResource, MIMEType: "application/json", Component: "none"}}
	manifestBytes, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "mcp.yaml", string(manifestBytes))
	reviewAppMCPFixture(t, dir)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load source-backed roadmap command app: %v", err)
	}
	app.DB.SetMaxOpenConns(1)
	t.Cleanup(app.Shutdown)
	ensureEmptyCommandWebhookFixture(t, app)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	sid := createCrudScopeSession(t, app, "roadmap-actor@example.com", "editor", "17", "")
	actor := GetSessionFromDB(app.DB, sid)
	if actor == nil {
		t.Fatal("native roadmap actor session was not created")
	}
	if _, err := app.DB.Exec(`INSERT INTO members(org_id,email,user_id) VALUES('17',?,?)`, actor.Email, actor.UserID); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO projects(id,org_id) VALUES(9,'17')`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO roadmap_stages(id,project_id,org_id) VALUES(4,9,'17')`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO roadmap_slots(id,project_id,stage_id,org_id,start_date,due_date) VALUES(1,9,4,'17','2026-01-01','2026-01-02'),(2,9,4,'17','2026-01-02','2026-01-03')`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO roadmap_slots(id,project_id,stage_id,org_id,start_date,due_date) VALUES(3,10,5,'18','2026-01-04','2026-01-05')`); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO roadmap_slots(id,project_id,stage_id,org_id,start_date,due_date) VALUES(4,9,4,'18','2026-01-04','2026-01-05')`); err != nil {
		t.Fatal(err)
	}
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatalf("establish explicit roadmap fixture owner: %v", err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatalf("explicit roadmap fixture enrollment: %v", err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatalf("enable explicitly enrolled roadmap fixture: %v", err)
	}
	return app, actor.ID, actor.UserID
}

const commandRoadmapFlowFixture = `command:
  version: 1
  prepared_schema:
    type: object
    additionalProperties: false
    required: [project_id, stage_id, predecessor_slot_id, successor_slot_id, lag_days, changes]
    properties:
      project_id: {type: integer, minimum: 1, maximum: 9007199254740991}
      stage_id: {type: integer, minimum: 1, maximum: 9007199254740991}
      predecessor_slot_id: {type: integer, minimum: 1, maximum: 9007199254740991}
      successor_slot_id: {type: integer, minimum: 1, maximum: 9007199254740991}
      lag_days: {type: integer, minimum: 0, maximum: 365}
      changes:
        type: array
        minItems: 1
        maxItems: 256
        items:
          type: object
          additionalProperties: false
          required: [slot_id, new_start_date, new_due_date]
          properties:
            slot_id: {type: integer, minimum: 1, maximum: 9007199254740991}
            new_start_date: {type: string, maxLength: 32}
            new_due_date: {type: string, maxLength: 32}
  preview_schema:
    type: object
    additionalProperties: false
    required: [change_count]
    properties:
      change_count: {type: integer, minimum: 1, maximum: 256}
  writes: [roadmap_stages, roadmap_edges, roadmap_slots]
  dependencies:
    - name: project_stage
      table: roadmap_stages
      query: SELECT id FROM roadmap_stages WHERE id = :stage_id AND project_id = :project_id AND org_id = :tenant
      params: {stage_id: '${{ params.arguments.stage_id }}', project_id: '${{ params.arguments.project_id }}', tenant: '${{ user.group_id }}'}
      max_rows: 1
    - name: project_slots
      table: roadmap_slots
      query: SELECT id FROM roadmap_slots WHERE project_id = :project_id AND org_id = :tenant
      params: {project_id: '${{ params.arguments.project_id }}', tenant: '${{ user.group_id }}'}
      max_rows: 256
    - name: project_edges
      table: roadmap_edges
      query: SELECT id FROM roadmap_edges WHERE project_id = :project_id AND org_id = :tenant
      params: {project_id: '${{ params.arguments.project_id }}', tenant: '${{ user.group_id }}'}
      max_rows: 256
jobs:
  prepare:
    steps:
      - id: captured_slots
        run: sql
        with:
          query: SELECT id,start_date,due_date FROM roadmap_slots WHERE project_id=:project_id AND stage_id=:stage_id AND org_id=:tenant ORDER BY id
          params: {project_id: '${{ params.arguments.project_id }}', stage_id: '${{ params.arguments.stage_id }}', tenant: '${{ user.group_id }}'}
      - id: prepared_changes
        run: compute
        with:
          module: roadmap/prepare
          function: prepareRoadmap
          args:
            intent: '${{ params.arguments }}'
            slots: '${{ steps.captured_slots.outputs }}'
      - run: respond
        with:
          status: 200
          json:
            arguments:
              project_id: '${{ params.arguments.project_id }}'
              stage_id: '${{ params.arguments.stage_id }}'
              predecessor_slot_id: '${{ params.arguments.predecessor_slot_id }}'
              successor_slot_id: '${{ params.arguments.successor_slot_id }}'
              lag_days: '${{ params.arguments.lag_days }}'
              changes: '${{ steps.prepared_changes.outputs.changes }}'
            preview: {change_count: '${{ steps.prepared_changes.outputs.count }}'}
  apply:
    steps:
      - id: persist_stage_floor
        run: sql
        expect_rows: '=1'
        with:
          query: UPDATE roadmap_stages SET start_date=(SELECT min(start_date) FROM roadmap_slots WHERE stage_id=:stage_id AND project_id=:project_id AND org_id=:tenant), due_date=(SELECT max(due_date) FROM roadmap_slots WHERE stage_id=:stage_id AND project_id=:project_id AND org_id=:tenant) WHERE id=:stage_id AND project_id=:project_id AND org_id=:tenant AND start_date IS NULL
          params: {stage_id: '${{ params.stage_id }}', project_id: '${{ params.project_id }}', tenant: '${{ user.group_id }}'}
      - id: upsert_dependency_edge
        run: sql
        expect_rows: '>0'
        with:
          query: INSERT INTO roadmap_edges(id,project_id,org_id,predecessor_slot_id,successor_slot_id,lag_days) VALUES(1,:project_id,:tenant,:predecessor_slot_id,:successor_slot_id,:lag_days) ON CONFLICT(project_id,predecessor_slot_id,successor_slot_id) DO UPDATE SET lag_days=excluded.lag_days
          params: {project_id: '${{ params.project_id }}', tenant: '${{ user.group_id }}', predecessor_slot_id: '${{ params.predecessor_slot_id }}', successor_slot_id: '${{ params.successor_slot_id }}', lag_days: '${{ params.lag_days }}'}
      - for_each: '${{ params.changes }}'
        as: change
        steps:
          - id: update_slot
            run: sql
            expect_rows: '=1'
            with:
              query: UPDATE roadmap_slots SET start_date=NULLIF(:new_start_date,''),due_date=NULLIF(:new_due_date,'') WHERE id=:slot_id AND project_id=:project_id AND org_id=:tenant AND stage_id=:stage_id
              params: {new_start_date: '${{ change.new_start_date }}', new_due_date: '${{ change.new_due_date }}', slot_id: '${{ change.slot_id }}', project_id: '${{ params.project_id }}', tenant: '${{ user.group_id }}', stage_id: '${{ params.stage_id }}'}
      - run: respond
        with: {status: 200, json: {ok: true}}
  readback:
    steps:
      - id: stage_state
        run: sql
        with:
          query: SELECT start_date,due_date FROM roadmap_stages WHERE id=:stage_id AND project_id=:project_id AND org_id=:tenant
          params: {stage_id: '${{ params.stage_id }}', project_id: '${{ params.project_id }}', tenant: '${{ user.group_id }}'}
      - id: edge_state
        run: sql
        with:
          query: SELECT lag_days FROM roadmap_edges WHERE project_id=:project_id AND org_id=:tenant AND predecessor_slot_id=:predecessor_slot_id AND successor_slot_id=:successor_slot_id
          params: {project_id: '${{ params.project_id }}', tenant: '${{ user.group_id }}', predecessor_slot_id: '${{ params.predecessor_slot_id }}', successor_slot_id: '${{ params.successor_slot_id }}'}
      - id: slot_state
        run: sql
        with:
          query: SELECT id,start_date,due_date FROM roadmap_slots WHERE project_id=:project_id AND org_id=:tenant ORDER BY id
          params: {project_id: '${{ params.project_id }}', tenant: '${{ user.group_id }}'}
      - run: respond
        with:
          status: 200
          json:
            stage_start: '${{ steps.stage_state.outputs.first.start_date }}'
            stage_due: '${{ steps.stage_state.outputs.first.due_date }}'
            edge_lag_days: '${{ steps.edge_state.outputs.first.lag_days }}'
            slots: '${{ steps.slot_state.outputs }}'
`

func TestAppMCPCommandProviderRoadmapCapturedComputeTwoSlotPrepareApplyReadback(t *testing.T) {
	app, sessionID, _ := newCommandProviderRoadmapFixture(t)
	generation := snapshotAppMCPGeneration(app)
	tool, flow, err := appMCPFindCommandDeclaration(generation, "update_roadmap")
	if err != nil || tool == nil || flow == nil || flow.Command == nil {
		t.Fatalf("source-loaded roadmap command binding missing: %v", err)
	}
	if len(flow.Command.Apply.Steps) < 4 || flow.Command.Apply.Steps[0].SQL == "" || flow.Command.Apply.Steps[1].SQL == "" || flow.Command.Apply.Steps[2].Type != "for_each" {
		t.Fatal("roadmap apply no longer preserves stage-floor, edge, then prepared-slot ordering")
	}
	intent := map[string]any{"arguments": map[string]any{
		"project_id": 9, "stage_id": 4, "predecessor_slot_id": 1, "successor_slot_id": 2, "lag_days": 2,
	}}
	var preparedSnapshot *appMCPCommandPrepared
	var readback map[string]any
	err = appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "update_roadmap", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		prepared, err := cap.prepare(intent)
		if err != nil {
			return false, err
		}
		preparedSnapshot = prepared
		changes, ok := prepared.Arguments["changes"].([]any)
		if !ok || len(changes) != 2 {
			return false, errors.New("captured compute did not produce the two native prepared changes")
		}
		if _, result, err := cap.apply(prepared); err != nil {
			return false, err
		} else {
			readback = result
		}
		return true, nil
	})
	if err != nil {
		t.Fatalf("source-backed native roadmap command failed: %v", err)
	}
	if preparedSnapshot == nil || len(preparedSnapshot.Arguments) != 6 || len(preparedSnapshot.Dependencies.Sets) != 3 {
		t.Fatalf("roadmap prepare did not retain typed args and captured table sets: %+v", preparedSnapshot)
	}
	if readback["stage_start"] != "2026-01-01" || readback["stage_due"] != "2026-01-03" || readback["edge_lag_days"] != json.Number("2") {
		t.Fatalf("roadmap readback missed pre-move floor or scoped edge: %#v", readback)
	}
	slots, ok := readback["slots"].([]any)
	if !ok || len(slots) != 2 {
		t.Fatalf("roadmap readback did not query both changed rows: %#v", readback["slots"])
	}
	first, ok1 := slots[0].(map[string]any)
	second, ok2 := slots[1].(map[string]any)
	if !ok1 || !ok2 || first["start_date"] != "2026-01-01" || first["due_date"] != "2026-01-02" || second["start_date"] != "2026-01-04" || second["due_date"] != "2026-01-05" {
		t.Fatalf("roadmap readback does not match both committed slot changes: %#v", slots)
	}
	var stageStart, slotStarts, edgeCount int
	if err := app.DB.QueryRow(`SELECT count(*) FROM roadmap_stages WHERE id=4 AND start_date='2026-01-01' AND due_date='2026-01-03'`).Scan(&stageStart); err != nil || stageStart != 1 {
		t.Fatalf("stage floor was not persisted from pre-move slot state: %d %v", stageStart, err)
	}
	if err := app.DB.QueryRow(`SELECT count(*) FROM roadmap_slots WHERE (id=1 AND start_date='2026-01-01' AND due_date='2026-01-02') OR (id=2 AND start_date='2026-01-04' AND due_date='2026-01-05')`).Scan(&slotStarts); err != nil || slotStarts != 2 {
		t.Fatalf("both slot changes were not persisted: %d %v", slotStarts, err)
	}
	if err := app.DB.QueryRow(`SELECT count(*) FROM roadmap_edges WHERE project_id=9 AND org_id='17' AND predecessor_slot_id=1 AND successor_slot_id=2 AND lag_days=2`).Scan(&edgeCount); err != nil || edgeCount != 1 {
		t.Fatalf("scoped roadmap edge was not persisted once: %d %v", edgeCount, err)
	}
}

func TestAppMCPCommandProviderRoadmapRejectsInvalidTargetsAtomically(t *testing.T) {
	for _, test := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{name: "wrong project identity type", mutate: func(args map[string]any) { args["project_id"] = "9" }},
		{name: "caller cannot supply prepared changes", mutate: func(args map[string]any) { args["changes"] = []any{map[string]any{"slot_id": 1}} }},
		{name: "missing required lag", mutate: func(args map[string]any) { delete(args, "lag_days") }},
		{name: "duplicate endpoints", mutate: func(args map[string]any) { args["successor_slot_id"] = 1 }},
		{name: "foreign project stage", mutate: func(args map[string]any) { args["project_id"], args["stage_id"] = 10, 5 }},
		{name: "foreign tenant endpoint", mutate: func(args map[string]any) { args["successor_slot_id"] = 4 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			app, sessionID, _ := newCommandProviderRoadmapFixture(t)
			intent := commandRoadmapIntent()
			test.mutate(intent["arguments"].(map[string]any))
			generation := snapshotAppMCPGeneration(app)
			err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
				app: app, generation: generation, toolName: "update_roadmap", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
			}, func(cap *appMCPCommandCapability) (bool, error) {
				prepared, err := cap.prepare(intent)
				if err != nil {
					return false, err
				}
				_ = prepared
				return false, nil
			})
			if err == nil {
				t.Fatal("invalid roadmap command was accepted")
			}
			assertRoadmapFixtureUnchanged(t, app)
		})
	}
}

func commandRoadmapIntent() map[string]any {
	return map[string]any{"arguments": map[string]any{
		"project_id": 9, "stage_id": 4, "predecessor_slot_id": 1, "successor_slot_id": 2, "lag_days": 2,
	}}
}

func assertRoadmapFixtureUnchanged(t *testing.T, app *App) {
	t.Helper()
	var stageNull, edgeCount, originalSlots, foreignProject, foreignTenant int
	if err := app.DB.QueryRow(`SELECT count(*) FROM roadmap_stages WHERE id=4 AND start_date IS NULL AND due_date IS NULL`).Scan(&stageNull); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT count(*) FROM roadmap_edges WHERE project_id=9`).Scan(&edgeCount); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT count(*) FROM roadmap_slots WHERE (id=1 AND start_date='2026-01-01' AND due_date='2026-01-02') OR (id=2 AND start_date='2026-01-02' AND due_date='2026-01-03')`).Scan(&originalSlots); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT count(*) FROM roadmap_slots WHERE id=3 AND project_id=10 AND org_id='18' AND start_date='2026-01-04' AND due_date='2026-01-05'`).Scan(&foreignProject); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT count(*) FROM roadmap_slots WHERE id=4 AND project_id=9 AND org_id='18' AND start_date='2026-01-04' AND due_date='2026-01-05'`).Scan(&foreignTenant); err != nil {
		t.Fatal(err)
	}
	if stageNull != 1 || edgeCount != 0 || originalSlots != 2 || foreignProject != 1 || foreignTenant != 1 {
		t.Fatalf("rejected roadmap command left partial effects: stageNull=%d edges=%d originalSlots=%d foreignProject=%d foreignTenant=%d", stageNull, edgeCount, originalSlots, foreignProject, foreignTenant)
	}
}
