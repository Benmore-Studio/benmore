//go:build !cli && !windows

package main

import (
	"context"
	cryptorand "crypto/rand"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

func appMCPGenerationCountFixture(t *testing.T, app *App, onCount func() error) *[]string {
	t.Helper()
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	events := []string{}
	driverName := "mcp-generation-count-" + generateToken(8)
	sql.Register(driverName, &sqlite3.SQLiteDriver{ConnectHook: func(conn *sqlite3.SQLiteConn) error {
		return conn.RegisterFunc("generation_mcp_count", func() (int64, error) {
			switch len(events) {
			case 0:
				events = append(events, "page")
			case 1:
				events = append(events, "count")
				if onCount != nil {
					return 0, onCount()
				}
			default:
				events = append(events, "extra")
			}
			return 1, nil
		}, false)
	}})
	db, err := sql.Open(driverName, filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(3)
	for _, statement := range []string{
		"ALTER TABLE notes RENAME TO notes_storage",
		"DELETE FROM notes_storage WHERE id != 1",
		"CREATE VIEW notes AS SELECT * FROM notes_storage WHERE generation_mcp_count() = 1",
	} {
		if _, err := db.Exec(statement); err != nil {
			_ = db.Close()
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { _ = db.Close() })
	app.DB = db
	return &events
}

func appMCPGenerationSingleReadBarrier(t *testing.T, app *App, onRead func() error) {
	t.Helper()
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	var barrierErr error
	driverName := "mcp-generation-read-barrier-" + generateToken(8)
	sql.Register(driverName, &sqlite3.SQLiteDriver{ConnectHook: func(conn *sqlite3.SQLiteConn) error {
		return conn.RegisterFunc("generation_app_mcp_barrier", func() (int64, error) {
			once.Do(func() { barrierErr = onRead() })
			if barrierErr != nil {
				return 0, barrierErr
			}
			return 1, nil
		}, false)
	}})
	db, err := sql.Open(driverName, filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(3)
	if _, err := db.Exec("ALTER TABLE notes RENAME TO notes_storage"); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE VIEW notes AS SELECT * FROM notes_storage WHERE generation_app_mcp_barrier()=1"); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	app.DB = db
}

// A manifest pointer check at result release cannot protect the canonical
// actor's intermediate Group/Roles reads from a real staged publication.
func TestAppMCPActorAndReloadUseOneRuntimeGeneration(t *testing.T) {
	app, uid, now := appMCPGrantFixture(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, created_at TEXT);\n")
	writeTestFile(t, app.Dir, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\nroles: {editor: {scopes: [notes:read]}, admin: {scopes: [notes:read]}}\n")
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP, app.Group, app.Roles = config.mcp, config.group, config.roles
	pair := fixtureGrant(t, app, uid, now)
	grant, err := readAppMCPGrant(app.DB, pair.GrantID)
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "ALTER TABLE _benmore_users RENAME TO _benmore_users_generation_storage")
	auditExec(t, app.DB, `CREATE VIEW _benmore_users AS SELECT id,CASE WHEN generation_actor_started()=1 THEN email ELSE email END AS email,role,deactivated_at,verified,email_grandfathered,password_change_required,created_at FROM _benmore_users_generation_storage`)
	started, unblock := make(chan struct{}), make(chan struct{})
	var once, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(unblock) }) }
	defer release()
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	driver := "mcp-generation-" + generateToken(8)
	sql.Register(driver, &sqlite3.SQLiteDriver{ConnectHook: func(conn *sqlite3.SQLiteConn) error {
		return conn.RegisterFunc("generation_actor_started", func() int64 {
			once.Do(func() { close(started) })
			<-unblock
			return 1
		}, false)
	}})
	app.DB, err = sql.Open(driver, filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.DB.Close() })
	actorDone := make(chan error, 1)
	go func() {
		actor, err := appMCPGrantActorFor(context.Background(), app, grant, now)
		if err == nil || actor != nil {
			actorDone <- fmt.Errorf("actor crossed a published generation: actor=%+v error=%v", actor, err)
			return
		}
		actorDone <- nil
	}()
	select {
	case <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("canonical actor SQL never started")
	}
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	release()
	select {
	case err := <-actorDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("actor blocked across reload")
	}
	if app.Group != config.group || app.Roles != config.roles {
		t.Fatal("reload did not publish candidate authority")
	}
}

func TestAppMCPReadAuditUsesLiveOwnerSinkForListAndRead(t *testing.T) {
	for _, read := range []bool{false, true} {
		name := "list"
		if read {
			name = "read"
		}
		t.Run(name, func(t *testing.T) {
			app, pair, _ := appMCPResultFixture(t, read)
			app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "notes"}}
			EnsureReadAuditTable(app.DB)
			generation := snapshotAppMCPGeneration(app)
			app.mu.Lock()
			app.readAudit = &readAuditBuffer{db: app.DB, sync: true}
			app.mu.Unlock()
			input := map[string]any{}
			if read {
				input["id"] = 1
			}
			if _, err := runAppMCPNativeReadGeneration(context.Background(), app, generation, pair.AccessToken, grantFixtureResource, "list_notes", input); err != nil {
				t.Fatal(err)
			}
			var count int
			var queryType string
			if err := app.DB.QueryRow("SELECT count(*), COALESCE(min(query_type), '') FROM _benmore_read_audit WHERE table_name='notes'").Scan(&count, &queryType); err != nil {
				t.Fatal(err)
			}
			want := "list"
			if read {
				want = "read"
			}
			if count != 1 || queryType != want {
				t.Fatalf("native %s did not reach live read-audit sink: count=%d type=%q", want, count, queryType)
			}
		})
	}
}

func TestAppMCPNativeReadPinsDifferentPolicyGeneration(t *testing.T) {
	app, pair, uid := appMCPResultFixture(t, false)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT);\nCREATE TABLE members_b (id INTEGER PRIMARY KEY, tenant_key TEXT, email TEXT);\n")
	manifest := appMCPManifestFixture()
	manifest = strings.Replace(manifest, "properties:\n        id: {type: integer}", "required: [id, title]\n      properties:\n        id: {type: integer}\n        title: {type: string}", 1)
	manifest = strings.Replace(manifest, "output: {include: [id]}", "output: {include: [id, title]}", 1)
	manifest = strings.Replace(manifest, "resources: []", `  - name: read_note
    description: Read one reviewed note
    handler: {kind: native, operation: table.read, table: notes}
    input_schema: {type: object, additionalProperties: false, required: [id], properties: {id: {type: integer}}}
    output_schema:
      type: object
      additionalProperties: false
      required: [id, title]
      properties:
        id: {type: integer}
        title: {type: string}
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id, title]}
    component: none
resources: []`, 1)
	writeTestFile(t, app.Dir, "mcp.yaml", manifest)
	writeTestFile(t, app.Dir, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\nroles: {editor: {scopes: [notes:read]}}\nscopes: {notes: {public_read_when: \"title = 'A'\"}}\n")
	reviewAppMCPFixture(t, app.Dir)
	configA, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfigStaged(app, configA, nil); err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "INSERT INTO members_b(tenant_key,email) VALUES ('17','delegate@example.com')")
	auditExec(t, app.DB, "UPDATE notes SET user_id=999,title='A' WHERE id=1")
	baseline, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(fmt.Sprint(baseline.Data), "A") {
		t.Fatalf("A policy did not expose its own row: data=%#v", baseline)
	}
	var configB *runtimeConfig
	events := appMCPGenerationCountFixture(t, app, func() error {
		writeTestFile(t, app.Dir, "app.yaml", "groups: {table: members_b, key: tenant_key, user_field: email}\nroles: {editor: {inherits: [viewer]}, viewer: {scopes: [notes:read]}}\naccess: {notes: {read: self}}\nscopes: {notes: {public_read_when: \"title = 'B'\"}}\n")
		reviewAppMCPFixture(t, app.Dir)
		var err error
		configB, err = loadRuntimeConfig(app.Dir)
		if err != nil {
			return err
		}
		return reloadAppConfigStaged(app, configB, nil)
	})
	// The SQL callback fixture replaces only the DB pool. Rebind the already
	// staged A source/policy snapshot to that test pool before dispatch.
	app.mu.Lock()
	a := newAppMCPRuntimeGeneration(app, configA.mcp, configA.group, configA.roles, configA.access, configA.scopes, configA.design, app.Tables, app.UUIDTables, configA.encrypted, configA.flows, configA.sourceFiles, app.environment, configA.templateEnvSource, configA.hooks, configA.validators, configA.computed, configA.workflows, configA.pages)
	app.mcpGeneration = a
	app.mu.Unlock()
	if _, err := app.DB.Exec("UPDATE notes_storage SET user_id=999,title='A' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	// Pause after canonical rows have been read but before the count completes,
	// publish a different reviewed read policy, then verify A cannot release.
	if result, err := runAppMCPNativeReadGeneration(context.Background(), app, a, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{}); result != nil || nativeResultErrorCode(t, err) != "denied" {
		t.Fatalf("paused A result crossed B publication: result=%+v err=%v", result, err)
	}
	if len(*events) != 2 || (*events)[0] != "page" || (*events)[1] != "count" {
		t.Fatalf("reload callback did not happen after the page query: %v", *events)
	}
	b := snapshotAppMCPGeneration(app)
	if b == a || appMCPGenerationCurrent(app, a) || !appMCPGenerationCurrent(app, b) {
		t.Fatal("successful config publication did not replace generation identity")
	}
	if a.view.Group.Table != "members" || a.view.Group.Key != "org_id" || b.view.Group.Table != "members_b" || b.view.Group.Key != "tenant_key" || b.view.Roles == a.view.Roles || !slices.Contains(b.view.Roles.Roles["editor"].Inherits, "viewer") || b.view.Access == nil || b.view.Scopes["notes"].PublicReadWhen == a.view.Scopes["notes"].PublicReadWhen {
		t.Fatal("runtime policy bundle did not capture the candidate group/roles/access/scopes")
	}
	if _, err := app.DB.Exec("INSERT INTO notes_storage(id,user_id,title) VALUES (2,?,'B')", uid); err != nil {
		t.Fatal(err)
	}
	fresh, err := runAppMCPNativeReadGeneration(context.Background(), app, b, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	rows, ok := fresh.Data.([]map[string]any)
	if !ok || len(rows) != 1 || rows[0]["title"] != "B" {
		t.Fatalf("fresh B policy did not return only B facts: %#v", fresh.Data)
	}
	if result, err := runAppMCPNativeReadGeneration(context.Background(), app, b, pair.AccessToken, grantFixtureResource, "read_note", map[string]any{"id": 2}); err != nil || result == nil || result.Data.(map[string]any)["title"] != "B" {
		t.Fatalf("fresh B point-read did not return B row: result=%+v err=%v", result, err)
	}

	// Invalid route candidates leave B published and usable. Reusing the exact
	// successful config pointer publishes a new generation despite same manifest.
	bad := *configB
	badManifest := *configB.mcp
	badManifest.Tools = append([]AppMCPTool(nil), configB.mcp.Tools...)
	badManifest.Tools[0].Handler = AppMCPHandler{Kind: "native", Operation: "flow.call", Flow: "shadow"}
	bad.mcp = &badManifest
	bad.flows = append(append([]Flow(nil), configB.flows...), Flow{Name: "shadow", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/notes"}})
	if err := reloadAppConfigStaged(app, &bad, nil); err == nil || err.Error() != `mcp.yaml: tool "list_notes" has no uniquely registered flow handler` {
		t.Fatalf("route-conflicting candidate was not rejected by checked flow binding: %v", err)
	}
	if !appMCPGenerationCurrent(app, b) {
		t.Fatal("failed candidate replaced published generation")
	}
	if result, err := runAppMCPNativeReadGeneration(context.Background(), app, b, pair.AccessToken, grantFixtureResource, "read_note", map[string]any{"id": 2}); err != nil || result == nil || result.Data.(map[string]any)["title"] != "B" {
		t.Fatalf("failed candidate made previous operation unusable: result=%+v err=%v", result, err)
	}
	if err := reloadAppConfigStaged(app, configB, nil); err != nil {
		t.Fatal(err)
	}
	c := snapshotAppMCPGeneration(app)
	if result, err := runAppMCPNativeReadGeneration(context.Background(), app, b, pair.AccessToken, grantFixtureResource, "read_note", map[string]any{"id": 2}); result != nil || nativeResultErrorCode(t, err) != "denied" {
		t.Fatalf("same-manifest reload allowed a stale native read: result=%+v err=%v", result, err)
	}
	if c == b || c.manifest != b.manifest || appMCPGenerationCurrent(app, b) {
		t.Fatal("same-pointer reload did not invalidate prior generation")
	}
}

func TestAppMCPPointReadFailsClosedAcrossPolicyReload(t *testing.T) {
	app, pair, uid := appMCPResultFixture(t, true)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT);\nCREATE TABLE members_b (id INTEGER PRIMARY KEY, tenant_key TEXT, email TEXT);\n")
	writeTestFile(t, app.Dir, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\nroles: {editor: {scopes: [notes:read]}}\nscopes: {notes: {public_read_when: \"title = 'A'\"}}\n")
	reviewAppMCPFixture(t, app.Dir)
	configA, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfigStaged(app, configA, nil); err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "INSERT INTO members_b(tenant_key,email) VALUES ('17','delegate@example.com')")
	auditExec(t, app.DB, "UPDATE notes SET title='A' WHERE id=1")
	auditExec(t, app.DB, "UPDATE notes SET user_id=?,title='B' WHERE id=2", uid)

	var configB *runtimeConfig
	appMCPGenerationSingleReadBarrier(t, app, func() error {
		writeTestFile(t, app.Dir, "app.yaml", "groups: {table: members_b, key: tenant_key, user_field: email}\nroles: {editor: {inherits: [viewer]}, viewer: {scopes: [notes:read]}}\naccess: {notes: {read: self}}\nscopes: {notes: {public_read_when: \"title = 'B'\"}}\n")
		reviewAppMCPFixture(t, app.Dir)
		var err error
		configB, err = loadRuntimeConfig(app.Dir)
		if err != nil {
			return err
		}
		return reloadAppConfigStaged(app, configB, nil)
	})
	app.mu.Lock()
	a := newAppMCPRuntimeGeneration(app, configA.mcp, configA.group, configA.roles, configA.access, configA.scopes, configA.design, app.Tables, app.UUIDTables, configA.encrypted, configA.flows, configA.sourceFiles, app.environment, configA.templateEnvSource, configA.hooks, configA.validators, configA.computed, configA.workflows, configA.pages)
	app.mcpGeneration = a
	app.mu.Unlock()
	if result, err := runAppMCPNativeReadGeneration(context.Background(), app, a, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"id": 1}); result != nil || nativeResultErrorCode(t, err) != "denied" {
		t.Fatalf("in-flight A point read crossed B policy publication: result=%+v err=%v", result, err)
	}
	b := snapshotAppMCPGeneration(app)
	if configB == nil || b == a || b.view.Group.Key != "tenant_key" {
		t.Fatal("B tenant key policy was not published")
	}
	result, err := runAppMCPNativeReadGeneration(context.Background(), app, b, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"id": 2})
	if err != nil || result == nil || result.Data.(map[string]any)["id"] == nil {
		t.Fatalf("fresh B point read lacked its authorized row: %+v %v", result, err)
	}
}

func TestAppMCPFlowUsesPublishedFlowSourceAndEnvironment(t *testing.T) {
	const childEnv = "BENMORE_MCP_GOJA_RELOAD_CHILD"
	if mode := os.Getenv(childEnv); mode != "" {
		runAppMCPGojaReloadChild(t, mode)
		return
	}
	for _, mode := range []string{"changed-source", "same-config"} {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppMCPFlowUsesPublishedFlowSourceAndEnvironment$")
		cmd.Env = append(os.Environ(), childEnv+"="+mode)
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			t.Fatalf("isolated active-Goja %s reload fixture failed: %v\n%s", mode, err, output)
		}
	}

	app, uid, pair, _ := appMCPReadFlowFixture(t, "GET", false)
	flow := func() string {
		return `on:
  request:
    method: GET
    path: /api/mcp-note/:id
    auth: required
    role: editor
    permissions: [notes:read]
jobs:
  read_note:
    steps:
      - id: note
        query: SELECT id, user_id AS actor_id, CAST(:_group_id AS TEXT) AS tenant_id, 'base' AS title FROM notes WHERE id = :id AND user_id = :user_id
      - id: checked
        run: compute
        with:
          module: revision
          function: inspect
          args:
            row: ${{ steps.note.outputs.rows[0] }}
            env: '{{env.REVISION}}'
      - run: respond
        with:
          body: ${{ steps.checked.outputs }}`
	}
	writeTestFile(t, app.Dir, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\nroles: {editor: {scopes: [notes:read]}}\n")
	writeTestFile(t, app.Dir, "flows/read_note.yaml", flow())
	writeTestFile(t, app.Dir, "static/revision.ts", `export function inspect(args) { return {...args.row, title: "A:" + args.env}; }`)
	writeTestFile(t, app.Dir, "env.yaml", "REVISION: source-A\n")
	reviewAppMCPFixture(t, app.Dir)
	configA, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	envA, err := configA.stageEnvironment(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfigStaged(app, configA, envA); err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (1,?,'fixture')", uid)
	var configB *runtimeConfig
	var envB map[string]string
	// This barrier publishes B during A's SQL step, before A reaches Goja.
	// The fixture covers release invalidation and B's source/environment pair;
	// it does not claim to pause an already-running Goja computation.
	appMCPGenerationSingleReadBarrier(t, app, func() error {
		writeTestFile(t, app.Dir, "static/revision.ts", `export function inspect(args) { return {...args.row, title: "B:" + args.env}; }`)
		writeTestFile(t, app.Dir, "env.yaml", "REVISION: source-B\n")
		reviewAppMCPFixture(t, app.Dir)
		var err error
		configB, err = loadRuntimeConfig(app.Dir)
		if err != nil {
			return err
		}
		envB, err = configB.stageEnvironment(app.Dir)
		if err != nil {
			return err
		}
		return reloadAppConfigStaged(app, configB, envB)
	})
	app.mu.Lock()
	a := newAppMCPRuntimeGeneration(app, configA.mcp, configA.group, configA.roles, configA.access, configA.scopes, configA.design, app.Tables, app.UUIDTables, configA.encrypted, configA.flows, configA.sourceFiles, envA, configA.templateEnvSource, configA.hooks, configA.validators, configA.computed, configA.workflows, configA.pages)
	app.mcpGeneration = a
	app.mu.Unlock()
	if result, err := runAppMCPNativeReadGeneration(context.Background(), app, a, pair.AccessToken, grantFixtureResource, "read_note", map[string]any{"id": 1}); result != nil || nativeResultErrorCode(t, err) != "denied" {
		t.Fatalf("in-flight A flow/compute crossed B publication: result=%+v err=%v", result, err)
	}
	b := snapshotAppMCPGeneration(app)
	if configB == nil || envB["REVISION"] != "source-B" || b == a {
		t.Fatal("flow candidate did not publish B source/environment generation")
	}
	result, err := runAppMCPNativeReadGeneration(context.Background(), app, b, pair.AccessToken, grantFixtureResource, "read_note", map[string]any{"id": 1})
	if err != nil {
		t.Fatal(err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok || data["title"] != "B:source-B" {
		t.Fatalf("flow mixed source/environment generations: %#v", result.Data)
	}
}

// appMCPGojaPauseReader is installed only in the isolated test subprocess.
// It delegates every read and pauses once only after the fixture arms it.
type appMCPGojaPauseReader struct {
	delegate    io.Reader
	armed       atomic.Bool
	entered     chan struct{}
	release     chan struct{}
	pauseOnce   sync.Once
	releaseOnce sync.Once
}

func (r *appMCPGojaPauseReader) Read(p []byte) (int, error) {
	if len(p) == 4096 && r.armed.Load() {
		r.pauseOnce.Do(func() {
			close(r.entered)
			<-r.release
		})
	}
	return r.delegate.Read(p)
}

func (r *appMCPGojaPauseReader) releasePause() {
	r.releaseOnce.Do(func() { close(r.release) })
}

func runAppMCPGojaReloadChild(t *testing.T, mode string) {
	t.Helper()
	if mode != "changed-source" && mode != "same-config" {
		t.Fatalf("unknown active-Goja child mode %q", mode)
	}
	reader := &appMCPGojaPauseReader{
		delegate: cryptorand.Reader,
		entered:  make(chan struct{}),
		release:  make(chan struct{}),
	}
	// This process exits after the test; do not restore the package global.
	// Installing before fixture creation ensures setup entropy is delegated too.
	cryptorand.Reader = reader
	defer reader.releasePause()

	app, uid, pair, _ := appMCPReadFlowFixture(t, "GET", false)
	flow := `on:
  request:
    method: GET
    path: /api/mcp-note/:id
    auth: required
    role: editor
    permissions: [notes:read]
jobs:
  read_note:
    steps:
      - id: note
        query: SELECT id, user_id AS actor_id, CAST(:_group_id AS TEXT) AS tenant_id, 'base' AS title FROM notes WHERE id = :id AND user_id = :user_id
      - id: checked
        run: compute
        with:
          module: revision
          function: inspect
          args:
            row: ${{ steps.note.outputs.rows[0] }}
            env: '{{env.REVISION}}'
      - run: respond
        with:
          body: ${{ steps.checked.outputs }}`
	writeTestFile(t, app.Dir, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\nroles: {editor: {scopes: [notes:read]}}\n")
	writeTestFile(t, app.Dir, "flows/read_note.yaml", flow)
	writeTestFile(t, app.Dir, "static/revision.ts", `export function inspect(args) { crypto.randomHex(4096); return {...args.row, title: "A:" + args.env}; }`)
	writeTestFile(t, app.Dir, "env.yaml", "REVISION: source-A\n")
	reviewAppMCPFixture(t, app.Dir)
	configA, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	envA, err := configA.stageEnvironment(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfigStaged(app, configA, envA); err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (1,?,'fixture')", uid)

	type response struct {
		result *appMCPReadResult
		err    error
	}
	reader.armed.Store(true)
	done := make(chan response, 1)
	finished := make(chan struct{})
	requestCtx, cancelRequest := context.WithCancel(context.Background())
	go func() {
		defer close(finished)
		result, err := runAppMCPNativeRead(requestCtx, app, pair.AccessToken, grantFixtureResource, "read_note", map[string]any{"id": 1})
		done <- response{result: result, err: err}
	}()
	defer func() {
		cancelRequest()
		reader.releasePause()
		select {
		case <-finished:
		case <-time.After(10 * time.Second):
			t.Error("A request did not join before fixture cleanup")
		}
	}()
	select {
	case <-reader.entered:
	case outcome := <-done:
		t.Fatalf("A flow finished before entering its JavaScript callback: result=%+v err=%v", outcome.result, outcome.err)
	case <-time.After(10 * time.Second):
		t.Fatal("A flow never entered crypto.randomHex inside Goja")
	}

	configB, envB := configA, envA
	wantTitle := "A:source-A"
	if mode == "changed-source" {
		writeTestFile(t, app.Dir, "static/revision.ts", `export function inspect(args) { return {...args.row, title: "B:" + args.env}; }`)
		writeTestFile(t, app.Dir, "env.yaml", "REVISION: source-B\n")
		reviewAppMCPFixture(t, app.Dir)
		configB, err = loadRuntimeConfig(app.Dir)
		if err != nil {
			t.Fatal(err)
		}
		envB, err = configB.stageEnvironment(app.Dir)
		if err != nil {
			t.Fatal(err)
		}
		wantTitle = "B:source-B"
	}
	assertAParked := func(where string) {
		t.Helper()
		select {
		case outcome := <-done:
			t.Fatalf("A request completed %s before callback release: result=%+v err=%v", where, outcome.result, outcome.err)
		default:
		}
	}
	assertAParked("before B publication")
	if err := reloadAppConfigStaged(app, configB, envB); err != nil {
		t.Fatal(err)
	}
	assertAParked("before reader release")
	reader.releasePause()
	select {
	case outcome := <-done:
		if outcome.result != nil || nativeResultErrorCode(t, outcome.err) != "denied" {
			t.Fatalf("in-flight A Goja result crossed B publication: result=%+v err=%v", outcome.result, outcome.err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("in-flight A Goja request did not finish after release")
	}

	fresh, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "read_note", map[string]any{"id": 1})
	if err != nil {
		t.Fatal(err)
	}
	if fresh == nil {
		t.Fatal("fresh B flow returned no result")
	}
	data, ok := fresh.Data.(map[string]any)
	if !ok || data["title"] != wantTitle {
		t.Fatalf("fresh %s flow did not return its matching source and environment: %#v", mode, fresh.Data)
	}
}
