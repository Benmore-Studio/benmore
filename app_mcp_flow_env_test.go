//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

func TestAppMCPReadFlowRetainsEnvironmentAcrossSteps(t *testing.T) {
	fixture, uid, _, _ := appMCPReadFlowFixture(t, http.MethodGet, false)
	dir := fixture.Dir
	auditExec(t, fixture.DB, "INSERT INTO notes(id,user_id,title) VALUES (1,?,'owned')", uid)
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT);\nCREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT);\n")
	writeTestFile(t, dir, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\nroles: {editor: {scopes: [notes:read]}}\naccess: {notes: {all: self}}\n")
	writeTestFile(t, dir, "index.html", "<p>source-backed fixture</p>")
	writeTestFile(t, dir, "env.yaml", "REVIEWED: captured\n")
	writeTestFile(t, dir, ".benmore/env", "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	writeTestFile(t, dir, "flows/read_note.yaml", `on:
  request:
    method: GET
    path: /api/mcp-note/:id
    auth: required
    role: editor
    permissions: [notes:read]
jobs:
  read_note:
    steps:
      - id: rotate
        query: SELECT rotate_fixture_environment() AS changed
      - id: note
        query: SELECT id, user_id AS actor_id, CAST(:_group_id AS TEXT) AS tenant_id, '{{env.REVIEWED}}' || ':' || '{{env.REVIEWED | default:"missing"}}' AS title FROM notes WHERE id = :id AND user_id = :user_id
      - id: checked
        if: ${{ env.REVIEWED }} == 'captured' && ${{ env.REVIEWED }} != 'late'
        run: compute
        with:
          module: env-generation
          function: inspect
          args:
            row: ${{ steps.note.outputs.rows[0] }}
            compact: '{{env.REVIEWED}}'
            pipe: '{{env.REVIEWED | default:"missing"}}'
            late: '{{env.LATE_ONLY | default:"absent"}}'
      - run: respond
        with:
          body: ${{ steps.checked.outputs }}
`)
	writeTestFile(t, dir, "static/env-generation.ts", `export function inspect(args) {
 if (args.compact !== "captured" || args.pipe !== "captured" || args.late !== "absent") throw new Error("environment changed across compute arguments");
 return args.row;
}`)
	reviewAppMCPFixture(t, dir)
	fixture.Shutdown()
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load reviewed native flow app: %v", err)
	}
	t.Cleanup(app.Shutdown)
	if app.environment == nil || app.environment["REVIEWED"] != "captured" {
		t.Fatalf("source loader did not publish captured environment: %#v", app.environment)
	}
	generation := snapshotAppMCPGeneration(app)
	if generation == nil || generation.environment["REVIEWED"] != "captured" || generation.view == nil || generation.view.environment["REVIEWED"] != "captured" {
		t.Fatalf("native runtime generation did not capture source environment: %+v", generation)
	}
	pair := fixtureGrant(t, app, uid, time.Now())
	app.DB.SetMaxOpenConns(1)
	SetAppEnv(app.Dir, "REVIEWED", "captured")
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Raw(func(raw any) error {
		return raw.(*sqlite3.SQLiteConn).RegisterFunc("rotate_fixture_environment", func() int {
			SetAppEnv(app.Dir, "REVIEWED", "late")
			SetAppEnv(app.Dir, "LATE_ONLY", "late-only")
			return 1
		}, false)
	})
	if closeErr := conn.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	result, err := runAppMCPReadFlow(context.Background(), app, pair.AccessToken, grantFixtureResource, &generation.manifest.Tools[0], map[string]any{"id": json.Number("1")})
	if err != nil {
		t.Fatalf("native private flow: %v", err)
	}
	data, ok := result.Data.(map[string]any)
	if !ok || data["title"] != "captured:captured" {
		t.Fatalf("flow crossed environment generation: %#v", result.Data)
	}
	ordinary := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	if got := resolveComputeArgsValue("{{env.REVIEWED}}", ordinary); got != "late" {
		t.Fatalf("ordinary environment lookup changed: %#v", got)
	}
}

func TestAppMCPReloadPublishesEnvironmentBeforeGeneration(t *testing.T) {
	app, _, _, _ := appMCPReadFlowFixture(t, http.MethodGet, false)
	SetAppEnv(app.Dir, "REVIEWED", "old")
	oldManifest := app.MCP
	// Intentional connector removal uses the same publication block while
	// avoiding candidate route registration's unrelated live env readers.
	if err := os.Remove(filepath.Join(app.Dir, "mcp.yaml")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "env.yaml", "REVIEWED: replacement\n")
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	values, err := config.stageEnvironment(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	// Hold only the existing env-store lock: publication must retain app.mu
	// while it waits, rather than exposing replacement metadata with old env.
	appEnvStore.mu.Lock()
	locked := true
	done := make(chan error, 1)
	reloadDone := false
	defer func() {
		if locked {
			appEnvStore.mu.Unlock()
		}
		if !reloadDone {
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Error("reload cleanup did not finish")
			}
		}
	}()
	go func() { done <- reloadAppConfigStaged(app, config, values) }()
	deadline := time.NewTimer(2 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(time.Millisecond)
	defer tick.Stop()
	for {
		if !app.mu.TryRLock() {
			break
		}
		current := app.MCP
		app.mu.RUnlock()
		if current != oldManifest {
			t.Fatal("replacement generation became visible before environment publication")
		}
		select {
		case err := <-done:
			reloadDone = true
			t.Fatalf("reload ended before blocked environment publication: %v", err)
		case <-deadline.C:
			t.Fatal("reload never reached publication")
		case <-tick.C:
		}
	}
	observed := make(chan *AppMCPManifest, 1)
	go func() { observed <- appMCPManifestSnapshot(app) }()
	select {
	case <-observed:
		t.Fatal("generation reader crossed blocked environment publication")
	case <-time.After(30 * time.Millisecond):
	}
	appEnvStore.mu.Unlock()
	locked = false
	select {
	case err := <-done:
		reloadDone = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("reload publication did not finish")
	}
	select {
	case got := <-observed:
		if got != config.mcp {
			t.Fatal("reader did not receive the completed generation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("generation reader remained blocked")
	}
	app.mu.RLock()
	env := AppEnvSnapshot(app.Dir)
	source := string(app.templateEnvSource)
	app.mu.RUnlock()
	if env["REVIEWED"] != "replacement" || source != "REVIEWED: replacement\n" {
		t.Fatalf("published fixture environment pair mismatched: %q %q", env["REVIEWED"], source)
	}
}

func TestAppMCPColdReplacementRetainsEachAppsEnvironment(t *testing.T) {
	fixture, uid, _, _ := appMCPReadFlowFixture(t, http.MethodGet, false)
	writeTestFile(t, fixture.Dir, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\naccess: {notes: {all: self}}\nroles: {editor: {scopes: [notes:read]}}\n")
	writeTestFile(t, fixture.Dir, "index.html", "<p>synthetic fixture</p>")
	writeTestFile(t, fixture.Dir, "env.yaml", "")
	writeTestFile(t, fixture.Dir, ".benmore/env", "")
	t.Setenv("CREDENTIALS_DIRECTORY", "")
	writeTestFile(t, fixture.Dir, "flows/read_note.yaml", `on:
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
        query: SELECT id, user_id AS actor_id, CAST(:_group_id AS TEXT) AS tenant_id, '{{env.REVIEWED | default:"absent"}}' || ':' || '{{env.LATE_ONLY | default:"absent"}}' AS title FROM notes WHERE id = :id AND user_id = :user_id
      - run: respond
        with:
          body: ${{ steps.note.outputs.rows[0] }}
`)
	reviewAppMCPFixture(t, fixture.Dir)
	old, err := loadApp(fixture.Dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(old.Shutdown)
	if old.environment == nil || len(old.environment) != 0 {
		t.Fatalf("old app was not cold-loaded with an empty bound generation (nil=%t, keys=%d)", old.environment == nil, len(old.environment))
	}
	oldGeneration := snapshotAppMCPGeneration(old)
	if oldGeneration == nil || oldGeneration.environment == nil || len(oldGeneration.environment) != 0 || oldGeneration.view == nil || oldGeneration.view.environment == nil || len(oldGeneration.view.environment) != 0 {
		t.Fatalf("old runtime generation did not retain an explicitly empty captured environment: %+v", oldGeneration)
	}
	auditExec(t, old.DB, "INSERT INTO notes(id,user_id,title) VALUES (1,?,'owned')", uid)
	pair := fixtureGrant(t, old, uid, time.Now())
	writeTestFile(t, fixture.Dir, "env.yaml", "REVIEWED: replacement\nLATE_ONLY: present\n")
	replacement, err := loadApp(fixture.Dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(replacement.Shutdown)
	for _, tc := range []struct {
		name  string
		app   *App
		title string
	}{
		{"old", old, "absent:absent"}, {"replacement", replacement, "replacement:present"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result, err := runAppMCPReadFlow(context.Background(), tc.app, pair.AccessToken, grantFixtureResource, &tc.app.MCP.Tools[0], map[string]any{"id": json.Number("1")})
			if err != nil {
				t.Fatalf("actual private flow: %v", err)
			}
			row, ok := result.Data.(map[string]any)
			if !ok || row["title"] != tc.title {
				t.Fatalf("cold generation changed: %#v, want %q", result.Data, tc.title)
			}
		})
	}
	if got := GetAppEnv(fixture.Dir, "REVIEWED"); got != "replacement" {
		t.Fatalf("ordinary current lookup = %q", got)
	}
	if got := GetAppEnv(fixture.Dir, "LATE_ONLY"); got != "present" {
		t.Fatalf("ordinary replacement lookup = %q", got)
	}
	if oldGeneration.environment["REVIEWED"] != "" || oldGeneration.environment["LATE_ONLY"] != "" {
		t.Fatalf("old captured environment inherited replacement keys: %#v", oldGeneration.environment)
	}
}
