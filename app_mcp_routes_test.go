//go:build !cli

package main

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func mcpRouteFlow(name, path string) Flow {
	return Flow{Name: name, Trigger: FlowTrigger{Type: "http", Method: "GET", Path: path}, Permissions: []string{"notes:read"}}
}
func TestAppMCPRouteBindingUsesCanonicalRegistration(t *testing.T) {
	manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	tables := map[string]bool{"notes": true}
	for _, tc := range []struct {
		name, operation string
		flows           []Flow
		wantError       bool
	}{
		{"list registered", "table.list", nil, false},
		{"read registered", "table.read", nil, false},
		{"static read shadow", "table.read", []Flow{mcpRouteFlow("shadow", "/api/notes/special")}, true},
		{"subtree redirect shadow", "table.read", []Flow{mcpRouteFlow("shadow", "/api/notes/special/")}, true},
		{"remainder redirect shadow", "table.read", []Flow{mcpRouteFlow("shadow", "/api/notes/special/{rest...}")}, true},
		{"end-marker redirect shadow", "table.read", []Flow{mcpRouteFlow("shadow", "/api/notes/special/{$}")}, true},
		{"escaped reserved path", "table.list", []Flow{mcpRouteFlow("shadow", "/api/%5Fmcp")}, true},
		{"escaped reserved descendant", "table.list", []Flow{mcpRouteFlow("shadow", "/%61pi/%5Fmcp/foo")}, true},
		{"dynamic read shadow", "table.read", []Flow{mcpRouteFlow("shadow", "/api/notes/:id")}, true},
		{"unrelated flow", "table.read", []Flow{mcpRouteFlow("other", "/api/other/:id")}, false},
		{"reserved path", "table.list", []Flow{mcpRouteFlow("bad", "/api/_mcp")}, true},
		{"reserved descendant", "table.list", []Flow{mcpRouteFlow("bad", "/api/_mcp/tool")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			manifest.Tools[0].Handler.Operation = tc.operation
			err := validateAppMCPRouteBindings(manifest, tc.flows, tables)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v wantError=%v", err, tc.wantError)
			}
		})
	}
	manifest.Tools[0].Handler = AppMCPHandler{Kind: "native", Operation: "flow.call", Flow: "read_notes"}
	for _, tc := range []struct {
		name      string
		flows     []Flow
		wantError bool
	}{
		{"registered flow", []Flow{mcpRouteFlow("read_notes", "/api/read-notes")}, false},
		{"skipped collision", []Flow{mcpRouteFlow("read_notes", "/api/notes")}, true},
		{"static shadow", []Flow{mcpRouteFlow("read_notes", "/api/read-notes/:id"), mcpRouteFlow("other", "/api/read-notes/special")}, true},
		{"duplicate name", []Flow{mcpRouteFlow("read_notes", "/api/read-notes"), mcpRouteFlow("read_notes", "/api/read-notes-2")}, true},
		{"unsupported subtree", []Flow{mcpRouteFlow("read_notes", "/api/read-notes/")}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateAppMCPRouteBindings(manifest, tc.flows, tables)
			if (err != nil) != tc.wantError {
				t.Fatalf("error=%v wantError=%v", err, tc.wantError)
			}
		})
	}
}

func TestAppMCPRouteInvalidBindingPrecedesReloadMigration(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Stop = make(chan struct{})
	defer close(app.Stop)
	old := &AppMCPManifest{Version: 1}
	app.MCP = old
	source := strings.Replace(appMCPManifestFixture(), "operation: table.list", "operation: table.read", 1)
	writeTestFile(t, app.Dir, "mcp.yaml", source)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER);\nCREATE TABLE should_not_exist (id INTEGER);")
	writeTestFile(t, app.Dir, "flows/shadow.yaml", "on:\n  request: {method: GET, path: /api/notes/:id}\njobs:\n  read:\n    steps:\n      - query: SELECT 1\n")
	reviewAppMCPFixture(t, app.Dir)
	if err := hotReloadApp(app, false); err == nil {
		t.Fatal("shadowed native binding accepted")
	}
	if app.MCP != old {
		t.Fatal("invalid binding replaced active manifest")
	}
	select {
	case <-app.Stop:
		t.Fatal("invalid binding stopped workers")
	default:
	}
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='should_not_exist'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid binding migrated: count=%d err=%v", count, err)
	}
}

func TestRegisteredFlowInventoryOmitsSkippedHandler(t *testing.T) {
	mux := http.NewServeMux()
	app := &App{}
	registerCRUDTables(mux, app, []string{"notes"})
	registered := RegisterFlows(mux, app, []Flow{mcpRouteFlow("skipped", "/api/notes"), mcpRouteFlow("live", "/api/read-notes")})
	if _, exists := registered["skipped"]; exists {
		t.Fatal("skipped flow reported registered")
	}
	_, pattern := mux.Handler(httptest.NewRequest("GET", "/api/read-notes", nil))
	if registered["live"] != pattern {
		t.Fatalf("actual handler=%q inventory=%q", pattern, registered["live"])
	}
}

func TestAppMCPRouteBindingRequiresResolvableProbe(t *testing.T) {
	manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Tools[0].Handler.Table = "notes#fragment"
	if err := validateAppMCPRegisteredBindings(manifest, nil, http.NewServeMux(), nil, nil); err == nil {
		t.Fatal("unregistered delimiter-bearing route accepted")
	}
	// Literal fragments are valid path segments once probes encode them correctly.
	if err := validateAppMCPRouteBindings(manifest, nil, map[string]bool{"notes#fragment": true}); err != nil {
		t.Fatalf("resolvable escaped route rejected: %v", err)
	}
}

func TestAppMCPDatabaseBindingRejectsRetainedTableBeforeMigration(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Stop = make(chan struct{})
	defer close(app.Stop)
	mustExec(t, app.DB, "CREATE TABLE read_notes (id INTEGER)")
	source := strings.Replace(appMCPManifestFixture(), "handler: {kind: native, operation: table.list, table: notes}", "handler: {kind: native, operation: flow.call, flow: read_notes}", 1)
	writeTestFile(t, app.Dir, "mcp.yaml", source)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE should_not_exist (id INTEGER);")
	writeTestFile(t, app.Dir, "flows/read_notes.yaml", "on:\n  request: {method: GET, path: /api/read_notes, permissions: [notes:read]}\njobs:\n  read:\n    steps:\n      - query: SELECT 1\n")
	reviewAppMCPFixture(t, app.Dir)
	if err := hotReloadApp(app, false); err == nil {
		t.Fatal("retained table collision accepted")
	}
	select {
	case <-app.Stop:
		t.Fatal("retained collision retired workers")
	default:
	}
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='should_not_exist'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("retained collision migrated: %d %v", count, err)
	}
}

func TestAppMCPEligibilityMatchesLiveSQLite(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	source := `CREATE TABLE notes (id INTEGER PRIMARY KEY);
CREATE TABLE notes_history (id INTEGER, _version INTEGER, _valid_from TEXT, _valid_to TEXT, _changed_by TEXT, _change_type TEXT);
CREATE TABLE business_history (id INTEGER, comment TEXT);
CREATE TABLE _benmore_private (id INTEGER);
CREATE VIRTUAL TABLE notes_fts USING fts5(body);
CREATE TABLE quoted_history ("(" TEXT, _version INTEGER, _valid_from TEXT, _valid_to TEXT, _changed_by TEXT, _change_type TEXT);
`
	writeTestFile(t, app.Dir, "schema.sql", source)
	if err := splitSQLStatements(strings.NewReader(source), func(statement string) error { _, err := app.DB.Exec(statement); return err }); err != nil {
		t.Fatal(err)
	}
	expected, err := GetTableNames(app.DB)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := appMCPSchemaTables(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(expected) != len(actual) {
		t.Fatalf("source eligible=%v live=%v", actual, expected)
	}
	for _, name := range expected {
		if !actual[name] {
			t.Fatalf("source missed eligible %s", name)
		}
	}
	if actual["notes_history"] || actual["notes_fts"] || actual["quoted_history"] {
		t.Fatalf("internal eligible=%v", actual)
	}
}

func TestAppMCPDatabaseBindingKeepsExistingHistoryExcluded(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE notes_history (id INTEGER, _version INTEGER, _valid_from TEXT, _valid_to TEXT, _changed_by TEXT, _change_type TEXT)")
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes_history (id INTEGER);")
	source := strings.ReplaceAll(appMCPManifestFixture(), "notes", "notes_history")
	manifest, err := parseAppMCPManifest([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPDatabaseBindings(app.Dir, manifest, nil, app.DB); err == nil {
		t.Fatal("retained history metadata exposed as canonical CRUD")
	}
}

func TestAppMCPDatabaseBindingPreservesColumnSpellingAndTableKind(t *testing.T) {
	for _, tc := range []struct{ name, live, source string }{
		{"column spelling", `CREATE TABLE notes_history (id INTEGER, _VERSION INTEGER, _valid_from TEXT, _valid_to TEXT, _changed_by TEXT, _change_type TEXT)`, `CREATE TABLE notes_history (id INTEGER, _version INTEGER, _valid_from TEXT, _valid_to TEXT, _changed_by TEXT, _change_type TEXT);`},
		{"table kind", `CREATE TABLE notes_history (id INTEGER)`, `CREATE VIRTUAL TABLE notes_history USING fts5(body);`},
		{"hidden identity", `CREATE TABLE notes_history (id INTEGER, _version INTEGER AS (1), _valid_from TEXT, _valid_to TEXT, _changed_by TEXT, _change_type TEXT)`, `CREATE TABLE notes_history (id INTEGER, _version INTEGER, _valid_from TEXT, _valid_to TEXT, _changed_by TEXT, _change_type TEXT);`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			mustExec(t, app.DB, tc.live)
			writeTestFile(t, app.Dir, "schema.sql", tc.source)
			manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
			if err != nil {
				t.Fatal(err)
			}
			manifest.Tools[0].Handler = AppMCPHandler{Kind: "native", Operation: "flow.call", Flow: "history"}
			flow := mcpRouteFlow("history", "/api/notes_history")
			if err := validateAppMCPDatabaseBindings(app.Dir, manifest, []Flow{flow}, app.DB); err == nil {
				t.Fatal("live CRUD collision hidden by source metadata")
			}
		})
	}
}

func TestAppMCPGeneratedHistoryColumnMatchesLiveVisibility(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	source := `CREATE TABLE notes_history (id INTEGER, _version INTEGER GENERATED ALWAYS AS (1), _valid_from TEXT, _valid_to TEXT, _changed_by TEXT, _change_type TEXT);`
	writeTestFile(t, app.Dir, "schema.sql", source)
	mustExec(t, app.DB, source)
	actual, err := appMCPSchemaTables(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := GetTableNames(app.DB)
	if err != nil {
		t.Fatal(err)
	}
	if !actual["notes_history"] || len(expected) != 1 || expected[0] != "notes_history" {
		t.Fatalf("generated visibility mismatches: source=%v live=%v", actual, expected)
	}
	manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Tools[0].Handler = AppMCPHandler{Kind: "native", Operation: "flow.call", Flow: "history"}
	if err := validateAppMCPRouteBindings(manifest, []Flow{mcpRouteFlow("history", "/api/notes_history")}, actual); err == nil {
		t.Fatal("generated-column history concealed CRUD collision")
	}
}

func TestAppMCPGeneratedMetadataAdditionRejectedBeforeMigration(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Stop = make(chan struct{})
	defer close(app.Stop)
	mustExec(t, app.DB, "CREATE TABLE notes_history (id INTEGER, _valid_from TEXT, _valid_to TEXT, _changed_by TEXT, _change_type TEXT)")
	writeTestFile(t, app.Dir, "schema.sql", `CREATE TABLE notes_history (
 id INTEGER,
 _version INTEGER GENERATED ALWAYS AS (1),
 _valid_from TEXT,
 _valid_to TEXT,
 _changed_by TEXT,
 _change_type TEXT
);`)
	writeTestFile(t, app.Dir, "mcp.yaml", strings.ReplaceAll(appMCPManifestFixture(), "notes", "notes_history"))
	reviewAppMCPFixture(t, app.Dir)
	if err := hotReloadApp(app, false); err == nil {
		t.Fatal("unsupported generated metadata addition passed preflight")
	}
	select {
	case <-app.Stop:
		t.Fatal("unsupported addition retired workers")
	default:
	}
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM pragma_table_info('notes_history') WHERE name='_version'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("unsupported generated addition migrated: count=%d err=%v", count, err)
	}
}

func TestAppMCPRejectsAmbiguousDuplicateSchemaDeclarations(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE IF NOT EXISTS notes (id INTEGER);\nCREATE TABLE IF NOT EXISTS NOTES (id INTEGER, body TEXT);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	if _, err := loadRuntimeConfig(dir); err == nil {
		t.Fatal("ambiguous duplicate physical binding accepted")
	}
}

func TestRegisteredPageInventoryUsesActualPatterns(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/notes", http.NotFound)
	app := &App{Pages: map[string]*Page{
		"/":             {RawHTML: "home"},
		"/contacts/:id": {RawHTML: "contact"},
		"/api/notes":    {RawHTML: "skipped"},
	}}
	registered := registerAppPageRoutes(mux, app, false)
	seen := map[string]bool{}
	for _, pattern := range registered {
		seen[pattern] = true
	}
	if len(registered) != 2 || !seen["GET /{$}"] || !seen["GET /contacts/{id}"] || seen["GET /api/notes"] {
		t.Fatalf("unexpected successful page patterns: %v", registered)
	}
	for path, expected := range map[string]string{"/": "GET /{$}", "/contacts/123": "GET /contacts/{id}", "/api/notes": "GET /api/notes"} {
		_, pattern := mux.Handler(httptest.NewRequest("GET", path, nil))
		if pattern != expected {
			t.Fatalf("resolved %q to %q, expected %q", path, pattern, expected)
		}
	}
}

func TestAppMCPFullCandidateRejectsFrameworkAndPageShadows(t *testing.T) {
	for _, tc := range []struct {
		name, path string
		page       bool
	}{
		{"framework skipped flow", "/api/_query", false},
		{"framework literal shadows wildcard", "/:id", false},
		{"framework health collision", "/health", false},
		{"page read shadow", "/api/notes/special", true},
		{"reserved escaped page", "/api/%5Fmcp/tool", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER);\n")
			manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
			if err != nil {
				t.Fatal(err)
			}
			config := &runtimeConfig{mcp: manifest, migrations: map[string][]byte{}, pages: map[string]*Page{}, schemaSources: map[string][]byte{"schema.prisma": nil, "schema.sql": []byte("CREATE TABLE notes (id INTEGER);\n")}}
			if tc.page {
				manifest.Tools[0].Handler.Operation = "table.read"
				config.pages[tc.path] = &Page{RawHTML: "fixture"}
			} else {
				manifest.Tools[0].Handler = AppMCPHandler{Kind: "native", Operation: "flow.call", Flow: "fixture"}
				flow := mcpRouteFlow("fixture", tc.path)
				if tc.path == "/api/_query" {
					flow.Trigger.Method = "POST"
				}
				config.flows = []Flow{flow}
			}
			if err := validateAppMCPCandidateRoutes(app.Dir, config, app.DB, map[string]string{}); err == nil {
				t.Fatal("full candidate shadow accepted")
			}
		})
	}
}

func TestAppMCPCandidateRegistrationHasNoStartupEffects(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.DB.SetMaxOpenConns(1)
	mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER)")
	enabled := true
	app.Design = &DesignConfig{Auth: map[string]string{"billing_provider": "stripe"}, Features: &FeaturesConfig{Testing: &enabled}}
	app.Paths = DiscoverAuthPaths(nil)
	app.routeEnv = map[string]string{"DEMO_PASSWORD": "fixture"}
	app.Pages = map[string]*Page{"/": {RawHTML: "fixture"}}
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"notes": {Name: "notes", Table: "notes", Timeouts: map[string]WorkflowTimeout{"pending": {After: time.Hour, To: "done"}}}}}
	before, err := QueryRows(app.DB, "SELECT name, sql FROM sqlite_master ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var changesBefore int
	if err := app.DB.QueryRow("SELECT total_changes()").Scan(&changesBefore); err != nil {
		t.Fatal(err)
	}
	filesBefore, err := os.ReadDir(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	signedURLKeyMu.Lock()
	keyBefore := append([]byte(nil), signedURLKey...)
	signedURLKeyMu.Unlock()
	mux := buildAppRouteMux(app, false, "", false, []string{"notes"})
	after, err := QueryRows(app.DB, "SELECT name, sql FROM sqlite_master ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var changesAfter int
	if err := app.DB.QueryRow("SELECT total_changes()").Scan(&changesAfter); err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(before) != fmt.Sprint(after) || changesBefore != changesAfter {
		t.Fatal("candidate registration changed SQLite")
	}
	filesAfter, err := os.ReadDir(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(filesBefore) != len(filesAfter) {
		t.Fatal("candidate registration created files")
	}
	for i := range filesBefore {
		if filesBefore[i].Name() != filesAfter[i].Name() {
			t.Fatal("candidate registration changed files")
		}
	}
	signedURLKeyMu.Lock()
	sameKey := bytes.Equal(keyBefore, signedURLKey)
	signedURLKeyMu.Unlock()
	if !sameKey || app.Stop != nil || app.readAudit != nil || app.usage != nil || app.SessionDuration != 0 {
		t.Fatal("candidate registration initialized runtime state")
	}
	for _, path := range []string{"/api/_query", "/api/_scheduled", "/api/_auth/token", "/api/_billing/me", "/api/_feedback", "/api/notes/1/transitions"} {
		method := "GET"
		if path == "/api/_query" || path == "/api/_scheduled" || path == "/api/_auth/token" || path == "/api/_feedback" {
			method = "POST"
		}
		_, pattern := mux.Handler(httptest.NewRequest(method, path, nil))
		expected := method + " " + path
		if path == "/api/notes/1/transitions" {
			expected = "GET /api/notes/{id}/transitions"
		}
		if pattern != expected {
			t.Fatalf("candidate resolved %s to %q, expected %q", path, pattern, expected)
		}
	}
}

func TestAppMCPFullCandidateInvalidBindingPrecedesReloadEffects(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Stop = make(chan struct{})
	defer close(app.Stop)
	old := &AppMCPManifest{Version: 1}
	app.MCP = old
	oldPages := map[string]*Page{"/original": {RawHTML: "old"}}
	app.Pages = oldPages
	source := strings.Replace(appMCPManifestFixture(), "handler: {kind: native, operation: table.list, table: notes}", "handler: {kind: native, operation: flow.call, flow: read_notes}", 1)
	writeTestFile(t, app.Dir, "mcp.yaml", source)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE should_not_exist (id INTEGER);")
	writeTestFile(t, app.Dir, "flows/read_notes.yaml", "on:\n  request: {method: GET, path: /health, permissions: [notes:read]}\njobs:\n  read:\n    steps:\n      - query: SELECT 1\n")
	writeTestFile(t, app.Dir, "new-page.html", "<page>new</page>")
	reviewAppMCPFixture(t, app.Dir)
	if err := hotReloadApp(app, false); err == nil {
		t.Fatal("full framework collision accepted")
	}
	if app.MCP != old || app.Pages["/original"] != oldPages["/original"] || app.Pages["/new-page"] != nil {
		t.Fatal("failed candidate replaced current configuration")
	}
	select {
	case <-app.Stop:
		t.Fatal("failed candidate stopped workers")
	default:
	}
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='should_not_exist'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed candidate migrated: count=%d err=%v", count, err)
	}
}

func TestAppMCPReservedEncodedTableCannotOverrideConnector(t *testing.T) {
	manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPRouteBindings(manifest, nil, map[string]bool{"notes": true, "%5Fmcp": true}); err == nil {
		t.Fatal("encoded table alias can override the connector")
	}
}

func TestAppMCPReloadPublishesStagedPages(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER);")
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	writeTestFile(t, app.Dir, "new-page.html", "<p>fixture page</p>")
	app.Pages = map[string]*Page{"/old": {RawHTML: "old"}}
	reviewAppMCPFixture(t, app.Dir)
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	if app.Pages["/new-page"] == nil || app.Pages["/old"] != nil || app.Paths == nil {
		t.Fatal("candidate pages were not published with manifest")
	}
	mux := buildAppMux(app, false, "https://fixture.example.com")
	_, pattern := mux.Handler(httptest.NewRequest("GET", "/new-page", nil))
	if pattern != "GET /new-page" {
		t.Fatalf("runtime did not use staged page: %q", pattern)
	}
}

func TestAppMCPDelimiterShadowsAndReservedDescendants(t *testing.T) {
	manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Tools[0].Handler = AppMCPHandler{Kind: "native", Operation: "flow.call", Flow: "read"}
	for _, path := range []string{"/read/special?x", "/read/special#x", "/read/special%2Fx"} {
		if err := validateAppMCPRouteBindings(manifest, []Flow{mcpRouteFlow("read", "/read/:id"), mcpRouteFlow("shadow", path)}, map[string]bool{}); err == nil {
			t.Fatalf("delimiter shadow accepted: %s", path)
		}
	}
	manifest.Tools[0].Handler = AppMCPHandler{Kind: "native", Operation: "table.list", Table: "notes"}
	for _, name := range []string{"_mcp/tools", "%5Fmcp/tools"} {
		if err := validateAppMCPRouteBindings(manifest, nil, map[string]bool{"notes": true, name: true}); err == nil {
			t.Fatalf("reserved descendant accepted: %s", name)
		}
	}
	if reserved, err := appMCPReservedRoute("/api/_mcp%2Ftools"); err != nil || reserved {
		t.Fatalf("encoded slash became a separator: reserved=%v err=%v", reserved, err)
	}
}

func TestAppMCPPendingMigrationBindingPrecedesEffects(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Stop = make(chan struct{})
	defer close(app.Stop)
	old := &AppMCPManifest{Version: 1}
	app.MCP = old
	source := strings.Replace(appMCPManifestFixture(), "handler: {kind: native, operation: table.list, table: notes}", "handler: {kind: native, operation: flow.call, flow: read_notes}", 1)
	writeTestFile(t, app.Dir, "mcp.yaml", source)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE should_not_exist (id INTEGER);")
	writeTestFile(t, app.Dir, "flows/read_notes.yaml", "on:\n  request: {method: GET, path: /api/read_notes, permissions: [notes:read]}\njobs:\n  read:\n    steps:\n      - query: SELECT 1\n")
	writeTestFile(t, app.Dir, "migrations/new_table.sql", "CREATE TABLE read_notes (id INTEGER);")
	reviewAppMCPFixture(t, app.Dir)
	if err := hotReloadApp(app, false); err == nil {
		t.Fatal("pending migration collision accepted")
	}
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE name IN ('should_not_exist','read_notes','_benmore_migrations')").Scan(&count); err != nil || count != 0 {
		t.Fatalf("candidate applied DDL: count=%d err=%v", count, err)
	}
	if app.MCP != old {
		t.Fatal("candidate changed active manifest")
	}
	select {
	case <-app.Stop:
		t.Fatal("candidate retired workers")
	default:
	}
}

func TestAppMCPMigrationProjectionSupportsCreatesAndSkipsAppliedDDL(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER)")
	mustExec(t, app.DB, "CREATE TABLE _benmore_migrations (name TEXT PRIMARY KEY)")
	mustExec(t, app.DB, "INSERT INTO _benmore_migrations VALUES ('applied.sql')")
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER);")
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	writeTestFile(t, app.Dir, "migrations/applied.sql", "ALTER TABLE notes RENAME TO stale_name;")
	writeTestFile(t, app.Dir, "migrations/new.sql", "-- UP --\nCREATE TABLE other (id INTEGER);\n-- DOWN --\nDROP TABLE other;")
	reviewAppMCPFixture(t, app.Dir)
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='other'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("canonical migration did not create projected table: count=%d err=%v", count, err)
	}
	writeTestFile(t, app.Dir, "migrations/unsupported.sql", "ALTER TABLE notes RENAME TO read_notes;")
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPCandidateRoutes(app.Dir, config, app.DB, map[string]string{}); err == nil {
		t.Fatal("unsupported pending route DDL accepted")
	}
}

func TestAppMCPFailedLoadRetainsOwningEnvironment(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	before := AppEnvSnapshot(app.Dir)
	defer storeAppEnv(app.Dir, before)
	storeAppEnv(app.Dir, map[string]string{"MCP_FIXTURE": "old"})
	source := strings.Replace(appMCPManifestFixture(), "handler: {kind: native, operation: table.list, table: notes}", "handler: {kind: native, operation: flow.call, flow: read_notes}", 1)
	writeTestFile(t, app.Dir, "mcp.yaml", source)
	writeTestFile(t, app.Dir, "env.yaml", "MCP_FIXTURE: new\n")
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE should_not_exist (id INTEGER);")
	writeTestFile(t, app.Dir, "index.html", "<p>fixture</p>")
	writeTestFile(t, app.Dir, "flows/read_notes.yaml", "on:\n  request: {method: GET, path: /health, permissions: [notes:read]}\njobs:\n  read:\n    steps:\n      - query: SELECT 1\n")
	reviewAppMCPFixture(t, app.Dir)
	if candidate, err := loadApp(app.Dir); err == nil {
		candidate.Shutdown()
		t.Fatal("bad candidate load accepted")
	}
	if GetAppEnv(app.Dir, "MCP_FIXTURE") != "old" {
		t.Fatal("failed candidate published new environment")
	}
}

func TestAppMCPMigrationProjectionRejectsUnresolvedDDL(t *testing.T) {
	for _, source := range []string{
		"CREATE TABLE read_notes AS SELECT 1 AS id;",
		"CREATE TABLE main.read_notes (id INTEGER);",
		"CREATE TABLE helper (id INTEGER); ALTER TABLE helper RENAME TO read_notes;",
		"CREATE TRIGGER sample AFTER INSERT ON notes BEGIN SELECT 1; END; ALTER TABLE notes RENAME TO read_notes;",
	} {
		t.Run(source, func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			mustExec(t, app.DB, "CREATE TABLE notes (id INTEGER)")
			writeTestFile(t, app.Dir, "migrations/pending.sql", source)
			if _, err := appMCPPendingMigrationTables(app.Dir, app.DB, nil); err == nil {
				t.Fatal("unprojectable DDL accepted")
			}
		})
	}
	app, cleanup := newTestApp(t)
	defer cleanup()
	writeTestFile(t, app.Dir, "migrations/pending.sql", "CREATE TRIGGER sample AFTER INSERT ON notes BEGIN SELECT 'ALTER TABLE notes'; SELECT 2; END; CREATE TABLE other (id INTEGER);")
	definitions, err := appMCPPendingMigrationTables(app.Dir, app.DB, nil)
	if err != nil || len(definitions) != 1 || definitions[0].name != "other" {
		t.Fatalf("trigger body corrupted projection: %v %v", definitions, err)
	}
}

func TestAppMCPPrismaDropRejectedBeforeMigration(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	previous := "model Removed {\n id Int @id\n}\n"
	mustExec(t, app.DB, "CREATE TABLE _benmore_migrations (id INTEGER PRIMARY KEY, source TEXT)")
	if _, err := app.DB.Exec("INSERT INTO _benmore_migrations (source) VALUES (?)", previous); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "schema.prisma", "model Notes {\n id Int @id\n}\n")
	if _, err := appMCPCandidateTables(app.Dir, app.DB); err == nil {
		t.Fatal("auto-generated Prisma table drop accepted")
	}
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_migrations").Scan(&count); err != nil || count != 1 {
		t.Fatalf("preflight changed migration ledger: %d %v", count, err)
	}
}

func TestAppMCPSchemaProjectionRejectsRouteChangingDDL(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE helper (id INTEGER); ALTER TABLE helper RENAME TO read_notes;")
	if _, err := appMCPCandidateTables(app.Dir, app.DB); err == nil {
		t.Fatal("schema source route-changing DDL accepted")
	}
}
