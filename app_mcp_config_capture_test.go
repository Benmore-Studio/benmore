//go:build !cli

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestAppMCPCapturedFeatureConfigUsesCanonicalConsumers(t *testing.T) {
	app, _ := auditApp(t)
	sources := map[string]string{
		"schema.sql":      `CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT, created_at TEXT);`,
		"app.yaml":        "ws_rooms:\n  'room-:id': room_members(room_id, member_id)\nversioned:\n  - notes\naggregates:\n  approved:\n    sql: SELECT 'approved-value'\n    refresh: 1h\nretention:\n  notes: 90d\n",
		"validators.yaml": "notes:\n  - rule: body != 'blocked'\n    error: approved-validation\n",
		"admin.yaml":      "tables:\n  notes:\n    readonly: [title]\n",
		"computed.yaml":   "notes:\n  title:\n    expr: \"'approved-computed'\"\n",
		"retention.yaml":  "policies:\n  - table: notes\n    ttl: 1h\n    column: created_at\n",
	}
	for name, source := range sources {
		writeTestFile(t, app.Dir, name, source)
	}
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "app.yaml", "ws_rooms: {}\nversioned:\n  - orgdocs\naggregates:\n  replacement:\n    sql: SELECT 'unreviewed-value'\n    refresh: 1h\nretention:\n  orgdocs: 1h\n")
	for _, name := range []string{"validators.yaml", "admin.yaml", "computed.yaml", "retention.yaml"} {
		if err := os.Remove(filepath.Join(app.Dir, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	if len(app.WSRooms) != 1 || app.WSRooms[0].Pattern != "room-:id" || app.Admin == nil || !app.Admin.IsReadonly("notes", "title") || app.Computed == nil || app.Computed.Fields["notes"]["title"].Expr != "'approved-computed'" {
		t.Fatal("published feature config differs from capture")
	}
	sid := createCrudScopeSession(t, app, "config-admin@example.com", "admin", "", "")
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	recorder := auditPost(mux, sid, "/api/notes", "", `{"body":"blocked"}`, false)
	if recorder.Code == http.StatusOK || !strings.Contains(recorder.Body.String(), "approved-validation") {
		t.Fatalf("canonical validator reread: %d %s", recorder.Code, recorder.Body.String())
	}
	EnsureAggregatesTable(app.DB)
	RegisterAggregateRoutes(mux, app)
	recorder = auditPost(mux, sid, "/api/_aggregates/refresh", "", `{}`, false)
	if recorder.Code != http.StatusOK {
		t.Fatalf("canonical aggregate refresh: %d %s", recorder.Code, recorder.Body.String())
	}
	var value string
	if err := app.DB.QueryRow("SELECT value FROM _benmore_aggregates WHERE name='approved'").Scan(&value); err != nil || value != "approved-value" {
		t.Fatalf("aggregate generation: %q %v", value, err)
	}
	versioned := app.versionedConfig()
	if versioned == nil || len(versioned.Tables) != 1 || versioned.Tables[0] != "notes" {
		t.Fatalf("version generation: %+v", versioned)
	}
	policies := app.retentionConfig()
	if len(policies) != 1 || policies[0].Table != "notes" || policies[0].TTL != time.Hour {
		t.Fatalf("retention precedence/generation: %+v", policies)
	}
	mustExec(t, app.DB, "INSERT INTO notes(title,created_at) VALUES ('old','2000-01-01T00:00:00Z'),('new','2999-01-01T00:00:00Z')")
	RunRetentionNow(app)
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&count); err != nil || count != 1 {
		t.Fatalf("retention flush did not use capture: %d %v", count, err)
	}
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM orgdocs").Scan(&count); err != nil || count != 2 {
		t.Fatalf("replacement retention selected: %d %v", count, err)
	}
	// An empty capture never admits late feature files. Ordinary loaders still do.
	app.sourceFiles = map[string][]byte{}
	writeTestFile(t, app.Dir, "retention.yaml", "policies: [{table: notes, ttl: 1h}]")
	if app.versionedConfig() != nil || len(app.aggregateConfig()) != 0 || len(app.retentionConfig()) != 0 {
		t.Fatal("empty capture admitted late files")
	}
	if LoadVersionedConfig(app.Dir) == nil || len(LoadAggregateConfig(app.Dir)) != 1 || len(LoadRetentionConfig(app.Dir)) != 2 {
		t.Fatal("ordinary feature loaders changed")
	}
}

func TestAppMCPFeatureSourceKindsRejectBeforeDatabase(t *testing.T) {
	for _, name := range []string{"validators.yaml", "admin.yaml", "computed.yaml", "retention.yaml"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
			writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
			reviewAppMCPFixture(t, dir)
			if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
				t.Fatal(err)
			}
			if _, err := loadApp(dir); err == nil {
				t.Fatal("directory accepted as feature configuration")
			}
			if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
				t.Fatalf("database effect before rejection: %v", err)
			}
		})
	}
}

func TestAppMCPCapturedComputedTriggerReplacementIsAtomic(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT);")
	writeTestFile(t, app.Dir, "computed.yaml", "notes:\n  title:\n    expr: \"'approved-computed'\"\n")
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, "CREATE TRIGGER xbenmoreXcfXkeep AFTER INSERT ON notes BEGIN SELECT 1; END")
	writeTestFile(t, app.Dir, "computed.yaml", "notes:\n  title:\n    expr: \"'replacement'\"\n")
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	assertTitle := func(want string) {
		t.Helper()
		mustExec(t, app.DB, "INSERT INTO notes(title) VALUES ('plain')")
		var title string
		if err := app.DB.QueryRow("SELECT title FROM notes ORDER BY id DESC LIMIT 1").Scan(&title); err != nil || title != want {
			t.Fatalf("computed generation: %q want %q: %v", title, want, err)
		}
	}
	assertTitle("approved-computed")
	before := app.MCP
	for _, expression := range []string{"missing(", "nonexistent_column", "nonexistent_function(title)"} {
		writeTestFile(t, app.Dir, "computed.yaml", "notes:\n  title:\n    expr: '"+expression+"'\n")
		reviewAppMCPFixture(t, app.Dir)
		rejected, err := loadRuntimeConfig(app.Dir)
		if err != nil {
			t.Fatal(err)
		}
		if err := reloadAppConfigStaged(app, rejected, nil); err == nil {
			t.Fatalf("bad trigger replacement %s published", expression)
		}
		if app.MCP != before || app.Computed.Fields["notes"]["title"].Expr != "'approved-computed'" {
			t.Fatal("rejected reload replaced published source generation")
		}
		assertTitle("approved-computed")
	}
	writeTestFile(t, app.Dir, "computed.yaml", "fields: []\n")
	reviewAppMCPFixture(t, app.Dir)
	removed, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfigStaged(app, removed, nil); err != nil {
		t.Fatal(err)
	}
	assertTitle("plain")
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name='xbenmoreXcfXkeep'").Scan(&count); err != nil || count != 1 {
		t.Fatalf("unrelated trigger removed: %d %v", count, err)
	}
}

func TestAppMCPMalformedFeatureConfigDoesNotFallBack(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"computed.yaml", "fields:\n - {table: notes, column: title, expr: title}\n - {column: forgotten, expr: title}\n"},
		{"computed.yaml", "fields:\n - {table: notes, column: title, expr: title}\n - {table: notes, expr: title}\n"},
		{"retention.yaml", "policies: invalid\n"},
		{"retention.yaml", "policies: [{table: notes, ttl: invalid}]\n"},
	} {
		t.Run(tc.name+tc.source, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
			writeTestFile(t, dir, "app.yaml", "retention: {notes: 1h}\n")
			writeTestFile(t, dir, tc.name, tc.source)
			writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
			reviewAppMCPFixture(t, dir)
			if _, err := loadApp(dir); err == nil {
				t.Fatal("malformed feature selected partial/fallback generation")
			}
			if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
				t.Fatalf("malformed config opened DB: %v", err)
			}
		})
	}
}

func TestAppMCPFeatureSnapshotsDuringPublication(t *testing.T) {
	room := parseWSRooms([]byte("ws_rooms: {'room-:id': 'room_members(room_id, member_id)'}"))
	validators := parseValidatorsYAML([]byte("notes: [{rule: \"title != 'blocked'\", error: blocked}]"))
	admin := parseAdminConfig([]byte("tables: {notes: {hidden: true}}"))
	computed := parseComputedFieldsYAML([]byte("notes: {title: {expr: title}}"))
	app := &App{WSRooms: room, Validators: validators, Admin: admin, Computed: computed}
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			app.mu.Lock()
			app.WSRooms, app.Validators, app.Admin, app.Computed = room, validators, admin, computed
			app.mu.Unlock()
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 1000; i++ {
			if roomMembershipAllowed(app, nil, 0, "room-1") {
				t.Error("anonymous room admission")
			}
			if ValidateCrossField(app.validatorConfig(), "notes", map[string]any{"title": "blocked"}) == nil {
				t.Error("validator admission")
			}
			if !app.adminConfig().IsTableHidden("notes") || app.computedConfig().Fields["notes"]["title"].Expr != "title" {
				t.Error("feature snapshot changed")
			}
			appKeysGrantsByEmail(app)
		}
	}()
	wg.Wait()
}

func TestAppMCPCapturedNestedComputedTableNamedFields(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT); CREATE TABLE fields (id INTEGER PRIMARY KEY, quantity REAL, price REAL, total REAL);")
	writeTestFile(t, app.Dir, "computed.yaml", "fields:\n  total:\n    expr: quantity * price\n")
	if ordinary := LoadComputedFieldsYAML(app.Dir); ordinary == nil || ordinary.Fields["fields"]["total"].Expr != "quantity * price" {
		t.Fatal("legacy nested fields table unsupported")
	}
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, "INSERT INTO fields(quantity,price) VALUES (3,7)")
	var total float64
	if err := app.DB.QueryRow("SELECT total FROM fields").Scan(&total); err != nil || total != 21 {
		t.Fatalf("nested captured computed: %v %v", total, err)
	}
}
