//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
	"gopkg.in/yaml.v3"
)

func appMCPResultFixture(t *testing.T, read bool) (*App, *appMCPTokenPair, int64) {
	t.Helper()
	app, uid, _ := appMCPGrantFixture(t)
	source := appMCPManifestFixture()
	input := `input_schema:
      type: object
      additionalProperties: false
      properties:
        page: {type: integer, minimum: 1}
        per_page: {type: integer, minimum: 1, maximum: 500}
        sort: {type: string}
        order: {type: string}
        q: {type: string}
        group_id: {type: string}
        filters:
          type: object
          additionalProperties: false
          properties:
            id: {type: integer}
            title: {type: string}
            title__in: {type: array, items: {type: string}, minItems: 1}
            missing: {type: string}
            title__unknown: {type: string}`
	if read {
		source = strings.Replace(source, "table.list", "table.read", 1)
		input = `input_schema: {type: object, additionalProperties: false, required: [id], properties: {id: {type: integer}}}`
	}
	source = strings.Replace(source, "input_schema: {type: object, additionalProperties: false}", input, 1)
	source = strings.Replace(source, "output_schema:\n      type: object", "output_schema:\n      type: object\n      required: [id]", 1)
	writeTestFile(t, app.Dir, "mcp.yaml", source)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP = config.mcp
	pair := fixtureGrant(t, app, uid, time.Now())
	auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (1,?,'unapproved-document-text'),(2,?,'another-unapproved-text'),(3,999,'foreign-secret')", uid, uid)
	return app, pair, uid
}
func nativeResultErrorCode(t *testing.T, err error) string {
	t.Helper()
	value, ok := err.(*appMCPResultError)
	if !ok {
		t.Fatalf("expected stable connector error, got %v", err)
	}
	return value.Code
}

func appMCPNativeCountFixture(t *testing.T, app *App, onCount func() error) *[]string {
	t.Helper()
	if err := app.DB.Close(); err != nil {
		t.Fatal(err)
	}
	// One backing row plus per_page=1 makes the first callback the completed
	// page read; the separately issued outer COUNT(*) produces the second.
	events := []string{}
	driverName := "mcp-native-count-" + generateToken(8)
	sql.Register(driverName, &sqlite3.SQLiteDriver{ConnectHook: func(conn *sqlite3.SQLiteConn) error {
		return conn.RegisterFunc("audit_mcp_count", func() (int64, error) {
			switch len(events) {
			case 0:
				events = append(events, "first-page-row")
			case 1:
				events = append(events, "outer-count")
				if onCount != nil {
					return 0, onCount()
				}
			default:
				events = append(events, "unexpected-extra-evaluation")
			}
			return 1, nil
		}, false)
	}})
	db, err := sql.Open(driverName, filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		"ALTER TABLE notes RENAME TO notes_storage",
		"DELETE FROM notes_storage WHERE id != 1",
		"CREATE VIEW notes AS SELECT * FROM notes_storage WHERE audit_mcp_count() = 1",
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

func assertAppMCPCountReached(t *testing.T, recorded *[]string) {
	t.Helper()
	events := *recorded
	if len(events) != 2 || events[0] != "first-page-row" || events[1] != "outer-count" {
		t.Fatalf("outer count callback not reached after page row: %v", events)
	}
}
func TestAppMCPNativeResultProjectsAndReportsPagination(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	first, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"per_page": 1})
	if err != nil {
		t.Fatal(err)
	}
	if first.Pagination.Total != 2 || first.Pagination.Page != 1 || first.Pagination.PerPage != 1 || !first.Pagination.HasNext || first.Completeness.State != "partial" || first.Completeness.SnapshotConsistent {
		t.Fatalf("dishonest page: %+v", first)
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "unapproved") || strings.Contains(string(encoded), "foreign-secret") || strings.Contains(string(encoded), pair.AccessToken) || strings.Contains(string(encoded), "user_id") {
		t.Fatalf("unapproved result: %s", encoded)
	}
	if first.ObservedAt == "" || first.SourceRevisions["execution"] != app.MCP.ExecutionDigest || len(first.Warnings) < 2 {
		t.Fatal("missing observations/limitations")
	}
	second, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"page": 2, "per_page": 1})
	if err != nil || second.Pagination.HasNext || second.Completeness.State != "partial" {
		t.Fatalf("last page incorrectly complete: %+v %v", second, err)
	}
	all, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{})
	if err != nil || all.Completeness.State != "complete" || len(all.Data.([]map[string]any)) != 2 {
		t.Fatalf("whole observed page: %+v %v", all, err)
	}
	empty, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"filters": map[string]any{"id": 99999}})
	if err != nil || empty.Pagination.Total != 0 || len(empty.Data.([]map[string]any)) != 0 {
		t.Fatalf("empty page: %+v %v", empty, err)
	}
}
func TestAppMCPNativeResultRejectsIgnoredAndUnboundInputs(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	for _, input := range []map[string]any{
		{"group_id": "29"}, {"per_page": 501}, {"page": 0}, {"sort": "missing"}, {"order": "desc"}, {"q": "ignored search"},
		{"filters": map[string]any{"missing": "ignored"}}, {"filters": map[string]any{"title__unknown": "ignored"}},
		{"filters": map[string]any{"title__in": []any{"ambiguous,comma"}}}, {"filters": map[string]any{"title": nil}},
		{"filters": map[string]any{"title": string([]byte{0xff})}},
	} {
		if result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", input); result != nil || nativeResultErrorCode(t, err) != "invalid_input" {
			t.Fatalf("ignored input accepted: %v %+v %v", input, result, err)
		}
	}
	selected, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"filters": map[string]any{"title__in": []any{"unapproved-document-text"}}})
	if err != nil || selected.Pagination.Total != 1 {
		t.Fatalf("canonical IN filter: %+v %v", selected, err)
	}
	if result, err := runAppMCPNativeRead(context.Background(), app, pair.RefreshToken, grantFixtureResource, "list_notes", map[string]any{}); result != nil || nativeResultErrorCode(t, err) != "denied" {
		t.Fatal("refresh accepted as read credential")
	}
}
func TestAppMCPNativeReadResultProjectsSingleRowAndDeniesForeign(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, true)
	result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"id": 1})
	if err != nil || len(result.Data.(map[string]any)) != 1 || result.Pagination != nil {
		t.Fatalf("single row projection: %+v %v", result, err)
	}
	if result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"id": 3}); result != nil || nativeResultErrorCode(t, err) != "denied" {
		t.Fatal("foreign row returned")
	}
}
func TestAppMCPNativeResultCountFailureHasNoSuccessPayload(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	events := appMCPNativeCountFixture(t, app, func() error { return errors.New("injected count failure") })
	result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"per_page": 1})
	assertAppMCPCountReached(t, events)
	if result != nil || nativeResultErrorCode(t, err) != "incomplete_result" || strings.Contains(err.Error(), "injected") {
		t.Fatalf("failed total became success/raw error: %+v %v", result, err)
	}
}
func TestAppMCPNativeResultCaptureIsBounded(t *testing.T) {
	capture := &appMCPReadCapture{header: make(http.Header)}
	if _, err := capture.Write(make([]byte, appMCPResultLimit+1)); err == nil || !capture.overflow || capture.Len() != 0 {
		t.Fatal("oversized canonical response retained")
	}
}

func publishNativeResultFixture(t *testing.T, app *App) {
	t.Helper()
	value, err := yaml.Marshal(app.MCP)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "mcp.yaml", string(value))
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP = config.mcp
}
func exposeNativeTitle(t *testing.T, app *App) {
	t.Helper()
	tool := &app.MCP.Tools[0]
	tool.Output.Include = []string{"title"}
	tool.OutputSchema.Required = []string{"title"}
	tool.OutputSchema.Properties = map[string]*AppMCPSchema{"title": {Type: "string"}}
	publishNativeResultFixture(t, app)
}
func TestAppMCPNativeResultPreservesOwnerMaskingContext(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	exposeNativeTitle(t, app)
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"notes": {{Column: "title", Roles: []string{"self"}}}}}
	result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{})
	if err != nil {
		t.Fatal(err)
	}
	rows := result.Data.([]map[string]any)
	if len(rows) != 2 || rows[0]["title"] != "another-unapproved-text" || len(rows[0]) != 1 {
		t.Fatalf("owner context lost or disclosed: %+v", rows)
	}
}
func TestAppMCPNativeResultDeniesDemotionDuringEncoding(t *testing.T) {
	app, pair, uid := appMCPResultFixture(t, false)
	exposeNativeTitle(t, app)
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"admin": {Scopes: "notes:read"}, "editor": {Scopes: "notes:read"}}}
	app.Access.rules["notes"]["all"] = "admin"
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"notes": {{Column: "title", Roles: []string{"admin"}}}}}
	auditExec(t, app.DB, "UPDATE _benmore_users SET role='admin' WHERE id=?", uid)
	dbPath := filepath.Join(app.Dir, "data.db")
	events := appMCPNativeCountFixture(t, app, func() error {
		name := "mcp-demote-writer-" + generateToken(8)
		sql.Register(name, &sqlite3.SQLiteDriver{})
		writer, err := sql.Open(name, dbPath+"?_journal_mode=WAL")
		if err != nil {
			return err
		}
		defer writer.Close()
		_, err = writer.Exec("UPDATE _benmore_users SET role='editor' WHERE id=?", uid)
		return err
	})
	result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"per_page": 1})
	assertAppMCPCountReached(t, events)
	if result != nil || nativeResultErrorCode(t, err) != "denied" {
		t.Fatalf("lost admin/unmask authority released data: %+v %v", result, err)
	}
}
func TestAppMCPNativeBooleanFiltersUseCanonicalStorage(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	auditExec(t, app.DB, "ALTER TABLE notes ADD COLUMN completed INTEGER")
	auditExec(t, app.DB, "UPDATE notes SET completed=CASE WHEN id=1 THEN 1 ELSE 0 END")
	filters := app.MCP.Tools[0].InputSchema.Properties["filters"].Properties
	filters["completed"] = &AppMCPSchema{Type: "boolean"}
	filters["completed__ne"] = &AppMCPSchema{Type: "boolean"}
	filters["completed__in"] = &AppMCPSchema{Type: "array", Items: &AppMCPSchema{Type: "boolean"}}
	publishNativeResultFixture(t, app)
	for _, key := range []string{"completed", "completed__ne", "completed__in"} {
		var filter any = true
		if key == "completed__in" {
			filter = []any{true}
		}
		result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"filters": map[string]any{key: filter}})
		if err != nil || result.Pagination.Total != 1 {
			t.Fatalf("boolean %s: %+v %v", key, result, err)
		}
		id := result.Data.([]map[string]any)[0]["id"].(json.Number).String()
		want := "1"
		if key == "completed__ne" {
			want = "2"
		}
		if id != want {
			t.Fatalf("boolean %s selected %s want %s", key, id, want)
		}
	}
}

func TestAppMCPNativeResultRejectsManifestGenerationChange(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	events := appMCPNativeCountFixture(t, app, func() error {
		app.mu.Lock()
		generation := *app.MCP
		app.MCP = &generation
		app.mu.Unlock()
		return nil
	})
	result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"per_page": 1})
	assertAppMCPCountReached(t, events)
	if result != nil || nativeResultErrorCode(t, err) != "denied" {
		t.Fatalf("cross-generation result released: %+v %v", result, err)
	}
}
