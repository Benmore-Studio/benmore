//go:build !cli && !windows

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"

	"github.com/mattn/go-sqlite3"
)

func TestAppMCPMetadataReadsLiveSchemaAndDiscardsDirtyConnection(t *testing.T) {
	app, _, uid := appMCPResultFixture(t, false)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, `ALTER TABLE notes ADD COLUMN actual_field VARCHAR(23) NOT NULL DEFAULT 'live'`)

	var configured bool
	for _, table := range app.Tables {
		if table.Name != "notes" {
			continue
		}
		for _, column := range table.Columns {
			configured = configured || column.Name == "actual_field"
		}
	}
	if configured {
		t.Fatal("fixture metadata unexpectedly includes the physical-only column")
	}

	got, err := appMCPReadColumns(context.Background(), app, "notes")
	if err != nil {
		t.Fatal(err)
	}
	want, err := GetTableColumns(app.DB, "notes")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("connector schema differs from the live schema: got=%+v want=%+v", got, want)
	}
	var actual *Column
	for i := range got {
		if got[i].Name == "actual_field" {
			actual = &got[i]
		}
	}
	if actual == nil || actual.Type != "VARCHAR(23)" || !actual.NotNull || actual.Default != "'live'" || actual.PK {
		t.Fatalf("physical column metadata: %+v", actual)
	}
	var primary *Column
	for i := range got {
		if got[i].Name == "id" {
			primary = &got[i]
		}
	}
	if primary == nil || !primary.PK {
		t.Fatalf("primary-key metadata missing: %+v", primary)
	}

	auditExec(t, app.DB, "BEGIN")
	auditExec(t, app.DB, `ALTER TABLE notes ADD COLUMN dirty_ghost TEXT`)
	if columns, err := appMCPReadColumns(context.Background(), app, "notes"); err == nil || columns != nil {
		t.Fatalf("metadata read accepted a dirty pooled transaction: columns=%+v err=%v", columns, err)
	}
	columns, err := GetTableColumns(app.DB, "notes")
	if err != nil {
		t.Fatal(err)
	}
	for _, column := range columns {
		if column.Name == "dirty_ghost" {
			t.Fatal("discarded transaction's schema change became visible")
		}
	}
	if _, err := app.DB.Exec(`UPDATE notes SET title='normal write' WHERE user_id=?`, uid); err != nil {
		t.Fatalf("fresh pooled connection rejected a normal write: %v", err)
	}
}

func TestAppMCPMetadataPrivateColumnsAreCopiedAndBound(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	original, err := appMCPReadColumns(context.Background(), app, "notes")
	if err != nil {
		t.Fatal(err)
	}
	snapshot := append([]Column(nil), original...)
	source := httptest.NewRequest(http.MethodGet, "/api/notes", nil)
	request, policy, err := newAppMCPNativeRequestWithColumns(app, source, pair.AccessToken, grantFixtureResource, "list_notes", original)
	if err != nil {
		t.Fatal(err)
	}
	original[0].Name = "preflight_mutation"
	auditExec(t, app.DB, "ALTER TABLE notes ADD COLUMN later_field TEXT DEFAULT 'later'")

	bound, err := crudTableColumns(request, policy, "notes")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(bound, snapshot) {
		t.Fatalf("private request did not retain an immutable schema snapshot: got=%+v want=%+v", bound, snapshot)
	}
	live, err := crudTableColumns(httptest.NewRequest(http.MethodGet, "/api/notes", nil), app, "notes")
	if err != nil {
		t.Fatal(err)
	}
	foundLater := false
	for _, column := range live {
		foundLater = foundLater || column.Name == "later_field"
	}
	if !foundLater {
		t.Fatal("ordinary CRUD metadata did not see the later physical column")
	}
	refetched, refetchedPolicy, err := newAppMCPNativeRequest(app, source, pair.AccessToken, grantFixtureResource, "list_notes")
	if err != nil {
		t.Fatal(err)
	}
	refetchedColumns, err := crudTableColumns(refetched, refetchedPolicy, "notes")
	if err != nil {
		t.Fatal(err)
	}
	foundLater = false
	for _, column := range refetchedColumns {
		foundLater = foundLater || column.Name == "later_field"
	}
	if !foundLater {
		t.Fatal("native request wrapper did not fetch live physical columns")
	}

	var nilIdentity *appMCPPrivateRead
	for name, value := range map[string]*appMCPPrivateRead{
		"nil identity":       nilIdentity,
		"cross-app identity": {app: &App{}, table: "notes", columns: bound},
		"wrong table":        {app: policy, table: "other", columns: bound},
	} {
		t.Run(name, func(t *testing.T) {
			forged := source.WithContext(context.WithValue(source.Context(), appMCPPrivateKey{}, value))
			if columns, err := crudTableColumns(forged, policy, "notes"); !errors.Is(err, errAppMCPGrantDenied) || columns != nil {
				t.Fatalf("forged private metadata was accepted: columns=%+v err=%v", columns, err)
			}
		})
	}
	if columns, err := crudTableColumns(request, policy, "other"); !errors.Is(err, errAppMCPGrantDenied) || columns != nil {
		t.Fatalf("cross-table lookup was accepted: columns=%+v err=%v", columns, err)
	}
}

func TestAppMCPMetadataAuthorizerAndCancellation(t *testing.T) {
	app, _, _ := appMCPResultFixture(t, false)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	if columns, err := appMCPReadColumns(context.Background(), app, "notes"); err != nil || len(columns) == 0 {
		t.Fatalf("metadata authorizer denied actual table_info: columns=%+v err=%v", columns, err)
	}
	var queryOnly bool
	if err := app.DB.QueryRow("PRAGMA query_only").Scan(&queryOnly); err != nil || queryOnly {
		t.Fatalf("metadata helper did not restore query_only: query_only=%v err=%v", queryOnly, err)
	}

	conn, _, closeConn, err := openReadOnlyQueryConn(context.Background(), app.DB)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Raw(func(raw any) error {
		raw.(*sqlite3.SQLiteConn).RegisterAuthorizer(authorizeAppMCPMetadata)
		return nil
	}); err != nil {
		closeConn()
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), "PRAGMA query_only=OFF"); err == nil {
		closeConn()
		t.Fatal("metadata authorizer allowed query_only to be disabled")
	}
	closeConn()

	for _, query := range []string{
		"PRAGMA table_info(notes)",
		"SELECT * FROM pragma_table_info('notes')",
	} {
		rows, truncated, err := queryReadOnlyRows(context.Background(), app.DB, query, 10)
		if err == nil || rows != nil || truncated {
			t.Errorf("user query retained metadata access for %q: rows=%+v truncated=%v err=%v", query, rows, truncated, err)
		}
	}
	masked, _, err := queryReadOnlyRows(context.Background(), app.DB, "SELECT token_hash FROM _benmore_mcp_credentials", 10)
	if err != nil || len(masked) == 0 {
		t.Fatalf("credential read did not retain its masked result: rows=%+v err=%v", masked, err)
	}
	for _, row := range masked {
		if row["token_hash"] != nil {
			t.Fatalf("credential column was not SQLITE_IGNORE-masked: %#v", row)
		}
	}
	if err := app.DB.QueryRow("PRAGMA query_only").Scan(&queryOnly); err != nil || queryOnly {
		t.Fatalf("read-only helper did not restore query_only: query_only=%v err=%v", queryOnly, err)
	}

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	columns, err := appMCPReadColumns(canceled, app, "notes")
	if !errors.Is(err, context.Canceled) || columns != nil {
		t.Fatalf("canceled metadata read returned columns or wrong error: columns=%+v err=%v", columns, err)
	}
}

func TestAppMCPMetadataNativeUsesPhysicalColumnsForFilterAndProjection(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	auditExec(t, app.DB, "ALTER TABLE notes ADD COLUMN physical_only TEXT")
	auditExec(t, app.DB, "UPDATE notes SET physical_only=CASE WHEN id=1 THEN 'wanted' ELSE 'other' END")
	for _, table := range app.Tables {
		for _, column := range table.Columns {
			if table.Name == "notes" && column.Name == "physical_only" {
				t.Fatal("fixture column was declared in runtime app.Tables")
			}
		}
	}
	// The reviewed contract permits this field; the runtime table configuration
	// intentionally predates its physical addition, as on a staged migration.
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, physical_only TEXT);\n")
	tool := &app.MCP.Tools[0]
	tool.InputSchema.Properties["filters"].Properties["physical_only"] = &AppMCPSchema{Type: "string"}
	tool.Output.Include = []string{"physical_only"}
	tool.OutputSchema.Required = []string{"physical_only"}
	tool.OutputSchema.Properties = map[string]*AppMCPSchema{"physical_only": {Type: "string"}}
	publishNativeResultFixture(t, app)
	result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"filters": map[string]any{"physical_only": "wanted"}})
	if err != nil || result == nil {
		t.Fatalf("physical native filter/projection failed: %+v %v", result, err)
	}
	rows := result.Data.([]map[string]any)
	if result.Pagination.Total != 1 || len(rows) != 1 || len(rows[0]) != 1 || rows[0]["physical_only"] != "wanted" {
		t.Fatalf("physical filter was dropped or projection widened: %+v", result)
	}
}
