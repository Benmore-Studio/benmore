//go:build !cli && !windows

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

func TestAppMCPNativeCRUDProtectsRowsAndPageTotal(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "CREATE TABLE side_effects (id INTEGER PRIMARY KEY)")
	auditExec(t, app.DB, "ALTER TABLE notes RENAME TO notes_storage")
	var protected, writes int
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	err = conn.Raw(func(raw any) error {
		sqlite := raw.(*sqlite3.SQLiteConn)
		return sqlite.RegisterFunc("audit_private_read", func() int64 {
			// A schema expression must not gain write authority from either query.
			if _, err := sqlite.Exec("INSERT INTO side_effects DEFAULT VALUES", nil); err != nil {
				protected++
			} else {
				writes++
			}
			return 1
		}, false)
	})
	_ = conn.Close()
	if err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "CREATE VIEW notes AS SELECT * FROM notes_storage WHERE audit_private_read()=1")
	result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{"per_page": 1})
	if err != nil || result.Pagination.Total != 2 || len(result.Data.([]map[string]any)) != 1 {
		t.Fatalf("native page/total: %+v %v", result, err)
	}
	if protected < 3 || writes != 0 {
		t.Fatalf("rows or total lacked the shared guard: protected=%d writes=%d", protected, writes)
	}
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM side_effects").Scan(&count); err != nil || count != 0 {
		t.Fatalf("private read changed storage: %d %v", count, err)
	}
	if _, err := QueryRows(app.DB, "SELECT id FROM notes LIMIT 1"); err != nil || writes != 1 {
		t.Fatalf("ordinary query did not retain write-capable connection: writes=%d err=%v", writes, err)
	}
}

func TestAppMCPNativeCRUDDiscardsDirtyPooledRead(t *testing.T) {
	app, pair, uid := appMCPResultFixture(t, false)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "BEGIN")
	auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (4,?,'uncommitted')", uid)
	result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", map[string]any{})
	if result != nil || nativeResultErrorCode(t, err) != "denied" {
		t.Fatalf("dirty connection released a native result: %+v %v", result, err)
	}
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM notes WHERE id=4").Scan(&count); err != nil || count != 0 {
		t.Fatalf("dirty transaction was not discarded: %d %v", count, err)
	}
	auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (4,?,'normal write')", uid)
}

func TestAppMCPPrivateCRUDRefusesUnsupportedIncludes(t *testing.T) {
	app, pair, _ := appMCPResultFixture(t, false)
	source := httptest.NewRequest(http.MethodGet, "/api/notes?include=orgdocs", nil)
	if _, _, err := newAppMCPNativeRequest(app, source, pair.AccessToken, grantFixtureResource, "list_notes"); err == nil {
		t.Fatal("unsupported include entered an unguarded related query")
	}
}

func TestAppMCPPrivateCRUDHistoricalFallbackAndDirtyPool(t *testing.T) {
	app, pair, uid := appMCPResultFixture(t, true)
	app.DB.SetMaxOpenConns(1)
	app.DB.SetMaxIdleConns(1)
	auditExec(t, app.DB, "ALTER TABLE notes ADD COLUMN created_at TEXT DEFAULT '2000-01-01'")
	app.MCP.Tools[0].InputSchema.Properties["as_of"] = &AppMCPSchema{Type: "string"}
	exposeNativeTitle(t, app)
	input := map[string]any{"id": 1, "as_of": "2020-01-01T00:00:00Z"}
	result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", input)
	if err != nil || result == nil || result.Data.(map[string]any)["title"] != "unapproved-document-text" {
		t.Fatalf("native missing-history fallback changed: %+v %v", result, err)
	}
	auditExec(t, app.DB, "ALTER TABLE notes ADD COLUMN updated_at TEXT DEFAULT '2026-01-01'")
	InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"notes"}})
	auditExec(t, app.DB, "UPDATE notes SET title='new' WHERE id=1")
	auditExec(t, app.DB, "UPDATE notes_history SET _valid_from='2000-01-01',_valid_to='2030-01-01' WHERE id=1")
	result, err = runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", input)
	if err != nil || result == nil || result.Data.(map[string]any)["title"] != "unapproved-document-text" {
		t.Fatalf("native history read failed: %+v %v", result, err)
	}
	source := httptest.NewRequest(http.MethodGet, "/api/notes/1?as_of=2020-01-01T00%3A00%3A00Z", nil)
	request, policy, err := newAppMCPNativeRequest(app, source, pair.AccessToken, grantFixtureResource, "list_notes")
	if err != nil {
		t.Fatal(err)
	}
	actor := getSession(policy, request)
	if actor == nil || actor.UserID != uid {
		t.Fatal("missing pinned actor")
	}
	auditExec(t, app.DB, "BEGIN")
	auditExec(t, app.DB, "UPDATE notes_history SET title='uncommitted-history' WHERE id=1")
	row, err := handlePointInTime(policy, request, "notes", "1", "2020-01-01T00:00:00Z", actor)
	if err == nil || row != nil {
		t.Fatalf("dirty history read fell back or returned data: %v %v", row, err)
	}
	// Cleanup must restore a new normal connection after rejecting the lease.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := app.DB.ExecContext(ctx, "UPDATE notes SET title='normal write' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	auditExec(t, app.DB, "ALTER TABLE notes_history RENAME TO history_case_temp")
	auditExec(t, app.DB, "ALTER TABLE history_case_temp RENAME TO Notes_History")
	result, err = runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", input)
	if err != nil || result == nil || result.Data.(map[string]any)["title"] != "unapproved-document-text" {
		t.Fatalf("case-insensitive history was substituted: %+v %v", result, err)
	}
	auditExec(t, app.DB, "ALTER TABLE Notes_History RENAME TO history_storage")
	auditExec(t, app.DB, "CREATE VIEW notes_history AS SELECT * FROM history_storage")
	result, err = runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", input)
	if err != nil || result == nil || result.Data.(map[string]any)["title"] != "unapproved-document-text" {
		t.Fatalf("existing history view was substituted: %+v %v", result, err)
	}
	auditExec(t, app.DB, "ALTER TABLE history_storage RENAME COLUMN _valid_from TO broken_from")
	result, err = runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "list_notes", input)
	if result != nil || err == nil {
		t.Fatalf("malformed existing history became a current success: %+v %v", result, err)
	}
}

func TestAppMCPHistoricalFallbackRechecksRowScope(t *testing.T) {
	for _, private := range []bool{false, true} {
		for _, change := range []string{"owner", "deleted"} {
			t.Run(fmt.Sprintf("private=%t/%s", private, change), func(t *testing.T) {
				app, pair, uid := appMCPResultFixture(t, true)
				auditExec(t, app.DB, "ALTER TABLE notes ADD COLUMN created_at TEXT DEFAULT '2000-01-01'")
				if change == "deleted" {
					auditExec(t, app.DB, "ALTER TABLE notes ADD COLUMN deleted_at TEXT")
					for i := range app.Tables {
						if app.Tables[i].Name == "notes" {
							app.Tables[i].Columns = append(app.Tables[i].Columns, Column{Name: "deleted_at"})
						}
					}
				}
				source := httptest.NewRequest(http.MethodGet, "/api/notes/1?as_of=2020-01-01T00%3A00%3A00Z", nil)
				request, policy, err := newAppMCPNativeRequest(app, source, pair.AccessToken, grantFixtureResource, "list_notes")
				if err != nil {
					t.Fatal(err)
				}
				actor := getSession(policy, request)
				if actor == nil || actor.UserID != uid || !canAccessRow(policy, "notes", "1", actor) {
					t.Fatal("initial native access was not authorized")
				}
				if !private {
					request = source
				}
				if change == "owner" {
					auditExec(t, app.DB, "UPDATE notes SET user_id=999,title='foreign-owner-content' WHERE id=1")
				} else {
					auditExec(t, app.DB, "UPDATE notes SET deleted_at='2026-10-02' WHERE id=1")
				}
				row, err := handlePointInTime(policy, request, "notes", "1", "2020-01-01T00:00:00Z", actor)
				if err == nil || row != nil {
					t.Fatalf("fallback released a newly inaccessible row: %v %v", row, err)
				}
			})
		}
	}
}
