//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	sqlite3 "github.com/mattn/go-sqlite3"
)

func TestAppMCPCanonicalHookWhenUsesMainDependencyTrueAndFalse(t *testing.T) {
	hooks := `before_update:
  notes:
    - when: "EXISTS (SELECT 1 FROM lifecycle_markers WHERE value='permit')"
      sql: "SELECT CASE WHEN '{{title}}'='blocked' THEN 'blocked by before hook' END AS error"
on_update:
  notes:
    - when: "EXISTS (SELECT 1 FROM lifecycle_markers WHERE value='permit')"
      sql: "UPDATE notes SET title='after-when' WHERE id={{id}}"
`
	t.Run("true-before-and-after", func(t *testing.T) {
		f := newCanonicalUpdateFixture(t, hooks, "", "")
		canonicalPositiveThenReset(t, f)
		if _, err := f.app.DB.Exec(`INSERT INTO main.lifecycle_markers(id,value) VALUES(1,'permit')`); err != nil {
			t.Fatal(err)
		}
		positive, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("submitted"), f.now)
		if err != nil || positive["title"] != "after-when" {
			t.Fatalf("true when/after-hook positive precondition failed: result=%v err=%v", positive, err)
		}
		resetCanonicalNote(t, f.app)
		before := canonicalEffectsSnapshot(t, f.app)
		if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("blocked"), f.now); err == nil {
			t.Fatal("true before-hook condition did not reject its blocked row")
		}
		if after := canonicalEffectsSnapshot(t, f.app); after != before {
			t.Fatalf("true before-hook denial changed state: before=%s after=%s", before, after)
		}
		projected, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("submitted"), f.now)
		if err != nil || projected["title"] != "after-when" || readCanonicalNote(t, f.app.DB) != "after-when" {
			t.Fatalf("true after-hook condition failed to use main dependency: result=%v err=%v", projected, err)
		}
	})

	t.Run("false-before-and-after", func(t *testing.T) {
		f := newCanonicalUpdateFixture(t, hooks, "", "")
		canonicalPositiveThenReset(t, f)
		before := canonicalEffectsSnapshot(t, f.app)
		projected, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("blocked"), f.now)
		if err != nil || projected["title"] != "blocked" || readCanonicalNote(t, f.app.DB) != "blocked" {
			t.Fatalf("false before/after conditions did not skip their hooks: result=%v err=%v", projected, err)
		}
		if after := canonicalEffectsSnapshot(t, f.app); after == before {
			t.Fatal("false-condition control did not perform the canonical update")
		}
	})
}

func TestAppMCPCanonicalHookScriptsRunCaseCTEAndMultiTableDML(t *testing.T) {
	script := `UPDATE notes SET title=CASE WHEN title='run' THEN 'case-done' ELSE title END WHERE id={{id}};
INSERT INTO lifecycle_markers(id,value) SELECT 1,title FROM notes WHERE id={{id}};
WITH chosen(id) AS (SELECT id FROM notes WHERE id={{id}}) UPDATE notes SET title='cte-done' WHERE id IN (SELECT id FROM chosen);
INSERT INTO lifecycle_markers(id,value) SELECT 2,title FROM notes WHERE id={{id}};
UPDATE notes SET title='multi-done' WHERE id={{id}};
INSERT INTO lifecycle_markers(id,value) SELECT 3,title FROM notes WHERE id={{id}};`
	f := newCanonicalUpdateFixture(t, canonicalAdmissionAfterHook(script, `title='run'`), "", "")
	canonicalPositiveThenReset(t, f)
	projected, refreshed, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("run"), f.now)
	if err != nil || projected["title"] != "multi-done" || readCanonicalNote(t, f.app.DB) != "multi-done" {
		t.Fatalf("authored CASE/CTE/multi-DML hook failed to return final main row: result=%v err=%v", projected, err)
	}
	var stages []string
	rows, err := f.app.DB.Query(`SELECT value FROM main.lifecycle_markers ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var stage string
		if err := rows.Scan(&stage); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		stages = append(stages, stage)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	if want := []string{"case-done", "cte-done", "multi-done"}; !slices.Equal(stages, want) {
		t.Fatalf("script stages=%v, want %v", stages, want)
	}
	if !slices.Equal(refreshed, []string{"lifecycle_markers"}) {
		t.Fatalf("authored DML refresh targets=%v, want one deduplicated lifecycle_markers target", refreshed)
	}
}

func TestAppMCPCanonicalHookRejectsSameConnectionTempAndAttachmentDecoys(t *testing.T) {
	decoys := []struct {
		name, sql, verify string
	}{
		{"business-table", `CREATE TEMP TABLE notes(id INTEGER PRIMARY KEY,user_id INTEGER,title TEXT,updated_at TEXT,normalized TEXT,secret TEXT)`, `SELECT count(*) FROM temp.sqlite_schema WHERE type='table' AND name='notes'`},
		{"membership-view", `CREATE TEMP VIEW members AS SELECT 'decoy' AS org_id,'decoy' AS email`, `SELECT count(*) FROM temp.sqlite_schema WHERE type='view' AND name='members'`},
		{"audit-table", `CREATE TEMP TABLE _benmore_audit_log(id INTEGER PRIMARY KEY)`, `SELECT count(*) FROM temp.sqlite_schema WHERE type='table' AND name='_benmore_audit_log'`},
		{"key-identity-view", `CREATE TEMP VIEW _benmore_users AS SELECT 999 AS id,'decoy' AS email`, `SELECT count(*) FROM temp.sqlite_schema WHERE type='view' AND name='_benmore_users'`},
		{"effect-ledger", `CREATE TEMP TABLE _benmore_mcp_authorizations(id INTEGER PRIMARY KEY)`, `SELECT count(*) FROM temp.sqlite_schema WHERE type='table' AND name='_benmore_mcp_authorizations'`},
		{"trigger", `CREATE TEMP TRIGGER mcp_decoy AFTER UPDATE ON notes BEGIN SELECT 1; END`, `SELECT count(*) FROM temp.sqlite_schema WHERE type='trigger' AND name='mcp_decoy'`},
		{"attached-database", `ATTACH DATABASE ':memory:' AS mcp_decoy`, `SELECT count(*) FROM pragma_database_list WHERE name='mcp_decoy'`},
	}
	for _, tc := range decoys {
		t.Run(tc.name, func(t *testing.T) {
			f := newCanonicalUpdateFixture(t, "", "", "")
			canonicalPositiveThenReset(t, f)
			f.app.DB.SetMaxOpenConns(1)
			var present int
			if tc.name == "attached-database" {
				establishCanonicalAdmissionAttachment(t, f.app, tc.sql, tc.verify)
			} else if _, err := f.app.DB.Exec(tc.sql); err != nil {
				t.Fatalf("establish decoy on coordinator's sole pooled connection: %v", err)
			}
			if err := f.app.DB.QueryRow(tc.verify).Scan(&present); err != nil || present != 1 {
				t.Fatalf("decoy precondition not active on pooled connection: count=%d err=%v", present, err)
			}
			before := canonicalAdmissionState(t, f.app)
			if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("denied"), f.now); !errors.Is(err, errAppMCPGrantDenied) {
				t.Fatalf("private coordinator did not refuse %s decoy: %v", tc.name, err)
			}
			if after := canonicalAdmissionState(t, f.app); after != before {
				t.Fatalf("%s decoy refusal changed main business/effect state: before=%s after=%s", tc.name, before, after)
			}
			if err := f.app.DB.QueryRow(tc.verify).Scan(&present); err != nil || present != 1 {
				t.Fatalf("decoy was removed instead of remaining an active refusal condition: count=%d err=%v", present, err)
			}
		})
	}
}

func establishCanonicalAdmissionAttachment(t *testing.T, app *App, attachSQL, verifySQL string) {
	t.Helper()
	conn, err := app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var originalLimit int
	if err := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("unexpected SQLite connection type")
		}
		originalLimit = sqliteConn.SetLimit(sqlite3.SQLITE_LIMIT_ATTACHED, -1)
		if originalLimit != 0 {
			return errors.New("connector SQLite connection did not start with ATTACH disabled")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	restoreLimit := func() error {
		err := conn.Raw(func(raw any) error {
			sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
			if !ok {
				return errors.New("unexpected SQLite connection type during ATTACH limit restore")
			}
			sqliteConn.SetLimit(sqlite3.SQLITE_LIMIT_ATTACHED, originalLimit)
			return nil
		})
		if err != nil {
			return errors.Join(err, conn.Raw(func(any) error { return driver.ErrBadConn }))
		}
		return nil
	}
	defer func() {
		if err := restoreLimit(); err != nil {
			t.Errorf("restore sole pooled connection's ATTACH limit: %v", err)
		}
	}()
	if _, err := conn.ExecContext(context.Background(), attachSQL); err == nil {
		t.Fatal("ordinary ATTACH unexpectedly succeeded with the driver limit at zero")
	}
	var absent int
	if err := conn.QueryRowContext(context.Background(), verifySQL).Scan(&absent); err != nil || absent != 0 {
		t.Fatalf("blocked ordinary ATTACH left an attachment behind: count=%d err=%v", absent, err)
	}
	if err := conn.Raw(func(raw any) error {
		sqliteConn := raw.(*sqlite3.SQLiteConn)
		if previous := sqliteConn.SetLimit(sqlite3.SQLITE_LIMIT_ATTACHED, 1); previous != originalLimit {
			return fmt.Errorf("ATTACH limit changed unexpectedly before setup: %d", previous)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	_, attachErr := conn.ExecContext(context.Background(), attachSQL)
	if err := restoreLimit(); err != nil {
		t.Fatal(err)
	}
	if attachErr != nil {
		t.Fatalf("trusted test setup could not attach on the coordinator's sole connection: %v", attachErr)
	}
	var present int
	if err := conn.QueryRowContext(context.Background(), verifySQL).Scan(&present); err != nil || present != 1 {
		t.Fatalf("same-connection attachment did not persist after restoring limit zero: count=%d err=%v", present, err)
	}
	if err := conn.Raw(func(raw any) error {
		if limit := raw.(*sqlite3.SQLiteConn).SetLimit(sqlite3.SQLITE_LIMIT_ATTACHED, -1); limit != originalLimit {
			return fmt.Errorf("ATTACH limit after setup=%d, want %d", limit, originalLimit)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPCanonicalHookPrevalidatesWholeAuthoredScript(t *testing.T) {
	for _, tc := range []struct{ name, suffix, wantError string }{
		{"begin", "BEGIN", "hook statement type is unsupported"},
		{"commit", "COMMIT", "hook statement type is unsupported"},
		{"end", "END", "hook statement type is unsupported"},
		{"rollback", "ROLLBACK", "hook statement type is unsupported"},
		{"savepoint", "SAVEPOINT mcp_guard", "hook statement type is unsupported"},
		{"release", "RELEASE mcp_guard", "hook statement type is unsupported"},
		{"create-temp-use-drop", "CREATE TEMP TABLE mcp_script_tmp(value TEXT); INSERT INTO temp.mcp_script_tmp VALUES('used'); DROP TABLE temp.mcp_script_tmp", "hook statement type is unsupported"},
		{"create-main-table", "CREATE TABLE mcp_script_main(value TEXT)", "hook statement type is unsupported"},
		{"attach", "ATTACH DATABASE ':memory:' AS mcp_script_attached", "hook statement type is unsupported"},
		{"detach", "DETACH DATABASE main", "hook statement type is unsupported"},
		{"pragma", "PRAGMA query_only=OFF", "hook statement type is unsupported"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var prefixCalls atomic.Int64
			script := "SELECT mcp_admission_prefix_observer(); UPDATE notes SET title='partial-prefix' WHERE id={{id}};\n" + tc.suffix
			f := newCanonicalUpdateSourceFixture(t, canonicalAdmissionAfterHook(script, `title='attempt'`), "", "", false)
			registerCanonicalAdmissionObserver(t, f, &prefixCalls)
			generation := snapshotAppMCPGeneration(f.app)
			authorityRoot := os.Getenv("BENMORE_MCP_AUTHORITY_DIR")
			owner, err := currentAppMCPEpoch(f.app.Dir)
			if err != nil {
				t.Fatal(err)
			}
			ownerPath := filepath.Join(authorityRoot, owner.App+".json")
			revisionPath := filepath.Join(authorityRoot, owner.App+".revisions.json")
			ownerBefore, err := os.ReadFile(ownerPath)
			if err != nil {
				t.Fatal(err)
			}
			if owner.ApprovedWrites == nil || *owner.ApprovedWrites {
				t.Fatalf("source fixture does not start with writes disabled: %+v (%v)", owner, err)
			}
			if _, err := os.Lstat(revisionPath); !os.IsNotExist(err) {
				t.Fatalf("source fixture unexpectedly has an external enrollment record: %v", err)
			}
			before := canonicalAdmissionState(t, f.app) + revisionStorageSnapshot(t, f.app)

			if _, err := initializeAppMCPRevisionEnrollment(context.Background(), f.app, generation); err == nil || !strings.Contains(err.Error(), "outside the supported read/write set") {
				t.Fatalf("unsupported source did not fail closed during enrollment preflight: %v", err)
			}
			if got := prefixCalls.Load(); got != 0 {
				t.Fatalf("enrollment refusal executed safe-prefix observer %d times", got)
			}
			if got, err := os.ReadFile(ownerPath); err != nil || string(got) != string(ownerBefore) {
				t.Fatalf("enrollment refusal changed owner bytes: %v", err)
			}
			if _, err := os.Lstat(revisionPath); !os.IsNotExist(err) {
				t.Fatalf("enrollment refusal left a pending external record: %v", err)
			}
			if after := canonicalAdmissionState(t, f.app) + revisionStorageSnapshot(t, f.app); after != before {
				t.Fatalf("enrollment refusal changed business, audit, sidecar, trigger, or schema state")
			}

			// Exercise the actual borrowed-transaction hook executor for the exact
			// source-loaded generation after enrollment correctly refused it.
			ctx := context.Background()
			tx, err := f.app.DB.BeginTx(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			row := map[string]any{"id": int64(1), "user_id": f.uid, "title": "attempt"}
			_, hookErr := fireAfterHooksTx(appMCPContextTx{tx: tx, ctx: ctx, private: true}, generation.view, "update", "notes", row)
			if hookErr == nil || !strings.Contains(hookErr.Error(), tc.wantError) {
				t.Fatalf("borrowed transaction did not reject full %s script during hook prevalidation: %v", tc.name, hookErr)
			}
			if got := prefixCalls.Load(); got != 0 {
				t.Fatalf("hook-executor refusal ran safe-prefix observer %d times", got)
			}
			var usable int
			if err := tx.QueryRowContext(ctx, "SELECT 1").Scan(&usable); err != nil || usable != 1 {
				t.Fatalf("caller transaction was not usable after prevalidation refusal: value=%d err=%v", usable, err)
			}
			if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
				t.Fatal(err)
			}
			assertCanonicalAdmissionConnectionClean(t, f.app)
			if after := canonicalAdmissionState(t, f.app) + revisionStorageSnapshot(t, f.app); after != before {
				t.Fatalf("hook-executor refusal changed business, audit, sidecar, trigger, or schema state")
			}
			if got, err := os.ReadFile(ownerPath); err != nil || string(got) != string(ownerBefore) {
				t.Fatalf("hook-executor component changed owner bytes: %v", err)
			}
			if _, err := os.Lstat(revisionPath); !os.IsNotExist(err) {
				t.Fatalf("hook-executor component left an external enrollment record: %v", err)
			}
		})
	}
	t.Run("allowed-script-runs-prefix", func(t *testing.T) {
		var prefixCalls atomic.Int64
		script := "SELECT mcp_admission_prefix_observer(); UPDATE notes SET title='allowed-prefix' WHERE id={{id}}"
		f := newCanonicalUpdateFixture(t, canonicalAdmissionAfterHook(script, `title='attempt'`), "", "")
		registerCanonicalAdmissionObserver(t, f, &prefixCalls)
		canonicalPositiveThenReset(t, f)
		projected, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("attempt"), f.now)
		if err != nil || projected["title"] != "allowed-prefix" || readCanonicalNote(t, f.app.DB) != "allowed-prefix" {
			t.Fatalf("allowed enrolled canonical control failed: result=%v err=%v", projected, err)
		}
		if got := prefixCalls.Load(); got != 1 {
			t.Fatalf("allowed enrolled prefix observer calls=%d, want 1", got)
		}
	})
}

func TestAppMCPCanonicalHookBorrowedTransactionExecutesAllowedScript(t *testing.T) {
	var prefixCalls atomic.Int64
	script := "SELECT mcp_admission_prefix_observer(); UPDATE notes SET title='allowed-prefix' WHERE id={{id}}"
	f := newCanonicalUpdateSourceFixture(t, canonicalAdmissionAfterHook(script, `title='attempt'`), "", "", false)
	registerCanonicalAdmissionObserver(t, f, &prefixCalls)
	generation := snapshotAppMCPGeneration(f.app)
	before := canonicalAdmissionState(t, f.app) + revisionStorageSnapshot(t, f.app)
	ctx := context.Background()
	tx, err := f.app.DB.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := fireAfterHooksTx(appMCPContextTx{tx: tx, ctx: ctx, private: true}, generation.view, "update", "notes", map[string]any{"id": int64(1), "user_id": f.uid, "title": "attempt"}); err != nil {
		t.Fatalf("allowed component-level hook execution failed: %v", err)
	}
	var title string
	if err := tx.QueryRowContext(ctx, "SELECT title FROM main.notes WHERE id=1").Scan(&title); err != nil || title != "allowed-prefix" {
		t.Fatalf("allowed hook result is not visible in the same borrowed transaction: title=%q err=%v", title, err)
	}
	if got := prefixCalls.Load(); got != 1 {
		t.Fatalf("allowed borrowed-transaction prefix observer calls=%d, want 1", got)
	}
	if err := tx.Rollback(); err != nil && !errors.Is(err, sql.ErrTxDone) {
		t.Fatal(err)
	}
	if got := readCanonicalNote(t, f.app.DB); got != "before" {
		t.Fatalf("borrowed-transaction positive was not rolled back: title=%q", got)
	}
	assertCanonicalAdmissionConnectionClean(t, f.app)
	if after := canonicalAdmissionState(t, f.app) + revisionStorageSnapshot(t, f.app); after != before {
		t.Fatal("borrowed-transaction positive did not restore the database state after rollback")
	}
}

func assertCanonicalAdmissionConnectionClean(t *testing.T, app *App) {
	t.Helper()
	rows, err := app.DB.Query("PRAGMA database_list")
	if err != nil {
		t.Fatal(err)
	}
	for rows.Next() {
		var seq int
		var name, path string
		if err := rows.Scan(&seq, &name, &path); err != nil {
			rows.Close()
			t.Fatal(err)
		}
		if name != "main" && name != "temp" {
			rows.Close()
			t.Fatalf("hook script left attached database %q", name)
		}
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		t.Fatal(err)
	}
	var tempObjects int
	if err := app.DB.QueryRow("SELECT count(*) FROM temp.sqlite_schema WHERE name NOT LIKE 'sqlite_%'").Scan(&tempObjects); err != nil || tempObjects != 0 {
		t.Fatalf("hook script left temp schema objects: count=%d err=%v", tempObjects, err)
	}
}

func registerCanonicalAdmissionObserver(t *testing.T, f appMCPCanonicalUpdateFixture, calls *atomic.Int64) {
	t.Helper()
	f.app.DB.SetMaxOpenConns(1)
	conn, err := f.app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.Raw(func(raw any) error {
		sqliteConn, ok := raw.(*sqlite3.SQLiteConn)
		if !ok {
			return errors.New("unexpected SQLite connection type")
		}
		return sqliteConn.RegisterFunc("mcp_admission_prefix_observer", func() int64 {
			return calls.Add(1)
		}, false)
	}); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPCanonicalHookScannerHandlesQuotedCommentsAndMalformedSQL(t *testing.T) {
	t.Run("quoted-and-comment-delimiters", func(t *testing.T) {
		script := `UPDATE notes SET title='COMMIT; END; ROLLBACK; it''s text' WHERE id={{id}};
-- semicolons; END; ROLLBACK; in a comment do not become statements`
		f := newCanonicalUpdateFixture(t, canonicalAdmissionAfterHook(script, `title='attempt'`), "", "")
		canonicalPositiveThenReset(t, f)
		projected, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("attempt"), f.now)
		if err != nil || projected["title"] != "COMMIT; END; ROLLBACK; it's text" {
			t.Fatalf("quoted/comment delimiters changed authored SQL semantics: result=%v err=%v", projected, err)
		}
	})

	t.Run("malformed-script-rolls-back-without-panic", func(t *testing.T) {
		script := "UPDATE notes SET title='partial-prefix' WHERE id={{id}}; UPDATE notes SET title='unterminated WHERE id=1"
		f := newCanonicalUpdateFixture(t, canonicalAdmissionAfterHook(script, `title='attempt'`), "", "")
		canonicalPositiveThenReset(t, f)
		before := canonicalAdmissionState(t, f.app)
		if _, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("attempt"), f.now); err == nil {
			t.Fatal("malformed authored SQL unexpectedly succeeded")
		}
		if after := canonicalAdmissionState(t, f.app); after != before {
			t.Fatalf("malformed SQL changed state: before=%s after=%s", before, after)
		}
	})
}

func canonicalAdmissionAfterHook(sql, when string) string {
	var b strings.Builder
	b.WriteString("on_update:\n  notes:\n    - when: \"")
	b.WriteString(strings.ReplaceAll(when, `"`, `\"`))
	b.WriteString("\"\n      sql: |\n")
	for _, line := range strings.Split(sql, "\n") {
		b.WriteString("        ")
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

func canonicalAdmissionState(t *testing.T, app *App) string {
	t.Helper()
	markers, err := QueryRows(app.DB, `SELECT id,value FROM main.lifecycle_markers ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(markers)
	if err != nil {
		t.Fatal(err)
	}
	return canonicalEffectsSnapshot(t, app) + string(encoded)
}
