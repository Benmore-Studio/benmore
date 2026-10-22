//go:build !cli

package main

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const prismaUpdatedAtTestSchema = `model Note {
  id Int @id
  title String
  updated_at DateTime? @updatedAt
  @@map("notes")
}`

func prismaUpdatedAtTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE notes(id INTEGER PRIMARY KEY,title TEXT,updated_at DATETIME)`)
	return db
}

func prismaUpdatedAtStoredSQL(t *testing.T, db *sql.DB, name string) string {
	t.Helper()
	var ddl string
	if err := db.QueryRow(`SELECT sql FROM main.sqlite_schema WHERE type='trigger' AND name=?`, name).Scan(&ddl); err != nil {
		t.Fatal(err)
	}
	return ddl
}

type prismaUpdatedAtReadRecorder struct {
	*sql.DB
	queries []string
}

func (q *prismaUpdatedAtReadRecorder) QueryRow(query string, args ...any) *sql.Row {
	q.queries = append(q.queries, query)
	return q.DB.QueryRow(query, args...)
}

func TestPrismaUpdatedAtPreflightReadOnlyCapturedDeclarations(t *testing.T) {
	for _, kind := range []string{"missing", "legacy", "current", "altered", "table_collision"} {
		t.Run(kind, func(t *testing.T) {
			db := prismaUpdatedAtTestDB(t)
			switch kind {
			case "legacy":
				crudScopeMustExec(t, db, legacyPrismaUpdatedAtTriggerSQL("notes", "updated_at"))
			case "current":
				crudScopeMustExec(t, db, prismaUpdatedAtTriggerSQL("notes", "updated_at"))
			case "altered":
				crudScopeMustExec(t, db, `CREATE TRIGGER trg_notes_updated_at_updated AFTER UPDATE ON notes BEGIN DELETE FROM notes; END`)
			case "table_collision":
				crudScopeMustExec(t, db, `CREATE TABLE trg_notes_updated_at_updated (value TEXT)`)
			}
			crudScopeMustExec(t, db, `INSERT INTO notes VALUES(1,'untouched','2000-01-01')`)
			var schemaBefore, schemaAfter string
			if err := db.QueryRow(`SELECT group_concat(sql,'|') FROM (SELECT sql FROM sqlite_schema ORDER BY type,name)`).Scan(&schemaBefore); err != nil {
				t.Fatal(err)
			}
			crudScopeMustExec(t, db, `PRAGMA query_only=ON`)
			recorder := &prismaUpdatedAtReadRecorder{DB: db}
			err := checkPrismaUpdatedAtTriggers(recorder, []byte(prismaUpdatedAtTestSchema))
			wantError := kind == "altered" || kind == "table_collision"
			if (err != nil) != wantError {
				t.Fatalf("preflight %s: %v", kind, err)
			}
			if len(recorder.queries) != 1 || !strings.HasPrefix(recorder.queries[0], "SELECT type, tbl_name, COALESCE(sql,'') FROM main.sqlite_schema WHERE name=?") {
				t.Fatalf("preflight queried outside trigger metadata: %q", recorder.queries)
			}
			// No capture declaration means no authority to inspect or adopt a
			// same-named trigger, including one pending in mutable source.
			undeclared := strings.Replace(prismaUpdatedAtTestSchema, " @updatedAt", "", 1)
			recorder.queries = nil
			if err := checkPrismaUpdatedAtTriggers(recorder, []byte(undeclared)); err != nil || len(recorder.queries) != 0 {
				t.Fatalf("undeclared timestamp trigger inspected: %q (%v)", recorder.queries, err)
			}
			if err := db.QueryRow(`SELECT group_concat(sql,'|') FROM (SELECT sql FROM sqlite_schema ORDER BY type,name)`).Scan(&schemaAfter); err != nil || schemaBefore != schemaAfter {
				t.Fatalf("preflight changed database schema: %v", err)
			}
			var title string
			if err := db.QueryRow(`SELECT title FROM notes WHERE id=1`).Scan(&title); err != nil || title != "untouched" {
				t.Fatalf("preflight changed application row: %q (%v)", title, err)
			}
		})
	}
}

func TestPrismaUpdatedAtKeepsExplicitPreciseAndFutureTimestamps(t *testing.T) {
	db := prismaUpdatedAtTestDB(t)
	crudScopeMustExec(t, db, prismaUpdatedAtTriggerSQL("notes", "updated_at"))
	for _, tc := range []struct{ name, previous, supplied string }{
		{"explicit_fraction", "2000-01-01 00:00:00", "2000-01-01 00:00:00.123456789"},
		{"explicit_past", "2000-01-01 00:00:00", "1999-01-01 00:00:00"},
		{"future_maintenance", "2999-01-01 00:00:00.123456789", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			crudScopeMustExec(t, db, `DELETE FROM notes`)
			if _, err := db.Exec(`INSERT INTO notes VALUES(1,'before',?)`, tc.previous); err != nil {
				t.Fatal(err)
			}
			want := tc.previous
			if tc.supplied != "" {
				want = tc.supplied
				if _, err := db.Exec(`UPDATE notes SET title='after',updated_at=? WHERE id=1`, tc.supplied); err != nil {
					t.Fatal(err)
				}
			} else {
				crudScopeMustExec(t, db, `UPDATE notes SET title='after' WHERE id=1`)
			}
			var got string
			if err := db.QueryRow(`SELECT CAST(updated_at AS TEXT) FROM notes WHERE id=1`).Scan(&got); err != nil || got != want {
				t.Fatalf("timestamp regressed: got %q, want %q (%v)", got, want, err)
			}
		})
	}
	for _, seed := range []string{"NULL", "'2000-01-01 00:00:00'"} {
		crudScopeMustExec(t, db, `DELETE FROM notes`)
		crudScopeMustExec(t, db, `INSERT INTO notes VALUES(1,'before',`+seed+`)`)
		crudScopeMustExec(t, db, `UPDATE notes SET title='implicit' WHERE id=1`)
		var advanced bool
		if err := db.QueryRow(`SELECT updated_at IS NOT NULL AND julianday(updated_at)>julianday('2000-01-01') FROM notes`).Scan(&advanced); err != nil || !advanced {
			t.Fatalf("implicit update did not advance metadata: %v (%v)", advanced, err)
		}
	}
}

func TestPrismaUpdatedAtUpgradeAtomicAndPreservesLegacyHistory(t *testing.T) {
	for _, failure := range []string{"changed_trigger", "invalid_column", "none"} {
		t.Run(failure, func(t *testing.T) {
			db := prismaUpdatedAtTestDB(t)
			crudScopeMustExec(t, db, legacyPrismaUpdatedAtTriggerSQL("notes", "updated_at"))
			crudScopeMustExec(t, db, `CREATE TABLE notes_history(id INTEGER, title TEXT, _version INTEGER, _valid_from TEXT, _valid_to TEXT)`)
			crudScopeMustExec(t, db, `INSERT INTO notes_history VALUES(1,'retained',9,'2026-10-16 03:28:39.137470092','2026-10-16 03:28:39')`)
			crudScopeMustExec(t, db, `INSERT INTO notes VALUES(1,'source','2000-01-01')`)
			before := prismaUpdatedAtStoredSQL(t, db, "trg_notes_updated_at_updated")
			deferred := []string{prismaUpdatedAtTriggerSQL("notes", "updated_at")}
			if failure != "none" {
				crudScopeMustExec(t, db, `CREATE TABLE extras(id INTEGER PRIMARY KEY,stamp DATETIME)`)
				if failure == "changed_trigger" {
					crudScopeMustExec(t, db, `CREATE TRIGGER trg_extras_stamp_updated AFTER UPDATE ON extras BEGIN DELETE FROM notes; END`)
					deferred = append(deferred, prismaUpdatedAtTriggerSQL("extras", "stamp"))
				} else {
					deferred = append(deferred, prismaUpdatedAtTriggerSQL("extras", "missing"))
				}
			}
			err := ApplyDeferredDDL(db, deferred)
			if failure != "none" {
				if err == nil {
					t.Fatal("invalid second trigger did not abort upgrade")
				}
				if got := prismaUpdatedAtStoredSQL(t, db, "trg_notes_updated_at_updated"); got != before {
					t.Fatal("failed second trigger committed first trigger upgrade")
				}
				var leaked int
				if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name='trg_extras_missing_updated'`).Scan(&leaked); err != nil || leaked != 0 {
					t.Fatalf("invalid compiled trigger leaked: %d (%v)", leaked, err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if got := prismaUpdatedAtStoredSQL(t, db, "trg_notes_updated_at_updated"); normalizePrismaUpdatedAtSQL(got) != normalizePrismaUpdatedAtSQL(deferred[0]) {
					t.Fatalf("retained trigger was not upgraded: %s", got)
				}
				if err := ApplyDeferredDDL(db, deferred); err != nil {
					t.Fatalf("repeat upgrade: %v", err)
				}
			}
			var retained string
			if err := db.QueryRow(`SELECT id||'|'||title||'|'||_version||'|'||_valid_from||'|'||_valid_to FROM notes_history`).Scan(&retained); err != nil || retained != "1|retained|9|2026-10-16 03:28:39.137470092|2026-10-16 03:28:39" {
				t.Fatalf("legacy history was rewritten: %q (%v)", retained, err)
			}
			var source string
			if err := db.QueryRow(`SELECT title FROM notes WHERE id=1`).Scan(&source); err != nil || source != "source" {
				t.Fatalf("DDL executed application mutation: %q (%v)", source, err)
			}
		})
	}
}

func TestPrismaUpdatedAtCapturedSchemaUpgradeAndMCPClosure(t *testing.T) {
	db := prismaUpdatedAtTestDB(t)
	dir := t.TempDir()
	crudScopeMustExec(t, db, legacyPrismaUpdatedAtTriggerSQL("notes", "updated_at"))
	// Pending disk content cannot authorize a trigger. Load from the reviewed
	// source capture, then verify closure against that same immutable capture.
	writeTestFile(t, dir, "schema.prisma", strings.Replace(prismaUpdatedAtTestSchema, " @updatedAt", "", 1))
	readCaptured := func(name string) ([]byte, error) {
		if name == "schema.prisma" {
			return []byte(prismaUpdatedAtTestSchema), nil
		}
		return nil, os.ErrNotExist
	}
	for i := 0; i < 2; i++ {
		tables, deferred, err := loadSchemaWithReader(db, dir, readCaptured, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Migrate(db, tables, false); err != nil {
			t.Fatal(err)
		}
		if err := ApplyDeferredDDL(db, deferred); err != nil {
			t.Fatal(err)
		}
	}
	generation := &appMCPRuntimeGeneration{view: &App{}, sourceFiles: map[string][]byte{"schema.prisma": []byte(prismaUpdatedAtTestSchema)}}
	checkClosure := func(generation *appMCPRuntimeGeneration) error {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		return verifyAppMCPDeclaredTriggerClosure(tx, generation, []string{"notes"}, false)
	}
	if err := checkClosure(generation); err != nil {
		stored := prismaUpdatedAtStoredSQL(t, db, "trg_notes_updated_at_updated")
		matches, matchErr := appMCPRevisionSQLMatches(stored, strings.TrimSuffix(prismaUpdatedAtTriggerSQL("notes", "updated_at"), ";"))
		t.Fatalf("upgraded captured trigger rejected: %v; stored=%q, canonicalMatches=%v (%v)", err, stored, matches, matchErr)
	}
	undeclared := &appMCPRuntimeGeneration{view: &App{}, sourceFiles: map[string][]byte{"schema.prisma": []byte(strings.Replace(prismaUpdatedAtTestSchema, " @updatedAt", "", 1))}}
	if err := checkClosure(undeclared); err == nil {
		t.Fatal("trigger accepted without captured updatedAt declaration")
	}
	crudScopeMustExec(t, db, `DROP TRIGGER trg_notes_updated_at_updated`)
	altered := strings.Replace(prismaUpdatedAtTriggerSQL("notes", "updated_at"), "END;", "DELETE FROM notes WHERE id <> NEW.id; END;", 1)
	crudScopeMustExec(t, db, altered)
	if err := checkClosure(generation); err == nil {
		t.Fatal("changed generated trigger accepted by MCP closure")
	}
	if err := ApplyDeferredDDL(db, []string{prismaUpdatedAtTriggerSQL("notes", "updated_at")}); err == nil {
		t.Fatal("changed generated trigger was silently repaired")
	}
	if got := prismaUpdatedAtStoredSQL(t, db, "trg_notes_updated_at_updated"); normalizePrismaUpdatedAtSQL(got) != normalizePrismaUpdatedAtSQL(altered) {
		t.Fatal("refusal overwrote changed trigger")
	}
}

func TestPrismaUpdatedAtRetainedMCPCheckedStartupAndReload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("MCP owner authority requires the Unix filesystem boundary")
	}
	for _, phase := range []string{"startup", "reload"} {
		t.Run(phase, func(t *testing.T) {
			t.Setenv("BENMORE_TEST_BOOT", "1")
			authority, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(authority, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, dir, "schema.prisma", prismaUpdatedAtTestSchema)
			writeTestFile(t, dir, "app.yaml", "access:\n  notes: {all: everyone}\n")
			writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: '"+strings.Repeat("31", 32)+"'\n")
			writeTestFile(t, dir, "mcp.yaml", appMCPUpdateManifestFixture())
			reviewAppMCPFixture(t, dir)
			app, err := loadApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if app != nil {
					app.Shutdown()
				}
			})
			if err := EnsureUsersTable(app.DB); err != nil {
				t.Fatal(err)
			}
			if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
				t.Fatal(err)
			}
			if _, err := setAppMCPApprovedWrites(app.Dir, false); err != nil {
				t.Fatal(err)
			}
			if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, snapshotAppMCPGeneration(app)); err != nil {
				t.Fatalf("enroll real checked MCP fixture: %v", err)
			}
			crudScopeMustExec(t, app.DB, `INSERT INTO notes VALUES(1,'retained','2000-01-01')`)
			crudScopeMustExec(t, app.DB, `DROP TRIGGER trg_notes_updated_at_updated`)
			crudScopeMustExec(t, app.DB, legacyPrismaUpdatedAtTriggerSQL("notes", "updated_at"))
			beforeTx, err := app.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			legacyClosureErr := verifyAppMCPDeclaredTriggerClosure(beforeTx, snapshotAppMCPGeneration(app), []string{"notes"}, false)
			beforeTx.Rollback()
			if legacyClosureErr == nil {
				t.Fatal("ordinary MCP closure accepted retained legacy SQL before upgrade")
			}
			if phase == "startup" {
				app.Shutdown()
				app, err = loadApp(dir)
			} else {
				err = reloadAppConfig(app)
			}
			if err != nil {
				t.Fatalf("checked MCP %s rejected retained legacy trigger before upgrade: %v", phase, err)
			}
			if app.MCP == nil {
				t.Fatal("checked app withheld its reviewed MCP manifest")
			}
			if got := prismaUpdatedAtStoredSQL(t, app.DB, "trg_notes_updated_at_updated"); normalizePrismaUpdatedAtSQL(got) != normalizePrismaUpdatedAtSQL(prismaUpdatedAtTriggerSQL("notes", "updated_at")) {
				t.Fatalf("checked MCP %s did not replace retained legacy trigger", phase)
			}
			tx, err := app.DB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			closureErr := verifyAppMCPDeclaredTriggerClosure(tx, snapshotAppMCPGeneration(app), []string{"notes"}, false)
			tx.Rollback()
			if closureErr != nil {
				t.Fatalf("current-only post-upgrade closure failed: %v", closureErr)
			}
			var title string
			if err := app.DB.QueryRow(`SELECT title FROM notes WHERE id=1`).Scan(&title); err != nil || title != "retained" {
				t.Fatalf("checked upgrade changed retained application row: %q (%v)", title, err)
			}
		})
	}
}
