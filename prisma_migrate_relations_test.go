//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const relationParents = `model Dispatch {
 id Int @id @default(autoincrement())
 user_id Int?
 title String @default("")
 notes Note[]
}
`

func TestPrismaRelationRepairReferenceAffinity(t *testing.T) {
	for _, tc := range []struct {
		name, parentType, childType string
		parent, child               any
		valid                       bool
	}{
		{"parent text does not inherit child integer affinity", "TEXT", "INTEGER", "001", 1, false},
		{"parent numeric coerces child text", "INTEGER", "TEXT", 1, "01", true},
		{"parent collation controls equality", "TEXT COLLATE NOCASE", "TEXT", "parent-a", "PARENT-A", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := migrationSafetyDB(t)
			mustExec(t, db, "CREATE TABLE parents(id "+tc.parentType+" PRIMARY KEY)")
			mustExec(t, db, "CREATE TABLE children(id INTEGER PRIMARY KEY,parent_id "+tc.childType+")")
			mustExec(t, db, "CREATE TABLE constrained(id INTEGER PRIMARY KEY,parent_id "+tc.childType+" REFERENCES parents(id))")
			if _, err := db.Exec("INSERT INTO parents VALUES(?)", tc.parent); err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec("INSERT INTO children VALUES(1,?)", tc.child); err != nil {
				t.Fatal(err)
			}
			_, controlErr := db.Exec("INSERT INTO constrained VALUES(1,?)", tc.child)
			if (controlErr == nil) != tc.valid {
				t.Fatalf("SQLite native FK control disagrees: %v", controlErr)
			}
			_, err := checkPrismaRelationRepairs(db, map[string][]PrismaField{"children": {{Column: "parent_id", FKTable: "parents", FKColumn: "id"}}})
			if (err == nil) != tc.valid {
				t.Fatalf("read-only repair check disagrees with SQLite: %v", err)
			}
		})
	}
}

func TestPrismaRelationRepairPreservesCatalogAndHiddenRowIDs(t *testing.T) {
	db, dir := migrationSafetyDB(t), t.TempDir()
	for _, statement := range []string{
		`CREATE TABLE dispatches(id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,title TEXT NOT NULL DEFAULT '')`,
		`CREATE TABLE owners(id INTEGER PRIMARY KEY)`,
		`INSERT INTO dispatches(id) VALUES(1)`, `INSERT INTO owners VALUES(1)`,
		`CREATE TABLE notes(id TEXT PRIMARY KEY, dispatch_id INTEGER, title TEXT COLLATE NOCASE UNIQUE CHECK(length(title)>0), owner_id INTEGER REFERENCES owners(id) ON DELETE SET NULL, computed TEXT GENERATED ALWAYS AS (title || '!') STORED) STRICT`,
		`INSERT INTO notes(rowid,id,dispatch_id,title,owner_id) VALUES(7,'a',1,'Alpha',1),(19,'b',NULL,'Bravo',1)`,
		`CREATE VIRTUAL TABLE notes_search USING fts5(title,content='notes',content_rowid='rowid')`,
		`INSERT INTO notes_search(notes_search) VALUES('rebuild')`,
		`CREATE TRIGGER note_search_update AFTER UPDATE ON notes BEGIN INSERT INTO notes_search(notes_search,rowid,title) VALUES('delete',old.rowid,old.title); INSERT INTO notes_search(rowid,title) VALUES(new.rowid,new.title); END`,
	} {
		mustExec(t, db, statement)
	}
	current := relationParents + `model Note {
 id String @id
 dispatch_id Int?
 title String
 dispatch Dispatch? @relation(fields: [dispatch_id], references: [id])
}`
	if _, err := ApplyPrismaMigration(db, dir, current); err != nil {
		t.Fatal(err)
	}
	assertRelation(t, db, "notes", "dispatch_id", "dispatches")
	var rowid int
	var generated, ddl string
	if err := db.QueryRow(`SELECT rowid,computed FROM notes WHERE id='b'`).Scan(&rowid, &generated); err != nil || rowid != 19 || generated != "Bravo!" {
		t.Fatalf("identity/generated changed: %d %q %v", rowid, generated, err)
	}
	if err := db.QueryRow(`SELECT sql FROM sqlite_schema WHERE name='notes'`).Scan(&ddl); err != nil || !strings.Contains(ddl, "STRICT") {
		t.Fatalf("table options changed: %q %v", ddl, err)
	}
	for _, statement := range []string{`INSERT INTO notes(id,title) VALUES('c','ALPHA')`, `INSERT INTO notes(id,title) VALUES('c','')`, `INSERT INTO notes(id,title,owner_id) VALUES('c','Charlie',999)`} {
		if _, err := db.Exec(statement); err == nil {
			t.Fatalf("constraint lost: %s", statement)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM notes_search WHERE notes_search MATCH 'Bravo' AND rowid=19`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("FTS identity changed: %d %v", n, err)
	}
	mustExec(t, db, `UPDATE notes SET title='Revised' WHERE id='b'`)
	if err := db.QueryRow(`SELECT count(*) FROM notes_search WHERE notes_search MATCH 'Revised' AND rowid=19`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("FTS trigger lost: %d %v", n, err)
	}
	mustExec(t, db, `DELETE FROM owners WHERE id=1`)
	if err := db.QueryRow(`SELECT count(*) FROM notes WHERE owner_id IS NULL`).Scan(&n); err != nil || n != 2 {
		t.Fatalf("custom FK action changed: %d %v", n, err)
	}
}

func TestPrismaRelationRepairWithoutRowIDAndForeignKeysOff(t *testing.T) {
	for _, invalid := range []bool{false, true} {
		t.Run(fmt.Sprintf("invalid_%v", invalid), func(t *testing.T) {
			db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			mustExec(t, db, `CREATE TABLE dispatches(id INTEGER PRIMARY KEY); INSERT INTO dispatches VALUES(1)`)
			mustExec(t, db, `CREATE TABLE notes(id TEXT PRIMARY KEY,dispatch_id INTEGER) WITHOUT ROWID`)
			parent := 1
			if invalid {
				parent = 999
			}
			mustExecArgs(t, db, `INSERT INTO notes VALUES('keep',?)`, parent)
			current := relationParents + `model Note {
 id String @id
 dispatch_id Int?
 dispatch Dispatch? @relation(fields: [dispatch_id],references:[id])
}`
			_, err = ApplyPrismaMigration(db, t.TempDir(), current)
			if invalid {
				if err == nil {
					t.Fatal("foreign_keys=off bypassed migration integrity check")
				}
			} else if err != nil {
				t.Fatal(err)
			} else {
				assertRelation(t, db, "notes", "dispatch_id", "dispatches")
			}
			var n, wr int
			if err := db.QueryRow(`SELECT count(*) FROM notes WHERE id='keep'`).Scan(&n); err != nil || n != 1 {
				t.Fatalf("row lost: %d %v", n, err)
			}
			if err := db.QueryRow(`SELECT wr FROM pragma_table_list WHERE name='notes'`).Scan(&wr); err != nil || wr != 1 {
				t.Fatalf("WITHOUT ROWID lost: %d %v", wr, err)
			}
		})
	}
}

func TestPrismaRelationRepairJournalsAndRollbackRefusal(t *testing.T) {
	for _, runtime := range []bool{false, true} {
		t.Run(fmt.Sprintf("runtime_%v", runtime), func(t *testing.T) {
			db, dir := migrationSafetyDB(t), t.TempDir()
			initial := relationNoteSource(" dispatch_id Int?", "")
			if _, err := applyPrismaMigration(db, dir, initial, runtime); err != nil {
				t.Fatal(err)
			}
			mustExec(t, db, `INSERT INTO dispatches(id) VALUES(1); INSERT INTO notes(id,title,dispatch_id) VALUES(7,'journal row',1)`)
			copyPath := filepath.Join(t.TempDir(), "before.db")
			mustExecArgs(t, db, `VACUUM INTO ?`, copyPath)
			current := relationNoteSource(" dispatch_id Int?", " dispatch Dispatch? @relation(fields:[dispatch_id],references:[id])")
			name, err := applyPrismaMigration(db, dir, current, runtime)
			if err != nil {
				t.Fatal(err)
			}
			var journal string
			if runtime {
				err = db.QueryRow(`SELECT sql FROM _benmore_prisma_runtime_journals WHERE name=?`, name).Scan(&journal)
			} else {
				var b []byte
				b, err = os.ReadFile(filepath.Join(dir, "migrations", name))
				journal = string(b)
			}
			if err != nil || !strings.Contains(journal, `FOREIGN KEY ("dispatch_id") REFERENCES "dispatches"("id")`) || !strings.Contains(journal, prismaRelationExplicitRollback) {
				t.Fatalf("journal incomplete: %v\n%s", err, journal)
			}
			copyDB, err := sql.Open("sqlite3", copyPath+"?_foreign_keys=on")
			if err != nil {
				t.Fatal(err)
			}
			defer copyDB.Close()
			up, _ := extractMigrationSection(journal)
			tx, err := copyDB.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			for _, statement := range splitStatements(up) {
				statement = strings.TrimSpace(statement)
				if statement == "" || strings.HasPrefix(statement, "--") {
					continue
				}
				if _, err := tx.Exec(statement); err != nil {
					t.Fatalf("replay emitted journal: %v\n%s", err, statement)
				}
			}
			if err := tx.Commit(); err != nil {
				t.Fatal(err)
			}
			assertRelation(t, copyDB, "notes", "dispatch_id", "dispatches")
			var retained int
			if err := copyDB.QueryRow(`SELECT count(*) FROM notes WHERE id=7 AND title='journal row' AND dispatch_id=1`).Scan(&retained); err != nil || retained != 1 {
				t.Fatalf("journal replay data: %d %v", retained, err)
			}
			if _, err := RollbackPrismaMigration(db, dir, 1, true); err == nil || !strings.Contains(err.Error(), "explicit migration") {
				t.Fatalf("unsafe rollback accepted: %v", err)
			}
			assertRelation(t, db, "notes", "dispatch_id", "dispatches")
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM _benmore_migrations`).Scan(&n); err != nil || n != 2 {
				t.Fatalf("rollback modified ledger: %d %v", n, err)
			}
		})
	}
}

func TestPrismaNewRelationDefaultValidatedWithForeignKeysOff(t *testing.T) {
	for _, valid := range []bool{false, true} {
		t.Run(fmt.Sprintf("valid_%v", valid), func(t *testing.T) {
			db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			dir := t.TempDir()
			initial := relationNoteSource("", "")
			if _, err := ApplyPrismaMigration(db, dir, initial); err != nil {
				t.Fatal(err)
			}
			mustExec(t, db, `INSERT INTO notes(title) VALUES('existing row')`)
			if valid {
				mustExec(t, db, `INSERT INTO dispatches(id) VALUES(17)`)
			}
			current := relationNoteSource(" dispatch_id Int? @default(17)", " dispatch Dispatch? @relation(fields:[dispatch_id],references:[id])")
			_, err = ApplyPrismaMigration(db, dir, current)
			if valid {
				if err != nil {
					t.Fatal(err)
				}
				assertRelation(t, db, "notes", "dispatch_id", "dispatches")
			} else {
				if err == nil {
					t.Fatal("new inline FK accepted invalid default with foreign_keys disabled")
				}
				if dbColumnExists(db, "notes", "dispatch_id") {
					t.Fatal("invalid inline FK did not roll back")
				}
				var source string
				if err := db.QueryRow(`SELECT source FROM _benmore_migrations ORDER BY id DESC LIMIT 1`).Scan(&source); err != nil || source != initial {
					t.Fatalf("ledger changed: %v", err)
				}
			}
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM notes WHERE title='existing row'`).Scan(&n); err != nil || n != 1 {
				t.Fatalf("row changed: %d %v", n, err)
			}
		})
	}
}

func TestPrismaNewNullableRelationDoesNotRebuildReferencedTable(t *testing.T) {
	db, dir := migrationSafetyDB(t), t.TempDir()
	if _, err := ApplyPrismaMigration(db, dir, relationNoteSource("", "")); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO notes(id,title) VALUES(1,'kept'); CREATE TABLE attachments(note_id INTEGER REFERENCES notes(id) ON DELETE CASCADE); INSERT INTO attachments VALUES(1)`)
	current := relationNoteSource(" dispatch_id Int?", " dispatch Dispatch? @relation(fields:[dispatch_id],references:[id])")
	if _, err := ApplyPrismaMigration(db, dir, current); err != nil {
		t.Fatal(err)
	}
	assertRelation(t, db, "notes", "dispatch_id", "dispatches")
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM attachments`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("child lost: %d %v", n, err)
	}
	if _, err := RollbackPrismaMigration(db, dir, 1, true); err != nil {
		t.Fatal(err)
	}
	if dbColumnExists(db, "notes", "dispatch_id") {
		t.Fatal("inline relation addition did not roll back")
	}
}

func relationNoteSource(column, relation string) string {
	return relationParents + "model Note {\n id Int @id @default(autoincrement())\n user_id Int?\n title String @default(\"\")\n" + column + "\n" + relation + "\n}\n"
}

func assertRelation(t *testing.T, db *sql.DB, table, column, target string) {
	t.Helper()
	fks, err := GetForeignKeys(db, table)
	if err != nil || fks[column].Table != target || fks[column].Column != "id" {
		t.Fatalf("physical relation %s.%s -> %s.id missing: %+v err=%v", table, column, target, fks, err)
	}
}

func TestPrismaAddedRelationExistingRows(t *testing.T) {
	for _, sameSource := range []bool{false, true} {
		t.Run(fmt.Sprintf("already_recorded_%v", sameSource), func(t *testing.T) {
			db, dir := migrationSafetyDB(t), t.TempDir()
			initial := relationNoteSource(" dispatch_id Int?", "")
			current := relationNoteSource(" dispatch_id Int?", " dispatch Dispatch? @relation(fields: [dispatch_id], references: [id])")
			if _, err := ApplyPrismaMigration(db, dir, initial); err != nil {
				t.Fatal(err)
			}
			mustExec(t, db, `INSERT INTO dispatches(id,title) VALUES(1,'parent')`)
			mustExec(t, db, `INSERT INTO notes(id,title,dispatch_id) VALUES(5,'retained',1),(100,'deleted high-water',NULL)`)
			mustExec(t, db, `DELETE FROM notes WHERE id=100`)
			mustExec(t, db, `CREATE INDEX custom_note_title ON notes(title) WHERE title<>''`)
			mustExec(t, db, `CREATE TABLE note_changes(id INTEGER)`)
			mustExec(t, db, `CREATE TRIGGER custom_note_update AFTER UPDATE ON notes BEGIN INSERT INTO note_changes VALUES(new.id); END`)
			if sameSource {
				// Older runtimes recorded success but left the column unconstrained.
				mustExecArgs(t, db, `UPDATE _benmore_migrations SET source=?,source_hash=?`, current, schemaHash(current))
			}
			name, err := ApplyPrismaMigration(db, dir, current)
			if err != nil || name == "" {
				t.Fatalf("repair name=%q err=%v", name, err)
			}
			assertRelation(t, db, "notes", "dispatch_id", "dispatches")
			var title string
			if err := db.QueryRow(`SELECT title FROM notes WHERE id=5 AND dispatch_id=1`).Scan(&title); err != nil || title != "retained" {
				t.Fatalf("existing row lost: %q %v", title, err)
			}
			mustExec(t, db, `UPDATE notes SET title='updated' WHERE id=5`)
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM note_changes`).Scan(&n); err != nil || n != 1 {
				t.Fatalf("trigger lost: %d %v", n, err)
			}
			if err := db.QueryRow(`SELECT count(*) FROM sqlite_schema WHERE name='custom_note_title'`).Scan(&n); err != nil || n != 1 {
				t.Fatalf("index lost: %d %v", n, err)
			}
			result, err := db.Exec(`INSERT INTO notes(title,dispatch_id) VALUES('next',1)`)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := result.LastInsertId()
			if id <= 100 {
				t.Fatalf("sequence reused: %d", id)
			}
			if _, err := db.Exec(`INSERT INTO notes(dispatch_id) VALUES(999)`); err == nil {
				t.Fatal("nonexistent parent accepted")
			}
			if name, err := ApplyPrismaMigration(db, dir, current); err != nil || name != "" {
				t.Fatalf("not idempotent: %q %v", name, err)
			}
		})
	}
}

func TestPrismaAddedRelationNewColumn(t *testing.T) {
	for _, populated := range []bool{false, true} {
		for _, optional := range []bool{false, true} {
			t.Run(fmt.Sprintf("populated_%v_optional_%v", populated, optional), func(t *testing.T) {
				db, dir := migrationSafetyDB(t), t.TempDir()
				initial := relationNoteSource("", "")
				if _, err := ApplyPrismaMigration(db, dir, initial); err != nil {
					t.Fatal(err)
				}
				if populated {
					mustExec(t, db, `INSERT INTO notes(title) VALUES('keep me')`)
				}
				suffix := ""
				if optional {
					suffix = "?"
				}
				current := relationNoteSource(" dispatch_id Int"+suffix, " dispatch Dispatch"+suffix+" @relation(fields: [dispatch_id], references: [id])")
				_, err := ApplyPrismaMigration(db, dir, current)
				if populated && !optional {
					if err == nil {
						t.Fatal("required relation silently backfilled an invented parent")
					}
					if dbColumnExists(db, "notes", "dispatch_id") {
						t.Fatal("failed migration left new column")
					}
					var source, title string
					if err := db.QueryRow(`SELECT source FROM _benmore_migrations ORDER BY id DESC LIMIT 1`).Scan(&source); err != nil || source != initial {
						t.Fatalf("ledger changed: %v", err)
					}
					if err := db.QueryRow(`SELECT title FROM notes`).Scan(&title); err != nil || title != "keep me" {
						t.Fatalf("data changed: %q %v", title, err)
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				assertRelation(t, db, "notes", "dispatch_id", "dispatches")
				if populated {
					var n int
					if err := db.QueryRow(`SELECT count(*) FROM notes WHERE title='keep me' AND dispatch_id IS NULL`).Scan(&n); err != nil || n != 1 {
						t.Fatalf("nullable backfill changed data: %d %v", n, err)
					}
				}
			})
		}
	}
}

func TestPrismaAddedRelationInvalidRowsRollBack(t *testing.T) {
	db, dir := migrationSafetyDB(t), t.TempDir()
	initial := relationNoteSource(" dispatch_id Int?", "")
	if _, err := ApplyPrismaMigration(db, dir, initial); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO notes(title,dispatch_id) VALUES('orphan must survive',987)`)
	current := relationNoteSource(" dispatch_id Int?\n extra String?", " dispatch Dispatch? @relation(fields: [dispatch_id], references: [id])")
	if _, err := ApplyPrismaMigration(db, dir, current); err == nil {
		t.Fatal("invalid existing reference silently accepted")
	}
	if dbColumnExists(db, "notes", "extra") {
		t.Fatal("earlier ALTER did not roll back")
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM notes WHERE dispatch_id=987 AND title='orphan must survive'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("orphan lost: %d %v", n, err)
	}
	if err := db.QueryRow(`SELECT count(*) FROM _benmore_migrations`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("ledger advanced: %d %v", n, err)
	}
}

func TestPrismaAddedRelationRefusesReferencedTable(t *testing.T) {
	db, dir := migrationSafetyDB(t), t.TempDir()
	initial := relationNoteSource(" dispatch_id Int?", "")
	if _, err := ApplyPrismaMigration(db, dir, initial); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO dispatches(id) VALUES(1)`)
	mustExec(t, db, `INSERT INTO notes(id,dispatch_id) VALUES(1,1)`)
	mustExec(t, db, `CREATE TABLE attachments(id INTEGER PRIMARY KEY, note_id INTEGER REFERENCES notes(id) ON DELETE CASCADE)`)
	mustExec(t, db, `INSERT INTO attachments VALUES(1,1)`)
	current := relationNoteSource(" dispatch_id Int?", " dispatch Dispatch? @relation(fields: [dispatch_id], references: [id])")
	if _, err := ApplyPrismaMigration(db, dir, current); err == nil || !strings.Contains(err.Error(), "explicit migration") {
		t.Fatalf("unsafe rebuild not refused: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM attachments`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("cascade deleted rows: %d %v", n, err)
	}
}

func TestReloadStorageAddsPrismaRelationToExistingTable(t *testing.T) {
	app := reloadStorageApp(t)
	writeTestFile(t, app.Dir, "schema.prisma", relationNoteSource(" dispatch_id Int?", ""))
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	uid, sid := gateUser(t, app, "relation-owner@example.test")
	other, _ := gateUser(t, app, "relation-other@example.test")
	mustExecArgs(t, app.DB, `INSERT INTO dispatches(id,user_id,title) VALUES(1,?,'mine'),(2,?,'other')`, uid, other)
	writeTestFile(t, app.Dir, "schema.prisma", relationNoteSource(" dispatch_id Int?", " dispatch Dispatch? @relation(fields: [dispatch_id], references: [id])"))
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	for _, parent := range []int{2, 999} {
		w := gateCall(app, handleCreate, "notes", "POST", "/api/notes", "application/json", fmt.Sprintf(`{"title":"blocked","dispatch_id":%d}`, parent), sid)
		if w.Code != http.StatusUnprocessableEntity {
			t.Errorf("parent %d: %d %s", parent, w.Code, w.Body.String())
		}
	}
	w := gateCall(app, handleCreate, "notes", "POST", "/api/notes", "application/json", `{"title":"valid","dispatch_id":1}`, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("own parent: %d %s", w.Code, w.Body.String())
	}
	w = gateCall(app, handleList, "notes", "GET", "/api/notes?include=dispatch", "", "", sid)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"dispatch":{`) || !strings.Contains(w.Body.String(), `"title":"mine"`) {
		t.Fatalf("relation include: %d %s", w.Code, w.Body.String())
	}
}
