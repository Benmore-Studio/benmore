//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func migrationSafetyDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db")+"?_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestCustomFieldDropPreservesRelatedDataAndDependencies(t *testing.T) {
	for _, indexed := range []bool{false, true} {
		t.Run(map[bool]string{false: "supported", true: "dependent index refuses"}[indexed], func(t *testing.T) {
			db := migrationSafetyDB(t)
			for _, q := range []string{
				`CREATE TABLE parents(id INTEGER PRIMARY KEY, label TEXT NOT NULL UNIQUE, custom_field TEXT)`,
				`CREATE TABLE children(id INTEGER PRIMARY KEY, parent_id INTEGER REFERENCES parents(id) ON DELETE CASCADE)`,
				`INSERT INTO parents VALUES(1,'original','x')`, `INSERT INTO children VALUES(1,1)`,
			} {
				mustExec(t, db, q)
			}
			if indexed {
				mustExec(t, db, `CREATE INDEX parents_custom ON parents(custom_field)`)
			}
			app := &App{Dir: t.TempDir(), DB: db, SessionDuration: time.Hour}
			_, sid, _ := loginTestUser(app, "migration@example.test", "admin")
			EnsureAuditLogTable(db)
			mux := http.NewServeMux()
			RegisterCustomFieldRoutes(mux, app)
			mustExec(t, db, `INSERT INTO _benmore_custom_fields(table_name,column_name,column_type) VALUES('parents','custom_field','TEXT')`)
			req := httptest.NewRequest(http.MethodDelete, "/api/_schema/parents/fields/custom_field", nil)
			req.AddCookie(&http.Cookie{Name: devSessionCookieName, Value: sid})
			req.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
			rec := httptest.NewRecorder()
			mux.ServeHTTP(rec, req)
			if !indexed && rec.Code != http.StatusOK || indexed && rec.Code < 400 {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var n int
			if err := db.QueryRow(`SELECT COUNT(*) FROM children WHERE parent_id=1`).Scan(&n); err != nil || n != 1 {
				t.Fatalf("child rows=%d err=%v", n, err)
			}
			if _, err := db.Exec(`INSERT INTO parents(id,label) VALUES(2,'original')`); err == nil {
				t.Fatal("UNIQUE constraint lost")
			}
			if dbColumnExists(db, "parents", "custom_field") != indexed {
				t.Fatal("unexpected column state")
			}
			if err := db.QueryRow(`SELECT COUNT(*) FROM _benmore_custom_fields`).Scan(&n); err != nil || n != map[bool]int{false: 0, true: 1}[indexed] {
				t.Fatalf("tracking state=%d err=%v", n, err)
			}
		})
	}
}

func TestRebuildPreservesConstraintsIndexesTriggersAndSequence(t *testing.T) {
	db := migrationSafetyDB(t)
	for _, q := range []string{
		`CREATE TABLE owners(id INTEGER PRIMARY KEY)`, `INSERT INTO owners VALUES(1)`,
		`CREATE TABLE things(id INTEGER PRIMARY KEY AUTOINCREMENT, owner_id INTEGER REFERENCES owners(id), name TEXT COLLATE NOCASE UNIQUE, quantity INTEGER CHECK(quantity>=0), body TEXT CONSTRAINT body_required NOT NULL ON CONFLICT ABORT DEFAULT 'x', computed TEXT GENERATED ALWAYS AS (name || body) STORED)`,
		`CREATE INDEX things_quantity ON things(quantity) WHERE quantity>0`,
		`CREATE TABLE changes(id INTEGER)`,
		`CREATE TRIGGER things_update AFTER UPDATE ON things BEGIN INSERT INTO changes VALUES(new.id); END`,
		`INSERT INTO things(id,owner_id,name,quantity,body) VALUES(1,1,'Ada',5,'old'),(100,1,'Grace',1,'removed')`,
		`DELETE FROM things WHERE id=100`,
	} {
		mustExec(t, db, q)
	}
	if err := rebuildTable(db, "things", func(c Column) *Column {
		if c.Name == "body" {
			c.NotNull = false
		}
		return &c
	}); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `UPDATE things SET body=NULL WHERE id=1`)
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM changes`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("trigger rows=%d err=%v", n, err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_schema WHERE name='things_quantity'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("index missing: %v", err)
	}
	for _, q := range []string{
		`INSERT INTO things(name) VALUES('ADA')`,
		`INSERT INTO things(name,quantity) VALUES('bad-check',-1)`,
		`INSERT INTO things(name,owner_id) VALUES('bad-fk',999)`,
	} {
		if _, err := db.Exec(q); err == nil {
			t.Fatalf("constraint lost: %s", q)
		}
	}
	result, err := db.Exec(`INSERT INTO things(name,quantity) VALUES('new',1)`)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := result.LastInsertId()
	if id <= 100 {
		t.Fatalf("AUTOINCREMENT reused ID: %d", id)
	}
	var generated string
	if err := db.QueryRow(`SELECT computed FROM things WHERE id=?`, id).Scan(&generated); err != nil || generated != "newx" {
		t.Fatalf("generated/default=%q err=%v", generated, err)
	}
}

func TestRebuildRefusesReferencedParentAndRollsBackInvalidData(t *testing.T) {
	db := migrationSafetyDB(t)
	for _, q := range []string{`CREATE TABLE parents(id INTEGER PRIMARY KEY, name TEXT NOT NULL UNIQUE)`, `CREATE TABLE children(parent_id INTEGER REFERENCES parents(id) ON DELETE CASCADE)`, `INSERT INTO parents VALUES(1,'saved')`, `INSERT INTO children VALUES(1)`} {
		mustExec(t, db, q)
	}
	if err := rebuildTable(db, "parents", func(c Column) *Column {
		if c.Name == "name" {
			c.NotNull = false
		}
		return &c
	}); err == nil || !strings.Contains(err.Error(), "referenced") {
		t.Fatalf("wanted safe refusal: %v", err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM children`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("child data changed: %d %v", n, err)
	}
	mustExec(t, db, `CREATE TABLE nullable(id INTEGER PRIMARY KEY, value TEXT); INSERT INTO nullable VALUES(1,NULL)`)
	if err := rebuildTable(db, "nullable", func(c Column) *Column {
		if c.Name == "value" {
			c.NotNull = true
		}
		return &c
	}); err == nil {
		t.Fatal("invalid tightening succeeded")
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM nullable WHERE value IS NULL`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("rollback lost data: %d %v", n, err)
	}
	if dbTableExists(db, "nullable_migrate_tmp") {
		t.Fatal("failed rebuild left temp table")
	}
}

func TestRebuildPreservesCompositeKeyAndTableOptions(t *testing.T) {
	db := migrationSafetyDB(t)
	mustExec(t, db, `CREATE TABLE pairs(a TEXT,b INTEGER,value TEXT NOT NULL,PRIMARY KEY(a,b)) WITHOUT ROWID, STRICT`)
	mustExec(t, db, `INSERT INTO pairs VALUES('x',1,'old')`)
	if err := rebuildTable(db, "pairs", func(c Column) *Column {
		if c.Name == "value" {
			c.NotNull = false
		}
		return &c
	}); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `UPDATE pairs SET value=NULL`)
	for _, q := range []string{`INSERT INTO pairs VALUES('x',1,'duplicate')`, `INSERT INTO pairs VALUES('y','wrong-type','bad')`, `SELECT rowid FROM pairs`} {
		if _, err := db.Exec(q); err == nil {
			t.Fatalf("table option lost: %s", q)
		}
	}
}

func TestRebuildPreservesHiddenRowIDs(t *testing.T) {
	db := migrationSafetyDB(t)
	mustExec(t, db, `CREATE TABLE notes(id TEXT PRIMARY KEY,body TEXT NOT NULL); INSERT INTO notes(rowid,id,body) VALUES(7,'one','first'),(900,'two','second')`)
	if err := rebuildTable(db, "notes", func(c Column) *Column {
		if c.Name == "body" {
			c.NotNull = false
		}
		return &c
	}); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string]int{"one": 7, "two": 900} {
		var got int
		if err := db.QueryRow(`SELECT rowid FROM notes WHERE id=?`, id).Scan(&got); err != nil || got != want {
			t.Fatalf("%s rowid=%d want=%d err=%v", id, got, want, err)
		}
	}
}
